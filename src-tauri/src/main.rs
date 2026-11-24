#![cfg_attr(
    all(windows, not(debug_assertions), feature = "gui"),
    windows_subsystem = "windows"
)]

use anyhow::{Context, Result};
#[cfg(target_os = "macos")]
use mcp_vault::crypto::MasterKey;
#[cfg(feature = "gui")]
use mcp_vault::run_gui;
use mcp_vault::{
    backup,
    browser::BrowserBridge,
    mcp,
    migration,
    model::{ItemModule, SecretBundle, SettingsPatch},
    smart_ingest,
    storage::{app_data_dir, resolve_user_path},
    updater,
    vault::Vault,
};
use std::env;
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    if let Err(error) = dispatch().await {
        eprintln!("OpenKeylet: {error:#}");
        std::process::exit(1);
    }
}

async fn dispatch() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.first().is_some_and(|arg| arg == "gui") {
        #[cfg(feature = "gui")]
        {
            run_gui()?;
            return Ok(());
        }
        #[cfg(not(feature = "gui"))]
        anyhow::bail!(
            "This is the headless version of OpenKeylet; use the mcp stdio, config, browser, or backup subcommand"
        );
    }

    #[cfg(target_os = "macos")]
    if matches!(args.as_slice(), [command, action] if command == "key" && action == "migrate") {
        let data_dir = app_data_dir()?;
        if MasterKey::migrate_legacy_macos_key(&data_dir)? {
            Vault::open(data_dir)?;
            println!(
                "The legacy keychain master key has been migrated; future OpenKeylet launches will no longer request keychain permission"
            );
        } else {
            println!("The app-private master key file already exists; no migration is needed");
        }
        return Ok(());
    }

    let vault = Vault::open(app_data_dir()?)?;
    match args.as_slice() {
        [command, transport] if command == "mcp" && transport == "stdio" => {
            mcp::serve_stdio(vault).await
        }
        [command, format] if command == "config" => {
            println!("{}", mcp::render_config(format)?);
            Ok(())
        }
        [command, action] if command == "browser" && action == "status" => {
            print_browser_status(&vault)
        }
        [command, action] if command == "browser" && action == "enable" => {
            set_browser_enabled(&vault, true, None)
        }
        [command, action, port] if command == "browser" && action == "enable" => {
            set_browser_enabled(&vault, true, Some(parse_port(port)?))
        }
        [command, action] if command == "browser" && action == "disable" => {
            set_browser_enabled(&vault, false, None)
        }
        [command, action] if command == "browser" && action == "pair" => {
            pair_browser(&vault, None).await
        }
        [command, action, port] if command == "browser" && action == "pair" => {
            pair_browser(&vault, Some(parse_port(port)?)).await
        }
        [command, action] if command == "browser" && action == "reset" => {
            reset_browser(&vault).await
        }
        [command, action, file] if command == "backup" && action == "export" => {
            backup::export_to_file(&vault, file)?;
            println!("Backup written to {file}");
            Ok(())
        }
        [command, action, file] if command == "backup" && action == "import" => {
            let summary = backup::import_from_file(&vault, file)?;
            println!(
                "Imported: added {}, merged duplicates {}",
                summary.added, summary.merged
            );
            Ok(())
        }
        [command, action] if command == "update" && action == "check" => {
            run_cli_update(&vault, false).await
        }
        [command, action] if command == "update" && action == "install" => {
            run_cli_update(&vault, true).await
        }
        [command, rest @ ..] if command == "add" => run_cli_add(&vault, rest),
        [command, rest @ ..] if command == "import-env" => run_cli_import_env(&vault, rest),
        [command, rest @ ..] if command == "import-ssh" => run_cli_import_ssh(&vault, rest),
        [command, rest @ ..] if command == "keygen" => run_cli_keygen(&vault, rest),
        _ => anyhow::bail!(
            "Usage: openkeylet [gui] | mcp stdio | config <stdio-json|stdio-toml> | add [--name <NAME>] [--folder <FOLDER>] [--file <PATH>] | import-env <FILE> [--name <NAME>] [--folder <FOLDER>] [--seal [TEMPLATE]] | import-ssh [CONFIG_FILE] | keygen <NAME> [--host <HOST>] [--port <PORT>] [--user <USER>] [--comment <COMMENT>] [--folder <FOLDER>] | browser <status|enable [port]|disable|pair [port]|reset> | backup <export|import> <file> | update <check|install> | key migrate (macOS)"
        ),
    }
}

fn unique_cli_name(vault: &Vault, base: &str) -> Result<String> {
    let existing: Vec<String> = vault
        .list_connections()?
        .into_iter()
        .map(|c| c.name)
        .collect();
    let trimmed = base.trim();
    let root = if trimmed.is_empty() { "Imported item" } else { trimmed };
    if !existing.iter().any(|n| n.eq_ignore_ascii_case(root)) {
        return Ok(root.to_owned());
    }
    let mut index = 2;
    loop {
        let candidate = format!("{root} ({index})");
        if !existing.iter().any(|n| n.eq_ignore_ascii_case(&candidate)) {
            return Ok(candidate);
        }
        index += 1;
    }
}

fn run_cli_add(vault: &Vault, args: &[String]) -> Result<()> {
    let mut name_override: Option<String> = None;
    let mut folder_override: Option<String> = None;
    let mut file_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" | "-n" => {
                i += 1;
                name_override = Some(args.get(i).context("--name requires a value")?.clone());
            }
            "--folder" | "-f" => {
                i += 1;
                folder_override = Some(args.get(i).context("--folder requires a value")?.clone());
            }
            "--file" => {
                i += 1;
                file_path = Some(args.get(i).context("--file requires a path")?.clone());
            }
            "--stdin" => {}
            other => anyhow::bail!("Unknown flag for `openkeylet add`: {other}"),
        }
        i += 1;
    }

    let (raw, hint_name) = if let Some(raw_path) = file_path {
        let resolved = resolve_user_path(&raw_path)?;
        let content = std::fs::read_to_string(&resolved)
            .with_context(|| format!("Unable to read {}", resolved.display()))?;
        let fname = resolved
            .file_name()
            .and_then(|s| s.to_str())
            .map(str::to_owned);
        (zeroize::Zeroizing::new(content), fname)
    } else {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("Unable to read from stdin (pipe a secret or pass --file <path>)")?;
        (zeroize::Zeroizing::new(buf), None)
    };

    let parsed = smart_ingest::smart_parse(&raw, hint_name.as_deref(), None)?;
    let mut input = parsed.input;
    if let Some(name) = name_override {
        input.name = name;
    }
    if let Some(folder) = folder_override {
        input.folder = folder;
    }
    input.name = unique_cli_name(vault, &input.name)?;
    let saved = vault.save_connection(input)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "id": saved.id,
            "name": saved.name,
            "itemType": saved.item_type,
            "detected": parsed.label,
            "summary": parsed.summary,
            "modules": saved.modules.iter().map(|m| if m.kind == "customSecret" { m.name.as_str() } else { m.kind.as_str() }).collect::<Vec<_>>(),
        }))?
    );
    Ok(())
}

fn run_cli_import_env(vault: &Vault, args: &[String]) -> Result<()> {
    let mut file_arg: Option<String> = None;
    let mut name_override: Option<String> = None;
    let mut folder_override: Option<String> = None;
    let mut seal = false;
    let mut seal_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" | "-n" => {
                i += 1;
                name_override = Some(args.get(i).context("--name requires a value")?.clone());
            }
            "--folder" | "-f" => {
                i += 1;
                folder_override = Some(args.get(i).context("--folder requires a value")?.clone());
            }
            "--seal" => {
                seal = true;
                if let Some(next) = args.get(i + 1)
                    && !next.starts_with('-')
                {
                    i += 1;
                    seal_path = Some(next.clone());
                }
            }
            other if !other.starts_with('-') && file_arg.is_none() => {
                file_arg = Some(other.to_owned());
            }
            other => anyhow::bail!("Unknown argument for `openkeylet import-env`: {other}"),
        }
        i += 1;
    }
    let raw_path = file_arg.context("Usage: openkeylet import-env <FILE> [--name <NAME>] [--folder <FOLDER>] [--seal [TEMPLATE]]")?;
    let resolved = resolve_user_path(&raw_path)?;
    let raw = zeroize::Zeroizing::new(
        std::fs::read_to_string(&resolved)
            .with_context(|| format!("Unable to read {}", resolved.display()))?,
    );
    let default_name = resolved
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| format!("Env · {s}"))
        .unwrap_or_else(|| "Imported .env".to_owned());
    let (mut entries, _) = smart_ingest::parse_env_file(
        raw.as_bytes(),
        name_override.as_deref().unwrap_or(&default_name),
    )?;
    if let Some(folder) = folder_override {
        entries[0].0.folder = folder;
    }
    let keys: Vec<String> = entries[0]
        .0
        .modules
        .iter()
        .filter(|m| m.kind == "customSecret")
        .map(|m| m.name.clone())
        .collect();
    let item_name = entries[0].0.name.clone();
    let summary = vault.merge_connections(entries)?;

    let mut written_template: Option<String> = None;
    if seal {
        let target = match seal_path {
            Some(p) => resolve_user_path(&p)?,
            None => PathBuf::from(format!("{}.template", resolved.display())),
        };
        let (sealed_text, _) = smart_ingest::render_sealed_env(&raw);
        let mut writer = atomic_write_file::AtomicWriteFile::open(&target)
            .with_context(|| format!("Unable to write {}", target.display()))?;
        std::io::Write::write_all(&mut writer, sealed_text.as_bytes())?;
        writer.commit()?;
        written_template = Some(target.to_string_lossy().into_owned());
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "itemName": item_name,
            "added": summary.added,
            "merged": summary.merged,
            "keys": keys,
            "placeholders": keys.iter().map(|k| format!("{{{{openkeylet:{k}}}}}")).collect::<Vec<_>>(),
            "templatePath": written_template,
        }))?
    );
    Ok(())
}

fn run_cli_import_ssh(vault: &Vault, args: &[String]) -> Result<()> {
    let path = match args {
        [] => smart_ingest::default_ssh_config_path()
            .context("Could not locate your home directory for ~/.ssh/config")?,
        [file] => resolve_user_path(file)?,
        _ => anyhow::bail!("Usage: openkeylet import-ssh [CONFIG_FILE]"),
    };
    let parsed = migration::read(&path, "ssh_config")?;
    let total = parsed.preview.total;
    let summary = vault.merge_connections(parsed.entries)?;
    println!(
        "Imported SSH config ({}): found {}, added {}, merged duplicates {}",
        path.display(),
        total,
        summary.added,
        summary.merged
    );
    Ok(())
}

fn run_cli_keygen(vault: &Vault, args: &[String]) -> Result<()> {
    let mut name_arg: Option<String> = None;
    let mut host = String::new();
    let mut port: u16 = 22;
    let mut user = String::new();
    let mut comment = String::new();
    let mut folder = "SSH".to_owned();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--host" | "-h" => {
                i += 1;
                host = args.get(i).context("--host requires a value")?.clone();
            }
            "--port" | "-p" => {
                i += 1;
                port = parse_port(args.get(i).context("--port requires a value")?)?;
            }
            "--user" | "-u" => {
                i += 1;
                user = args.get(i).context("--user requires a value")?.clone();
            }
            "--comment" | "-C" => {
                i += 1;
                comment = args.get(i).context("--comment requires a value")?.clone();
            }
            "--folder" | "-f" => {
                i += 1;
                folder = args.get(i).context("--folder requires a value")?.clone();
            }
            other if !other.starts_with('-') && name_arg.is_none() => {
                name_arg = Some(other.to_owned());
            }
            other => anyhow::bail!("Unknown argument for `openkeylet keygen`: {other}"),
        }
        i += 1;
    }
    let name = name_arg.context(
        "Usage: openkeylet keygen <NAME> [--host <HOST>] [--port <PORT>] [--user <USER>] [--comment <COMMENT>] [--folder <FOLDER>]",
    )?;
    let unique_name = unique_cli_name(vault, &name)?;
    let key_comment = if comment.trim().is_empty() {
        format!("{unique_name}@openkeylet")
    } else {
        comment
    };
    let keypair = smart_ingest::generate_ed25519_keypair(&key_comment)?;

    let mut modules = Vec::new();
    let mut secrets = SecretBundle::default();
    if !host.trim().is_empty() {
        modules.push(ItemModule {
            kind: "host".to_owned(),
            name: "host".to_owned(),
            value: host.trim().to_owned(),
            agent_visible: Some(true),
        });
        modules.push(ItemModule {
            kind: "port".to_owned(),
            name: "port".to_owned(),
            value: port.to_string(),
            agent_visible: Some(true),
        });
    }
    if !user.trim().is_empty() {
        modules.push(ItemModule {
            kind: "username".to_owned(),
            name: "username".to_owned(),
            value: String::new(),
            agent_visible: Some(false),
        });
        secrets
            .named_secrets
            .insert("username".to_owned(), user.trim().to_owned());
    }
    modules.push(ItemModule {
        kind: "privateKey".to_owned(),
        name: "privateKey".to_owned(),
        value: String::new(),
        agent_visible: Some(false),
    });
    secrets.private_key = Some(keypair.private_key_pem.to_string());
    secrets.private_key_name = Some("id_ed25519".to_owned());

    let input = mcp_vault::model::ConnectionInput {
        login_uris: Vec::new(),
        item_type: "ssh".to_owned(),
        folder,
        favorite: false,
        id: None,
        modules,
        name: unique_name.clone(),
        enabled: true,
        description: format!("Ed25519 · {}", keypair.fingerprint),
        http_auth_type: String::new(),
        private_key_import_path: String::new(),
        auth_header: String::new(),
        auth_location: String::new(),
        auth_prefix: String::new(),
        api_auth_headers: Vec::new(),
        test_path: String::new(),
        remove_secret_names: Vec::new(),
        secrets,
    };
    vault.save_connection(input)?;
    eprintln!(
        "Stored Ed25519 private key in OpenKeylet item \"{unique_name}\" ({})",
        keypair.fingerprint
    );
    // Print ONLY the public key on stdout so callers can pipe directly to clip/pbcopy/authorized_keys.
    println!("{}", keypair.public_key);
    Ok(())
}

async fn run_cli_update(vault: &Vault, install: bool) -> Result<()> {
    let executable = mcp::launcher_executable()?;
    updater::cleanup_previous_update_artifacts(&executable, vault.data_dir());
    let manager = updater::UpdateManager::new(vault.clone(), executable);
    let outcome = manager.check_for_updates(true, |_| {}).await?;
    if !install {
        println!("{}", serde_json::to_string_pretty(&outcome.status)?);
        return Ok(());
    }
    if !outcome.update_available {
        println!(
            "OpenKeylet {} is already up to date.",
            outcome.status.current_version
        );
        return Ok(());
    }
    let target_version = outcome
        .status
        .latest_version
        .clone()
        .unwrap_or_else(|| "latest".to_owned());
    eprintln!(
        "Downloading and verifying OpenKeylet {} ({})...",
        target_version, outcome.status.platform
    );
    manager.download_and_stage(|_| {}).await?;
    manager.apply_and_relaunch(false, |_| {}).await?;
    println!("OpenKeylet updated to {target_version}. Restart any running OpenKeylet processes to use the new version.");
    Ok(())
}

fn parse_port(value: &str) -> Result<u16> {
    let port = value
        .parse::<u16>()
        .context("Invalid browser bridge port")?;
    if port == 0 {
        anyhow::bail!("Browser bridge port must be between 1 and 65535");
    }
    Ok(port)
}

fn set_browser_enabled(vault: &Vault, enabled: bool, port: Option<u16>) -> Result<()> {
    vault.update_settings_patch(SettingsPatch {
        browser_enabled: Some(enabled),
        browser_port: port,
        ..SettingsPatch::default()
    })?;
    print_browser_status(vault)
}

fn print_browser_status(vault: &Vault) -> Result<()> {
    let settings = vault.settings()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "enabled": settings.browser_enabled,
            "paired": settings.browser_paired,
            "port": settings.browser_port,
            "endpoint": format!("ws://127.0.0.1:{}/extension", settings.browser_port),
        }))?
    );
    Ok(())
}

async fn pair_browser(vault: &Vault, port: Option<u16>) -> Result<()> {
    let settings = vault.update_settings_patch(SettingsPatch {
        browser_enabled: Some(true),
        browser_port: port,
        ..SettingsPatch::default()
    })?;

    let bridge = BrowserBridge::new(vault.clone());
    bridge.sync().await;
    bridge.start_quick_pairing().await?;
    eprintln!(
        "A 120-second automatic pairing window is open; load or wake the OpenKeylet Chromium extension (port {}）…",
        settings.browser_port
    );
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(120) {
        if vault.settings()?.browser_paired {
            bridge.stop().await;
            println!("Browser extension paired successfully");
            return Ok(());
        }
        sleep(Duration::from_millis(250)).await;
    }
    bridge.stop().await;
    anyhow::bail!(
        "Browser extension pairing timed out; confirm that the extension port matches OpenKeylet and try again"
    )
}

async fn reset_browser(vault: &Vault) -> Result<()> {
    let bridge = BrowserBridge::new(vault.clone());
    bridge.reset_pairing().await?;
    bridge.stop().await;
    print_browser_status(vault)
}
