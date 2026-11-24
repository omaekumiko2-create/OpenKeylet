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
    admin_server::{self, AdminServerConfig, DEFAULT_ADMIN_PORT},
    backup,
    browser::BrowserBridge,
    mcp,
    migration,
    model::{ItemModule, SecretBundle, SettingsPatch},
    smart_ingest,
    storage::{app_data_dir, resolve_user_path, uses_explicit_data_dir},
    updater,
    vault::Vault,
};
use std::env;
use std::io::{BufRead, IsTerminal, Read, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use uuid::Uuid;
use zeroize::Zeroizing;

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
            "This is the headless version of OpenKeylet; use the mcp stdio, config, vault, admin, browser, or backup subcommand"
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
            print_browser_status(&vault).await
        }
        [command, action] if command == "browser" && action == "enable" => {
            set_browser_enabled(&vault, true, None).await
        }
        [command, action, port] if command == "browser" && action == "enable" => {
            set_browser_enabled(&vault, true, Some(parse_port(port)?)).await
        }
        [command, action] if command == "browser" && action == "disable" => {
            set_browser_enabled(&vault, false, None).await
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
        [command, rest @ ..] if command == "backup" => run_cli_backup(&vault, rest),
        [command, rest @ ..] if command == "vault" => run_cli_vault(&vault, rest),
        [command, rest @ ..] if command == "admin" => run_cli_admin(vault, rest).await,
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
            "Usage: openkeylet [gui] | mcp stdio | config <stdio-json|stdio-toml> | vault <status|list [--all]|show <ITEM>|enable <ITEM>|disable <ITEM>|trash <ITEM>|restore <ITEM>|pin <status|set|clear>> | admin serve [--port <PORT>] [--bind <IP>] [--token-env <VAR>] | add [--name <NAME>] [--folder <FOLDER>] [--file <PATH>] | import-env <FILE> [--name <NAME>] [--folder <FOLDER>] [--seal [TEMPLATE]] | import-ssh [CONFIG_FILE] | keygen <NAME> [--host <HOST>] [--port <PORT>] [--user <USER>] [--comment <COMMENT>] [--folder <FOLDER>] | browser <status|enable [port]|disable|pair [port]|reset> | backup <export|import> <file> [--passphrase | --passphrase-env <VAR> | --passphrase-stdin] | update <check|install> | key migrate (macOS)"
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

async fn set_browser_enabled(vault: &Vault, enabled: bool, port: Option<u16>) -> Result<()> {
    vault.update_settings_patch(SettingsPatch {
        browser_enabled: Some(enabled),
        browser_port: port,
        ..SettingsPatch::default()
    })?;
    print_browser_status(vault).await
}

async fn print_browser_status(vault: &Vault) -> Result<()> {
    let bridge = BrowserBridge::new(vault.clone());
    let state = bridge.probe_live_status().await?;
    println!("{}", serde_json::to_string_pretty(&state)?);
    Ok(())
}

async fn pair_browser(vault: &Vault, port: Option<u16>) -> Result<()> {
    let settings = vault.update_settings_patch(SettingsPatch {
        browser_enabled: Some(true),
        browser_port: port,
        ..SettingsPatch::default()
    })?;

    let bridge = BrowserBridge::new(vault.clone());
    let net_cfg = bridge.network_config()?;
    bridge.sync().await;
    bridge.start_quick_pairing().await?;
    eprintln!(
        "A 120-second automatic pairing window is open; load or wake the OpenKeylet Chromium extension ({})…",
        net_cfg.advertised_endpoint(settings.browser_port)
    );
    if net_cfg.is_lan_mode() {
        eprintln!(
            "LAN mode active (bind={}, ipAllowlist={:?}). Configure the workstation extension host to '{}' and port {}.",
            net_cfg.bind_addr(settings.browser_port),
            net_cfg.ip_allowlist_strings(),
            net_cfg.advertised_host,
            settings.browser_port
        );
    }
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
        "Browser extension pairing timed out; confirm that the extension host/port matches OpenKeylet and try again"
    )
}

async fn reset_browser(vault: &Vault) -> Result<()> {
    let bridge = BrowserBridge::new(vault.clone());
    bridge.reset_pairing().await?;
    bridge.stop().await;
    print_browser_status(vault).await
}

enum PassphraseSource {
    None,
    Prompt,
    Env(String),
    Stdin,
}

fn read_secret_line_hidden(prompt: &str) -> Result<Zeroizing<String>> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();

    #[cfg(windows)]
    let _echo_guard = {
        if std::io::stdin().is_terminal() {
            windows_echo::disable_console_echo()
        } else {
            None
        }
    };
    #[cfg(unix)]
    let _echo_guard = {
        if std::io::stdin().is_terminal() {
            unix_echo::disable_tty_echo()
        } else {
            None
        }
    };

    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("Unable to read passphrase from stdin")?;
    if std::io::stdin().is_terminal() {
        eprintln!();
    }
    let trimmed = line.trim_end_matches(&['\r', '\n'][..]).to_owned();
    Ok(Zeroizing::new(trimmed))
}

#[cfg(windows)]
mod windows_echo {
    const STD_INPUT_HANDLE: u32 = (-10_i32) as u32;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(n_std_handle: u32) -> isize;
        fn GetConsoleMode(h_console_handle: isize, lp_mode: *mut u32) -> i32;
        fn SetConsoleMode(h_console_handle: isize, dw_mode: u32) -> i32;
    }

    pub struct EchoGuard {
        handle: isize,
        original_mode: u32,
    }

    impl Drop for EchoGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = SetConsoleMode(self.handle, self.original_mode);
            }
        }
    }

    pub fn disable_console_echo() -> Option<EchoGuard> {
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            if handle == 0 || handle == -1 {
                return None;
            }
            let mut mode: u32 = 0;
            if GetConsoleMode(handle, &mut mode) == 0 {
                return None;
            }
            if SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) == 0 {
                return None;
            }
            Some(EchoGuard {
                handle,
                original_mode: mode,
            })
        }
    }
}

#[cfg(unix)]
mod unix_echo {
    use std::process::Command;

    pub struct EchoGuard;

    impl Drop for EchoGuard {
        fn drop(&mut self) {
            let _ = Command::new("stty").arg("echo").status();
        }
    }

    pub fn disable_tty_echo() -> Option<EchoGuard> {
        if Command::new("stty")
            .arg("-echo")
            .status()
            .is_ok_and(|s| s.success())
        {
            Some(EchoGuard)
        } else {
            None
        }
    }
}

fn obtain_passphrase(source: &PassphraseSource, confirm: bool) -> Result<Zeroizing<String>> {
    match source {
        PassphraseSource::Env(var_name) => {
            let val = env::var(var_name)
                .with_context(|| format!("Environment variable '{var_name}' is not set"))?;
            Ok(Zeroizing::new(val))
        }
        PassphraseSource::Stdin => {
            let mut line = String::new();
            std::io::stdin()
                .lock()
                .read_line(&mut line)
                .context("Unable to read passphrase from stdin")?;
            Ok(Zeroizing::new(
                line.trim_end_matches(&['\r', '\n'][..]).to_owned(),
            ))
        }
        PassphraseSource::Prompt => {
            let first = read_secret_line_hidden("Enter backup passphrase (min 12 chars): ")?;
            if confirm {
                let second = read_secret_line_hidden("Confirm backup passphrase: ")?;
                if *first != *second {
                    anyhow::bail!("Backup passphrases do not match");
                }
            }
            Ok(first)
        }
        PassphraseSource::None => {
            anyhow::bail!(
                "This .mvault backup is passphrase-protected. Pass --passphrase, --passphrase-env <VAR>, or --passphrase-stdin."
            )
        }
    }
}

fn parse_backup_args(args: &[String]) -> Result<(String, String, PassphraseSource)> {
    let action = args
        .first()
        .context("Usage: openkeylet backup <export|import> <file> [--passphrase | --passphrase-env <VAR> | --passphrase-stdin]")?
        .as_str();
    if !matches!(action, "export" | "import") {
        anyhow::bail!(
            "Usage: openkeylet backup <export|import> <file> [--passphrase | --passphrase-env <VAR> | --passphrase-stdin]"
        );
    }
    let mut file_arg: Option<String> = None;
    let mut source = PassphraseSource::None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--passphrase" | "-p" => source = PassphraseSource::Prompt,
            "--passphrase-stdin" => source = PassphraseSource::Stdin,
            "--passphrase-env" => {
                i += 1;
                let var = args
                    .get(i)
                    .context("--passphrase-env requires an environment variable name")?
                    .clone();
                source = PassphraseSource::Env(var);
            }
            other if !other.starts_with('-') && file_arg.is_none() => {
                file_arg = Some(other.to_owned());
            }
            other => anyhow::bail!("Unknown argument for `openkeylet backup {action}`: {other}"),
        }
        i += 1;
    }
    let file = file_arg.context(
        "Usage: openkeylet backup <export|import> <file> [--passphrase | --passphrase-env <VAR> | --passphrase-stdin]",
    )?;
    Ok((action.to_owned(), file, source))
}

fn run_cli_backup(vault: &Vault, args: &[String]) -> Result<()> {
    let (action, file, source) = parse_backup_args(args)?;
    let path = resolve_user_path(&file)?;
    match action.as_str() {
        "export" => match source {
            PassphraseSource::None => {
                backup::export_to_file(vault, &path)?;
                eprintln!(
                    "Note: exported a convenient self-unlocking .mvault backup (must be protected like plaintext secrets). Use --passphrase for Argon2id passphrase-protected storage."
                );
                println!("Backup written to {file}");
                Ok(())
            }
            _ => {
                let passphrase = obtain_passphrase(&source, matches!(source, PassphraseSource::Prompt))?;
                backup::export_protected(vault, &path, &passphrase)?;
                eprintln!(
                    "Warning: losing this passphrase makes the backup permanently unrecoverable."
                );
                println!("Passphrase-protected backup written to {file}");
                Ok(())
            }
        },
        "import" => {
            let requires_password = backup::inspect_file_requires_password(&path)?;
            if requires_password {
                let effective_source = match source {
                    PassphraseSource::None if std::io::stdin().is_terminal() => {
                        PassphraseSource::Prompt
                    }
                    other => other,
                };
                let passphrase = obtain_passphrase(&effective_source, false)?;
                let summary = backup::import_with_password(vault, &path, &passphrase)?;
                println!(
                    "Imported protected backup: added {}, merged duplicates {}",
                    summary.added, summary.merged
                );
                Ok(())
            } else {
                let summary = backup::import_from_file(vault, &path)?;
                eprintln!(
                    "Note: imported a legacy self-unlocking .mvault backup. Consider re-exporting with --passphrase."
                );
                println!(
                    "Imported: added {}, merged duplicates {}",
                    summary.added, summary.merged
                );
                Ok(())
            }
        }
        _ => unreachable!(),
    }
}

fn resolve_cli_item_id(vault: &Vault, query: &str) -> Result<Uuid> {
    let trimmed = query.trim();
    if let Ok(id) = Uuid::parse_str(trimmed) {
        return Ok(id);
    }
    let items = vault.list_connections()?;
    let exact: Vec<_> = items
        .iter()
        .filter(|c| c.name.eq_ignore_ascii_case(trimmed))
        .collect();
    if exact.len() == 1 {
        return Ok(exact[0].id);
    }
    let contains: Vec<_> = items
        .iter()
        .filter(|c| c.name.to_lowercase().contains(&trimmed.to_lowercase()))
        .collect();
    match contains.len() {
        0 => anyhow::bail!("No vault item found matching '{trimmed}'"),
        1 => Ok(contains[0].id),
        _ => anyhow::bail!(
            "Multiple items match '{trimmed}': {}. Specify the exact name or UUID.",
            contains
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn run_cli_vault(vault: &Vault, args: &[String]) -> Result<()> {
    match args {
        [action] if action == "status" => {
            let items = vault.list_connections()?;
            let trash = vault.trash_items()?;
            let settings = vault.settings()?;
            let enabled_count = items.iter().filter(|i| i.enabled).count();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "dataDir": vault.data_dir().to_string_lossy(),
                    "explicitDataDir": uses_explicit_data_dir(vault.data_dir()),
                    "keySource": vault.storage_label(),
                    "strongMode": vault.is_strong_mode(),
                    "strongUnlocked": vault.is_strong_unlocked(),
                    "ownerPinConfigured": vault.owner_pin_configured()?,
                    "itemCount": items.len(),
                    "enabledItemCount": enabled_count,
                    "trashCount": trash.len(),
                    "browserEnabled": settings.browser_enabled,
                    "browserPaired": settings.browser_paired,
                    "browserPort": settings.browser_port,
                }))?
            );
            Ok(())
        }
        [action, rest @ ..] if action == "list" => {
            let include_trash = rest.iter().any(|a| a == "--all");
            let items = vault.list_connections()?;
            if include_trash {
                let trash = vault.trash_items()?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "items": items,
                        "trash": trash,
                    }))?
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&items)?);
            }
            Ok(())
        }
        [action, query] if action == "show" => {
            let id = resolve_cli_item_id(vault, query)?;
            let item = vault.get_connection(id)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&item.stored.public(Some(&item.secrets)))?
            );
            Ok(())
        }
        [action, query] if action == "enable" => {
            let id = resolve_cli_item_id(vault, query)?;
            vault.set_connection_enabled(id, true)?;
            println!("Enabled item {id}");
            Ok(())
        }
        [action, query] if action == "disable" => {
            let id = resolve_cli_item_id(vault, query)?;
            vault.set_connection_enabled(id, false)?;
            println!("Disabled item {id}");
            Ok(())
        }
        [action, query] if action == "trash" => {
            let id = resolve_cli_item_id(vault, query)?;
            vault.trash_connection(id, None)?;
            println!("Moved item {id} to trash");
            Ok(())
        }
        [action, query] if action == "restore" => {
            let trash = vault.trash_items()?;
            let trimmed = query.trim();
            let matched: Vec<_> = trash
                .iter()
                .filter(|t| {
                    t.item.id.to_string().eq_ignore_ascii_case(trimmed)
                        || t.item.name.eq_ignore_ascii_case(trimmed)
                })
                .collect();
            if matched.len() != 1 {
                anyhow::bail!(
                    "Expected exactly one trash item matching '{trimmed}', found {}",
                    matched.len()
                );
            }
            vault.restore_connection(matched[0].item.id, &matched[0].deleted_at)?;
            println!(
                "Restored item {} ({})",
                matched[0].item.name, matched[0].item.id
            );
            Ok(())
        }
        [action, sub, rest @ ..] if action == "pin" => match sub.as_str() {
            "status" => {
                println!(
                    "{}",
                    serde_json::json!({ "ownerPinConfigured": vault.owner_pin_configured()? })
                );
                Ok(())
            }
            "set" => {
                let pin = match rest {
                    [flag, var] if flag == "--pin-env" => Zeroizing::new(
                        env::var(var)
                            .with_context(|| format!("Environment variable '{var}' is not set"))?,
                    ),
                    [] => {
                        let first = read_secret_line_hidden("Enter 6-digit Owner PIN: ")?;
                        let second = read_secret_line_hidden("Confirm 6-digit Owner PIN: ")?;
                        if *first != *second {
                            anyhow::bail!("PINs do not match");
                        }
                        first
                    }
                    _ => anyhow::bail!("Usage: openkeylet vault pin set [--pin-env <VAR>]"),
                };
                vault.set_owner_pin(pin.trim())?;
                println!("Owner PIN configured");
                Ok(())
            }
            "clear" => {
                vault.disable_owner_pin()?;
                println!("Owner PIN cleared");
                Ok(())
            }
            _ => anyhow::bail!("Usage: openkeylet vault pin <status|set [--pin-env <VAR>]|clear>"),
        },
        _ => anyhow::bail!(
            "Usage: openkeylet vault <status|list [--all]|show <ITEM>|enable <ITEM>|disable <ITEM>|trash <ITEM>|restore <ITEM>|pin <status|set|clear>>"
        ),
    }
}

async fn run_cli_admin(vault: Vault, args: &[String]) -> Result<()> {
    let Some(first) = args.first() else {
        anyhow::bail!(
            "Usage: openkeylet admin serve [--port <PORT>] [--bind <IP>] [--allow-non-loopback] [--token-env <VAR>]"
        );
    };
    if first != "serve" {
        anyhow::bail!(
            "Usage: openkeylet admin serve [--port <PORT>] [--bind <IP>] [--allow-non-loopback] [--token-env <VAR>]"
        );
    }
    let mut config = AdminServerConfig {
        port: DEFAULT_ADMIN_PORT,
        ..AdminServerConfig::default()
    };
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                i += 1;
                config.port = parse_port(args.get(i).context("--port requires a value")?)?;
            }
            "--bind" => {
                i += 1;
                let raw = args.get(i).context("--bind requires an IP address")?;
                config.bind_ip = raw
                    .parse::<IpAddr>()
                    .with_context(|| format!("Invalid --bind IP address: '{raw}'"))?;
            }
            "--allow-non-loopback" => {
                config.allow_non_loopback = true;
            }
            "--token-env" => {
                i += 1;
                let var = args
                    .get(i)
                    .context("--token-env requires an environment variable name")?;
                let val = env::var(var)
                    .with_context(|| format!("Environment variable '{var}' is not set"))?;
                config.initial_token = Some(Zeroizing::new(val));
            }
            other => anyhow::bail!("Unknown flag for `openkeylet admin serve`: {other}"),
        }
        i += 1;
    }
    admin_server::serve_until_ctrl_c(vault, config).await
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn cli_backup_parse_supports_passphrase_flags() {
        let args = vec![
            "export".to_owned(),
            "protected.mvault".to_owned(),
            "--passphrase".to_owned(),
        ];
        let (action, file, src) = parse_backup_args(&args).unwrap();
        assert_eq!(action, "export");
        assert_eq!(file, "protected.mvault");
        assert!(matches!(src, PassphraseSource::Prompt));

        let env_args = vec![
            "import".to_owned(),
            "protected.mvault".to_owned(),
            "--passphrase-env".to_owned(),
            "TEST_BACKUP_PW".to_owned(),
        ];
        let (action, file, src) = parse_backup_args(&env_args).unwrap();
        assert_eq!(action, "import");
        assert_eq!(file, "protected.mvault");
        assert!(matches!(src, PassphraseSource::Env(ref v) if v == "TEST_BACKUP_PW"));
    }

    #[test]
    fn cli_vault_enable_disable_trash_restore_work_without_gui() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path().join("vault")).unwrap();
        let mut secrets = SecretBundle::default();
        secrets
            .named_secrets
            .insert("password".to_owned(), "s3cr3t-password".to_owned());
        let saved = vault
            .save_connection(mcp_vault::model::ConnectionInput {
                login_uris: Vec::new(),
                item_type: "login".to_owned(),
                folder: String::new(),
                favorite: false,
                id: None,
                modules: vec![ItemModule {
                    kind: "password".to_owned(),
                    name: "password".to_owned(),
                    value: String::new(),
                    agent_visible: Some(false),
                }],
                name: "Headless Test".to_owned(),
                enabled: true,
                description: String::new(),
                http_auth_type: String::new(),
                private_key_import_path: String::new(),
                auth_header: String::new(),
                auth_location: String::new(),
                auth_prefix: String::new(),
                api_auth_headers: Vec::new(),
                test_path: String::new(),
                remove_secret_names: Vec::new(),
                secrets,
            })
            .unwrap();

        run_cli_vault(&vault, &["disable".to_owned(), "Headless Test".to_owned()]).unwrap();
        assert!(!vault.get_connection(saved.id).unwrap().stored.enabled);

        run_cli_vault(&vault, &["enable".to_owned(), "Headless Test".to_owned()]).unwrap();
        assert!(vault.get_connection(saved.id).unwrap().stored.enabled);

        run_cli_vault(&vault, &["trash".to_owned(), saved.id.to_string()]).unwrap();
        assert!(vault.list_connections().unwrap().is_empty());
        assert_eq!(vault.trash_items().unwrap().len(), 1);

        run_cli_vault(&vault, &["restore".to_owned(), "Headless Test".to_owned()]).unwrap();
        assert_eq!(vault.list_connections().unwrap().len(), 1);
    }
}
