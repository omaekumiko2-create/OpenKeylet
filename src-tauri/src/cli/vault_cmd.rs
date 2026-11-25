//! CLI vault management, ingestion, and SSH keygen subcommand handlers.

use super::{
    AddArgs, ImportEnvArgs, KeygenArgs, VaultCommand, VaultPinCommand,
    prompt::read_secret_line_hidden,
};
use crate::{
    crypto::ssh_keygen,
    model::{ConnectionInput, ItemModule, SecretBundle},
    extract::ingest as smart_ingest,
    storage::{resolve_user_path, uses_explicit_data_dir},
    vault::Vault,
};
use anyhow::{Context, Result};
use std::{
    env,
    io::Read,
    path::{Path, PathBuf},
};

/// Same ceiling as file imports in `migration::read`.
const MAX_SSH_CONFIG_BYTES: u64 = 64 * 1024 * 1024;
use uuid::Uuid;
use zeroize::Zeroizing;

fn unique_cli_name(vault: &Vault, base: &str) -> Result<String> {
    let existing: Vec<String> = vault
        .list_connections()?
        .into_iter()
        .map(|c| c.name)
        .collect();
    let trimmed = base.trim();
    let root = if trimmed.is_empty() {
        "Imported item"
    } else {
        trimmed
    };
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

pub fn run_add(vault: &Vault, args: AddArgs) -> Result<()> {
    let (raw, hint_name) = if let Some(raw_path) = args.file {
        let resolved = resolve_user_path(&raw_path)?;
        let content = std::fs::read_to_string(&resolved)
            .with_context(|| format!("Unable to read {}", resolved.display()))?;
        let fname = resolved
            .file_name()
            .and_then(|s| s.to_str())
            .map(str::to_owned);
        (Zeroizing::new(content), fname)
    } else {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("Unable to read from stdin (pipe a secret or pass --file <path>)")?;
        (Zeroizing::new(buf), None)
    };

    let parsed = smart_ingest::smart_parse(&raw, hint_name.as_deref(), None)?;
    let mut input = parsed.input;
    if let Some(name) = args.name {
        input.name = name;
    }
    if let Some(folder) = args.folder {
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

pub fn run_import_env(vault: &Vault, args: ImportEnvArgs) -> Result<()> {
    let resolved = resolve_user_path(&args.file)?;
    let raw = Zeroizing::new(
        std::fs::read_to_string(&resolved)
            .with_context(|| format!("Unable to read {}", resolved.display()))?,
    );
    let default_name = resolved
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| format!("Env · {s}"))
        .unwrap_or_else(|| "Imported .env".to_owned());
    let template_target = match &args.seal {
        Some(Some(p)) if !p.is_empty() => Some(resolve_user_path(p)?),
        Some(_) => Some(PathBuf::from(format!("{}.template", resolved.display()))),
        None => None,
    };
    // Values that cannot be sealed are dropped from the template, so writing it over the
    // source would destroy them. Replacing the file stays the user's decision.
    if let Some(target) = &template_target
        && same_file(target, &resolved)
    {
        anyhow::bail!(
            "Refusing to overwrite {} with its sealed template; write the template to another path, check it, then replace the file yourself",
            resolved.display()
        );
    }
    let mut import = smart_ingest::parse_env_file_detailed(
        raw.as_bytes(),
        args.name.as_deref().unwrap_or(&default_name),
    )?;
    if let Some(folder) = args.folder {
        import.entries[0].0.folder = folder;
    }
    let keys: Vec<String> = import.fields.keys().cloned().collect();
    let placeholders: Vec<String> = import
        .fields
        .values()
        .map(|field| format!("{{{{openkeylet:{field}}}}}"))
        .collect();
    let item_name = import.entries[0].0.name.clone();
    let summary = vault.merge_connections(import.entries)?;

    let mut written_template: Option<String> = None;
    let mut removed_lines = 0;
    if let Some(target) = &template_target {
        let sealed = smart_ingest::seal_env_template_with_fields(&raw, &import.fields);
        let mut writer = atomic_write_file::AtomicWriteFile::open(target)
            .with_context(|| format!("Unable to write {}", target.display()))?;
        std::io::Write::write_all(&mut writer, sealed.text.as_bytes())?;
        writer.commit()?;
        written_template = Some(target.to_string_lossy().into_owned());
        removed_lines = sealed.removed_lines;
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "itemName": item_name,
            "added": summary.added,
            "merged": summary.merged,
            "keys": keys,
            "placeholders": placeholders,
            "templatePath": written_template,
            "templateRemovedLines": removed_lines,
            "plaintextStillAt": [resolved.to_string_lossy()],
        }))?
    );
    eprint!(
        "{}",
        env_plaintext_notice(&resolved, keys.len(), written_template.as_deref(), removed_lines)
    );
    Ok(())
}

fn same_file(left: &Path, right: &Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

/// Human-readable reminder that importing copied the values but left the file in place,
/// with the next step that actually removes the plaintext.
pub(super) fn env_plaintext_notice(
    source: &Path,
    stored: usize,
    template: Option<&str>,
    removed_lines: usize,
) -> String {
    let source = source.display();
    let mut notice = format!(
        "Plaintext is still on disk: {source}\n  OpenKeylet stored {stored} value(s) in the vault and did not change this file.\n"
    );
    match template {
        Some(template) => {
            if removed_lines > 0 {
                notice.push_str(&format!(
                    "  {removed_lines} line(s) could not be sealed; the template marks them with \"{}\" and their values exist only in {source}. Move them into the vault first.\n",
                    smart_ingest::SEALED_REMOVAL_MARKER
                ));
            }
            notice.push_str(&format!(
                "  Next step: check {template}, run your app with `openkeylet run --env-file {template} -- <command>`, then delete {source}.\n"
            ));
        }
        None => notice.push_str(&format!(
            "  Next step: run `openkeylet import-env {source} --seal` to write a template with {{{{openkeylet:…}}}} placeholders, switch your app to it, then delete {source}.\n"
        )),
    }
    notice
}

pub fn run_import_ssh(vault: &Vault, config_file: Option<String>) -> Result<()> {
    let path = match config_file {
        None => smart_ingest::default_ssh_config_path()
            .context("Could not locate your home directory for ~/.ssh/config")?,
        Some(file) => resolve_user_path(&file)?,
    };
    let size = std::fs::metadata(&path)
        .with_context(|| format!("Unable to read {}", path.display()))?
        .len();
    anyhow::ensure!(size <= MAX_SSH_CONFIG_BYTES, "Import file exceeds 64 MiB");
    let bytes = Zeroizing::new(
        std::fs::read(&path).with_context(|| format!("Unable to read {}", path.display()))?,
    );
    let (entries, preview, key_files) =
        smart_ingest::parse_ssh_config_bytes_with_key_files(&bytes, path.parent())?;
    let total = preview.total;
    let summary = vault.merge_connections(entries)?;
    println!(
        "Imported SSH config ({}): found {}, added {}, merged duplicates {}",
        path.display(),
        total,
        summary.added,
        summary.merged
    );
    let still_plain = crate::extract::plaintext_sources(key_files.into_iter().flatten());
    eprint!("{}", ssh_plaintext_notice(&still_plain));
    Ok(())
}

/// The config file only names keys; the key files it pointed at are what still holds
/// plaintext. Passphrase-protected keys are already left out of `keys`.
pub(super) fn ssh_plaintext_notice(keys: &[crate::extract::PlaintextSource]) -> String {
    if keys.is_empty() {
        return String::new();
    }
    let mut notice = String::from("Unprotected private keys are still on disk:\n");
    for key in keys {
        notice.push_str(&format!("  {}\n", key.display_path));
    }
    notice.push_str(
        "  Next step: once `openkeylet ssh-agent` serves these keys, delete the files, or give each one a passphrase with `ssh-keygen -p -f <file>`.\n",
    );
    notice
}

pub fn run_keygen(vault: &Vault, args: KeygenArgs) -> Result<()> {
    let port = super::validate_nonzero_port(args.port)?;
    let unique_name = unique_cli_name(vault, &args.name)?;
    let key_comment = if args.comment.trim().is_empty() {
        format!("{unique_name}@openkeylet")
    } else {
        args.comment
    };
    let keypair = ssh_keygen::generate_ed25519_keypair(&key_comment)?;

    let mut modules = Vec::new();
    let mut secrets = SecretBundle::default();
    if !args.host.trim().is_empty() {
        modules.push(ItemModule {
            kind: "host".to_owned(),
            name: "host".to_owned(),
            value: args.host.trim().to_owned(),
            agent_visible: Some(true),
        });
        modules.push(ItemModule {
            kind: "port".to_owned(),
            name: "port".to_owned(),
            value: port.to_string(),
            agent_visible: Some(true),
        });
    }
    if !args.user.trim().is_empty() {
        modules.push(ItemModule {
            kind: "username".to_owned(),
            name: "username".to_owned(),
            value: String::new(),
            agent_visible: Some(false),
        });
        secrets
            .named_secrets
            .insert("username".to_owned(), args.user.trim().to_owned());
    }
    modules.push(ItemModule {
        kind: "privateKey".to_owned(),
        name: "privateKey".to_owned(),
        value: String::new(),
        agent_visible: Some(false),
    });
    secrets.private_key = Some(keypair.private_key_pem.to_string());
    secrets.private_key_name = Some("id_ed25519".to_owned());

    let input = ConnectionInput {
        login_uris: Vec::new(),
        item_type: "ssh".to_owned(),
        folder: args.folder,
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
    println!("{}", keypair.public_key);
    Ok(())
}

pub fn run_vault(vault: &Vault, action: VaultCommand) -> Result<()> {
    match action {
        VaultCommand::Status => {
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
        VaultCommand::List { all } => {
            let items = vault.list_connections()?;
            if all {
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
        VaultCommand::Show { item } => {
            let id = resolve_cli_item_id(vault, &item)?;
            let found = vault.get_connection(id)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&found.stored.public(Some(&found.secrets)))?
            );
            Ok(())
        }
        VaultCommand::Enable { item } => {
            let id = resolve_cli_item_id(vault, &item)?;
            vault.set_connection_enabled(id, true)?;
            println!("Enabled item {id}");
            Ok(())
        }
        VaultCommand::Disable { item } => {
            let id = resolve_cli_item_id(vault, &item)?;
            vault.set_connection_enabled(id, false)?;
            println!("Disabled item {id}");
            Ok(())
        }
        VaultCommand::Trash { item } => {
            let id = resolve_cli_item_id(vault, &item)?;
            vault.trash_connection(id, None)?;
            println!("Moved item {id} to trash");
            Ok(())
        }
        VaultCommand::Restore { item } => {
            let trash = vault.trash_items()?;
            let trimmed = item.trim();
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
        VaultCommand::Pin { action } => match action {
            VaultPinCommand::Status => {
                println!(
                    "{}",
                    serde_json::json!({ "ownerPinConfigured": vault.owner_pin_configured()? })
                );
                Ok(())
            }
            VaultPinCommand::Set { pin_env } => {
                let pin = match pin_env {
                    Some(var) => Zeroizing::new(
                        env::var(&var)
                            .with_context(|| format!("Environment variable '{var}' is not set"))?,
                    ),
                    None => {
                        let first = read_secret_line_hidden("Enter 6-digit Owner PIN: ")?;
                        let second = read_secret_line_hidden("Confirm 6-digit Owner PIN: ")?;
                        if *first != *second {
                            anyhow::bail!("PINs do not match");
                        }
                        first
                    }
                };
                vault.set_owner_pin(pin.trim())?;
                println!("Owner PIN configured");
                Ok(())
            }
            VaultPinCommand::Clear { force } => {
                use std::io::{BufRead, IsTerminal, Write};
                let cleared = clear_owner_pin_with_confirmation(
                    vault,
                    force,
                    std::io::stdin().is_terminal(),
                    || {
                        eprint!(
                            "This clears the Owner PIN without verifying the current PIN (local forgot-PIN recovery).\nType 'clear' to confirm: "
                        );
                        let _ = std::io::stderr().flush();
                        let mut line = String::new();
                        std::io::stdin()
                            .lock()
                            .read_line(&mut line)
                            .context("Unable to read confirmation from stdin")?;
                        Ok(line)
                    },
                )?;
                if cleared {
                    println!("Owner PIN cleared");
                } else {
                    println!("No Owner PIN is configured");
                }
                Ok(())
            }
        },
    }
}

fn clear_owner_pin_with_confirmation<F>(
    vault: &Vault,
    force: bool,
    is_terminal: bool,
    read_confirmation: F,
) -> Result<bool>
where
    F: FnOnce() -> Result<String>,
{
    if !vault.owner_pin_configured()? {
        return Ok(false);
    }
    if !force {
        if !is_terminal {
            anyhow::bail!(
                "Refused: `openkeylet vault pin clear` is a local forgot-PIN recovery command that does not verify the current PIN. Run it in an interactive terminal to confirm, or pass --force explicitly."
            );
        }
        let response = read_confirmation()?;
        if response.trim() != "clear" {
            anyhow::bail!("Cancelled: Owner PIN was not cleared");
        }
    }
    vault.disable_owner_pin()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn vault_pin_clear_requires_interactive_confirmation_or_force() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path().join("vault")).unwrap();

        // No PIN configured is a no-op regardless of force/tty.
        assert!(!clear_owner_pin_with_confirmation(&vault, false, false, || Ok(String::new())).unwrap());

        vault.set_owner_pin("123456").unwrap();

        // Non-interactive call without --force is refused.
        let non_tty_err =
            clear_owner_pin_with_confirmation(&vault, false, false, || Ok("clear".into()))
                .unwrap_err()
                .to_string();
        assert!(non_tty_err.contains("--force"), "{non_tty_err}");
        assert!(vault.owner_pin_configured().unwrap());

        // Interactive call with wrong confirmation is cancelled.
        let wrong_confirm =
            clear_owner_pin_with_confirmation(&vault, false, true, || Ok("no\n".into()))
                .unwrap_err()
                .to_string();
        assert!(wrong_confirm.contains("Cancelled"), "{wrong_confirm}");
        assert!(vault.owner_pin_configured().unwrap());

        // Interactive call with exact "clear" succeeds.
        assert!(clear_owner_pin_with_confirmation(&vault, false, true, || Ok("clear\n".into())).unwrap());
        assert!(!vault.owner_pin_configured().unwrap());

        // --force works non-interactively for explicit local recovery.
        vault.set_owner_pin("654321").unwrap();
        assert!(clear_owner_pin_with_confirmation(&vault, true, false, || unreachable!()).unwrap());
        assert!(!vault.owner_pin_configured().unwrap());
    }
}
