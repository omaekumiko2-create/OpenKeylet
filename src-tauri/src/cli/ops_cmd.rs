//! CLI operational subcommands: browser bridge, backups, headless admin server, and updater.

use super::{
    AdminCommand, BackupAction, BackupArgs, BrowserCommand, UpdateCommand,
    prompt::{PassphraseSource, obtain_passphrase},
};
use crate::{
    admin::{self, AdminServerConfig, DEFAULT_ADMIN_PORT},
    agents::AgentRegistry,
    backup,
    browser::BrowserBridge,
    model::SettingsPatch,
    platform,
    storage::resolve_user_path,
    updater,
    vault::Vault,
};
use anyhow::{Context, Result};
use std::{
    env,
    io::IsTerminal,
    path::Path,
    time::{Duration, Instant},
};
use tokio::time::sleep;
use zeroize::Zeroizing;

pub async fn run_update(vault: &Vault, action: UpdateCommand) -> Result<()> {
    let executable = platform::launcher_executable()?;
    updater::cleanup_previous_update_artifacts(&executable, vault.data_dir());
    let manager = updater::UpdateManager::new(vault.clone(), executable.clone());
    let outcome = manager.check_for_updates(true, |_| {}).await?;

    let UpdateCommand::Install {
        json,
        relaunch,
        no_sync_agents,
    } = action
    else {
        println!("{}", serde_json::to_string_pretty(&outcome.status)?);
        return Ok(());
    };

    let previous_version = outcome.status.current_version.clone();
    if !outcome.update_available {
        let mut agent_sync = None;
        let mut restart_required = false;
        if !no_sync_agents
            && let Ok(registry) = AgentRegistry::new(executable.clone())
        {
            let synced = registry.sync_detected(false).await;
            restart_required = synced.iter().any(|item| item.ok && item.client.restart_required);
            agent_sync = Some(serde_json::to_value(&synced)?);
        }
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "updated": false,
                    "alreadyUpToDate": true,
                    "previousVersion": previous_version,
                    "currentVersion": outcome.status.current_version,
                    "latestVersion": outcome.status.latest_version,
                    "platform": outcome.status.platform,
                    "executable": executable.to_string_lossy(),
                    "signatureVerified": outcome.status.signature_verified,
                    "relaunchRequested": false,
                    "agentSync": agent_sync,
                    "restartRequired": restart_required,
                }))?
            );
        } else {
            println!(
                "OpenKeylet {} is already up to date.",
                outcome.status.current_version
            );
            if restart_required {
                println!(
                    "Managed agent rules were refreshed; restart your AI agent session to load them."
                );
            }
        }
        return Ok(());
    }

    let target_version = outcome
        .status
        .latest_version
        .clone()
        .unwrap_or_else(|| "latest".to_owned());
    if !json {
        eprintln!(
            "Downloading and verifying OpenKeylet {} ({})...",
            target_version, outcome.status.platform
        );
    }
    manager.download_and_stage(|_| {}).await?;
    let effective_relaunch = relaunch && cfg!(feature = "gui");
    manager
        .apply_and_relaunch(effective_relaunch, |_| {})
        .await?;

    let (agent_sync, sync_restart_required, agent_sync_warning) = if no_sync_agents {
        (None, false, None)
    } else {
        sync_agents_with_updated_binary(&executable).await
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "updated": true,
                "alreadyUpToDate": false,
                "previousVersion": previous_version,
                "newVersion": target_version,
                "platform": outcome.status.platform,
                "executable": executable.to_string_lossy(),
                "releaseUrl": outcome.status.release_url,
                "signatureVerified": outcome.status.signature_verified,
                "relaunchRequested": effective_relaunch,
                "agentSync": agent_sync,
                "agentSyncWarning": agent_sync_warning,
                "restartRequired": true,
                "agentRulesRefreshed": sync_restart_required,
            }))?
        );
    } else {
        println!(
            "OpenKeylet updated from {previous_version} to {target_version}. Restart any running OpenKeylet processes and AI agent sessions to use the new version."
        );
        if let Some(warning) = agent_sync_warning {
            eprintln!("Note: post-update agent sync skipped ({warning}).");
        }
    }
    Ok(())
}

/// Invoke the newly installed executable on disk so any updated managed agent
/// instructions from the new release are synced immediately without failing the update.
async fn sync_agents_with_updated_binary(
    executable: &Path,
) -> (Option<serde_json::Value>, bool, Option<String>) {
    let future = tokio::process::Command::new(executable)
        .args(["agent", "sync", "--json"])
        .stdin(std::process::Stdio::null())
        .output();
    let output = match tokio::time::timeout(Duration::from_secs(15), future).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => return (None, false, Some(error.to_string())),
        Err(_) => return (None, false, Some("timed out after 15s".to_owned())),
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let detail = if stderr.is_empty() {
            format!("exited with {}", output.status)
        } else {
            stderr
        };
        return (None, false, Some(detail));
    }
    match serde_json::from_slice::<serde_json::Value>(&output.stdout) {
        Ok(value) => {
            let restart = value
                .get("restartRequired")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            (Some(value), restart, None)
        }
        Err(error) => (
            None,
            false,
            Some(format!("invalid JSON output from updated binary: {error}")),
        ),
    }
}

pub async fn run_browser(vault: &Vault, action: BrowserCommand) -> Result<()> {
    match action {
        BrowserCommand::Status => print_browser_status(vault).await,
        BrowserCommand::Enable { port } => {
            let port = port.map(super::validate_nonzero_port).transpose()?;
            set_browser_enabled(vault, true, port).await
        }
        BrowserCommand::Disable => set_browser_enabled(vault, false, None).await,
        BrowserCommand::Pair { port } => {
            let port = port.map(super::validate_nonzero_port).transpose()?;
            pair_browser(vault, port).await
        }
        BrowserCommand::Reset => reset_browser(vault).await,
    }
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

/// How `backup export` protects the file.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ExportProtection {
    Passphrase(PassphraseSource),
    SelfUnlocking,
}

/// A self-unlocking `.mvault` is as readable as the plaintext it contains, so it is only
/// written when asked for by name. The default asks for a passphrase, and refuses rather
/// than falling back when there is no terminal to ask on.
pub(super) fn export_protection(args: &BackupArgs, stdin_is_terminal: bool) -> Result<ExportProtection> {
    if args.self_unlocking {
        return Ok(ExportProtection::SelfUnlocking);
    }
    match args.passphrase_source() {
        PassphraseSource::None if stdin_is_terminal => {
            Ok(ExportProtection::Passphrase(PassphraseSource::Prompt))
        }
        PassphraseSource::None => anyhow::bail!(
            "A backup needs a passphrase and no terminal is attached to ask for one. Pass --passphrase-env <VAR> or --passphrase-stdin, or --self-unlocking to write a file that unlocks itself (anyone who copies it can read every secret)."
        ),
        source => Ok(ExportProtection::Passphrase(source)),
    }
}

pub fn run_backup(vault: &Vault, args: BackupArgs) -> Result<()> {
    let path = resolve_user_path(&args.file)?;
    match args.action {
        BackupAction::Export => match export_protection(&args, std::io::stdin().is_terminal())? {
            ExportProtection::SelfUnlocking => {
                backup::export_to_file(vault, &path)?;
                eprintln!(
                    "Warning: this self-unlocking .mvault carries its own unlock key; anyone who copies it can read every secret. Keep it off shared and synced folders, or re-export with a passphrase."
                );
                println!("Self-unlocking backup written to {}", args.file);
                Ok(())
            }
            ExportProtection::Passphrase(source) => {
                let passphrase =
                    obtain_passphrase(&source, matches!(source, PassphraseSource::Prompt))?;
                backup::export_protected(vault, &path, &passphrase)?;
                eprintln!(
                    "Warning: losing this passphrase makes the backup permanently unrecoverable."
                );
                println!("Passphrase-protected backup written to {}", args.file);
                Ok(())
            }
        },
        BackupAction::Import => {
            anyhow::ensure!(
                !args.self_unlocking,
                "--self-unlocking only applies to `backup export`; import detects the file type itself"
            );
            let source = args.passphrase_source();
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
    }
}

pub async fn run_admin(vault: Vault, action: AdminCommand) -> Result<()> {
    match action {
        AdminCommand::Serve {
            port,
            bind,
            allow_non_loopback,
            token_env,
        } => {
            let mut config = AdminServerConfig {
                port: super::validate_nonzero_port(port.unwrap_or(DEFAULT_ADMIN_PORT))?,
                allow_non_loopback,
                ..AdminServerConfig::default()
            };
            if let Some(ip) = bind {
                config.bind_ip = ip;
            }
            if let Some(var) = token_env {
                let val = env::var(&var)
                    .with_context(|| format!("Environment variable '{var}' is not set"))?;
                config.initial_token = Some(Zeroizing::new(val));
            }
            admin::serve_until_ctrl_c(vault, config).await
        }
    }
}
