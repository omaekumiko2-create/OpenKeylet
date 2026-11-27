//! CLI subcommands for connecting AI agents (`openkeylet agent ...`) and
//! one-shot post-install setup (`openkeylet setup`).

use super::{AgentCommand, SetupArgs};
use crate::{
    agents::{AgentActionResult, AgentRegistry},
    platform, updater,
    vault::Vault,
};
use anyhow::{Result, bail};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentCommandReport {
    executable: String,
    action: String,
    results: Vec<AgentActionResult>,
    restart_required: bool,
    all_ok: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SetupReport {
    version: String,
    platform: String,
    executable: String,
    data_dir: String,
    key_source: String,
    browser_extension_path: Option<String>,
    desktop_shortcut: Option<bool>,
    launch_at_login: Option<bool>,
    gui_launched: bool,
    agents: Vec<AgentActionResult>,
    warnings: Vec<String>,
    restart_required: bool,
    next_steps: Vec<String>,
}

pub async fn run_agent(action: AgentCommand) -> Result<i32> {
    let executable = platform::launcher_executable()?;
    let registry = AgentRegistry::new(executable)?;
    run_agent_with_registry(&registry, action).await
}

pub(super) async fn run_agent_with_registry(
    registry: &AgentRegistry,
    action: AgentCommand,
) -> Result<i32> {
    match action {
        AgentCommand::List { json } => {
            let clients = registry.list().await;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "executable": registry.executable_path().to_string_lossy(),
                        "clients": clients,
                    }))?
                );
            } else {
                println!(
                    "OpenKeylet executable: {}",
                    registry.executable_path().display()
                );
                for client in &clients {
                    println!(
                        "  {:<18} {:<12} {}",
                        client.client_id, client.state, client.message
                    );
                }
            }
            Ok(0)
        }
        AgentCommand::Connect {
            clients,
            detected: _,
            all: _,
            json,
        } => {
            let explicit = !clients.is_empty();
            let results = if explicit {
                let normalized = normalize_client_list(&clients)?;
                let mut out = Vec::with_capacity(normalized.len());
                for id in normalized {
                    out.push(registry.connect_or_repair(id).await);
                }
                out
            } else {
                registry.sync_detected(true).await
            };
            emit_agent_report(registry, "connect", results, explicit, json)
        }
        AgentCommand::Repair {
            clients,
            all: _,
            json,
        } => {
            let explicit = !clients.is_empty();
            let results = if explicit {
                let normalized = normalize_client_list(&clients)?;
                let mut out = Vec::with_capacity(normalized.len());
                for id in normalized {
                    out.push(registry.repair(id).await);
                }
                out
            } else {
                let statuses = registry.list().await;
                let mut out = Vec::new();
                for status in statuses {
                    if status.detected && status.can_repair {
                        out.push(registry.repair(&status.client_id).await);
                    }
                }
                out
            };
            emit_agent_report(registry, "repair", results, explicit, json)
        }
        AgentCommand::Remove { clients, json } => {
            let normalized = normalize_client_list(&clients)?;
            let mut results = Vec::with_capacity(normalized.len());
            for id in normalized {
                results.push(registry.remove(id).await);
            }
            emit_agent_report(registry, "remove", results, true, json)
        }
        AgentCommand::Sync { json } => {
            let results = registry.sync_detected(false).await;
            emit_agent_report(registry, "sync", results, false, json)
        }
    }
}

pub async fn run_setup(vault: &Vault, args: SetupArgs) -> Result<i32> {
    let executable = platform::launcher_executable()?;
    let registry = AgentRegistry::new(executable.clone())?;
    run_setup_with_registry(vault, &executable, &registry, args).await
}

pub(super) async fn run_setup_with_registry(
    vault: &Vault,
    executable: &Path,
    registry: &AgentRegistry,
    args: SetupArgs,
) -> Result<i32> {
    updater::cleanup_previous_update_artifacts(executable, vault.data_dir());

    let mut warnings = Vec::new();
    #[cfg_attr(not(feature = "gui"), allow(unused_mut))]
    let mut desktop_shortcut = None;
    #[cfg_attr(not(feature = "gui"), allow(unused_mut))]
    let mut launch_at_login = None;

    #[cfg(feature = "gui")]
    {
        #[cfg(target_os = "linux")]
        if let Err(error) = crate::system_integration::ensure_application_entry(executable) {
            warnings.push(format!("Desktop menu entry skipped: {error}"));
        }

        if args.shortcut {
            match crate::system_integration::set_desktop_shortcut(executable, true) {
                Ok(state) => desktop_shortcut = Some(state.desktop_shortcut),
                Err(error) => warnings.push(format!("Desktop shortcut skipped: {error}")),
            }
        }
        if args.autostart {
            match crate::system_integration::set_launch_at_login(executable, true) {
                Ok(state) => launch_at_login = Some(state.launch_at_login),
                Err(error) => warnings.push(format!("Launch at login skipped: {error}")),
            }
        }
    }

    #[cfg(not(feature = "gui"))]
    {
        if args.shortcut {
            warnings.push("Desktop shortcut is not applicable to the headless build.".to_owned());
        }
        if args.autostart {
            warnings.push("Launch at login is not applicable to the headless build.".to_owned());
        }
    }

    let explicit_clients = !args.clients.is_empty();
    let agent_results = if args.no_connect_agents {
        Vec::new()
    } else if explicit_clients {
        let normalized = normalize_client_list(&args.clients)?;
        let mut out = Vec::with_capacity(normalized.len());
        for id in normalized {
            out.push(registry.connect_or_repair(id).await);
        }
        out
    } else {
        registry.sync_detected(true).await
    };

    for result in &agent_results {
        if !result.ok {
            warnings.push(format!(
                "Agent '{}' ({}): {}",
                result.client.client_id, result.client.state, result.client.message
            ));
        }
    }

    let browser_extension_path = platform::find_browser_extension_dir(executable)
        .map(|path| path.to_string_lossy().into_owned());

    #[cfg_attr(not(feature = "gui"), allow(unused_mut))]
    let mut gui_launched = false;
    if args.launch {
        #[cfg(feature = "gui")]
        {
            match launch_gui_detached(executable) {
                Ok(()) => gui_launched = true,
                Err(error) => warnings.push(format!("Unable to launch desktop GUI: {error}")),
            }
        }
        #[cfg(not(feature = "gui"))]
        {
            warnings.push(
                "Cannot launch desktop GUI from the headless build; use `openkeylet admin serve` or CLI commands."
                    .to_owned(),
            );
        }
    }

    let restart_required = agent_results
        .iter()
        .any(|item| item.ok && item.client.restart_required);
    let any_connected = agent_results
        .iter()
        .any(|item| item.client.state == "registered");

    let mut next_steps = Vec::new();
    if restart_required {
        next_steps.push(
            "Restart or start a new AI agent session so the updated OpenKeylet MCP tools load."
                .to_owned(),
        );
    }
    if any_connected {
        next_steps.push(
            "Verify in a fresh agent session: \"List the enabled items you can see in OpenKeylet MCP.\""
                .to_owned(),
        );
    } else if !args.no_connect_agents {
        next_steps.push(
            "No supported AI agent client was auto-detected; run `openkeylet config stdio-json` or `openkeylet config stdio-toml` for manual MCP setup."
                .to_owned(),
        );
    }
    if let Some(ref ext_path) = browser_extension_path {
        next_steps.push(format!(
            "Optional browser autofill & Passkeys: open OpenKeylet -> SYSTEM -> WEB / 04 and load the extension from {ext_path}."
        ));
    }

    let report = SetupReport {
        version: updater::current_version().to_owned(),
        platform: updater::current_platform_key().to_owned(),
        executable: executable.to_string_lossy().into_owned(),
        data_dir: vault.data_dir().to_string_lossy().into_owned(),
        key_source: vault.storage_label().to_owned(),
        browser_extension_path,
        desktop_shortcut,
        launch_at_login,
        gui_launched,
        agents: agent_results,
        warnings,
        restart_required,
        next_steps,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "OpenKeylet {} ({}) is ready.",
            report.version, report.platform
        );
        println!("  Executable : {}", report.executable);
        println!("  Vault data : {} ({})", report.data_dir, report.key_source);
        if let Some(ref ext) = report.browser_extension_path {
            println!("  Extension  : {ext}");
        }
        if !report.agents.is_empty() {
            println!("  Agents     :");
            for item in &report.agents {
                let badge = if item.ok { "OK" } else { "WARN" };
                println!(
                    "    [{badge}] {:<18} ({:<9}) {}",
                    item.client.client_id, item.action, item.client.message
                );
            }
        }
        for warning in &report.warnings {
            eprintln!("Warning: {warning}");
        }
        if !report.next_steps.is_empty() {
            println!("Next steps:");
            for step in &report.next_steps {
                println!("  - {step}");
            }
        }
    }

    let explicit_failed = explicit_clients && report.agents.iter().any(|item| !item.ok);
    Ok(if explicit_failed { 1 } else { 0 })
}

fn normalize_client_list(raw: &[String]) -> Result<Vec<&'static str>> {
    let mut normalized = Vec::with_capacity(raw.len());
    for entry in raw {
        let Some(id) = AgentRegistry::normalize_client_id(entry) else {
            bail!(
                "Unsupported agent client '{}'. Supported clients: {}",
                entry,
                AgentRegistry::supported_client_ids().join(", ")
            );
        };
        if !normalized.contains(&id) {
            normalized.push(id);
        }
    }
    Ok(normalized)
}

fn emit_agent_report(
    registry: &AgentRegistry,
    action: &str,
    results: Vec<AgentActionResult>,
    explicit: bool,
    json: bool,
) -> Result<i32> {
    let restart_required = results
        .iter()
        .any(|item| item.ok && item.client.restart_required);
    let all_ok = results.iter().all(|item| item.ok);
    let has_hard_error = results
        .iter()
        .any(|item| !item.ok && item.client.state == "error");

    if json {
        let report = AgentCommandReport {
            executable: registry.executable_path().to_string_lossy().into_owned(),
            action: action.to_owned(),
            results,
            restart_required,
            all_ok,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if results.is_empty() {
        println!(
            "No matching AI agent clients required changes for `{action}`. Run `openkeylet agent list` to inspect client status."
        );
    } else {
        for item in &results {
            let badge = if item.ok { "OK" } else { "WARN" };
            println!(
                "[{badge}] {:<18} {:<10} {}",
                item.client.client_id, item.action, item.client.message
            );
        }
        if restart_required {
            println!("Restart or start a new agent session so the updated MCP config takes effect.");
        }
    }

    if (explicit && !all_ok) || has_hard_error {
        Ok(1)
    } else {
        Ok(0)
    }
}

#[cfg(feature = "gui")]
fn launch_gui_detached(executable: &Path) -> Result<()> {
    use anyhow::Context;
    use std::process::{Command, Stdio};

    #[cfg(target_os = "macos")]
    if let Some(bundle) = platform::macos_app_bundle(executable) {
        Command::new("/usr/bin/open")
            .arg("-a")
            .arg(&bundle)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("Unable to open {}", bundle.display()))?;
        return Ok(());
    }

    let mut command = Command::new(executable);
    command
        .arg("gui")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    command
        .spawn()
        .with_context(|| format!("Unable to launch {}", executable.display()))?;
    Ok(())
}
