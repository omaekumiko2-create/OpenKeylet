//! CLI owner-only management of SSH host keys pinned on first use.

use super::{SshCommand, prompt::read_secret_line_hidden};
use crate::{ssh_host_keys, vault::Vault};
use anyhow::{Context, Result};
use std::{
    env,
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

/// The host key store is a separate plaintext file; the vault is opened only
/// to check the Owner PIN before a pin is removed.
pub fn run_ssh(data_dir: PathBuf, action: SshCommand) -> Result<()> {
    match action {
        SshCommand::Hosts => {
            let hosts = ssh_host_keys::list(&data_dir)?;
            println!("{}", serde_json::to_string_pretty(&hosts)?);
            Ok(())
        }
        SshCommand::ForgetHost {
            host,
            port,
            pin_env,
        } => {
            let port = port.map(super::validate_nonzero_port).transpose()?;
            if host.trim().is_empty() {
                anyhow::bail!("Host must not be empty");
            }
            require_owner_pin(&data_dir, pin_env)?;
            let removed = ssh_host_keys::forget(&data_dir, &host, port)?;
            let target = match port {
                Some(port) => ssh_host_keys::host_port_key(&host, port),
                None => host.trim().to_owned(),
            };
            println!(
                "Removed {removed} pinned SSH host key {} for {target}",
                if removed == 1 { "entry" } else { "entries" }
            );
            Ok(())
        }
    }
}

fn require_owner_pin(data_dir: &Path, pin_env: Option<String>) -> Result<()> {
    let vault = Vault::open(data_dir.to_path_buf())?;
    if !vault.owner_pin_configured()? {
        return Ok(());
    }
    let pin = match pin_env {
        Some(var) => Zeroizing::new(
            env::var(&var).with_context(|| format!("Environment variable '{var}' is not set"))?,
        ),
        None => read_secret_line_hidden("Enter 6-digit Owner PIN: ")?,
    };
    if !vault.verify_owner_pin(pin.trim())? {
        // Space out guesses like the loopback PIN endpoints do.
        std::thread::sleep(Duration::from_secs(1));
        anyhow::bail!("Incorrect Owner PIN");
    }
    Ok(())
}
