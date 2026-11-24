//! Authenticated loopback RAM-key broker for Strong Cloud Vault mode.
//!
//! When Strong Mode is enabled, no vault decryption key is stored on disk or in
//! the OS keyring. The unlocked desktop application keeps the 256-bit DEK only
//! in RAM and exposes a short-lived loopback broker authenticated with a random
//! per-session token so local `openkeylet mcp stdio` processes can operate while
//! the desktop app is unlocked, and immediately lose access on lock or quit.

use crate::vault::Vault;
use anyhow::{Context, Result};
use atomic_write_file::AtomicWriteFile;
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const BROKER_FILE: &str = "session-broker.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrokerDescriptor {
    port: u16,
    token: String,
    session_id: String,
}

struct RunningBroker {
    port: u16,
    shutdown: Arc<AtomicBool>,
    descriptor_path: PathBuf,
}

impl RunningBroker {
    fn stop(self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = fs::remove_file(&self.descriptor_path);
        // Wake the blocking accept() loop so the thread exits promptly.
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, self.port));
        let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(100));
    }
}

pub struct SessionBroker {
    data_dir: PathBuf,
    running: Mutex<Option<RunningBroker>>,
}

impl SessionBroker {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            running: Mutex::new(None),
        }
    }

    pub fn start(&self, vault: Vault) -> Result<()> {
        self.stop();
        if !vault.is_strong_mode() || !vault.is_strong_unlocked() {
            return Ok(());
        }
        fs::create_dir_all(&self.data_dir)
            .context("Unable to create OpenKeylet data directory for session broker")?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .context("Unable to bind local Strong Vault session broker")?;
        let port = listener.local_addr()?.port();
        let token = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
        let session_id = uuid::Uuid::new_v4().to_string();
        let descriptor_path = self.data_dir.join(BROKER_FILE);
        write_descriptor(
            &descriptor_path,
            &BrokerDescriptor {
                port,
                token: token.clone(),
                session_id: session_id.clone(),
            },
        )?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        thread::Builder::new()
            .name("openkeylet-session-broker".to_owned())
            .spawn(move || {
                for incoming in listener.incoming() {
                    if thread_shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(stream) = incoming else {
                        continue;
                    };
                    if thread_shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    handle_client(stream, &token, &session_id, &vault);
                }
            })
            .context("Unable to spawn Strong Vault session broker thread")?;

        if let Ok(mut slot) = self.running.lock() {
            *slot = Some(RunningBroker {
                port,
                shutdown,
                descriptor_path,
            });
        }
        Ok(())
    }

    pub fn stop(&self) {
        if let Ok(mut slot) = self.running.lock()
            && let Some(active) = slot.take()
        {
            active.stop();
        }
        let _ = fs::remove_file(self.data_dir.join(BROKER_FILE));
    }
}

impl Drop for SessionBroker {
    fn drop(&mut self) {
        self.stop();
    }
}

fn handle_client(mut stream: TcpStream, expected_token: &str, session_id: &str, vault: &Vault) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(1500)));
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.len() > 256 {
        let _ = stream.write_all(b"DENIED\n");
        return;
    }
    let candidate = line.trim().as_bytes();
    let expected = expected_token.as_bytes();
    let authorized =
        candidate.len() == expected.len() && bool::from(candidate.ct_eq(expected));
    if !authorized {
        let _ = stream.write_all(b"DENIED\n");
        return;
    }
    let Some(dek) = vault.export_ram_dek_for_broker() else {
        let _ = stream.write_all(b"LOCKED\n");
        return;
    };
    let encoded = Zeroizing::new(STANDARD_NO_PAD.encode(*dek));
    let response = Zeroizing::new(format!("OK {} {}\n", encoded.as_str(), session_id));
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn write_descriptor(path: &Path, descriptor: &BrokerDescriptor) -> Result<()> {
    let bytes = serde_json::to_vec(descriptor)?;
    let mut file = AtomicWriteFile::open(path)
        .context("Unable to create Strong Vault session broker descriptor")?;
    file.write_all(&bytes)
        .context("Unable to write Strong Vault session broker descriptor")?;
    file.commit()
        .context("Unable to commit Strong Vault session broker descriptor")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn is_session_still_valid(data_dir: &Path, expected_session_id: &str) -> bool {
    let Ok(bytes) = fs::read(data_dir.join(BROKER_FILE)) else {
        return false;
    };
    let Ok(descriptor) = serde_json::from_slice::<BrokerDescriptor>(&bytes) else {
        return false;
    };
    descriptor.session_id == expected_session_id
}

pub fn try_fetch_ram_key(data_dir: &Path) -> Option<(Zeroizing<[u8; 32]>, String)> {
    let bytes = fs::read(data_dir.join(BROKER_FILE)).ok()?;
    let descriptor: BrokerDescriptor = serde_json::from_slice(&bytes).ok()?;
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, descriptor.port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(1000)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(1500)));
    let req = Zeroizing::new(format!("{}\n", descriptor.token));
    stream.write_all(req.as_bytes()).ok()?;
    stream.flush().ok()?;
    let mut line = Zeroizing::new(String::new());
    BufReader::new(&stream).read_line(&mut line).ok()?;
    let mut parts = line.trim().split_whitespace();
    if parts.next() != Some("OK") {
        return None;
    }
    let encoded_key = parts.next()?;
    let session_id = parts.next()?.to_owned();
    let decoded = Zeroizing::new(STANDARD_NO_PAD.decode(encoded_key).ok()?);
    let dek: [u8; 32] = decoded.as_slice().try_into().ok()?;
    Some((Zeroizing::new(dek), session_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ConnectionInput;
    use tempfile::tempdir;

    #[test]
    fn broker_serves_ram_key_while_unlocked_and_revokes_immediately_on_lock() {
        let temp = tempdir().unwrap();
        let data_dir = temp.path().join("vault");
        let desktop_vault = Vault::open(data_dir.clone()).unwrap();
        let input: ConnectionInput = serde_json::from_value(serde_json::json!({
            "name": "BrokerSecret",
            "modules": [
                { "kind": "password" }
            ],
            "secrets": { "password": "ultra-secret-password" }
        }))
        .unwrap();
        desktop_vault.save_connection(input).unwrap();

        let recovery_key = format!("okv1_{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9_u8; 32]));
        desktop_vault
            .enable_strong_mode("Correct-Horse-Battery-Staple-2026!", &recovery_key)
            .unwrap();
        assert!(!data_dir.join("master.key").exists());
        assert!(data_dir.join(crate::crypto::STRONG_KEY_FILE).is_file());

        // Child MCP process opens Vault while broker is NOT started yet -> locked!
        let mcp_vault = Vault::open(data_dir.clone()).unwrap();
        assert!(mcp_vault.is_strong_mode());
        assert!(mcp_vault.list_decrypted_connections().is_err());

        // Start desktop broker while desktop vault is unlocked -> child MCP transparently works!
        let broker = SessionBroker::new(data_dir.clone());
        broker.start(desktop_vault.clone()).unwrap();
        let items = mcp_vault.list_decrypted_connections().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].secrets.get("password"), Some("ultra-secret-password"));

        // Lock desktop vault & stop broker -> child MCP immediately loses access!
        desktop_vault.lock_strong();
        broker.stop();
        assert!(mcp_vault.list_decrypted_connections().is_err());
    }
}
