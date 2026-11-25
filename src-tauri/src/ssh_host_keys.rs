//! Device-local SSH host key pinning (trust on first use).
//!
//! The first handshake with `<host>:<port>` records the server's host key
//! fingerprint in `<data_dir>/ssh-known-hosts.json`; every later handshake
//! must present a pinned key or the connection is refused before any
//! credentials are sent. The store is a separate plaintext file that is never
//! synced or exported, and only the vault owner can drop a pin
//! (`openkeylet ssh forget-host`).

use anyhow::{Context, Result, bail};
use atomic_write_file::AtomicWriteFile;
use chrono::Utc;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    net::Ipv6Addr,
    path::Path,
};

pub const KNOWN_HOSTS_FILE: &str = "ssh-known-hosts.json";
const KNOWN_HOSTS_LOCK_FILE: &str = "ssh-known-hosts.lock";
const KNOWN_HOSTS_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PinnedHostKey {
    algorithm: String,
    fingerprint: String,
    first_seen: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct KnownHostsDocument {
    version: u32,
    hosts: BTreeMap<String, Vec<PinnedHostKey>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyVerdict {
    /// No key was pinned for this host:port; the presented key is now pinned.
    Pinned,
    /// The presented key equals a pinned key.
    Matched,
    /// A key is pinned for this host:port and the presented key is different.
    Mismatch { expected: Vec<String>, actual: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownHost {
    /// Normalized `host:port` (IPv6 literals as `[addr]:port`).
    pub host: String,
    pub algorithm: String,
    pub fingerprint: String,
    pub first_seen: String,
}

/// Normalized store key: host trimmed and lowercased, IPv6 literals bracketed.
pub fn host_port_key(host: &str, port: u16) -> String {
    format!("{}:{port}", normalize_host(host))
}

fn normalize_host(host: &str) -> String {
    let trimmed = host.trim();
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(trimmed);
    let lowered = unbracketed.to_lowercase();
    if let Ok(address) = lowered.parse::<Ipv6Addr>() {
        return format!("[{address}]");
    }
    if lowered.contains(':') {
        return format!("[{lowered}]");
    }
    lowered
}

/// Accept the presented key if it is pinned for `host:port`, pin it if nothing
/// is pinned yet, and report a mismatch otherwise. An unreadable or corrupt
/// store is an error, never a silent re-pin.
pub fn verify_or_pin(
    data_dir: &Path,
    host: &str,
    port: u16,
    algorithm: &str,
    fingerprint: &str,
) -> Result<HostKeyVerdict> {
    if host.trim().is_empty() {
        bail!("SSH host is empty");
    }
    if fingerprint.trim().is_empty() {
        bail!("SSH server presented an empty host key fingerprint");
    }
    let key = host_port_key(host, port);
    with_store_lock(data_dir, || {
        let mut document = load(&data_dir.join(KNOWN_HOSTS_FILE))?;
        if let Some(pins) = document.hosts.get(&key).filter(|pins| !pins.is_empty()) {
            if pins.iter().any(|pin| pin.fingerprint == fingerprint) {
                return Ok(HostKeyVerdict::Matched);
            }
            return Ok(HostKeyVerdict::Mismatch {
                expected: pins.iter().map(|pin| pin.fingerprint.clone()).collect(),
                actual: fingerprint.to_owned(),
            });
        }
        document.hosts.insert(
            key,
            vec![PinnedHostKey {
                algorithm: algorithm.to_owned(),
                fingerprint: fingerprint.to_owned(),
                first_seen: Utc::now().to_rfc3339(),
            }],
        );
        save(data_dir, &document)?;
        Ok(HostKeyVerdict::Pinned)
    })
}

pub fn list(data_dir: &Path) -> Result<Vec<KnownHost>> {
    let document = load(&data_dir.join(KNOWN_HOSTS_FILE))?;
    Ok(document
        .hosts
        .into_iter()
        .flat_map(|(host, pins)| {
            pins.into_iter().map(move |pin| KnownHost {
                host: host.clone(),
                algorithm: pin.algorithm,
                fingerprint: pin.fingerprint,
                first_seen: pin.first_seen,
            })
        })
        .collect())
}

/// Remove pinned keys for `host:port`, or for every port of `host` when `port`
/// is `None`. Returns the number of pinned keys removed.
pub fn forget(data_dir: &Path, host: &str, port: Option<u16>) -> Result<usize> {
    if host.trim().is_empty() {
        bail!("SSH host is empty");
    }
    let normalized = normalize_host(host);
    let exact = port.map(|port| host_port_key(host, port));
    with_store_lock(data_dir, || {
        let mut document = load(&data_dir.join(KNOWN_HOSTS_FILE))?;
        let mut removed = 0;
        document.hosts.retain(|key, pins| {
            let matches = match &exact {
                Some(exact) => key == exact,
                None => key
                    .rsplit_once(':')
                    .is_some_and(|(key_host, _)| key_host == normalized),
            };
            if matches {
                removed += pins.len();
            }
            !matches
        });
        if removed > 0 {
            save(data_dir, &document)?;
        }
        Ok(removed)
    })
}

/// Actionable rejection text for a host key that differs from the pinned one.
pub fn mismatch_message(host: &str, port: u16, expected: &[String], actual: &str) -> String {
    format!(
        "SSH host key for {} does not match the key pinned on first use (pinned {}, server presented {actual}). No credentials were sent. A changed host key can mean the connection is being intercepted, so do not reset this pin on the owner's behalf: report it to the vault owner. If the server was reinstalled or rotated its host key, the owner can confirm that and run `openkeylet ssh forget-host {} --port {port}`, then retry.",
        host_port_key(host, port),
        expected.join(", "),
        host.trim()
    )
}

fn with_store_lock<T>(data_dir: &Path, action: impl FnOnce() -> Result<T>) -> Result<T> {
    fs::create_dir_all(data_dir).context("Unable to create the OpenKeylet data directory")?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(data_dir.join(KNOWN_HOSTS_LOCK_FILE))
        .context("Unable to open the SSH host key store lock")?;
    lock.lock_exclusive()
        .context("Unable to lock the SSH host key store")?;
    let result = action();
    let _ = FileExt::unlock(&lock);
    result
}

fn load(path: &Path) -> Result<KnownHostsDocument> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(KnownHostsDocument {
                version: KNOWN_HOSTS_VERSION,
                hosts: BTreeMap::new(),
            });
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "Unable to read the SSH host key store {}; SSH connections are refused until it is readable",
                    path.display()
                )
            });
        }
    };
    let document: KnownHostsDocument = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "The SSH host key store {} is corrupt; SSH connections are refused until it is repaired or removed (removing it pins every host again on next use)",
            path.display()
        )
    })?;
    if document.version != KNOWN_HOSTS_VERSION {
        bail!(
            "The SSH host key store {} has unsupported version {}; SSH connections are refused until it is repaired or removed",
            path.display(),
            document.version
        );
    }
    Ok(document)
}

fn save(data_dir: &Path, document: &KnownHostsDocument) -> Result<()> {
    let path = data_dir.join(KNOWN_HOSTS_FILE);
    let bytes =
        serde_json::to_vec_pretty(document).context("Unable to serialize the SSH host key store")?;
    let mut file = AtomicWriteFile::open(&path)
        .with_context(|| format!("Unable to create the SSH host key store {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .context("Unable to restrict SSH host key store permissions")?;
    }
    file.write_all(&bytes)
        .context("Unable to write the SSH host key store")?;
    file.commit()
        .context("Unable to save the SSH host key store")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const KEY_A: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
    const KEY_B: &str = "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s";
    const ED25519: &str = "ssh-ed25519";

    #[test]
    fn first_use_pins_and_the_same_key_matches() {
        let dir = tempdir().unwrap();
        assert_eq!(
            verify_or_pin(dir.path(), "server.example", 22, ED25519, KEY_A).unwrap(),
            HostKeyVerdict::Pinned
        );
        assert_eq!(
            verify_or_pin(dir.path(), "server.example", 22, ED25519, KEY_A).unwrap(),
            HostKeyVerdict::Matched
        );
        let hosts = list(dir.path()).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host, "server.example:22");
        assert_eq!(hosts[0].algorithm, ED25519);
        assert_eq!(hosts[0].fingerprint, KEY_A);
        assert!(chrono::DateTime::parse_from_rfc3339(&hosts[0].first_seen).is_ok());

        let raw: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.path().join(KNOWN_HOSTS_FILE)).unwrap()).unwrap();
        assert_eq!(raw["version"], 1);
        assert_eq!(raw["hosts"]["server.example:22"][0]["fingerprint"], KEY_A);
        assert!(raw["hosts"]["server.example:22"][0]["firstSeen"].is_string());
    }

    #[test]
    fn different_key_is_rejected_and_does_not_replace_the_pin() {
        let dir = tempdir().unwrap();
        verify_or_pin(dir.path(), "server.example", 22, ED25519, KEY_A).unwrap();
        for _ in 0..2 {
            assert_eq!(
                verify_or_pin(dir.path(), "server.example", 22, ED25519, KEY_B).unwrap(),
                HostKeyVerdict::Mismatch {
                    expected: vec![KEY_A.to_owned()],
                    actual: KEY_B.to_owned(),
                }
            );
        }
        let hosts = list(dir.path()).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].fingerprint, KEY_A);
        assert_eq!(
            verify_or_pin(dir.path(), "server.example", 22, ED25519, KEY_A).unwrap(),
            HostKeyVerdict::Matched
        );
        // Pins are per host:port.
        assert_eq!(
            verify_or_pin(dir.path(), "server.example", 2222, ED25519, KEY_B).unwrap(),
            HostKeyVerdict::Pinned
        );

        let message = mismatch_message(" Server.Example ", 22, &[KEY_A.to_owned()], KEY_B);
        assert!(message.contains("server.example:22"));
        assert!(message.contains(&format!("pinned {KEY_A}")));
        assert!(message.contains(&format!("server presented {KEY_B}")));
        assert!(message.contains("No credentials were sent"));
        assert!(message.contains("`openkeylet ssh forget-host Server.Example --port 22`"));
    }

    #[test]
    fn forget_removes_one_port_or_every_port_of_a_host() {
        let dir = tempdir().unwrap();
        verify_or_pin(dir.path(), "server.example", 22, ED25519, KEY_A).unwrap();
        verify_or_pin(dir.path(), "server.example", 2222, ED25519, KEY_A).unwrap();
        verify_or_pin(dir.path(), "server.example.net", 22, ED25519, KEY_A).unwrap();
        verify_or_pin(dir.path(), "other.example", 22, ED25519, KEY_A).unwrap();

        assert_eq!(forget(dir.path(), "SERVER.example", Some(2222)).unwrap(), 1);
        let remaining = |dir: &Path| {
            list(dir)
                .unwrap()
                .into_iter()
                .map(|host| host.host)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            remaining(dir.path()),
            vec!["other.example:22", "server.example.net:22", "server.example:22"]
        );

        verify_or_pin(dir.path(), "server.example", 2200, ED25519, KEY_A).unwrap();
        assert_eq!(forget(dir.path(), "server.example", None).unwrap(), 2);
        assert_eq!(
            remaining(dir.path()),
            vec!["other.example:22", "server.example.net:22"]
        );
        assert_eq!(forget(dir.path(), "server.example", None).unwrap(), 0);
        assert_eq!(forget(dir.path(), "missing.example", Some(22)).unwrap(), 0);

        // A forgotten host pins whatever key it presents next.
        assert_eq!(
            verify_or_pin(dir.path(), "server.example", 22, ED25519, KEY_B).unwrap(),
            HostKeyVerdict::Pinned
        );
    }

    #[test]
    fn host_case_whitespace_and_ipv6_literals_are_normalized() {
        assert_eq!(host_port_key("  Server.Example ", 22), "server.example:22");
        assert_eq!(host_port_key("192.0.2.10", 22), "192.0.2.10:22");
        assert_eq!(host_port_key("::1", 22), "[::1]:22");
        assert_eq!(host_port_key("[0:0:0:0:0:0:0:1]", 2222), "[::1]:2222");
        assert_eq!(host_port_key("FE80::A", 22), "[fe80::a]:22");

        let dir = tempdir().unwrap();
        verify_or_pin(dir.path(), "Server.EXAMPLE", 22, ED25519, KEY_A).unwrap();
        assert_eq!(
            verify_or_pin(dir.path(), " server.example ", 22, ED25519, KEY_A).unwrap(),
            HostKeyVerdict::Matched
        );
        verify_or_pin(dir.path(), "::1", 22, ED25519, KEY_A).unwrap();
        assert!(matches!(
            verify_or_pin(dir.path(), "0:0:0:0:0:0:0:1", 22, ED25519, KEY_B).unwrap(),
            HostKeyVerdict::Mismatch { .. }
        ));
        assert_eq!(forget(dir.path(), "[::1]", None).unwrap(), 1);
        assert_eq!(list(dir.path()).unwrap().len(), 1);
    }

    #[test]
    fn corrupt_or_unsupported_store_fails_closed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(KNOWN_HOSTS_FILE);
        fs::write(&path, b"{not json").unwrap();
        let error = verify_or_pin(dir.path(), "server.example", 22, ED25519, KEY_A).unwrap_err();
        assert!(format!("{error:#}").contains(KNOWN_HOSTS_FILE));
        assert!(list(dir.path()).is_err());
        assert!(forget(dir.path(), "server.example", None).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"{not json");

        fs::write(&path, br#"{"version":2,"hosts":{}}"#).unwrap();
        let error = verify_or_pin(dir.path(), "server.example", 22, ED25519, KEY_A).unwrap_err();
        assert!(format!("{error:#}").contains(KNOWN_HOSTS_FILE));
        assert_eq!(fs::read(&path).unwrap(), br#"{"version":2,"hosts":{}}"#);
    }

    #[test]
    fn simultaneous_first_connections_pin_exactly_one_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let attempts = (0..8)
            .map(|index| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let fingerprint = format!("SHA256:candidate-{index}");
                    verify_or_pin(&path, "server.example", 22, ED25519, &fingerprint).unwrap()
                })
            })
            .collect::<Vec<_>>();
        let verdicts = attempts
            .into_iter()
            .map(|attempt| attempt.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            verdicts
                .iter()
                .filter(|verdict| **verdict == HostKeyVerdict::Pinned)
                .count(),
            1
        );
        assert_eq!(list(dir.path()).unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn store_file_is_private_to_the_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        verify_or_pin(dir.path(), "server.example", 22, ED25519, KEY_A).unwrap();
        let mode = fs::metadata(dir.path().join(KNOWN_HOSTS_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        forget(dir.path(), "server.example", None).unwrap();
        let mode = fs::metadata(dir.path().join(KNOWN_HOSTS_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
