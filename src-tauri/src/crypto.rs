pub mod key_location;
pub mod ssh_keygen;
pub mod totp;
#[cfg(windows)]
mod windows_acl;

use crate::model::{OwnerPinVerifier, SecretEnvelope};
use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use key_location::{KeyLocations, KeyPlace};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs,
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SECRET_AAD: &[u8] = b"mcp-vault/secret/v2";

pub fn parse_okv1_recovery_key(encoded: &str) -> Result<Zeroizing<[u8; 32]>> {
    let raw = encoded
        .trim()
        .strip_prefix("okv1_")
        .context("GITHUB_KEY_INVALID")?;
    if raw.len() != 43 {
        bail!("GITHUB_KEY_INVALID");
    }
    let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(raw).context("GITHUB_KEY_INVALID")?);
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("GITHUB_KEY_INVALID"))?;
    Ok(Zeroizing::new(key))
}

/// Argon2id 32-byte key derivation used by password-protected `.mvault` backups.
pub fn derive_argon2id_key_32(
    secret: &str,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    if !(16_384..=262_144).contains(&memory_kib)
        || !(1..=10).contains(&iterations)
        || !(1..=4).contains(&parallelism)
    {
        bail!("Unsupported Argon2id parameters");
    }
    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|error| anyhow::anyhow!("Invalid Argon2id KDF parameters: {error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(secret.as_bytes(), salt, key.as_mut())
        .map_err(|error| anyhow::anyhow!("Unable to derive key: {error}"))?;
    Ok(key)
}

pub fn create_owner_pin_verifier(pin: &str) -> Result<OwnerPinVerifier> {
    validate_owner_pin(pin)?;
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt)
        .map_err(|error| anyhow::anyhow!("Unable to generate PIN salt:{error}"))?;
    let hash = derive_owner_pin_hash(pin, &salt)?;
    Ok(OwnerPinVerifier {
        version: 1,
        salt: STANDARD_NO_PAD.encode(salt),
        hash: STANDARD_NO_PAD.encode(hash),
    })
}

pub fn verify_owner_pin(pin: &str, verifier: &OwnerPinVerifier) -> Result<bool> {
    validate_owner_pin(pin)?;
    if verifier.version != 1 {
        bail!("Unsupported PIN version");
    }
    let salt = STANDARD_NO_PAD
        .decode(&verifier.salt)
        .context("Invalid PIN salt")?;
    let expected = STANDARD_NO_PAD
        .decode(&verifier.hash)
        .context("Invalid PIN hash")?;
    let actual = derive_owner_pin_hash(pin, &salt)?;
    Ok(expected.len() == actual.len() && expected.ct_eq(actual.as_slice()).into())
}

fn validate_owner_pin(pin: &str) -> Result<()> {
    if pin.len() != 6 || !pin.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("PIN must contain six digits");
    }
    Ok(())
}

fn derive_owner_pin_hash(pin: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|error| anyhow::anyhow!("Invalid Argon2 parameters:{error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut hash = [0_u8; 32];
    argon2
        .hash_password_into(pin.as_bytes(), salt, &mut hash)
        .map_err(|error| anyhow::anyhow!("Unable to verify PIN:{error}"))?;
    Ok(hash)
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; 32],
    #[zeroize(skip)]
    place: KeyPlace,
    #[zeroize(skip)]
    key_file: Option<PathBuf>,
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MasterKey")
            .field("bytes", &"[REDACTED]")
            .field("place", &self.place)
            .field("key_file", &self.key_file)
            .finish()
    }
}

impl MasterKey {
    /// Loads the vault key; `key_location` documents where it is looked for,
    /// how `probes` (envelopes from the existing `vault.json`) decide between
    /// candidates, and when a key is created or moved.
    pub fn load_or_create(
        locations: &KeyLocations,
        vault_exists: bool,
        probes: &[&SecretEnvelope],
    ) -> Result<Self> {
        key_location::load_or_create(locations, vault_exists, probes)
    }

    pub fn place(&self) -> KeyPlace {
        self.place
    }

    /// The key file in use, or `None` when the key came from an OS key store.
    pub fn key_file(&self) -> Option<&Path> {
        self.key_file.as_deref()
    }

    #[cfg(target_os = "macos")]
    pub fn migrate_legacy_macos_key(data_dir: &Path) -> Result<bool> {
        let locations = KeyLocations::for_data_dir(data_dir)?;
        key_location::import_legacy_key(&locations, || {
            let entry = keyring::Entry::new("mcp-vault", "master-key-v2")
                .context("Unable to access the legacy macOS Keychain item")?;
            let encoded = Zeroizing::new(
                entry
                    .get_password()
                    .context("Not authorized to read the legacy macOS Keychain master key")?,
            );
            decode_key(&encoded)
        })
    }

    pub fn encrypt<T: Serialize>(&self, value: &T) -> Result<SecretEnvelope> {
        let bytes =
            Zeroizing::new(serde_json::to_vec(value).context("Unable to serialize secret")?);
        encrypt_bytes(&self.bytes, &bytes, SECRET_AAD)
    }

    pub fn decrypt<T: DeserializeOwned>(&self, envelope: &SecretEnvelope) -> Result<T> {
        let plain = Zeroizing::new(decrypt_bytes(&self.bytes, envelope, SECRET_AAD)?);
        serde_json::from_slice(&plain).context("Invalid secret content format")
    }
}

fn decode_key(encoded: &str) -> Result<[u8; 32]> {
    let decoded = STANDARD_NO_PAD
        .decode(encoded)
        .context("Invalid master key format")?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid master key length"))
}

#[cfg(target_os = "macos")]
fn load_legacy_macos_key_without_ui() -> Option<[u8; 32]> {
    use security_framework::os::macos::keychain::SecKeychain;

    let _interaction_lock = SecKeychain::disable_user_interaction().ok()?;
    let entry = keyring::Entry::new("mcp-vault", "master-key-v2").ok()?;
    let encoded = entry.get_password().ok()?;
    decode_key(&encoded).ok()
}

pub fn encrypt_bytes(key: &[u8; 32], bytes: &[u8], aad: &[u8]) -> Result<SecretEnvelope> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow::anyhow!("Unable to generate encryption nonce:{error}"))?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: bytes, aad })
        .map_err(|_| anyhow::anyhow!("Secret encryption failed"))?;
    Ok(SecretEnvelope {
        version: 1,
        nonce: STANDARD_NO_PAD.encode(nonce),
        ciphertext: STANDARD_NO_PAD.encode(ciphertext),
    })
}

pub fn decrypt_bytes(key: &[u8; 32], envelope: &SecretEnvelope, aad: &[u8]) -> Result<Vec<u8>> {
    if envelope.version != 1 {
        bail!("Unsupported ciphertext version");
    }
    let nonce = STANDARD_NO_PAD
        .decode(&envelope.nonce)
        .context("Invalid ciphertext nonce")?;
    if nonce.len() != 24 {
        bail!("Invalid ciphertext nonce length");
    }
    let ciphertext = STANDARD_NO_PAD
        .decode(&envelope.ciphertext)
        .context("Invalid ciphertext content")?;
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("Ciphertext verification failed or incorrect key"))
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::{fs::OpenOptions, io::Write};
    let mut options = OpenOptions::new();
    // `create_new` on every platform: a key file that already exists may be
    // the only copy of some vault's key, so it is never truncated or replaced.
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("Unable to create local permissions key file")?;
    let write_result = (|| -> Result<()> {
        // On Windows, apply an owner-only protected NTFS DACL before writing key
        // bytes so the key never rests on disk under inherited shared permissions.
        #[cfg(windows)]
        harden_private_file(path)?;
        file.write_all(bytes)
            .context("Unable to write local permissions key file")?;
        file.sync_all()
            .context("Unable to sync local permissions key file")?;
        Ok(())
    })();
    if let Err(error) = write_result {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

/// Atomically writes a rendered secret file (`secret_write_file`) by hardening
/// the temporary file BEFORE writing secret bytes and BEFORE replacing the
/// destination. Returns `Ok(hardened)` indicating whether owner-only file
/// permissions were successfully applied (best-effort on filesystems without
/// ACL support such as FAT32/SMB).
pub(crate) fn write_atomic_private_file(target_path: &Path, bytes: &[u8]) -> Result<bool> {
    use std::{fs::OpenOptions, io::Write};
    let file_name = target_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("secret");
    let temp_path = target_path.with_file_name(format!(
        ".{file_name}.openkeylet-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp_path)
        .context("Unable to create temporary file")?;
    // Harden permissions before writing a single secret byte to disk.
    let hardened = harden_private_file(&temp_path).is_ok();
    let write_result = (|| -> Result<()> {
        file.write_all(bytes)
            .context("Unable to write rendered file")?;
        file.sync_all()
            .context("Unable to sync rendered file")?;
        Ok(())
    })();
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }

    #[cfg(not(windows))]
    {
        if let Err(error) = fs::rename(&temp_path, target_path) {
            let _ = fs::remove_file(&temp_path);
            return Err(error).context("Unable to save file atomically");
        }
    }

    #[cfg(windows)]
    {
        if !target_path.exists() {
            if let Err(error) = fs::rename(&temp_path, target_path) {
                let _ = fs::remove_file(&temp_path);
                return Err(error).context("Unable to save file atomically");
            }
        } else {
            let backup_path = target_path.with_file_name(format!(
                ".{file_name}.openkeylet-{}.bak",
                uuid::Uuid::new_v4().simple()
            ));
            if let Err(error) = fs::rename(target_path, &backup_path) {
                let _ = fs::remove_file(&temp_path);
                return Err(error).context("Unable to stage existing destination file");
            }
            if let Err(error) = fs::rename(&temp_path, target_path) {
                let _ = fs::rename(&backup_path, target_path);
                let _ = fs::remove_file(&temp_path);
                return Err(error).context("Unable to save file atomically");
            }
            let _ = fs::remove_file(&backup_path);
        }
    }

    Ok(hardened)
}

fn prepare_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).context("Unable to create vault directory")?;
    harden_private_directory(path)
}

fn harden_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .context("Unable to tighten vault directory permissions")?;
    }
    #[cfg(windows)]
    {
        windows_acl::harden_owner_only(path, true)?;
    }
    #[cfg(not(any(unix, windows)))]
    let _ = path;
    Ok(())
}

pub(crate) fn harden_private_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .context("Unable to tighten local permissions key file permissions")?;
    }
    #[cfg(windows)]
    {
        windows_acl::harden_owner_only(path, false)?;
    }
    #[cfg(not(any(unix, windows)))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn secret_roundtrip_and_tamper_detection() {
        let key = [7_u8; 32];
        let envelope = encrypt_bytes(&key, b"hidden", SECRET_AAD).unwrap();
        assert_eq!(
            decrypt_bytes(&key, &envelope, SECRET_AAD).unwrap(),
            b"hidden"
        );
        let mut tampered = envelope;
        tampered.ciphertext.push('A');
        assert!(decrypt_bytes(&key, &tampered, SECRET_AAD).is_err());
    }

    #[test]
    fn owner_pin_verifier_accepts_only_the_configured_six_digits() {
        let verifier = create_owner_pin_verifier("123456").unwrap();
        assert!(verify_owner_pin("123456", &verifier).unwrap());
        assert!(!verify_owner_pin("654321", &verifier).unwrap());
        assert!(create_owner_pin_verifier("12345").is_err());
        assert!(!verifier.hash.contains("123456"));
    }

    #[test]
    fn explicit_data_directory_uses_directory_master_key_without_os_keyring() {
        let directory = tempdir().unwrap();
        assert!(crate::storage::uses_explicit_data_dir(directory.path()));
        let locations = KeyLocations::for_data_dir(directory.path()).unwrap();
        let key = MasterKey::load_or_create(&locations, false, &[]).unwrap();
        assert!(directory.path().join("master.key").is_file());
        assert_eq!(key.place(), KeyPlace::FileInsideDataDir);
        assert_eq!(
            key.key_file(),
            Some(directory.path().join("master.key").as_path())
        );
        let envelope = key.encrypt(&"shared-vault-secret").unwrap();
        drop(key);
        let reopened = MasterKey::load_or_create(&locations, true, &[&envelope]).unwrap();
        assert_eq!(
            reopened.decrypt::<String>(&envelope).unwrap(),
            "shared-vault-secret"
        );
        // Existing vault without master.key in an explicit directory must fail closed.
        fs::remove_file(directory.path().join("master.key")).unwrap();
        assert!(MasterKey::load_or_create(&locations, true, &[&envelope]).is_err());
        assert!(!directory.path().join("master.key").exists());
    }

    #[test]
    fn writing_a_key_file_never_replaces_an_existing_one() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("master.key");
        fs::write(&path, "existing").unwrap();
        assert!(write_private_file(&path, b"replacement").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "existing");
    }
}
