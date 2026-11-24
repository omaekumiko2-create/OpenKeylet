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
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{fs, path::Path};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SECRET_AAD: &[u8] = b"mcp-vault/secret/v2";
pub const STRONG_KEY_FILE: &str = "strong-key.json";
const STRONG_KEY_FORMAT: &str = "openkeylet-strong-vault-v1";
const STRONG_PASSPHRASE_AAD: &[u8] = b"openkeylet/strong-vault/passphrase/v1";
const STRONG_RECOVERY_AAD: &[u8] = b"openkeylet/strong-vault/recovery/v1";
const STRONG_ARGON2_MEMORY_KIB: u32 = 65_536;
const STRONG_ARGON2_ITERATIONS: u32 = 3;
const STRONG_ARGON2_PARALLELISM: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StrongKeyBundle {
    pub format: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub passphrase_salt: String,
    pub passphrase_wrapped_dek: SecretEnvelope,
    pub recovery_wrapped_dek: SecretEnvelope,
}

pub fn validate_master_passphrase(passphrase: &str) -> Result<()> {
    let chars = passphrase.chars().count();
    if chars < 12 {
        bail!("STRONG_PASSPHRASE_SHORT: Master passphrase must be at least 12 characters");
    }
    if passphrase.len() > 4096 {
        bail!("STRONG_PASSPHRASE_LONG: Master passphrase is too long");
    }
    Ok(())
}

pub fn parse_okv1_recovery_key(encoded: &str) -> Result<[u8; 32]> {
    let raw = encoded
        .trim()
        .strip_prefix("okv1_")
        .context("GITHUB_KEY_INVALID")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .context("GITHUB_KEY_INVALID")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("GITHUB_KEY_INVALID"))
}

fn derive_strong_passphrase_kek(
    passphrase: &str,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    if !(16_384..=262_144).contains(&memory_kib)
        || !(1..=10).contains(&iterations)
        || !(1..=4).contains(&parallelism)
    {
        bail!("STRONG_KEY_INVALID: Unsupported Argon2id parameters");
    }
    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|error| anyhow::anyhow!("Invalid strong vault KDF parameters:{error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, kek.as_mut())
        .map_err(|error| anyhow::anyhow!("Unable to derive strong vault key:{error}"))?;
    Ok(kek)
}

pub fn create_strong_key_bundle(
    dek: &[u8; 32],
    master_passphrase: &str,
    recovery_key: &str,
) -> Result<StrongKeyBundle> {
    validate_master_passphrase(master_passphrase)?;
    let recovery_bytes = Zeroizing::new(parse_okv1_recovery_key(recovery_key)?);
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt)
        .map_err(|error| anyhow::anyhow!("Unable to generate strong vault salt:{error}"))?;
    let passphrase_kek = derive_strong_passphrase_kek(
        master_passphrase,
        &salt,
        STRONG_ARGON2_MEMORY_KIB,
        STRONG_ARGON2_ITERATIONS,
        STRONG_ARGON2_PARALLELISM,
    )?;
    let passphrase_wrapped_dek = encrypt_bytes(&passphrase_kek, dek, STRONG_PASSPHRASE_AAD)?;
    let recovery_wrapped_dek = encrypt_bytes(&recovery_bytes, dek, STRONG_RECOVERY_AAD)?;
    Ok(StrongKeyBundle {
        format: STRONG_KEY_FORMAT.to_owned(),
        memory_kib: STRONG_ARGON2_MEMORY_KIB,
        iterations: STRONG_ARGON2_ITERATIONS,
        parallelism: STRONG_ARGON2_PARALLELISM,
        passphrase_salt: STANDARD_NO_PAD.encode(salt),
        passphrase_wrapped_dek,
        recovery_wrapped_dek,
    })
}

pub fn rewrap_strong_passphrase(
    existing: &StrongKeyBundle,
    dek: &[u8; 32],
    new_passphrase: &str,
) -> Result<StrongKeyBundle> {
    validate_master_passphrase(new_passphrase)?;
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt)
        .map_err(|error| anyhow::anyhow!("Unable to generate strong vault salt:{error}"))?;
    let passphrase_kek = derive_strong_passphrase_kek(
        new_passphrase,
        &salt,
        STRONG_ARGON2_MEMORY_KIB,
        STRONG_ARGON2_ITERATIONS,
        STRONG_ARGON2_PARALLELISM,
    )?;
    let passphrase_wrapped_dek = encrypt_bytes(&passphrase_kek, dek, STRONG_PASSPHRASE_AAD)?;
    Ok(StrongKeyBundle {
        format: STRONG_KEY_FORMAT.to_owned(),
        memory_kib: STRONG_ARGON2_MEMORY_KIB,
        iterations: STRONG_ARGON2_ITERATIONS,
        parallelism: STRONG_ARGON2_PARALLELISM,
        passphrase_salt: STANDARD_NO_PAD.encode(salt),
        passphrase_wrapped_dek,
        recovery_wrapped_dek: existing.recovery_wrapped_dek.clone(),
    })
}

pub fn unwrap_strong_key_bundle(
    bundle: &StrongKeyBundle,
    secret: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    if bundle.format != STRONG_KEY_FORMAT {
        bail!("STRONG_KEY_INVALID: Unsupported strong key bundle format");
    }
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        bail!("STRONG_UNLOCK_FAILED: Enter your master passphrase or okv1_ recovery key");
    }
    let plain = if trimmed.starts_with("okv1_") {
        let recovery_bytes = Zeroizing::new(
            parse_okv1_recovery_key(trimmed)
                .map_err(|_| anyhow::anyhow!("STRONG_UNLOCK_FAILED: Invalid recovery key"))?,
        );
        Zeroizing::new(
            decrypt_bytes(&recovery_bytes, &bundle.recovery_wrapped_dek, STRONG_RECOVERY_AAD)
                .map_err(|_| anyhow::anyhow!("STRONG_UNLOCK_FAILED: Incorrect recovery key"))?,
        )
    } else {
        let salt = STANDARD_NO_PAD
            .decode(&bundle.passphrase_salt)
            .context("STRONG_KEY_INVALID: Invalid passphrase salt")?;
        if salt.len() != 16 {
            bail!("STRONG_KEY_INVALID: Invalid passphrase salt length");
        }
        let kek = derive_strong_passphrase_kek(
            secret,
            &salt,
            bundle.memory_kib,
            bundle.iterations,
            bundle.parallelism,
        )?;
        Zeroizing::new(
            decrypt_bytes(&kek, &bundle.passphrase_wrapped_dek, STRONG_PASSPHRASE_AAD)
                .map_err(|_| anyhow::anyhow!("STRONG_UNLOCK_FAILED: Incorrect master passphrase"))?,
        )
    };
    let dek: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("STRONG_KEY_INVALID: Unwrapped DEK has invalid length"))?;
    Ok(Zeroizing::new(dek))
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
    source: String,
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MasterKey")
            .field("bytes", &"[REDACTED]")
            .field("source", &self.source)
            .finish()
    }
}

impl MasterKey {
    pub fn load_or_create(data_dir: &Path, vault_exists: bool) -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let key_file = data_dir.join("master.key");
            let legacy_key = if vault_exists && !key_file.exists() {
                load_legacy_macos_key_without_ui()
            } else {
                None
            };
            Self::load_or_create_file_key(data_dir, vault_exists, legacy_key)
        }

        #[cfg(not(target_os = "macos"))]
        {
            let use_keyring = !crate::storage::uses_explicit_data_dir(data_dir);
            Self::load_or_create_inner(data_dir, vault_exists, use_keyring)
        }
    }

    #[cfg(any(target_os = "macos", test))]
    fn load_or_create_file_key(
        data_dir: &Path,
        vault_exists: bool,
        legacy_key: Option<[u8; 32]>,
    ) -> Result<Self> {
        prepare_private_directory(data_dir)?;
        let key_file = data_dir.join("master.key");

        if key_file.exists() {
            harden_private_file(&key_file)?;
            let encoded = fs::read_to_string(&key_file)
                .context("Unable to read the local permissions key file")?;
            return Ok(Self {
                bytes: decode_key(encoded.trim())?,
                source: "Application-private master key file".to_owned(),
            });
        }

        if let Some(bytes) = legacy_key {
            write_private_file(&key_file, STANDARD_NO_PAD.encode(bytes).as_bytes())?;
            return Ok(Self {
                bytes,
                source: "Application-private master key file".to_owned(),
            });
        }

        if vault_exists {
            bail!(
                "Vault master key is missing; OpenKeylet will not show a macOS Keychain authorization prompt or generate a new key that overwrites existing data"
            );
        }

        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|error| anyhow::anyhow!("Unable to generate vault master key:{error}"))?;
        write_private_file(&key_file, STANDARD_NO_PAD.encode(bytes).as_bytes())?;
        Ok(Self {
            bytes,
            source: "Application-private master key file".to_owned(),
        })
    }

    #[cfg(not(target_os = "macos"))]
    fn load_or_create_inner(
        data_dir: &Path,
        vault_exists: bool,
        use_keyring: bool,
    ) -> Result<Self> {
        prepare_private_directory(data_dir)?;
        let key_file = data_dir.join("master.key");

        if use_keyring && let Ok(entry) = keyring::Entry::new("mcp-vault", "master-key-v2") {
            if let Ok(encoded) = entry.get_password() {
                if let Ok(bytes) = decode_key(&encoded) {
                    return Ok(Self {
                        bytes,
                        source: system_storage_label().to_owned(),
                    });
                }
            }
        }

        if key_file.exists() {
            harden_private_file(&key_file)?;
            let encoded = fs::read_to_string(&key_file)
                .context("Unable to read the local permissions key file")?;
            return Ok(Self {
                bytes: decode_key(encoded.trim())?,
                source: "Local permissions key file".to_owned(),
            });
        }

        if vault_exists {
            bail!(
                "Vault master key is missing; to avoid overwriting data, the program refused to generate a new key"
            );
        }

        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|error| anyhow::anyhow!("Unable to generate vault master key:{error}"))?;
        let encoded = STANDARD_NO_PAD.encode(bytes);

        if use_keyring && let Ok(entry) = keyring::Entry::new("mcp-vault", "master-key-v2") {
            if entry.set_password(&encoded).is_ok() {
                return Ok(Self {
                    bytes,
                    source: system_storage_label().to_owned(),
                });
            }
        }

        write_private_file(&key_file, encoded.as_bytes())?;
        Ok(Self {
            bytes,
            source: "Local permissions key file".to_owned(),
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn from_ram_bytes(bytes: [u8; 32], source: impl Into<String>) -> Self {
        Self {
            bytes,
            source: source.into(),
        }
    }

    pub fn generate_random(source: impl Into<String>) -> Result<Self> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|error| anyhow::anyhow!("Unable to generate vault master key:{error}"))?;
        Ok(Self {
            bytes,
            source: source.into(),
        })
    }

    pub(crate) fn clone_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.bytes)
    }

    pub fn has_strong_key_bundle(data_dir: &Path) -> bool {
        data_dir.join(STRONG_KEY_FILE).is_file()
    }

    pub fn persist_local_key(data_dir: &Path, bytes: &[u8; 32]) -> Result<String> {
        prepare_private_directory(data_dir)?;
        let encoded = Zeroizing::new(STANDARD_NO_PAD.encode(bytes));
        let key_file = data_dir.join("master.key");
        #[cfg(not(target_os = "macos"))]
        {
            let use_keyring = !crate::storage::uses_explicit_data_dir(data_dir);
            if use_keyring && let Ok(entry) = keyring::Entry::new("mcp-vault", "master-key-v2") {
                if entry.set_password(&encoded).is_ok() {
                    let _ = fs::remove_file(&key_file);
                    return Ok(system_storage_label().to_owned());
                }
            }
        }
        if key_file.exists() {
            let _ = fs::remove_file(&key_file);
        }
        write_private_file(&key_file, encoded.as_bytes())?;
        #[cfg(target_os = "macos")]
        {
            Ok("Application-private master key file".to_owned())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Ok("Local permissions key file".to_owned())
        }
    }

    pub fn wipe_local_key(data_dir: &Path) -> Result<()> {
        let key_file = data_dir.join("master.key");
        if key_file.is_file() {
            if let Ok(meta) = fs::metadata(&key_file) {
                let zeros = vec![0_u8; meta.len().clamp(32, 4096) as usize];
                let _ = fs::write(&key_file, zeros);
            }
            fs::remove_file(&key_file)
                .context("Unable to remove local master.key after enabling Strong Mode")?;
        }
        #[cfg(not(target_os = "macos"))]
        if !crate::storage::uses_explicit_data_dir(data_dir) {
            if let Ok(entry) = keyring::Entry::new("mcp-vault", "master-key-v2") {
                let _ = entry.delete_credential();
            }
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub fn migrate_legacy_macos_key(data_dir: &Path) -> Result<bool> {
        prepare_private_directory(data_dir)?;
        let key_file = data_dir.join("master.key");
        if key_file.exists() {
            harden_private_file(&key_file)?;
            return Ok(false);
        }
        if !data_dir.join("vault.json").exists() {
            bail!("No legacy vault needs to be migrated");
        }

        let entry = keyring::Entry::new("mcp-vault", "master-key-v2")
            .context("Unable to access the legacy macOS Keychain item")?;
        let mut encoded = entry
            .get_password()
            .context("Not authorized to read the legacy macOS Keychain master key")?;
        let decoded = decode_key(&encoded);
        encoded.zeroize();
        let bytes = decoded?;
        write_private_file(&key_file, STANDARD_NO_PAD.encode(bytes).as_bytes())?;
        Ok(true)
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

#[cfg(not(target_os = "macos"))]
fn system_storage_label() -> &'static str {
    #[cfg(target_os = "windows")]
    return "Windows Credential Manager";
    #[cfg(all(unix, not(target_os = "macos")))]
    return "Linux Secret Service";
    #[allow(unreachable_code)]
    "System secure storage"
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::{fs::OpenOptions, io::Write};
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .context("Unable to create local permissions key file")?;
        file.write_all(bytes)
            .context("Unable to write local permissions key file")?;
        file.sync_all()
            .context("Unable to sync local permissions key file")?;
    }
    #[cfg(not(unix))]
    fs::write(path, bytes).context("Unable to write local permissions key file")?;
    Ok(())
}

fn prepare_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).context("Unable to create vault directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .context("Unable to tighten vault directory permissions")?;
    }
    Ok(())
}

fn harden_private_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .context("Unable to tighten local permissions key file permissions")?;
    }
    #[cfg(not(unix))]
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
    fn existing_vault_without_master_key_is_rejected() {
        let directory = tempdir().unwrap();
        let result = MasterKey::load_or_create_file_key(directory.path(), true, None);
        assert!(result.is_err());
        assert!(!directory.path().join("master.key").exists());
    }

    #[test]
    fn file_key_is_created_and_reused() {
        let directory = tempdir().unwrap();
        let first = MasterKey::load_or_create_file_key(directory.path(), false, None).unwrap();
        let envelope = first.encrypt(&"kept secret").unwrap();
        drop(first);

        let second = MasterKey::load_or_create_file_key(directory.path(), true, None).unwrap();
        assert_eq!(second.source(), "Application-private master key file");
        assert_eq!(second.decrypt::<String>(&envelope).unwrap(), "kept secret");
    }

    #[test]
    fn legacy_key_is_migrated_to_private_file() {
        let directory = tempdir().unwrap();
        let legacy_key = [42_u8; 32];
        let migrated =
            MasterKey::load_or_create_file_key(directory.path(), true, Some(legacy_key)).unwrap();
        let envelope = migrated.encrypt(&"migrated secret").unwrap();
        drop(migrated);

        let reopened = MasterKey::load_or_create_file_key(directory.path(), true, None).unwrap();
        assert_eq!(
            reopened.decrypt::<String>(&envelope).unwrap(),
            "migrated secret"
        );
    }

    #[test]
    fn explicit_data_directory_uses_directory_master_key_without_os_keyring() {
        let directory = tempdir().unwrap();
        assert!(crate::storage::uses_explicit_data_dir(directory.path()));
        let key = MasterKey::load_or_create(directory.path(), false).unwrap();
        assert!(directory.path().join("master.key").is_file());
        let envelope = key.encrypt(&"shared-vault-secret").unwrap();
        drop(key);
        let reopened = MasterKey::load_or_create(directory.path(), true).unwrap();
        assert_eq!(
            reopened.decrypt::<String>(&envelope).unwrap(),
            "shared-vault-secret"
        );
        // Existing vault without master.key in an explicit directory must fail closed.
        fs::remove_file(directory.path().join("master.key")).unwrap();
        assert!(MasterKey::load_or_create(directory.path(), true).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_storage_permissions_are_restricted() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().unwrap();
        MasterKey::load_or_create_file_key(directory.path(), false, None).unwrap();
        let directory_mode = fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777;
        let key_mode = fs::metadata(directory.path().join("master.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(key_mode, 0o600);
    }
}
