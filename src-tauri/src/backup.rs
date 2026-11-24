use crate::{
    crypto::{decrypt_bytes, encrypt_bytes},
    model::{ImportSummary, PortableConnection, SecretBundle, SecretEnvelope},
    vault::Vault,
};
use anyhow::{Context, Result, bail, ensure};
use atomic_write_file::AtomicWriteFile;
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::Path};
use zeroize::{Zeroize, Zeroizing};

const BACKUP_VERSION: u8 = 8;
const PASSWORD_BACKUP_AAD: &[u8] = b"openkeylet/password-backup/v1";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PasswordBackupFile {
    format: String,
    version: u8,
    kdf: String,
    salt: String,
    cipher: String,
    payload: SecretEnvelope,
}

fn password_backup_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(salt.len() == 16, "Invalid backup salt");
    ensure!(
        !password.is_empty() && password.len() <= 4096,
        "Enter the backup password"
    );
    let params = argon2::Params::new(65_536, 3, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("Invalid backup parameters: {e}"))?;
    let mut key = Zeroizing::new([0; 32]);
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| anyhow::anyhow!("Unable to derive backup key: {e}"))?;
    Ok(key)
}

pub fn export_protected(vault: &Vault, path: &Path, password: &str) -> Result<()> {
    ensure!(
        password.chars().count() >= 12 && password.len() <= 4096,
        "Use a backup password of at least 12 characters"
    );
    reject_vault_internal_export_path(vault, path)?;
    let mut salt = [0; 16];
    getrandom::fill(&mut salt).map_err(|e| anyhow::anyhow!("Random generator unavailable: {e}"))?;
    let key = password_backup_key(password, &salt)?;
    let plain = cloud_snapshot(vault)?;
    let file = PasswordBackupFile {
        format: "openkeylet-password-backup".into(),
        version: 1,
        kdf: "argon2id-64m-t3-p1".into(),
        salt: STANDARD_NO_PAD.encode(salt),
        cipher: "xchacha20poly1305".into(),
        payload: encrypt_bytes(&key, &plain, PASSWORD_BACKUP_AAD)?,
    };
    let mut writer = AtomicWriteFile::open(path).context("Unable to create backup file")?;
    writer.write_all(&serde_json::to_vec_pretty(&file)?)?;
    writer.commit()?;
    Ok(())
}

pub fn import_with_password(vault: &Vault, path: &Path, password: &str) -> Result<ImportSummary> {
    ensure!(
        fs::metadata(path)?.len() <= 64 * 1024 * 1024,
        "Backup exceeds 64 MiB"
    );
    let bytes = fs::read(path).context("Unable to read backup")?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("Invalid backup format")?;
    if value["format"] != "openkeylet-password-backup" {
        return import_from_file(vault, path);
    }
    let file: PasswordBackupFile = serde_json::from_value(value)?;
    ensure!(
        file.version == 1 && file.kdf == "argon2id-64m-t3-p1" && file.cipher == "xchacha20poly1305",
        "Unsupported protected backup format"
    );
    let salt = STANDARD_NO_PAD
        .decode(&file.salt)
        .context("Invalid backup salt")?;
    let key = password_backup_key(password, &salt)?;
    let plain = Zeroizing::new(
        decrypt_bytes(&key, &file.payload, PASSWORD_BACKUP_AAD)
            .context("Incorrect backup password or damaged backup")?,
    );
    restore_cloud_snapshot(vault, &plain)
}

fn backup_aad(version: u8) -> Result<&'static [u8]> {
    match version {
        3 => Ok(b"kru/backup/v3"),
        4 => Ok(b"kru/backup/v4"),
        5 => Ok(b"kru/backup/v5"),
        6 => Ok(b"kru/backup/v6"),
        7 => Ok(b"kru/backup/v7"),
        BACKUP_VERSION => Ok(b"kru/backup/v8"),
        _ => bail!("Unsupported backup file version"),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupFile {
    format: String,
    version: u8,
    cipher: String,
    unlock_key: String,
    payload: SecretEnvelope,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupPayload {
    format: String,
    version: u8,
    created_at: String,
    connections: Vec<BackupConnection>,
    #[serde(default)]
    trash: Vec<crate::model::PortableTrashItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deleted_ids: Vec<crate::model::DeletedItemTombstone>,
}

#[derive(Serialize, Deserialize)]
struct BackupConnection {
    connection: PortableConnection,
    secrets: SecretBundle,
}

// Only the v3 import boundary knows about obsolete connection metadata.
// Secret payloads are deserialized directly into their zeroizing type.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct V3BackupPayload {
    format: String,
    version: u8,
    connections: Vec<V3BackupConnection>,
}

#[derive(Deserialize)]
struct V3BackupConnection {
    connection: serde_json::Value,
    secrets: SecretBundle,
}

pub fn export_to_file(vault: &Vault, path: impl AsRef<Path>) -> Result<()> {
    reject_vault_internal_export_path(vault, path.as_ref())?;
    let payload = backup_payload(vault)?;
    let mut plain = serde_json::to_vec(&payload).context("Unable to serialize backup")?;
    let mut key = [0_u8; 32];
    getrandom::fill(&mut key)
        .map_err(|error| anyhow::anyhow!("Unable to generate backup key:{error}"))?;
    let encrypted = encrypt_bytes(&key, &plain, backup_aad(BACKUP_VERSION)?);
    plain.zeroize();
    let payload = encrypted?;
    let unlock_key = STANDARD_NO_PAD.encode(key);
    key.zeroize();
    let file = BackupFile {
        format: "mcp-vault-backup".to_owned(),
        version: BACKUP_VERSION,
        cipher: "xchacha20poly1305".to_owned(),
        unlock_key,
        payload,
    };
    write_backup_file(path.as_ref(), &file)
}

fn backup_payload(vault: &Vault) -> Result<BackupPayload> {
    let (connections, trash) = vault.export_backup_entries()?;
    let deleted_ids = vault.export_tombstones()?;
    let connections = connections
        .into_iter()
        .map(|(connection, secrets)| BackupConnection {
            connection,
            secrets,
        })
        .collect();
    Ok(BackupPayload {
        format: "mcp-vault-portable".to_owned(),
        version: BACKUP_VERSION,
        created_at: Utc::now().to_rfc3339(),
        connections,
        trash,
        deleted_ids,
    })
}

// Cloud snapshots reuse the portable payload, never the self-unlocking .mvault
// container. The caller must encrypt these bytes with a separately held key.
pub(crate) fn cloud_snapshot(vault: &Vault) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(serde_json::to_vec(&backup_payload(vault)?)?))
}

pub(crate) fn inspect_cloud_snapshot(plain: &[u8]) -> Result<(String, usize)> {
    let payload: BackupPayload = serde_json::from_slice(plain)?;
    if payload.format != "mcp-vault-portable"
        || !matches!(payload.version, 4 | 5 | 6 | 7 | BACKUP_VERSION)
    {
        bail!("Unsupported cloud backup content version");
    }
    chrono::DateTime::parse_from_rfc3339(&payload.created_at)?;
    Ok((
        payload.created_at,
        payload.connections.len() + payload.trash.len(),
    ))
}

pub(crate) fn restore_cloud_snapshot(vault: &Vault, plain: &[u8]) -> Result<ImportSummary> {
    let payload: BackupPayload = serde_json::from_slice(plain)?;
    merge_backup_payload(vault, plain, payload.version)
}

pub(crate) fn sync_merge_cloud_snapshot(
    vault: &Vault,
    plain: &[u8],
) -> Result<crate::model::SyncMergeSummary> {
    let payload: BackupPayload = serde_json::from_slice(plain)?;
    if payload.format != "mcp-vault-portable"
        || !matches!(payload.version, 4 | 5 | 6 | 7 | BACKUP_VERSION)
    {
        bail!("Unsupported cloud sync payload version");
    }
    vault.sync_merge_entries(
        payload
            .connections
            .into_iter()
            .map(|item| (item.connection, item.secrets))
            .collect(),
        payload.trash,
        payload.deleted_ids,
    )
}

fn write_backup_file(path: &Path, file: &BackupFile) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(&file).context("Unable to generate backup file")?;
    let mut writer = AtomicWriteFile::open(path).context("Unable to create backup file")?;
    writer
        .write_all(&bytes)
        .context("Unable to write backup file")?;
    writer.commit().context("Unable to commit backup file")?;
    Ok(())
}

fn reject_vault_internal_export_path(vault: &Vault, path: &Path) -> Result<()> {
    let data_dir =
        fs::canonicalize(vault.data_dir()).context("Unable to confirm vault directory")?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("Unable to confirm current directory")?
            .join(path)
    };
    let target = if absolute.exists() {
        fs::canonicalize(&absolute).context("Unable to confirm backup destination path")?
    } else {
        let parent = absolute
            .parent()
            .context("Invalid backup destination path")?;
        let name = absolute.file_name().context("Invalid backup file name")?;
        fs::canonicalize(parent)
            .context("Unable to confirm backup destination directory")?
            .join(name)
    };
    if target.starts_with(&data_dir) {
        bail!(
            "Backup files cannot be saved inside the OpenKeylet data directory. Choose another location"
        );
    }
    Ok(())
}

pub fn import_from_file(vault: &Vault, path: impl AsRef<Path>) -> Result<ImportSummary> {
    let file = read_backup_file(path.as_ref())?;
    validate_backup_file(&file)?;
    let mut plain = decrypt_automatic_backup(&file)?;
    let result = merge_backup_payload(vault, &plain, file.version);
    plain.zeroize();
    result
}

fn read_backup_file(path: &Path) -> Result<BackupFile> {
    let bytes = fs::read(path).context("Unable to read backup file")?;
    serde_json::from_slice(&bytes).context("Invalid backup file format")
}

fn validate_backup_file(file: &BackupFile) -> Result<()> {
    if file.format != "mcp-vault-backup" {
        bail!("Unsupported backup file version");
    }
    backup_aad(file.version)?;
    if file.cipher != "xchacha20poly1305" {
        bail!("Unsupported backup encryption method");
    }
    Ok(())
}

fn decrypt_automatic_backup(file: &BackupFile) -> Result<Vec<u8>> {
    let decoded = STANDARD_NO_PAD
        .decode(&file.unlock_key)
        .context("Invalid backup auto-unlock material")?;
    let mut key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid backup auto-unlock material length"))?;
    let result = decrypt_bytes(&key, &file.payload, backup_aad(file.version)?);
    key.zeroize();
    result
}

fn merge_backup_payload(vault: &Vault, plain: &[u8], version: u8) -> Result<ImportSummary> {
    if version == 3 {
        let payload: V3BackupPayload =
            serde_json::from_slice(plain).context("Backup contents are corrupted")?;
        if payload.format != "mcp-vault-portable" || payload.version != 3 {
            bail!("Unsupported backup content version");
        }
        let mut connections = Vec::with_capacity(payload.connections.len());
        for mut item in payload.connections {
            if let Some(connection) = item.connection.as_object_mut() {
                for obsolete in [
                    "hostFingerprint",
                    "hostFingerprintHost",
                    "hostFingerprintPort",
                    "allowedMethods",
                    "allowedPathPrefixes",
                ] {
                    connection.remove(obsolete);
                }
            }
            let connection =
                serde_json::from_value(item.connection).context("Invalid backup item format")?;
            connections.push((connection, item.secrets));
        }
        return vault.merge_connections(connections);
    }
    let payload: BackupPayload =
        serde_json::from_slice(plain).context("Backup contents are corrupted")?;
    if payload.format != "mcp-vault-portable"
        || !matches!(payload.version, 4 | 5 | 6 | 7 | BACKUP_VERSION)
        || version != payload.version
    {
        bail!("Unsupported backup content version");
    }
    vault.merge_backup_entries(
        payload
            .connections
            .into_iter()
            .map(|item| (item.connection, item.secrets))
            .collect(),
        payload.trash,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn protected_backup_requires_password_and_keeps_unlock_key_out_of_file() {
        let d = tempdir().unwrap();
        let source = Vault::open(d.path().join("source")).unwrap();
        source
            .save_connection(input(
                Uuid::new_v4(),
                "Protected",
                "protected-secret-marker",
            ))
            .unwrap();
        let path = d.path().join("protected.mvault");
        assert!(export_protected(&source, &path, "short").is_err());
        export_protected(&source, &path, "synthetic-backup-password").unwrap();
        let bytes = fs::read_to_string(&path).unwrap();
        assert!(!bytes.contains("unlockKey"));
        assert!(!bytes.contains("protected-secret-marker"));
        let target = Vault::open(d.path().join("target")).unwrap();
        assert!(import_with_password(&target, &path, "wrong password").is_err());
        assert!(target.list_connections().unwrap().is_empty());
        assert_eq!(
            import_with_password(&target, &path, "synthetic-backup-password")
                .unwrap()
                .added,
            1
        );
    }
    #[test]
    fn older_untyped_v4_and_v5_backups_import_without_a_password() {
        let d = tempdir().unwrap();
        let source = Vault::open(d.path().join("source")).unwrap();
        source
            .save_connection(input(Uuid::new_v4(), "Legacy API", "legacy-marker"))
            .unwrap();
        for version in [4, 5] {
            let mut payload = serde_json::to_value(backup_payload(&source).unwrap()).unwrap();
            payload["version"] = serde_json::json!(version);
            let metadata = payload["connections"][0]["connection"]
                .as_object_mut()
                .unwrap();
            for field in ["itemType", "folder", "favorite"] {
                metadata.remove(field);
            }
            let file = BackupFile {
                format: "mcp-vault-backup".into(),
                version,
                cipher: "xchacha20poly1305".into(),
                unlock_key: STANDARD_NO_PAD.encode([42; 32]),
                payload: encrypt_bytes(
                    &[42; 32],
                    &serde_json::to_vec(&payload).unwrap(),
                    backup_aad(version).unwrap(),
                )
                .unwrap(),
            };
            let path = d.path().join(format!("v{version}.mvault"));
            write_backup_file(&path, &file).unwrap();
            let target = Vault::open(d.path().join(format!("target-{version}"))).unwrap();
            assert_eq!(import_with_password(&target, &path, "").unwrap().added, 1);
            let items = target.list_decrypted_connections().unwrap();
            assert_eq!(items[0].stored.item_type(), "api");
            assert_eq!(items[0].secrets.get("apiCredential"), Some("legacy-marker"));
        }
    }
    use super::*;
    use crate::model::{ConnectionInput, SecretBundle};
    use tempfile::tempdir;
    use uuid::Uuid;

    fn input(id: Uuid, name: &str, token: &str) -> ConnectionInput {
        let mut secrets = SecretBundle::default();
        secrets
            .named_secrets
            .insert("apiCredential".into(), token.to_owned());
        ConnectionInput {
            login_uris: Vec::new(),
            item_type: String::new(),
            folder: String::new(),
            favorite: false,
            id: Some(id),
            modules: vec![
                crate::model::ItemModule {
                    kind: "url".into(),
                    value: "https://api.example.test/v1/".into(),
                    ..Default::default()
                },
                crate::model::ItemModule {
                    kind: "apiCredential".into(),
                    ..Default::default()
                },
            ],
            name: name.into(),
            enabled: true,
            description: String::new(),
            http_auth_type: "bearer".into(),
            private_key_import_path: String::new(),
            auth_header: "X-API-Key".into(),
            auth_location: "header".into(),
            auth_prefix: String::new(),
            api_auth_headers: vec![],
            test_path: String::new(),
            remove_secret_names: vec![],
            secrets,
        }
    }

    #[test]
    fn automatic_backup_contains_no_marker_plaintext() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        vault
            .save_connection(input(
                Uuid::new_v4(),
                "private-service-marker",
                "marker-secret-123",
            ))
            .unwrap();
        let path = directory.path().join("test.mvault");
        export_to_file(&vault, &path).unwrap();
        let contents = fs::read_to_string(path).unwrap();
        assert!(!contents.contains("marker-secret-123"));
        assert!(!contents.contains("private_key"));
        assert!(contents.contains("xchacha20poly1305"));
        assert!(contents.contains("unlockKey"));
        let file: BackupFile = serde_json::from_str(&contents).unwrap();
        assert_eq!(file.version, BACKUP_VERSION);
        let plain = decrypt_automatic_backup(&file).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(payload["version"], BACKUP_VERSION);
        assert!(
            payload["connections"][0]["connection"]
                .get("allowedMethods")
                .is_none()
        );
        assert!(
            payload["connections"][0]["connection"]
                .get("hostFingerprint")
                .is_none()
        );
    }

    #[test]
    fn v3_backup_import_preserves_all_secret_payloads_and_current_transport_settings() {
        let directory = tempdir().unwrap();
        let source = Vault::open(directory.path().join("source")).unwrap();
        let target_dir = directory.path().join("target");
        let target = Vault::open(target_dir.clone()).unwrap();
        let id = Uuid::new_v4();
        source
            .save_connection(input(id, "v3 API", "api-marker"))
            .unwrap();
        let mut fixture = serde_json::to_value(backup_payload(&source).unwrap()).unwrap();
        fixture["version"] = serde_json::json!(3);
        let metadata = fixture["connections"][0]["connection"]
            .as_object_mut()
            .unwrap();
        metadata.insert(
            "hostFingerprint".into(),
            serde_json::json!("old-fingerprint"),
        );
        metadata.insert("hostFingerprintHost".into(), serde_json::json!("old-host"));
        metadata.insert("hostFingerprintPort".into(), serde_json::json!(22));
        metadata.insert("allowedMethods".into(), serde_json::json!(["GET"]));
        metadata.insert("allowedPathPrefixes".into(), serde_json::json!(["/v1/"]));
        metadata.insert("testPath".into(), serde_json::json!("/health"));
        fixture["connections"][0]["secrets"] = serde_json::json!({
            "privateKeyName": "existing-key",
            "password": "password-marker",
            "passphrase": "passphrase-marker",
            "privateKey": "private-key-marker",
            "token": "token-marker",
            "apiKey": "api-key-marker",
            "namedSecrets": {
                "username": "username-marker",
                "apiCredential": "api-marker",
                "extra": "extra-marker"
            }
        });
        let key = [31_u8; 32];
        let plain = serde_json::to_vec(&fixture).unwrap();
        let file = BackupFile {
            format: "mcp-vault-backup".into(),
            version: 3,
            cipher: "xchacha20poly1305".into(),
            unlock_key: STANDARD_NO_PAD.encode(key),
            payload: encrypt_bytes(&key, &plain, backup_aad(3).unwrap()).unwrap(),
        };
        let path = directory.path().join("existing-v3.mvault");
        write_backup_file(&path, &file).unwrap();
        assert_eq!(import_from_file(&target, &path).unwrap().added, 1);
        drop(target);

        let reopened = Vault::open(target_dir).unwrap();
        let imported = reopened.get_connection(id).unwrap();
        assert_eq!(imported.stored.http_auth_type, "bearer");
        assert_eq!(imported.stored.auth_header, "X-API-Key");
        assert_eq!(imported.stored.base_url, "https://api.example.test/v1/");
        assert_eq!(imported.stored.test_path, "/health");
        for (field, expected) in [
            ("password", "password-marker"),
            ("passphrase", "passphrase-marker"),
            ("privateKey", "private-key-marker"),
            ("token", "token-marker"),
            ("apiKey", "api-key-marker"),
            ("username", "username-marker"),
            ("apiCredential", "api-marker"),
            ("extra", "extra-marker"),
        ] {
            assert_eq!(imported.secrets.get(field), Some(expected), "{field}");
        }
        assert_eq!(
            imported.secrets.private_key_name.as_deref(),
            Some("existing-key")
        );
        let public = imported.stored.public(Some(&imported.secrets));
        assert_eq!(public.capabilities, ["fill", "http"]);
        assert!(public.can_test);
    }

    #[test]
    fn v4_file_and_cloud_backups_remain_importable() {
        let directory = tempdir().unwrap();
        let source = Vault::open(directory.path().join("source-v4")).unwrap();
        let id = Uuid::new_v4();
        source
            .save_connection(input(id, "Existing login", "v4-secret"))
            .unwrap();
        let mut payload = backup_payload(&source).unwrap();
        payload.version = 4;
        let plain = serde_json::to_vec(&payload).unwrap();
        assert!(!String::from_utf8_lossy(&plain).contains("passkeys"));
        let key = [41_u8; 32];
        let file = BackupFile {
            format: "mcp-vault-backup".into(),
            version: 4,
            cipher: "xchacha20poly1305".into(),
            unlock_key: STANDARD_NO_PAD.encode(key),
            payload: encrypt_bytes(&key, &plain, b"kru/backup/v4").unwrap(),
        };
        let path = directory.path().join("existing-v4.mvault");
        write_backup_file(&path, &file).unwrap();
        let target = Vault::open(directory.path().join("file-target")).unwrap();
        assert_eq!(import_from_file(&target, &path).unwrap().added, 1);
        assert_eq!(
            target
                .get_connection(id)
                .unwrap()
                .secrets
                .get("apiCredential"),
            Some("v4-secret")
        );
        assert_eq!(inspect_cloud_snapshot(&plain).unwrap().1, 1);
        let cloud_target = Vault::open(directory.path().join("cloud-target")).unwrap();
        assert_eq!(
            restore_cloud_snapshot(&cloud_target, &plain).unwrap().added,
            1
        );
        assert_eq!(
            cloud_target
                .get_connection(id)
                .unwrap()
                .secrets
                .get("apiCredential"),
            Some("v4-secret")
        );
    }

    #[test]
    fn backup_version_is_bound_to_its_ciphertext() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let path = directory.path().join("version.mvault");
        export_to_file(&vault, &path).unwrap();
        let mut file = read_backup_file(&path).unwrap();
        file.version = 3;
        write_backup_file(&path, &file).unwrap();
        assert!(import_from_file(&vault, &path).is_err());
    }

    #[test]
    fn export_refuses_to_overwrite_files_inside_the_vault_directory() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();

        for name in ["vault.json", "master.key", "vault.lock", "backup.mvault"] {
            let error = export_to_file(&vault, vault.data_dir().join(name)).unwrap_err();
            assert!(error.to_string().contains("data directory"));
        }
    }

    #[test]
    fn import_appends_conflicts_numbers_names_and_merges_reimports() {
        let directory = tempdir().unwrap();
        let source = Vault::open(directory.path().join("source")).unwrap();
        let target = Vault::open(directory.path().join("target")).unwrap();
        let shared_id = Uuid::new_v4();
        source
            .save_connection(input(shared_id, "service", "backup-token-123"))
            .unwrap();
        source
            .save_connection(input(Uuid::new_v4(), "service(2)", "backup-token-456"))
            .unwrap();
        target
            .save_connection(input(shared_id, "service", "local-token-123"))
            .unwrap();

        let path = directory.path().join("merge.mvault");
        export_to_file(&source, &path).unwrap();
        let summary = import_from_file(&target, &path).unwrap();
        assert_eq!(summary.added, 2);
        assert_eq!(summary.merged, 0);
        let connections = target.list_connections().unwrap();
        assert_eq!(connections.len(), 3);
        assert_eq!(connections[0].name, "service");
        assert_eq!(connections[1].name, "service(2)");
        assert_eq!(connections[2].name, "service(3)");
        assert_eq!(
            target
                .get_connection(shared_id)
                .unwrap()
                .secrets
                .get("apiCredential"),
            Some("local-token-123")
        );

        let mut locally_edited = input(connections[1].id, "service(2)", "backup-token-123");
        locally_edited.description = "local note".to_owned();
        target.save_connection(locally_edited).unwrap();

        let summary = import_from_file(&target, &path).unwrap();
        assert_eq!(summary.added, 0);
        assert_eq!(summary.merged, 2);
        assert_eq!(target.list_connections().unwrap().len(), 3);
    }

    #[test]
    fn import_treats_an_existing_numbered_name_as_literal_until_the_base_exists() {
        let directory = tempdir().unwrap();
        let source = Vault::open(directory.path().join("source-numbered")).unwrap();
        let target = Vault::open(directory.path().join("target-numbered")).unwrap();
        source
            .save_connection(input(Uuid::new_v4(), "service", "shared-token"))
            .unwrap();
        source
            .save_connection(input(Uuid::new_v4(), "service(2)", "backup-token"))
            .unwrap();
        target
            .save_connection(input(Uuid::new_v4(), "service(2)", "shared-token"))
            .unwrap();

        let path = directory.path().join("numbered.mvault");
        export_to_file(&source, &path).unwrap();
        let summary = import_from_file(&target, &path).unwrap();
        assert_eq!(summary.added, 2);
        assert_eq!(summary.merged, 0);
        let names = target
            .list_connections()
            .unwrap()
            .into_iter()
            .map(|item| item.name)
            .collect::<Vec<_>>();
        assert_eq!(names, ["service(2)", "service", "service(3)"]);

        let summary = import_from_file(&target, &path).unwrap();
        assert_eq!(summary.added, 0);
        assert_eq!(summary.merged, 2);
    }

    #[test]
    fn full_fidelity_backup_and_sync_preserve_all_types_passkeys_and_metadata_edits() {
        let dir = tempdir().unwrap();
        let src = Vault::open(dir.path().join("src")).unwrap();
        let dst = Vault::open(dir.path().join("dst")).unwrap();

        // 1. Login + password history + TOTP + Passkey + URI rule
        let mut login_secrets = SecretBundle::default();
        login_secrets.password = Some("first-pass-1".into());
        login_secrets
            .named_secrets
            .insert("username".into(), "alice@example.com".into());
        login_secrets.named_secrets.insert(
            "totp".into(),
            "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=30".into(),
        );
        let login = src
            .save_connection(ConnectionInput {
                login_uris: vec![crate::login_uri::LoginUri {
                    uri: "https://example.com".into(),
                    match_type: "domain".into(),
                }],
                item_type: "login".into(),
                folder: "Work".into(),
                favorite: true,
                id: None,
                modules: vec![
                    crate::model::ItemModule { kind: "url".into(), value: "https://example.com".into(), ..Default::default() },
                    crate::model::ItemModule { kind: "username".into(), ..Default::default() },
                    crate::model::ItemModule { kind: "password".into(), ..Default::default() },
                    crate::model::ItemModule { kind: "totp".into(), ..Default::default() },
                ],
                name: "Example Login".into(),
                enabled: true,
                description: "Initial note".into(),
                http_auth_type: String::new(),
                private_key_import_path: String::new(),
                auth_header: String::new(),
                auth_location: String::new(),
                auth_prefix: String::new(),
                api_auth_headers: vec![],
                test_path: String::new(),
                remove_secret_names: vec![],
                secrets: login_secrets,
            })
            .unwrap();
        // Update password once to populate password history
        let mut pw_update = SecretBundle::default();
        pw_update.password = Some("second-pass-2".into());
        src.save_connection(ConnectionInput {
            login_uris: vec![crate::login_uri::LoginUri {
                uri: "https://example.com".into(),
                match_type: "domain".into(),
            }],
            item_type: "login".into(),
            folder: "Work".into(),
            favorite: true,
            id: Some(login.id),
            modules: vec![
                crate::model::ItemModule { kind: "url".into(), value: "https://example.com".into(), ..Default::default() },
                crate::model::ItemModule { kind: "username".into(), ..Default::default() },
                crate::model::ItemModule { kind: "password".into(), ..Default::default() },
                crate::model::ItemModule { kind: "totp".into(), ..Default::default() },
            ],
            name: "Example Login".into(),
            enabled: true,
            description: "Initial note".into(),
            http_auth_type: String::new(),
            private_key_import_path: String::new(),
            auth_header: String::new(),
            auth_location: String::new(),
            auth_prefix: String::new(),
            api_auth_headers: vec![],
            test_path: String::new(),
            remove_secret_names: vec![],
            secrets: pw_update,
        })
        .unwrap();

        // 2. Passkey item
        let pk_opts = serde_json::json!({
            "challenge": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [5; 32]),
            "rp": {"id": "example.com", "name": "Example"},
            "user": {"id": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [6; 16]), "name": "alice", "displayName": "Alice"},
            "pubKeyCredParams": []
        });
        let (pk, _) = crate::passkey::create("https://example.com", &pk_opts, true).unwrap();
        src.store_browser_passkey("https://example.com", pk, &pk_opts)
            .unwrap();

        // 3. Card + Identity + API item
        let mut card_sec = SecretBundle::default();
        for (k, v) in [
            ("cardholderName", "Zhang San"),
            ("cardNumber", "4111111111111111"),
            ("cardBrand", "Visa"),
            ("cardExpMonth", "07"),
            ("cardExpYear", "2030"),
            ("cardSecurityCode", "842"),
        ] {
            card_sec.named_secrets.insert(k.into(), v.into());
        }
        src.save_connection(ConnectionInput {
            login_uris: vec![],
            item_type: "card".into(),
            folder: "Wallet".into(),
            favorite: false,
            id: None,
            modules: crate::item_types::CARD_FIELDS
                .iter()
                .map(|k| crate::model::ItemModule { kind: (*k).into(), ..Default::default() })
                .collect(),
            name: "Corp Visa".into(),
            enabled: true,
            description: String::new(),
            http_auth_type: String::new(),
            private_key_import_path: String::new(),
            auth_header: String::new(),
            auth_location: String::new(),
            auth_prefix: String::new(),
            api_auth_headers: vec![],
            test_path: String::new(),
            remove_secret_names: vec![],
            secrets: card_sec,
        })
        .unwrap();

        let api_item = src
            .save_connection(input(Uuid::new_v4(), "Custom API", "tok-999"))
            .unwrap();

        // Export password-protected .mvault and restore on fresh device
        let mvault = dir.path().join("full-fidelity.mvault");
        export_protected(&src, &mvault, "correct-horse-battery").unwrap();
        let raw = fs::read_to_string(&mvault).unwrap();
        assert!(!raw.contains("second-pass-2"));
        assert!(!raw.contains("4111111111111111"));
        assert!(!raw.contains("tok-999"));

        let restored = import_with_password(&dst, &mvault, "correct-horse-battery").unwrap();
        assert_eq!(restored.added, 4);
        let dst_login = dst.get_connection(login.id).unwrap();
        assert_eq!(dst_login.secrets.password.as_deref(), Some("second-pass-2"));
        assert_eq!(dst_login.secrets.password_history.len(), 1);
        assert_eq!(dst_login.stored.folder, "Work");
        assert!(dst_login.stored.favorite);
        assert!(crate::browser::current_totp(dst_login.secrets.get("totp").unwrap()).is_ok());

        let dst_pk_item = dst
            .list_decrypted_connections()
            .unwrap()
            .into_iter()
            .find(|c| !c.secrets.passkeys.is_empty())
            .unwrap();
        let assert_req = serde_json::json!({
            "challenge": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [9; 32]),
            "rpId": "example.com"
        });
        assert!(
            crate::passkey::get(&dst_pk_item.secrets.passkeys[0], "https://example.com", &assert_req, true).is_ok(),
            "restored passkey must produce valid WebAuthn assertions"
        );

        // Now rename, edit description, disable item, and change API header -> verify cloud sync propagates ALL metadata edits!
        std::thread::sleep(std::time::Duration::from_millis(15));
        let mut updated_api = input(api_item.id, "Renamed API", "tok-999");
        updated_api.description = "Updated description".into();
        updated_api.enabled = false;
        updated_api.auth_header = "X-Custom-Token".into();
        src.save_connection(updated_api).unwrap();

        let snap = cloud_snapshot(&src).unwrap();
        let merged = sync_merge_cloud_snapshot(&dst, &snap).unwrap();
        assert_eq!(merged.updated, 1);
        let synced_api = dst.get_connection(api_item.id).unwrap();
        assert_eq!(synced_api.stored.name, "Renamed API");
        assert_eq!(synced_api.stored.description, "Updated description");
        assert!(!synced_api.stored.enabled);
        assert_eq!(synced_api.stored.auth_header, "X-Custom-Token");
    }

    #[test]
    fn tampered_mvault_and_truncated_files_never_modify_target_vault() {
        let dir = tempdir().unwrap();
        let src = Vault::open(dir.path().join("src")).unwrap();
        let dst = Vault::open(dir.path().join("dst")).unwrap();
        src.save_connection(input(Uuid::new_v4(), "Source Secret", "src-tok-1"))
            .unwrap();
        dst.save_connection(input(Uuid::new_v4(), "Existing Local", "local-tok-1"))
            .unwrap();

        let mvault = dir.path().join("good.mvault");
        assert!(export_protected(&src, &mvault, "11-char-pwd").is_err());
        export_protected(&src, &mvault, "valid-twelve-char-password").unwrap();

        // 1. Flip 1 char in ciphertext
        let mut doc: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&mvault).unwrap()).unwrap();
        let ct = doc["payload"]["ciphertext"].as_str().unwrap().to_owned();
        let mut chars: Vec<char> = ct.chars().collect();
        chars[5] = if chars[5] == 'A' { 'B' } else { 'A' };
        doc["payload"]["ciphertext"] = serde_json::json!(chars.into_iter().collect::<String>());
        let tampered = dir.path().join("tampered.mvault");
        fs::write(&tampered, serde_json::to_vec(&doc).unwrap()).unwrap();
        assert!(import_with_password(&dst, &tampered, "valid-twelve-char-password").is_err());

        // 2. Truncated file
        let truncated = dir.path().join("truncated.mvault");
        let full = fs::read(&mvault).unwrap();
        fs::write(&truncated, &full[..full.len() / 2]).unwrap();
        assert!(import_with_password(&dst, &truncated, "valid-twelve-char-password").is_err());

        // 3. Empty password on protected backup
        assert!(import_with_password(&dst, &mvault, "").is_err());

        // Target vault remains completely untouched
        let items = dst.list_connections().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "Existing Local");
    }
}
