use super::*;

pub(super) fn backup_aad(version: u8) -> Result<&'static [u8]> {
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
pub(super) struct BackupFile {
    pub(super) format: String,
    pub(super) version: u8,
    pub(super) cipher: String,
    pub(super) unlock_key: String,
    pub(super) payload: SecretEnvelope,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct BackupPayload {
    pub(super) format: String,
    pub(super) version: u8,
    pub(super) created_at: String,
    pub(super) connections: Vec<BackupConnection>,
    #[serde(default)]
    pub(super) trash: Vec<crate::model::PortableTrashItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) deleted_ids: Vec<crate::model::DeletedItemTombstone>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct BackupConnection {
    pub(super) connection: PortableConnection,
    pub(super) secrets: SecretBundle,
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

pub(super) fn backup_payload(vault: &Vault) -> Result<BackupPayload> {
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

pub(super) fn write_backup_file(path: &Path, file: &BackupFile) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(&file).context("Unable to generate backup file")?;
    let mut writer = AtomicWriteFile::open(path).context("Unable to create backup file")?;
    writer
        .write_all(&bytes)
        .context("Unable to write backup file")?;
    writer.commit().context("Unable to commit backup file")?;
    Ok(())
}

pub(super) fn reject_vault_internal_export_path(vault: &Vault, path: &Path) -> Result<()> {
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

pub(super) fn read_backup_file(path: &Path) -> Result<BackupFile> {
    let bytes = fs::read(path).context("Unable to read backup file")?;
    serde_json::from_slice(&bytes).context("Invalid backup file format")
}

pub(super) fn validate_backup_file(file: &BackupFile) -> Result<()> {
    if file.format != "mcp-vault-backup" {
        bail!("Unsupported backup file version");
    }
    backup_aad(file.version)?;
    if file.cipher != "xchacha20poly1305" {
        bail!("Unsupported backup encryption method");
    }
    Ok(())
}

pub(super) fn decrypt_automatic_backup(file: &BackupFile) -> Result<Vec<u8>> {
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

type ParsedBackup = (
    Vec<(PortableConnection, SecretBundle)>,
    Vec<crate::model::PortableTrashItem>,
    Option<String>,
);

pub(super) fn parse_backup_payload(plain: &[u8], version: u8) -> Result<ParsedBackup> {
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
        return Ok((connections, Vec::new(), None));
    }
    let payload: BackupPayload =
        serde_json::from_slice(plain).context("Backup contents are corrupted")?;
    if payload.format != "mcp-vault-portable"
        || !matches!(payload.version, 4 | 5 | 6 | 7 | BACKUP_VERSION)
        || version != payload.version
    {
        bail!("Unsupported backup content version");
    }
    let connections = payload
        .connections
        .into_iter()
        .map(|item| (item.connection, item.secrets))
        .collect();
    Ok((connections, payload.trash, Some(payload.created_at)))
}

pub(super) fn merge_backup_payload(vault: &Vault, plain: &[u8], version: u8) -> Result<ImportSummary> {
    let (connections, trash, _) = parse_backup_payload(plain, version)?;
    if version == 3 {
        return vault.merge_connections(connections);
    }
    vault.merge_backup_entries(connections, trash)
}

