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

mod legacy_mvault;
pub use legacy_mvault::{export_to_file, import_from_file};
pub(crate) use legacy_mvault::{cloud_snapshot, inspect_cloud_snapshot, restore_cloud_snapshot, sync_merge_cloud_snapshot};
use legacy_mvault::*;

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
    crate::crypto::derive_argon2id_key_32(password, salt, 65_536, 3, 1)
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupPreviewItem {
    pub index: usize,
    pub kind: String,
    pub id: String,
    pub name: String,
    pub item_type: String,
    pub folder: String,
    pub summary: String,
    pub status: String,
    pub assigned_name: Option<String>,
    pub passkey_count: usize,
    pub history_count: usize,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupMergeStats {
    pub total_items: usize,
    pub new_items: usize,
    pub duplicate_skipped: usize,
    pub name_conflicts: usize,
    pub passkey_count: usize,
    pub trash_count: usize,
    pub history_entries: usize,
    pub sample_names: Vec<String>,
    pub conflict_renames: Vec<String>,
    pub items: Vec<BackupPreviewItem>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupPreview {
    pub format_label: String,
    pub version: u8,
    pub protected: bool,
    pub created_at: Option<String>,
    pub total_items: usize,
    pub new_items: usize,
    pub duplicate_skipped: usize,
    pub name_conflicts: usize,
    pub passkey_count: usize,
    pub trash_count: usize,
    pub history_entries: usize,
    pub sample_names: Vec<String>,
    pub conflict_renames: Vec<String>,
    pub items: Vec<BackupPreviewItem>,
}

pub struct PreparedBackup {
    pub preview: BackupPreview,
    pub version: u8,
    pub raw_payload: Zeroizing<Vec<u8>>,
}

const MAX_BACKUP_FILE_BYTES: usize = 64 * 1024 * 1024;

pub fn inspect_bytes_requires_password(bytes: &[u8]) -> Result<bool> {
    ensure!(bytes.len() <= MAX_BACKUP_FILE_BYTES, "Backup exceeds 64 MiB");
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("Invalid backup format")?;
    if value["format"] == "openkeylet-password-backup" {
        return Ok(true);
    }
    let file: BackupFile = serde_json::from_value(value).context("Invalid backup file format")?;
    validate_backup_file(&file)?;
    Ok(false)
}

pub fn inspect_file_requires_password(path: &Path) -> Result<bool> {
    ensure!(
        fs::metadata(path)?.len() <= MAX_BACKUP_FILE_BYTES as u64,
        "Backup exceeds 64 MiB"
    );
    let bytes = fs::read(path).context("Unable to read backup")?;
    inspect_bytes_requires_password(&bytes)
}

pub fn prepare_import_bytes_with_password(
    vault: &Vault,
    bytes: &[u8],
    password: &str,
) -> Result<PreparedBackup> {
    ensure!(bytes.len() <= MAX_BACKUP_FILE_BYTES, "Backup exceeds 64 MiB");
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("Invalid backup format")?;
    let (plain, version, protected) = if value["format"] == "openkeylet-password-backup" {
        let file: PasswordBackupFile = serde_json::from_value(value)?;
        ensure!(
            file.version == 1
                && file.kdf == "argon2id-64m-t3-p1"
                && file.cipher == "xchacha20poly1305",
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
        let payload: BackupPayload =
            serde_json::from_slice(&plain).context("Backup contents are corrupted")?;
        let v = payload.version;
        (plain, v, true)
    } else {
        let file: BackupFile =
            serde_json::from_value(value).context("Invalid backup file format")?;
        validate_backup_file(&file)?;
        let plain = Zeroizing::new(decrypt_automatic_backup(&file)?);
        (plain, file.version, false)
    };

    let (entries, trash, created_at) = parse_backup_payload(&plain, version)?;
    let stats = vault.preview_merge_backup_entries(&entries, &trash)?;
    let format_label = if protected {
        format!("Protected .mvault (v{version})")
    } else {
        format!("Legacy self-unlocking .mvault (v{version})")
    };
    Ok(PreparedBackup {
        preview: BackupPreview {
            format_label,
            version,
            protected,
            created_at,
            total_items: stats.total_items,
            new_items: stats.new_items,
            duplicate_skipped: stats.duplicate_skipped,
            name_conflicts: stats.name_conflicts,
            passkey_count: stats.passkey_count,
            trash_count: stats.trash_count,
            history_entries: stats.history_entries,
            sample_names: stats.sample_names,
            conflict_renames: stats.conflict_renames,
            items: stats.items,
        },
        version,
        raw_payload: plain,
    })
}

pub fn prepare_import_with_password(
    vault: &Vault,
    path: &Path,
    password: &str,
) -> Result<PreparedBackup> {
    ensure!(
        fs::metadata(path)?.len() <= MAX_BACKUP_FILE_BYTES as u64,
        "Backup exceeds 64 MiB"
    );
    let bytes = fs::read(path).context("Unable to read backup")?;
    prepare_import_bytes_with_password(vault, &bytes, password)
}

/// Builds a selective-import preview for decrypted third-party vault packages
/// (Bitwarden encrypted JSON, KeePass `.kdbx`) using the exact same duplicate &
/// conflict-rename simulation as `.mvault` backups.
pub fn preview_migration_entries(
    vault: &Vault,
    format_label: String,
    entries: &[(PortableConnection, SecretBundle)],
) -> Result<BackupPreview> {
    let stats = vault.preview_merge_backup_entries(entries, &[])?;
    Ok(BackupPreview {
        format_label,
        version: 0,
        protected: true,
        created_at: None,
        total_items: stats.total_items,
        new_items: stats.new_items,
        duplicate_skipped: stats.duplicate_skipped,
        name_conflicts: stats.name_conflicts,
        passkey_count: stats.passkey_count,
        trash_count: stats.trash_count,
        history_entries: stats.history_entries,
        sample_names: stats.sample_names,
        conflict_renames: stats.conflict_renames,
        items: stats.items,
    })
}

pub fn commit_prepared_import(
    vault: &Vault,
    raw_payload: &[u8],
    version: u8,
) -> Result<ImportSummary> {
    commit_prepared_import_selected(vault, raw_payload, version, None, None)
}

pub fn commit_prepared_import_selected(
    vault: &Vault,
    raw_payload: &[u8],
    version: u8,
    selected_item_indices: Option<&[usize]>,
    selected_trash_indices: Option<&[usize]>,
) -> Result<ImportSummary> {
    let (connections, trash, _) = parse_backup_payload(raw_payload, version)?;
    let connections = match selected_item_indices {
        Some(indices) => {
            let allow: std::collections::HashSet<usize> = indices.iter().copied().collect();
            connections
                .into_iter()
                .enumerate()
                .filter_map(|(idx, item)| allow.contains(&idx).then_some(item))
                .collect()
        }
        None => connections,
    };
    let trash = if version == 3 {
        Vec::new()
    } else {
        match selected_trash_indices {
            Some(indices) => {
                let allow: std::collections::HashSet<usize> = indices.iter().copied().collect();
                trash
                    .into_iter()
                    .enumerate()
                    .filter_map(|(idx, item)| allow.contains(&idx).then_some(item))
                    .collect()
            }
            None => trash,
        }
    };
    if connections.is_empty() && trash.is_empty() {
        return Ok(ImportSummary {
            added: 0,
            merged: 0,
        });
    }
    if version == 3 {
        return vault.merge_connections(connections);
    }
    vault.merge_backup_entries(connections, trash)
}

pub fn import_with_password(vault: &Vault, path: &Path, password: &str) -> Result<ImportSummary> {
    let prepared = prepare_import_with_password(vault, path, password)?;
    commit_prepared_import(vault, &prepared.raw_payload, prepared.version)
}

/// One active item of an earlier cloud snapshot, compared with this vault by id.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPreviewItem {
    pub id: String,
    pub name: String,
    /// The item's name in this vault, when it differs from the version's.
    pub current_name: Option<String>,
    /// The name a restore would use because another item now holds the version's name.
    pub assigned_name: Option<String>,
    pub item_type: String,
    pub folder: String,
    pub summary: String,
    /// `changed`, `deleted`, `trash` or `same`; only `same` cannot be restored.
    pub status: String,
    pub passkey_count: usize,
    pub history_count: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPreview {
    pub created_at: String,
    pub total_items: usize,
    pub changed: usize,
    pub deleted: usize,
    pub in_trash: usize,
    pub same: usize,
    pub items: Vec<HistoryPreviewItem>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryRestoreSummary {
    pub restored: usize,
    pub unchanged: usize,
}

/// Only the active items of a version are offered. Its trash and tombstones describe
/// deletions, and restoring never deletes: items created after the version stay.
fn history_snapshot_items(plain: &[u8]) -> Result<(Vec<(PortableConnection, SecretBundle)>, String)> {
    let payload: BackupPayload =
        serde_json::from_slice(plain).context("Backup contents are corrupted")?;
    ensure!(
        payload.format == "mcp-vault-portable"
            && matches!(payload.version, 4 | 5 | 6 | 7 | BACKUP_VERSION),
        "Unsupported cloud backup content version"
    );
    let items = payload
        .connections
        .into_iter()
        .map(|item| (item.connection, item.secrets))
        .collect();
    Ok((items, payload.created_at))
}

pub(crate) fn history_preview(vault: &Vault, plain: &[u8]) -> Result<HistoryPreview> {
    let (items, created_at) = history_snapshot_items(plain)?;
    let items = vault.preview_history_items(&items)?;
    let count = |status: &str| items.iter().filter(|item| item.status == status).count();
    Ok(HistoryPreview {
        created_at,
        total_items: items.len(),
        changed: count("changed"),
        deleted: count("deleted"),
        in_trash: count("trash"),
        same: count("same"),
        items,
    })
}

pub(crate) fn restore_history_selection(
    vault: &Vault,
    plain: &[u8],
    ids: &[uuid::Uuid],
    version_label: &str,
) -> Result<HistoryRestoreSummary> {
    let wanted: std::collections::HashSet<uuid::Uuid> = ids.iter().copied().collect();
    let (items, _) = history_snapshot_items(plain)?;
    let selected: Vec<_> = items
        .into_iter()
        .filter(|(public, _)| wanted.contains(&public.id))
        .collect();
    if selected.is_empty() {
        return Ok(HistoryRestoreSummary::default());
    }
    vault.restore_history_items(selected, version_label)
}


#[cfg(test)]
mod tests;
