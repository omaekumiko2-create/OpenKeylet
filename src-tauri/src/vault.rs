use crate::{
    api_catalog,
    crypto::{MasterKey, create_owner_pin_verifier, verify_owner_pin},
    model::{
        Activity, AppState, ConnectionInput, ImportSummary, ItemModule, McpState, NewActivity,
        OwnerEditorDraft, OwnerSecretField, OwnerSecretView, PortableConnection, PublicConnection,
        SecretBundle, SecretField, SecretProfile, SecurityState, Settings, SettingsPatch,
        StoredConnection, StoredEditorDraft, VaultDocument, module_kind_has_plaintext_reveal,
    },
};
use anyhow::{Context, Result, bail};
use atomic_write_file::AtomicWriteFile;
use chrono::Utc;
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use url::Url;
use uuid::Uuid;

mod activity_log;
mod browser_ops;
mod connections;
mod normalize;
mod owner;
mod sync_merge;

pub(crate) use normalize::normalize_connection;
use normalize::*;
use sync_merge::*;

const MAX_ACTIVITIES: usize = 3_000;
const MAX_EDITOR_DRAFTS: usize = 10;
const VAULT_VERSION: u8 = 12;
#[cfg(test)]
mod lifecycle_tests;

pub fn normalize_language(raw: &str) -> String {
    crate::platform::normalize_language(raw)
}

#[derive(Clone)]
pub struct Vault {
    inner: Arc<VaultInner>,
}

struct VaultInner {
    data_dir: PathBuf,
    vault_path: PathBuf,
    lock_path: PathBuf,
    key: MasterKey,
    /// `(byte length, line count)` of `activity.jsonl` as last seen by this
    /// handle, so appends need not re-read the log to decide on compaction.
    activity_log_cache: Mutex<Option<(u64, usize)>>,
}

pub struct DecryptedConnection {
    pub stored: StoredConnection,
    pub secrets: SecretBundle,
}

impl Vault {
    pub fn open(data_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&data_dir).context("Unable to create vault directory")?;
        let bootstrap = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(data_dir.join("bootstrap.lock"))
            .context("Could not open vault startup lock")?;
        FileExt::lock_exclusive(&bootstrap).context("Could not lock vault startup process")?;

        let result = (|| {
            let vault_path = data_dir.join("vault.json");
            let key = MasterKey::load_or_create(&data_dir, vault_path.exists())?;
            let vault = Self {
                inner: Arc::new(VaultInner {
                    lock_path: data_dir.join("vault.lock"),
                    data_dir,
                    vault_path,
                    key,
                    activity_log_cache: Mutex::new(None),
                }),
            };

            if !vault.inner.vault_path.exists() {
                let document = VaultDocument {
                    version: VAULT_VERSION,
                    settings: Settings::default(),
                    browser_bridge_secret: None,
                    owner_pin: None,
                    connections: Vec::new(),
                    trash: Vec::new(),
                    deleted_ids: Vec::new(),
                    editor_drafts: Vec::new(),
                    activities: Vec::new(),
                };
                vault.with_exclusive_lock(|_| vault.write_document_unlocked(&document))?;
            } else {
                vault.require_supported_version()?;
                // Best effort: on failure the legacy entries stay in vault.json
                // and the move is retried on the next open.
                let _ = vault.migrate_legacy_activities();
            }
            Ok(vault)
        })();
        let _ = FileExt::unlock(&bootstrap);
        result
    }

    pub fn data_dir(&self) -> &Path {
        &self.inner.data_dir
    }

    pub fn storage_label(&self) -> String {
        self.inner.key.source().to_owned()
    }

    fn with_key<T>(&self, action: impl FnOnce(&MasterKey) -> Result<T>) -> Result<T> {
        action(&self.inner.key)
    }

    // Device-local integration credentials never enter portable/cloud exports.
    pub(crate) fn protect_local_state<T: serde::Serialize>(
        &self,
        value: &T,
    ) -> Result<crate::model::SecretEnvelope> {
        self.with_key(|key| key.encrypt(value))
    }

    pub(crate) fn unprotect_local_state<T: serde::de::DeserializeOwned>(
        &self,
        envelope: &crate::model::SecretEnvelope,
    ) -> Result<T> {
        self.with_key(|key| key.decrypt(envelope))
    }

    fn require_supported_version(&self) -> Result<()> {
        let bytes = fs::read(&self.inner.vault_path).context("Could not read vault")?;
        let document: VaultDocument =
            serde_json::from_slice(&bytes).context("Invalid vault file format")?;
        if !matches!(document.version, 7 | 8 | 9 | 10 | 11 | VAULT_VERSION) {
            bail!(
                "OpenKeylet supports vault versions 7 through 12; current file version is {}",
                document.version
            );
        }
        Ok(())
    }

    fn read_document(&self) -> Result<VaultDocument> {
        let lock = self.open_lock()?;
        FileExt::lock_shared(&lock).context("Could not lock vault")?;
        let result = self.read_document_unlocked();
        let _ = FileExt::unlock(&lock);
        result
    }

    fn read_document_unlocked(&self) -> Result<VaultDocument> {
        let bytes = fs::read(&self.inner.vault_path).context("Could not read vault")?;
        let mut document: VaultDocument =
            serde_json::from_slice(&bytes).context("Invalid vault file format")?;
        if !matches!(document.version, 7 | 8 | 9 | 10 | 11 | VAULT_VERSION) {
            bail!("Unsupported vault version {}", document.version);
        }
        // Reading older vaults is harmless; the next actual write uses v12
        // schema so older processes cannot mistake it for their own model.
        document.version = VAULT_VERSION;
        Ok(document)
    }

    fn write_document_unlocked(&self, document: &VaultDocument) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(document).context("Could not serialize vault")?;
        let mut file = AtomicWriteFile::open(&self.inner.vault_path)
            .context("Could not create temporary vault file")?;
        file.write_all(&bytes).context("Could not write vault")?;
        file.commit().context("Could not commit vault file")?;
        Ok(())
    }

    fn update_document<F>(&self, update: F) -> Result<()>
    where
        F: FnOnce(&mut VaultDocument) -> Result<()>,
    {
        self.with_exclusive_lock(|_| {
            let mut document = self.read_document_unlocked()?;
            update(&mut document)?;
            self.write_document_unlocked(&document)
        })
    }

    pub(crate) fn update_document_with_result<T, F>(&self, update: F) -> Result<T>
    where
        F: FnOnce(&mut VaultDocument) -> Result<T>,
    {
        self.with_exclusive_lock(|_| {
            let mut document = self.read_document_unlocked()?;
            let result = update(&mut document)?;
            self.write_document_unlocked(&document)?;
            Ok(result)
        })
    }

    fn with_exclusive_lock<T, F>(&self, action: F) -> Result<T>
    where
        F: FnOnce(&File) -> Result<T>,
    {
        let lock = self.open_lock()?;
        lock.lock_exclusive().context("Could not lock vault")?;
        let result = action(&lock);
        let _ = FileExt::unlock(&lock);
        result
    }

    fn open_lock(&self) -> Result<File> {
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.inner.lock_path)
            .context("Could not open vault lock file")
    }
}


#[cfg(test)]
mod tests;
