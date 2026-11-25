//! Opt-in encrypted snapshots in a user-owned GitHub private repository.
//!
//! This is backup/merge-restore, not an automatic multi-writer sync protocol.
//! The vault leaves this device only as an encrypted snapshot. By default its key is
//! kept in a second private repository of the same account (see `key_repo`), so
//! binding the account is all another device needs; a caller that supplies its own
//! key keeps it off the host instead. Repository history retains older ciphertext,
//! which `history` lists and restores items from; disconnecting removes local
//! authorization, not remote history.

use crate::{
    backup,
    crypto::{decrypt_bytes, encrypt_bytes},
    model::{ImportSummary, SecretEnvelope},
    vault::Vault,
};
use anyhow::{Context, Result, bail};
use atomic_write_file::AtomicWriteFile;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::Utc;
use reqwest::{
    Client, Method, Response, StatusCode,
    header::{AUTHORIZATION, HeaderValue},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha1::{Digest, Sha1};
use std::{fs, io::Write, time::Duration};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const CLOUD_FILE: &str = "openkeylet.vault.json";
const LOCAL_FILE: &str = "github-backup.json";
const CLOUD_FORMAT: &str = "openkeylet-cloud-backup";
const LOCAL_FORMAT: &str = "openkeylet-github-device";
const VAULT_TOPIC: &str = "openkeylet-vault";
const CLOUD_AAD: &[u8] = b"openkeylet/cloud-backup/v1";
const MAX_CLOUD_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = MAX_CLOUD_BYTES * 2;
const MAX_DISCOVERY_PROBES: usize = 15;

mod auth;
mod helpers;
mod history;
mod key_repo;
use helpers::*;
use key_repo::key_repo_name;
pub use auth::{AccountStatus, AuthInput, DiscoveredVaultRepo};
pub use history::{SnapshotVersion, VersionList, VersionPreview, VersionRestoreResult};

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct ConnectInput {
    pub repository: String,
    pub token: String,
    /// Empty by default: the key then lives in the key repository. A caller that keeps
    /// its own key supplies it here, and the key repository is not used.
    #[serde(default)]
    pub recovery_key: String,
    pub mode: String,
    #[serde(default)]
    pub auth_source: String,
    #[serde(default)]
    pub create_repository: bool,
    #[serde(default)]
    pub auto_sync: bool,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub server_url: String,
}

#[derive(Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupStatus {
    pub connected: bool,
    pub provider: String,
    pub server_url: String,
    pub repository: String,
    /// `owner/name` of the key repository, or empty when the owner holds the key.
    pub key_repository: String,
    pub branch: String,
    pub auto_sync: bool,
    pub pending_sync: bool,
    pub last_sync_error: Option<String>,
    pub needs_restore: bool,
    pub has_remote_backup: bool,
    pub last_backup_at: Option<String>,
    pub last_restore_at: Option<String>,
    pub last_synced_at: Option<String>,
    pub remote_backup_at: Option<String>,
    pub remote_item_count: Option<usize>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreResult {
    pub summary: ImportSummary,
    pub status: BackupStatus,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResult {
    pub action: String,
    pub merge: crate::model::SyncMergeSummary,
    pub status: BackupStatus,
}

fn default_provider() -> String {
    "github".to_owned()
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct DeviceConfig {
    format: String,
    #[serde(default = "default_provider")]
    provider: String,
    #[serde(default)]
    server_url: String,
    owner: String,
    repo: String,
    repository_id: u64,
    branch: String,
    token: String,
    recovery_key: String,
    /// Name of the key repository under `owner`, or empty when the owner holds the key.
    #[serde(default)]
    key_repo: String,
    base_sha: Option<String>,
    #[serde(default)]
    auto_sync: bool,
    needs_restore: bool,
    has_remote_backup: bool,
    last_backup_at: Option<String>,
    last_restore_at: Option<String>,
    #[serde(default)]
    last_synced_at: Option<String>,
    #[serde(default)]
    last_synced_fingerprint: Option<String>,
    #[serde(default)]
    pending_sync: bool,
    #[serde(default)]
    last_sync_error: Option<String>,
    remote_backup_at: Option<String>,
    remote_item_count: Option<usize>,
}

impl DeviceConfig {
    fn is_gitea(&self) -> bool {
        self.provider == "gitea"
    }

    fn status(&self) -> BackupStatus {
        self.status_with_fingerprint(None)
    }

    fn status_with_fingerprint(&self, current_fingerprint: Option<&str>) -> BackupStatus {
        let local_dirty = match (current_fingerprint, self.last_synced_fingerprint.as_deref()) {
            (Some(curr), Some(last)) => curr != last,
            _ => false,
        };
        BackupStatus {
            connected: true,
            provider: if self.provider.is_empty() {
                "github".to_owned()
            } else {
                self.provider.clone()
            },
            server_url: self.server_url.clone(),
            repository: format!("{}/{}", self.owner, self.repo),
            key_repository: if self.key_repo.is_empty() {
                String::new()
            } else {
                format!("{}/{}", self.owner, self.key_repo)
            },
            branch: self.branch.clone(),
            auto_sync: self.auto_sync,
            pending_sync: self.pending_sync || local_dirty || self.last_sync_error.is_some(),
            last_sync_error: self.last_sync_error.clone(),
            needs_restore: self.needs_restore,
            has_remote_backup: self.has_remote_backup,
            last_backup_at: self.last_backup_at.clone(),
            last_restore_at: self.last_restore_at.clone(),
            last_synced_at: self.last_synced_at.clone(),
            remote_backup_at: self.remote_backup_at.clone(),
            remote_item_count: self.remote_item_count,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudFile {
    format: String,
    version: u8,
    cipher: String,
    payload: SecretEnvelope,
}

#[derive(Deserialize)]
struct Repository {
    id: u64,
    private: bool,
    archived: bool,
    #[serde(default)]
    disabled: bool,
    default_branch: String,
}

#[derive(Deserialize)]
struct RepoListOwner {
    #[serde(alias = "username")]
    login: String,
}

#[derive(Deserialize)]
struct RepoListItem {
    name: String,
    #[serde(default)]
    full_name: String,
    owner: Option<RepoListOwner>,
    private: bool,
    #[serde(default)]
    archived: bool,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    default_branch: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    topics: Vec<String>,
    #[serde(default)]
    updated_at: String,
}

#[derive(Deserialize)]
struct CloudEnvelopeHeader {
    format: String,
    version: u8,
}

#[derive(Deserialize)]
struct GithubUser {
    #[serde(alias = "username")]
    login: String,
}

#[derive(Deserialize)]
struct ContentFile {
    #[serde(rename = "type")]
    kind: String,
    sha: String,
    size: usize,
    #[serde(default)]
    encoding: String,
    #[serde(default)]
    content: String,
}

#[derive(Deserialize)]
struct Blob {
    sha: String,
    size: usize,
    encoding: String,
    content: String,
}

struct RemoteFile {
    sha: String,
    bytes: Vec<u8>,
}

pub struct GithubBackup {
    vault: Vault,
    client: Client,
    api_base: Url,
}

impl GithubBackup {
    pub fn new(vault: Vault) -> Result<Self> {
        let client = Client::builder()
            .user_agent(concat!("OpenKeylet/", env!("CARGO_PKG_VERSION")))
            // Never follow a repository rename or an attacker-controlled redirect
            // while holding a GitHub token. The user can reconnect explicitly.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(40))
            .build()
            .context("GITHUB_NETWORK")?;
        Ok(Self {
            vault,
            client,
            api_base: Url::parse("https://api.github.com/").expect("static GitHub URL"),
        })
    }

    pub fn status(&self) -> Result<BackupStatus> {
        let current_fp = self.vault.sync_content_fingerprint().ok();
        let status = self
            .load()?
            .map(|config| config.status_with_fingerprint(current_fp.as_deref()))
            .unwrap_or_default();
        Ok(status)
    }

    pub fn is_auto_sync_enabled(&self) -> bool {
        self.load()
            .ok()
            .flatten()
            .is_some_and(|config| config.auto_sync)
    }

    pub fn mark_pending_sync(&self) -> Result<Option<BackupStatus>> {
        let Some(mut config) = self.load()? else {
            return Ok(None);
        };
        if !config.auto_sync {
            return Ok(None);
        }
        config.pending_sync = true;
        self.save(&config)?;
        Ok(Some(config.status()))
    }

    pub fn record_sync_error(&self, error: &str) -> Result<Option<BackupStatus>> {
        let Some(mut config) = self.load()? else {
            return Ok(None);
        };
        let code = error
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .find(|part| part.starts_with("GITHUB_"))
            .unwrap_or("GITHUB_NETWORK")
            .to_owned();
        config.pending_sync = true;
        config.last_sync_error = Some(code);
        self.save(&config)?;
        Ok(Some(config.status()))
    }

    pub fn set_auto_sync(&self, enabled: bool) -> Result<BackupStatus> {
        let mut config = self.connected()?;
        config.auto_sync = enabled;
        self.save(&config)?;
        let current_fp = self.vault.sync_content_fingerprint().ok();
        Ok(config.status_with_fingerprint(current_fp.as_deref()))
    }

    pub async fn account(&self, input: AuthInput) -> Result<AccountStatus> {
        let provider = normalize_provider(&input.provider)?;
        let server_url = normalize_server_url(&provider, &input.server_url)?;
        let auth_source = if provider == "gitea" && input.auth_source.trim().is_empty() {
            "token"
        } else {
            &input.auth_source
        };
        let token = auth::token(auth_source, &input.token).await?;
        let user = self.user(&token, &provider, &server_url).await?;
        let discovered = self
            .discover_private_vault_repos(&token, &provider, &server_url, &user.login)
            .await;
        Ok(AccountStatus {
            login: user.login,
            discovery_failed: discovered.is_none(),
            discovered_repos: discovered.unwrap_or_default(),
        })
    }

    /// `None` when the repository list could not be read. The account itself is fine
    /// then, but "nothing found" would be wrong and could lead to a second vault repo.
    async fn discover_private_vault_repos(
        &self,
        token: &str,
        provider: &str,
        server_url: &str,
        login: &str,
    ) -> Option<Vec<DiscoveredVaultRepo>> {
        use futures_util::stream::{self, StreamExt};

        let request = self
            .api_request_for(Method::GET, &["user", "repos"], token, provider, server_url)
            .ok()?;
        let request = if provider == "gitea" {
            request.query(&[("limit", "50")])
        } else {
            request.query(&[
                ("affiliation", "owner"),
                ("visibility", "private"),
                ("sort", "updated"),
                ("per_page", "100"),
            ])
        };
        let response = request.send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        let repos = read_json::<Vec<RepoListItem>>(response).await.ok()?;

        // Strict privacy guard: NEVER inspect or recommend public, archived, or disabled repos.
        let mut candidates: Vec<(u8, String, String, String, bool, String)> = repos
            .into_iter()
            .filter(|r| r.private && !r.archived && !r.disabled && !r.default_branch.is_empty())
            .filter_map(|r| {
                let owner = r
                    .owner
                    .as_ref()
                    .map(|o| o.login.clone())
                    .or_else(|| r.full_name.split('/').next().map(str::to_owned))
                    .unwrap_or_else(|| login.to_owned());
                if owner.is_empty() || r.name.is_empty() {
                    return None;
                }
                let has_topic = r
                    .topics
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(VAULT_TOPIC));
                let name_lower = r.name.to_ascii_lowercase();
                let desc_lower = r
                    .description
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let priority = if has_topic || name_lower == VAULT_TOPIC {
                    0
                } else if name_lower.contains("openkeylet") || desc_lower.contains("openkeylet") {
                    1
                } else if name_lower.contains("vault") {
                    2
                } else {
                    3
                };
                Some((
                    priority,
                    owner,
                    r.name,
                    r.default_branch,
                    has_topic,
                    r.updated_at,
                ))
            })
            .collect();

        candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.5.cmp(&a.5)));
        candidates.truncate(MAX_DISCOVERY_PROBES);

        let mut discovered: Vec<DiscoveredVaultRepo> = stream::iter(candidates)
            .map(|(priority, owner, name, default_branch, has_topic, updated_at)| async move {
                let has_vault_file = self
                    .probe_vault_file(&owner, &name, &default_branch, token, provider, server_url)
                    .await;
                if has_vault_file || has_topic || priority == 0 {
                    Some(DiscoveredVaultRepo {
                        full_name: format!("{owner}/{name}"),
                        owner,
                        name,
                        default_branch,
                        has_vault_file,
                        has_topic,
                        updated_at,
                        private: true,
                    })
                } else {
                    None
                }
            })
            .buffer_unordered(6)
            .filter_map(|item| async move { item })
            .collect()
            .await;

        discovered.sort_by(|a, b| {
            b.has_vault_file
                .cmp(&a.has_vault_file)
                .then_with(|| b.has_topic.cmp(&a.has_topic))
                .then_with(|| b.updated_at.cmp(&a.updated_at))
        });
        Some(discovered)
    }

    async fn probe_vault_file(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        token: &str,
        provider: &str,
        server_url: &str,
    ) -> bool {
        let Ok(req) = self.request_for(
            Method::GET,
            owner,
            repo,
            &["contents", CLOUD_FILE],
            token,
            provider,
            server_url,
        ) else {
            return false;
        };
        let Ok(response) = req.query(&[("ref", branch)]).send().await else {
            return false;
        };
        if !response.status().is_success() {
            return false;
        }
        let Ok(file) = read_json::<ContentFile>(response).await else {
            return false;
        };
        if file.kind != "file" || file.size == 0 || file.size > MAX_CLOUD_BYTES {
            return false;
        }
        if file.encoding == "base64" && !file.content.is_empty() {
            let Ok(bytes) = decode_content(&file.content) else {
                return false;
            };
            return serde_json::from_slice::<CloudEnvelopeHeader>(&bytes)
                .is_ok_and(|header| header.format == CLOUD_FORMAT && header.version == 1);
        }
        // Files larger than 1 MB omit inline content on GitHub Contents API; presence of
        // openkeylet.vault.json on a private repo is still a strong fingerprint.
        valid_sha(&file.sha)
    }

    async fn tag_repository_topic(
        &self,
        owner: &str,
        repo: &str,
        token: &str,
        provider: &str,
        server_url: &str,
    ) {
        if provider != "github" {
            return;
        }
        if let Ok(req) = self.request_for(
            Method::PUT,
            owner,
            repo,
            &["topics"],
            token,
            provider,
            server_url,
        ) {
            let _ = req
                .json(&serde_json::json!({ "names": [VAULT_TOPIC] }))
                .send()
                .await;
        }
    }

    async fn user(&self, token: &str, provider: &str, server_url: &str) -> Result<GithubUser> {
        let response = self
            .api_request_for(Method::GET, &["user"], token, provider, server_url)?
            .send()
            .await
            .context("GITHUB_NETWORK")?;
        check_response(&response)?;
        let user: GithubUser = read_json(response).await?;
        parse_repository(&format!("{}/vault", user.login)).context("GITHUB_RESPONSE_INVALID")?;
        Ok(user)
    }

    pub fn recovery_key(&self) -> Result<String> {
        Ok(self.connected()?.recovery_key.clone())
    }

    pub fn disconnect(&self) -> Result<BackupStatus> {
        match fs::remove_file(self.vault.data_dir().join(LOCAL_FILE)) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => bail!("GITHUB_LOCAL_STATE"),
        }
        Ok(BackupStatus::default())
    }

    pub async fn connect(&self, input: ConnectInput) -> Result<BackupStatus> {
        if !matches!(input.mode.as_str(), "new" | "existing") {
            bail!("GITHUB_MODE_INVALID");
        }
        let provider = normalize_provider(&input.provider)?;
        let server_url = normalize_server_url(&provider, &input.server_url)?;
        let (owner, repo) = parse_repository_for(&input.repository, &server_url)?;
        let supplied_key = input.recovery_key.trim();
        if !supplied_key.is_empty() {
            parse_recovery_key(supplied_key)?;
        }
        let auth_source = if provider == "gitea" && input.auth_source.trim().is_empty() {
            "token"
        } else {
            &input.auth_source
        };
        let token = auth::token(auth_source, &input.token).await?;
        if input.create_repository {
            if input.mode != "new" {
                bail!("GITHUB_CREATE_MODE");
            }
            let user = self.user(&token, &provider, &server_url).await?;
            if !user.login.eq_ignore_ascii_case(&owner) {
                bail!("GITHUB_CREATE_OWNER");
            }
            // Creating is opt-in. Never adopt or change an existing repository.
            let existing = self
                .request_for(Method::GET, &owner, &repo, &[], &token, &provider, &server_url)?
                .send()
                .await
                .context("GITHUB_NETWORK")?;
            if existing.status().is_success() {
                bail!("GITHUB_REPOSITORY_EXISTS");
            }
            if existing.status() != StatusCode::NOT_FOUND {
                check_response(&existing)?;
            }
            let response = self
                .api_request_for(Method::POST, &["user", "repos"], &token, &provider, &server_url)?
                .json(&serde_json::json!({"name":repo,"private":true,"auto_init":true,"description":"Encrypted OpenKeylet vault backups"}))
                .send()
                .await
                .context("GITHUB_CREATE_UNCONFIRMED")?;
            if response.status() == StatusCode::UNPROCESSABLE_ENTITY {
                bail!("GITHUB_REPOSITORY_EXISTS");
            }
            if response.status().is_server_error() {
                bail!("GITHUB_CREATE_UNCONFIRMED");
            }
            check_response(&response)?;
            let created: Repository = read_json(response)
                .await
                .context("GITHUB_CREATE_UNCONFIRMED")?;
            if !created.private || created.id == 0 {
                bail!("GITHUB_PRIVATE_REQUIRED");
            }
            self.tag_repository_topic(&owner, &repo, &token, &provider, &server_url)
                .await;
        }
        let repository = self
            .repository(&owner, &repo, &token, &provider, &server_url)
            .await?;
        let mut config = DeviceConfig {
            format: LOCAL_FORMAT.to_owned(),
            provider,
            server_url,
            owner,
            repo,
            repository_id: repository.id,
            branch: repository.default_branch,
            token: token.to_string(),
            recovery_key: String::new(),
            key_repo: String::new(),
            base_sha: None,
            auto_sync: input.auto_sync,
            needs_restore: false,
            has_remote_backup: false,
            last_backup_at: None,
            last_restore_at: None,
            last_synced_at: None,
            last_synced_fingerprint: None,
            pending_sync: false,
            last_sync_error: None,
            remote_backup_at: None,
            remote_item_count: None,
        };
        let remote = self.remote_file(&config, &config.branch).await?;
        match (input.mode.as_str(), remote.is_some()) {
            ("new", true) => bail!("GITHUB_BACKUP_EXISTS"),
            ("existing", false) => bail!("GITHUB_BACKUP_MISSING"),
            _ => (),
        }
        if supplied_key.is_empty() {
            let key_repo = key_repo_name(&config.owner, &config.repo)?;
            let stored = self
                .read_repo_key(
                    &config.owner,
                    &key_repo,
                    &config.token,
                    &config.provider,
                    &config.server_url,
                )
                .await?;
            let key = match stored {
                Some(key) => key,
                // Without its key an existing snapshot cannot be opened, and a fresh
                // key would not match it.
                None if remote.is_some() => bail!("GITHUB_KEY_REPO_MISSING"),
                None => {
                    self.create_repo_key(
                        &config.owner,
                        &key_repo,
                        &config.token,
                        &config.provider,
                        &config.server_url,
                    )
                    .await?
                }
            };
            config.recovery_key = key.to_string();
            config.key_repo = key_repo;
        } else {
            config.recovery_key = supplied_key.to_owned();
        }
        if let Some(remote) = remote {
            let plain = decrypt_snapshot(&remote.bytes, &config.recovery_key)?;
            let (created_at, count) =
                backup::inspect_cloud_snapshot(&plain).context("GITHUB_BACKUP_INVALID")?;
            // Merely seeing the remote SHA is not permission to overwrite it.
            // A newly connected device must first restore/sync this snapshot.
            config.needs_restore = true;
            config.has_remote_backup = true;
            config.remote_backup_at = Some(created_at);
            config.remote_item_count = Some(count);
        }
        self.save(&config)?;
        Ok(config.status())
    }

    pub async fn sync(&self) -> Result<SyncResult> {
        let mut config = self.connected()?;
        self.check_repository(&config).await?;
        let local_was_empty = self
            .vault
            .export_backup_entries()
            .map(|(active, trash)| active.is_empty() && trash.is_empty())
            .unwrap_or(false)
            && self
                .vault
                .export_tombstones()
                .map(|t| t.is_empty())
                .unwrap_or(false);
        let before_fp = self
            .vault
            .sync_content_fingerprint()
            .context("GITHUB_LOCAL_VAULT")?;
        let mut total_merge = crate::model::SyncMergeSummary::default();
        let mut pulled = false;

        let remote = self.remote_file(&config, &config.branch).await?;
        if let Some(remote_file) = remote.as_ref()
            && config.base_sha.as_deref() != Some(remote_file.sha.as_str())
        {
            let plain = decrypt_snapshot(&remote_file.bytes, &config.recovery_key)?;
            let (created_at, count) =
                backup::inspect_cloud_snapshot(&plain).context("GITHUB_BACKUP_INVALID")?;
            let merged = backup::sync_merge_cloud_snapshot(&self.vault, &plain)
                .context("GITHUB_RESTORE_FAILED")?;
            total_merge.added += merged.added;
            total_merge.updated += merged.updated;
            total_merge.deleted += merged.deleted;
            total_merge.unchanged += merged.unchanged;
            config.base_sha = Some(remote_file.sha.clone());
            config.needs_restore = false;
            config.has_remote_backup = true;
            config.remote_backup_at = Some(created_at);
            config.remote_item_count = Some(count);
            config.last_restore_at = Some(Utc::now().to_rfc3339());
            pulled = true;
        }

        let after_pull_fp = self
            .vault
            .sync_content_fingerprint()
            .context("GITHUB_LOCAL_VAULT")?;
        let local_had_changes = match config.last_synced_fingerprint.as_deref() {
            Some(last) => last != before_fp.as_str(),
            None => !local_was_empty,
        };
        let needs_push = remote.is_none() || local_had_changes;

        if !needs_push {
            let now = Utc::now().to_rfc3339();
            config.last_synced_at = Some(now);
            config.last_synced_fingerprint = Some(after_pull_fp);
            config.pending_sync = false;
            config.last_sync_error = None;
            self.save(&config)?;
            return Ok(SyncResult {
                action: if pulled { "pulled" } else { "up_to_date" }.to_owned(),
                merge: total_merge,
                status: config.status(),
            });
        }

        // Push merged encrypted snapshot with compare-and-swap; retry once on 409 conflict.
        for attempt in 0..2 {
            match self.push_encrypted_snapshot(&mut config).await {
                Ok(()) => {
                    let final_fp = self
                        .vault
                        .sync_content_fingerprint()
                        .context("GITHUB_LOCAL_VAULT")?;
                    let now = Utc::now().to_rfc3339();
                    config.last_synced_at = Some(now);
                    config.last_synced_fingerprint = Some(final_fp);
                    config.pending_sync = false;
                    config.last_sync_error = None;
                    self.save(&config)?;
                    return Ok(SyncResult {
                        action: if pulled { "merged" } else { "pushed" }.to_owned(),
                        merge: total_merge,
                        status: config.status(),
                    });
                }
                Err(error) if attempt == 0 && error.to_string().contains("GITHUB_CONFLICT") => {
                    if let Some(latest) = self.remote_file(&config, &config.branch).await? {
                        let plain = decrypt_snapshot(&latest.bytes, &config.recovery_key)?;
                        let (created_at, count) =
                            backup::inspect_cloud_snapshot(&plain).context("GITHUB_BACKUP_INVALID")?;
                        let merged = backup::sync_merge_cloud_snapshot(&self.vault, &plain)
                            .context("GITHUB_RESTORE_FAILED")?;
                        total_merge.added += merged.added;
                        total_merge.updated += merged.updated;
                        total_merge.deleted += merged.deleted;
                        total_merge.unchanged += merged.unchanged;
                        config.base_sha = Some(latest.sha);
                        config.needs_restore = false;
                        config.has_remote_backup = true;
                        config.remote_backup_at = Some(created_at);
                        config.remote_item_count = Some(count);
                        config.last_restore_at = Some(Utc::now().to_rfc3339());
                        pulled = true;
                        continue;
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        }
        bail!("GITHUB_CONFLICT")
    }

    async fn push_encrypted_snapshot(&self, config: &mut DeviceConfig) -> Result<()> {
        let plain = backup::cloud_snapshot(&self.vault).context("GITHUB_LOCAL_VAULT")?;
        let (created_at, count) =
            backup::inspect_cloud_snapshot(&plain).context("GITHUB_LOCAL_VAULT")?;
        let encrypted = encrypt_snapshot(&plain, &config.recovery_key)?;
        let expected_sha = blob_sha(&encrypted);
        let mut payload = serde_json::json!({
            "message": "Update encrypted OpenKeylet backup",
            "content": STANDARD.encode(&encrypted),
            "branch": config.branch,
        });
        if let Some(sha) = &config.base_sha {
            payload["sha"] = serde_json::Value::String(sha.clone());
        }
        let method = if config.is_gitea() && config.base_sha.is_none() {
            Method::POST
        } else {
            Method::PUT
        };
        let response = self
            .request_for(
                method,
                &config.owner,
                &config.repo,
                &["contents", CLOUD_FILE],
                &config.token,
                &config.provider,
                &config.server_url,
            )?
            .json(&payload)
            .send()
            .await
            .context("GITHUB_UPLOAD_UNCONFIRMED")?;
        check_response(&response)?;
        let result: serde_json::Value = read_json(response).await?;
        if result
            .pointer("/content/sha")
            .and_then(|value| value.as_str())
            != Some(&expected_sha)
        {
            bail!("GITHUB_UPLOAD_UNCONFIRMED");
        }
        config.base_sha = Some(expected_sha);
        config.has_remote_backup = true;
        config.remote_backup_at = Some(created_at);
        config.remote_item_count = Some(count);
        config.last_backup_at = Some(Utc::now().to_rfc3339());
        Ok(())
    }

    pub async fn upload(&self) -> Result<BackupStatus> {
        let mut config = self.connected()?;
        if config.needs_restore {
            bail!("GITHUB_RESTORE_REQUIRED");
        }
        self.check_repository(&config).await?;
        let remote = self.remote_file(&config, &config.branch).await?;
        if remote.as_ref().map(|file| file.sha.as_str()) != config.base_sha.as_deref() {
            config.needs_restore = true;
            config.has_remote_backup = remote.is_some();
            self.save(&config)?;
            bail!("GITHUB_REMOTE_CHANGED");
        }
        self.push_encrypted_snapshot(&mut config).await?;
        let fp = self
            .vault
            .sync_content_fingerprint()
            .context("GITHUB_LOCAL_VAULT")?;
        config.last_synced_at = config.last_backup_at.clone();
        config.last_synced_fingerprint = Some(fp);
        config.pending_sync = false;
        config.last_sync_error = None;
        self.save(&config)?;
        Ok(config.status())
    }

    pub async fn restore(&self) -> Result<RestoreResult> {
        let mut config = self.connected()?;
        self.check_repository(&config).await?;
        let remote = self
            .remote_file(&config, &config.branch)
            .await?
            .context("GITHUB_BACKUP_MISSING")?;
        let plain = decrypt_snapshot(&remote.bytes, &config.recovery_key)?;
        let (created_at, count) =
            backup::inspect_cloud_snapshot(&plain).context("GITHUB_BACKUP_INVALID")?;
        // Merge is transactional: duplicate entries are skipped and differing
        // entries are retained under distinct names. Local entries are not lost.
        let summary =
            backup::restore_cloud_snapshot(&self.vault, &plain).context("GITHUB_RESTORE_FAILED")?;
        config.base_sha = Some(remote.sha);
        config.needs_restore = false;
        config.has_remote_backup = true;
        config.remote_backup_at = Some(created_at);
        config.remote_item_count = Some(count);
        config.last_restore_at = Some(Utc::now().to_rfc3339());
        config.last_synced_at = config.last_restore_at.clone();
        config.last_synced_fingerprint = self.vault.sync_content_fingerprint().ok();
        config.pending_sync = false;
        config.last_sync_error = None;
        self.save(&config)?;
        Ok(RestoreResult {
            summary,
            status: config.status(),
        })
    }

    fn load(&self) -> Result<Option<DeviceConfig>> {
        let path = self.vault.data_dir().join(LOCAL_FILE);
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => bail!("GITHUB_LOCAL_STATE"),
        };
        if bytes.len() > 64 * 1024 {
            bail!("GITHUB_LOCAL_STATE");
        }
        let envelope = serde_json::from_slice(&bytes).context("GITHUB_LOCAL_STATE")?;
        let config: DeviceConfig = self
            .vault
            .unprotect_local_state(&envelope)
            .context("GITHUB_LOCAL_STATE")?;
        if config.format != LOCAL_FORMAT {
            bail!("GITHUB_LOCAL_STATE");
        }
        Ok(Some(config))
    }

    fn connected(&self) -> Result<DeviceConfig> {
        self.load()?.context("GITHUB_NOT_CONNECTED")
    }

    fn save(&self, config: &DeviceConfig) -> Result<()> {
        let envelope = self
            .vault
            .protect_local_state(config)
            .context("GITHUB_LOCAL_STATE")?;
        let bytes = serde_json::to_vec(&envelope).context("GITHUB_LOCAL_STATE")?;
        let mut file = AtomicWriteFile::open(self.vault.data_dir().join(LOCAL_FILE))
            .context("GITHUB_LOCAL_STATE")?;
        file.write_all(&bytes).context("GITHUB_LOCAL_STATE")?;
        file.commit().context("GITHUB_LOCAL_STATE")?;
        Ok(())
    }

    fn request_for(
        &self,
        method: Method,
        owner: &str,
        repo: &str,
        suffix: &[&str],
        token: &str,
        provider: &str,
        server_url: &str,
    ) -> Result<reqwest::RequestBuilder> {
        let mut segments = vec!["repos", owner, repo];
        segments.extend(suffix);
        self.api_request_for(method, &segments, token, provider, server_url)
    }

    fn api_request_for(
        &self,
        method: Method,
        segments: &[&str],
        token: &str,
        provider: &str,
        server_url: &str,
    ) -> Result<reqwest::RequestBuilder> {
        let mut url = if provider == "gitea" && !server_url.is_empty() {
            gitea_api_base(server_url)?
        } else {
            self.api_base.clone()
        };
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("GITHUB_REPOSITORY_INVALID"))?
            .pop_if_empty()
            .extend(segments);
        let auth_value = if provider == "gitea" {
            format!("token {token}")
        } else {
            format!("Bearer {token}")
        };
        let mut authorization =
            HeaderValue::from_str(&auth_value).map_err(|_| anyhow::anyhow!("GITHUB_TOKEN_INVALID"))?;
        authorization.set_sensitive(true);
        let builder = self
            .client
            .request(method, url)
            .header(AUTHORIZATION, authorization);
        if provider == "gitea" {
            Ok(builder.header("Accept", "application/json"))
        } else {
            Ok(builder
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2026-03-10"))
        }
    }

    async fn repository(
        &self,
        owner: &str,
        repo: &str,
        token: &str,
        provider: &str,
        server_url: &str,
    ) -> Result<Repository> {
        self.find_repository(owner, repo, token, provider, server_url)
            .await?
            .context("GITHUB_NOT_FOUND")
    }

    /// Looks up a repository, returning `None` when it does not exist or this token
    /// cannot see it. One that exists must be private and writable.
    async fn find_repository(
        &self,
        owner: &str,
        repo: &str,
        token: &str,
        provider: &str,
        server_url: &str,
    ) -> Result<Option<Repository>> {
        let response = self
            .request_for(Method::GET, owner, repo, &[], token, provider, server_url)?
            .send()
            .await
            .context("GITHUB_NETWORK")?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        check_response(&response)?;
        let repository: Repository = read_json(response).await?;
        if !repository.private {
            bail!("GITHUB_PRIVATE_REQUIRED");
        }
        if repository.archived || repository.disabled {
            bail!("GITHUB_REPOSITORY_READ_ONLY");
        }
        if repository.id == 0 || repository.default_branch.is_empty() {
            bail!("GITHUB_RESPONSE_INVALID");
        }
        Ok(Some(repository))
    }

    async fn check_repository(&self, config: &DeviceConfig) -> Result<()> {
        let repository = self
            .repository(
                &config.owner,
                &config.repo,
                &config.token,
                &config.provider,
                &config.server_url,
            )
            .await?;
        if repository.id != config.repository_id {
            bail!("GITHUB_REPOSITORY_CHANGED");
        }
        if repository.default_branch != config.branch {
            bail!("GITHUB_BRANCH_CHANGED");
        }
        self.check_key_repository_private(config).await?;
        Ok(())
    }

    /// Reads the snapshot at `git_ref`: the branch for the live copy, or a commit SHA for
    /// an earlier version. Both go through the same size, SHA and blob checks.
    async fn remote_file(&self, config: &DeviceConfig, git_ref: &str) -> Result<Option<RemoteFile>> {
        let response = self
            .request_for(
                Method::GET,
                &config.owner,
                &config.repo,
                &["contents", CLOUD_FILE],
                &config.token,
                &config.provider,
                &config.server_url,
            )?
            .query(&[("ref", git_ref)])
            .send()
            .await
            .context("GITHUB_NETWORK")?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        check_response(&response)?;
        let file: ContentFile = read_json(response).await?;
        if file.kind != "file" || !valid_sha(&file.sha) {
            bail!("GITHUB_BACKUP_INVALID");
        }
        if file.size > MAX_CLOUD_BYTES {
            bail!("GITHUB_BACKUP_TOO_LARGE");
        }
        let bytes = if file.encoding == "base64" {
            decode_content(&file.content)?
        } else {
            // Contents API omits inline content above 1 MB. Pin the blob SHA
            // instead of following download_url or reading a moving branch.
            let response = self
                .request_for(
                    Method::GET,
                    &config.owner,
                    &config.repo,
                    &["git", "blobs", &file.sha],
                    &config.token,
                    &config.provider,
                    &config.server_url,
                )?
                .send()
                .await
                .context("GITHUB_NETWORK")?;
            check_response(&response)?;
            let blob: Blob = read_json(response).await?;
            if blob.sha != file.sha || blob.encoding != "base64" || blob.size != file.size {
                bail!("GITHUB_BACKUP_INVALID");
            }
            decode_content(&blob.content)?
        };
        if bytes.len() != file.size || blob_sha(&bytes) != file.sha {
            bail!("GITHUB_BACKUP_INVALID");
        }
        Ok(Some(RemoteFile {
            sha: file.sha,
            bytes,
        }))
    }
}


#[cfg(test)]
mod tests;
