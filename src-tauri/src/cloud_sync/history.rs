//! Version history of the encrypted snapshot. Every push is one commit touching
//! `CLOUD_FILE`, so the commit log of that path is the list of versions, and the
//! file at any of those commits opens with the current key because the key is never
//! rotated. Restoring from a version never rewrites history: it applies the chosen
//! items as fresh edits that the next push records as a new commit.
use super::*;
use reqwest::header::LINK;
use uuid::Uuid;

/// GitHub honours `per_page` (at most 100). Gitea and Forgejo ignore `limit` whenever
/// `path` is given and use their own page size, so paging relies on `page` and on the
/// server's "has more" signal rather than on counting rows.
const HISTORY_PER_PAGE: u32 = 30;
const MAX_HISTORY_PAGE: u32 = 1000;
const MAX_HISTORY_ROWS: usize = 500;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotVersion {
    pub sha: String,
    /// RFC 3339, or empty when the host reported no usable date.
    pub committed_at: String,
    /// The newest commit touching the snapshot, i.e. what the branch holds now.
    pub is_head: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionList {
    pub versions: Vec<SnapshotVersion>,
    pub page: u32,
    pub has_more: bool,
}

/// A version whose snapshot cannot be opened is a property of that row, not a failed
/// request: the list stays usable and the row says why it cannot be restored.
pub enum VersionPreview {
    Ready {
        plain: Zeroizing<Vec<u8>>,
        preview: backup::HistoryPreview,
    },
    Unreadable {
        reason: String,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionRestoreResult {
    pub summary: backup::HistoryRestoreSummary,
    /// What the sync run before the restore did, e.g. `pushed` when unsynced local
    /// edits were committed first.
    pub pre_sync: String,
    pub status: BackupStatus,
}

#[derive(Deserialize)]
struct CommitPerson {
    #[serde(default)]
    date: String,
}

#[derive(Deserialize)]
struct CommitDetail {
    committer: Option<CommitPerson>,
    author: Option<CommitPerson>,
}

// Author names, e-mails and messages are deliberately not read: the UI needs none of
// them and the message is a constant.
#[derive(Deserialize)]
struct CommitEntry {
    sha: String,
    commit: Option<CommitDetail>,
    #[serde(default)]
    created: String,
}

impl CommitEntry {
    fn date(&self) -> String {
        let detail = self.commit.as_ref();
        [
            detail.and_then(|c| c.committer.as_ref()).map(|p| p.date.as_str()),
            detail.and_then(|c| c.author.as_ref()).map(|p| p.date.as_str()),
            Some(self.created.as_str()),
        ]
        .into_iter()
        .flatten()
        .find_map(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|date| date.with_timezone(&Utc).to_rfc3339())
        .unwrap_or_default()
    }
}

fn link_has_next(value: &str) -> bool {
    value
        .split(',')
        .any(|part| part.split(';').skip(1).any(|param| param.trim() == "rel=\"next\""))
}

pub(super) fn short_sha(sha: &str) -> &str {
    &sha[..sha.len().min(7)]
}

impl GithubBackup {
    /// One page of the commits that touched the snapshot on the connected branch,
    /// newest first. `page` starts at 1.
    pub async fn list_versions(&self, page: u32) -> Result<VersionList> {
        if page == 0 || page > MAX_HISTORY_PAGE {
            bail!("GITHUB_HISTORY_INVALID");
        }
        let config = self.connected()?;
        self.check_repository(&config).await?;
        let page_text = page.to_string();
        let per_page = HISTORY_PER_PAGE.to_string();
        let mut query = vec![
            ("path", CLOUD_FILE),
            ("sha", config.branch.as_str()),
            ("page", page_text.as_str()),
        ];
        if config.is_gitea() {
            // Skip the per-commit diff stats and signature checks Gitea computes by default.
            query.extend([("stat", "false"), ("verification", "false"), ("files", "false")]);
        } else {
            query.push(("per_page", per_page.as_str()));
        }
        let response = self
            .request_for(
                Method::GET,
                &config.owner,
                &config.repo,
                &["commits"],
                &config.token,
                &config.provider,
                &config.server_url,
            )?
            .query(&query)
            .send()
            .await
            .context("GITHUB_NETWORK")?;
        // GitHub answers 409 for a repository without any commit; there is no history.
        if response.status() == StatusCode::CONFLICT {
            return Ok(VersionList {
                versions: Vec::new(),
                page,
                has_more: false,
            });
        }
        let has_more = response
            .headers()
            .get("x-hasmore")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
            || response
                .headers()
                .get_all(LINK)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .any(link_has_next);
        check_response(&response)?;
        let entries: Vec<CommitEntry> = read_json(response).await?;
        if entries.len() > MAX_HISTORY_ROWS {
            bail!("GITHUB_RESPONSE_INVALID");
        }
        let mut versions: Vec<SnapshotVersion> = Vec::with_capacity(entries.len());
        for entry in entries {
            // The SHA is later sent back as a `ref`; anything but a full object id is refused.
            if !valid_sha(&entry.sha) {
                bail!("GITHUB_RESPONSE_INVALID");
            }
            let sha = entry.sha.to_ascii_lowercase();
            if versions.iter().any(|version| version.sha == sha) {
                continue;
            }
            versions.push(SnapshotVersion {
                committed_at: entry.date(),
                is_head: page == 1 && versions.is_empty(),
                sha,
            });
        }
        Ok(VersionList {
            has_more: has_more && !versions.is_empty(),
            versions,
            page,
        })
    }

    /// Fetches the snapshot as it was at commit `sha` and decrypts it with the key in use.
    pub async fn fetch_version(&self, sha: &str) -> Result<VersionPreview> {
        let sha = sha.trim().to_ascii_lowercase();
        if !valid_sha(&sha) {
            bail!("GITHUB_HISTORY_INVALID");
        }
        let config = self.connected()?;
        self.check_repository(&config).await?;
        let unreadable = |reason: &str| -> Result<VersionPreview> {
            Ok(VersionPreview::Unreadable { reason: reason.to_owned() })
        };
        // A commit that removed the file, or a SHA the host does not know, has no snapshot.
        let remote = match self.remote_file(&config, &sha).await {
            Ok(Some(remote)) => remote,
            Ok(None) => return unreadable("GITHUB_BACKUP_MISSING"),
            Err(error) => return content_error(error),
        };
        let plain = match decrypt_snapshot(&remote.bytes, &config.recovery_key) {
            Ok(plain) => plain,
            Err(error) => return content_error(error),
        };
        if backup::inspect_cloud_snapshot(&plain).is_err() {
            return unreadable("GITHUB_BACKUP_INVALID");
        }
        let preview = backup::history_preview(&self.vault, &plain).context("GITHUB_LOCAL_VAULT")?;
        Ok(VersionPreview::Ready { plain, preview })
    }

    /// Restores the items `ids` from a version fetched with `fetch_version`.
    ///
    /// A normal sync runs first, so the state before the restore is itself a commit and
    /// restoring that commit undoes this one. It also merges every remote edit and
    /// tombstone, so the restored items are stamped past everything known about them.
    /// If that sync fails nothing is restored.
    pub async fn restore_version(
        &self,
        sha: &str,
        plain: &[u8],
        ids: &[Uuid],
    ) -> Result<VersionRestoreResult> {
        if !valid_sha(sha) {
            bail!("GITHUB_HISTORY_INVALID");
        }
        if ids.is_empty() {
            bail!("GITHUB_HISTORY_EMPTY");
        }
        let synced = self.sync().await?;
        let summary = backup::restore_history_selection(&self.vault, plain, ids, short_sha(sha))
            .context("GITHUB_RESTORE_FAILED")?;
        Ok(VersionRestoreResult {
            summary,
            pre_sync: synced.action,
            status: self.status()?,
        })
    }
}

/// Errors that describe the stored snapshot rather than the request.
fn content_error(error: anyhow::Error) -> Result<VersionPreview> {
    let code = error.to_string();
    match code.as_str() {
        "GITHUB_KEY_MISMATCH" | "GITHUB_BACKUP_INVALID" | "GITHUB_BACKUP_TOO_LARGE" => {
            Ok(VersionPreview::Unreadable { reason: code })
        }
        _ => Err(error),
    }
}
