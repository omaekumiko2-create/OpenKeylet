//! Device-local activity log, kept out of vault.json so that logging an agent
//! action never rewrites the encrypted secrets file or takes the vault lock.
//!
//! `activity.jsonl` holds one JSON `Activity` per line, oldest first, guarded by
//! `activity.lock` (shared for reads, exclusive for writes). When both locks are
//! needed the order is always `vault.lock`, then `activity.lock`.

use super::*;
use std::{
    collections::HashSet,
    io::{Read, Seek, SeekFrom},
};

const ACTIVITY_LOG_FILE: &str = "activity.jsonl";
const ACTIVITY_LOCK_FILE: &str = "activity.lock";
/// Lines tolerated past `MAX_ACTIVITIES` before an append compacts the log, so
/// the full rewrite happens once per this many appends rather than on each.
pub(super) const ACTIVITY_COMPACT_SLACK: usize = 500;

impl Vault {
    pub fn activities(&self) -> Result<Vec<Activity>> {
        let entries = self.with_activity_lock(false, || self.read_activity_log_unlocked())?;
        Ok(entries.into_iter().rev().take(MAX_ACTIVITIES).collect())
    }

    pub fn add_activity(&self, activity: NewActivity) -> Result<()> {
        self.with_activity_lock(true, || {
            // Timestamped under the lock so line order matches time order
            // across processes.
            self.append_activity_unlocked(&Activity {
                id: Uuid::new_v4(),
                time: Utc::now().to_rfc3339(),
                status: if activity.status == "error" {
                    "error"
                } else {
                    "success"
                }
                .to_owned(),
                source: clean_text(&activity.source, 40),
                connection_name: clean_text(&activity.connection_name, 80),
                action: clean_text(&activity.action, 160),
                duration_ms: activity.duration_ms,
                error: clean_text(&activity.error, 240),
            })
        })
    }

    pub fn delete_activity(&self, id: Uuid) -> Result<bool> {
        Ok(self.delete_activities(&[id])? > 0)
    }

    pub fn delete_activities(&self, ids: &[Uuid]) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let targets: HashSet<Uuid> = ids.iter().copied().collect();
        self.with_activity_lock(true, || {
            let mut entries = self.read_activity_log_unlocked()?;
            // Delete from the visible window only, as when the capped log lived
            // in vault.json; uncompacted older lines are dropped by the rewrite.
            keep_newest(&mut entries);
            let before = entries.len();
            entries.retain(|entry| !targets.contains(&entry.id));
            let removed = before - entries.len();
            if removed > 0 {
                self.write_activity_log_unlocked(&entries)?;
            }
            Ok(removed)
        })
    }

    pub fn clear_activities(&self) -> Result<()> {
        self.with_activity_lock(true, || self.write_activity_log_unlocked(&[]))
    }

    /// Moves activities that older builds kept inside vault.json into the
    /// device-local log. The log is written before vault.json is cleared, and
    /// entries are de-duplicated by id, so an interrupted run is safely retried.
    pub(super) fn migrate_legacy_activities(&self) -> Result<()> {
        if self.read_document()?.activities.is_empty() {
            return Ok(());
        }
        self.with_exclusive_lock(|_| {
            let legacy = self.read_document_unlocked()?.activities;
            if legacy.is_empty() {
                return Ok(());
            }
            self.with_activity_lock(true, || {
                let mut entries = self.read_activity_log_unlocked()?;
                let known: HashSet<Uuid> = entries.iter().map(|entry| entry.id).collect();
                // vault.json kept the newest entry first; the log is oldest first.
                entries.extend(
                    legacy
                        .into_iter()
                        .rev()
                        .filter(|entry| !known.contains(&entry.id)),
                );
                entries.sort_by_cached_key(|entry| {
                    chrono::DateTime::parse_from_rfc3339(&entry.time).ok()
                });
                keep_newest(&mut entries);
                self.write_activity_log_unlocked(&entries)
            })?;
            // Clear only the `activities` key and keep every other field and
            // the on-disk version as they are, so opening an older-version vault
            // still does not upgrade it.
            let bytes = fs::read(&self.inner.vault_path).context("Could not read vault")?;
            let mut document: serde_json::Value =
                serde_json::from_slice(&bytes).context("Invalid vault file format")?;
            if let Some(activities) = document.get_mut("activities") {
                *activities = serde_json::Value::Array(Vec::new());
            }
            let bytes =
                serde_json::to_vec_pretty(&document).context("Could not serialize vault")?;
            let mut file = AtomicWriteFile::open(&self.inner.vault_path)
                .context("Could not create temporary vault file")?;
            file.write_all(&bytes).context("Could not write vault")?;
            file.commit().context("Could not commit vault file")?;
            Ok(())
        })
    }

    fn append_activity_unlocked(&self, entry: &Activity) -> Result<()> {
        let mut options = OpenOptions::new();
        options.create(true).read(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(self.activity_log_path())
            .context("Could not open activity log")?;
        let len = file
            .metadata()
            .context("Could not read activity log")?
            .len();
        let mut line = Vec::new();
        if len > 0 {
            // A crash mid-append can leave a torn last line without its newline;
            // start a fresh line so this entry is not glued onto the fragment.
            let mut last = [0_u8; 1];
            file.seek(SeekFrom::End(-1))
                .context("Could not read activity log")?;
            file.read_exact(&mut last)
                .context("Could not read activity log")?;
            if last[0] != b'\n' {
                line.push(b'\n');
            }
        }
        line.extend_from_slice(&serde_json::to_vec(entry).context("Could not serialize activity")?);
        line.push(b'\n');
        file.write_all(&line)
            .context("Could not write activity log")?;
        file.flush().context("Could not write activity log")?;
        drop(file);
        // The entry is recorded; keeping the log bounded is best effort and a
        // failed compaction is retried by the next append.
        let _ = self.compact_activity_log_if_needed(len, &line);
        Ok(())
    }

    fn compact_activity_log_if_needed(&self, len_before: u64, appended: &[u8]) -> Result<()> {
        let cached = self
            .inner
            .activity_log_cache
            .lock()
            .ok()
            .and_then(|cache| *cache);
        self.set_activity_log_cache(None);
        let lines = match cached {
            Some((cached_len, cached_lines)) if cached_len == len_before => {
                cached_lines + count_lines(appended)
            }
            // Another handle or process changed the log since this one last saw it.
            _ => count_lines(&self.read_activity_log_bytes()?),
        };
        if lines > MAX_ACTIVITIES + ACTIVITY_COMPACT_SLACK {
            let mut entries = self.read_activity_log_unlocked()?;
            keep_newest(&mut entries);
            return self.write_activity_log_unlocked(&entries);
        }
        self.set_activity_log_cache(Some((len_before + appended.len() as u64, lines)));
        Ok(())
    }

    /// Entries oldest first. Torn or malformed lines are skipped and dropped by
    /// the next rewrite; a missing log is empty.
    fn read_activity_log_unlocked(&self) -> Result<Vec<Activity>> {
        Ok(self
            .read_activity_log_bytes()?
            .split(|byte| *byte == b'\n')
            .filter_map(|line| serde_json::from_slice::<Activity>(line).ok())
            .collect())
    }

    fn read_activity_log_bytes(&self) -> Result<Vec<u8>> {
        match fs::read(self.activity_log_path()) {
            Ok(bytes) => Ok(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error).context("Could not read activity log"),
        }
    }

    fn write_activity_log_unlocked(&self, entries: &[Activity]) -> Result<()> {
        let mut bytes = Vec::new();
        for entry in entries {
            bytes.extend_from_slice(
                &serde_json::to_vec(entry).context("Could not serialize activity")?,
            );
            bytes.push(b'\n');
        }
        let path = self.activity_log_path();
        self.set_activity_log_cache(None);
        let mut file =
            AtomicWriteFile::open(&path).context("Could not create temporary activity log")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o600));
        }
        file.write_all(&bytes)
            .context("Could not write activity log")?;
        file.commit().context("Could not commit activity log")?;
        self.set_activity_log_cache(Some((bytes.len() as u64, entries.len())));
        Ok(())
    }

    fn set_activity_log_cache(&self, value: Option<(u64, usize)>) {
        if let Ok(mut cache) = self.inner.activity_log_cache.lock() {
            *cache = value;
        }
    }

    fn activity_log_path(&self) -> PathBuf {
        self.inner.data_dir.join(ACTIVITY_LOG_FILE)
    }

    fn with_activity_lock<T>(
        &self,
        exclusive: bool,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.inner.data_dir.join(ACTIVITY_LOCK_FILE))
            .context("Could not open activity log lock file")?;
        if exclusive {
            FileExt::lock_exclusive(&lock).context("Could not lock activity log")?;
        } else {
            FileExt::lock_shared(&lock).context("Could not lock activity log")?;
        }
        let result = action();
        let _ = FileExt::unlock(&lock);
        result
    }
}

fn keep_newest(entries: &mut Vec<Activity>) {
    if entries.len() > MAX_ACTIVITIES {
        let excess = entries.len() - MAX_ACTIVITIES;
        entries.drain(..excess);
    }
}

fn count_lines(bytes: &[u8]) -> usize {
    bytes.iter().filter(|byte| **byte == b'\n').count()
}
