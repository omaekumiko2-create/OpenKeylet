use super::*;

pub struct AppRuntime {
    pub(super) _gui_instance: GuiInstance,
    pub(super) vault: Vault,
    pub(super) executable: String,
    pub(super) browser: BrowserBridge,
    pub(super) clipboard: Arc<ClipboardGuard>,
    pub(super) pending_private_key: Mutex<Option<PathBuf>>,
    pub(super) pending_import: Mutex<Option<PendingImport>>,
    pub(super) pending_backup_source: Mutex<Option<PendingBackupSource>>,
    pub(super) pending_backup_import: Mutex<Option<PendingBackupImport>>,
    pub(super) backup_import_generation: AtomicU64,
    pub(super) backup_prepare_in_flight: Arc<AtomicBool>,
    pub(super) pending_history_restore: Mutex<Option<PendingHistoryRestore>>,
    pub(super) discovered_mvault_paths: Mutex<Vec<PathBuf>>,
    pub(super) import_sources: Mutex<super::cmd_import::ImportSourceRegistry>,
    pub(super) owner_session: Mutex<OwnerSession>,
    pub(super) github_backup: Mutex<GithubBackup>,
    pub(super) updater: Arc<UpdateManager>,
    pub(super) edge_dock: Arc<EdgeDockController>,
    pub(super) tray_menu: Arc<TrayMenuController>,
    pub(super) auto_sync_generation: AtomicU64,
    pub(super) agent_registry: AgentRegistry,
    pub(super) tray_available: AtomicBool,
}

pub(super) struct PendingImport {
    pub(super) id: String,
    pub(super) created: Instant,
    pub(super) encrypted: crate::model::SecretEnvelope,
}

#[derive(Clone)]
pub(super) enum PendingBackupSource {
    Path {
        path: PathBuf,
        kind: crate::migration::VaultPackageKind,
    },
    Bytes {
        bytes: zeroize::Zeroizing<Vec<u8>>,
        kind: crate::migration::VaultPackageKind,
    },
}

pub(super) fn is_mvault_path(path: &Path) -> bool {
    // Extension-only check (zero filesystem I/O) safe for synchronous UI drag-hover events.
    crate::migration::is_vault_package_extension(path)
}

impl AppRuntime {
    pub(super) async fn clear_pending_imports(&self) {
        self.backup_import_generation.fetch_add(1, Ordering::AcqRel);
        *self.pending_import.lock().await = None;
        *self.pending_backup_source.lock().await = None;
        *self.pending_backup_import.lock().await = None;
        *self.pending_history_restore.lock().await = None;
    }
}

pub(super) enum PendingBackupPayloadKind {
    Mvault { version: u8 },
    MigrationEntries,
}

pub(super) struct PendingBackupImport {
    pub(super) id: String,
    pub(super) created: Instant,
    pub(super) payload_kind: PendingBackupPayloadKind,
    pub(super) encrypted: crate::model::SecretEnvelope,
}

/// A decrypted earlier snapshot waiting for the owner to pick items, kept under the
/// device key so plaintext does not sit in memory between preview and restore.
pub(super) struct PendingHistoryRestore {
    pub(super) id: String,
    pub(super) created: Instant,
    pub(super) sha: String,
    pub(super) encrypted: crate::model::SecretEnvelope,
}

#[derive(Default)]
pub(super) struct OwnerSession {
    pub(super) unlocked: bool,
    pub(super) last_activity: Option<Instant>,
    pub(super) failed_attempts: u32,
    pub(super) locked_until: Option<Instant>,
}

impl OwnerSession {
    pub(super) fn is_unlocked_at(&mut self, now: Instant, auto_lock_minutes: u32) -> (bool, u64, bool) {
        if !self.unlocked {
            return (false, 0, false);
        }
        if auto_lock_minutes == 0 {
            return (true, 0, false);
        }
        let timeout = Duration::from_secs(u64::from(auto_lock_minutes) * 60);
        let last = self.last_activity.unwrap_or(now);
        let elapsed = now.saturating_duration_since(last);
        if elapsed >= timeout {
            self.unlocked = false;
            self.last_activity = None;
            return (false, 0, true);
        }
        let remaining = timeout.saturating_sub(elapsed).as_secs().max(1);
        (true, remaining, false)
    }

    pub(super) fn touch(&mut self, now: Instant) {
        if self.unlocked {
            self.last_activity = Some(now);
        }
    }

    pub(super) fn unlock(&mut self, now: Instant) {
        self.unlocked = true;
        self.last_activity = Some(now);
        self.failed_attempts = 0;
        self.locked_until = None;
    }

    pub(super) fn lock(&mut self) {
        self.unlocked = false;
        self.last_activity = None;
    }

    pub(super) fn cooldown_remaining(&self, now: Instant) -> Option<u64> {
        let until = self.locked_until?;
        if until > now {
            Some(until.saturating_duration_since(now).as_secs().max(1))
        } else {
            None
        }
    }

    pub(super) fn record_failed_attempt(&mut self, now: Instant) -> u64 {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        let delay_secs = match self.failed_attempts {
            0..=2 => 0,
            3 => 2,
            4 => 5,
            5..=6 => 15,
            _ => 30,
        };
        if delay_secs > 0 {
            self.locked_until = Some(now + Duration::from_secs(delay_secs));
        }
        delay_secs
    }
}

pub(super) fn scrub_locked_app_state(mut state: AppState) -> AppState {
    state.connections.clear();
    state.activities.clear();
    state
}

pub(super) const WINDOW_LOGICAL_WIDTH: f64 = 460.0;
pub(super) const WINDOW_LOGICAL_HEIGHT: f64 = 690.0;
pub(super) const WINDOW_MIN_LOGICAL_HEIGHT: f64 = 560.0;
pub(super) const WINDOW_MAX_LOGICAL_HEIGHT: f64 = 4000.0;

pub(super) async fn owner_lock_state(runtime: &AppRuntime) -> Result<OwnerLockState, String> {
    let pin_configured = runtime
        .vault
        .owner_pin_configured()
        .map_err(command_error)?;
    let auto_lock_minutes = runtime
        .vault
        .settings()
        .map(|settings| settings.owner_auto_lock_minutes)
        .unwrap_or(0);
    let mut session = runtime.owner_session.lock().await;
    if !pin_configured {
        session.lock();
        return Ok(OwnerLockState {
            pin_configured: false,
            unlocked: true,
            expires_in_seconds: 0,
            mode: "none".to_owned(),
        });
    }
    let (unlocked, expires_in_seconds, expired_now) =
        session.is_unlocked_at(Instant::now(), auto_lock_minutes);
    drop(session);
    if expired_now {
        runtime.clear_pending_imports().await;
    }
    Ok(OwnerLockState {
        pin_configured,
        unlocked,
        expires_in_seconds,
        mode: "pin".to_owned(),
    })
}

pub(super) async fn require_owner_unlocked(runtime: &AppRuntime) -> Result<(), String> {
    let state = owner_lock_state(runtime).await?;
    if state.unlocked {
        runtime.owner_session.lock().await.touch(Instant::now());
        Ok(())
    } else {
        Err("GUI is locked; enter the six-digit PIN".to_owned())
    }
}

pub(super) async fn keep_owner_unlocked(runtime: &AppRuntime) {
    runtime.owner_session.lock().await.unlock(Instant::now());
}

pub(super) fn command_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

pub(super) fn emit_changed(app: &AppHandle) {
    let _ = app.emit("state-changed", ());
    schedule_tray_refresh(app);
}

pub(super) fn emit_update_status(app: &AppHandle, status: &UpdateStatus) {
    let _ = app.emit("update-state-changed", status);
    schedule_tray_refresh(app);
}

pub(super) fn schedule_auto_update_check(app: &AppHandle, delay_ms: u64) {
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        if delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        let runtime = handle.state::<AppRuntime>();
        let settings = runtime.vault.settings().unwrap_or_default();
        if !settings.update_auto_check {
            return;
        }
        let updater = runtime.updater.clone();
        let emit_handle = handle.clone();
        let Ok(outcome) = updater
            .check_for_updates(false, move |status| {
                emit_update_status(&emit_handle, status);
            })
            .await
        else {
            return;
        };
        if outcome.update_available
            && !outcome.is_skipped
            && outcome.status.phase == "available"
            && settings.update_auto_download
            && outcome.status.can_auto_install
        {
            let emit_handle = handle.clone();
            let _ = updater
                .download_and_stage(move |status| {
                    emit_update_status(&emit_handle, status);
                })
                .await;
        }
    });
}

pub(super) fn schedule_auto_sync(app: &AppHandle, delay_ms: u64) {
    let runtime = app.state::<AppRuntime>();
    let generation = runtime.auto_sync_generation.fetch_add(1, Ordering::AcqRel) + 1;
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        {
            let runtime = handle.state::<AppRuntime>();
            let backup = runtime.github_backup.lock().await;
            if let Ok(Some(status)) = backup.mark_pending_sync() {
                let _ = handle.emit("cloud-sync-updated", status);
            }
        }
        if delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
        let runtime = handle.state::<AppRuntime>();
        if runtime.auto_sync_generation.load(Ordering::Acquire) != generation {
            return;
        }
        let backup = runtime.github_backup.lock().await;
        if !backup.is_auto_sync_enabled() {
            return;
        }
        match backup.sync().await {
            Ok(result) => {
                if result.merge.added > 0 || result.merge.updated > 0 || result.merge.deleted > 0 {
                    emit_changed(&handle);
                }
                let _ = handle.emit("cloud-sync-updated", result.status);
            }
            Err(error) => {
                let message = error.to_string();
                if let Ok(Some(status)) = backup.record_sync_error(&message) {
                    let _ = handle.emit("cloud-sync-updated", status);
                }
                let _ = handle.emit("cloud-sync-error", message);
            }
        }
    });
}

