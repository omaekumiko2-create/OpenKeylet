use crate::{
    agent_registry::{AgentActionResult, AgentClientStatus, AgentRegistry},
    backup,
    browser::BrowserBridge,
    clipboard::{self, ClipboardGuard, SENSITIVE_CLIPBOARD_TTL_SECS},
    edge_dock::EdgeDockController,
    executor,
    github_backup::{self, BackupStatus, ConnectInput, GithubBackup, RestoreResult, SyncResult},
    gui_instance::GuiInstance,
    mcp,
    model::{
        AppState, ConnectionInput, ImportSummary, NewActivity, OwnerEditorDraft, OwnerLockState,
        OwnerSecretView, PublicConnection, SettingsPatch,
    },
    session_broker::SessionBroker,
    storage::app_data_dir,
    updater::{self, UpdateManager, UpdateStatus},
    vault::Vault,
};
use anyhow::{Context, Result};
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tauri::{
    AppHandle, Emitter, LogicalSize, Manager, State, WebviewWindow,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct AppRuntime {
    _gui_instance: GuiInstance,
    vault: Vault,
    executable: String,
    browser: BrowserBridge,
    clipboard: Arc<ClipboardGuard>,
    pending_private_key: Mutex<Option<PathBuf>>,
    pending_import: Mutex<Option<PendingImport>>,
    pending_backup_source: Mutex<Option<PendingBackupSource>>,
    pending_backup_import: Mutex<Option<PendingBackupImport>>,
    owner_session: Mutex<OwnerSession>,
    github_backup: Mutex<GithubBackup>,
    session_broker: SessionBroker,
    updater: Arc<UpdateManager>,
    edge_dock: Arc<EdgeDockController>,
    auto_sync_generation: AtomicU64,
    agent_registry: AgentRegistry,
    tray_available: AtomicBool,
}

struct PendingImport {
    id: String,
    created: Instant,
    encrypted: crate::model::SecretEnvelope,
}

#[derive(Clone)]
enum PendingBackupSource {
    Path(PathBuf),
    Bytes(Vec<u8>),
}

fn is_mvault_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("mvault"))
}

struct PendingBackupImport {
    id: String,
    created: Instant,
    version: u8,
    encrypted: crate::model::SecretEnvelope,
}

#[derive(Default)]
struct OwnerSession {
    unlocked: bool,
    last_activity: Option<Instant>,
    failed_attempts: u32,
    locked_until: Option<Instant>,
}

impl OwnerSession {
    fn is_unlocked_at(&mut self, now: Instant, auto_lock_minutes: u32) -> (bool, u64, bool) {
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

    fn touch(&mut self, now: Instant) {
        if self.unlocked {
            self.last_activity = Some(now);
        }
    }

    fn unlock(&mut self, now: Instant) {
        self.unlocked = true;
        self.last_activity = Some(now);
        self.failed_attempts = 0;
        self.locked_until = None;
    }

    fn lock(&mut self) {
        self.unlocked = false;
        self.last_activity = None;
    }

    fn cooldown_remaining(&self, now: Instant) -> Option<u64> {
        let until = self.locked_until?;
        if until > now {
            Some(until.saturating_duration_since(now).as_secs().max(1))
        } else {
            None
        }
    }

    fn record_failed_attempt(&mut self, now: Instant) -> u64 {
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

fn scrub_locked_app_state(mut state: AppState) -> AppState {
    state.connections.clear();
    state.activities.clear();
    state
}

const WINDOW_LOGICAL_WIDTH: f64 = 460.0;
const WINDOW_LOGICAL_HEIGHT: f64 = 690.0;
const WINDOW_MIN_LOGICAL_HEIGHT: f64 = 560.0;
const WINDOW_MAX_LOGICAL_HEIGHT: f64 = 4000.0;

async fn owner_lock_state(runtime: &AppRuntime) -> Result<OwnerLockState, String> {
    let strong_mode = runtime.vault.is_strong_mode();
    let pin_configured = if strong_mode {
        true
    } else {
        runtime
            .vault
            .owner_pin_configured()
            .map_err(command_error)?
    };
    let auto_lock_minutes = runtime
        .vault
        .settings()
        .map(|settings| settings.owner_auto_lock_minutes)
        .unwrap_or(0);
    let mut session = runtime.owner_session.lock().await;
    if strong_mode {
        if !runtime.vault.is_strong_unlocked() {
            session.lock();
            drop(session);
            runtime.session_broker.stop();
            return Ok(OwnerLockState {
                pin_configured: true,
                unlocked: false,
                expires_in_seconds: 0,
                strong_mode: true,
                mode: "strong".to_owned(),
            });
        }
        let (unlocked, expires_in_seconds, expired_now) =
            session.is_unlocked_at(Instant::now(), auto_lock_minutes);
        drop(session);
        if expired_now || !unlocked {
            runtime.vault.lock_strong();
            runtime.session_broker.stop();
            *runtime.pending_import.lock().await = None;
            *runtime.pending_backup_source.lock().await = None;
            *runtime.pending_backup_import.lock().await = None;
            return Ok(OwnerLockState {
                pin_configured: true,
                unlocked: false,
                expires_in_seconds: 0,
                strong_mode: true,
                mode: "strong".to_owned(),
            });
        }
        return Ok(OwnerLockState {
            pin_configured: true,
            unlocked: true,
            expires_in_seconds,
            strong_mode: true,
            mode: "strong".to_owned(),
        });
    }
    if !pin_configured {
        session.lock();
        return Ok(OwnerLockState {
            pin_configured: false,
            unlocked: true,
            expires_in_seconds: 0,
            strong_mode: false,
            mode: "none".to_owned(),
        });
    }
    let (unlocked, expires_in_seconds, expired_now) =
        session.is_unlocked_at(Instant::now(), auto_lock_minutes);
    drop(session);
    if expired_now {
        *runtime.pending_import.lock().await = None;
        *runtime.pending_backup_source.lock().await = None;
        *runtime.pending_backup_import.lock().await = None;
    }
    Ok(OwnerLockState {
        pin_configured,
        unlocked,
        expires_in_seconds,
        strong_mode: false,
        mode: "pin".to_owned(),
    })
}

async fn require_owner_unlocked(runtime: &AppRuntime) -> Result<(), String> {
    let state = owner_lock_state(runtime).await?;
    if state.unlocked {
        runtime.owner_session.lock().await.touch(Instant::now());
        Ok(())
    } else if state.strong_mode {
        Err("Strong Cloud Vault is locked; enter your master passphrase or recovery key".to_owned())
    } else {
        Err("GUI is locked; enter the six-digit PIN".to_owned())
    }
}

async fn keep_owner_unlocked(runtime: &AppRuntime) {
    runtime.owner_session.lock().await.unlock(Instant::now());
}

fn command_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn emit_changed(app: &AppHandle) {
    let _ = app.emit("state-changed", ());
}

fn emit_update_status(app: &AppHandle, status: &UpdateStatus) {
    let _ = app.emit("update-state-changed", status);
}

fn schedule_auto_update_check(app: &AppHandle, delay_ms: u64) {
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

fn schedule_auto_sync(app: &AppHandle, delay_ms: u64) {
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

#[tauri::command]
async fn get_state(runtime: State<'_, AppRuntime>) -> Result<AppState, String> {
    let lock = owner_lock_state(&runtime).await?;
    runtime.browser.sync().await;
    let browser = runtime.browser.status().await;
    let state = runtime
        .vault
        .app_state(&runtime.executable, browser)
        .map_err(command_error)?;
    if lock.pin_configured && !lock.unlocked {
        Ok(scrub_locked_app_state(state))
    } else {
        Ok(state)
    }
}

#[tauri::command]
async fn owner_status(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<OwnerLockState, String> {
    let state = owner_lock_state(&runtime).await?;
    if state.pin_configured && !state.unlocked {
        clipboard::clear_if_unchanged(&app, &runtime.clipboard, None);
    }
    Ok(state)
}

#[tauri::command]
async fn owner_touch(runtime: State<'_, AppRuntime>) -> Result<OwnerLockState, String> {
    let state = owner_lock_state(&runtime).await?;
    if state.pin_configured && state.unlocked {
        runtime.owner_session.lock().await.touch(Instant::now());
        return owner_lock_state(&runtime).await;
    }
    Ok(state)
}

#[tauri::command]
async fn owner_set_pin(
    runtime: State<'_, AppRuntime>,
    pin: String,
) -> Result<OwnerLockState, String> {
    if runtime.vault.is_strong_mode() {
        return Err("Strong Cloud Vault mode is active; lock and unlock use your master passphrase".to_owned());
    }
    runtime.vault.set_owner_pin(&pin).map_err(command_error)?;
    keep_owner_unlocked(&runtime).await;
    owner_lock_state(&runtime).await
}

#[tauri::command]
async fn owner_disable_pin(runtime: State<'_, AppRuntime>) -> Result<OwnerLockState, String> {
    require_owner_unlocked(&runtime).await?;
    if runtime.vault.is_strong_mode() {
        return Err("Disconnect your GitHub Strong Cloud Vault to revert to local-only mode".to_owned());
    }
    runtime.vault.disable_owner_pin().map_err(command_error)?;
    runtime.owner_session.lock().await.lock();
    owner_lock_state(&runtime).await
}

#[tauri::command]
async fn owner_unlock(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    pin: String,
) -> Result<OwnerLockState, String> {
    let now = Instant::now();
    if let Some(wait_secs) = runtime.owner_session.lock().await.cooldown_remaining(now) {
        return Err(format!(
            "Too many incorrect attempts; wait {wait_secs}s"
        ));
    }
    if runtime.vault.is_strong_mode() {
        if let Err(error) = runtime.vault.unlock_strong(&pin) {
            let delay = runtime
                .owner_session
                .lock()
                .await
                .record_failed_attempt(Instant::now());
            let base = if pin.trim().starts_with("okv1_") {
                "Incorrect recovery key"
            } else {
                "Incorrect master passphrase"
            };
            if delay > 0 {
                return Err(format!("{base}; wait {delay}s before trying again"));
            }
            let _ = error;
            return Err(base.to_owned());
        }
        keep_owner_unlocked(&runtime).await;
        if let Err(error) = runtime.session_broker.start(runtime.vault.clone()) {
            eprintln!("OpenKeylet: failed to start Strong Vault MCP session broker: {error:#}");
        }
        runtime.browser.sync().await;
        schedule_auto_sync(&app, 400);
        emit_changed(&app);
        return owner_lock_state(&runtime).await;
    }
    if !runtime
        .vault
        .verify_owner_pin(&pin)
        .map_err(command_error)?
    {
        let delay = runtime
            .owner_session
            .lock()
            .await
            .record_failed_attempt(Instant::now());
        if delay > 0 {
            return Err(format!("Incorrect PIN; wait {delay}s before trying again"));
        }
        return Err("Incorrect PIN".to_owned());
    }
    keep_owner_unlocked(&runtime).await;
    owner_lock_state(&runtime).await
}

#[tauri::command]
async fn owner_change_master_passphrase(
    runtime: State<'_, AppRuntime>,
    new_passphrase: String,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .vault
        .change_strong_passphrase(&new_passphrase)
        .map_err(command_error)
}

#[tauri::command]
async fn owner_lock(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<OwnerLockState, String> {
    runtime.owner_session.lock().await.lock();
    if runtime.vault.is_strong_mode() {
        runtime.vault.lock_strong();
        runtime.session_broker.stop();
    }
    *runtime.pending_import.lock().await = None;
    *runtime.pending_backup_source.lock().await = None;
    *runtime.pending_backup_import.lock().await = None;
    clipboard::clear_if_unchanged(&app, &runtime.clipboard, None);
    owner_lock_state(&runtime).await
}

#[tauri::command]
async fn owner_secret_view(
    runtime: State<'_, AppRuntime>,
    id: Uuid,
) -> Result<OwnerSecretView, String> {
    require_owner_unlocked(&runtime).await?;
    keep_owner_unlocked(&runtime).await;
    runtime.vault.owner_secret_view(id).map_err(command_error)
}

#[tauri::command]
async fn owner_editor_drafts(
    runtime: State<'_, AppRuntime>,
) -> Result<Vec<OwnerEditorDraft>, String> {
    require_owner_unlocked(&runtime).await?;
    keep_owner_unlocked(&runtime).await;
    runtime.vault.list_editor_drafts().map_err(command_error)
}

#[tauri::command]
async fn save_editor_draft(
    runtime: State<'_, AppRuntime>,
    draft_id: Option<Uuid>,
    mut input: ConnectionInput,
) -> Result<OwnerEditorDraft, String> {
    require_owner_unlocked(&runtime).await?;
    keep_owner_unlocked(&runtime).await;
    if input.private_key_import_path == "pending" {
        let path = runtime
            .pending_private_key
            .lock()
            .await
            .take()
            .ok_or_else(|| "Please select the SSH private key again".to_owned())?;
        input.secrets.private_key = Some(std::fs::read_to_string(&path).map_err(command_error)?);
        input.secrets.private_key_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned);
    }
    input.private_key_import_path.clear();
    runtime
        .vault
        .save_editor_draft(draft_id, input)
        .map_err(command_error)
}

#[tauri::command]
async fn delete_editor_draft(runtime: State<'_, AppRuntime>, id: Uuid) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime.vault.delete_editor_draft(id).map_err(command_error)
}

#[tauri::command]
async fn copy_owner_value(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    value: String,
    sensitive: Option<bool>,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    let sensitive = sensitive.unwrap_or(true);
    clipboard::write_text(
        &app,
        &runtime.clipboard,
        &value,
        sensitive,
        SENSITIVE_CLIPBOARD_TTL_SECS,
    )
    .map_err(command_error)
}

#[tauri::command]
async fn copy_totp_code(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    secret: String,
) -> Result<serde_json::Value, String> {
    require_owner_unlocked(&runtime).await?;
    let (code, remaining_seconds, period) =
        crate::browser::current_totp_details(&secret).map_err(command_error)?;
    clipboard::write_text(
        &app,
        &runtime.clipboard,
        &code,
        true,
        SENSITIVE_CLIPBOARD_TTL_SECS,
    )
    .map_err(command_error)?;
    Ok(serde_json::json!({
        "remainingSeconds": remaining_seconds,
        "period": period,
        "clearAfterSeconds": SENSITIVE_CLIPBOARD_TTL_SECS,
    }))
}

#[tauri::command]
async fn save_connection(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    mut input: ConnectionInput,
    expected_updated_at: Option<String>,
) -> Result<PublicConnection, String> {
    require_owner_unlocked(&runtime).await?;
    if input.private_key_import_path == "pending" {
        let selected = runtime
            .pending_private_key
            .lock()
            .await
            .take()
            .ok_or_else(|| "Please select the SSH private key again".to_owned())?;
        input.private_key_import_path = selected.to_string_lossy().into_owned();
    } else {
        input.private_key_import_path.clear();
    }
    let connection = runtime
        .vault
        .save_connection_checked(input, expected_updated_at.as_deref())
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(connection)
}

#[tauri::command]
async fn reorder_connections(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    ids: Vec<Uuid>,
    expected_order: Vec<Uuid>,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .vault
        .reorder_connections(&ids, &expected_order)
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(())
}

#[tauri::command]
async fn set_connection_enabled(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
    enabled: bool,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .vault
        .set_connection_enabled(id, enabled)
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(())
}

#[tauri::command]
async fn delete_connection(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
    expected_updated_at: String,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .vault
        .trash_connection(id, Some(&expected_updated_at))
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(())
}

#[tauri::command]
async fn owner_trash(
    runtime: State<'_, AppRuntime>,
) -> Result<Vec<crate::model::PublicTrashItem>, String> {
    require_owner_unlocked(&runtime).await?;
    runtime.vault.trash_items().map_err(command_error)
}

#[tauri::command]
async fn owner_restore_item(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
    deleted_at: String,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .vault
        .restore_connection(id, &deleted_at)
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(())
}

#[tauri::command]
async fn owner_purge_item(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
    deleted_at: String,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .vault
        .purge_connection(id, &deleted_at)
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(())
}

#[tauri::command]
async fn owner_password_history(
    runtime: State<'_, AppRuntime>,
    id: Uuid,
) -> Result<serde_json::Value, String> {
    require_owner_unlocked(&runtime).await?;
    let item = runtime.vault.get_connection(id).map_err(command_error)?;
    Ok(
        serde_json::json!({"updatedAt":item.stored.updated_at,"entries":item.secrets.password_history}),
    )
}

#[tauri::command]
async fn owner_clear_password_history(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
    expected_updated_at: String,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .vault
        .clear_password_history(id, &expected_updated_at)
        .map_err(command_error)?;
    emit_changed(&app);
    Ok(())
}

#[tauri::command]
async fn test_connection(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
) -> Result<String, String> {
    require_owner_unlocked(&runtime).await?;
    let started = Instant::now();
    let connection = runtime.vault.get_connection(id).map_err(command_error)?;
    let connection_name = connection.stored.name.clone();
    let result: anyhow::Result<String> =
        if connection.stored.test_target(&connection.secrets).is_some() {
            executor::test_connection(&runtime.vault, &connection).await
        } else {
            Ok(format!(
                "Secure entry ready · {} fields",
                connection
                    .secrets
                    .available_fields(connection.stored.secret.as_ref())
                    .len()
            ))
        }
        .map_err(|error| {
            anyhow::anyhow!(crate::policy::redact(
                error.to_string(),
                &connection.stored,
                &connection.secrets,
            ))
        });
    let (status, error) = match &result {
        Ok(_) => ("success", String::new()),
        Err(error) => ("error", error.to_string()),
    };
    let _ = runtime.vault.add_activity(NewActivity {
        status: status.to_owned(),
        source: "Apply".to_owned(),
        connection_name,
        action: "Test connection".to_owned(),
        duration_ms: started.elapsed().as_millis() as u64,
        error,
    });
    emit_changed(&app);
    result.map_err(command_error)
}

#[tauri::command]
async fn update_settings(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    patch: SettingsPatch,
) -> Result<crate::model::Settings, String> {
    require_owner_unlocked(&runtime).await?;
    let enabling_browser = patch.browser_enabled == Some(true);
    let enabling_auto_download = patch.update_auto_download == Some(true);
    let settings = runtime
        .vault
        .update_settings_patch(patch)
        .map_err(command_error)?;
    runtime.browser.sync().await;
    if enabling_browser && settings.browser_enabled {
        let _ = runtime.browser.start_quick_pairing().await;
    }
    let update_status = runtime.updater.refresh_settings().await;
    emit_update_status(&app, &update_status);
    if enabling_auto_download
        && update_status.phase == "available"
        && update_status.can_auto_install
    {
        let updater = runtime.updater.clone();
        let handle = app.clone();
        tauri::async_runtime::spawn(async move {
            let emit_handle = handle.clone();
            let _ = updater
                .download_and_stage(move |status| {
                    emit_update_status(&emit_handle, status);
                })
                .await;
        });
    }
    emit_changed(&app);
    Ok(settings)
}

#[tauri::command]
fn system_integration_status(
    runtime: State<'_, AppRuntime>,
) -> Result<crate::system_integration::SystemIntegrationState, String> {
    crate::system_integration::status(PathBuf::from(&runtime.executable).as_path())
        .map_err(command_error)
}

#[tauri::command]
async fn set_desktop_shortcut(
    runtime: State<'_, AppRuntime>,
    enabled: bool,
) -> Result<crate::system_integration::SystemIntegrationState, String> {
    require_owner_unlocked(&runtime).await?;
    crate::system_integration::set_desktop_shortcut(
        PathBuf::from(&runtime.executable).as_path(),
        enabled,
    )
    .map_err(command_error)
}

#[tauri::command]
async fn set_launch_at_login(
    runtime: State<'_, AppRuntime>,
    enabled: bool,
) -> Result<crate::system_integration::SystemIntegrationState, String> {
    require_owner_unlocked(&runtime).await?;
    crate::system_integration::set_launch_at_login(
        PathBuf::from(&runtime.executable).as_path(),
        enabled,
    )
    .map_err(command_error)
}

#[tauri::command]
async fn clear_activities(app: AppHandle, runtime: State<'_, AppRuntime>) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime.vault.clear_activities().map_err(command_error)?;
    emit_changed(&app);
    Ok(())
}

#[tauri::command]
async fn copy_mcp_config(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    format: String,
) -> Result<String, String> {
    require_owner_unlocked(&runtime).await?;
    let config = mcp::render_config(&format).map_err(command_error)?;
    clipboard::write_text(&app, &runtime.clipboard, &config, false, 0).map_err(command_error)?;
    Ok(config)
}

#[tauri::command]
async fn agent_mcp_status(
    runtime: State<'_, AppRuntime>,
) -> Result<Vec<AgentClientStatus>, String> {
    Ok(runtime.agent_registry.list().await)
}

#[tauri::command]
async fn agent_mcp_register(
    runtime: State<'_, AppRuntime>,
    client_ids: Vec<String>,
) -> Result<Vec<AgentActionResult>, String> {
    require_owner_unlocked(&runtime).await?;
    Ok(runtime.agent_registry.register(&client_ids).await)
}

#[tauri::command]
async fn agent_mcp_repair(
    runtime: State<'_, AppRuntime>,
    client_id: String,
) -> Result<AgentActionResult, String> {
    require_owner_unlocked(&runtime).await?;
    Ok(runtime.agent_registry.repair(&client_id).await)
}

#[tauri::command]
async fn agent_mcp_remove(
    runtime: State<'_, AppRuntime>,
    client_id: String,
) -> Result<AgentActionResult, String> {
    require_owner_unlocked(&runtime).await?;
    Ok(runtime.agent_registry.remove(&client_id).await)
}

#[tauri::command]
async fn choose_private_key(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<Option<String>, String> {
    require_owner_unlocked(&runtime).await?;
    let selected = app
        .dialog()
        .file()
        .add_filter("SSH private key", &["pem", "key", "ppk", "txt"])
        .blocking_pick_file();
    let Some(path) = selected else {
        return Ok(None);
    };
    let path = path.into_path().map_err(command_error)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("SSH KEY")
        .to_owned();
    *runtime.pending_private_key.lock().await = Some(path);
    Ok(Some(name))
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ChromeProfile {
    directory: String,
    name: String,
    account: String,
    is_last_used: bool,
}

fn is_valid_chrome_profile_dir(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > 128
        || trimmed != value
        || trimmed.starts_with('-')
        || trimmed.eq_ignore_ascii_case("System Profile")
        || trimmed.eq_ignore_ascii_case("Guest Profile")
        || trimmed.chars().any(|ch| ch.is_control() || matches!(ch, '/' | '\\'))
    {
        return false;
    }
    let mut components = Path::new(trimmed).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

fn chrome_user_data_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(|root| PathBuf::from(root).join("Google/Chrome/User Data"))
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(|home| PathBuf::from(home).join("Library/Application Support/Google/Chrome"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(|config| PathBuf::from(config).join("google-chrome"))
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|home| PathBuf::from(home).join(".config/google-chrome"))
            })
    }
}

fn parse_chrome_profiles_from_local_state(
    user_data_dir: &Path,
    raw: &str,
) -> Vec<ChromeProfile> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    let last_used = json
        .pointer("/profile/last_used")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let Some(cache) = json
        .pointer("/profile/info_cache")
        .and_then(|value| value.as_object())
    else {
        return Vec::new();
    };
    let mut profiles = Vec::new();
    for (directory, entry) in cache {
        if !is_valid_chrome_profile_dir(directory) || !user_data_dir.join(directory).is_dir() {
            continue;
        }
        let str_field = |key: &str| {
            entry
                .get(key)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .unwrap_or("")
        };
        let name = [
            str_field("name"),
            str_field("shortcut_name"),
            str_field("gaia_name"),
            directory.as_str(),
        ]
        .into_iter()
        .find(|v| !v.is_empty())
        .unwrap_or(directory.as_str())
        .to_owned();
        let account = str_field("user_name").to_owned();
        profiles.push(ChromeProfile {
            directory: directory.clone(),
            name,
            account,
            is_last_used: directory == last_used,
        });
    }
    profiles.sort_by(|a, b| {
        b.is_last_used
            .cmp(&a.is_last_used)
            .then_with(|| (b.directory == "Default").cmp(&(a.directory == "Default")))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.directory.cmp(&b.directory))
    });
    profiles
}

#[tauri::command]
fn list_chrome_profiles() -> Vec<ChromeProfile> {
    let Some(user_data_dir) = chrome_user_data_dir() else {
        return Vec::new();
    };
    let Ok(raw) = std::fs::read_to_string(user_data_dir.join("Local State")) else {
        return Vec::new();
    };
    parse_chrome_profiles_from_local_state(&user_data_dir, &raw)
}

async fn arm_browser_pairing(app: &AppHandle, runtime: &AppRuntime) {
    if let Ok(settings) = runtime.vault.settings()
        && !settings.browser_enabled
    {
        let _ = runtime.vault.update_settings_patch(SettingsPatch {
            browser_enabled: Some(true),
            ..SettingsPatch::default()
        });
    }
    runtime.browser.sync().await;
    let _ = runtime.browser.start_quick_pairing().await;
    emit_changed(app);
}

#[tauri::command]
async fn quick_pair_browser(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    port: u16,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .vault
        .update_settings_patch(SettingsPatch {
            browser_enabled: Some(true),
            browser_port: Some(port),
            ..SettingsPatch::default()
        })
        .map_err(command_error)?;
    runtime.browser.sync().await;
    runtime
        .browser
        .start_quick_pairing()
        .await
        .map_err(command_error)?;

    emit_changed(&app);

    Ok(())
}

#[tauri::command]
fn open_chrome_browser(profile_directory: Option<String>) -> Result<(), String> {
    let profile = match profile_directory {
        Some(dir) if !dir.trim().is_empty() => {
            if !is_valid_chrome_profile_dir(&dir) {
                return Err("Invalid Chrome profile directory".to_owned());
            }
            Some(dir)
        }
        _ => None,
    };
    #[cfg(windows)]
    {
        let mut candidates = Vec::new();
        for root in ["LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)"] {
            if let Some(root) = std::env::var_os(root) {
                let base = PathBuf::from(root);
                candidates.push(base.join("Google/Chrome/Application/chrome.exe"));
                if profile.is_none() {
                    candidates.push(base.join("Microsoft/Edge/Application/msedge.exe"));
                    candidates
                        .push(base.join("BraveSoftware/Brave-Browser/Application/brave.exe"));
                    candidates.push(base.join("Chromium/Application/chrome.exe"));
                }
            }
        }
        candidates.push(PathBuf::from("chrome.exe"));
        if profile.is_none() {
            candidates.push(PathBuf::from("msedge.exe"));
            candidates.push(PathBuf::from("brave.exe"));
        }
        if candidates.into_iter().any(|candidate| {
            if candidate.components().count() != 1 && !candidate.is_file() {
                return false;
            }
            let mut command = Command::new(candidate);
            if let Some(ref dir) = profile {
                command.arg(format!("--profile-directory={dir}"));
            }
            command.arg("--new-tab").spawn().is_ok()
        }) {
            return Ok(());
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(ref dir) = profile {
            let mut binaries = vec![PathBuf::from(
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            )];
            if let Some(home) = std::env::var_os("HOME") {
                binaries.push(
                    PathBuf::from(home)
                        .join("Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
                );
            }
            if binaries.into_iter().any(|binary| {
                binary.is_file()
                    && Command::new(binary)
                        .arg(format!("--profile-directory={dir}"))
                        .arg("--new-tab")
                        .spawn()
                        .is_ok()
            }) {
                return Ok(());
            }
            if Command::new("open")
                .args([
                    "-a",
                    "Google Chrome",
                    "--args",
                    &format!("--profile-directory={dir}"),
                    "--new-tab",
                ])
                .status()
                .is_ok_and(|status| status.success())
            {
                return Ok(());
            }
        } else {
            for app in ["Google Chrome", "Microsoft Edge", "Brave Browser", "Arc", "Chromium"] {
                if Command::new("open")
                    .args(["-a", app])
                    .status()
                    .is_ok_and(|status| status.success())
                {
                    return Ok(());
                }
            }
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let browsers: &[&str] = if profile.is_some() {
            &["google-chrome", "google-chrome-stable"]
        } else {
            &[
                "google-chrome",
                "google-chrome-stable",
                "microsoft-edge",
                "brave-browser",
                "chromium",
                "chromium-browser",
            ]
        };
        if browsers.iter().any(|browser| {
            let mut command = Command::new(browser);
            if let Some(ref dir) = profile {
                command.arg(format!("--profile-directory={dir}"));
            }
            command.arg("--new-tab").spawn().is_ok()
        }) {
            return Ok(());
        }
    }
    Err("Unable to open Chrome; open it manually and paste the copied address".to_owned())
}

#[tauri::command]
async fn test_browser_bridge(
    runtime: State<'_, AppRuntime>,
) -> Result<serde_json::Value, String> {
    require_owner_unlocked(&runtime).await?;
    runtime.browser.sync().await;
    runtime
        .browser
        .inspect_page(None, None)
        .await
        .map_err(command_error)
}

#[tauri::command]
async fn reset_browser_pairing(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .browser
        .reset_pairing()
        .await
        .map_err(command_error)?;
    emit_changed(&app);
    Ok(())
}

#[tauri::command]
async fn reload_browser_extension(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<usize, String> {
    require_owner_unlocked(&runtime).await?;
    let reloaded = runtime
        .browser
        .reload_extensions()
        .await
        .map_err(command_error)?;
    emit_changed(&app);
    Ok(reloaded)
}

#[tauri::command]
async fn open_browser_extension_folder(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    arm_browser_pairing(&app, &runtime).await;
    let path = browser_extension_path(&app)?;
    app.opener()
        .open_path(path.to_string_lossy(), None::<&str>)
        .map_err(command_error)
}

#[tauri::command]
async fn drag_browser_extension(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    window: WebviewWindow,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    let path = browser_extension_path(&app)?;
    let pair_app = app.clone();
    tauri::async_runtime::spawn(async move {
        let runtime = pair_app.state::<AppRuntime>();
        arm_browser_pairing(&pair_app, &runtime).await;
    });
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let drag_window = window.clone();
    window
        .run_on_main_thread(move || {
            let result = (|| -> Result<(), String> {
                #[cfg(target_os = "linux")]
                let native = drag_window.gtk_window().map_err(command_error)?;
                #[cfg(target_os = "linux")]
                let handle = &native;
                #[cfg(not(target_os = "linux"))]
                let handle = &drag_window;
                drag::start_drag(
                    handle,
                    drag::DragItem::Files(vec![path]),
                    drag::Image::Raw(include_bytes!("../icons/32x32.png").to_vec()),
                    |_, _| {},
                    drag::Options::default(),
                )
                .map_err(command_error)
            })();
            let _ = sender.send(result);
        })
        .map_err(command_error)?;
    receiver.await.map_err(command_error)?
}

fn browser_extension_path(app: &AppHandle) -> Result<PathBuf, String> {
    let bundled = app
        .path()
        .resource_dir()
        .ok()
        .map(|path| path.join("browser-extension"))
        .filter(|path| path.is_dir());
    let executable = mcp::launcher_executable().map_err(command_error)?;
    let portable = executable
        .parent()
        .map(|path| path.join("browser-extension"))
        .filter(|path| path.is_dir());
    let development = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|path| path.join("browser-extension"))
        .filter(|path| path.is_dir());
    let path = portable.or(bundled).or(development).ok_or_else(|| {
        "browser-extension directory not found; use the complete portable ZIP".to_owned()
    })?;
    Ok(path)
}

#[tauri::command]
async fn generate_password(
    runtime: State<'_, AppRuntime>,
    options: crate::generator::Options,
) -> Result<String, String> {
    require_owner_unlocked(&runtime).await?;
    crate::generator::password(&options).map_err(command_error)
}

#[tauri::command]
async fn export_backup(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    password: String,
) -> Result<Option<String>, String> {
    require_owner_unlocked(&runtime).await?;
    let password = zeroize::Zeroizing::new(password);
    let selected = app
        .dialog()
        .file()
        .add_filter("OpenKeylet backup", &["mvault"])
        .set_file_name("openkeylet-backup.mvault")
        .blocking_save_file();
    let Some(path) = selected else {
        return Ok(None);
    };
    let path = path.into_path().map_err(command_error)?;
    backup::export_protected(&runtime.vault, &path, &password).map_err(command_error)?;
    Ok(Some(path.to_string_lossy().into_owned()))
}

#[tauri::command]
async fn github_backup_status(runtime: State<'_, AppRuntime>) -> Result<BackupStatus, String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .github_backup
        .lock()
        .await
        .status()
        .map_err(command_error)
}

#[tauri::command]
async fn github_backup_account(
    runtime: State<'_, AppRuntime>,
    input: github_backup::AuthInput,
) -> Result<github_backup::AccountStatus, String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .github_backup
        .lock()
        .await
        .account(input)
        .await
        .map_err(command_error)
}

#[tauri::command]
async fn github_backup_generate_key(runtime: State<'_, AppRuntime>) -> Result<String, String> {
    require_owner_unlocked(&runtime).await?;
    github_backup::generate_recovery_key().map_err(command_error)
}

#[tauri::command]
async fn github_backup_recovery_key(runtime: State<'_, AppRuntime>) -> Result<String, String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .github_backup
        .lock()
        .await
        .recovery_key()
        .map_err(command_error)
}

#[tauri::command]
async fn github_backup_connect(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    input: ConnectInput,
) -> Result<BackupStatus, String> {
    require_owner_unlocked(&runtime).await?;
    if !runtime.vault.is_strong_mode() && input.master_passphrase.trim().is_empty() {
        return Err("STRONG_PASSPHRASE_SHORT: Set a master passphrase (at least 12 characters) to enable Strong Cloud Vault mode".to_owned());
    }
    let status = runtime
        .github_backup
        .lock()
        .await
        .connect(input)
        .await
        .map_err(command_error)?;
    if runtime.vault.is_strong_mode() {
        keep_owner_unlocked(&runtime).await;
        if let Err(error) = runtime.session_broker.start(runtime.vault.clone()) {
            eprintln!("OpenKeylet: failed to start Strong Vault MCP session broker: {error:#}");
        }
    }
    emit_changed(&app);
    Ok(status)
}

#[tauri::command]
async fn github_backup_upload(runtime: State<'_, AppRuntime>) -> Result<BackupStatus, String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .github_backup
        .lock()
        .await
        .upload()
        .await
        .map_err(command_error)
}

#[tauri::command]
async fn github_backup_restore(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<RestoreResult, String> {
    require_owner_unlocked(&runtime).await?;
    let result = runtime
        .github_backup
        .lock()
        .await
        .restore()
        .await
        .map_err(command_error)?;
    emit_changed(&app);
    Ok(result)
}

#[tauri::command]
async fn github_backup_sync(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<SyncResult, String> {
    require_owner_unlocked(&runtime).await?;
    let result = runtime
        .github_backup
        .lock()
        .await
        .sync()
        .await
        .map_err(command_error)?;
    if result.merge.added > 0 || result.merge.updated > 0 || result.merge.deleted > 0 {
        emit_changed(&app);
    }
    Ok(result)
}

#[tauri::command]
async fn github_backup_set_auto_sync(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    enabled: bool,
) -> Result<BackupStatus, String> {
    require_owner_unlocked(&runtime).await?;
    let status = runtime
        .github_backup
        .lock()
        .await
        .set_auto_sync(enabled)
        .map_err(command_error)?;
    if enabled {
        schedule_auto_sync(&app, 100);
    }
    Ok(status)
}

#[tauri::command]
async fn github_backup_disconnect(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<BackupStatus, String> {
    require_owner_unlocked(&runtime).await?;
    let status = runtime
        .github_backup
        .lock()
        .await
        .disconnect()
        .map_err(command_error)?;
    runtime.session_broker.stop();
    emit_changed(&app);
    Ok(status)
}

#[tauri::command]
async fn github_backup_help(app: AppHandle, page: String) -> Result<(), String> {
    let url = match page.as_str() {
        "repository" => "https://github.com/new",
        "token" => "https://github.com/settings/personal-access-tokens/new",
        "login" => "https://cli.github.com/manual/gh_auth_login",
        _ => return Err("GITHUB_HELP_INVALID".to_owned()),
    };
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(command_error)
}

#[tauri::command]
async fn import_backup(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    password: String,
) -> Result<Option<ImportSummary>, String> {
    require_owner_unlocked(&runtime).await?;
    let password = zeroize::Zeroizing::new(password);
    let selected = app
        .dialog()
        .file()
        .add_filter("OpenKeylet backup", &["mvault"])
        .blocking_pick_file();
    let Some(path) = selected else {
        return Ok(None);
    };
    let path = path.into_path().map_err(command_error)?;
    let summary =
        backup::import_with_password(&runtime.vault, &path, &password).map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(Some(summary))
}

#[tauri::command]
async fn pick_backup_import_file(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<Option<serde_json::Value>, String> {
    require_owner_unlocked(&runtime).await?;
    *runtime.pending_backup_source.lock().await = None;
    *runtime.pending_backup_import.lock().await = None;
    let selected = app
        .dialog()
        .file()
        .add_filter("OpenKeylet backup", &["mvault"])
        .blocking_pick_file();
    let Some(path) = selected else {
        return Ok(None);
    };
    require_owner_unlocked(&runtime).await?;
    let path = path.into_path().map_err(command_error)?;
    let requires_password =
        backup::inspect_file_requires_password(&path).map_err(command_error)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("backup.mvault")
        .to_owned();
    *runtime.pending_backup_source.lock().await = Some(PendingBackupSource::Path(path));
    Ok(Some(serde_json::json!({
        "fileName": file_name,
        "requiresPassword": requires_password,
    })))
}

#[tauri::command]
async fn inspect_dropped_backup_bytes(
    runtime: State<'_, AppRuntime>,
    file_name: String,
    content: String,
) -> Result<serde_json::Value, String> {
    require_owner_unlocked(&runtime).await?;
    *runtime.pending_backup_source.lock().await = None;
    *runtime.pending_backup_import.lock().await = None;
    let bytes = content.into_bytes();
    let requires_password =
        backup::inspect_bytes_requires_password(&bytes).map_err(command_error)?;
    let display_name = Path::new(&file_name)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("openkeylet-backup.mvault")
        .to_owned();
    *runtime.pending_backup_source.lock().await = Some(PendingBackupSource::Bytes(bytes));
    Ok(serde_json::json!({
        "fileName": display_name,
        "requiresPassword": requires_password,
    }))
}

#[tauri::command]
async fn prepare_backup_import(
    runtime: State<'_, AppRuntime>,
    password: String,
) -> Result<serde_json::Value, String> {
    require_owner_unlocked(&runtime).await?;
    let password = zeroize::Zeroizing::new(password);
    let source = runtime
        .pending_backup_source
        .lock()
        .await
        .clone()
        .ok_or_else(|| "Choose a .mvault backup file first".to_owned())?;
    let prepared = match &source {
        PendingBackupSource::Path(path) => {
            backup::prepare_import_with_password(&runtime.vault, path, &password)
        }
        PendingBackupSource::Bytes(bytes) => {
            backup::prepare_import_bytes_with_password(&runtime.vault, bytes, &password)
        }
    }
    .map_err(command_error)?;
    let id = Uuid::new_v4().to_string();
    let encrypted = runtime
        .vault
        .protect_local_state(&*prepared.raw_payload)
        .map_err(command_error)?;
    let result = serde_json::json!({
        "id": id,
        "preview": prepared.preview,
    });
    *runtime.pending_backup_source.lock().await = None;
    *runtime.pending_backup_import.lock().await = Some(PendingBackupImport {
        id,
        created: Instant::now(),
        version: prepared.version,
        encrypted,
    });
    Ok(result)
}

#[tauri::command]
async fn commit_backup_import(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: String,
    selected_item_indices: Option<Vec<usize>>,
    selected_trash_indices: Option<Vec<usize>>,
) -> Result<ImportSummary, String> {
    require_owner_unlocked(&runtime).await?;
    let mut slot = runtime.pending_backup_import.lock().await;
    let pending = slot.as_ref().ok_or("Choose a .mvault backup file first")?;
    if pending.id != id {
        return Err("Backup preview changed; choose the file again".into());
    }
    if pending.created.elapsed().as_secs() > 300 {
        *slot = None;
        return Err("Backup preview expired; choose the file again".into());
    }
    let raw_payload: Vec<u8> = runtime
        .vault
        .unprotect_local_state(&pending.encrypted)
        .map_err(command_error)?;
    let raw_payload = zeroize::Zeroizing::new(raw_payload);
    let summary = backup::commit_prepared_import_selected(
        &runtime.vault,
        &raw_payload,
        pending.version,
        selected_item_indices.as_deref(),
        selected_trash_indices.as_deref(),
    )
    .map_err(command_error)?;
    *slot = None;
    emit_changed(&app);
    if summary.added > 0 {
        schedule_auto_sync(&app, 3000);
    }
    Ok(summary)
}

#[tauri::command]
async fn cancel_backup_import(runtime: State<'_, AppRuntime>) -> Result<(), String> {
    *runtime.pending_backup_source.lock().await = None;
    *runtime.pending_backup_import.lock().await = None;
    Ok(())
}

#[tauri::command]
async fn prepare_import(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    format: String,
) -> Result<Option<serde_json::Value>, String> {
    require_owner_unlocked(&runtime).await?;
    *runtime.pending_import.lock().await = None;
    let selected = match format.as_str() {
        "bitwarden" => app
            .dialog()
            .file()
            .add_filter("Bitwarden JSON", &["json"])
            .blocking_pick_file(),
        "chrome" => app
            .dialog()
            .file()
            .add_filter("Password CSV", &["csv"])
            .blocking_pick_file(),
        "env" | "ssh_config" => app.dialog().file().blocking_pick_file(),
        _ => return Err("Unsupported import format".into()),
    };
    let Some(path) = selected else {
        return Ok(None);
    };
    require_owner_unlocked(&runtime).await?;
    let parsed = crate::migration::read(&path.into_path().map_err(command_error)?, &format)
        .map_err(command_error)?;
    let id = Uuid::new_v4().to_string();
    let encrypted = runtime
        .vault
        .protect_local_state(&parsed.entries)
        .map_err(command_error)?;
    let result = serde_json::json!({"id":id,"preview":parsed.preview});
    *runtime.pending_import.lock().await = Some(PendingImport {
        id,
        created: Instant::now(),
        encrypted,
    });
    Ok(Some(result))
}

#[tauri::command]
async fn prepare_ssh_config_import(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    use_default: bool,
) -> Result<Option<serde_json::Value>, String> {
    require_owner_unlocked(&runtime).await?;
    *runtime.pending_import.lock().await = None;
    let path = if use_default {
        let Some(default_path) = crate::smart_ingest::default_ssh_config_path() else {
            return Err("Could not locate your home directory for ~/.ssh/config".into());
        };
        if !default_path.exists() {
            return Err(format!(
                "Default SSH config not found at {}",
                default_path.display()
            ));
        }
        default_path
    } else {
        let Some(picked) = app.dialog().file().blocking_pick_file() else {
            return Ok(None);
        };
        require_owner_unlocked(&runtime).await?;
        picked.into_path().map_err(command_error)?
    };
    let parsed = crate::migration::read(&path, "ssh_config").map_err(command_error)?;
    let id = Uuid::new_v4().to_string();
    let encrypted = runtime
        .vault
        .protect_local_state(&parsed.entries)
        .map_err(command_error)?;
    let result = serde_json::json!({
        "id": id,
        "preview": parsed.preview,
        "sourcePath": path.to_string_lossy(),
    });
    *runtime.pending_import.lock().await = Some(PendingImport {
        id,
        created: Instant::now(),
        encrypted,
    });
    Ok(Some(result))
}

#[tauri::command]
async fn smart_parse_text(
    runtime: State<'_, AppRuntime>,
    text: String,
    filename: Option<String>,
    url: Option<String>,
) -> Result<crate::smart_ingest::SmartParseResult, String> {
    require_owner_unlocked(&runtime).await?;
    crate::smart_ingest::smart_parse(&text, filename.as_deref(), url.as_deref())
        .map_err(command_error)
}

#[tauri::command]
async fn smart_extract_batch(
    runtime: State<'_, AppRuntime>,
    text: String,
    filename: Option<String>,
) -> Result<crate::smart_extract::SmartExtractBatchResult, String> {
    require_owner_unlocked(&runtime).await?;
    let existing = runtime
        .vault
        .list_decrypted_connections()
        .map_err(command_error)?;
    crate::smart_extract::extract_batch(&text, filename.as_deref(), &existing)
        .map_err(command_error)
}

#[tauri::command]
async fn smart_pick_and_extract_files(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<Option<serde_json::Value>, String> {
    require_owner_unlocked(&runtime).await?;
    let Some(picked) = app.dialog().file().blocking_pick_files() else {
        return Ok(None);
    };
    require_owner_unlocked(&runtime).await?;
    let mut paths = Vec::with_capacity(picked.len());
    for file_path in picked {
        paths.push(file_path.into_path().map_err(command_error)?);
    }
    let existing = runtime
        .vault
        .list_decrypted_connections()
        .map_err(command_error)?;
    let mut outcome = crate::smart_extract::extract_from_paths(&paths, &existing);

    let mut mvault_file = None;
    if let Some(mvault_path) = outcome.mvault_paths.first() {
        let file_name = mvault_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("openkeylet-backup.mvault")
            .to_owned();
        match backup::inspect_file_requires_password(mvault_path) {
            Ok(requires_password) => {
                *runtime.pending_backup_import.lock().await = None;
                *runtime.pending_backup_source.lock().await =
                    Some(PendingBackupSource::Path(mvault_path.clone()));
                mvault_file = Some(serde_json::json!({
                    "fileName": file_name,
                    "requiresPassword": requires_password,
                }));
            }
            Err(error) => {
                outcome.batch.warnings.push(format!("{file_name}: {error}"));
            }
        }
    }

    let mut value = serde_json::to_value(&outcome.batch).map_err(command_error)?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "images".to_owned(),
            serde_json::to_value(&outcome.images).map_err(command_error)?,
        );
        obj.insert(
            "sourceFiles".to_owned(),
            serde_json::to_value(&outcome.source_files).map_err(command_error)?,
        );
        if let Some(mv) = mvault_file {
            obj.insert("mvaultFile".to_owned(), mv);
        }
    }
    Ok(Some(value))
}

#[tauri::command]
async fn smart_extract_dropped_binary(
    runtime: State<'_, AppRuntime>,
    file_name: String,
    data_base64: String,
) -> Result<crate::smart_extract::SmartExtractBatchResult, String> {
    require_owner_unlocked(&runtime).await?;
    use base64::{Engine, engine::general_purpose::STANDARD};
    let bytes = STANDARD
        .decode(data_base64.trim())
        .map_err(|e| format!("Invalid file encoding: {e}"))?;
    let display_name = Path::new(&file_name)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("file");
    let existing = runtime
        .vault
        .list_decrypted_connections()
        .map_err(command_error)?;
    crate::smart_extract::extract_from_bytes(&bytes, display_name, &existing)
        .map_err(command_error)
}

#[tauri::command]
async fn smart_scan_local_dev_configs(
    runtime: State<'_, AppRuntime>,
) -> Result<crate::smart_extract::SmartExtractBatchResult, String> {
    require_owner_unlocked(&runtime).await?;
    let existing = runtime
        .vault
        .list_decrypted_connections()
        .map_err(command_error)?;
    crate::smart_extract::scan_local_dev_configs(&existing).map_err(command_error)
}

#[tauri::command]
async fn commit_smart_batch(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    items: Vec<crate::smart_extract::SmartCommitItem>,
    folder: Option<String>,
) -> Result<crate::smart_extract::SmartCommitSummary, String> {
    require_owner_unlocked(&runtime).await?;
    if items.is_empty() {
        return Err("No items selected to import".into());
    }
    let default_folder = folder.unwrap_or_default().trim().to_owned();
    let mut used_names: std::collections::HashSet<String> = runtime
        .vault
        .list_connections()
        .map_err(command_error)?
        .into_iter()
        .map(|c| c.name.trim().to_ascii_lowercase())
        .collect();

    let mut added = 0usize;
    let mut updated = 0usize;
    let mut created_ids = Vec::new();

    for item in items {
        let mut input = item.input;
        if input.folder.trim().is_empty() && !default_folder.is_empty() {
            input.folder = default_folder.clone();
        }
        if item.update_existing
            && let Some(raw_id) = item.existing_item_id.as_deref()
            && let Ok(uuid) = Uuid::parse_str(raw_id.trim())
            && let Ok(existing) = runtime.vault.get_connection(uuid)
        {
            // Merge new modules & secrets into existing item without losing existing metadata
            let mut merged_modules = existing.stored.modules.clone();
            for m in &input.modules {
                if let Some(pos) = merged_modules
                    .iter()
                    .position(|em| em.kind == m.kind && em.name.eq_ignore_ascii_case(&m.name))
                {
                    if !m.value.trim().is_empty() {
                        merged_modules[pos].value = m.value.clone();
                    }
                } else {
                    merged_modules.push(m.clone());
                }
            }
            let mut merged_uris = existing.stored.login_uris.clone();
            for uri in &input.login_uris {
                if !merged_uris.iter().any(|u| u.uri == uri.uri) {
                    merged_uris.push(uri.clone());
                }
            }
            let merged_input = ConnectionInput {
                login_uris: merged_uris,
                item_type: existing.stored.item_type().to_owned(),
                folder: if !input.folder.trim().is_empty() {
                    input.folder
                } else {
                    existing.stored.folder
                },
                favorite: existing.stored.favorite,
                id: Some(uuid),
                modules: merged_modules,
                name: existing.stored.name,
                enabled: existing.stored.enabled,
                description: if existing.stored.description.is_empty() {
                    input.description
                } else {
                    existing.stored.description
                },
                http_auth_type: if !input.http_auth_type.is_empty() {
                    input.http_auth_type
                } else {
                    existing.stored.http_auth_type
                },
                private_key_import_path: String::new(),
                auth_header: if !input.auth_header.is_empty() {
                    input.auth_header
                } else {
                    existing.stored.auth_header
                },
                auth_location: if !input.auth_location.is_empty() {
                    input.auth_location
                } else {
                    existing.stored.auth_location
                },
                auth_prefix: if !input.auth_prefix.is_empty() {
                    input.auth_prefix
                } else {
                    existing.stored.auth_prefix
                },
                api_auth_headers: if !input.api_auth_headers.is_empty() {
                    input.api_auth_headers
                } else {
                    existing.stored.api_auth_headers
                },
                test_path: if !input.test_path.is_empty() {
                    input.test_path
                } else {
                    existing.stored.test_path
                },
                remove_secret_names: Vec::new(),
                secrets: input.secrets,
            };
            runtime
                .vault
                .save_connection(merged_input)
                .map_err(command_error)?;
            updated += 1;
            continue;
        }

        // Resolve unique name cleanly for new items
        input.id = None;
        let base_name = if input.name.trim().is_empty() {
            "Imported item".to_owned()
        } else {
            input.name.trim().to_owned()
        };
        let mut candidate_name = base_name.clone();
        let mut suffix = 2usize;
        while used_names.contains(&candidate_name.to_ascii_lowercase()) {
            let tag = format!(" ({suffix})");
            let max_base = 80usize.saturating_sub(tag.chars().count());
            let truncated: String = base_name.chars().take(max_base).collect();
            candidate_name = format!("{truncated}{tag}");
            suffix += 1;
        }
        used_names.insert(candidate_name.to_ascii_lowercase());
        input.name = candidate_name;

        let saved = runtime.vault.save_connection(input).map_err(command_error)?;
        created_ids.push(saved.id.to_string());
        added += 1;
    }

    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(crate::smart_extract::SmartCommitSummary {
        added,
        updated,
        created_ids,
    })
}

#[tauri::command]
async fn undo_smart_batch(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    ids: Vec<String>,
) -> Result<usize, String> {
    require_owner_unlocked(&runtime).await?;
    let mut removed = 0usize;
    for raw_id in ids {
        if let Ok(uuid) = Uuid::parse_str(raw_id.trim())
            && runtime.vault.trash_connection(uuid, None).is_ok()
        {
            removed += 1;
        }
    }
    if removed > 0 {
        emit_changed(&app);
        schedule_auto_sync(&app, 3000);
    }
    Ok(removed)
}

#[tauri::command]
async fn read_owner_clipboard(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<String, String> {
    require_owner_unlocked(&runtime).await?;
    Ok(clipboard::read_text(&app).unwrap_or_default())
}

#[tauri::command]
async fn clear_clipboard_if_matches(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    text: String,
) -> Result<bool, String> {
    require_owner_unlocked(&runtime).await?;
    Ok(clipboard::clear_if_exact(&app, &runtime.clipboard, &text))
}

#[tauri::command]
async fn attach_totp_to_item(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: String,
    totp: String,
    expected_updated_at: String,
) -> Result<PublicConnection, String> {
    require_owner_unlocked(&runtime).await?;
    let trimmed = totp.trim();
    crate::browser::current_totp(trimmed).map_err(command_error)?;
    let uuid = Uuid::parse_str(id.trim()).map_err(|_| "Invalid item ID".to_owned())?;
    let existing = runtime.vault.get_connection(uuid).map_err(command_error)?;
    let mut modules = existing.stored.modules.clone();
    if !modules.iter().any(|m| m.kind == "totp") {
        modules.push(crate::model::ItemModule {
            kind: "totp".to_owned(),
            name: "totp".to_owned(),
            value: String::new(),
            agent_visible: Some(false),
        });
    }
    let mut secrets = crate::model::SecretBundle::default();
    secrets
        .named_secrets
        .insert("totp".to_owned(), trimmed.to_owned());
    let item_type = existing.stored.item_type().to_owned();
    let input = ConnectionInput {
        login_uris: existing.stored.login_uris,
        item_type,
        folder: existing.stored.folder,
        favorite: existing.stored.favorite,
        id: Some(uuid),
        modules,
        name: existing.stored.name,
        enabled: existing.stored.enabled,
        description: existing.stored.description,
        http_auth_type: existing.stored.http_auth_type,
        private_key_import_path: String::new(),
        auth_header: existing.stored.auth_header,
        auth_location: existing.stored.auth_location,
        auth_prefix: existing.stored.auth_prefix,
        api_auth_headers: existing.stored.api_auth_headers,
        test_path: existing.stored.test_path,
        remove_secret_names: Vec::new(),
        secrets,
    };
    let saved = runtime
        .vault
        .save_connection_checked(input, Some(expected_updated_at.as_str()))
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(saved)
}

#[tauri::command]
async fn commit_import(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: String,
) -> Result<ImportSummary, String> {
    require_owner_unlocked(&runtime).await?;
    let mut slot = runtime.pending_import.lock().await;
    let pending = slot.as_ref().ok_or("Choose an import file first")?;
    if pending.id != id {
        return Err("Import preview changed; choose the file again".into());
    }
    if pending.created.elapsed().as_secs() > 300 {
        *slot = None;
        return Err("Import preview expired; choose the file again".into());
    }
    let entries = runtime
        .vault
        .unprotect_local_state(&pending.encrypted)
        .map_err(command_error)?;
    let summary = runtime
        .vault
        .merge_connections(entries)
        .map_err(command_error)?;
    *slot = None;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(summary)
}

#[tauri::command]
async fn cancel_import(runtime: State<'_, AppRuntime>) -> Result<(), String> {
    *runtime.pending_import.lock().await = None;
    Ok(())
}

#[tauri::command]
async fn update_status(runtime: State<'_, AppRuntime>) -> Result<UpdateStatus, String> {
    Ok(runtime.updater.status().await)
}

#[tauri::command]
async fn update_check(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<UpdateStatus, String> {
    let emit_handle = app.clone();
    let outcome = runtime
        .updater
        .check_for_updates(true, move |status| {
            emit_update_status(&emit_handle, status);
        })
        .await
        .map_err(command_error)?;
    let settings = runtime.vault.settings().unwrap_or_default();
    if outcome.update_available
        && outcome.status.phase == "available"
        && settings.update_auto_download
        && outcome.status.can_auto_install
    {
        let updater = runtime.updater.clone();
        let handle = app.clone();
        tauri::async_runtime::spawn(async move {
            let emit_handle = handle.clone();
            let _ = updater
                .download_and_stage(move |status| {
                    emit_update_status(&emit_handle, status);
                })
                .await;
        });
    }
    Ok(outcome.status)
}

#[tauri::command]
async fn update_download(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<UpdateStatus, String> {
    require_owner_unlocked(&runtime).await?;
    let emit_handle = app.clone();
    runtime
        .updater
        .download_and_stage(move |status| {
            emit_update_status(&emit_handle, status);
        })
        .await
        .map_err(command_error)
}

#[tauri::command]
async fn update_install_and_restart(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    let current_status = runtime.updater.status().await;
    if current_status.phase != "ready" {
        let emit_handle = app.clone();
        runtime
            .updater
            .download_and_stage(move |status| {
                emit_update_status(&emit_handle, status);
            })
            .await
            .map_err(command_error)?;
    }
    let emit_handle = app.clone();
    runtime
        .updater
        .apply_and_relaunch(true, move |status| {
            emit_update_status(&emit_handle, status);
        })
        .await
        .map_err(command_error)?;
    clipboard::clear_if_unchanged(&app, &runtime.clipboard, None);
    let exit_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(120)).await;
        exit_handle.exit(0);
    });
    Ok(())
}

#[tauri::command]
async fn update_skip_version(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    version: String,
) -> Result<UpdateStatus, String> {
    require_owner_unlocked(&runtime).await?;
    let status = runtime
        .updater
        .skip_version(&version)
        .await
        .map_err(command_error)?;
    emit_update_status(&app, &status);
    emit_changed(&app);
    Ok(status)
}

#[tauri::command]
async fn update_open_release_page(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<(), String> {
    let status = runtime.updater.status().await;
    let url = if status.release_url.starts_with("https://github.com/") {
        status.release_url
    } else {
        updater::DEFAULT_RELEASES_URL.to_owned()
    };
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(command_error)
}

#[tauri::command]
async fn open_data_folder(app: AppHandle, runtime: State<'_, AppRuntime>) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    app.opener()
        .open_path(runtime.vault.data_dir().to_string_lossy(), None::<&str>)
        .map_err(command_error)
}

#[tauri::command]
async fn window_action(
    window: WebviewWindow,
    runtime: State<'_, AppRuntime>,
    action: String,
) -> Result<(), String> {
    match action.as_str() {
        "minimize" => window.minimize().map_err(command_error),
        "close" => {
            let tray_available = runtime.tray_available.load(Ordering::Acquire);
            if !tray_available {
                runtime.vault.lock_strong();
                runtime.session_broker.stop();
                clipboard::clear_if_unchanged(window.app_handle(), &runtime.clipboard, None);
                window.app_handle().exit(0);
                return Ok(());
            }
            let close_behavior = runtime
                .vault
                .settings()
                .map_err(command_error)?
                .close_behavior;
            if !should_hide_on_close(&close_behavior, tray_available) {
                runtime.vault.lock_strong();
                runtime.session_broker.stop();
                clipboard::clear_if_unchanged(window.app_handle(), &runtime.clipboard, None);
                window.app_handle().exit(0);
                Ok(())
            } else {
                window.hide().map_err(command_error)
            }
        }
        _ => Err("Unknown window operation".to_owned()),
    }
}

#[tauri::command]
async fn start_vertical_resize(window: WebviewWindow, direction: String) -> Result<(), String> {
    let is_north = match direction.as_str() {
        "north" | "top" => true,
        "south" | "bottom" => false,
        _ => return Err("Only vertical resizing is supported".to_owned()),
    };
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
        use windows::Win32::UI::Input::KeyboardAndMouse::ReleaseCapture;
        use windows::Win32::UI::WindowsAndMessaging::{PostMessageW, SC_SIZE, WM_SYSCOMMAND};
        const WMSZ_TOP: usize = 3;
        const WMSZ_BOTTOM: usize = 6;

        let hwnd = window.hwnd().map_err(command_error)?;
        let cmd = SC_SIZE as usize + if is_north { WMSZ_TOP } else { WMSZ_BOTTOM };
        unsafe {
            let _ = ReleaseCapture();
            PostMessageW(Some(HWND(hwnd.0)), WM_SYSCOMMAND, WPARAM(cmd), LPARAM(0))
                .map_err(command_error)?;
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (window, is_north);
    }
    Ok(())
}

#[tauri::command]
async fn set_edge_dock_enabled(
    window: WebviewWindow,
    runtime: State<'_, AppRuntime>,
    enabled: bool,
) -> Result<(), String> {
    runtime.edge_dock.set_enabled(&window, enabled);
    Ok(())
}

#[tauri::command]
async fn edge_dock_expand(
    window: WebviewWindow,
    runtime: State<'_, AppRuntime>,
) -> Result<(), String> {
    runtime.edge_dock.expand(&window);
    Ok(())
}

#[tauri::command]
async fn edge_dock_hover(
    window: WebviewWindow,
    runtime: State<'_, AppRuntime>,
    entered: bool,
) -> Result<(), String> {
    runtime.edge_dock.on_frontend_hover(&window, entered);
    Ok(())
}

fn should_hide_on_close(close_behavior: &str, tray_available: bool) -> bool {
    tray_available && !close_behavior.eq_ignore_ascii_case("exit")
}

fn show_main_window(app: &AppHandle) {
    #[cfg(target_os = "macos")]
    let _ = app.show();
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        if let Some(runtime) = app.try_state::<AppRuntime>() {
            runtime.edge_dock.expand(&window);
        }
        let _ = window.set_focus();
    }
}

fn install_tray(app: &tauri::App) -> Result<()> {
    let open = MenuItem::with_id(app, "tray-open", "OPEN OpenKeylet", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "tray-lock", "LOCK", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "tray-quit", "QUIT", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &lock, &separator, &quit])?;
    #[cfg(target_os = "macos")]
    let icon = app
        .default_window_icon()
        .context("OpenKeylet tray icon not found")?
        .clone();
    #[cfg(not(target_os = "macos"))]
    let icon = tauri::include_image!("icons/tray.png");

    let builder = TrayIconBuilder::with_id("openkeylet-tray")
        .icon(icon)
        .icon_as_template(cfg!(target_os = "macos"))
        .tooltip("OpenKeylet — LOCAL VAULT")
        .menu(&menu)
        .show_menu_on_left_click(false);
    #[cfg(target_os = "linux")]
    let builder = builder.temp_dir_path(
        app.path()
            .app_cache_dir()?
            .join("tray")
            .join(std::process::id().to_string()),
    );

    let tray = builder
        .on_menu_event(|app, event| {
            if event.id() == "tray-open" {
                show_main_window(app);
            } else if event.id() == "tray-lock" {
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let runtime = handle.state::<AppRuntime>();
                    let strong_mode = runtime.vault.is_strong_mode();
                    let pin_configured = runtime.vault.owner_pin_configured();
                    runtime.owner_session.lock().await.lock();
                    if strong_mode {
                        runtime.vault.lock_strong();
                        runtime.session_broker.stop();
                    }
                    *runtime.pending_import.lock().await = None;
                    clipboard::clear_if_unchanged(&handle, &runtime.clipboard, None);
                    show_main_window(&handle);
                    if !strong_mode && matches!(pin_configured, Ok(false)) {
                        let _ = handle.emit("pin-setup-requested", ());
                    } else {
                        emit_changed(&handle);
                    }
                });
            } else if event.id() == "tray-quit" {
                let runtime = app.state::<AppRuntime>();
                runtime.vault.lock_strong();
                runtime.session_broker.stop();
                clipboard::clear_if_unchanged(app, &runtime.clipboard, None);
                if let Err(error) = crate::runtime_epoch::invalidate(runtime.vault.data_dir()) {
                    eprintln!("OpenKeylet: failed to stop MCP sessions: {error:#}");
                }
                app.exit(0);
            }
        })
        .on_tray_icon_event(|tray, event| match event {
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            }
            | TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            } => show_main_window(tray.app_handle()),
            _ => {}
        })
        .build(app)?;
    #[cfg(target_os = "linux")]
    {
        // GTK exports the dbusmenu tree from idle callbacks. Keep the indicator
        // passive until those callbacks finish so hosts cannot cache an empty
        // first layout and then refuse to open it to request an update.
        tray.set_visible(false)?;
        glib::idle_add_local_full(glib::Priority::LOW, move || {
            if let Err(error) = tray.set_visible(true) {
                eprintln!("OpenKeylet: failed to show the system tray: {error:#}");
            }
            glib::ControlFlow::Break
        });
    }
    #[cfg(not(target_os = "linux"))]
    let _ = tray;
    Ok(())
}

#[cfg(windows)]
fn request_rounded_corners(window: &WebviewWindow) -> Result<()> {
    use windows::Win32::Graphics::Dwm::{
        DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND, DwmSetWindowAttribute,
    };

    let hwnd = window.hwnd().context("Unable to obtain window handle")?;
    // Match the rounded native Bricktone shell; CSS keeps inner wells at 4px.
    let preference = DWMWCP_ROUND;
    unsafe {
        DwmSetWindowAttribute(
            windows::Win32::Foundation::HWND(hwnd.0),
            DWMWA_WINDOW_CORNER_PREFERENCE,
            &preference as *const _ as *const _,
            size_of_val(&preference) as u32,
        )
        .context("Unable to request a rounded-corner window on Windows")?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn request_rounded_corners(_window: &WebviewWindow) -> Result<()> {
    Ok(())
}

pub fn run_gui() -> Result<()> {
    let context = tauri::generate_context!();
    #[cfg(target_os = "linux")]
    let context = {
        let mut context = context;
        let main = context
            .config_mut()
            .app
            .windows
            .iter_mut()
            .find(|window| window.label == "main")
            .context("Main window configuration not found")?;
        // Both the GTK surface and WebKit backing must be transparent; an
        // opaque native background fills the CSS-rounded corners back in.
        main.transparent = true;
        main.background_color = Some(tauri::window::Color(0, 0, 0, 0));
        context
    };
    let data_dir = app_data_dir()?;
    if let Ok(executable) = mcp::launcher_executable() {
        match updater::try_apply_pending_on_startup(&executable, &data_dir) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => {
                eprintln!("OpenKeylet: deferred startup update skipped: {error:#}");
            }
        }
    }
    let mut gui_instance = GuiInstance::acquire(&data_dir)?;
    #[cfg(target_os = "linux")]
    if let Err(error) =
        crate::system_integration::ensure_application_entry(&mcp::launcher_executable()?)
    {
        eprintln!("OpenKeylet: failed to register the application launcher: {error:#}");
    }
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .setup(move |app| {
            let exit_handle = app.handle().clone();
            gui_instance.listen_for_takeover(move || exit_handle.exit(0))?;
            let vault = Vault::open(data_dir.clone())?;
            let executable = mcp::launcher_executable()?.to_string_lossy().into_owned();
            if let Err(error) = crate::system_integration::migrate_legacy_entries(Path::new(&executable)) {
                eprintln!("OpenKeylet: failed to migrate legacy system shortcuts: {error:#}");
            }
            let bridge_handle = app.handle().clone();
            let browser = BrowserBridge::with_on_change(vault.clone(), move || {
                emit_changed(&bridge_handle);
            });
            let agent_registry = AgentRegistry::new(PathBuf::from(&executable))?;
            agent_registry.refresh_managed_instructions();
            let session_broker = SessionBroker::new(data_dir.clone());
            let updater = Arc::new(UpdateManager::new(
                vault.clone(),
                PathBuf::from(&executable),
            ));
            let edge_dock = Arc::new(EdgeDockController::new());
            edge_dock.spawn_monitor(app.handle().clone());
            app.manage(AppRuntime {
                _gui_instance: gui_instance,
                github_backup: Mutex::new(GithubBackup::new(vault.clone())?),
                session_broker,
                updater,
                edge_dock,
                vault,
                executable,
                browser,
                clipboard: Arc::new(ClipboardGuard::new()),
                pending_private_key: Mutex::new(None),
                pending_import: Mutex::new(None),
                pending_backup_source: Mutex::new(None),
                pending_backup_import: Mutex::new(None),
                owner_session: Mutex::new(OwnerSession::default()),
                auto_sync_generation: AtomicU64::new(0),
                agent_registry,
                tray_available: AtomicBool::new(false),
            });

            let window = app.get_webview_window("main").context("Main window not found")?;
            let _ = window.set_icon(tauri::include_image!("icons/128x128@2x.png"));
            #[cfg(debug_assertions)]
            window.set_title("OpenKeylet · DEV")?;
            window.set_min_size(Some(LogicalSize::new(
                WINDOW_LOGICAL_WIDTH,
                WINDOW_MIN_LOGICAL_HEIGHT,
            )))?;
            window.set_max_size(Some(LogicalSize::new(
                WINDOW_LOGICAL_WIDTH,
                WINDOW_MAX_LOGICAL_HEIGHT,
            )))?;
            window.set_size(LogicalSize::new(
                WINDOW_LOGICAL_WIDTH,
                WINDOW_LOGICAL_HEIGHT,
            ))?;
            window.set_resizable(true)?;
            window.set_maximizable(false)?;
            if let Err(error) = request_rounded_corners(&window) {
                // DWMWA_WINDOW_CORNER_PREFERENCE is Windows 11+; Windows 10 returns E_INVALIDARG.
                eprintln!(
                    "OpenKeylet: native rounded corners unavailable on this OS build: {error:#}"
                );
            }
            match install_tray(app) {
                Ok(()) => app
                    .state::<AppRuntime>()
                    .tray_available
                    .store(true, Ordering::Release),
                Err(error) => {
                    eprintln!(
                        "OpenKeylet: system tray unavailable; closing the window will exit: {error:#}"
                    )
                }
            }
            {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    handle.state::<AppRuntime>().browser.sync().await;
                    emit_changed(&handle);
                });
            }
            schedule_auto_sync(app.handle(), 1500);
            schedule_auto_update_check(app.handle(), 3500);
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::DragDrop(drag_event) = event {
                match drag_event {
                    tauri::DragDropEvent::Enter { paths, .. } => {
                        let has_mvault = paths.iter().any(|path| is_mvault_path(path));
                        let other_count = paths.iter().filter(|path| !is_mvault_path(path)).count();
                        let has_folder = paths.iter().any(|path| path.is_dir());
                        let file_names: Vec<String> = paths
                            .iter()
                            .take(4)
                            .filter_map(|path| {
                                path.file_name()
                                    .and_then(|name| name.to_str())
                                    .map(str::to_owned)
                            })
                            .collect();
                        let _ = window.app_handle().emit(
                            "native-file-drag",
                            serde_json::json!({
                                "state": "enter",
                                "hasMvault": has_mvault,
                                "otherCount": other_count,
                                "hasFolder": has_folder,
                                "totalCount": paths.len(),
                                "fileNames": file_names,
                            }),
                        );
                    }
                    tauri::DragDropEvent::Leave => {
                        let _ = window.app_handle().emit(
                            "native-file-drag",
                            serde_json::json!({
                                "state": "leave",
                                "hasMvault": false,
                                "otherCount": 0,
                            }),
                        );
                    }
                    tauri::DragDropEvent::Drop { paths, .. } => {
                        let _ = window.app_handle().emit(
                            "native-file-drag",
                            serde_json::json!({
                                "state": "leave",
                                "hasMvault": false,
                                "otherCount": 0,
                            }),
                        );
                        if !paths.is_empty() {
                            let handle = window.app_handle().clone();
                            let win = window.clone();
                            let dropped_paths = paths.clone();
                            tauri::async_runtime::spawn(async move {
                                let runtime = handle.state::<AppRuntime>();
                                let unlocked = owner_lock_state(&runtime)
                                    .await
                                    .map(|state| state.unlocked)
                                    .unwrap_or(false);
                                if !unlocked {
                                    let _ = win.set_focus();
                                    if let Some(mvault_path) =
                                        dropped_paths.iter().find(|p| is_mvault_path(p))
                                    {
                                        let file_name = mvault_path
                                            .file_name()
                                            .and_then(|n| n.to_str())
                                            .unwrap_or("openkeylet-backup.mvault")
                                            .to_owned();
                                        let _ = handle.emit(
                                            "mvault-file-dropped",
                                            serde_json::json!({
                                                "fileName": file_name,
                                                "locked": true,
                                            }),
                                        );
                                    } else {
                                        let _ = handle.emit(
                                            "native-files-dropped",
                                            serde_json::json!({ "locked": true }),
                                        );
                                    }
                                    return;
                                }

                                let existing = match runtime.vault.list_decrypted_connections() {
                                    Ok(list) => list,
                                    Err(error) => {
                                        let _ = handle.emit(
                                            "native-files-dropped",
                                            serde_json::json!({ "error": error.to_string() }),
                                        );
                                        return;
                                    }
                                };

                                let outcome =
                                    crate::smart_extract::extract_from_paths(&dropped_paths, &existing);
                                let has_other_payload = !outcome.batch.candidates.is_empty()
                                    || !outcome.batch.ignored.is_empty()
                                    || !outcome.batch.warnings.is_empty()
                                    || !outcome.images.is_empty();

                                if has_other_payload {
                                    let _ = win.set_focus();
                                    let _ = handle.emit(
                                        "native-files-dropped",
                                        serde_json::json!({
                                            "batch": outcome.batch,
                                            "images": outcome.images,
                                            "sourceFiles": outcome.source_files,
                                        }),
                                    );
                                }

                                if let Some(mvault_path) = outcome.mvault_paths.first() {
                                    let file_name = mvault_path
                                        .file_name()
                                        .and_then(|name| name.to_str())
                                        .unwrap_or("openkeylet-backup.mvault")
                                        .to_owned();
                                    match backup::inspect_file_requires_password(mvault_path) {
                                        Ok(requires_password) => {
                                            *runtime.pending_backup_import.lock().await = None;
                                            *runtime.pending_backup_source.lock().await =
                                                Some(PendingBackupSource::Path(mvault_path.clone()));
                                            let _ = win.set_focus();
                                            let _ = handle.emit(
                                                "mvault-file-dropped",
                                                serde_json::json!({
                                                    "fileName": file_name,
                                                    "requiresPassword": requires_password,
                                                }),
                                            );
                                        }
                                        Err(error) => {
                                            let _ = win.set_focus();
                                            let _ = handle.emit(
                                                "mvault-file-dropped",
                                                serde_json::json!({
                                                    "fileName": file_name,
                                                    "error": error.to_string(),
                                                }),
                                            );
                                        }
                                    }
                                }
                            });
                        }
                    }
                    _ => {}
                }
            }
            if matches!(event, tauri::WindowEvent::Moved(_)) {
                window.state::<AppRuntime>().edge_dock.on_window_moved();
            }
            if let tauri::WindowEvent::Resized(size) = event {
                let scale = window.scale_factor().unwrap_or(1.0);
                let logical_w = size.width as f64 / scale;
                let logical_h = (size.height as f64 / scale)
                    .clamp(WINDOW_MIN_LOGICAL_HEIGHT, WINDOW_MAX_LOGICAL_HEIGHT);
                if (logical_w - WINDOW_LOGICAL_WIDTH).abs() > 1.5 {
                    let _ = window.set_size(LogicalSize::new(WINDOW_LOGICAL_WIDTH, logical_h));
                }
            }
            if let tauri::WindowEvent::ScaleFactorChanged { scale_factor, .. } = event {
                let current_h = window
                    .inner_size()
                    .map(|s| s.height as f64 / *scale_factor)
                    .unwrap_or(WINDOW_LOGICAL_HEIGHT)
                    .clamp(WINDOW_MIN_LOGICAL_HEIGHT, WINDOW_MAX_LOGICAL_HEIGHT);
                let _ = window.set_size(LogicalSize::new(WINDOW_LOGICAL_WIDTH, current_h));
            }
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let runtime = window.state::<AppRuntime>();
                let close_behavior = runtime
                    .vault
                    .settings()
                    .map(|settings| settings.close_behavior)
                    .unwrap_or_else(|_| "exit".to_owned());
                if should_hide_on_close(
                    &close_behavior,
                    runtime.tray_available.load(Ordering::Acquire),
                ) {
                    api.prevent_close();
                    let _ = window.hide();
                } else {
                    runtime.vault.lock_strong();
                    runtime.session_broker.stop();
                    clipboard::clear_if_unchanged(window.app_handle(), &runtime.clipboard, None);
                    if let Err(error) =
                        crate::runtime_epoch::invalidate(runtime.vault.data_dir())
                    {
                        eprintln!("OpenKeylet: failed to stop MCP sessions: {error:#}");
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            owner_status,
            owner_touch,
            owner_set_pin,
            owner_disable_pin,
            owner_unlock,
            owner_lock,
            owner_change_master_passphrase,
            owner_secret_view,
            owner_editor_drafts,
            save_editor_draft,
            delete_editor_draft,
            copy_owner_value,
            copy_totp_code,
            save_connection,
            reorder_connections,
            set_connection_enabled,
            delete_connection,
            owner_trash,
            owner_restore_item,
            owner_purge_item,
            owner_password_history,
            owner_clear_password_history,
            test_connection,
            update_settings,
            system_integration_status,
            set_desktop_shortcut,
            set_launch_at_login,
            clear_activities,
            copy_mcp_config,
            agent_mcp_status,
            agent_mcp_register,
            agent_mcp_repair,
            agent_mcp_remove,
            choose_private_key,
            list_chrome_profiles,
            quick_pair_browser,
            open_chrome_browser,
            test_browser_bridge,
            reload_browser_extension,
            reset_browser_pairing,
            open_browser_extension_folder,
            drag_browser_extension,
            export_backup,
            generate_password,
            import_backup,
            pick_backup_import_file,
            inspect_dropped_backup_bytes,
            prepare_backup_import,
            commit_backup_import,
            cancel_backup_import,
            prepare_import,
            prepare_ssh_config_import,
            smart_parse_text,
            smart_extract_batch,
            smart_extract_dropped_binary,
            smart_pick_and_extract_files,
            smart_scan_local_dev_configs,
            commit_smart_batch,
            undo_smart_batch,
            read_owner_clipboard,
            clear_clipboard_if_matches,
            attach_totp_to_item,
            commit_import,
            cancel_import,
            github_backup_status,
            github_backup_account,
            github_backup_generate_key,
            github_backup_recovery_key,
            github_backup_connect,
            github_backup_upload,
            github_backup_restore,
            github_backup_sync,
            github_backup_set_auto_sync,
            github_backup_disconnect,
            github_backup_help,
            update_status,
            update_check,
            update_download,
            update_install_and_restart,
            update_skip_version,
            update_open_release_page,
            open_data_folder,
            window_action,
            start_vertical_resize,
            set_edge_dock_enabled,
            edge_dock_expand,
            edge_dock_hover,
        ])
        .build(context)
        .context("OpenKeylet GUI startup failed")?;

    #[cfg(target_os = "macos")]
    app.run(|app, event| {
        if let tauri::RunEvent::Reopen { .. } = event {
            show_main_window(app);
        }
    });

    #[cfg(not(target_os = "macos"))]
    app.run(|app, event| {
        // A hidden development launcher can pass its initial show state to the
        // child process. Explicitly show the GUI once its event loop is ready.
        if matches!(event, tauri::RunEvent::Ready) {
            show_main_window(app);
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        OwnerSession, is_valid_chrome_profile_dir, parse_chrome_profiles_from_local_state,
        scrub_locked_app_state, should_hide_on_close,
    };
    use crate::{
        model::{BrowserBridgeState, ConnectionInput, NewActivity, SettingsPatch},
        vault::Vault,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn close_only_hides_when_a_tray_entry_exists() {
        assert!(should_hide_on_close("tray", true));
        assert!(!should_hide_on_close("tray", false));
        assert!(!should_hide_on_close("exit", true));
    }

    #[test]
    fn owner_session_auto_locks_after_idle_timeout_and_resets_on_touch() {
        let base = Instant::now();
        let mut session = OwnerSession::default();
        session.unlock(base);

        // auto_lock_minutes == 0 stays unlocked indefinitely.
        assert_eq!(
            session.is_unlocked_at(base + Duration::from_secs(86_400), 0),
            (true, 0, false)
        );

        // With 5-minute auto-lock, touching at 4m extends the deadline by another 5m.
        let at_4m = base + Duration::from_secs(240);
        assert_eq!(session.is_unlocked_at(at_4m, 5), (true, 60, false));
        session.touch(at_4m);
        assert_eq!(
            session.is_unlocked_at(at_4m + Duration::from_secs(200), 5),
            (true, 100, false)
        );

        // After 5 minutes without activity, session transitions to locked.
        assert_eq!(
            session.is_unlocked_at(at_4m + Duration::from_secs(300), 5),
            (false, 0, true)
        );
        assert_eq!(
            session.is_unlocked_at(at_4m + Duration::from_secs(301), 5),
            (false, 0, false)
        );
    }

    #[test]
    fn owner_session_applies_lightweight_progressive_pin_cooldown_and_clears_on_unlock() {
        let base = Instant::now();
        let mut session = OwnerSession::default();

        assert_eq!(session.record_failed_attempt(base), 0);
        assert_eq!(session.record_failed_attempt(base), 0);
        assert!(session.cooldown_remaining(base).is_none());

        assert_eq!(session.record_failed_attempt(base), 2);
        assert_eq!(session.cooldown_remaining(base), Some(2));
        assert!(session.cooldown_remaining(base + Duration::from_secs(2)).is_none());

        let after_wait = base + Duration::from_secs(3);
        assert_eq!(session.record_failed_attempt(after_wait), 5);
        assert_eq!(session.record_failed_attempt(after_wait), 15);
        assert_eq!(session.record_failed_attempt(after_wait), 15);
        assert_eq!(session.record_failed_attempt(after_wait), 30);

        session.unlock(after_wait + Duration::from_secs(31));
        assert!(session.cooldown_remaining(after_wait + Duration::from_secs(31)).is_none());
        assert_eq!(
            session.record_failed_attempt(after_wait + Duration::from_secs(32)),
            0
        );
    }

    #[test]
    fn locked_app_state_scrubs_items_and_activities_but_preserves_settings() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path().to_path_buf()).unwrap();
        vault
            .update_settings_patch(SettingsPatch {
                language: Some("zh".to_owned()),
                owner_auto_lock_minutes: Some(15),
                ..SettingsPatch::default()
            })
            .unwrap();
        let input: ConnectionInput = serde_json::from_value(serde_json::json!({
            "name": "SensitiveProd",
            "modules": [
                { "kind": "username", "value": "alice" },
                { "kind": "password", "value": "super-secret" }
            ]
        }))
        .unwrap();
        vault.save_connection(input).unwrap();
        vault
            .add_activity(NewActivity {
                status: "success".to_owned(),
                source: "MCP".to_owned(),
                connection_name: "SensitiveProd".to_owned(),
                action: "ssh_run".to_owned(),
                duration_ms: 10,
                error: String::new(),
            })
            .unwrap();

        let state = vault
            .app_state(
                "openkeylet",
                BrowserBridgeState {
                    status: "off".to_owned(),
                    app_version: env!("CARGO_PKG_VERSION").to_owned(),
                    ..BrowserBridgeState::default()
                },
            )
            .unwrap();
        assert_eq!(state.connections.len(), 1);
        assert_eq!(state.activities.len(), 1);

        let scrubbed = scrub_locked_app_state(state);
        assert!(scrubbed.connections.is_empty());
        assert!(scrubbed.activities.is_empty());
        assert_eq!(scrubbed.settings.language, "zh");
        assert_eq!(scrubbed.settings.owner_auto_lock_minutes, 15);
    }

    #[test]
    fn chrome_profile_parser_filters_invalid_and_sorts_last_used_first() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("Default")).unwrap();
        std::fs::create_dir(dir.path().join("Profile 1")).unwrap();
        std::fs::create_dir(dir.path().join("System Profile")).unwrap();
        let raw = r#"{
            "profile": {
                "last_used": "Profile 1",
                "info_cache": {
                    "Default": { "name": "Personal", "user_name": "me@example.com" },
                    "Profile 1": { "name": "Work", "user_name": "work@example.com" },
                    "Profile 2": { "name": "Missing On Disk" },
                    "System Profile": { "name": "System" },
                    "../evil": { "name": "Traversal" }
                }
            }
        }"#;
        let profiles = parse_chrome_profiles_from_local_state(dir.path(), raw);
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].directory, "Profile 1");
        assert_eq!(profiles[0].name, "Work");
        assert_eq!(profiles[0].account, "work@example.com");
        assert!(profiles[0].is_last_used);
        assert_eq!(profiles[1].directory, "Default");
        assert_eq!(profiles[1].name, "Personal");
        assert!(!is_valid_chrome_profile_dir("--evil"));
        assert!(!is_valid_chrome_profile_dir("../Profile 1"));
        assert!(!is_valid_chrome_profile_dir("System Profile"));
    }
}
