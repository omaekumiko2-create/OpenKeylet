use crate::{
    agent_registry::{AgentActionResult, AgentClientStatus, AgentRegistry},
    backup,
    browser::BrowserBridge,
    clipboard::{self, ClipboardGuard, SENSITIVE_CLIPBOARD_TTL_SECS},
    executor,
    github_backup::{self, BackupStatus, ConnectInput, GithubBackup, RestoreResult, SyncResult},
    gui_instance::GuiInstance,
    mcp,
    model::{
        AppState, ConnectionInput, ImportSummary, NewActivity, OwnerEditorDraft, OwnerLockState,
        OwnerSecretView, PublicConnection, SettingsPatch,
    },
    storage::app_data_dir,
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
    owner_session: Mutex<OwnerSession>,
    github_backup: Mutex<GithubBackup>,
    auto_sync_generation: AtomicU64,
    agent_registry: AgentRegistry,
    tray_available: AtomicBool,
}

struct PendingImport {
    id: String,
    created: Instant,
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

async fn owner_lock_state(runtime: &AppRuntime) -> Result<OwnerLockState, String> {
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
            pin_configured,
            unlocked: true,
            expires_in_seconds: 0,
        });
    }
    let (unlocked, expires_in_seconds, expired_now) =
        session.is_unlocked_at(Instant::now(), auto_lock_minutes);
    drop(session);
    if expired_now {
        *runtime.pending_import.lock().await = None;
    }
    Ok(OwnerLockState {
        pin_configured,
        unlocked,
        expires_in_seconds,
    })
}

async fn require_owner_unlocked(runtime: &AppRuntime) -> Result<(), String> {
    if owner_lock_state(runtime).await?.unlocked {
        runtime.owner_session.lock().await.touch(Instant::now());
        Ok(())
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

fn schedule_auto_sync(app: &AppHandle, delay_ms: u64) {
    let runtime = app.state::<AppRuntime>();
    let generation = runtime.auto_sync_generation.fetch_add(1, Ordering::AcqRel) + 1;
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
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
                let _ = handle.emit("cloud-sync-error", error.to_string());
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
    runtime.vault.set_owner_pin(&pin).map_err(command_error)?;
    keep_owner_unlocked(&runtime).await;
    owner_lock_state(&runtime).await
}

#[tauri::command]
async fn owner_disable_pin(runtime: State<'_, AppRuntime>) -> Result<OwnerLockState, String> {
    require_owner_unlocked(&runtime).await?;
    runtime.vault.disable_owner_pin().map_err(command_error)?;
    runtime.owner_session.lock().await.lock();
    owner_lock_state(&runtime).await
}

#[tauri::command]
async fn owner_unlock(
    runtime: State<'_, AppRuntime>,
    pin: String,
) -> Result<OwnerLockState, String> {
    let now = Instant::now();
    if let Some(wait_secs) = runtime.owner_session.lock().await.cooldown_remaining(now) {
        return Err(format!(
            "Too many incorrect PIN attempts; wait {wait_secs}s"
        ));
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
async fn owner_lock(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<OwnerLockState, String> {
    runtime.owner_session.lock().await.lock();
    *runtime.pending_import.lock().await = None;
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
    let settings = runtime
        .vault
        .update_settings_patch(patch)
        .map_err(command_error)?;
    runtime.browser.sync().await;
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
fn open_chrome_browser() -> Result<(), String> {
    #[cfg(windows)]
    {
        let mut candidates = Vec::new();
        for root in ["LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)"] {
            if let Some(root) = std::env::var_os(root) {
                let base = PathBuf::from(root);
                candidates.push(base.join("Google/Chrome/Application/chrome.exe"));
                candidates.push(base.join("Microsoft/Edge/Application/msedge.exe"));
                candidates.push(base.join("BraveSoftware/Brave-Browser/Application/brave.exe"));
                candidates.push(base.join("Chromium/Application/chrome.exe"));
            }
        }
        candidates.push(PathBuf::from("chrome.exe"));
        candidates.push(PathBuf::from("msedge.exe"));
        candidates.push(PathBuf::from("brave.exe"));
        if candidates.into_iter().any(|candidate| {
            (candidate.components().count() == 1 || candidate.is_file())
                && Command::new(candidate).arg("--new-tab").spawn().is_ok()
        }) {
            return Ok(());
        }
    }
    #[cfg(target_os = "macos")]
    {
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
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if [
            "google-chrome",
            "google-chrome-stable",
            "microsoft-edge",
            "brave-browser",
            "chromium",
            "chromium-browser",
        ]
        .into_iter()
        .any(|browser| Command::new(browser).arg("--new-tab").spawn().is_ok())
        {
            return Ok(());
        }
    }
    Err("Unable to open a Chromium browser; open it manually and paste the copied address".to_owned())
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
async fn open_browser_extension_folder(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
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
    runtime: State<'_, AppRuntime>,
    input: ConnectInput,
) -> Result<BackupStatus, String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .github_backup
        .lock()
        .await
        .connect(input)
        .await
        .map_err(command_error)
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
async fn github_backup_disconnect(runtime: State<'_, AppRuntime>) -> Result<BackupStatus, String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .github_backup
        .lock()
        .await
        .disconnect()
        .map_err(command_error)
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
    Ok(Some(summary))
}

#[tauri::command]
async fn prepare_import(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    format: String,
) -> Result<Option<serde_json::Value>, String> {
    require_owner_unlocked(&runtime).await?;
    *runtime.pending_import.lock().await = None;
    let extension = match format.as_str() {
        "bitwarden" => "json",
        "chrome" => "csv",
        _ => return Err("Unsupported import format".into()),
    };
    let selected = app
        .dialog()
        .file()
        .add_filter("Vault export", &[extension])
        .blocking_pick_file();
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
    Ok(summary)
}

#[tauri::command]
async fn cancel_import(runtime: State<'_, AppRuntime>) -> Result<(), String> {
    *runtime.pending_import.lock().await = None;
    Ok(())
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

fn should_hide_on_close(close_behavior: &str, tray_available: bool) -> bool {
    tray_available && !close_behavior.eq_ignore_ascii_case("exit")
}

fn show_main_window(app: &AppHandle) {
    #[cfg(target_os = "macos")]
    let _ = app.show();
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
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
                    let pin_configured = runtime.vault.owner_pin_configured();
                    runtime.owner_session.lock().await.lock();
                    *runtime.pending_import.lock().await = None;
                    clipboard::clear_if_unchanged(&handle, &runtime.clipboard, None);
                    show_main_window(&handle);
                    if matches!(pin_configured, Ok(false)) {
                        let _ = handle.emit("pin-setup-requested", ());
                    } else {
                        emit_changed(&handle);
                    }
                });
            } else if event.id() == "tray-quit" {
                let runtime = app.state::<AppRuntime>();
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
            let browser = BrowserBridge::new(vault.clone());
            let agent_registry = AgentRegistry::new(PathBuf::from(&executable))?;
            agent_registry.refresh_managed_instructions();
            app.manage(AppRuntime {
                _gui_instance: gui_instance,
                github_backup: Mutex::new(GithubBackup::new(vault.clone())?),
                vault,
                executable,
                browser,
                clipboard: Arc::new(ClipboardGuard::new()),
                pending_private_key: Mutex::new(None),
                pending_import: Mutex::new(None),
                owner_session: Mutex::new(OwnerSession::default()),
                auto_sync_generation: AtomicU64::new(0),
                agent_registry,
                tray_available: AtomicBool::new(false),
            });

            let window = app.get_webview_window("main").context("Main window not found")?;
            #[cfg(debug_assertions)]
            window.set_title("OpenKeylet · DEV")?;
            let fixed_size = LogicalSize::new(WINDOW_LOGICAL_WIDTH, WINDOW_LOGICAL_HEIGHT);
            window.set_min_size(Some(fixed_size))?;
            window.set_max_size(Some(fixed_size))?;
            window.set_size(fixed_size)?;
            window.set_resizable(false)?;
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
            Ok(())
        })
        .on_window_event(|window, event| {
            if matches!(event, tauri::WindowEvent::ScaleFactorChanged { .. }) {
                let _ = window.set_size(LogicalSize::new(
                    WINDOW_LOGICAL_WIDTH,
                    WINDOW_LOGICAL_HEIGHT,
                ));
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
            quick_pair_browser,
            open_chrome_browser,
            test_browser_bridge,
            reset_browser_pairing,
            open_browser_extension_folder,
            drag_browser_extension,
            export_backup,
            generate_password,
            import_backup,
            prepare_import,
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
            open_data_folder,
            window_action,
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
    use super::{OwnerSession, scrub_locked_app_state, should_hide_on_close};
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
                    enabled: false,
                    paired: false,
                    connected: false,
                    status: "off".to_owned(),
                    error: String::new(),
                    endpoint: String::new(),
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
}
