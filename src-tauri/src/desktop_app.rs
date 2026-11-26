use crate::{
    agents::{AgentActionResult, AgentClientStatus, AgentRegistry},
    backup,
    browser::BrowserBridge,
    clipboard::{self, ClipboardGuard, SENSITIVE_CLIPBOARD_TTL_SECS},
    cloud_sync::{self as github_backup, BackupStatus, ConnectInput, GithubBackup, RestoreResult, SyncResult},
    edge_dock::EdgeDockController,
    exec,
    gui_instance::GuiInstance,
    mcp,
    model::{
        AppState, ConnectionInput, ImportSummary, NewActivity, OwnerEditorDraft, OwnerLockState,
        OwnerSecretView, PublicConnection, SettingsPatch,
    },
    storage::app_data_dir,
    tray_menu::{self, TRAY_ID, TRAY_MENU_LABEL, TrayActionResult, TrayMenuController, TrayMenuState},
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
#[cfg(not(target_os = "linux"))]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
use tauri::{
    AppHandle, Emitter, LogicalSize, Manager, State, WebviewWindow, tray::TrayIconBuilder,
};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;
use tokio::sync::Mutex;
use uuid::Uuid;

mod chrome_profiles;
mod cmd_import;
mod cmd_integrations;
mod cmd_vault;
mod cmd_window;
mod runtime;

#[allow(unused_imports)]
use chrome_profiles::*;
#[allow(unused_imports)]
use cmd_import::*;
#[allow(unused_imports)]
use cmd_integrations::*;
#[allow(unused_imports)]
use cmd_vault::*;
#[allow(unused_imports)]
use cmd_window::*;
use runtime::*;

fn install_tray(app: &tauri::App) -> Result<()> {
    #[cfg(target_os = "macos")]
    let icon = tauri::include_image!("icons/tray-macos.png");
    #[cfg(not(target_os = "macos"))]
    let (icon, initial_panel_dark) = {
        let dark = tray_menu::panel_is_dark();
        (tray_menu::tray_icon_for_panel(dark), dark)
    };

    let runtime = app.state::<AppRuntime>();
    #[cfg(not(target_os = "macos"))]
    let _ = runtime
        .tray_menu
        .update_cached_panel_dark(initial_panel_dark);
    let initial_settings = runtime.vault.settings().unwrap_or_default();
    let initial_resolved_lang = runtime
        .tray_menu
        .resolve_language(&initial_settings.language);
    let initial_pin = runtime.vault.owner_pin_configured().unwrap_or(false);
    let initial_unlocked = !initial_pin;
    let initial_state = TrayMenuState {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        language: initial_settings.language,
        resolved_language: initial_resolved_lang,
        theme: runtime.tray_menu.current_theme(),
        unlocked: initial_unlocked,
        pin_configured: initial_pin,
        item_count: None,
        main_visible: true,
        browser_enabled: initial_settings.browser_enabled,
        browser_status: if initial_settings.browser_enabled {
            "listening".to_owned()
        } else {
            "off".to_owned()
        },
        browser_connected: false,
        edge_dock_enabled: runtime.edge_dock.is_enabled(),
        update_available: false,
        latest_version: None,
        platform: tray_menu::platform_name().to_owned(),
    };
    let initial_tooltip = tray_menu::format_tooltip(&initial_state);
    let _ = runtime.tray_menu.update_cached_tooltip(&initial_tooltip);

    let builder = TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .icon_as_template(cfg!(target_os = "macos"))
        .tooltip(initial_tooltip)
        .show_menu_on_left_click(false);

    #[cfg(target_os = "linux")]
    let builder = {
        let menu = tray_menu::build_native_linux_menu(app.handle(), &initial_state)?;
        let _ = runtime.tray_menu.should_rebuild_linux_menu(&initial_state);
        builder
            .menu(&menu)
            .temp_dir_path(
                app.path()
                    .app_cache_dir()?
                    .join("tray")
                    .join(std::process::id().to_string()),
            )
            .on_menu_event(|app, event| {
                let id = event.id().as_ref().to_owned();
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(error) = execute_tray_action(&handle, &id).await {
                        eprintln!("OpenKeylet: tray menu action '{id}' failed: {error}");
                    }
                });
            })
    };

    #[cfg(not(target_os = "linux"))]
    let builder = builder.on_tray_icon_event(|tray, event| match event {
        TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        }
        | TrayIconEvent::DoubleClick {
            button: MouseButton::Left,
            ..
        } => {
            show_main_window(tray.app_handle());
        }
        TrayIconEvent::Click {
            button: MouseButton::Right,
            button_state: MouseButtonState::Up,
            position,
            rect,
            ..
        } => {
            let handle = tray.app_handle().clone();
            let scale = handle
                .get_webview_window(TRAY_MENU_LABEL)
                .or_else(|| handle.get_webview_window("main"))
                .and_then(|win| win.scale_factor().ok())
                .unwrap_or(1.0);
            let anchor = tray_menu::anchor_from_event(position, rect, scale);
            tauri::async_runtime::spawn(async move {
                let runtime = handle.state::<AppRuntime>();
                let state = collect_tray_menu_state(&handle, &runtime).await;
                tray_menu::toggle_custom_tray_menu(&handle, &runtime.tray_menu, anchor, &state);
            });
        }
        _ => {}
    });

    let tray = builder.build(app)?;
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
    {
        let _ = tray;
        // Pre-warm the hidden custom tray popover after initial paint so right-clicking
        // the taskbar/menu-bar icon opens instantaneously with zero blank flash.
        let handle = app.handle().clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_millis(450)).await;
            if let Some(runtime) = handle.try_state::<AppRuntime>() {
                let _ = tray_menu::ensure_tray_window(&handle, &runtime.tray_menu);
            }
        });
    }
    Ok(())
}

fn request_rounded_corners(window: &WebviewWindow) -> Result<()> {
    crate::platform::apply_native_rounded_corners(window)
}

pub fn run_gui() -> Result<()> {
    let context = tauri::generate_context!();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let context = {
        let mut context = context;
        let main = context
            .config_mut()
            .app
            .windows
            .iter_mut()
            .find(|window| window.label == "main")
            .context("Main window configuration not found")?;
        // Both the native window surface and WebKit backing must be transparent;
        // an opaque native background fills the CSS-rounded corners back in.
        main.transparent = true;
        main.background_color = Some(tauri::window::Color(0, 0, 0, 0));
        context
    };
    let data_dir = app_data_dir()?;
    if let Ok(executable) = crate::platform::launcher_executable() {
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
        crate::system_integration::ensure_application_entry(&crate::platform::launcher_executable()?)
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
            let executable = crate::platform::launcher_executable()?.to_string_lossy().into_owned();
            if let Err(error) = crate::system_integration::migrate_legacy_entries(Path::new(&executable)) {
                eprintln!("OpenKeylet: failed to migrate legacy system shortcuts: {error:#}");
            }
            let bridge_handle = app.handle().clone();
            let browser = BrowserBridge::with_on_change(vault.clone(), move || {
                emit_changed(&bridge_handle);
            });
            let agent_registry = AgentRegistry::new(PathBuf::from(&executable))?;
            agent_registry.refresh_managed_instructions();
            let updater = Arc::new(UpdateManager::new(
                vault.clone(),
                PathBuf::from(&executable),
            ));
            let edge_dock = Arc::new(EdgeDockController::new());
            edge_dock.spawn_monitor(app.handle().clone());
            let tray_menu = Arc::new(TrayMenuController::new());
            app.manage(AppRuntime {
                _gui_instance: gui_instance,
                github_backup: Mutex::new(GithubBackup::new(vault.clone())?),
                updater,
                edge_dock,
                tray_menu,
                vault,
                executable,
                browser,
                clipboard: Arc::new(ClipboardGuard::new()),
                pending_private_key: Mutex::new(None),
                pending_import: Mutex::new(None),
                pending_backup_source: Mutex::new(None),
                pending_backup_import: Mutex::new(None),
                backup_import_generation: AtomicU64::new(0),
                backup_prepare_in_flight: Arc::new(AtomicBool::new(false)),
                pending_history_restore: Mutex::new(None),
                discovered_mvault_paths: Mutex::new(Vec::new()),
                import_sources: Mutex::new(Default::default()),
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
                    let runtime = handle.state::<AppRuntime>();
                    runtime.browser.sync().await;
                    let theme = runtime.tray_menu.current_theme();
                    let lang_setting = runtime
                        .vault
                        .settings()
                        .map(|s| s.language)
                        .unwrap_or_else(|_| "auto".to_owned());
                    let lang = runtime.tray_menu.resolve_language(&lang_setting);
                    runtime
                        .browser
                        .sync_appearance(Some(theme), Some(lang))
                        .await;
                    emit_changed(&handle);
                });
            }
            schedule_auto_sync(app.handle(), 1500);
            schedule_auto_update_check(app.handle(), 3500);
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() == TRAY_MENU_LABEL {
                match event {
                    tauri::WindowEvent::Focused(false) => {
                        if let Some(runtime) = window.try_state::<AppRuntime>() {
                            tray_menu::hide_tray_menu(
                                window.app_handle(),
                                &runtime.tray_menu,
                                true,
                            );
                        }
                    }
                    tauri::WindowEvent::CloseRequested { api, .. } => {
                        api.prevent_close();
                        if let Some(runtime) = window.try_state::<AppRuntime>() {
                            tray_menu::hide_tray_menu(
                                window.app_handle(),
                                &runtime.tray_menu,
                                false,
                            );
                        }
                    }
                    _ => {}
                }
                return;
            }
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

                                let paths_for_extract = dropped_paths.clone();
                                let mut outcome = match tokio::task::spawn_blocking(move || {
                                    crate::extract::extract_from_paths(&paths_for_extract, &existing)
                                })
                                .await
                                {
                                    Ok(o) => o,
                                    Err(error) => {
                                        let _ = handle.emit(
                                            "native-files-dropped",
                                            serde_json::json!({ "error": error.to_string() }),
                                        );
                                        return;
                                    }
                                };
                                cmd_import::remember_import_sources(
                                    &runtime,
                                    &mut outcome.batch,
                                    &mut outcome.images,
                                )
                                .await;
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
                                    let path_for_inspect = mvault_path.clone();
                                    let inspect_res = tokio::task::spawn_blocking(move || {
                                        crate::migration::inspect_vault_package_file(&path_for_inspect)
                                    })
                                    .await
                                    .map_err(|e| anyhow::anyhow!("{e}"))
                                    .and_then(|r| r);
                                    match inspect_res {
                                        Ok(info) => {
                                            runtime
                                                .backup_import_generation
                                                .fetch_add(1, Ordering::AcqRel);
                                            *runtime.pending_backup_import.lock().await = None;
                                            *runtime.pending_backup_source.lock().await =
                                                Some(PendingBackupSource::Path {
                                                    path: mvault_path.clone(),
                                                    kind: info.package_kind,
                                                });
                                            let _ = win.set_focus();
                                            let _ = handle.emit(
                                                "mvault-file-dropped",
                                                serde_json::json!({
                                                    "fileName": info.file_name,
                                                    "requiresPassword": info.requires_password,
                                                    "packageKind": info.package_kind.as_str(),
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
            if matches!(event, tauri::WindowEvent::ThemeChanged(_)) {
                schedule_tray_refresh(window.app_handle());
            }
            if matches!(event, tauri::WindowEvent::Moved(_)) {
                window.state::<AppRuntime>().edge_dock.on_window_moved();
            }
            if let tauri::WindowEvent::Resized(size) = event
                && size.width > 0
                && size.height > 0
                && !window.is_minimized().unwrap_or(false)
            {
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
                    schedule_tray_refresh(window.app_handle());
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
            cmd_vault::get_state,
            cmd_vault::owner_status,
            cmd_vault::owner_touch,
            cmd_vault::owner_set_pin,
            cmd_vault::owner_disable_pin,
            cmd_vault::owner_unlock,
            cmd_vault::owner_lock,
            cmd_vault::owner_secret_view,
            cmd_vault::owner_editor_drafts,
            cmd_vault::save_editor_draft,
            cmd_vault::delete_editor_draft,
            cmd_vault::copy_owner_value,
            cmd_vault::copy_totp_code,
            cmd_vault::save_connection,
            cmd_vault::reorder_connections,
            cmd_vault::set_connection_enabled,
            cmd_vault::delete_connection,
            cmd_vault::owner_trash,
            cmd_vault::owner_restore_item,
            cmd_vault::owner_purge_item,
            cmd_vault::owner_password_history,
            cmd_vault::owner_clear_password_history,
            cmd_vault::owner_add_agent_note,
            cmd_vault::owner_update_agent_note,
            cmd_vault::owner_delete_agent_note,
            cmd_vault::owner_clear_agent_notes,
            cmd_vault::owner_set_agent_notes_locked,
            cmd_vault::test_connection,
            cmd_integrations::update_settings,
            cmd_integrations::system_integration_status,
            cmd_integrations::set_desktop_shortcut,
            cmd_integrations::set_launch_at_login,
            cmd_integrations::delete_activity,
            cmd_integrations::delete_activities,
            cmd_integrations::clear_activities,
            cmd_integrations::copy_mcp_config,
            cmd_integrations::agent_mcp_status,
            cmd_integrations::agent_mcp_register,
            cmd_integrations::agent_mcp_repair,
            cmd_integrations::agent_mcp_remove,
            cmd_integrations::choose_private_key,
            chrome_profiles::list_chrome_profiles,
            cmd_integrations::quick_pair_browser,
            cmd_integrations::open_chrome_browser,
            cmd_integrations::test_browser_bridge,
            cmd_integrations::reload_browser_extension,
            cmd_integrations::reset_browser_pairing,
            cmd_integrations::open_browser_extension_folder,
            cmd_integrations::drag_browser_extension,
            cmd_import::export_backup,
            cmd_import::generate_password,
            cmd_import::pick_backup_import_file,
            cmd_import::inspect_dropped_backup_bytes,
            cmd_import::prepare_backup_import,
            cmd_import::commit_backup_import,
            cmd_import::cancel_backup_import,
            cmd_import::prepare_import,
            cmd_import::prepare_ssh_config_import,
            cmd_import::smart_parse_text,
            cmd_import::smart_extract_batch,
            cmd_import::smart_extract_dropped_binary,
            cmd_import::smart_pick_and_extract_files,
            cmd_import::smart_scan_local_dev_configs,
            cmd_import::smart_scan_workspace_folder,
            cmd_import::open_discovered_mvault,
            cmd_import::commit_smart_batch,
            cmd_import::undo_smart_batch,
            cmd_import::read_owner_clipboard,
            cmd_import::clear_clipboard_if_matches,
            cmd_import::attach_totp_to_item,
            cmd_import::commit_import,
            cmd_import::cancel_import,
            cmd_integrations::github_backup_status,
            cmd_integrations::github_backup_account,
            cmd_integrations::github_backup_recovery_key,
            cmd_integrations::github_backup_connect,
            cmd_integrations::github_backup_upload,
            cmd_integrations::github_backup_restore,
            cmd_integrations::github_backup_sync,
            cmd_integrations::github_backup_set_auto_sync,
            cmd_integrations::github_backup_disconnect,
            cmd_integrations::github_backup_help,
            cmd_integrations::github_backup_history,
            cmd_integrations::github_backup_history_prepare,
            cmd_integrations::github_backup_history_commit,
            cmd_integrations::github_backup_history_cancel,
            cmd_integrations::update_status,
            cmd_integrations::update_check,
            cmd_integrations::update_install_and_restart,
            cmd_integrations::update_skip_version,
            cmd_integrations::update_open_release_page,
            cmd_window::open_data_folder,
            cmd_window::window_action,
            cmd_window::start_vertical_resize,
            cmd_window::set_edge_dock_enabled,
            cmd_window::edge_dock_expand,
            cmd_window::edge_dock_hover,
            cmd_window::tray_menu_state,
            cmd_window::tray_menu_action,
            cmd_window::tray_menu_resize,
            cmd_window::tray_menu_hide,
            cmd_window::sync_appearance_theme,
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
mod tests;
