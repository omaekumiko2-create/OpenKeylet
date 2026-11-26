use super::*;

#[tauri::command]
pub(crate) async fn open_data_folder(app: AppHandle, runtime: State<'_, AppRuntime>) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    app.opener()
        .open_path(runtime.vault.data_dir().to_string_lossy(), None::<&str>)
        .map_err(command_error)
}

#[tauri::command]
pub(crate) async fn window_action(
    window: WebviewWindow,
    runtime: State<'_, AppRuntime>,
    action: String,
) -> Result<(), String> {
    match action.as_str() {
        "minimize" => {
            window.minimize().map_err(command_error)?;
            schedule_tray_refresh(window.app_handle());
            Ok(())
        }
        "close" => {
            let tray_available = runtime.tray_available.load(Ordering::Acquire);
            if !tray_available {
                perform_clean_quit(window.app_handle());
                return Ok(());
            }
            let close_behavior = runtime
                .vault
                .settings()
                .map_err(command_error)?
                .close_behavior;
            if !should_hide_on_close(&close_behavior, tray_available) {
                perform_clean_quit(window.app_handle());
                Ok(())
            } else {
                window.hide().map_err(command_error)?;
                schedule_tray_refresh(window.app_handle());
                Ok(())
            }
        }
        _ => Err("Unknown window operation".to_owned()),
    }
}

#[tauri::command]
pub(crate) async fn start_vertical_resize(window: WebviewWindow, direction: String) -> Result<bool, String> {
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
        Ok(true)
    }
    #[cfg(not(windows))]
    {
        let _ = (window, is_north);
        Ok(false)
    }
}

#[tauri::command]
pub(crate) async fn set_edge_dock_enabled(
    window: WebviewWindow,
    runtime: State<'_, AppRuntime>,
    enabled: bool,
) -> Result<(), String> {
    runtime.edge_dock.set_enabled(&window, enabled).await;
    schedule_tray_refresh(window.app_handle());
    Ok(())
}

#[tauri::command]
pub(crate) async fn edge_dock_expand(
    window: WebviewWindow,
    runtime: State<'_, AppRuntime>,
) -> Result<(), String> {
    runtime.edge_dock.expand(&window).await;
    Ok(())
}

#[tauri::command]
pub(crate) async fn edge_dock_hover(
    window: WebviewWindow,
    runtime: State<'_, AppRuntime>,
    entered: bool,
) -> Result<(), String> {
    runtime.edge_dock.on_frontend_hover(&window, entered).await;
    Ok(())
}

pub(crate) fn should_hide_on_close(close_behavior: &str, tray_available: bool) -> bool {
    tray_available && !close_behavior.eq_ignore_ascii_case("exit")
}

pub(crate) fn perform_clean_quit(app: &AppHandle) {
    if let Some(runtime) = app.try_state::<AppRuntime>() {
        clipboard::clear_if_unchanged(app, &runtime.clipboard, None);
        if let Err(error) = crate::runtime_epoch::invalidate(runtime.vault.data_dir()) {
            eprintln!("OpenKeylet: failed to stop MCP sessions: {error:#}");
        }
    }
    app.exit(0);
}

pub(crate) fn main_window_is_visible(app: &AppHandle) -> bool {
    let Some(window) = app.get_webview_window("main") else {
        return false;
    };
    let visible = window.is_visible().unwrap_or(false);
    let minimized = window.is_minimized().unwrap_or(false);
    let collapsed = app
        .try_state::<AppRuntime>()
        .is_some_and(|runtime| runtime.edge_dock.is_collapsed());
    visible && !minimized && !collapsed
}

pub(crate) fn show_main_window(app: &AppHandle) {
    if let Some(runtime) = app.try_state::<AppRuntime>() {
        tray_menu::hide_tray_menu(app, &runtime.tray_menu, false);
    }
    #[cfg(target_os = "macos")]
    let _ = app.show();
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        if let Some(runtime) = app.try_state::<AppRuntime>() {
            let edge_dock = Arc::clone(&runtime.edge_dock);
            let expand_window = window.clone();
            tauri::async_runtime::spawn(async move {
                edge_dock.expand(&expand_window).await;
            });
        }
        let _ = window.set_focus();
    }
    schedule_tray_refresh(app);
}

pub(crate) fn hide_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
    schedule_tray_refresh(app);
}

pub(crate) async fn collect_tray_menu_state(app: &AppHandle, runtime: &AppRuntime) -> TrayMenuState {
    let lock = owner_lock_state(runtime).await.unwrap_or(OwnerLockState {
        pin_configured: true,
        unlocked: false,
        expires_in_seconds: 0,
        mode: "pin".to_owned(),
    });
    let settings = runtime.vault.settings().unwrap_or_default();
    let browser = runtime.browser.status().await;
    let update = runtime.updater.status().await;
    let item_count = if lock.unlocked {
        runtime.vault.list_connections().ok().map(|items| items.len())
    } else {
        None
    };
    let active_update_phase = matches!(
        update.phase.as_str(),
        "available" | "downloading" | "verifying" | "ready" | "applying"
    );
    let skipped = update
        .latest_version
        .as_deref()
        .is_some_and(|ver| !ver.is_empty() && ver == update.skipped_version)
        && matches!(update.phase.as_str(), "available");
    let update_available = active_update_phase && update.latest_version.is_some() && !skipped;
    let resolved_language = runtime.tray_menu.resolve_language(&settings.language);
    let version = if update.current_version.is_empty() {
        env!("CARGO_PKG_VERSION").to_owned()
    } else {
        update.current_version
    };

    TrayMenuState {
        version,
        language: settings.language,
        resolved_language,
        theme: runtime.tray_menu.current_theme(),
        unlocked: lock.unlocked,
        pin_configured: lock.pin_configured,
        item_count,
        main_visible: main_window_is_visible(app),
        browser_enabled: settings.browser_enabled,
        browser_status: browser.status,
        browser_connected: browser.connected,
        edge_dock_enabled: runtime.edge_dock.is_enabled(),
        update_available,
        latest_version: if update_available {
            update.latest_version
        } else {
            None
        },
        platform: tray_menu::platform_name().to_owned(),
    }
}

pub(crate) fn schedule_tray_refresh(app: &AppHandle) {
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let Some(runtime) = handle.try_state::<AppRuntime>() else {
            return;
        };
        let state = collect_tray_menu_state(&handle, &runtime).await;
        tray_menu::sync_tray_surface(&handle, &runtime.tray_menu, &state);
    });
}

pub(crate) async fn execute_tray_action(app: &AppHandle, action: &str) -> Result<TrayActionResult, String> {
    let runtime = app.state::<AppRuntime>();
    match action {
        "show-main" | "tray-open" => {
            show_main_window(app);
            Ok(TrayActionResult::done())
        }
        "toggle-main" | "tray-toggle-main" => {
            if main_window_is_visible(app) && runtime.tray_available.load(Ordering::Acquire) {
                tray_menu::hide_tray_menu(app, &runtime.tray_menu, false);
                hide_main_window(app);
            } else {
                show_main_window(app);
            }
            Ok(TrayActionResult::done())
        }
        "new-item" | "tray-new-item" => {
            show_main_window(app);
            let _ = app.emit("tray-command", serde_json::json!({ "action": "new-item" }));
            Ok(TrayActionResult::done())
        }
        "smart-import" | "tray-smart-import" => {
            show_main_window(app);
            let _ = app.emit(
                "tray-command",
                serde_json::json!({ "action": "smart-import" }),
            );
            Ok(TrayActionResult::done())
        }
        "generate-password" | "tray-generate-password" => {
            require_owner_unlocked(&runtime).await?;
            let generated = zeroize::Zeroizing::new(
                crate::generator::password(&crate::generator::Options {
                    length: 24,
                    uppercase: true,
                    lowercase: true,
                    digits: true,
                    symbols: true,
                })
                .map_err(command_error)?,
            );
            clipboard::write_text(
                app,
                &runtime.clipboard,
                &generated,
                true,
                SENSITIVE_CLIPBOARD_TTL_SECS,
            )
            .map_err(command_error)?;
            Ok(TrayActionResult::stay(
                Some("password-copied"),
                Some(SENSITIVE_CLIPBOARD_TTL_SECS),
            ))
        }
        "toggle-browser-bridge" | "tray-toggle-browser-bridge" => {
            require_owner_unlocked(&runtime).await?;
            let current = runtime
                .vault
                .settings()
                .map_err(command_error)?
                .browser_enabled;
            let next_enabled = !current;
            let settings = runtime
                .vault
                .update_settings_patch(SettingsPatch {
                    browser_enabled: Some(next_enabled),
                    ..Default::default()
                })
                .map_err(command_error)?;
            runtime.browser.sync().await;
            if next_enabled && settings.browser_enabled {
                let _ = runtime.browser.start_quick_pairing().await;
            }
            emit_changed(app);
            Ok(TrayActionResult::stay(None, None))
        }
        "toggle-edge-dock" | "tray-toggle-edge-dock" => {
            let next_enabled = !runtime.edge_dock.is_enabled();
            if let Some(window) = app.get_webview_window("main") {
                runtime.edge_dock.set_enabled(&window, next_enabled).await;
            }
            let _ = app.emit("edge-dock-preference-changed", next_enabled);
            schedule_tray_refresh(app);
            Ok(TrayActionResult::stay(None, None))
        }
        "open-settings" | "tray-open-settings" => {
            show_main_window(app);
            let _ = app.emit("tray-command", serde_json::json!({ "action": "settings" }));
            Ok(TrayActionResult::done())
        }
        "open-update" | "tray-open-update" => {
            show_main_window(app);
            let _ = app.emit("tray-command", serde_json::json!({ "action": "update" }));
            Ok(TrayActionResult::done())
        }
        "lock-or-unlock" | "tray-lock" | "tray-lock-or-unlock" => {
            let lock = owner_lock_state(&runtime).await?;
            if !lock.unlocked {
                show_main_window(app);
                return Ok(TrayActionResult::done());
            }
            if !lock.pin_configured {
                show_main_window(app);
                let _ = app.emit("pin-setup-requested", ());
                return Ok(TrayActionResult::done());
            }
            runtime.owner_session.lock().await.lock();
            runtime.clear_pending_imports().await;
            runtime.discovered_mvault_paths.lock().await.clear();
            clipboard::clear_if_unchanged(app, &runtime.clipboard, None);
            tray_menu::hide_tray_menu(app, &runtime.tray_menu, false);
            emit_changed(app);
            Ok(TrayActionResult::done())
        }
        "quit" | "tray-quit" => {
            tray_menu::hide_tray_menu(app, &runtime.tray_menu, false);
            perform_clean_quit(app);
            Ok(TrayActionResult::done())
        }
        _ => Err("Unknown tray action".to_owned()),
    }
}

#[tauri::command]
pub(crate) async fn tray_menu_state(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<TrayMenuState, String> {
    Ok(collect_tray_menu_state(&app, &runtime).await)
}

#[tauri::command]
pub(crate) async fn tray_menu_action(app: AppHandle, action: String) -> Result<TrayActionResult, String> {
    let result = execute_tray_action(&app, &action).await?;
    if !result.keep_open
        && let Some(runtime) = app.try_state::<AppRuntime>()
    {
        tray_menu::hide_tray_menu(&app, &runtime.tray_menu, false);
    }
    Ok(result)
}

#[tauri::command]
pub(crate) async fn tray_menu_resize(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    height: f64,
) -> Result<(), String> {
    tray_menu::resize_tray_menu(&app, &runtime.tray_menu, height).map_err(command_error)
}

#[tauri::command]
pub(crate) async fn tray_menu_hide(app: AppHandle, runtime: State<'_, AppRuntime>) -> Result<(), String> {
    tray_menu::hide_tray_menu(&app, &runtime.tray_menu, false);
    Ok(())
}

#[tauri::command]
pub(crate) async fn sync_appearance_theme(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    theme: Option<String>,
    resolved_language: Option<String>,
) -> Result<(), String> {
    if let Some(ref next_theme) = theme {
        let normalized = if next_theme == "light" { "light" } else { "dark" };
        let native_theme = if normalized == "light" {
            tauri::Theme::Light
        } else {
            tauri::Theme::Dark
        };
        if let Some(main_win) = app.get_webview_window("main") {
            let _ = main_win.set_theme(Some(native_theme));
            #[cfg(windows)]
            let _ = main_win.set_background_color(Some(tray_menu::theme_background_color(normalized)));
        }
        tray_menu::set_tray_window_theme(&app, &runtime.tray_menu, normalized);
        let _ = app.emit(
            "appearance-changed",
            serde_json::json!({ "theme": normalized }),
        );
    }
    if let Some(ref locale) = resolved_language {
        runtime
            .tray_menu
            .set_appearance(None, Some(locale.as_str()));
    }
    let effective_theme = runtime.tray_menu.current_theme();
    let lang_setting = runtime
        .vault
        .settings()
        .map(|s| s.language)
        .unwrap_or_else(|_| "auto".to_owned());
    let effective_language = runtime.tray_menu.resolve_language(&lang_setting);
    let browser = runtime.browser.clone();
    tauri::async_runtime::spawn(async move {
        browser
            .sync_appearance(Some(effective_theme), Some(effective_language))
            .await;
    });
    schedule_tray_refresh(&app);
    Ok(())
}

