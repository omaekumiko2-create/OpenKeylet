use super::*;

#[cfg(windows)]
pub(super) fn apply_windows_tray_window_style(window: &WebviewWindow) {
    let _ = crate::platform::apply_native_rounded_corners(window);
}

#[cfg(windows)]
pub(super) fn bring_tray_window_foreground(window: &WebviewWindow) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::SetForegroundWindow;

    if let Ok(hwnd) = window.hwnd() {
        unsafe {
            let _ = SetForegroundWindow(HWND(hwnd.0));
        }
    }
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub(super) fn resolve_windows_taskbar_is_dark(
    override_tone: Option<&str>,
    system_uses_light_theme: Option<u32>,
    apps_use_light_theme: Option<u32>,
) -> bool {
    if let Some(raw) = override_tone {
        match raw.trim().to_ascii_lowercase().as_str() {
            "dark" => return true,
            "light" => return false,
            _ => {}
        }
    }
    if let Some(value) = system_uses_light_theme {
        return value == 0;
    }
    if let Some(value) = apps_use_light_theme {
        return value == 0;
    }
    true
}

#[cfg(windows)]
fn read_hkcu_dword(subkey: &str, value_name: &str) -> Option<u32> {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};

    let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let name_wide: Vec<u16> = value_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut data: u32 = 0;
    let mut size: u32 = size_of::<u32>() as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            windows::core::PCWSTR(subkey_wide.as_ptr()),
            windows::core::PCWSTR(name_wide.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some((&mut data as *mut u32).cast()),
            Some(&mut size),
        )
    };
    if status.is_ok() { Some(data) } else { None }
}

#[cfg(windows)]
pub fn panel_is_dark() -> bool {
    const PERSONALIZE_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
    let override_tone = std::env::var("OPENKEYLET_TRAY_TONE").ok();
    let system_light = read_hkcu_dword(PERSONALIZE_KEY, "SystemUsesLightTheme");
    let apps_light = read_hkcu_dword(PERSONALIZE_KEY, "AppsUseLightTheme");
    resolve_windows_taskbar_is_dark(override_tone.as_deref(), system_light, apps_light)
}

#[cfg(target_os = "macos")]
pub(super) fn apply_macos_tray_window_style(window: &WebviewWindow) {
    use objc2_app_kit::{NSPopUpMenuWindowLevel, NSWindow, NSWindowCollectionBehavior};

    let _ = crate::platform::apply_native_rounded_corners(window);
    let win_clone = window.clone();
    let _ = window.run_on_main_thread(move || {
        if let Ok(ptr) = win_clone.ns_window()
            && !ptr.is_null()
        {
            // SAFETY: `ns_window()` returns the valid `NSWindow` pointer owned by Tauri
            // on the AppKit main thread.
            let ns_window = unsafe { &*(ptr.cast::<NSWindow>()) };
            // Place the popover at pop-up menu level (101) so macOS Notification Center
            // banners (21) and Dock overlays (20) never cover or intercept clicks on it.
            ns_window.setLevel(NSPopUpMenuWindowLevel);
            let behavior = ns_window.collectionBehavior()
                | NSWindowCollectionBehavior::CanJoinAllSpaces
                | NSWindowCollectionBehavior::FullScreenAuxiliary
                | NSWindowCollectionBehavior::Transient
                | NSWindowCollectionBehavior::IgnoresCycle;
            ns_window.setCollectionBehavior(behavior);
        }
    });
}

/// Signals used to determine whether a Linux desktop panel (top/bottom bar) is
/// dark so the tray icon can invert between a white-background dark logo (on
/// dark panels) and a black-background white logo (on light panels).
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
#[derive(Debug, Default)]
pub(super) struct LinuxPanelSignals {
    pub override_tone: Option<String>,
    pub desktop: String,
    pub gnome_shell_theme: Option<String>,
    pub cinnamon_theme: Option<String>,
    pub xfce_theme: Option<String>,
    pub kde_plasma_theme: Option<String>,
    pub kde_color_scheme: Option<String>,
    pub gtk_theme: Option<String>,
    pub gnome_color_scheme: Option<String>,
    pub portal_color_scheme: Option<u32>,
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
fn theme_name_tone(name: &str) -> Option<bool> {
    let lower = name.trim().trim_matches('\'').trim_matches('"').to_ascii_lowercase();
    if lower.is_empty() {
        return None;
    }
    if lower.contains("dark") || lower.contains("noir") || lower.contains("black") {
        return Some(true);
    }
    if lower.contains("light") || lower.contains("white") || lower.contains("day") {
        return Some(false);
    }
    None
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
pub(super) fn resolve_linux_panel_is_dark(signals: &LinuxPanelSignals) -> bool {
    if let Some(raw) = signals.override_tone.as_deref() {
        match raw.trim().to_ascii_lowercase().as_str() {
            "dark" => return true,
            "light" => return false,
            _ => {}
        }
    }

    let desktop = signals.desktop.to_ascii_lowercase();

    // GNOME Shell (including Ubuntu GNOME) renders a dark top bar by default
    // even when applications use the light color scheme, unless a light
    // GNOME Shell user-theme is explicitly active.
    if desktop.contains("gnome") {
        if let Some(shell_theme) = signals.gnome_shell_theme.as_deref()
            && let Some(is_dark) = theme_name_tone(shell_theme)
        {
            return is_dark;
        }
        return true;
    }

    if desktop.contains("kde") || desktop.contains("plasma") {
        if let Some(plasma) = signals.kde_plasma_theme.as_deref()
            && let Some(is_dark) = theme_name_tone(plasma)
        {
            return is_dark;
        }
        if let Some(scheme) = signals.kde_color_scheme.as_deref()
            && let Some(is_dark) = theme_name_tone(scheme)
        {
            return is_dark;
        }
    }

    if desktop.contains("cinnamon")
        && let Some(theme) = signals.cinnamon_theme.as_deref()
        && let Some(is_dark) = theme_name_tone(theme)
    {
        return is_dark;
    }

    if desktop.contains("xfce")
        && let Some(theme) = signals.xfce_theme.as_deref()
        && let Some(is_dark) = theme_name_tone(theme)
    {
        return is_dark;
    }

    if let Some(gtk) = signals.gtk_theme.as_deref()
        && let Some(is_dark) = theme_name_tone(gtk)
    {
        return is_dark;
    }

    if let Some(scheme) = signals.gnome_color_scheme.as_deref() {
        let lower = scheme.trim().trim_matches('\'').to_ascii_lowercase();
        if lower.contains("dark") {
            return true;
        }
        if lower.contains("light") {
            return false;
        }
    }

    match signals.portal_color_scheme {
        Some(1) => true,
        Some(2) => false,
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn read_cmd_stdout(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() { None } else { Some(text) }
}

#[cfg(target_os = "linux")]
fn read_ini_value(path: &std::path::Path, section: &str, key: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut in_section = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_section = line[1..line.len() - 1].eq_ignore_ascii_case(section);
            continue;
        }
        if in_section
            && let Some((k, v)) = line.split_once('=')
            && k.trim().eq_ignore_ascii_case(key)
        {
            let value = v.trim();
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn parse_portal_color_scheme(raw: &str) -> Option<u32> {
    if raw.contains("uint32 1") {
        Some(1)
    } else if raw.contains("uint32 2") {
        Some(2)
    } else if raw.contains("uint32 0") {
        Some(0)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
pub fn linux_panel_is_dark() -> bool {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .or_else(|_| std::env::var("DESKTOP_SESSION"))
        .unwrap_or_default();
    let lower_desktop = desktop.to_ascii_lowercase();
    let override_tone = std::env::var("OPENKEYLET_TRAY_TONE").ok();

    let gnome_shell_theme = if lower_desktop.contains("gnome") {
        read_cmd_stdout(
            "gsettings",
            &["get", "org.gnome.shell.extensions.user-theme", "name"],
        )
    } else {
        None
    };

    let cinnamon_theme = if lower_desktop.contains("cinnamon") {
        read_cmd_stdout("gsettings", &["get", "org.cinnamon.theme", "name"])
    } else {
        None
    };

    let xfce_theme = if lower_desktop.contains("xfce") {
        read_cmd_stdout("xfconf-query", &["-c", "xsettings", "-p", "/Net/ThemeName"])
    } else {
        None
    };

    let (kde_plasma_theme, kde_color_scheme) =
        if lower_desktop.contains("kde") || lower_desktop.contains("plasma") {
            let config_dir = dirs::config_dir();
            let plasma = config_dir
                .as_deref()
                .and_then(|dir| read_ini_value(&dir.join("plasmarc"), "Theme", "name"));
            let scheme = config_dir
                .as_deref()
                .and_then(|dir| read_ini_value(&dir.join("kdeglobals"), "General", "ColorScheme"));
            (plasma, scheme)
        } else {
            (None, None)
        };

    let gtk_theme = std::env::var("GTK_THEME").ok().or_else(|| {
        if lower_desktop.contains("gnome") {
            None
        } else {
            read_cmd_stdout("gsettings", &["get", "org.gnome.desktop.interface", "gtk-theme"])
        }
    });

    let gnome_color_scheme = if lower_desktop.contains("gnome") {
        None
    } else {
        read_cmd_stdout(
            "gsettings",
            &["get", "org.gnome.desktop.interface", "color-scheme"],
        )
    };

    let portal_color_scheme = if lower_desktop.contains("gnome") {
        None
    } else {
        read_cmd_stdout(
            "gdbus",
            &[
                "call",
                "--session",
                "--dest",
                "org.freedesktop.portal.Desktop",
                "--object-path",
                "/org/freedesktop/portal/desktop",
                "--method",
                "org.freedesktop.portal.Settings.Read",
                "org.freedesktop.appearance",
                "color-scheme",
            ],
        )
        .as_deref()
        .and_then(parse_portal_color_scheme)
    };

    resolve_linux_panel_is_dark(&LinuxPanelSignals {
        override_tone,
        desktop,
        gnome_shell_theme,
        cinnamon_theme,
        xfce_theme,
        kde_plasma_theme,
        kde_color_scheme,
        gtk_theme,
        gnome_color_scheme,
        portal_color_scheme,
    })
}

#[cfg(target_os = "linux")]
pub fn panel_is_dark() -> bool {
    linux_panel_is_dark()
}

/// Pick the tray icon that contrasts cleanly with the OS taskbar/panel bar:
/// - Dark taskbar/panel -> white/porcelain background with black logo (`tray-light.png`)
/// - Light taskbar/panel -> black/carbon background with white logo (`tray.png`)
#[cfg(not(target_os = "macos"))]
pub fn tray_icon_for_panel(panel_is_dark: bool) -> tauri::image::Image<'static> {
    if panel_is_dark {
        tauri::include_image!("icons/tray-light.png")
    } else {
        tauri::include_image!("icons/tray.png")
    }
}

#[cfg(target_os = "macos")]
pub fn set_macos_status_item_highlight(app: &AppHandle, highlighted: bool) {
    use objc2_foundation::MainThreadMarker;

    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.with_inner_tray_icon(move |inner| {
            if let Some(mtm) = MainThreadMarker::new()
                && let Some(status_item) = inner.ns_status_item()
                && let Some(button) = status_item.button(mtm)
            {
                button.highlight(highlighted);
            }
        });
    }
}


#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn build_native_linux_menu(
    app: &AppHandle,
    state: &TrayMenuState,
) -> Result<tauri::menu::Menu<tauri::Wry>> {
    use tauri::menu::{CheckMenuItem, IconMenuItem, Menu, MenuItem, PredefinedMenuItem};

    let copy = tray_copy(&state.resolved_language);
    let status_text = if state.unlocked {
        match state.item_count {
            Some(count) => format!(
                "OpenKeylet v{} · {} ({} {})",
                state.version, copy.status_unlocked, count, copy.items_suffix
            ),
            None => format!("OpenKeylet v{} · {}", state.version, copy.status_unlocked),
        }
    } else {
        format!("OpenKeylet v{} · {}", state.version, copy.status_locked)
    };

    #[cfg(target_os = "linux")]
    let header_icon = tray_icon_for_panel(panel_is_dark());
    #[cfg(not(target_os = "linux"))]
    let header_icon = tauri::include_image!("icons/tray.png");

    let header = IconMenuItem::with_id(
        app,
        "tray-header",
        status_text,
        false,
        Some(header_icon),
        None::<&str>,
    )?;
    let sep0 = PredefinedMenuItem::separator(app)?;

    let toggle_label = if state.main_visible {
        copy.hide_window
    } else {
        copy.show_window
    };
    let toggle_main = MenuItem::with_id(app, "tray-toggle-main", toggle_label, true, None::<&str>)?;
    let new_item = MenuItem::with_id(app, "tray-new-item", copy.new_item, true, None::<&str>)?;
    let smart_import = MenuItem::with_id(
        app,
        "tray-smart-import",
        copy.smart_import,
        true,
        None::<&str>,
    )?;
    let gen_password = MenuItem::with_id(
        app,
        "tray-generate-password",
        copy.generate_password,
        state.unlocked,
        None::<&str>,
    )?;

    let sep1 = PredefinedMenuItem::separator(app)?;

    let bridge_label = if !state.browser_enabled {
        copy.browser_bridge.to_owned()
    } else if state.browser_connected {
        format!("{} · {}", copy.browser_bridge, copy.bridge_connected)
    } else {
        format!("{} · {}", copy.browser_bridge, copy.bridge_listening)
    };
    let browser_bridge = CheckMenuItem::with_id(
        app,
        "tray-toggle-browser-bridge",
        bridge_label,
        state.unlocked,
        state.browser_enabled,
        None::<&str>,
    )?;

    let sep2 = PredefinedMenuItem::separator(app)?;

    let settings = MenuItem::with_id(app, "tray-open-settings", copy.settings, true, None::<&str>)?;
    let lock_label = if !state.unlocked {
        copy.unlock_vault
    } else if state.pin_configured {
        copy.lock_vault
    } else {
        copy.set_pin_lock
    };
    let lock_item = MenuItem::with_id(app, "tray-lock-or-unlock", lock_label, true, None::<&str>)?;

    let sep3 = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "tray-quit", copy.quit, true, None::<&str>)?;

    let menu = Menu::new(app)?;
    menu.append(&header)?;
    if state.update_available {
        let update_text = match state.latest_version.as_deref() {
            Some(ver) => format!("↑ {} v{}", copy.update_available, ver),
            None => format!("↑ {}", copy.update_available),
        };
        let update_item =
            MenuItem::with_id(app, "tray-open-update", update_text, true, None::<&str>)?;
        menu.append(&update_item)?;
    }
    menu.append_items(&[
        &sep0,
        &toggle_main,
        &new_item,
        &smart_import,
        &gen_password,
        &sep1,
        &browser_bridge,
        &sep2,
        &settings,
        &lock_item,
        &sep3,
        &quit,
    ])?;
    Ok(menu)
}

