use anyhow::{Context, Result};
use serde::Serialize;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{
    AppHandle, Emitter, LogicalSize, Manager, PhysicalPosition, PhysicalSize, Rect, WebviewUrl,
    WebviewWindow, WebviewWindowBuilder,
};
#[allow(unused_imports)]
use tauri::window::Color;

mod copy;
mod geometry;
mod platform;

pub use copy::{TrayCopy, format_tooltip, normalize_lang, platform_name, theme_background_color, tray_copy};
pub use geometry::{anchor_from_event, compute_popup_position};
use geometry::find_monitor_for_point;
pub use platform::build_native_linux_menu;
#[cfg(not(target_os = "macos"))]
pub use platform::{panel_is_dark, tray_icon_for_panel};
#[cfg(target_os = "macos")]
pub use platform::set_macos_status_item_highlight;
#[cfg(target_os = "macos")]
use platform::apply_macos_tray_window_style;
#[cfg(windows)]
use platform::{apply_windows_tray_window_style, bring_tray_window_foreground};
use copy::detect_env_locale_opt;

pub const TRAY_ID: &str = "openkeylet-tray";
pub const TRAY_MENU_LABEL: &str = "tray-menu";
pub const TRAY_MENU_LOGICAL_WIDTH: f64 = 256.0;
pub const TRAY_MENU_DEFAULT_LOGICAL_HEIGHT: f64 = 400.0;
pub const TRAY_MENU_MIN_LOGICAL_HEIGHT: f64 = 220.0;
pub const TRAY_MENU_MAX_LOGICAL_HEIGHT: f64 = 560.0;

const BLUR_TOGGLE_DEBOUNCE: Duration = Duration::from_millis(220);
const SHOW_BLUR_GRACE: Duration = Duration::from_millis(140);

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrayMenuState {
    pub version: String,
    pub language: String,
    pub resolved_language: String,
    pub theme: String,
    pub unlocked: bool,
    pub pin_configured: bool,
    pub item_count: Option<usize>,
    pub main_visible: bool,
    pub browser_enabled: bool,
    pub browser_status: String,
    pub browser_connected: bool,
    pub edge_dock_enabled: bool,
    pub update_available: bool,
    pub latest_version: Option<String>,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrayActionResult {
    pub ok: bool,
    pub keep_open: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feedback_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

impl TrayActionResult {
    pub fn done() -> Self {
        Self {
            ok: true,
            keep_open: false,
            feedback_kind: None,
            ttl_seconds: None,
        }
    }

    pub fn stay(feedback_kind: Option<&str>, ttl_seconds: Option<u64>) -> Self {
        Self {
            ok: true,
            keep_open: true,
            feedback_kind: feedback_kind.map(str::to_owned),
            ttl_seconds,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TrayAnchor {
    pub click_x: f64,
    pub click_y: f64,
    pub icon_rect: Option<PixelRect>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PixelRect {
    pub left: f64,
    pub top: f64,
    pub width: f64,
    pub height: f64,
}

impl PixelRect {
    pub fn right(self) -> f64 {
        self.left + self.width
    }

    pub fn bottom(self) -> f64 {
        self.top + self.height
    }

    pub fn center_x(self) -> f64 {
        self.left + self.width * 0.5
    }

    pub fn contains_point(self, x: f64, y: f64) -> bool {
        x >= self.left && x <= self.right() && y >= self.top && y <= self.bottom()
    }
}

#[derive(Debug, Default)]
struct TrayMenuInner {
    last_anchor: Option<TrayAnchor>,
    last_blur_hide: Option<Instant>,
    last_shown_at: Option<Instant>,
    logical_height: f64,
    theme: String,
    detected_locale: Option<String>,
    last_tooltip: Option<String>,
    #[cfg(target_os = "linux")]
    last_linux_state: Option<TrayMenuState>,
    #[cfg(not(target_os = "macos"))]
    last_panel_dark: Option<bool>,
}

pub struct TrayMenuController {
    inner: Mutex<TrayMenuInner>,
}

impl Default for TrayMenuController {
    fn default() -> Self {
        Self::new()
    }
}

impl TrayMenuController {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(TrayMenuInner {
                logical_height: TRAY_MENU_DEFAULT_LOGICAL_HEIGHT,
                theme: "dark".to_owned(),
                ..Default::default()
            }),
        }
    }

    pub fn current_theme(&self) -> String {
        self.inner
            .lock()
            .map(|guard| {
                if guard.theme == "light" {
                    "light".to_owned()
                } else {
                    "dark".to_owned()
                }
            })
            .unwrap_or_else(|_| "dark".to_owned())
    }

    pub fn set_appearance(&self, theme: Option<&str>, resolved_locale: Option<&str>) {
        if let Ok(mut guard) = self.inner.lock() {
            if let Some(theme) = theme {
                guard.theme = if theme == "light" {
                    "light".to_owned()
                } else {
                    "dark".to_owned()
                };
            }
            if let Some(locale) = resolved_locale
                && !locale.trim().is_empty()
            {
                guard.detected_locale = Some(normalize_lang(locale).to_owned());
            }
        }
    }

    pub fn resolve_language(&self, setting: &str) -> String {
        let lower = setting.trim().to_ascii_lowercase();
        if !lower.is_empty() && lower != "auto" && lower != "system" {
            return normalize_lang(setting).to_owned();
        }
        let detected = self
            .inner
            .lock()
            .ok()
            .and_then(|guard| guard.detected_locale.clone());
        #[cfg(target_os = "linux")]
        {
            // On Linux, POSIX locale env vars (LC_ALL / LC_MESSAGES / LANG) are
            // authoritative even when the target locale isn't compiled in glibc
            // for WebKitGTK's navigator.language fallback.
            if let Some(env_lang) = detect_env_locale_opt() {
                return env_lang.to_owned();
            }
        }
        if let Some(locale) = detected {
            return normalize_lang(&locale).to_owned();
        }
        detect_env_locale_opt().unwrap_or("en").to_owned()
    }

    pub fn set_logical_height(&self, height: f64) -> f64 {
        let clamped = height
            .clamp(TRAY_MENU_MIN_LOGICAL_HEIGHT, TRAY_MENU_MAX_LOGICAL_HEIGHT)
            .ceil();
        if let Ok(mut guard) = self.inner.lock() {
            guard.logical_height = clamped;
        }
        clamped
    }

    pub fn logical_height(&self) -> f64 {
        self.inner
            .lock()
            .map(|guard| {
                if guard.logical_height >= TRAY_MENU_MIN_LOGICAL_HEIGHT {
                    guard.logical_height
                } else {
                    TRAY_MENU_DEFAULT_LOGICAL_HEIGHT
                }
            })
            .unwrap_or(TRAY_MENU_DEFAULT_LOGICAL_HEIGHT)
    }

    pub fn set_last_anchor(&self, anchor: TrayAnchor) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.last_anchor = Some(anchor);
        }
    }

    pub fn last_anchor(&self) -> Option<TrayAnchor> {
        self.inner.lock().ok().and_then(|guard| guard.last_anchor)
    }

    pub fn was_just_hidden_by_blur(&self) -> bool {
        self.inner
            .lock()
            .ok()
            .and_then(|guard| guard.last_blur_hide)
            .is_some_and(|at| at.elapsed() <= BLUR_TOGGLE_DEBOUNCE)
    }

    pub fn mark_shown(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.last_shown_at = Some(Instant::now());
            guard.last_blur_hide = None;
        }
    }

    pub fn should_ignore_blur(&self) -> bool {
        self.inner
            .lock()
            .ok()
            .and_then(|guard| guard.last_shown_at)
            .is_some_and(|at| at.elapsed() <= SHOW_BLUR_GRACE)
    }

    pub fn mark_blur_hidden(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.last_blur_hide = Some(Instant::now());
        }
    }

    pub fn clear_blur_mark(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.last_blur_hide = None;
        }
    }

    pub fn update_cached_tooltip(&self, tooltip: &str) -> bool {
        if let Ok(mut guard) = self.inner.lock() {
            if guard.last_tooltip.as_deref() == Some(tooltip) {
                return false;
            }
            guard.last_tooltip = Some(tooltip.to_owned());
            return true;
        }
        false
    }

    #[cfg(target_os = "linux")]
    pub fn should_rebuild_linux_menu(&self, next: &TrayMenuState) -> bool {
        if let Ok(mut guard) = self.inner.lock() {
            if guard.last_linux_state.as_ref() == Some(next) {
                return false;
            }
            guard.last_linux_state = Some(next.clone());
            return true;
        }
        false
    }

    #[cfg(not(target_os = "macos"))]
    pub fn update_cached_panel_dark(&self, dark: bool) -> bool {
        if let Ok(mut guard) = self.inner.lock() {
            if guard.last_panel_dark == Some(dark) {
                return false;
            }
            guard.last_panel_dark = Some(dark);
            return true;
        }
        false
    }
}

pub fn ensure_tray_window(
    app: &AppHandle,
    controller: &TrayMenuController,
) -> Result<WebviewWindow> {
    if let Some(existing) = app.get_webview_window(TRAY_MENU_LABEL) {
        return Ok(existing);
    }

    let height = controller.logical_height();
    let current_theme = controller.current_theme();
    let native_theme = if current_theme == "light" {
        tauri::Theme::Light
    } else {
        tauri::Theme::Dark
    };
    let builder = WebviewWindowBuilder::new(
        app,
        TRAY_MENU_LABEL,
        WebviewUrl::App("tray-menu.html".into()),
    )
    .title("OpenKeylet Menu")
    .inner_size(TRAY_MENU_LOGICAL_WIDTH, height)
    .resizable(false)
    .minimizable(false)
    .maximizable(false)
    .decorations(false)
    .always_on_top(true)
    .skip_taskbar(true)
    .shadow(true)
    .theme(Some(native_theme))
    .visible(false)
    .focused(false);

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let builder = builder
        .transparent(true)
        .background_color(Color(0, 0, 0, 0));

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let builder = builder.background_color(theme_background_color(&current_theme));

    let window = builder
        .build()
        .context("Failed to create OpenKeylet tray menu window")?;

    #[cfg(windows)]
    apply_windows_tray_window_style(&window);

    #[cfg(target_os = "macos")]
    apply_macos_tray_window_style(&window);

    Ok(window)
}

pub fn set_tray_window_theme(app: &AppHandle, controller: &TrayMenuController, theme: &str) {
    controller.set_appearance(Some(theme), None);
    let native_theme = if theme == "light" {
        tauri::Theme::Light
    } else {
        tauri::Theme::Dark
    };
    if let Some(window) = app.get_webview_window(TRAY_MENU_LABEL) {
        let _ = window.set_theme(Some(native_theme));
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = window.set_background_color(Some(theme_background_color(theme)));
    }
}

pub fn position_tray_window(
    window: &WebviewWindow,
    anchor: TrayAnchor,
    logical_height: f64,
) {
    let fallback_scale = window.scale_factor().unwrap_or(1.0);
    let (work_area, scale) = find_monitor_for_point(window, anchor.click_x, anchor.click_y)
        .unwrap_or((
            PixelRect {
                left: 0.0,
                top: 0.0,
                width: 1920.0 * fallback_scale,
                height: 1040.0 * fallback_scale,
            },
            fallback_scale,
        ));

    let phys_w = (TRAY_MENU_LOGICAL_WIDTH * scale).round();
    let phys_h = (logical_height * scale).round();
    let (x, y) = compute_popup_position(
        anchor,
        work_area,
        phys_w,
        phys_h,
        scale,
        cfg!(target_os = "macos"),
    );

    let _ = window.set_size(PhysicalSize::new(phys_w as u32, phys_h as u32));
    let _ = window.set_position(PhysicalPosition::new(x, y));
}

pub fn hide_tray_menu(app: &AppHandle, controller: &TrayMenuController, from_blur: bool) {
    if from_blur && controller.should_ignore_blur() {
        return;
    }
    if let Some(window) = app.get_webview_window(TRAY_MENU_LABEL)
        && window.is_visible().unwrap_or(false)
    {
        let _ = window.hide();
        #[cfg(target_os = "macos")]
        set_macos_status_item_highlight(app, false);
        if from_blur {
            controller.mark_blur_hidden();
        } else {
            controller.clear_blur_mark();
        }
    }
}

pub fn toggle_custom_tray_menu(
    app: &AppHandle,
    controller: &TrayMenuController,
    anchor: TrayAnchor,
    state: &TrayMenuState,
) {
    if controller.was_just_hidden_by_blur() {
        controller.clear_blur_mark();
        #[cfg(target_os = "macos")]
        set_macos_status_item_highlight(app, false);
        return;
    }

    let window = match ensure_tray_window(app, controller) {
        Ok(win) => win,
        Err(error) => {
            eprintln!("OpenKeylet: unable to open tray menu: {error:#}");
            #[cfg(target_os = "macos")]
            set_macos_status_item_highlight(app, false);
            return;
        }
    };

    if window.is_visible().unwrap_or(false) {
        let _ = window.hide();
        controller.clear_blur_mark();
        #[cfg(target_os = "macos")]
        set_macos_status_item_highlight(app, false);
        return;
    }

    controller.set_last_anchor(anchor);
    let height = controller.logical_height();
    position_tray_window(&window, anchor, height);
    let _ = window.emit("tray-state-changed", state);
    controller.mark_shown();
    let _ = window.show();
    #[cfg(windows)]
    bring_tray_window_foreground(&window);
    #[cfg(target_os = "macos")]
    set_macos_status_item_highlight(app, true);
    let _ = window.set_focus();
}

pub fn resize_tray_menu(
    app: &AppHandle,
    controller: &TrayMenuController,
    height: f64,
) -> Result<()> {
    let clamped = controller.set_logical_height(height);
    if let Some(window) = app.get_webview_window(TRAY_MENU_LABEL) {
        if let Some(anchor) = controller.last_anchor() {
            position_tray_window(&window, anchor, clamped);
        } else {
            let _ = window.set_size(LogicalSize::new(TRAY_MENU_LOGICAL_WIDTH, clamped));
        }
    }
    Ok(())
}

pub fn sync_tray_surface(app: &AppHandle, controller: &TrayMenuController, state: &TrayMenuState) {
    let tooltip = format_tooltip(state);
    if controller.update_cached_tooltip(&tooltip)
        && let Some(tray) = app.tray_by_id(TRAY_ID)
    {
        let _ = tray.set_tooltip(Some(tooltip));
    }

    if let Some(window) = app.get_webview_window(TRAY_MENU_LABEL) {
        let _ = window.emit("tray-state-changed", state);
    }

    #[cfg(windows)]
    {
        let panel_dark = platform::panel_is_dark();
        if controller.update_cached_panel_dark(panel_dark)
            && let Some(tray) = app.tray_by_id(TRAY_ID)
        {
            let _ = tray.set_icon(Some(platform::tray_icon_for_panel(panel_dark)));
        }
    }

    #[cfg(target_os = "linux")]
    {
        let panel_dark = platform::panel_is_dark();
        let panel_changed = controller.update_cached_panel_dark(panel_dark);
        let menu_changed = controller.should_rebuild_linux_menu(state);
        if (panel_changed || menu_changed)
            && let Some(tray) = app.tray_by_id(TRAY_ID)
        {
            if panel_changed {
                let _ = tray.set_icon(Some(platform::tray_icon_for_panel(panel_dark)));
            }
            match build_native_linux_menu(app, state) {
                Ok(menu) => {
                    let _ = tray.set_menu(Some(menu));
                }
                Err(error) => {
                    eprintln!("OpenKeylet: failed to refresh Linux tray menu: {error:#}");
                }
            }
        }
    }
}


#[cfg(test)]
mod tests;
