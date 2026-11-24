use anyhow::{Context, Result};
use serde::Serialize;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{
    AppHandle, Emitter, LogicalSize, Manager, PhysicalPosition, PhysicalSize, Rect, WebviewUrl,
    WebviewWindow, WebviewWindowBuilder, window::Color,
};

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
    pub strong_mode: bool,
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
}

pub fn platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "windows"
    }
}

pub fn normalize_lang(raw: &str) -> &'static str {
    let lower = raw.trim().to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "zh-tw" | "zh_tw" | "zh-hk" | "zh_hk" | "zh-hant" | "zh_hant"
    ) || lower.starts_with("zh-tw")
        || lower.starts_with("zh_tw")
        || lower.starts_with("zh-hk")
        || lower.starts_with("zh_hk")
        || lower.starts_with("zh-hant")
        || lower.starts_with("zh_hant")
    {
        return "zh-TW";
    }
    if lower == "zh" || lower.starts_with("zh-") || lower.starts_with("zh_") {
        return "zh";
    }
    if lower == "ja" || lower.starts_with("ja-") || lower.starts_with("ja_") {
        return "ja";
    }
    if lower == "ko" || lower.starts_with("ko-") || lower.starts_with("ko_") {
        return "ko";
    }
    if lower == "es" || lower.starts_with("es-") || lower.starts_with("es_") {
        return "es";
    }
    "en"
}

fn detect_env_locale_opt() -> Option<&'static str> {
    for var in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(value) = std::env::var(var) {
            let trimmed = value.trim();
            if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("c") && trimmed != "POSIX" {
                let base = trimmed.split('.').next().unwrap_or(trimmed);
                return Some(normalize_lang(base));
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy)]
pub struct TrayCopy {
    pub tooltip_unlocked: &'static str,
    pub tooltip_locked: &'static str,
    pub status_unlocked: &'static str,
    pub status_locked: &'static str,
    pub status_strong_locked: &'static str,
    pub items_suffix: &'static str,
    pub update_available: &'static str,
    pub show_window: &'static str,
    pub hide_window: &'static str,
    pub new_item: &'static str,
    pub smart_import: &'static str,
    pub generate_password: &'static str,
    pub browser_bridge: &'static str,
    pub bridge_connected: &'static str,
    pub bridge_listening: &'static str,
    pub edge_dock: &'static str,
    pub settings: &'static str,
    pub lock_vault: &'static str,
    pub unlock_vault: &'static str,
    pub set_pin_lock: &'static str,
    pub quit: &'static str,
}

pub fn tray_copy(lang: &str) -> TrayCopy {
    match normalize_lang(lang) {
        "zh" => TrayCopy {
            tooltip_unlocked: "OpenKeylet — 本地加密密码库（已解锁）",
            tooltip_locked: "OpenKeylet — 本地加密密码库（已锁定）",
            status_unlocked: "已解锁",
            status_locked: "已锁定",
            status_strong_locked: "强云库已锁定",
            items_suffix: "项凭据",
            update_available: "发现新版本",
            show_window: "显示 OpenKeylet",
            hide_window: "隐藏到托盘",
            new_item: "新建凭据",
            smart_import: "智能导入",
            generate_password: "生成并复制强密码",
            browser_bridge: "浏览器桥接",
            bridge_connected: "已连接",
            bridge_listening: "等待配对",
            edge_dock: "贴边自动收起",
            settings: "系统设置",
            lock_vault: "立即锁定",
            unlock_vault: "解锁密码库",
            set_pin_lock: "设置 PIN 锁",
            quit: "退出 OpenKeylet",
        },
        "zh-TW" => TrayCopy {
            tooltip_unlocked: "OpenKeylet — 本機加密密碼庫（已解鎖）",
            tooltip_locked: "OpenKeylet — 本機加密密碼庫（已鎖定）",
            status_unlocked: "已解鎖",
            status_locked: "已鎖定",
            status_strong_locked: "強雲庫已鎖定",
            items_suffix: "項憑證",
            update_available: "發現新版本",
            show_window: "顯示 OpenKeylet",
            hide_window: "隱藏至系統匣",
            new_item: "新增憑證",
            smart_import: "智慧匯入",
            generate_password: "產生並複製強密碼",
            browser_bridge: "瀏覽器橋接",
            bridge_connected: "已連線",
            bridge_listening: "等待配對",
            edge_dock: "貼邊自動收合",
            settings: "系統設定",
            lock_vault: "立即鎖定",
            unlock_vault: "解鎖密碼庫",
            set_pin_lock: "設定 PIN 鎖",
            quit: "結束 OpenKeylet",
        },
        "ja" => TrayCopy {
            tooltip_unlocked: "OpenKeylet — ローカル暗号化ボールト（解除済み）",
            tooltip_locked: "OpenKeylet — ローカル暗号化ボールト（ロック中）",
            status_unlocked: "ロック解除",
            status_locked: "ロック中",
            status_strong_locked: "クラウド金庫ロック中",
            items_suffix: "件",
            update_available: "アップデートあり",
            show_window: "OpenKeylet を表示",
            hide_window: "トレイに隠す",
            new_item: "新規項目",
            smart_import: "スマートインポート",
            generate_password: "強力なパスワードをコピー",
            browser_bridge: "ブラウザ連携",
            bridge_connected: "接続済み",
            bridge_listening: "待機中",
            edge_dock: "画面端オートドック",
            settings: "システム設定",
            lock_vault: "今すぐロック",
            unlock_vault: "ロック解除",
            set_pin_lock: "PIN ロックを設定",
            quit: "OpenKeylet を終了",
        },
        "ko" => TrayCopy {
            tooltip_unlocked: "OpenKeylet — 로컬 암호화 금고 (잠금 해제됨)",
            tooltip_locked: "OpenKeylet — 로컬 암호화 금고 (잠김)",
            status_unlocked: "잠금 해제",
            status_locked: "잠김",
            status_strong_locked: "클라우드 금고 잠김",
            items_suffix: "개 항목",
            update_available: "새 버전 있음",
            show_window: "OpenKeylet 표시",
            hide_window: "트레이로 숨기기",
            new_item: "새 항목",
            smart_import: "스마트 가져오기",
            generate_password: "강력한 비밀번호 복사",
            browser_bridge: "브라우저 브리지",
            bridge_connected: "연결됨",
            bridge_listening: "대기 중",
            edge_dock: "화면 가장자리 자동 숨김",
            settings: "시스템 설정",
            lock_vault: "지금 잠금",
            unlock_vault: "금고 잠금 해제",
            set_pin_lock: "PIN 잠금 설정",
            quit: "OpenKeylet 종료",
        },
        "es" => TrayCopy {
            tooltip_unlocked: "OpenKeylet — Bóveda local (Desbloqueada)",
            tooltip_locked: "OpenKeylet — Bóveda local (Bloqueada)",
            status_unlocked: "Desbloqueada",
            status_locked: "Bloqueada",
            status_strong_locked: "Bóveda nube bloqueada",
            items_suffix: "elementos",
            update_available: "Actualización disponible",
            show_window: "Mostrar OpenKeylet",
            hide_window: "Ocultar en bandeja",
            new_item: "Nuevo elemento",
            smart_import: "Importación inteligente",
            generate_password: "Copiar contraseña segura",
            browser_bridge: "Puente del navegador",
            bridge_connected: "Conectado",
            bridge_listening: "Esperando",
            edge_dock: "Acoplamiento en borde",
            settings: "Ajustes del sistema",
            lock_vault: "Bloquear ahora",
            unlock_vault: "Desbloquear bóveda",
            set_pin_lock: "Configurar PIN",
            quit: "Salir de OpenKeylet",
        },
        _ => TrayCopy {
            tooltip_unlocked: "OpenKeylet — Local Vault (Unlocked)",
            tooltip_locked: "OpenKeylet — Local Vault (Locked)",
            status_unlocked: "Unlocked",
            status_locked: "Locked",
            status_strong_locked: "Cloud Vault Locked",
            items_suffix: "items",
            update_available: "Update available",
            show_window: "Show OpenKeylet",
            hide_window: "Hide to tray",
            new_item: "New item",
            smart_import: "Smart import",
            generate_password: "Copy strong password",
            browser_bridge: "Browser bridge",
            bridge_connected: "Connected",
            bridge_listening: "Waiting",
            edge_dock: "Edge-dock drawer",
            settings: "System settings",
            lock_vault: "Lock vault",
            unlock_vault: "Unlock vault",
            set_pin_lock: "Set PIN lock",
            quit: "Quit OpenKeylet",
        },
    }
}

pub fn format_tooltip(state: &TrayMenuState) -> String {
    let copy = tray_copy(&state.resolved_language);
    if state.unlocked {
        copy.tooltip_unlocked.to_owned()
    } else {
        copy.tooltip_locked.to_owned()
    }
}

pub fn theme_background_color(theme: &str) -> Color {
    if theme == "light" {
        Color(255, 255, 255, 255)
    } else {
        Color(11, 11, 13, 255)
    }
}

/// Computes the physical top-left screen position of the tray popover window.
/// Handles bottom/top/left/right Windows taskbars, Windows 11 overflow flyouts,
/// macOS top menu bar, multi-monitor negative coordinates, and arbitrary DPI scales.
pub fn compute_popup_position(
    anchor: TrayAnchor,
    work_area: PixelRect,
    menu_width: f64,
    menu_height: f64,
    scale_factor: f64,
    is_macos: bool,
) -> (i32, i32) {
    let scale = if scale_factor.is_finite() && scale_factor > 0.25 {
        scale_factor
    } else {
        1.0
    };
    let gap = (8.0 * scale).round();
    let edge_margin = (8.0 * scale).round();

    // Only trust icon_rect when it is non-empty and reasonably close to the actual click
    // (guards against Windows 11 overflow tray flyouts where icon_rect can differ from cursor).
    let usable_rect = anchor.icon_rect.filter(|rect| {
        if rect.width <= 1.0 || rect.height <= 1.0 {
            return false;
        }
        let max_dist = 72.0 * scale;
        let dx = if anchor.click_x < rect.left {
            rect.left - anchor.click_x
        } else if anchor.click_x > rect.right() {
            anchor.click_x - rect.right()
        } else {
            0.0
        };
        let dy = if anchor.click_y < rect.top {
            rect.top - anchor.click_y
        } else if anchor.click_y > rect.bottom() {
            anchor.click_y - rect.bottom()
        } else {
            0.0
        };
        dx <= max_dist && dy <= max_dist
    });

    let (anchor_left, anchor_top, anchor_right, anchor_bottom, anchor_cx) = match usable_rect {
        Some(rect) => (
            rect.left,
            rect.top,
            rect.right(),
            rect.bottom(),
            rect.center_x(),
        ),
        None => (
            anchor.click_x,
            anchor.click_y,
            anchor.click_x,
            anchor.click_y,
            anchor.click_x,
        ),
    };

    let (raw_x, raw_y) = if is_macos {
        // macOS menu bar sits above work_area.top; open directly below the status item.
        let x = anchor_cx - menu_width * 0.5;
        let y = anchor_bottom.max(work_area.top) + gap;
        (x, y)
    } else if anchor_right <= work_area.left + 2.0 {
        // Vertical taskbar docked on the left edge.
        let x = work_area.left + gap;
        let y = anchor.click_y - menu_height * 0.5;
        (x, y)
    } else if anchor_left >= work_area.right() - 2.0 {
        // Vertical taskbar docked on the right edge.
        let x = work_area.right() - menu_width - gap;
        let y = anchor.click_y - menu_height * 0.5;
        (x, y)
    } else if anchor_bottom <= work_area.top + 2.0 {
        // Horizontal taskbar docked on the top edge.
        let x = anchor_cx - menu_width * 0.5;
        let y = work_area.top + gap;
        (x, y)
    } else if anchor_top >= work_area.bottom() - 2.0 {
        // Standard horizontal taskbar docked on the bottom edge.
        let x = anchor_cx - menu_width * 0.5;
        let y = work_area.bottom() - menu_height - gap;
        (x, y)
    } else {
        // Click occurred inside the work area (e.g. Windows 11 tray overflow flyout).
        let x = anchor_cx - menu_width * 0.5;
        let mid_y = work_area.top + work_area.height * 0.5;
        let y = if anchor.click_y >= mid_y {
            anchor_top - menu_height - gap
        } else {
            anchor_bottom + gap
        };
        (x, y)
    };

    let min_x = work_area.left + edge_margin;
    let max_x = (work_area.right() - menu_width - edge_margin).max(min_x);
    let min_y = work_area.top + edge_margin;
    let max_y = (work_area.bottom() - menu_height - edge_margin).max(min_y);

    (
        raw_x.clamp(min_x, max_x).round() as i32,
        raw_y.clamp(min_y, max_y).round() as i32,
    )
}

pub fn anchor_from_event(
    position: PhysicalPosition<f64>,
    rect: Rect,
    scale_factor: f64,
) -> TrayAnchor {
    let rect_pos = rect.position.to_physical::<f64>(scale_factor);
    let rect_size = rect.size.to_physical::<f64>(scale_factor);
    let icon_rect = if rect_size.width > 1.0 && rect_size.height > 1.0 {
        Some(PixelRect {
            left: rect_pos.x,
            top: rect_pos.y,
            width: rect_size.width,
            height: rect_size.height,
        })
    } else {
        None
    };
    TrayAnchor {
        click_x: position.x,
        click_y: position.y,
        icon_rect,
    }
}

fn find_monitor_for_point(
    window: &WebviewWindow,
    x: f64,
    y: f64,
) -> Option<(PixelRect, f64)> {
    if let Ok(monitors) = window.available_monitors() {
        for monitor in &monitors {
            let pos = monitor.position();
            let size = monitor.size();
            let bounds = PixelRect {
                left: pos.x as f64,
                top: pos.y as f64,
                width: size.width as f64,
                height: size.height as f64,
            };
            if bounds.contains_point(x, y) {
                let work = monitor.work_area();
                return Some((
                    PixelRect {
                        left: work.position.x as f64,
                        top: work.position.y as f64,
                        width: work.size.width as f64,
                        height: work.size.height as f64,
                    },
                    monitor.scale_factor(),
                ));
            }
        }
    }
    let fallback = window
        .current_monitor()
        .ok()
        .flatten()
        .or_else(|| window.primary_monitor().ok().flatten())?;
    let work = fallback.work_area();
    Some((
        PixelRect {
            left: work.position.x as f64,
            top: work.position.y as f64,
            width: work.size.width as f64,
            height: work.size.height as f64,
        },
        fallback.scale_factor(),
    ))
}

#[cfg(windows)]
fn apply_windows_tray_window_style(window: &WebviewWindow) {
    use windows::Win32::Graphics::Dwm::{
        DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND, DwmSetWindowAttribute,
    };

    if let Ok(hwnd) = window.hwnd() {
        let preference = DWMWCP_ROUND;
        unsafe {
            let _ = DwmSetWindowAttribute(
                windows::Win32::Foundation::HWND(hwnd.0),
                DWMWA_WINDOW_CORNER_PREFERENCE,
                &preference as *const _ as *const _,
                size_of_val(&preference) as u32,
            );
        }
    }
}

#[cfg(windows)]
fn bring_tray_window_foreground(window: &WebviewWindow) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::SetForegroundWindow;

    if let Ok(hwnd) = window.hwnd() {
        unsafe {
            let _ = SetForegroundWindow(HWND(hwnd.0));
        }
    }
}

#[cfg(target_os = "macos")]
fn apply_macos_tray_window_style(window: &WebviewWindow) {
    use objc2_app_kit::{NSPopUpMenuWindowLevel, NSWindow, NSWindowCollectionBehavior};

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

pub fn ensure_tray_window(
    app: &AppHandle,
    controller: &TrayMenuController,
) -> Result<WebviewWindow> {
    if let Some(existing) = app.get_webview_window(TRAY_MENU_LABEL) {
        return Ok(existing);
    }

    let height = controller.logical_height();
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
    .visible(false)
    .focused(false);

    #[cfg(target_os = "linux")]
    let builder = builder
        .transparent(true)
        .background_color(Color(0, 0, 0, 0));

    #[cfg(not(target_os = "linux"))]
    let builder = builder.background_color(theme_background_color(&controller.current_theme()));

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
    #[cfg(not(target_os = "linux"))]
    if let Some(window) = app.get_webview_window(TRAY_MENU_LABEL) {
        let _ = window.set_background_color(Some(theme_background_color(theme)));
    }
    #[cfg(target_os = "linux")]
    let _ = app;
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
    } else if state.strong_mode {
        format!(
            "OpenKeylet v{} · {}",
            state.version, copy.status_strong_locked
        )
    } else {
        format!("OpenKeylet v{} · {}", state.version, copy.status_locked)
    };

    let header = IconMenuItem::with_id(
        app,
        "tray-header",
        status_text,
        false,
        Some(tauri::include_image!("icons/tray.png")),
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
    let edge_dock = CheckMenuItem::with_id(
        app,
        "tray-toggle-edge-dock",
        copy.edge_dock,
        true,
        state.edge_dock_enabled,
        None::<&str>,
    )?;

    let sep2 = PredefinedMenuItem::separator(app)?;

    let settings = MenuItem::with_id(app, "tray-open-settings", copy.settings, true, None::<&str>)?;
    let lock_label = if !state.unlocked {
        copy.unlock_vault
    } else if state.pin_configured || state.strong_mode {
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
        &edge_dock,
        &sep2,
        &settings,
        &lock_item,
        &sep3,
        &quit,
    ])?;
    Ok(menu)
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

    #[cfg(target_os = "linux")]
    if controller.should_rebuild_linux_menu(state)
        && let Some(tray) = app.tray_by_id(TRAY_ID)
    {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_bottom_taskbar_places_menu_above_work_area_and_clamps_right_edge() {
        let work = PixelRect {
            left: 0.0,
            top: 0.0,
            width: 1920.0,
            height: 1032.0,
        };
        let anchor = TrayAnchor {
            click_x: 1810.0,
            click_y: 1054.0,
            icon_rect: Some(PixelRect {
                left: 1796.0,
                top: 1036.0,
                width: 28.0,
                height: 40.0,
            }),
        };
        let (x, y) = compute_popup_position(anchor, work, 256.0, 388.0, 1.0, false);
        assert_eq!(x, 1920 - 256 - 8);
        assert_eq!(y, 1032 - 388 - 8);
    }

    #[test]
    fn windows_hidpi_overflow_flyout_falls_back_to_cursor_when_icon_rect_is_far() {
        let work = PixelRect {
            left: 0.0,
            top: 0.0,
            width: 2880.0,
            height: 1728.0,
        };
        let anchor = TrayAnchor {
            click_x: 2520.0,
            click_y: 1580.0,
            // Simulated stale chevron rect far from cursor
            icon_rect: Some(PixelRect {
                left: 2680.0,
                top: 1740.0,
                width: 36.0,
                height: 60.0,
            }),
        };
        let (x, y) = compute_popup_position(anchor, work, 384.0, 582.0, 1.5, false);
        assert_eq!(x, 2520 - 192);
        assert_eq!(y, 1580 - 582 - 12);
    }

    #[test]
    fn windows_left_and_top_taskbars_anchor_inside_work_area() {
        let left_work = PixelRect {
            left: 64.0,
            top: 0.0,
            width: 1856.0,
            height: 1080.0,
        };
        let left_anchor = TrayAnchor {
            click_x: 32.0,
            click_y: 980.0,
            icon_rect: Some(PixelRect {
                left: 12.0,
                top: 960.0,
                width: 40.0,
                height: 40.0,
            }),
        };
        let (lx, ly) = compute_popup_position(left_anchor, left_work, 256.0, 388.0, 1.0, false);
        assert_eq!(lx, 64 + 8);
        assert_eq!(ly, 1080 - 388 - 8);

        let top_work = PixelRect {
            left: 0.0,
            top: 48.0,
            width: 1920.0,
            height: 1032.0,
        };
        let top_anchor = TrayAnchor {
            click_x: 1600.0,
            click_y: 24.0,
            icon_rect: Some(PixelRect {
                left: 1588.0,
                top: 4.0,
                width: 24.0,
                height: 40.0,
            }),
        };
        let (tx, ty) = compute_popup_position(top_anchor, top_work, 256.0, 388.0, 1.0, false);
        assert_eq!(tx, 1600 - 128);
        assert_eq!(ty, 48 + 8);
    }

    #[test]
    fn macos_menu_bar_positions_directly_below_status_item() {
        let work = PixelRect {
            left: 0.0,
            top: 50.0,
            width: 3024.0,
            height: 1860.0,
        };
        let anchor = TrayAnchor {
            click_x: 2400.0,
            click_y: 24.0,
            icon_rect: Some(PixelRect {
                left: 2384.0,
                top: 0.0,
                width: 44.0,
                height: 48.0,
            }),
        };
        let (x, y) = compute_popup_position(anchor, work, 512.0, 776.0, 2.0, true);
        assert_eq!(x, 2406 - 256);
        assert_eq!(y, 50 + 16);
    }

    #[test]
    fn multi_monitor_negative_coordinates_clamp_cleanly() {
        let work = PixelRect {
            left: -1920.0,
            top: 0.0,
            width: 1920.0,
            height: 1032.0,
        };
        let anchor = TrayAnchor {
            click_x: -40.0,
            click_y: 1054.0,
            icon_rect: Some(PixelRect {
                left: -54.0,
                top: 1036.0,
                width: 28.0,
                height: 40.0,
            }),
        };
        let (x, y) = compute_popup_position(anchor, work, 256.0, 388.0, 1.0, false);
        assert_eq!(x, -256 - 8);
        assert_eq!(y, 1032 - 388 - 8);
    }

    #[test]
    fn tray_copy_supports_all_six_locales() {
        for code in ["en", "zh", "zh-TW", "ja", "ko", "es"] {
            let c = tray_copy(code);
            assert!(!c.show_window.is_empty());
            assert!(!c.quit.is_empty());
            assert!(!c.generate_password.is_empty());
        }
        assert_eq!(normalize_lang("zh_HK.UTF-8"), "zh-TW");
        assert_eq!(normalize_lang("zh-CN"), "zh");
        assert_eq!(normalize_lang("ja_JP"), "ja");
        assert_eq!(normalize_lang("ko-KR"), "ko");
        assert_eq!(normalize_lang("es-MX"), "es");
        assert_eq!(normalize_lang("fr-FR"), "en");
    }

    #[test]
    fn explicit_language_setting_overrides_detected_locale() {
        let controller = TrayMenuController::new();
        controller.set_appearance(Some("light"), Some("en-US"));
        assert_eq!(controller.current_theme(), "light");
        assert_eq!(controller.resolve_language("ja"), "ja");
        assert_eq!(controller.resolve_language("zh-TW"), "zh-TW");
        assert_eq!(controller.resolve_language("ko"), "ko");
    }
}
