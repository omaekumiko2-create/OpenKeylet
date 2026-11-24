use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{Emitter, Manager, PhysicalPosition, PhysicalSize, WebviewWindow};

const SNAP_THRESHOLD_LOGICAL: f64 = 16.0;
const UNDOCK_THRESHOLD_LOGICAL: f64 = 36.0;
const PEEK_VISIBLE_LOGICAL: f64 = 10.0;
const HOVER_MARGIN_LOGICAL: f64 = 16.0;
const COLLAPSE_DELAY: Duration = Duration::from_millis(380);
const ANIMATION_STEPS: usize = 9;
const ANIMATION_FRAME: Duration = Duration::from_millis(14);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DockEdge {
    Left,
    Right,
    Top,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdgeDockPayload {
    pub edge: Option<DockEdge>,
    pub collapsed: bool,
}

#[derive(Debug, Clone, Copy)]
struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

impl Rect {
    fn from_pos_size(pos: PhysicalPosition<i32>, size: PhysicalSize<u32>) -> Self {
        Self {
            left: pos.x,
            top: pos.y,
            right: pos.x + size.width as i32,
            bottom: pos.y + size.height as i32,
        }
    }

    fn contains_with_margin(&self, x: i32, y: i32, margin: i32) -> bool {
        x >= self.left - margin
            && x <= self.right + margin
            && y >= self.top - margin
            && y <= self.bottom + margin
    }
}

#[derive(Debug, Clone)]
struct DockedSession {
    edge: DockEdge,
    collapsed: bool,
    work_area: Rect,
    leave_since: Option<Instant>,
}

#[derive(Debug, Default)]
struct EdgeDockInner {
    docked: Option<DockedSession>,
    last_user_move: Option<Instant>,
    frontend_hovered: bool,
}

pub struct EdgeDockController {
    enabled: AtomicBool,
    animating: AtomicBool,
    inner: Mutex<EdgeDockInner>,
}

impl Default for EdgeDockController {
    fn default() -> Self {
        Self::new()
    }
}

impl EdgeDockController {
    pub fn new() -> Self {
        Self {
            enabled: AtomicBool::new(Self::platform_supported()),
            animating: AtomicBool::new(false),
            inner: Mutex::new(EdgeDockInner::default()),
        }
    }

    pub fn platform_supported() -> bool {
        !is_wayland_session()
    }

    pub fn is_supported(&self) -> bool {
        Self::platform_supported()
    }

    pub fn is_enabled(&self) -> bool {
        Self::platform_supported() && self.enabled.load(Ordering::Acquire)
    }

    pub fn is_collapsed(&self) -> bool {
        self.inner
            .lock()
            .ok()
            .and_then(|guard| guard.docked.as_ref().map(|docked| docked.collapsed))
            .unwrap_or(false)
    }

    pub fn set_enabled(&self, window: &WebviewWindow, enabled: bool) {
        let effective = Self::platform_supported() && enabled;
        self.enabled.store(effective, Ordering::Release);
        if !effective {
            self.undock(window, true);
        }
    }

    pub fn on_window_moved(&self) {
        if !self.is_enabled() || self.animating.load(Ordering::Acquire) {
            return;
        }
        if let Ok(mut guard) = self.inner.lock() {
            guard.last_user_move = Some(Instant::now());
            if let Some(docked) = guard.docked.as_mut() {
                docked.leave_since = None;
            }
        }
    }

    pub fn on_frontend_hover(&self, window: &WebviewWindow, entered: bool) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.frontend_hovered = entered;
            if let Some(docked) = guard.docked.as_mut() {
                if entered {
                    docked.leave_since = None;
                } else if !docked.collapsed && docked.leave_since.is_none() {
                    docked.leave_since = Some(Instant::now());
                }
            }
        }
        if entered {
            self.expand(window);
        }
    }

    pub fn expand(&self, window: &WebviewWindow) {
        let target = {
            let mut guard = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            let Some(docked) = guard.docked.as_mut() else {
                return;
            };
            docked.leave_since = None;
            if !docked.collapsed {
                return;
            }
            docked.collapsed = false;
            (docked.edge, docked.work_area)
        };
        if let Ok(pos) = window.outer_position()
            && let Ok(size) = window.outer_size()
        {
            let expanded = expanded_position(target.0, pos, size, target.1);
            self.animate_to(window, pos, expanded);
            emit_state(window, Some(target.0), false);
        }
    }

    pub fn undock(&self, window: &WebviewWindow, restore_if_collapsed: bool) {
        let previous = {
            let mut guard = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            guard.last_user_move = None;
            guard.docked.take()
        };
        if let Some(docked) = previous {
            if restore_if_collapsed && docked.collapsed {
                if let Ok(pos) = window.outer_position()
                    && let Ok(size) = window.outer_size()
                {
                    let expanded = expanded_position(docked.edge, pos, size, docked.work_area);
                    self.animate_to(window, pos, expanded);
                }
            }
            let _ = window.set_always_on_top(false);
            emit_state(window, None, false);
        }
    }

    pub fn spawn_monitor(self: &Arc<Self>, app_handle: tauri::AppHandle) {
        let controller = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            loop {
                let (has_pending_move, is_docked) = {
                    if let Ok(guard) = controller.inner.lock() {
                        (guard.last_user_move.is_some(), guard.docked.is_some())
                    } else {
                        (false, false)
                    }
                };
                let sleep_ms = if has_pending_move || is_docked { 55 } else { 220 };
                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;

                if !controller.is_enabled() || controller.animating.load(Ordering::Acquire) {
                    continue;
                }
                let Some(window) = app_handle.get_webview_window("main") else {
                    continue;
                };
                if !window.is_visible().unwrap_or(false) || window.is_minimized().unwrap_or(false) {
                    continue;
                }

                controller.tick(&window);
            }
        });
    }

    fn tick(&self, window: &WebviewWindow) {
        if is_primary_mouse_down() {
            return;
        }

        // 1. Evaluate whether a completed user drag snapped to or left a screen edge.
        let settle_needed = if cfg!(windows) {
            Duration::from_millis(90)
        } else {
            Duration::from_millis(260)
        };
        let should_evaluate_move = {
            if let Ok(guard) = self.inner.lock() {
                guard
                    .last_user_move
                    .is_some_and(|at| at.elapsed() >= settle_needed)
            } else {
                false
            }
        };
        if should_evaluate_move {
            self.evaluate_snap(window);
        }

        // 2. When docked, auto-collapse on cursor leave and auto-expand on edge hover.
        let docked_snapshot = {
            match self.inner.lock() {
                Ok(guard) => guard.docked.clone(),
                Err(_) => return,
            }
        };
        let Some(docked) = docked_snapshot else {
            return;
        };

        let Ok(pos) = window.outer_position() else {
            return;
        };
        let Ok(size) = window.outer_size() else {
            return;
        };
        let scale = window.scale_factor().unwrap_or(1.0);
        let margin = (HOVER_MARGIN_LOGICAL * scale).round() as i32;
        let peek_trigger = ((PEEK_VISIBLE_LOGICAL + 6.0) * scale).round() as i32;

        if let Some((cx, cy)) = cursor_position() {
            let win_rect = Rect::from_pos_size(pos, size);
            if docked.collapsed {
                let touching_edge = match docked.edge {
                    DockEdge::Left => {
                        cx <= docked.work_area.left + peek_trigger
                            && cy >= win_rect.top - margin
                            && cy <= win_rect.bottom + margin
                    }
                    DockEdge::Right => {
                        cx >= docked.work_area.right - peek_trigger
                            && cy >= win_rect.top - margin
                            && cy <= win_rect.bottom + margin
                    }
                    DockEdge::Top => {
                        cy <= docked.work_area.top + peek_trigger
                            && cx >= win_rect.left - margin
                            && cx <= win_rect.right + margin
                    }
                };
                if touching_edge {
                    self.expand(window);
                }
            } else if win_rect.contains_with_margin(cx, cy, margin) {
                if let Ok(mut guard) = self.inner.lock()
                    && let Some(d) = guard.docked.as_mut()
                {
                    d.leave_since = None;
                }
            } else {
                let should_collapse = {
                    let mut guard = match self.inner.lock() {
                        Ok(g) => g,
                        Err(_) => return,
                    };
                    if let Some(d) = guard.docked.as_mut() {
                        let started = d.leave_since.get_or_insert_with(Instant::now);
                        if started.elapsed() >= COLLAPSE_DELAY {
                            d.collapsed = true;
                            d.leave_since = None;
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                };
                if should_collapse {
                    self.collapse_to_edge(window, &docked, pos, size, scale);
                }
            }
        } else if !docked.collapsed {
            // Non-Windows fallback: rely on frontend pointerleave timer when unfocused.
            let should_collapse = {
                let mut guard = match self.inner.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                if !guard.frontend_hovered
                    && let Some(d) = guard.docked.as_mut()
                    && let Some(started) = d.leave_since
                    && started.elapsed() >= COLLAPSE_DELAY
                {
                    d.collapsed = true;
                    d.leave_since = None;
                    true
                } else {
                    false
                }
            };
            if should_collapse {
                self.collapse_to_edge(window, &docked, pos, size, scale);
            }
        }
    }

    fn collapse_to_edge(
        &self,
        window: &WebviewWindow,
        docked: &DockedSession,
        pos: PhysicalPosition<i32>,
        size: PhysicalSize<u32>,
        scale: f64,
    ) {
        let peek_px = (PEEK_VISIBLE_LOGICAL * scale).round() as i32;
        let collapsed_pos = collapsed_position(docked.edge, pos, size, docked.work_area, peek_px);
        self.animate_to(window, pos, collapsed_pos);
        // Verify the OS/window manager actually moved the window off-screen.
        // On compositors that clamp windows inside the work area (e.g. Wayland,
        // macOS menu bar, or strict tiling WMs), abort collapse instead of leaving
        // the full-window peek overlay covering the live UI.
        if let Ok(actual) = window.outer_position()
            && !position_reached_collapse_target(docked.edge, actual, collapsed_pos, scale)
        {
            self.undock(window, false);
            return;
        }
        emit_state(window, Some(docked.edge), true);
    }

    fn evaluate_snap(&self, window: &WebviewWindow) {
        {
            if let Ok(mut guard) = self.inner.lock() {
                guard.last_user_move = None;
            }
        }
        let Ok(pos) = window.outer_position() else {
            return;
        };
        let Ok(size) = window.outer_size() else {
            return;
        };
        let Ok(Some(monitor)) = window.current_monitor() else {
            return;
        };
        let work = monitor.work_area();
        let work_rect = Rect::from_pos_size(work.position, work.size);
        let scale = window.scale_factor().unwrap_or(1.0);
        let snap_px = (SNAP_THRESHOLD_LOGICAL * scale).round() as i32;
        let undock_px = (UNDOCK_THRESHOLD_LOGICAL * scale).round() as i32;

        let win_rect = Rect::from_pos_size(pos, size);
        let near_edge = detect_snap_edge(win_rect, work_rect, snap_px, !cfg!(target_os = "macos"));

        let existing_edge = self
            .inner
            .lock()
            .ok()
            .and_then(|g| g.docked.as_ref().map(|d| d.edge));

        if let Some(edge) = near_edge {
            let snapped = expanded_position(edge, pos, size, work_rect);
            if snapped.x != pos.x || snapped.y != pos.y {
                self.animate_to(window, pos, snapped);
            }
            if let Ok(mut guard) = self.inner.lock() {
                guard.docked = Some(DockedSession {
                    edge,
                    collapsed: false,
                    work_area: work_rect,
                    leave_since: None,
                });
            }
            let _ = window.set_always_on_top(true);
            emit_state(window, Some(edge), false);
        } else if let Some(edge) = existing_edge {
            let moved_away = match edge {
                DockEdge::Left => win_rect.left > work_rect.left + undock_px,
                DockEdge::Right => win_rect.right < work_rect.right - undock_px,
                DockEdge::Top => win_rect.top > work_rect.top + undock_px,
            };
            if moved_away {
                self.undock(window, false);
            }
        }
    }

    fn animate_to(
        &self,
        window: &WebviewWindow,
        from: PhysicalPosition<i32>,
        to: PhysicalPosition<i32>,
    ) {
        if from.x == to.x && from.y == to.y {
            return;
        }
        self.animating.store(true, Ordering::Release);
        for step in 1..=ANIMATION_STEPS {
            let t = step as f64 / ANIMATION_STEPS as f64;
            let eased = 1.0 - (1.0 - t).powi(3);
            let x = from.x + ((to.x - from.x) as f64 * eased).round() as i32;
            let y = from.y + ((to.y - from.y) as f64 * eased).round() as i32;
            let _ = window.set_position(PhysicalPosition::new(x, y));
            if step < ANIMATION_STEPS {
                std::thread::sleep(ANIMATION_FRAME);
            }
        }
        // Brief guard so the final OS Moved event is ignored as programmatic.
        std::thread::sleep(Duration::from_millis(20));
        self.animating.store(false, Ordering::Release);
    }
}

fn expanded_position(
    edge: DockEdge,
    current: PhysicalPosition<i32>,
    size: PhysicalSize<u32>,
    work: Rect,
) -> PhysicalPosition<i32> {
    let w = size.width as i32;
    let h = size.height as i32;
    match edge {
        DockEdge::Left => PhysicalPosition::new(
            work.left,
            current.y.clamp(work.top, (work.bottom - h).max(work.top)),
        ),
        DockEdge::Right => PhysicalPosition::new(
            work.right - w,
            current.y.clamp(work.top, (work.bottom - h).max(work.top)),
        ),
        DockEdge::Top => PhysicalPosition::new(
            current.x.clamp(work.left, (work.right - w).max(work.left)),
            work.top,
        ),
    }
}

fn collapsed_position(
    edge: DockEdge,
    current: PhysicalPosition<i32>,
    size: PhysicalSize<u32>,
    work: Rect,
    peek_px: i32,
) -> PhysicalPosition<i32> {
    let w = size.width as i32;
    let h = size.height as i32;
    match edge {
        DockEdge::Left => PhysicalPosition::new(work.left - w + peek_px, current.y),
        DockEdge::Right => PhysicalPosition::new(work.right - peek_px, current.y),
        DockEdge::Top => PhysicalPosition::new(current.x, work.top - h + peek_px),
    }
}

fn emit_state(window: &WebviewWindow, edge: Option<DockEdge>, collapsed: bool) {
    let _ = window.emit("edge-dock-state", EdgeDockPayload { edge, collapsed });
}

fn detect_snap_edge(
    win_rect: Rect,
    work_rect: Rect,
    snap_px: i32,
    allow_top_edge: bool,
) -> Option<DockEdge> {
    if win_rect.left <= work_rect.left + snap_px {
        Some(DockEdge::Left)
    } else if win_rect.right >= work_rect.right - snap_px {
        Some(DockEdge::Right)
    } else if allow_top_edge && win_rect.top <= work_rect.top + snap_px {
        Some(DockEdge::Top)
    } else {
        None
    }
}

fn position_reached_collapse_target(
    edge: DockEdge,
    actual: PhysicalPosition<i32>,
    target: PhysicalPosition<i32>,
    scale: f64,
) -> bool {
    let tolerance = (24.0 * scale.max(1.0)).round() as i32;
    match edge {
        DockEdge::Left | DockEdge::Right => (actual.x - target.x).abs() <= tolerance,
        DockEdge::Top => (actual.y - target.y).abs() <= tolerance,
    }
}

fn is_wayland_session() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("WAYLAND_DISPLAY").is_some()
            || std::env::var("XDG_SESSION_TYPE")
                .is_ok_and(|value| value.eq_ignore_ascii_case("wayland"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(windows)]
fn cursor_position() -> Option<(i32, i32)> {
    use windows::Win32::Foundation::POINT;
    use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;

    let mut point = POINT::default();
    unsafe { GetCursorPos(&mut point).ok()? };
    Some((point.x, point.y))
}

#[cfg(not(windows))]
fn cursor_position() -> Option<(i32, i32)> {
    None
}

#[cfg(windows)]
fn is_primary_mouse_down() -> bool {
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetAsyncKeyState, VK_LBUTTON};
    unsafe { (GetAsyncKeyState(VK_LBUTTON.0 as i32) as u16 & 0x8000) != 0 }
}

#[cfg(not(windows))]
fn is_primary_mouse_down() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_snap_edge_excludes_top_when_disallowed_for_macos_menu_bar() {
        let work = Rect {
            left: 0,
            top: 38,
            right: 1440,
            bottom: 900,
        };
        let near_top = Rect {
            left: 400,
            top: 40,
            right: 860,
            bottom: 730,
        };
        assert_eq!(detect_snap_edge(near_top, work, 16, true), Some(DockEdge::Top));
        assert_eq!(detect_snap_edge(near_top, work, 16, false), None);

        let near_right = Rect {
            left: 980,
            top: 100,
            right: 1440,
            bottom: 790,
        };
        assert_eq!(
            detect_snap_edge(near_right, work, 16, false),
            Some(DockEdge::Right)
        );
    }

    #[test]
    fn collapse_target_verification_detects_os_clamping() {
        let target_left = PhysicalPosition::new(-450, 100);
        assert!(position_reached_collapse_target(
            DockEdge::Left,
            PhysicalPosition::new(-448, 100),
            target_left,
            1.0
        ));
        // Compositor clamped the window back to x=0 instead of sliding off-screen
        assert!(!position_reached_collapse_target(
            DockEdge::Left,
            PhysicalPosition::new(0, 100),
            target_left,
            1.0
        ));

        let target_top = PhysicalPosition::new(400, -640);
        assert!(!position_reached_collapse_target(
            DockEdge::Top,
            PhysicalPosition::new(400, 38),
            target_top,
            2.0
        ));
    }
}
