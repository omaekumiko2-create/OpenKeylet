use super::*;

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

pub(super) fn find_monitor_for_point(
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

