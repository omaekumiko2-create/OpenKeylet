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

#[test]
fn linux_panel_tone_selects_contrasting_tray_icon() {
    use platform::{LinuxPanelSignals, resolve_linux_panel_is_dark};

    // Ubuntu / GNOME default has a dark top bar even in light app color-scheme.
    assert!(resolve_linux_panel_is_dark(&LinuxPanelSignals {
        desktop: "ubuntu:GNOME".to_owned(),
        gnome_color_scheme: Some("'default'".to_owned()),
        portal_color_scheme: Some(0),
        ..Default::default()
    }));

    // Explicit light GNOME Shell user-theme switches to dark-background icon.
    assert!(!resolve_linux_panel_is_dark(&LinuxPanelSignals {
        desktop: "ubuntu:GNOME".to_owned(),
        gnome_shell_theme: Some("'Yaru-light'".to_owned()),
        ..Default::default()
    }));

    // KDE Plasma Breeze Dark vs Breeze Light.
    assert!(resolve_linux_panel_is_dark(&LinuxPanelSignals {
        desktop: "KDE".to_owned(),
        kde_plasma_theme: Some("breeze-dark".to_owned()),
        ..Default::default()
    }));
    assert!(!resolve_linux_panel_is_dark(&LinuxPanelSignals {
        desktop: "KDE".to_owned(),
        kde_plasma_theme: Some("breeze-light".to_owned()),
        ..Default::default()
    }));

    // Portal / GTK fallback on other desktops.
    assert!(resolve_linux_panel_is_dark(&LinuxPanelSignals {
        desktop: "XFCE".to_owned(),
        xfce_theme: Some("Adwaita-dark".to_owned()),
        ..Default::default()
    }));
    assert!(!resolve_linux_panel_is_dark(&LinuxPanelSignals {
        desktop: "XFCE".to_owned(),
        xfce_theme: Some("Adwaita-light".to_owned()),
        ..Default::default()
    }));

    // Explicit environment override wins over desktop heuristics.
    assert!(!resolve_linux_panel_is_dark(&LinuxPanelSignals {
        override_tone: Some("light".to_owned()),
        desktop: "ubuntu:GNOME".to_owned(),
        ..Default::default()
    }));
    assert!(resolve_linux_panel_is_dark(&LinuxPanelSignals {
        override_tone: Some("dark".to_owned()),
        desktop: "XFCE".to_owned(),
        xfce_theme: Some("Adwaita-light".to_owned()),
        ..Default::default()
    }));
}

#[test]
fn windows_taskbar_tone_selects_contrasting_tray_icon() {
    use platform::resolve_windows_taskbar_is_dark;

    // SystemUsesLightTheme == 0 -> dark taskbar (white-bg black logo).
    assert!(resolve_windows_taskbar_is_dark(None, Some(0), Some(1)));
    // SystemUsesLightTheme == 1 -> light taskbar (black-bg white logo).
    assert!(!resolve_windows_taskbar_is_dark(None, Some(1), Some(0)));
    // Falls back to AppsUseLightTheme when SystemUsesLightTheme is absent.
    assert!(resolve_windows_taskbar_is_dark(None, None, Some(0)));
    assert!(!resolve_windows_taskbar_is_dark(None, None, Some(1)));
    // Explicit env override always wins.
    assert!(!resolve_windows_taskbar_is_dark(Some("light"), Some(0), Some(0)));
    assert!(resolve_windows_taskbar_is_dark(Some("dark"), Some(1), Some(1)));
}
