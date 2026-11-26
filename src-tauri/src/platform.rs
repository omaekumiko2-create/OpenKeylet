//! Cross-cutting platform utilities shared across GUI, headless, CLI, and MCP modules.

use crate::vault::Vault;
use anyhow::{Context, Result};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::path::Path;
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

/// Normalize a language preference string into one of OpenKeylet's supported
/// setting values: `"auto"`, `"en"`, `"zh"`, `"zh-TW"`, `"ja"`, `"ko"`, `"es"`.
pub fn normalize_language(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    if lower.is_empty() || lower == "auto" || lower == "system" {
        return "auto".to_owned();
    }
    if lower == "en" || lower.starts_with("en-") || lower.starts_with("en_") {
        return "en".to_owned();
    }
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
        return "zh-TW".to_owned();
    }
    if lower == "zh" || lower.starts_with("zh-") || lower.starts_with("zh_") {
        return "zh".to_owned();
    }
    if lower == "ja" || lower.starts_with("ja-") || lower.starts_with("ja_") {
        return "ja".to_owned();
    }
    if lower == "ko" || lower.starts_with("ko-") || lower.starts_with("ko_") {
        return "ko".to_owned();
    }
    if lower == "es" || lower.starts_with("es-") || lower.starts_with("es_") {
        return "es".to_owned();
    }
    "auto".to_owned()
}

/// Normalize a concrete locale code into one of the 6 rendered UI languages
/// (defaulting to `"en"` when unknown or `"auto"`).
pub fn normalize_ui_lang(raw: &str) -> &'static str {
    match normalize_language(raw).as_str() {
        "zh-TW" => "zh-TW",
        "zh" => "zh",
        "ja" => "ja",
        "ko" => "ko",
        "es" => "es",
        _ => "en",
    }
}

/// Strip Windows verbatim `\\?\` / `\\?\UNC\` path prefixes for shell/process calls.
#[cfg(target_os = "windows")]
pub fn strip_windows_verbatim_prefix(path: &Path) -> String {
    let text = path.to_string_lossy();
    if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else {
        text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned()
    }
}

/// Locate the enclosing `.app` bundle directory on macOS if the executable runs inside one.
#[cfg(target_os = "macos")]
pub fn macos_app_bundle(executable: &Path) -> Option<PathBuf> {
    executable
        .ancestors()
        .find(|path| path.extension().is_some_and(|ext| ext == "app"))
        .map(Path::to_path_buf)
}

/// Detect whether the current Linux desktop session runs under Wayland.
pub fn is_wayland_session() -> bool {
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

/// Apply native OS rounded window corners (`DWMWCP_ROUND` on Windows 11,
/// transparent `NSWindow` + `CALayer` corner mask on macOS).
#[cfg(all(feature = "gui", windows))]
pub fn apply_native_rounded_corners(window: &tauri::WebviewWindow) -> Result<()> {
    use windows::Win32::Graphics::Dwm::{
        DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND, DwmSetWindowAttribute,
    };

    let hwnd = window.hwnd().context("Unable to obtain window handle")?;
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

#[cfg(all(feature = "gui", target_os = "macos"))]
pub fn apply_native_rounded_corners(window: &tauri::WebviewWindow) -> Result<()> {
    use objc2_app_kit::{NSColor, NSWindow};

    const WINDOW_CORNER_RADIUS_PT: f64 = 8.0;
    let win_clone = window.clone();
    let _ = window.run_on_main_thread(move || {
        if let Ok(ptr) = win_clone.ns_window()
            && !ptr.is_null()
        {
            // SAFETY: `ns_window()` returns the valid `NSWindow` pointer owned by Tauri
            // on the AppKit main thread.
            let ns_window = unsafe { &*(ptr.cast::<NSWindow>()) };
            ns_window.setOpaque(false);
            let clear = NSColor::clearColor();
            ns_window.setBackgroundColor(Some(&clear));
            ns_window.setHasShadow(true);
            if let Some(content_view) = ns_window.contentView() {
                content_view.setWantsLayer(true);
                if let Some(layer) = content_view.layer() {
                    layer.setCornerRadius(WINDOW_CORNER_RADIUS_PT);
                    layer.setMasksToBounds(true);
                }
            }
            ns_window.invalidateShadow();
        }
    });
    Ok(())
}

#[cfg(all(feature = "gui", not(any(windows, target_os = "macos"))))]
pub fn apply_native_rounded_corners(_window: &tauri::WebviewWindow) -> Result<()> {
    Ok(())
}

/// Shared 1-second serialized rate-limiter for Owner PIN verification across
/// loopback HTTP/WS endpoints (`browser_vault` and `admin_server`).
pub async fn verify_pin_throttled(
    vault: &Vault,
    pin: &str,
    throttle: &Mutex<Instant>,
) -> Result<bool> {
    let mut next = throttle.lock().await;
    tokio::time::sleep(next.saturating_duration_since(Instant::now())).await;
    *next = Instant::now() + Duration::from_secs(1);
    drop(next);
    vault.verify_owner_pin(pin)
}

/// Resolve the stable launcher executable path used for MCP configs, OS shortcuts,
/// and autostart entries (handling Linux AppImage / `OPENKEYLET_LAUNCHER_PATH` and
/// legacy `KRU_LAUNCHER_PATH`).
pub fn launcher_executable() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    if let Some(path) = validated_linux_launcher(
        std::env::var_os("OPENKEYLET_LAUNCHER_PATH")
            .or_else(|| std::env::var_os("KRU_LAUNCHER_PATH"))
            .map(PathBuf::from),
        std::env::var_os("APPIMAGE").map(PathBuf::from),
    ) {
        return Ok(path);
    }
    #[cfg(target_os = "linux")]
    if let Some(path) = std::env::var_os("APPIMAGE").map(PathBuf::from)
        && path.is_absolute()
        && path.is_file()
    {
        return Ok(path);
    }
    let current =
        std::env::current_exe().context("Unable to determine the OpenKeylet executable path")?;
    Ok(stable_launcher_executable(current))
}

pub(crate) fn stable_launcher_executable(current: PathBuf) -> PathBuf {
    let Some(parent) = current.parent() else {
        return current;
    };
    if !parent
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("deps"))
    {
        return current;
    }
    let Some(file_name) = current.file_name() else {
        return current;
    };
    let Some(release_dir) = parent.parent() else {
        return current;
    };
    let stable = release_dir.join(file_name);
    if stable.is_file() { stable } else { current }
}

#[cfg(target_os = "linux")]
fn validated_linux_launcher(
    candidate: Option<PathBuf>,
    appimage: Option<PathBuf>,
) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let candidate = candidate?;
    let appimage = appimage?;
    let metadata = candidate.metadata().ok()?;
    if !candidate.is_absolute()
        || !appimage.is_absolute()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o111 == 0
        || !appimage.is_file()
        || candidate.parent()?.canonicalize().ok()? != appimage.parent()?.canonicalize().ok()?
    {
        return None;
    }
    Some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_normalization_handles_regions_and_auto() {
        assert_eq!(normalize_language(""), "auto");
        assert_eq!(normalize_language("system"), "auto");
        assert_eq!(normalize_language("en-US"), "en");
        assert_eq!(normalize_language("zh_CN"), "zh");
        assert_eq!(normalize_language("zh-HK"), "zh-TW");
        assert_eq!(normalize_language("zh-Hant-TW"), "zh-TW");
        assert_eq!(normalize_language("ja-JP"), "ja");
        assert_eq!(normalize_language("ko_KR"), "ko");
        assert_eq!(normalize_language("es-MX"), "es");
        assert_eq!(normalize_ui_lang("auto"), "en");
        assert_eq!(normalize_ui_lang("zh-Hant"), "zh-TW");
    }

    #[test]
    fn development_binary_registers_the_stable_release_launcher() {
        let directory = tempfile::tempdir().unwrap();
        let release = directory.path().join("release");
        let deps = release.join("deps");
        std::fs::create_dir_all(&deps).unwrap();
        let stable = release.join(if cfg!(windows) {
            "openkeylet.exe"
        } else {
            "openkeylet"
        });
        let development = deps.join(if cfg!(windows) {
            "openkeylet.exe"
        } else {
            "openkeylet"
        });
        std::fs::write(&stable, "stable").unwrap();
        std::fs::write(&development, "development").unwrap();

        assert_eq!(stable_launcher_executable(development), stable);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn portable_launcher_must_be_executable_and_beside_appimage() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let launcher = directory.path().join("openkeylet");
        let appimage = directory.path().join("OpenKeylet.AppImage");
        std::fs::write(&launcher, "#!/bin/sh\n").unwrap();
        std::fs::write(&appimage, "appimage").unwrap();
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            validated_linux_launcher(Some(launcher.clone()), Some(appimage.clone())),
            Some(launcher.clone())
        );

        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            validated_linux_launcher(Some(launcher), Some(appimage)),
            None
        );
    }
}
