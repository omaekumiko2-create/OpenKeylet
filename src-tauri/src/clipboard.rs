use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tauri::AppHandle;
use tauri_plugin_clipboard_manager::ClipboardExt;

pub const SENSITIVE_CLIPBOARD_TTL_SECS: u64 = 30;

#[derive(Default)]
pub struct ClipboardGuard {
    generation: AtomicU64,
    active_hash: Mutex<Option<[u8; 32]>>,
}

impl ClipboardGuard {
    pub fn new() -> Self {
        Self::default()
    }

    fn record_sensitive(&self, value: &str) -> u64 {
        let hash = sha256_bytes(value);
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        if let Ok(mut active) = self.active_hash.lock() {
            *active = Some(hash);
        }
        generation
    }

    fn clear_tracking(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut active) = self.active_hash.lock() {
            *active = None;
        }
    }

    fn expected_hash(&self, expected_generation: Option<u64>) -> Option<[u8; 32]> {
        if let Some(generation) = expected_generation
            && self.generation.load(Ordering::Acquire) != generation
        {
            return None;
        }
        self.active_hash.lock().ok().and_then(|active| *active)
    }

    fn take_if_still_active(&self, expected_generation: Option<u64>) -> Option<[u8; 32]> {
        if let Some(generation) = expected_generation
            && self.generation.load(Ordering::Acquire) != generation
        {
            return None;
        }
        self.active_hash.lock().ok().and_then(|mut active| active.take())
    }
}

pub fn sha256_bytes(value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hasher.finalize().into()
}

pub fn should_clear_clipboard(current: Option<&str>, expected_hash: [u8; 32]) -> bool {
    let Some(current) = current else {
        return false;
    };
    if current.is_empty() {
        return false;
    }
    sha256_bytes(current) == expected_hash
}

pub fn write_text(
    app: &AppHandle,
    guard: &Arc<ClipboardGuard>,
    value: &str,
    sensitive: bool,
    ttl_secs: u64,
) -> Result<()> {
    if !sensitive {
        guard.clear_tracking();
        app.clipboard()
            .write_text(value)
            .context("Unable to write to clipboard")?;
        return Ok(());
    }

    write_sensitive_platform(app, value)?;
    let generation = guard.record_sensitive(value);
    if ttl_secs > 0 {
        let app = app.clone();
        let guard = Arc::clone(guard);
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_secs(ttl_secs)).await;
            clear_if_unchanged(&app, &guard, Some(generation));
        });
    }
    Ok(())
}

pub fn clear_if_unchanged(
    app: &AppHandle,
    guard: &ClipboardGuard,
    expected_generation: Option<u64>,
) -> bool {
    let Some(expected_hash) = guard.expected_hash(expected_generation) else {
        return false;
    };
    let current = app.clipboard().read_text().ok();
    if !should_clear_clipboard(current.as_deref(), expected_hash) {
        let _ = guard.take_if_still_active(expected_generation);
        return false;
    }
    let _ = guard.take_if_still_active(expected_generation);
    clear_platform_clipboard(app)
}

pub fn read_text(app: &AppHandle) -> Result<String> {
    app.clipboard()
        .read_text()
        .context("Unable to read text from clipboard")
}

pub fn clear_if_exact(app: &AppHandle, guard: &ClipboardGuard, expected_text: &str) -> bool {
    if expected_text.is_empty() {
        return false;
    }
    let expected_hash = sha256_bytes(expected_text);
    let current = app.clipboard().read_text().ok();
    if !should_clear_clipboard(current.as_deref(), expected_hash) {
        return false;
    }
    guard.clear_tracking();
    clear_platform_clipboard(app)
}

fn clear_platform_clipboard(app: &AppHandle) -> bool {
    #[cfg(windows)]
    {
        if clear_windows_clipboard().is_ok() {
            return true;
        }
    }
    app.clipboard().write_text("").is_ok()
}

fn write_sensitive_platform(app: &AppHandle, value: &str) -> Result<()> {
    #[cfg(windows)]
    {
        if write_windows_sensitive_clipboard(value).is_ok() {
            return Ok(());
        }
    }
    app.clipboard()
        .write_text(value)
        .context("Unable to write sensitive value to clipboard")
}

#[cfg(windows)]
fn encode_utf16_nul(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn open_windows_clipboard() -> Result<()> {
    use windows::Win32::System::DataExchange::OpenClipboard;

    for attempt in 0..5 {
        if unsafe { OpenClipboard(None) }.is_ok() {
            return Ok(());
        }
        if attempt < 4 {
            std::thread::sleep(Duration::from_millis(15));
        }
    }
    anyhow::bail!("Unable to open Windows clipboard")
}

#[cfg(windows)]
fn clear_windows_clipboard() -> Result<()> {
    use windows::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard};

    open_windows_clipboard()?;
    let result = unsafe { EmptyClipboard() }.context("Unable to empty Windows clipboard");
    let _ = unsafe { CloseClipboard() };
    result
}

#[cfg(windows)]
fn set_windows_clipboard_bytes(format: u32, bytes: &[u8]) -> Result<()> {
    use windows::Win32::{
        Foundation::{GlobalFree, HANDLE},
        System::{
            DataExchange::SetClipboardData,
            Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock},
        },
    };

    let alloc = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes.len()) }
        .context("Unable to allocate Windows clipboard buffer")?;
    let ptr = unsafe { GlobalLock(alloc) };
    if ptr.is_null() {
        let _ = unsafe { GlobalFree(Some(alloc)) };
        anyhow::bail!("Unable to lock Windows clipboard buffer");
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len());
        let _ = GlobalUnlock(alloc);
    }
    if unsafe { SetClipboardData(format, Some(HANDLE(alloc.0))) }.is_err() {
        let _ = unsafe { GlobalFree(Some(alloc)) };
        anyhow::bail!("Unable to set Windows clipboard data");
    }
    Ok(())
}

#[cfg(windows)]
fn write_windows_sensitive_clipboard(value: &str) -> Result<()> {
    use windows::{
        Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, RegisterClipboardFormatW},
        core::PCWSTR,
    };

    const CF_UNICODETEXT: u32 = 13;
    const EXCLUDE_MONITOR: &str = "ExcludeClipboardContentFromMonitorProcessing";
    const CAN_HISTORY: &str = "CanIncludeInClipboardHistory";
    const CAN_CLOUD: &str = "CanUploadToCloudClipboard";

    let utf16 = encode_utf16_nul(value);
    let text_bytes =
        unsafe { std::slice::from_raw_parts(utf16.as_ptr().cast::<u8>(), utf16.len() * 2) };
    let zero_dword = 0_u32.to_ne_bytes();

    open_windows_clipboard()?;
    let write_result = (|| -> Result<()> {
        unsafe { EmptyClipboard() }.context("Unable to empty Windows clipboard")?;
        set_windows_clipboard_bytes(CF_UNICODETEXT, text_bytes)?;

        for name in [EXCLUDE_MONITOR, CAN_HISTORY, CAN_CLOUD] {
            let wide = encode_utf16_nul(name);
            let format = unsafe { RegisterClipboardFormatW(PCWSTR(wide.as_ptr())) };
            if format != 0 {
                let _ = set_windows_clipboard_bytes(format, &zero_dword);
            }
        }
        Ok(())
    })();
    let _ = unsafe { CloseClipboard() };
    write_result
}

#[cfg(test)]
mod tests {
    use super::{ClipboardGuard, sha256_bytes, should_clear_clipboard};

    #[test]
    fn sensitive_clipboard_only_clears_when_content_is_unchanged() {
        let secret = "S3cr3t!Pass#2026";
        let expected = sha256_bytes(secret);

        assert!(should_clear_clipboard(Some(secret), expected));
        assert!(!should_clear_clipboard(Some("user copied something else"), expected));
        assert!(!should_clear_clipboard(Some(""), expected));
        assert!(!should_clear_clipboard(None, expected));
    }

    #[test]
    fn newer_copy_supersedes_previous_generation() {
        let guard = ClipboardGuard::new();
        let gen1 = guard.record_sensitive("first-secret");
        let gen2 = guard.record_sensitive("second-secret");

        assert!(guard.expected_hash(Some(gen1)).is_none());
        assert_eq!(
            guard.expected_hash(Some(gen2)),
            Some(sha256_bytes("second-secret"))
        );

        guard.clear_tracking();
        assert!(guard.expected_hash(Some(gen2)).is_none());
        assert!(guard.expected_hash(None).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn windows_utf16_encoder_terminates_unicode_strings() {
        let encoded = super::encode_utf16_nul("密码-🔑");
        assert_eq!(encoded.last(), Some(&0));
        let decoded = String::from_utf16(&encoded[..encoded.len() - 1]).unwrap();
        assert_eq!(decoded, "密码-🔑");
    }
}
