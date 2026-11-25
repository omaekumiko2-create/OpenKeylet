use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemIntegrationState {
    pub desktop_shortcut: bool,
    pub launch_at_login: bool,
}

pub fn status(executable: &Path) -> Result<SystemIntegrationState> {
    Ok(SystemIntegrationState {
        desktop_shortcut: desktop_shortcut_status(executable)?,
        launch_at_login: entry_or_legacy_exists(&autostart_entry_path()?),
    })
}

#[cfg(not(target_os = "macos"))]
pub fn set_desktop_shortcut(executable: &Path, enabled: bool) -> Result<SystemIntegrationState> {
    let path = desktop_entry_path(executable)?;
    set_entry(&path, executable, enabled, EntryKind::Desktop)?;
    remove_legacy_entry(&path)?;
    status(executable)
}

#[cfg(target_os = "macos")]
pub fn set_desktop_shortcut(executable: &Path, enabled: bool) -> Result<SystemIntegrationState> {
    if enabled {
        bail!(
            "macOS does not create desktop shortcuts; launch OpenKeylet from Applications, the Dock, or Spotlight"
        )
    }
    remove_entry(&desktop_entry_path(executable)?)?;
    status(executable)
}

pub fn set_launch_at_login(executable: &Path, enabled: bool) -> Result<SystemIntegrationState> {
    let path = autostart_entry_path()?;
    set_entry(&path, executable, enabled, EntryKind::Autostart)?;
    remove_legacy_entry(&path)?;
    status(executable)
}

/// Preserve existing opt-ins when upgrading from the KRU application.
pub fn migrate_legacy_entries(executable: &Path) -> Result<()> {
    #[cfg(not(target_os = "macos"))]
    if legacy_entry_path(&desktop_entry_path(executable)?).is_some_and(|path| entry_exists(&path)) {
        set_desktop_shortcut(executable, true)?;
    }
    if legacy_entry_path(&autostart_entry_path()?).is_some_and(|path| entry_exists(&path)) {
        set_launch_at_login(executable, true)?;
    }
    Ok(())
}

fn legacy_entry_path(path: &Path) -> Option<PathBuf> {
    let name = match path.file_name()?.to_str()? {
        "OpenKeylet.lnk" => "KRU.lnk",
        "OpenKeylet.desktop" => "KRU.desktop",
        "dev.openkeylet.app.plist" => "dev.kru.app.plist",
        _ => return None,
    };
    Some(path.with_file_name(name))
}

fn entry_or_legacy_exists(path: &Path) -> bool {
    entry_exists(path) || legacy_entry_path(path).is_some_and(|path| entry_exists(&path))
}

fn remove_legacy_entry(path: &Path) -> Result<()> {
    if let Some(path) = legacy_entry_path(path) {
        remove_entry(&path)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum EntryKind {
    #[cfg(not(target_os = "macos"))]
    Desktop,
    Autostart,
}

fn entry_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

#[cfg(not(target_os = "macos"))]
fn desktop_shortcut_status(executable: &Path) -> Result<bool> {
    Ok(entry_or_legacy_exists(&desktop_entry_path(executable)?))
}

#[cfg(target_os = "macos")]
fn desktop_shortcut_status(_executable: &Path) -> Result<bool> {
    Ok(false)
}

fn remove_entry(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            bail!(
                "Refusing to delete a non-shortcut directory:{}",
                path.display()
            )
        }
        Ok(_) => fs::remove_file(path)
            .with_context(|| format!("Unable to delete system entry:{}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("Unable to read system entry:{}", path.display()))
        }
    }
}

#[cfg(target_os = "windows")]
fn desktop_entry_path(_executable: &Path) -> Result<PathBuf> {
    Ok(dirs::desktop_dir()
        .context("Desktop directory not found")?
        .join("OpenKeylet.lnk"))
}

#[cfg(target_os = "windows")]
fn autostart_entry_path() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .context("Windows configuration directory not found")?
        .join("Microsoft/Windows/Start Menu/Programs/Startup/OpenKeylet.lnk"))
}

#[cfg(target_os = "windows")]
fn set_entry(path: &Path, executable: &Path, enabled: bool, _kind: EntryKind) -> Result<()> {
    if !enabled {
        return remove_entry(path);
    }
    create_windows_shortcut(path, executable)
}

#[cfg(target_os = "windows")]
fn create_windows_shortcut(path: &Path, executable: &Path) -> Result<()> {
    use windows::{
        Win32::{
            System::Com::{
                CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
                CoUninitialize, IPersistFile,
            },
            UI::Shell::{IShellLinkW, ShellLink},
        },
        core::{HSTRING, IUnknown, Interface},
    };

    let parent = path
        .parent()
        .context("Shortcut path is missing a parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("Unable to create shortcut directory:{}", parent.display()))?;
    let executable = executable
        .canonicalize()
        .with_context(|| format!("OpenKeylet executable not found:{}", executable.display()))?;
    let working_directory = executable
        .parent()
        .context("OpenKeylet executable path is missing a parent directory")?;
    let initialized = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.is_ok();
    let result = (|| -> Result<()> {
        let shell_link: IShellLinkW =
            unsafe { CoCreateInstance(&ShellLink, None::<&IUnknown>, CLSCTX_INPROC_SERVER) }
                .context("Could not create Windows shortcut")?;
        let executable_text = HSTRING::from(windows_shell_path(&executable));
        let working_text = HSTRING::from(windows_shell_path(working_directory));
        let arguments = HSTRING::from("gui");
        let description = HSTRING::from("OpenKeylet — local credential relay for AI agents");
        unsafe {
            shell_link.SetPath(&executable_text).context("SetPath")?;
            shell_link
                .SetWorkingDirectory(&working_text)
                .context("SetWorkingDirectory")?;
            shell_link
                .SetArguments(&arguments)
                .context("SetArguments")?;
            shell_link
                .SetDescription(&description)
                .context("SetDescription")?;
            shell_link
                .SetIconLocation(&executable_text, 0)
                .context("SetIconLocation")?;
            let persist: IPersistFile = shell_link.cast().context("IPersistFile")?;
            let path_text = HSTRING::from(windows_shell_path(path));
            persist
                .Save(&path_text, true)
                .context("IPersistFile::Save")?;
        }
        Ok(())
    })();
    if initialized {
        unsafe { CoUninitialize() };
    }
    result.with_context(|| format!("Could not write shortcut:{}", path.display()))
}

#[cfg(target_os = "windows")]
fn windows_shell_path(path: &Path) -> String {
    crate::platform::strip_windows_verbatim_prefix(path)
}

#[cfg(target_os = "macos")]
fn desktop_entry_path(executable: &Path) -> Result<PathBuf> {
    let name = if macos_app_bundle(executable).is_some() {
        "OpenKeylet.app"
    } else {
        "OpenKeylet"
    };
    Ok(dirs::desktop_dir()
        .context("Desktop directory not found")?
        .join(name))
}

#[cfg(target_os = "macos")]
fn autostart_entry_path() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .context("Could not find user directory")?
        .join("Library/LaunchAgents/dev.openkeylet.app.plist"))
}

#[cfg(target_os = "macos")]
fn macos_app_bundle(executable: &Path) -> Option<PathBuf> {
    crate::platform::macos_app_bundle(executable)
}

#[cfg(target_os = "macos")]
fn set_entry(path: &Path, executable: &Path, enabled: bool, kind: EntryKind) -> Result<()> {
    if !enabled {
        return remove_entry(path);
    }
    let parent = path
        .parent()
        .context("System entry path is missing a parent directory")?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "Could not create system entry directory:{}",
            parent.display()
        )
    })?;
    remove_entry(path)?;
    match kind {
        EntryKind::Autostart => {
            let executable = xml_escape(executable.to_string_lossy().as_ref());
            let content = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>dev.openkeylet.app</string>\n  <key>ProgramArguments</key><array><string>{executable}</string><string>gui</string></array>\n  <key>RunAtLoad</key><true/>\n</dict>\n</plist>\n"
            );
            fs::write(path, content).with_context(|| {
                format!(
                    "Could not write login startup configuration:{}",
                    path.display()
                )
            })
        }
    }
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(target_os = "linux")]
pub fn ensure_application_entry(executable: &Path) -> Result<()> {
    let path = dirs::data_dir()
        .context("Could not find Linux application data directory")?
        .join("applications/openkeylet.desktop");
    set_entry(&path, executable, true, EntryKind::Desktop)
}

#[cfg(target_os = "linux")]
fn desktop_entry_path(_executable: &Path) -> Result<PathBuf> {
    Ok(dirs::desktop_dir()
        .context("Desktop directory not found")?
        .join("OpenKeylet.desktop"))
}

#[cfg(target_os = "linux")]
fn autostart_entry_path() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .context("Could not find Linux configuration directory")?
        .join("autostart/OpenKeylet.desktop"))
}

#[cfg(target_os = "linux")]
fn set_entry(path: &Path, executable: &Path, enabled: bool, _kind: EntryKind) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if !enabled {
        return remove_entry(path);
    }
    let parent = path
        .parent()
        .context("System entry path is missing a parent directory")?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "Could not create system entry directory:{}",
            parent.display()
        )
    })?;
    let icon_path = dirs::data_dir()
        .context("Could not find Linux application data directory")?
        .join("icons/hicolor/256x256/apps/openkeylet.png");
    fs::create_dir_all(
        icon_path
            .parent()
            .context("Icon path is missing a parent directory")?,
    )?;
    write_if_changed(&icon_path, include_bytes!("../icons/128x128@2x.png"))?;
    let executable_path = executable.to_string_lossy();
    let command = desktop_exec_quote(&executable_path);
    let try_exec = desktop_entry_value(&executable_path);
    let icon = desktop_entry_value(icon_path.to_string_lossy().as_ref());
    let content = format!(
        "[Desktop Entry]\nType=Application\nVersion=1.0\nName=OpenKeylet\nComment=Local credential relay for AI agents\nExec=env GDK_BACKEND=wayland,x11 {command} gui\nTryExec={try_exec}\nIcon={icon}\nStartupWMClass=openkeylet\nTerminal=false\nCategories=Utility;Security;\n"
    );
    write_if_changed(path, content.as_bytes())
        .with_context(|| format!("Could not write system entry:{}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("Could not set system entry permissions:{}", path.display()))
}

#[cfg(target_os = "linux")]
fn write_if_changed(path: &Path, content: &[u8]) -> Result<()> {
    if fs::read(path).is_ok_and(|current| current == content) {
        return Ok(());
    }
    fs::write(path, content)
        .with_context(|| format!("Could not write application resource:{}", path.display()))
}

#[cfg(target_os = "linux")]
fn desktop_entry_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(target_os = "linux")]
fn desktop_exec_quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('`', "\\`")
            .replace('$', "\\$")
            .replace('%', "%%")
    )
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
compile_error!("OpenKeylet system integration is only supported on Windows, macOS, and Linux");

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::create_windows_shortcut;

    #[test]
    fn creates_a_real_windows_shortcut() {
        let directory = tempfile::tempdir().unwrap();
        let shortcut = directory.path().join("OpenKeylet.lnk");
        create_windows_shortcut(&shortcut, &std::env::current_exe().unwrap()).unwrap();
        assert!(shortcut.is_file());
    }
}
