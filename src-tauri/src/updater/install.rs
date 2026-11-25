use super::*;

pub fn apply_staged_package(executable: &Path, staged_root: &Path) -> Result<()> {
    validate_staged_package_root(staged_root)?;

    #[cfg(target_os = "windows")]
    {
        let install_dir = executable
            .parent()
            .context("Unable to determine Windows install directory")?;
        let new_exe = staged_root.join("openkeylet.exe");
        replace_file_with_windows_backup(executable, &new_exe)?;
        sync_optional_portable_extras(staged_root, install_dir)?;
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let target_app = macos_app_bundle(executable)
            .context("UPDATE_INSTALL_BLOCKED: OpenKeylet must be running from OpenKeylet.app to self-update on macOS")?;
        let parent_dir = target_app
            .parent()
            .context("Unable to determine macOS Applications directory")?;
        let staged_app = staged_root.join("OpenKeylet.app");
        let temp_new = parent_dir.join(format!("OpenKeylet.app.new.{}", std::process::id()));
        let backup_old = parent_dir.join(format!("OpenKeylet.app.old.{}", std::process::id()));
        if temp_new.exists() {
            let _ = fs::remove_dir_all(&temp_new);
        }
        let copy_status = Command::new("/usr/bin/ditto")
            .arg(&staged_app)
            .arg(&temp_new)
            .status()
            .context("Unable to copy staged macOS app bundle")?;
        if !copy_status.success() {
            let _ = fs::remove_dir_all(&temp_new);
            bail!("UPDATE_INSTALL_FAILED: Failed to stage OpenKeylet.app into installation directory");
        }
        if backup_old.exists() {
            let _ = fs::remove_dir_all(&backup_old);
        }
        fs::rename(&target_app, &backup_old)
            .context("UPDATE_INSTALL_FAILED: Unable to move current OpenKeylet.app aside")?;
        if let Err(error) = fs::rename(&temp_new, &target_app) {
            let _ = fs::rename(&backup_old, &target_app);
            let _ = fs::remove_dir_all(&temp_new);
            return Err(error)
                .context("UPDATE_INSTALL_FAILED: Unable to place updated OpenKeylet.app");
        }
        let _ = fs::remove_dir_all(&backup_old);
        sync_optional_portable_extras(staged_root, parent_dir)?;
        return Ok(());
    }

    #[cfg(all(target_os = "linux", feature = "gui"))]
    {
        let install_dir = executable
            .parent()
            .context("Unable to determine Linux install directory")?;
        let target_appimage = std::env::var_os("APPIMAGE")
            .map(PathBuf::from)
            .filter(|path| path.is_file())
            .unwrap_or_else(|| {
                if executable
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("AppImage"))
                {
                    executable.to_path_buf()
                } else {
                    install_dir.join("OpenKeylet.AppImage")
                }
            });
        replace_unix_executable(&target_appimage, &staged_root.join("OpenKeylet.AppImage"))?;
        let staged_launcher = staged_root.join("openkeylet");
        let target_launcher = install_dir.join("openkeylet");
        if staged_launcher.is_file() && target_launcher.is_file() {
            replace_unix_executable(&target_launcher, &staged_launcher)?;
        }
        sync_optional_portable_extras(staged_root, install_dir)?;
        return Ok(());
    }

    #[cfg(all(target_os = "linux", not(feature = "gui")))]
    {
        let install_dir = executable
            .parent()
            .context("Unable to determine Linux headless install directory")?;
        replace_unix_executable(executable, &staged_root.join("openkeylet"))?;
        sync_optional_portable_extras(staged_root, install_dir)?;
        return Ok(());
    }
}

#[cfg(target_os = "windows")]
fn replace_file_with_windows_backup(target: &Path, staged_file: &Path) -> Result<()> {
    let parent = target
        .parent()
        .context("Missing parent directory for target executable")?;
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("openkeylet.exe");
    let temp_new = parent.join(format!("{file_name}.new.{}", std::process::id()));
    let backup_old = parent.join(format!(
        "{file_name}.old.{}.{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));

    fs::copy(staged_file, &temp_new)
        .context("UPDATE_INSTALL_FAILED: Unable to stage updated executable in install folder")?;
    if target.exists() {
        fs::rename(target, &backup_old).map_err(|error| {
            let _ = fs::remove_file(&temp_new);
            anyhow!("UPDATE_INSTALL_FAILED: Unable to move running executable aside: {error}")
        })?;
    }
    if let Err(error) = fs::rename(&temp_new, target) {
        if backup_old.exists() {
            let _ = fs::rename(&backup_old, target);
        }
        let _ = fs::remove_file(&temp_new);
        bail!("UPDATE_INSTALL_FAILED: Unable to move updated executable into place: {error}");
    }
    // Best effort removal; if current or child MCP process still holds it, next launch cleans it up.
    let _ = fs::remove_file(&backup_old);
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn replace_unix_executable(target: &Path, staged_file: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let parent = target
        .parent()
        .context("Missing parent directory for target executable")?;
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("openkeylet");
    let temp_new = parent.join(format!(".{file_name}.new.{}", std::process::id()));
    fs::copy(staged_file, &temp_new)
        .context("UPDATE_INSTALL_FAILED: Unable to copy updated executable")?;
    fs::set_permissions(&temp_new, fs::Permissions::from_mode(0o755))
        .context("UPDATE_INSTALL_FAILED: Unable to mark updated executable runnable")?;
    if let Err(error) = fs::rename(&temp_new, target) {
        let _ = fs::remove_file(&temp_new);
        return Err(error)
            .context("UPDATE_INSTALL_FAILED: Unable to atomically replace executable");
    }
    Ok(())
}

fn sync_optional_portable_extras(staged_root: &Path, install_dir: &Path) -> Result<()> {
    // Sync browser-extension folder when present in the portable install directory.
    let staged_ext = staged_root.join("browser-extension");
    let target_ext = install_dir.join("browser-extension");
    if staged_ext.is_dir() && target_ext.is_dir() {
        let temp_ext = install_dir.join(format!("browser-extension.new.{}", std::process::id()));
        let backup_ext = install_dir.join(format!(
            "browser-extension.old.{}",
            uuid::Uuid::new_v4().simple()
        ));
        if temp_ext.exists() {
            let _ = fs::remove_dir_all(&temp_ext);
        }
        copy_dir_recursive(&staged_ext, &temp_ext)?;
        if fs::rename(&target_ext, &backup_ext).is_ok() {
            if fs::rename(&temp_ext, &target_ext).is_err() {
                let _ = fs::rename(&backup_ext, &target_ext);
                let _ = fs::remove_dir_all(&temp_ext);
            } else {
                let _ = fs::remove_dir_all(&backup_ext);
            }
        } else {
            let _ = fs::remove_dir_all(&temp_ext);
        }
    }

    // Refresh bundled documentation files only if they already exist in install_dir.
    for file_name in [
        "README.md",
        "README.zh-CN.md",
        "SECURITY.md",
        "SECURITY.zh-CN.md",
        "LICENSE",
        "SHA256SUMS.txt",
    ] {
        let src = staged_root.join(file_name);
        let dst = install_dir.join(file_name);
        if src.is_file() && dst.is_file() {
            let _ = fs::copy(&src, &dst);
        }
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let target = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

