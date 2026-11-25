use super::*;

#[tauri::command]
pub(crate) async fn update_settings(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    patch: SettingsPatch,
) -> Result<crate::model::Settings, String> {
    require_owner_unlocked(&runtime).await?;
    let enabling_browser = patch.browser_enabled == Some(true);
    let enabling_auto_download = patch.update_auto_download == Some(true);
    let settings = runtime
        .vault
        .update_settings_patch(patch)
        .map_err(command_error)?;
    runtime.browser.sync().await;
    let effective_theme = runtime.tray_menu.current_theme();
    let effective_language = runtime.tray_menu.resolve_language(&settings.language);
    runtime
        .browser
        .sync_appearance(Some(effective_theme), Some(effective_language))
        .await;
    if enabling_browser && settings.browser_enabled {
        let _ = runtime.browser.start_quick_pairing().await;
    }
    let update_status = runtime.updater.refresh_settings().await;
    emit_update_status(&app, &update_status);
    if enabling_auto_download
        && update_status.phase == "available"
        && update_status.can_auto_install
    {
        let updater = runtime.updater.clone();
        let handle = app.clone();
        tauri::async_runtime::spawn(async move {
            let emit_handle = handle.clone();
            let _ = updater
                .download_and_stage(move |status| {
                    emit_update_status(&emit_handle, status);
                })
                .await;
        });
    }
    emit_changed(&app);
    Ok(settings)
}

#[tauri::command]
pub(crate) fn system_integration_status(
    runtime: State<'_, AppRuntime>,
) -> Result<crate::system_integration::SystemIntegrationState, String> {
    crate::system_integration::status(PathBuf::from(&runtime.executable).as_path())
        .map_err(command_error)
}

#[tauri::command]
pub(crate) async fn set_desktop_shortcut(
    runtime: State<'_, AppRuntime>,
    enabled: bool,
) -> Result<crate::system_integration::SystemIntegrationState, String> {
    require_owner_unlocked(&runtime).await?;
    crate::system_integration::set_desktop_shortcut(
        PathBuf::from(&runtime.executable).as_path(),
        enabled,
    )
    .map_err(command_error)
}

#[tauri::command]
pub(crate) async fn set_launch_at_login(
    runtime: State<'_, AppRuntime>,
    enabled: bool,
) -> Result<crate::system_integration::SystemIntegrationState, String> {
    require_owner_unlocked(&runtime).await?;
    crate::system_integration::set_launch_at_login(
        PathBuf::from(&runtime.executable).as_path(),
        enabled,
    )
    .map_err(command_error)
}

#[tauri::command]
pub(crate) async fn delete_activity(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: String,
) -> Result<bool, String> {
    require_owner_unlocked(&runtime).await?;
    let id = Uuid::parse_str(&id).map_err(|_| "Invalid activity id".to_owned())?;
    let removed = runtime.vault.delete_activity(id).map_err(command_error)?;
    if removed {
        emit_changed(&app);
    }
    Ok(removed)
}

#[tauri::command]
pub(crate) async fn delete_activities(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    ids: Vec<String>,
) -> Result<usize, String> {
    require_owner_unlocked(&runtime).await?;
    let mut parsed = Vec::with_capacity(ids.len());
    for raw in ids {
        parsed.push(Uuid::parse_str(&raw).map_err(|_| "Invalid activity id".to_owned())?);
    }
    let removed = runtime
        .vault
        .delete_activities(&parsed)
        .map_err(command_error)?;
    if removed > 0 {
        emit_changed(&app);
    }
    Ok(removed)
}

#[tauri::command]
pub(crate) async fn clear_activities(app: AppHandle, runtime: State<'_, AppRuntime>) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime.vault.clear_activities().map_err(command_error)?;
    emit_changed(&app);
    Ok(())
}

#[tauri::command]
pub(crate) async fn copy_mcp_config(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    format: String,
) -> Result<String, String> {
    require_owner_unlocked(&runtime).await?;
    let config = mcp::render_config(&format).map_err(command_error)?;
    clipboard::write_text(&app, &runtime.clipboard, &config, false, 0).map_err(command_error)?;
    Ok(config)
}

#[tauri::command]
pub(crate) async fn agent_mcp_status(
    runtime: State<'_, AppRuntime>,
) -> Result<Vec<AgentClientStatus>, String> {
    Ok(runtime.agent_registry.list().await)
}

#[tauri::command]
pub(crate) async fn agent_mcp_register(
    runtime: State<'_, AppRuntime>,
    client_ids: Vec<String>,
) -> Result<Vec<AgentActionResult>, String> {
    require_owner_unlocked(&runtime).await?;
    Ok(runtime.agent_registry.register(&client_ids).await)
}

#[tauri::command]
pub(crate) async fn agent_mcp_repair(
    runtime: State<'_, AppRuntime>,
    client_id: String,
) -> Result<AgentActionResult, String> {
    require_owner_unlocked(&runtime).await?;
    Ok(runtime.agent_registry.repair(&client_id).await)
}

#[tauri::command]
pub(crate) async fn agent_mcp_remove(
    runtime: State<'_, AppRuntime>,
    client_id: String,
) -> Result<AgentActionResult, String> {
    require_owner_unlocked(&runtime).await?;
    Ok(runtime.agent_registry.remove(&client_id).await)
}

#[tauri::command]
pub(crate) async fn choose_private_key(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<Option<String>, String> {
    require_owner_unlocked(&runtime).await?;
    let selected = app
        .dialog()
        .file()
        .add_filter("SSH private key", &["pem", "key", "ppk", "txt"])
        .blocking_pick_file();
    let Some(path) = selected else {
        return Ok(None);
    };
    let path = path.into_path().map_err(command_error)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("SSH KEY")
        .to_owned();
    *runtime.pending_private_key.lock().await = Some(path);
    Ok(Some(name))
}


pub(crate) async fn arm_browser_pairing(app: &AppHandle, runtime: &AppRuntime) {
    if let Ok(settings) = runtime.vault.settings()
        && !settings.browser_enabled
    {
        let _ = runtime.vault.update_settings_patch(SettingsPatch {
            browser_enabled: Some(true),
            ..SettingsPatch::default()
        });
    }
    runtime.browser.sync().await;
    let _ = runtime.browser.start_quick_pairing().await;
    emit_changed(app);
}

#[tauri::command]
pub(crate) async fn quick_pair_browser(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    port: u16,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .vault
        .update_settings_patch(SettingsPatch {
            browser_enabled: Some(true),
            browser_port: Some(port),
            ..SettingsPatch::default()
        })
        .map_err(command_error)?;
    runtime.browser.sync().await;
    runtime
        .browser
        .start_quick_pairing()
        .await
        .map_err(command_error)?;

    emit_changed(&app);

    Ok(())
}

#[tauri::command]
pub(crate) fn open_chrome_browser(profile_directory: Option<String>) -> Result<(), String> {
    let profile = match profile_directory {
        Some(dir) if !dir.trim().is_empty() => {
            if !is_valid_chrome_profile_dir(&dir) {
                return Err("Invalid Chrome profile directory".to_owned());
            }
            Some(dir)
        }
        _ => None,
    };
    #[cfg(windows)]
    {
        let mut candidates = Vec::new();
        for root in ["LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)"] {
            if let Some(root) = std::env::var_os(root) {
                let base = PathBuf::from(root);
                candidates.push(base.join("Google/Chrome/Application/chrome.exe"));
                if profile.is_none() {
                    candidates.push(base.join("Microsoft/Edge/Application/msedge.exe"));
                    candidates
                        .push(base.join("BraveSoftware/Brave-Browser/Application/brave.exe"));
                    candidates.push(base.join("Chromium/Application/chrome.exe"));
                }
            }
        }
        candidates.push(PathBuf::from("chrome.exe"));
        if profile.is_none() {
            candidates.push(PathBuf::from("msedge.exe"));
            candidates.push(PathBuf::from("brave.exe"));
        }
        if candidates.into_iter().any(|candidate| {
            if candidate.components().count() != 1 && !candidate.is_file() {
                return false;
            }
            let mut command = Command::new(candidate);
            if let Some(ref dir) = profile {
                command.arg(format!("--profile-directory={dir}"));
            }
            command.arg("--new-tab").spawn().is_ok()
        }) {
            return Ok(());
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(ref dir) = profile {
            let mut binaries = vec![PathBuf::from(
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            )];
            if let Some(home) = std::env::var_os("HOME") {
                binaries.push(
                    PathBuf::from(home)
                        .join("Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
                );
            }
            if binaries.into_iter().any(|binary| {
                binary.is_file()
                    && Command::new(binary)
                        .arg(format!("--profile-directory={dir}"))
                        .arg("--new-tab")
                        .spawn()
                        .is_ok()
            }) {
                return Ok(());
            }
            if Command::new("open")
                .args([
                    "-a",
                    "Google Chrome",
                    "--args",
                    &format!("--profile-directory={dir}"),
                    "--new-tab",
                ])
                .status()
                .is_ok_and(|status| status.success())
            {
                return Ok(());
            }
        } else {
            for app in ["Google Chrome", "Microsoft Edge", "Brave Browser", "Arc", "Chromium"] {
                if Command::new("open")
                    .args(["-a", app])
                    .status()
                    .is_ok_and(|status| status.success())
                {
                    return Ok(());
                }
            }
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let browsers: &[&str] = if profile.is_some() {
            &["google-chrome", "google-chrome-stable"]
        } else {
            &[
                "google-chrome",
                "google-chrome-stable",
                "microsoft-edge",
                "brave-browser",
                "chromium",
                "chromium-browser",
            ]
        };
        if browsers.iter().any(|browser| {
            let mut command = Command::new(browser);
            if let Some(ref dir) = profile {
                command.arg(format!("--profile-directory={dir}"));
            }
            command.arg("--new-tab").spawn().is_ok()
        }) {
            return Ok(());
        }
    }
    Err("Unable to open Chrome; open it manually and paste the copied address".to_owned())
}

#[tauri::command]
pub(crate) async fn test_browser_bridge(
    runtime: State<'_, AppRuntime>,
) -> Result<serde_json::Value, String> {
    require_owner_unlocked(&runtime).await?;
    runtime.browser.sync().await;
    runtime
        .browser
        .inspect_page(None, None)
        .await
        .map_err(command_error)
}

#[tauri::command]
pub(crate) async fn reset_browser_pairing(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .browser
        .reset_pairing()
        .await
        .map_err(command_error)?;
    emit_changed(&app);
    Ok(())
}

#[tauri::command]
pub(crate) async fn reload_browser_extension(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<usize, String> {
    require_owner_unlocked(&runtime).await?;
    let reloaded = runtime
        .browser
        .reload_extensions()
        .await
        .map_err(command_error)?;
    emit_changed(&app);
    Ok(reloaded)
}

#[tauri::command]
pub(crate) async fn open_browser_extension_folder(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    arm_browser_pairing(&app, &runtime).await;
    let path = browser_extension_path(&app)?;
    app.opener()
        .open_path(path.to_string_lossy(), None::<&str>)
        .map_err(command_error)
}

#[tauri::command]
pub(crate) async fn drag_browser_extension(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    window: WebviewWindow,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    let path = browser_extension_path(&app)?;
    let pair_app = app.clone();
    tauri::async_runtime::spawn(async move {
        let runtime = pair_app.state::<AppRuntime>();
        arm_browser_pairing(&pair_app, &runtime).await;
    });
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let drag_window = window.clone();
    window
        .run_on_main_thread(move || {
            let result = (|| -> Result<(), String> {
                #[cfg(target_os = "linux")]
                let native = drag_window.gtk_window().map_err(command_error)?;
                #[cfg(target_os = "linux")]
                let handle = &native;
                #[cfg(not(target_os = "linux"))]
                let handle = &drag_window;
                drag::start_drag(
                    handle,
                    drag::DragItem::Files(vec![path]),
                    drag::Image::Raw(include_bytes!("../../icons/32x32.png").to_vec()),
                    |_, _| {},
                    drag::Options::default(),
                )
                .map_err(command_error)
            })();
            let _ = sender.send(result);
        })
        .map_err(command_error)?;
    receiver.await.map_err(command_error)?
}

pub(crate) fn browser_extension_path(app: &AppHandle) -> Result<PathBuf, String> {
    let bundled = app
        .path()
        .resource_dir()
        .ok()
        .map(|path| path.join("browser-extension"))
        .filter(|path| path.is_dir());
    let executable = crate::platform::launcher_executable().map_err(command_error)?;
    let portable = executable
        .parent()
        .map(|path| path.join("browser-extension"))
        .filter(|path| path.is_dir());
    let development = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|path| path.join("browser-extension"))
        .filter(|path| path.is_dir());
    let path = portable.or(bundled).or(development).ok_or_else(|| {
        "browser-extension directory not found; use the complete portable ZIP".to_owned()
    })?;
    Ok(path)
}


#[tauri::command]
pub(crate) async fn github_backup_status(runtime: State<'_, AppRuntime>) -> Result<BackupStatus, String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .github_backup
        .lock()
        .await
        .status()
        .map_err(command_error)
}

#[tauri::command]
pub(crate) async fn github_backup_account(
    runtime: State<'_, AppRuntime>,
    input: github_backup::AuthInput,
) -> Result<github_backup::AccountStatus, String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .github_backup
        .lock()
        .await
        .account(input)
        .await
        .map_err(command_error)
}

#[tauri::command]
pub(crate) async fn github_backup_recovery_key(runtime: State<'_, AppRuntime>) -> Result<String, String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .github_backup
        .lock()
        .await
        .recovery_key()
        .map_err(command_error)
}

#[tauri::command]
pub(crate) async fn github_backup_connect(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    input: ConnectInput,
) -> Result<BackupStatus, String> {
    require_owner_unlocked(&runtime).await?;
    // A version prepared from the previous repository must not be restored into this one.
    *runtime.pending_history_restore.lock().await = None;
    let status = runtime
        .github_backup
        .lock()
        .await
        .connect(input)
        .await
        .map_err(command_error)?;
    emit_changed(&app);
    Ok(status)
}

#[tauri::command]
pub(crate) async fn github_backup_upload(runtime: State<'_, AppRuntime>) -> Result<BackupStatus, String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .github_backup
        .lock()
        .await
        .upload()
        .await
        .map_err(command_error)
}

#[tauri::command]
pub(crate) async fn github_backup_restore(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<RestoreResult, String> {
    require_owner_unlocked(&runtime).await?;
    let result = runtime
        .github_backup
        .lock()
        .await
        .restore()
        .await
        .map_err(command_error)?;
    emit_changed(&app);
    Ok(result)
}

#[tauri::command]
pub(crate) async fn github_backup_sync(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<SyncResult, String> {
    require_owner_unlocked(&runtime).await?;
    let result = runtime
        .github_backup
        .lock()
        .await
        .sync()
        .await
        .map_err(command_error)?;
    if result.merge.added > 0 || result.merge.updated > 0 || result.merge.deleted > 0 {
        emit_changed(&app);
    }
    Ok(result)
}

#[tauri::command]
pub(crate) async fn github_backup_set_auto_sync(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    enabled: bool,
) -> Result<BackupStatus, String> {
    require_owner_unlocked(&runtime).await?;
    let status = runtime
        .github_backup
        .lock()
        .await
        .set_auto_sync(enabled)
        .map_err(command_error)?;
    if enabled {
        schedule_auto_sync(&app, 100);
    }
    Ok(status)
}

#[tauri::command]
pub(crate) async fn github_backup_disconnect(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<BackupStatus, String> {
    require_owner_unlocked(&runtime).await?;
    *runtime.pending_history_restore.lock().await = None;
    let status = runtime
        .github_backup
        .lock()
        .await
        .disconnect()
        .map_err(command_error)?;
    emit_changed(&app);
    Ok(status)
}

/// A prepared version stays restorable for as long as an `.mvault` preview does.
const HISTORY_PREVIEW_TTL_SECS: u64 = 300;

#[tauri::command]
pub(crate) async fn github_backup_history(
    runtime: State<'_, AppRuntime>,
    page: Option<u32>,
) -> Result<github_backup::VersionList, String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .github_backup
        .lock()
        .await
        .list_versions(page.unwrap_or(1))
        .await
        .map_err(command_error)
}

/// Fetches and decrypts one version and returns what restoring from it would change.
/// Read-only: nothing in the vault or the repository changes until the commit.
#[tauri::command]
pub(crate) async fn github_backup_history_prepare(
    runtime: State<'_, AppRuntime>,
    sha: String,
) -> Result<serde_json::Value, String> {
    require_owner_unlocked(&runtime).await?;
    *runtime.pending_history_restore.lock().await = None;
    let sha = sha.trim().to_ascii_lowercase();
    let outcome = runtime
        .github_backup
        .lock()
        .await
        .fetch_version(&sha)
        .await
        .map_err(command_error)?;
    let (plain, preview) = match outcome {
        github_backup::VersionPreview::Unreadable { reason } => {
            return Ok(serde_json::json!({ "sha": sha, "unreadable": true, "reason": reason }));
        }
        github_backup::VersionPreview::Ready { plain, preview } => (plain, preview),
    };
    let encrypted = runtime
        .vault
        .protect_local_state(&*plain)
        .map_err(command_error)?;
    let id = Uuid::new_v4().to_string();
    *runtime.pending_history_restore.lock().await = Some(PendingHistoryRestore {
        id: id.clone(),
        created: Instant::now(),
        sha: sha.clone(),
        encrypted,
    });
    Ok(serde_json::json!({
        "id": id,
        "sha": sha,
        "unreadable": false,
        "preview": preview,
    }))
}

#[tauri::command]
pub(crate) async fn github_backup_history_commit(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: String,
    selected_ids: Vec<String>,
) -> Result<github_backup::VersionRestoreResult, String> {
    require_owner_unlocked(&runtime).await?;
    let mut ids = Vec::with_capacity(selected_ids.len());
    for raw in &selected_ids {
        ids.push(Uuid::parse_str(raw).map_err(|_| "GITHUB_HISTORY_INVALID".to_owned())?);
    }
    let mut slot = runtime.pending_history_restore.lock().await;
    let pending = slot.as_ref().ok_or("GITHUB_HISTORY_EXPIRED")?;
    if pending.id != id {
        return Err("GITHUB_HISTORY_EXPIRED".into());
    }
    if pending.created.elapsed().as_secs() > HISTORY_PREVIEW_TTL_SECS {
        *slot = None;
        return Err("GITHUB_HISTORY_EXPIRED".into());
    }
    let plain: Vec<u8> = runtime
        .vault
        .unprotect_local_state(&pending.encrypted)
        .map_err(command_error)?;
    let plain = zeroize::Zeroizing::new(plain);
    let sha = pending.sha.clone();
    // The pending slot stays held so a second commit cannot run alongside this one; on
    // failure it is kept, and the same preview can be retried once the error is fixed.
    let result = runtime
        .github_backup
        .lock()
        .await
        .restore_version(&sha, &plain, &ids)
        .await
        .map_err(command_error)?;
    *slot = None;
    drop(slot);
    emit_changed(&app);
    let _ = app.emit("cloud-sync-updated", &result.status);
    if result.summary.restored > 0 {
        schedule_auto_sync(&app, 500);
    }
    Ok(result)
}

#[tauri::command]
pub(crate) async fn github_backup_history_cancel(runtime: State<'_, AppRuntime>) -> Result<(), String> {
    *runtime.pending_history_restore.lock().await = None;
    Ok(())
}

#[tauri::command]
pub(crate) async fn github_backup_help(app: AppHandle, page: String) -> Result<(), String> {
    let url = match page.as_str() {
        "repository" => "https://github.com/new",
        "token" => "https://github.com/settings/personal-access-tokens/new",
        "login" => "https://cli.github.com/manual/gh_auth_login",
        _ => return Err("GITHUB_HELP_INVALID".to_owned()),
    };
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(command_error)
}


#[tauri::command]
pub(crate) async fn update_status(runtime: State<'_, AppRuntime>) -> Result<UpdateStatus, String> {
    Ok(runtime.updater.status().await)
}

#[tauri::command]
pub(crate) async fn update_check(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<UpdateStatus, String> {
    let emit_handle = app.clone();
    let outcome = runtime
        .updater
        .check_for_updates(true, move |status| {
            emit_update_status(&emit_handle, status);
        })
        .await
        .map_err(command_error)?;
    let settings = runtime.vault.settings().unwrap_or_default();
    if outcome.update_available
        && outcome.status.phase == "available"
        && settings.update_auto_download
        && outcome.status.can_auto_install
    {
        let updater = runtime.updater.clone();
        let handle = app.clone();
        tauri::async_runtime::spawn(async move {
            let emit_handle = handle.clone();
            let _ = updater
                .download_and_stage(move |status| {
                    emit_update_status(&emit_handle, status);
                })
                .await;
        });
    }
    Ok(outcome.status)
}

#[tauri::command]
pub(crate) async fn update_install_and_restart(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    let current_status = runtime.updater.status().await;
    if current_status.phase != "ready" {
        let emit_handle = app.clone();
        runtime
            .updater
            .download_and_stage(move |status| {
                emit_update_status(&emit_handle, status);
            })
            .await
            .map_err(command_error)?;
    }
    let emit_handle = app.clone();
    runtime
        .updater
        .apply_and_relaunch(true, move |status| {
            emit_update_status(&emit_handle, status);
        })
        .await
        .map_err(command_error)?;
    clipboard::clear_if_unchanged(&app, &runtime.clipboard, None);
    let exit_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(120)).await;
        exit_handle.exit(0);
    });
    Ok(())
}

#[tauri::command]
pub(crate) async fn update_skip_version(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    version: String,
) -> Result<UpdateStatus, String> {
    require_owner_unlocked(&runtime).await?;
    let status = runtime
        .updater
        .skip_version(&version)
        .await
        .map_err(command_error)?;
    emit_update_status(&app, &status);
    emit_changed(&app);
    Ok(status)
}

#[tauri::command]
pub(crate) async fn update_open_release_page(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<(), String> {
    let status = runtime.updater.status().await;
    let url = if status.release_url.starts_with("https://github.com/") {
        status.release_url
    } else {
        updater::DEFAULT_RELEASES_URL.to_owned()
    };
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(command_error)
}

