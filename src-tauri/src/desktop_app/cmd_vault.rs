use super::*;

#[tauri::command]
pub(crate) async fn get_state(runtime: State<'_, AppRuntime>) -> Result<AppState, String> {
    let lock = owner_lock_state(&runtime).await?;
    runtime.browser.sync().await;
    let browser = runtime.browser.status().await;
    let state = runtime
        .vault
        .app_state(&runtime.executable, browser)
        .map_err(command_error)?;
    if lock.pin_configured && !lock.unlocked {
        Ok(scrub_locked_app_state(state))
    } else {
        Ok(state)
    }
}

#[tauri::command]
pub(crate) async fn owner_status(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<OwnerLockState, String> {
    let state = owner_lock_state(&runtime).await?;
    if state.pin_configured && !state.unlocked {
        clipboard::clear_if_unchanged(&app, &runtime.clipboard, None);
    }
    Ok(state)
}

#[tauri::command]
pub(crate) async fn owner_touch(runtime: State<'_, AppRuntime>) -> Result<OwnerLockState, String> {
    let state = owner_lock_state(&runtime).await?;
    if state.pin_configured && state.unlocked {
        runtime.owner_session.lock().await.touch(Instant::now());
        return owner_lock_state(&runtime).await;
    }
    Ok(state)
}

#[tauri::command]
pub(crate) async fn owner_set_pin(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    pin: String,
) -> Result<OwnerLockState, String> {
    runtime.vault.set_owner_pin(&pin).map_err(command_error)?;
    keep_owner_unlocked(&runtime).await;
    schedule_tray_refresh(&app);
    owner_lock_state(&runtime).await
}

#[tauri::command]
pub(crate) async fn owner_disable_pin(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<OwnerLockState, String> {
    require_owner_unlocked(&runtime).await?;
    runtime.vault.disable_owner_pin().map_err(command_error)?;
    runtime.owner_session.lock().await.lock();
    schedule_tray_refresh(&app);
    owner_lock_state(&runtime).await
}

#[tauri::command]
pub(crate) async fn owner_unlock(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    pin: String,
) -> Result<OwnerLockState, String> {
    let now = Instant::now();
    if let Some(wait_secs) = runtime.owner_session.lock().await.cooldown_remaining(now) {
        return Err(format!(
            "Too many incorrect attempts; wait {wait_secs}s"
        ));
    }
    if !runtime
        .vault
        .verify_owner_pin(&pin)
        .map_err(command_error)?
    {
        let delay = runtime
            .owner_session
            .lock()
            .await
            .record_failed_attempt(Instant::now());
        if delay > 0 {
            return Err(format!("Incorrect PIN; wait {delay}s before trying again"));
        }
        return Err("Incorrect PIN".to_owned());
    }
    keep_owner_unlocked(&runtime).await;
    schedule_tray_refresh(&app);
    owner_lock_state(&runtime).await
}

#[tauri::command]
pub(crate) async fn owner_lock(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<OwnerLockState, String> {
    runtime.owner_session.lock().await.lock();
    *runtime.pending_import.lock().await = None;
    *runtime.pending_backup_source.lock().await = None;
    *runtime.pending_backup_import.lock().await = None;
    *runtime.pending_history_restore.lock().await = None;
    runtime.discovered_mvault_paths.lock().await.clear();
    clipboard::clear_if_unchanged(&app, &runtime.clipboard, None);
    schedule_tray_refresh(&app);
    owner_lock_state(&runtime).await
}

#[tauri::command]
pub(crate) async fn owner_secret_view(
    runtime: State<'_, AppRuntime>,
    id: Uuid,
) -> Result<OwnerSecretView, String> {
    require_owner_unlocked(&runtime).await?;
    keep_owner_unlocked(&runtime).await;
    runtime.vault.owner_secret_view(id).map_err(command_error)
}

#[tauri::command]
pub(crate) async fn owner_editor_drafts(
    runtime: State<'_, AppRuntime>,
) -> Result<Vec<OwnerEditorDraft>, String> {
    require_owner_unlocked(&runtime).await?;
    keep_owner_unlocked(&runtime).await;
    runtime.vault.list_editor_drafts().map_err(command_error)
}

#[tauri::command]
pub(crate) async fn save_editor_draft(
    runtime: State<'_, AppRuntime>,
    draft_id: Option<Uuid>,
    mut input: ConnectionInput,
) -> Result<OwnerEditorDraft, String> {
    require_owner_unlocked(&runtime).await?;
    keep_owner_unlocked(&runtime).await;
    if input.private_key_import_path == "pending" {
        let path = runtime
            .pending_private_key
            .lock()
            .await
            .take()
            .ok_or_else(|| "Please select the SSH private key again".to_owned())?;
        input.secrets.private_key = Some(std::fs::read_to_string(&path).map_err(command_error)?);
        input.secrets.private_key_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned);
    }
    input.private_key_import_path.clear();
    runtime
        .vault
        .save_editor_draft(draft_id, input)
        .map_err(command_error)
}

#[tauri::command]
pub(crate) async fn delete_editor_draft(runtime: State<'_, AppRuntime>, id: Uuid) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime.vault.delete_editor_draft(id).map_err(command_error)
}

#[tauri::command]
pub(crate) async fn copy_owner_value(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    value: String,
    sensitive: Option<bool>,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    let sensitive = sensitive.unwrap_or(true);
    clipboard::write_text(
        &app,
        &runtime.clipboard,
        &value,
        sensitive,
        SENSITIVE_CLIPBOARD_TTL_SECS,
    )
    .map_err(command_error)
}

#[tauri::command]
pub(crate) async fn copy_totp_code(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    secret: String,
) -> Result<serde_json::Value, String> {
    require_owner_unlocked(&runtime).await?;
    let (code, remaining_seconds, period) =
        crate::crypto::totp::current_totp_details(&secret).map_err(command_error)?;
    clipboard::write_text(
        &app,
        &runtime.clipboard,
        &code,
        true,
        SENSITIVE_CLIPBOARD_TTL_SECS,
    )
    .map_err(command_error)?;
    Ok(serde_json::json!({
        "remainingSeconds": remaining_seconds,
        "period": period,
        "clearAfterSeconds": SENSITIVE_CLIPBOARD_TTL_SECS,
    }))
}

#[tauri::command]
pub(crate) async fn save_connection(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    mut input: ConnectionInput,
    expected_updated_at: Option<String>,
) -> Result<PublicConnection, String> {
    require_owner_unlocked(&runtime).await?;
    if input.private_key_import_path == "pending" {
        let selected = runtime
            .pending_private_key
            .lock()
            .await
            .take()
            .ok_or_else(|| "Please select the SSH private key again".to_owned())?;
        input.private_key_import_path = selected.to_string_lossy().into_owned();
    } else {
        input.private_key_import_path.clear();
    }
    let connection = runtime
        .vault
        .save_connection_checked(input, expected_updated_at.as_deref())
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(connection)
}

#[tauri::command]
pub(crate) async fn reorder_connections(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    ids: Vec<Uuid>,
    expected_order: Vec<Uuid>,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .vault
        .reorder_connections(&ids, &expected_order)
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(())
}

#[tauri::command]
pub(crate) async fn set_connection_enabled(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
    enabled: bool,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .vault
        .set_connection_enabled(id, enabled)
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(())
}

#[tauri::command]
pub(crate) async fn delete_connection(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
    expected_updated_at: String,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .vault
        .trash_connection(id, Some(&expected_updated_at))
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(())
}

#[tauri::command]
pub(crate) async fn owner_trash(
    runtime: State<'_, AppRuntime>,
) -> Result<Vec<crate::model::PublicTrashItem>, String> {
    require_owner_unlocked(&runtime).await?;
    runtime.vault.trash_items().map_err(command_error)
}

#[tauri::command]
pub(crate) async fn owner_restore_item(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
    deleted_at: String,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .vault
        .restore_connection(id, &deleted_at)
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(())
}

#[tauri::command]
pub(crate) async fn owner_purge_item(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
    deleted_at: String,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .vault
        .purge_connection(id, &deleted_at)
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(())
}

#[tauri::command]
pub(crate) async fn owner_password_history(
    runtime: State<'_, AppRuntime>,
    id: Uuid,
) -> Result<serde_json::Value, String> {
    require_owner_unlocked(&runtime).await?;
    let item = runtime.vault.get_connection(id).map_err(command_error)?;
    Ok(
        serde_json::json!({"updatedAt":item.stored.updated_at,"entries":item.secrets.password_history}),
    )
}

#[tauri::command]
pub(crate) async fn owner_clear_password_history(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
    expected_updated_at: String,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .vault
        .clear_password_history(id, &expected_updated_at)
        .map_err(command_error)?;
    emit_changed(&app);
    Ok(())
}

#[tauri::command]
pub(crate) async fn owner_add_agent_note(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
    text: String,
) -> Result<PublicConnection, String> {
    require_owner_unlocked(&runtime).await?;
    let updated = runtime
        .vault
        .add_agent_note(id, &text, "OWNER", false)
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(updated)
}

#[tauri::command]
pub(crate) async fn owner_update_agent_note(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
    note_id: String,
    text: String,
) -> Result<PublicConnection, String> {
    require_owner_unlocked(&runtime).await?;
    let updated = runtime
        .vault
        .update_agent_note(id, &note_id, &text, Some("OWNER"), false)
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(updated)
}

#[tauri::command]
pub(crate) async fn owner_delete_agent_note(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
    note_id: String,
) -> Result<PublicConnection, String> {
    require_owner_unlocked(&runtime).await?;
    let updated = runtime
        .vault
        .remove_agent_note(id, &note_id, false)
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(updated)
}

#[tauri::command]
pub(crate) async fn owner_clear_agent_notes(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
) -> Result<PublicConnection, String> {
    require_owner_unlocked(&runtime).await?;
    let updated = runtime
        .vault
        .clear_agent_notes(id)
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(updated)
}

#[tauri::command]
pub(crate) async fn owner_set_agent_notes_locked(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
    locked: bool,
) -> Result<PublicConnection, String> {
    require_owner_unlocked(&runtime).await?;
    let updated = runtime
        .vault
        .set_agent_notes_locked(id, locked)
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(updated)
}

#[tauri::command]
pub(crate) async fn test_connection(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
) -> Result<String, String> {
    require_owner_unlocked(&runtime).await?;
    let started = Instant::now();
    let connection = runtime.vault.get_connection(id).map_err(command_error)?;
    let connection_name = connection.stored.name.clone();
    let result: anyhow::Result<String> =
        if connection.stored.test_target(&connection.secrets).is_some() {
            exec::test_connection(&runtime.vault, &connection).await
        } else {
            Ok(format!(
                "Secure entry ready · {} fields",
                connection
                    .secrets
                    .available_fields(connection.stored.secret.as_ref())
                    .len()
            ))
        }
        .map_err(|error| {
            anyhow::anyhow!(crate::policy::redact(
                error.to_string(),
                &connection.stored,
                &connection.secrets,
            ))
        });
    let (status, error) = match &result {
        Ok(_) => ("success", String::new()),
        Err(error) => ("error", error.to_string()),
    };
    let _ = runtime.vault.add_activity(NewActivity {
        status: status.to_owned(),
        source: "Apply".to_owned(),
        connection_name,
        action: "Test connection".to_owned(),
        duration_ms: started.elapsed().as_millis() as u64,
        error,
    });
    emit_changed(&app);
    result.map_err(command_error)
}

