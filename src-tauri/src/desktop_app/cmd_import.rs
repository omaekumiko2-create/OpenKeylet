use super::*;

/// Source files behind the candidates shown in the import hub. The renderer only ever
/// sees an opaque reference per file and echoes it back on commit, so the paths stay in
/// the backend and a reference cannot be turned into an arbitrary path later.
#[derive(Default)]
pub(crate) struct ImportSourceRegistry {
    entries: std::collections::VecDeque<(String, PathBuf)>,
}

impl ImportSourceRegistry {
    /// Scans add up over a session; old references only stop being reported.
    const MAX_ENTRIES: usize = 4096;

    fn reference_for(&mut self, path: &Path) -> String {
        if let Some((reference, _)) = self.entries.iter().find(|(_, known)| known == path) {
            return reference.clone();
        }
        let reference = Uuid::new_v4().to_string();
        self.entries.push_back((reference.clone(), path.to_path_buf()));
        while self.entries.len() > Self::MAX_ENTRIES {
            self.entries.pop_front();
        }
        reference
    }

    fn resolve(&self, reference: &str) -> Option<&Path> {
        self.entries
            .iter()
            .find(|(known, _)| known == reference)
            .map(|(_, path)| path.as_path())
    }

    pub(crate) fn attach(
        &mut self,
        batch: &mut crate::extract::SmartExtractBatchResult,
        images: &mut [crate::extract::DroppedImagePayload],
    ) {
        let candidates = batch
            .candidates
            .iter_mut()
            .chain(batch.ignored.iter_mut().filter_map(|item| item.candidate.as_mut()));
        for cand in candidates {
            cand.source_refs = cand
                .source_paths
                .iter()
                .map(|path| self.reference_for(path))
                .collect();
        }
        for image in images {
            image.source_ref = image.source_path.as_deref().map(|path| self.reference_for(path));
        }
    }
}

/// Hands out source references for a freshly extracted batch. The native drag-and-drop
/// handler should call this too before it emits its batch.
pub(super) async fn remember_import_sources(
    runtime: &AppRuntime,
    batch: &mut crate::extract::SmartExtractBatchResult,
    images: &mut [crate::extract::DroppedImagePayload],
) {
    runtime.import_sources.lock().await.attach(batch, images);
}

#[tauri::command]
pub(crate) async fn generate_password(
    runtime: State<'_, AppRuntime>,
    options: crate::generator::Options,
) -> Result<String, String> {
    require_owner_unlocked(&runtime).await?;
    crate::generator::password(&options).map_err(command_error)
}

#[tauri::command]
pub(crate) async fn export_backup(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    password: String,
) -> Result<Option<String>, String> {
    require_owner_unlocked(&runtime).await?;
    let password = zeroize::Zeroizing::new(password);
    let selected = app
        .dialog()
        .file()
        .add_filter("OpenKeylet backup", &["mvault"])
        .set_file_name("openkeylet-backup.mvault")
        .blocking_save_file();
    let Some(path) = selected else {
        return Ok(None);
    };
    let path = path.into_path().map_err(command_error)?;
    backup::export_protected(&runtime.vault, &path, &password).map_err(command_error)?;
    Ok(Some(path.to_string_lossy().into_owned()))
}


const MAX_PACKAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_EXTRACT_BINARY_BYTES: usize = 16 * 1024 * 1024;

fn max_base64_len(max_decoded_bytes: usize) -> usize {
    max_decoded_bytes.div_ceil(3) * 4 + 64
}

struct InFlightGuard(Arc<AtomicBool>);
impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[tauri::command]
pub(crate) async fn pick_backup_import_file(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<Option<serde_json::Value>, String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .backup_import_generation
        .fetch_add(1, Ordering::AcqRel);
    *runtime.pending_backup_source.lock().await = None;
    *runtime.pending_backup_import.lock().await = None;
    let selected = app
        .dialog()
        .file()
        .add_filter(
            "Vault packages (.mvault, .kdbx, Bitwarden .json)",
            &["mvault", "kdbx", "json"],
        )
        .add_filter("OpenKeylet backup", &["mvault"])
        .blocking_pick_file();
    let Some(path) = selected else {
        return Ok(None);
    };
    require_owner_unlocked(&runtime).await?;
    let path = path.into_path().map_err(command_error)?;
    let path_for_inspect = path.clone();
    let info = tokio::task::spawn_blocking(move || {
        crate::migration::inspect_vault_package_file(&path_for_inspect)
    })
    .await
    .map_err(command_error)?
    .map_err(command_error)?;
    runtime
        .backup_import_generation
        .fetch_add(1, Ordering::AcqRel);
    *runtime.pending_backup_source.lock().await = Some(PendingBackupSource::Path {
        path,
        kind: info.package_kind,
    });
    Ok(Some(serde_json::json!({
        "fileName": info.file_name,
        "requiresPassword": info.requires_password,
        "packageKind": info.package_kind.as_str(),
    })))
}

#[tauri::command]
pub(crate) async fn inspect_dropped_backup_bytes(
    runtime: State<'_, AppRuntime>,
    file_name: String,
    content: String,
    is_base64: Option<bool>,
) -> Result<serde_json::Value, String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .backup_import_generation
        .fetch_add(1, Ordering::AcqRel);
    *runtime.pending_backup_source.lock().await = None;
    *runtime.pending_backup_import.lock().await = None;
    let decode_b64 = is_base64.unwrap_or(false);
    let max_raw = if decode_b64 {
        max_base64_len(MAX_PACKAGE_BYTES)
    } else {
        MAX_PACKAGE_BYTES
    };
    if content.len() > max_raw {
        return Err("Vault package exceeds 64 MiB limit".into());
    }
    let bytes = if decode_b64 {
        use base64::{Engine, engine::general_purpose::STANDARD};
        zeroize::Zeroizing::new(
            STANDARD
                .decode(content.trim())
                .map_err(|e| format!("Invalid vault package encoding: {e}"))?,
        )
    } else {
        zeroize::Zeroizing::new(content.into_bytes())
    };
    if bytes.len() > MAX_PACKAGE_BYTES {
        return Err("Vault package exceeds 64 MiB limit".into());
    }
    let info = crate::migration::inspect_vault_package_bytes(&bytes, &file_name)
        .map_err(command_error)?;
    runtime
        .backup_import_generation
        .fetch_add(1, Ordering::AcqRel);
    *runtime.pending_backup_source.lock().await = Some(PendingBackupSource::Bytes {
        bytes,
        kind: info.package_kind,
    });
    Ok(serde_json::json!({
        "fileName": info.file_name,
        "requiresPassword": info.requires_password,
        "packageKind": info.package_kind.as_str(),
    }))
}

#[tauri::command]
pub(crate) async fn prepare_backup_import(
    runtime: State<'_, AppRuntime>,
    password: String,
) -> Result<serde_json::Value, String> {
    require_owner_unlocked(&runtime).await?;
    if runtime
        .backup_prepare_in_flight
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("Another vault package decryption is already in progress".into());
    }
    let _in_flight = InFlightGuard(Arc::clone(&runtime.backup_prepare_in_flight));

    let password = zeroize::Zeroizing::new(password);
    let generation = runtime.backup_import_generation.load(Ordering::Acquire);
    let source = runtime
        .pending_backup_source
        .lock()
        .await
        .clone()
        .ok_or_else(|| "Choose a vault backup or package file first".to_owned())?;
    let vault = runtime.vault.clone();
    let id = Uuid::new_v4().to_string();
    let id_for_worker = id.clone();

    enum WorkerResult {
        Mvault {
            result: serde_json::Value,
            version: u8,
            encrypted: crate::model::SecretEnvelope,
        },
        Migration {
            result: serde_json::Value,
            encrypted: crate::model::SecretEnvelope,
        },
    }

    let worker = tokio::task::spawn_blocking(move || -> anyhow::Result<WorkerResult> {
        match source {
            PendingBackupSource::Path {
                path,
                kind: crate::migration::VaultPackageKind::Mvault,
            } => {
                let bytes = crate::migration::read_bounded_regular_file(
                    &path,
                    MAX_PACKAGE_BYTES as u64,
                )?;
                let prepared =
                    backup::prepare_import_bytes_with_password(&vault, &bytes, &password)?;
                let encrypted = vault.protect_local_state(&*prepared.raw_payload)?;
                let result = serde_json::json!({
                    "id": id_for_worker,
                    "preview": prepared.preview,
                });
                Ok(WorkerResult::Mvault {
                    result,
                    version: prepared.version,
                    encrypted,
                })
            }
            PendingBackupSource::Bytes {
                bytes,
                kind: crate::migration::VaultPackageKind::Mvault,
            } => {
                let prepared =
                    backup::prepare_import_bytes_with_password(&vault, &bytes, &password)?;
                let encrypted = vault.protect_local_state(&*prepared.raw_payload)?;
                let result = serde_json::json!({
                    "id": id_for_worker,
                    "preview": prepared.preview,
                });
                Ok(WorkerResult::Mvault {
                    result,
                    version: prepared.version,
                    encrypted,
                })
            }
            PendingBackupSource::Path { path, kind } => {
                let bytes = crate::migration::read_bounded_regular_file(
                    &path,
                    MAX_PACKAGE_BYTES as u64,
                )?;
                let parsed = crate::migration::parse_package_with_password(&bytes, kind, &password)?;
                let preview = backup::preview_migration_entries(
                    &vault,
                    kind.format_label().to_owned(),
                    &parsed.entries,
                )?;
                let encrypted = vault.protect_local_state(&parsed.entries)?;
                let result = serde_json::json!({
                    "id": id_for_worker,
                    "preview": preview,
                    "packageKind": kind.as_str(),
                    "warnings": parsed.preview.warnings,
                    "skippedDeleted": parsed.preview.skipped_deleted,
                });
                Ok(WorkerResult::Migration { result, encrypted })
            }
            PendingBackupSource::Bytes { bytes, kind } => {
                let parsed =
                    crate::migration::parse_package_with_password(&bytes, kind, &password)?;
                let preview = backup::preview_migration_entries(
                    &vault,
                    kind.format_label().to_owned(),
                    &parsed.entries,
                )?;
                let encrypted = vault.protect_local_state(&parsed.entries)?;
                let result = serde_json::json!({
                    "id": id_for_worker,
                    "preview": preview,
                    "packageKind": kind.as_str(),
                    "warnings": parsed.preview.warnings,
                    "skippedDeleted": parsed.preview.skipped_deleted,
                });
                Ok(WorkerResult::Migration { result, encrypted })
            }
        }
    })
    .await
    .map_err(command_error)?
    .map_err(command_error)?;

    // Re-validate lock state and generation before publishing so a concurrent lock, cancel,
    // or new file drop can never be overwritten by a delayed background decryption.
    require_owner_unlocked(&runtime).await?;
    let mut source_slot = runtime.pending_backup_source.lock().await;
    let mut import_slot = runtime.pending_backup_import.lock().await;
    if runtime.backup_import_generation.load(Ordering::Acquire) != generation {
        return Err("Backup import was cancelled or replaced; choose the file again".into());
    }
    match worker {
        WorkerResult::Mvault {
            result,
            version,
            encrypted,
        } => {
            *source_slot = None;
            *import_slot = Some(PendingBackupImport {
                id,
                created: Instant::now(),
                payload_kind: PendingBackupPayloadKind::Mvault { version },
                encrypted,
            });
            Ok(result)
        }
        WorkerResult::Migration { result, encrypted } => {
            *source_slot = None;
            *import_slot = Some(PendingBackupImport {
                id,
                created: Instant::now(),
                payload_kind: PendingBackupPayloadKind::MigrationEntries,
                encrypted,
            });
            Ok(result)
        }
    }
}

#[tauri::command]
pub(crate) async fn commit_backup_import(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: String,
    selected_item_indices: Option<Vec<usize>>,
    selected_trash_indices: Option<Vec<usize>>,
) -> Result<ImportSummary, String> {
    require_owner_unlocked(&runtime).await?;
    let mut slot = runtime.pending_backup_import.lock().await;
    let pending = slot
        .as_ref()
        .ok_or("Choose a vault backup or package file first")?;
    if pending.id != id {
        return Err("Backup preview changed; choose the file again".into());
    }
    if pending.created.elapsed().as_secs() > 300 {
        *slot = None;
        return Err("Backup preview expired; choose the file again".into());
    }
    let summary = match pending.payload_kind {
        PendingBackupPayloadKind::Mvault { version } => {
            let raw_payload: Vec<u8> = runtime
                .vault
                .unprotect_local_state(&pending.encrypted)
                .map_err(command_error)?;
            let raw_payload = zeroize::Zeroizing::new(raw_payload);
            backup::commit_prepared_import_selected(
                &runtime.vault,
                &raw_payload,
                version,
                selected_item_indices.as_deref(),
                selected_trash_indices.as_deref(),
            )
            .map_err(command_error)?
        }
        PendingBackupPayloadKind::MigrationEntries => {
            let entries: Vec<(crate::model::PortableConnection, crate::model::SecretBundle)> =
                runtime
                    .vault
                    .unprotect_local_state(&pending.encrypted)
                    .map_err(command_error)?;
            let selected = match selected_item_indices {
                Some(indices) => {
                    let len = entries.len();
                    if indices.iter().any(|&idx| idx >= len) {
                        return Err("Selected item index is out of range; reopen the import preview".into());
                    }
                    let allow: std::collections::HashSet<usize> = indices.into_iter().collect();
                    entries
                        .into_iter()
                        .enumerate()
                        .filter_map(|(idx, entry)| allow.contains(&idx).then_some(entry))
                        .collect()
                }
                None => entries,
            };
            if selected.is_empty() {
                ImportSummary {
                    added: 0,
                    merged: 0,
                }
            } else {
                runtime
                    .vault
                    .merge_connections(selected)
                    .map_err(command_error)?
            }
        }
    };
    *slot = None;
    emit_changed(&app);
    if summary.added > 0 {
        schedule_auto_sync(&app, 3000);
    }
    Ok(summary)
}

#[tauri::command]
pub(crate) async fn cancel_backup_import(runtime: State<'_, AppRuntime>) -> Result<(), String> {
    runtime
        .backup_import_generation
        .fetch_add(1, Ordering::AcqRel);
    *runtime.pending_backup_source.lock().await = None;
    *runtime.pending_backup_import.lock().await = None;
    Ok(())
}

#[tauri::command]
pub(crate) async fn prepare_import(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    format: String,
) -> Result<Option<serde_json::Value>, String> {
    require_owner_unlocked(&runtime).await?;
    *runtime.pending_import.lock().await = None;
    let selected = match format.as_str() {
        "bitwarden" => app
            .dialog()
            .file()
            .add_filter("Bitwarden JSON", &["json"])
            .blocking_pick_file(),
        "onepassword" => app
            .dialog()
            .file()
            .add_filter("1Password Export (.1pux)", &["1pux"])
            .blocking_pick_file(),
        "keepass" => app
            .dialog()
            .file()
            .add_filter("KeePass (.kdbx / .xml)", &["kdbx", "xml"])
            .blocking_pick_file(),
        "chrome" => app
            .dialog()
            .file()
            .add_filter("Password CSV", &["csv"])
            .blocking_pick_file(),
        "env" | "ssh_config" => app.dialog().file().blocking_pick_file(),
        _ => return Err("Unsupported import format".into()),
    };
    let Some(path) = selected else {
        return Ok(None);
    };
    require_owner_unlocked(&runtime).await?;
    let path = path.into_path().map_err(command_error)?;

    // Seamless redirect: if the chosen Bitwarden JSON or KeePass file is password-protected,
    // hand off to the unified unlock & selective preview modal instead of failing.
    let path_check = path.clone();
    let is_pkg = if format == "bitwarden" || format == "keepass" {
        tokio::task::spawn_blocking(move || crate::migration::is_vault_package_path(&path_check))
            .await
            .map_err(command_error)?
    } else {
        false
    };
    if is_pkg {
        let path_inspect = path.clone();
        let info = tokio::task::spawn_blocking(move || {
            crate::migration::inspect_vault_package_file(&path_inspect)
        })
        .await
        .map_err(command_error)?
        .map_err(command_error)?;
        runtime
            .backup_import_generation
            .fetch_add(1, Ordering::AcqRel);
        *runtime.pending_backup_import.lock().await = None;
        *runtime.pending_backup_source.lock().await = Some(PendingBackupSource::Path {
            path,
            kind: info.package_kind,
        });
        return Ok(Some(serde_json::json!({
            "redirectVaultPackage": {
                "fileName": info.file_name,
                "requiresPassword": info.requires_password,
                "packageKind": info.package_kind.as_str(),
            }
        })));
    }

    let format_for_read = format.clone();
    let parsed = tokio::task::spawn_blocking(move || crate::migration::read(&path, &format_for_read))
        .await
        .map_err(command_error)?
        .map_err(command_error)?;
    let id = Uuid::new_v4().to_string();
    let encrypted = runtime
        .vault
        .protect_local_state(&parsed.entries)
        .map_err(command_error)?;
    let result = serde_json::json!({"id":id,"preview":parsed.preview});
    *runtime.pending_import.lock().await = Some(PendingImport {
        id,
        created: Instant::now(),
        encrypted,
    });
    Ok(Some(result))
}

#[tauri::command]
pub(crate) async fn prepare_ssh_config_import(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    use_default: bool,
) -> Result<Option<serde_json::Value>, String> {
    require_owner_unlocked(&runtime).await?;
    *runtime.pending_import.lock().await = None;
    let path = if use_default {
        let Some(default_path) = crate::extract::ingest::default_ssh_config_path() else {
            return Err("Could not locate your home directory for ~/.ssh/config".into());
        };
        if !default_path.exists() {
            return Err(format!(
                "Default SSH config not found at {}",
                default_path.display()
            ));
        }
        default_path
    } else {
        let Some(picked) = app.dialog().file().blocking_pick_file() else {
            return Ok(None);
        };
        require_owner_unlocked(&runtime).await?;
        picked.into_path().map_err(command_error)?
    };
    let parsed = crate::migration::read(&path, "ssh_config").map_err(command_error)?;
    let id = Uuid::new_v4().to_string();
    let encrypted = runtime
        .vault
        .protect_local_state(&parsed.entries)
        .map_err(command_error)?;
    let result = serde_json::json!({
        "id": id,
        "preview": parsed.preview,
        "sourcePath": path.to_string_lossy(),
    });
    *runtime.pending_import.lock().await = Some(PendingImport {
        id,
        created: Instant::now(),
        encrypted,
    });
    Ok(Some(result))
}

#[tauri::command]
pub(crate) async fn smart_parse_text(
    runtime: State<'_, AppRuntime>,
    text: String,
    filename: Option<String>,
    url: Option<String>,
) -> Result<crate::extract::ingest::SmartParseResult, String> {
    require_owner_unlocked(&runtime).await?;
    crate::extract::ingest::smart_parse(&text, filename.as_deref(), url.as_deref())
        .map_err(command_error)
}

#[tauri::command]
pub(crate) async fn smart_extract_batch(
    runtime: State<'_, AppRuntime>,
    text: String,
    filename: Option<String>,
) -> Result<crate::extract::SmartExtractBatchResult, String> {
    require_owner_unlocked(&runtime).await?;
    let existing = runtime
        .vault
        .list_decrypted_connections()
        .map_err(command_error)?;
    crate::extract::extract_batch(&text, filename.as_deref(), &existing)
        .map_err(command_error)
}

#[tauri::command]
pub(crate) async fn smart_pick_and_extract_files(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<Option<serde_json::Value>, String> {
    require_owner_unlocked(&runtime).await?;
    let Some(picked) = app.dialog().file().blocking_pick_files() else {
        return Ok(None);
    };
    require_owner_unlocked(&runtime).await?;
    let mut paths = Vec::with_capacity(picked.len());
    for file_path in picked {
        paths.push(file_path.into_path().map_err(command_error)?);
    }
    let existing = runtime
        .vault
        .list_decrypted_connections()
        .map_err(command_error)?;
    let mut outcome = crate::extract::extract_from_paths(&paths, &existing);
    remember_import_sources(&runtime, &mut outcome.batch, &mut outcome.images).await;

    let mut mvault_file = None;
    if let Some(mvault_path) = outcome.mvault_paths.first() {
        let file_name = mvault_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("openkeylet-backup.mvault")
            .to_owned();
        let path_for_inspect = mvault_path.clone();
        let inspect_res = tokio::task::spawn_blocking(move || {
            crate::migration::inspect_vault_package_file(&path_for_inspect)
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .and_then(|r| r);
        match inspect_res {
            Ok(info) => {
                runtime
                    .backup_import_generation
                    .fetch_add(1, Ordering::AcqRel);
                *runtime.pending_backup_import.lock().await = None;
                *runtime.pending_backup_source.lock().await = Some(PendingBackupSource::Path {
                    path: mvault_path.clone(),
                    kind: info.package_kind,
                });
                mvault_file = Some(serde_json::json!({
                    "fileName": info.file_name,
                    "requiresPassword": info.requires_password,
                    "packageKind": info.package_kind.as_str(),
                }));
            }
            Err(error) => {
                outcome.batch.warnings.push(format!("{file_name}: {error}"));
            }
        }
    }

    let mut value = serde_json::to_value(&outcome.batch).map_err(command_error)?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "images".to_owned(),
            serde_json::to_value(&outcome.images).map_err(command_error)?,
        );
        obj.insert(
            "sourceFiles".to_owned(),
            serde_json::to_value(&outcome.source_files).map_err(command_error)?,
        );
        if let Some(mv) = mvault_file {
            obj.insert("mvaultFile".to_owned(), mv);
        }
    }
    Ok(Some(value))
}

#[tauri::command]
pub(crate) async fn smart_extract_dropped_binary(
    runtime: State<'_, AppRuntime>,
    file_name: String,
    data_base64: String,
) -> Result<crate::extract::SmartExtractBatchResult, String> {
    require_owner_unlocked(&runtime).await?;
    let display_name = Path::new(&file_name)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("file")
        .to_owned();
    let max_decoded = if display_name.to_ascii_lowercase().ends_with(".1pux") {
        MAX_PACKAGE_BYTES
    } else {
        MAX_EXTRACT_BINARY_BYTES
    };
    if data_base64.len() > max_base64_len(max_decoded) {
        return Err(format!("{display_name} exceeds file size limit"));
    }
    use base64::{Engine, engine::general_purpose::STANDARD};
    let bytes = zeroize::Zeroizing::new(
        STANDARD
            .decode(data_base64.trim())
            .map_err(|e| format!("Invalid file encoding: {e}"))?,
    );
    if bytes.len() > max_decoded {
        return Err(format!("{display_name} exceeds file size limit"));
    }
    let existing = runtime
        .vault
        .list_decrypted_connections()
        .map_err(command_error)?;
    tokio::task::spawn_blocking(move || {
        crate::extract::extract_from_bytes(&bytes, &display_name, &existing)
    })
    .await
    .map_err(command_error)?
    .map_err(command_error)
}

#[tauri::command]
pub(crate) async fn smart_scan_local_dev_configs(
    runtime: State<'_, AppRuntime>,
) -> Result<serde_json::Value, String> {
    require_owner_unlocked(&runtime).await?;
    let existing = runtime
        .vault
        .list_decrypted_connections()
        .map_err(command_error)?;
    let mut outcome = tokio::task::spawn_blocking(move || {
        crate::extract::scan_local_dev_configs_with_mvaults(&existing)
    })
    .await
    .map_err(command_error)?
    .map_err(command_error)?;
    remember_import_sources(&runtime, &mut outcome.batch, &mut []).await;
    *runtime.discovered_mvault_paths.lock().await = outcome.mvault_paths;
    let mut value = serde_json::to_value(&outcome.batch).map_err(command_error)?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "discoveredMvaults".to_owned(),
            serde_json::to_value(&outcome.discovered_mvaults).map_err(command_error)?,
        );
        obj.insert(
            "scanReport".to_owned(),
            serde_json::to_value(&outcome.report).map_err(command_error)?,
        );
    }
    Ok(value)
}

#[tauri::command]
pub(crate) async fn smart_scan_workspace_folder(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<Option<serde_json::Value>, String> {
    require_owner_unlocked(&runtime).await?;
    let Some(picked) = app.dialog().file().blocking_pick_folder() else {
        return Ok(None);
    };
    require_owner_unlocked(&runtime).await?;
    let folder_path = picked.into_path().map_err(command_error)?;
    let existing = runtime
        .vault
        .list_decrypted_connections()
        .map_err(command_error)?;
    let mut outcome = tokio::task::spawn_blocking(move || {
        crate::extract::scan_workspace_directory(&folder_path, &existing)
    })
    .await
    .map_err(command_error)?
    .map_err(command_error)?;
    remember_import_sources(&runtime, &mut outcome.batch, &mut []).await;
    *runtime.discovered_mvault_paths.lock().await = outcome.mvault_paths;
    let mut value = serde_json::to_value(&outcome.batch).map_err(command_error)?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "discoveredMvaults".to_owned(),
            serde_json::to_value(&outcome.discovered_mvaults).map_err(command_error)?,
        );
        obj.insert(
            "scanReport".to_owned(),
            serde_json::to_value(&outcome.report).map_err(command_error)?,
        );
    }
    Ok(Some(value))
}

#[tauri::command]
pub(crate) async fn open_discovered_mvault(
    runtime: State<'_, AppRuntime>,
    index: usize,
) -> Result<serde_json::Value, String> {
    require_owner_unlocked(&runtime).await?;
    let path = runtime
        .discovered_mvault_paths
        .lock()
        .await
        .get(index)
        .cloned()
        .ok_or_else(|| "Discovered .mvault backup is no longer available; scan again".to_owned())?;
    let path_for_inspect = path.clone();
    let info = tokio::task::spawn_blocking(move || {
        crate::migration::inspect_vault_package_file(&path_for_inspect)
    })
    .await
    .map_err(command_error)?
    .map_err(command_error)?;
    runtime
        .backup_import_generation
        .fetch_add(1, Ordering::AcqRel);
    *runtime.pending_backup_import.lock().await = None;
    *runtime.pending_backup_source.lock().await = Some(PendingBackupSource::Path {
        path,
        kind: info.package_kind,
    });
    Ok(serde_json::json!({
        "fileName": info.file_name,
        "requiresPassword": info.requires_password,
        "packageKind": info.package_kind.as_str(),
    }))
}

#[tauri::command]
pub(crate) async fn commit_smart_batch(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    items: Vec<crate::extract::SmartCommitItem>,
    folder: Option<String>,
) -> Result<crate::extract::SmartCommitSummary, String> {
    require_owner_unlocked(&runtime).await?;
    if items.is_empty() {
        return Err("No items selected to import".into());
    }
    let default_folder = folder.unwrap_or_default().trim().to_owned();
    let mut used_names: std::collections::HashSet<String> = runtime
        .vault
        .list_connections()
        .map_err(command_error)?
        .into_iter()
        .map(|c| c.name.trim().to_ascii_lowercase())
        .collect();

    let mut added = 0usize;
    let mut updated = 0usize;
    let mut created_ids = Vec::new();
    let mut source_refs: Vec<String> = Vec::new();

    for item in items {
        source_refs.extend(item.source_refs);
        let mut input = item.input;
        if input.folder.trim().is_empty() && !default_folder.is_empty() {
            input.folder = default_folder.clone();
        }
        if item.update_existing
            && let Some(raw_id) = item.existing_item_id.as_deref()
            && let Ok(uuid) = Uuid::parse_str(raw_id.trim())
            && let Ok(existing) = runtime.vault.get_connection(uuid)
        {
            // Merge new modules & secrets into existing item without losing existing metadata
            let mut merged_modules = existing.stored.modules.clone();
            for m in &input.modules {
                if let Some(pos) = merged_modules
                    .iter()
                    .position(|em| em.kind == m.kind && em.name.eq_ignore_ascii_case(&m.name))
                {
                    if !m.value.trim().is_empty() {
                        merged_modules[pos].value = m.value.clone();
                    }
                } else {
                    merged_modules.push(m.clone());
                }
            }
            let mut merged_uris = existing.stored.login_uris.clone();
            for uri in &input.login_uris {
                if !merged_uris.iter().any(|u| u.uri == uri.uri) {
                    merged_uris.push(uri.clone());
                }
            }
            let merged_input = ConnectionInput {
                login_uris: merged_uris,
                item_type: existing.stored.item_type().to_owned(),
                folder: if !input.folder.trim().is_empty() {
                    input.folder
                } else {
                    existing.stored.folder
                },
                favorite: existing.stored.favorite,
                id: Some(uuid),
                modules: merged_modules,
                name: existing.stored.name,
                enabled: existing.stored.enabled,
                description: if existing.stored.description.is_empty() {
                    input.description
                } else {
                    existing.stored.description
                },
                http_auth_type: if !input.http_auth_type.is_empty() {
                    input.http_auth_type
                } else {
                    existing.stored.http_auth_type
                },
                private_key_import_path: String::new(),
                auth_header: if !input.auth_header.is_empty() {
                    input.auth_header
                } else {
                    existing.stored.auth_header
                },
                auth_location: if !input.auth_location.is_empty() {
                    input.auth_location
                } else {
                    existing.stored.auth_location
                },
                auth_prefix: if !input.auth_prefix.is_empty() {
                    input.auth_prefix
                } else {
                    existing.stored.auth_prefix
                },
                api_auth_headers: if !input.api_auth_headers.is_empty() {
                    input.api_auth_headers
                } else {
                    existing.stored.api_auth_headers
                },
                test_path: if !input.test_path.is_empty() {
                    input.test_path
                } else {
                    existing.stored.test_path
                },
                remove_secret_names: Vec::new(),
                secrets: input.secrets,
            };
            runtime
                .vault
                .save_connection(merged_input)
                .map_err(command_error)?;
            updated += 1;
            continue;
        }

        // Resolve unique name cleanly for new items
        input.id = None;
        let base_name = if input.name.trim().is_empty() {
            "Imported item".to_owned()
        } else {
            input.name.trim().to_owned()
        };
        let mut candidate_name = base_name.clone();
        let mut suffix = 2usize;
        while used_names.contains(&candidate_name.to_ascii_lowercase()) {
            let tag = format!(" ({suffix})");
            let max_base = 80usize.saturating_sub(tag.chars().count());
            let truncated: String = base_name.chars().take(max_base).collect();
            candidate_name = format!("{truncated}{tag}");
            suffix += 1;
        }
        used_names.insert(candidate_name.to_ascii_lowercase());
        input.name = candidate_name;

        let saved = runtime.vault.save_connection(input).map_err(command_error)?;
        created_ids.push(saved.id.to_string());
        added += 1;
    }

    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    // Only reached once every item is saved: the list describes what the vault now holds
    // a copy of, while the original files are left exactly as they were.
    let source_paths: Vec<PathBuf> = {
        let registry = runtime.import_sources.lock().await;
        source_refs
            .iter()
            .filter_map(|reference| registry.resolve(reference).map(Path::to_path_buf))
            .collect()
    };
    let plaintext_sources =
        tokio::task::spawn_blocking(move || crate::extract::plaintext_sources(source_paths))
            .await
            .map_err(command_error)?;
    Ok(crate::extract::SmartCommitSummary {
        added,
        updated,
        created_ids,
        plaintext_sources,
    })
}

#[tauri::command]
pub(crate) async fn undo_smart_batch(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    ids: Vec<String>,
) -> Result<usize, String> {
    require_owner_unlocked(&runtime).await?;
    let mut removed = 0usize;
    for raw_id in ids {
        if let Ok(uuid) = Uuid::parse_str(raw_id.trim())
            && runtime.vault.trash_connection(uuid, None).is_ok()
        {
            removed += 1;
        }
    }
    if removed > 0 {
        emit_changed(&app);
        schedule_auto_sync(&app, 3000);
    }
    Ok(removed)
}

#[tauri::command]
pub(crate) async fn read_owner_clipboard(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<String, String> {
    require_owner_unlocked(&runtime).await?;
    Ok(clipboard::read_text(&app).unwrap_or_default())
}

#[tauri::command]
pub(crate) async fn clear_clipboard_if_matches(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    text: String,
) -> Result<bool, String> {
    require_owner_unlocked(&runtime).await?;
    Ok(clipboard::clear_if_exact(&app, &runtime.clipboard, &text))
}

#[tauri::command]
pub(crate) async fn attach_totp_to_item(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: String,
    totp: String,
    expected_updated_at: String,
) -> Result<PublicConnection, String> {
    require_owner_unlocked(&runtime).await?;
    let trimmed = totp.trim();
    crate::crypto::totp::current_totp(trimmed).map_err(command_error)?;
    let uuid = Uuid::parse_str(id.trim()).map_err(|_| "Invalid item ID".to_owned())?;
    let existing = runtime.vault.get_connection(uuid).map_err(command_error)?;
    let mut modules = existing.stored.modules.clone();
    if !modules.iter().any(|m| m.kind == "totp") {
        modules.push(crate::model::ItemModule {
            kind: "totp".to_owned(),
            name: "totp".to_owned(),
            value: String::new(),
            agent_visible: Some(false),
        });
    }
    let mut secrets = crate::model::SecretBundle::default();
    secrets
        .named_secrets
        .insert("totp".to_owned(), trimmed.to_owned());
    let item_type = existing.stored.item_type().to_owned();
    let input = ConnectionInput {
        login_uris: existing.stored.login_uris,
        item_type,
        folder: existing.stored.folder,
        favorite: existing.stored.favorite,
        id: Some(uuid),
        modules,
        name: existing.stored.name,
        enabled: existing.stored.enabled,
        description: existing.stored.description,
        http_auth_type: existing.stored.http_auth_type,
        private_key_import_path: String::new(),
        auth_header: existing.stored.auth_header,
        auth_location: existing.stored.auth_location,
        auth_prefix: existing.stored.auth_prefix,
        api_auth_headers: existing.stored.api_auth_headers,
        test_path: existing.stored.test_path,
        remove_secret_names: Vec::new(),
        secrets,
    };
    let saved = runtime
        .vault
        .save_connection_checked(input, Some(expected_updated_at.as_str()))
        .map_err(command_error)?;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(saved)
}

#[tauri::command]
pub(crate) async fn commit_import(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: String,
) -> Result<ImportSummary, String> {
    require_owner_unlocked(&runtime).await?;
    let mut slot = runtime.pending_import.lock().await;
    let pending = slot.as_ref().ok_or("Choose an import file first")?;
    if pending.id != id {
        return Err("Import preview changed; choose the file again".into());
    }
    if pending.created.elapsed().as_secs() > 300 {
        *slot = None;
        return Err("Import preview expired; choose the file again".into());
    }
    let entries = runtime
        .vault
        .unprotect_local_state(&pending.encrypted)
        .map_err(command_error)?;
    let summary = runtime
        .vault
        .merge_connections(entries)
        .map_err(command_error)?;
    *slot = None;
    emit_changed(&app);
    schedule_auto_sync(&app, 3000);
    Ok(summary)
}

#[tauri::command]
pub(crate) async fn cancel_import(runtime: State<'_, AppRuntime>) -> Result<(), String> {
    *runtime.pending_import.lock().await = None;
    Ok(())
}

