use super::*;

impl Vault {
    #[cfg(test)]
    pub fn export_connections(&self) -> Result<Vec<(PortableConnection, SecretBundle)>> {
        Ok(self.export_backup_entries()?.0)
    }

    pub fn export_backup_entries(
        &self,
    ) -> Result<(
        Vec<(PortableConnection, SecretBundle)>,
        Vec<crate::model::PortableTrashItem>,
    )> {
        let document = self.read_document()?;
        self.with_key(|key| {
            let active = document
                .connections
                .into_iter()
                .map(|connection| {
                    let secrets = key.decrypt::<SecretBundle>(&connection.encrypted_secrets)?;
                    Ok((connection.portable(), secrets))
                })
                .collect::<Result<Vec<_>>>()?;
            let trash = document
                .trash
                .into_iter()
                .map(|entry| {
                    Ok(crate::model::PortableTrashItem {
                        deleted_at: entry.deleted_at,
                        connection: entry.connection.portable(),
                        secrets: key.decrypt(&entry.connection.encrypted_secrets)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok((active, trash))
        })
    }

    pub fn export_tombstones(&self) -> Result<Vec<crate::model::DeletedItemTombstone>> {
        Ok(self.read_document()?.deleted_ids)
    }

    pub fn sync_content_fingerprint(&self) -> Result<String> {
        use sha2::{Digest, Sha256};
        let (active, trash) = self.export_backup_entries()?;
        let tombstones = self.export_tombstones()?;
        let mut active_sorted = active;
        active_sorted.sort_by_key(|(c, _)| c.id);
        let mut trash_sorted = trash;
        trash_sorted.sort_by_key(|t| (t.connection.id, t.deleted_at.clone()));
        let mut tombstones_sorted = tombstones;
        tombstones_sorted.sort_by_key(|t| t.id);
        let bytes = serde_json::to_vec(&serde_json::json!({
            "active": active_sorted,
            "trash": trash_sorted,
            "deletedIds": tombstones_sorted,
        }))?;
        let digest = Sha256::digest(&bytes);
        Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
    }

    pub fn sync_merge_entries(
        &self,
        remote_active: Vec<(PortableConnection, SecretBundle)>,
        remote_trash: Vec<crate::model::PortableTrashItem>,
        remote_tombstones: Vec<crate::model::DeletedItemTombstone>,
    ) -> Result<crate::model::SyncMergeSummary> {
        let parse_ts = |value: &str| chrono::DateTime::parse_from_rfc3339(value).ok();
        let is_newer = |candidate: &str, baseline: &str| match (parse_ts(candidate), parse_ts(baseline)) {
            (Some(a), Some(b)) => a > b,
            _ => candidate > baseline,
        };

        self.with_key(|key| {
            self.update_document_with_result(|document| {
            let mut summary = crate::model::SyncMergeSummary::default();

            // 1. Merge remote tombstones first and purge older local active/trash items.
            for tomb in remote_tombstones {
                if parse_ts(&tomb.deleted_at).is_none() {
                    continue;
                }
                if let Some(existing) = document.deleted_ids.iter_mut().find(|t| t.id == tomb.id) {
                    if is_newer(&tomb.deleted_at, &existing.deleted_at) {
                        existing.deleted_at = tomb.deleted_at.clone();
                    }
                } else {
                    document.deleted_ids.push(tomb.clone());
                }
                if let Some(pos) = document.connections.iter().position(|c| c.id == tomb.id)
                    && is_newer(&tomb.deleted_at, &document.connections[pos].updated_at)
                {
                    document.connections.remove(pos);
                    summary.deleted += 1;
                }
                if let Some(pos) = document.trash.iter().position(|t| t.connection.id == tomb.id)
                    && is_newer(&tomb.deleted_at, &document.trash[pos].deleted_at)
                {
                    document.trash.remove(pos);
                    summary.deleted += 1;
                }
            }
            document.deleted_ids.sort_by(|a, b| b.deleted_at.cmp(&a.deleted_at));
            document.deleted_ids.truncate(500);

            // 2. Merge remote active connections by UUID + updatedAt (preserving local edits & tombstones).
            for (public, secrets) in remote_active {
                let mut stored = stored_from_portable(&public, &secrets, key)?;
                let imported_secrets: SecretBundle = key.decrypt(&stored.encrypted_secrets)?;
                let requested_name = clean_text(&stored.name, 80);
                stored.name = if requested_name.is_empty() {
                    "Synced item".to_owned()
                } else {
                    requested_name
                };

                // Skip if a newer tombstone exists locally.
                if let Some(tomb) = document.deleted_ids.iter().find(|t| t.id == stored.id)
                    && is_newer(&tomb.deleted_at, &stored.updated_at)
                {
                    summary.unchanged += 1;
                    continue;
                }

                // Check if currently in local trash.
                if let Some(trash_pos) = document
                    .trash
                    .iter()
                    .position(|entry| entry.connection.id == stored.id)
                {
                    if is_newer(&stored.updated_at, &document.trash[trash_pos].deleted_at) {
                        document.trash.remove(trash_pos);
                        document.deleted_ids.retain(|t| t.id != stored.id);
                        if document
                            .connections
                            .iter()
                            .any(|c| same_item_name(&c.name, &stored.name))
                        {
                            stored.name = unique_import_name(&document.connections, &stored.name);
                        }
                        document.connections.push(stored);
                        summary.updated += 1;
                    } else {
                        summary.unchanged += 1;
                    }
                    continue;
                }

                // Check if already active locally with the same UUID.
                if let Some(pos) = document.connections.iter().position(|c| c.id == stored.id) {
                    let existing = &document.connections[pos];
                    let existing_secrets: SecretBundle = key.decrypt(&existing.encrypted_secrets)?;
                    if same_synced_state(
                        existing,
                        &existing_secrets,
                        &stored,
                        &imported_secrets,
                    ) {
                        summary.unchanged += 1;
                    } else if is_newer(&stored.updated_at, &existing.updated_at) {
                        let name_collision = document
                            .connections
                            .iter()
                            .enumerate()
                            .any(|(idx, c)| idx != pos && same_item_name(&c.name, &stored.name));
                        if name_collision {
                            stored.name = unique_import_name(&document.connections, &stored.name);
                        }
                        document.connections[pos] = stored;
                        summary.updated += 1;
                    } else {
                        summary.unchanged += 1;
                    }
                    continue;
                }

                // Unknown UUID: avoid duplicating identical item imported previously under another ID.
                let mut identical_exists = false;
                for existing in document
                    .connections
                    .iter()
                    .filter(|c| same_item_name(&c.name, &stored.name))
                {
                    let existing_secrets: SecretBundle = key.decrypt(&existing.encrypted_secrets)?;
                    if same_portable_content(
                        existing,
                        &existing_secrets,
                        &stored,
                        &imported_secrets,
                    ) {
                        identical_exists = true;
                        break;
                    }
                }
                if identical_exists {
                    summary.unchanged += 1;
                    continue;
                }

                document.deleted_ids.retain(|t| t.id != stored.id);
                if document
                    .connections
                    .iter()
                    .any(|c| same_item_name(&c.name, &stored.name))
                {
                    stored.name = unique_import_name(&document.connections, &stored.name);
                }
                document.connections.push(stored);
                summary.added += 1;
            }

            // 3. Merge remote trash entries (trashing local active items if remote deletion is newer).
            for entry in remote_trash {
                if parse_ts(&entry.deleted_at).is_none() {
                    continue;
                }
                let id = entry.connection.id;
                if let Some(tomb) = document.deleted_ids.iter().find(|t| t.id == id)
                    && is_newer(&tomb.deleted_at, &entry.deleted_at)
                {
                    summary.unchanged += 1;
                    continue;
                }
                if let Some(pos) = document.connections.iter().position(|c| c.id == id) {
                    if is_newer(&entry.deleted_at, &document.connections[pos].updated_at) {
                        let removed = document.connections.remove(pos);
                        document.trash.insert(
                            0,
                            crate::model::StoredTrashItem {
                                deleted_at: entry.deleted_at,
                                connection: removed,
                            },
                        );
                        summary.deleted += 1;
                    } else {
                        summary.unchanged += 1;
                    }
                    continue;
                }
                if document.trash.iter().any(|t| t.connection.id == id) {
                    summary.unchanged += 1;
                    continue;
                }
                let stored = stored_from_portable(&entry.connection, &entry.secrets, key)?;
                document.trash.push(crate::model::StoredTrashItem {
                    deleted_at: entry.deleted_at,
                    connection: stored,
                });
                summary.added += 1;
            }

            Ok(summary)
        })
        })
    }

    pub fn preview_merge_backup_entries(
        &self,
        imported: &[(PortableConnection, SecretBundle)],
        trash: &[crate::model::PortableTrashItem],
    ) -> Result<crate::backup::BackupMergeStats> {
        let document = self.read_document()?;
        self.with_key(|key| {
            let mut simulated = document.connections;
            let mut simulated_trash = document.trash;
            let mut stats = crate::backup::BackupMergeStats {
                total_items: imported.len(),
                trash_count: trash.len(),
                items: Vec::with_capacity(imported.len() + trash.len()),
                ..Default::default()
            };
            for (index, (public, secrets)) in imported.iter().enumerate() {
                stats.passkey_count += secrets.passkeys.len();
                stats.history_entries += secrets.password_history.len();
                let mut stored = stored_from_portable(public, secrets, key)?;
                let requested_name = clean_text(&stored.name, 80);
                stored.name = if requested_name.is_empty() {
                    "Import project".to_owned()
                } else {
                    requested_name
                };
                if stats.sample_names.len() < 6 {
                    stats.sample_names.push(stored.name.clone());
                }

                let public_view = stored.public(Some(secrets));
                let summary = backup_preview_summary(&public_view);
                let original_name = stored.name.clone();
                let item_id = stored.id.to_string();
                let item_type = public_view.item_type.clone();
                let folder = public_view.folder.clone();
                let passkey_count = secrets.passkeys.len();
                let history_count = secrets.password_history.len();

                let has_requested_name = simulated
                    .iter()
                    .any(|item| same_item_name(&item.name, &stored.name));
                let mut duplicate = false;
                for existing in simulated.iter().filter(|item| {
                    same_item_name(&item.name, &stored.name)
                        || (has_requested_name && import_name_in_family(&item.name, &stored.name))
                }) {
                    let existing_secrets: SecretBundle = key.decrypt(&existing.encrypted_secrets)?;
                    if same_portable_content(existing, &existing_secrets, &stored, secrets) {
                        duplicate = true;
                        break;
                    }
                }
                if duplicate {
                    stats.duplicate_skipped += 1;
                    stats.items.push(crate::backup::BackupPreviewItem {
                        index,
                        kind: "item".to_owned(),
                        id: item_id,
                        name: original_name,
                        item_type,
                        folder,
                        summary,
                        status: "duplicate".to_owned(),
                        assigned_name: None,
                        passkey_count,
                        history_count,
                        deleted_at: None,
                    });
                    continue;
                }
                let assigned = unique_import_name(&simulated, &stored.name);
                let is_conflict = assigned != stored.name;
                if is_conflict {
                    stats.name_conflicts += 1;
                    if stats.conflict_renames.len() < 6 {
                        stats
                            .conflict_renames
                            .push(format!("{} → {}", stored.name, assigned));
                    }
                }
                stored.name = assigned.clone();
                simulated.push(stored);
                stats.new_items += 1;
                stats.items.push(crate::backup::BackupPreviewItem {
                    index,
                    kind: "item".to_owned(),
                    id: item_id,
                    name: original_name,
                    item_type,
                    folder,
                    summary,
                    status: if is_conflict {
                        "conflict".to_owned()
                    } else {
                        "new".to_owned()
                    },
                    assigned_name: is_conflict.then_some(assigned),
                    passkey_count,
                    history_count,
                    deleted_at: None,
                });
            }
            for (index, entry) in trash.iter().enumerate() {
                let stored = stored_from_portable(&entry.connection, &entry.secrets, key)?;
                let public_view = stored.public(Some(&entry.secrets));
                let summary = backup_preview_summary(&public_view);
                let mut duplicate = false;
                for existing in simulated_trash.iter().map(|e| &e.connection) {
                    if same_item_name(&existing.name, &stored.name) {
                        let existing_secrets: SecretBundle =
                            key.decrypt(&existing.encrypted_secrets)?;
                        if same_portable_content(existing, &existing_secrets, &stored, &entry.secrets)
                        {
                            duplicate = true;
                            break;
                        }
                    }
                }
                let status = if duplicate {
                    "duplicate".to_owned()
                } else {
                    simulated_trash.push(crate::model::StoredTrashItem {
                        deleted_at: entry.deleted_at.clone(),
                        connection: stored.clone(),
                    });
                    "new".to_owned()
                };
                stats.items.push(crate::backup::BackupPreviewItem {
                    index,
                    kind: "trash".to_owned(),
                    id: stored.id.to_string(),
                    name: stored.name,
                    item_type: public_view.item_type,
                    folder: public_view.folder,
                    summary,
                    status,
                    assigned_name: None,
                    passkey_count: entry.secrets.passkeys.len(),
                    history_count: entry.secrets.password_history.len(),
                    deleted_at: Some(entry.deleted_at.clone()),
                });
            }
            Ok(stats)
        })
    }

    pub fn merge_connections(
        &self,
        imported: Vec<(PortableConnection, SecretBundle)>,
    ) -> Result<ImportSummary> {
        self.merge_backup_entries(imported, Vec::new())
    }

    pub fn merge_backup_entries(
        &self,
        imported: Vec<(PortableConnection, SecretBundle)>,
        trash: Vec<crate::model::PortableTrashItem>,
    ) -> Result<ImportSummary> {
        let summary = self.with_key(|key| {
            self.update_document_with_result(|document| {
            let mut summary = ImportSummary {
                added: 0,
                merged: 0,
            };
            for (public, secrets) in imported {
                let mut stored = stored_from_portable(&public, &secrets, key)?;
                let imported_secrets: SecretBundle = key.decrypt(&stored.encrypted_secrets)?;
                let requested_name = clean_text(&stored.name, 80);
                stored.name = if requested_name.is_empty() {
                    "Import project".to_owned()
                } else {
                    requested_name
                };

                let has_requested_name = document
                    .connections
                    .iter()
                    .any(|item| same_item_name(&item.name, &stored.name));
                let mut duplicate = false;
                for existing in document.connections.iter().filter(|item| {
                    same_item_name(&item.name, &stored.name)
                        || (has_requested_name && import_name_in_family(&item.name, &stored.name))
                }) {
                    let existing_secrets: SecretBundle = key.decrypt(&existing.encrypted_secrets)?;
                    if same_portable_content(
                        existing,
                        &existing_secrets,
                        &stored,
                        &imported_secrets,
                    ) {
                        duplicate = true;
                        break;
                    }
                }

                if duplicate {
                    summary.merged += 1;
                    continue;
                }

                stored.name = unique_import_name(&document.connections, &stored.name);
                if document.connections.iter().any(|item| item.id == stored.id)
                    || document
                        .trash
                        .iter()
                        .any(|item| item.connection.id == stored.id)
                {
                    stored.id = Uuid::new_v4();
                } else {
                    outlive_local_tombstone(document, stored.id, &mut stored.updated_at);
                }
                document.connections.push(stored);
                summary.added += 1;
            }
            for entry in trash {
                chrono::DateTime::parse_from_rfc3339(&entry.deleted_at)
                    .context("Invalid trash deletion date")?;
                let mut stored = stored_from_portable(&entry.connection, &entry.secrets, key)?;
                let mut duplicate = false;
                for existing in document.trash.iter().map(|entry| &entry.connection) {
                    if same_item_name(&existing.name, &stored.name) {
                        let secrets: SecretBundle = key.decrypt(&existing.encrypted_secrets)?;
                        if same_portable_content(existing, &secrets, &stored, &entry.secrets) {
                            duplicate = true;
                            break;
                        }
                    }
                }
                if duplicate {
                    summary.merged += 1;
                    continue;
                }
                let mut deleted_at = entry.deleted_at;
                if document.connections.iter().any(|item| item.id == stored.id)
                    || document
                        .trash
                        .iter()
                        .any(|item| item.connection.id == stored.id)
                {
                    stored.id = Uuid::new_v4();
                } else {
                    outlive_local_tombstone(document, stored.id, &mut deleted_at);
                }
                document.trash.push(crate::model::StoredTrashItem {
                    deleted_at,
                    connection: stored,
                });
                summary.added += 1;
            }
            Ok(summary)
        })
        })?;
        // Logged after the vault write completes so the activity lock is never
        // taken while the vault lock is held. The import is already committed,
        // so a logging failure must not report it as failed.
        let _ = self.add_activity(NewActivity {
            status: "success".to_owned(),
            source: "Apply".to_owned(),
            connection_name: "Portable backup".to_owned(),
            action: format!(
                "Import backup: added {}, merged duplicates {}",
                summary.added, summary.merged
            ),
            duration_ms: 0,
            error: String::new(),
        });
        Ok(summary)
    }

    /// Compares the active items of an earlier snapshot with this vault by id. An item
    /// is `same` only when restoring it would leave it exactly as it is now, which is
    /// the same test `restore_history_items` applies when it commits.
    pub fn preview_history_items(
        &self,
        items: &[(PortableConnection, SecretBundle)],
    ) -> Result<Vec<crate::backup::HistoryPreviewItem>> {
        let document = self.read_document()?;
        self.with_key(|key| {
            let mut seen = std::collections::HashSet::new();
            let mut preview = Vec::with_capacity(items.len());
            for (public, secrets) in items {
                if !seen.insert(public.id) {
                    continue;
                }
                let plan = plan_history_restore(&document, key, public, secrets)?;
                let status = match plan.current {
                    HistoryCurrent::Active(_) if plan.unchanged => "same",
                    HistoryCurrent::Active(_) => "changed",
                    HistoryCurrent::Trash => "trash",
                    HistoryCurrent::Gone => "deleted",
                };
                let view = plan.stored.public(Some(&plan.secrets));
                let requested = restored_item_name(&public.name);
                preview.push(crate::backup::HistoryPreviewItem {
                    id: public.id.to_string(),
                    summary: backup_preview_summary(&view),
                    item_type: view.item_type,
                    folder: view.folder,
                    current_name: plan.current_name.filter(|name| name != &requested),
                    assigned_name: (status != "same" && plan.stored.name != requested)
                        .then(|| plan.stored.name.clone()),
                    name: requested,
                    status: status.to_owned(),
                    passkey_count: secrets.passkeys.len(),
                    history_count: secrets.password_history.len(),
                });
            }
            Ok(preview)
        })
    }

    /// Brings items of an earlier snapshot back as fresh edits: same id, a timestamp
    /// newer than anything this device knows about the item, and no same-id trash
    /// entry or tombstone left behind. Last-writer-wins then carries the restored
    /// version to every device. Replacing the whole vault would not work, because the
    /// next sync would bring back newer items and re-delete tombstoned ones.
    pub fn restore_history_items(
        &self,
        items: Vec<(PortableConnection, SecretBundle)>,
        version_label: &str,
    ) -> Result<crate::backup::HistoryRestoreSummary> {
        let summary = self.with_key(|key| {
            self.update_document_with_result(|document| {
                let mut summary = crate::backup::HistoryRestoreSummary::default();
                let mut seen = std::collections::HashSet::new();
                for (public, secrets) in items {
                    if !seen.insert(public.id) {
                        continue;
                    }
                    // Planned against the document inside this transaction, so a sync
                    // or edit that landed after the preview is taken into account.
                    let plan = plan_history_restore(document, key, &public, &secrets)?;
                    if plan.unchanged {
                        summary.unchanged += 1;
                        continue;
                    }
                    let id = public.id;
                    let mut known: Vec<&str> = Vec::new();
                    if let HistoryCurrent::Active(index) = plan.current {
                        known.push(&document.connections[index].updated_at);
                    }
                    for entry in document.trash.iter().filter(|entry| entry.connection.id == id) {
                        known.push(&entry.deleted_at);
                        known.push(&entry.connection.updated_at);
                    }
                    for tomb in document.deleted_ids.iter().filter(|tomb| tomb.id == id) {
                        known.push(&tomb.deleted_at);
                    }
                    let mut stored = plan.stored;
                    stored.updated_at = restore_stamp(known);
                    document.trash.retain(|entry| entry.connection.id != id);
                    document.deleted_ids.retain(|tomb| tomb.id != id);
                    match plan.current {
                        HistoryCurrent::Active(index) => document.connections[index] = stored,
                        HistoryCurrent::Trash | HistoryCurrent::Gone => {
                            document.connections.push(stored)
                        }
                    }
                    summary.restored += 1;
                }
                Ok(summary)
            })
        })?;
        // Logged after the vault write, as for backup imports: the activity lock is
        // never taken under the vault lock, and the restore is already committed.
        if summary.restored > 0 {
            let _ = self.add_activity(NewActivity {
                status: "success".to_owned(),
                source: "Apply".to_owned(),
                connection_name: "Version history".to_owned(),
                action: format!(
                    "Restore from version {version_label}: restored {}, unchanged {}",
                    summary.restored, summary.unchanged
                ),
                duration_ms: 0,
                error: String::new(),
            });
        }
        Ok(summary)
    }
}

enum HistoryCurrent {
    Active(usize),
    Trash,
    Gone,
}

struct HistoryRestorePlan {
    current: HistoryCurrent,
    current_name: Option<String>,
    stored: StoredConnection,
    secrets: SecretBundle,
    unchanged: bool,
}

/// What restoring `public` from an earlier snapshot would produce against `document`.
fn plan_history_restore(
    document: &crate::model::VaultDocument,
    key: &MasterKey,
    public: &PortableConnection,
    old_secrets: &SecretBundle,
) -> Result<HistoryRestorePlan> {
    let (current, current_stored) =
        if let Some(index) = document.connections.iter().position(|c| c.id == public.id) {
            (HistoryCurrent::Active(index), Some(&document.connections[index]))
        } else if let Some(entry) = document.trash.iter().find(|t| t.connection.id == public.id) {
            (HistoryCurrent::Trash, Some(&entry.connection))
        } else {
            (HistoryCurrent::Gone, None)
        };
    let current_secrets: Option<SecretBundle> = current_stored
        .map(|stored| key.decrypt(&stored.encrypted_secrets))
        .transpose()?;
    let secrets = restored_secret_bundle(old_secrets, current_secrets.as_ref());
    let mut stored = stored_from_portable(public, &secrets, key)?;
    stored.name = unique_item_name(&restored_item_name(&public.name), |candidate| {
        document
            .connections
            .iter()
            .any(|item| item.id != public.id && same_item_name(&item.name, candidate))
    });
    let unchanged = match (&current, current_stored, current_secrets.as_ref()) {
        (HistoryCurrent::Active(_), Some(existing), Some(existing_secrets)) => {
            same_synced_state(existing, existing_secrets, &stored, &secrets)
        }
        _ => false,
    };
    Ok(HistoryRestorePlan {
        current,
        current_name: current_stored.map(|stored| stored.name.clone()),
        stored,
        secrets,
        unchanged,
    })
}

fn restored_item_name(name: &str) -> String {
    let name = clean_text(name, 80);
    if name.is_empty() {
        "Restored item".to_owned()
    } else {
        name
    }
}

/// The version's secrets, except for what must not go backwards. Password history is
/// the current one with the current password pushed onto it, so restoring never
/// loses a password. Passkeys are the union by credential id, keeping the entry with
/// the higher signature counter: dropping a credential registered later, or lowering
/// a counter, would make relying parties reject the authenticator.
fn restored_secret_bundle(old: &SecretBundle, current: Option<&SecretBundle>) -> SecretBundle {
    let mut next = old.clone();
    let Some(current) = current else {
        return next;
    };
    next.password_history = current.password_history.clone();
    next.remember_password_change(current.get("password"));
    // Current order first, so an item whose passkeys did not change compares equal.
    let mut passkeys = current.passkeys.clone();
    for passkey in &old.passkeys {
        match passkeys
            .iter_mut()
            .find(|existing| existing.credential_id == passkey.credential_id)
        {
            Some(existing) if passkey.counter > existing.counter => *existing = passkey.clone(),
            Some(_) => {}
            None => passkeys.push(passkey.clone()),
        }
    }
    next.passkeys = passkeys;
    next
}

/// A timestamp later than every one given and than now. Clocks differ between
/// devices, so a tombstone written by a device running ahead can be dated in the
/// future; a restored item stamped only with this device's `now` would lose to it.
pub(super) fn restore_stamp<'a>(known: impl IntoIterator<Item = &'a str>) -> String {
    let mut latest = Utc::now();
    for value in known {
        if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(value) {
            latest = latest.max(parsed.with_timezone(&Utc));
        }
    }
    (latest + chrono::Duration::milliseconds(1)).to_rfc3339()
}

/// An imported item that keeps the id of a purged item would keep its old timestamp
/// and lose to the tombstone on the next sync, which deletes it again. Stamping it
/// past the tombstone and dropping the tombstone makes the import stick everywhere.
fn outlive_local_tombstone(document: &mut crate::model::VaultDocument, id: Uuid, stamp: &mut String) {
    let Some(deleted_at) = document
        .deleted_ids
        .iter()
        .find(|tomb| tomb.id == id)
        .map(|tomb| tomb.deleted_at.clone())
    else {
        return;
    };
    *stamp = restore_stamp([stamp.as_str(), deleted_at.as_str()]);
    document.deleted_ids.retain(|tomb| tomb.id != id);
}

pub(super) fn stored_from_portable(
    portable: &PortableConnection,
    secrets: &SecretBundle,
    key: &MasterKey,
) -> Result<StoredConnection> {
    let input = ConnectionInput {
        login_uris: portable.login_uris.clone(),
        item_type: portable.item_type.clone(),
        folder: portable.folder.clone(),
        favorite: portable.favorite,
        id: Some(portable.id),
        modules: portable.modules.clone(),
        name: portable.name.clone(),
        enabled: portable.enabled,
        description: portable.description.clone(),
        http_auth_type: portable.http_auth_type.clone(),
        private_key_import_path: String::new(),
        auth_header: portable.auth_header.clone(),
        auth_location: portable.auth_location.clone(),
        auth_prefix: portable.auth_prefix.clone(),
        api_auth_headers: portable.api_auth_headers.clone(),
        test_path: portable.test_path.clone(),
        remove_secret_names: Vec::new(),
        secrets: secrets.clone(),
    };
    let mut stored = normalize_connection(
        input,
        None,
        secrets,
        portable.private_key_name.clone(),
        portable.updated_at.clone(),
    )?;
    stored.created_at = portable.created_at.clone();
    stored.encrypted_secrets = key.encrypt(&secrets)?;
    Ok(stored)
}

pub(super) fn same_synced_state(
    left: &StoredConnection,
    left_secrets: &SecretBundle,
    right: &StoredConnection,
    right_secrets: &SecretBundle,
) -> bool {
    left.name == right.name
        && left.enabled == right.enabled
        && left.description == right.description
        && left.http_auth_type == right.http_auth_type
        && left.private_key_name == right.private_key_name
        && left.auth_header == right.auth_header
        && left.auth_location == right.auth_location
        && left.auth_prefix == right.auth_prefix
        && left.api_auth_headers == right.api_auth_headers
        && left.test_path == right.test_path
        && same_portable_content(left, left_secrets, right, right_secrets)
}

pub(super) fn same_portable_content(
    left: &StoredConnection,
    left_secrets: &SecretBundle,
    right: &StoredConnection,
    right_secrets: &SecretBundle,
) -> bool {
    if left.login_uris != right.login_uris
        || left.modules != right.modules
        || left.item_type() != right.item_type()
        || left.folder != right.folder
        || left.favorite != right.favorite
    {
        return false;
    }
    if left_secrets.passkeys != right_secrets.passkeys
        || left_secrets.password_history != right_secrets.password_history
        || left_secrets.agent_notes != right_secrets.agent_notes
        || left_secrets.agent_notes_locked != right_secrets.agent_notes_locked
    {
        return false;
    }
    for module in &left.modules {
        let Some(name) = module.secret_name() else {
            continue;
        };
        if left_secrets.get(name) != right_secrets.get(name) {
            return false;
        }
    }
    true
}

pub(super) fn import_name_in_family(candidate: &str, requested: &str) -> bool {
    let Some((candidate_base, candidate_index)) = split_numbered_import_name(candidate) else {
        return false;
    };
    let (requested_base, requested_index) = split_numbered_import_name(requested)
        .map(|(base, index)| (base, index + 1))
        .unwrap_or((requested, 2));
    same_item_name(candidate_base, requested_base) && candidate_index >= requested_index
}

pub(super) fn split_numbered_import_name(name: &str) -> Option<(&str, usize)> {
    let without_closing = name.strip_suffix(')')?;
    let opening = without_closing.rfind('(')?;
    let index = without_closing[opening + 1..].parse::<usize>().ok()?;
    ((2..usize::MAX).contains(&index) && opening > 0)
        .then_some((&without_closing[..opening], index))
}

pub(super) fn backup_preview_summary(public: &PublicConnection) -> String {
    let mut parts: Vec<String> = Vec::new();
    let host = public
        .modules
        .iter()
        .find(|m| m.kind == "host" && !m.value.trim().is_empty())
        .map(|m| m.value.trim());
    let port = public
        .modules
        .iter()
        .find(|m| m.kind == "port" && !m.value.trim().is_empty())
        .map(|m| m.value.trim());
    let url = public
        .modules
        .iter()
        .find(|m| m.kind == "url" && !m.value.trim().is_empty())
        .map(|m| m.value.trim())
        .or_else(|| {
            public
                .login_uris
                .iter()
                .map(|u| u.uri.trim())
                .find(|u| !u.is_empty())
        });

    if let Some(h) = host {
        if let Some(p) = port {
            parts.push(format!("{h}:{p}"));
        } else {
            parts.push(h.to_owned());
        }
    } else if let Some(u) = url {
        let compact = u
            .strip_prefix("https://")
            .or_else(|| u.strip_prefix("http://"))
            .unwrap_or(u)
            .trim_end_matches('/');
        if !compact.is_empty() {
            parts.push(compact.chars().take(64).collect());
        }
    }

    let desc = public.description.trim();
    if !desc.is_empty() && parts.is_empty() {
        parts.push(desc.chars().take(64).collect());
    }

    parts.join(" · ")
}

pub(super) fn unique_import_name(connections: &[StoredConnection], requested: &str) -> String {
    unique_item_name(requested, |candidate| {
        connections
            .iter()
            .any(|item| same_item_name(&item.name, candidate))
    })
}

pub(super) fn unique_item_name<F>(requested: &str, exists: F) -> String
where
    F: Fn(&str) -> bool,
{
    if !exists(requested) {
        return requested.to_owned();
    }
    let (base, mut index) = split_numbered_import_name(requested)
        .map(|(base, index)| (base, index + 1))
        .unwrap_or((requested, 2));
    loop {
        let candidate = format!("{base}({index})");
        if !exists(&candidate) {
            return candidate;
        }
        index += 1;
    }
}

pub(super) fn same_item_name(left: &str, right: &str) -> bool {
    left.trim().to_lowercase() == right.trim().to_lowercase()
}

pub(super) fn empty_envelope() -> crate::model::SecretEnvelope {
    crate::model::SecretEnvelope {
        version: 0,
        nonce: String::new(),
        ciphertext: String::new(),
    }
}

pub(super) fn merge_secret_bundle(current: &mut SecretBundle, next: &SecretBundle) {
    if next.password.as_ref().is_some_and(|v| !v.is_empty()) {
        current.password = next.password.clone();
    }
    if next.passphrase.as_ref().is_some_and(|v| !v.is_empty()) {
        current.passphrase = next.passphrase.clone();
    }
    if next.private_key.as_ref().is_some_and(|v| !v.is_empty()) {
        current.private_key = next.private_key.clone();
        if next.private_key_name.as_ref().is_some_and(|v| !v.is_empty()) {
            current.private_key_name = next.private_key_name.clone();
        }
    }
    if next.token.as_ref().is_some_and(|v| !v.is_empty()) {
        current.token = next.token.clone();
    }
    if next.api_key.as_ref().is_some_and(|v| !v.is_empty()) {
        current.api_key = next.api_key.clone();
    }
    for (name, value) in next.named_secrets.iter() {
        if !value.is_empty() {
            current.named_secrets.insert(name.clone(), value.clone());
        }
    }
}

