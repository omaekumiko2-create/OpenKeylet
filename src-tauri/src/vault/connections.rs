use super::*;

impl Vault {
    pub fn list_connections(&self) -> Result<Vec<PublicConnection>> {
        self.list_decrypted_connections().map(|connections| {
            connections
                .into_iter()
                .map(|connection| connection.stored.public(Some(&connection.secrets)))
                .collect()
        })
    }

    pub fn list_decrypted_connections(&self) -> Result<Vec<DecryptedConnection>> {
        let document = self.read_document()?;
        self.with_key(|key| {
            document
                .connections
                .into_iter()
                .map(|stored| {
                    let secrets = key.decrypt(&stored.encrypted_secrets)?;
                    Ok(DecryptedConnection { stored, secrets })
                })
                .collect()
        })
    }

    pub fn get_connection(&self, id: Uuid) -> Result<DecryptedConnection> {
        let document = self.read_document()?;
        let stored = document
            .connections
            .into_iter()
            .find(|connection| connection.id == id)
            .context("Connection not found")?;
        let secrets = self.with_key(|key| key.decrypt(&stored.encrypted_secrets))?;
        Ok(DecryptedConnection { stored, secrets })
    }

    pub fn get_secret_value(&self, id: Uuid, field: &str) -> Result<(String, String, String)> {
        let connection = self.get_connection(id)?;
        if !connection.stored.enabled {
            bail!("This project is disabled");
        }
        // Module names are length-checked when saved. Do not truncate a caller's
        // lookup here: a longer, different name must never alias an existing
        // credential and fill the wrong value.
        let field = field.trim().to_owned();
        let metadata = connection
            .secrets
            .available_fields(connection.stored.secret.as_ref())
            .into_iter()
            .find(|candidate| candidate.name == field)
            .context("This project does not have this secret field")?;
        let value = connection
            .secrets
            .get(&field)
            .context("This secret field has not been configured")?
            .to_owned();
        Ok((connection.stored.name, metadata.kind, value))
    }

    pub fn get_module_value(
        &self,
        id: Uuid,
        field: &str,
    ) -> Result<(String, String, String, bool)> {
        let connection = self.get_connection(id)?;
        if !connection.stored.enabled {
            bail!("This project is disabled");
        }
        let field = field.trim();
        if let Some(metadata) = connection
            .secrets
            .available_fields(connection.stored.secret.as_ref())
            .into_iter()
            .find(|candidate| candidate.name == field)
        {
            let value = connection
                .secrets
                .get(field)
                .context("This secret field has not been configured")?
                .to_owned();
            return Ok((connection.stored.name, metadata.kind, value, true));
        }
        if let Some(module) = connection
            .stored
            .modules
            .iter()
            .find(|module| !module.is_secret() && module.kind == field)
        {
            let value = module.value.trim().to_owned();
            if value.is_empty() {
                bail!("This module has not been configured");
            }
            return Ok((connection.stored.name, module.kind.clone(), value, false));
        }
        bail!("This project does not have this module or secret field")
    }

    pub fn save_connection(&self, input: ConnectionInput) -> Result<PublicConnection> {
        self.save_connection_checked(input, None)
    }

    pub fn save_connection_checked(
        &self,
        mut input: ConnectionInput,
        expected_updated_at: Option<&str>,
    ) -> Result<PublicConnection> {
        self.update_document_with_result(|document| {
            let existing_index = input.id.and_then(|id| {
                document
                    .connections
                    .iter()
                    .position(|connection| connection.id == id)
            });
            let existing = existing_index.map(|index| document.connections[index].clone());
            if input
                .id
                .is_some_and(|id| document.trash.iter().any(|item| item.connection.id == id))
            {
                bail!("This item is in the trash; restore it before editing");
            }
            if let Some(expected) = expected_updated_at {
                if existing
                    .as_ref()
                    .is_none_or(|item| item.updated_at != expected)
                {
                    bail!("This item changed or was deleted; close and reopen it before saving");
                }
            }
            let mut secrets = if let Some(connection) = &existing {
                self.with_key(|key| key.decrypt::<SecretBundle>(&connection.encrypted_secrets))?
            } else {
                SecretBundle::default()
            };
            let previous_password =
                zeroize::Zeroizing::new(secrets.get("password").map(str::to_owned));
            if !input.modules.is_empty() {
                input.modules = normalize_modules(input.modules.clone())?;
                if let Some(connection) = &existing {
                    let retained = input
                        .modules
                        .iter()
                        .filter_map(ItemModule::secret_name)
                        .collect::<Vec<_>>();
                    for removed in connection
                        .modules
                        .iter()
                        .filter_map(ItemModule::secret_name)
                        .filter(|name| !retained.contains(name))
                    {
                        input.remove_secret_names.push(removed.to_owned());
                    }
                }
            }
            merge_secret_bundle(&mut secrets, &input.secrets);
            for name in &input.remove_secret_names {
                secrets.named_secrets.remove(name.trim());
                match name.trim() {
                    "password" => secrets.password = None,
                    "passphrase" => secrets.passphrase = None,
                    "privateKey" | "private_key" => {
                        secrets.private_key = None;
                        secrets.private_key_name = None;
                    }
                    "token" => secrets.token = None,
                    "apiKey" | "api_key" => secrets.api_key = None,
                    "apiCredential" | "api_credential" => {
                        secrets.named_secrets.remove("apiCredential");
                        secrets.token = None;
                        secrets.api_key = None;
                    }
                    _ => {}
                }
            }

            input.name = checked_text(&input.name, "Project name", 80)?;
            if input.name.is_empty() {
                bail!("Project name cannot be empty");
            }
            if document
                .connections
                .iter()
                .enumerate()
                .any(|(index, item)| {
                    Some(index) != existing_index && same_item_name(&item.name, &input.name)
                })
            {
                bail!("Project name already exists; use a different name");
            }
            if input.modules.is_empty() {
                bail!("Project must have at least one module");
            }

            let mut imported_key_name = existing
                .as_ref()
                .map(|v| v.private_key_name.clone())
                .unwrap_or_default();
            if !input.private_key_import_path.trim().is_empty() {
                let path = PathBuf::from(input.private_key_import_path.trim());
                secrets.private_key = Some(
                    fs::read_to_string(&path).context("SSH private key must be in text format")?,
                );
                imported_key_name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("SSH KEY")
                    .to_owned();
                secrets.private_key_name = Some(imported_key_name.clone());
            } else if let Some(name) = secrets
                .private_key_name
                .as_deref()
                .filter(|s| !s.trim().is_empty())
            {
                imported_key_name = name.trim().to_owned();
            }

            prepare_auto_api(&mut input, &mut secrets)?;
            secrets.remember_password_change(previous_password.as_deref());

            let now = Utc::now().to_rfc3339();
            let mut stored =
                normalize_connection(input, existing.as_ref(), &secrets, imported_key_name, now)?;
            stored.encrypted_secrets = self.with_key(|key| key.encrypt(&secrets))?;
            let public = stored.public(Some(&secrets));
            if let Some(index) = existing_index {
                document.connections[index] = stored;
            } else {
                document.connections.push(stored);
            }
            Ok(public)
        })
    }

    pub fn reorder_connections(&self, ids: &[Uuid], expected_order: &[Uuid]) -> Result<()> {
        self.update_document(|document| {
            let current: Vec<Uuid> = document.connections.iter().map(|item| item.id).collect();
            if current != expected_order {
                bail!("The item list changed; refresh before reordering");
            }
            let positions: std::collections::HashMap<Uuid, usize> = ids
                .iter()
                .copied()
                .enumerate()
                .map(|(index, id)| (id, index))
                .collect();
            if positions.len() != ids.len()
                || ids.len() != current.len()
                || current.iter().any(|id| !positions.contains_key(id))
            {
                bail!("The order must contain every current item exactly once");
            }
            // Order is presentation metadata; preserve revisions and encrypted payloads.
            document.connections.sort_by_key(|item| positions[&item.id]);
            Ok(())
        })
    }

    #[cfg(test)]
    pub fn delete_connection(&self, id: Uuid) -> Result<()> {
        self.trash_connection(id, None)
    }

    pub fn trash_connection(&self, id: Uuid, expected_updated_at: Option<&str>) -> Result<()> {
        self.update_document(|document| {
            let index = document
                .connections
                .iter()
                .position(|item| item.id == id)
                .context("Connection not found")?;
            if expected_updated_at
                .is_some_and(|expected| document.connections[index].updated_at != expected)
            {
                bail!("This item changed; refresh before moving it to trash");
            }
            let connection = document.connections.remove(index);
            document.trash.insert(
                0,
                crate::model::StoredTrashItem {
                    deleted_at: Utc::now().to_rfc3339(),
                    connection,
                },
            );
            Ok(())
        })
    }

    pub fn trash_items(&self) -> Result<Vec<crate::model::PublicTrashItem>> {
        let trash = self.read_document()?.trash;
        self.with_key(|key| {
            trash
                .into_iter()
                .map(|entry| {
                    let secrets: SecretBundle = key.decrypt(&entry.connection.encrypted_secrets)?;
                    Ok(crate::model::PublicTrashItem {
                        deleted_at: entry.deleted_at,
                        item: entry.connection.public(Some(&secrets)),
                    })
                })
                .collect()
        })
    }

    pub fn restore_connection(&self, id: Uuid, deleted_at: &str) -> Result<()> {
        self.update_document(|document| {
            let index = document
                .trash
                .iter()
                .position(|entry| entry.connection.id == id && entry.deleted_at == deleted_at)
                .context("Trash item changed; refresh before restoring")?;
            let mut stored = document.trash.remove(index).connection;
            stored.name = unique_import_name(&document.connections, &stored.name);
            if document.connections.iter().any(|item| item.id == stored.id) {
                stored.id = Uuid::new_v4();
            }
            stored.updated_at = Utc::now().to_rfc3339();
            document.connections.push(stored);
            Ok(())
        })
    }

    pub fn purge_connection(&self, id: Uuid, deleted_at: &str) -> Result<()> {
        self.update_document(|document| {
            let index = document
                .trash
                .iter()
                .position(|entry| entry.connection.id == id && entry.deleted_at == deleted_at)
                .context("Trash item changed; refresh before deleting permanently")?;
            document.trash.remove(index);
            document.deleted_ids.retain(|entry| entry.id != id);
            document.deleted_ids.insert(
                0,
                crate::model::DeletedItemTombstone {
                    id,
                    deleted_at: Utc::now().to_rfc3339(),
                },
            );
            document.deleted_ids.truncate(500);
            Ok(())
        })
    }

    pub fn password_history(&self, id: Uuid) -> Result<Vec<crate::model::PasswordHistoryEntry>> {
        Ok(self.get_connection(id)?.secrets.password_history.clone())
    }

    pub fn clear_password_history(&self, id: Uuid, expected_updated_at: &str) -> Result<()> {
        self.update_document(|document| {
            let stored = document
                .connections
                .iter_mut()
                .find(|item| item.id == id)
                .context("Connection not found")?;
            if stored.updated_at != expected_updated_at {
                bail!("This item changed; refresh before clearing history");
            }
            let mut secrets: SecretBundle =
                self.with_key(|key| key.decrypt(&stored.encrypted_secrets))?;
            secrets.password_history.clear();
            stored.encrypted_secrets = self.with_key(|key| key.encrypt(&secrets))?;
            stored.updated_at = Utc::now().to_rfc3339();
            Ok(())
        })
    }

    pub fn add_agent_note(
        &self,
        id: Uuid,
        text: &str,
        author: &str,
        enforce_agent_guards: bool,
    ) -> Result<PublicConnection> {
        let clean_note = crate::policy::sanitize_agent_note_text(text)?;
        let clean_author = crate::policy::sanitize_agent_note_author(author);
        self.update_document_with_result(|document| {
            let index = document
                .connections
                .iter()
                .position(|item| item.id == id)
                .context("Connection not found")?;
            if enforce_agent_guards && !document.connections[index].enabled {
                bail!("This project is disabled");
            }
            let mut secrets: SecretBundle = self.with_key(|key| {
                key.decrypt(&document.connections[index].encrypted_secrets)
            })?;
            if enforce_agent_guards && secrets.agent_notes_locked {
                bail!(
                    "Agent notes for '{}' are locked by the owner and cannot be modified by agents",
                    document.connections[index].name
                );
            }
            if enforce_agent_guards {
                let decrypted_all: Vec<SecretBundle> = self.with_key(|key| {
                    document
                        .connections
                        .iter()
                        .map(|conn| key.decrypt::<SecretBundle>(&conn.encrypted_secrets))
                        .collect()
                })?;
                let pairs: Vec<(&StoredConnection, &SecretBundle)> = document
                    .connections
                    .iter()
                    .zip(decrypted_all.iter())
                    .collect();
                crate::policy::validate_agent_note_no_secrets(
                    &clean_note,
                    pairs[index],
                    &pairs,
                )?;
            }

            let now = Utc::now().to_rfc3339();
            if let Some(dup_pos) = secrets
                .agent_notes
                .iter()
                .position(|entry| entry.text.eq_ignore_ascii_case(&clean_note))
            {
                if enforce_agent_guards && secrets.agent_notes[dup_pos].author == "OWNER" {
                    return Ok(document.connections[index].public(Some(&secrets)));
                }
                let mut existing = secrets.agent_notes.remove(dup_pos);
                existing.text = clean_note;
                existing.author = clean_author;
                existing.updated_at = now.clone();
                secrets.agent_notes.insert(0, existing);
            } else {
                if enforce_agent_guards
                    && secrets.agent_notes.len() >= crate::model::MAX_AGENT_NOTES
                    && !secrets
                        .agent_notes
                        .iter()
                        .any(|entry| entry.author != "OWNER")
                {
                    bail!(
                        "Agent note slots for '{}' are filled with owner notes",
                        document.connections[index].name
                    );
                }
                secrets.agent_notes.insert(
                    0,
                    crate::model::AgentNoteEntry {
                        id: Uuid::new_v4().to_string(),
                        text: clean_note,
                        author: clean_author,
                        updated_at: now.clone(),
                    },
                );
                while secrets.agent_notes.len() > crate::model::MAX_AGENT_NOTES {
                    if enforce_agent_guards {
                        if let Some(evict_pos) = secrets
                            .agent_notes
                            .iter()
                            .rposition(|entry| entry.author != "OWNER")
                        {
                            secrets.agent_notes.remove(evict_pos);
                            continue;
                        }
                    }
                    secrets.agent_notes.pop();
                }
            }

            let stored = &mut document.connections[index];
            stored.encrypted_secrets = self.with_key(|key| key.encrypt(&secrets))?;
            stored.updated_at = now;
            Ok(stored.public(Some(&secrets)))
        })
    }

    pub fn update_agent_note(
        &self,
        id: Uuid,
        note_id: &str,
        text: &str,
        author: Option<&str>,
        enforce_agent_guards: bool,
    ) -> Result<PublicConnection> {
        let note_id = note_id.trim();
        if note_id.is_empty() {
            bail!("Note ID cannot be empty");
        }
        let clean_note = crate::policy::sanitize_agent_note_text(text)?;
        let clean_author = author.map(crate::policy::sanitize_agent_note_author);
        self.update_document_with_result(|document| {
            let index = document
                .connections
                .iter()
                .position(|item| item.id == id)
                .context("Connection not found")?;
            if enforce_agent_guards && !document.connections[index].enabled {
                bail!("This project is disabled");
            }
            let mut secrets: SecretBundle = self.with_key(|key| {
                key.decrypt(&document.connections[index].encrypted_secrets)
            })?;
            if enforce_agent_guards && secrets.agent_notes_locked {
                bail!(
                    "Agent notes for '{}' are locked by the owner and cannot be modified by agents",
                    document.connections[index].name
                );
            }
            let note_pos = secrets
                .agent_notes
                .iter()
                .position(|entry| entry.id == note_id)
                .context("Agent note not found")?;
            if enforce_agent_guards && secrets.agent_notes[note_pos].author == "OWNER" {
                bail!("Agents cannot edit an owner-authored note");
            }
            if enforce_agent_guards {
                let decrypted_all: Vec<SecretBundle> = self.with_key(|key| {
                    document
                        .connections
                        .iter()
                        .map(|conn| key.decrypt::<SecretBundle>(&conn.encrypted_secrets))
                        .collect()
                })?;
                let pairs: Vec<(&StoredConnection, &SecretBundle)> = document
                    .connections
                    .iter()
                    .zip(decrypted_all.iter())
                    .collect();
                crate::policy::validate_agent_note_no_secrets(
                    &clean_note,
                    pairs[index],
                    &pairs,
                )?;
            }

            let now = Utc::now().to_rfc3339();
            secrets.agent_notes[note_pos].text = clean_note;
            if let Some(next_author) = clean_author {
                secrets.agent_notes[note_pos].author = next_author;
            }
            secrets.agent_notes[note_pos].updated_at = now.clone();
            let stored = &mut document.connections[index];
            stored.encrypted_secrets = self.with_key(|key| key.encrypt(&secrets))?;
            stored.updated_at = now;
            Ok(stored.public(Some(&secrets)))
        })
    }

    pub fn remove_agent_note(
        &self,
        id: Uuid,
        note_id: &str,
        enforce_agent_guards: bool,
    ) -> Result<PublicConnection> {
        let note_id = note_id.trim();
        if note_id.is_empty() {
            bail!("Note ID cannot be empty");
        }
        self.update_document_with_result(|document| {
            let index = document
                .connections
                .iter()
                .position(|item| item.id == id)
                .context("Connection not found")?;
            if enforce_agent_guards && !document.connections[index].enabled {
                bail!("This project is disabled");
            }
            let mut secrets: SecretBundle = self.with_key(|key| {
                key.decrypt(&document.connections[index].encrypted_secrets)
            })?;
            if enforce_agent_guards && secrets.agent_notes_locked {
                bail!(
                    "Agent notes for '{}' are locked by the owner and cannot be modified by agents",
                    document.connections[index].name
                );
            }
            let note_pos = secrets
                .agent_notes
                .iter()
                .position(|entry| entry.id == note_id)
                .context("Agent note not found")?;
            if enforce_agent_guards && secrets.agent_notes[note_pos].author == "OWNER" {
                bail!("Agents cannot remove an owner-authored note");
            }
            secrets.agent_notes.remove(note_pos);
            let now = Utc::now().to_rfc3339();
            let stored = &mut document.connections[index];
            stored.encrypted_secrets = self.with_key(|key| key.encrypt(&secrets))?;
            stored.updated_at = now;
            Ok(stored.public(Some(&secrets)))
        })
    }

    pub fn clear_agent_notes(&self, id: Uuid) -> Result<PublicConnection> {
        self.update_document_with_result(|document| {
            let stored = document
                .connections
                .iter_mut()
                .find(|item| item.id == id)
                .context("Connection not found")?;
            let mut secrets: SecretBundle =
                self.with_key(|key| key.decrypt(&stored.encrypted_secrets))?;
            secrets.agent_notes.clear();
            stored.encrypted_secrets = self.with_key(|key| key.encrypt(&secrets))?;
            stored.updated_at = Utc::now().to_rfc3339();
            Ok(stored.public(Some(&secrets)))
        })
    }

    pub fn set_agent_notes_locked(&self, id: Uuid, locked: bool) -> Result<PublicConnection> {
        self.update_document_with_result(|document| {
            let stored = document
                .connections
                .iter_mut()
                .find(|item| item.id == id)
                .context("Connection not found")?;
            let mut secrets: SecretBundle =
                self.with_key(|key| key.decrypt(&stored.encrypted_secrets))?;
            secrets.agent_notes_locked = locked;
            stored.encrypted_secrets = self.with_key(|key| key.encrypt(&secrets))?;
            stored.updated_at = Utc::now().to_rfc3339();
            Ok(stored.public(Some(&secrets)))
        })
    }

    pub fn set_connection_enabled(&self, id: Uuid, enabled: bool) -> Result<()> {
        self.update_document(|document| {
            let connection = document
                .connections
                .iter_mut()
                .find(|connection| connection.id == id)
                .context("Connection not found")?;
            connection.enabled = enabled;
            connection.updated_at = Utc::now().to_rfc3339();
            Ok(())
        })
    }

}
