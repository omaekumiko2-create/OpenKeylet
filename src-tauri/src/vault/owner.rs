use super::*;

impl Vault {
    pub fn owner_pin_configured(&self) -> Result<bool> {
        Ok(self.read_document()?.owner_pin.is_some())
    }

    pub fn set_owner_pin(&self, pin: &str) -> Result<()> {
        let verifier = create_owner_pin_verifier(pin)?;
        self.update_document(|document| {
            if document.owner_pin.is_some() {
                bail!("PIN is set");
            }
            document.owner_pin = Some(verifier);
            Ok(())
        })
    }

    pub fn disable_owner_pin(&self) -> Result<()> {
        self.update_document(|document| {
            document.owner_pin = None;
            Ok(())
        })
    }

    pub fn verify_owner_pin(&self, pin: &str) -> Result<bool> {
        let document = self.read_document()?;
        let verifier = document
            .owner_pin
            .as_ref()
            .context("PIN has not been set")?;
        verify_owner_pin(pin, verifier)
    }

    pub fn owner_secret_view(&self, id: Uuid) -> Result<OwnerSecretView> {
        let connection = self.get_connection(id)?;
        Ok(Self::owner_secret_view_for(&connection))
    }

    pub(crate) fn owner_secret_view_for(connection: &DecryptedConnection) -> OwnerSecretView {
        let fields = connection
            .secrets
            .available_fields(connection.stored.secret.as_ref())
            .into_iter()
            .filter_map(|field| {
                connection
                    .secrets
                    .get(&field.name)
                    .map(|value| OwnerSecretField {
                        name: field.name,
                        kind: field.kind,
                        value: value.to_owned(),
                    })
            })
            .collect();
        OwnerSecretView {
            id: connection.stored.id,
            fields,
        }
    }

    pub fn list_editor_drafts(&self) -> Result<Vec<OwnerEditorDraft>> {
        let document = self.read_document()?;
        let mut drafts = self.with_key(|key| {
            document
                .editor_drafts
                .into_iter()
                .map(|draft| {
                    Ok(OwnerEditorDraft {
                        id: draft.id,
                        updated_at: draft.updated_at,
                        input: key.decrypt(&draft.payload)?,
                    })
                })
                .collect::<Result<Vec<_>>>()
        })?;
        drafts.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
        drafts.truncate(MAX_EDITOR_DRAFTS);
        Ok(drafts)
    }

    pub fn save_editor_draft(
        &self,
        id: Option<Uuid>,
        mut input: ConnectionInput,
    ) -> Result<OwnerEditorDraft> {
        input.name = checked_text(&input.name, "Project name", 80)?;
        input.description = checked_text(&input.description, "Project description", 240)?;
        let id = id.unwrap_or_else(Uuid::new_v4);
        let updated_at = Utc::now().to_rfc3339();
        let payload = self.with_key(|key| key.encrypt(&input))?;
        self.update_document(|document| {
            if let Some(pos) = document.editor_drafts.iter().position(|draft| draft.id == id) {
                document.editor_drafts.remove(pos);
            }
            document.editor_drafts.insert(
                0,
                StoredEditorDraft {
                    id,
                    updated_at: updated_at.clone(),
                    payload,
                },
            );
            document
                .editor_drafts
                .sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
            document.editor_drafts.truncate(MAX_EDITOR_DRAFTS);
            Ok(())
        })?;
        Ok(OwnerEditorDraft {
            id,
            updated_at,
            input,
        })
    }

    pub fn delete_editor_draft(&self, id: Uuid) -> Result<()> {
        self.update_document(|document| {
            document.editor_drafts.retain(|draft| draft.id != id);
            Ok(())
        })
    }

    pub fn settings(&self) -> Result<Settings> {
        Ok(self.read_document()?.settings)
    }

    #[cfg(test)]
    pub fn update_settings(&self, mut next: Settings) -> Result<Settings> {
        if next.browser_port == 0 {
            bail!("Local port must be between 1–65535");
        }
        next.language = normalize_language(&next.language);
        next.close_behavior = if next.close_behavior.eq_ignore_ascii_case("exit") {
            "exit".to_owned()
        } else {
            "tray".to_owned()
        };
        self.update_document(|document| {
            // Pairing state is changed only by the authenticated bridge handshake.
            next.browser_paired = document.settings.browser_paired;
            document.settings = next.clone();
            Ok(())
        })?;
        Ok(next)
    }

    pub fn update_settings_patch(&self, patch: SettingsPatch) -> Result<Settings> {
        self.update_document_with_result(|document| {
            let mut next = document.settings.clone();
            if let Some(language) = patch.language {
                next.language = normalize_language(&language);
            }
            if let Some(close_behavior) = patch.close_behavior {
                next.close_behavior = if close_behavior.eq_ignore_ascii_case("exit") {
                    "exit".to_owned()
                } else {
                    "tray".to_owned()
                };
            }
            if let Some(browser_enabled) = patch.browser_enabled {
                next.browser_enabled = browser_enabled;
            }
            if let Some(browser_port) = patch.browser_port {
                if browser_port < 1024 {
                    bail!("Local port must be between 1024–65535");
                }
                next.browser_port = browser_port;
            }
            if let Some(browser_agent_passkey) = patch.browser_agent_passkey {
                next.browser_agent_passkey = browser_agent_passkey;
            }
            if let Some(minutes) = patch.owner_auto_lock_minutes {
                if !matches!(minutes, 0 | 5 | 15 | 30 | 60) {
                    bail!("Auto-lock timeout must be 0, 5, 15, 30, or 60 minutes");
                }
                next.owner_auto_lock_minutes = minutes;
            }
            if let Some(auto_check_enabled) = patch.auto_check_enabled {
                next.auto_check_enabled = auto_check_enabled;
            }
            if let Some(minutes) = patch.auto_check_interval_minutes {
                if !matches!(minutes, 15 | 30 | 60 | 180 | 360 | 720 | 1440) {
                    bail!("Auto-check interval must be 15, 30, 60, 180, 360, 720, or 1440 minutes");
                }
                next.auto_check_interval_minutes = minutes;
            }
            if let Some(update_auto_check) = patch.update_auto_check {
                next.update_auto_check = update_auto_check;
            }
            if let Some(update_auto_download) = patch.update_auto_download {
                next.update_auto_download = update_auto_download;
            }
            if let Some(update_skipped_version) = patch.update_skipped_version {
                let trimmed = update_skipped_version.trim();
                if trimmed.len() > 64 {
                    bail!("Skipped version string is too long");
                }
                next.update_skipped_version = trimmed.to_owned();
            }
            document.settings = next.clone();
            Ok(next)
        })
    }

    pub fn browser_bridge_secret(&self) -> Result<String> {
        if let Some(secret) = self.read_document()?.browser_bridge_secret {
            return self.with_key(|key| key.decrypt(&secret));
        }
        self.with_exclusive_lock(|_| {
            let mut document = self.read_document_unlocked()?;
            if let Some(secret) = document.browser_bridge_secret.as_ref() {
                return self.with_key(|key| key.decrypt(secret));
            }
            let secret = random_token()?;
            document.browser_bridge_secret = Some(self.with_key(|key| key.encrypt(&secret))?);
            self.write_document_unlocked(&document)?;
            Ok(secret)
        })
    }

    pub fn rotate_browser_bridge_secret(&self) -> Result<()> {
        let encrypted = self.with_key(|key| key.encrypt(&random_token()?))?;
        self.update_document(|document| {
            document.browser_bridge_secret = Some(encrypted);
            document.settings.browser_paired = false;
            Ok(())
        })
    }

    pub fn set_browser_paired(&self, paired: bool) -> Result<()> {
        self.update_document(|document| {
            document.settings.browser_paired = paired;
            Ok(())
        })
    }

    pub fn app_state(
        &self,
        executable: &str,
        browser_bridge: crate::model::BrowserBridgeState,
    ) -> Result<AppState> {
        let document = self.read_document()?;
        let connections = self.with_key(|key| {
            document
                .connections
                .iter()
                .map(|connection| {
                    let secrets: SecretBundle = key.decrypt(&connection.encrypted_secrets)?;
                    Ok(connection.public(Some(&secrets)))
                })
                .collect::<Result<Vec<_>>>()
        })?;
        Ok(AppState {
            connections,
            activities: self.activities()?,
            mcp: McpState {
                status: "ready".to_owned(),
                error: String::new(),
                endpoint: "stdio".to_owned(),
                stdio_command: executable.to_owned(),
            },
            browser_bridge,
            security: SecurityState {
                encrypted: true,
                storage: self.storage_label(),
                key_location: self.key_place().code().to_owned(),
                key_file: self
                    .key_file()
                    .map(|path| path.to_string_lossy().into_owned()),
            },
            settings: document.settings.clone(),
        })
    }

}
