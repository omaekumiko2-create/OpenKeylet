use super::*;
use crate::browser::vault_rpc::{new_item, same_origin, text};
use crate::passkey;
use anyhow::ensure;
use serde_json::{Value, json};

impl Vault {
    pub fn assert_browser_passkey(
        &self,
        id: Uuid,
        credential_id: &str,
        website: &str,
        options: &Value,
        verified: bool,
    ) -> Result<Value> {
        self.update_document_with_result(|document| {
            let stored = document
                .connections
                .iter_mut()
                .find(|c| c.id == id)
                .context("Passkey item not found")?;
            ensure!(stored.enabled, "This project is disabled");
            let mut secrets: SecretBundle =
                self.unprotect_local_state(&stored.encrypted_secrets)?;
            let key = secrets
                .passkeys
                .iter_mut()
                .find(|k| k.credential_id == credential_id)
                .context("Passkey not found")?;
            if key.counter > 0 {
                key.counter = key
                    .counter
                    .checked_add(1)
                    .context("Passkey counter exhausted; register a new passkey")?;
            }
            let response = passkey::get(key, website, options, verified)?;
            // Persist before returning the signature, under the vault's exclusive lock.
            if key.counter > 0 {
                stored.encrypted_secrets = self.protect_local_state(&secrets)?;
                stored.updated_at = chrono::Utc::now().to_rfc3339();
            }
            Ok(response)
        })
    }

    pub fn save_browser_login(&self, p: &Value) -> Result<Value> {
        let website = text(p, "origin")?;
        passkey::origin(website)?;
        let username = text(p, "username")?;
        let password = text(p, "password")?;
        ensure!(
            !password.is_empty() && password.len() <= 16384 && username.len() <= 4096,
            "Invalid login size"
        );
        let id = p["id"].as_str().map(Uuid::parse_str).transpose()?;
        self.update_document_with_result(|document| {
            let index = id
                .map(|id| {
                    document
                        .connections
                        .iter()
                        .position(|c| c.id == id)
                        .context("Login was deleted; reload the extension")
                })
                .transpose()?;
            let (mut stored, mut secrets) = if let Some(i) = index {
                let c = &document.connections[i];
                ensure!(
                    c.enabled && same_origin(c, website),
                    "This login does not belong to the current website"
                );
                ensure!(
                    Some(c.updated_at.as_str()) == p["expectedUpdatedAt"].as_str(),
                    "Login changed in OpenKeylet; reload before saving"
                );
                (
                    c.clone(),
                    self.unprotect_local_state::<SecretBundle>(&c.encrypted_secrets)?,
                )
            } else {
                new_item(
                    self,
                    document,
                    website,
                    username,
                    p["name"].as_str().unwrap_or_default(),
                    true,
                )?
            };
            for kind in ["username", "password"] {
                if !stored.modules.iter().any(|m| m.kind == kind) {
                    stored.modules.push(ItemModule {
                        kind: kind.into(),
                        name: kind.into(),
                        agent_visible: Some(false),
                        ..Default::default()
                    });
                }
            }
            secrets
                .named_secrets
                .insert("username".into(), username.into());
            let previous_password =
                zeroize::Zeroizing::new(secrets.get("password").map(str::to_owned));
            secrets.password = Some(password.into());
            secrets.remember_password_change(previous_password.as_deref());
            stored.updated_at = chrono::Utc::now().to_rfc3339();
            stored.encrypted_secrets = self.protect_local_state(&secrets)?;
            let result = json!({"id":stored.id,"name":stored.name,"updatedAt":stored.updated_at});
            if let Some(i) = index {
                document.connections[i] = stored;
            } else {
                document.connections.push(stored);
            }
            Ok(result)
        })
    }

    pub fn store_browser_passkey(
        &self,
        website: &str,
        key: passkey::StoredPasskey,
        options: &Value,
    ) -> Result<()> {
        self.store_browser_passkey_for_item(None, website, key, options)?;
        Ok(())
    }

    pub fn store_browser_passkey_for_item(
        &self,
        target_item_id: Option<Uuid>,
        website: &str,
        key: passkey::StoredPasskey,
        options: &Value,
    ) -> Result<String> {
        let origin_url = passkey::origin(website)?;
        self.update_document_with_result(|document| {
            let mut decrypted_secrets = Vec::with_capacity(document.connections.len());
            for c in &document.connections {
                let secrets: SecretBundle = self.unprotect_local_state(&c.encrypted_secrets)?;
                if let Some(exclude) = options["excludeCredentials"].as_array() {
                    ensure!(
                        !secrets.passkeys.iter().any(|k| k.rp_id == key.rp_id
                            && exclude
                                .iter()
                                .any(|e| e["type"] == "public-key" && e["id"] == k.credential_id)),
                        "InvalidStateError: A matching passkey already exists"
                    );
                }
                decrypted_secrets.push(secrets);
            }

            let attach_index = if let Some(target_id) = target_item_id {
                let index = document
                    .connections
                    .iter()
                    .position(|c| c.id == target_id)
                    .context("Target item not found")?;
                ensure!(
                    document.connections[index].enabled,
                    "This project is disabled"
                );
                Some(index)
            } else {
                let target_user = key.user_name.trim();
                if target_user.is_empty() {
                    None
                } else {
                    let matching: Vec<usize> = document
                        .connections
                        .iter()
                        .enumerate()
                        .filter(|(index, c)| {
                            if !c.enabled || !same_origin(c, website) {
                                return false;
                            }
                            let secrets = &decrypted_secrets[*index];
                            let same_user = secrets
                                .get("username")
                                .is_some_and(|u| u.trim().eq_ignore_ascii_case(target_user));
                            if !same_user {
                                return false;
                            }
                            !secrets.passkeys.iter().any(|existing| {
                                existing.rp_id == key.rp_id
                                    && (existing.credential_id == key.credential_id
                                        || (!key.user_handle.is_empty()
                                            && !existing.user_handle.is_empty()
                                            && existing.user_handle != key.user_handle))
                            })
                        })
                        .map(|(index, _)| index)
                        .collect();
                    if matching.len() == 1 {
                        Some(matching[0])
                    } else {
                        None
                    }
                }
            };

            if let Some(index) = attach_index {
                let stored = &mut document.connections[index];
                let mut secrets = decrypted_secrets.swap_remove(index);
                ensure!(
                    !secrets
                        .passkeys
                        .iter()
                        .any(|existing| existing.credential_id == key.credential_id),
                    "InvalidStateError: A matching passkey already exists"
                );
                if !same_origin(stored, website) {
                    if stored.login_uris.is_empty()
                        && let Ok(existing_base) = passkey::origin(&stored.base_url)
                    {
                        stored.login_uris.push(crate::login_uri::LoginUri {
                            uri: existing_base.origin().ascii_serialization(),
                            match_type: "origin".to_owned(),
                        });
                    }
                    if stored.login_uris.len() < 128 {
                        stored.login_uris.push(crate::login_uri::LoginUri {
                            uri: origin_url.origin().ascii_serialization(),
                            match_type: "origin".to_owned(),
                        });
                    }
                }
                secrets.passkeys.push(key);
                stored.encrypted_secrets = self.protect_local_state(&secrets)?;
                stored.updated_at = chrono::Utc::now().to_rfc3339();
                return Ok(stored.name.clone());
            }

            let label = format!("{} · {} · Passkey", key.rp_id, key.user_name);
            let (mut stored, mut secrets) =
                new_item(self, document, website, &key.user_name, &label, false)?;
            let item_name = stored.name.clone();
            secrets.passkeys.push(key);
            stored.encrypted_secrets = self.protect_local_state(&secrets)?;
            document.connections.push(stored);
            Ok(item_name)
        })
    }
}

