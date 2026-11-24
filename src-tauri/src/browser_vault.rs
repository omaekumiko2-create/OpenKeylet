//! Authenticated browser operations over the existing loopback bridge.
use crate::{
    model::{ConnectionInput, ItemModule, SecretBundle, StoredConnection},
    passkey,
    vault::{Vault, normalize_connection},
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Default)]
pub struct Session {
    unlocked_until: Option<Instant>,
}

fn text<'a>(p: &'a Value, name: &str) -> Result<&'a str> {
    p[name].as_str().with_context(|| format!("Missing {name}"))
}
fn same_origin(stored: &StoredConnection, website: &str) -> bool {
    if !stored.login_uris.is_empty() {
        return stored
            .login_uris
            .iter()
            .any(|rule| crate::login_uri::matches(rule, website));
    }
    match (passkey::origin(&stored.base_url), passkey::origin(website)) {
        (Ok(a), Ok(b)) => a.origin() == b.origin(),
        _ => false,
    }
}
fn list(vault: &Vault, website: &str) -> Result<Value> {
    passkey::origin(website)?;
    Ok(Value::Array(vault.list_decrypted_connections()?.into_iter().filter(|c| c.stored.enabled && same_origin(&c.stored, website) && c.secrets.get("password").is_some())
        .map(|c| json!({"id":c.stored.id,"name":c.stored.name,"username":c.secrets.get("username").unwrap_or_default(),"hasTotp":c.secrets.get("totp").is_some(),"updatedAt":c.stored.updated_at})).collect()))
}

async fn verify(vault: &Vault, pin: &str, throttle: &Mutex<Instant>) -> Result<bool> {
    if !vault.owner_pin_configured()? {
        return Ok(false);
    }
    ensure!(!pin.is_empty(), "Enter your OpenKeylet PIN");
    // Shared across connections; reconnecting cannot reset PIN attempt throttling.
    let mut next = throttle.lock().await;
    tokio::time::sleep(next.saturating_duration_since(Instant::now())).await;
    *next = Instant::now() + Duration::from_secs(1);
    ensure!(vault.verify_owner_pin(pin)?, "Incorrect PIN");
    Ok(true)
}

pub async fn handle(
    vault: &Vault,
    session: &mut Session,
    throttle: &Mutex<Instant>,
    method: &str,
    p: &Value,
) -> Result<Value> {
    let pin_configured = vault.owner_pin_configured()?;
    let unlocked = !pin_configured || session.unlocked_until.is_some_and(|t| t > Instant::now());
    match method {
        "status" => return Ok(json!({"pinConfigured":pin_configured,"locked":!unlocked})),
        "unlock" => {
            verify(vault, p["pin"].as_str().unwrap_or_default(), throttle).await?;
            session.unlocked_until = Some(Instant::now() + Duration::from_secs(300));
            return Ok(json!({"ok":true}));
        }
        "lock" => {
            session.unlocked_until = None;
            return Ok(json!({"ok":true}));
        }
        "passkey.prepare" => {
            let create = text(p, "operation")? == "create";
            let rp = passkey::rp_id(text(p, "origin")?, &p["options"], create)?;
            let mut entries = Vec::new();
            if create {
                if let Some(exclude) = p["options"]["excludeCredentials"].as_array() {
                    for c in vault.list_decrypted_connections()? {
                        ensure!(
                            !c.secrets.passkeys.iter().any(|k| k.rp_id == rp
                                && exclude.iter().any(|e| {
                                    e["type"] == "public-key" && e["id"] == k.credential_id
                                })),
                            "InvalidStateError: A matching passkey already exists"
                        );
                    }
                }
            } else {
                for c in vault.list_decrypted_connections()? {
                    if c.stored.enabled {
                        for k in &c.secrets.passkeys {
                            if passkey::matches_request(k, &rp, &p["options"]) {
                                entries.push(json!({"itemId":c.stored.id,"name":c.stored.name,"passkey":k.summary()}));
                            }
                        }
                    }
                }
            }
            return Ok(
                json!({"rpId":rp,"entries":entries,"pinConfigured":pin_configured,"verificationRequired":passkey::requires_verification(&p["options"],create)}),
            );
        }
        "passkey.create" | "passkey.get" => {
            let verified = verify(vault, p["pin"].as_str().unwrap_or_default(), throttle).await?;
            let website = text(p, "origin")?;
            if method == "passkey.create" {
                let (key, response) = passkey::create(website, &p["options"], verified)?;
                vault.store_browser_passkey(website, key, &p["options"])?;
                return Ok(response);
            }
            return vault.assert_browser_passkey(
                Uuid::parse_str(text(p, "itemId")?)?,
                text(p, "credentialId")?,
                website,
                &p["options"],
                verified,
            );
        }
        _ => {}
    }
    ensure!(unlocked, "OpenKeylet is locked; enter your PIN");
    match method {
        "password.generate" => Ok(json!(crate::generator::password(&serde_json::from_value(
            p.clone()
        )?)?)),
        "personal.list" => {
            let entries = vault.list_decrypted_connections()?.into_iter()
                .filter(|c| c.stored.enabled && matches!(c.stored.item_type(), "card" | "identity"))
                .map(|c| {
                    let subtitle = if c.stored.item_type() == "card" {
                        let digits: String = c.secrets.get("cardNumber").unwrap_or_default().chars().filter(char::is_ascii_digit).collect();
                        let last: String = digits.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
                        if last.is_empty() { String::new() } else { format!("•••• {last}") }
                    } else { c.stored.folder.clone() };
                    json!({"id":c.stored.id,"name":c.stored.name,"itemType":c.stored.item_type(),
                        "subtitle":subtitle,"favorite":c.stored.favorite,"updatedAt":c.stored.updated_at})
                }).collect::<Vec<_>>();
            Ok(json!(entries))
        }
        "personal.get" => {
            let c = vault.get_connection(Uuid::parse_str(text(p, "id")?)?)?;
            ensure!(c.stored.enabled, "This item is disabled");
            let fields = personal_fields(c.stored.item_type())?;
            let values: serde_json::Map<String, Value> = fields
                .iter()
                .map(|name| {
                    (
                        (*name).to_owned(),
                        json!(c.secrets.get(name).unwrap_or_default()),
                    )
                })
                .collect();
            Ok(
                json!({"id":c.stored.id,"name":c.stored.name,"itemType":c.stored.item_type(),
                "fields":values,"updatedAt":c.stored.updated_at}),
            )
        }
        "password.list" => list(vault, text(p, "origin")?),
        "password.get" => {
            let c = vault.get_connection(Uuid::parse_str(text(p, "id")?)?)?;
            ensure!(
                c.stored.enabled && same_origin(&c.stored, text(p, "origin")?),
                "This login does not belong to the current website"
            );
            Ok(
                json!({"username":c.secrets.get("username").unwrap_or_default(),"password":c.secrets.get("password").context("No password saved")?}),
            )
        }
        "password.totp" => {
            let c = vault.get_connection(Uuid::parse_str(text(p, "id")?)?)?;
            ensure!(
                c.stored.enabled && same_origin(&c.stored, text(p, "origin")?),
                "This login does not belong to the current website"
            );
            let totp_secret = c.secrets.get("totp").context("No TOTP configured for this item")?;
            let (code, remaining_seconds, period) = crate::browser::current_totp_details(totp_secret)?;
            Ok(json!({"code": code, "remainingSeconds": remaining_seconds, "period": period}))
        }
        "password.save" => vault.save_browser_login(p),
        _ => bail!("Unsupported browser operation"),
    }
}

fn personal_fields(kind: &str) -> Result<&'static [&'static str]> {
    match kind {
        "card" => Ok(crate::item_types::CARD_FIELDS),
        "identity" => Ok(crate::item_types::IDENTITY_FIELDS),
        _ => bail!("Only card and identity items can be autofilled"),
    }
}

fn new_item(
    vault: &Vault,
    document: &crate::model::VaultDocument,
    website: &str,
    username: &str,
    label: &str,
    password: bool,
) -> Result<(StoredConnection, SecretBundle)> {
    let mut name = label.trim().chars().take(64).collect::<String>();
    if name.is_empty() {
        name = passkey::origin(website)?
            .host_str()
            .unwrap()
            .chars()
            .take(64)
            .collect();
    }
    let base = name.clone();
    let mut suffix = 2;
    while document
        .connections
        .iter()
        .any(|c| c.name.eq_ignore_ascii_case(&name))
    {
        name = format!("{base} ({suffix})");
        suffix += 1;
    }
    let mut modules = vec![
        json!({"kind":"url","value":passkey::origin(website)?.origin().ascii_serialization()}),
        json!({"kind":"username"}),
    ];
    if password {
        modules.push(json!({"kind":"password"}));
    }
    let input: ConnectionInput =
        serde_json::from_value(json!({"name":name,"modules":modules,"httpAuthType":"auto"}))?;
    let mut secrets = SecretBundle::default();
    secrets
        .named_secrets
        .insert("username".into(), username.to_owned());
    let mut stored = normalize_connection(
        input,
        None,
        &secrets,
        String::new(),
        chrono::Utc::now().to_rfc3339(),
    )?;
    stored.encrypted_secrets = vault.protect_local_state(&secrets)?;
    Ok((stored, secrets))
}

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
        self.update_document_with_result(|document| {
            if let Some(exclude) = options["excludeCredentials"].as_array() {
                for c in &document.connections {
                    let secrets: SecretBundle = self.unprotect_local_state(&c.encrypted_secrets)?;
                    ensure!(
                        !secrets.passkeys.iter().any(|k| k.rp_id == key.rp_id
                            && exclude
                                .iter()
                                .any(|e| e["type"] == "public-key" && e["id"] == k.credential_id)),
                        "InvalidStateError: A matching passkey already exists"
                    );
                }
            }
            let label = format!("{} · {} · Passkey", key.rp_id, key.user_name);
            let (mut stored, mut secrets) =
                new_item(self, document, website, &key.user_name, &label, false)?;
            secrets.passkeys.push(key);
            stored.encrypted_secrets = self.protect_local_state(&secrets)?;
            document.connections.push(stored);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn personal_items_list_only_autofillable_cards_and_identities_when_unlocked() {
        let d = tempfile::tempdir().unwrap();
        let v = Vault::open(d.path().join("original")).unwrap();
        v.set_owner_pin("123456").unwrap();
        let mut session = Session::default();
        let throttle = Mutex::new(Instant::now());

        // Cards, identities and secure notes are managed in the desktop vault.
        let card_input: ConnectionInput = serde_json::from_value(json!({
            "name": "Test card",
            "itemType": "card",
            "folder": "Wallet",
            "favorite": true,
            "modules": [
                {"kind": "cardNumber"},
                {"kind": "cardholderName"},
                {"kind": "cardSecurityCode"},
                {"kind": "cardExpMonth"},
                {"kind": "cardExpYear"}
            ],
            "secrets": {
                "namedSecrets": {
                    "cardNumber": "4111111111111111",
                    "cardholderName": "Synthetic Cardholder",
                    "cardSecurityCode": "987",
                    "cardExpMonth": "07",
                    "cardExpYear": "2030"
                }
            }
        }))
        .unwrap();
        let saved_card = v.save_connection(card_input).unwrap();
        let note_input: ConnectionInput = serde_json::from_value(json!({
            "name": "Private note",
            "itemType": "secureNote",
            "modules": [{"kind": "secureNote", "value": "must never persist"}],
            "secrets": {"namedSecrets": {"secureNote": "Synthetic private\nmultiline note"}}
        }))
        .unwrap();
        let saved_note = v.save_connection(note_input).unwrap();

        // Locked browser session cannot list or read personal items.
        assert!(handle(&v, &mut session, &throttle, "personal.list", &json!({})).await.is_err());

        handle(&v, &mut session, &throttle, "unlock", &json!({"pin": "123456"}))
            .await
            .unwrap();

        let listed = handle(&v, &mut session, &throttle, "personal.list", &json!({}))
            .await
            .unwrap();
        let items = listed.as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["itemType"], "card");
        assert_eq!(items[0]["subtitle"], "•••• 1111");
        assert!(items[0].get("fields").is_none());

        // Cards can be fetched for autofill; secure notes are strictly rejected by the bridge.
        let card_fields = handle(
            &v,
            &mut session,
            &throttle,
            "personal.get",
            &json!({"id": saved_card.id}),
        )
        .await
        .unwrap();
        assert_eq!(card_fields["fields"]["cardNumber"], "4111111111111111");
        assert!(
            handle(
                &v,
                &mut session,
                &throttle,
                "personal.get",
                &json!({"id": saved_note.id}),
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn shared_vault_password_updates_are_atomic_and_origin_bound() {
        let d = tempfile::tempdir().unwrap();
        let v = Vault::open(d.path().into()).unwrap();
        let mut p = json!({"origin":"https://example.com","username":"alice","password":"super-secret","name":"Example"});
        let saved = v.save_browser_login(&p).unwrap();
        p["id"] = saved["id"].clone();
        p["expectedUpdatedAt"] = saved["updatedAt"].clone();
        p["origin"] = json!("https://evil.example.com");
        assert!(v.save_browser_login(&p).is_err());
        p["origin"] = json!("http://example.com");
        assert!(v.save_browser_login(&p).is_err());
        p["origin"] = json!("https://example.com");
        p["password"] = json!("changed-secret");
        v.save_browser_login(&p).unwrap();
        assert!(v.save_browser_login(&p).is_err());
        assert_eq!(
            v.get_connection(Uuid::parse_str(saved["id"].as_str().unwrap()).unwrap())
                .unwrap()
                .secrets
                .password
                .as_deref(),
            Some("changed-secret")
        );
        let disk = std::fs::read_to_string(d.path().join("vault.json")).unwrap();
        assert!(!disk.contains("changed-secret"));
        assert!(!disk.contains("super-secret"));
    }

    #[tokio::test]
    async fn browser_pin_and_passkey_backup_round_trip() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        let d = tempfile::tempdir().unwrap();
        let v = Vault::open(d.path().join("original")).unwrap();
        v.set_owner_pin("123456").unwrap();
        let mut session = Session::default();
        let throttle = Mutex::new(Instant::now());
        assert!(
            handle(
                &v,
                &mut session,
                &throttle,
                "password.list",
                &json!({"origin":"https://example.com"})
            )
            .await
            .is_err()
        );
        assert!(
            handle(
                &v,
                &mut session,
                &throttle,
                "unlock",
                &json!({"pin":"000000"})
            )
            .await
            .is_err()
        );
        handle(
            &v,
            &mut session,
            &throttle,
            "unlock",
            &json!({"pin":"123456"}),
        )
        .await
        .unwrap();
        assert!(
            handle(
                &v,
                &mut session,
                &throttle,
                "password.list",
                &json!({"origin":"https://example.com"})
            )
            .await
            .is_ok()
        );
        let options = json!({"challenge":B64.encode([2;32]),"rp":{"id":"example.com"},"user":{"id":B64.encode([3;16]),"name":"alice"},
            "pubKeyCredParams":[{"type":"public-key","alg":-7}],"authenticatorSelection":{"residentKey":"required","userVerification":"required"}});
        let (key, _) = passkey::create("https://example.com", &options, true).unwrap();
        let secret = key.private_key.clone();
        let credential_id = key.credential_id.clone();
        v.store_browser_passkey("https://example.com", key.clone(), &options)
            .unwrap();
        let mut exclude = options.clone();
        exclude["excludeCredentials"] = json!([{"type":"public-key","id":credential_id}]);
        assert!(
            v.store_browser_passkey("https://example.com", key, &exclude)
                .is_err()
        );
        let public = v.list_connections().unwrap().remove(0);
        assert!(!serde_json::to_string(&public).unwrap().contains(&secret));
        assert!(
            !serde_json::to_string(&v.owner_secret_view(public.id).unwrap())
                .unwrap()
                .contains(&secret)
        );
        let mut input: ConnectionInput = serde_json::from_value(
            json!({"id":public.id,"name":"Renamed","modules":public.modules}),
        )
        .unwrap();
        v.save_connection_checked(input.clone(), Some(&public.updated_at))
            .unwrap();
        assert!(
            v.save_connection_checked(input.clone(), Some(&public.updated_at))
                .is_err()
        );
        input.name = "After edit".into();
        v.save_connection(input).unwrap();
        assert_eq!(
            v.get_connection(public.id).unwrap().secrets.passkeys.len(),
            1
        );
        let backup = d.path().join("backup.mvault");
        crate::backup::export_to_file(&v, &backup).unwrap();
        let restored = Vault::open(d.path().join("restored")).unwrap();
        crate::backup::import_from_file(&restored, &backup).unwrap();
        let restored = restored.list_decrypted_connections().unwrap();
        let request = json!({"challenge":B64.encode([8;32]),"rpId":"example.com","userVerification":"required"});
        assert!(
            passkey::get(
                &restored[0].secrets.passkeys[0],
                "https://example.com",
                &request,
                true
            )
            .is_ok()
        );
        assert!(
            !std::fs::read_to_string(d.path().join("original/vault.json"))
                .unwrap()
                .contains(&secret)
        );
    }

    #[tokio::test]
    async fn passkey_prepare_fails_fast_on_excluded_and_password_totp_returns_live_code() {
        let d = tempfile::tempdir().unwrap();
        let v = Vault::open(d.path().join("vault")).unwrap();
        let mut session = Session::default();
        let throttle = Mutex::new(Instant::now());

        let options = json!({
            "challenge": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [7; 32]),
            "rp": {"id": "example.com", "name": "Example"},
            "user": {"id": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [9; 16]), "name": "alice", "displayName": "Alice"},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {"residentKey": "preferred"}
        });
        let (key, _) = passkey::create("https://example.com", &options, false).unwrap();
        let cred_id = key.credential_id.clone();
        v.store_browser_passkey("https://example.com", key, &options)
            .unwrap();

        let mut dup = options.clone();
        dup["excludeCredentials"] = json!([{"type": "public-key", "id": cred_id}]);
        let err = handle(
            &v,
            &mut session,
            &throttle,
            "passkey.prepare",
            &json!({"origin": "https://example.com", "operation": "create", "options": dup}),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().starts_with("InvalidStateError:"));

        let mut secrets = SecretBundle::default();
        secrets.password = Some("pw-1".into());
        secrets.named_secrets.insert("username".into(), "alice".into());
        secrets
            .named_secrets
            .insert("totp".into(), "JBSWY3DPEHPK3PXP".into());
        let saved = v
            .save_connection(ConnectionInput {
                login_uris: Vec::new(),
                item_type: "login".into(),
                folder: String::new(),
                favorite: false,
                id: None,
                modules: vec![
                    ItemModule { kind: "url".into(), value: "https://example.com".into(), ..Default::default() },
                    ItemModule { kind: "username".into(), ..Default::default() },
                    ItemModule { kind: "password".into(), ..Default::default() },
                    ItemModule { kind: "totp".into(), ..Default::default() },
                ],
                name: "Example 2FA".into(),
                enabled: true,
                description: String::new(),
                http_auth_type: String::new(),
                private_key_import_path: String::new(),
                auth_header: String::new(),
                auth_location: String::new(),
                auth_prefix: String::new(),
                api_auth_headers: vec![],
                test_path: String::new(),
                remove_secret_names: vec![],
                secrets,
            })
            .unwrap();

        let listed = handle(
            &v,
            &mut session,
            &throttle,
            "password.list",
            &json!({"origin": "https://example.com/login"}),
        )
        .await
        .unwrap();
        assert_eq!(listed.as_array().unwrap()[0]["hasTotp"], true);

        let totp = handle(
            &v,
            &mut session,
            &throttle,
            "password.totp",
            &json!({"origin": "https://example.com/login", "id": saved.id}),
        )
        .await
        .unwrap();
        let code = totp["code"].as_str().unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!(totp["remainingSeconds"].as_u64().unwrap() <= 30);

        assert!(
            handle(
                &v,
                &mut session,
                &throttle,
                "password.totp",
                &json!({"origin": "https://evil.example", "id": saved.id}),
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn full_vault_crud_and_quick_rpcs_are_rejected_for_least_privilege() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path().to_path_buf()).unwrap();
        let mut session = Session::default();
        let throttle = Mutex::new(Instant::now());

        // Extension bridge must never expose desktop vault management, trash, history, or quick-ingest CRUD.
        for blocked in [
            "vault.list",
            "vault.get",
            "vault.save",
            "vault.trash",
            "vault.restore",
            "vault.purge",
            "vault.history",
            "vault.clearHistory",
            "personal.save",
            "quick.parse",
            "quick.save",
            "password.attachTotp",
        ] {
            let err = handle(&vault, &mut session, &throttle, blocked, &json!({}))
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("Unsupported browser operation"),
                "expected {blocked} to be rejected, got: {err}"
            );
        }
    }
}
