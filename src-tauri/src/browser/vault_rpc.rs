//! Authenticated browser operations over the existing loopback bridge.
use crate::{
    model::{ConnectionInput, SecretBundle, StoredConnection},
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

pub(crate) fn text<'a>(p: &'a Value, name: &str) -> Result<&'a str> {
    p[name].as_str().with_context(|| format!("Missing {name}"))
}
pub(crate) fn same_origin(stored: &StoredConnection, website: &str) -> bool {
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
    ensure!(
        crate::platform::verify_pin_throttled(vault, pin, throttle).await?,
        "Incorrect PIN"
    );
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
                let target_item_id = p["itemId"]
                    .as_str()
                    .filter(|value| !value.trim().is_empty())
                    .map(Uuid::parse_str)
                    .transpose()?;
                vault.store_browser_passkey_for_item(target_item_id, website, key, &p["options"])?;
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
            let (code, remaining_seconds, period) = crate::crypto::totp::current_totp_details(totp_secret)?;
            Ok(json!({"code": code, "remainingSeconds": remaining_seconds, "period": period}))
        }
        "apiKey.save" => {
            let origin = passkey::origin(text(p, "origin")?)?;
            ensure!(origin.scheme() == "https" || matches!(origin.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")), "Secure issuing origin required");
            let site = origin.origin().ascii_serialization();
            let service = p["serviceOrigin"].as_str().unwrap_or(&site);
            let target = passkey::origin(service)?;
            let site_domain = |url: &url::Url| match url.host() {
                Some(url::Host::Domain(host)) => psl::domain_str(host).map(str::to_owned),
                _ => None,
            };
            let issuer_domain = site_domain(&origin);
            ensure!(service == target.origin().ascii_serialization()
                && (service == site || (target.scheme() == "https" && issuer_domain.is_some()
                    && issuer_domain == site_domain(&target))),
                "Choose an HTTPS API origin belonging to the issuing site");
            let value = text(p, "value")?;
            ensure!(!value.is_empty() && value.len() <= 16384 && !value.chars().any(|c| c.is_whitespace() || c.is_control()), "Invalid issued key");
            let input = serde_json::from_value(json!({
                "name": text(p, "name")?, "itemType": "api", "enabled": true, "httpAuthType": "auto",
                "modules": [
                    {"kind":"url","value":service},
                    {"kind":"apiCredential","agentVisible":false}
                ],
                "secrets": {"namedSecrets":{"apiCredential":value}}
            }))?;
            let saved = vault.save_connection(input)?;
            Ok(json!({"id": saved.id}))
        }
        "password.save" => vault.save_browser_login(p),
        _ => bail!("Unsupported browser operation"),
    }
}

pub(crate) fn personal_fields(kind: &str) -> Result<&'static [&'static str]> {
    match kind {
        "card" => Ok(crate::item_types::CARD_FIELDS),
        "identity" => Ok(crate::item_types::IDENTITY_FIELDS),
        _ => bail!("Only card and identity items can be autofilled"),
    }
}

pub(crate) fn new_item(
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


#[cfg(test)]
mod tests;
