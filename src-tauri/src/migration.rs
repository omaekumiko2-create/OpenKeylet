//! Local, transactional imports. Previews contain counts and compatibility notices only.
use crate::{
    login_uri::LoginUri,
    model::{ItemModule, PortableConnection, SecretBundle},
    passkey::StoredPasskey,
};
use anyhow::{Context, Result, bail, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeMap, io::Read, path::Path};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_BYTES: u64 = 64 * 1024 * 1024;
type Entry = (PortableConnection, SecretBundle);

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    pub total: usize,
    pub types: BTreeMap<String, usize>,
    pub passkeys: usize,
    pub skipped_deleted: usize,
    pub warnings: Vec<String>,
}

pub struct Parsed {
    pub entries: Vec<Entry>,
    pub preview: Preview,
}

impl Preview {
    fn warn(&mut self, code: &str) {
        if !self.warnings.iter().any(|w| w == code) {
            self.warnings.push(code.into());
        }
    }
}

pub fn read(path: &Path, format: &str) -> Result<Parsed> {
    let file = std::fs::File::open(path).context("Could not open import file")?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("Could not read import file")?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "Import file exceeds 64 MiB"
    );
    if format == "ssh_config" {
        let (entries, preview) =
            crate::extract::ingest::parse_ssh_config_bytes(&bytes, path.parent())?;
        return Ok(Parsed { entries, preview });
    }
    if format == "env" {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| format!("Env · {s}"))
            .unwrap_or_else(|| "Imported .env".to_owned());
        let (entries, preview) = crate::extract::ingest::parse_env_file(&bytes, &name)?;
        return Ok(Parsed { entries, preview });
    }
    parse(&bytes, format)
}

pub fn parse(bytes: &[u8], format: &str) -> Result<Parsed> {
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "Import file exceeds 64 MiB"
    );
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    if format == "ssh_config" {
        let (entries, preview) = crate::extract::ingest::parse_ssh_config_bytes(bytes, None)?;
        return Ok(Parsed { entries, preview });
    }
    if format == "env" {
        let (entries, preview) = crate::extract::ingest::parse_env_file(bytes, "Imported .env")?;
        return Ok(Parsed { entries, preview });
    }
    let mut preview = Preview::default();
    let entries = match format {
        "bitwarden" => bitwarden(bytes, &mut preview)?,
        "chrome" => chrome_csv(bytes, &mut preview)?,
        _ => bail!("Unsupported import format"),
    };
    ensure!(
        entries.len() <= 50_000,
        "Import contains more than 50,000 items"
    );
    for (item, secrets) in &entries {
        *preview.types.entry(item.item_type.clone()).or_default() += 1;
        preview.passkeys += secrets.passkeys.len();
    }
    preview.total = entries.len();
    Ok(Parsed { entries, preview })
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn blank(kind: &str, name: &str) -> Result<Entry> {
    ensure!(
        name.chars().count() <= 80,
        "Item name exceeds 80 characters"
    );
    let now = chrono::Utc::now().to_rfc3339();
    Ok((
        PortableConnection {
            login_uris: vec![],
            item_type: kind.into(),
            folder: String::new(),
            favorite: false,
            id: Uuid::new_v4(),
            modules: vec![],
            name: if name.trim().is_empty() {
                "Imported item".into()
            } else {
                name.into()
            },
            enabled: true,
            created_at: now.clone(),
            updated_at: now,
            description: String::new(),
            http_auth_type: String::new(),
            private_key_name: String::new(),
            auth_header: String::new(),
            auth_location: String::new(),
            auth_prefix: String::new(),
            api_auth_headers: vec![],
            test_path: String::new(),
        },
        SecretBundle::default(),
    ))
}

fn field(entry: &mut Entry, kind: &str, value: &str) -> Result<()> {
    ensure!(value.len() <= 1_048_576, "Imported field exceeds 1 MiB");
    if value.is_empty() {
        return Ok(());
    }
    entry.0.modules.push(ItemModule {
        kind: kind.into(),
        agent_visible: Some(false),
        ..Default::default()
    });
    match kind {
        "password" => entry.1.password = Some(value.into()),
        "privateKey" => entry.1.private_key = Some(value.into()),
        "passphrase" => entry.1.passphrase = Some(value.into()),
        _ => {
            entry.1.named_secrets.insert(kind.into(), value.into());
        }
    }
    Ok(())
}

fn custom(entry: &mut Entry, name: &str, value: &str) -> Result<()> {
    ensure!(value.len() <= 1_048_576, "Imported field exceeds 1 MiB");
    // Prefix prevents collisions with reserved names and keeps duplicate source fields distinct.
    let base = format!(
        "Imported · {}",
        if name.is_empty() { "Field" } else { name }
    );
    ensure!(
        base.chars().count() <= 70 && !base.chars().any(char::is_control),
        "Imported custom field name is too long or invalid"
    );
    let mut unique = base.clone();
    let mut index = 2;
    let normalized = |value: &str| {
        value
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '_' && *c != '-')
            .flat_map(char::to_lowercase)
            .collect::<String>()
    };
    while entry
        .0
        .modules
        .iter()
        .any(|m| normalized(&m.name) == normalized(&unique))
    {
        unique = format!("{base} ({index})");
        index += 1;
    }
    entry.0.modules.push(ItemModule {
        kind: "customSecret".into(),
        name: unique.clone(),
        agent_visible: Some(false),
        ..Default::default()
    });
    entry.1.named_secrets.insert(unique, value.into());
    Ok(())
}

fn login_uri(uri: &str, strategy: &str, preview: &mut Preview) -> LoginUri {
    if strategy != "regex" && crate::passkey::origin(uri).is_err() {
        preview.warn("nonWebUris");
        return LoginUri {
            uri: uri.into(),
            match_type: "never".into(),
        };
    }
    LoginUri {
        uri: uri.into(),
        match_type: strategy.into(),
    }
}

fn finish(entry: &mut Entry) -> Result<()> {
    crate::login_uri::validate(&entry.0.login_uris)?;
    if let Some(uri) = entry
        .0
        .login_uris
        .iter()
        .find(|uri| crate::passkey::origin(&uri.uri).is_ok())
    {
        entry.0.modules.push(ItemModule {
            kind: "url".into(),
            value: uri.uri.clone(),
            agent_visible: Some(false),
            ..Default::default()
        });
    }
    if entry.0.modules.is_empty() {
        entry.0.modules.push(ItemModule {
            kind: "username".into(),
            agent_visible: Some(false),
            ..Default::default()
        });
    }
    Ok(())
}

fn bitwarden(bytes: &[u8], preview: &mut Preview) -> Result<Vec<Entry>> {
    let root: Value = serde_json::from_slice(bytes)
        .map_err(|e| anyhow::anyhow!("Invalid JSON at line {}, column {}", e.line(), e.column()))?;
    ensure!(
        root["encrypted"] == false,
        "Choose Bitwarden's unencrypted .json export; encrypted exports are not supported"
    );
    let items = root["items"]
        .as_array()
        .context("Bitwarden JSON has no items array")?;
    ensure!(
        items.len() <= 50_000,
        "Import contains more than 50,000 items"
    );
    let folders: BTreeMap<&str, &str> = root["folders"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|folder| (text(folder, "id"), text(folder, "name")))
        .collect();
    let mut result = Vec::new();
    for (index, item) in items.iter().enumerate() {
        if !item["deletedDate"].is_null() {
            preview.skipped_deleted += 1;
            continue;
        }
        // Return a row number, never include source values in errors or logs.
        let entry = bitwarden_item(item, &folders, preview)
            .map_err(|e| anyhow::anyhow!("Item {}: {e}", index + 1))?;
        result.push(entry);
    }
    Ok(result)
}

fn bitwarden_item(
    item: &Value,
    folders: &BTreeMap<&str, &str>,
    preview: &mut Preview,
) -> Result<Entry> {
    let kind = match item["type"].as_u64() {
        Some(1) => "login",
        Some(2) => "secureNote",
        Some(3) => "card",
        Some(4) => "identity",
        Some(5) => "ssh",
        _ => bail!("Unsupported Bitwarden item type; no items were imported"),
    };
    let mut entry = blank(kind, text(item, "name"))?;
    entry.0.favorite = item["favorite"].as_bool().unwrap_or(false);
    if let Some(folder) = folders.get(text(item, "folderId")) {
        ensure!(
            folder.chars().count() <= 120,
            "Folder exceeds 120 characters"
        );
        entry.0.folder = (*folder).into();
    }
    for (key, target) in [
        ("creationDate", &mut entry.0.created_at),
        ("revisionDate", &mut entry.0.updated_at),
    ] {
        let date = text(item, key);
        if !date.is_empty() {
            chrono::DateTime::parse_from_rfc3339(date).context("Invalid item date")?;
            *target = date.into();
        }
    }
    field(&mut entry, "secureNote", text(item, "notes"))?;
    match kind {
        "login" => {
            let login = &item["login"];
            field(&mut entry, "username", text(login, "username"))?;
            field(&mut entry, "password", text(login, "password"))?;
            let totp = text(login, "totp");
            field(&mut entry, "totp", totp)?;
            if !totp.is_empty() && crate::crypto::totp::current_totp(totp).is_err() {
                preview.warn("unsupportedTotp");
            }
            for uri in login["uris"].as_array().into_iter().flatten() {
                let address = text(uri, "uri");
                if address.is_empty() {
                    continue;
                }
                let strategy = match uri["match"].as_u64() {
                    None | Some(0) => "domain",
                    Some(1) => "host",
                    Some(2) => "prefix",
                    Some(3) => "exact",
                    Some(4) => "regex",
                    Some(5) => "never",
                    _ => bail!("Unsupported website match rule"),
                };
                if uri["match"].is_null() {
                    preview.warn("defaultDomainMatch");
                }
                entry
                    .0
                    .login_uris
                    .push(login_uri(address, strategy, preview));
            }
            for key in login["fido2Credentials"].as_array().into_iter().flatten() {
                let imported = import_passkey(key)?;
                if imported.counter > 0 {
                    preview.warn("passkeyCounter");
                }
                entry.1.passkeys.push(imported);
            }
        }
        "card" => {
            for (source, target) in [
                ("cardholderName", "cardholderName"),
                ("brand", "cardBrand"),
                ("number", "cardNumber"),
                ("expMonth", "cardExpMonth"),
                ("expYear", "cardExpYear"),
                ("code", "cardSecurityCode"),
            ] {
                field(&mut entry, target, text(&item["card"], source))?;
            }
        }
        "identity" => {
            for target in crate::item_types::IDENTITY_FIELDS {
                let source = match *target {
                    "identityTitle" => "title",
                    "nationalId" => "ssn",
                    other => other,
                };
                field(&mut entry, target, text(&item["identity"], source))?;
            }
            field(&mut entry, "username", text(&item["identity"], "username"))?;
        }
        "ssh" => {
            field(
                &mut entry,
                "privateKey",
                text(&item["sshKey"], "privateKey"),
            )?;
            entry.0.private_key_name = "imported-key".into();
            for name in ["publicKey", "keyFingerprint"] {
                if !text(&item["sshKey"], name).is_empty() {
                    custom(&mut entry, name, text(&item["sshKey"], name))?;
                }
            }
        }
        _ => {}
    }
    for source in item["fields"].as_array().into_iter().flatten() {
        let value = if source["type"] == 3 {
            preview.warn("linkedFields");
            serde_json::to_string(source)?
        } else {
            text(source, "value").to_owned()
        };
        custom(&mut entry, text(source, "name"), &value)?;
    }
    if let Some(history) = item["passwordHistory"].as_array() {
        for previous in history.iter().take(20) {
            let password = text(previous, "password");
            ensure!(
                password.len() <= 1_048_576,
                "Imported password history entry is too long"
            );
            if password.is_empty() {
                continue;
            }
            let date = text(previous, "lastUsedDate");
            if !date.is_empty() {
                chrono::DateTime::parse_from_rfc3339(date)
                    .context("Invalid password history date")?;
            }
            entry
                .1
                .password_history
                .push(crate::model::PasswordHistoryEntry {
                    password: password.into(),
                    changed_at: if date.is_empty() {
                        entry.0.updated_at.clone()
                    } else {
                        date.into()
                    },
                });
        }
        if history.len() > 20 {
            custom(
                &mut entry,
                "Password history archive",
                &serde_json::to_string(&item["passwordHistory"])?,
            )?;
            preview.warn("passwordHistory");
        }
    }
    if item["reprompt"].as_u64().unwrap_or(0) > 0 {
        preview.warn("reprompt");
    }
    if item["attachments"]
        .as_array()
        .is_some_and(|a| !a.is_empty())
    {
        preview.warn("attachments");
    }
    if !item["organizationId"].is_null() {
        preview.warn("organization");
    }
    finish(&mut entry)?;
    Ok(entry)
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .or_else(|_| STANDARD.decode(value))
        .map_err(|_| anyhow::anyhow!("Invalid passkey encoding"))
}

fn import_passkey(source: &Value) -> Result<StoredPasskey> {
    ensure!(
        source["keyType"] == "public-key"
            && source["keyAlgorithm"] == "ECDSA"
            && source["keyCurve"] == "P-256",
        "Unsupported passkey algorithm; no items were imported"
    );
    let bytes = Zeroizing::new(decode_base64(text(source, "keyValue"))?);
    let key = SigningKey::from_pkcs8_der(&bytes).context("Invalid passkey private key")?;
    let raw_id = if let Some(encoded) = text(source, "credentialId").strip_prefix("b64.") {
        decode_base64(encoded)?
    } else {
        Uuid::parse_str(text(source, "credentialId"))
            .context("Invalid passkey credential ID")?
            .as_bytes()
            .to_vec()
    };
    ensure!(
        !raw_id.is_empty() && raw_id.len() <= 1023,
        "Invalid passkey credential ID length"
    );
    let user = decode_base64(text(source, "userHandle"))?;
    let discoverable = source["discoverable"] == "true" || source["discoverable"] == true;
    ensure!(
        user.len() <= 64 && (!discoverable || !user.is_empty()),
        "Invalid passkey user handle"
    );
    let rp = text(source, "rpId");
    let origin = crate::passkey::origin(&format!("https://{rp}"))?;
    ensure!(
        origin.host_str() == Some(rp)
            && !rp.ends_with('.')
            && (psl::domain_str(rp).is_some() || rp == "localhost")
            && rp.parse::<std::net::IpAddr>().is_err(),
        "Invalid passkey relying party"
    );
    let counter = match &source["counter"] {
        Value::String(s) => s.parse::<u32>().context("Invalid passkey counter")?,
        value => value
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .context("Invalid passkey counter")?,
    };
    Ok(StoredPasskey {
        counter,
        credential_id: URL_SAFE_NO_PAD.encode(raw_id),
        rp_id: rp.into(),
        user_handle: URL_SAFE_NO_PAD.encode(user),
        user_name: text(source, "userName").into(),
        display_name: text(source, "userDisplayName").into(),
        private_key: URL_SAFE_NO_PAD.encode(key.to_bytes()),
        discoverable,
        created_at: text(source, "creationDate").into(),
    })
}

fn chrome_csv(bytes: &[u8], preview: &mut Preview) -> Result<Vec<Entry>> {
    let mut reader = csv::ReaderBuilder::new().from_reader(bytes);
    let headers = reader.headers().context("Invalid CSV header")?.clone();
    for name in ["url", "username", "password"] {
        ensure!(
            headers
                .iter()
                .filter(|h| h.eq_ignore_ascii_case(name))
                .count()
                == 1,
            "CSV must contain unique url, username and password columns"
        );
    }
    let column = |row: &csv::StringRecord, name: &str| -> String {
        headers
            .iter()
            .position(|h| h.eq_ignore_ascii_case(name))
            .and_then(|i| row.get(i))
            .unwrap_or_default()
            .to_owned()
    };
    let mut entries = Vec::new();
    for (index, row) in reader.records().enumerate() {
        ensure!(index < 50_000, "Import contains more than 50,000 items");
        let row = row.map_err(|_| anyhow::anyhow!("Invalid CSV record {}", index + 2))?;
        let result = (|| -> Result<Entry> {
            let url = column(&row, "url");
            let name = column(&row, "name");
            let fallback = crate::passkey::origin(&url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned))
                .unwrap_or_else(|| "Imported login".into());
            let mut entry = blank("login", if name.is_empty() { &fallback } else { &name })?;
            field(&mut entry, "username", &column(&row, "username"))?;
            field(&mut entry, "password", &column(&row, "password"))?;
            let note = column(&row, "note");
            let notes = column(&row, "notes");
            field(
                &mut entry,
                "secureNote",
                if note.is_empty() { &notes } else { &note },
            )?;
            if !url.is_empty() {
                entry.0.login_uris.push(login_uri(&url, "origin", preview));
            }
            for (i, header) in headers.iter().enumerate() {
                if !["name", "url", "username", "password", "note", "notes"]
                    .contains(&header.to_ascii_lowercase().as_str())
                    && !row[i].is_empty()
                {
                    custom(&mut entry, header, &row[i])?;
                }
            }
            finish(&mut entry)?;
            Ok(entry)
        })()
        .map_err(|e| anyhow::anyhow!("CSV record {}: {e}", index + 2))?;
        entries.push(result);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        ecdsa::{Signature, signature::Verifier},
        pkcs8::EncodePrivateKey,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};

    #[test]
    fn bitwarden_history_imports_recent_entries_and_preserves_overflow() {
        let history: Vec<_> = (0..23).map(|i|json!({"password":format!("previous-{i}"),"lastUsedDate":"2026-01-01T00:00:00Z"})).collect();
        let source = json!({"encrypted":false,"items":[{"type":1,"name":"History login","login":{"password":"current"},"passwordHistory":history}]});
        let parsed = parse(&serde_json::to_vec(&source).unwrap(), "bitwarden").unwrap();
        let secrets = &parsed.entries[0].1;
        assert_eq!(secrets.password_history.len(), 20);
        assert_eq!(secrets.password_history[0].password, "previous-0");
        assert_eq!(
            secrets.password_history[19].changed_at,
            "2026-01-01T00:00:00Z"
        );
        assert!(
            secrets
                .named_secrets
                .values()
                .any(|value| value.contains("previous-22"))
        );
        assert_eq!(secrets.get("password"), Some("current"));
    }

    #[test]
    fn bitwarden_preserves_personal_types_metadata_and_encrypted_secrets() {
        let source = json!({"encrypted":false,"folders":[{"id":"f","name":"Personal"}],"items":[
            {"type":1,"name":"Login","folderId":"f","favorite":true,"notes":"private note","login":{"username":"alice","password":"secret-password","totp":"JBSWY3DPEHPK3PXP","uris":[{"uri":"https://example.com/login","match":3},{"uri":"https://other.example.com","match":5}]},"fields":[{"name":"password","value":"custom password","type":1},{"name":"password","value":"second","type":0}]},
            {"type":3,"name":"Card","card":{"number":"4111111111111111","code":"123"}},
            {"type":4,"name":"Identity","identity":{"firstName":"Ada","ssn":"synthetic-doc"}},
            {"type":2,"name":"Note","notes":"line1\nline2"},
            {"type":2,"name":"Deleted","deletedDate":"2024-01-01T00:00:00Z"}
        ]});
        let parsed = parse(&serde_json::to_vec(&source).unwrap(), "bitwarden").unwrap();
        assert_eq!(parsed.preview.total, 4);
        assert_eq!(parsed.preview.skipped_deleted, 1);
        let tmp = tempfile::tempdir().unwrap();
        let vault = crate::vault::Vault::open(tmp.path().into()).unwrap();
        let mut invalid_batch = parsed.entries.clone();
        invalid_batch[3].0.folder = "x".repeat(121);
        assert!(vault.merge_connections(invalid_batch).is_err());
        assert!(
            vault.list_connections().unwrap().is_empty(),
            "A late invalid record must roll back the entire batch"
        );
        assert_eq!(vault.merge_connections(parsed.entries).unwrap().added, 4);
        let items = vault.export_connections().unwrap();
        assert_eq!(items[0].0.folder, "Personal");
        assert!(items[0].0.favorite);
        assert_eq!(items[0].0.login_uris.len(), 2);
        assert_eq!(items[0].1.get("Imported · password (2)"), Some("second"));
        assert_eq!(items[2].1.get("nationalId"), Some("synthetic-doc"));
        let disk = std::fs::read_to_string(tmp.path().join("vault.json")).unwrap();
        for secret in [
            "secret-password",
            "4111111111111111",
            "synthetic-doc",
            "private note",
        ] {
            assert!(!disk.contains(secret));
        }
        let reparsed = parse(&serde_json::to_vec(&source).unwrap(), "bitwarden").unwrap();
        assert_eq!(vault.merge_connections(reparsed.entries).unwrap().merged, 4);
        let exported = crate::backup::cloud_snapshot(&vault).unwrap();
        let restored = crate::vault::Vault::open(tmp.path().join("restored")).unwrap();
        crate::backup::restore_cloud_snapshot(&restored, &exported).unwrap();
        assert_eq!(
            restored.export_connections().unwrap()[0].0.login_uris,
            items[0].0.login_uris
        );
    }

    #[test]
    fn csv_handles_bom_quotes_commas_newlines_and_invalid_records() {
        let parsed = parse(b"\xef\xbb\xbfname,url,username,password,note\r\n\"A, B\",https://example.com,alice,\"p\"\"ass\",\"one\r\ntwo\"\r\n", "chrome").unwrap();
        assert_eq!(parsed.entries[0].0.name, "A, B");
        assert_eq!(parsed.entries[0].1.get("password"), Some("p\"ass"));
        assert_eq!(parsed.entries[0].1.get("secureNote"), Some("one\r\ntwo"));
        assert!(
            parse(
                b"name,url,username,password\nA,https://example.com,alice,p,extra",
                "chrome"
            )
            .is_err()
        );
        assert!(parse(br#"{"encrypted":true,"items":[]}"#, "bitwarden").is_err());
        assert!(
            parse(
                br#"{"encrypted":false,"items":[{"name":"a","type":99}]}"#,
                "bitwarden"
            )
            .is_err()
        );
    }

    #[test]
    fn imported_pkcs8_passkey_signs_and_increments_persisted_counter() {
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let source = json!({"keyType":"public-key","keyAlgorithm":"ECDSA","keyCurve":"P-256",
            "keyValue":URL_SAFE_NO_PAD.encode(key.to_pkcs8_der().unwrap().as_bytes()),"rpId":"example.com",
            "credentialId":"00112233-4455-4677-8899-aabbccddeeff","userHandle":URL_SAFE_NO_PAD.encode([3;16]),
            "userName":"alice","discoverable":"true","counter":"12"});
        let passkey = import_passkey(&source).unwrap();
        let id = passkey.credential_id.clone();
        assert_eq!(
            crate::passkey::decode(&id).unwrap(),
            Uuid::parse_str("00112233-4455-4677-8899-aabbccddeeff")
                .unwrap()
                .as_bytes()
        );
        let mut entry = blank("login", "Imported passkey").unwrap();
        entry.1.passkeys.push(passkey);
        finish(&mut entry).unwrap();
        let item_id = entry.0.id;
        let tmp = tempfile::tempdir().unwrap();
        let vault = crate::vault::Vault::open(tmp.path().into()).unwrap();
        vault.merge_connections(vec![entry]).unwrap();
        let options = json!({"rpId":"example.com","challenge":URL_SAFE_NO_PAD.encode([8;32]),"userVerification":"required"});
        assert!(
            vault
                .assert_browser_passkey(item_id, &id, "https://evil.test", &options, true)
                .is_err()
        );
        assert_eq!(
            vault.get_connection(item_id).unwrap().secrets.passkeys[0].counter,
            12
        );
        for counter in [13u32, 14] {
            let response = vault
                .assert_browser_passkey(item_id, &id, "https://example.com", &options, true)
                .unwrap();
            let auth =
                crate::passkey::decode(response["response"]["authenticatorData"].as_str().unwrap())
                    .unwrap();
            assert_eq!(&auth[33..37], &counter.to_be_bytes());
            let mut signed = auth;
            signed.extend_from_slice(&Sha256::digest(
                crate::passkey::decode(response["response"]["clientDataJSON"].as_str().unwrap())
                    .unwrap(),
            ));
            let signature = Signature::from_der(
                &crate::passkey::decode(response["response"]["signature"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
            key.verifying_key().verify(&signed, &signature).unwrap();
            assert_eq!(
                vault.get_connection(item_id).unwrap().secrets.passkeys[0].counter,
                counter
            );
        }
    }
}
