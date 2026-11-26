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
use std::{collections::BTreeMap, path::Path};
use uuid::Uuid;
use zeroize::Zeroizing;

pub mod packages;
pub use packages::{
    VaultPackageInspection, VaultPackageKind, inspect_vault_package_bytes,
    inspect_vault_package_file, is_bitwarden_encrypted_json_bytes, is_kdbx_bytes,
    is_vault_package_extension, is_vault_package_path, parse_package_with_password,
    parse_with_password, read_bounded_regular_file, read_with_password,
};

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
    let bytes = read_bounded_regular_file(path, MAX_BYTES)?;
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
        "onepassword" | "1password" | "1pux" => packages::parse_1password_1pux(bytes, &mut preview)?,
        "keepass" | "keepass_xml" => packages::parse_keepass_xml(bytes, &mut preview)?,
        _ => bail!("Unsupported import format"),
    };
    finalize_parsed(entries, preview)
}

pub(super) fn finalize_parsed(entries: Vec<Entry>, mut preview: Preview) -> Result<Parsed> {
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
    if root["encrypted"] == true {
        if root["passwordProtected"] == true {
            bail!(
                "This Bitwarden export is password-protected; unlock it with its export password to import."
            );
        }
        bail!(
            "This Bitwarden export is account-restricted and can only be decrypted inside Bitwarden. Re-export using 'Encrypted JSON (Password protected)' or unencrypted JSON."
        );
    }
    ensure!(
        root["encrypted"] == false,
        "Choose Bitwarden's unencrypted .json or password-protected encrypted .json export"
    );
    bitwarden_plain_root(&root, preview)
}

pub(super) fn bitwarden_plain_root(root: &Value, preview: &mut Preview) -> Result<Vec<Entry>> {
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

    #[test]
    fn bitwarden_encrypted_pbkdf2_roundtrip_tamper_and_selective_preview() {
        let pk = SigningKey::from_slice(&[9; 32]).unwrap();
        // Real Bitwarden encrypted exports omit "encrypted": false inside the decrypted JSON payload.
        let inner = json!({
            "folders": [{"id": "f-work", "name": "Work"}],
            "items": [
                {
                    "type": 1,
                    "name": "GitHub Enterprise",
                    "folderId": "f-work",
                    "favorite": true,
                    "notes": "primary work account",
                    "login": {
                        "username": "alice@corp.test",
                        "password": "bw-secret-password-1",
                        "totp": "JBSWY3DPEHPK3PXP",
                        "uris": [{"uri": "https://github.com/login", "match": 0}],
                        "fido2Credentials": [{
                            "keyType": "public-key",
                            "keyAlgorithm": "ECDSA",
                            "keyCurve": "P-256",
                            "keyValue": URL_SAFE_NO_PAD.encode(pk.to_pkcs8_der().unwrap().as_bytes()),
                            "rpId": "github.com",
                            "credentialId": "11223344-5566-4777-8899-aabbccddeeff",
                            "userHandle": URL_SAFE_NO_PAD.encode([4; 16]),
                            "userName": "alice",
                            "discoverable": "true",
                            "counter": "0"
                        }]
                    },
                    "passwordHistory": [{"password": "old-bw-password", "lastUsedDate": "2026-01-01T00:00:00Z"}]
                },
                {
                    "type": 5,
                    "name": "Prod SSH Key",
                    "folderId": "f-work",
                    "sshKey": {
                        "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nTESTKEY\n-----END OPENSSH PRIVATE KEY-----",
                        "publicKey": "ssh-ed25519 AAAATEST alice@corp"
                    }
                },
                {
                    "type": 2,
                    "name": "Deleted Note",
                    "deletedDate": "2026-01-02T00:00:00Z",
                    "notes": "should be skipped"
                }
            ]
        });

        let encrypted = packages::test_helpers::make_bitwarden_encrypted_pbkdf2(
            &inner,
            "ExportPass#2026!",
        );
        assert!(is_bitwarden_encrypted_json_bytes(&encrypted));
        let inspected = inspect_vault_package_bytes(&encrypted, "bitwarden_export.json").unwrap();
        assert_eq!(inspected.package_kind, VaultPackageKind::BitwardenEncrypted);
        assert!(inspected.requires_password);

        // Plain parse without password fails with password hint
        assert!(parse(&encrypted, "bitwarden").is_err());

        // Wrong password must be rejected
        let wrong = parse_package_with_password(
            &encrypted,
            VaultPackageKind::BitwardenEncrypted,
            "wrong-password",
        );
        assert!(wrong.is_err());

        // Tampered MAC must be rejected
        let mut tampered_val: Value = serde_json::from_slice(&encrypted).unwrap();
        let orig_data = tampered_val["data"].as_str().unwrap().to_owned();
        let mut chars: Vec<char> = orig_data.chars().collect();
        let last = chars.len() - 2;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        tampered_val["data"] = Value::String(chars.into_iter().collect());
        let tampered_bytes = serde_json::to_vec(&tampered_val).unwrap();
        assert!(
            parse_package_with_password(
                &tampered_bytes,
                VaultPackageKind::BitwardenEncrypted,
                "ExportPass#2026!"
            )
            .is_err()
        );

        // Correct password decrypts & preserves all fields including Passkey + SSH
        let parsed = parse_package_with_password(
            &encrypted,
            VaultPackageKind::BitwardenEncrypted,
            "ExportPass#2026!",
        )
        .unwrap();
        assert_eq!(parsed.preview.total, 2);
        assert_eq!(parsed.preview.passkeys, 1);
        assert_eq!(parsed.preview.skipped_deleted, 1);

        let tmp = tempfile::tempdir().unwrap();
        let vault = crate::vault::Vault::open(tmp.path().into()).unwrap();
        let preview = crate::backup::preview_migration_entries(
            &vault,
            VaultPackageKind::BitwardenEncrypted.format_label().to_owned(),
            &parsed.entries,
        )
        .unwrap();
        assert_eq!(preview.new_items, 2);
        assert_eq!(preview.passkey_count, 1);
        assert_eq!(preview.items.len(), 2);

        let summary = vault.merge_connections(parsed.entries).unwrap();
        assert_eq!(summary.added, 2);
        let disk = std::fs::read_to_string(tmp.path().join("vault.json")).unwrap();
        assert!(!disk.contains("bw-secret-password-1"));
        assert!(!disk.contains("TESTKEY"));
    }

    #[test]
    fn bitwarden_encrypted_argon2id_and_account_restricted() {
        let inner = json!({
            "items": [{
                "type": 1,
                "name": "Argon2 Login",
                "login": {"username": "bob", "password": "argon2-secret-value", "uris": [{"uri": "https://argon2.example.com"}]}
            }]
        });
        let encrypted = packages::test_helpers::make_bitwarden_encrypted_argon2id(
            &inner,
            "Argon2Export#99!",
        );
        assert!(
            parse_with_password(&encrypted, "bitwarden", "wrong").is_err(),
            "Argon2id wrong password must fail"
        );
        let parsed = parse_with_password(&encrypted, "bitwarden", "Argon2Export#99!").unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].0.name, "Argon2 Login");
        assert_eq!(parsed.entries[0].1.get("password"), Some("argon2-secret-value"));

        // Account-restricted export (encrypted: true, no passwordProtected)
        let restricted = br#"{"encrypted":true,"encKeyValidation_MAC":"2.AA|BB|CC","items":[]}"#;
        let err = inspect_vault_package_bytes(restricted, "bw-account.json")
            .unwrap_err()
            .to_string();
        assert!(err.contains("account-restricted"), "unexpected error: {err}");
    }

    #[test]
    fn onepassword_1pux_imports_all_categories_and_skips_archived() {
        let export_data = json!({
            "accounts": [{
                "attrs": {"name": "Alice", "email": "alice@example.com"},
                "vaults": [{
                    "attrs": {"uuid": "v1", "name": "Engineering", "type": "P"},
                    "items": [
                        {
                            "uuid": "i1",
                            "favIndex": 1,
                            "createdAt": 1700000000,
                            "updatedAt": 1700000100,
                            "state": "active",
                            "categoryUuid": "001",
                            "overview": {
                                "title": "Linear App",
                                "url": "https://linear.app/login",
                                "urls": [{"label": "website", "url": "https://linear.app/login"}]
                            },
                            "details": {
                                "loginFields": [
                                    {"value": "alice@linear.test", "name": "email", "fieldType": "T", "designation": "username"},
                                    {"value": "1pux-login-pass", "name": "password", "fieldType": "P", "designation": "password"}
                                ],
                                "notesPlain": "SSO backup",
                                "sections": [{
                                    "title": "2FA",
                                    "fields": [{
                                        "title": "one-time password",
                                        "id": "TOTP_1",
                                        "value": {"totp": "otpauth://totp/Linear:alice?secret=JBSWY3DPEHPK3PXP&issuer=Linear"}
                                    }]
                                }],
                                "passwordHistory": [{"value": "older-1pux-pass", "time": 1690000000}]
                            }
                        },
                        {
                            "uuid": "i2",
                            "state": "active",
                            "categoryUuid": "114",
                            "overview": {"title": "Deploy Ed25519"},
                            "details": {
                                "sections": [{
                                    "title": "",
                                    "fields": [{
                                        "title": "private key",
                                        "id": "private_key",
                                        "value": {
                                            "sshKey": {
                                                "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n1PUXSSH\n-----END OPENSSH PRIVATE KEY-----",
                                                "metadata": {"publicKey": "ssh-ed25519 AAAA1PUX", "fingerprint": "SHA256:abc"}
                                            }
                                        }
                                    }]
                                }]
                            }
                        },
                        {
                            "uuid": "i3",
                            "state": "active",
                            "categoryUuid": "112",
                            "overview": {"title": "Stripe Live"},
                            "details": {
                                "sections": [{
                                    "title": "API",
                                    "fields": [
                                        {"title": "credential", "id": "credential", "value": {"concealed": "sk_live_1pux_token_999"}},
                                        {"title": "hostname", "id": "hostname", "value": {"url": "https://api.stripe.com"}}
                                    ]
                                }]
                            }
                        },
                        {
                            "uuid": "i4",
                            "state": "active",
                            "categoryUuid": "002",
                            "overview": {"title": "Corp Visa"},
                            "details": {
                                "sections": [{
                                    "title": "Card",
                                    "fields": [
                                        {"title": "cardholder", "id": "cardholder", "value": {"string": "Alice Dev"}},
                                        {"title": "number", "id": "ccnum", "value": {"creditCardNumber": "4242424242424242"}},
                                        {"title": "cvv", "id": "cvv", "value": {"concealed": "789"}},
                                        {"title": "expiry", "id": "expiry", "value": {"monthYear": 202912}}
                                    ]
                                }]
                            }
                        },
                        {
                            "uuid": "i5",
                            "state": "active",
                            "categoryUuid": "004",
                            "overview": {"title": "Alice Identity"},
                            "details": {
                                "sections": [{
                                    "title": "Personal",
                                    "fields": [
                                        {"title": "first name", "id": "firstname", "value": {"string": "Alice"}},
                                        {"title": "email", "id": "email", "value": {"email": "alice@example.com"}},
                                        {"title": "address", "id": "address", "value": {"address": {"street": "1 Main St", "city": "SF", "zip": "94105"}}}
                                    ]
                                }]
                            }
                        },
                        {
                            "uuid": "i6",
                            "state": "archived",
                            "categoryUuid": "003",
                            "overview": {"title": "Archived Note"},
                            "details": {"notesPlain": "skip me"}
                        }
                    ]
                }]
            }]
        });

        let mut zip_buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_buf));
            let opts = zip::write::SimpleFileOptions::default();
            zw.start_file("export.data", opts).unwrap();
            std::io::Write::write_all(&mut zw, &serde_json::to_vec(&export_data).unwrap()).unwrap();
            zw.finish().unwrap();
        }

        let parsed = parse(&zip_buf, "onepassword").unwrap();
        assert_eq!(parsed.preview.total, 5);
        assert_eq!(parsed.preview.skipped_deleted, 1);
        assert_eq!(parsed.entries[0].0.folder, "Engineering");
        assert!(parsed.entries[0].0.favorite);
        assert_eq!(parsed.entries[0].1.get("password"), Some("1pux-login-pass"));
        assert!(parsed.entries[0].1.get("totp").unwrap().contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(parsed.entries[0].1.password_history.len(), 1);
        assert_eq!(parsed.entries[1].0.item_type, "ssh");
        assert!(parsed.entries[1].1.private_key.as_deref().unwrap().contains("1PUXSSH"));
        assert_eq!(parsed.entries[2].0.item_type, "api");
        assert_eq!(parsed.entries[2].1.get("apiCredential"), Some("sk_live_1pux_token_999"));
        assert_eq!(parsed.entries[3].0.item_type, "card");
        assert_eq!(parsed.entries[3].1.get("cardExpYear"), Some("2029"));
        assert_eq!(parsed.entries[3].1.get("cardExpMonth"), Some("12"));
        assert_eq!(parsed.entries[4].0.item_type, "identity");
        assert_eq!(parsed.entries[4].1.get("city"), Some("SF"));

        // Verify vault commit encrypts all secrets
        let tmp = tempfile::tempdir().unwrap();
        let vault = crate::vault::Vault::open(tmp.path().into()).unwrap();
        assert_eq!(vault.merge_connections(parsed.entries).unwrap().added, 5);
        let disk = std::fs::read_to_string(tmp.path().join("vault.json")).unwrap();
        assert!(!disk.contains("1pux-login-pass"));
        assert!(!disk.contains("sk_live_1pux_token_999"));

        // Verify Import Hub binary extraction handles .1pux directly
        let extracted = crate::extract::extract_from_bytes(&zip_buf, "1Password.1pux", &[]).unwrap();
        assert_eq!(extracted.detected_format, "onepassword_1pux");
        assert_eq!(extracted.candidates.len(), 5);
    }

    #[test]
    fn keepass_kdbx4_roundtrip_folders_totp_ssh_and_recycle_bin() {
        use keepass::{Database, DatabaseKey, db::fields};

        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            root.name = "Root".into();

            let mut work = root.add_group();
            work.name = "Work".into();
            let mut cloud = work.add_group();
            cloud.name = "Cloud".into();
            let mut entry = cloud.add_entry();
            entry.set_unprotected(fields::TITLE, "AWS Console");
            entry.set_unprotected(fields::USERNAME, "admin@corp.test");
            entry.set_protected(fields::PASSWORD, "kdbx-aws-secret-1");
            entry.set_unprotected(fields::URL, "https://console.aws.amazon.com");
            entry.set_protected("otp", "otpauth://totp/AWS:admin?secret=JBSWY3DPEHPK3PXP");
            entry.set_unprotected("AccountId", "123456789012");
        }
        {
            let mut root = db.root_mut();
            let mut totp_entry = root.add_entry();
            totp_entry.set_unprotected(fields::TITLE, "Native KeePass TOTP");
            totp_entry.set_unprotected(fields::USERNAME, "bob");
            totp_entry.set_protected(fields::PASSWORD, "kdbx-totp-pass");
            totp_entry.set_protected("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP");
            totp_entry.set_unprotected("TimeOtp-Period", "30");

            let mut ssh_entry = root.add_entry();
            ssh_entry.set_unprotected(fields::TITLE, "Bastion Host");
            ssh_entry.set_unprotected(fields::USERNAME, "ops");
            ssh_entry.set_unprotected(fields::URL, "ssh://ops@10.0.0.8:2222");
            ssh_entry.set_protected(
                fields::NOTES,
                "-----BEGIN OPENSSH PRIVATE KEY-----\nKDBXSSH\n-----END OPENSSH PRIVATE KEY-----",
            );
        }
        let recycle_uuid = {
            let mut root = db.root_mut();
            let mut bin = root.add_group();
            bin.name = "Trash Bin Custom".into();
            let id = bin.id().uuid();
            let mut del = bin.add_entry();
            del.set_unprotected(fields::TITLE, "Deleted Item");
            del.set_protected(fields::PASSWORD, "must-not-import");
            id
        };
        db.meta.recyclebin_enabled = Some(true);
        db.meta.recyclebin_uuid = Some(recycle_uuid);

        let mut kdbx_bytes = Vec::new();
        db.save(&mut kdbx_bytes, DatabaseKey::new().with_password("KeePass#Master99"))
            .unwrap();

        assert!(is_kdbx_bytes(&kdbx_bytes));
        let inspected = inspect_vault_package_bytes(&kdbx_bytes, "passwords.kdbx").unwrap();
        assert_eq!(inspected.package_kind, VaultPackageKind::KeepassKdbx);
        assert!(inspected.requires_password);

        // Wrong password fails with crisp message
        let err = parse_package_with_password(
            &kdbx_bytes,
            VaultPackageKind::KeepassKdbx,
            "wrong-master",
        )
        .err()
        .expect("wrong KeePass password must fail")
        .to_string();
        assert!(err.contains("Incorrect KeePass master password"), "unexpected error: {err}");

        // Plain keepass format rejects KDBX without password
        assert!(parse(&kdbx_bytes, "keepass").is_err());

        // Correct password decrypts 3 entries and skips Recycle Bin
        let parsed = parse_package_with_password(
            &kdbx_bytes,
            VaultPackageKind::KeepassKdbx,
            "KeePass#Master99",
        )
        .unwrap();
        assert_eq!(parsed.preview.total, 3);
        assert_eq!(parsed.preview.skipped_deleted, 1);

        let aws = parsed.entries.iter().find(|(p, _)| p.name == "AWS Console").unwrap();
        assert_eq!(aws.0.folder, "Work / Cloud");
        assert_eq!(aws.1.get("password"), Some("kdbx-aws-secret-1"));
        assert!(aws.1.get("totp").unwrap().contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(aws.1.get("Imported · AccountId"), Some("123456789012"));

        let native_otp = parsed
            .entries
            .iter()
            .find(|(p, _)| p.name == "Native KeePass TOTP")
            .unwrap();
        assert_eq!(native_otp.1.get("totp"), Some("JBSWY3DPEHPK3PXP"));

        let ssh = parsed.entries.iter().find(|(p, _)| p.name == "Bastion Host").unwrap();
        assert_eq!(ssh.0.item_type, "ssh");
        assert!(ssh.0.modules.iter().any(|m| m.kind == "host" && m.value == "10.0.0.8"));
        assert!(ssh.0.modules.iter().any(|m| m.kind == "port" && m.value == "2222"));
        assert!(ssh.1.private_key.as_deref().unwrap().contains("KDBXSSH"));

        // Verify selective preview + encrypted vault storage
        let tmp = tempfile::tempdir().unwrap();
        let vault = crate::vault::Vault::open(tmp.path().into()).unwrap();
        let preview = crate::backup::preview_migration_entries(
            &vault,
            VaultPackageKind::KeepassKdbx.format_label().to_owned(),
            &parsed.entries,
        )
        .unwrap();
        assert_eq!(preview.new_items, 3);
        assert_eq!(vault.merge_connections(parsed.entries).unwrap().added, 3);
        let disk = std::fs::read_to_string(tmp.path().join("vault.json")).unwrap();
        assert!(!disk.contains("kdbx-aws-secret-1"));
        assert!(!disk.contains("KDBXSSH"));
        assert!(!disk.contains("must-not-import"));
    }

    #[test]
    fn keepass_xml_migration_parses_entries() {
        let xml = br#"<?xml version="1.0" encoding="utf-8"?>
        <KeePassFile><Root><Group><Name>Root</Name><Group><Name>Dev</Name><Entry>
            <String><Key>Title</Key><Value>GitLab &amp; CI</Value></String>
            <String><Key>UserName</Key><Value>dev</Value></String>
            <String><Key>Password</Key><Value>p&#39;a&#x26;s<![CDATA[<>]]>s</Value></String>
            <String><Key>URL</Key><Value>https://gitlab.example.com</Value></String>
            <String><Key>otp</Key><Value>JBSWY3DPEHPK3PXP</Value></String>
            <History><Entry><String><Key>Password</Key><Value>old-history-pass</Value></String></Entry></History>
        </Entry></Group></Group></Root></KeePassFile>"#;
        let parsed = parse(xml, "keepass").unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].0.name, "GitLab & CI");
        assert_eq!(parsed.entries[0].0.folder, "Dev");
        assert_eq!(parsed.entries[0].1.get("password"), Some("p'a&s<>s"));
        assert_eq!(parsed.entries[0].1.get("totp"), Some("JBSWY3DPEHPK3PXP"));

        // Protected="True" XML values must be rejected rather than imported as plaintext
        let protected_xml = br#"<KeePassFile><Root><Group><Name>Root</Name><Entry>
            <String><Key>Password</Key><Value Protected="True">AAECAw==</Value></String>
        </Entry></Group></Root></KeePassFile>"#;
        assert!(parse(protected_xml, "keepass").is_err());
    }

    #[test]
    fn audit_regression_bitwarden_reordered_bom_cost_and_1pux_keepass_edge_cases() {
        // 1. Bitwarden encrypted JSON with UTF-8 BOM and "encrypted": true AFTER byte 4096
        let padding = "x".repeat(5000);
        let reordered = format!(
            "\u{feff}{{\"padding\":\"{padding}\",\"data\":\"2.AA|BB|CC\",\"kdfType\":1,\"kdfMemory\":1024,\"kdfIterations\":20,\"kdfParallelism\":4,\"salt\":\"s\",\"passwordProtected\":true,\"encrypted\":true}}"
        );
        assert!(is_bitwarden_encrypted_json_bytes(reordered.as_bytes()));
        let insp = inspect_vault_package_bytes(reordered.as_bytes(), "reordered.json").unwrap();
        assert_eq!(insp.package_kind, VaultPackageKind::BitwardenEncrypted);
        // Excessive Argon2id cost (1024 MiB x 20 > 2048 MiB*passes) rejected with cost error
        let cost_err = parse_package_with_password(
            reordered.as_bytes(),
            VaultPackageKind::BitwardenEncrypted,
            "any-pass",
        )
        .err()
        .unwrap()
        .to_string();
        assert!(cost_err.contains("Unsupported KDF cost"), "unexpected: {cost_err}");

        // 2. KDBX 2 pre-release signature (0x66) rejected upfront
        let kdbx2 = [0x03, 0xD9, 0xA2, 0x9A, 0x66, 0xFB, 0x4B, 0xB5, 0, 0, 2, 0];
        assert!(!is_kdbx_bytes(&kdbx2));
        let kdbx2_err = inspect_vault_package_bytes(&kdbx2, "old.kdbx").unwrap_err().to_string();
        assert!(kdbx2_err.contains("pre-release"), "unexpected: {kdbx2_err}");

        // 3. 1Password loginFields: undesignated text field before designated username must NOT steal username
        let op_data = json!({
            "accounts": [{
                "vaults": [{
                    "attrs": {"name": "Corp"},
                    "items": [{
                        "state": "active",
                        "categoryUuid": "001",
                        "overview": {"title": "SSO Portal", "url": "https://sso.corp.test"},
                        "details": {
                            "loginFields": [
                                {"name": "tenant", "fieldType": "T", "value": "ACME-CORP"},
                                {"name": "email", "fieldType": "E", "designation": "username", "value": "real-user@corp.test"},
                                {"name": "pwd", "fieldType": "P", "designation": "password", "value": "real-pass"}
                            ]
                        }
                    }]
                }]
            }]
        });
        let mut zip_buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_buf));
            zw.start_file("export.data", zip::write::SimpleFileOptions::default()).unwrap();
            std::io::Write::write_all(&mut zw, &serde_json::to_vec(&op_data).unwrap()).unwrap();
            zw.finish().unwrap();
        }
        let op_parsed = parse(&zip_buf, "onepassword").unwrap();
        assert_eq!(op_parsed.entries[0].1.get("username"), Some("real-user@corp.test"));
        assert_eq!(op_parsed.entries[0].1.get("Imported · tenant"), Some("ACME-CORP"));

        // 4. KeePass: user folder named "Recycle Bin" preserved when recyclebin_uuid points elsewhere,
        //    and ssh://deploy@[::1]:2222 preserves username + IPv6 host + port.
        use keepass::{Database, DatabaseKey, db::fields};
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut fake_bin = root.add_group();
            fake_bin.name = "Recycle Bin".into();
            let mut keep_entry = fake_bin.add_entry();
            keep_entry.set_unprotected(fields::TITLE, "IPv6 SSH Node");
            keep_entry.set_unprotected(fields::URL, "ssh://deploy@[::1]:2222");
            keep_entry.set_protected(fields::PASSWORD, "ipv6-pass");
        }
        let real_bin_uuid = {
            let mut root = db.root_mut();
            let mut real_bin = root.add_group();
            real_bin.name = "Actual Trash".into();
            let id = real_bin.id().uuid();
            let mut del = real_bin.add_entry();
            del.set_unprotected(fields::TITLE, "Really Deleted");
            id
        };
        db.meta.recyclebin_enabled = Some(true);
        db.meta.recyclebin_uuid = Some(real_bin_uuid);
        let mut kdbx_buf = Vec::new();
        db.save(&mut kdbx_buf, DatabaseKey::new().with_password("pass1234")).unwrap();

        let kp_parsed = parse_package_with_password(&kdbx_buf, VaultPackageKind::KeepassKdbx, "pass1234").unwrap();
        assert_eq!(kp_parsed.preview.total, 1);
        assert_eq!(kp_parsed.preview.skipped_deleted, 1);
        assert_eq!(kp_parsed.entries[0].0.folder, "Recycle Bin");
        assert_eq!(kp_parsed.entries[0].1.get("username"), Some("deploy"));
        assert!(kp_parsed.entries[0].0.modules.iter().any(|m| m.kind == "host" && m.value == "[::1]"));
        assert!(kp_parsed.entries[0].0.modules.iter().any(|m| m.kind == "port" && m.value == "2222"));
    }
}
