//! Password-manager vault package decoders:
//! - Bitwarden Password-Protected Encrypted JSON (PBKDF2-HMAC-SHA256 & Argon2id + AES-256-CBC + HMAC-SHA256)
//! - 1Password `.1pux` ZIP export (`export.data`)
//! - KeePass `.kdbx` (KDBX 3.1 / 4.x / KDB) & KeePass 2.x XML (streaming `quick-xml`)
//!
//! All raw input buffers, derived keys, and decrypted plaintext payloads are wrapped in
//! `Zeroizing` and strictly bounded before allocation/KDF execution.

use super::{Entry, MAX_BYTES, Parsed, Preview, blank, custom, field, finish, login_uri, text};
use crate::model::{ItemModule, PasswordHistoryEntry};
use aes::Aes256;
use anyhow::{Context, Result, bail, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use quick_xml::{events::Event, reader::Reader};
use ring::pbkdf2;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    io::{Cursor, Read},
    num::NonZeroU32,
    path::Path,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Supported password-protected vault package formats handled by the unified unlock & preview flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultPackageKind {
    Mvault,
    BitwardenEncrypted,
    KeepassKdbx,
}

impl VaultPackageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mvault => "mvault",
            Self::BitwardenEncrypted => "bitwarden_encrypted",
            Self::KeepassKdbx => "keepass_kdbx",
        }
    }

    pub fn format_label(self) -> &'static str {
        match self {
            Self::Mvault => "Protected .mvault",
            Self::BitwardenEncrypted => "Bitwarden Encrypted JSON",
            Self::KeepassKdbx => "KeePass .kdbx",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultPackageInspection {
    pub file_name: String,
    pub requires_password: bool,
    pub package_kind: VaultPackageKind,
}

const KDBX_SIG_1: [u8; 4] = [0x03, 0xD9, 0xA2, 0x9A];
const KDBX_SIG_2_V34: [u8; 4] = [0x67, 0xFB, 0x4B, 0xB5];
const KDBX_SIG_2_V2_PRERELEASE: [u8; 4] = [0x66, 0xFB, 0x4B, 0xB5];
const KDBX_SIG_2_KDB: [u8; 4] = [0x65, 0xFB, 0x4B, 0xB5];

const MAX_GROUP_DEPTH: usize = 64;
const MAX_XML_DEPTH: usize = 64;
const MAX_BW_PBKDF2_ITERS: u64 = 2_500_000;
const MAX_BW_ARGON2_MEM_MIB: u64 = 512;
const MAX_BW_ARGON2_ITERS: u64 = 20;
const MAX_ARGON2_WORK_MIB_PASSES: u64 = 2_048;
const MAX_KDBX_AES_ROUNDS: u64 = 20_000_000;

const ACCOUNT_RESTRICTED_BW_ERROR: &str = "This Bitwarden export is account-restricted and can only be decrypted inside Bitwarden. Re-export using 'Encrypted JSON (Password protected)' or unencrypted JSON.";

/// Opens a regular file once and reads at most `max_bytes` into a zeroizing buffer,
/// rejecting pipes/devices/special files and files that grow past `max_bytes`.
pub fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> Result<Zeroizing<Vec<u8>>> {
    let file = std::fs::File::open(path).context("Unable to open file")?;
    let meta = file.metadata().context("Unable to inspect file metadata")?;
    ensure!(meta.is_file(), "Expected a regular file");
    ensure!(
        meta.len() <= max_bytes,
        "File exceeds {} MiB limit",
        max_bytes / (1024 * 1024)
    );
    let mut bytes = Zeroizing::new(Vec::with_capacity((meta.len() as usize).min(1024 * 1024)));
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .context("Unable to read file")?;
    ensure!(
        bytes.len() as u64 <= max_bytes,
        "File exceeds {} MiB limit",
        max_bytes / (1024 * 1024)
    );
    Ok(bytes)
}

pub fn is_kdbx_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= 8
        && bytes[0..4] == KDBX_SIG_1
        && (bytes[4..8] == KDBX_SIG_2_V34 || bytes[4..8] == KDBX_SIG_2_KDB)
}

fn is_unsupported_kdbx2_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && bytes[0..4] == KDBX_SIG_1 && bytes[4..8] == KDBX_SIG_2_V2_PRERELEASE
}

/// Pure extension check (zero disk I/O) safe to call synchronously on UI hover events.
pub fn is_vault_package_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("mvault") || ext.eq_ignore_ascii_case("kdbx"))
}

/// Top-level JSON classifier for Bitwarden encrypted exports (handles UTF-8 BOM, arbitrary
/// whitespace, and arbitrary key ordering without any prefix-length assumption).
pub fn is_bitwarden_encrypted_json_bytes(bytes: &[u8]) -> bool {
    if bytes.len() as u64 > MAX_BYTES {
        return false;
    }
    let stripped = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let first_non_ws = stripped.iter().copied().find(|b| !b.is_ascii_whitespace());
    if first_non_ws != Some(b'{') {
        return false;
    }
    serde_json::from_slice::<Value>(stripped)
        .ok()
        .and_then(|v| v.as_object().and_then(|o| o.get("encrypted")).and_then(Value::as_bool))
        .unwrap_or(false)
}

/// Worker-thread classifier used after drop or file selection to route `.mvault`, `.kdbx`,
/// and Bitwarden encrypted `.json` files into the unified unlock & preview flow.
pub fn is_vault_package_path(path: &Path) -> bool {
    if is_vault_package_extension(path) {
        return true;
    }
    let is_json = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
    if is_json
        && let Ok(bytes) = read_bounded_regular_file(path, MAX_BYTES)
    {
        return is_bitwarden_encrypted_json_bytes(&bytes);
    }
    false
}

pub fn inspect_vault_package_bytes(bytes: &[u8], file_name: &str) -> Result<VaultPackageInspection> {
    ensure!(bytes.len() as u64 <= MAX_BYTES, "Vault package exceeds 64 MiB");
    let display_name = Path::new(file_name)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.trim().is_empty())
        .unwrap_or("vault-package")
        .to_owned();

    if is_unsupported_kdbx2_bytes(bytes) {
        bail!("Unsupported KeePass 2.x pre-release format; export as KDBX 3.1/4.x or XML");
    }

    if is_kdbx_bytes(bytes) {
        validate_kdbx_header_cost(bytes)?;
        return Ok(VaultPackageInspection {
            file_name: display_name,
            requires_password: true,
            package_kind: VaultPackageKind::KeepassKdbx,
        });
    }

    if display_name.to_ascii_lowercase().ends_with(".kdbx") {
        bail!("Invalid or damaged KeePass .kdbx database file");
    }

    let stripped = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    if let Ok(value) = serde_json::from_slice::<Value>(stripped)
        && value.is_object()
        && value["encrypted"] == true
    {
        if value["passwordProtected"] == true {
            ensure!(
                value["data"].as_str().is_some_and(|s| !s.is_empty()),
                "Bitwarden encrypted export is missing encrypted data payload"
            );
            return Ok(VaultPackageInspection {
                file_name: display_name,
                requires_password: true,
                package_kind: VaultPackageKind::BitwardenEncrypted,
            });
        }
        bail!("{ACCOUNT_RESTRICTED_BW_ERROR}");
    }

    let requires_password = crate::backup::inspect_bytes_requires_password(stripped)?;
    Ok(VaultPackageInspection {
        file_name: display_name,
        requires_password,
        package_kind: VaultPackageKind::Mvault,
    })
}

pub fn inspect_vault_package_file(path: &Path) -> Result<VaultPackageInspection> {
    let bytes = read_bounded_regular_file(path, MAX_BYTES)?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault-package");
    inspect_vault_package_bytes(&bytes, file_name)
}

// ---------------------------------------------------------------------------
// 1. Bitwarden Password-Protected Encrypted JSON
// ---------------------------------------------------------------------------

fn bitwarden_hkdf_expand_32(prk: &[u8; 32], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(prk).expect("HMAC accepts 32-byte key");
    mac.update(info);
    mac.update(&[0x01]);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn decrypt_bitwarden_enc_string(
    enc_string: &str,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>> {
    let rest = enc_string
        .trim()
        .strip_prefix("2.")
        .context("Unsupported Bitwarden cipher format (expected AES-256-CBC + HMAC-SHA256 type 2)")?;
    let mut parts = rest.split('|');
    let (Some(iv_b64), Some(ct_b64), Some(mac_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        bail!("Malformed Bitwarden encrypted string");
    };
    let iv = STANDARD.decode(iv_b64).context("Invalid Bitwarden IV encoding")?;
    let ct = STANDARD.decode(ct_b64).context("Invalid Bitwarden ciphertext encoding")?;
    let provided_mac = STANDARD.decode(mac_b64).context("Invalid Bitwarden MAC encoding")?;
    ensure!(iv.len() == 16, "Invalid Bitwarden IV length");
    ensure!(
        !ct.is_empty() && ct.len() % 16 == 0,
        "Invalid Bitwarden ciphertext block length"
    );
    ensure!(provided_mac.len() == 32, "Invalid Bitwarden MAC length");

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key).expect("HMAC accepts 32-byte key");
    mac.update(&iv);
    mac.update(&ct);
    let computed_mac = mac.finalize().into_bytes();
    if computed_mac.as_slice().ct_eq(&provided_mac).unwrap_u8() != 1 {
        bail!("Incorrect password or damaged Bitwarden export");
    }

    let decryptor = cbc::Decryptor::<Aes256>::new_from_slices(enc_key, &iv)
        .map_err(|_| anyhow::anyhow!("Invalid Bitwarden AES key/IV"))?;
    let plain = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(&ct)
        .map_err(|_| anyhow::anyhow!("Incorrect password or damaged Bitwarden export"))?;
    Ok(Zeroizing::new(plain))
}

pub fn decrypt_bitwarden_encrypted(bytes: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(bytes.len() as u64 <= MAX_BYTES, "Import file exceeds 64 MiB");
    ensure!(
        !password.is_empty() && password.len() <= 4096,
        "Enter the Bitwarden export password"
    );
    let stripped = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let root: Value = serde_json::from_slice(stripped)
        .map_err(|e| anyhow::anyhow!("Invalid JSON at line {}, column {}", e.line(), e.column()))?;
    ensure!(root["encrypted"] == true, "File is not an encrypted Bitwarden export");
    if root["passwordProtected"] != true {
        bail!("{ACCOUNT_RESTRICTED_BW_ERROR}");
    }

    let salt = root["salt"]
        .as_str()
        .filter(|s| !s.is_empty())
        .context("Bitwarden encrypted export is missing KDF salt")?;
    let kdf_type = root["kdfType"]
        .as_u64()
        .context("Bitwarden encrypted export is missing kdfType")?;
    let iterations = root["kdfIterations"]
        .as_u64()
        .context("Bitwarden encrypted export is missing kdfIterations")?;

    let mut master_key = Zeroizing::new([0u8; 32]);
    match kdf_type {
        0 => {
            ensure!(
                (1..=MAX_BW_PBKDF2_ITERS).contains(&iterations),
                "Unsupported KDF cost: Bitwarden PBKDF2 iterations ({iterations}) exceeds {MAX_BW_PBKDF2_ITERS}"
            );
            let iter_nz = NonZeroU32::new(iterations as u32)
                .context("Invalid PBKDF2 iteration count")?;
            pbkdf2::derive(
                pbkdf2::PBKDF2_HMAC_SHA256,
                iter_nz,
                salt.as_bytes(),
                password.as_bytes(),
                &mut *master_key,
            );
        }
        1 => {
            let memory_mib = root["kdfMemory"]
                .as_u64()
                .context("Bitwarden Argon2id export is missing kdfMemory")?;
            let parallelism = root["kdfParallelism"]
                .as_u64()
                .context("Bitwarden Argon2id export is missing kdfParallelism")?;
            ensure!(
                (1..=MAX_BW_ARGON2_ITERS).contains(&iterations)
                    && (1..=MAX_BW_ARGON2_MEM_MIB).contains(&memory_mib)
                    && (1..=16).contains(&parallelism)
                    && memory_mib.saturating_mul(iterations) <= MAX_ARGON2_WORK_MIB_PASSES,
                "Unsupported KDF cost: Bitwarden Argon2id parameters ({memory_mib} MiB × {iterations} passes) exceed safe local limits"
            );
            let params = Params::new(
                (memory_mib as u32) * 1024,
                iterations as u32,
                parallelism as u32,
                Some(32),
            )
            .map_err(|e| anyhow::anyhow!("Invalid Bitwarden Argon2id parameters: {e}"))?;
            // Official Bitwarden spec: SHA-256 hash the UTF-8 salt string into 32 bytes for Argon2id.
            let salt_hash = Sha256::digest(salt.as_bytes());
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(password.as_bytes(), &salt_hash, &mut *master_key)
                .map_err(|e| anyhow::anyhow!("Argon2id key derivation failed: {e}"))?;
        }
        _ => bail!("Unsupported Bitwarden KDF type ({kdf_type})"),
    }

    let enc_key = bitwarden_hkdf_expand_32(&master_key, b"enc");
    let mac_key = bitwarden_hkdf_expand_32(&master_key, b"mac");

    if let Some(validation_mac) = root["encKeyValidation_MAC"].as_str()
        && !validation_mac.is_empty()
    {
        let _verified = decrypt_bitwarden_enc_string(validation_mac, &enc_key, &mac_key)?;
    }

    let data = root["data"]
        .as_str()
        .filter(|s| !s.is_empty())
        .context("Bitwarden encrypted export is missing data payload")?;
    decrypt_bitwarden_enc_string(data, &enc_key, &mac_key)
}

pub fn parse_bitwarden_encrypted(bytes: &[u8], password: &str) -> Result<Parsed> {
    let plain = decrypt_bitwarden_encrypted(bytes, password)?;
    let inner: Value = serde_json::from_slice(&plain)
        .context("Decrypted Bitwarden payload is not valid JSON")?;
    ensure!(
        inner["encrypted"] != true,
        "Decrypted Bitwarden payload is still encrypted"
    );
    let mut preview = Preview::default();
    let entries = super::bitwarden_plain_root(&inner, &mut preview)?;
    super::finalize_parsed(entries, preview)
}

// ---------------------------------------------------------------------------
// Shared Safe Field Helpers (1Password & KeePass)
// ---------------------------------------------------------------------------

fn clamp_chars(raw: &str, max_chars: usize) -> String {
    let trimmed = raw.trim();
    if trimmed.chars().count() <= max_chars {
        trimmed.to_owned()
    } else {
        trimmed.chars().take(max_chars).collect()
    }
}

fn sanitize_custom_label(raw: &str) -> String {
    let clean: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let collapsed = clean.split_whitespace().collect::<Vec<_>>().join(" ");
    // "Imported · " is 11 chars; leave room for " (9999)" collision suffix within 70-char ceiling.
    let clamped = clamp_chars(&collapsed, 48);
    if clamped.is_empty() {
        "Field".to_owned()
    } else {
        clamped
    }
}

fn push_field_once(entry: &mut Entry, kind: &str, value: &str) -> Result<bool> {
    if value.is_empty() {
        return Ok(false);
    }
    if entry.0.modules.iter().any(|m| m.kind == kind) {
        return Ok(false);
    }
    field(entry, kind, value)?;
    Ok(true)
}

fn push_public_once(entry: &mut Entry, kind: &str, value: &str) {
    let trimmed = value.trim();
    if trimmed.is_empty() || entry.0.modules.iter().any(|m| m.kind == kind) {
        return;
    }
    entry.0.modules.push(ItemModule {
        kind: kind.into(),
        value: trimmed.into(),
        agent_visible: Some(false),
        ..Default::default()
    });
}

fn push_custom_safe(entry: &mut Entry, name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    let safe_name = sanitize_custom_label(name);
    custom(entry, &safe_name, value)
}

fn unix_to_rfc3339(ts: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(ts, 0).map(|dt| dt.to_rfc3339())
}

// ---------------------------------------------------------------------------
// 2. 1Password .1pux (ZIP archive containing export.data JSON)
// ---------------------------------------------------------------------------

pub fn parse_1password_1pux(bytes: &[u8], preview: &mut Preview) -> Result<Vec<Entry>> {
    ensure!(bytes.len() as u64 <= MAX_BYTES, "Import file exceeds 64 MiB");
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).context("Invalid 1Password .1pux archive")?;
    let export_entry = archive
        .by_name("export.data")
        .context("Invalid 1Password .1pux archive: missing export.data")?;
    let mut data_bytes = Zeroizing::new(Vec::new());
    export_entry
        .take(MAX_BYTES + 1)
        .read_to_end(&mut data_bytes)
        .context("Could not read export.data from .1pux archive")?;
    ensure!(
        data_bytes.len() as u64 <= MAX_BYTES,
        "1Password export.data exceeds 64 MiB uncompressed limit"
    );

    let root: Value = serde_json::from_slice(&data_bytes).map_err(|e| {
        anyhow::anyhow!(
            "Invalid 1Password export.data JSON at line {}, column {}",
            e.line(),
            e.column()
        )
    })?;
    let accounts = root["accounts"]
        .as_array()
        .context("1Password export.data has no accounts array")?;

    let mut entries = Vec::new();
    for account in accounts {
        for vault in account["vaults"].as_array().into_iter().flatten() {
            let vault_name = clamp_chars(text(&vault["attrs"], "name"), 120);
            for item in vault["items"].as_array().into_iter().flatten() {
                ensure!(entries.len() < 50_000, "Import contains more than 50,000 items");
                let state = text(item, "state");
                if state.eq_ignore_ascii_case("archived") || state.eq_ignore_ascii_case("trashed") {
                    preview.skipped_deleted += 1;
                    continue;
                }
                let entry = parse_1pux_item(item, &vault_name, preview)?;
                entries.push(entry);
            }
        }
    }
    Ok(entries)
}

fn extract_1pux_field_string(val: &Value) -> Option<String> {
    if let Some(s) = val.as_str() {
        return (!s.is_empty()).then(|| s.to_owned());
    }
    let obj = val.as_object()?;
    for key in [
        "string",
        "concealed",
        "email",
        "url",
        "phone",
        "totp",
        "creditCardNumber",
        "creditCardType",
        "menu",
        "gender",
        "reference",
    ] {
        if let Some(s) = obj.get(key).and_then(Value::as_str)
            && !s.is_empty()
        {
            return Some(s.to_owned());
        }
    }
    if let Some(n) = obj.get("monthYear").and_then(Value::as_i64)
        && n > 0
    {
        return Some(n.to_string());
    }
    if let Some(ts) = obj.get("date").and_then(Value::as_i64)
        && let Some(iso) = unix_to_rfc3339(ts)
    {
        return Some(iso);
    }
    None
}

fn parse_1pux_item(item: &Value, vault_name: &str, preview: &mut Preview) -> Result<Entry> {
    let category = text(item, "categoryUuid");
    let overview = &item["overview"];
    let details = &item["details"];

    let mut urls: Vec<String> = Vec::new();
    let primary_url = text(overview, "url").trim();
    if !primary_url.is_empty() {
        urls.push(primary_url.to_owned());
    }
    for u in overview["urls"].as_array().into_iter().flatten() {
        let addr = text(u, "url").trim();
        if !addr.is_empty() && !urls.iter().any(|x| x == addr) {
            urls.push(addr.to_owned());
        }
    }

    let raw_title = text(overview, "title").trim();
    let fallback_title = urls
        .first()
        .and_then(|u| crate::passkey::origin(u).ok())
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| "Imported 1Password item".to_owned());
    let title = clamp_chars(
        if raw_title.is_empty() {
            &fallback_title
        } else {
            raw_title
        },
        80,
    );

    let kind = match category {
        "001" | "005" => "login",
        "002" => "card",
        "003" => "secureNote",
        "004" => "identity",
        "114" => "ssh",
        "112" => "api",
        "110" => {
            // Only classify Server (110) as SSH if it carries an sshKey or ssh:// URL; otherwise custom.
            let has_ssh_signal = urls.iter().any(|u| u.to_ascii_lowercase().starts_with("ssh://"))
                || details["sections"].as_array().is_some_and(|secs| {
                    secs.iter().any(|s| {
                        s["fields"].as_array().is_some_and(|fs| {
                            fs.iter().any(|f| {
                                f["value"]["sshKey"].is_object()
                                    || text(f, "id").eq_ignore_ascii_case("ssh_key")
                            })
                        })
                    })
                });
            if has_ssh_signal { "ssh" } else { "custom" }
        }
        _ => "custom",
    };

    let mut entry = blank(kind, &title)?;
    entry.0.favorite = item["favIndex"].as_i64().unwrap_or(0) > 0;
    if !vault_name.is_empty() {
        entry.0.folder = vault_name.to_owned();
    } else if let Some(first_tag) = overview["tags"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
    {
        entry.0.folder = clamp_chars(first_tag, 120);
    }

    if let Some(ts) = item["createdAt"].as_i64().and_then(unix_to_rfc3339) {
        entry.0.created_at = ts;
    }
    if let Some(ts) = item["updatedAt"].as_i64().and_then(unix_to_rfc3339) {
        entry.0.updated_at = ts;
    }

    for url in &urls {
        entry.0.login_uris.push(login_uri(url, "domain", preview));
    }

    // Top-level notesPlain
    let notes = text(details, "notesPlain");
    if !notes.is_empty() {
        push_field_once(&mut entry, "secureNote", notes)?;
    }

    // Two-pass loginFields resolution: explicit designations first, heuristic fallback second,
    // so an undesignated text field earlier in the form never displaces an explicit username/password.
    let login_fields: Vec<&Value> = details["loginFields"]
        .as_array()
        .into_iter()
        .flatten()
        .collect();
    let mut consumed = vec![false; login_fields.len()];
    let mut extra_login_fields: Vec<(String, String)> = Vec::new();

    // Pass 1: explicit designations
    for (idx, lf) in login_fields.iter().enumerate() {
        let val = text(lf, "value");
        if val.is_empty() {
            consumed[idx] = true;
            continue;
        }
        match text(lf, "designation") {
            "username" => {
                if push_field_once(&mut entry, "username", val)? {
                    consumed[idx] = true;
                }
            }
            "password" => {
                if push_field_once(&mut entry, "password", val)? {
                    consumed[idx] = true;
                }
            }
            _ => {}
        }
    }
    // Pass 2: heuristic fallback only for still-missing primary fields, preserving all others
    for (idx, lf) in login_fields.iter().enumerate() {
        if consumed[idx] {
            continue;
        }
        let val = text(lf, "value");
        let field_type = text(lf, "fieldType");
        let designation = text(lf, "designation");
        let field_name = text(lf, "name");
        if designation.is_empty()
            && matches!(field_type, "T" | "E")
            && !entry.0.modules.iter().any(|m| m.kind == "username")
            && push_field_once(&mut entry, "username", val)?
        {
            continue;
        }
        if designation.is_empty()
            && field_type == "P"
            && !entry.0.modules.iter().any(|m| m.kind == "password")
            && push_field_once(&mut entry, "password", val)?
        {
            continue;
        }
        if !matches!(field_type, "B" | "I" | "C") {
            let label = if !field_name.is_empty() {
                field_name
            } else if !designation.is_empty() {
                designation
            } else {
                "Field"
            };
            extra_login_fields.push((label.to_owned(), val.to_owned()));
        }
    }

    // Top-level details.password (Password category 005 or fallback)
    let top_password = text(details, "password");
    if !top_password.is_empty() {
        push_field_once(&mut entry, "password", top_password)?;
    }

    // Walk sections & fields
    for section in details["sections"].as_array().into_iter().flatten() {
        let sec_title = text(section, "title").trim();
        for f in section["fields"].as_array().into_iter().flatten() {
            let fid = text(f, "id").to_ascii_lowercase();
            let ftitle = text(f, "title").trim();
            let fval = &f["value"];

            if let Some(totp) = fval.get("totp").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                if !push_field_once(&mut entry, "totp", totp)? {
                    push_custom_safe(
                        &mut entry,
                        if ftitle.is_empty() { "TOTP" } else { ftitle },
                        totp,
                    )?;
                } else if crate::crypto::totp::current_totp(totp).is_err() {
                    preview.warn("unsupportedTotp");
                }
                continue;
            }

            if let Some(ssh_obj) = fval.get("sshKey").and_then(Value::as_object) {
                if let Some(pk) = ssh_obj
                    .get("privateKey")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    push_field_once(&mut entry, "privateKey", pk)?;
                    entry.0.private_key_name = "imported-1password-key".into();
                }
                if let Some(meta) = ssh_obj.get("metadata").and_then(Value::as_object) {
                    for mk in ["publicKey", "fingerprint", "keyType"] {
                        if let Some(mv) = meta
                            .get(mk)
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                        {
                            push_custom_safe(&mut entry, mk, mv)?;
                        }
                    }
                }
                continue;
            }

            if kind == "identity"
                && let Some(addr) = fval.get("address").and_then(Value::as_object)
            {
                for (src, dst) in [
                    ("street", "address1"),
                    ("city", "city"),
                    ("state", "state"),
                    ("zip", "postalCode"),
                    ("country", "country"),
                ] {
                    if let Some(s) = addr
                        .get(src)
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        push_field_once(&mut entry, dst, s)?;
                    }
                }
                continue;
            }

            let Some(val_str) = extract_1pux_field_string(fval) else {
                continue;
            };

            let mut handled = false;
            match kind {
                "card" => {
                    if fid == "cardholder" {
                        handled = push_field_once(&mut entry, "cardholderName", &val_str)?;
                    } else if fid == "type" || fval.get("creditCardType").is_some() {
                        handled = push_field_once(&mut entry, "cardBrand", &val_str)?;
                    } else if fid == "ccnum" || fval.get("creditCardNumber").is_some() {
                        handled = push_field_once(&mut entry, "cardNumber", &val_str)?;
                    } else if fid == "cvv" {
                        handled = push_field_once(&mut entry, "cardSecurityCode", &val_str)?;
                    } else if (fid == "expiry" || fval.get("monthYear").is_some())
                        && val_str.len() == 6
                        && val_str.bytes().all(|b| b.is_ascii_digit())
                    {
                        let _ = push_field_once(&mut entry, "cardExpYear", &val_str[0..4])?;
                        let _ = push_field_once(&mut entry, "cardExpMonth", &val_str[4..6])?;
                        handled = true;
                    }
                }
                "identity" => {
                    let mapped = match fid.as_str() {
                        "firstname" => Some("firstName"),
                        "initial" => Some("middleName"),
                        "lastname" => Some("lastName"),
                        "company" => Some("company"),
                        "email" => Some("email"),
                        "defphone" | "cellphone" | "homephone" | "busphone" => Some("phone"),
                        "username" => Some("username"),
                        "ssn" => Some("nationalId"),
                        "passport" => Some("passportNumber"),
                        "driverlicense" => Some("licenseNumber"),
                        _ => None,
                    };
                    if let Some(dst) = mapped {
                        handled = push_field_once(&mut entry, dst, &val_str)?;
                    }
                }
                "api" => {
                    if matches!(
                        fid.as_str(),
                        "credential" | "token" | "api_key" | "apikey" | "secret"
                    ) || ftitle.eq_ignore_ascii_case("credential")
                    {
                        handled = push_field_once(&mut entry, "apiCredential", &val_str)?;
                    } else if fid == "username" {
                        handled = push_field_once(&mut entry, "username", &val_str)?;
                    } else if matches!(fid.as_str(), "hostname" | "url" | "endpoint")
                        && crate::passkey::origin(&val_str).is_ok()
                    {
                        entry.0.login_uris.push(login_uri(&val_str, "domain", preview));
                        handled = true;
                    }
                }
                "ssh" => {
                    if matches!(fid.as_str(), "url" | "hostname" | "server" | "host") {
                        if let Ok(parsed_url) = url::Url::parse(&val_str)
                            && let Some(host) = parsed_url.host_str()
                        {
                            push_public_once(&mut entry, "host", host);
                            if let Some(port) = parsed_url.port() {
                                push_public_once(&mut entry, "port", &port.to_string());
                            }
                            if !parsed_url.username().is_empty() {
                                let _ = push_field_once(&mut entry, "username", parsed_url.username())?;
                            }
                            handled = true;
                        } else if !val_str.trim().is_empty() {
                            push_public_once(&mut entry, "host", val_str.trim());
                            handled = true;
                        }
                    } else if fid == "port" && val_str.trim().parse::<u16>().is_ok() {
                        push_public_once(&mut entry, "port", val_str.trim());
                        handled = true;
                    } else if matches!(fid.as_str(), "username" | "user") {
                        handled = push_field_once(&mut entry, "username", &val_str)?;
                    } else if fid == "password" {
                        handled = push_field_once(&mut entry, "password", &val_str)?;
                    } else if fid == "passphrase" {
                        handled = push_field_once(&mut entry, "passphrase", &val_str)?;
                    } else if is_ssh_private_key_pem(&val_str) {
                        handled = push_field_once(&mut entry, "privateKey", &val_str)?;
                        if handled {
                            entry.0.private_key_name = "imported-1password-key".into();
                        }
                    }
                }
                _ => {
                    if matches!(fid.as_str(), "username" | "user") {
                        handled = push_field_once(&mut entry, "username", &val_str)?;
                    } else if fid == "password" {
                        handled = push_field_once(&mut entry, "password", &val_str)?;
                    }
                }
            }

            if !handled {
                let label = if !ftitle.is_empty() {
                    ftitle.to_owned()
                } else if !fid.is_empty() {
                    fid
                } else if !sec_title.is_empty() {
                    sec_title.to_owned()
                } else {
                    "Field".to_owned()
                };
                push_custom_safe(&mut entry, &label, &val_str)?;
            }
        }
    }

    for (k, v) in extra_login_fields {
        push_custom_safe(&mut entry, &k, &v)?;
    }

    if let Some(history) = details["passwordHistory"].as_array() {
        for prev in history.iter().take(20) {
            let pw = text(prev, "value");
            if pw.is_empty() || pw.len() > 1_048_576 {
                continue;
            }
            let changed_at = prev["time"]
                .as_i64()
                .and_then(unix_to_rfc3339)
                .unwrap_or_else(|| entry.0.updated_at.clone());
            entry.1.password_history.push(PasswordHistoryEntry {
                password: pw.to_owned(),
                changed_at,
            });
        }
        if history.len() > 20 {
            preview.warn("passwordHistory");
        }
    }

    if details["documentAttributes"].is_object()
        || details["sections"].as_array().is_some_and(|secs| {
            secs.iter().any(|s| {
                s["fields"]
                    .as_array()
                    .is_some_and(|fs| fs.iter().any(|f| f["value"]["file"].is_object()))
            })
        })
    {
        preview.warn("attachments");
    }

    finish(&mut entry)?;
    Ok(entry)
}

// ---------------------------------------------------------------------------
// 3. KeePass .kdbx (KDBX 3.1 / 4.x / KDB) & KeePass 2.x XML (quick-xml)
// ---------------------------------------------------------------------------

/// Pre-validates KDBX 3 / KDBX 4 outer header KDF cost parameters BEFORE calling into
/// `keepass::Database::parse`, rejecting crafted KDF bombs with a clear cost error.
pub fn validate_kdbx_header_cost(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 12 || bytes[0..4] != KDBX_SIG_1 {
        return Ok(());
    }
    if bytes[4..8] == KDBX_SIG_2_KDB {
        // KDB 1.x header: rounds at bytes 120..124 (u32 LE) if present
        if bytes.len() >= 124 {
            let rounds = u32::from_le_bytes(bytes[120..124].try_into().unwrap()) as u64;
            ensure!(
                rounds <= MAX_KDBX_AES_ROUNDS,
                "Unsupported KDF cost: KeePass KDB rounds ({rounds}) exceeds safe local limit"
            );
        }
        return Ok(());
    }
    if bytes[4..8] != KDBX_SIG_2_V34 {
        return Ok(());
    }
    let major = u16::from_le_bytes([bytes[10], bytes[11]]);
    let mut pos = 12usize;
    let mut fields_seen = 0usize;

    match major {
        3 => {
            while pos + 3 <= bytes.len() && fields_seen < 64 {
                fields_seen += 1;
                let id = bytes[pos];
                let len = u16::from_le_bytes([bytes[pos + 1], bytes[pos + 2]]) as usize;
                pos += 3;
                if pos.checked_add(len).is_none_or(|end| end > bytes.len()) {
                    bail!("Truncated KDBX 3 header");
                }
                let data = &bytes[pos..pos + len];
                pos += len;
                if id == 6 && data.len() == 8 {
                    let rounds = u64::from_le_bytes(data.try_into().unwrap());
                    ensure!(
                        rounds <= MAX_KDBX_AES_ROUNDS,
                        "Unsupported KDF cost: KDBX 3 AES rounds ({rounds}) exceeds safe local limit"
                    );
                }
                if id == 0 {
                    break;
                }
            }
        }
        4 => {
            while pos + 5 <= bytes.len() && fields_seen < 64 {
                fields_seen += 1;
                let id = bytes[pos];
                let len = u32::from_le_bytes(bytes[pos + 1..pos + 5].try_into().unwrap()) as usize;
                pos += 5;
                if pos.checked_add(len).is_none_or(|end| end > bytes.len()) {
                    bail!("Truncated KDBX 4 header");
                }
                let data = &bytes[pos..pos + len];
                pos += len;
                if id == 11 {
                    validate_kdbx4_kdf_variant_dict(data)?;
                }
                if id == 0 {
                    break;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_kdbx4_kdf_variant_dict(data: &[u8]) -> Result<()> {
    if data.len() < 2 {
        bail!("Invalid KDBX 4 KDF parameters");
    }
    let mut pos = 2usize; // skip u16 version
    let mut mem_bytes: Option<u64> = None;
    let mut iters: Option<u64> = None;
    let mut parallelism: Option<u32> = None;
    let mut aes_rounds: Option<u64> = None;
    let mut entries = 0usize;

    while pos < data.len() && entries < 64 {
        entries += 1;
        let vtype = data[pos];
        pos += 1;
        if vtype == 0 {
            break;
        }
        ensure!(pos + 4 <= data.len(), "Truncated KDBX 4 KDF dictionary key");
        let klen = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        ensure!(
            pos.checked_add(klen).is_some_and(|end| end <= data.len()),
            "Truncated KDBX 4 KDF dictionary key"
        );
        let key = std::str::from_utf8(&data[pos..pos + klen]).unwrap_or_default();
        pos += klen;

        ensure!(pos + 4 <= data.len(), "Truncated KDBX 4 KDF dictionary value");
        let vlen = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        ensure!(
            pos.checked_add(vlen).is_some_and(|end| end <= data.len()),
            "Truncated KDBX 4 KDF dictionary value"
        );
        let val = &data[pos..pos + vlen];
        pos += vlen;

        match (key, vtype, val.len()) {
            ("M", 0x05 | 0x0D, 8) => mem_bytes = Some(u64::from_le_bytes(val.try_into().unwrap())),
            ("I", 0x05 | 0x0D, 8) => iters = Some(u64::from_le_bytes(val.try_into().unwrap())),
            ("P", 0x04 | 0x0C, 4) => {
                parallelism = Some(u32::from_le_bytes(val.try_into().unwrap()));
            }
            ("R", 0x05 | 0x0D, 8) => aes_rounds = Some(u64::from_le_bytes(val.try_into().unwrap())),
            _ => {}
        }
    }

    if let Some(m) = mem_bytes {
        let max_mem_bytes = MAX_BW_ARGON2_MEM_MIB * 1024 * 1024;
        ensure!(
            m <= max_mem_bytes,
            "Unsupported KDF cost: KeePass Argon2 memory ({} MiB) exceeds {} MiB safe limit",
            m / (1024 * 1024),
            MAX_BW_ARGON2_MEM_MIB
        );
    }
    if let Some(i) = iters {
        ensure!(
            i <= 256,
            "Unsupported KDF cost: KeePass Argon2 iterations ({i}) exceeds safe limit (256)"
        );
        if let Some(m) = mem_bytes {
            let m_mib = (m / (1024 * 1024)).max(1);
            ensure!(
                m_mib.saturating_mul(i) <= MAX_ARGON2_WORK_MIB_PASSES,
                "Unsupported KDF cost: KeePass Argon2 work ({m_mib} MiB × {i} passes) exceeds safe limit"
            );
        }
    }
    if let Some(p) = parallelism {
        ensure!(
            p <= 16,
            "Unsupported KDF cost: KeePass Argon2 parallelism ({p}) exceeds safe limit (16)"
        );
    }
    if let Some(r) = aes_rounds {
        ensure!(
            r <= MAX_KDBX_AES_ROUNDS,
            "Unsupported KDF cost: KeePass AES-KDF rounds ({r}) exceeds safe limit"
        );
    }
    Ok(())
}

pub fn parse_keepass_kdbx(bytes: &[u8], password: &str) -> Result<Parsed> {
    ensure!(bytes.len() as u64 <= MAX_BYTES, "Import file exceeds 64 MiB");
    if is_unsupported_kdbx2_bytes(bytes) {
        bail!("Unsupported KeePass 2.x pre-release format; export as KDBX 3.1/4.x or XML");
    }
    ensure!(is_kdbx_bytes(bytes), "Invalid KeePass .kdbx database header");
    ensure!(
        !password.is_empty() && password.len() <= 4096,
        "Enter the KeePass master password"
    );
    validate_kdbx_header_cost(bytes)?;

    let key = keepass::DatabaseKey::new().with_password(password);
    let db = keepass::Database::parse(bytes, key).map_err(|err| {
        let msg = err.to_string();
        let lower = msg.to_ascii_lowercase();
        if lower.contains("key")
            || lower.contains("hmac")
            || lower.contains("decrypt")
            || lower.contains("padding")
            || lower.contains("hash")
            || lower.contains("mac")
        {
            anyhow::anyhow!(
                "Incorrect KeePass master password. Note: password-only databases are supported; databases requiring a key file or hardware challenge-response must be exported as KeePass XML or re-saved with password-only protection."
            )
        } else {
            anyhow::anyhow!("Unable to open KeePass database: {msg}")
        }
    })?;

    // Only skip the configured Recycle Bin UUID when recycle bin is not explicitly disabled.
    let recycle_bin_id = if db.meta.recyclebin_enabled == Some(false) {
        None
    } else {
        db.recycle_bin().map(|g| g.id())
    };
    let mut preview = Preview::default();
    let mut entries = Vec::new();

    // Depth-bounded iterative group traversal using GroupId (immune to stack overflow).
    let mut stack: Vec<(keepass::db::GroupId, Vec<String>, bool)> =
        vec![(db.root().id(), Vec::new(), true)];
    while let Some((group_id, path_segments, is_root)) = stack.pop() {
        let Some(group) = db.group(group_id) else {
            continue;
        };
        if !is_root && recycle_bin_id.is_some_and(|id| id == group.id()) {
            preview.skipped_deleted += count_group_entries_iterative(&db, group_id);
            continue;
        }
        ensure!(
            path_segments.len() <= MAX_GROUP_DEPTH,
            "KeePass group nesting exceeds maximum depth ({MAX_GROUP_DEPTH})"
        );
        let next_segments = if is_root {
            path_segments
        } else {
            let mut segs = path_segments;
            let clean = group.name.trim();
            if !clean.is_empty() {
                segs.push(clean.to_owned());
            }
            segs
        };
        let folder = clamp_chars(&next_segments.join(" / "), 120);
        for entry_ref in group.entries() {
            ensure!(entries.len() < 50_000, "Import contains more than 50,000 items");
            if let Some(converted) = convert_keepass_entry(&entry_ref, &folder, &mut preview)? {
                entries.push(converted);
            }
        }
        let child_ids: Vec<keepass::db::GroupId> = group.group_ids().collect();
        for cid in child_ids.into_iter().rev() {
            stack.push((cid, next_segments.clone(), false));
        }
    }

    super::finalize_parsed(entries, preview)
}

fn count_group_entries_iterative(db: &keepass::Database, root_id: keepass::db::GroupId) -> usize {
    let mut total = 0usize;
    let mut stack = vec![(root_id, 0usize)];
    while let Some((gid, depth)) = stack.pop() {
        let Some(g) = db.group(gid) else {
            continue;
        };
        total += g.entries().count();
        if depth < MAX_GROUP_DEPTH {
            for cid in g.group_ids() {
                stack.push((cid, depth + 1));
            }
        }
    }
    total
}

fn is_ssh_private_key_pem(value: &str) -> bool {
    (value.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
        || value.contains("-----BEGIN RSA PRIVATE KEY-----")
        || value.contains("-----BEGIN EC PRIVATE KEY-----")
        || value.contains("-----BEGIN ED25519 PRIVATE KEY-----"))
        && value.contains("PRIVATE KEY-----")
}

fn extract_keepass_totp(entry: &keepass::db::Entry) -> Option<String> {
    for key in ["otp", "OTP", "TOTP", "totp", "TOTP Seed"] {
        if let Some(v) = entry.get(key).map(str::trim).filter(|s| !s.is_empty()) {
            return Some(v.to_owned());
        }
    }
    if let Some(secret) = entry
        .get("TimeOtp-Secret-Base32")
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let period = entry
            .get("TimeOtp-Period")
            .and_then(|s| s.trim().parse::<u32>().ok())
            .filter(|&p| p > 0)
            .unwrap_or(30);
        let digits = entry
            .get("TimeOtp-Length")
            .and_then(|s| s.trim().parse::<u32>().ok())
            .filter(|&d| matches!(d, 6 | 7 | 8))
            .unwrap_or(6);
        let algo = match entry.get("TimeOtp-Algorithm").map(str::trim) {
            Some("HMAC-SHA-256") => "SHA256",
            Some("HMAC-SHA-512") => "SHA512",
            _ => "SHA1",
        };
        if period == 30 && digits == 6 && algo == "SHA1" {
            return Some(secret.to_owned());
        }
        return Some(format!(
            "otpauth://totp/KeePass?secret={secret}&algorithm={algo}&digits={digits}&period={period}"
        ));
    }
    None
}

fn convert_keepass_entry(
    kp: &keepass::db::EntryRef<'_>,
    folder: &str,
    preview: &mut Preview,
) -> Result<Option<Entry>> {
    let title_raw = kp.get("Title").unwrap_or_default().trim();
    let username = kp.get("UserName").unwrap_or_default();
    let password = kp.get("Password").unwrap_or_default();
    let url = kp.get("URL").unwrap_or_default().trim();
    let notes = kp.get("Notes").unwrap_or_default();
    let totp = extract_keepass_totp(kp);

    let lower_url = url.to_ascii_lowercase();
    let is_ssh_url = lower_url.starts_with("ssh://");
    let is_web_url = lower_url.starts_with("http://") || lower_url.starts_with("https://");

    let mut ssh_private_key_pem: Option<String> = None;
    if !is_web_url {
        if is_ssh_private_key_pem(notes) {
            ssh_private_key_pem = Some(notes.to_owned());
        } else {
            for (_, v) in &kp.fields {
                let s = v.as_str();
                if is_ssh_private_key_pem(s) {
                    ssh_private_key_pem = Some(s.to_owned());
                    break;
                }
            }
        }
    }

    let has_any_custom = kp.fields.iter().any(|(k, v)| {
        !v.as_str().is_empty()
            && !matches!(
                k.as_str(),
                "Title"
                    | "UserName"
                    | "Password"
                    | "URL"
                    | "Notes"
                    | "otp"
                    | "OTP"
                    | "TOTP"
                    | "totp"
                    | "TOTP Seed"
                    | "TimeOtp-Secret-Base32"
                    | "TimeOtp-Period"
                    | "TimeOtp-Length"
                    | "TimeOtp-Algorithm"
            )
    });

    if title_raw.is_empty()
        && username.is_empty()
        && password.is_empty()
        && url.is_empty()
        && notes.is_empty()
        && totp.is_none()
        && !has_any_custom
    {
        return Ok(None);
    }

    let is_ssh = is_ssh_url || ssh_private_key_pem.is_some();
    let is_note_only = !is_ssh
        && username.is_empty()
        && password.is_empty()
        && url.is_empty()
        && totp.is_none()
        && !notes.is_empty();
    let kind = if is_ssh {
        "ssh"
    } else if is_note_only {
        "secureNote"
    } else {
        "login"
    };

    let parsed_ssh_url = if is_ssh_url {
        url::Url::parse(url).ok()
    } else {
        None
    };

    let fallback_name = crate::passkey::origin(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .or_else(|| {
            parsed_ssh_url
                .as_ref()
                .and_then(|u| u.host_str().map(str::to_owned))
        })
        .or_else(|| (!username.trim().is_empty()).then(|| username.trim().to_owned()))
        .unwrap_or_else(|| "KeePass entry".to_owned());
    let name = clamp_chars(
        if title_raw.is_empty() {
            &fallback_name
        } else {
            title_raw
        },
        80,
    );

    let mut entry = blank(kind, &name)?;
    if !folder.is_empty() {
        entry.0.folder = folder.to_owned();
    }
    if let Some(created) = kp.times.creation {
        entry.0.created_at = created.and_utc().to_rfc3339();
    }
    if let Some(modified) = kp.times.last_modification {
        entry.0.updated_at = modified.and_utc().to_rfc3339();
    }

    let mut ssh_url_username: Option<String> = None;
    if is_ssh {
        if let Some(ref parsed) = parsed_ssh_url {
            if let Some(host) = parsed.host_str().filter(|h| !h.is_empty()) {
                push_public_once(&mut entry, "host", host);
            }
            if let Some(port) = parsed.port() {
                push_public_once(&mut entry, "port", &port.to_string());
            }
            if !parsed.username().is_empty() {
                ssh_url_username = Some(parsed.username().to_owned());
            }
        } else if !url.is_empty() {
            entry.0.login_uris.push(login_uri(url, "never", preview));
        }
        if let Some(pem) = ssh_private_key_pem.as_deref() {
            push_field_once(&mut entry, "privateKey", pem)?;
            entry.0.private_key_name = "imported-keepass-key".into();
        }
    } else if !url.is_empty() {
        entry.0.login_uris.push(login_uri(url, "domain", preview));
    }

    let effective_user = if !username.is_empty() {
        username
    } else {
        ssh_url_username.as_deref().unwrap_or_default()
    };
    push_field_once(&mut entry, "username", effective_user)?;
    push_field_once(&mut entry, "password", password)?;
    if let Some(ref otp) = totp {
        push_field_once(&mut entry, "totp", otp)?;
        if crate::crypto::totp::current_totp(otp).is_err() {
            preview.warn("unsupportedTotp");
        }
    }
    if !notes.is_empty() && ssh_private_key_pem.as_deref() != Some(notes) {
        push_field_once(&mut entry, "secureNote", notes)?;
    }

    let mut extra_keys: Vec<&String> = kp.fields.keys().collect();
    extra_keys.sort();
    for k in extra_keys {
        if matches!(
            k.as_str(),
            "Title"
                | "UserName"
                | "Password"
                | "URL"
                | "Notes"
                | "otp"
                | "OTP"
                | "TOTP"
                | "totp"
                | "TOTP Seed"
                | "TimeOtp-Secret-Base32"
                | "TimeOtp-Period"
                | "TimeOtp-Length"
                | "TimeOtp-Algorithm"
        ) {
            continue;
        }
        let val = kp.fields[k].as_str();
        if val.is_empty() || ssh_private_key_pem.as_deref() == Some(val) {
            continue;
        }
        push_custom_safe(&mut entry, k, val)?;
    }

    if let Some(history) = &kp.history {
        let mut seen_pw: HashSet<String> = HashSet::new();
        if !password.is_empty() {
            seen_pw.insert(password.to_owned());
        }
        let mut total_hist = 0usize;
        for hist_entry in history.get_entries() {
            let Some(prev_pw) = hist_entry.get("Password").filter(|s| !s.is_empty()) else {
                continue;
            };
            if prev_pw.len() > 1_048_576 || !seen_pw.insert(prev_pw.to_owned()) {
                continue;
            }
            total_hist += 1;
            if entry.1.password_history.len() < 20 {
                let changed_at = hist_entry
                    .times
                    .last_modification
                    .map(|dt| dt.and_utc().to_rfc3339())
                    .unwrap_or_else(|| entry.0.updated_at.clone());
                entry.1.password_history.push(PasswordHistoryEntry {
                    password: prev_pw.to_owned(),
                    changed_at,
                });
            }
        }
        if total_hist > 20 {
            preview.warn("passwordHistory");
        }
    }

    if kp.attachments().next().is_some() {
        preview.warn("attachments");
    }

    finish(&mut entry)?;
    Ok(Some(entry))
}

fn resolve_xml_general_ref(name: &str) -> Result<String> {
    match name {
        "amp" => Ok("&".into()),
        "lt" => Ok("<".into()),
        "gt" => Ok(">".into()),
        "quot" => Ok("\"".into()),
        "apos" => Ok("'".into()),
        _ if name.starts_with("#x") || name.starts_with("#X") => {
            let code = u32::from_str_radix(&name[2..], 16)
                .map_err(|_| anyhow::anyhow!("Invalid hex XML character reference &{name};"))?;
            ensure!(code != 0, "NUL XML character reference is not allowed");
            let ch = char::from_u32(code)
                .ok_or_else(|| anyhow::anyhow!("Invalid Unicode codepoint &{name};"))?;
            Ok(ch.to_string())
        }
        _ if name.starts_with('#') => {
            let code = name[1..]
                .parse::<u32>()
                .map_err(|_| anyhow::anyhow!("Invalid decimal XML character reference &{name};"))?;
            ensure!(code != 0, "NUL XML character reference is not allowed");
            let ch = char::from_u32(code)
                .ok_or_else(|| anyhow::anyhow!("Invalid Unicode codepoint &{name};"))?;
            Ok(ch.to_string())
        }
        _ => bail!("Unsupported custom XML entity &{name}; in KeePass XML"),
    }
}

/// Streaming, depth-bounded `quick-xml` parser for KeePass 2.x plain XML exports.
/// Correctly decodes all standard entities, numeric character references (`&#...;`, `&#x...;`),
/// and CDATA, preserves `<Group>` folder paths, skips `<History>`, and rejects encrypted
/// `<Value Protected="True">` elements instead of importing ciphertext as plaintext.
pub fn parse_keepass_xml(bytes: &[u8], preview: &mut Preview) -> Result<Vec<Entry>> {
    ensure!(bytes.len() as u64 <= MAX_BYTES, "Import file exceeds 64 MiB");
    if is_unsupported_kdbx2_bytes(bytes) {
        bail!("Unsupported KeePass 2.x pre-release format; export as KDBX 3.1/4.x or XML");
    }
    if is_kdbx_bytes(bytes) {
        bail!("This KeePass .kdbx database is password-protected; unlock it with your master password.");
    }
    let stripped = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let xml = std::str::from_utf8(stripped).context("KeePass XML must be valid UTF-8")?;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut depth = 0usize;
    let mut saw_keepass_root = false;
    let mut history_depth = 0usize;
    let mut group_names: Vec<String> = Vec::new();
    let mut in_group_name = false;
    let mut group_name_buf = String::new();

    let mut in_entry = false;
    let mut entry_fields: Vec<(String, String)> = Vec::new();
    let mut in_string = false;
    let mut in_key = false;
    let mut in_value = false;
    let mut value_protected = false;
    let mut cur_key = String::new();
    let mut cur_val = String::new();
    let mut entries: Vec<Entry> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                depth += 1;
                ensure!(depth <= MAX_XML_DEPTH, "KeePass XML exceeds maximum nesting depth");
                let tag = e.name();
                let name = tag.as_ref();
                if name == "KeePassFile" {
                    saw_keepass_root = true;
                } else if name == "History" {
                    history_depth += 1;
                } else if history_depth == 0 {
                    match name {
                        "Group" => {
                            group_names.push(String::new());
                        }
                        "Name" if !group_names.is_empty() && !in_entry => {
                            in_group_name = true;
                            group_name_buf.clear();
                        }
                        "Entry" => {
                            in_entry = true;
                            entry_fields.clear();
                        }
                        "String" if in_entry => {
                            in_string = true;
                            cur_key.clear();
                            cur_val.clear();
                            value_protected = false;
                        }
                        "Key" if in_string => {
                            in_key = true;
                            cur_key.clear();
                        }
                        "Value" if in_string => {
                            in_value = true;
                            cur_val.clear();
                            value_protected = false;
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref().eq_ignore_ascii_case("Protected")
                                    && attr.value.as_ref().eq_ignore_ascii_case("True")
                                {
                                    value_protected = true;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                if e.name().as_ref() == "KeePassFile" {
                    saw_keepass_root = true;
                }
            }
            Ok(Event::Text(t)) => {
                if history_depth == 0 {
                    let s = t.as_ref();
                    if in_group_name {
                        ensure!(group_name_buf.len() + s.len() <= 4096, "KeePass group name too long");
                        group_name_buf.push_str(s);
                    } else if in_key {
                        ensure!(cur_key.len() + s.len() <= 4096, "KeePass XML field key too long");
                        cur_key.push_str(s);
                    } else if in_value {
                        ensure!(cur_val.len() + s.len() <= 1_048_576, "KeePass XML field exceeds 1 MiB");
                        cur_val.push_str(s);
                    }
                }
            }
            Ok(Event::CData(c)) => {
                if history_depth == 0 {
                    let s = c.as_ref();
                    if in_group_name {
                        ensure!(group_name_buf.len() + s.len() <= 4096, "KeePass group name too long");
                        group_name_buf.push_str(s);
                    } else if in_key {
                        ensure!(cur_key.len() + s.len() <= 4096, "KeePass XML field key too long");
                        cur_key.push_str(s);
                    } else if in_value {
                        ensure!(cur_val.len() + s.len() <= 1_048_576, "KeePass XML field exceeds 1 MiB");
                        cur_val.push_str(s);
                    }
                }
            }
            Ok(Event::GeneralRef(r)) => {
                if history_depth == 0 && (in_group_name || in_key || in_value) {
                    let resolved = resolve_xml_general_ref(r.as_ref())?;
                    if in_group_name {
                        group_name_buf.push_str(&resolved);
                    } else if in_key {
                        cur_key.push_str(&resolved);
                    } else if in_value {
                        ensure!(
                            cur_val.len() + resolved.len() <= 1_048_576,
                            "KeePass XML field exceeds 1 MiB"
                        );
                        cur_val.push_str(&resolved);
                    }
                }
            }
            Ok(Event::End(e)) => {
                depth = depth.saturating_sub(1);
                let tag = e.name();
                let name = tag.as_ref();
                if name == "History" {
                    history_depth = history_depth.saturating_sub(1);
                } else if history_depth == 0 {
                    match name {
                        "Name" if in_group_name => {
                            in_group_name = false;
                            if let Some(last) = group_names.last_mut() {
                                *last = group_name_buf.trim().to_owned();
                            }
                        }
                        "Key" if in_key => {
                            in_key = false;
                        }
                        "Value" if in_value => {
                            in_value = false;
                            if value_protected && !cur_val.trim().is_empty() {
                                bail!(
                                    "KeePass XML contains encrypted Protected values; export unencrypted KeePass 2.x XML or import the .kdbx database directly"
                                );
                            }
                        }
                        "String" if in_string => {
                            in_string = false;
                            let k = cur_key.trim().to_owned();
                            if !k.is_empty() && !cur_val.is_empty() {
                                entry_fields.push((k, std::mem::take(&mut cur_val)));
                            }
                            cur_key.clear();
                            cur_val.clear();
                        }
                        "Entry" if in_entry => {
                            in_entry = false;
                            ensure!(entries.len() < 50_000, "Import contains more than 50,000 items");
                            // Skip top-level root group name (index 0) for folder path
                            let folder_parts: Vec<&str> = group_names
                                .iter()
                                .skip(1)
                                .map(String::as_str)
                                .filter(|s| !s.is_empty())
                                .collect();
                            let folder = clamp_chars(&folder_parts.join(" / "), 120);
                            if let Some(entry) =
                                build_entry_from_keepass_xml_fields(&entry_fields, &folder, preview)?
                            {
                                entries.push(entry);
                            }
                            entry_fields.clear();
                        }
                        "Group" => {
                            group_names.pop();
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(err) => bail!("Invalid KeePass XML: {err}"),
            _ => {}
        }
    }

    ensure!(
        saw_keepass_root || !entries.is_empty(),
        "File is not a valid KeePass XML export or .kdbx database"
    );
    Ok(entries)
}

fn build_entry_from_keepass_xml_fields(
    fields: &[(String, String)],
    folder: &str,
    preview: &mut Preview,
) -> Result<Option<Entry>> {
    let mut title = String::new();
    let mut user = String::new();
    let mut pass = String::new();
    let mut url = String::new();
    let mut totp = String::new();
    let mut notes = String::new();
    let mut extras: Vec<(&str, &str)> = Vec::new();

    for (k, v) in fields {
        match k.to_ascii_lowercase().as_str() {
            "title" => title = v.clone(),
            "username" => user = v.clone(),
            "password" => pass = v.clone(),
            "url" => url = v.trim().to_owned(),
            "otp" | "totp" | "totp seed" | "timeotp-secret-base32" => {
                if totp.is_empty() {
                    totp = v.trim().to_owned();
                }
            }
            "notes" => notes = v.clone(),
            _ => extras.push((k.as_str(), v.as_str())),
        }
    }
    if title.is_empty()
        && user.is_empty()
        && pass.is_empty()
        && url.is_empty()
        && notes.is_empty()
        && totp.is_empty()
        && extras.is_empty()
    {
        return Ok(None);
    }

    let fallback = crate::passkey::origin(&url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .or_else(|| (!user.is_empty()).then(|| user.clone()))
        .unwrap_or_else(|| "KeePass entry".to_owned());
    let name = clamp_chars(if title.trim().is_empty() { &fallback } else { &title }, 80);
    let kind = if user.is_empty()
        && pass.is_empty()
        && url.is_empty()
        && totp.is_empty()
        && !notes.is_empty()
    {
        "secureNote"
    } else {
        "login"
    };
    let mut entry = blank(kind, &name)?;
    if !folder.is_empty() {
        entry.0.folder = folder.to_owned();
    }
    if !url.is_empty() {
        entry.0.login_uris.push(login_uri(&url, "domain", preview));
    }
    push_field_once(&mut entry, "username", &user)?;
    push_field_once(&mut entry, "password", &pass)?;
    if !totp.is_empty() {
        push_field_once(&mut entry, "totp", &totp)?;
        if crate::crypto::totp::current_totp(&totp).is_err() {
            preview.warn("unsupportedTotp");
        }
    }
    push_field_once(&mut entry, "secureNote", &notes)?;
    for (ek, ev) in extras {
        push_custom_safe(&mut entry, ek, ev)?;
    }
    finish(&mut entry)?;
    Ok(Some(entry))
}

pub fn parse_package_with_password(
    bytes: &[u8],
    kind: VaultPackageKind,
    password: &str,
) -> Result<Parsed> {
    match kind {
        VaultPackageKind::BitwardenEncrypted => parse_bitwarden_encrypted(bytes, password),
        VaultPackageKind::KeepassKdbx => parse_keepass_kdbx(bytes, password),
        VaultPackageKind::Mvault => {
            bail!("Use backup::prepare_import_bytes_with_password for .mvault files")
        }
    }
}

pub fn parse_with_password(bytes: &[u8], format: &str, password: &str) -> Result<Parsed> {
    match format {
        "bitwarden" | "bitwarden_encrypted" => {
            if is_bitwarden_encrypted_json_bytes(bytes) {
                parse_bitwarden_encrypted(bytes, password)
            } else {
                super::parse(bytes, "bitwarden")
            }
        }
        "keepass" | "keepass_kdbx" => {
            if is_kdbx_bytes(bytes) || is_unsupported_kdbx2_bytes(bytes) {
                parse_keepass_kdbx(bytes, password)
            } else {
                super::parse(bytes, "keepass")
            }
        }
        other => super::parse(bytes, other),
    }
}

pub fn read_with_password(path: &Path, format: &str, password: &str) -> Result<Parsed> {
    let bytes = read_bounded_regular_file(path, MAX_BYTES)?;
    parse_with_password(&bytes, format, password)
}

#[cfg(test)]
pub(super) mod test_helpers {
    use super::*;
    use cbc::cipher::BlockEncryptMut;
    use serde_json::json;

    fn encrypt_bw_string(
        plain: &[u8],
        enc_key: &[u8; 32],
        mac_key: &[u8; 32],
        iv: [u8; 16],
    ) -> String {
        let encryptor = cbc::Encryptor::<Aes256>::new_from_slices(enc_key, &iv).unwrap();
        let ct = encryptor.encrypt_padded_vec_mut::<Pkcs7>(plain);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key).unwrap();
        mac.update(&iv);
        mac.update(&ct);
        let tag = mac.finalize().into_bytes();
        format!(
            "2.{}|{}|{}",
            STANDARD.encode(iv),
            STANDARD.encode(ct),
            STANDARD.encode(tag)
        )
    }

    pub fn make_bitwarden_encrypted_pbkdf2(inner_json: &Value, password: &str) -> Vec<u8> {
        let salt = "test-bitwarden-salt-pbkdf2@example.com";
        let iterations: u32 = 10_000;
        let mut master_key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(iterations).unwrap(),
            salt.as_bytes(),
            password.as_bytes(),
            &mut master_key,
        );
        let enc_key = bitwarden_hkdf_expand_32(&master_key, b"enc");
        let mac_key = bitwarden_hkdf_expand_32(&master_key, b"mac");
        let validation = encrypt_bw_string(
            b"00000000-1111-2222-3333-444444444444",
            &enc_key,
            &mac_key,
            [0x11; 16],
        );
        let payload = encrypt_bw_string(
            &serde_json::to_vec(inner_json).unwrap(),
            &enc_key,
            &mac_key,
            [0x22; 16],
        );
        serde_json::to_vec(&json!({
            "encrypted": true,
            "passwordProtected": true,
            "salt": salt,
            "kdfIterations": iterations,
            "kdfType": 0,
            "encKeyValidation_MAC": validation,
            "data": payload
        }))
        .unwrap()
    }

    pub fn make_bitwarden_encrypted_argon2id(inner_json: &Value, password: &str) -> Vec<u8> {
        let salt = "test-bitwarden-salt-argon2@example.com";
        let iterations: u32 = 2;
        let memory_mib: u32 = 16;
        let parallelism: u32 = 1;
        let params = Params::new(memory_mib * 1024, iterations, parallelism, Some(32)).unwrap();
        let salt_hash = Sha256::digest(salt.as_bytes());
        let mut master_key = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password.as_bytes(), &salt_hash, &mut master_key)
            .unwrap();
        let enc_key = bitwarden_hkdf_expand_32(&master_key, b"enc");
        let mac_key = bitwarden_hkdf_expand_32(&master_key, b"mac");
        let validation = encrypt_bw_string(
            b"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            &enc_key,
            &mac_key,
            [0x33; 16],
        );
        let payload = encrypt_bw_string(
            &serde_json::to_vec(inner_json).unwrap(),
            &enc_key,
            &mac_key,
            [0x44; 16],
        );
        serde_json::to_vec(&json!({
            "encrypted": true,
            "passwordProtected": true,
            "salt": salt,
            "kdfIterations": iterations,
            "kdfMemory": memory_mib,
            "kdfParallelism": parallelism,
            "kdfType": 1,
            "encKeyValidation_MAC": validation,
            "data": payload
        }))
        .unwrap()
    }
}
