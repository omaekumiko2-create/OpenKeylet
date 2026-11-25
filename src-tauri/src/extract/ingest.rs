//! Pure local smart-parsing and developer asset ingestion (.env, ~/.ssh/config).
//! Never sends data to any network or LLM.

use crate::{
    api_catalog,
    crypto::totp::current_totp,
    login_uri::LoginUri,
    migration::Preview,
    model::{
        ApiAuthHeader, ConnectionInput, ItemModule, PortableConnection, SecretBundle,
    },
    storage::resolve_user_path,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
};
use url::Url;
use uuid::Uuid;

const MAX_SMART_TEXT_BYTES: usize = 512 * 1024;
const MAX_SSH_KEY_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SmartParseResult {
    pub kind: String,
    pub label: String,
    pub label_zh: String,
    pub summary: String,
    pub input: ConnectionInput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_account: Option<String>,
    pub multi_entries: usize,
    pub warnings: Vec<String>,
}

pub fn default_ssh_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".ssh").join("config"))
}

pub fn smart_parse(
    raw: &str,
    hint_filename: Option<&str>,
    hint_url: Option<&str>,
) -> Result<SmartParseResult> {
    let trimmed = raw.trim_start_matches('\u{feff}').trim();
    ensure!(!trimmed.is_empty(), "Nothing to parse");
    ensure!(
        trimmed.len() <= MAX_SMART_TEXT_BYTES,
        "Input exceeds 512 KiB limit"
    );

    if let Some(parsed) = try_parse_totp(trimmed)? {
        return Ok(parsed);
    }
    if let Some(parsed) = try_parse_private_key(trimmed, hint_filename) {
        return Ok(parsed);
    }
    if let Some(parsed) = try_parse_curl(trimmed) {
        return Ok(parsed);
    }
    if let Some(parsed) = try_parse_ssh_command(trimmed) {
        return Ok(parsed);
    }
    if let Some(parsed) = try_parse_connection_uri(trimmed) {
        return Ok(parsed);
    }
    if let Some(parsed) = try_parse_ssh_config_snippet(trimmed) {
        return Ok(parsed);
    }
    if let Some(parsed) = try_parse_env_snippet(trimmed, hint_filename) {
        return Ok(parsed);
    }
    if let Some(parsed) = try_parse_server_info(trimmed) {
        return Ok(parsed);
    }
    if let Some(parsed) = try_parse_known_api_key(trimmed, hint_url) {
        return Ok(parsed);
    }
    if let Some(parsed) = try_parse_login_url(trimmed) {
        return Ok(parsed);
    }

    Ok(fallback_secure_note(trimmed, hint_filename, hint_url))
}

fn empty_input(item_type: &str, name: String) -> ConnectionInput {
    ConnectionInput {
        login_uris: Vec::new(),
        item_type: item_type.to_owned(),
        folder: String::new(),
        favorite: false,
        id: None,
        modules: Vec::new(),
        name: sanitize_name(&name, 80),
        enabled: true,
        description: String::new(),
        http_auth_type: String::new(),
        private_key_import_path: String::new(),
        auth_header: String::new(),
        auth_location: String::new(),
        auth_prefix: String::new(),
        api_auth_headers: Vec::new(),
        test_path: String::new(),
        remove_secret_names: Vec::new(),
        secrets: SecretBundle::default(),
    }
}

fn sanitize_name(raw: &str, max_chars: usize) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let truncated: String = collapsed.chars().take(max_chars).collect();
    if truncated.is_empty() {
        "Imported item".to_owned()
    } else {
        truncated
    }
}

fn public_module(kind: &str, value: impl Into<String>) -> ItemModule {
    ItemModule {
        kind: kind.to_owned(),
        name: kind.to_owned(),
        value: value.into(),
        agent_visible: Some(true),
    }
}

fn secret_module(kind: &str) -> ItemModule {
    ItemModule {
        kind: kind.to_owned(),
        name: kind.to_owned(),
        value: String::new(),
        agent_visible: Some(false),
    }
}

fn custom_secret_module(name: impl Into<String>) -> ItemModule {
    ItemModule {
        kind: "customSecret".to_owned(),
        name: name.into(),
        value: String::new(),
        agent_visible: Some(false),
    }
}

fn try_parse_totp(text: &str) -> Result<Option<SmartParseResult>> {
    let first_line = text.lines().next().unwrap_or("").trim();
    if !first_line.starts_with("otpauth://") {
        return Ok(None);
    }
    // Validate that it is a genuine RFC6238 TOTP URI.
    let _code = current_totp(first_line).context("Invalid otpauth:// TOTP URI")?;
    let url = Url::parse(first_line).context("Invalid TOTP URI")?;
    let raw_label = urlencoding_decode(url.path().trim_start_matches('/'));
    let query_issuer = url
        .query_pairs()
        .find(|(k, _)| k.eq_ignore_ascii_case("issuer"))
        .map(|(_, v)| v.trim().to_owned())
        .filter(|v| !v.is_empty());

    let (label_issuer, account) = if let Some((left, right)) = raw_label.split_once(':') {
        (
            Some(left.trim().to_owned()).filter(|v| !v.is_empty()),
            Some(right.trim().to_owned()).filter(|v| !v.is_empty()),
        )
    } else {
        (None, Some(raw_label.trim().to_owned()).filter(|v| !v.is_empty()))
    };
    let issuer = query_issuer.or(label_issuer);
    let display_name = match (&issuer, &account) {
        (Some(iss), Some(acc)) if !acc.eq_ignore_ascii_case(iss) => format!("{iss} ({acc})"),
        (Some(iss), _) => iss.clone(),
        (None, Some(acc)) => acc.clone(),
        (None, None) => "2FA TOTP".to_owned(),
    };

    let mut input = empty_input("login", display_name.clone());
    if let Some(acc) = &account {
        input.modules.push(secret_module("username"));
        input
            .secrets
            .named_secrets
            .insert("username".to_owned(), acc.clone());
    }
    input.modules.push(secret_module("totp"));
    input
        .secrets
        .named_secrets
        .insert("totp".to_owned(), first_line.to_owned());

    let summary = match (&issuer, &account) {
        (Some(iss), Some(acc)) => format!("2FA TOTP · {iss} · {acc}"),
        (Some(iss), None) => format!("2FA TOTP · {iss}"),
        (None, Some(acc)) => format!("2FA TOTP · {acc}"),
        (None, None) => "2FA TOTP".to_owned(),
    };

    Ok(Some(SmartParseResult {
        kind: "totp".to_owned(),
        label: "2FA TOTP".to_owned(),
        label_zh: "2FA 动态验证码".to_owned(),
        summary,
        input,
        totp_uri: Some(first_line.to_owned()),
        totp_issuer: issuer,
        totp_account: account,
        multi_entries: 1,
        warnings: Vec::new(),
    }))
}

fn urlencoding_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((h << 4) | l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn try_parse_private_key(text: &str, hint_filename: Option<&str>) -> Option<SmartParseResult> {
    let has_begin = text.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
        || text.contains("-----BEGIN RSA PRIVATE KEY-----")
        || text.contains("-----BEGIN EC PRIVATE KEY-----")
        || text.contains("-----BEGIN PRIVATE KEY-----")
        || text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        || text.contains("-----BEGIN DSA PRIVATE KEY-----");
    let has_end = text.contains("-----END ") && text.contains("PRIVATE KEY-----");
    if !has_begin || !has_end {
        return None;
    }

    let key_name = hint_filename
        .and_then(|name| Path::new(name).file_name().and_then(|s| s.to_str()))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("id_key")
        .to_owned();
    let stem = Path::new(&key_name)
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("SSH Key");

    let mut input = empty_input("ssh", format!("SSH · {stem}"));
    input.modules.push(public_module("host", ""));
    input.modules.push(public_module("port", "22"));
    input.modules.push(secret_module("username"));
    input.modules.push(secret_module("privateKey"));
    input.secrets.private_key = Some(text.to_owned());
    input.secrets.private_key_name = Some(key_name.clone());

    let mut warnings = Vec::new();
    if text.contains("ENCRYPTED") {
        input.modules.push(secret_module("passphrase"));
        warnings.push("Key appears encrypted; enter its passphrase before saving".to_owned());
    }

    Some(SmartParseResult {
        kind: "privateKey".to_owned(),
        label: "SSH Private Key".to_owned(),
        label_zh: "SSH 私钥".to_owned(),
        summary: format!("SSH Private Key · {key_name}"),
        input,
        totp_uri: None,
        totp_issuer: None,
        totp_account: None,
        multi_entries: 1,
        warnings,
    })
}

fn tokenize_shell(raw: &str) -> Vec<String> {
    // Collapse line continuations: Unix `\`, PowerShell `` ` ``, and Windows cmd.exe `^`
    let mut normalized = raw
        .replace("\\\r\n", " ")
        .replace("\\\n", " ")
        .replace("`\r\n", " ")
        .replace("`\n", " ")
        .replace("^\r\n", " ")
        .replace("^\n", " ");
    // Chrome DevTools "Copy as cURL (cmd)" uses caret-escaped quotes `^"` and symbols `^&`, `^%`, `^^`
    if normalized.contains("^\"") {
        normalized = normalized
            .replace("^\"", "\"")
            .replace("^&", "&")
            .replace("^%", "%")
            .replace("^^", "^");
    }
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for ch in normalized.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && !in_single {
            escaped = true;
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = !in_single;
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if ch.is_whitespace() && !in_single && !in_double {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(ch);
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn try_parse_curl(text: &str) -> Option<SmartParseResult> {
    let tokens = tokenize_shell(text);
    let first = tokens.first()?.to_ascii_lowercase();
    if first != "curl" && first != "curl.exe" {
        return None;
    }

    let mut url_str: Option<String> = None;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut basic_user_pass: Option<String> = None;
    let mut i = 1;
    while i < tokens.len() {
        let tok = &tokens[i];
        match tok.as_str() {
            "-H" | "--header" => {
                if let Some(val) = tokens.get(i + 1) {
                    if let Some((k, v)) = val.split_once(':') {
                        headers.push((k.trim().to_owned(), v.trim().to_owned()));
                    }
                    i += 2;
                    continue;
                }
            }
            "-u" | "--user" => {
                if let Some(val) = tokens.get(i + 1) {
                    basic_user_pass = Some(val.clone());
                    i += 2;
                    continue;
                }
            }
            "--url" => {
                if let Some(val) = tokens.get(i + 1) {
                    url_str = Some(val.clone());
                    i += 2;
                    continue;
                }
            }
            "-X" | "--request" | "-d" | "--data" | "--data-raw" | "--data-binary"
            | "--data-urlencode" | "-F" | "--form" | "-o" | "--output" | "-A"
            | "--user-agent" | "-b" | "--cookie" | "-e" | "--referer" | "--connect-timeout"
            | "-m" | "--max-time" => {
                i += 2;
                continue;
            }
            other if !other.starts_with('-') => {
                if url_str.is_none()
                    && (other.starts_with("http://")
                        || other.starts_with("https://")
                        || other.contains('.'))
                {
                    url_str = Some(other.to_owned());
                }
            }
            _ => {}
        }
        i += 1;
    }

    let raw_url = url_str?;
    let candidate_url = if raw_url.contains("://") {
        raw_url.clone()
    } else {
        format!("https://{raw_url}")
    };
    let mut parsed_url = Url::parse(&candidate_url).ok()?;
    let host = parsed_url.host_str()?.to_owned();

    // Check query params for API key
    let mut query_secret: Option<(String, String)> = None;
    let kept_query: Vec<(String, String)> = parsed_url
        .query_pairs()
        .filter_map(|(k, v)| {
            let lower = k.to_ascii_lowercase();
            if query_secret.is_none()
                && matches!(
                    lower.as_str(),
                    "key" | "api_key" | "apikey" | "token" | "access_token"
                )
                && !v.trim().is_empty()
            {
                query_secret = Some((k.into_owned(), v.into_owned()));
                None
            } else {
                Some((k.into_owned(), v.into_owned()))
            }
        })
        .collect();
    if query_secret.is_some() {
        parsed_url.query_pairs_mut().clear();
        for (k, v) in kept_query {
            parsed_url.query_pairs_mut().append_pair(&k, &v);
        }
    }

    let base_url = format!(
        "{}://{}{}{}",
        parsed_url.scheme(),
        host,
        parsed_url
            .port()
            .map(|p| format!(":{p}"))
            .unwrap_or_default(),
        {
            let p = parsed_url.path();
            if p.is_empty() { "/" } else { p }
        }
    );

    let mut primary_secret = String::new();
    let mut auth_header = String::new();
    let mut auth_prefix = String::new();
    let mut auth_location = "header".to_owned();
    let mut http_auth_type = "auto".to_owned();
    let mut extra_auth_headers: Vec<(String, String)> = Vec::new();

    for (name, val) in &headers {
        let lower = name.to_ascii_lowercase();
        let is_auth = lower == "authorization"
            || lower.contains("api-key")
            || lower.contains("apikey")
            || lower.contains("token")
            || lower.contains("secret")
            || lower == "x-auth-key";
        if !is_auth || val.is_empty() {
            continue;
        }
        if primary_secret.is_empty() {
            if lower == "authorization" {
                if let Some((scheme, rest)) = val.split_once(' ') {
                    let rest = rest.trim();
                    if scheme.eq_ignore_ascii_case("bearer") {
                        http_auth_type = "bearer".to_owned();
                        auth_header = "Authorization".to_owned();
                        auth_prefix = "Bearer".to_owned();
                        primary_secret = rest.to_owned();
                    } else if scheme.eq_ignore_ascii_case("basic") {
                        http_auth_type = "basic".to_owned();
                        auth_header = "Authorization".to_owned();
                        auth_prefix = "Basic".to_owned();
                        primary_secret = rest.to_owned();
                    } else {
                        http_auth_type = "apiKey".to_owned();
                        auth_header = name.clone();
                        auth_prefix = scheme.to_owned();
                        primary_secret = rest.to_owned();
                    }
                } else {
                    http_auth_type = "apiKey".to_owned();
                    auth_header = name.clone();
                    auth_prefix = String::new();
                    primary_secret = val.clone();
                }
            } else {
                http_auth_type = "apiKey".to_owned();
                auth_header = name.clone();
                auth_prefix = String::new();
                primary_secret = val.clone();
            }
        } else {
            extra_auth_headers.push((name.clone(), val.clone()));
        }
    }

    if primary_secret.is_empty()
        && let Some((qk, qv)) = query_secret
    {
        http_auth_type = "apiKey".to_owned();
        auth_header = qk;
        auth_location = "query".to_owned();
        auth_prefix = String::new();
        primary_secret = qv;
    }

    let profile = api_catalog::infer("", &base_url, &primary_secret);
    let item_name = if profile.display_name != "API" {
        format!("{} API", profile.display_name)
    } else {
        format!("{host} API")
    };

    let mut input = empty_input("api", item_name.clone());
    input.modules.push(public_module("url", base_url.clone()));

    if let Some(user_pass) = basic_user_pass {
        let (u, p) = user_pass.split_once(':').unwrap_or((&user_pass, ""));
        input.http_auth_type = "basic".to_owned();
        input.modules.push(secret_module("username"));
        input
            .secrets
            .named_secrets
            .insert("username".to_owned(), u.to_owned());
        if !p.is_empty() {
            input.modules.push(secret_module("password"));
            input.secrets.password = Some(p.to_owned());
        }
    } else {
        input.http_auth_type = http_auth_type;
        input.auth_header = auth_header;
        input.auth_location = auth_location;
        input.auth_prefix = auth_prefix;
        input.modules.push(secret_module("apiCredential"));
        if !primary_secret.is_empty() {
            input
                .secrets
                .named_secrets
                .insert("apiCredential".to_owned(), primary_secret);
        }
    }

    for (hdr_name, hdr_val) in extra_auth_headers {
        let before = input.modules.len();
        super::reconcile::push_vault_safe_secret_module(&mut input, &hdr_name, hdr_val);
        if let Some(added_mod) = input.modules.get(before)
            && let Some(secret_name) = added_mod.secret_name()
        {
            input.api_auth_headers.push(ApiAuthHeader {
                name: hdr_name,
                secret_name: secret_name.to_owned(),
            });
        }
    }

    Some(SmartParseResult {
        kind: "curl".to_owned(),
        label: "cURL API".to_owned(),
        label_zh: "cURL API 命令".to_owned(),
        summary: format!("{item_name} · {host}"),
        input,
        totp_uri: None,
        totp_issuer: None,
        totp_account: None,
        multi_entries: 1,
        warnings: Vec::new(),
    })
}

fn try_parse_ssh_command(text: &str) -> Option<SmartParseResult> {
    let first_line = text.lines().find(|l| !l.trim().is_empty())?.trim();
    // Support `ssh://user@host:port`
    if first_line.starts_with("ssh://") {
        let url = Url::parse(first_line).ok()?;
        let host = url.host_str()?.to_owned();
        let port = url.port().unwrap_or(22);
        let user = urlencoding_decode(url.username());
        let pass = url.password().map(urlencoding_decode);
        return Some(build_ssh_result(
            &host,
            port,
            (!user.is_empty()).then_some(user),
            pass,
            None,
            Vec::new(),
        ));
    }

    let tokens = tokenize_shell(first_line);
    let cmd = tokens.first()?.to_ascii_lowercase();
    if cmd != "ssh" && cmd != "ssh.exe" && cmd != "sftp" {
        return None;
    }

    let mut port: u16 = 22;
    let mut user: Option<String> = None;
    let mut key_path: Option<String> = None;
    let mut destination: Option<String> = None;
    let mut i = 1;
    while i < tokens.len() {
        let tok = &tokens[i];
        match tok.as_str() {
            "-p" => {
                if let Some(p) = tokens.get(i + 1).and_then(|v| v.parse::<u16>().ok()) {
                    port = p;
                }
                i += 2;
                continue;
            }
            "-l" => {
                if let Some(u) = tokens.get(i + 1) {
                    user = Some(u.clone());
                }
                i += 2;
                continue;
            }
            "-i" => {
                if let Some(k) = tokens.get(i + 1) {
                    key_path = Some(k.clone());
                }
                i += 2;
                continue;
            }
            "-o" | "-F" | "-J" | "-L" | "-R" | "-D" | "-W" | "-b" | "-c" | "-E" | "-I" | "-m"
            | "-O" | "-Q" | "-S" | "-w" => {
                i += 2;
                continue;
            }
            other if !other.starts_with('-') => {
                if destination.is_none() {
                    destination = Some(other.to_owned());
                }
            }
            _ => {}
        }
        i += 1;
    }

    let dest = destination?;
    let (parsed_user, host) = if let Some((u, h)) = dest.split_once('@') {
        (Some(u.to_owned()), h.to_owned())
    } else {
        (None, dest)
    };
    let final_user = user.or(parsed_user);
    if host.trim().is_empty() {
        return None;
    }

    let mut warnings = Vec::new();
    let loaded_key = key_path.as_deref().and_then(|raw_path| {
        match read_local_ssh_key(raw_path, None) {
            Ok(loaded) => Some(loaded),
            Err(err) => {
                warnings.push(format!("Could not read key file {raw_path}: {err}"));
                None
            }
        }
    });

    Some(build_ssh_result(
        &host,
        port,
        final_user,
        None,
        loaded_key,
        warnings,
    ))
}

fn build_ssh_result(
    host: &str,
    port: u16,
    user: Option<String>,
    password: Option<String>,
    private_key: Option<(String, String)>,
    warnings: Vec<String>,
) -> SmartParseResult {
    let label_target = match &user {
        Some(u) if !u.is_empty() => format!("{u}@{host}"),
        _ => host.to_owned(),
    };
    let mut input = empty_input("ssh", format!("SSH · {host}"));
    input.modules.push(public_module("host", host));
    input.modules.push(public_module("port", port.to_string()));
    input.modules.push(secret_module("username"));
    if let Some(u) = user
        && !u.is_empty()
    {
        input
            .secrets
            .named_secrets
            .insert("username".to_owned(), u);
    }
    if let Some((key_name, key_pem)) = private_key {
        input.modules.push(secret_module("privateKey"));
        input.secrets.private_key = Some(key_pem);
        input.secrets.private_key_name = Some(key_name);
    } else {
        input.modules.push(secret_module("password"));
        if let Some(p) = password
            && !p.is_empty()
        {
            input.secrets.password = Some(p);
        }
    }

    SmartParseResult {
        kind: "sshCommand".to_owned(),
        label: "SSH Server".to_owned(),
        label_zh: "SSH 服务器".to_owned(),
        summary: format!("SSH · {label_target}:{port}"),
        input,
        totp_uri: None,
        totp_issuer: None,
        totp_account: None,
        multi_entries: 1,
        warnings,
    }
}

fn read_local_ssh_key(raw_path: &str, base_dir: Option<&Path>) -> Result<(String, String)> {
    read_local_ssh_key_at(raw_path, base_dir).map(|(name, content, _)| (name, content))
}

fn read_local_ssh_key_at(raw_path: &str, base_dir: Option<&Path>) -> Result<(String, String, PathBuf)> {
    let trimmed = raw_path.trim().trim_matches('"').trim_matches('\'');
    let path = if trimmed.starts_with("~/") || trimmed.starts_with("~\\") {
        resolve_user_path(trimmed)?
    } else {
        let p = PathBuf::from(trimmed);
        if p.is_absolute() {
            p
        } else if let Some(base) = base_dir {
            base.join(p)
        } else {
            resolve_user_path(trimmed)?
        }
    };
    let meta = std::fs::metadata(&path).context("Key file not found")?;
    ensure!(meta.len() <= MAX_SSH_KEY_BYTES, "Key file exceeds 256 KiB");
    let content = std::fs::read_to_string(&path).context("Key file is not UTF-8 text")?;
    ensure!(
        content.contains("PRIVATE KEY-----"),
        "File does not appear to be a PEM/OpenSSH private key"
    );
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("id_key")
        .to_owned();
    Ok((name, content, path))
}

fn try_parse_connection_uri(text: &str) -> Option<SmartParseResult> {
    let first_line = text.lines().next()?.trim();
    if text.lines().filter(|l| !l.trim().is_empty()).count() > 1 {
        return None;
    }
    let url = Url::parse(first_line).ok()?;
    let (service_label, default_port) = match url.scheme().to_ascii_lowercase().as_str() {
        "postgres" | "postgresql" => ("PostgreSQL", 5432),
        "mysql" => ("MySQL", 3306),
        "mariadb" => ("MariaDB", 3306),
        "redis" | "rediss" => ("Redis", 6379),
        "mongodb" | "mongodb+srv" => ("MongoDB", 27017),
        "amqp" | "amqps" => ("RabbitMQ / AMQP", 5672),
        "mssql" | "sqlserver" => ("SQL Server", 1433),
        "clickhouse" => ("ClickHouse", 8123),
        "sftp" => ("SFTP", 22),
        "ftp" | "ftps" => ("FTP", 21),
        _ => return None,
    };
    let host = url.host_str()?.to_owned();
    let port = url.port().unwrap_or(default_port);
    let username = urlencoding_decode(url.username());
    let password = url.password().map(urlencoding_decode);
    let db_name = url.path().trim_start_matches('/').to_owned();

    let name = if db_name.is_empty() {
        format!("{service_label} · {host}")
    } else {
        format!("{service_label} · {db_name} ({host})")
    };
    let mut input = empty_input("custom", name.clone());
    input.description = format!("{service_label} connection");
    input.modules.push(public_module("host", host.clone()));
    input.modules.push(public_module("port", port.to_string()));
    if !username.is_empty() {
        input.modules.push(secret_module("username"));
        input
            .secrets
            .named_secrets
            .insert("username".to_owned(), username);
    }
    if let Some(pass) = password
        && !pass.is_empty()
    {
        input.modules.push(secret_module("password"));
        input.secrets.password = Some(pass);
    }
    if !db_name.is_empty() {
        input.modules.push(custom_secret_module("Database"));
        input
            .secrets
            .named_secrets
            .insert("Database".to_owned(), db_name);
    }
    input.modules.push(custom_secret_module("Connection URI"));
    input
        .secrets
        .named_secrets
        .insert("Connection URI".to_owned(), first_line.to_owned());

    Some(SmartParseResult {
        kind: "connectionUri".to_owned(),
        label: format!("{service_label} URI"),
        label_zh: format!("{service_label} 连接串"),
        summary: format!("{service_label} · {host}:{port}"),
        input,
        totp_uri: None,
        totp_issuer: None,
        totp_account: None,
        multi_entries: 1,
        warnings: Vec::new(),
    })
}

#[derive(Debug, Default, Clone)]
struct SshHostBlock {
    alias: String,
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<String>,
    proxy_jump: Option<String>,
}

fn parse_ssh_config_blocks(text: &str) -> Vec<SshHostBlock> {
    let mut defaults = SshHostBlock::default();
    let mut blocks: Vec<SshHostBlock> = Vec::new();
    let mut current_indices: Vec<usize> = Vec::new();
    let mut in_wildcard_defaults = false;

    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = if let Some((k, v)) = line.split_once('=') {
            (k.trim(), v.trim())
        } else {
            let mut parts = line.splitn(2, char::is_whitespace);
            let k = parts.next().unwrap_or("").trim();
            let v = parts.next().unwrap_or("").trim();
            (k, v)
        };
        if value.is_empty() {
            continue;
        }
        let key_lower = key.to_ascii_lowercase();
        if key_lower == "host" {
            current_indices.clear();
            in_wildcard_defaults = false;
            for pattern in value.split_whitespace() {
                if pattern == "*" {
                    in_wildcard_defaults = true;
                } else if !pattern.contains('*') && !pattern.contains('?') && !pattern.starts_with('!') {
                    blocks.push(SshHostBlock {
                        alias: pattern.to_owned(),
                        ..Default::default()
                    });
                    current_indices.push(blocks.len() - 1);
                }
            }
            continue;
        }
        if key_lower == "match" {
            current_indices.clear();
            in_wildcard_defaults = false;
            continue;
        }

        let apply = |target: &mut SshHostBlock| match key_lower.as_str() {
            "hostname" => {
                if target.hostname.is_none() {
                    target.hostname = Some(value.trim_matches('"').to_owned());
                }
            }
            "user" => {
                if target.user.is_none() {
                    target.user = Some(value.trim_matches('"').to_owned());
                }
            }
            "port" => {
                if target.port.is_none()
                    && let Ok(p) = value.parse::<u16>()
                    && p > 0
                {
                    target.port = Some(p);
                }
            }
            "identityfile" => {
                if target.identity_file.is_none() {
                    target.identity_file = Some(value.trim_matches('"').to_owned());
                }
            }
            "proxyjump" => {
                if target.proxy_jump.is_none() {
                    target.proxy_jump = Some(value.to_owned());
                }
            }
            _ => {}
        };

        if in_wildcard_defaults {
            apply(&mut defaults);
        }
        for &idx in &current_indices {
            apply(&mut blocks[idx]);
        }
    }

    for block in &mut blocks {
        if block.user.is_none() {
            block.user = defaults.user.clone();
        }
        if block.port.is_none() {
            block.port = defaults.port;
        }
        if block.identity_file.is_none() {
            block.identity_file = defaults.identity_file.clone();
        }
        if block.proxy_jump.is_none() {
            block.proxy_jump = defaults.proxy_jump.clone();
        }
    }
    blocks
}

pub fn parse_ssh_config_bytes(
    bytes: &[u8],
    base_dir: Option<&Path>,
) -> Result<(Vec<(PortableConnection, SecretBundle)>, Preview)> {
    let (entries, preview, _) = parse_ssh_config_bytes_with_key_files(bytes, base_dir)?;
    Ok((entries, preview))
}

/// Like [`parse_ssh_config_bytes`], plus the private key file each entry was loaded from
/// (parallel to the entries). The config only names the keys; the key files are what
/// still holds plaintext after an import.
pub fn parse_ssh_config_bytes_with_key_files(
    bytes: &[u8],
    base_dir: Option<&Path>,
) -> Result<(Vec<(PortableConnection, SecretBundle)>, Preview, Vec<Option<PathBuf>>)> {
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let text = std::str::from_utf8(bytes)
        .context("SSH config must be valid UTF-8 text")?
        .trim_start_matches('\u{feff}');
    let blocks = parse_ssh_config_blocks(text);
    ensure!(
        !blocks.is_empty(),
        "No concrete Host entries found in SSH config"
    );

    let mut entries = Vec::new();
    let mut key_files = Vec::new();
    let mut preview = Preview::default();
    let now = chrono::Utc::now().to_rfc3339();
    let mut missing_keys = false;

    for block in blocks {
        let mut key_file = None;
        let host = block.hostname.unwrap_or_else(|| block.alias.clone());
        let port = block.port.unwrap_or(22);
        let mut modules = vec![
            public_module("host", host.clone()),
            public_module("port", port.to_string()),
        ];
        let mut secrets = SecretBundle::default();
        if let Some(user) = block.user.filter(|u| !u.trim().is_empty()) {
            modules.push(secret_module("username"));
            secrets.named_secrets.insert("username".to_owned(), user);
        }
        let mut private_key_name = String::new();
        if let Some(key_path) = block.identity_file {
            match read_local_ssh_key_at(&key_path, base_dir) {
                Ok((name, pem, path)) => {
                    modules.push(secret_module("privateKey"));
                    secrets.private_key = Some(pem);
                    secrets.private_key_name = Some(name.clone());
                    private_key_name = name;
                    key_file = Some(path);
                }
                Err(_) => {
                    missing_keys = true;
                }
            }
        }
        let description = match block.proxy_jump {
            Some(jump) => format!("Imported from ~/.ssh/config · ProxyJump {jump}"),
            None => "Imported from ~/.ssh/config".to_owned(),
        };
        let portable = PortableConnection {
            login_uris: Vec::new(),
            item_type: "ssh".to_owned(),
            folder: "SSH".to_owned(),
            favorite: false,
            id: Uuid::new_v4(),
            modules,
            name: sanitize_name(&block.alias, 80),
            enabled: true,
            created_at: now.clone(),
            updated_at: now.clone(),
            description,
            http_auth_type: String::new(),
            private_key_name,
            auth_header: String::new(),
            auth_location: String::new(),
            auth_prefix: String::new(),
            api_auth_headers: Vec::new(),
            test_path: String::new(),
        };
        *preview.types.entry("ssh".to_owned()).or_default() += 1;
        entries.push((portable, secrets));
        key_files.push(key_file);
    }

    if missing_keys {
        preview.warnings.push("sshKeyNotFound".to_owned());
    }
    preview.total = entries.len();
    Ok((entries, preview, key_files))
}

fn try_parse_ssh_config_snippet(text: &str) -> Option<SmartParseResult> {
    let lower = text.to_ascii_lowercase();
    if !lower.contains("hostname") && !lower.contains("identityfile") {
        return None;
    }
    let blocks = parse_ssh_config_blocks(text);
    let first = blocks.first()?;
    let host = first
        .hostname
        .clone()
        .unwrap_or_else(|| first.alias.clone());
    let port = first.port.unwrap_or(22);
    let mut warnings = Vec::new();
    let loaded_key = first.identity_file.as_deref().and_then(|p| {
        match read_local_ssh_key(p, None) {
            Ok(loaded) => Some(loaded),
            Err(err) => {
                warnings.push(format!("Key file {p} not loaded: {err}"));
                None
            }
        }
    });
    if blocks.len() > 1 {
        warnings.push(format!(
            "Detected {} SSH hosts; showing the first host (use Import SSH Config for batch import)",
            blocks.len()
        ));
    }
    let mut result = build_ssh_result(
        &host,
        port,
        first.user.clone(),
        None,
        loaded_key,
        warnings,
    );
    result.kind = "sshConfig".to_owned();
    result.label = "SSH Config".to_owned();
    result.label_zh = "SSH 配置片段".to_owned();
    result.input.name = sanitize_name(&first.alias, 80);
    result.multi_entries = blocks.len();
    Some(result)
}

#[derive(Debug, Clone)]
pub struct ParsedEnvVar {
    pub key: String,
    pub value: String,
}

/// dotenv / properties key names longer than this are not imported: the vault's
/// field-name sanitizer truncates at 64 characters, so a longer key could not be
/// referenced by a placeholder that resolves.
const MAX_ENV_KEY_CHARS: usize = 64;
/// A quoted value may continue on later lines (PEM keys, JSON blobs). The bound keeps an
/// unbalanced quote from swallowing the rest of a large file.
const MAX_QUOTED_VALUE_LINES: usize = 256;

/// Shell-style assignments only: these are the names the MCP ingest tool stores verbatim,
/// and free-text extraction relies on the uppercase requirement to ignore `a=b` prose.
pub fn parse_env_vars(text: &str) -> Vec<ParsedEnvVar> {
    collect_env_vars(text, is_valid_env_key)
}

/// Every assignment of a configuration file, including lowercase and dotted keys such as
/// `db_password` or `spring.datasource.password`. Use it when the whole file is known to
/// be configuration the user chose to import; prose would produce noise.
pub fn parse_env_config_vars(text: &str) -> Vec<ParsedEnvVar> {
    collect_env_vars(text, |_| true)
}

fn collect_env_vars(text: &str, accept_key: impl Fn(&str) -> bool) -> Vec<ParsedEnvVar> {
    let text = text.trim_start_matches('\u{feff}');
    let lines = split_env_lines(text);
    let mut vars = Vec::new();
    let mut seen = HashSet::new();
    for entry in scan_env_entries(&lines) {
        let EnvEntryKind::Assignment { key, value, .. } = entry.kind else {
            continue;
        };
        // An existing placeholder is a reference to the vault, not a secret to store.
        if value.is_empty() || contains_secret_placeholder(&value) || !accept_key(&key) {
            continue;
        }
        if seen.insert(key.clone()) {
            vars.push(ParsedEnvVar { key, value });
        }
    }
    vars
}

/// Key grammar shared by dotenv and Java properties files.
fn is_config_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && key.len() <= MAX_ENV_KEY_CHARS
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        && !key.ends_with(['.', '-'])
        && !looks_like_key_material(key)
}

/// A long run of letters and digits without any separator is far more likely to be a
/// wrapped line of base64 key material followed by `=` padding than a variable name.
/// Treating it as a key would copy that material into the template as a placeholder name.
fn looks_like_key_material(key: &str) -> bool {
    key.len() >= 24 && !key.contains(['_', '.', '-'])
}

fn contains_secret_placeholder(value: &str) -> bool {
    // Covers `{{openkeylet:…}}`, `{{openkeylet-raw:…}}` and the legacy `{{kru…}}` forms.
    value.contains("{{openkeylet") || value.contains("{{kru:") || value.contains("{{kru-raw:")
}

/// Shell environment variable names as the shell-file scanner accepts them.
pub(super) fn is_shell_env_name(key: &str) -> bool {
    is_valid_env_key(key)
}

fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    key.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && key.chars().any(|c| c.is_ascii_uppercase())
}

fn unquote_env_value(raw: &str) -> String {
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        raw[1..raw.len() - 1]
            .replace("\\n", "\n")
            .replace("\\r", "\r")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    } else if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        raw[1..raw.len() - 1].to_owned()
    } else {
        // Strip inline comments preceded by whitespace for unquoted values.
        if let Some(pos) = raw.find(" #") {
            raw[..pos].trim().to_owned()
        } else {
            raw.to_owned()
        }
    }
}

struct EnvLine<'a> {
    body: &'a str,
    ending: &'a str,
}

fn split_env_lines(raw: &str) -> Vec<EnvLine<'_>> {
    raw.split_inclusive('\n')
        .map(|line| {
            if let Some(body) = line.strip_suffix("\r\n") {
                EnvLine { body, ending: "\r\n" }
            } else if let Some(body) = line.strip_suffix('\n') {
                EnvLine { body, ending: "\n" }
            } else {
                EnvLine { body: line, ending: "" }
            }
        })
        .collect()
}

#[derive(Debug)]
enum EnvEntryKind {
    Blank,
    Comment,
    /// `# KEY=value`: dead configuration that still carries a value.
    CommentedValue { key: String },
    /// A comment holding a token, a URL password or a commented-out private key.
    CommentedCredential,
    Assignment {
        key: String,
        value: String,
        /// Bytes of the first line up to and including `=`, kept verbatim when sealing so
        /// `export`, indentation and spacing survive.
        head_len: usize,
    },
    /// Anything this parser cannot read as `KEY=VALUE`, including stray token lines.
    Unrecognized,
}

/// One logical entry spanning `first..=last` physical lines (multi-line quoted values and
/// commented-out PEM blocks span several).
#[derive(Debug)]
struct EnvEntry {
    first: usize,
    last: usize,
    kind: EnvEntryKind,
}

fn scan_env_entries(lines: &[EnvLine<'_>]) -> Vec<EnvEntry> {
    let mut entries = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].body.trim();
        if trimmed.is_empty() {
            entries.push(EnvEntry { first: i, last: i, kind: EnvEntryKind::Blank });
            i += 1;
            continue;
        }
        if let Some(comment) = trimmed.strip_prefix('#') {
            let (kind, last) = classify_env_comment(lines, i, comment);
            entries.push(EnvEntry { first: i, last, kind });
            i = last + 1;
            continue;
        }
        match parse_env_assignment(lines, i) {
            Some((key, value, head_len, last)) => {
                entries.push(EnvEntry {
                    first: i,
                    last,
                    kind: EnvEntryKind::Assignment { key, value, head_len },
                });
                i = last + 1;
            }
            None => {
                entries.push(EnvEntry { first: i, last: i, kind: EnvEntryKind::Unrecognized });
                i += 1;
            }
        }
    }
    entries
}

fn strip_export_keyword(text: &str) -> Option<&str> {
    text.strip_prefix("export")
        .filter(|rest| rest.starts_with([' ', '\t']))
        .map(str::trim_start)
}

/// Returns `(key, value, head_len, last_line)` for a `[export] KEY=VALUE` entry.
fn parse_env_assignment(lines: &[EnvLine<'_>], index: usize) -> Option<(String, String, usize, usize)> {
    let body = lines[index].body;
    let mut offset = body.len() - body.trim_start().len();
    let mut rest = &body[offset..];
    if let Some(after) = strip_export_keyword(rest) {
        offset += rest.len() - after.len();
        rest = after;
    }
    let eq = rest.find('=')?;
    let key = rest[..eq].trim();
    if !is_config_env_key(key) {
        return None;
    }
    let head_len = offset + eq + 1;
    let (value, last) = read_env_value(lines, index, &body[head_len..]);
    Some((key.to_owned(), value, head_len, last))
}

fn read_env_value(lines: &[EnvLine<'_>], index: usize, raw_val: &str) -> (String, usize) {
    let value = raw_val.trim_start();
    let Some(quote) = value.chars().next().filter(|c| matches!(c, '"' | '\'' | '`')) else {
        return (unquote_env_value(raw_val.trim()), index);
    };
    let inner = &value[1..];
    if let Some(close) = find_closing_quote(inner, quote) {
        let after = inner[close + 1..].trim();
        if after.is_empty() || after.starts_with('#') {
            return (unescape_quoted_env(&inner[..close], quote), index);
        }
        return (unquote_env_value(raw_val.trim()), index);
    }
    // dotenv continues an unterminated quoted value on the following lines.
    let mut collected = inner.to_owned();
    let limit = lines.len().min(index + 1 + MAX_QUOTED_VALUE_LINES);
    for (next, line) in lines.iter().enumerate().take(limit).skip(index + 1) {
        collected.push('\n');
        if let Some(close) = find_closing_quote(line.body, quote) {
            collected.push_str(&line.body[..close]);
            return (unescape_quoted_env(&collected, quote), next);
        }
        collected.push_str(line.body);
    }
    // No closing quote: read it the way a line-based parser would. The following lines
    // are then scanned on their own, so nothing they contain is lost or copied blindly.
    (unquote_env_value(raw_val.trim()), index)
}

fn find_closing_quote(text: &str, quote: char) -> Option<usize> {
    let mut escaped = false;
    for (idx, ch) in text.char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' && quote != '\'' {
            escaped = true;
        } else if ch == quote {
            return Some(idx);
        }
    }
    None
}

fn unescape_quoted_env(inner: &str, quote: char) -> String {
    if quote == '"' {
        inner
            .replace("\\n", "\n")
            .replace("\\r", "\r")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    } else {
        inner.to_owned()
    }
}

fn classify_env_comment(lines: &[EnvLine<'_>], index: usize, comment: &str) -> (EnvEntryKind, usize) {
    let text = comment.trim();
    if text.contains("-----BEGIN ") && text.contains("PRIVATE KEY") {
        // A commented-out key keeps its base64 body on the following comment lines, which
        // carry no recognizable marker of their own.
        let mut last = index;
        if !text.contains("-----END ") {
            let limit = lines.len().min(index + 1 + MAX_QUOTED_VALUE_LINES);
            for (next, line) in lines.iter().enumerate().take(limit).skip(index + 1) {
                let body = line.body.trim();
                if !body.starts_with('#') {
                    break;
                }
                last = next;
                if body.contains("-----END ") {
                    break;
                }
            }
        }
        return (EnvEntryKind::CommentedCredential, last);
    }
    if let Some(key) = commented_assignment_key(text) {
        return (EnvEntryKind::CommentedValue { key }, index);
    }
    if comment_mentions_credential(text) {
        return (EnvEntryKind::CommentedCredential, index);
    }
    (EnvEntryKind::Comment, index)
}

fn commented_assignment_key(text: &str) -> Option<String> {
    let text = strip_export_keyword(text).unwrap_or(text);
    let (raw_key, raw_val) = text.split_once('=')?;
    let key = raw_key.trim();
    if !is_config_env_key(key) {
        return None;
    }
    let value = unquote_env_value(raw_val.trim());
    (!value.is_empty() && !contains_secret_placeholder(&value)).then(|| key.to_owned())
}

fn comment_mentions_credential(text: &str) -> bool {
    text.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '=' | ',' | ';' | '(' | ')' | '<' | '>'))
        .filter(|word| !word.is_empty())
        .any(|word| {
            let url_password = word.contains("://")
                && Url::parse(word)
                    .ok()
                    .and_then(|url| url.password().map(str::to_owned))
                    .is_some_and(|pass| !super::freetext::is_placeholder_value(&pass));
            url_password
                || word.split(':').any(|part| {
                    super::freetext::has_high_confidence_token_prefix(part)
                        && !super::freetext::is_placeholder_value(part)
                })
        })
}

/// Every line written in place of content that could not be sealed starts with this, so
/// readers (and the desktop app) can count and find them.
pub const SEALED_REMOVAL_MARKER: &str = "# OpenKeylet removed";

/// A dotenv-style file rewritten so it can be committed: each imported value is a
/// `{{openkeylet:FIELD}}` placeholder and every other value is gone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SealedEnvTemplate {
    pub text: String,
    /// Env keys replaced by placeholders, in file order.
    pub sealed_keys: Vec<String>,
    /// Entries replaced by a [`SEALED_REMOVAL_MARKER`] comment instead of a placeholder.
    pub removed_lines: usize,
    /// Names (never values) of assignments whose value was removed.
    pub removed_keys: Vec<String>,
}

/// Seals the keys that [`parse_env_vars`] returns, which is what the MCP ingest tool stores.
pub fn render_sealed_env(raw: &str) -> (String, Vec<String>) {
    let sealed = seal_env_template(raw);
    (sealed.text, sealed.sealed_keys)
}

/// [`render_sealed_env`] with the count of removed lines.
pub fn seal_env_template(raw: &str) -> SealedEnvTemplate {
    let ingested: HashSet<String> = parse_env_vars(raw).into_iter().map(|var| var.key).collect();
    seal_env_text(raw, &|key| ingested.contains(key).then(|| key.to_owned()), None)
}

/// Seals each key with the vault field that holds its value (see [`EnvFileImport::fields`]),
/// so the placeholders resolve even when an env key was stored under another field name.
pub fn seal_env_template_with_fields(raw: &str, fields: &BTreeMap<String, String>) -> SealedEnvTemplate {
    seal_env_text(raw, &|key| fields.get(key).cloned(), None)
}

/// Seals `sealed` keys and keeps `public` keys verbatim. The extractor judged the public
/// ones to be ordinary configuration (ports, URLs, flags, placeholders) that the template
/// still needs; every other value is removed.
pub fn seal_env_template_selected(
    raw: &str,
    sealed: &HashSet<String>,
    public: &HashSet<String>,
) -> SealedEnvTemplate {
    seal_env_text(raw, &|key| sealed.contains(key).then(|| key.to_owned()), Some(public))
}

// Fails closed: a line is copied only when it is blank, an ordinary comment, an assignment
// with an empty or already-templated value, or a key the caller marked public. Everything
// else is either sealed or replaced by a removal comment that names the key but never the
// value, so a template can never carry plaintext the parser did not understand.
fn seal_env_text(
    raw: &str,
    placeholder_for: &dyn Fn(&str) -> Option<String>,
    public: Option<&HashSet<String>>,
) -> SealedEnvTemplate {
    let raw = raw.trim_start_matches('\u{feff}');
    let lines = split_env_lines(raw);
    let mut sealed = SealedEnvTemplate {
        text: String::with_capacity(raw.len() + 128),
        ..SealedEnvTemplate::default()
    };
    let mut taken: HashSet<String> = HashSet::new();

    for entry in scan_env_entries(&lines) {
        let span = &lines[entry.first..=entry.last];
        let ending = lines[entry.last].ending;
        let where_ = if entry.first == entry.last {
            format!("line {}", entry.first + 1)
        } else {
            format!("lines {}-{}", entry.first + 1, entry.last + 1)
        };
        let removal = match entry.kind {
            EnvEntryKind::Blank | EnvEntryKind::Comment => {
                push_env_lines(&mut sealed.text, span);
                continue;
            }
            EnvEntryKind::CommentedValue { key } => {
                format!("a commented-out value of {key} ({where_})")
            }
            EnvEntryKind::CommentedCredential => {
                format!("a comment that contained a credential ({where_})")
            }
            EnvEntryKind::Unrecognized => {
                format!("{where_}: not a KEY=VALUE line it can import")
            }
            EnvEntryKind::Assignment { key, value, head_len } => {
                if value.is_empty() || contains_secret_placeholder(&value) {
                    push_env_lines(&mut sealed.text, span);
                    continue;
                }
                if !taken.contains(&key)
                    && let Some(field) = placeholder_for(&key)
                {
                    sealed.text.push_str(&lines[entry.first].body[..head_len]);
                    sealed.text.push_str("{{openkeylet:");
                    sealed.text.push_str(&field);
                    sealed.text.push_str("}}");
                    sealed.text.push_str(ending);
                    if !sealed.sealed_keys.contains(&key) {
                        sealed.sealed_keys.push(key.clone());
                    }
                    taken.insert(key);
                    continue;
                }
                if public.is_some_and(|keys| keys.contains(&key)) {
                    push_env_lines(&mut sealed.text, span);
                    continue;
                }
                let reason = if taken.contains(&key) {
                    format!("the value of {key} ({where_}): duplicate of an earlier {key}")
                } else {
                    format!("the value of {key} ({where_}): it is not stored in the vault")
                };
                if !sealed.removed_keys.contains(&key) {
                    sealed.removed_keys.push(key);
                }
                reason
            }
        };
        sealed.text.push_str(SEALED_REMOVAL_MARKER);
        sealed.text.push(' ');
        sealed.text.push_str(&removal);
        sealed.text.push_str(ending);
        sealed.removed_lines += 1;
    }
    sealed
}

fn push_env_lines(out: &mut String, lines: &[EnvLine<'_>]) {
    for line in lines {
        out.push_str(line.body);
        out.push_str(line.ending);
    }
}

/// Adds or updates `.env` / properties entries onto `input` using vault-safe field names.
/// Reserved names (`PASSWORD`, `TOKEN`, `API_KEY`, `USERNAME`, `PRIVATE_KEY`, etc.) map onto
/// their built-in vault modules instead of failing validation as `customSecret`, and clashes
/// get a disambiguated suffix. Returns `(env_key, vault_field, value)` in input order.
pub fn apply_env_vars_to_connection(
    input: &mut ConnectionInput,
    vars: &[ParsedEnvVar],
    overwrite: bool,
    existing_item_name: Option<&str>,
) -> Result<Vec<(String, String, String)>> {
    let mut mapped = Vec::with_capacity(vars.len());
    let mut assigned_in_batch: HashSet<String> = HashSet::new();

    for var in vars {
        let base_name = super::reconcile::sanitize_name(&var.key, MAX_ENV_KEY_CHARS);
        let norm = super::reconcile::normalized_secret_field_name(&base_name);
        let canonical = match norm.as_str() {
            "username" => Some(("username", "username")),
            "password" => Some(("password", "password")),
            "passphrase" => Some(("passphrase", "passphrase")),
            "privatekey" => Some(("privateKey", "privateKey")),
            "totp" => Some(("totp", "totp")),
            "apicredential" | "token" | "apikey" => Some(("apiCredential", "apiCredential")),
            "securenote" => Some(("secureNote", "secureNote")),
            _ => None,
        };

        if let Some((kind, field)) = canonical
            && !assigned_in_batch.contains(field)
        {
            let already_on_item = input.modules.iter().any(|m| m.kind == kind);
            if already_on_item {
                if input.secrets.get(field).is_some() && !overwrite {
                    let label = existing_item_name.unwrap_or(&input.name);
                    anyhow::bail!(
                        "Field '{field}' already exists on '{label}'. Pass overwrite=true to update it."
                    );
                }
            } else {
                input.modules.push(super::reconcile::secret_mod(kind, field));
            }
            match field {
                "password" => input.secrets.password = Some(var.value.clone()),
                "passphrase" => input.secrets.passphrase = Some(var.value.clone()),
                "privateKey" => input.secrets.private_key = Some(var.value.clone()),
                _ => {
                    input
                        .secrets
                        .named_secrets
                        .insert(field.to_owned(), var.value.clone());
                }
            }
            assigned_in_batch.insert(field.to_owned());
            mapped.push((var.key.clone(), field.to_owned(), var.value.clone()));
            continue;
        }

        let target_norm = if super::reconcile::is_reserved_custom_secret_name(&base_name) {
            super::reconcile::normalized_secret_field_name(&super::reconcile::sanitize_name(
                &format!("{base_name}_secret"),
                MAX_ENV_KEY_CHARS,
            ))
        } else {
            norm
        };
        if let Some((field_name, field_norm)) = input
            .modules
            .iter()
            .filter(|m| m.kind == "customSecret")
            .find_map(|m| {
                let m_norm = super::reconcile::normalized_secret_field_name(&m.name);
                (m_norm == target_norm && !assigned_in_batch.contains(&m_norm))
                    .then(|| (m.name.clone(), m_norm))
            })
        {
            if input.secrets.get(&field_name).is_some() && !overwrite {
                let label = existing_item_name.unwrap_or(&input.name);
                anyhow::bail!(
                    "Field '{field_name}' already exists on '{label}'. Pass overwrite=true to update it."
                );
            }
            input
                .secrets
                .named_secrets
                .insert(field_name.clone(), var.value.clone());
            assigned_in_batch.insert(field_norm);
            mapped.push((var.key.clone(), field_name, var.value.clone()));
            continue;
        }

        let before = input.modules.len();
        super::reconcile::push_vault_safe_secret_module(input, &var.key, var.value.clone());
        if let Some(field) = input.modules.get(before).and_then(ItemModule::secret_name) {
            let field_owned = field.to_owned();
            assigned_in_batch.insert(super::reconcile::normalized_secret_field_name(&field_owned));
            mapped.push((var.key.clone(), field_owned, var.value.clone()));
        }
    }

    Ok(mapped)
}

/// An `.env` import plus what is needed to write a template whose placeholders resolve.
pub struct EnvFileImport {
    pub entries: Vec<(PortableConnection, SecretBundle)>,
    pub preview: Preview,
    /// Env key -> vault field holding its value. Most keys keep their name; reserved names
    /// such as `PASSWORD` or `TOKEN` map onto built-in fields and clashes get a suffix.
    pub fields: BTreeMap<String, String>,
}

pub fn parse_env_file(
    bytes: &[u8],
    default_name: &str,
) -> Result<(Vec<(PortableConnection, SecretBundle)>, Preview)> {
    let import = parse_env_file_detailed(bytes, default_name)?;
    Ok((import.entries, import.preview))
}

pub fn parse_env_file_detailed(bytes: &[u8], default_name: &str) -> Result<EnvFileImport> {
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let text = std::str::from_utf8(bytes)
        .context(".env file must be valid UTF-8 text")?
        .trim_start_matches('\u{feff}');
    let vars = parse_env_config_vars(text);
    ensure!(!vars.is_empty(), "No KEY=VALUE entries found in .env file");
    let mut temp = empty_input("custom", default_name.to_owned());
    let mut preview = Preview::default();
    let mut fields = BTreeMap::new();

    for var in &vars {
        let before = temp.modules.len();
        super::reconcile::push_vault_safe_secret_module(&mut temp, &var.key, var.value.clone());
        if let Some(field) = temp.modules.get(before).and_then(ItemModule::secret_name) {
            fields.insert(var.key.clone(), field.to_owned());
        }
    }
    let modules = temp.modules;
    let secrets = temp.secrets;

    let now = chrono::Utc::now().to_rfc3339();
    let item_name = sanitize_name(
        if default_name.trim().is_empty() {
            "Imported .env"
        } else {
            default_name
        },
        80,
    );
    let portable = PortableConnection {
        login_uris: Vec::new(),
        item_type: "custom".to_owned(),
        folder: "Env".to_owned(),
        favorite: false,
        id: Uuid::new_v4(),
        modules,
        name: item_name,
        enabled: true,
        created_at: now.clone(),
        updated_at: now,
        description: format!("Imported .env ({} keys)", vars.len()),
        http_auth_type: String::new(),
        private_key_name: String::new(),
        auth_header: String::new(),
        auth_location: String::new(),
        auth_prefix: String::new(),
        api_auth_headers: Vec::new(),
        test_path: String::new(),
    };
    *preview.types.entry("custom".to_owned()).or_default() += 1;
    preview.total = 1;
    Ok(EnvFileImport {
        entries: vec![(portable, secrets)],
        preview,
        fields,
    })
}

fn try_parse_env_snippet(text: &str, hint_filename: Option<&str>) -> Option<SmartParseResult> {
    let non_comment_lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if non_comment_lines.is_empty() {
        return None;
    }
    let vars = parse_env_vars(text);
    if vars.is_empty() {
        return None;
    }
    // Require that at least half of non-comment lines are valid KEY=VALUE assignments
    if vars.len() * 2 < non_comment_lines.len() {
        return None;
    }

    // Special case: a single recognizable API key line like `ANTHROPIC_API_KEY=sk-ant-...`
    if vars.len() == 1 {
        let var = &vars[0];
        let profile = api_catalog::infer(&var.key, "", &var.value);
        let looks_like_real_api_secret = !super::freetext::is_placeholder_value(&var.value)
            && (super::freetext::has_high_confidence_token_prefix(&var.value)
                || (super::freetext::key_secret_score(&var.key) >= 1
                    && !super::freetext::is_explicit_non_secret_key(&var.key)
                    && !super::freetext::is_obvious_non_secret_value(&var.value)
                    && var.value.len() >= 12
                    && !var.value.contains(char::is_whitespace)));
        if profile.display_name != "API" && looks_like_real_api_secret {
            let mut input = empty_input("api", format!("{} API", profile.display_name));
            if !profile.default_base_url.is_empty() {
                input
                    .modules
                    .push(public_module("url", profile.default_base_url));
            }
            input.modules.push(secret_module("apiCredential"));
            input
                .secrets
                .named_secrets
                .insert("apiCredential".to_owned(), var.value.clone());
            input.http_auth_type = profile.auth_type.to_owned();
            input.auth_header = profile.auth_header.to_owned();
            input.auth_location = profile.auth_location.to_owned();
            input.auth_prefix = profile.auth_prefix.to_owned();
            return Some(SmartParseResult {
                kind: "apiKey".to_owned(),
                label: format!("{} API", profile.display_name),
                label_zh: format!("{} API 密钥", profile.display_name),
                summary: format!("{} · {}", profile.display_name, var.key),
                input,
                totp_uri: None,
                totp_issuer: None,
                totp_account: None,
                multi_entries: 1,
                warnings: Vec::new(),
            });
        }
    }

    let base_name = hint_filename
        .and_then(|f| Path::new(f).file_name().and_then(|s| s.to_str()))
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!("Env · {s}"))
        .unwrap_or_else(|| {
            if vars.len() == 1 {
                vars[0].key.clone()
            } else {
                format!("Env Secrets ({})", vars.len())
            }
        });
    let mut input = empty_input("custom", base_name.clone());
    input.folder = "Env".to_owned();
    input.description = format!("{} environment variables", vars.len());
    for var in &vars {
        super::reconcile::push_vault_safe_secret_module(&mut input, &var.key, var.value.clone());
    }

    Some(SmartParseResult {
        kind: "env".to_owned(),
        label: format!(".env ({} keys)", vars.len()),
        label_zh: format!(".env 环境变量 ({} 项)", vars.len()),
        summary: format!(
            ".env · {}",
            vars.iter()
                .take(3)
                .map(|v| v.key.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        input,
        totp_uri: None,
        totp_issuer: None,
        totp_account: None,
        multi_entries: 1,
        warnings: Vec::new(),
    })
}

fn try_parse_server_info(text: &str) -> Option<SmartParseResult> {
    if text.lines().filter(|l| !l.trim().is_empty()).count() < 2 {
        return None;
    }
    let mut map: BTreeMap<&'static str, String> = BTreeMap::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((raw_k, raw_v)) = super::freetext::split_label_value(line) else {
            continue;
        };
        let k = raw_k.trim().to_ascii_lowercase();
        let v = raw_v.trim().to_owned();
        if v.is_empty() || super::freetext::is_placeholder_value(&v) {
            continue;
        }
        if matches!(
            k.as_str(),
            "ip" | "host" | "hostname" | "server" | "address" | "主机" | "服务器" | "地址" | "ip地址"
        ) {
            if super::freetext::is_plausible_host(&v) {
                map.entry("host").or_insert(v);
            }
        } else if matches!(k.as_str(), "port" | "ssh port" | "端口" | "端口号") {
            map.entry("port").or_insert(v);
        } else if matches!(
            k.as_str(),
            "user" | "username" | "account" | "login" | "email" | "账号" | "用户名" | "登录名" | "邮箱"
        ) {
            if !super::freetext::is_prose_sentence(&k, &v) {
                map.entry("username").or_insert(v);
            }
        } else if matches!(
            k.as_str(),
            "pass" | "password" | "pwd" | "密码" | "登录密码" | "初始密码"
        ) {
            if !super::freetext::is_filesystem_path_value(&v)
                && !super::freetext::is_api_route_or_url_value(&v)
                && !super::freetext::is_prose_sentence(&k, &v)
            {
                map.entry("password").or_insert(v);
            }
        } else if matches!(
            k.as_str(),
            "url" | "website" | "site" | "endpoint" | "base url" | "网址" | "链接" | "接口地址"
        ) {
            map.entry("url").or_insert(v);
        } else if matches!(
            k.as_str(),
            "api key" | "apikey" | "token" | "access token" | "secret" | "密钥" | "令牌"
        ) {
            if !super::freetext::is_obvious_non_secret_value(&v)
                && !super::freetext::is_prose_sentence(&k, &v)
            {
                map.entry("apiCredential").or_insert(v);
            }
        }
    }

    if map.len() < 2 {
        return None;
    }

    if let Some(host) = map.get("host").cloned() {
        let port = map
            .get("port")
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(22);
        let mut res = build_ssh_result(
            &host,
            port,
            map.get("username").cloned(),
            map.get("password").cloned(),
            None,
            Vec::new(),
        );
        res.kind = "serverInfo".to_owned();
        res.label = "Server Credentials".to_owned();
        res.label_zh = "服务器凭据".to_owned();
        return Some(res);
    }

    if let Some(token) = map.get("apiCredential").cloned() {
        let raw_url = map.get("url").cloned().unwrap_or_default();
        let profile = api_catalog::infer("", &raw_url, &token);
        let resolved_url = api_catalog::normalize_base_url(&raw_url, profile.default_base_url)
            .unwrap_or(raw_url);
        let name = api_catalog::fallback_name(&resolved_url, profile);
        let mut input = empty_input("api", format!("{name} API"));
        if !resolved_url.is_empty() {
            input.modules.push(public_module("url", resolved_url.clone()));
        }
        input.modules.push(secret_module("apiCredential"));
        input
            .secrets
            .named_secrets
            .insert("apiCredential".to_owned(), token);
        input.http_auth_type = profile.auth_type.to_owned();
        input.auth_header = profile.auth_header.to_owned();
        input.auth_location = profile.auth_location.to_owned();
        input.auth_prefix = profile.auth_prefix.to_owned();
        return Some(SmartParseResult {
            kind: "serverInfo".to_owned(),
            label: "API Credentials".to_owned(),
            label_zh: "API 凭据".to_owned(),
            summary: format!("{name} API"),
            input,
            totp_uri: None,
            totp_issuer: None,
            totp_account: None,
            multi_entries: 1,
            warnings: Vec::new(),
        });
    }

    if map.contains_key("username") || map.contains_key("password") {
        let raw_url = map.get("url").cloned().unwrap_or_default();
        let host_label = Url::parse(&raw_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_else(|| "Account Login".to_owned());
        let mut input = empty_input("login", host_label.clone());
        if !raw_url.is_empty() {
            input.modules.push(public_module("url", raw_url.clone()));
            input.login_uris.push(LoginUri {
                uri: raw_url,
                match_type: "domain".to_owned(),
            });
        }
        input.modules.push(secret_module("username"));
        if let Some(u) = map.get("username") {
            input
                .secrets
                .named_secrets
                .insert("username".to_owned(), u.clone());
        }
        input.modules.push(secret_module("password"));
        if let Some(p) = map.get("password") {
            input.secrets.password = Some(p.clone());
        }
        return Some(SmartParseResult {
            kind: "serverInfo".to_owned(),
            label: "Account Login".to_owned(),
            label_zh: "网站账号密码".to_owned(),
            summary: format!("Login · {host_label}"),
            input,
            totp_uri: None,
            totp_issuer: None,
            totp_account: None,
            multi_entries: 1,
            warnings: Vec::new(),
        });
    }

    None
}

fn try_parse_known_api_key(text: &str, hint_url: Option<&str>) -> Option<SmartParseResult> {
    if text.contains('\n') || text.contains('\r') || text.contains(char::is_whitespace) {
        return None;
    }
    let token = text.trim();
    if token.len() < 12
        || token.len() > 2048
        || super::freetext::is_placeholder_value(token)
        || super::freetext::is_filesystem_path_value(token)
        || super::freetext::is_api_route_or_url_value(token)
    {
        return None;
    }
    let hint_url_str = hint_url.unwrap_or_default();
    let profile = api_catalog::infer("", hint_url_str, token);
    let looks_like_generic_token = token.starts_with("sk-")
        || token.starts_with("AKIA")
        || token.starts_with("eyJ");
    if profile.display_name == "API" && !looks_like_generic_token {
        return None;
    }

    let base_url = if !profile.default_base_url.is_empty() {
        profile.default_base_url.to_owned()
    } else if let Ok(url) = Url::parse(hint_url_str) {
        url.origin().ascii_serialization()
    } else {
        String::new()
    };

    let display_name = if profile.display_name != "API" {
        format!("{} API", profile.display_name)
    } else if token.starts_with("AKIA") {
        "AWS Access Key".to_owned()
    } else if let Ok(url) = Url::parse(&base_url) {
        format!(
            "{} API",
            url.host_str().unwrap_or("API")
        )
    } else {
        "API Key".to_owned()
    };

    let mut input = empty_input("api", display_name.clone());
    if !base_url.is_empty() {
        input.modules.push(public_module("url", base_url.clone()));
    }
    input.modules.push(secret_module("apiCredential"));
    input
        .secrets
        .named_secrets
        .insert("apiCredential".to_owned(), token.to_owned());
    input.http_auth_type = profile.auth_type.to_owned();
    input.auth_header = profile.auth_header.to_owned();
    input.auth_location = profile.auth_location.to_owned();
    input.auth_prefix = profile.auth_prefix.to_owned();

    let summary = if !base_url.is_empty() {
        format!("{display_name} · {base_url}")
    } else {
        display_name.clone()
    };
    Some(SmartParseResult {
        kind: "apiKey".to_owned(),
        label: display_name,
        label_zh: if profile.display_name != "API" {
            format!("{} API 密钥", profile.display_name)
        } else {
            "API 密钥".to_owned()
        },
        summary,
        input,
        totp_uri: None,
        totp_issuer: None,
        totp_account: None,
        multi_entries: 1,
        warnings: Vec::new(),
    })
}

fn try_parse_login_url(text: &str) -> Option<SmartParseResult> {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() || lines.len() > 3 {
        return None;
    }
    let url = Url::parse(lines[0]).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host_str()?.to_owned();
    let mut input = empty_input("login", host.clone());
    input.modules.push(public_module("url", url.to_string()));
    input.login_uris.push(LoginUri {
        uri: url.to_string(),
        match_type: "domain".to_owned(),
    });
    input.modules.push(secret_module("username"));
    if let Some(u) = lines.get(1) {
        input
            .secrets
            .named_secrets
            .insert("username".to_owned(), (*u).to_owned());
    }
    input.modules.push(secret_module("password"));
    if let Some(p) = lines.get(2) {
        input.secrets.password = Some((*p).to_owned());
    }

    Some(SmartParseResult {
        kind: "loginUrl".to_owned(),
        label: "Website Login".to_owned(),
        label_zh: "网站登录".to_owned(),
        summary: format!("Login · {host}"),
        input,
        totp_uri: None,
        totp_issuer: None,
        totp_account: None,
        multi_entries: 1,
        warnings: Vec::new(),
    })
}

fn fallback_secure_note(
    text: &str,
    hint_filename: Option<&str>,
    hint_url: Option<&str>,
) -> SmartParseResult {
    let name = hint_filename
        .and_then(|f| Path::new(f).file_name().and_then(|s| s.to_str()))
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned)
        .or_else(|| {
            hint_url
                .and_then(|u| Url::parse(u).ok())
                .and_then(|u| u.host_str().map(|h| format!("{h} Secret")))
        })
        .unwrap_or_else(|| "Quick Secret".to_owned());
    let mut input = empty_input("secureNote", name.clone());
    input.modules.push(secret_module("secureNote"));
    input
        .secrets
        .named_secrets
        .insert("secureNote".to_owned(), text.to_owned());
    SmartParseResult {
        kind: "secureNote".to_owned(),
        label: "Secure Note".to_owned(),
        label_zh: "安全笔记".to_owned(),
        summary: format!("Secure Note · {} chars", text.chars().count()),
        input,
        totp_uri: None,
        totp_issuer: None,
        totp_account: None,
        multi_entries: 1,
        warnings: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_anthropic_api_key() {
        let res = smart_parse("sk-ant-api03-example-token-12345", None, None).unwrap();
        assert_eq!(res.kind, "apiKey");
        assert_eq!(res.input.item_type, "api");
        assert_eq!(res.input.name, "Anthropic API");
        assert_eq!(res.input.auth_header, "x-api-key");
        assert_eq!(
            res.input.secrets.get("apiCredential"),
            Some("sk-ant-api03-example-token-12345")
        );
    }

    #[test]
    fn detects_curl_command_with_bearer_header() {
        let cmd = "curl -X POST https://api.deepseek.com/v1/chat/completions \\\n  -H \"Authorization: Bearer sk-ds-secret-123\" \\\n  -H \"Content-Type: application/json\"";
        let res = smart_parse(cmd, None, None).unwrap();
        assert_eq!(res.kind, "curl");
        assert_eq!(res.input.item_type, "api");
        assert_eq!(res.input.name, "DeepSeek API");
        assert_eq!(res.input.auth_header, "Authorization");
        assert_eq!(res.input.auth_prefix, "Bearer");
        assert_eq!(
            res.input.secrets.get("apiCredential"),
            Some("sk-ds-secret-123")
        );
    }

    #[test]
    fn detects_ssh_command_with_port_and_user() {
        let res = smart_parse("ssh -p 2222 deploy@203.0.113.10", None, None).unwrap();
        assert_eq!(res.kind, "sshCommand");
        assert_eq!(res.input.item_type, "ssh");
        assert_eq!(res.input.secrets.get("username"), Some("deploy"));
        assert!(res
            .input
            .modules
            .iter()
            .any(|m| m.kind == "host" && m.value == "203.0.113.10"));
        assert!(res
            .input
            .modules
            .iter()
            .any(|m| m.kind == "port" && m.value == "2222"));
    }

    #[test]
    fn detects_postgres_connection_uri() {
        let res = smart_parse("postgres://admin:s3cr3t@db.internal:5433/prod_db", None, None)
            .unwrap();
        assert_eq!(res.kind, "connectionUri");
        assert_eq!(res.input.secrets.get("username"), Some("admin"));
        assert_eq!(res.input.secrets.get("password"), Some("s3cr3t"));
        assert_eq!(res.input.secrets.get("Database"), Some("prod_db"));
        assert!(res.input.secrets.get("Connection URI").is_some());
    }

    #[test]
    fn detects_env_snippet_and_renders_sealed_template() {
        let raw = "# Production\nOPENAI_API_KEY=\"sk-proj-abc123\"\nDATABASE_URL=postgres://u:p@h/db\n";
        let res = smart_parse(raw, Some(".env.production"), None).unwrap();
        assert_eq!(res.kind, "env");
        assert_eq!(
            res.input.secrets.get("OPENAI_API_KEY"),
            Some("sk-proj-abc123")
        );
        assert_eq!(
            res.input.secrets.get("DATABASE_URL"),
            Some("postgres://u:p@h/db")
        );

        let (sealed, keys) = render_sealed_env(raw);
        assert_eq!(keys, vec!["OPENAI_API_KEY", "DATABASE_URL"]);
        assert!(sealed.contains("OPENAI_API_KEY={{openkeylet:OPENAI_API_KEY}}"));
        assert!(sealed.contains("DATABASE_URL={{openkeylet:DATABASE_URL}}"));
        assert!(sealed.contains("# Production"));
    }

    #[test]
    fn detects_totp_uri() {
        let uri = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
        let res = smart_parse(uri, None, None).unwrap();
        assert_eq!(res.kind, "totp");
        assert_eq!(res.totp_issuer.as_deref(), Some("GitHub"));
        assert_eq!(res.totp_account.as_deref(), Some("octocat"));
        assert_eq!(res.input.secrets.get("totp"), Some(uri));
    }

    #[test]
    fn detects_chinese_server_info_block() {
        let note = "IP: 198.51.100.8\n端口：2200\n账号：root\n密码：P@ssw0rd!";
        let res = smart_parse(note, None, None).unwrap();
        assert_eq!(res.kind, "serverInfo");
        assert_eq!(res.input.item_type, "ssh");
        assert_eq!(res.input.secrets.get("username"), Some("root"));
        assert_eq!(res.input.secrets.get("password"), Some("P@ssw0rd!"));
    }

    #[test]
    fn parses_ssh_config_with_wildcard_defaults() {
        let cfg = b"Host *\n  User ops\n  Port 2222\n\nHost prod-tokyo\n  HostName 198.51.100.42\n\nHost staging\n  HostName 198.51.100.43\n  User deploy\n";
        let (entries, preview) = parse_ssh_config_bytes(cfg, None).unwrap();
        assert_eq!(preview.total, 2);
        assert_eq!(entries[0].0.name, "prod-tokyo");
        assert_eq!(entries[0].1.get("username"), Some("ops"));
        assert_eq!(entries[1].0.name, "staging");
        assert_eq!(entries[1].1.get("username"), Some("deploy"));
    }

    #[test]
    fn strips_utf8_bom_on_windows_inputs() {
        let res = smart_parse("\u{feff}sk-ant-api03-bom-test-12345", None, None).unwrap();
        assert_eq!(res.kind, "apiKey");
        assert_eq!(res.input.name, "Anthropic API");

        let ssh_bom = b"\xef\xbb\xbfHost win-box\r\n  HostName 198.51.100.7\r\n  User admin\r\n";
        let (entries, preview) = parse_ssh_config_bytes(ssh_bom, None).unwrap();
        assert_eq!(preview.total, 1);
        assert_eq!(entries[0].0.name, "win-box");

        let (sealed, keys) = render_sealed_env("\u{feff}MY_SECRET=abc123\r\n");
        assert_eq!(keys, vec!["MY_SECRET"]);
        assert!(sealed.contains("MY_SECRET={{openkeylet:MY_SECRET}}"));
    }
}
