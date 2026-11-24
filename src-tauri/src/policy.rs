use crate::model::{
    MAX_AGENT_NOTE_AUTHOR_CHARS, MAX_AGENT_NOTE_CHARS, SecretBundle, StoredConnection,
};
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::header::HeaderMap;
use std::collections::HashSet;
use url::Url;

pub fn validate_ssh_command(command: &str) -> Result<String> {
    let value = command.trim();
    if value.is_empty() {
        bail!("Command cannot be empty");
    }
    if value.contains('\0') {
        bail!("SSH command cannot contain a null character");
    }
    Ok(value.to_owned())
}

pub fn normalize_api_request_method(method: &str, target: &Url) -> Result<String> {
    let normalized = method.trim().to_uppercase();
    if !matches!(target.scheme(), "http" | "https") {
        bail!("API URL must use HTTP or HTTPS");
    }
    Ok(normalized)
}

pub fn redirect_target_supported(target: &Url) -> bool {
    matches!(target.scheme(), "http" | "https")
}

pub fn blocked_header_names(connection: &StoredConnection) -> HashSet<String> {
    let mut blocked = HashSet::new();
    if connection.auth_location != "query" && !connection.auth_header.is_empty() {
        blocked.insert(connection.auth_header.to_lowercase());
    }
    blocked.extend(
        connection
            .api_auth_headers
            .iter()
            .map(|header| header.name.to_lowercase()),
    );
    blocked
}

pub fn visible_response_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}

pub fn redact(mut value: String, connection: &StoredConnection, secrets: &SecretBundle) -> String {
    let raw_secrets = secrets.non_empty_values();
    value = redact_values(value, &raw_secrets);
    let mut candidates = Vec::new();
    for secret in &raw_secrets {
        candidates.push(STANDARD.encode(secret.as_bytes()));
        candidates.push(url::form_urlencoded::byte_serialize(secret.as_bytes()).collect());
    }
    if let Some(token) = &secrets.token {
        candidates.push(format!("Bearer {token}"));
    }
    if connection.http_auth_type == "basic" {
        if let (Some(username), Some(password)) = (secrets.get("username"), &secrets.password) {
            candidates.push(STANDARD.encode(format!("{username}:{password}")));
        }
    }
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.len()));
    candidates.dedup();
    for candidate in candidates {
        if candidate.len() >= 4 {
            value = value.replace(&candidate, "[REDACTED]");
        }
    }
    value
}

pub fn redact_values(mut value: String, raw_secrets: &[String]) -> String {
    for candidate in redaction_candidates(raw_secrets) {
        value = value.replace(&candidate, "[REDACTED]");
    }
    value
}

pub fn redaction_candidates(raw_secrets: &[String]) -> Vec<String> {
    let mut candidates = raw_secrets.to_vec();
    for secret in raw_secrets {
        candidates.push(STANDARD.encode(secret.as_bytes()));
        candidates.push(url::form_urlencoded::byte_serialize(secret.as_bytes()).collect());
    }
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.len()));
    candidates.dedup();
    candidates.retain(|candidate| !candidate.is_empty());
    candidates
}

pub fn sanitize_agent_note_text(raw: &str) -> Result<String> {
    let cleaned = raw
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if cleaned.is_empty() {
        bail!("Agent note cannot be empty");
    }
    if cleaned.chars().count() > MAX_AGENT_NOTE_CHARS {
        bail!(
            "Agent note cannot exceed {} characters",
            MAX_AGENT_NOTE_CHARS
        );
    }
    Ok(cleaned)
}

pub fn sanitize_agent_note_author(raw: &str) -> String {
    let cleaned = raw
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let truncated: String = cleaned.chars().take(MAX_AGENT_NOTE_AUTHOR_CHARS).collect();
    if truncated.is_empty() {
        "MCP CLIENT".to_owned()
    } else {
        truncated
    }
}

fn contains_secret_pattern(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if lower.contains("-----begin ")
        || lower.contains("otpauth://")
        || lower.contains("okv1_")
        || lower.contains("oka1_")
    {
        return true;
    }
    const TOKEN_PREFIXES: &[&str] = &[
        "sk-proj-",
        "sk-ant-",
        "sk-live-",
        "sk-test-",
        "sk-or-",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
    ];
    for prefix in TOKEN_PREFIXES {
        if let Some(pos) = text.find(prefix) {
            let tail_len = text[pos + prefix.len()..]
                .chars()
                .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
                .count();
            if tail_len >= 10 {
                return true;
            }
        }
    }
    // AWS access key IDs (AKIA + 16 uppercase alnum) or Google API keys (AIza + 20+ token chars)
    for token in text.split_whitespace() {
        let trimmed = token.trim_matches(|ch: char| {
            matches!(ch, '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}')
        });
        if trimmed.len() == 20
            && trimmed.starts_with("AKIA")
            && trimmed[4..]
                .chars()
                .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
        {
            return true;
        }
        if trimmed.len() >= 28
            && trimmed.starts_with("AIza")
            && trimmed
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
        {
            return true;
        }
        if trimmed.len() >= 36
            && trimmed.starts_with("eyJ")
            && trimmed.matches('.').count() == 2
            && trimmed
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
        {
            return true;
        }
    }
    false
}

fn secret_values_for_note_guard(
    stored: &StoredConnection,
    secrets: &SecretBundle,
    is_target: bool,
) -> Vec<(String, usize)> {
    let min_len = if is_target { 4 } else { 6 };
    let mut values = Vec::new();
    for value in [
        secrets.password.as_deref(),
        secrets.passphrase.as_deref(),
        secrets.private_key.as_deref(),
        secrets.token.as_deref(),
        secrets.api_key.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !value.is_empty() {
            values.push((value.to_owned(), min_len));
        }
    }
    for entry in &secrets.password_history {
        if !entry.password.is_empty() {
            values.push((entry.password.clone(), min_len));
        }
    }
    let username_hidden = stored
        .modules
        .iter()
        .find(|m| m.kind == "username")
        .is_some_and(|m| !m.agent_visible());
    for (name, value) in secrets.named_secrets.iter() {
        if value.is_empty() {
            continue;
        }
        if name == "username" {
            // Avoid blocking generic words like "root" or "admin" in usage notes,
            // while still protecting longer hidden usernames on the target item.
            if is_target && username_hidden {
                values.push((value.clone(), 6));
            }
            continue;
        }
        values.push((value.clone(), min_len));
    }
    values
}

pub fn validate_agent_note_no_secrets(
    note: &str,
    target: (&StoredConnection, &SecretBundle),
    all_connections: &[(&StoredConnection, &SecretBundle)],
) -> Result<()> {
    const REJECT_MSG: &str = "Refused to save agent note because it appears to contain a secret value. Write only non-sensitive context such as server role, environment, workspace path, or account purpose.";
    if contains_secret_pattern(note) {
        bail!("{REJECT_MSG}");
    }
    for &(stored, secrets) in all_connections {
        let is_target = stored.id == target.0.id;
        for (secret, min_len) in secret_values_for_note_guard(stored, secrets, is_target) {
            if secret.len() >= min_len && note.contains(&secret) {
                bail!("{REJECT_MSG}");
            }
            // Catch partial lines from multi-line PEM private keys or long credentials.
            if secret.contains('\n') {
                for line in secret.lines().map(str::trim) {
                    if line.len() >= 24
                        && !line.starts_with("-----")
                        && note.contains(line)
                    {
                        bail!("{REJECT_MSG}");
                    }
                }
            }
            if secret.len() >= 6 {
                let encoded = STANDARD.encode(secret.as_bytes());
                if encoded.len() >= 8 && note.contains(&encoded) {
                    bail!("{REJECT_MSG}");
                }
                let url_encoded: String =
                    url::form_urlencoded::byte_serialize(secret.as_bytes()).collect();
                if url_encoded.len() >= 6 && note.contains(&url_encoded) {
                    bail!("{REJECT_MSG}");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SecretEnvelope;
    use chrono::Utc;
    use uuid::Uuid;

    fn connection() -> StoredConnection {
        StoredConnection {
            login_uris: Vec::new(),
            item_type: String::new(),
            folder: String::new(),
            favorite: false,
            id: Uuid::new_v4(),
            modules: vec![],
            name: "test".into(),
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            description: String::new(),
            host: String::new(),
            port: 0,
            ssh_auth_type: String::new(),
            http_auth_type: "bearer".into(),
            private_key_name: String::new(),
            base_url: "https://api.example.com/v1/".into(),
            auth_header: "X-API-Key".into(),
            auth_location: "header".into(),
            auth_prefix: String::new(),
            api_auth_headers: vec![],
            test_path: String::new(),
            secret: None,
            encrypted_secrets: SecretEnvelope {
                version: 1,
                nonce: String::new(),
                ciphertext: String::new(),
            },
        }
    }

    #[test]
    fn api_accepts_any_http_target_and_method() {
        for (method, target) in [
            ("POST", "https://api.example.com/v1/items"),
            ("PROPFIND", "https://other.example/other/path"),
            ("GET", "http://api.example.com/test"),
        ] {
            assert!(normalize_api_request_method(method, &Url::parse(target).unwrap()).is_ok());
        }
        assert!(
            normalize_api_request_method(
                "GET",
                &Url::parse("ftp://files.example.com/test").unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn redirects_follow_any_http_target() {
        assert!(redirect_target_supported(
            &Url::parse("https://api.example.com/v2/items").unwrap()
        ));
        assert!(redirect_target_supported(
            &Url::parse("https://other.example/v2/items").unwrap()
        ));
        assert!(redirect_target_supported(
            &Url::parse("http://api.example.com/v2/items").unwrap()
        ));
        assert!(!redirect_target_supported(
            &Url::parse("ftp://files.example.com/items").unwrap()
        ));
    }

    #[test]
    fn redacts_raw_and_bearer_secret() {
        let connection = connection();
        let mut secrets = SecretBundle::default();
        secrets.token = Some("abc123secret".into());
        let result = redact(
            "Bearer abc123secret / abc123secret".into(),
            &connection,
            &secrets,
        );
        assert!(!result.contains("abc123secret"));
    }

    #[test]
    fn ssh_validation_accepts_commands_without_classifying_their_purpose() {
        for command in [
            "hostname",
            "nvidia-smi --query-gpu=name,memory.total --format=csv",
            "head /srv/app/.env | grep TOKEN",
            "mkdir -p /srv/train && python train.py --epochs 20",
            "printf fixture-ok > /tmp/openkeylet-probe",
        ] {
            assert!(
                validate_ssh_command(command).is_ok(),
                "valid command should be accepted: {command}"
            );
        }
        assert!(validate_ssh_command("  ").is_err());
        assert!(validate_ssh_command("printf 'a\0b'").is_err());
        assert!(validate_ssh_command(&"x".repeat(256_000)).is_ok());
        assert!(validate_ssh_command(&"x".repeat(2 * 1_048_576)).is_ok());
    }

    #[test]
    fn reserves_only_headers_that_openkeylet_injects() {
        let blocked = blocked_header_names(&connection());
        assert!(blocked.contains("x-api-key"));
        for name in ["host", "authorization", "cookie", "proxy-authorization"] {
            assert!(!blocked.contains(name));
        }
    }

    #[test]
    fn response_headers_are_returned_without_classification() {
        let mut headers = HeaderMap::new();
        headers.insert("x-feature-state", "ready".parse().unwrap());
        headers.append("set-cookie", "session=server-secret".parse().unwrap());

        let visible = visible_response_headers(&headers)
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            visible.get("x-feature-state").map(String::as_str),
            Some("ready")
        );
        assert_eq!(
            visible.get("set-cookie").map(String::as_str),
            Some("session=server-secret")
        );
    }

    #[test]
    fn agent_note_sanitization_and_secret_guards_work() {
        assert_eq!(
            sanitize_agent_note_text("  Prod\nGPU\tserver  /srv/ml ").unwrap(),
            "Prod GPU server /srv/ml"
        );
        assert!(sanitize_agent_note_text("   \n\t ").is_err());
        assert!(sanitize_agent_note_text(&"a".repeat(201)).is_err());
        assert_eq!(sanitize_agent_note_text(&"中".repeat(200)).unwrap().chars().count(), 200);

        let conn = connection();
        let mut secrets = SecretBundle::default();
        secrets.password = Some("Sup3rS3cretPass!".into());
        secrets.token = Some("my-secret-api-token-99".into());
        secrets
            .named_secrets
            .insert("username".into(), "root".into());

        let pairs = vec![(&conn, &secrets)];
        // Non-secret usage context (including generic "root") is accepted
        assert!(
            validate_agent_note_no_secrets(
                "Ubuntu 24.04 prod node, SSH as root, app at /srv/web",
                (&conn, &secrets),
                &pairs,
            )
            .is_ok()
        );
        // Raw stored secret is rejected
        assert!(
            validate_agent_note_no_secrets(
                "Password is Sup3rS3cretPass! for admin",
                (&conn, &secrets),
                &pairs,
            )
            .is_err()
        );
        // Base64-encoded stored secret is rejected
        let b64 = STANDARD.encode(b"my-secret-api-token-99");
        assert!(
            validate_agent_note_no_secrets(
                &format!("Encoded token {b64}"),
                (&conn, &secrets),
                &pairs,
            )
            .is_err()
        );
        // Well-known token prefixes / PEM markers are rejected even if not in vault
        assert!(
            validate_agent_note_no_secrets(
                "Uses key sk-proj-abcdefghijklmnop",
                (&conn, &secrets),
                &pairs,
            )
            .is_err()
        );
        assert!(
            validate_agent_note_no_secrets(
                "-----BEGIN OPENSSH PRIVATE KEY-----",
                (&conn, &secrets),
                &pairs,
            )
            .is_err()
        );
    }
}
