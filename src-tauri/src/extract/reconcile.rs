use super::*;

pub(super) fn reconcile_with_vault(candidates: &mut [ExtractedCandidate], existing: &[DecryptedConnection]) {
    for cand in candidates.iter_mut() {
        let mut best_match: Option<(&DecryptedConnection, bool)> = None; // (conn, exact_duplicate)
        for conn in existing {
            if let Some(exact) = compare_candidate_with_existing(cand, conn) {
                match best_match {
                    None => best_match = Some((conn, exact)),
                    Some((_, false)) if exact => best_match = Some((conn, true)),
                    _ => {}
                }
                if exact {
                    break;
                }
            }
        }
        if let Some((conn, exact)) = best_match {
            cand.existing_item_id = Some(conn.stored.id.to_string());
            cand.existing_item_name = Some(conn.stored.name.clone());
            if exact {
                cand.match_status = "duplicate".to_owned();
                cand.selected = false;
                cand.update_existing = false;
            } else {
                cand.match_status = "update".to_owned();
                cand.selected = true;
                cand.update_existing = true;
            }
        } else {
            cand.match_status = "new".to_owned();
            cand.update_existing = false;
        }
    }
}

pub(super) fn compare_candidate_with_existing(
    cand: &ExtractedCandidate,
    conn: &DecryptedConnection,
) -> Option<bool> {
    let cand_secrets = &cand.input.secrets;
    let conn_secrets = &conn.secrets;

    // 1. Exact API token / TOTP / Private key match
    if let (Some(a), Some(b)) = (
        cand_secrets.get("apiCredential"),
        conn_secrets.get("apiCredential"),
    ) {
        if a == b {
            return Some(true);
        }
        if cand.input.name.eq_ignore_ascii_case(&conn.stored.name) {
            return Some(false);
        }
    }
    if let (Some(a), Some(b)) = (cand_secrets.get("totp"), conn_secrets.get("totp"))
        && a == b
    {
        return Some(true);
    }
    if let (Some(a), Some(b)) = (cand_secrets.get("privateKey"), conn_secrets.get("privateKey"))
        && a.trim() == b.trim()
    {
        return Some(true);
    }

    // 2. SSH / Database host + username match
    let cand_host = module_val(&cand.input.modules, "host");
    let conn_host = module_val(&conn.stored.modules, "host");
    if let (Some(ch), Some(eh)) = (cand_host, conn_host)
        && ch.eq_ignore_ascii_case(eh)
    {
        let cu = cand_secrets.get("username");
        let eu = conn_secrets.get("username");
        if cu.is_some() && cu == eu {
            let cp = cand_secrets.get("password");
            let ep = conn_secrets.get("password");
            return Some(cp == ep);
        }
    }

    // 3. Login URL domain + username match
    let cand_domain = cand
        .input
        .login_uris
        .first()
        .and_then(|u| host_from_url(&u.uri))
        .or_else(|| module_val(&cand.input.modules, "url").and_then(host_from_url));
    let conn_domain = conn
        .stored
        .login_uris
        .first()
        .and_then(|u| host_from_url(&u.uri))
        .or_else(|| module_val(&conn.stored.modules, "url").and_then(host_from_url));
    if let (Some(cd), Some(ed)) = (cand_domain, conn_domain)
        && cd.eq_ignore_ascii_case(&ed)
    {
        let cu = cand_secrets.get("username");
        let eu = conn_secrets.get("username");
        if cu.is_some() && cu == eu {
            let cp = cand_secrets.get("password");
            let ep = conn_secrets.get("password");
            return Some(cp == ep);
        }
    }

    // 4. Same name & item_type fallback
    if cand.input.name.eq_ignore_ascii_case(&conn.stored.name)
        && cand.input.item_type == conn.stored.item_type()
    {
        let same_pass = cand_secrets.password == conn_secrets.password
            && cand_secrets.named_secrets.0 == conn_secrets.named_secrets.0;
        return Some(same_pass);
    }

    None
}

pub(super) fn module_val<'a>(modules: &'a [ItemModule], kind: &str) -> Option<&'a str> {
    modules
        .iter()
        .find(|m| m.kind == kind && !m.value.trim().is_empty())
        .map(|m| m.value.trim())
}

pub(super) fn candidate_dedup_key(cand: &ExtractedCandidate) -> String {
    if let Some(tok) = cand.input.secrets.get("apiCredential") {
        return format!("api:{tok}");
    }
    if let Some(uri) = cand.input.secrets.get("Connection URI") {
        return format!("uri:{uri}");
    }
    if let Some(totp) = cand.input.secrets.get("totp") {
        return format!("totp:{totp}");
    }
    if let Some(host) = module_val(&cand.input.modules, "host") {
        return format!(
            "host:{}:{}:{}:{}",
            host.to_ascii_lowercase(),
            module_val(&cand.input.modules, "port").unwrap_or("22"),
            cand.input.secrets.get("username").unwrap_or(""),
            cand.input.secrets.get("password").unwrap_or("")
        );
    }
    if let Some(pk) = cand.input.secrets.get("privateKey") {
        return format!("pk:{}", pk.trim());
    }
    if let Some(url) = module_val(&cand.input.modules, "url") {
        return format!(
            "login:{}:{}:{}",
            host_from_url(url).unwrap_or_else(|| url.to_ascii_lowercase()),
            cand.input.secrets.get("username").unwrap_or(""),
            cand.input.secrets.get("password").unwrap_or("")
        );
    }
    if !cand.input.secrets.named_secrets.0.is_empty() {
        let mut pairs: Vec<String> = cand
            .input
            .secrets
            .named_secrets
            .0
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        pairs.sort();
        return format!("kv:{}:{}", cand.kind, pairs.join("&"));
    }
    format!("name:{}:{}", cand.kind, cand.input.name.to_ascii_lowercase())
}

pub(super) fn push_unique(
    candidates: &mut Vec<ExtractedCandidate>,
    seen: &mut HashSet<String>,
    cand: ExtractedCandidate,
) {
    let key = candidate_dedup_key(&cand);
    if key.is_empty() || seen.insert(key) {
        candidates.push(cand);
    }
}

pub(super) fn candidate_from_smart_parse(
    mut parsed: ingest::SmartParseResult,
    heading_override: Option<&str>,
    source_snippet: &str,
) -> ExtractedCandidate {
    if let Some(h) = heading_override
        && !h.trim().is_empty()
        && matches!(
            parsed.kind.as_str(),
            "connectionUri" | "privateKey" | "sshCommand" | "curl"
        )
    {
        parsed.input.name = sanitize_name(h, 80);
    }
    let (kind, badge, badge_zh) = match parsed.kind.as_str() {
        "apiKey" | "curl" => ("apiKey", "API", "API"),
        "serverInfo" if parsed.input.item_type == "api" => ("apiKey", "API", "API"),
        "totp" => ("totp", "2FA", "2FA"),
        "privateKey" => ("privateKey", "KEY", "私钥"),
        "connectionUri" => ("database", "DB", "数据库"),
        "sshCommand" | "sshConfig" | "serverInfo" if parsed.input.item_type == "ssh" => {
            ("ssh", "SSH", "SSH")
        }
        "env" => ("env", "ENV", "环境"),
        _ => ("login", "LOGIN", "账号"),
    };
    make_candidate(
        kind,
        badge,
        badge_zh,
        "high",
        parsed.summary,
        source_snippet.to_owned(),
        parsed.input,
        parsed.totp_uri,
    )
}

pub(super) fn candidate_from_portable(
    portable: PortableConnection,
    secrets: SecretBundle,
    kind: &str,
    badge: &str,
    badge_zh: &str,
    source: &str,
) -> ExtractedCandidate {
    let summary = portable
        .modules
        .iter()
        .find(|m| matches!(m.kind.as_str(), "url" | "host") && !m.value.is_empty())
        .map(|m| m.value.clone())
        .or_else(|| {
            portable
                .login_uris
                .first()
                .map(|u| u.uri.clone())
        })
        .unwrap_or_else(|| portable.description.clone());
    let totp_uri = secrets.get("totp").map(str::to_owned);
    let input = ConnectionInput {
        login_uris: portable.login_uris,
        item_type: portable.item_type,
        folder: portable.folder,
        favorite: portable.favorite,
        id: None,
        modules: portable.modules,
        name: portable.name,
        enabled: portable.enabled,
        description: portable.description,
        http_auth_type: portable.http_auth_type,
        private_key_import_path: String::new(),
        auth_header: portable.auth_header,
        auth_location: portable.auth_location,
        auth_prefix: portable.auth_prefix,
        api_auth_headers: portable.api_auth_headers,
        test_path: portable.test_path,
        remove_secret_names: Vec::new(),
        secrets,
    };
    make_candidate(
        kind,
        badge,
        badge_zh,
        "high",
        summary,
        source.to_owned(),
        input,
        totp_uri,
    )
}

pub(super) fn classify_portable_kind(p: &PortableConnection) -> (&'static str, &'static str, &'static str) {
    match p.item_type.as_str() {
        "api" => ("apiKey", "API", "API"),
        "ssh" => ("ssh", "SSH", "SSH"),
        "login" => ("login", "LOGIN", "账号"),
        "secureNote" => ("custom", "NOTE", "笔记"),
        _ => ("custom", "ITEM", "凭据"),
    }
}

pub(super) fn sanitize_http_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let normalized = api_catalog::normalize_base_url(trimmed, "").ok()?;
    let mut parsed = Url::parse(&normalized).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return None;
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        let _ = parsed.set_username("");
        let _ = parsed.set_password(None);
        return Some(parsed.to_string());
    }
    let out = parsed.to_string();
    if !trimmed.ends_with('/')
        && parsed.path() == "/"
        && parsed.query().is_none()
        && parsed.fragment().is_none()
    {
        Some(out.trim_end_matches('/').to_owned())
    } else {
        Some(out)
    }
}

pub(super) fn normalized_secret_field_name(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace() && !matches!(character, '_' | '-'))
        .flat_map(char::to_lowercase)
        .collect()
}

pub(super) fn is_reserved_custom_secret_name(value: &str) -> bool {
    let norm = normalized_secret_field_name(value);
    crate::item_types::CARD_FIELDS
        .iter()
        .chain(crate::item_types::IDENTITY_FIELDS)
        .chain(std::iter::once(&"secureNote"))
        .any(|name| normalized_secret_field_name(name) == norm)
        || matches!(
            norm.as_str(),
            "username"
                | "password"
                | "apicredential"
                | "privatekey"
                | "passphrase"
                | "totp"
                | "token"
                | "apikey"
        )
}

pub(super) fn push_vault_safe_secret_module(
    input: &mut ConnectionInput,
    raw_key: &str,
    value: String,
) {
    let base_name = sanitize_name(raw_key, 64);
    let norm = normalized_secret_field_name(&base_name);
    let has_kind = |mods: &[ItemModule], kind: &str| mods.iter().any(|m| m.kind == kind);

    // Map canonical built-in secret names directly to their first-class Vault module when unused
    match norm.as_str() {
        "username" if !has_kind(&input.modules, "username") => {
            input.modules.push(secret_mod("username", "username"));
            input.secrets.named_secrets.insert("username".to_owned(), value);
            return;
        }
        "password" if !has_kind(&input.modules, "password") => {
            input.modules.push(secret_mod("password", "password"));
            input.secrets.password = Some(value);
            return;
        }
        "passphrase" if !has_kind(&input.modules, "passphrase") => {
            input.modules.push(secret_mod("passphrase", "passphrase"));
            input.secrets.passphrase = Some(value);
            return;
        }
        "privatekey" if !has_kind(&input.modules, "privateKey") => {
            input.modules.push(secret_mod("privateKey", "privateKey"));
            input.secrets.private_key = Some(value);
            return;
        }
        "totp" if !has_kind(&input.modules, "totp") => {
            input.modules.push(secret_mod("totp", "totp"));
            input.secrets.named_secrets.insert("totp".to_owned(), value);
            return;
        }
        "apicredential" | "token" | "apikey" if !has_kind(&input.modules, "apiCredential") => {
            input.modules.push(secret_mod("apiCredential", "apiCredential"));
            input.secrets.named_secrets.insert("apiCredential".to_owned(), value);
            return;
        }
        "securenote" if !has_kind(&input.modules, "secureNote") => {
            input.modules.push(secret_mod("secureNote", "secureNote"));
            input.secrets.named_secrets.insert("secureNote".to_owned(), value);
            return;
        }
        _ => {}
    }

    // Otherwise emit a valid, non-reserved, deduplicated customSecret field name
    let mut candidate_name = if is_reserved_custom_secret_name(&base_name) {
        sanitize_name(&format!("{base_name}_secret"), 64)
    } else {
        base_name
    };
    let mut suffix = 2usize;
    while is_reserved_custom_secret_name(&candidate_name)
        || input.modules.iter().any(|m| {
            m.secret_name().is_some_and(|n| {
                normalized_secret_field_name(n) == normalized_secret_field_name(&candidate_name)
            })
        })
    {
        candidate_name = sanitize_name(&format!("{raw_key}_{suffix}"), 64);
        suffix += 1;
    }
    input.modules.push(secret_mod("customSecret", &candidate_name));
    input.secrets.named_secrets.insert(candidate_name, value);
}

pub(super) fn build_api_candidate(
    name: &str,
    token: &str,
    profile: api_catalog::ApiProfile,
    base_url: Option<String>,
    source: &str,
    confidence: &str,
) -> ExtractedCandidate {
    let mut input = blank_input("api", name);
    let resolved_url = base_url
        .as_deref()
        .and_then(sanitize_http_url)
        .or_else(|| sanitize_http_url(profile.default_base_url));
    if let Some(ref url) = resolved_url {
        input.modules.push(public_mod("url", "url", url));
    }
    input.modules.push(secret_mod("apiCredential", "apiCredential"));
    input
        .secrets
        .named_secrets
        .insert("apiCredential".to_owned(), token.to_owned());
    input.http_auth_type = profile.auth_type.to_owned();
    input.auth_header = profile.auth_header.to_owned();
    input.auth_location = profile.auth_location.to_owned();
    input.auth_prefix = profile.auth_prefix.to_owned();

    let summary = resolved_url
        .as_deref()
        .map(|u| format!("{name} · {}", compact_url(u)))
        .unwrap_or_else(|| format!("{name} · {}", mask_preview(token)));
    make_candidate(
        "apiKey",
        "API",
        "API",
        confidence,
        summary,
        source.to_owned(),
        input,
        None,
    )
}

pub(super) fn build_login_candidate(
    name: &str,
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    source: &str,
    confidence: &str,
) -> ExtractedCandidate {
    let mut input = blank_input("login", name);
    let clean_url = url.as_deref().and_then(sanitize_http_url);
    if let Some(ref u) = clean_url {
        input.modules.push(public_mod("url", "url", u));
        input.login_uris.push(LoginUri {
            uri: u.clone(),
            match_type: "domain".to_owned(),
        });
    }
    if let Some(ref u) = username {
        input.modules.push(secret_mod("username", "username"));
        input
            .secrets
            .named_secrets
            .insert("username".to_owned(), u.clone());
    }
    if let Some(ref p) = password {
        input.modules.push(secret_mod("password", "password"));
        input.secrets.password = Some(p.clone());
    }
    let mut totp_uri = None;
    if let Some(ref t) = totp
        && t.starts_with("otpauth://")
    {
        input.modules.push(secret_mod("totp", "totp"));
        input
            .secrets
            .named_secrets
            .insert("totp".to_owned(), t.clone());
        totp_uri = Some(t.clone());
    }
    let summary = match (&clean_url, &username) {
        (Some(u), Some(usr)) => format!("{} · {}", compact_url(u), usr),
        (Some(u), None) => compact_url(u),
        (None, Some(usr)) => usr.clone(),
        (None, None) => name.to_owned(),
    };
    make_candidate(
        "login",
        "LOGIN",
        "账号",
        confidence,
        summary,
        source.to_owned(),
        input,
        totp_uri,
    )
}

pub(super) fn build_ssh_candidate(
    name: &str,
    host: &str,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    source: &str,
) -> ExtractedCandidate {
    let safe_port = if port == 0 { 22 } else { port };
    let mut input = blank_input("ssh", name);
    input.modules.push(public_mod("host", "host", host));
    input
        .modules
        .push(public_mod("port", "port", &safe_port.to_string()));
    if let Some(ref u) = username {
        input.modules.push(secret_mod("username", "username"));
        input
            .secrets
            .named_secrets
            .insert("username".to_owned(), u.clone());
    }
    if let Some(ref p) = password {
        input.modules.push(secret_mod("password", "password"));
        input.secrets.password = Some(p.clone());
    }
    let summary = match &username {
        Some(u) => format!("{u}@{host}:{safe_port}"),
        None => format!("{host}:{safe_port}"),
    };
    make_candidate(
        "ssh",
        "SSH",
        "SSH",
        "high",
        summary,
        source.to_owned(),
        input,
        None,
    )
}

pub(super) fn build_env_group_candidate(
    pairs: &[(String, String)],
    filename: Option<&str>,
    fallback_source: &str,
) -> ExtractedCandidate {
    let base_name = filename
        .and_then(|f| {
            let leaf = Path::new(f).file_name().and_then(|s| s.to_str())?.trim();
            if leaf.is_empty() {
                return None;
            }
            if let Some(ctx) = short_source_context(f)
                && !ctx.eq_ignore_ascii_case(leaf)
            {
                return Some(format!("Env · {ctx} ({leaf})"));
            }
            Some(format!("Env · {leaf}"))
        })
        .unwrap_or_else(|| {
            if pairs.len() == 1 {
                pairs[0].0.clone()
            } else {
                format!("Env Secrets ({})", pairs.len())
            }
        });
    let mut input = blank_input("custom", &base_name);
    input.folder = "Env".to_owned();
    input.description = format!("{} secret keys", pairs.len());
    for (k, v) in pairs {
        push_vault_safe_secret_module(&mut input, k, v.clone());
    }
    let summary = pairs
        .iter()
        .take(3)
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    make_candidate(
        "env",
        "ENV",
        "环境",
        "medium",
        format!("{} keys · {summary}", pairs.len()),
        fallback_source.to_owned(),
        input,
        None,
    )
}

pub(super) fn build_single_env_candidate(key: &str, value: &str, source: &str) -> ExtractedCandidate {
    let mut input = blank_input("custom", key);
    input.folder = "Env".to_owned();
    push_vault_safe_secret_module(&mut input, key, value.to_owned());
    make_candidate(
        "env",
        "ENV",
        "环境",
        "low",
        format!("{key} = {}", truncate_chars(value, 24)),
        source.to_owned(),
        input,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn make_candidate(
    kind: &str,
    badge: &str,
    badge_zh: &str,
    confidence: &str,
    summary: String,
    source_snippet: String,
    mut input: ConnectionInput,
    totp_uri: Option<String>,
) -> ExtractedCandidate {
    if input.description.chars().count() > 240 {
        input.description = truncate_chars(&input.description, 240);
    }
    if input.folder.chars().count() > 120 {
        input.folder = truncate_chars(&input.folder, 120);
    }
    let fields = build_field_previews(&input);
    ExtractedCandidate {
        id: Uuid::new_v4().to_string(),
        kind: kind.to_owned(),
        badge: badge.to_owned(),
        badge_zh: badge_zh.to_owned(),
        confidence: confidence.to_owned(),
        selected: confidence != "low",
        summary,
        source_snippet: truncate_chars(&source_snippet, 80),
        match_status: "new".to_owned(),
        existing_item_id: None,
        existing_item_name: None,
        update_existing: false,
        fields,
        input,
        totp_uri,
        source_paths: Vec::new(),
        source_refs: Vec::new(),
    }
}

pub(super) fn build_field_previews(input: &ConnectionInput) -> Vec<ExtractedFieldPreview> {
    let mut fields = Vec::new();
    for m in &input.modules {
        let is_secret = !m.agent_visible.unwrap_or(false)
            || matches!(
                m.kind.as_str(),
                "password" | "passphrase" | "apiCredential" | "privateKey" | "totp" | "customSecret" | "username" | "secureNote"
            );
        if is_secret {
            let val = if m.kind == "password" {
                input.secrets.password.clone().unwrap_or_default()
            } else if m.kind == "passphrase" {
                input.secrets.passphrase.clone().unwrap_or_default()
            } else if m.kind == "privateKey" {
                input.secrets.private_key.clone().unwrap_or_default()
            } else {
                input
                    .secrets
                    .named_secrets
                    .get(&m.name)
                    .or_else(|| input.secrets.named_secrets.get(&m.kind))
                    .cloned()
                    .unwrap_or_default()
            };
            if val.is_empty() {
                continue;
            }
            let is_username = m.kind == "username";
            let masked = if is_username {
                val.clone()
            } else if m.kind == "privateKey" {
                input
                    .secrets
                    .private_key_name
                    .clone()
                    .unwrap_or_else(|| "PEM Key".to_owned())
            } else {
                mask_preview(&val)
            };
            fields.push(ExtractedFieldPreview {
                label: friendly_field_label(&m.name, &m.kind),
                masked,
                value: val,
                secret: !is_username,
            });
        } else if !m.value.trim().is_empty() {
            fields.push(ExtractedFieldPreview {
                label: friendly_field_label(&m.name, &m.kind),
                masked: m.value.clone(),
                value: m.value.clone(),
                secret: false,
            });
        }
    }
    fields
}

pub(super) fn friendly_field_label(name: &str, kind: &str) -> String {
    match kind {
        "url" => "URL".to_owned(),
        "host" => "Host".to_owned(),
        "port" => "Port".to_owned(),
        "username" => "User".to_owned(),
        "password" => "Password".to_owned(),
        "apiCredential" => "API Key".to_owned(),
        "privateKey" => "Private Key".to_owned(),
        "totp" => "2FA TOTP".to_owned(),
        _ => name.to_owned(),
    }
}

pub(super) fn blank_input(item_type: &str, name: &str) -> ConnectionInput {
    ConnectionInput {
        login_uris: Vec::new(),
        item_type: item_type.to_owned(),
        folder: String::new(),
        favorite: false,
        id: None,
        modules: Vec::new(),
        name: sanitize_name(name, 80),
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

pub(super) fn public_mod(kind: &str, name: &str, value: &str) -> ItemModule {
    ItemModule {
        kind: kind.to_owned(),
        name: name.to_owned(),
        value: value.to_owned(),
        agent_visible: Some(true),
    }
}

pub(super) fn secret_mod(kind: &str, name: &str) -> ItemModule {
    ItemModule {
        kind: kind.to_owned(),
        name: name.to_owned(),
        value: String::new(),
        agent_visible: Some(false),
    }
}

pub(super) fn sanitize_name(raw: &str, max_chars: usize) -> String {
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

pub(super) fn pretty_key_title(key: &str) -> String {
    let cleaned = key.replace(['_', '.', '/'], " ");
    sanitize_name(&cleaned, 60)
}

pub(super) fn host_from_url(raw: &str) -> Option<String> {
    let candidate = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    Url::parse(&candidate)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
}

pub(super) fn compact_url(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_owned()
}

pub(super) fn mask_preview(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    if chars.len() <= 6 {
        return "••••••".to_owned();
    }
    if chars.len() <= 12 {
        let head: String = chars[..2].iter().collect();
        let tail: String = chars[chars.len() - 2..].iter().collect();
        return format!("{head}••••{tail}");
    }
    let head: String = chars[..5].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}••••{tail}")
}

pub(super) fn mask_uri(raw: &str) -> String {
    if let Ok(mut url) = Url::parse(raw) {
        if url.password().is_some() {
            let _ = url.set_password(Some("••••"));
        }
        return url.to_string();
    }
    mask_preview(raw)
}

pub(super) fn truncate_chars(raw: &str, max: usize) -> String {
    let count = raw.chars().count();
    if count <= max {
        raw.to_owned()
    } else {
        let mut s: String = raw.chars().take(max.saturating_sub(1)).collect();
        s.push('…');
        s
    }
}

pub(super) fn strip_inline_quotes(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        return trimmed[1..trimmed.len() - 1].to_owned();
    }
    // Strip trailing YAML/TOML inline comment ` # ...`
    if let Some(pos) = trimmed.find(" #") {
        return trimmed[..pos].trim().to_owned();
    }
    trimmed.to_owned()
}

// ============================================================================
// Universal Multi-Format & Container Extractors (Office / ZIP / XML / Dev / Folder)
// ============================================================================

