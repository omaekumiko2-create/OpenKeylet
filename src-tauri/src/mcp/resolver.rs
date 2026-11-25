use super::*;

/// The full URL of an inspected page or frame for website-rule matching. The extension masks
/// query values in `url`, which goes to the agent, and sends the full URL as `matchUrl`, which
/// [`strip_match_urls`] removes before the result is returned. Older extensions send only
/// `url`.
pub(super) fn inspected_match_url(inspected: &Value) -> Option<&str> {
    inspected["matchUrl"]
        .as_str()
        .or_else(|| inspected["url"].as_str())
        .filter(|value| !value.is_empty())
}

pub(super) fn strip_match_urls(inspected: &mut Value) {
    if let Some(object) = inspected.as_object_mut() {
        object.remove("matchUrl");
    }
    if let Some(frames) = inspected["frames"].as_array_mut() {
        for frame in frames {
            if let Some(object) = frame.as_object_mut() {
                object.remove("matchUrl");
            }
        }
    }
}

pub(super) fn website_matches_stored(stored: &crate::model::StoredConnection, website: &str) -> bool {
    if !stored.login_uris.is_empty() {
        return stored
            .login_uris
            .iter()
            .any(|rule| crate::login_uri::matches(rule, website));
    }
    match (
        crate::passkey::origin(&stored.base_url),
        crate::passkey::origin(website),
    ) {
        (Ok(a), Ok(b)) => a.origin() == b.origin(),
        _ => false,
    }
}

/// Computes the exact frame origins permitted to receive login credentials for `stored`.
/// Prevents filling a site's saved password into an unrelated third-party HTTPS iframe
/// embedded on the same page while still supporting matching SSO / subdomain login iframes.
pub(super) fn allowed_login_frame_origins(
    stored: &crate::model::StoredConnection,
    page_url: &str,
    page_origin: &str,
    inspected: &Value,
) -> Vec<String> {
    let has_website_binding =
        !stored.login_uris.is_empty() || !stored.base_url.trim().is_empty();
    if !has_website_binding {
        return vec![page_origin.to_owned()];
    }
    let mut allowed = Vec::new();
    if website_matches_stored(stored, page_url) && !page_origin.is_empty() {
        allowed.push(page_origin.to_owned());
    }
    if let Some(frames) = inspected["frames"].as_array() {
        for frame in frames {
            let Some(frame_origin) = frame["frameOrigin"].as_str().filter(|v| !v.is_empty())
            else {
                continue;
            };
            let frame_url = inspected_match_url(frame).unwrap_or(frame_origin);
            if website_matches_stored(stored, frame_url)
                && !allowed.iter().any(|existing| existing == frame_origin)
            {
                allowed.push(frame_origin.to_owned());
            }
        }
    }
    allowed
}

/// Field names whose values identify an account or a person (login names, contact and
/// address details, card metadata) rather than authenticate it. They stay redacted in calls
/// that use their item, but are left out of the session-wide redaction set: redacting a
/// username such as "ubuntu" from every later command would shred paths and logs.
pub(super) fn is_identifier_field(name: &str) -> bool {
    name == "username"
        || (crate::item_types::personal_field(name)
            && !matches!(name, "cardNumber" | "cardSecurityCode" | "secureNote"))
}

/// Whether a named field's value joins the session-wide and vault-wide redaction sets.
/// Built-in secret fields always do. A custom field, such as one imported from a .env file,
/// does when its name says it is a credential or its value looks like a random token, so
/// that ordinary configuration (NODE_ENV=production, DB_HOST=localhost) is not redacted from
/// every later command's output. Calls that use the item still redact all of its values.
pub(super) fn field_holds_secret(name: &str, value: &str) -> bool {
    if is_identifier_field(name) {
        return false;
    }
    if matches!(
        name,
        "password"
            | "passphrase"
            | "privateKey"
            | "apiCredential"
            | "token"
            | "apiKey"
            | "totp"
            | "cardNumber"
            | "cardSecurityCode"
            | "secureNote"
    ) {
        return true;
    }
    const SECRET_NAME_PARTS: &[&str] = &[
        "key", "token", "secret", "pass", "pwd", "auth", "credential", "private", "dsn",
        "cookie", "session", "signature", "webhook", "salt",
    ];
    let lower = name.to_ascii_lowercase();
    SECRET_NAME_PARTS.iter().any(|part| lower.contains(part)) || looks_like_random_token(value)
}

fn looks_like_random_token(value: &str) -> bool {
    if value.contains("://") {
        // A URL is configuration unless it carries a password in its userinfo.
        return url::Url::parse(value).is_ok_and(|url| url.password().is_some());
    }
    if value.len() < 16 || value.chars().any(char::is_whitespace) {
        return false;
    }
    let classes = [
        value.chars().any(|ch| ch.is_ascii_lowercase()),
        value.chars().any(|ch| ch.is_ascii_uppercase()),
        value.chars().any(|ch| ch.is_ascii_digit()),
        value.chars().any(|ch| !ch.is_ascii_alphanumeric()),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    classes >= 3 || (classes >= 2 && value.len() >= 32)
}

pub(super) fn module_is_agent_visible(connection: &DecryptedConnection, name: &str) -> bool {
    connection
        .stored
        .modules
        .iter()
        .any(|module| module.secret_name() == Some(name) && module.agent_visible())
}

/// The secret values of `connection` that the agent cannot see, at least `min_chars` long
/// (see [`field_holds_secret`]). Values of modules the owner made agent-visible are left out
/// (items_search shows them), except TOTP seeds, of which the agent only sees the current code.
pub(super) fn hidden_secret_values(connection: &DecryptedConnection, min_chars: usize) -> Vec<String> {
    let secrets = &connection.secrets;
    let visible: HashSet<&str> = connection
        .stored
        .modules
        .iter()
        .filter(|module| module.agent_visible() && module.kind != "totp")
        .filter_map(|module| module.secret_name().and_then(|name| secrets.get(name)))
        .collect();
    let mut values: Vec<&str> = [
        secrets.password.as_deref(),
        secrets.passphrase.as_deref(),
        secrets.private_key.as_deref(),
        secrets.token.as_deref(),
        secrets.api_key.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect();
    values.extend(secrets.password_history.iter().map(|entry| entry.password.as_str()));
    values.extend(
        secrets
            .named_secrets
            .iter()
            .filter(|(name, value)| field_holds_secret(name, value))
            .map(|(_, value)| value.as_str()),
    );
    let mut hidden: Vec<String> = values
        .into_iter()
        .filter(|value| value.chars().count() >= min_chars && !visible.contains(value))
        .map(str::to_owned)
        .collect();
    hidden.sort();
    hidden.dedup();
    hidden
}

/// Key paths of a JSON document in captureSecrets syntax, without any values, so an agent
/// can correct a path without seeing the body. Arrays list their first element only.
pub(super) fn json_key_paths(root: &Value) -> Vec<String> {
    const MAX_PATHS: usize = 200;
    const MAX_DEPTH: usize = 8;
    fn visit(value: &Value, path: String, depth: usize, out: &mut Vec<String>) {
        if out.len() >= MAX_PATHS {
            return;
        }
        match value {
            Value::Object(map) if depth < MAX_DEPTH && !map.is_empty() => {
                for (key, child) in map {
                    let simple = !key.is_empty()
                        && key
                            .chars()
                            .all(|ch| ch.is_alphanumeric() || matches!(ch, '_' | '-' | '$'));
                    let child_path = if simple {
                        format!("{path}.{key}")
                    } else {
                        format!("{path}[\"{key}\"]")
                    };
                    visit(child, child_path, depth + 1, out);
                }
            }
            Value::Array(items) if depth < MAX_DEPTH && !items.is_empty() => {
                visit(&items[0], format!("{path}[0]"), depth + 1, out);
            }
            _ => out.push(path),
        }
    }
    let mut out = Vec::new();
    visit(root, "$".to_owned(), 0, &mut out);
    out
}

pub(super) fn connection_supports_action(connection: &DecryptedConnection, capability: Option<&str>) -> bool {
    match capability {
        None => !connection
            .stored
            .capabilities(&connection.secrets)
            .is_empty(),
        Some(capability) => connection
            .stored
            .has_capability(&connection.secrets, capability),
    }
}

pub(super) fn action_label(capability: &str) -> &str {
    match capability {
        "ssh" => "SSH",
        capability => capability,
    }
}

pub(super) fn filter_connections_by_query(
    mut connections: Vec<DecryptedConnection>,
    query: &str,
) -> Vec<DecryptedConnection> {
    let normalized_query = query.trim().to_lowercase();
    let search_query = normalize_search_text(query);
    let has_literal_exact = connections
        .iter()
        .any(|item| item.stored.name.trim().to_lowercase() == normalized_query);
    let has_normalized_exact = !search_query.is_empty()
        && connections
            .iter()
            .any(|item| normalize_search_text(&item.stored.name) == search_query);
    let longest_embedded_name = if !has_literal_exact && !has_normalized_exact {
        connections
            .iter()
            .map(|item| normalize_search_text(&item.stored.name))
            .filter(|name| phrase_contains(&search_query, name))
            .map(|name| name.len())
            .max()
    } else {
        None
    };
    connections.retain(|item| {
        let name = item.stored.name.trim().to_lowercase();
        if has_literal_exact {
            name == normalized_query
        } else if has_normalized_exact {
            normalize_search_text(&item.stored.name) == search_query
        } else if let Some(longest) = longest_embedded_name {
            let normalized_name = normalize_search_text(&item.stored.name);
            normalized_name.len() == longest && phrase_contains(&search_query, &normalized_name)
        } else {
            let normalized_name = normalize_search_text(&item.stored.name);
            name.contains(&normalized_query)
                || phrase_contains(&search_query, &normalized_name)
                || phrase_contains(&normalized_name, &search_query)
        }
    });
    connections
}

pub(super) fn search_connections_by_query(
    connections: Vec<DecryptedConnection>,
    query: &str,
) -> Vec<DecryptedConnection> {
    let normalized_query = query.trim().to_lowercase();
    let search_query = normalize_search_text(query);
    if normalized_query.is_empty() {
        return connections;
    }
    let has_literal_exact = connections
        .iter()
        .any(|item| item.stored.name.trim().to_lowercase() == normalized_query);
    if has_literal_exact {
        return connections
            .into_iter()
            .filter(|item| item.stored.name.trim().to_lowercase() == normalized_query)
            .collect();
    }
    let has_normalized_exact = !search_query.is_empty()
        && connections
            .iter()
            .any(|item| normalize_search_text(&item.stored.name) == search_query);
    if has_normalized_exact {
        return connections
            .into_iter()
            .filter(|item| normalize_search_text(&item.stored.name) == search_query)
            .collect();
    }
    let longest_embedded_name = connections
        .iter()
        .map(|item| normalize_search_text(&item.stored.name))
        .filter(|name| phrase_contains(&search_query, name))
        .map(|name| name.len())
        .max();
    if let Some(longest) = longest_embedded_name {
        return connections
            .into_iter()
            .filter(|item| {
                let normalized_name = normalize_search_text(&item.stored.name);
                normalized_name.len() == longest
                    && phrase_contains(&search_query, &normalized_name)
            })
            .collect();
    }

    let query_tokens: Vec<&str> = search_query.split_whitespace().collect();
    let raw_tokens: Vec<&str> = normalized_query.split_whitespace().collect();
    let mut name_matches = Vec::new();
    let mut metadata_matches = Vec::new();
    for item in connections {
        let name_lower = item.stored.name.trim().to_lowercase();
        let normalized_name = normalize_search_text(&item.stored.name);
        let matched_name = name_lower.contains(&normalized_query)
            || phrase_contains(&search_query, &normalized_name)
            || phrase_contains(&normalized_name, &search_query);
        if matched_name {
            name_matches.push(item);
            continue;
        }
        let mut metadata_parts = vec![
            item.stored.name.as_str(),
            item.stored.description.as_str(),
            item.stored.folder.as_str(),
        ];
        for note in &item.secrets.agent_notes {
            metadata_parts.push(note.text.as_str());
            metadata_parts.push(note.author.as_str());
        }
        let combined_raw = metadata_parts.join(" ").to_lowercase();
        let combined_norm = normalize_search_text(&combined_raw);
        let raw_match = combined_raw.contains(&normalized_query)
            || (!raw_tokens.is_empty()
                && raw_tokens.iter().all(|tok| combined_raw.contains(tok)));
        let norm_match = (!search_query.is_empty() && combined_norm.contains(&search_query))
            || (!query_tokens.is_empty()
                && query_tokens.iter().all(|tok| combined_norm.contains(tok)));
        if raw_match || norm_match {
            metadata_matches.push(item);
        }
    }
    name_matches.extend(metadata_matches);
    name_matches
}

pub(super) fn normalize_search_text(value: &str) -> String {
    value
        .to_lowercase()
        .chars()
        .map(|character| {
            if character.is_alphanumeric() {
                character
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

pub(super) fn phrase_contains(haystack: &str, needle: &str) -> bool {
    !needle.is_empty() && format!(" {haystack} ").contains(&format!(" {needle} "))
}

pub(super) fn module_aliases(name: &str) -> &'static [&'static str] {
    match name {
        "username" => &[
            "username",
            "user name",
            "account",
            "email",
            "Username",
            "Account",
        ],
        "password" => &["password", "passwd", "pwd", "Password"],
        "apiCredential" => &[
            "api credential",
            "api key",
            "access token",
            "bearer token",
            "token",
            "api credential",
        ],
        "privateKey" => &["private key", "ssh key", "identity file", "Private key"],
        "passphrase" => &[
            "passphrase",
            "key passphrase",
            "private key password",
            "Private key passphrase",
            "password",
        ],
        "totp" => &[
            "totp",
            "otp",
            "one time code",
            "verification code",
            "2fa code",
            "verification code",
        ],
        _ => &[],
    }
}

pub(super) fn secret_module_match_score(name: &str, phrase: &str) -> Option<usize> {
    let phrase = normalize_search_text(phrase);
    let normalized_name = normalize_search_text(name);
    if phrase == normalized_name {
        return Some(10_000 + normalized_name.len());
    }
    std::iter::once(normalized_name)
        .chain(
            module_aliases(name)
                .iter()
                .map(|alias| normalize_search_text(alias)),
        )
        .filter(|alias| phrase_contains(&phrase, alias))
        .map(|alias| alias.len())
        .max()
}

pub(super) fn module_hint_from_item(item_phrase: &str, project_name: &str) -> String {
    let phrase = format!(" {} ", normalize_search_text(item_phrase));
    let project = format!(" {} ", normalize_search_text(project_name));
    phrase.replace(&project, " ").trim().to_owned()
}

pub(super) fn resolve_secret_module(
    connection: &DecryptedConnection,
    requested: &str,
    item_phrase: &str,
) -> Result<String, String> {
    let fields = connection
        .secrets
        .available_fields(connection.stored.secret.as_ref())
        .into_iter()
        .filter(|field| connection.secrets.get(&field.name).is_some())
        .collect::<Vec<_>>();
    match fields.as_slice() {
        [] => return Err("This project has no configured secret modules".to_owned()),
        [field] if requested.trim().is_empty() => return Ok(field.name.clone()),
        _ => {}
    }

    let hint = if requested.trim().is_empty() {
        module_hint_from_item(item_phrase, &connection.stored.name)
    } else {
        requested.trim().to_owned()
    };
    let scored = fields
        .iter()
        .filter_map(|field| {
            secret_module_match_score(&field.name, &hint).map(|score| (field.name.clone(), score))
        })
        .collect::<Vec<_>>();
    let best_score = scored.iter().map(|(_, score)| *score).max();
    let best = best_score.map_or_else(Vec::new, |best_score| {
        scored
            .into_iter()
            .filter(|(_, score)| *score == best_score)
            .map(|(name, _)| name)
            .collect::<Vec<_>>()
    });
    if let [name] = best.as_slice() {
        return Ok(name.clone());
    }
    let names = fields
        .iter()
        .map(|field| field.name.as_str())
        .collect::<Vec<_>>()
        .join("、");
    if requested.trim().is_empty() {
        Err(format!(
            "This project contains multiple secret modules; specify which module to use in the item statement, or specify module:{names}"
        ))
    } else {
        Err(format!(
            "Unable to uniquely match the secret module; available modules:{names}"
        ))
    }
}

#[derive(Debug, Default)]
pub(super) struct ResolvedBindings {
    pub(super) values: HashMap<String, String>,
    pub(super) redactions: Vec<String>,
    pub(super) referenced_items: Vec<Uuid>,
    /// Items (once each) that supplied a value hidden from the agent: a secret module or a
    /// module the owner did not make agent-visible. Public values are not listed.
    pub(super) secret_sources: Vec<crate::model::StoredConnection>,
}

/// Refuses an HTTP request whose destination is outside the website binding of any item that
/// supplied a hidden value to it (see `crate::policy::api_target_allowed`).
pub(super) fn ensure_http_secret_destinations(
    connection: &DecryptedConnection,
    request: &ApiRequestInput,
    secret_sources: &[crate::model::StoredConnection],
) -> Result<()> {
    let target = crate::exec::api_request_target(&connection.stored, request)?;
    if let Some(refused) = secret_sources
        .iter()
        .find(|source| !crate::policy::api_target_allowed(source, &target))
    {
        bail!("{}", crate::policy::api_target_refusal(refused));
    }
    Ok(())
}

pub(super) fn split_cross_item_spec(spec: &str) -> Option<(&str, &str)> {
    let trimmed = spec.trim();
    let (item, module) = trimmed.rsplit_once('/')?;
    let item = item.trim();
    let module = module.trim();
    if item.is_empty() || module.is_empty() {
        None
    } else {
        Some((item, module))
    }
}

pub(super) fn bindings_need_default_item(bindings: &HashMap<String, String>) -> bool {
    bindings
        .values()
        .any(|spec| split_cross_item_spec(spec).is_none())
}

pub(super) fn append_redaction_secret(connection: &mut DecryptedConnection, value: &str) {
    if value.is_empty() {
        return;
    }
    if connection
        .secrets
        .named_secrets
        .values()
        .any(|existing| existing == value)
    {
        return;
    }
    let mut redaction_index = connection.secrets.named_secrets.0.len();
    let redaction_name = loop {
        let candidate = format!("__openkeylet_binding_{redaction_index}");
        if !connection.secrets.named_secrets.0.contains_key(&candidate) {
            break candidate;
        }
        redaction_index += 1;
    };
    connection
        .secrets
        .named_secrets
        .insert(redaction_name, value.to_owned());
}

pub(super) fn has_exact_module_name(connection: &DecryptedConnection, candidate: &str) -> bool {
    let candidate = candidate.trim();
    if candidate.is_empty() {
        return false;
    }
    if connection
        .secrets
        .available_fields(connection.stored.secret.as_ref())
        .iter()
        .any(|field| {
            field.name.eq_ignore_ascii_case(candidate)
                && connection.secrets.get(&field.name).is_some()
        })
    {
        return true;
    }
    connection.stored.modules.iter().any(|module| {
        module.secret_name().is_none()
            && !module.value.trim().is_empty()
            && (module.name.eq_ignore_ascii_case(candidate)
                || module.kind.eq_ignore_ascii_case(candidate))
    })
}

pub(super) fn public_module_aliases(kind: &str) -> &'static [&'static str] {
    match kind {
        "host" => &["host", "hostname", "server", "server host", "ip", "address"],
        "port" => &["port", "ssh port"],
        "url" => &[
            "url",
            "base url",
            "baseurl",
            "service url",
            "endpoint",
            "website",
            "uri",
        ],
        _ => &[],
    }
}

pub(super) fn public_module_match_score(kind: &str, name: &str, requested: &str) -> Option<usize> {
    let trimmed = requested.trim();
    if trimmed.is_empty() {
        return None;
    }
    if (!name.is_empty() && name.eq_ignore_ascii_case(trimmed))
        || kind.eq_ignore_ascii_case(trimmed)
    {
        return Some(10_000 + trimmed.len());
    }
    let phrase = normalize_search_text(trimmed);
    if phrase.is_empty() {
        return None;
    }
    let norm_name = normalize_search_text(name);
    let norm_kind = normalize_search_text(kind);
    if (!norm_name.is_empty() && phrase == norm_name) || (!norm_kind.is_empty() && phrase == norm_kind) {
        return Some(10_000 + phrase.len());
    }
    [norm_name, norm_kind]
        .into_iter()
        .filter(|s| !s.is_empty())
        .chain(
            public_module_aliases(kind)
                .iter()
                .map(|alias| normalize_search_text(alias)),
        )
        .filter(|alias| phrase_contains(&phrase, alias))
        .map(|alias| alias.len())
        .max()
}

pub(super) fn resolve_public_module(
    connection: &DecryptedConnection,
    requested: &str,
) -> Option<(String, bool)> {
    let mut candidates: Vec<(&str, &str, String, bool)> = Vec::new();
    let mut has_host = false;
    let mut has_port = false;
    let mut has_url = false;
    for module in &connection.stored.modules {
        if module.secret_name().is_some() || module.value.trim().is_empty() {
            continue;
        }
        match module.kind.as_str() {
            "host" => has_host = true,
            "port" => has_port = true,
            "url" => has_url = true,
            _ => {}
        }
        let name = if module.name.trim().is_empty() {
            module.kind.as_str()
        } else {
            module.name.as_str()
        };
        candidates.push((
            module.kind.as_str(),
            name,
            module.value.clone(),
            !module.agent_visible(),
        ));
    }
    if !has_host && !connection.stored.host.trim().is_empty() {
        candidates.push(("host", "host", connection.stored.host.clone(), false));
    }
    if !has_port && connection.stored.port > 0 && !connection.stored.host.trim().is_empty() {
        candidates.push(("port", "port", connection.stored.port.to_string(), false));
    }
    if !has_url && !connection.stored.base_url.trim().is_empty() {
        candidates.push(("url", "url", connection.stored.base_url.clone(), false));
    }
    let scored: Vec<(usize, String, bool)> = candidates
        .into_iter()
        .filter_map(|(kind, name, value, is_hidden)| {
            public_module_match_score(kind, name, requested)
                .map(|score| (score, value, is_hidden))
        })
        .collect();
    let best_score = scored.iter().map(|(score, _, _)| *score).max()?;
    let mut best: Vec<(String, bool)> = scored
        .into_iter()
        .filter(|(score, _, _)| *score == best_score)
        .map(|(_, value, is_hidden)| (value, is_hidden))
        .collect();
    if best.len() == 1 {
        Some(best.remove(0))
    } else {
        None
    }
}

// Keep existing automation templates usable after the KRU -> OpenKeylet rename.
// Supports both standard `{{openkeylet:...}}` / `{{kru:...}}` and unquoted raw
// `{{openkeylet-raw:...}}` / `{{kru-raw:...}}` placeholders.
pub(super) fn next_secret_placeholder(input: &str) -> Option<(usize, usize, bool)> {
    [
        ("{{openkeylet-raw:", true),
        ("{{kru-raw:", true),
        ("{{openkeylet:", false),
        ("{{kru:", false),
    ]
    .into_iter()
    .filter_map(|(prefix, raw)| input.find(prefix).map(|start| (start, prefix.len(), raw)))
    .min_by_key(|(start, _, _)| *start)
}

pub(super) fn interpolate_command_text(
    input: &str,
    raw_replacements: &HashMap<String, String>,
    quoted_replacements: &HashMap<String, String>,
    used: &mut HashSet<String>,
) -> Result<String, String> {
    let mut rest = input;
    let mut output = String::with_capacity(input.len());
    while let Some((start, prefix_len, is_raw)) = next_secret_placeholder(rest) {
        output.push_str(&rest[..start]);
        let after_open = &rest[start + prefix_len..];
        let Some(end) = after_open.find("}}") else {
            return Err("Missing OpenKeylet secret placeholder }}".to_owned());
        };
        let alias = after_open[..end].trim();
        let table = if is_raw {
            raw_replacements
        } else {
            quoted_replacements
        };
        let value = table.get(alias).ok_or_else(|| {
            format!("OpenKeylet secret placeholder has no corresponding binding:{alias}")
        })?;
        output.push_str(value);
        used.insert(alias.to_owned());
        rest = &after_open[end + 2..];
    }
    output.push_str(rest);
    Ok(output)
}

pub(super) fn interpolate_http_text(
    input: &str,
    replacements: &HashMap<String, String>,
    used: &mut HashSet<String>,
) -> Result<String, String> {
    let mut rest = input;
    let mut output = String::with_capacity(input.len());
    while let Some((start, prefix_len, _is_raw)) = next_secret_placeholder(rest) {
        output.push_str(&rest[..start]);
        let after_open = &rest[start + prefix_len..];
        let Some(end) = after_open.find("}}") else {
            return Err("Missing OpenKeylet secret placeholder }}".to_owned());
        };
        let alias = after_open[..end].trim();
        let value = replacements.get(alias).ok_or_else(|| {
            format!("OpenKeylet HTTP secret placeholder has no corresponding binding:{alias}")
        })?;
        output.push_str(value);
        used.insert(alias.to_owned());
        rest = &after_open[end + 2..];
    }
    output.push_str(rest);
    Ok(output)
}

pub(super) fn redact_secret_placeholders(input: &str) -> String {
    let mut rest = input;
    let mut output = String::with_capacity(input.len());
    while let Some((start, prefix_len, _is_raw)) = next_secret_placeholder(rest) {
        output.push_str(&rest[..start]);
        let after_open = &rest[start + prefix_len..];
        let Some(end) = after_open.find("}}") else {
            output.push_str(&rest[start..]);
            return output;
        };
        output.push_str("[REDACTED]");
        rest = &after_open[end + 2..];
    }
    output.push_str(rest);
    output
}

pub(super) fn collect_secret_placeholders_text(
    input: &str,
    placeholders: &mut HashSet<String>,
) -> Result<(), String> {
    let mut rest = input;
    while let Some((start, prefix_len, _is_raw)) = next_secret_placeholder(rest) {
        let after_open = &rest[start + prefix_len..];
        let Some(end) = after_open.find("}}") else {
            return Err("Missing OpenKeylet HTTP secret placeholder }}".to_owned());
        };
        let module = after_open[..end].trim();
        if module.is_empty() {
            return Err("OpenKeylet secret placeholder name cannot be empty".to_owned());
        }
        placeholders.insert(module.to_owned());
        rest = &after_open[end + 2..];
    }
    Ok(())
}

pub(super) fn effective_max_output_bytes(requested: Option<usize>) -> Option<usize> {
    match requested {
        Some(0) => None,
        Some(limit) => Some(limit),
        None => Some(DEFAULT_MAX_OUTPUT_BYTES),
    }
}

pub(super) fn should_auto_include_totp(inspected: &Value, include_totp: bool) -> bool {
    if include_totp {
        return true;
    }
    let otp_count = inspected["otpFieldCount"].as_u64().unwrap_or(0);
    if otp_count == 0 {
        return false;
    }
    let has_password_field = inspected["loginForms"]
        .as_array()
        .is_some_and(|forms| {
            forms
                .iter()
                .any(|form| form["hasPassword"].as_bool().unwrap_or(false))
        })
        || inspected["fields"].as_array().is_some_and(|fields| {
            fields
                .iter()
                .any(|field| field["type"].as_str() == Some("password"))
        });
    !has_password_field
}

pub(super) fn extract_json_path(root: &Value, raw_path: &str) -> Option<String> {
    let path = raw_path.trim();
    if path.is_empty() {
        return None;
    }
    let mut rest = path;
    if let Some(stripped) = rest.strip_prefix('$') {
        rest = stripped;
        if let Some(stripped_dot) = rest.strip_prefix('.') {
            rest = stripped_dot;
        }
    }
    let mut current = root;
    while !rest.is_empty() {
        if let Some(after_dot) = rest.strip_prefix('.') {
            rest = after_dot;
            continue;
        }
        if let Some(after_open) = rest.strip_prefix('[') {
            let (token, after_close) = if let Some(quoted) = after_open.strip_prefix('"') {
                let end = quoted.find("\"]")?;
                (&quoted[..end], &quoted[end + 2..])
            } else if let Some(quoted) = after_open.strip_prefix('\'') {
                let end = quoted.find("']")?;
                (&quoted[..end], &quoted[end + 2..])
            } else {
                let end = after_open.find(']')?;
                (&after_open[..end], &after_open[end + 1..])
            };
            let token = token.trim();
            if let Ok(index) = token.parse::<usize>()
                && let Some(arr) = current.as_array()
            {
                current = arr.get(index)?;
            } else {
                current = current.as_object()?.get(token)?;
            }
            rest = after_close;
        } else {
            let end = rest.find(['.', '[']).unwrap_or(rest.len());
            let segment = rest[..end].trim();
            if segment.is_empty() {
                return None;
            }
            if let Some(obj) = current.as_object() {
                current = obj.get(segment)?;
            } else if let Some(arr) = current.as_array() {
                let index = segment.parse::<usize>().ok()?;
                current = arr.get(index)?;
            } else {
                return None;
            }
            rest = &rest[end..];
        }
    }
    match current {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

pub(super) fn collect_secret_placeholders_value(
    value: &Value,
    placeholders: &mut HashSet<String>,
) -> Result<(), String> {
    match value {
        Value::String(text) => collect_secret_placeholders_text(text, placeholders)?,
        Value::Array(values) => {
            for value in values {
                collect_secret_placeholders_value(value, placeholders)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_secret_placeholders_value(value, placeholders)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn collect_http_secret_placeholders(input: &HttpSendInput) -> Result<HashSet<String>, String> {
    let mut placeholders = HashSet::new();
    collect_secret_placeholders_text(&input.url, &mut placeholders)?;
    for value in input.headers.values() {
        collect_secret_placeholders_text(value, &mut placeholders)?;
    }
    for value in input.query.values() {
        collect_secret_placeholders_value(value, &mut placeholders)?;
    }
    if let Some(body) = input.body.as_ref() {
        collect_secret_placeholders_value(body, &mut placeholders)?;
    }
    for value in input.form.values() {
        collect_secret_placeholders_value(value, &mut placeholders)?;
    }
    Ok(placeholders)
}

pub(super) fn interpolate_http_value(
    value: &mut Value,
    replacements: &HashMap<String, String>,
    used: &mut HashSet<String>,
) -> Result<(), String> {
    match value {
        Value::String(text) => *text = interpolate_http_text(text, replacements, used)?,
        Value::Array(values) => {
            for value in values {
                interpolate_http_value(value, replacements, used)?;
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                interpolate_http_value(value, replacements, used)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn interpolate_http_input(
    input: &mut HttpSendInput,
    replacements: &HashMap<String, String>,
) -> Result<HashSet<String>, String> {
    let mut used = HashSet::new();
    input.url = interpolate_http_text(&input.url, replacements, &mut used)?;
    for value in input.headers.values_mut() {
        *value = interpolate_http_text(value, replacements, &mut used)?;
    }
    for value in input.query.values_mut() {
        interpolate_http_value(value, replacements, &mut used)?;
    }
    if let Some(body) = input.body.as_mut() {
        interpolate_http_value(body, replacements, &mut used)?;
    }
    for value in input.form.values_mut() {
        interpolate_http_value(value, replacements, &mut used)?;
    }
    Ok(used)
}

