use super::*;

pub(super) fn canonical_secret_module_name(kind: &str) -> Option<&str> {
    match kind {
        "username" => Some("username"),
        "password" => Some("password"),
        "apiCredential" => Some("apiCredential"),
        "privateKey" => Some("privateKey"),
        "passphrase" => Some("passphrase"),
        "totp" => Some("totp"),
        kind if crate::item_types::personal_field(kind) => Some(kind),
        _ => None,
    }
}

pub(super) fn normalize_modules(modules: Vec<ItemModule>) -> Result<Vec<ItemModule>> {
    let mut output = Vec::new();
    let mut singleton_kinds = Vec::new();
    let mut secret_names: Vec<String> = Vec::new();
    for mut module in modules {
        module.kind = module.kind.trim().to_owned();
        if !crate::item_types::personal_field(&module.kind)
            && !matches!(
                module.kind.as_str(),
                "username"
                    | "password"
                    | "apiCredential"
                    | "privateKey"
                    | "passphrase"
                    | "totp"
                    | "customSecret"
                    | "host"
                    | "port"
                    | "url"
            )
        {
            bail!("Unsupported module:{}", module.kind);
        }
        if module.agent_visible.is_none() {
            module.agent_visible = Some(!module_kind_has_plaintext_reveal(&module.kind));
        }
        if module.kind != "customSecret" {
            if singleton_kinds.contains(&module.kind) {
                bail!("Duplicate module:{}", module.kind);
            }
            singleton_kinds.push(module.kind.clone());
        }
        if let Some(name) = canonical_secret_module_name(&module.kind) {
            module.name = name.to_owned();
            module.value.clear();
        } else if module.kind == "customSecret" {
            module.name = checked_text(&module.name, "Custom secret field name", 80)?;
            if !valid_custom_field_name(&module.name) || reserved_secret_name(&module.name) {
                bail!("Invalid custom secret field name:{}", module.name);
            }
            module.value.clear();
        } else {
            module.name.clear();
            module.value = module.value.trim().to_owned();
            if module.kind == "port" && !module.value.is_empty() {
                let port = module
                    .value
                    .parse::<u16>()
                    .context("Port must be 1–65535")?;
                if port == 0 {
                    bail!("Port must be 1–65535");
                }
                module.value = port.to_string();
            }
        }
        if let Some(name) = module.secret_name() {
            if secret_names
                .iter()
                .any(|candidate| normalized_field_name(candidate) == normalized_field_name(name))
            {
                bail!("Duplicate secret module field name:{name}");
            }
            secret_names.push(name.to_owned());
        }
        output.push(module);
    }
    Ok(output)
}

pub(super) fn module_value<'a>(modules: &'a [ItemModule], kind: &str) -> Option<&'a str> {
    modules
        .iter()
        .find(|module| module.kind == kind)
        .map(|module| module.value.trim())
        .filter(|value| !value.is_empty())
}

pub(super) fn module_secret_configured(modules: &[ItemModule], secrets: &SecretBundle, kind: &str) -> bool {
    modules
        .iter()
        .find(|module| module.kind == kind)
        .and_then(ItemModule::secret_name)
        .and_then(|name| secrets.get(name))
        .is_some()
}

pub(super) fn module_fields(modules: &[ItemModule]) -> Vec<SecretField> {
    modules
        .iter()
        .filter_map(|module| {
            module.secret_name().map(|name| SecretField {
                name: name.to_owned(),
                kind: if module.kind == "totp" {
                    "totp"
                } else {
                    "text"
                }
                .to_owned(),
            })
        })
        .collect()
}

pub(super) fn push_module(modules: &mut Vec<ItemModule>, kind: &str, name: &str, value: &str) {
    if kind != "customSecret" && modules.iter().any(|module| module.kind == kind) {
        return;
    }
    if kind == "customSecret" && modules.iter().any(|module| module.name == name) {
        return;
    }
    modules.push(ItemModule {
        kind: kind.to_owned(),
        name: name.to_owned(),
        value: value.to_owned(),
        agent_visible: Some(!module_kind_has_plaintext_reveal(kind)),
    });
}

pub(super) fn fallback_item_name(
    requested: &str,
    id: Uuid,
    modules: &[ItemModule],
    secrets: &SecretBundle,
) -> String {
    let requested = clean_text(requested, 80);
    if !requested.is_empty() {
        return requested;
    }
    if let Some(host) = module_value(modules, "host") {
        return clean_text(host, 80);
    }
    if let Some(url) = module_value(modules, "url") {
        let profile = api_catalog::infer("", url, secrets.get("apiCredential").unwrap_or_default());
        return api_catalog::fallback_name(url, profile);
    }
    if let Some(secret) = secrets.get("apiCredential") {
        let inferred = api_catalog::fallback_name("", api_catalog::infer("", "", secret));
        if inferred != "API" {
            return inferred;
        }
    }
    let short = id.simple().to_string()[..6].to_ascii_uppercase();
    if module_secret_configured(modules, secrets, "username")
        && module_secret_configured(modules, secrets, "password")
    {
        format!("LOGIN-{short}")
    } else {
        format!("ITEM-{short}")
    }
}

pub(crate) fn normalize_connection(
    input: ConnectionInput,
    existing: Option<&StoredConnection>,
    secrets: &SecretBundle,
    private_key_name: String,
    now: String,
) -> Result<StoredConnection> {
    crate::login_uri::validate(&input.login_uris)?;
    let modules = normalize_modules(input.modules)?;
    let item_type = crate::item_types::normalize(&input.item_type, &modules)?;

    let id = existing
        .map(|value| value.id)
        .or(input.id)
        .unwrap_or_else(Uuid::new_v4);
    let created_at = existing
        .map(|value| value.created_at.clone())
        .unwrap_or_else(|| now.clone());
    let host = module_value(&modules, "host")
        .unwrap_or_default()
        .to_owned();
    let port = module_value(&modules, "port")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    let base_url = if let Some(raw) = module_value(&modules, "url") {
        let normalized = api_catalog::normalize_base_url(raw, "")?;
        let parsed = Url::parse(&normalized).context("Invalid API URL")?;
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            bail!(
                "API URL must use HTTP/HTTPS and must not include an account or password in the address"
            );
        }
        normalized
    } else {
        String::new()
    };
    let ssh_auth_type = if module_secret_configured(&modules, secrets, "privateKey") {
        "privateKey"
    } else if module_secret_configured(&modules, secrets, "password") {
        "password"
    } else {
        ""
    }
    .to_owned();
    let http_auth_type = input.http_auth_type.clone();
    let name = fallback_item_name(&input.name, id, &modules, secrets);
    Ok(StoredConnection {
        login_uris: input.login_uris,
        item_type,
        folder: checked_text(&input.folder, "Folder", 120)?,
        favorite: input.favorite,
        id,
        modules: modules.clone(),
        name,
        enabled: input.enabled,
        created_at,
        updated_at: now,
        description: checked_text(&input.description, "Project description", 240)?,
        host,
        port,
        ssh_auth_type,
        http_auth_type,
        private_key_name: if modules.iter().any(|module| module.kind == "privateKey") {
            private_key_name
        } else {
            String::new()
        },
        base_url,
        auth_header: input.auth_header.trim().to_owned(),
        auth_location: input.auth_location.trim().to_owned(),
        auth_prefix: input.auth_prefix.trim().to_owned(),
        api_auth_headers: input.api_auth_headers,
        test_path: input.test_path.trim().to_owned(),
        secret: Some(SecretProfile {
            fields: module_fields(&modules),
        }),
        encrypted_secrets: empty_envelope(),
    })
}

pub(super) fn prepare_auto_api(input: &mut ConnectionInput, secrets: &mut SecretBundle) -> Result<()> {
    if input.http_auth_type != "auto" {
        return Ok(());
    }
    let has_api_credential = input
        .modules
        .iter()
        .any(|module| module.kind == "apiCredential");
    if !has_api_credential {
        let basic_ready = module_value(&input.modules, "url").is_some()
            && module_secret_configured(&input.modules, secrets, "username")
            && module_secret_configured(&input.modules, secrets, "password");
        if basic_ready {
            input.http_auth_type = "basic".to_owned();
            input.auth_header = "Authorization".to_owned();
            input.auth_location = "header".to_owned();
            input.auth_prefix.clear();
            input.api_auth_headers.clear();
        }
        return Ok(());
    }
    let Some(secret) = secrets
        .get("apiCredential")
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
    else {
        // An empty API credential module is a valid draft.  It becomes callable
        // only after a value is configured and capabilities are derived again.
        return Ok(());
    };
    let current_url = module_value(&input.modules, "url").unwrap_or_default();
    let profile = api_catalog::infer(&input.name, current_url, &secret);
    let normalized_url = api_catalog::normalize_base_url(current_url, profile.default_base_url)?;
    if !normalized_url.is_empty() {
        if let Some(module) = input.modules.iter_mut().find(|module| module.kind == "url") {
            module.value = normalized_url;
        } else {
            push_module(&mut input.modules, "url", "", &normalized_url);
        }
    }
    input.http_auth_type = profile.auth_type.to_owned();
    input.auth_header = profile.auth_header.to_owned();
    input.auth_location = profile.auth_location.to_owned();
    input.auth_prefix = profile.auth_prefix.to_owned();
    input.api_auth_headers.clear();
    input.test_path.clear();
    Ok(())
}

pub(super) fn valid_custom_field_name(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

pub(super) fn normalized_field_name(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace() && !matches!(character, '_' | '-'))
        .flat_map(char::to_lowercase)
        .collect()
}

pub(super) fn reserved_secret_name(value: &str) -> bool {
    crate::item_types::CARD_FIELDS
        .iter()
        .chain(crate::item_types::IDENTITY_FIELDS)
        .chain(std::iter::once(&"secureNote"))
        .any(|name| normalized_field_name(name) == normalized_field_name(value))
        || matches!(
            normalized_field_name(value).as_str(),
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

pub(super) fn checked_text(value: &str, label: &str, max_chars: usize) -> Result<String> {
    let value = value.trim();
    if value.chars().count() > max_chars {
        bail!("{label}Cannot exceed {max_chars} characters");
    }
    Ok(value.to_owned())
}

pub(super) fn clean_text(value: &str, max_chars: usize) -> String {
    value.trim().chars().take(max_chars).collect()
}

pub(super) fn random_token() -> Result<String> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut token = [0_u8; 32];
    getrandom::fill(&mut token)
        .map_err(|error| anyhow::anyhow!("Could not generate MCP access token:{error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(token))
}

