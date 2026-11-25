use super::*;

pub(super) fn extract_without_dedup(
    trimmed: &str,
    filename: Option<&str>,
) -> Result<SmartExtractBatchResult> {
    let lower_file = filename
        .map(|f| f.to_ascii_lowercase())
        .unwrap_or_default();

    // 1. Bitwarden JSON export
    if looks_like_bitwarden_json(trimmed)
        && let Ok(parsed) = migration::parse(trimmed.as_bytes(), "bitwarden")
    {
        let candidates = parsed
            .entries
            .into_iter()
            .map(|(p, s)| {
                let (kind, badge, badge_zh) = classify_portable_kind(&p);
                candidate_from_portable(p, s, kind, badge, badge_zh, filename.unwrap_or("Bitwarden JSON"))
            })
            .collect();
        return Ok(SmartExtractBatchResult {
            detected_format: "bitwarden".to_owned(),
            detected_format_zh: "Bitwarden 导出 (JSON)".to_owned(),
            candidates,
            ignored: Vec::new(),
            warnings: parsed.preview.warnings,
            sealed_env_template: None,
        });
    }

    // 2. KeePass 2.x XML export
    if (lower_file.ends_with(".xml") || trimmed.contains("<KeePassFile"))
        && let Some(kp_res) = try_extract_keepass_xml(trimmed, filename)
    {
        return Ok(kp_res);
    }

    // 2b. PuTTY private key (.ppk)
    if (lower_file.ends_with(".ppk") || trimmed.starts_with("PuTTY-User-Key-File-"))
        && let Some(ppk_res) = try_extract_putty_ppk(trimmed, filename)
    {
        return Ok(ppk_res);
    }

    // 3a. AWS / Alibaba Cloud / Tencent Cloud IAM AccessKey CSV exports
    if (lower_file.ends_with(".csv") || trimmed.lines().next().is_some_and(|l| l.contains(',')))
        && let Some(cloud_csv) = try_extract_cloud_key_csv(trimmed, filename)
    {
        return Ok(cloud_csv);
    }

    // 3b. Chrome / Edge / Firefox / 1Password / Generic Password CSV
    if (lower_file.ends_with(".csv") || looks_like_password_csv(trimmed))
        && let Some(csv_res) = try_extract_password_csv(trimmed, filename)
    {
        return Ok(csv_res);
    }

    // 4. Tab-separated tables (TSV / Excel / Notion / Feishu sheets)
    if (lower_file.ends_with(".tsv") || lower_file.ends_with(".xlsx") || looks_like_password_tsv(trimmed))
        && let Some(tsv_res) = try_extract_password_tsv(trimmed, filename)
    {
        return Ok(tsv_res);
    }

    // 5. Dev credential dotfiles (.netrc / .npmrc / .pgpass / .pypirc)
    if let Some(netrc_res) = try_extract_netrc(trimmed, filename) {
        return Ok(netrc_res);
    }
    if let Some(npmrc_res) = try_extract_npmrc(trimmed, filename) {
        return Ok(npmrc_res);
    }
    if let Some(pgpass_res) = try_extract_pgpass(trimmed, filename) {
        return Ok(pgpass_res);
    }
    if let Some(pypirc_res) = try_extract_pypirc(trimmed, filename) {
        return Ok(pypirc_res);
    }

    // 6. AWS credentials INI
    if let Some(aws_res) = try_extract_aws_credentials(trimmed, filename) {
        return Ok(aws_res);
    }

    // 7. SSH config file
    if looks_like_ssh_config_file(trimmed, &lower_file)
        && let Ok((entries, preview)) = ingest::parse_ssh_config_bytes(trimmed.as_bytes(), None)
        && !entries.is_empty()
    {
        let candidates = entries
            .into_iter()
            .map(|(p, s)| {
                candidate_from_portable(p, s, "ssh", "SSH", "SSH", filename.unwrap_or("ssh config"))
            })
            .collect();
        return Ok(SmartExtractBatchResult {
            detected_format: "ssh_config".to_owned(),
            detected_format_zh: "SSH 配置文件".to_owned(),
            candidates,
            ignored: Vec::new(),
            warnings: preview.warnings,
            sealed_env_template: None,
        });
    }

    // 8. Structured JSON / JSONC config (mcp.json, opencode.jsonc, docker config.json, etc.)
    if let Some(json_val) = parse_json_or_jsonc(trimmed, &lower_file)
        && let Some(json_res) = try_extract_json_config(&json_val, filename)
    {
        return Ok(json_res);
    }

    // 9. Pure .env file
    if looks_like_env_document(trimmed, &lower_file) {
        return Ok(extract_env_document(trimmed, filename));
    }

    // 10. YAML / TOML / INI / Properties / Cloud & Kube config file
    if (lower_file.ends_with(".yml")
        || lower_file.ends_with(".yaml")
        || lower_file.ends_with(".toml")
        || lower_file.ends_with(".ini")
        || lower_file.ends_with(".conf")
        || lower_file.ends_with(".cfg")
        || lower_file.ends_with(".properties")
        || lower_file.ends_with(".tfvars")
        || lower_file.ends_with(".credential")
        || lower_file.ends_with(".credentials")
        || lower_file.ends_with("/credentials")
        || lower_file.ends_with("\\credentials")
        || lower_file == "credentials"
        || lower_file.ends_with("kubeconfig")
        || lower_file.ends_with("/.kube/config")
        || lower_file.ends_with("\\.kube\\config")
        || lower_file.ends_with("/kube/config")
        || lower_file.ends_with("\\kube\\config"))
        && let Some(cfg_res) = try_extract_yaml_toml_config(trimmed, filename)
    {
        return Ok(cfg_res);
    }

    // 11. Universal Mixed Free-Text Multi-Extractor (chats, notes, emails, handover docs)
    Ok(extract_mixed_free_text(trimmed, filename))
}

pub(super) fn looks_like_bitwarden_json(text: &str) -> bool {
    text.starts_with('{') && text.contains("\"items\"") && text.contains("\"type\"")
}

pub(super) fn try_extract_putty_ppk(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
    if !text.starts_with("PuTTY-User-Key-File-") {
        return None;
    }
    let key_file = filename
        .and_then(|f| Path::new(f).file_name().and_then(|s| s.to_str()))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("id_key.ppk");
    let stem = Path::new(key_file)
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("PuTTY Key");
    let mut input = blank_input("ssh", &format!("SSH · {stem}"));
    input.modules.push(public_mod("host", "host", ""));
    input.modules.push(public_mod("port", "port", "22"));
    input.modules.push(secret_mod("username", "username"));
    input.modules.push(secret_mod("privateKey", "privateKey"));
    input.secrets.private_key = Some(text.to_owned());
    input.secrets.private_key_name = Some(key_file.to_owned());

    let cand = make_candidate(
        "privateKey",
        "KEY",
        "私钥",
        "high",
        format!("PuTTY Private Key · {key_file}"),
        filename.unwrap_or(key_file).to_owned(),
        input,
        None,
    );
    Some(SmartExtractBatchResult {
        detected_format: "putty_ppk".to_owned(),
        detected_format_zh: "PuTTY 私钥 (.ppk)".to_owned(),
        candidates: vec![cand],
        ignored: Vec::new(),
        warnings: Vec::new(),
        sealed_env_template: None,
    })
}

pub(super) fn try_extract_cloud_key_csv(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers: Vec<String> = reader
        .headers()
        .ok()?
        .iter()
        .map(|h| h.trim().trim_start_matches('\u{feff}').to_ascii_lowercase())
        .collect();
    let idx_id = headers.iter().position(|h| {
        matches!(
            h.as_str(),
            "access key id"
                | "accesskey id"
                | "accesskeyid"
                | "access_key_id"
                | "secretid"
                | "secret id"
                | "密钥id"
                | "access key"
        )
    })?;
    let idx_secret = headers.iter().position(|h| {
        matches!(
            h.as_str(),
            "secret access key"
                | "accesskey secret"
                | "accesskeysecret"
                | "secret_access_key"
                | "secretkey"
                | "secret key"
                | "密钥key"
                | "secret"
        )
    })?;
    let idx_user = headers.iter().position(|h| {
        matches!(
            h.as_str(),
            "user name"
                | "username"
                | "user"
                | "account"
                | "description"
                | "备注"
                | "用户名"
                | "用户名称"
                | "ram用户"
                | "ram 账号"
                | "子账号"
        )
    });

    let mut candidates = Vec::new();
    for record in reader.records().flatten() {
        let ak = record.get(idx_id).map(str::trim).unwrap_or_default();
        let sk = record.get(idx_secret).map(str::trim).unwrap_or_default();
        if ak.is_empty() || sk.is_empty() || is_placeholder_value(ak) || is_placeholder_value(sk) {
            continue;
        }
        let user_hint = idx_user
            .and_then(|i| record.get(i))
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let (provider, id_key, sec_key) = if ak.starts_with("LTAI") {
            ("Alibaba Cloud", "ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_SECRET")
        } else if ak.starts_with("AKID") {
            ("Tencent Cloud", "TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY")
        } else if ak.starts_with("AKIA") || ak.starts_with("ASIA") {
            ("AWS", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
        } else {
            ("Cloud", "ACCESS_KEY_ID", "SECRET_ACCESS_KEY")
        };
        let title = match user_hint {
            Some(u) => format!("{provider} ({u})"),
            None => format!("{provider} AccessKey"),
        };
        let mut input = blank_input("custom", &title);
        input.folder = "Cloud".to_owned();
        if let Some(u) = user_hint {
            input.description = format!("{provider} account: {u}");
        }
        input.modules.push(secret_mod("customSecret", id_key));
        input.secrets.named_secrets.insert(id_key.to_owned(), ak.to_owned());
        input.modules.push(secret_mod("customSecret", sec_key));
        input.secrets.named_secrets.insert(sec_key.to_owned(), sk.to_owned());
        candidates.push(make_candidate(
            "aws",
            "AWS",
            "云密钥",
            "high",
            format!("{provider} · {}", mask_preview(ak)),
            filename.unwrap_or("accessKeys.csv").to_owned(),
            input,
            None,
        ));
    }

    if candidates.is_empty() {
        return None;
    }
    Some(SmartExtractBatchResult {
        detected_format: "cloud_key_csv".to_owned(),
        detected_format_zh: "云厂商 AccessKey 表格".to_owned(),
        candidates,
        ignored: Vec::new(),
        warnings: Vec::new(),
        sealed_env_template: None,
    })
}

pub(super) fn looks_like_password_csv(text: &str) -> bool {
    let Some(first_line) = text.lines().next() else {
        return false;
    };
    let lower = first_line.to_ascii_lowercase();
    lower.contains(',')
        && (lower.contains("password") || lower.contains("密码"))
        && (lower.contains("username")
            || lower.contains("url")
            || lower.contains("origin")
            || lower.contains("website")
            || lower.contains("账号"))
}

pub(super) fn try_extract_password_csv(
    text: &str,
    filename: Option<&str>,
) -> Option<SmartExtractBatchResult> {
    // Try native Chrome/Firefox/Edge migration parser first
    if let Ok(parsed) = migration::parse(text.as_bytes(), "chrome")
        && !parsed.entries.is_empty()
    {
        let candidates = parsed
            .entries
            .into_iter()
            .map(|(p, s)| {
                let (kind, badge, badge_zh) = classify_portable_kind(&p);
                candidate_from_portable(p, s, kind, badge, badge_zh, filename.unwrap_or("Password CSV"))
            })
            .collect();
        return Some(SmartExtractBatchResult {
            detected_format: "chrome_csv".to_owned(),
            detected_format_zh: "浏览器 / 密码表 CSV".to_owned(),
            candidates,
            ignored: Vec::new(),
            warnings: parsed.preview.warnings,
            sealed_env_template: None,
        });
    }

    // Fallback generic CSV parser (supports Chinese headers, 1Password, KeePass, custom tables)
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers: Vec<String> = reader
        .headers()
        .ok()?
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    let idx_name = headers
        .iter()
        .position(|h| matches!(h.as_str(), "name" | "title" | "service" | "site" | "名称" | "标题" | "平台" | "系统"));
    let idx_url = headers
        .iter()
        .position(|h| matches!(h.as_str(), "url" | "website" | "origin" | "login_uri" | "网址" | "链接" | "地址"));
    let idx_user = headers.iter().position(|h| {
        matches!(
            h.as_str(),
            "username" | "login_username" | "user" | "email" | "account" | "login" | "账号" | "用户名" | "邮箱"
        )
    });
    let idx_pass = headers
        .iter()
        .position(|h| matches!(h.as_str(), "password" | "login_password" | "pass" | "pwd" | "密码"));
    let idx_totp = headers
        .iter()
        .position(|h| matches!(h.as_str(), "totp" | "login_totp" | "otp" | "2fa" | "otpauth"));

    if idx_pass.is_none() && idx_totp.is_none() {
        return None;
    }

    let mut candidates = Vec::new();
    for record in reader.records().flatten() {
        let get = |idx: Option<usize>| -> String {
            idx.and_then(|i| record.get(i))
                .map(str::trim)
                .unwrap_or_default()
                .to_owned()
        };
        let url = get(idx_url);
        let user = get(idx_user);
        let pass = get(idx_pass);
        let totp = get(idx_totp);
        let clean_pass = (!pass.is_empty() && !is_placeholder_value(&pass)).then_some(pass);
        let clean_totp = (!totp.is_empty() && !is_placeholder_value(&totp)).then_some(totp);
        if clean_pass.is_none() && clean_totp.is_none() {
            continue;
        }
        let mut name = get(idx_name);
        if name.is_empty() {
            name = host_from_url(&url)
                .or_else(|| (!user.is_empty()).then(|| user.clone()))
                .unwrap_or_else(|| "Imported Login".to_owned());
        }
        candidates.push(build_login_candidate(
            &name,
            (!url.is_empty()).then_some(url),
            (!user.is_empty()).then_some(user),
            clean_pass,
            clean_totp,
            filename.unwrap_or("CSV row"),
            "high",
        ));
    }

    if candidates.is_empty() {
        return None;
    }
    Some(SmartExtractBatchResult {
        detected_format: "chrome_csv".to_owned(),
        detected_format_zh: "表格凭据 CSV".to_owned(),
        candidates,
        ignored: Vec::new(),
        warnings: Vec::new(),
        sealed_env_template: None,
    })
}

pub(super) fn try_extract_aws_credentials(
    text: &str,
    filename: Option<&str>,
) -> Option<SmartExtractBatchResult> {
    if !text.contains("aws_access_key_id") {
        return None;
    }
    let mut current_profile = "default".to_owned();
    let mut sections: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') && line.len() > 2 {
            current_profile = line[1..line.len() - 1]
                .trim()
                .trim_start_matches("profile ")
                .trim()
                .to_owned();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            sections
                .entry(current_profile.clone())
                .or_default()
                .insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }

    let mut candidates = Vec::new();
    for (profile, map) in sections {
        let Some(access_key) = map.get("aws_access_key_id").cloned().filter(|s| !s.is_empty()) else {
            continue;
        };
        let secret_key = map
            .get("aws_secret_access_key")
            .cloned()
            .filter(|s| !s.is_empty());
        let session_token = map
            .get("aws_session_token")
            .cloned()
            .filter(|s| !s.is_empty());
        let region = map.get("region").cloned().filter(|s| !s.is_empty());

        let name = if profile == "default" {
            "AWS Credentials".to_owned()
        } else {
            format!("AWS ({profile})")
        };
        let mut input = blank_input("custom", &name);
        input.folder = "Cloud".to_owned();
        input.description = match &region {
            Some(reg) => format!("AWS profile: {profile} · {reg}"),
            None => format!("AWS profile: {profile}"),
        };
        input
            .modules
            .push(secret_mod("customSecret", "AWS_ACCESS_KEY_ID"));
        input
            .secrets
            .named_secrets
            .insert("AWS_ACCESS_KEY_ID".to_owned(), access_key.clone());
        if let Some(ref sk) = secret_key {
            input
                .modules
                .push(secret_mod("customSecret", "AWS_SECRET_ACCESS_KEY"));
            input
                .secrets
                .named_secrets
                .insert("AWS_SECRET_ACCESS_KEY".to_owned(), sk.clone());
        }
        if let Some(ref st) = session_token {
            input
                .modules
                .push(secret_mod("customSecret", "AWS_SESSION_TOKEN"));
            input
                .secrets
                .named_secrets
                .insert("AWS_SESSION_TOKEN".to_owned(), st.clone());
        }
        let summary = match region {
            Some(r) => format!("AWS · {profile} · {r}"),
            None => format!("AWS · {profile}"),
        };
        candidates.push(make_candidate(
            "aws",
            "AWS",
            "AWS",
            "high",
            summary,
            filename.unwrap_or("~/.aws/credentials").to_owned(),
            input,
            None,
        ));
    }

    if candidates.is_empty() {
        return None;
    }
    Some(SmartExtractBatchResult {
        detected_format: "aws_credentials".to_owned(),
        detected_format_zh: "AWS 凭据配置".to_owned(),
        candidates,
        ignored: Vec::new(),
        warnings: Vec::new(),
        sealed_env_template: None,
    })
}

pub(super) fn looks_like_ssh_config_file(text: &str, lower_file: &str) -> bool {
    let has_host = text
        .lines()
        .any(|l| l.trim_start().to_ascii_lowercase().starts_with("host "));
    let has_hostname = text
        .lines()
        .any(|l| l.trim_start().to_ascii_lowercase().starts_with("hostname "));
    (has_host && has_hostname) || (lower_file.ends_with("ssh/config") && has_host)
}

pub(super) fn looks_like_env_document(text: &str, lower_file: &str) -> bool {
    let file_hint = lower_file.ends_with(".env")
        || lower_file.contains(".env.")
        || lower_file.ends_with(".env.local")
        || lower_file.ends_with(".env.production");
    let non_comment: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if non_comment.is_empty() {
        return false;
    }
    // A file named .env is configuration even when every key is lowercase; content
    // sniffing keeps the stricter shell grammar so TOML/INI/properties files are not
    // mistaken for dotenv files.
    if file_hint {
        return !ingest::parse_env_config_vars(text).is_empty();
    }
    let vars = ingest::parse_env_vars(text);
    if vars.is_empty() {
        return false;
    }
    // Require high ratio of KEY=VALUE lines and at least 2 vars (single line handled by mixed extractor too)
    vars.len() * 10 >= non_comment.len() * 7
}

pub(super) fn extract_env_document(text: &str, filename: Option<&str>) -> SmartExtractBatchResult {
    let vars = ingest::parse_env_config_vars(text);
    let mut candidates = Vec::new();
    let mut ignored = Vec::new();
    let mut remaining_secrets: Vec<(String, String)> = Vec::new();
    let mut seen_keys = HashSet::new();
    let mut extracted_secret_keys = HashSet::new();
    let mut public_keys = HashSet::new();

    for var in vars {
        if !seen_keys.insert(var.key.clone()) {
            continue;
        }
        let before_cands = candidates.len();
        let before_rem = remaining_secrets.len();
        let before_ignored = ignored.len();
        classify_key_value_entry(
            &var.key,
            &var.value,
            filename.unwrap_or(".env"),
            &mut candidates,
            &mut remaining_secrets,
            &mut ignored,
        );
        if candidates.len() > before_cands || remaining_secrets.len() > before_rem {
            extracted_secret_keys.insert(var.key);
        } else if ignored.len() > before_ignored
            && template_may_keep_value(&ignored[ignored.len() - 1], &var.key, &var.value)
        {
            public_keys.insert(var.key);
        }
    }

    if !remaining_secrets.is_empty() {
        candidates.push(build_env_group_candidate(
            &remaining_secrets,
            filename,
            ".env",
        ));
    }

    let sealed = ingest::seal_env_template_selected(text, &extracted_secret_keys, &public_keys);
    let sealed_env_template = (!sealed.sealed_keys.is_empty()).then_some(sealed.text);

    SmartExtractBatchResult {
        detected_format: "env".to_owned(),
        detected_format_zh: ".env 环境变量".to_owned(),
        candidates,
        ignored,
        warnings: Vec::new(),
        sealed_env_template,
    }
}

/// Whether a value the classifier filtered out may stay verbatim in the sealed template.
/// Ports, URLs, flags and sample placeholders must survive or the template is useless; a
/// weak value under a secret-sounding key (`DB_PASS=abc`) is still a secret and is removed.
fn template_may_keep_value(ignored: &IgnoredSnippet, key: &str, value: &str) -> bool {
    // A "public" URL can still embed a password (`https://user:pass@host`).
    let embeds_credential = has_high_confidence_token_prefix(value)
        || Url::parse(value)
            .ok()
            .and_then(|url| url.password().map(str::to_owned))
            .is_some_and(|pass| !pass.is_empty());
    match ignored.reason.as_str() {
        "placeholder" => true,
        "non_secret" => !embeds_credential,
        "low_entropy" => {
            let leaf = key.rsplit(['.', '/']).next().unwrap_or(key);
            key_secret_score(leaf) == 0 && !embeds_credential
        }
        _ => false,
    }
}

pub(super) fn parse_json_or_jsonc(trimmed: &str, lower_file: &str) -> Option<Value> {
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
            return Some(val);
        }
        let cleaned = strip_jsonc(trimmed);
        return serde_json::from_str::<Value>(&cleaned).ok();
    }
    if (lower_file.ends_with(".json") || lower_file.ends_with(".jsonc"))
        && (trimmed.starts_with("//") || trimmed.starts_with("/*"))
    {
        let cleaned = strip_jsonc(trimmed);
        let c = cleaned.trim();
        if c.starts_with('{') || c.starts_with('[') {
            return serde_json::from_str::<Value>(c).ok();
        }
    }
    None
}

pub(super) fn strip_jsonc(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut no_comments = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_str = false;
    while i < bytes.len() {
        if in_str {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                no_comments.push(bytes[i] as char);
                no_comments.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if bytes[i] == b'"' {
                in_str = false;
            }
            let ch = input[i..].chars().next().unwrap();
            no_comments.push(ch);
            i += ch.len_utf8();
        } else if bytes[i] == b'"' {
            in_str = true;
            no_comments.push('"');
            i += 1;
        } else if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            if i + 1 < bytes.len() {
                i += 2;
            } else {
                break;
            }
        } else {
            let ch = input[i..].chars().next().unwrap();
            no_comments.push(ch);
            i += ch.len_utf8();
        }
    }

    // Strip trailing commas before `}` or `]` outside strings
    let cb = no_comments.as_bytes();
    let mut out = String::with_capacity(no_comments.len());
    let mut j = 0;
    let mut in_s = false;
    while j < cb.len() {
        if in_s {
            if cb[j] == b'\\' && j + 1 < cb.len() {
                out.push(cb[j] as char);
                out.push(cb[j + 1] as char);
                j += 2;
                continue;
            }
            if cb[j] == b'"' {
                in_s = false;
            }
            let ch = no_comments[j..].chars().next().unwrap();
            out.push(ch);
            j += ch.len_utf8();
        } else if cb[j] == b'"' {
            in_s = true;
            out.push('"');
            j += 1;
        } else if cb[j] == b',' {
            let mut k = j + 1;
            while k < cb.len() && cb[k].is_ascii_whitespace() {
                k += 1;
            }
            if k < cb.len() && (cb[k] == b'}' || cb[k] == b']') {
                j += 1;
                continue;
            }
            out.push(',');
            j += 1;
        } else {
            let ch = no_comments[j..].chars().next().unwrap();
            out.push(ch);
            j += ch.len_utf8();
        }
    }
    out
}

pub(super) fn try_extract_docker_auths(
    value: &Value,
    filename: Option<&str>,
    candidates: &mut Vec<ExtractedCandidate>,
    decoded_paths: &mut HashSet<String>,
) {
    let Some(auths) = value.get("auths").and_then(Value::as_object) else {
        return;
    };
    for (registry, entry) in auths {
        let Some(auth_b64) = entry.get("auth").and_then(Value::as_str) else {
            continue;
        };
        let trimmed = auth_b64.trim();
        if trimmed.is_empty() || is_placeholder_value(trimmed) {
            continue;
        }
        let Ok(decoded_bytes) = BASE64_STANDARD.decode(trimmed) else {
            continue;
        };
        let Ok(decoded_str) = String::from_utf8(decoded_bytes) else {
            continue;
        };
        let Some((user, pass)) = decoded_str.split_once(':') else {
            continue;
        };
        if pass.is_empty() || is_placeholder_value(pass) {
            continue;
        }
        decoded_paths.insert(format!("auths.{registry}.auth"));
        let clean_url = if registry.starts_with("http://") || registry.starts_with("https://") {
            registry.clone()
        } else {
            format!("https://{registry}")
        };
        let host = host_from_url(&clean_url).unwrap_or_else(|| registry.clone());
        candidates.push(build_login_candidate(
            &format!("Docker · {host}"),
            Some(clean_url),
            (!user.is_empty()).then(|| user.to_owned()),
            Some(pass.to_owned()),
            None,
            filename.unwrap_or("~/.docker/config.json"),
            "high",
        ));
    }
}

pub(super) fn try_extract_gcp_service_account(
    value: &Value,
    filename: Option<&str>,
) -> Option<SmartExtractBatchResult> {
    if value.get("type").and_then(Value::as_str) != Some("service_account") {
        return None;
    }
    let private_key = value.get("private_key").and_then(Value::as_str)?.trim();
    if !private_key.contains("PRIVATE KEY-----") {
        return None;
    }
    let project_id = value
        .get("project_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("GCP");
    let client_email = value
        .get("client_email")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let key_file = filename
        .and_then(|f| Path::new(f).file_name().and_then(|s| s.to_str()))
        .unwrap_or("service-account.json");
    let mut input = blank_input("custom", &format!("GCP · {project_id}"));
    input.folder = "Cloud".to_owned();
    input.description = match client_email {
        Some(email) => format!("GCP Service Account · {email}"),
        None => format!("GCP Service Account · {project_id}"),
    };
    if let Some(email) = client_email {
        input.modules.push(secret_mod("username", "username"));
        input
            .secrets
            .named_secrets
            .insert("username".to_owned(), email.to_owned());
    }
    input.modules.push(secret_mod("privateKey", "privateKey"));
    input.secrets.private_key = Some(private_key.to_owned());
    input.secrets.private_key_name = Some(key_file.to_owned());
    if let Some(key_id) = value
        .get("private_key_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        input.modules.push(secret_mod("customSecret", "GCP_PRIVATE_KEY_ID"));
        input
            .secrets
            .named_secrets
            .insert("GCP_PRIVATE_KEY_ID".to_owned(), key_id.to_owned());
    }
    let cand = make_candidate(
        "aws",
        "GCP",
        "云密钥",
        "high",
        match client_email {
            Some(email) => format!("GCP · {project_id} · {email}"),
            None => format!("GCP · {project_id}"),
        },
        filename.unwrap_or("service-account.json").to_owned(),
        input,
        None,
    );
    Some(SmartExtractBatchResult {
        detected_format: "gcp_service_account".to_owned(),
        detected_format_zh: "Google Cloud 服务账号 (JSON)".to_owned(),
        candidates: vec![cand],
        ignored: Vec::new(),
        warnings: Vec::new(),
        sealed_env_template: None,
    })
}

pub(super) fn try_extract_json_config(
    value: &Value,
    filename: Option<&str>,
) -> Option<SmartExtractBatchResult> {
    if let Some(gcp_res) = try_extract_gcp_service_account(value, filename) {
        return Some(gcp_res);
    }
    let mut candidates = Vec::new();
    let mut decoded_paths = HashSet::new();
    try_extract_docker_auths(value, filename, &mut candidates, &mut decoded_paths);

    let mut pairs = Vec::new();
    flatten_json_strings(value, "", &mut pairs);
    if pairs.is_empty() && candidates.is_empty() {
        return None;
    }
    let mut ignored = Vec::new();
    let mut remaining_secrets = Vec::new();
    for (path, val) in pairs {
        if decoded_paths.contains(&path) {
            continue;
        }
        let trimmed = val.trim();
        if trimmed.is_empty() {
            continue;
        }
        classify_key_value_entry(
            &path,
            trimmed,
            filename.unwrap_or("JSON config"),
            &mut candidates,
            &mut remaining_secrets,
            &mut ignored,
        );
    }
    if !remaining_secrets.is_empty() {
        candidates.push(build_env_group_candidate(
            &remaining_secrets,
            filename,
            "JSON config",
        ));
    }
    if candidates.is_empty() && ignored.is_empty() {
        return None;
    }
    Some(SmartExtractBatchResult {
        detected_format: "json_config".to_owned(),
        detected_format_zh: "JSON 配置文件".to_owned(),
        candidates,
        ignored,
        warnings: Vec::new(),
        sealed_env_template: None,
    })
}

pub(super) fn flatten_json_strings(value: &Value, prefix: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let next = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_json_strings(v, &next, out);
            }
        }
        Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                let next = format!("{prefix}[{idx}]");
                flatten_json_strings(item, &next, out);
            }
        }
        Value::String(s) => {
            if !prefix.is_empty() && s.len() <= 8192 {
                out.push((prefix.to_owned(), s.clone()));
            }
        }
        _ => {}
    }
}

pub(super) fn try_extract_yaml_toml_config(
    text: &str,
    filename: Option<&str>,
) -> Option<SmartExtractBatchResult> {
    let lower_file = filename.map(|f| f.to_ascii_lowercase()).unwrap_or_default();
    let is_equals_only = lower_file.ends_with(".toml") || lower_file.ends_with(".tfvars");
    let is_yaml = lower_file.ends_with(".yml")
        || lower_file.ends_with(".yaml")
        || lower_file.ends_with("kubeconfig")
        || lower_file.ends_with("/.kube/config")
        || lower_file.ends_with("\\.kube\\config")
        || lower_file.ends_with("/kube/config")
        || lower_file.ends_with("\\kube\\config");

    let mut candidates = Vec::new();
    let mut ignored = Vec::new();
    let mut remaining_secrets = Vec::new();
    let mut section = String::new();
    let mut yaml_sections: Vec<(usize, String)> = Vec::new();

    for raw_line in text.lines() {
        let indent = raw_line.len() - raw_line.trim_start().len();
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if is_yaml {
            while let Some(&(top_indent, _)) = yaml_sections.last() {
                if top_indent >= indent {
                    yaml_sections.pop();
                } else {
                    break;
                }
            }
            // Track YAML parent mapping headers like `anthropic:` or `github.com:`
            if line.ends_with(':') && !line.contains(": ") && !line.contains("://") {
                let header = line
                    .trim_end_matches(':')
                    .trim_start_matches('-')
                    .trim()
                    .trim_matches(['"', '\''])
                    .trim();
                if !header.is_empty() && !is_filesystem_path_value(header) {
                    yaml_sections.push((indent, header.to_owned()));
                }
                continue;
            }
        }
        if !is_yaml && line.starts_with('[') && line.ends_with(']') && line.len() > 2 {
            let raw_sec = line[1..line.len() - 1]
                .trim()
                .trim_matches(['[', ']', '"', '\''])
                .trim();
            // Do not carry filesystem path sections (e.g. Codex [projects.'\\?\C:\...']) as key prefixes
            if is_filesystem_path_value(raw_sec)
                || raw_sec.contains(":\\")
                || raw_sec.contains("\\\\?\\")
            {
                section.clear();
            } else {
                section = raw_sec.to_owned();
            }
            continue;
        }
        // Skip bare quoted strings / array items (common in multiline TOML arrays)
        if line.starts_with('"') || line.starts_with('\'') || line.starts_with(']') || line.starts_with('}') {
            if !line.contains('=') && !is_yaml {
                continue;
            }
        }
        let pair = if is_equals_only {
            line.split_once('=')
        } else if is_yaml {
            split_yaml_key_value(line).or_else(|| split_yaml_env_list_item(line))
        } else {
            line.split_once('=').or_else(|| split_yaml_key_value(line))
        };
        let Some((raw_k, raw_v)) = pair else {
            continue;
        };
        let k = raw_k.trim().trim_start_matches('-').trim().trim_matches('"').trim_matches('\'');
        let v = strip_inline_quotes(raw_v.trim());
        if k.is_empty() || v.is_empty() || is_filesystem_path_value(k) {
            continue;
        }
        let full_key = if is_yaml {
            if yaml_sections.is_empty() {
                k.to_owned()
            } else {
                let prefix = yaml_sections
                    .iter()
                    .map(|(_, s)| s.as_str())
                    .collect::<Vec<_>>()
                    .join(".");
                format!("{prefix}.{k}")
            }
        } else if section.is_empty() {
            k.to_owned()
        } else {
            format!("{section}.{k}")
        };
        classify_key_value_entry(
            &full_key,
            &v,
            filename.unwrap_or("Config"),
            &mut candidates,
            &mut remaining_secrets,
            &mut ignored,
        );
    }

    if !remaining_secrets.is_empty() {
        candidates.push(build_env_group_candidate(
            &remaining_secrets,
            filename,
            "Config",
        ));
    }

    if candidates.is_empty() && ignored.is_empty() {
        return None;
    }

    Some(SmartExtractBatchResult {
        detected_format: "yaml_toml".to_owned(),
        detected_format_zh: "YAML / TOML 配置".to_owned(),
        candidates,
        ignored,
        warnings: Vec::new(),
        sealed_env_template: None,
    })
}

fn split_yaml_env_list_item(line: &str) -> Option<(&str, &str)> {
    // Support docker-compose / K8s YAML sequence environment entries: `- POSTGRES_PASSWORD=secret`
    let rest = line.strip_prefix('-')?.trim();
    let unquoted = if rest.len() >= 2
        && ((rest.starts_with('"') && rest.ends_with('"'))
            || (rest.starts_with('\'') && rest.ends_with('\'')))
    {
        &rest[1..rest.len() - 1]
    } else {
        rest
    };
    let (k, v) = unquoted.split_once('=')?;
    let k = k.trim();
    let v = v.trim();
    if k.is_empty()
        || v.is_empty()
        || k.len() > 64
        || !k.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return None;
    }
    Some((k, v))
}

fn split_yaml_key_value(line: &str) -> Option<(&str, &str)> {
    let bytes = line.as_bytes();
    for (idx, &b) in bytes.iter().enumerate() {
        if b != b':' {
            continue;
        }
        let next = bytes.get(idx + 1).copied();
        // Require YAML ": " separator (avoid splitting Windows C:\ paths or https:// URLs)
        if !matches!(next, Some(b' ' | b'\t')) {
            continue;
        }
        let k = line[..idx].trim();
        let v = line[idx + 1..].trim();
        if !k.is_empty() && !v.is_empty() && !k.contains("://") {
            return Some((k, v));
        }
        return None;
    }
    None
}

pub(super) fn classify_key_value_entry(
    key: &str,
    value: &str,
    source_hint: &str,
    candidates: &mut Vec<ExtractedCandidate>,
    remaining_secrets: &mut Vec<(String, String)>,
    ignored: &mut Vec<IgnoredSnippet>,
) {
    let leaf_key = key
        .rsplit(['.', '/'])
        .next()
        .unwrap_or(key)
        .trim();
    let lower_source = source_hint.to_ascii_lowercase();
    let is_env_source = lower_source == ".env"
        || lower_source.ends_with("/.env")
        || lower_source.ends_with("\\.env")
        || lower_source.contains(".env.");

    if is_placeholder_value(value) {
        let backup = build_single_env_candidate(leaf_key, value, source_hint);
        ignored.push(IgnoredSnippet {
            reason: "placeholder".to_owned(),
            reason_zh: "占位符 / 示例值".to_owned(),
            key: key.to_owned(),
            preview: mask_preview(value),
            candidate: Some(backup),
        });
        return;
    }

    // 1. TOTP URI
    if value.starts_with("otpauth://")
        && let Ok(parsed) = ingest::smart_parse(value, None, None)
    {
        candidates.push(candidate_from_smart_parse(
            parsed,
            Some(leaf_key),
            &format!("{key}=otpauth://..."),
        ));
        return;
    }

    // 2. Database / auth connection URI
    if looks_like_connection_uri(value)
        && let Ok(parsed) = ingest::smart_parse(value, None, None)
        && parsed.kind == "connectionUri"
    {
        candidates.push(candidate_from_smart_parse(
            parsed,
            Some(&pretty_key_title(key)),
            &format!("{key}={}", mask_uri(value)),
        ));
        return;
    }

    // 3. Private key PEM embedded in config
    if value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----")
        && let Ok(parsed) = ingest::smart_parse(value, Some(leaf_key), None)
    {
        candidates.push(candidate_from_smart_parse(
            parsed,
            Some(&pretty_key_title(key)),
            &format!("{key}=<PEM key>"),
        ));
        return;
    }

    let secret_key_score = key_secret_score(leaf_key);
    let non_secret_key = is_explicit_non_secret_key(leaf_key);
    let non_secret_val = is_obvious_non_secret_value(value);

    // 4. Known API key (either unmistakable token prefix, OR known provider + actual secret key + token-like value)
    let looks_like_token_prefix = has_high_confidence_token_prefix(value);
    let profile = api_catalog::infer(key, "", value);
    let has_known_provider = profile.display_name != "API";
    if looks_like_token_prefix
        || (has_known_provider
            && secret_key_score >= 1
            && !non_secret_key
            && !non_secret_val
            && value.len() >= 12
            && !value.contains(char::is_whitespace))
    {
        candidates.push(build_api_candidate(
            &if has_known_provider {
                format!("{} API", profile.display_name)
            } else {
                pretty_key_title(key)
            },
            value,
            profile,
            None,
            &format!("{key}={}", mask_preview(value)),
            "high",
        ));
        return;
    }

    // 5. Public / non-secret config keys, paths, URLs, prose sentences, or model/enum names
    if non_secret_key || non_secret_val || is_prose_sentence(leaf_key, value) {
        let backup = build_single_env_candidate(leaf_key, value, source_hint);
        ignored.push(IgnoredSnippet {
            reason: "non_secret".to_owned(),
            reason_zh: "非敏感普通配置".to_owned(),
            key: key.to_owned(),
            preview: truncate_chars(value, 36),
            candidate: Some(backup),
        });
        return;
    }

    // 6. Secret-looking key name (high precision — never slurp arbitrary paths/routes/doc strings by loose entropy)
    let entropy = shannon_entropy(value);
    let strong_secret = secret_key_score >= 2 && value.len() >= 6;
    let medium_secret = secret_key_score == 1
        && value.len() >= 10
        && !value.contains(char::is_whitespace)
        && (entropy >= 2.8 || has_mixed_secret_chars(value));
    let env_high_entropy_token = is_env_source
        && value.len() >= 32
        && !value.contains(char::is_whitespace)
        && !value.contains('/')
        && !value.contains('\\')
        && entropy >= 4.2
        && has_mixed_secret_chars(value);

    if strong_secret || medium_secret || env_high_entropy_token {
        remaining_secrets.push((leaf_key.to_owned(), value.to_owned()));
    } else {
        let backup = build_single_env_candidate(leaf_key, value, source_hint);
        ignored.push(IgnoredSnippet {
            reason: "low_entropy".to_owned(),
            reason_zh: "普通参数 / 低置信度".to_owned(),
            key: key.to_owned(),
            preview: truncate_chars(value, 36),
            candidate: Some(backup),
        });
    }
}

