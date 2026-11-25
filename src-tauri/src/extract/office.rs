use super::*;

pub(super) const MAX_OFFICE_ENTRY_BYTES: u64 = 8 * 1024 * 1024;
pub(super) const MAX_ZIP_ENTRIES: usize = 30;
pub(super) const MAX_ZIP_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
pub(super) const MAX_FOLDER_DEPTH: usize = 2;
pub(super) const MAX_FOLDER_FILES: usize = 40;
pub(super) const MAX_NOTE_FALLBACK_CHARS: usize = 64 * 1024;

pub(super) fn unescape_xml_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_owned();
    }
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&'
            && let Some(rel_end) = input[i..].find(';')
            && rel_end <= 12
        {
            let entity = &input[i + 1..i + rel_end];
            let decoded = match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                    u32::from_str_radix(&entity[2..], 16)
                        .ok()
                        .and_then(char::from_u32)
                }
                _ if entity.starts_with('#') => entity[1..]
                    .parse::<u32>()
                    .ok()
                    .and_then(char::from_u32),
                _ => None,
            };
            if let Some(ch) = decoded {
                out.push(ch);
                i += rel_end + 1;
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

pub(super) fn try_extract_keepass_xml(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
    if !text.contains("<Entry>") && !text.contains("<KeePassFile") {
        return None;
    }
    static RE_HISTORY: OnceLock<Regex> = OnceLock::new();
    static RE_ENTRY: OnceLock<Regex> = OnceLock::new();
    static RE_STRING: OnceLock<Regex> = OnceLock::new();
    let re_history = RE_HISTORY.get_or_init(|| Regex::new(r"(?s)<History>.*?</History>").unwrap());
    let re_entry = RE_ENTRY.get_or_init(|| Regex::new(r"(?s)<Entry\b[^>]*>(.*?)</Entry>").unwrap());
    let re_string = RE_STRING.get_or_init(|| {
        Regex::new(r"(?s)<String>\s*<Key>([^<]+)</Key>\s*<Value[^>]*>(.*?)</Value>\s*</String>")
            .unwrap()
    });

    let without_history = re_history.replace_all(text, "");
    let mut candidates = Vec::new();
    for cap in re_entry.captures_iter(&without_history) {
        let block = &cap[1];
        let mut title = String::new();
        let mut user = String::new();
        let mut pass = String::new();
        let mut url = String::new();
        let mut totp = String::new();
        let mut notes = String::new();
        for kv in re_string.captures_iter(block) {
            let k = unescape_xml_entities(kv[1].trim());
            let v = unescape_xml_entities(kv[2].trim());
            if v.is_empty() {
                continue;
            }
            match k.to_ascii_lowercase().as_str() {
                "title" => title = v,
                "username" => user = v,
                "password" => pass = v,
                "url" => url = v,
                "otp" | "totp" | "totp seed" => totp = v,
                "notes" => notes = v,
                _ => {}
            }
        }
        if title.is_empty() && user.is_empty() && pass.is_empty() && url.is_empty() {
            continue;
        }
        let name = if !title.is_empty() {
            title
        } else {
            host_from_url(&url)
                .or_else(|| (!user.is_empty()).then(|| user.clone()))
                .unwrap_or_else(|| "KeePass Entry".to_owned())
        };
        let mut cand = build_login_candidate(
            &name,
            (!url.is_empty()).then_some(url),
            (!user.is_empty()).then_some(user),
            (!pass.is_empty()).then_some(pass),
            (!totp.is_empty()).then_some(totp),
            filename.unwrap_or("KeePass XML"),
            "high",
        );
        if !notes.is_empty() {
            cand.input.description = truncate_chars(&notes, 200);
        }
        candidates.push(cand);
    }

    if candidates.is_empty() {
        return None;
    }
    Some(SmartExtractBatchResult {
        detected_format: "keepass_xml".to_owned(),
        detected_format_zh: "KeePass 导出 (XML)".to_owned(),
        candidates,
        ignored: Vec::new(),
        warnings: Vec::new(),
        sealed_env_template: None,
    })
}

pub(super) fn looks_like_password_tsv(text: &str) -> bool {
    let Some(first_line) = text.lines().find(|l| !l.trim().is_empty()) else {
        return false;
    };
    if !first_line.contains('\t') {
        return false;
    }
    let lower = first_line.to_ascii_lowercase();
    (lower.contains("password") || lower.contains("密码") || lower.contains("token") || lower.contains("密钥") || lower.contains("key"))
        && (lower.contains("user")
            || lower.contains("url")
            || lower.contains("host")
            || lower.contains("ip")
            || lower.contains("name")
            || lower.contains("账号")
            || lower.contains("网址")
            || lower.contains("主机")
            || lower.contains("名称")
            || lower.contains("服务"))
}

pub(super) fn try_extract_password_tsv(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty())
        .collect();
    if lines.len() < 2 || !lines[0].contains('\t') {
        return None;
    }
    let headers: Vec<String> = lines[0]
        .split('\t')
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    let find_col = |names: &[&str]| -> Option<usize> {
        headers.iter().position(|h| {
            names
                .iter()
                .any(|n| h == n || h.contains(n))
        })
    };
    let idx_name = find_col(&["name", "title", "service", "site", "名称", "标题", "平台", "服务", "项目", "备注"]);
    let idx_url = find_col(&["url", "website", "origin", "login_uri", "网址", "链接", "地址", "域名"]);
    let idx_host = find_col(&["host", "ip", "server", "主机", "服务器", "ip地址"]);
    let idx_port = find_col(&["port", "端口"]);
    let idx_user = find_col(&["username", "user", "email", "account", "login", "账号", "用户名", "邮箱"]);
    let idx_pass = find_col(&["password", "pass", "pwd", "密码", "口令"]);
    let idx_key = find_col(&["api_key", "apikey", "token", "secret", "密钥"]);
    let idx_totp = find_col(&["totp", "otp", "2fa", "otpauth"]);

    if idx_pass.is_none() && idx_key.is_none() && idx_totp.is_none() {
        return None;
    }

    let source = filename.unwrap_or("Table");
    let mut candidates = Vec::new();
    for line in &lines[1..] {
        let cols: Vec<&str> = line.split('\t').map(str::trim).collect();
        let get = |idx: Option<usize>| -> String {
            idx.and_then(|i| cols.get(i))
                .copied()
                .unwrap_or_default()
                .to_owned()
        };
        let raw_name = get(idx_name);
        let url = get(idx_url);
        let host = get(idx_host);
        let port_str = get(idx_port);
        let user = get(idx_user);
        let pass = get(idx_pass);
        let key = get(idx_key);
        let totp = get(idx_totp);

        let clean_pass = (!pass.is_empty() && !is_placeholder_value(&pass)).then_some(pass);
        let clean_key = (!key.is_empty() && !is_placeholder_value(&key)).then_some(key);
        let clean_totp = (!totp.is_empty() && !is_placeholder_value(&totp)).then_some(totp);

        if url.is_empty()
            && host.is_empty()
            && user.is_empty()
            && clean_pass.is_none()
            && clean_key.is_none()
            && clean_totp.is_none()
        {
            continue;
        }
        // API key row
        if let Some(ref api_key) = clean_key
            && clean_pass.is_none()
            && host.is_empty()
        {
            let name = if !raw_name.is_empty() {
                raw_name
            } else {
                host_from_url(&url).unwrap_or_else(|| "API Credential".to_owned())
            };
            let profile = api_catalog::infer(&name, &url, api_key);
            candidates.push(build_api_candidate(
                &name,
                api_key,
                profile,
                (!url.is_empty()).then_some(url),
                source,
                "high",
            ));
            continue;
        }
        // SSH / Server row
        if !host.is_empty()
            && !host.starts_with("http://")
            && !host.starts_with("https://")
            && (!user.is_empty() || clean_pass.is_some())
        {
            let port = port_str.parse::<u16>().unwrap_or(22);
            let name = if !raw_name.is_empty() {
                raw_name
            } else {
                format!("SSH {host}")
            };
            candidates.push(build_ssh_candidate(
                &name,
                &host,
                port,
                (!user.is_empty()).then_some(user),
                clean_pass,
                source,
            ));
            continue;
        }
        // Login row (require at least a password or 2FA secret so contact/CRM sheets are not treated as logins)
        if clean_pass.is_none() && clean_totp.is_none() {
            continue;
        }
        let name = if !raw_name.is_empty() {
            raw_name
        } else {
            host_from_url(&url)
                .or_else(|| (!user.is_empty()).then(|| user.clone()))
                .unwrap_or_else(|| "Imported Login".to_owned())
        };
        candidates.push(build_login_candidate(
            &name,
            (!url.is_empty()).then_some(url),
            (!user.is_empty()).then_some(user),
            clean_pass,
            clean_totp,
            source,
            "high",
        ));
    }

    if candidates.is_empty() {
        return None;
    }
    let is_xlsx = filename.is_some_and(|f| f.to_ascii_lowercase().ends_with(".xlsx"));
    Some(SmartExtractBatchResult {
        detected_format: if is_xlsx { "xlsx_table" } else { "tsv_table" }.to_owned(),
        detected_format_zh: if is_xlsx { "Excel 表格 (.xlsx)" } else { "制表符表格 (TSV)" }.to_owned(),
        candidates,
        ignored: Vec::new(),
        warnings: Vec::new(),
        sealed_env_template: None,
    })
}

pub(super) fn try_extract_netrc(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
    let lower = filename.unwrap_or_default().to_ascii_lowercase();
    if !lower.ends_with("netrc") && !(text.contains("machine ") && text.contains("password ")) {
        return None;
    }
    let tokens: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .flat_map(|l| l.split_whitespace())
        .collect();
    let mut candidates = Vec::new();
    let mut i = 0;
    let mut cur_machine = String::new();
    let mut cur_login = String::new();
    let mut cur_pass = String::new();
    let flush = |m: &mut String, l: &mut String, p: &mut String, out: &mut Vec<ExtractedCandidate>| {
        if !m.is_empty() && (!l.is_empty() || !p.is_empty()) {
            let url = if m.starts_with("http://") || m.starts_with("https://") {
                m.clone()
            } else {
                format!("https://{m}")
            };
            out.push(build_login_candidate(
                m,
                Some(url),
                (!l.is_empty()).then(|| l.clone()),
                (!p.is_empty()).then(|| p.clone()),
                None,
                filename.unwrap_or(".netrc"),
                "high",
            ));
        }
        m.clear();
        l.clear();
        p.clear();
    };
    while i < tokens.len() {
        match tokens[i] {
            "machine" if i + 1 < tokens.len() => {
                flush(&mut cur_machine, &mut cur_login, &mut cur_pass, &mut candidates);
                cur_machine = tokens[i + 1].to_owned();
                i += 2;
            }
            "login" if i + 1 < tokens.len() => {
                cur_login = tokens[i + 1].to_owned();
                i += 2;
            }
            "password" if i + 1 < tokens.len() => {
                cur_pass = tokens[i + 1].to_owned();
                i += 2;
            }
            _ => i += 1,
        }
    }
    flush(&mut cur_machine, &mut cur_login, &mut cur_pass, &mut candidates);
    if candidates.is_empty() {
        return None;
    }
    Some(SmartExtractBatchResult {
        detected_format: "netrc".to_owned(),
        detected_format_zh: ".netrc 凭据".to_owned(),
        candidates,
        ignored: Vec::new(),
        warnings: Vec::new(),
        sealed_env_template: None,
    })
}

pub(super) fn try_extract_npmrc(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
    let lower = filename.unwrap_or_default().to_ascii_lowercase();
    if !lower.ends_with("npmrc") && !text.contains("_authToken=") {
        return None;
    }
    let mut candidates = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some((lhs, rhs)) = trimmed.split_once(":_authToken=") {
            let token = strip_inline_quotes(rhs);
            if token.is_empty() || token.starts_with("${") {
                continue;
            }
            let host = lhs.trim_start_matches("//").trim_end_matches('/');
            let name = format!("npm · {}", if host.is_empty() { "registry" } else { host });
            let url = (!host.is_empty()).then(|| format!("https://{host}/"));
            let profile = api_catalog::infer(&name, url.as_deref().unwrap_or(""), &token);
            candidates.push(build_api_candidate(
                &name,
                &token,
                profile,
                url,
                filename.unwrap_or(".npmrc"),
                "high",
            ));
        }
    }
    if candidates.is_empty() {
        return None;
    }
    Some(SmartExtractBatchResult {
        detected_format: "npmrc".to_owned(),
        detected_format_zh: ".npmrc 令牌".to_owned(),
        candidates,
        ignored: Vec::new(),
        warnings: Vec::new(),
        sealed_env_template: None,
    })
}

pub(super) fn try_extract_pgpass(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
    let lower = filename.unwrap_or_default().to_ascii_lowercase();
    if !lower.ends_with("pgpass") && !lower.ends_with("pgpass.conf") {
        return None;
    }
    let mut candidates = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(5, ':').collect();
        if parts.len() != 5 || parts[4].is_empty() || is_placeholder_value(parts[4]) {
            continue;
        }
        let (host, port, db, user, pass) = (parts[0], parts[1], parts[2], parts[3], parts[4]);
        let name = format!("PostgreSQL · {host}/{db}");
        let mut input = blank_input("custom", &name);
        input.folder = "Database".to_owned();
        input.modules.push(public_mod("host", "host", host));
        if let Ok(port_num) = port.parse::<u16>()
            && port_num > 0
        {
            input.modules.push(public_mod("port", "port", &port_num.to_string()));
        }
        input.modules.push(secret_mod("username", "username"));
        input.secrets.named_secrets.insert("username".to_owned(), user.to_owned());
        input.modules.push(secret_mod("password", "password"));
        input.secrets.password = Some(pass.to_owned());
        if !db.is_empty() && db != "*" {
            input.modules.push(secret_mod("customSecret", "database"));
            input.secrets.named_secrets.insert("database".to_owned(), db.to_owned());
        }
        candidates.push(make_candidate(
            "database",
            "DB",
            "数据库",
            "high",
            format!("{user}@{host}:{port}/{db}"),
            filename.unwrap_or(".pgpass").to_owned(),
            input,
            None,
        ));
    }
    if candidates.is_empty() {
        return None;
    }
    Some(SmartExtractBatchResult {
        detected_format: "pgpass".to_owned(),
        detected_format_zh: "PostgreSQL (.pgpass)".to_owned(),
        candidates,
        ignored: Vec::new(),
        warnings: Vec::new(),
        sealed_env_template: None,
    })
}

pub(super) fn try_extract_pypirc(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
    let lower = filename.unwrap_or_default().to_ascii_lowercase();
    if !lower.ends_with("pypirc") {
        return None;
    }
    let mut section = String::new();
    let mut repo = String::new();
    let mut user = String::new();
    let mut pass = String::new();
    let mut candidates = Vec::new();
    let flush = |sec: &str, r: &mut String, u: &mut String, p: &mut String, out: &mut Vec<ExtractedCandidate>| {
        if !sec.is_empty() && sec != "distutils" && (!u.is_empty() || !p.is_empty()) {
            let name = format!("PyPI · {sec}");
            out.push(build_login_candidate(
                &name,
                (!r.is_empty()).then(|| r.clone()),
                (!u.is_empty()).then(|| u.clone()),
                (!p.is_empty()).then(|| p.clone()),
                None,
                filename.unwrap_or(".pypirc"),
                "high",
            ));
        }
        r.clear();
        u.clear();
        p.clear();
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            flush(&section, &mut repo, &mut user, &mut pass, &mut candidates);
            section = trimmed[1..trimmed.len() - 1].trim().to_owned();
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=').or_else(|| trimmed.split_once(':')) {
            let val = strip_inline_quotes(v.trim());
            match k.trim().to_ascii_lowercase().as_str() {
                "repository" => repo = val,
                "username" => user = val,
                "password" => pass = val,
                _ => {}
            }
        }
    }
    flush(&section, &mut repo, &mut user, &mut pass, &mut candidates);
    if candidates.is_empty() {
        return None;
    }
    Some(SmartExtractBatchResult {
        detected_format: "pypirc".to_owned(),
        detected_format_zh: "PyPI (.pypirc)".to_owned(),
        candidates,
        ignored: Vec::new(),
        warnings: Vec::new(),
        sealed_env_template: None,
    })
}

pub(super) fn build_secure_note_candidate(filename: &str, text: &str) -> ExtractedCandidate {
    let stem = Path::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(filename);
    let name = sanitize_name(stem, 80);
    let clipped = if text.chars().count() > MAX_NOTE_FALLBACK_CHARS {
        text.chars().take(MAX_NOTE_FALLBACK_CHARS).collect::<String>()
    } else {
        text.to_owned()
    };
    let line_count = clipped.lines().count().max(1);
    let mut input = blank_input("secureNote", &name);
    input.description = format!("Imported from {filename}");
    input.modules.push(secret_mod("secureNote", "secureNote"));
    input
        .secrets
        .named_secrets
        .insert("secureNote".to_owned(), clipped);
    make_candidate(
        "custom",
        "NOTE",
        "笔记",
        "medium",
        format!("{filename} · {line_count} lines"),
        filename.to_owned(),
        input,
        None,
    )
}

pub(super) fn read_zip_entry_bounded<R: Read>(mut entry: R, limit: u64) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    entry
        .by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut buf)?;
    ensure!(buf.len() as u64 <= limit, "Archive entry exceeds size limit");
    Ok(buf)
}

pub fn extract_docx_text(bytes: &[u8]) -> Result<String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).context("Invalid .docx archive")?;
    let entry = archive
        .by_name("word/document.xml")
        .context("Missing word/document.xml in .docx")?;
    let xml_bytes = read_zip_entry_bounded(entry, MAX_OFFICE_ENTRY_BYTES)?;
    let xml = String::from_utf8_lossy(&xml_bytes);

    let mut out = String::new();
    let mut in_text_tag = false;
    let mut text_buf = String::new();
    let mut i = 0;
    let raw = xml.as_ref();
    while i < raw.len() {
        if raw.as_bytes()[i] == b'<'
            && let Some(rel_end) = raw[i..].find('>')
        {
            let tag = &raw[i + 1..i + rel_end];
            if tag == "w:t" || tag.starts_with("w:t ") {
                in_text_tag = true;
                text_buf.clear();
            } else if tag == "/w:t" {
                in_text_tag = false;
                out.push_str(&unescape_xml_entities(&text_buf));
                text_buf.clear();
            } else if tag.starts_with("w:tab") {
                out.push('\t');
            } else if tag.starts_with("w:br") || tag.starts_with("w:cr") || tag == "/w:p" || tag == "/w:tr" {
                if !out.ends_with('\n') {
                    out.push('\n');
                }
            } else if tag == "/w:tc" {
                out.push('\t');
            }
            i += rel_end + 1;
            continue;
        }
        let next_lt = raw[i..].find('<').map(|p| i + p).unwrap_or(raw.len());
        if in_text_tag {
            text_buf.push_str(&raw[i..next_lt]);
        }
        i = next_lt;
    }

    let cleaned: Vec<String> = out
        .lines()
        .map(|line| line.trim_end_matches('\t').trim_end().to_owned())
        .filter(|line| !line.trim().is_empty())
        .collect();
    Ok(cleaned.join("\n"))
}

pub(super) fn excel_col_index(cell_ref: &str) -> Option<usize> {
    let mut col = 0usize;
    let mut seen = false;
    for b in cell_ref.bytes() {
        if b.is_ascii_alphabetic() {
            seen = true;
            col = col * 26 + ((b.to_ascii_uppercase() - b'A') as usize + 1);
        } else {
            break;
        }
    }
    seen.then(|| col.saturating_sub(1))
}

pub fn extract_xlsx_text(bytes: &[u8]) -> Result<String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).context("Invalid .xlsx archive")?;
    static RE_SI: OnceLock<Regex> = OnceLock::new();
    static RE_T: OnceLock<Regex> = OnceLock::new();
    static RE_ROW: OnceLock<Regex> = OnceLock::new();
    static RE_CELL: OnceLock<Regex> = OnceLock::new();
    static RE_V: OnceLock<Regex> = OnceLock::new();
    let re_si = RE_SI.get_or_init(|| Regex::new(r"(?s)<si\b[^>]*>(.*?)</si>").unwrap());
    let re_t = RE_T.get_or_init(|| Regex::new(r"(?s)<t\b[^>]*>(.*?)</t>").unwrap());
    let re_row = RE_ROW.get_or_init(|| Regex::new(r"(?s)<row\b[^>]*>(.*?)</row>").unwrap());
    let re_cell = RE_CELL.get_or_init(|| Regex::new(r"(?s)<c\b([^>]*)>(.*?)</c>").unwrap());
    let re_v = RE_V.get_or_init(|| Regex::new(r"(?s)<v[^>]*>(.*?)</v>").unwrap());

    let mut shared_strings = Vec::new();
    if let Ok(entry) = archive.by_name("xl/sharedStrings.xml") {
        let xml_bytes = read_zip_entry_bounded(entry, MAX_OFFICE_ENTRY_BYTES)?;
        let xml = String::from_utf8_lossy(&xml_bytes);
        for si in re_si.captures_iter(&xml) {
            let mut joined = String::new();
            for t in re_t.captures_iter(&si[1]) {
                joined.push_str(&unescape_xml_entities(&t[1]));
            }
            shared_strings.push(joined);
        }
    }

    let mut sheet_names: Vec<String> = (0..archive.len())
        .filter_map(|i| archive.by_index(i).ok().map(|f| f.name().to_owned()))
        .filter(|name| name.starts_with("xl/worksheets/sheet") && name.ends_with(".xml"))
        .collect();
    sheet_names.sort();
    sheet_names.truncate(10);

    let mut all_lines = Vec::new();
    for sheet_name in sheet_names {
        let Ok(entry) = archive.by_name(&sheet_name) else {
            continue;
        };
        let Ok(xml_bytes) = read_zip_entry_bounded(entry, MAX_OFFICE_ENTRY_BYTES) else {
            continue;
        };
        let xml = String::from_utf8_lossy(&xml_bytes);
        for row_cap in re_row.captures_iter(&xml) {
            let mut row_cells: Vec<String> = Vec::new();
            for cell_cap in re_cell.captures_iter(&row_cap[1]) {
                let attrs = &cell_cap[1];
                let inner = &cell_cap[2];
                let is_shared = attrs.contains("t=\"s\"") || attrs.contains("t='s'");
                let is_inline = attrs.contains("t=\"inlineStr\"") || attrs.contains("t='inlineStr'");
                let cell_ref = attrs
                    .split_whitespace()
                    .find_map(|part| {
                        part.strip_prefix("r=\"")
                            .and_then(|s| s.strip_suffix('"'))
                            .or_else(|| part.strip_prefix("r='").and_then(|s| s.strip_suffix('\'')))
                    });
                let value = if is_inline {
                    let mut s = String::new();
                    for t in re_t.captures_iter(inner) {
                        s.push_str(&unescape_xml_entities(&t[1]));
                    }
                    s
                } else if let Some(v_cap) = re_v.captures(inner) {
                    let raw_v = unescape_xml_entities(v_cap[1].trim());
                    if is_shared {
                        raw_v
                            .parse::<usize>()
                            .ok()
                            .and_then(|idx| shared_strings.get(idx))
                            .cloned()
                            .unwrap_or_default()
                    } else {
                        raw_v
                    }
                } else {
                    String::new()
                };
                let sanitized = value.replace(['\r', '\n', '\t'], " ").trim().to_owned();
                if let Some(col_idx) = cell_ref.and_then(excel_col_index) {
                    if col_idx < 64 {
                        while row_cells.len() < col_idx {
                            row_cells.push(String::new());
                        }
                        if col_idx == row_cells.len() {
                            row_cells.push(sanitized);
                        } else {
                            row_cells[col_idx] = sanitized;
                        }
                    }
                } else {
                    row_cells.push(sanitized);
                }
            }
            while row_cells.last().is_some_and(|c| c.is_empty()) {
                row_cells.pop();
            }
            if row_cells.iter().any(|c| !c.is_empty()) {
                all_lines.push(row_cells.join("\t"));
            }
        }
    }
    Ok(all_lines.join("\n"))
}

pub(super) fn image_mime_for_ext(ext: &str) -> Option<&'static str> {
    match ext {
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "webp" => Some("image/webp"),
        "gif" => Some("image/gif"),
        "bmp" => Some("image/bmp"),
        _ => None,
    }
}

pub(super) fn should_skip_walk_dir(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        ".git" | "node_modules" | "target" | "dist" | "build" | ".venv" | "__pycache__" | ".idea" | ".vscode"
    )
}

pub(super) fn should_skip_binary_ext(ext: &str) -> bool {
    matches!(
        ext,
        "exe" | "dll" | "so" | "dylib" | "bin" | "pdb" | "o" | "obj" | "rlib" | "a" | "lib"
            | "mp4" | "mov" | "avi" | "mkv" | "mp3" | "wav" | "flac" | "iso" | "dmg" | "msi"
            | "woff" | "woff2" | "ttf" | "otf" | "ico" | "icns" | "class" | "pyc" | "wasm"
    )
}

pub(super) fn collect_walk_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_FOLDER_DEPTH || out.len() >= MAX_FOLDER_FILES {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut sorted: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    sorted.sort();
    for path in sorted {
        if out.len() >= MAX_FOLDER_FILES {
            break;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if is_symlink_path(&path) {
            continue;
        }
        if path.is_dir() {
            if !should_skip_walk_dir(name) && depth < MAX_FOLDER_DEPTH {
                collect_walk_files(&path, depth + 1, out);
            }
            continue;
        }
        if path.is_file() {
            let lower_name = name.to_ascii_lowercase();
            if is_env_template_filename(&lower_name) || is_non_secret_ssh_artifact(&lower_name) {
                continue;
            }
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase)
                .unwrap_or_default();
            if !should_skip_binary_ext(&ext) {
                out.push(path);
            }
        }
    }
}

pub fn extract_from_bytes(
    bytes: &[u8],
    filename: &str,
    existing: &[DecryptedConnection],
) -> Result<SmartExtractBatchResult> {
    extract_from_bytes_inner(bytes, filename, existing, true)
}

pub(super) fn extract_from_bytes_inner(
    bytes: &[u8],
    filename: &str,
    existing: &[DecryptedConnection],
    allow_note_fallback: bool,
) -> Result<SmartExtractBatchResult> {
    ensure!(
        bytes.len() <= MAX_BATCH_TEXT_BYTES,
        "{filename} exceeds 16 MiB limit"
    );
    let lower = filename.to_ascii_lowercase();

    if lower.ends_with(".docx") {
        let text = extract_docx_text(bytes)?;
        ensure!(!text.trim().is_empty(), "{filename} contains no readable text");
        let mut res = extract_batch(&text, Some(filename), existing)?;
        if allow_note_fallback && res.candidates.is_empty() && res.ignored.is_empty() {
            res.candidates.push(build_secure_note_candidate(filename, &text));
            res.detected_format = "docx_note".to_owned();
            res.detected_format_zh = "Word 文档 (.docx)".to_owned();
            reconcile_with_vault(&mut res.candidates, existing);
        }
        return Ok(res);
    }

    if lower.ends_with(".xlsx") {
        let text = extract_xlsx_text(bytes)?;
        ensure!(!text.trim().is_empty(), "{filename} contains no readable cells");
        let mut res = extract_batch(&text, Some(filename), existing)?;
        if allow_note_fallback && res.candidates.is_empty() && res.ignored.is_empty() {
            res.candidates.push(build_secure_note_candidate(filename, &text));
            res.detected_format = "xlsx_note".to_owned();
            res.detected_format_zh = "Excel 表格 (.xlsx)".to_owned();
            reconcile_with_vault(&mut res.candidates, existing);
        }
        return Ok(res);
    }

    if lower.ends_with(".zip") {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).context("Invalid .zip archive")?;
        let mut parts = Vec::new();
        let mut warnings = Vec::new();
        let mut total_unpacked = 0u64;
        let mut processed = 0usize;
        for idx in 0..archive.len() {
            if processed >= MAX_ZIP_ENTRIES {
                warnings.push(format!("{filename}: only first {MAX_ZIP_ENTRIES} files inspected"));
                break;
            }
            let Ok(entry) = archive.by_index(idx) else {
                continue;
            };
            if entry.is_dir() {
                continue;
            }
            let raw_name = entry.name().to_owned();
            if raw_name.contains("..")
                || raw_name.split('/').any(should_skip_walk_dir)
                || raw_name.ends_with(".mvault")
            {
                continue;
            }
            let display_name = Path::new(&raw_name)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&raw_name)
                .to_owned();
            let lower_display = display_name.to_ascii_lowercase();
            if is_env_template_filename(&lower_display) || is_non_secret_ssh_artifact(&lower_display) {
                continue;
            }
            let ext = Path::new(&display_name)
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase)
                .unwrap_or_default();
            if should_skip_binary_ext(&ext) || image_mime_for_ext(&ext).is_some() || ext == "zip" {
                continue;
            }
            let remaining = MAX_ZIP_TOTAL_BYTES.saturating_sub(total_unpacked);
            if remaining == 0 {
                warnings.push(format!("{filename}: reached 16 MiB unpacked limit"));
                break;
            }
            let Ok(entry_bytes) = read_zip_entry_bounded(entry, remaining.min(MAX_OFFICE_ENTRY_BYTES)) else {
                continue;
            };
            total_unpacked += entry_bytes.len() as u64;
            processed += 1;
            // Inside archives, extract only real credentials (do NOT turn README/source files into junk notes)
            if let Ok(part) = extract_from_bytes_inner(&entry_bytes, &display_name, existing, false)
                && (!part.candidates.is_empty() || !part.ignored.is_empty())
            {
                parts.push(part);
            }
        }
        let mut merged = merge_batch_results(parts, existing);
        if merged.detected_format == "mixed_text" {
            merged.detected_format = "zip_archive".to_owned();
            merged.detected_format_zh = "压缩包 (.zip)".to_owned();
        }
        merged.warnings.extend(warnings);
        return Ok(merged);
    }

    let text = std::str::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("{filename} is binary or not UTF-8 text and was skipped"))?;
    let trimmed = text.trim_start_matches('\u{feff}').trim();
    ensure!(!trimmed.is_empty(), "{filename} is empty");
    let mut res = extract_batch(trimmed, Some(filename), existing)?;
    if allow_note_fallback && res.candidates.is_empty() && res.ignored.is_empty() {
        res.candidates.push(build_secure_note_candidate(filename, trimmed));
        res.detected_format = "text_note".to_owned();
        res.detected_format_zh = "文本 / 安全笔记".to_owned();
        reconcile_with_vault(&mut res.candidates, existing);
    }
    Ok(res)
}

pub fn extract_from_paths(
    paths: &[PathBuf],
    existing: &[DecryptedConnection],
) -> ExtractedPathsOutcome {
    // Track (path, is_direct_file): direct dropped files allow secure-note fallback; walked folder files do not.
    let mut expanded_files: Vec<(PathBuf, bool)> = Vec::new();
    for path in paths {
        if path.is_dir() {
            let mut walked = Vec::new();
            collect_walk_files(path, 0, &mut walked);
            for p in walked {
                expanded_files.push((p, false));
            }
        } else if path.is_file() {
            expanded_files.push((path.clone(), true));
        }
    }

    let mut mvault_paths = Vec::new();
    let mut images = Vec::new();
    let mut parts = Vec::new();
    let mut warnings = Vec::new();
    let mut source_files = Vec::new();

    for (path, is_direct_file) in expanded_files {
        let fname = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("file")
            .to_owned();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();

        if ext == "mvault" {
            mvault_paths.push(path);
            continue;
        }

        let Ok(meta) = std::fs::metadata(&path) else {
            if is_direct_file {
                warnings.push(format!("{fname}: unable to read file metadata"));
            }
            continue;
        };
        if meta.len() > MAX_BATCH_TEXT_BYTES as u64 {
            if is_direct_file {
                warnings.push(format!("{fname} exceeds 16 MiB and was skipped"));
            }
            continue;
        }

        if let Some(mime) = image_mime_for_ext(&ext) {
            if let Ok(bytes) = std::fs::read(&path) {
                images.push(DroppedImagePayload {
                    file_name: fname.clone(),
                    mime_type: mime.to_owned(),
                    data_base64: BASE64_STANDARD.encode(&bytes),
                    source_path: Some(path.clone()),
                    source_ref: None,
                });
                source_files.push(fname);
            }
            continue;
        }

        let Ok(bytes) = std::fs::read(&path) else {
            if is_direct_file {
                warnings.push(format!("{fname}: unable to read file"));
            }
            continue;
        };
        match extract_from_bytes_inner(&bytes, &fname, existing, is_direct_file) {
            Ok(mut part) => {
                if is_direct_file || !part.candidates.is_empty() || !part.ignored.is_empty() {
                    record_source_path(&mut part, &path);
                    source_files.push(fname);
                    parts.push(part);
                }
            }
            Err(error) => {
                if is_direct_file {
                    warnings.push(format!("{fname}: {error}"));
                }
            }
        }
    }

    let mut merged = merge_batch_results(parts, existing);
    merged.warnings.extend(warnings);
    ExtractedPathsOutcome {
        batch: merged,
        images,
        mvault_paths,
        source_files,
    }
}

