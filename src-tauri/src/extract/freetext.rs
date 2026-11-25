use super::*;

pub(super) fn extract_mixed_free_text(text: &str, filename: Option<&str>) -> SmartExtractBatchResult {
    let mut candidates = Vec::new();
    let mut ignored = Vec::new();
    let mut seen_fp = HashSet::new();

    // Pass 1: PEM Private Keys
    let mut working = extract_pem_blocks(text, filename, &mut candidates, &mut seen_fp);

    // Pass 2: Multi-line cURL commands
    working = extract_curl_blocks(&working, &mut candidates, &mut seen_fp);

    // Pass 3: Semantic Context Blocks
    let blocks = slice_context_blocks(&working);
    let mut loose_env_secrets: Vec<(String, String)> = Vec::new();

    for block in &blocks {
        let heading = block.heading.as_deref();

        // 3a. Extract all otpauth:// URIs in block
        for uri in find_totp_uris(&block.body) {
            if let Ok(parsed) = ingest::smart_parse(&uri, None, None) {
                let cand = candidate_from_smart_parse(parsed, heading, "otpauth://...");
                push_unique(&mut candidates, &mut seen_fp, cand);
            }
        }

        // 3b. Extract all database / auth connection URIs
        for uri in find_connection_uris(&block.body) {
            if let Ok(parsed) = ingest::smart_parse(&uri, None, None)
                && parsed.kind == "connectionUri"
            {
                let cand = candidate_from_smart_parse(parsed, heading, &mask_uri(&uri));
                push_unique(&mut candidates, &mut seen_fp, cand);
            }
        }

        // 3c. Extract ssh commands
        for line in block.body.lines() {
            let l = line.trim().trim_start_matches('$').trim();
            if l.starts_with("ssh ")
                && let Ok(parsed) = ingest::smart_parse(l, None, None)
                && parsed.kind == "sshCommand"
            {
                let cand = candidate_from_smart_parse(parsed, heading, l);
                push_unique(&mut candidates, &mut seen_fp, cand);
            }
        }

        // 3d. Labeled server / login / API key-value block (Chinese & English)
        let labeled_matched = extract_labeled_block(&block.body, heading, &mut candidates, &mut seen_fp);

        // 3e. Single-line login triplets & server shorthands
        if !labeled_matched {
            extract_inline_patterns(&block.body, heading, &mut candidates, &mut seen_fp);
        }

        // 3f. Embedded KEY=VALUE lines (e.g. inside code blocks or chat snippets)
        let env_vars = ingest::parse_env_vars(&block.body);
        for var in env_vars {
            let mut promoted = Vec::new();
            classify_key_value_entry(
                &var.key,
                &var.value,
                heading.unwrap_or("snippet"),
                &mut promoted,
                &mut loose_env_secrets,
                &mut ignored,
            );
            for mut cand in promoted {
                if let Some(h) = heading
                    && (cand.input.name == "API" || cand.input.name.starts_with("Imported"))
                {
                    cand.input.name = sanitize_name(h, 80);
                }
                push_unique(&mut candidates, &mut seen_fp, cand);
            }
        }

        // 3g. Standalone known API keys / tokens anywhere in prose
        extract_bare_tokens(&block.body, heading, &mut candidates, &mut seen_fp);
    }

    if !loose_env_secrets.is_empty() {
        let env_cand = build_env_group_candidate(&loose_env_secrets, filename, "Env snippet");
        push_unique(&mut candidates, &mut seen_fp, env_cand);
    }

    // If nothing at all was extracted, try single-item smart_parse ONLY if it actually carries credentials
    // (avoid turning bare URLs or unauthenticated curl commands into empty credential cards).
    if candidates.is_empty() && ignored.is_empty() {
        if let Ok(parsed) = ingest::smart_parse(text, filename, None)
            && parsed.kind != "secureNote"
            && smart_parse_has_real_credential(&parsed)
        {
            candidates.push(candidate_from_smart_parse(
                parsed,
                None,
                filename.unwrap_or("Input"),
            ));
        }
    }

    let (detected_format, detected_format_zh) = if candidates.len() == 1 {
        match candidates[0].kind.as_str() {
            "totp" => ("totp".to_owned(), "2FA 动态验证码".to_owned()),
            "privateKey" => ("private_key".to_owned(), "SSH 私钥".to_owned()),
            "apiKey" => ("api_key".to_owned(), "API 密钥".to_owned()),
            "database" => ("database".to_owned(), "数据库连接".to_owned()),
            "ssh" => ("ssh".to_owned(), "SSH 服务器".to_owned()),
            "login" => ("login".to_owned(), "网站账号密码".to_owned()),
            _ => ("mixed_text".to_owned(), "混合文本".to_owned()),
        }
    } else {
        ("mixed_text".to_owned(), "混合文本智能提取".to_owned())
    };

    SmartExtractBatchResult {
        detected_format,
        detected_format_zh,
        candidates,
        ignored,
        warnings: Vec::new(),
        sealed_env_template: None,
    }
}

pub(super) fn extract_pem_blocks(
    text: &str,
    filename: Option<&str>,
    candidates: &mut Vec<ExtractedCandidate>,
    seen_fp: &mut HashSet<String>,
) -> String {
    static PEM_RE: OnceLock<Regex> = OnceLock::new();
    let re = PEM_RE.get_or_init(|| {
        Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
            .unwrap()
    });
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for m in re.find_iter(text) {
        let prefix = &text[last..m.start()];
        let heading = extract_trailing_heading(prefix);
        if let Ok(parsed) =
            ingest::smart_parse(m.as_str(), heading.as_deref().or(filename), None)
        {
            let cand = candidate_from_smart_parse(
                parsed,
                heading.as_deref(),
                filename.unwrap_or("-----BEGIN PRIVATE KEY-----"),
            );
            push_unique(candidates, seen_fp, cand);
        }
        out.push_str(prefix);
        out.push('\n');
        last = m.end();
    }
    out.push_str(&text[last..]);
    out
}

pub(super) fn smart_parse_has_real_credential(parsed: &ingest::SmartParseResult) -> bool {
    let secrets = &parsed.input.secrets;
    match parsed.kind.as_str() {
        "loginUrl" => {
            let has_user = secrets.get("username").is_some_and(|v| !v.trim().is_empty() && !is_placeholder_value(v));
            let has_pass = secrets.password.as_deref().is_some_and(|v| !v.trim().is_empty() && !is_placeholder_value(v));
            has_user || has_pass
        }
        "curl" => {
            let has_api = secrets.get("apiCredential").is_some_and(|v| !v.trim().is_empty() && !is_placeholder_value(v));
            let has_user = secrets.get("username").is_some_and(|v| !v.trim().is_empty() && !is_placeholder_value(v));
            let has_pass = secrets.password.as_deref().is_some_and(|v| !v.trim().is_empty() && !is_placeholder_value(v));
            has_api || has_user || has_pass
        }
        "apiKey" => secrets
            .get("apiCredential")
            .is_some_and(|v| !v.trim().is_empty() && !is_placeholder_value(v)),
        _ => true,
    }
}

pub(super) fn extract_curl_blocks(
    text: &str,
    candidates: &mut Vec<ExtractedCandidate>,
    seen_fp: &mut HashSet<String>,
) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut kept: Vec<&str> = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim().trim_start_matches('$').trim();
        if trimmed.starts_with("curl ") {
            let heading = kept.last().copied().and_then(clean_heading_line);
            let mut block = trimmed.to_owned();
            while (block.ends_with('\\') || block.ends_with('^')) && i + 1 < lines.len() {
                i += 1;
                block.push('\n');
                block.push_str(lines[i]);
            }
            if let Ok(parsed) = ingest::smart_parse(&block, None, None)
                && parsed.kind == "curl"
                && smart_parse_has_real_credential(&parsed)
            {
                let cand = candidate_from_smart_parse(parsed, heading.as_deref(), "curl ...");
                push_unique(candidates, seen_fp, cand);
                i += 1;
                continue;
            }
        }
        kept.push(lines[i]);
        i += 1;
    }
    kept.join("\n")
}

pub(super) struct ContextBlock {
    heading: Option<String>,
    body: String,
}

pub(super) fn slice_context_blocks(text: &str) -> Vec<ContextBlock> {
    let mut blocks: Vec<ContextBlock> = Vec::new();
    let mut current_heading: Option<String> = None;
    let mut current_lines: Vec<String> = Vec::new();

    let flush = |heading: &mut Option<String>,
                 lines: &mut Vec<String>,
                 out: &mut Vec<ContextBlock>| {
        let body = lines.join("\n").trim().to_owned();
        if !body.is_empty() {
            out.push(ContextBlock {
                heading: heading.clone(),
                body,
            });
        }
        lines.clear();
    };

    for raw_line in text.lines() {
        let trimmed = raw_line.trim();
        // Horizontal rule divider
        if trimmed.len() >= 3
            && (trimmed.chars().all(|c| c == '-')
                || trimmed.chars().all(|c| c == '=')
                || trimmed.chars().all(|c| c == '*'))
        {
            flush(&mut current_heading, &mut current_lines, &mut blocks);
            current_heading = None;
            continue;
        }
        // Blank line ends block
        if trimmed.is_empty() {
            flush(&mut current_heading, &mut current_lines, &mut blocks);
            continue;
        }
        // Explicit heading line (Markdown `#`, Chinese `【...】`, `[Title]`, or numbered title with no secret)
        if let Some(h) = detect_explicit_heading(trimmed) {
            flush(&mut current_heading, &mut current_lines, &mut blocks);
            current_heading = Some(h);
            continue;
        }
        current_lines.push(raw_line.to_owned());
    }
    flush(&mut current_heading, &mut current_lines, &mut blocks);
    blocks
}

pub(super) fn detect_explicit_heading(line: &str) -> Option<String> {
    if line.starts_with('#') {
        let h = line.trim_start_matches('#').trim();
        if !h.is_empty() && h.chars().count() <= 48 && !h.contains("://") {
            return Some(h.to_owned());
        }
    }
    if line.starts_with('【') && line.ends_with('】') && line.chars().count() <= 40 {
        let inner = line.trim_start_matches('【').trim_end_matches('】').trim();
        if !inner.is_empty() {
            return Some(inner.to_owned());
        }
    }
    if line.starts_with('[') && line.ends_with(']') && line.chars().count() <= 40 && !line.contains(' ') {
        let inner = line[1..line.len() - 1].trim();
        if !inner.is_empty() {
            return Some(inner.to_owned());
        }
    }
    // Plain short Chinese/English label ending with colon like "生产服务器：" or "OpenAI 测试："
    if (line.ends_with(':') || line.ends_with('：'))
        && !line.contains("://")
        && line.chars().count() <= 32
    {
        let inner = line.trim_end_matches([':', '：']).trim();
        let lower = inner.to_ascii_lowercase();
        if !inner.is_empty() && !is_field_label_word(&lower) {
            return Some(inner.to_owned());
        }
    }
    None
}

pub(super) fn is_field_label_word(lower: &str) -> bool {
    matches!(
        lower,
        "ip" | "host"
            | "hostname"
            | "server"
            | "address"
            | "port"
            | "user"
            | "username"
            | "account"
            | "login"
            | "email"
            | "pass"
            | "password"
            | "pwd"
            | "url"
            | "website"
            | "site"
            | "endpoint"
            | "token"
            | "apikey"
            | "api key"
            | "secret"
            | "主机"
            | "服务器"
            | "地址"
            | "端口"
            | "账号"
            | "用户名"
            | "密码"
            | "网址"
            | "链接"
            | "密钥"
    )
}

pub(super) fn extract_trailing_heading(prefix: &str) -> Option<String> {
    prefix
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .and_then(clean_heading_line)
}

pub(super) fn clean_heading_line(line: &str) -> Option<String> {
    let t = line.trim();
    if let Some(h) = detect_explicit_heading(t) {
        return Some(h);
    }
    if t.chars().count() <= 36 && !t.contains('=') && !t.contains("://") {
        let cleaned = t.trim_matches(['#', '【', '】', '[', ']', ':', '：', '-', '*']).trim();
        if !cleaned.is_empty() {
            return Some(cleaned.to_owned());
        }
    }
    None
}

pub(super) fn find_totp_uris(text: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"otpauth://[^\s<>"'`]+"#).unwrap());
    re.find_iter(text)
        .map(|m| m.as_str().trim_end_matches([',', '.', ';', ')', ']']).to_owned())
        .collect()
}

pub(super) fn find_connection_uris(text: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)://[^\s<>"'`]+"#).unwrap()
    });
    re.find_iter(text)
        .map(|m| m.as_str().trim_end_matches([',', '.', ';', ')', ']']).to_owned())
        .collect()
}

pub(super) fn looks_like_connection_uri(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "postgres://",
        "postgresql://",
        "mysql://",
        "mariadb://",
        "mongodb://",
        "mongodb+srv://",
        "redis://",
        "rediss://",
        "amqp://",
        "amqps://",
        "mssql://",
        "sqlserver://",
    ]
    .iter()
    .any(|p| lower.starts_with(p))
}

pub(super) fn extract_labeled_block(
    body: &str,
    heading: Option<&str>,
    candidates: &mut Vec<ExtractedCandidate>,
    seen_fp: &mut HashSet<String>,
) -> bool {
    let mut map: BTreeMap<&'static str, String> = BTreeMap::new();
    let mut custom_title: Option<String> = None;

    for raw_line in body.lines() {
        let line = raw_line
            .trim()
            .trim_start_matches(['-', '*', '•', '·'])
            .trim();
        if line.is_empty() {
            continue;
        }
        // Support multiple labeled fields on one line separated by `,` `，` `;` `；` or `  `
        let segments = split_labeled_segments(line);
        for seg in segments {
            let Some((raw_k, raw_v)) = split_label_value(&seg) else {
                // Capture an unlabeled https?:// URL inside the same block (e.g. "测试后台 https://test.foo.com 账号：admin 密码：123")
                if !map.contains_key("url")
                    && (seg.contains("https://") || seg.contains("http://"))
                {
                    static INLINE_URL_RE: OnceLock<Regex> = OnceLock::new();
                    let url_re = INLINE_URL_RE
                        .get_or_init(|| Regex::new(r#"https?://[^\s<>"'`]+"#).unwrap());
                    if let Some(m) = url_re.find(&seg) {
                        let found_url = m
                            .as_str()
                            .trim_end_matches([',', '.', ';', ')', ']', '，', '。'])
                            .to_owned();
                        map.entry("url").or_insert(found_url);
                        let before = seg[..m.start()].trim().trim_matches(['#', '【', '】', '[', ']', ':', '：']);
                        if custom_title.is_none() && !before.is_empty() && before.chars().count() <= 28 {
                            custom_title = Some(before.to_owned());
                        }
                        continue;
                    }
                }
                // Capture an unlabeled IPv4 address (e.g. "生产阿里云 47.98.120.44 端口2222 账号 root 密码 ...")
                if !map.contains_key("host") && !seg.contains("://") {
                    static INLINE_IP_RE: OnceLock<Regex> = OnceLock::new();
                    let ip_re = INLINE_IP_RE
                        .get_or_init(|| Regex::new(r"\b((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?\b").unwrap());
                    if let Some(caps) = ip_re.captures(&seg) {
                        let ip = caps[1].to_owned();
                        if ip.split('.').all(|oct| oct.parse::<u8>().is_ok()) {
                            map.entry("host").or_insert(ip);
                            if let Some(p) = caps.get(2)
                                && p.as_str().parse::<u16>().is_ok_and(|n| n > 0)
                            {
                                map.entry("port").or_insert(p.as_str().to_owned());
                            }
                            let before = seg[..caps.get(0).unwrap().start()]
                                .trim()
                                .trim_matches(['#', '【', '】', '[', ']', ':', '：']);
                            if custom_title.is_none() && !before.is_empty() && before.chars().count() <= 28 {
                                custom_title = Some(before.to_owned());
                            }
                            continue;
                        }
                    }
                }
                // Capture first non-KV short title line inside the block
                if custom_title.is_none()
                    && map.is_empty()
                    && seg.chars().count() <= 32
                    && !seg.contains("://")
                    && !seg.contains('=')
                {
                    custom_title = Some(seg.trim_matches(['#', '【', '】', '[', ']']).trim().to_owned());
                }
                continue;
            };
            let k = raw_k.trim().to_ascii_lowercase();
            let v = raw_v.trim().trim_matches(['`', '"', '\'']).to_owned();
            if v.is_empty() || is_placeholder_value(&v) {
                continue;
            }
            if matches!(
                k.as_str(),
                "name" | "title" | "service" | "app" | "名称" | "平台" | "服务" | "项目"
            ) {
                custom_title.get_or_insert(v);
            } else if matches!(
                k.as_str(),
                "ip" | "host" | "hostname" | "server" | "address" | "ssh" | "主机" | "服务器" | "服务器地址" | "ip地址" | "公网ip" | "内网ip"
            ) {
                // Support "1.2.3.4:2222" inside host value, rejecting filesystem paths / prose addresses
                if let Some((h, p)) = split_host_port(&v) {
                    if is_plausible_host(&h) {
                        map.entry("host").or_insert(h);
                        map.entry("port").or_insert(p);
                    }
                } else if is_plausible_host(&v) {
                    map.entry("host").or_insert(v);
                }
            } else if matches!(k.as_str(), "port" | "ssh port" | "端口" | "端口号") {
                map.entry("port").or_insert(v);
            } else if matches!(
                k.as_str(),
                "user" | "username" | "account" | "login" | "email" | "phone" | "账号" | "帐号" | "用户名" | "登录名" | "邮箱" | "手机号"
            ) {
                if !is_prose_sentence(&k, &v) {
                    map.entry("username").or_insert(v);
                }
            } else if matches!(
                k.as_str(),
                "pass" | "password" | "pwd" | "passwd" | "密码" | "登录密码" | "初始密码" | "口令"
            ) {
                if !is_filesystem_path_value(&v) && !is_api_route_or_url_value(&v) && !is_prose_sentence(&k, &v) {
                    map.entry("password").or_insert(v);
                }
            } else if matches!(
                k.as_str(),
                "url" | "website" | "site" | "endpoint" | "base url" | "baseurl" | "link" | "网址" | "链接" | "后台" | "后台地址" | "登录地址" | "接口地址"
            ) {
                map.entry("url").or_insert(v);
            } else if matches!(
                k.as_str(),
                "api key" | "apikey" | "api_key" | "token" | "access token" | "secret" | "key" | "密钥" | "令牌"
            ) {
                if !is_obvious_non_secret_value(&v) && !is_prose_sentence(&k, &v) {
                    map.entry("apiCredential").or_insert(v);
                }
            } else if matches!(k.as_str(), "totp" | "2fa" | "otp") {
                map.entry("totp").or_insert(v);
            }
        }
    }

    if map.len() < 2 {
        return false;
    }

    let title_hint = heading.or(custom_title.as_deref());

    // Case A: Server / SSH block
    if let Some(host) = map.get("host").cloned() {
        let port = map
            .get("port")
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(22);
        let name = title_hint
            .map(|h| sanitize_name(h, 80))
            .unwrap_or_else(|| {
                map.get("username")
                    .map(|u| format!("{u}@{host}"))
                    .unwrap_or_else(|| host.clone())
            });
        let cand = build_ssh_candidate(
            &name,
            &host,
            port,
            map.get("username").cloned(),
            map.get("password").cloned(),
            &format!("SSH {host}:{port}"),
        );
        push_unique(candidates, seen_fp, cand);
        return true;
    }

    // Case B: API Credentials block
    if let Some(token) = map.get("apiCredential").cloned() {
        let raw_url = map.get("url").cloned().unwrap_or_default();
        let profile = api_catalog::infer(title_hint.unwrap_or_default(), &raw_url, &token);
        let resolved_url = api_catalog::normalize_base_url(&raw_url, profile.default_base_url)
            .ok()
            .filter(|s| !s.is_empty());
        let name = title_hint
            .map(|h| sanitize_name(h, 80))
            .unwrap_or_else(|| {
                let fallback = api_catalog::fallback_name(
                    resolved_url.as_deref().unwrap_or_default(),
                    profile,
                );
                format!("{fallback} API")
            });
        let cand = build_api_candidate(
            &name,
            &token,
            profile,
            resolved_url,
            &format!("{name} · {}", mask_preview(&token)),
            "high",
        );
        push_unique(candidates, seen_fp, cand);
        return true;
    }

    // Case C: Website Login block
    if map.contains_key("username") || map.contains_key("password") {
        let raw_url = map.get("url").cloned();
        let name = title_hint
            .map(|h| sanitize_name(h, 80))
            .or_else(|| raw_url.as_deref().and_then(host_from_url))
            .or_else(|| map.get("username").cloned())
            .unwrap_or_else(|| "Account Login".to_owned());
        let cand = build_login_candidate(
            &name,
            raw_url,
            map.get("username").cloned(),
            map.get("password").cloned(),
            map.get("totp").cloned(),
            &format!("Login · {name}"),
            "high",
        );
        push_unique(candidates, seen_fp, cand);
        return true;
    }

    false
}

pub(super) fn split_labeled_segments(line: &str) -> Vec<String> {
    // Split lines that contain multiple Chinese/English field labels like "账号：root  密码：123456"
    // or colon-less Chinese chat style like "账号 admin@foo.com 密码 Pass123! 端口2222"
    static LABEL_RE: OnceLock<Regex> = OnceLock::new();
    let re = LABEL_RE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)(?:^|\s+)(?:",
            r"(?:ip|host|port|user|username|account|email|pass|password|pwd|url|token|apikey|主机|服务器|地址|端口|账号|帐号|用户名|邮箱|密码|网址|链接|密钥)\s*[:：]|",
            r"(?:主机|服务器|端口|账号|帐号|用户名|密码|网址|密钥)\s+|",
            r"端口\d{2,5}\b",
            r")"
        ))
        .unwrap()
    });
    let mut out = Vec::new();
    for semi_part in line.split(['；', ';']) {
        let piece = semi_part.trim();
        if piece.is_empty() {
            continue;
        }
        let starts: Vec<usize> = re
            .find_iter(piece)
            .map(|m| {
                // Skip leading whitespace before the label itself
                let s = m.as_str();
                let ws_len = s.len() - s.trim_start().len();
                m.start() + ws_len
            })
            .collect();
        if starts.len() <= 1 {
            out.push(piece.to_owned());
            continue;
        }
        if starts[0] > 0 {
            let prefix = piece[..starts[0]].trim();
            if !prefix.is_empty() {
                out.push(prefix.to_owned());
            }
        }
        for idx in 0..starts.len() {
            let start = starts[idx];
            let end = starts.get(idx + 1).copied().unwrap_or(piece.len());
            let slice = piece[start..end].trim();
            if !slice.is_empty() {
                out.push(slice.to_owned());
            }
        }
    }
    out
}

pub(super) fn split_label_value(seg: &str) -> Option<(&str, &str)> {
    // Avoid splitting URLs like "https://..." at the scheme colon
    if let Some(pos) = seg.find('：') {
        let k = seg[..pos].trim();
        let v = seg[pos + '：'.len_utf8()..].trim();
        if !k.is_empty() && !v.is_empty() {
            return Some((k, v));
        }
    }
    if let Some(pos) = seg.find(':') {
        let k = seg[..pos].trim();
        let rest = &seg[pos + 1..];
        if rest.starts_with("//") {
            return None;
        }
        let v = rest.trim();
        if !k.is_empty() && !v.is_empty() && k.chars().count() <= 20 {
            return Some((k, v));
        }
    }
    // Support compact Chinese port shorthand like "端口2222"
    if let Some(rest) = seg.strip_prefix("端口") {
        let port_val = rest.trim();
        if !port_val.is_empty() && port_val.chars().all(|c| c.is_ascii_digit()) {
            return Some(("端口", port_val));
        }
    }
    // Support colon-less Chinese chat labels like "账号 admin@myapp.cn" / "密码 Admin#2026"
    for prefix in [
        "服务器地址",
        "登录密码",
        "初始密码",
        "后台地址",
        "登录地址",
        "接口地址",
        "用户名",
        "登录名",
        "服务器",
        "端口号",
        "账号",
        "帐号",
        "密码",
        "口令",
        "端口",
        "主机",
        "网址",
        "链接",
        "密钥",
        "令牌",
    ] {
        if let Some(rest) = seg.strip_prefix(prefix)
            && rest.starts_with(char::is_whitespace)
        {
            let v = rest.trim();
            if !v.is_empty() {
                return Some((prefix, v));
            }
        }
    }
    None
}

pub(super) fn is_plausible_host(raw: &str) -> bool {
    let h = raw.trim();
    if h.is_empty()
        || h.len() > 253
        || h.contains(char::is_whitespace)
        || h.contains('/')
        || h.contains('\\')
        || h.contains("://")
        || is_filesystem_path_value(h)
    {
        return false;
    }
    let valid_chars = h
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'));
    valid_chars && (h.contains('.') || h.contains(':') || h.eq_ignore_ascii_case("localhost"))
}

pub(super) fn split_host_port(raw: &str) -> Option<(String, String)> {
    let (h, p) = raw.rsplit_once(':')?;
    if !h.is_empty() && !h.contains("://") && p.parse::<u16>().is_ok() {
        return Some((h.trim().to_owned(), p.trim().to_owned()));
    }
    None
}

pub(super) fn extract_inline_patterns(
    body: &str,
    heading: Option<&str>,
    candidates: &mut Vec<ExtractedCandidate>,
    seen_fp: &mut HashSet<String>,
) {
    // 1. Single-line login triplets: "https://example.com  user@mail.com  Pass123!"
    //    or "https://example.com | user | pass"
    static URL_LINE_RE: OnceLock<Regex> = OnceLock::new();
    let url_re = URL_LINE_RE.get_or_init(|| {
        Regex::new(r"^(https?://[^\s|]+)\s*(?:\||\t|\s{1,})\s*([^\s|]+)\s*(?:\||\t|/|\s{1,})\s*(\S+)$")
            .unwrap()
    });

    // 2. Single-line server shorthand: "198.51.100.8:22 root P@ss123" or "198.51.100.8:2200 root/P@ss123"
    static SSH_LINE_RE: OnceLock<Regex> = OnceLock::new();
    let ssh_re = SSH_LINE_RE.get_or_init(|| {
        Regex::new(r"^((?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)(?::(\d{1,5}))?\s+([a-zA-Z0-9._-]+)(?:\s+|/|:\s*)(\S{4,})$")
            .unwrap()
    });

    // 3. 3-line login block: URL on line 1, username on line 2, password on line 3
    let non_empty: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if non_empty.len() == 3
        && (non_empty[0].starts_with("http://") || non_empty[0].starts_with("https://"))
        && Url::parse(non_empty[0]).is_ok()
        && !non_empty[1].contains(' ')
        && !non_empty[2].contains(' ')
        && !non_empty[1].contains("://")
        && !non_empty[2].contains("://")
    {
        let host = host_from_url(non_empty[0]).unwrap_or_else(|| "Website Login".to_owned());
        let name = heading.map(|h| sanitize_name(h, 80)).unwrap_or(host);
        let cand = build_login_candidate(
            &name,
            Some(non_empty[0].to_owned()),
            Some(non_empty[1].to_owned()),
            Some(non_empty[2].to_owned()),
            None,
            non_empty[0],
            "high",
        );
        push_unique(candidates, seen_fp, cand);
        return;
    }

    for raw_line in &non_empty {
        let line = raw_line.trim_start_matches(['-', '*', '•']).trim();
        if let Some(caps) = url_re.captures(line) {
            let url = caps[1].to_owned();
            let user = caps[2].to_owned();
            let pass = caps[3].to_owned();
            if !is_placeholder_value(&pass) {
                let name = heading
                    .map(|h| sanitize_name(h, 80))
                    .or_else(|| host_from_url(&url))
                    .unwrap_or_else(|| "Website Login".to_owned());
                let cand = build_login_candidate(
                    &name,
                    Some(url.clone()),
                    Some(user),
                    Some(pass),
                    None,
                    &url,
                    "high",
                );
                push_unique(candidates, seen_fp, cand);
                continue;
            }
        }
        if let Some(caps) = ssh_re.captures(line) {
            let host = caps[1].to_owned();
            let port = caps
                .get(2)
                .and_then(|m| m.as_str().parse::<u16>().ok())
                .unwrap_or(22);
            let user = caps[3].to_owned();
            let pass = caps[4].to_owned();
            if !host.starts_with("http") && !is_placeholder_value(&pass) {
                let name = heading
                    .map(|h| sanitize_name(h, 80))
                    .unwrap_or_else(|| format!("{user}@{host}"));
                let cand = build_ssh_candidate(
                    &name,
                    &host,
                    port,
                    Some(user),
                    Some(pass),
                    &format!("{host}:{port}"),
                );
                push_unique(candidates, seen_fp, cand);
            }
        }
    }
}

pub(super) fn extract_bare_tokens(
    body: &str,
    heading: Option<&str>,
    candidates: &mut Vec<ExtractedCandidate>,
    seen_fp: &mut HashSet<String>,
) {
    static TOKEN_RE: OnceLock<Regex> = OnceLock::new();
    let re = TOKEN_RE.get_or_init(|| {
        Regex::new(concat!(
            r"(?:",
            r"sk-ant-[A-Za-z0-9_-]{16,}|",
            r"sk-proj-[A-Za-z0-9_-]{16,}|",
            r"sk-svcacct-[A-Za-z0-9_-]{16,}|",
            r"sk-or-v1-[A-Za-z0-9]{16,}|",
            r"github_pat_[A-Za-z0-9_]{20,}|",
            r"gh[pous]_[A-Za-z0-9]{20,}|",
            r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|",
            r"AIza[0-9A-Za-z_-]{30,}|",
            r"gsk_[A-Za-z0-9]{20,}|",
            r"xai-[A-Za-z0-9]{20,}|",
            r"hf_[A-Za-z0-9]{20,}|",
            r"(?:xoxb|xoxp|xapp)-[0-9A-Za-z-]{20,}|",
            r"glpat-[A-Za-z0-9_-]{18,}|",
            r"cfut_[A-Za-z0-9_-]{16,}|",
            r"sbp_[A-Za-z0-9]{20,}|",
            r"lin_api_[A-Za-z0-9]{20,}|",
            r"ntn_[A-Za-z0-9]{20,}|",
            r"re_[A-Za-z0-9_]{16,}|",
            r"npm_[A-Za-z0-9]{20,}|",
            r"pypi-[A-Za-z0-9_-]{24,}|",
            r"pplx-[A-Za-z0-9]{20,}|",
            r"tvly-[A-Za-z0-9_-]{16,}|",
            r"fc-[A-Za-z0-9]{20,}|",
            r"sntrys_[A-Za-z0-9_=+-]{20,}|",
            r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|",
            r"AKIA[0-9A-Z]{16}|",
            r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}\b|",
            r"sk-[A-Za-z0-9_-]{24,}",
            r")"
        ))
        .unwrap()
    });

    for m in re.find_iter(body) {
        let token = m.as_str().trim();
        if is_placeholder_value(token) {
            continue;
        }
        // Telegram bot token
        if token.contains(":AA") && token.split(':').next().is_some_and(|p| p.chars().all(|c| c.is_ascii_digit())) {
            let mut input = blank_input("api", heading.unwrap_or("Telegram Bot API"));
            input.modules.push(public_mod("url", "url", "https://api.telegram.org/"));
            input.modules.push(secret_mod("apiCredential", "apiCredential"));
            input.secrets.named_secrets.insert("apiCredential".to_owned(), token.to_owned());
            let cand = make_candidate(
                "apiKey",
                "API",
                "API",
                "high",
                format!("Telegram Bot · {}", mask_preview(token)),
                mask_preview(token),
                input,
                None,
            );
            push_unique(candidates, seen_fp, cand);
            continue;
        }

        // AWS Access Key ID
        if token.starts_with("AKIA") && token.len() == 20 {
            let mut input = blank_input("custom", heading.unwrap_or("AWS Access Key"));
            input.folder = "Cloud".to_owned();
            input.modules.push(secret_mod("customSecret", "AWS_ACCESS_KEY_ID"));
            input
                .secrets
                .named_secrets
                .insert("AWS_ACCESS_KEY_ID".to_owned(), token.to_owned());
            let cand = make_candidate(
                "aws",
                "AWS",
                "AWS",
                "high",
                format!("AWS · {}", mask_preview(token)),
                mask_preview(token),
                input,
                None,
            );
            push_unique(candidates, seen_fp, cand);
            continue;
        }

        let context = heading.unwrap_or(body);
        let profile = api_catalog::infer(context, "", token);
        let name = if profile.display_name != "API" {
            match heading {
                Some(h) if !h.to_ascii_lowercase().contains(&profile.display_name.to_ascii_lowercase()) => {
                    format!("{h} ({})", profile.display_name)
                }
                _ => format!("{} API", profile.display_name),
            }
        } else {
            heading
                .map(|h| sanitize_name(h, 80))
                .unwrap_or_else(|| "API Key".to_owned())
        };
        let base_url = (!profile.default_base_url.is_empty())
            .then(|| profile.default_base_url.to_owned());
        let cand = build_api_candidate(
            &name,
            token,
            profile,
            base_url,
            &mask_preview(token),
            if profile.display_name != "API" { "high" } else { "medium" },
        );
        push_unique(candidates, seen_fp, cand);
    }
}

pub(super) fn has_high_confidence_token_prefix(value: &str) -> bool {
    if value.len() < 16 || value.contains(char::is_whitespace) {
        return false;
    }
    [
        "sk-ant-",
        "sk-proj-",
        "sk-svcacct-",
        "sk-or-v1-",
        "github_pat_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "sk_live_",
        "sk_test_",
        "rk_live_",
        "rk_test_",
        "AIza",
        "gsk_",
        "xai-",
        "hf_",
        "xoxb-",
        "xoxp-",
        "xapp-",
        "glpat-",
        "cfut_",
        "sbp_",
        "lin_api_",
        "ntn_",
        "re_",
        "npm_",
        "pypi-",
        "pplx-",
        "tvly-",
        "fc-",
        "sntrys_",
        "SG.",
        "AKIA",
    ]
    .iter()
    .any(|p| value.starts_with(p))
}

pub(super) fn is_placeholder_value(val: &str) -> bool {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return true;
    }
    if (trimmed.starts_with('<') && trimmed.ends_with('>'))
        || (trimmed.starts_with("{{") && trimmed.ends_with("}}"))
        || (trimmed.starts_with("${") && trimmed.ends_with('}'))
    {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "xxx"
            | "xxxx"
            | "xxxxx"
            | "xxxxxx"
            | "changeme"
            | "change_me"
            | "change-me"
            | "replace_me"
            | "replace-me"
            | "todo"
            | "none"
            | "null"
            | "placeholder"
            | "secret"
            | "password"
            | "your_api_key"
            | "your-api-key"
            | "your-api-key-here"
            | "your_secret_here"
            | "your-token-here"
            | "your_key_here"
            | "your-key-here"
            | "your_token_here"
            | "your_password_here"
            | "your-password-here"
            | "put_your_key_here"
            | "insert_here"
            | "insert-here"
            | "sk-xxx"
            | "sk-..."
            | "sk-your-api-key"
            | "sk-your-api-key-here"
            | "dummy"
            | "fake"
            | "redacted"
            | "[redacted]"
            | "example"
            | "demo"
            | "test"
    ) {
        return true;
    }
    if lower.starts_with("your_")
        || lower.starts_with("your-")
        || lower.contains("placeholder")
        || lower.contains("replace_with")
        || lower.contains("replace-with")
        || lower.contains("your-api-key")
        || lower.contains("your_api_key")
        || lower.contains("your-token")
        || lower.contains("your_token")
        || lower.contains("insert_your")
        || lower.contains("insert-your")
        || lower.contains("redacted")
    {
        return true;
    }
    // Masked bullets/asterisks like "sk-••••1234" or "********"
    if trimmed.chars().all(|c| c == '*' || c == '•' || c == 'x' || c == 'X') && trimmed.len() >= 3 {
        return true;
    }
    // Repeated dummy fill after a token prefix (e.g. "sk-xxxxxxxxxxxx", "ghp_00000000000000000000")
    for prefix in ["sk-proj-", "sk-ant-", "sk-", "ghp_", "gho_", "glpat-", "xai-", "gsk_"] {
        if let Some(rest) = lower.strip_prefix(prefix)
            && rest.len() >= 6
            && let Some(first) = rest.chars().next()
            && matches!(first, 'x' | '0' | '*' | '•' | '.')
            && rest.chars().all(|c| c == first)
        {
            return true;
        }
    }
    false
}

pub(super) fn is_explicit_non_secret_key(key: &str) -> bool {
    let base = key.split('[').next().unwrap_or(key).trim();
    let upper = base.to_ascii_uppercase();
    if upper.starts_with("NEXT_PUBLIC_")
        || upper.starts_with("VITE_")
        || upper.starts_with("PUBLIC_")
        || upper.starts_with("REACT_APP_PUBLIC_")
        || upper.starts_with("NPM_CONFIG_")
        || upper.starts_with("CARGO_")
        || upper.starts_with("RUSTUP_")
        || upper.starts_with("PLAYWRIGHT_")
        || upper.starts_with("PNPM_")
        || upper.starts_with("CONDA_")
        || upper.starts_with("POETRY_")
        || upper.starts_with("CUDA_")
        || upper.starts_with("XDG_")
    {
        return true;
    }
    if matches!(
        upper.as_str(),
        "NODE_ENV"
            | "APP_ENV"
            | "ENV"
            | "ENVIRONMENT"
            | "RUST_LOG"
            | "LOG_LEVEL"
            | "DEBUG"
            | "VERBOSE"
            | "PORT"
            | "HOST"
            | "HOSTS"
            | "HOSTNAME"
            | "BIND"
            | "DOMAIN"
            | "DOMAINS"
            | "RULE"
            | "RULES"
            | "GEOSITE"
            | "GEOIP"
            | "OUTBOUND"
            | "OUTBOUNDTAG"
            | "INBOUND"
            | "INBOUNDTAG"
            | "PROXY"
            | "PROXIES"
            | "ROUTE"
            | "ROUTES"
            | "PATTERN"
            | "PATTERNS"
            | "TAG"
            | "TAGS"
            | "TYPE"
            | "PROTOCOL"
            | "NETWORK"
            | "REMARKS"
            | "DESCRIPTION"
            | "TITLE"
            | "NAME"
            | "TZ"
            | "TIMEZONE"
            | "LANG"
            | "LOCALE"
            | "APP_NAME"
            | "APP_URL"
            | "SITE_URL"
            | "BASE_URL"
            | "BASEURL"
            | "API_URL"
            | "ENDPOINT"
            | "URI"
            | "URL"
            | "ORIGIN"
            | "PATH"
            | "PATHS"
            | "FILEPATH"
            | "FILE_PATH"
            | "DIR"
            | "DIRECTORY"
            | "FOLDER"
            | "CWD"
            | "WORKDIR"
            | "ROOT"
            | "HOME"
            | "PREFIX"
            | "COMMAND"
            | "CMD"
            | "ARGS"
            | "ARG"
            | "BIN"
            | "BINARY"
            | "EXEC"
            | "EXECUTABLE"
            | "SHELL"
            | "SCRIPT"
            | "METHOD"
            | "HTTP_METHOD"
            | "SCOPE"
            | "SCOPES"
            | "BASIS"
            | "SOURCE"
            | "SOURCES"
            | "TARGET"
            | "SCHEMA"
            | "FORMAT"
            | "CONTENT_TYPE"
            | "MIME_TYPE"
            | "ENCODING"
            | "SUMMARY"
            | "DOC"
            | "DOCS"
            | "DOCUMENTATION"
            | "EXAMPLE"
            | "EXAMPLES"
            | "SAMPLE"
            | "DEFAULT"
            | "DEFAULTS"
            | "NOTE"
            | "NOTES"
            | "COMMENT"
            | "COMMENTS"
            | "LABEL"
            | "LABELS"
            | "MESSAGE"
            | "ERROR"
            | "STATUS"
            | "STATE"
            | "PHASE"
            | "STAGE"
            | "MODE"
            | "LEVEL"
            | "PRIORITY"
            | "CATEGORY"
            | "GROUP"
            | "KIND"
            | "CLASS"
            | "ROLE"
            | "PERMISSION"
            | "PERMISSIONS"
            | "POLICY"
            | "APPROVAL_POLICY"
            | "SANDBOX_MODE"
            | "TRUST_LEVEL"
            | "MODEL"
            | "MODELS"
            | "PROVIDER"
            | "PROVIDERS"
            | "VENDOR"
            | "ENGINE"
            | "RUNTIME"
            | "PLATFORM"
            | "ARCH"
            | "OS"
            | "LANGUAGE"
            | "CHARSET"
            | "CURRENCY"
            | "UNIT"
            | "TIMEFRAME"
            | "INTERVAL"
            | "PERIOD"
            | "FREQUENCY"
            | "SCHEDULE"
            | "CRON"
            | "LIMIT"
            | "OFFSET"
            | "PAGE"
            | "SORT"
            | "ORDER"
            | "FILTER"
            | "QUERY"
            | "FIELD"
            | "FIELDS"
            | "COLUMN"
            | "COLUMNS"
            | "TABLE"
            | "INDEX"
            | "PRIMARY_KEY"
            | "FOREIGN_KEY"
            | "SORT_KEY"
            | "PARTITION_KEY"
            | "SHARD_KEY"
            | "CACHE_KEY"
            | "GROUP_KEY"
            | "UNIQUE_KEY"
            | "COMPOSITE_KEY"
            | "KEY_NAME"
            | "KEY_TYPE"
            | "KEY_FIELD"
            | "KEY_PATH"
            | "KEY_FILE"
            | "PUBLIC_KEY"
            | "PUBKEY"
            | "PUB_KEY"
            | "SSH_PUBLIC_KEY"
            | "AUTHOR"
            | "AUTHORS"
            | "AUTHORITY"
            | "LICENSE"
            | "HOMEPAGE"
            | "REPOSITORY"
            | "REPO"
            | "BRANCH"
            | "COMMIT"
            | "PACKAGE"
            | "MODULE"
            | "NAMESPACE"
            | "WORKSPACE"
            | "PROJECT"
            | "PROJECTS"
            | "SERVICE"
            | "CLIENT"
            | "ID"
            | "UUID"
            | "SLUG"
            | "ALIAS"
            | "VERSION"
            | "REGION"
            | "AWS_REGION"
            | "AWS_DEFAULT_REGION"
            | "TIMEOUT"
            | "MAX_RETRIES"
            | "WORKERS"
            | "THREADS"
            | "AUTH_TYPE"
            | "AUTH_MODE"
            | "AUTH_METHOD"
            | "AUTH_HEADER"
            | "AUTH_URL"
            | "AUTH_PROVIDER"
            | "AUTH_SCHEME"
            | "AUTH_FLOW"
            | "PASSWORD_HINT"
            | "PASSWORD_POLICY"
            | "PASSWORD_MIN_LENGTH"
            | "PASSWORD_FIELD"
    ) {
        return true;
    }
    let non_secret_suffixes = [
        "_PATH",
        "_DIR",
        "_DIRECTORY",
        "_FILE",
        "_FOLDER",
        "_CWD",
        "_ROOT",
        "_PREFIX",
        "_SUFFIX",
        "_URL",
        "_URI",
        "_ENDPOINT",
        "_HOST",
        "_PORT",
        "_MODEL",
        "_NAME",
        "_TYPE",
        "_MODE",
        "_HEADER",
        "_FORMAT",
        "_SCHEMA",
        "_DOC",
        "_DOCS",
        "_DESC",
        "_DESCRIPTION",
        "_LABEL",
        "_TITLE",
        "_HINT",
        "_POLICY",
        "_COUNT",
        "_SIZE",
        "_TIMEOUT",
        "_INTERVAL",
        "_ENABLED",
        "_DISABLED",
        "_LEVEL",
        "_VERSION",
        "_REGION",
        "_ZONE",
    ];
    non_secret_suffixes.iter().any(|s| upper.ends_with(s))
}

pub(super) fn is_filesystem_path_value(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return false;
    }
    // Windows extended/UNC paths (`\\?\C:\...`, `\\.\...`, `\\server\share`)
    if v.starts_with(r"\\?\") || v.starts_with(r"\\.\") || v.starts_with(r"\\") {
        return true;
    }
    // Windows drive-letter paths (`C:\...`, `S:/...`)
    let bytes = v.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        return true;
    }
    // Tilde / relative paths (`~/.codex/...`, `./...`, `../...`)
    if v.starts_with("~/") || v.starts_with("~\\") || v.starts_with("./") || v.starts_with("../") || v.starts_with(".\\") || v.starts_with("..\\") {
        return true;
    }
    // Common absolute Unix filesystem prefixes
    if [
        "/usr/",
        "/opt/",
        "/var/",
        "/etc/",
        "/home/",
        "/Users/",
        "/Library/",
        "/Applications/",
        "/System/",
        "/bin/",
        "/sbin/",
        "/tmp/",
        "/srv/",
        "/root/",
        "/mnt/",
        "/proc/",
        "/dev/",
    ]
    .iter()
    .any(|prefix| v.starts_with(prefix))
    {
        return true;
    }
    // Path with slash/backslash ending in a well-known code/config/binary extension
    if (v.contains('/') || v.contains('\\')) && !v.contains("://") {
        let lower = v.to_ascii_lowercase();
        let exts = [
            ".exe", ".cmd", ".bat", ".ps1", ".sh", ".mjs", ".cjs", ".js", ".ts", ".tsx",
            ".jsx", ".py", ".rs", ".go", ".json", ".jsonc", ".yaml", ".yml", ".toml",
            ".ini", ".md", ".txt", ".html", ".css", ".png", ".jpg", ".svg", ".dll", ".so",
            ".dylib", ".lock", ".log", ".sqlite", ".db",
        ];
        if exts.iter().any(|ext| lower.ends_with(ext)) {
            return true;
        }
    }
    false
}

pub(super) fn is_api_route_or_url_value(value: &str) -> bool {
    let v = value.trim();
    if v.starts_with("http://") || v.starts_with("https://") {
        // Reject plain URLs unless they carry embedded credentials or secret query parameters
        if let Ok(url) = Url::parse(v) {
            let has_creds = url.password().is_some_and(|p| !p.is_empty());
            let has_secret_query = url.query_pairs().any(|(k, val)| {
                let kl = k.to_ascii_lowercase();
                !val.is_empty()
                    && (kl.contains("key") || kl.contains("token") || kl.contains("secret") || kl == "sig")
            });
            return !has_creds && !has_secret_query;
        }
        return true;
    }
    // Relative REST/API route paths like `/api/v1/broker/accounts/{account_id}/pnl-history`
    if v.starts_with('/') && !v.contains(char::is_whitespace) {
        let slash_count = v.bytes().filter(|&b| b == b'/').count();
        if v.contains('{') && v.contains('}') {
            return true;
        }
        if slash_count >= 2
            && !v.contains('=')
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b':' | b'{' | b'}'))
        {
            return true;
        }
    }
    false
}

pub(super) fn is_prose_sentence(leaf_key: &str, value: &str) -> bool {
    let v = value.trim();
    if !v.contains(' ') {
        return false;
    }
    // Keep explicit Bearer / Basic / Token auth header values
    let lower = v.to_ascii_lowercase();
    if lower.starts_with("bearer ") || lower.starts_with("basic ") || lower.starts_with("token ") {
        return false;
    }
    // Allow explicit passphrase / recovery phrase / mnemonic keys to hold multi-word phrases
    let ku = leaf_key.to_ascii_uppercase();
    if ku.contains("PASSPHRASE") || ku.contains("MNEMONIC") || ku.contains("SEED_PHRASE") || ku.contains("RECOVERY_PHRASE") {
        return false;
    }
    let words: Vec<&str> = v.split_whitespace().collect();
    if words.len() >= 4 {
        let plain_words = words
            .iter()
            .filter(|w| {
                let cleaned = w.trim_matches(|c: char| !c.is_alphanumeric());
                !cleaned.is_empty() && cleaned.chars().all(|c| c.is_ascii_alphabetic())
            })
            .count();
        if plain_words * 2 >= words.len() {
            return true;
        }
    }
    false
}

pub(super) fn has_mixed_secret_chars(value: &str) -> bool {
    let has_upper = value.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = value.bytes().any(|b| b.is_ascii_lowercase());
    let has_digit = value.bytes().any(|b| b.is_ascii_digit());
    let has_symbol = value
        .bytes()
        .any(|b| matches!(b, b'-' | b'_' | b'+' | b'/' | b'=' | b'.' | b'!' | b'@' | b'#' | b'$' | b'%' | b'^' | b'&' | b'*'));
    let classes = usize::from(has_upper) + usize::from(has_lower) + usize::from(has_digit) + usize::from(has_symbol);
    classes >= 2 && (has_digit || (has_upper && has_lower))
}

pub(super) fn is_obvious_non_secret_value(value: &str) -> bool {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "true"
            | "false"
            | "yes"
            | "no"
            | "on"
            | "off"
            | "0"
            | "1"
            | "development"
            | "production"
            | "staging"
            | "info"
            | "debug"
            | "warn"
            | "error"
            | "localhost"
            | "127.0.0.1"
            | "0.0.0.0"
            | "trusted"
            | "untrusted"
            | "auto"
            | "manual"
            | "never"
            | "always"
            | "read-only"
            | "workspace-write"
            | "danger-full-access"
            | "bearer"
            | "basic"
            | "oauth"
            | "oauth2"
            | "jwt"
            | "session"
            | "required"
            | "optional"
            | "enabled"
            | "disabled"
            | "public"
            | "private"
            | "internal"
            | "external"
            | "default"
            | "string"
            | "number"
            | "integer"
            | "boolean"
            | "object"
            | "array"
    ) {
        return true;
    }
    if lower.starts_with("domain:")
        || lower.starts_with("full:")
        || lower.starts_with("geosite:")
        || lower.starts_with("geoip:")
        || lower.starts_with("keyword:")
        || lower.starts_with("regexp:")
    {
        return true;
    }
    // AI model IDs (e.g. gpt-4o, claude-3-5-sonnet, gemini-2.5-pro, o3-mini)
    if ["gpt-", "claude-", "gemini-", "deepseek-", "qwen-", "llama-", "o1-", "o3-", "o4-"]
        .iter()
        .any(|p| lower.starts_with(p))
        && !lower.contains("sk-")
    {
        return true;
    }
    // Template placeholder variables embedded inside values (e.g. `{account_id}`, `${TOKEN}`, `{{openkeylet:...}}`)
    if (trimmed.contains("{{") && trimmed.contains("}}"))
        || (trimmed.contains("${") && trimmed.contains('}'))
    {
        return true;
    }
    if is_filesystem_path_value(trimmed) || is_api_route_or_url_value(trimmed) {
        return true;
    }
    // Pure short integer (e.g. ports, timeouts)
    if trimmed.len() <= 6 && trimmed.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    false
}

fn split_key_tokens(key: &str) -> Vec<String> {
    let base = key.split('[').next().unwrap_or(key).trim();
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = base.chars().collect();
    for (idx, &ch) in chars.iter().enumerate() {
        if matches!(ch, '_' | '-' | '.' | '/' | ' ' | ':') {
            if !cur.is_empty() {
                tokens.push(cur.to_ascii_uppercase());
                cur.clear();
            }
            continue;
        }
        if idx > 0
            && ch.is_ascii_uppercase()
            && chars[idx - 1].is_ascii_lowercase()
            && !cur.is_empty()
        {
            tokens.push(cur.to_ascii_uppercase());
            cur.clear();
        }
        cur.push(ch);
    }
    if !cur.is_empty() {
        tokens.push(cur.to_ascii_uppercase());
    }
    tokens
}

pub(super) fn key_secret_score(key: &str) -> u8 {
    let base = key.split('[').next().unwrap_or(key).trim();
    let upper = base.to_ascii_uppercase();
    let tokens = split_key_tokens(base);

    // Explicit non-secret compound keys that contain KEY / AUTH / PASS
    if matches!(
        upper.as_str(),
        "PRIMARY_KEY"
            | "FOREIGN_KEY"
            | "SORT_KEY"
            | "PARTITION_KEY"
            | "SHARD_KEY"
            | "CACHE_KEY"
            | "GROUP_KEY"
            | "UNIQUE_KEY"
            | "COMPOSITE_KEY"
            | "PUBLIC_KEY"
            | "PUBKEY"
            | "PUB_KEY"
            | "HOTKEY"
            | "SHORTCUT_KEY"
            | "KEYBOARD"
            | "AUTHOR"
            | "AUTHORS"
            | "AUTHORITY"
            | "BYPASS"
            | "COMPASS"
            | "PASSPORT"
    ) {
        return 0;
    }

    let strong_compound = [
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "ACCESSKEY",
        "SECRET_KEY",
        "SECRETKEY",
        "PRIVATE_KEY",
        "PRIVKEY",
        "AUTH_KEY",
        "MASTER_KEY",
        "SIGNING_KEY",
        "ENCRYPTION_KEY",
        "SESSION_KEY",
        "CLIENT_SECRET",
        "AUTH_TOKEN",
        "ACCESS_TOKEN",
        "REFRESH_TOKEN",
        "BEARER_TOKEN",
        "WEBHOOK_SECRET",
    ];
    if strong_compound.iter().any(|w| upper.contains(w)) {
        return 2;
    }

    let strong_tokens = [
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "PWD",
        "TOKEN",
        "APIKEY",
        "ACCESSKEY",
        "SECRETKEY",
        "PRIVKEY",
        "CREDENTIAL",
        "CREDENTIALS",
        "PASSPHRASE",
        "BEARER",
        "JWT",
        "DSN",
        "COOKIE",
        "TOTP",
    ];
    if tokens.iter().any(|tok| strong_tokens.contains(&tok.as_str())) {
        return 2;
    }

    // Compound token pairs like ["API", "KEY"], ["ACCESS", "KEY"], ["PRIVATE", "KEY"], ["SIGNING", "KEY"]
    let has_key_tok = tokens.iter().any(|t| t == "KEY");
    if has_key_tok
        && tokens.iter().any(|t| {
            matches!(
                t.as_str(),
                "API" | "ACCESS" | "SECRET" | "PRIVATE" | "MASTER" | "SIGNING" | "ENCRYPTION"
                    | "AUTH" | "SESSION" | "CLIENT" | "APP" | "LICENSE" | "WEBHOOK" | "OPENAI"
                    | "ANTHROPIC" | "CLAUDE" | "GEMINI" | "DEEPSEEK" | "STRIPE" | "GITHUB"
                    | "GROQ" | "XAI" | "OPENROUTER" | "DASHSCOPE" | "MOONSHOT" | "ZHIPU"
            )
        })
    {
        return 2;
    }

    let medium_tokens = ["KEY", "AUTH", "AUTHENTICATION", "PASS", "CERT", "PEM", "SALT", "PEPPER", "OTP", "WEBHOOK", "SIGNING", "ENCRYPTION"];
    if tokens.iter().any(|tok| medium_tokens.contains(&tok.as_str())) {
        return 1;
    }
    0
}

pub(super) fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

