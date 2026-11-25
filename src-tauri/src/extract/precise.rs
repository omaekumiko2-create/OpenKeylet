//! Precision extractors for files that are mostly prose or commands: agent instruction and
//! rule files, shell startup files and shell history.
//!
//! The general free-text extractor is tuned for pasted notes, where `ssh deploy@host` or
//! `user: alice` is worth a card. Run over a CLAUDE.md or a year of shell history it would
//! fill the scan results with servers and logins that hold no secret, so here a line only
//! counts when it carries something that is unmistakably a credential: a known token
//! format, a private key, an authenticated cURL call, a database URI with a password, or a
//! literal `NAME=value` assignment that the key/value classifier accepts.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PreciseSource {
    /// CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules and rule files.
    AgentRules,
    /// .bashrc, .zshrc, .profile, config.fish, PowerShell profiles.
    ShellStartup,
    /// .bash_history, .zsh_history, fish_history, PSReadLine history.
    ShellHistory,
}

impl PreciseSource {
    fn labels(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::AgentRules => ("agent_rules", "Agent 规则文件", "Agent rules"),
            Self::ShellStartup => ("shell_startup", "Shell 启动配置", "Shell"),
            Self::ShellHistory => ("shell_history", "Shell 历史记录", "Shell history"),
        }
    }
}

pub(super) fn extract_precise_secrets(
    text: &str,
    filename: Option<&str>,
    source: PreciseSource,
) -> SmartExtractBatchResult {
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    let working = extract_pem_blocks(text, filename, &mut candidates, &mut seen);
    let normalized = working
        .lines()
        .map(|line| normalize_precise_line(line, source))
        .collect::<Vec<_>>()
        .join("\n");
    let working = extract_curl_blocks(&normalized, &mut candidates, &mut seen);

    for uri in find_totp_uris(&working) {
        if let Ok(parsed) = ingest::smart_parse(&uri, None, None) {
            push_unique(&mut candidates, &mut seen, candidate_from_smart_parse(parsed, None, "otpauth://..."));
        }
    }
    for uri in find_connection_uris(&working) {
        // A URI without a password is an address, not a credential.
        if let Ok(parsed) = ingest::smart_parse(&uri, None, None)
            && parsed.kind == "connectionUri"
            && parsed
                .input
                .secrets
                .password
                .as_deref()
                .is_some_and(|pass| !is_placeholder_value(pass))
        {
            let cand = candidate_from_smart_parse(parsed, None, &mask_uri(&uri));
            push_unique(&mut candidates, &mut seen, cand);
        }
    }

    let (_, _, group_label) = source.labels();
    let source_hint = filename.unwrap_or(group_label);
    let mut remaining = Vec::new();
    let mut classified_ignored = Vec::new();
    let mut seen_pairs = HashSet::new();
    for line in working.lines() {
        for (key, value) in shell_assignments(line) {
            // History repeats the same export many times; classify each pair once.
            if !seen_pairs.insert((key.clone(), value.clone())) {
                continue;
            }
            let mut promoted = Vec::new();
            classify_key_value_entry(
                &key,
                &value,
                source_hint,
                &mut promoted,
                &mut remaining,
                &mut classified_ignored,
            );
            for cand in promoted {
                push_unique(&mut candidates, &mut seen, cand);
            }
        }
    }

    let mut bare = Vec::new();
    let mut bare_seen = HashSet::new();
    extract_bare_tokens(&working, None, &mut bare, &mut bare_seen);
    for cand in bare {
        // Prose and code blocks contain identifiers such as `re_compile_pattern_cache`
        // that match short token prefixes; real tokens are random and mix digits in.
        let token = cand
            .input
            .secrets
            .get("apiCredential")
            .or_else(|| cand.input.secrets.get("AWS_ACCESS_KEY_ID"))
            .unwrap_or_default();
        if looks_like_random_token(token) {
            push_unique(&mut candidates, &mut seen, cand);
        }
    }

    if !remaining.is_empty() {
        let cand = build_env_group_candidate(&remaining, filename, group_label);
        push_unique(&mut candidates, &mut seen, cand);
    }

    // `export EDITOR=vim` and friends are filtered as ordinary configuration; listing them
    // as "filtered items" would bury the real findings. Keep only weak values under
    // secret-sounding names, which the user may still want to restore.
    let ignored = classified_ignored
        .into_iter()
        .filter(|item| {
            let leaf = item.key.rsplit(['.', '/']).next().unwrap_or(&item.key);
            item.reason == "low_entropy" && key_secret_score(leaf) >= 1
        })
        .collect();

    let (format, format_zh, _) = source.labels();
    SmartExtractBatchResult {
        detected_format: format.to_owned(),
        detected_format_zh: format_zh.to_owned(),
        candidates,
        ignored,
        warnings: Vec::new(),
        sealed_env_template: None,
    }
}

fn looks_like_random_token(token: &str) -> bool {
    token.chars().any(|c| c.is_ascii_digit())
        && token.chars().any(|c| c.is_ascii_alphabetic())
        && shannon_entropy(token) >= 3.0
}

/// Strips the decoration around a command or assignment: history timestamps, Markdown
/// list markers, block quotes, inline-code backticks and shell prompts.
pub(super) fn normalize_precise_line(line: &str, source: PreciseSource) -> String {
    static ZSH_EXTENDED: OnceLock<Regex> = OnceLock::new();
    let mut text = line.trim();
    if source == PreciseSource::ShellHistory {
        let zsh = ZSH_EXTENDED.get_or_init(|| Regex::new(r"^: ?\d+:\d+;").unwrap());
        if let Some(found) = zsh.find(text) {
            text = &text[found.end()..];
        }
        // fish_history is YAML: `- cmd: <command>` followed by `when:` / `paths:` lines.
        if let Some(rest) = text.strip_prefix("- cmd:") {
            text = rest.trim_start();
        } else if text.starts_with("when:") || text.starts_with("paths:") {
            return String::new();
        }
    }
    if source == PreciseSource::AgentRules {
        loop {
            let before = text;
            text = text.trim_start_matches('>').trim_start();
            for marker in ["- ", "* ", "+ "] {
                if let Some(rest) = text.strip_prefix(marker) {
                    text = rest.trim_start();
                }
            }
            let digits = text.chars().take_while(char::is_ascii_digit).count();
            if digits > 0
                && let Some(rest) = text[digits..].strip_prefix(". ")
            {
                text = rest.trim_start();
            }
            if before == text {
                break;
            }
        }
        if text.len() >= 2 && text.starts_with('`') && text.ends_with('`') && !text.starts_with("```") {
            text = text.trim_matches('`').trim();
        }
    }
    for prompt in ["$ ", "% ", "> "] {
        if let Some(rest) = text.strip_prefix(prompt) {
            text = rest.trim_start();
            break;
        }
    }
    text.to_owned()
}

/// Literal `NAME=value` assignments made by one line of shell, fish or PowerShell.
/// Values built from variables or command substitution (`$HOME/bin`, `$(pass show x)`)
/// are skipped: they do not contain the secret, they only point at it.
pub(super) fn shell_assignments(line: &str) -> Vec<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Vec::new();
    }
    if let Some(prefix) = line.get(..5)
        && prefix.eq_ignore_ascii_case("$env:")
    {
        return powershell_assignment(&line[5..]).into_iter().collect();
    }
    let mut found = Vec::new();
    for command in shell_commands(line) {
        let Some(first) = command.first().copied() else {
            continue;
        };
        if first == "set" || first == "setenv" {
            // fish `set -gx NAME value`, csh `setenv NAME value`.
            let mut rest = command[1..].iter().copied().skip_while(|word| word.starts_with('-'));
            if let (Some(name), Some(raw_value)) = (rest.next(), rest.next())
                && ingest::is_shell_env_name(name)
                && let Some(value) = unquote_shell_word(raw_value)
                && !value.is_empty()
            {
                found.push((name.to_owned(), value));
            }
            continue;
        }
        let mut words = command
            .iter()
            .copied()
            .skip_while(|word| {
                matches!(*word, "export" | "declare" | "typeset" | "readonly" | "local" | "env" | "sudo")
                    || (word.starts_with('-') && !word.contains('='))
            })
            .peekable();
        while let Some(word) = words.next_if(|word| word.contains('=')) {
            let Some((name, raw_value)) = word.split_once('=') else {
                break;
            };
            if !ingest::is_shell_env_name(name) {
                break;
            }
            if let Some(value) = unquote_shell_word(raw_value)
                && !value.is_empty()
            {
                found.push((name.to_owned(), value));
            }
        }
    }
    found
}

fn powershell_assignment(rest: &str) -> Option<(String, String)> {
    let (name, raw_value) = rest.split_once('=')?;
    let name = name.trim();
    if !ingest::is_shell_env_name(name) {
        return None;
    }
    let raw_value = raw_value.trim();
    let word = shell_commands(raw_value).into_iter().next()?.into_iter().next()?;
    let value = unquote_shell_word(word)?;
    (!value.is_empty()).then(|| (name.to_owned(), value))
}

/// Splits a line into commands (at `;`, `&&`, `||`, `|`) of raw words, keeping quotes so
/// the caller can tell literal text from expansions. A trailing `#` comment and an
/// unterminated quoted word are dropped.
fn shell_commands(line: &str) -> Vec<Vec<&str>> {
    let mut commands = vec![Vec::new()];
    let mut start: Option<usize> = None;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if let Some(open) = quote {
            if ch == '\\' && open == '"' {
                escaped = true;
            } else if ch == open {
                quote = None;
            }
            continue;
        }
        match ch {
            '\\' => {
                escaped = true;
                start.get_or_insert(idx);
            }
            '"' | '\'' => {
                quote = Some(ch);
                start.get_or_insert(idx);
            }
            ';' | '|' | '&' => {
                if let Some(begin) = start.take() {
                    commands.last_mut().unwrap().push(&line[begin..idx]);
                }
                if !commands.last().unwrap().is_empty() {
                    commands.push(Vec::new());
                }
            }
            '#' if start.is_none() => break,
            ch if ch.is_whitespace() => {
                if let Some(begin) = start.take() {
                    commands.last_mut().unwrap().push(&line[begin..idx]);
                }
            }
            _ => {
                start.get_or_insert(idx);
            }
        }
    }
    if quote.is_none()
        && let Some(begin) = start
    {
        commands.last_mut().unwrap().push(&line[begin..]);
    }
    commands.retain(|command| !command.is_empty());
    commands
}

/// Removes shell quoting from one word, or returns `None` when the word expands a
/// variable or runs a command, because then the literal text is not the value.
fn unquote_shell_word(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut quote: Option<char> = None;
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some('\''), '\'') => quote = None,
            (Some('\''), _) => out.push(ch),
            (Some('"'), '"') => quote = None,
            (_, '$' | '`') => return None,
            (Some('"'), '\\') => match chars.next() {
                Some(next @ ('"' | '\\' | '$' | '`')) => out.push(next),
                Some(next) => {
                    out.push('\\');
                    out.push(next);
                }
                None => out.push('\\'),
            },
            (None, '\\') => {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            (None, '"' | '\'') => quote = Some(ch),
            _ => out.push(ch),
        }
    }
    Some(out)
}
