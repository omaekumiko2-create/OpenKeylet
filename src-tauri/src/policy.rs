use crate::model::{
    MAX_AGENT_NOTE_AUTHOR_CHARS, MAX_AGENT_NOTE_CHARS, SecretBundle, StoredConnection,
};
use anyhow::{Result, bail};
use base64::{
    Engine,
    engine::{
        GeneralPurpose,
        general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    },
};
use reqwest::header::HeaderMap;
use std::collections::{HashMap, HashSet};
use url::Url;
use zeroize::Zeroize;

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

pub fn sensitive_redirect_header_names(connection: &StoredConnection) -> HashSet<String> {
    let mut sensitive = blocked_header_names(connection);
    sensitive.insert("authorization".to_owned());
    sensitive.insert("proxy-authorization".to_owned());
    sensitive.insert("cookie".to_owned());
    sensitive.insert("cookie2".to_owned());
    sensitive
}

pub fn strip_cross_origin_redirect_auth(
    headers: &mut HeaderMap,
    target_url: &mut Url,
    connection: &StoredConnection,
    secrets: &SecretBundle,
) {
    let sensitive_names = sensitive_redirect_header_names(connection);
    let raw_secrets = secrets.non_empty_values();
    let header_names_to_remove: Vec<_> = headers
        .keys()
        .filter(|name| {
            let lower = name.as_str().to_ascii_lowercase();
            if sensitive_names.contains(&lower) {
                return true;
            }
            headers.get_all(*name).iter().any(|val| {
                val.to_str().ok().is_some_and(|text| {
                    raw_secrets
                        .iter()
                        .any(|secret| secret.len() >= 4 && text.contains(secret.as_str()))
                })
            })
        })
        .cloned()
        .collect();
    for name in header_names_to_remove {
        headers.remove(name);
    }

    let query_auth_param = (connection.http_auth_type == "apiKey"
        && connection.auth_location == "query"
        && !connection.auth_header.is_empty())
    .then_some(connection.auth_header.as_str());
    if target_url.query().is_some() {
        let mut removed_any = false;
        let retained: Vec<(String, String)> = target_url
            .query_pairs()
            .filter_map(|(key, val)| {
                let is_auth_param = query_auth_param.is_some_and(|param| key == param);
                let leaks_secret = raw_secrets
                    .iter()
                    .any(|secret| secret.len() >= 4 && val.contains(secret.as_str()));
                if is_auth_param || leaks_secret {
                    removed_any = true;
                    None
                } else {
                    Some((key.into_owned(), val.into_owned()))
                }
            })
            .collect();
        if removed_any {
            target_url.set_query(None);
            if !retained.is_empty() {
                let mut pairs = target_url.query_pairs_mut();
                for (key, val) in retained {
                    pairs.append_pair(&key, &val);
                }
            }
        }
    }
}

fn login_rules_govern_origin(
    rules: &[crate::login_uri::LoginUri],
    base: &Url,
) -> bool {
    let origin = base.origin();
    let origin_root = format!("{}/", origin.ascii_serialization());
    let base_host = base.host_str().map(str::to_ascii_lowercase);
    rules.iter().any(|rule| {
        if rule.match_type == "regex" {
            if crate::login_uri::matches(rule, base.as_str())
                || crate::login_uri::matches(rule, &origin_root)
            {
                return true;
            }
            if let Some(host) = base_host.as_deref() {
                let unescaped = rule.uri.replace('\\', "").to_ascii_lowercase();
                if unescaped.contains(host) {
                    return true;
                }
            }
            return false;
        }
        crate::passkey::origin(&rule.uri)
            .ok()
            .is_some_and(|parsed| parsed.origin() == origin)
    })
}

/// Reports whether `target` may receive this item's secrets. An item with a saved service
/// URL or website rules (its binding) only sends them to the service URL's origin or to a
/// URL matching one of its rules; if website rules explicitly govern the service URL's own
/// origin (for example `never`, `exact`, `prefix`, or `regex` rules), those rules take
/// precedence over the service URL fallback. An item with neither leaves the destination to
/// the caller.
pub fn api_target_allowed(stored: &StoredConnection, target: &Url) -> bool {
    let base_url = stored.base_url.trim();
    if base_url.is_empty() && stored.login_uris.is_empty() {
        return true;
    }
    if stored
        .login_uris
        .iter()
        .any(|rule| crate::login_uri::matches(rule, target.as_str()))
    {
        return true;
    }
    if let Ok(base) = Url::parse(base_url)
        && base.origin() == target.origin()
        && !login_rules_govern_origin(&stored.login_uris, &base)
    {
        return true;
    }
    false
}

/// Error for a destination refused by [`api_target_allowed`]. The requested URL is not
/// echoed because it may carry a substituted secret (for example in the host name) in a
/// transformed form that redaction cannot recognize.
pub fn api_target_refusal(stored: &StoredConnection) -> String {
    let mut allowed = Vec::new();
    if let Ok(base) = Url::parse(stored.base_url.trim())
        && matches!(base.scheme(), "http" | "https")
        && !login_rules_govern_origin(&stored.login_uris, &base)
    {
        allowed.push(base.origin().ascii_serialization());
    }
    for rule in &stored.login_uris {
        let entry = match rule.match_type.as_str() {
            "never" => continue,
            "regex" => "a regex website rule".to_owned(),
            match_type => {
                let Ok(url) = Url::parse(rule.uri.trim()) else {
                    continue;
                };
                let origin = url.origin().ascii_serialization();
                if matches!(match_type, "origin" | "host") {
                    origin
                } else {
                    format!("{origin} ({match_type} match)")
                }
            }
        };
        if !allowed.contains(&entry) {
            allowed.push(entry);
        }
    }
    let allowed = match allowed.len() {
        0 => "no usable destination".to_owned(),
        1..=4 => allowed.join(", "),
        count => format!("{}, and {} more", allowed[..4].join(", "), count - 4),
    };
    format!(
        "Refused: this request's destination is outside the saved service URL / website rules of \"{}\" ({allowed}). OpenKeylet only sends an item's credentials to its saved destination. The vault owner can change the item's URL or add a website rule in OpenKeylet.",
        stored.name
    )
}

/// Reports whether a request body contains any of `secrets` verbatim or in one of the encoded
/// forms listed by [`redaction_candidates`] (JSON string, form-urlencoded, Base64, ...).
pub fn body_contains_secret(body: &[u8], secrets: &SecretBundle) -> bool {
    if body.is_empty() {
        return false;
    }
    Redactor::new(&redaction_candidates(&secrets.non_empty_values())).contains_secret(body)
}

pub fn replace_captured_secrets(mut text: String, captured: &[(String, String)]) -> String {
    let mut ordered: Vec<(&str, &str)> = captured
        .iter()
        .filter(|(field, val)| !field.is_empty() && !val.is_empty())
        .map(|(field, val)| (field.as_str(), val.as_str()))
        .collect();
    ordered.sort_by_key(|(_, val)| std::cmp::Reverse(val.len()));
    for (field, secret) in ordered {
        let marker = format!("[CAPTURED:{{{{openkeylet:{field}}}}}]");
        text = Redactor::with_marker(&redaction_candidates(&[secret.to_owned()]), &marker)
            .redact_string(text);
    }
    text
}

/// Replaces the cookie value in a `Set-Cookie` / `Set-Cookie2` header with `[REDACTED]`
/// while preserving the cookie name and non-secret attributes (`Path`, `HttpOnly`, etc.)
/// so freshly issued session cookies never enter LLM context.
fn redact_set_cookie_header(raw: &str) -> String {
    let mut parts = raw.split(';');
    let first = parts.next().unwrap_or("").trim();
    let redacted_pair = match first.split_once('=') {
        Some((name, _)) if !name.trim().is_empty() => format!("{}=[REDACTED]", name.trim()),
        _ => "[REDACTED]".to_owned(),
    };
    let rest: Vec<&str> = parts
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect();
    if rest.is_empty() {
        redacted_pair
    } else {
        format!("{redacted_pair}; {}", rest.join("; "))
    }
}

pub fn visible_response_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|value| {
                let rendered = if name.as_str().eq_ignore_ascii_case("set-cookie")
                    || name.as_str().eq_ignore_ascii_case("set-cookie2")
                {
                    redact_set_cookie_header(value)
                } else {
                    value.to_owned()
                };
                (name.as_str().to_owned(), rendered)
            })
        })
        .collect()
}

pub fn redact(value: String, _connection: &StoredConnection, secrets: &SecretBundle) -> String {
    Redactor::new(&connection_redaction_candidates(secrets)).redact_string(value)
}

pub fn redact_values(value: String, raw_secrets: &[String]) -> String {
    if raw_secrets.iter().all(String::is_empty) {
        return value;
    }
    Redactor::new(&redaction_candidates(raw_secrets)).redact_string(value)
}

/// Candidates for every hidden value an item holds, plus the Basic-auth encoding of its
/// username and password. That encoding is kept whatever the item's auth type because tools
/// such as curl, git, and docker build it from any username and password the agent passes.
pub fn connection_redaction_candidates(secrets: &SecretBundle) -> Vec<String> {
    let mut candidates = redaction_candidates(&secrets.non_empty_values());
    if let (Some(username), Some(password)) = (secrets.get("username"), secrets.get("password"))
        && !password.is_empty()
    {
        candidates.push(STANDARD.encode(format!("{username}:{password}")));
    }
    candidates
}

/// Below this length a secret only gets the raw, JSON, shell-quoted, standard Base64 and
/// form-urlencoded forms that earlier releases already redacted. Short values have so few
/// bytes that their other encodings would match ordinary output.
const DERIVED_FORMS_MIN_SECRET_LEN: usize = 6;
/// Shortest encoded candidate (Base64 fragment, hex, percent-encoding) that is kept.
const DERIVED_FORMS_MIN_LEN: usize = 8;
/// Shortest line of a multi-line secret that is matched on its own, so that `head` of a
/// key file is caught while generic lines of a structured secret are not.
const SECRET_LINE_MIN_LEN: usize = 16;

/// Expands raw secret values into the text forms in which honest tools commonly print them.
/// Callers choose which raw values to pass; this function only applies the minimum lengths
/// for the derived forms (see the constants above).
pub fn redaction_candidates(raw_secrets: &[String]) -> Vec<String> {
    let mut candidates = Vec::new();
    for secret in raw_secrets.iter().filter(|secret| !secret.is_empty()) {
        push_secret_forms(&mut candidates, secret);
        if secret.contains(['\n', '\r']) {
            for line in secret.split(['\n', '\r']) {
                let line = line.trim();
                if line.len() >= SECRET_LINE_MIN_LEN
                    && !line.starts_with("-----")
                    && !line.bytes().any(|byte| byte.is_ascii_whitespace())
                {
                    candidates.push(line.to_owned());
                }
            }
        }
    }
    candidates.retain(|candidate| !candidate.is_empty());
    candidates.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    candidates.dedup();
    candidates
}

fn push_secret_forms(out: &mut Vec<String>, secret: &str) {
    let bytes = secret.as_bytes();
    out.push(secret.to_owned());
    out.push(STANDARD.encode(bytes));
    out.push(url::form_urlencoded::byte_serialize(bytes).collect());
    push_json_forms(out, secret);
    if secret.contains('\'') {
        // The echo of a shell-quoted literal, as typed into a PTY or quoted in an error:
        // POSIX '…'\''…' and PowerShell '…''…'.
        out.push(secret.replace('\'', "'\\''"));
        out.push(secret.replace('\'', "''"));
    }
    if bytes.len() < DERIVED_FORMS_MIN_SECRET_LEN {
        return;
    }
    let mut derived = Vec::new();
    let mut with_newline = bytes.to_vec();
    with_newline.push(b'\n');
    // `echo "$SECRET" | base64`
    derived.push(STANDARD.encode(&with_newline));
    with_newline.zeroize();
    derived.push(URL_SAFE_NO_PAD.encode(bytes));
    // The fragments cover the value inside a larger encoded payload, such as
    // base64(user:secret), a Kubernetes secret, or a JWT claim, whatever precedes it.
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        for offset in 0..3 {
            derived.push(aligned_base64_fragment(engine, bytes, offset));
        }
    }
    let mut lower_hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        lower_hex.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        lower_hex.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
    derived.push(lower_hex.to_ascii_uppercase());
    derived.push(lower_hex);
    push_percent_forms(&mut derived, bytes);
    out.extend(
        derived
            .into_iter()
            .filter(|candidate| candidate.len() >= DERIVED_FORMS_MIN_LEN),
    );
}

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// The characters of a Base64 encoding that depend only on `bytes` when they start `offset`
/// bytes into a 3-byte group. Characters that mix in bits of neighbouring bytes are dropped.
fn aligned_base64_fragment(engine: &GeneralPurpose, bytes: &[u8], offset: usize) -> String {
    let mut padded = vec![0_u8; offset];
    padded.extend_from_slice(bytes);
    let encoded = engine.encode(&padded);
    padded.zeroize();
    let start = (offset * 8).div_ceil(6);
    let end = (offset + bytes.len()) * 8 / 6;
    encoded.get(start..end).unwrap_or_default().to_owned()
}

fn push_json_forms(out: &mut Vec<String>, secret: &str) {
    let Ok(quoted) = serde_json::to_string(secret) else {
        return;
    };
    let inner = &quoted[1..quoted.len() - 1];
    if inner != secret {
        out.push(inner.to_owned());
    }
    // Go's encoding/json escapes <, > and & so that JSON can be embedded in HTML.
    if secret.contains(['<', '>', '&']) {
        out.push(
            inner
                .replace('<', "\\u003c")
                .replace('>', "\\u003e")
                .replace('&', "\\u0026"),
        );
    }
    // PHP escapes '/' by default; PHP and Python escape non-ASCII characters as \uXXXX.
    let ascii = if secret.is_ascii() {
        inner.to_owned()
    } else {
        ascii_json_escape(inner)
    };
    if secret.contains('/') {
        out.push(inner.replace('/', "\\/"));
        out.push(ascii.replace('/', "\\/"));
    }
    if !secret.is_ascii() {
        out.push(ascii);
    }
}

fn ascii_json_escape(inner: &str) -> String {
    let mut escaped = String::with_capacity(inner.len() * 2);
    for character in inner.chars() {
        if character.is_ascii() {
            escaped.push(character);
            continue;
        }
        let mut units = [0_u16; 2];
        for unit in character.encode_utf16(&mut units) {
            escaped.push_str("\\u");
            for shift in [12, 8, 4, 0] {
                escaped.push(char::from(HEX_LOWER[usize::from((*unit >> shift) & 0x0f)]));
            }
        }
    }
    escaped
}

fn push_percent_forms(out: &mut Vec<String>, bytes: &[u8]) {
    // encodeURIComponent, RFC 3986 unreserved, and Python's quote() which keeps '/'.
    for keep in [b"-_.!~*'()".as_slice(), b"-_.~", b"-_.~/"] {
        for hex in [HEX_UPPER, HEX_LOWER] {
            out.push(percent_encode(bytes, keep, hex, false));
        }
    }
    // application/x-www-form-urlencoded with lowercase escapes; the uppercase form is a
    // base candidate.
    out.push(percent_encode(bytes, b"*-._", HEX_LOWER, true));
}

fn percent_encode(bytes: &[u8], keep: &[u8], hex: &[u8; 16], space_as_plus: bool) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 3);
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || keep.contains(&byte) {
            encoded.push(char::from(byte));
        } else if byte == b' ' && space_as_plus {
            encoded.push('+');
        } else {
            encoded.push('%');
            encoded.push(char::from(hex[usize::from(byte >> 4)]));
            encoded.push(char::from(hex[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

/// Bytes a terminal or line editor may insert between the characters of echoed text.
enum Noise {
    Skip(usize),
    /// The buffer ends inside a sequence that may turn out to be skippable.
    Incomplete,
    None,
}

const MAX_CSI_LEN: usize = 64;
const MAX_STRING_SEQUENCE_LEN: usize = 4096;

fn noise_at(text: &[u8], at: usize) -> Noise {
    match text[at] {
        b'\r' | b'\n' => Noise::Skip(1),
        // Line editors force a wrap at the right margin with a space and a carriage return.
        b' ' if text.get(at + 1) == Some(&b'\r') => Noise::Skip(2),
        0x1b => escape_sequence_len(text, at),
        _ => Noise::None,
    }
}

fn escape_sequence_len(text: &[u8], at: usize) -> Noise {
    let Some(&kind) = text.get(at + 1) else {
        return Noise::Incomplete;
    };
    match kind {
        // CSI: parameter bytes, intermediate bytes, one final byte.
        b'[' => {
            let mut cursor = at + 2;
            while cursor < text.len() && (0x30..=0x3f).contains(&text[cursor]) {
                cursor += 1;
            }
            while cursor < text.len() && (0x20..=0x2f).contains(&text[cursor]) {
                cursor += 1;
            }
            if cursor - at > MAX_CSI_LEN {
                return Noise::None;
            }
            match text.get(cursor) {
                None => Noise::Incomplete,
                Some(0x40..=0x7e) => Noise::Skip(cursor + 1 - at),
                Some(_) => Noise::None,
            }
        }
        // OSC, DCS, SOS, PM and APC strings end with BEL or ESC \.
        b']' | b'P' | b'X' | b'^' | b'_' => {
            let mut cursor = at + 2;
            loop {
                if cursor - at > MAX_STRING_SEQUENCE_LEN {
                    return Noise::None;
                }
                match text.get(cursor) {
                    None => return Noise::Incomplete,
                    Some(0x07) => return Noise::Skip(cursor + 1 - at),
                    Some(0x1b) => {
                        return match text.get(cursor + 1) {
                            None => Noise::Incomplete,
                            Some(b'\\') => Noise::Skip(cursor + 2 - at),
                            Some(_) => Noise::None,
                        };
                    }
                    Some(_) => cursor += 1,
                }
            }
        }
        // nF sequences such as character-set selection: intermediates, then a final byte.
        0x20..=0x2f => {
            let mut cursor = at + 1;
            while cursor < text.len() && (0x20..=0x2f).contains(&text[cursor]) {
                cursor += 1;
            }
            match text.get(cursor) {
                None => Noise::Incomplete,
                Some(0x30..=0x7e) => Noise::Skip(cursor + 1 - at),
                Some(_) => Noise::None,
            }
        }
        // Two-byte sequences such as ESC 7 / ESC 8 (save and restore the cursor).
        0x30..=0x7e => Noise::Skip(2),
        _ => Noise::None,
    }
}

enum Walk {
    Match(usize),
    /// The text ended first: `matched` pattern bytes were seen, and `noise_tail` tells
    /// whether only terminal noise followed them.
    Partial { matched: usize, noise_tail: bool },
    Miss,
}

/// A candidate prefix followed only by CR/LF or escape bytes at the end of a read is held
/// back only once this many of its bytes have matched. Otherwise every output line ending
/// in a character that also starts some vault secret would be held back.
const MIN_HELD_PREFIX_BEFORE_NOISE: usize = 4;

fn hold_partial(matched: usize, noise_tail: bool) -> bool {
    !noise_tail || matched >= MIN_HELD_PREFIX_BEFORE_NOISE
}

/// Terminal noise is only skipped inside candidates at least this long. A short value such
/// as a four-letter username would otherwise match across unrelated line breaks ("ro\not").
const MIN_NOISE_TOLERANT_LEN: usize = 8;

fn pair_key(first: u8, second: u8) -> u16 {
    (u16::from(first) << 8) | u16::from(second)
}

/// Multi-pattern secret matcher shared by every OpenKeylet output path.
///
/// A match may have CR, LF, a line editor's wrap (" \r"), or ANSI CSI/OSC sequences between
/// any two of its bytes, because terminals insert those into echoed text; candidates are
/// stored without their own CR/LF so a multi-line secret matches with either line ending.
/// Overlapping matches merge into one redacted span, so a shorter candidate that starts first
/// cannot leave the tail of a longer one visible. Patterns are bucketed by their first two
/// bytes, which keeps the per-byte cost flat when the candidate set covers the whole vault.
pub struct Redactor {
    patterns: Vec<Vec<u8>>,
    first: [bool; 256],
    single: [bool; 256],
    multi_first: [bool; 256],
    pairs: Vec<u64>,
    buckets: HashMap<u16, Vec<u32>>,
    max_len: usize,
    marker: Vec<u8>,
}

impl Redactor {
    pub fn new(candidates: &[String]) -> Self {
        Self::with_marker(candidates, "[REDACTED]")
    }

    pub fn with_marker(candidates: &[String], marker: &str) -> Self {
        let patterns = candidates
            .iter()
            .map(|candidate| {
                candidate
                    .bytes()
                    .filter(|byte| !matches!(byte, b'\r' | b'\n'))
                    .collect::<Vec<u8>>()
            })
            .filter(|pattern| !pattern.is_empty())
            .collect();
        Self::from_patterns(patterns, marker.as_bytes().to_vec())
    }

    fn from_patterns(mut patterns: Vec<Vec<u8>>, marker: Vec<u8>) -> Self {
        patterns.sort_unstable();
        patterns.dedup();
        let mut redactor = Self {
            patterns: Vec::new(),
            first: [false; 256],
            single: [false; 256],
            multi_first: [false; 256],
            pairs: vec![0; 1024],
            buckets: HashMap::new(),
            max_len: 0,
            marker,
        };
        for (index, pattern) in patterns.iter().enumerate() {
            let head = usize::from(pattern[0]);
            redactor.first[head] = true;
            redactor.max_len = redactor.max_len.max(pattern.len());
            if pattern.len() == 1 {
                redactor.single[head] = true;
                continue;
            }
            redactor.multi_first[head] = true;
            let key = pair_key(pattern[0], pattern[1]);
            redactor.pairs[usize::from(key / 64)] |= 1 << (key % 64);
            redactor
                .buckets
                .entry(key)
                .or_default()
                .push(u32::try_from(index).unwrap_or(u32::MAX));
        }
        redactor.patterns = patterns;
        redactor
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    pub fn contains_secret(&self, text: &[u8]) -> bool {
        !self.scan(text).0.is_empty()
    }

    pub fn redact_bytes(&self, text: &[u8]) -> Vec<u8> {
        let (spans, _) = self.scan(text);
        self.render(text, &spans, text.len())
    }

    pub fn redact_string(&self, text: String) -> String {
        let (spans, _) = self.scan(text.as_bytes());
        if spans.is_empty() {
            return text;
        }
        bytes_to_string(self.render(text.as_bytes(), &spans, text.len()))
    }

    /// Redacts the part of `text` that can be released now. With `hold_incomplete`, bytes
    /// from the earliest candidate that is still incomplete at the end of `text` are not
    /// consumed, so a secret split across reads is matched once the rest arrives. Returns the
    /// redacted output and the number of input bytes it covers.
    pub fn redact_stream(&self, text: &[u8], hold_incomplete: bool) -> (Vec<u8>, usize) {
        let (spans, incomplete_from) = self.scan(text);
        let mut cut = if hold_incomplete {
            incomplete_from.unwrap_or(text.len())
        } else {
            text.len()
        };
        if let Some(&(start, _)) = spans.iter().find(|(start, end)| *start < cut && cut < *end) {
            cut = start;
        }
        (self.render(text, &spans, cut), cut)
    }

    /// The number of leading bytes of `text` that may be the end of a candidate whose start is
    /// not in `text`, as at the start of the tail kept after truncated output. Only CR and LF
    /// are tolerated inside such a fragment.
    pub fn leading_fragment_len(&self, text: &[u8]) -> usize {
        if self.patterns.is_empty() || text.is_empty() {
            return 0;
        }
        let window = &text[..text.len().min(self.max_len.saturating_mul(2))];
        let reversed_text: Vec<u8> = window.iter().rev().copied().collect();
        let reversed = Self::from_patterns(
            self.patterns
                .iter()
                .map(|pattern| pattern.iter().rev().copied().collect())
                .collect(),
            Vec::new(),
        );
        let (_, cut) = reversed.redact_stream(&reversed_text, true);
        reversed_text.len() - cut
    }

    fn scan(&self, text: &[u8]) -> (Vec<(usize, usize)>, Option<usize>) {
        let mut spans: Vec<(usize, usize)> = Vec::new();
        let mut incomplete_from = None;
        if self.patterns.is_empty() {
            return (spans, None);
        }
        for start in 0..text.len() {
            if !self.first[usize::from(text[start])] {
                continue;
            }
            let (end, incomplete) = self.longest_at(text, start);
            if incomplete && incomplete_from.is_none() {
                incomplete_from = Some(start);
            }
            if let Some(end) = end {
                match spans.last_mut() {
                    Some(last) if start < last.1 => last.1 = last.1.max(end),
                    _ => spans.push((start, end)),
                }
            }
        }
        (spans, incomplete_from)
    }

    fn longest_at(&self, text: &[u8], start: usize) -> (Option<usize>, bool) {
        let head = text[start];
        let mut end = self.single[usize::from(head)].then_some(start + 1);
        if !self.multi_first[usize::from(head)] {
            return (end, false);
        }
        let mut incomplete = false;
        let mut cursor = start + 1;
        loop {
            let Some(&second) = text.get(cursor) else {
                incomplete |= hold_partial(1, cursor > start + 1);
                break;
            };
            let key = pair_key(head, second);
            if self.pairs[usize::from(key / 64)] & (1 << (key % 64)) != 0
                && let Some(bucket) = self.buckets.get(&key)
            {
                let skipped_noise = cursor > start + 1;
                for &index in bucket {
                    let pattern = &self.patterns[index as usize];
                    let tolerate_noise = pattern.len() >= MIN_NOISE_TOLERANT_LEN;
                    if skipped_noise && !tolerate_noise {
                        continue;
                    }
                    match walk(text, cursor + 1, &pattern[2..], tolerate_noise) {
                        Walk::Match(found) => end = Some(end.map_or(found, |old| old.max(found))),
                        Walk::Partial {
                            matched,
                            noise_tail,
                        } => incomplete |= hold_partial(matched + 2, noise_tail),
                        Walk::Miss => {}
                    }
                }
            }
            match noise_at(text, cursor) {
                Noise::Skip(length) => cursor += length,
                Noise::Incomplete => {
                    incomplete |= hold_partial(1, true);
                    break;
                }
                Noise::None => break,
            }
        }
        (end, incomplete)
    }

    fn render(&self, text: &[u8], spans: &[(usize, usize)], upto: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(upto);
        let mut cursor = 0;
        for &(start, end) in spans {
            if end > upto {
                break;
            }
            output.extend_from_slice(&text[cursor..start]);
            output.extend_from_slice(&self.marker);
            cursor = end;
        }
        output.extend_from_slice(&text[cursor..upto]);
        output
    }
}

impl Drop for Redactor {
    fn drop(&mut self) {
        for pattern in &mut self.patterns {
            pattern.zeroize();
        }
    }
}

fn walk(text: &[u8], mut cursor: usize, rest: &[u8], tolerate_noise: bool) -> Walk {
    let mut matched = 0;
    let mut noise_tail = false;
    while matched < rest.len() {
        let Some(&byte) = text.get(cursor) else {
            return Walk::Partial {
                matched,
                noise_tail,
            };
        };
        if byte == rest[matched] {
            cursor += 1;
            matched += 1;
            noise_tail = false;
            continue;
        }
        if !tolerate_noise {
            return Walk::Miss;
        }
        match noise_at(text, cursor) {
            Noise::Skip(length) => {
                cursor += length;
                noise_tail = true;
            }
            Noise::Incomplete => {
                return Walk::Partial {
                    matched,
                    noise_tail: true,
                };
            }
            Noise::None => return Walk::Miss,
        }
    }
    Walk::Match(cursor)
}

fn bytes_to_string(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned())
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
    fn response_headers_are_returned_with_set_cookie_values_redacted() {
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
            Some("session=[REDACTED]")
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

    #[test]
    fn cross_origin_redirect_strips_auth_headers_and_query_secrets() {
        let mut conn = connection();
        conn.http_auth_type = "apiKey".into();
        conn.auth_location = "query".into();
        conn.auth_header = "api_key".into();
        conn.api_auth_headers = vec![crate::model::ApiAuthHeader {
            name: "X-Custom-Auth".into(),
            secret_name: "custom".into(),
        }];
        let mut secrets = SecretBundle::default();
        secrets.api_key = Some("query-secret-9988".into());
        secrets
            .named_secrets
            .insert("other".into(), "inline-header-secret-7766".into());

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer leak".parse().unwrap());
        headers.insert("cookie", "sid=secret".parse().unwrap());
        headers.insert("x-custom-auth", "custom-val".parse().unwrap());
        headers.insert(
            "x-inline-secret",
            "Bearer inline-header-secret-7766".parse().unwrap(),
        );
        headers.insert("x-safe-header", "keep-me".parse().unwrap());

        let mut target =
            Url::parse("https://other.example/cb?api_key=query-secret-9988&keep=yes&leak=inline-header-secret-7766")
                .unwrap();

        strip_cross_origin_redirect_auth(&mut headers, &mut target, &conn, &secrets);

        assert!(headers.get("authorization").is_none());
        assert!(headers.get("cookie").is_none());
        assert!(headers.get("x-custom-auth").is_none());
        assert!(headers.get("x-inline-secret").is_none());
        assert_eq!(headers.get("x-safe-header").unwrap(), "keep-me");
        assert_eq!(target.as_str(), "https://other.example/cb?keep=yes");
    }

    #[test]
    fn api_targets_are_bound_to_the_saved_service_url_and_website_rules() {
        let url = |value: &str| Url::parse(value).unwrap();
        let rule = |uri: &str, match_type: &str| crate::login_uri::LoginUri {
            uri: uri.into(),
            match_type: match_type.into(),
        };

        let mut unbound = connection();
        unbound.base_url = "  ".into();
        for target in ["https://anything.example/x", "http://127.0.0.1:9/"] {
            assert!(api_target_allowed(&unbound, &url(target)), "{target}");
        }

        // connection() saves https://api.example.com/v1/.
        let bound = connection();
        for target in [
            "https://api.example.com/v2/other?x=1",
            "https://api.example.com:443/",
        ] {
            assert!(api_target_allowed(&bound, &url(target)), "{target}");
        }
        for target in [
            "https://attacker.example/v1/",
            "https://api.example.com.attacker.example/v1/",
            "https://uploads.api.example.com/v1/",
            "https://api.example.com:8443/v1/",
            "http://api.example.com/v1/",
        ] {
            assert!(!api_target_allowed(&bound, &url(target)), "{target}");
        }

        let mut rules_only = connection();
        rules_only.base_url = String::new();
        rules_only.login_uris = vec![rule("https://example.com", "domain")];
        assert!(api_target_allowed(&rules_only, &url("https://uploads.example.com/f")));
        assert!(api_target_allowed(&rules_only, &url("https://example.com/")));
        assert!(!api_target_allowed(&rules_only, &url("https://example.com.evil.test/")));
        assert!(!api_target_allowed(&rules_only, &url("http://uploads.example.com/f")));

        let mut union = connection();
        union.login_uris = vec![rule("https://uploads.example.net", "origin")];
        assert!(api_target_allowed(&union, &url("https://api.example.com/v1/items")));
        assert!(api_target_allowed(&union, &url("https://uploads.example.net/x")));
        assert!(!api_target_allowed(&union, &url("https://other.example.net/x")));

        let mut never_only = connection();
        never_only.base_url = String::new();
        never_only.login_uris = vec![rule("https://example.com", "never")];
        assert!(!api_target_allowed(&never_only, &url("https://example.com/")));

        // Explicit rules on the service URL's own origin take precedence over base_url.
        let mut narrowed = connection();
        narrowed.login_uris = vec![rule("https://api.example.com/v1/", "prefix")];
        assert!(api_target_allowed(&narrowed, &url("https://api.example.com/v1/items")));
        assert!(!api_target_allowed(&narrowed, &url("https://api.example.com/admin")));
        let narrowed_refusal = api_target_refusal(&narrowed);
        assert!(narrowed_refusal.contains("https://api.example.com (prefix match)"), "{narrowed_refusal}");
        assert!(!narrowed_refusal.contains("(https://api.example.com,"));

        let mut base_never = connection();
        base_never.login_uris = vec![rule("https://api.example.com", "never")];
        assert!(!api_target_allowed(&base_never, &url("https://api.example.com/v1/items")));
        assert!(api_target_refusal(&base_never).contains("(no usable destination)"));

        // A regex rule narrowing the saved base_url origin must NOT fall back to whole-origin access.
        let mut narrowed_regex = connection();
        narrowed_regex.login_uris = vec![rule(r"^https://api\.example\.com/app-a/.*", "regex")];
        assert!(api_target_allowed(&narrowed_regex, &url("https://api.example.com/app-a/items")));
        assert!(!api_target_allowed(&narrowed_regex, &url("https://api.example.com/app-b/admin")));
        let regex_refusal = api_target_refusal(&narrowed_regex);
        assert!(regex_refusal.contains("a regex website rule"), "{regex_refusal}");
        assert!(!regex_refusal.contains("https://api.example.com"), "{regex_refusal}");

        // A regex rule targeting a different host keeps base_url origin intact.
        let mut union_regex = connection();
        union_regex.login_uris = vec![rule(r"^https://cdn\.other\.net/.*", "regex")];
        assert!(api_target_allowed(&union_regex, &url("https://api.example.com/v1/items")));
        assert!(api_target_allowed(&union_regex, &url("https://cdn.other.net/file.bin")));
        assert!(!api_target_allowed(&union_regex, &url("https://evil.other.net/file.bin")));

        let refusal = api_target_refusal(&union);
        assert!(refusal.starts_with("Refused: "));
        assert!(refusal.contains("\"test\""));
        assert!(refusal.contains("https://api.example.com, https://uploads.example.net"));
        assert!(api_target_refusal(&rules_only).contains("https://example.com (domain match)"));
        assert!(api_target_refusal(&never_only).contains("(no usable destination)"));
    }

    #[test]
    fn visible_response_headers_redacts_set_cookie_values_preserving_attributes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::SET_COOKIE,
            reqwest::header::HeaderValue::from_static(
                "session_id=fresh_secret_cookie_999; Path=/; HttpOnly; Secure; SameSite=Lax",
            ),
        );
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        let visible = visible_response_headers(&headers);
        let cookie = visible
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert!(!cookie.contains("fresh_secret_cookie_999"), "{cookie}");
        assert_eq!(
            cookie,
            "session_id=[REDACTED]; Path=/; HttpOnly; Secure; SameSite=Lax"
        );
        assert!(visible.iter().any(|(k, v)| k == "content-type" && v == "application/json"));
    }

    #[test]
    fn request_bodies_are_scanned_for_raw_and_encoded_secrets() {
        let secret = "tok\"en/with space+9384";
        let mut secrets = SecretBundle::default();
        secrets.token = Some(secret.into());

        assert!(body_contains_secret(secret.as_bytes(), &secrets));
        let json = serde_json::to_vec(&serde_json::json!({ "auth": format!("Bearer {secret}") }))
            .unwrap();
        assert!(!String::from_utf8_lossy(&json).contains(secret));
        assert!(body_contains_secret(&json, &secrets));
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("auth", secret)
            .finish();
        assert!(!form.contains(secret));
        assert!(body_contains_secret(form.as_bytes(), &secrets));
        assert!(body_contains_secret(
            STANDARD.encode(secret.as_bytes()).as_bytes(),
            &secrets
        ));

        assert!(!body_contains_secret(br#"{"ping":true}"#, &secrets));
        assert!(!body_contains_secret(b"", &secrets));
        assert!(!body_contains_secret(secret.as_bytes(), &SecretBundle::default()));
    }

    fn redactor_for(values: &[&str]) -> Redactor {
        Redactor::new(&redaction_candidates(
            &values.iter().map(|value| (*value).to_owned()).collect::<Vec<_>>(),
        ))
    }

    #[test]
    fn redaction_candidates_cover_json_shell_and_per_line_forms() {
        let secret = "s3cr3t/Value+<tag>&é ok\"q'x";
        let redactor = redactor_for(&[secret]);
        for printed in [
            // serde_json / JavaScript
            r#"{"v":"s3cr3t/Value+<tag>&é ok\"q'x"}"#,
            // Go encoding/json
            r#"{"v":"s3cr3t/Value+<tag>&é ok\"q'x"}"#,
            // PHP json_encode
            r#"{"v":"s3cr3t\/Value+<tag>&é ok\"q'x"}"#,
            // Python json.dumps
            r#"{"v": "s3cr3t/Value+<tag>&é ok\"q'x"}"#,
            // A POSIX shell echoing the quoted literal it was given.
            r#"+ printf %s 's3cr3t/Value+<tag>&é ok"q'\''x'"#,
            // PowerShell
            r#"Write-Output 's3cr3t/Value+<tag>&é ok"q''x'"#,
        ] {
            let redacted = redactor.redact_string(printed.to_owned());
            assert!(redacted.contains("[REDACTED]"), "{printed} -> {redacted}");
            assert!(!redacted.contains("s3cr3t"), "{printed} -> {redacted}");
        }

        let pem = "-----BEGIN TEST KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEFAASC\nAUAwggE8AgEAAkEAq7BFUpkGp3+XQorKV\n-----END TEST KEY-----\n";
        let redactor = redactor_for(&[pem]);
        let head = redactor.redact_string(
            "-----BEGIN TEST KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEFAASC\n".to_owned(),
        );
        assert_eq!(head, "-----BEGIN TEST KEY-----\n[REDACTED]\n");
        let crlf = redactor.redact_string(pem.replace('\n', "\r\n"));
        assert_eq!(crlf, "[REDACTED]\r\n");
        let generic = redactor_for(&["user = alice\npassword-line-value-1234"]);
        assert_eq!(
            generic.redact_string("user = alice".to_owned()),
            "user = alice",
            "short or spaced lines of a multi-line value must not be candidates"
        );
    }

    #[test]
    fn redaction_candidates_cover_base64_hex_and_percent_forms() {
        let secret = "pa ss/wörd+42?&=";
        let bytes = secret.as_bytes();
        let redactor = redactor_for(&[secret]);
        let wrapped = STANDARD
            .encode(format!("{secret}{secret}{secret}"))
            .as_bytes()
            .chunks(20)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join("\n");
        let mut printed = vec![
            STANDARD.encode(format!("{secret}\n")),
            URL_SAFE_NO_PAD.encode(bytes),
            wrapped,
            bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
            bytes.iter().map(|byte| format!("{byte:02X}")).collect(),
            // encodeURIComponent
            "pa%20ss%2Fw%C3%B6rd%2B42%3F%26%3D".to_owned(),
            // Python quote(), lowercase escapes
            "pa%20ss/w%c3%b6rd%2b42%3f%26%3d".to_owned(),
            // form-urlencoded with lowercase escapes
            "pa+ss%2fw%c3%b6rd%2b42%3f%26%3d".to_owned(),
        ];
        // base64(user:secret) for every alignment of the secret within the encoding.
        for user in ["a", "ab", "abc", "deploy-user"] {
            printed.push(STANDARD.encode(format!("{user}:{secret}")));
            printed.push(URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{user}","pw":"{secret}"}}"#)));
        }
        for text in printed {
            assert!(
                redactor.contains_secret(text.as_bytes()),
                "missed encoded form {text}"
            );
        }
        assert!(!redactor.contains_secret(b"ordinary output with no secret"));
    }

    #[test]
    fn short_values_only_get_their_legacy_forms() {
        let candidates = redaction_candidates(&["root".to_owned()]);
        assert_eq!(
            candidates.iter().map(String::as_str).collect::<HashSet<_>>(),
            HashSet::from(["root", "cm9vdA=="])
        );
        // Derived forms are only added for values of 6+ bytes and kept at 8+ characters.
        let candidates = redaction_candidates(&["abcdef".to_owned()]);
        assert!(candidates.contains(&"616263646566".to_owned()));
        assert!(candidates.iter().all(|candidate| candidate == "abcdef"
            || candidate.len() >= DERIVED_FORMS_MIN_LEN));
    }

    #[test]
    fn overlapping_secrets_are_redacted_as_one_span() {
        let redactor = redactor_for(&["AAAA-1111", "1111-BBBB-CCCC"]);
        assert_eq!(
            redactor.redact_string("x AAAA-1111-BBBB-CCCC y".to_owned()),
            "x [REDACTED] y"
        );
        let redactor = redactor_for(&["needle-secret"]);
        assert_eq!(
            redactor.redact_string("a needle-secret b needle-secret".to_owned()),
            "a [REDACTED] b [REDACTED]"
        );
        assert_eq!(
            Redactor::new(&[]).redact_string("unchanged".to_owned()),
            "unchanged"
        );
    }

    #[test]
    fn short_candidates_do_not_match_across_line_breaks() {
        let redactor = redactor_for(&["root", "long-enough-secret"]);
        assert_eq!(
            redactor.redact_string("user ro\not ok; root".to_owned()),
            "user ro\not ok; [REDACTED]"
        );
        assert_eq!(
            redactor.redact_string("long-enough\r\n-secret".to_owned()),
            "[REDACTED]"
        );
    }

    #[test]
    fn stream_redaction_holds_only_incomplete_candidates() {
        let redactor = redactor_for(&["stream-secret-77"]);
        let (out, consumed) = redactor.redact_stream(b"ok stream-sec", true);
        assert_eq!((out.as_slice(), consumed), (b"ok ".as_slice(), 3));
        let (out, consumed) = redactor.redact_stream(b"ok stream-sec", false);
        assert_eq!((out.as_slice(), consumed), (b"ok stream-sec".as_slice(), 13));
        let (out, _) = redactor.redact_stream(b"ok stream-secret-77 done", true);
        assert_eq!(out, b"ok [REDACTED] done");
        assert_eq!(redactor.leading_fragment_len(b"ret-77 tail"), 6);
        assert_eq!(redactor.leading_fragment_len(b"# plain tail"), 0);
    }

    #[test]
    fn replace_captured_secrets_masks_raw_and_encoded_forms() {
        let secret = "tok_live/abc+123";
        let b64 = STANDARD.encode(secret.as_bytes());
        let text = format!(r#"{{"token":"{secret}","b64":"{b64}","ok":true}}"#);
        let replaced = replace_captured_secrets(
            text,
            &[("accessToken".to_owned(), secret.to_owned())],
        );
        assert!(!replaced.contains(secret));
        assert!(!replaced.contains(&b64));
        assert!(replaced.contains("[CAPTURED:{{openkeylet:accessToken}}]"));
        assert!(replaced.contains(r#""ok":true"#));
    }
}
