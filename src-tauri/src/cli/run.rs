//! Zero-plaintext CLI secret injector (`openkeylet run`).
//!
//! Resolves vault secret references into a child process's environment and argv
//! locally, streams stdout/stderr in real time with chunk-boundary-safe redaction,
//! forwards stdin, propagates the exact exit code, and writes an audit record.

use crate::{
    crypto::totp::current_totp,
    model::NewActivity,
    policy::{Redactor, redaction_candidates},
    storage::resolve_user_path,
    vault::{DecryptedConnection, Vault},
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
#[cfg(windows)]
use std::path::PathBuf;
use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
    process::Stdio,
    time::Instant,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const RUN_USAGE: &str = "Usage: openkeylet run [--item <ITEM>]... [--env VAR=MODULE]... [--env-file <TEMPLATE_PATH>]... [--no-redact] -- <COMMAND> [ARGS...]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOptions {
    pub items: Vec<String>,
    pub env_bindings: Vec<(String, String)>,
    pub env_files: Vec<String>,
    pub redact: bool,
    pub command: String,
    pub args: Vec<String>,
}

/// Parse CLI arguments following `openkeylet run`.
pub fn parse_run_args(args: &[String]) -> Result<RunOptions> {
    let mut items = Vec::new();
    let mut env_bindings = Vec::new();
    let mut env_files = Vec::new();
    let mut redact = true;
    let mut cmd_start: Option<usize> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--" => {
                cmd_start = Some(i + 1);
                break;
            }
            "--item" | "-i" => {
                i += 1;
                let value = args
                    .get(i)
                    .context("--item requires a vault item name or UUID")?;
                ensure!(!value.trim().is_empty(), "--item cannot be empty");
                items.push(value.clone());
            }
            "--env" | "-e" => {
                i += 1;
                let raw = args
                    .get(i)
                    .context("--env requires VAR=MODULE or VAR=VALUE")?;
                let (var, spec) = raw
                    .split_once('=')
                    .with_context(|| format!("Invalid --env binding '{raw}'; expected VAR=MODULE"))?;
                let var = var.trim();
                ensure!(
                    is_valid_env_var_name(var),
                    "Invalid environment variable name '{var}'"
                );
                env_bindings.push((var.to_owned(), spec.to_owned()));
            }
            "--env-file" => {
                i += 1;
                let path = args
                    .get(i)
                    .context("--env-file requires a template file path")?;
                ensure!(!path.trim().is_empty(), "--env-file path cannot be empty");
                env_files.push(path.clone());
            }
            "--no-redact" => {
                redact = false;
            }
            other if other.starts_with('-') => {
                bail!("Unknown flag for `openkeylet run`: {other}\n{RUN_USAGE}");
            }
            _ => {
                cmd_start = Some(i);
                break;
            }
        }
        i += 1;
    }

    let start = cmd_start.with_context(|| format!("Missing command to execute.\n{RUN_USAGE}"))?;
    let command = args
        .get(start)
        .with_context(|| format!("Missing command after `--`.\n{RUN_USAGE}"))?
        .clone();
    ensure!(!command.trim().is_empty(), "Command cannot be empty");
    ensure!(
        !command.contains('\0'),
        "Command cannot contain null characters"
    );
    let cmd_args = args[start + 1..].to_vec();

    Ok(RunOptions {
        items,
        env_bindings,
        env_files,
        redact,
        command,
        args: cmd_args,
    })
}

pub fn is_valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('_' | 'a'..='z' | 'A'..='Z'))
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// Parse a `.env` template file into ordered `(KEY, RAW_VALUE)` pairs.
/// Ignores blank lines and `#` comments, supports optional `export ` prefix,
/// strips matching outer quotes, and strips trailing inline `#` comments on unquoted values.
pub fn parse_env_template(text: &str) -> Result<Vec<(String, String)>> {
    let text = text.trim_start_matches('\u{feff}');
    let mut entries = Vec::new();
    for (line_idx, raw_line) in text.lines().enumerate() {
        let mut line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("export ") {
            line = rest.trim_start();
        }
        let Some((raw_key, raw_val)) = line.split_once('=') else {
            bail!(
                "Invalid line {} in --env-file (expected KEY=VALUE)",
                line_idx + 1
            );
        };
        let key = raw_key.trim();
        ensure!(
            is_valid_env_var_name(key),
            "Invalid environment variable name '{key}' on line {} in --env-file",
            line_idx + 1
        );
        let value = unquote_env_value(raw_val.trim());
        entries.push((key.to_owned(), value));
    }
    Ok(entries)
}

fn unquote_env_value(raw: &str) -> String {
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        let inner = &raw[1..raw.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                    None => out.push('\\'),
                }
            } else {
                out.push(ch);
            }
        }
        out
    } else if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        raw[1..raw.len() - 1].to_owned()
    } else if let Some(pos) = raw.find(" #") {
        raw[..pos].trim_end().to_owned()
    } else {
        raw.to_owned()
    }
}

fn next_placeholder(input: &str) -> Option<(usize, usize)> {
    ["{{openkeylet:", "{{kru:"]
        .into_iter()
        .filter_map(|prefix| input.find(prefix).map(|start| (start, prefix.len())))
        .min_by_key(|(start, _)| *start)
}

fn normalize_lookup_text(value: &str) -> String {
    value
        .to_lowercase()
        .chars()
        .map(|ch| if ch.is_alphanumeric() { ch } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

struct SecretResolver {
    all_connections: Vec<DecryptedConnection>,
    default_item_ids: Vec<Uuid>,
    referenced_ids: Vec<Uuid>,
    referenced_set: HashSet<Uuid>,
    extra_redactions: Vec<Zeroizing<String>>,
}

impl SecretResolver {
    fn new(vault: &Vault, default_item_queries: &[String]) -> Result<Self> {
        let all_connections = vault.list_decrypted_connections()?;
        let mut resolver = Self {
            all_connections,
            default_item_ids: Vec::new(),
            referenced_ids: Vec::new(),
            referenced_set: HashSet::new(),
            extra_redactions: Vec::new(),
        };
        for query in default_item_queries {
            let id = resolver.find_enabled_item_id(query)?;
            if !resolver.default_item_ids.contains(&id) {
                resolver.default_item_ids.push(id);
            }
            resolver.mark_referenced(id);
        }
        Ok(resolver)
    }

    fn mark_referenced(&mut self, id: Uuid) {
        if self.referenced_set.insert(id) {
            self.referenced_ids.push(id);
        }
    }

    fn connection_by_id(&self, id: Uuid) -> Option<&DecryptedConnection> {
        self.all_connections.iter().find(|c| c.stored.id == id)
    }

    fn find_enabled_item_id(&self, query: &str) -> Result<Uuid> {
        let trimmed = query.trim();
        ensure!(!trimmed.is_empty(), "Vault item name cannot be empty");

        if let Ok(id) = Uuid::parse_str(trimmed) {
            let conn = self
                .all_connections
                .iter()
                .find(|c| c.stored.id == id)
                .with_context(|| format!("No vault item found with ID '{trimmed}'"))?;
            ensure!(
                conn.stored.enabled,
                "Vault item '{}' is disabled",
                conn.stored.name
            );
            return Ok(conn.stored.id);
        }

        // 1. Exact case-insensitive name match across all items (so disabled items give a clear error).
        let exact: Vec<&DecryptedConnection> = self
            .all_connections
            .iter()
            .filter(|c| c.stored.name.trim().eq_ignore_ascii_case(trimmed))
            .collect();
        if exact.len() == 1 {
            ensure!(
                exact[0].stored.enabled,
                "Vault item '{}' is disabled",
                exact[0].stored.name
            );
            return Ok(exact[0].stored.id);
        }

        let enabled: Vec<&DecryptedConnection> = self
            .all_connections
            .iter()
            .filter(|c| c.stored.enabled)
            .collect();

        // 2. Normalized exact name match among enabled items.
        let norm_query = normalize_lookup_text(trimmed);
        if !norm_query.is_empty() {
            let norm_exact: Vec<&DecryptedConnection> = enabled
                .iter()
                .copied()
                .filter(|c| normalize_lookup_text(&c.stored.name) == norm_query)
                .collect();
            if norm_exact.len() == 1 {
                return Ok(norm_exact[0].stored.id);
            }
        }

        // 3. Substring match among enabled items.
        let lower = trimmed.to_lowercase();
        let contains: Vec<&DecryptedConnection> = enabled
            .iter()
            .copied()
            .filter(|c| c.stored.name.to_lowercase().contains(&lower))
            .collect();
        match contains.len() {
            0 => bail!("No enabled vault item found matching '{trimmed}'"),
            1 => Ok(contains[0].stored.id),
            _ => bail!(
                "Multiple enabled vault items match '{trimmed}': {}. Specify the exact item name or UUID.",
                contains
                    .iter()
                    .map(|c| c.stored.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    /// Resolve a bare or `ItemName/module` reference into its value.
    fn resolve_reference(&mut self, reference: &str) -> Result<Zeroizing<String>> {
        let trimmed = reference.trim();
        ensure!(!trimmed.is_empty(), "Empty OpenKeylet secret reference");

        if let Some((item_query, module_name)) = self.try_split_cross_item(trimmed)? {
            let item_id = self.find_enabled_item_id(&item_query)?;
            self.mark_referenced(item_id);
            let value = self.read_module_from_item(item_id, &module_name)?;
            return Ok(value);
        }

        // Bare module reference: resolve against explicit `--item` list, or sole enabled item.
        if !self.default_item_ids.is_empty() {
            if self.default_item_ids.len() == 1 {
                let id = self.default_item_ids[0];
                return self.read_module_from_item(id, trimmed);
            }
            let mut matched: Vec<(Uuid, String, Zeroizing<String>)> = Vec::new();
            let candidate_ids = self.default_item_ids.clone();
            for id in candidate_ids {
                if let Ok(value) = self.read_module_from_item(id, trimmed) {
                    let name = self
                        .connection_by_id(id)
                        .map(|c| c.stored.name.clone())
                        .unwrap_or_default();
                    matched.push((id, name, value));
                }
            }
            match matched.len() {
                1 => return Ok(matched.pop().unwrap().2),
                0 => {
                    let searched = self
                        .default_item_ids
                        .iter()
                        .filter_map(|id| self.connection_by_id(*id).map(|c| c.stored.name.as_str()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    bail!(
                        "Module '{trimmed}' was not found in any specified --item ({searched})"
                    );
                }
                _ => {
                    let names = matched
                        .iter()
                        .map(|(_, name, _)| name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    bail!(
                        "Module '{trimmed}' exists in multiple --item entries ({names}); qualify it as ItemName/{trimmed}"
                    );
                }
            }
        }

        // No `--item` passed: allow bare reference only if there is a single enabled vault item.
        let enabled_ids: Vec<Uuid> = self
            .all_connections
            .iter()
            .filter(|c| c.stored.enabled)
            .map(|c| c.stored.id)
            .collect();
        if enabled_ids.len() == 1 {
            let id = enabled_ids[0];
            self.mark_referenced(id);
            return self.read_module_from_item(id, trimmed);
        }

        bail!(
            "Bare reference '{trimmed}' requires `--item <ITEM>` or an explicit `ItemName/{trimmed}` reference"
        );
    }

    fn try_split_cross_item(&self, trimmed: &str) -> Result<Option<(String, String)>> {
        if !trimmed.contains('/') {
            return Ok(None);
        }
        // Try splitting at the first `/` first (`ItemName/module`), then last `/` in case an item name contains `/`.
        let mut splits = Vec::new();
        if let Some((left, right)) = trimmed.split_once('/') {
            splits.push((left.trim(), right.trim()));
        }
        if let Some((left, right)) = trimmed.rsplit_once('/') {
            let pair = (left.trim(), right.trim());
            if !splits.contains(&pair) {
                splits.push(pair);
            }
        }

        for (item_part, module_part) in &splits {
            if item_part.is_empty() || module_part.is_empty() {
                continue;
            }
            if self.find_enabled_item_id(item_part).is_ok() {
                return Ok(Some(((*item_part).to_owned(), (*module_part).to_owned())));
            }
        }

        // If any default item literally contains a module named `trimmed`, allow bare lookup.
        for &id in &self.default_item_ids {
            if let Some(conn) = self.connection_by_id(id)
                && resolve_module_value(conn, trimmed).is_some()
            {
                return Ok(None);
            }
        }

        // Otherwise surface the real error from looking up the item portion.
        let (item_part, module_part) = splits[0];
        ensure!(
            !item_part.is_empty() && !module_part.is_empty(),
            "Invalid cross-item reference '{trimmed}'; expected ItemName/module"
        );
        // Trigger the descriptive item-not-found / disabled / ambiguous error.
        let _ = self.find_enabled_item_id(item_part)?;
        Ok(Some((item_part.to_owned(), module_part.to_owned())))
    }

    fn read_module_from_item(&mut self, item_id: Uuid, module_name: &str) -> Result<Zeroizing<String>> {
        let conn = self
            .connection_by_id(item_id)
            .context("Vault item not found")?;
        ensure!(
            conn.stored.enabled,
            "Vault item '{}' is disabled",
            conn.stored.name
        );

        let (resolved_value, is_totp, is_secret) = resolve_module_value(conn, module_name)
            .with_context(|| {
                let available = available_module_names(conn).join(", ");
                if available.is_empty() {
                    format!(
                        "Vault item '{}' has no configured modules",
                        conn.stored.name
                    )
                } else {
                    format!(
                        "Module '{module_name}' not found on vault item '{}' (available: {available})",
                        conn.stored.name
                    )
                }
            })?;

        let final_value = if is_totp {
            let code = current_totp(&resolved_value).with_context(|| {
                format!(
                    "Unable to generate TOTP code for vault item '{}'",
                    conn.stored.name
                )
            })?;
            Zeroizing::new(code)
        } else {
            Zeroizing::new(resolved_value)
        };

        ensure!(
            !final_value.contains('\0'),
            "Module '{module_name}' on '{}' contains a null byte and cannot be injected",
            conn.stored.name
        );

        if is_secret && !final_value.is_empty() {
            self.extra_redactions.push(final_value.clone());
        }
        Ok(final_value)
    }

    /// Interpolate every `{{openkeylet:...}}` or `{{kru:...}}` placeholder in `template`.
    fn interpolate(&mut self, template: &str) -> Result<Zeroizing<String>> {
        let mut rest = template;
        let mut output = String::with_capacity(template.len());
        while let Some((start, prefix_len)) = next_placeholder(rest) {
            output.push_str(&rest[..start]);
            let after_open = &rest[start + prefix_len..];
            let Some(end) = after_open.find("}}") else {
                bail!("Unclosed OpenKeylet secret placeholder (missing `}}}}`)");
            };
            let reference = after_open[..end].trim();
            let resolved = self.resolve_reference(reference)?;
            output.push_str(&resolved);
            rest = &after_open[end + 2..];
        }
        output.push_str(rest);
        ensure!(
            !output.contains('\0'),
            "Resolved value contains a null byte and cannot be injected"
        );
        Ok(Zeroizing::new(output))
    }

    fn referenced_item_names(&self) -> Vec<String> {
        self.referenced_ids
            .iter()
            .filter_map(|id| self.connection_by_id(*id).map(|c| c.stored.name.clone()))
            .collect()
    }

    fn collect_redaction_candidates(&self) -> Vec<String> {
        let mut raw_secrets: Vec<String> = Vec::new();
        for &id in &self.referenced_ids {
            if let Some(conn) = self.connection_by_id(id) {
                for secret in conn.secrets.non_empty_values() {
                    raw_secrets.push(secret.clone());
                    // Also cover CRLF variants of multi-line secrets (e.g. PEM keys echoed on Windows).
                    if secret.contains('\n') {
                        if secret.contains("\r\n") {
                            raw_secrets.push(secret.replace("\r\n", "\n"));
                        } else {
                            raw_secrets.push(secret.replace('\n', "\r\n"));
                        }
                    }
                }
                if let (Some(username), Some(password)) =
                    (conn.secrets.get("username"), conn.secrets.get("password"))
                {
                    let basic = STANDARD.encode(format!("{username}:{password}"));
                    if basic.len() >= 4 {
                        raw_secrets.push(basic);
                    }
                }
            }
        }
        for extra in &self.extra_redactions {
            raw_secrets.push((**extra).clone());
        }
        let mut candidates = redaction_candidates(&raw_secrets);
        raw_secrets.zeroize();
        // Avoid redacting empty strings; `redaction_candidates` already sorts longest-first & dedups.
        candidates.retain(|c| !c.is_empty());
        candidates
    }
}

fn resolve_module_value(
    conn: &DecryptedConnection,
    requested: &str,
) -> Option<(String, bool, bool)> {
    let trimmed = requested.trim();
    if trimmed.is_empty() {
        return None;
    }

    // 1. Direct SecretBundle lookup (exact name and standard aliases like apiCredential, private_key, etc.).
    if let Some(val) = conn.secrets.get(trimmed) {
        let is_totp = trimmed.eq_ignore_ascii_case("totp");
        return Some((val.to_owned(), is_totp, true));
    }

    // 2. Canonical alias mapping for common developer names.
    let canonical = match trimmed.to_ascii_lowercase().as_str() {
        "api_credential" | "apicredential" | "api_key" | "apikey" | "access_token"
        | "bearer_token" => Some("apiCredential"),
        "private_key" | "privatekey" | "ssh_key" => Some("privateKey"),
        "pass" | "pwd" | "passwd" => Some("password"),
        "user" | "account" => Some("username"),
        "otp" | "2fa" => Some("totp"),
        _ => None,
    };
    if let Some(alias) = canonical
        && let Some(val) = conn.secrets.get(alias)
    {
        return Some((val.to_owned(), alias == "totp", true));
    }

    // 3. Case-insensitive match against configured secret fields.
    for field in conn.secrets.available_fields(conn.stored.secret.as_ref()) {
        if field.name.eq_ignore_ascii_case(trimmed)
            && let Some(val) = conn.secrets.get(&field.name)
        {
            let is_totp = field.kind == "totp" || field.name.eq_ignore_ascii_case("totp");
            return Some((val.to_owned(), is_totp, true));
        }
    }

    // 4. Public non-secret module fallback (`host`, `port`, `url`, etc.).
    for module in &conn.stored.modules {
        if !module.is_secret()
            && !module.value.trim().is_empty()
            && (module.kind.eq_ignore_ascii_case(trimmed)
                || module.name.eq_ignore_ascii_case(trimmed))
        {
            return Some((module.value.clone(), false, false));
        }
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "host" if !conn.stored.host.trim().is_empty() => {
            return Some((conn.stored.host.clone(), false, false));
        }
        "port" if conn.stored.port > 0 => {
            return Some((conn.stored.port.to_string(), false, false));
        }
        "url" | "base_url" | "baseurl" if !conn.stored.base_url.trim().is_empty() => {
            return Some((conn.stored.base_url.clone(), false, false));
        }
        _ => {}
    }

    None
}

fn available_module_names(conn: &DecryptedConnection) -> Vec<String> {
    let mut names: Vec<String> = conn
        .secrets
        .available_fields(conn.stored.secret.as_ref())
        .into_iter()
        .filter(|field| conn.secrets.get(&field.name).is_some())
        .map(|field| field.name)
        .collect();
    for module in &conn.stored.modules {
        if !module.is_secret() && !module.value.trim().is_empty() {
            let label = if module.name.is_empty() {
                &module.kind
            } else {
                &module.name
            };
            if !names.iter().any(|existing| existing == label) {
                names.push(label.to_owned());
            }
        }
    }
    names
}

/// Resolved execution plan ready to spawn.
pub struct ResolvedRunPlan {
    pub command: String,
    pub args: Vec<Zeroizing<String>>,
    pub env: BTreeMap<String, Zeroizing<String>>,
    pub redaction_candidates: Vec<String>,
    pub referenced_items: Vec<String>,
    pub redact: bool,
}

impl Drop for ResolvedRunPlan {
    fn drop(&mut self) {
        for candidate in &mut self.redaction_candidates {
            candidate.zeroize();
        }
    }
}

/// Resolve all `--item`, `--env-file`, `--env`, and argv placeholders against the vault.
pub fn resolve_run_plan(vault: &Vault, options: &RunOptions) -> Result<ResolvedRunPlan> {
    let mut resolver = SecretResolver::new(vault, &options.items)?;
    let mut env: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();

    // 1. Load `--env-file` templates in order.
    for raw_path in &options.env_files {
        let resolved_path = resolve_user_path(raw_path)?;
        let content = std::fs::read_to_string(&resolved_path)
            .with_context(|| format!("Unable to read --env-file {}", resolved_path.display()))?;
        let entries = parse_env_template(&content)
            .with_context(|| format!("Failed to parse --env-file {}", resolved_path.display()))?;
        for (key, raw_value) in entries {
            let value = if next_placeholder(&raw_value).is_some() {
                resolver.interpolate(&raw_value)?
            } else {
                ensure!(
                    !raw_value.contains('\0'),
                    "Environment variable '{key}' contains a null byte"
                );
                Zeroizing::new(raw_value)
            };
            env.insert(key, value);
        }
    }

    // 2. Apply explicit `--env VAR=SPEC` bindings (overriding `--env-file` entries if duplicated).
    for (var, spec) in &options.env_bindings {
        let value = if next_placeholder(spec).is_some() {
            resolver.interpolate(spec)?
        } else {
            resolver.resolve_reference(spec)?
        };
        env.insert(var.clone(), value);
    }

    // 3. Interpolate placeholders in command arguments after `--`.
    let mut resolved_args = Vec::with_capacity(options.args.len());
    for arg in &options.args {
        if next_placeholder(arg).is_some() {
            resolved_args.push(resolver.interpolate(arg)?);
        } else {
            ensure!(
                !arg.contains('\0'),
                "Command argument cannot contain null characters"
            );
            resolved_args.push(Zeroizing::new(arg.clone()));
        }
    }

    let redaction_candidates = if options.redact {
        resolver.collect_redaction_candidates()
    } else {
        Vec::new()
    };
    let referenced_items = resolver.referenced_item_names();

    Ok(ResolvedRunPlan {
        command: options.command.clone(),
        args: resolved_args,
        env,
        redaction_candidates,
        referenced_items,
        redact: options.redact,
    })
}

/// Chunk-boundary-safe streaming secret redactor.
///
/// Holds back trailing bytes that may begin a known secret candidate until subsequent
/// bytes confirm or refute the match, so a secret split across OS `read()` boundaries is
/// still redacted, including when a shorter encoding of it would match first.
pub struct StreamRedactor {
    redactor: Redactor,
    pending: Vec<u8>,
}

impl StreamRedactor {
    pub fn new(candidates: &[String]) -> Self {
        Self {
            redactor: Redactor::new(candidates),
            pending: Vec::new(),
        }
    }

    /// Feed a new chunk of bytes while the stream is still open, returning the redacted
    /// bytes that can be emitted immediately.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.redactor.is_empty() {
            return chunk.to_vec();
        }
        if chunk.is_empty() {
            return Vec::new();
        }
        self.pending.extend_from_slice(chunk);
        let (out, consumed) = self.redactor.redact_stream(&self.pending, true);
        self.pending[..consumed].zeroize();
        self.pending.drain(..consumed);
        out
    }

    /// Flush all remaining held-back bytes at EOF, redacting any complete matches
    /// at the tail and releasing non-matching partial prefixes.
    pub fn finish(&mut self) -> Vec<u8> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        let out = self.redactor.redact_bytes(&self.pending);
        self.pending.zeroize();
        self.pending.clear();
        out
    }
}

impl Drop for StreamRedactor {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}

async fn pump_redacted<R, W>(
    mut reader: R,
    mut writer: W,
    candidates: Vec<String>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut redactor = StreamRedactor::new(&candidates);
    let mut buf = [0u8; 8_192];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let redacted = redactor.push(&buf[..n]);
        if !redacted.is_empty() {
            writer.write_all(&redacted).await?;
            writer.flush().await?;
        }
    }
    let tail = redactor.finish();
    if !tail.is_empty() {
        writer.write_all(&tail).await?;
        writer.flush().await?;
    }
    Ok(())
}

fn build_child_command(plan: &ResolvedRunPlan) -> tokio::process::Command {
    #[cfg(windows)]
    if let Some((cmd_exe, prefix_args)) = resolve_windows_batch_wrapper(&plan.command) {
        let mut cmd = tokio::process::Command::new(cmd_exe);
        cmd.args(prefix_args);
        for arg in &plan.args {
            cmd.arg(arg.as_str());
        }
        for (key, value) in &plan.env {
            cmd.env(key, value.as_str());
        }
        return cmd;
    }

    let mut cmd = tokio::process::Command::new(&plan.command);
    for arg in &plan.args {
        cmd.arg(arg.as_str());
    }
    for (key, value) in &plan.env {
        cmd.env(key, value.as_str());
    }
    cmd
}

#[cfg(windows)]
fn resolve_windows_batch_wrapper(program: &str) -> Option<(PathBuf, Vec<String>)> {
    let candidate = find_windows_program(program)?;
    let ext = candidate.extension()?.to_str()?;
    if !ext.eq_ignore_ascii_case("cmd") && !ext.eq_ignore_ascii_case("bat") {
        return None;
    }
    let cmd_exe = find_windows_native("cmd")?;
    let script_path = strip_verbatim_prefix(&candidate);
    Some((
        cmd_exe,
        vec![
            "/d".to_owned(),
            "/s".to_owned(),
            "/c".to_owned(),
            "call".to_owned(),
            script_path,
        ],
    ))
}

#[cfg(windows)]
fn find_windows_program(program: &str) -> Option<PathBuf> {
    let path = Path::new(program);
    if path.is_absolute() || path.components().count() > 1 {
        return path.is_file().then(|| path.to_path_buf());
    }
    let path_var = std::env::var_os("PATH")?;
    let exts: Vec<String> = if path.extension().is_some() {
        vec![String::new()]
    } else {
        std::env::var_os("PATHEXT")
            .map(|v| {
                v.to_string_lossy()
                    .split(';')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_else(|| vec![".exe".into(), ".cmd".into(), ".bat".into(), ".com".into()])
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in &exts {
            let candidate = dir.join(format!("{program}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(windows)]
fn find_windows_native(program: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for ext in [".exe", ".com"] {
            let candidate = dir.join(format!("{program}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(windows)]
fn strip_verbatim_prefix(path: &Path) -> String {
    let s = path.to_string_lossy();
    if let Some(unc) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else {
        s.strip_prefix(r"\\?\").unwrap_or(&s).to_owned()
    }
}

fn exit_status_to_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

fn audit_command_label(command: &str) -> String {
    Path::new(command)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(command)
        .to_owned()
}

fn record_run_activity(
    vault: &Vault,
    plan: &ResolvedRunPlan,
    started: Instant,
    exit_code: Option<i32>,
    error_message: Option<&str>,
) {
    let connection_name = if plan.referenced_items.is_empty() {
        "CLI".to_owned()
    } else {
        plan.referenced_items.join(", ")
    };
    let cmd_label = audit_command_label(&plan.command);
    let action = match exit_code {
        Some(code) => format!(
            "Run {cmd_label} ({} env, exit {code})",
            plan.env.len()
        ),
        None => format!("Run {cmd_label} ({} env)", plan.env.len()),
    };
    let status = if error_message.is_none() && exit_code == Some(0) {
        "success"
    } else {
        "error"
    };
    let _ = vault.add_activity(NewActivity {
        status: status.to_owned(),
        source: "CLI · RUN".to_owned(),
        connection_name,
        action,
        duration_ms: started.elapsed().as_millis() as u64,
        error: error_message.unwrap_or_default().to_owned(),
    });
}

/// Execute `openkeylet run` with real stdio streams and return the child exit code.
pub async fn run_cli(vault: &Vault, args: &[String]) -> Result<i32> {
    let options = parse_run_args(args)?;
    let plan = resolve_run_plan(vault, &options)?;
    execute_plan_with_writers(vault, &plan, None).await
}

/// Execute a resolved plan, optionally capturing stdout/stderr into caller-supplied buffers
/// (used by tests) or streaming directly to the process's stdout/stderr.
async fn execute_plan_with_writers(
    vault: &Vault,
    plan: &ResolvedRunPlan,
    capture: Option<(&mut Vec<u8>, &mut Vec<u8>)>,
) -> Result<i32> {
    let started = Instant::now();
    let mut cmd = build_child_command(plan);
    cmd.stdin(Stdio::inherit());

    let use_pipes = plan.redact || capture.is_some();
    if use_pipes {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    } else {
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            let msg = format!("Unable to spawn '{}': {err}", plan.command);
            record_run_activity(vault, plan, started, None, Some(&msg));
            return Err(anyhow::anyhow!(msg));
        }
    };

    let status = if use_pipes {
        let child_stdout = child
            .stdout
            .take()
            .context("Unable to capture child stdout")?;
        let child_stderr = child
            .stderr
            .take()
            .context("Unable to capture child stderr")?;
        let stdout_candidates = if plan.redact {
            plan.redaction_candidates.clone()
        } else {
            Vec::new()
        };
        let stderr_candidates = if plan.redact {
            plan.redaction_candidates.clone()
        } else {
            Vec::new()
        };

        if let Some((out_buf, err_buf)) = capture {
            let out_task = tokio::spawn(async move {
                let mut collected = Vec::new();
                pump_redacted(child_stdout, &mut collected, stdout_candidates).await?;
                Ok::<Vec<u8>, std::io::Error>(collected)
            });
            let err_task = tokio::spawn(async move {
                let mut collected = Vec::new();
                pump_redacted(child_stderr, &mut collected, stderr_candidates).await?;
                Ok::<Vec<u8>, std::io::Error>(collected)
            });
            let status = child
                .wait()
                .await
                .context("Unable to wait for child process")?;
            let out_bytes = out_task
                .await
                .context("Stdout redaction task failed")?
                .context("Unable to read child stdout")?;
            let err_bytes = err_task
                .await
                .context("Stderr redaction task failed")?
                .context("Unable to read child stderr")?;
            out_buf.extend_from_slice(&out_bytes);
            err_buf.extend_from_slice(&err_bytes);
            status
        } else {
            let out_task = tokio::spawn(async move {
                pump_redacted(child_stdout, tokio::io::stdout(), stdout_candidates).await
            });
            let err_task = tokio::spawn(async move {
                pump_redacted(child_stderr, tokio::io::stderr(), stderr_candidates).await
            });
            let status = child
                .wait()
                .await
                .context("Unable to wait for child process")?;
            let _ = out_task.await;
            let _ = err_task.await;
            status
        }
    } else {
        child
            .wait()
            .await
            .context("Unable to wait for child process")?
    };

    let exit_code = exit_status_to_code(status);
    record_run_activity(vault, plan, started, Some(exit_code), None);
    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ConnectionInput, ItemModule, SecretBundle};
    use tempfile::tempdir;

    fn make_item(
        vault: &Vault,
        name: &str,
        enabled: bool,
        pairs: &[(&str, &str)],
    ) -> Uuid {
        let mut modules = Vec::new();
        let mut secrets = SecretBundle::default();
        for &(k, v) in pairs {
            match k {
                "password" => {
                    modules.push(ItemModule {
                        kind: "password".to_owned(),
                        name: "password".to_owned(),
                        value: String::new(),
                        agent_visible: Some(false),
                    });
                    secrets.password = Some(v.to_owned());
                }
                "apiCredential" => {
                    modules.push(ItemModule {
                        kind: "apiCredential".to_owned(),
                        name: "apiCredential".to_owned(),
                        value: String::new(),
                        agent_visible: Some(false),
                    });
                    secrets
                        .named_secrets
                        .insert("apiCredential".to_owned(), v.to_owned());
                }
                "username" => {
                    modules.push(ItemModule {
                        kind: "username".to_owned(),
                        name: "username".to_owned(),
                        value: String::new(),
                        agent_visible: Some(false),
                    });
                    secrets
                        .named_secrets
                        .insert("username".to_owned(), v.to_owned());
                }
                custom => {
                    modules.push(ItemModule {
                        kind: "customSecret".to_owned(),
                        name: custom.to_owned(),
                        value: String::new(),
                        agent_visible: Some(false),
                    });
                    secrets
                        .named_secrets
                        .insert(custom.to_owned(), v.to_owned());
                }
            }
        }
        let saved = vault
            .save_connection(ConnectionInput {
                login_uris: Vec::new(),
                item_type: "custom".to_owned(),
                folder: String::new(),
                favorite: false,
                id: None,
                modules,
                name: name.to_owned(),
                enabled,
                description: String::new(),
                http_auth_type: String::new(),
                private_key_import_path: String::new(),
                auth_header: String::new(),
                auth_location: String::new(),
                auth_prefix: String::new(),
                api_auth_headers: Vec::new(),
                test_path: String::new(),
                remove_secret_names: Vec::new(),
                secrets,
            })
            .unwrap();
        saved.id
    }

    #[test]
    fn parse_env_template_handles_comments_quotes_exports_and_placeholders() {
        let tpl = "\u{feff}# Leading comment\n\
                   \n\
                   APP_ENV=production # inline comment\n\
                   export API_KEY={{openkeylet:apiCredential}}\n\
                   QUOTED_DOUBLE=\"line1\\n{{openkeylet:Prod DB/password}}\"\n\
                   QUOTED_SINGLE='literal # not comment {{kru:token}}'\n\
                   EMPTY_VAL=\n";
        let parsed = parse_env_template(tpl).unwrap();
        assert_eq!(parsed.len(), 5);
        assert_eq!(parsed[0], ("APP_ENV".into(), "production".into()));
        assert_eq!(
            parsed[1],
            ("API_KEY".into(), "{{openkeylet:apiCredential}}".into())
        );
        assert_eq!(
            parsed[2],
            (
                "QUOTED_DOUBLE".into(),
                "line1\n{{openkeylet:Prod DB/password}}".into()
            )
        );
        assert_eq!(
            parsed[3],
            (
                "QUOTED_SINGLE".into(),
                "literal # not comment {{kru:token}}".into()
            )
        );
        assert_eq!(parsed[4], ("EMPTY_VAL".into(), String::new()));
    }

    #[test]
    fn cross_item_resolution_env_file_and_args_work() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path().join("vault")).unwrap();
        make_item(
            &vault,
            "OpenAI",
            true,
            &[("apiCredential", "sk-openai-test-987654")],
        );
        make_item(
            &vault,
            "Prod DB",
            true,
            &[
                ("username", "db_admin"),
                ("password", "pg-ultra-secret-42"),
            ],
        );
        make_item(&vault, "Disabled Item", false, &[("password", "nope-999")]);

        let env_file_path = dir.path().join("app.env.template");
        std::fs::write(
            &env_file_path,
            "NODE_ENV=production\n\
             OPENAI_API_KEY={{openkeylet:apiCredential}}\n\
             DATABASE_URL=postgres://{{openkeylet:Prod DB/username}}:{{openkeylet:Prod DB/password}}@db.internal:5432/app\n\
             LEGACY_REF={{kru:Prod DB/password}}\n",
        )
        .unwrap();

        let args: Vec<String> = vec![
            "--item",
            "OpenAI",
            "--env-file",
            env_file_path.to_str().unwrap(),
            "--env",
            "DB_PASS=Prod DB/password",
            "--",
            "my-cli",
            "--header",
            "Bearer {{openkeylet:apiCredential}}",
            "--db",
            "{{openkeylet:Prod DB/password}}",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let opts = parse_run_args(&args).unwrap();
        let plan = resolve_run_plan(&vault, &opts).unwrap();

        assert_eq!(plan.env.get("NODE_ENV").unwrap().as_str(), "production");
        assert_eq!(
            plan.env.get("OPENAI_API_KEY").unwrap().as_str(),
            "sk-openai-test-987654"
        );
        assert_eq!(
            plan.env.get("DATABASE_URL").unwrap().as_str(),
            "postgres://db_admin:pg-ultra-secret-42@db.internal:5432/app"
        );
        assert_eq!(
            plan.env.get("LEGACY_REF").unwrap().as_str(),
            "pg-ultra-secret-42"
        );
        assert_eq!(
            plan.env.get("DB_PASS").unwrap().as_str(),
            "pg-ultra-secret-42"
        );
        assert_eq!(plan.args[0].as_str(), "--header");
        assert_eq!(plan.args[1].as_str(), "Bearer sk-openai-test-987654");
        assert_eq!(plan.args[3].as_str(), "pg-ultra-secret-42");

        // Both referenced items must be in redaction candidates.
        assert!(
            plan.redaction_candidates
                .iter()
                .any(|c| c == "sk-openai-test-987654")
        );
        assert!(
            plan.redaction_candidates
                .iter()
                .any(|c| c == "pg-ultra-secret-42")
        );

        // Disabled item must be rejected.
        let disabled_opts = parse_run_args(&[
            "--env".into(),
            "X=Disabled Item/password".into(),
            "--".into(),
            "echo".into(),
        ])
        .unwrap();
        let err = resolve_run_plan(&vault, &disabled_opts).err().unwrap();
        assert!(err.to_string().contains("disabled"), "unexpected error: {err}");

        // Multiple `--item` flags: unambiguous bare module resolves, ambiguous bare module errors cleanly.
        let multi_ok = parse_run_args(&[
            "--item".into(),
            "OpenAI".into(),
            "--item".into(),
            "Prod DB".into(),
            "--env".into(),
            "K=apiCredential".into(),
            "--env".into(),
            "P=password".into(),
            "--".into(),
            "my-cli".into(),
        ])
        .unwrap();
        let multi_plan = resolve_run_plan(&vault, &multi_ok).unwrap();
        assert_eq!(multi_plan.env.get("K").unwrap().as_str(), "sk-openai-test-987654");
        assert_eq!(multi_plan.env.get("P").unwrap().as_str(), "pg-ultra-secret-42");

        make_item(&vault, "Staging DB", true, &[("password", "staging-pw-123")]);
        let multi_ambig = parse_run_args(&[
            "--item".into(),
            "Prod DB".into(),
            "--item".into(),
            "Staging DB".into(),
            "--env".into(),
            "P=password".into(),
            "--".into(),
            "my-cli".into(),
        ])
        .unwrap();
        let ambig_err = resolve_run_plan(&vault, &multi_ambig).err().unwrap();
        assert!(
            ambig_err.to_string().contains("multiple --item"),
            "expected ambiguity error, got: {ambig_err}"
        );
    }

    #[test]
    fn stream_redactor_blocks_secret_split_byte_by_byte_and_false_prefixes() {
        let secret = "ok_super_secret_token_7788";
        let candidates = redaction_candidates(&[secret.to_owned()]);
        let payload = format!(
            "prefix ok_super_false_alarm middle {secret} encoded={} tail ok_sup",
            STANDARD.encode(secret.as_bytes())
        );

        // Feed 1 byte at a time to stress every possible chunk boundary!
        let mut redactor = StreamRedactor::new(&candidates);
        let mut emitted = Vec::new();
        for &byte in payload.as_bytes() {
            emitted.extend_from_slice(&redactor.push(&[byte]));
        }
        emitted.extend_from_slice(&redactor.finish());

        let result = String::from_utf8(emitted).unwrap();
        assert!(
            !result.contains(secret),
            "raw secret leaked into output: {result}"
        );
        assert!(
            !result.contains(&STANDARD.encode(secret.as_bytes())),
            "base64 secret leaked into output: {result}"
        );
        assert_eq!(
            result,
            "prefix ok_super_false_alarm middle [REDACTED] encoded=[REDACTED] tail ok_sup"
        );
    }

    #[tokio::test]
    async fn subprocess_execution_injects_secret_redacts_output_and_propagates_exit_code() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path().join("vault")).unwrap();
        let secret = "CLI_RUN_E2E_SECRET_99182736";
        make_item(&vault, "Runner Item", true, &[("apiCredential", secret)]);

        #[cfg(windows)]
        let cmd_args: Vec<String> = vec![
            "--item".into(),
            "Runner Item".into(),
            "--env".into(),
            "MY_SECRET=apiCredential".into(),
            "--".into(),
            "cmd.exe".into(),
            "/d".into(),
            "/c".into(),
            "echo stdout=%MY_SECRET% && echo arg={{openkeylet:apiCredential}} && echo stderr=%MY_SECRET% 1>&2 && exit /b 7".into(),
        ];
        #[cfg(not(windows))]
        let cmd_args: Vec<String> = vec![
            "--item".into(),
            "Runner Item".into(),
            "--env".into(),
            "MY_SECRET=apiCredential".into(),
            "--".into(),
            "sh".into(),
            "-c".into(),
            "printf 'stdout=%s\\n' \"$MY_SECRET\"; printf 'arg=%s\\n' \"$1\"; printf 'stderr=%s\\n' \"$MY_SECRET\" >&2; exit 7".into(),
            "sh".into(),
            "{{openkeylet:apiCredential}}".into(),
        ];

        let opts = parse_run_args(&cmd_args).unwrap();
        let plan = resolve_run_plan(&vault, &opts).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = execute_plan_with_writers(&vault, &plan, Some((&mut stdout, &mut stderr)))
            .await
            .unwrap();

        assert_eq!(exit_code, 7);
        let stdout_text = String::from_utf8_lossy(&stdout);
        let stderr_text = String::from_utf8_lossy(&stderr);
        assert!(
            stdout_text.contains("stdout=[REDACTED]"),
            "stdout did not contain redacted env value: {stdout_text:?}"
        );
        assert!(
            stdout_text.contains("arg=[REDACTED]"),
            "stdout did not contain redacted arg value: {stdout_text:?}"
        );
        assert!(
            stderr_text.contains("stderr=[REDACTED]"),
            "stderr did not contain redacted env value: {stderr_text:?}"
        );
        assert!(!stdout_text.contains(secret));
        assert!(!stderr_text.contains(secret));

        // Verify audit activity was recorded with source "CLI · RUN".
        let activities = vault.activities().unwrap();
        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0].source, "CLI · RUN");
        assert_eq!(activities[0].connection_name, "Runner Item");
        assert!(activities[0].action.contains("exit 7"));
        assert!(!activities[0].action.contains(secret));
    }

    #[tokio::test]
    async fn no_redact_flag_passes_output_through_unmodified() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path().join("vault")).unwrap();
        let marker = "UNREDACTED_MARKER_554433";
        make_item(&vault, "Raw Item", true, &[("apiCredential", marker)]);

        #[cfg(windows)]
        let cmd_args: Vec<String> = vec![
            "--item".into(),
            "Raw Item".into(),
            "--env".into(),
            "MY_VAL=apiCredential".into(),
            "--no-redact".into(),
            "--".into(),
            "cmd.exe".into(),
            "/d".into(),
            "/c".into(),
            "echo %MY_VAL%".into(),
        ];
        #[cfg(not(windows))]
        let cmd_args: Vec<String> = vec![
            "--item".into(),
            "Raw Item".into(),
            "--env".into(),
            "MY_VAL=apiCredential".into(),
            "--no-redact".into(),
            "--".into(),
            "sh".into(),
            "-c".into(),
            "printf '%s' \"$MY_VAL\"".into(),
        ];

        let opts = parse_run_args(&cmd_args).unwrap();
        assert!(!opts.redact);
        let plan = resolve_run_plan(&vault, &opts).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = execute_plan_with_writers(&vault, &plan, Some((&mut stdout, &mut stderr)))
            .await
            .unwrap();
        assert_eq!(code, 0);
        assert!(String::from_utf8_lossy(&stdout).contains(marker));
    }
}
