//! Pure local, zero-network multi-target credential extraction engine.
//!
//! Accepts messy free-form text (chat logs, handover docs, notes, emails),
//! structured developer configs (.env, ~/.ssh/config, ~/.aws/credentials,
//! JSON/YAML/TOML), and password-manager exports (Bitwarden JSON, Chrome/1Password CSV),
//! extracts all likely credentials with noise/placeholder filtering, and reconciles
//! them in-memory against the unlocked local Vault to detect duplicates and updates.

use crate::{
    api_catalog,
    login_uri::LoginUri,
    migration,
    model::{ConnectionInput, ItemModule, PortableConnection, SecretBundle},
    smart_ingest,
    vault::DecryptedConnection,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Instant,
};
use url::Url;
use uuid::Uuid;

const MAX_BATCH_TEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_BATCH_CANDIDATES: usize = 2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractedFieldPreview {
    pub label: String,
    pub value: String,
    pub masked: String,
    pub secret: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractedCandidate {
    pub id: String,
    pub kind: String,
    pub badge: String,
    pub badge_zh: String,
    pub confidence: String,
    pub selected: bool,
    pub summary: String,
    pub source_snippet: String,
    pub match_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub existing_item_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub existing_item_name: Option<String>,
    pub update_existing: bool,
    pub fields: Vec<ExtractedFieldPreview>,
    pub input: ConnectionInput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IgnoredSnippet {
    pub reason: String,
    pub reason_zh: String,
    pub key: String,
    pub preview: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate: Option<ExtractedCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmartExtractBatchResult {
    pub detected_format: String,
    pub detected_format_zh: String,
    pub candidates: Vec<ExtractedCandidate>,
    pub ignored: Vec<IgnoredSnippet>,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_env_template: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmartCommitItem {
    pub input: ConnectionInput,
    #[serde(default)]
    pub update_existing: bool,
    #[serde(default)]
    pub existing_item_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SmartCommitSummary {
    pub added: usize,
    pub updated: usize,
    pub created_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DroppedImagePayload {
    pub file_name: String,
    pub mime_type: String,
    pub data_base64: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredMvault {
    pub index: usize,
    pub file_name: String,
    pub display_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalScanCategoryStat {
    pub id: String,
    pub label: String,
    pub label_zh: String,
    pub probed_locations: usize,
    pub inspected_files: usize,
    pub matched_files: usize,
    pub extracted_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalScanReport {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_label: Option<String>,
    pub total_inspected_files: usize,
    pub total_matched_files: usize,
    pub duration_ms: u64,
    pub categories: Vec<LocalScanCategoryStat>,
}

#[derive(Debug, Clone)]
pub struct LocalScanOutcome {
    pub batch: SmartExtractBatchResult,
    pub discovered_mvaults: Vec<DiscoveredMvault>,
    pub mvault_paths: Vec<PathBuf>,
    pub report: LocalScanReport,
}

#[derive(Debug, Clone)]
pub struct ExtractedPathsOutcome {
    pub batch: SmartExtractBatchResult,
    pub images: Vec<DroppedImagePayload>,
    pub mvault_paths: Vec<PathBuf>,
    pub source_files: Vec<String>,
}

pub fn extract_batch(
    raw: &str,
    filename: Option<&str>,
    existing: &[DecryptedConnection],
) -> Result<SmartExtractBatchResult> {
    let trimmed = raw.trim_start_matches('\u{feff}').trim();
    ensure!(!trimmed.is_empty(), "Nothing to extract");
    ensure!(
        trimmed.len() <= MAX_BATCH_TEXT_BYTES,
        "Input exceeds 16 MiB limit"
    );

    let mut result = extract_without_dedup(trimmed, filename)?;
    if result.candidates.len() > MAX_BATCH_CANDIDATES {
        result.candidates.truncate(MAX_BATCH_CANDIDATES);
        result.warnings.push(format!(
            "Truncated preview to first {MAX_BATCH_CANDIDATES} items"
        ));
    }

    reconcile_with_vault(&mut result.candidates, existing);
    Ok(result)
}

pub fn merge_batch_results(
    parts: Vec<SmartExtractBatchResult>,
    existing: &[DecryptedConnection],
) -> SmartExtractBatchResult {
    let mut candidates = Vec::new();
    let mut ignored = Vec::new();
    let mut warnings = Vec::new();
    let mut sealed_env_template = None;
    let mut formats = Vec::new();
    let mut formats_zh = Vec::new();
    let mut seen_fingerprints = HashSet::new();

    for part in parts {
        if !formats.contains(&part.detected_format) {
            formats.push(part.detected_format);
            formats_zh.push(part.detected_format_zh);
        }
        if sealed_env_template.is_none() && part.sealed_env_template.is_some() {
            sealed_env_template = part.sealed_env_template;
        }
        for warning in part.warnings {
            if !warnings.contains(&warning) {
                warnings.push(warning);
            }
        }
        for candidate in part.candidates {
            let fp = candidate_dedup_key(&candidate);
            if fp.is_empty() || seen_fingerprints.insert(fp) {
                candidates.push(candidate);
            }
        }
        ignored.extend(part.ignored);
    }

    if candidates.len() > MAX_BATCH_CANDIDATES {
        candidates.truncate(MAX_BATCH_CANDIDATES);
        warnings.push(format!(
            "Truncated preview to first {MAX_BATCH_CANDIDATES} items"
        ));
    }

    reconcile_with_vault(&mut candidates, existing);

    let (detected_format, detected_format_zh) = if formats.len() == 1 {
        (formats.remove(0), formats_zh.remove(0))
    } else if formats.is_empty() {
        ("mixed_text".to_owned(), "混合文本".to_owned())
    } else {
        ("multi_source".to_owned(), "多来源混合".to_owned())
    };

    SmartExtractBatchResult {
        detected_format,
        detected_format_zh,
        candidates,
        ignored,
        warnings,
        sealed_env_template,
    }
}

const LOCAL_SCAN_MAX_DEPTH: usize = 3;
const LOCAL_SCAN_MAX_VISITED_PER_ROOT: usize = 2500;
const LOCAL_SCAN_MAX_MATCHED_FILES: usize = 120;
const LOCAL_SCAN_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

const WORKSPACE_SCAN_MAX_DEPTH: usize = 5;
const WORKSPACE_SCAN_MAX_VISITED: usize = 20_000;
const WORKSPACE_SCAN_MAX_MATCHED: usize = 250;

fn should_skip_local_scan_dir(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    should_skip_walk_dir(&lower)
        || matches!(
            lower.as_str(),
            "myenv"
                | "appdata"
                | "library"
                | "caches"
                | "cache"
                | "venv"
                | "vendor"
                | "packages"
                | "program files"
                | "windows"
                | "wechat files"
                | "tencent files"
                | "adobe"
                | "steam"
                | "games"
                | "videos"
                | "music"
                | "pictures"
                | "photos"
                | ".cargo"
                | ".rustup"
                | ".npm"
                | ".cache"
        )
}

fn should_skip_workspace_scan_dir(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    should_skip_walk_dir(&lower)
        || matches!(
            lower.as_str(),
            "myenv"
                | "appdata"
                | "library"
                | "caches"
                | "cache"
                | "venv"
                | "vendor"
                | ".cargo"
                | ".rustup"
                | ".npm"
                | ".cache"
                | "out"
                | ".next"
                | ".nuxt"
                | ".svelte-kit"
                | ".turbo"
                | ".parcel-cache"
                | "coverage"
                | ".pytest_cache"
                | ".mypy_cache"
                | "pods"
                | ".gradle"
                | "bin"
                | "obj"
                | "test-results"
                | "playwright-report"
        )
}

fn is_env_template_filename(lower: &str) -> bool {
    [
        ".example",
        ".sample",
        ".template",
        ".dist",
        ".schema",
        ".defaults",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
}

fn is_non_secret_ssh_artifact(lower: &str) -> bool {
    lower.ends_with(".pub")
        || lower.ends_with(".bak")
        || lower.ends_with(".old")
        || lower.starts_with("known_hosts")
        || lower.starts_with("authorized_keys")
}

fn is_suspected_credential_filename(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    if is_non_secret_ssh_artifact(&lower) || is_env_template_filename(&lower) {
        return false;
    }
    if lower == ".env"
        || lower.starts_with(".env.")
        || matches!(
            lower.as_str(),
            ".netrc"
                | "_netrc"
                | ".npmrc"
                | ".pypirc"
                | ".pgpass"
                | "pgpass.conf"
                | ".git-credentials"
                | "kubeconfig"
                | "rclone.conf"
                | "id_rsa"
                | "id_ed25519"
                | "id_ecdsa"
                | "id_dsa"
        )
    {
        return true;
    }
    if lower.contains("v2ray")
        || lower.contains("clash")
        || lower.contains("sing-box")
        || lower.contains("geosite")
        || lower.contains("package-lock")
        || lower.contains("pnpm-lock")
        || lower == "yarn.lock"
        || lower == "cargo.lock"
        || lower == "composer.lock"
        || lower.contains("tsconfig")
    {
        return false;
    }
    let ext = Path::new(&lower)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    if matches!(ext, "pem" | "key" | "ppk") {
        return true;
    }
    if !matches!(
        ext,
        "txt"
            | "md"
            | "csv"
            | "tsv"
            | "json"
            | "jsonc"
            | "yml"
            | "yaml"
            | "toml"
            | "ini"
            | "conf"
            | "cfg"
            | "properties"
            | "xml"
            | "xlsx"
            | "docx"
            | "sh"
            | "ps1"
            | "env"
    ) {
        return false;
    }
    const KEYWORDS: &[&str] = &[
        "password",
        "passwd",
        "pwd",
        "secret",
        "secretkey",
        "secret_key",
        "token",
        "apikey",
        "api_key",
        "api-key",
        "accesskey",
        "access_key",
        "access-key",
        "rootkey",
        "credential",
        "creds",
        "account",
        "login",
        "vault",
        "bitwarden",
        "1password",
        "keepass",
        "lastpass",
        "nordpass",
        "dashlane",
        "enpass",
        "chrome",
        "edge",
        "server",
        "ssh",
        "vps",
        "database",
        "db_",
        "db-",
        "kubeconfig",
        "rclone",
        ".env",
        "密码",
        "账号",
        "账户",
        "凭据",
        "密钥",
        "秘钥",
        "服务器",
        "主机",
        "数据库",
        "交接",
        "登录",
        "口令",
    ];
    KEYWORDS.iter().any(|kw| lower.contains(kw))
}

fn classify_workspace_credential_file(file_name: &str, in_test_dir: bool) -> Option<&'static str> {
    let lower = file_name.to_ascii_lowercase();
    if is_non_secret_ssh_artifact(&lower) || is_env_template_filename(&lower) {
        return None;
    }
    if lower == ".env" || lower.starts_with(".env.") || lower.ends_with(".env") {
        return Some("env_files");
    }
    if matches!(
        lower.as_str(),
        "id_rsa" | "id_ed25519" | "id_ecdsa" | "id_dsa"
    ) {
        return Some("ssh_keys");
    }
    let ext = Path::new(&lower)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    if matches!(ext, "pem" | "key" | "ppk") {
        return if in_test_dir { None } else { Some("ssh_keys") };
    }
    if in_test_dir {
        return None;
    }
    if matches!(
        lower.as_str(),
        "package.json"
            | "cargo.toml"
            | "pyproject.toml"
            | "composer.json"
            | "manifest.json"
            | "settings.json"
    ) {
        return None;
    }
    if matches!(
        lower.as_str(),
        ".mcp.json"
            | "mcp.json"
            | "mcp_config.json"
            | "claude_desktop_config.json"
            | ".npmrc"
            | ".pypirc"
            | ".netrc"
            | "_netrc"
            | ".pgpass"
            | "pgpass.conf"
            | ".git-credentials"
            | "kubeconfig"
            | "rclone.conf"
            | "credentials.json"
            | "service-account.json"
            | "docker-compose.yml"
            | "docker-compose.yaml"
    ) || (lower.starts_with("docker-compose.") && (lower.ends_with(".yml") || lower.ends_with(".yaml")))
        || ext == "tfvars"
        || is_suspected_credential_filename(file_name)
    {
        return Some("project_configs");
    }
    None
}

fn try_extract_git_credentials(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
    let lower = filename.unwrap_or_default().to_ascii_lowercase();
    if !lower.ends_with("git-credentials") {
        return None;
    }
    let mut candidates = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Ok(url) = Url::parse(trimmed) else {
            continue;
        };
        let Some(pass) = url.password() else {
            continue;
        };
        if pass.is_empty() {
            continue;
        }
        let host = url.host_str().unwrap_or("git");
        let user = url.username();
        let clean_url = format!("{}://{host}", url.scheme());
        candidates.push(build_login_candidate(
            &format!("Git · {host}"),
            Some(clean_url),
            (!user.is_empty()).then(|| user.to_owned()),
            Some(pass.to_owned()),
            None,
            filename.unwrap_or("~/.git-credentials"),
            "high",
        ));
    }
    if candidates.is_empty() {
        return None;
    }
    Some(SmartExtractBatchResult {
        detected_format: "git_credentials".to_owned(),
        detected_format_zh: "Git 凭据 (.git-credentials)".to_owned(),
        candidates,
        ignored: Vec::new(),
        warnings: Vec::new(),
        sealed_env_template: None,
    })
}

fn extract_suspected_file_strict(
    path: &Path,
    display_label: &str,
    existing: &[DecryptedConnection],
) -> Option<SmartExtractBatchResult> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > LOCAL_SCAN_MAX_FILE_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let lower = display_label.to_ascii_lowercase();
    let text = if lower.ends_with(".docx") {
        extract_docx_text(&bytes).ok()?
    } else if lower.ends_with(".xlsx") {
        extract_xlsx_text(&bytes).ok()?
    } else {
        std::str::from_utf8(&bytes).ok()?.to_owned()
    };
    let trimmed = text.trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(mut git_res) = try_extract_git_credentials(trimmed, Some(display_label)) {
        for cand in &mut git_res.candidates {
            cand.source_snippet = truncate_chars(display_label, 80);
        }
        reconcile_with_vault(&mut git_res.candidates, existing);
        return Some(git_res);
    }
    let mut res = extract_batch(trimmed, Some(display_label), existing).ok()?;
    // Keep only real extracted credentials during automated local search (no noisy low-confidence noise).
    res.candidates.retain(|c| c.confidence != "low");
    if res.candidates.is_empty() {
        return None;
    }
    for cand in &mut res.candidates {
        cand.source_snippet = truncate_chars(display_label, 80);
        if cand.input.description.trim().is_empty() {
            cand.input.description = format!("Found in {display_label}");
        }
    }
    Some(res)
}

fn collect_suspected_files_in_dir(
    root: &Path,
    root_label: &str,
    dir: &Path,
    depth: usize,
    visited: &mut usize,
    files_inspected: &mut usize,
    matched: &mut Vec<(PathBuf, String)>,
    mvault_found: &mut Vec<(PathBuf, String)>,
) {
    if depth > LOCAL_SCAN_MAX_DEPTH
        || *visited >= LOCAL_SCAN_MAX_VISITED_PER_ROOT
        || matched.len() >= LOCAL_SCAN_MAX_MATCHED_FILES
    {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if *visited >= LOCAL_SCAN_MAX_VISITED_PER_ROOT
            || matched.len() >= LOCAL_SCAN_MAX_MATCHED_FILES
        {
            break;
        }
        *visited += 1;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            if !should_skip_local_scan_dir(name) && depth < LOCAL_SCAN_MAX_DEPTH {
                collect_suspected_files_in_dir(
                    root,
                    root_label,
                    &path,
                    depth + 1,
                    visited,
                    files_inspected,
                    matched,
                    mvault_found,
                );
            }
            continue;
        }
        if !path.is_file() {
            continue;
        }
        *files_inspected += 1;
        let rel = path
            .strip_prefix(root)
            .ok()
            .map(|r| r.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|| name.to_owned());
        let label = format!("{root_label}/{rel}");
        if name.to_ascii_lowercase().ends_with(".mvault") {
            if mvault_found.len() < 12 {
                mvault_found.push((path, label));
            }
            continue;
        }
        if is_suspected_credential_filename(name) {
            matched.push((path, label));
        }
    }
}

fn short_source_context(source_snippet: &str) -> Option<String> {
    let normalized = source_snippet.replace('\\', "/");
    let parts: Vec<&str> = normalized
        .split('/')
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "~" && *s != ".")
        .collect();
    if parts.is_empty() {
        return None;
    }
    if parts.len() >= 2 {
        let parent = parts[parts.len() - 2];
        if !matches!(
            parent.to_ascii_lowercase().as_str(),
            "desktop" | "documents" | "downloads" | ".config" | "appdata" | "roaming" | "local" | "user"
        ) {
            return Some(parent.trim_start_matches('.').to_owned());
        }
    }
    parts.last().map(|s| (*s).to_owned())
}

fn disambiguate_multi_source_names(candidates: &mut [ExtractedCandidate]) {
    let mut name_counts: BTreeMap<String, usize> = BTreeMap::new();
    for cand in candidates.iter() {
        *name_counts
            .entry(cand.input.name.to_ascii_lowercase())
            .or_insert(0) += 1;
    }
    for cand in candidates.iter_mut() {
        let key = cand.input.name.to_ascii_lowercase();
        if name_counts.get(&key).copied().unwrap_or(0) > 1
            && let Some(ctx) = short_source_context(&cand.source_snippet)
            && !ctx.is_empty()
            && !cand.input.name.to_ascii_lowercase().contains(&ctx.to_ascii_lowercase())
        {
            cand.input.name = sanitize_name(&format!("{} ({ctx})", cand.input.name), 80);
        }
    }
}

fn scan_ssh_home_dir(
    ssh_dir: &Path,
    seen_paths: &mut HashSet<PathBuf>,
    parts: &mut Vec<SmartExtractBatchResult>,
    warnings: &mut Vec<String>,
    existing: &[DecryptedConnection],
) -> LocalScanCategoryStat {
    let mut probed_locations = 2usize; // ~/.ssh/config + ~/.ssh/* keys
    let mut inspected_files = 0usize;
    let mut matched_files = 0usize;
    let mut extracted_count = 0usize;
    let mut bound_pems: HashSet<String> = HashSet::new();

    if !ssh_dir.is_dir() {
        return LocalScanCategoryStat {
            id: "ssh_keys".to_owned(),
            label: "SSH & Keys".to_owned(),
            label_zh: "SSH 与私钥".to_owned(),
            probed_locations,
            inspected_files,
            matched_files,
            extracted_count,
        };
    }

    let mut config_files: Vec<(String, PathBuf)> = Vec::new();
    let main_cfg = ssh_dir.join("config");
    if main_cfg.is_file() {
        config_files.push(("~/.ssh/config".to_owned(), main_cfg));
    }
    let cfg_d = ssh_dir.join("config.d");
    if cfg_d.is_dir()
        && let Ok(entries) = std::fs::read_dir(&cfg_d)
    {
        probed_locations += 1;
        let mut sub: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        sub.sort();
        for p in sub {
            if p.is_file() {
                let fname = p
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("config");
                if !is_non_secret_ssh_artifact(&fname.to_ascii_lowercase()) {
                    config_files.push((format!("~/.ssh/config.d/{fname}"), p));
                }
            }
        }
    }

    for (label, cfg_path) in config_files {
        if !seen_paths.insert(cfg_path.clone()) {
            continue;
        }
        inspected_files += 1;
        match std::fs::read(&cfg_path) {
            Ok(bytes) => {
                if let Ok((entries, _)) =
                    smart_ingest::parse_ssh_config_bytes(&bytes, cfg_path.parent())
                    && !entries.is_empty()
                {
                    let mut candidates = Vec::new();
                    for (p, s) in entries {
                        if let Some(pk) = s.get("privateKey") {
                            bound_pems.insert(pk.trim().to_owned());
                        }
                        candidates.push(candidate_from_portable(p, s, "ssh", "SSH", "SSH", &label));
                    }
                    matched_files += 1;
                    extracted_count += candidates.len();
                    parts.push(SmartExtractBatchResult {
                        detected_format: "ssh_config".to_owned(),
                        detected_format_zh: format!("SSH 配置 ({label})"),
                        candidates,
                        ignored: Vec::new(),
                        warnings: Vec::new(),
                        sealed_env_template: None,
                    });
                }
            }
            Err(error) => warnings.push(format!("Could not read {label}: {error}")),
        }
    }

    // Scan standalone private keys inside ~/.ssh/ (e.g. id_ed25519, id_rsa, *.pem, *.ppk)
    if let Ok(entries) = std::fs::read_dir(ssh_dir) {
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for path in paths.into_iter().take(64) {
            if !path.is_file() || !seen_paths.insert(path.clone()) {
                continue;
            }
            let fname = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            let lower = fname.to_ascii_lowercase();
            if lower == "config"
                || lower == ".ds_store"
                || lower.starts_with("agent")
                || is_non_secret_ssh_artifact(&lower)
            {
                continue;
            }
            inspected_files += 1;
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if meta.len() == 0 || meta.len() > 256 * 1024 {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            if !content.contains("PRIVATE KEY-----") && !content.starts_with("PuTTY-User-Key-File-") {
                continue;
            }
            let label = format!("~/.ssh/{fname}");
            if let Some(mut res) = extract_suspected_file_strict(&path, &label, existing) {
                res.candidates.retain(|c| {
                    c.input
                        .secrets
                        .get("privateKey")
                        .is_none_or(|pk| !bound_pems.contains(pk.trim()))
                });
                if !res.candidates.is_empty() {
                    matched_files += 1;
                    extracted_count += res.candidates.len();
                    parts.push(res);
                }
            }
        }
    }

    LocalScanCategoryStat {
        id: "ssh_keys".to_owned(),
        label: "SSH & Keys".to_owned(),
        label_zh: "SSH 与私钥".to_owned(),
        probed_locations,
        inspected_files,
        matched_files,
        extracted_count,
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_fixed_config_group(
    id: &str,
    label: &str,
    label_zh: &str,
    targets: &[(String, PathBuf)],
    seen_paths: &mut HashSet<PathBuf>,
    parts: &mut Vec<SmartExtractBatchResult>,
    existing: &[DecryptedConnection],
) -> LocalScanCategoryStat {
    let mut probed_locations = 0usize;
    let mut inspected_files = 0usize;
    let mut matched_files = 0usize;
    let mut extracted_count = 0usize;
    let mut unique_group_paths = HashSet::new();

    for (display_label, path) in targets {
        if !unique_group_paths.insert(path.clone()) {
            continue;
        }
        probed_locations += 1;
        if !path.is_file() || !seen_paths.insert(path.clone()) {
            continue;
        }
        inspected_files += 1;
        if let Some(res) = extract_suspected_file_strict(path, display_label, existing) {
            matched_files += 1;
            extracted_count += res.candidates.len();
            parts.push(res);
        }
    }

    LocalScanCategoryStat {
        id: id.to_owned(),
        label: label.to_owned(),
        label_zh: label_zh.to_owned(),
        probed_locations,
        inspected_files,
        matched_files,
        extracted_count,
    }
}

#[cfg(test)]
pub(crate) fn scan_local_credential_roots(
    home: Option<&Path>,
    user_dirs: &[(&str, PathBuf)],
    existing: &[DecryptedConnection],
) -> Result<LocalScanOutcome> {
    let default_cfg = home.map(|h| h.join("AppData").join("Roaming"));
    scan_local_credential_roots_with_config(home, default_cfg.as_deref(), user_dirs, existing)
}

pub(crate) fn scan_local_credential_roots_with_config(
    home: Option<&Path>,
    os_config_dir: Option<&Path>,
    user_dirs: &[(&str, PathBuf)],
    existing: &[DecryptedConnection],
) -> Result<LocalScanOutcome> {
    let started = Instant::now();
    let mut parts = Vec::new();
    let mut warnings = Vec::new();
    let mut seen_paths: HashSet<PathBuf> = HashSet::new();
    let mut categories: Vec<LocalScanCategoryStat> = Vec::new();

    if let Some(home_dir) = home {
        // 1. SSH config & standalone private keys
        let ssh_stat = scan_ssh_home_dir(
            &home_dir.join(".ssh"),
            &mut seen_paths,
            &mut parts,
            &mut warnings,
            existing,
        );
        categories.push(ssh_stat);

        // 2. Developer, Git, Registry & Cloud CLI credentials
        let mut dev_targets: Vec<(String, PathBuf)> = vec![
            ("~/.git-credentials".to_owned(), home_dir.join(".git-credentials")),
            (
                "~/.config/gh/hosts.yml".to_owned(),
                home_dir.join(".config").join("gh").join("hosts.yml"),
            ),
            (
                "~/.config/glab-cli/config.yml".to_owned(),
                home_dir.join(".config").join("glab-cli").join("config.yml"),
            ),
            ("~/.aws/credentials".to_owned(), home_dir.join(".aws").join("credentials")),
            ("~/.aliyun/config.json".to_owned(), home_dir.join(".aliyun").join("config.json")),
            (
                "~/.tccli/default.credential".to_owned(),
                home_dir.join(".tccli").join("default.credential"),
            ),
            ("~/.azure/credentials".to_owned(), home_dir.join(".azure").join("credentials")),
            ("~/.docker/config.json".to_owned(), home_dir.join(".docker").join("config.json")),
            ("~/.kube/config".to_owned(), home_dir.join(".kube").join("config")),
            ("~/.netrc".to_owned(), home_dir.join(".netrc")),
            ("~/_netrc".to_owned(), home_dir.join("_netrc")),
            ("~/.npmrc".to_owned(), home_dir.join(".npmrc")),
            ("~/.yarnrc.yml".to_owned(), home_dir.join(".yarnrc.yml")),
            ("~/.pypirc".to_owned(), home_dir.join(".pypirc")),
            ("~/.pgpass".to_owned(), home_dir.join(".pgpass")),
            ("~/.composer/auth.json".to_owned(), home_dir.join(".composer").join("auth.json")),
            (
                "~/.config/rclone/rclone.conf".to_owned(),
                home_dir.join(".config").join("rclone").join("rclone.conf"),
            ),
            ("~/.env".to_owned(), home_dir.join(".env")),
            ("~/.env.local".to_owned(), home_dir.join(".env.local")),
        ];
        if let Some(cfg) = os_config_dir {
            dev_targets.push((
                "AppData/postgresql/pgpass.conf".to_owned(),
                cfg.join("postgresql").join("pgpass.conf"),
            ));
            dev_targets.push((
                "AppData/rclone/rclone.conf".to_owned(),
                cfg.join("rclone").join("rclone.conf"),
            ));
            dev_targets.push((
                "AppData/gh/hosts.yml".to_owned(),
                cfg.join("GitHub CLI").join("hosts.yml"),
            ));
        }
        categories.push(scan_fixed_config_group(
            "dev_cloud",
            "Git · Cloud · CLI",
            "Git 与云凭据",
            &dev_targets,
            &mut seen_paths,
            &mut parts,
            existing,
        ));

        // 3. AI Coding Agents & MCP Client plaintext env configs
        let mut ai_targets: Vec<(String, PathBuf)> = vec![
            ("~/.claude.json".to_owned(), home_dir.join(".claude.json")),
            ("~/.claude/settings.json".to_owned(), home_dir.join(".claude").join("settings.json")),
            ("~/.cursor/mcp.json".to_owned(), home_dir.join(".cursor").join("mcp.json")),
            (
                "~/.codeium/windsurf/mcp_config.json".to_owned(),
                home_dir.join(".codeium").join("windsurf").join("mcp_config.json"),
            ),
            (
                "~/.gemini/antigravity/mcp_config.json".to_owned(),
                home_dir.join(".gemini").join("antigravity").join("mcp_config.json"),
            ),
            ("~/.gemini/settings.json".to_owned(), home_dir.join(".gemini").join("settings.json")),
            ("~/.codex/config.toml".to_owned(), home_dir.join(".codex").join("config.toml")),
            ("~/.codex/auth.json".to_owned(), home_dir.join(".codex").join("auth.json")),
            (
                "~/.config/opencode/opencode.jsonc".to_owned(),
                home_dir.join(".config").join("opencode").join("opencode.jsonc"),
            ),
            (
                "~/.config/opencode/opencode.json".to_owned(),
                home_dir.join(".config").join("opencode").join("opencode.json"),
            ),
            (
                "~/.local/share/opencode/auth.json".to_owned(),
                home_dir.join(".local").join("share").join("opencode").join("auth.json"),
            ),
            ("~/.continue/config.json".to_owned(), home_dir.join(".continue").join("config.json")),
            ("~/.continue/config.yaml".to_owned(), home_dir.join(".continue").join("config.yaml")),
            (
                "~/Library/Application Support/Claude/claude_desktop_config.json".to_owned(),
                home_dir
                    .join("Library")
                    .join("Application Support")
                    .join("Claude")
                    .join("claude_desktop_config.json"),
            ),
            (
                "~/.config/Claude/claude_desktop_config.json".to_owned(),
                home_dir.join(".config").join("Claude").join("claude_desktop_config.json"),
            ),
        ];
        if let Some(cfg) = os_config_dir {
            ai_targets.push((
                "Claude/claude_desktop_config.json".to_owned(),
                cfg.join("Claude").join("claude_desktop_config.json"),
            ));
            ai_targets.push((
                "VSCode/User/mcp.json".to_owned(),
                cfg.join("Code").join("User").join("mcp.json"),
            ));
        }
        categories.push(scan_fixed_config_group(
            "ai_mcp",
            "AI & MCP Configs",
            "AI 与 MCP 配置",
            &ai_targets,
            &mut seen_paths,
            &mut parts,
            existing,
        ));
    }

    // 4. User Desktop / Documents / Downloads (up to depth 3)
    let mut matched_files: Vec<(PathBuf, String)> = Vec::new();
    let mut mvault_found: Vec<(PathBuf, String)> = Vec::new();
    let mut seen_roots: HashSet<PathBuf> = HashSet::new();
    let mut user_probed_roots = 0usize;
    let mut user_files_inspected = 0usize;

    for (root_label, dir) in user_dirs {
        if !dir.is_dir() || !seen_roots.insert(dir.clone()) {
            continue;
        }
        user_probed_roots += 1;
        let mut visited = 0usize;
        collect_suspected_files_in_dir(
            dir,
            root_label,
            dir,
            0,
            &mut visited,
            &mut user_files_inspected,
            &mut matched_files,
            &mut mvault_found,
        );
    }

    let mut user_matched_count = mvault_found.len();
    let mut user_extracted_count = mvault_found.len();
    for (path, label) in matched_files {
        if !seen_paths.insert(path.clone()) {
            continue;
        }
        if let Some(res) = extract_suspected_file_strict(&path, &label, existing) {
            user_matched_count += 1;
            user_extracted_count += res.candidates.len();
            parts.push(res);
        }
    }

    if user_probed_roots > 0 || !user_dirs.is_empty() {
        categories.push(LocalScanCategoryStat {
            id: "user_files".to_owned(),
            label: "Desktop · Docs · Downloads".to_owned(),
            label_zh: "桌面 · 文档 · 下载".to_owned(),
            probed_locations: user_probed_roots.max(user_dirs.len()),
            inspected_files: user_files_inspected,
            matched_files: user_matched_count,
            extracted_count: user_extracted_count,
        });
    }

    let mut merged = merge_batch_results(parts, existing);
    disambiguate_multi_source_names(&mut merged.candidates);

    let mut discovered_mvaults = Vec::new();
    let mut mvault_paths = Vec::new();
    for (idx, (path, display_path)) in mvault_found.into_iter().enumerate() {
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("openkeylet-backup.mvault")
            .to_owned();
        discovered_mvaults.push(DiscoveredMvault {
            index: idx,
            file_name,
            display_path,
        });
        mvault_paths.push(path);
    }

    merged.detected_format = "local_search".to_owned();
    merged.detected_format_zh = "本机一键搜索".to_owned();
    merged.warnings.extend(warnings);

    let total_inspected_files = categories.iter().map(|c| c.inspected_files).sum();
    let total_matched_files = categories.iter().map(|c| c.matched_files).sum();
    let report = LocalScanReport {
        mode: "quick_pc".to_owned(),
        target_label: None,
        total_inspected_files,
        total_matched_files,
        duration_ms: started.elapsed().as_millis() as u64,
        categories,
    };

    Ok(LocalScanOutcome {
        batch: merged,
        discovered_mvaults,
        mvault_paths,
        report,
    })
}

pub fn scan_local_dev_configs_with_mvaults(
    existing: &[DecryptedConnection],
) -> Result<LocalScanOutcome> {
    let home = dirs::home_dir();
    let cfg = dirs::config_dir();
    let mut user_dirs: Vec<(&str, PathBuf)> = Vec::new();
    if let Some(d) = dirs::desktop_dir() {
        user_dirs.push(("Desktop", d));
    }
    if let Some(d) = dirs::document_dir() {
        user_dirs.push(("Documents", d));
    }
    if let Some(d) = dirs::download_dir() {
        user_dirs.push(("Downloads", d));
    }
    scan_local_credential_roots_with_config(
        home.as_deref(),
        cfg.as_deref(),
        &user_dirs,
        existing,
    )
}

pub fn scan_local_dev_configs(existing: &[DecryptedConnection]) -> Result<SmartExtractBatchResult> {
    Ok(scan_local_dev_configs_with_mvaults(existing)?.batch)
}

#[allow(clippy::too_many_arguments)]
fn collect_workspace_files_in_dir(
    root: &Path,
    root_label: &str,
    dir: &Path,
    depth: usize,
    in_test_dir: bool,
    visited: &mut usize,
    files_inspected: &mut usize,
    matched: &mut Vec<(PathBuf, String, &'static str)>,
    mvault_found: &mut Vec<(PathBuf, String)>,
) {
    if depth > WORKSPACE_SCAN_MAX_DEPTH
        || *visited >= WORKSPACE_SCAN_MAX_VISITED
        || matched.len() >= WORKSPACE_SCAN_MAX_MATCHED
    {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if *visited >= WORKSPACE_SCAN_MAX_VISITED
            || matched.len() >= WORKSPACE_SCAN_MAX_MATCHED
        {
            break;
        }
        *visited += 1;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            if !should_skip_workspace_scan_dir(name) && depth < WORKSPACE_SCAN_MAX_DEPTH {
                let lower_dir = name.to_ascii_lowercase();
                let child_in_test = in_test_dir
                    || matches!(
                        lower_dir.as_str(),
                        "test" | "tests" | "__tests__" | "fixtures" | "testdata" | "examples" | "mocks"
                    );
                collect_workspace_files_in_dir(
                    root,
                    root_label,
                    &path,
                    depth + 1,
                    child_in_test,
                    visited,
                    files_inspected,
                    matched,
                    mvault_found,
                );
            }
            continue;
        }
        if !path.is_file() {
            continue;
        }
        *files_inspected += 1;
        let rel = path
            .strip_prefix(root)
            .ok()
            .map(|r| r.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|| name.to_owned());
        let label = format!("{root_label}/{rel}");
        if name.to_ascii_lowercase().ends_with(".mvault") {
            if mvault_found.len() < 16 {
                mvault_found.push((path, label));
            }
            continue;
        }
        if let Some(cat_id) = classify_workspace_credential_file(name, in_test_dir) {
            matched.push((path, label, cat_id));
        }
    }
}

pub fn scan_workspace_directory(
    root: &Path,
    existing: &[DecryptedConnection],
) -> Result<LocalScanOutcome> {
    ensure!(root.is_dir(), "Selected path is not a directory");
    let started = Instant::now();
    let root_label = root
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| root.to_string_lossy().replace('\\', "/"));

    let mut visited = 0usize;
    let mut files_inspected = 0usize;
    let mut matched: Vec<(PathBuf, String, &'static str)> = Vec::new();
    let mut mvault_found: Vec<(PathBuf, String)> = Vec::new();
    collect_workspace_files_in_dir(
        root,
        &root_label,
        root,
        0,
        false,
        &mut visited,
        &mut files_inspected,
        &mut matched,
        &mut mvault_found,
    );

    let mut parts = Vec::new();
    let mut seen_paths = HashSet::new();
    let mut env_stat = (0usize, 0usize, 0usize); // (probed_candidates, matched_with_secrets, extracted_count)
    let mut key_stat = (0usize, 0usize, 0usize);
    let mut cfg_stat = (mvault_found.len(), mvault_found.len(), mvault_found.len());

    for (path, label, cat_id) in matched {
        if !seen_paths.insert(path.clone()) {
            continue;
        }
        let stat_ref = match cat_id {
            "env_files" => &mut env_stat,
            "ssh_keys" => &mut key_stat,
            _ => &mut cfg_stat,
        };
        stat_ref.0 += 1;
        if let Some(res) = extract_suspected_file_strict(&path, &label, existing) {
            stat_ref.1 += 1;
            stat_ref.2 += res.candidates.len();
            parts.push(res);
        }
    }

    let mut merged = merge_batch_results(parts, existing);
    disambiguate_multi_source_names(&mut merged.candidates);

    if visited >= WORKSPACE_SCAN_MAX_VISITED {
        merged.warnings.push(format!(
            "Inspected first {WORKSPACE_SCAN_MAX_VISITED} entries in {root_label}; pick a narrower subfolder if needed"
        ));
    }

    let mut discovered_mvaults = Vec::new();
    let mut mvault_paths = Vec::new();
    for (idx, (path, display_path)) in mvault_found.into_iter().enumerate() {
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("openkeylet-backup.mvault")
            .to_owned();
        discovered_mvaults.push(DiscoveredMvault {
            index: idx,
            file_name,
            display_path,
        });
        mvault_paths.push(path);
    }

    merged.detected_format = "workspace_scan".to_owned();
    merged.detected_format_zh = format!("目录深扫 · {root_label}");

    let categories = vec![
        LocalScanCategoryStat {
            id: "env_files".to_owned(),
            label: "Env Files (.env*)".to_owned(),
            label_zh: ".env 环境文件".to_owned(),
            probed_locations: 1,
            inspected_files: env_stat.0,
            matched_files: env_stat.1,
            extracted_count: env_stat.2,
        },
        LocalScanCategoryStat {
            id: "ssh_keys".to_owned(),
            label: "SSH & Keys".to_owned(),
            label_zh: "私钥与证书".to_owned(),
            probed_locations: 1,
            inspected_files: key_stat.0,
            matched_files: key_stat.1,
            extracted_count: key_stat.2,
        },
        LocalScanCategoryStat {
            id: "project_configs".to_owned(),
            label: "Configs & Backups".to_owned(),
            label_zh: "配置与备份".to_owned(),
            probed_locations: 1,
            inspected_files: cfg_stat.0,
            matched_files: cfg_stat.1,
            extracted_count: cfg_stat.2,
        },
    ];
    let total_matched_files = env_stat.1 + key_stat.1 + cfg_stat.1;
    let report = LocalScanReport {
        mode: "workspace_folder".to_owned(),
        target_label: Some(root.to_string_lossy().replace('\\', "/")),
        total_inspected_files: files_inspected,
        total_matched_files,
        duration_ms: started.elapsed().as_millis() as u64,
        categories,
    };

    Ok(LocalScanOutcome {
        batch: merged,
        discovered_mvaults,
        mvault_paths,
        report,
    })
}

fn extract_without_dedup(
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
        && let Ok((entries, preview)) = smart_ingest::parse_ssh_config_bytes(trimmed.as_bytes(), None)
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

    // 10. YAML / TOML / INI / Properties config file
    if (lower_file.ends_with(".yml")
        || lower_file.ends_with(".yaml")
        || lower_file.ends_with(".toml")
        || lower_file.ends_with(".ini")
        || lower_file.ends_with(".conf")
        || lower_file.ends_with(".cfg")
        || lower_file.ends_with(".properties"))
        && let Some(cfg_res) = try_extract_yaml_toml_config(trimmed, filename)
    {
        return Ok(cfg_res);
    }

    // 11. Universal Mixed Free-Text Multi-Extractor (chats, notes, emails, handover docs)
    Ok(extract_mixed_free_text(trimmed, filename))
}

fn looks_like_bitwarden_json(text: &str) -> bool {
    text.starts_with('{') && text.contains("\"items\"") && text.contains("\"type\"")
}

fn try_extract_putty_ppk(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
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

fn try_extract_cloud_key_csv(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
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
            "access key id" | "accesskey id" | "accesskeyid" | "access_key_id" | "secretid" | "secret id"
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
        )
    })?;
    let idx_user = headers.iter().position(|h| {
        matches!(
            h.as_str(),
            "user name" | "username" | "user" | "account" | "description" | "备注" | "用户名"
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
            input.modules.push(public_mod("customField", "Account", u));
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

fn looks_like_password_csv(text: &str) -> bool {
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

fn try_extract_password_csv(
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
        .position(|h| matches!(h.as_str(), "name" | "title" | "service" | "site" | "名称" | "标题" | "平台"));
    let idx_url = headers
        .iter()
        .position(|h| matches!(h.as_str(), "url" | "website" | "origin" | "login_uri" | "网址" | "链接" | "地址"));
    let idx_user = headers
        .iter()
        .position(|h| matches!(h.as_str(), "username" | "user" | "email" | "account" | "login" | "账号" | "用户名" | "邮箱"));
    let idx_pass = headers
        .iter()
        .position(|h| matches!(h.as_str(), "password" | "pass" | "pwd" | "密码"));
    let idx_totp = headers
        .iter()
        .position(|h| matches!(h.as_str(), "totp" | "otp" | "2fa" | "otpauth"));

    if idx_pass.is_none() && idx_user.is_none() {
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
        if url.is_empty() && user.is_empty() && pass.is_empty() {
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
            (!pass.is_empty()).then_some(pass),
            (!totp.is_empty()).then_some(totp),
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

fn try_extract_aws_credentials(
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
        input.description = format!("AWS profile: {profile}");
        if let Some(ref reg) = region {
            input.modules.push(public_mod("customField", "Region", reg));
        }
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

fn looks_like_ssh_config_file(text: &str, lower_file: &str) -> bool {
    let has_host = text
        .lines()
        .any(|l| l.trim_start().to_ascii_lowercase().starts_with("host "));
    let has_hostname = text
        .lines()
        .any(|l| l.trim_start().to_ascii_lowercase().starts_with("hostname "));
    (has_host && has_hostname) || (lower_file.ends_with("ssh/config") && has_host)
}

fn looks_like_env_document(text: &str, lower_file: &str) -> bool {
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
    let vars = smart_ingest::parse_env_vars(text);
    if vars.is_empty() {
        return false;
    }
    if file_hint {
        return true;
    }
    // Require high ratio of KEY=VALUE lines and at least 2 vars (single line handled by mixed extractor too)
    vars.len() * 10 >= non_comment.len() * 7
}

fn extract_env_document(text: &str, filename: Option<&str>) -> SmartExtractBatchResult {
    let vars = smart_ingest::parse_env_vars(text);
    let mut candidates = Vec::new();
    let mut ignored = Vec::new();
    let mut remaining_secrets: Vec<(String, String)> = Vec::new();
    let mut seen_keys = HashSet::new();

    for var in vars {
        if !seen_keys.insert(var.key.clone()) {
            continue;
        }
        classify_key_value_entry(
            &var.key,
            &var.value,
            filename.unwrap_or(".env"),
            &mut candidates,
            &mut remaining_secrets,
            &mut ignored,
        );
    }

    if !remaining_secrets.is_empty() {
        candidates.push(build_env_group_candidate(
            &remaining_secrets,
            filename,
            ".env",
        ));
    }

    let (sealed, sealed_keys) = smart_ingest::render_sealed_env(text);
    let sealed_env_template = (!sealed_keys.is_empty()).then_some(sealed);

    SmartExtractBatchResult {
        detected_format: "env".to_owned(),
        detected_format_zh: ".env 环境变量".to_owned(),
        candidates,
        ignored,
        warnings: Vec::new(),
        sealed_env_template,
    }
}

fn parse_json_or_jsonc(trimmed: &str, lower_file: &str) -> Option<Value> {
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

fn strip_jsonc(input: &str) -> String {
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

fn try_extract_docker_auths(
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

fn try_extract_json_config(
    value: &Value,
    filename: Option<&str>,
) -> Option<SmartExtractBatchResult> {
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

fn flatten_json_strings(value: &Value, prefix: &str, out: &mut Vec<(String, String)>) {
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

fn try_extract_yaml_toml_config(
    text: &str,
    filename: Option<&str>,
) -> Option<SmartExtractBatchResult> {
    let mut candidates = Vec::new();
    let mut ignored = Vec::new();
    let mut remaining_secrets = Vec::new();
    let mut section = String::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') && line.len() > 2 {
            section = line[1..line.len() - 1].trim().to_owned();
            continue;
        }
        let pair = line
            .split_once('=')
            .or_else(|| line.split_once(':'));
        let Some((raw_k, raw_v)) = pair else {
            continue;
        };
        let k = raw_k.trim().trim_start_matches('-').trim().trim_matches('"').trim_matches('\'');
        let v = strip_inline_quotes(raw_v.trim());
        if k.is_empty() || v.is_empty() {
            continue;
        }
        let full_key = if section.is_empty() {
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

fn classify_key_value_entry(
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
        && let Ok(parsed) = smart_ingest::smart_parse(value, None, None)
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
        && let Ok(parsed) = smart_ingest::smart_parse(value, None, None)
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
        && let Ok(parsed) = smart_ingest::smart_parse(value, Some(leaf_key), None)
    {
        candidates.push(candidate_from_smart_parse(
            parsed,
            Some(&pretty_key_title(key)),
            &format!("{key}=<PEM key>"),
        ));
        return;
    }

    // 4. Known API key (by prefix or provider key name)
    let profile = api_catalog::infer(key, "", value);
    let has_known_provider = profile.display_name != "API";
    let looks_like_token_prefix = has_high_confidence_token_prefix(value);
    if (has_known_provider && value.len() >= 10 && !is_obvious_non_secret_value(value))
        || looks_like_token_prefix
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

    // 5. Public / non-secret config keys
    if is_explicit_non_secret_key(leaf_key) || is_obvious_non_secret_value(value) {
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

    // 6. Secret-looking key name OR high Shannon entropy
    let secret_key_score = key_secret_score(leaf_key);
    let entropy = shannon_entropy(value);
    if secret_key_score >= 2 || (secret_key_score >= 1 && value.len() >= 8) || (value.len() >= 20 && entropy >= 3.6 && !value.contains(' ')) {
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

fn extract_mixed_free_text(text: &str, filename: Option<&str>) -> SmartExtractBatchResult {
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
            if let Ok(parsed) = smart_ingest::smart_parse(&uri, None, None) {
                let cand = candidate_from_smart_parse(parsed, heading, "otpauth://...");
                push_unique(&mut candidates, &mut seen_fp, cand);
            }
        }

        // 3b. Extract all database / auth connection URIs
        for uri in find_connection_uris(&block.body) {
            if let Ok(parsed) = smart_ingest::smart_parse(&uri, None, None)
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
                && let Ok(parsed) = smart_ingest::smart_parse(l, None, None)
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
        let env_vars = smart_ingest::parse_env_vars(&block.body);
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

    // If nothing at all was extracted, try single-item smart_parse (e.g. plain login URL)
    // without forcing arbitrary chat prose into a junk secure note unless it looks useful.
    if candidates.is_empty() && ignored.is_empty() {
        if let Ok(parsed) = smart_ingest::smart_parse(text, filename, None)
            && parsed.kind != "secureNote"
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

fn extract_pem_blocks(
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
            smart_ingest::smart_parse(m.as_str(), heading.as_deref().or(filename), None)
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

fn extract_curl_blocks(
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
            if let Ok(parsed) = smart_ingest::smart_parse(&block, None, None)
                && parsed.kind == "curl"
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

struct ContextBlock {
    heading: Option<String>,
    body: String,
}

fn slice_context_blocks(text: &str) -> Vec<ContextBlock> {
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

fn detect_explicit_heading(line: &str) -> Option<String> {
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

fn is_field_label_word(lower: &str) -> bool {
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

fn extract_trailing_heading(prefix: &str) -> Option<String> {
    prefix
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .and_then(clean_heading_line)
}

fn clean_heading_line(line: &str) -> Option<String> {
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

fn find_totp_uris(text: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"otpauth://[^\s<>"'`]+"#).unwrap());
    re.find_iter(text)
        .map(|m| m.as_str().trim_end_matches([',', '.', ';', ')', ']']).to_owned())
        .collect()
}

fn find_connection_uris(text: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)://[^\s<>"'`]+"#).unwrap()
    });
    re.find_iter(text)
        .map(|m| m.as_str().trim_end_matches([',', '.', ';', ')', ']']).to_owned())
        .collect()
}

fn looks_like_connection_uri(value: &str) -> bool {
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

fn extract_labeled_block(
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
                // Support "1.2.3.4:2222" inside host value
                if let Some((h, p)) = split_host_port(&v) {
                    map.entry("host").or_insert(h);
                    map.entry("port").or_insert(p);
                } else {
                    map.entry("host").or_insert(v);
                }
            } else if matches!(k.as_str(), "port" | "ssh port" | "端口" | "端口号") {
                map.entry("port").or_insert(v);
            } else if matches!(
                k.as_str(),
                "user" | "username" | "account" | "login" | "email" | "phone" | "账号" | "帐号" | "用户名" | "登录名" | "邮箱" | "手机号"
            ) {
                map.entry("username").or_insert(v);
            } else if matches!(
                k.as_str(),
                "pass" | "password" | "pwd" | "passwd" | "密码" | "登录密码" | "初始密码" | "口令"
            ) {
                map.entry("password").or_insert(v);
            } else if matches!(
                k.as_str(),
                "url" | "website" | "site" | "endpoint" | "base url" | "baseurl" | "link" | "网址" | "链接" | "后台" | "后台地址" | "登录地址" | "接口地址"
            ) {
                map.entry("url").or_insert(v);
            } else if matches!(
                k.as_str(),
                "api key" | "apikey" | "api_key" | "token" | "access token" | "secret" | "key" | "密钥" | "令牌"
            ) {
                map.entry("apiCredential").or_insert(v);
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

fn split_labeled_segments(line: &str) -> Vec<String> {
    // Split lines that contain multiple Chinese/English field labels like "账号：root  密码：123456"
    // without using look-around (unsupported in Rust `regex`).
    static LABEL_RE: OnceLock<Regex> = OnceLock::new();
    let re = LABEL_RE.get_or_init(|| {
        Regex::new(r"(?i)(?:^|\s+)(?:ip|host|port|user|username|account|email|pass|password|pwd|url|token|apikey|主机|服务器|地址|端口|账号|帐号|用户名|邮箱|密码|网址|链接|密钥)\s*[:：]")
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

fn split_label_value(seg: &str) -> Option<(&str, &str)> {
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
    None
}

fn split_host_port(raw: &str) -> Option<(String, String)> {
    let (h, p) = raw.rsplit_once(':')?;
    if !h.is_empty() && !h.contains("://") && p.parse::<u16>().is_ok() {
        return Some((h.trim().to_owned(), p.trim().to_owned()));
    }
    None
}

fn extract_inline_patterns(
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

fn extract_bare_tokens(
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

fn has_high_confidence_token_prefix(value: &str) -> bool {
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

fn is_placeholder_value(val: &str) -> bool {
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
            | "sk-xxx"
            | "sk-..."
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
    {
        return true;
    }
    // Masked bullets/asterisks like "sk-••••1234" or "********"
    if trimmed.chars().all(|c| c == '*' || c == '•' || c == 'x' || c == 'X') && trimmed.len() >= 3 {
        return true;
    }
    false
}

fn is_explicit_non_secret_key(key: &str) -> bool {
    let base = key.split('[').next().unwrap_or(key).trim();
    let upper = base.to_ascii_uppercase();
    if upper.starts_with("NEXT_PUBLIC_")
        || upper.starts_with("VITE_")
        || upper.starts_with("PUBLIC_")
        || upper.starts_with("REACT_APP_PUBLIC_")
    {
        return true;
    }
    matches!(
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
            | "VERSION"
            | "REGION"
            | "AWS_REGION"
            | "AWS_DEFAULT_REGION"
            | "TIMEOUT"
            | "MAX_RETRIES"
            | "WORKERS"
            | "THREADS"
    )
}

fn is_obvious_non_secret_value(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "true" | "false" | "yes" | "no" | "on" | "off" | "0" | "1" | "development" | "production" | "staging" | "info" | "debug" | "warn" | "error" | "localhost" | "127.0.0.1" | "0.0.0.0"
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
    // Pure short integer (e.g. ports, timeouts)
    if value.len() <= 6 && value.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    false
}

fn key_secret_score(key: &str) -> u8 {
    let upper = key.to_ascii_uppercase();
    let strong = [
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "PWD",
        "TOKEN",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "ACCESSKEY",
        "SECRETKEY",
        "PRIVATE_KEY",
        "PRIVKEY",
        "CREDENTIAL",
        "AUTH_KEY",
        "SIGNING",
        "ENCRYPTION",
        "MASTER_KEY",
        "WEBHOOK",
        "COOKIE",
        "SESSION_KEY",
        "DSN",
        "BEARER",
        "JWT",
        "CLIENT_SECRET",
    ];
    if strong.iter().any(|w| upper.contains(w)) {
        return 2;
    }
    let medium = ["KEY", "AUTH", "PASS", "CERT", "PEM", "SALT", "PEPPER", "OTP", "TOTP"];
    if medium.iter().any(|w| upper.contains(w)) {
        return 1;
    }
    0
}

fn shannon_entropy(s: &str) -> f64 {
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

fn reconcile_with_vault(candidates: &mut [ExtractedCandidate], existing: &[DecryptedConnection]) {
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

fn compare_candidate_with_existing(
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

fn module_val<'a>(modules: &'a [ItemModule], kind: &str) -> Option<&'a str> {
    modules
        .iter()
        .find(|m| m.kind == kind && !m.value.trim().is_empty())
        .map(|m| m.value.trim())
}

fn candidate_dedup_key(cand: &ExtractedCandidate) -> String {
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

fn push_unique(
    candidates: &mut Vec<ExtractedCandidate>,
    seen: &mut HashSet<String>,
    cand: ExtractedCandidate,
) {
    let key = candidate_dedup_key(&cand);
    if key.is_empty() || seen.insert(key) {
        candidates.push(cand);
    }
}

fn candidate_from_smart_parse(
    mut parsed: smart_ingest::SmartParseResult,
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

fn candidate_from_portable(
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

fn classify_portable_kind(p: &PortableConnection) -> (&'static str, &'static str, &'static str) {
    match p.item_type.as_str() {
        "api" => ("apiKey", "API", "API"),
        "ssh" => ("ssh", "SSH", "SSH"),
        "login" => ("login", "LOGIN", "账号"),
        "secureNote" => ("custom", "NOTE", "笔记"),
        _ => ("custom", "ITEM", "凭据"),
    }
}

fn build_api_candidate(
    name: &str,
    token: &str,
    profile: api_catalog::ApiProfile,
    base_url: Option<String>,
    source: &str,
    confidence: &str,
) -> ExtractedCandidate {
    let mut input = blank_input("api", name);
    let resolved_url = base_url.or_else(|| {
        (!profile.default_base_url.is_empty()).then(|| profile.default_base_url.to_owned())
    });
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

fn build_login_candidate(
    name: &str,
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    source: &str,
    confidence: &str,
) -> ExtractedCandidate {
    let mut input = blank_input("login", name);
    if let Some(ref u) = url {
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
    let summary = match (&url, &username) {
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

fn build_ssh_candidate(
    name: &str,
    host: &str,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    source: &str,
) -> ExtractedCandidate {
    let mut input = blank_input("ssh", name);
    input.modules.push(public_mod("host", "host", host));
    input
        .modules
        .push(public_mod("port", "port", &port.to_string()));
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
        Some(u) => format!("{u}@{host}:{port}"),
        None => format!("{host}:{port}"),
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

fn build_env_group_candidate(
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
        let key_name = sanitize_name(k, 64);
        if !input.modules.iter().any(|m| m.name == key_name) {
            input.modules.push(secret_mod("customSecret", &key_name));
        }
        input.secrets.named_secrets.insert(key_name, v.clone());
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

fn build_single_env_candidate(key: &str, value: &str, source: &str) -> ExtractedCandidate {
    let mut input = blank_input("custom", key);
    input.folder = "Env".to_owned();
    let key_name = sanitize_name(key, 64);
    input.modules.push(secret_mod("customSecret", &key_name));
    input
        .secrets
        .named_secrets
        .insert(key_name, value.to_owned());
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
fn make_candidate(
    kind: &str,
    badge: &str,
    badge_zh: &str,
    confidence: &str,
    summary: String,
    source_snippet: String,
    input: ConnectionInput,
    totp_uri: Option<String>,
) -> ExtractedCandidate {
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
    }
}

fn build_field_previews(input: &ConnectionInput) -> Vec<ExtractedFieldPreview> {
    let mut fields = Vec::new();
    for m in &input.modules {
        let is_secret = !m.agent_visible.unwrap_or(false)
            || matches!(
                m.kind.as_str(),
                "password" | "apiCredential" | "privateKey" | "totp" | "customSecret" | "username"
            );
        if is_secret {
            let val = if m.kind == "password" {
                input.secrets.password.clone().unwrap_or_default()
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
            fields.push(ExtractedFieldPreview {
                label: friendly_field_label(&m.name, &m.kind),
                masked: if is_username {
                    val.clone()
                } else {
                    mask_preview(&val)
                },
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

fn friendly_field_label(name: &str, kind: &str) -> String {
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

fn blank_input(item_type: &str, name: &str) -> ConnectionInput {
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

fn public_mod(kind: &str, name: &str, value: &str) -> ItemModule {
    ItemModule {
        kind: kind.to_owned(),
        name: name.to_owned(),
        value: value.to_owned(),
        agent_visible: Some(true),
    }
}

fn secret_mod(kind: &str, name: &str) -> ItemModule {
    ItemModule {
        kind: kind.to_owned(),
        name: name.to_owned(),
        value: String::new(),
        agent_visible: Some(false),
    }
}

fn sanitize_name(raw: &str, max_chars: usize) -> String {
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

fn pretty_key_title(key: &str) -> String {
    let cleaned = key.replace(['_', '.', '/'], " ");
    sanitize_name(&cleaned, 60)
}

fn host_from_url(raw: &str) -> Option<String> {
    let candidate = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    Url::parse(&candidate)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
}

fn compact_url(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_owned()
}

fn mask_preview(raw: &str) -> String {
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

fn mask_uri(raw: &str) -> String {
    if let Ok(mut url) = Url::parse(raw) {
        if url.password().is_some() {
            let _ = url.set_password(Some("••••"));
        }
        return url.to_string();
    }
    mask_preview(raw)
}

fn truncate_chars(raw: &str, max: usize) -> String {
    let count = raw.chars().count();
    if count <= max {
        raw.to_owned()
    } else {
        let mut s: String = raw.chars().take(max.saturating_sub(1)).collect();
        s.push('…');
        s
    }
}

fn strip_inline_quotes(raw: &str) -> String {
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

const MAX_OFFICE_ENTRY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ZIP_ENTRIES: usize = 30;
const MAX_ZIP_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FOLDER_DEPTH: usize = 2;
const MAX_FOLDER_FILES: usize = 40;
const MAX_NOTE_FALLBACK_CHARS: usize = 64 * 1024;

fn unescape_xml_entities(input: &str) -> String {
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

fn try_extract_keepass_xml(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
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

fn looks_like_password_tsv(text: &str) -> bool {
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

fn try_extract_password_tsv(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
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

    if idx_pass.is_none() && idx_key.is_none() && idx_user.is_none() {
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

        if url.is_empty() && host.is_empty() && user.is_empty() && pass.is_empty() && key.is_empty() {
            continue;
        }
        // API key row
        if !key.is_empty() && pass.is_empty() && host.is_empty() {
            let name = if !raw_name.is_empty() {
                raw_name
            } else {
                host_from_url(&url).unwrap_or_else(|| "API Credential".to_owned())
            };
            let profile = api_catalog::infer(&name, &url, &key);
            candidates.push(build_api_candidate(
                &name,
                &key,
                profile,
                (!url.is_empty()).then_some(url),
                source,
                "high",
            ));
            continue;
        }
        // SSH / Server row
        if !host.is_empty() && !host.starts_with("http://") && !host.starts_with("https://") {
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
                (!pass.is_empty()).then_some(pass),
                source,
            ));
            continue;
        }
        // Login row
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
            (!pass.is_empty()).then_some(pass),
            (!totp.is_empty()).then_some(totp),
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

fn try_extract_netrc(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
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

fn try_extract_npmrc(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
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

fn try_extract_pgpass(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
    let lower = filename.unwrap_or_default().to_ascii_lowercase();
    if !lower.ends_with("pgpass") {
        return None;
    }
    let mut candidates = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(5, ':').collect();
        if parts.len() != 5 || parts[4].is_empty() {
            continue;
        }
        let (host, port, db, user, pass) = (parts[0], parts[1], parts[2], parts[3], parts[4]);
        let name = format!("PostgreSQL · {host}/{db}");
        let mut input = blank_input("custom", &name);
        input.folder = "Database".to_owned();
        input.modules.push(public_mod("host", "host", host));
        if !port.is_empty() && port != "*" {
            input.modules.push(public_mod("port", "port", port));
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

fn try_extract_pypirc(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
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

fn build_secure_note_candidate(filename: &str, text: &str) -> ExtractedCandidate {
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
    input.modules.push(secret_mod("customSecret", "note"));
    input
        .secrets
        .named_secrets
        .insert("note".to_owned(), clipped);
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

fn read_zip_entry_bounded<R: Read>(mut entry: R, limit: u64) -> Result<Vec<u8>> {
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

fn excel_col_index(cell_ref: &str) -> Option<usize> {
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

fn image_mime_for_ext(ext: &str) -> Option<&'static str> {
    match ext {
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "webp" => Some("image/webp"),
        "gif" => Some("image/gif"),
        "bmp" => Some("image/bmp"),
        _ => None,
    }
}

fn should_skip_walk_dir(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        ".git" | "node_modules" | "target" | "dist" | "build" | ".venv" | "__pycache__" | ".idea" | ".vscode"
    )
}

fn should_skip_binary_ext(ext: &str) -> bool {
    matches!(
        ext,
        "exe" | "dll" | "so" | "dylib" | "bin" | "pdb" | "o" | "obj" | "rlib" | "a" | "lib"
            | "mp4" | "mov" | "avi" | "mkv" | "mp3" | "wav" | "flac" | "iso" | "dmg" | "msi"
            | "woff" | "woff2" | "ttf" | "otf" | "ico" | "icns" | "class" | "pyc" | "wasm"
    )
}

fn collect_walk_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
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
        if path.is_dir() {
            if !should_skip_walk_dir(name) && depth < MAX_FOLDER_DEPTH {
                collect_walk_files(&path, depth + 1, out);
            }
            continue;
        }
        if path.is_file() {
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
    ensure!(
        bytes.len() <= MAX_BATCH_TEXT_BYTES,
        "{filename} exceeds 16 MiB limit"
    );
    let lower = filename.to_ascii_lowercase();

    if lower.ends_with(".docx") {
        let text = extract_docx_text(bytes)?;
        ensure!(!text.trim().is_empty(), "{filename} contains no readable text");
        let mut res = extract_batch(&text, Some(filename), existing)?;
        if res.candidates.is_empty() && res.ignored.is_empty() {
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
        if res.candidates.is_empty() && res.ignored.is_empty() {
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
            if let Ok(part) = extract_from_bytes(&entry_bytes, &display_name, existing)
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
    if res.candidates.is_empty() && res.ignored.is_empty() {
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
    let mut expanded_files: Vec<PathBuf> = Vec::new();
    for path in paths {
        if path.is_dir() {
            collect_walk_files(path, 0, &mut expanded_files);
        } else if path.is_file() {
            expanded_files.push(path.clone());
        }
    }

    let mut mvault_paths = Vec::new();
    let mut images = Vec::new();
    let mut parts = Vec::new();
    let mut warnings = Vec::new();
    let mut source_files = Vec::new();

    for path in expanded_files {
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
            warnings.push(format!("{fname}: unable to read file metadata"));
            continue;
        };
        if meta.len() > MAX_BATCH_TEXT_BYTES as u64 {
            warnings.push(format!("{fname} exceeds 16 MiB and was skipped"));
            continue;
        }

        if let Some(mime) = image_mime_for_ext(&ext) {
            if let Ok(bytes) = std::fs::read(&path) {
                images.push(DroppedImagePayload {
                    file_name: fname.clone(),
                    mime_type: mime.to_owned(),
                    data_base64: BASE64_STANDARD.encode(&bytes),
                });
                source_files.push(fname);
            }
            continue;
        }

        let Ok(bytes) = std::fs::read(&path) else {
            warnings.push(format!("{fname}: unable to read file"));
            continue;
        };
        match extract_from_bytes(&bytes, &fname, existing) {
            Ok(part) => {
                source_files.push(fname);
                parts.push(part);
            }
            Err(error) => warnings.push(format!("{fname}: {error}")),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;

    #[test]
    fn extracts_multiple_heterogeneous_credentials_from_messy_chat_log() {
        let chat = r#"
hi 交接一下上线要用到的几个配置，别发群里了：

【生产服务器】
主机：198.51.100.22
端口：2222
账号：deploy
密码：Pr0d!Server#99

### 生产数据库
postgres://pgadmin:DbS3cr3tPass!@db.prod.internal:5432/orders

后台管理：
网址：https://admin.example.com/login
账号：ops@example.com
密码：AdminP@ss2026

AI Key 顺便也给你：
sk-ant-api03-live-demo-key-1234567890abcdef
还有 GitHub token：ghp_1234567890abcdefghij1234567890ab

2FA 备用：otpauth://totp/GitHub:ops?secret=JBSWY3DPEHPK3PXP&issuer=GitHub
"#;

        let res = extract_batch(chat, None, &[]).unwrap();
        assert_eq!(res.detected_format, "mixed_text");
        assert!(
            res.candidates.len() >= 6,
            "expected at least 6 candidates, got {}: {:?}",
            res.candidates.len(),
            res.candidates.iter().map(|c| (&c.kind, &c.input.name)).collect::<Vec<_>>()
        );

        assert!(res.candidates.iter().any(|c| c.kind == "ssh" && c.input.name == "生产服务器"));
        assert!(res.candidates.iter().any(|c| c.kind == "database" && c.input.name == "生产数据库"));
        assert!(res.candidates.iter().any(|c| c.kind == "login" && c.input.secrets.get("username") == Some("ops@example.com")));
        assert!(res.candidates.iter().any(|c| c.kind == "apiKey" && c.input.name.contains("Anthropic")));
        assert!(res.candidates.iter().any(|c| c.kind == "apiKey" && c.input.name.contains("GitHub")));
        assert!(res.candidates.iter().any(|c| c.kind == "totp"));
    }

    #[test]
    fn filters_env_noise_and_placeholders_while_promoting_api_and_db() {
        let env_text = r#"
NODE_ENV=production
PORT=3000
DEBUG=false
NEXT_PUBLIC_SITE_URL=https://openkeylet.dev
OPENAI_API_KEY=sk-proj-real-production-token-1234567890
DATABASE_URL=postgres://app:SuperSecret99@db.local:5432/app
STRIPE_SECRET_KEY=your-api-key-here
WEBHOOK_SIGNING_SECRET=whsec_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d
"#;
        let res = extract_batch(env_text, Some(".env.production"), &[]).unwrap();
        assert_eq!(res.detected_format, "env");
        assert!(res.sealed_env_template.is_some());

        // Promoted: OpenAI API, Postgres DB, and 1 grouped Env secret (WEBHOOK_SIGNING_SECRET)
        assert!(res.candidates.iter().any(|c| c.kind == "apiKey" && c.input.name.contains("OpenAI")));
        assert!(res.candidates.iter().any(|c| c.kind == "database"));
        assert!(res.candidates.iter().any(|c| c.kind == "env" && c.input.secrets.get("WEBHOOK_SIGNING_SECRET").is_some()));

        // Noise & placeholder filtered into ignored (each recoverable!)
        assert!(res.ignored.iter().any(|i| i.key == "PORT" && i.reason == "non_secret"));
        assert!(res.ignored.iter().any(|i| i.key == "NODE_ENV" && i.reason == "non_secret"));
        assert!(res.ignored.iter().any(|i| i.key == "STRIPE_SECRET_KEY" && i.reason == "placeholder" && i.candidate.is_some()));
    }

    #[test]
    fn detects_duplicates_and_updates_against_existing_vault() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path().to_path_buf()).unwrap();
        let mut existing_login = blank_input("login", "Example Admin");
        existing_login.modules.push(public_mod("url", "url", "https://admin.example.com"));
        existing_login.login_uris.push(LoginUri {
            uri: "https://admin.example.com".to_owned(),
            match_type: "domain".to_owned(),
        });
        existing_login.modules.push(secret_mod("username", "username"));
        existing_login
            .secrets
            .named_secrets
            .insert("username".to_owned(), "alice@example.com".to_owned());
        existing_login.modules.push(secret_mod("password", "password"));
        existing_login.secrets.password = Some("OldPass!123".to_owned());
        let saved = vault.save_connection(existing_login).unwrap();

        let existing = vault.list_decrypted_connections().unwrap();

        // Exact duplicate -> unchecked
        let dup_res = extract_batch(
            "https://admin.example.com  alice@example.com  OldPass!123",
            None,
            &existing,
        )
        .unwrap();
        assert_eq!(dup_res.candidates.len(), 1);
        assert_eq!(dup_res.candidates[0].match_status, "duplicate");
        assert!(!dup_res.candidates[0].selected);
        assert_eq!(
            dup_res.candidates[0].existing_item_id.as_deref(),
            Some(saved.id.to_string().as_str())
        );

        // Changed password -> marked as update & update_existing = true
        let upd_res = extract_batch(
            "https://admin.example.com  alice@example.com  NewPass!456",
            None,
            &existing,
        )
        .unwrap();
        assert_eq!(upd_res.candidates.len(), 1);
        assert_eq!(upd_res.candidates[0].match_status, "update");
        assert!(upd_res.candidates[0].selected);
        assert!(upd_res.candidates[0].update_existing);
    }

    #[test]
    fn parses_aws_credentials_and_json_config() {
        let aws = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion = us-east-1\n";
        let res = extract_batch(aws, Some("credentials"), &[]).unwrap();
        assert_eq!(res.detected_format, "aws_credentials");
        assert_eq!(res.candidates.len(), 1);
        assert_eq!(res.candidates[0].badge, "AWS");

        let json = r#"{
            "mcpServers": {
                "anthropic": { "env": { "ANTHROPIC_API_KEY": "sk-ant-api03-json-extracted-key-987654" } }
            },
            "port": "8080"
        }"#;
        let json_res = extract_batch(json, Some("mcp.json"), &[]).unwrap();
        assert_eq!(json_res.detected_format, "json_config");
        assert!(json_res.candidates.iter().any(|c| c.kind == "apiKey" && c.input.name.contains("Anthropic")));
        assert!(json_res.ignored.iter().any(|i| i.key == "port"));
    }

    #[test]
    fn captures_unlabeled_url_inside_chinese_chat_login_line() {
        let line = "测试后台 https://test.foo.com 账号：admin 密码：Test1234!";
        let res = extract_batch(line, None, &[]).unwrap();
        assert_eq!(res.candidates.len(), 1);
        let c = &res.candidates[0];
        assert_eq!(c.kind, "login");
        assert_eq!(c.input.name, "测试后台");
        assert_eq!(c.input.secrets.get("username"), Some("admin"));
        assert_eq!(c.input.secrets.get("password"), Some("Test1234!"));
        assert!(c.input.login_uris.iter().any(|u| u.uri == "https://test.foo.com"));
    }

    fn make_zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (name, data) in entries {
                writer.start_file(*name, opts).unwrap();
                writer.write_all(data).unwrap();
            }
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    #[test]
    fn extracts_keepass_xml_netrc_npmrc_pgpass_and_pypirc() {
        let kp_xml = r#"<?xml version="1.0" encoding="utf-8"?>
        <KeePassFile><Root><Group>
          <Entry>
            <String><Key>Title</Key><Value>GitHub Prod</Value></String>
            <String><Key>UserName</Key><Value>ops@example.com</Value></String>
            <String><Key>Password</Key><Value>Kp&amp;Secret#9</Value></String>
            <String><Key>URL</Key><Value>https://github.com</Value></String>
            <History><Entry><String><Key>Password</Key><Value>OldPass</Value></String></Entry></History>
          </Entry>
        </Group></Root></KeePassFile>"#;
        let kp = extract_batch(kp_xml, Some("vault.xml"), &[]).unwrap();
        assert_eq!(kp.detected_format, "keepass_xml");
        assert_eq!(kp.candidates.len(), 1);
        assert_eq!(kp.candidates[0].input.secrets.get("password"), Some("Kp&Secret#9"));

        let netrc = "machine api.github.com login octocat password ghp_netrcSecretToken123456\n";
        let nr = extract_batch(netrc, Some(".netrc"), &[]).unwrap();
        assert_eq!(nr.detected_format, "netrc");
        assert_eq!(nr.candidates.len(), 1);
        assert_eq!(nr.candidates[0].input.secrets.get("username"), Some("octocat"));

        let npmrc = "//registry.npmjs.org/:_authToken=npm_RealTokenValue987654321\n";
        let npm = extract_batch(npmrc, Some(".npmrc"), &[]).unwrap();
        assert_eq!(npm.detected_format, "npmrc");
        assert_eq!(npm.candidates.len(), 1);

        let pgpass = "db.internal:5432:prod:pgadmin:PgS3cret!99\n";
        let pg = extract_batch(pgpass, Some(".pgpass"), &[]).unwrap();
        assert_eq!(pg.detected_format, "pgpass");
        assert_eq!(pg.candidates.len(), 1);
        assert_eq!(pg.candidates[0].kind, "database");

        let pypirc = "[pypi]\nrepository = https://upload.pypi.org/legacy/\nusername = __token__\npassword = pypi-AgEIcHlwaS5vcmcsecret123456\n";
        let pp = extract_batch(pypirc, Some(".pypirc"), &[]).unwrap();
        assert_eq!(pp.detected_format, "pypirc");
        assert_eq!(pp.candidates.len(), 1);
    }

    #[test]
    fn extracts_xlsx_docx_zip_and_falls_back_to_secure_note_for_arbitrary_files() {
        let shared = r#"<?xml version="1.0" encoding="UTF-8"?>
        <sst>
          <si><t>名称</t></si>
          <si><t>主机</t></si>
          <si><t>端口</t></si>
          <si><t>账号</t></si>
          <si><t>密码</t></si>
          <si><t>生产跳板机</t></si>
          <si><t>10.10.0.5</t></si>
          <si><t>root</t></si>
          <si><t>XlsxS3cret!88</t></si>
        </sst>"#
            .as_bytes();
        let sheet = br#"<?xml version="1.0" encoding="UTF-8"?>
        <worksheet><sheetData>
          <row r="1">
            <c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c><c r="D1" t="s"><v>3</v></c><c r="E1" t="s"><v>4</v></c>
          </row>
          <row r="2">
            <c r="A2" t="s"><v>5</v></c><c r="B2" t="s"><v>6</v></c><c r="C2"><v>2222</v></c><c r="D2" t="s"><v>7</v></c><c r="E2" t="s"><v>8</v></c>
          </row>
        </sheetData></worksheet>"#;
        let xlsx_bytes = make_zip_bytes(&[
            ("xl/sharedStrings.xml", shared),
            ("xl/worksheets/sheet1.xml", sheet),
        ]);
        let xlsx_res = extract_from_bytes(&xlsx_bytes, "servers.xlsx", &[]).unwrap();
        assert_eq!(xlsx_res.detected_format, "xlsx_table");
        assert_eq!(xlsx_res.candidates.len(), 1);
        assert_eq!(xlsx_res.candidates[0].kind, "ssh");
        assert_eq!(xlsx_res.candidates[0].input.name, "生产跳板机");
        assert_eq!(xlsx_res.candidates[0].input.secrets.get("password"), Some("XlsxS3cret!88"));

        let docx_xml = br#"<?xml version="1.0" encoding="UTF-8"?>
        <w:document><w:body>
          <w:p><w:r><w:t>OpenAI Key: sk-proj-docxExtractedKey1234567890abcdef</w:t></w:r></w:p>
        </w:body></w:document>"#;
        let docx_bytes = make_zip_bytes(&[("word/document.xml", docx_xml)]);
        let docx_res = extract_from_bytes(&docx_bytes, "handover.docx", &[]).unwrap();
        assert_eq!(docx_res.candidates.len(), 1);
        assert_eq!(docx_res.candidates[0].kind, "apiKey");

        let zip_bytes = make_zip_bytes(&[
            (
                "project/.env",
                concat!("STRIPE_SECRET_KEY=", "sk_", "live_", "ZipExtractedKey1234567890abcd\n")
                    .as_bytes(),
            ),
            ("project/node_modules/ignored.env", b"SHOULD_SKIP=123\n"),
        ]);
        let zip_res = extract_from_bytes(&zip_bytes, "bundle.zip", &[]).unwrap();
        assert_eq!(zip_res.candidates.len(), 1);

        // Arbitrary plain note file without secret regex -> falls back to editable Secure Note candidate
        let note_res = extract_from_bytes(
            b"Backup recovery instructions:\n1. Call IT desk ext 4401\n2. Safe combo box #3\n",
            "recovery-memo.txt",
            &[],
        )
        .unwrap();
        assert_eq!(note_res.detected_format, "text_note");
        assert_eq!(note_res.candidates.len(), 1);
        assert_eq!(note_res.candidates[0].input.item_type, "secureNote");
        assert_eq!(note_res.candidates[0].input.name, "recovery-memo");
    }

    #[test]
    fn extract_from_paths_walks_folders_separates_mvault_and_images() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("project-bundle");
        std::fs::create_dir_all(folder.join(".git")).unwrap();
        std::fs::write(folder.join(".env"), "OPENAI_API_KEY=sk-proj-folderTestKey1234567890abcd\n").unwrap();
        std::fs::write(folder.join(".git").join("config"), "secret=should_not_scan\n").unwrap();
        std::fs::write(folder.join("backup.mvault"), "{}").unwrap();
        std::fs::write(folder.join("qr.png"), [0x89, b'P', b'N', b'G']).unwrap();

        let outcome = extract_from_paths(&[folder], &[]);
        assert_eq!(outcome.mvault_paths.len(), 1);
        assert_eq!(outcome.images.len(), 1);
        assert_eq!(outcome.images[0].mime_type, "image/png");
        assert_eq!(outcome.batch.candidates.len(), 1);
        assert_eq!(outcome.batch.candidates[0].kind, "apiKey");
    }

    #[test]
    fn one_click_local_search_finds_home_dotfiles_and_suspected_user_files() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let desktop = dir.path().join("Desktop");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::create_dir_all(&desktop).unwrap();

        std::fs::write(
            home.join(".ssh").join("config"),
            "Host prod-box\n  HostName 10.0.0.12\n  User ubuntu\n  Port 2222\n",
        )
        .unwrap();
        std::fs::write(
            home.join(".git-credentials"),
            "https://alice:ghp_gitCredSecretToken1234567890@github.com\n",
        )
        .unwrap();
        std::fs::write(
            desktop.join("公司密码本.txt"),
            "测试后台 https://portal.example.com 账号：admin 密码：DeskPass!99\n",
        )
        .unwrap();
        // Unrelated file without credential keywords should NOT be scanned or added as note
        std::fs::write(desktop.join("shopping-list.txt"), "milk, bread, apples\n").unwrap();
        std::fs::write(
            desktop.join("v2rayN-custom-non-cn-proxy-vpn.json"),
            r#"{"routing":{"rules":[{"domain":["domain:example.com","full:api.service.example.com"]}]}}"#,
        )
        .unwrap();
        std::fs::write(desktop.join("openkeylet-backup.mvault"), "{}").unwrap();

        let outcome = scan_local_credential_roots(
            Some(&home),
            &[("Desktop", desktop)],
            &[],
        )
        .unwrap();
        let res = outcome.batch;
        assert_eq!(res.detected_format, "local_search");
        assert!(res.candidates.iter().any(|c| c.kind == "ssh"));
        assert!(res.candidates.iter().any(|c| c.input.name.contains("github.com")));
        assert!(res.candidates.iter().any(|c| c.input.secrets.get("password") == Some("DeskPass!99")));
        assert!(!res.candidates.iter().any(|c| c.input.name.contains("shopping")));
        assert!(!res.candidates.iter().any(|c| c.input.name.contains("v2rayN")));
        assert_eq!(outcome.discovered_mvaults.len(), 1);
        assert_eq!(outcome.discovered_mvaults[0].file_name, "openkeylet-backup.mvault");
        assert_eq!(outcome.discovered_mvaults[0].display_path, "Desktop/openkeylet-backup.mvault");
        assert_eq!(outcome.report.mode, "quick_pc");
        assert_eq!(outcome.report.categories.len(), 4);
    }

    #[test]
    fn local_scan_finds_standalone_ssh_keys_ai_mcp_jsonc_docker_and_cloud_csv() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let downloads = dir.path().join("Downloads");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::create_dir_all(home.join(".cursor")).unwrap();
        std::fs::create_dir_all(home.join(".config").join("opencode")).unwrap();
        std::fs::create_dir_all(home.join(".docker")).unwrap();
        std::fs::create_dir_all(&downloads).unwrap();

        let bound_pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----\n";
        let standalone_pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nc3RhbmRhbG9uZS1zc2gta2V5LXYx\n-----END OPENSSH PRIVATE KEY-----\n";
        std::fs::write(home.join(".ssh").join("id_bound"), bound_pem).unwrap();
        std::fs::write(home.join(".ssh").join("id_deploy"), standalone_pem).unwrap();
        std::fs::write(home.join(".ssh").join("id_deploy.pub"), "ssh-ed25519 AAAA...").unwrap();
        std::fs::write(
            home.join(".ssh").join("config"),
            format!(
                "Host bound-host\n  HostName 10.0.1.9\n  User deploy\n  IdentityFile {}\n",
                home.join(".ssh").join("id_bound").display()
            ),
        )
        .unwrap();

        // AI MCP config with plaintext token + OpenKeylet placeholder (placeholder must be ignored)
        std::fs::write(
            home.join(".cursor").join("mcp.json"),
            r#"{
                "mcpServers": {
                    "github": {
                        "command": "npx",
                        "env": {
                            "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_cursorMcpExtractedToken1234567890",
                            "SEALED_KEY": "{{openkeylet:SEALED}}"
                        }
                    }
                }
            }"#,
        )
        .unwrap();

        // JSONC config with // comments and trailing commas
        std::fs::write(
            home.join(".config").join("opencode").join("opencode.jsonc"),
            "// OpenCode user config\n{\n  \"provider\": {\n    \"anthropic\": {\n      \"apiKey\": \"sk-ant-api03-jsoncCommentExtractedKey9876543210\",\n    },\n  },\n}\n",
        )
        .unwrap();

        // Docker config.json base64 auth
        let docker_b64 = BASE64_STANDARD.encode("ops_user:dckr_pat_DockerSecret987654");
        std::fs::write(
            home.join(".docker").join("config.json"),
            format!(r#"{{"auths":{{"https://index.docker.io/v1/":{{"auth":"{docker_b64}"}}}}}}"#),
        )
        .unwrap();

        // AWS IAM accessKeys.csv in Downloads subfolder (depth 2)
        let sub_dl = downloads.join("aws-iam");
        std::fs::create_dir_all(&sub_dl).unwrap();
        std::fs::write(
            sub_dl.join("deploy_accessKeys.csv"),
            "Access key ID,Secret access key\nAKIAIOSFODNN7REALKEY,wJalrXUtnFEMI/K7MDENG/bPxRfiCYREALKEY99\n",
        )
        .unwrap();

        let outcome = scan_local_credential_roots(
            Some(&home),
            &[("Downloads", downloads)],
            &[],
        )
        .unwrap();
        let cands = &outcome.batch.candidates;

        // bound-host is extracted once as SSH; standalone id_deploy is extracted as KEY; id_bound is NOT duplicated
        assert!(cands.iter().any(|c| c.kind == "ssh" && c.input.name == "bound-host"));
        assert!(cands.iter().any(|c| c.kind == "privateKey" && c.input.name.contains("id_deploy")));
        assert!(!cands.iter().any(|c| c.kind == "privateKey" && c.input.name.contains("id_bound")));

        // Cursor MCP & OpenCode JSONC tokens extracted
        assert!(cands.iter().any(|c| c.input.secrets.get("apiCredential") == Some("ghp_cursorMcpExtractedToken1234567890")));
        assert!(cands.iter().any(|c| c.input.secrets.get("apiCredential") == Some("sk-ant-api03-jsoncCommentExtractedKey9876543210")));

        // Docker Hub login decoded
        assert!(cands.iter().any(|c| c.input.name.contains("Docker") && c.input.secrets.get("password") == Some("dckr_pat_DockerSecret987654")));

        // AWS CSV extracted
        assert!(cands.iter().any(|c| c.kind == "aws" && c.input.secrets.get("AWS_ACCESS_KEY_ID") == Some("AKIAIOSFODNN7REALKEY")));

        // Verify category telemetry
        let ai_stat = outcome.report.categories.iter().find(|c| c.id == "ai_mcp").unwrap();
        assert_eq!(ai_stat.matched_files, 2);
        assert_eq!(ai_stat.extracted_count, 2);
    }

    #[test]
    fn workspace_directory_deep_scan_extracts_multi_repo_envs_and_skips_templates() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("Github");
        std::fs::create_dir_all(ws.join("app-alpha")).unwrap();
        std::fs::create_dir_all(ws.join("app-beta").join("packages").join("web")).unwrap();
        std::fs::create_dir_all(ws.join("app-alpha").join("node_modules").join("pkg")).unwrap();

        std::fs::write(
            ws.join("app-alpha").join(".env"),
            "OPENAI_API_KEY=sk-proj-alphaWorkspaceKey1234567890abcd\nCUSTOM_SIGNING_SECRET=alpha_super_secret_signing_998877\n",
        )
        .unwrap();
        std::fs::write(
            ws.join("app-alpha").join(".env.example"),
            "OPENAI_API_KEY=sk-proj-shouldSkipTemplateKey1234567890\n",
        )
        .unwrap();
        std::fs::write(
            ws.join("app-alpha").join("node_modules").join("pkg").join(".env"),
            "OPENAI_API_KEY=sk-proj-shouldSkipNodeModules1234567890\n",
        )
        .unwrap();
        std::fs::write(
            ws.join("app-beta").join("packages").join("web").join(".env.local"),
            "OPENAI_API_KEY=sk-proj-betaWorkspaceKey9876543210zyxw\nCUSTOM_SIGNING_SECRET=beta_different_secret_signing_112233\n",
        )
        .unwrap();
        // Plain README should NEVER become a secure note in workspace scan
        std::fs::write(ws.join("app-alpha").join("README.md"), "# App Alpha\nHello world\n").unwrap();

        let outcome = scan_workspace_directory(&ws, &[]).unwrap();
        assert_eq!(outcome.report.mode, "workspace_folder");
        let cands = &outcome.batch.candidates;

        // Both OpenAI keys and both distinct .env groups kept & disambiguated; .env.example & node_modules & README skipped
        assert_eq!(cands.len(), 4, "got candidates: {:?}", cands.iter().map(|c| &c.input.name).collect::<Vec<_>>());
        assert!(cands.iter().any(|c| c.input.name.contains("app-alpha")));
        assert!(cands.iter().any(|c| c.input.name.contains("web")));
        assert!(!cands.iter().any(|c| c.input.secrets.get("apiCredential") == Some("sk-proj-shouldSkipTemplateKey1234567890")));
        assert!(!cands.iter().any(|c| c.input.item_type == "secureNote"));
    }
}
