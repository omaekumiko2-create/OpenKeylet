use super::*;

pub(super) const LOCAL_SCAN_MAX_DEPTH: usize = 3;
pub(super) const LOCAL_SCAN_MAX_VISITED_PER_ROOT: usize = 2500;
pub(super) const LOCAL_SCAN_MAX_MATCHED_FILES: usize = 120;
pub(super) const LOCAL_SCAN_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

pub(super) const WORKSPACE_SCAN_MAX_DEPTH: usize = 5;
pub(super) const WORKSPACE_SCAN_MAX_VISITED: usize = 20_000;
pub(super) const WORKSPACE_SCAN_MAX_MATCHED: usize = 250;

pub(super) fn should_skip_local_scan_dir(name: &str) -> bool {
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
                | "docs"
                | "doc"
                | "documentation"
                | "examples"
                | "samples"
                | "fixtures"
                | "tests"
                | "test"
                | "__tests__"
                | "specs"
                | "templates"
                | ".cargo"
                | ".rustup"
                | ".npm"
                | ".cache"
        )
}

pub(super) fn should_skip_workspace_scan_dir(name: &str) -> bool {
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
                | "docs"
                | "doc"
                | "documentation"
                | "samples"
                | "specs"
                | "templates"
        )
}

pub(super) fn is_symlink_path(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .ok()
        .is_some_and(|m| m.file_type().is_symlink())
}

pub(super) fn is_env_template_filename(lower: &str) -> bool {
    if [
        ".example",
        ".sample",
        ".template",
        ".dist",
        ".schema",
        ".defaults",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
    {
        return true;
    }
    if lower != ".env" && (lower.starts_with(".env.") || lower.ends_with(".env") || lower.contains(".env.")) {
        return lower
            .split(['.', '-', '_'])
            .any(|seg| matches!(seg, "example" | "sample" | "template" | "dist" | "schema" | "defaults" | "mock" | "dummy"));
    }
    false
}

pub(super) fn is_non_secret_ssh_artifact(lower: &str) -> bool {
    lower.ends_with(".pub")
        || lower.ends_with(".bak")
        || lower.ends_with(".old")
        || lower.starts_with("known_hosts")
        || lower.starts_with("authorized_keys")
}

pub(super) fn is_suspected_credential_filename(file_name: &str) -> bool {
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
    const STRICT_KEYWORDS: &[&str] = &[
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
        "vault",
        "bitwarden",
        "1password",
        "keepass",
        "lastpass",
        "nordpass",
        "dashlane",
        "enpass",
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
    if STRICT_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        return true;
    }
    // Broader export/handover keywords only match tabular/document exports (avoid matching API docs/specs in .json/.yaml/.md)
    if matches!(ext, "csv" | "tsv" | "xlsx" | "docx" | "txt") {
        const DOC_EXPORT_KEYWORDS: &[&str] = &[
            "account",
            "login",
            "chrome",
            "edge",
            "server",
            "ssh",
            "vps",
            "database",
            "db_",
            "db-",
        ];
        return DOC_EXPORT_KEYWORDS.iter().any(|kw| lower.contains(kw));
    }
    false
}

pub(super) fn classify_workspace_credential_file(file_name: &str, in_test_dir: bool) -> Option<&'static str> {
    let lower = file_name.to_ascii_lowercase();
    if in_test_dir || is_non_secret_ssh_artifact(&lower) || is_env_template_filename(&lower) {
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
        return Some("ssh_keys");
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

pub(super) fn try_extract_git_credentials(text: &str, filename: Option<&str>) -> Option<SmartExtractBatchResult> {
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

/// Remembers which file every candidate of `part` came from, including filtered entries
/// the user may restore, so an import can report what is still on disk afterwards.
pub(super) fn record_source_path(part: &mut SmartExtractBatchResult, path: &Path) {
    let candidates = part
        .candidates
        .iter_mut()
        .chain(part.ignored.iter_mut().filter_map(|item| item.candidate.as_mut()));
    for cand in candidates {
        if !cand.source_paths.iter().any(|known| known == path) {
            cand.source_paths.push(path.to_path_buf());
        }
    }
}

/// Agent instruction and rule files. The names mirror the global rule files that
/// `agents.rs` maintains per client, plus the per-project files those clients read.
pub(super) fn is_agent_rules_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "claude.md"
            | "claude.local.md"
            | "agents.md"
            | "agents.override.md"
            | "gemini.md"
            | ".cursorrules"
            | ".windsurfrules"
            | ".clinerules"
            | "copilot-instructions.md"
    ) {
        return true;
    }
    let ext = Path::new(&name).extension().and_then(|e| e.to_str()).unwrap_or_default();
    if ext == "mdc" {
        return true;
    }
    let mut ancestors = path.ancestors().skip(1).filter_map(|p| p.file_name()?.to_str());
    ext == "md"
        && ancestors.next().is_some_and(|dir| dir.eq_ignore_ascii_case("rules"))
        && ancestors.next().is_some_and(|dir| {
            matches!(dir.to_ascii_lowercase().as_str(), ".claude" | ".cursor" | ".codex" | ".windsurf")
        })
}

const SHELL_STARTUP_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    "config.fish",
    "microsoft.powershell_profile.ps1",
];

const SHELL_HISTORY_FILES: &[&str] = &[
    ".bash_history",
    ".zsh_history",
    ".zhistory",
    ".sh_history",
    "fish_history",
    "consolehost_history.txt",
];

pub(super) fn precise_source_for_path(path: &Path) -> Option<PreciseSource> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    if SHELL_HISTORY_FILES.contains(&name.as_str()) {
        Some(PreciseSource::ShellHistory)
    } else if SHELL_STARTUP_FILES.contains(&name.as_str()) {
        Some(PreciseSource::ShellStartup)
    } else if is_agent_rules_path(path) {
        Some(PreciseSource::AgentRules)
    } else {
        None
    }
}

pub(super) fn extract_suspected_file_strict(
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
        record_source_path(&mut git_res, path);
        reconcile_with_vault(&mut git_res.candidates, existing);
        return Some(git_res);
    }
    let mut res = if let Some(source) = precise_source_for_path(path) {
        let mut res = extract_precise_secrets(trimmed, Some(display_label), source);
        res.candidates.truncate(MAX_BATCH_CANDIDATES);
        reconcile_with_vault(&mut res.candidates, existing);
        res
    } else {
        extract_batch(trimmed, Some(display_label), existing).ok()?
    };
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
    record_source_path(&mut res, path);
    Some(res)
}

/// The kind of file that still holds plaintext, which decides the advice the user gets.
pub fn plaintext_source_kind(path: &Path) -> &'static str {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let parent = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let in_dir = |dirs: &[&str]| {
        path.ancestors()
            .skip(1)
            .take(4)
            .filter_map(|p| p.file_name()?.to_str())
            .any(|dir| dirs.contains(&dir.to_ascii_lowercase().as_str()))
    };
    let ext = Path::new(&name).extension().and_then(|e| e.to_str()).unwrap_or_default();
    if name.contains(".openkeylet.") && name.ends_with(".bak") {
        return "backup";
    }
    if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") || name == ".envrc" {
        return "env";
    }
    if precise_source_for_path(path).is_some_and(|source| source != PreciseSource::AgentRules) {
        return "shell";
    }
    if is_agent_rules_path(path)
        || matches!(
            name.as_str(),
            ".claude.json" | "claude_desktop_config.json" | "mcp.json" | ".mcp.json" | "mcp_config.json"
                | "opencode.json" | "opencode.jsonc"
        )
        || in_dir(&[".claude", ".codex", ".cursor", ".gemini", ".continue", "opencode", ".codeium", "windsurf"])
    {
        return "agent";
    }
    if matches!(ext, "pem" | "key" | "ppk")
        || (name.starts_with("id_") && !name.ends_with(".pub") && ext.is_empty())
    {
        return "key";
    }
    if matches!(
        name.as_str(),
        ".git-credentials" | ".netrc" | "_netrc" | ".npmrc" | ".yarnrc.yml" | ".pypirc" | ".pgpass"
            | "pgpass.conf" | "rclone.conf" | "kubeconfig" | "hosts.yml" | "credentials"
            | "default.credential"
    ) || (name == "config.json" && matches!(parent.as_str(), ".docker" | ".aliyun"))
        || (name == "config" && parent == ".kube")
        || (name == "auth.json" && parent == ".composer")
        || (name == "config.yml" && parent == "glab-cli")
    {
        return "tool";
    }
    "document"
}

/// `~/…` for files under `home`, so the list stays readable at 460 px.
pub(super) fn display_source_path(path: &Path, home: Option<&Path>) -> String {
    if let Some(home) = home
        && let Ok(rel) = path.strip_prefix(home)
    {
        return format!("~/{}", rel.to_string_lossy().replace('\\', "/"));
    }
    path.to_string_lossy().into_owned()
}

/// A private key file protected by a passphrase is not plaintext on disk.
pub(super) fn private_key_file_is_protected(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if meta.len() > 256 * 1024 {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    if let Some(rest) = text.strip_prefix("PuTTY-User-Key-File-") {
        return rest
            .lines()
            .find_map(|line| line.strip_prefix("Encryption:"))
            .is_some_and(|cipher| cipher.trim() != "none");
    }
    if !text.contains("PRIVATE KEY-----") {
        return false;
    }
    if text.contains("ENCRYPTED") {
        return true;
    }
    // OpenSSH keys hide the cipher inside the base64 body: "openssh-key-v1\0", then a
    // length-prefixed cipher name that is "none" for an unprotected key.
    let body: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect();
    let Ok(decoded) = BASE64_STANDARD.decode(body.as_bytes()) else {
        return false;
    };
    let Some(rest) = decoded.strip_prefix(b"openssh-key-v1\0".as_slice()) else {
        return false;
    };
    let Some(len) = rest.get(..4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize) else {
        return false;
    };
    rest.get(4..4 + len).is_some_and(|cipher| cipher != b"none")
}

/// Files that still hold the plaintext of credentials that were just imported: deduplicated,
/// sorted, and limited to files that still exist and are not passphrase-protected keys.
pub fn plaintext_sources(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PlaintextSource> {
    plaintext_sources_with_home(paths, dirs::home_dir().as_deref())
}

pub(crate) fn plaintext_sources_with_home(
    paths: impl IntoIterator<Item = PathBuf>,
    home: Option<&Path>,
) -> Vec<PlaintextSource> {
    let mut seen = HashSet::new();
    let mut sources = Vec::new();
    for path in paths {
        if !seen.insert(path.clone()) || !path.is_file() {
            continue;
        }
        if private_key_file_is_protected(&path) {
            continue;
        }
        sources.push(PlaintextSource {
            display_path: display_source_path(&path, home),
            kind: plaintext_source_kind(&path).to_owned(),
        });
    }
    sources.sort_by(|a, b| a.display_path.cmp(&b.display_path));
    sources
}

/// Lists up to `limit` files in `dir` that `keep` accepts, sorted for stable reports.
fn list_dir_files(dir: &Path, limit: usize, keep: impl Fn(&Path) -> bool) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && !is_symlink_path(path) && keep(path))
        .collect();
    files.sort();
    files.truncate(limit);
    files
}

const RULE_FILES_PER_DIR: usize = 32;
const REPAIR_BACKUPS_PER_CONFIG: usize = 8;

pub(super) fn collect_suspected_files_in_dir(
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
        if is_symlink_path(&path) {
            continue;
        }
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
        if is_suspected_credential_filename(name) || precise_source_for_path(&path).is_some() {
            matched.push((path, label));
        }
    }
}

pub(super) fn short_source_context(source_snippet: &str) -> Option<String> {
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

pub(super) fn disambiguate_multi_source_names(candidates: &mut [ExtractedCandidate]) {
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

pub(super) fn scan_ssh_home_dir(
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
                if let Ok((entries, _, key_files)) =
                    ingest::parse_ssh_config_bytes_with_key_files(&bytes, cfg_path.parent())
                    && !entries.is_empty()
                {
                    let mut candidates = Vec::new();
                    for ((p, s), key_file) in entries.into_iter().zip(key_files) {
                        if let Some(pk) = s.get("privateKey") {
                            bound_pems.insert(pk.trim().to_owned());
                        }
                        let mut cand = candidate_from_portable(p, s, "ssh", "SSH", "SSH", &label);
                        // The config only names the key; the key file holds the secret.
                        cand.source_paths.extend(key_file);
                        candidates.push(cand);
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
pub(super) fn scan_fixed_config_group(
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
        // Older "Repair" runs left full copies of these configs next to them.
        let mut repair_backups = Vec::new();
        for (label, path) in &ai_targets {
            let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str()))
            else {
                continue;
            };
            let prefix = format!("{name}.openkeylet.");
            for backup in list_dir_files(dir, REPAIR_BACKUPS_PER_CONFIG, |candidate| {
                candidate
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(".bak"))
            }) {
                let file_name = backup.file_name().and_then(|n| n.to_str()).unwrap_or_default();
                let dir_label = label.rsplit_once('/').map_or("", |(dir, _)| dir);
                let backup_label = if dir_label.is_empty() {
                    file_name.to_owned()
                } else {
                    format!("{dir_label}/{file_name}")
                };
                repair_backups.push((backup_label, backup));
            }
        }
        ai_targets.extend(repair_backups);
        // Global agent instruction and rule files, at the default locations `agents.rs`
        // writes its managed rules to. Users paste keys into these for the agent to use.
        let claude_dir = home_dir.join(".claude");
        let codex_dir = home_dir.join(".codex");
        let cursor_dir = home_dir.join(".cursor");
        let gemini_dir = home_dir.join(".gemini");
        ai_targets.extend([
            ("~/.claude/CLAUDE.md".to_owned(), claude_dir.join("CLAUDE.md")),
            ("~/.codex/AGENTS.md".to_owned(), codex_dir.join("AGENTS.md")),
            ("~/.codex/AGENTS.override.md".to_owned(), codex_dir.join("AGENTS.override.md")),
            ("~/.gemini/GEMINI.md".to_owned(), gemini_dir.join("GEMINI.md")),
            ("~/.gemini/config/GEMINI.md".to_owned(), gemini_dir.join("config").join("GEMINI.md")),
            (
                "~/.config/opencode/AGENTS.md".to_owned(),
                home_dir.join(".config").join("opencode").join("AGENTS.md"),
            ),
            ("~/.dsh/AGENTS.md".to_owned(), home_dir.join(".dsh").join("AGENTS.md")),
            ("~/.cursorrules".to_owned(), home_dir.join(".cursorrules")),
        ]);
        for (label, dir) in [
            ("~/.claude/rules", claude_dir.join("rules")),
            ("~/.codex/rules", codex_dir.join("rules")),
            ("~/.cursor/rules", cursor_dir.join("rules")),
        ] {
            for rule in list_dir_files(&dir, RULE_FILES_PER_DIR, is_agent_rules_path) {
                let name = rule.file_name().and_then(|n| n.to_str()).unwrap_or_default();
                ai_targets.push((format!("{label}/{name}"), rule));
            }
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

        // 4. Shell startup files (`export NAME=value`) and shell history (keys typed or
        // pasted on the command line).
        let fish_dir = home_dir.join(".config").join("fish");
        let mut shell_targets: Vec<(String, PathBuf)> = [
            ".bashrc",
            ".bash_profile",
            ".bash_login",
            ".profile",
            ".zshrc",
            ".zshenv",
            ".zprofile",
            ".zlogin",
            ".bash_history",
            ".zsh_history",
            ".zhistory",
            ".sh_history",
        ]
        .into_iter()
        .map(|name| (format!("~/{name}"), home_dir.join(name)))
        .collect();
        shell_targets.extend([
            ("~/.config/fish/config.fish".to_owned(), fish_dir.join("config.fish")),
            (
                "~/.local/share/fish/fish_history".to_owned(),
                home_dir.join(".local").join("share").join("fish").join("fish_history"),
            ),
            (
                "~/Documents/PowerShell/Microsoft.PowerShell_profile.ps1".to_owned(),
                home_dir
                    .join("Documents")
                    .join("PowerShell")
                    .join("Microsoft.PowerShell_profile.ps1"),
            ),
            (
                "~/Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1".to_owned(),
                home_dir
                    .join("Documents")
                    .join("WindowsPowerShell")
                    .join("Microsoft.PowerShell_profile.ps1"),
            ),
        ]);
        if let Some(cfg) = os_config_dir {
            shell_targets.push((
                "AppData/PowerShell/PSReadLine/ConsoleHost_history.txt".to_owned(),
                cfg.join("Microsoft")
                    .join("Windows")
                    .join("PowerShell")
                    .join("PSReadLine")
                    .join("ConsoleHost_history.txt"),
            ));
        }
        categories.push(scan_fixed_config_group(
            "shell",
            "Shell rc & History",
            "Shell 配置与历史",
            &shell_targets,
            &mut seen_paths,
            &mut parts,
            existing,
        ));
    }

    // 5. User Desktop / Documents / Downloads (up to depth 3)
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
    reconcile_with_vault(&mut merged.candidates, existing);

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

#[allow(clippy::too_many_arguments)]
pub(super) fn collect_workspace_files_in_dir(
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
        if is_symlink_path(&path) {
            continue;
        }
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
            if !in_test_dir && mvault_found.len() < 16 {
                mvault_found.push((path, label));
            }
            continue;
        }
        let category = classify_workspace_credential_file(name, in_test_dir).or_else(|| {
            // Agent rule files and dotfile copies sit next to the code they describe.
            (!in_test_dir && precise_source_for_path(&path).is_some()).then_some("project_configs")
        });
        if let Some(cat_id) = category {
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
    reconcile_with_vault(&mut merged.candidates, existing);

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

