use super::*;

pub(super) fn is_openkeylet_command(command: &str) -> bool {
    let file_name = command
        .trim()
        .trim_matches(['\'', '"'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command);
    Path::new(file_name)
        .file_stem()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.eq_ignore_ascii_case("openkeylet") || name.eq_ignore_ascii_case("kru")
        })
}

pub(super) fn same_path(left: &Path, right: &Path) -> bool {
    let left = normalize_path(left);
    let right = normalize_path(right);
    if cfg!(windows) {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    } else {
        left == right
    }
}

pub(super) fn normalize_path(path: impl AsRef<Path>) -> PathBuf {
    fs::canonicalize(path.as_ref()).unwrap_or_else(|_| path.as_ref().to_path_buf())
}

pub(super) fn is_runnable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    true
}

pub(super) fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

pub(super) fn resolve_codex_home(home: &Path, configured: Option<PathBuf>) -> PathBuf {
    configured
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| home.join(".codex"))
}

pub(super) fn resolve_claude_config(home: &Path, configured: Option<PathBuf>) -> (PathBuf, PathBuf) {
    if let Some(directory) = configured.filter(|path| !path.as_os_str().is_empty()) {
        (directory.join(".claude.json"), directory)
    } else {
        (home.join(".claude.json"), home.join(".claude"))
    }
}

pub(super) fn resolve_opencode_config(
    home: &Path,
    configured_file: Option<PathBuf>,
    configured_directory: Option<PathBuf>,
    xdg_config_home: Option<PathBuf>,
) -> (PathBuf, bool) {
    if let Some(path) = configured_file.filter(|path| !path.as_os_str().is_empty()) {
        return (path, true);
    }
    if let Some(directory) = configured_directory.filter(|path| !path.as_os_str().is_empty()) {
        return (preferred_json_config(&directory), true);
    }
    let base = xdg_config_home
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| home.join(".config"));
    (preferred_json_config(&base.join("opencode")), false)
}

pub(super) fn preferred_json_config(directory: &Path) -> PathBuf {
    let jsonc = directory.join("opencode.jsonc");
    if jsonc.is_file() {
        return jsonc;
    }
    let json = directory.join("opencode.json");
    if json.is_file() { json } else { jsonc }
}

pub(super) fn resolve_antigravity_config_dir(home: &Path, configured: Option<PathBuf>) -> PathBuf {
    configured
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| home.join(".gemini").join("config"))
}

pub(super) fn resolve_dsh_home(home: &Path, configured: Option<PathBuf>) -> PathBuf {
    if let Some(path) = configured.filter(|path| !path.as_os_str().is_empty()) {
        return path;
    }
    let default = home.join(".dsh");
    if default.exists() {
        return default;
    }
    let myenv_projects = home.join("Documents").join("myenv").join("projects");
    if let Ok(entries) = fs::read_dir(&myenv_projects) {
        let mut homes: Vec<PathBuf> = entries
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .starts_with("dsh-")
            })
            .map(|entry| entry.path().join("home"))
            .filter(|candidate| candidate.join("profiles").is_dir())
            .collect();
        homes.sort();
        if let Some(found) = homes.into_iter().next() {
            return found;
        }
    }
    default
}

pub(super) fn toml_array_strings(array: &Array) -> Vec<String> {
    array
        .iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect()
}

pub(super) fn json_array_strings(value: Option<&JsonValue>) -> Vec<String> {
    value
        .and_then(JsonValue::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(JsonValue::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn read_or(path: &Path, fallback: &str) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(value),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(fallback.to_owned()),
        Err(error) => Err(error).with_context(|| format!("Unable to read {}", path.display())),
    }
}

pub(super) fn has_legacy_instruction(text: &str) -> bool {
    text.contains(LEGACY_INSTRUCTION_START) || text.contains(LEGACY_INSTRUCTION_END)
}

pub(super) fn has_managed_instruction(text: &str) -> bool {
    text.contains(OPENKEYLET_INSTRUCTION_START) || text.contains(LEGACY_INSTRUCTION_START)
}

pub(super) fn upsert_managed_instruction(path: &Path, dedicated_file: bool) -> Result<()> {
    let original = read_or(path, "")?;
    if dedicated_file && !original.trim().is_empty() && !has_managed_instruction(&original) {
        bail!(
            "{} Already exists and is not an OpenKeylet managed rule; not overwritten",
            path.display()
        );
    }
    let mut updated = strip_managed_instruction(&original)?
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    if !updated.is_empty() {
        updated.push_str("\n\n");
    }
    updated.push_str(OPENKEYLET_INSTRUCTION_BLOCK);
    updated.push('\n');
    write_atomic_checked(path, &original, &updated)
}

pub(super) fn remove_managed_instruction(path: &Path, dedicated_file: bool) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }
    let original = fs::read_to_string(path)
        .with_context(|| format!("Unable to read Agent global rules {}", path.display()))?;
    if !has_managed_instruction(&original) && !has_legacy_instruction(&original) {
        return Ok(());
    }
    let updated = strip_managed_instruction(&original)?;
    if dedicated_file && updated.trim().is_empty() {
        fs::remove_file(path).with_context(|| {
            format!("Unable to remove OpenKeylet global rule {}", path.display())
        })?;
        return Ok(());
    }
    write_atomic_checked(path, &original, &updated)
}

pub(super) fn strip_managed_instruction(text: &str) -> Result<String> {
    let text = strip_instruction_block(text, LEGACY_INSTRUCTION_START, LEGACY_INSTRUCTION_END)?;
    strip_instruction_block(
        &text,
        OPENKEYLET_INSTRUCTION_START,
        OPENKEYLET_INSTRUCTION_END,
    )
}

pub(super) fn strip_instruction_block(text: &str, start_marker: &str, end_marker: &str) -> Result<String> {
    let Some(start) = text.find(start_marker) else {
        if text.contains(end_marker) {
            bail!("OpenKeylet managed marker in Agent global rules is incomplete");
        }
        return Ok(text.to_owned());
    };
    let content_start = start + start_marker.len();
    let end_offset = text[content_start..]
        .find(end_marker)
        .context("OpenKeylet managed marker in Agent global rules is incomplete")?;
    let end = content_start + end_offset + end_marker.len();
    let mut before = text[..start].trim_end_matches(['\r', '\n']).to_owned();
    let after = text[end..].trim_start_matches(['\r', '\n']);
    if !before.is_empty() && !after.is_empty() {
        before.push_str("\n\n");
    }
    before.push_str(after);
    if !before.is_empty() && text.ends_with('\n') && !before.ends_with('\n') {
        before.push('\n');
    }
    Ok(before)
}

pub(super) fn write_atomic_checked(path: &Path, expected: &str, value: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("Unable to create Agent configuration directory")?;
    }
    let current = read_or(path, expected)?;
    if current != expected {
        bail!("Agent configuration changed during modification; rescan and try again");
    }
    let mut writer = AtomicWriteFile::open(path)
        .context("Unable to create temporary Agent configuration file")?;
    writer
        .write_all(value.as_bytes())
        .context("Unable to write Agent configuration")?;
    writer
        .commit()
        .context("Unable to save Agent configuration atomically")?;
    Ok(())
}

/// A copy of an agent config taken before "Repair" rewrites it. Agent configs such as
/// `~/.claude.json` hold tokens, so a forgotten copy is one more plaintext file for
/// anything that searches the disk. The copy is deleted on drop: after the new config was
/// written and read back intact, and also on every error before that point, because the
/// atomic write leaves the original file in place. Only a failed read-back keeps it.
pub(super) struct ConfigBackup {
    path: Option<PathBuf>,
}

impl ConfigBackup {
    pub(super) fn none() -> Self {
        Self { path: None }
    }

    /// Writes `value` over `expected` (see [`write_atomic_checked`]) and verifies it.
    pub(super) fn write_verified(self, path: &Path, expected: &str, value: &str) -> Result<()> {
        write_atomic_checked(path, expected, value)?;
        self.finish(path, value)
    }

    /// Reads `path` back: deletes the backup when it holds `value`, keeps it otherwise.
    pub(super) fn finish(mut self, path: &Path, value: &str) -> Result<()> {
        if fs::read_to_string(path).is_ok_and(|written| written == value) {
            return Ok(());
        }
        match self.path.take() {
            Some(backup) => bail!(
                "Agent configuration {} could not be verified after writing; the previous version is kept at {}",
                path.display(),
                backup.display()
            ),
            None => bail!(
                "Agent configuration {} could not be verified after writing",
                path.display()
            ),
        }
    }
}

impl Drop for ConfigBackup {
    fn drop(&mut self) {
        if let Some(backup) = self.path.take() {
            let _ = fs::remove_file(backup);
        }
    }
}

pub(super) fn backup_config(path: &Path) -> Result<ConfigBackup> {
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config");
    let backup = path.with_file_name(format!("{file_name}.openkeylet.{stamp}.bak"));
    fs::copy(path, &backup).context("Unable to back up conflicting configuration")?;
    Ok(ConfigBackup { path: Some(backup) })
}

pub(super) fn display_name(client_id: &str) -> &str {
    match client_id {
        "codex" => "Codex",
        "claude-code" => "Claude Code",
        "cursor" => "Cursor",
        "opencode" => "OpenCode",
        "antigravity" => "Antigravity",
        "deepseek-harness" => "DeepSeek Harness",
        _ => "Unknown Agent",
    }
}

pub(super) fn action_label(action: &str) -> &str {
    match action {
        "register" => "Connect",
        "repair" => "Repair",
        "remove" => "Remove",
        _ => "Actions",
    }
}

#[cfg(target_os = "macos")]
pub(super) fn app_translocated(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case("AppTranslocation")
    })
}

#[cfg(not(target_os = "macos"))]
pub(super) fn app_translocated(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod backup_tests {
    use super::*;

    fn backups_in(dir: &Path) -> Vec<PathBuf> {
        fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.to_string_lossy().ends_with(".bak"))
            .collect()
    }

    #[test]
    fn repair_backup_is_removed_after_the_new_config_reads_back() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(".claude.json");
        fs::write(&path, "{\"token\":\"old\"}\n").unwrap();
        let backup = backup_config(&path).unwrap();
        assert_eq!(backups_in(temp.path()).len(), 1);
        backup
            .write_verified(&path, "{\"token\":\"old\"}\n", "{\"token\":\"new\"}\n")
            .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"token\":\"new\"}\n");
        assert!(backups_in(temp.path()).is_empty());
    }

    #[test]
    fn repair_backup_is_removed_when_the_write_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        fs::write(&path, "changed by someone else\n").unwrap();
        let backup = backup_config(&path).unwrap();
        // The atomic write refuses and leaves the original in place, so the copy is useless.
        assert!(backup.write_verified(&path, "what we read earlier\n", "new\n").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "changed by someone else\n");
        assert!(backups_in(temp.path()).is_empty());
    }

    #[test]
    fn repair_backup_is_kept_when_verification_fails() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("mcp.json");
        fs::write(&path, "{}\n").unwrap();
        let backup = backup_config(&path).unwrap();
        let error = backup.finish(&path, "{\"expected\":true}\n").unwrap_err().to_string();
        let kept = backups_in(temp.path());
        assert_eq!(kept.len(), 1);
        assert!(error.contains(&kept[0].display().to_string()), "{error}");
    }
}

