use super::*;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChromeProfile {
    pub(super) directory: String,
    pub(super) name: String,
    pub(super) account: String,
    pub(super) is_last_used: bool,
}

pub(super) fn is_valid_chrome_profile_dir(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > 128
        || trimmed != value
        || trimmed.starts_with('-')
        || trimmed.eq_ignore_ascii_case("System Profile")
        || trimmed.eq_ignore_ascii_case("Guest Profile")
        || trimmed.chars().any(|ch| ch.is_control() || matches!(ch, '/' | '\\'))
    {
        return false;
    }
    let mut components = Path::new(trimmed).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

pub(super) fn chrome_user_data_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(|root| PathBuf::from(root).join("Google/Chrome/User Data"))
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(|home| PathBuf::from(home).join("Library/Application Support/Google/Chrome"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(|config| PathBuf::from(config).join("google-chrome"))
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|home| PathBuf::from(home).join(".config/google-chrome"))
            })
    }
}

pub(super) fn parse_chrome_profiles_from_local_state(
    user_data_dir: &Path,
    raw: &str,
) -> Vec<ChromeProfile> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    let last_used = json
        .pointer("/profile/last_used")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let Some(cache) = json
        .pointer("/profile/info_cache")
        .and_then(|value| value.as_object())
    else {
        return Vec::new();
    };
    let mut profiles = Vec::new();
    for (directory, entry) in cache {
        if !is_valid_chrome_profile_dir(directory) || !user_data_dir.join(directory).is_dir() {
            continue;
        }
        let str_field = |key: &str| {
            entry
                .get(key)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .unwrap_or("")
        };
        let name = [
            str_field("name"),
            str_field("shortcut_name"),
            str_field("gaia_name"),
            directory.as_str(),
        ]
        .into_iter()
        .find(|v| !v.is_empty())
        .unwrap_or(directory.as_str())
        .to_owned();
        let account = str_field("user_name").to_owned();
        profiles.push(ChromeProfile {
            directory: directory.clone(),
            name,
            account,
            is_last_used: directory == last_used,
        });
    }
    profiles.sort_by(|a, b| {
        b.is_last_used
            .cmp(&a.is_last_used)
            .then_with(|| (b.directory == "Default").cmp(&(a.directory == "Default")))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.directory.cmp(&b.directory))
    });
    profiles
}

#[tauri::command]
pub(crate) fn list_chrome_profiles() -> Vec<ChromeProfile> {
    let Some(user_data_dir) = chrome_user_data_dir() else {
        return Vec::new();
    };
    let Ok(raw) = std::fs::read_to_string(user_data_dir.join("Local State")) else {
        return Vec::new();
    };
    parse_chrome_profiles_from_local_state(&user_data_dir, &raw)
}

