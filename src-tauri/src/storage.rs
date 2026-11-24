use anyhow::{Context, Result, bail};
use std::{env, ffi::OsString, path::PathBuf};

pub const DATA_DIR_OVERRIDE_ENV: &str = "OPENKEYLET_DATA_DIR";
const LEGACY_DATA_DIR_OVERRIDE_ENV: &str = "KRU_DATA_DIR";

pub fn app_data_dir() -> Result<PathBuf> {
    resolve_data_dir(
        env::var_os(DATA_DIR_OVERRIDE_ENV).or_else(|| env::var_os(LEGACY_DATA_DIR_OVERRIDE_ENV)),
        default_app_data_dir(),
    )
}

pub fn default_app_data_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|path| path.join("mcp-vault").join("v2"))
}

pub fn uses_explicit_data_dir(data_dir: &std::path::Path) -> bool {
    if env::var_os(DATA_DIR_OVERRIDE_ENV).is_some()
        || env::var_os(LEGACY_DATA_DIR_OVERRIDE_ENV).is_some()
    {
        return true;
    }
    default_app_data_dir().is_some_and(|default_dir| default_dir != data_dir)
}

pub fn resolve_user_path(value: &str) -> Result<PathBuf> {
    let current_dir =
        env::current_dir().context("Unable to determine the current working directory")?;
    let home_dir = dirs::home_dir();
    resolve_user_path_from(value, &current_dir, home_dir.as_deref())
}

fn resolve_user_path_from(
    value: &str,
    current_dir: &std::path::Path,
    home_dir: Option<&std::path::Path>,
) -> Result<PathBuf> {
    let value = value.trim();
    if value.is_empty() || value.contains('\0') {
        bail!("Invalid local path");
    }
    let path = if value == "~" {
        home_dir
            .context("Unable to determine the user home directory")?
            .to_path_buf()
    } else if let Some(relative) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    {
        home_dir
            .context("Unable to determine the user home directory")?
            .join(relative)
    } else {
        PathBuf::from(value)
    };
    Ok(if path.is_absolute() {
        path
    } else {
        current_dir.join(path)
    })
}

fn resolve_data_dir(
    override_path: Option<OsString>,
    default_path: Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(path) = override_path {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            bail!("{DATA_DIR_OVERRIDE_ENV} must be an absolute path");
        }
        return Ok(path);
    }
    default_path.context("Unable to determine the local data directory")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_data_directory_must_be_absolute_and_wins_over_the_default() {
        let absolute = if cfg!(windows) {
            PathBuf::from(r"C:\openkeylet-isolated-vault")
        } else {
            PathBuf::from("/tmp/openkeylet-isolated-vault")
        };
        let overridden = resolve_data_dir(
            Some(absolute.clone().into_os_string()),
            Some(PathBuf::from("/default")),
        )
        .unwrap();
        assert_eq!(overridden, absolute);
        assert!(
            resolve_data_dir(
                Some(OsString::from("relative/vault")),
                Some(PathBuf::from("/default"))
            )
            .is_err()
        );
        assert_eq!(
            resolve_data_dir(None, Some(PathBuf::from("/default"))).unwrap(),
            PathBuf::from("/default")
        );
    }

    #[test]
    fn user_paths_accept_workspace_relative_and_home_relative_forms() {
        let (current, home) = if cfg!(windows) {
            (
                PathBuf::from(r"C:\workspace"),
                PathBuf::from(r"C:\Users\tester"),
            )
        } else {
            (PathBuf::from("/workspace"), PathBuf::from("/home/tester"))
        };
        assert_eq!(
            resolve_user_path_from("artifacts/output.bin", &current, Some(&home)).unwrap(),
            current.join("artifacts/output.bin")
        );
        assert_eq!(
            resolve_user_path_from("~/downloads/output.bin", &current, Some(&home)).unwrap(),
            home.join("downloads/output.bin")
        );
        assert!(resolve_user_path_from("", &current, Some(&home)).is_err());
    }
}
