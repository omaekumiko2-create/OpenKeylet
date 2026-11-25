use crate::model::{Settings, SettingsPatch};
#[cfg(target_os = "macos")]
use crate::platform::macos_app_bundle;
use crate::vault::Vault;
use anyhow::{Context, Result, anyhow, bail};
use atomic_write_file::AtomicWriteFile;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use reqwest::redirect::Policy;
use ring::signature::{ED25519, UnparsedPublicKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Write},
    path::{Component, Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use url::Url;

mod archive;
mod install;
mod manifest;

pub use install::apply_staged_package;
pub use manifest::{is_newer_version, verify_signed_manifest};
use archive::*;
use manifest::*;

pub const DEFAULT_MANIFEST_URL: &str =
    "https://github.com/omaekumiko2-create/OpenKeylet/releases/latest/download/latest.json";
pub const DEFAULT_RELEASES_URL: &str =
    "https://github.com/omaekumiko2-create/OpenKeylet/releases/latest";
pub const MANIFEST_ENVELOPE_FORMAT: &str = "openkeylet-update-v1";

const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 200 * 1024 * 1024;
const MAX_EXTRACTED_FILES: usize = 500;
const MAX_EXTRACTED_BYTES: u64 = 400 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;

const ALLOWED_GITHUB_HOSTS: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "github-releases.githubusercontent.com",
];

// Official CI builds inject OPENKEYLET_UPDATE_PUBLIC_KEY at compile time by
// deriving the 32-byte Ed25519 public key from secrets.OPENKEYLET_UPDATE_SIGNING_KEY.
// Fallback embeds the official omaekumiko2-create/OpenKeylet Ed25519 public key so
// local builds can also verify official GitHub Releases.
const FALLBACK_UPDATE_PUBLIC_KEY_B64: &str = "uCBOtL43FyR7FSOGo9eo+MzKfxX7oSb+ZWQb7oGcrfM=";
const COMPILED_UPDATE_PUBLIC_KEY_B64: Option<&str> = option_env!("OPENKEYLET_UPDATE_PUBLIC_KEY");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedManifestEnvelope {
    pub format: String,
    #[serde(default)]
    pub key_id: String,
    pub payload: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseManifest {
    pub schema_version: u8,
    pub version: String,
    pub tag: String,
    #[serde(default)]
    pub published_at: String,
    pub release_url: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub platforms: BTreeMap<String, PlatformAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformAsset {
    pub url: String,
    pub sha256: String,
    pub size: u64,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingUpdateMarker {
    pub version: String,
    pub tag: String,
    pub platform: String,
    pub archive_sha256: String,
    pub staged_root: PathBuf,
    pub signature_verified: bool,
    pub prepared_at: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub release_url: String,
    #[serde(default)]
    pub published_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatus {
    pub phase: String,
    pub current_version: String,
    pub platform: String,
    pub latest_version: Option<String>,
    pub tag: Option<String>,
    pub published_at: Option<String>,
    pub release_url: String,
    pub notes: String,
    pub asset_size: Option<u64>,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub signature_verified: bool,
    pub signing_key_configured: bool,
    pub can_auto_install: bool,
    pub install_blocked_reason: Option<String>,
    pub checked_at: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub auto_check: bool,
    pub auto_download: bool,
    pub skipped_version: String,
}

#[derive(Debug, Clone)]
pub struct CheckOutcome {
    pub status: UpdateStatus,
    pub manifest: Option<ReleaseManifest>,
    pub asset: Option<PlatformAsset>,
    pub update_available: bool,
    pub is_skipped: bool,
}

pub struct UpdateManager {
    vault: Vault,
    executable: PathBuf,
    state: Arc<Mutex<UpdateStateInner>>,
    op_lock: Arc<Mutex<()>>,
}

struct UpdateStateInner {
    status: UpdateStatus,
    manifest: Option<ReleaseManifest>,
    asset: Option<PlatformAsset>,
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn current_platform_key() -> &'static str {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        "windows-x64"
    }
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        "windows-arm64"
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "macos-arm64"
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "macos-x64"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "gui"))]
    {
        "linux-x64-gui"
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64", feature = "gui"))]
    {
        "linux-arm64-gui"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", not(feature = "gui")))]
    {
        "linux-x64-headless"
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64", not(feature = "gui")))]
    {
        "linux-arm64-headless"
    }
    #[cfg(not(any(
        all(target_os = "windows", any(target_arch = "x86_64", target_arch = "aarch64")),
        all(target_os = "macos", any(target_arch = "aarch64", target_arch = "x86_64")),
        all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")),
    )))]
    {
        "unsupported"
    }
}

fn manifest_url() -> String {
    std::env::var("OPENKEYLET_UPDATE_MANIFEST_URL")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_MANIFEST_URL.to_owned())
}

fn custom_manifest_origin() -> Option<String> {
    let custom = std::env::var("OPENKEYLET_UPDATE_MANIFEST_URL").ok()?;
    let parsed = Url::parse(custom.trim()).ok()?;
    Some(parsed.origin().ascii_serialization())
}

fn effective_public_key_b64() -> Option<String> {
    let compiled = COMPILED_UPDATE_PUBLIC_KEY_B64
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            let fallback = FALLBACK_UPDATE_PUBLIC_KEY_B64.trim();
            (!fallback.is_empty()).then(|| fallback.to_owned())
        });
    if custom_manifest_origin().is_some() || cfg!(test) || compiled.is_none() {
        if let Ok(env_key) = std::env::var("OPENKEYLET_UPDATE_PUBLIC_KEY") {
            let trimmed = env_key.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_owned());
            }
        }
    }
    compiled
}

fn updates_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("updates")
}

fn pending_marker_path(data_dir: &Path) -> PathBuf {
    updates_dir(data_dir).join("pending-update.json")
}

fn staging_dir_for_version(data_dir: &Path, version: &str) -> PathBuf {
    let safe_version: String = version
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    updates_dir(data_dir)
        .join("staging")
        .join(format!("v{safe_version}"))
}

fn is_cargo_dev_executable(executable: &Path) -> bool {
    let normalized = executable.to_string_lossy().replace('\\', "/");
    if !(normalized.contains("/target/debug/") || normalized.contains("/target/release/")) {
        return false;
    }
    // Confirm a Cargo.toml exists up the tree so a user folder casually named "target/release" is not misclassified.
    executable
        .ancestors()
        .take(5)
        .any(|ancestor| ancestor.join("Cargo.toml").is_file())
}

fn install_target_directory(executable: &Path) -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        if let Some(bundle) = macos_app_bundle(executable) {
            return bundle
                .parent()
                .map(Path::to_path_buf)
                .context("Unable to determine macOS application parent directory");
        }
    }
    executable
        .parent()
        .map(Path::to_path_buf)
        .context("Unable to determine OpenKeylet installation directory")
}

fn is_directory_writable(directory: &Path) -> bool {
    let probe = directory.join(format!(
        ".openkeylet-update-probe-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    match File::create(&probe) {
        Ok(file) => {
            drop(file);
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn check_install_capability(
    executable: &Path,
    signature_verified: bool,
    signing_key_configured: bool,
    has_platform_asset: bool,
) -> (bool, Option<String>) {
    if !signing_key_configured || !signature_verified {
        return (false, Some("UPDATE_NO_SIGNING_KEY".to_owned()));
    }
    if !has_platform_asset {
        return (false, Some("UPDATE_UNSUPPORTED_PLATFORM".to_owned()));
    }
    if std::env::var_os("OPENKEYLET_ALLOW_DEV_SELF_UPDATE").is_none()
        && is_cargo_dev_executable(executable)
    {
        return (false, Some("UPDATE_DEV_BUILD".to_owned()));
    }
    match install_target_directory(executable) {
        Ok(dir) if is_directory_writable(&dir) => (true, None),
        _ => (false, Some("UPDATE_READONLY_DIR".to_owned())),
    }
}

pub fn load_pending_update(data_dir: &Path) -> Option<PendingUpdateMarker> {
    let path = pending_marker_path(data_dir);
    let bytes = fs::read(&path).ok()?;
    let marker: PendingUpdateMarker = serde_json::from_slice(&bytes).ok()?;
    if !marker.signature_verified || marker.platform != current_platform_key() {
        return None;
    }
    if !is_newer_version(current_version(), &marker.version).unwrap_or(false) {
        return None;
    }
    if !marker.staged_root.is_dir() || validate_staged_package_root(&marker.staged_root).is_err() {
        return None;
    }
    Some(marker)
}

fn save_pending_update(data_dir: &Path, marker: &PendingUpdateMarker) -> Result<()> {
    let path = pending_marker_path(data_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("Unable to create OpenKeylet updates directory")?;
    }
    let bytes = serde_json::to_vec_pretty(marker)?;
    let mut file =
        AtomicWriteFile::open(&path).context("Unable to open pending update marker file")?;
    file.write_all(&bytes)
        .context("Unable to write pending update marker")?;
    file.commit()
        .context("Unable to commit pending update marker")?;
    Ok(())
}

pub fn clear_pending_update(data_dir: &Path) {
    let _ = fs::remove_file(pending_marker_path(data_dir));
    let _ = fs::remove_dir_all(updates_dir(data_dir).join("staging"));
}

pub fn cleanup_previous_update_artifacts(executable: &Path, data_dir: &Path) {
    if let Ok(install_dir) = install_target_directory(executable) {
        if let Ok(entries) = fs::read_dir(&install_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let is_old_backup = name.starts_with("openkeylet.exe.old")
                    || name.starts_with("openkeylet.old")
                    || name.starts_with("OpenKeylet.AppImage.old")
                    || name.starts_with("OpenKeylet.app.old")
                    || name.starts_with("browser-extension.old");
                if is_old_backup {
                    let path = entry.path();
                    if path.is_dir() {
                        let _ = fs::remove_dir_all(&path);
                    } else {
                        let _ = fs::remove_file(&path);
                    }
                }
            }
        }
    }
    // Clear obsolete pending markers (already running same or newer version).
    let marker_path = pending_marker_path(data_dir);
    if let Ok(bytes) = fs::read(&marker_path) {
        if let Ok(marker) = serde_json::from_slice::<PendingUpdateMarker>(&bytes) {
            if !is_newer_version(current_version(), &marker.version).unwrap_or(false) {
                clear_pending_update(data_dir);
            }
        } else {
            let _ = fs::remove_file(&marker_path);
        }
    }
}

/// Checks if a verified update was staged earlier (e.g. background download) and
/// applies it before launching the GUI so updates take effect automatically on
/// next launch. Returns `Ok(true)` if the update was applied and the new binary
/// was spawned (caller should exit cleanly).
pub fn try_apply_pending_on_startup(executable: &Path, data_dir: &Path) -> Result<bool> {
    cleanup_previous_update_artifacts(executable, data_dir);
    if std::env::var_os("OPENKEYLET_JUST_UPDATED").is_some() {
        return Ok(false);
    }
    let Some(pending) = load_pending_update(data_dir) else {
        return Ok(false);
    };
    let signing_key_configured = effective_public_key_b64().is_some();
    let (can_install, _) =
        check_install_capability(executable, pending.signature_verified, signing_key_configured, true);
    if !can_install {
        return Ok(false);
    }
    if let Err(error) = apply_staged_package(executable, &pending.staged_root) {
        eprintln!("OpenKeylet: deferred update could not be applied on startup: {error:#}");
        return Ok(false);
    }
    clear_pending_update(data_dir);
    spawn_relaunched_gui(executable)?;
    Ok(true)
}

fn spawn_relaunched_gui(executable: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        if let Some(bundle) = macos_app_bundle(executable) {
            Command::new("/usr/bin/open")
                .arg("-n")
                .arg(&bundle)
                .env("OPENKEYLET_JUST_UPDATED", "1")
                .spawn()
                .with_context(|| {
                    format!("Unable to relaunch OpenKeylet bundle: {}", bundle.display())
                })?;
            return Ok(());
        }
    }
    Command::new(executable)
        .arg("gui")
        .env("OPENKEYLET_JUST_UPDATED", "1")
        .spawn()
        .with_context(|| format!("Unable to relaunch OpenKeylet: {}", executable.display()))?;
    Ok(())
}

impl UpdateManager {
    pub fn new(vault: Vault, executable: PathBuf) -> Self {
        let settings = vault.settings().unwrap_or_default();
        let initial = initial_status(&vault, &executable, &settings);
        Self {
            vault,
            executable,
            state: Arc::new(Mutex::new(UpdateStateInner {
                status: initial,
                manifest: None,
                asset: None,
            })),
            op_lock: Arc::new(Mutex::new(())),
        }
    }

    pub async fn status(&self) -> UpdateStatus {
        let settings = self.vault.settings().unwrap_or_default();
        let mut inner = self.state.lock().await;
        sync_settings_into_status(&mut inner.status, &settings);
        inner.status.clone()
    }

    pub async fn refresh_settings(&self) -> UpdateStatus {
        self.status().await
    }

    pub async fn skip_version(&self, version: &str) -> Result<UpdateStatus> {
        let trimmed = version.trim();
        if !trimmed.is_empty() {
            Version::parse(trimmed).context("Invalid version to skip")?;
        }
        let settings = self.vault.update_settings_patch(SettingsPatch {
            update_skipped_version: Some(trimmed.to_owned()),
            ..SettingsPatch::default()
        })?;
        let mut inner = self.state.lock().await;
        sync_settings_into_status(&mut inner.status, &settings);
        Ok(inner.status.clone())
    }

    pub async fn check_for_updates(
        &self,
        manual: bool,
        on_update: impl Fn(&UpdateStatus) + Send + Sync,
    ) -> Result<CheckOutcome> {
        let _guard = self.op_lock.lock().await;
        let settings = self.vault.settings().unwrap_or_default();

        // If a verified staged update is already ready and matches or exceeds remote, keep ready unless newer exists.
        {
            let mut inner = self.state.lock().await;
            sync_settings_into_status(&mut inner.status, &settings);
            inner.status.phase = "checking".to_owned();
            inner.status.error_code = None;
            inner.status.error_message = None;
            on_update(&inner.status);
        }

        let url = manifest_url();
        let custom_origin = custom_manifest_origin();
        let public_key = effective_public_key_b64();
        let signing_key_configured = public_key.is_some();

        let fetch_result = fetch_and_verify_manifest(
            &url,
            public_key.as_deref(),
            custom_origin.as_deref(),
        )
        .await;

        match fetch_result {
            Ok((manifest, signature_verified)) => {
                let newer = is_newer_version(current_version(), &manifest.version)?;
                let platform = current_platform_key().to_owned();
                let asset = manifest.platforms.get(&platform).cloned();
                let checked_at = Some(Utc::now().to_rfc3339());
                let (can_auto_install, install_blocked_reason) = check_install_capability(
                    &self.executable,
                    signature_verified,
                    signing_key_configured,
                    asset.is_some(),
                );
                let pending = load_pending_update(self.vault.data_dir());
                let already_ready = newer
                    && pending
                        .as_ref()
                        .is_some_and(|item| item.version == manifest.version);
                let is_skipped = !manual
                    && !settings.update_skipped_version.is_empty()
                    && settings.update_skipped_version == manifest.version;

                let phase = if !newer {
                    "up_to_date".to_owned()
                } else if already_ready {
                    "ready".to_owned()
                } else {
                    "available".to_owned()
                };

                let status = {
                    let mut inner = self.state.lock().await;
                    let asset_size = asset.as_ref().map(|item| item.size);
                    inner.status = UpdateStatus {
                        phase,
                        current_version: current_version().to_owned(),
                        platform,
                        latest_version: Some(manifest.version.clone()),
                        tag: Some(manifest.tag.clone()),
                        published_at: if manifest.published_at.is_empty() {
                            None
                        } else {
                            Some(manifest.published_at.clone())
                        },
                        release_url: manifest.release_url.clone(),
                        notes: manifest.notes.clone(),
                        asset_size,
                        downloaded_bytes: if already_ready {
                            asset_size.unwrap_or(0)
                        } else {
                            0
                        },
                        total_bytes: asset_size.unwrap_or(0),
                        signature_verified,
                        signing_key_configured,
                        can_auto_install,
                        install_blocked_reason,
                        checked_at,
                        error_code: None,
                        error_message: None,
                        auto_check: settings.update_auto_check,
                        auto_download: settings.update_auto_download,
                        skipped_version: settings.update_skipped_version.clone(),
                    };
                    inner.manifest = Some(manifest.clone());
                    inner.asset = asset.clone();
                    on_update(&inner.status);
                    inner.status.clone()
                };

                Ok(CheckOutcome {
                    status,
                    manifest: Some(manifest),
                    asset,
                    update_available: newer,
                    is_skipped,
                })
            }
            Err(error) => {
                let (code, message) = split_error_code(&error);
                let status = {
                    let mut inner = self.state.lock().await;
                    let fallback = load_pending_update(self.vault.data_dir());
                    if let Some(pending) = fallback {
                        // Preserve an already-staged ready update even if the network check failed.
                        inner.status.phase = "ready".to_owned();
                        inner.status.latest_version = Some(pending.version);
                        inner.status.tag = Some(pending.tag);
                    } else if manual {
                        inner.status.phase = "error".to_owned();
                        inner.status.error_code = Some(code);
                        inner.status.error_message = Some(message);
                    } else {
                        // Silent background check: keep UI quiet when offline.
                        inner.status.phase = "idle".to_owned();
                    }
                    inner.status.checked_at = Some(Utc::now().to_rfc3339());
                    sync_settings_into_status(&mut inner.status, &settings);
                    on_update(&inner.status);
                    inner.status.clone()
                };
                if manual {
                    Err(error)
                } else {
                    Ok(CheckOutcome {
                        status,
                        manifest: None,
                        asset: None,
                        update_available: false,
                        is_skipped: false,
                    })
                }
            }
        }
    }

    pub async fn download_and_stage(
        &self,
        on_update: impl Fn(&UpdateStatus) + Send + Sync,
    ) -> Result<UpdateStatus> {
        // Ensure we have fresh manifest metadata if none is cached yet.
        let need_check = { self.state.lock().await.manifest.is_none() };
        if need_check {
            self.check_for_updates(true, &on_update).await?;
        }

        let _guard = self.op_lock.lock().await;
        let settings = self.vault.settings().unwrap_or_default();
        let (manifest, asset, signature_verified, can_auto_install, blocked_reason) = {
            let inner = self.state.lock().await;
            (
                inner.manifest.clone(),
                inner.asset.clone(),
                inner.status.signature_verified,
                inner.status.can_auto_install,
                inner.status.install_blocked_reason.clone(),
            )
        };

        let manifest = manifest
            .ok_or_else(|| anyhow!("UPDATE_NOT_AVAILABLE: No newer release manifest available"))?;
        if !is_newer_version(current_version(), &manifest.version)? {
            return Ok(self.status().await);
        }
        if !signature_verified {
            bail!("UPDATE_NO_SIGNING_KEY: Cannot auto-install an update without a verified release signing key");
        }
        if !can_auto_install {
            let reason = blocked_reason.unwrap_or_else(|| "UPDATE_INSTALL_BLOCKED".to_owned());
            bail!("{reason}: Automatic installation is unavailable for this installation");
        }
        let asset = asset.ok_or_else(|| {
            anyhow!(
                "UPDATE_UNSUPPORTED_PLATFORM: No release archive found for {}",
                current_platform_key()
            )
        })?;

        // Already staged and verified for this exact version & hash?
        if let Some(existing) = load_pending_update(self.vault.data_dir()) {
            if existing.version == manifest.version && existing.archive_sha256 == asset.sha256 {
                let mut inner = self.state.lock().await;
                inner.status.phase = "ready".to_owned();
                inner.status.downloaded_bytes = asset.size;
                inner.status.total_bytes = asset.size;
                inner.status.error_code = None;
                inner.status.error_message = None;
                sync_settings_into_status(&mut inner.status, &settings);
                on_update(&inner.status);
                return Ok(inner.status.clone());
            }
        }

        // Transition to downloading.
        {
            let mut inner = self.state.lock().await;
            inner.status.phase = "downloading".to_owned();
            inner.status.downloaded_bytes = 0;
            inner.status.total_bytes = asset.size;
            inner.status.error_code = None;
            inner.status.error_message = None;
            on_update(&inner.status);
        }

        let staging_root = staging_dir_for_version(self.vault.data_dir(), &manifest.version);
        if staging_root.exists() {
            let _ = fs::remove_dir_all(&staging_root);
        }
        fs::create_dir_all(&staging_root).context("Unable to create update staging directory")?;
        let archive_ext = if asset.format == "tar.gz" {
            "tar.gz"
        } else {
            "zip"
        };
        let archive_path = staging_root.join(format!("package.{archive_ext}"));
        let extract_dir = staging_root.join("extracted");

        let download_result = async {
            let custom_origin = custom_manifest_origin();
            download_verified_archive(
                &asset,
                &archive_path,
                custom_origin,
                |downloaded, total| {
                    if let Ok(mut inner) = self.state.try_lock() {
                        inner.status.downloaded_bytes = downloaded;
                        inner.status.total_bytes = total;
                        on_update(&inner.status);
                    }
                },
            )
            .await?;

            {
                let mut inner = self.state.lock().await;
                inner.status.phase = "verifying".to_owned();
                inner.status.downloaded_bytes = asset.size;
                inner.status.total_bytes = asset.size;
                on_update(&inner.status);
            }

            let archive_clone = archive_path.clone();
            let extract_clone = extract_dir.clone();
            let format_clone = asset.format.clone();
            let package_root = tokio::task::spawn_blocking(move || -> Result<PathBuf> {
                extract_archive_safely(&archive_clone, &extract_clone, &format_clone)?;
                let root = locate_extracted_package_root(&extract_clone)?;
                validate_staged_package_root(&root)?;
                Ok(root)
            })
            .await
            .context("Update verification worker panicked")??;

            // Remove the downloaded archive once extracted and validated to save disk space.
            let _ = fs::remove_file(&archive_path);

            let marker = PendingUpdateMarker {
                version: manifest.version.clone(),
                tag: manifest.tag.clone(),
                platform: current_platform_key().to_owned(),
                archive_sha256: asset.sha256.clone(),
                staged_root: package_root,
                signature_verified: true,
                prepared_at: Utc::now().to_rfc3339(),
                notes: manifest.notes.clone(),
                release_url: manifest.release_url.clone(),
                published_at: manifest.published_at.clone(),
            };
            save_pending_update(self.vault.data_dir(), &marker)?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        match download_result {
            Ok(()) => {
                let mut inner = self.state.lock().await;
                inner.status.phase = "ready".to_owned();
                inner.status.downloaded_bytes = asset.size;
                inner.status.total_bytes = asset.size;
                inner.status.error_code = None;
                inner.status.error_message = None;
                sync_settings_into_status(&mut inner.status, &settings);
                on_update(&inner.status);
                Ok(inner.status.clone())
            }
            Err(error) => {
                let _ = fs::remove_dir_all(&staging_root);
                let (code, message) = split_error_code(&error);
                let mut inner = self.state.lock().await;
                inner.status.phase = "error".to_owned();
                inner.status.error_code = Some(code);
                inner.status.error_message = Some(message);
                sync_settings_into_status(&mut inner.status, &settings);
                on_update(&inner.status);
                Err(error)
            }
        }
    }

    pub async fn apply_and_relaunch(
        &self,
        relaunch_gui: bool,
        on_update: impl Fn(&UpdateStatus) + Send + Sync,
    ) -> Result<()> {
        let _guard = self.op_lock.lock().await;
        let pending = load_pending_update(self.vault.data_dir())
            .ok_or_else(|| anyhow!("UPDATE_NOT_READY: No verified update is staged for installation"))?;

        let signing_key_configured = effective_public_key_b64().is_some();
        let (can_install, blocked_reason) = check_install_capability(
            &self.executable,
            pending.signature_verified,
            signing_key_configured,
            true,
        );
        if !can_install {
            let reason = blocked_reason.unwrap_or_else(|| "UPDATE_INSTALL_BLOCKED".to_owned());
            bail!("{reason}: Automatic installation is unavailable for this installation");
        }

        {
            let mut inner = self.state.lock().await;
            inner.status.phase = "applying".to_owned();
            inner.status.error_code = None;
            inner.status.error_message = None;
            on_update(&inner.status);
        }

        let executable = self.executable.clone();
        let staged_root = pending.staged_root.clone();
        let apply_result =
            tokio::task::spawn_blocking(move || apply_staged_package(&executable, &staged_root))
                .await
                .context("Update installation worker panicked")?;

        if let Err(error) = apply_result {
            let (code, message) = split_error_code(&error);
            let mut inner = self.state.lock().await;
            inner.status.phase = "error".to_owned();
            inner.status.error_code = Some(code);
            inner.status.error_message = Some(message);
            on_update(&inner.status);
            return Err(error);
        }

        clear_pending_update(self.vault.data_dir());
        if relaunch_gui {
            spawn_relaunched_gui(&self.executable)?;
        }
        Ok(())
    }
}

fn initial_status(vault: &Vault, executable: &Path, settings: &Settings) -> UpdateStatus {
    let signing_key_configured = effective_public_key_b64().is_some();
    if let Some(pending) = load_pending_update(vault.data_dir()) {
        let (can_auto_install, install_blocked_reason) =
            check_install_capability(executable, pending.signature_verified, signing_key_configured, true);
        return UpdateStatus {
            phase: "ready".to_owned(),
            current_version: current_version().to_owned(),
            platform: current_platform_key().to_owned(),
            latest_version: Some(pending.version),
            tag: Some(pending.tag),
            published_at: if pending.published_at.is_empty() {
                None
            } else {
                Some(pending.published_at)
            },
            release_url: if pending.release_url.is_empty() {
                DEFAULT_RELEASES_URL.to_owned()
            } else {
                pending.release_url
            },
            notes: pending.notes,
            asset_size: None,
            downloaded_bytes: 0,
            total_bytes: 0,
            signature_verified: pending.signature_verified,
            signing_key_configured,
            can_auto_install,
            install_blocked_reason,
            checked_at: Some(pending.prepared_at),
            error_code: None,
            error_message: None,
            auto_check: settings.update_auto_check,
            auto_download: settings.update_auto_download,
            skipped_version: settings.update_skipped_version.clone(),
        };
    }

    let (can_auto_install, install_blocked_reason) =
        check_install_capability(executable, signing_key_configured, signing_key_configured, true);
    UpdateStatus {
        phase: "idle".to_owned(),
        current_version: current_version().to_owned(),
        platform: current_platform_key().to_owned(),
        latest_version: None,
        tag: None,
        published_at: None,
        release_url: DEFAULT_RELEASES_URL.to_owned(),
        notes: String::new(),
        asset_size: None,
        downloaded_bytes: 0,
        total_bytes: 0,
        signature_verified: false,
        signing_key_configured,
        can_auto_install,
        install_blocked_reason,
        checked_at: None,
        error_code: None,
        error_message: None,
        auto_check: settings.update_auto_check,
        auto_download: settings.update_auto_download,
        skipped_version: settings.update_skipped_version.clone(),
    }
}

fn sync_settings_into_status(status: &mut UpdateStatus, settings: &Settings) {
    status.auto_check = settings.update_auto_check;
    status.auto_download = settings.update_auto_download;
    status.skipped_version = settings.update_skipped_version.clone();
}

fn split_error_code(error: &anyhow::Error) -> (String, String) {
    let text = error.to_string();
    if let Some((prefix, rest)) = text.split_once(':') {
        let code = prefix.trim();
        if code.starts_with("UPDATE_")
            && code
                .bytes()
                .all(|byte| matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
        {
            return (code.to_owned(), rest.trim().to_owned());
        }
    }
    ("UPDATE_FAILED".to_owned(), text)
}


#[cfg(test)]
mod tests;
