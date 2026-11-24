use crate::model::{Settings, SettingsPatch};
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

fn is_allowed_update_url(raw: &str, custom_origin: Option<&str>) -> bool {
    let Ok(parsed) = Url::parse(raw) else {
        return false;
    };
    if let Some(allowed_origin) = custom_origin {
        if parsed.origin().ascii_serialization() == allowed_origin
            && matches!(parsed.scheme(), "http" | "https")
        {
            return true;
        }
    }
    if parsed.scheme() != "https" {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    ALLOWED_GITHUB_HOSTS
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
}

fn build_http_client(
    connect_timeout: Duration,
    total_timeout: Duration,
    custom_origin: Option<String>,
) -> Result<reqwest::Client> {
    let policy = Policy::custom(move |attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("UPDATE_REDIRECT_LIMIT: Too many redirects while contacting GitHub Releases");
        }
        if !is_allowed_update_url(attempt.url().as_str(), custom_origin.as_deref()) {
            return attempt.error("UPDATE_URL_REJECTED: Update redirect pointed outside GitHub Releases");
        }
        attempt.follow()
    });
    reqwest::Client::builder()
        .user_agent(format!("OpenKeylet/{}", current_version()))
        .connect_timeout(connect_timeout)
        .timeout(total_timeout)
        .redirect(policy)
        .build()
        .context("UPDATE_HTTP_CLIENT: Unable to initialize update HTTP client")
}

pub fn verify_signed_manifest(
    raw: &[u8],
    public_key_b64: Option<&str>,
    custom_origin: Option<&str>,
) -> Result<(ReleaseManifest, bool)> {
    if raw.len() > MAX_MANIFEST_BYTES {
        bail!("UPDATE_MANIFEST_TOO_LARGE: Update manifest exceeds 256 KiB limit");
    }
    let envelope: SignedManifestEnvelope = serde_json::from_slice(raw)
        .context("UPDATE_MANIFEST_INVALID: Release manifest is not valid JSON")?;
    if envelope.format != MANIFEST_ENVELOPE_FORMAT {
        bail!(
            "UPDATE_MANIFEST_FORMAT: Unsupported update manifest format '{}'",
            envelope.format
        );
    }

    let signature_verified = if let Some(pk_b64) = public_key_b64.filter(|key| !key.trim().is_empty())
    {
        let pk_bytes = BASE64
            .decode(pk_b64.trim())
            .context("UPDATE_PUBLIC_KEY_INVALID: Embedded update public key is invalid base64")?;
        if pk_bytes.len() != 32 {
            bail!("UPDATE_PUBLIC_KEY_INVALID: Embedded Ed25519 public key must be 32 bytes");
        }
        let sig_bytes = BASE64
            .decode(envelope.signature.trim())
            .context("UPDATE_SIGNATURE_INVALID: Release manifest signature is invalid base64")?;
        if sig_bytes.len() != 64 {
            bail!("UPDATE_SIGNATURE_INVALID: Ed25519 signature must be 64 bytes");
        }
        let mut signing_input =
            Vec::with_capacity(MANIFEST_ENVELOPE_FORMAT.len() + 1 + envelope.payload.len());
        signing_input.extend_from_slice(MANIFEST_ENVELOPE_FORMAT.as_bytes());
        signing_input.push(b'\n');
        signing_input.extend_from_slice(envelope.payload.as_bytes());
        UnparsedPublicKey::new(&ED25519, &pk_bytes)
            .verify(&signing_input, &sig_bytes)
            .map_err(|_| {
                anyhow!("UPDATE_SIGNATURE_INVALID: Release manifest Ed25519 signature verification failed")
            })?;
        true
    } else {
        false
    };

    let manifest: ReleaseManifest = serde_json::from_str(&envelope.payload)
        .context("UPDATE_MANIFEST_INVALID: Signed payload is not a valid release manifest")?;
    if manifest.schema_version != 1 {
        bail!(
            "UPDATE_MANIFEST_SCHEMA: Unsupported manifest schema version {}",
            manifest.schema_version
        );
    }
    Version::parse(manifest.version.trim())
        .context("UPDATE_VERSION_INVALID: Release manifest version is not valid SemVer")?;
    if !is_allowed_update_url(&manifest.release_url, custom_origin) {
        bail!("UPDATE_URL_REJECTED: Release page URL is outside GitHub Releases");
    }
    for asset in manifest.platforms.values() {
        if !is_allowed_update_url(&asset.url, custom_origin) {
            bail!("UPDATE_URL_REJECTED: Release asset URL is outside GitHub Releases");
        }
        if !is_valid_sha256_hex(&asset.sha256) {
            bail!("UPDATE_MANIFEST_INVALID: Release asset SHA-256 is malformed");
        }
        if asset.size == 0 || asset.size > MAX_ARCHIVE_BYTES {
            bail!("UPDATE_MANIFEST_INVALID: Release asset size is out of allowed bounds");
        }
        if !matches!(asset.format.as_str(), "zip" | "tar.gz") {
            bail!("UPDATE_MANIFEST_INVALID: Unsupported archive format '{}'", asset.format);
        }
    }
    Ok((manifest, signature_verified))
}

fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn is_newer_version(current: &str, candidate: &str) -> Result<bool> {
    let current = Version::parse(current.trim().trim_start_matches('v'))
        .context("Current application version is not valid SemVer")?;
    let candidate = Version::parse(candidate.trim().trim_start_matches('v'))
        .context("UPDATE_VERSION_INVALID: Remote version is not valid SemVer")?;
    Ok(candidate > current)
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

async fn fetch_and_verify_manifest(
    url: &str,
    public_key_b64: Option<&str>,
    custom_origin: Option<&str>,
) -> Result<(ReleaseManifest, bool)> {
    if !is_allowed_update_url(url, custom_origin) {
        bail!("UPDATE_URL_REJECTED: Update manifest URL is outside GitHub Releases");
    }
    let client = build_http_client(
        Duration::from_secs(10),
        Duration::from_secs(15),
        custom_origin.map(str::to_owned),
    )?;
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .context("UPDATE_NETWORK: Unable to reach GitHub Releases")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        bail!("UPDATE_MANIFEST_MISSING: No signed update manifest (latest.json) is published on the latest GitHub Release yet");
    }
    if !response.status().is_success() {
        bail!(
            "UPDATE_HTTP_STATUS: GitHub Releases returned HTTP {}",
            response.status().as_u16()
        );
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("UPDATE_NETWORK: Failed while reading update manifest")?;
        if bytes.len().saturating_add(chunk.len()) > MAX_MANIFEST_BYTES {
            bail!("UPDATE_MANIFEST_TOO_LARGE: Update manifest exceeds 256 KiB limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    verify_signed_manifest(&bytes, public_key_b64, custom_origin)
}

async fn download_verified_archive(
    asset: &PlatformAsset,
    destination: &Path,
    custom_origin: Option<String>,
    on_progress: impl Fn(u64, u64),
) -> Result<()> {
    if !is_allowed_update_url(&asset.url, custom_origin.as_deref()) {
        bail!("UPDATE_URL_REJECTED: Release archive URL is outside GitHub Releases");
    }
    let client = build_http_client(
        Duration::from_secs(15),
        Duration::from_secs(300),
        custom_origin,
    )?;
    let response = client
        .get(&asset.url)
        .send()
        .await
        .context("UPDATE_NETWORK: Unable to download release archive from GitHub")?;
    if !response.status().is_success() {
        bail!(
            "UPDATE_HTTP_STATUS: GitHub returned HTTP {} while downloading the update",
            response.status().as_u16()
        );
    }

    let mut file = File::create(destination)
        .with_context(|| format!("Unable to create download file: {}", destination.display()))?;
    let mut hasher = Sha256::new();
    let mut downloaded: u64 = 0;
    let mut last_emit = Instant::now();
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("UPDATE_NETWORK: Connection interrupted during download")?;
        downloaded = downloaded.saturating_add(chunk.len() as u64);
        if downloaded > asset.size || downloaded > MAX_ARCHIVE_BYTES {
            bail!("UPDATE_SIZE_MISMATCH: Downloaded archive exceeded expected manifest size");
        }
        file.write_all(&chunk)
            .context("Unable to write downloaded update chunk to disk")?;
        hasher.update(&chunk);
        if last_emit.elapsed() >= Duration::from_millis(120) || downloaded == asset.size {
            on_progress(downloaded, asset.size);
            last_emit = Instant::now();
        }
    }
    file.flush()?;
    drop(file);

    if downloaded != asset.size {
        bail!(
            "UPDATE_SIZE_MISMATCH: Downloaded {} bytes, expected {} bytes",
            downloaded,
            asset.size
        );
    }
    let actual_hex = encode_hex(&hasher.finalize());
    if !actual_hex.eq_ignore_ascii_case(&asset.sha256) {
        bail!("UPDATE_CHECKSUM_MISMATCH: Downloaded update SHA-256 did not match the signed manifest");
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn validate_relative_archive_path(path: &Path) -> Result<PathBuf> {
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!(
                    "UPDATE_ARCHIVE_UNSAFE: Archive contains unsafe path '{}'",
                    path.display()
                );
            }
        }
    }
    if clean.as_os_str().is_empty() {
        bail!("UPDATE_ARCHIVE_UNSAFE: Archive contains an empty entry path");
    }
    Ok(clean)
}

fn extract_archive_safely(archive_path: &Path, destination: &Path, format: &str) -> Result<()> {
    if destination.exists() {
        fs::remove_dir_all(destination)?;
    }
    fs::create_dir_all(destination)?;

    match format {
        "zip" => {
            // Validate every zip entry path and total size before extraction.
            let file = File::open(archive_path).context("Unable to open downloaded zip archive")?;
            let mut archive =
                zip::ZipArchive::new(file).context("UPDATE_ARCHIVE_INVALID: Corrupt zip archive")?;
            if archive.len() > MAX_EXTRACTED_FILES {
                bail!("UPDATE_ARCHIVE_UNSAFE: Archive exceeds maximum file count");
            }
            let mut total_uncompressed: u64 = 0;
            for idx in 0..archive.len() {
                let entry = archive.by_index(idx)?;
                let name = entry.name().to_owned();
                if name.starts_with("__MACOSX/") {
                    continue;
                }
                let enclosed = entry
                    .enclosed_name()
                    .ok_or_else(|| anyhow!("UPDATE_ARCHIVE_UNSAFE: Zip entry escapes target directory: {name}"))?;
                let _ = validate_relative_archive_path(&enclosed)?;
                total_uncompressed = total_uncompressed.saturating_add(entry.size());
                if total_uncompressed > MAX_EXTRACTED_BYTES {
                    bail!("UPDATE_ARCHIVE_UNSAFE: Uncompressed archive size exceeds safety cap");
                }
            }

            #[cfg(target_os = "macos")]
            {
                // Preserve macOS code signatures, symlinks, and extended attributes using ditto.
                drop(archive);
                let status = Command::new("/usr/bin/ditto")
                    .arg("-x")
                    .arg("-k")
                    .arg(archive_path)
                    .arg(destination)
                    .status()
                    .context("Unable to execute /usr/bin/ditto to extract macOS update")?;
                if !status.success() {
                    bail!("UPDATE_ARCHIVE_INVALID: macOS ditto extraction failed");
                }
                Ok(())
            }

            #[cfg(not(target_os = "macos"))]
            {
                let mut written_total: u64 = 0;
                for idx in 0..archive.len() {
                    let mut entry = archive.by_index(idx)?;
                    if entry.is_symlink() {
                        bail!("UPDATE_ARCHIVE_UNSAFE: Refusing symlink entry inside zip archive");
                    }
                    let enclosed = entry
                        .enclosed_name()
                        .ok_or_else(|| anyhow!("UPDATE_ARCHIVE_UNSAFE: Unsafe zip entry path"))?;
                    let clean = validate_relative_archive_path(&enclosed)?;
                    let out_path = destination.join(clean);
                    if entry.is_dir() {
                        fs::create_dir_all(&out_path)?;
                        continue;
                    }
                    if let Some(parent) = out_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let mut out_file = File::create(&out_path)?;
                    let copied = copy_bounded(&mut entry, &mut out_file, MAX_EXTRACTED_BYTES - written_total)?;
                    written_total = written_total.saturating_add(copied);
                    #[cfg(unix)]
                    if let Some(mode) = entry.unix_mode() {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(&out_path, fs::Permissions::from_mode(mode & 0o777));
                    }
                }
                Ok(())
            }
        }
        "tar.gz" => {
            let file = File::open(archive_path).context("Unable to open downloaded tar.gz archive")?;
            let decoder = GzDecoder::new(file);
            let mut archive = tar::Archive::new(decoder);
            let mut file_count: usize = 0;
            let mut written_total: u64 = 0;
            for entry_result in archive
                .entries()
                .context("UPDATE_ARCHIVE_INVALID: Corrupt tar.gz archive")?
            {
                let mut entry = entry_result?;
                file_count += 1;
                if file_count > MAX_EXTRACTED_FILES {
                    bail!("UPDATE_ARCHIVE_UNSAFE: Archive exceeds maximum file count");
                }
                let entry_type = entry.header().entry_type();
                if entry_type.is_symlink() || entry_type.is_hard_link() {
                    bail!("UPDATE_ARCHIVE_UNSAFE: Refusing link entry inside tar.gz archive");
                }
                if !(entry_type.is_file() || entry_type.is_dir()) {
                    continue;
                }
                let raw_path = entry.path()?.into_owned();
                let clean = validate_relative_archive_path(&raw_path)?;
                let out_path = destination.join(clean);
                if entry_type.is_dir() {
                    fs::create_dir_all(&out_path)?;
                    continue;
                }
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                #[cfg(unix)]
                let mode = entry.header().mode().ok();
                let mut out_file = File::create(&out_path)?;
                let copied =
                    copy_bounded(&mut entry, &mut out_file, MAX_EXTRACTED_BYTES - written_total)?;
                written_total = written_total.saturating_add(copied);
                #[cfg(unix)]
                if let Some(mode) = mode {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&out_path, fs::Permissions::from_mode(mode & 0o777));
                }
            }
            Ok(())
        }
        other => bail!("UPDATE_ARCHIVE_INVALID: Unsupported archive format '{other}'"),
    }
}

fn copy_bounded(reader: &mut impl io::Read, writer: &mut impl io::Write, limit: u64) -> Result<u64> {
    let mut buf = [0_u8; 32 * 1024];
    let mut total: u64 = 0;
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > limit {
            bail!("UPDATE_ARCHIVE_UNSAFE: Uncompressed archive exceeded safety size limit");
        }
        writer.write_all(&buf[..read])?;
    }
    Ok(total)
}

fn locate_extracted_package_root(extract_dir: &Path) -> Result<PathBuf> {
    if validate_staged_package_root(extract_dir).is_ok() {
        return Ok(extract_dir.to_path_buf());
    }
    let mut dirs = Vec::new();
    for entry in fs::read_dir(extract_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir()
            && !entry
                .file_name()
                .to_string_lossy()
                .starts_with("__MACOSX")
        {
            dirs.push(path);
        }
    }
    for dir in dirs {
        if validate_staged_package_root(&dir).is_ok() {
            return Ok(dir);
        }
    }
    bail!("UPDATE_ARCHIVE_INVALID: Expected OpenKeylet payload was not found inside the downloaded archive")
}

fn validate_staged_package_root(package_root: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        if !package_root.join("openkeylet.exe").is_file() {
            bail!("UPDATE_ARCHIVE_INVALID: Missing openkeylet.exe in Windows package");
        }
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let app = package_root.join("OpenKeylet.app");
        if !app.join("Contents/MacOS/openkeylet").is_file() {
            bail!("UPDATE_ARCHIVE_INVALID: Missing OpenKeylet.app in macOS package");
        }
        if std::env::var_os("OPENKEYLET_SKIP_CODESIGN_VERIFY").is_none() {
            let status = Command::new("/usr/bin/codesign")
                .args(["--verify", "--deep", "--strict"])
                .arg(&app)
                .status()
                .context("Unable to run codesign verification on downloaded macOS update")?;
            if !status.success() {
                bail!("UPDATE_CODESIGN_INVALID: Downloaded OpenKeylet.app failed macOS codesign verification");
            }
        }
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "gui"))]
    {
        if !package_root.join("OpenKeylet.AppImage").is_file() {
            bail!("UPDATE_ARCHIVE_INVALID: Missing OpenKeylet.AppImage in Linux GUI package");
        }
        return Ok(());
    }
    #[cfg(all(target_os = "linux", not(feature = "gui")))]
    {
        if !package_root.join("openkeylet").is_file() {
            bail!("UPDATE_ARCHIVE_INVALID: Missing openkeylet binary in Linux headless package");
        }
        return Ok(());
    }
}

#[cfg(target_os = "macos")]
fn macos_app_bundle(executable: &Path) -> Option<PathBuf> {
    executable
        .ancestors()
        .find(|path| path.extension().is_some_and(|ext| ext == "app"))
        .map(Path::to_path_buf)
}

pub fn apply_staged_package(executable: &Path, staged_root: &Path) -> Result<()> {
    validate_staged_package_root(staged_root)?;

    #[cfg(target_os = "windows")]
    {
        let install_dir = executable
            .parent()
            .context("Unable to determine Windows install directory")?;
        let new_exe = staged_root.join("openkeylet.exe");
        replace_file_with_windows_backup(executable, &new_exe)?;
        sync_optional_portable_extras(staged_root, install_dir)?;
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let target_app = macos_app_bundle(executable)
            .context("UPDATE_INSTALL_BLOCKED: OpenKeylet must be running from OpenKeylet.app to self-update on macOS")?;
        let parent_dir = target_app
            .parent()
            .context("Unable to determine macOS Applications directory")?;
        let staged_app = staged_root.join("OpenKeylet.app");
        let temp_new = parent_dir.join(format!("OpenKeylet.app.new.{}", std::process::id()));
        let backup_old = parent_dir.join(format!("OpenKeylet.app.old.{}", std::process::id()));
        if temp_new.exists() {
            let _ = fs::remove_dir_all(&temp_new);
        }
        let copy_status = Command::new("/usr/bin/ditto")
            .arg(&staged_app)
            .arg(&temp_new)
            .status()
            .context("Unable to copy staged macOS app bundle")?;
        if !copy_status.success() {
            let _ = fs::remove_dir_all(&temp_new);
            bail!("UPDATE_INSTALL_FAILED: Failed to stage OpenKeylet.app into installation directory");
        }
        if backup_old.exists() {
            let _ = fs::remove_dir_all(&backup_old);
        }
        fs::rename(&target_app, &backup_old)
            .context("UPDATE_INSTALL_FAILED: Unable to move current OpenKeylet.app aside")?;
        if let Err(error) = fs::rename(&temp_new, &target_app) {
            let _ = fs::rename(&backup_old, &target_app);
            let _ = fs::remove_dir_all(&temp_new);
            return Err(error)
                .context("UPDATE_INSTALL_FAILED: Unable to place updated OpenKeylet.app");
        }
        let _ = fs::remove_dir_all(&backup_old);
        sync_optional_portable_extras(staged_root, parent_dir)?;
        return Ok(());
    }

    #[cfg(all(target_os = "linux", feature = "gui"))]
    {
        let install_dir = executable
            .parent()
            .context("Unable to determine Linux install directory")?;
        let target_appimage = std::env::var_os("APPIMAGE")
            .map(PathBuf::from)
            .filter(|path| path.is_file())
            .unwrap_or_else(|| {
                if executable
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("AppImage"))
                {
                    executable.to_path_buf()
                } else {
                    install_dir.join("OpenKeylet.AppImage")
                }
            });
        replace_unix_executable(&target_appimage, &staged_root.join("OpenKeylet.AppImage"))?;
        let staged_launcher = staged_root.join("openkeylet");
        let target_launcher = install_dir.join("openkeylet");
        if staged_launcher.is_file() && target_launcher.is_file() {
            replace_unix_executable(&target_launcher, &staged_launcher)?;
        }
        sync_optional_portable_extras(staged_root, install_dir)?;
        return Ok(());
    }

    #[cfg(all(target_os = "linux", not(feature = "gui")))]
    {
        let install_dir = executable
            .parent()
            .context("Unable to determine Linux headless install directory")?;
        replace_unix_executable(executable, &staged_root.join("openkeylet"))?;
        sync_optional_portable_extras(staged_root, install_dir)?;
        return Ok(());
    }
}

#[cfg(target_os = "windows")]
fn replace_file_with_windows_backup(target: &Path, staged_file: &Path) -> Result<()> {
    let parent = target
        .parent()
        .context("Missing parent directory for target executable")?;
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("openkeylet.exe");
    let temp_new = parent.join(format!("{file_name}.new.{}", std::process::id()));
    let backup_old = parent.join(format!(
        "{file_name}.old.{}.{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));

    fs::copy(staged_file, &temp_new)
        .context("UPDATE_INSTALL_FAILED: Unable to stage updated executable in install folder")?;
    if target.exists() {
        fs::rename(target, &backup_old).map_err(|error| {
            let _ = fs::remove_file(&temp_new);
            anyhow!("UPDATE_INSTALL_FAILED: Unable to move running executable aside: {error}")
        })?;
    }
    if let Err(error) = fs::rename(&temp_new, target) {
        if backup_old.exists() {
            let _ = fs::rename(&backup_old, target);
        }
        let _ = fs::remove_file(&temp_new);
        bail!("UPDATE_INSTALL_FAILED: Unable to move updated executable into place: {error}");
    }
    // Best effort removal; if current or child MCP process still holds it, next launch cleans it up.
    let _ = fs::remove_file(&backup_old);
    Ok(())
}

#[cfg(unix)]
fn replace_unix_executable(target: &Path, staged_file: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let parent = target
        .parent()
        .context("Missing parent directory for target executable")?;
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("openkeylet");
    let temp_new = parent.join(format!(".{file_name}.new.{}", std::process::id()));
    fs::copy(staged_file, &temp_new)
        .context("UPDATE_INSTALL_FAILED: Unable to copy updated executable")?;
    fs::set_permissions(&temp_new, fs::Permissions::from_mode(0o755))
        .context("UPDATE_INSTALL_FAILED: Unable to mark updated executable runnable")?;
    if let Err(error) = fs::rename(&temp_new, target) {
        let _ = fs::remove_file(&temp_new);
        return Err(error)
            .context("UPDATE_INSTALL_FAILED: Unable to atomically replace executable");
    }
    Ok(())
}

fn sync_optional_portable_extras(staged_root: &Path, install_dir: &Path) -> Result<()> {
    // Sync browser-extension folder when present in the portable install directory.
    let staged_ext = staged_root.join("browser-extension");
    let target_ext = install_dir.join("browser-extension");
    if staged_ext.is_dir() && target_ext.is_dir() {
        let temp_ext = install_dir.join(format!("browser-extension.new.{}", std::process::id()));
        let backup_ext = install_dir.join(format!(
            "browser-extension.old.{}",
            uuid::Uuid::new_v4().simple()
        ));
        if temp_ext.exists() {
            let _ = fs::remove_dir_all(&temp_ext);
        }
        copy_dir_recursive(&staged_ext, &temp_ext)?;
        if fs::rename(&target_ext, &backup_ext).is_ok() {
            if fs::rename(&temp_ext, &target_ext).is_err() {
                let _ = fs::rename(&backup_ext, &target_ext);
                let _ = fs::remove_dir_all(&temp_ext);
            } else {
                let _ = fs::remove_dir_all(&backup_ext);
            }
        } else {
            let _ = fs::remove_dir_all(&temp_ext);
        }
    }

    // Refresh bundled documentation files only if they already exist in install_dir.
    for file_name in [
        "README.md",
        "README.zh-CN.md",
        "SECURITY.md",
        "SECURITY.zh-CN.md",
        "LICENSE",
        "SHA256SUMS.txt",
    ] {
        let src = staged_root.join(file_name);
        let dst = install_dir.join(file_name);
        if src.is_file() && dst.is_file() {
            let _ = fs::copy(&src, &dst);
        }
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let target = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tempfile::tempdir;

    fn generate_test_keypair() -> (Ed25519KeyPair, String) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_b64 = BASE64.encode(keypair.public_key().as_ref());
        (keypair, pub_b64)
    }

    fn sign_manifest(keypair: &Ed25519KeyPair, manifest: &ReleaseManifest) -> Vec<u8> {
        let payload = serde_json::to_string(manifest).unwrap();
        let mut msg = Vec::new();
        msg.extend_from_slice(MANIFEST_ENVELOPE_FORMAT.as_bytes());
        msg.push(b'\n');
        msg.extend_from_slice(payload.as_bytes());
        let sig = keypair.sign(&msg);
        let envelope = SignedManifestEnvelope {
            format: MANIFEST_ENVELOPE_FORMAT.to_owned(),
            key_id: "test-key-1".to_owned(),
            payload,
            signature: BASE64.encode(sig.as_ref()),
        };
        serde_json::to_vec(&envelope).unwrap()
    }

    fn sample_manifest() -> ReleaseManifest {
        let mut platforms = BTreeMap::new();
        platforms.insert(
            current_platform_key().to_owned(),
            PlatformAsset {
                url: "https://github.com/omaekumiko2-create/OpenKeylet/releases/download/v9.9.9/OpenKeylet_9.9.9_test.zip".to_owned(),
                sha256: "a".repeat(64),
                size: 1024,
                format: "zip".to_owned(),
            },
        );
        ReleaseManifest {
            schema_version: 1,
            version: "9.9.9".to_owned(),
            tag: "v9.9.9".to_owned(),
            published_at: "2026-11-24T10:00:00Z".to_owned(),
            release_url: "https://github.com/omaekumiko2-create/OpenKeylet/releases/tag/v9.9.9"
                .to_owned(),
            notes: "## Highlights\n- Added automatic updates".to_owned(),
            platforms,
        }
    }

    #[test]
    fn verifies_valid_ed25519_signed_manifest_and_rejects_tampering() {
        let (keypair, pub_b64) = generate_test_keypair();
        let manifest = sample_manifest();
        let signed = sign_manifest(&keypair, &manifest);

        let (parsed, verified) =
            verify_signed_manifest(&signed, Some(&pub_b64), None).expect("valid signature");
        assert!(verified);
        assert_eq!(parsed.version, "9.9.9");
        assert_eq!(parsed.tag, "v9.9.9");

        // Tamper with payload inside envelope without re-signing.
        let mut tampered: SignedManifestEnvelope = serde_json::from_slice(&signed).unwrap();
        tampered.payload = tampered.payload.replace("9.9.9", "9.9.8");
        let tampered_bytes = serde_json::to_vec(&tampered).unwrap();
        let err = verify_signed_manifest(&tampered_bytes, Some(&pub_b64), None).unwrap_err();
        assert!(err.to_string().contains("UPDATE_SIGNATURE_INVALID"));

        // Wrong public key is rejected.
        let (_, other_pub_b64) = generate_test_keypair();
        let err = verify_signed_manifest(&signed, Some(&other_pub_b64), None).unwrap_err();
        assert!(err.to_string().contains("UPDATE_SIGNATURE_INVALID"));
    }

    #[test]
    fn rejects_non_github_asset_and_release_urls() {
        let (keypair, pub_b64) = generate_test_keypair();
        let mut manifest = sample_manifest();
        manifest
            .platforms
            .get_mut(current_platform_key())
            .unwrap()
            .url = "https://evil.example.com/openkeylet.zip".to_owned();
        let signed = sign_manifest(&keypair, &manifest);
        let err = verify_signed_manifest(&signed, Some(&pub_b64), None).unwrap_err();
        assert!(err.to_string().contains("UPDATE_URL_REJECTED"));
    }

    #[test]
    fn semver_comparison_prevents_downgrades() {
        assert!(is_newer_version("0.16.0", "0.16.1").unwrap());
        assert!(is_newer_version("0.16.0", "v0.17.0").unwrap());
        assert!(!is_newer_version("0.16.0", "0.16.0").unwrap());
        assert!(!is_newer_version("0.16.0", "0.15.9").unwrap());
        assert!(!is_newer_version("0.16.0", "0.16.0-rc.1").unwrap());
    }

    #[test]
    fn zip_extraction_blocks_path_traversal_and_extracts_valid_package() {
        let dir = tempdir().unwrap();
        let evil_zip = dir.path().join("evil.zip");
        {
            let file = File::create(&evil_zip).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            writer.start_file("../escape.txt", opts).unwrap();
            writer.write_all(b"evil").unwrap();
            writer.finish().unwrap();
        }
        let err = extract_archive_safely(&evil_zip, &dir.path().join("out-evil"), "zip")
            .unwrap_err();
        assert!(err.to_string().contains("UPDATE_ARCHIVE_UNSAFE"));

        let good_zip = dir.path().join("good.zip");
        {
            let file = File::create(&good_zip).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            writer
                .start_file("OpenKeylet_9.9.9_windows-x64/openkeylet.exe", opts)
                .unwrap();
            writer.write_all(b"NEW_EXE_BYTES").unwrap();
            writer
                .start_file(
                    "OpenKeylet_9.9.9_windows-x64/browser-extension/manifest.json",
                    opts,
                )
                .unwrap();
            writer.write_all(br#"{"version":"9.9.9"}"#).unwrap();
            writer.finish().unwrap();
        }
        let out_good = dir.path().join("out-good");
        extract_archive_safely(&good_zip, &out_good, "zip").unwrap();
        assert_eq!(
            fs::read(out_good.join("OpenKeylet_9.9.9_windows-x64/openkeylet.exe")).unwrap(),
            b"NEW_EXE_BYTES"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn applies_staged_windows_portable_package_and_syncs_extension() {
        let dir = tempdir().unwrap();
        let install_dir = dir.path().join("installed");
        let staged_dir = dir.path().join("staged");
        fs::create_dir_all(install_dir.join("browser-extension")).unwrap();
        fs::create_dir_all(staged_dir.join("browser-extension")).unwrap();

        let target_exe = install_dir.join("openkeylet.exe");
        fs::write(&target_exe, b"OLD_BINARY_0_16_0").unwrap();
        fs::write(
            install_dir.join("browser-extension/manifest.json"),
            br#"{"version":"0.16.0"}"#,
        )
        .unwrap();
        fs::write(install_dir.join("README.md"), b"OLD_README").unwrap();

        fs::write(staged_dir.join("openkeylet.exe"), b"NEW_BINARY_0_17_0").unwrap();
        fs::write(
            staged_dir.join("browser-extension/manifest.json"),
            br#"{"version":"0.17.0"}"#,
        )
        .unwrap();
        fs::write(staged_dir.join("README.md"), b"NEW_README").unwrap();

        apply_staged_package(&target_exe, &staged_dir).unwrap();

        assert_eq!(fs::read(&target_exe).unwrap(), b"NEW_BINARY_0_17_0");
        assert_eq!(
            fs::read(install_dir.join("browser-extension/manifest.json")).unwrap(),
            br#"{"version":"0.17.0"}"#
        );
        assert_eq!(fs::read(install_dir.join("README.md")).unwrap(), b"NEW_README");
    }

    #[tokio::test]
    async fn end_to_end_local_http_check_download_verify_and_stage() {
        use axum::{Router, routing::get};

        let (keypair, pub_b64) = generate_test_keypair();
        let temp = tempdir().unwrap();
        let install_dir = temp.path().join("install");
        let data_dir = temp.path().join("data");
        fs::create_dir_all(&install_dir).unwrap();
        let fake_exe = if cfg!(windows) {
            install_dir.join("openkeylet.exe")
        } else {
            install_dir.join("openkeylet")
        };
        fs::write(&fake_exe, b"OLD_VERSION").unwrap();

        // Build a real archive for the current test platform.
        let archive_bytes = {
            let archive_file = temp.path().join("release.zip");
            let file = File::create(&archive_file).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            #[cfg(target_os = "windows")]
            {
                writer
                    .start_file("OpenKeylet_9.9.9_windows-x64/openkeylet.exe", opts)
                    .unwrap();
                writer.write_all(b"UPGRADED_VERSION_9_9_9").unwrap();
            }
            #[cfg(not(target_os = "windows"))]
            {
                writer
                    .start_file("OpenKeylet_9.9.9/openkeylet", opts)
                    .unwrap();
                writer.write_all(b"UPGRADED_VERSION_9_9_9").unwrap();
            }
            writer.finish().unwrap();
            fs::read(&archive_file).unwrap()
        };
        let archive_sha = encode_hex(&Sha256::digest(&archive_bytes));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");

        let mut platforms = BTreeMap::new();
        platforms.insert(
            current_platform_key().to_owned(),
            PlatformAsset {
                url: format!("{base_url}/download/release.zip"),
                sha256: archive_sha.clone(),
                size: archive_bytes.len() as u64,
                format: "zip".to_owned(),
            },
        );
        let manifest = ReleaseManifest {
            schema_version: 1,
            version: "9.9.9".to_owned(),
            tag: "v9.9.9".to_owned(),
            published_at: "2026-11-24T12:00:00Z".to_owned(),
            release_url: format!("{base_url}/releases/tag/v9.9.9"),
            notes: "Test release notes".to_owned(),
            platforms,
        };
        let signed_manifest = sign_manifest(&keypair, &manifest);

        let manifest_body = signed_manifest.clone();
        let archive_body = archive_bytes.clone();
        let app = Router::new()
            .route(
                "/latest.json",
                get(move || {
                    let body = manifest_body.clone();
                    async move { body }
                }),
            )
            .route(
                "/download/release.zip",
                get(move || {
                    let body = archive_body.clone();
                    async move { body }
                }),
            );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let custom_origin = Url::parse(&base_url).unwrap().origin().ascii_serialization();
        let (verified_manifest, verified) = fetch_and_verify_manifest(
            &format!("{base_url}/latest.json"),
            Some(&pub_b64),
            Some(&custom_origin),
        )
        .await
        .unwrap();
        assert!(verified);
        assert_eq!(verified_manifest.version, "9.9.9");

        let asset = verified_manifest
            .platforms
            .get(current_platform_key())
            .unwrap();
        let dest = temp.path().join("downloaded.zip");
        download_verified_archive(asset, &dest, Some(custom_origin), |_, _| {})
            .await
            .unwrap();
        assert_eq!(fs::read(&dest).unwrap(), archive_bytes);

        #[cfg(target_os = "windows")]
        {
            let extract_dir = temp.path().join("extracted");
            extract_archive_safely(&dest, &extract_dir, "zip").unwrap();
            let root = locate_extracted_package_root(&extract_dir).unwrap();
            let marker = PendingUpdateMarker {
                version: "9.9.9".to_owned(),
                tag: "v9.9.9".to_owned(),
                platform: current_platform_key().to_owned(),
                archive_sha256: archive_sha,
                staged_root: root.clone(),
                signature_verified: true,
                prepared_at: Utc::now().to_rfc3339(),
                notes: "Test".to_owned(),
                release_url: format!("{base_url}/releases/tag/v9.9.9"),
                published_at: "2026-11-24T12:00:00Z".to_owned(),
            };
            save_pending_update(&data_dir, &marker).unwrap();
            assert!(load_pending_update(&data_dir).is_some());

            apply_staged_package(&fake_exe, &root).unwrap();
            assert_eq!(fs::read(&fake_exe).unwrap(), b"UPGRADED_VERSION_9_9_9");
        }

        server.abort();
    }
}
