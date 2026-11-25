//! Where the vault master key lives, which stored key is used, and how a key
//! left inside the data directory by older versions is moved out of it.
//!
//! The key is kept apart from `vault.json` so that a copy of the data
//! directory, whether taken by a program that steals files or made by a user
//! who zips, uploads or syncs it, does not carry the key with the ciphertext.
//!
//! Candidates, in the order they are tried:
//! 1. the OS keyring (Windows and Linux, default data directory only);
//! 2. the resolved key file (see [`resolve_key_file`]);
//! 3. `<data_dir>/master.key`, when that is not the resolved file;
//! 4. on macOS, the legacy keychain item, read without UI and only for an
//!    existing vault.
//!
//! When the vault already holds ciphertext, a candidate is used only if it
//! decrypts some of it. Otherwise the first key found wins, as it always has.

use super::{
    MasterKey, SECRET_AAD, decode_key, decrypt_bytes, harden_private_file,
    prepare_private_directory, write_private_file,
};
use crate::model::SecretEnvelope;
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use std::{
    ffi::{OsStr, OsString},
    fs, io,
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const KEY_FILE_ENV: &str = "OPENKEYLET_KEY_FILE";
const KEY_FILE_NAME: &str = "master.key";

/// The kind of place the key in use came from, as reported to the owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyPlace {
    OsKeyring,
    FileOutsideDataDir,
    FileInsideDataDir,
    FileFromEnv,
}

impl KeyPlace {
    /// English label for `vault status`, the admin endpoint and `security.storage`.
    pub fn label(self) -> String {
        match self {
            Self::OsKeyring => format!("OS keyring ({})", os_keyring_name()),
            Self::FileOutsideDataDir => "Master key file outside the data directory".to_owned(),
            Self::FileInsideDataDir => "Master key file inside the data directory".to_owned(),
            Self::FileFromEnv => format!("Master key file from {KEY_FILE_ENV}"),
        }
    }

    /// Stable identifier that the desktop renderer localizes.
    pub fn code(self) -> &'static str {
        match self {
            Self::OsKeyring => "osKeyring",
            Self::FileOutsideDataDir => "fileOutsideDataDir",
            Self::FileInsideDataDir => "fileInsideDataDir",
            Self::FileFromEnv => "fileFromEnv",
        }
    }
}

fn os_keyring_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "Windows Credential Manager"
    } else if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else {
        "Linux Secret Service"
    }
}

/// Where a file key belongs. A pure function of its inputs so that every mode
/// can be tested without changing the process environment.
///
/// `user_key_dir` is the per-user directory used with the default data
/// directory ([`default_key_dir`] in production).
pub fn resolve_key_file(
    env_value: Option<&OsStr>,
    explicit_data_dir: bool,
    data_dir: &Path,
    user_key_dir: Option<&Path>,
) -> Result<(PathBuf, KeyPlace)> {
    if let Some(value) = env_value {
        let path = PathBuf::from(value);
        // A relative path would name a different file from each working
        // directory, so one vault could end up with several keys.
        if !path.is_absolute() {
            bail!("{KEY_FILE_ENV} must be an absolute path to the master key file");
        }
        return Ok((path, KeyPlace::FileFromEnv));
    }
    // An explicit data directory stays self-contained and portable.
    if !explicit_data_dir && let Some(directory) = user_key_dir {
        return Ok((directory.join(KEY_FILE_NAME), KeyPlace::FileOutsideDataDir));
    }
    Ok((data_dir.join(KEY_FILE_NAME), KeyPlace::FileInsideDataDir))
}

/// Per-user directory for the key file with the default data directory. Each
/// is a different application folder from the data directory
/// (`…/mcp-vault/v2`); on Windows it is also outside the roaming profile.
pub fn default_key_dir() -> Option<PathBuf> {
    if cfg!(target_os = "windows") {
        dirs::data_local_dir().map(|directory| directory.join("OpenKeylet"))
    } else if cfg!(target_os = "macos") {
        // ~/Library/Application Support/OpenKeylet
        dirs::data_dir().map(|directory| directory.join("OpenKeylet"))
    } else {
        dirs::config_dir().map(|directory| directory.join("openkeylet"))
    }
}

fn key_file_env() -> Option<OsString> {
    // Unit tests open hundreds of temporary vaults through `Vault::open`; a
    // developer's own setting must not point them at a real key file.
    if cfg!(test) {
        None
    } else {
        std::env::var_os(KEY_FILE_ENV)
    }
}

/// A key held by the operating system rather than in a file. A trait so that
/// tests can stand in for the real keyring.
pub trait SystemKeySlot {
    /// The stored key, or `None` when the slot is empty, unreachable or holds
    /// something that is not a key.
    fn read(&self) -> Option<[u8; 32]>;
    /// Stores a newly generated key; `false` sends the caller to a key file.
    fn store(&self, key: &[u8; 32]) -> bool;
}

#[cfg(not(target_os = "macos"))]
struct OsKeyring;

#[cfg(not(target_os = "macos"))]
impl SystemKeySlot for OsKeyring {
    fn read(&self) -> Option<[u8; 32]> {
        let entry = keyring::Entry::new("mcp-vault", "master-key-v2").ok()?;
        let encoded = Zeroizing::new(entry.get_password().ok()?);
        decode_key(&encoded).ok()
    }

    fn store(&self, key: &[u8; 32]) -> bool {
        let Ok(entry) = keyring::Entry::new("mcp-vault", "master-key-v2") else {
            return false;
        };
        let encoded = Zeroizing::new(STANDARD_NO_PAD.encode(key));
        entry.set_password(&encoded).is_ok()
    }
}

#[cfg(target_os = "macos")]
struct LegacyMacosKeychain;

#[cfg(target_os = "macos")]
impl SystemKeySlot for LegacyMacosKeychain {
    fn read(&self) -> Option<[u8; 32]> {
        super::load_legacy_macos_key_without_ui()
    }

    // The keychain was abandoned because it prompts; nothing goes back into it.
    fn store(&self, _key: &[u8; 32]) -> bool {
        false
    }
}

/// Every place the key may be read from, and where a file key is written.
/// Production builds it with [`KeyLocations::for_data_dir`]; tests build it
/// from temporary directories, so they never reach the real home directory,
/// config directory or keyring.
pub struct KeyLocations {
    data_dir: PathBuf,
    keyring: Option<Box<dyn SystemKeySlot>>,
    /// Where a new file key is created and where a legacy one is moved to.
    key_file: PathBuf,
    key_file_place: KeyPlace,
    /// `<data_dir>/master.key` when it is not `key_file`. Older versions kept
    /// the key there and a restored copy of the data directory brings it back
    /// there, so it is always read.
    legacy_file: Option<PathBuf>,
    legacy_keychain: Option<Box<dyn SystemKeySlot>>,
}

impl KeyLocations {
    pub fn for_data_dir(data_dir: &Path) -> Result<Self> {
        let explicit = crate::storage::uses_explicit_data_dir(data_dir);
        let env_value = key_file_env();
        let (key_file, place) = resolve_key_file(
            env_value.as_deref(),
            explicit,
            data_dir,
            default_key_dir().as_deref(),
        )?;
        let mut locations = Self::new(data_dir, key_file, place);
        if cfg!(test) {
            return Ok(locations);
        }
        #[cfg(not(target_os = "macos"))]
        if !explicit {
            locations.keyring = Some(Box::new(OsKeyring));
        }
        #[cfg(target_os = "macos")]
        {
            locations.legacy_keychain = Some(Box::new(LegacyMacosKeychain));
        }
        Ok(locations)
    }

    /// Locations for `data_dir` with the given resolved key file and no OS
    /// key store.
    pub fn new(data_dir: &Path, key_file: PathBuf, key_file_place: KeyPlace) -> Self {
        let in_data_dir = data_dir.join(KEY_FILE_NAME);
        let legacy_file = (in_data_dir != key_file).then_some(in_data_dir);
        Self {
            data_dir: data_dir.to_path_buf(),
            keyring: None,
            key_file,
            key_file_place,
            legacy_file,
            legacy_keychain: None,
        }
    }

    #[cfg(test)]
    pub fn with_keyring(mut self, slot: impl SystemKeySlot + 'static) -> Self {
        self.keyring = Some(Box::new(slot));
        self
    }

    #[cfg(test)]
    pub fn with_legacy_keychain(mut self, slot: impl SystemKeySlot + 'static) -> Self {
        self.legacy_keychain = Some(Box::new(slot));
        self
    }
}

/// Where the chosen key was found.
#[derive(Clone, Copy)]
enum Found {
    Keyring,
    KeyFile,
    LegacyFile,
    LegacyKeychain,
}

pub(super) fn load_or_create(
    locations: &KeyLocations,
    vault_exists: bool,
    probes: &[&SecretEnvelope],
) -> Result<MasterKey> {
    prepare_private_directory(&locations.data_dir)?;
    let opens_vault = |key: &[u8; 32]| {
        probes.is_empty()
            || probes
                .iter()
                .any(|probe| decrypt_bytes(key, probe, SECRET_AAD).is_ok())
    };
    // What each candidate held, for the error message. Never key material.
    let mut looked = Vec::new();
    let mut unreadable_file = false;

    if let Some(keyring) = &locations.keyring {
        let name = KeyPlace::OsKeyring.label();
        match keyring.read() {
            Some(bytes) if opens_vault(&bytes) => {
                return Ok(settle(locations, bytes, Found::Keyring));
            }
            Some(_) => looked.push(format!("{name}: holds a key that does not open this vault")),
            None => looked.push(format!("{name}: no key")),
        }
    }

    let files = [
        (Some(&locations.key_file), locations.key_file_place, Found::KeyFile),
        (
            locations.legacy_file.as_ref(),
            KeyPlace::FileInsideDataDir,
            Found::LegacyFile,
        ),
    ];
    for (path, place, found) in files {
        let Some(path) = path else { continue };
        match read_candidate_file(path, place) {
            Ok(Some(bytes)) if opens_vault(&bytes) => {
                return Ok(settle(locations, bytes, found));
            }
            Ok(Some(_)) => looked.push(format!(
                "{}: holds a key that does not open this vault",
                path.display()
            )),
            Ok(None) => looked.push(format!("{}: not found", path.display())),
            Err(error) => {
                unreadable_file = true;
                looked.push(format!("{}: {error:#}", path.display()));
            }
        }
    }

    if vault_exists && let Some(keychain) = &locations.legacy_keychain {
        match keychain.read() {
            Some(bytes) if opens_vault(&bytes) => {
                return Ok(settle(locations, bytes, Found::LegacyKeychain));
            }
            Some(_) => looked
                .push("legacy macOS Keychain item: holds a key that does not open this vault".to_owned()),
            None => looked.push("legacy macOS Keychain item: not readable without a prompt".to_owned()),
        }
    }

    if vault_exists {
        bail!(
            "Vault master key is missing or does not open this vault, so OpenKeylet did not generate a new key over the existing data. Looked in: {}. Restore the master key file to {}, or import a .mvault backup.",
            looked.join("; "),
            locations.key_file.display()
        );
    }
    if unreadable_file {
        bail!(
            "A master key file exists but cannot be read, so OpenKeylet will not create a new key beside it. {}",
            looked.join("; ")
        );
    }
    create(locations)
}

/// Reads a key file. `Ok(None)` means no file at all; a file that exists but
/// cannot be read or decoded is an error, because it may still be the only
/// copy of a key.
fn read_key_file(path: &Path) -> Result<Option<[u8; 32]>> {
    let encoded = match fs::read_to_string(path) {
        Ok(text) => Zeroizing::new(text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("Unable to read the master key file"),
    };
    decode_key(encoded.trim()).map(Some)
}

fn read_candidate_file(path: &Path, place: KeyPlace) -> Result<Option<[u8; 32]>> {
    let found = read_key_file(path)?;
    // Files OpenKeylet created are kept at 0600. A file named by
    // OPENKEYLET_KEY_FILE belongs to whoever provisioned it and may sit on a
    // read-only mount, so its permissions are left alone.
    if found.is_some() && place != KeyPlace::FileFromEnv {
        harden_private_file(path)?;
    }
    Ok(found)
}

/// Builds the key in use and moves a copy of it out of the data directory.
fn settle(locations: &KeyLocations, bytes: [u8; 32], found: Found) -> MasterKey {
    let at_key_file = || (locations.key_file_place, Some(locations.key_file.clone()));
    let (place, key_file) = match found {
        Found::Keyring => {
            move_legacy_copy(locations, &bytes);
            (KeyPlace::OsKeyring, None)
        }
        Found::KeyFile => {
            move_legacy_copy(locations, &bytes);
            at_key_file()
        }
        Found::LegacyFile => {
            if move_legacy_copy(locations, &bytes) {
                at_key_file()
            } else {
                (KeyPlace::FileInsideDataDir, locations.legacy_file.clone())
            }
        }
        // The keychain item itself is left alone; once the key file exists it
        // is no longer read.
        Found::LegacyKeychain => {
            if matches!(store_at_key_file(locations, &bytes), Ok(true)) {
                at_key_file()
            } else {
                (KeyPlace::OsKeyring, None)
            }
        }
    };
    MasterKey {
        bytes,
        place,
        key_file,
    }
}

/// Moves `<data_dir>/master.key` to the resolved key file when it holds the
/// key in use, and returns whether the legacy copy is gone. Every failure
/// leaves it in place: it is still read, and the move is retried next time.
fn move_legacy_copy(locations: &KeyLocations, key: &[u8; 32]) -> bool {
    let Some(legacy) = &locations.legacy_file else {
        return false;
    };
    // A legacy file holding any other key may be the last copy of that key.
    if !matches!(read_key_file(legacy), Ok(Some(existing)) if same_key(&existing, key)) {
        return false;
    }
    if !matches!(store_at_key_file(locations, key), Ok(true)) {
        return false;
    }
    // Two names can reach one file (a symlink, or OPENKEYLET_KEY_FILE spelled
    // differently); removing the legacy name would then delete the key.
    if may_be_same_file(legacy, &locations.key_file) {
        return false;
    }
    fs::remove_file(legacy).is_ok()
}

/// Makes sure the resolved key file holds `key`, writing it only where no file
/// exists. `Ok(false)`: something else is there and was left untouched.
fn store_at_key_file(locations: &KeyLocations, key: &[u8; 32]) -> Result<bool> {
    match read_key_file(&locations.key_file) {
        Ok(Some(existing)) => return Ok(same_key(&existing, key)),
        Ok(None) => {}
        Err(_) => return Ok(false),
    }
    write_key_file_no_replace(&locations.key_file, key)?;
    // Trust what is on disk, not what was meant to be written.
    Ok(matches!(read_key_file(&locations.key_file)?, Some(written) if same_key(&written, key)))
}

/// Writes a key file that did not exist: temporary file in the same
/// directory, fsync, then a hard link into place. A link fails when the target
/// exists, where a rename would silently replace a key file that another
/// process (say, a second data directory sharing OPENKEYLET_KEY_FILE) created
/// in the meantime. Without hard-link support the write fails, and the caller
/// keeps the key where it was.
fn write_key_file_no_replace(path: &Path, key: &[u8; 32]) -> Result<()> {
    let parent = path
        .parent()
        .context("The master key file path has no parent directory")?;
    let name = path
        .file_name()
        .context("The master key file path has no file name")?;
    create_private_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        uuid::Uuid::new_v4().simple()
    ));
    let encoded = Zeroizing::new(STANDARD_NO_PAD.encode(key));
    write_private_file(&temporary, encoded.as_bytes())?;
    let linked = fs::hard_link(&temporary, path);
    let _ = fs::remove_file(&temporary);
    linked.context("Unable to move the master key file into place")?;
    sync_directory(parent);
    Ok(())
}

/// Reports whether `error` indicates a filesystem that does not support hard
/// links (e.g. FAT32/exFAT removable drives), as distinct from `AlreadyExists`
/// or permission failures.
fn is_hard_link_unsupported(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<io::Error>())
        .any(|io_err| {
            if io_err.kind() == io::ErrorKind::Unsupported {
                return true;
            }
            #[cfg(windows)]
            if matches!(io_err.raw_os_error(), Some(1 | 50)) {
                // ERROR_INVALID_FUNCTION (1) / ERROR_NOT_SUPPORTED (50) on FAT/exFAT
                return true;
            }
            #[cfg(unix)]
            if matches!(io_err.raw_os_error(), Some(libc_enotsup) if libc_enotsup == 95 || libc_enotsup == 45 || libc_enotsup == 38 || libc_enotsup == 18) {
                return true;
            }
            false
        })
}

/// Creates missing directories as 0700 on Unix. Directories that already exist
/// are left as they are: the parent of OPENKEYLET_KEY_FILE may be shared with
/// other software.
fn create_private_dir_all(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .context("Unable to create the master key directory")
}

/// Makes the new directory entry durable before the legacy copy is removed.
/// Best effort, as in SQLite: not every filesystem can sync a directory.
fn sync_directory(path: &Path) {
    #[cfg(unix)]
    if let Ok(directory) = fs::File::open(path) {
        let _ = directory.sync_all();
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Errs towards "yes", because the only caller uses it to avoid deleting the
/// file it keeps.
fn may_be_same_file(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(a), Ok(b)) = (fs::metadata(a), fs::metadata(b))
            && (a.dev(), a.ino()) == (b.dev(), b.ino())
        {
            return true;
        }
    }
    !matches!((fs::canonicalize(a), fs::canonicalize(b)), (Ok(a), Ok(b)) if a != b)
}

fn same_key(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a[..].ct_eq(&b[..]).into()
}

fn create(locations: &KeyLocations) -> Result<MasterKey> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("Unable to generate vault master key:{error}"))?;
    if let Some(keyring) = &locations.keyring
        && keyring.store(&bytes)
    {
        return Ok(MasterKey {
            bytes,
            place: KeyPlace::OsKeyring,
            key_file: None,
        });
    }
    let path = &locations.key_file;
    // Prefer atomic temp-file + fsync + hard_link so an interrupted write never
    // leaves a partial master.key behind. Fall back to `create_new` direct write
    // only on filesystems without hard-link support (e.g. FAT32/exFAT).
    if let Err(error) = write_key_file_no_replace(path, &bytes) {
        if !is_hard_link_unsupported(&error) || path.exists() {
            return Err(error);
        }
        if let Some(parent) = path.parent() {
            create_private_dir_all(parent)?;
        }
        let encoded = Zeroizing::new(STANDARD_NO_PAD.encode(bytes));
        write_private_file(path, encoded.as_bytes())?;
    }
    // Nothing is encrypted with this key yet, so stopping here loses nothing;
    // carrying on with a key that did not reach the disk would.
    if !matches!(read_key_file(path)?, Some(written) if same_key(&written, &bytes)) {
        bail!(
            "The new master key could not be read back from {}",
            path.display()
        );
    }
    Ok(MasterKey {
        bytes,
        place: locations.key_file_place,
        key_file: Some(path.clone()),
    })
}

/// `openkeylet key migrate` on macOS: copies the key from the legacy keychain
/// item (`read` may show the keychain prompt) to the resolved key file.
/// Returns `false` when a key file already exists and nothing needs doing.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn import_legacy_key(
    locations: &KeyLocations,
    read: impl FnOnce() -> Result<[u8; 32]>,
) -> Result<bool> {
    prepare_private_directory(&locations.data_dir)?;
    let existing = [Some(&locations.key_file), locations.legacy_file.as_ref()];
    if existing.into_iter().flatten().any(|path| path.exists()) {
        return Ok(false);
    }
    if !locations.data_dir.join("vault.json").exists() {
        bail!("No legacy vault needs to be migrated");
    }
    let key = Zeroizing::new(read()?);
    if !store_at_key_file(locations, &key)? {
        bail!(
            "{} appeared while migrating and holds a different key; nothing was changed",
            locations.key_file.display()
        );
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
