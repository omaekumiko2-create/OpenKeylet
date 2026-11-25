use super::*;
use crate::{
    model::{ConnectionInput, ItemModule, SecretBundle},
    vault::Vault,
};
use std::{
    cell::RefCell,
    rc::Rc,
    sync::{Arc, Barrier},
};
use tempfile::{TempDir, tempdir};
use uuid::Uuid;

/// A data directory laid out like the default one, and a separate per-user
/// directory standing in for `default_key_dir()`. Both are temporary.
struct Dirs {
    _root: TempDir,
    data: PathBuf,
    user: PathBuf,
}

fn temp_dirs() -> Dirs {
    let root = tempdir().unwrap();
    let data = root.path().join("data").join("mcp-vault").join("v2");
    let user = root.path().join("config").join("openkeylet");
    Dirs {
        _root: root,
        data,
        user,
    }
}

impl Dirs {
    fn legacy(&self) -> PathBuf {
        self.data.join("master.key")
    }

    fn resolved(&self) -> PathBuf {
        self.user.join("master.key")
    }

    /// Where versions before the key file moved kept it.
    fn old_locations(&self) -> KeyLocations {
        KeyLocations::new(&self.data, self.legacy(), KeyPlace::FileInsideDataDir)
    }

    /// The default data directory, with the key file outside it.
    fn locations(&self) -> KeyLocations {
        let (path, place) = resolve_key_file(None, false, &self.data, Some(&self.user)).unwrap();
        KeyLocations::new(&self.data, path, place)
    }

    fn explicit_locations(&self) -> KeyLocations {
        let (path, place) = resolve_key_file(None, true, &self.data, Some(&self.user)).unwrap();
        KeyLocations::new(&self.data, path, place)
    }

    fn user_dir_entries(&self) -> Vec<OsString> {
        let mut names: Vec<_> = fs::read_dir(&self.user)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        names
    }
}

fn open(data: &Path, locations: KeyLocations) -> Result<Vault> {
    Vault::open_with_key_locations(data.to_path_buf(), locations)
}

fn store_secret(vault: &Vault, value: &str) -> Uuid {
    let mut secrets = SecretBundle::default();
    secrets
        .named_secrets
        .insert("password".to_owned(), value.to_owned());
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: "login".to_owned(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![ItemModule {
                kind: "password".to_owned(),
                name: "password".to_owned(),
                value: String::new(),
                agent_visible: Some(false),
            }],
            name: format!("Item {}", Uuid::new_v4()),
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
            secrets,
        })
        .unwrap()
        .id
}

fn secret(vault: &Vault, id: Uuid) -> String {
    vault.get_secret_value(id, "password").unwrap().2
}

fn write_key(path: &Path, key: [u8; 32]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, STANDARD_NO_PAD.encode(key)).unwrap();
}

fn file_key(path: &Path) -> [u8; 32] {
    read_key_file(path).unwrap().expect("key file exists")
}

/// A vault written by a version that kept the key in the data directory.
fn old_vault_with_secret(dirs: &Dirs, value: &str) -> Uuid {
    let vault = open(&dirs.data, dirs.old_locations()).unwrap();
    let id = store_secret(&vault, value);
    assert!(dirs.legacy().is_file());
    id
}

/// Stands in for the OS keyring or the legacy macOS keychain item.
#[derive(Clone)]
struct FakeSlot {
    key: Rc<RefCell<Option<[u8; 32]>>>,
    writable: bool,
}

impl FakeSlot {
    fn new(writable: bool) -> Self {
        Self {
            key: Rc::new(RefCell::new(None)),
            writable,
        }
    }

    fn get(&self) -> Option<[u8; 32]> {
        *self.key.borrow()
    }

    fn set(&self, key: [u8; 32]) {
        *self.key.borrow_mut() = Some(key);
    }
}

impl SystemKeySlot for FakeSlot {
    fn read(&self) -> Option<[u8; 32]> {
        self.get()
    }

    fn store(&self, key: &[u8; 32]) -> bool {
        if self.writable {
            self.set(*key);
        }
        self.writable
    }
}

#[test]
fn key_file_location_follows_the_mode() {
    let root = tempdir().unwrap();
    let data = root.path().join("data");
    let user = root.path().join("user");
    let from_env = root.path().join("secrets").join("vault.key");

    for explicit in [false, true] {
        assert_eq!(
            resolve_key_file(Some(from_env.as_os_str()), explicit, &data, Some(&user)).unwrap(),
            (from_env.clone(), KeyPlace::FileFromEnv)
        );
        for rejected in ["secrets/vault.key", "vault.key", ""] {
            let error =
                resolve_key_file(Some(OsStr::new(rejected)), explicit, &data, Some(&user))
                    .unwrap_err()
                    .to_string();
            assert!(
                error.contains(KEY_FILE_ENV) && error.contains("absolute"),
                "{error}"
            );
        }
    }
    assert_eq!(
        resolve_key_file(None, true, &data, Some(&user)).unwrap(),
        (data.join("master.key"), KeyPlace::FileInsideDataDir)
    );
    assert_eq!(
        resolve_key_file(None, false, &data, Some(&user)).unwrap(),
        (user.join("master.key"), KeyPlace::FileOutsideDataDir)
    );
    assert_eq!(
        resolve_key_file(None, false, &data, None).unwrap(),
        (data.join("master.key"), KeyPlace::FileInsideDataDir)
    );

    // Only a resolved file other than `<data_dir>/master.key` leaves a legacy location to read.
    let outside = KeyLocations::new(&data, user.join("master.key"), KeyPlace::FileOutsideDataDir);
    assert_eq!(outside.legacy_file, Some(data.join("master.key")));
    let inside = KeyLocations::new(&data, data.join("master.key"), KeyPlace::FileInsideDataDir);
    assert_eq!(inside.legacy_file, None);
}

#[test]
fn a_legacy_key_moves_out_of_the_data_directory() {
    let dirs = temp_dirs();
    let id = old_vault_with_secret(&dirs, "moved");
    let original = file_key(&dirs.legacy());

    let vault = open(&dirs.data, dirs.locations()).unwrap();
    assert_eq!(secret(&vault, id), "moved");
    assert!(!dirs.legacy().exists(), "the copy in the data directory is removed");
    assert!(same_key(&file_key(&dirs.resolved()), &original));
    assert_eq!(vault.key_place(), KeyPlace::FileOutsideDataDir);
    assert_eq!(vault.key_file(), Some(dirs.resolved().as_path()));
    assert_eq!(
        vault.storage_label(),
        "Master key file outside the data directory"
    );
    assert_eq!(dirs.user_dir_entries(), [OsString::from("master.key")]);
}

#[test]
fn reopening_after_the_move_reads_the_moved_key() {
    let dirs = temp_dirs();
    let before = old_vault_with_secret(&dirs, "before the move");
    let moved = open(&dirs.data, dirs.locations()).unwrap();
    let after = store_secret(&moved, "after the move");
    drop(moved);

    for _ in 0..2 {
        let vault = open(&dirs.data, dirs.locations()).unwrap();
        assert_eq!(secret(&vault, before), "before the move");
        assert_eq!(secret(&vault, after), "after the move");
        assert_eq!(vault.key_place(), KeyPlace::FileOutsideDataDir);
        assert!(!dirs.legacy().exists());
    }
}

#[test]
fn an_unwritable_key_location_keeps_the_legacy_key() {
    let dirs = temp_dirs();
    let id = old_vault_with_secret(&dirs, "kept");
    let original = fs::read(dirs.legacy()).unwrap();
    // A regular file where the key directory belongs: nobody, root included,
    // can create the directory or the key file there.
    fs::create_dir_all(dirs.user.parent().unwrap()).unwrap();
    fs::write(&dirs.user, "not a directory").unwrap();

    for _ in 0..2 {
        let vault = open(&dirs.data, dirs.locations()).unwrap();
        assert_eq!(secret(&vault, id), "kept");
        assert_eq!(vault.key_place(), KeyPlace::FileInsideDataDir);
        assert_eq!(vault.key_file(), Some(dirs.legacy().as_path()));
    }
    assert_eq!(fs::read(dirs.legacy()).unwrap(), original);
    assert_eq!(fs::read_to_string(&dirs.user).unwrap(), "not a directory");
}

#[test]
fn an_identical_legacy_copy_is_removed() {
    let dirs = temp_dirs();
    let id = old_vault_with_secret(&dirs, "same key twice");
    write_key(&dirs.resolved(), file_key(&dirs.legacy()));
    let resolved_before = fs::read(dirs.resolved()).unwrap();

    let vault = open(&dirs.data, dirs.locations()).unwrap();
    assert_eq!(secret(&vault, id), "same key twice");
    assert!(!dirs.legacy().exists());
    assert_eq!(fs::read(dirs.resolved()).unwrap(), resolved_before);
    assert_eq!(vault.key_place(), KeyPlace::FileOutsideDataDir);
}

#[test]
fn the_key_that_opens_the_vault_wins_and_nothing_is_deleted() {
    // The resolved location holds another vault's key and comes first; the
    // legacy file holds this vault's key.
    let dirs = temp_dirs();
    let id = old_vault_with_secret(&dirs, "legacy key");
    write_key(&dirs.resolved(), [7; 32]);
    let legacy_before = fs::read(dirs.legacy()).unwrap();
    let resolved_before = fs::read(dirs.resolved()).unwrap();

    let vault = open(&dirs.data, dirs.locations()).unwrap();
    assert_eq!(secret(&vault, id), "legacy key");
    assert_eq!(vault.key_place(), KeyPlace::FileInsideDataDir);
    assert_eq!(vault.key_file(), Some(dirs.legacy().as_path()));
    drop(vault);
    assert_eq!(fs::read(dirs.legacy()).unwrap(), legacy_before);
    assert_eq!(fs::read(dirs.resolved()).unwrap(), resolved_before);

    // The other way round: a restored legacy file holding another key is
    // neither used nor deleted.
    let dirs = temp_dirs();
    let vault = open(&dirs.data, dirs.locations()).unwrap();
    let id = store_secret(&vault, "resolved key");
    drop(vault);
    write_key(&dirs.legacy(), [9; 32]);
    let legacy_before = fs::read(dirs.legacy()).unwrap();

    let vault = open(&dirs.data, dirs.locations()).unwrap();
    assert_eq!(secret(&vault, id), "resolved key");
    assert_eq!(vault.key_place(), KeyPlace::FileOutsideDataDir);
    assert_eq!(fs::read(dirs.legacy()).unwrap(), legacy_before);
}

#[test]
fn a_vault_without_a_usable_key_fails_and_no_key_is_generated() {
    let dirs = temp_dirs();
    old_vault_with_secret(&dirs, "unreachable");
    fs::remove_file(dirs.legacy()).unwrap();

    let error = open(&dirs.data, dirs.locations()).err().unwrap().to_string();
    assert!(error.contains("master key is missing"), "{error}");
    assert!(error.contains(&dirs.resolved().display().to_string()), "{error}");
    assert!(error.contains(&dirs.legacy().display().to_string()), "{error}");
    assert!(error.contains(".mvault"), "{error}");
    assert!(!dirs.resolved().exists());
    assert!(!dirs.legacy().exists());

    // A key that does not open the vault is reported, kept and not joined by a new one.
    write_key(&dirs.resolved(), [3; 32]);
    let error = open(&dirs.data, dirs.locations()).err().unwrap().to_string();
    assert!(error.contains("does not open this vault"), "{error}");
    assert!(same_key(&file_key(&dirs.resolved()), &[3; 32]));
    assert!(!dirs.legacy().exists());
    assert_eq!(dirs.user_dir_entries(), [OsString::from("master.key")]);
}

#[test]
fn an_unreadable_key_file_is_never_joined_by_a_new_key() {
    let dirs = temp_dirs();
    fs::create_dir_all(&dirs.user).unwrap();
    fs::write(dirs.resolved(), "damaged").unwrap();

    let error = open(&dirs.data, dirs.locations()).err().unwrap().to_string();
    assert!(error.contains("cannot be read"), "{error}");
    assert_eq!(fs::read_to_string(dirs.resolved()).unwrap(), "damaged");
    assert!(!dirs.legacy().exists());
    assert!(!dirs.data.join("vault.json").exists());
}

#[test]
fn an_explicit_data_directory_keeps_its_key_inside() {
    let dirs = temp_dirs();
    let vault = open(&dirs.data, dirs.explicit_locations()).unwrap();
    let id = store_secret(&vault, "portable");
    assert_eq!(vault.key_place(), KeyPlace::FileInsideDataDir);
    assert_eq!(vault.key_file(), Some(dirs.legacy().as_path()));
    drop(vault);

    let reopened = open(&dirs.data, dirs.explicit_locations()).unwrap();
    assert_eq!(secret(&reopened, id), "portable");
    drop(reopened);
    assert!(dirs.legacy().is_file());
    assert!(!dirs.user.exists(), "nothing is written outside the directory");

    fs::remove_file(dirs.legacy()).unwrap();
    let error = open(&dirs.data, dirs.explicit_locations())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("master key is missing"), "{error}");
    assert!(!dirs.legacy().exists());
    assert!(!dirs.user.exists());
}

#[test]
fn concurrent_first_opens_agree_on_one_key() {
    for _ in 0..10 {
        let dirs = temp_dirs();
        let barrier = Arc::new(Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|index| {
                let (data, user) = (dirs.data.clone(), dirs.user.clone());
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let (path, place) = resolve_key_file(None, false, &data, Some(&user)).unwrap();
                    let locations = KeyLocations::new(&data, path, place);
                    barrier.wait();
                    let vault = open(&data, locations).unwrap();
                    store_secret(&vault, &format!("thread {index}"))
                })
            })
            .collect();
        let ids: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();

        let vault = open(&dirs.data, dirs.locations()).unwrap();
        for (index, id) in ids.into_iter().enumerate() {
            assert_eq!(secret(&vault, id), format!("thread {index}"));
        }
        assert!(!dirs.legacy().exists());
        assert_eq!(dirs.user_dir_entries(), [OsString::from("master.key")]);
    }
}

#[test]
fn fresh_create_writes_atomically_and_leaves_no_temp_files() {
    let dirs = temp_dirs();
    let vault = open(&dirs.data, dirs.locations()).unwrap();
    let id = store_secret(&vault, "fresh atomic");
    assert_eq!(vault.key_place(), KeyPlace::FileOutsideDataDir);
    assert_eq!(dirs.user_dir_entries(), [OsString::from("master.key")]);
    drop(vault);

    let reopened = open(&dirs.data, dirs.locations()).unwrap();
    assert_eq!(secret(&reopened, id), "fresh atomic");
}

#[test]
fn the_keyring_keeps_priority_and_a_stale_entry_is_skipped() {
    let dirs = temp_dirs();
    let keyring = FakeSlot::new(true);
    let vault = open(&dirs.data, dirs.locations().with_keyring(keyring.clone())).unwrap();
    let id = store_secret(&vault, "keyring vault");
    assert_eq!(vault.key_place(), KeyPlace::OsKeyring);
    assert_eq!(vault.key_file(), None);
    drop(vault);
    assert!(!dirs.resolved().exists() && !dirs.legacy().exists());

    // Someone replaces the keyring entry; the vault's key survives in the key file.
    write_key(&dirs.resolved(), keyring.get().unwrap());
    keyring.set([5; 32]);
    let vault = open(&dirs.data, dirs.locations().with_keyring(keyring.clone())).unwrap();
    assert_eq!(secret(&vault, id), "keyring vault");
    assert_eq!(vault.key_place(), KeyPlace::FileOutsideDataDir);
    assert_eq!(keyring.get(), Some([5; 32]), "the keyring entry is left alone");
}

#[test]
fn a_legacy_keychain_key_is_copied_to_the_resolved_key_file() {
    let dirs = temp_dirs();
    let id = old_vault_with_secret(&dirs, "keychain era");
    let keychain = FakeSlot::new(false);
    keychain.set(file_key(&dirs.legacy()));
    fs::remove_file(dirs.legacy()).unwrap();

    let vault = open(&dirs.data, dirs.locations().with_legacy_keychain(keychain.clone())).unwrap();
    assert_eq!(secret(&vault, id), "keychain era");
    assert_eq!(vault.key_place(), KeyPlace::FileOutsideDataDir);
    assert!(same_key(&file_key(&dirs.resolved()), &keychain.get().unwrap()));
    assert!(!dirs.legacy().exists(), "nothing is written into the data directory");
    drop(vault);

    let reopened = open(&dirs.data, dirs.locations()).unwrap();
    assert_eq!(secret(&reopened, id), "keychain era");
}

#[test]
fn key_migrate_writes_the_keychain_key_to_the_resolved_key_file() {
    let dirs = temp_dirs();
    let id = old_vault_with_secret(&dirs, "migrated by command");
    let key = file_key(&dirs.legacy());
    fs::remove_file(dirs.legacy()).unwrap();

    assert!(import_legacy_key(&dirs.locations(), || Ok(key)).unwrap());
    assert!(same_key(&file_key(&dirs.resolved()), &key));
    assert!(!dirs.legacy().exists());
    // With a key file in place there is nothing to do and the keychain is not read.
    assert!(!import_legacy_key(&dirs.locations(), || panic!("keychain read")).unwrap());

    let vault = open(&dirs.data, dirs.locations()).unwrap();
    assert_eq!(secret(&vault, id), "migrated by command");
}

#[test]
fn placing_a_key_file_never_replaces_one() {
    // Another process may create the file between the existence check and
    // the write; whatever it wrote must survive.
    let dirs = temp_dirs();
    write_key(&dirs.resolved(), [1; 32]);
    assert!(write_key_file_no_replace(&dirs.resolved(), &[2; 32]).is_err());
    assert!(same_key(&file_key(&dirs.resolved()), &[1; 32]));
    assert_eq!(dirs.user_dir_entries(), [OsString::from("master.key")]);
}

#[cfg(unix)]
#[test]
fn a_key_file_reached_through_two_names_is_not_deleted() {
    let dirs = temp_dirs();
    let id = old_vault_with_secret(&dirs, "one file, two names");
    fs::create_dir_all(&dirs.user).unwrap();
    std::os::unix::fs::symlink(dirs.legacy(), dirs.resolved()).unwrap();

    for _ in 0..2 {
        let vault = open(&dirs.data, dirs.locations()).unwrap();
        assert_eq!(secret(&vault, id), "one file, two names");
        assert!(dirs.legacy().is_file());
    }
}

#[cfg(unix)]
#[test]
fn key_files_and_new_directories_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;

    let created = temp_dirs();
    open(&created.data, created.locations()).unwrap();
    assert_eq!(mode(&created.resolved()), 0o600);
    assert_eq!(mode(&created.user), 0o700);
    assert_eq!(mode(&created.data), 0o700);

    let moved = temp_dirs();
    old_vault_with_secret(&moved, "moved");
    open(&moved.data, moved.locations()).unwrap();
    assert_eq!(mode(&moved.resolved()), 0o600);
    assert_eq!(mode(&moved.user), 0o700);
}

#[test]
fn openkeylet_key_file_overrides_os_keyring_in_default_mode() {
    let dirs = temp_dirs();
    let custom_key = dirs._root.path().join("custom").join("vault.key");
    let keyring = FakeSlot::new(true);
    keyring.set([42; 32]);

    // Default data directory + explicit OPENKEYLET_KEY_FILE must bypass the OS
    // keyring instead of silently reading from or creating into it.
    let locations = KeyLocations::build(
        &dirs.data,
        false,
        Some(custom_key.as_os_str()),
        Some(&dirs.user),
        Some(Box::new(keyring.clone())),
    )
    .unwrap();
    assert!(locations.keyring.is_none());

    let vault = open(&dirs.data, locations).unwrap();
    let id = store_secret(&vault, "env-file-secret");
    assert_eq!(vault.key_place(), KeyPlace::FileFromEnv);
    assert_eq!(vault.key_file(), Some(custom_key.as_path()));
    assert!(custom_key.is_file());
    assert!(!dirs.resolved().exists());
    assert!(!dirs.legacy().exists());
    assert_eq!(
        keyring.get(),
        Some([42; 32]),
        "existing OS keyring entry must not be modified or preferred"
    );
    drop(vault);

    // Reopening with OPENKEYLET_KEY_FILE reads the custom key file directly.
    let reopen_locations = KeyLocations::build(
        &dirs.data,
        false,
        Some(custom_key.as_os_str()),
        Some(&dirs.user),
        Some(Box::new(keyring.clone())),
    )
    .unwrap();
    let reopened = open(&dirs.data, reopen_locations).unwrap();
    assert_eq!(secret(&reopened, id), "env-file-secret");
    assert_eq!(reopened.key_place(), KeyPlace::FileFromEnv);
    assert_eq!(reopened.key_file(), Some(custom_key.as_path()));

    // Without OPENKEYLET_KEY_FILE in default mode, OS keyring stays enabled.
    let default_locations = KeyLocations::build(
        &dirs.data,
        false,
        None,
        Some(&dirs.user),
        Some(Box::new(keyring)),
    )
    .unwrap();
    assert!(default_locations.keyring.is_some());
}

#[cfg(windows)]
#[test]
fn windows_key_files_and_new_directories_have_owner_only_protected_dacl() {
    use super::super::windows_acl::{current_user_sid, read_dacl_sddl};

    let sid = current_user_sid().unwrap();
    let assert_owner_only = |path: &Path| {
        let sddl = read_dacl_sddl(path).unwrap();
        assert!(
            sddl.starts_with("D:P"),
            "expected protected DACL on {}: {sddl}",
            path.display()
        );
        assert!(
            sddl.contains(sid),
            "expected current user SID {sid} in DACL on {}: {sddl}",
            path.display()
        );
        for broad in [";;;WD)", ";;;BU)", ";;;AU)"] {
            assert!(
                !sddl.contains(broad),
                "unexpected broad principal {broad} in DACL on {}: {sddl}",
                path.display()
            );
        }
    };

    // 1. Fresh vault creates private key file, new key dir, and data dir.
    let created = temp_dirs();
    open(&created.data, created.locations()).unwrap();
    assert_owner_only(&created.resolved());
    assert_owner_only(&created.user);
    assert_owner_only(&created.data);

    // 2. Existing parent directory for OPENKEYLET_KEY_FILE is left untouched,
    //    while the newly created key file itself gets a protected owner-only DACL.
    let env_case = temp_dirs();
    let shared_parent = env_case._root.path().join("existing-shared");
    fs::create_dir_all(&shared_parent).unwrap();
    let parent_sddl_before = read_dacl_sddl(&shared_parent).unwrap();
    let custom_key = shared_parent.join("custom.key");
    let locations = KeyLocations::build(
        &env_case.data,
        false,
        Some(custom_key.as_os_str()),
        Some(&env_case.user),
        None,
    )
    .unwrap();
    open(&env_case.data, locations).unwrap();
    assert_owner_only(&custom_key);
    assert_eq!(
        read_dacl_sddl(&shared_parent).unwrap(),
        parent_sddl_before,
        "existing parent directory ACL must not be rewritten"
    );
}
