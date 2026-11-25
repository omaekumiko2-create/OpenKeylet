use super::*;
use serde_json::json;

fn login(name: &str, password: &str, id: Option<Uuid>) -> ConnectionInput {
    serde_json::from_value(json!({"id":id,"name":name,"itemType":"login",
        "modules":[{"kind":"username"},{"kind":"password"},{"kind":"url","value":"https://example.com"}],
        "secrets":{"password":password,"namedSecrets":{"username":"alice"}}})).unwrap()
}

#[test]
fn reorder_connections_persists_without_changing_items() {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::open(directory.path().into()).unwrap();
    for name in ["First", "Second", "Third"] {
        vault.save_connection(login(name, "synthetic-password", None)).unwrap();
    }
    let before = vault.read_document().unwrap();
    let original: Vec<_> = before.connections.iter().map(|item| item.id).collect();
    let reordered = vec![original[2], original[0], original[1]];
    vault.reorder_connections(&reordered, &original).unwrap();
    let reopened = Vault::open(directory.path().into()).unwrap();
    let after = reopened.read_document().unwrap();
    assert_eq!(after.connections.iter().map(|item| item.id).collect::<Vec<_>>(), reordered);
    for item in &after.connections {
        let previous = before.connections.iter().find(|old| old.id == item.id).unwrap();
        assert_eq!(serde_json::to_value(item).unwrap(), serde_json::to_value(previous).unwrap());
        assert_eq!(reopened.get_connection(item.id).unwrap().secrets.get("password"), Some("synthetic-password"));
    }
}

#[test]
fn reorder_connections_rejects_stale_or_invalid_orders_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::open(directory.path().into()).unwrap();
    let first = vault.save_connection(login("First", "one", None)).unwrap();
    let second = vault.save_connection(login("Second", "two", None)).unwrap();
    let original = [first.id, second.id];
    let path = directory.path().join("vault.json");
    let before = std::fs::read(&path).unwrap();
    for invalid in [vec![first.id], vec![first.id, first.id], vec![first.id, Uuid::new_v4()]] {
        assert!(vault.reorder_connections(&invalid, &original).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    vault.reorder_connections(&[second.id, first.id], &original).unwrap();
    let reordered = std::fs::read(&path).unwrap();
    assert!(vault.reorder_connections(&original, &original).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), reordered);
    let other_writer = Vault::open(directory.path().into()).unwrap();
    other_writer.save_connection(login("New item", "new", None)).unwrap();
    let with_new_item = std::fs::read(&path).unwrap();
    assert!(vault.reorder_connections(&original, &[second.id, first.id]).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), with_new_item);
    assert_eq!(vault.list_connections().unwrap().len(), 3);
}

#[test]
fn previous_vault_version_opens_without_rewriting_and_upgrades_on_save() {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::open(directory.path().into()).unwrap();
    let item = vault
        .save_connection(login("Existing", "existing-password", None))
        .unwrap();
    let path = directory.path().join("vault.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["version"] = json!(11);
    value.as_object_mut().unwrap().remove("trash");
    let old = serde_json::to_vec(&value).unwrap();
    std::fs::write(&path, &old).unwrap();
    drop(vault);
    let reopened = Vault::open(directory.path().into()).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), old);
    assert_eq!(
        reopened
            .get_connection(item.id)
            .unwrap()
            .secrets
            .get("password"),
        Some("existing-password")
    );
    reopened.delete_connection(item.id).unwrap();
    assert_eq!(reopened.trash_items().unwrap().len(), 1);
    let current: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(current["version"], 12);
}

#[test]
fn password_history_is_bounded_encrypted_and_owner_only() {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::open(directory.path().into()).unwrap();
    let mut item = vault
        .save_connection(login("Login", "old-secret-0", None))
        .unwrap();
    for i in 1..=22 {
        item = vault
            .save_connection_checked(
                login("Login", &format!("old-secret-{i}"), Some(item.id)),
                Some(&item.updated_at),
            )
            .unwrap();
    }
    let current = vault
        .save_connection_checked(
            login("Login", "old-secret-22", Some(item.id)),
            Some(&item.updated_at),
        )
        .unwrap();
    let history = vault.password_history(item.id).unwrap();
    assert_eq!(history.len(), 20);
    assert_eq!(history[0].password, "old-secret-21");
    assert_eq!(history[19].password, "old-secret-2");
    assert_eq!(current.password_history_count, 20);
    assert!(
        !serde_json::to_string(&current)
            .unwrap()
            .contains("old-secret")
    );
    assert!(
        !serde_json::to_string(&vault.owner_secret_view(item.id).unwrap())
            .unwrap()
            .contains("old-secret-21")
    );
    assert!(vault.get_secret_value(item.id, "passwordHistory").is_err());
    assert!(
        !std::fs::read_to_string(directory.path().join("vault.json"))
            .unwrap()
            .contains("old-secret")
    );
    assert!(
        vault
            .clear_password_history(item.id, &item.updated_at)
            .is_err()
    );
    vault
        .clear_password_history(item.id, &current.updated_at)
        .unwrap();
    assert!(vault.password_history(item.id).unwrap().is_empty());
    assert_eq!(
        vault
            .get_connection(item.id)
            .unwrap()
            .secrets
            .get("password"),
        Some("old-secret-22")
    );
}

#[test]
fn trash_restores_without_overwriting_and_permanent_delete_requires_current_token() {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::open(directory.path().into()).unwrap();
    let old = vault
        .save_connection(login("Same name", "deleted-secret", None))
        .unwrap();
    assert!(vault.trash_connection(old.id, Some("stale")).is_err());
    vault
        .trash_connection(old.id, Some(&old.updated_at))
        .unwrap();
    assert!(vault.list_connections().unwrap().is_empty());
    assert!(vault.get_connection(old.id).is_err());
    assert!(vault.get_secret_value(old.id, "password").is_err());
    assert!(
        vault
            .save_connection(login("Stale editor", "resurrect", Some(old.id)))
            .is_err()
    );
    let trash = vault.trash_items().unwrap();
    assert!(
        !serde_json::to_string(&trash)
            .unwrap()
            .contains("deleted-secret")
    );
    let replacement = vault
        .save_connection(login("Same name", "replacement-secret", None))
        .unwrap();
    assert!(
        vault.purge_connection(replacement.id, "").is_err(),
        "Active items cannot be permanently deleted"
    );
    assert!(vault.restore_connection(old.id, "stale").is_err());
    vault
        .restore_connection(old.id, &trash[0].deleted_at)
        .unwrap();
    let restored = vault.get_connection(old.id).unwrap();
    assert_ne!(restored.stored.name, "Same name");
    assert!(restored.stored.name.starts_with("Same name"));
    assert_eq!(restored.secrets.get("password"), Some("deleted-secret"));
    assert_eq!(
        vault
            .get_connection(replacement.id)
            .unwrap()
            .secrets
            .get("password"),
        Some("replacement-secret")
    );
    vault.delete_connection(old.id).unwrap();
    let trash = vault.trash_items().unwrap();
    assert!(vault.purge_connection(old.id, "stale").is_err());
    vault
        .purge_connection(old.id, &trash[0].deleted_at)
        .unwrap();
    assert!(vault.trash_items().unwrap().is_empty());
    assert!(vault.get_connection(old.id).is_err());
}

#[test]
fn backup_round_trips_trash_and_history_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::open(directory.path().join("original")).unwrap();
    let item = vault
        .save_connection(login("Deleted", "before-change", None))
        .unwrap();
    vault
        .save_connection(login("Deleted", "after-change", Some(item.id)))
        .unwrap();
    vault.delete_connection(item.id).unwrap();
    vault
        .save_connection(login("Active", "active-secret", None))
        .unwrap();
    let bytes = crate::backup::cloud_snapshot(&vault).unwrap();
    let target = Vault::open(directory.path().join("restored")).unwrap();
    assert_eq!(
        crate::backup::restore_cloud_snapshot(&target, &bytes)
            .unwrap()
            .added,
        2
    );
    assert_eq!(target.list_connections().unwrap().len(), 1);
    let trash = target.trash_items().unwrap();
    assert_eq!(trash.len(), 1);
    assert_eq!(
        crate::backup::restore_cloud_snapshot(&target, &bytes)
            .unwrap()
            .merged,
        2
    );
    target
        .restore_connection(item.id, &trash[0].deleted_at)
        .unwrap();
    assert_eq!(
        target.password_history(item.id).unwrap()[0].password,
        "before-change"
    );
    let (active, mut trash) = vault.export_backup_entries().unwrap();
    trash[0].deleted_at = "invalid".into();
    let empty = Vault::open(directory.path().join("atomic")).unwrap();
    assert!(empty.merge_backup_entries(active, trash).is_err());
    assert!(empty.list_connections().unwrap().is_empty());
    assert!(empty.trash_items().unwrap().is_empty());
}

#[tokio::test]
async fn browser_management_is_locked_and_deleted_passkeys_cannot_sign() {
    use crate::browser::vault_rpc::{Session, handle};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::open(directory.path().into()).unwrap();
    vault.set_owner_pin("123456").unwrap();
    let mut session = Session::default();
    let throttle = tokio::sync::Mutex::new(std::time::Instant::now());
    for method in [
        "vault.list",
        "vault.get",
        "vault.save",
        "vault.trash",
        "vault.restore",
        "vault.purge",
        "vault.history",
        "vault.clearHistory",
    ] {
        assert!(
            handle(&vault, &mut session, &throttle, method, &json!({}))
                .await
                .unwrap_err()
                .to_string()
                .contains("locked")
        );
    }
    handle(
        &vault,
        &mut session,
        &throttle,
        "unlock",
        &json!({"pin":"123456"}),
    )
    .await
    .unwrap();
    let first=vault.save_browser_login(&json!({"origin":"https://example.com","name":"Browser login","username":"alice","password":"browser-old"})).unwrap();
    vault.save_browser_login(&json!({"id":first["id"],"expectedUpdatedAt":first["updatedAt"],"origin":"https://example.com","username":"alice","password":"browser-new"})).unwrap();
    let first_id = uuid::Uuid::parse_str(first["id"].as_str().unwrap()).unwrap();
    assert_eq!(vault.password_history(first_id).unwrap()[0].password, "browser-old");
    // Least-privilege browser bridge rejects full-vault history/CRUD RPCs even after PIN unlock.
    assert!(
        handle(&vault, &mut session, &throttle, "vault.history", &json!({"id": first["id"]}))
            .await
            .is_err()
    );
    assert!(
        handle(&vault, &mut session, &throttle, "vault.list", &json!({}))
            .await
            .is_err()
    );
    let options = json!({"challenge":B64.encode([4;32]),"rp":{"id":"example.com"},"user":{"id":B64.encode([3;16]),"name":"alice"},"pubKeyCredParams":[{"type":"public-key","alg":-7}],"authenticatorSelection":{"residentKey":"required"}});
    let (key, _) = crate::passkey::create("https://example.com", &options, true).unwrap();
    let credential_id = key.credential_id.clone();
    vault
        .store_browser_passkey("https://example.com", key, &options)
        .unwrap();
    let passkey = vault
        .list_connections()
        .unwrap()
        .into_iter()
        .find(|item| !item.passkeys.is_empty())
        .unwrap();
    vault.delete_connection(passkey.id).unwrap();
    let request = json!({"rpId":"example.com","challenge":B64.encode([7;32])});
    assert!(
        vault
            .assert_browser_passkey(
                passkey.id,
                &credential_id,
                "https://example.com",
                &request,
                true
            )
            .is_err()
    );
    let prepared = handle(
        &vault,
        &mut session,
        &throttle,
        "passkey.prepare",
        &json!({"origin":"https://example.com","operation":"get","options":request}),
    )
    .await
    .unwrap();
    assert!(prepared["entries"].as_array().unwrap().is_empty());
    let deleted = vault.trash_items().unwrap().remove(0);
    vault
        .restore_connection(passkey.id, &deleted.deleted_at)
        .unwrap();
    assert!(
        vault
            .assert_browser_passkey(
                passkey.id,
                &credential_id,
                "https://example.com",
                &request,
                true
            )
            .is_ok()
    );
    assert!(handle(&vault,&mut session,&throttle,"vault.save",&json!({"input":{"name":"file probe","privateKeyImportPath":"C:/secret","modules":[{"kind":"privateKey"}]}})).await.is_err());
}

#[test]
fn shared_directory_locking_key_source_and_missing_key_safety() {
    let dir = tempfile::tempdir().unwrap();
    let shared_path = dir.path().join("shared-vault");

    // First installation opens the explicit/non-default directory -> uses <dir>/master.key (never OS keyring).
    let inst_a = Vault::open(shared_path.clone()).unwrap();
    assert!(shared_path.join("master.key").is_file());
    assert!(shared_path.join("vault.json").is_file());
    assert!(
        inst_a.storage_label().contains("key file"),
        "expected file-backed key source for explicit directory, got: {}",
        inst_a.storage_label()
    );

    // Second installation opens the exact same directory and reads items encrypted by the first.
    let inst_b = Vault::open(shared_path.clone()).unwrap();
    let mut s1 = SecretBundle::default();
    s1.named_secrets
        .insert("password".to_owned(), "from-instance-a".to_owned());
    let saved_a = inst_a
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
            name: "Shared Item A".to_owned(),
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
            secrets: s1,
        })
        .unwrap();
    assert_eq!(
        inst_b
            .get_secret_value(saved_a.id, "password")
            .unwrap()
            .2,
        "from-instance-a"
    );

    // Concurrent multi-thread readers & serialized writers do not corrupt or lose items.
    let mut handles = Vec::new();
    for worker in 0..4 {
        let path_clone = shared_path.clone();
        handles.push(std::thread::spawn(move || {
            let v = Vault::open(path_clone).unwrap();
            for step in 0..3 {
                let mut sb = SecretBundle::default();
                sb.named_secrets.insert(
                    "password".to_owned(),
                    format!("pw-{worker}-{step}"),
                );
                v.save_connection(ConnectionInput {
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
                    name: format!("Concurrent-{worker}-{step}"),
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
                    secrets: sb,
                })
                .unwrap();
                let _ = v.list_connections().unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(inst_a.list_connections().unwrap().len(), 1 + 4 * 3);

    // Removing master.key while vault.json exists must fail safely and never overwrite or regenerate a key.
    let saved_key_bytes = std::fs::read(shared_path.join("master.key")).unwrap();
    std::fs::remove_file(shared_path.join("master.key")).unwrap();
    let err = Vault::open(shared_path.clone()).err().unwrap().to_string();
    assert!(err.contains("master key is missing"), "unexpected error: {err}");
    assert!(!shared_path.join("master.key").exists());

    // Restoring master.key recovers full access.
    std::fs::write(shared_path.join("master.key"), saved_key_bytes).unwrap();
    let recovered = Vault::open(shared_path).unwrap();
    assert_eq!(recovered.list_connections().unwrap().len(), 13);
}
