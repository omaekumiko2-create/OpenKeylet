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
        vault
            .save_connection(login(name, "synthetic-password", None))
            .unwrap();
    }
    let before = vault.read_document().unwrap();
    let original: Vec<_> = before.connections.iter().map(|item| item.id).collect();
    let reordered = vec![original[2], original[0], original[1]];
    vault.reorder_connections(&reordered, &original).unwrap();
    let reopened = Vault::open(directory.path().into()).unwrap();
    let after = reopened.read_document().unwrap();
    assert_eq!(
        after
            .connections
            .iter()
            .map(|item| item.id)
            .collect::<Vec<_>>(),
        reordered
    );
    for item in &after.connections {
        let previous = before
            .connections
            .iter()
            .find(|old| old.id == item.id)
            .unwrap();
        assert_eq!(
            serde_json::to_value(item).unwrap(),
            serde_json::to_value(previous).unwrap()
        );
        assert_eq!(
            reopened
                .get_connection(item.id)
                .unwrap()
                .secrets
                .get("password"),
            Some("synthetic-password")
        );
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
    for invalid in [
        vec![first.id],
        vec![first.id, first.id],
        vec![first.id, Uuid::new_v4()],
    ] {
        assert!(vault.reorder_connections(&invalid, &original).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    vault
        .reorder_connections(&[second.id, first.id], &original)
        .unwrap();
    let reordered = std::fs::read(&path).unwrap();
    assert!(vault.reorder_connections(&original, &original).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), reordered);
    let other_writer = Vault::open(directory.path().into()).unwrap();
    other_writer
        .save_connection(login("New item", "new", None))
        .unwrap();
    let with_new_item = std::fs::read(&path).unwrap();
    assert!(
        vault
            .reorder_connections(&original, &[second.id, first.id])
            .is_err()
    );
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
    use crate::browser_vault::{Session, handle};
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
    let history = handle(
        &vault,
        &mut session,
        &throttle,
        "vault.history",
        &json!({"id":first["id"]}),
    )
    .await
    .unwrap();
    assert_eq!(history["entries"][0]["password"], "browser-old");
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
