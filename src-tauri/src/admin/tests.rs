use super::*;
use crate::model::{ItemModule, SecretBundle};
use tempfile::tempdir;

#[test]
fn non_loopback_bind_is_rejected_by_default() {
    let cfg = AdminServerConfig {
        bind_ip: "0.0.0.0".parse().unwrap(),
        port: DEFAULT_ADMIN_PORT,
        allow_non_loopback: false,
        initial_token: None,
    };
    assert!(cfg.validate().is_err());

    let local_cfg = AdminServerConfig::default();
    assert!(local_cfg.validate().is_ok());
}

#[tokio::test]
async fn admin_server_enforces_auth_hides_secrets_by_default_and_rotates_tokens() {
    let dir = tempdir().unwrap();
    let vault = Vault::open(dir.path().join("vault")).unwrap();
    let mut secrets = SecretBundle::default();
    secrets
        .named_secrets
        .insert("apiCredential".to_owned(), "sk-super-secret-value-123".to_owned());
    let saved = vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: "api".to_owned(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![ItemModule {
                kind: "apiCredential".to_owned(),
                name: "apiCredential".to_owned(),
                value: String::new(),
                agent_visible: Some(false),
            }],
            name: "Prod API".to_owned(),
            enabled: true,
            description: String::new(),
            http_auth_type: "auto".to_owned(),
            private_key_import_path: String::new(),
            auth_header: String::new(),
            auth_location: String::new(),
            auth_prefix: String::new(),
            api_auth_headers: Vec::new(),
            test_path: String::new(),
            remove_secret_names: Vec::new(),
            secrets,
        })
        .unwrap();
    vault.set_owner_pin("654321").unwrap();

    let port = {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        l.local_addr().unwrap().port()
    };
    let running = start(
        vault.clone(),
        AdminServerConfig {
            port,
            ..AdminServerConfig::default()
        },
    )
    .await
    .unwrap();
    let base = format!("http://{}", running.addr);
    let client = reqwest::Client::new();

    // Unauthenticated requests are rejected.
    let unauth = client.get(format!("{base}/api/items")).send().await.unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    // Authenticated list returns metadata without hidden plaintext.
    let list_res = client
        .get(format!("{base}/api/items"))
        .bearer_auth(&*running.token)
        .send()
        .await
        .unwrap();
    assert_eq!(list_res.status(), StatusCode::OK);
    let list_text = list_res.text().await.unwrap();
    assert!(list_text.contains("Prod API"));
    assert!(!list_text.contains("sk-super-secret-value-123"));

    // Reveal requires PIN when configured.
    let no_pin = client
        .post(format!("{base}/api/items/{}/reveal", saved.id))
        .bearer_auth(&*running.token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(no_pin.status(), StatusCode::FORBIDDEN);

    let with_pin = client
        .post(format!("{base}/api/items/{}/reveal", saved.id))
        .bearer_auth(&*running.token)
        .json(&json!({ "pin": "654321" }))
        .send()
        .await
        .unwrap();
    assert_eq!(with_pin.status(), StatusCode::OK);
    let reveal_text = with_pin.text().await.unwrap();
    assert!(reveal_text.contains("sk-super-secret-value-123"));

    // Toggle enabled off.
    let toggle = client
        .post(format!("{base}/api/items/{}/enabled", saved.id))
        .bearer_auth(&*running.token)
        .json(&json!({ "enabled": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(toggle.status(), StatusCode::OK);
    assert!(!vault.get_connection(saved.id).unwrap().stored.enabled);

    // Delete a single activity entry and clear remaining activities.
    for label in ["seed-one", "seed-two"] {
        vault
            .add_activity(NewActivity {
                status: "success".to_owned(),
                source: "admin".to_owned(),
                connection_name: "Prod API".to_owned(),
                action: label.to_owned(),
                duration_ms: 5,
                error: String::new(),
            })
            .unwrap();
    }
    let before_acts = vault.activities().unwrap();
    assert!(before_acts.len() >= 2);
    let del_one: Value = client
        .delete(format!("{base}/api/activities/{}", before_acts[0].id))
        .bearer_auth(&*running.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(del_one["deleted"], Value::Bool(true));
    assert_eq!(vault.activities().unwrap().len(), before_acts.len() - 1);
    let clear_res = client
        .delete(format!("{base}/api/activities"))
        .bearer_auth(&*running.token)
        .send()
        .await
        .unwrap();
    assert_eq!(clear_res.status(), StatusCode::OK);
    assert!(vault.activities().unwrap().is_empty());

    // Rotate token invalidates old token immediately.
    let rotated: Value = client
        .post(format!("{base}/api/session/rotate"))
        .bearer_auth(&*running.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let new_token = rotated["token"].as_str().unwrap().to_owned();
    assert_ne!(new_token, *running.token);

    let old_res = client
        .get(format!("{base}/api/status"))
        .bearer_auth(&*running.token)
        .send()
        .await
        .unwrap();
    assert_eq!(old_res.status(), StatusCode::UNAUTHORIZED);

    let new_res = client
        .get(format!("{base}/api/status"))
        .bearer_auth(&new_token)
        .send()
        .await
        .unwrap();
    assert_eq!(new_res.status(), StatusCode::OK);

    // Revoke kills the session completely.
    let revoke = client
        .post(format!("{base}/api/session/revoke"))
        .bearer_auth(&new_token)
        .send()
        .await
        .unwrap();
    assert_eq!(revoke.status(), StatusCode::OK);
    let after_revoke = client
        .get(format!("{base}/api/status"))
        .bearer_auth(&new_token)
        .send()
        .await
        .unwrap();
    assert_eq!(after_revoke.status(), StatusCode::UNAUTHORIZED);

    running.shutdown().await;
}
