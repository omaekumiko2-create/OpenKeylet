use super::*;
use crate::model::ItemModule;
#[tokio::test]
async fn personal_items_list_only_autofillable_cards_and_identities_when_unlocked() {
    let d = tempfile::tempdir().unwrap();
    let v = Vault::open(d.path().join("original")).unwrap();
    v.set_owner_pin("123456").unwrap();
    let mut session = Session::default();
    let throttle = Mutex::new(Instant::now());

    // Cards, identities and secure notes are managed in the desktop vault.
    let card_input: ConnectionInput = serde_json::from_value(json!({
        "name": "Test card",
        "itemType": "card",
        "folder": "Wallet",
        "favorite": true,
        "modules": [
            {"kind": "cardNumber"},
            {"kind": "cardholderName"},
            {"kind": "cardSecurityCode"},
            {"kind": "cardExpMonth"},
            {"kind": "cardExpYear"}
        ],
        "secrets": {
            "namedSecrets": {
                "cardNumber": "4111111111111111",
                "cardholderName": "Synthetic Cardholder",
                "cardSecurityCode": "987",
                "cardExpMonth": "07",
                "cardExpYear": "2030"
            }
        }
    }))
    .unwrap();
    let saved_card = v.save_connection(card_input).unwrap();
    let note_input: ConnectionInput = serde_json::from_value(json!({
        "name": "Private note",
        "itemType": "secureNote",
        "modules": [{"kind": "secureNote", "value": "must never persist"}],
        "secrets": {"namedSecrets": {"secureNote": "Synthetic private\nmultiline note"}}
    }))
    .unwrap();
    let saved_note = v.save_connection(note_input).unwrap();

    // Locked browser session cannot list or read personal items.
    assert!(handle(&v, &mut session, &throttle, "personal.list", &json!({})).await.is_err());

    handle(&v, &mut session, &throttle, "unlock", &json!({"pin": "123456"}))
        .await
        .unwrap();

    let listed = handle(&v, &mut session, &throttle, "personal.list", &json!({}))
        .await
        .unwrap();
    let items = listed.as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["itemType"], "card");
    assert_eq!(items[0]["subtitle"], "•••• 1111");
    assert!(items[0].get("fields").is_none());

    // Cards can be fetched for autofill; secure notes are strictly rejected by the bridge.
    let card_fields = handle(
        &v,
        &mut session,
        &throttle,
        "personal.get",
        &json!({"id": saved_card.id}),
    )
    .await
    .unwrap();
    assert_eq!(card_fields["fields"]["cardNumber"], "4111111111111111");
    assert!(
        handle(
            &v,
            &mut session,
            &throttle,
            "personal.get",
            &json!({"id": saved_note.id}),
        )
        .await
        .is_err()
    );
}

#[test]
fn shared_vault_password_updates_are_atomic_and_origin_bound() {
    let d = tempfile::tempdir().unwrap();
    let v = Vault::open(d.path().into()).unwrap();
    let mut p = json!({"origin":"https://example.com","username":"alice","password":"super-secret","name":"Example"});
    let saved = v.save_browser_login(&p).unwrap();
    p["id"] = saved["id"].clone();
    p["expectedUpdatedAt"] = saved["updatedAt"].clone();
    p["origin"] = json!("https://evil.example.com");
    assert!(v.save_browser_login(&p).is_err());
    p["origin"] = json!("http://example.com");
    assert!(v.save_browser_login(&p).is_err());
    p["origin"] = json!("https://example.com");
    p["password"] = json!("changed-secret");
    v.save_browser_login(&p).unwrap();
    assert!(v.save_browser_login(&p).is_err());
    assert_eq!(
        v.get_connection(Uuid::parse_str(saved["id"].as_str().unwrap()).unwrap())
            .unwrap()
            .secrets
            .password
            .as_deref(),
        Some("changed-secret")
    );
    let disk = std::fs::read_to_string(d.path().join("vault.json")).unwrap();
    assert!(!disk.contains("changed-secret"));
    assert!(!disk.contains("super-secret"));
}

#[tokio::test]
async fn browser_pin_and_passkey_backup_round_trip() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    let d = tempfile::tempdir().unwrap();
    let v = Vault::open(d.path().join("original")).unwrap();
    v.set_owner_pin("123456").unwrap();
    let mut session = Session::default();
    let throttle = Mutex::new(Instant::now());
    assert!(
        handle(
            &v,
            &mut session,
            &throttle,
            "password.list",
            &json!({"origin":"https://example.com"})
        )
        .await
        .is_err()
    );
    assert!(
        handle(
            &v,
            &mut session,
            &throttle,
            "unlock",
            &json!({"pin":"000000"})
        )
        .await
        .is_err()
    );
    handle(
        &v,
        &mut session,
        &throttle,
        "unlock",
        &json!({"pin":"123456"}),
    )
    .await
    .unwrap();
    assert!(
        handle(
            &v,
            &mut session,
            &throttle,
            "password.list",
            &json!({"origin":"https://example.com"})
        )
        .await
        .is_ok()
    );
    let options = json!({"challenge":B64.encode([2;32]),"rp":{"id":"example.com"},"user":{"id":B64.encode([3;16]),"name":"alice"},
        "pubKeyCredParams":[{"type":"public-key","alg":-7}],"authenticatorSelection":{"residentKey":"required","userVerification":"required"}});
    let (key, _) = passkey::create("https://example.com", &options, true).unwrap();
    let secret = key.private_key.clone();
    let credential_id = key.credential_id.clone();
    v.store_browser_passkey("https://example.com", key.clone(), &options)
        .unwrap();
    let mut exclude = options.clone();
    exclude["excludeCredentials"] = json!([{"type":"public-key","id":credential_id}]);
    assert!(
        v.store_browser_passkey("https://example.com", key, &exclude)
            .is_err()
    );
    let public = v.list_connections().unwrap().remove(0);
    assert!(!serde_json::to_string(&public).unwrap().contains(&secret));
    assert!(
        !serde_json::to_string(&v.owner_secret_view(public.id).unwrap())
            .unwrap()
            .contains(&secret)
    );
    let mut input: ConnectionInput = serde_json::from_value(
        json!({"id":public.id,"name":"Renamed","modules":public.modules}),
    )
    .unwrap();
    v.save_connection_checked(input.clone(), Some(&public.updated_at))
        .unwrap();
    assert!(
        v.save_connection_checked(input.clone(), Some(&public.updated_at))
            .is_err()
    );
    input.name = "After edit".into();
    v.save_connection(input).unwrap();
    assert_eq!(
        v.get_connection(public.id).unwrap().secrets.passkeys.len(),
        1
    );
    let backup = d.path().join("backup.mvault");
    crate::backup::export_to_file(&v, &backup).unwrap();
    let restored = Vault::open(d.path().join("restored")).unwrap();
    crate::backup::import_from_file(&restored, &backup).unwrap();
    let restored = restored.list_decrypted_connections().unwrap();
    let request = json!({"challenge":B64.encode([8;32]),"rpId":"example.com","userVerification":"required"});
    assert!(
        passkey::get(
            &restored[0].secrets.passkeys[0],
            "https://example.com",
            &request,
            true
        )
        .is_ok()
    );
    assert!(
        !std::fs::read_to_string(d.path().join("original/vault.json"))
            .unwrap()
            .contains(&secret)
    );
}

#[tokio::test]
async fn passkey_prepare_fails_fast_on_excluded_and_password_totp_returns_live_code() {
    let d = tempfile::tempdir().unwrap();
    let v = Vault::open(d.path().join("vault")).unwrap();
    let mut session = Session::default();
    let throttle = Mutex::new(Instant::now());

    let options = json!({
        "challenge": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [7; 32]),
        "rp": {"id": "example.com", "name": "Example"},
        "user": {"id": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [9; 16]), "name": "alice", "displayName": "Alice"},
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "authenticatorSelection": {"residentKey": "preferred"}
    });
    let (key, _) = passkey::create("https://example.com", &options, false).unwrap();
    let cred_id = key.credential_id.clone();
    v.store_browser_passkey("https://example.com", key, &options)
        .unwrap();

    let mut dup = options.clone();
    dup["excludeCredentials"] = json!([{"type": "public-key", "id": cred_id}]);
    let err = handle(
        &v,
        &mut session,
        &throttle,
        "passkey.prepare",
        &json!({"origin": "https://example.com", "operation": "create", "options": dup}),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("InvalidStateError:"));

    let mut secrets = SecretBundle::default();
    secrets.password = Some("pw-1".into());
    secrets.named_secrets.insert("username".into(), "alice".into());
    secrets
        .named_secrets
        .insert("totp".into(), "JBSWY3DPEHPK3PXP".into());
    let saved = v
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: "login".into(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![
                ItemModule { kind: "url".into(), value: "https://example.com".into(), ..Default::default() },
                ItemModule { kind: "username".into(), ..Default::default() },
                ItemModule { kind: "password".into(), ..Default::default() },
                ItemModule { kind: "totp".into(), ..Default::default() },
            ],
            name: "Example 2FA".into(),
            enabled: true,
            description: String::new(),
            http_auth_type: String::new(),
            private_key_import_path: String::new(),
            auth_header: String::new(),
            auth_location: String::new(),
            auth_prefix: String::new(),
            api_auth_headers: vec![],
            test_path: String::new(),
            remove_secret_names: vec![],
            secrets,
        })
        .unwrap();

    let listed = handle(
        &v,
        &mut session,
        &throttle,
        "password.list",
        &json!({"origin": "https://example.com/login"}),
    )
    .await
    .unwrap();
    assert_eq!(listed.as_array().unwrap()[0]["hasTotp"], true);

    let totp = handle(
        &v,
        &mut session,
        &throttle,
        "password.totp",
        &json!({"origin": "https://example.com/login", "id": saved.id}),
    )
    .await
    .unwrap();
    let code = totp["code"].as_str().unwrap();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    assert!(totp["remainingSeconds"].as_u64().unwrap() <= 30);

    assert!(
        handle(
            &v,
            &mut session,
            &throttle,
            "password.totp",
            &json!({"origin": "https://evil.example", "id": saved.id}),
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn full_vault_crud_and_quick_rpcs_are_rejected_for_least_privilege() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path().to_path_buf()).unwrap();
    let mut session = Session::default();
    let throttle = Mutex::new(Instant::now());

    // Extension bridge must never expose desktop vault management, trash, history, or quick-ingest CRUD.
    for blocked in [
        "vault.list",
        "vault.get",
        "vault.save",
        "vault.trash",
        "vault.restore",
        "vault.purge",
        "vault.history",
        "vault.clearHistory",
        "personal.save",
        "quick.parse",
        "quick.save",
        "password.attachTotp",
    ] {
        let err = handle(&vault, &mut session, &throttle, blocked, &json!({}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("Unsupported browser operation"),
            "expected {blocked} to be rejected, got: {err}"
        );
    }
}

#[test]
fn store_browser_passkey_for_item_attaches_explicitly_auto_matches_unique_and_falls_back() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path().to_path_buf()).unwrap();

    let make_options = |rp: &str, user_name: &str, handle_byte: u8| {
        json!({
            "challenge": B64.encode([handle_byte; 32]),
            "rp": {"id": rp, "name": rp},
            "user": {"id": B64.encode([handle_byte; 16]), "name": user_name, "displayName": user_name},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {"residentKey": "required"}
        })
    };

    // 1. Explicit target_item_id attaches to an existing item and adds a login_uri rule when base_url doesn't match.
    let mut secrets = SecretBundle::default();
    secrets.password = Some("pw-1".into());
    secrets
        .named_secrets
        .insert("username".into(), "alice@corp.test".into());
    let explicit_target = vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: "login".into(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![
                ItemModule {
                    kind: "url".into(),
                    value: "https://app.example.com".into(),
                    ..Default::default()
                },
                ItemModule {
                    kind: "username".into(),
                    ..Default::default()
                },
                ItemModule {
                    kind: "password".into(),
                    ..Default::default()
                },
            ],
            name: "Corp Account".into(),
            enabled: true,
            description: String::new(),
            http_auth_type: String::new(),
            private_key_import_path: String::new(),
            auth_header: String::new(),
            auth_location: String::new(),
            auth_prefix: String::new(),
            api_auth_headers: vec![],
            test_path: String::new(),
            remove_secret_names: vec![],
            secrets,
        })
        .unwrap();

    let opts1 = make_options("example.com", "alice@corp.test", 1);
    let (key1, _) = passkey::create("https://auth.example.com", &opts1, true).unwrap();
    let stored_name = vault
        .store_browser_passkey_for_item(
            Some(explicit_target.id),
            "https://auth.example.com",
            key1.clone(),
            &opts1,
        )
        .unwrap();
    assert_eq!(stored_name, "Corp Account");
    assert_eq!(vault.list_connections().unwrap().len(), 1);
    let updated = vault.get_connection(explicit_target.id).unwrap();
    assert_eq!(updated.secrets.passkeys.len(), 1);
    assert_eq!(updated.secrets.passkeys[0].credential_id, key1.credential_id);
    assert!(same_origin(&updated.stored, "https://auth.example.com"));
    assert!(same_origin(&updated.stored, "https://app.example.com"));

    // Duplicate credential via excludeCredentials is still rejected across the vault.
    let mut excluded = opts1.clone();
    excluded["excludeCredentials"] =
        json!([{"type": "public-key", "id": key1.credential_id}]);
    assert!(
        vault
            .store_browser_passkey_for_item(
                Some(explicit_target.id),
                "https://auth.example.com",
                key1,
                &excluded,
            )
            .is_err()
    );

    // 2. target_item_id = None auto-attaches to a unique enabled item matching website + username (case-insensitive).
    let saved_login = vault
        .save_browser_login(&json!({
            "origin": "https://login.other.example",
            "username": "Bob@Other.Example",
            "password": "bob-password",
            "name": "Other Login"
        }))
        .unwrap();
    let bob_id = Uuid::parse_str(saved_login["id"].as_str().unwrap()).unwrap();
    let opts2 = make_options("other.example", "bob@other.example", 2);
    let (key2, _) = passkey::create("https://login.other.example", &opts2, true).unwrap();
    let auto_name = vault
        .store_browser_passkey_for_item(None, "https://login.other.example", key2, &opts2)
        .unwrap();
    assert_eq!(auto_name, "Other Login");
    assert_eq!(vault.get_connection(bob_id).unwrap().secrets.passkeys.len(), 1);
    assert_eq!(vault.list_connections().unwrap().len(), 2);

    // 3. target_item_id = None falls back to creating a new Passkey item when no unique match exists.
    let opts3 = make_options("fresh.example", "carol", 3);
    let (key3, _) = passkey::create("https://fresh.example", &opts3, true).unwrap();
    let created_name = vault
        .store_browser_passkey_for_item(None, "https://fresh.example", key3, &opts3)
        .unwrap();
    assert_eq!(created_name, "fresh.example · carol · Passkey");
    assert_eq!(vault.list_connections().unwrap().len(), 3);

    // 4. Ambiguous match (two items for same origin + username) falls back to creating a new Passkey item.
    vault
        .save_browser_login(&json!({
            "origin": "https://dup.example",
            "username": "dave",
            "password": "pw-a",
            "name": "Dup A"
        }))
        .unwrap();
    vault
        .save_browser_login(&json!({
            "origin": "https://dup.example",
            "username": "DAVE",
            "password": "pw-b",
            "name": "Dup B"
        }))
        .unwrap();
    let opts4 = make_options("dup.example", "dave", 4);
    let (key4, _) = passkey::create("https://dup.example", &opts4, true).unwrap();
    let fallback_name = vault
        .store_browser_passkey_for_item(None, "https://dup.example", key4, &opts4)
        .unwrap();
    assert_eq!(fallback_name, "dup.example · dave · Passkey");
    assert_eq!(vault.list_connections().unwrap().len(), 6);
}
