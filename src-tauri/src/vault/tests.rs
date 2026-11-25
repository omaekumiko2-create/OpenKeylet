use super::*;
use tempfile::tempdir;

#[test]
fn module_normalization_preserves_editor_order() {
    let modules = vec![
        ItemModule {
            kind: "url".to_owned(),
            name: String::new(),
            value: "https://example.test".to_owned(),
            agent_visible: None,
        },
        ItemModule {
            kind: "password".to_owned(),
            name: String::new(),
            value: String::new(),
            agent_visible: None,
        },
        ItemModule {
            kind: "host".to_owned(),
            name: String::new(),
            value: "example.test".to_owned(),
            agent_visible: None,
        },
    ];

    let normalized = normalize_modules(modules).unwrap();
    assert_eq!(
        normalized
            .iter()
            .map(|module| module.kind.as_str())
            .collect::<Vec<_>>(),
        vec!["url", "password", "host"]
    );
    assert_eq!(
        normalized
            .iter()
            .map(|module| module.agent_visible)
            .collect::<Vec<_>>(),
        vec![Some(true), Some(false), Some(true)]
    );
}

fn api_input(id: Option<Uuid>, name: &str, token: &str) -> ConnectionInput {
    let mut secrets = SecretBundle::default();
    secrets
        .named_secrets
        .insert("apiCredential".into(), token.to_owned());
    ConnectionInput {
        login_uris: Vec::new(),
        item_type: String::new(),
        folder: String::new(),
        favorite: false,
        id,
        modules: vec![
            ItemModule {
                kind: "url".into(),
                value: "https://api.example.test/v1/".into(),
                ..Default::default()
            },
            ItemModule {
                kind: "apiCredential".into(),
                ..Default::default()
            },
        ],
        name: name.to_owned(),
        enabled: true,
        description: "test connection".to_owned(),
        http_auth_type: "bearer".to_owned(),
        private_key_import_path: String::new(),
        auth_header: "X-API-Key".to_owned(),
        auth_location: "header".to_owned(),
        auth_prefix: String::new(),
        api_auth_headers: vec![],
        test_path: "/health".to_owned(),
        remove_secret_names: vec![],
        secrets,
    }
}

fn ssh_input(id: Option<Uuid>) -> ConnectionInput {
    let mut secrets = SecretBundle::default();
    secrets.password = Some("test-password".to_owned());
    secrets
        .named_secrets
        .insert("username".into(), "root".into());
    ConnectionInput {
        login_uris: Vec::new(),
        item_type: String::new(),
        folder: String::new(),
        favorite: false,
        id,
        modules: vec![
            ItemModule {
                kind: "host".into(),
                value: "127.0.0.1".into(),
                ..Default::default()
            },
            ItemModule {
                kind: "port".into(),
                value: "22".into(),
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
        name: "ssh-test".to_owned(),
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
    }
}

#[test]
fn vault_file_contains_no_plain_secret_and_remains_valid_json() {
    let directory = tempdir().unwrap();
    let vault_dir = directory.path().join("vault");
    let vault = Vault::open(vault_dir.clone()).unwrap();
    vault
        .save_connection(api_input(None, "plain-check", "unique-secret-marker-9437"))
        .unwrap();

    let contents = fs::read_to_string(vault_dir.join("vault.json")).unwrap();
    assert!(!contents.contains("unique-secret-marker-9437"));
    let stored_json: serde_json::Value = serde_json::from_str(&contents).unwrap();
    assert_eq!(stored_json["version"], VAULT_VERSION);
    assert!(stored_json["connections"][0].get("type").is_none());
    assert!(stored_json["connections"][0].get("capabilities").is_none());
    assert!(serde_json::from_str::<VaultDocument>(&contents).is_ok());
    let public = vault.list_connections().unwrap();
    let serialized = serde_json::to_string(&public).unwrap();
    assert!(!serialized.contains("unique-secret-marker-9437"));
    let public_json = serde_json::to_value(&public).unwrap();
    assert!(public_json[0].get("type").is_none());
    assert_eq!(
        public_json[0]["capabilities"],
        serde_json::json!(["fill", "http"])
    );
}

#[test]
fn v7_vault_upgrades_on_write_without_changing_secrets() {
    let directory = tempdir().unwrap();
    let vault_dir = directory.path().join("vault");
    let vault = Vault::open(vault_dir.clone()).unwrap();
    let saved = vault
        .save_connection(api_input(None, "Existing API", "existing-secret-marker"))
        .unwrap();
    let path = vault_dir.join("vault.json");
    let mut fixture: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    fixture["version"] = serde_json::json!(7);
    let encrypted = fixture["connections"][0]["encryptedSecrets"].clone();
    let obsolete = serde_json::json!({
        "type": "ssh",
        "capabilities": ["ssh"],
        "username": "",
        "authType": "obsolete",
        "hostFingerprint": "unused",
        "hostFingerprintHost": "unused.test",
        "hostFingerprintPort": 22,
        "allowedMethods": ["GET"],
        "allowedPathPrefixes": ["/old"],
        "cli": {"executablePath": "old-tool", "actions": []},
        "browser": {"origin": "https://old.test"},
        "credential": {"boundExecutable": "old-tool"}
    });
    fixture["connections"][0]
        .as_object_mut()
        .unwrap()
        .extend(obsolete.as_object().unwrap().clone());
    let old_bytes = serde_json::to_vec_pretty(&fixture).unwrap();
    fs::write(&path, &old_bytes).unwrap();
    drop(vault);

    let reopened = Vault::open(vault_dir.clone()).unwrap();
    let public = reopened.list_connections().unwrap();
    assert_eq!(public[0].capabilities, ["fill", "http"]);
    assert!(public[0].can_test);
    assert_eq!(fs::read(&path).unwrap(), old_bytes);
    reopened.set_connection_enabled(saved.id, false).unwrap();
    let rewritten: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(rewritten["version"], VAULT_VERSION);
    for name in obsolete.as_object().unwrap().keys() {
        assert!(rewritten["connections"][0].get(name).is_none(), "{name}");
    }
    assert_eq!(rewritten["connections"][0]["encryptedSecrets"], encrypted);
    drop(reopened);
    let reopened = Vault::open(vault_dir).unwrap();
    assert_eq!(
        reopened
            .get_connection(saved.id)
            .unwrap()
            .secrets
            .get("apiCredential"),
        Some("existing-secret-marker")
    );
}

#[test]
fn runtime_capabilities_and_saved_test_targets_are_distinct() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let mut input = ssh_input(None);
    input.modules.retain(|module| module.kind == "password");
    let saved = vault.save_connection(input).unwrap();
    assert_eq!(saved.capabilities, ["fill", "ssh", "http"]);
    assert!(!saved.can_test);

    let mut input = ssh_input(Some(saved.id));
    let saved = vault.save_connection(input.clone()).unwrap();
    assert!(saved.can_test);
    let stored = vault.get_connection(saved.id).unwrap();
    assert_eq!(stored.stored.test_target(&stored.secrets), Some("ssh"));

    input.modules.retain(|module| module.kind != "port");
    input.modules.push(ItemModule {
        kind: "url".into(),
        value: "https://example.test".into(),
        ..Default::default()
    });
    let saved = vault.save_connection(input).unwrap();
    assert!(saved.can_test);
    let stored = vault.get_connection(saved.id).unwrap();
    assert_eq!(stored.stored.test_target(&stored.secrets), Some("http"));
}

#[test]
fn reading_an_existing_browser_secret_does_not_rewrite_the_vault() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let secret = vault.browser_bridge_secret().unwrap();
    let path = vault.data_dir().join("vault.json");
    // A normal write prettifies the document; preserve compact bytes to
    // detect even a rewrite that leaves all logical values unchanged.
    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let compact = serde_json::to_vec(&document).unwrap();
    fs::write(&path, &compact).unwrap();

    assert_eq!(vault.browser_bridge_secret().unwrap(), secret);
    assert_eq!(fs::read(path).unwrap(), compact);
}

#[test]
fn editor_draft_encrypts_the_entire_form_and_can_be_reopened() {
    let directory = tempdir().unwrap();
    let vault_dir = directory.path().join("vault");
    let vault = Vault::open(vault_dir.clone()).unwrap();
    let mut input = ssh_input(None);
    input.name = "unfinished-draft-name-7129".to_owned();
    input.description = "unfinished-draft-note-7129".to_owned();
    input.modules = vec![ItemModule {
        kind: "password".to_owned(),
        name: String::new(),
        value: String::new(),
        agent_visible: None,
    }];
    input.secrets.password = Some("unfinished-draft-secret-7129".to_owned());

    let saved = vault.save_editor_draft(None, input).unwrap();
    let contents = fs::read_to_string(vault_dir.join("vault.json")).unwrap();
    assert!(!contents.contains("unfinished-draft-name-7129"));
    assert!(!contents.contains("unfinished-draft-note-7129"));
    assert!(!contents.contains("unfinished-draft-secret-7129"));

    let drafts = vault.list_editor_drafts().unwrap();
    assert_eq!(drafts.len(), 1);
    assert_eq!(drafts[0].id, saved.id);
    assert_eq!(drafts[0].input.name, "unfinished-draft-name-7129");
    assert_eq!(
        drafts[0].input.secrets.password.as_deref(),
        Some("unfinished-draft-secret-7129")
    );

    let existing_item_id = Uuid::new_v4();
    let mut second = ssh_input(Some(existing_item_id));
    second.name = "second-draft".to_owned();
    let second = vault.save_editor_draft(None, second).unwrap();
    let drafts = vault.list_editor_drafts().unwrap();
    assert_eq!(drafts.len(), 2);
    assert_eq!(drafts[0].id, second.id);
    assert_eq!(drafts[0].input.id, Some(existing_item_id));
    assert_eq!(drafts[1].id, saved.id);
    assert_ne!(second.id, saved.id);

    // Updating an existing draft refreshes it in place without duplicating or wiping others.
    let mut updated_first = ssh_input(None);
    updated_first.name = "updated-first-draft".to_owned();
    let updated = vault.save_editor_draft(Some(saved.id), updated_first).unwrap();
    assert_eq!(updated.id, saved.id);
    let drafts = vault.list_editor_drafts().unwrap();
    assert_eq!(drafts.len(), 2);
    assert_eq!(drafts[0].id, saved.id);
    assert_eq!(drafts[0].input.name, "updated-first-draft");
    assert_eq!(drafts[1].id, second.id);

    vault.delete_editor_draft(second.id).unwrap();
    let drafts = vault.list_editor_drafts().unwrap();
    assert_eq!(drafts.len(), 1);
    assert_eq!(drafts[0].id, saved.id);

    vault.delete_editor_draft(saved.id).unwrap();
    let drafts = vault.list_editor_drafts().unwrap();
    assert!(drafts.is_empty());

    // Queue caps at MAX_EDITOR_DRAFTS (10), evicting only the oldest drafts.
    let mut ids = Vec::new();
    for idx in 1..=12 {
        let mut item = ssh_input(None);
        item.name = format!("queued-draft-{idx}");
        ids.push(vault.save_editor_draft(None, item).unwrap().id);
    }
    let queued = vault.list_editor_drafts().unwrap();
    assert_eq!(queued.len(), MAX_EDITOR_DRAFTS);
    assert_eq!(queued[0].id, ids[11]);
    assert_eq!(queued[0].input.name, "queued-draft-12");
    assert_eq!(queued[9].id, ids[2]);
    assert_eq!(queued[9].input.name, "queued-draft-3");
    assert!(!queued.iter().any(|d| d.id == ids[0] || d.id == ids[1]));
}

#[test]
fn automatic_api_requires_only_a_secret_and_normalizes_optional_url() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let mut input = api_input(None, "Addressless API", "opaque-api-secret");
    input.http_auth_type = "auto".to_owned();
    input.modules.retain(|module| module.kind != "url");
    let addressless = vault.save_connection(input).unwrap();
    assert_eq!(addressless.name, "Addressless API");
    assert!(addressless.base_url.is_empty());
    assert_eq!(addressless.http_auth_type, "bearer");

    let mut input = api_input(None, "Example", "another-api-secret");
    input.http_auth_type = "auto".to_owned();
    input
        .modules
        .iter_mut()
        .find(|module| module.kind == "url")
        .unwrap()
        .value = "api.example.test/v1".to_owned();
    let normalized = vault.save_connection(input).unwrap();
    assert_eq!(normalized.base_url, "https://api.example.test/v1");

    let mut input = api_input(None, "Query API", "query-api-secret");
    input
        .modules
        .iter_mut()
        .find(|module| module.kind == "url")
        .unwrap()
        .value = "http://api.example.test/v1?preview=true".to_owned();
    let query_url = vault.save_connection(input).unwrap();
    assert_eq!(
        query_url.base_url,
        "http://api.example.test/v1?preview=true"
    );
}

#[test]
fn url_username_and_password_automatically_enable_basic_http() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let mut input = ssh_input(None);
    input.name = "Basic HTTP".to_owned();
    input.http_auth_type = "auto".to_owned();
    input
        .modules
        .retain(|module| !matches!(module.kind.as_str(), "host" | "port"));
    input.modules.push(ItemModule {
        kind: "url".into(),
        value: "api.example.test/v1".into(),
        ..Default::default()
    });

    let saved = vault.save_connection(input).unwrap();
    assert_eq!(saved.capabilities, vec!["fill", "ssh", "http"]);
    assert_eq!(saved.http_auth_type, "basic");
    assert_eq!(saved.base_url, "https://api.example.test/v1");
}

#[test]
fn explicit_api_transport_settings_survive_editor_saves() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let mut input = api_input(None, "Configured API", "configured-api-secret");
    input.auth_prefix = "Token".to_owned();
    let saved = vault.save_connection(input).unwrap();

    assert_eq!(saved.http_auth_type, "bearer");
    assert_eq!(saved.auth_header, "X-API-Key");
    assert_eq!(saved.auth_prefix, "Token");
    assert_eq!(saved.test_path, "/health");
}

#[test]
fn operational_api_values_are_preserved_instead_of_silently_truncated() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let long_url = format!("https://example.test/{}", "route/".repeat(120));
    let long_test_path = format!("/{}", "health/".repeat(80));
    let long_auth_prefix = "CustomAuthorizationPrefix".repeat(4);
    let mut input = api_input(None, "Long API configuration", "long-api-secret");
    input
        .modules
        .iter_mut()
        .find(|module| module.kind == "url")
        .unwrap()
        .value = long_url.clone();
    input.test_path = long_test_path.clone();
    input.auth_prefix = long_auth_prefix.clone();

    let saved = vault.save_connection(input).unwrap();
    assert_eq!(saved.base_url, long_url);
    assert_eq!(saved.test_path, long_test_path);
    assert_eq!(saved.auth_prefix, long_auth_prefix);
}

#[test]
fn modules_derive_mixed_actions_and_keep_incomplete_items_as_drafts() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let mut mixed = ssh_input(None);
    mixed.http_auth_type = "auto".to_owned();
    mixed.modules = vec![
        ItemModule {
            kind: "host".into(),
            name: String::new(),
            value: "127.0.0.1".into(),
            agent_visible: None,
        },
        ItemModule {
            kind: "port".into(),
            name: String::new(),
            value: "22".into(),
            agent_visible: None,
        },
        ItemModule {
            kind: "username".into(),
            name: String::new(),
            value: String::new(),
            agent_visible: None,
        },
        ItemModule {
            kind: "password".into(),
            name: String::new(),
            value: String::new(),
            agent_visible: None,
        },
        ItemModule {
            kind: "apiCredential".into(),
            name: String::new(),
            value: String::new(),
            agent_visible: None,
        },
    ];
    mixed
        .secrets
        .named_secrets
        .insert("apiCredential".into(), "mixed-api-marker".into());
    let saved = vault.save_connection(mixed).unwrap();
    assert_eq!(saved.capabilities, vec!["fill", "ssh", "http"]);
    assert!(
        saved
            .modules
            .iter()
            .all(|module| module.value != "mixed-api-marker")
    );

    let mut draft = ssh_input(None);
    draft.name = "Draft host".to_owned();
    draft.secrets = SecretBundle::default();
    draft.modules = vec![
        ItemModule {
            kind: "host".into(),
            name: String::new(),
            value: "draft.example".into(),
            agent_visible: None,
        },
        ItemModule {
            kind: "port".into(),
            name: String::new(),
            value: "22".into(),
            agent_visible: None,
        },
        ItemModule {
            kind: "username".into(),
            name: String::new(),
            value: String::new(),
            agent_visible: None,
        },
    ];
    let saved_draft = vault.save_connection(draft).unwrap();
    assert_eq!(saved_draft.capabilities, vec!["note"]);
    assert!(!saved_draft.can_test);
    assert_eq!(saved_draft.name, "Draft host");

    let mut hidden_draft = ssh_input(None);
    hidden_draft.name = "Hidden draft".to_owned();
    hidden_draft.secrets = SecretBundle::default();
    hidden_draft.modules = vec![ItemModule {
        kind: "username".into(),
        name: String::new(),
        value: String::new(),
        agent_visible: None,
    }];
    let saved_hidden = vault.save_connection(hidden_draft).unwrap();
    assert!(saved_hidden.capabilities.is_empty());
}

#[test]
fn ssh_auth_prefers_private_key_over_password_when_both_are_stored() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();

    let mut dual = ssh_input(None);
    dual.name = "Dual auth host".to_owned();
    dual.modules.push(ItemModule {
        kind: "privateKey".into(),
        ..Default::default()
    });
    dual.secrets.private_key = Some(
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntest-key\n-----END OPENSSH PRIVATE KEY-----"
            .to_owned(),
    );
    let saved_dual = vault.save_connection(dual).unwrap();
    assert_eq!(saved_dual.ssh_auth_type, "privateKey");

    let mut pw_only = ssh_input(None);
    pw_only.name = "Password host".to_owned();
    let saved_pw = vault.save_connection(pw_only).unwrap();
    assert_eq!(saved_pw.ssh_auth_type, "password");

    let (item_name, host_kind, host_val, host_secret) =
        vault.get_module_value(saved_dual.id, "host").unwrap();
    assert_eq!(item_name, "Dual auth host");
    assert_eq!(host_kind, "host");
    assert_eq!(host_val, "127.0.0.1");
    assert!(!host_secret);

    let (_, pw_kind, pw_val, pw_secret) =
        vault.get_module_value(saved_dual.id, "password").unwrap();
    assert_eq!(pw_kind, "text");
    assert_eq!(pw_val, "test-password");
    assert!(pw_secret);
    assert!(vault.get_module_value(saved_dual.id, "nonexistent").is_err());
}

#[test]
fn new_items_require_a_name_and_at_least_one_module() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();

    let mut missing_name = ssh_input(None);
    missing_name.name.clear();
    missing_name.modules = vec![ItemModule {
        kind: "password".into(),
        name: String::new(),
        value: String::new(),
        agent_visible: None,
    }];
    assert!(
        vault
            .save_connection(missing_name)
            .unwrap_err()
            .to_string()
            .contains("name")
    );

    let mut missing_modules = ssh_input(None);
    missing_modules.modules.clear();
    assert!(
        vault
            .save_connection(missing_modules)
            .unwrap_err()
            .to_string()
            .contains("module")
    );
}

#[test]
fn item_names_are_unique_ignoring_case_and_outer_whitespace() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let saved = vault
        .save_connection(api_input(None, "Production API", "first-token"))
        .unwrap();

    let duplicate = vault
        .save_connection(api_input(None, "  production api  ", "second-token"))
        .unwrap_err();
    assert!(duplicate.to_string().contains("name already exists"));

    let renamed = vault
        .save_connection(api_input(Some(saved.id), "PRODUCTION API", "first-token"))
        .unwrap();
    assert_eq!(renamed.name, "PRODUCTION API");
}

#[test]
fn unsupported_vault_versions_are_rejected() {
    let directory = tempdir().unwrap();
    let vault_dir = directory.path().join("vault");
    let vault = Vault::open(vault_dir.clone()).unwrap();
    let mut document = vault.read_document().unwrap();
    document.version = 6;
    vault.write_document_unlocked(&document).unwrap();
    drop(vault);

    let error = Vault::open(vault_dir).err().expect("version 6 must fail");
    assert!(format!("{error:#}").contains("supports vault versions 7 through 12"));
}

#[test]
fn removing_a_secret_module_deletes_its_encrypted_value() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let saved = vault.save_connection(ssh_input(None)).unwrap();
    let existing = vault.get_connection(saved.id).unwrap();
    let mut update = ssh_input(Some(saved.id));
    update.secrets = SecretBundle::default();
    update.modules = existing
        .stored
        .modules
        .into_iter()
        .filter(|module| module.kind != "password")
        .collect();
    vault.save_connection(update).unwrap();
    let after = vault.get_connection(saved.id).unwrap();
    assert!(after.secrets.get("password").is_none());
    assert!(!after.stored.has_capability(&after.secrets, "ssh"));
}

#[test]
fn owner_pin_is_hashed_and_owner_view_returns_only_on_explicit_request() {
    let directory = tempdir().unwrap();
    let vault_dir = directory.path().join("vault");
    let vault = Vault::open(vault_dir.clone()).unwrap();
    vault.set_owner_pin("123456").unwrap();
    let saved = vault
        .save_connection(api_input(None, "owner-view", "owner-token-marker-7721"))
        .unwrap();

    assert!(vault.verify_owner_pin("123456").unwrap());
    assert!(!vault.verify_owner_pin("654321").unwrap());
    let raw = fs::read_to_string(vault_dir.join("vault.json")).unwrap();
    assert!(!raw.contains("123456"));
    assert!(!raw.contains("owner-token-marker-7721"));
    let public = serde_json::to_string(&vault.list_connections().unwrap()).unwrap();
    assert!(!public.contains("owner-token-marker-7721"));
    let owner = vault.owner_secret_view(saved.id).unwrap();
    assert_eq!(
        owner
            .fields
            .iter()
            .find(|field| field.name == "apiCredential")
            .map(|field| field.value.as_str()),
        Some("owner-token-marker-7721")
    );

    vault.disable_owner_pin().unwrap();
    assert!(!vault.owner_pin_configured().unwrap());
}

#[test]
fn settings_patches_do_not_overwrite_unrelated_concurrent_changes() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().to_path_buf()).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));

    let language_vault = vault.clone();
    let language_barrier = barrier.clone();
    let language = std::thread::spawn(move || {
        language_barrier.wait();
        language_vault
            .update_settings_patch(SettingsPatch {
                language: Some("en".to_owned()),
                ..SettingsPatch::default()
            })
            .unwrap();
    });

    let browser_vault = vault.clone();
    let browser_barrier = barrier.clone();
    let browser = std::thread::spawn(move || {
        browser_barrier.wait();
        browser_vault
            .update_settings_patch(SettingsPatch {
                browser_enabled: Some(true),
                ..SettingsPatch::default()
            })
            .unwrap();
    });

    barrier.wait();
    language.join().unwrap();
    browser.join().unwrap();

    let settings = vault.settings().unwrap();
    assert_eq!(settings.language, "en");
    assert!(settings.browser_enabled);
}

#[test]
fn concurrent_writes_keep_every_connection() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let handles = (0..4)
        .map(|index| {
            let vault = vault.clone();
            std::thread::spawn(move || {
                vault
                    .save_connection(api_input(
                        None,
                        &format!("connection-{index}"),
                        &format!("secret-token-{index}"),
                    ))
                    .unwrap();
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().unwrap();
    }
    assert_eq!(vault.list_connections().unwrap().len(), 4);
}

#[test]
fn concurrent_first_open_uses_one_initialized_vault() {
    let directory = tempdir().unwrap();
    let vault_dir = Arc::new(directory.path().join("vault"));
    let barrier = Arc::new(std::sync::Barrier::new(6));
    let handles = (0..6)
        .map(|index| {
            let vault_dir = vault_dir.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let vault = Vault::open((*vault_dir).clone()).unwrap();
                vault
                    .save_connection(api_input(
                        None,
                        &format!("first-open-{index}"),
                        &format!("first-open-secret-{index}"),
                    ))
                    .unwrap();
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().unwrap();
    }

    let reopened = Vault::open((*vault_dir).clone()).unwrap();
    let connections = reopened.list_decrypted_connections().unwrap();
    assert_eq!(connections.len(), 6);
    for index in 0..6 {
        assert!(connections.iter().any(|connection| {
            connection.stored.name == format!("first-open-{index}")
                && connection.secrets.get("apiCredential")
                    == Some(format!("first-open-secret-{index}").as_str())
        }));
    }
}

#[test]
fn imported_private_key_survives_source_file_removal() {
    let directory = tempdir().unwrap();
    let vault_dir = directory.path().join("vault");
    let key_path = directory.path().join("id_test");
    let key_marker =
        "-----BEGIN PRIVATE KEY-----\nprivate-key-marker-4382\n-----END PRIVATE KEY-----";
    fs::write(&key_path, key_marker).unwrap();
    let vault = Vault::open(vault_dir.clone()).unwrap();
    let saved = vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: String::new(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![
                ItemModule {
                    kind: "host".into(),
                    value: "127.0.0.1".into(),
                    ..Default::default()
                },
                ItemModule {
                    kind: "port".into(),
                    value: "22".into(),
                    ..Default::default()
                },
                ItemModule {
                    kind: "username".into(),
                    ..Default::default()
                },
                ItemModule {
                    kind: "privateKey".into(),
                    ..Default::default()
                },
            ],
            name: "key-test".into(),
            enabled: true,
            description: String::new(),
            http_auth_type: String::new(),
            private_key_import_path: key_path.to_string_lossy().into_owned(),
            auth_header: String::new(),
            auth_location: String::new(),
            auth_prefix: String::new(),
            api_auth_headers: vec![],
            test_path: String::new(),
            remove_secret_names: vec![],
            secrets: {
                let mut secrets = SecretBundle::default();
                secrets
                    .named_secrets
                    .insert("username".into(), "root".into());
                secrets
            },
        })
        .unwrap();
    fs::remove_file(&key_path).unwrap();

    let decrypted = vault.get_connection(saved.id).unwrap();
    assert_eq!(decrypted.secrets.private_key.as_deref(), Some(key_marker));
    assert_eq!(decrypted.stored.private_key_name, "id_test");
    let raw = fs::read_to_string(vault_dir.join("vault.json")).unwrap();
    assert!(!raw.contains("private-key-marker-4382"));
}

#[test]
fn named_secrets_are_encrypted_preserved_on_empty_and_explicitly_deleted() {
    let directory = tempdir().unwrap();
    let vault_dir = directory.path().join("vault");
    let vault = Vault::open(vault_dir.clone()).unwrap();
    let mut secrets = SecretBundle::default();
    secrets
        .named_secrets
        .insert("password".into(), "browser-secret-marker-7482".into());
    secrets
        .named_secrets
        .insert("username".into(), "developer@example.test".into());
    let input = |id, secrets, remove_secret_names| ConnectionInput {
        login_uris: Vec::new(),
        item_type: String::new(),
        folder: String::new(),
        favorite: false,
        id,
        modules: vec![
            ItemModule {
                kind: "username".into(),
                ..Default::default()
            },
            ItemModule {
                kind: "password".into(),
                ..Default::default()
            },
        ],
        name: "generic-login".into(),
        enabled: true,
        description: String::new(),
        http_auth_type: String::new(),
        private_key_import_path: String::new(),
        auth_header: String::new(),
        auth_location: String::new(),
        auth_prefix: String::new(),
        api_auth_headers: vec![],
        test_path: String::new(),
        remove_secret_names,
        secrets,
    };
    let saved = vault.save_connection(input(None, secrets, vec![])).unwrap();
    assert!(
        !fs::read_to_string(vault_dir.join("vault.json"))
            .unwrap()
            .contains("browser-secret-marker-7482")
    );

    vault
        .save_connection(input(Some(saved.id), SecretBundle::default(), vec![]))
        .unwrap();
    assert_eq!(
        vault
            .get_connection(saved.id)
            .unwrap()
            .secrets
            .named_secrets
            .get("password")
            .map(String::as_str),
        Some("browser-secret-marker-7482")
    );

    vault
        .save_connection(input(
            Some(saved.id),
            SecretBundle::default(),
            vec!["password".into()],
        ))
        .unwrap();
    assert!(
        vault
            .get_connection(saved.id)
            .unwrap()
            .secrets
            .named_secrets
            .get("password")
            .is_none()
    );
}

#[test]
fn secret_lookup_never_aliases_a_longer_module_name() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let module_name = format!("a{}", "x".repeat(79));
    let mut input = api_input(None, "Exact module lookup", "api-secret");
    input.modules.push(ItemModule {
        kind: "customSecret".into(),
        name: module_name.clone(),
        agent_visible: Some(false),
        ..Default::default()
    });
    input
        .secrets
        .named_secrets
        .insert(module_name.clone(), "exact-secret".into());
    let saved = vault.save_connection(input).unwrap();

    assert_eq!(
        vault.get_secret_value(saved.id, &module_name).unwrap().2,
        "exact-secret"
    );
    assert!(
        vault
            .get_secret_value(saved.id, &format!("{module_name}x"))
            .is_err()
    );
}

#[test]
fn custom_secret_modules_accept_natural_names() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let module_name = "Backup verification code";
    let mut input = api_input(None, "Natural module name", "api-secret");
    input.modules.push(ItemModule {
        kind: "customSecret".into(),
        name: module_name.into(),
        agent_visible: Some(false),
        ..Default::default()
    });
    input
        .secrets
        .named_secrets
        .insert(module_name.into(), "custom-value".into());
    let saved = vault.save_connection(input).unwrap();

    assert_eq!(
        vault.get_secret_value(saved.id, module_name).unwrap().2,
        "custom-value"
    );
}

#[test]
fn supports_all_six_interface_languages() {
    let dir = tempdir().unwrap();
    let vault = Vault::open(dir.path().to_path_buf()).unwrap();
    for (input, expected) in [
        ("auto", "auto"),
        ("system", "auto"),
        ("", "auto"),
        ("en", "en"),
        ("zh", "zh"),
        ("zh-CN", "zh"),
        ("zh-TW", "zh-TW"),
        ("zh-Hant", "zh-TW"),
        ("ja", "ja"),
        ("ja-JP", "ja"),
        ("ko", "ko"),
        ("es", "es"),
        ("es-MX", "es"),
        ("unknown", "auto"),
    ] {
        let settings = vault
            .update_settings_patch(SettingsPatch {
                language: Some(input.to_owned()),
                ..SettingsPatch::default()
            })
            .unwrap();
        assert_eq!(settings.language, expected);
    }
}

#[test]
fn deletes_single_batch_and_all_activities() {
    let dir = tempdir().unwrap();
    let vault = Vault::open(dir.path().join("vault")).unwrap();
    for idx in 1..=4 {
        vault
            .add_activity(NewActivity {
                status: if idx % 2 == 0 { "error" } else { "success" }.to_owned(),
                source: "MCP".to_owned(),
                connection_name: format!("Item {idx}"),
                action: format!("action-{idx}"),
                duration_ms: idx * 10,
                error: if idx % 2 == 0 {
                    format!("boom-{idx}")
                } else {
                    String::new()
                },
            })
            .unwrap();
    }
    let initial = vault.activities().unwrap();
    assert_eq!(initial.len(), 4);

    // Single delete removes only the targeted entry and is idempotent.
    let target_id = initial[1].id;
    assert!(vault.delete_activity(target_id).unwrap());
    assert!(!vault.delete_activity(target_id).unwrap());
    let after_single = vault.activities().unwrap();
    assert_eq!(after_single.len(), 3);
    assert!(after_single.iter().all(|a| a.id != target_id));

    // Batch delete removes only matching entries.
    let batch_ids = vec![after_single[0].id, after_single[2].id, Uuid::new_v4()];
    assert_eq!(vault.delete_activities(&batch_ids).unwrap(), 2);
    let after_batch = vault.activities().unwrap();
    assert_eq!(after_batch.len(), 1);
    assert_eq!(after_batch[0].id, after_single[1].id);

    // Clear removes everything remaining.
    vault.clear_activities().unwrap();
    assert!(vault.activities().unwrap().is_empty());
}

#[test]
fn agent_notes_survive_editor_save_backup_and_cloud_sync_merge() {
    let dir = tempdir().unwrap();
    let src = Vault::open(dir.path().join("src")).unwrap();
    let saved = src
        .save_connection(api_input(None, "Sync API", "sync-secret-8899"))
        .unwrap();
    let with_note = src
        .add_agent_note(saved.id, "Production billing endpoint", "CLAUDE CODE", true)
        .unwrap();
    let locked = src.set_agent_notes_locked(saved.id, true).unwrap();
    assert_eq!(locked.agent_notes.len(), 1);
    assert!(locked.agent_notes_locked);

    // Saving regular item fields must preserve existing agent_notes and lock state.
    let mut edited = api_input(Some(saved.id), "Sync API", "sync-secret-8899");
    edited.description = "Updated description".into();
    let after_save = src
        .save_connection_checked(edited, Some(&locked.updated_at))
        .unwrap();
    assert_eq!(after_save.agent_notes.len(), 1);
    assert_eq!(after_save.agent_notes[0].text, "Production billing endpoint");
    assert!(after_save.agent_notes_locked);

    // Export & sync-merge into a fresh target vault preserves notes + lock flag.
    let (exported, trash) = src.export_backup_entries().unwrap();
    let tombstones = src.export_tombstones().unwrap();
    let dst = Vault::open(dir.path().join("dst")).unwrap();
    let merged = dst.sync_merge_entries(exported, trash, tombstones).unwrap();
    assert_eq!(merged.added, 1);
    let dst_item = dst.get_connection(saved.id).unwrap();
    assert_eq!(dst_item.secrets.agent_notes.len(), 1);
    assert_eq!(
        dst_item.secrets.agent_notes[0].text,
        "Production billing endpoint"
    );
    assert!(dst_item.secrets.agent_notes_locked);

    // Later note update on src is detected by sync_merge_entries and synced to dst.
    std::thread::sleep(std::time::Duration::from_millis(5));
    let _ = src.set_agent_notes_locked(saved.id, false).unwrap();
    let _ = src
        .add_agent_note(saved.id, "Supports idempotency keys", "CODEX", true)
        .unwrap();
    let (exported2, trash2) = src.export_backup_entries().unwrap();
    let tombstones2 = src.export_tombstones().unwrap();
    let merged2 = dst
        .sync_merge_entries(exported2, trash2, tombstones2)
        .unwrap();
    assert_eq!(merged2.updated, 1);
    let dst_item2 = dst.get_connection(saved.id).unwrap();
    assert_eq!(dst_item2.secrets.agent_notes.len(), 2);
    assert_eq!(
        dst_item2.secrets.agent_notes[0].text,
        "Supports idempotency keys"
    );
    assert!(!dst_item2.secrets.agent_notes_locked);
    assert_eq!(with_note.agent_notes[0].author, "CLAUDE CODE");
}

fn sample_activity(action: &str) -> NewActivity {
    NewActivity {
        status: "success".to_owned(),
        source: "MCP".to_owned(),
        connection_name: "Logged API".to_owned(),
        action: action.to_owned(),
        duration_ms: 1,
        error: String::new(),
    }
}

fn stored_activity(action: &str, time: &str) -> Activity {
    Activity {
        id: Uuid::new_v4(),
        time: time.to_owned(),
        status: "success".to_owned(),
        source: "MCP".to_owned(),
        connection_name: "Logged API".to_owned(),
        action: action.to_owned(),
        duration_ms: 1,
        error: String::new(),
    }
}

fn activity_actions(vault: &Vault) -> Vec<String> {
    vault
        .activities()
        .unwrap()
        .into_iter()
        .map(|entry| entry.action)
        .collect()
}

#[cfg(unix)]
fn assert_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn activity_log_appends_newest_first_without_rewriting_vault_file() {
    let directory = tempdir().unwrap();
    let vault_dir = directory.path().join("vault");
    let vault = Vault::open(vault_dir.clone()).unwrap();
    vault
        .save_connection(api_input(None, "Logged API", "logged-token-3310"))
        .unwrap();
    let vault_file = vault_dir.join("vault.json");
    let log_file = vault_dir.join("activity.jsonl");
    let before = fs::read(&vault_file).unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(stored["activities"], serde_json::json!([]));
    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(&vault_file).unwrap().ino()
    };

    for index in 0..5 {
        vault
            .add_activity(sample_activity(&format!("action-{index}")))
            .unwrap();
    }
    assert_eq!(
        activity_actions(&vault),
        ["action-4", "action-3", "action-2", "action-1", "action-0"]
    );
    assert_eq!(fs::read_to_string(&log_file).unwrap().lines().count(), 5);
    #[cfg(unix)]
    assert_owner_only(&log_file);

    let listed = vault.activities().unwrap();
    assert!(vault.delete_activity(listed[0].id).unwrap());
    assert_eq!(
        vault
            .delete_activities(&[listed[1].id, listed[3].id])
            .unwrap(),
        2
    );
    assert_eq!(activity_actions(&vault), ["action-2", "action-0"]);
    #[cfg(unix)]
    assert_owner_only(&log_file);
    vault.clear_activities().unwrap();
    assert!(vault.activities().unwrap().is_empty());

    // Logging, deleting and clearing never touch the secrets file.
    assert_eq!(fs::read(&vault_file).unwrap(), before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(fs::metadata(&vault_file).unwrap().ino(), inode);
    }
}

#[test]
fn activity_log_serves_newest_entries_and_compacts_past_the_cap() {
    let directory = tempdir().unwrap();
    let vault_dir = directory.path().join("vault");
    let vault = Vault::open(vault_dir.clone()).unwrap();
    let slack = super::activity_log::ACTIVITY_COMPACT_SLACK;
    let log_file = vault_dir.join("activity.jsonl");
    // Seed a log (oldest first) that sits exactly at the compaction threshold.
    let seeded: Vec<Activity> = (0..MAX_ACTIVITIES + slack)
        .map(|index| stored_activity(&format!("seeded-{index}"), "2001-01-01T00:00:00+00:00"))
        .collect();
    let mut log = String::new();
    for entry in &seeded {
        log.push_str(&serde_json::to_string(entry).unwrap());
        log.push('\n');
    }
    fs::write(&log_file, log).unwrap();

    let listed = vault.activities().unwrap();
    assert_eq!(listed.len(), MAX_ACTIVITIES);
    assert_eq!(listed[0].id, seeded[MAX_ACTIVITIES + slack - 1].id);
    assert_eq!(listed[MAX_ACTIVITIES - 1].id, seeded[slack].id);

    // One more append crosses the threshold and keeps only the newest entries.
    vault.add_activity(sample_activity("newest")).unwrap();
    assert_eq!(
        fs::read_to_string(&log_file).unwrap().lines().count(),
        MAX_ACTIVITIES
    );
    let listed = vault.activities().unwrap();
    assert_eq!(listed.len(), MAX_ACTIVITIES);
    assert_eq!(listed[0].action, "newest");
    assert_eq!(listed[MAX_ACTIVITIES - 1].id, seeded[slack + 1].id);
    #[cfg(unix)]
    assert_owner_only(&log_file);

    // Below the threshold, appends grow the log again without compacting.
    vault
        .add_activity(sample_activity("after-compaction"))
        .unwrap();
    assert_eq!(
        fs::read_to_string(&log_file).unwrap().lines().count(),
        MAX_ACTIVITIES + 1
    );
    assert_eq!(vault.activities().unwrap().len(), MAX_ACTIVITIES);
}

#[test]
fn activity_log_skips_torn_and_malformed_lines() {
    let directory = tempdir().unwrap();
    let vault_dir = directory.path().join("vault");
    let vault = Vault::open(vault_dir.clone()).unwrap();
    vault.add_activity(sample_activity("first")).unwrap();
    vault.add_activity(sample_activity("second")).unwrap();
    let log_file = vault_dir.join("activity.jsonl");
    // Damage in the middle plus a torn trailing line, as left by a crash mid-append.
    let mut file = OpenOptions::new().append(true).open(&log_file).unwrap();
    file.write_all(b"not json\n\xff\xfe\n{\"id\":\"torn-fragment")
        .unwrap();
    drop(file);

    assert_eq!(activity_actions(&vault), ["second", "first"]);
    vault.add_activity(sample_activity("third")).unwrap();
    assert_eq!(activity_actions(&vault), ["third", "second", "first"]);
    let other = Vault::open(vault_dir.clone()).unwrap();
    assert_eq!(activity_actions(&other), ["third", "second", "first"]);

    // The next rewrite drops the damaged lines.
    let oldest = vault.activities().unwrap()[2].id;
    assert!(vault.delete_activity(oldest).unwrap());
    let log = fs::read_to_string(&log_file).unwrap();
    assert_eq!(log.lines().count(), 2);
    assert!(!log.contains("not json"));
    assert!(!log.contains("torn-fragment"));
    assert_eq!(activity_actions(&other), ["third", "second"]);
}

#[test]
fn activity_log_handles_on_one_data_dir_lose_no_entries() {
    let directory = tempdir().unwrap();
    let vault_dir = directory.path().join("vault");
    let first = Vault::open(vault_dir.clone()).unwrap();
    let second = Vault::open(vault_dir.clone()).unwrap();
    for index in 0..20 {
        first
            .add_activity(sample_activity(&format!("first-{index}")))
            .unwrap();
        second
            .add_activity(sample_activity(&format!("second-{index}")))
            .unwrap();
    }
    let expected: Vec<String> = (0..20)
        .rev()
        .flat_map(|index| [format!("second-{index}"), format!("first-{index}")])
        .collect();
    assert_eq!(activity_actions(&first), expected);
    assert_eq!(activity_actions(&second), expected);

    // Separate handles appending concurrently from separate threads.
    let workers: Vec<_> = (0..2)
        .map(|worker| {
            let vault_dir = vault_dir.clone();
            std::thread::spawn(move || {
                let vault = Vault::open(vault_dir).unwrap();
                for index in 0..50 {
                    vault
                        .add_activity(sample_activity(&format!("thread-{worker}-{index}")))
                        .unwrap();
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let all = first.activities().unwrap();
    assert_eq!(all.len(), 140);
    let unique: std::collections::HashSet<Uuid> = all.iter().map(|entry| entry.id).collect();
    assert_eq!(unique.len(), 140);
    assert_eq!(
        fs::read_to_string(vault_dir.join("activity.jsonl"))
            .unwrap()
            .lines()
            .count(),
        140
    );
}

#[test]
fn legacy_vault_activities_move_to_activity_log_once() {
    let directory = tempdir().unwrap();
    let vault_dir = directory.path().join("vault");
    let vault = Vault::open(vault_dir.clone()).unwrap();
    let saved = vault
        .save_connection(api_input(None, "Legacy API", "legacy-token-5521"))
        .unwrap();
    vault
        .add_activity(sample_activity("already-in-log"))
        .unwrap();
    let in_log = vault.activities().unwrap().remove(0);
    drop(vault);

    // An older build kept the log in vault.json, newest first. It also repeats
    // the entry already in the new log, as after an interrupted migration.
    let older = stored_activity("legacy-older", "2001-01-01T00:00:00+00:00");
    let newer = stored_activity("legacy-newer", "2001-01-02T00:00:00+00:00");
    let vault_file = vault_dir.join("vault.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&vault_file).unwrap()).unwrap();
    value["version"] = serde_json::json!(11);
    value["activities"] = serde_json::json!([in_log, newer, older]);
    fs::write(&vault_file, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    let ids = |vault: &Vault| {
        vault
            .activities()
            .unwrap()
            .into_iter()
            .map(|entry| entry.id)
            .collect::<Vec<_>>()
    };
    let reopened = Vault::open(vault_dir.clone()).unwrap();
    assert_eq!(ids(&reopened), [in_log.id, newer.id, older.id]);
    let migrated: serde_json::Value =
        serde_json::from_slice(&fs::read(&vault_file).unwrap()).unwrap();
    assert_eq!(migrated["activities"], serde_json::json!([]));
    // Only the log moved: the on-disk version and the encrypted items are untouched.
    assert_eq!(migrated["version"], 11);
    assert_eq!(migrated["connections"], value["connections"]);
    assert_eq!(
        reopened
            .get_connection(saved.id)
            .unwrap()
            .secrets
            .get("apiCredential"),
        Some("legacy-token-5521")
    );
    drop(reopened);

    // A second open finds nothing to migrate and rewrites neither file.
    let log_file = vault_dir.join("activity.jsonl");
    let vault_bytes = fs::read(&vault_file).unwrap();
    let log_bytes = fs::read(&log_file).unwrap();
    let again = Vault::open(vault_dir.clone()).unwrap();
    assert_eq!(ids(&again), [in_log.id, newer.id, older.id]);
    assert_eq!(fs::read(&vault_file).unwrap(), vault_bytes);
    assert_eq!(fs::read(&log_file).unwrap(), log_bytes);
}

fn login_input(id: Option<Uuid>, name: &str, password: &str) -> ConnectionInput {
    let mut input = ssh_input(id);
    input.name = name.to_owned();
    input.modules = vec![
        ItemModule { kind: "username".into(), ..Default::default() },
        ItemModule { kind: "password".into(), ..Default::default() },
    ];
    input.secrets.password = Some(password.to_owned());
    input
}

fn passkey(credential_id: &str, counter: u32) -> crate::passkey::StoredPasskey {
    crate::passkey::StoredPasskey {
        counter,
        credential_id: credential_id.to_owned(),
        rp_id: "login.example.test".to_owned(),
        user_handle: "dXNlcg".to_owned(),
        user_name: "alice".to_owned(),
        display_name: "Alice".to_owned(),
        private_key: format!("synthetic-key-{credential_id}"),
        discoverable: true,
        created_at: "2026-01-01T00:00:00+00:00".to_owned(),
    }
}

fn entry_for(vault: &Vault, id: Uuid) -> (PortableConnection, SecretBundle) {
    vault
        .export_connections()
        .unwrap()
        .into_iter()
        .find(|(public, _)| public.id == id)
        .unwrap()
}

fn rfc3339(value: &str) -> chrono::DateTime<chrono::FixedOffset> {
    chrono::DateTime::parse_from_rfc3339(value).unwrap()
}

#[test]
fn history_restore_outlives_a_tombstone_dated_in_the_future() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let item = vault
        .save_connection(api_input(None, "Clock skew API", "skew-token-1"))
        .unwrap();
    let version = vault.export_connections().unwrap();
    // A device whose clock runs an hour ahead purged the item.
    let ahead = crate::model::DeletedItemTombstone {
        id: item.id,
        deleted_at: (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
    };
    let removed = vault
        .sync_merge_entries(Vec::new(), Vec::new(), vec![ahead.clone()])
        .unwrap();
    assert_eq!(removed.deleted, 1);

    let summary = vault.restore_history_items(version, "abc1234").unwrap();
    assert_eq!((summary.restored, summary.unchanged), (1, 0));
    let restored = vault.get_connection(item.id).unwrap();
    assert!(rfc3339(&restored.stored.updated_at) > rfc3339(&ahead.deleted_at));
    assert!(vault.export_tombstones().unwrap().is_empty());

    // That device sends its tombstone again: the restored item stays.
    let again = vault
        .sync_merge_entries(Vec::new(), Vec::new(), vec![ahead.clone()])
        .unwrap();
    assert_eq!(again.deleted, 0);
    assert_eq!(
        vault.get_connection(item.id).unwrap().secrets.get("apiCredential"),
        Some("skew-token-1")
    );
    // And it takes the item back from this device's next snapshot.
    let skewed = Vault::open(directory.path().join("skewed")).unwrap();
    skewed
        .sync_merge_entries(Vec::new(), Vec::new(), vec![ahead])
        .unwrap();
    let (active, trash) = vault.export_backup_entries().unwrap();
    let tombstones = vault.export_tombstones().unwrap();
    assert_eq!(skewed.sync_merge_entries(active, trash, tombstones).unwrap().added, 1);
}

#[test]
fn history_restore_keeps_password_history_unions_passkeys_and_leaves_other_items_alone() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let login = vault
        .save_connection(login_input(None, "Shop login", "shop-pass-v1"))
        .unwrap();
    let other = vault
        .save_connection(api_input(None, "Other API", "other-token-v1"))
        .unwrap();
    // The version holds passkey A at counter 3.
    let (mut public, mut secrets) = entry_for(&vault, login.id);
    secrets.passkeys = vec![passkey("cred-a", 3)];
    public.updated_at = Utc::now().to_rfc3339();
    vault
        .sync_merge_entries(vec![(public, secrets)], Vec::new(), Vec::new())
        .unwrap();
    let version = vault.export_connections().unwrap();

    // Since then: a new password, passkey A used up to counter 9, passkey B registered.
    std::thread::sleep(std::time::Duration::from_millis(5));
    vault
        .save_connection(login_input(Some(login.id), "Shop login", "shop-pass-v2"))
        .unwrap();
    let (mut public, mut secrets) = entry_for(&vault, login.id);
    secrets.passkeys = vec![passkey("cred-b", 1), passkey("cred-a", 9)];
    public.updated_at = Utc::now().to_rfc3339();
    vault
        .sync_merge_entries(vec![(public, secrets)], Vec::new(), Vec::new())
        .unwrap();
    vault
        .save_connection(api_input(Some(other.id), "Other API", "other-token-v2"))
        .unwrap();
    let other_before = vault.get_connection(other.id).unwrap().stored.updated_at;

    let selected: Vec<_> = version
        .into_iter()
        .filter(|(public, _)| public.id == login.id)
        .collect();
    let summary = vault
        .restore_history_items(selected.clone(), "abc1234")
        .unwrap();
    assert_eq!((summary.restored, summary.unchanged), (1, 0));

    let restored = vault.get_connection(login.id).unwrap();
    assert_eq!(restored.secrets.get("password"), Some("shop-pass-v1"));
    let history: Vec<&str> = restored
        .secrets
        .password_history
        .iter()
        .map(|entry| entry.password.as_str())
        .collect();
    assert_eq!(history, ["shop-pass-v2", "shop-pass-v1"]);
    let passkeys: Vec<(&str, u32)> = restored
        .secrets
        .passkeys
        .iter()
        .map(|p| (p.credential_id.as_str(), p.counter))
        .collect();
    assert_eq!(passkeys, [("cred-b", 1), ("cred-a", 9)]);

    let untouched = vault.get_connection(other.id).unwrap();
    assert_eq!(untouched.secrets.get("apiCredential"), Some("other-token-v2"));
    assert_eq!(untouched.stored.updated_at, other_before);

    // Decided again at commit time: restoring the same version twice changes nothing more.
    let stamp = restored.stored.updated_at.clone();
    let summary = vault.restore_history_items(selected, "abc1234").unwrap();
    assert_eq!((summary.restored, summary.unchanged), (0, 1));
    assert_eq!(vault.get_connection(login.id).unwrap().stored.updated_at, stamp);
    let restores = activity_actions(&vault)
        .into_iter()
        .filter(|action| action.starts_with("Restore from version abc1234"))
        .count();
    assert_eq!(restores, 1);
}

#[test]
fn history_restore_takes_a_trashed_item_out_of_the_trash_for_good() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let item = vault
        .save_connection(api_input(None, "Trashed API", "trashed-token"))
        .unwrap();
    let version = vault.export_connections().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    vault.trash_connection(item.id, Some(&item.updated_at)).unwrap();
    let (_, remote_trash) = vault.export_backup_entries().unwrap();
    assert_eq!(remote_trash.len(), 1);

    assert_eq!(vault.restore_history_items(version, "abc1234").unwrap().restored, 1);
    assert!(vault.trash_items().unwrap().is_empty());
    assert!(vault.get_connection(item.id).is_ok());
    // Devices that still have it in the trash do not send it back there.
    let merged = vault
        .sync_merge_entries(Vec::new(), remote_trash, Vec::new())
        .unwrap();
    assert_eq!(merged.deleted, 0);
    assert!(vault.get_connection(item.id).is_ok());
    assert!(vault.trash_items().unwrap().is_empty());
}

#[test]
fn importing_a_purged_item_outlives_its_tombstone_on_the_next_sync() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let item = vault
        .save_connection(api_input(None, "Purged API", "purged-token-5521"))
        .unwrap();
    let (backup, backup_trash) = vault.export_backup_entries().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    vault.trash_connection(item.id, Some(&item.updated_at)).unwrap();
    let trashed = vault.trash_items().unwrap();
    vault.purge_connection(item.id, &trashed[0].deleted_at).unwrap();
    // The tombstone has already left this device; every other device holds it.
    let remote_tombstones = vault.export_tombstones().unwrap();
    assert_eq!(remote_tombstones.len(), 1);

    assert_eq!(vault.merge_backup_entries(backup, backup_trash).unwrap().added, 1);
    assert_eq!(vault.get_connection(item.id).unwrap().stored.name, "Purged API");

    let merged = vault
        .sync_merge_entries(Vec::new(), Vec::new(), remote_tombstones.clone())
        .unwrap();
    assert_eq!(merged.deleted, 0, "the next sync must not delete the imported item again");
    assert_eq!(
        vault.get_connection(item.id).unwrap().secrets.get("apiCredential"),
        Some("purged-token-5521")
    );

    // Another device that only knows the tombstone takes the item back as well.
    let other = Vault::open(directory.path().join("other")).unwrap();
    other
        .sync_merge_entries(Vec::new(), Vec::new(), remote_tombstones)
        .unwrap();
    let (active, trash) = vault.export_backup_entries().unwrap();
    let tombstones = vault.export_tombstones().unwrap();
    assert_eq!(other.sync_merge_entries(active, trash, tombstones).unwrap().added, 1);
    assert!(other.get_connection(item.id).is_ok());
}

#[test]
fn backup_import_activity_is_logged_outside_vault_file() {
    let directory = tempdir().unwrap();
    let source = Vault::open(directory.path().join("source")).unwrap();
    source
        .save_connection(api_input(None, "Imported API", "import-token-7781"))
        .unwrap();
    let (exported, trash) = source.export_backup_entries().unwrap();
    let vault_dir = directory.path().join("vault");
    let vault = Vault::open(vault_dir.clone()).unwrap();
    assert_eq!(
        vault.merge_backup_entries(exported, trash).unwrap().added,
        1
    );
    let activities = vault.activities().unwrap();
    assert_eq!(activities.len(), 1);
    assert_eq!(activities[0].source, "Apply");
    assert_eq!(activities[0].connection_name, "Portable backup");
    assert_eq!(
        activities[0].action,
        "Import backup: added 1, merged duplicates 0"
    );
    let stored: serde_json::Value =
        serde_json::from_slice(&fs::read(vault_dir.join("vault.json")).unwrap()).unwrap();
    assert_eq!(stored["activities"], serde_json::json!([]));
}
