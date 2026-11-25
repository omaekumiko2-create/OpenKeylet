use super::*;
use crate::model::{ApiAuthHeader, ItemModule, SecretEnvelope};
use axum::{
    Router,
    body::Bytes,
    extract::Query,
    http::HeaderMap as AxumHeaders,
    response::Redirect,
    routing::{get, post},
};
use chrono::Utc;
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn ssh_connection_test_accepts_windows_and_unix_line_endings() {
    let mut result = SshResponse {
        exit_code: Some(0),
        signal: None,
        stdout: "mcp-vault-ok\r\n".into(),
        stderr: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    };
    assert!(validate_ssh_connection_test(&result).is_ok());
    result.stdout = "mcp-vault-ok\n".into();
    assert!(validate_ssh_connection_test(&result).is_ok());
    result.exit_code = Some(1);
    assert!(validate_ssh_connection_test(&result).is_err());
    result.exit_code = Some(0);
    result.stdout = "unexpected\n".into();
    assert!(validate_ssh_connection_test(&result).is_err());
}

fn stored(base_url: String) -> StoredConnection {
    StoredConnection {
        login_uris: Vec::new(),
        item_type: String::new(),
        folder: String::new(),
        favorite: false,
        id: Uuid::new_v4(),
        modules: vec![],
        name: "local-api".into(),
        enabled: true,
        created_at: Utc::now().to_rfc3339(),
        updated_at: Utc::now().to_rfc3339(),
        description: String::new(),
        host: String::new(),
        port: 0,
        ssh_auth_type: String::new(),
        http_auth_type: "bearer".into(),
        private_key_name: String::new(),
        base_url,
        auth_header: "X-API-Key".into(),
        auth_location: "header".into(),
        auth_prefix: String::new(),
        api_auth_headers: vec![],
        test_path: String::new(),
        secret: None,
        encrypted_secrets: SecretEnvelope {
            version: 1,
            nonce: String::new(),
            ciphertext: String::new(),
        },
    }
}

#[tokio::test]
async fn runtime_target_item_does_not_offer_a_fake_connection_test() {
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let mut stored = stored(String::new());
    stored.modules.push(ItemModule {
        kind: "password".to_owned(),
        ..Default::default()
    });
    let mut secrets = SecretBundle::default();
    secrets.password = Some("synthetic-runtime-password".to_owned());
    let connection = DecryptedConnection { stored, secrets };
    assert!(connection.stored.has_capability(&connection.secrets, "ssh"));
    assert!(
        connection
            .stored
            .has_capability(&connection.secrets, "http")
    );
    assert!(!connection.stored.public(Some(&connection.secrets)).can_test);
    assert_eq!(
        test_connection(&vault, &connection)
            .await
            .unwrap_err()
            .to_string(),
        "This project has no connection target that can be tested automatically"
    );
}

#[test]
fn remote_parent_paths_are_normalized_and_incremental() {
    assert_eq!(
        remote_parent_directories("/home/user/project/file.txt"),
        vec!["/home", "/home/user", "/home/user/project"]
    );
    assert_eq!(
        remote_parent_directories("/home/user/../shared/file.txt"),
        vec!["/home", "/home/shared"]
    );
    assert_eq!(
        remote_parent_directories("C:\\Users\\me\\file.txt"),
        vec!["C:", "C:/Users", "C:/Users/me"]
    );
    assert_eq!(
        remote_parent_directories("C:/../shared/file.txt"),
        vec!["C:", "C:/shared"]
    );
    assert!(remote_parent_directories("file.txt").is_empty());
}

#[tokio::test]
async fn local_transfer_commit_preserves_existing_files_until_replacement_is_ready() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("download.txt");
    let refused_temporary = directory.path().join("refused.part");
    std::fs::write(&destination, "old").unwrap();
    std::fs::write(&refused_temporary, "new").unwrap();

    assert!(
        commit_local_file(&refused_temporary, &destination, false)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read_to_string(&destination).unwrap(), "old");
    assert_eq!(std::fs::read_to_string(&refused_temporary).unwrap(), "new");

    commit_local_file(&refused_temporary, &destination, true)
        .await
        .unwrap();
    assert_eq!(std::fs::read_to_string(&destination).unwrap(), "new");
    assert!(!refused_temporary.exists());
    assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".backup")
    }));

    let fresh_temporary = directory.path().join("fresh.part");
    let fresh_destination = directory.path().join("fresh.txt");
    std::fs::write(&fresh_temporary, "fresh").unwrap();
    commit_local_file(&fresh_temporary, &fresh_destination, false)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(&fresh_destination).unwrap(),
        "fresh"
    );

    let directory_destination = directory.path().join("existing-directory");
    let directory_temporary = directory.path().join("directory.part");
    std::fs::create_dir(&directory_destination).unwrap();
    std::fs::write(&directory_temporary, "must-not-replace-directory").unwrap();
    commit_local_file(&directory_temporary, &directory_destination, true)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(&directory_destination).unwrap(),
        "must-not-replace-directory"
    );
    assert!(!directory_temporary.exists());

    let mixed_directory_temporary = directory.path().join("mixed-directory.part");
    std::fs::create_dir(&mixed_directory_temporary).unwrap();
    std::fs::write(mixed_directory_temporary.join("new.txt"), "directory-wins").unwrap();
    commit_local_directory(&mixed_directory_temporary, &directory_destination, true)
        .await
        .unwrap();
    assert!(directory_destination.is_dir());
    assert_eq!(
        std::fs::read_to_string(directory_destination.join("new.txt")).unwrap(),
        "directory-wins"
    );

    let existing_tree = directory.path().join("existing-tree");
    let replacement_tree = directory.path().join("replacement-tree.part");
    std::fs::create_dir(&existing_tree).unwrap();
    std::fs::write(existing_tree.join("old.txt"), "old-tree").unwrap();
    std::fs::create_dir(&replacement_tree).unwrap();
    std::fs::create_dir(replacement_tree.join("nested")).unwrap();
    std::fs::write(replacement_tree.join("nested/new.txt"), "new-tree").unwrap();

    assert!(
        commit_local_directory(&replacement_tree, &existing_tree, false)
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read_to_string(existing_tree.join("old.txt")).unwrap(),
        "old-tree"
    );
    commit_local_directory(&replacement_tree, &existing_tree, true)
        .await
        .unwrap();
    assert!(!existing_tree.join("old.txt").exists());
    assert_eq!(
        std::fs::read_to_string(existing_tree.join("nested/new.txt")).unwrap(),
        "new-tree"
    );
    assert!(!replacement_tree.exists());
}

#[tokio::test]
async fn api_injects_vault_auth_overwrites_auth_and_keeps_ordinary_headers() {
    async fn response(headers: AxumHeaders) -> String {
        let auth = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let cookie = headers
            .get("cookie")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        format!("auth={auth}\ncookie={cookie}\n{}", "x".repeat(1_048_676))
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/v1/echo", get(response)))
            .await
            .unwrap();
    });

    let mut secrets = SecretBundle::default();
    secrets.token = Some("vault-secret-token-9384".into());
    let connection = DecryptedConnection {
        stored: stored(format!("http://{address}/v1/")),
        secrets,
    };
    let mut headers = HashMap::new();
    headers.insert("Authorization".into(), "Bearer attacker-value".into());
    headers.insert("Cookie".into(), "session=attacker".into());
    let result = execute_api(
        &connection,
        ApiRequestInput {
            url: format!("http://{address}/v1/echo"),
            method: "GET".into(),
            query: HashMap::new(),
            headers,
            body: None,
            ..ApiRequestInput::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(result.status, 200);
    assert!(!result.body.contains("vault-secret-token-9384"));
    assert!(!result.body.contains("attacker-value"));
    assert!(result.body.contains("[REDACTED]"));
    assert!(result.body.contains("cookie=session=attacker"));
    assert!(!result.body.contains("[Result truncated]"));
    assert!(!result.truncated);
    assert!(result.body.len() > 1_048_576);

    let limited = execute_api(
        &connection,
        ApiRequestInput {
            url: format!("http://{address}/v1/echo"),
            method: "GET".into(),
            max_response_bytes: Some(1_024),
            ..ApiRequestInput::default()
        },
    )
    .await
    .unwrap();
    assert!(limited.body.contains("[Result truncated]"));
    assert!(limited.truncated);
    server.abort();
}

#[tokio::test]
async fn api_streams_large_responses_to_a_safe_local_file() {
    async fn artifact() -> Vec<u8> {
        vec![b'Z'; 1_148_576]
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/v1/artifact", get(artifact)))
            .await
            .unwrap();
    });
    let mut secrets = SecretBundle::default();
    secrets.token = Some("artifact-test-token".into());
    let connection = DecryptedConnection {
        stored: stored(format!("http://{address}/v1/")),
        secrets,
    };
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("nested/artifact.bin");
    let request = || ApiRequestInput {
        url: format!("http://{address}/v1/artifact"),
        method: "GET".into(),
        save_response_to: Some(destination.to_string_lossy().into_owned()),
        ..ApiRequestInput::default()
    };

    let result = execute_api(&connection, request()).await.unwrap();
    assert_eq!(result.body, "");
    assert!(!result.truncated);
    assert_eq!(result.bytes_transferred, Some(1_148_576));
    assert_eq!(std::fs::metadata(&destination).unwrap().len(), 1_148_576);
    assert!(
        result
            .saved_to
            .as_deref()
            .is_some_and(|path| path.ends_with("artifact.bin"))
    );

    assert!(execute_api(&connection, request()).await.is_err());
    std::fs::write(&destination, "old").unwrap();
    let overwritten = execute_api(
        &connection,
        ApiRequestInput {
            overwrite_response_file: true,
            ..request()
        },
    )
    .await
    .unwrap();
    assert_eq!(overwritten.bytes_transferred, Some(1_148_576));
    assert_eq!(std::fs::read(&destination).unwrap()[0], b'Z');
    server.abort();
}

#[tokio::test]
async fn api_follows_redirects_and_reports_the_final_url() {
    let final_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let final_address = final_listener.local_addr().unwrap();
    let final_server = tokio::spawn(async move {
        axum::serve(
            final_listener,
            Router::new().route("/v1/final", get(|| async { "redirect-complete" })),
        )
        .await
        .unwrap();
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let redirect_url = format!("http://{final_address}/v1/final");
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/v1/start",
                get(move || {
                    let redirect_url = redirect_url.clone();
                    async move { Redirect::temporary(&redirect_url) }
                }),
            ),
        )
        .await
        .unwrap();
    });
    let mut secrets = SecretBundle::default();
    secrets.token = Some("redirect-token-9384".into());
    let connection = DecryptedConnection {
        stored: stored(format!("http://{address}/v1/")),
        secrets,
    };

    let result = execute_api(
        &connection,
        ApiRequestInput {
            url: format!("http://{address}/v1/start"),
            method: "GET".into(),
            ..ApiRequestInput::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(result.status, 200);
    assert_eq!(result.body, "redirect-complete");
    assert_eq!(result.url, format!("http://{final_address}/v1/final"));
    server.abort();
    final_server.abort();
}

#[tokio::test]
async fn api_key_query_replaces_agent_value_without_exposing_secret() {
    async fn response(Query(query): Query<HashMap<String, String>>) -> &'static str {
        if query.get("key").map(String::as_str) == Some("vault-query-key-9384") {
            "correct"
        } else {
            "wrong"
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/v1/echo", get(response)))
            .await
            .unwrap();
    });
    let mut item = stored(format!("http://{address}/v1/"));
    item.http_auth_type = "apiKey".into();
    item.auth_location = "query".into();
    item.auth_header = "key".into();
    let mut secrets = SecretBundle::default();
    secrets.api_key = Some("vault-query-key-9384".into());
    let connection = DecryptedConnection {
        stored: item,
        secrets,
    };
    let mut query = HashMap::new();
    query.insert("key".into(), Value::String("agent-value".into()));

    let result = execute_api(
        &connection,
        ApiRequestInput {
            url: format!("http://{address}/v1/echo"),
            method: "GET".into(),
            query,
            headers: HashMap::new(),
            body: None,
            ..ApiRequestInput::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(result.body, "correct");
    assert!(!result.url.contains("vault-query-key-9384"));
    assert!(result.url.contains("[REDACTED]"));
    server.abort();
}

#[tokio::test]
async fn api_supports_forms_raw_bytes_and_streamed_file_uploads() {
    async fn echo(headers: AxumHeaders, body: Bytes) -> String {
        format!(
            "{}\n{}",
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default(),
            String::from_utf8_lossy(&body)
        )
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/v1/echo", post(echo)))
            .await
            .unwrap();
    });
    let stored = stored(format!("http://{address}/v1/"));
    let mut secrets = SecretBundle::default();
    secrets.token = Some("vault-form-token-9384".into());
    let connection = DecryptedConnection { stored, secrets };
    let url = format!("http://{address}/v1/echo");

    let mut form = HashMap::new();
    form.insert(
        "tag".into(),
        Value::Array(vec![
            Value::String("one".into()),
            Value::String("two".into()),
        ]),
    );
    let form_result = execute_api(
        &connection,
        ApiRequestInput {
            url: url.clone(),
            method: "POST".into(),
            form,
            ..ApiRequestInput::default()
        },
    )
    .await
    .unwrap();
    assert!(
        form_result
            .body
            .contains("application/x-www-form-urlencoded")
    );
    assert!(form_result.body.contains("tag=one"));
    assert!(form_result.body.contains("tag=two"));

    let raw_result = execute_api(
        &connection,
        ApiRequestInput {
            url: url.clone(),
            method: "POST".into(),
            body_base64: Some(STANDARD.encode(b"raw-binary-marker-9384\0tail")),
            ..ApiRequestInput::default()
        },
    )
    .await
    .unwrap();
    assert!(raw_result.body.contains("raw-binary-marker-9384"));

    let mut text_headers = HashMap::new();
    text_headers.insert("Content-Type".into(), "text/plain; charset=utf-8".into());
    let text_result = execute_api(
        &connection,
        ApiRequestInput {
            url: url.clone(),
            method: "POST".into(),
            headers: text_headers,
            body: Some(Value::String("plain-text-marker-9384".into())),
            max_response_bytes: Some(32 * 1024 * 1024),
            ..ApiRequestInput::default()
        },
    )
    .await
    .unwrap();
    assert!(text_result.body.contains("text/plain"));
    assert!(text_result.body.contains("plain-text-marker-9384"));

    let directory = tempfile::tempdir().unwrap();
    let file_path = directory.path().join("upload.txt");
    std::fs::write(&file_path, "multipart-file-marker-9384").unwrap();
    let mut multipart_fields = HashMap::new();
    multipart_fields.insert("note".into(), Value::String("multipart-note-9384".into()));
    let multipart_result = execute_api(
        &connection,
        ApiRequestInput {
            url,
            method: "POST".into(),
            form: multipart_fields,
            files: vec![ApiUploadFile {
                field: "attachment".into(),
                path: file_path.to_string_lossy().into_owned(),
                file_name: None,
                content_type: None,
            }],
            ..ApiRequestInput::default()
        },
    )
    .await
    .unwrap();
    assert!(multipart_result.body.contains("multipart/form-data"));
    assert!(multipart_result.body.contains("multipart-note-9384"));
    assert!(multipart_result.body.contains("multipart-file-marker-9384"));
    server.abort();
}

#[test]
fn custom_auth_headers_are_injected_from_named_secrets() {
    let mut item = stored("https://api.example.test/v1/".to_owned());
    item.http_auth_type = "custom".into();
    item.api_auth_headers = vec![ApiAuthHeader {
        name: "X-Client-Secret".into(),
        secret_name: "apiHeader_client".into(),
    }];
    let mut secrets = SecretBundle::default();
    secrets
        .named_secrets
        .insert("apiHeader_client".into(), "custom-secret-9384".into());
    let mut headers = HeaderMap::new();
    let mut target = Url::parse("https://api.example.test/v1/").unwrap();

    apply_api_auth(&item, &secrets, &mut headers, &mut target).unwrap();

    assert_eq!(
        headers.get("x-client-secret").unwrap(),
        "custom-secret-9384"
    );
    assert!(blocked_header_names(&item).contains("x-client-secret"));
}

#[test]
fn api_activity_description_omits_query_and_records_origin_and_path() {
    let mut query = HashMap::new();
    query.insert("token".into(), Value::String("must-not-be-logged".into()));
    let connection = stored("https://api.example.test/v1/".to_owned());
    let description = describe_api_request(
        &connection,
        &ApiRequestInput {
            url: "https://api.example.test/v1/items".into(),
            method: "post".into(),
            query,
            headers: HashMap::new(),
            body: None,
            ..ApiRequestInput::default()
        },
    );
    assert_eq!(description, "API POST https://api.example.test/v1/items");
    assert!(!description.contains("token"));
    assert!(!description.contains("must-not-be-logged"));
}

#[test]
fn api_response_only_redacts_secrets_known_to_openkeylet() {
    let connection = stored("https://api.example.test/v1/".to_owned());
    let mut secrets = SecretBundle::default();
    secrets.token = Some("stored-token-9384".to_owned());
    let body = sanitize_api_body(
        r#"{
            "name": "visible",
            "access_token": "new-access-token",
            "nested": [{"client-secret": "new-client-secret"}],
            "credential": {"value": "new-credential"},
            "echo": "stored-token-9384"
        }"#
        .to_owned(),
        false,
        &connection,
        &secrets,
    );
    assert!(body.contains("visible"));
    for server_value in ["new-access-token", "new-client-secret", "new-credential"] {
        assert!(body.contains(server_value));
    }
    assert!(!body.contains("stored-token-9384"));

    let malformed = sanitize_api_body(
        r#"{"token":"new-token""#.to_owned(),
        false,
        &connection,
        &secrets,
    );
    assert_eq!(malformed, r#"{"token":"new-token""#);

    let truncated = sanitize_api_body(
        r#"{"name":"partial""#.to_owned(),
        true,
        &connection,
        &secrets,
    );
    assert_eq!(truncated, "{\"name\":\"partial\"\n…[Result truncated]");
}

#[test]
fn saved_api_url_accepts_omitted_and_relative_request_urls() {
    let connection = stored("https://api.example.test/v1".to_owned());
    let query = HashMap::new();

    assert_eq!(
        build_api_url(&connection, "", &query).unwrap().as_str(),
        "https://api.example.test/v1"
    );
    assert_eq!(
        build_api_url(&connection, "items/42", &query)
            .unwrap()
            .as_str(),
        "https://api.example.test/v1/items/42"
    );
    assert_eq!(
        build_api_url(&connection, "/health", &query)
            .unwrap()
            .as_str(),
        "https://api.example.test/health"
    );

    let addressless = stored(String::new());
    assert!(build_api_url(&addressless, "", &query).is_err());
    assert!(build_api_url(&addressless, "items", &query).is_err());
    assert_eq!(
        build_api_url(&addressless, "https://other.example/items", &query)
            .unwrap()
            .as_str(),
        "https://other.example/items"
    );
}

#[test]
fn ssh_connect_errors_name_the_failed_stage() {
    assert!(ssh_connect_error_message(&"Disconnected").contains("handshake"));
    assert!(ssh_connect_error_message(&"os error 10060").contains("TCP"));
    assert!(ssh_connect_error_message(&"connection refused").contains("port"));
}

#[test]
fn ssh_secret_environment_quotes_values_and_rejects_invalid_names() {
    let command = ssh_command_with_secret_environment(
        "printf '%s' \"$OPENKEYLET_PASSWORD\"",
        &HashMap::from([(
            "OPENKEYLET_PASSWORD".to_owned(),
            "value with ' quotes and $shell".to_owned(),
        )]),
    )
    .unwrap();
    assert!(
        command.starts_with("OPENKEYLET_PASSWORD='value with '\\'' quotes and $shell' sh -c ")
    );
    assert!(command.contains("$OPENKEYLET_PASSWORD"));
    assert!(
        ssh_command_with_secret_environment(
            "true",
            &HashMap::from([("NOT-VALID".to_owned(), "secret".to_owned())]),
        )
        .is_err()
    );
}

#[test]
fn ssh_auth_methods_prefer_private_key_with_password_fallback() {
    let mut both_secrets = SecretBundle::default();
    both_secrets.private_key = Some("-----BEGIN OPENSSH PRIVATE KEY-----".into());
    both_secrets.password = Some("sudo-password".into());
    let mut both_stored = stored(String::new());
    both_stored.ssh_auth_type = "password".into();
    let both = DecryptedConnection {
        stored: both_stored,
        secrets: both_secrets,
    };
    assert_eq!(ssh_auth_methods(&both), vec!["privateKey", "password"]);

    let mut pw_only_secrets = SecretBundle::default();
    pw_only_secrets.password = Some("only-password".into());
    let pw_only = DecryptedConnection {
        stored: stored(String::new()),
        secrets: pw_only_secrets,
    };
    assert_eq!(ssh_auth_methods(&pw_only), vec!["password"]);
}

#[test]
fn bounded_output_capture_preserves_head_and_tail_and_redacts() {
    let redactor = Redactor::new(&redaction_candidates(&["topsecret123".to_owned()]));
    let mut capture = BoundedOutputCapture::new(Some(64));
    capture.push(b"HEAD_SECRET=topsecret123_");
    capture.push(&vec![b'M'; 400]);
    capture.push(b"_TAIL_SECRET=topsecret123");
    let (text, truncated) = capture.finish(&redactor);
    assert!(truncated);
    assert!(text.contains("HEAD_SECRET=[REDACTED]"));
    assert!(text.contains("_TAIL_SECRET=[REDACTED]"));
    assert!(text.contains("Output truncated: omitted"));
    assert!(!text.contains("topsecret123"));

    let mut unlimited = BoundedOutputCapture::new(Some(0));
    unlimited.push(&vec![b'X'; 4096]);
    let (full, full_truncated) = unlimited.finish(&Redactor::new(&[]));
    assert!(!full_truncated);
    assert_eq!(full.len(), 4096);
}

#[test]
fn bounded_output_capture_drops_secret_fragments_at_both_cuts() {
    let secret = "straddling-secret-XYZ";
    let redactor = Redactor::new(&redaction_candidates(&[secret.to_owned()]));
    // With a 64-byte cap the head keeps 32 bytes and ends inside the first copy of the
    // secret ("straddling-s"); the tail keeps the last 32 bytes and starts inside the
    // second copy ("g-secret-XYZ").
    let mut capture = BoundedOutputCapture::new(Some(64));
    capture.push(format!("{}{secret}", "h".repeat(20)).as_bytes());
    capture.push(&vec![b'.'; 200]);
    capture.push(format!("{secret}{}", "t".repeat(20)).as_bytes());
    let (text, truncated) = capture.finish(&redactor);
    assert!(truncated);
    for fragment in ["straddling", "XYZ", "secret-", "dling", "g-s"] {
        assert!(!text.contains(fragment), "{fragment} leaked: {text:?}");
    }
    assert!(text.starts_with(&format!("{}\n…[Output truncated", "h".repeat(20))), "{text:?}");
    assert!(text.ends_with(&format!("unlimited]\n{}", "t".repeat(20))), "{text:?}");
    // 218 bytes fell between head and tail; the two 12-byte fragments are dropped as well.
    assert!(text.contains("omitted 242 bytes"), "{text:?}");
}

#[tokio::test]
async fn api_cross_origin_redirect_strips_custom_auth_headers_and_supports_no_redirect() {
    async fn inspect_headers(headers: AxumHeaders) -> String {
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("NONE");
        let api_key = headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("NONE");
        let custom = headers
            .get("x-client-secret")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("NONE");
        format!("auth={auth}|key={api_key}|custom={custom}")
    }

    let foreign_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let foreign_addr = foreign_listener.local_addr().unwrap();
    let foreign_server = tokio::spawn(async move {
        axum::serve(
            foreign_listener,
            Router::new().route("/landed", get(inspect_headers)),
        )
        .await
        .unwrap();
    });

    let origin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin_listener.local_addr().unwrap();
    let foreign_target = format!("http://{foreign_addr}/landed");
    let same_origin_target = format!("http://{origin_addr}/same-landed");
    let origin_server = tokio::spawn(async move {
        axum::serve(
            origin_listener,
            Router::new()
                .route(
                    "/to-foreign",
                    get({
                        let url = foreign_target.clone();
                        move || {
                            let url = url.clone();
                            async move { Redirect::temporary(&url) }
                        }
                    }),
                )
                .route(
                    "/to-same",
                    get({
                        let url = same_origin_target.clone();
                        move || {
                            let url = url.clone();
                            async move { Redirect::temporary(&url) }
                        }
                    }),
                )
                .route("/same-landed", get(inspect_headers)),
        )
        .await
        .unwrap();
    });

    let mut item = stored(format!("http://{origin_addr}/"));
    item.http_auth_type = "custom".into();
    item.api_auth_headers = vec![ApiAuthHeader {
        name: "X-Client-Secret".into(),
        secret_name: "clientSecret".into(),
    }];
    let mut secrets = SecretBundle::default();
    secrets
        .named_secrets
        .insert("clientSecret".into(), "custom-header-secret-5544".into());
    let connection = DecryptedConnection {
        stored: item,
        secrets,
    };

    // Cross-origin redirect must follow AND strip X-Client-Secret
    let foreign_res = execute_api(
        &connection,
        ApiRequestInput {
            url: format!("http://{origin_addr}/to-foreign"),
            method: "GET".into(),
            ..ApiRequestInput::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(foreign_res.status, 200);
    assert_eq!(foreign_res.body, "auth=NONE|key=NONE|custom=NONE");

    // Same-origin redirect keeps X-Client-Secret (redacted in echoed body)
    let same_res = execute_api(
        &connection,
        ApiRequestInput {
            url: format!("http://{origin_addr}/to-same"),
            method: "GET".into(),
            ..ApiRequestInput::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(same_res.status, 200);
    assert_eq!(same_res.body, "auth=NONE|key=NONE|custom=[REDACTED]");

    // follow_redirects=false returns 307 + Location without following
    let no_redir = execute_api(
        &connection,
        ApiRequestInput {
            url: format!("http://{origin_addr}/to-foreign"),
            method: "GET".into(),
            follow_redirects: Some(false),
            ..ApiRequestInput::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(no_redir.status, 307);
    assert_eq!(
        no_redir.headers.get("location").map(String::as_str),
        Some(format!("http://{foreign_addr}/landed").as_str())
    );

    origin_server.abort();
    foreign_server.abort();
}

type SeenRequests = Arc<std::sync::Mutex<Vec<String>>>;

async fn record_request(
    axum::extract::State(seen): axum::extract::State<SeenRequests>,
    headers: AxumHeaders,
    body: Bytes,
) -> String {
    let auth = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("NONE");
    let entry = format!("auth={auth}|body={}", String::from_utf8_lossy(&body));
    seen.lock().unwrap().push(entry.clone());
    entry
}

#[tokio::test]
async fn api_refuses_bound_item_credentials_outside_its_destination_and_sends_nothing() {
    let seen = SeenRequests::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let application = Router::new()
        .route("/collect", get(record_request))
        .with_state(seen.clone());
    let server = tokio::spawn(async move { axum::serve(listener, application).await });

    let secret = "bound-auth-secret-6620";
    let mut secrets = SecretBundle::default();
    secrets.token = Some(secret.into());
    let collect = || ApiRequestInput {
        url: format!("http://{address}/collect"),
        method: "GET".into(),
        ..ApiRequestInput::default()
    };
    let directory = tempdir().unwrap();
    let destination = directory.path().join("refused/response.bin");

    let bound = DecryptedConnection {
        stored: stored("https://api.example.test/v1/".to_owned()),
        secrets: secrets.clone(),
    };
    let error = execute_api(
        &bound,
        ApiRequestInput {
            save_response_to: Some(destination.to_string_lossy().into_owned()),
            ..collect()
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.starts_with("Refused: "), "{error}");
    assert!(error.contains("\"local-api\" (https://api.example.test)"), "{error}");
    assert!(!error.contains(secret));
    assert!(!destination.parent().unwrap().exists());

    // Same host and port over a different scheme is a different origin.
    let other_scheme = DecryptedConnection {
        stored: stored(format!("https://{address}/")),
        secrets: secrets.clone(),
    };
    assert!(
        execute_api(&other_scheme, collect())
            .await
            .unwrap_err()
            .to_string()
            .starts_with("Refused: ")
    );
    assert!(seen.lock().unwrap().is_empty());

    // A matching website rule lends the credential to that origin.
    let mut ruled = stored("https://api.example.test/v1/".to_owned());
    ruled.login_uris = vec![crate::login_uri::LoginUri {
        uri: format!("http://{address}"),
        match_type: "origin".into(),
    }];
    let ruled = DecryptedConnection {
        stored: ruled,
        secrets: secrets.clone(),
    };
    assert_eq!(execute_api(&ruled, collect()).await.unwrap().status, 200);

    // An item without a saved URL or rules still targets whatever URL the caller supplies.
    let unbound = DecryptedConnection {
        stored: stored(String::new()),
        secrets,
    };
    assert_eq!(execute_api(&unbound, collect()).await.unwrap().status, 200);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![format!("auth=Bearer {secret}|body="); 2]
    );
    server.abort();
}

#[tokio::test]
async fn api_cross_origin_307_and_308_never_redeliver_secret_bearing_bodies() {
    let foreign_seen = SeenRequests::default();
    let foreign_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let foreign_addr = foreign_listener.local_addr().unwrap();
    let foreign_application = Router::new()
        .route("/landed", post(record_request))
        .with_state(foreign_seen.clone());
    let foreign_server =
        tokio::spawn(async move { axum::serve(foreign_listener, foreign_application).await });

    let origin_seen = SeenRequests::default();
    let origin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin_listener.local_addr().unwrap();
    let foreign_landed = format!("http://{foreign_addr}/landed");
    // The redirect handlers read the request body so streamed uploads complete cleanly.
    let origin_application = Router::new()
        .route(
            "/to-foreign-307",
            post({
                let url = foreign_landed.clone();
                move |_body: Bytes| {
                    let url = url.clone();
                    async move { Redirect::temporary(&url) }
                }
            }),
        )
        .route(
            "/to-foreign-308",
            post({
                let url = foreign_landed.clone();
                move |_body: Bytes| {
                    let url = url.clone();
                    async move { Redirect::permanent(&url) }
                }
            }),
        )
        .route(
            "/to-same-307",
            post(|| async { Redirect::temporary("/same-landed") }),
        )
        .route("/same-landed", post(record_request))
        .route(
            "/api/to-outside",
            get(|| async { Redirect::temporary("/outside") }),
        )
        .route("/outside", get(record_request))
        .with_state(origin_seen.clone());
    let origin_server =
        tokio::spawn(async move { axum::serve(origin_listener, origin_application).await });

    let secret = "redirect-body-secret-7731";
    let mut secrets = SecretBundle::default();
    secrets.token = Some(secret.into());
    let bound = DecryptedConnection {
        stored: stored(format!("http://{origin_addr}/")),
        secrets: secrets.clone(),
    };
    let unbound = DecryptedConnection {
        stored: stored(String::new()),
        secrets: secrets.clone(),
    };
    let post_to = |path: &str| ApiRequestInput {
        url: format!("http://{origin_addr}{path}"),
        method: "POST".into(),
        ..ApiRequestInput::default()
    };

    // A substituted secret in a JSON or form body is never re-sent to another origin; the
    // redirect itself is returned, for bound and unbound items alike.
    for (connection, path, status) in [
        (&bound, "/to-foreign-307", 307),
        (&bound, "/to-foreign-308", 308),
        (&unbound, "/to-foreign-307", 307),
    ] {
        let response = execute_api(
            connection,
            ApiRequestInput {
                body: Some(serde_json::json!({ "credential": secret })),
                ..post_to(path)
            },
        )
        .await
        .unwrap();
        assert_eq!(response.status, status);
        assert_eq!(
            response.headers.get("location").map(String::as_str),
            Some(foreign_landed.as_str())
        );
    }
    let form = HashMap::from([("credential".to_owned(), Value::String(secret.into()))]);
    let form_response = execute_api(
        &bound,
        ApiRequestInput {
            form,
            ..post_to("/to-foreign-308")
        },
    )
    .await
    .unwrap();
    assert_eq!(form_response.status, 308);

    // Multipart bodies stream local files and cannot be inspected, so they are never re-sent.
    let directory = tempdir().unwrap();
    let upload = directory.path().join("upload.txt");
    std::fs::write(&upload, "no secret in this file").unwrap();
    let multipart_response = execute_api(
        &bound,
        ApiRequestInput {
            files: vec![ApiUploadFile {
                field: "attachment".into(),
                path: upload.to_string_lossy().into_owned(),
                file_name: None,
                content_type: None,
            }],
            ..post_to("/to-foreign-307")
        },
    )
    .await
    .unwrap();
    assert_eq!(multipart_response.status, 307);
    assert!(foreign_seen.lock().unwrap().is_empty());

    // A body without secrets still follows the cross-origin redirect, minus authentication.
    let followed = execute_api(
        &bound,
        ApiRequestInput {
            body: Some(serde_json::json!({ "ping": true })),
            ..post_to("/to-foreign-307")
        },
    )
    .await
    .unwrap();
    assert_eq!(followed.status, 200);
    assert_eq!(
        *foreign_seen.lock().unwrap(),
        vec![r#"auth=NONE|body={"ping":true}"#.to_owned()]
    );

    // Same-origin 307 keeps the secret-bearing body and authentication.
    let same = execute_api(
        &bound,
        ApiRequestInput {
            body: Some(serde_json::json!({ "credential": secret })),
            ..post_to("/to-same-307")
        },
    )
    .await
    .unwrap();
    assert_eq!(same.status, 200);
    assert!(!same.body.contains(secret));
    assert_eq!(
        *origin_seen.lock().unwrap(),
        vec![format!(r#"auth=Bearer {secret}|body={{"credential":"{secret}"}}"#)]
    );

    // A same-origin hop outside a path-scoped website rule is treated as cross-origin.
    let mut scoped = stored(String::new());
    scoped.login_uris = vec![crate::login_uri::LoginUri {
        uri: format!("http://{origin_addr}/api/"),
        match_type: "prefix".into(),
    }];
    let scoped = DecryptedConnection {
        stored: scoped,
        secrets,
    };
    let outside = execute_api(
        &scoped,
        ApiRequestInput {
            url: format!("http://{origin_addr}/api/to-outside"),
            method: "GET".into(),
            ..ApiRequestInput::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(outside.status, 200);
    assert_eq!(outside.body, "auth=NONE|body=");

    origin_server.abort();
    foreign_server.abort();
}

#[tokio::test]
async fn execute_local_truncates_large_output_and_redacts_extra_secrets() {
    #[cfg(windows)]
    let cmd = "Write-Output ('START_sec9988_' + ('Z' * 1200) + '_END_sec9988')";
    #[cfg(not(windows))]
    let cmd = "printf 'START_sec9988_%01200d_END_sec9988\\n' 0";

    let res = execute_local(
        None,
        cmd,
        None,
        Some(15),
        &HashMap::new(),
        None,
        Some(256),
        &["sec9988".to_owned()],
    )
    .await
    .unwrap();
    assert_eq!(res.exit_code, Some(0));
    assert!(res.stdout_truncated);
    assert!(res.stdout.contains("START_[REDACTED]_"));
    assert!(res.stdout.contains("_END_[REDACTED]"));
    assert!(!res.stdout.contains("sec9988"));
}
