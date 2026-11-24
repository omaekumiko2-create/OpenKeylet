use super::*;
use crate::model::{ConnectionInput, ItemModule, SecretBundle};
use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Uri},
    response::{IntoResponse, Response as AxumResponse},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use uuid::Uuid;

#[derive(Default)]
struct MockState {
    bytes: Option<Vec<u8>>,
    public: bool,
    force_blob: bool,
    conflict_on_put: bool,
    force_status: Option<u16>,
    requests: usize,
    writes: usize,
    missing_repo: bool,
    creates: usize,
    create_public: bool,
    create_unconfirmed: bool,
}

struct MockGithub {
    state: Arc<Mutex<MockState>>,
    base: Url,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MockGithub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockGithub {
    async fn start() -> Self {
        let state = Arc::new(Mutex::new(MockState::default()));
        let router = Router::new()
            .fallback(mock_handler)
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self { state, base, task }
    }

    fn manager(&self) -> (TempDir, GithubBackup) {
        let directory = tempfile::tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let mut manager = GithubBackup::new(vault).unwrap();
        manager.api_base = self.base.clone();
        (directory, manager)
    }
}

async fn mock_handler(
    State(state): State<Arc<Mutex<MockState>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> AxumResponse {
    let mut state = state.lock().unwrap();
    state.requests += 1;
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some("Bearer test-token")
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if let Some(status) = state.force_status {
        return (
            StatusCode::from_u16(status).unwrap(),
            [("location", "http://127.0.0.1:1/do-not-follow")],
            "token-and-secret-marker-must-not-be-echoed",
        )
            .into_response();
    }
    if method == Method::GET && uri.path() == "/user" {
        return Json(json!({"login":"test"})).into_response();
    }
    if method == Method::POST && uri.path() == "/user/repos" {
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["name"], "vault");
        assert_eq!(payload["private"], true);
        assert_eq!(payload["auto_init"], true);
        assert!(!String::from_utf8_lossy(&body).contains("okv1_"));
        if !state.missing_repo {
            return StatusCode::UNPROCESSABLE_ENTITY.into_response();
        }
        state.missing_repo = false;
        state.creates += 1;
        if state.create_unconfirmed {
            return StatusCode::BAD_GATEWAY.into_response();
        }
        return (StatusCode::CREATED,Json(json!({"id":7,"private":!state.create_public,"archived":false,"default_branch":"main"}))).into_response();
    }
    if method == Method::GET && uri.path() == "/repos/test/vault" {
        if state.missing_repo {
            return StatusCode::NOT_FOUND.into_response();
        }
        return Json(json!({"id": 7, "private": !state.public, "archived": false,
            "disabled": false, "default_branch": "main"}))
        .into_response();
    }
    let content_path = format!("/repos/test/vault/contents/{CLOUD_FILE}");
    if method == Method::GET && uri.path() == content_path {
        return match &state.bytes {
            None => StatusCode::NOT_FOUND.into_response(),
            Some(bytes) => Json(
                json!({"type":"file", "sha":blob_sha(bytes), "size":bytes.len(),
                    "encoding": if state.force_blob { "none" } else { "base64" },
                    "content": if state.force_blob { String::new() } else { STANDARD.encode(bytes) }
                }),
            )
            .into_response(),
        };
    }
    if method == Method::GET && uri.path().starts_with("/repos/test/vault/git/blobs/") {
        let bytes = state.bytes.as_ref().unwrap();
        assert!(uri.path().ends_with(&blob_sha(bytes)));
        return Json(json!({"sha":blob_sha(bytes), "size":bytes.len(),
            "encoding":"base64", "content":STANDARD.encode(bytes)}))
        .into_response();
    }
    if method == Method::PUT && uri.path() == content_path {
        let request: Value = serde_json::from_slice(&body).unwrap();
        if state.conflict_on_put {
            state.conflict_on_put = false;
            return StatusCode::CONFLICT.into_response();
        }
        let current_sha = state.bytes.as_ref().map(|bytes| blob_sha(bytes));
        if request.get("sha").and_then(Value::as_str) != current_sha.as_deref() {
            return StatusCode::CONFLICT.into_response();
        }
        assert_eq!(request["branch"], "main");
        assert_eq!(request["message"], "Update encrypted OpenKeylet backup");
        let bytes = STANDARD
            .decode(request["content"].as_str().unwrap())
            .unwrap();
        let sha = blob_sha(&bytes);
        state.bytes = Some(bytes);
        state.writes += 1;
        return Json(json!({"content":{"sha":sha}})).into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}

fn input(key: &str, mode: &str) -> ConnectInput {
    ConnectInput {
        repository: "test/vault".into(),
        token: "test-token".into(),
        recovery_key: key.into(),
        mode: mode.into(),
        recovery_key_saved: true,
        auth_source: "token".into(),
        create_repository: false,
        auto_sync: false,
        provider: String::new(),
        server_url: String::new(),
        master_passphrase: String::new(),
    }
}

#[tokio::test]
async fn account_check_and_private_repository_creation_do_not_upload_secrets() {
    let remote = MockGithub::start().await;
    remote.state.lock().unwrap().missing_repo = true;
    let (_directory, manager) = remote.manager();
    let account = manager
        .account(AuthInput {
            auth_source: "token".into(),
            token: "test-token".into(),
            provider: String::new(),
            server_url: String::new(),
        })
        .await
        .unwrap();
    assert_eq!(account.login, "test");
    assert!(!manager.status().unwrap().connected);
    let key = generate_recovery_key().unwrap();
    let mut request = input(&key, "new");
    request.create_repository = true;
    add_item(
        &manager.vault,
        Uuid::new_v4(),
        "Local item",
        "secret-never-in-repository-create",
    );
    let status = manager.connect(request).await.unwrap();
    assert!(status.connected);
    assert!(!status.has_remote_backup);
    {
        let state = remote.state.lock().unwrap();
        assert_eq!(state.creates, 1);
        assert_eq!(state.writes, 0);
        assert!(state.bytes.is_none());
    }
    manager.upload().await.unwrap();
    let ciphertext = remote.state.lock().unwrap().bytes.clone().unwrap();
    assert!(!String::from_utf8_lossy(&ciphertext).contains("secret-never-in-repository-create"));
    assert!(!String::from_utf8_lossy(&ciphertext).contains(&key));
    let (_other_directory, other) = remote.manager();
    other.connect(input(&key, "existing")).await.unwrap();
    assert_eq!(other.restore().await.unwrap().summary.added, 1);
}

#[tokio::test]
async fn creation_requires_explicit_valid_input_and_does_not_adopt_existing_repos() {
    let remote = MockGithub::start().await;
    let (_directory, manager) = remote.manager();
    let key = generate_recovery_key().unwrap();
    let mut request = input(&key, "new");
    request.create_repository = true;
    request.recovery_key_saved = false;
    assert_eq!(
        manager.connect(request).await.err().unwrap().to_string(),
        "GITHUB_KEY_NOT_SAVED"
    );
    assert_eq!(remote.state.lock().unwrap().requests, 0);
    let mut request = input(&key, "new");
    request.create_repository = true;
    assert_eq!(
        manager.connect(request).await.err().unwrap().to_string(),
        "GITHUB_REPOSITORY_EXISTS"
    );
    let mut request = input(&key, "existing");
    request.create_repository = true;
    assert_eq!(
        manager.connect(request).await.err().unwrap().to_string(),
        "GITHUB_CREATE_MODE"
    );
    let mut request = input(&key, "new");
    request.create_repository = true;
    request.repository = "someone-else/vault".into();
    assert_eq!(
        manager.connect(request).await.err().unwrap().to_string(),
        "GITHUB_CREATE_OWNER"
    );
    assert!(!manager.status().unwrap().connected);
    assert_eq!(remote.state.lock().unwrap().creates, 0);
    remote.state.lock().unwrap().missing_repo = true;
    remote.state.lock().unwrap().create_public = true;
    let mut request = input(&key, "new");
    request.create_repository = true;
    assert_eq!(
        manager.connect(request).await.err().unwrap().to_string(),
        "GITHUB_PRIVATE_REQUIRED"
    );
    assert!(!manager.status().unwrap().connected);
    assert_eq!(remote.state.lock().unwrap().writes, 0);
}

#[tokio::test]
async fn uncertain_creation_can_reconnect_without_recreating_or_uploading() {
    let remote = MockGithub::start().await;
    {
        let mut state = remote.state.lock().unwrap();
        state.missing_repo = true;
        state.create_unconfirmed = true;
    }
    let (_directory, manager) = remote.manager();
    let key = generate_recovery_key().unwrap();
    let mut request = input(&key, "new");
    request.create_repository = true;
    assert_eq!(
        manager.connect(request).await.err().unwrap().to_string(),
        "GITHUB_CREATE_UNCONFIRMED"
    );
    assert!(!manager.status().unwrap().connected);
    manager.connect(input(&key, "new")).await.unwrap();
    assert!(manager.status().unwrap().connected);
    let state = remote.state.lock().unwrap();
    assert_eq!(state.creates, 1);
    assert_eq!(state.writes, 0);
}

fn add_item(vault: &Vault, id: Uuid, name: &str, secret: &str) {
    let mut secrets = SecretBundle::default();
    secrets
        .named_secrets
        .insert("apiCredential".into(), secret.into());
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: String::new(),
            folder: String::new(),
            favorite: false,
            id: Some(id),
            name: name.into(),
            enabled: true,
            description: "private-description-marker".into(),
            modules: vec![ItemModule {
                kind: "apiCredential".into(),
                ..Default::default()
            }],
            http_auth_type: "bearer".into(),
            private_key_import_path: String::new(),
            auth_header: "Authorization".into(),
            auth_location: "header".into(),
            auth_prefix: "Bearer ".into(),
            api_auth_headers: vec![],
            test_path: "/".into(),
            remove_secret_names: vec![],
            secrets,
        })
        .unwrap();
}

#[test]
fn snapshots_are_authenticated_and_contain_no_unlock_material() {
    let key = generate_recovery_key().unwrap();
    let other_key = generate_recovery_key().unwrap();
    assert_ne!(key, other_key);
    let bytes = encrypt_snapshot(b"credential-and-project-marker", &key).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(!text.contains("credential-and-project-marker"));
    assert!(!text.contains(&key));
    assert!(!text.contains("unlockKey"));
    assert_eq!(
        decrypt_snapshot(&bytes, &key).unwrap().as_slice(),
        b"credential-and-project-marker"
    );
    assert_eq!(
        decrypt_snapshot(&bytes, &other_key)
            .unwrap_err()
            .to_string(),
        "GITHUB_KEY_MISMATCH"
    );
    let mut changed: CloudFile = serde_json::from_slice(&bytes).unwrap();
    changed.payload.nonce = STANDARD.encode([0_u8; 24]).trim_end_matches('=').to_owned();
    assert!(decrypt_snapshot(&serde_json::to_vec(&changed).unwrap(), &key).is_err());
    changed.version = 2;
    assert_eq!(
        decrypt_snapshot(&serde_json::to_vec(&changed).unwrap(), &key)
            .unwrap_err()
            .to_string(),
        "GITHUB_BACKUP_INVALID"
    );
    assert!(
        decrypt_snapshot(
            br#"{"format":"mcp-vault-backup","unlockKey":"unsafe"}"#,
            &key
        )
        .is_err()
    );
}

#[test]
fn inputs_cannot_change_the_api_origin_or_inject_paths() {
    assert_eq!(
        parse_repository(" https://github.com/test/vault.git/ ").unwrap(),
        ("test".into(), "vault".into())
    );
    for value in [
        "../vault",
        "test/..",
        "test/vault/extra",
        "https://evil.test/x/y",
        "test/a?b",
        "test/a%2Fb",
        "test/a#ref",
    ] {
        assert!(parse_repository(value).is_err(), "{value}");
    }
    assert!(parse_recovery_key("123456").is_err());
    assert!(validate_token("token\nInjected: value").is_err());
    assert!(validate_token("").is_err());
    assert!(
        encrypt_snapshot(&vec![0; MAX_CLOUD_BYTES], &generate_recovery_key().unwrap()).is_err()
    );
}

#[tokio::test]
async fn backup_restores_on_another_device_and_keeps_local_credentials_private() {
    let mock = MockGithub::start().await;
    let (_source_directory, source) = mock.manager();
    let key = generate_recovery_key().unwrap();
    add_item(
        &source.vault,
        Uuid::new_v4(),
        "project-marker",
        "credential-marker",
    );
    source.connect(input(&key, "new")).await.unwrap();
    source.upload().await.unwrap();
    let local_file = fs::read_to_string(source.vault.data_dir().join(LOCAL_FILE)).unwrap();
    let remote_file = String::from_utf8(mock.state.lock().unwrap().bytes.clone().unwrap()).unwrap();
    for marker in [
        key.as_str(),
        "test-token",
        "project-marker",
        "credential-marker",
        "private-description-marker",
    ] {
        assert!(!local_file.contains(marker));
        assert!(!remote_file.contains(marker));
    }
    let status_json = serde_json::to_string(&source.status().unwrap()).unwrap();
    assert!(!status_json.contains(&key));
    assert!(!status_json.contains("test-token"));

    let (_target_directory, target) = mock.manager();
    assert!(
        target
            .connect(input(&key, "existing"))
            .await
            .unwrap()
            .needs_restore
    );
    assert_eq!(
        target.upload().await.err().unwrap().to_string(),
        "GITHUB_RESTORE_REQUIRED"
    );
    let restored = target.restore().await.unwrap();
    assert_eq!(restored.summary.added, 1);
    assert!(!restored.status.needs_restore);
    let entries = target.vault.export_connections().unwrap();
    assert_eq!(entries[0].0.name, "project-marker");
    assert_eq!(entries[0].1.get("apiCredential"), Some("credential-marker"));
    assert_eq!(target.restore().await.unwrap().summary.merged, 1);
    assert_eq!(target.vault.export_connections().unwrap().len(), 1);
    assert!(!target.disconnect().unwrap().connected);
    assert!(mock.state.lock().unwrap().bytes.is_some());
    assert_eq!(target.vault.export_connections().unwrap().len(), 1);
    assert!(target.recovery_key().is_err());
}

#[tokio::test]
async fn remote_changes_require_restore_and_conflicting_items_are_preserved() {
    let mock = MockGithub::start().await;
    let (_a, first) = mock.manager();
    let (_b, second) = mock.manager();
    let key = generate_recovery_key().unwrap();
    let id = Uuid::new_v4();
    add_item(&first.vault, id, "shared", "first-secret");
    first.connect(input(&key, "new")).await.unwrap();
    first.upload().await.unwrap();
    second.connect(input(&key, "existing")).await.unwrap();
    second.restore().await.unwrap();
    add_item(&first.vault, id, "shared", "updated-first-secret");
    first.upload().await.unwrap();
    let before = mock.state.lock().unwrap().bytes.clone();
    assert_eq!(
        second.upload().await.err().unwrap().to_string(),
        "GITHUB_REMOTE_CHANGED"
    );
    assert!(second.status().unwrap().needs_restore);
    assert_eq!(mock.state.lock().unwrap().bytes, before);
    let result = second.restore().await.unwrap();
    assert_eq!(result.summary.added, 1);
    let entries = second.vault.export_connections().unwrap();
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .any(|(_, secret)| secret.get("apiCredential") == Some("first-secret"))
    );
    assert!(
        entries
            .iter()
            .any(|(_, secret)| secret.get("apiCredential") == Some("updated-first-secret"))
    );
    second.upload().await.unwrap();
}

#[tokio::test]
async fn wrong_keys_and_public_repositories_do_not_modify_local_or_remote_data() {
    let mock = MockGithub::start().await;
    let (_a, source) = mock.manager();
    let key = generate_recovery_key().unwrap();
    let mut unsaved = input(&key, "new");
    unsaved.recovery_key_saved = false;
    assert!(source.connect(unsaved).await.is_err());
    assert_eq!(mock.state.lock().unwrap().requests, 0);
    mock.state.lock().unwrap().public = true;
    assert_eq!(
        source
            .connect(input(&key, "new"))
            .await
            .err()
            .unwrap()
            .to_string(),
        "GITHUB_PRIVATE_REQUIRED"
    );
    assert!(!source.status().unwrap().connected);
    mock.state.lock().unwrap().public = false;
    source.connect(input(&key, "new")).await.unwrap();
    source.upload().await.unwrap();
    let (_b, target) = mock.manager();
    let before = fs::read(target.vault.data_dir().join("vault.json")).unwrap();
    assert_eq!(
        target
            .connect(input(&generate_recovery_key().unwrap(), "existing"))
            .await
            .err()
            .unwrap()
            .to_string(),
        "GITHUB_KEY_MISMATCH"
    );
    assert!(!target.status().unwrap().connected);
    assert_eq!(
        fs::read(target.vault.data_dir().join("vault.json")).unwrap(),
        before
    );
    assert_eq!(
        target
            .connect(input(&key, "new"))
            .await
            .err()
            .unwrap()
            .to_string(),
        "GITHUB_BACKUP_EXISTS"
    );
    mock.state.lock().unwrap().public = true;
    assert_eq!(
        source.upload().await.err().unwrap().to_string(),
        "GITHUB_PRIVATE_REQUIRED"
    );
    assert_eq!(
        source.restore().await.err().unwrap().to_string(),
        "GITHUB_PRIVATE_REQUIRED"
    );
    assert_eq!(mock.state.lock().unwrap().writes, 1);
}

#[tokio::test]
async fn optimistic_write_conflicts_and_remote_deletion_never_force_overwrite() {
    let mock = MockGithub::start().await;
    let (_directory, manager) = mock.manager();
    let key = generate_recovery_key().unwrap();
    manager.connect(input(&key, "new")).await.unwrap();
    manager.upload().await.unwrap();
    let before = mock.state.lock().unwrap().bytes.clone();
    mock.state.lock().unwrap().conflict_on_put = true;
    assert_eq!(
        manager.upload().await.err().unwrap().to_string(),
        "GITHUB_CONFLICT"
    );
    assert_eq!(mock.state.lock().unwrap().bytes, before);
    mock.state.lock().unwrap().bytes = None;
    assert_eq!(
        manager.upload().await.err().unwrap().to_string(),
        "GITHUB_REMOTE_CHANGED"
    );
    assert!(mock.state.lock().unwrap().bytes.is_none());
}

#[tokio::test]
async fn large_contents_use_the_pinned_blob_and_errors_are_redacted() {
    let mock = MockGithub::start().await;
    let (_directory, manager) = mock.manager();
    let key = generate_recovery_key().unwrap();
    manager.connect(input(&key, "new")).await.unwrap();
    manager.upload().await.unwrap();
    mock.state.lock().unwrap().force_blob = true;
    manager.restore().await.unwrap();
    for (status, expected) in [
        (401, "GITHUB_AUTH"),
        (403, "GITHUB_PERMISSION"),
        (429, "GITHUB_RATE_LIMIT"),
        (302, "GITHUB_REDIRECT"),
    ] {
        mock.state.lock().unwrap().force_status = Some(status);
        let error = manager.restore().await.err().unwrap().to_string();
        assert_eq!(error, expected);
        assert!(!error.contains("token-and-secret-marker"));
    }
}

#[tokio::test]
async fn bidirectional_sync_merges_multi_device_edits_propagates_deletions_and_skips_empty_commits() {
    let mock = MockGithub::start().await;
    let (_dir_a, device_a) = mock.manager();
    let (_dir_b, device_b) = mock.manager();
    let key = generate_recovery_key().unwrap();

    // Device A saves item 1 and connects with auto_sync enabled.
    let mut cfg_a = input(&key, "new");
    cfg_a.auto_sync = true;
    device_a.connect(cfg_a).await.unwrap();
    let item1 = device_a
        .vault
        .save_connection(crate::model::ConnectionInput {
            login_uris: Vec::new(),
            item_type: "login".into(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![
                crate::model::ItemModule {
                    kind: "username".into(),
                    ..Default::default()
                },
                crate::model::ItemModule {
                    kind: "password".into(),
                    ..Default::default()
                },
            ],
            name: "Shared Login".into(),
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
                let mut s = crate::model::SecretBundle::default();
                s.password = Some("pass-v1".into());
                s.named_secrets.insert("username".into(), "alice".into());
                s
            },
        })
        .unwrap();

    let first_sync = device_a.sync().await.unwrap();
    assert_eq!(first_sync.action, "pushed");
    assert!(first_sync.status.auto_sync);
    assert_eq!(mock.state.lock().unwrap().writes, 1);

    // Second sync with no changes must NOT create an empty commit.
    let noop = device_a.sync().await.unwrap();
    assert_eq!(noop.action, "up_to_date");
    assert_eq!(mock.state.lock().unwrap().writes, 1);

    // Device B connects to existing repo and syncs -> pulls Shared Login!
    let mut cfg_b = input(&key, "existing");
    cfg_b.auto_sync = true;
    device_b.connect(cfg_b).await.unwrap();
    let pull_b = device_b.sync().await.unwrap();
    assert_eq!(pull_b.merge.added, 1);
    assert_eq!(device_b.vault.list_connections().unwrap().len(), 1);
    assert_eq!(
        device_b.vault.list_connections().unwrap()[0].id,
        item1.id
    );

    // Device B adds item 2 while Device A permanently deletes item 1.
    device_b
        .vault
        .save_connection(crate::model::ConnectionInput {
            login_uris: Vec::new(),
            item_type: "api".into(),
            folder: String::new(),
            favorite: false,
            id: None,
            modules: vec![crate::model::ItemModule {
                kind: "apiCredential".into(),
                ..Default::default()
            }],
            name: "Mac API Key".into(),
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
                let mut s = crate::model::SecretBundle::default();
                s.named_secrets.insert("apiCredential".into(), "mac-key-123".into());
                s
            },
        })
        .unwrap();
    let b_push = device_b.sync().await.unwrap();
    assert_eq!(b_push.action, "pushed");

    // Sleep briefly so tombstone timestamp is strictly newer than item1.updated_at.
    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
    device_a
        .vault
        .trash_connection(item1.id, Some(&item1.updated_at))
        .unwrap();
    let trashed = device_a.vault.trash_items().unwrap();
    device_a
        .vault
        .purge_connection(item1.id, &trashed[0].deleted_at)
        .unwrap();

    // Device A syncs: receives Mac API Key AND pushes tombstone for Shared Login (does NOT resurrect Shared Login!).
    let a_merge = device_a.sync().await.unwrap();
    assert_eq!(a_merge.action, "merged");
    let a_names: Vec<_> = device_a
        .vault
        .list_connections()
        .unwrap()
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(a_names, vec!["Mac API Key"]);

    // Device B syncs: receives tombstone and removes Shared Login while keeping Mac API Key!
    let b_final = device_b.sync().await.unwrap();
    assert_eq!(b_final.merge.deleted, 1);
    let b_names: Vec<_> = device_b
        .vault
        .list_connections()
        .unwrap()
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(b_names, vec!["Mac API Key"]);

    // Toggle auto_sync off cleanly.
    let disabled = device_b.set_auto_sync(false).unwrap();
    assert!(!disabled.auto_sync);
    assert!(!device_b.is_auto_sync_enabled());
}

#[test]
fn gitea_provider_validation_enforces_https_and_builds_api_v1_base() {
    assert_eq!(normalize_provider("").unwrap(), "github");
    assert_eq!(normalize_provider("forgejo").unwrap(), "gitea");
    assert!(normalize_server_url("gitea", "http://git.example.com").is_err());
    let base = gitea_api_base("https://git.example.com/subpath").unwrap();
    assert_eq!(base.as_str(), "https://git.example.com/subpath/api/v1/");
    let base_dedup = gitea_api_base("https://git.example.com/api/v1/").unwrap();
    assert_eq!(base_dedup.as_str(), "https://git.example.com/api/v1/");
    assert_eq!(
        parse_repository_for("https://git.example.com/alice/vault.git", "https://git.example.com")
            .unwrap(),
        ("alice".to_owned(), "vault".to_owned())
    );
}

#[tokio::test]
async fn gitea_full_http_e2e_post_create_put_update_token_auth_and_public_rejection() {
    #[derive(Default)]
    struct GiteaState {
        bytes: Option<Vec<u8>>,
        public: bool,
        post_creates: usize,
        put_updates: usize,
        auth_headers: Vec<String>,
    }

    async fn gitea_handler(
        State(state): State<Arc<Mutex<GiteaState>>>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> AxumResponse {
        let mut s = state.lock().unwrap();
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        s.auth_headers.push(auth.clone());
        if auth != "token gitea-secret-tok" {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        if method == Method::GET && uri.path() == "/api/v1/user" {
            return Json(json!({"login": "alice"})).into_response();
        }
        if method == Method::GET && uri.path() == "/api/v1/repos/alice/vault" {
            return Json(json!({"id": 42, "private": !s.public, "archived": false, "disabled": false, "default_branch": "main"})).into_response();
        }
        let content_path = format!("/api/v1/repos/alice/vault/contents/{CLOUD_FILE}");
        if method == Method::GET && uri.path() == content_path {
            return match &s.bytes {
                None => StatusCode::NOT_FOUND.into_response(),
                Some(bytes) => Json(json!({
                    "type": "file",
                    "sha": blob_sha(bytes),
                    "size": bytes.len(),
                    "encoding": "base64",
                    "content": STANDARD.encode(bytes),
                }))
                .into_response(),
            };
        }
        if method == Method::POST && uri.path() == content_path {
            if s.bytes.is_some() {
                return StatusCode::CONFLICT.into_response();
            }
            let req: Value = serde_json::from_slice(&body).unwrap();
            let bytes = STANDARD.decode(req["content"].as_str().unwrap()).unwrap();
            let sha = blob_sha(&bytes);
            s.bytes = Some(bytes);
            s.post_creates += 1;
            return (StatusCode::CREATED, Json(json!({"content": {"sha": sha}}))).into_response();
        }
        if method == Method::PUT && uri.path() == content_path {
            let req: Value = serde_json::from_slice(&body).unwrap();
            let current_sha = s.bytes.as_ref().map(|b| blob_sha(b));
            if req.get("sha").and_then(Value::as_str) != current_sha.as_deref() {
                return StatusCode::CONFLICT.into_response();
            }
            let bytes = STANDARD.decode(req["content"].as_str().unwrap()).unwrap();
            let sha = blob_sha(&bytes);
            s.bytes = Some(bytes);
            s.put_updates += 1;
            return Json(json!({"content": {"sha": sha}})).into_response();
        }
        StatusCode::NOT_FOUND.into_response()
    }

    let state = Arc::new(Mutex::new(GiteaState::default()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let router = Router::new().fallback(gitea_handler).with_state(state.clone());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); });

    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let dev_a = GithubBackup::new(Vault::open(dir_a.path().join("vault")).unwrap()).unwrap();
    let dev_b = GithubBackup::new(Vault::open(dir_b.path().join("vault")).unwrap()).unwrap();
    let key = generate_recovery_key().unwrap();

    let gitea_input = |mode: &str| ConnectInput {
        repository: format!("{server_url}/alice/vault.git"),
        token: "gitea-secret-tok".into(),
        recovery_key: key.clone(),
        mode: mode.into(),
        recovery_key_saved: true,
        auth_source: "token".into(),
        create_repository: false,
        auto_sync: true,
        provider: "gitea".into(),
        server_url: server_url.clone(),
        master_passphrase: String::new(),
    };

    // Verify Gitea account pre-check via /api/v1/user
    let acct = dev_a
        .account(AuthInput {
            auth_source: "token".into(),
            token: "gitea-secret-tok".into(),
            provider: "gitea".into(),
            server_url: server_url.clone(),
        })
        .await
        .unwrap();
    assert_eq!(acct.login, "alice");

    // Reject public Gitea repository
    state.lock().unwrap().public = true;
    assert!(dev_a.connect(gitea_input("new")).await.is_err());
    state.lock().unwrap().public = false;

    // Connect private Gitea repo + initial sync -> MUST use POST
    let status = dev_a.connect(gitea_input("new")).await.unwrap();
    assert_eq!(status.provider, "gitea");
    let mut s1 = SecretBundle::default();
    s1.named_secrets.insert("apiCredential".into(), "gitea-tok-1".into());
    dev_a.vault.save_connection(ConnectionInput {
        login_uris: vec![], item_type: "api".into(), folder: String::new(), favorite: false, id: None,
        modules: vec![ItemModule { kind: "apiCredential".into(), ..Default::default() }],
        name: "Gitea First".into(), enabled: true, description: String::new(), http_auth_type: String::new(),
        private_key_import_path: String::new(), auth_header: String::new(), auth_location: String::new(),
        auth_prefix: String::new(), api_auth_headers: vec![], test_path: String::new(),
        remove_secret_names: vec![], secrets: s1,
    }).unwrap();
    let first = dev_a.sync().await.unwrap();
    assert_eq!(first.action, "pushed");
    assert_eq!(state.lock().unwrap().post_creates, 1);
    assert_eq!(state.lock().unwrap().put_updates, 0);

    // Second device connects & syncs, adds item -> MUST use PUT with sha
    dev_b.connect(gitea_input("existing")).await.unwrap();
    let b_pull = dev_b.sync().await.unwrap();
    assert_eq!(b_pull.merge.added, 1);
    let mut s2 = SecretBundle::default();
    s2.named_secrets.insert("apiCredential".into(), "gitea-tok-2".into());
    dev_b.vault.save_connection(ConnectionInput {
        login_uris: vec![], item_type: "api".into(), folder: String::new(), favorite: false, id: None,
        modules: vec![ItemModule { kind: "apiCredential".into(), ..Default::default() }],
        name: "Gitea Second".into(), enabled: true, description: String::new(), http_auth_type: String::new(),
        private_key_import_path: String::new(), auth_header: String::new(), auth_location: String::new(),
        auth_prefix: String::new(), api_auth_headers: vec![], test_path: String::new(),
        remove_secret_names: vec![], secrets: s2,
    }).unwrap();
    assert!(dev_b.status().unwrap().pending_sync, "Local edit must mark status.pending_sync = true");
    let b_push = dev_b.sync().await.unwrap();
    assert_eq!(b_push.action, "pushed");
    assert!(!b_push.status.pending_sync, "Successful sync clears pending_sync");
    assert!(!dev_b.status().unwrap().pending_sync);
    assert_eq!(state.lock().unwrap().post_creates, 1);
    assert_eq!(state.lock().unwrap().put_updates, 1);
    assert!(state.lock().unwrap().auth_headers.iter().all(|h| h == "token gitea-secret-tok"));

    task.abort();
}

#[tokio::test]
async fn sync_recovers_from_409_conflict_storm_and_rejects_tampered_ciphertext() {
    let mock = MockGithub::start().await;
    let (_da, dev_a) = mock.manager();
    let (_db, dev_b) = mock.manager();
    let key = generate_recovery_key().unwrap();

    dev_a.connect(input(&key, "new")).await.unwrap();
    dev_a.sync().await.unwrap();
    dev_b.connect(input(&key, "existing")).await.unwrap();
    dev_b.sync().await.unwrap();

    // Both devices edit offline simultaneously
    let make_api = |name: &str, tok: &str| {
        let mut s = SecretBundle::default();
        s.named_secrets.insert("apiCredential".into(), tok.into());
        ConnectionInput {
            login_uris: vec![], item_type: "api".into(), folder: String::new(), favorite: false, id: None,
            modules: vec![ItemModule { kind: "apiCredential".into(), ..Default::default() }],
            name: name.into(), enabled: true, description: String::new(), http_auth_type: String::new(),
            private_key_import_path: String::new(), auth_header: String::new(), auth_location: String::new(),
            auth_prefix: String::new(), api_auth_headers: vec![], test_path: String::new(),
            remove_secret_names: vec![], secrets: s,
        }
    };
    dev_a.vault.save_connection(make_api("Device A Key", "tok-a")).unwrap();
    dev_b.vault.save_connection(make_api("Device B Key", "tok-b")).unwrap();

    // Device B pushes first; also force a transient 409 conflict on Device A's first PUT!
    dev_b.sync().await.unwrap();
    mock.state.lock().unwrap().conflict_on_put = true;
    let a_res = dev_a.sync().await.unwrap();
    assert_eq!(a_res.action, "merged");
    let mut a_names: Vec<_> = dev_a.vault.list_connections().unwrap().into_iter().map(|c| c.name).collect();
    a_names.sort();
    assert_eq!(a_names, vec!["Device A Key", "Device B Key"]);

    // Tamper 1 byte inside remote ciphertext -> sync MUST fail cleanly and keep local vault intact
    {
        let mut guard = mock.state.lock().unwrap();
        let bytes = guard.bytes.as_mut().unwrap();
        let mut doc: Value = serde_json::from_slice(bytes).unwrap();
        let ct = doc["payload"]["ciphertext"].as_str().unwrap().to_owned();
        let mut chars: Vec<char> = ct.chars().collect();
        chars[4] = if chars[4] == 'A' { 'B' } else { 'A' };
        doc["payload"]["ciphertext"] = json!(chars.into_iter().collect::<String>());
        *bytes = serde_json::to_vec(&doc).unwrap();
    }
    assert!(dev_b.sync().await.is_err());
    assert_eq!(dev_b.vault.list_connections().unwrap().len(), 1);
}

#[tokio::test]
async fn discovers_private_openkeylet_repos_and_never_surfaces_public_repos() {
    let valid_envelope = serde_json::to_vec(&json!({
        "format": CLOUD_FORMAT,
        "version": 1,
        "cipher": "xchacha20poly1305",
        "payload": { "version": 1, "nonce": "AAAA", "ciphertext": "BBBB" }
    }))
    .unwrap();
    let envelope_b64 = STANDARD.encode(&valid_envelope);
    let envelope_size = valid_envelope.len();
    let envelope_sha = blob_sha(&valid_envelope);

    let router = Router::new().fallback(move |method: Method, uri: Uri| {
        let envelope_b64 = envelope_b64.clone();
        let envelope_sha = envelope_sha.clone();
        async move {
            if method == Method::GET && uri.path() == "/user" {
                return Json(json!({ "login": "alice" })).into_response();
            }
            if method == Method::GET && uri.path() == "/user/repos" {
                return Json(json!([
                    {
                        "name": "openkeylet-public-decoy",
                        "full_name": "alice/openkeylet-public-decoy",
                        "owner": { "login": "alice" },
                        "private": false,
                        "archived": false,
                        "disabled": false,
                        "default_branch": "main",
                        "topics": ["openkeylet-vault"],
                        "updated_at": "2026-11-24T12:00:00Z"
                    },
                    {
                        "name": "my-secret-safe",
                        "full_name": "alice/my-secret-safe",
                        "owner": { "login": "alice" },
                        "private": true,
                        "archived": false,
                        "disabled": false,
                        "default_branch": "main",
                        "topics": [],
                        "updated_at": "2026-11-24T11:00:00Z"
                    },
                    {
                        "name": "openkeylet-vault",
                        "full_name": "alice/openkeylet-vault",
                        "owner": { "login": "alice" },
                        "private": true,
                        "archived": false,
                        "disabled": false,
                        "default_branch": "main",
                        "topics": ["openkeylet-vault"],
                        "updated_at": "2026-11-24T10:00:00Z"
                    },
                    {
                        "name": "unrelated-private-notes",
                        "full_name": "alice/unrelated-private-notes",
                        "owner": { "login": "alice" },
                        "private": true,
                        "archived": false,
                        "disabled": false,
                        "default_branch": "main",
                        "topics": [],
                        "updated_at": "2026-11-24T09:00:00Z"
                    }
                ]))
                .into_response();
            }
            if method == Method::GET
                && uri.path() == format!("/repos/alice/my-secret-safe/contents/{CLOUD_FILE}")
            {
                return Json(json!({
                    "type": "file",
                    "sha": envelope_sha,
                    "size": envelope_size,
                    "encoding": "base64",
                    "content": envelope_b64
                }))
                .into_response();
            }
            StatusCode::NOT_FOUND.into_response()
        }
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path().join("vault")).unwrap();
    let mut manager = GithubBackup::new(vault).unwrap();
    manager.api_base = base;

    let account = manager
        .account(AuthInput {
            auth_source: "token".into(),
            token: "test-token".into(),
            provider: "github".into(),
            server_url: String::new(),
        })
        .await
        .unwrap();
    server.abort();

    assert_eq!(account.login, "alice");
    // Public decoy MUST be excluded; renamed private repo with vault file comes first, then topic-tagged private repo.
    assert_eq!(account.discovered_repos.len(), 2);
    assert!(account.discovered_repos.iter().all(|r| r.private));
    assert_eq!(account.discovered_repos[0].full_name, "alice/my-secret-safe");
    assert!(account.discovered_repos[0].has_vault_file);
    assert_eq!(account.discovered_repos[1].full_name, "alice/openkeylet-vault");
    assert!(account.discovered_repos[1].has_topic);
}

#[tokio::test]
async fn coupled_strong_mode_wipes_local_key_on_bind_and_reverts_on_disconnect() {
    let mock = MockGithub::start().await;
    let (dir, manager) = mock.manager();
    let vault_dir = dir.path().join("vault");
    assert!(vault_dir.join("master.key").is_file());
    assert!(!vault_dir.join(crate::crypto::STRONG_KEY_FILE).exists());

    // Save a secret before binding.
    let item: ConnectionInput = serde_json::from_value(json!({
        "name": "Prod SSH",
        "modules": [{ "kind": "password" }],
        "secrets": { "password": "top-secret-before-bind" }
    }))
    .unwrap();
    manager.vault.save_connection(item).unwrap();

    // Bind GitHub with a strong master passphrase -> enables Strong Cloud Vault mode together.
    let key = generate_recovery_key().unwrap();
    let mut cfg = input(&key, "new");
    cfg.master_passphrase = "My-Super-Strong-Passphrase-2026!".to_owned();
    let status = manager.connect(cfg).await.unwrap();
    assert!(status.connected);
    assert!(status.strong_mode);

    // Local master.key MUST be completely wiped from disk; strong-key.json MUST exist.
    assert!(!vault_dir.join("master.key").exists());
    assert!(vault_dir.join(crate::crypto::STRONG_KEY_FILE).is_file());
    manager.upload().await.unwrap();

    // Reopening from disk starts LOCKED (zero plaintext secrets or GitHub config readable).
    let reopened = Vault::open(vault_dir.clone()).unwrap();
    assert!(reopened.is_strong_mode());
    assert!(!reopened.is_strong_unlocked());
    assert!(reopened.list_decrypted_connections().is_err());

    // Wrong passphrase fails; correct master passphrase unlocks RAM key.
    assert!(reopened.unlock_strong("wrong-passphrase-12345").is_err());
    reopened
        .unlock_strong("My-Super-Strong-Passphrase-2026!")
        .unwrap();
    assert!(reopened.is_strong_unlocked());
    let items = reopened.list_decrypted_connections().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].secrets.get("password"),
        Some("top-secret-before-bind")
    );

    // Lock -> wipe RAM key -> unlock via okv1_ recovery key slot works too!
    reopened.lock_strong();
    assert!(!reopened.is_strong_unlocked());
    reopened.unlock_strong(&key).unwrap();
    assert_eq!(reopened.list_decrypted_connections().unwrap().len(), 1);

    // Disconnecting GitHub atomically reverts local vault back to local-only mode!
    let mut reopened_manager = GithubBackup::new(reopened.clone()).unwrap();
    reopened_manager.api_base = mock.base.clone();
    let disconnected = reopened_manager.disconnect().unwrap();
    assert!(!disconnected.connected);
    assert!(!disconnected.strong_mode);
    assert!(!reopened.is_strong_mode());
    assert!(vault_dir.join("master.key").is_file());
    assert!(!vault_dir.join(crate::crypto::STRONG_KEY_FILE).exists());

    // Reopening after disconnect works directly in local-only mode with all secrets intact.
    let final_vault = Vault::open(vault_dir).unwrap();
    assert!(!final_vault.is_strong_mode());
    let final_items = final_vault.list_decrypted_connections().unwrap();
    assert_eq!(
        final_items[0].secrets.get("password"),
        Some("top-secret-before-bind")
    );
}

#[tokio::test]
#[ignore = "Live end-to-end test against authenticated real GitHub account via gh CLI"]
async fn live_github_private_vault_discovery_sync_strong_mode_e2e() {
    use crate::session_broker::SessionBroker;

    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let vault_a_dir = dir_a.path().join("vault-a");
    let vault_b_dir = dir_b.path().join("vault-b");

    let vault_a = Vault::open(vault_a_dir.clone()).unwrap();
    let dev_a = GithubBackup::new(vault_a.clone()).unwrap();

    // 1. Authenticate via real local `gh` CLI and verify no public repos leak into discovery.
    let acct_a = dev_a
        .account(AuthInput {
            auth_source: "cli".into(),
            token: String::new(),
            provider: "github".into(),
            server_url: String::new(),
        })
        .await
        .expect("gh CLI login must succeed");
    println!("[LIVE] Authenticated GitHub account: {}", acct_a.login);
    assert!(acct_a.discovered_repos.iter().all(|r| r.private));

    let repo_full = format!("{}/openkeylet-vault", acct_a.login);
    let already_exists = acct_a
        .discovered_repos
        .iter()
        .any(|r| r.full_name.eq_ignore_ascii_case(&repo_full));

    // Seed synthetic items on Device A before binding.
    let ssh_item: ConnectionInput = serde_json::from_value(json!({
        "name": "Live-Test-SSH",
        "itemType": "ssh",
        "modules": [
            { "kind": "host", "value": "10.0.0.42" },
            { "kind": "username", "value": "deploy" },
            { "kind": "password" }
        ],
        "secrets": { "password": "live-ssh-pass-999-SECRET" }
    }))
    .unwrap();
    let api_item: ConnectionInput = serde_json::from_value(json!({
        "name": "Live-Test-API",
        "itemType": "api",
        "modules": [
            { "kind": "url", "value": "https://api.example.invalid" },
            { "kind": "apiCredential" }
        ],
        "secrets": { "apiKey": "live-api-token-888-SECRET" }
    }))
    .unwrap();
    let saved_ssh = vault_a.save_connection(ssh_item).unwrap();
    let saved_api = vault_a.save_connection(api_item).unwrap();

    // 2. Bind Device A -> create private repo (if new) + enable coupled Strong Cloud Vault mode!
    let recovery_key = generate_recovery_key().unwrap();
    let pass_a = "Live-Strong-Passphrase-A-2026!";
    let connect_status = dev_a
        .connect(ConnectInput {
            repository: repo_full.clone(),
            token: String::new(),
            recovery_key: recovery_key.clone(),
            mode: "new".into(),
            recovery_key_saved: true,
            auth_source: "cli".into(),
            create_repository: !already_exists,
            auto_sync: true,
            provider: "github".into(),
            server_url: String::new(),
            master_passphrase: pass_a.into(),
        })
        .await
        .expect("connecting & creating private openkeylet-vault must succeed");
    assert!(connect_status.connected);
    assert!(connect_status.strong_mode);
    assert!(!vault_a_dir.join("master.key").exists(), "master.key MUST be wiped");
    assert!(vault_a_dir.join(crate::crypto::STRONG_KEY_FILE).is_file());
    println!("[LIVE] Bound {repo_full} in Strong Cloud Vault mode (master.key wiped).");

    // 3. Push encrypted snapshot to GitHub.
    let push_res = dev_a.sync().await.expect("initial push must succeed");
    assert_eq!(push_res.action, "pushed");
    println!("[LIVE] Pushed encrypted snapshot to {repo_full}.");

    // 4. Independently inspect raw GitHub remote file & verify zero plaintext + private=true.
    let token = auth::token("cli", "").await.unwrap();
    let repo_info = dev_a
        .repository(&acct_a.login, "openkeylet-vault", &token, "github", "")
        .await
        .expect("repo must be private and readable");
    assert!(repo_info.private, "Repository MUST be private");
    let config_a = dev_a.connected().unwrap();
    let remote = dev_a
        .remote_file(&config_a)
        .await
        .unwrap()
        .expect("openkeylet.vault.json must exist on GitHub");
    let remote_text = String::from_utf8_lossy(&remote.bytes);
    assert!(remote_text.contains(CLOUD_FORMAT));
    assert!(!remote_text.contains("Live-Test-SSH"));
    assert!(!remote_text.contains("live-ssh-pass-999-SECRET"));
    assert!(!remote_text.contains("live-api-token-888-SECRET"));
    assert!(!remote_text.contains("okv1_"));
    println!(
        "[LIVE] Verified remote file is {} bytes of pure XChaCha20-Poly1305 ciphertext (zero plaintext).",
        remote.bytes.len()
    );

    // 5. Device B (brand-new machine) auto-discovers private openkeylet-vault with ZERO manual input!
    let vault_b = Vault::open(vault_b_dir.clone()).unwrap();
    let dev_b = GithubBackup::new(vault_b.clone()).unwrap();
    let acct_b = dev_b
        .account(AuthInput {
            auth_source: "cli".into(),
            token: String::new(),
            provider: "github".into(),
            server_url: String::new(),
        })
        .await
        .expect("Device B gh login must succeed");
    let found = acct_b
        .discovered_repos
        .iter()
        .find(|r| r.full_name.eq_ignore_ascii_case(&repo_full))
        .expect("Device B MUST auto-discover private openkeylet-vault");
    assert!(found.private);
    assert!(found.has_vault_file);
    println!(
        "[LIVE] Device B auto-discovered {} (private={}, has_vault_file={}, has_topic={})",
        found.full_name, found.private, found.has_vault_file, found.has_topic
    );

    // 6. Device B connects using discovered repo + okv1_ recovery key + its own master passphrase, then syncs!
    let pass_b = "Live-Strong-Passphrase-B-2026!";
    dev_b
        .connect(ConnectInput {
            repository: found.full_name.clone(),
            token: String::new(),
            recovery_key: recovery_key.clone(),
            mode: "existing".into(),
            recovery_key_saved: true,
            auth_source: "cli".into(),
            create_repository: false,
            auto_sync: true,
            provider: "github".into(),
            server_url: String::new(),
            master_passphrase: pass_b.into(),
        })
        .await
        .expect("Device B connect existing must succeed");
    let b_sync = dev_b.sync().await.expect("Device B initial pull must succeed");
    assert_eq!(b_sync.action, "pulled");
    assert_eq!(b_sync.merge.added, 2);
    let b_ssh = vault_b.get_connection(saved_ssh.id).unwrap();
    assert_eq!(b_ssh.secrets.get("password"), Some("live-ssh-pass-999-SECRET"));
    println!("[LIVE] Device B synced & decrypted all items from GitHub.");

    // 7. Device B adds a new item, updates API item, deletes SSH item -> pushes -> Device A pulls!
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let login_item: ConnectionInput = serde_json::from_value(json!({
        "name": "Live-Test-Login",
        "itemType": "login",
        "modules": [{ "kind": "username", "value": "akko" }, { "kind": "password" }],
        "secrets": { "password": "live-login-pass-777-SECRET" }
    }))
    .unwrap();
    vault_b.save_connection(login_item).unwrap();
    let updated_api: ConnectionInput = serde_json::from_value(json!({
        "id": saved_api.id,
        "name": "Live-Test-API",
        "itemType": "api",
        "modules": [
            { "kind": "url", "value": "https://api.example.invalid" },
            { "kind": "apiCredential" }
        ],
        "secrets": { "apiKey": "live-api-token-ROTATED" }
    }))
    .unwrap();
    vault_b.save_connection(updated_api).unwrap();
    vault_b.delete_connection(saved_ssh.id).unwrap();
    let b_push = dev_b.sync().await.expect("Device B push edits must succeed");
    assert_eq!(b_push.action, "pushed");

    let a_pull = dev_a.sync().await.expect("Device A pull edits must succeed");
    assert_eq!(a_pull.action, "pulled");
    assert_eq!(
        vault_a.get_connection(saved_api.id).unwrap().secrets.get("apiKey"),
        Some("live-api-token-ROTATED")
    );
    assert!(vault_a.get_connection(saved_ssh.id).is_err(), "Deleted item must move to trash on Device A");
    assert!(vault_a.list_connections().unwrap().iter().any(|c| c.name == "Live-Test-Login"));
    println!("[LIVE] Bidirectional add + update + delete sync verified across Device A & B.");

    // 8. Verify cold-start Strong Vault lock, passphrase/recovery unlock, and MCP SessionBroker!
    let reopened_a = Vault::open(vault_a_dir.clone()).unwrap();
    assert!(reopened_a.is_strong_mode());
    assert!(!reopened_a.is_strong_unlocked());
    assert!(reopened_a.list_decrypted_connections().is_err());

    let mcp_child = Vault::open(vault_a_dir.clone()).unwrap();
    assert!(mcp_child.list_decrypted_connections().is_err());

    reopened_a.unlock_strong(pass_a).unwrap();
    let broker = SessionBroker::new(vault_a_dir.clone());
    broker.start(reopened_a.clone()).unwrap();
    assert_eq!(mcp_child.list_decrypted_connections().unwrap().len(), 2);

    reopened_a.lock_strong();
    broker.stop();
    assert!(mcp_child.list_decrypted_connections().is_err(), "MCP child MUST lose access immediately on lock");

    // Unlock via okv1_ recovery slot and verify disconnect reverts cleanly to local mode!
    reopened_a.unlock_strong(&recovery_key).unwrap();
    let reopened_dev_a = GithubBackup::new(reopened_a.clone()).unwrap();
    let disc = reopened_dev_a.disconnect().unwrap();
    assert!(!disc.connected);
    assert!(!disc.strong_mode);
    assert!(vault_a_dir.join("master.key").is_file());
    assert!(!vault_a_dir.join(crate::crypto::STRONG_KEY_FILE).exists());
    println!("[LIVE] Strong lock/unlock, MCP SessionBroker revocation, okv1_ recovery & disconnect revert verified.");

    // 9. Clean synthetic test openkeylet.vault.json from GitHub so user starts with a spotless private repo!
    let latest_remote = dev_b
        .remote_file(&dev_b.connected().unwrap())
        .await
        .unwrap()
        .expect("latest remote file must exist");
    let del_resp = dev_b
        .request_for(
            Method::DELETE,
            &acct_a.login,
            "openkeylet-vault",
            &["contents", CLOUD_FILE],
            &token,
            "github",
            "",
        )
        .unwrap()
        .json(&json!({
            "message": "Clean up live E2E test fixture",
            "sha": latest_remote.sha,
            "branch": repo_info.default_branch
        }))
        .send()
        .await
        .unwrap();
    assert!(del_resp.status().is_success(), "Cleaning synthetic test file must succeed");
    println!("[LIVE] Cleaned synthetic test snapshot; {repo_full} is private, tagged, and ready for production use!");
}
