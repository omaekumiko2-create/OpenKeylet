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
    key_repo_exists: bool,
    key_repo_public: bool,
    key_repo_create_denied: bool,
    key_bytes: Option<Vec<u8>>,
    key_creates: usize,
    key_writes: usize,
    /// Every commit that touched the snapshot, oldest first; `None` bytes is a deletion.
    commits: Vec<MockCommit>,
    blob_reads: usize,
    history_queries: Vec<String>,
}

#[derive(Clone)]
struct MockCommit {
    sha: String,
    bytes: Option<Vec<u8>>,
    date: String,
}

impl MockState {
    fn commit(&mut self, bytes: Option<Vec<u8>>) -> String {
        let index = self.commits.len();
        let sha = blob_sha(format!("mock commit {index} {:?}", bytes.as_ref().map(|b| blob_sha(b))).as_bytes());
        let date = chrono::DateTime::from_timestamp(1_790_000_000 + index as i64 * 60, 0)
            .unwrap()
            .to_rfc3339();
        self.commits.push(MockCommit {
            sha: sha.clone(),
            bytes,
            date,
        });
        sha
    }

    /// The snapshot at `git_ref`: the branch head, or the file as of a known commit.
    fn bytes_at(&self, git_ref: Option<&str>) -> Option<Vec<u8>> {
        match git_ref {
            None | Some("main") => self.bytes.clone(),
            Some(sha) => self
                .commits
                .iter()
                .find(|commit| commit.sha == sha)
                .and_then(|commit| commit.bytes.clone()),
        }
    }
}

fn query_params(uri: &Uri) -> std::collections::HashMap<String, String> {
    url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
        .into_owned()
        .collect()
}

fn commit_json(commit: &MockCommit) -> Value {
    json!({
        "sha": commit.sha,
        "commit": {
            "author": {"name": "Synthetic", "email": "synthetic@example.invalid", "date": commit.date},
            "committer": {"name": "Synthetic", "email": "synthetic@example.invalid", "date": commit.date},
            "message": "Update encrypted OpenKeylet backup"
        }
    })
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
        assert_eq!(payload["private"], true);
        assert_eq!(payload["auto_init"], true);
        assert!(!String::from_utf8_lossy(&body).contains("okv1_"));
        if payload["name"] == "vault-key" {
            if state.key_repo_create_denied {
                return StatusCode::FORBIDDEN.into_response();
            }
            if state.key_repo_exists {
                return StatusCode::UNPROCESSABLE_ENTITY.into_response();
            }
            state.key_repo_exists = true;
            state.key_creates += 1;
            return (StatusCode::CREATED,Json(json!({"id":8,"private":true,"archived":false,"default_branch":"main"}))).into_response();
        }
        assert_eq!(payload["name"], "vault");
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
    if method == Method::GET && uri.path() == "/repos/test/vault-key" {
        if !state.key_repo_exists {
            return StatusCode::NOT_FOUND.into_response();
        }
        return Json(json!({"id": 8, "private": !state.key_repo_public, "archived": false,
            "disabled": false, "default_branch": "main"}))
        .into_response();
    }
    let key_path = format!("/repos/test/vault-key/contents/{}", key_repo::KEY_FILE);
    if method == Method::GET && uri.path() == key_path {
        return match &state.key_bytes {
            None => StatusCode::NOT_FOUND.into_response(),
            Some(bytes) => Json(json!({"type":"file", "sha":blob_sha(bytes), "size":bytes.len(),
                "encoding":"base64", "content":STANDARD.encode(bytes)}))
            .into_response(),
        };
    }
    if method == Method::PUT && uri.path() == key_path {
        let request: Value = serde_json::from_slice(&body).unwrap();
        assert!(state.key_repo_exists);
        assert!(state.key_bytes.is_none(), "a stored key must never be overwritten");
        assert!(request.get("sha").is_none());
        assert_eq!(request["branch"], "main");
        let bytes = STANDARD
            .decode(request["content"].as_str().unwrap())
            .unwrap();
        let sha = blob_sha(&bytes);
        state.key_bytes = Some(bytes);
        state.key_writes += 1;
        return Json(json!({"content":{"sha":sha}})).into_response();
    }
    let content_path = format!("/repos/test/vault/contents/{CLOUD_FILE}");
    if method == Method::GET && uri.path() == content_path {
        let params = query_params(&uri);
        return match state.bytes_at(params.get("ref").map(String::as_str)) {
            None => StatusCode::NOT_FOUND.into_response(),
            Some(bytes) => Json(
                json!({"type":"file", "sha":blob_sha(&bytes), "size":bytes.len(),
                    "encoding": if state.force_blob { "none" } else { "base64" },
                    "content": if state.force_blob { String::new() } else { STANDARD.encode(&bytes) }
                }),
            )
            .into_response(),
        };
    }
    if method == Method::GET && uri.path().starts_with("/repos/test/vault/git/blobs/") {
        // Blobs are addressed by content, so any version ever pushed can be read back.
        let wanted = uri.path().rsplit('/').next().unwrap();
        let found = state
            .bytes
            .iter()
            .chain(state.commits.iter().filter_map(|commit| commit.bytes.as_ref()))
            .find(|bytes| blob_sha(bytes) == wanted)
            .cloned();
        state.blob_reads += 1;
        return match found {
            None => StatusCode::NOT_FOUND.into_response(),
            Some(bytes) => Json(json!({"sha":blob_sha(&bytes), "size":bytes.len(),
                "encoding":"base64", "content":STANDARD.encode(&bytes)}))
            .into_response(),
        };
    }
    if method == Method::GET && uri.path() == "/repos/test/vault/commits" {
        let params = query_params(&uri);
        state.history_queries.push(uri.query().unwrap_or("").to_owned());
        assert_eq!(params.get("path").map(String::as_str), Some(CLOUD_FILE));
        assert_eq!(params.get("sha").map(String::as_str), Some("main"));
        let per_page: usize = params.get("per_page").map_or(30, |value| value.parse().unwrap());
        let page: usize = params.get("page").map_or(1, |value| value.parse().unwrap());
        let newest_first: Vec<&MockCommit> = state.commits.iter().rev().collect();
        let start = (page - 1) * per_page;
        let rows: Vec<Value> = newest_first
            .iter()
            .skip(start)
            .take(per_page)
            .map(|commit| commit_json(commit))
            .collect();
        let mut response = Json(Value::Array(rows)).into_response();
        if start + per_page < newest_first.len() {
            let link = format!(
                "<https://api.github.com/repositories/7/commits?page={}>; rel=\"next\", <https://api.github.com/repositories/7/commits?page=99>; rel=\"last\"",
                page + 1
            );
            response
                .headers_mut()
                .insert("link", axum::http::HeaderValue::from_str(&link).unwrap());
        }
        return response;
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
        state.commit(Some(bytes.clone()));
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
        auth_source: "token".into(),
        create_repository: false,
        auto_sync: false,
        provider: String::new(),
        server_url: String::new(),
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
    let mut request = input("okv1_not-a-key", "new");
    request.create_repository = true;
    assert_eq!(
        manager.connect(request).await.err().unwrap().to_string(),
        "GITHUB_KEY_INVALID"
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

#[tokio::test]
async fn binding_alone_restores_on_another_device_through_the_key_repository() {
    let remote = MockGithub::start().await;
    let (_directory, first) = remote.manager();
    add_item(
        &first.vault,
        Uuid::new_v4(),
        "Synced item",
        "secret-only-in-ciphertext",
    );

    // No key is supplied: connecting creates the key repository and stores a key in it.
    let status = first.connect(input("", "new")).await.unwrap();
    assert!(status.connected);
    assert_eq!(status.repository, "test/vault");
    assert_eq!(status.key_repository, "test/vault-key");
    let key = first.recovery_key().unwrap();
    {
        let state = remote.state.lock().unwrap();
        assert_eq!((state.key_creates, state.key_writes, state.writes), (1, 1, 0));
        let key_file: Value = serde_json::from_slice(state.key_bytes.as_ref().unwrap()).unwrap();
        assert_eq!(key_file["format"], "openkeylet-sync-key");
        assert_eq!(key_file["key"], key);
    }
    first.upload().await.unwrap();

    // Each repository on its own gives nothing usable: the vault repository holds only
    // ciphertext, the key repository only a key.
    {
        let state = remote.state.lock().unwrap();
        let ciphertext = String::from_utf8_lossy(state.bytes.as_ref().unwrap()).into_owned();
        assert!(!ciphertext.contains("secret-only-in-ciphertext"));
        assert!(!ciphertext.contains(&key));
        let key_text = String::from_utf8_lossy(state.key_bytes.as_ref().unwrap()).into_owned();
        assert!(!key_text.contains("secret-only-in-ciphertext"));
        assert!(!key_text.contains("Synced item"));
    }

    // A second device needs only the binding.
    let (_other_directory, second) = remote.manager();
    let status = second.connect(input("", "existing")).await.unwrap();
    assert!(status.needs_restore);
    assert_eq!(status.key_repository, "test/vault-key");
    assert_eq!(second.recovery_key().unwrap(), key);
    assert_eq!(second.restore().await.unwrap().summary.added, 1);
    let state = remote.state.lock().unwrap();
    assert_eq!((state.key_creates, state.key_writes), (1, 1));
}

#[tokio::test]
async fn a_supplied_key_stays_off_the_host_and_a_missing_key_repository_is_reported() {
    let remote = MockGithub::start().await;
    let (_directory, owner) = remote.manager();
    let key = generate_recovery_key().unwrap();
    add_item(&owner.vault, Uuid::new_v4(), "Self-held", "self-held-secret");

    // Supplying a key keeps it with its owner: no key repository is read or created.
    let status = owner.connect(input(&key, "new")).await.unwrap();
    assert_eq!(status.key_repository, "");
    owner.upload().await.unwrap();
    {
        let state = remote.state.lock().unwrap();
        assert!(!state.key_repo_exists);
        assert_eq!((state.key_creates, state.key_writes), (0, 0));
    }

    // Without that key another device cannot open the snapshot, and nothing is created.
    let (_other_directory, other) = remote.manager();
    assert_eq!(
        other.connect(input("", "existing")).await.err().unwrap().to_string(),
        "GITHUB_KEY_REPO_MISSING"
    );
    assert!(!other.status().unwrap().connected);
    assert!(!remote.state.lock().unwrap().key_repo_exists);

    other.connect(input(&key, "existing")).await.unwrap();
    assert_eq!(other.restore().await.unwrap().summary.added, 1);
}

#[tokio::test]
async fn key_repository_must_be_creatable_private_and_well_formed() {
    let remote = MockGithub::start().await;
    let (_directory, manager) = remote.manager();
    let connect = || async {
        manager
            .connect(input("", "new"))
            .await
            .map_err(|error| error.to_string())
    };

    remote.state.lock().unwrap().key_repo_create_denied = true;
    assert_eq!(connect().await.err().unwrap(), "GITHUB_KEY_REPO_CREATE");
    assert!(!manager.status().unwrap().connected);

    {
        let mut state = remote.state.lock().unwrap();
        state.key_repo_create_denied = false;
        state.key_repo_exists = true;
        state.key_repo_public = true;
    }
    assert_eq!(connect().await.err().unwrap(), "GITHUB_PRIVATE_REQUIRED");

    {
        let mut state = remote.state.lock().unwrap();
        state.key_repo_public = false;
        state.key_bytes = Some(br#"{"format":"something-else","version":1,"key":"x"}"#.to_vec());
    }
    assert_eq!(connect().await.err().unwrap(), "GITHUB_KEY_REPO_INVALID");
    assert!(!manager.status().unwrap().connected);

    // An existing private key repository without a key file is filled, not recreated.
    remote.state.lock().unwrap().key_bytes = None;
    assert_eq!(connect().await.unwrap().key_repository, "test/vault-key");
    let state = remote.state.lock().unwrap();
    assert_eq!((state.key_creates, state.key_writes), (0, 1));
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
    assert!(source.connect(input("okv1_too-short", "new")).await.is_err());
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
        key_repo_exists: bool,
        key_bytes: Option<Vec<u8>>,
        key_post_creates: usize,
        commits: Vec<MockCommit>,
        history_queries: Vec<String>,
    }

    // Gitea ignores `limit` when `path` is given and uses its own page size; a small
    // one here makes three pushes span two pages.
    const GITEA_PAGE: usize = 2;

    fn gitea_commit(s: &mut GiteaState, bytes: Vec<u8>) {
        let index = s.commits.len();
        s.commits.push(MockCommit {
            sha: blob_sha(format!("gitea commit {index} {}", blob_sha(&bytes)).as_bytes()),
            date: chrono::DateTime::from_timestamp(1_790_000_000 + index as i64 * 60, 0)
                .unwrap()
                .to_rfc3339(),
            bytes: Some(bytes),
        });
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
        if method == Method::POST && uri.path() == "/api/v1/user/repos" {
            let req: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(req["name"], "vault-key");
            assert_eq!(req["private"], true);
            s.key_repo_exists = true;
            return (StatusCode::CREATED, Json(json!({"id": 43, "private": true, "archived": false, "default_branch": "main"}))).into_response();
        }
        if method == Method::GET && uri.path() == "/api/v1/repos/alice/vault-key" {
            if !s.key_repo_exists {
                return StatusCode::NOT_FOUND.into_response();
            }
            return Json(json!({"id": 43, "private": true, "archived": false, "disabled": false, "default_branch": "main"})).into_response();
        }
        let key_path = format!("/api/v1/repos/alice/vault-key/contents/{}", key_repo::KEY_FILE);
        if method == Method::GET && uri.path() == key_path {
            return match &s.key_bytes {
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
        // Gitea creates a file with POST; a PUT without a sha would be rejected.
        if method == Method::POST && uri.path() == key_path {
            assert!(s.key_bytes.is_none());
            let req: Value = serde_json::from_slice(&body).unwrap();
            let bytes = STANDARD.decode(req["content"].as_str().unwrap()).unwrap();
            let sha = blob_sha(&bytes);
            s.key_bytes = Some(bytes);
            s.key_post_creates += 1;
            return (StatusCode::CREATED, Json(json!({"content": {"sha": sha}}))).into_response();
        }
        let content_path = format!("/api/v1/repos/alice/vault/contents/{CLOUD_FILE}");
        if method == Method::GET && uri.path() == content_path {
            let params = query_params(&uri);
            let bytes = match params.get("ref").map(String::as_str) {
                None | Some("main") => s.bytes.clone(),
                Some(sha) => s.commits.iter().find(|c| c.sha == sha).and_then(|c| c.bytes.clone()),
            };
            return match bytes {
                None => StatusCode::NOT_FOUND.into_response(),
                Some(bytes) => Json(json!({
                    "type": "file",
                    "sha": blob_sha(&bytes),
                    "size": bytes.len(),
                    "encoding": "base64",
                    "content": STANDARD.encode(&bytes),
                }))
                .into_response(),
            };
        }
        if method == Method::GET && uri.path() == "/api/v1/repos/alice/vault/commits" {
            let params = query_params(&uri);
            s.history_queries.push(uri.query().unwrap_or("").to_owned());
            assert_eq!(params.get("path").map(String::as_str), Some(CLOUD_FILE));
            assert_eq!(params.get("sha").map(String::as_str), Some("main"));
            let page: usize = params.get("page").map_or(1, |value| value.parse().unwrap());
            let newest_first: Vec<&MockCommit> = s.commits.iter().rev().collect();
            let start = (page - 1) * GITEA_PAGE;
            let rows: Vec<Value> = newest_first
                .iter()
                .skip(start)
                .take(GITEA_PAGE)
                .map(|commit| {
                    let mut row = commit_json(commit);
                    row["created"] = json!(commit.date);
                    row
                })
                .collect();
            let more = start + GITEA_PAGE < newest_first.len();
            return (
                [("x-hasmore", if more { "true" } else { "false" })],
                Json(Value::Array(rows)),
            )
                .into_response();
        }
        if method == Method::POST && uri.path() == content_path {
            if s.bytes.is_some() {
                return StatusCode::CONFLICT.into_response();
            }
            let req: Value = serde_json::from_slice(&body).unwrap();
            let bytes = STANDARD.decode(req["content"].as_str().unwrap()).unwrap();
            let sha = blob_sha(&bytes);
            gitea_commit(&mut s, bytes.clone());
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
            gitea_commit(&mut s, bytes.clone());
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

    // No key is supplied, so the key lives in the `alice/vault-key` repository.
    let gitea_input = |mode: &str| ConnectInput {
        repository: format!("{server_url}/alice/vault.git"),
        token: "gitea-secret-tok".into(),
        recovery_key: String::new(),
        mode: mode.into(),
        auth_source: "token".into(),
        create_repository: false,
        auto_sync: true,
        provider: "gitea".into(),
        server_url: server_url.clone(),
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
    assert_eq!(status.key_repository, "alice/vault-key");
    assert_eq!(state.lock().unwrap().key_post_creates, 1);
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
    assert_eq!(dev_b.recovery_key().unwrap(), dev_a.recovery_key().unwrap());
    assert_eq!(state.lock().unwrap().key_post_creates, 1);
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

    // Version history: a third push spans two Gitea pages, paged by `page` and `X-HasMore`.
    let mut s3 = SecretBundle::default();
    s3.named_secrets.insert("apiCredential".into(), "gitea-tok-3".into());
    dev_a.vault.save_connection(ConnectionInput {
        login_uris: vec![], item_type: "api".into(), folder: String::new(), favorite: false, id: None,
        modules: vec![ItemModule { kind: "apiCredential".into(), ..Default::default() }],
        name: "Gitea Third".into(), enabled: true, description: String::new(), http_auth_type: String::new(),
        private_key_import_path: String::new(), auth_header: String::new(), auth_location: String::new(),
        auth_prefix: String::new(), api_auth_headers: vec![], test_path: String::new(),
        remove_secret_names: vec![], secrets: s3,
    }).unwrap();
    assert_eq!(dev_a.sync().await.unwrap().action, "merged");
    let first_page = dev_a.list_versions(1).await.unwrap();
    assert_eq!(first_page.versions.len(), 2);
    assert!(first_page.has_more);
    assert!(first_page.versions[0].is_head && !first_page.versions[1].is_head);
    let second_page = dev_a.list_versions(2).await.unwrap();
    assert_eq!(second_page.versions.len(), 1);
    assert!(!second_page.has_more);
    assert!(!second_page.versions[0].is_head);
    {
        let s = state.lock().unwrap();
        let newest_first: Vec<&str> = s.commits.iter().rev().map(|c| c.sha.as_str()).collect();
        let listed: Vec<&str> = first_page.versions.iter().chain(&second_page.versions).map(|v| v.sha.as_str()).collect();
        assert_eq!(listed, newest_first);
        assert!(s.history_queries.iter().all(|q| !q.contains("limit") && !q.contains("per_page")));
    }
    // The oldest version holds only the first item, which is unchanged since.
    let oldest = &second_page.versions[0].sha;
    let VersionPreview::Ready { preview, .. } = dev_a.fetch_version(oldest).await.unwrap() else {
        panic!("the first Gitea version must open with the current key");
    };
    assert_eq!(preview.items.len(), 1);
    assert_eq!(preview.items[0].name, "Gitea First");
    assert_eq!(preview.items[0].status, "same");

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
    assert!(!account.discovery_failed);
    // Public decoy MUST be excluded; renamed private repo with vault file comes first, then topic-tagged private repo.
    assert_eq!(account.discovered_repos.len(), 2);
    assert!(account.discovered_repos.iter().all(|r| r.private));
    assert_eq!(account.discovered_repos[0].full_name, "alice/my-secret-safe");
    assert!(account.discovered_repos[0].has_vault_file);
    assert_eq!(account.discovered_repos[1].full_name, "alice/openkeylet-vault");
    assert!(account.discovered_repos[1].has_topic);
}

#[tokio::test]
#[ignore = "Live end-to-end test against authenticated real GitHub account via gh CLI"]
async fn live_github_private_vault_discovery_sync_e2e() {
    // A dedicated repository: the last step deletes the snapshot file, which must never
    // happen to a vault repository that is in real use.
    const LIVE_TEST_REPO: &str = "openkeylet-e2e-test";

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

    let repo_full = format!("{}/{LIVE_TEST_REPO}", acct_a.login);
    let token = auth::token("cli", "").await.unwrap();

    // An aborted earlier run leaves its snapshot behind. This repository exists only for
    // this test, so clear it before starting.
    if let Some(existing) = dev_a
        .find_repository(&acct_a.login, LIVE_TEST_REPO, &token, "github", "")
        .await
        .unwrap()
    {
        let leftover = dev_a
            .request_for(Method::GET, &acct_a.login, LIVE_TEST_REPO, &["contents", CLOUD_FILE], &token, "github", "")
            .unwrap()
            .query(&[("ref", &existing.default_branch)])
            .send()
            .await
            .unwrap();
        if leftover.status().is_success() {
            let file: Value = leftover.json().await.unwrap();
            let removed = dev_a
                .request_for(Method::DELETE, &acct_a.login, LIVE_TEST_REPO, &["contents", CLOUD_FILE], &token, "github", "")
                .unwrap()
                .json(&json!({
                    "message": "Clear leftover live E2E snapshot",
                    "sha": file["sha"],
                    "branch": existing.default_branch
                }))
                .send()
                .await
                .unwrap();
            assert!(removed.status().is_success(), "clearing a leftover snapshot must succeed");
            println!("[LIVE] Cleared a snapshot left behind by an earlier aborted run.");
        }
    }
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

    // 2. Bind Device A -> create private repo (if new); the key goes to `<repo>-key`.
    let connect_status = dev_a
        .connect(ConnectInput {
            repository: repo_full.clone(),
            token: String::new(),
            recovery_key: String::new(),
            mode: "new".into(),
            auth_source: "cli".into(),
            create_repository: !already_exists,
            auto_sync: true,
            provider: "github".into(),
            server_url: String::new(),
        })
        .await
        .expect("connecting & creating the private test repository must succeed");
    assert!(connect_status.connected);
    assert_eq!(connect_status.key_repository, format!("{repo_full}-key"));
    println!("[LIVE] Bound {repo_full}; key stored in {}.", connect_status.key_repository);

    // 3. Push encrypted snapshot to GitHub.
    let push_res = dev_a.sync().await.expect("initial push must succeed");
    assert_eq!(push_res.action, "pushed");
    println!("[LIVE] Pushed encrypted snapshot to {repo_full}.");

    // 4. Independently inspect raw GitHub remote file & verify zero plaintext + private=true.
    let repo_info = dev_a
        .repository(&acct_a.login, LIVE_TEST_REPO, &token, "github", "")
        .await
        .expect("repo must be private and readable");
    assert!(repo_info.private, "Repository MUST be private");
    // The key repository is private as well and holds exactly the key this device uses.
    let key_repo = format!("{LIVE_TEST_REPO}-key");
    let key_info = dev_a
        .repository(&acct_a.login, &key_repo, &token, "github", "")
        .await
        .expect("key repo must be private and readable");
    assert!(key_info.private, "Key repository MUST be private");
    let stored_key = dev_a
        .read_repo_key(&acct_a.login, &key_repo, &token, "github", "")
        .await
        .unwrap()
        .expect("key file must exist in the key repository");
    assert_eq!(*stored_key, dev_a.recovery_key().unwrap());
    println!("[LIVE] Verified {}/{key_repo} is private and holds the sync key.", acct_a.login);
    let config_a = dev_a.connected().unwrap();
    let remote = dev_a
        .remote_file(&config_a, &config_a.branch)
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
    // The listing can lag a moment behind a push, so allow a few attempts and report how
    // many were needed.
    let mut found = None;
    for attempt in 1..=6 {
        let acct_b = dev_b
            .account(AuthInput {
                auth_source: "cli".into(),
                token: String::new(),
                provider: "github".into(),
                server_url: String::new(),
            })
            .await
            .expect("Device B gh login must succeed");
        println!(
            "[LIVE] Discovery attempt {attempt}: {} private candidate(s) reported.",
            acct_b.discovered_repos.len()
        );
        found = acct_b
            .discovered_repos
            .into_iter()
            .find(|r| r.full_name.eq_ignore_ascii_case(&repo_full));
        if found.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let found = found.expect("Device B MUST auto-discover the private test repository");
    assert!(found.private);
    assert!(found.has_vault_file);
    println!(
        "[LIVE] Device B auto-discovered {} (private={}, has_vault_file={}, has_topic={})",
        found.full_name, found.private, found.has_vault_file, found.has_topic
    );

    // 6. Device B connects using only the discovered repo (its key comes from `<repo>-key`), then syncs!
    dev_b
        .connect(ConnectInput {
            repository: found.full_name.clone(),
            token: String::new(),
            recovery_key: String::new(),
            mode: "existing".into(),
            auth_source: "cli".into(),
            create_repository: false,
            auto_sync: true,
            provider: "github".into(),
            server_url: String::new(),
        })
        .await
        .expect("Device B connect existing must succeed");
    assert_eq!(dev_b.recovery_key().unwrap(), dev_a.recovery_key().unwrap());
    println!("[LIVE] Device B read the key from the key repository; nothing was typed.");
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

    // 8. Reopening from disk reads the vault directly; disconnect only removes local state.
    let reopened_a = Vault::open(vault_a_dir.clone()).unwrap();
    assert_eq!(reopened_a.list_decrypted_connections().unwrap().len(), 2);
    let reopened_dev_a = GithubBackup::new(reopened_a.clone()).unwrap();
    let disc = reopened_dev_a.disconnect().unwrap();
    assert!(!disc.connected);
    println!("[LIVE] Reopen and disconnect verified.");

    // 9. Clean synthetic test openkeylet.vault.json from GitHub so user starts with a spotless private repo!
    let config_b = dev_b.connected().unwrap();
    let latest_remote = dev_b
        .remote_file(&config_b, &config_b.branch)
        .await
        .unwrap()
        .expect("latest remote file must exist");
    let del_resp = dev_b
        .request_for(
            Method::DELETE,
            &acct_a.login,
            LIVE_TEST_REPO,
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
    println!("[LIVE] Cleaned synthetic test snapshot; {repo_full} and its key repository stay in the account for the next run.");
}

fn save_login(vault: &Vault, id: Option<Uuid>, name: &str, password: &str) -> crate::model::PublicConnection {
    let mut secrets = SecretBundle::default();
    secrets.password = Some(password.into());
    secrets.named_secrets.insert("username".into(), "alice".into());
    vault
        .save_connection(ConnectionInput {
            login_uris: Vec::new(),
            item_type: "login".into(),
            folder: String::new(),
            favorite: false,
            id,
            modules: vec![
                ItemModule { kind: "username".into(), ..Default::default() },
                ItemModule { kind: "password".into(), ..Default::default() },
            ],
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
            secrets,
        })
        .unwrap()
}

fn ready(preview: VersionPreview) -> (Zeroizing<Vec<u8>>, backup::HistoryPreview) {
    match preview {
        VersionPreview::Ready { plain, preview } => (plain, preview),
        VersionPreview::Unreadable { reason } => panic!("version must be readable, got {reason}"),
    }
}

fn unreadable_reason(preview: VersionPreview) -> String {
    match preview {
        VersionPreview::Ready { .. } => panic!("version must be reported as unreadable"),
        VersionPreview::Unreadable { reason } => reason,
    }
}

fn status_of<'a>(preview: &'a backup::HistoryPreview, id: Uuid) -> &'a str {
    &preview
        .items
        .iter()
        .find(|item| item.id == id.to_string())
        .unwrap()
        .status
}

#[tokio::test]
async fn version_history_lists_snapshot_commits_newest_first_and_pages() {
    let mock = MockGithub::start().await;
    let (_directory, device) = mock.manager();
    assert_eq!(
        device.list_versions(1).await.err().unwrap().to_string(),
        "GITHUB_NOT_CONNECTED"
    );
    let key = generate_recovery_key().unwrap();
    device.connect(input(&key, "new")).await.unwrap();
    let empty = device.list_versions(1).await.unwrap();
    assert!(empty.versions.is_empty() && !empty.has_more);

    let id = Uuid::new_v4();
    for round in 0..3 {
        add_item(&device.vault, id, "Rotated", &format!("rotated-secret-{round}"));
        device.sync().await.unwrap();
    }
    let listed = device.list_versions(1).await.unwrap();
    assert!(!listed.has_more);
    let expected: Vec<String> = mock
        .state
        .lock()
        .unwrap()
        .commits
        .iter()
        .rev()
        .map(|commit| commit.sha.clone())
        .collect();
    assert_eq!(listed.versions.iter().map(|v| v.sha.clone()).collect::<Vec<_>>(), expected);
    assert_eq!(listed.versions.iter().filter(|v| v.is_head).count(), 1);
    assert!(listed.versions[0].is_head);
    assert!(listed.versions.windows(2).all(|pair| pair[0].committed_at > pair[1].committed_at));
    assert!(listed.versions.iter().all(|v| chrono::DateTime::parse_from_rfc3339(&v.committed_at).is_ok()));

    // More versions than one page: GitHub pages by `per_page` and announces the rest in `Link`.
    {
        let mut state = mock.state.lock().unwrap();
        let bytes = state.bytes.clone();
        for _ in 0..30 {
            state.commit(bytes.clone());
        }
    }
    let first = device.list_versions(1).await.unwrap();
    assert_eq!(first.versions.len(), 30);
    assert!(first.has_more);
    let second = device.list_versions(2).await.unwrap();
    assert_eq!(second.versions.len(), 3);
    assert!(!second.has_more);
    assert!(second.versions.iter().all(|v| !v.is_head));
    let mut all: Vec<String> = first.versions.iter().chain(&second.versions).map(|v| v.sha.clone()).collect();
    assert_eq!(&all[30..], &expected[..]);
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 33);
    {
        let state = mock.state.lock().unwrap();
        assert!(state.history_queries.iter().all(|q| q.contains("per_page=30") && q.contains("path=openkeylet.vault.json")));
        assert_eq!(state.writes, 3, "listing never writes");
    }
    for page in [0, 1001] {
        assert_eq!(
            device.list_versions(page).await.err().unwrap().to_string(),
            "GITHUB_HISTORY_INVALID"
        );
    }
    // The repository is checked before its history is read.
    mock.state.lock().unwrap().public = true;
    assert_eq!(
        device.list_versions(1).await.err().unwrap().to_string(),
        "GITHUB_PRIVATE_REQUIRED"
    );
}

#[tokio::test]
async fn fetching_a_version_reads_that_commit_through_the_blob_fallback_and_flags_unreadable_rows() {
    let mock = MockGithub::start().await;
    let (_directory, device) = mock.manager();
    let key = generate_recovery_key().unwrap();
    device.connect(input(&key, "new")).await.unwrap();
    let id = Uuid::new_v4();
    add_item(&device.vault, id, "Versioned", "first-version-secret");
    device.sync().await.unwrap();
    add_item(&device.vault, id, "Versioned", "second-version-secret");
    device.sync().await.unwrap();
    let versions = device.list_versions(1).await.unwrap().versions;
    let (head, first) = (versions[0].sha.clone(), versions[1].sha.clone());

    let (plain, preview) = ready(device.fetch_version(&first).await.unwrap());
    assert!(String::from_utf8_lossy(&plain).contains("first-version-secret"));
    assert_eq!(status_of(&preview, id), "changed");
    assert_eq!((preview.total_items, preview.changed, preview.same), (1, 1, 0));
    assert!(!serde_json::to_string(&preview).unwrap().contains("version-secret"));
    let (_, head_preview) = ready(device.fetch_version(&head.to_uppercase()).await.unwrap());
    assert_eq!(status_of(&head_preview, id), "same");

    // Above 1 MB the Contents API omits the content, and the pinned blob of that commit is read.
    let blob_reads = {
        let mut state = mock.state.lock().unwrap();
        state.force_blob = true;
        state.blob_reads
    };
    let (blob_plain, _) = ready(device.fetch_version(&first).await.unwrap());
    assert_eq!(&*blob_plain, &*plain);
    assert_eq!(mock.state.lock().unwrap().blob_reads, blob_reads + 1);
    mock.state.lock().unwrap().force_blob = false;

    // Rows that cannot be opened say why, and the list around them keeps working.
    let foreign = encrypt_snapshot(&plain, &generate_recovery_key().unwrap()).unwrap();
    let foreign_sha = mock.state.lock().unwrap().commit(Some(foreign));
    assert_eq!(unreadable_reason(device.fetch_version(&foreign_sha).await.unwrap()), "GITHUB_KEY_MISMATCH");
    let removed_sha = mock.state.lock().unwrap().commit(None);
    assert_eq!(unreadable_reason(device.fetch_version(&removed_sha).await.unwrap()), "GITHUB_BACKUP_MISSING");
    let junk_sha = mock.state.lock().unwrap().commit(Some(b"{\"not\":\"a snapshot\"}".to_vec()));
    assert_eq!(unreadable_reason(device.fetch_version(&junk_sha).await.unwrap()), "GITHUB_BACKUP_INVALID");
    assert_eq!(
        unreadable_reason(device.fetch_version(&blob_sha(b"unknown commit")).await.unwrap()),
        "GITHUB_BACKUP_MISSING"
    );
    assert_eq!(device.list_versions(1).await.unwrap().versions.len(), 5);

    // Only a full object id is ever sent as a `ref`.
    for bad in ["main", "../main", "abc1234", &format!("{first}?ref=main"), &format!("{}g", &first[..39])] {
        assert_eq!(
            device.fetch_version(bad).await.err().unwrap().to_string(),
            "GITHUB_HISTORY_INVALID",
            "{bad}"
        );
    }
    // Transport failures are errors, not unreadable rows.
    mock.state.lock().unwrap().force_status = Some(429);
    assert_eq!(device.fetch_version(&first).await.err().unwrap().to_string(), "GITHUB_RATE_LIMIT");
    mock.state.lock().unwrap().force_status = None;

    // Fetching and previewing are read-only.
    assert_eq!(
        device.vault.get_connection(id).unwrap().secrets.get("apiCredential"),
        Some("second-version-secret")
    );
    assert_eq!(mock.state.lock().unwrap().writes, 2);
}

#[tokio::test]
async fn a_restored_item_survives_sync_and_reaches_another_device() {
    let mock = MockGithub::start().await;
    let (_a, first) = mock.manager();
    let (_b, second) = mock.manager();
    let key = generate_recovery_key().unwrap();
    first.connect(input(&key, "new")).await.unwrap();
    let login = save_login(&first.vault, None, "Mail login", "mail-pass-v1");
    let token = Uuid::new_v4();
    add_item(&first.vault, token, "Deploy token", "deploy-token-v1");
    first.sync().await.unwrap();
    second.connect(input(&key, "existing")).await.unwrap();
    second.sync().await.unwrap();

    tokio::time::sleep(Duration::from_millis(5)).await;
    let edited = save_login(&first.vault, Some(login.id), "Mail login", "mail-pass-v2");
    add_item(&first.vault, token, "Deploy token", "deploy-token-v2");
    first.sync().await.unwrap();
    second.sync().await.unwrap();
    assert_eq!(second.vault.get_connection(login.id).unwrap().secrets.get("password"), Some("mail-pass-v2"));

    // An edit not pushed yet is committed by the restore's own sync, before anything changes.
    let local = Uuid::new_v4();
    add_item(&first.vault, local, "Local only", "local-only-v1");
    let versions = first.list_versions(1).await.unwrap().versions;
    assert_eq!(versions.len(), 2);
    let v1 = versions[1].sha.clone();
    let (plain, preview) = ready(first.fetch_version(&v1).await.unwrap());
    assert_eq!(status_of(&preview, login.id), "changed");
    assert_eq!(status_of(&preview, token), "changed");
    assert_eq!(preview.total_items, 2, "items created after the version are not part of it");

    let writes_before = mock.state.lock().unwrap().writes;
    let result = first.restore_version(&v1, &plain, &[login.id]).await.unwrap();
    assert_eq!(result.pre_sync, "pushed");
    assert_eq!((result.summary.restored, result.summary.unchanged), (1, 0));
    assert!(result.status.pending_sync);
    assert_eq!(mock.state.lock().unwrap().writes, writes_before + 1);
    let undo = first.list_versions(1).await.unwrap().versions[0].sha.clone();
    let (undo_plain, undo_preview) = ready(first.fetch_version(&undo).await.unwrap());
    let undo_text = String::from_utf8_lossy(&undo_plain).into_owned();
    assert!(undo_text.contains("mail-pass-v2") && undo_text.contains("local-only-v1"));
    assert_eq!(status_of(&undo_preview, login.id), "changed", "undo restores the pre-restore value");

    let restored = first.vault.get_connection(login.id).unwrap();
    assert_eq!(restored.secrets.get("password"), Some("mail-pass-v1"));
    let history: Vec<&str> = restored.secrets.password_history.iter().map(|e| e.password.as_str()).collect();
    assert_eq!(history, ["mail-pass-v2", "mail-pass-v1"]);
    assert!(
        chrono::DateTime::parse_from_rfc3339(&restored.stored.updated_at).unwrap()
            > chrono::DateTime::parse_from_rfc3339(&edited.updated_at).unwrap()
    );
    assert_eq!(first.vault.get_connection(token).unwrap().secrets.get("apiCredential"), Some("deploy-token-v2"));
    let short = &v1[..7];
    assert!(
        first
            .vault
            .activities()
            .unwrap()
            .iter()
            .any(|a| a.connection_name == "Version history"
                && a.action == format!("Restore from version {short}: restored 1, unchanged 0"))
    );

    assert_eq!(first.sync().await.unwrap().action, "pushed");
    second.sync().await.unwrap();
    let on_second = second.vault.get_connection(login.id).unwrap();
    assert_eq!(on_second.secrets.get("password"), Some("mail-pass-v1"));
    assert_eq!(on_second.secrets.password_history[0].password, "mail-pass-v2");
    assert_eq!(second.vault.get_connection(token).unwrap().secrets.get("apiCredential"), Some("deploy-token-v2"));
    assert!(second.vault.get_connection(local).is_ok());

    // Later rounds in either order leave the restored value in place.
    for _ in 0..2 {
        first.sync().await.unwrap();
        second.sync().await.unwrap();
    }
    for device in [&first, &second] {
        assert_eq!(device.vault.get_connection(login.id).unwrap().secrets.get("password"), Some("mail-pass-v1"));
    }

    // Nothing selected, or a SHA that is not one, restores nothing.
    assert_eq!(first.restore_version(&v1, &plain, &[]).await.err().unwrap().to_string(), "GITHUB_HISTORY_EMPTY");
    assert_eq!(first.restore_version("main", &plain, &[login.id]).await.err().unwrap().to_string(), "GITHUB_HISTORY_INVALID");
}

#[tokio::test]
async fn restored_items_beat_their_tombstone_and_trash_on_every_device() {
    let mock = MockGithub::start().await;
    let (_a, first) = mock.manager();
    let (_b, second) = mock.manager();
    let key = generate_recovery_key().unwrap();
    first.connect(input(&key, "new")).await.unwrap();
    let purged = Uuid::new_v4();
    add_item(&first.vault, purged, "Purged item", "purged-secret");
    let trashed = Uuid::new_v4();
    add_item(&first.vault, trashed, "Trashed item", "trashed-secret");
    first.sync().await.unwrap();
    second.connect(input(&key, "existing")).await.unwrap();
    second.sync().await.unwrap();

    tokio::time::sleep(Duration::from_millis(5)).await;
    first.vault.trash_connection(purged, None).unwrap();
    let in_trash = first.vault.trash_items().unwrap();
    first.vault.purge_connection(purged, &in_trash[0].deleted_at).unwrap();
    first.sync().await.unwrap();
    second.vault.trash_connection(trashed, None).unwrap();
    second.sync().await.unwrap();
    first.sync().await.unwrap();
    for device in [&first, &second] {
        assert!(device.vault.get_connection(purged).is_err());
        assert!(device.vault.get_connection(trashed).is_err());
    }
    assert_eq!(first.vault.export_tombstones().unwrap().len(), 1);

    let v1 = first.list_versions(1).await.unwrap().versions.last().unwrap().sha.clone();
    let (plain, preview) = ready(first.fetch_version(&v1).await.unwrap());
    assert_eq!(status_of(&preview, purged), "deleted");
    assert_eq!(status_of(&preview, trashed), "trash");
    let result = first.restore_version(&v1, &plain, &[purged, trashed]).await.unwrap();
    assert_eq!(result.pre_sync, "up_to_date");
    assert_eq!(result.summary.restored, 2);
    assert!(first.vault.trash_items().unwrap().is_empty());
    assert!(first.vault.export_tombstones().unwrap().is_empty());

    // The other device still holds the tombstone and pushes it before this one pushes.
    tokio::time::sleep(Duration::from_millis(5)).await;
    add_item(&second.vault, Uuid::new_v4(), "Second device item", "second-secret");
    assert_eq!(second.sync().await.unwrap().action, "pushed");
    assert_eq!(second.vault.export_tombstones().unwrap().len(), 1);
    assert_eq!(first.sync().await.unwrap().action, "merged");
    assert_eq!(first.vault.get_connection(purged).unwrap().secrets.get("apiCredential"), Some("purged-secret"));
    assert!(first.vault.get_connection(trashed).is_ok());
    second.sync().await.unwrap();
    assert_eq!(second.vault.get_connection(purged).unwrap().secrets.get("apiCredential"), Some("purged-secret"));
    assert_eq!(second.vault.get_connection(trashed).unwrap().secrets.get("apiCredential"), Some("trashed-secret"));
    assert!(second.vault.trash_items().unwrap().is_empty());
    for _ in 0..2 {
        first.sync().await.unwrap();
        second.sync().await.unwrap();
    }
    for device in [&first, &second] {
        assert!(device.vault.get_connection(purged).is_ok());
        assert!(device.vault.get_connection(trashed).is_ok());
    }

    // A device joining now gets both items, whatever tombstone the snapshot still carries.
    let (_c, third) = mock.manager();
    third.connect(input(&key, "existing")).await.unwrap();
    third.sync().await.unwrap();
    assert!(third.vault.get_connection(purged).is_ok());
    assert!(third.vault.get_connection(trashed).is_ok());
}

#[tokio::test]
async fn account_check_reports_a_failed_repository_listing_instead_of_an_empty_one() {
    let failing = Router::new().fallback(|method: Method, uri: Uri| async move {
        if method == Method::GET && uri.path() == "/user" {
            return Json(json!({"login": "alice"})).into_response();
        }
        if method == Method::GET && uri.path() == "/user/repos" {
            return StatusCode::BAD_GATEWAY.into_response();
        }
        StatusCode::NOT_FOUND.into_response()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, failing).await.unwrap() });
    let directory = tempfile::tempdir().unwrap();
    let mut manager = GithubBackup::new(Vault::open(directory.path().join("vault")).unwrap()).unwrap();
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
    assert!(account.discovery_failed);
    assert!(account.discovered_repos.is_empty());
    assert_eq!(
        serde_json::to_value(&account).unwrap()["discoveryFailed"],
        json!(true)
    );
}
