use super::*;
use tempfile::tempdir;

// These tests temporarily release an OS-assigned port before the bridge
// binds it. Serialize them so Windows cannot assign it to both bridges.
static BRIDGE_TEST_LOCK: Mutex<()> = Mutex::const_new(());

fn test_server_state(vault: Vault) -> BridgeServerState {
    BridgeServerState {
        pin_throttle: Arc::new(Mutex::new(std::time::Instant::now())),
        vault,
        port: 0,
        config: BridgeNetworkConfig::default(),
        internal_token: "internal".to_owned(),
        extension_token: "extension".to_owned(),
        pairing: Arc::new(Mutex::new(None)),
        extensions: Arc::new(Mutex::new(ExtensionPool::default())),
        pending: Arc::new(Mutex::new(HashMap::new())),
        appearance: Arc::new(Mutex::new(BridgeAppearance::default())),
        cancellation: CancellationToken::new(),
        on_change: None,
    }
}

#[test]
fn bridge_roles_use_distinct_tokens() {
    let internal = derive_token("same-local-secret", "internal").unwrap();
    let extension = derive_token("same-local-secret", "extension").unwrap();
    assert_ne!(internal, extension);
}

#[tokio::test]
async fn stalled_extension_queue_is_bounded_and_client_is_removed() {
    let directory = tempdir().unwrap();
    let state = test_server_state(Vault::open(directory.path().join("vault")).unwrap());
    let (jobs, mut receiver) = mpsc::channel(1);
    jobs.send(BrowserJob::with_deadline(
        Uuid::new_v4(),
        "already queued".to_owned(),
        false,
    ))
    .await
    .unwrap();
    let (control, _control_rx) = mpsc::channel(1);
    state.extensions.lock().await.add(
        Uuid::new_v4(),
        jobs,
        control,
        None,
        "127.0.0.1".to_owned(),
    );

    let mut job = BrowserJob::with_deadline(Uuid::new_v4(), "secret".to_owned(), false);
    job.expires_at = unix_millis().saturating_add(100);
    let (result, _receiver) = oneshot::channel();
    state.pending.lock().await.insert(job.id, result);

    let started = std::time::Instant::now();
    assert!(!deliver_to_extension(&state, &job).await);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(state.extensions.lock().await.active().is_none());
    assert_eq!(receiver.recv().await.unwrap().value, "already queued");
}

#[tokio::test]
async fn expired_or_cancelled_jobs_cannot_be_delivered_later() {
    let directory = tempdir().unwrap();
    let state = test_server_state(Vault::open(directory.path().join("vault")).unwrap());

    let mut expired = BrowserJob::with_deadline(Uuid::new_v4(), "expired".to_owned(), false);
    expired.expires_at = unix_millis().saturating_sub(1);
    expired.normalize_deadline();
    let (result, _receiver) = oneshot::channel();
    state.pending.lock().await.insert(expired.id, result);
    assert!(expired.is_expired());
    assert!(!job_is_deliverable(&state, &expired).await);

    let active = BrowserJob::with_deadline(Uuid::new_v4(), "active".to_owned(), false);
    let (result, _receiver) = oneshot::channel();
    state.pending.lock().await.insert(active.id, result);
    assert!(job_is_deliverable(&state, &active).await);
    state.pending.lock().await.remove(&active.id);
    assert!(!job_is_deliverable(&state, &active).await);
}

#[tokio::test]
async fn first_job_waits_briefly_for_extension_reconnect() {
    let directory = tempdir().unwrap();
    let state = test_server_state(Vault::open(directory.path().join("vault")).unwrap());
    let job = BrowserJob::with_deadline(Uuid::new_v4(), "secret".to_owned(), false);
    let (result, _receiver) = oneshot::channel();
    state.pending.lock().await.insert(job.id, result);

    let extensions = state.extensions.clone();
    let (jobs, mut receiver) = mpsc::channel(1);
    let (control, _control_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        sleep(Duration::from_millis(100)).await;
        extensions.lock().await.add(
            Uuid::new_v4(),
            jobs,
            control,
            None,
            "127.0.0.1".to_owned(),
        );
    });

    assert!(deliver_to_extension_with_grace(&state, &job).await);
    assert_eq!(receiver.recv().await.unwrap().id, job.id);
}

#[tokio::test]
async fn quick_pairing_requires_a_chromium_extension_origin() {
    let _guard = BRIDGE_TEST_LOCK.lock().await;
    let port = {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.local_addr().unwrap().port()
    };
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let mut settings = vault.settings().unwrap();
    settings.browser_enabled = true;
    settings.browser_port = port;
    vault.update_settings(settings).unwrap();
    let bridge = BrowserBridge::new(vault.clone());
    bridge.sync().await;
    let client = reqwest::Client::new();
    let claim_url = format!("http://127.0.0.1:{port}/claim");
    let before_window = client
        .post(&claim_url)
        .header(
            header::ORIGIN,
            "chrome-extension://knkjojeijgalhpdkfapohofobfomenmi",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(before_window.status(), StatusCode::UNAUTHORIZED);
    for removed_path in ["pair", "internal/pair-code"] {
        let response = client
            .post(format!("http://127.0.0.1:{port}/{removed_path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    bridge.start_quick_pairing().await.unwrap();

    let web_page = client
        .post(format!("http://127.0.0.1:{port}/claim"))
        .header(header::ORIGIN, "https://example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(web_page.status(), StatusCode::FORBIDDEN);

    let extension = client
        .post(format!("http://127.0.0.1:{port}/claim"))
        .header(
            header::ORIGIN,
            "chrome-extension://knkjojeijgalhpdkfapohofobfomenmi",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(extension.status(), StatusCode::OK);
    let payload: serde_json::Value = extension.json().await.unwrap();
    assert!(
        payload["token"]
            .as_str()
            .is_some_and(|token| token.len() > 20)
    );
    assert!(payload.get("internalToken").is_none());
    assert_ne!(
        payload["token"].as_str().unwrap(),
        bridge.internal_token().unwrap()
    );
    assert!(vault.settings().unwrap().browser_paired);
    assert!(bridge.status().await.pairing_active);
    // Multiple Chrome profiles can pair within the same active pairing window.
    let second_profile = client
        .post(&claim_url)
        .header(
            header::ORIGIN,
            "chrome-extension://knkjojeijgalhpdkfapohofobfomenmi",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(second_profile.status(), StatusCode::OK);
    let second_payload: serde_json::Value = second_profile.json().await.unwrap();
    assert_eq!(second_payload["token"], payload["token"]);
    bridge.stop().await;
}

#[tokio::test]
async fn quick_pairing_rejects_an_expired_window() {
    let directory = tempdir().unwrap();
    let state = test_server_state(Vault::open(directory.path().join("vault")).unwrap());
    *state.pairing.lock().await = Some(PairingWindow {
        expires_at: std::time::Instant::now() - Duration::from_secs(1),
    });
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ORIGIN,
        "chrome-extension://knkjojeijgalhpdkfapohofobfomenmi"
            .parse()
            .unwrap(),
    );
    let (status, _) = claim(
        State(state.clone()),
        ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))),
        headers,
    )
    .await
    .unwrap_err();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(state.pairing.lock().await.is_none());
    assert!(!state.vault.settings().unwrap().browser_paired);
}

#[tokio::test]
async fn activated_extension_receives_the_job_and_a_standby_takes_over() {
    let _guard = BRIDGE_TEST_LOCK.lock().await;
    use tokio_tungstenite::tungstenite::Message as ClientMessage;

    let port = {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.local_addr().unwrap().port()
    };
    let directory = tempdir().unwrap();
    let vault = Vault::open(directory.path().join("vault")).unwrap();
    let mut settings = vault.settings().unwrap();
    settings.browser_enabled = true;
    settings.browser_port = port;
    vault.update_settings(settings).unwrap();
    vault.set_browser_paired(true).unwrap();
    let bridge = BrowserBridge::new(vault);
    bridge.sync().await;
    assert!(bridge.fill_configured());
    assert!(!bridge.status().await.connected);

    let url = format!("ws://127.0.0.1:{port}/extension");
    // WebSocket upgrade must reject missing or non-extension origins.
    assert!(tokio_tungstenite::connect_async(&url).await.is_err());

    let ws_request = || {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut req = url.as_str().into_client_request().unwrap();
        req.headers_mut().insert(
            header::ORIGIN,
            EXTENSION_ORIGIN.parse().unwrap(),
        );
        req
    };
    let auth = serde_json::json!({
        "type": "auth",
        "token": bridge.extension_token().unwrap()
    })
    .to_string();
    let (mut first, _) = tokio_tungstenite::connect_async(ws_request()).await.unwrap();
    first
        .send(ClientMessage::Text(auth.clone().into()))
        .await
        .unwrap();
    assert!(
        first
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap()
            .contains("ready")
    );
    sleep(Duration::from_millis(20)).await;
    let first_status = bridge.status().await;
    assert!(first_status.connected);
    assert_eq!(first_status.connected_count, 1);

    let (mut second, _) = tokio_tungstenite::connect_async(ws_request()).await.unwrap();
    second.send(ClientMessage::Text(auth.into())).await.unwrap();
    assert!(
        second
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap()
            .contains("ready")
    );
    sleep(Duration::from_millis(20)).await;
    assert_eq!(bridge.status().await.connected_count, 2);
    second
        .send(ClientMessage::Text(r#"{"type":"activate"}"#.into()))
        .await
        .unwrap();
    second
        .send(ClientMessage::Text(r#"{"type":"ping"}"#.into()))
        .await
        .unwrap();
    assert!(
        second
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap()
            .contains("pong")
    );

    let job_id = Uuid::new_v4();
    let client = reqwest::Client::new();
    let job_request = tokio::spawn({
        let url = format!("http://127.0.0.1:{port}/internal/jobs");
        let token = bridge.internal_token().unwrap();
        async move {
            client
                .post(url)
                .bearer_auth(token)
                .json(&serde_json::json!({"id": job_id, "value": "test-value"}))
                .send()
                .await
                .unwrap()
        }
    });

    let delivered = timeout(Duration::from_secs(2), second.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap();
    let delivered: serde_json::Value = serde_json::from_str(&delivered).unwrap();
    assert_eq!(delivered["type"], "job");
    assert_eq!(delivered["job"]["id"], job_id.to_string());

    if let Ok(Some(Ok(ClientMessage::Text(message)))) =
        timeout(Duration::from_millis(250), first.next()).await
    {
        let message: serde_json::Value = serde_json::from_str(&message).unwrap();
        assert_ne!(message["type"], "job");
    }

    second
        .send(ClientMessage::Text(
            serde_json::json!({
                "type": "complete",
                "jobId": job_id,
                "ok": true,
                "message": "done"
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    assert_eq!(job_request.await.unwrap().status(), StatusCode::OK);

    second.close(None).await.unwrap();
    sleep(Duration::from_millis(50)).await;
    let takeover_job_id = Uuid::new_v4();
    let takeover_request = tokio::spawn({
        let url = format!("http://127.0.0.1:{port}/internal/jobs");
        let token = bridge.internal_token().unwrap();
        async move {
            reqwest::Client::new()
                .post(url)
                .bearer_auth(token)
                .json(&serde_json::json!({"id": takeover_job_id, "value": "next"}))
                .send()
                .await
                .unwrap()
        }
    });
    let delivered = timeout(Duration::from_secs(2), first.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap();
    let delivered: serde_json::Value = serde_json::from_str(&delivered).unwrap();
    assert_eq!(delivered["job"]["id"], takeover_job_id.to_string());
    first
        .send(ClientMessage::Text(
            serde_json::json!({
                "type": "complete",
                "jobId": takeover_job_id,
                "ok": true,
                "message": "done"
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    assert_eq!(takeover_request.await.unwrap().status(), StatusCode::OK);
    bridge.stop().await;
}

#[test]
fn extension_manifest_version_matches_app_version() {
    let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("browser-extension")
        .join("manifest.json");
    let raw = std::fs::read_to_string(&manifest_path)
        .expect("browser-extension/manifest.json must exist");
    let manifest: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        manifest["version"].as_str(),
        Some(env!("CARGO_PKG_VERSION")),
        "browser-extension/manifest.json version must always stay in lockstep with Cargo.toml (run `npm run version:sync`)"
    );
}

#[tokio::test]
async fn extension_version_mismatch_is_reported_and_reload_is_broadcast() {
    use tokio_tungstenite::tungstenite::{
        Message as ClientMessage, client::IntoClientRequest,
    };
    let _guard = BRIDGE_TEST_LOCK.lock().await;
    let dir = tempdir().unwrap();
    let vault = Vault::open(dir.path().to_path_buf()).unwrap();
    let port = {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.local_addr().unwrap().port()
    };
    vault
        .update_settings(crate::model::Settings {
            browser_enabled: true,
            browser_port: port,
            ..crate::model::Settings::default()
        })
        .unwrap();
    let bridge = BrowserBridge::new(vault.clone());
    bridge.start_quick_pairing().await.unwrap();
    let client = reqwest::Client::new();
    let claim = client
        .post(format!("http://127.0.0.1:{port}/claim"))
        .header(header::ORIGIN, EXTENSION_ORIGIN)
        .send()
        .await
        .unwrap();
    assert_eq!(claim.status(), reqwest::StatusCode::OK);

    let mut request = format!("ws://127.0.0.1:{port}/extension")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("Origin", EXTENSION_ORIGIN.parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    ws.send(ClientMessage::Text(
        serde_json::json!({
            "type": "auth",
            "token": bridge.extension_token().unwrap(),
            "extensionVersion": "0.1.0"
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    let ready_text = ws.next().await.unwrap().unwrap().into_text().unwrap();
    let ready_json: serde_json::Value = serde_json::from_str(&ready_text).unwrap();
    assert_eq!(ready_json["type"], "ready");
    assert_eq!(ready_json["appVersion"], env!("CARGO_PKG_VERSION"));

    sleep(Duration::from_millis(20)).await;
    let status = bridge.status().await;
    assert!(status.connected);
    assert_eq!(status.extension_version.as_deref(), Some("0.1.0"));
    assert!(status.extension_outdated);

    let reloaded = bridge.reload_extensions().await.unwrap();
    assert_eq!(reloaded, 1);
    let reload_text = timeout(Duration::from_secs(2), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap();
    let reload_json: serde_json::Value = serde_json::from_str(&reload_text).unwrap();
    assert_eq!(reload_json["type"], "reload");
    assert_eq!(reload_json["appVersion"], env!("CARGO_PKG_VERSION"));

    // Verify live desktop appearance (theme & language) sync broadcasts cleanly.
    bridge
        .sync_appearance(Some("light".to_owned()), Some("zh".to_owned()))
        .await;
    let appearance_text = timeout(Duration::from_secs(2), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap();
    let appearance_json: serde_json::Value = serde_json::from_str(&appearance_text).unwrap();
    assert_eq!(appearance_json["type"], "appearance");
    assert_eq!(appearance_json["theme"], "light");
    assert_eq!(appearance_json["language"], "zh");

    bridge.stop().await;
}

#[test]
fn lan_binding_is_disabled_by_default_and_requires_explicit_opt_in() {
    let default_cfg = BridgeNetworkConfig::from_values(None, None, None, None, None, None).unwrap();
    assert_eq!(default_cfg.bind_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(!default_cfg.is_lan_mode());
    assert_eq!(default_cfg.internal_http_url(39272, "/internal/health"), "http://127.0.0.1:39272/internal/health");
    assert_eq!(default_cfg.advertised_endpoint(39272), "ws://127.0.0.1:39272/extension");

    let denied = BridgeNetworkConfig::from_values(Some("0.0.0.0"), None, None, None, None, None);
    assert!(denied.is_err());

    let allowed = BridgeNetworkConfig::from_values(
        Some("0.0.0.0"),
        Some("192.0.2.10"),
        Some("1"),
        Some("192.0.2.50,10.20.0.0/16,fd00::/8"),
        Some("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        Some("wss"),
    )
    .unwrap();
    assert!(allowed.is_lan_mode());
    assert_eq!(allowed.bind_addr(39272), SocketAddr::from(([0, 0, 0, 0], 39272)));
    // Unspecified bind 0.0.0.0 must use loopback for internal client HTTP calls.
    assert_eq!(allowed.internal_http_url(39272, "/internal/jobs"), "http://127.0.0.1:39272/internal/jobs");
    assert_eq!(allowed.advertised_endpoint(39272), "wss://192.0.2.10:39272/extension");
    assert!(allowed.allows_peer("127.0.0.1".parse().unwrap()));
    assert!(allowed.allows_peer("192.0.2.50".parse().unwrap()));
    assert!(allowed.allows_peer("10.20.4.9".parse().unwrap()));
    assert!(allowed.allows_peer("fd12::1".parse().unwrap()));
    assert!(!allowed.allows_peer("192.0.2.51".parse().unwrap()));
    assert!(!allowed.allows_peer("10.21.0.1".parse().unwrap()));
    assert!(allowed.allows_origin(EXTENSION_ORIGIN));
    assert!(allowed.allows_origin("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert!(!allowed.allows_origin("https://evil.example"));

    // Wildcard origins must always be rejected.
    assert!(
        BridgeNetworkConfig::from_values(None, None, None, None, Some("*"), None).is_err()
    );
}

#[tokio::test]
async fn custom_allowed_origin_client_tracking_and_reset_token_rotation() {
    use tokio_tungstenite::tungstenite::{
        Message as ClientMessage, client::IntoClientRequest,
    };
    let _guard = BRIDGE_TEST_LOCK.lock().await;
    let dir = tempdir().unwrap();
    let vault = Vault::open(dir.path().to_path_buf()).unwrap();
    let port = {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.local_addr().unwrap().port()
    };
    vault
        .update_settings(crate::model::Settings {
            browser_enabled: true,
            browser_port: port,
            ..crate::model::Settings::default()
        })
        .unwrap();
    let custom_origin = "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let config = BridgeNetworkConfig::from_values(
        Some("127.0.0.1"),
        Some("workstation.local"),
        None,
        None,
        Some(custom_origin),
        Some("ws"),
    )
    .unwrap();
    let bridge = BrowserBridge::with_network_config(vault.clone(), config);
    bridge.start_quick_pairing().await.unwrap();

    let client = reqwest::Client::new();
    let claim = client
        .post(format!("http://127.0.0.1:{port}/claim"))
        .header(header::ORIGIN, custom_origin)
        .send()
        .await
        .unwrap();
    assert_eq!(claim.status(), StatusCode::OK);
    let first_token = claim.json::<serde_json::Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();

    let mut ws_req = format!("ws://127.0.0.1:{port}/extension")
        .into_client_request()
        .unwrap();
    ws_req
        .headers_mut()
        .insert("Origin", custom_origin.parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_req).await.unwrap();
    ws.send(ClientMessage::Text(
        serde_json::json!({
            "type": "auth",
            "token": first_token,
            "extensionVersion": env!("CARGO_PKG_VERSION")
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    let _ = ws.next().await.unwrap().unwrap();
    sleep(Duration::from_millis(25)).await;

    let status = bridge.status().await;
    assert_eq!(status.endpoint, format!("ws://workstation.local:{port}/extension"));
    assert_eq!(status.clients.len(), 1);
    assert_eq!(status.clients[0].peer_ip, "127.0.0.1");
    assert!(status.last_used_at.is_some());
    assert_eq!(status.last_client_ip.as_deref(), Some("127.0.0.1"));

    // Reset pairing rotates extension token and disconnects existing client.
    bridge.reset_pairing().await.unwrap();
    let rotated_token = bridge.extension_token().unwrap();
    assert_ne!(rotated_token, first_token);
    assert!(!vault.settings().unwrap().browser_paired);

    bridge.stop().await;
}
