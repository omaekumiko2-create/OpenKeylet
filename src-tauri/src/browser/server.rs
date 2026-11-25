use super::*;

pub(super) fn require_allowed_peer(
    config: &BridgeNetworkConfig,
    peer: IpAddr,
    route: &str,
) -> Result<(), (StatusCode, String)> {
    if config.allows_peer(peer) {
        Ok(())
    } else {
        log_bridge_event(
            "peer_rejected",
            Some(peer),
            &format!("route={route} reason=ip_not_in_allowlist"),
        );
        Err((
            StatusCode::FORBIDDEN,
            "Client IP is not permitted by Browser Bridge allowlist".to_owned(),
        ))
    }
}

pub(super) fn require_internal_peer(
    config: &BridgeNetworkConfig,
    peer: IpAddr,
    route: &str,
) -> Result<(), (StatusCode, String)> {
    if config.allows_internal_peer(peer) {
        Ok(())
    } else {
        log_bridge_event(
            "internal_peer_rejected",
            Some(peer),
            &format!("route={route} reason=non_local_peer"),
        );
        Err((
            StatusCode::FORBIDDEN,
            "Internal Browser Bridge endpoints only accept local requests".to_owned(),
        ))
    }
}

pub(super) async fn health(
    State(state): State<BridgeServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<&'static str, (StatusCode, String)> {
    require_allowed_peer(&state.config, peer.ip(), "/health")?;
    Ok("OpenKeylet Browser Bridge")
}

pub(super) async fn internal_health(
    State(state): State<BridgeServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<&'static str, (StatusCode, String)> {
    require_internal_peer(&state.config, peer.ip(), "/internal/health")?;
    require_bearer(&headers, &state.internal_token)?;
    Ok("ok")
}

pub(super) async fn internal_ready(
    State(state): State<BridgeServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<&'static str, (StatusCode, String)> {
    require_internal_peer(&state.config, peer.ip(), "/internal/ready")?;
    require_bearer(&headers, &state.internal_token)?;
    if state.extensions.lock().await.active().is_some() {
        Ok("ready")
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Browser extension is not connected".to_owned(),
        ))
    }
}

pub(super) async fn internal_status(
    State(state): State<BridgeServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<InternalBridgeStatus>, (StatusCode, String)> {
    require_internal_peer(&state.config, peer.ip(), "/internal/status")?;
    require_bearer(&headers, &state.internal_token)?;
    let (connected_count, extension_version, extension_outdated, clients, last_client_ip, last_used_at) = {
        let pool = state.extensions.lock().await;
        let (ver, outdated) = pool.version_summary();
        (
            pool.clients.len(),
            ver,
            outdated,
            pool.client_infos(),
            pool.last_client_ip.clone(),
            pool.last_used_at.clone(),
        )
    };
    let pairing_active = {
        let mut pairing = state.pairing.lock().await;
        match pairing.as_ref() {
            Some(window) if std::time::Instant::now() <= window.expires_at => true,
            Some(_) => {
                *pairing = None;
                false
            }
            None => false,
        }
    };
    Ok(Json(InternalBridgeStatus {
        connected_count,
        pairing_active,
        extension_version,
        extension_outdated,
        clients,
        last_client_ip,
        last_used_at,
    }))
}

pub(super) async fn reload_extensions_route(
    State(state): State<BridgeServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_internal_peer(&state.config, peer.ip(), "/internal/reload-extensions")?;
    require_bearer(&headers, &state.internal_token)?;
    let senders = state.extensions.lock().await.control_senders();
    let payload = serde_json::json!({
        "type": "reload",
        "appVersion": env!("CARGO_PKG_VERSION"),
    })
    .to_string();
    let mut reloaded = 0usize;
    for tx in senders {
        if tx.try_send(payload.clone()).is_ok() {
            reloaded += 1;
        }
    }
    Ok(Json(serde_json::json!({ "reloaded": reloaded })))
}

pub(super) async fn sync_appearance_route(
    State(state): State<BridgeServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(patch): Json<AppearancePatch>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_internal_peer(&state.config, peer.ip(), "/internal/appearance")?;
    require_bearer(&headers, &state.internal_token)?;
    let snapshot = {
        let mut guard = state.appearance.lock().await;
        if let Some(theme) = patch.theme {
            guard.theme = normalize_bridge_theme(&theme);
        }
        if let Some(language) = patch.language {
            guard.language = normalize_bridge_language(&language);
        }
        guard.clone()
    };
    let senders = state.extensions.lock().await.control_senders();
    let payload = serde_json::json!({
        "type": "appearance",
        "theme": snapshot.theme,
        "language": snapshot.language,
    })
    .to_string();
    let mut notified = 0usize;
    for tx in senders {
        if tx.try_send(payload.clone()).is_ok() {
            notified += 1;
        }
    }
    Ok(Json(serde_json::json!({ "notified": notified })))
}

pub(super) async fn create_quick_pair(
    State(state): State<BridgeServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<&'static str, (StatusCode, String)> {
    require_internal_peer(&state.config, peer.ip(), "/internal/quick-pair")?;
    require_bearer(&headers, &state.internal_token)?;
    let expires_at = std::time::Instant::now() + PAIRING_WINDOW;
    *state.pairing.lock().await = Some(PairingWindow { expires_at });
    state.notify_change();
    let state_for_expiry = state.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = state_for_expiry.cancellation.cancelled() => {}
            _ = sleep(PAIRING_WINDOW + Duration::from_millis(100)) => {
                let expired = {
                    let mut pairing = state_for_expiry.pairing.lock().await;
                    if pairing.as_ref().is_some_and(|w| std::time::Instant::now() > w.expires_at) {
                        *pairing = None;
                        true
                    } else {
                        false
                    }
                };
                if expired {
                    state_for_expiry.notify_change();
                }
            }
        }
    });
    Ok("ready")
}

pub(super) async fn claim(
    State(state): State<BridgeServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<PairResponse>, (StatusCode, String)> {
    require_allowed_peer(&state.config, peer.ip(), "/claim")?;
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !state.config.allows_origin(origin) {
        log_bridge_event(
            "claim_rejected",
            Some(peer.ip()),
            "reason=origin_not_allowed",
        );
        return Err((
            StatusCode::FORBIDDEN,
            "Only the Chromium extension can claim pairing".to_owned(),
        ));
    }
    let mut pairing = state.pairing.lock().await;
    let current = pairing
        .as_ref()
        .ok_or((StatusCode::UNAUTHORIZED, "No pending pairing".to_owned()))?;
    if std::time::Instant::now() > current.expires_at {
        *pairing = None;
        return Err((
            StatusCode::UNAUTHORIZED,
            "Automatic pairing window is closed".to_owned(),
        ));
    }
    drop(pairing);
    state
        .vault
        .set_browser_paired(true)
        .map_err(internal_error)?;
    state
        .extensions
        .lock()
        .await
        .record_claim(normalize_ip(peer.ip()).to_string());
    log_bridge_event("pairing_claimed", Some(peer.ip()), "status=ok");
    state.notify_change();
    Ok(Json(PairResponse {
        token: state.extension_token.clone(),
        port: state.port,
    }))
}

pub(super) async fn submit_job(
    State(state): State<BridgeServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(mut job): Json<BrowserJob>,
) -> Result<Json<BrowserFillResult>, (StatusCode, String)> {
    require_internal_peer(&state.config, peer.ip(), "/internal/jobs")?;
    require_bearer(&headers, &state.internal_token)?;
    job.normalize_deadline();
    let (sender, receiver) = oneshot::channel();
    state.pending.lock().await.insert(job.id, sender);
    let delivered = deliver_to_extension_with_grace(&state, &job).await;
    if !delivered {
        state.pending.lock().await.remove(&job.id);
        if job.is_expired() {
            return Err((
                StatusCode::GATEWAY_TIMEOUT,
                "Browser fill timed out".to_owned(),
            ));
        }
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Browser extension is not connected".to_owned(),
        ));
    }
    match timeout(job.remaining(), receiver).await {
        Ok(Ok(result)) => {
            if result.status == "ok" {
                Ok(Json(result))
            } else {
                Err((StatusCode::BAD_REQUEST, result.message))
            }
        }
        _ => {
            state.pending.lock().await.remove(&job.id);
            Err((
                StatusCode::GATEWAY_TIMEOUT,
                "Browser fill timed out".to_owned(),
            ))
        }
    }
}

pub(super) async fn deliver_to_extension_with_grace(state: &BridgeServerState, job: &BrowserJob) -> bool {
    let grace = EXTENSION_RECONNECT_GRACE.min(job.remaining());
    let deadline = tokio::time::Instant::now() + grace;
    loop {
        if deliver_to_extension(state, job).await {
            return true;
        }
        if job.is_expired() || tokio::time::Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(50)).await;
    }
}

pub(super) async fn deliver_to_extension(state: &BridgeServerState, job: &BrowserJob) -> bool {
    let candidates = state.extensions.lock().await.clients.len();
    for _ in 0..candidates {
        if !job_is_deliverable(state, job).await {
            return false;
        }
        let Some(active) = state.extensions.lock().await.active() else {
            break;
        };
        let send_timeout = EXTENSION_QUEUE_TIMEOUT.min(job.remaining());
        match timeout(send_timeout, active.jobs.send(job.clone())).await {
            Ok(Ok(())) => {
                state.extensions.lock().await.touch(active.id);
                return true;
            }
            Ok(Err(_)) | Err(_) => state.extensions.lock().await.remove(active.id),
        }
    }
    false
}

pub(super) async fn job_is_deliverable(state: &BridgeServerState, job: &BrowserJob) -> bool {
    !job.is_expired() && state.pending.lock().await.contains_key(&job.id)
}

pub(super) async fn reset_pairing(
    State(state): State<BridgeServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<&'static str, (StatusCode, String)> {
    require_internal_peer(&state.config, peer.ip(), "/internal/reset")?;
    require_bearer(&headers, &state.internal_token)?;
    state
        .vault
        .rotate_browser_bridge_secret()
        .map_err(internal_error)?;
    log_bridge_event(
        "pairing_reset",
        Some(peer.ip()),
        "action=token_rotated_and_clients_disconnected",
    );
    let cancellation = state.cancellation.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(80)).await;
        cancellation.cancel();
    });
    Ok("reset")
}

pub(super) async fn extension_upgrade(
    ws: WebSocketUpgrade,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<BridgeServerState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    require_allowed_peer(&state.config, peer.ip(), "/extension")?;
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !state.config.allows_origin(origin) {
        log_bridge_event(
            "ws_rejected",
            Some(peer.ip()),
            "reason=origin_not_allowed",
        );
        return Err((
            StatusCode::FORBIDDEN,
            "Only the OpenKeylet Chromium extension can connect to Browser Bridge".to_owned(),
        ));
    }
    let peer_ip = normalize_ip(peer.ip());
    Ok(ws.on_upgrade(move |socket| extension_socket(socket, state, peer_ip)))
}

pub(super) fn constant_time_eq(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && subtle::ConstantTimeEq::ct_eq(left.as_bytes(), right.as_bytes()).into()
}

pub(super) async fn extension_socket(socket: WebSocket, state: BridgeServerState, peer_ip: IpAddr) {
    let mut browser_session = crate::browser::vault_rpc::Session::default();
    let (mut sender, mut receiver) = socket.split();
    let authenticated = timeout(Duration::from_secs(5), receiver.next()).await;
    let Ok(Some(Ok(Message::Text(message)))) = authenticated else {
        let _ = sender.send(Message::Close(None)).await;
        return;
    };
    let Ok(message) = serde_json::from_str::<ExtensionMessage>(&message) else {
        let _ = sender.send(Message::Close(None)).await;
        return;
    };
    if message.kind != "auth" || !constant_time_eq(&message.token, &state.extension_token) {
        log_bridge_event("ws_auth_failed", Some(peer_ip), "reason=invalid_token");
        let _ = sender
            .send(Message::Text(
                serde_json::json!({"type":"auth-error"}).to_string().into(),
            ))
            .await;
        let _ = sender.send(Message::Close(None)).await;
        return;
    }
    let extension_version = message
        .extension_version
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 32)
        .map(str::to_owned);
    let appearance = state.appearance.lock().await.clone();
    let _ = sender
        .send(Message::Text(
            serde_json::json!({
                "type": "ready",
                "appVersion": env!("CARGO_PKG_VERSION"),
                "theme": appearance.theme,
                "language": appearance.language,
            })
            .to_string()
            .into(),
        ))
        .await;
    let connection_id = Uuid::new_v4();
    let (job_sender, mut jobs) = mpsc::channel(8);
    let (control_sender, mut control_rx) = mpsc::channel::<String>(4);
    state.extensions.lock().await.add(
        connection_id,
        job_sender,
        control_sender,
        extension_version.clone(),
        peer_ip.to_string(),
    );
    if state.config.is_lan_mode() {
        log_bridge_event(
            "ws_connected",
            Some(peer_ip),
            &format!(
                "extension_version={}",
                extension_version.as_deref().unwrap_or("unknown")
            ),
        );
    }
    state.notify_change();
    loop {
        tokio::select! {
            _ = state.cancellation.cancelled() => {
                let _ = sender.send(Message::Close(None)).await;
                break;
            }
            ctrl = control_rx.recv() => {
                let Some(text) = ctrl else { break; };
                if sender.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            job = jobs.recv() => {
                let Some(job) = job else { break; };
                if !job_is_deliverable(&state, &job).await { continue; }
                let Ok(json) = serde_json::to_string(&serde_json::json!({"type":"job", "job":job})) else { continue; };
                match timeout(job.remaining(), sender.send(Message::Text(json.into()))).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) | Err(_) => break,
                }
            }
            message = receiver.next() => {
                match message {
                    Some(Ok(Message::Text(message))) => {
                        if message.len() > 262_144 { continue; }
                        let Ok(message) = serde_json::from_str::<ExtensionMessage>(&message) else { continue; };
                        if message.kind == "rpc" {
                            let Some(request_id) = message.request_id else { continue; };
                            state.extensions.lock().await.touch(connection_id);
                            let result = crate::browser::vault_rpc::handle(&state.vault, &mut browser_session, &state.pin_throttle, &message.method, &message.params).await;
                            let response = match result {
                                Ok(value) => serde_json::json!({"type":"rpc-result","requestId":request_id,"ok":true,"result":value}),
                                Err(error) => serde_json::json!({"type":"rpc-result","requestId":request_id,"ok":false,"error":error.to_string()}),
                            };
                            if sender.send(Message::Text(response.to_string().into())).await.is_err() { break; }
                            continue;
                        }
                        if message.kind == "ping" {
                            let pong = serde_json::json!({"type":"pong"}).to_string();
                            if sender.send(Message::Text(pong.into())).await.is_err() { break; }
                            continue;
                        }
                        if message.kind == "activate" {
                            state.extensions.lock().await.activate(connection_id);
                            continue;
                        }
                        if message.kind != "complete" { continue; }
                        state.extensions.lock().await.touch(connection_id);
                        let Some(job_id) = message.job_id else { continue; };
                        if let Some(pending) = state.pending.lock().await.remove(&job_id) {
                            let _ = pending.send(BrowserFillResult {
                                status: if message.ok { "ok" } else { "error" }.to_owned(),
                                message: message.message,
                                data: message.data,
                            });
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if sender.send(Message::Pong(payload)).await.is_err() { break; }
                    }
                    Some(Ok(Message::Pong(_))) | Some(Ok(Message::Binary(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                }
            }
        }
    }
    state.extensions.lock().await.remove(connection_id);
    if state.config.is_lan_mode() {
        log_bridge_event("ws_disconnected", Some(peer_ip), "status=closed");
    }
    state.notify_change();
}

pub(super) fn require_bearer(headers: &HeaderMap, expected: &str) -> Result<(), (StatusCode, String)> {
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    if supplied.len() == expected.len()
        && subtle::ConstantTimeEq::ct_eq(supplied.as_bytes(), expected.as_bytes()).into()
    {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "Unauthorized".to_owned()))
    }
}

pub(super) fn internal_error(error: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

pub(super) fn derive_token(secret: &str, role: &str) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"mcp-vault/browser/v1/");
    hasher.update(role.as_bytes());
    hasher.update(secret.as_bytes());
    Ok(STANDARD_NO_PAD.encode(hasher.finalize()))
}

pub(super) fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

