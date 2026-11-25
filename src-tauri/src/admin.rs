//! Opt-in, loopback-only authenticated management server for headless OpenKeylet deployments.
//!
//! Intended to stay bound to `127.0.0.1` on the server and be accessed over an SSH tunnel:
//! `ssh -L 39273:127.0.0.1:39273 user@server`

use crate::{
    model::{ConnectionInput, NewActivity},
    extract::ingest as smart_ingest,
    storage::uses_explicit_data_dir,
    vault::Vault,
};
use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse},
    routing::{delete, get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Instant,
};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::Mutex};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const DEFAULT_ADMIN_PORT: u16 = 39273;

#[derive(Clone)]
pub struct AdminServerConfig {
    pub bind_ip: IpAddr,
    pub port: u16,
    pub allow_non_loopback: bool,
    pub initial_token: Option<Zeroizing<String>>,
}

impl Default for AdminServerConfig {
    fn default() -> Self {
        Self {
            bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: DEFAULT_ADMIN_PORT,
            allow_non_loopback: false,
            initial_token: None,
        }
    }
}

impl AdminServerConfig {
    pub fn validate(&self) -> Result<()> {
        if self.port == 0 {
            bail!("Admin server port must be between 1 and 65535");
        }
        if !self.bind_ip.is_loopback() && !self.allow_non_loopback {
            bail!(
                "Refusing to bind headless management server on non-loopback address {}. Keep it on 127.0.0.1 and use `ssh -L {}:127.0.0.1:{} user@server`, or pass --allow-non-loopback explicitly on a trusted private interface.",
                self.bind_ip,
                self.port,
                self.port
            );
        }
        if let Some(token) = &self.initial_token
            && token.trim().len() < 24
        {
            bail!("Admin bearer token must be at least 24 characters");
        }
        Ok(())
    }
}

#[derive(Clone)]
struct AdminState {
    vault: Vault,
    active_token: Arc<Mutex<Option<Zeroizing<String>>>>,
    pin_throttle: Arc<Mutex<Instant>>,
}

pub fn generate_session_token() -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(bytes.as_mut())
        .map_err(|error| anyhow::anyhow!("Unable to generate admin session token: {error}"))?;
    Ok(Zeroizing::new(format!(
        "oka1_{}",
        URL_SAFE_NO_PAD.encode(&*bytes)
    )))
}

pub struct RunningAdminServer {
    pub addr: SocketAddr,
    pub token: Zeroizing<String>,
    cancellation: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

impl RunningAdminServer {
    pub async fn shutdown(self) {
        self.cancellation.cancel();
        let _ = self.handle.await;
    }
}

pub async fn start(vault: Vault, config: AdminServerConfig) -> Result<RunningAdminServer> {
    config.validate()?;
    let token = match config.initial_token {
        Some(t) => Zeroizing::new(t.trim().to_owned()),
        None => generate_session_token()?,
    };
    let listener = TcpListener::bind(SocketAddr::new(config.bind_ip, config.port))
        .await
        .with_context(|| {
            format!(
                "Unable to bind OpenKeylet admin server on {}:{}",
                config.bind_ip, config.port
            )
        })?;
    let addr = listener.local_addr()?;
    let state = AdminState {
        vault,
        active_token: Arc::new(Mutex::new(Some(token.clone()))),
        pin_throttle: Arc::new(Mutex::new(Instant::now())),
    };
    let router = build_router(state);
    let cancellation = CancellationToken::new();
    let child_cancel = cancellation.clone();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(child_cancel.cancelled_owned())
            .await;
    });
    Ok(RunningAdminServer {
        addr,
        token,
        cancellation,
        handle,
    })
}

pub async fn serve_until_ctrl_c(vault: Vault, config: AdminServerConfig) -> Result<()> {
    let running = start(vault, config).await?;
    let port = running.addr.port();
    eprintln!("OpenKeylet Headless Management Server listening on http://{}", running.addr);
    eprintln!("SSH tunnel example: ssh -L {port}:127.0.0.1:{port} user@server");
    eprintln!("Session Bearer token (keep secret, never pass in URL): {}", &*running.token);
    eprintln!("Press Ctrl+C to stop and revoke the session token.");
    tokio::signal::ctrl_c()
        .await
        .context("Failed waiting for Ctrl+C")?;
    eprintln!("Shutting down OpenKeylet Headless Management Server...");
    running.shutdown().await;
    Ok(())
}

fn build_router(state: AdminState) -> Router {
    Router::new()
        .route("/", get(index_page))
        .route("/api/status", get(api_status))
        .route("/api/items", get(api_list_items).post(api_save_item))
        .route("/api/items/smart-add", post(api_smart_add))
        .route("/api/items/{id}/enabled", post(api_set_enabled))
        .route("/api/items/{id}/reveal", post(api_reveal_item))
        .route("/api/items/{id}/trash", post(api_trash_item))
        .route("/api/trash/{id}/restore", post(api_restore_item))
        .route("/api/trash/{id}/purge", post(api_purge_item))
        .route("/api/activities", get(api_activities).delete(api_clear_activities))
        .route("/api/activities/{id}", delete(api_delete_activity))
        .route("/api/session/rotate", post(api_rotate_token))
        .route("/api/session/revoke", post(api_revoke_token))
        .with_state(state)
}

async fn require_auth(
    state: &AdminState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<Value>)> {
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let guard = state.active_token.lock().await;
    let Some(expected) = guard.as_ref() else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Session has been revoked; restart the admin server to issue a new token" })),
        ));
    };
    let ok = supplied.len() == expected.len()
        && bool::from(supplied.as_bytes().ct_eq(expected.as_bytes()));
    if ok {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid or missing Bearer token" })),
        ))
    }
}

fn api_error(status: StatusCode, error: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "error": error.to_string() })))
}

async fn index_page() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    (headers, Html(ADMIN_HTML))
}

async fn api_status(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_auth(&state, &headers).await?;
    let items = state
        .vault
        .list_connections()
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let trash = state
        .vault
        .trash_items()
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let settings = state
        .vault
        .settings()
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let pin_configured = state
        .vault
        .owner_pin_configured()
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let enabled_count = items.iter().filter(|i| i.enabled).count();
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "dataDir": state.vault.data_dir().to_string_lossy(),
        "explicitDataDir": uses_explicit_data_dir(state.vault.data_dir()),
        "keySource": state.vault.storage_label(),
        "ownerPinConfigured": pin_configured,
        "itemCount": items.len(),
        "enabledItemCount": enabled_count,
        "trashCount": trash.len(),
        "browserEnabled": settings.browser_enabled,
        "browserPaired": settings.browser_paired,
        "browserPort": settings.browser_port,
    })))
}

async fn api_list_items(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_auth(&state, &headers).await?;
    let items = state
        .vault
        .list_connections()
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let trash = state
        .vault
        .trash_items()
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "items": items, "trash": trash })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveItemRequest {
    input: ConnectionInput,
    #[serde(default)]
    expected_updated_at: Option<String>,
}

async fn api_save_item(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(req): Json<SaveItemRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_auth(&state, &headers).await?;
    if !req.input.private_key_import_path.is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Private key file paths cannot be imported through the remote admin API; paste key text directly instead",
        ));
    }
    let saved = state
        .vault
        .save_connection_checked(req.input, req.expected_updated_at.as_deref())
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, e))?;
    let _ = state.vault.add_activity(NewActivity {
        status: "success".to_owned(),
        source: "HEADLESS ADMIN".to_owned(),
        connection_name: saved.name.clone(),
        action: "Save item".to_owned(),
        duration_ms: 0,
        error: String::new(),
    });
    Ok(Json(json!({ "item": saved })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SmartAddRequest {
    raw: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    folder: Option<String>,
}

async fn api_smart_add(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(req): Json<SmartAddRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_auth(&state, &headers).await?;
    let raw = Zeroizing::new(req.raw);
    let parsed = smart_ingest::smart_parse(&raw, None, None)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, e))?;
    let mut input = parsed.input;
    if let Some(name) = req.name.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()) {
        input.name = name;
    }
    if let Some(folder) = req.folder.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()) {
        input.folder = folder;
    }
    let saved = state
        .vault
        .save_connection(input)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, e))?;
    let _ = state.vault.add_activity(NewActivity {
        status: "success".to_owned(),
        source: "HEADLESS ADMIN".to_owned(),
        connection_name: saved.name.clone(),
        action: format!("Smart add ({})", parsed.label),
        duration_ms: 0,
        error: String::new(),
    });
    Ok(Json(json!({ "item": saved, "detected": parsed.label })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ToggleEnabledRequest {
    enabled: bool,
}

async fn api_set_enabled(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<ToggleEnabledRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_auth(&state, &headers).await?;
    state
        .vault
        .set_connection_enabled(id, req.enabled)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({ "ok": true, "id": id, "enabled": req.enabled })))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RevealRequest {
    #[serde(default)]
    pin: String,
}

async fn api_reveal_item(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<RevealRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_auth(&state, &headers).await?;
    let pin = Zeroizing::new(req.pin);
    if state
        .vault
        .owner_pin_configured()
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?
    {
        if pin.trim().is_empty() {
            return Err(api_error(
                StatusCode::FORBIDDEN,
                "Owner PIN is required to reveal secret values",
            ));
        }
        let valid = crate::platform::verify_pin_throttled(
            &state.vault,
            pin.trim(),
            &state.pin_throttle,
        )
        .await
        .map_err(|e| api_error(StatusCode::FORBIDDEN, e))?;
        if !valid {
            return Err(api_error(StatusCode::FORBIDDEN, "Incorrect Owner PIN"));
        }
    }
    let view = state
        .vault
        .owner_secret_view(id)
        .map_err(|e| api_error(StatusCode::NOT_FOUND, e))?;
    let item_name = state
        .vault
        .get_connection(id)
        .map(|c| c.stored.name)
        .unwrap_or_else(|_| id.to_string());
    let _ = state.vault.add_activity(NewActivity {
        status: "success".to_owned(),
        source: "HEADLESS ADMIN".to_owned(),
        connection_name: item_name,
        action: "Explicit secret reveal".to_owned(),
        duration_ms: 0,
        error: String::new(),
    });
    Ok(Json(json!({ "id": view.id, "fields": view.fields })))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct TrashRequest {
    #[serde(default)]
    expected_updated_at: Option<String>,
}

async fn api_trash_item(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<TrashRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_auth(&state, &headers).await?;
    state
        .vault
        .trash_connection(id, req.expected_updated_at.as_deref())
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrashTimestampRequest {
    deleted_at: String,
}

async fn api_restore_item(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<TrashTimestampRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_auth(&state, &headers).await?;
    state
        .vault
        .restore_connection(id, &req.deleted_at)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({ "ok": true })))
}

async fn api_purge_item(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<TrashTimestampRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_auth(&state, &headers).await?;
    state
        .vault
        .purge_connection(id, &req.deleted_at)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({ "ok": true })))
}

async fn api_activities(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_auth(&state, &headers).await?;
    let activities = state
        .vault
        .activities()
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "activities": activities.into_iter().take(100).collect::<Vec<_>>() })))
}

async fn api_delete_activity(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_auth(&state, &headers).await?;
    let deleted = state
        .vault
        .delete_activity(id)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "ok": true, "deleted": deleted })))
}

async fn api_clear_activities(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_auth(&state, &headers).await?;
    state
        .vault
        .clear_activities()
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "ok": true })))
}

async fn api_rotate_token(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_auth(&state, &headers).await?;
    let next = generate_session_token()
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    *state.active_token.lock().await = Some(next.clone());
    Ok(Json(json!({ "token": &*next })))
}

async fn api_revoke_token(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_auth(&state, &headers).await?;
    *state.active_token.lock().await = None;
    Ok(Json(json!({ "ok": true, "revoked": true })))
}

const ADMIN_HTML: &str = include_str!("admin/index.html");

#[cfg(test)]
mod tests;
