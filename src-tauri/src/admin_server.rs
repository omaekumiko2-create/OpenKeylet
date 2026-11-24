//! Opt-in, loopback-only authenticated management server for headless OpenKeylet deployments.
//!
//! Intended to stay bound to `127.0.0.1` on the server and be accessed over an SSH tunnel:
//! `ssh -L 39273:127.0.0.1:39273 user@server`

use crate::{
    model::{ConnectionInput, NewActivity},
    smart_ingest,
    storage::uses_explicit_data_dir,
    vault::Vault,
};
use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
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
        .route("/api/activities", get(api_activities))
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
        "strongMode": state.vault.is_strong_mode(),
        "strongUnlocked": state.vault.is_strong_unlocked(),
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
        let mut next = state.pin_throttle.lock().await;
        tokio::time::sleep(next.saturating_duration_since(Instant::now())).await;
        *next = Instant::now() + Duration::from_secs(1);
        drop(next);
        let valid = state
            .vault
            .verify_owner_pin(pin.trim())
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

const ADMIN_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenKeylet · Headless Admin</title>
<style>
  :root { color-scheme: dark; --bg:#0d0d0f; --panel:#16161a; --line:#292930; --fg:#f2f2f4; --muted:#9a9aa6; --ok:#3ad29f; --danger:#f26b6b; }
  * { box-sizing: border-box; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; }
  body { margin:0; background:var(--bg); color:var(--fg); padding:24px; max-width:960px; margin-inline:auto; }
  header { display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--line); padding-bottom:14px; margin-bottom:20px; }
  h1 { font-size:18px; margin:0; letter-spacing:0.04em; }
  .badge { font-size:12px; color:var(--muted); border:1px solid var(--line); padding:3px 8px; border-radius:4px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:16px; margin-bottom:16px; }
  .row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
  input, textarea, button { background:#101014; color:var(--fg); border:1px solid var(--line); border-radius:4px; padding:8px 10px; font-size:13px; }
  input, textarea { width:100%; }
  button { cursor:pointer; width:auto; font-weight:500; }
  button:hover { border-color:#5a5a68; }
  button.primary { background:#f2f2f4; color:#0d0d0f; border-color:#f2f2f4; }
  button.danger { border-color:var(--danger); color:var(--danger); }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:10px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--muted); font-weight:500; }
  .dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; background:#555; }
  .dot.on { background:var(--ok); }
  .muted { color:var(--muted); font-size:12px; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; }
  pre { background:#0a0a0c; border:1px solid var(--line); padding:10px; border-radius:4px; overflow:auto; font-size:12px; }
  [hidden] { display:none !important; }
</style>
</head>
<body>
<header>
  <h1>OPENKEYLET · HEADLESS VAULT ADMIN</h1>
  <span class="badge" id="hdr-status">LOCKED</span>
</header>

<section class="card" id="auth-card">
  <strong>Authenticate Session</strong>
  <p class="muted">Paste the Bearer token printed by <code>openkeylet admin serve</code>. The token stays in page memory only and is cleared on reload.</p>
  <form id="auth-form" class="row">
    <input id="token-input" type="password" placeholder="oka1_..." autocomplete="off" required style="flex:1">
    <button type="submit" class="primary">Connect</button>
  </form>
  <p id="auth-err" class="muted" style="color:var(--danger)"></p>
</section>

<div id="app" hidden>
  <section class="card">
    <div class="row" style="justify-content:space-between">
      <div>
        <strong>Vault Diagnostics</strong>
        <div id="diag" class="muted mono" style="margin-top:6px"></div>
      </div>
      <div class="row">
        <button id="btn-refresh">Refresh</button>
        <button id="btn-rotate">Rotate Token</button>
        <button id="btn-revoke" class="danger">Revoke Session</button>
      </div>
    </div>
  </section>

  <section class="card">
    <div class="row" style="justify-content:space-between; margin-bottom:10px">
      <strong>Vault Items (Secrets Hidden by Default)</strong>
      <input id="search" type="search" placeholder="Filter by name / type..." style="max-width:260px">
    </div>
    <table>
      <thead><tr><th>Name</th><th>Type</th><th>Agent Access</th><th>Actions</th></tr></thead>
      <tbody id="items-body"></tbody>
    </table>
    <div id="reveal-box" hidden style="margin-top:14px">
      <div class="row" style="justify-content:space-between">
        <strong id="reveal-title">Revealed Secret</strong>
        <button id="reveal-close">Hide</button>
      </div>
      <pre id="reveal-pre" class="mono"></pre>
    </div>
  </section>

  <section class="card">
    <strong>Quick Add Item (Smart Ingest)</strong>
    <p class="muted">Paste an API key, <code>.env</code> snippet, SSH key, or credential text. Secret modules default to hidden from AI agents.</p>
    <form id="smart-form">
      <div class="row" style="margin-bottom:8px">
        <input id="smart-name" placeholder="Optional item name" style="flex:1">
        <input id="smart-folder" placeholder="Optional folder" style="max-width:200px">
      </div>
      <textarea id="smart-raw" rows="3" placeholder="sk-... / KEY=VALUE / -----BEGIN OPENSSH PRIVATE KEY-----" required></textarea>
      <div class="row" style="margin-top:8px">
        <button type="submit" class="primary">Encrypt &amp; Save</button>
        <span id="smart-msg" class="muted"></span>
      </div>
    </form>
  </section>

  <section class="card" id="trash-card" hidden>
    <strong>Trash</strong>
    <table>
      <thead><tr><th>Name</th><th>Deleted At</th><th>Actions</th></tr></thead>
      <tbody id="trash-body"></tbody>
    </table>
  </section>
</div>

<script>
let token = "";
let allItems = [];
let pinConfigured = false;
const $ = s => document.querySelector(s);

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: {
      "Authorization": "Bearer " + token,
      ...(opts.body ? { "Content-Type": "application/json" } : {}),
      ...(opts.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
  return data;
}

async function refresh() {
  const [st, list] = await Promise.all([api("/api/status"), api("/api/items")]);
  pinConfigured = Boolean(st.ownerPinConfigured);
  $("#hdr-status").textContent = "CONNECTED · v" + st.version;
  $("#diag").textContent =
    `dir=${st.dataDir} | keySource=${st.keySource} | items=${st.itemCount} (${st.enabledItemCount} enabled) | trash=${st.trashCount} | pin=${pinConfigured ? "on" : "off"}`;
  allItems = list.items || [];
  renderItems();
  renderTrash(list.trash || []);
}

function renderItems() {
  const q = ($("#search").value || "").trim().toLowerCase();
  const body = $("#items-body");
  body.replaceChildren();
  for (const item of allItems) {
    if (q && !item.name.toLowerCase().includes(q) && !(item.itemType || "").toLowerCase().includes(q)) continue;
    const tr = document.createElement("tr");
    const tdName = document.createElement("td");
    tdName.innerHTML = "";
    const strong = document.createElement("strong");
    strong.textContent = item.name;
    tdName.appendChild(strong);
    if (item.folder) {
      const sub = document.createElement("div");
      sub.className = "muted";
      sub.textContent = item.folder;
      tdName.appendChild(sub);
    }
    const tdType = document.createElement("td");
    tdType.textContent = item.itemType || "custom";
    const tdEn = document.createElement("td");
    const dot = document.createElement("span");
    dot.className = "dot" + (item.enabled ? " on" : "");
    tdEn.append(dot, document.createTextNode(item.enabled ? "Enabled" : "Disabled"));
    const tdAct = document.createElement("td");
    const row = document.createElement("div");
    row.className = "row";
    const toggleBtn = document.createElement("button");
    toggleBtn.textContent = item.enabled ? "Disable" : "Enable";
    toggleBtn.onclick = async () => {
      await api(`/api/items/${item.id}/enabled`, { method: "POST", body: JSON.stringify({ enabled: !item.enabled }) });
      await refresh();
    };
    const revBtn = document.createElement("button");
    revBtn.textContent = "Reveal";
    revBtn.onclick = async () => {
      const pin = pinConfigured ? (prompt("Enter 6-digit Owner PIN to reveal secrets:") || "") : "";
      try {
        const res = await api(`/api/items/${item.id}/reveal`, { method: "POST", body: JSON.stringify({ pin }) });
        $("#reveal-title").textContent = "Revealed: " + item.name;
        $("#reveal-pre").textContent = JSON.stringify(res.fields, null, 2);
        $("#reveal-box").hidden = false;
      } catch (e) { alert(e.message); }
    };
    const trashBtn = document.createElement("button");
    trashBtn.className = "danger";
    trashBtn.textContent = "Trash";
    trashBtn.onclick = async () => {
      if (!confirm(`Move "${item.name}" to trash?`)) return;
      await api(`/api/items/${item.id}/trash`, { method: "POST", body: JSON.stringify({ expectedUpdatedAt: item.updatedAt }) });
      await refresh();
    };
    row.append(toggleBtn, revBtn, trashBtn);
    tdAct.appendChild(row);
    tr.append(tdName, tdType, tdEn, tdAct);
    body.appendChild(tr);
  }
}

function renderTrash(trash) {
  $("#trash-card").hidden = trash.length === 0;
  const body = $("#trash-body");
  body.replaceChildren();
  for (const entry of trash) {
    const item = entry.item || entry;
    const tr = document.createElement("tr");
    const tdName = document.createElement("td");
    tdName.textContent = item.name;
    const tdAt = document.createElement("td");
    tdAt.className = "mono muted";
    tdAt.textContent = entry.deletedAt;
    const tdAct = document.createElement("td");
    const restoreBtn = document.createElement("button");
    restoreBtn.textContent = "Restore";
    restoreBtn.onclick = async () => {
      await api(`/api/trash/${item.id}/restore`, { method: "POST", body: JSON.stringify({ deletedAt: entry.deletedAt }) });
      await refresh();
    };
    tdAct.appendChild(restoreBtn);
    tr.append(tdName, tdAt, tdAct);
    body.appendChild(tr);
  }
}

$("#auth-form").addEventListener("submit", async e => {
  e.preventDefault();
  $("#auth-err").textContent = "";
  token = $("#token-input").value.trim();
  try {
    await refresh();
    $("#token-input").value = "";
    $("#auth-card").hidden = true;
    $("#app").hidden = false;
  } catch (err) {
    token = "";
    $("#auth-err").textContent = err.message;
  }
});

$("#search").addEventListener("input", renderItems);
$("#btn-refresh").addEventListener("click", () => refresh().catch(e => alert(e.message)));
$("#reveal-close").addEventListener("click", () => { $("#reveal-pre").textContent = ""; $("#reveal-box").hidden = true; });
$("#smart-form").addEventListener("submit", async e => {
  e.preventDefault();
  $("#smart-msg").textContent = "Saving...";
  try {
    const res = await api("/api/items/smart-add", {
      method: "POST",
      body: JSON.stringify({
        raw: $("#smart-raw").value,
        name: $("#smart-name").value || null,
        folder: $("#smart-folder").value || null,
      }),
    });
    $("#smart-raw").value = "";
    $("#smart-name").value = "";
    $("#smart-msg").textContent = `Saved "${res.item.name}" (${res.detected})`;
    await refresh();
  } catch (err) {
    $("#smart-msg").textContent = err.message;
  }
});
$("#btn-rotate").addEventListener("click", async () => {
  try {
    const res = await api("/api/session/rotate", { method: "POST" });
    token = res.token;
    alert("Session token rotated. New token:\n\n" + res.token);
  } catch (err) { alert(err.message); }
});
$("#btn-revoke").addEventListener("click", async () => {
  if (!confirm("Revoke current session token? You will need to restart `openkeylet admin serve`.")) return;
  try {
    await api("/api/session/revoke", { method: "POST" });
    token = "";
    $("#app").hidden = true;
    $("#auth-card").hidden = false;
    $("#hdr-status").textContent = "REVOKED";
  } catch (err) { alert(err.message); }
});
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
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
}
