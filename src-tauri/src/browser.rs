use crate::{model::BrowserBridgeState, vault::Vault};
use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, Method, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, mpsc, oneshot},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

const JOB_TIMEOUT: Duration = Duration::from_secs(35);
const EXTENSION_QUEUE_TIMEOUT: Duration = Duration::from_millis(500);
const EXTENSION_RECONNECT_GRACE: Duration = Duration::from_secs(2);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(40);
const HEALTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const EXTENSION_ORIGIN: &str = "chrome-extension://knkjojeijgalhpdkfapohofobfomenmi";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialReference {
    item_id: Uuid,
    module: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialFillRequest {
    id: Uuid,
    credential_ref: CredentialReference,
    #[serde(default)]
    expires_at: u64,
}
impl CredentialFillRequest {
    fn normalize_deadline(&mut self) {
        let now = unix_millis();
        let latest = now.saturating_add(JOB_TIMEOUT.as_millis() as u64);
        if self.expires_at == 0 || self.expires_at > latest {
            self.expires_at = latest;
        }
    }
    fn remaining(&self) -> Duration {
        Duration::from_millis(self.expires_at.saturating_sub(unix_millis()))
    }
    fn is_expired(&self) -> bool {
        self.remaining().is_zero()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrowserJob {
    id: Uuid,
    credential_ref: CredentialReference,
    application_id: Uuid,
    connection_id: Uuid,
    browser_instance_id: Uuid,
    expires_at: u64,
}
impl BrowserJob {
    fn from_request(
        mut request: CredentialFillRequest,
        application_id: Uuid,
        connection_id: Uuid,
        browser_instance_id: Uuid,
    ) -> Self {
        request.normalize_deadline();
        Self {
            id: request.id,
            credential_ref: request.credential_ref,
            application_id,
            connection_id,
            browser_instance_id,
            expires_at: request.expires_at,
        }
    }
    fn remaining(&self) -> Duration {
        Duration::from_millis(self.expires_at.saturating_sub(unix_millis()))
    }
    fn is_expired(&self) -> bool {
        self.remaining().is_zero()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFillResult {
    pub ok: bool,
    pub operation_id: Uuid,
    pub application_id: Uuid,
    pub connection_id: Uuid,
    pub browser_instance_id: Uuid,
    pub origin: String,
    pub tab_id: i64,
    pub window_id: i64,
    pub frame_id: i64,
    pub document_id: String,
    pub top_document_id: String,
    pub field_role: String,
    pub delivered: bool,
    pub readback: bool,
    pub submitted: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairResponse {
    token: String,
    port: u16,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ExtensionMessage {
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    method: String,
    #[serde(default)]
    params: serde_json::Value,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    extension_id: String,
    #[serde(default)]
    browser_instance_id: Option<Uuid>,
    #[serde(default)]
    operation_id: Option<Uuid>,
    #[serde(default)]
    application_id: Option<Uuid>,
    #[serde(default)]
    connection_id: Option<Uuid>,
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    origin: String,
    #[serde(default)]
    tab_id: Option<i64>,
    #[serde(default)]
    window_id: Option<i64>,
    #[serde(default)]
    frame_id: Option<i64>,
    #[serde(default)]
    document_id: String,
    #[serde(default)]
    top_document_id: String,
    #[serde(default)]
    field_role: String,
    #[serde(default)]
    field_token: String,
    #[serde(default)]
    delivered: bool,
    #[serde(default)]
    readback: bool,
    #[serde(default)]
    submitted: bool,
}

struct PairingWindow {
    expires_at: std::time::Instant,
}

#[derive(Clone)]
struct ExtensionConnection {
    browser_instance_id: Uuid,
    jobs: mpsc::Sender<BrowserJob>,
}

#[derive(Clone)]
struct ActiveExtension {
    id: Uuid,
    browser_instance_id: Uuid,
    jobs: mpsc::Sender<BrowserJob>,
}

#[derive(Default)]
struct ExtensionPool {
    clients: HashMap<Uuid, ExtensionConnection>,
    active: Option<Uuid>,
}
impl ExtensionPool {
    fn add(&mut self, id: Uuid, browser_instance_id: Uuid, jobs: mpsc::Sender<BrowserJob>) {
        self.clients.insert(
            id,
            ExtensionConnection {
                browser_instance_id,
                jobs,
            },
        );
        if self.active.is_none() {
            self.active = Some(id);
        }
    }
    fn activate(&mut self, id: Uuid) -> bool {
        if self.clients.contains_key(&id) {
            self.active = Some(id);
            true
        } else {
            false
        }
    }
    fn remove(&mut self, id: Uuid) {
        self.clients.remove(&id);
        if self.active == Some(id) {
            self.active = self.clients.keys().next().copied();
        }
    }
    fn active(&self) -> Option<ActiveExtension> {
        let id = self.active?;
        let connection = self.clients.get(&id)?;
        Some(ActiveExtension {
            id,
            browser_instance_id: connection.browser_instance_id,
            jobs: connection.jobs.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CredentialTargetBinding {
    origin: String,
    tab_id: i64,
    window_id: i64,
    frame_id: i64,
    document_id: String,
    top_document_id: String,
    field_role: String,
    field_token: String,
}

impl CredentialTargetBinding {
    fn from_message(message: &ExtensionMessage, expected_module: &str) -> Option<Self> {
        if !valid_credential_origin(&message.origin)
            || message.field_role != expected_module
            || Uuid::parse_str(&message.field_token).is_err()
        {
            return None;
        }
        let tab_id = message.tab_id.filter(|value| *value >= 0)?;
        let window_id = message.window_id.filter(|value| *value >= 0)?;
        let frame_id = message.frame_id.filter(|value| *value >= 0)?;
        if Uuid::parse_str(&message.document_id).is_err()
            || Uuid::parse_str(&message.top_document_id).is_err()
        {
            return None;
        }
        Some(Self {
            origin: message.origin.clone(),
            tab_id,
            window_id,
            frame_id,
            document_id: message.document_id.clone(),
            top_document_id: message.top_document_id.clone(),
            field_role: message.field_role.clone(),
            field_token: message.field_token.clone(),
        })
    }
}

struct PendingCredentialFill {
    application_id: Uuid,
    connection_id: Uuid,
    browser_instance_id: Uuid,
    module: String,
    target: Option<CredentialTargetBinding>,
    sender: oneshot::Sender<BrowserFillResult>,
}

#[derive(Clone)]
struct BridgeServerState {
    pin_throttle: Arc<Mutex<std::time::Instant>>,
    vault: Vault,
    port: u16,
    internal_token: String,
    extension_token: String,
    application_id: Uuid,
    pairing: Arc<Mutex<Option<PairingWindow>>>,
    extensions: Arc<Mutex<ExtensionPool>>,
    pending: Arc<Mutex<HashMap<Uuid, PendingCredentialFill>>>,
    cancellation: CancellationToken,
}

struct Runtime {
    port: u16,
    status: String,
    error: String,
    cancellation: Option<CancellationToken>,
    task: Option<JoinHandle<()>>,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            port: 0,
            status: "off".to_owned(),
            error: String::new(),
            cancellation: None,
            task: None,
        }
    }
}

#[derive(Clone)]
pub struct BrowserBridge {
    vault: Vault,
    runtime: Arc<Mutex<Runtime>>,
    client: reqwest::Client,
}

impl BrowserBridge {
    pub fn new(vault: Vault) -> Self {
        Self {
            vault,
            runtime: Arc::new(Mutex::new(Runtime::default())),
            client: reqwest::Client::builder()
                .timeout(HTTP_REQUEST_TIMEOUT)
                .connect_timeout(Duration::from_secs(2))
                .build()
                .expect("reqwest client configuration must be valid"),
        }
    }

    pub async fn sync(&self) {
        let settings = match self.vault.settings() {
            Ok(settings) => settings,
            Err(error) => {
                self.set_error(error.to_string()).await;
                return;
            }
        };
        if !settings.browser_enabled {
            self.stop().await;
            return;
        }
        if let Err(error) = self.ensure_started(settings.browser_port).await {
            self.set_error(error.to_string()).await;
        }
    }

    pub async fn stop(&self) {
        let (cancellation, task) = {
            let mut runtime = self.runtime.lock().await;
            runtime.status = "off".to_owned();
            runtime.error.clear();
            (runtime.cancellation.take(), runtime.task.take())
        };
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
        if let Some(task) = task {
            let _ = task.await;
        }
    }

    pub async fn status(&self) -> BrowserBridgeState {
        let settings = self.vault.settings().unwrap_or_default();
        let (status, error) = {
            let runtime = self.runtime.lock().await;
            (runtime.status.clone(), runtime.error.clone())
        };
        let connected = settings.browser_enabled
            && settings.browser_paired
            && matches!(status.as_str(), "listening" | "delegated")
            && self.probe_fill_ready(settings.browser_port).await;
        BrowserBridgeState {
            enabled: settings.browser_enabled,
            paired: settings.browser_paired,
            connected,
            status,
            error,
            endpoint: format!("ws://127.0.0.1:{}/extension", settings.browser_port),
        }
    }

    pub fn fill_enabled(&self) -> Result<bool> {
        Ok(self.vault.settings()?.browser_enabled)
    }

    pub fn fill_configured(&self) -> bool {
        self.vault
            .settings()
            .is_ok_and(|settings| settings.browser_enabled && settings.browser_paired)
    }

    async fn probe_fill_ready(&self, port: u16) -> bool {
        self.client
            .get(format!("http://127.0.0.1:{port}/internal/ready"))
            .bearer_auth(self.internal_token().unwrap_or_default())
            .timeout(HEALTH_REQUEST_TIMEOUT)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
    }

    pub async fn start_quick_pairing(&self) -> Result<()> {
        let settings = self.vault.settings()?;
        if !settings.browser_enabled {
            bail!("Enable Browser Bridge first");
        }
        self.ensure_started(settings.browser_port).await?;
        let response = self
            .client
            .post(format!(
                "http://127.0.0.1:{}/internal/quick-pair",
                settings.browser_port
            ))
            .bearer_auth(self.internal_token()?)
            .send()
            .await
            .context("Unable to connect to Browser Bridge")?;
        if !response.status().is_success() {
            bail!(
                "Unable to start automatic browser pairing:{}",
                response.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }

    pub async fn reset_pairing(&self) -> Result<()> {
        let settings = self.vault.settings()?;
        if !settings.browser_enabled {
            self.vault.rotate_browser_bridge_secret()?;
            return Ok(());
        }
        self.ensure_started(settings.browser_port).await?;
        let response = self
            .client
            .post(format!(
                "http://127.0.0.1:{}/internal/reset",
                settings.browser_port
            ))
            .bearer_auth(self.internal_token()?)
            .send()
            .await
            .context("Unable to connect to Browser Bridge")?;
        if !response.status().is_success() {
            bail!("Unable to reset browser pairing");
        }
        self.stop().await;
        sleep(Duration::from_millis(120)).await;
        self.sync().await;
        Ok(())
    }

    pub async fn fill_credential(&self, item_id: Uuid, module: &str) -> Result<BrowserFillResult> {
        let module = module.trim();
        if !matches!(module, "password" | "username") {
            bail!("Browser credential filling supports only password and username modules");
        }
        let settings = self.vault.settings()?;
        if !settings.browser_enabled {
            bail!("Browser Bridge is not enabled");
        }
        if !settings.browser_paired {
            bail!("Chromium extension has not been paired");
        }
        self.ensure_started(settings.browser_port).await?;
        let request = CredentialFillRequest {
            id: Uuid::new_v4(),
            credential_ref: CredentialReference {
                item_id,
                module: module.to_owned(),
            },
            expires_at: unix_millis().saturating_add(JOB_TIMEOUT.as_millis() as u64),
        };
        let response = self
            .client
            .post(format!(
                "http://127.0.0.1:{}/internal/credential-fills",
                settings.browser_port
            ))
            .bearer_auth(self.internal_token()?)
            .json(&request)
            .send()
            .await
            .context("Unable to submit browser credential reference")?;
        if !response.status().is_success() {
            let status = response.status();
            let _ = response.bytes().await;
            bail!("Browser credential fill failed ({status}); the operation was not replayed");
        }
        let result: BrowserFillResult = response
            .json()
            .await
            .context("Invalid browser credential result format")?;
        if result.operation_id != request.id
            || result.application_id != self.application_id()?
            || result.connection_id.is_nil()
            || result.browser_instance_id.is_nil()
            || !result.ok
            || !result.delivered
            || !result.readback
            || result.submitted
        {
            bail!("Browser credential delivery could not be independently verified");
        }
        Ok(result)
    }

    async fn ensure_started(&self, port: u16) -> Result<()> {
        self.clear_finished_runtime().await;
        let current_status = {
            let runtime = self.runtime.lock().await;
            (runtime.port, runtime.status.clone())
        };
        if current_status.0 == port && current_status.1 == "listening" {
            return Ok(());
        }
        if current_status.0 == port && current_status.1 == "delegated" {
            let alive = self
                .client
                .get(format!("http://127.0.0.1:{port}/internal/health"))
                .bearer_auth(self.internal_token()?)
                .timeout(HEALTH_REQUEST_TIMEOUT)
                .send()
                .await
                .is_ok_and(|response| response.status().is_success());
            if alive {
                return Ok(());
            }
        }
        self.stop().await;
        let internal_token = self.internal_token()?;
        let extension_token = self.extension_token()?;
        let application_id = self.application_id()?;
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => {
                let cancellation = CancellationToken::new();
                let state = BridgeServerState {
                    pin_throttle: Arc::new(Mutex::new(std::time::Instant::now())),
                    vault: self.vault.clone(),
                    port,
                    internal_token,
                    extension_token,
                    application_id,
                    pairing: Arc::new(Mutex::new(None)),
                    extensions: Arc::new(Mutex::new(ExtensionPool::default())),
                    pending: Arc::new(Mutex::new(HashMap::new())),
                    cancellation: cancellation.clone(),
                };
                let router = Router::new()
                    .route("/health", get(health))
                    .route("/claim", post(claim))
                    .route("/extension", get(extension_upgrade))
                    .route("/internal/health", get(internal_health))
                    .route("/internal/ready", get(internal_ready))
                    .route("/internal/quick-pair", post(create_quick_pair))
                    .route("/internal/credential-fills", post(submit_credential_fill))
                    .route("/internal/reset", post(reset_pairing))
                    .layer(
                        CorsLayer::new()
                            .allow_origin(Any)
                            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
                            .allow_methods([Method::GET, Method::POST]),
                    )
                    .with_state(state);
                let child_cancellation = cancellation.clone();
                let task = tokio::spawn(async move {
                    let _ = axum::serve(listener, router)
                        .with_graceful_shutdown(child_cancellation.cancelled_owned())
                        .await;
                });
                let mut runtime = self.runtime.lock().await;
                runtime.port = port;
                runtime.status = "listening".to_owned();
                runtime.error.clear();
                runtime.cancellation = Some(cancellation);
                runtime.task = Some(task);
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                let response = self
                    .client
                    .get(format!("http://127.0.0.1:{port}/internal/health"))
                    .bearer_auth(internal_token)
                    .timeout(HEALTH_REQUEST_TIMEOUT)
                    .send()
                    .await
                    .context("Browser Bridge port is occupied by another program")?;
                if !response.status().is_success() {
                    bail!("Browser Bridge port is occupied by another program");
                }
                let mut runtime = self.runtime.lock().await;
                runtime.port = port;
                runtime.status = "delegated".to_owned();
                runtime.error.clear();
                Ok(())
            }
            Err(error) => Err(error).context("Unable to start Browser Bridge"),
        }
    }

    async fn clear_finished_runtime(&self) {
        let mut runtime = self.runtime.lock().await;
        if runtime.task.as_ref().is_some_and(JoinHandle::is_finished) {
            runtime.task = None;
            runtime.cancellation = None;
            runtime.status = "off".to_owned();
        }
    }

    async fn set_error(&self, message: String) {
        let mut runtime = self.runtime.lock().await;
        runtime.status = "error".to_owned();
        runtime.error = message;
    }

    fn internal_token(&self) -> Result<String> {
        derive_token(&self.vault.browser_bridge_secret()?, "internal")
    }

    fn extension_token(&self) -> Result<String> {
        derive_token(&self.vault.browser_bridge_secret()?, "extension")
    }

    fn application_id(&self) -> Result<Uuid> {
        derive_application_id(&self.vault.browser_bridge_secret()?)
    }
}

async fn health() -> &'static str {
    "OpenKeylet Browser Bridge"
}

async fn internal_health(
    State(state): State<BridgeServerState>,
    headers: HeaderMap,
) -> Result<&'static str, (StatusCode, String)> {
    require_bearer(&headers, &state.internal_token)?;
    Ok("ok")
}

async fn internal_ready(
    State(state): State<BridgeServerState>,
    headers: HeaderMap,
) -> Result<&'static str, (StatusCode, String)> {
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

async fn create_quick_pair(
    State(state): State<BridgeServerState>,
    headers: HeaderMap,
) -> Result<&'static str, (StatusCode, String)> {
    require_bearer(&headers, &state.internal_token)?;
    *state.pairing.lock().await = Some(PairingWindow {
        expires_at: std::time::Instant::now() + Duration::from_secs(120),
    });
    Ok("ready")
}

async fn claim(
    State(state): State<BridgeServerState>,
    headers: HeaderMap,
) -> Result<Json<PairResponse>, (StatusCode, String)> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if origin != EXTENSION_ORIGIN {
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
    *pairing = None;
    state
        .vault
        .set_browser_paired(true)
        .map_err(internal_error)?;
    Ok(Json(PairResponse {
        token: state.extension_token.clone(),
        port: state.port,
    }))
}

async fn submit_credential_fill(
    State(state): State<BridgeServerState>,
    headers: HeaderMap,
    Json(mut request): Json<CredentialFillRequest>,
) -> Result<Json<BrowserFillResult>, (StatusCode, String)> {
    require_bearer(&headers, &state.internal_token)?;
    request.normalize_deadline();
    if request.id.is_nil() || request.credential_ref.item_id.is_nil() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid credential reference".to_owned(),
        ));
    }
    if !matches!(
        request.credential_ref.module.as_str(),
        "password" | "username"
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Unsupported browser credential module".to_owned(),
        ));
    }
    if request.is_expired() {
        return Err((
            StatusCode::GATEWAY_TIMEOUT,
            "Browser credential operation expired".to_owned(),
        ));
    }

    // Pin one exact extension connection. An uncertain operation is never replayed.
    let grace = EXTENSION_RECONNECT_GRACE.min(request.remaining());
    let Some(active) = wait_for_active_extension(&state, grace).await else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Browser extension is not connected".to_owned(),
        ));
    };
    let job = BrowserJob::from_request(
        request,
        state.application_id,
        active.id,
        active.browser_instance_id,
    );
    let (sender, receiver) = oneshot::channel();
    state.pending.lock().await.insert(
        job.id,
        PendingCredentialFill {
            application_id: job.application_id,
            connection_id: job.connection_id,
            browser_instance_id: job.browser_instance_id,
            module: job.credential_ref.module.clone(),
            target: None,
            sender,
        },
    );

    if !job_is_deliverable(&state, &job, active.id, active.browser_instance_id).await {
        state.pending.lock().await.remove(&job.id);
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "The pinned browser connection is no longer available".to_owned(),
        ));
    }
    if !deliver_to_extension(&active, &job).await {
        if active.jobs.is_closed() {
            state.extensions.lock().await.remove(active.id);
        }
        state.pending.lock().await.remove(&job.id);
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "The pinned browser connection is unavailable; the operation was not replayed"
                .to_owned(),
        ));
    }

    match timeout(job.remaining(), receiver).await {
        Ok(Ok(result)) if result.ok && result.delivered && result.readback && !result.submitted => {
            Ok(Json(result))
        }
        Ok(Ok(_)) => Err((
            StatusCode::BAD_REQUEST,
            "Browser credential delivery could not be independently verified".to_owned(),
        )),
        _ => {
            state.pending.lock().await.remove(&job.id);
            Err((
                StatusCode::GATEWAY_TIMEOUT,
                "Browser credential operation timed out; it was not replayed".to_owned(),
            ))
        }
    }
}

async fn wait_for_active_extension(
    state: &BridgeServerState,
    grace: Duration,
) -> Option<ActiveExtension> {
    let deadline = tokio::time::Instant::now() + grace;
    loop {
        if let Some(active) = state.extensions.lock().await.active() {
            return Some(active);
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return None;
        }
        sleep(Duration::from_millis(50).min(deadline - now)).await;
    }
}

async fn job_is_deliverable(
    state: &BridgeServerState,
    job: &BrowserJob,
    connection_id: Uuid,
    browser_instance_id: Uuid,
) -> bool {
    if job.is_expired()
        || job.application_id != state.application_id
        || job.connection_id != connection_id
        || job.browser_instance_id != browser_instance_id
    {
        return false;
    }
    state
        .pending
        .lock()
        .await
        .get(&job.id)
        .is_some_and(|pending| {
            pending.application_id == job.application_id
                && pending.connection_id == connection_id
                && pending.browser_instance_id == browser_instance_id
                && pending.module == job.credential_ref.module
        })
}

async fn deliver_to_extension(active: &ActiveExtension, job: &BrowserJob) -> bool {
    timeout(
        EXTENSION_QUEUE_TIMEOUT.min(job.remaining()),
        active.jobs.send(job.clone()),
    )
    .await
    .is_ok_and(|result| result.is_ok())
}

async fn reset_pairing(
    State(state): State<BridgeServerState>,
    headers: HeaderMap,
) -> Result<&'static str, (StatusCode, String)> {
    require_bearer(&headers, &state.internal_token)?;
    state
        .vault
        .rotate_browser_bridge_secret()
        .map_err(internal_error)?;
    let cancellation = state.cancellation.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(80)).await;
        cancellation.cancel();
    });
    Ok("reset")
}

async fn extension_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<BridgeServerState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if origin != EXTENSION_ORIGIN {
        return Err((
            StatusCode::FORBIDDEN,
            "Only the paired Chromium extension may connect".to_owned(),
        ));
    }
    Ok(ws.on_upgrade(move |socket| extension_socket(socket, state)))
}

async fn extension_socket(socket: WebSocket, state: BridgeServerState) {
    let mut browser_session = crate::browser_vault::Session::default();
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
    let token_matches = message.token.len() == state.extension_token.len()
        && subtle::ConstantTimeEq::ct_eq(
            message.token.as_bytes(),
            state.extension_token.as_bytes(),
        )
        .into();
    let Some(browser_instance_id) = message.browser_instance_id else {
        let _ = sender.send(Message::Close(None)).await;
        return;
    };
    if message.kind != "auth"
        || !token_matches
        || browser_instance_id.is_nil()
        || message.extension_id != EXTENSION_ORIGIN.trim_start_matches("chrome-extension://")
    {
        let _ = sender
            .send(Message::Text(
                serde_json::json!({"type":"auth-error"}).to_string().into(),
            ))
            .await;
        let _ = sender.send(Message::Close(None)).await;
        return;
    }

    let connection_id = Uuid::new_v4();
    let (job_sender, mut jobs) = mpsc::channel(8);
    state
        .extensions
        .lock()
        .await
        .add(connection_id, browser_instance_id, job_sender);
    let ready = serde_json::json!({
        "type":"ready",
        "applicationId":state.application_id,
        "connectionId":connection_id,
        "browserInstanceId":browser_instance_id
    });
    if sender
        .send(Message::Text(ready.to_string().into()))
        .await
        .is_err()
    {
        state.extensions.lock().await.remove(connection_id);
        return;
    }

    loop {
        tokio::select! {
            job = jobs.recv() => {
                let Some(job) = job else { break; };
                if !job_is_deliverable(&state, &job, connection_id, browser_instance_id).await { continue; }
                let Ok(json) = serde_json::to_string(&serde_json::json!({"type":"job","job":job})) else { continue; };
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
                            let result = crate::browser_vault::handle(&state.vault, &mut browser_session, &state.pin_throttle, &message.method, &message.params).await;
                            let response = match result {
                                Ok(value) => serde_json::json!({"type":"rpc-result","requestId":request_id,"ok":true,"result":value}),
                                Err(error) => serde_json::json!({"type":"rpc-result","requestId":request_id,"ok":false,"error":error.to_string()}),
                            };
                            if sender.send(Message::Text(response.to_string().into())).await.is_err() { break; }
                            continue;
                        }
                        if message.kind == "ping" {
                            if sender.send(Message::Text(serde_json::json!({"type":"pong"}).to_string().into())).await.is_err() { break; }
                            continue;
                        }
                        if message.kind == "activate" {
                            state.extensions.lock().await.activate(connection_id);
                            continue;
                        }
                        if message.kind == "prepare" {
                            let Some(operation_id) = message.operation_id else { continue; };
                            let prepare_status = {
                                let mut pending = state.pending.lock().await;
                                let Some(expected) = pending.get_mut(&operation_id) else { continue; };
                                if expected.application_id != state.application_id
                                    || expected.connection_id != connection_id
                                    || expected.browser_instance_id != browser_instance_id
                                    || message.application_id != Some(state.application_id)
                                    || message.connection_id != Some(connection_id)
                                    || message.browser_instance_id != Some(browser_instance_id)
                                {
                                    0
                                } else if expected.target.is_some() {
                                    2
                                } else if let Some(binding) = CredentialTargetBinding::from_message(&message, &expected.module) {
                                    expected.target = Some(binding);
                                    1
                                } else {
                                    2
                                }
                            };
                            let response = serde_json::json!({
                                "type": if prepare_status == 1 { "prepared" } else { "prepare-rejected" },
                                "operationId": operation_id,
                                "applicationId": state.application_id,
                                "connectionId": connection_id,
                                "browserInstanceId": browser_instance_id,
                                "fieldToken": message.field_token,
                            });
                            if prepare_status != 0 && sender.send(Message::Text(response.to_string().into())).await.is_err() { break; }
                            continue;
                        }
                        if message.kind != "complete" { continue; }
                        let Some(operation_id) = message.operation_id else { continue; };
                        let (expected_module, expected_target) = {
                            let pending = state.pending.lock().await;
                            let Some(expected) = pending.get(&operation_id) else { continue; };
                            if expected.application_id != state.application_id
                                || expected.connection_id != connection_id
                                || expected.browser_instance_id != browser_instance_id
                                || message.application_id != Some(state.application_id)
                                || message.connection_id != Some(connection_id)
                                || message.browser_instance_id != Some(browser_instance_id)
                            { continue; }
                            (expected.module.clone(), expected.target.clone())
                        };
                        let completion_binding = CredentialTargetBinding::from_message(&message, &expected_module);
                        let target_matches = expected_target.as_ref().is_some_and(|expected| {
                            completion_binding.as_ref() == Some(expected)
                        });
                        let result = BrowserFillResult {
                            ok: message.ok && message.delivered && message.readback && !message.submitted && target_matches,
                            operation_id,
                            application_id: state.application_id,
                            connection_id,
                            browser_instance_id,
                            origin: message.origin,
                            tab_id: message.tab_id.unwrap_or_default(),
                            window_id: message.window_id.unwrap_or_default(),
                            frame_id: message.frame_id.unwrap_or_default(),
                            document_id: message.document_id,
                            top_document_id: message.top_document_id,
                            field_role: message.field_role,
                            delivered: message.delivered,
                            readback: message.readback,
                            submitted: message.submitted,
                        };
                        let Some(pending) = state.pending.lock().await.remove(&operation_id) else { continue; };
                        let _ = pending.sender.send(result);
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
}

fn valid_credential_origin(origin: &str) -> bool {
    let Ok(url) = url::Url::parse(origin) else {
        return false;
    };
    if url.origin().ascii_serialization() != origin
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    match url.scheme() {
        "https" => true,
        "http" => {
            cfg!(feature = "synthetic-browser-tests")
                && matches!(
                    url.host_str(),
                    Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
                )
        }
        _ => false,
    }
}

fn require_bearer(headers: &HeaderMap, expected: &str) -> Result<(), (StatusCode, String)> {
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

fn internal_error(error: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

fn derive_token(secret: &str, role: &str) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"mcp-vault/browser/v1/");
    hasher.update(role.as_bytes());
    hasher.update(secret.as_bytes());
    Ok(STANDARD_NO_PAD.encode(hasher.finalize()))
}

fn derive_application_id(secret: &str) -> Result<Uuid> {
    let mut hasher = Sha256::new();
    hasher.update(b"mcp-vault/browser/application/v1/");
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes))
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn current_totp(secret: &str) -> Result<String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Invalid system time")?
        .as_secs();
    totp_at(secret, timestamp)
}

fn totp_at(secret: &str, timestamp: u64) -> Result<String> {
    let mut seed = secret.trim().to_owned();
    let (mut digits, mut period, mut algorithm) = (6usize, 30u64, "SHA1".to_owned());
    if seed.starts_with("otpauth://") {
        let uri = url::Url::parse(&seed).context("Invalid TOTP URI")?;
        if uri.host_str() != Some("totp") {
            bail!("Only time-based TOTP URIs are supported");
        }
        let pairs: Vec<_> = uri.query_pairs().collect();
        for name in ["secret", "digits", "period", "algorithm"] {
            if pairs.iter().filter(|(key, _)| key == name).count() > 1 {
                bail!("Duplicate TOTP parameter");
            }
        }
        let get = |name| {
            pairs
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_ref())
        };
        digits = get("digits")
            .unwrap_or("6")
            .parse()
            .context("Invalid TOTP digits")?;
        period = get("period")
            .unwrap_or("30")
            .parse()
            .context("Invalid TOTP period")?;
        algorithm = get("algorithm").unwrap_or("SHA1").to_ascii_uppercase();
        seed = get("secret").context("Missing TOTP secret")?.to_owned();
    }
    if !(6..=8).contains(&digits) || !(1..=300).contains(&period) {
        bail!("Invalid TOTP digits or period");
    }
    let key = zeroize::Zeroizing::new(decode_base32(&seed)?);
    let counter = timestamp / period;
    macro_rules! digest {
        ($hash:ty) => {{
            let mut mac = Hmac::<$hash>::new_from_slice(&key).context("Invalid TOTP key")?;
            mac.update(&counter.to_be_bytes());
            mac.finalize().into_bytes().to_vec()
        }};
    }
    let digest = match algorithm.as_str() {
        "SHA1" => digest!(Sha1),
        "SHA256" => digest!(Sha256),
        "SHA512" => digest!(sha2::Sha512),
        _ => bail!("Unsupported TOTP algorithm"),
    };
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let value = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok(format!("{:0digits$}", value % 10u32.pow(digits as u32)))
}

fn decode_base32(value: &str) -> Result<Vec<u8>> {
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    let mut output = Vec::new();
    for character in value
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '-')
    {
        if character == '=' {
            break;
        }
        let character = character.to_ascii_uppercase();
        let number = match character {
            'A'..='Z' => character as u8 - b'A',
            '2'..='7' => character as u8 - b'2' + 26,
            _ => bail!("TOTP Secret must be Base32"),
        };
        buffer = (buffer << 5) | u32::from(number);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1_u32 << bits).saturating_sub(1);
        }
    }
    if output.is_empty() {
        bail!("TOTP Secret cannot be empty");
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use tempfile::{TempDir, tempdir};
    use tokio_tungstenite::{
        connect_async,
        tungstenite::{Message as TungsteniteMessage, client::IntoClientRequest},
    };

    fn test_vault() -> (TempDir, Vault) {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().to_path_buf()).unwrap();
        (directory, vault)
    }

    fn test_server_state(vault: Vault, port: u16) -> BridgeServerState {
        let secret = vault.browser_bridge_secret().unwrap();
        BridgeServerState {
            pin_throttle: Arc::new(Mutex::new(std::time::Instant::now())),
            vault,
            port,
            internal_token: "test-internal-token".to_owned(),
            extension_token: "test-extension-token".to_owned(),
            application_id: derive_application_id(&secret).unwrap(),
            pairing: Arc::new(Mutex::new(None)),
            extensions: Arc::new(Mutex::new(ExtensionPool::default())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            cancellation: CancellationToken::new(),
        }
    }

    fn test_request(id: Uuid) -> CredentialFillRequest {
        CredentialFillRequest {
            id,
            credential_ref: CredentialReference {
                item_id: Uuid::new_v4(),
                module: "password".to_owned(),
            },
            expires_at: unix_millis().saturating_add(5_000),
        }
    }

    fn extension_auth(token: &str, browser_instance_id: Uuid) -> Value {
        json!({
            "type": "auth",
            "token": token,
            "extensionId": EXTENSION_ORIGIN.trim_start_matches("chrome-extension://"),
            "browserInstanceId": browser_instance_id,
        })
    }

    async fn receive_json<S>(socket: &mut tokio_tungstenite::WebSocketStream<S>) -> Value
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let message = timeout(Duration::from_secs(3), socket.next())
            .await
            .expect("timed out waiting for websocket message")
            .expect("websocket closed")
            .expect("websocket receive failed");
        let TungsteniteMessage::Text(text) = message else {
            panic!("expected a websocket text message");
        };
        serde_json::from_str(&text).unwrap()
    }

    fn extension_request(
        url: &str,
        origin: &str,
    ) -> tokio_tungstenite::tungstenite::http::Request<()> {
        let mut request = url.into_client_request().unwrap();
        request
            .headers_mut()
            .insert(header::ORIGIN, origin.parse().unwrap());
        request
    }

    #[test]
    fn application_identity_is_stable_and_not_a_client_name() {
        let secret = "synthetic-browser-bridge-secret";
        let first = derive_application_id(secret).unwrap();
        let second = derive_application_id(secret).unwrap();
        assert_eq!(first, second);
        assert_ne!(first, Uuid::nil());
        assert_ne!(first.to_string(), "self-asserted-untrusted-client-label");
    }

    #[test]
    fn browser_jobs_contain_only_a_credential_reference_and_bindings() {
        let request = test_request(Uuid::new_v4());
        let item_id = request.credential_ref.item_id;
        let application_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let browser_instance_id = Uuid::new_v4();
        let job =
            BrowserJob::from_request(request, application_id, connection_id, browser_instance_id);
        let value = serde_json::to_value(&job).unwrap();

        assert_eq!(value["credentialRef"]["itemId"], item_id.to_string());
        assert_eq!(value["credentialRef"]["module"], "password");
        assert_eq!(value["applicationId"], application_id.to_string());
        assert_eq!(value["connectionId"], connection_id.to_string());
        assert_eq!(value["browserInstanceId"], browser_instance_id.to_string());
        assert!(value.get("value").is_none());
        assert!(value.get("password").is_none());
        assert!(value.get("submit").is_none());
    }

    #[test]
    fn credential_origins_require_https_except_loopback() {
        assert!(valid_credential_origin("https://example.com"));
        assert!(valid_credential_origin("https://example.com:8443"));
        #[cfg(feature = "synthetic-browser-tests")]
        {
            assert!(valid_credential_origin("http://localhost:5173"));
            assert!(valid_credential_origin("http://127.0.0.1:5173"));
            assert!(valid_credential_origin("http://[::1]:5173"));
        }
        #[cfg(not(feature = "synthetic-browser-tests"))]
        {
            assert!(!valid_credential_origin("http://localhost:5173"));
            assert!(!valid_credential_origin("http://127.0.0.1:5173"));
            assert!(!valid_credential_origin("http://[::1]:5173"));
        }
        assert!(!valid_credential_origin("http://example.com"));
        assert!(!valid_credential_origin("https://example.com/path"));
        assert!(!valid_credential_origin("file:///tmp/test"));
    }

    #[cfg(not(feature = "synthetic-browser-tests"))]
    #[test]
    fn production_credential_origins_reject_http_even_on_loopback() {
        assert!(!valid_credential_origin("http://localhost"));
        assert!(!valid_credential_origin("http://127.0.0.1"));
        assert!(!valid_credential_origin("http://[::1]"));
        assert!(valid_credential_origin("https://example.com"));
    }

    #[test]
    fn credential_target_binding_requires_origin_document_and_exact_field_identity() {
        let field_token = Uuid::new_v4();
        let valid: ExtensionMessage = serde_json::from_value(json!({
            "type":"prepare",
            "origin":"https://example.com",
            "tabId":7,
            "windowId":2,
            "frameId":0,
            "documentId":Uuid::new_v4().to_string(),
            "topDocumentId":Uuid::new_v4().to_string(),
            "fieldRole":"password",
            "fieldToken":field_token,
        }))
        .unwrap();
        assert!(CredentialTargetBinding::from_message(&valid, "password").is_some());
        assert!(CredentialTargetBinding::from_message(&valid, "username").is_none());

        let mut wrong_origin = valid.clone();
        wrong_origin.origin = "http://example.com".to_owned();
        assert!(CredentialTargetBinding::from_message(&wrong_origin, "password").is_none());

        let mut missing_document = valid.clone();
        missing_document.document_id.clear();
        assert!(CredentialTargetBinding::from_message(&missing_document, "password").is_none());

        let mut replaced_field = valid;
        replaced_field.field_token = "not-a-uuid".to_owned();
        assert!(CredentialTargetBinding::from_message(&replaced_field, "password").is_none());
    }

    #[tokio::test]
    async fn quick_pairing_requires_the_exact_extension_origin() {
        let (_directory, vault) = test_vault();
        let state = test_server_state(vault, 45678);
        let denied = claim(State(state.clone()), HeaderMap::new()).await;
        assert_eq!(denied.unwrap_err().0, StatusCode::FORBIDDEN);

        state.pairing.lock().await.replace(PairingWindow {
            expires_at: std::time::Instant::now() + Duration::from_secs(60),
        });
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, EXTENSION_ORIGIN.parse().unwrap());
        let response = claim(State(state), headers).await.unwrap().0;
        assert!(!response.token.is_empty());
        assert!(response.port > 0);
    }

    #[tokio::test]
    async fn quick_pairing_rejects_an_expired_window() {
        let (_directory, vault) = test_vault();
        let state = test_server_state(vault, 0);
        state.pairing.lock().await.replace(PairingWindow {
            expires_at: std::time::Instant::now() - Duration::from_secs(1),
        });
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, EXTENSION_ORIGIN.parse().unwrap());
        let denied = claim(State(state), headers).await;
        assert_eq!(denied.unwrap_err().0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn active_extension_waits_briefly_for_a_reconnecting_client() {
        let (_directory, vault) = test_vault();
        let state = test_server_state(vault, 0);
        let waiting_state = state.clone();
        let waiting = tokio::spawn(async move {
            wait_for_active_extension(&waiting_state, Duration::from_secs(1)).await
        });
        sleep(Duration::from_millis(80)).await;
        let connection_id = Uuid::new_v4();
        let browser_instance_id = Uuid::new_v4();
        let (sender, _receiver) = mpsc::channel(1);
        state
            .extensions
            .lock()
            .await
            .add(connection_id, browser_instance_id, sender);
        let active = waiting.await.unwrap().unwrap();
        assert_eq!(active.id, connection_id);
        assert_eq!(active.browser_instance_id, browser_instance_id);
    }

    #[tokio::test]
    async fn a_job_is_deliverable_only_to_its_pinned_connection_and_pending_operation() {
        let (_directory, vault) = test_vault();
        let state = test_server_state(vault, 0);
        let connection_id = Uuid::new_v4();
        let browser_instance_id = Uuid::new_v4();
        let job = BrowserJob::from_request(
            test_request(Uuid::new_v4()),
            state.application_id,
            connection_id,
            browser_instance_id,
        );
        let (sender, _receiver) = oneshot::channel();
        state.pending.lock().await.insert(
            job.id,
            PendingCredentialFill {
                application_id: job.application_id,
                connection_id,
                browser_instance_id,
                module: "password".to_owned(),
                target: None,
                sender,
            },
        );

        assert!(job_is_deliverable(&state, &job, connection_id, browser_instance_id).await);
        assert!(!job_is_deliverable(&state, &job, Uuid::new_v4(), browser_instance_id).await);
        assert!(!job_is_deliverable(&state, &job, connection_id, Uuid::new_v4()).await);
        state.pending.lock().await.remove(&job.id);
        assert!(!job_is_deliverable(&state, &job, connection_id, browser_instance_id).await);
    }

    #[tokio::test]
    async fn a_stalled_extension_queue_is_bounded_without_replay() {
        let connection_id = Uuid::new_v4();
        let browser_instance_id = Uuid::new_v4();
        let (sender, mut receiver) = mpsc::channel(1);
        let first = BrowserJob::from_request(
            test_request(Uuid::new_v4()),
            Uuid::new_v4(),
            connection_id,
            browser_instance_id,
        );
        sender.try_send(first).unwrap();
        let active = ActiveExtension {
            id: connection_id,
            browser_instance_id,
            jobs: sender,
        };
        let second = BrowserJob::from_request(
            test_request(Uuid::new_v4()),
            Uuid::new_v4(),
            connection_id,
            browser_instance_id,
        );
        assert!(!deliver_to_extension(&active, &second).await);
        let _ = receiver.recv().await;
    }

    #[tokio::test]
    async fn credential_fill_is_bound_to_one_extension_socket_and_falls_back_only_after_disconnect()
    {
        let (_directory, vault) = test_vault();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = test_server_state(vault, port);
        let app = Router::new()
            .route("/extension", get(extension_upgrade))
            .route("/internal/credential-fills", post(submit_credential_fill))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let url = format!("ws://127.0.0.1:{port}/extension");

        let denied = connect_async(extension_request(&url, "https://evil.example")).await;
        assert!(denied.is_err(), "non-extension Origin was accepted");

        let first_browser = Uuid::new_v4();
        let second_browser = Uuid::new_v4();
        let (mut first, _) = connect_async(extension_request(&url, EXTENSION_ORIGIN))
            .await
            .unwrap();
        first
            .send(TungsteniteMessage::Text(
                extension_auth(&state.extension_token, first_browser)
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        let first_ready = receive_json(&mut first).await;
        let application_id = first_ready["applicationId"].as_str().unwrap().to_owned();
        let first_connection = first_ready["connectionId"].as_str().unwrap().to_owned();
        assert_eq!(first_ready["browserInstanceId"], first_browser.to_string());

        let (mut second, _) = connect_async(extension_request(&url, EXTENSION_ORIGIN))
            .await
            .unwrap();
        second
            .send(TungsteniteMessage::Text(
                extension_auth(&state.extension_token, second_browser)
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        let second_ready = receive_json(&mut second).await;
        let second_connection = second_ready["connectionId"].as_str().unwrap().to_owned();
        assert_eq!(second_ready["applicationId"], application_id);
        assert_eq!(
            second_ready["browserInstanceId"],
            second_browser.to_string()
        );
        second
            .send(TungsteniteMessage::Text(
                json!({"type":"activate"}).to_string().into(),
            ))
            .await
            .unwrap();

        let client = reqwest::Client::new();
        let request_url = format!("http://127.0.0.1:{port}/internal/credential-fills");
        let operation_id = Uuid::new_v4();
        let item_id = Uuid::new_v4();
        let request = CredentialFillRequest {
            id: operation_id,
            credential_ref: CredentialReference {
                item_id,
                module: "password".to_owned(),
            },
            expires_at: unix_millis().saturating_add(5_000),
        };
        let token = "test-internal-token".to_owned();
        let client_for_fill = client.clone();
        let url_for_fill = request_url.clone();
        let mut fill_task = tokio::spawn(async move {
            client_for_fill
                .post(url_for_fill)
                .bearer_auth(token)
                .json(&request)
                .send()
                .await
                .unwrap()
        });

        let job_message = receive_json(&mut second).await;
        assert_eq!(job_message["type"], "job");
        let job = &job_message["job"];
        assert_eq!(job["id"], operation_id.to_string());
        assert_eq!(job["credentialRef"]["itemId"], item_id.to_string());
        assert_eq!(job["credentialRef"]["module"], "password");
        assert_eq!(job["applicationId"], application_id);
        assert_eq!(job["connectionId"], second_connection);
        assert_eq!(job["browserInstanceId"], second_browser.to_string());
        assert!(job.get("value").is_none());
        assert!(job.get("password").is_none());
        assert!(job.get("passwordHash").is_none());
        assert!(job.get("hash").is_none());
        assert!(job.get("submit").is_none());
        assert_eq!(job["credentialRef"].as_object().unwrap().len(), 2);

        let field_token = Uuid::new_v4();
        let binding = json!({
            "origin":"https://example.com",
            "tabId":7,
            "windowId":1,
            "frameId":0,
            "documentId":Uuid::new_v4().to_string(),
            "topDocumentId":Uuid::new_v4().to_string(),
            "fieldRole":"password",
            "fieldToken":field_token,
        });
        let mut wrong_prepare = json!({
            "type":"prepare",
            "operationId":operation_id,
            "applicationId":application_id,
            "connectionId":first_connection,
            "browserInstanceId":first_browser,
        });
        for (key, value) in binding.as_object().unwrap() {
            wrong_prepare[key] = value.clone();
        }
        first
            .send(TungsteniteMessage::Text(wrong_prepare.to_string().into()))
            .await
            .unwrap();
        let mut wrong_completion = json!({
            "type":"complete",
            "operationId":operation_id,
            "applicationId":application_id,
            "connectionId":first_connection,
            "browserInstanceId":first_browser,
            "ok":true,
            "delivered":true,
            "readback":true,
            "submitted":false,
        });
        for (key, value) in binding.as_object().unwrap() {
            wrong_completion[key] = value.clone();
        }
        first
            .send(TungsteniteMessage::Text(
                wrong_completion.to_string().into(),
            ))
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(120), &mut fill_task)
                .await
                .is_err(),
            "a different extension socket prepared or completed the pinned operation"
        );

        let wrong_application_token = Uuid::new_v4();
        let wrong_application_binding = json!({
            "origin":"https://example.com","tabId":7,"windowId":1,"frameId":0,
            "documentId":Uuid::new_v4().to_string(),"topDocumentId":Uuid::new_v4().to_string(),
            "fieldRole":"password","fieldToken":wrong_application_token,
        });
        let mut wrong_application_prepare = json!({
            "type":"prepare","operationId":operation_id,"applicationId":Uuid::new_v4(),
            "connectionId":second_connection,"browserInstanceId":second_browser,
        });
        for (key, value) in wrong_application_binding.as_object().unwrap() {
            wrong_application_prepare[key] = value.clone();
        }
        second
            .send(TungsteniteMessage::Text(
                wrong_application_prepare.to_string().into(),
            ))
            .await
            .unwrap();

        let wrong_browser_token = Uuid::new_v4();
        let wrong_browser_binding = json!({
            "origin":"https://example.com","tabId":7,"windowId":1,"frameId":0,
            "documentId":Uuid::new_v4().to_string(),"topDocumentId":Uuid::new_v4().to_string(),
            "fieldRole":"password","fieldToken":wrong_browser_token,
        });
        let mut wrong_browser_prepare = json!({
            "type":"prepare","operationId":operation_id,"applicationId":application_id,
            "connectionId":second_connection,"browserInstanceId":Uuid::new_v4(),
        });
        for (key, value) in wrong_browser_binding.as_object().unwrap() {
            wrong_browser_prepare[key] = value.clone();
        }
        second
            .send(TungsteniteMessage::Text(
                wrong_browser_prepare.to_string().into(),
            ))
            .await
            .unwrap();

        let mut prepare = json!({
            "type":"prepare",
            "operationId":operation_id,
            "applicationId":application_id,
            "connectionId":second_connection,
            "browserInstanceId":second_browser,
        });
        for (key, value) in binding.as_object().unwrap() {
            prepare[key] = value.clone();
        }
        second
            .send(TungsteniteMessage::Text(prepare.to_string().into()))
            .await
            .unwrap();
        let acknowledgement = receive_json(&mut second).await;
        assert_eq!(acknowledgement["type"], "prepared");
        assert_eq!(acknowledgement["fieldToken"], field_token.to_string());

        let mut completion = json!({
            "type":"complete",
            "operationId":operation_id,
            "applicationId":application_id,
            "connectionId":second_connection,
            "browserInstanceId":second_browser,
            "ok":true,
            "delivered":true,
            "readback":true,
            "submitted":false,
        });
        for (key, value) in binding.as_object().unwrap() {
            completion[key] = value.clone();
        }
        second
            .send(TungsteniteMessage::Text(completion.to_string().into()))
            .await
            .unwrap();
        let response = fill_task.await.unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let result: Value = response.json().await.unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["operationId"], operation_id.to_string());
        assert_eq!(result["applicationId"], application_id);
        assert_eq!(result["connectionId"], second_connection);
        assert_eq!(result["browserInstanceId"], second_browser.to_string());
        assert_eq!(result["delivered"], true);
        assert_eq!(result["readback"], true);
        assert_eq!(result["submitted"], false);

        // A completion cannot change the tab/document/field that was registered before mutation.
        let mismatch_operation = Uuid::new_v4();
        let mismatch_request = CredentialFillRequest {
            id: mismatch_operation,
            credential_ref: CredentialReference {
                item_id: Uuid::new_v4(),
                module: "password".to_owned(),
            },
            expires_at: unix_millis().saturating_add(5_000),
        };
        let mismatch_client = client.clone();
        let mismatch_url = request_url.clone();
        let mismatch_task = tokio::spawn(async move {
            mismatch_client
                .post(mismatch_url)
                .bearer_auth("test-internal-token")
                .json(&mismatch_request)
                .send()
                .await
                .unwrap()
        });
        let mismatch_job = receive_json(&mut second).await;
        assert_eq!(mismatch_job["job"]["id"], mismatch_operation.to_string());
        let mismatch_field_token = Uuid::new_v4();
        let mismatch_binding = json!({
            "origin":"https://example.com","tabId":9,"windowId":1,"frameId":0,
            "documentId":Uuid::new_v4().to_string(),"topDocumentId":Uuid::new_v4().to_string(),
            "fieldRole":"password","fieldToken":mismatch_field_token,
        });
        let mut mismatch_prepare = json!({
            "type":"prepare","operationId":mismatch_operation,"applicationId":application_id,
            "connectionId":second_connection,"browserInstanceId":second_browser,
        });
        for (key, value) in mismatch_binding.as_object().unwrap() {
            mismatch_prepare[key] = value.clone();
        }
        second
            .send(TungsteniteMessage::Text(
                mismatch_prepare.to_string().into(),
            ))
            .await
            .unwrap();
        assert_eq!(receive_json(&mut second).await["type"], "prepared");
        let mut mismatched_completion = json!({
            "type":"complete","operationId":mismatch_operation,"applicationId":application_id,
            "connectionId":second_connection,"browserInstanceId":second_browser,
            "ok":true,"delivered":true,"readback":true,"submitted":false,
        });
        for (key, value) in mismatch_binding.as_object().unwrap() {
            mismatched_completion[key] = value.clone();
        }
        mismatched_completion["documentId"] = json!(Uuid::new_v4().to_string());
        second
            .send(TungsteniteMessage::Text(
                mismatched_completion.to_string().into(),
            ))
            .await
            .unwrap();
        assert_eq!(
            mismatch_task.await.unwrap().status().as_u16(),
            StatusCode::BAD_REQUEST.as_u16()
        );

        second.close(None).await.unwrap();
        for _ in 0..30 {
            if state
                .extensions
                .lock()
                .await
                .active()
                .is_some_and(|active| active.id.to_string() == first_connection)
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        let fallback_operation = Uuid::new_v4();
        let fallback_request = CredentialFillRequest {
            id: fallback_operation,
            credential_ref: CredentialReference {
                item_id: Uuid::new_v4(),
                module: "password".to_owned(),
            },
            expires_at: unix_millis().saturating_add(5_000),
        };
        let fallback_client = client.clone();
        let fallback_url = request_url.clone();
        let fallback_task = tokio::spawn(async move {
            fallback_client
                .post(fallback_url)
                .bearer_auth("test-internal-token")
                .json(&fallback_request)
                .send()
                .await
                .unwrap()
        });
        let fallback_job = receive_json(&mut first).await;
        assert_eq!(fallback_job["job"]["connectionId"], first_connection);
        assert_eq!(
            fallback_job["job"]["browserInstanceId"],
            first_browser.to_string()
        );
        let fallback_field_token = Uuid::new_v4();
        let fallback_binding = json!({
            "origin":"https://example.com","tabId":8,"windowId":1,"frameId":0,
            "documentId":Uuid::new_v4().to_string(),"topDocumentId":Uuid::new_v4().to_string(),
            "fieldRole":"password","fieldToken":fallback_field_token,
        });
        let mut fallback_prepare = json!({
            "type":"prepare","operationId":fallback_operation,"applicationId":application_id,
            "connectionId":first_connection,"browserInstanceId":first_browser,
        });
        for (key, value) in fallback_binding.as_object().unwrap() {
            fallback_prepare[key] = value.clone();
        }
        first
            .send(TungsteniteMessage::Text(
                fallback_prepare.to_string().into(),
            ))
            .await
            .unwrap();
        assert_eq!(receive_json(&mut first).await["type"], "prepared");
        let mut fallback_completion = json!({
            "type":"complete","operationId":fallback_operation,"applicationId":application_id,
            "connectionId":first_connection,"browserInstanceId":first_browser,
            "ok":true,"delivered":true,"readback":true,"submitted":false,
        });
        for (key, value) in fallback_binding.as_object().unwrap() {
            fallback_completion[key] = value.clone();
        }
        first
            .send(TungsteniteMessage::Text(
                fallback_completion.to_string().into(),
            ))
            .await
            .unwrap();
        assert_eq!(fallback_task.await.unwrap().status(), StatusCode::OK);

        first.close(None).await.unwrap();
        server.abort();
        let _ = server.await;
    }
}
