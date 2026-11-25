use crate::{
    model::{BridgeClientInfo, BrowserBridgeState},
    vault::Vault,
};
use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{
        ConnectInfo, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, Method, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
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
use tower_http::cors::{AllowOrigin, CorsLayer};
use uuid::Uuid;

mod net_config;
mod pool;
mod server;
pub mod vault_rpc;

pub use net_config::{BridgeNetworkConfig, IpCidr};
pub use pool::{BridgeAppearance, BrowserFillResult};
use net_config::*;
use pool::*;
use server::*;

const JOB_TIMEOUT: Duration = Duration::from_secs(35);
const EXTENSION_QUEUE_TIMEOUT: Duration = Duration::from_millis(500);
const EXTENSION_RECONNECT_GRACE: Duration = Duration::from_secs(2);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(40);
const HEALTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const PAIRING_WINDOW: Duration = Duration::from_secs(300);
pub(crate) const EXTENSION_ORIGIN: &str = "chrome-extension://knkjojeijgalhpdkfapohofobfomenmi";

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
    appearance: Arc<Mutex<BridgeAppearance>>,
    client: reqwest::Client,
    network_override: Option<BridgeNetworkConfig>,
    on_change: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl BrowserBridge {
    pub fn new(vault: Vault) -> Self {
        Self::build(vault, None, None)
    }

    pub fn with_on_change(vault: Vault, on_change: impl Fn() + Send + Sync + 'static) -> Self {
        Self::build(vault, None, Some(Arc::new(on_change)))
    }

    #[cfg(test)]
    pub fn with_network_config(vault: Vault, config: BridgeNetworkConfig) -> Self {
        Self::build(vault, Some(config), None)
    }

    fn build(
        vault: Vault,
        network_override: Option<BridgeNetworkConfig>,
        on_change: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Self {
        let initial_language = vault
            .settings()
            .map(|s| normalize_bridge_language(&s.language))
            .unwrap_or_else(|_| default_bridge_language());
        Self {
            vault,
            runtime: Arc::new(Mutex::new(Runtime::default())),
            appearance: Arc::new(Mutex::new(BridgeAppearance {
                theme: default_bridge_theme(),
                language: initial_language,
            })),
            client: reqwest::Client::builder()
                .timeout(HTTP_REQUEST_TIMEOUT)
                .connect_timeout(Duration::from_secs(2))
                .build()
                .expect("reqwest client configuration must be valid"),
            network_override,
            on_change,
        }
    }

    pub fn network_config(&self) -> Result<BridgeNetworkConfig> {
        match &self.network_override {
            Some(cfg) => Ok(cfg.clone()),
            None => BridgeNetworkConfig::from_env(),
        }
    }

    fn bridge_http_url(&self, config: &BridgeNetworkConfig, port: u16, path: &str) -> String {
        config.internal_http_url(port, path)
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
        let (status, mut error) = {
            let runtime = self.runtime.lock().await;
            (runtime.status.clone(), runtime.error.clone())
        };
        let config = match self.network_config() {
            Ok(cfg) => cfg,
            Err(cfg_err) => {
                if error.is_empty() {
                    error = cfg_err.to_string();
                }
                BridgeNetworkConfig::default()
            }
        };
        let live = if settings.browser_enabled && matches!(status.as_str(), "listening" | "delegated")
        {
            self.probe_bridge_status(&config, settings.browser_port)
                .await
        } else {
            InternalBridgeStatus::default()
        };
        let connected = settings.browser_enabled
            && settings.browser_paired
            && live.connected_count > 0;
        BrowserBridgeState {
            enabled: settings.browser_enabled,
            paired: settings.browser_paired,
            connected,
            connected_count: if connected { live.connected_count } else { 0 },
            pairing_active: live.pairing_active,
            status,
            error,
            endpoint: config.advertised_endpoint(settings.browser_port),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            extension_version: if connected {
                live.extension_version
            } else {
                None
            },
            extension_outdated: connected && live.extension_outdated,
            bind_address: config.bind_addr(settings.browser_port).to_string(),
            lan_mode: config.is_lan_mode(),
            ip_allowlist: config.ip_allowlist_strings(),
            allowed_origins: config.allowed_origins.clone(),
            clients: if connected { live.clients } else { Vec::new() },
            last_client_ip: live.last_client_ip,
            last_used_at: live.last_used_at,
        }
    }

    pub fn fill_configured(&self) -> bool {
        self.vault
            .settings()
            .is_ok_and(|settings| settings.browser_enabled && settings.browser_paired)
    }

    pub async fn probe_live_status(&self) -> Result<BrowserBridgeState> {
        let settings = self.vault.settings()?;
        let config = self.network_config()?;
        let live = if settings.browser_enabled {
            self.probe_bridge_status(&config, settings.browser_port)
                .await
        } else {
            InternalBridgeStatus::default()
        };
        let connected = settings.browser_enabled
            && settings.browser_paired
            && live.connected_count > 0;
        let runtime_state = self.runtime.lock().await;
        let status = if !settings.browser_enabled {
            "off".to_owned()
        } else if runtime_state.status != "off" {
            runtime_state.status.clone()
        } else if live.connected_count > 0 || live.pairing_active || live.last_used_at.is_some() {
            "delegated".to_owned()
        } else {
            let alive = self
                .client
                .get(self.bridge_http_url(&config, settings.browser_port, "/internal/health"))
                .bearer_auth(self.internal_token().unwrap_or_default())
                .timeout(HEALTH_REQUEST_TIMEOUT)
                .send()
                .await
                .is_ok_and(|r| r.status().is_success());
            if alive {
                "delegated".to_owned()
            } else {
                "off".to_owned()
            }
        };
        let error = runtime_state.error.clone();
        drop(runtime_state);
        Ok(BrowserBridgeState {
            enabled: settings.browser_enabled,
            paired: settings.browser_paired,
            connected,
            connected_count: if connected { live.connected_count } else { 0 },
            pairing_active: live.pairing_active,
            status,
            error,
            endpoint: config.advertised_endpoint(settings.browser_port),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            extension_version: if connected {
                live.extension_version
            } else {
                None
            },
            extension_outdated: connected && live.extension_outdated,
            bind_address: config.bind_addr(settings.browser_port).to_string(),
            lan_mode: config.is_lan_mode(),
            ip_allowlist: config.ip_allowlist_strings(),
            allowed_origins: config.allowed_origins.clone(),
            clients: if connected { live.clients } else { Vec::new() },
            last_client_ip: live.last_client_ip,
            last_used_at: live.last_used_at,
        })
    }

    async fn probe_bridge_status(
        &self,
        config: &BridgeNetworkConfig,
        port: u16,
    ) -> InternalBridgeStatus {
        let token = self.internal_token().unwrap_or_default();
        if let Ok(response) = self
            .client
            .get(self.bridge_http_url(config, port, "/internal/status"))
            .bearer_auth(&token)
            .timeout(HEALTH_REQUEST_TIMEOUT)
            .send()
            .await
            && response.status().is_success()
            && let Ok(parsed) = response.json::<InternalBridgeStatus>().await
        {
            return parsed;
        }
        let ready = self
            .client
            .get(self.bridge_http_url(config, port, "/internal/ready"))
            .bearer_auth(token)
            .timeout(HEALTH_REQUEST_TIMEOUT)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success());
        InternalBridgeStatus {
            connected_count: usize::from(ready),
            ..InternalBridgeStatus::default()
        }
    }

    pub async fn sync_appearance(&self, theme: Option<String>, language: Option<String>) {
        let snapshot = {
            let mut guard = self.appearance.lock().await;
            if let Some(next_theme) = theme {
                guard.theme = normalize_bridge_theme(&next_theme);
            }
            if let Some(next_lang) = language {
                guard.language = normalize_bridge_language(&next_lang);
            }
            guard.clone()
        };
        let Ok(settings) = self.vault.settings() else {
            return;
        };
        if !settings.browser_enabled {
            return;
        }
        let active = {
            let runtime = self.runtime.lock().await;
            matches!(runtime.status.as_str(), "listening" | "delegated")
        };
        if !active {
            return;
        }
        let Ok(config) = self.network_config() else {
            return;
        };
        let Ok(token) = self.internal_token() else {
            return;
        };
        let _ = self
            .client
            .post(self.bridge_http_url(&config, settings.browser_port, "/internal/appearance"))
            .bearer_auth(token)
            .timeout(HEALTH_REQUEST_TIMEOUT)
            .json(&snapshot)
            .send()
            .await;
    }

    pub async fn reload_extensions(&self) -> Result<usize> {
        let settings = self.vault.settings()?;
        if !settings.browser_enabled {
            bail!("Enable Browser Bridge first");
        }
        let config = self.network_config()?;
        self.ensure_started(settings.browser_port).await?;
        let response = self
            .client
            .post(self.bridge_http_url(&config, settings.browser_port, "/internal/reload-extensions"))
            .bearer_auth(self.internal_token()?)
            .timeout(HEALTH_REQUEST_TIMEOUT)
            .send()
            .await
            .context("Unable to signal browser extension reload")?;
        if !response.status().is_success() {
            bail!("Browser Bridge rejected extension reload");
        }
        let body: serde_json::Value = response.json().await.unwrap_or_default();
        Ok(body.get("reloaded").and_then(|v| v.as_u64()).unwrap_or(0) as usize)
    }

    pub async fn start_quick_pairing(&self) -> Result<()> {
        let settings = self.vault.settings()?;
        if !settings.browser_enabled {
            bail!("Enable Browser Bridge first");
        }
        let config = self.network_config()?;
        self.ensure_started(settings.browser_port).await?;
        let response = self
            .client
            .post(self.bridge_http_url(&config, settings.browser_port, "/internal/quick-pair"))
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
        let config = self.network_config()?;
        self.ensure_started(settings.browser_port).await?;
        let response = self
            .client
            .post(self.bridge_http_url(&config, settings.browser_port, "/internal/reset"))
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

    pub async fn fill_value(&self, value: String, submit: bool) -> Result<BrowserFillResult> {
        self.execute_job("fill_focused", value, submit, serde_json::Value::Null)
            .await
    }

    pub async fn execute_job(
        &self,
        kind: &str,
        value: String,
        submit: bool,
        payload: serde_json::Value,
    ) -> Result<BrowserFillResult> {
        let settings = self.vault.settings()?;
        if !settings.browser_enabled {
            bail!("Browser Bridge is not enabled");
        }
        if !settings.browser_paired {
            bail!("Chromium extension has not been paired");
        }
        let config = self.network_config()?;
        self.ensure_started(settings.browser_port).await?;
        let job = BrowserJob::action(Uuid::new_v4(), kind, value, submit, payload);
        let response = self
            .client
            .post(self.bridge_http_url(&config, settings.browser_port, "/internal/jobs"))
            .bearer_auth(self.internal_token()?)
            .json(&job)
            .send()
            .await
            .context("Unable to submit browser task")?;
        if !response.status().is_success() {
            bail!(
                "Browser operation failed: {}",
                response.text().await.unwrap_or_default()
            );
        }
        response
            .json()
            .await
            .context("Invalid browser result format")
    }

    pub async fn inspect_page(
        &self,
        tab_id: Option<i64>,
        url: Option<&str>,
    ) -> Result<serde_json::Value> {
        let result = self
            .execute_job(
                "inspect_page",
                String::new(),
                false,
                serde_json::json!({
                    "tabId": tab_id,
                    "url": url,
                }),
            )
            .await?;
        Ok(result.data.unwrap_or_else(|| serde_json::json!({})))
    }

    pub async fn fill_login(&self, payload: serde_json::Value) -> Result<BrowserFillResult> {
        self.execute_job("fill_login", String::new(), false, payload)
            .await
    }

    pub async fn fill_field(
        &self,
        value: String,
        submit: bool,
        payload: serde_json::Value,
    ) -> Result<BrowserFillResult> {
        self.execute_job("fill_field", value, submit, payload).await
    }

    pub async fn fill_personal(&self, payload: serde_json::Value) -> Result<BrowserFillResult> {
        self.execute_job("fill_personal", String::new(), false, payload)
            .await
    }

    pub async fn click(&self, payload: serde_json::Value) -> Result<BrowserFillResult> {
        self.execute_job("click", String::new(), false, payload)
            .await
    }

    pub async fn open_tab(&self, payload: serde_json::Value) -> Result<BrowserFillResult> {
        self.execute_job("open_tab", String::new(), false, payload)
            .await
    }

    pub async fn passkey_capture(&self, payload: serde_json::Value) -> Result<serde_json::Value> {
        let result = self
            .execute_job("passkey_capture", String::new(), false, payload)
            .await?;
        result
            .data
            .context("Browser extension did not return passkey request details")
    }

    pub async fn passkey_resolve(&self, payload: serde_json::Value) -> Result<BrowserFillResult> {
        self.execute_job("passkey_resolve", String::new(), false, payload)
            .await
    }

    async fn ensure_started(&self, port: u16) -> Result<()> {
        let config = self.network_config()?;
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
                .get(self.bridge_http_url(&config, port, "/internal/health"))
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
        let bind_addr = config.bind_addr(port);
        match TcpListener::bind(bind_addr).await {
            Ok(listener) => {
                if config.is_lan_mode() {
                    log_bridge_event(
                        "lan_listening",
                        None,
                        &format!(
                            "bind={bind_addr} advertised={} allowlist_entries={} allowed_origins={} WARNING: non-loopback mode exposes credential-filling over the network",
                            config.advertised_endpoint(port),
                            config.ip_allowlist.len(),
                            config.allowed_origins.len()
                        ),
                    );
                }
                let cancellation = CancellationToken::new();
                let cors_origins = Arc::new(config.allowed_origins.clone());
                let state = BridgeServerState {
                    pin_throttle: Arc::new(Mutex::new(std::time::Instant::now())),
                    vault: self.vault.clone(),
                    port,
                    config: config.clone(),
                    internal_token,
                    extension_token,
                    pairing: Arc::new(Mutex::new(None)),
                    extensions: Arc::new(Mutex::new(ExtensionPool::default())),
                    pending: Arc::new(Mutex::new(HashMap::new())),
                    appearance: Arc::clone(&self.appearance),
                    cancellation: cancellation.clone(),
                    on_change: self.on_change.clone(),
                };
                let router = Router::new()
                    .route("/health", get(health))
                    .route("/claim", post(claim))
                    .route("/extension", get(extension_upgrade))
                    .route("/internal/health", get(internal_health))
                    .route("/internal/ready", get(internal_ready))
                    .route("/internal/status", get(internal_status))
                    .route("/internal/quick-pair", post(create_quick_pair))
                    .route("/internal/jobs", post(submit_job))
                    .route("/internal/reload-extensions", post(reload_extensions_route))
                    .route("/internal/appearance", post(sync_appearance_route))
                    .route("/internal/reset", post(reset_pairing))
                    .layer(
                        CorsLayer::new()
                            .allow_origin(AllowOrigin::predicate(move |origin, _| {
                                origin.to_str().is_ok_and(|raw| {
                                    let trimmed = raw.trim().trim_end_matches('/');
                                    cors_origins.iter().any(|allowed| allowed == trimmed)
                                })
                            }))
                            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
                            .allow_methods([Method::GET, Method::POST]),
                    )
                    .with_state(state);
                let child_cancellation = cancellation.clone();
                let task = tokio::spawn(async move {
                    let _ = axum::serve(
                        listener,
                        router.into_make_service_with_connect_info::<SocketAddr>(),
                    )
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
                    .get(self.bridge_http_url(&config, port, "/internal/health"))
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
}


#[cfg(test)]
mod tests;
