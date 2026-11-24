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
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
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

const JOB_TIMEOUT: Duration = Duration::from_secs(35);
const EXTENSION_QUEUE_TIMEOUT: Duration = Duration::from_millis(500);
const EXTENSION_RECONNECT_GRACE: Duration = Duration::from_secs(2);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(40);
const HEALTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const PAIRING_WINDOW: Duration = Duration::from_secs(300);
pub(crate) const EXTENSION_ORIGIN: &str = "chrome-extension://knkjojeijgalhpdkfapohofobfomenmi";

const ENV_BRIDGE_BIND: &str = "OPENKEYLET_BRIDGE_BIND";
const LEGACY_ENV_BRIDGE_BIND: &str = "KRU_BRIDGE_BIND";
const ENV_BRIDGE_HOST: &str = "OPENKEYLET_BRIDGE_HOST";
const LEGACY_ENV_BRIDGE_HOST: &str = "KRU_BRIDGE_HOST";
const ENV_BRIDGE_ALLOW_LAN: &str = "OPENKEYLET_BRIDGE_ALLOW_LAN";
const LEGACY_ENV_BRIDGE_ALLOW_LAN: &str = "KRU_BRIDGE_ALLOW_LAN";
const ENV_BRIDGE_ALLOW_IPS: &str = "OPENKEYLET_BRIDGE_ALLOW_IPS";
const LEGACY_ENV_BRIDGE_ALLOW_IPS: &str = "KRU_BRIDGE_ALLOW_IPS";
const ENV_BRIDGE_ALLOWED_ORIGINS: &str = "OPENKEYLET_BRIDGE_ALLOWED_ORIGINS";
const LEGACY_ENV_BRIDGE_ALLOWED_ORIGINS: &str = "KRU_BRIDGE_ALLOWED_ORIGINS";
const ENV_BRIDGE_SCHEME: &str = "OPENKEYLET_BRIDGE_SCHEME";
const LEGACY_ENV_BRIDGE_SCHEME: &str = "KRU_BRIDGE_SCHEME";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
    raw: String,
}

impl IpCidr {
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            bail!("Empty IP allowlist entry");
        }
        let (ip_str, prefix_opt) = match trimmed.split_once('/') {
            Some((ip, prefix)) => (ip.trim(), Some(prefix.trim())),
            None => (trimmed, None),
        };
        let ip: IpAddr = ip_str
            .parse()
            .with_context(|| format!("Invalid IP address in allowlist: '{trimmed}'"))?;
        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = match prefix_opt {
            Some(p) => {
                let value: u8 = p
                    .parse()
                    .with_context(|| format!("Invalid CIDR prefix in allowlist: '{trimmed}'"))?;
                if value > max_prefix {
                    bail!("CIDR prefix out of range in allowlist: '{trimmed}'");
                }
                value
            }
            None => max_prefix,
        };
        Ok(Self {
            network: ip,
            prefix,
            raw: trimmed.to_owned(),
        })
    }

    pub fn contains(&self, candidate: IpAddr) -> bool {
        let candidate = normalize_ip(candidate);
        let network = normalize_ip(self.network);
        match (network, candidate) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u32::MAX.checked_shl(32 - u32::from(self.prefix)).unwrap_or(0);
                (u32::from(net) & mask) == (u32::from(addr) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                (u128::from(net) & mask) == (u128::from(addr) & mask)
            }
            _ => false,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

#[derive(Debug, Clone)]
pub struct BridgeNetworkConfig {
    pub bind_ip: IpAddr,
    pub advertised_host: String,
    pub scheme: String,
    pub allow_lan: bool,
    pub ip_allowlist: Vec<IpCidr>,
    pub allowed_origins: Vec<String>,
}

impl Default for BridgeNetworkConfig {
    fn default() -> Self {
        Self {
            bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            advertised_host: "127.0.0.1".to_owned(),
            scheme: "ws".to_owned(),
            allow_lan: false,
            ip_allowlist: Vec::new(),
            allowed_origins: vec![EXTENSION_ORIGIN.to_owned()],
        }
    }
}

fn read_env_with_legacy(primary: &str, legacy: &str) -> Option<String> {
    std::env::var(primary)
        .ok()
        .or_else(|| std::env::var(legacy).ok())
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

fn parse_bool_flag(value: Option<&str>) -> bool {
    value.is_some_and(|raw| {
        matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn validate_allowed_origin(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() || trimmed.contains('*') || trimmed.chars().any(char::is_whitespace) {
        bail!("Invalid allowed origin: '{raw}' (wildcards and whitespace are not permitted)");
    }
    let parsed = url::Url::parse(trimmed)
        .with_context(|| format!("Invalid allowed origin URL: '{raw}'"))?;
    match parsed.scheme() {
        "chrome-extension" | "moz-extension" | "https" | "http" => {}
        other => bail!("Unsupported origin scheme '{other}' in '{raw}'"),
    }
    if parsed.host_str().is_none()
        || !matches!(parsed.path(), "" | "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        bail!("Allowed origin must be an origin without path, query, or fragment: '{raw}'");
    }
    Ok(trimmed.to_owned())
}

fn format_url_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

impl BridgeNetworkConfig {
    pub fn from_env() -> Result<Self> {
        let bind = read_env_with_legacy(ENV_BRIDGE_BIND, LEGACY_ENV_BRIDGE_BIND);
        let host = read_env_with_legacy(ENV_BRIDGE_HOST, LEGACY_ENV_BRIDGE_HOST);
        let allow_lan = read_env_with_legacy(ENV_BRIDGE_ALLOW_LAN, LEGACY_ENV_BRIDGE_ALLOW_LAN);
        let allow_ips = read_env_with_legacy(ENV_BRIDGE_ALLOW_IPS, LEGACY_ENV_BRIDGE_ALLOW_IPS);
        let allowed_origins = read_env_with_legacy(
            ENV_BRIDGE_ALLOWED_ORIGINS,
            LEGACY_ENV_BRIDGE_ALLOWED_ORIGINS,
        );
        let scheme = read_env_with_legacy(ENV_BRIDGE_SCHEME, LEGACY_ENV_BRIDGE_SCHEME);
        Self::from_values(
            bind.as_deref(),
            host.as_deref(),
            allow_lan.as_deref(),
            allow_ips.as_deref(),
            allowed_origins.as_deref(),
            scheme.as_deref(),
        )
    }

    pub fn from_values(
        bind: Option<&str>,
        host: Option<&str>,
        allow_lan_flag: Option<&str>,
        allow_ips_csv: Option<&str>,
        allowed_origins_csv: Option<&str>,
        scheme: Option<&str>,
    ) -> Result<Self> {
        let bind_ip: IpAddr = match bind.map(str::trim).filter(|s| !s.is_empty()) {
            Some(raw) => raw
                .parse()
                .with_context(|| format!("Invalid {ENV_BRIDGE_BIND} IP address: '{raw}'"))?,
            None => IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        let allow_lan = parse_bool_flag(allow_lan_flag);
        if !bind_ip.is_loopback() && !allow_lan {
            bail!(
                "Refusing to bind Browser Bridge on non-loopback address {bind_ip} without explicit opt-in. Set {ENV_BRIDGE_ALLOW_LAN}=1 (and ideally {ENV_BRIDGE_ALLOW_IPS}=<client-ip>) to acknowledge that Browser Bridge exposes credential-filling over the network."
            );
        }

        let advertised_host = match host.map(str::trim).filter(|s| !s.is_empty()) {
            Some(h) => {
                if h.chars().any(char::is_whitespace) || h.contains('/') || h.contains('@') {
                    bail!("Invalid {ENV_BRIDGE_HOST}: '{h}'");
                }
                h.to_owned()
            }
            None => {
                if bind_ip.is_unspecified() {
                    match bind_ip {
                        IpAddr::V4(_) => "127.0.0.1".to_owned(),
                        IpAddr::V6(_) => "::1".to_owned(),
                    }
                } else {
                    bind_ip.to_string()
                }
            }
        };

        let scheme = match scheme.map(str::trim).filter(|s| !s.is_empty()) {
            None => "ws".to_owned(),
            Some(s) if s.eq_ignore_ascii_case("ws") => "ws".to_owned(),
            Some(s) if s.eq_ignore_ascii_case("wss") => "wss".to_owned(),
            Some(other) => bail!("Invalid {ENV_BRIDGE_SCHEME} '{other}'; expected 'ws' or 'wss'"),
        };

        let mut ip_allowlist = Vec::new();
        if let Some(csv) = allow_ips_csv {
            for entry in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                ip_allowlist.push(IpCidr::parse(entry)?);
            }
        }

        let mut allowed_origins = vec![EXTENSION_ORIGIN.to_owned()];
        if let Some(csv) = allowed_origins_csv {
            for entry in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let normalized = validate_allowed_origin(entry)?;
                if !allowed_origins.iter().any(|existing| existing == &normalized) {
                    allowed_origins.push(normalized);
                }
            }
        }

        Ok(Self {
            bind_ip,
            advertised_host,
            scheme,
            allow_lan: !bind_ip.is_loopback(),
            ip_allowlist,
            allowed_origins,
        })
    }

    pub fn is_lan_mode(&self) -> bool {
        !self.bind_ip.is_loopback()
    }

    pub fn bind_addr(&self, port: u16) -> SocketAddr {
        SocketAddr::new(self.bind_ip, port)
    }

    /// Address OpenKeylet itself uses when making internal HTTP calls to its own bridge.
    /// Correctly maps unspecified bind addresses (`0.0.0.0`, `::`) to loopback.
    pub fn internal_host(&self) -> IpAddr {
        if self.bind_ip.is_unspecified() {
            match self.bind_ip {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            }
        } else {
            self.bind_ip
        }
    }

    pub fn internal_http_url(&self, port: u16, path: &str) -> String {
        let host = format_url_host(&self.internal_host().to_string());
        let suffix = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        format!("http://{host}:{port}{suffix}")
    }

    pub fn advertised_endpoint(&self, port: u16) -> String {
        let host = format_url_host(&self.advertised_host);
        format!("{}://{host}:{port}/extension", self.scheme)
    }

    pub fn allows_peer(&self, peer: IpAddr) -> bool {
        let peer = normalize_ip(peer);
        if peer.is_loopback() {
            return true;
        }
        if !self.is_lan_mode() {
            return false;
        }
        if self.ip_allowlist.is_empty() {
            return true;
        }
        self.ip_allowlist.iter().any(|cidr| cidr.contains(peer))
    }

    pub fn allows_internal_peer(&self, peer: IpAddr) -> bool {
        let peer = normalize_ip(peer);
        peer.is_loopback() || peer == normalize_ip(self.bind_ip)
    }

    pub fn allows_origin(&self, origin: &str) -> bool {
        let trimmed = origin.trim().trim_end_matches('/');
        !trimmed.is_empty() && self.allowed_origins.iter().any(|allowed| allowed == trimmed)
    }

    pub fn ip_allowlist_strings(&self) -> Vec<String> {
        self.ip_allowlist
            .iter()
            .map(|c| c.as_str().to_owned())
            .collect()
    }
}

fn log_bridge_event(event: &str, peer: Option<IpAddr>, detail: &str) {
    let ts = Utc::now().to_rfc3339();
    match peer {
        Some(ip) => eprintln!("OpenKeylet Browser Bridge [{ts}] event={event} peer={ip} {detail}"),
        None => eprintln!("OpenKeylet Browser Bridge [{ts}] event={event} {detail}"),
    }
}

fn default_job_kind() -> String {
    "fill_focused".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserJob {
    id: Uuid,
    #[serde(default = "default_job_kind")]
    kind: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    submit: bool,
    #[serde(default)]
    payload: serde_json::Value,
    #[serde(default)]
    expires_at: u64,
}

impl BrowserJob {
    #[cfg(test)]
    fn with_deadline(id: Uuid, value: String, submit: bool) -> Self {
        Self::action(id, "fill_focused", value, submit, serde_json::Value::Null)
    }

    fn action(
        id: Uuid,
        kind: &str,
        value: String,
        submit: bool,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            id,
            kind: kind.to_owned(),
            value,
            submit,
            payload,
            expires_at: unix_millis().saturating_add(JOB_TIMEOUT.as_millis() as u64),
        }
    }

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
#[serde(rename_all = "camelCase")]
pub struct BrowserFillResult {
    pub status: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairResponse {
    token: String,
    port: u16,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InternalBridgeStatus {
    connected_count: usize,
    pairing_active: bool,
    #[serde(default)]
    extension_version: Option<String>,
    #[serde(default)]
    extension_outdated: bool,
    #[serde(default)]
    clients: Vec<BridgeClientInfo>,
    #[serde(default)]
    last_client_ip: Option<String>,
    #[serde(default)]
    last_used_at: Option<String>,
}

#[derive(Debug, Deserialize)]
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
    extension_version: Option<String>,
    #[serde(default)]
    job_id: Option<Uuid>,
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    message: String,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

struct PairingWindow {
    expires_at: std::time::Instant,
}

#[derive(Clone)]
struct ActiveExtension {
    id: Uuid,
    jobs: mpsc::Sender<BrowserJob>,
}

struct ConnectedClient {
    jobs: mpsc::Sender<BrowserJob>,
    control: mpsc::Sender<String>,
    version: Option<String>,
    peer_ip: String,
    connected_at: String,
    last_used_at: String,
}

#[derive(Default)]
struct ExtensionPool {
    clients: HashMap<Uuid, ConnectedClient>,
    active: Option<Uuid>,
    last_client_ip: Option<String>,
    last_used_at: Option<String>,
}

impl ExtensionPool {
    fn add(
        &mut self,
        id: Uuid,
        jobs: mpsc::Sender<BrowserJob>,
        control: mpsc::Sender<String>,
        version: Option<String>,
        peer_ip: String,
    ) {
        let now = Utc::now().to_rfc3339();
        self.last_client_ip = Some(peer_ip.clone());
        self.last_used_at = Some(now.clone());
        self.clients.insert(
            id,
            ConnectedClient {
                jobs,
                control,
                version,
                peer_ip,
                connected_at: now.clone(),
                last_used_at: now,
            },
        );
        if self.active.is_none() {
            self.active = Some(id);
        }
    }

    fn touch(&mut self, id: Uuid) {
        let now = Utc::now().to_rfc3339();
        if let Some(client) = self.clients.get_mut(&id) {
            client.last_used_at = now.clone();
            self.last_client_ip = Some(client.peer_ip.clone());
            self.last_used_at = Some(now);
        }
    }

    fn record_claim(&mut self, peer_ip: String) {
        self.last_client_ip = Some(peer_ip);
        self.last_used_at = Some(Utc::now().to_rfc3339());
    }

    fn activate(&mut self, id: Uuid) -> bool {
        if self.clients.contains_key(&id) {
            self.active = Some(id);
            self.touch(id);
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
        Some(ActiveExtension {
            id,
            jobs: self.clients.get(&id)?.jobs.clone(),
        })
    }

    fn client_infos(&self) -> Vec<BridgeClientInfo> {
        let mut list: Vec<BridgeClientInfo> = self
            .clients
            .values()
            .map(|c| BridgeClientInfo {
                peer_ip: c.peer_ip.clone(),
                connected_at: c.connected_at.clone(),
                last_used_at: c.last_used_at.clone(),
                extension_version: c.version.clone(),
            })
            .collect();
        list.sort_by(|a, b| a.connected_at.cmp(&b.connected_at));
        list
    }

    fn version_summary(&self) -> (Option<String>, bool) {
        let app_version = env!("CARGO_PKG_VERSION");
        let mut reported: Option<String> = None;
        for client in self.clients.values() {
            if let Some(ver) = &client.version {
                if ver != app_version {
                    return (Some(ver.clone()), true);
                }
                if reported.is_none() {
                    reported = Some(ver.clone());
                }
            }
        }
        (reported, false)
    }

    fn control_senders(&self) -> Vec<mpsc::Sender<String>> {
        self.clients.values().map(|c| c.control.clone()).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BridgeAppearance {
    #[serde(default = "default_bridge_theme")]
    pub theme: String,
    #[serde(default = "default_bridge_language")]
    pub language: String,
}

fn default_bridge_theme() -> String {
    "dark".to_owned()
}

fn default_bridge_language() -> String {
    "auto".to_owned()
}

impl Default for BridgeAppearance {
    fn default() -> Self {
        Self {
            theme: default_bridge_theme(),
            language: default_bridge_language(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppearancePatch {
    #[serde(default)]
    theme: Option<String>,
    #[serde(default)]
    language: Option<String>,
}

fn normalize_bridge_theme(raw: &str) -> String {
    if raw.trim().eq_ignore_ascii_case("light") {
        "light".to_owned()
    } else {
        "dark".to_owned()
    }
}

fn normalize_bridge_language(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "auto".to_owned();
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower == "auto" || lower == "system" {
        return "auto".to_owned();
    }
    if matches!(
        lower.as_str(),
        "zh-tw" | "zh_tw" | "zh-hk" | "zh_hk" | "zh-hant" | "zh_hant"
    ) || lower.starts_with("zh-tw")
        || lower.starts_with("zh_tw")
        || lower.starts_with("zh-hk")
        || lower.starts_with("zh_hk")
        || lower.starts_with("zh-hant")
        || lower.starts_with("zh_hant")
    {
        return "zh-TW".to_owned();
    }
    if lower == "zh" || lower.starts_with("zh-") || lower.starts_with("zh_") {
        return "zh".to_owned();
    }
    if lower == "ja" || lower.starts_with("ja-") || lower.starts_with("ja_") {
        return "ja".to_owned();
    }
    if lower == "ko" || lower.starts_with("ko-") || lower.starts_with("ko_") {
        return "ko".to_owned();
    }
    if lower == "es" || lower.starts_with("es-") || lower.starts_with("es_") {
        return "es".to_owned();
    }
    if lower == "en" || lower.starts_with("en-") || lower.starts_with("en_") {
        return "en".to_owned();
    }
    "auto".to_owned()
}

#[derive(Clone)]
struct BridgeServerState {
    pin_throttle: Arc<Mutex<std::time::Instant>>,
    vault: Vault,
    port: u16,
    config: BridgeNetworkConfig,
    internal_token: String,
    extension_token: String,
    pairing: Arc<Mutex<Option<PairingWindow>>>,
    extensions: Arc<Mutex<ExtensionPool>>,
    pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<BrowserFillResult>>>>,
    appearance: Arc<Mutex<BridgeAppearance>>,
    cancellation: CancellationToken,
    on_change: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl BridgeServerState {
    fn notify_change(&self) {
        if let Some(callback) = &self.on_change {
            callback();
        }
    }
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

fn require_allowed_peer(
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

fn require_internal_peer(
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

async fn health(
    State(state): State<BridgeServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<&'static str, (StatusCode, String)> {
    require_allowed_peer(&state.config, peer.ip(), "/health")?;
    Ok("OpenKeylet Browser Bridge")
}

async fn internal_health(
    State(state): State<BridgeServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<&'static str, (StatusCode, String)> {
    require_internal_peer(&state.config, peer.ip(), "/internal/health")?;
    require_bearer(&headers, &state.internal_token)?;
    Ok("ok")
}

async fn internal_ready(
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

async fn internal_status(
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

async fn reload_extensions_route(
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

async fn sync_appearance_route(
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

async fn create_quick_pair(
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

async fn claim(
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

async fn submit_job(
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

async fn deliver_to_extension_with_grace(state: &BridgeServerState, job: &BrowserJob) -> bool {
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

async fn deliver_to_extension(state: &BridgeServerState, job: &BrowserJob) -> bool {
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

async fn job_is_deliverable(state: &BridgeServerState, job: &BrowserJob) -> bool {
    !job.is_expired() && state.pending.lock().await.contains_key(&job.id)
}

async fn reset_pairing(
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

async fn extension_upgrade(
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

fn constant_time_eq(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && subtle::ConstantTimeEq::ct_eq(left.as_bytes(), right.as_bytes()).into()
}

async fn extension_socket(socket: WebSocket, state: BridgeServerState, peer_ip: IpAddr) {
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
                            let result = crate::browser_vault::handle(&state.vault, &mut browser_session, &state.pin_throttle, &message.method, &message.params).await;
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

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn current_totp(secret: &str) -> Result<String> {
    let (code, _, _) = current_totp_details(secret)?;
    Ok(code)
}

pub fn current_totp_details(secret: &str) -> Result<(String, u64, u64)> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Invalid system time")?
        .as_secs();
    totp_details_at(secret, timestamp)
}

#[cfg(test)]
fn totp_at(secret: &str, timestamp: u64) -> Result<String> {
    let (code, _, _) = totp_details_at(secret, timestamp)?;
    Ok(code)
}

fn totp_details_at(secret: &str, timestamp: u64) -> Result<(String, u64, u64)> {
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
    let code = format!("{:0digits$}", value % 10u32.pow(digits as u32));
    let remaining = period - (timestamp % period);
    Ok((code, remaining, period))
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
    use tempfile::tempdir;

    #[test]
    fn otpauth_uses_rfc6238_algorithms_digits_and_period() {
        let base32 = |bytes: &[u8]| {
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let (mut buffer, mut bits, mut result) = (0u32, 0u32, String::new());
            for byte in bytes {
                buffer = (buffer << 8) | u32::from(*byte);
                bits += 8;
                while bits >= 5 {
                    bits -= 5;
                    result.push(alphabet[((buffer >> bits) & 31) as usize] as char);
                }
                buffer &= (1 << bits) - 1;
            }
            if bits > 0 {
                result.push(alphabet[((buffer << (5 - bits)) & 31) as usize] as char);
            }
            result
        };
        for (algorithm, seed, expected) in [
            ("SHA1", "12345678901234567890", "94287082"),
            ("SHA256", "12345678901234567890123456789012", "46119246"),
            (
                "SHA512",
                "1234567890123456789012345678901234567890123456789012345678901234",
                "90693936",
            ),
        ] {
            let uri = format!(
                "otpauth://totp/Example?secret={}&algorithm={algorithm}&digits=8&period=30",
                base32(seed.as_bytes())
            );
            assert_eq!(totp_at(&uri, 59).unwrap(), expected);
            assert_eq!(
                totp_at(&uri.replace("period=30", "period=60"), 119).unwrap(),
                expected
            );
        }
        assert!(current_totp("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&period=0").is_err());
        assert!(current_totp("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&digits=99").is_err());
    }

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
    fn totp_matches_rfc_vector_truncated_to_six_digits() {
        assert_eq!(
            totp_at("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap(),
            "287082"
        );
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
}
