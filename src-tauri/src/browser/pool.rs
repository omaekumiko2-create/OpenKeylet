use super::*;

pub(super) fn default_job_kind() -> String {
    "fill_focused".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct BrowserJob {
    pub(super) id: Uuid,
    #[serde(default = "default_job_kind")]
    pub(super) kind: String,
    #[serde(default)]
    pub(super) value: String,
    #[serde(default)]
    pub(super) submit: bool,
    #[serde(default)]
    pub(super) payload: serde_json::Value,
    #[serde(default)]
    pub(super) expires_at: u64,
}

impl BrowserJob {
    #[cfg(test)]
    pub(super) fn with_deadline(id: Uuid, value: String, submit: bool) -> Self {
        Self::action(id, "fill_focused", value, submit, serde_json::Value::Null)
    }

    pub(super) fn action(
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

    pub(super) fn normalize_deadline(&mut self) {
        let now = unix_millis();
        let latest = now.saturating_add(JOB_TIMEOUT.as_millis() as u64);
        if self.expires_at == 0 || self.expires_at > latest {
            self.expires_at = latest;
        }
    }

    pub(super) fn remaining(&self) -> Duration {
        Duration::from_millis(self.expires_at.saturating_sub(unix_millis()))
    }

    pub(super) fn is_expired(&self) -> bool {
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
pub(super) struct PairResponse {
    pub(super) token: String,
    pub(super) port: u16,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct InternalBridgeStatus {
    pub(super) connected_count: usize,
    pub(super) pairing_active: bool,
    #[serde(default)]
    pub(super) extension_version: Option<String>,
    #[serde(default)]
    pub(super) extension_outdated: bool,
    #[serde(default)]
    pub(super) clients: Vec<BridgeClientInfo>,
    #[serde(default)]
    pub(super) last_client_ip: Option<String>,
    #[serde(default)]
    pub(super) last_used_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ExtensionMessage {
    #[serde(default)]
    pub(super) request_id: Option<String>,
    #[serde(default)]
    pub(super) method: String,
    #[serde(default)]
    pub(super) params: serde_json::Value,
    #[serde(rename = "type")]
    pub(super) kind: String,
    #[serde(default)]
    pub(super) token: String,
    #[serde(default)]
    pub(super) extension_version: Option<String>,
    #[serde(default)]
    pub(super) job_id: Option<Uuid>,
    #[serde(default)]
    pub(super) ok: bool,
    #[serde(default)]
    pub(super) message: String,
    #[serde(default)]
    pub(super) data: Option<serde_json::Value>,
}

pub(super) struct PairingWindow {
    pub(super) expires_at: std::time::Instant,
}

#[derive(Clone)]
pub(super) struct ActiveExtension {
    pub(super) id: Uuid,
    pub(super) jobs: mpsc::Sender<BrowserJob>,
}

pub(super) struct ConnectedClient {
    pub(super) jobs: mpsc::Sender<BrowserJob>,
    pub(super) control: mpsc::Sender<String>,
    pub(super) version: Option<String>,
    pub(super) peer_ip: String,
    pub(super) connected_at: String,
    pub(super) last_used_at: String,
}

#[derive(Default)]
pub(super) struct ExtensionPool {
    pub(super) clients: HashMap<Uuid, ConnectedClient>,
    pub(super) active: Option<Uuid>,
    pub(super) last_client_ip: Option<String>,
    pub(super) last_used_at: Option<String>,
}

impl ExtensionPool {
    pub(super) fn add(
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

    pub(super) fn touch(&mut self, id: Uuid) {
        let now = Utc::now().to_rfc3339();
        if let Some(client) = self.clients.get_mut(&id) {
            client.last_used_at = now.clone();
            self.last_client_ip = Some(client.peer_ip.clone());
            self.last_used_at = Some(now);
        }
    }

    pub(super) fn record_claim(&mut self, peer_ip: String) {
        self.last_client_ip = Some(peer_ip);
        self.last_used_at = Some(Utc::now().to_rfc3339());
    }

    pub(super) fn activate(&mut self, id: Uuid) -> bool {
        if self.clients.contains_key(&id) {
            self.active = Some(id);
            self.touch(id);
            true
        } else {
            false
        }
    }

    pub(super) fn remove(&mut self, id: Uuid) {
        self.clients.remove(&id);
        if self.active == Some(id) {
            self.active = self.clients.keys().next().copied();
        }
    }

    pub(super) fn active(&self) -> Option<ActiveExtension> {
        let id = self.active?;
        Some(ActiveExtension {
            id,
            jobs: self.clients.get(&id)?.jobs.clone(),
        })
    }

    pub(super) fn client_infos(&self) -> Vec<BridgeClientInfo> {
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

    pub(super) fn version_summary(&self) -> (Option<String>, bool) {
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

    pub(super) fn control_senders(&self) -> Vec<mpsc::Sender<String>> {
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

pub(super) fn default_bridge_theme() -> String {
    "dark".to_owned()
}

pub(super) fn default_bridge_language() -> String {
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
pub(super) struct AppearancePatch {
    #[serde(default)]
    pub(super) theme: Option<String>,
    #[serde(default)]
    pub(super) language: Option<String>,
}

pub(super) fn normalize_bridge_theme(raw: &str) -> String {
    if raw.trim().eq_ignore_ascii_case("light") {
        "light".to_owned()
    } else {
        "dark".to_owned()
    }
}

pub(super) fn normalize_bridge_language(raw: &str) -> String {
    crate::platform::normalize_language(raw)
}

#[derive(Clone)]
pub(super) struct BridgeServerState {
    pub(super) pin_throttle: Arc<Mutex<std::time::Instant>>,
    pub(super) vault: Vault,
    pub(super) port: u16,
    pub(super) config: BridgeNetworkConfig,
    pub(super) internal_token: String,
    pub(super) extension_token: String,
    pub(super) pairing: Arc<Mutex<Option<PairingWindow>>>,
    pub(super) extensions: Arc<Mutex<ExtensionPool>>,
    pub(super) pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<BrowserFillResult>>>>,
    pub(super) appearance: Arc<Mutex<BridgeAppearance>>,
    pub(super) cancellation: CancellationToken,
    pub(super) on_change: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl BridgeServerState {
    pub(super) fn notify_change(&self) {
        if let Some(callback) = &self.on_change {
            callback();
        }
    }
}

