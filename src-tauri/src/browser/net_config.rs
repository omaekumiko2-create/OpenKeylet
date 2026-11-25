use super::*;

pub(super) const ENV_BRIDGE_BIND: &str = "OPENKEYLET_BRIDGE_BIND";
pub(super) const LEGACY_ENV_BRIDGE_BIND: &str = "KRU_BRIDGE_BIND";
pub(super) const ENV_BRIDGE_HOST: &str = "OPENKEYLET_BRIDGE_HOST";
pub(super) const LEGACY_ENV_BRIDGE_HOST: &str = "KRU_BRIDGE_HOST";
pub(super) const ENV_BRIDGE_ALLOW_LAN: &str = "OPENKEYLET_BRIDGE_ALLOW_LAN";
pub(super) const LEGACY_ENV_BRIDGE_ALLOW_LAN: &str = "KRU_BRIDGE_ALLOW_LAN";
pub(super) const ENV_BRIDGE_ALLOW_IPS: &str = "OPENKEYLET_BRIDGE_ALLOW_IPS";
pub(super) const LEGACY_ENV_BRIDGE_ALLOW_IPS: &str = "KRU_BRIDGE_ALLOW_IPS";
pub(super) const ENV_BRIDGE_ALLOWED_ORIGINS: &str = "OPENKEYLET_BRIDGE_ALLOWED_ORIGINS";
pub(super) const LEGACY_ENV_BRIDGE_ALLOWED_ORIGINS: &str = "KRU_BRIDGE_ALLOWED_ORIGINS";
pub(super) const ENV_BRIDGE_SCHEME: &str = "OPENKEYLET_BRIDGE_SCHEME";
pub(super) const LEGACY_ENV_BRIDGE_SCHEME: &str = "KRU_BRIDGE_SCHEME";

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

pub(super) fn normalize_ip(ip: IpAddr) -> IpAddr {
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

pub(super) fn read_env_with_legacy(primary: &str, legacy: &str) -> Option<String> {
    std::env::var(primary)
        .ok()
        .or_else(|| std::env::var(legacy).ok())
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

pub(super) fn parse_bool_flag(value: Option<&str>) -> bool {
    value.is_some_and(|raw| {
        matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

pub(super) fn validate_allowed_origin(raw: &str) -> Result<String> {
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

pub(super) fn format_url_host(host: &str) -> String {
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

pub(super) fn log_bridge_event(event: &str, peer: Option<IpAddr>, detail: &str) {
    let ts = Utc::now().to_rfc3339();
    match peer {
        Some(ip) => eprintln!("OpenKeylet Browser Bridge [{ts}] event={event} peer={ip} {detail}"),
        None => eprintln!("OpenKeylet Browser Bridge [{ts}] event={event} {detail}"),
    }
}

