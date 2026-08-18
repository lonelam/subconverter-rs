use serde::{Deserialize, Serialize};

/// Hysteria (v1) specific options.
///
/// TLS-related settings (sni, alpn, fingerprint, ca) that are shared across
/// protocols live on the common [`crate::models::Proxy`] fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HysteriaProxy {
    /// Port hopping range, e.g. "30000-40000"
    pub ports: Option<String>,
    /// udp / wechat-video / faketcp
    pub protocol: Option<String>,
    pub obfs: Option<String>,
    /// Upload speed in Mbps (0 = unset)
    pub up_speed: u32,
    /// Download speed in Mbps (0 = unset)
    pub down_speed: u32,
    pub auth: Option<String>,
    pub auth_str: Option<String>,
    pub ca: Option<String>,
    pub ca_str: Option<String>,
    pub recv_window_conn: u32,
    pub recv_window: u32,
    pub disable_mtu_discovery: Option<bool>,
    pub hop_interval: u32,
}
