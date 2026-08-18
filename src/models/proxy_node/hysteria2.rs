use serde::{Deserialize, Serialize};

/// Hysteria2-specific options.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Hysteria2Proxy {
    pub password: String,
    /// Port hopping range, e.g. "30000-40000"
    pub ports: Option<String>,
    pub obfs: Option<String>,
    pub obfs_password: Option<String>,
    /// Upload speed in Mbps (0 = unset)
    pub up_speed: u32,
    /// Download speed in Mbps (0 = unset)
    pub down_speed: u32,
    pub ca: Option<String>,
    pub ca_str: Option<String>,
    pub cwnd: u32,
    /// UDP MTU
    pub udp_mtu: u32,
    pub recv_window_conn: u32,
    pub recv_window: u32,
    pub disable_mtu_discovery: Option<bool>,
    pub hop_interval: u32,
}
