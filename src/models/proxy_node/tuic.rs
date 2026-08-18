use serde::{Deserialize, Serialize};

/// TUIC-specific options (v5, with v4 token kept for compatibility).
///
/// TLS-related settings (sni, alpn, skip-cert-verify) live on the common
/// [`crate::models::Proxy`] fields; TUIC is always TLS-secured.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TuicProxy {
    /// v5 authentication uuid
    pub uuid: String,
    /// v5 authentication password
    pub password: String,
    /// v4 legacy token; presence marks a v4 node
    pub token: Option<String>,
    /// Server IP override
    pub ip: Option<String>,
    pub heartbeat_interval: Option<u32>,
    /// cubic / new_reno / bbr
    pub congestion_controller: Option<String>,
    /// native / quic
    pub udp_relay_mode: Option<String>,
    pub reduce_rtt: Option<bool>,
    pub request_timeout: Option<u32>,
    pub max_udp_relay_packet_size: Option<u32>,
    pub disable_sni: Option<bool>,
}
