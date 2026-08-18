use serde::{Deserialize, Serialize};

/// Trojan-specific options.
///
/// TLS-related settings (sni, alpn, fingerprints) live on the common
/// [`crate::models::Proxy`] fields; trojan is always TLS-secured.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrojanProxy {
    pub password: String,
    /// Transport network: tcp / ws / grpc
    pub network: Option<String>,
    /// ws Host header
    pub host: Option<String>,
    /// ws path / grpc service name
    pub path: Option<String>,
}
