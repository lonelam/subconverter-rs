use serde::{Deserialize, Serialize};

/// AnyTLS-specific options (mihomo extension).
///
/// TLS-related settings (sni, alpn, fingerprints, skip-cert-verify) live on
/// the common [`crate::models::Proxy`] fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnyTlsProxy {
    pub password: String,
    pub idle_session_check_interval: Option<i32>,
    pub idle_session_timeout: Option<i32>,
    pub min_idle_session: Option<i32>,
}
