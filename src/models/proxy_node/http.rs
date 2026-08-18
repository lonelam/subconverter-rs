use serde::{Deserialize, Serialize};

/// HTTP/HTTPS proxy options. HTTPS is expressed by
/// `proxy_type == ProxyType::HTTPS` / the common `tls_secure` flag.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpProxy {
    pub username: Option<String>,
    pub password: Option<String>,
}
