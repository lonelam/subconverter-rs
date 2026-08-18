use serde::{Deserialize, Serialize};

/// SOCKS5 proxy options.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Socks5Proxy {
    pub username: Option<String>,
    pub password: Option<String>,
}
