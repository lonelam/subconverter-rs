use serde::{Deserialize, Serialize};

/// WireGuard-specific options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardProxy {
    pub self_ip: Option<String>,
    pub self_ipv6: Option<String>,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub pre_shared_key: Option<String>,
    /// DNS servers, in configuration order
    pub dns_servers: Vec<String>,
    pub mtu: u16,
    pub allowed_ips: String,
    pub keep_alive: u16,
    pub test_url: Option<String>,
    pub client_id: Option<String>,
}

impl Default for WireGuardProxy {
    fn default() -> Self {
        Self {
            self_ip: None,
            self_ipv6: None,
            private_key: None,
            public_key: None,
            pre_shared_key: None,
            dns_servers: Vec::new(),
            mtu: 0,
            allowed_ips: String::from("0.0.0.0/0, ::/0"),
            keep_alive: 0,
            test_url: None,
            client_id: None,
        }
    }
}
