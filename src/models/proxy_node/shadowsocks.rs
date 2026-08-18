use serde::{Deserialize, Serialize};

/// Shadowsocks-specific options.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShadowsocksProxy {
    pub password: String,
    pub cipher: String,
    /// Plugin name (e.g. "obfs-local", "v2ray-plugin")
    pub plugin: Option<String>,
    /// Plugin options in `key1=value1;key2=value2` form
    pub plugin_opts: Option<String>,
    pub udp_over_tcp: Option<bool>,
    pub udp_over_tcp_version: Option<u8>,
}
