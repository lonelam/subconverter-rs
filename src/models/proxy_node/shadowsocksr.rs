use serde::{Deserialize, Serialize};

/// ShadowsocksR-specific options.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShadowsocksRProxy {
    pub password: String,
    pub cipher: String,
    pub protocol: Option<String>,
    pub protocol_param: Option<String>,
    pub obfs: Option<String>,
    pub obfs_param: Option<String>,
}
