use serde::{Deserialize, Serialize};

/// Snell-specific options.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnellProxy {
    pub psk: String,
    pub version: u16,
    pub obfs: Option<String>,
    /// Host used for obfuscation
    pub obfs_host: Option<String>,
}
