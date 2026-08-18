use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// VLESS-specific options.
///
/// TLS-related settings (tls, sni, alpn, fingerprints, skip-cert-verify) live
/// on the common [`crate::models::Proxy`] fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VlessProxy {
    pub uuid: String,
    pub flow: Option<String>,
    pub packet_addr: Option<bool>,
    pub xudp: Option<bool>,
    pub packet_encoding: Option<String>,
    /// Transport network: tcp / ws / h2 / http / grpc
    pub network: Option<String>,
    pub reality_public_key: Option<String>,
    pub reality_short_id: Option<String>,
    pub http_method: Option<String>,
    pub http_path: Option<String>,
    pub http_headers: Option<HashMap<String, Vec<String>>>,
    pub h2_host: Option<Vec<String>>,
    pub h2_path: Option<String>,
    pub grpc_service_name: Option<String>,
    pub ws_path: Option<String>,
    pub ws_headers: Option<HashMap<String, String>>,
}
