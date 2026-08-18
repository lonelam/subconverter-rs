use serde::{Deserialize, Serialize};

/// VMess-specific options.
///
/// TLS-related settings (tls, sni, alpn, fingerprints) live on the common
/// [`crate::models::Proxy`] fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VmessProxy {
    pub uuid: String,
    pub alter_id: u16,
    /// Encryption method ("auto", "aes-128-gcm", ...)
    pub cipher: Option<String>,
    /// Transport network: tcp / ws / h2 / http / grpc / quic
    pub network: Option<String>,
    /// Legacy obfs type used by some link formats
    pub fake_type: Option<String>,
    /// Host header / h2 host / http host
    pub host: Option<String>,
    /// ws path / h2 path / http path / grpc service name
    pub path: Option<String>,
    /// Edge header for ws
    pub edge: Option<String>,
    /// QUIC security type
    pub quic_secure: Option<String>,
    /// QUIC key/secret
    pub quic_secret: Option<String>,
}
