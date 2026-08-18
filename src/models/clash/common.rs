use crate::models::Proxy;
use crate::utils::is_empty_option_string;
use serde::{Deserialize, Serialize};

/// Options shared by every Clash proxy type. Field order here defines the
/// key order of the emitted YAML, so keep it stable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashCommon {
    pub name: String,
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tfo: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub client_fingerprint: Option<String>,
    #[serde(default, alias = "servername", skip_serializing_if = "is_empty_option_string")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mptcp: Option<bool>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_mark: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dialer_proxy: Option<String>,
    /// Input-only: accepted when parsing but not part of Clash output
    /// (Clash itself uses `dialer-proxy` for chaining)
    #[serde(default, alias = "underlying-proxy", skip_serializing)]
    pub underlying_proxy: Option<String>,
}

impl ClashCommon {
    /// Common options populated from the shared Proxy fields. Callers adjust
    /// protocol-specific placement (e.g. clearing `sni` when the protocol
    /// uses `servername`) afterwards.
    pub fn from_proxy(proxy: &Proxy) -> Self {
        ClashCommon {
            name: proxy.remark.clone(),
            server: proxy.hostname.clone(),
            port: proxy.port,
            udp: proxy.udp,
            tfo: proxy.tcp_fast_open,
            skip_cert_verify: proxy.allow_insecure,
            ..Default::default()
        }
    }

    /// Apply the common fields onto a Proxy being built from Clash input.
    pub fn apply_to_proxy(&self, proxy: &mut Proxy) {
        proxy.remark = self.name.clone();
        proxy.hostname = self.server.clone();
        proxy.port = self.port;
        proxy.udp = self.udp;
        proxy.tcp_fast_open = self.tfo;
        proxy.allow_insecure = self.skip_cert_verify;
        proxy.underlying_proxy = self.underlying_proxy.clone().filter(|u| !u.is_empty());
    }
}

/// Serialize helper: sorted ALPN list from the shared HashSet, for
/// deterministic output.
pub(crate) fn sorted_alpn(proxy: &Proxy) -> Option<Vec<String>> {
    if proxy.alpn.is_empty() {
        None
    } else {
        let mut alpn: Vec<String> = proxy.alpn.iter().cloned().collect();
        alpn.sort();
        Some(alpn)
    }
}

/// Deserialize helper: move a parsed ALPN list into the shared HashSet.
pub(crate) fn apply_alpn(proxy: &mut Proxy, alpn: Option<Vec<String>>) {
    if let Some(values) = alpn {
        for value in values {
            if !value.is_empty() {
                proxy.alpn.insert(value);
            }
        }
    }
}
