use super::common::{apply_alpn, sorted_alpn, ClashCommon};
use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::proxy_node::trojan::TrojanProxy;
use crate::models::{Proxy, ProxyType};
use crate::utils::deserialize::deserialize_string_or_vec;
use crate::utils::is_empty_option_string;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// WebSocket options (`ws-opts`)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrojanWsOptions {
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
}

/// gRPC options (`grpc-opts`)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrojanGrpcOptions {
    #[serde(
        rename = "grpc-service-name",
        default,
        skip_serializing_if = "is_empty_option_string"
    )]
    pub grpc_service_name: Option<String>,
}

/// Trojan proxy in a Clash configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashTrojan {
    #[serde(flatten)]
    pub common: ClashCommon,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub network: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_string_or_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub alpn: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_opts: Option<TrojanWsOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_opts: Option<TrojanGrpcOptions>,
    /// Accepted on input for uTLS naming used by some clients
    #[serde(default, skip_serializing, alias = "utls-fingerprint")]
    pub utls_fingerprint: Option<String>,
}

impl ClashTrojan {
    pub fn into_proxy(self) -> Proxy {
        let mut proxy = Proxy::default();
        proxy.proxy_type = ProxyType::Trojan;
        self.common.apply_to_proxy(&mut proxy);
        // Trojan always runs over TLS
        proxy.tls_secure = true;
        proxy.sni = self.common.sni.clone();
        proxy.fingerprint = self.common.fingerprint.clone();
        proxy.client_fingerprint = self
            .common
            .client_fingerprint
            .clone()
            .or(self.utls_fingerprint);
        apply_alpn(&mut proxy, self.alpn);

        let mut trojan = TrojanProxy::default();
        trojan.password = self.password.unwrap_or_default();
        trojan.network = self.network.clone();

        match self.network.as_deref() {
            Some("ws") => {
                if let Some(opts) = self.ws_opts {
                    trojan.path = opts.path;
                    if let Some(headers) = opts.headers {
                        trojan.host = headers
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                            .map(|(_, v)| v.clone());
                    }
                }
            }
            Some("grpc") => {
                if let Some(opts) = self.grpc_opts {
                    trojan.path = opts.grpc_service_name;
                }
            }
            _ => {}
        }

        proxy.combined_proxy = Some(CombinedProxy::Trojan(trojan));
        proxy
    }
}

impl From<&Proxy> for ClashTrojan {
    fn from(proxy: &Proxy) -> Self {
        let mut out = ClashTrojan::default();
        out.common = ClashCommon::from_proxy(proxy);
        out.common.sni = proxy.sni.clone();
        out.common.fingerprint = proxy.fingerprint.clone();
        out.common.client_fingerprint = proxy.client_fingerprint.clone();
        out.alpn = sorted_alpn(proxy);

        if let Some(trojan) = proxy.as_trojan() {
            out.password = Some(trojan.password.clone());
            out.network = trojan.network.clone();

            match trojan.network.as_deref() {
                Some("ws") => {
                    let mut ws_opts = TrojanWsOptions::default();
                    ws_opts.path = trojan.path.clone();
                    if let Some(host) = &trojan.host {
                        let mut headers = HashMap::new();
                        headers.insert("Host".to_string(), host.clone());
                        ws_opts.headers = Some(headers);
                    }
                    out.ws_opts = Some(ws_opts);
                }
                Some("grpc") => {
                    out.grpc_opts = Some(TrojanGrpcOptions {
                        grpc_service_name: trojan.path.clone(),
                    });
                }
                _ => {}
            }
        }

        out
    }
}
