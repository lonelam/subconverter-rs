use super::CommonProxyOptions;
use crate::models::Proxy;
use crate::utils::is_empty_option_string;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Trojan proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrojanProxy {
    #[serde(flatten)]
    pub common: CommonProxyOptions,
    #[serde(skip_serializing_if = "is_empty_option_string")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "is_empty_option_string")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_opts: Option<WsOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_opts: Option<GrpcOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WsOptions {
    #[serde(skip_serializing_if = "is_empty_option_string")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GrpcOptions {
    #[serde(
        rename = "grpc-service-name",
        skip_serializing_if = "is_empty_option_string"
    )]
    pub service_name: Option<String>,
}

impl TrojanProxy {
    /// Create a new Trojan proxy
    pub fn new(common: CommonProxyOptions) -> Self {
        Self {
            common,
            password: None,
            network: None,
            alpn: None,
            ws_opts: None,
            grpc_opts: None,
        }
    }
}

impl From<Proxy> for TrojanProxy {
    fn from(proxy: Proxy) -> Self {
        let common =
            CommonProxyOptions::builder(proxy.remark.clone(), proxy.hostname.clone(), proxy.port)
                .udp(proxy.udp)
                .tfo(proxy.tcp_fast_open)
                .skip_cert_verify(proxy.allow_insecure)
                .sni(proxy.sni.clone().or_else(|| proxy.server_name.clone()))
                .fingerprint(proxy.fingerprint.clone())
                .client_fingerprint(proxy.client_fingerprint.clone())
                .build();

        let mut trojan = TrojanProxy::new(common);

        trojan.password = proxy.password;
        trojan.network = proxy.transfer_protocol.clone();
        if !proxy.alpn.is_empty() {
            let mut alpn: Vec<String> = proxy.alpn.iter().cloned().collect();
            alpn.sort();
            trojan.alpn = Some(alpn);
        }

        if let Some(network) = &proxy.transfer_protocol {
            match network.as_str() {
                "ws" => {
                    let mut ws_opts = WsOptions {
                        path: None,
                        headers: None,
                    };

                    if let Some(path) = &proxy.path {
                        ws_opts.path = Some(path.clone());
                    }

                    if let Some(host) = &proxy.host {
                        let mut headers = HashMap::new();
                        headers.insert("Host".to_string(), host.clone());
                        ws_opts.headers = Some(headers);
                    }

                    trojan.ws_opts = Some(ws_opts);
                }
                "grpc" => {
                    let mut grpc_opts = GrpcOptions { service_name: None };

                    if let Some(path) = &proxy.path {
                        grpc_opts.service_name = Some(path.clone());
                    }

                    trojan.grpc_opts = Some(grpc_opts);
                }
                _ => {}
            }
        }

        trojan
    }
}
