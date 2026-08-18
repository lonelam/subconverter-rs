use std::collections::HashMap;

use serde::Deserialize;

use crate::models::proxy::Proxy;
use crate::models::proxy::ProxyType;
use crate::utils::deserialize::deserialize_string_or_vec;
use crate::utils::tribool::OptionSetExt;

/// WebSocket options for Trojan proxy (`ws-opts`)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrojanWsOptions {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
}

/// gRPC options for Trojan proxy (`grpc-opts`)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrojanGrpcOptions {
    #[serde(rename = "grpc-service-name", default)]
    pub grpc_service_name: Option<String>,
}

/// Represents a Trojan proxy in Clash configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub struct ClashInputTrojan {
    name: String,
    server: String,
    port: u16,
    password: String,
    #[serde(default)]
    udp: Option<bool>,
    #[serde(default)]
    tfo: Option<bool>,
    #[serde(alias = "skip-cert-verify", default)]
    skip_cert_verify: Option<bool>,
    #[serde(default)]
    network: Option<String>,
    #[serde(alias = "servername", default)]
    sni: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    alpn: Option<Vec<String>>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(
        alias = "client-fingerprint",
        alias = "utls-fingerprint",
        default
    )]
    client_fingerprint: Option<String>,
    #[serde(alias = "ws-opts", default)]
    ws_opts: Option<TrojanWsOptions>,
    #[serde(alias = "grpc-opts", default)]
    grpc_opts: Option<TrojanGrpcOptions>,
}

impl ClashInputTrojan {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn udp(&self) -> Option<bool> {
        self.udp
    }

    pub fn tfo(&self) -> Option<bool> {
        self.tfo
    }

    pub fn skip_cert_verify(&self) -> Option<bool> {
        self.skip_cert_verify
    }

    pub fn network(&self) -> Option<&str> {
        self.network.as_deref()
    }

    pub fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }
}

impl Into<Proxy> for ClashInputTrojan {
    fn into(self) -> Proxy {
        let mut proxy = Proxy::default();
        proxy.proxy_type = ProxyType::Trojan;
        proxy.remark = self.name;
        proxy.hostname = self.server;
        proxy.port = self.port;
        proxy.password = Some(self.password);
        proxy.udp.set_if_some(self.udp);
        proxy.tcp_fast_open.set_if_some(self.tfo);
        proxy.allow_insecure.set_if_some(self.skip_cert_verify);
        proxy.sni = self.sni;
        // Trojan always runs over TLS
        proxy.tls_secure = true;
        proxy.fingerprint = self.fingerprint;
        proxy.client_fingerprint = self.client_fingerprint;

        if let Some(alpn_values) = self.alpn {
            for value in alpn_values {
                proxy.alpn.insert(value);
            }
        }

        if let Some(net) = self.network.as_deref() {
            match net {
                "ws" => {
                    if let Some(opts) = self.ws_opts {
                        proxy.path = opts.path;
                        if let Some(headers) = opts.headers {
                            for (key, value) in headers {
                                if key.to_lowercase() == "host" {
                                    proxy.host = Some(value);
                                }
                            }
                        }
                    }
                }
                "grpc" => {
                    if let Some(opts) = self.grpc_opts {
                        proxy.path = opts.grpc_service_name;
                    }
                }
                _ => {}
            }
        }

        if let Some(net) = self.network {
            proxy.transfer_protocol = Some(net);
        }

        proxy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduces https://github.com/lonelam/subconverter-rs/issues/44 —
    /// alpn and the uTLS fingerprint must survive parsing.
    #[test]
    fn test_trojan_alpn_and_fingerprint_preserved() {
        let yaml = r#"
name: node
type: trojan
server: example.com
port: 443
password: secret
udp: true
tls: true
alpn:
  - h2
  - http/1.1
skip-cert-verify: false
utls-fingerprint: chrome
"#;
        let trojan: ClashInputTrojan = serde_yaml::from_str(yaml).unwrap();
        let proxy: Proxy = trojan.into();

        assert!(proxy.tls_secure);
        assert!(proxy.alpn.contains("h2"));
        assert!(proxy.alpn.contains("http/1.1"));
        assert_eq!(proxy.client_fingerprint.as_deref(), Some("chrome"));
        assert_eq!(proxy.allow_insecure, Some(false));
        assert_eq!(proxy.udp, Some(true));
    }

    #[test]
    fn test_trojan_grpc_service_name() {
        let yaml = r#"
name: node
type: trojan
server: example.com
port: 443
password: secret
network: grpc
grpc-opts:
  grpc-service-name: mygrpc
"#;
        let trojan: ClashInputTrojan = serde_yaml::from_str(yaml).unwrap();
        let proxy: Proxy = trojan.into();
        assert_eq!(proxy.transfer_protocol.as_deref(), Some("grpc"));
        assert_eq!(proxy.path.as_deref(), Some("mygrpc"));
    }
}
