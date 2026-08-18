use std::collections::HashMap;

use serde::Deserialize;

use crate::models::proxy::Proxy;
use crate::models::proxy::ProxyType;
use crate::utils::deserialize::deserialize_string_or_vec;
use crate::utils::tribool::OptionSetExt;

/// WebSocket options for VMess proxy (`ws-opts`)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VmessWsOptions {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
}

/// HTTP/2 options for VMess proxy (`h2-opts`)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VmessH2Options {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<Vec<String>>,
}

/// HTTP options for VMess proxy (`http-opts`); the `method` key is accepted
/// but ignored since the internal model has no field for it
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VmessHttpOptions {
    #[serde(default)]
    pub path: Option<Vec<String>>,
    #[serde(default)]
    pub headers: Option<HashMap<String, Vec<String>>>,
}

/// gRPC options for VMess proxy (`grpc-opts`)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VmessGrpcOptions {
    #[serde(rename = "grpc-service-name", default)]
    pub grpc_service_name: Option<String>,
}

/// Represents a VMess proxy in Clash configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub struct ClashInputVMess {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    #[serde(alias = "alterId", default)]
    alter_id: u32,
    #[serde(default = "default_cipher")]
    cipher: String,
    #[serde(default)]
    udp: Option<bool>,
    #[serde(default)]
    tfo: Option<bool>,
    #[serde(alias = "skip-cert-verify", default)]
    skip_cert_verify: Option<bool>,
    #[serde(default)]
    network: Option<String>,
    #[serde(alias = "ws-opts", default)]
    ws_opts: Option<VmessWsOptions>,
    #[serde(alias = "h2-opts", default)]
    h2_opts: Option<VmessH2Options>,
    #[serde(alias = "http-opts", default)]
    http_opts: Option<VmessHttpOptions>,
    #[serde(alias = "grpc-opts", default)]
    grpc_opts: Option<VmessGrpcOptions>,
    #[serde(alias = "ws-path", default)]
    ws_path: Option<String>,
    #[serde(alias = "ws-headers", default)]
    ws_headers: Option<HashMap<String, String>>,
    #[serde(default)]
    tls: Option<bool>,
    #[serde(alias = "servername", alias = "sni", default)]
    servername: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    alpn: Option<Vec<String>>,
    #[serde(alias = "client-fingerprint", default)]
    client_fingerprint: Option<String>,
}

fn default_cipher() -> String {
    "auto".to_string()
}

impl ClashInputVMess {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    pub fn alter_id(&self) -> u32 {
        self.alter_id
    }

    pub fn cipher(&self) -> &str {
        &self.cipher
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

    pub fn ws_path(&self) -> Option<&str> {
        self.ws_path.as_deref()
    }

    pub fn ws_headers(&self) -> Option<&HashMap<String, String>> {
        self.ws_headers.as_ref()
    }

    pub fn tls(&self) -> Option<bool> {
        self.tls
    }

    pub fn servername(&self) -> Option<&str> {
        self.servername.as_deref()
    }
}

impl Into<Proxy> for ClashInputVMess {
    fn into(self) -> Proxy {
        let mut proxy = Proxy::default();
        proxy.proxy_type = ProxyType::VMess;
        proxy.remark = self.name;
        proxy.hostname = self.server.clone();
        proxy.port = self.port;
        proxy.user_id = Some(self.uuid);
        proxy.alter_id = self.alter_id as u16;
        proxy.encrypt_method = Some(self.cipher);
        proxy.udp.set_if_some(self.udp);
        proxy.tcp_fast_open.set_if_some(self.tfo);
        proxy.allow_insecure.set_if_some(self.skip_cert_verify);
        proxy.tls_secure = self.tls.unwrap_or(false);
        proxy.server_name = self.servername;
        proxy.client_fingerprint = self.client_fingerprint;

        if let Some(alpn_values) = self.alpn {
            for value in alpn_values {
                proxy.alpn.insert(value);
            }
        }

        // Network protocol handling. Modern Clash configs use the nested
        // `*-opts` mappings; the flat `ws-path`/`ws-headers` keys are legacy
        // and only used as a fallback.
        if let Some(net) = self.network {
            proxy.transfer_protocol = Some(net.clone());
            match net.as_str() {
                "ws" => {
                    if let Some(opts) = self.ws_opts {
                        proxy.path = opts.path;
                        if let Some(headers) = opts.headers {
                            for (key, value) in headers {
                                match key.to_lowercase().as_str() {
                                    "host" => proxy.host = Some(value),
                                    "edge" => proxy.edge = Some(value),
                                    _ => {}
                                }
                            }
                        }
                    } else {
                        proxy.path = self.ws_path;
                        if let Some(headers) = self.ws_headers {
                            for (key, value) in headers {
                                match key.to_lowercase().as_str() {
                                    "host" => proxy.host = Some(value),
                                    "edge" => proxy.edge = Some(value),
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                "http" => {
                    if let Some(opts) = self.http_opts {
                        proxy.path = opts.path.and_then(|paths| paths.into_iter().next());
                        if let Some(headers) = opts.headers {
                            for (key, values) in headers {
                                if key.to_lowercase() == "host" {
                                    proxy.host = values.into_iter().next();
                                }
                            }
                        }
                    } else {
                        proxy.path = self.ws_path;
                        if let Some(headers) = self.ws_headers {
                            if let Some(host) = headers.get("Host") {
                                proxy.host = Some(host.clone());
                            }
                        }
                    }
                }
                "h2" => {
                    if let Some(opts) = self.h2_opts {
                        proxy.path = opts.path;
                        proxy.host = opts.host.and_then(|hosts| hosts.into_iter().next());
                    } else {
                        proxy.path = self.ws_path;
                        if let Some(headers) = self.ws_headers {
                            if let Some(host) = headers.get("Host") {
                                proxy.host = Some(host.clone());
                            }
                        }
                    }
                }
                "grpc" => {
                    if let Some(opts) = self.grpc_opts {
                        proxy.path = opts.grpc_service_name;
                    } else if self.ws_path.is_some() {
                        proxy.path = self.ws_path;
                    }
                    proxy.host = Some(self.server);
                }
                _ => {}
            }
        }

        proxy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduces https://github.com/lonelam/subconverter-rs/issues/40 —
    /// ws-opts, tls, udp and servername must survive parsing.
    #[test]
    fn test_vmess_ws_opts_tls_preserved() {
        let yaml = r#"{"name":"vmess-jp1","type":"vmess","server":"tokyo1.example.top","port":10000,"uuid":"b445361a-abcf-aaaa-a97a-0bf4136d6ddc","alterId":0,"cipher":"auto","udp":true,"tls":true,"network":"ws","ws-opts":{"path":"/vm","headers":{"Host":"tokyo1.example.top"}},"servername":"tokyo1.example.top"}"#;
        let vmess: ClashInputVMess = serde_yaml::from_str(yaml).unwrap();
        let proxy: Proxy = vmess.into();

        assert_eq!(proxy.proxy_type, ProxyType::VMess);
        assert_eq!(proxy.udp, Some(true));
        assert!(proxy.tls_secure);
        assert_eq!(proxy.server_name.as_deref(), Some("tokyo1.example.top"));
        assert_eq!(proxy.transfer_protocol.as_deref(), Some("ws"));
        assert_eq!(proxy.path.as_deref(), Some("/vm"));
        assert_eq!(proxy.host.as_deref(), Some("tokyo1.example.top"));
    }

    #[test]
    fn test_vmess_missing_cipher_defaults_to_auto() {
        let yaml = r#"{"name":"n","type":"vmess","server":"s.example.com","port":443,"uuid":"u"}"#;
        let vmess: ClashInputVMess = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(vmess.cipher(), "auto");
    }
}
