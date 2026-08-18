use std::collections::HashMap;

use serde::Deserialize;

use crate::models::proxy::Proxy;
use crate::models::proxy::ProxyType;
use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::proxy_node::vless::VlessProxy;

/// Represents a VLESS proxy in Clash configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub struct ClashInputVLess {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    #[serde(default)]
    flow: Option<String>,
    #[serde(default)]
    tls: Option<bool>,
    #[serde(default)]
    alpn: Option<Vec<String>>,
    #[serde(default)]
    udp: Option<bool>,
    #[serde(alias = "packet-addr", default)]
    packet_addr: Option<bool>,
    #[serde(alias = "xudp", default)]
    xudp: Option<bool>,
    #[serde(alias = "packet-encoding", default)]
    packet_encoding: Option<String>,
    #[serde(default)]
    network: Option<String>,
    #[serde(alias = "reality-opts", default)]
    reality_opts: Option<RealityOptions>,
    #[serde(alias = "http-opts", default)]
    http_opts: Option<HttpOptions>,
    #[serde(alias = "h2-opts", default)]
    h2_opts: Option<H2Options>,
    #[serde(alias = "grpc-opts", default)]
    grpc_opts: Option<GrpcOptions>,
    #[serde(alias = "ws-opts", default)]
    ws_opts: Option<WsOptions>,
    #[serde(alias = "ws-path", default)]
    ws_path: Option<String>,
    #[serde(alias = "ws-headers", default)]
    ws_headers: Option<HashMap<String, String>>,
    #[serde(alias = "skip-cert-verify", default)]
    skip_cert_verify: Option<bool>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(alias = "servername", alias = "sni", default)]
    servername: Option<String>,
    #[serde(alias = "client-fingerprint", default)]
    client_fingerprint: Option<String>,
}

impl ClashInputVLess {
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

    pub fn flow(&self) -> Option<&str> {
        self.flow.as_deref()
    }

    pub fn tls(&self) -> Option<bool> {
        self.tls
    }

    pub fn alpn(&self) -> Option<&Vec<String>> {
        self.alpn.as_ref()
    }

    pub fn udp(&self) -> Option<bool> {
        self.udp
    }

    pub fn packet_addr(&self) -> Option<bool> {
        self.packet_addr
    }

    pub fn xudp(&self) -> Option<bool> {
        self.xudp
    }

    pub fn packet_encoding(&self) -> Option<&str> {
        self.packet_encoding.as_deref()
    }

    pub fn network(&self) -> Option<&str> {
        self.network.as_deref()
    }

    pub fn reality_opts(&self) -> Option<&RealityOptions> {
        self.reality_opts.as_ref()
    }

    pub fn http_opts(&self) -> Option<&HttpOptions> {
        self.http_opts.as_ref()
    }

    pub fn h2_opts(&self) -> Option<&H2Options> {
        self.h2_opts.as_ref()
    }

    pub fn grpc_opts(&self) -> Option<&GrpcOptions> {
        self.grpc_opts.as_ref()
    }

    pub fn ws_opts(&self) -> Option<&WsOptions> {
        self.ws_opts.as_ref()
    }

    pub fn ws_path(&self) -> Option<&str> {
        self.ws_path.as_deref()
    }

    pub fn ws_headers(&self) -> Option<&HashMap<String, String>> {
        self.ws_headers.as_ref()
    }

    pub fn skip_cert_verify(&self) -> Option<bool> {
        self.skip_cert_verify
    }

    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }

    pub fn servername(&self) -> Option<&str> {
        self.servername.as_deref()
    }

    pub fn client_fingerprint(&self) -> Option<&str> {
        self.client_fingerprint.as_deref()
    }
}

/// Reality options for VLESS proxy
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RealityOptions {
    #[serde(rename = "public-key")]
    pub public_key: String,
    #[serde(rename = "short-id", default, deserialize_with = "short_id_lenient")]
    pub short_id: String,
}

/// `short-id` appears in the wild as a string, a bare number, or null.
fn short_id_lenient<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(
        crate::utils::deserialize::deserialize_string_or_number(deserializer)?
            .unwrap_or_default(),
    )
}

/// HTTP options for VLESS proxy
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HttpOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, Vec<String>>>,
}

/// HTTP2 options for VLESS proxy
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct H2Options {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<Vec<String>>,
}

/// gRPC options for VLESS proxy
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GrpcOptions {
    #[serde(rename = "grpc-service-name", skip_serializing_if = "Option::is_none")]
    pub grpc_service_name: Option<String>,
}

/// WebSocket options for VLESS proxy
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WsOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    #[serde(rename = "max-early-data", skip_serializing_if = "Option::is_none")]
    pub max_early_data: Option<i32>,
    #[serde(
        rename = "early-data-header-name",
        skip_serializing_if = "Option::is_none"
    )]
    pub early_data_header_name: Option<String>,
    #[serde(rename = "v2ray-http-upgrade", skip_serializing_if = "Option::is_none")]
    pub v2ray_http_upgrade: Option<bool>,
    #[serde(
        rename = "v2ray-http-upgrade-fast-open",
        skip_serializing_if = "Option::is_none"
    )]
    pub v2ray_http_upgrade_fast_open: Option<bool>,
}

impl Into<Proxy> for ClashInputVLess {
    fn into(self) -> Proxy {
        let mut proxy = Proxy::default();
        proxy.proxy_type = ProxyType::Vless;

        let mut vless_proxy = VlessProxy::default();
        vless_proxy.uuid = self.uuid;
        vless_proxy.flow = self.flow;
        vless_proxy.tls = self.tls.unwrap_or(false);
        vless_proxy.udp = self.udp.unwrap_or(true);
        vless_proxy.packet_addr = self.packet_addr;
        vless_proxy.xudp = self.xudp;
        vless_proxy.packet_encoding = self.packet_encoding;
        vless_proxy.network = self.network.clone();
        vless_proxy.skip_cert_verify = self.skip_cert_verify;
        vless_proxy.fingerprint = self.fingerprint;
        vless_proxy.servername = self.servername;
        vless_proxy.client_fingerprint = self.client_fingerprint;

        // Handle ALPN
        if let Some(alpn_values) = self.alpn {
            for value in alpn_values {
                vless_proxy.alpn.insert(value);
            }
        }

        // Handle network-specific options
        if let Some(net) = self.network.as_deref() {
            match net {
                "ws" => {
                    if let Some(opts) = self.ws_opts {
                        vless_proxy.ws_path = opts.path;
                        vless_proxy.ws_headers = opts.headers;
                    } else {
                        vless_proxy.ws_path = self.ws_path;
                        vless_proxy.ws_headers = self.ws_headers;
                    }
                }
                "http" => {
                    if let Some(opts) = self.http_opts {
                        vless_proxy.http_method = opts.method;
                        if let Some(paths) = opts.path {
                            if !paths.is_empty() {
                                vless_proxy.http_path = Some(paths[0].clone());
                            }
                        }
                        vless_proxy.http_headers = opts.headers;
                    }
                }
                "h2" => {
                    if let Some(opts) = self.h2_opts {
                        vless_proxy.h2_path = opts.path;
                        vless_proxy.h2_host = opts.host;
                    }
                }
                "grpc" => {
                    if let Some(opts) = self.grpc_opts {
                        vless_proxy.grpc_service_name = opts.grpc_service_name;
                    }
                }
                _ => {}
            }
        }

        // Handle Reality options
        if let Some(reality) = self.reality_opts {
            vless_proxy.reality_public_key = Some(reality.public_key);
            vless_proxy.reality_short_id = Some(reality.short_id);
        }

        proxy.combined_proxy = Some(CombinedProxy::Vless(vless_proxy));
        proxy.remark = self.name;
        proxy.hostname = self.server;
        proxy.port = self.port;

        proxy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduces https://github.com/lonelam/subconverter-rs/issues/41 and
    /// https://github.com/lonelam/subconverter-rs/issues/42 — reality-opts
    /// must survive parsing, including unknown sibling keys like `smux`.
    #[test]
    fn test_vless_reality_opts_preserved() {
        let yaml = r#"{"name":"grpc-reality","type":"vless","server":"2.22.22.22","port":13340,"uuid":"56b8aaaa-c339-4502-86ae-9d2a20dcbbbb","network":"grpc","tls":true,"udp":true,"client-fingerprint":"chrome","grpc-opts":{"grpc-service-name":"grpc"},"reality-opts":{"public-key":"bY9DOyBwDrix8ArirlAd","short-id":""},"smux":{"enabled":true,"protocol":"h2mux","padding":true,"max-connections":"8","min-streams":"16","statistic":true,"only-tcp":false},"brutal-opts":{"enabled":false,"up":"1000 Mbps","down":"1000 Mbps"},"servername":"addons.mozilla.org"}"#;
        let vless: ClashInputVLess = serde_yaml::from_str(yaml).unwrap();
        let proxy: Proxy = vless.into();

        let combined = proxy.combined_proxy.expect("combined proxy must exist");
        let vless_proxy = match combined {
            CombinedProxy::Vless(v) => v,
            _ => panic!("expected vless combined proxy"),
        };
        assert_eq!(
            vless_proxy.reality_public_key.as_deref(),
            Some("bY9DOyBwDrix8ArirlAd")
        );
        assert_eq!(vless_proxy.reality_short_id.as_deref(), Some(""));
        assert_eq!(vless_proxy.client_fingerprint.as_deref(), Some("chrome"));
        assert_eq!(vless_proxy.grpc_service_name.as_deref(), Some("grpc"));
        assert_eq!(vless_proxy.servername.as_deref(), Some("addons.mozilla.org"));
        assert!(vless_proxy.tls);
    }
}
