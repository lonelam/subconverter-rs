use super::common::{apply_alpn, sorted_alpn, ClashCommon};
use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::proxy_node::vless::VlessProxy;
use crate::models::{Proxy, ProxyType};
use crate::utils::deserialize::deserialize_string_or_vec;
use crate::utils::is_empty_option_string;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Reality options (`reality-opts`)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VlessRealityOptions {
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

/// HTTP options (`http-opts`)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VlessHttpOptions {
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, Vec<String>>>,
}

/// HTTP/2 options (`h2-opts`)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VlessH2Options {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub path: Option<String>,
}

/// gRPC options (`grpc-opts`)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VlessGrpcOptions {
    #[serde(
        rename = "grpc-service-name",
        default,
        skip_serializing_if = "is_empty_option_string"
    )]
    pub grpc_service_name: Option<String>,
}

/// WebSocket options (`ws-opts`)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VlessWsOptions {
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    #[serde(
        rename = "max-early-data",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_early_data: Option<i32>,
    #[serde(
        rename = "early-data-header-name",
        default,
        skip_serializing_if = "is_empty_option_string"
    )]
    pub early_data_header_name: Option<String>,
    #[serde(
        rename = "v2ray-http-upgrade",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub v2ray_http_upgrade: Option<bool>,
    #[serde(
        rename = "v2ray-http-upgrade-fast-open",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub v2ray_http_upgrade_fast_open: Option<bool>,
}

/// VLESS proxy in a Clash configuration.
///
/// VLESS keeps its own `tls`/`client-fingerprint`/`servername` fields (their
/// historical output positions) instead of the common ones.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashVless {
    #[serde(flatten)]
    pub common: ClashCommon,
    pub uuid: String,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub flow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_string_or_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub alpn: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_addr: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xudp: Option<bool>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub packet_encoding: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality_opts: Option<VlessRealityOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_opts: Option<VlessHttpOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2_opts: Option<VlessH2Options>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_opts: Option<VlessGrpcOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_opts: Option<VlessWsOptions>,
    /// Legacy flat forms still seen in old configs
    #[serde(default, skip_serializing, alias = "ws-path")]
    pub ws_path: Option<String>,
    #[serde(default, skip_serializing, alias = "ws-headers")]
    pub ws_headers: Option<HashMap<String, String>>,
    #[serde(
        default,
        alias = "sni",
        skip_serializing_if = "is_empty_option_string"
    )]
    pub servername: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub fingerprint: Option<String>,
    #[serde(
        rename = "client-fingerprint",
        default,
        skip_serializing_if = "is_empty_option_string"
    )]
    pub client_fingerprint: Option<String>,
}

impl ClashVless {
    pub fn into_proxy(self) -> Proxy {
        let mut proxy = Proxy::default();
        proxy.proxy_type = ProxyType::Vless;
        self.common.apply_to_proxy(&mut proxy);
        proxy.tls_secure = self.tls.unwrap_or(false);
        // VLESS historically defaults to udp on
        proxy.udp = Some(self.common.udp.unwrap_or(true));
        proxy.sni = self.servername;
        proxy.fingerprint = self.fingerprint;
        proxy.client_fingerprint = self.client_fingerprint;
        apply_alpn(&mut proxy, self.alpn);

        let mut vless = VlessProxy::default();
        vless.uuid = self.uuid;
        vless.flow = self.flow;
        vless.packet_addr = self.packet_addr;
        vless.xudp = self.xudp;
        vless.packet_encoding = self.packet_encoding;
        vless.network = self.network.clone();

        match self.network.as_deref() {
            Some("ws") => {
                if let Some(opts) = self.ws_opts {
                    vless.ws_path = opts.path;
                    vless.ws_headers = opts.headers;
                } else {
                    vless.ws_path = self.ws_path;
                    vless.ws_headers = self.ws_headers;
                }
            }
            Some("http") => {
                if let Some(opts) = self.http_opts {
                    vless.http_method = opts.method;
                    vless.http_path = opts.path.and_then(|paths| paths.into_iter().next());
                    vless.http_headers = opts.headers;
                }
            }
            Some("h2") => {
                if let Some(opts) = self.h2_opts {
                    vless.h2_path = opts.path;
                    vless.h2_host = opts.host;
                }
            }
            Some("grpc") => {
                if let Some(opts) = self.grpc_opts {
                    vless.grpc_service_name = opts.grpc_service_name;
                }
            }
            _ => {}
        }

        if let Some(reality) = self.reality_opts {
            vless.reality_public_key = Some(reality.public_key);
            vless.reality_short_id = Some(reality.short_id);
        }

        proxy.combined_proxy = Some(CombinedProxy::Vless(vless));
        proxy
    }
}

impl From<&Proxy> for ClashVless {
    fn from(proxy: &Proxy) -> Self {
        let mut out = ClashVless::default();
        out.common = ClashCommon::from_proxy(proxy);
        // VLESS should force udp on unless explicitly disabled
        out.common.udp = Some(proxy.udp.unwrap_or(true));
        out.tls = Some(proxy.tls_secure);
        out.alpn = sorted_alpn(proxy);
        out.servername = proxy.sni.clone();
        out.fingerprint = proxy.fingerprint.clone();
        out.client_fingerprint = proxy.client_fingerprint.clone();

        if let Some(vless) = proxy.as_vless() {
            out.uuid = vless.uuid.clone();
            out.flow = vless.flow.clone();
            out.network = vless.network.clone();
            out.packet_addr = vless.packet_addr;
            out.xudp = vless.xudp;
            out.packet_encoding = vless.packet_encoding.clone();

            if let (Some(public_key), Some(short_id)) =
                (&vless.reality_public_key, &vless.reality_short_id)
            {
                out.reality_opts = Some(VlessRealityOptions {
                    public_key: public_key.clone(),
                    short_id: short_id.clone(),
                });
            }

            match vless.network.as_deref() {
                Some("ws") => {
                    out.ws_opts = Some(VlessWsOptions {
                        path: vless.ws_path.clone(),
                        headers: vless.ws_headers.clone(),
                        ..Default::default()
                    });
                }
                Some("http") => {
                    out.http_opts = Some(VlessHttpOptions {
                        method: vless.http_method.clone(),
                        path: vless.http_path.clone().map(|p| vec![p]),
                        headers: vless.http_headers.clone(),
                    });
                }
                Some("h2") => {
                    out.h2_opts = Some(VlessH2Options {
                        host: vless.h2_host.clone(),
                        path: vless.h2_path.clone(),
                    });
                }
                Some("grpc") => {
                    out.grpc_opts = Some(VlessGrpcOptions {
                        grpc_service_name: vless.grpc_service_name.clone(),
                    });
                }
                _ => {}
            }
        }

        out
    }
}
