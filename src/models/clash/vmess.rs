use super::common::{apply_alpn, sorted_alpn, ClashCommon};
use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::proxy_node::vmess::VmessProxy;
use crate::models::{Proxy, ProxyType};
use crate::utils::deserialize::deserialize_string_or_vec;
use crate::utils::is_empty_option_string;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// WebSocket options (`ws-opts`)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VmessWsOptions {
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
}

/// HTTP options (`http-opts`); `method` is accepted but not modeled
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VmessHttpOptions {
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
}

/// HTTP/2 options (`h2-opts`)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VmessH2Options {
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<Vec<String>>,
}

/// gRPC options (`grpc-opts`)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VmessGrpcOptions {
    #[serde(
        rename = "grpc-service-name",
        default,
        skip_serializing_if = "is_empty_option_string"
    )]
    pub grpc_service_name: Option<String>,
}

/// Lenient `http-opts` input form: clash uses list-valued path/headers
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VmessHttpOptionsInput {
    #[serde(default)]
    pub path: Option<Vec<String>>,
    #[serde(default)]
    pub headers: Option<HashMap<String, Vec<String>>>,
}

/// VMess proxy in a Clash configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashVmess {
    #[serde(flatten)]
    pub common: ClashCommon,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub uuid: Option<String>,
    /// Required by Clash under the historical name `alterId`
    #[serde(rename = "alterId", alias = "alter-id", default)]
    pub alter_id: u32,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub cipher: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub network: Option<String>,
    #[serde(
        default,
        alias = "sni",
        skip_serializing_if = "is_empty_option_string"
    )]
    pub servername: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_string_or_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub alpn: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_opts: Option<VmessWsOptions>,
    #[serde(default, skip_serializing, alias = "http-opts")]
    pub http_opts_in: Option<VmessHttpOptionsInput>,
    #[serde(default, skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub http_opts: Option<VmessHttpOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2_opts: Option<VmessH2Options>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_opts: Option<VmessGrpcOptions>,
    /// Legacy flat forms still seen in old configs
    #[serde(default, skip_serializing, alias = "ws-path")]
    pub ws_path: Option<String>,
    #[serde(default, skip_serializing, alias = "ws-headers")]
    pub ws_headers: Option<HashMap<String, String>>,
}

fn header_lookup(headers: &HashMap<String, String>, key: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.clone())
}

impl ClashVmess {
    pub fn into_proxy(self) -> Proxy {
        let mut proxy = Proxy::default();
        proxy.proxy_type = ProxyType::VMess;
        self.common.apply_to_proxy(&mut proxy);
        proxy.tls_secure = self.common.tls.unwrap_or(false);
        proxy.sni = self.servername;
        proxy.client_fingerprint = self.common.client_fingerprint.clone();
        proxy.fingerprint = self.common.fingerprint.clone();
        apply_alpn(&mut proxy, self.alpn);

        let mut vmess = VmessProxy::default();
        vmess.uuid = self.uuid.unwrap_or_default();
        vmess.alter_id = self.alter_id as u16;
        vmess.cipher = Some(self.cipher.unwrap_or_else(|| "auto".to_string()));
        vmess.network = self.network.clone();
        let network = self.network.unwrap_or_default();

        match network.as_str() {
            "ws" => {
                if let Some(opts) = self.ws_opts {
                    vmess.path = opts.path;
                    if let Some(headers) = opts.headers {
                        vmess.host = header_lookup(&headers, "host");
                        vmess.edge = header_lookup(&headers, "edge");
                    }
                } else {
                    vmess.path = self.ws_path;
                    if let Some(headers) = self.ws_headers {
                        vmess.host = header_lookup(&headers, "host");
                        vmess.edge = header_lookup(&headers, "edge");
                    }
                }
            }
            "http" => {
                if let Some(opts) = self.http_opts_in {
                    vmess.path = opts.path.and_then(|paths| paths.into_iter().next());
                    if let Some(headers) = opts.headers {
                        vmess.host = headers
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                            .and_then(|(_, v)| v.first().cloned());
                    }
                } else {
                    vmess.path = self.ws_path;
                    if let Some(headers) = self.ws_headers {
                        vmess.host = header_lookup(&headers, "host");
                    }
                }
            }
            "h2" => {
                if let Some(opts) = self.h2_opts {
                    vmess.path = opts.path;
                    vmess.host = opts.host.and_then(|hosts| hosts.into_iter().next());
                } else {
                    vmess.path = self.ws_path;
                    if let Some(headers) = self.ws_headers {
                        vmess.host = header_lookup(&headers, "host");
                    }
                }
            }
            "grpc" => {
                if let Some(opts) = self.grpc_opts {
                    vmess.path = opts.grpc_service_name;
                } else if self.ws_path.is_some() {
                    vmess.path = self.ws_path;
                }
                vmess.host = Some(self.common.server.clone());
            }
            _ => {}
        }

        proxy.combined_proxy = Some(CombinedProxy::VMess(vmess));
        proxy
    }
}

impl From<&Proxy> for ClashVmess {
    fn from(proxy: &Proxy) -> Self {
        let mut out = ClashVmess::default();
        out.common = ClashCommon::from_proxy(proxy);
        out.common.tls = if proxy.tls_secure { Some(true) } else { None };
        out.common.client_fingerprint = proxy.client_fingerprint.clone();
        // Clash vmess uses `servername` for SNI
        out.servername = proxy.sni.clone();
        out.alpn = sorted_alpn(proxy);

        if let Some(vmess) = proxy.as_vmess() {
            out.uuid = Some(vmess.uuid.clone());
            out.alter_id = vmess.alter_id as u32;
            out.cipher = vmess.cipher.clone();
            out.network = vmess.network.clone();

            match vmess.network.as_deref() {
                Some("ws") => {
                    let mut ws_opts = VmessWsOptions::default();
                    ws_opts.path = vmess.path.clone();
                    if let Some(host) = &vmess.host {
                        let mut headers = HashMap::new();
                        headers.insert("Host".to_string(), host.clone());
                        ws_opts.headers = Some(headers);
                    }
                    out.ws_opts = Some(ws_opts);
                }
                Some("http") => {
                    let mut http_opts = VmessHttpOptions::default();
                    http_opts.path = vmess.path.clone();
                    if let Some(host) = &vmess.host {
                        let mut headers = HashMap::new();
                        headers.insert("Host".to_string(), host.clone());
                        http_opts.headers = Some(headers);
                    }
                    out.http_opts = Some(http_opts);
                }
                Some("h2") => {
                    let mut h2_opts = VmessH2Options::default();
                    h2_opts.path = vmess.path.clone();
                    h2_opts.host = vmess.host.clone().map(|host| vec![host]);
                    out.h2_opts = Some(h2_opts);
                }
                Some("grpc") => {
                    out.grpc_opts = Some(VmessGrpcOptions {
                        grpc_service_name: vmess.path.clone(),
                    });
                }
                _ => {}
            }
        }

        out
    }
}
