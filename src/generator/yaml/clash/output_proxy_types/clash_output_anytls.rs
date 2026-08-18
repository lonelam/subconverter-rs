use serde::{Deserialize, Serialize};

use crate::Proxy;

use super::CommonProxyOptions;

/// Represents an AnyTLS proxy for Clash output configuration (mihomo extension)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashOutputAnyTLS {
    #[serde(flatten)]
    pub common: CommonProxyOptions,
    password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    alpn: Option<Vec<String>>, // Convert HashSet back to Vec for output
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<String>,
    #[serde(rename = "skip-cert-verify", skip_serializing_if = "Option::is_none")]
    skip_cert_verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
    #[serde(rename = "client-fingerprint", skip_serializing_if = "Option::is_none")]
    client_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    // Assuming false is default, don't serialize if false
    udp: Option<bool>,
    #[serde(
        rename = "idle-session-check-interval",
        skip_serializing_if = "Option::is_none"
    )]
    idle_session_check_interval: Option<i32>,
    #[serde(
        rename = "idle-session-timeout",
        skip_serializing_if = "Option::is_none"
    )]
    idle_session_timeout: Option<i32>,
    #[serde(rename = "min-idle-session", skip_serializing_if = "Option::is_none")]
    min_idle_session: Option<i32>,
}

impl ClashOutputAnyTLS {
    pub fn new(common: CommonProxyOptions) -> Self {
        Self {
            common,
            password: String::new(),
            alpn: None,
            sni: None,
            skip_cert_verify: None,
            fingerprint: None,
            client_fingerprint: None,
            udp: None,
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
        }
    }
}

impl From<Proxy> for ClashOutputAnyTLS {
    fn from(proxy: Proxy) -> Self {
        let common =
            CommonProxyOptions::builder(proxy.remark.clone(), proxy.hostname.clone(), proxy.port)
                .udp(proxy.udp)
                .tfo(proxy.tcp_fast_open)
                .skip_cert_verify(proxy.allow_insecure)
                .sni(proxy.sni.clone())
                .build();

        let mut anytls = ClashOutputAnyTLS::new(common);
        if let Some(ref combined) = proxy.combined_proxy {
            if let crate::models::proxy_node::combined::CombinedProxy::AnyTls(ref anytls_proxy) =
                combined
            {
                anytls.password = anytls_proxy.password.clone();
                anytls.sni = anytls_proxy.sni.clone();
                anytls.skip_cert_verify = anytls_proxy.skip_cert_verify;
                anytls.fingerprint = anytls_proxy.fingerprint.clone();
                anytls.client_fingerprint = anytls_proxy.client_fingerprint.clone();
                anytls.idle_session_check_interval = anytls_proxy.idle_session_check_interval;
                anytls.idle_session_timeout = anytls_proxy.idle_session_timeout;
                anytls.min_idle_session = anytls_proxy.min_idle_session;
                // 处理 ALPN
                if let Some(alpn) = &anytls_proxy.alpn {
                    if !alpn.is_empty() {
                        anytls.alpn = Some(alpn.iter().cloned().collect());
                    }
                }
            }
        }
        anytls
    }
}
