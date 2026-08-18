use super::common::{apply_alpn, sorted_alpn, ClashCommon};
use crate::models::proxy_node::anytls::AnyTlsProxy;
use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::{Proxy, ProxyType};
use crate::utils::is_empty_option_string;
use serde::{Deserialize, Serialize};

/// AnyTLS proxy in a Clash configuration (mihomo extension).
///
/// TLS options keep their historical struct-level output positions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashAnyTls {
    #[serde(flatten)]
    pub common: ClashCommon,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub sni: Option<String>,
    #[serde(
        rename = "skip-cert-verify",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub skip_cert_verify: Option<bool>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub fingerprint: Option<String>,
    #[serde(
        rename = "client-fingerprint",
        default,
        skip_serializing_if = "is_empty_option_string"
    )]
    pub client_fingerprint: Option<String>,
    #[serde(
        rename = "idle-session-check-interval",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub idle_session_check_interval: Option<i32>,
    #[serde(
        rename = "idle-session-timeout",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub idle_session_timeout: Option<i32>,
    #[serde(
        rename = "min-idle-session",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub min_idle_session: Option<i32>,
}

impl ClashAnyTls {
    pub fn into_proxy(self) -> Proxy {
        let mut proxy = Proxy::default();
        proxy.proxy_type = ProxyType::AnyTls;
        self.common.apply_to_proxy(&mut proxy);
        proxy.tls_secure = true;
        proxy.sni = self.sni.or_else(|| self.common.sni.clone());
        proxy.allow_insecure = self.skip_cert_verify.or(self.common.skip_cert_verify);
        proxy.fingerprint = self.fingerprint.or_else(|| self.common.fingerprint.clone());
        proxy.client_fingerprint = self
            .client_fingerprint
            .or_else(|| self.common.client_fingerprint.clone());
        apply_alpn(&mut proxy, self.alpn);

        proxy.combined_proxy = Some(CombinedProxy::AnyTls(AnyTlsProxy {
            password: self.password,
            idle_session_check_interval: self.idle_session_check_interval,
            idle_session_timeout: self.idle_session_timeout,
            min_idle_session: self.min_idle_session,
        }));

        proxy
    }
}

impl From<&Proxy> for ClashAnyTls {
    fn from(proxy: &Proxy) -> Self {
        let mut out = ClashAnyTls::default();
        out.common = ClashCommon::from_proxy(proxy);
        // TLS fields keep their historical struct-level positions
        out.common.skip_cert_verify = None;
        out.skip_cert_verify = proxy.allow_insecure;
        out.sni = proxy.sni.clone();
        out.fingerprint = proxy.fingerprint.clone();
        out.client_fingerprint = proxy.client_fingerprint.clone();
        out.alpn = sorted_alpn(proxy);

        if let Some(anytls) = proxy.as_anytls() {
            out.password = anytls.password.clone();
            out.idle_session_check_interval = anytls.idle_session_check_interval;
            out.idle_session_timeout = anytls.idle_session_timeout;
            out.min_idle_session = anytls.min_idle_session;
        }

        out
    }
}
