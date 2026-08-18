use super::common::ClashCommon;
use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::proxy_node::http::HttpProxy;
use crate::models::{Proxy, ProxyType};
use crate::utils::is_empty_option_string;
use serde::{Deserialize, Serialize};

/// HTTP(S) proxy in a Clash configuration; `tls: true` marks HTTPS.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashHttp {
    #[serde(flatten)]
    pub common: ClashCommon,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub password: Option<String>,
}

impl ClashHttp {
    pub fn into_proxy(self) -> Proxy {
        let mut proxy = Proxy::default();
        let tls = self.common.tls.unwrap_or(false);
        proxy.proxy_type = if tls {
            ProxyType::HTTPS
        } else {
            ProxyType::HTTP
        };
        self.common.apply_to_proxy(&mut proxy);
        proxy.tls_secure = tls;
        proxy.sni = self.common.sni.clone();

        proxy.combined_proxy = Some(CombinedProxy::Http(HttpProxy {
            username: self.username,
            password: self.password,
        }));

        proxy
    }
}

impl From<&Proxy> for ClashHttp {
    fn from(proxy: &Proxy) -> Self {
        let mut out = ClashHttp::default();
        out.common = ClashCommon::from_proxy(proxy);
        out.common.tls = Some(proxy.proxy_type == ProxyType::HTTPS);

        if let Some(http) = proxy.as_http() {
            out.username = http.username.clone();
            out.password = http.password.clone();
        }

        out
    }
}
