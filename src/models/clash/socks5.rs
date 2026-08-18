use super::common::ClashCommon;
use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::proxy_node::socks5::Socks5Proxy;
use crate::models::{Proxy, ProxyType};
use crate::utils::is_empty_option_string;
use serde::{Deserialize, Serialize};

/// SOCKS5 proxy in a Clash configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashSocks5 {
    #[serde(flatten)]
    pub common: ClashCommon,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub password: Option<String>,
}

impl ClashSocks5 {
    pub fn into_proxy(self) -> Proxy {
        let mut proxy = Proxy::default();
        proxy.proxy_type = ProxyType::Socks5;
        self.common.apply_to_proxy(&mut proxy);

        proxy.combined_proxy = Some(CombinedProxy::Socks5(Socks5Proxy {
            username: self.username,
            password: self.password,
        }));

        proxy
    }
}

impl From<&Proxy> for ClashSocks5 {
    fn from(proxy: &Proxy) -> Self {
        let mut out = ClashSocks5::default();
        out.common = ClashCommon::from_proxy(proxy);

        if let Some(socks) = proxy.as_socks5() {
            out.username = socks.username.clone();
            out.password = socks.password.clone();
        }

        out
    }
}
