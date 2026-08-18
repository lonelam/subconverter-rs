use super::common::ClashCommon;
use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::proxy_node::shadowsocksr::ShadowsocksRProxy;
use crate::models::{Proxy, ProxyType};
use crate::utils::is_empty_option_string;
use serde::{Deserialize, Serialize};

/// ShadowsocksR proxy in a Clash configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashShadowsocksR {
    #[serde(flatten)]
    pub common: ClashCommon,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub cipher: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub protocol_param: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub obfs: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub obfs_param: Option<String>,
}

impl ClashShadowsocksR {
    pub fn into_proxy(self) -> Proxy {
        let mut proxy = Proxy::default();
        proxy.proxy_type = ProxyType::ShadowsocksR;
        self.common.apply_to_proxy(&mut proxy);

        proxy.combined_proxy = Some(CombinedProxy::ShadowsocksR(ShadowsocksRProxy {
            password: self.password.unwrap_or_default(),
            cipher: self.cipher.unwrap_or_default(),
            protocol: self.protocol,
            protocol_param: self.protocol_param,
            obfs: self.obfs,
            obfs_param: self.obfs_param,
        }));

        proxy
    }
}

impl From<&Proxy> for ClashShadowsocksR {
    fn from(proxy: &Proxy) -> Self {
        let mut out = ClashShadowsocksR::default();
        out.common = ClashCommon::from_proxy(proxy);

        if let Some(ssr) = proxy.as_shadowsocksr() {
            out.cipher = Some(ssr.cipher.clone());
            out.password = Some(ssr.password.clone());
            out.protocol = ssr.protocol.clone();
            out.protocol_param = ssr.protocol_param.clone();
            out.obfs = ssr.obfs.clone();
            out.obfs_param = ssr.obfs_param.clone();
        }

        out
    }
}
