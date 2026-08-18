use super::common::ClashCommon;
use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::proxy_node::snell::SnellProxy;
use crate::models::{Proxy, ProxyType};
use crate::utils::is_empty_option_string;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Snell proxy in a Clash configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashSnell {
    #[serde(flatten)]
    pub common: ClashCommon,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub psk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// Ordered map so emitted YAML stays deterministic
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs_opts: Option<BTreeMap<String, String>>,
}

impl ClashSnell {
    pub fn into_proxy(self) -> Proxy {
        let mut proxy = Proxy::default();
        proxy.proxy_type = ProxyType::Snell;
        self.common.apply_to_proxy(&mut proxy);

        let mut snell = SnellProxy::default();
        snell.psk = self.psk.unwrap_or_default();
        snell.version = self.version.unwrap_or(1) as u16;
        if let Some(opts) = self.obfs_opts {
            snell.obfs = opts.get("mode").cloned();
            snell.obfs_host = opts.get("host").cloned();
        }

        proxy.combined_proxy = Some(CombinedProxy::Snell(snell));
        proxy
    }
}

impl From<&Proxy> for ClashSnell {
    fn from(proxy: &Proxy) -> Self {
        let mut out = ClashSnell::default();
        out.common = ClashCommon::from_proxy(proxy);

        if let Some(snell) = proxy.as_snell() {
            out.psk = Some(snell.psk.clone());
            out.version = Some(snell.version.max(1) as u32);

            let mut opts = BTreeMap::new();
            if let Some(obfs) = snell.obfs.clone().filter(|o| !o.is_empty()) {
                opts.insert("mode".to_string(), obfs);
            }
            if let Some(host) = snell.obfs_host.clone().filter(|h| !h.is_empty()) {
                opts.insert("host".to_string(), host);
            }
            if !opts.is_empty() {
                out.obfs_opts = Some(opts);
            }
        }

        out
    }
}
