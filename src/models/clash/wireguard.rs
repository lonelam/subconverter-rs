use super::common::ClashCommon;
use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::proxy_node::wireguard::WireGuardProxy;
use crate::models::{Proxy, ProxyType};
use crate::utils::is_empty_option_string;
use serde::{Deserialize, Serialize};

/// WireGuard proxy in a Clash configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashWireGuard {
    #[serde(flatten)]
    pub common: ClashCommon,
    #[serde(default, alias = "privateKey", skip_serializing_if = "is_empty_option_string")]
    pub private_key: Option<String>,
    #[serde(default, alias = "publicKey", skip_serializing_if = "is_empty_option_string")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub ipv6: Option<String>,
    #[serde(
        default,
        alias = "presharedKey",
        alias = "pre-shared-key",
        skip_serializing_if = "is_empty_option_string"
    )]
    pub preshared_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ips: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<u32>,
}

impl ClashWireGuard {
    pub fn into_proxy(self) -> Proxy {
        let mut proxy = Proxy::default();
        proxy.proxy_type = ProxyType::WireGuard;
        self.common.apply_to_proxy(&mut proxy);

        proxy.combined_proxy = Some(CombinedProxy::WireGuard(WireGuardProxy {
            self_ip: self.ip,
            self_ipv6: self.ipv6,
            private_key: self.private_key,
            public_key: self.public_key,
            pre_shared_key: self.preshared_key,
            dns_servers: self.dns.unwrap_or_default(),
            mtu: self.mtu.unwrap_or(0) as u16,
            allowed_ips: self.allowed_ips.unwrap_or_default().join(","),
            keep_alive: self.keepalive.unwrap_or(0) as u16,
            test_url: None,
            client_id: None,
        }));

        proxy
    }
}

impl From<&Proxy> for ClashWireGuard {
    fn from(proxy: &Proxy) -> Self {
        let mut out = ClashWireGuard::default();
        out.common = ClashCommon::from_proxy(proxy);

        if let Some(wg) = proxy.as_wireguard() {
            out.private_key = wg.private_key.clone();
            out.public_key = wg.public_key.clone();
            out.ip = wg.self_ip.clone();
            out.ipv6 = wg.self_ipv6.clone();
            out.preshared_key = wg.pre_shared_key.clone();

            if !wg.dns_servers.is_empty() {
                out.dns = Some(wg.dns_servers.clone());
            }

            out.mtu = Some(wg.mtu as u32).filter(|m| *m > 0);

            if !wg.allowed_ips.is_empty() {
                out.allowed_ips = Some(
                    wg.allowed_ips
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect(),
                );
            }

            out.keepalive = Some(wg.keep_alive as u32).filter(|k| *k > 0);
        }

        out
    }
}
