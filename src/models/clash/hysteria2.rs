use super::common::{apply_alpn, sorted_alpn, ClashCommon};
use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::proxy_node::hysteria2::Hysteria2Proxy;
use crate::models::{Proxy, ProxyType};
use crate::utils::deserialize::{
    deserialize_string_or_number, deserialize_string_or_vec, parse_speed_mbps,
};
use crate::utils::is_empty_option_string;
use serde::{Deserialize, Serialize};

fn is_zero(value: &u32) -> bool {
    *value == 0
}

/// Hysteria2 proxy in a Clash configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashHysteria2 {
    #[serde(flatten)]
    pub common: ClashCommon,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub obfs: Option<String>,
    #[serde(
        default,
        alias = "obfs-password",
        skip_serializing_if = "is_empty_option_string"
    )]
    pub obfs_password: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub ports: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_string_or_number",
        skip_serializing_if = "is_empty_option_string"
    )]
    pub up: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_string_or_number",
        skip_serializing_if = "is_empty_option_string"
    )]
    pub down: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub fingerprint: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_string_or_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub alpn: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub ca: Option<String>,
    #[serde(rename = "ca-str", default, skip_serializing_if = "is_empty_option_string")]
    pub ca_str: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwnd: Option<u32>,
    #[serde(rename = "udp-mtu", default, skip_serializing_if = "Option::is_none")]
    pub udp_mtu: Option<u32>,
    #[serde(
        rename = "recv-window-conn",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub recv_window_conn: Option<u32>,
    #[serde(rename = "recv-window", default, skip_serializing_if = "Option::is_none")]
    pub recv_window: Option<u32>,
    #[serde(
        rename = "disable-mtu-discovery",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disable_mtu_discovery: Option<bool>,
    #[serde(
        rename = "fast-open",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub fast_open: Option<bool>,
    #[serde(
        rename = "hop-interval",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hop_interval: Option<u32>,
}

impl ClashHysteria2 {
    pub fn into_proxy(self) -> Proxy {
        let mut proxy = Proxy::default();
        proxy.proxy_type = ProxyType::Hysteria2;
        self.common.apply_to_proxy(&mut proxy);
        proxy.tcp_fast_open = self.fast_open.or(self.common.tfo);
        proxy.sni = self.common.sni.clone();
        proxy.fingerprint = self.fingerprint;
        apply_alpn(&mut proxy, self.alpn);

        let mut hysteria2 = Hysteria2Proxy::default();
        hysteria2.password = self.password.unwrap_or_default();
        hysteria2.ports = self.ports;
        hysteria2.obfs = self.obfs;
        hysteria2.obfs_password = self.obfs_password;

        // Speed values may carry units ("1000 Mbps")
        if let Some(up) = self.up {
            hysteria2.up_speed = parse_speed_mbps(&up);
        }
        if let Some(down) = self.down {
            hysteria2.down_speed = parse_speed_mbps(&down);
        }

        hysteria2.ca = self.ca;
        hysteria2.ca_str = self.ca_str;
        hysteria2.cwnd = self.cwnd.unwrap_or(0);
        hysteria2.udp_mtu = self.udp_mtu.unwrap_or(0);
        hysteria2.recv_window_conn = self.recv_window_conn.unwrap_or(0);
        hysteria2.recv_window = self.recv_window.unwrap_or(0);
        hysteria2.disable_mtu_discovery = self.disable_mtu_discovery;
        hysteria2.hop_interval = self.hop_interval.unwrap_or(0);

        proxy.combined_proxy = Some(CombinedProxy::Hysteria2(hysteria2));
        proxy
    }
}

impl From<&Proxy> for ClashHysteria2 {
    fn from(proxy: &Proxy) -> Self {
        let mut out = ClashHysteria2::default();
        out.common = ClashCommon::from_proxy(proxy);
        out.common.sni = proxy.sni.clone();
        out.fingerprint = proxy.fingerprint.clone();
        out.alpn = sorted_alpn(proxy);
        out.fast_open = proxy.tcp_fast_open;

        if let Some(hysteria2) = proxy.as_hysteria2() {
            out.password = Some(hysteria2.password.clone());
            out.obfs = hysteria2.obfs.clone();
            out.obfs_password = hysteria2.obfs_password.clone();
            out.ports = hysteria2.ports.clone();

            if hysteria2.up_speed > 0 {
                out.up = Some(format!("{}Mbps", hysteria2.up_speed));
            }
            if hysteria2.down_speed > 0 {
                out.down = Some(format!("{}Mbps", hysteria2.down_speed));
            }

            out.ca = hysteria2.ca.clone();
            out.ca_str = hysteria2.ca_str.clone();
            out.cwnd = Some(hysteria2.cwnd).filter(|v| !is_zero(v));
            out.udp_mtu = Some(hysteria2.udp_mtu).filter(|v| !is_zero(v));
            out.recv_window_conn = Some(hysteria2.recv_window_conn).filter(|v| !is_zero(v));
            out.recv_window = Some(hysteria2.recv_window).filter(|v| !is_zero(v));
            out.disable_mtu_discovery = hysteria2.disable_mtu_discovery;
            out.hop_interval = Some(hysteria2.hop_interval).filter(|v| !is_zero(v));
        }

        out
    }
}
