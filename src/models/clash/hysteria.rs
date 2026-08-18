use super::common::{apply_alpn, sorted_alpn, ClashCommon};
use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::proxy_node::hysteria::HysteriaProxy;
use crate::models::{Proxy, ProxyType};
use crate::utils::deserialize::{
    deserialize_string_or_number, deserialize_string_or_vec, parse_speed_mbps,
};
use crate::utils::is_empty_option_string;
use serde::{Deserialize, Serialize};

fn is_zero(value: &u32) -> bool {
    *value == 0
}

/// Hysteria (v1) proxy in a Clash configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashHysteria {
    #[serde(flatten)]
    pub common: ClashCommon,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub ports: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub protocol: Option<String>,
    /// Input-only legacy alias for `obfs`
    #[serde(default, alias = "obfs-protocol", skip_serializing)]
    pub obfs_protocol: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_string_or_number",
        skip_serializing_if = "is_empty_option_string"
    )]
    pub up: Option<String>,
    #[serde(default, alias = "up_speed", skip_serializing_if = "Option::is_none")]
    pub up_speed: Option<u32>,
    #[serde(
        default,
        deserialize_with = "deserialize_string_or_number",
        skip_serializing_if = "is_empty_option_string"
    )]
    pub down: Option<String>,
    #[serde(default, alias = "down_speed", skip_serializing_if = "Option::is_none")]
    pub down_speed: Option<u32>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub auth: Option<String>,
    #[serde(default, alias = "auth_str", skip_serializing_if = "is_empty_option_string")]
    pub auth_str: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub obfs: Option<String>,
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
        alias = "disable_mtu_discovery",
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

impl ClashHysteria {
    pub fn into_proxy(self) -> Proxy {
        let mut proxy = Proxy::default();
        proxy.proxy_type = ProxyType::Hysteria;
        self.common.apply_to_proxy(&mut proxy);
        proxy.tcp_fast_open = self.fast_open.or(self.common.tfo);
        proxy.sni = self.common.sni.clone();
        proxy.fingerprint = self.fingerprint;
        apply_alpn(&mut proxy, self.alpn);

        let mut hysteria = HysteriaProxy::default();
        hysteria.ports = self.ports;
        hysteria.protocol = self.protocol;
        hysteria.obfs = self.obfs.or(self.obfs_protocol);

        // Speed values may carry units ("1000 Mbps")
        if let Some(up) = self.up {
            hysteria.up_speed = parse_speed_mbps(&up);
        } else if let Some(up_speed) = self.up_speed {
            hysteria.up_speed = up_speed;
        }
        if let Some(down) = self.down {
            hysteria.down_speed = parse_speed_mbps(&down);
        } else if let Some(down_speed) = self.down_speed {
            hysteria.down_speed = down_speed;
        }

        hysteria.auth = self.auth;
        hysteria.auth_str = self.auth_str;
        hysteria.ca = self.ca;
        hysteria.ca_str = self.ca_str;
        hysteria.recv_window_conn = self.recv_window_conn.unwrap_or(0);
        hysteria.recv_window = self.recv_window.unwrap_or(0);
        hysteria.disable_mtu_discovery = self.disable_mtu_discovery;
        hysteria.hop_interval = self.hop_interval.unwrap_or(0);

        proxy.combined_proxy = Some(CombinedProxy::Hysteria(hysteria));
        proxy
    }
}

impl From<&Proxy> for ClashHysteria {
    fn from(proxy: &Proxy) -> Self {
        let mut out = ClashHysteria::default();
        out.common = ClashCommon::from_proxy(proxy);
        out.common.sni = proxy.sni.clone();
        out.fingerprint = proxy.fingerprint.clone();
        out.alpn = sorted_alpn(proxy);
        out.fast_open = proxy.tcp_fast_open;

        if let Some(hysteria) = proxy.as_hysteria() {
            out.ports = hysteria.ports.clone();
            out.protocol = hysteria.protocol.clone();
            out.obfs = hysteria.obfs.clone();

            if hysteria.up_speed > 0 {
                out.up = Some(format!("{} Mbps", hysteria.up_speed));
                out.up_speed = Some(hysteria.up_speed);
            }
            if hysteria.down_speed > 0 {
                out.down = Some(format!("{} Mbps", hysteria.down_speed));
                out.down_speed = Some(hysteria.down_speed);
            }

            out.auth = hysteria.auth.clone();
            out.auth_str = hysteria.auth_str.clone();
            out.ca = hysteria.ca.clone();
            out.ca_str = hysteria.ca_str.clone();
            out.recv_window_conn = Some(hysteria.recv_window_conn).filter(|v| !is_zero(v));
            out.recv_window = Some(hysteria.recv_window).filter(|v| !is_zero(v));
            out.disable_mtu_discovery = hysteria.disable_mtu_discovery;
            out.hop_interval = Some(hysteria.hop_interval).filter(|v| !is_zero(v));
        }

        out
    }
}
