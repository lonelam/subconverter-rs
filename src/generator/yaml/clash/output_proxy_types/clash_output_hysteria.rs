use super::CommonProxyOptions;
use crate::models::Proxy;
use crate::utils::{is_empty_option_string, is_u32_option_zero};
use serde::{Deserialize, Serialize};

/// Hysteria proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HysteriaProxy {
    #[serde(flatten)]
    pub common: CommonProxyOptions,
    #[serde(skip_serializing_if = "is_empty_option_string")]
    pub ports: Option<String>,
    #[serde(skip_serializing_if = "is_empty_option_string")]
    pub protocol: Option<String>,
    #[serde(
        rename = "obfs-protocol",
        skip_serializing_if = "is_empty_option_string"
    )]
    pub obfs_protocol: Option<String>,
    #[serde(skip_serializing_if = "is_empty_option_string")]
    pub up: Option<String>,
    #[serde(rename = "up-speed", skip_serializing_if = "is_u32_option_zero")]
    pub up_speed: Option<u32>,
    #[serde(skip_serializing_if = "is_empty_option_string")]
    pub down: Option<String>,
    #[serde(rename = "down-speed", skip_serializing_if = "is_u32_option_zero")]
    pub down_speed: Option<u32>,
    #[serde(skip_serializing_if = "is_empty_option_string")]
    pub auth: Option<String>,
    #[serde(rename = "auth-str", skip_serializing_if = "is_empty_option_string")]
    pub auth_str: Option<String>,
    #[serde(skip_serializing_if = "is_empty_option_string")]
    pub obfs: Option<String>,
    #[serde(skip_serializing_if = "is_empty_option_string")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    #[serde(skip_serializing_if = "is_empty_option_string")]
    pub ca: Option<String>,
    #[serde(rename = "ca-str", skip_serializing_if = "is_empty_option_string")]
    pub ca_str: Option<String>,
    #[serde(
        rename = "recv-window-conn",
        skip_serializing_if = "is_u32_option_zero"
    )]
    pub recv_window_conn: Option<u32>,
    #[serde(rename = "recv-window", skip_serializing_if = "is_u32_option_zero")]
    pub recv_window: Option<u32>,
    #[serde(
        rename = "disable-mtu-discovery",
        skip_serializing_if = "Option::is_none"
    )]
    pub disable_mtu_discovery: Option<bool>,
    #[serde(rename = "fast-open", skip_serializing_if = "Option::is_none")]
    pub fast_open: Option<bool>,
    #[serde(rename = "hop-interval", skip_serializing_if = "is_u32_option_zero")]
    pub hop_interval: Option<u32>,
}

impl HysteriaProxy {
    /// Create a new Hysteria proxy
    pub fn new(common: CommonProxyOptions) -> Self {
        Self {
            common,
            ports: None,
            protocol: None,
            obfs_protocol: None,
            up: None,
            up_speed: None,
            down: None,
            down_speed: None,
            auth: None,
            auth_str: None,
            obfs: None,
            fingerprint: None,
            alpn: None,
            ca: None,
            ca_str: None,
            recv_window_conn: None,
            recv_window: None,
            disable_mtu_discovery: None,
            fast_open: None,
            hop_interval: None,
        }
    }
}

impl From<Proxy> for HysteriaProxy {
    fn from(proxy: Proxy) -> Self {
        let common =
            CommonProxyOptions::builder(proxy.remark.clone(), proxy.hostname.clone(), proxy.port)
                .udp(proxy.udp)
                .tfo(proxy.tcp_fast_open)
                .skip_cert_verify(proxy.allow_insecure)
                .sni(proxy.sni.clone())
                .build();

        let mut hysteria = HysteriaProxy::new(common);

        hysteria.ports = proxy.ports;
        hysteria.protocol = proxy.protocol;

        if proxy.up_speed > 0 {
            hysteria.up = Some(format!("{} Mbps", proxy.up_speed));
            hysteria.up_speed = Some(proxy.up_speed);
        }

        if proxy.down_speed > 0 {
            hysteria.down = Some(format!("{} Mbps", proxy.down_speed));
            hysteria.down_speed = Some(proxy.down_speed);
        }

        hysteria.auth = proxy.auth;
        hysteria.auth_str = proxy.auth_str;

        hysteria.obfs = proxy.obfs.clone();
        hysteria.fingerprint = proxy.fingerprint;

        if !proxy.alpn.is_empty() {
            let mut alpn: Vec<String> = proxy.alpn.into_iter().collect();
            alpn.sort();
            hysteria.alpn = Some(alpn);
        }

        hysteria.ca = proxy.ca;
        hysteria.ca_str = proxy.ca_str;

        if proxy.recv_window_conn > 0 {
            hysteria.recv_window_conn = Some(proxy.recv_window_conn);
        }

        if proxy.recv_window > 0 {
            hysteria.recv_window = Some(proxy.recv_window);
        }

        hysteria.disable_mtu_discovery = proxy.disable_mtu_discovery;
        hysteria.fast_open = proxy.tcp_fast_open;

        if proxy.hop_interval > 0 {
            hysteria.hop_interval = Some(proxy.hop_interval);
        }

        hysteria
    }
}
