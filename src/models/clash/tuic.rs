use super::common::{apply_alpn, sorted_alpn, ClashCommon};
use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::proxy_node::tuic::TuicProxy;
use crate::models::{Proxy, ProxyType};
use crate::utils::deserialize::deserialize_string_or_vec;
use crate::utils::is_empty_option_string;
use serde::{Deserialize, Serialize};

/// TUIC proxy in a Clash (mihomo) configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashTuic {
    #[serde(flatten)]
    pub common: ClashCommon,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub password: Option<String>,
    /// v4 legacy token
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_interval: Option<u32>,
    #[serde(
        default,
        deserialize_with = "deserialize_string_or_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub alpn: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_sni: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reduce_rtt: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout: Option<u32>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub udp_relay_mode: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub congestion_controller: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_udp_relay_packet_size: Option<u32>,
}

impl ClashTuic {
    pub fn into_proxy(self) -> Proxy {
        let mut proxy = Proxy::default();
        proxy.proxy_type = ProxyType::Tuic;
        self.common.apply_to_proxy(&mut proxy);
        // TUIC always runs over QUIC/TLS
        proxy.tls_secure = true;
        proxy.sni = self.common.sni.clone();
        proxy.fingerprint = self.common.fingerprint.clone();
        apply_alpn(&mut proxy, self.alpn);

        proxy.combined_proxy = Some(CombinedProxy::Tuic(TuicProxy {
            uuid: self.uuid.unwrap_or_default(),
            password: self.password.unwrap_or_default(),
            token: self.token,
            ip: self.ip,
            heartbeat_interval: self.heartbeat_interval,
            congestion_controller: self.congestion_controller,
            udp_relay_mode: self.udp_relay_mode,
            reduce_rtt: self.reduce_rtt,
            request_timeout: self.request_timeout,
            max_udp_relay_packet_size: self.max_udp_relay_packet_size,
            disable_sni: self.disable_sni,
        }));

        proxy
    }
}

impl From<&Proxy> for ClashTuic {
    fn from(proxy: &Proxy) -> Self {
        let mut out = ClashTuic::default();
        out.common = ClashCommon::from_proxy(proxy);
        out.common.sni = proxy.sni.clone();
        out.common.fingerprint = proxy.fingerprint.clone();
        out.alpn = sorted_alpn(proxy);

        if let Some(tuic) = proxy.as_tuic() {
            if !tuic.uuid.is_empty() {
                out.uuid = Some(tuic.uuid.clone());
            }
            if !tuic.password.is_empty() {
                out.password = Some(tuic.password.clone());
            }
            out.token = tuic.token.clone();
            out.ip = tuic.ip.clone();
            out.heartbeat_interval = tuic.heartbeat_interval;
            out.disable_sni = tuic.disable_sni;
            out.reduce_rtt = tuic.reduce_rtt;
            out.request_timeout = tuic.request_timeout;
            out.udp_relay_mode = tuic.udp_relay_mode.clone();
            out.congestion_controller = tuic.congestion_controller.clone();
            out.max_udp_relay_packet_size = tuic.max_udp_relay_packet_size;
        }

        out
    }
}
