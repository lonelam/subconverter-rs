use serde::Deserialize;

use crate::models::proxy::Proxy;
use crate::models::proxy::ProxyType;
use crate::utils::deserialize::{
    deserialize_string_or_number, deserialize_string_or_vec, parse_speed_mbps,
};
use crate::utils::tribool::OptionSetExt;

/// Represents a Hysteria proxy in Clash configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub struct ClashInputHysteria {
    name: String,
    server: String,
    port: u16,
    #[serde(default)]
    ports: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(alias = "obfs-protocol", default)]
    obfs_protocol: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_number")]
    up: Option<String>,
    #[serde(alias = "up_speed", default)]
    up_speed: Option<u32>,
    #[serde(default, deserialize_with = "deserialize_string_or_number")]
    down: Option<String>,
    #[serde(alias = "down_speed", default)]
    down_speed: Option<u32>,
    #[serde(default)]
    auth: Option<String>,
    #[serde(alias = "auth_str", default)]
    auth_str: Option<String>,
    #[serde(default)]
    obfs: Option<String>,
    #[serde(default)]
    sni: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    alpn: Option<Vec<String>>,
    #[serde(default)]
    ca: Option<String>,
    #[serde(alias = "ca-str", default)]
    ca_str: Option<String>,
    #[serde(alias = "recv-window-conn", default)]
    recv_window_conn: Option<u32>,
    #[serde(alias = "recv-window", default)]
    recv_window: Option<u32>,
    #[serde(alias = "disable_mtu_discovery", default)]
    disable_mtu_discovery: Option<bool>,
    #[serde(alias = "fast-open", default)]
    fast_open: Option<bool>,
    #[serde(alias = "hop-interval", default)]
    hop_interval: Option<u32>,
    #[serde(alias = "skip-cert-verify", default)]
    skip_cert_verify: Option<bool>,
    #[serde(default)]
    tfo: Option<bool>,
}

impl ClashInputHysteria {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn ports(&self) -> Option<&str> {
        self.ports.as_deref()
    }

    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    pub fn obfs_protocol(&self) -> Option<&str> {
        self.obfs_protocol.as_deref()
    }

    pub fn up(&self) -> Option<&str> {
        self.up.as_deref()
    }

    pub fn up_speed(&self) -> Option<u32> {
        self.up_speed
    }

    pub fn down(&self) -> Option<&str> {
        self.down.as_deref()
    }

    pub fn down_speed(&self) -> Option<u32> {
        self.down_speed
    }

    pub fn auth(&self) -> Option<&str> {
        self.auth.as_deref()
    }

    pub fn auth_str(&self) -> Option<&str> {
        self.auth_str.as_deref()
    }

    pub fn obfs(&self) -> Option<&str> {
        self.obfs.as_deref()
    }

    pub fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }

    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }

    pub fn alpn(&self) -> Option<&Vec<String>> {
        self.alpn.as_ref()
    }

    pub fn ca(&self) -> Option<&str> {
        self.ca.as_deref()
    }

    pub fn ca_str(&self) -> Option<&str> {
        self.ca_str.as_deref()
    }

    pub fn recv_window_conn(&self) -> Option<u32> {
        self.recv_window_conn
    }

    pub fn recv_window(&self) -> Option<u32> {
        self.recv_window
    }

    pub fn disable_mtu_discovery(&self) -> Option<bool> {
        self.disable_mtu_discovery
    }

    pub fn fast_open(&self) -> Option<bool> {
        self.fast_open
    }

    pub fn hop_interval(&self) -> Option<u32> {
        self.hop_interval
    }

    pub fn skip_cert_verify(&self) -> Option<bool> {
        self.skip_cert_verify
    }

    pub fn tfo(&self) -> Option<bool> {
        self.tfo
    }
}

impl Into<Proxy> for ClashInputHysteria {
    fn into(self) -> Proxy {
        let mut proxy = Proxy::default();
        proxy.proxy_type = ProxyType::Hysteria;
        proxy.remark = self.name;
        proxy.hostname = self.server;
        proxy.port = self.port;
        proxy.ports = self.ports;
        proxy.protocol = self.protocol;

        // Handle upload/download speed; values may carry units ("1000 Mbps")
        if let Some(up_value) = self.up {
            proxy.up_speed = parse_speed_mbps(&up_value);
        } else if let Some(up_speed) = self.up_speed {
            proxy.up_speed = up_speed;
        }

        if let Some(down_value) = self.down {
            proxy.down_speed = parse_speed_mbps(&down_value);
        } else if let Some(down_speed) = self.down_speed {
            proxy.down_speed = down_speed;
        }

        // Set authentication
        proxy.auth = self.auth;
        proxy.auth_str = self.auth_str;

        // Set obfuscation (`obfs`, falling back to the legacy `obfs-protocol`)
        proxy.obfs = self.obfs.or(self.obfs_protocol);

        // Set TLS related fields
        proxy.sni = self.sni;
        proxy.fingerprint = self.fingerprint;

        // Handle alpn as a HashSet
        if let Some(alpn_values) = self.alpn {
            for value in alpn_values {
                proxy.alpn.insert(value);
            }
        }

        proxy.ca = self.ca;
        proxy.ca_str = self.ca_str;

        // Set window sizes
        proxy.recv_window_conn = self.recv_window_conn.unwrap_or(0);
        proxy.recv_window = self.recv_window.unwrap_or(0);

        // Set boolean options
        proxy
            .disable_mtu_discovery
            .set_if_some(self.disable_mtu_discovery);
        proxy.tcp_fast_open.set_if_some(self.fast_open.or(self.tfo));
        proxy.allow_insecure.set_if_some(self.skip_cert_verify);

        // Set hop interval
        proxy.hop_interval = self.hop_interval.unwrap_or(0);

        proxy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduces https://github.com/lonelam/subconverter-rs/issues/37 —
    /// `up`/`down` with a "Mbps" suffix and list-valued `alpn` must survive.
    #[test]
    fn test_hysteria_speed_with_unit_and_alpn() {
        let yaml = r#"{name: serves, server: 192.168.1.1, port: 62003, type: hysteria, auth-str: auth, up: 1000 Mbps, down: 1000 Mbps, protocol: none, skip-cert-verify: true, alpn: [h3]}"#;
        let hysteria: ClashInputHysteria = serde_yaml::from_str(yaml).unwrap();
        let proxy: Proxy = hysteria.into();

        assert_eq!(proxy.up_speed, 1000);
        assert_eq!(proxy.down_speed, 1000);
        assert!(proxy.alpn.contains("h3"));
        assert_eq!(proxy.auth_str.as_deref(), Some("auth"));
        assert_eq!(proxy.allow_insecure, Some(true));
    }

    #[test]
    fn test_hysteria_alpn_as_string() {
        let yaml =
            r#"{name: n, server: s.example.com, port: 443, type: hysteria, alpn: h3, up: 100, down: 100}"#;
        let hysteria: ClashInputHysteria = serde_yaml::from_str(yaml).unwrap();
        let proxy: Proxy = hysteria.into();
        assert!(proxy.alpn.contains("h3"));
        assert_eq!(proxy.up_speed, 100);
    }
}
