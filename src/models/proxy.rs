//! Proxy model definitions
//!
//! Contains the core data structures for proxy configurations.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::proxy_node::combined::CombinedProxy;

/// Represents the type of a proxy.
/// This is the canonical enum used for proxy type identification across the
/// application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProxyType {
    Unknown,
    Shadowsocks,
    ShadowsocksR,
    VMess,
    Trojan,
    Snell,
    HTTP,
    HTTPS,
    Socks5,
    WireGuard,
    Hysteria,
    Hysteria2,
    // new proxy types could be added as enum combined proxy types
    Vless,
    AnyTls,
}

/// Converts a `ProxyType` into a human-readable name.
impl ProxyType {
    pub fn to_string(self) -> &'static str {
        match self {
            ProxyType::Shadowsocks => "SS",
            ProxyType::ShadowsocksR => "SSR",
            ProxyType::VMess => "VMess",
            ProxyType::Trojan => "Trojan",
            ProxyType::Snell => "Snell",
            ProxyType::HTTP => "HTTP",
            ProxyType::HTTPS => "HTTPS",
            ProxyType::Socks5 => "SOCKS5",
            ProxyType::WireGuard => "WireGuard",
            ProxyType::Hysteria => "Hysteria",
            ProxyType::Hysteria2 => "Hysteria2",
            ProxyType::Vless => "Vless",
            ProxyType::AnyTls => "AnyTLS",
            ProxyType::Unknown => "Unknown",
        }
    }
}

/// Represents a proxy configuration. Serialized for JavaScripts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Proxy {
    pub proxy_type: ProxyType,
    #[serde(flatten)]
    pub combined_proxy: Option<CombinedProxy>,
    pub id: u32,
    pub group_id: i32,
    pub group: String,
    pub remark: String,
    pub hostname: String,
    pub port: u16,

    pub username: Option<String>,
    pub password: Option<String>,
    pub encrypt_method: Option<String>,
    pub plugin: Option<String>,
    /// Plugin options in the format of `key1=value1;key2=value2`
    pub plugin_option: Option<String>,
    pub protocol: Option<String>,
    pub protocol_param: Option<String>,
    pub obfs: Option<String>,
    pub obfs_param: Option<String>,
    pub user_id: Option<String>,
    pub alter_id: u16,
    pub transfer_protocol: Option<String>,
    pub fake_type: Option<String>,
    pub tls_secure: bool,

    pub host: Option<String>,
    pub path: Option<String>,
    pub edge: Option<String>,

    pub quic_secure: Option<String>,
    pub quic_secret: Option<String>,

    pub udp: Option<bool>,
    pub tcp_fast_open: Option<bool>,
    pub allow_insecure: Option<bool>,
    pub tls13: Option<bool>,

    pub underlying_proxy: Option<String>,

    pub snell_version: u16,
    pub server_name: Option<String>,

    pub self_ip: Option<String>,
    pub self_ipv6: Option<String>,
    pub public_key: Option<String>,
    pub private_key: Option<String>,
    pub pre_shared_key: Option<String>,
    pub dns_servers: HashSet<String>,
    pub mtu: u16,
    pub allowed_ips: String,
    pub keep_alive: u16,
    pub test_url: Option<String>,
    pub client_id: Option<String>,

    pub ports: Option<String>,
    /// upload speed in Mbps
    pub up_speed: u32,
    /// download speed in Mbps
    pub down_speed: u32,
    pub auth: Option<String>,
    pub auth_str: Option<String>,
    pub sni: Option<String>,
    pub fingerprint: Option<String>,
    /// uTLS client fingerprint (e.g. "chrome"), distinct from the TLS
    /// certificate `fingerprint` above
    #[serde(default)]
    pub client_fingerprint: Option<String>,
    pub ca: Option<String>,
    pub ca_str: Option<String>,
    pub recv_window_conn: u32,
    pub recv_window: u32,
    pub disable_mtu_discovery: Option<bool>,
    pub hop_interval: u32,
    pub alpn: HashSet<String>,

    pub cwnd: u32,
}

/// Implement Default for Proxy
impl Default for Proxy {
    fn default() -> Self {
        Proxy {
            proxy_type: ProxyType::Unknown,
            combined_proxy: None,
            id: 0,
            group_id: 0,
            group: String::new(),
            remark: String::new(),
            hostname: String::new(),
            port: 0,
            username: None,
            password: None,
            encrypt_method: None,
            plugin: None,
            plugin_option: None,
            protocol: None,
            protocol_param: None,
            obfs: None,
            obfs_param: None,
            user_id: None,
            alter_id: 0,
            transfer_protocol: None,
            fake_type: None,
            tls_secure: false,
            host: None,
            path: None,
            edge: None,
            quic_secure: None,
            quic_secret: None,
            udp: None,
            tcp_fast_open: None,
            allow_insecure: None,
            tls13: None,
            underlying_proxy: None,
            snell_version: 0,
            server_name: None,
            self_ip: None,
            self_ipv6: None,
            public_key: None,
            private_key: None,
            pre_shared_key: None,
            dns_servers: HashSet::new(),
            mtu: 0,
            allowed_ips: String::from("0.0.0.0/0, ::/0"),
            keep_alive: 0,
            test_url: None,
            client_id: None,
            ports: None,
            up_speed: 0,
            down_speed: 0,
            auth: None,
            auth_str: None,
            sni: None,
            fingerprint: None,
            client_fingerprint: None,
            ca: None,
            ca_str: None,
            recv_window_conn: 0,
            recv_window: 0,
            disable_mtu_discovery: None,
            hop_interval: 0,
            alpn: HashSet::new(),
            cwnd: 0,
        }
    }
}
#[cfg(feature = "js-runtime")]
use rquickjs::{Ctx, IntoJs};
#[cfg(feature = "js-runtime")]
impl<'js> IntoJs<'js> for Proxy {
    fn into_js(self, ctx: &Ctx<'js>) -> Result<rquickjs::Value<'js>, rquickjs::Error> {
        let value =
            ctx.json_parse(
                serde_json::to_string(&self).map_err(|e| rquickjs::Error::IntoJs {
                    from: "Proxy",
                    to: "Json",
                    message: Some(e.to_string()),
                })?,
            )?;
        Ok(value)
    }
}

impl Proxy {
    pub fn is_combined_proxy(&self) -> bool {
        matches!(
            self.proxy_type,
            ProxyType::Vless | ProxyType::Shadowsocks | ProxyType::AnyTls
        )
    }

    /// 设置 UDP 支持，如果值已存在则不覆盖
    pub fn with_udp(mut self, udp: Option<bool>) -> Self {
        if self.udp.is_none() {
            self.udp = udp;
        }
        self
    }

    /// 强制设置 UDP 支持，不论是否已存在值
    pub fn set_udp(mut self, udp: bool) -> Self {
        self.udp = Some(udp);
        self
    }

    /// 设置 TCP Fast Open，如果值已存在则不覆盖
    pub fn with_tfo(mut self, tfo: Option<bool>) -> Self {
        if self.tcp_fast_open.is_none() {
            self.tcp_fast_open = tfo;
        }
        self
    }

    /// 强制设置 TCP Fast Open，不论是否已存在值
    pub fn set_tfo(mut self, tfo: bool) -> Self {
        self.tcp_fast_open = Some(tfo);
        self
    }

    /// 设置 Skip Cert Verify，如果值已存在则不覆盖
    pub fn with_skip_cert_verify(mut self, scv: Option<bool>) -> Self {
        if self.allow_insecure.is_none() {
            self.allow_insecure = scv;
        }
        self
    }

    /// 强制设置 Skip Cert Verify，不论是否已存在值
    pub fn set_skip_cert_verify(mut self, scv: bool) -> Self {
        self.allow_insecure = Some(scv);
        self
    }

    /// 设置代理备注
    pub fn set_remark(mut self, remark: String) -> Self {
        self.remark = remark;
        self
    }

    /// 使用默认值应用 tribool 属性，如果属性值为 None 则设置为提供的默认值
    pub fn apply_default_values(
        mut self,
        default_udp: Option<bool>,
        default_tfo: Option<bool>,
        default_scv: Option<bool>,
    ) -> Self {
        if self.udp.is_none() {
            self.udp = default_udp;
        }

        if self.tcp_fast_open.is_none() {
            self.tcp_fast_open = default_tfo;
        }

        if self.allow_insecure.is_none() {
            self.allow_insecure = default_scv;
        }

        self
    }
}

/// Default provider group names as constants.
pub const SS_DEFAULT_GROUP: &str = "SSProvider";
pub const SSR_DEFAULT_GROUP: &str = "SSRProvider";
pub const V2RAY_DEFAULT_GROUP: &str = "V2RayProvider";
pub const SOCKS_DEFAULT_GROUP: &str = "SocksProvider";
pub const HTTP_DEFAULT_GROUP: &str = "HTTPProvider";
pub const TROJAN_DEFAULT_GROUP: &str = "TrojanProvider";
pub const SNELL_DEFAULT_GROUP: &str = "SnellProvider";
pub const WG_DEFAULT_GROUP: &str = "WireGuardProvider";
pub const HYSTERIA_DEFAULT_GROUP: &str = "HysteriaProvider";
pub const HYSTERIA2_DEFAULT_GROUP: &str = "Hysteria2Provider";
pub const ANYTLS_DEFAULT_GROUP: &str = "AnyTLSProvider";
