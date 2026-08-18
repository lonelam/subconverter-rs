//! Proxy model definitions
//!
//! Contains the core data structures for proxy configurations.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::proxy_node::anytls::AnyTlsProxy;
use super::proxy_node::combined::CombinedProxy;
use super::proxy_node::http::HttpProxy;
use super::proxy_node::hysteria::HysteriaProxy;
use super::proxy_node::hysteria2::Hysteria2Proxy;
use super::proxy_node::shadowsocks::ShadowsocksProxy;
use super::proxy_node::shadowsocksr::ShadowsocksRProxy;
use super::proxy_node::snell::SnellProxy;
use super::proxy_node::socks5::Socks5Proxy;
use super::proxy_node::trojan::TrojanProxy;
use super::proxy_node::tuic::TuicProxy;
use super::proxy_node::vless::VlessProxy;
use super::proxy_node::vmess::VmessProxy;
use super::proxy_node::wireguard::WireGuardProxy;

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
    Vless,
    AnyTls,
    Tuic,
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
            ProxyType::Tuic => "TUIC",
            ProxyType::Unknown => "Unknown",
        }
    }
}

/// Represents a proxy configuration. Serialized for JavaScripts.
///
/// Fields shared across protocols (endpoint, TLS parameters, transport
/// behavior flags) live directly on this struct; everything protocol-specific
/// lives in [`CombinedProxy`] so each piece of information has exactly one
/// home.
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

    /// Whether the node supports UDP relay
    pub udp: Option<bool>,
    /// TCP Fast Open
    pub tcp_fast_open: Option<bool>,
    /// Skip certificate verification
    pub allow_insecure: Option<bool>,
    pub tls13: Option<bool>,
    pub underlying_proxy: Option<String>,

    /// Whether the connection is TLS-secured
    pub tls_secure: bool,
    /// TLS server name indication
    pub sni: Option<String>,
    /// TLS ALPN protocols
    pub alpn: HashSet<String>,
    /// TLS certificate fingerprint
    pub fingerprint: Option<String>,
    /// uTLS client fingerprint (e.g. "chrome"), distinct from the TLS
    /// certificate `fingerprint` above
    #[serde(default)]
    pub client_fingerprint: Option<String>,
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
            udp: None,
            tcp_fast_open: None,
            allow_insecure: None,
            tls13: None,
            underlying_proxy: None,
            tls_secure: false,
            sni: None,
            alpn: HashSet::new(),
            fingerprint: None,
            client_fingerprint: None,
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

macro_rules! typed_accessors {
    ($as_ref:ident, $as_mut:ident, $variant:ident, $ty:ty) => {
        pub fn $as_ref(&self) -> Option<&$ty> {
            match &self.combined_proxy {
                Some(CombinedProxy::$variant(inner)) => Some(inner),
                _ => None,
            }
        }

        pub fn $as_mut(&mut self) -> Option<&mut $ty> {
            match &mut self.combined_proxy {
                Some(CombinedProxy::$variant(inner)) => Some(inner),
                _ => None,
            }
        }
    };
}

impl Proxy {
    typed_accessors!(as_shadowsocks, as_shadowsocks_mut, Shadowsocks, ShadowsocksProxy);
    typed_accessors!(
        as_shadowsocksr,
        as_shadowsocksr_mut,
        ShadowsocksR,
        ShadowsocksRProxy
    );
    typed_accessors!(as_vmess, as_vmess_mut, VMess, VmessProxy);
    typed_accessors!(as_trojan, as_trojan_mut, Trojan, TrojanProxy);
    typed_accessors!(as_snell, as_snell_mut, Snell, SnellProxy);
    typed_accessors!(as_http, as_http_mut, Http, HttpProxy);
    typed_accessors!(as_socks5, as_socks5_mut, Socks5, Socks5Proxy);
    typed_accessors!(as_wireguard, as_wireguard_mut, WireGuard, WireGuardProxy);
    typed_accessors!(as_hysteria, as_hysteria_mut, Hysteria, HysteriaProxy);
    typed_accessors!(as_hysteria2, as_hysteria2_mut, Hysteria2, Hysteria2Proxy);
    typed_accessors!(as_vless, as_vless_mut, Vless, VlessProxy);
    typed_accessors!(as_tuic, as_tuic_mut, Tuic, TuicProxy);
    typed_accessors!(as_anytls, as_anytls_mut, AnyTls, AnyTlsProxy);

    /// The password / PSK / auth secret of the node, regardless of protocol.
    pub fn password(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::Shadowsocks(ss)) => Some(ss.password.as_str()),
            Some(CombinedProxy::ShadowsocksR(ssr)) => Some(ssr.password.as_str()),
            Some(CombinedProxy::Trojan(trojan)) => Some(trojan.password.as_str()),
            Some(CombinedProxy::Http(http)) => http.password.as_deref(),
            Some(CombinedProxy::Socks5(socks)) => socks.password.as_deref(),
            Some(CombinedProxy::Snell(snell)) => Some(snell.psk.as_str()),
            Some(CombinedProxy::Hysteria2(hy2)) => Some(hy2.password.as_str()),
            Some(CombinedProxy::AnyTls(anytls)) => Some(anytls.password.as_str()),
            _ => None,
        }
    }

    pub fn username(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::Http(http)) => http.username.as_deref(),
            Some(CombinedProxy::Socks5(socks)) => socks.username.as_deref(),
            _ => None,
        }
    }

    /// Encryption method (ss/ssr cipher, vmess cipher).
    pub fn encrypt_method(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::Shadowsocks(ss)) => Some(ss.cipher.as_str()),
            Some(CombinedProxy::ShadowsocksR(ssr)) => Some(ssr.cipher.as_str()),
            Some(CombinedProxy::VMess(vmess)) => vmess.cipher.as_deref(),
            _ => None,
        }
    }

    /// UUID of vmess/vless nodes.
    pub fn user_id(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::VMess(vmess)) => Some(vmess.uuid.as_str()),
            Some(CombinedProxy::Vless(vless)) => Some(vless.uuid.as_str()),
            _ => None,
        }
    }

    pub fn alter_id(&self) -> u16 {
        match &self.combined_proxy {
            Some(CombinedProxy::VMess(vmess)) => vmess.alter_id,
            _ => 0,
        }
    }

    /// Transport network (tcp/ws/h2/http/grpc) of vmess/trojan/vless nodes.
    pub fn transfer_protocol(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::VMess(vmess)) => vmess.network.as_deref(),
            Some(CombinedProxy::Trojan(trojan)) => trojan.network.as_deref(),
            Some(CombinedProxy::Vless(vless)) => vless.network.as_deref(),
            _ => None,
        }
    }

    /// Transport host header. For snell this is the obfs host.
    pub fn host(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::VMess(vmess)) => vmess.host.as_deref(),
            Some(CombinedProxy::Trojan(trojan)) => trojan.host.as_deref(),
            Some(CombinedProxy::Snell(snell)) => snell.obfs_host.as_deref(),
            _ => None,
        }
    }

    /// Transport path (ws path / h2 path / grpc service name).
    pub fn path(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::VMess(vmess)) => vmess.path.as_deref(),
            Some(CombinedProxy::Trojan(trojan)) => trojan.path.as_deref(),
            _ => None,
        }
    }

    pub fn edge(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::VMess(vmess)) => vmess.edge.as_deref(),
            _ => None,
        }
    }

    pub fn fake_type(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::VMess(vmess)) => vmess.fake_type.as_deref(),
            _ => None,
        }
    }

    pub fn quic_secure(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::VMess(vmess)) => vmess.quic_secure.as_deref(),
            _ => None,
        }
    }

    pub fn quic_secret(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::VMess(vmess)) => vmess.quic_secret.as_deref(),
            _ => None,
        }
    }

    /// SSR protocol / hysteria transport protocol.
    pub fn protocol(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::ShadowsocksR(ssr)) => ssr.protocol.as_deref(),
            Some(CombinedProxy::Hysteria(hysteria)) => hysteria.protocol.as_deref(),
            _ => None,
        }
    }

    pub fn protocol_param(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::ShadowsocksR(ssr)) => ssr.protocol_param.as_deref(),
            _ => None,
        }
    }

    pub fn obfs(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::ShadowsocksR(ssr)) => ssr.obfs.as_deref(),
            Some(CombinedProxy::Snell(snell)) => snell.obfs.as_deref(),
            Some(CombinedProxy::Hysteria(hysteria)) => hysteria.obfs.as_deref(),
            Some(CombinedProxy::Hysteria2(hy2)) => hy2.obfs.as_deref(),
            _ => None,
        }
    }

    /// SSR obfs parameter / hysteria2 obfs password.
    pub fn obfs_param(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::ShadowsocksR(ssr)) => ssr.obfs_param.as_deref(),
            Some(CombinedProxy::Hysteria2(hy2)) => hy2.obfs_password.as_deref(),
            _ => None,
        }
    }

    pub fn plugin(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::Shadowsocks(ss)) => ss.plugin.as_deref(),
            _ => None,
        }
    }

    pub fn plugin_option(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::Shadowsocks(ss)) => ss.plugin_opts.as_deref(),
            _ => None,
        }
    }

    pub fn snell_version(&self) -> u16 {
        match &self.combined_proxy {
            Some(CombinedProxy::Snell(snell)) => snell.version,
            _ => 0,
        }
    }

    pub fn up_speed(&self) -> u32 {
        match &self.combined_proxy {
            Some(CombinedProxy::Hysteria(hysteria)) => hysteria.up_speed,
            Some(CombinedProxy::Hysteria2(hy2)) => hy2.up_speed,
            _ => 0,
        }
    }

    pub fn down_speed(&self) -> u32 {
        match &self.combined_proxy {
            Some(CombinedProxy::Hysteria(hysteria)) => hysteria.down_speed,
            Some(CombinedProxy::Hysteria2(hy2)) => hy2.down_speed,
            _ => 0,
        }
    }

    pub fn auth(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::Hysteria(hysteria)) => hysteria.auth.as_deref(),
            _ => None,
        }
    }

    pub fn auth_str(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::Hysteria(hysteria)) => hysteria.auth_str.as_deref(),
            _ => None,
        }
    }

    pub fn ports(&self) -> Option<&str> {
        match &self.combined_proxy {
            Some(CombinedProxy::Hysteria(hysteria)) => hysteria.ports.as_deref(),
            Some(CombinedProxy::Hysteria2(hy2)) => hy2.ports.as_deref(),
            _ => None,
        }
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
pub const TUIC_DEFAULT_GROUP: &str = "TuicProvider";
