use crate::utils::is_empty_option_string;
use crate::{generator::yaml::clash::output_proxy_types::*, Proxy, ProxyType};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a complete Clash configuration output
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClashYamlOutput {
    // General settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socks_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redir_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tproxy_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mixed_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_lan: Option<bool>,
    #[serde(alias = "bind-address", skip_serializing_if = "is_empty_option_string")]
    pub bind_address: Option<String>,
    #[serde(skip_serializing_if = "is_empty_option_string")]
    pub mode: Option<String>,
    #[serde(alias = "log-level", skip_serializing_if = "is_empty_option_string")]
    pub log_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<bool>,

    // DNS settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<ClashDns>,

    // Proxy settings
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub proxies: Vec<ClashProxyOutput>,

    #[serde(alias = "proxy-groups", skip_serializing_if = "Vec::is_empty")]
    pub proxy_groups: Vec<ClashProxyGroup>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<String>,

    // Additional fields (for compatibility with ClashR and other variants)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tun: Option<ClashTun>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<ClashProfile>,

    #[serde(flatten)]
    pub extra_options: HashMap<String, serde_yaml::Value>,
}

// Wrapper struct for custom serialization
pub struct SerializableClashYamlOutput<'a> {
    output: &'a ClashYamlOutput,
    use_new_field_names: bool,
}

impl<'a> SerializableClashYamlOutput<'a> {
    pub fn new(output: &'a ClashYamlOutput, use_new_field_names: bool) -> Self {
        Self {
            output,
            use_new_field_names,
        }
    }
}

// Custom Serialize implementation for the wrapper
impl<'a> Serialize for SerializableClashYamlOutput<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let output = self.output;
        let new_names = self.use_new_field_names;

        // Calculate the number of fields to serialize accurately
        let mut map_len = 0;
        if output.port.is_some() {
            map_len += 1;
        }
        if output.socks_port.is_some() {
            map_len += 1;
        }
        if output.redir_port.is_some() {
            map_len += 1;
        }
        if output.tproxy_port.is_some() {
            map_len += 1;
        }
        if output.mixed_port.is_some() {
            map_len += 1;
        }
        if output.allow_lan.is_some() {
            map_len += 1;
        }
        // Use the exact same filter logic as in serialization
        if output
            .bind_address
            .as_ref()
            .filter(|s| !s.is_empty())
            .is_some()
        {
            map_len += 1;
        }
        if output.mode.as_ref().filter(|s| !s.is_empty()).is_some() {
            map_len += 1;
        }
        if output
            .log_level
            .as_ref()
            .filter(|s| !s.is_empty())
            .is_some()
        {
            map_len += 1;
        }
        if output.ipv6.is_some() {
            map_len += 1;
        }
        if output.dns.is_some() {
            map_len += 1;
        }
        if !output.proxies.is_empty() {
            map_len += 1;
        }
        if !output.proxy_groups.is_empty() {
            map_len += 1;
        }
        if !output.rules.is_empty() {
            map_len += 1;
        }
        if output.tun.is_some() {
            map_len += 1;
        }
        if output.profile.is_some() {
            map_len += 1;
        }
        map_len += output.extra_options.len();

        let mut map = serializer.serialize_map(Some(map_len))?;

        // Serialize fields using kebab-case keys unless overridden
        if let Some(port) = output.port {
            map.serialize_entry("port", &port)?;
        }
        if let Some(socks_port) = output.socks_port {
            map.serialize_entry("socks-port", &socks_port)?;
        }
        if let Some(redir_port) = output.redir_port {
            map.serialize_entry("redir-port", &redir_port)?;
        }
        if let Some(tproxy_port) = output.tproxy_port {
            map.serialize_entry("tproxy-port", &tproxy_port)?;
        }
        if let Some(mixed_port) = output.mixed_port {
            map.serialize_entry("mixed-port", &mixed_port)?;
        }
        if let Some(allow_lan) = output.allow_lan {
            map.serialize_entry("allow-lan", &allow_lan)?;
        }
        if let Some(bind_address) = output.bind_address.as_ref().filter(|s| !s.is_empty()) {
            map.serialize_entry("bind-address", bind_address)?;
        }

        // Mode (dynamic key)
        if let Some(mode_val) = output.mode.as_ref().filter(|s| !s.is_empty()) {
            let mode_key = if new_names { "mode" } else { "Mode" };
            map.serialize_entry(mode_key, mode_val)?;
        }

        if let Some(log_level) = output.log_level.as_ref().filter(|s| !s.is_empty()) {
            map.serialize_entry("log-level", log_level)?;
        }
        if let Some(ipv6) = output.ipv6 {
            map.serialize_entry("ipv6", &ipv6)?;
        }
        if let Some(dns) = &output.dns {
            map.serialize_entry("dns", dns)?;
        }

        // Proxies (dynamic key)
        if !output.proxies.is_empty() {
            let proxies_key = if new_names { "proxies" } else { "Proxy" };
            map.serialize_entry(proxies_key, &output.proxies)?
        }

        // Proxy Groups (dynamic key)
        if !output.proxy_groups.is_empty() {
            let groups_key = if new_names {
                "proxy-groups"
            } else {
                "Proxy Group"
            };
            map.serialize_entry(groups_key, &output.proxy_groups)?
        }

        // Rules (dynamic key)
        if !output.rules.is_empty() {
            let rules_key = if new_names { "rules" } else { "Rule" };
            map.serialize_entry(rules_key, &output.rules)?
        }

        // Other complex fields
        if let Some(tun) = &output.tun {
            map.serialize_entry("tun", tun)?;
        }
        if let Some(profile) = &output.profile {
            map.serialize_entry("profile", profile)?;
        }

        // Flatten extra_options
        for (k, v) in &output.extra_options {
            map.serialize_entry(k, v)?;
        }

        map.end()
    }
}

/// DNS configuration for Clash
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashDns {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    #[serde(skip_serializing_if = "is_empty_option_string")]
    pub listen: Option<String>,
    #[serde(skip_serializing_if = "is_empty_option_string")]
    pub enhanced_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nameserver: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_filter: Option<ClashDnsFallbackFilter>,
    #[serde(flatten)]
    pub extra_options: HashMap<String, serde_yaml::Value>,
}

/// DNS fallback filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashDnsFallbackFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipcidr: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra_options: HashMap<String, serde_yaml::Value>,
}

/// TUN configuration for Clash
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashTun {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    #[serde(skip_serializing_if = "is_empty_option_string")]
    pub device: Option<String>,
    #[serde(skip_serializing_if = "is_empty_option_string")]
    pub stack: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_hijack: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_route: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_detect_interface: Option<bool>,
    #[serde(flatten)]
    pub extra_options: HashMap<String, serde_yaml::Value>,
}

/// Profile settings for Clash
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store_selected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store_fake_ip: Option<bool>,
    #[serde(flatten)]
    pub extra_options: HashMap<String, serde_yaml::Value>,
}

/// Represents a single proxy in Clash configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ClashProxyOutput {
    #[serde(rename = "ss")]
    Shadowsocks(ShadowsocksProxy),
    #[serde(rename = "ssr")]
    ShadowsocksR(ShadowsocksRProxy),
    #[serde(rename = "vmess")]
    VMess(VmessProxy),
    #[serde(rename = "trojan")]
    Trojan(TrojanProxy),
    #[serde(rename = "http")]
    Http(HttpProxy),
    #[serde(rename = "socks5")]
    Socks5(Socks5Proxy),
    #[serde(rename = "snell")]
    Snell(SnellProxy),
    #[serde(rename = "wireguard")]
    WireGuard(WireGuardProxy),
    #[serde(rename = "hysteria")]
    Hysteria(HysteriaProxy),
    #[serde(rename = "hysteria2")]
    Hysteria2(Hysteria2Proxy),
    #[serde(rename = "vless")]
    VLess(VLessProxy),
}

/// Factory methods for creating various proxy types
impl ClashProxyOutput {
    /// Create a new Shadowsocks proxy
    pub fn new_shadowsocks(common: CommonProxyOptions) -> Self {
        ClashProxyOutput::Shadowsocks(ShadowsocksProxy::new(common))
    }

    /// Create a new ShadowsocksR proxy
    pub fn new_shadowsocksr(common: CommonProxyOptions) -> Self {
        ClashProxyOutput::ShadowsocksR(ShadowsocksRProxy::new(common))
    }

    /// Create a new VMess proxy
    pub fn new_vmess(common: CommonProxyOptions) -> Self {
        ClashProxyOutput::VMess(VmessProxy::new(common))
    }

    /// Create a new HTTP proxy
    pub fn new_http(common: CommonProxyOptions) -> Self {
        ClashProxyOutput::Http(HttpProxy::new(common))
    }

    /// Create a new Trojan proxy
    pub fn new_trojan(common: CommonProxyOptions) -> Self {
        ClashProxyOutput::Trojan(TrojanProxy::new(common))
    }

    /// Create a new Socks5 proxy
    pub fn new_socks5(common: CommonProxyOptions) -> Self {
        ClashProxyOutput::Socks5(Socks5Proxy::new(common))
    }

    /// Create a new Snell proxy
    pub fn new_snell(common: CommonProxyOptions) -> Self {
        ClashProxyOutput::Snell(SnellProxy::new(common))
    }

    /// Create a new WireGuard proxy
    pub fn new_wireguard(common: CommonProxyOptions) -> Self {
        ClashProxyOutput::WireGuard(WireGuardProxy::new(common))
    }

    /// Create a new Hysteria proxy
    pub fn new_hysteria(common: CommonProxyOptions) -> Self {
        ClashProxyOutput::Hysteria(HysteriaProxy::new(common))
    }

    /// Create a new Hysteria2 proxy
    pub fn new_hysteria2(common: CommonProxyOptions) -> Self {
        ClashProxyOutput::Hysteria2(Hysteria2Proxy::new(common))
    }

    /// Create a new VLESS proxy
    pub fn new_vless(common: CommonProxyOptions) -> Self {
        ClashProxyOutput::VLess(VLessProxy::new(common))
    }
}

/// Trait for common operations on all ClashProxy variants
pub trait ClashProxyCommon {
    /// Get a reference to the common options
    fn common(&self) -> &CommonProxyOptions;

    /// Get a mutable reference to the common options
    fn common_mut(&mut self) -> &mut CommonProxyOptions;

    /// Set a TFO (TCP Fast Open) option
    fn set_tfo(&mut self, value: bool) {
        self.common_mut().tfo = Some(value);
    }

    /// Set a UDP option
    fn set_udp(&mut self, value: bool) {
        self.common_mut().udp = Some(value);
    }

    /// Set skip certificate verification option
    fn set_skip_cert_verify(&mut self, value: bool) {
        self.common_mut().skip_cert_verify = Some(value);
    }

    /// Set TLS option
    fn set_tls(&mut self, value: bool) {
        self.common_mut().tls = Some(value);
    }

    /// Set SNI option
    fn set_sni(&mut self, value: String) {
        self.common_mut().sni = Some(value);
    }

    /// Set fingerprint option
    fn set_fingerprint(&mut self, value: String) {
        self.common_mut().fingerprint = Some(value);
    }
}

impl ClashProxyCommon for ClashProxyOutput {
    fn common(&self) -> &CommonProxyOptions {
        match self {
            ClashProxyOutput::Shadowsocks(proxy) => &proxy.common,
            ClashProxyOutput::ShadowsocksR(proxy) => &proxy.common,
            ClashProxyOutput::VMess(proxy) => &proxy.common,
            ClashProxyOutput::Trojan(proxy) => &proxy.common,
            ClashProxyOutput::Http(proxy) => &proxy.common,
            ClashProxyOutput::Socks5(proxy) => &proxy.common,
            ClashProxyOutput::Snell(proxy) => &proxy.common,
            ClashProxyOutput::WireGuard(proxy) => &proxy.common,
            ClashProxyOutput::Hysteria(proxy) => &proxy.common,
            ClashProxyOutput::Hysteria2(proxy) => &proxy.common,
            ClashProxyOutput::VLess(proxy) => &proxy.common,
        }
    }

    fn common_mut(&mut self) -> &mut CommonProxyOptions {
        match self {
            ClashProxyOutput::Shadowsocks(proxy) => &mut proxy.common,
            ClashProxyOutput::ShadowsocksR(proxy) => &mut proxy.common,
            ClashProxyOutput::VMess(proxy) => &mut proxy.common,
            ClashProxyOutput::Trojan(proxy) => &mut proxy.common,
            ClashProxyOutput::Http(proxy) => &mut proxy.common,
            ClashProxyOutput::Socks5(proxy) => &mut proxy.common,
            ClashProxyOutput::Snell(proxy) => &mut proxy.common,
            ClashProxyOutput::WireGuard(proxy) => &mut proxy.common,
            ClashProxyOutput::Hysteria(proxy) => &mut proxy.common,
            ClashProxyOutput::Hysteria2(proxy) => &mut proxy.common,
            ClashProxyOutput::VLess(proxy) => &mut proxy.common,
        }
    }
}

/// Represents a proxy group in Clash configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ClashProxyGroup {
    #[serde(rename = "select")]
    Select {
        name: String,
        proxies: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        r#use: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        disable_udp: Option<bool>,
    },
    #[serde(rename = "url-test")]
    UrlTest {
        name: String,
        proxies: Vec<String>,
        url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        interval: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tolerance: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        lazy: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        disable_udp: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        r#use: Option<Vec<String>>,
    },
    #[serde(rename = "fallback")]
    Fallback {
        name: String,
        proxies: Vec<String>,
        url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        interval: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tolerance: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        disable_udp: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        r#use: Option<Vec<String>>,
    },
    #[serde(rename = "load-balance")]
    LoadBalance {
        name: String,
        proxies: Vec<String>,
        strategy: String,
        #[serde(skip_serializing_if = "is_empty_option_string")]
        url: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        interval: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tolerance: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        lazy: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        disable_udp: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        r#use: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        persistent: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        evaluate_before_use: Option<bool>,
    },
    #[serde(rename = "relay")]
    Relay {
        name: String,
        proxies: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        disable_udp: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        r#use: Option<Vec<String>>,
    },
}

impl ClashProxyGroup {
    /// Returns a reference to the name of the proxy group.
    pub fn name(&self) -> &str {
        match self {
            ClashProxyGroup::Select { name, .. } => name,
            ClashProxyGroup::UrlTest { name, .. } => name,
            ClashProxyGroup::Fallback { name, .. } => name,
            ClashProxyGroup::LoadBalance { name, .. } => name,
            ClashProxyGroup::Relay { name, .. } => name,
        }
    }
}

/// Implementation of From trait for ClashProxyOutput
impl From<Proxy> for ClashProxyOutput {
    fn from(proxy: Proxy) -> Self {
        match proxy.proxy_type {
            ProxyType::Shadowsocks => ClashProxyOutput::Shadowsocks(ShadowsocksProxy::from(proxy)),
            ProxyType::ShadowsocksR => {
                ClashProxyOutput::ShadowsocksR(ShadowsocksRProxy::from(proxy))
            }
            ProxyType::VMess => ClashProxyOutput::VMess(VmessProxy::from(proxy)),
            ProxyType::Vless => ClashProxyOutput::VLess(VLessProxy::from(proxy)),
            ProxyType::Trojan => ClashProxyOutput::Trojan(TrojanProxy::from(proxy)),
            ProxyType::HTTP | ProxyType::HTTPS => ClashProxyOutput::Http(HttpProxy::from(proxy)),
            ProxyType::Socks5 => ClashProxyOutput::Socks5(Socks5Proxy::from(proxy)),
            ProxyType::Snell => {
                // Skip Snell v4+ if exists - exactly matching C++ behavior
                if proxy.snell_version >= 4 {
                    // 为了处理这种特殊情况，我们返回一个默认的Snell代理
                    // 调用方应该检查snell_version并据此跳过这个代理
                    let common = CommonProxyOptions::builder(
                        proxy.remark.clone(),
                        proxy.hostname.clone(),
                        proxy.port,
                    )
                    .build();
                    ClashProxyOutput::Snell(SnellProxy::new(common))
                } else {
                    ClashProxyOutput::Snell(SnellProxy::from(proxy))
                }
            }
            ProxyType::WireGuard => ClashProxyOutput::WireGuard(WireGuardProxy::from(proxy)),
            ProxyType::Hysteria => ClashProxyOutput::Hysteria(HysteriaProxy::from(proxy)),
            ProxyType::Hysteria2 => ClashProxyOutput::Hysteria2(Hysteria2Proxy::from(proxy)),
            _ => {
                // 遇到不支持的类型，返回一个默认的HTTP代理
                // 实际使用时应该在转换前检查并筛选掉不支持的类型
                let common = CommonProxyOptions::builder(
                    proxy.remark.clone(),
                    proxy.hostname.clone(),
                    proxy.port,
                )
                .build();
                ClashProxyOutput::Http(HttpProxy::new(common))
            }
        }
    }
}
