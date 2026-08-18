//! Unified bidirectional Clash proxy schema.
//!
//! One struct per protocol serves both parsing (`Deserialize`, with the
//! aliases and lenient value handling Clash configs need in the wild) and
//! generation (`Serialize`, with the exact field order and skip rules the
//! emitted YAML uses). Each struct converts to and from the internal
//! [`crate::models::Proxy`] representation, so a parse → emit roundtrip is
//! lossless by construction.

mod anytls;
mod common;
mod http;
mod hysteria;
mod hysteria2;
mod shadowsocks;
mod shadowsocksr;
mod snell;
mod socks5;
mod trojan;
mod tuic;
mod vless;
mod vmess;
mod wireguard;

pub use anytls::ClashAnyTls;
pub use common::ClashCommon;
pub use http::ClashHttp;
pub use hysteria::ClashHysteria;
pub use hysteria2::ClashHysteria2;
pub use shadowsocks::ClashShadowsocks;
pub use shadowsocksr::ClashShadowsocksR;
pub use snell::ClashSnell;
pub use socks5::ClashSocks5;
pub use trojan::ClashTrojan;
pub use tuic::ClashTuic;
pub use vless::ClashVless;
pub use vmess::ClashVmess;
pub use wireguard::ClashWireGuard;

use crate::models::{Proxy, ProxyType};
use serde::{Deserialize, Serialize};

/// A single proxy entry in a Clash configuration, tagged by `type`.
/// Used for both deserializing `proxies:` sections and serializing them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ClashProxy {
    #[serde(rename = "ss")]
    Shadowsocks(ClashShadowsocks),
    #[serde(rename = "ssr")]
    ShadowsocksR(ClashShadowsocksR),
    #[serde(rename = "vmess")]
    VMess(ClashVmess),
    #[serde(rename = "trojan")]
    Trojan(ClashTrojan),
    #[serde(rename = "http")]
    Http(ClashHttp),
    #[serde(rename = "socks5")]
    Socks5(ClashSocks5),
    #[serde(rename = "snell")]
    Snell(ClashSnell),
    #[serde(rename = "wireguard")]
    WireGuard(ClashWireGuard),
    #[serde(rename = "hysteria")]
    Hysteria(ClashHysteria),
    #[serde(rename = "hysteria2")]
    Hysteria2(ClashHysteria2),
    #[serde(rename = "tuic")]
    Tuic(ClashTuic),
    #[serde(rename = "vless")]
    VLess(ClashVless),
    #[serde(rename = "anytls")]
    AnyTls(ClashAnyTls),
    /// Unknown proxy type; skipped on input, never constructed for output
    #[serde(other)]
    Unknown,
}

impl ClashProxy {
    /// Convert this typed Clash proxy into the internal [`Proxy`] model.
    /// Returns `None` for unknown proxy types.
    pub fn into_proxy(self) -> Option<Proxy> {
        match self {
            ClashProxy::Shadowsocks(inner) => Some(inner.into_proxy()),
            ClashProxy::ShadowsocksR(inner) => Some(inner.into_proxy()),
            ClashProxy::VMess(inner) => Some(inner.into_proxy()),
            ClashProxy::Trojan(inner) => Some(inner.into_proxy()),
            ClashProxy::Http(inner) => Some(inner.into_proxy()),
            ClashProxy::Socks5(inner) => Some(inner.into_proxy()),
            ClashProxy::Snell(inner) => Some(inner.into_proxy()),
            ClashProxy::WireGuard(inner) => Some(inner.into_proxy()),
            ClashProxy::Hysteria(inner) => Some(inner.into_proxy()),
            ClashProxy::Hysteria2(inner) => Some(inner.into_proxy()),
            ClashProxy::Tuic(inner) => Some(inner.into_proxy()),
            ClashProxy::VLess(inner) => Some(inner.into_proxy()),
            ClashProxy::AnyTls(inner) => Some(inner.into_proxy()),
            ClashProxy::Unknown => None,
        }
    }

    /// Whether this entry is the Unknown placeholder.
    pub fn is_unknown(&self) -> bool {
        matches!(self, ClashProxy::Unknown)
    }

    /// Build the Clash representation of a [`Proxy`], if the protocol is
    /// expressible in a Clash configuration.
    pub fn from_proxy(proxy: &Proxy) -> Option<Self> {
        match proxy.proxy_type {
            ProxyType::Shadowsocks => Some(ClashProxy::Shadowsocks(ClashShadowsocks::from(proxy))),
            ProxyType::ShadowsocksR => {
                Some(ClashProxy::ShadowsocksR(ClashShadowsocksR::from(proxy)))
            }
            ProxyType::VMess => Some(ClashProxy::VMess(ClashVmess::from(proxy))),
            ProxyType::Trojan => Some(ClashProxy::Trojan(ClashTrojan::from(proxy))),
            ProxyType::HTTP | ProxyType::HTTPS => Some(ClashProxy::Http(ClashHttp::from(proxy))),
            ProxyType::Socks5 => Some(ClashProxy::Socks5(ClashSocks5::from(proxy))),
            ProxyType::Snell => Some(ClashProxy::Snell(ClashSnell::from(proxy))),
            ProxyType::WireGuard => Some(ClashProxy::WireGuard(ClashWireGuard::from(proxy))),
            ProxyType::Hysteria => Some(ClashProxy::Hysteria(ClashHysteria::from(proxy))),
            ProxyType::Hysteria2 => Some(ClashProxy::Hysteria2(ClashHysteria2::from(proxy))),
            ProxyType::Tuic => Some(ClashProxy::Tuic(ClashTuic::from(proxy))),
            ProxyType::Vless => Some(ClashProxy::VLess(ClashVless::from(proxy))),
            ProxyType::AnyTls => Some(ClashProxy::AnyTls(ClashAnyTls::from(proxy))),
            ProxyType::Unknown => None,
        }
    }
}

impl From<Proxy> for ClashProxy {
    fn from(proxy: Proxy) -> Self {
        ClashProxy::from_proxy(&proxy).unwrap_or(ClashProxy::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_one(yaml: &str) -> Proxy {
        let clash: ClashProxy = serde_yaml::from_str(yaml).expect("entry must parse");
        clash.into_proxy().expect("known proxy type")
    }

    fn emit(proxy: &Proxy) -> String {
        serde_yaml::to_string(&ClashProxy::from_proxy(proxy).expect("expressible")).unwrap()
    }

    /// Issue #40: ws-opts, tls, udp and servername survive parsing.
    #[test]
    fn test_vmess_ws_opts_tls_preserved() {
        let proxy = parse_one(
            r#"{"name":"vmess-jp1","type":"vmess","server":"tokyo1.example.top","port":10000,"uuid":"b445361a-abcf-aaaa-a97a-0bf4136d6ddc","alterId":0,"cipher":"auto","udp":true,"tls":true,"network":"ws","ws-opts":{"path":"/vm","headers":{"Host":"tokyo1.example.top"}},"servername":"tokyo1.example.top"}"#,
        );
        assert_eq!(proxy.proxy_type, ProxyType::VMess);
        assert_eq!(proxy.udp, Some(true));
        assert!(proxy.tls_secure);
        assert_eq!(proxy.sni.as_deref(), Some("tokyo1.example.top"));
        assert_eq!(proxy.transfer_protocol(), Some("ws"));
        assert_eq!(proxy.path(), Some("/vm"));
        assert_eq!(proxy.host(), Some("tokyo1.example.top"));
    }

    #[test]
    fn test_vmess_missing_cipher_defaults_to_auto() {
        let proxy =
            parse_one(r#"{"name":"n","type":"vmess","server":"s.example.com","port":443,"uuid":"u"}"#);
        assert_eq!(proxy.encrypt_method(), Some("auto"));
    }

    /// Issue #44: alpn and the uTLS fingerprint survive parsing.
    #[test]
    fn test_trojan_alpn_and_fingerprint_preserved() {
        let proxy = parse_one(
            r#"{name: node, type: trojan, server: example.com, port: 443, password: secret, udp: true, alpn: [h2, "http/1.1"], skip-cert-verify: false, utls-fingerprint: chrome}"#,
        );
        assert!(proxy.tls_secure);
        assert!(proxy.alpn.contains("h2"));
        assert!(proxy.alpn.contains("http/1.1"));
        assert_eq!(proxy.client_fingerprint.as_deref(), Some("chrome"));
        assert_eq!(proxy.allow_insecure, Some(false));
    }

    /// Issues #41/#42: reality-opts survive parsing including unknown keys.
    #[test]
    fn test_vless_reality_opts_preserved() {
        let proxy = parse_one(
            r#"{"name":"reality","type":"vless","server":"2.22.22.22","port":13340,"uuid":"56b8aaaa","network":"grpc","tls":true,"udp":true,"client-fingerprint":"chrome","grpc-opts":{"grpc-service-name":"grpc"},"reality-opts":{"public-key":"bY9DOyBw","short-id":""},"smux":{"enabled":true},"servername":"addons.mozilla.org"}"#,
        );
        let vless = proxy.as_vless().expect("vless options");
        assert_eq!(vless.reality_public_key.as_deref(), Some("bY9DOyBw"));
        assert_eq!(vless.reality_short_id.as_deref(), Some(""));
        assert_eq!(vless.grpc_service_name.as_deref(), Some("grpc"));
        assert_eq!(proxy.client_fingerprint.as_deref(), Some("chrome"));
        assert_eq!(proxy.sni.as_deref(), Some("addons.mozilla.org"));
        assert!(proxy.tls_secure);
    }

    /// Issue #37: hysteria speeds with units and alpn lists survive.
    #[test]
    fn test_hysteria_speed_with_unit_and_alpn() {
        let proxy = parse_one(
            r#"{name: serves, server: 192.168.1.1, port: 62003, type: hysteria, auth-str: auth, up: 1000 Mbps, down: 1000 Mbps, protocol: none, skip-cert-verify: true, alpn: [h3]}"#,
        );
        assert_eq!(proxy.up_speed(), 1000);
        assert_eq!(proxy.down_speed(), 1000);
        assert!(proxy.alpn.contains("h3"));
        assert_eq!(proxy.auth_str(), Some("auth"));
        assert_eq!(proxy.allow_insecure, Some(true));
    }

    /// The bidirectional schema must be idempotent: parse -> emit -> parse ->
    /// emit yields identical output for every protocol.
    #[test]
    fn test_roundtrip_idempotent_for_all_protocols() {
        let entries = [
            r#"{name: ss, type: ss, server: s.example.com, port: 8388, cipher: aes-256-gcm, password: "pw==", udp: true, plugin: obfs, plugin-opts: {mode: http, host: bing.com}}"#,
            r#"{name: ssr, type: ssr, server: s.example.com, port: 8389, cipher: aes-128-cfb, password: pw, protocol: auth_aes128_md5, protocol-param: "32", obfs: http_simple, obfs-param: o.example.com}"#,
            r#"{name: vm, type: vmess, server: s.example.com, port: 443, uuid: u, alterId: 0, cipher: auto, udp: true, tls: true, network: ws, servername: sni.example.com, ws-opts: {path: /ws, headers: {Host: h.example.com}}}"#,
            r#"{name: tr, type: trojan, server: s.example.com, port: 443, password: pw, sni: sni.example.com, alpn: [h2], network: grpc, grpc-opts: {grpc-service-name: svc}}"#,
            r#"{name: vl, type: vless, server: s.example.com, port: 443, uuid: u, network: ws, tls: true, servername: sni.example.com, ws-opts: {path: /ws}, reality-opts: {public-key: pk, short-id: "01"}}"#,
            r#"{name: hy, type: hysteria, server: s.example.com, port: 443, auth-str: a, up: 100, down: 100, protocol: udp, alpn: [h3]}"#,
            r#"{name: hy2, type: hysteria2, server: s.example.com, port: 443, password: pw, obfs: salamander, obfs-password: opw, sni: sni.example.com}"#,
            r#"{name: sn, type: snell, server: s.example.com, port: 44046, psk: pk, version: 4, obfs-opts: {mode: http, host: bing.com}}"#,
            r#"{name: ht, type: http, server: s.example.com, port: 8080, username: u, password: pw}"#,
            r#"{name: so, type: socks5, server: s.example.com, port: 1080, username: u, password: pw, udp: true}"#,
            r#"{name: wg, type: wireguard, server: s.example.com, port: 51820, private-key: pk, public-key: pub, ip: 10.0.0.2, dns: [1.1.1.1], mtu: 1420, udp: true}"#,
            r#"{name: at, type: anytls, server: s.example.com, port: 8443, password: pw, sni: sni.example.com, client-fingerprint: chrome, udp: true}"#,
            r#"{name: tu, type: tuic, server: s.example.com, port: 443, uuid: u, password: pw, congestion-controller: bbr, udp-relay-mode: native, alpn: [h3], sni: sni.example.com}"#,
        ];
        for entry in entries {
            let first = parse_one(entry);
            let emitted1 = emit(&first);
            let second: ClashProxy = serde_yaml::from_str(&emitted1)
                .unwrap_or_else(|e| panic!("re-parse failed for {}: {}", entry, e));
            let second = second.into_proxy().expect("known type");
            let emitted2 = emit(&second);
            assert_eq!(emitted1, emitted2, "roundtrip not stable for {}", entry);
        }
    }
}
