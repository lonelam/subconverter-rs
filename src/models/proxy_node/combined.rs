use serde::{Deserialize, Serialize};

use super::anytls::AnyTlsProxy;
use super::http::HttpProxy;
use super::hysteria::HysteriaProxy;
use super::hysteria2::Hysteria2Proxy;
use super::shadowsocks::ShadowsocksProxy;
use super::shadowsocksr::ShadowsocksRProxy;
use super::snell::SnellProxy;
use super::socks5::Socks5Proxy;
use super::trojan::TrojanProxy;
use super::vless::VlessProxy;
use super::vmess::VmessProxy;
use super::wireguard::WireGuardProxy;

/// Protocol-specific options of a proxy node. This is the single home for
/// per-protocol data; fields shared across protocols (server, port, TLS
/// settings, udp/tfo flags, ...) live directly on [`crate::models::Proxy`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", tag = "combined_type")]
pub enum CombinedProxy {
    Vless(VlessProxy),
    Shadowsocks(ShadowsocksProxy),
    AnyTls(AnyTlsProxy),
    VMess(VmessProxy),
    ShadowsocksR(ShadowsocksRProxy),
    Trojan(TrojanProxy),
    Snell(SnellProxy),
    Http(HttpProxy),
    Socks5(Socks5Proxy),
    WireGuard(WireGuardProxy),
    Hysteria(HysteriaProxy),
    Hysteria2(Hysteria2Proxy),
}
