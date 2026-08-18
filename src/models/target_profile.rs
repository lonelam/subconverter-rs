//! Target client profiles and their capability matrices.
//!
//! Different builds and versions of the same client family accept different
//! protocols and fields. The capability matrix makes those differences
//! explicit data instead of scattered conditionals, so an emitter can ask
//! "does this target support X?" in one place.

use super::ProxyType;

/// Which flavor of the Clash family the output targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClashFlavor {
    /// mihomo / Clash.Meta: the maintained superset. Default because it
    /// accepts everything this converter can express.
    #[default]
    Mihomo,
    /// The original closed-source Clash Premium core.
    Premium,
    /// Stash on iOS/macOS (mihomo-like, but no uTLS fingerprints).
    Stash,
}

impl ClashFlavor {
    /// Parse a `flavor=` query value. Unknown values fall back to mihomo.
    pub fn from_str(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "premium" | "original" | "classic" | "clash" => ClashFlavor::Premium,
            "stash" => ClashFlavor::Stash,
            _ => ClashFlavor::Mihomo,
        }
    }

    /// The capability set of this flavor.
    pub fn capabilities(&self) -> &'static ClashCapabilities {
        match self {
            ClashFlavor::Mihomo => &MIHOMO_CAPABILITIES,
            ClashFlavor::Premium => &PREMIUM_CAPABILITIES,
            ClashFlavor::Stash => &STASH_CAPABILITIES,
        }
    }
}

/// What a Clash-family client accepts.
#[derive(Debug, Clone)]
pub struct ClashCapabilities {
    /// Protocols the client can load at all; nodes of other types are
    /// dropped instead of producing a config the client rejects.
    pub supported_protocols: &'static [ProxyType],
    /// Whether `client-fingerprint` (uTLS) is understood.
    pub client_fingerprint: bool,
    /// Whether `reality-opts` is understood.
    pub reality: bool,
    /// Whether `udp-over-tcp` is understood.
    pub udp_over_tcp: bool,
}

impl ClashCapabilities {
    pub fn supports(&self, proxy_type: ProxyType) -> bool {
        self.supported_protocols.contains(&proxy_type)
    }
}

static MIHOMO_CAPABILITIES: ClashCapabilities = ClashCapabilities {
    supported_protocols: &[
        ProxyType::Shadowsocks,
        ProxyType::ShadowsocksR,
        ProxyType::VMess,
        ProxyType::Trojan,
        ProxyType::Snell,
        ProxyType::HTTP,
        ProxyType::HTTPS,
        ProxyType::Socks5,
        ProxyType::WireGuard,
        ProxyType::Hysteria,
        ProxyType::Hysteria2,
        ProxyType::Vless,
        ProxyType::AnyTls,
    ],
    client_fingerprint: true,
    reality: true,
    udp_over_tcp: true,
};

static PREMIUM_CAPABILITIES: ClashCapabilities = ClashCapabilities {
    supported_protocols: &[
        ProxyType::Shadowsocks,
        ProxyType::ShadowsocksR,
        ProxyType::VMess,
        ProxyType::Trojan,
        ProxyType::Snell,
        ProxyType::HTTP,
        ProxyType::HTTPS,
        ProxyType::Socks5,
        ProxyType::WireGuard,
    ],
    client_fingerprint: false,
    reality: false,
    udp_over_tcp: false,
};

static STASH_CAPABILITIES: ClashCapabilities = ClashCapabilities {
    supported_protocols: &[
        ProxyType::Shadowsocks,
        ProxyType::ShadowsocksR,
        ProxyType::VMess,
        ProxyType::Trojan,
        ProxyType::Snell,
        ProxyType::HTTP,
        ProxyType::HTTPS,
        ProxyType::Socks5,
        ProxyType::WireGuard,
        ProxyType::Hysteria,
        ProxyType::Hysteria2,
        ProxyType::Vless,
    ],
    // Stash has no uTLS support
    client_fingerprint: false,
    reality: true,
    udp_over_tcp: false,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flavor_parsing() {
        assert_eq!(ClashFlavor::from_str("premium"), ClashFlavor::Premium);
        assert_eq!(ClashFlavor::from_str("STASH"), ClashFlavor::Stash);
        assert_eq!(ClashFlavor::from_str("meta"), ClashFlavor::Mihomo);
        assert_eq!(ClashFlavor::from_str("mihomo"), ClashFlavor::Mihomo);
        assert_eq!(ClashFlavor::from_str(""), ClashFlavor::Mihomo);
    }

    #[test]
    fn test_premium_capabilities() {
        let caps = ClashFlavor::Premium.capabilities();
        assert!(caps.supports(ProxyType::Shadowsocks));
        assert!(!caps.supports(ProxyType::Vless));
        assert!(!caps.supports(ProxyType::Hysteria2));
        assert!(!caps.client_fingerprint);
        assert!(!caps.reality);
    }
}
