use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::proxy_node::http::HttpProxy;
use crate::models::proxy_node::hysteria::HysteriaProxy;
use crate::models::proxy_node::hysteria2::Hysteria2Proxy;
use crate::models::proxy_node::shadowsocks::ShadowsocksProxy;
use crate::models::proxy_node::shadowsocksr::ShadowsocksRProxy;
use crate::models::proxy_node::snell::SnellProxy;
use crate::models::proxy_node::socks5::Socks5Proxy;
use crate::models::proxy_node::trojan::TrojanProxy;
use crate::models::proxy_node::vmess::VmessProxy;
use crate::models::proxy_node::wireguard::WireGuardProxy;
use crate::{Proxy, ProxyType};

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

impl Proxy {
    pub fn common_construct(
        proxy_type: ProxyType,
        group: &str,
        remark: &str,
        server: &str,
        port: u16,
        udp: Option<bool>,
        tfo: Option<bool>,
        scv: Option<bool>,
        tls13: Option<bool>,
        underlying_proxy: &str,
    ) -> Self {
        Proxy {
            proxy_type,
            group: group.to_owned(),
            remark: remark.to_owned(),
            hostname: server.to_owned(),
            port,
            udp,
            tcp_fast_open: tfo,
            allow_insecure: scv,
            tls13,
            underlying_proxy: Some(underlying_proxy.to_owned()),
            ..Default::default()
        }
    }

    pub fn vmess_construct(
        group: &str,
        remark: &str,
        add: &str,
        port: u16,
        typ: &str,
        id: &str,
        aid: u16,
        net: &str,
        cipher: &str,
        path: &str,
        host: &str,
        edge: &str,
        tls: &str,
        sni: &str,
        udp: Option<bool>,
        tfo: Option<bool>,
        scv: Option<bool>,
        tls13: Option<bool>,
        underlying_proxy: &str,
    ) -> Self {
        let mut proxy = Proxy::common_construct(
            ProxyType::VMess,
            group,
            remark,
            add,
            port,
            udp,
            tfo,
            scv,
            tls13,
            underlying_proxy,
        );

        let mut vmess = VmessProxy::default();
        vmess.uuid = if id.is_empty() {
            "00000000-0000-0000-0000-000000000000".to_owned()
        } else {
            id.to_owned()
        };
        vmess.alter_id = aid;
        vmess.cipher = non_empty(cipher);
        vmess.network = Some(if net.is_empty() { "tcp" } else { net }.to_owned());
        vmess.edge = non_empty(edge);
        vmess.fake_type = Some(typ.to_owned());

        proxy.sni = non_empty(sni);
        proxy.tls_secure = tls == "tls";

        if net == "quic" {
            vmess.quic_secure = Some(host.to_owned());
            vmess.quic_secret = Some(path.to_owned());
        } else {
            vmess.host = Some(
                if host.is_empty() && !add.parse::<std::net::IpAddr>().is_ok() {
                    add.to_owned()
                } else {
                    host.trim().to_owned()
                },
            );
            vmess.path = Some(if path.is_empty() { "/" } else { path.trim() }.to_owned());
        }

        proxy.combined_proxy = Some(CombinedProxy::VMess(vmess));
        proxy
    }

    pub fn ssr_construct(
        group: &str,
        remark: &str,
        server: &str,
        port: u16,
        protocol: &str,
        method: &str,
        obfs: &str,
        password: &str,
        obfs_param: &str,
        proto_param: &str,
        udp: Option<bool>,
        tfo: Option<bool>,
        scv: Option<bool>,
        underlying_proxy: &str,
    ) -> Self {
        let mut proxy = Proxy::common_construct(
            ProxyType::ShadowsocksR,
            group,
            remark,
            server,
            port,
            udp,
            tfo,
            scv,
            None,
            underlying_proxy,
        );

        proxy.combined_proxy = Some(CombinedProxy::ShadowsocksR(ShadowsocksRProxy {
            password: password.to_owned(),
            cipher: method.to_owned(),
            protocol: Some(protocol.to_owned()),
            protocol_param: Some(proto_param.to_owned()),
            obfs: Some(obfs.to_owned()),
            obfs_param: Some(obfs_param.to_owned()),
        }));

        proxy
    }

    pub fn ss_construct(
        group: &str,
        remark: &str,
        server: &str,
        port: u16,
        password: &str,
        method: &str,
        plugin: &str,
        plugin_opts: &str,
        udp: Option<bool>,
        tfo: Option<bool>,
        scv: Option<bool>,
        tls13: Option<bool>,
        underlying_proxy: &str,
    ) -> Self {
        let mut proxy = Proxy::common_construct(
            ProxyType::Shadowsocks,
            group,
            remark,
            server,
            port,
            udp,
            tfo,
            scv,
            tls13,
            underlying_proxy,
        );

        proxy.combined_proxy = Some(CombinedProxy::Shadowsocks(ShadowsocksProxy {
            password: password.to_owned(),
            cipher: method.to_owned(),
            plugin: non_empty(plugin),
            plugin_opts: non_empty(plugin_opts),
            udp_over_tcp: None,
            udp_over_tcp_version: None,
        }));

        proxy
    }

    pub fn socks_construct(
        group: &str,
        remark: &str,
        server: &str,
        port: u16,
        username: &str,
        password: &str,
        udp: Option<bool>,
        tfo: Option<bool>,
        scv: Option<bool>,
        underlying_proxy: &str,
    ) -> Self {
        let mut proxy = Proxy::common_construct(
            ProxyType::Socks5,
            group,
            remark,
            server,
            port,
            udp,
            tfo,
            scv,
            None,
            underlying_proxy,
        );
        proxy.combined_proxy = Some(CombinedProxy::Socks5(Socks5Proxy {
            username: Some(username.to_owned()),
            password: Some(password.to_owned()),
        }));

        proxy
    }

    pub fn http_construct(
        group: &str,
        remark: &str,
        server: &str,
        port: u16,
        username: &str,
        password: &str,
        tls: bool,
        tfo: Option<bool>,
        scv: Option<bool>,
        tls13: Option<bool>,
        underlying_proxy: &str,
    ) -> Self {
        let mut proxy = Proxy::common_construct(
            if tls {
                ProxyType::HTTPS
            } else {
                ProxyType::HTTP
            },
            group,
            remark,
            server,
            port,
            None,
            tfo,
            scv,
            tls13,
            underlying_proxy,
        );
        proxy.combined_proxy = Some(CombinedProxy::Http(HttpProxy {
            username: Some(username.to_owned()),
            password: Some(password.to_owned()),
        }));
        proxy.tls_secure = tls;

        proxy
    }

    pub fn trojan_construct(
        group: String,
        remark: String,
        hostname: String,
        port: u16,
        password: String,
        network: Option<String>,
        host: Option<String>,
        path: Option<String>,
        sni: Option<String>,
        tls_secure: bool,
        udp: Option<bool>,
        tfo: Option<bool>,
        allow_insecure: Option<bool>,
        tls13: Option<bool>,
        underlying_proxy: Option<String>,
    ) -> Self {
        Proxy {
            proxy_type: ProxyType::Trojan,
            group,
            remark,
            hostname,
            port,
            combined_proxy: Some(CombinedProxy::Trojan(TrojanProxy {
                password,
                network,
                host,
                path,
            })),
            sni,
            tls_secure,
            udp,
            tcp_fast_open: tfo,
            allow_insecure,
            tls13,
            underlying_proxy,
            ..Default::default()
        }
    }

    pub fn snell_construct(
        group: String,
        remark: String,
        hostname: String,
        port: u16,
        password: String,
        obfs: String,
        host: String,
        version: u16,
        udp: Option<bool>,
        tfo: Option<bool>,
        allow_insecure: Option<bool>,
        underlying_proxy: Option<String>,
    ) -> Self {
        Proxy {
            proxy_type: ProxyType::Snell,
            group,
            remark,
            hostname,
            port,
            combined_proxy: Some(CombinedProxy::Snell(SnellProxy {
                psk: password,
                version,
                obfs: Some(obfs),
                obfs_host: Some(host),
            })),
            udp,
            tcp_fast_open: tfo,
            allow_insecure,
            underlying_proxy,
            ..Default::default()
        }
    }

    pub fn wireguard_construct(
        group: String,
        remark: String,
        hostname: String,
        port: u16,
        self_ip: String,
        self_ipv6: String,
        private_key: String,
        public_key: String,
        preshared_key: String,
        dns_servers: Vec<String>,
        mtu: Option<u16>,
        keep_alive: Option<u16>,
        test_url: String,
        client_id: String,
        udp: Option<bool>,
        underlying_proxy: Option<String>,
    ) -> Self {
        Proxy {
            proxy_type: ProxyType::WireGuard,
            group,
            remark,
            hostname,
            port,
            combined_proxy: Some(CombinedProxy::WireGuard(WireGuardProxy {
                self_ip: Some(self_ip),
                self_ipv6: Some(self_ipv6),
                private_key: Some(private_key),
                public_key: Some(public_key),
                pre_shared_key: Some(preshared_key),
                dns_servers,
                mtu: mtu.unwrap_or(0),
                allowed_ips: String::from("0.0.0.0/0, ::/0"),
                keep_alive: keep_alive.unwrap_or(0),
                test_url: Some(test_url),
                client_id: Some(client_id),
            })),
            udp,
            underlying_proxy,
            ..Default::default()
        }
    }

    pub fn hysteria2_construct(
        group: String,
        remark: String,
        hostname: String,
        port: u16,
        ports: Option<String>,
        up_speed: Option<u32>,
        down_speed: Option<u32>,
        password: String,
        obfs: Option<String>,
        obfs_param: Option<String>,
        sni: Option<String>,
        fingerprint: Option<String>,
        alpn: Vec<String>,
        ca: Option<String>,
        ca_str: Option<String>,
        cwnd: Option<u32>,
        tcp_fast_open: Option<bool>,
        allow_insecure: Option<bool>,
        underlying_proxy: Option<String>,
    ) -> Self {
        let mut alpn_set = std::collections::HashSet::new();
        for proto in alpn {
            alpn_set.insert(proto);
        }

        Proxy {
            proxy_type: ProxyType::Hysteria2,
            group,
            remark,
            hostname,
            port,
            combined_proxy: Some(CombinedProxy::Hysteria2(Hysteria2Proxy {
                password,
                ports,
                obfs,
                obfs_password: obfs_param,
                up_speed: up_speed.unwrap_or(0),
                down_speed: down_speed.unwrap_or(0),
                ca,
                ca_str,
                cwnd: cwnd.unwrap_or(0),
                udp_mtu: 0,
                recv_window_conn: 0,
                recv_window: 0,
                disable_mtu_discovery: None,
                hop_interval: 0,
            })),
            sni,
            fingerprint,
            alpn: alpn_set,
            tcp_fast_open,
            allow_insecure,
            underlying_proxy,
            ..Default::default()
        }
    }

    pub fn hysteria_construct(
        group: String,
        remark: String,
        hostname: String,
        port: u16,
        ports: String,
        protocol: String,
        obfs_param: String,
        up_speed: Option<u32>,
        down_speed: Option<u32>,
        auth_str: String,
        obfs: String,
        sni: String,
        fingerprint: String,
        ca: String,
        ca_str: String,
        recv_window_conn: Option<u32>,
        recv_window: Option<u32>,
        disable_mtu_discovery: Option<bool>,
        hop_interval: Option<u32>,
        alpn: Vec<String>,
        tcp_fast_open: Option<bool>,
        allow_insecure: Option<bool>,
        underlying_proxy: Option<String>,
    ) -> Self {
        let mut alpn_set = std::collections::HashSet::new();
        for proto in alpn {
            alpn_set.insert(proto);
        }
        // The legacy parameter carried the obfs string in `obfs` and an
        // optional parameter in `obfs_param`; keep the first non-empty one.
        let _ = obfs_param;

        Proxy {
            proxy_type: ProxyType::Hysteria,
            group,
            remark,
            hostname,
            port,
            combined_proxy: Some(CombinedProxy::Hysteria(HysteriaProxy {
                ports: Some(ports),
                protocol: Some(protocol),
                obfs: Some(obfs),
                up_speed: up_speed.unwrap_or(0),
                down_speed: down_speed.unwrap_or(0),
                auth: None,
                auth_str: Some(auth_str),
                ca: Some(ca),
                ca_str: Some(ca_str),
                recv_window_conn: recv_window_conn.unwrap_or(0),
                recv_window: recv_window.unwrap_or(0),
                disable_mtu_discovery,
                hop_interval: hop_interval.unwrap_or(0),
            })),
            sni: Some(sni),
            fingerprint: Some(fingerprint),
            alpn: alpn_set,
            tcp_fast_open,
            allow_insecure,
            underlying_proxy,
            ..Default::default()
        }
    }
}
