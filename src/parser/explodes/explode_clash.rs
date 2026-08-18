use crate::{
    models::{
        Proxy, HTTP_DEFAULT_GROUP, HYSTERIA2_DEFAULT_GROUP, HYSTERIA_DEFAULT_GROUP,
        SNELL_DEFAULT_GROUP, SOCKS_DEFAULT_GROUP, SSR_DEFAULT_GROUP, SS_DEFAULT_GROUP,
        TROJAN_DEFAULT_GROUP, V2RAY_DEFAULT_GROUP, WG_DEFAULT_GROUP,
    },
    parser::yaml::clash::{extract_proxy_entries, ClashProxyYamlInput},
};
use serde_yaml::Value;

/// Parse a Clash YAML configuration into a vector of Proxy objects.
///
/// Each proxy entry is parsed independently: the typed serde-based parser is
/// tried first and, if it rejects the entry, the legacy field-by-field parser
/// is used as a fallback. A malformed node is logged and skipped instead of
/// discarding the whole subscription.
pub fn explode_clash(content: &str, nodes: &mut Vec<Proxy>) -> bool {
    let yaml: Value = match serde_yaml::from_str(content) {
        Ok(y) => y,
        Err(e) => {
            log::warn!("Failed to parse Clash YAML: {}", e);
            return false;
        }
    };

    let proxies = match extract_proxy_entries(&yaml) {
        Some(seq) => seq,
        None => return false,
    };

    let mut success = false;

    for entry in proxies {
        // Try the typed parser first
        match serde_yaml::from_value::<ClashProxyYamlInput>(entry.clone()) {
            Ok(typed) => {
                if let Some(node) = typed.into_proxy() {
                    nodes.push(node);
                    success = true;
                    continue;
                }
            }
            Err(e) => {
                log::debug!(
                    "Typed Clash proxy parser rejected entry ({}), trying legacy parser",
                    e
                );
            }
        }

        // Fall back to the legacy per-entry parser
        if let Some(node) = parse_clash_proxy(entry) {
            nodes.push(node);
            success = true;
        } else {
            log::warn!("Skipping unparsable Clash proxy entry");
        }
    }

    success
}

/// Parse a single proxy from Clash YAML
fn parse_clash_proxy(proxy: &Value) -> Option<Proxy> {
    // Extract the proxy type
    let proxy_type = match proxy.get("type") {
        Some(Value::String(t)) => t.to_lowercase(),
        _ => return None,
    };

    // Extract common fields
    let name = proxy.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let server = proxy.get("server").and_then(|v| v.as_str()).unwrap_or("");
    let port_value = proxy.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
    let port = port_value as u16;

    // Skip if missing essential information
    if name.is_empty() || server.is_empty() || port == 0 {
        return None;
    }

    // Extract common optional fields
    let udp = proxy.get("udp").and_then(|v| v.as_bool());
    let tfo = proxy.get("tfo").and_then(|v| v.as_bool());
    let skip_cert_verify = proxy.get("skip-cert-verify").and_then(|v| v.as_bool());

    // Process based on proxy type
    match proxy_type.as_str() {
        "ss" | "shadowsocks" => {
            parse_clash_ss(proxy, name, server, port, udp, tfo, skip_cert_verify)
        }
        "ssr" | "shadowsocksr" => {
            parse_clash_ssr(proxy, name, server, port, udp, tfo, skip_cert_verify)
        }
        "vmess" => parse_clash_vmess(proxy, name, server, port, udp, tfo, skip_cert_verify),
        "socks" | "socks5" => {
            parse_clash_socks(proxy, name, server, port, udp, tfo, skip_cert_verify)
        }
        "http" => parse_clash_http(proxy, name, server, port, false, tfo, skip_cert_verify),
        "https" => parse_clash_http(proxy, name, server, port, true, tfo, skip_cert_verify),
        "trojan" => parse_clash_trojan(proxy, name, server, port, udp, tfo, skip_cert_verify),
        "snell" => parse_clash_snell(proxy, name, server, port, udp, tfo, skip_cert_verify),
        "wireguard" => parse_clash_wireguard(proxy, name, server, port, udp),
        "hysteria" => parse_clash_hysteria(proxy, name, server, port, tfo, skip_cert_verify),
        "hysteria2" => parse_clash_hysteria2(proxy, name, server, port, tfo, skip_cert_verify),
        _ => None,
    }
}

/// Parse a Shadowsocks proxy from Clash YAML
fn parse_clash_ss(
    proxy: &Value,
    name: &str,
    server: &str,
    port: u16,
    udp: Option<bool>,
    tfo: Option<bool>,
    skip_cert_verify: Option<bool>,
) -> Option<Proxy> {
    // Extract SS-specific fields
    let password = proxy.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let method = proxy.get("cipher").and_then(|v| v.as_str()).unwrap_or("");

    if password.is_empty() || method.is_empty() {
        return None;
    }

    // Extract underlying proxy
    let underlying_proxy = proxy
        .get("underlying-proxy")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Extract plugin information
    let mut plugin = "";
    let mut pluginopts_mode = "";
    let mut pluginopts_host = "";
    let mut path = "";
    let mut tls = "";
    let mut pluginopts_mux = "";
    let mut pluginopts = String::new();

    // Check if plugin is defined
    if let Some(plugin_val) = proxy.get("plugin").and_then(|v| v.as_str()) {
        match plugin_val {
            "obfs" => {
                plugin = "obfs-local";
                if let Some(plugin_opts) = proxy.get("plugin-opts").and_then(|v| v.as_mapping()) {
                    if let Some(mode) = plugin_opts
                        .get(&Value::String("mode".to_string()))
                        .and_then(|v| v.as_str())
                    {
                        pluginopts_mode = mode;
                    }
                    if let Some(host) = plugin_opts
                        .get(&Value::String("host".to_string()))
                        .and_then(|v| v.as_str())
                    {
                        pluginopts_host = host;
                    }
                }
            }
            "v2ray-plugin" => {
                plugin = "v2ray-plugin";
                if let Some(plugin_opts) = proxy.get("plugin-opts").and_then(|v| v.as_mapping()) {
                    if let Some(mode) = plugin_opts
                        .get(&Value::String("mode".to_string()))
                        .and_then(|v| v.as_str())
                    {
                        pluginopts_mode = mode;
                    }
                    if let Some(host) = plugin_opts
                        .get(&Value::String("host".to_string()))
                        .and_then(|v| v.as_str())
                    {
                        pluginopts_host = host;
                    }
                    if let Some(plugin_tls) = plugin_opts
                        .get(&Value::String("tls".to_string()))
                        .and_then(|v| v.as_bool())
                    {
                        tls = if plugin_tls { "tls;" } else { "" };
                    }
                    if let Some(plugin_path) = plugin_opts
                        .get(&Value::String("path".to_string()))
                        .and_then(|v| v.as_str())
                    {
                        path = plugin_path;
                    }
                    if let Some(mux) = plugin_opts
                        .get(&Value::String("mux".to_string()))
                        .and_then(|v| v.as_bool())
                    {
                        pluginopts_mux = if mux { "mux=4;" } else { "" };
                    }
                }
            }
            _ => {}
        }
    } else if let Some(obfs) = proxy.get("obfs").and_then(|v| v.as_str()) {
        // Legacy support for obfs and obfs-host fields
        plugin = "obfs-local";
        pluginopts_mode = obfs;
        if let Some(obfs_host) = proxy.get("obfs-host").and_then(|v| v.as_str()) {
            pluginopts_host = obfs_host;
        }
    }

    // Format plugin options based on plugin type
    match plugin {
        "simple-obfs" | "obfs-local" => {
            pluginopts = format!("obfs={}", pluginopts_mode);
            if !pluginopts_host.is_empty() {
                pluginopts.push_str(&format!(";obfs-host={}", pluginopts_host));
            }
        }
        "v2ray-plugin" => {
            pluginopts = format!("mode={};{}{}", pluginopts_mode, tls, pluginopts_mux);
            if !pluginopts_host.is_empty() {
                pluginopts.push_str(&format!("host={};", pluginopts_host));
            }
            if !path.is_empty() {
                pluginopts.push_str(&format!("path={};", path));
            }
            if !pluginopts_mux.is_empty() {
                pluginopts.push_str(&format!("mux={};", pluginopts_mux));
            }
        }
        _ => {}
    }

    // Handle special cipher types (support for go-shadowsocks2)
    let mut cipher = method;
    if cipher == "AEAD_CHACHA20_POLY1305" {
        cipher = "chacha20-ietf-poly1305";
    } else if cipher.contains("AEAD") {
        // Not implementing the full C++ transformation for now
    }

    Some(Proxy::ss_construct(
        SS_DEFAULT_GROUP,
        name,
        server,
        port,
        password,
        cipher,
        plugin,
        &pluginopts,
        udp,
        tfo,
        skip_cert_verify,
        None,
        underlying_proxy,
    ))
}

/// Parse a ShadowsocksR proxy from Clash YAML
fn parse_clash_ssr(
    proxy: &Value,
    name: &str,
    server: &str,
    port: u16,
    udp: Option<bool>,
    tfo: Option<bool>,
    skip_cert_verify: Option<bool>,
) -> Option<Proxy> {
    // Extract SSR-specific fields
    let password = proxy.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let method = proxy.get("cipher").and_then(|v| v.as_str()).unwrap_or("");
    let protocol = proxy.get("protocol").and_then(|v| v.as_str()).unwrap_or("");
    let protocol_param = proxy
        .get("protocol-param")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let obfs = proxy.get("obfs").and_then(|v| v.as_str()).unwrap_or("");
    let obfs_param = proxy
        .get("obfs-param")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Extract underlying proxy
    let underlying_proxy = proxy
        .get("underlying-proxy")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if password.is_empty() || method.is_empty() || protocol.is_empty() || obfs.is_empty() {
        return None;
    }

    Some(Proxy::ssr_construct(
        SSR_DEFAULT_GROUP,
        name,
        server,
        port,
        protocol,
        method,
        obfs,
        password,
        obfs_param,
        protocol_param,
        udp,
        tfo,
        skip_cert_verify,
        underlying_proxy,
    ))
}

/// Parse a VMess proxy from Clash YAML
fn parse_clash_vmess(
    proxy: &Value,
    name: &str,
    server: &str,
    port: u16,
    udp: Option<bool>,
    tfo: Option<bool>,
    skip_cert_verify: Option<bool>,
) -> Option<Proxy> {
    // Extract VMess-specific fields
    let uuid = proxy.get("uuid").and_then(|v| v.as_str()).unwrap_or("");
    let alter_id_val = proxy.get("alterId").and_then(|v| v.as_u64()).unwrap_or(0);
    let alter_id = alter_id_val as u16;
    let cipher = proxy
        .get("cipher")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");

    // Extract underlying proxy
    let underlying_proxy = proxy
        .get("underlying-proxy")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if uuid.is_empty() {
        return None;
    }

    // Get network settings
    let network = proxy
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp");

    // Get TLS settings
    let tls = proxy.get("tls").and_then(|v| v.as_bool()).unwrap_or(false);
    let sni = proxy
        .get("servername")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Parse network specific options
    let mut host = String::new();
    let mut path = String::new();

    // Handle WebSocket options
    if let Some(ws_opts) = proxy.get("ws-opts").and_then(|v| v.as_mapping()) {
        if let Some(path_val) = ws_opts
            .get(&Value::String("path".to_string()))
            .and_then(|v| v.as_str())
        {
            path = path_val.to_string();
        }

        if let Some(headers) = ws_opts
            .get(&Value::String("headers".to_string()))
            .and_then(|v| v.as_mapping())
        {
            if let Some(host_val) = headers
                .get(&Value::String("Host".to_string()))
                .and_then(|v| v.as_str())
            {
                host = host_val.to_string();
            }
        }
    }
    // Handle HTTP/2 options
    else if let Some(h2_opts) = proxy.get("h2-opts").and_then(|v| v.as_mapping()) {
        if let Some(path_val) = h2_opts
            .get(&Value::String("path".to_string()))
            .and_then(|v| v.as_str())
        {
            path = path_val.to_string();
        }

        if let Some(hosts) = h2_opts
            .get(&Value::String("host".to_string()))
            .and_then(|v| v.as_sequence())
        {
            if !hosts.is_empty() {
                if let Some(first_host) = hosts.get(0).and_then(|v| v.as_str()) {
                    host = first_host.to_string();
                }
            }
        }
    }
    // Handle HTTP options
    else if let Some(http_opts) = proxy.get("http-opts").and_then(|v| v.as_mapping()) {
        if let Some(paths) = http_opts
            .get(&Value::String("path".to_string()))
            .and_then(|v| v.as_sequence())
        {
            if !paths.is_empty() {
                if let Some(first_path) = paths.get(0).and_then(|v| v.as_str()) {
                    path = first_path.to_string();
                }
            }
        }

        if let Some(hosts) = http_opts
            .get(&Value::String("host".to_string()))
            .and_then(|v| v.as_sequence())
        {
            if !hosts.is_empty() {
                if let Some(first_host) = hosts.get(0).and_then(|v| v.as_str()) {
                    host = first_host.to_string();
                }
            }
        }
    }
    // Handle gRPC options
    else if let Some(grpc_opts) = proxy.get("grpc-opts").and_then(|v| v.as_mapping()) {
        if let Some(service_name) = grpc_opts
            .get(&Value::String("grpc-service-name".to_string()))
            .and_then(|v| v.as_str())
        {
            path = service_name.to_string();
        }
    }

    // Prepare path
    let final_path = if path.is_empty() { "/" } else { &path };

    // Get edge value
    let edge = "";

    Some(Proxy::vmess_construct(
        V2RAY_DEFAULT_GROUP,
        name,
        server,
        port,
        "", // type
        uuid,
        alter_id,
        network,
        cipher,
        final_path,
        &host,
        edge,
        if tls { "tls" } else { "" },
        sni,
        udp,
        tfo,
        skip_cert_verify,
        None,
        underlying_proxy,
    ))
}

/// Parse a SOCKS5 proxy from Clash YAML
fn parse_clash_socks(
    proxy: &Value,
    name: &str,
    server: &str,
    port: u16,
    udp: Option<bool>,
    tfo: Option<bool>,
    skip_cert_verify: Option<bool>,
) -> Option<Proxy> {
    // Extract SOCKS-specific fields
    let username = proxy.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = proxy.get("password").and_then(|v| v.as_str()).unwrap_or("");

    // Extract underlying proxy
    let underlying_proxy = proxy
        .get("underlying-proxy")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    Some(Proxy::socks_construct(
        SOCKS_DEFAULT_GROUP,
        name,
        server,
        port,
        username,
        password,
        udp,
        tfo,
        skip_cert_verify,
        underlying_proxy,
    ))
}

/// Parse an HTTP/HTTPS proxy from Clash YAML
fn parse_clash_http(
    proxy: &Value,
    name: &str,
    server: &str,
    port: u16,
    is_https: bool,
    tfo: Option<bool>,
    skip_cert_verify: Option<bool>,
) -> Option<Proxy> {
    // Extract HTTP-specific fields
    let username = proxy.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = proxy.get("password").and_then(|v| v.as_str()).unwrap_or("");

    // Extract underlying proxy
    let underlying_proxy = proxy
        .get("underlying-proxy")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    Some(Proxy::http_construct(
        HTTP_DEFAULT_GROUP,
        name,
        server,
        port,
        username,
        password,
        is_https,
        tfo,
        skip_cert_verify,
        None,
        underlying_proxy,
    ))
}

/// Parse a Trojan proxy from Clash YAML
fn parse_clash_trojan(
    proxy: &Value,
    name: &str,
    server: &str,
    port: u16,
    udp: Option<bool>,
    tfo: Option<bool>,
    skip_cert_verify: Option<bool>,
) -> Option<Proxy> {
    // Extract Trojan-specific fields
    let password = proxy.get("password").and_then(|v| v.as_str()).unwrap_or("");

    if password.is_empty() {
        return None;
    }

    // Extract underlying proxy
    let underlying_proxy = proxy
        .get("underlying-proxy")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Get SNI and network settings
    let sni = proxy
        .get("sni")
        .or_else(|| proxy.get("servername"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let network = proxy.get("network").and_then(|v| v.as_str()).unwrap_or("");

    // Get path and host, if any
    let mut host = String::new();
    let mut path = String::new();

    // Handle WebSocket options if specified
    if network == "ws" && proxy.get("ws-opts").is_some() {
        if let Some(ws_opts) = proxy.get("ws-opts").and_then(|v| v.as_mapping()) {
            if let Some(path_val) = ws_opts
                .get(&Value::String("path".to_string()))
                .and_then(|v| v.as_str())
            {
                path = path_val.to_string();
            }

            if let Some(headers) = ws_opts
                .get(&Value::String("headers".to_string()))
                .and_then(|v| v.as_mapping())
            {
                if let Some(host_val) = headers
                    .get(&Value::String("Host".to_string()))
                    .and_then(|v| v.as_str())
                {
                    host = host_val.to_string();
                }
            }
        }
    }

    // Handle gRPC options if specified
    if network == "grpc" {
        if let Some(grpc_opts) = proxy.get("grpc-opts").and_then(|v| v.as_mapping()) {
            if let Some(service_name) = grpc_opts
                .get(&Value::String("grpc-service-name".to_string()))
                .and_then(|v| v.as_str())
            {
                path = service_name.to_string();
            }
        }
    }

    let mut node = Proxy::trojan_construct(
        TROJAN_DEFAULT_GROUP.to_string(),
        name.to_string(),
        server.to_string(),
        port,
        password.to_string(),
        Some(network.to_string()),
        Some(host),
        Some(path),
        Some(sni.to_owned()),
        true, // tls_secure, Trojan always uses TLS
        udp,
        tfo,
        skip_cert_verify,
        None,
        Some(underlying_proxy.to_string()),
    );

    // Preserve TLS extras that the constructor does not cover
    for alpn in yaml_string_or_seq(proxy.get("alpn")) {
        node.alpn.insert(alpn);
    }
    node.fingerprint = proxy
        .get("fingerprint")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    node.client_fingerprint = proxy
        .get("client-fingerprint")
        .or_else(|| proxy.get("utls-fingerprint"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Some(node)
}

/// Read a YAML value that may be either a scalar string or a sequence of
/// strings (e.g. `alpn: h3` vs `alpn: [h3, h2]`).
fn yaml_string_or_seq(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(s)) if !s.is_empty() => {
            s.split(',').map(|part| part.trim().to_string()).collect()
        }
        Some(Value::Sequence(seq)) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

/// Read a YAML value that may be a number or a string with a bandwidth unit.
fn yaml_speed_mbps(value: Option<&Value>) -> Option<u32> {
    match value {
        Some(Value::Number(n)) => n.as_u64().map(|v| v as u32),
        Some(Value::String(s)) => {
            let speed = crate::utils::deserialize::parse_speed_mbps(s);
            if speed > 0 {
                Some(speed)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Parse a Snell proxy from Clash YAML
fn parse_clash_snell(
    proxy: &Value,
    name: &str,
    server: &str,
    port: u16,
    udp: Option<bool>,
    tfo: Option<bool>,
    skip_cert_verify: Option<bool>,
) -> Option<Proxy> {
    // Extract Snell-specific fields
    let psk = proxy.get("psk").and_then(|v| v.as_str()).unwrap_or("");

    if psk.is_empty() {
        return None;
    }

    // Extract underlying proxy
    let underlying_proxy = proxy
        .get("underlying-proxy")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Get obfs settings
    let version = proxy.get("version").and_then(|v| v.as_u64()).unwrap_or(1) as u16;
    let obfs = proxy.get("obfs").and_then(|v| v.as_str()).unwrap_or("");
    let obfs_host = proxy
        .get("obfs-host")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    Some(Proxy::snell_construct(
        SNELL_DEFAULT_GROUP.to_string(),
        name.to_string(),
        server.to_string(),
        port,
        psk.to_string(),
        obfs.to_string(),
        obfs_host.to_string(),
        version,
        udp,
        tfo,
        skip_cert_verify,
        Some(underlying_proxy.to_string()),
    ))
}

/// Parse a WireGuard proxy from Clash YAML
fn parse_clash_wireguard(
    proxy: &Value,
    name: &str,
    server: &str,
    port: u16,
    udp: Option<bool>,
) -> Option<Proxy> {
    // Extract WireGuard-specific fields
    let private_key = proxy
        .get("privateKey")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let public_key = proxy
        .get("publicKey")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let preshared_key = proxy
        .get("presharedKey")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if private_key.is_empty() || public_key.is_empty() {
        return None;
    }

    // Extract underlying proxy
    let underlying_proxy = proxy
        .get("underlying-proxy")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Get IP addresses
    let self_ip = proxy.get("ip").and_then(|v| v.as_str()).unwrap_or("");
    let self_ipv6 = proxy.get("ipv6").and_then(|v| v.as_str()).unwrap_or("");

    // Get MTU and keepalive
    let mtu_value = proxy.get("mtu").and_then(|v| v.as_u64()).unwrap_or(0);
    let mtu = if mtu_value > 0 {
        Some(mtu_value as u16)
    } else {
        None
    };

    let keepalive_value = proxy.get("keepalive").and_then(|v| v.as_u64()).unwrap_or(0);
    let keepalive = if keepalive_value > 0 {
        Some(keepalive_value as u16)
    } else {
        None
    };

    // Get DNS servers
    let mut dns_servers = Vec::new();
    if let Some(Value::Sequence(dns_seq)) = proxy.get("dns") {
        for dns in dns_seq {
            if let Some(dns_str) = dns.as_str() {
                dns_servers.push(dns_str.to_string());
            }
        }
    }

    // Get client ID and test URL
    let client_id = proxy.get("clientId").and_then(|v| v.as_str()).unwrap_or("");
    let test_url = proxy.get("testUrl").and_then(|v| v.as_str()).unwrap_or("");

    Some(Proxy::wireguard_construct(
        WG_DEFAULT_GROUP.to_string(),
        name.to_string(),
        server.to_string(),
        port,
        self_ip.to_string(),
        self_ipv6.to_string(),
        private_key.to_string(),
        public_key.to_string(),
        preshared_key.to_string(),
        dns_servers,
        mtu,
        keepalive,
        test_url.to_string(),
        client_id.to_string(),
        udp,
        Some(underlying_proxy.to_string()),
    ))
}

/// Parse a Hysteria proxy from Clash YAML
fn parse_clash_hysteria(
    proxy: &Value,
    name: &str,
    server: &str,
    port: u16,
    tfo: Option<bool>,
    skip_cert_verify: Option<bool>,
) -> Option<Proxy> {
    // Extract Hysteria-specific fields
    let auth = proxy.get("auth").and_then(|v| v.as_str()).unwrap_or("");
    let auth_str = proxy
        .get("auth-str")
        .or_else(|| proxy.get("auth_str"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let obfs = proxy.get("obfs").and_then(|v| v.as_str()).unwrap_or("");
    let protocol = proxy
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("udp");

    // Extract underlying proxy
    let underlying_proxy = proxy
        .get("underlying-proxy")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Get ports range if specified
    let ports = proxy.get("ports").and_then(|v| v.as_str()).unwrap_or("");

    // Get up/down speeds; values may be numbers or strings with units
    let up_speed = yaml_speed_mbps(proxy.get("up"));
    let down_speed = yaml_speed_mbps(proxy.get("down"));

    // Get TLS settings
    let sni = proxy.get("sni").and_then(|v| v.as_str()).unwrap_or("");
    let alpn = yaml_string_or_seq(proxy.get("alpn"));

    let fingerprint = proxy
        .get("fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let ca = proxy.get("ca").and_then(|v| v.as_str()).unwrap_or("");
    let ca_str = proxy.get("ca-str").and_then(|v| v.as_str()).unwrap_or("");

    // Get advanced settings
    let recv_window_conn_value = proxy
        .get("recv-window-conn")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let recv_window_value = proxy
        .get("recv-window")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let recv_window_conn = if recv_window_conn_value > 0 {
        Some(recv_window_conn_value as u32)
    } else {
        None
    };
    let recv_window = if recv_window_value > 0 {
        Some(recv_window_value as u32)
    } else {
        None
    };

    let disable_mtu_discovery = proxy.get("disable-mtu-discovery").and_then(|v| v.as_bool());

    let hop_interval_value = proxy
        .get("hop-interval")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let hop_interval = if hop_interval_value > 0 {
        Some(hop_interval_value as u32)
    } else {
        None
    };

    Some(Proxy::hysteria_construct(
        HYSTERIA_DEFAULT_GROUP.to_string(),
        name.to_string(),
        server.to_string(),
        port,
        ports.to_string(),
        protocol.to_string(),
        "".to_string(), // obfs_param
        up_speed,
        down_speed,
        if !auth.is_empty() {
            auth.to_string()
        } else {
            auth_str.to_string()
        },
        obfs.to_string(),
        sni.to_string(),
        fingerprint.to_string(),
        ca.to_string(),
        ca_str.to_string(),
        recv_window_conn,
        recv_window,
        disable_mtu_discovery,
        hop_interval,
        alpn,
        tfo,
        skip_cert_verify,
        Some(underlying_proxy.to_string()),
    ))
}

/// Parse a Hysteria2 proxy from Clash YAML
fn parse_clash_hysteria2(
    proxy: &Value,
    name: &str,
    server: &str,
    port: u16,
    tfo: Option<bool>,
    skip_cert_verify: Option<bool>,
) -> Option<Proxy> {
    // Extract Hysteria2-specific fields
    let password = proxy
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    // Extract underlying proxy
    let underlying_proxy = match proxy.get("underlying-proxy").and_then(|v| v.as_str()) {
        Some(v) => Some(v.to_owned()),
        None => None,
    };

    // Get obfs settings
    let obfs = match proxy.get("obfs").and_then(|v| v.as_str()) {
        Some(v) => Some(v.to_owned()),
        None => None,
    };
    let obfs_password = match proxy.get("obfs-password").and_then(|v| v.as_str()) {
        Some(v) => Some(v.to_owned()),
        None => None,
    };

    // Get ports range if specified
    let ports = match proxy.get("ports").and_then(|v| v.as_str()) {
        Some(v) => Some(v.to_owned()),
        None => None,
    };
    // Get up/down speeds
    let up_mbps = match proxy.get("up").and_then(|v| v.as_u64()) {
        Some(v) => Some(v as u32),
        None => None,
    };
    let down_mbps = match proxy.get("down").and_then(|v| v.as_u64()) {
        Some(v) => Some(v as u32),
        None => None,
    };

    // Get TLS settings
    let sni = match proxy.get("sni").and_then(|v| v.as_str()) {
        Some(v) => Some(v.to_owned()),
        None => None,
    };
    let alpn = proxy
        .get("alpn")
        .and_then(|v| v.as_sequence())
        .map(|v| {
            v.iter()
                .map(|v| v.as_str().unwrap_or("").to_owned())
                .collect()
        })
        .unwrap_or_default();

    let fingerprint = match proxy.get("fingerprint").and_then(|v| v.as_str()) {
        Some(v) => Some(v.to_owned()),
        None => None,
    };
    let ca = match proxy.get("ca").and_then(|v| v.as_str()) {
        Some(v) => Some(v.to_owned()),
        None => None,
    };
    let ca_str = match proxy.get("ca-str").and_then(|v| v.as_str()) {
        Some(v) => Some(v.to_owned()),
        None => None,
    };

    // Get congestion window
    let cwnd_value = proxy.get("cwnd").and_then(|v| v.as_u64()).unwrap_or(0);
    let cwnd = if cwnd_value > 0 {
        Some(cwnd_value as u32)
    } else {
        None
    };

    Some(Proxy::hysteria2_construct(
        HYSTERIA2_DEFAULT_GROUP.to_string(),
        name.to_string(),
        server.to_string(),
        port,
        ports,
        up_mbps,
        down_mbps,
        password,
        obfs,
        obfs_password,
        sni,
        fingerprint,
        alpn,
        ca,
        ca_str,
        cwnd,
        tfo,
        skip_cert_verify,
        underlying_proxy,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::yaml::clash::clash_output::ClashProxyOutput;

    fn roundtrip_to_yaml(input: &str) -> Vec<serde_yaml::Value> {
        let mut nodes = Vec::new();
        assert!(explode_clash(input, &mut nodes), "input must parse");
        nodes
            .into_iter()
            .map(|node| {
                let output = ClashProxyOutput::from(node);
                serde_yaml::to_value(&output).expect("output must serialize")
            })
            .collect()
    }

    /// One malformed proxy must not discard the rest of the subscription.
    #[test]
    fn test_malformed_entry_does_not_break_subscription() {
        let input = r#"
proxies:
  - {name: broken, type: ss, server: s1.example.com, port: not-a-port}
  - {name: good, type: trojan, server: s2.example.com, port: 443, password: pw}
"#;
        let mut nodes = Vec::new();
        assert!(explode_clash(input, &mut nodes));
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].remark, "good");
    }

    /// Issue #37: hysteria up/down with units and alpn list survive a
    /// clash -> clash roundtrip, even with duplicate auth keys present.
    #[test]
    fn test_hysteria_roundtrip_keeps_speed_and_alpn() {
        let input = r#"
proxies:
  - {name: serves, server: 192.168.1.1, port: 62003, type: hysteria, auth_str: auth, auth-str: auth, up: 1000 Mbps, down: 1000 Mbps, protocol: none, skip-cert-verify: true, alpn: [h3]}
"#;
        let outputs = roundtrip_to_yaml(input);
        assert_eq!(outputs.len(), 1);
        let out = &outputs[0];
        assert_eq!(out["up"].as_str(), Some("1000 Mbps"));
        assert_eq!(out["down"].as_str(), Some("1000 Mbps"));
        assert_eq!(out["alpn"][0].as_str(), Some("h3"));
        assert_eq!(out["auth-str"].as_str(), Some("auth"));
    }

    /// Issue #40: vmess tls/servername/udp survive a clash -> clash roundtrip.
    #[test]
    fn test_vmess_roundtrip_keeps_tls_and_servername() {
        let input = r#"
proxies:
  - {"name":"vmess-jp","type":"vmess","server":"tokyo.example.top","port":10000,"uuid":"b445361a-abcf-aaaa-a97a-0bf4136d6ddc","alterId":0,"cipher":"auto","udp":true,"tls":true,"network":"ws","ws-opts":{"path":"/vm","headers":{"Host":"tokyo.example.top"}},"servername":"tokyo.example.top"}
"#;
        let outputs = roundtrip_to_yaml(input);
        let out = &outputs[0];
        assert_eq!(out["tls"].as_bool(), Some(true));
        assert_eq!(out["udp"].as_bool(), Some(true));
        assert_eq!(out["servername"].as_str(), Some("tokyo.example.top"));
        assert_eq!(out["ws-opts"]["path"].as_str(), Some("/vm"));
        assert_eq!(
            out["ws-opts"]["headers"]["Host"].as_str(),
            Some("tokyo.example.top")
        );
    }

    /// Issues #41/#42: vless reality-opts survive a clash -> clash roundtrip.
    #[test]
    fn test_vless_roundtrip_keeps_reality_opts() {
        let input = r#"
proxies:
  - {"name":"reality","type":"vless","server":"2.22.22.22","port":13340,"uuid":"56b8aaaa-c339-4502-86ae-9d2a20dcbbbb","network":"grpc","tls":true,"udp":true,"client-fingerprint":"chrome","grpc-opts":{"grpc-service-name":"grpc"},"reality-opts":{"public-key":"bY9DOyBwDrix8ArirlAd","short-id":""},"smux":{"enabled":true},"servername":"addons.mozilla.org"}
"#;
        let outputs = roundtrip_to_yaml(input);
        let out = &outputs[0];
        assert_eq!(
            out["reality-opts"]["public-key"].as_str(),
            Some("bY9DOyBwDrix8ArirlAd")
        );
        assert_eq!(out["client-fingerprint"].as_str(), Some("chrome"));
        assert_eq!(out["grpc-opts"]["grpc-service-name"].as_str(), Some("grpc"));
        assert_eq!(out["servername"].as_str(), Some("addons.mozilla.org"));
        assert_eq!(out["tls"].as_bool(), Some(true));
    }

    /// Issue #44: trojan alpn and fingerprint survive a clash -> clash
    /// roundtrip; no empty plugin-opts are emitted for plain ss nodes (#38).
    #[test]
    fn test_trojan_roundtrip_keeps_alpn() {
        let input = r#"
proxies:
  - name: t1
    type: trojan
    server: example.com
    port: 443
    password: pw
    udp: true
    tls: true
    alpn: [h2, http/1.1]
    skip-cert-verify: false
    utls-fingerprint: chrome
"#;
        let outputs = roundtrip_to_yaml(input);
        let out = &outputs[0];
        let alpn: Vec<&str> = out["alpn"]
            .as_sequence()
            .expect("alpn must be a sequence")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(alpn.contains(&"h2"));
        assert!(alpn.contains(&"http/1.1"));
        assert_eq!(out["client-fingerprint"].as_str(), Some("chrome"));
        assert_eq!(out["skip-cert-verify"].as_bool(), Some(false));
    }

    /// Issue #38: plain ss node must not gain an empty plugin-opts mapping.
    #[test]
    fn test_ss_roundtrip_no_empty_plugin_opts() {
        let input = r#"
proxies:
  - {name: hk, type: ss, server: a01.example.com, port: 52011, cipher: 2022-blake3-aes-128-gcm, password: "NWI2YjgyYzU1MzZkYzYzMA==:ZWUyMzc4ODMtZDkxYi00NQ==", udp: true}
"#;
        let outputs = roundtrip_to_yaml(input);
        let out = &outputs[0];
        assert_eq!(
            out["password"].as_str(),
            Some("NWI2YjgyYzU1MzZkYzYzMA==:ZWUyMzc4ODMtZDkxYi00NQ==")
        );
        assert!(out.get("plugin-opts").is_none(), "no empty plugin-opts");
        assert!(out.get("plugin").is_none(), "no empty plugin");
    }
}
