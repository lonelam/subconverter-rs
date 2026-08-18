use crate::generator::config::group::group_generate;
use crate::generator::config::remark::process_remark;
use crate::generator::ruleconvert::ruleset_to_sing_box::ruleset_to_sing_box;
use crate::models::{
    ExtraSettings, Proxy, ProxyGroupConfigs, ProxyGroupType, ProxyType, RulesetContent,
};
use crate::utils::base64::base64_encode;
use crate::Settings;
use log::error;
use serde_json::{json, Map, Value as JsonValue};

/// Format SingBox interval from seconds
///
/// # Arguments
/// * `interval` - Interval in seconds
///
/// # Returns
/// * Formatted interval string
fn format_singbox_interval(interval: u32) -> String {
    let mut result = String::new();
    let mut remaining_seconds = interval;

    if remaining_seconds >= 3600 {
        result.push_str(&format!("{}h", remaining_seconds / 3600));
        remaining_seconds %= 3600;
    }

    if remaining_seconds >= 60 {
        result.push_str(&format!("{}m", remaining_seconds / 60));
        remaining_seconds %= 60;
    }

    if remaining_seconds > 0 {
        result.push_str(&format!("{}s", remaining_seconds));
    }

    result
}

/// Build SingBox transport configuration
///
/// # Arguments
/// * `proxy` - The proxy node
///
/// # Returns
/// * Transport configuration as JSON
fn build_singbox_transport(proxy: &Proxy) -> JsonValue {
    let mut transport = Map::new();

    // Extract transport protocol
    let transproto = proxy.transfer_protocol().unwrap_or("");

    match transproto {
        "http" => {
            if let Some(host) = proxy.host() {
                if !host.is_empty() {
                    transport.insert("host".to_string(), JsonValue::String(host.to_string()));
                }
            }
            // Fall through to WS handler for common settings
            transport.insert("type".to_string(), JsonValue::String("http".to_string()));
        }
        "ws" => {
            transport.insert("type".to_string(), JsonValue::String("ws".to_string()));

            // Set path or default to "/"
            if let Some(path) = proxy.path() {
                transport.insert("path".to_string(), JsonValue::String(path.to_string()));
            } else {
                transport.insert("path".to_string(), JsonValue::String("/".to_string()));
            }

            // Add headers
            let mut headers = Map::new();
            if let Some(host) = proxy.host() {
                if !host.is_empty() {
                    headers.insert("Host".to_string(), JsonValue::String(host.to_string()));
                }
            }

            if let Some(edge) = proxy.edge() {
                if !edge.is_empty() {
                    headers.insert("Edge".to_string(), JsonValue::String(edge.to_string()));
                }
            }

            if !headers.is_empty() {
                transport.insert("headers".to_string(), JsonValue::Object(headers));
            }
        }
        "grpc" => {
            transport.insert("type".to_string(), JsonValue::String("grpc".to_string()));

            if let Some(path) = proxy.path() {
                if !path.is_empty() {
                    transport.insert("service_name".to_string(), JsonValue::String(path.to_string()));
                }
            }
        }
        _ => {} // Default empty transport
    }

    JsonValue::Object(transport)
}

/// Add common members to a SingBox proxy configuration
///
/// # Arguments
/// * `proxy_obj` - Proxy object to add members to
/// * `proxy` - Source proxy data
/// * `proxy_type` - Type of proxy
///
/// # Returns
/// * Updated proxy object
fn add_singbox_common_members(
    proxy_obj: &mut Map<String, JsonValue>,
    proxy: &Proxy,
    proxy_type: &str,
) {
    proxy_obj.insert(
        "type".to_string(),
        JsonValue::String(proxy_type.to_string()),
    );
    proxy_obj.insert("tag".to_string(), JsonValue::String(proxy.remark.clone()));
    proxy_obj.insert(
        "server".to_string(),
        JsonValue::String(proxy.hostname.clone()),
    );
    proxy_obj.insert(
        "server_port".to_string(),
        JsonValue::Number(proxy.port.into()),
    );
}

/// Convert string array to JSON array
///
/// # Arguments
/// * `array` - String containing values separated by delimiter
/// * `delimiter` - Delimiter separating values
///
/// # Returns
/// * Array of values as JSON
fn string_array_to_json_array(array: &str, delimiter: &str) -> JsonValue {
    let values: Vec<JsonValue> = array
        .split(delimiter)
        .map(|s| JsonValue::String(s.trim().to_string()))
        .collect();

    JsonValue::Array(values)
}

/// Convert proxies to SingBox format
///
/// # Arguments
/// * `nodes` - List of proxy nodes to convert
/// * `base_conf` - Base SingBox configuration as a string
/// * `ruleset_content_array` - Array of ruleset contents to apply
/// * `extra_proxy_group` - Extra proxy group configurations
/// * `ext` - Extra settings for conversion
///
/// # Returns
/// * Converted configuration as a string
pub fn proxy_to_singbox(
    nodes: &mut Vec<Proxy>,
    base_conf: &str,
    ruleset_content_array: &mut Vec<RulesetContent>,
    extra_proxy_group: &ProxyGroupConfigs,
    ext: &mut ExtraSettings,
) -> String {
    // Parse the base configuration
    let mut json: JsonValue = if ext.nodelist {
        json!({})
    } else {
        match serde_json::from_str(base_conf) {
            Ok(json) => json,
            Err(e) => {
                error!(
                    "SingBox base loader failed with error: {}, base_conf: {}",
                    e, base_conf
                );
                return String::new();
            }
        }
    };

    // Convert nodes to outbounds
    let mut outbounds = Vec::new();
    let mut nodelist = Vec::new();
    let mut remarks_list = Vec::new();

    // Add default outbounds if not in nodelist mode
    if !ext.nodelist {
        // Direct outbound
        outbounds.push(json!({
            "type": "direct",
            "tag": "DIRECT"
        }));

        // Reject outbound
        outbounds.push(json!({
            "type": "block",
            "tag": "REJECT"
        }));

        // DNS outbound
        outbounds.push(json!({
            "type": "dns",
            "tag": "dns-out"
        }));
    }

    // Process each proxy node
    for node in nodes.iter_mut() {
        // Add proxy type prefix if enabled
        if ext.append_proxy_type {
            let proxy_type = node.proxy_type.to_string();
            node.remark = format!("[{}] {}", proxy_type, node.remark);
        }

        // Process remark
        let mut remark = node.remark.clone();
        process_remark(&mut remark, &remarks_list, false);
        node.remark = remark;

        // Define tribool values with defaults from ext and override with node-specific values
        let mut udp = ext.udp;
        let mut tfo = ext.tfo;
        let mut scv = ext.skip_cert_verify;

        udp = node.udp.as_ref().map_or(udp, |val| Some(*val));
        tfo = node.tcp_fast_open.as_ref().map_or(tfo, |val| Some(*val));
        scv = node.allow_insecure.as_ref().map_or(scv, |val| Some(*val));

        // Create proxy object based on type
        let mut proxy_obj = match node.proxy_type {
            ProxyType::Shadowsocks => {
                let mut obj = Map::new();
                add_singbox_common_members(&mut obj, node, "shadowsocks");

                // Add encryption method and password
                if let Some(method) = node.encrypt_method() {
                    obj.insert("method".to_string(), JsonValue::String(method.to_string()));
                }

                if let Some(password) = node.password() {
                    obj.insert("password".to_string(), JsonValue::String(password.to_string()));
                }

                // Handle plugin if present
                if let (Some(plugin), Some(plugin_opts)) = (node.plugin(), node.plugin_option()) {
                    if !plugin.is_empty() && !plugin_opts.is_empty() {
                        let plugin_name = if plugin == "simple-obfs" {
                            "obfs-local"
                        } else {
                            plugin
                        };

                        obj.insert(
                            "plugin".to_string(),
                            JsonValue::String(plugin_name.to_string()),
                        );
                        obj.insert(
                            "plugin_opts".to_string(),
                            JsonValue::String(plugin_opts.to_string()),
                        );
                    }
                }

                obj
            }
            ProxyType::ShadowsocksR => {
                let mut obj = Map::new();
                add_singbox_common_members(&mut obj, node, "shadowsocksr");

                // Add shadowsocksr specific fields
                if let Some(method) = node.encrypt_method() {
                    obj.insert("method".to_string(), JsonValue::String(method.to_string()));
                }

                if let Some(password) = node.password() {
                    obj.insert("password".to_string(), JsonValue::String(password.to_string()));
                }

                if let Some(protocol) = node.protocol() {
                    obj.insert("protocol".to_string(), JsonValue::String(protocol.to_string()));
                }

                if let Some(protocol_param) = node.protocol_param() {
                    obj.insert(
                        "protocol_param".to_string(),
                        JsonValue::String(protocol_param.to_string()),
                    );
                }

                if let Some(obfs) = node.obfs() {
                    obj.insert("obfs".to_string(), JsonValue::String(obfs.to_string()));
                }

                if let Some(obfs_param) = node.obfs_param() {
                    obj.insert(
                        "obfs_param".to_string(),
                        JsonValue::String(obfs_param.to_string()),
                    );
                }

                obj
            }
            ProxyType::VMess => {
                let mut obj = Map::new();
                add_singbox_common_members(&mut obj, node, "vmess");

                // Add VMess specific fields
                if let Some(user_id) = node.user_id() {
                    obj.insert("uuid".to_string(), JsonValue::String(user_id.to_string()));
                }

                obj.insert(
                    "alter_id".to_string(),
                    JsonValue::Number(node.alter_id().into()),
                );

                if let Some(method) = node.encrypt_method() {
                    obj.insert("security".to_string(), JsonValue::String(method.to_string()));
                }

                // Add transport settings if any
                let transport = build_singbox_transport(node);
                if !transport.as_object().unwrap().is_empty() {
                    obj.insert("transport".to_string(), transport);
                }

                obj
            }
            ProxyType::Trojan => {
                let mut obj = Map::new();
                add_singbox_common_members(&mut obj, node, "trojan");

                // Add Trojan specific fields
                if let Some(password) = node.password() {
                    obj.insert("password".to_string(), JsonValue::String(password.to_string()));
                }

                // Add transport settings if any
                let transport = build_singbox_transport(node);
                if !transport.as_object().unwrap().is_empty() {
                    obj.insert("transport".to_string(), transport);
                }

                obj
            }
            ProxyType::WireGuard => {
                let default_wg = Default::default();
                let wg = node.as_wireguard().unwrap_or(&default_wg);
                let mut obj = Map::new();
                obj.insert(
                    "type".to_string(),
                    JsonValue::String("wireguard".to_string()),
                );
                obj.insert("tag".to_string(), JsonValue::String(node.remark.clone()));

                // Add WireGuard specific fields
                let mut addresses = Vec::new();
                if let Some(self_ip) = &wg.self_ip {
                    addresses.push(JsonValue::String(self_ip.to_string()));
                }

                if let Some(self_ipv6) = &wg.self_ipv6 {
                    if !self_ipv6.is_empty() {
                        addresses.push(JsonValue::String(self_ipv6.to_string()));
                    }
                }

                obj.insert("local_address".to_string(), JsonValue::Array(addresses));

                if let Some(private_key) = &wg.private_key {
                    obj.insert(
                        "private_key".to_string(),
                        JsonValue::String(private_key.to_string()),
                    );
                }

                // Create peer
                let mut peer = Map::new();
                peer.insert(
                    "server".to_string(),
                    JsonValue::String(node.hostname.clone()),
                );
                peer.insert(
                    "server_port".to_string(),
                    JsonValue::Number(node.port.into()),
                );

                if let Some(public_key) = &wg.public_key {
                    peer.insert(
                        "public_key".to_string(),
                        JsonValue::String(public_key.to_string()),
                    );
                }

                if let Some(pre_shared_key) = &wg.pre_shared_key {
                    if !pre_shared_key.is_empty() {
                        peer.insert(
                            "pre_shared_key".to_string(),
                            JsonValue::String(pre_shared_key.to_string()),
                        );
                    }
                }

                if !wg.allowed_ips.is_empty() {
                    let allowed_ips = string_array_to_json_array(&wg.allowed_ips, ",");
                    peer.insert("allowed_ips".to_string(), allowed_ips);
                }

                if let Some(client_id) = &wg.client_id {
                    if !client_id.is_empty() {
                        let reserved = string_array_to_json_array(client_id, ",");
                        peer.insert("reserved".to_string(), reserved);
                    }
                }

                // Add peer to peers array
                let peers = vec![JsonValue::Object(peer)];
                obj.insert("peers".to_string(), JsonValue::Array(peers));

                // Add MTU if present
                if wg.mtu > 0 {
                    obj.insert("mtu".to_string(), JsonValue::Number(wg.mtu.into()));
                }

                obj
            }
            ProxyType::Hysteria => {
                let default_hy = Default::default();
                let hy = node.as_hysteria().unwrap_or(&default_hy);
                let mut obj = Map::new();
                add_singbox_common_members(&mut obj, node, "hysteria");

                // Add Hysteria specific fields
                if node.up_speed() > 0 {
                    obj.insert(
                        "up_mbps".to_string(),
                        JsonValue::Number(node.up_speed().into()),
                    );
                }

                if node.down_speed() > 0 {
                    obj.insert(
                        "down_mbps".to_string(),
                        JsonValue::Number(node.down_speed().into()),
                    );
                }

                if let Some(obfs) = node.obfs() {
                    if !obfs.is_empty() {
                        obj.insert("obfs".to_string(), JsonValue::String(obfs.to_string()));
                    }
                }

                if let Some(auth_str) = node.auth_str() {
                    if !auth_str.is_empty() {
                        obj.insert("auth_str".to_string(), JsonValue::String(auth_str.to_string()));

                        // Create a temporary String
                        let auth_str_value = auth_str.clone();
                        obj.insert(
                            "auth".to_string(),
                            JsonValue::String(base64_encode(&auth_str_value)),
                        );
                    }
                }

                if hy.recv_window_conn > 0 {
                    obj.insert(
                        "recv_window_conn".to_string(),
                        JsonValue::Number(hy.recv_window_conn.into()),
                    );
                }

                if hy.recv_window > 0 {
                    obj.insert(
                        "recv_window".to_string(),
                        JsonValue::Number(hy.recv_window.into()),
                    );
                }

                if let Some(disable_mtu_discovery) = hy.disable_mtu_discovery {
                    obj.insert(
                        "disable_mtu_discovery".to_string(),
                        JsonValue::Bool(disable_mtu_discovery),
                    );
                }

                // Add TLS settings
                let mut tls = Map::new();
                tls.insert("enabled".to_string(), JsonValue::Bool(true));

                if let Some(allow_insecure) = scv {
                    tls.insert("insecure".to_string(), JsonValue::Bool(allow_insecure));
                }

                if !node.alpn.is_empty() && node.alpn.len() > 0 {
                    let alpn = vec![JsonValue::String(node.alpn.iter().next().unwrap().clone())];
                    tls.insert("alpn".to_string(), JsonValue::Array(alpn));
                }

                if let Some(ca) = &hy.ca {
                    if !ca.is_empty() {
                        tls.insert("certificate".to_string(), JsonValue::String(ca.to_string()));
                    }
                }

                if let Some(ca_str) = &hy.ca_str {
                    if !ca_str.is_empty() {
                        tls.insert("certificate".to_string(), JsonValue::String(ca_str.to_string()));
                    }
                }

                obj.insert("tls".to_string(), JsonValue::Object(tls));
                obj
            }
            ProxyType::Hysteria2 => {
                let default_hy2 = Default::default();
                let hy2 = node.as_hysteria2().unwrap_or(&default_hy2);
                let mut obj = Map::new();
                add_singbox_common_members(&mut obj, node, "hysteria2");

                // Add Hysteria2 specific fields
                if node.up_speed() > 0 {
                    obj.insert(
                        "up_mbps".to_string(),
                        JsonValue::Number(node.up_speed().into()),
                    );
                }

                if node.down_speed() > 0 {
                    obj.insert(
                        "down_mbps".to_string(),
                        JsonValue::Number(node.down_speed().into()),
                    );
                }

                if let Some(obfs) = node.obfs() {
                    if !obfs.is_empty() {
                        let mut obfs_obj = Map::new();
                        obfs_obj.insert("type".to_string(), JsonValue::String(obfs.to_string()));

                        if let Some(obfs_param) = node.obfs_param() {
                            if !obfs_param.is_empty() {
                                obfs_obj.insert(
                                    "password".to_string(),
                                    JsonValue::String(obfs_param.to_string()),
                                );
                            }
                        }

                        obj.insert("obfs".to_string(), JsonValue::Object(obfs_obj));
                    }
                }

                if let Some(password) = node.password() {
                    if !password.is_empty() {
                        obj.insert("password".to_string(), JsonValue::String(password.to_string()));
                    }
                }

                // Add TLS settings
                let mut tls = Map::new();
                tls.insert("enabled".to_string(), JsonValue::Bool(true));

                if let Some(allow_insecure) = scv {
                    tls.insert("insecure".to_string(), JsonValue::Bool(allow_insecure));
                }

                if !node.alpn.is_empty() && node.alpn.len() > 0 {
                    let alpn = vec![JsonValue::String(node.alpn.iter().next().unwrap().clone())];
                    tls.insert("alpn".to_string(), JsonValue::Array(alpn));
                }

                if let Some(ca) = &hy2.ca {
                    if !ca.is_empty() {
                        tls.insert("certificate".to_string(), JsonValue::String(ca.to_string()));
                    }
                }

                if let Some(ca_str) = &hy2.ca_str {
                    if !ca_str.is_empty() {
                        tls.insert("certificate".to_string(), JsonValue::String(ca_str.to_string()));
                    }
                }

                obj.insert("tls".to_string(), JsonValue::Object(tls));
                obj
            }
            ProxyType::HTTP | ProxyType::HTTPS => {
                let mut obj = Map::new();
                add_singbox_common_members(&mut obj, node, "http");

                // Add HTTP/HTTPS specific fields
                if let Some(username) = node.username() {
                    obj.insert("username".to_string(), JsonValue::String(username.to_string()));
                }

                if let Some(password) = node.password() {
                    obj.insert("password".to_string(), JsonValue::String(password.to_string()));
                }

                obj
            }
            ProxyType::Socks5 => {
                let mut obj = Map::new();
                add_singbox_common_members(&mut obj, node, "socks");

                // Add Socks5 specific fields
                obj.insert("version".to_string(), JsonValue::String("5".to_string()));

                if let Some(username) = node.username() {
                    obj.insert("username".to_string(), JsonValue::String(username.to_string()));
                }

                if let Some(password) = node.password() {
                    obj.insert("password".to_string(), JsonValue::String(password.to_string()));
                }

                obj
            }
            _ => continue, // Skip unsupported types
        };

        // Add TLS settings for protocols that need it
        if node.tls_secure {
            let mut tls = Map::new();
            tls.insert("enabled".to_string(), JsonValue::Bool(true));

            // Set server_name from ServerName or Host
            if let Some(server_name) = &node.sni {
                if !server_name.is_empty() {
                    tls.insert(
                        "server_name".to_string(),
                        JsonValue::String(server_name.to_string()),
                    );
                }
            } else if let Some(host) = node.host() {
                if !host.is_empty() {
                    tls.insert("server_name".to_string(), JsonValue::String(host.to_string()));
                }
            }

            // Add insecure option
            if let Some(allow_insecure) = scv {
                tls.insert("insecure".to_string(), JsonValue::Bool(allow_insecure));
            }

            proxy_obj.insert("tls".to_string(), JsonValue::Object(tls));
        }

        // Add UDP and TFO settings
        if let Some(udp_enabled) = udp {
            if !udp_enabled {
                proxy_obj.insert("network".to_string(), JsonValue::String("tcp".to_string()));
            }
        }

        if let Some(tfo_enabled) = tfo {
            proxy_obj.insert("tcp_fast_open".to_string(), JsonValue::Bool(tfo_enabled));
        }

        // Add to node list and outbounds
        nodelist.push(node.clone());
        remarks_list.push(node.remark.clone());
        outbounds.push(JsonValue::Object(proxy_obj));
    }

    // If nodelist mode, just return outbounds
    if ext.nodelist {
        if let JsonValue::Object(obj) = &mut json {
            obj.insert("outbounds".to_string(), JsonValue::Array(outbounds));
        }

        return serde_json::to_string_pretty(&json).unwrap_or_default();
    }

    // Process proxy groups
    for group in extra_proxy_group {
        let mut filtered_nodelist = Vec::new();

        // Determine group type
        let group_type = match group.group_type {
            ProxyGroupType::Select => "selector",
            ProxyGroupType::URLTest | ProxyGroupType::Fallback | ProxyGroupType::LoadBalance => {
                "urltest"
            }
            _ => continue, // Skip unsupported types
        };

        // Generate filtered proxy list
        for proxy_name in &group.proxies {
            group_generate(proxy_name, &nodelist, &mut filtered_nodelist, true, ext);
        }

        // Add DIRECT if empty
        if filtered_nodelist.is_empty() {
            filtered_nodelist.push("DIRECT".to_string());
        }

        // Create group object
        let mut group_obj = Map::new();
        group_obj.insert(
            "type".to_string(),
            JsonValue::String(group_type.to_string()),
        );
        group_obj.insert("tag".to_string(), JsonValue::String(group.name.clone()));

        // Add outbounds
        let group_outbounds: Vec<JsonValue> = filtered_nodelist
            .iter()
            .map(|name| JsonValue::String(name.to_string()))
            .collect();

        group_obj.insert("outbounds".to_string(), JsonValue::Array(group_outbounds));

        // Add URL Test specific settings
        if group.group_type == ProxyGroupType::URLTest {
            group_obj.insert("url".to_string(), JsonValue::String(group.url.clone()));
            group_obj.insert(
                "interval".to_string(),
                JsonValue::String(format_singbox_interval(group.interval as u32)),
            );

            if group.tolerance > 0 {
                group_obj.insert(
                    "tolerance".to_string(),
                    JsonValue::Number(group.tolerance.into()),
                );
            }
        }

        outbounds.push(JsonValue::Object(group_obj));
    }

    let global = Settings::current();

    // Add global group if enabled
    if global.singbox_add_clash_modes {
        let mut global_group = Map::new();
        global_group.insert(
            "type".to_string(),
            JsonValue::String("selector".to_string()),
        );
        global_group.insert("tag".to_string(), JsonValue::String("GLOBAL".to_string()));

        let mut global_outbounds = vec![JsonValue::String("DIRECT".to_string())];

        // Add all remarks
        for remark in &remarks_list {
            global_outbounds.push(JsonValue::String(remark.to_string()));
        }

        global_group.insert("outbounds".to_string(), JsonValue::Array(global_outbounds));
        outbounds.push(JsonValue::Object(global_group));
    }

    // Add outbounds to JSON
    if let JsonValue::Object(obj) = &mut json {
        obj.insert("outbounds".to_string(), JsonValue::Array(outbounds));
    }

    // Handle rule generation
    if !ext.enable_rule_generator {
        return serde_json::to_string_pretty(&json).unwrap_or_default();
    }

    // Generate rules
    ruleset_to_sing_box(
        &mut json,
        ruleset_content_array,
        ext.overwrite_original_rules,
    );

    serde_json::to_string_pretty(&json).unwrap_or_default()
}

/// Generate a Sing-Box configuration
pub fn generate_singbox(
    _proxies: &[Proxy],
    _group_config: &ProxyGroupConfigs,
    _ruleset_content_array: &mut Vec<RulesetContent>,
    _config: &str,
    _extra_settings: &ExtraSettings,
) -> String {
    String::new()
}
