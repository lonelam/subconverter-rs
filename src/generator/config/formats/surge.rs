use crate::generator::config::group::group_generate;
use crate::generator::config::remark::process_remark;
use crate::generator::ruleconvert::ruleset_to_surge::ruleset_to_surge;
use crate::models::{
    ExtraSettings, Proxy, ProxyGroupConfigs, ProxyGroupType, ProxyType, RulesetContent,
};
use crate::utils::ini_reader::IniReader;
use crate::utils::network::{hostname_to_ip_addr, is_ipv4, is_ipv6};
use crate::utils::string::{hash, join, to_lower};
use crate::utils::tribool::{BoolTriboolExt, TriboolExt};
use crate::Settings;
use log::error;

/// Generate a WireGuard peer configuration string
///
/// # Arguments
/// * `node` - Proxy node with WireGuard configuration
/// * `client_id_as_reserved` - Whether to use client_id as reserved field
///
/// # Returns
/// * Peer configuration string
fn generate_peer(node: &Proxy, client_id_as_reserved: bool) -> String {
    let mut peer = String::new();
    let default_wg = Default::default();
    let wg = node.as_wireguard().unwrap_or(&default_wg);

    if let Some(public_key) = &wg.public_key {
        peer.push_str("public-key = ");
        peer.push_str(public_key);
        peer.push_str(", ");
    }

    peer.push_str("endpoint = ");
    peer.push_str(&node.hostname);
    peer.push_str(":");
    peer.push_str(&node.port.to_string());

    if !wg.allowed_ips.is_empty() {
        peer.push_str(", allowed-ips = ");
        peer.push_str(&wg.allowed_ips);
    }

    if let Some(client_id) = &wg.client_id {
        if !client_id.is_empty() {
            if client_id_as_reserved {
                peer.push_str(", reserved = ");
                peer.push_str(client_id);
            } else {
                peer.push_str(", client-id = ");
                peer.push_str(client_id);
            }
        }
    }

    peer
}

/// Convert proxies to Surge format
///
/// This function converts a list of proxies to the Surge configuration format,
/// using a base configuration as a template and applying rules from ruleset_content_array.
///
/// # Arguments
/// * `nodes` - List of proxy nodes to convert
/// * `base_conf` - Base Surge configuration as a string
/// * `ruleset_content_array` - Array of ruleset contents to apply
/// * `extra_proxy_group` - Extra proxy group configurations
/// * `surge_ver` - Surge version to target (or negative for special formats)
/// * `ext` - Extra settings for conversion
///
/// # Returns
/// * Converted configuration as a string
pub async fn proxy_to_surge(
    nodes: &mut Vec<Proxy>,
    base_conf: &str,
    ruleset_content_array: &mut Vec<RulesetContent>,
    extra_proxy_group: &ProxyGroupConfigs,
    surge_ver: i32,
    ext: &mut ExtraSettings,
) -> String {
    let mut ini = IniReader::new();
    let mut output_nodelist = String::new();
    let mut nodelist = Vec::new();
    let mut local_port = 1080;
    let mut remarks_list = Vec::new();
    let global = Settings::current();

    // Configure INI reader
    ini.store_any_line = true;

    // Add direct save sections
    let direct_save_sections = vec![
        "General",
        "Replica",
        "Rule",
        "MITM",
        "Script",
        "Host",
        "URL Rewrite",
        "Header Rewrite",
    ];
    for section in direct_save_sections {
        ini.add_direct_save_section(section);
    }

    // Parse base configuration
    if ini.parse(base_conf).is_err() && !ext.nodelist {
        error!(
            "Surge base loader failed with error: {}",
            ini.get_last_error()
        );
        return String::new();
    }

    // Prepare Proxy section
    ini.set_current_section("Proxy");
    ini.erase_section();
    ini.set("{NONAME}", "DIRECT", "direct").unwrap_or(());

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

        // Extract node properties for easier access
        let hostname = &node.hostname;
        let port = node.port.to_string();
        let username = node.username().unwrap_or("");
        let password = node.password().unwrap_or("");
        let method = node.encrypt_method().unwrap_or("");
        let id = node.user_id().unwrap_or("");
        let transproto = node.transfer_protocol().unwrap_or("");
        let host = node.host().unwrap_or("");
        let edge = node.edge().unwrap_or("");
        let path = node.path().unwrap_or("");
        let protocol = node.protocol().unwrap_or("");
        let protoparam = node.protocol_param().unwrap_or("");
        let obfs = node.obfs().unwrap_or("");
        let obfsparam = node.obfs_param().unwrap_or("");
        let plugin = node.plugin().unwrap_or("");
        let pluginopts = node.plugin_option().unwrap_or("");
        let underlying_proxy = node.underlying_proxy.as_deref().unwrap_or("");
        let tls_secure = node.tls_secure;

        // Define tribool values with defaults from ext and override with node-specific values
        let mut udp = ext.udp;
        let mut tfo = ext.tfo;
        let mut scv = ext.skip_cert_verify;
        let mut tls13 = ext.tls13;

        udp = node.udp.define(udp);
        tfo = node.tcp_fast_open.define(tfo);
        scv = node.allow_insecure.define(scv);
        tls13 = node.tls13.define(tls13);

        let mut _proxy = String::new();
        let mut _section = String::new();
        let mut _real_section = String::new();
        let mut _args = Vec::new();
        let mut headers = Vec::new();

        // Build proxy string based on type
        match node.proxy_type {
            ProxyType::Shadowsocks => {
                if surge_ver >= 3 || surge_ver == -3 {
                    _proxy = format!(
                        "ss, {}, {}, encrypt-method={}, password={}",
                        hostname, port, method, password
                    );
                } else {
                    _proxy = format!("custom, {}, {}, {}, {}, https://github.com/pobizhe/SSEncrypt/raw/master/SSEncrypt.module", 
                                   hostname, port, method, password);
                }

                if !plugin.is_empty() {
                    match plugin {
                        "simple-obfs" | "obfs-local" => {
                            if !pluginopts.is_empty() {
                                _proxy.push_str(&format!(",{}", pluginopts.replace(';', ",")));
                            }
                        }
                        _ => continue,
                    }
                }
            }
            ProxyType::VMess => {
                if surge_ver < 4 && surge_ver != -3 {
                    continue;
                }

                _proxy = format!(
                    "vmess, {}, {}, username={}, tls={}, vmess-aead={}",
                    hostname,
                    port,
                    id,
                    if tls_secure { "true" } else { "false" },
                    if node.alter_id() == 0 { "true" } else { "false" }
                );

                if tls_secure && !tls13.is_undef() {
                    _proxy.push_str(&format!(
                        ", tls13={}",
                        if tls13.unwrap_or(false) {
                            "true"
                        } else {
                            "false"
                        }
                    ));
                }

                match transproto {
                    "tcp" => {}
                    "ws" => {
                        if host.is_empty() {
                            _proxy.push_str(&format!(
                                ", ws=true, ws-path={}, sni={}",
                                path, hostname
                            ));
                        } else {
                            _proxy.push_str(&format!(", ws=true, ws-path={}, sni={}", path, host));
                        }

                        if !host.is_empty() {
                            headers.push(format!("Host:{}", host));
                        }

                        if !edge.is_empty() {
                            headers.push(format!("Edge:{}", edge));
                        }

                        if !headers.is_empty() {
                            _proxy.push_str(&format!(", ws-headers={}", join(&headers, "|")));
                        }
                    }
                    _ => continue,
                }

                if scv.is_some() {
                    _proxy.push_str(&format!(
                        ", skip-cert-verify={}",
                        if scv.unwrap_or(false) {
                            "true"
                        } else {
                            "false"
                        }
                    ));
                }
            }
            ProxyType::ShadowsocksR => {
                if ext.surge_ssr_path.is_empty() || surge_ver < 2 {
                    continue;
                }

                _proxy = format!("external, exec=\"{}\", args=\"", ext.surge_ssr_path);
                _args = vec![
                    "-l".to_string(),
                    local_port.to_string(),
                    "-s".to_string(),
                    hostname.to_string(),
                    "-p".to_string(),
                    port.to_string(),
                    "-m".to_string(),
                    method.to_string(),
                    "-k".to_string(),
                    password.to_string(),
                    "-o".to_string(),
                    obfs.to_string(),
                    "-O".to_string(),
                    protocol.to_string(),
                ];

                if !obfsparam.is_empty() {
                    _args.push("-g".to_string());
                    _args.push(obfsparam.to_string());
                }

                if !protoparam.is_empty() {
                    _args.push("-G".to_string());
                    _args.push(protoparam.to_string());
                }

                _proxy.push_str(&join(&_args, "\", args=\""));
                _proxy.push_str(&format!("\", local-port={}", local_port));

                if is_ipv4(hostname) || is_ipv6(hostname) {
                    _proxy.push_str(&format!(", addresses={}", hostname));
                } else if global.surge_resolve_hostname {
                    if let Some(ip) = hostname_to_ip_addr(hostname) {
                        _proxy.push_str(&format!(", addresses={}", ip));
                    }
                }

                local_port += 1;
            }
            ProxyType::Socks5 => {
                _proxy = format!("socks5, {}, {}", hostname, port);

                if !username.is_empty() {
                    _proxy.push_str(&format!(", username={}", username));
                }

                if !password.is_empty() {
                    _proxy.push_str(&format!(", password={}", password));
                }

                if scv.is_some() {
                    _proxy.push_str(&format!(
                        ", skip-cert-verify={}",
                        if scv.unwrap_or(false) {
                            "true"
                        } else {
                            "false"
                        }
                    ));
                }
            }
            ProxyType::HTTPS => {
                if surge_ver == -3 {
                    _proxy = format!("https, {}, {}, {}, {}", hostname, port, username, password);

                    if scv.is_some() {
                        _proxy.push_str(&format!(
                            ", skip-cert-verify={}",
                            if scv.unwrap_or(false) {
                                "true"
                            } else {
                                "false"
                            }
                        ));
                    }
                    break;
                }
                // Fall through to HTTP case for non -3 versions
                _proxy = format!("http, {}, {}", hostname, port);

                if !username.is_empty() {
                    _proxy.push_str(&format!(", username={}", username));
                }

                if !password.is_empty() {
                    _proxy.push_str(&format!(", password={}", password));
                }

                _proxy.push_str(&format!(
                    ", tls={}",
                    if tls_secure { "true" } else { "false" }
                ));

                if scv.is_some() {
                    _proxy.push_str(&format!(
                        ", skip-cert-verify={}",
                        if scv.unwrap_or(false) {
                            "true"
                        } else {
                            "false"
                        }
                    ));
                }
            }
            ProxyType::HTTP => {
                _proxy = format!("http, {}, {}", hostname, port);

                if !username.is_empty() {
                    _proxy.push_str(&format!(", username={}", username));
                }

                if !password.is_empty() {
                    _proxy.push_str(&format!(", password={}", password));
                }

                _proxy.push_str(&format!(
                    ", tls={}",
                    if tls_secure { "true" } else { "false" }
                ));

                if scv.is_some() {
                    _proxy.push_str(&format!(
                        ", skip-cert-verify={}",
                        if scv.unwrap_or(false) {
                            "true"
                        } else {
                            "false"
                        }
                    ));
                }
            }
            ProxyType::Trojan => {
                if surge_ver < 4 && surge_ver != -3 {
                    continue;
                }

                _proxy = format!("trojan, {}, {}, password={}", hostname, port, password);

                if node.snell_version() != 0 {
                    _proxy.push_str(&format!(", version={}", node.snell_version()));
                }

                if !host.is_empty() {
                    _proxy.push_str(&format!(", sni={}", host));
                }

                if scv.is_some() {
                    _proxy.push_str(&format!(
                        ", skip-cert-verify={}",
                        if scv.unwrap_or(false) {
                            "true"
                        } else {
                            "false"
                        }
                    ));
                }
            }
            ProxyType::Snell => {
                _proxy = format!("snell, {}, {}, psk={}", hostname, port, password);

                if !obfs.is_empty() {
                    _proxy.push_str(&format!(", obfs={}", obfs));

                    if !host.is_empty() {
                        _proxy.push_str(&format!(", obfs-host={}", host));
                    }
                }

                if node.snell_version() != 0 {
                    _proxy.push_str(&format!(", version={}", node.snell_version()));
                }
            }
            ProxyType::WireGuard => {
                if surge_ver < 4 && surge_ver != -3 {
                    continue;
                }

                let hash_val = hash(&remark);
                _section = format!("{:05x}", hash_val);
                _real_section = format!("WireGuard {}", _section);
                _proxy = format!("wireguard, section-name={}", _section);

                let default_wg = Default::default();
                let wg = node.as_wireguard().unwrap_or(&default_wg);

                if let Some(test_url) = &wg.test_url {
                    if !test_url.is_empty() {
                        _proxy.push_str(&format!(", test-url={}", test_url));
                    }
                }

                if let Some(private_key) = &wg.private_key {
                    ini.set(&_real_section, "private-key", private_key)
                        .unwrap_or(());
                }

                if let Some(self_ip) = &wg.self_ip {
                    ini.set(&_real_section, "self-ip", self_ip).unwrap_or(());
                }

                if let Some(self_ipv6) = &wg.self_ipv6 {
                    if !self_ipv6.is_empty() {
                        ini.set(&_real_section, "self-ip-v6", self_ipv6)
                            .unwrap_or(());
                    }
                }

                if let Some(pre_shared_key) = &wg.pre_shared_key {
                    if !pre_shared_key.is_empty() {
                        ini.set(&_real_section, "preshared-key", pre_shared_key)
                            .unwrap_or(());
                    }
                }

                if !wg.dns_servers.is_empty() {
                    let dns_list: Vec<String> = wg.dns_servers.clone();
                    ini.set(&_real_section, "dns-server", &join(&dns_list, ","))
                        .unwrap_or(());
                }

                if wg.mtu > 0 {
                    ini.set(&_real_section, "mtu", &wg.mtu.to_string())
                        .unwrap_or(());
                }

                if wg.keep_alive > 0 {
                    ini.set(&_real_section, "keepalive", &wg.keep_alive.to_string())
                        .unwrap_or(());
                }

                ini.set(
                    &_real_section,
                    "peer",
                    &format!("({})", generate_peer(node, false)),
                )
                .unwrap_or(());
            }
            ProxyType::Hysteria2 => {
                if surge_ver < 4 {
                    continue;
                }

                _proxy = format!("hysteria, {}, {}, password={}", hostname, port, password);

                if node.down_speed() > 0 {
                    _proxy.push_str(&format!(", download-bandwidth={}", node.down_speed()));
                }

                if scv.is_some() {
                    _proxy.push_str(&format!(
                        ",skip-cert-verify={}",
                        if scv.unwrap_or(false) {
                            "true"
                        } else {
                            "false"
                        }
                    ));
                }

                if let Some(fingerprint) = &node.fingerprint {
                    if !fingerprint.is_empty() {
                        _proxy
                            .push_str(&format!(",server-cert-fingerprint-sha256={}", fingerprint));
                    }
                }

                if let Some(sni) = &node.sni {
                    if !sni.is_empty() {
                        _proxy.push_str(&format!(",sni={}", sni));
                    }
                }
            }
            _ => continue,
        }

        // Add common options
        if !tfo.is_undef() {
            _proxy.push_str(&format!(
                ", tfo={}",
                if tfo.unwrap_or(false) {
                    "true"
                } else {
                    "false"
                }
            ));
        }

        if !udp.is_undef() {
            _proxy.push_str(&format!(
                ", udp-relay={}",
                if udp.unwrap_or(false) {
                    "true"
                } else {
                    "false"
                }
            ));
        }

        if !underlying_proxy.is_empty() {
            _proxy.push_str(&format!(", underlying-proxy={}", underlying_proxy));
        }

        // Add to nodelist or INI
        if ext.nodelist {
            output_nodelist.push_str(&format!("{} = {}\n", remark, _proxy));
        } else {
            ini.set("{NONAME}", &format!("{} = {}", remark, _proxy), "")
                .unwrap_or(());
            nodelist.push(node.clone());
        }

        remarks_list.push(remark);
    }

    if ext.nodelist {
        return output_nodelist;
    }

    // Process proxy groups
    ini.set_current_section("Proxy Group");
    ini.erase_section();

    for group in extra_proxy_group {
        let mut filtered_nodelist = Vec::new();
        let mut _group_str = String::new();

        match group.group_type {
            ProxyGroupType::Select
            | ProxyGroupType::Smart
            | ProxyGroupType::URLTest
            | ProxyGroupType::Fallback => {
                // These types are supported
            }
            ProxyGroupType::LoadBalance => {
                if surge_ver < 1 && surge_ver != -3 {
                    continue;
                }
            }
            ProxyGroupType::SSID => {
                _group_str = format!("{},default={},", group.type_str(), group.proxies[0]);
                _group_str.push_str(&join(&group.proxies[1..], ","));
                ini.set("{NONAME}", &format!("{} = {}", group.name, _group_str), "")
                    .unwrap_or(());
                continue;
            }
            _ => continue,
        }

        // Generate filtered proxy list
        for proxy_name in &group.proxies {
            group_generate(proxy_name, &nodelist, &mut filtered_nodelist, true, ext);
        }

        if filtered_nodelist.is_empty() {
            filtered_nodelist.push("DIRECT".to_string());
        }

        if filtered_nodelist.len() == 1 {
            let proxy_name = to_lower(&filtered_nodelist[0]);
            match proxy_name.as_str() {
                "direct" | "reject" | "reject-tinygif" => {
                    ini.set(
                        "Proxy",
                        "{NONAME}",
                        &format!("{} = {}", group.name, proxy_name),
                    )
                    .unwrap_or(());
                    continue;
                }
                _ => {}
            }
        }

        // Build group string
        _group_str = format!("{},", group.type_str());
        _group_str.push_str(&join(&filtered_nodelist, ","));

        if group.group_type == ProxyGroupType::URLTest
            || group.group_type == ProxyGroupType::Fallback
            || group.group_type == ProxyGroupType::LoadBalance
        {
            _group_str.push_str(&format!(",url={},interval={}", group.url, group.interval));

            if group.tolerance > 0 {
                _group_str.push_str(&format!(",tolerance={}", group.tolerance));
            }

            if group.timeout > 0 {
                _group_str.push_str(&format!(",timeout={}", group.timeout));
            }

            // Handle persistent field directly
            if group.persistent {
                _group_str.push_str(",persistent=true");
            }

            // Handle evaluate_before_use field directly
            if group.evaluate_before_use {
                _group_str.push_str(",evaluate-before-use=true");
            }
        }

        ini.set("{NONAME}", &format!("{} = {}", group.name, _group_str), "")
            .unwrap_or(());
    }

    // Generate rules if enabled
    if ext.enable_rule_generator {
        ruleset_to_surge(
            &mut ini,
            ruleset_content_array,
            surge_ver,
            ext.overwrite_original_rules,
            &ext.managed_config_prefix,
        )
        .await;
    }

    ini.to_string()
}
