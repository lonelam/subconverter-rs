use crate::generator::config::group::group_generate;
use crate::generator::config::remark::process_remark;
use crate::generator::ruleconvert::ruleset_to_surge::ruleset_to_surge;
use crate::models::{
    ExtraSettings, Proxy, ProxyGroupConfigs, ProxyGroupType, ProxyType, RulesetContent,
};
use crate::utils::ini_reader::IniReader;
use crate::utils::string::{hash, join, replace_all_distinct, trim};
use crate::utils::tribool::BoolTriboolExt;
use crate::utils::url::get_url_arg;
use log::error;

/// Convert proxies to QuantumultX format (main entry point)
///
/// This function converts a list of proxies to QuantumultX format,
/// using a base configuration as a template and applying rules from ruleset_content_array.
///
/// # Arguments
/// * `nodes` - List of proxy nodes to convert
/// * `base_conf` - Base QuantumultX configuration as a string
/// * `ruleset_content_array` - Array of ruleset contents to apply
/// * `extra_proxy_group` - Extra proxy group configurations
/// * `ext` - Extra settings for conversion
///
/// # Returns
/// * QuantumultX configuration as a string
pub async fn proxy_to_quanx(
    nodes: &mut Vec<Proxy>,
    base_conf: &str,
    ruleset_content_array: &mut Vec<RulesetContent>,
    extra_proxy_group: &ProxyGroupConfigs,
    ext: &mut ExtraSettings,
) -> String {
    let mut ini = IniReader::new();
    ini.store_any_line = true;

    // Add direct save sections
    ini.add_direct_save_section("general");
    ini.add_direct_save_section("dns");
    ini.add_direct_save_section("rewrite_remote");
    ini.add_direct_save_section("rewrite_local");
    ini.add_direct_save_section("task_local");
    ini.add_direct_save_section("mitm");
    ini.add_direct_save_section("server_remote");

    // Parse base configuration if not in nodelist mode
    if !ext.nodelist && ini.parse(base_conf).is_err() {
        error!(
            "QuantumultX base loader failed with error: {}",
            ini.get_last_error()
        );
        return String::new();
    }

    // Process nodes and rules
    proxy_to_quanx_internal(
        nodes,
        &mut ini,
        ruleset_content_array,
        extra_proxy_group,
        ext,
    )
    .await;

    // Return result based on mode (nodelist or full config)
    if ext.nodelist {
        let mut all_nodes = Vec::new();
        if ini.get_all("server_local", "{NONAME}").is_ok() {
            all_nodes = ini.get_all("server_local", "{NONAME}").unwrap();
        }

        if !all_nodes.is_empty() {
            return join(&all_nodes, "\n");
        }

        return String::new();
    }

    ini.to_string()
}

/// Internal function for converting proxies to QuantumultX format
///
/// This function handles the actual conversion logic for QuantumultX.
///
/// # Arguments
/// * `nodes` - List of proxy nodes to convert
/// * `ini` - INI reader to store configuration
/// * `ruleset_content_array` - Array of ruleset contents to apply
/// * `extra_proxy_group` - Extra proxy group configurations
/// * `ext` - Extra settings for conversion
async fn proxy_to_quanx_internal(
    nodes: &mut Vec<Proxy>,
    ini: &mut IniReader,
    ruleset_content_array: &mut Vec<RulesetContent>,
    extra_proxy_group: &ProxyGroupConfigs,
    ext: &mut ExtraSettings,
) {
    let mut nodelist = Vec::new();
    let mut remarks_list = Vec::new();

    // Set up server_local section
    ini.set_current_section("server_local");
    ini.erase_section();

    // Process each proxy node
    for node in nodes {
        // Add proxy type prefix if enabled
        if ext.append_proxy_type {
            let proxy_type = node.proxy_type.to_string();
            node.remark = format!("[{}] {}", proxy_type, node.remark);
        }

        // Process remark
        let mut remark = node.remark.clone();
        process_remark(&mut remark, &remarks_list, false);
        node.remark = remark;

        // Extract node properties for easier access
        let hostname = &node.hostname;
        let port = node.port.to_string();
        let username = node.username().unwrap_or("");
        let password = node.password().unwrap_or("");
        let method = node.encrypt_method().unwrap_or("");
        let id = node.user_id().unwrap_or("");
        let transproto = node.transfer_protocol().unwrap_or("");
        let host = node.host().unwrap_or("");
        let path = node.path().unwrap_or("");
        let plugin = node.plugin().unwrap_or("");
        let pluginopts = node.plugin_option().unwrap_or("");
        let protocol = node.protocol().unwrap_or("");
        let protoparam = node.protocol_param().unwrap_or("");
        let obfs = node.obfs().unwrap_or("");
        let obfsparam = node.obfs_param().unwrap_or("");
        let tls_secure = node.tls_secure;

        // Get option values with defaults from ext
        let mut udp = ext.udp;
        let mut tfo = ext.tfo;
        let mut scv = ext.skip_cert_verify;
        let mut tls13 = ext.tls13;

        // Override with node-specific values if present
        udp = node.udp.as_ref().map_or(udp, |val| Some(*val));
        tfo = node.tcp_fast_open.as_ref().map_or(tfo, |val| Some(*val));
        scv = node.allow_insecure.as_ref().map_or(scv, |val| Some(*val));
        tls13 = node.tls13.as_ref().map_or(tls13, |val| Some(*val));

        let mut _proxy_str = String::new();

        // Format proxy string based on proxy type
        match node.proxy_type {
            ProxyType::VMess => {
                let mut actual_method = method;
                if method == "auto" {
                    actual_method = "chacha20-ietf-poly1305";
                }

                _proxy_str = format!(
                    "vmess = {}:{}, method={}, password={}",
                    hostname, port, actual_method, id
                );

                if node.alter_id() == 0 {
                    // AEAD is enabled when alter_id is 0
                } else {
                    _proxy_str.push_str(", aead=false");
                }

                if tls_secure && !tls13.is_undef() {
                    _proxy_str.push_str(&format!(
                        ", tls13={}",
                        if tls13.unwrap_or(false) {
                            "true"
                        } else {
                            "false"
                        }
                    ));
                }

                if transproto == "ws" {
                    if tls_secure {
                        _proxy_str.push_str(", obfs=wss");
                    } else {
                        _proxy_str.push_str(", obfs=ws");
                    }
                    _proxy_str.push_str(&format!(", obfs-host={}, obfs-uri={}", host, path));
                } else if tls_secure {
                    _proxy_str.push_str(&format!(", obfs=over-tls, obfs-host={}", host));
                }
            }
            ProxyType::Shadowsocks => {
                _proxy_str = format!(
                    "shadowsocks = {}:{}, method={}, password={}",
                    hostname, port, method, password
                );

                if !plugin.is_empty() {
                    // Handle plugin based on type
                    let plugin_hash = hash(plugin);

                    if plugin_hash == hash("simple-obfs") || plugin_hash == hash("obfs-local") {
                        if !pluginopts.is_empty() {
                            _proxy_str.push_str(&format!(
                                ", {}",
                                replace_all_distinct(pluginopts, ";", ", ")
                            ));
                        }
                    } else if plugin_hash == hash("v2ray-plugin") {
                        let opts = replace_all_distinct(pluginopts, ";", "&");
                        let mode = get_url_arg(&opts, "mode");
                        let mut plugin_type =
                            (if mode == "websocket" { "ws" } else { "" }).to_string();
                        let plugin_host = get_url_arg(&opts, "host");
                        let plugin_path = get_url_arg(&opts, "path");
                        let is_tls = opts.contains("tls");

                        if is_tls && plugin_type == "ws" {
                            plugin_type.push('s');
                            if !tls13.is_undef() {
                                _proxy_str.push_str(&format!(
                                    ", tls13={}",
                                    if tls13.unwrap_or(false) {
                                        "true"
                                    } else {
                                        "false"
                                    }
                                ));
                            }
                        }

                        _proxy_str.push_str(&format!(", obfs={}", plugin_type));

                        if !plugin_host.is_empty() {
                            _proxy_str.push_str(&format!(", obfs-host={}", plugin_host));
                        }

                        if !plugin_path.is_empty() {
                            _proxy_str.push_str(&format!(", obfs-uri={}", plugin_path));
                        }
                    } else {
                        continue; // Skip unsupported plugin
                    }
                }
            }
            ProxyType::ShadowsocksR => {
                _proxy_str = format!(
                    "shadowsocks = {}:{}, method={}, password={}, ssr-protocol={}",
                    hostname, port, method, password, protocol
                );

                if !protoparam.is_empty() {
                    _proxy_str.push_str(&format!(", ssr-protocol-param={}", protoparam));
                }

                _proxy_str.push_str(&format!(", obfs={}", obfs));

                if !obfsparam.is_empty() {
                    _proxy_str.push_str(&format!(", obfs-host={}", obfsparam));
                }
            }
            ProxyType::HTTP | ProxyType::HTTPS => {
                _proxy_str = format!(
                    "http = {}:{}, username={}, password={}",
                    hostname,
                    port,
                    if username.is_empty() {
                        "none"
                    } else {
                        username
                    },
                    if password.is_empty() {
                        "none"
                    } else {
                        password
                    }
                );

                if tls_secure {
                    _proxy_str.push_str(", over-tls=true");
                    if !tls13.is_undef() {
                        _proxy_str.push_str(&format!(
                            ", tls13={}",
                            if tls13.unwrap_or(false) {
                                "true"
                            } else {
                                "false"
                            }
                        ));
                    }
                } else {
                    _proxy_str.push_str(", over-tls=false");
                }
            }
            ProxyType::Trojan => {
                _proxy_str = format!("trojan = {}:{}, password={}", hostname, port, password);

                if tls_secure {
                    _proxy_str.push_str(&format!(", over-tls=true, tls-host={}", host));
                    if !tls13.is_undef() {
                        _proxy_str.push_str(&format!(
                            ", tls13={}",
                            if tls13.unwrap_or(false) {
                                "true"
                            } else {
                                "false"
                            }
                        ));
                    }
                } else {
                    _proxy_str.push_str(", over-tls=false");
                }
            }
            ProxyType::Socks5 => {
                _proxy_str = format!("socks5 = {}:{}", hostname, port);

                if !username.is_empty() && !password.is_empty() {
                    _proxy_str.push_str(&format!(", username={}, password={}", username, password));

                    if tls_secure {
                        _proxy_str.push_str(&format!(", over-tls=true, tls-host={}", host));
                        if !tls13.is_undef() {
                            _proxy_str.push_str(&format!(
                                ", tls13={}",
                                if tls13.unwrap_or(false) {
                                    "true"
                                } else {
                                    "false"
                                }
                            ));
                        }
                    } else {
                        _proxy_str.push_str(", over-tls=false");
                    }
                }
            }
            _ => continue,
        }

        // Add common options
        if !tfo.is_undef() {
            _proxy_str.push_str(&format!(
                ", fast-open={}",
                if tfo.unwrap_or(false) {
                    "true"
                } else {
                    "false"
                }
            ));
        }

        if !udp.is_undef() {
            _proxy_str.push_str(&format!(
                ", udp-relay={}",
                if udp.unwrap_or(false) {
                    "true"
                } else {
                    "false"
                }
            ));
        }

        // Add TLS verification option (scv is reversed for QuantumultX)
        if tls_secure
            && !scv.is_undef()
            && node.proxy_type != ProxyType::Shadowsocks
            && node.proxy_type != ProxyType::ShadowsocksR
        {
            _proxy_str.push_str(&format!(
                ", tls-verification={}",
                if scv.unwrap_or(false) {
                    "false"
                } else {
                    "true"
                }
            ));
        }

        // Add tag
        _proxy_str.push_str(&format!(", tag={}", node.remark));

        // Add to INI
        ini.set_current("{NONAME}", &_proxy_str).unwrap_or(());
        remarks_list.push(node.remark.clone());
        nodelist.push(node.clone());
    }

    // Stop here if nodelist mode is enabled
    if ext.nodelist {
        return;
    }

    // Process policy section
    ini.set_current_section("policy");
    let mut original_groups = Vec::new();
    if let Ok(items) = ini.get_items("policy") {
        original_groups = items;
    }
    ini.erase_section();

    // Process proxy groups
    for group in extra_proxy_group {
        let mut _type_str = String::new();
        let mut filtered_nodelist = Vec::new();

        // Determine group type
        match group.group_type {
            ProxyGroupType::Select => {
                _type_str = "static".to_string();
            }
            ProxyGroupType::URLTest => {
                _type_str = "url-latency-benchmark".to_string();
            }
            ProxyGroupType::Fallback => {
                _type_str = "available".to_string();
            }
            ProxyGroupType::LoadBalance => {
                _type_str = "round-robin".to_string();
            }
            ProxyGroupType::SSID => {
                _type_str = "ssid".to_string();

                // Special handling for SSID groups
                for proxy in &group.proxies {
                    filtered_nodelist.push(replace_all_distinct(proxy, "=", ":"));
                }
            }
            _ => continue,
        }

        // Generate node list for non-SSID groups
        if group.group_type != ProxyGroupType::SSID {
            for proxy_name in &group.proxies {
                group_generate(proxy_name, &nodelist, &mut filtered_nodelist, true, ext);
            }

            if filtered_nodelist.is_empty() {
                filtered_nodelist.push("direct".to_string());
            }

            // Force groups with 1 node to be static
            if filtered_nodelist.len() < 2 {
                _type_str = "static".to_string();
            }
        }

        // Check for image URL in original group
        for (_, group_data) in &original_groups {
            let pos = group_data.find(',');
            if let Some(pos) = pos {
                let name = trim(&group_data[..pos]);
                if name == group.name {
                    let parts: Vec<&str> = group_data.split(',').collect();
                    if !parts.is_empty() {
                        let last_part = trim(parts[parts.len() - 1]);
                        if last_part.starts_with("img-url") {
                            filtered_nodelist.push(last_part.to_string());
                        }
                    }
                }
            }
        }

        // Join proxies
        let proxies = join(&filtered_nodelist, ", ");

        // Create group string
        let mut single_group = format!("{}={}, {}", _type_str, group.name, proxies);

        // Add type-specific options
        if group.group_type != ProxyGroupType::Select && group.group_type != ProxyGroupType::SSID {
            single_group.push_str(&format!(", check-interval={}", group.interval));

            if group.tolerance > 0 {
                single_group.push_str(&format!(", tolerance={}", group.tolerance));
            }
        }

        // Add to INI
        ini.set_current("{NONAME}", &single_group).unwrap_or(());
    }

    // Generate rules if enabled
    if ext.enable_rule_generator {
        ruleset_to_surge(
            ini,
            ruleset_content_array,
            -1,
            ext.overwrite_original_rules,
            &ext.managed_config_prefix,
        )
        .await;
    }
}
