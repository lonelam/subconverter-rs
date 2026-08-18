use crate::generator::config::group::group_generate;
use crate::generator::config::remark::process_remark;
use crate::generator::ruleconvert::ruleset_to_surge::ruleset_to_surge;
use crate::models::{
    BalanceStrategy, ExtraSettings, Proxy, ProxyGroupConfigs, ProxyGroupType, ProxyType,
    RulesetContent,
};
use crate::utils::ini_reader::IniReader;
use crate::utils::string::join;
use log::error;
use std::collections::HashMap;

/// Convert proxies to Loon format
///
/// This function converts a list of proxies to the Loon configuration format,
/// using a base configuration as a template and applying rules from ruleset_content_array.
///
/// # Arguments
/// * `nodes` - List of proxy nodes to convert
/// * `base_conf` - Base Loon configuration as a string
/// * `ruleset_content_array` - Array of ruleset contents to apply
/// * `extra_proxy_group` - Extra proxy group configurations
/// * `ext` - Extra settings for conversion
///
/// # Returns
/// * Converted configuration as a string
pub async fn proxy_to_loon(
    nodes: &mut Vec<Proxy>,
    base_conf: &str,
    ruleset_content_array: &mut Vec<RulesetContent>,
    extra_proxy_group: &ProxyGroupConfigs,
    ext: &mut ExtraSettings,
) -> String {
    let mut ini = IniReader::new();
    let mut output_nodelist = String::new();
    let mut nodelist = Vec::new();
    let mut remarks_list = Vec::new();

    // Configure INI reader
    ini.store_any_line = true;
    ini.add_direct_save_section("Plugin");

    // Parse base configuration
    if ini.parse(base_conf).is_err() && !ext.nodelist {
        error!(
            "Loon base loader failed with error: {}",
            ini.get_last_error()
        );
        return String::new();
    }

    // Prepare Proxy section
    ini.set_current_section("Proxy");
    ini.erase_section();

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
        let path = node.path().unwrap_or("");
        let protocol = node.protocol().unwrap_or("");
        let protoparam = node.protocol_param().unwrap_or("");
        let obfs = node.obfs().unwrap_or("");
        let obfsparam = node.obfs_param().unwrap_or("");
        let plugin = node.plugin().unwrap_or("");
        let pluginopts = node.plugin_option().unwrap_or("");
        let tls_secure = node.tls_secure;

        // Define tribool values with defaults from ext and override with node-specific values
        let scv = ext.skip_cert_verify;
        let scv = node.allow_insecure.as_ref().map_or(scv, |val| Some(*val));

        let mut proxy;

        // Build proxy string based on type
        match node.proxy_type {
            ProxyType::Shadowsocks => {
                proxy = format!(
                    "Shadowsocks,{},{},{},\"{}\"",
                    hostname, port, method, password
                );

                if plugin == "simple-obfs" || plugin == "obfs-local" {
                    if !pluginopts.is_empty() {
                        // Replace obfs=xxx;obfs-host=yyy with xxx,yyy
                        let plugin_opts =
                            pluginopts.replace(";obfs-host=", ",").replace("obfs=", "");
                        proxy.push_str(&format!(",{}", plugin_opts));
                    }
                } else if !plugin.is_empty() {
                    continue;
                }
            }
            ProxyType::VMess => {
                let actual_method = if method == "auto" {
                    "chacha20-ietf-poly1305"
                } else {
                    method
                };

                proxy = format!(
                    "vmess,{},{},{},\"{}\",over-tls={}",
                    hostname,
                    port,
                    actual_method,
                    id,
                    if tls_secure { "true" } else { "false" }
                );

                if tls_secure {
                    proxy.push_str(&format!(",tls-name={}", host));
                }

                match transproto {
                    "tcp" => {
                        proxy.push_str(",transport=tcp");
                    }
                    "ws" => {
                        proxy.push_str(&format!(",transport=ws,path={},host={}", path, host));
                    }
                    _ => continue,
                }

                if scv.is_some() {
                    proxy.push_str(&format!(
                        ",skip-cert-verify={}",
                        if scv.unwrap_or(false) {
                            "true"
                        } else {
                            "false"
                        }
                    ));
                }
            }
            ProxyType::ShadowsocksR => {
                proxy = format!(
                    "ShadowsocksR,{},{},{},\"{}\",protocol={},protocol-param={},obfs={},obfs-param={}",
                    hostname, port, method, password, protocol, protoparam, obfs, obfsparam
                );
            }
            ProxyType::HTTP => {
                proxy = format!("http,{},{}", hostname, port);

                if !username.is_empty() {
                    proxy.push_str(&format!(",{}", username));

                    if !password.is_empty() {
                        proxy.push_str(&format!(",\"{}\"", password));
                    }
                }
            }
            ProxyType::HTTPS => {
                proxy = format!("https,{},{}", hostname, port);

                if !username.is_empty() {
                    proxy.push_str(&format!(",{}", username));

                    if !password.is_empty() {
                        proxy.push_str(&format!(",\"{}\"", password));
                    }
                }

                if !host.is_empty() {
                    proxy.push_str(&format!(",tls-name={}", host));
                }

                if scv.is_some() {
                    proxy.push_str(&format!(
                        ",skip-cert-verify={}",
                        if scv.unwrap_or(false) {
                            "true"
                        } else {
                            "false"
                        }
                    ));
                }
            }
            ProxyType::Trojan => {
                proxy = format!("trojan,{},{},\"{}\"", hostname, port, password);

                if !host.is_empty() {
                    proxy.push_str(&format!(",tls-name={}", host));
                }

                if scv.is_some() {
                    proxy.push_str(&format!(
                        ",skip-cert-verify={}",
                        if scv.unwrap_or(false) {
                            "true"
                        } else {
                            "false"
                        }
                    ));
                }
            }
            ProxyType::Socks5 => {
                proxy = format!("socks5,{},{}", hostname, port);

                if !username.is_empty() && !password.is_empty() {
                    proxy.push_str(&format!(",{},\"{}\"", username, password));
                }

                proxy.push_str(&format!(
                    ",over-tls={}",
                    if tls_secure { "true" } else { "false" }
                ));

                if tls_secure {
                    if !host.is_empty() {
                        proxy.push_str(&format!(",tls-name={}", host));
                    }

                    if scv.is_some() {
                        proxy.push_str(&format!(
                            ",skip-cert-verify={}",
                            if scv.unwrap_or(false) {
                                "true"
                            } else {
                                "false"
                            }
                        ));
                    }
                }
            }
            ProxyType::WireGuard => {
                let default_wg = Default::default();
                let wg = node.as_wireguard().unwrap_or(&default_wg);
                proxy = format!(
                    "wireguard, interface-ip={}",
                    wg.self_ip.as_deref().unwrap_or("")
                );

                if let Some(ipv6) = &wg.self_ipv6 {
                    if !ipv6.is_empty() {
                        proxy.push_str(&format!(", interface-ipv6={}", ipv6));
                    }
                }

                if let Some(private_key) = &wg.private_key {
                    proxy.push_str(&format!(", private-key={}", private_key));
                }

                // Add DNS servers
                for server in &wg.dns_servers {
                    // Check if IPv4 or IPv6
                    if server.contains('.') {
                        proxy.push_str(&format!(", dns={}", server));
                    } else if server.contains(':') {
                        proxy.push_str(&format!(", dnsv6={}", server));
                    }
                }

                if wg.mtu > 0 {
                    proxy.push_str(&format!(", mtu={}", wg.mtu));
                }

                if wg.keep_alive > 0 {
                    proxy.push_str(&format!(", keepalive={}", wg.keep_alive));
                }

                // Add peer info
                proxy.push_str(&format!(", peers=[{{{}}}]", generate_peer(node, true)));
            }
            _ => continue,
        }

        // Add fast-open option if enabled
        if ext.tfo.unwrap_or(false) {
            proxy.push_str(",fast-open=true");
        }

        // Add UDP option if enabled
        if ext.udp.unwrap_or(false) {
            proxy.push_str(",udp=true");
        }

        // Add to nodelist or INI
        if ext.nodelist {
            output_nodelist.push_str(&format!("{} = {}\n", remark, proxy));
        } else {
            ini.set("{NONAME}", &format!("{} = {}", remark, proxy), "")
                .unwrap_or(());
            nodelist.push(node.clone());
            remarks_list.push(remark);
        }
    }

    if ext.nodelist {
        return output_nodelist;
    }

    // Process proxy groups
    let original_groups: HashMap<String, Vec<String>> = HashMap::new();
    ini.set_current_section("Proxy Group");
    ini.erase_section();

    for group in extra_proxy_group {
        let mut filtered_nodelist = Vec::new();
        let mut group_str;

        match group.group_type {
            ProxyGroupType::Select
            | ProxyGroupType::LoadBalance
            | ProxyGroupType::URLTest
            | ProxyGroupType::Fallback => {
                // These types are supported
            }
            ProxyGroupType::SSID => {
                if group.proxies.len() < 2 {
                    continue;
                }
                group_str = format!("{},default={},", group.type_str(), group.proxies[0]);
                group_str.push_str(&join(&group.proxies[1..], ","));
                ini.set("{NONAME}", &format!("{} = {}", group.name, group_str), "")
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

        // Update original_groups handling to extract image URLs
        // In C++ original_groups is loaded from the INI and checked for image-url values
        // For each group, get the items from original_groups and check for img-url:
        let mut img_url = String::new();
        if let Some(values) = original_groups.get(&group.name) {
            if !values.is_empty() {
                // Check if the last element contains "img-url"
                let last_item = &values[values.len() - 1];
                if last_item.contains("img-url") {
                    img_url = last_item.clone();
                }
            }
        }

        // Build group string
        group_str = format!("{},", group.type_str());
        group_str.push_str(&join(&filtered_nodelist, ","));

        // Ensure proper order for group fields to match C++ implementation
        if group.group_type != ProxyGroupType::Select {
            // C++ adds these fields in this specific order
            group_str.push_str(&format!(",url={},interval={}", group.url, group.interval));

            // The additional fields are added based on group type
            if group.group_type == ProxyGroupType::LoadBalance {
                let algorithm = match group.strategy {
                    BalanceStrategy::RoundRobin => "round-robin",
                    BalanceStrategy::ConsistentHashing => "pcc",
                };
                group_str.push_str(&format!(",algorithm={}", algorithm));

                if group.timeout > 0 {
                    group_str.push_str(&format!(",max-timeout={}", group.timeout));
                }
            } else if group.group_type == ProxyGroupType::URLTest {
                // For URL-Test, add tolerance
                if group.tolerance > 0 {
                    group_str.push_str(&format!(",tolerance={}", group.tolerance));
                }
            } else if group.group_type == ProxyGroupType::Fallback {
                // For Fallback, add max-timeout
                group_str.push_str(&format!(",max-timeout={}", group.timeout));
            }
        }

        // Add image URL if found
        if !img_url.is_empty() {
            group_str.push_str(&format!(",{}", img_url));
        }

        ini.set("{NONAME}", &format!("{} = {}", group.name, group_str), "")
            .unwrap_or(());
    }

    // Generate rules if enabled
    if ext.enable_rule_generator {
        ruleset_to_loon(
            &mut ini,
            ruleset_content_array,
            ext.overwrite_original_rules,
            &ext.managed_config_prefix,
        )
        .await;
    }

    ini.to_string()
}

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
        peer.push_str(&format!("public-key={}", public_key));
    }

    peer.push_str(&format!(", endpoint={}:{}", node.hostname, node.port));

    if !wg.allowed_ips.is_empty() {
        peer.push_str(&format!(", allowed-ips={}", wg.allowed_ips));
    }

    if let Some(client_id) = &wg.client_id {
        if !client_id.is_empty() {
            if client_id_as_reserved {
                peer.push_str(&format!(", reserved={}", client_id));
            } else {
                peer.push_str(&format!(", client-id={}", client_id));
            }
        }
    }

    peer
}

async fn ruleset_to_loon(
    ini: &mut IniReader,
    ruleset_content_array: &mut Vec<RulesetContent>,
    overwrite_original_rules: bool,
    managed_config_prefix: &str,
) {
    ruleset_to_surge(
        ini,
        ruleset_content_array,
        -4,
        overwrite_original_rules,
        managed_config_prefix,
    )
    .await;
}
