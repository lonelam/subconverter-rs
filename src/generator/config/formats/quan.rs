use crate::generator::config::group::group_generate;
use crate::generator::config::remark::process_remark;
use crate::generator::ruleconvert::ruleset_to_surge::ruleset_to_surge;
use crate::models::{
    ExtraSettings, Proxy, ProxyGroupConfigs, ProxyGroupType, ProxyType, RulesetContent,
};
use crate::utils::base64::{base64_encode, url_safe_base64_encode};
use crate::utils::ini_reader::IniReader;
use crate::utils::regexp::reg_get_match;
use crate::utils::string::{join, replace_all_distinct, trim_of};
use crate::utils::tribool::BoolTriboolExt;
use crate::utils::url::url_encode;
use log::error;

/// Convert proxies to Quantumult format (main entry point)
///
/// This function converts a list of proxies to Quantumult format,
/// using a base configuration as a template and applying rules from ruleset_content_array.
///
/// # Arguments
/// * `nodes` - List of proxy nodes to convert
/// * `base_conf` - Base Quantumult configuration as a string
/// * `ruleset_content_array` - Array of ruleset contents to apply
/// * `extra_proxy_group` - Extra proxy group configurations
/// * `ext` - Extra settings for conversion
///
/// # Returns
/// * Quantumult configuration as a string
pub async fn proxy_to_quan(
    nodes: &mut Vec<Proxy>,
    base_conf: &str,
    ruleset_content_array: &mut Vec<RulesetContent>,
    extra_proxy_group: &ProxyGroupConfigs,
    ext: &mut ExtraSettings,
) -> String {
    let mut ini = IniReader::new();
    ini.store_any_line = true;

    // Parse base configuration if not in nodelist mode
    if !ext.nodelist && ini.parse(base_conf).is_err() {
        error!(
            "Quantumult base loader failed with error: {}",
            ini.get_last_error()
        );
        return String::new();
    }

    // Process nodes and rules
    proxy_to_quan_internal(
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
        if let Ok(nodes) = ini.get_all_current("") {
            all_nodes = nodes;
        }

        if !all_nodes.is_empty() {
            let all_links = join(&all_nodes, "\n");
            return base64_encode(&all_links);
        }

        return String::new();
    }

    ini.to_string()
}

/// Internal function for converting proxies to Quantumult format
///
/// This function handles the actual conversion logic for Quantumult.
///
/// # Arguments
/// * `nodes` - List of proxy nodes to convert
/// * `ini` - INI reader to store configuration
/// * `ruleset_content_array` - Array of ruleset contents to apply
/// * `extra_proxy_group` - Extra proxy group configurations
/// * `ext` - Extra settings for conversion
async fn proxy_to_quan_internal(
    nodes: &mut Vec<Proxy>,
    ini: &mut IniReader,
    ruleset_content_array: &mut Vec<RulesetContent>,
    extra_proxy_group: &ProxyGroupConfigs,
    ext: &mut ExtraSettings,
) {
    let mut nodelist = Vec::new();
    let mut remarks_list = Vec::new();

    // Set up SERVER section
    ini.set_current_section("SERVER");
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
        let edge = node.edge().unwrap_or("");
        let protocol = node.protocol().unwrap_or("");
        let protoparam = node.protocol_param().unwrap_or("");
        let obfs = node.obfs().unwrap_or("");
        let obfsparam = node.obfs_param().unwrap_or("");
        let plugin = node.plugin().unwrap_or("");
        let pluginopts = node.plugin_option().unwrap_or("");
        let tls_secure = node.tls_secure;
        let group = node.group.as_ref();

        // Define skip_cert_verify with default from ext and override with node-specific value
        let mut scv = ext.skip_cert_verify;
        scv = node.allow_insecure.as_ref().map_or(scv, |val| Some(*val));

        let mut proxy_str;

        // Format proxy string based on proxy type
        match node.proxy_type {
            ProxyType::VMess => {
                let mut actual_method = method;
                if method == "auto" {
                    actual_method = "chacha20-ietf-poly1305";
                }

                proxy_str = format!(
                    "{} = vmess, {}, {}, {}, \"{}\", group={}",
                    node.remark, hostname, port, actual_method, id, group
                );

                if tls_secure {
                    proxy_str.push_str(&format!(", over-tls=true, tls-host={}", host));
                    if !scv.is_undef() {
                        proxy_str.push_str(&format!(
                            ", certificate={}",
                            if scv.unwrap_or(false) { "0" } else { "1" }
                        ));
                    }
                }

                if transproto == "ws" {
                    proxy_str.push_str(&format!(
                        ", obfs=ws, obfs-path=\"{}\", obfs-header=\"Host: {}",
                        path, host
                    ));
                    if !edge.is_empty() {
                        proxy_str.push_str(&format!("[Rr][Nn]Edge: {}", edge));
                    }
                    proxy_str.push('"');
                }

                if ext.nodelist {
                    proxy_str = format!("vmess://{}", url_safe_base64_encode(&proxy_str));
                }
            }
            ProxyType::ShadowsocksR => {
                if ext.nodelist {
                    proxy_str = format!(
                        "ssr://{}",
                        url_safe_base64_encode(&format!(
                            "{}:{}:{}:{}:{}:{}/?group={}&remarks={}&obfsparam={}&protoparam={}",
                            hostname,
                            port,
                            protocol,
                            method,
                            obfs,
                            url_safe_base64_encode(password),
                            url_safe_base64_encode(group),
                            url_safe_base64_encode(&node.remark),
                            url_safe_base64_encode(obfsparam),
                            url_safe_base64_encode(protoparam)
                        ))
                    );
                } else {
                    proxy_str = format!(
                        "{} = shadowsocksr, {}, {}, {}, \"{}\", group={}, protocol={}, obfs={}",
                        node.remark, hostname, port, method, password, group, protocol, obfs
                    );

                    if !protoparam.is_empty() {
                        proxy_str.push_str(&format!(", protocol_param={}", protoparam));
                    }

                    if !obfsparam.is_empty() {
                        proxy_str.push_str(&format!(", obfs_param={}", obfsparam));
                    }
                }
            }
            ProxyType::Shadowsocks => {
                if ext.nodelist {
                    proxy_str = format!(
                        "ss://{}@{}:{}",
                        url_safe_base64_encode(&format!("{}:{}", method, password)),
                        hostname,
                        port
                    );

                    if !plugin.is_empty() && !pluginopts.is_empty() {
                        proxy_str.push_str(&format!(
                            "/?plugin={}",
                            url_encode(&format!("{};{}", plugin, pluginopts))
                        ));
                    }

                    proxy_str.push_str(&format!(
                        "&group={}#{}",
                        url_safe_base64_encode(group),
                        url_encode(&node.remark)
                    ));
                } else {
                    proxy_str = format!(
                        "{} = shadowsocks, {}, {}, {}, \"{}\", group={}",
                        node.remark, hostname, port, method, password, group
                    );

                    if plugin == "obfs-local" && !pluginopts.is_empty() {
                        proxy_str.push_str(&format!(
                            ", {}",
                            replace_all_distinct(pluginopts, ";", ", ")
                        ));
                    }
                }
            }
            ProxyType::HTTP | ProxyType::HTTPS => {
                proxy_str = format!(
                    "{} = http, upstream-proxy-address={}, upstream-proxy-port={}, group={}",
                    node.remark, hostname, port, group
                );

                if !username.is_empty() && !password.is_empty() {
                    proxy_str.push_str(
                        &format!(
                            ", upstream-proxy-auth=true, upstream-proxy-username={}, upstream-proxy-password={}",
                            username, password
                        )
                    );
                } else {
                    proxy_str.push_str(", upstream-proxy-auth=false");
                }

                if tls_secure {
                    proxy_str.push_str(", over-tls=true");
                    if !host.is_empty() {
                        proxy_str.push_str(&format!(", tls-host={}", host));
                    }
                    if !scv.is_undef() {
                        proxy_str.push_str(&format!(
                            ", certificate={}",
                            if scv.unwrap_or(false) { "0" } else { "1" }
                        ));
                    }
                }

                if ext.nodelist {
                    proxy_str = format!("http://{}", url_safe_base64_encode(&proxy_str));
                }
            }
            ProxyType::Socks5 => {
                proxy_str = format!(
                    "{} = socks, upstream-proxy-address={}, upstream-proxy-port={}, group={}",
                    node.remark, hostname, port, group
                );

                if !username.is_empty() && !password.is_empty() {
                    proxy_str.push_str(
                        &format!(
                            ", upstream-proxy-auth=true, upstream-proxy-username={}, upstream-proxy-password={}",
                            username, password
                        )
                    );
                } else {
                    proxy_str.push_str(", upstream-proxy-auth=false");
                }

                if tls_secure {
                    proxy_str.push_str(", over-tls=true");
                    if !host.is_empty() {
                        proxy_str.push_str(&format!(", tls-host={}", host));
                    }
                    if !scv.is_undef() {
                        proxy_str.push_str(&format!(
                            ", certificate={}",
                            if scv.unwrap_or(false) { "0" } else { "1" }
                        ));
                    }
                }

                if ext.nodelist {
                    proxy_str = format!("socks://{}", url_safe_base64_encode(&proxy_str));
                }
            }
            _ => continue,
        }

        // Add to INI
        ini.set("{NONAME}", &proxy_str, "").unwrap_or(());
        remarks_list.push(node.remark.clone());
        nodelist.push(node.clone());
    }

    // Stop here if nodelist mode is enabled
    if ext.nodelist {
        return;
    }

    // Process proxy groups
    ini.set_current_section("POLICY");
    ini.erase_section();

    for group in extra_proxy_group {
        let mut filtered_nodelist = Vec::new();
        let mut single_group;

        // Determine group type and format accordingly
        match group.group_type {
            ProxyGroupType::Select | ProxyGroupType::Fallback => {
                // Process as static type
                for proxy_name in &group.proxies {
                    group_generate(proxy_name, &nodelist, &mut filtered_nodelist, true, ext);
                }

                if filtered_nodelist.is_empty() {
                    filtered_nodelist.push("direct".to_string());
                }

                let proxies = join(&filtered_nodelist, "\n");

                single_group = format!("{} : static, {}", group.name, filtered_nodelist[0]);
                single_group.push_str(&format!("\n{}\n", proxies));
            }
            ProxyGroupType::URLTest => {
                // Process as auto type
                for proxy_name in &group.proxies {
                    group_generate(proxy_name, &nodelist, &mut filtered_nodelist, true, ext);
                }

                if filtered_nodelist.is_empty() {
                    filtered_nodelist.push("direct".to_string());
                }

                let proxies = join(&filtered_nodelist, "\n");

                // For groups with only 1 node, force static type
                if filtered_nodelist.len() < 2 {
                    single_group = format!("{} : static, {}", group.name, filtered_nodelist[0]);
                } else {
                    single_group = format!("{} : auto", group.name);
                }

                single_group.push_str(&format!("\n{}\n", proxies));
            }
            ProxyGroupType::LoadBalance => {
                // Process as balance type
                for proxy_name in &group.proxies {
                    group_generate(proxy_name, &nodelist, &mut filtered_nodelist, true, ext);
                }

                if filtered_nodelist.is_empty() {
                    filtered_nodelist.push("direct".to_string());
                }

                let proxies = join(&filtered_nodelist, "\n");

                // For groups with only 1 node, force static type
                if filtered_nodelist.len() < 2 {
                    single_group = format!("{} : static, {}", group.name, filtered_nodelist[0]);
                } else {
                    single_group = format!("{} : balance, round-robin", group.name);
                }

                single_group.push_str(&format!("\n{}\n", proxies));
            }
            ProxyGroupType::SSID => {
                // Handle SSID group type
                if group.proxies.len() < 1 {
                    continue;
                }

                single_group = format!("{} : wifi = {}", group.name, group.proxies[0]);

                let mut content = String::new();
                let celluar_matcher = r"^(.*?),?celluar\s?=\s?(.*?)(,.*)$";
                let mut celluar = String::new();

                // Process SSID rules
                for proxy in group.proxies.iter().skip(1) {
                    let captures = reg_get_match(proxy, celluar_matcher);
                    if captures.len() != 4 {
                        content.push_str(&format!("{}\n", proxy));
                        continue;
                    }
                    let (rem_a, celluar_match, rem_b) = (
                        captures[1].to_string(),
                        captures[2].to_string(),
                        captures[3].to_string(),
                    );

                    if !celluar_match.is_empty() {
                        celluar = celluar_match;
                        content.push_str(&format!("{}{}\n", rem_a, rem_b));
                    } else {
                        content.push_str(&format!("{}\n", proxy));
                    }
                }

                if !celluar.is_empty() {
                    single_group.push_str(&format!(", celluar = {}", celluar));
                }

                single_group.push('\n');
                single_group.push_str(&replace_all_distinct(
                    &trim_of(&content, ',', true, true),
                    ",",
                    "\n",
                ));
            }
            _ => continue,
        }

        // Add group to INI if not empty
        if !single_group.is_empty() {
            ini.set("{NONAME}", &base64_encode(&single_group), "")
                .unwrap_or(());
        }
    }

    // Generate rules if enabled
    if ext.enable_rule_generator {
        ruleset_to_surge(
            ini,
            ruleset_content_array,
            -2,
            ext.overwrite_original_rules,
            "",
        )
        .await;
    }
}
