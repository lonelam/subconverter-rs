use crate::generator::config::group::group_generate;
use crate::generator::config::remark::process_remark;
use crate::generator::ruleconvert::ruleset_to_surge::ruleset_to_surge;
use crate::models::{
    ExtraSettings, Proxy, ProxyGroupConfigs, ProxyGroupType, ProxyType, RulesetContent,
};
use crate::utils::base64::url_safe_base64_encode;
use crate::utils::ini_reader::IniReader;
use crate::utils::string::{hash, join};
use crate::utils::tribool::BoolTriboolExt;
use crate::utils::url::url_encode;
use log::error;

/// Convert proxies to Mellow format (main entry point)
///
/// This function converts a list of proxies to Mellow format,
/// using a base configuration as a template and applying rules from ruleset_content_array.
///
/// # Arguments
/// * `nodes` - List of proxy nodes to convert
/// * `base_conf` - Base Mellow configuration as a string
/// * `ruleset_content_array` - Array of ruleset contents to apply
/// * `extra_proxy_group` - Extra proxy group configurations
/// * `ext` - Extra settings for conversion
///
/// # Returns
/// * Mellow configuration as a string
pub async fn proxy_to_mellow(
    nodes: &mut Vec<Proxy>,
    base_conf: &str,
    ruleset_content_array: &mut Vec<RulesetContent>,
    extra_proxy_group: &ProxyGroupConfigs,
    ext: &mut ExtraSettings,
) -> String {
    let mut ini = IniReader::new();
    ini.store_any_line = true;

    // Parse base configuration
    if ini.parse(base_conf).is_err() {
        error!(
            "Mellow base loader failed with error: {}",
            ini.get_last_error()
        );
        return String::new();
    }

    // Process nodes and rules
    proxy_to_mellow_internal(
        nodes,
        &mut ini,
        ruleset_content_array,
        extra_proxy_group,
        ext,
    )
    .await;

    // Return the INI as a string
    ini.to_string()
}

/// Internal function for converting proxies to Mellow format
///
/// This function handles the actual conversion logic for Mellow.
///
/// # Arguments
/// * `nodes` - List of proxy nodes to convert
/// * `ini` - INI reader to store configuration
/// * `ruleset_content_array` - Array of ruleset contents to apply
/// * `extra_proxy_group` - Extra proxy group configurations
/// * `ext` - Extra settings for conversion
async fn proxy_to_mellow_internal(
    nodes: &mut Vec<Proxy>,
    ini: &mut IniReader,
    ruleset_content_array: &mut Vec<RulesetContent>,
    extra_proxy_group: &ProxyGroupConfigs,
    ext: &mut ExtraSettings,
) {
    let mut nodelist = Vec::new();
    let mut remarks_list = Vec::new();

    // Set up Endpoint section
    ini.set_current_section("Endpoint");

    // Process each proxy node
    for node in nodes {
        // Add proxy type prefix if enabled
        if ext.append_proxy_type {
            let proxy_type = node.proxy_type.to_string();
            node.remark = format!("[{}] {}", proxy_type, node.remark);
        }

        // Process remark
        let mut remark = node.remark.clone();
        process_remark(&mut remark, &remarks_list, true);
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
        let quicsecure = node.quic_secure().unwrap_or("");
        let quicsecret = node.quic_secret().unwrap_or("");
        let plugin = node.plugin().unwrap_or("");
        let tls_secure = if node.tls_secure { "true" } else { "false" };

        // Get option values with defaults from ext
        let mut tfo = ext.tfo;
        let mut scv = ext.skip_cert_verify;

        // Override with node-specific values if present
        tfo = node.tcp_fast_open.as_ref().map_or(tfo, |val| Some(*val));
        scv = node.allow_insecure.as_ref().map_or(scv, |val| Some(*val));

        let mut _proxy_str: String = String::new();

        // Format proxy string based on proxy type
        match node.proxy_type {
            ProxyType::Shadowsocks => {
                // Skip if plugin is not empty
                if !plugin.is_empty() {
                    continue;
                }

                _proxy_str = format!(
                    "{}, ss, ss://{}/{}:{}",
                    node.remark,
                    url_safe_base64_encode(&format!("{}:{}", method, password)),
                    hostname,
                    port
                );
            }
            ProxyType::VMess => {
                _proxy_str = format!(
                    "{}, vmess1, vmess1://{}@{}:{}",
                    node.remark, id, hostname, port
                );

                // Add path if not empty
                if !path.is_empty() {
                    _proxy_str.push_str(path);
                }

                // Add network type
                _proxy_str.push_str(&format!("?network={}", transproto));

                // Add protocol-specific options
                match hash(transproto) {
                    h if h == hash("ws") => {
                        _proxy_str.push_str(&format!("&ws.host={}", url_encode(host)));
                    }
                    h if h == hash("http") => {
                        if !host.is_empty() {
                            _proxy_str.push_str(&format!("&http.host={}", url_encode(host)));
                        }
                    }
                    h if h == hash("quic") => {
                        if !quicsecure.is_empty() {
                            _proxy_str.push_str(&format!(
                                "&quic.security={}&quic.key={}",
                                quicsecure, quicsecret
                            ));
                        }
                    }
                    h if h == hash("kcp") || h == hash("tcp") => {
                        // No additional parameters needed
                    }
                    _ => {}
                }

                // Add TLS settings
                _proxy_str.push_str(&format!("&tls={}", tls_secure));

                if tls_secure == "true" {
                    if !host.is_empty() {
                        _proxy_str.push_str(&format!("&tls.servername={}", url_encode(host)));
                    }
                }

                // Add skip cert verify if defined
                if !scv.is_undef() {
                    _proxy_str.push_str(&format!(
                        "&tls.allowinsecure={}",
                        if scv.unwrap_or(false) {
                            "true"
                        } else {
                            "false"
                        }
                    ));
                }

                // Add TCP fast open if defined
                if !tfo.is_undef() {
                    _proxy_str.push_str(&format!(
                        "&sockopt.tcpfastopen={}",
                        if tfo.unwrap_or(false) {
                            "true"
                        } else {
                            "false"
                        }
                    ));
                }
            }
            ProxyType::Socks5 => {
                _proxy_str = format!(
                    "{}, builtin, socks, address={}, port={}, user={}, pass={}",
                    node.remark, hostname, port, username, password
                );
            }
            ProxyType::HTTP => {
                _proxy_str = format!(
                    "{}, builtin, http, address={}, port={}, user={}, pass={}",
                    node.remark, hostname, port, username, password
                );
            }
            _ => continue,
        }

        // Add to INI
        ini.set("{NONAME}", &_proxy_str, "").unwrap_or(());
        remarks_list.push(node.remark.clone());
        nodelist.push(node.clone());
    }

    // Process endpoint groups
    ini.set_current_section("EndpointGroup");

    for group in extra_proxy_group {
        // Only process certain group types
        match group.group_type {
            ProxyGroupType::Select
            | ProxyGroupType::URLTest
            | ProxyGroupType::Fallback
            | ProxyGroupType::LoadBalance => {
                // Generate node list
                let mut filtered_nodelist = Vec::new();

                // Process each proxy in the group
                for proxy_name in &group.proxies {
                    group_generate(proxy_name, &nodelist, &mut filtered_nodelist, false, ext);
                }

                // Use default if filtered list is empty
                if filtered_nodelist.is_empty() {
                    if remarks_list.is_empty() {
                        filtered_nodelist.push("DIRECT".to_string());
                    } else {
                        filtered_nodelist = remarks_list.clone();
                    }
                }

                // Create group string with joined node list
                let proxy_str = format!(
                    "{}, {}, latency, interval=300, timeout=6",
                    group.name,
                    join(&filtered_nodelist, ":")
                );

                // Add to INI
                ini.set("{NONAME}", &proxy_str, "").unwrap_or(());
            }
            _ => continue,
        }
    }

    // Generate rules if enabled
    if ext.enable_rule_generator {
        ruleset_to_surge(
            ini,
            ruleset_content_array,
            0,
            ext.overwrite_original_rules,
            "",
        )
        .await;
    }
}
