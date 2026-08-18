use crate::generator::config::group::group_generate;
use crate::generator::config::remark::process_remark;
use crate::generator::ruleconvert::ruleset_to_clash_str;
use crate::generator::yaml::clash::clash_output::ClashProxyOutput;
use crate::generator::yaml::proxy_group_output::convert_proxy_groups;
use crate::models::{ExtraSettings, Proxy, ProxyGroupConfigs, ProxyType, RulesetContent};
use log::error;
use serde_yaml::{self, Mapping, Sequence, Value as YamlValue};
use std::collections::{HashMap, HashSet};

// Lists of supported protocols and encryption methods for filtering in ClashR
lazy_static::lazy_static! {
    static ref CLASH_SSR_CIPHERS: HashSet<&'static str> = {
        let mut ciphers = HashSet::new();
        ciphers.insert("aes-128-cfb");
        ciphers.insert("aes-192-cfb");
        ciphers.insert("aes-256-cfb");
        ciphers.insert("aes-128-ctr");
        ciphers.insert("aes-192-ctr");
        ciphers.insert("aes-256-ctr");
        ciphers.insert("aes-128-ofb");
        ciphers.insert("aes-192-ofb");
        ciphers.insert("aes-256-ofb");
        ciphers.insert("des-cfb");
        ciphers.insert("bf-cfb");
        ciphers.insert("cast5-cfb");
        ciphers.insert("rc4-md5");
        ciphers.insert("chacha20");
        ciphers.insert("chacha20-ietf");
        ciphers.insert("salsa20");
        ciphers.insert("camellia-128-cfb");
        ciphers.insert("camellia-192-cfb");
        ciphers.insert("camellia-256-cfb");
        ciphers.insert("idea-cfb");
        ciphers.insert("rc2-cfb");
        ciphers.insert("seed-cfb");
        ciphers
    };

    static ref CLASHR_PROTOCOLS: HashSet<&'static str> = {
        let mut protocols = HashSet::new();
        protocols.insert("origin");
        protocols.insert("auth_sha1_v4");
        protocols.insert("auth_aes128_md5");
        protocols.insert("auth_aes128_sha1");
        protocols.insert("auth_chain_a");
        protocols.insert("auth_chain_b");
        protocols
    };

    static ref CLASHR_OBFS: HashSet<&'static str> = {
        let mut obfs = HashSet::new();
        obfs.insert("plain");
        obfs.insert("http_simple");
        obfs.insert("http_post");
        obfs.insert("random_head");
        obfs.insert("tls1.2_ticket_auth");
        obfs.insert("tls1.2_ticket_fastauth");
        obfs
    };
}

/// Convert proxies to Clash format
///
/// This function converts a list of proxies to the Clash configuration format,
/// using a base configuration as a template and applying rules from ruleset_content_array.
///
/// # Arguments
/// * `nodes` - List of proxy nodes to convert
/// * `base_conf` - Base Clash configuration as a string
/// * `ruleset_content_array` - Array of ruleset contents to apply
/// * `extra_proxy_group` - Extra proxy group configurations
/// * `clash_r` - Whether to use ClashR format
/// * `ext` - Extra settings for conversion
pub fn proxy_to_clash(
    nodes: &mut Vec<Proxy>,
    base_conf: &str,
    ruleset_content_array: &mut Vec<RulesetContent>,
    extra_proxy_group: &ProxyGroupConfigs,
    clash_r: bool,
    ext: &mut ExtraSettings,
) -> String {
    // Parse the base configuration
    let mut yaml_node: YamlValue = match serde_yaml::from_str(base_conf) {
        Ok(node) => node,
        Err(e) => {
            error!("Clash base loader failed with error: {}", e);
            return String::new();
        }
    };

    if yaml_node.is_null() {
        yaml_node = YamlValue::Mapping(Mapping::new());
    }

    // Apply conversion to the YAML node
    proxy_to_clash_yaml(
        nodes,
        &mut yaml_node,
        ruleset_content_array,
        extra_proxy_group,
        clash_r,
        ext,
    );

    // If nodelist mode is enabled, just return the YAML node
    if ext.nodelist {
        return match serde_yaml::to_string(&yaml_node) {
            Ok(result) => result,
            Err(_) => String::new(),
        };
    }

    // Handle rule generation if enabled
    if !ext.enable_rule_generator {
        return match serde_yaml::to_string(&yaml_node) {
            Ok(result) => result,
            Err(_) => String::new(),
        };
    }

    // Handle managed config and clash script
    if !ext.managed_config_prefix.is_empty() || ext.clash_script {
        // Set mode if it exists
        if yaml_node.get("mode").is_some() {
            if let Some(ref mut map) = yaml_node.as_mapping_mut() {
                map.insert(
                    YamlValue::String("mode".to_string()),
                    YamlValue::String(
                        if ext.clash_script {
                            if ext.clash_new_field_name {
                                "script"
                            } else {
                                "Script"
                            }
                        } else {
                            if ext.clash_new_field_name {
                                "rule"
                            } else {
                                "Rule"
                            }
                        }
                        .to_string(),
                    ),
                );
            }
        }

        // TODO: Implement renderClashScript
        // For now, just return the YAML
        return match serde_yaml::to_string(&yaml_node) {
            Ok(result) => result,
            Err(_) => String::new(),
        };
    }

    // Generate rules and return combined output
    let rules_str = ruleset_to_clash_str(
        &yaml_node,
        ruleset_content_array,
        ext.overwrite_original_rules,
        ext.clash_new_field_name,
    );

    let yaml_output = match serde_yaml::to_string(&yaml_node) {
        Ok(result) => result,
        Err(_) => String::new(),
    };

    format!("{}{}", yaml_output, rules_str)
}

/// Convert proxies to Clash format with YAML node
///
/// This function modifies a YAML node in place to add Clash configuration
/// for the provided proxy nodes.
///
/// # Arguments
/// * `nodes` - List of proxy nodes to convert
/// * `yaml_node` - YAML node to modify
/// * `ruleset_content_array` - Array of ruleset contents to apply
/// * `extra_proxy_group` - Extra proxy group configurations
/// * `clash_r` - Whether to use ClashR format
/// * `ext` - Extra settings for conversion
pub fn proxy_to_clash_yaml(
    nodes: &mut Vec<Proxy>,
    yaml_node: &mut serde_yaml::Value,
    _ruleset_content_array: &Vec<RulesetContent>,
    extra_proxy_group: &ProxyGroupConfigs,
    clash_r: bool,
    ext: &mut ExtraSettings,
) {
    // Style settings - in C++ this is used to set serialization style but in Rust we have less control
    // over the serialization format. We keep them for compatibility but their actual effect may differ.
    let _proxy_block = ext.clash_proxies_style == "block";
    let _proxy_compact = ext.clash_proxies_style == "compact";
    let _group_block = ext.clash_proxy_groups_style == "block";
    let _group_compact = ext.clash_proxy_groups_style == "compact";

    // Create JSON structure for the proxies
    let mut proxies_json = Vec::new();
    let mut remarks_list = Vec::new();

    // Process each node
    for node in nodes.iter_mut() {
        // Create a local copy of the node for processing
        let mut remark = node.remark.clone();

        // Add proxy type prefix if enabled
        if ext.append_proxy_type {
            remark = format!("[{}] {}", node.proxy_type.to_string(), remark);
        }

        // Process remark with optional remarks list
        process_remark(&mut remark, &remarks_list, false);
        remarks_list.push(remark.clone());
        // Check if this proxy type should be skipped
        let should_skip = match node.proxy_type {
            // Skip Snell v4+ if exists - exactly matching C++ behavior
            ProxyType::Snell if node.snell_version() >= 4 => true,

            // Skip if not using ClashR or if using deprecated features with ShadowsocksR
            ProxyType::ShadowsocksR if !clash_r && ext.filter_deprecated => true,

            // Skip chacha20 encryption if filter_deprecated is enabled
            ProxyType::Shadowsocks
                if ext.filter_deprecated && node.encrypt_method() == Some("chacha20") =>
            {
                true
            }

            // Skip ShadowsocksR with deprecated features if filter_deprecated is enabled
            ProxyType::ShadowsocksR if ext.filter_deprecated => {
                let encrypt_method = node.encrypt_method().unwrap_or("");
                let protocol = node.protocol().unwrap_or("");
                let obfs = node.obfs().unwrap_or("");

                !CLASH_SSR_CIPHERS.contains(encrypt_method)
                    || !CLASHR_PROTOCOLS.contains(protocol)
                    || !CLASHR_OBFS.contains(obfs)
            }

            // Skip unsupported proxy types
            ProxyType::Unknown | ProxyType::HTTPS => true,

            // Process all other types
            _ => false,
        };

        if should_skip {
            continue;
        }

        // 创建代理副本，并应用所有必要的属性设置
        let proxy_copy = node.clone().set_remark(remark).apply_default_values(
            ext.udp,
            ext.tfo,
            ext.skip_cert_verify,
        );

        // 使用 From trait 自动转换为 ClashProxyOutput
        let clash_proxy = ClashProxyOutput::from(proxy_copy);

        // 添加到代理列表
        proxies_json.push(clash_proxy);
    }

    if ext.nodelist {
        let mut provider = YamlValue::Mapping(Mapping::new());
        provider["proxies"] =
            serde_yaml::to_value(&proxies_json).unwrap_or(YamlValue::Sequence(Vec::new()));
        *yaml_node = provider;
        return;
    }

    // Update the YAML node with proxies
    if let Some(ref mut map) = yaml_node.as_mapping_mut() {
        // Convert JSON proxies array to YAML
        let proxies_yaml_value =
            serde_yaml::to_value(&proxies_json).unwrap_or(YamlValue::Sequence(Vec::new()));
        if ext.clash_new_field_name {
            map.insert(YamlValue::String("proxies".to_string()), proxies_yaml_value);
        } else {
            map.insert(YamlValue::String("Proxy".to_string()), proxies_yaml_value);
        }
    }

    // Add proxy groups if present
    if !extra_proxy_group.is_empty() {
        // Get existing proxy groups if any
        let mut original_groups = if ext.clash_new_field_name {
            match yaml_node.get("proxy-groups") {
                Some(YamlValue::Sequence(seq)) => seq.clone(),
                _ => Sequence::new(),
            }
        } else {
            match yaml_node.get("Proxy Group") {
                Some(YamlValue::Sequence(seq)) => seq.clone(),
                _ => Sequence::new(),
            }
        };

        // Build filtered nodes map for each group
        let mut filtered_nodes_map = HashMap::new();
        for group in extra_proxy_group {
            let mut filtered_nodes = Vec::new();
            for proxy_name in &group.proxies {
                group_generate(proxy_name, nodes, &mut filtered_nodes, true, ext);
            }

            // Add DIRECT if empty
            if filtered_nodes.is_empty() && group.using_provider.is_empty() {
                filtered_nodes.push("DIRECT".to_string());
            }

            filtered_nodes_map.insert(group.name.clone(), filtered_nodes);
        }

        // Convert proxy groups using the new serialization
        let clash_proxy_groups = convert_proxy_groups(extra_proxy_group, Some(&filtered_nodes_map));

        // Merge with existing groups
        for group in clash_proxy_groups {
            // Check if this group should replace an existing one with the same name
            let mut replaced = false;
            for i in 0..original_groups.len() {
                if let Some(YamlValue::Mapping(map)) = original_groups.get(i) {
                    if let Some(YamlValue::String(name)) =
                        map.get(&YamlValue::String("name".to_string()))
                    {
                        if name == &group.name {
                            if let Some(elem) = original_groups.get_mut(i) {
                                // Convert the group to YAML and replace
                                if let Ok(group_yaml) = serde_yaml::to_value(&group) {
                                    *elem = group_yaml;
                                    replaced = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            // If not replaced, add to the list
            if !replaced {
                if let Ok(group_yaml) = serde_yaml::to_value(&group) {
                    original_groups.push(group_yaml);
                }
            }
        }

        // Update the YAML node with proxy groups
        if let Some(ref mut map) = yaml_node.as_mapping_mut() {
            if ext.clash_new_field_name {
                map.insert(
                    YamlValue::String("proxy-groups".to_string()),
                    YamlValue::Sequence(original_groups),
                );
            } else {
                map.insert(
                    YamlValue::String("Proxy Group".to_string()),
                    YamlValue::Sequence(original_groups),
                );
            }
        }
    }
}
