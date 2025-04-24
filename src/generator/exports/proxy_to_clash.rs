use crate::generator::config::group::group_generate;
use crate::generator::config::remark::process_remark;
use crate::generator::ruleset_to_clash_str::ruleset_to_clash;
use crate::generator::yaml::clash::clash_output::{
    ClashProxyGroup, ClashProxyOutput, ClashYamlOutput, SerializableClashYamlOutput,
};
use crate::models::{
    ExtraSettings, Proxy, ProxyGroupConfig, ProxyGroupConfigs, ProxyGroupType, ProxyType,
    RulesetContent,
};
use log::{error, warn};
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

/// Converts ProxyGroupConfigs to a vector of ClashProxyGroup enum objects
fn convert_proxy_groups_to_enum(
    group_configs: &[ProxyGroupConfig],
    filtered_nodes_map: Option<&HashMap<String, Vec<String>>>,
) -> Vec<ClashProxyGroup> {
    let mut clash_groups = Vec::with_capacity(group_configs.len());

    for group in group_configs {
        let name = group.name.clone();

        // Determine proxies list, considering filtered nodes and the DIRECT default
        let mut proxies = if let Some(filtered_map) = filtered_nodes_map {
            filtered_map
                .get(&group.name)
                .cloned()
                .unwrap_or_else(|| group.proxies.clone())
        } else {
            group.proxies.clone()
        };

        // Add DIRECT if proxies are empty and no providers are used
        if proxies.is_empty() && group.using_provider.is_empty() {
            proxies = vec!["DIRECT".to_string()];
        }

        // Map using_provider to r#use, ensuring it's None if empty
        let r#use = if group.using_provider.is_empty() {
            None
        } else {
            Some(group.using_provider.clone())
        };

        // Map disable_udp to Option<bool>, None if false (default)
        let disable_udp = if group.disable_udp { Some(true) } else { None };

        // Helper to convert u32 to Option<u32>, None if zero
        let interval_opt = if group.interval > 0 {
            Some(group.interval)
        } else {
            None
        };
        let tolerance_opt = if group.tolerance > 0 {
            Some(group.tolerance)
        } else {
            None
        };

        let clash_group = match group.group_type {
            ProxyGroupType::Select => ClashProxyGroup::Select {
                name,
                proxies,
                r#use,
                disable_udp,
            },
            ProxyGroupType::Relay => ClashProxyGroup::Relay {
                name,
                proxies,
                disable_udp,
                r#use,
            },
            ProxyGroupType::URLTest | ProxyGroupType::Smart => {
                // Smart group is treated as url-test
                ClashProxyGroup::UrlTest {
                    name,
                    proxies,
                    url: group.url.clone(), // url is required for UrlTest
                    interval: interval_opt,
                    tolerance: tolerance_opt,
                    lazy: if !group.lazy { Some(false) } else { None }, // None if true (default)
                    disable_udp,
                    r#use,
                }
            }
            ProxyGroupType::Fallback => ClashProxyGroup::Fallback {
                name,
                proxies,
                url: group.url.clone(), // url is required for Fallback
                interval: interval_opt,
                tolerance: tolerance_opt,
                disable_udp,
                r#use,
            },
            ProxyGroupType::LoadBalance => {
                // Map persistent and evaluate_before_use to Option<bool>, None if false (default)
                let persistent = if group.persistent { Some(true) } else { None };
                let evaluate_before_use = if group.evaluate_before_use {
                    Some(true)
                } else {
                    None
                };

                ClashProxyGroup::LoadBalance {
                    name,
                    proxies,
                    strategy: group.strategy_str().to_string(),
                    url: if group.url.is_empty() {
                        None
                    } else {
                        Some(group.url.clone())
                    }, // Optional for LoadBalance
                    interval: interval_opt,
                    tolerance: tolerance_opt,
                    lazy: if group.lazy { None } else { Some(false) }, // None if true (default)
                    disable_udp,
                    r#use,
                    persistent,
                    evaluate_before_use,
                }
            }
            ProxyGroupType::SSID => {
                // SSID groups are not directly represented in the ClashProxyGroup enum
                // and are typically handled differently by specific formatters (e.g., Surge, Loon).
                // Skip conversion for now.
                warn!(
                    "Skipping SSID group '{}' during Clash enum conversion.",
                    group.name
                );
                continue; // Skip adding this group
            }
        };
        clash_groups.push(clash_group);
    }

    clash_groups
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
    // Parse the base configuration into ClashYamlOutput, default if empty or error
    let mut output: ClashYamlOutput = match serde_yaml::from_str(base_conf) {
        Ok(parsed_output) => parsed_output,
        Err(e) => {
            if !base_conf.trim().is_empty() {
                // Only warn if base_conf wasn't empty
                warn!("Failed to parse base Clash config: {}. Using default.", e);
            }
            ClashYamlOutput::default()
        }
    };

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
            ProxyType::Snell if node.snell_version >= 4 => true,

            // Skip if not using ClashR or if using deprecated features with ShadowsocksR
            ProxyType::ShadowsocksR if !clash_r && ext.filter_deprecated => true,

            // Skip chacha20 encryption if filter_deprecated is enabled
            ProxyType::Shadowsocks
                if ext.filter_deprecated && node.encrypt_method.as_deref() == Some("chacha20") =>
            {
                true
            }

            // Skip ShadowsocksR with deprecated features if filter_deprecated is enabled
            ProxyType::ShadowsocksR if ext.filter_deprecated => {
                let encrypt_method = node.encrypt_method.as_deref().unwrap_or("");
                let protocol = node.protocol.as_deref().unwrap_or("");
                let obfs = node.obfs.as_deref().unwrap_or("");

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

    // Handle nodelist mode specifically
    if ext.nodelist {
        let mut provider = serde_yaml::Mapping::new();
        provider.insert(
            serde_yaml::Value::String("proxies".to_string()),
            serde_yaml::to_value(&proxies_json).unwrap_or(serde_yaml::Value::Sequence(Vec::new())),
        );
        // Serialize just the provider map
        return match serde_yaml::to_string(&provider) {
            Ok(result) => result,
            Err(e) => {
                error!("Failed to serialize nodelist: {}", e);
                String::new()
            }
        };
    }

    // Update the ClashYamlOutput with proxies
    output.proxies = proxies_json;

    // Add proxy groups if present
    if !extra_proxy_group.is_empty() {
        // Get existing proxy groups from parsed base config
        let mut original_groups = std::mem::take(&mut output.proxy_groups);

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

        // Convert proxy groups using the new serialization struct
        let clash_proxy_groups =
            convert_proxy_groups_to_enum(extra_proxy_group, Some(&filtered_nodes_map));

        // Merge with existing groups (replace by name or append)
        let mut final_groups = Vec::new();
        let mut processed_indices = HashSet::new(); // Track indices of original groups processed

        for new_group in clash_proxy_groups {
            let mut replaced = false;
            for (i, existing_group) in original_groups.iter().enumerate() {
                // Need a way to get the name from ClashProxyGroup enum
                // Assuming a method `name()` exists or accessing a public field
                let existing_name = existing_group.name();

                // Get name from the new group (which is now also an enum)
                let new_name = new_group.name();

                // Compare names
                if existing_name == new_name {
                    final_groups.push(new_group.clone()); // Use the new group
                    processed_indices.insert(i);
                    replaced = true;
                    break;
                }
            }
            if !replaced {
                final_groups.push(new_group); // Add new group if no existing one matched
            }
        }

        // Add back original groups that were not replaced
        for (i, existing_group) in original_groups.into_iter().enumerate() {
            if !processed_indices.contains(&i) {
                final_groups.push(existing_group);
            }
        }

        // Update the ClashYamlOutput with merged proxy groups
        output.proxy_groups = final_groups;
    }

    // Handle rule generation if enabled
    if ext.enable_rule_generator {
        // Generate rules using the refactored function
        let mut generated_rules = ruleset_to_clash(ruleset_content_array);

        // Prepend existing rules if not overwriting
        if !ext.overwrite_original_rules {
            let mut existing_rules = std::mem::take(&mut output.rules);
            existing_rules.append(&mut generated_rules);
            output.rules = existing_rules;
        } else {
            output.rules = generated_rules;
        }

        // Handle managed config and clash script mode update
        if !ext.managed_config_prefix.is_empty() || ext.clash_script {
            // Set mode based on clash_script and clash_new_field_name
            let mode_str = if ext.clash_script {
                // Clash script mode names are capitalized by default
                if ext.clash_new_field_name {
                    "script"
                } else {
                    "Script"
                }
            } else {
                // Rule mode names are lowercase by default
                if ext.clash_new_field_name {
                    "rule"
                } else {
                    "Rule" // Note: Old clash might expect "Rule", check compatibility
                }
            };
            output.mode = Some(mode_str.to_string());

            // TODO: Implement renderClashScript - affects final output string, not just mode
            // For now, serialization below handles the structure based on the set mode.
        }
    } else {
        // If rule generation is disabled, ensure rules from base_conf are kept
        // (This happens by default as we parsed base_conf into output)
    }

    // Serialize the final ClashYamlOutput using the wrapper
    let serializable_output = SerializableClashYamlOutput::new(&output, ext.clash_new_field_name);

    match serde_yaml::to_string(&serializable_output) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to serialize Clash config: {}", e);
            String::new()
        }
    }
}
