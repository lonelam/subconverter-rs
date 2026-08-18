use crate::models::{ExtraSettings, Proxy, ProxyType, SS_CIPHERS};
use crate::utils::string::trim_whitespace;
use log::error;
use serde_json::{json, Value as JsonValue};

/// Convert proxies to SIP008 Shadowsocks subscription format
///
/// This function converts a list of proxies to the SIP008 JSON format
/// used by modern Shadowsocks clients.
///
/// # Arguments
/// * `base_conf` - Base configuration as a JSON string
/// * `nodes` - List of proxy nodes to convert
/// * `ext` - Extra settings for conversion
///
/// # Returns
/// * JSON string in SIP008 format
pub fn proxy_to_ss_sub(
    base_conf: &str,
    nodes: &mut Vec<Proxy>,
    _ext: &mut ExtraSettings,
) -> String {
    // Parse the base configuration
    let base_conf = trim_whitespace(base_conf, true, true);
    let base_conf = if base_conf.is_empty() {
        "{}"
    } else {
        &base_conf
    };

    let base_json: JsonValue = match serde_json::from_str(base_conf) {
        Ok(json) => json,
        Err(e) => {
            error!("SIP008 base loader failed with error: {}", e);
            json!({})
        }
    };

    // Create the array to hold proxy objects
    let mut proxies = Vec::new();

    // Process each proxy node
    for node in nodes {
        let remark = &node.remark;
        let hostname = &node.hostname;
        let port = node.port;

        // Extract optional fields with safe defaults
        let password = node.password().unwrap_or("");
        let method = node.encrypt_method().unwrap_or("");
        let mut plugin = node.plugin().unwrap_or("").to_string();
        let plugin_opts = node.plugin_option().unwrap_or("");
        let protocol = node.protocol().unwrap_or("");
        let obfs = node.obfs().unwrap_or("");

        // Filter nodes based on type and compatibility
        match node.proxy_type {
            ProxyType::Shadowsocks => {
                // Convert simple-obfs to obfs-local
                if plugin == "simple-obfs" {
                    plugin = "obfs-local".to_string();
                }
            }
            ProxyType::ShadowsocksR => {
                // Skip incompatible SSR nodes
                if !SS_CIPHERS.contains(&method) || protocol != "origin" || obfs != "plain" {
                    continue;
                }
            }
            _ => continue, // Skip all other proxy types
        }

        // Create a proxy object
        let mut proxy = match base_json.as_object() {
            Some(obj) => obj.clone(),
            None => serde_json::Map::new(),
        };

        // Add all required fields
        proxy.insert("remarks".to_string(), json!(remark));
        proxy.insert("server".to_string(), json!(hostname));
        proxy.insert("server_port".to_string(), json!(port));
        proxy.insert("method".to_string(), json!(method));
        proxy.insert("password".to_string(), json!(password));
        proxy.insert("plugin".to_string(), json!(plugin));
        proxy.insert("plugin_opts".to_string(), json!(plugin_opts));

        // Add to proxies array
        proxies.push(JsonValue::Object(proxy));
    }

    // Serialize the array to a JSON string
    match serde_json::to_string_pretty(&proxies) {
        Ok(json_str) => json_str,
        Err(e) => {
            error!("Failed to serialize SIP008 JSON: {}", e);
            String::new()
        }
    }
}
