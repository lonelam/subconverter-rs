use crate::models::Proxy;
use crate::parser::yaml::clash::clash_proxy_types::ClashProxyYamlInput;

/// Parse Clash configuration from YAML string
///
/// This function is the Rust equivalent of the C++ `explodeClash` function.
/// The key improvements in this Rust implementation are:
/// 1. Type safety through enum variants in ClashProxyYamlInput
/// 2. Proper error handling with Result type
/// 3. Automatic deserialization using serde
/// 4. Per-proxy resilience: one malformed node no longer discards the whole
///    subscription — it is logged and skipped instead.
pub fn parse_clash_yaml(content: &str) -> Result<Vec<Proxy>, String> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(content)
        .map_err(|e| format!("Failed to parse Clash YAML: {}", e))?;

    let proxy_entries = extract_proxy_entries(&yaml)
        .ok_or_else(|| "No `proxies` section found in Clash YAML".to_string())?;

    let mut proxies = Vec::new();
    for entry in proxy_entries {
        match serde_yaml::from_value::<ClashProxyYamlInput>(entry.clone()) {
            Ok(typed) => {
                if let Some(proxy) = typed.into_proxy() {
                    proxies.push(proxy);
                }
            }
            Err(e) => {
                log::warn!("Skipping malformed Clash proxy entry: {}", e);
            }
        }
    }

    Ok(proxies)
}

/// Locate the proxies sequence in a parsed Clash YAML document, supporting
/// both the modern `proxies` key and the legacy `Proxy` key.
pub fn extract_proxy_entries(yaml: &serde_yaml::Value) -> Option<&Vec<serde_yaml::Value>> {
    match yaml.get("proxies") {
        Some(serde_yaml::Value::Sequence(seq)) => Some(seq),
        _ => match yaml.get("Proxy") {
            Some(serde_yaml::Value::Sequence(seq)) => Some(seq),
            _ => None,
        },
    }
}
