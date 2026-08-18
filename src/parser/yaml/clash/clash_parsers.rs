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
