use crate::models::Proxy;
use crate::models::ProxyType;
use crate::utils::base64::base64_encode;
use crate::utils::string::replace_all_distinct;
use crate::utils::url::get_url_arg;
use serde_json::json;
use std::time::SystemTime;

/// Parse string to f64, return default value if parsing fails
fn parse_f64(s: &str, default: f64) -> f64 {
    s.parse::<f64>().unwrap_or(default)
}

/// Convert proxies to SSD subscription format
pub fn proxy_to_ssd(
    nodes: &mut Vec<Proxy>,
    group: &str,
    userinfo: &str,
    _ext: &crate::models::ExtraSettings,
) -> String {
    let mut index = 0;
    let group = if group.is_empty() { "SSD" } else { group };

    // Build base object
    let mut base = json!({
        "airport": group,
        "port": 1,
        "encryption": "aes-128-gcm",
        "password": "password"
    });

    // Handle user info if provided
    if !userinfo.is_empty() {
        let data = replace_all_distinct(userinfo, "; ", "&");
        let upload = get_url_arg(&data, "upload");
        let download = get_url_arg(&data, "download");
        let total = get_url_arg(&data, "total");
        let expire = get_url_arg(&data, "expire");

        let used =
            (parse_f64(&upload, 0.0) + parse_f64(&download, 0.0)) / f64::powf(1024.0, 3.0) * 1.0;
        let tot = parse_f64(&total, 0.0) / f64::powf(1024.0, 3.0) * 1.0;

        base["traffic_used"] = json!(used);
        base["traffic_total"] = json!(tot);

        if !expire.is_empty() {
            if let Ok(raw_time) = expire.parse::<i64>() {
                if let Some(dt) = SystemTime::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_secs(raw_time as u64))
                {
                    if let Ok(duration) = dt.duration_since(SystemTime::UNIX_EPOCH) {
                        let secs = duration.as_secs();
                        let mins = (secs / 60) % 60;
                        let hours = (secs / 3600) % 24;
                        let days = secs / 86400;
                        let years = days / 365;
                        let remaining_days = days % 365;
                        let months = remaining_days / 30;
                        let days = remaining_days % 30;

                        base["expiry"] = json!(format!(
                            "{:04}-{:02}-{:02} {:02}:{:02}",
                            1970 + years,
                            months + 1,
                            days + 1,
                            hours,
                            mins
                        ));
                    }
                }
            }
        }
    }

    // Process nodes
    let mut servers = Vec::new();
    for node in nodes.iter() {
        match node.proxy_type {
            ProxyType::Shadowsocks => {
                // Handle plugin conversion
                let plugin = node
                    .plugin()
                    .map(|p| {
                        if p == "obfs-local" {
                            "simple-obfs".to_string()
                        } else {
                            p.to_string()
                        }
                    })
                    .unwrap_or_default();

                let server = json!({
                    "server": node.hostname,
                    "port": node.port,
                    "encryption": node.encrypt_method(),
                    "password": node.password(),
                    "plugin": plugin,
                    "plugin_options": node.plugin_option().map(|s| s.to_string()).unwrap_or_default(),
                    "remarks": node.remark,
                    "id": index
                });
                servers.push(server);
                index += 1;
            }
            ProxyType::ShadowsocksR => {
                // Check if SSR can be converted to SS
                let ss_ciphers = [
                    "aes-128-gcm",
                    "aes-192-gcm",
                    "aes-256-gcm",
                    "chacha20-ietf-poly1305",
                ];

                // Only convert if method is supported and using basic settings
                if node
                    .encrypt_method()
                    .map_or(false, |m| ss_ciphers.contains(&m))
                    && node.protocol().map_or(false, |p| p == "origin")
                    && node.obfs().map_or(false, |o| o == "plain")
                {
                    let server = json!({
                        "server": node.hostname,
                        "port": node.port,
                        "encryption": node.encrypt_method(),
                        "password": node.password(),
                        "remarks": node.remark,
                        "id": index
                    });
                    servers.push(server);
                    index += 1;
                }
            }
            _ => continue,
        }
    }

    base["servers"] = json!(servers);

    // Return SSD URL
    format!("ssd://{}", base64_encode(&base.to_string()))
}
