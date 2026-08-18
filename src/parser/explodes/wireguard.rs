use crate::{utils::url_decode, Proxy};
use regex::Regex;
use std::collections::HashMap;
use url::Url;

/// Parse a WireGuard link into a Proxy object
pub fn explode_wireguard(wireguard: &str, node: &mut Proxy) -> bool {
    // Check if the link starts with wireguard://
    if !wireguard.starts_with("wireguard://") {
        return false;
    }

    // Try to parse as URL
    let url = match Url::parse(wireguard) {
        Ok(url) => url,
        Err(_) => return false,
    };

    // Extract parameters from the query string
    let mut params = HashMap::new();
    for (key, value) in url.query_pairs() {
        params.insert(key.to_string(), url_decode(&value));
    }

    // Extract required fields
    let private_key = match params.get("privateKey") {
        Some(key) => key,
        None => return false,
    };

    let public_key = match params.get("publicKey") {
        Some(key) => key,
        None => return false,
    };

    // Extract host and port
    let host = match url.host_str() {
        Some(host) => host,
        None => return false,
    };
    let port = url.port().unwrap_or(51820);

    // Extract optional fields
    let preshared_key = params.get("presharedKey").map(|s| s.as_str()).unwrap_or("");
    let self_ip = params
        .get("selfIP")
        .map(|s| s.as_str())
        .unwrap_or("10.0.0.2");
    let self_ipv6 = params.get("selfIPv6").map(|s| s.as_str()).unwrap_or("");
    let mtu = params
        .get("mtu")
        .map(|s| s.parse::<u16>().unwrap_or(1420))
        .unwrap_or(1420);
    let keep_alive = params
        .get("keepAlive")
        .map(|s| s.parse::<u16>().unwrap_or(25))
        .unwrap_or(25);

    // Extract DNS servers
    let dns_str = params.get("dns").map(|s| s.as_str()).unwrap_or("");
    let dns_servers: Vec<String> = if dns_str.is_empty() {
        vec!["1.1.1.1".to_string()]
    } else {
        dns_str.split(',').map(|s| s.trim().to_string()).collect()
    };

    // Extract remark from the fragment
    let remark = url_decode(url.fragment().unwrap_or(""));
    let formatted_remark = if remark.is_empty() {
        format!("{} ({})", host, port)
    } else {
        remark.to_string()
    };

    // Create the proxy object
    *node = Proxy::wireguard_construct(
        "WireGuard".to_string(),
        formatted_remark,
        host.to_string(),
        port,
        self_ip.to_string(),
        self_ipv6.to_string(),
        private_key.to_string(),
        public_key.to_string(),
        preshared_key.to_string(),
        dns_servers,
        Some(mtu),
        Some(keep_alive),
        "https://www.gstatic.com/generate_204".to_string(),
        "".to_string(),
        None,
        None,
    );
    parse_peers(wireguard, node);

    true
}

/// Parse WireGuard peers from configuration text
pub fn parse_peers(data: &str, node: &mut Proxy) -> bool {
    // Find peers enclosed in parentheses
    let peer_regex = Regex::new(r"\((.*?)\)").unwrap();
    let peers: Vec<&str> = peer_regex
        .captures_iter(data)
        .filter_map(|cap| cap.get(1))
        .map(|m| m.as_str())
        .collect();

    if peers.is_empty() {
        return false;
    }

    // Take the first peer
    let peer = peers[0];

    // Extract key-value pairs
    let pair_regex = Regex::new(r#"([a-z-]+) ?= ?([^" ),]+|".*?"),? ?"#).unwrap();
    let pairs: Vec<(String, String)> = pair_regex
        .captures_iter(peer)
        .filter_map(|cap| {
            if let (Some(key), Some(val)) = (cap.get(1), cap.get(2)) {
                Some((key.as_str().to_string(), val.as_str().to_string()))
            } else {
                None
            }
        })
        .collect();

    if pairs.is_empty() {
        return false;
    }

    // Ensure the node carries WireGuard options before applying peer fields
    if node.as_wireguard().is_none() {
        node.combined_proxy = Some(
            crate::models::proxy_node::combined::CombinedProxy::WireGuard(Default::default()),
        );
    }

    // Process key-value pairs
    for (key, val) in pairs {
        match key.as_str() {
            "public-key" => {
                if let Some(wg) = node.as_wireguard_mut() {
                    wg.public_key = Some(val);
                }
            }
            "endpoint" => {
                if let Some(idx) = val.rfind(':') {
                    node.hostname = val[..idx].to_string();
                    if let Ok(port) = val[idx + 1..].parse::<u16>() {
                        node.port = port;
                    }
                }
            }
            "client-id" => {
                if let Some(wg) = node.as_wireguard_mut() {
                    wg.client_id = Some(val);
                }
            }
            "allowed-ips" => {
                if let Some(wg) = node.as_wireguard_mut() {
                    wg.allowed_ips = val.trim_matches('"').to_string();
                }
            }
            _ => {}
        }
    }

    true
}
