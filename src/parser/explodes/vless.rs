use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::proxy_node::vless::VlessProxy;
use crate::models::{Proxy, ProxyType};
use crate::utils::url_decode;
use std::collections::{HashMap, HashSet};
use url::Url;

/// Parse a VLESS link into a Proxy object
pub fn explode_vless(vless: &str, node: &mut Proxy) -> bool {
    // Check if the link starts with vless://
    if !vless.starts_with("vless://") {
        return false;
    }

    // Try to parse as URL
    let url = match Url::parse(vless) {
        Ok(url) => url,
        Err(_) => return false,
    };

    // Extract parameters from the query string
    let mut params = HashMap::new();
    for (key, value) in url.query_pairs() {
        params.insert(key.to_string(), url_decode(&value));
    }

    // Extract required fields
    let uuid = match url.username() {
        "" => return false,
        username => username.to_string(),
    };

    // Extract host and port
    let host = match url.host_str() {
        Some(host) => host,
        None => return false,
    };
    let port = url.port().unwrap_or(443);

    // Extract optional fields
    let tls = params
        .get("security")
        .map(|s| s.to_lowercase())
        .map(|s| s.ends_with("tls") || s == "reality")
        .unwrap_or(false);

    let fingerprint = params
        .get("fp")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "chrome".to_string());

    let alpn = params
        .get("alpn")
        .map(|s| {
            s.split(',')
                .map(|s| s.trim().to_string())
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default();

    let sni = params.get("sni").map(|s| s.to_string());

    let flow = params.get("flow").map(|s| s.to_string());

    let packet_encoding = params.get("packetEncoding").map(|s| s.to_string());
    let packet_addr = packet_encoding.as_deref() == Some("packet");

    let network = params
        .get("type")
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| "tcp".to_string());

    let fake_type = params
        .get("headerType")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    let mut vless_proxy = VlessProxy::default();
    vless_proxy.uuid = uuid;
    if let Some(packet_encoding) = packet_encoding {
        let xudp = packet_encoding != "none";
        vless_proxy.xudp = Some(xudp);
        vless_proxy.packet_encoding = Some(packet_encoding);
        vless_proxy.packet_addr = Some(packet_addr);
    }
    vless_proxy.network = Some(network.clone());
    vless_proxy.flow = flow;

    // Handle Reality options
    if let Some(public_key) = params.get("pbk") {
        vless_proxy.reality_public_key = Some(public_key.to_string());
        vless_proxy.reality_short_id = params.get("sid").map(|s| s.to_string());
    }

    // Handle network-specific options
    match network.as_str() {
        "tcp" => {
            if fake_type != "none" {
                let mut http_headers = HashMap::new();
                let mut http_path = vec!["/".to_string()];

                if let Some(host) = params.get("host") {
                    http_headers.insert("Host".to_string(), vec![host.to_string()]);
                }

                if let Some(path) = params.get("path") {
                    http_path = vec![path.to_string()];
                }

                vless_proxy.http_method = params.get("method").map(|s| s.to_string());
                vless_proxy.http_path = Some(http_path[0].clone());
                vless_proxy.http_headers = Some(http_headers);
            }
        }
        "http" | "h2" => {
            let mut h2_headers = HashMap::new();
            let mut h2_path = vec!["/".to_string()];

            if let Some(path) = params.get("path") {
                h2_path = vec![path.to_string()];
            }

            if let Some(host) = params.get("host") {
                h2_headers.insert("Host".to_string(), vec![host.to_string()]);
            }

            vless_proxy.h2_path = Some(h2_path[0].clone());
            vless_proxy.h2_host = Some(h2_headers.get("Host").unwrap_or(&vec![]).clone());
        }
        "ws" | "httpupgrade" => {
            let mut ws_headers = HashMap::new();
            ws_headers.insert("User-Agent".to_string(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string());

            if let Some(host) = params.get("host") {
                ws_headers.insert("Host".to_string(), host.to_string());
            }

            vless_proxy.ws_path = params.get("path").map(|s| s.to_string());
            vless_proxy.ws_headers = Some(ws_headers);

            if let Some(early_data) = params.get("ed") {
                if let Ok(_med) = early_data.parse::<i32>() {
                    if network == "ws" {
                        // Handle max early data
                    } else if network == "httpupgrade" {
                        // Handle v2ray-http-upgrade-fast-open
                    }
                }
            }

            if let Some(_early_data_header) = params.get("eh") {
                // Handle early data header name
            }
        }
        "grpc" => {
            vless_proxy.grpc_service_name = params.get("serviceName").map(|s| s.to_string());
        }
        _ => {}
    }

    node.proxy_type = ProxyType::Vless;
    node.combined_proxy = Some(CombinedProxy::Vless(vless_proxy));
    node.remark = url_decode(url.fragment().unwrap_or(""));
    node.hostname = host.to_string();
    node.port = port;
    // VLESS defaults to udp on
    node.udp = Some(true);
    node.tls_secure = tls;
    node.sni = sni;
    node.alpn = alpn;
    node.client_fingerprint = Some(fingerprint);

    true
}
