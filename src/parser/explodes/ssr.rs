use crate::models::{Proxy, SSR_DEFAULT_GROUP, SS_CIPHERS};
use crate::utils::base64::url_safe_base64_decode;
use serde_json::Value;
use url::Url;

/// Parse a ShadowsocksR link into a Proxy object
/// Based on the C++ implementation in explodeSSR function
pub fn explode_ssr(ssr: &str, node: &mut Proxy) -> bool {
    // Check if the link starts with ssr://
    if !ssr.starts_with("ssr://") {
        return false;
    }

    // Extract the base64 part and decode it
    let encoded = &ssr[6..];

    // Decode base64
    let mut decoded = url_safe_base64_decode(encoded);
    if decoded.is_empty() {
        return false;
    }

    // Replace \r with empty string
    decoded = decoded.replace('\r', "");

    // Extract query parameters if present
    let mut _strobfs = String::new();
    let mut group = String::new();
    let mut remarks = String::new();
    let mut obfsparam = String::new();
    let mut protoparam = String::new();

    if let Some(query_pos) = decoded.find("/?") {
        _strobfs = decoded[query_pos + 2..].to_string();
        decoded = decoded[..query_pos].to_string();

        // Parse query parameters
        let url_str = format!("http://localhost/?{}", _strobfs);
        if let Ok(url) = Url::parse(&url_str) {
            for (key, value) in url.query_pairs() {
                let decoded_value = url_safe_base64_decode(&value);

                match key.as_ref() {
                    "group" => group = decoded_value,
                    "remarks" => remarks = decoded_value,
                    "obfsparam" => obfsparam = decoded_value.replace(" ", ""),
                    "protoparam" => protoparam = decoded_value.replace(" ", ""),
                    _ => {}
                }
            }
        }
    }

    // Parse the main part of the URL (server:port:protocol:method:obfs:password)
    let parts: Vec<&str> = decoded.split(':').collect();
    if parts.len() < 6 {
        return false;
    }

    let server = parts[0];
    let port_str = parts[1];
    let protocol = parts[2];
    let method = parts[3];
    let obfs = parts[4];
    let password_encoded = parts[5];

    // Decode password (base64 encoded)
    let password = url_safe_base64_decode(password_encoded);

    // Parse port
    let port = match port_str.parse::<u16>() {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Skip if port is 0
    if port == 0 {
        return false;
    }

    // Set default group and remarks if not provided
    if group.is_empty() {
        group = SSR_DEFAULT_GROUP.to_string();
    }
    if remarks.is_empty() {
        remarks = format!("{} ({})", server, port);
    }

    // Check if this should be an SS or SSR proxy
    if SS_CIPHERS.iter().any(|c| *c == method)
        && (obfs.is_empty() || obfs == "plain")
        && (protocol.is_empty() || protocol == "origin")
    {
        // Create SS proxy
        *node = Proxy::ss_construct(
            &group, &remarks, server, port, &password, method, "", "", None, None, None, None, "",
        );
    } else {
        // Create SSR proxy
        *node = Proxy::ssr_construct(
            &group,
            &remarks,
            server,
            port,
            protocol,
            method,
            obfs,
            &password,
            &obfsparam,
            &protoparam,
            None,
            None,
            None,
            "",
        );
    }

    true
}

/// Parse a ShadowsocksR configuration file into a vector of Proxy objects
pub fn explode_ssr_conf(content: &str, nodes: &mut Vec<Proxy>) -> bool {
    // Try to parse as JSON
    let json: Value = match serde_json::from_str(content) {
        Ok(json) => json,
        Err(_) => return false,
    };

    // Check if it's a ShadowsocksR configuration
    if !json["configs"].is_array() {
        return false;
    }

    // Extract configs
    let configs = json["configs"].as_array().unwrap();

    for config in configs {
        let server = config["server"].as_str().unwrap_or("");
        let port = config["server_port"].as_u64().unwrap_or(0) as u16;
        let protocol = config["protocol"].as_str().unwrap_or("");
        let method = config["method"].as_str().unwrap_or("");
        let obfs = config["obfs"].as_str().unwrap_or("");
        let password = config["password"].as_str().unwrap_or("");
        let obfs_param = config["obfsparam"].as_str().unwrap_or("");
        let proto_param = config["protocolparam"].as_str().unwrap_or("");
        let remarks = config["remarks"].as_str().unwrap_or("");
        let group = config["group"].as_str().unwrap_or("");

        // Create formatted remark and group
        let group_str = if group.is_empty() {
            SSR_DEFAULT_GROUP.to_string()
        } else {
            group.to_string()
        };
        let remark_str = if remarks.is_empty() {
            format!("{} ({})", server, port)
        } else {
            remarks.to_string()
        };

        // Create the proxy object
        let node = Proxy::ssr_construct(
            &group_str,
            &remark_str,
            server,
            port,
            protocol,
            method,
            obfs,
            password,
            obfs_param,
            proto_param,
            None,
            None,
            None,
            "",
        );

        nodes.push(node);
    }

    !nodes.is_empty()
}

#[cfg(test)]
mod tests {
    use crate::ProxyType;

    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn test_explode_ssr_valid_link() {
        let mut node = Proxy::default();

        // This is a valid SSR link with known parameters
        let ssr_link = "ssr://ZXhhbXBsZS5jb206ODM4ODphdXRoX2FlczEyOF9tZDU6YWVzLTI1Ni1jZmI6dGxzMS4yX3RpY2tldF9hdXRoOmRHVnpkQT09Lz9vYmZzcGFyYW09ZEdWemRBPT0mcHJvdG9wYXJhbT1kR1Z6ZEE9PSZyZW1hcmtzPVZHVnpkQ0JUVTFJPSZncm91cD1WR1Z6ZENCVFUxST0=";

        // Parse the link
        let result = explode_ssr(ssr_link, &mut node);

        // Verify the result
        assert!(result);
        assert_eq!(node.proxy_type, ProxyType::ShadowsocksR);
        assert_eq!(node.hostname, "example.com");
        assert_eq!(node.port, 8388);
        assert_eq!(node.protocol().unwrap_or(""), "auth_aes128_md5");
        assert_eq!(node.encrypt_method().unwrap_or(""), "aes-256-cfb");
        assert_eq!(node.obfs().unwrap_or(""), "tls1.2_ticket_auth");
        assert_eq!(node.password().unwrap_or(""), "test");
        assert_eq!(node.obfs_param().unwrap_or(""), "test");
        assert_eq!(node.protocol_param().unwrap_or(""), "test");
        assert_eq!(node.remark, "Test SSR");
        assert_eq!(node.group, "Test SSR");
    }

    #[test]
    fn test_explode_ssr_invalid_prefix() {
        let mut node = Proxy::default();
        let result = explode_ssr("ss://invalid", &mut node);
        assert!(!result);
    }

    #[test]
    fn test_explode_ssr_invalid_base64() {
        let mut node = Proxy::default();
        let result = explode_ssr("ssr://invalid!base64", &mut node);
        assert!(!result);
    }

    #[test]
    fn test_explode_ssr_missing_parts() {
        let mut node = Proxy::default();
        // Only server:port:protocol
        let link = format!(
            "ssr://{}",
            STANDARD.encode("example.com:8388:auth_aes128_md5")
        );
        let result = explode_ssr(&link, &mut node);
        assert!(!result);
    }

    #[test]
    fn test_explode_ssr_default_group() {
        let mut node = Proxy::default();
        let server = "example.com";
        let port = 8388;
        let protocol = "auth_aes128_md5";
        let method = "aes-256-cfb";
        let obfs = "tls1.2_ticket_auth";
        let password = "password123";

        // Encode the password
        let password_b64 = STANDARD.encode(password);

        // Construct the SSR link without group
        let ssr_link = format!(
            "{}:{}:{}:{}:{}:{}",
            server, port, protocol, method, obfs, password_b64
        );

        // Base64 encode the entire link
        let ssr_link_b64 = format!("ssr://{}", STANDARD.encode(&ssr_link));

        // Parse the link
        let result = explode_ssr(&ssr_link_b64, &mut node);

        // Verify the result
        assert!(result);
        assert_eq!(node.group, SSR_DEFAULT_GROUP);
        assert_eq!(node.remark, format!("{} ({})", server, port));
    }

    #[test]
    fn test_explode_ssr_conf_valid() {
        let mut nodes = Vec::new();
        let content = r#"{
            "configs": [
                {
                    "server": "example1.com",
                    "server_port": 8388,
                    "protocol": "auth_aes128_md5",
                    "method": "aes-256-cfb",
                    "obfs": "tls1.2_ticket_auth",
                    "password": "password1",
                    "obfsparam": "obfs.param1",
                    "protocolparam": "proto.param1",
                    "remarks": "Server 1",
                    "group": "Group 1"
                },
                {
                    "server": "example2.com",
                    "server_port": 8389,
                    "protocol": "auth_chain_a",
                    "method": "chacha20",
                    "obfs": "http_simple",
                    "password": "password2",
                    "obfsparam": "obfs.param2",
                    "protocolparam": "proto.param2",
                    "remarks": "Server 2",
                    "group": "Group 2"
                }
            ]
        }"#;

        let result = explode_ssr_conf(content, &mut nodes);

        assert!(result);
        assert_eq!(nodes.len(), 2);

        // Check first node
        assert_eq!(nodes[0].proxy_type, ProxyType::ShadowsocksR);
        assert_eq!(nodes[0].hostname, "example1.com");
        assert_eq!(nodes[0].port, 8388);
        assert_eq!(
            nodes[0].protocol().unwrap_or(""),
            "auth_aes128_md5"
        );
        assert_eq!(
            nodes[0].encrypt_method().unwrap_or(""),
            "aes-256-cfb"
        );
        assert_eq!(nodes[0].obfs().unwrap_or(""), "tls1.2_ticket_auth");
        assert_eq!(nodes[0].password().unwrap_or(""), "password1");
        assert_eq!(nodes[0].obfs_param().unwrap_or(""), "obfs.param1");
        assert_eq!(
            nodes[0].protocol_param().unwrap_or(""),
            "proto.param1"
        );
        assert_eq!(nodes[0].remark, "Server 1");
        assert_eq!(nodes[0].group, "Group 1");

        // Check second node
        assert_eq!(nodes[1].proxy_type, ProxyType::ShadowsocksR);
        assert_eq!(nodes[1].hostname, "example2.com");
        assert_eq!(nodes[1].port, 8389);
        assert_eq!(nodes[1].protocol().unwrap_or(""), "auth_chain_a");
        assert_eq!(nodes[1].encrypt_method().unwrap_or(""), "chacha20");
        assert_eq!(nodes[1].obfs().unwrap_or(""), "http_simple");
        assert_eq!(nodes[1].password().unwrap_or(""), "password2");
        assert_eq!(nodes[1].obfs_param().unwrap_or(""), "obfs.param2");
        assert_eq!(
            nodes[1].protocol_param().unwrap_or(""),
            "proto.param2"
        );
        assert_eq!(nodes[1].remark, "Server 2");
        assert_eq!(nodes[1].group, "Group 2");
    }

    #[test]
    fn test_explode_ssr_conf_invalid_json() {
        let mut nodes = Vec::new();
        let content = "invalid json";
        let result = explode_ssr_conf(content, &mut nodes);
        assert!(!result);
        assert_eq!(nodes.len(), 0);
    }

    #[test]
    fn test_explode_ssr_conf_missing_configs() {
        let mut nodes = Vec::new();
        let content = r#"{ "not_configs": [] }"#;
        let result = explode_ssr_conf(content, &mut nodes);
        assert!(!result);
        assert_eq!(nodes.len(), 0);
    }

    #[test]
    fn test_explode_ssr_conf_empty_configs() {
        let mut nodes = Vec::new();
        let content = r#"{ "configs": [] }"#;
        let result = explode_ssr_conf(content, &mut nodes);
        assert!(!result);
        assert_eq!(nodes.len(), 0);
    }

    #[test]
    fn test_explode_ssr_conf_default_values() {
        let mut nodes = Vec::new();
        let content = r#"{
            "configs": [
                {
                    "server": "example.com",
                    "server_port": 8388
                }
            ]
        }"#;

        let result = explode_ssr_conf(content, &mut nodes);

        assert!(result);
        assert_eq!(nodes.len(), 1);

        assert_eq!(nodes[0].proxy_type, ProxyType::ShadowsocksR);
        assert_eq!(nodes[0].hostname, "example.com");
        assert_eq!(nodes[0].port, 8388);
        assert_eq!(nodes[0].protocol().unwrap_or(""), "");
        assert_eq!(nodes[0].encrypt_method().unwrap_or(""), "");
        assert_eq!(nodes[0].obfs().unwrap_or(""), "");
        assert_eq!(nodes[0].password().unwrap_or(""), "");
        assert_eq!(nodes[0].obfs_param().unwrap_or(""), "");
        assert_eq!(nodes[0].protocol_param().unwrap_or(""), "");
        assert_eq!(nodes[0].remark, "example.com (8388)");
        assert_eq!(nodes[0].group, SSR_DEFAULT_GROUP);
    }
}
