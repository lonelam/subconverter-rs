use crate::models::{Proxy, SS_DEFAULT_GROUP};
use crate::utils::url::url_decode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::Value;

/// Parse a Shadowsocks link into a Proxy object
/// Based on the C++ implementation in explodeSS function
pub fn explode_ss(ss: &str, node: &mut Proxy) -> bool {
    // Check if the link starts with ss://
    if !ss.starts_with("ss://") {
        return false;
    }

    // Extract the content part after ss://
    let mut ss_content = ss[5..].to_string();
    // Replace "/?" with "?" like in C++ replaceAllDistinct
    ss_content = ss_content.replace("/?", "?");

    // Extract fragment (remark) if present
    let mut ps = String::new();
    if let Some(hash_pos) = ss_content.find('#') {
        ps = url_decode(&ss_content[hash_pos + 1..]);
        ss_content = ss_content[..hash_pos].to_string();
    }

    // Extract plugin and other query parameters
    let mut plugin = String::new();
    let mut plugin_opts = String::new();
    let mut group = SS_DEFAULT_GROUP.to_string();

    if let Some(query_pos) = ss_content.find('?') {
        let addition = ss_content[query_pos + 1..].to_string();
        ss_content = ss_content[..query_pos].to_string();

        // Parse query parameters
        for (key, value) in url::form_urlencoded::parse(addition.as_bytes()) {
            if key == "plugin" {
                let plugins = url_decode(&value);
                if let Some(semicolon_pos) = plugins.find(';') {
                    plugin = plugins[..semicolon_pos].to_string();
                    plugin_opts = plugins[semicolon_pos + 1..].to_string();
                } else {
                    plugin = plugins;
                }
            } else if key == "group" {
                if !value.is_empty() {
                    group = crate::utils::base64::url_safe_base64_decode(&value);
                }
            }
        }
    }

    // Parse the main part of the URL
    let method;
    let password;
    let server;
    let port;

    if ss_content.contains('@') {
        // SIP002 format (method:password@server:port)
        let parts: Vec<&str> = ss_content.split('@').collect();
        if parts.len() < 2 {
            return false;
        }

        let secret = parts[0];
        let server_port = parts[1];

        // Parse server and port
        let server_port_parts: Vec<&str> = server_port.split(':').collect();
        if server_port_parts.len() < 2 {
            return false;
        }
        server = server_port_parts[0].to_string();
        port = match server_port_parts[1].parse::<u16>() {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Decode the secret part. SIP002 allows two forms:
        // - base64("method:password") for classic ciphers
        // - plaintext "method:password", percent-encoded, for AEAD-2022
        //   ciphers (the base64 decode fails and returns the input unchanged)
        let decoded_secret = crate::utils::base64::url_safe_base64_decode(secret);
        let (parsed_method, parsed_password) = if decoded_secret.contains(':') {
            let mut parts = decoded_secret.splitn(2, ':');
            let m = parts.next().unwrap_or_default().to_string();
            let p = parts.next().unwrap_or_default().to_string();
            if decoded_secret == secret {
                // Plaintext form: undo the percent-encoding
                (url_decode(&m), url_decode(&p))
            } else {
                (m, p)
            }
        } else {
            return false;
        };
        method = parsed_method;
        password = parsed_password;
    } else {
        // Legacy format
        let decoded = crate::utils::base64::url_safe_base64_decode(&ss_content);
        if decoded.is_empty() {
            return false;
        }

        // Parse method:password@server:port
        let parts: Vec<&str> = decoded.split('@').collect();
        if parts.len() < 2 {
            return false;
        }

        let method_pass = parts[0];
        let server_port = parts[1];

        // Parse method and password
        let method_pass_parts: Vec<&str> = method_pass.split(':').collect();
        if method_pass_parts.len() < 2 {
            return false;
        }
        method = method_pass_parts[0].to_string();
        password = method_pass_parts[1..].join(":"); // In case password contains colons

        // Parse server and port
        let server_port_parts: Vec<&str> = server_port.split(':').collect();
        if server_port_parts.len() < 2 {
            return false;
        }
        server = server_port_parts[0].to_string();
        port = match server_port_parts[1].parse::<u16>() {
            Ok(p) => p,
            Err(_) => return false,
        };
    }

    // Skip if port is 0
    if port == 0 {
        return false;
    }

    // Use server:port as remark if none provided
    if ps.is_empty() {
        ps = format!("{} ({})", server, port);
    }

    // Create the proxy
    *node = Proxy::ss_construct(
        &group,
        &ps,
        &server,
        port,
        &password,
        &method,
        &plugin,
        &plugin_opts,
        None,
        None,
        None,
        None,
        "",
    );

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduces https://github.com/lonelam/subconverter-rs/issues/38 —
    /// SIP002 links for AEAD-2022 ciphers carry a percent-encoded plaintext
    /// userinfo which must be URL-decoded, not left as-is.
    #[test]
    fn test_explode_ss_2022_plaintext_userinfo() {
        let link = "ss://2022-blake3-aes-128-gcm:NWI2YjgyYzU1MzZkYzYzMA%3D%3D%3AZWUyMzc4ODMtZDkxYi00NQ%3D%3D@a01.example.com:52011#HK01";
        let mut node = Proxy::default();
        assert!(explode_ss(link, &mut node));
        assert_eq!(node.encrypt_method.as_deref(), Some("2022-blake3-aes-128-gcm"));
        assert_eq!(
            node.password.as_deref(),
            Some("NWI2YjgyYzU1MzZkYzYzMA==:ZWUyMzc4ODMtZDkxYi00NQ==")
        );
        assert_eq!(node.hostname, "a01.example.com");
        assert_eq!(node.port, 52011);
    }

    /// Classic base64 userinfo must keep working.
    #[test]
    fn test_explode_ss_base64_userinfo() {
        // base64("aes-256-gcm:test1234") = YWVzLTI1Ni1nY206dGVzdDEyMzQ=
        let link = "ss://YWVzLTI1Ni1nY206dGVzdDEyMzQ=@example.com:8388#node";
        let mut node = Proxy::default();
        assert!(explode_ss(link, &mut node));
        assert_eq!(node.encrypt_method.as_deref(), Some("aes-256-gcm"));
        assert_eq!(node.password.as_deref(), Some("test1234"));
    }
}

/// Parse a SSD (Shadowsocks subscription) link into a vector of Proxy objects
pub fn explode_ssd(link: &str, nodes: &mut Vec<Proxy>) -> bool {
    // Check if the link starts with ssd://
    if !link.starts_with("ssd://") {
        return false;
    }

    // Extract the base64 part
    let encoded = &link[6..];

    // Decode base64
    let decoded = match STANDARD.decode(encoded) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return false,
        },
        Err(_) => return false,
    };

    // Parse as JSON
    let json: Value = match serde_json::from_str(&decoded) {
        Ok(json) => json,
        Err(_) => return false,
    };

    // Extract common fields
    let airport = json["airport"].as_str().unwrap_or("");
    let port = json["port"].as_u64().unwrap_or(0) as u16;
    let encryption = json["encryption"].as_str().unwrap_or("");
    let password = json["password"].as_str().unwrap_or("");

    // Extract servers
    if !json["servers"].is_array() {
        return false;
    }

    let servers = json["servers"].as_array().unwrap();

    for server in servers {
        let server_host = server["server"].as_str().unwrap_or("");
        let server_port = server["port"].as_u64().unwrap_or(port as u64) as u16;
        let server_encryption = server["encryption"].as_str().unwrap_or(encryption);
        let server_password = server["password"].as_str().unwrap_or(password);
        let server_remark = server["remarks"].as_str().unwrap_or("");
        let server_plugin = server["plugin"].as_str().unwrap_or("");
        let server_plugin_opts = server["plugin_options"].as_str().unwrap_or("");

        // Create formatted remark
        let formatted_remark = format!("{} - {}", airport, server_remark);

        // Create the proxy object
        let node = Proxy::ss_construct(
            SS_DEFAULT_GROUP,
            &formatted_remark,
            server_host,
            server_port,
            server_password,
            server_encryption,
            server_plugin,
            server_plugin_opts,
            None,
            None,
            None,
            None,
            "",
        );

        nodes.push(node);
    }

    !nodes.is_empty()
}

/// Parse Android Shadowsocks configuration into a vector of Proxy objects
pub fn explode_ss_android(content: &str, nodes: &mut Vec<Proxy>) -> bool {
    // Try to parse as JSON
    let json: Value = match serde_json::from_str(content) {
        Ok(json) => json,
        Err(_) => {
            println!(
                "Error parsing Android Shadowsocks configuration: {}",
                content
            );
            return false;
        }
    };

    // Check if it contains profiles
    if !json["configs"].is_array() && !json["proxies"].is_array() {
        return false;
    }

    // Determine which field to use
    let configs = if json["configs"].is_array() {
        json["configs"].as_array().unwrap()
    } else {
        json["proxies"].as_array().unwrap()
    };

    let mut index = nodes.len();

    for config in configs {
        // Extract fields
        let server = config["server"].as_str().unwrap_or("");
        if server.is_empty() {
            continue;
        }

        let port_num = config["server_port"].as_u64().unwrap_or(0) as u16;
        if port_num == 0 {
            continue;
        }

        let method = config["method"].as_str().unwrap_or("");
        let password = config["password"].as_str().unwrap_or("");

        // Get remark, try both "remarks" and "name" fields
        let remark = if config["remarks"].is_string() {
            config["remarks"].as_str().unwrap_or("").to_string()
        } else if config["name"].is_string() {
            config["name"].as_str().unwrap_or("").to_string()
        } else {
            format!("{} ({})", server, port_num)
        };

        // Get plugin and plugin_opts
        let plugin = config["plugin"].as_str().unwrap_or("");
        let plugin_opts = config["plugin_opts"].as_str().unwrap_or("");

        // Create the proxy object
        let mut node = Proxy::ss_construct(
            SS_DEFAULT_GROUP,
            &remark,
            server,
            port_num,
            password,
            method,
            plugin,
            plugin_opts,
            None,
            None,
            None,
            None,
            "",
        );

        node.id = index as u32;
        nodes.push(node);
        index += 1;
    }

    !nodes.is_empty()
}

/// Parse a Shadowsocks configuration file into a vector of Proxy objects
pub fn explode_ss_conf(content: &str, nodes: &mut Vec<Proxy>) -> bool {
    // Try to parse as JSON
    let json: Value = match serde_json::from_str(content) {
        Ok(json) => json,
        Err(_) => return false,
    };

    // Check for different configuration formats
    if json["configs"].is_array() || json["proxies"].is_array() {
        return explode_ss_android(content, nodes);
    }

    // Check for single server configuration
    if json["server"].is_string() && json["server_port"].is_u64() {
        let index = nodes.len();

        // Extract fields
        let server = json["server"].as_str().unwrap_or("");
        let port_num = json["server_port"].as_u64().unwrap_or(0) as u16;
        if server.is_empty() || port_num == 0 {
            return false;
        }

        let method = json["method"].as_str().unwrap_or("");
        let password = json["password"].as_str().unwrap_or("");

        // Get remark
        let remark = if json["remarks"].is_string() {
            json["remarks"].as_str().unwrap_or("")
        } else {
            &format!("{} ({})", server, port_num)
        };

        // Get plugin and plugin_opts
        let plugin = json["plugin"].as_str().unwrap_or("");
        let plugin_opts = json["plugin_opts"].as_str().unwrap_or("");

        // Create the proxy object
        let mut node = Proxy::ss_construct(
            SS_DEFAULT_GROUP,
            remark,
            server,
            port_num,
            password,
            method,
            plugin,
            plugin_opts,
            None,
            None,
            None,
            None,
            "",
        );

        node.id = index as u32;
        nodes.push(node);

        return true;
    }

    // Check for server list configuration
    if json["servers"].is_array() {
        let servers = json["servers"].as_array().unwrap();
        let mut index = nodes.len();

        for server_json in servers {
            // Extract fields
            let server = server_json["server"].as_str().unwrap_or("");
            let port_num = server_json["server_port"].as_u64().unwrap_or(0) as u16;
            if server.is_empty() || port_num == 0 {
                continue;
            }

            let method = server_json["method"].as_str().unwrap_or("");
            let password = server_json["password"].as_str().unwrap_or("");

            // Get remark
            let remark = if server_json["remarks"].is_string() {
                server_json["remarks"].as_str().unwrap_or("")
            } else {
                &format!("{} ({})", server, port_num)
            };

            // Get plugin and plugin_opts
            let plugin = server_json["plugin"].as_str().unwrap_or("");
            let plugin_opts = server_json["plugin_opts"].as_str().unwrap_or("");

            // Create the proxy object
            let mut node = Proxy::ss_construct(
                SS_DEFAULT_GROUP,
                remark,
                server,
                port_num,
                password,
                method,
                plugin,
                plugin_opts,
                None,
                None,
                None,
                None,
                "",
            );

            node.id = index as u32;
            nodes.push(node);
            index += 1;
        }

        return !nodes.is_empty();
    }

    false
}
