use crate::models::{ExtraSettings, Proxy, ProxyType, SSR_CIPHERS, SS_CIPHERS};
use crate::utils::base64::{base64_encode, url_safe_base64_encode};
use crate::utils::url::url_encode;
use log::error;
// Bitflags for proxy types used in conversions
use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ProxyUriTypes: u32 {
        const SS = 0b0001;
        const SSR = 0b0010;
        const VMESS = 0b0100;
        const TROJAN = 0b1000;
        const MIXED = Self::SS.bits() | Self::SSR.bits() | Self::VMESS.bits() | Self::TROJAN.bits();
    }
}

/// Generate a VMess link
///
/// # Arguments
/// * `remark` - Remark for the node
/// * `hostname` - Server hostname
/// * `port` - Server port
/// * `fake_type` - Fake type
/// * `user_id` - User ID
/// * `alter_id` - Alter ID
/// * `transfer_protocol` - Transfer protocol
/// * `path` - Path
/// * `host` - Host
/// * `tls` - TLS setting
///
/// # Returns
/// * VMess link as JSON string
fn vmess_link_construct(
    remark: &str,
    hostname: &str,
    port: u16,
    fake_type: Option<&str>,
    user_id: &str,
    alter_id: u16,
    transfer_protocol: &str,
    path: &str,
    host: &str,
    tls: &str,
) -> String {
    let mut json = serde_json::json!({
        "v": "2",
        "ps": remark,
        "add": hostname,
        "port": port.to_string(),
        "id": user_id,
        "aid": alter_id.to_string(),
        "net": transfer_protocol,
        "path": path,
        "host": host,
        "tls": tls
    });

    if let Some(ft) = fake_type {
        json["type"] = serde_json::Value::String(ft.to_string());
    }

    match serde_json::to_string(&json) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to serialize VMess JSON: {}", e);
            String::new()
        }
    }
}

/// Convert proxies to single links
///
/// This function converts a list of proxies to single URL format links.
///
/// # Arguments
/// * `nodes` - List of proxy nodes to convert
/// * `types` - Bitflags indicating which proxy types to include (SS, SSR, VMess, Trojan)
/// * `ext` - Extra settings for conversion
///
/// # Returns
/// * String containing the converted proxies
pub fn proxy_to_single(
    nodes: &mut Vec<Proxy>,
    types: ProxyUriTypes,
    ext: &mut ExtraSettings,
) -> String {
    let mut all_links = String::new();

    for node in nodes {
        let remark = &node.remark;
        let hostname = &node.hostname;
        let port = node.port.to_string();

        // Extract optional fields with safe defaults
        let password = node.password().unwrap_or("");
        let method = node.encrypt_method().unwrap_or("");
        let plugin = node.plugin().unwrap_or("");
        let plugin_opts = node.plugin_option().unwrap_or("");
        let protocol = node.protocol().unwrap_or("");
        let protocol_param = node.protocol_param().unwrap_or("");
        let obfs = node.obfs().unwrap_or("");
        let obfs_param = node.obfs_param().unwrap_or("");
        let user_id = node.user_id().unwrap_or("");
        let transfer_protocol = node.transfer_protocol().unwrap_or("");
        let host = node.host().unwrap_or("");
        let path = node.path().unwrap_or("");
        let fake_type = node.fake_type();
        let tls_secure = node.tls_secure;
        let alter_id = node.alter_id();
        let group = node.group.as_ref();

        let mut _proxy_str = String::new();

        match node.proxy_type {
            ProxyType::Shadowsocks => {
                if types.contains(ProxyUriTypes::SS) {
                    // SS format
                    _proxy_str = format!(
                        "ss://{}@{}:{}",
                        url_safe_base64_encode(&format!("{}:{}", method, password)),
                        hostname,
                        port
                    );

                    if !plugin.is_empty() && !plugin_opts.is_empty() {
                        _proxy_str.push_str(&format!(
                            "/?plugin={}",
                            url_encode(&format!("{};{}", plugin, plugin_opts))
                        ));
                    }

                    _proxy_str.push_str(&format!("#{}", url_encode(remark)));
                } else if types.contains(ProxyUriTypes::SSR) {
                    // Convert SS to SSR if compatible
                    if SSR_CIPHERS.contains(&method) && plugin.is_empty() {
                        _proxy_str = format!(
                            "ssr://{}",
                            url_safe_base64_encode(&format!(
                                "{}:{}:origin:{}:plain:{}/?group={}&remarks={}",
                                hostname,
                                port,
                                method,
                                url_safe_base64_encode(password),
                                url_safe_base64_encode(group),
                                url_safe_base64_encode(remark)
                            ))
                        );
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            }
            ProxyType::ShadowsocksR => {
                if types.contains(ProxyUriTypes::SSR) {
                    // SSR format
                    _proxy_str = format!(
                        "ssr://{}",
                        url_safe_base64_encode(&format!(
                            "{}:{}:{}:{}:{}:{}/?group={}&remarks={}&obfsparam={}&protoparam={}",
                            hostname,
                            port,
                            protocol,
                            method,
                            obfs,
                            url_safe_base64_encode(password),
                            url_safe_base64_encode(group),
                            url_safe_base64_encode(remark),
                            url_safe_base64_encode(obfs_param),
                            url_safe_base64_encode(protocol_param)
                        ))
                    );
                } else if types.contains(ProxyUriTypes::SS) {
                    // Convert SSR to SS if compatible
                    if SS_CIPHERS.contains(&method) && protocol == "origin" && obfs == "plain" {
                        _proxy_str = format!(
                            "ss://{}@{}:{}#{}",
                            url_safe_base64_encode(&format!("{}:{}", method, password)),
                            hostname,
                            port,
                            url_encode(remark)
                        );
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            }
            ProxyType::VMess => {
                if !types.contains(ProxyUriTypes::VMESS) {
                    continue;
                }

                // VMess format
                let vmess_json = vmess_link_construct(
                    remark,
                    hostname,
                    node.port,
                    fake_type,
                    user_id,
                    alter_id,
                    transfer_protocol,
                    path,
                    host,
                    if tls_secure { "tls" } else { "" },
                );

                _proxy_str = format!("vmess://{}", base64_encode(&vmess_json));
            }
            ProxyType::Trojan => {
                if !types.contains(ProxyUriTypes::TROJAN) {
                    continue;
                }

                // Trojan format
                _proxy_str = format!(
                    "trojan://{}@{}:{}?allowInsecure={}",
                    password,
                    hostname,
                    port,
                    if node.allow_insecure.unwrap_or(false) {
                        "1"
                    } else {
                        "0"
                    }
                );

                if !host.is_empty() {
                    _proxy_str.push_str(&format!("&sni={}", host));
                }

                if transfer_protocol == "ws" {
                    _proxy_str.push_str("&ws=1");
                    if !path.is_empty() {
                        _proxy_str.push_str(&format!("&wspath={}", url_encode(path)));
                    }
                }

                _proxy_str.push_str(&format!("#{}", url_encode(remark)));
            }
            _ => continue,
        }

        all_links.push_str(&_proxy_str);
        all_links.push('\n');
    }

    // Return raw links or base64 encoded based on settings
    if ext.nodelist {
        all_links
    } else {
        base64_encode(&all_links)
    }
}
