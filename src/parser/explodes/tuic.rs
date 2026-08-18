use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::proxy_node::tuic::TuicProxy;
use crate::models::{Proxy, ProxyType, TUIC_DEFAULT_GROUP};
use crate::utils::url_decode;
use std::collections::HashMap;
use url::Url;

/// Parse a TUIC v5 link into a Proxy object.
///
/// Follows the URI scheme used by tuic-client / v2rayN / NekoBox:
/// `tuic://uuid:password@host:port?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=...&allow_insecure=1&disable_sni=1#name`
pub fn explode_tuic(link: &str, node: &mut Proxy) -> bool {
    if !link.starts_with("tuic://") {
        return false;
    }

    let url = match Url::parse(link) {
        Ok(url) => url,
        Err(_) => return false,
    };

    // v5 carries `uuid:password` in the userinfo part (percent-encoded)
    let uuid = url_decode(url.username());
    if uuid.is_empty() {
        return false;
    }
    let password = url_decode(url.password().unwrap_or(""));

    let host = match url.host_str() {
        Some(host) => host.to_string(),
        None => return false,
    };
    let port = url.port().unwrap_or(443);
    if port == 0 {
        return false;
    }

    let mut params = HashMap::new();
    for (key, value) in url.query_pairs() {
        params.insert(key.to_string().to_lowercase(), value.to_string());
    }

    let truthy = |v: &String| v == "1" || v.eq_ignore_ascii_case("true");

    let sni = params.get("sni").or_else(|| params.get("peer")).cloned();
    let insecure = params
        .get("allow_insecure")
        .or_else(|| params.get("allowinsecure"))
        .or_else(|| params.get("insecure"))
        .map(truthy);
    let disable_sni = params.get("disable_sni").map(truthy);
    let reduce_rtt = params.get("reduce_rtt").map(truthy);
    let congestion_controller = params
        .get("congestion_control")
        .or_else(|| params.get("congestion_controller"))
        .cloned();
    let udp_relay_mode = params.get("udp_relay_mode").cloned();
    let alpn: Vec<String> = params
        .get("alpn")
        .map(|value| {
            value
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().to_string())
                .collect()
        })
        .unwrap_or_default();

    let remark = match url.fragment() {
        Some(fragment) if !fragment.is_empty() => url_decode(fragment),
        _ => format!("{} ({})", host, port),
    };

    *node = Proxy::default();
    node.proxy_type = ProxyType::Tuic;
    node.group = TUIC_DEFAULT_GROUP.to_string();
    node.remark = remark;
    node.hostname = host;
    node.port = port;
    // TUIC is QUIC-based: UDP relay is part of the protocol
    node.udp = Some(true);
    node.tls_secure = true;
    node.sni = sni;
    node.allow_insecure = insecure;
    for proto in alpn {
        node.alpn.insert(proto);
    }
    node.combined_proxy = Some(CombinedProxy::Tuic(TuicProxy {
        uuid,
        password,
        congestion_controller,
        udp_relay_mode,
        reduce_rtt,
        disable_sni,
        ..Default::default()
    }));

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explode_tuic_full() {
        let link = "tuic://b445361a-abcf-4a4a-a97a-0bf4136d6ddc:pass%3Aword@example.com:8443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=sni.example.com&allow_insecure=1&disable_sni=0#My%20TUIC";
        let mut node = Proxy::default();
        assert!(explode_tuic(link, &mut node));

        assert_eq!(node.proxy_type, ProxyType::Tuic);
        assert_eq!(node.remark, "My TUIC");
        assert_eq!(node.hostname, "example.com");
        assert_eq!(node.port, 8443);
        assert_eq!(node.sni.as_deref(), Some("sni.example.com"));
        assert_eq!(node.allow_insecure, Some(true));
        assert!(node.alpn.contains("h3"));

        let tuic = node.as_tuic().expect("tuic options");
        assert_eq!(tuic.uuid, "b445361a-abcf-4a4a-a97a-0bf4136d6ddc");
        assert_eq!(tuic.password, "pass:word");
        assert_eq!(tuic.congestion_controller.as_deref(), Some("bbr"));
        assert_eq!(tuic.udp_relay_mode.as_deref(), Some("native"));
        assert_eq!(tuic.disable_sni, Some(false));
    }

    #[test]
    fn test_explode_tuic_minimal() {
        let mut node = Proxy::default();
        assert!(explode_tuic("tuic://uuid-value:pw@1.2.3.4:443#n", &mut node));
        assert_eq!(node.port, 443);
        assert_eq!(node.as_tuic().unwrap().password, "pw");
    }

    #[test]
    fn test_explode_tuic_rejects_missing_uuid() {
        let mut node = Proxy::default();
        assert!(!explode_tuic("tuic://example.com:443", &mut node));
    }
}
