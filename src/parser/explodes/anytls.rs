use crate::models::proxy_node::anytls::AnyTlsProxy;
use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::{Proxy, ProxyType, ANYTLS_DEFAULT_GROUP};
use crate::utils::url_decode;
use std::collections::HashMap;
use url::Url;

/// Parse an AnyTLS link into a Proxy object.
///
/// Follows the URI scheme used by anytls-go / mihomo:
/// `anytls://password@host:port/?sni=...&insecure=1&fp=chrome&alpn=h2,http/1.1&udp=1#name`
pub fn explode_anytls(link: &str, node: &mut Proxy) -> bool {
    if !link.starts_with("anytls://") {
        return false;
    }

    let url = match Url::parse(link) {
        Ok(url) => url,
        Err(_) => return false,
    };

    // Password is carried in the userinfo part (possibly percent-encoded)
    let password = url_decode(url.username());
    if password.is_empty() {
        return false;
    }

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

    let sni = params.get("sni").or_else(|| params.get("peer")).cloned();
    let insecure = params
        .get("insecure")
        .or_else(|| params.get("allow_insecure"))
        .or_else(|| params.get("allowinsecure"))
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    let client_fingerprint = params.get("fp").cloned();
    let udp = params
        .get("udp")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    let alpn = params.get("alpn").map(|value| {
        value
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_string())
            .collect()
    });

    // Remark comes from the fragment, falling back to host:port
    let remark = match url.fragment() {
        Some(fragment) if !fragment.is_empty() => url_decode(fragment),
        _ => format!("{} ({})", host, port),
    };

    let mut anytls_proxy = AnyTlsProxy::default();
    anytls_proxy.password = password;

    *node = Proxy::default();
    node.proxy_type = ProxyType::AnyTls;
    node.group = ANYTLS_DEFAULT_GROUP.to_string();
    node.remark = remark;
    node.hostname = host;
    node.port = port;
    node.udp = udp;
    node.allow_insecure = insecure;
    node.tls_secure = true;
    node.sni = sni;
    node.client_fingerprint = client_fingerprint;
    if let Some(alpn_values) = alpn {
        node.alpn = alpn_values;
    }
    node.combined_proxy = Some(CombinedProxy::AnyTls(anytls_proxy));

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explode_anytls_full() {
        let link =
            "anytls://secret-pass@example.com:8443/?sni=example.org&insecure=1&fp=chrome&alpn=h2,http/1.1&udp=1#My%20Node";
        let mut node = Proxy::default();
        assert!(explode_anytls(link, &mut node));

        assert_eq!(node.proxy_type, ProxyType::AnyTls);
        assert_eq!(node.remark, "My Node");
        assert_eq!(node.hostname, "example.com");
        assert_eq!(node.port, 8443);
        assert_eq!(node.udp, Some(true));
        assert_eq!(node.allow_insecure, Some(true));

        let anytls = match node.combined_proxy {
            Some(CombinedProxy::AnyTls(ref p)) => p,
            _ => panic!("expected anytls combined proxy"),
        };
        assert_eq!(anytls.password, "secret-pass");
        assert_eq!(node.sni.as_deref(), Some("example.org"));
        assert_eq!(node.client_fingerprint.as_deref(), Some("chrome"));
        assert!(node.alpn.contains("h2"));
        assert!(node.alpn.contains("http/1.1"));
    }

    #[test]
    fn test_explode_anytls_minimal() {
        let link = "anytls://pw@1.2.3.4:443";
        let mut node = Proxy::default();
        assert!(explode_anytls(link, &mut node));
        assert_eq!(node.remark, "1.2.3.4 (443)");
        assert_eq!(node.port, 443);
    }

    #[test]
    fn test_explode_anytls_rejects_missing_password() {
        let mut node = Proxy::default();
        assert!(!explode_anytls("anytls://example.com:443", &mut node));
    }
}
