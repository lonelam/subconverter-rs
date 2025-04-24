use crate::utils::base64::url_safe_base64_decode;
use crate::Proxy;

/// Explode a proxy link into a Proxy object
///
/// This function detects the type of proxy link and calls the appropriate parser
pub fn explode(link: &str, node: &mut Proxy) -> bool {
    // Check for empty link
    if link.is_empty() {
        return false;
    }

    // Detect link type and call appropriate parser
    if link.starts_with("vmess://") {
        // Try standard VMess parser first
        if super::vmess::explode_vmess(link, node) {
            return true;
        }

        // Try alternative VMess formats if standard parser fails
        if super::vmess::explode_std_vmess(link, node) {
            return true;
        }

        if super::vmess::explode_shadowrocket(link, node) {
            return true;
        }

        if super::vmess::explode_kitsunebi(link, node) {
            return true;
        }

        return false;
    } else if link.starts_with("ss://") {
        super::ss::explode_ss(link, node)
    } else if link.starts_with("ssr://") {
        // super::ssr::explode_ssr(link, node)
        false
    } else if link.starts_with("socks://")
        || link.starts_with("https://t.me/socks")
        || link.starts_with("tg://socks")
    {
        super::socks::explode_socks(link, node)
    } else if link.starts_with("http://") || link.starts_with("https://") {
        // Try HTTP parser first
        if super::http::explode_http(link, node) {
            return true;
        }

        // If that fails, try HTTP subscription format
        super::httpsub::explode_http_sub(link, node)
    } else if link.starts_with("trojan://") {
        super::trojan::explode_trojan(link, node)
    } else if link.starts_with("snell://") {
        super::snell::explode_snell(link, node)
    } else if link.starts_with("wg://") || link.starts_with("wireguard://") {
        super::wireguard::explode_wireguard(link, node)
    } else if link.starts_with("hysteria://") {
        super::hysteria::explode_hysteria(link, node)
    } else if link.starts_with("hysteria2://") || link.starts_with("hy2://") {
        super::hysteria2::explode_hysteria2(link, node)
    } else if link.starts_with("vmess+") {
        false
        // super::vmess::explode_std_vmess(link, node)
    } else if link.starts_with("vless://") {
        super::vless::explode_vless(link, node)
    } else {
        false
    }
}

/// Explode a subscription content into a vector of Proxy objects
///
/// This function parses a subscription content (which may contain multiple proxy links)
/// and returns a vector of Proxy objects
pub fn explode_sub(sub: &str, nodes: &mut Vec<Proxy>) -> bool {
    // Trim the subscription content
    let sub = sub.trim();

    // Check for empty subscription
    if sub.is_empty() {
        return false;
    }

    let mut processed = false;

    // Try to parse as SSD configuration
    if sub.starts_with("ssd://") {
        if super::ss::explode_ssd(sub, nodes) {
            processed = true;
        }
    }

    // Try to parse as Clash configuration
    if !processed
        && (sub.contains("\"Proxy\":")
            || sub.contains("\"proxies\":")
            || sub.contains("Proxy:")
            || sub.contains("proxies:"))
    {
        if super::explode_clash::explode_clash(sub, nodes) {
            processed = true;
        }
    }

    // Try to parse as Surge configuration
    if !processed && super::surge::explode_surge(sub, nodes) {
        processed = true;
    }

    // If no specific format was detected, try as a normal subscription
    if !processed {
        // Try to decode as base64
        let decoded = url_safe_base64_decode(sub);

        // Check if it's a Surge format after decoding
        if decoded.contains("vmess=")
            || decoded.contains("shadowsocks=")
            || decoded.contains("http=")
            || decoded.contains("trojan=")
        {
            if super::surge::explode_surge(&decoded, nodes) {
                return true;
            }
        }

        // Split by newlines or spaces depending on content
        let delimiter = if decoded.contains('\n') {
            '\n'
        } else if decoded.contains('\r') {
            '\r'
        } else {
            ' '
        };

        let lines: Vec<&str> = decoded.split(delimiter).collect();

        for line in lines {
            let line = line.trim().trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }

            let mut node = Proxy::default();
            if explode(line, &mut node) {
                nodes.push(node);
            }
        }
    }

    !nodes.is_empty()
}

/// Explodes a configuration file content into a vector of Proxy objects
///
/// Attempts to detect and parse various configuration formats like
/// Clash, SSD, Surge, Quantumult, etc., and converts them to Proxy objects.
///
/// # Arguments
/// * `content` - The configuration content as a string
/// * `nodes` - Vector to store the parsed Proxy objects
///
/// # Returns
/// Number of nodes successfully parsed, or 0 if parsing failed
pub fn explode_conf_content(content: &str, nodes: &mut Vec<Proxy>) -> i32 {
    // Trim the content
    let content = content.trim();

    // Check for empty content
    if content.is_empty() {
        return 0;
    }

    let orig_size = nodes.len();
    let mut parsed = false;

    // Try to parse as JSON
    if content.starts_with('{') {
        // Try to parse as V2Ray configuration
        if super::vmess::explode_vmess_conf(content, nodes) {
            parsed = true;
        }
        // Try Netch configuration
        else if content.contains("\"server\"") && content.contains("\"port\"") {
            if super::netch::explode_netch_conf(content, nodes) {
                parsed = true;
            }
        }
    }
    // Try to parse as YAML/Clash
    else if content.contains("proxies:") || content.contains("Proxy:") {
        if super::explode_clash::explode_clash(content, nodes) {
            parsed = true;
        }
    }
    // Try to parse as SSD
    else if content.starts_with("ssd://") {
        if super::ss::explode_ssd(content, nodes) {
            parsed = true;
        }
    }
    // Try to parse as SSTap configuration
    else if content.contains("\"servers\":") || content.contains("\"configs\":") {
        if super::sstap::explode_sstap(content, nodes) {
            parsed = true;
        }
    }
    // Try to parse as Surge configuration
    else if content.contains("[Proxy]") {
        if super::surge::explode_surge(content, nodes) {
            parsed = true;
        }
    }
    // Try to parse as Quantumult configuration
    else if content.contains(" = vmess")
        || content.contains(" = shadowsocks")
        || content.contains(" = shadowsocksr")
        || content.contains(" = http")
        || content.contains(" = trojan")
    {
        if super::quan::explode_quan(content, nodes) {
            parsed = true;
        }
    }

    // If no specific format was detected, try as a simple subscription
    if !parsed && explode_sub(content, nodes) {
        parsed = true;
    }

    if parsed {
        (nodes.len() - orig_size) as i32
    } else {
        0
    }
}
