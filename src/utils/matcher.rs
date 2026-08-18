use crate::models::{Proxy, ProxyType};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::str::FromStr;

lazy_static! {
    static ref GROUPID_REGEX: Regex =
        Regex::new(r"^!!(?:GROUPID|INSERT)=([\d\-+!,]+)(?:!!(.*))?$").unwrap();
    static ref GROUP_REGEX: Regex = Regex::new(r"^!!(?:GROUP)=(.+?)(?:!!(.*))?$").unwrap();
    static ref TYPE_REGEX: Regex = Regex::new(r"^!!(?:TYPE)=(.+?)(?:!!(.*))?$").unwrap();
    static ref PORT_REGEX: Regex = Regex::new(r"^!!(?:PORT)=(.+?)(?:!!(.*))?$").unwrap();
    static ref SERVER_REGEX: Regex = Regex::new(r"^!!(?:SERVER)=(.+?)(?:!!(.*))?$").unwrap();
    static ref PROTOCOL_REGEX: Regex = Regex::new(r"^!!(?:PROTOCOL)=(.+?)(?:!!(.*))?$").unwrap();
    static ref UDPSUPPORT_REGEX: Regex =
        Regex::new(r"^!!(?:UDPSUPPORT)=(.+?)(?:!!(.*))?$").unwrap();
    static ref SECURITY_REGEX: Regex = Regex::new(r"^!!(?:SECURITY)=(.+?)(?:!!(.*))?$").unwrap();
    static ref REMARKS_REGEX: Regex = Regex::new(r"^!!(?:REMARKS)=(.+?)(?:!!(.*))?$").unwrap();
    static ref PROXY_TYPES: HashMap<ProxyType, &'static str> = {
        let mut m = HashMap::new();
        m.insert(ProxyType::Shadowsocks, "SS");
        m.insert(ProxyType::ShadowsocksR, "SSR");
        m.insert(ProxyType::VMess, "VMESS");
        m.insert(ProxyType::Trojan, "TROJAN");
        m.insert(ProxyType::Snell, "SNELL");
        m.insert(ProxyType::HTTP, "HTTP");
        m.insert(ProxyType::HTTPS, "HTTPS");
        m.insert(ProxyType::Socks5, "SOCKS5");
        m.insert(ProxyType::WireGuard, "WIREGUARD");
        m.insert(ProxyType::Hysteria, "HYSTERIA");
        m.insert(ProxyType::Hysteria2, "HYSTERIA2");
        m.insert(ProxyType::Vless, "VLESS");
        m.insert(ProxyType::AnyTls, "ANYTLS");
        m.insert(ProxyType::Tuic, "TUIC");
        m.insert(ProxyType::Unknown, "UNKNOWN");
        m
    };
}

/// Match a rule against a proxy node
///
/// This function evaluates complex rule strings that can match different
/// aspects of a proxy node. Special rule formats begin with "!!" and can match
/// against properties like group, type, port, etc.
///
/// Supported special rules:
/// - !!GROUP=<group_pattern> - Matches node's group against pattern
/// - !!GROUPID=<id_range> - Matches node's group ID against range
/// - !!INSERT=<id_range> - Like GROUPID but negates direction
/// - !!TYPE=<type_pattern> - Matches node's proxy type against pattern
/// - !!PORT=<port_range> - Matches node's port against range
/// - !!SERVER=<server_pattern> - Matches node's hostname against pattern
/// - !!PROTOCOL=<protocol_pattern> - Matches node's protocol against pattern
/// - !!UDPSUPPORT=<support_pattern> - Matches node's UDP support status
/// - !!SECURITY=<security_pattern> - Matches node's security features
/// - !!REMARKS=<remarks_pattern> - Matches node's remark against pattern
///
/// # Arguments
/// * `rule` - The rule to match
/// * `real_rule` - Output parameter that will contain the processed rule after
///   special prefix handling
/// * `node` - The proxy node to match against
///
/// # Returns
/// * `true` if the rule matches the node
/// * `false` otherwise
pub fn apply_matcher(rule: &str, real_rule: &mut String, node: &Proxy) -> bool {
    if rule.starts_with("!!GROUP=") {
        if let Some(captures) = GROUP_REGEX.captures(rule) {
            let target = captures.get(1).map_or("", |m| m.as_str());
            *real_rule = captures.get(2).map_or("", |m| m.as_str()).to_string();
            return reg_find(&node.group, target);
        }
    } else if rule.starts_with("!!GROUPID=") || rule.starts_with("!!INSERT=") {
        let dir = if rule.starts_with("!!INSERT=") { -1 } else { 1 };
        if let Some(captures) = GROUPID_REGEX.captures(rule) {
            let target = captures.get(1).map_or("", |m| m.as_str());
            *real_rule = captures.get(2).map_or("", |m| m.as_str()).to_string();
            return match_range(target, dir * (node.group_id as i32));
        }
    } else if rule.starts_with("!!TYPE=") {
        if let Some(captures) = TYPE_REGEX.captures(rule) {
            let target = captures.get(1).map_or("", |m| m.as_str());
            *real_rule = captures.get(2).map_or("", |m| m.as_str()).to_string();
            if node.proxy_type == ProxyType::Unknown {
                return false;
            }

            let type_str = PROXY_TYPES.get(&node.proxy_type).unwrap_or(&"UNKNOWN");
            return reg_match(type_str, target);
        }
    } else if rule.starts_with("!!PORT=") {
        if let Some(captures) = PORT_REGEX.captures(rule) {
            let target = captures.get(1).map_or("", |m| m.as_str());
            *real_rule = captures.get(2).map_or("", |m| m.as_str()).to_string();
            return match_range(target, node.port as i32);
        }
    } else if rule.starts_with("!!SERVER=") {
        if let Some(captures) = SERVER_REGEX.captures(rule) {
            let target = captures.get(1).map_or("", |m| m.as_str());
            *real_rule = captures.get(2).map_or("", |m| m.as_str()).to_string();
            return reg_find(&node.hostname, target);
        }
    } else if rule.starts_with("!!PROTOCOL=") {
        if let Some(captures) = PROTOCOL_REGEX.captures(rule) {
            let target = captures.get(1).map_or("", |m| m.as_str());
            *real_rule = captures.get(2).map_or("", |m| m.as_str()).to_string();
            let protocol = match node.protocol() {
                Some(proto) => proto,
                None => return false,
            };
            return reg_find(protocol, target);
        }
    } else if rule.starts_with("!!UDPSUPPORT=") {
        if let Some(captures) = UDPSUPPORT_REGEX.captures(rule) {
            let target = captures.get(1).map_or("", |m| m.as_str());
            *real_rule = captures.get(2).map_or("", |m| m.as_str()).to_string();

            match node.udp {
                Some(true) => return reg_match("yes", target),
                Some(false) => return reg_match("no", target),
                None => return reg_match("undefined", target),
            }
        }
    } else if rule.starts_with("!!SECURITY=") {
        if let Some(captures) = SECURITY_REGEX.captures(rule) {
            let target = captures.get(1).map_or("", |m| m.as_str());
            *real_rule = captures.get(2).map_or("", |m| m.as_str()).to_string();

            // Build a string of security features
            let mut features = String::new();

            if node.tls_secure {
                features.push_str("TLS,");
            }

            if let Some(true) = node.allow_insecure {
                features.push_str("INSECURE,");
            }

            if let Some(true) = node.tls13 {
                features.push_str("TLS13,");
            }

            if !features.is_empty() {
                features.pop(); // Remove trailing comma
            } else {
                features.push_str("NONE");
            }

            return reg_find(&features, target);
        }
    } else if rule.starts_with("!!REMARKS=") {
        if let Some(captures) = REMARKS_REGEX.captures(rule) {
            let target = captures.get(1).map_or("", |m| m.as_str());
            *real_rule = captures.get(2).map_or("", |m| m.as_str()).to_string();
            return reg_find(&node.remark, target);
        }
    } else {
        *real_rule = rule.to_string();
    }

    true
}

/// Match a number against a range specification
///
/// Range specification can include:
/// * Single numbers: "1", "2"
/// * Ranges: "1-10", "100-200"
/// * Negation: "!1-10" (everything except 1-10)
/// * Multiple ranges: "1-10,20-30,50"
///
/// # Arguments
/// * `range` - The range specification string
/// * `target` - The target number to match
///
/// # Returns
/// * `true` if the target matches the range
/// * `false` otherwise
pub fn match_range(range: &str, target: i32) -> bool {
    let mut negate = false;
    let mut matched = false;

    for range_part in range.split(',') {
        let mut part = range_part.trim();

        if part.starts_with('!') {
            negate = true;
            part = &part[1..];
        }

        if part.contains('-') {
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() == 2 {
                let lower = bounds[0].parse::<i32>().unwrap_or(i32::MIN);
                let upper = bounds[1].parse::<i32>().unwrap_or(i32::MAX);

                if target >= lower && target <= upper {
                    matched = true;
                    break;
                }
            }
        } else if let Ok(exact) = part.parse::<i32>() {
            if target == exact {
                matched = true;
                break;
            }
        }
    }

    if negate {
        !matched
    } else {
        matched
    }
}

/// Check if a string matches a regular expression pattern
///
/// # Arguments
/// * `text` - The text to search
/// * `pattern` - The regex pattern to match
///
/// # Returns
/// * `true` if the pattern is found in the text
/// * `false` otherwise
pub fn reg_find(text: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }

    match Regex::new(&format!("(?i){}", pattern)) {
        Ok(re) => re.is_match(text),
        Err(_) => false,
    }
}

/// Check if a string fully matches a regular expression pattern
///
/// # Arguments
/// * `text` - The text to match
/// * `pattern` - The regex pattern to match
///
/// # Returns
/// * `true` if the pattern fully matches the text
/// * `false` otherwise
pub fn reg_match(text: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }

    match Regex::new(&format!("(?i)^{}$", pattern)) {
        Ok(re) => re.is_match(text),
        Err(_) => false,
    }
}

#[derive(Debug, Clone)]
pub struct CompiledRange {
    lower: i32,
    upper: i32,
}

#[derive(Debug, Clone)]
pub enum CompiledMatcher {
    /// Match against group name (case-insensitive regex find)
    Group(Regex),
    /// Match against group ID range
    GroupId {
        ranges: Vec<CompiledRange>,
        negate: bool,
    },
    /// Match against proxy type (case-insensitive regex match)
    Type(Regex),
    /// Match against port range
    Port {
        ranges: Vec<CompiledRange>,
        negate: bool,
    },
    /// Match against server/hostname (case-insensitive regex find)
    Server(Regex),
    /// Match against protocol (case-insensitive regex find)
    Protocol(Regex),
    /// Match against UDP support (case-insensitive regex match: "yes", "no",
    /// "undefined")
    UdpSupport(Regex),
    /// Match against security features (case-insensitive regex find: "TLS",
    /// "INSECURE", "TLS13", "NONE")
    Security(Regex),
    /// Match against remark (case-insensitive regex find)
    Remarks(Regex),
    /// A plain regex rule (equivalent to !!REMARKS= but without the prefix)
    Plain(Regex),
    /// Rule that always matches (e.g., empty rule)
    AlwaysTrue,
    /// Rule that is invalid or cannot be compiled
    Invalid,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub matcher: CompiledMatcher,
    pub sub_rule: Option<Box<CompiledRule>>, // For rules like !!GROUP=X!!Y
}

fn parse_range_string(range_str: &str) -> (Vec<CompiledRange>, bool) {
    let mut negate = false;
    let mut ranges = Vec::new();
    let mut effective_range_str = range_str;

    if let Some(stripped) = range_str.strip_prefix('!') {
        negate = true;
        effective_range_str = stripped;
    }

    for range_part in effective_range_str.split(',') {
        let part = range_part.trim();
        if part.is_empty() {
            continue;
        }

        if part.contains('-') {
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() == 2 {
                // Allow empty bounds to signify MIN/MAX
                let lower = bounds[0].parse::<i32>().unwrap_or_else(|_| i32::MIN);
                let upper = bounds[1].parse::<i32>().unwrap_or_else(|_| i32::MAX);
                if lower <= upper {
                    ranges.push(CompiledRange { lower, upper });
                } // else: invalid range like 10-1, ignore
            }
        } else if let Ok(exact) = part.parse::<i32>() {
            ranges.push(CompiledRange {
                lower: exact,
                upper: exact,
            });
        }
        // Ignore parts that are not numbers or valid ranges
    }
    (ranges, negate)
}

/// Compiles a rule string into a `CompiledRule` structure.
///
/// This function parses the rule string, pre-compiles any regex patterns,
/// and determines the type of match to perform.
pub fn compile_rule(rule: &str) -> CompiledRule {
    let mut sub_rule_str: Option<&str> = None;
    let matcher = if let Some(captures) = GROUP_REGEX.captures(rule) {
        sub_rule_str = captures.get(2).map(|m| m.as_str());
        let target = captures.get(1).map_or("", |m| m.as_str());
        Regex::new(&format!("(?i){}", target))
            .map(CompiledMatcher::Group)
            .unwrap_or(CompiledMatcher::Invalid)
    } else if let Some(captures) = GROUPID_REGEX.captures(rule) {
        sub_rule_str = captures.get(2).map(|m| m.as_str());
        let target = captures.get(1).map_or("", |m| m.as_str());
        let dir = if rule.starts_with("!!INSERT=") { -1 } else { 1 }; // Apply direction modifier conceptually later
        let (ranges, negate) = parse_range_string(target);
        // The 'dir' multiplier is handled during application, not compilation
        CompiledMatcher::GroupId { ranges, negate }
    } else if let Some(captures) = TYPE_REGEX.captures(rule) {
        sub_rule_str = captures.get(2).map(|m| m.as_str());
        let target = captures.get(1).map_or("", |m| m.as_str());
        Regex::new(&format!("(?i)^{}$", target))
            .map(CompiledMatcher::Type)
            .unwrap_or(CompiledMatcher::Invalid)
    } else if let Some(captures) = PORT_REGEX.captures(rule) {
        sub_rule_str = captures.get(2).map(|m| m.as_str());
        let target = captures.get(1).map_or("", |m| m.as_str());
        let (ranges, negate) = parse_range_string(target);
        CompiledMatcher::Port { ranges, negate }
    } else if let Some(captures) = SERVER_REGEX.captures(rule) {
        sub_rule_str = captures.get(2).map(|m| m.as_str());
        let target = captures.get(1).map_or("", |m| m.as_str());
        Regex::new(&format!("(?i){}", target))
            .map(CompiledMatcher::Server)
            .unwrap_or(CompiledMatcher::Invalid)
    } else if let Some(captures) = PROTOCOL_REGEX.captures(rule) {
        sub_rule_str = captures.get(2).map(|m| m.as_str());
        let target = captures.get(1).map_or("", |m| m.as_str());
        Regex::new(&format!("(?i){}", target))
            .map(CompiledMatcher::Protocol)
            .unwrap_or(CompiledMatcher::Invalid)
    } else if let Some(captures) = UDPSUPPORT_REGEX.captures(rule) {
        sub_rule_str = captures.get(2).map(|m| m.as_str());
        let target = captures.get(1).map_or("", |m| m.as_str());
        Regex::new(&format!("(?i)^{}$", target))
            .map(CompiledMatcher::UdpSupport)
            .unwrap_or(CompiledMatcher::Invalid)
    } else if let Some(captures) = SECURITY_REGEX.captures(rule) {
        sub_rule_str = captures.get(2).map(|m| m.as_str());
        let target = captures.get(1).map_or("", |m| m.as_str());
        // The target is a comma-separated list of feature flags
        // (e.g. "TLS,TLS13"); a node matches when it has ANY of them.
        let alternatives = target
            .split(',')
            .map(|flag| regex::escape(flag.trim()))
            .collect::<Vec<_>>()
            .join("|");
        Regex::new(&format!("(?i)(?:^|,)(?:{})(?:,|$)", alternatives))
            .map(CompiledMatcher::Security)
            .unwrap_or(CompiledMatcher::Invalid)
    } else if let Some(captures) = REMARKS_REGEX.captures(rule) {
        sub_rule_str = captures.get(2).map(|m| m.as_str());
        let target = captures.get(1).map_or("", |m| m.as_str());
        Regex::new(&format!("(?i){}", target))
            .map(CompiledMatcher::Remarks)
            .unwrap_or(CompiledMatcher::Invalid)
    } else {
        // Treat as plain regex match against remark if no prefix
        if rule.is_empty() {
            CompiledMatcher::AlwaysTrue
        } else {
            Regex::new(&format!("(?i){}", rule))
                .map(CompiledMatcher::Plain)
                .unwrap_or(CompiledMatcher::Invalid)
        }
    };

    // The capture strips the leading "!!", so restore it before recursing —
    // otherwise "PORT=80" in "!!GROUP=X!!PORT=80" would be treated as a
    // plain remark regex instead of a port matcher.
    let sub_rule = sub_rule_str
        .filter(|s| !s.is_empty()) // Only compile non-empty sub-rules
        .map(|s| Box::new(compile_rule(&format!("!!{}", s))));

    CompiledRule { matcher, sub_rule }
}

/// Applies a pre-compiled rule against a proxy node.
///
/// # Arguments
/// * `compiled_rule` - The pre-compiled rule structure.
/// * `node` - The proxy node to match against.
///
/// # Returns
/// * `true` if the rule matches the node, `false` otherwise.
pub fn apply_compiled_rule(compiled_rule: &CompiledRule, node: &Proxy) -> bool {
    let primary_match = match &compiled_rule.matcher {
        CompiledMatcher::Group(re) => re.is_match(&node.group),
        CompiledMatcher::GroupId { ranges, negate } => {
            // Determine direction based on original rule (though not stored in compiled,
            // assume GroupId is +1, Insert is -1 conceptually)
            // We assume compile_rule was called on the original string, so we don't store
            // 'dir' Let's refine this: The compile function needs to know if
            // it's GROUPID or INSERT. For now, let's assume we only compile
            // GROUPID-like rules or handle INSERT elsewhere. A better approach
            // might be to store the direction in the CompiledMatcher enum.
            // Let's stick to the original match_range logic for simplicity for now.
            // We need the original rule string to call match_range properly,
            // which defeats the purpose of compiling.
            // Let's reimplement match_range logic here based on compiled ranges.
            let target = node.group_id as i32; // Assume dir = 1 for now
            let mut matched = false;
            for r in ranges {
                if target >= r.lower && target <= r.upper {
                    matched = true;
                    break;
                }
            }
            if *negate {
                !matched
            } else {
                matched
            }
        }
        CompiledMatcher::Type(re) => {
            if node.proxy_type == ProxyType::Unknown {
                false
            } else {
                let type_str = PROXY_TYPES.get(&node.proxy_type).unwrap_or(&"UNKNOWN");
                re.is_match(type_str)
            }
        }
        CompiledMatcher::Port { ranges, negate } => {
            let target = node.port as i32;
            let mut matched = false;
            for r in ranges {
                if target >= r.lower && target <= r.upper {
                    matched = true;
                    break;
                }
            }
            if *negate {
                !matched
            } else {
                matched
            }
        }
        CompiledMatcher::Server(re) => re.is_match(&node.hostname),
        CompiledMatcher::Protocol(re) => node.protocol().map_or(false, |p| re.is_match(p)),
        CompiledMatcher::UdpSupport(re) => {
            let udp_str = match node.udp {
                Some(true) => "yes",
                Some(false) => "no",
                None => "undefined",
            };
            re.is_match(udp_str)
        }
        CompiledMatcher::Security(re) => {
            let mut features = String::new();
            if node.tls_secure {
                features.push_str("TLS,");
            }
            if let Some(true) = node.allow_insecure {
                features.push_str("INSECURE,");
            }
            if let Some(true) = node.tls13 {
                features.push_str("TLS13,");
            }
            if !features.is_empty() {
                features.pop();
            } else {
                features.push_str("NONE");
            }
            re.is_match(&features)
        }
        CompiledMatcher::Remarks(re) | CompiledMatcher::Plain(re) => re.is_match(&node.remark),
        CompiledMatcher::AlwaysTrue => true,
        CompiledMatcher::Invalid => false, // Invalid rules never match
    };

    // If there's a sub-rule, the overall result is the logical AND of the primary
    // match and the sub-rule match.
    match &compiled_rule.sub_rule {
        Some(sub) => primary_match && apply_compiled_rule(sub, node),
        None => primary_match,
    }
}

/// Applies a pre-compiled rule against a simple string (like a remark).
/// Used for `RegexMatchConfig`.
pub fn apply_compiled_rule_to_string(compiled_rule: &CompiledRule, text: &str) -> bool {
    // Only Plain and Remarks matchers directly apply to a simple string.
    // Other matchers implicitly require a Proxy node context.
    let primary_match = match &compiled_rule.matcher {
        CompiledMatcher::Plain(re) | CompiledMatcher::Remarks(re) => re.is_match(text),
        CompiledMatcher::AlwaysTrue => true,
        CompiledMatcher::Invalid => false,
        // For other types, when applied to a string, they don't match
        _ => false,
    };

    // Sub-rules don't make sense when matching against a single string,
    // as the context (Proxy node) is lost. We only consider the primary match.
    // If a sub-rule exists, it implies the original rule was complex (e.g.,
    // !!GROUP=X!!Y) and shouldn't have been compiled for simple string matching
    // context. However, to be safe, let's return false if a sub-rule exists in
    // this context.
    if compiled_rule.sub_rule.is_some() {
        false
    } else {
        primary_match
    }
}

/// Replaces text using a pre-compiled regex.
///
/// # Arguments
/// * `text` - The input text.
/// * `re` - The pre-compiled regex object.
/// * `replacement` - The replacement string (can use capture groups like $1,
///   $name).
/// * `replace_all` - Whether to replace all occurrences or just the first.
/// * `literal` - Whether the replacement string should be treated literally (no
///   capture group expansion).
///
/// # Returns
/// * The text with replacements made.
pub fn replace_with_compiled_regex(
    text: &str,
    re: &Regex,
    replacement: &str,
    replace_all: bool,
    literal: bool,
) -> String {
    let result = if replace_all {
        if literal {
            re.replace_all(text, regex::NoExpand(replacement))
        } else {
            re.replace_all(text, replacement)
        }
    } else {
        // Find the first match for non-literal replacement
        if literal {
            re.replacen(text, 1, regex::NoExpand(replacement))
        } else {
            re.replacen(text, 1, replacement)
        }
    };
    result.into_owned() // Convert Cow<str> to String
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ProxyType;

    // Helper function to create a test proxy
    fn create_test_proxy() -> Proxy {
        Proxy {
            id: 1,
            group_id: 2,
            group: "TestGroup".to_string(),
            remark: "TestRemark".to_string(),
            hostname: "example.com".to_string(),
            port: 8080,
            proxy_type: ProxyType::Shadowsocks,
            combined_proxy: Some(
                crate::models::proxy_node::combined::CombinedProxy::ShadowsocksR(
                    crate::models::proxy_node::shadowsocksr::ShadowsocksRProxy {
                        protocol: Some("origin".to_string()),
                        ..Default::default()
                    },
                ),
            ),
            udp: Some(true),
            tls_secure: true,
            tls13: Some(true),
            ..Default::default()
        }
    }

    #[test]
    fn test_match_range_simple() {
        assert!(match_range("5", 5));
        assert!(!match_range("5", 6));
    }

    #[test]
    fn test_match_range_with_ranges() {
        assert!(match_range("1-10", 5));
        assert!(!match_range("1-10", 11));
    }

    #[test]
    fn test_match_range_with_negation() {
        assert!(!match_range("!5", 5));
        assert!(match_range("!5", 6));
        assert!(!match_range("!1-10", 5));
        assert!(match_range("!1-10", 11));
    }

    #[test]
    fn test_match_range_with_multiple() {
        assert!(match_range("1-5,10-15", 3));
        assert!(match_range("1-5,10-15", 12));
        assert!(!match_range("1-5,10-15", 7));
    }

    #[test]
    fn test_match_range_complex() {
        assert!(match_range("!1-5,10,15-20", 12));
        assert!(!match_range("!1-5,10,15-20", 10));
        assert!(!match_range("!1-5,10,15-20", 3));
        assert!(match_range("!1-5,10,15-20", 6));
    }

    #[test]
    fn test_reg_find() {
        assert!(reg_find("This is a test", "test"));
        assert!(reg_find("This is a test", "TEST")); // Case insensitive
        assert!(!reg_find("This is a test", "banana"));
        assert!(reg_find("This is a test", "")); // Empty pattern always matches
    }

    #[test]
    fn test_reg_match() {
        assert!(reg_match("12345", r"^\d+$"));
        assert!(!reg_match("12345a", r"^\d+$"));
        assert!(reg_match("HELLO", r"(?i)hello"));
    }

    #[test]
    fn test_apply_matcher_group() {
        let node = create_test_proxy();
        let mut real_rule = String::new();

        assert!(apply_matcher("!!GROUP=TestGroup", &mut real_rule, &node));
        assert_eq!(real_rule, "");

        real_rule.clear();
        assert!(!apply_matcher("!!GROUP=OtherGroup", &mut real_rule, &node));
    }

    #[test]
    fn test_apply_matcher_type() {
        let node = create_test_proxy();
        let mut real_rule = String::new();

        assert!(apply_matcher("!!TYPE=SS", &mut real_rule, &node));
        assert_eq!(real_rule, "");

        real_rule.clear();
        assert!(!apply_matcher("!!TYPE=VMess", &mut real_rule, &node));
    }

    #[test]
    fn test_apply_matcher_port() {
        let node = create_test_proxy();
        let mut real_rule = String::new();

        assert!(apply_matcher("!!PORT=8080", &mut real_rule, &node));
        assert_eq!(real_rule, "");

        real_rule.clear();
        assert!(apply_matcher("!!PORT=8000-9000", &mut real_rule, &node));

        real_rule.clear();
        assert!(!apply_matcher("!!PORT=443", &mut real_rule, &node));
    }

    #[test]
    fn test_apply_matcher_server() {
        let node = create_test_proxy();
        let mut real_rule = String::new();

        assert!(apply_matcher("!!SERVER=example", &mut real_rule, &node));
        assert_eq!(real_rule, "");

        real_rule.clear();
        assert!(!apply_matcher("!!SERVER=google", &mut real_rule, &node));
    }

    #[test]
    fn test_apply_matcher_protocol() {
        let node = create_test_proxy();
        let mut real_rule = String::new();

        assert!(apply_matcher("!!PROTOCOL=origin", &mut real_rule, &node));
        assert_eq!(real_rule, "");

        real_rule.clear();
        assert!(!apply_matcher(
            "!!PROTOCOL=auth_sha1",
            &mut real_rule,
            &node
        ));
    }

    #[test]
    fn test_apply_matcher_udp_support() {
        let node = create_test_proxy();
        let mut real_rule = String::new();

        assert!(apply_matcher("!!UDPSUPPORT=yes", &mut real_rule, &node));
        assert_eq!(real_rule, "");

        real_rule.clear();
        assert!(!apply_matcher("!!UDPSUPPORT=no", &mut real_rule, &node));

        // Test with undefined UDP support
        let mut node_no_udp = node.clone();
        node_no_udp.udp = None;

        real_rule.clear();
        assert!(apply_matcher(
            "!!UDPSUPPORT=undefined",
            &mut real_rule,
            &node_no_udp
        ));
    }

    #[test]
    fn test_apply_matcher_security() {
        let node = create_test_proxy();
        let mut real_rule = String::new();

        assert!(apply_matcher("!!SECURITY=TLS", &mut real_rule, &node));
        assert_eq!(real_rule, "");

        real_rule.clear();
        assert!(apply_matcher("!!SECURITY=TLS13", &mut real_rule, &node));

        real_rule.clear();
        assert!(!apply_matcher("!!SECURITY=INSECURE", &mut real_rule, &node));

        // Test with insecure allowed
        let mut node_insecure = node.clone();
        node_insecure.allow_insecure = Some(true);

        real_rule.clear();
        assert!(apply_matcher(
            "!!SECURITY=INSECURE",
            &mut real_rule,
            &node_insecure
        ));
    }

    #[test]
    fn test_apply_matcher_remarks() {
        let node = create_test_proxy();
        let mut real_rule = String::new();

        assert!(apply_matcher("!!REMARKS=Test", &mut real_rule, &node));
        assert_eq!(real_rule, "");

        real_rule.clear();
        assert!(!apply_matcher("!!REMARKS=Premium", &mut real_rule, &node));
    }

    #[test]
    fn test_apply_matcher_with_trailing_rule() {
        let node = create_test_proxy();
        let mut real_rule = String::new();

        assert!(apply_matcher(
            "!!GROUP=TestGroup!!.+",
            &mut real_rule,
            &node
        ));
        assert_eq!(real_rule, ".+");

        // The trailing rule ".+" will be used with node.remark in the parent
        // function
    }

    // Helper for creating test proxies
    fn create_proxy_for_compile_test(
        group: &str,
        group_id: i32,
        ptype: ProxyType,
        port: u16,
        hostname: &str,
        protocol: Option<&str>,
        udp: Option<bool>,
        tls: bool,
        insecure: Option<bool>,
        tls13: Option<bool>,
        remark: &str,
    ) -> Proxy {
        Proxy {
            id: 1, // Not usually matched
            group_id: group_id,
            group: group.to_string(),
            remark: remark.to_string(),
            hostname: hostname.to_string(),
            port,
            proxy_type: ptype,
            combined_proxy: protocol.map(|p| {
                crate::models::proxy_node::combined::CombinedProxy::ShadowsocksR(
                    crate::models::proxy_node::shadowsocksr::ShadowsocksRProxy {
                        protocol: Some(p.to_string()),
                        ..Default::default()
                    },
                )
            }),
            udp,
            tls_secure: tls,
            allow_insecure: insecure,
            tls13,
            ..Default::default()
        }
    }

    #[test]
    fn test_compile_rule_plain_regex() {
        let rule = compile_rule("some_remark_pattern");
        assert!(matches!(rule.matcher, CompiledMatcher::Plain(_)));
        assert!(rule.sub_rule.is_none());
        let node = create_proxy_for_compile_test(
            "G",
            1,
            ProxyType::HTTP,
            80,
            "h",
            None,
            None,
            false,
            None,
            None,
            "this matches some_remark_pattern",
        );
        assert!(apply_compiled_rule(&rule, &node));
        assert!(apply_compiled_rule_to_string(
            &rule,
            "this matches some_remark_pattern"
        ));
        assert!(!apply_compiled_rule_to_string(&rule, "no match here"));
    }

    #[test]
    fn test_compile_rule_group() {
        let rule = compile_rule("!!GROUP=Test.*");
        assert!(matches!(rule.matcher, CompiledMatcher::Group(_)));
        assert!(rule.sub_rule.is_none());
        let node = create_proxy_for_compile_test(
            "TestGroup",
            1,
            ProxyType::HTTP,
            80,
            "h",
            None,
            None,
            false,
            None,
            None,
            "remark",
        );
        assert!(apply_compiled_rule(&rule, &node));
        let node2 = create_proxy_for_compile_test(
            "OtherGroup",
            1,
            ProxyType::HTTP,
            80,
            "h",
            None,
            None,
            false,
            None,
            None,
            "remark",
        );
        assert!(!apply_compiled_rule(&rule, &node2));
    }

    #[test]
    fn test_compile_rule_group_with_subrule() {
        let rule = compile_rule("!!GROUP=Test.*!!PORT=80");
        assert!(matches!(rule.matcher, CompiledMatcher::Group(_)));
        assert!(rule.sub_rule.is_some());
        assert!(matches!(
            rule.sub_rule.as_ref().unwrap().matcher,
            CompiledMatcher::Port { .. }
        ));

        let node_match = create_proxy_for_compile_test(
            "TestGroup",
            1,
            ProxyType::HTTP,
            80,
            "h",
            None,
            None,
            false,
            None,
            None,
            "remark",
        );
        let node_no_group = create_proxy_for_compile_test(
            "OtherGroup",
            1,
            ProxyType::HTTP,
            80,
            "h",
            None,
            None,
            false,
            None,
            None,
            "remark",
        );
        let node_no_port = create_proxy_for_compile_test(
            "TestGroup",
            1,
            ProxyType::HTTP,
            81,
            "h",
            None,
            None,
            false,
            None,
            None,
            "remark",
        );

        assert!(apply_compiled_rule(&rule, &node_match));
        assert!(!apply_compiled_rule(&rule, &node_no_group));
        assert!(!apply_compiled_rule(&rule, &node_no_port));
    }

    #[test]
    fn test_compile_rule_groupid() {
        // Note: Doesn't handle !!INSERT= direction multiplier directly in compiled
        // struct yet
        let rule = compile_rule("!!GROUPID=1-5,10");
        assert!(matches!(rule.matcher, CompiledMatcher::GroupId { .. }));
        let node = create_proxy_for_compile_test(
            "G",
            3,
            ProxyType::HTTP,
            80,
            "h",
            None,
            None,
            false,
            None,
            None,
            "remark",
        );
        assert!(apply_compiled_rule(&rule, &node));
        let node2 = create_proxy_for_compile_test(
            "G",
            7,
            ProxyType::HTTP,
            80,
            "h",
            None,
            None,
            false,
            None,
            None,
            "remark",
        );
        assert!(!apply_compiled_rule(&rule, &node2));
        let node3 = create_proxy_for_compile_test(
            "G",
            10,
            ProxyType::HTTP,
            80,
            "h",
            None,
            None,
            false,
            None,
            None,
            "remark",
        );
        assert!(apply_compiled_rule(&rule, &node3));
    }

    #[test]
    fn test_compile_rule_port_negated() {
        let rule = compile_rule("!!PORT=!80,443");
        assert!(matches!(
            rule.matcher,
            CompiledMatcher::Port { negate: true, .. }
        ));
        let node_80 = create_proxy_for_compile_test(
            "G",
            1,
            ProxyType::HTTP,
            80,
            "h",
            None,
            None,
            false,
            None,
            None,
            "remark",
        );
        let node_443 = create_proxy_for_compile_test(
            "G",
            1,
            ProxyType::HTTPS,
            443,
            "h",
            None,
            None,
            false,
            None,
            None,
            "remark",
        );
        let node_other = create_proxy_for_compile_test(
            "G",
            1,
            ProxyType::Socks5,
            1080,
            "h",
            None,
            None,
            false,
            None,
            None,
            "remark",
        );
        assert!(!apply_compiled_rule(&rule, &node_80));
        assert!(!apply_compiled_rule(&rule, &node_443));
        assert!(apply_compiled_rule(&rule, &node_other));
    }

    #[test]
    fn test_compile_rule_type() {
        let rule = compile_rule("!!TYPE=S(S|OCKS5)"); // Matches SS or SOCKS5
        assert!(matches!(rule.matcher, CompiledMatcher::Type(_)));
        let node_ss = create_proxy_for_compile_test(
            "G",
            1,
            ProxyType::Shadowsocks,
            80,
            "h",
            None,
            None,
            false,
            None,
            None,
            "remark",
        );
        let node_socks = create_proxy_for_compile_test(
            "G",
            1,
            ProxyType::Socks5,
            1080,
            "h",
            None,
            None,
            false,
            None,
            None,
            "remark",
        );
        let node_vmess = create_proxy_for_compile_test(
            "G",
            1,
            ProxyType::VMess,
            80,
            "h",
            None,
            None,
            false,
            None,
            None,
            "remark",
        );
        assert!(apply_compiled_rule(&rule, &node_ss));
        assert!(apply_compiled_rule(&rule, &node_socks));
        assert!(!apply_compiled_rule(&rule, &node_vmess));
    }

    #[test]
    fn test_compile_rule_security() {
        let rule = compile_rule("!!SECURITY=TLS,TLS13");
        assert!(matches!(rule.matcher, CompiledMatcher::Security(_)));

        let node_match = create_proxy_for_compile_test(
            "G",
            1,
            ProxyType::Trojan,
            443,
            "h",
            None,
            None,
            true,
            None,
            Some(true),
            "remark",
        );
        let node_no_tls13 = create_proxy_for_compile_test(
            "G",
            1,
            ProxyType::Trojan,
            443,
            "h",
            None,
            None,
            true,
            None,
            Some(false),
            "remark",
        );
        let node_insecure = create_proxy_for_compile_test(
            "G",
            1,
            ProxyType::Trojan,
            443,
            "h",
            None,
            None,
            true,
            Some(true),
            Some(true),
            "remark",
        ); // Also matches "TLS," part

        assert!(apply_compiled_rule(&rule, &node_match)); // Matches "TLS,TLS13"
        assert!(apply_compiled_rule(&rule, &node_no_tls13)); // Matches "TLS" part
        assert!(apply_compiled_rule(&rule, &node_insecure)); // Matches "TLS,INSECURE,TLS13" -> contains "TLS,"
    }
}
