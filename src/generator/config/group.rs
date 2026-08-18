//! Group generation utilities
//!
//! This module provides functionality for generating proxy groups.

use crate::{
    models::ExtraSettings,
    utils::{
        matcher::{apply_matcher, reg_find},
        starts_with,
    },
    Proxy,
};

/// Generates a filtered list of nodes based on a rule and node list
///
/// # Arguments
///
/// * `rule` - The rule to apply to filter nodes
/// * `nodelist` - List of all available proxy nodes
/// * `filtered_nodelist` - Output parameter that will contain the filtered node list
/// * `add_direct` - Whether to add direct connection to the list
/// * `ext` - Extra settings
///
/// # Returns
///
/// Nothing, modifies filtered_nodelist in-place
pub fn group_generate(
    rule: &str,
    nodelist: &[Proxy],
    filtered_nodelist: &mut Vec<String>,
    add_direct: bool,
    ext: &ExtraSettings,
) {
    // Rule parsing
    if starts_with(rule, "[]") && add_direct {
        filtered_nodelist.push(rule[2..].to_string());
    } else if starts_with(rule, "script:") && ext.authorized {
        // TODO: javascript
    } else {
        // Include only nodes that match the rule
        for node in nodelist {
            let mut real_rule = String::new();
            if apply_matcher(rule, &mut real_rule, node) {
                if real_rule.is_empty() || reg_find(&node.remark, &real_rule) {
                    filtered_nodelist.push(node.remark.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Proxy, ProxyType};

    // 创建测试用的代理节点
    fn create_test_nodes() -> Vec<Proxy> {
        vec![
            Proxy {
                id: 1,
                group_id: 1,
                group: "HK".to_string(),
                remark: "HK Node 1".to_string(),
                hostname: "hk1.example.com".to_string(),
                port: 443,
                proxy_type: ProxyType::Shadowsocks,
                udp: Some(true),
                ..Default::default()
            },
            Proxy {
                id: 2,
                group_id: 1,
                group: "HK".to_string(),
                remark: "HK Node 2".to_string(),
                hostname: "hk2.example.com".to_string(),
                port: 8388,
                proxy_type: ProxyType::Shadowsocks,
                ..Default::default()
            },
            Proxy {
                id: 3,
                group_id: 2,
                group: "JP".to_string(),
                remark: "JP Node 1".to_string(),
                hostname: "jp1.example.com".to_string(),
                port: 443,
                proxy_type: ProxyType::VMess,
                ..Default::default()
            },
            Proxy {
                id: 4,
                group_id: 3,
                group: "US".to_string(),
                remark: "US Node 1".to_string(),
                hostname: "us1.example.com".to_string(),
                port: 8080,
                proxy_type: ProxyType::Trojan,
                ..Default::default()
            },
        ]
    }

    #[test]
    fn test_group_generate_direct_string() {
        let nodes = create_test_nodes();
        let mut filtered = Vec::new();
        let ext = ExtraSettings::default();

        // 测试直接字符串规则
        group_generate("[]DIRECT", &nodes, &mut filtered, true, &ext);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], "DIRECT");
    }

    #[test]
    fn test_group_generate_with_group_match() {
        let nodes = create_test_nodes();
        let mut filtered = Vec::new();
        let ext = ExtraSettings::default();

        // 测试组匹配规则
        group_generate("!!GROUP=HK", &nodes, &mut filtered, true, &ext);

        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains(&"HK Node 1".to_string()));
        assert!(filtered.contains(&"HK Node 2".to_string()));
    }

    #[test]
    fn test_group_generate_with_type_match() {
        let nodes = create_test_nodes();
        let mut filtered = Vec::new();
        let ext = ExtraSettings::default();

        // 测试类型匹配规则
        group_generate("!!TYPE=VMESS", &nodes, &mut filtered, true, &ext);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], "JP Node 1");
    }

    #[test]
    fn test_group_generate_with_port_match() {
        let nodes = create_test_nodes();
        let mut filtered = Vec::new();
        let ext = ExtraSettings::default();

        // 测试端口匹配规则
        group_generate("!!PORT=443", &nodes, &mut filtered, true, &ext);

        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains(&"HK Node 1".to_string()));
        assert!(filtered.contains(&"JP Node 1".to_string()));
    }

    #[test]
    fn test_group_generate_empty_result_with_direct() {
        let nodes = create_test_nodes();
        let mut filtered = Vec::new();
        let ext = ExtraSettings::default();

        // 没有匹配节点时结果为空；由调用方（如 proxy_to_clash）负责
        // 在空组时补充 DIRECT，与 C++ 版本行为一致
        group_generate("!!GROUP=SG", &nodes, &mut filtered, true, &ext);
        assert!(filtered.is_empty());

        // 显式 []DIRECT 规则在 add_direct 模式下应被保留
        group_generate("[]DIRECT", &nodes, &mut filtered, true, &ext);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], "DIRECT");
    }

    #[test]
    fn test_group_generate_empty_result_without_direct() {
        let nodes = create_test_nodes();
        let mut filtered = Vec::new();
        let ext = ExtraSettings::default();

        // 测试没有匹配节点且不添加 DIRECT
        group_generate("!!GROUP=SG", &nodes, &mut filtered, false, &ext);

        assert_eq!(filtered.len(), 0);
    }

    #[test]
    fn test_group_generate_with_regex_match() {
        let nodes = create_test_nodes();
        let mut filtered = Vec::new();
        let ext = ExtraSettings::default();

        // 测试正则表达式匹配
        group_generate("Node \\d", &nodes, &mut filtered, true, &ext);

        assert_eq!(filtered.len(), 4);
        assert!(filtered.contains(&"HK Node 1".to_string()));
        assert!(filtered.contains(&"HK Node 2".to_string()));
        assert!(filtered.contains(&"JP Node 1".to_string()));
        assert!(filtered.contains(&"US Node 1".to_string()));
    }
}
