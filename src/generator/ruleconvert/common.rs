/// Transforms a rule to a common format for use in different proxy clients
///
/// # Arguments
///
/// * `input` - The rule to transform
/// * `group` - The proxy group to assign
/// * `no_resolve_only` - Whether to only keep no-resolve parameter
///
/// # Returns
///
/// The transformed rule as a string
pub fn transform_rule_to_common(input: &str, group: &str, no_resolve_only: bool) -> String {
    let mut parts = ["", "", "", ""]; // Pre-allocate array with 4 elements like C++ version
    let mut part_count = 0;

    // Split the input by comma and fill the parts array
    for (i, part) in input.split(',').enumerate() {
        if i < 4 {
            parts[i] = part;
            part_count = i + 1;
        } else {
            break;
        }
    }

    if part_count < 2 {
        // Single part rule, just add group
        format!("{},{}", parts[0], group)
    } else {
        // IPv6 CIDR values are sometimes written with surrounding brackets
        // (`IP-CIDR6,[2401::]/128`); most clients reject that form, so strip
        // the brackets (issue #39)
        let value = if parts[0].contains("IP-CIDR") || parts[0].contains("IP6-CIDR") {
            parts[1].replace(['[', ']'], "")
        } else {
            parts[1].to_string()
        };

        // Multi-part rule
        let mut result = format!("{},{},{}", parts[0], value, group);

        // Add options like no-resolve if present and applicable
        if part_count > 2 && (!no_resolve_only || parts[2] == "no-resolve") {
            result = format!("{},{}", result, parts[2]);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::transform_rule_to_common;

    /// Reproduces https://github.com/lonelam/subconverter-rs/issues/39
    #[test]
    fn test_ipv6_brackets_stripped() {
        assert_eq!(
            transform_rule_to_common(
                "IP-CIDR6,[2401:b60:e00e:715f::]/128,no-resolve",
                "DIRECT",
                false
            ),
            "IP-CIDR6,2401:b60:e00e:715f::/128,DIRECT,no-resolve"
        );
    }

    #[test]
    fn test_domain_rule_untouched() {
        assert_eq!(
            transform_rule_to_common("DOMAIN-SUFFIX,example.com", "PROXY", false),
            "DOMAIN-SUFFIX,example.com,PROXY"
        );
    }
}
