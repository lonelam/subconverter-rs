use serde::Deserialize;

use crate::utils::{
    matcher::{
        apply_compiled_rule_to_string, compile_rule, replace_with_compiled_regex, CompiledRule,
    },
    reg_replace,
};
use regex::Regex;

/// Configuration for regex-based matching operations
#[derive(Debug, Clone, Deserialize)]
pub struct RegexMatchConfig {
    #[serde(rename = "match")]
    pub _match: String,
    pub replace: String,
    pub script: String,

    // Non-serialized field to hold the compiled rule
    #[serde(skip)]
    pub compiled_rule: Option<CompiledRule>,
    // Optionally store the compiled regex specifically for replacement if needed
    #[serde(skip)]
    pub compiled_regex_for_replace: Option<Regex>,
}

impl RegexMatchConfig {
    pub fn new(_match: String, replace: String, script: String) -> Self {
        let mut config = Self {
            _match,
            replace,
            script,
            compiled_rule: None,
            compiled_regex_for_replace: None,
        };

        config.compile();
        config
    }

    /// Compiles the regex pattern in the `_match` field.
    /// This should be called after deserialization or creation.
    pub fn compile(&mut self) {
        self.compiled_rule = Some(compile_rule(&self._match));
        // Also pre-compile the regex specifically for the replacement logic
        // Use the same case-insensitivity as reg_find/compile_rule(Plain/Remarks)
        self.compiled_regex_for_replace = Regex::new(&format!("(?i){}", self._match)).ok();
    }

    pub fn process(&self, remark: &mut String) {
        // Use compiled rule for matching if available, falling back to the
        // original method if not compiled (shouldn't happen if compile() is
        // called)
        let matched = if let Some(compiled) = &self.compiled_rule {
            apply_compiled_rule_to_string(compiled, remark)
        } else {
            crate::utils::matcher::reg_find(remark, &self._match)
        };

        if matched {
            // Use pre-compiled regex for replacement if available
            if let Some(re) = &self.compiled_regex_for_replace {
                *remark = replace_with_compiled_regex(remark, re, &self.replace, true, false);
            } else {
                // Fallback to original reg_replace if regex compilation failed during compile()
                *remark = reg_replace(remark, &self._match, &self.replace, true, false);
            }
        }
    }
}

/// Collection of regex match configurations
pub type RegexMatchConfigs = Vec<RegexMatchConfig>;
