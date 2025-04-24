//! Rule conversion module for different proxy configuration formats
//!
//! This module provides functionality for converting proxy rules between different formats
//! such as Clash, Surge, Quantumult X, etc.

pub mod common;
pub mod convert_ruleset;
// Keep the ruleset module for now but don't use its RulesetType
mod ruleset;
// mod ruleset_to_clash; // @deprecated
pub mod ruleset_to_clash_str;
pub mod ruleset_to_sing_box;
pub mod ruleset_to_surge;

pub use convert_ruleset::convert_ruleset;
pub use ruleset_to_sing_box::ruleset_to_sing_box;
pub use ruleset_to_surge::ruleset_to_surge;
