pub mod api;
pub mod constants;
pub mod generator;
pub mod interfaces;
pub mod models;
pub mod parser;
pub mod rulesets;
pub mod settings;
pub mod template;
pub mod upload;
pub mod utils;
#[cfg(target_arch = "wasm32")]
pub mod vfs;
#[cfg(feature = "web-api")]
pub mod web_handlers;

// Re-export the main proxy types for easier access
pub use models::{Proxy, ProxyType};

// Re-export configuration types
pub use parser::types::ConfType;

// Re-export settings
pub use settings::settings::settings_struct::update_settings_from_content;
pub use settings::settings::settings_struct::update_settings_from_file;
pub use settings::{ExternalSettings, Settings};

// Re-export ruleset types
pub use models::ruleset::RulesetType;

// Re-export SubconverterTarget
pub use models::SubconverterTarget;

// Re-export interfaces
pub use interfaces::*;

// Re-export template functionality
pub use template::{render_template, TemplateArgs};
