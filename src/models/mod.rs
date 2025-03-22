//! Core data models for the application
//!
//! This module contains the primary data structures used throughout the application,
//! separated from the logic that operates on them.
//!
//! # Usage
//!
//! Import the models directly from this module:
//!
//! ```rust
//! use subconverter_rs::models::{Proxy, ProxyType};
//!
//! // Create a new proxy
//! let mut proxy = Proxy::default();
//! proxy.proxy_type = ProxyType::VMess;
//! proxy.hostname = "example.com".to_string();
//! proxy.port = 443;
//! ```
//!
//! Or use the re-exports from the crate root:
//!
//! ```rust
//! use subconverter_rs::{Proxy, ProxyType};
//!
//! // Create a new proxy
//! let mut proxy = Proxy::default();
//! proxy.proxy_type = ProxyType::VMess;
//! ```
//!
//! # Working with Option fields
//!
//! Many fields in the `Proxy` struct are wrapped in `Option`, which requires
//! special handling:
//!
//! ```rust
//! use subconverter_rs::Proxy;
//!
//! let proxy = Proxy::default();
//!
//! // Check if an Option<String> field is Some and not empty
//! if proxy.encrypt_method.as_ref().map_or(false, |s| !s.is_empty()) {
//!     println!("Encryption method: {}", proxy.encrypt_method.as_ref().unwrap());
//! }
//!
//! // Provide a default value
//! let method = proxy.encrypt_method.as_deref().unwrap_or("none");
//! ```
//!
//! See the examples directory for more detailed usage examples.

mod app_state;
mod builder;
mod ciphers;
mod configs;
mod extra_settings;
mod proxy;
mod proxy_group_config;
pub mod ruleset;

pub use app_state::AppState;
pub use extra_settings::{ExtraSettings, RegexMatchConfig, RegexMatchConfigs};
pub use proxy_group_config::{
    BalanceStrategy, ProxyGroupConfig, ProxyGroupConfigs, ProxyGroupType,
};

pub use proxy::{Proxy, ProxyType};
pub use ruleset::{RulesetContent, RulesetType};

// Re-export constants to module scope for use by other modules
// Default proxy group names
pub use ciphers::{SSR_CIPHERS, SS_CIPHERS};
pub use proxy::{
    HTTP_DEFAULT_GROUP, HYSTERIA2_DEFAULT_GROUP, HYSTERIA_DEFAULT_GROUP, SNELL_DEFAULT_GROUP,
    SOCKS_DEFAULT_GROUP, SSR_DEFAULT_GROUP, SS_DEFAULT_GROUP, TROJAN_DEFAULT_GROUP,
    V2RAY_DEFAULT_GROUP, WG_DEFAULT_GROUP,
};
