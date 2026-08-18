use std::{cmp::Ordering, str::FromStr};

use crate::{utils::file_get_async, Settings};

use super::{Proxy, ProxyType, RegexMatchConfig, RegexMatchConfigs};

/// Settings for subscription export operations
pub struct ExtraSettings {
    /// Whether to enable the rule generator
    pub enable_rule_generator: bool,
    /// Whether to overwrite original rules
    pub overwrite_original_rules: bool,
    /// Rename operations to apply
    pub rename_array: RegexMatchConfigs,
    /// Emoji operations to apply
    pub emoji_array: RegexMatchConfigs,
    /// Whether to add emoji
    pub add_emoji: bool,
    /// Whether to remove emoji
    pub remove_emoji: bool,
    /// Whether to append proxy type
    pub append_proxy_type: bool,
    /// Whether to output as node list
    pub nodelist: bool,
    /// Whether to sort nodes
    pub sort_flag: bool,
    /// Whether to filter deprecated nodes
    pub filter_deprecated: bool,
    /// Whether to use new field names in Clash
    pub clash_new_field_name: bool,
    /// Which Clash flavor the output targets
    pub clash_flavor: crate::models::ClashFlavor,
    /// Whether to use scripts in Clash
    pub clash_script: bool,
    /// Path to Surge SSR binary
    pub surge_ssr_path: String,
    /// Prefix for managed configs
    pub managed_config_prefix: String,
    /// QuantumultX device ID
    pub quanx_dev_id: String,
    /// UDP support flag
    pub udp: Option<bool>,
    /// TCP Fast Open support flag
    pub tfo: Option<bool>,
    /// Skip certificate verification flag
    pub skip_cert_verify: Option<bool>,
    /// TLS 1.3 support flag
    pub tls13: Option<bool>,
    /// Whether to use classical ruleset in Clash
    pub clash_classical_ruleset: bool,
    /// Script for sorting nodes
    pub sort_script: String,
    /// Style for Clash proxies output
    pub clash_proxies_style: String,
    /// Style for Clash proxy groups output
    pub clash_proxy_groups_style: String,
    /// Whether the export is authorized
    pub authorized: bool,
    /// JavaScript runtime context (not implemented in Rust version)
    #[cfg(feature = "js-runtime")]
    pub js_context: Option<rquickjs::Context>,
    /// JavaScript runtime
    #[cfg(feature = "js-runtime")]
    pub js_runtime: Option<rquickjs::Runtime>,
}

impl std::fmt::Debug for ExtraSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("ExtraSettings")
            .field("enable_rule_generator", &self.enable_rule_generator)
            .field("overwrite_original_rules", &self.overwrite_original_rules)
            .field("rename_array", &self.rename_array)
            .field("emoji_array", &self.emoji_array)
            .field("add_emoji", &self.add_emoji)
            .field("remove_emoji", &self.remove_emoji)
            .field("append_proxy_type", &self.append_proxy_type)
            .field("nodelist", &self.nodelist)
            .field("sort_flag", &self.sort_flag)
            .field("filter_deprecated", &self.filter_deprecated)
            .field("clash_new_field_name", &self.clash_new_field_name)
            .field("clash_script", &self.clash_script)
            .field("surge_ssr_path", &self.surge_ssr_path)
            .field("managed_config_prefix", &self.managed_config_prefix)
            .field("quanx_dev_id", &self.quanx_dev_id)
            .field("udp", &self.udp)
            .field("tfo", &self.tfo)
            .field("skip_cert_verify", &self.skip_cert_verify)
            .field("tls13", &self.tls13)
            .field("clash_classical_ruleset", &self.clash_classical_ruleset)
            .field("sort_script", &self.sort_script)
            .field("clash_proxies_style", &self.clash_proxies_style)
            .field("clash_proxy_groups_style", &self.clash_proxy_groups_style)
            .field("authorized", &self.authorized)
            .finish()
    }
}

impl Default for ExtraSettings {
    fn default() -> Self {
        let global = Settings::current();

        ExtraSettings {
            enable_rule_generator: global.enable_rule_gen,
            overwrite_original_rules: global.overwrite_original_rules,
            rename_array: Vec::new(),
            emoji_array: Vec::new(),
            add_emoji: false,
            remove_emoji: false,
            append_proxy_type: false,
            nodelist: false,
            sort_flag: false,
            filter_deprecated: false,
            clash_new_field_name: true,
            clash_flavor: Default::default(),
            clash_script: false,
            surge_ssr_path: global.surge_ssr_path.clone(),
            managed_config_prefix: String::new(),
            quanx_dev_id: String::new(),
            udp: None,
            tfo: None,
            skip_cert_verify: None,
            tls13: None,
            clash_classical_ruleset: false,
            sort_script: String::new(),
            clash_proxies_style: if global.clash_proxies_style.is_empty() {
                "flow".to_string()
            } else {
                global.clash_proxies_style.clone()
            },
            clash_proxy_groups_style: if global.clash_proxy_groups_style.is_empty() {
                "flow".to_string()
            } else {
                global.clash_proxy_groups_style.clone()
            },
            authorized: false,
            #[cfg(feature = "js-runtime")]
            js_context: None,
            #[cfg(feature = "js-runtime")]
            js_runtime: None,
        }
    }
}

#[cfg(feature = "js-runtime")]
impl ExtraSettings {
    pub fn init_js_context(&mut self) {
        if self.js_runtime.is_none() {
            self.js_runtime = Some(rquickjs::Runtime::new().unwrap());
            self.js_context =
                Some(rquickjs::Context::base(&self.js_runtime.as_ref().unwrap()).unwrap());
        }
    }

    pub fn eval_filter_function(
        &mut self,
        nodes: &mut Vec<Proxy>,
        source_str: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.init_js_context();
        if let Some(context) = &mut self.js_context {
            let mut error_thrown = None;
            context.with(|ctx| {
                match ctx.eval::<(), &str>(source_str) {
                    Ok(_) => (),
                    Err(e) => {
                        match e {
                            rquickjs::Error::Exception => {
                                log::error!(
                                    "JavaScript eval throw exception: {}",
                                    ctx.catch()
                                        .try_into_string()
                                        .unwrap()
                                        .to_string()
                                        .unwrap_or_default()
                                );
                            }
                            _ => {
                                log::error!("JavaScript eval error: {}", e);
                            }
                        }
                        error_thrown = Some(e);
                        return;
                    }
                };
                let filter_evaluated: rquickjs::Function =
                    match ctx.globals().get::<_, rquickjs::Function>("filter") {
                        Ok(value) => value,
                        Err(e) => {
                            log::error!("JavaScript eval get function error: {}", e);
                            return;
                        }
                    };

                nodes.retain_mut(|node| {
                    match filter_evaluated.call::<(Proxy,), bool>((node.clone(),)) {
                        Ok(value) => value,
                        Err(e) => {
                            log::error!("JavaScript eval call function error: {}", e);
                            false
                        }
                    }
                });
            });
            match error_thrown {
                Some(e) => Err(e.into()),
                None => {
                    log::info!("Filter function evaluated successfully");
                    Ok(())
                }
            }
        } else {
            Err("JavaScript context not initialized".into())
        }
    }

    /// Sorts nodes by a specified criterion
    pub async fn eval_sort_nodes(
        &mut self,
        nodes: &mut Vec<Proxy>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !self.sort_script.is_empty() {
            let sort_script;
            if self.sort_script.starts_with("path:") {
                sort_script = file_get_async(&self.sort_script[5..], None).await?;
            } else {
                sort_script = self.sort_script.clone();
            }
            self.init_js_context();
            let mut error_thrown = None;
            if let Some(context) = &mut self.js_context {
                context.with(|ctx| {
                    match ctx.eval::<(), &str>(&sort_script) {
                        Ok(_) => (),
                        Err(e) => match e {
                            rquickjs::Error::Exception => {
                                error_thrown = Some(e);
                                return;
                            }
                            _ => {
                                error_thrown = Some(e);
                                return;
                            }
                        },
                    }
                    let compare = match ctx.globals().get::<_, rquickjs::Function>("compare") {
                        Ok(value) => value,
                        Err(e) => {
                            log::error!("JavaScript eval get function error: {}", e);
                            return;
                        }
                    };
                    nodes.sort_by(|a, b| {
                        match compare.call::<(Proxy, Proxy), i32>((a.clone(), b.clone())) {
                            Ok(value) => {
                                if value > 0 {
                                    Ordering::Greater
                                } else if value < 0 {
                                    Ordering::Less
                                } else {
                                    Ordering::Equal
                                }
                            }
                            Err(e) => {
                                log::error!("JavaScript eval call function error: {}", e);
                                return Ordering::Equal;
                            }
                        }
                    });
                });
            }
            if let Some(e) = error_thrown {
                return Err(e.into());
            }
        } else {
            // Default sort by remark
            nodes.sort_by(|a, b| {
                if a.proxy_type == ProxyType::Unknown {
                    return Ordering::Greater;
                }
                if b.proxy_type == ProxyType::Unknown {
                    return Ordering::Less;
                }
                a.remark.cmp(&b.remark)
            });
        }
        Ok(())
    }

    pub async fn eval_get_rename_node_remark(
        &self,
        node: &Proxy,
        match_script: String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut node_name = String::new();
        if !match_script.is_empty() {
            let mut error_thrown = None;
            if let Some(context) = &self.js_context {
                context.with(|ctx| {
                    match ctx.eval::<(), &str>(&match_script) {
                        Ok(_) => (),
                        Err(e) => {
                            error_thrown = Some(e);
                            return;
                        }
                    }
                    let rename = match ctx.globals().get::<_, rquickjs::Function>("rename") {
                        Ok(value) => value,
                        Err(e) => {
                            log::error!("JavaScript eval get function error: {}", e);
                            error_thrown = Some(e);
                            return;
                        }
                    };
                    match rename.call::<(Proxy,), String>((node.clone(),)) {
                        Ok(value) => {
                            if !value.is_empty() {
                                node_name = value;
                            }
                        }
                        Err(e) => {
                            log::error!("JavaScript eval call function error: {}", e);
                            error_thrown = Some(e);
                            return;
                        }
                    }
                })
            }
            if let Some(e) = error_thrown {
                return Err(e.into());
            }
        }
        Ok(node_name)
    }

    pub async fn eval_get_emoji_node_remark(
        &self,
        node: &Proxy,
        match_script: String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut node_emoji = String::new();
        if !match_script.is_empty() {
            let mut error_thrown = None;
            if let Some(context) = &self.js_context {
                context.with(|ctx| {
                    match ctx.eval::<(), &str>(&match_script) {
                        Ok(_) => (),
                        Err(e) => {
                            error_thrown = Some(e);
                            return;
                        }
                    }
                    let get_emoji = match ctx.globals().get::<_, rquickjs::Function>("getEmoji") {
                        Ok(value) => value,
                        Err(e) => {
                            log::error!("JavaScript eval get function error: {}", e);
                            error_thrown = Some(e);
                            return;
                        }
                    };
                    match get_emoji.call::<(Proxy,), String>((node.clone(),)) {
                        Ok(value) => {
                            if !value.is_empty() {
                                node_emoji = value;
                            }
                        }
                        Err(e) => {
                            log::error!("JavaScript eval call function error: {}", e);
                            error_thrown = Some(e);
                            return;
                        }
                    }
                })
            }
            if let Some(e) = error_thrown {
                return Err(e.into());
            }
        }
        Ok(node_emoji)
    }
}

#[cfg(not(feature = "js-runtime"))]
impl ExtraSettings {
    pub fn init_js_context(&mut self) {}
    pub fn eval_filter_function(
        &mut self,
        _nodes: &mut Vec<Proxy>,
        _source_str: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err(
            "JavaScript is not supported in this build, please enable js-runtime feature in cargo build"
                .into(),
        )
    }
    pub async fn eval_sort_nodes(
        &mut self,
        _nodes: &mut Vec<Proxy>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err(
            "JavaScript is not supported in this build, please enable js-runtime feature in cargo build"
                .into(),
        )
    }
    pub async fn eval_get_rename_node_remark(
        &self,
        _node: &Proxy,
        _match_script: String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        Err(
            "JavaScript is not supported in this build, please enable js-runtime feature in cargo build"
                .into(),
        )
    }
    pub async fn eval_get_emoji_node_remark(
        &self,
        _node: &Proxy,
        _match_script: String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        Err(
            "JavaScript is not supported in this build, please enable js-runtime feature in cargo build"
                .into(),
        )
    }
}
