use crate::generator::config::formats::single::{proxy_to_single, ProxyUriTypes};
use crate::generator::config::formats::ssd::proxy_to_ssd;
use crate::generator::config::formats::{
    loon::proxy_to_loon, mellow::proxy_to_mellow, quan::proxy_to_quan, quanx::proxy_to_quanx,
    singbox::proxy_to_singbox, ss_sub::proxy_to_ss_sub, surge::proxy_to_surge,
};
use crate::generator::exports::proxy_to_clash::proxy_to_clash;
use crate::models::ruleset::RulesetConfigs;
use crate::models::{
    ExtraSettings, Proxy, ProxyGroupConfigs, RegexMatchConfig, RulesetContent, SubconverterTarget,
};
use crate::parser::parse_settings::ParseSettings;
use crate::parser::subparser::add_nodes;
use crate::rulesets::ruleset::refresh_rulesets;
use crate::utils::file_get_async;
use crate::utils::http::parse_proxy;
use crate::utils::http::web_get_async;
use crate::{Settings, TemplateArgs};
use case_insensitive_string::CaseInsensitiveString;
use log::{debug, error, info, warn};
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct RuleBases {
    // Rule bases
    pub clash_rule_base: String,
    pub surge_rule_base: String,
    pub surfboard_rule_base: String,
    pub mellow_rule_base: String,
    pub quan_rule_base: String,
    pub quanx_rule_base: String,
    pub loon_rule_base: String,
    pub sssub_rule_base: String,
    pub singbox_rule_base: String,
}

/// Configuration for subconverter
#[derive(Debug, Clone)]
pub struct SubconverterConfig {
    /// Target conversion format
    pub target: SubconverterTarget,
    /// URLs to parse
    pub urls: Vec<String>,
    /// URLs to insert
    pub insert_urls: Vec<String>,
    /// Whether to prepend inserted nodes
    pub prepend_insert: bool,
    /// Custom group name
    pub group_name: Option<String>,
    /// Ruleset configs
    pub ruleset_configs: RulesetConfigs,
    /// Custom proxy groups
    pub proxy_groups: ProxyGroupConfigs,
    /// Include nodes matching these remarks
    pub include_remarks: Vec<String>,
    /// Exclude nodes matching these remarks
    pub exclude_remarks: Vec<String>,
    /// Additional settings
    pub extra: ExtraSettings,
    /// Device ID for certain formats
    pub device_id: Option<String>,
    /// Filename for download
    pub filename: Option<String>,
    /// Update interval in seconds
    pub update_interval: u32,
    /// Filter script
    pub filter_script: Option<String>,
    /// Whether update is strict
    pub update_strict: bool,
    /// Managed config prefix
    pub managed_config_prefix: String,
    /// Upload path
    pub upload_path: Option<String>,
    /// Whether to upload the result
    pub upload: bool,
    /// Proxy for fetching subscriptions
    pub proxy: Option<String>,
    /// Authentication token
    pub token: Option<String>,
    /// Whether this request is authorized
    pub authorized: bool,
    /// Subscription information
    pub sub_info: Option<String>,
    /// Rule bases
    pub rule_bases: RuleBases,
    /// Template arguments
    pub template_args: Option<TemplateArgs>,
    /// Request headers
    pub request_headers: Option<HashMap<String, String>>,
}

/// Builder for SubconverterConfig
#[derive(Debug, Clone)]
pub struct SubconverterConfigBuilder {
    config: SubconverterConfig,
}

impl Default for SubconverterConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SubconverterConfigBuilder {
    /// Create a new default builder
    pub fn new() -> Self {
        SubconverterConfigBuilder {
            config: SubconverterConfig {
                target: SubconverterTarget::Clash,
                urls: Vec::new(),
                insert_urls: Vec::new(),
                prepend_insert: false,
                group_name: None,
                ruleset_configs: RulesetConfigs::default(),
                proxy_groups: Vec::new(),
                include_remarks: Vec::new(),
                exclude_remarks: Vec::new(),
                extra: ExtraSettings::default(),
                device_id: None,
                filename: None,
                update_interval: 86400, // 24 hours
                filter_script: None,
                update_strict: false,
                managed_config_prefix: String::new(),
                upload_path: None,
                upload: false,
                proxy: None,
                token: None,
                authorized: false,
                sub_info: None,
                rule_bases: RuleBases::default(),
                template_args: None,
                request_headers: None,
            },
        }
    }

    /// Set the target format
    pub fn target(&mut self, target: SubconverterTarget) -> &mut Self {
        self.config.target = target;
        self
    }

    /// Set target from string
    pub fn target_from_str(&mut self, target: &str) -> &mut Self {
        if let Some(t) = SubconverterTarget::from_str(target) {
            self.config.target = t;
        }
        self
    }

    /// Set Surge version if target is Surge
    pub fn surge_version(&mut self, version: i32) -> &mut Self {
        if let SubconverterTarget::Surge(_) = self.config.target {
            self.config.target = SubconverterTarget::Surge(version);
        }
        self
    }

    /// Add a URL to parse
    pub fn add_url(&mut self, url: &str) -> &mut Self {
        self.config.urls.push(url.to_string());
        self
    }

    /// Set URLs to parse
    pub fn urls(&mut self, urls: Vec<String>) -> &mut Self {
        self.config.urls = urls;
        self
    }

    /// Set URLs from pipe-separated string
    pub fn urls_from_str(&mut self, urls: &str) -> &mut Self {
        self.config.urls = urls.split('|').map(|s| s.trim().to_string()).collect();
        self
    }

    /// Add an insert URL
    pub fn add_insert_url(&mut self, url: &str) -> &mut Self {
        if !url.is_empty() {
            self.config.insert_urls.push(url.to_string());
        }
        self
    }

    /// Set insert URLs
    pub fn insert_urls(&mut self, urls: Vec<String>) -> &mut Self {
        self.config.insert_urls = urls
            .iter()
            .filter(|u| !u.is_empty())
            .map(|u| u.to_string())
            .collect();
        self
    }

    /// Set insert URLs from pipe-separated string
    pub fn insert_urls_from_str(&mut self, urls: &str) -> &mut Self {
        self.config.insert_urls = urls.split('|').map(|s| s.trim().to_string()).collect();
        self
    }

    /// Set whether to prepend inserted nodes
    pub fn prepend_insert(&mut self, prepend: bool) -> &mut Self {
        self.config.prepend_insert = prepend;
        self
    }

    /// Set custom group name
    pub fn group_name(&mut self, name: Option<String>) -> &mut Self {
        self.config.group_name = name;
        self
    }

    /// Set proxy groups
    pub fn proxy_groups(&mut self, groups: ProxyGroupConfigs) -> &mut Self {
        self.config.proxy_groups = groups;
        self
    }

    pub fn ruleset_configs(&mut self, configs: RulesetConfigs) -> &mut Self {
        self.config.ruleset_configs = configs;
        self
    }

    /// Add an include remark pattern
    pub fn add_include_remark(&mut self, pattern: &str) -> &mut Self {
        self.config.include_remarks.push(pattern.to_string());
        self
    }

    /// Set include remark patterns
    pub fn include_remarks(&mut self, patterns: Vec<String>) -> &mut Self {
        self.config.include_remarks = patterns;
        self
    }

    /// Add an exclude remark pattern
    pub fn add_exclude_remark(&mut self, pattern: &str) -> &mut Self {
        self.config.exclude_remarks.push(pattern.to_string());
        self
    }

    /// Set exclude remark patterns
    pub fn exclude_remarks(&mut self, patterns: Vec<String>) -> &mut Self {
        self.config.exclude_remarks = patterns;
        self
    }

    pub fn emoji_array(&mut self, patterns: Vec<RegexMatchConfig>) -> &mut Self {
        self.config.extra.emoji_array = patterns;
        self
    }

    pub fn rename_array(&mut self, patterns: Vec<RegexMatchConfig>) -> &mut Self {
        self.config.extra.rename_array = patterns;
        self
    }

    pub fn add_emoji(&mut self, add: bool) -> &mut Self {
        self.config.extra.add_emoji = add;
        self
    }

    pub fn remove_emoji(&mut self, remove: bool) -> &mut Self {
        self.config.extra.remove_emoji = remove;
        self
    }

    /// Set extra settings
    pub fn extra(&mut self, extra: ExtraSettings) -> &mut Self {
        self.config.extra = extra;
        self
    }

    /// Set whether to append proxy type to remarks
    pub fn append_proxy_type(&mut self, append: bool) -> &mut Self {
        self.config.extra.append_proxy_type = append;
        self
    }

    /// Set whether to enable TCP Fast Open
    pub fn tfo(&mut self, tfo: Option<bool>) -> &mut Self {
        self.config.extra.tfo = tfo;
        self
    }

    /// Set whether to enable UDP
    pub fn udp(&mut self, udp: Option<bool>) -> &mut Self {
        self.config.extra.udp = udp;
        self
    }

    /// Set whether to skip certificate verification
    pub fn skip_cert_verify(&mut self, skip: Option<bool>) -> &mut Self {
        self.config.extra.skip_cert_verify = skip;
        self
    }

    /// Set whether to enable TLS 1.3
    pub fn tls13(&mut self, tls13: Option<bool>) -> &mut Self {
        self.config.extra.tls13 = tls13;
        self
    }

    /// Set whether to sort nodes
    pub fn sort(&mut self, sort: bool) -> &mut Self {
        self.config.extra.sort_flag = sort;
        self
    }

    /// Set sort script
    pub fn sort_script(&mut self, script: String) -> &mut Self {
        self.config.extra.sort_script = script;
        self
    }

    /// Set whether to filter deprecated nodes
    pub fn filter_deprecated(&mut self, filter: bool) -> &mut Self {
        self.config.extra.filter_deprecated = filter;
        self
    }

    /// Set whether to use new field names in Clash
    pub fn clash_new_field_name(&mut self, new_field: bool) -> &mut Self {
        self.config.extra.clash_new_field_name = new_field;
        self
    }

    /// Set whether to enable Clash script
    pub fn clash_script(&mut self, enable: bool) -> &mut Self {
        self.config.extra.clash_script = enable;
        self
    }

    pub fn clash_classical_ruleset(&mut self, enable: bool) -> &mut Self {
        self.config.extra.clash_classical_ruleset = enable;
        self
    }

    /// Set whether to generate node list
    pub fn nodelist(&mut self, nodelist: bool) -> &mut Self {
        self.config.extra.nodelist = nodelist;
        self
    }

    /// Set whether to enable rule generator
    pub fn enable_rule_generator(&mut self, enable: bool) -> &mut Self {
        self.config.extra.enable_rule_generator = enable;
        self
    }

    /// Set whether to overwrite original rules
    pub fn overwrite_original_rules(&mut self, overwrite: bool) -> &mut Self {
        self.config.extra.overwrite_original_rules = overwrite;
        self
    }

    /// Set device ID
    pub fn device_id(&mut self, device_id: Option<String>) -> &mut Self {
        self.config.device_id = device_id;
        self
    }

    /// Set filename
    pub fn filename(&mut self, filename: Option<String>) -> &mut Self {
        self.config.filename = filename;
        self
    }

    /// Set update interval
    pub fn update_interval(&mut self, interval: u32) -> &mut Self {
        self.config.update_interval = interval;
        self
    }

    /// Set filter script
    pub fn filter_script(&mut self, script: Option<String>) -> &mut Self {
        self.config.filter_script = script;
        self
    }

    /// Set whether update is strict
    pub fn update_strict(&mut self, strict: bool) -> &mut Self {
        self.config.update_strict = strict;
        self
    }

    /// Set managed config prefix
    pub fn managed_config_prefix(&mut self, prefix: String) -> &mut Self {
        self.config.managed_config_prefix = prefix;
        self
    }

    /// Set upload path
    pub fn upload_path(&mut self, path: Option<String>) -> &mut Self {
        self.config.upload_path = path;
        self
    }

    /// Set whether to upload the result
    pub fn upload(&mut self, upload: bool) -> &mut Self {
        self.config.upload = upload;
        self
    }

    /// Set proxy for fetching subscriptions
    pub fn proxy(&mut self, proxy: Option<String>) -> &mut Self {
        self.config.proxy = proxy;
        self
    }

    /// Set authentication token
    pub fn token(&mut self, token: Option<String>) -> &mut Self {
        self.config.token = token;
        self
    }

    /// Set whether this request is authorized
    pub fn authorized(&mut self, authorized: bool) -> &mut Self {
        self.config.authorized = authorized;
        self
    }

    /// Set subscription information
    pub fn sub_info(&mut self, sub_info: Option<String>) -> &mut Self {
        self.config.sub_info = sub_info;
        self
    }
    /// rule bases updates
    pub fn rule_bases(&mut self, rule_bases: RuleBases) -> &mut Self {
        self.config.rule_bases = rule_bases;
        self
    }

    /// Set template arguments
    pub fn template_args(&mut self, template_args: TemplateArgs) -> &mut Self {
        self.config.template_args = Some(template_args);
        self
    }

    /// Set rule base for Clash
    pub fn clash_rule_base(&mut self, path: &str) -> &mut Self {
        self.config.rule_bases.clash_rule_base = path.to_string();
        self
    }

    /// Set rule base for Surge
    pub fn surge_rule_base(&mut self, path: &str) -> &mut Self {
        self.config.rule_bases.surge_rule_base = path.to_string();
        self
    }

    /// Set rule base for Surfboard
    pub fn surfboard_rule_base(&mut self, path: &str) -> &mut Self {
        self.config.rule_bases.surfboard_rule_base = path.to_string();
        self
    }

    /// Set rule base for Mellow
    pub fn mellow_rule_base(&mut self, path: &str) -> &mut Self {
        self.config.rule_bases.mellow_rule_base = path.to_string();
        self
    }

    /// Set rule base for Quantumult
    pub fn quan_rule_base(&mut self, path: &str) -> &mut Self {
        self.config.rule_bases.quan_rule_base = path.to_string();
        self
    }

    /// Set rule base for QuantumultX
    pub fn quanx_rule_base(&mut self, path: &str) -> &mut Self {
        self.config.rule_bases.quanx_rule_base = path.to_string();
        self
    }

    /// Set rule base for Loon
    pub fn loon_rule_base(&mut self, path: &str) -> &mut Self {
        self.config.rule_bases.loon_rule_base = path.to_string();
        self
    }

    /// Set rule base for SS Subscription
    pub fn sssub_rule_base(&mut self, path: &str) -> &mut Self {
        self.config.rule_bases.sssub_rule_base = path.to_string();
        self
    }

    /// Set rule base for SingBox
    pub fn singbox_rule_base(&mut self, path: &str) -> &mut Self {
        self.config.rule_bases.singbox_rule_base = path.to_string();
        self
    }

    /// Set request headers
    pub fn request_headers(&mut self, headers: HashMap<String, String>) -> &mut Self {
        self.config.request_headers = Some(headers);
        self
    }

    /// Build the final configuration
    pub fn build(self) -> Result<SubconverterConfig, String> {
        let config = self.config;

        // Basic validation
        if config.urls.is_empty() && config.insert_urls.is_empty() {
            return Err("No URLs provided".to_string());
        }

        Ok(config)
    }
}

/// Result of subscription conversion
#[derive(Debug, Clone)]
pub struct SubconverterResult {
    /// Converted content
    pub content: String,
    /// Response headers
    pub headers: HashMap<String, String>,
}

/// Options for parsing subscriptions
#[derive(Debug, Clone)]
pub struct ParseOptions {
    /// Remarks to include in parsing
    pub include_remarks: Vec<String>,

    /// Remarks to exclude from parsing
    pub exclude_remarks: Vec<String>,

    /// Whether the request is authorized
    pub authorized: bool,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            include_remarks: Vec::new(),
            exclude_remarks: Vec::new(),
            authorized: false,
        }
    }
}

/// Parse a subscription URL and return a vector of proxies
///
/// # Arguments
/// * `url` - The subscription URL to parse
/// * `options` - Options for parsing
///
/// # Returns
/// * `Ok(Vec<Proxy>)` - The parsed proxies
/// * `Err(String)` - Error message if parsing fails
pub async fn parse_subscription(
    url: &str,
    options: ParseOptions,
    group_id: i32,
    request_headers: &Option<HashMap<String, String>>,
) -> Result<Vec<Proxy>, String> {
    // Create a new parse settings instance
    let mut parse_settings = ParseSettings::default();

    if let Some(headers) = request_headers {
        let mut i_request_headers = HashMap::new();
        for (key, value) in headers {
            i_request_headers.insert(CaseInsensitiveString::new(&key), value.clone());
        }
        parse_settings.request_header = Some(i_request_headers);
    }

    // Set options from the provided config
    if !options.include_remarks.is_empty() {
        parse_settings.include_remarks = Some(options.include_remarks.clone());
    }

    if !options.exclude_remarks.is_empty() {
        parse_settings.exclude_remarks = Some(options.exclude_remarks.clone());
    }

    parse_settings.authorized = options.authorized;

    // Create a vector to hold the nodes
    let mut nodes = Vec::new();

    // Call add_nodes to do the actual parsing
    // We use group_id = 0 since we don't care about it in this context
    add_nodes(url.to_string(), &mut nodes, group_id, &mut parse_settings).await?;

    Ok(nodes)
}

/// Process a subscription conversion request
pub async fn subconverter(config: SubconverterConfig) -> Result<SubconverterResult, String> {
    let mut response_headers = HashMap::new();
    let mut nodes = Vec::new();
    let global = Settings::current();

    info!(
        "Processing subscription conversion request to {}",
        config.target.to_str()
    );

    // Parse subscription URLs
    let opts = ParseOptions {
        include_remarks: config.include_remarks.clone(),
        exclude_remarks: config.exclude_remarks.clone(),
        authorized: config.authorized,
    };

    // Parse insert URLs first if needed
    let mut insert_nodes = Vec::new();
    if !config.insert_urls.is_empty() {
        let mut group_id = -1;
        info!("Fetching node data from insert URLs");
        for url in &config.insert_urls {
            debug!("Parsing insert URL: {}", url);
            match parse_subscription(url, opts.clone(), group_id, &config.request_headers).await {
                Ok(mut parsed_nodes) => {
                    info!("Found {} nodes from insert URL", parsed_nodes.len());
                    insert_nodes.append(&mut parsed_nodes);
                }
                Err(e) => {
                    warn!("Failed to parse insert URL '{}': {}", url, e);
                    if !global.skip_failed_links {
                        return Err(format!("Failed to parse insert URL '{}': {}", url, e));
                    }
                }
            }
            group_id += 1;
        }
    }

    let mut group_id = 0;
    // Parse main URLs
    info!("Fetching node data from main URLs");
    for url in &config.urls {
        debug!("Parsing URL: {}", url);
        match parse_subscription(url, opts.clone(), group_id, &config.request_headers).await {
            Ok(mut parsed_nodes) => {
                info!("Found {} nodes from URL", parsed_nodes.len());
                nodes.append(&mut parsed_nodes);
            }
            Err(e) => {
                error!("Failed to parse URL '{}': {}", url, e);
                if !global.skip_failed_links {
                    return Err(format!("Failed to parse URL '{}': {}", url, e));
                }
            }
        }
        group_id += 1;
    }

    // Exit if found nothing
    if nodes.is_empty() && insert_nodes.is_empty() {
        return Err("No nodes were found!".to_string());
    }

    // Merge insert nodes and main nodes
    if config.prepend_insert {
        // Prepend insert nodes
        info!(
            "Prepending {} insert nodes to {} main nodes",
            insert_nodes.len(),
            nodes.len()
        );
        let mut combined = insert_nodes;
        combined.append(&mut nodes);
        nodes = combined;
    } else {
        // Append insert nodes
        info!(
            "Appending {} insert nodes to {} main nodes",
            insert_nodes.len(),
            nodes.len()
        );
        nodes.append(&mut insert_nodes);
    }

    // Apply group name if specified
    if let Some(group_name) = &config.group_name {
        info!("Setting group name to '{}'", group_name);
        for node in &mut nodes {
            node.group = group_name.clone();
        }
    }

    // Apply filter script if available
    if let Some(_script) = &config.filter_script {
        info!("Applying filter script");
        if config.authorized {
            #[cfg(feature = "js_runtime")]
            {
                // Run filter script in JavaScript context
                // if let Some(runtime) = &config.extra.js_runtime {
                //     if let Some(context) = &config.extra.js_context {
                //         script_safe_runner(
                //             runtime,
                //             context,
                //             |ctx| match ctx.eval(script) {
                //                 Ok(_) => {
                //                     if let Ok(filter) =
                // ctx.eval::<quickjs::Function>("filter") {
                //                         nodes.retain(|node| {
                //                             match filter.call1(
                //                                 &quickjs::Value::Null,
                //
                // &quickjs::Value::from_serde(node).unwrap(),
                //                             ) {
                //                                 Ok(result) =>
                // result.as_bool().unwrap_or(false),
                //                                 Err(_) => false,
                //                             }
                //                         });
                //                     }
                //                 }
                //                 Err(e) => {
                //                     script_print_stack(ctx);
                //                 }
                //             },
                //             global.script_clean_context,
                //         );
                //     }
                // }
            }
            #[cfg(not(feature = "js_runtime"))]
            {
                warn!("JavaScript runtime feature not enabled, skipping filter script");
            }
        }
    }

    // Process nodes (rename, emoji, sort, etc.)
    preprocess_nodes(
        &mut nodes,
        &config.extra,
        &config.extra.rename_array,
        &config.extra.emoji_array,
    );

    // Pass subscription info if provided
    if let Some(sub_info) = &config.sub_info {
        response_headers.insert("Subscription-UserInfo".to_string(), sub_info.clone());
    }

    // Refresh rulesets if needed
    let mut ruleset_content = Vec::new();
    if config.extra.enable_rule_generator {
        // TODO: Check if we're using custom rulesets or global rulesets
        // if config.ruleset_configs == global.custom_rulesets {
        //     refresh_rulesets(&config.ruleset_configs, &mut
        // global.rulesets_content).await;     debug!("Using global ruleset
        // content");     // Use global ruleset content if it's the same
        // configuration     ruleset_content = global.rulesets_content.clone();

        // Refresh rulesets with custom configuration
        info!("Refreshing rulesets with custom configuration");
        refresh_rulesets(&config.ruleset_configs, &mut ruleset_content).await;

        // Prepend proxy direct ruleset if needed
        if global.prepend_proxy_direct_ruleset {
            prepend_proxy_direct_ruleset(&mut ruleset_content, &nodes);
        }
    }

    // Generate output based on target
    let output_content = match &config.target {
        SubconverterTarget::Clash => {
            info!("Generate target: Clash");
            let base = config
                .rule_bases
                .get_base_content(&SubconverterTarget::Clash, config.template_args.as_ref())
                .await;
            proxy_to_clash(
                &mut nodes,
                &base,
                &mut ruleset_content,
                &config.proxy_groups,
                false,
                &mut config.extra.clone(),
            )
        }
        SubconverterTarget::ClashR => {
            info!("Generate target: ClashR");
            let base = config
                .rule_bases
                .get_base_content(&SubconverterTarget::ClashR, config.template_args.as_ref())
                .await;
            proxy_to_clash(
                &mut nodes,
                &base,
                &mut ruleset_content,
                &config.proxy_groups,
                true,
                &mut config.extra.clone(),
            )
        }
        SubconverterTarget::Surge(ver) => {
            info!("Generate target: Surge {}", ver);
            let base = config
                .rule_bases
                .get_base_content(&config.target, config.template_args.as_ref())
                .await;
            let output = proxy_to_surge(
                &mut nodes,
                &base,
                &mut ruleset_content,
                &config.proxy_groups,
                *ver,
                &mut config.extra.clone(),
            )
            .await;

            // Add managed configuration header if needed
            if !config.managed_config_prefix.is_empty() && config.extra.enable_rule_generator {
                let managed_url = format!(
                    "{}sub?target=surge&ver={}&url={}",
                    config.managed_config_prefix,
                    ver,
                    // URL would need to be properly encoded
                    config.urls.join("|")
                );

                format!(
                    "#!MANAGED-CONFIG {} interval={} strict={}\n\n{}",
                    managed_url,
                    config.update_interval,
                    if config.update_strict {
                        "true"
                    } else {
                        "false"
                    },
                    output
                )
            } else {
                output
            }
        }
        SubconverterTarget::Surfboard => {
            info!("Generate target: Surfboard");
            let base = config
                .rule_bases
                .get_base_content(&config.target, config.template_args.as_ref())
                .await;
            let output = proxy_to_surge(
                &mut nodes,
                &base,
                &mut ruleset_content,
                &config.proxy_groups,
                -3, // Special version for Surfboard
                &mut config.extra.clone(),
            )
            .await;

            // Add managed configuration header if needed
            if !config.managed_config_prefix.is_empty() && config.extra.enable_rule_generator {
                let managed_url = format!(
                    "{}sub?target=surfboard&url={}",
                    config.managed_config_prefix,
                    // URL would need to be properly encoded
                    config.urls.join("|")
                );

                format!(
                    "#!MANAGED-CONFIG {} interval={} strict={}\n\n{}",
                    managed_url,
                    config.update_interval,
                    if config.update_strict {
                        "true"
                    } else {
                        "false"
                    },
                    output
                )
            } else {
                output
            }
        }
        SubconverterTarget::Mellow => {
            info!("Generate target: Mellow");
            let base = config
                .rule_bases
                .get_base_content(&config.target, config.template_args.as_ref())
                .await;
            proxy_to_mellow(
                &mut nodes,
                &base,
                &mut ruleset_content,
                &config.proxy_groups,
                &mut config.extra.clone(),
            )
            .await
        }
        SubconverterTarget::SSSub => {
            info!("Generate target: SS Subscription");
            let base = config
                .rule_bases
                .get_base_content(&config.target, config.template_args.as_ref())
                .await;
            proxy_to_ss_sub(&base, &mut nodes, &mut config.extra.clone())
        }
        SubconverterTarget::SS => {
            info!("Generate target: SS");
            proxy_to_single(&mut nodes, ProxyUriTypes::SS, &mut config.extra.clone())
        }
        SubconverterTarget::SSR => {
            info!("Generate target: SSR");
            proxy_to_single(
                &mut nodes,
                ProxyUriTypes::SSR | ProxyUriTypes::SS,
                &mut config.extra.clone(),
            )
        }
        SubconverterTarget::V2Ray => {
            info!("Generate target: V2Ray");
            proxy_to_single(&mut nodes, ProxyUriTypes::VMESS, &mut config.extra.clone())
        }
        SubconverterTarget::Trojan => {
            info!("Generate target: Trojan");
            proxy_to_single(&mut nodes, ProxyUriTypes::TROJAN, &mut config.extra.clone())
        }
        SubconverterTarget::Mixed => {
            info!("Generate target: Mixed");
            proxy_to_single(&mut nodes, ProxyUriTypes::MIXED, &mut config.extra.clone())
        }
        SubconverterTarget::Quantumult => {
            info!("Generate target: Quantumult");
            let base = config
                .rule_bases
                .get_base_content(&config.target, config.template_args.as_ref())
                .await;
            proxy_to_quan(
                &mut nodes,
                &base,
                &mut ruleset_content,
                &config.proxy_groups,
                &mut config.extra.clone(),
            )
            .await
        }
        SubconverterTarget::QuantumultX => {
            info!("Generate target: Quantumult X");
            let base = config
                .rule_bases
                .get_base_content(&config.target, config.template_args.as_ref())
                .await;
            proxy_to_quanx(
                &mut nodes,
                &base,
                &mut ruleset_content,
                &config.proxy_groups,
                &mut config.extra.clone(),
            )
            .await
        }
        SubconverterTarget::Loon => {
            info!("Generate target: Loon");
            let base = config
                .rule_bases
                .get_base_content(&config.target, config.template_args.as_ref())
                .await;
            proxy_to_loon(
                &mut nodes,
                &base,
                &mut ruleset_content,
                &config.proxy_groups,
                &mut config.extra.clone(),
            )
            .await
        }
        SubconverterTarget::SSD => {
            info!("Generate target: SSD");
            proxy_to_ssd(
                &mut nodes,
                &config.group_name.as_deref().unwrap_or(""),
                &config.sub_info.as_deref().unwrap_or(""),
                &mut config.extra.clone(),
            )
        }
        SubconverterTarget::SingBox => {
            info!("Generate target: SingBox");
            let base = config
                .rule_bases
                .get_base_content(&config.target, config.template_args.as_ref())
                .await;
            proxy_to_singbox(
                &mut nodes,
                &base,
                &mut ruleset_content,
                &config.proxy_groups,
                &mut config.extra.clone(),
            )
        }
        SubconverterTarget::Auto => {
            // When target is Auto, we should have decided on a specific target earlier
            // based on user agent If we still have Auto at this point, default
            // to Clash
            info!("Generate target: Auto (defaulting to Clash)");
            let base = config
                .rule_bases
                .get_base_content(&SubconverterTarget::Clash, config.template_args.as_ref())
                .await;
            proxy_to_clash(
                &mut nodes,
                &base,
                &mut ruleset_content,
                &config.proxy_groups,
                false,
                &mut config.extra.clone(),
            )
        }
    };

    // Set filename header if provided
    if let Some(filename) = &config.filename {
        response_headers.insert(
            "Content-Disposition".to_string(),
            format!("attachment; filename=\"{}\"; filename*=utf-8''", filename),
        );
    }

    // Upload result if needed
    if config.upload {
        // Determine arguments for upload_gist based on C++ logic
        let (gist_name, write_manage_url) = match &config.target {
            SubconverterTarget::Clash => ("clash".to_string(), false),
            SubconverterTarget::ClashR => ("clashr".to_string(), false),
            SubconverterTarget::Surge(ver) => {
                let name = format!("surge{}", ver);
                if config.extra.nodelist {
                    (format!("{}list", name), true)
                } else {
                    (name, true)
                }
            }
            SubconverterTarget::Surfboard => ("surfboard".to_string(), !config.extra.nodelist), /* Only true for config, not list */
            SubconverterTarget::Mellow => ("mellow".to_string(), !config.extra.nodelist), /* Only true for config, not list */
            SubconverterTarget::SSSub => ("sssub".to_string(), false),
            SubconverterTarget::SS => ("ss".to_string(), false),
            SubconverterTarget::SSR => ("ssr".to_string(), false),
            SubconverterTarget::V2Ray => ("v2ray".to_string(), false),
            SubconverterTarget::Trojan => ("trojan".to_string(), false),
            SubconverterTarget::Mixed => ("sub".to_string(), false), // Corresponds to "sub" in C++
            SubconverterTarget::Quantumult => ("quan".to_string(), false),
            SubconverterTarget::QuantumultX => ("quanx".to_string(), false),
            SubconverterTarget::Loon => ("loon".to_string(), false),
            SubconverterTarget::SSD => ("ssd".to_string(), false),
            SubconverterTarget::SingBox => ("singbox".to_string(), false),
            SubconverterTarget::Auto => ("clash".to_string(), false), /* Defaulting to clash like
                                                                       * the main logic */
        };

        // Use filename as path if provided, otherwise use the derived gist_name
        let gist_path = config.filename.clone().unwrap_or_else(|| gist_name.clone());

        info!(
            "Attempting to upload result to Gist: name='{}', path='{}', write_manage_url={}",
            gist_name, gist_path, write_manage_url
        );

        match crate::upload::gist::upload_gist(
            &gist_name,
            gist_path,
            output_content.clone(), // Clone content for upload
            write_manage_url,
        )
        .await
        {
            Ok(_) => info!("Successfully uploaded result to Gist."),
            Err(e) => warn!("Failed to upload result to Gist: {}", e),
        }
    }

    info!("Conversion completed");
    Ok(SubconverterResult {
        content: output_content,
        headers: response_headers,
    })
}

/// Preprocess nodes before conversion
pub fn preprocess_nodes(
    nodes: &mut Vec<Proxy>,
    extra: &ExtraSettings,
    rename_patterns: &Vec<RegexMatchConfig>,
    emoji_patterns: &Vec<RegexMatchConfig>,
) {
    // Call the implementation in utils/node_manip
    crate::utils::preprocess_nodes(nodes, extra, rename_patterns, emoji_patterns);
}

/// Prepend proxy direct ruleset to ruleset content
fn prepend_proxy_direct_ruleset(ruleset_content: &mut Vec<RulesetContent>, nodes: &[Proxy]) {
    use crate::models::ruleset::RulesetType;
    use crate::utils::network::{is_ipv4, is_ipv6};

    info!("Prepending proxy direct ruleset");

    // Create content for the ruleset
    for node in nodes {
        let mut content = String::new();
        if is_ipv6(&node.hostname) {
            content.push_str(&format!("IP-CIDR6,{}/128,no-resolve", node.hostname));
        } else if is_ipv4(&node.hostname) {
            content.push_str(&format!("IP-CIDR,{}/32,no-resolve", node.hostname));
        } else {
            content.push_str(&format!("DOMAIN,{}", node.hostname));
        }
        // Create the ruleset
        let mut ruleset = RulesetContent::new("", "DIRECT");
        ruleset.rule_type = RulesetType::Surge;
        ruleset.set_rule_content(&content);

        // Insert at the beginning
        ruleset_content.insert(0, ruleset);
    }
}

impl RuleBases {
    /// Load rule base content from files or URLs
    pub async fn load_content(&self) -> HashMap<SubconverterTarget, String> {
        let mut base_content = HashMap::new();

        let global = Settings::current();
        let proxy_config = parse_proxy(&global.proxy_config);

        // Helper function to load content from file or URL
        let load_content = async move |path: &str| -> Option<String> {
            if path.is_empty() {
                return None;
            }

            // Check if path is a URL
            if path.starts_with("http://") || path.starts_with("https://") {
                match web_get_async(path, &proxy_config, None).await {
                    Ok(response) => {
                        let content = response.body;
                        if content.is_empty() {
                            debug!("Empty content from URL: {}", path);
                            return None;
                        }
                        debug!("Loaded rule base from URL: {}", path);
                        Some(content)
                    }
                    Err(e) => {
                        debug!("Failed to load rule base from URL {}: {}", path, e);
                        None
                    }
                }
            } else {
                // Treat as file path
                match file_get_async(path, None).await {
                    Ok(content) => {
                        debug!("Loaded rule base from file: {}", path);
                        Some(content)
                    }
                    Err(e) => {
                        warn!("Failed to load rule base from file {}: {}", path, e);
                        None
                    }
                }
            }
        };

        // Load rule bases for each target format
        if let Some(content) = load_content(&self.clash_rule_base).await {
            base_content.insert(SubconverterTarget::Clash, content.clone());
            base_content.insert(SubconverterTarget::ClashR, content);
        }

        if let Some(content) = load_content(&self.surge_rule_base).await {
            base_content.insert(SubconverterTarget::Surge(3), content.clone());
            base_content.insert(SubconverterTarget::Surge(4), content);
        }

        if let Some(content) = load_content(&self.surfboard_rule_base).await {
            base_content.insert(SubconverterTarget::Surfboard, content);
        }

        if let Some(content) = load_content(&self.mellow_rule_base).await {
            base_content.insert(SubconverterTarget::Mellow, content);
        }

        if let Some(content) = load_content(&self.quan_rule_base).await {
            base_content.insert(SubconverterTarget::Quantumult, content);
        }

        if let Some(content) = load_content(&self.quanx_rule_base).await {
            base_content.insert(SubconverterTarget::QuantumultX, content);
        }

        if let Some(content) = load_content(&self.loon_rule_base).await {
            base_content.insert(SubconverterTarget::Loon, content);
        }

        if let Some(content) = load_content(&self.sssub_rule_base).await {
            base_content.insert(SubconverterTarget::SSSub, content);
        }

        if let Some(content) = load_content(&self.singbox_rule_base).await {
            base_content.insert(SubconverterTarget::SingBox, content);
        }

        base_content
    }

    /// Get base content for a specific target
    pub async fn get_base_content(
        &self,
        target: &SubconverterTarget,
        template_args: Option<&TemplateArgs>,
    ) -> String {
        let global = Settings::current();
        let proxy_config = parse_proxy(&global.proxy_config);

        // Helper function to load content from file or URL
        let load_content = async move |path: &str| -> String {
            if path.is_empty() {
                return String::new();
            }

            // Check if path is a URL
            if path.starts_with("http://") || path.starts_with("https://") {
                match web_get_async(path, &proxy_config, None).await {
                    Ok(response) => {
                        let content = response.body;
                        if content.is_empty() {
                            debug!("Empty content from URL: {}", path);
                            return String::new();
                        }
                        debug!("Loaded rule base from URL: {}", path);
                        content
                    }
                    Err(e) => {
                        warn!("Failed to load rule base from URL {}: {}", path, e);
                        String::new()
                    }
                }
            } else {
                // Treat as file path
                match file_get_async(path, None).await {
                    Ok(content) => {
                        debug!("Loaded rule base from file: {}", path);
                        content
                    }
                    Err(e) => {
                        warn!("Failed to load rule base from file {}: {}", path, e);
                        String::new()
                    }
                }
            }
        };

        // Get path based on target
        let path = match target {
            SubconverterTarget::Clash | SubconverterTarget::ClashR => &self.clash_rule_base,
            SubconverterTarget::Surge(_) => &self.surge_rule_base,
            SubconverterTarget::Surfboard => &self.surfboard_rule_base,
            SubconverterTarget::Mellow => &self.mellow_rule_base,
            SubconverterTarget::Quantumult => &self.quan_rule_base,
            SubconverterTarget::QuantumultX => &self.quanx_rule_base,
            SubconverterTarget::Loon => &self.loon_rule_base,
            SubconverterTarget::SSSub => &self.sssub_rule_base,
            SubconverterTarget::SingBox => &self.singbox_rule_base,
            _ => return String::new(),
        };

        // Load the base content
        let content = load_content(path).await;
        if content.is_empty() {
            return content;
        }

        // Apply template if template args are provided
        if let Some(args) = template_args {
            // Using template rendering
            info!("Applying template to rule base for {}", target.to_str());
            match crate::template::render_template(&content, args, &global.template_path) {
                Ok(rendered) => {
                    debug!("Successfully rendered template for rule base");
                    rendered
                }
                Err(e) => {
                    warn!("Failed to render template for rule base: {}", e);
                    content // Return original content if rendering fails
                }
            }
        } else {
            content
        }
    }

    /// Check and update rule bases with external configuration paths
    ///
    /// This method checks if paths from external configuration are valid
    /// (either links or existing files) and updates the corresponding rule
    /// bases.
    pub async fn check_external_bases(
        &mut self,
        ext_conf: &crate::settings::external::ExternalSettings,
        base_path: &str,
    ) {
        Self::check_external_base(
            &ext_conf.clash_rule_base,
            &mut self.clash_rule_base,
            base_path,
        )
        .await;
        Self::check_external_base(
            &ext_conf.surge_rule_base,
            &mut self.surge_rule_base,
            base_path,
        )
        .await;
        Self::check_external_base(
            &ext_conf.surfboard_rule_base,
            &mut self.surfboard_rule_base,
            base_path,
        )
        .await;
        Self::check_external_base(
            &ext_conf.mellow_rule_base,
            &mut self.mellow_rule_base,
            base_path,
        )
        .await;
        Self::check_external_base(
            &ext_conf.quan_rule_base,
            &mut self.quan_rule_base,
            base_path,
        )
        .await;
        Self::check_external_base(
            &ext_conf.quanx_rule_base,
            &mut self.quanx_rule_base,
            base_path,
        )
        .await;
        Self::check_external_base(
            &ext_conf.loon_rule_base,
            &mut self.loon_rule_base,
            base_path,
        )
        .await;
        Self::check_external_base(
            &ext_conf.sssub_rule_base,
            &mut self.sssub_rule_base,
            base_path,
        )
        .await;
        Self::check_external_base(
            &ext_conf.singbox_rule_base,
            &mut self.singbox_rule_base,
            base_path,
        )
        .await;
    }

    /// Check if a path is a link or exists in the base path and update the
    /// destination if valid
    async fn check_external_base(path: &str, dest: &mut String, base_path: &str) -> bool {
        if crate::utils::is_link(path)
            || (crate::utils::starts_with(path, base_path) && crate::utils::file_exists(path).await)
        {
            *dest = path.to_string();
            true
        } else {
            false
        }
    }
}
