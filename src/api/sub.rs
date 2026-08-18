use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::constants::regex_black_list::REGEX_BLACK_LIST;
use crate::interfaces::subconverter::{subconverter, SubconverterConfigBuilder, UploadStatus};
use crate::models::ruleset::RulesetConfigs;
use crate::models::{ProxyGroupConfigs, RegexMatchConfigs, SubconverterTarget};
use crate::settings::external::ExternalSettings;
use crate::settings::settings::init_settings;
use crate::settings::{refresh_configuration, FromIni, FromIniWithDelimiter};
use crate::utils::reg_valid;
use crate::{RuleBases, Settings, TemplateArgs};

#[cfg(target_arch = "wasm32")]
use {js_sys::Promise, wasm_bindgen::prelude::*, wasm_bindgen_futures::future_to_promise};

fn default_ver() -> u32 {
    3
}

// START Helper function for deserializing boolean-like values
mod bool_deserializer {
    use serde::{self, Deserialize, Deserializer};

    pub fn deserialize_option_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum BoolOrString {
            Bool(bool),
            String(String),
            Int(i64),
        }

        match Option::<BoolOrString>::deserialize(deserializer)? {
            Some(BoolOrString::Bool(b)) => Ok(Some(b)),
            Some(BoolOrString::Int(i)) => match i {
                0 => Ok(Some(false)),
                1 => Ok(Some(true)),
                _ => Ok(None), /* Or return an error: Err(serde::de::Error::custom("invalid
                                * integer for bool")) */
            },
            Some(BoolOrString::String(s)) => match s.to_lowercase().as_str() {
                "true" | "yes" | "1" | "on" => Ok(Some(true)),
                "false" | "no" | "0" | "off" => Ok(Some(false)),
                _ => Ok(None), /* Or return an error:
                                * Err(serde::de::Error::custom(format!("invalid string for bool:
                                * {}", s))) */
            },
            None => Ok(None),
        }
    }
}

/// Helper module for numeric query parameters that may arrive as strings
/// (e.g. when the query is forwarded as JSON by the WASM/serverless wrapper).
mod number_deserializer {
    use serde::{self, Deserialize, Deserializer};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumberOrString {
        Number(u64),
        String(String),
    }

    pub fn deserialize_option_u32<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<NumberOrString>::deserialize(deserializer)? {
            Some(NumberOrString::Number(n)) => Ok(Some(n as u32)),
            Some(NumberOrString::String(s)) => {
                if s.is_empty() {
                    Ok(None)
                } else {
                    s.trim().parse::<u32>().map(Some).map_err(|_| {
                        serde::de::Error::custom(format!("invalid number: {}", s))
                    })
                }
            }
            None => Ok(None),
        }
    }

    pub fn deserialize_u32_with_default<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(deserialize_option_u32(deserializer)?.unwrap_or_else(super::default_ver))
    }
}
// END Helper function

/// Query parameters for subscription conversion
#[derive(Deserialize, Serialize, Debug, Default, Clone)]
pub struct SubconverterQuery {
    /// Target format
    pub target: Option<String>,
    /// Surge version number
    #[serde(
        default = "default_ver",
        deserialize_with = "number_deserializer::deserialize_u32_with_default"
    )]
    pub ver: u32,
    /// Clash new field name
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub new_name: Option<bool>,
    /// URLs to convert (pipe separated)
    pub url: Option<String>,
    /// Custom group name
    pub group: Option<String>,
    /// Upload path (optional)
    pub upload_path: Option<String>,
    /// Include remarks regex, multiple regexes separated by '|'
    pub include: Option<String>,
    /// Exclude remarks regex, multiple regexes separated by '|'
    pub exclude: Option<String>,
    /// custom groups
    pub groups: Option<String>,
    /// Ruleset contents
    pub ruleset: Option<String>,
    /// External configuration file (optional)
    pub config: Option<String>,

    /// Device ID (for device-specific configurations)
    pub dev_id: Option<String>,
    /// Whether to insert nodes
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub insert: Option<bool>,
    /// Whether to prepend insert nodes
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub prepend: Option<bool>,
    /// Custom filename for download
    pub filename: Option<String>,
    /// Append proxy type to remarks
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub append_type: Option<bool>,
    /// Whether to remove old emoji and add new emoji
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub emoji: Option<bool>,
    /// Whether to add emoji
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub add_emoji: Option<bool>,
    /// Whether to remove emoji
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub remove_emoji: Option<bool>,
    /// List mode (node list only)
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub list: Option<bool>,
    /// Sort nodes
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub sort: Option<bool>,

    /// Sort Script
    pub sort_script: Option<String>,

    /// argFilterDeprecated
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub fdn: Option<bool>,

    /// Information for filtering, rename, emoji addition
    pub rename: Option<String>,
    /// Whether to enable TCP Fast Open
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub tfo: Option<bool>,
    /// Whether to enable UDP
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub udp: Option<bool>,
    /// Whether to skip certificate verification
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub scv: Option<bool>,
    /// Whether to enable TLS 1.3
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub tls13: Option<bool>,
    /// Enable rule generator
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub rename_node: Option<bool>,
    /// Update interval in seconds
    #[serde(
        default,
        deserialize_with = "number_deserializer::deserialize_option_u32"
    )]
    pub interval: Option<u32>,
    /// Update strict mode
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub strict: Option<bool>,
    /// Upload to gist
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub upload: Option<bool>,
    /// Authentication token
    pub token: Option<String>,
    /// Filter script
    pub filter: Option<String>,

    /// Clash script
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub script: Option<bool>,
    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub classic: Option<bool>,

    #[serde(
        default,
        deserialize_with = "bool_deserializer::deserialize_option_bool"
    )]
    pub expand: Option<bool>,

    /// Singbox specific parameters
    #[serde(default)]
    pub singbox: HashMap<String, String>,

    /// Request headers
    pub request_headers: Option<HashMap<String, String>>,
}

/// Parse a query string into a HashMap
pub fn parse_query_string(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if let Some(key) = parts.next() {
            let value = parts.next().unwrap_or("");
            params.insert(key.to_string(), value.to_string());
        }
    }
    params
}

/// Struct to represent a subscription process response
#[derive(Debug, Serialize)]
pub struct SubResponse {
    pub content: String,
    pub content_type: String,
    pub headers: HashMap<String, String>,
    pub status_code: u16,
    #[serde(skip_serializing_if = "is_not_attempted")] // Don't include if upload wasn't attempted
    pub upload_status: UploadStatus,
}

// Helper function for skip_serializing_if
fn is_not_attempted(status: &UploadStatus) -> bool {
    matches!(status, UploadStatus::NotAttempted)
}

impl SubResponse {
    pub fn ok(content: String, content_type: String) -> Self {
        Self {
            content,
            content_type,
            headers: HashMap::new(),
            status_code: 200,
            upload_status: UploadStatus::NotAttempted, // Default to not attempted
        }
    }

    pub fn error(content: String, status_code: u16) -> Self {
        Self {
            content,
            content_type: "text/plain".to_string(),
            headers: HashMap::new(),
            status_code,
            upload_status: UploadStatus::NotAttempted, // Default to not attempted
        }
    }

    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_upload_status(mut self, status: UploadStatus) -> Self {
        self.upload_status = status;
        self
    }
}

/// Handler for subscription conversion
pub async fn sub_process(
    req_url: Option<String>,
    query: SubconverterQuery,
) -> Result<SubResponse, Box<dyn std::error::Error>> {
    let mut global = Settings::current();

    // not initialized, in wasm that's common for cold start.
    if global.pref_path.is_empty() {
        debug!("Global config not initialized, reloading");
        init_settings("").await?;
        global = Settings::current();
    } else if global.reload_conf_on_request && !global.api_mode && !global.generator_mode {
        refresh_configuration().await;
        global = Settings::current();
    }

    // Start building configuration
    let mut builder = SubconverterConfigBuilder::new();

    let target;
    if let Some(_target) = &query.target {
        match SubconverterTarget::from_str(&_target) {
            Some(_target) => {
                target = _target.clone();
                if _target == SubconverterTarget::Auto {
                    // TODO: Check user agent and set target accordingly
                    // if let Some(user_agent) = req.headers().get("User-Agent") {
                    //     if let Ok(user_agent) = user_agent.to_str() {

                    //         // match_user_agent(
                    //         //     user_agent,
                    //         //     &target,
                    //         //      query.new_name,
                    //         //      &query.ver);
                    //     }
                    // }
                    return Ok(SubResponse::error(
                        "Auto user agent is not supported for now.".to_string(),
                        400,
                    ));
                }
                builder.target(_target);
            }
            None => {
                return Ok(SubResponse::error(
                    "Invalid target parameter".to_string(),
                    400,
                ));
            }
        }
    } else {
        return Ok(SubResponse::error(
            "Missing target parameter".to_string(),
            400,
        ));
    }

    builder.update_interval(match query.interval {
        Some(interval) => interval,
        None => global.update_interval,
    });
    // Check if we should authorize the request. Outside API mode every
    // request is authorized; in API mode a matching access token is required.
    // (This must not depend on the js-runtime feature — see issue #46: it
    // also gates local-file access for insert_url/default_url, issue #48.)
    let authorized =
        !global.api_mode || query.token.as_deref().unwrap_or_default() == global.api_access_token;
    builder.authorized(authorized);
    builder.update_strict(query.strict.unwrap_or(global.update_strict));

    if query
        .include
        .clone()
        .is_some_and(|include| REGEX_BLACK_LIST.contains(&include))
        || query
            .exclude
            .clone()
            .is_some_and(|exclude| REGEX_BLACK_LIST.contains(&exclude))
    {
        return Ok(SubResponse::error(
            "Invalid regex in request!".to_string(),
            400,
        ));
    }

    let enable_insert = match query.insert {
        Some(insert) => insert,
        None => global.enable_insert,
    };

    if enable_insert {
        builder.insert_urls(global.insert_urls.clone());
        // 加在前面还是加在后面
        builder.prepend_insert(query.prepend.unwrap_or(global.prepend_insert));
    }

    let urls = match query.url.as_deref() {
        Some(query_url) => query_url.split('|').map(|s| s.to_owned()).collect(),
        None => {
            if authorized {
                global.default_urls.clone()
            } else {
                vec![]
            }
        }
    };
    builder.urls(urls);

    // TODO: what if urls still empty after insert?

    // Create template args from request parameters and other settings
    let mut template_args = TemplateArgs::default();
    template_args.global_vars = global.template_vars.clone();

    template_args.request_params = query.clone();

    builder.append_proxy_type(query.append_type.unwrap_or(global.append_type));

    let mut arg_expand_rulesets = query.expand;
    if target.is_clash() && query.script.is_none() {
        arg_expand_rulesets = Some(true);
    }

    // flags
    builder.tfo(query.tfo.or(global.tfo_flag));
    builder.udp(query.udp.or(global.udp_flag));
    builder.skip_cert_verify(query.scv.or(global.skip_cert_verify));
    builder.tls13(query.tls13.or(global.tls13_flag));
    builder.sort(query.sort.unwrap_or(global.enable_sort));
    builder.sort_script(query.sort_script.unwrap_or(global.sort_script.clone()));

    builder.filter_deprecated(query.fdn.unwrap_or(global.filter_deprecated));
    builder.clash_new_field_name(query.new_name.unwrap_or(global.clash_use_new_field));
    builder.clash_script(query.script.unwrap_or_default());
    builder.clash_classical_ruleset(query.classic.unwrap_or_default());
    let nodelist = query.list.unwrap_or_default();
    builder.nodelist(nodelist);

    if arg_expand_rulesets != Some(true) {
        builder.clash_new_field_name(true);
    } else {
        builder.managed_config_prefix(global.managed_config_prefix.clone());
        builder.clash_script(false);
    }

    let mut ruleset_configs = global.custom_rulesets.clone();
    let mut custom_group_configs = global.custom_proxy_groups.clone();

    // 这部分参数有优先级：query > external > global
    builder.include_remarks(global.include_remarks.clone());
    builder.exclude_remarks(global.exclude_remarks.clone());
    builder.rename_array(global.renames.clone());
    builder.emoji_array(global.emojis.clone());
    builder.add_emoji(global.add_emoji);
    builder.remove_emoji(global.remove_emoji);
    builder.enable_rule_generator(global.enable_rule_gen);
    let mut rule_bases = RuleBases {
        clash_rule_base: global.clash_base.clone(),
        surge_rule_base: global.surge_base.clone(),
        surfboard_rule_base: global.surfboard_base.clone(),
        mellow_rule_base: global.mellow_base.clone(),
        quan_rule_base: global.quan_base.clone(),
        quanx_rule_base: global.quanx_base.clone(),
        loon_rule_base: global.loon_base.clone(),
        sssub_rule_base: global.ssub_base.clone(),
        singbox_rule_base: global.singbox_base.clone(),
    };
    builder.rule_bases(rule_bases.clone());
    builder.template_args(template_args.clone());

    let ext_config = match query.config.as_deref() {
        Some(config) => config.to_owned(),
        None => global.default_ext_config.clone(),
    };
    if !ext_config.is_empty() {
        debug!("Loading external config from {}", ext_config);

        // In WebAssembly environment, we can't use std::thread::spawn
        // Instead, we use the async version directly
        let extconf_result = ExternalSettings::load_from_file(&ext_config).await;

        match extconf_result {
            Ok(extconf) => {
                debug!("Successfully loaded external config from {}", ext_config);
                if !nodelist {
                    rule_bases
                        .check_external_bases(&extconf, &global.base_path)
                        .await;
                    builder.rule_bases(rule_bases);

                    if let Some(tpl_args) = extconf.tpl_args {
                        template_args.local_vars = tpl_args;
                    }

                    builder.template_args(template_args);

                    if !target.is_simple() {
                        if !extconf.custom_rulesets.is_empty() {
                            ruleset_configs = extconf.custom_rulesets;
                        }
                        if !extconf.custom_proxy_groups.is_empty() {
                            custom_group_configs = extconf.custom_proxy_groups;
                        }
                        if let Some(enable_rule_gen) = extconf.enable_rule_generator {
                            builder.enable_rule_generator(enable_rule_gen);
                        }
                        if let Some(overwrite_original_rules) = extconf.overwrite_original_rules {
                            builder.overwrite_original_rules(overwrite_original_rules);
                        }
                    }
                }
                if !extconf.rename_nodes.is_empty() {
                    builder.rename_array(extconf.rename_nodes);
                }
                if !extconf.emojis.is_empty() {
                    builder.emoji_array(extconf.emojis);
                }
                if !extconf.include_remarks.is_empty() {
                    builder.include_remarks(extconf.include_remarks);
                }
                if !extconf.exclude_remarks.is_empty() {
                    builder.exclude_remarks(extconf.exclude_remarks);
                }
                if extconf.add_emoji.is_some() {
                    builder.add_emoji(extconf.add_emoji.unwrap());
                }
                if extconf.remove_old_emoji.is_some() {
                    builder.remove_emoji(extconf.remove_old_emoji.unwrap());
                }
            }
            Err(e) => {
                error!("Failed to load external config from {}: {}", ext_config, e);
            }
        }
    }

    // 请求参数的覆盖优先级最高
    if let Some(include) = query.include.as_deref() {
        if reg_valid(&include) {
            builder.include_remarks(vec![include.to_owned()]);
        }
    }
    if let Some(exclude) = query.exclude.as_deref() {
        if reg_valid(&exclude) {
            builder.exclude_remarks(vec![exclude.to_owned()]);
        }
    }
    if let Some(emoji) = query.emoji {
        builder.add_emoji(emoji);
        builder.remove_emoji(true);
    }

    if let Some(add_emoji) = query.add_emoji {
        builder.add_emoji(add_emoji);
    }
    if let Some(remove_emoji) = query.remove_emoji {
        builder.remove_emoji(remove_emoji);
    }
    if let Some(rename) = query.rename.as_deref() {
        if !rename.is_empty() {
            let v_array: Vec<String> = rename.split('`').map(|s| s.to_string()).collect();
            builder.rename_array(RegexMatchConfigs::from_ini_with_delimiter(&v_array, "@"));
        }
    }

    if !target.is_simple() {
        // loading custom groups
        if !query
            .groups
            .as_deref()
            .is_none_or(|groups| groups.is_empty())
            && !nodelist
        {
            if let Some(groups) = query.groups.as_deref() {
                let v_array: Vec<String> = groups.split('@').map(|s| s.to_string()).collect();
                custom_group_configs = ProxyGroupConfigs::from_ini(&v_array);
            }
        }
        // loading custom rulesets
        if !query
            .ruleset
            .as_deref()
            .is_none_or(|ruleset| ruleset.is_empty())
            && !nodelist
        {
            if let Some(ruleset) = query.ruleset.as_deref() {
                let v_array: Vec<String> = ruleset.split('@').map(|s| s.to_string()).collect();
                ruleset_configs = RulesetConfigs::from_ini(&v_array);
            }
        }
    }
    builder.proxy_groups(custom_group_configs);
    builder.ruleset_configs(ruleset_configs);

    // TODO: process with the script runtime

    // parse settings

    // Process group name
    builder.group_name(query.group.clone());
    builder.filename(query.filename.clone());
    builder.upload(query.upload.unwrap_or_default());

    // Process filter script
    let filter = query.filter.unwrap_or(global.filter_script.clone());
    if !filter.is_empty() {
        builder.filter_script(Some(filter));
    }

    // // Process device ID
    // if let Some(dev_id) = &query.dev_id {
    //     builder.device_id(Some(dev_id.clone()));
    // }

    // // Set managed config prefix from global settings
    // if !global.managed_config_prefix.is_empty() {
    //     builder =
    // builder.managed_config_prefix(global.managed_config_prefix.clone()); }

    if let Some(request_headers) = &query.request_headers {
        builder.request_headers(request_headers.clone());
    }

    // Build and validate configuration
    let config = match builder.build() {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to build subconverter config: {}", e);
            return Ok(SubResponse::error(
                format!("Configuration error: {}", e),
                400,
            ));
        }
    };

    // Run subconverter directly instead of spawning a thread
    // This is necessary for WebAssembly compatibility
    debug!("Running subconverter with config: {:?}", config);
    let subconverter_result = subconverter(config).await;

    match subconverter_result {
        Ok(result) => {
            // Determine content type based on target
            let content_type = match target {
                SubconverterTarget::Clash
                | SubconverterTarget::ClashR
                | SubconverterTarget::SingBox => "application/yaml",
                SubconverterTarget::SSSub | SubconverterTarget::SSD => "application/json",
                _ => "text/plain",
            };

            debug!("Subconverter completed successfully");
            Ok(SubResponse::ok(result.content, content_type.to_string())
                .with_headers(result.headers)
                .with_upload_status(result.upload_status))
        }
        Err(e) => {
            error!("Subconverter error: {}", e);
            Ok(SubResponse::error(format!("Conversion error: {}", e), 500))
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn sub_process_wasm(query_json: &str) -> Promise {
    // Parse the query from JSON
    let query = match serde_json::from_str::<SubconverterQuery>(query_json) {
        Ok(q) => q,
        Err(e) => {
            return Promise::reject(&JsValue::from_str(&format!("Failed to parse query: {}", e)));
        }
    };

    let query_json_string = Some(query_json.to_string());
    // Create a future for the async sub_process
    let future = async move {
        match sub_process(None, query).await {
            Ok(response) => {
                // Convert the SubResponse to JSON string
                match serde_json::to_string(&response) {
                    Ok(json) => Ok(JsValue::from_str(&json)),
                    Err(e) => Err(JsValue::from_str(&format!(
                        "Failed to serialize response: {}",
                        e
                    ))),
                }
            }
            Err(e) => Err(JsValue::from_str(&format!(
                "Subscription processing error: {}",
                e
            ))),
        }
    };

    // Convert the future to a JavaScript Promise
    future_to_promise(future)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn init_settings_wasm(pref_path: &str) -> Promise {
    let pref_path = pref_path.to_string();
    let future = async move {
        match init_settings(&pref_path).await {
            Ok(_) => Ok(JsValue::from_bool(true)),
            Err(e) => Err(JsValue::from_str(&format!(
                "Failed to initialize settings: {}",
                e
            ))),
        }
    };

    future_to_promise(future)
}

#[cfg(test)]
mod tests {
    use super::SubconverterQuery;

    /// Reproduces https://github.com/lonelam/subconverter-rs/issues/43 and
    /// https://github.com/lonelam/subconverter-rs/issues/32 — query values
    /// forwarded as JSON strings must still parse.
    #[test]
    fn test_query_accepts_string_numbers_and_bools() {
        let json = r#"{"target":"clash","url":"https://example.com/sub","interval":"180","ver":"4","list":"1","udp":"1","remove_emoji":"1"}"#;
        let query: SubconverterQuery = serde_json::from_str(json).expect("query must parse");
        assert_eq!(query.interval, Some(180));
        assert_eq!(query.ver, 4);
        assert_eq!(query.list, Some(true));
        assert_eq!(query.udp, Some(true));
        assert_eq!(query.remove_emoji, Some(true));
    }

    #[test]
    fn test_query_accepts_native_types() {
        let json = r#"{"target":"clash","interval":180,"ver":4,"list":true}"#;
        let query: SubconverterQuery = serde_json::from_str(json).expect("query must parse");
        assert_eq!(query.interval, Some(180));
        assert_eq!(query.ver, 4);
        assert_eq!(query.list, Some(true));
    }
}
