use super::common::ClashCommon;
use crate::models::proxy_node::combined::CombinedProxy;
use crate::models::proxy_node::shadowsocks::ShadowsocksProxy;
use crate::models::{Proxy, ProxyType};
use crate::utils::is_empty_option_string;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Shadowsocks proxy in a Clash configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashShadowsocks {
    #[serde(flatten)]
    pub common: ClashCommon,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub cipher: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_string")]
    pub plugin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_opts: Option<BTreeMap<String, serde_yaml::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_over_tcp: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_over_tcp_version: Option<u8>,
}

fn yaml_value_to_string(value: &serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

impl ClashShadowsocks {
    pub fn into_proxy(self) -> Proxy {
        let mut proxy = Proxy::default();
        proxy.proxy_type = ProxyType::Shadowsocks;
        self.common.apply_to_proxy(&mut proxy);

        // Normalize the clash plugin naming to the internal one
        let plugin = self.plugin.filter(|p| !p.is_empty()).map(|p| {
            if p == "obfs" {
                "obfs-local".to_string()
            } else {
                p
            }
        });

        // Convert the plugin-opts mapping into the internal
        // `key=value;key2=value2` option string. The obfs plugin family uses
        // obfs/obfs-host keys internally; v2ray-plugin keeps mode/host/path
        // with boolean flags written bare ("tls") or as mux=4.
        let is_obfs = matches!(plugin.as_deref(), Some("obfs-local") | Some("simple-obfs"));
        let plugin_opts = self.plugin_opts.filter(|_| plugin.is_some()).map(|opts| {
            let mut parts: Vec<String> = Vec::new();
            let mut ordered: Vec<(String, serde_yaml::Value)> = opts.into_iter().collect();
            ordered.sort_by(|a, b| a.0.cmp(&b.0));
            for (key, value) in ordered {
                let key = if is_obfs {
                    match key.as_str() {
                        "mode" => "obfs".to_string(),
                        "host" => "obfs-host".to_string(),
                        other => other.to_string(),
                    }
                } else {
                    key
                };
                match value {
                    serde_yaml::Value::Bool(true) if key == "mux" => {
                        parts.push("mux=4".to_string())
                    }
                    serde_yaml::Value::Bool(true) => parts.push(key),
                    serde_yaml::Value::Bool(false) => {}
                    other => {
                        let value = yaml_value_to_string(&other);
                        if !value.is_empty() {
                            parts.push(format!("{}={}", key, value));
                        }
                    }
                }
            }
            parts.join(";")
        });

        proxy.combined_proxy = Some(CombinedProxy::Shadowsocks(ShadowsocksProxy {
            password: self.password.unwrap_or_default(),
            cipher: self.cipher.unwrap_or_default(),
            plugin,
            plugin_opts: plugin_opts.filter(|o| !o.is_empty()),
            udp_over_tcp: self.udp_over_tcp,
            udp_over_tcp_version: self.udp_over_tcp_version,
        }));

        proxy
    }
}

impl From<&Proxy> for ClashShadowsocks {
    fn from(proxy: &Proxy) -> Self {
        let mut out = ClashShadowsocks::default();
        out.common = ClashCommon::from_proxy(proxy);

        if let Some(ss) = proxy.as_shadowsocks() {
            out.cipher = Some(ss.cipher.clone());
            out.password = Some(ss.password.clone());

            // Clash expects `obfs`, not `obfs-local`/`simple-obfs`
            let plugin = ss.plugin.clone().filter(|p| !p.is_empty()).map(|p| {
                if p == "obfs-local" || p == "simple-obfs" {
                    "obfs".to_string()
                } else {
                    p
                }
            });

            // Only emit plugin-opts when a plugin is actually configured;
            // an empty `plugin-opts: {}` breaks some Clash clients.
            if let Some(plugin_opts) = ss.plugin_opts.clone().filter(|_| plugin.is_some()) {
                let mut opts: BTreeMap<String, serde_yaml::Value> = BTreeMap::new();

                for opt in plugin_opts.split(';') {
                    let opt = opt.trim();
                    if opt.is_empty() {
                        continue;
                    }
                    let mut parts = opt.splitn(2, '=');
                    let key = parts.next().unwrap_or_default().trim();
                    if key.is_empty() {
                        continue;
                    }
                    // Strip the "obfs" prefix used by the ss plugin option syntax
                    let key = match key {
                        "obfs" => "mode",
                        "obfs-host" => "host",
                        other => other,
                    };
                    let value = match parts.next() {
                        // Bare flags such as `tls` mean "enabled"
                        None => serde_yaml::Value::Bool(true),
                        Some(v) => match v.trim() {
                            "true" => serde_yaml::Value::Bool(true),
                            "false" => serde_yaml::Value::Bool(false),
                            // Clash expects `mux` to be a boolean; the ss plugin
                            // option syntax uses a connection count
                            v if key == "mux" => serde_yaml::Value::Bool(v != "0"),
                            v => serde_yaml::Value::String(v.to_string()),
                        },
                    };
                    opts.insert(key.to_string(), value);
                }

                if !opts.is_empty() {
                    out.plugin_opts = Some(opts);
                }
            }

            out.plugin = plugin;
            out.udp_over_tcp = ss.udp_over_tcp;
            out.udp_over_tcp_version = ss.udp_over_tcp_version;
        }

        out
    }
}
