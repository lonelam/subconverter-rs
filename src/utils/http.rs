use case_insensitive_string::CaseInsensitiveString;
use std::collections::HashMap;

// Import platform-specific implementations
#[cfg(not(target_arch = "wasm32"))]
mod platform {
    pub use crate::utils::http_std::{
        get_sub_info_from_header, get_sub_info_from_response, parse_proxy, web_get, web_get_async,
        ProxyConfig,
    };
}

#[cfg(target_arch = "wasm32")]
mod platform {
    pub use crate::utils::http_wasm::{
        get_sub_info_from_header, get_sub_info_from_response, parse_proxy, web_get, web_get_async,
        ProxyConfig,
    };
}

// Re-export platform-specific implementations
pub use platform::*;

/// Asynchronous function that returns only the body content if status is 2xx,
/// otherwise treats as error
/// This provides backward compatibility with code expecting only successful
/// responses
pub async fn web_get_content_async(
    url: &str,
    proxy_config: &ProxyConfig,
    headers: Option<&HashMap<CaseInsensitiveString, String>>,
) -> Result<String, String> {
    match web_get_async(url, proxy_config, headers).await {
        Ok(response) => {
            if (200..300).contains(&response.status) {
                Ok(response.body)
            } else {
                Err(format!("HTTP error {}: {}", response.status, response.body))
            }
        }
        Err(e) => Err(e.message),
    }
}

/// Extract subscription info from HTTP headers
///
/// # Arguments
/// * `headers` - HTTP response headers
///
/// # Returns
/// * Subscription info string with key-value pairs
pub fn get_sub_info_from_header(headers: &HashMap<String, String>) -> String {
    let mut sub_info = String::new();

    // Extract upload and download
    let mut upload: u64 = 0;
    let mut download: u64 = 0;
    let mut total: u64 = 0;
    let mut expire: String = String::new();

    // Look for subscription-userinfo header
    if let Some(userinfo) = headers.get("subscription-userinfo") {
        for info_item in userinfo.split(';') {
            let info_item = info_item.trim();
            if info_item.starts_with("upload=") {
                if let Ok(value) = info_item[7..].parse::<u64>() {
                    upload = value;
                }
            } else if info_item.starts_with("download=") {
                if let Ok(value) = info_item[9..].parse::<u64>() {
                    download = value;
                }
            } else if info_item.starts_with("total=") {
                if let Ok(value) = info_item[6..].parse::<u64>() {
                    total = value;
                }
            } else if info_item.starts_with("expire=") {
                expire = info_item[7..].to_string();
            }
        }
    }

    // Add traffic info
    if upload > 0 || download > 0 {
        sub_info.push_str(&format!("upload={}, download={}", upload, download));
    }

    // Add total traffic
    if total > 0 {
        if !sub_info.is_empty() {
            sub_info.push_str(", ");
        }
        sub_info.push_str(&format!("total={}", total));
    }

    // Add expiry info
    if !expire.is_empty() {
        if !sub_info.is_empty() {
            sub_info.push_str(", ");
        }
        sub_info.push_str(&format!("expire={}", expire));
    }

    sub_info
}

/// Get subscription info from response headers with additional formatting
///
/// # Arguments
/// * `headers` - HTTP response headers
/// * `sub_info` - Mutable string to append info to
///
/// # Returns
/// * `true` if info was extracted, `false` otherwise
pub fn get_sub_info_from_response(
    headers: &HashMap<String, String>,
    sub_info: &mut String,
) -> bool {
    let header_info = get_sub_info_from_header(headers);
    if !header_info.is_empty() {
        if !sub_info.is_empty() {
            sub_info.push_str(", ");
        }
        sub_info.push_str(&header_info);
        true
    } else {
        false
    }
}
