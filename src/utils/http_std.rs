use crate::utils::system::get_system_proxy;
use awc::Client;
use case_insensitive_string::CaseInsensitiveString;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::time::Duration;
/// Default timeout for HTTP requests in seconds
const DEFAULT_TIMEOUT: u64 = 15;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub proxy: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig { proxy: None }
    }
}

/// HTTP response structure
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code
    pub status: u16,
    /// Response body
    pub body: String,
    /// Response headers
    pub headers: HashMap<String, String>,
}

/// HTTP error structure
#[derive(Debug, Clone)]
pub struct HttpError {
    /// Error message
    pub message: String,
    /// Optional status code if available
    pub status: Option<u16>,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(status) = self.status {
            write!(f, "HTTP error {}: {}", status, self.message)
        } else {
            write!(f, "HTTP error: {}", self.message)
        }
    }
}

impl StdError for HttpError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        None
    }
}

pub fn parse_proxy(proxy_str: &str) -> ProxyConfig {
    if proxy_str == "SYSTEM" {
        return ProxyConfig {
            proxy: Some(get_system_proxy()),
        };
    } else if proxy_str == "NONE" {
        return ProxyConfig { proxy: None };
    } else if !proxy_str.is_empty() {
        return ProxyConfig {
            proxy: Some(proxy_str.to_string()),
        };
    }
    ProxyConfig { proxy: None }
}

/// Makes an HTTP request to the specified URL
///
/// # Arguments
/// * `url` - The URL to request
/// * `proxy_str` - Optional proxy string (e.g., "http://127.0.0.1:8080")
/// * `headers` - Optional custom headers
///
/// # Returns
/// * `Ok(HttpResponse)` - The response with status, body, and headers
/// * `Err(HttpError)` - Error details if the request failed
pub async fn web_get_async(
    url: &str,
    proxy_config: &ProxyConfig,
    headers: Option<&HashMap<CaseInsensitiveString, String>>,
) -> Result<HttpResponse, HttpError> {
    // Build client with proxy if specified

    let mut client_builder = Client::builder().timeout(Duration::from_secs(DEFAULT_TIMEOUT));

    // if let Some(proxy) = &proxy_config.proxy {
    //     if !proxy.is_empty() {
    //         match Proxy::all(proxy) {
    //             Ok(proxy) => {
    //                 client_builder = client_builder.proxy(proxy);
    //             }
    //             Err(e) => {
    //                 return Err(HttpError {
    //                     message: format!("Failed to set proxy: {}", e),
    //                     status: None,
    //                 });
    //             }
    //         }
    //     }
    // }

    let client = client_builder.finish();

    // Build request with headers if specified
    let mut client_request = client
        .get(url)
        .insert_header(("User-Agent", "subconverter-rs"));
    if let Some(custom_headers) = headers {
        for (key, value) in custom_headers {
            client_request = client_request.insert_header((key.to_string(), value.to_string()));
        }
    }

    // Send request and get response
    let mut response = match client_request.send().await {
        Ok(resp) => resp,
        Err(e) => {
            return Err(HttpError {
                message: format!("Failed to send request: {}", e),
                status: None,
            });
        }
    };

    // Get status and headers before attempting to read the body
    let status = response.status().as_u16();

    // Get response headers
    let mut resp_headers = HashMap::new();
    for (key, value) in response.headers() {
        if let Ok(v) = value.to_str() {
            resp_headers.insert(key.to_string(), v.to_string());
        }
    }

    // Get response body, even for error responses
    match response.body().await {
        Ok(body) => Ok(HttpResponse {
            status,
            body: String::from_utf8(body.to_vec()).unwrap(),
            headers: resp_headers,
        }),
        Err(e) => Err(HttpError {
            message: format!("Failed to read response body: {}", e),
            status: Some(status),
        }),
    }
}

/// Synchronous version of web_get_async that uses tokio runtime to run the
/// async function
///
/// This function is provided for compatibility with the existing codebase.
pub fn web_get(
    url: &str,
    proxy_config: &ProxyConfig,
    headers: Option<&HashMap<CaseInsensitiveString, String>>,
) -> Result<HttpResponse, HttpError> {
    // Create a tokio runtime for running the async function
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            return Err(HttpError {
                message: format!("Failed to create tokio runtime: {}", e),
                status: None,
            });
        }
    };

    // Run the async function in the runtime
    rt.block_on(web_get_async(url, proxy_config, headers))
}

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

/// Makes an HTTP POST request to the specified URL
///
/// # Arguments
/// * `url` - The URL to request
/// * `data` - The request body data
/// * `proxy_config` - Proxy configuration
/// * `headers` - Optional custom headers
///
/// # Returns
/// * `Ok(HttpResponse)` - The response with status, body, and headers
/// * `Err(HttpError)` - Error details if the request failed
pub async fn web_post_async(
    url: &str,
    data: String,
    proxy_config: &ProxyConfig,
    headers: Option<&HashMap<CaseInsensitiveString, String>>,
) -> Result<HttpResponse, HttpError> {
    let mut client_builder = Client::builder().timeout(Duration::from_secs(DEFAULT_TIMEOUT));

    // TODO: Implement proxy support for awc if needed, similar to commented-out
    // code in web_get_async if let Some(proxy) = &proxy_config.proxy {
    //     if !proxy.is_empty() { ... }
    // }

    let client = client_builder.finish();

    let mut client_request = client
        .post(url)
        .insert_header(("Content-Type", "application/json")); // Assume JSON for POST/PATCH

    if let Some(custom_headers) = headers {
        for (key, value) in custom_headers {
            client_request = client_request.insert_header((key.to_string(), value.to_string()));
        }
    }

    // Send request with body
    let mut response = match client_request.send_body(data).await {
        Ok(resp) => resp,
        Err(e) => {
            return Err(HttpError {
                message: format!("Failed to send POST request: {}", e),
                status: None,
            });
        }
    };

    let status = response.status().as_u16();

    let mut resp_headers = HashMap::new();
    for (key, value) in response.headers() {
        if let Ok(v) = value.to_str() {
            resp_headers.insert(key.to_string(), v.to_string());
        }
    }

    match response.body().limit(10_000_000).await {
        // Limit body size (e.g., 10MB)
        Ok(body) => Ok(HttpResponse {
            status,
            body: String::from_utf8(body.to_vec())
                .unwrap_or_else(|_| "Invalid UTF-8 body".to_string()),
            headers: resp_headers,
        }),
        Err(e) => Err(HttpError {
            message: format!("Failed to read POST response body: {}", e),
            status: Some(status),
        }),
    }
}

/// Makes an HTTP PATCH request to the specified URL
///
/// # Arguments
/// * `url` - The URL to request
/// * `data` - The request body data
/// * `proxy_config` - Proxy configuration
/// * `headers` - Optional custom headers
///
/// # Returns
/// * `Ok(HttpResponse)` - The response with status, body, and headers
/// * `Err(HttpError)` - Error details if the request failed
pub async fn web_patch_async(
    url: &str,
    data: String,
    proxy_config: &ProxyConfig,
    headers: Option<&HashMap<CaseInsensitiveString, String>>,
) -> Result<HttpResponse, HttpError> {
    let mut client_builder = Client::builder().timeout(Duration::from_secs(DEFAULT_TIMEOUT));

    // TODO: Implement proxy support for awc if needed

    let client = client_builder.finish();

    let mut client_request = client
        .patch(url)
        .insert_header(("Content-Type", "application/json")); // Assume JSON

    if let Some(custom_headers) = headers {
        for (key, value) in custom_headers {
            client_request = client_request.insert_header((key.to_string(), value.to_string()));
        }
    }

    // Send request with body
    let mut response = match client_request.send_body(data).await {
        Ok(resp) => resp,
        Err(e) => {
            return Err(HttpError {
                message: format!("Failed to send PATCH request: {}", e),
                status: None,
            });
        }
    };

    let status = response.status().as_u16();

    let mut resp_headers = HashMap::new();
    for (key, value) in response.headers() {
        if let Ok(v) = value.to_str() {
            resp_headers.insert(key.to_string(), v.to_string());
        }
    }

    match response.body().limit(10_000_000).await {
        // Limit body size
        Ok(body) => Ok(HttpResponse {
            status,
            body: String::from_utf8(body.to_vec())
                .unwrap_or_else(|_| "Invalid UTF-8 body".to_string()),
            headers: resp_headers,
        }),
        Err(e) => Err(HttpError {
            message: format!("Failed to read PATCH response body: {}", e),
            status: Some(status),
        }),
    }
}
