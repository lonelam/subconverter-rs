use crate::utils::system::get_system_proxy;
use case_insensitive_string::CaseInsensitiveString;
use std::collections::HashMap;
use std::error::Error as StdError;

use js_sys::{Array, Object};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

// Import our JavaScript binding functions
#[wasm_bindgen(module = "/js/kv_bindings.js")]
extern "C" {
    #[wasm_bindgen(js_name = "wasm_fetch_with_request")]
    fn js_wasm_fetch_with_request(url: &str, options: &JsValue) -> js_sys::Promise;

    #[wasm_bindgen(js_name = "response_headers")]
    fn js_response_headers(response: &JsValue) -> js_sys::Promise;

    #[wasm_bindgen(js_name = "response_text")]
    fn js_response_text(response: &JsValue) -> js_sys::Promise;

    #[wasm_bindgen(js_name = "response_status")]
    fn js_response_status(response: &JsValue) -> js_sys::Promise;
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub proxy: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig { proxy: None }
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
    _proxy_config: &ProxyConfig,
    headers: Option<&HashMap<CaseInsensitiveString, String>>,
) -> Result<HttpResponse, HttpError> {
    // In WASM environment, we use the fetch API
    // Note: Proxy configuration is not supported in WASM environment
    #[allow(unused_mut)]
    let mut opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    // Try getting window object to determine environment
    let window_available = web_sys::window().is_some();

    if window_available {
        // Browser environment - use standard web_sys approach
        // Create request object
        let request = match Request::new_with_str_and_init(url, &opts) {
            Ok(req) => req,
            Err(e) => {
                return Err(HttpError {
                    message: format!("Failed to create request: {:?}", e),
                    status: None,
                })
            }
        };

        // Add headers if specified
        if let Some(custom_headers) = headers {
            let headers_obj = request.headers();

            for (key, value) in custom_headers {
                if let Err(e) = headers_obj.set(key.to_string().as_str(), value) {
                    return Err(HttpError {
                        message: format!("Failed to set header {}: {:?}", key, e),
                        status: None,
                    });
                }
            }
        }

        // Get window object
        let window = web_sys::window().unwrap();

        // Fetch the request
        let resp_promise = window.fetch_with_request(&request);

        // Wait for the response
        let resp_value = match JsFuture::from(resp_promise).await {
            Ok(val) => val,
            Err(e) => {
                return Err(HttpError {
                    message: format!("Failed to get response: {:?}", e),
                    status: None,
                })
            }
        };

        // Convert to Response object
        let response: Response = match resp_value.dyn_into() {
            Ok(resp) => resp,
            Err(_) => {
                return Err(HttpError {
                    message: "Failed to convert response".to_string(),
                    status: None,
                })
            }
        };

        // Get response status
        let status = response.status();

        // Get response headers
        let mut resp_headers = HashMap::new();
        let headers = response.headers();
        let js_headers: Object = headers.into();
        let entries = Object::entries(&js_headers);
        let entries_array: Array = entries.into();
        for i in 0..entries_array.length() {
            let entry = entries_array.get(i);
            let entry_array: Array = entry.into();
            let key = entry_array.get(0);
            let value = entry_array.get(1);
            if let (Some(key_str), Some(value_str)) = (key.as_string(), value.as_string()) {
                resp_headers.insert(key_str, value_str);
            }
        }

        // Get response body as text, even if it's an error response
        let text_promise = match response.text() {
            Ok(p) => p,
            Err(e) => {
                return Err(HttpError {
                    message: format!("Failed to get response text: {:?}", e),
                    status: Some(status),
                })
            }
        };

        let text_value = match JsFuture::from(text_promise).await {
            Ok(val) => val,
            Err(e) => {
                return Err(HttpError {
                    message: format!("Failed to read response body: {:?}", e),
                    status: Some(status),
                })
            }
        };

        let body = match text_value.as_string() {
            Some(s) => s,
            None => {
                return Err(HttpError {
                    message: "Failed to convert response to string".to_string(),
                    status: Some(status),
                })
            }
        };

        // Return the full HttpResponse regardless of status code
        Ok(HttpResponse {
            status,
            body,
            headers: resp_headers,
        })
    } else {
        // Node.js environment - use our JS bindings
        // Create JS object for request options
        let request_options = Object::new();
        js_sys::Reflect::set(
            &request_options,
            &JsValue::from_str("method"),
            &JsValue::from_str("GET"),
        )
        .unwrap();

        // Add headers if specified
        if let Some(custom_headers) = headers {
            let headers_obj = Object::new();

            for (key, value) in custom_headers {
                js_sys::Reflect::set(
                    &headers_obj,
                    &JsValue::from_str(key.to_string().as_str()),
                    &JsValue::from_str(value),
                )
                .unwrap();
            }

            js_sys::Reflect::set(
                &request_options,
                &JsValue::from_str("headers"),
                &headers_obj,
            )
            .unwrap();
        }

        // Make fetch request using our JS binding
        let resp_promise = js_wasm_fetch_with_request(url, &request_options);

        // Wait for the response
        let resp_value = match JsFuture::from(resp_promise).await {
            Ok(val) => val,
            Err(e) => {
                return Err(HttpError {
                    message: format!("Failed to get response: {:?}", e),
                    status: None,
                })
            }
        };

        // Get response status
        let status_promise = js_response_status(&resp_value);
        let status_value = match JsFuture::from(status_promise).await {
            Ok(val) => val,
            Err(e) => {
                return Err(HttpError {
                    message: format!("Failed to get response status: {:?}", e),
                    status: None,
                })
            }
        };

        let status = match status_value.as_f64() {
            Some(s) => s as u16,
            None => {
                return Err(HttpError {
                    message: "Failed to convert status to number".to_string(),
                    status: None,
                })
            }
        };

        // Get response headers
        let headers_promise = js_response_headers(&resp_value);
        let headers_value = match JsFuture::from(headers_promise).await {
            Ok(val) => val,
            Err(e) => {
                return Err(HttpError {
                    message: format!("Failed to get response headers: {:?}", e),
                    status: Some(status),
                })
            }
        };

        let mut resp_headers = HashMap::new();
        let headers_obj: Object = headers_value.dyn_into().unwrap_or_else(|_| Object::new());
        let entries = Object::entries(&headers_obj);
        let entries_array: Array = entries.into();
        for i in 0..entries_array.length() {
            let entry = entries_array.get(i);
            let entry_array: Array = entry.into();
            let key = entry_array.get(0);
            let value = entry_array.get(1);
            if let (Some(key_str), Some(value_str)) = (key.as_string(), value.as_string()) {
                resp_headers.insert(key_str, value_str);
            }
        }

        // Get response body as text
        let text_promise = js_response_text(&resp_value);
        let text_value = match JsFuture::from(text_promise).await {
            Ok(val) => val,
            Err(e) => {
                return Err(HttpError {
                    message: format!("Failed to read response body: {:?}", e),
                    status: Some(status),
                })
            }
        };

        let body = match text_value.as_string() {
            Some(s) => s,
            None => {
                return Err(HttpError {
                    message: "Failed to convert response to string".to_string(),
                    status: Some(status),
                })
            }
        };

        // Return the full HttpResponse regardless of status code
        Ok(HttpResponse {
            status,
            body,
            headers: resp_headers,
        })
    }
}

/// Synchronous version of web_get_async that uses tokio runtime to run the
/// async function
///
/// This function is provided for compatibility with the existing codebase.
pub fn web_get(
    _url: &str,
    _proxy_config: &ProxyConfig,
    _headers: Option<&HashMap<CaseInsensitiveString, String>>,
) -> Result<HttpResponse, HttpError> {
    // In WASM environment, we can't block and wait for async operations
    // Users should use web_get_async directly
    Err(HttpError {
        message: "在WASM环境中，请直接使用web_get_async函数而不是web_get".to_string(),
        status: None,
    })
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

/// Makes an HTTP POST request to the specified URL (WASM environment)
///
/// # Arguments
/// * `url` - The URL to request
/// * `data` - The request body data
/// * `_proxy_config` - Proxy configuration (ignored in WASM)
/// * `headers` - Optional custom headers
///
/// # Returns
/// * `Ok(HttpResponse)` - The response with status, body, and headers
/// * `Err(HttpError)` - Error details if the request failed
pub async fn web_post_async(
    url: &str,
    data: String,
    _proxy_config: &ProxyConfig,
    headers: Option<&HashMap<CaseInsensitiveString, String>>,
) -> Result<HttpResponse, HttpError> {
    let mut opts = RequestInit::new();
    opts.set_method("POST");
    opts.set_mode(RequestMode::Cors);
    opts.set_body(Some(&JsValue::from_str(&data)));

    // Create headers object
    let request_headers = web_sys::Headers::new().map_err(|e| HttpError {
        message: format!("Failed to create headers: {:?}", e),
        status: None,
    })?;
    request_headers
        .set("Content-Type", "application/json")
        .map_err(|e| HttpError {
            message: format!("Failed to set Content-Type header: {:?}", e),
            status: None,
        })?;

    // Add custom headers
    if let Some(custom_headers) = headers {
        for (key, value) in custom_headers {
            request_headers
                .set(key.to_string().as_str(), value)
                .map_err(|e| HttpError {
                    message: format!("Failed to set header {}: {:?}", key, e),
                    status: None,
                })?;
        }
    }
    opts.set_headers(Some(&request_headers));

    // Try getting window object to determine environment
    let window_available = web_sys::window().is_some();

    if window_available {
        // Browser environment
        let request = Request::new_with_str_and_init(url, &opts).map_err(|e| HttpError {
            message: format!("Failed to create POST request: {:?}", e),
            status: None,
        })?;

        let window = web_sys::window().unwrap();
        let resp_promise = window.fetch_with_request(&request);
        let resp_value = JsFuture::from(resp_promise).await.map_err(|e| HttpError {
            message: format!("Failed to get POST response: {:?}", e),
            status: None,
        })?;

        let response: Response = resp_value.dyn_into().map_err(|_| HttpError {
            message: "Failed to convert POST response".to_string(),
            status: None,
        })?;

        let status = response.status();

        // Get response headers
        let mut resp_headers = HashMap::new();
        let headers = response.headers();
        let js_headers: Object = headers.into();
        let entries = Object::entries(&js_headers);
        let entries_array: Array = entries.into();
        for i in 0..entries_array.length() {
            let entry = entries_array.get(i);
            let entry_array: Array = entry.into();
            let key = entry_array.get(0);
            let value = entry_array.get(1);
            if let (Some(key_str), Some(value_str)) = (key.as_string(), value.as_string()) {
                resp_headers.insert(key_str, value_str);
            }
        }

        let text_promise = response.text().map_err(|e| HttpError {
            message: format!("Failed to get POST response text: {:?}", e),
            status: Some(status),
        })?;

        let text_value = JsFuture::from(text_promise).await.map_err(|e| HttpError {
            message: format!("Failed to read POST response body: {:?}", e),
            status: Some(status),
        })?;

        let body = text_value.as_string().ok_or_else(|| HttpError {
            message: "Failed to convert POST response to string".to_string(),
            status: Some(status),
        })?;

        Ok(HttpResponse {
            status,
            body,
            headers: resp_headers,
        })
    } else {
        // Node.js environment - use JS bindings
        let request_options = Object::new();
        js_sys::Reflect::set(
            &request_options,
            &JsValue::from_str("method"),
            &JsValue::from_str("POST"),
        )
        .unwrap();
        js_sys::Reflect::set(
            &request_options,
            &JsValue::from_str("body"),
            &JsValue::from_str(&data),
        )
        .unwrap();

        let headers_obj = Object::new();
        js_sys::Reflect::set(
            &headers_obj,
            &JsValue::from_str("Content-Type"),
            &JsValue::from_str("application/json"),
        )
        .unwrap();
        if let Some(custom_headers) = headers {
            for (key, value) in custom_headers {
                js_sys::Reflect::set(
                    &headers_obj,
                    &JsValue::from_str(key.to_string().as_str()),
                    &JsValue::from_str(value),
                )
                .unwrap();
            }
        }
        js_sys::Reflect::set(
            &request_options,
            &JsValue::from_str("headers"),
            &headers_obj,
        )
        .unwrap();

        let resp_promise = js_wasm_fetch_with_request(url, &request_options);
        let resp_value = JsFuture::from(resp_promise).await.map_err(|e| HttpError {
            message: format!("Failed to get POST response: {:?}", e),
            status: None,
        })?;

        let status_promise = js_response_status(&resp_value);
        let status_value = JsFuture::from(status_promise)
            .await
            .map_err(|e| HttpError {
                message: format!("Failed to get POST response status: {:?}", e),
                status: None,
            })?;
        let status = status_value
            .as_f64()
            .map(|s| s as u16)
            .ok_or_else(|| HttpError {
                message: "Failed to convert POST status to number".to_string(),
                status: None,
            })?;

        let headers_promise = js_response_headers(&resp_value);
        let headers_value = JsFuture::from(headers_promise)
            .await
            .map_err(|e| HttpError {
                message: format!("Failed to get POST response headers: {:?}", e),
                status: Some(status),
            })?;
        let mut resp_headers = HashMap::new();
        let headers_obj: Object = headers_value.dyn_into().unwrap_or_else(|_| Object::new());
        let entries = Object::entries(&headers_obj);
        let entries_array: Array = entries.into();
        for i in 0..entries_array.length() {
            let entry = entries_array.get(i);
            let entry_array: Array = entry.into();
            let key = entry_array.get(0);
            let value = entry_array.get(1);
            if let (Some(key_str), Some(value_str)) = (key.as_string(), value.as_string()) {
                resp_headers.insert(key_str, value_str);
            }
        }

        let text_promise = js_response_text(&resp_value);
        let text_value = JsFuture::from(text_promise).await.map_err(|e| HttpError {
            message: format!("Failed to read POST response body: {:?}", e),
            status: Some(status),
        })?;
        let body = text_value.as_string().ok_or_else(|| HttpError {
            message: "Failed to convert POST response to string".to_string(),
            status: Some(status),
        })?;

        Ok(HttpResponse {
            status,
            body,
            headers: resp_headers,
        })
    }
}

/// Makes an HTTP PATCH request to the specified URL (WASM environment)
///
/// # Arguments
/// * `url` - The URL to request
/// * `data` - The request body data
/// * `_proxy_config` - Proxy configuration (ignored in WASM)
/// * `headers` - Optional custom headers
///
/// # Returns
/// * `Ok(HttpResponse)` - The response with status, body, and headers
/// * `Err(HttpError)` - Error details if the request failed
pub async fn web_patch_async(
    url: &str,
    data: String,
    _proxy_config: &ProxyConfig,
    headers: Option<&HashMap<CaseInsensitiveString, String>>,
) -> Result<HttpResponse, HttpError> {
    let mut opts = RequestInit::new();
    opts.set_method("PATCH");
    opts.set_mode(RequestMode::Cors);
    opts.set_body(Some(&JsValue::from_str(&data)));

    // Create headers object
    let request_headers = web_sys::Headers::new().map_err(|e| HttpError {
        message: format!("Failed to create headers: {:?}", e),
        status: None,
    })?;
    request_headers
        .set("Content-Type", "application/json")
        .map_err(|e| HttpError {
            message: format!("Failed to set Content-Type header: {:?}", e),
            status: None,
        })?;

    // Add custom headers
    if let Some(custom_headers) = headers {
        for (key, value) in custom_headers {
            request_headers
                .set(key.to_string().as_str(), value)
                .map_err(|e| HttpError {
                    message: format!("Failed to set header {}: {:?}", key, e),
                    status: None,
                })?;
        }
    }
    opts.set_headers(Some(&request_headers));

    // Try getting window object to determine environment
    let window_available = web_sys::window().is_some();

    if window_available {
        // Browser environment
        let request = Request::new_with_str_and_init(url, &opts).map_err(|e| HttpError {
            message: format!("Failed to create PATCH request: {:?}", e),
            status: None,
        })?;

        let window = web_sys::window().unwrap();
        let resp_promise = window.fetch_with_request(&request);
        let resp_value = JsFuture::from(resp_promise).await.map_err(|e| HttpError {
            message: format!("Failed to get PATCH response: {:?}", e),
            status: None,
        })?;

        let response: Response = resp_value.dyn_into().map_err(|_| HttpError {
            message: "Failed to convert PATCH response".to_string(),
            status: None,
        })?;

        let status = response.status();

        // Get response headers
        let mut resp_headers = HashMap::new();
        let headers = response.headers();
        let js_headers: Object = headers.into();
        let entries = Object::entries(&js_headers);
        let entries_array: Array = entries.into();
        for i in 0..entries_array.length() {
            let entry = entries_array.get(i);
            let entry_array: Array = entry.into();
            let key = entry_array.get(0);
            let value = entry_array.get(1);
            if let (Some(key_str), Some(value_str)) = (key.as_string(), value.as_string()) {
                resp_headers.insert(key_str, value_str);
            }
        }

        let text_promise = response.text().map_err(|e| HttpError {
            message: format!("Failed to get PATCH response text: {:?}", e),
            status: Some(status),
        })?;

        let text_value = JsFuture::from(text_promise).await.map_err(|e| HttpError {
            message: format!("Failed to read PATCH response body: {:?}", e),
            status: Some(status),
        })?;

        let body = text_value.as_string().ok_or_else(|| HttpError {
            message: "Failed to convert PATCH response to string".to_string(),
            status: Some(status),
        })?;

        Ok(HttpResponse {
            status,
            body,
            headers: resp_headers,
        })
    } else {
        // Node.js environment - use JS bindings
        let request_options = Object::new();
        js_sys::Reflect::set(
            &request_options,
            &JsValue::from_str("method"),
            &JsValue::from_str("PATCH"),
        )
        .unwrap();
        js_sys::Reflect::set(
            &request_options,
            &JsValue::from_str("body"),
            &JsValue::from_str(&data),
        )
        .unwrap();

        let headers_obj = Object::new();
        js_sys::Reflect::set(
            &headers_obj,
            &JsValue::from_str("Content-Type"),
            &JsValue::from_str("application/json"),
        )
        .unwrap();
        if let Some(custom_headers) = headers {
            for (key, value) in custom_headers {
                js_sys::Reflect::set(
                    &headers_obj,
                    &JsValue::from_str(key.to_string().as_str()),
                    &JsValue::from_str(value),
                )
                .unwrap();
            }
        }
        js_sys::Reflect::set(
            &request_options,
            &JsValue::from_str("headers"),
            &headers_obj,
        )
        .unwrap();

        let resp_promise = js_wasm_fetch_with_request(url, &request_options);
        let resp_value = JsFuture::from(resp_promise).await.map_err(|e| HttpError {
            message: format!("Failed to get PATCH response: {:?}", e),
            status: None,
        })?;

        let status_promise = js_response_status(&resp_value);
        let status_value = JsFuture::from(status_promise)
            .await
            .map_err(|e| HttpError {
                message: format!("Failed to get PATCH response status: {:?}", e),
                status: None,
            })?;
        let status = status_value
            .as_f64()
            .map(|s| s as u16)
            .ok_or_else(|| HttpError {
                message: "Failed to convert PATCH status to number".to_string(),
                status: None,
            })?;

        let headers_promise = js_response_headers(&resp_value);
        let headers_value = JsFuture::from(headers_promise)
            .await
            .map_err(|e| HttpError {
                message: format!("Failed to get PATCH response headers: {:?}", e),
                status: Some(status),
            })?;
        let mut resp_headers = HashMap::new();
        let headers_obj: Object = headers_value.dyn_into().unwrap_or_else(|_| Object::new());
        let entries = Object::entries(&headers_obj);
        let entries_array: Array = entries.into();
        for i in 0..entries_array.length() {
            let entry = entries_array.get(i);
            let entry_array: Array = entry.into();
            let key = entry_array.get(0);
            let value = entry_array.get(1);
            if let (Some(key_str), Some(value_str)) = (key.as_string(), value.as_string()) {
                resp_headers.insert(key_str, value_str);
            }
        }

        let text_promise = js_response_text(&resp_value);
        let text_value = JsFuture::from(text_promise).await.map_err(|e| HttpError {
            message: format!("Failed to read PATCH response body: {:?}", e),
            status: Some(status),
        })?;
        let body = text_value.as_string().ok_or_else(|| HttpError {
            message: "Failed to convert PATCH response to string".to_string(),
            status: Some(status),
        })?;

        Ok(HttpResponse {
            status,
            body,
            headers: resp_headers,
        })
    }
}
