use base64::{
    engine::{general_purpose, DecodePaddingMode},
    Engine as _,
};

/// Encodes a string to Base64 format.
pub fn base64_encode(input: &str) -> String {
    general_purpose::STANDARD.encode(input)
}

/// Decodes a Base64 string to its original form.
///
/// # Arguments
/// * `input` - The Base64 encoded string.
/// * `accept_urlsafe` - A boolean indicating whether to accept URL-safe Base64 encoding.
///
/// # Returns
/// The decoded string, or an empty string if the input is invalid.
fn base64_decode(input: &str, accept_urlsafe: bool) -> Option<String> {
    let purpose_config = general_purpose::GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent);
    let engine = general_purpose::GeneralPurpose::new(
        if accept_urlsafe {
            &base64::alphabet::URL_SAFE
        } else {
            &base64::alphabet::STANDARD
        },
        purpose_config,
    );
    match engine.decode(input) {
        Ok(decoded) => Some(String::from_utf8_lossy(&decoded).to_string()),
        Err(e) => {
            log::error!("Failed to decode base64: {}", e);
            None
        } // Handle invalid Base64 input
    }
}

/// Reverses a URL-safe Base64 string to standard Base64 format.
fn url_safe_base64_reverse(input: &str) -> String {
    input.replace('-', "+").replace('_', "/")
}

/// Converts a Base64 string to URL-safe Base64 format by replacing specific characters.
fn url_safe_base64_apply(input: &str) -> String {
    input.replace('+', "-").replace('/', "_").replace('=', "") // Remove padding
}

/// Decodes a URL-safe Base64 string to its original form.
pub fn url_safe_base64_decode(input: &str) -> String {
    match base64_decode(&url_safe_base64_reverse(input), false) {
        Some(decoded) => decoded,
        None => input.to_string(),
    }
}

/// Encodes a string to URL-safe Base64 format.
pub fn url_safe_base64_encode(input: &str) -> String {
    url_safe_base64_apply(&base64_encode(input))
}
