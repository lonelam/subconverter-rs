use crate::settings::Settings;
use crate::utils::file::file_exists;
use crate::utils::http::{parse_proxy, ProxyConfig};
use crate::utils::http_std::{web_patch_async, web_post_async, HttpError, HttpResponse};
use crate::utils::ini_reader::{IniReader, IniReaderError};
use case_insensitive_string::CaseInsensitiveString;
use serde_json::json;
use std::collections::HashMap;
use std::env;

/// Builds the JSON payload for creating or updating a Gist.
fn build_gist_data(name: &str, content: &str) -> String {
    json!({
        "description": "subconverter",
        "public": false,
        "files": {
            name: {
                "content": content
            }
        }
    })
    .to_string()
}

/// Uploads content to a GitHub Gist based on configuration in gistconf.ini.
///
/// # Arguments
/// * `name` - The logical name of the content (used for looking up path in
///   ini).
/// * `path` - The desired filename within the Gist. If empty, defaults to
///   `name` or value from ini.
/// * `content` - The content to upload.
/// * `write_manage_url` - Whether to prepend a #!MANAGED-CONFIG line if
///   updating an existing Gist.
///
/// # Returns
/// * `Ok(())` on success.
/// * `Err(String)` on failure, containing an error message.
pub async fn upload_gist(
    name: &str,
    mut path: String,
    mut content: String,
    write_manage_url: bool,
) -> Result<(), String> {
    let ini_path = "gistconf.ini";

    if !file_exists(ini_path).await {
        log::error!("gistconf.ini not found. Skipping...");
        return Err("gistconf.ini not found".to_string());
    }

    let mut ini = IniReader::new();
    if let Err(e) = ini.parse_file(ini_path) {
        let err_msg = format!("Failed to parse gistconf.ini: {}", e);
        log::error!("{}", err_msg);
        return Err(err_msg);
    }

    if ini.enter_section("common").is_err() {
        log::error!("gistconf.ini has incorrect format ([common] section missing). Skipping...");
        return Err("gistconf.ini has incorrect format".to_string());
    }

    let mut token = ini.get_current("token");
    if token.is_empty() {
        log::info!(
            "Token not found in gistconf.ini, checking GITHUB_TOKEN environment variable..."
        );
        match env::var("GITHUB_TOKEN") {
            Ok(env_token) if !env_token.is_empty() => {
                token = env_token;
            }
            _ => {
                log::error!(
                    "No token provided in gistconf.ini or GITHUB_TOKEN environment variable. Skipping..."
                );
                return Err("No token provided".to_string());
            }
        }
    }

    let mut id = ini.get_current("id");
    let mut username = ini.get_current("username");

    if path.is_empty() {
        let path_from_common = ini.get_current(name);
        if !path_from_common.is_empty() {
            path = path_from_common;
        } else {
            path = name.to_string();
        }
    }

    let proxy_config = parse_proxy(&Settings::current().proxy_config);
    let mut headers = HashMap::new();
    headers.insert(
        CaseInsensitiveString::new("Authorization"),
        format!("token {}", token),
    );
    headers.insert(
        CaseInsensitiveString::new("Accept"),
        "application/vnd.github.v3+json".to_string(),
    );
    headers.insert(
        CaseInsensitiveString::new("User-Agent"),
        "subconverter-rs".to_string(),
    ); // Good practice

    let mut final_url = String::new(); // To store the raw URL after creation/update
    let response: HttpResponse;

    if id.is_empty() {
        log::info!("No Gist id is provided. Creating new Gist...");
        let gist_data = build_gist_data(&path, &content);
        let api_url = "https://api.github.com/gists";

        match web_post_async(api_url, gist_data, &proxy_config, Some(&headers)).await {
            Ok(resp) => {
                response = resp;
                if response.status != 201 {
                    let err_msg = format!(
                        "Create new Gist failed!\nReturn code: {}\nReturn data:\n{}",
                        response.status, response.body
                    );
                    log::error!("{}", err_msg);
                    return Err("Failed to create Gist".to_string());
                }
            }
            Err(e) => {
                let err_msg = format!("Create new Gist HTTP request failed: {}", e);
                log::error!("{}", err_msg);
                return Err(err_msg);
            }
        }
    } else {
        log::info!("Gist id provided. Modifying Gist...");
        let base_url = format!(
            "https://gist.githubusercontent.com/{}/{}/raw/{}",
            username, id, path
        );

        if write_manage_url {
            content = format!("#!MANAGED-CONFIG {}\n{}", base_url, content);
        }

        let gist_data = build_gist_data(&path, &content);
        let api_url = format!("https://api.github.com/gists/{}", id);

        match web_patch_async(&api_url, gist_data, &proxy_config, Some(&headers)).await {
            Ok(resp) => {
                response = resp;
                if response.status != 200 {
                    let err_msg = format!(
                        "Modify Gist failed!\nReturn code: {}\nReturn data:\n{}",
                        response.status, response.body
                    );
                    log::error!("{}", err_msg);
                    return Err("Failed to modify Gist".to_string());
                }
            }
            Err(e) => {
                let err_msg = format!("Modify Gist HTTP request failed: {}", e);
                log::error!("{}", err_msg);
                return Err(err_msg);
            }
        }
    }

    // Parse response JSON
    match serde_json::from_str::<serde_json::Value>(&response.body) {
        Ok(json) => {
            if let Some(new_id) = json["id"].as_str() {
                id = new_id.to_string();
            }
            if let Some(owner_login) = json["owner"]["login"].as_str() {
                username = owner_login.to_string();
            }

            final_url = format!(
                "https://gist.githubusercontent.com/{}/{}/raw/{}",
                username, id, path
            );

            let log_msg = format!(
                "Writing to Gist success!\nGenerator: {}\nPath: {}\nRaw URL: {}\nGist owner: {}",
                name, path, final_url, username
            );
            log::info!("{}", log_msg);
        }
        Err(e) => {
            let err_msg = format!(
                "Failed to parse Gist API response JSON: {}\nResponse body:\n{}",
                e, response.body
            );
            log::error!("{}", err_msg);
            // Continue to save ini even if parsing fails, as the operation
            // might have succeeded
        }
    }

    // Update gistconf.ini
    // Re-enter common section as it was left via get_current before
    if ini.enter_section("common").is_ok() {
        ini.erase_section(); // Erase the items within the section
        ini.set_current("token", &token).ok(); // Pass as slice
        ini.set_current("id", &id).ok(); // Pass as slice
        ini.set_current("username", &username).ok(); // Pass as slice
    } else {
        // This shouldn't happen if the initial enter_section worked, but handle
        // defensively
        log::error!("Failed to re-enter [common] section to update ini.");
    }

    // Set the new section based on the actual path used
    ini.set_current_section(&path);
    ini.erase_section(); // Erase items in the path-named section
    ini.set_current("type", name).ok();
    ini.set_current("url", &final_url).ok();

    if let Err(e) = ini.to_file(ini_path) {
        let err_msg = format!("Failed to write updated gistconf.ini: {}", e);
        log::error!("{}", err_msg);
        return Err(err_msg);
    }

    Ok(())
}
