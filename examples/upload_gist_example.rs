use awc::Client;
use case_insensitive_string::CaseInsensitiveString;
use libsubconverter::upload::gist::upload_gist;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::time::Duration;

const DUMMY_INI_PATH: &str = "./gistconf.ini"; // Relative to where example is run (project root)

/// Fetches the ID and owner login of the first Gist found for the authenticated
/// user.
async fn fetch_first_gist_details(token: &str) -> Option<(String, String)> {
    log::info!("Attempting to fetch existing Gist details using provided token...");
    let client = Client::builder().timeout(Duration::from_secs(10)).finish();
    let url = "https://api.github.com/gists";

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
        "subconverter-rs-example".to_string(),
    );

    let mut client_request = client.get(url);
    for (key, value) in &headers {
        client_request = client_request.insert_header((key.as_ref(), value.as_str()));
    }

    match client_request.send().await {
        Ok(mut response) => {
            let status = response.status();
            if status.is_success() {
                match response.json::<Value>().await {
                    Ok(gists) => {
                        if let Some(first_gist) = gists.as_array().and_then(|arr| arr.get(0)) {
                            if let (Some(id), Some(login)) = (
                                first_gist["id"].as_str(),
                                first_gist["owner"]["login"].as_str(),
                            ) {
                                log::info!("Found existing Gist: ID={}, Owner={}", id, login);
                                Some((id.to_string(), login.to_string()))
                            } else {
                                log::warn!(
                                    "First Gist found but missing 'id' or 'owner.login' fields."
                                );
                                None
                            }
                        } else {
                            log::warn!("No Gists found for the provided token.");
                            None
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to parse Gist list response JSON: {}", e);
                        None
                    }
                }
            } else {
                let body = response
                    .body()
                    .await
                    .map(|b| String::from_utf8_lossy(&b).to_string())
                    .unwrap_or_else(|_| "<failed to read body>".to_string());
                log::error!(
                    "Failed to fetch Gist list: Status {}, Body: {}",
                    status,
                    body
                );
                None
            }
        }
        Err(e) => {
            log::error!("HTTP request to fetch Gist list failed: {}", e);
            None
        }
    }
}

async fn setup_dummy_ini(token: Option<&str>, id: Option<&str>, username: Option<&str>) {
    let mut content = "[common]\n".to_string();
    if let Some(t) = token {
        content.push_str(&format!("token={}\n", t));
    }
    if let Some(i) = id {
        content.push_str(&format!("id={}\n", i));
    }
    if let Some(u) = username {
        content.push_str(&format!("username={}\n", u));
    }

    let mut file = fs::File::create(DUMMY_INI_PATH).expect("Failed to create dummy ini");
    file.write_all(content.as_bytes())
        .expect("Failed to write dummy ini");
    println!(
        "Created dummy {} with content:\n{}",
        DUMMY_INI_PATH, content
    );
}

fn cleanup_dummy_ini() {
    match fs::remove_file(DUMMY_INI_PATH) {
        Ok(_) => println!("Cleaned up dummy {}", DUMMY_INI_PATH),
        Err(e) => println!("Failed to clean up dummy {}: {}", DUMMY_INI_PATH, e),
    }
}

#[actix_web::main]
async fn main() {
    // Basic logging setup for the example
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    println!("--- Running upload_gist example ---");

    // --- Attempt to fetch existing Gist details if token is available ---
    let github_token = env::var("GITHUB_TOKEN").ok();
    let existing_gist_details = if let Some(token) = github_token.as_deref() {
        fetch_first_gist_details(token).await
    } else {
        log::warn!("GITHUB_TOKEN environment variable not set. Update tests will use dummy data or may fail.");
        None
    };

    // --- Test Case 1: No INI file, relies on GITHUB_TOKEN env var (if set) ---
    println!("\n--- Test Case 1: No INI file ---");
    // Ensure no dummy file exists for this case
    let _ = fs::remove_file(DUMMY_INI_PATH);
    match upload_gist(
        "MyConfigName",
        "my_subconverter_config.txt".to_string(),
        "This is the content for the new gist file.".to_string(),
        false, // Don't write managed URL for new gist
    )
    .await
    {
        Ok(_) => println!("upload_gist (Test 1) succeeded."),
        Err(e) => println!("upload_gist (Test 1) failed: {}", e),
    }

    // --- Test Case 2: INI file exists, but no token (relies on env var) ---
    println!("\n--- Test Case 2: INI file without token ---");
    // Use fetched details if available, otherwise use dummies
    let (test2_id, test2_user) = existing_gist_details
        .as_ref()
        .map(|(id, user)| (id.as_str(), user.as_str()))
        .unwrap_or(("some_dummy_gist_id", "some_dummy_username"));
    log::info!(
        "Using Gist ID: {}, Username: {} for Test 2",
        test2_id,
        test2_user
    );
    setup_dummy_ini(None, None, Some(test2_user)).await;
    match upload_gist(
        "AnotherConfig",
        "another_config.yaml".to_string(),
        "YAML content here".to_string(),
        true, // Write managed URL when updating
    )
    .await
    {
        Ok(_) => println!("upload_gist (Test 2) succeeded."),
        Err(e) => println!("upload_gist (Test 2) failed: {}", e),
    }
    cleanup_dummy_ini();

    // --- Test Case 3: INI file with token ---
    println!("\n--- Test Case 3: INI file with token ---");
    setup_dummy_ini(github_token.as_deref(), None, None).await; // Create new gist
    match upload_gist(
        "IniTokenTest",
        "test_from_ini.txt".to_string(),
        "Content using token from INI file.".to_string(),
        false,
    )
    .await
    {
        Ok(_) => println!("upload_gist (Test 3) succeeded."),
        Err(e) => println!("upload_gist (Test 3) failed: {}", e),
    }
    // Note: Test 3 will likely fail if DUMMY_TOKEN_FROM_INI is not a valid token.
    // It will also create/modify the dummy ini file.

    // --- Test Case 4: INI file with token, id, and username (update) ---
    println!("\n--- Test Case 4: INI file with token, id, username (update) ---");
    // Re-use the INI potentially modified by Test 3, or create a new one
    // Use fetched details if available, otherwise use dummies
    let (test4_id, test4_user) = existing_gist_details
        .as_ref()
        .map(|(id, user)| (id.as_str(), user.as_str()))
        .unwrap_or(("another_dummy_gist_id", "another_dummy_username"));
    log::info!(
        "Using Gist ID: {}, Username: {} for Test 4",
        test4_id,
        test4_user
    );
    setup_dummy_ini(
        github_token.as_deref(), // Token still comes from INI for this test
        None,
        Some(test4_user),
    )
    .await;
    match upload_gist(
        "UpdateTest",
        "update_test.txt".to_string(), // Assuming this file exists in the gist
        "Updated content using token from INI file.".to_string(),
        true,
    )
    .await
    {
        Ok(_) => println!("upload_gist (Test 4) succeeded."),
        Err(e) => println!("upload_gist (Test 4) failed: {}", e),
    }
    // Test 4 will likely fail if the token/id/username are not valid and
    // corresponding.

    println!("\n--- Cleaning up --- ");
    cleanup_dummy_ini();
    println!("--- Example finished ---");
}
