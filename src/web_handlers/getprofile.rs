//! `/getprofile` compatibility endpoint.
//!
//! The C++ subconverter exposes profiles as a small INI file in `profiles/`.
//! This module implements the same idea on top of the Rust conversion
//! pipeline: read a local profile, merge its `[Profile]` values with the
//! request query (request values win), then hand the result to
//! [`sub_process`].
//!
//! Only local files below the directory containing `pref.toml` are allowed.
//! The endpoint never accepts an arbitrary URL or path.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use actix_web::{web, HttpRequest, HttpResponse};
use log::{error, info};

use crate::api::{sub_process, SubconverterQuery};
use crate::Settings;

/// Refuse absurdly large profile files before reading them into memory.
const MAX_PROFILE_SIZE: u64 = 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
enum ProfileError {
    InvalidName,
    Forbidden,
    NotFound,
    TooLarge,
    Io,
    EmptySection,
}

/// Resolve `name` below `base`. Relative names without an extension get
/// `.ini` appended, matching the common `profiles/xpin` shorthand.
fn resolve_profile_path(base: &Path, name: &str) -> Result<PathBuf, ProfileError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(ProfileError::InvalidName);
    }

    let candidate = if Path::new(name).extension().is_none() {
        format!("{name}.ini")
    } else {
        name.to_string()
    };
    let candidate_path = Path::new(&candidate);

    // Reject absolute paths and `..` before touching the filesystem. The
    // canonical-path check below is still required for symlinks.
    if candidate_path.is_absolute()
        || candidate_path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(ProfileError::Forbidden);
    }

    let canonical_base = base.canonicalize().map_err(|_| ProfileError::NotFound)?;
    let canonical_path = base
        .join(candidate_path)
        .canonicalize()
        .map_err(|_| ProfileError::NotFound)?;

    if !canonical_path.starts_with(&canonical_base) {
        return Err(ProfileError::Forbidden);
    }
    if !canonical_path.is_file() {
        return Err(ProfileError::NotFound);
    }
    if canonical_path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_none_or(|extension| !extension.eq_ignore_ascii_case("ini"))
    {
        return Err(ProfileError::Forbidden);
    }

    Ok(canonical_path)
}

/// Parse the `[Profile]` section of a subconverter profile. Keys are
/// lower-cased; repeated `url` lines are joined with `|`.
fn parse_profile(content: &str) -> Result<HashMap<String, String>, ProfileError> {
    let mut in_profile = false;
    let mut values: HashMap<String, String> = HashMap::new();

    for raw_line in content.lines() {
        let line = raw_line.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') {
            if let Some(end) = line.find(']') {
                in_profile = line[1..end].trim().eq_ignore_ascii_case("Profile");
                continue;
            }
        }

        if !in_profile {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        let value = value.trim().to_string();

        if key == "url" {
            if let Some(existing) = values.get_mut(&key) {
                if !existing.is_empty() {
                    existing.push('|');
                }
                existing.push_str(&value);
                continue;
            }
        }
        values.insert(key, value);
    }

    if values.is_empty() {
        Err(ProfileError::EmptySection)
    } else {
        Ok(values)
    }
}

/// Directory against which profile names are resolved. This is the directory
/// containing `pref.toml` (or the current directory when the config was
/// loaded from a URL / the default relative path).
fn profile_base_dir(pref_path: &str) -> PathBuf {
    if pref_path.starts_with("http://") || pref_path.starts_with("https://") {
        return PathBuf::from(".");
    }
    match Path::new(pref_path).parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left_byte, right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

fn error_response(error: ProfileError) -> HttpResponse {
    match error {
        ProfileError::InvalidName => HttpResponse::Forbidden().body("Forbidden"),
        ProfileError::Forbidden => HttpResponse::Forbidden().body("Forbidden"),
        ProfileError::NotFound => HttpResponse::NotFound().body("Profile not found"),
        ProfileError::TooLarge => {
            HttpResponse::build(actix_web::http::StatusCode::PAYLOAD_TOO_LARGE)
                .body("Profile too large")
        }
        ProfileError::Io => HttpResponse::InternalServerError().body("Failed to read profile"),
        ProfileError::EmptySection => HttpResponse::InternalServerError().body("Broken profile!"),
    }
}

/// `GET /getprofile?name=profiles/xpin.ini&token=...`
pub async fn get_profile_handler(
    req: HttpRequest,
    params: web::Query<HashMap<String, String>>,
) -> HttpResponse {
    let params = params.into_inner();
    let token = params.get("token").cloned().unwrap_or_default();
    let name = params.get("name").cloned().unwrap_or_default();

    if token.is_empty() || name.is_empty() {
        return HttpResponse::Forbidden().body("Forbidden");
    }

    let (base_dir, access_token) = {
        let settings = Settings::current();
        (
            profile_base_dir(&settings.pref_path),
            settings.api_access_token.clone(),
        )
    };

    if access_token.is_empty() || !constant_time_eq(token.as_bytes(), access_token.as_bytes()) {
        return HttpResponse::Forbidden().body("Forbidden");
    }

    let profile_path = match resolve_profile_path(&base_dir, &name) {
        Ok(path) => path,
        Err(error) => return error_response(error),
    };

    let metadata = match std::fs::metadata(&profile_path) {
        Ok(metadata) => metadata,
        Err(_) => return error_response(ProfileError::Io),
    };
    if metadata.len() > MAX_PROFILE_SIZE {
        return error_response(ProfileError::TooLarge);
    }

    let content = match std::fs::read_to_string(&profile_path) {
        Ok(content) => content,
        Err(_) => return error_response(ProfileError::Io),
    };
    let profile = match parse_profile(&content) {
        Ok(profile) => profile,
        Err(error) => return error_response(error),
    };
    info!("Loading profile {:?}", profile_path);

    // Request parameters override profile values; the validated token is
    // forwarded so sub_process treats local subscription URLs as authorized.
    let mut merged = profile;
    for (key, value) in &params {
        if key == "name" {
            continue;
        }
        merged.insert(key.clone(), value.clone());
    }
    merged.insert("token".to_string(), access_token);

    let query_string = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(merged.iter())
        .finish();
    let mut query: SubconverterQuery = match serde_urlencoded::from_str(&query_string) {
        Ok(query) => query,
        Err(error) => {
            error!("Invalid profile query: {}", error);
            return HttpResponse::BadRequest().body("Invalid profile parameters");
        }
    };

    let mut request_headers = HashMap::new();
    for (key, value) in req.headers() {
        request_headers.insert(key.to_string(), value.to_str().unwrap_or("").to_string());
    }
    query.request_headers = Some(request_headers);

    let interval = query.interval;
    match sub_process(Some(req.uri().to_string()), query).await {
        Ok(response) => {
            let mut http_response = response.to_http_response();
            if let Some(interval) = interval {
                let hours = (interval / 3600).to_string();
                if let Ok(value) = actix_web::http::header::HeaderValue::from_str(&hours) {
                    http_response.headers_mut().insert(
                        actix_web::http::header::HeaderName::from_static("profile-update-interval"),
                        value,
                    );
                }
            }
            http_response
        }
        Err(error) => {
            error!("Get profile error: {}", error);
            HttpResponse::InternalServerError().body(format!("Internal server error: {}", error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_profile_section_and_skips_other_sections() {
        let content = r#"
[common]
target = surge

[Profile]
target = clash
url = http://127.0.0.1:1088/a.txt
url = http://127.0.0.1:1088/b.txt
exclude = 原生|家宽
filename = XPIN.Mixed.01
interval = 604900
"#;

        let profile = parse_profile(content).expect("profile must parse");
        assert_eq!(profile.get("target").map(String::as_str), Some("clash"));
        assert_eq!(
            profile.get("url").map(String::as_str),
            Some("http://127.0.0.1:1088/a.txt|http://127.0.0.1:1088/b.txt")
        );
        assert_eq!(
            profile.get("exclude").map(String::as_str),
            Some("原生|家宽")
        );
        assert_eq!(
            profile.get("filename").map(String::as_str),
            Some("XPIN.Mixed.01")
        );
        assert_eq!(profile.get("interval").map(String::as_str), Some("604900"));
    }

    #[test]
    fn rejects_empty_profile_section() {
        assert_eq!(
            parse_profile("[Profile]\n"),
            Err(ProfileError::EmptySection)
        );
        assert_eq!(
            parse_profile("[common]\ntarget = clash\n"),
            Err(ProfileError::EmptySection)
        );
    }

    #[test]
    fn resolves_profile_relative_to_base() {
        let temporary = tempfile::tempdir().expect("temp dir");
        let base = temporary.path();
        std::fs::create_dir_all(base.join("profiles")).expect("profiles dir");
        std::fs::write(base.join("profiles/xpin.ini"), "[Profile]\n").expect("profile");

        assert_eq!(
            resolve_profile_path(base, "profiles/xpin.ini").expect("path"),
            base.join("profiles/xpin.ini")
                .canonicalize()
                .expect("canonical")
        );
        assert_eq!(
            resolve_profile_path(base, "profiles/xpin").expect("path"),
            base.join("profiles/xpin.ini")
                .canonicalize()
                .expect("canonical")
        );
    }

    #[test]
    fn blocks_traversal_and_non_ini_files() {
        let temporary = tempfile::tempdir().expect("temp dir");
        let base = temporary.path();
        std::fs::create_dir_all(base.join("profiles")).expect("profiles dir");
        std::fs::write(base.join("pref.toml"), "").expect("pref");
        std::fs::write(base.join("profiles/xpin.ini"), "[Profile]\n").expect("profile");

        assert_eq!(
            resolve_profile_path(base, "../pref.toml"),
            Err(ProfileError::Forbidden)
        );
        assert_eq!(
            resolve_profile_path(base, "pref.toml"),
            Err(ProfileError::Forbidden)
        );
        assert_eq!(
            resolve_profile_path(base, "profiles/missing.ini"),
            Err(ProfileError::NotFound)
        );
    }

    #[cfg(unix)]
    #[test]
    fn blocks_symlinks_that_escape_base() {
        let temporary = tempfile::tempdir().expect("temp dir");
        let base = temporary.path().join("root");
        let outside = temporary.path().join("outside.ini");
        std::fs::create_dir_all(base.join("profiles")).expect("profiles dir");
        std::fs::write(&outside, "[Profile]\n").expect("outside profile");
        std::os::unix::fs::symlink(&outside, base.join("profiles/link.ini")).expect("symlink");

        assert_eq!(
            resolve_profile_path(&base, "profiles/link.ini"),
            Err(ProfileError::Forbidden)
        );
    }

    #[test]
    fn constant_time_comparison() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret "));
    }

    #[test]
    fn merges_profile_values_into_query() {
        let mut merged = HashMap::new();
        merged.insert("target".to_string(), "clash".to_string());
        merged.insert(
            "url".to_string(),
            "http://127.0.0.1:1088/a.txt|http://127.0.0.1:1088/b.txt".to_string(),
        );
        merged.insert("exclude".to_string(), "原生|家宽".to_string());
        merged.insert("filename".to_string(), "XPIN.Mixed.01".to_string());
        merged.insert("interval".to_string(), "604900".to_string());

        let query_string = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(merged.iter())
            .finish();
        let query: SubconverterQuery = serde_urlencoded::from_str(&query_string).expect("query");

        assert_eq!(query.target.as_deref(), Some("clash"));
        assert_eq!(
            query.url.as_deref(),
            Some("http://127.0.0.1:1088/a.txt|http://127.0.0.1:1088/b.txt")
        );
        assert_eq!(query.exclude.as_deref(), Some("原生|家宽"));
        assert_eq!(query.filename.as_deref(), Some("XPIN.Mixed.01"));
        assert_eq!(query.interval, Some(604900));
    }
}
