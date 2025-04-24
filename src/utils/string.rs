//! String utility functions for text processing

/// FNV-1a hash constants
pub const HASH_PRIME: u64 = 0x100000001B3;
pub const HASH_BASIS: u64 = 0xCBF29CE484222325;

/// Hash a string using FNV-1a algorithm
///
/// This matches the behavior of the C++ hash_ function in string_hash.h
///
/// # Arguments
///
/// * `s` - The string to hash
///
/// # Returns
///
/// The 64-bit hash value
pub fn hash(s: &str) -> u64 {
    let mut result = HASH_BASIS;
    for &byte in s.as_bytes() {
        result ^= byte as u64;
        result = result.wrapping_mul(HASH_PRIME);
    }
    result
}
/// Compile-time version of the hash function
///
/// While not directly usable as a string literal suffix like in C++,
/// this can be used in const contexts.
///
/// # Arguments
///
/// * `s` - The string to hash
///
/// # Returns
///
/// The 64-bit hash value
pub const fn hash_const(s: &str) -> u64 {
    let bytes = s.as_bytes();
    let mut result = HASH_BASIS;
    let mut i = 0;
    while i < bytes.len() {
        result ^= bytes[i] as u64;
        result = result.wrapping_mul(HASH_PRIME);
        i += 1;
    }
    result
}

/// Alias for hash_const to match C++ naming pattern
pub const fn hash_compile_time(s: &str) -> u64 {
    hash_const(s)
}

/// Replace all occurrences of a string with another
///
/// # Arguments
///
/// * `s` - The input string
/// * `from` - The string to replace
/// * `to` - The replacement string
///
/// # Returns
///
/// The string with all occurrences replaced
pub fn replace_all_distinct(s: &str, from: &str, to: &str) -> String {
    let mut result = s.to_string();
    let mut position = 0;

    while let Some(found_pos) = result[position..].find(from) {
        let absolute_pos = position + found_pos;
        result.replace_range(absolute_pos..absolute_pos + from.len(), to);
        position = absolute_pos + to.len();
    }

    result
}

/// Check if a string starts with a specific prefix
///
/// # Arguments
///
/// * `s` - The string to check
/// * `prefix` - The prefix to look for
///
/// # Returns
///
/// True if the string starts with the prefix, false otherwise
pub fn starts_with(s: &str, prefix: &str) -> bool {
    s.starts_with(prefix)
}

/// Check if a string ends with a specific suffix
///
/// # Arguments
///
/// * `s` - The string to check
/// * `suffix` - The suffix to look for
///
/// # Returns
///
/// True if the string ends with the suffix, false otherwise
pub fn ends_with(s: &str, suffix: &str) -> bool {
    s.ends_with(suffix)
}

/// Convert a string to lowercase
///
/// # Arguments
///
/// * `s` - The string to convert
///
/// # Returns
///
/// The lowercase version of the string
pub fn to_lower(s: &str) -> String {
    s.to_lowercase()
}

/// Trim whitespace from the beginning and end of a string
///
/// # Arguments
///
/// * `s` - The string to trim
///
/// # Returns
///
/// The trimmed string
pub fn trim(s: &str) -> &str {
    s.trim()
}

pub fn trim_whitespace(s: &str, before: bool, after: bool) -> String {
    if before {
        s.trim_start().to_string()
    } else if after {
        s.trim_end().to_string()
    } else {
        s.trim().to_string()
    }
}

/// Trim a specific character from the beginning and/or end of a string
///
/// # Arguments
///
/// * `s` - The string to trim
/// * `target` - The character to trim
/// * `before` - Whether to trim from the beginning
/// * `after` - Whether to trim from the end
///
/// # Returns
///
/// The trimmed string
pub fn trim_of(s: &str, target: char, before: bool, after: bool) -> String {
    if !before && !after {
        return s.to_string();
    }

    let len = s.len();
    if len == 0 {
        return s.to_string();
    }

    let mut start = 0;
    let mut end = len;

    if before {
        for (i, ch) in s.char_indices() {
            if ch != target {
                start = i;
                break;
            }
        }
    }

    if after {
        for (i, ch) in s.char_indices().rev() {
            if ch != target {
                end = i + ch.len_utf8();
                break;
            }
        }
    }

    // Handle case where the string consists only of the target character
    if start >= end {
        return String::new();
    }

    s[start..end].to_string()
}

/// Find the position of a substring in a string
///
/// # Arguments
///
/// * `s` - The string to search in
/// * `search` - The substring to find
///
/// # Returns
///
/// The position of the substring if found, None otherwise
pub fn find_str(s: &str, search: &str) -> Option<usize> {
    s.find(search)
}

/// Join a slice of strings with a separator
///
/// # Arguments
///
/// * `parts` - Slice of strings to join
/// * `separator` - Separator to place between strings
///
/// # Returns
///
/// A new string with all parts joined by the separator
pub fn join<T: AsRef<str>>(parts: &[T], separator: &str) -> String {
    parts
        .iter()
        .map(|s| s.as_ref())
        .collect::<Vec<&str>>()
        .join(separator)
}

use unicode_segmentation::UnicodeSegmentation;

/// Removes emoji characters from a string.
/// Modern implementation using the `emojis` crate.
pub fn remove_emoji(s: &str) -> String {
    s.graphemes(true)
        .filter(|grapheme| emojis::get(grapheme).is_none())
        .collect()
}

/// Calculate MD5 hash for a string
///
/// # Arguments
///
/// * `input` - The input string to calculate MD5 hash for
///
/// # Returns
///
/// A string containing the hexadecimal representation of the MD5 hash
pub fn md5(input: &str) -> String {
    use md5::{Digest, Md5};

    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();

    // Convert to hex string
    let mut hex_string = String::with_capacity(32);
    for byte in result.iter() {
        hex_string.push_str(&format!("{:02x}", byte));
    }

    hex_string
}

/// Joins two path segments with a proper separator.
/// Makes sure there's exactly one '/' between segments.
pub fn join_path(base: &str, segment: &str) -> String {
    if base.is_empty() {
        return segment.to_string();
    }

    let base_has_trailing_slash = base.ends_with('/');
    let segment_has_leading_slash = segment.starts_with('/');

    match (base_has_trailing_slash, segment_has_leading_slash) {
        (true, true) => format!("{}{}", base, &segment[1..]),
        (false, false) => format!("{}/{}", base, segment),
        (true, false) => format!("{}{}", base, segment),
        (false, true) => format!("{}{}", base, segment),
    }
}

/// Normalize a directory path to ensure it ends with a slash
pub fn normalize_dir_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{}/", path)
    }
}

/// Constructs a full path for a directory entry with appropriate separators
pub fn build_dir_entry_path(base_path: &str, dir_name: &str) -> String {
    let base = normalize_dir_path(base_path);

    if base.is_empty() {
        format!("/{}/", dir_name)
    } else {
        join_path(&base, &format!("{}/", dir_name))
    }
}

/// Constructs a full path for a file entry with appropriate separators
pub fn build_file_entry_path(base_path: &str, file_name: &str) -> String {
    if base_path.is_empty() {
        format!("/{}", file_name)
    } else {
        join_path(base_path, file_name)
    }
}

/// Normalize a file path to ensure it starts with a slash when needed
pub fn normalize_file_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        // Test some known values
        assert_eq!(hash("test"), 18007334074686647077);
        assert_eq!(hash("hello"), 11831194018420276491);
        assert_eq!(hash(""), HASH_BASIS);
    }

    #[test]
    fn test_hash_const() {
        // Should match the runtime hash function
        assert_eq!(hash_const("test"), hash("test"));
        assert_eq!(hash_const("hello"), hash("hello"));
        assert_eq!(hash_const(""), HASH_BASIS);
    }

    #[test]
    fn test_replace_all_distinct() {
        assert_eq!(replace_all_distinct("hello world", "o", "0"), "hell0 w0rld");
        assert_eq!(replace_all_distinct("test-test", "-", "_"), "test_test");
        assert_eq!(replace_all_distinct("abcabc", "a", "x"), "xbcxbc");
    }

    #[test]
    fn test_starts_with() {
        assert!(starts_with("hello world", "hello"));
        assert!(!starts_with("hello world", "world"));
    }

    #[test]
    fn test_ends_with() {
        assert!(ends_with("hello world", "world"));
        assert!(!ends_with("hello world", "hello"));
    }

    #[test]
    fn test_to_lower() {
        assert_eq!(to_lower("HELLO"), "hello");
        assert_eq!(to_lower("Hello World"), "hello world");
    }

    #[test]
    fn test_trim() {
        assert_eq!(trim("  hello  "), "hello");
        assert_eq!(trim("\t\nhello\r\n"), "hello");
    }

    #[test]
    fn test_join() {
        let parts = vec!["a", "b", "c"];
        assert_eq!(join(&parts, ","), "a,b,c");
        assert_eq!(join(&parts, ""), "abc");
        assert_eq!(join(&parts, " - "), "a - b - c");

        // Test with empty array
        let empty: Vec<&str> = vec![];
        assert_eq!(join(&empty, ","), "");
    }

    #[test]
    fn test_remove_emoji() {
        // Test with emoji at the beginning
        assert_eq!(remove_emoji("😀Hello"), "Hello");
        // Test with multiple emoji
        assert_eq!(remove_emoji("😀😁Hello"), "Hello");
        // Test with no emoji
        assert_eq!(remove_emoji("Hello"), "Hello");
        // Test with only emoji
        assert_eq!(remove_emoji("😀"), "😀"); // Preserves the original if all emoji
    }

    #[test]
    fn test_md5() {
        // Test cases with known MD5 hashes
        assert_eq!(md5(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5("hello world"), "5eb63bbbe01eeed093cb22bb8f5acdc3");
        assert_eq!(md5("test"), "098f6bcd4621d373cade4e832627b4f6");
    }

    #[test]
    fn test_join_path() {
        assert_eq!(join_path("", "file.txt"), "file.txt");
        assert_eq!(join_path("/", "file.txt"), "/file.txt");
        assert_eq!(join_path("dir", "file.txt"), "dir/file.txt");
        assert_eq!(join_path("dir/", "file.txt"), "dir/file.txt");
        assert_eq!(join_path("dir", "/file.txt"), "dir/file.txt");
        assert_eq!(join_path("dir/", "/file.txt"), "dir/file.txt");
        assert_eq!(join_path("/dir", "subdir/file.txt"), "/dir/subdir/file.txt");
    }

    #[test]
    fn test_normalize_dir_path() {
        assert_eq!(normalize_dir_path(""), "");
        assert_eq!(normalize_dir_path("/"), "/");
        assert_eq!(normalize_dir_path("dir"), "dir/");
        assert_eq!(normalize_dir_path("dir/"), "dir/");
        assert_eq!(normalize_dir_path("/dir"), "/dir/");
        assert_eq!(normalize_dir_path("/dir/"), "/dir/");
    }

    #[test]
    fn test_build_dir_entry_path() {
        assert_eq!(build_dir_entry_path("", "dir"), "/dir/");
        assert_eq!(build_dir_entry_path("/", "dir"), "/dir/");
        assert_eq!(build_dir_entry_path("base", "dir"), "base/dir/");
        assert_eq!(build_dir_entry_path("base/", "dir"), "base/dir/");
        assert_eq!(build_dir_entry_path("/base", "dir"), "/base/dir/");
        assert_eq!(build_dir_entry_path("/base/", "dir"), "/base/dir/");
    }

    #[test]
    fn test_build_file_entry_path() {
        assert_eq!(build_file_entry_path("", "file.txt"), "/file.txt");
        assert_eq!(build_file_entry_path("/", "file.txt"), "/file.txt");
        assert_eq!(build_file_entry_path("dir", "file.txt"), "dir/file.txt");
        assert_eq!(build_file_entry_path("dir/", "file.txt"), "dir/file.txt");
        assert_eq!(build_file_entry_path("/dir", "file.txt"), "/dir/file.txt");
        assert_eq!(build_file_entry_path("/dir/", "file.txt"), "/dir/file.txt");
    }

    #[test]
    fn test_normalize_file_path() {
        assert_eq!(normalize_file_path(""), "");
        assert_eq!(normalize_file_path("/"), "/");
        assert_eq!(normalize_file_path("file.txt"), "/file.txt");
        assert_eq!(normalize_file_path("/file.txt"), "/file.txt");
        assert_eq!(normalize_file_path("dir/file.txt"), "/dir/file.txt");
        assert_eq!(normalize_file_path("/dir/file.txt"), "/dir/file.txt");
    }
}
