//! String utilities
//!
//! Exact port of lib/core/ogs-strings.h and ogs-strings.c

/// Duplicate string (identical to ogs_strdup)
pub fn ogs_strdup(s: &str) -> String {
    s.to_string()
}

/// Duplicate string with max length (identical to ogs_strndup)
pub fn ogs_strndup(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        s[..n].to_string()
    }
}

/// Convert to uppercase (identical to ogs_strupper)
pub fn ogs_strupper(s: &str) -> String {
    s.to_uppercase()
}

/// Convert to lowercase (identical to ogs_strlower)
pub fn ogs_strlower(s: &str) -> String {
    s.to_lowercase()
}

/// Trim whitespace (identical to ogs_strtrim)
pub fn ogs_strtrim(s: &str) -> &str {
    s.trim()
}

/// Check if string starts with prefix
pub fn ogs_strprefix(s: &str, prefix: &str) -> bool {
    s.starts_with(prefix)
}

/// Check if string ends with suffix
pub fn ogs_strsuffix(s: &str, suffix: &str) -> bool {
    s.ends_with(suffix)
}

/// Split string by delimiter
pub fn ogs_strsplit(s: &str, delim: char) -> Vec<&str> {
    s.split(delim).collect()
}

/// Join strings with delimiter
pub fn ogs_strjoin(parts: &[&str], delim: &str) -> String {
    parts.join(delim)
}

/// Safe string copy with bounds checking
pub fn ogs_strlcpy(dst: &mut [u8], src: &str) -> usize {
    let src_bytes = src.as_bytes();
    let copy_len = std::cmp::min(dst.len().saturating_sub(1), src_bytes.len());
    
    if copy_len > 0 {
        dst[..copy_len].copy_from_slice(&src_bytes[..copy_len]);
    }
    if !dst.is_empty() {
        dst[copy_len] = 0; // Null terminate
    }
    
    src_bytes.len()
}
