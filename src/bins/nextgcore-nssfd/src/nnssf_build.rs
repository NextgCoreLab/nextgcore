//! NSSF NS Selection Message Builder (live helpers)
//!
//! nssfd-08: Removed dead `nssf_nnssf_nsselection_build_get` (dot-notation
//! GET builder for H-NSSF) — it had no callers outside its own test module.
//! The function encoded query params as `tai.plmnId.mcc=…` dot-notation which
//! is non-standard for OpenAPI 3.0 form-style query encoding; confirmed dead
//! by grep (no references outside this file).

/// Build authorized network slice info response JSON body.
pub fn build_authorized_network_slice_info_response(nrf_id: &str, nsi_id: &str) -> String {
    serde_json_minimal(nrf_id, nsi_id)
}

/// Minimal JSON body without a serde_json allocation.
fn serde_json_minimal(nrf_id: &str, nsi_id: &str) -> String {
    format!(
        r#"{{"nsiInformation":{{"nrfId":"{}","nsiId":"{}"}}}}"#,
        escape_json_string(nrf_id),
        escape_json_string(nsi_id)
    )
}

/// Escape special characters in a JSON string value.
fn escape_json_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_authorized_response() {
        let response =
            build_authorized_network_slice_info_response("http://nrf.example.com", "nsi-123");
        assert!(response.contains("nrfId"));
        assert!(response.contains("nsiId"));
        assert!(response.contains("http://nrf.example.com"));
        assert!(response.contains("nsi-123"));
    }

    #[test]
    fn test_escape_json_string() {
        assert_eq!(escape_json_string("hello"), "hello");
        assert_eq!(escape_json_string("hello\"world"), "hello\\\"world");
        assert_eq!(escape_json_string("line1\nline2"), "line1\\nline2");
    }
}
