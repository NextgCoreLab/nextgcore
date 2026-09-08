//! Shared helpers left over from the `src/udm/nudm-handler.c` port.
//!
//! This module no longer handles any Nudm service request. It once held a
//! second, unreachable Nudm UECM/SDM/UEAU implementation beside the live one in
//! [`crate::uecm`] and [`crate::app`]; see the removal note below for what went
//! and why. What remains is the [`HandlerResult`] / [`http_status`] pair that
//! [`crate::nudr_handler`] returns, plus the hex codec that `app.rs`, `sor.rs`
//! and `upu.rs` use for wire-format key material.
//!
//! ## Removed in #236: nine unreachable Nudm handlers
//!
//! Every handler below had a live counterpart already serving the same
//! procedure, so the file was two implementations of one thing with nothing
//! marking which was which:
//!
//! | removed | live implementation that serves it |
//! |---|---|
//! | `udm_nudm_uecm_handle_amf_registration` | [`crate::uecm::process_amf_registration`] |
//! | `udm_nudm_uecm_handle_amf_registration_update` | [`crate::uecm::process_amf_registration_update`] |
//! | `udm_nudm_uecm_handle_amf_registration_get` | [`crate::uecm::process_amf_registration_get`] |
//! | `udm_nudm_uecm_handle_smf_registration` | [`crate::uecm::process_smf_registration`] |
//! | `udm_nudm_uecm_handle_smf_deregistration` | [`crate::uecm::process_smf_deregistration`] |
//! | `udm_nudm_ueau_handle_result_confirmation_inform` | [`crate::app::handle_auth_event`] |
//! | `udm_nudm_sdm_handle_subscription_create` | `app.rs::handle_sdm_subscribe` |
//! | `udm_nudm_sdm_handle_subscription_delete` | the `sdm-subscriptions` DELETE arm of `app.rs::udm_sbi_route` |
//! | `udm_nudm_sdm_handle_subscription_provisioned` | the `ue-context-in-smf-data` GET arm, which answers 501 |
//!
//! Seven had no reference anywhere outside this file. The two SMF ones were
//! reached only from [`crate::sess_sm`], whose SBI half is itself unreachable —
//! `UdmEvent::sbi_server` has no constructor in the tree, so the live router
//! (`app.rs::udm_sbi_route`) is the only thing that ever serves a Nudm request.
//! The `ue-context-in-smf-data` case is worth naming: the removed handler
//! returned `HandlerResult::ok()` while doing nothing, whereas the live route
//! answers 501, so the dead copy was the more dishonest of the two.
//!
//! Also removed, having had no non-test caller at all: `parse_amf_id`,
//! `guami_matches` (the live GUAMI comparison is `uecm.rs`'s, which operates on
//! the parsed JSON), `buffer_to_u64` and `u64_to_buffer`, together with the
//! request structs that only fed the deleted handlers
//! (`Amf3GppAccessRegistrationRequest`, `Amf3GppAccessRegistrationModificationRequest`,
//! `GuamiRequest`, `PlmnIdRequest`, `SmfRegistrationRequest`,
//! `SdmSubscriptionRequest`, `AuthEventRequest`) and the two `HandlerResult`
//! constructors only they used (`created`, `not_found`).
//!
//! This continues PR #228, which removed `udm_nudm_ueau_handle_get` from here
//! for the same reason: it was the only code that persisted `ausf_instance_id`
//! and it had no caller, so SoR/UPU always picked an arbitrary AUSF (#84 gap 4).

/// HTTP status codes
pub mod http_status {
    pub const OK: u16 = 200;
    pub const NO_CONTENT: u16 = 204;
    pub const BAD_REQUEST: u16 = 400;
    pub const FORBIDDEN: u16 = 403;
    pub const CREATED: u16 = 201;
    pub const INTERNAL_SERVER_ERROR: u16 = 500;
}

/// Handler result with HTTP status and optional error message
#[derive(Debug)]
pub struct HandlerResult {
    pub success: bool,
    pub status: u16,
    pub error_message: Option<String>,
    pub error_cause: Option<String>,
}

impl HandlerResult {
    pub fn ok() -> Self {
        Self {
            success: true,
            status: http_status::OK,
            error_message: None,
            error_cause: None,
        }
    }

    pub fn no_content() -> Self {
        Self {
            success: true,
            status: http_status::NO_CONTENT,
            error_message: None,
            error_cause: None,
        }
    }

    pub fn bad_request(message: &str) -> Self {
        Self {
            success: false,
            status: http_status::BAD_REQUEST,
            error_message: Some(message.to_string()),
            error_cause: None,
        }
    }

    pub fn forbidden(message: &str, cause: Option<&str>) -> Self {
        Self {
            success: false,
            status: http_status::FORBIDDEN,
            error_message: Some(message.to_string()),
            error_cause: cause.map(|s| s.to_string()),
        }
    }
}

// Helper functions

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Convert bytes to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_result_ok() {
        let result = HandlerResult::ok();
        assert!(result.success);
        assert_eq!(result.status, http_status::OK);
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_handler_result_no_content() {
        let result = HandlerResult::no_content();
        assert!(result.success);
        assert_eq!(result.status, http_status::NO_CONTENT);
    }

    #[test]
    fn test_handler_result_bad_request() {
        let result = HandlerResult::bad_request("Test error");
        assert!(!result.success);
        assert_eq!(result.status, http_status::BAD_REQUEST);
        assert_eq!(result.error_message, Some("Test error".to_string()));
    }

    #[test]
    fn test_handler_result_forbidden() {
        let result = HandlerResult::forbidden("Forbidden", Some("INVALID_GUAMI"));
        assert!(!result.success);
        assert_eq!(result.status, http_status::FORBIDDEN);
        assert_eq!(result.error_cause, Some("INVALID_GUAMI".to_string()));
    }

    #[test]
    fn test_hex_to_bytes() {
        let hex = "0123456789abcdef";
        let expected = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(hex_to_bytes(hex), expected);
    }

    #[test]
    fn test_bytes_to_hex() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(bytes_to_hex(&bytes), "0123456789abcdef");
    }

    #[test]
    fn test_hex_roundtrip() {
        let original = [0xde, 0xad, 0xbe, 0xef];
        let hex = bytes_to_hex(&original);
        let bytes = hex_to_bytes(&hex);
        assert_eq!(bytes, original);
    }

    #[test]
    fn test_hex_to_bytes_invalid_length() {
        // A short hex string yields the bytes it does contain rather than
        // padding or erroring: `app.rs` relies on the caller length-checking the
        // result (a 2-byte RAND is not silently widened to 16).
        let hex = "0123"; // Only 2 bytes instead of 16
        let bytes = hex_to_bytes(hex);
        assert_eq!(bytes.len(), 2);
    }
}
