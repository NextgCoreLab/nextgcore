//! The hex codec left over from the `src/udm/nudm-handler.c` port.
//!
//! This module no longer handles any Nudm service request. It once held a
//! second, unreachable Nudm UECM/SDM/UEAU implementation beside the live one in
//! [`crate::uecm`] and [`crate::app`]; see the removal notes below for what went
//! and why. What remains is the hex codec that `app.rs`, `sor.rs` and `upu.rs`
//! use for wire-format key material.
//!
//! ## Removed in #242: the `HandlerResult` / `http_status` pair
//!
//! Their only consumer was `nudr_handler.rs`, which #242 deleted along with the
//! rest of the unreachable state-machine request path (nothing in the tree
//! constructed the `UdmEvent::sbi_server` that reached it). The live path builds
//! its responses through `nextgcore_sbi`'s own helpers, so there was no second
//! caller to migrate — the pair had become a status-code vocabulary with nobody
//! left to speak it.
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
//! reached only from the former `sess_sm.rs`, whose SBI half was itself
//! unreachable — `UdmEvent::sbi_server` had no constructor in the tree, so the
//! live router (`app.rs::udm_sbi_route`) is the only thing that ever serves a
//! Nudm request. #242 removed `sess_sm.rs` for that reason.
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
