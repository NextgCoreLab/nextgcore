//! Hex helpers for the Nudm_UEAuthentication payloads.
//!
//! The C port's NUDM UEAU response handlers (`nudm-handler.c`) were only
//! reachable from the deleted per-UE FSM (#654); the live Nudm client calls
//! and their response handling are in `app`.

/// Convert bytes to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Convert hex string to bytes. Empty for malformed input (odd length or a
/// non-hex character): every caller checks the decoded length, so a bad
/// value is refused there rather than panicking here (#765). Before #765 an
/// odd length or a multi-byte character panicked, and bad pairs were dropped.
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    nextgcore_core::conv::hex_decode(hex).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_hex() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(bytes_to_hex(&bytes), "0123456789abcdef");
    }

    #[test]
    fn test_hex_to_bytes() {
        let hex = "0123456789abcdef";
        let expected = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(hex_to_bytes(hex), expected);
    }

    #[test]
    fn test_hex_roundtrip() {
        let original = [0xde, 0xad, 0xbe, 0xef];
        let hex = bytes_to_hex(&original);
        let bytes = hex_to_bytes(&hex);
        assert_eq!(bytes, original);
    }
}
