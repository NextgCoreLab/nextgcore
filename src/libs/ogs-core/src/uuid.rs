//! UUID generation and formatting
//!
//! Exact port of lib/core/ogs-uuid.h and ogs-uuid.c

use crate::rand::ogs_random;

/// UUID formatted length (36 characters: 8-4-4-4-12)
pub const OGS_UUID_FORMATTED_LENGTH: usize = 36;

/// UUID structure (identical to ogs_uuid_t)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct OgsUuid {
    pub data: [u8; 16],
}

impl OgsUuid {
    /// Create a new random UUID (version 4)
    pub fn new() -> Self {
        let mut uuid = OgsUuid { data: [0u8; 16] };
        ogs_uuid_get(&mut uuid);
        uuid
    }

    /// Create UUID from bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        OgsUuid { data: bytes }
    }

    /// Get UUID bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.data
    }

    /// Format UUID as string
    pub fn format(&self) -> String {
        ogs_uuid_format(self)
    }

    /// Parse UUID from string
    pub fn parse(s: &str) -> Option<Self> {
        let mut uuid = OgsUuid::default();
        if ogs_uuid_parse(&mut uuid, s) == 0 {
            Some(uuid)
        } else {
            None
        }
    }
}

impl std::fmt::Display for OgsUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.format())
    }
}

/// Generate a random UUID (identical to ogs_uuid_get)
pub fn ogs_uuid_get(uuid: &mut OgsUuid) {
    ogs_random(&mut uuid.data);
    
    // Set version to 4 (random UUID)
    uuid.data[6] = (uuid.data[6] & 0x0F) | 0x40;
    
    // Set variant to RFC 4122
    uuid.data[8] = (uuid.data[8] & 0x3F) | 0x80;
}

/// Format UUID as string (identical to ogs_uuid_format)
pub fn ogs_uuid_format(uuid: &OgsUuid) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid.data[0], uuid.data[1], uuid.data[2], uuid.data[3],
        uuid.data[4], uuid.data[5],
        uuid.data[6], uuid.data[7],
        uuid.data[8], uuid.data[9],
        uuid.data[10], uuid.data[11], uuid.data[12], uuid.data[13], uuid.data[14], uuid.data[15]
    )
}

/// Parse UUID from string (identical to ogs_uuid_parse)
/// Returns 0 on success, -1 on error
pub fn ogs_uuid_parse(uuid: &mut OgsUuid, uuid_str: &str) -> i32 {
    let s = uuid_str.trim();
    
    // Remove hyphens and validate length
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return -1;
    }
    
    // Parse hex string
    for i in 0..16 {
        match u8::from_str_radix(&hex[i*2..i*2+2], 16) {
            Ok(b) => uuid.data[i] = b,
            Err(_) => return -1,
        }
    }
    
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_new() {
        let uuid1 = OgsUuid::new();
        let uuid2 = OgsUuid::new();
        
        // UUIDs should be different
        assert_ne!(uuid1, uuid2);
        
        // Check version 4
        assert_eq!(uuid1.data[6] & 0xF0, 0x40);
        
        // Check variant
        assert_eq!(uuid1.data[8] & 0xC0, 0x80);
    }

    #[test]
    fn test_uuid_format() {
        let uuid = OgsUuid::from_bytes([
            0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc,
            0xde, 0xf0,
            0x12, 0x34,
            0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
        ]);
        
        let formatted = uuid.format();
        assert_eq!(formatted.len(), OGS_UUID_FORMATTED_LENGTH);
        assert_eq!(formatted, "12345678-9abc-def0-1234-56789abcdef0");
    }

    #[test]
    fn test_uuid_parse() {
        let uuid_str = "12345678-9abc-def0-1234-56789abcdef0";
        let uuid = OgsUuid::parse(uuid_str).unwrap();
        
        assert_eq!(uuid.data[0], 0x12);
        assert_eq!(uuid.data[1], 0x34);
        assert_eq!(uuid.data[15], 0xf0);
    }

    #[test]
    fn test_uuid_round_trip() {
        let original = OgsUuid::new();
        let formatted = original.format();
        let parsed = OgsUuid::parse(&formatted).unwrap();
        
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_uuid_parse_invalid() {
        assert!(OgsUuid::parse("invalid").is_none());
        assert!(OgsUuid::parse("12345678-9abc-def0-1234").is_none());
        assert!(OgsUuid::parse("12345678-9abc-def0-1234-56789abcdefg").is_none());
    }
}
