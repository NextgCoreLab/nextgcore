//! Conversion utilities
//!
//! Exact port of lib/core/nextgcore-conv.h and nextgcore-conv.c

/// Convert hex string to bytes (identical to nextgcore_hex_from_string)
pub fn nextgcore_hex_from_string(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return None;
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

/// Convert bytes to hex string (identical to nextgcore_hex_to_string)
pub fn nextgcore_hex_to_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Convert bytes to uppercase hex string
pub fn nextgcore_hex_to_string_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Convert uint24 to bytes (big-endian)
pub fn nextgcore_uint24_to_bytes(value: u32) -> [u8; 3] {
    [
        ((value >> 16) & 0xFF) as u8,
        ((value >> 8) & 0xFF) as u8,
        (value & 0xFF) as u8,
    ]
}

/// Convert bytes to uint24 (big-endian)
pub fn nextgcore_bytes_to_uint24(bytes: &[u8; 3]) -> u32 {
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32)
}

/// Convert uint16 to bytes (big-endian)
pub fn nextgcore_uint16_to_bytes(value: u16) -> [u8; 2] {
    value.to_be_bytes()
}

/// Convert bytes to uint16 (big-endian)
pub fn nextgcore_bytes_to_uint16(bytes: &[u8; 2]) -> u16 {
    u16::from_be_bytes(*bytes)
}

/// Convert uint32 to bytes (big-endian)
pub fn nextgcore_uint32_to_bytes(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

/// Convert bytes to uint32 (big-endian)
pub fn nextgcore_bytes_to_uint32(bytes: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*bytes)
}

/// Convert uint64 to bytes (big-endian)
pub fn nextgcore_uint64_to_bytes(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// Convert bytes to uint64 (big-endian)
pub fn nextgcore_bytes_to_uint64(bytes: &[u8; 8]) -> u64 {
    u64::from_be_bytes(*bytes)
}

/// 24-bit unsigned integer type
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NextgcoreUint24 {
    pub v: u32, // Only lower 24 bits used
}

impl NextgcoreUint24 {
    pub fn new(value: u32) -> Self {
        NextgcoreUint24 {
            v: value & 0xFFFFFF,
        }
    }

    pub fn to_be_bytes(&self) -> [u8; 3] {
        nextgcore_uint24_to_bytes(self.v)
    }

    pub fn from_be_bytes(bytes: [u8; 3]) -> Self {
        NextgcoreUint24 {
            v: nextgcore_bytes_to_uint24(&bytes),
        }
    }
}

impl From<u32> for NextgcoreUint24 {
    fn from(v: u32) -> Self {
        NextgcoreUint24::new(v)
    }
}

impl From<NextgcoreUint24> for u32 {
    fn from(v: NextgcoreUint24) -> Self {
        v.v
    }
}
