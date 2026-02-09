//! NextGCore TUN Interface Library
//!
//! This crate provides TUN interface operations for creating and managing
//! TUN/TAP devices on Linux and macOS (utun).

mod types;
mod io;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

pub use types::*;
pub use io::*;

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "macos")]
pub use macos::*;

/// Maximum headroom for TUN packets
/// 
/// Linux:
/// - ogs_tun_read(16bytes): OGS_GTPV1U_5GC_HEADER_LEN(16bytes)
/// - ogs_tun_write(0bytes): No Need for headroom
///
/// Mac OS X:
/// - ogs_tun_read(12bytes): OGS_GTPV1U_5GC_HEADER_LEN(16bytes) - Null/Loopback(4bytes)
/// - ogs_tun_write(4bytes): Null/Loopback(4bytes)
pub const TUN_MAX_HEADROOM: usize = 16;

/// Maximum TUN/TAP device ID to try
pub const TUNTAP_ID_MAX: u32 = 256;

/// Interface name size
pub const IFNAMSIZ: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(TUN_MAX_HEADROOM, 16);
        assert_eq!(TUNTAP_ID_MAX, 256);
        assert_eq!(IFNAMSIZ, 16);
    }

    #[test]
    fn test_tun_error_display() {
        let err = TunError::DeviceNotFound;
        assert!(!format!("{err}").is_empty());
        
        let err = TunError::IoError("test".to_string());
        assert!(format!("{err}").contains("test"));
    }
}
