//! TUN I/O operations (read/write)

use crate::types::{TunDevice, TunError, TunResult};

/// Maximum packet length
pub const MAX_PKT_LEN: usize = 65535;

/// Get errno value (platform-specific)
#[cfg(target_os = "macos")]
fn get_errno() -> i32 {
    unsafe { *libc::__error() }
}

#[cfg(not(target_os = "macos"))]
fn get_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

/// Read a packet from the TUN device
/// 
/// Returns the packet data with appropriate headroom handling for the platform.
/// On macOS, the 4-byte Null/Loopback header is removed.
pub fn tun_read(device: &TunDevice) -> TunResult<Vec<u8>> {
    if device.fd < 0 {
        return Err(TunError::IoError("Invalid file descriptor".to_string()));
    }

    let mut buffer = vec![0u8; MAX_PKT_LEN];
    
    let n = unsafe {
        libc::read(
            device.fd,
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
        )
    };

    if n <= 0 {
        let errno = get_errno();
        return Err(TunError::SyscallError(
            errno,
            format!("read() failed: {}", errno),
        ));
    }

    buffer.truncate(n as usize);

    // On macOS, remove the 4-byte Null/Loopback header
    #[cfg(target_os = "macos")]
    {
        if buffer.len() > 4 {
            buffer.drain(0..4);
        }
    }

    Ok(buffer)
}

/// Write a packet to the TUN device
/// 
/// On macOS, prepends the appropriate address family header.
pub fn tun_write(device: &TunDevice, data: &[u8]) -> TunResult<()> {
    if device.fd < 0 {
        return Err(TunError::IoError("Invalid file descriptor".to_string()));
    }

    if data.is_empty() {
        return Err(TunError::InvalidPacket("Empty packet".to_string()));
    }

    #[cfg(target_os = "macos")]
    let write_data = {
        // Get IP version from first byte
        let version = (data[0] >> 4) & 0x0f;
        
        let family: u32 = match version {
            4 => libc::AF_INET as u32,
            6 => libc::AF_INET6 as u32,
            _ => {
                return Err(TunError::InvalidPacket(format!(
                    "Invalid IP version: {}",
                    version
                )));
            }
        };

        // Prepend the address family header (big-endian)
        let mut buf = Vec::with_capacity(4 + data.len());
        buf.extend_from_slice(&family.to_be_bytes());
        buf.extend_from_slice(data);
        buf
    };

    #[cfg(not(target_os = "macos"))]
    let write_data = data.to_vec();

    let n = unsafe {
        libc::write(
            device.fd,
            write_data.as_ptr() as *const libc::c_void,
            write_data.len(),
        )
    };

    if n <= 0 {
        let errno = get_errno();
        return Err(TunError::SyscallError(
            errno,
            format!("write() failed: {}", errno),
        ));
    }

    Ok(())
}

/// Read a packet with headroom reservation
/// 
/// This is useful when the packet needs to be encapsulated with additional headers.
pub fn tun_read_with_headroom(device: &TunDevice, headroom: usize) -> TunResult<(Vec<u8>, usize)> {
    let packet = tun_read(device)?;
    
    // Create buffer with headroom
    let mut buffer = vec![0u8; headroom + packet.len()];
    buffer[headroom..].copy_from_slice(&packet);
    
    Ok((buffer, headroom))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_pkt_len() {
        assert_eq!(MAX_PKT_LEN, 65535);
    }

    #[test]
    fn test_tun_read_invalid_fd() {
        let device = TunDevice::new(-1, "test".to_string(), false);
        let result = tun_read(&device);
        assert!(result.is_err());
        
        // Prevent drop from closing invalid fd
        std::mem::forget(device);
    }

    #[test]
    fn test_tun_write_invalid_fd() {
        let device = TunDevice::new(-1, "test".to_string(), false);
        let result = tun_write(&device, &[0x45, 0x00]);
        assert!(result.is_err());
        
        // Prevent drop from closing invalid fd
        std::mem::forget(device);
    }

    #[test]
    fn test_tun_write_empty_packet() {
        let device = TunDevice::new(0, "test".to_string(), false);
        let result = tun_write(&device, &[]);
        assert!(matches!(result, Err(TunError::InvalidPacket(_))));
        
        // Prevent drop from closing fd 0
        std::mem::forget(device);
    }
}
