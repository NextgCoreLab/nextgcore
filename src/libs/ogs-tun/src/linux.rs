//! Linux TUN/TAP device implementation

use crate::types::{IpSubnet, TunDevice, TunError, TunResult};
use crate::IFNAMSIZ;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

/// Linux TUN device path
const TUN_DEV_PATH: &str = "/dev/net/tun";

/// IFF_TUN flag - TUN device (layer 3)
const IFF_TUN: libc::c_short = 0x0001;

/// IFF_TAP flag - TAP device (layer 2)
const IFF_TAP: libc::c_short = 0x0002;

/// IFF_NO_PI flag - No packet information
const IFF_NO_PI: libc::c_short = 0x1000;

/// TUNSETIFF ioctl command
const TUNSETIFF: libc::c_ulong = 0x400454ca;

/// ifreq structure for ioctl
#[repr(C)]
struct Ifreq {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_flags: libc::c_short,
    _padding: [u8; 22], // Padding to match struct size
}

impl Default for Ifreq {
    fn default() -> Self {
        Self {
            ifr_name: [0; IFNAMSIZ],
            ifr_flags: 0,
            _padding: [0; 22],
        }
    }
}

/// Open a TUN/TAP device on Linux
/// 
/// # Arguments
/// * `ifname` - Desired interface name (e.g., "tun0"). Can be empty for auto-assignment.
/// * `is_tap` - If true, create a TAP device (layer 2), otherwise TUN (layer 3)
/// 
/// # Returns
/// A `TunDevice` handle on success
pub fn tun_open(ifname: &str, is_tap: bool) -> TunResult<TunDevice> {
    // Open /dev/net/tun
    let dev_path = CString::new(TUN_DEV_PATH).unwrap();
    let fd = unsafe { libc::open(dev_path.as_ptr(), libc::O_RDWR) };

    if fd < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(TunError::SyscallError(
            errno,
            format!("Failed to open {}: errno {}", TUN_DEV_PATH, errno),
        ));
    }

    // Prepare ifreq structure
    let mut ifr = Ifreq::default();
    
    // Set flags
    let flags = IFF_NO_PI | if is_tap { IFF_TAP } else { IFF_TUN };
    ifr.ifr_flags = flags;

    // Copy interface name (truncate if too long)
    let name_bytes = ifname.as_bytes();
    let copy_len = std::cmp::min(name_bytes.len(), IFNAMSIZ - 1);
    for (i, &byte) in name_bytes.iter().take(copy_len).enumerate() {
        ifr.ifr_name[i] = byte as libc::c_char;
    }

    // Call ioctl to create the device
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF as libc::c_ulong, &ifr as *const Ifreq) };

    if rc < 0 {
        let errno = unsafe { *libc::__errno_location() };
        unsafe { libc::close(fd) };
        return Err(TunError::SyscallError(
            errno,
            format!(
                "ioctl TUNSETIFF failed for {}: errno {}",
                TUN_DEV_PATH, errno
            ),
        ));
    }

    // Extract the actual interface name
    let actual_name = {
        let name_slice: Vec<u8> = ifr
            .ifr_name
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        String::from_utf8_lossy(&name_slice).to_string()
    };

    Ok(TunDevice::new(fd, actual_name, is_tap))
}

/// Set IP address on a TUN interface
/// 
/// Note: On Linux, this is typically done via netlink or ip command.
/// This function is a placeholder that returns Ok for compatibility.
pub fn tun_set_ip(_ifname: &str, _gw: &IpSubnet, _sub: &IpSubnet) -> TunResult<()> {
    // On Linux, IP configuration is typically done via:
    // - netlink sockets
    // - ip command (ip addr add ...)
    // - ioctl with SIOCSIFADDR
    //
    // For now, we return Ok as the C implementation does
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ifreq_default() {
        let ifr = Ifreq::default();
        assert_eq!(ifr.ifr_flags, 0);
        assert!(ifr.ifr_name.iter().all(|&c| c == 0));
    }

    #[test]
    fn test_flags() {
        assert_eq!(IFF_TUN, 0x0001);
        assert_eq!(IFF_TAP, 0x0002);
        assert_eq!(IFF_NO_PI, 0x1000);
    }
}
