//! macOS utun device implementation

use crate::types::{IpSubnet, TunDevice, TunError, TunResult};
use crate::TUNTAP_ID_MAX;
use std::process::Command;

/// UTUN control name
const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";

/// Maximum kernel control name length
const MAX_KCTL_NAME: usize = 96;

/// SYSPROTO_CONTROL
const SYSPROTO_CONTROL: libc::c_int = 2;

/// AF_SYS_CONTROL
const AF_SYS_CONTROL: u16 = 2;

/// CTLIOCGINFO ioctl
const CTLIOCGINFO: libc::c_ulong = 0xc0644e03;

/// UTUN_OPT_IFNAME
const UTUN_OPT_IFNAME: libc::c_int = 2;

/// Get errno value
fn get_errno() -> i32 {
    unsafe { *libc::__error() }
}

/// ctl_info structure
#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [libc::c_char; MAX_KCTL_NAME],
}

impl Default for CtlInfo {
    fn default() -> Self {
        Self {
            ctl_id: 0,
            ctl_name: [0; MAX_KCTL_NAME],
        }
    }
}

/// sockaddr_ctl structure
#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

impl Default for SockaddrCtl {
    fn default() -> Self {
        Self {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: 0,
            sc_unit: 0,
            sc_reserved: [0; 5],
        }
    }
}

/// Open a utun device on macOS
fn utun_open(unit: u32) -> TunResult<(i32, String)> {
    // Create a system socket
    let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };

    if fd < 0 {
        let errno = get_errno();
        return Err(TunError::SyscallError(
            errno,
            format!("socket() failed: errno {}", errno),
        ));
    }

    // Get control info
    let mut info = CtlInfo::default();
    let name_bytes = UTUN_CONTROL_NAME.as_bytes();
    for (i, &byte) in name_bytes.iter().enumerate() {
        if i >= MAX_KCTL_NAME - 1 {
            break;
        }
        info.ctl_name[i] = byte as libc::c_char;
    }

    let rc = unsafe { libc::ioctl(fd, CTLIOCGINFO as libc::c_ulong, &mut info as *mut CtlInfo) };

    if rc != 0 {
        let errno = get_errno();
        unsafe { libc::close(fd) };
        return Err(TunError::SyscallError(
            errno,
            format!("ioctl CTLIOCGINFO failed: errno {}", errno),
        ));
    }

    // Connect to the control
    let mut addr = SockaddrCtl::default();
    addr.sc_id = info.ctl_id;
    addr.sc_unit = unit + 1; // utun unit numbers are 1-based

    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const SockaddrCtl as *const libc::sockaddr,
            std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
        )
    };

    if rc != 0 {
        let errno = get_errno();
        unsafe { libc::close(fd) };
        return Err(TunError::SyscallError(
            errno,
            format!("connect() failed: errno {}", errno),
        ));
    }

    // Get the interface name
    let mut ifname = [0u8; 32];
    let mut ifname_len: libc::socklen_t = ifname.len() as libc::socklen_t;

    let rc = unsafe {
        libc::getsockopt(
            fd,
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            ifname.as_mut_ptr() as *mut libc::c_void,
            &mut ifname_len,
        )
    };

    if rc != 0 {
        let errno = get_errno();
        unsafe { libc::close(fd) };
        return Err(TunError::SyscallError(
            errno,
            format!("getsockopt UTUN_OPT_IFNAME failed: errno {}", errno),
        ));
    }

    let name = String::from_utf8_lossy(&ifname[..ifname_len as usize - 1]).to_string();

    Ok((fd, name))
}

/// Open a TUN device on macOS
/// 
/// # Arguments
/// * `_ifname` - Ignored on macOS (utun names are auto-assigned)
/// * `_is_tap` - Ignored on macOS (only TUN is supported via utun)
/// 
/// # Returns
/// A `TunDevice` handle on success
pub fn tun_open(_ifname: &str, _is_tap: bool) -> TunResult<TunDevice> {
    // Try to open utun devices starting from unit 0
    for unit in 0..TUNTAP_ID_MAX {
        match utun_open(unit) {
            Ok((fd, name)) => {
                return Ok(TunDevice::new(fd, name, false));
            }
            Err(_) => continue,
        }
    }

    Err(TunError::DeviceNotFound)
}

/// Set IP address on a TUN interface (macOS)
/// 
/// Uses ifconfig command for IPv6 and ioctl for IPv4.
pub fn tun_set_ip(ifname: &str, gw: &IpSubnet, sub: &IpSubnet) -> TunResult<()> {
    if gw.is_ipv4() {
        tun_set_ipv4(ifname, gw, sub)
    } else if gw.is_ipv6() {
        tun_set_ipv6(ifname, gw, sub)
    } else {
        Err(TunError::InvalidPacket("Unknown address family".to_string()))
    }
}

/// Set IPv4 address on interface
fn tun_set_ipv4(ifname: &str, ipaddr: &IpSubnet, _ipsub: &IpSubnet) -> TunResult<()> {
    // Convert address to string
    let addr_bytes = ipaddr.sub[0].to_be_bytes();
    let addr_str = format!(
        "{}.{}.{}.{}",
        addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]
    );

    // Calculate prefix length from mask
    let mask = u32::from_be(ipaddr.mask[0]);
    let prefix_len = mask.count_ones();

    // Use ifconfig to set the address
    let output = Command::new("/sbin/ifconfig")
        .args([ifname, "inet", &addr_str, &format!("/{}", prefix_len), "up"])
        .output()
        .map_err(|e| TunError::IoError(format!("Failed to run ifconfig: {}", e)))?;

    if !output.status.success() {
        return Err(TunError::IoError(format!(
            "ifconfig failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Set IPv6 address on interface
fn tun_set_ipv6(ifname: &str, ipaddr: &IpSubnet, ipsub: &IpSubnet) -> TunResult<()> {
    // Convert address to string
    let mut addr_bytes = [0u8; 16];
    for i in 0..4 {
        let bytes = ipaddr.sub[i].to_be_bytes();
        addr_bytes[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }

    let addr = std::net::Ipv6Addr::from(addr_bytes);

    // Calculate prefix length from mask
    let mut prefix_len = 0u32;
    for i in 0..4 {
        prefix_len += u32::from_be(ipsub.mask[i]).count_ones();
    }

    let addr_str = format!("{}/{}", addr, prefix_len);

    // Use ifconfig to set the address
    let output = Command::new("/sbin/ifconfig")
        .args([ifname, "inet6", &addr_str, "up"])
        .output()
        .map_err(|e| TunError::IoError(format!("Failed to run ifconfig: {}", e)))?;

    if !output.status.success() {
        return Err(TunError::IoError(format!(
            "ifconfig failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(SYSPROTO_CONTROL, 2);
        assert_eq!(AF_SYS_CONTROL, 2);
    }

    #[test]
    fn test_ctl_info_default() {
        let info = CtlInfo::default();
        assert_eq!(info.ctl_id, 0);
    }

    #[test]
    fn test_sockaddr_ctl_default() {
        let addr = SockaddrCtl::default();
        assert_eq!(addr.sc_family, libc::AF_SYSTEM as u8);
        assert_eq!(addr.ss_sysaddr, AF_SYS_CONTROL);
    }
}
