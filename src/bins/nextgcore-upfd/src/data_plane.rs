//! UPF Data Plane Implementation
//!
//! This module implements the actual packet forwarding between GTP-U and TUN interfaces.
//! It handles:
//! - TUN device creation and configuration
//! - GTP-U UDP socket management
//! - Async packet forwarding (uplink/downlink)
//! - NAT/masquerading setup

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::mpsc;

use crate::gtp_path::{parse_gtpu_header, gtpu_msg_type};

// ============================================================================
// Constants
// ============================================================================

/// GTP-U port
pub const GTPU_PORT: u16 = 2152;

/// GTP-U header size (minimum, without extensions)
pub const GTPU_HEADER_SIZE: usize = 8;

/// GTP-U header size with sequence number
pub const GTPU_HEADER_SIZE_WITH_SEQ: usize = 12;

/// Maximum packet size
pub const MAX_PACKET_SIZE: usize = 65535;

/// TUN MTU
pub const TUN_MTU: u32 = 1400;

/// IP version 4
pub const IP_VERSION_4: u8 = 4;

/// IP version 6
pub const IP_VERSION_6: u8 = 6;

// ============================================================================
// TUN Device
// ============================================================================

/// TUN device wrapper
pub struct TunDevice {
    /// File descriptor
    fd: RawFd,
    /// Interface name
    name: String,
    /// Async file handle
    _file: Option<tokio::fs::File>,
}

impl TunDevice {
    /// Create and configure a TUN device
    #[cfg(target_os = "linux")]
    pub fn create(name: &str) -> io::Result<Self> {
        use std::ffi::CString;
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        // Open /dev/net/tun
        let tun_file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open("/dev/net/tun")?;

        let fd = tun_file.as_raw_fd();

        // Set up the interface
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

        // Copy interface name
        let name_cstr = CString::new(name).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Invalid interface name")
        })?;
        let name_bytes = name_cstr.as_bytes_with_nul();
        let copy_len = name_bytes.len().min(libc::IF_NAMESIZE - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                ifr.ifr_name.as_mut_ptr() as *mut u8,
                copy_len,
            );
        }

        // IFF_TUN | IFF_NO_PI (no packet info header)
        ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as i16;

        // Create the device
        let ret = unsafe { libc::ioctl(fd, libc::TUNSETIFF, &ifr) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Get actual interface name (might differ if we used %d pattern)
        let actual_name = unsafe {
            std::ffi::CStr::from_ptr(ifr.ifr_name.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        // Keep the file open by forgetting it (we'll use the fd directly)
        std::mem::forget(tun_file);

        log::info!("Created TUN device: {}", actual_name);

        Ok(Self {
            fd,
            name: actual_name,
            _file: None,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create(_name: &str) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TUN devices only supported on Linux",
        ))
    }

    /// Configure IP address on the TUN device
    #[cfg(target_os = "linux")]
    pub fn configure_ip(&self, addr: Ipv4Addr, prefix_len: u8) -> io::Result<()> {
        use std::process::Command;

        // Use ip command to configure the interface
        let addr_str = format!("{}/{}", addr, prefix_len);

        // Add IP address
        let output = Command::new("ip")
            .args(["addr", "add", &addr_str, "dev", &self.name])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "RTNETLINK answers: File exists" error (address already set)
            if !stderr.contains("File exists") {
                log::warn!("ip addr add failed: {}", stderr);
            }
        }

        // Bring interface up
        let output = Command::new("ip")
            .args(["link", "set", &self.name, "up"])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to bring up interface: {}", stderr),
            ));
        }

        // Set MTU
        let output = Command::new("ip")
            .args(["link", "set", &self.name, "mtu", &TUN_MTU.to_string()])
            .output()?;

        if !output.status.success() {
            log::warn!("Failed to set MTU: {}", String::from_utf8_lossy(&output.stderr));
        }

        log::info!("Configured TUN device {} with IP {}", self.name, addr_str);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn configure_ip(&self, _addr: Ipv4Addr, _prefix_len: u8) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TUN configuration only supported on Linux",
        ))
    }

    /// Set up NAT/masquerading for the subnet
    #[cfg(target_os = "linux")]
    pub fn setup_nat(&self, subnet: Ipv4Addr, prefix_len: u8) -> io::Result<()> {
        use std::process::Command;

        let subnet_str = format!("{}/{}", subnet, prefix_len);

        // Add iptables MASQUERADE rule
        let output = Command::new("iptables")
            .args([
                "-t", "nat",
                "-A", "POSTROUTING",
                "-s", &subnet_str,
                "!", "-o", &self.name,
                "-j", "MASQUERADE",
            ])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!("iptables NAT setup warning: {}", stderr);
        }

        log::info!("NAT configured for subnet {}", subnet_str);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn setup_nat(&self, _subnet: Ipv4Addr, _prefix_len: u8) -> io::Result<()> {
        Ok(()) // No-op on non-Linux
    }

    /// Get the interface name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the raw file descriptor
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Read a packet from the TUN device
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let ret = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    /// Write a packet to the TUN device
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let ret = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
            log::info!("Closed TUN device: {}", self.name);
        }
    }
}

// ============================================================================
// GTP-U Encapsulation/Decapsulation
// ============================================================================

/// Build a GTP-U header for G-PDU
pub fn build_gtpu_header(teid: u32, payload_len: u16) -> [u8; GTPU_HEADER_SIZE] {
    let mut header = [0u8; GTPU_HEADER_SIZE];

    // Version=1, PT=1, no extension/seq/n-pdu flags
    header[0] = 0x30;
    // Message type = G-PDU (255)
    header[1] = gtpu_msg_type::GPDU;
    // Length (payload only, not including header)
    header[2..4].copy_from_slice(&payload_len.to_be_bytes());
    // TEID
    header[4..8].copy_from_slice(&teid.to_be_bytes());

    header
}

/// Build a GTP-U header with sequence number
pub fn build_gtpu_header_with_seq(teid: u32, payload_len: u16, seq: u16) -> [u8; GTPU_HEADER_SIZE_WITH_SEQ] {
    let mut header = [0u8; GTPU_HEADER_SIZE_WITH_SEQ];

    // Version=1, PT=1, S=1 (sequence number present)
    header[0] = 0x32;
    // Message type = G-PDU (255)
    header[1] = gtpu_msg_type::GPDU;
    // Length (payload + 4 bytes for seq/npdu/next)
    let total_len = payload_len + 4;
    header[2..4].copy_from_slice(&total_len.to_be_bytes());
    // TEID
    header[4..8].copy_from_slice(&teid.to_be_bytes());
    // Sequence number
    header[8..10].copy_from_slice(&seq.to_be_bytes());
    // N-PDU number
    header[10] = 0;
    // Next extension header type
    header[11] = 0;

    header
}

/// Build GTP-U Echo Response
pub fn build_gtpu_echo_response(seq: Option<u16>) -> Vec<u8> {
    if let Some(seq_num) = seq {
        let mut pkt = vec![0u8; 12];
        pkt[0] = 0x32; // Version=1, PT=1, S=1
        pkt[1] = gtpu_msg_type::ECHO_RESPONSE;
        pkt[2..4].copy_from_slice(&4u16.to_be_bytes()); // Length
        pkt[4..8].copy_from_slice(&0u32.to_be_bytes()); // TEID=0
        pkt[8..10].copy_from_slice(&seq_num.to_be_bytes());
        pkt[10] = 0; // N-PDU
        pkt[11] = 0; // Next ext
        pkt
    } else {
        let mut pkt = vec![0u8; 8];
        pkt[0] = 0x30; // Version=1, PT=1
        pkt[1] = gtpu_msg_type::ECHO_RESPONSE;
        pkt[2..4].copy_from_slice(&0u16.to_be_bytes()); // Length
        pkt[4..8].copy_from_slice(&0u32.to_be_bytes()); // TEID=0
        pkt
    }
}

// ============================================================================
// Session/TEID Management
// ============================================================================

// ============================================================================
// FAR Apply Action Flags (from 3GPP TS 29.244)
// ============================================================================

/// FAR Apply Action: Forward
pub const FAR_ACTION_FORW: u16 = 0x0002;
/// FAR Apply Action: Drop
pub const FAR_ACTION_DROP: u16 = 0x0001;
/// FAR Apply Action: Buffer
pub const FAR_ACTION_BUFF: u16 = 0x0004;
/// FAR Apply Action: Notify CP
pub const FAR_ACTION_NOCP: u16 = 0x0008;

/// Source interface: Access (uplink from UE/gNB)
pub const SRC_INTF_ACCESS: u8 = 0;
/// Source interface: Core (downlink from DN)
pub const SRC_INTF_CORE: u8 = 1;

// ============================================================================
// PDR / FAR / QER / URR for data plane
// ============================================================================

/// Lightweight PDR for fast-path matching in the data plane
#[derive(Debug, Clone)]
pub struct DataPlanePdr {
    pub pdr_id: u16,
    pub precedence: u32,
    pub source_interface: u8,
    pub far_id: Option<u32>,
    pub qer_id: Option<u32>,
    pub urr_ids: Vec<u32>,
    pub outer_header_removal: Option<u8>,
    /// Compiled SDF filter rule for 5-tuple matching (None = match all)
    pub sdf_rule: Option<ogs_ipfw::IpfwRule>,
}

/// Lightweight FAR for fast-path forwarding in the data plane
#[derive(Debug, Clone)]
pub struct DataPlaneFar {
    pub far_id: u32,
    pub apply_action: u16,
    pub destination_interface: u8,
    /// Outer header creation: DL TEID for GTP-U encap
    pub ohc_teid: Option<u32>,
    /// Outer header creation: peer address
    pub ohc_addr: Option<Ipv4Addr>,
}

// ============================================================================
// Rel-18 QFI→DSCP Mapping (TS 29.281, TS 23.501)
// ============================================================================

/// Map QFI to DSCP value for outer IP header marking in GTP-U tunnel.
///
/// Per 3GPP TS 23.501 Table 5.7.4-1, each 5QI has standardized QoS
/// characteristics that map to DiffServ DSCP values for transport-level
/// QoS enforcement.
pub fn qfi_to_dscp(qfi: u8) -> u8 {
    match qfi {
        1 => 46,  // EF: Conversational voice
        2 => 34,  // AF41: Conversational video
        3 => 26,  // AF31: Real-time gaming
        4 => 24,  // AF21: Non-conversational video
        5 => 0,   // BE: IMS signaling
        6 => 18,  // AF21: Buffered streaming
        7 => 10,  // AF11: Interactive gaming
        8 | 9 => 0, // BE: Default
        65 => 46, // EF: Mission-critical user plane
        66 => 26, // AF31: Non-mission-critical user plane
        82 => 46, // EF: XR cloud rendering DL (Rel-18)
        83 => 46, // EF: XR pose/control UL (Rel-18)
        84 => 34, // AF41: XR split rendering DL (Rel-18)
        85 => 46, // EF: XR haptic feedback (Rel-18)
        _ => 0,   // Unknown → Best Effort
    }
}

/// Apply DSCP marking to an IP packet's TOS/Traffic Class field.
pub fn apply_dscp_to_ip_packet(packet: &mut [u8], dscp: u8) -> bool {
    if packet.is_empty() {
        return false;
    }
    let version = (packet[0] >> 4) & 0x0F;
    match version {
        4 if packet.len() >= 20 => {
            // IPv4: DSCP is in TOS field (byte 1), bits 7:2
            packet[1] = (dscp << 2) | (packet[1] & 0x03);
            true
        }
        6 if packet.len() >= 40 => {
            // IPv6: Traffic Class spans bytes 0-1 (bits 4:11)
            let tc = (dscp << 2) | (packet[1] & 0x03);
            packet[0] = (packet[0] & 0xF0) | ((tc >> 4) & 0x0F);
            packet[1] = ((tc & 0x0F) << 4) | (packet[1] & 0x0F);
            true
        }
        _ => false,
    }
}

// ============================================================================
// Rel-18 Energy Saving State
// ============================================================================

/// Energy saving state for UPF session-level power management.
#[derive(Debug)]
pub struct EnergySavingState {
    /// Last packet forwarded timestamp
    pub last_packet_time: RwLock<std::time::Instant>,
    /// Inactivity threshold before entering low-power (seconds)
    pub inactivity_threshold_secs: u32,
    /// Whether low-power mode is active
    pub low_power_active: AtomicBool,
}

impl EnergySavingState {
    pub fn new(inactivity_threshold_secs: u32) -> Self {
        Self {
            last_packet_time: RwLock::new(std::time::Instant::now()),
            inactivity_threshold_secs,
            low_power_active: AtomicBool::new(false),
        }
    }

    /// Record packet activity (resets inactivity timer).
    pub fn record_activity(&self) {
        *self.last_packet_time.write().unwrap() = std::time::Instant::now();
        self.low_power_active.store(false, Ordering::Relaxed);
    }

    /// Check if session is inactive beyond threshold.
    pub fn check_inactivity(&self) -> bool {
        let last = self.last_packet_time.read().unwrap();
        let inactive = last.elapsed().as_secs() > self.inactivity_threshold_secs as u64;
        if inactive {
            self.low_power_active.store(true, Ordering::Relaxed);
        }
        inactive
    }

    /// Returns whether session is in low-power mode.
    pub fn is_low_power(&self) -> bool {
        self.low_power_active.load(Ordering::Relaxed)
    }
}

impl Clone for EnergySavingState {
    fn clone(&self) -> Self {
        Self {
            last_packet_time: RwLock::new(*self.last_packet_time.read().unwrap()),
            inactivity_threshold_secs: self.inactivity_threshold_secs,
            low_power_active: AtomicBool::new(self.low_power_active.load(Ordering::Relaxed)),
        }
    }
}

/// Lightweight QER for QoS enforcement in the data plane
#[derive(Debug)]
pub struct DataPlaneQer {
    pub qer_id: u32,
    pub ul_gate_open: bool,
    pub dl_gate_open: bool,
    /// Maximum Bit Rate uplink (kbps, 0 = unlimited)
    pub ul_mbr: u64,
    /// Maximum Bit Rate downlink (kbps, 0 = unlimited)
    pub dl_mbr: u64,
    pub qfi: Option<u8>,
    /// DSCP value for outer GTP-U IP header (computed from QFI)
    pub dscp: u8,
    /// Bytes forwarded in current rate window (uplink)
    ul_bytes_in_window: AtomicU64,
    /// Bytes forwarded in current rate window (downlink)
    dl_bytes_in_window: AtomicU64,
    /// Window start time
    window_start: RwLock<std::time::Instant>,
}

impl Clone for DataPlaneQer {
    fn clone(&self) -> Self {
        Self {
            qer_id: self.qer_id,
            ul_gate_open: self.ul_gate_open,
            dl_gate_open: self.dl_gate_open,
            ul_mbr: self.ul_mbr,
            dl_mbr: self.dl_mbr,
            qfi: self.qfi,
            dscp: self.dscp,
            ul_bytes_in_window: AtomicU64::new(self.ul_bytes_in_window.load(Ordering::Relaxed)),
            dl_bytes_in_window: AtomicU64::new(self.dl_bytes_in_window.load(Ordering::Relaxed)),
            window_start: RwLock::new(*self.window_start.read().unwrap()),
        }
    }
}

impl DataPlaneQer {
    pub fn new(qer_id: u32) -> Self {
        Self {
            qer_id,
            ul_gate_open: true,
            dl_gate_open: true,
            ul_mbr: 0,
            dl_mbr: 0,
            qfi: None,
            dscp: 0,
            ul_bytes_in_window: AtomicU64::new(0),
            dl_bytes_in_window: AtomicU64::new(0),
            window_start: RwLock::new(std::time::Instant::now()),
        }
    }

    /// Set QFI and automatically compute DSCP mapping.
    pub fn set_qfi(&mut self, qfi: u8) {
        self.qfi = Some(qfi);
        self.dscp = qfi_to_dscp(qfi);
    }

    /// Check if a packet of given size is within the MBR rate limit.
    /// Returns true if the packet should be allowed.
    pub fn check_rate(&self, bytes: u64, is_uplink: bool) -> bool {
        let mbr = if is_uplink { self.ul_mbr } else { self.dl_mbr };
        if mbr == 0 {
            return true; // Unlimited
        }

        // Simple sliding window: 1-second window, mbr in kbps -> bytes/sec = mbr * 1000 / 8
        let max_bytes_per_sec = mbr * 125; // kbps to bytes/sec
        let window = self.window_start.read().unwrap();
        let elapsed = window.elapsed();

        if elapsed.as_secs() >= 1 {
            // Reset window
            drop(window);
            *self.window_start.write().unwrap() = std::time::Instant::now();
            if is_uplink {
                self.ul_bytes_in_window.store(bytes, Ordering::Relaxed);
            } else {
                self.dl_bytes_in_window.store(bytes, Ordering::Relaxed);
            }
            return true;
        }

        let counter = if is_uplink {
            &self.ul_bytes_in_window
        } else {
            &self.dl_bytes_in_window
        };

        let current = counter.fetch_add(bytes, Ordering::Relaxed) + bytes;
        current <= max_bytes_per_sec
    }
}

/// Lightweight URR for usage reporting in the data plane
#[derive(Debug)]
pub struct DataPlaneUrr {
    pub urr_id: u32,
    pub volume_threshold_total: Option<u64>,
    pub volume_threshold_ul: Option<u64>,
    pub volume_threshold_dl: Option<u64>,
    pub time_threshold_secs: Option<u32>,
    pub measurement_period_secs: Option<u32>,
    /// Accumulated volume since last report
    pub acc_total_bytes: AtomicU64,
    pub acc_ul_bytes: AtomicU64,
    pub acc_dl_bytes: AtomicU64,
    pub acc_total_pkts: AtomicU64,
    pub acc_ul_pkts: AtomicU64,
    pub acc_dl_pkts: AtomicU64,
    /// Timestamp of first packet in this measurement period
    pub first_pkt_time: RwLock<Option<std::time::Instant>>,
    /// Timestamp of last report
    pub last_report_time: RwLock<Option<std::time::Instant>>,
    /// Whether a threshold has been exceeded (needs reporting)
    pub threshold_exceeded: AtomicBool,
}

impl DataPlaneUrr {
    pub fn new(urr_id: u32) -> Self {
        Self {
            urr_id,
            volume_threshold_total: None,
            volume_threshold_ul: None,
            volume_threshold_dl: None,
            time_threshold_secs: None,
            measurement_period_secs: None,
            acc_total_bytes: AtomicU64::new(0),
            acc_ul_bytes: AtomicU64::new(0),
            acc_dl_bytes: AtomicU64::new(0),
            acc_total_pkts: AtomicU64::new(0),
            acc_ul_pkts: AtomicU64::new(0),
            acc_dl_pkts: AtomicU64::new(0),
            first_pkt_time: RwLock::new(None),
            last_report_time: RwLock::new(Some(std::time::Instant::now())),
            threshold_exceeded: AtomicBool::new(false),
        }
    }

    /// Record traffic and check thresholds, returns true if threshold exceeded
    pub fn record(&self, bytes: u64, is_uplink: bool) -> bool {
        let total = self.acc_total_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        self.acc_total_pkts.fetch_add(1, Ordering::Relaxed);

        if is_uplink {
            let ul = self.acc_ul_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
            self.acc_ul_pkts.fetch_add(1, Ordering::Relaxed);
            if let Some(thresh) = self.volume_threshold_ul {
                if ul >= thresh {
                    self.threshold_exceeded.store(true, Ordering::Relaxed);
                    return true;
                }
            }
        } else {
            let dl = self.acc_dl_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
            self.acc_dl_pkts.fetch_add(1, Ordering::Relaxed);
            if let Some(thresh) = self.volume_threshold_dl {
                if dl >= thresh {
                    self.threshold_exceeded.store(true, Ordering::Relaxed);
                    return true;
                }
            }
        }

        // Track first packet time
        {
            let mut fpt = self.first_pkt_time.write().unwrap();
            if fpt.is_none() {
                *fpt = Some(std::time::Instant::now());
            }
        }

        // Check total volume threshold
        if let Some(thresh) = self.volume_threshold_total {
            if total >= thresh {
                self.threshold_exceeded.store(true, Ordering::Relaxed);
                return true;
            }
        }

        // Check time threshold
        if let Some(time_thresh) = self.time_threshold_secs {
            let report_time = self.last_report_time.read().unwrap();
            if let Some(last) = *report_time {
                if last.elapsed().as_secs() >= time_thresh as u64 {
                    self.threshold_exceeded.store(true, Ordering::Relaxed);
                    return true;
                }
            }
        }

        false
    }

    /// Reset counters after generating a report
    pub fn reset_counters(&self) {
        self.acc_total_bytes.store(0, Ordering::Relaxed);
        self.acc_ul_bytes.store(0, Ordering::Relaxed);
        self.acc_dl_bytes.store(0, Ordering::Relaxed);
        self.acc_total_pkts.store(0, Ordering::Relaxed);
        self.acc_ul_pkts.store(0, Ordering::Relaxed);
        self.acc_dl_pkts.store(0, Ordering::Relaxed);
        *self.first_pkt_time.write().unwrap() = None;
        *self.last_report_time.write().unwrap() = Some(std::time::Instant::now());
        self.threshold_exceeded.store(false, Ordering::Relaxed);
    }
}

/// Session entry for data plane forwarding
#[derive(Debug)]
pub struct DataPlaneSession {
    /// UPF SEID (Session Endpoint Identifier) - unique session ID from PFCP
    pub upf_seid: u64,
    /// SMF SEID - peer's session ID
    pub smf_seid: u64,
    /// UE IPv4 address
    pub ue_ipv4: Option<Ipv4Addr>,
    /// Uplink TEID (UPF receives on this TEID)
    pub ul_teid: u32,
    /// Downlink TEID (UPF sends with this TEID)
    pub dl_teid: u32,
    /// gNB/eNB address for downlink
    pub gnb_addr: SocketAddr,
    /// PDU Session ID
    pub pdu_session_id: Option<u8>,
    /// QoS Flow Identifier
    pub qfi: Option<u8>,
    /// Packet counters
    pub ul_packets: AtomicU64,
    pub dl_packets: AtomicU64,
    pub ul_bytes: AtomicU64,
    pub dl_bytes: AtomicU64,
    /// PDR rules (sorted by precedence, lower value = higher priority)
    pub pdrs: RwLock<Vec<DataPlanePdr>>,
    /// FAR rules (keyed by far_id)
    pub fars: RwLock<HashMap<u32, DataPlaneFar>>,
    /// QER rules (keyed by qer_id)
    pub qers: RwLock<HashMap<u32, DataPlaneQer>>,
    /// URR rules (keyed by urr_id)
    pub urrs: RwLock<HashMap<u32, Arc<DataPlaneUrr>>>,
}

/// Data plane session manager
pub struct SessionManager {
    /// UPF SEID -> Session mapping (primary key)
    seid_map: RwLock<HashMap<u64, Arc<DataPlaneSession>>>,
    /// UL TEID -> Session mapping
    ul_teid_map: RwLock<HashMap<u32, Arc<DataPlaneSession>>>,
    /// UE IP -> Session mapping
    ue_ip_map: RwLock<HashMap<Ipv4Addr, Arc<DataPlaneSession>>>,
    /// Next TEID to allocate
    next_teid: AtomicU64,
    /// Next SEID to allocate
    next_seid: AtomicU64,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            seid_map: RwLock::new(HashMap::new()),
            ul_teid_map: RwLock::new(HashMap::new()),
            ue_ip_map: RwLock::new(HashMap::new()),
            next_teid: AtomicU64::new(1),
            next_seid: AtomicU64::new(1),
        }
    }

    /// Allocate a new TEID
    pub fn allocate_teid(&self) -> u32 {
        self.next_teid.fetch_add(1, Ordering::SeqCst) as u32
    }

    /// Allocate a new SEID
    pub fn allocate_seid(&self) -> u64 {
        self.next_seid.fetch_add(1, Ordering::SeqCst)
    }

    /// Add a session
    pub fn add_session(&self, session: DataPlaneSession) -> Arc<DataPlaneSession> {
        let session = Arc::new(session);

        // Add to SEID map
        {
            let mut seid_map = self.seid_map.write().unwrap();
            seid_map.insert(session.upf_seid, session.clone());
        }

        // Add to UL TEID map
        {
            let mut ul_map = self.ul_teid_map.write().unwrap();
            ul_map.insert(session.ul_teid, session.clone());
        }

        // Add to UE IP map
        if let Some(ip) = session.ue_ipv4 {
            let mut ip_map = self.ue_ip_map.write().unwrap();
            ip_map.insert(ip, session.clone());
        }

        log::info!(
            "Session added: SEID={:#x}, UL_TEID={:#x}, DL_TEID={:#x}, UE_IP={:?}, gNB={}",
            session.upf_seid, session.ul_teid, session.dl_teid, session.ue_ipv4, session.gnb_addr
        );

        session
    }

    /// Find session by UPF SEID
    pub fn find_by_seid(&self, seid: u64) -> Option<Arc<DataPlaneSession>> {
        let map = self.seid_map.read().unwrap();
        map.get(&seid).cloned()
    }

    /// Find session by uplink TEID
    pub fn find_by_ul_teid(&self, teid: u32) -> Option<Arc<DataPlaneSession>> {
        let map = self.ul_teid_map.read().unwrap();
        map.get(&teid).cloned()
    }

    /// Find session by UE IP
    pub fn find_by_ue_ip(&self, ip: Ipv4Addr) -> Option<Arc<DataPlaneSession>> {
        let map = self.ue_ip_map.read().unwrap();
        map.get(&ip).cloned()
    }

    /// Update session downlink info (called when gNB provides DL TEID)
    pub fn update_session_dl(&self, seid: u64, dl_teid: u32, gnb_addr: SocketAddr) -> bool {
        if let Some(_session) = self.find_by_seid(seid) {
            // We need to create a new session with updated values since Arc<DataPlaneSession>
            // For simplicity, remove old and add new with updated values
            // In production, use interior mutability (Mutex/RwLock inside DataPlaneSession)
            log::info!(
                "Session update: SEID={seid:#x}, new DL_TEID={dl_teid:#x}, gNB={gnb_addr}"
            );
            true
        } else {
            log::warn!("Session not found for update: SEID={seid:#x}");
            false
        }
    }

    /// Remove a session by SEID
    pub fn remove_session_by_seid(&self, seid: u64) -> bool {
        let session = {
            let mut seid_map = self.seid_map.write().unwrap();
            seid_map.remove(&seid)
        };

        if let Some(sess) = session {
            // Remove from TEID map
            {
                let mut ul_map = self.ul_teid_map.write().unwrap();
                ul_map.remove(&sess.ul_teid);
            }

            // Remove from IP map
            if let Some(ip) = sess.ue_ipv4 {
                let mut ip_map = self.ue_ip_map.write().unwrap();
                ip_map.remove(&ip);
            }

            log::info!("Session removed: SEID={seid:#x}");
            true
        } else {
            log::warn!("Session not found for removal: SEID={seid:#x}");
            false
        }
    }

    /// Remove a session by UL TEID (legacy)
    pub fn remove_session(&self, ul_teid: u32) {
        let session = {
            let mut ul_map = self.ul_teid_map.write().unwrap();
            ul_map.remove(&ul_teid)
        };

        if let Some(sess) = session {
            // Remove from SEID map
            {
                let mut seid_map = self.seid_map.write().unwrap();
                seid_map.remove(&sess.upf_seid);
            }

            // Remove from IP map
            if let Some(ip) = sess.ue_ipv4 {
                let mut ip_map = self.ue_ip_map.write().unwrap();
                ip_map.remove(&ip);
            }
        }
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.seid_map.read().unwrap().len()
    }

    /// Get all session stats for reporting
    /// Returns: (upf_seid, ue_ip, ul_packets, dl_packets, ul_bytes, dl_bytes)
    pub fn get_all_session_stats(&self) -> Vec<(u64, Option<Ipv4Addr>, u64, u64, u64, u64)> {
        let map = self.seid_map.read().unwrap();
        map.values()
            .map(|s| {
                (
                    s.upf_seid,
                    s.ue_ipv4,
                    s.ul_packets.load(Ordering::Relaxed),
                    s.dl_packets.load(Ordering::Relaxed),
                    s.ul_bytes.load(Ordering::Relaxed),
                    s.dl_bytes.load(Ordering::Relaxed),
                )
            })
            .collect()
    }
}

/// Packet 5-tuple for SDF filter matching
#[derive(Debug, Clone, Copy)]
pub struct PacketTuple {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

impl PacketTuple {
    /// Extract 5-tuple from an IPv4 packet payload (starting at IP header)
    pub fn from_ipv4_packet(ip_payload: &[u8]) -> Option<Self> {
        if ip_payload.len() < 20 {
            return None;
        }
        let ihl = ((ip_payload[0] & 0x0F) as usize) * 4;
        let protocol = ip_payload[9];
        let src_ip = u32::from_be_bytes([ip_payload[12], ip_payload[13], ip_payload[14], ip_payload[15]]);
        let dst_ip = u32::from_be_bytes([ip_payload[16], ip_payload[17], ip_payload[18], ip_payload[19]]);

        // Extract ports for TCP (6) and UDP (17)
        let (src_port, dst_port) = if (protocol == 6 || protocol == 17) && ip_payload.len() >= ihl + 4 {
            let sp = u16::from_be_bytes([ip_payload[ihl], ip_payload[ihl + 1]]);
            let dp = u16::from_be_bytes([ip_payload[ihl + 2], ip_payload[ihl + 3]]);
            (sp, dp)
        } else {
            (0, 0)
        };

        Some(PacketTuple { src_ip, dst_ip, protocol, src_port, dst_port })
    }

    /// Check if this packet matches an IpfwRule
    fn matches_rule(&self, rule: &ogs_ipfw::IpfwRule) -> bool {
        // Check protocol (0 = any)
        if rule.proto != 0 && rule.proto != self.protocol {
            return false;
        }
        // Check source IP (if specified)
        if rule.ipv4_src {
            if (self.src_ip & rule.ip.src.mask[0]) != (rule.ip.src.addr[0] & rule.ip.src.mask[0]) {
                return false;
            }
        }
        // Check destination IP (if specified)
        if rule.ipv4_dst {
            if (self.dst_ip & rule.ip.dst.mask[0]) != (rule.ip.dst.addr[0] & rule.ip.dst.mask[0]) {
                return false;
            }
        }
        // Check source port range (if specified)
        if !rule.port.src.is_empty() {
            if self.src_port < rule.port.src.low || self.src_port > rule.port.src.high {
                return false;
            }
        }
        // Check destination port range (if specified)
        if !rule.port.dst.is_empty() {
            if self.dst_port < rule.port.dst.low || self.dst_port > rule.port.dst.high {
                return false;
            }
        }
        true
    }
}

impl DataPlaneSession {
    /// Find the best matching PDR for a packet direction with optional 5-tuple matching
    /// Returns (far_id, qer_id, urr_ids, outer_header_removal)
    pub fn match_pdr(&self, source_interface: u8) -> Option<(Option<u32>, Option<u32>, Vec<u32>, Option<u8>)> {
        self.match_pdr_with_packet(source_interface, None)
    }

    /// Find the best matching PDR with SDF filter matching against packet tuple
    pub fn match_pdr_with_packet(
        &self,
        source_interface: u8,
        packet: Option<&PacketTuple>,
    ) -> Option<(Option<u32>, Option<u32>, Vec<u32>, Option<u8>)> {
        let pdrs = self.pdrs.read().unwrap();
        // PDRs are sorted by precedence (lower = higher priority)
        for pdr in pdrs.iter() {
            if pdr.source_interface != source_interface {
                continue;
            }
            // SDF filter matching: if rule present, packet must match
            if let Some(ref rule) = pdr.sdf_rule {
                if let Some(pkt) = packet {
                    if !pkt.matches_rule(rule) {
                        continue;
                    }
                }
                // If no packet info provided, skip SDF-filtered PDRs
                // (fall through to wildcard PDRs)
            }
            return Some((pdr.far_id, pdr.qer_id, pdr.urr_ids.clone(), pdr.outer_header_removal));
        }
        None
    }

    /// Look up a FAR and determine if the packet should be forwarded
    /// Returns: (should_forward, dl_teid, peer_addr)
    pub fn apply_far(&self, far_id: u32) -> (bool, Option<u32>, Option<Ipv4Addr>) {
        let fars = self.fars.read().unwrap();
        if let Some(far) = fars.get(&far_id) {
            if far.apply_action & FAR_ACTION_DROP != 0 {
                return (false, None, None);
            }
            if far.apply_action & FAR_ACTION_FORW != 0 {
                return (true, far.ohc_teid, far.ohc_addr);
            }
            // BUFF or NOCP - don't forward
            (false, None, None)
        } else {
            // No FAR found - default forward
            (true, None, None)
        }
    }

    /// Check QER gate status and MBR for the given direction.
    /// Returns true if traffic is allowed (gate open and within rate limit).
    pub fn check_qer_gate(&self, qer_id: u32, is_uplink: bool, pkt_bytes: u64) -> bool {
        let qers = self.qers.read().unwrap();
        if let Some(qer) = qers.get(&qer_id) {
            // Check gate status
            let gate_open = if is_uplink { qer.ul_gate_open } else { qer.dl_gate_open };
            if !gate_open {
                return false;
            }
            // Check MBR rate limit
            qer.check_rate(pkt_bytes, is_uplink)
        } else {
            true // No QER means open
        }
    }

    /// Record traffic in all matching URRs. Returns true if any threshold exceeded.
    pub fn record_urrs(&self, urr_ids: &[u32], bytes: u64, is_uplink: bool) -> bool {
        let urrs = self.urrs.read().unwrap();
        let mut any_exceeded = false;
        for urr_id in urr_ids {
            if let Some(urr) = urrs.get(urr_id) {
                if urr.record(bytes, is_uplink) {
                    any_exceeded = true;
                }
            }
        }
        any_exceeded
    }

    /// Check if any URR has a threshold exceeded
    pub fn has_urr_threshold_exceeded(&self) -> Vec<u32> {
        let urrs = self.urrs.read().unwrap();
        urrs.iter()
            .filter(|(_, urr)| urr.threshold_exceeded.load(Ordering::Relaxed))
            .map(|(id, _)| *id)
            .collect()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Data Plane Context
// ============================================================================

/// Data plane runtime context
pub struct DataPlane {
    /// TUN device
    pub tun: Option<TunDevice>,
    /// GTP-U socket
    pub gtpu_socket: Option<Arc<TokioUdpSocket>>,
    /// Session manager
    pub sessions: SessionManager,
    /// Shutdown flag
    pub shutdown: Arc<AtomicBool>,
    /// Statistics
    pub stats: DataPlaneStats,
}

/// Data plane statistics
pub struct DataPlaneStats {
    pub ul_packets: AtomicU64,
    pub dl_packets: AtomicU64,
    pub ul_bytes: AtomicU64,
    pub dl_bytes: AtomicU64,
    pub dropped_packets: AtomicU64,
}

impl Default for DataPlaneStats {
    fn default() -> Self {
        Self {
            ul_packets: AtomicU64::new(0),
            dl_packets: AtomicU64::new(0),
            ul_bytes: AtomicU64::new(0),
            dl_bytes: AtomicU64::new(0),
            dropped_packets: AtomicU64::new(0),
        }
    }
}

impl DataPlane {
    /// Create a new data plane context
    pub fn new(shutdown: Arc<AtomicBool>) -> Self {
        Self {
            tun: None,
            gtpu_socket: None,
            sessions: SessionManager::new(),
            shutdown,
            stats: DataPlaneStats::default(),
        }
    }

    /// Initialize the data plane
    pub async fn init(
        &mut self,
        tun_name: &str,
        tun_ip: Ipv4Addr,
        tun_prefix: u8,
        gtpu_addr: SocketAddr,
    ) -> io::Result<()> {
        // Create TUN device
        log::info!("Creating TUN device: {tun_name}");
        let tun = TunDevice::create(tun_name)?;

        // Configure IP
        log::info!("Configuring TUN IP: {tun_ip}/{tun_prefix}");
        tun.configure_ip(tun_ip, tun_prefix)?;

        // Setup NAT for UE subnet
        let subnet = Ipv4Addr::new(
            tun_ip.octets()[0],
            tun_ip.octets()[1],
            0,
            0,
        );
        log::info!("Setting up NAT for subnet: {subnet}/{tun_prefix}");
        tun.setup_nat(subnet, tun_prefix)?;

        self.tun = Some(tun);

        // Create GTP-U socket
        log::info!("Binding GTP-U socket on {gtpu_addr}");
        let socket = TokioUdpSocket::bind(gtpu_addr).await?;
        self.gtpu_socket = Some(Arc::new(socket));

        log::info!("Data plane initialized");
        Ok(())
    }

    /// Run the data plane forwarding loops
    pub async fn run(&self) -> io::Result<()> {
        let tun = self.tun.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "TUN device not initialized")
        })?;
        let gtpu = self.gtpu_socket.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "GTP-U socket not initialized")
        })?;

        // Clone for the tasks
        let tun_fd = tun.fd();
        let gtpu_clone = gtpu.clone();
        let shutdown = self.shutdown.clone();
        let stats = &self.stats;

        // Create channels for packet forwarding
        let (ul_tx, mut ul_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1000);
        let (dl_tx, mut dl_rx) = mpsc::channel::<Vec<u8>>(1000);

        // Spawn GTP-U receive task (uplink: gNB -> UPF -> TUN)
        let gtpu_recv = gtpu_clone.clone();
        let ul_tx_clone = ul_tx.clone();
        let shutdown_ul = shutdown.clone();

        let gtpu_recv_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            log::info!("GTP-U receive task started");
            loop {
                if shutdown_ul.load(Ordering::Relaxed) {
                    break;
                }

                match gtpu_recv.recv_from(&mut buf).await {
                    Ok((len, from)) => {
                        if len > 0 {
                            log::debug!("GTP-U received {len} bytes from {from}");
                            let _ = ul_tx_clone.send((buf[..len].to_vec(), from)).await;
                        }
                    }
                    Err(e) => {
                        if e.kind() != io::ErrorKind::WouldBlock {
                            log::error!("GTP-U recv error: {e}");
                        }
                    }
                }
            }
        });

        // Spawn TUN read task (downlink: TUN -> UPF -> gNB)
        let shutdown_dl = shutdown.clone();
        let dl_tx_clone = dl_tx.clone();

        let tun_read_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            loop {
                if shutdown_dl.load(Ordering::Relaxed) {
                    break;
                }

                // Use non-blocking read with poll
                let ret = unsafe {
                    libc::read(tun_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };

                if ret > 0 {
                    let _ = dl_tx_clone.send(buf[..ret as usize].to_vec()).await;
                } else if ret < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() != io::ErrorKind::WouldBlock {
                        log::error!("TUN read error: {err}");
                    }
                    // Small delay on would-block to prevent busy loop
                    tokio::time::sleep(tokio::time::Duration::from_micros(100)).await;
                }
            }
        });

        // Process uplink packets (GTP-U -> TUN)
        let gtpu_send = gtpu_clone.clone();
        let shutdown_proc_ul = shutdown.clone();

        loop {
            if shutdown_proc_ul.load(Ordering::Relaxed) {
                break;
            }

            tokio::select! {
                // Handle uplink packets from GTP-U
                Some((pkt, from)) = ul_rx.recv() => {
                    self.handle_uplink_packet(&pkt, from, tun_fd).await;
                }

                // Handle downlink packets from TUN
                Some(pkt) = dl_rx.recv() => {
                    self.handle_downlink_packet(&pkt, &gtpu_send).await;
                }

                // Periodic stats logging
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
                    let ul = stats.ul_packets.load(Ordering::Relaxed);
                    let dl = stats.dl_packets.load(Ordering::Relaxed);
                    log::info!("Data plane stats: UL={ul} pkts, DL={dl} pkts");
                }
            }
        }

        // Cleanup
        gtpu_recv_task.abort();
        tun_read_task.abort();

        Ok(())
    }

    /// Handle uplink packet (from gNB via GTP-U, to TUN)
    async fn handle_uplink_packet(&self, pkt: &[u8], from: SocketAddr, tun_fd: RawFd) {
        // Parse GTP-U header
        let header = match parse_gtpu_header(pkt) {
            Ok(h) => h,
            Err(e) => {
                log::debug!("Failed to parse GTP-U header: {e:?}");
                self.stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

        match header.msg_type {
            gtpu_msg_type::ECHO_REQUEST => {
                log::debug!("GTP-U Echo Request from {from}");
                let response = build_gtpu_echo_response(header.seq_num);
                if let Some(sock) = &self.gtpu_socket {
                    let _ = sock.send_to(&response, from).await;
                }
                return;
            }
            gtpu_msg_type::GPDU => {
                // Process G-PDU below
            }
            _ => {
                log::debug!("Ignoring GTP-U message type {}", header.msg_type);
                return;
            }
        }

        // Extract IP payload
        if pkt.len() <= header.header_len {
            self.stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let ip_payload = &pkt[header.header_len..];
        let payload_len = ip_payload.len() as u64;

        // Look up session by UL TEID first, then by source IP
        let session = self.sessions.find_by_ul_teid(header.teid).or_else(|| {
            if ip_payload.len() >= 20 {
                let ip_version = (ip_payload[0] >> 4) & 0x0F;
                if ip_version == IP_VERSION_4 {
                    let src_ip = Ipv4Addr::new(
                        ip_payload[12], ip_payload[13], ip_payload[14], ip_payload[15],
                    );
                    self.sessions.find_by_ue_ip(src_ip)
                } else {
                    None
                }
            } else {
                None
            }
        });

        // Auto-learn session if not found
        let session = match session {
            Some(s) => s,
            None => {
                if ip_payload.len() >= 20 {
                    let ip_version = (ip_payload[0] >> 4) & 0x0F;
                    if ip_version == IP_VERSION_4 {
                        let src_ip = Ipv4Addr::new(
                            ip_payload[12], ip_payload[13], ip_payload[14], ip_payload[15],
                        );
                        let upf_seid = self.sessions.allocate_seid();
                        let new_sess = DataPlaneSession {
                            upf_seid,
                            smf_seid: 0,
                            ue_ipv4: Some(src_ip),
                            ul_teid: header.teid,
                            dl_teid: header.teid,
                            gnb_addr: from,
                            pdu_session_id: None,
                            qfi: None,
                            ul_packets: AtomicU64::new(0),
                            dl_packets: AtomicU64::new(0),
                            ul_bytes: AtomicU64::new(0),
                            dl_bytes: AtomicU64::new(0),
                            pdrs: RwLock::new(Vec::new()),
                            fars: RwLock::new(HashMap::new()),
                            qers: RwLock::new(HashMap::new()),
                            urrs: RwLock::new(HashMap::new()),
                        };
                        let arc = self.sessions.add_session(new_sess);
                        log::info!("Auto-learned session: UE={}, TEID=0x{:x}, gNB={}", src_ip, header.teid, from);
                        arc
                    } else {
                        self.stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                } else {
                    self.stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        };

        // --- PDR matching (uplink: source_interface = Access) ---
        let pkt_tuple = PacketTuple::from_ipv4_packet(ip_payload);
        let mut dscp_to_apply: Option<u8> = None;
        if let Some((far_id, qer_id, urr_ids, _ohr)) = session.match_pdr_with_packet(SRC_INTF_ACCESS, pkt_tuple.as_ref()) {
            // Check QER gate and extract DSCP
            if let Some(qid) = qer_id {
                if !session.check_qer_gate(qid, true, payload_len) {
                    log::debug!("UL packet dropped by QER gate (qer_id={qid})");
                    self.stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                // Get DSCP from QER for marking
                let qers = session.qers.read().unwrap();
                if let Some(qer) = qers.get(&qid) {
                    if qer.dscp != 0 {
                        dscp_to_apply = Some(qer.dscp);
                    }
                }
            }

            // Apply FAR
            if let Some(fid) = far_id {
                let (should_forward, _, _) = session.apply_far(fid);
                if !should_forward {
                    log::debug!("UL packet dropped by FAR (far_id={fid})");
                    self.stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }

            // Record URR usage
            if !urr_ids.is_empty() {
                session.record_urrs(&urr_ids, payload_len, true);
            }
        }
        // If no PDR matches, default to forwarding (pass-through)

        // Apply DSCP marking to inner IP packet before writing to TUN
        let ip_payload = if let Some(dscp) = dscp_to_apply {
            let mut marked = ip_payload.to_vec();
            apply_dscp_to_ip_packet(&mut marked, dscp);
            marked
        } else {
            ip_payload.to_vec()
        };

        // Write to TUN device (decapsulated uplink)
        let ret = unsafe {
            libc::write(tun_fd, ip_payload.as_ptr() as *const libc::c_void, ip_payload.len())
        };

        if ret < 0 {
            log::error!("TUN write failed: {}", io::Error::last_os_error());
            self.stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
        } else {
            session.ul_packets.fetch_add(1, Ordering::Relaxed);
            session.ul_bytes.fetch_add(payload_len, Ordering::Relaxed);
            self.stats.ul_packets.fetch_add(1, Ordering::Relaxed);
            self.stats.ul_bytes.fetch_add(payload_len, Ordering::Relaxed);
            log::trace!("UL: {} bytes from {} TEID=0x{:x}", payload_len, from, header.teid);
        }
    }

    /// Handle downlink packet (from TUN, to gNB via GTP-U)
    async fn handle_downlink_packet(&self, pkt: &[u8], gtpu: &TokioUdpSocket) {
        if pkt.is_empty() {
            return;
        }

        let ip_version = (pkt[0] >> 4) & 0x0F;
        let payload_len = pkt.len() as u64;

        let dst_ip = match ip_version {
            IP_VERSION_4 if pkt.len() >= 20 => {
                Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
            }
            _ => None,
        };

        // Find session by destination UE IP
        let session = dst_ip.and_then(|ip| self.sessions.find_by_ue_ip(ip));

        let mut dscp_to_apply: Option<u8> = None;
        let dl_pkt_tuple = if ip_version == IP_VERSION_4 { PacketTuple::from_ipv4_packet(pkt) } else { None };
        let (dl_teid, gnb_addr) = if let Some(ref sess) = session {
            // --- PDR matching (downlink: source_interface = Core) ---
            if let Some((far_id, qer_id, urr_ids, _ohr)) = sess.match_pdr_with_packet(SRC_INTF_CORE, dl_pkt_tuple.as_ref()) {
                // Check QER gate and extract DSCP
                if let Some(qid) = qer_id {
                    if !sess.check_qer_gate(qid, false, payload_len) {
                        log::debug!("DL packet dropped by QER gate (qer_id={qid})");
                        self.stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    // Get DSCP from QER for marking
                    let qers = sess.qers.read().unwrap();
                    if let Some(qer) = qers.get(&qid) {
                        if qer.dscp != 0 {
                            dscp_to_apply = Some(qer.dscp);
                        }
                    }
                }

                // Apply FAR - may override dl_teid/gnb_addr from outer header creation
                if let Some(fid) = far_id {
                    let (should_forward, ohc_teid, ohc_addr) = sess.apply_far(fid);
                    if !should_forward {
                        log::debug!("DL packet dropped by FAR (far_id={fid})");
                        self.stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    // Use FAR outer header creation values if present, otherwise session defaults
                    let teid = ohc_teid.unwrap_or(sess.dl_teid);
                    let addr = ohc_addr
                        .map(|ip| SocketAddr::new(IpAddr::V4(ip), GTPU_PORT))
                        .unwrap_or(sess.gnb_addr);

                    // Record URR usage
                    if !urr_ids.is_empty() {
                        sess.record_urrs(&urr_ids, payload_len, false);
                    }

                    (teid, addr)
                } else {
                    if !urr_ids.is_empty() {
                        sess.record_urrs(&urr_ids, payload_len, false);
                    }
                    (sess.dl_teid, sess.gnb_addr)
                }
            } else {
                // No matching PDR, use session defaults
                (sess.dl_teid, sess.gnb_addr)
            }
        } else {
            // No session found - drop in production, use default for testing
            log::trace!("No session for DL packet to {dst_ip:?}");
            let default_teid = 1u32;
            let default_gnb = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(172, 23, 0, 100)),
                GTPU_PORT,
            );
            (default_teid, default_gnb)
        };

        // Apply DSCP marking to inner IP packet before GTP-U encapsulation
        let marked_pkt = if let Some(dscp) = dscp_to_apply {
            let mut marked = pkt.to_vec();
            apply_dscp_to_ip_packet(&mut marked, dscp);
            marked
        } else {
            pkt.to_vec()
        };

        // Build GTP-U encapsulated packet
        let gtpu_header = build_gtpu_header(dl_teid, marked_pkt.len() as u16);
        let mut gtpu_pkt = Vec::with_capacity(GTPU_HEADER_SIZE + marked_pkt.len());
        gtpu_pkt.extend_from_slice(&gtpu_header);
        gtpu_pkt.extend_from_slice(&marked_pkt);

        // Send to gNB
        match gtpu.send_to(&gtpu_pkt, gnb_addr).await {
            Ok(_) => {
                if let Some(ref sess) = session {
                    sess.dl_packets.fetch_add(1, Ordering::Relaxed);
                    sess.dl_bytes.fetch_add(payload_len, Ordering::Relaxed);
                }
                self.stats.dl_packets.fetch_add(1, Ordering::Relaxed);
                self.stats.dl_bytes.fetch_add(payload_len, Ordering::Relaxed);
                log::trace!("DL: {payload_len} bytes to {gnb_addr} TEID=0x{dl_teid:x}");
            }
            Err(e) => {
                log::error!("GTP-U send failed: {e}");
                self.stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Add a session from PFCP
    pub fn add_session_from_pfcp(
        &self,
        upf_seid: u64,
        smf_seid: u64,
        ue_ip: Ipv4Addr,
        ul_teid: u32,
        dl_teid: u32,
        gnb_addr: SocketAddr,
        pdu_session_id: Option<u8>,
        qfi: Option<u8>,
    ) {
        // Create default PDRs: uplink (Access->Core) and downlink (Core->Access)
        let mut pdrs = vec![
            DataPlanePdr {
                pdr_id: 1,
                precedence: 100,
                source_interface: SRC_INTF_ACCESS,
                far_id: Some(1),
                qer_id: None,
                urr_ids: Vec::new(),
                outer_header_removal: Some(0), // GTP-U/UDP/IPv4
                sdf_rule: None, // match all
            },
            DataPlanePdr {
                pdr_id: 2,
                precedence: 100,
                source_interface: SRC_INTF_CORE,
                far_id: Some(2),
                qer_id: None,
                urr_ids: Vec::new(),
                outer_header_removal: None,
                sdf_rule: None, // match all
            },
        ];
        pdrs.sort_by_key(|p| p.precedence);

        // Default FARs: UL forward (to core), DL forward (to access with GTP-U encap)
        let mut fars = HashMap::new();
        fars.insert(1, DataPlaneFar {
            far_id: 1,
            apply_action: FAR_ACTION_FORW,
            destination_interface: SRC_INTF_CORE,
            ohc_teid: None,
            ohc_addr: None,
        });
        fars.insert(2, DataPlaneFar {
            far_id: 2,
            apply_action: FAR_ACTION_FORW,
            destination_interface: SRC_INTF_ACCESS,
            ohc_teid: Some(dl_teid),
            ohc_addr: match gnb_addr.ip() {
                IpAddr::V4(ip) => Some(ip),
                _ => None,
            },
        });

        let session = DataPlaneSession {
            upf_seid,
            smf_seid,
            ue_ipv4: Some(ue_ip),
            ul_teid,
            dl_teid,
            gnb_addr,
            pdu_session_id,
            qfi,
            ul_packets: AtomicU64::new(0),
            dl_packets: AtomicU64::new(0),
            ul_bytes: AtomicU64::new(0),
            dl_bytes: AtomicU64::new(0),
            pdrs: RwLock::new(pdrs),
            fars: RwLock::new(fars),
            qers: RwLock::new(HashMap::new()),
            urrs: RwLock::new(HashMap::new()),
        };

        self.sessions.add_session(session);
        log::info!(
            "Added data plane session: SEID={upf_seid:#x}, SMF_SEID={smf_seid:#x}, UE={ue_ip}, UL_TEID=0x{ul_teid:x}, DL_TEID=0x{dl_teid:x}, gNB={gnb_addr}, PDU={pdu_session_id:?}, QFI={qfi:?}"
        );
    }

    /// Update a session from PFCP modification
    pub fn update_session_from_pfcp(
        &self,
        upf_seid: u64,
        dl_teid: Option<u32>,
        gnb_addr: Option<SocketAddr>,
    ) {
        if let Some(session) = self.sessions.find_by_seid(upf_seid) {
            let new_dl_teid = dl_teid.unwrap_or(session.dl_teid);
            let new_gnb_addr = gnb_addr.unwrap_or(session.gnb_addr);

            // Update the downlink FAR's outer header creation if present
            if dl_teid.is_some() || gnb_addr.is_some() {
                let mut fars = session.fars.write().unwrap();
                // Update any FAR targeting access interface (downlink)
                for far in fars.values_mut() {
                    if far.destination_interface == SRC_INTF_ACCESS {
                        if let Some(teid) = dl_teid {
                            far.ohc_teid = Some(teid);
                        }
                        if let Some(addr) = gnb_addr {
                            if let IpAddr::V4(ip) = addr.ip() {
                                far.ohc_addr = Some(ip);
                            }
                        }
                    }
                }
            }

            // Remove and re-add to update the immutable fields
            let pdrs = std::mem::take(&mut *session.pdrs.write().unwrap());
            let fars_map = std::mem::take(&mut *session.fars.write().unwrap());
            let qers_map = std::mem::take(&mut *session.qers.write().unwrap());
            let urrs_map = std::mem::take(&mut *session.urrs.write().unwrap());

            self.sessions.remove_session_by_seid(upf_seid);

            let new_session = DataPlaneSession {
                upf_seid: session.upf_seid,
                smf_seid: session.smf_seid,
                ue_ipv4: session.ue_ipv4,
                ul_teid: session.ul_teid,
                dl_teid: new_dl_teid,
                gnb_addr: new_gnb_addr,
                pdu_session_id: session.pdu_session_id,
                qfi: session.qfi,
                ul_packets: AtomicU64::new(session.ul_packets.load(Ordering::Relaxed)),
                dl_packets: AtomicU64::new(session.dl_packets.load(Ordering::Relaxed)),
                ul_bytes: AtomicU64::new(session.ul_bytes.load(Ordering::Relaxed)),
                dl_bytes: AtomicU64::new(session.dl_bytes.load(Ordering::Relaxed)),
                pdrs: RwLock::new(pdrs),
                fars: RwLock::new(fars_map),
                qers: RwLock::new(qers_map),
                urrs: RwLock::new(urrs_map),
            };

            self.sessions.add_session(new_session);
            log::info!(
                "Updated data plane session: SEID={upf_seid:#x}, DL_TEID=0x{new_dl_teid:x}, gNB={new_gnb_addr}"
            );
        } else {
            log::warn!("Session not found for SEID {upf_seid:#x} during update");
        }
    }

    /// Remove a session from PFCP deletion
    pub fn remove_session_from_pfcp(&self, upf_seid: u64) {
        if self.sessions.remove_session_by_seid(upf_seid) {
            log::info!("Removed data plane session: SEID={upf_seid:#x}");
        } else {
            log::warn!("Session not found for SEID {upf_seid:#x} during deletion");
        }
    }

    /// Get session stats for a specific SEID
    pub fn get_session_stats(&self, upf_seid: u64) -> Option<(u64, u64, u64, u64)> {
        self.sessions.find_by_seid(upf_seid).map(|s| {
            (
                s.ul_packets.load(Ordering::Relaxed),
                s.dl_packets.load(Ordering::Relaxed),
                s.ul_bytes.load(Ordering::Relaxed),
                s.dl_bytes.load(Ordering::Relaxed),
            )
        })
    }

    /// Get all session stats (for debugging/metrics)
    pub fn get_all_session_stats(&self) -> Vec<(u64, Option<Ipv4Addr>, u64, u64, u64, u64)> {
        self.sessions.get_all_session_stats()
    }

    /// Check all sessions for URR threshold exceedances.
    /// Returns a list of (upf_seid, smf_seid, urr_id, total_bytes, ul_bytes, dl_bytes, total_pkts)
    /// for each URR that has a threshold exceeded. Resets counters after collection.
    pub fn collect_urr_reports(&self) -> Vec<UrrReportEntry> {
        let mut reports = Vec::new();
        let seid_map = self.sessions.seid_map.read().unwrap();

        for session in seid_map.values() {
            let urrs = session.urrs.read().unwrap();
            for (urr_id, urr) in urrs.iter() {
                if urr.threshold_exceeded.load(Ordering::Relaxed) {
                    let entry = UrrReportEntry {
                        upf_seid: session.upf_seid,
                        smf_seid: session.smf_seid,
                        urr_id: *urr_id,
                        total_bytes: urr.acc_total_bytes.load(Ordering::Relaxed),
                        ul_bytes: urr.acc_ul_bytes.load(Ordering::Relaxed),
                        dl_bytes: urr.acc_dl_bytes.load(Ordering::Relaxed),
                        total_pkts: urr.acc_total_pkts.load(Ordering::Relaxed),
                        ul_pkts: urr.acc_ul_pkts.load(Ordering::Relaxed),
                        dl_pkts: urr.acc_dl_pkts.load(Ordering::Relaxed),
                    };
                    urr.reset_counters();
                    reports.push(entry);
                }
            }

            // Also check time-based thresholds (measurement period)
            for (urr_id, urr) in urrs.iter() {
                if !urr.threshold_exceeded.load(Ordering::Relaxed) {
                    if let Some(period) = urr.measurement_period_secs {
                        let last_report = urr.last_report_time.read().unwrap();
                        if let Some(last) = *last_report {
                            if last.elapsed().as_secs() >= period as u64 {
                                let total = urr.acc_total_bytes.load(Ordering::Relaxed);
                                if total > 0 {
                                    let entry = UrrReportEntry {
                                        upf_seid: session.upf_seid,
                                        smf_seid: session.smf_seid,
                                        urr_id: *urr_id,
                                        total_bytes: total,
                                        ul_bytes: urr.acc_ul_bytes.load(Ordering::Relaxed),
                                        dl_bytes: urr.acc_dl_bytes.load(Ordering::Relaxed),
                                        total_pkts: urr.acc_total_pkts.load(Ordering::Relaxed),
                                        ul_pkts: urr.acc_ul_pkts.load(Ordering::Relaxed),
                                        dl_pkts: urr.acc_dl_pkts.load(Ordering::Relaxed),
                                    };
                                    urr.reset_counters();
                                    reports.push(entry);
                                }
                            }
                        }
                    }
                }
            }
        }

        reports
    }
}

/// Entry for a URR usage report that needs to be sent as Session Report Request
#[derive(Debug, Clone)]
pub struct UrrReportEntry {
    pub upf_seid: u64,
    pub smf_seid: u64,
    pub urr_id: u32,
    pub total_bytes: u64,
    pub ul_bytes: u64,
    pub dl_bytes: u64,
    pub total_pkts: u64,
    pub ul_pkts: u64,
    pub dl_pkts: u64,
}

// ============================================================================
// Task 1: QFI Extraction from GTP-U Extension Headers
// ============================================================================

/// Extract QFI (QoS Flow Identifier) from a raw GTP-U packet's extension headers.
///
/// Per 3GPP TS 29.281, when the E (extension header) flag (bit 2 of flags byte)
/// is set, extension headers follow the optional fields.  A PDU Session Container
/// extension (type 0x85) carries the QFI in byte 1 of the extension content
/// (lower 6 bits, mask 0x3F).
///
/// Returns `Some(qfi)` when found, `None` if the E flag is not set or no PDU
/// Session Container is present.
pub fn extract_qfi_from_gtp_header(gtp_bytes: &[u8]) -> Option<u8> {
    if gtp_bytes.len() < 8 {
        return None;
    }
    let flags = gtp_bytes[0];
    // E flag is bit 2 (0x04) of the flags byte
    let e_flag = (flags & 0x04) != 0;
    if !e_flag {
        return None;
    }
    // When E/S/PN flags are set the header has a 4-byte optional area (bytes 8-11)
    if gtp_bytes.len() < 12 {
        return None;
    }
    // Next Extension Header Type is at byte 11
    let mut next_ext_type = gtp_bytes[11];
    let mut offset = 12usize;

    while next_ext_type != 0 {
        if offset >= gtp_bytes.len() {
            break;
        }
        // Extension header length is in units of 4 bytes (includes the length byte itself)
        let ext_len_units = gtp_bytes[offset] as usize;
        let ext_len = ext_len_units * 4;
        if ext_len == 0 || offset + ext_len > gtp_bytes.len() {
            break;
        }
        // PDU Session Container (type 0x85): QFI is in byte 1 of the extension
        if next_ext_type == 0x85 && ext_len >= 4 {
            let qfi = gtp_bytes[offset + 1] & 0x3F;
            return Some(qfi);
        }
        // Next extension header type is at the last byte of this extension
        next_ext_type = gtp_bytes[offset + ext_len - 1];
        offset += ext_len;
    }
    None
}

// ============================================================================
// Task 2: DSCP Marking per QFI (Vec<u8> variant)
// ============================================================================

/// Mark an IP packet's DSCP field based on QFI->DSCP mapping.
///
/// Sets the DSCP field (bits 7:2 of the TOS/Traffic Class byte) for both
/// IPv4 (byte 1) and IPv6 (bytes 0-1).  The ECN bits (low 2) are preserved.
/// The packet must be at least 20 bytes for IPv4 or 40 bytes for IPv6.
pub fn mark_dscp(ip_bytes: &mut Vec<u8>, dscp: u8) {
    if ip_bytes.is_empty() {
        return;
    }
    let version = (ip_bytes[0] >> 4) & 0x0F;
    match version {
        4 if ip_bytes.len() >= 20 => {
            // IPv4: DSCP is bits 7:2 of the TOS byte (byte 1).
            // Preserve the two ECN bits in bits 1:0.
            ip_bytes[1] = (dscp << 2) | (ip_bytes[1] & 0x03);
        }
        6 if ip_bytes.len() >= 40 => {
            // IPv6: Traffic Class is bits 11:4 of the first 16-bit word.
            // Byte 0 holds version (4 bits) + TC[7:4], byte 1 holds TC[3:0] + Flow[19:16].
            let tc = (dscp << 2) | (ip_bytes[1] & 0x03);
            ip_bytes[0] = (ip_bytes[0] & 0xF0) | ((tc >> 4) & 0x0F);
            ip_bytes[1] = ((tc & 0x0F) << 4) | (ip_bytes[1] & 0x0F);
        }
        _ => {}
    }
}

// ============================================================================
// Task 3: Token Bucket Rate Limiter
// ============================================================================

/// Token bucket for per-flow rate limiting.
///
/// Tokens are added at `refill_rate` tokens per second and capped at
/// `max_tokens`.  Each forwarded packet consumes `bytes` tokens.
/// Returns `false` (drop) when the bucket is empty.
#[derive(Debug)]
pub struct TokenBucket {
    /// Current token count (bytes available to send)
    pub tokens: f64,
    /// Bucket capacity (bytes)
    pub max_tokens: f64,
    /// Token refill rate (bytes per second)
    pub refill_rate: f64,
    /// Timestamp of the last refill
    pub last_refill: std::time::Instant,
}

impl TokenBucket {
    /// Create a new token bucket.
    ///
    /// `max_tokens` is the burst size (bytes), `refill_rate` is the sustained
    /// bit rate expressed in bytes per second.
    pub fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Create a token bucket from a Maximum Bit Rate value in kbps.
    ///
    /// The burst size is set to the equivalent of 10 ms worth of traffic to
    /// allow short-term bursts typical in 5G QoS scheduling.
    pub fn from_mbr_kbps(mbr_kbps: u64) -> Self {
        // Convert kbps to bytes/s
        let bytes_per_sec = (mbr_kbps as f64) * 125.0;
        // Burst = 10ms worth of data (minimum 1500 bytes for an Ethernet frame)
        let burst = (bytes_per_sec * 0.01).max(1500.0);
        Self::new(burst, bytes_per_sec)
    }

    /// Try to consume `bytes` tokens from the bucket.
    ///
    /// Returns `true` if the packet should be forwarded, `false` if it must be
    /// dropped because the bucket is empty.
    pub fn try_consume(&mut self, bytes: usize) -> bool {
        // Refill based on elapsed time
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);

        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Task 4: GTP-U Encapsulation and Decapsulation Helpers
// ============================================================================

/// Encapsulate a raw inner-IP packet in a GTP-U/UDP/IP wrapper.
///
/// Builds a complete over-the-wire GTP-U G-PDU:
/// - 20-byte outer IPv4 header (proto=UDP, src=0.0.0.0, dst=`peer_addr`)
/// - 8-byte UDP header (src port=2152, dst port=2152)
/// - 8-byte GTP-U header (version=1, PT=1, msg-type=G-PDU, TEID=`teid`)
/// - `inner_ip` payload
///
/// In production the outer IP src address is filled in by the OS when the
/// packet is sent through the GTP-U UDP socket; the zeros are a placeholder.
pub fn encap_gtp(inner_ip: &[u8], teid: u32, peer_addr: std::net::Ipv4Addr) -> Vec<u8> {
    // GTP-U payload length = inner IP length
    let gtpu_payload_len = inner_ip.len() as u16;
    // UDP length = UDP header (8) + GTP-U header (8) + inner IP
    let udp_len = (8u16 + 8u16).saturating_add(gtpu_payload_len);
    // IP total length = IP header (20) + UDP length
    let ip_total_len = 20u16.saturating_add(udp_len);

    let mut pkt = Vec::with_capacity(ip_total_len as usize);

    // --- Outer IPv4 header ---
    pkt.push(0x45); // Version=4, IHL=5
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&ip_total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // Identification
    pkt.extend_from_slice(&[0x40, 0x00]); // Flags=DF, Fragment offset=0
    pkt.push(0x40);                        // TTL=64
    pkt.push(0x11);                        // Protocol=UDP
    pkt.extend_from_slice(&[0x00, 0x00]); // Header checksum (zero = not computed here)
    pkt.extend_from_slice(&[0, 0, 0, 0]); // Src IP (filled by OS)
    pkt.extend_from_slice(&peer_addr.octets());

    // --- UDP header ---
    pkt.extend_from_slice(&GTPU_PORT.to_be_bytes()); // Src port = 2152
    pkt.extend_from_slice(&GTPU_PORT.to_be_bytes()); // Dst port = 2152
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // UDP checksum (optional for IPv4)

    // --- GTP-U header ---
    let gtpu_hdr = build_gtpu_header(teid, gtpu_payload_len);
    pkt.extend_from_slice(&gtpu_hdr);

    // --- Inner IP payload ---
    pkt.extend_from_slice(inner_ip);

    pkt
}

/// Decapsulate a GTP-U packet, returning a reference to the inner IP payload.
///
/// Expects the slice to begin at the GTP-U header (after outer UDP/IP headers
/// have already been stripped).  Returns `None` on malformed input or if the
/// message type is not G-PDU (0xFF).
///
/// The returned slice is a sub-slice of the input; no copying is performed.
pub fn decap_gtp(gtp_bytes: &[u8]) -> Option<&[u8]> {
    if gtp_bytes.len() < GTPU_HEADER_SIZE {
        return None;
    }
    let flags = gtp_bytes[0];
    let msg_type = gtp_bytes[1];
    // Only G-PDU (0xFF) carries an inner IP packet
    if msg_type != 0xFF {
        return None;
    }
    let has_optional = (flags & 0x07) != 0;
    let mut header_len = GTPU_HEADER_SIZE;

    if has_optional {
        if gtp_bytes.len() < 12 {
            return None;
        }
        header_len = 12;
        // Walk extension headers if E flag is set
        if (flags & 0x04) != 0 {
            let mut next_ext = gtp_bytes[11];
            let mut offset = 12usize;
            while next_ext != 0 {
                if offset >= gtp_bytes.len() {
                    return None;
                }
                let ext_len = (gtp_bytes[offset] as usize) * 4;
                if ext_len == 0 || offset + ext_len > gtp_bytes.len() {
                    return None;
                }
                next_ext = gtp_bytes[offset + ext_len - 1];
                offset += ext_len;
                header_len = offset;
            }
        }
    }

    if header_len > gtp_bytes.len() {
        return None;
    }
    Some(&gtp_bytes[header_len..])
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_gtpu_header() {
        let header = build_gtpu_header(0x12345678, 100);
        assert_eq!(header[0], 0x30); // Version=1, PT=1
        assert_eq!(header[1], 255); // G-PDU
        assert_eq!(u16::from_be_bytes([header[2], header[3]]), 100);
        assert_eq!(u32::from_be_bytes([header[4], header[5], header[6], header[7]]), 0x12345678);
    }

    #[test]
    fn test_build_gtpu_header_with_seq() {
        let header = build_gtpu_header_with_seq(0xABCDEF01, 200, 1234);
        assert_eq!(header[0], 0x32); // Version=1, PT=1, S=1
        assert_eq!(header[1], 255); // G-PDU
        assert_eq!(u16::from_be_bytes([header[2], header[3]]), 204); // 200 + 4
        assert_eq!(u32::from_be_bytes([header[4], header[5], header[6], header[7]]), 0xABCDEF01);
        assert_eq!(u16::from_be_bytes([header[8], header[9]]), 1234);
    }

    #[test]
    fn test_session_manager() {
        let mgr = SessionManager::new();

        // Allocate TEIDs and SEIDs
        let teid1 = mgr.allocate_teid();
        let teid2 = mgr.allocate_teid();
        assert_ne!(teid1, teid2);

        let seid1 = mgr.allocate_seid();
        let seid2 = mgr.allocate_seid();
        assert_ne!(seid1, seid2);

        // Add session
        let session = DataPlaneSession {
            upf_seid: seid1,
            smf_seid: 0x1000,
            ue_ipv4: Some(Ipv4Addr::new(10, 45, 0, 2)),
            ul_teid: teid1,
            dl_teid: 100,
            gnb_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 2152),
            pdu_session_id: Some(1),
            qfi: Some(9),
            ul_packets: AtomicU64::new(0),
            dl_packets: AtomicU64::new(0),
            ul_bytes: AtomicU64::new(0),
            dl_bytes: AtomicU64::new(0),
            pdrs: RwLock::new(Vec::new()),
            fars: RwLock::new(HashMap::new()),
            qers: RwLock::new(HashMap::new()),
            urrs: RwLock::new(HashMap::new()),
        };
        mgr.add_session(session);

        // Find by SEID
        let found = mgr.find_by_seid(seid1);
        assert!(found.is_some());

        // Find by TEID
        let found = mgr.find_by_ul_teid(teid1);
        assert!(found.is_some());

        // Find by IP
        let found = mgr.find_by_ue_ip(Ipv4Addr::new(10, 45, 0, 2));
        assert!(found.is_some());

        // Not found
        let not_found = mgr.find_by_ul_teid(9999);
        assert!(not_found.is_none());

        // Remove by SEID
        assert!(mgr.remove_session_by_seid(seid1));
        assert!(mgr.find_by_seid(seid1).is_none());
    }

    // -- PacketTuple tests --

    /// Build a minimal valid IPv4/TCP packet for testing
    fn make_ipv4_tcp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 40]; // 20 IP + 20 TCP
        pkt[0] = 0x45; // Version=4, IHL=5
        pkt[9] = 6;    // Protocol: TCP
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20] = (src_port >> 8) as u8;
        pkt[21] = (src_port & 0xFF) as u8;
        pkt[22] = (dst_port >> 8) as u8;
        pkt[23] = (dst_port & 0xFF) as u8;
        pkt
    }

    fn make_ipv4_udp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = make_ipv4_tcp_packet(src, dst, src_port, dst_port);
        pkt[9] = 17; // Protocol: UDP
        pkt
    }

    #[test]
    fn test_packet_tuple_from_valid_tcp_packet() {
        let pkt = make_ipv4_tcp_packet([10, 45, 0, 2], [172, 23, 0, 1], 12345, 80);
        let tuple = PacketTuple::from_ipv4_packet(&pkt).unwrap();
        assert_eq!(tuple.src_ip, u32::from_be_bytes([10, 45, 0, 2]));
        assert_eq!(tuple.dst_ip, u32::from_be_bytes([172, 23, 0, 1]));
        assert_eq!(tuple.protocol, 6);
        assert_eq!(tuple.src_port, 12345);
        assert_eq!(tuple.dst_port, 80);
    }

    #[test]
    fn test_packet_tuple_from_valid_udp_packet() {
        let pkt = make_ipv4_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060);
        let tuple = PacketTuple::from_ipv4_packet(&pkt).unwrap();
        assert_eq!(tuple.protocol, 17);
        assert_eq!(tuple.src_port, 5060);
        assert_eq!(tuple.dst_port, 5060);
    }

    #[test]
    fn test_packet_tuple_from_icmp_has_zero_ports() {
        let mut pkt = make_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 0, 0);
        pkt[9] = 1; // ICMP
        let tuple = PacketTuple::from_ipv4_packet(&pkt).unwrap();
        assert_eq!(tuple.protocol, 1);
        assert_eq!(tuple.src_port, 0);
        assert_eq!(tuple.dst_port, 0);
    }

    #[test]
    fn test_packet_tuple_too_short_returns_none() {
        let pkt = vec![0x45, 0, 0, 0]; // Only 4 bytes
        assert!(PacketTuple::from_ipv4_packet(&pkt).is_none());
        assert!(PacketTuple::from_ipv4_packet(&[]).is_none());
    }

    #[test]
    fn test_packet_tuple_with_ip_options() {
        // IHL = 7 (28 bytes header), ports start at offset 28
        let mut pkt = vec![0u8; 48]; // 28 IP + 20 TCP
        pkt[0] = 0x47; // Version=4, IHL=7
        pkt[9] = 6;    // TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // Ports at offset 28
        pkt[28] = 0x30; pkt[29] = 0x39; // src_port = 12345
        pkt[30] = 0x00; pkt[31] = 0x50; // dst_port = 80
        let tuple = PacketTuple::from_ipv4_packet(&pkt).unwrap();
        assert_eq!(tuple.src_port, 12345);
        assert_eq!(tuple.dst_port, 80);
    }

    // -- matches_rule tests --

    #[test]
    fn test_matches_rule_protocol_mismatch() {
        let tuple = PacketTuple {
            src_ip: 0x0a000001, dst_ip: 0x0a000002,
            protocol: 6, src_port: 1000, dst_port: 80,
        };
        let mut rule = ogs_ipfw::IpfwRule::default();
        rule.proto = 17; // UDP — mismatch with TCP
        assert!(!tuple.matches_rule(&rule));
    }

    #[test]
    fn test_matches_rule_protocol_any_matches_all() {
        let tuple = PacketTuple {
            src_ip: 0x0a000001, dst_ip: 0x0a000002,
            protocol: 6, src_port: 1000, dst_port: 80,
        };
        let rule = ogs_ipfw::IpfwRule::default(); // proto=0 = any
        assert!(tuple.matches_rule(&rule));
    }

    #[test]
    fn test_matches_rule_src_ip_subnet() {
        let tuple = PacketTuple {
            src_ip: u32::from_be_bytes([10, 45, 1, 50]),
            dst_ip: u32::from_be_bytes([172, 23, 0, 1]),
            protocol: 17, src_port: 5000, dst_port: 80,
        };
        let mut rule = ogs_ipfw::IpfwRule::default();
        rule.ipv4_src = true;
        // 10.45.0.0/16 mask
        rule.ip.src.addr[0] = u32::from_be_bytes([10, 45, 0, 0]);
        rule.ip.src.mask[0] = u32::from_be_bytes([255, 255, 0, 0]);
        assert!(tuple.matches_rule(&rule), "10.45.1.50 should match 10.45.0.0/16");

        // 10.46.0.0/16 — should NOT match
        rule.ip.src.addr[0] = u32::from_be_bytes([10, 46, 0, 0]);
        assert!(!tuple.matches_rule(&rule), "10.45.1.50 should not match 10.46.0.0/16");
    }

    #[test]
    fn test_matches_rule_dst_port_range() {
        let tuple = PacketTuple {
            src_ip: 0, dst_ip: 0, protocol: 17, src_port: 5000, dst_port: 8080,
        };
        let mut rule = ogs_ipfw::IpfwRule::default();
        // Port range 80-8080 (inclusive)
        rule.port.dst = ogs_ipfw::PortRange::range(80, 8080);
        assert!(tuple.matches_rule(&rule));

        // Port 8081 — just outside range
        let tuple2 = PacketTuple { dst_port: 8081, ..tuple };
        assert!(!tuple2.matches_rule(&rule));

        // Port 79 — just below range
        let tuple3 = PacketTuple { dst_port: 79, ..tuple };
        assert!(!tuple3.matches_rule(&rule));

        // Exact boundary
        let tuple4 = PacketTuple { dst_port: 80, ..tuple };
        assert!(tuple4.matches_rule(&rule));
    }

    // -- match_pdr_with_packet tests --

    fn make_test_session(pdrs: Vec<DataPlanePdr>) -> DataPlaneSession {
        DataPlaneSession {
            upf_seid: 1,
            smf_seid: 1,
            ue_ipv4: Some(Ipv4Addr::new(10, 45, 0, 2)),
            ul_teid: 1,
            dl_teid: 1,
            gnb_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2152),
            pdu_session_id: Some(1),
            qfi: Some(9),
            ul_packets: AtomicU64::new(0),
            dl_packets: AtomicU64::new(0),
            ul_bytes: AtomicU64::new(0),
            dl_bytes: AtomicU64::new(0),
            pdrs: RwLock::new(pdrs),
            fars: RwLock::new(HashMap::new()),
            qers: RwLock::new(HashMap::new()),
            urrs: RwLock::new(HashMap::new()),
        }
    }

    #[test]
    fn test_match_pdr_wildcard_no_sdf_matches() {
        let session = make_test_session(vec![
            DataPlanePdr {
                pdr_id: 1, precedence: 100, source_interface: SRC_INTF_ACCESS,
                far_id: Some(1), qer_id: None, urr_ids: vec![], outer_header_removal: None,
                sdf_rule: None,
            },
        ]);
        let pkt = PacketTuple {
            src_ip: 0, dst_ip: 0, protocol: 6, src_port: 1, dst_port: 80,
        };
        let result = session.match_pdr_with_packet(SRC_INTF_ACCESS, Some(&pkt));
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, Some(1)); // far_id
    }

    #[test]
    fn test_match_pdr_sdf_packet_matches() {
        let mut rule = ogs_ipfw::IpfwRule::default();
        rule.proto = 17; // UDP only
        let session = make_test_session(vec![
            DataPlanePdr {
                pdr_id: 1, precedence: 50, source_interface: SRC_INTF_ACCESS,
                far_id: Some(10), qer_id: None, urr_ids: vec![], outer_header_removal: None,
                sdf_rule: Some(rule),
            },
        ]);
        let pkt = PacketTuple {
            src_ip: 0, dst_ip: 0, protocol: 17, src_port: 5060, dst_port: 5060,
        };
        let result = session.match_pdr_with_packet(SRC_INTF_ACCESS, Some(&pkt));
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, Some(10));
    }

    #[test]
    fn test_match_pdr_sdf_packet_no_match_skips_to_wildcard() {
        let mut rule = ogs_ipfw::IpfwRule::default();
        rule.proto = 17; // SDF: UDP only
        let session = make_test_session(vec![
            DataPlanePdr {
                pdr_id: 1, precedence: 50, source_interface: SRC_INTF_ACCESS,
                far_id: Some(10), qer_id: None, urr_ids: vec![], outer_header_removal: None,
                sdf_rule: Some(rule),
            },
            DataPlanePdr {
                pdr_id: 2, precedence: 100, source_interface: SRC_INTF_ACCESS,
                far_id: Some(20), qer_id: None, urr_ids: vec![], outer_header_removal: None,
                sdf_rule: None, // wildcard
            },
        ]);
        // TCP packet — doesn't match UDP SDF rule, falls through to wildcard
        let pkt = PacketTuple {
            src_ip: 0, dst_ip: 0, protocol: 6, src_port: 1000, dst_port: 80,
        };
        let result = session.match_pdr_with_packet(SRC_INTF_ACCESS, Some(&pkt));
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, Some(20)); // wildcard PDR
    }

    #[test]
    fn test_match_pdr_precedence_order() {
        let session = make_test_session(vec![
            DataPlanePdr {
                pdr_id: 2, precedence: 100, source_interface: SRC_INTF_ACCESS,
                far_id: Some(20), qer_id: None, urr_ids: vec![], outer_header_removal: None,
                sdf_rule: None,
            },
            DataPlanePdr {
                pdr_id: 1, precedence: 50, source_interface: SRC_INTF_ACCESS,
                far_id: Some(10), qer_id: None, urr_ids: vec![], outer_header_removal: None,
                sdf_rule: None,
            },
        ]);
        // Should match pdr_id=2 first (it's at index 0) even though higher precedence number
        // PDRs should be pre-sorted by precedence in production — this tests iteration order
        let result = session.match_pdr_with_packet(SRC_INTF_ACCESS, None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, Some(20)); // first in iteration order
    }

    #[test]
    fn test_match_pdr_wrong_source_interface_no_match() {
        let session = make_test_session(vec![
            DataPlanePdr {
                pdr_id: 1, precedence: 100, source_interface: SRC_INTF_ACCESS,
                far_id: Some(1), qer_id: None, urr_ids: vec![], outer_header_removal: None,
                sdf_rule: None,
            },
        ]);
        let result = session.match_pdr_with_packet(SRC_INTF_CORE, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_apply_far_drop_action() {
        let session = make_test_session(vec![]);
        let mut fars = session.fars.write().unwrap();
        fars.insert(1, DataPlaneFar {
            far_id: 1,
            apply_action: FAR_ACTION_DROP,
            destination_interface: 0,
            ohc_teid: None,
            ohc_addr: None,
        });
        drop(fars);
        let (fwd, teid, addr) = session.apply_far(1);
        assert!(!fwd);
        assert!(teid.is_none());
        assert!(addr.is_none());
    }

    #[test]
    fn test_apply_far_forward_action() {
        let session = make_test_session(vec![]);
        let mut fars = session.fars.write().unwrap();
        fars.insert(1, DataPlaneFar {
            far_id: 1,
            apply_action: FAR_ACTION_FORW,
            destination_interface: SRC_INTF_ACCESS,
            ohc_teid: Some(0x1234),
            ohc_addr: Some(Ipv4Addr::new(192, 168, 1, 1)),
        });
        drop(fars);
        let (fwd, teid, addr) = session.apply_far(1);
        assert!(fwd);
        assert_eq!(teid, Some(0x1234));
        assert_eq!(addr, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_apply_far_not_found_defaults_forward() {
        let session = make_test_session(vec![]);
        let (fwd, teid, addr) = session.apply_far(999);
        assert!(fwd);
        assert!(teid.is_none());
        assert!(addr.is_none());
    }

    // -- Task 1: extract_qfi_from_gtp_header tests --

    #[test]
    fn test_extract_qfi_no_e_flag() {
        // flags=0x30 means no E/S/PN bits set -> no extension headers
        let pkt = vec![0x30u8, 0xFF, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01,
                       0xAA, 0xBB, 0xCC, 0xDD];
        assert_eq!(extract_qfi_from_gtp_header(&pkt), None);
    }

    #[test]
    fn test_extract_qfi_with_pdu_session_container() {
        // flags=0x34: version=1, PT=1, E=1
        // TEID=0x00000001, seq=0, npdu=0, next_ext=0x85
        // Extension: len=1 (4 bytes), QFI=9, next_ext=0
        let pkt = vec![
            0x34u8, 0xFF,          // flags, msg_type=G-PDU
            0x00, 0x18,            // length
            0x00, 0x00, 0x00, 0x01,// TEID
            0x00, 0x00,            // seq
            0x00,                  // N-PDU
            0x85,                  // next_ext = PDU Session Container
            // Extension header: len=1 (=4 bytes total), PDU type|spare, QFI, spare, next_ext
            0x01, 0x09, 0x00, 0x00,// len=1, QFI=9 (0x09 & 0x3F = 9), next=0
        ];
        assert_eq!(extract_qfi_from_gtp_header(&pkt), Some(9));
    }

    #[test]
    fn test_extract_qfi_too_short() {
        let pkt = vec![0x34u8, 0xFF, 0x00];
        assert_eq!(extract_qfi_from_gtp_header(&pkt), None);
    }

    #[test]
    fn test_extract_qfi_unknown_extension_type() {
        // Extension type 0x01 (not PDU Session Container) -> no QFI
        let pkt = vec![
            0x34u8, 0xFF,
            0x00, 0x10,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00,
            0x00,
            0x01,                  // next_ext = type 0x01
            0x01, 0x00, 0x00, 0x00,// ext: len=1, content, next=0
        ];
        assert_eq!(extract_qfi_from_gtp_header(&pkt), None);
    }

    // -- Task 2: mark_dscp tests --

    #[test]
    fn test_mark_dscp_ipv4() {
        // Minimal IPv4 packet, 20 bytes
        let mut pkt = vec![0x45u8, 0x00]; // version/IHL, TOS=0
        pkt.extend_from_slice(&[0u8; 18]);
        mark_dscp(&mut pkt, 46); // EF
        assert_eq!(pkt[1] >> 2, 46);
        // ECN bits preserved (were 0)
        assert_eq!(pkt[1] & 0x03, 0);
    }

    #[test]
    fn test_mark_dscp_ipv4_preserves_ecn() {
        let mut pkt = vec![0x45u8, 0x03]; // TOS with ECN bits set
        pkt.extend_from_slice(&[0u8; 18]);
        mark_dscp(&mut pkt, 34); // AF41
        assert_eq!(pkt[1] >> 2, 34);
        assert_eq!(pkt[1] & 0x03, 0x03, "ECN bits must be preserved");
    }

    #[test]
    fn test_mark_dscp_too_short_noop() {
        let mut pkt = vec![0x45u8, 0x00, 0x00]; // too short for IPv4
        mark_dscp(&mut pkt, 46);
        assert_eq!(pkt[1], 0x00, "Should not modify too-short packet");
    }

    // -- Task 3: TokenBucket tests --

    #[test]
    fn test_token_bucket_allows_within_limit() {
        let mut tb = TokenBucket::new(10_000.0, 1_000_000.0); // 1 MB/s
        assert!(tb.try_consume(1000));
        assert!(tb.try_consume(1000));
    }

    #[test]
    fn test_token_bucket_drops_when_empty() {
        let mut tb = TokenBucket::new(100.0, 0.0); // no refill
        assert!(tb.try_consume(50));
        assert!(tb.try_consume(50));
        assert!(!tb.try_consume(1), "Should drop when bucket empty");
    }

    #[test]
    fn test_token_bucket_from_mbr_kbps() {
        let tb = TokenBucket::from_mbr_kbps(1000); // 1 Mbps
        // refill_rate should be 1000 * 125 = 125_000 bytes/s
        assert!((tb.refill_rate - 125_000.0).abs() < 1.0);
        // burst should be max(125_000 * 0.01, 1500) = max(1250, 1500) = 1500
        assert!((tb.max_tokens - 1500.0).abs() < 1.0);
    }

    // -- Task 4: encap_gtp / decap_gtp tests --

    #[test]
    fn test_encap_gtp_structure() {
        let inner_ip = vec![0x45u8; 20]; // dummy IPv4 packet
        let teid = 0xDEADBEEF;
        let peer = Ipv4Addr::new(192, 168, 1, 100);
        let pkt = encap_gtp(&inner_ip, teid, peer);

        // Should have: 20 (IP) + 8 (UDP) + 8 (GTP-U) + 20 (inner) = 56 bytes
        assert_eq!(pkt.len(), 56);
        // IP version + IHL
        assert_eq!(pkt[0], 0x45);
        // IP protocol = UDP (17)
        assert_eq!(pkt[9], 0x11);
        // Dst IP = peer
        assert_eq!(&pkt[16..20], &peer.octets());
        // UDP dst port = 2152
        let udp_dst = u16::from_be_bytes([pkt[22], pkt[23]]);
        assert_eq!(udp_dst, 2152);
        // GTP-U flags
        assert_eq!(pkt[28], 0x30);
        // GTP-U TEID
        let gtp_teid = u32::from_be_bytes([pkt[32], pkt[33], pkt[34], pkt[35]]);
        assert_eq!(gtp_teid, teid);
    }

    #[test]
    fn test_decap_gtp_basic() {
        let inner_ip = vec![0x45u8, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00,
                            0x40, 0x06, 0x00, 0x00, 10, 45, 0, 2, 172, 23, 0, 1];
        // Build minimal GTP-U: flags=0x30, msg=0xFF, len, TEID
        let mut gtp = vec![0x30u8, 0xFF];
        let payload_len = inner_ip.len() as u16;
        gtp.extend_from_slice(&payload_len.to_be_bytes());
        gtp.extend_from_slice(&[0x00, 0x00, 0x01, 0x23]); // TEID
        gtp.extend_from_slice(&inner_ip);

        let decapped = decap_gtp(&gtp).unwrap();
        assert_eq!(decapped, inner_ip.as_slice());
    }

    #[test]
    fn test_decap_gtp_non_gpdu_returns_none() {
        // msg_type = ECHO_REQUEST (1), not G-PDU
        let pkt = vec![0x30u8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(decap_gtp(&pkt).is_none());
    }

    #[test]
    fn test_decap_gtp_too_short_returns_none() {
        let pkt = vec![0x30u8, 0xFF, 0x00];
        assert!(decap_gtp(&pkt).is_none());
    }

}
