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
use std::os::fd::{AsRawFd, RawFd};
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
    file: Option<tokio::fs::File>,
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
            file: None,
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
        if let Some(session) = self.find_by_seid(seid) {
            // We need to create a new session with updated values since Arc<DataPlaneSession>
            // For simplicity, remove old and add new with updated values
            // In production, use interior mutability (Mutex/RwLock inside DataPlaneSession)
            log::info!(
                "Session update: SEID={:#x}, new DL_TEID={:#x}, gNB={}",
                seid, dl_teid, gnb_addr
            );
            true
        } else {
            log::warn!("Session not found for update: SEID={:#x}", seid);
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

            log::info!("Session removed: SEID={:#x}", seid);
            true
        } else {
            log::warn!("Session not found for removal: SEID={:#x}", seid);
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
        log::info!("Creating TUN device: {}", tun_name);
        let tun = TunDevice::create(tun_name)?;

        // Configure IP
        log::info!("Configuring TUN IP: {}/{}", tun_ip, tun_prefix);
        tun.configure_ip(tun_ip, tun_prefix)?;

        // Setup NAT for UE subnet
        let subnet = Ipv4Addr::new(
            tun_ip.octets()[0],
            tun_ip.octets()[1],
            0,
            0,
        );
        log::info!("Setting up NAT for subnet: {}/{}", subnet, tun_prefix);
        tun.setup_nat(subnet, tun_prefix)?;

        self.tun = Some(tun);

        // Create GTP-U socket
        log::info!("Binding GTP-U socket on {}", gtpu_addr);
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
        let sessions = &self.sessions;
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
                            log::debug!("GTP-U received {} bytes from {}", len, from);
                            let _ = ul_tx_clone.send((buf[..len].to_vec(), from)).await;
                        }
                    }
                    Err(e) => {
                        if e.kind() != io::ErrorKind::WouldBlock {
                            log::error!("GTP-U recv error: {}", e);
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
                        log::error!("TUN read error: {}", err);
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
                    log::info!("Data plane stats: UL={} pkts, DL={} pkts", ul, dl);
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
                log::debug!("Failed to parse GTP-U header: {:?}", e);
                self.stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

        match header.msg_type {
            gtpu_msg_type::ECHO_REQUEST => {
                // Send echo response
                log::debug!("GTP-U Echo Request from {}", from);
                let response = build_gtpu_echo_response(header.seq_num);
                if let Some(sock) = &self.gtpu_socket {
                    let _ = sock.send_to(&response, from).await;
                }
                return;
            }
            gtpu_msg_type::GPDU => {
                // Process G-PDU
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

        // Auto-learn session from uplink packet if not exists
        // Extract source IP from IPv4 header for session lookup/creation
        if ip_payload.len() >= 20 {
            let ip_version = (ip_payload[0] >> 4) & 0x0F;
            if ip_version == IP_VERSION_4 {
                let src_ip = Ipv4Addr::new(
                    ip_payload[12], ip_payload[13], ip_payload[14], ip_payload[15]
                );

                // Check if session exists for this UE IP
                if self.sessions.find_by_ue_ip(src_ip).is_none() {
                    // Auto-create session from uplink packet info
                    // Use the incoming TEID as the uplink TEID
                    // Use the same TEID for downlink (gNB should accept it)
                    // Allocate a new SEID for auto-learned sessions
                    let upf_seid = self.sessions.allocate_seid();
                    let session = DataPlaneSession {
                        upf_seid,
                        smf_seid: 0, // Unknown for auto-learned sessions
                        ue_ipv4: Some(src_ip),
                        ul_teid: header.teid,
                        dl_teid: header.teid, // Use same TEID for downlink
                        gnb_addr: from,
                        pdu_session_id: None,
                        qfi: None,
                        ul_packets: AtomicU64::new(0),
                        dl_packets: AtomicU64::new(0),
                        ul_bytes: AtomicU64::new(0),
                        dl_bytes: AtomicU64::new(0),
                    };
                    self.sessions.add_session(session);
                    log::info!(
                        "Auto-learned session: UE={}, TEID=0x{:x}, gNB={}",
                        src_ip, header.teid, from
                    );
                }
            }
        }

        // Write to TUN device
        let ret = unsafe {
            libc::write(tun_fd, ip_payload.as_ptr() as *const libc::c_void, ip_payload.len())
        };

        if ret < 0 {
            log::error!("TUN write failed: {}", io::Error::last_os_error());
            self.stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.ul_packets.fetch_add(1, Ordering::Relaxed);
            self.stats.ul_bytes.fetch_add(ip_payload.len() as u64, Ordering::Relaxed);
            log::trace!("UL: {} bytes from {} TEID=0x{:x}", ip_payload.len(), from, header.teid);
        }
    }

    /// Handle downlink packet (from TUN, to gNB via GTP-U)
    async fn handle_downlink_packet(&self, pkt: &[u8], gtpu: &TokioUdpSocket) {
        if pkt.is_empty() {
            return;
        }

        // Get destination IP from packet
        let ip_version = (pkt[0] >> 4) & 0x0F;

        let dst_ip = match ip_version {
            IP_VERSION_4 if pkt.len() >= 20 => {
                let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                Some(dst)
            }
            _ => None,
        };

        // Find session by destination IP
        let session = dst_ip.and_then(|ip| self.sessions.find_by_ue_ip(ip));

        // If no session, try to find by looking at context
        let (dl_teid, gnb_addr) = if let Some(sess) = session {
            (sess.dl_teid, sess.gnb_addr)
        } else {
            // Default session for testing - use first available or hardcoded
            // In production, this would look up PFCP session rules
            log::trace!("No session for DL packet to {:?}, using default", dst_ip);

            // For testing: use a default TEID and gNB address
            // This should be populated from PFCP session establishment
            let default_teid = 1u32;
            let default_gnb = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(172, 23, 0, 100)), // nextgsim-gnb
                GTPU_PORT,
            );
            (default_teid, default_gnb)
        };

        // Build GTP-U encapsulated packet
        let gtpu_header = build_gtpu_header(dl_teid, pkt.len() as u16);
        let mut gtpu_pkt = Vec::with_capacity(GTPU_HEADER_SIZE + pkt.len());
        gtpu_pkt.extend_from_slice(&gtpu_header);
        gtpu_pkt.extend_from_slice(pkt);

        // Send to gNB
        match gtpu.send_to(&gtpu_pkt, gnb_addr).await {
            Ok(_) => {
                self.stats.dl_packets.fetch_add(1, Ordering::Relaxed);
                self.stats.dl_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                log::trace!("DL: {} bytes to {} TEID=0x{:x}", pkt.len(), gnb_addr, dl_teid);
            }
            Err(e) => {
                log::error!("GTP-U send failed: {}", e);
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
        };

        self.sessions.add_session(session);
        log::info!(
            "Added data plane session: SEID={:#x}, SMF_SEID={:#x}, UE={}, UL_TEID=0x{:x}, DL_TEID=0x{:x}, gNB={}, PDU={:?}, QFI={:?}",
            upf_seid, smf_seid, ue_ip, ul_teid, dl_teid, gnb_addr, pdu_session_id, qfi
        );
    }

    /// Update a session from PFCP modification
    pub fn update_session_from_pfcp(
        &self,
        upf_seid: u64,
        dl_teid: Option<u32>,
        gnb_addr: Option<SocketAddr>,
    ) {
        // Find and update the session by SEID
        if let Some(session) = self.sessions.find_by_seid(upf_seid) {
            // Note: DataPlaneSession fields are not mutable through Arc
            // For now, we'll remove and re-add with updated values
            let new_dl_teid = dl_teid.unwrap_or(session.dl_teid);
            let new_gnb_addr = gnb_addr.unwrap_or(session.gnb_addr);

            // Remove old session by SEID
            self.sessions.remove_session_by_seid(upf_seid);

            // Add updated session
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
            };

            self.sessions.add_session(new_session);
            log::info!(
                "Updated data plane session: SEID={:#x}, DL_TEID=0x{:x}, gNB={}",
                upf_seid, new_dl_teid, new_gnb_addr
            );
        } else {
            log::warn!("Session not found for SEID {:#x} during update", upf_seid);
        }
    }

    /// Remove a session from PFCP deletion
    pub fn remove_session_from_pfcp(&self, upf_seid: u64) {
        if self.sessions.remove_session_by_seid(upf_seid) {
            log::info!("Removed data plane session: SEID={:#x}", upf_seid);
        } else {
            log::warn!("Session not found for SEID {:#x} during deletion", upf_seid);
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
}
