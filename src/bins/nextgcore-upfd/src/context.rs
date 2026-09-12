//! UPF Context Management
//!
//! Port of src/upf/context.c, src/upf/context.h.
//!
//! # What this module is NOT, since it used to claim otherwise (#325)
//!
//! It used to carry a whole second session model — `UpfSess`, a `sess_list`, five
//! lookup indices and two framed-route tries — whose writers were all inside
//! `mod tests`. Nothing on the N4 wire path ever created a `UpfSess`, so the
//! UE-IP lookups built on it (`rule_match::upf_sess_find_by_ue_ip_address` and
//! its `_src` sibling) searched a permanently empty map. Those lookups had no
//! production caller either, so no packet was ever misrouted by it — but
//! [`UpfContext::sess_count`] DID have one, [`UpfContext::get_load`], and that is
//! how a dead store reached the wire: as a `load: 0` advertised to the NRF and to
//! the SMF by a UPF serving any number of sessions.
//!
//! It used to carry a second, parallel PFCP RULE model beside that session model —
//! `Pdr`/`Pdi`/`FTeid`/`SdfFilter`/`Far`/`OuterHeaderCreation`/`ForwardingParameters`/
//! `DuplicatingParameters`/`RedirectInformation`/`HeaderEnrichment`, a `UeIp` reachable
//! only from `Pdr.ue_ip`, and a token-bucket `RateLimiter` — with no importer in any
//! module and no reader in any test, so unlike the session model it never reached the
//! wire. Deleted in #335. The live rule model is `n4_handler`'s (parsed from the N4
//! wire) feeding `data_plane`'s `DataPlanePdr`/`DataPlaneFar`; note that `n4_handler`,
//! `n4_build` and `data_plane` each spell some of those names for THEIR OWN type, which
//! is what made a grep-based reachability check misleading and is why both halves of
//! this rot survived so long.
//!
//! What did NOT hide either half is `dead_code = "allow"` (`Cargo.toml`), despite being
//! the obvious suspect. Measured on this branch: with the lint at `warn` the workspace
//! emits 277 warnings and **upfd emits none of them**, because the lint does not fire on
//! `pub` items in a bin crate — a `pub fn` added to this file warns not at all, while the
//! same `fn` made private warns immediately. Narrowing the allow would therefore have
//! bought noise, not detection; the thing that finds this class is the importer grep both
//! #325 and #335 used.
//!
//! The live session stores are `pfcp_path::PfcpServer::sessions` (the N4 census,
//! written by the establishment/deletion handlers) and
//! `data_plane::DataPlaneSessionManager` (the forwarding tables, including the UE-IP
//! index the data path actually uses). This module holds neither, and no longer holds
//! any PFCP rule type. It holds the TSN bridge model that `PfcpSessionInfo` points at
//! and the process-global context whose only live business is the load gauge.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

// ============================================================================
// TSN Bridge (Rel-18, IEEE 802.1Q)
// ============================================================================

/// TSN (Time-Sensitive Networking) bridge port configuration
#[derive(Debug, Clone)]
pub struct TsnBridgePort {
    /// Port identifier (maps to a GTP tunnel endpoint)
    pub port_id: u16,
    /// VLAN ID (IEEE 802.1Q, 1-4094)
    pub vlan_id: u16,
    /// Port priority (PCP, 0-7)
    pub priority: u8,
    /// Whether this port is trunk (carries multiple VLANs)
    pub is_trunk: bool,
    /// Allowed VLAN IDs when trunk
    pub allowed_vlans: Vec<u16>,
    /// Port type (DS-TT: Device-Side Translator, NW-TT: Network-Side Translator)
    pub port_type: TsnPortType,
    /// Time-aware shaper enabled (IEEE 802.1Qbv)
    pub time_aware_shaper_enabled: bool,
    /// Gate control list for time-aware scheduling
    pub gate_control_list: Vec<TsnGateControlEntry>,
}

/// TSN port type (TS 23.501 Section 5.28)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TsnPortType {
    /// Device-Side Translator (connected to TSN device)
    #[default]
    DeviceSideTt,
    /// Network-Side Translator (connected to 5G network)
    NetworkSideTt,
}

/// TSN Gate Control Entry (IEEE 802.1Qbv)
#[derive(Debug, Clone, Default)]
pub struct TsnGateControlEntry {
    /// Gate state for each priority queue (bit mask, 8 bits for 8 priorities)
    pub gate_states: u8,
    /// Time interval for this gate state (nanoseconds)
    pub time_interval_ns: u64,
}

/// PTP (Precision Time Protocol) transparent clock state
#[derive(Debug, Clone, Default)]
pub struct PtpTransparentClock {
    /// Whether PTP transparent clock is enabled
    pub enabled: bool,
    /// Accumulated residence time in nanoseconds
    pub residence_time_ns: u64,
    /// Number of PTP messages processed
    pub messages_processed: u64,
    /// Mean path delay (nanoseconds)
    pub mean_path_delay_ns: u64,
}

impl PtpTransparentClock {
    /// Record residence time for a PTP message transit
    pub fn record_residence(&mut self, ingress_ns: u64, egress_ns: u64) {
        if !self.enabled {
            return;
        }
        let residence = egress_ns.saturating_sub(ingress_ns);
        self.residence_time_ns += residence;
        self.messages_processed += 1;
        if let Some(mean) = self.residence_time_ns.checked_div(self.messages_processed) {
            self.mean_path_delay_ns = mean;
        }
    }
}

/// TSN Stream Identification (TS 23.501 Section 5.28)
#[derive(Debug, Clone, Default)]
pub struct TsnStreamIdentification {
    /// Stream ID
    pub stream_id: u32,
    /// Source MAC address
    pub source_mac: [u8; 6],
    /// Destination MAC address
    pub destination_mac: [u8; 6],
    /// VLAN ID
    pub vlan_id: u16,
    /// Priority Code Point (PCP)
    pub pcp: u8,
    /// Mapped QoS Flow Identifier (QFI)
    pub qfi: u8,
    /// Mapped 5QI
    pub five_qi: u8,
    /// GFBR (Guaranteed Flow Bit Rate) in kbps
    pub gfbr_kbps: Option<u32>,
    /// MFBR (Maximum Flow Bit Rate) in kbps
    pub mfbr_kbps: Option<u32>,
}

impl TsnStreamIdentification {
    /// Create a new TSN stream identification
    pub fn new(stream_id: u32, vlan_id: u16, qfi: u8, five_qi: u8) -> Self {
        Self {
            stream_id,
            source_mac: [0; 6],
            destination_mac: [0; 6],
            vlan_id,
            pcp: 0,
            qfi,
            five_qi,
            gfbr_kbps: None,
            mfbr_kbps: None,
        }
    }

    /// Check if packet matches this stream
    pub fn matches(&self, src_mac: &[u8; 6], dst_mac: &[u8; 6], vlan_id: u16) -> bool {
        (self.source_mac == [0; 6] || self.source_mac == *src_mac)
            && (self.destination_mac == [0; 6] || self.destination_mac == *dst_mac)
            && self.vlan_id == vlan_id
    }
}

/// CNC (Centralized Network Controller) Interface Context
#[derive(Debug, Clone, Default)]
pub struct TsnCncInterface {
    /// CNC endpoint URI
    pub cnc_endpoint: String,
    /// CNC session identifier
    pub cnc_session_id: Option<String>,
    /// CNC connection status
    pub connected: bool,
    /// Last configuration update time
    pub last_config_update: u64,
    /// Stream configurations from CNC
    pub stream_configs: Vec<TsnStreamIdentification>,
    /// Gate control list update interval (nanoseconds)
    pub gate_update_interval_ns: u64,
}

impl TsnCncInterface {
    /// Create a new CNC interface
    pub fn new(cnc_endpoint: &str) -> Self {
        Self {
            cnc_endpoint: cnc_endpoint.to_string(),
            cnc_session_id: None,
            connected: false,
            last_config_update: 0,
            stream_configs: Vec::new(),
            gate_update_interval_ns: 1_000_000, // Default 1ms
        }
    }

    /// Connect to CNC
    pub fn connect(&mut self, session_id: &str) {
        self.cnc_session_id = Some(session_id.to_string());
        self.connected = true;
        self.last_config_update = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("value expected")
            .as_secs();
        log::info!(
            "[TSN CNC] Connected to CNC at {} with session ID {}",
            self.cnc_endpoint,
            session_id
        );
    }

    /// Disconnect from CNC
    pub fn disconnect(&mut self) {
        self.connected = false;
        log::info!("[TSN CNC] Disconnected from CNC at {}", self.cnc_endpoint);
    }

    /// Add stream configuration from CNC
    pub fn add_stream_config(&mut self, stream: TsnStreamIdentification) {
        log::info!(
            "[TSN CNC] Adding stream config: ID={}, VLAN={}, QFI={}, 5QI={}",
            stream.stream_id,
            stream.vlan_id,
            stream.qfi,
            stream.five_qi
        );
        self.stream_configs.push(stream);
        self.last_config_update = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("value expected")
            .as_secs();
    }

    /// Find stream by ID
    pub fn find_stream(&self, stream_id: u32) -> Option<&TsnStreamIdentification> {
        self.stream_configs
            .iter()
            .find(|s| s.stream_id == stream_id)
    }

    /// Find stream by packet characteristics
    pub fn find_stream_by_packet(
        &self,
        src_mac: &[u8; 6],
        dst_mac: &[u8; 6],
        vlan_id: u16,
    ) -> Option<&TsnStreamIdentification> {
        self.stream_configs
            .iter()
            .find(|s| s.matches(src_mac, dst_mac, vlan_id))
    }
}

/// UPF TSN Bridge context (Rel-18, TS 23.501 clause 5.28)
#[derive(Debug, Clone, Default)]
pub struct TsnBridge {
    /// Bridge ports (port_id -> config)
    pub ports: HashMap<u16, TsnBridgePort>,
    /// PTP transparent clock
    pub ptp_clock: PtpTransparentClock,
    /// Bridge ID (MAC-based, 8 bytes)
    pub bridge_id: [u8; 8],
    /// TSN stream identifications (stream_id -> stream)
    pub streams: HashMap<u32, TsnStreamIdentification>,
    /// CNC interface for centralized configuration
    pub cnc_interface: Option<TsnCncInterface>,
    /// Time-aware scheduling enabled globally
    pub time_aware_scheduling_enabled: bool,
    /// Cycle time for time-aware scheduling (nanoseconds)
    pub cycle_time_ns: u64,
    /// Port Management Information Containers received over N4, keyed by the NW-TT
    /// port number they were sent with (#321, TS 29.244 §8.2.144).
    ///
    /// Held as RAW OCTETS and not interpreted: §8.2.144 says the container encodes a
    /// Port management message from clause 8 of TS 24.539, and this tree has no
    /// TS 24.539 codec. Storing them is what makes the configuration the SMF sent
    /// observable and reportable; acting on their contents needs that codec and is a
    /// stated ceiling.
    pub port_management_containers: HashMap<u32, Vec<u8>>,
    /// The User Plane Node Management Information Container (the UMIC) last received
    /// over N4 (§8.2.182). Bridge-level, so there is one, not one per port.
    pub user_plane_node_management_container: Option<Vec<u8>>,
}

impl TsnBridge {
    /// Create a new TSN bridge with the given bridge ID
    pub fn new(bridge_id: [u8; 8]) -> Self {
        Self {
            ports: HashMap::new(),
            ptp_clock: PtpTransparentClock::default(),
            bridge_id,
            streams: HashMap::new(),
            cnc_interface: None,
            time_aware_scheduling_enabled: false,
            cycle_time_ns: 1_000_000, // Default 1ms cycle
            port_management_containers: HashMap::new(),
            user_plane_node_management_container: None,
        }
    }

    /// Apply one TSC Management Information IE received over N4 (#321,
    /// TS 29.244 §7.5.4.18).
    ///
    /// Returns whether anything was applied. A PMIC with no NW-TT Port Number is
    /// REJECTED rather than stored under a default port: §7.5.4.18 makes the port
    /// number conditional-mandatory when a PMIC is present precisely because port
    /// configuration with no port is unattributable, and defaulting it to 0 would
    /// silently attribute it to whichever port happens to be numbered 0.
    pub fn apply_tsc_management_information(
        &mut self,
        tsc: &nextgcore_pfcp::types::TscManagementInformation,
    ) -> bool {
        let mut applied = false;

        match (&tsc.port_management_container, tsc.nw_tt_port_number) {
            (Some(pmic), Some(port)) => {
                // A port the bridge has no entry for gets one: the SMF naming a port
                // in a PMIC is how the UPF learns the NW-TT side exists at all, and
                // dropping the container until some other message creates the port
                // would make the order of unrelated messages decide whether TSC works.
                self.ports
                    .entry(port as u16)
                    .or_insert_with(|| TsnBridgePort {
                        port_id: port as u16,
                        vlan_id: 0,
                        priority: 0,
                        is_trunk: false,
                        allowed_vlans: Vec::new(),
                        port_type: TsnPortType::NetworkSideTt,
                        time_aware_shaper_enabled: false,
                        gate_control_list: Vec::new(),
                    });
                self.port_management_containers.insert(port, pmic.clone());
                applied = true;
            }
            (Some(_), None) => {
                log::warn!(
                    "[TSN Bridge] TSC Management Information carries a PMIC with no NW-TT \
                     Port Number — not applied (TS 29.244 Table 7.5.4.18-1)"
                );
            }
            (None, _) => {}
        }

        if let Some(umic) = &tsc.user_plane_node_management_container {
            self.user_plane_node_management_container = Some(umic.clone());
            applied = true;
        }

        applied
    }

    /// What this bridge would report back in a TSC Management Information IE
    /// (§7.5.5.3): the containers it holds, per port, plus the bridge-level one.
    ///
    /// This is an echo of what was applied, which is what makes the SMF's
    /// "N sent, M echoed" comparison meaningful rather than a guess.
    pub fn tsc_management_information(
        &self,
    ) -> Vec<nextgcore_pfcp::types::TscManagementInformation> {
        use nextgcore_pfcp::types::TscManagementInformation;
        let mut out: Vec<_> = self
            .port_management_containers
            .iter()
            .map(|(port, cont)| TscManagementInformation::port(cont.clone(), *port))
            .collect();
        // Deterministic order: a HashMap iteration order would make the response
        // bytes differ run to run for identical state, which no test can pin.
        out.sort_by_key(|ie| ie.nw_tt_port_number);
        if let Some(umic) = &self.user_plane_node_management_container {
            out.push(TscManagementInformation::user_plane_node(umic.clone()));
        }
        out
    }

    /// Add a bridge port
    pub fn add_port(&mut self, port: TsnBridgePort) {
        log::info!(
            "[TSN Bridge] Adding port {} (type: {:?}, VLAN: {})",
            port.port_id,
            port.port_type,
            port.vlan_id
        );
        self.ports.insert(port.port_id, port);
    }

    /// Remove a bridge port
    pub fn remove_port(&mut self, port_id: u16) -> Option<TsnBridgePort> {
        self.ports.remove(&port_id)
    }

    /// Look up egress port for a given VLAN ID
    pub fn lookup_egress(&self, vlan_id: u16) -> Vec<u16> {
        self.ports
            .iter()
            .filter(|(_, p)| {
                p.vlan_id == vlan_id || (p.is_trunk && p.allowed_vlans.contains(&vlan_id))
            })
            .map(|(&id, _)| id)
            .collect()
    }

    /// Enable PTP transparent clock
    pub fn enable_ptp(&mut self) {
        self.ptp_clock.enabled = true;
        log::info!("[TSN Bridge] PTP transparent clock enabled");
    }

    /// Number of configured ports
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// Add TSN stream identification
    pub fn add_stream(&mut self, stream: TsnStreamIdentification) {
        log::info!(
            "[TSN Bridge] Adding stream {}: VLAN={}, QFI={}, 5QI={}",
            stream.stream_id,
            stream.vlan_id,
            stream.qfi,
            stream.five_qi
        );
        self.streams.insert(stream.stream_id, stream);
    }

    /// Remove TSN stream
    pub fn remove_stream(&mut self, stream_id: u32) -> Option<TsnStreamIdentification> {
        self.streams.remove(&stream_id)
    }

    /// Map TSN stream to QoS Flow
    pub fn map_stream_to_qos_flow(
        &self,
        src_mac: &[u8; 6],
        dst_mac: &[u8; 6],
        vlan_id: u16,
    ) -> Option<(u8, u8)> {
        // Find matching stream
        let stream = self
            .streams
            .values()
            .find(|s| s.matches(src_mac, dst_mac, vlan_id))?;

        log::debug!(
            "[TSN Bridge] Mapped stream {} to QFI={}, 5QI={}",
            stream.stream_id,
            stream.qfi,
            stream.five_qi
        );

        Some((stream.qfi, stream.five_qi))
    }

    /// Set CNC interface
    pub fn set_cnc_interface(&mut self, cnc: TsnCncInterface) {
        log::info!("[TSN Bridge] Setting CNC interface: {}", cnc.cnc_endpoint);
        self.cnc_interface = Some(cnc);
    }

    /// Enable time-aware scheduling (IEEE 802.1Qbv)
    pub fn enable_time_aware_scheduling(&mut self, cycle_time_ns: u64) {
        self.time_aware_scheduling_enabled = true;
        self.cycle_time_ns = cycle_time_ns;
        log::info!("[TSN Bridge] Time-aware scheduling enabled with cycle time {cycle_time_ns}ns");
    }

    /// Get current gate state for a port and priority (IEEE 802.1Qbv)
    pub fn get_gate_state(&self, port_id: u16, priority: u8, current_time_ns: u64) -> bool {
        let port = match self.ports.get(&port_id) {
            Some(p) => p,
            None => return true, // Port not found, allow all
        };

        if !port.time_aware_shaper_enabled || port.gate_control_list.is_empty() {
            return true; // Shaper disabled, allow all
        }

        // Calculate position in cycle
        let cycle_position = current_time_ns % self.cycle_time_ns;

        // Find active gate control entry
        let mut accumulated_time = 0u64;
        for entry in &port.gate_control_list {
            accumulated_time += entry.time_interval_ns;
            if cycle_position < accumulated_time {
                // Check if gate is open for this priority
                return (entry.gate_states & (1 << priority)) != 0;
            }
        }

        // Fallback: allow
        true
    }

    /// Number of configured streams
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}

// ============================================================================
// UPF Context
// ============================================================================

/// UPF Context - main context structure for UPF
/// Port of upf_context_t from context.h
pub struct UpfContext {
    /// Read handle on the live N4 session count, published by
    /// `pfcp_path::PfcpServer` (see [`UpfContext::set_session_gauge`]).
    ///
    /// `None` until the PFCP server is constructed, which is why
    /// [`UpfContext::sess_count`] reports 0 before then: at that point the UPF
    /// genuinely has no sessions.
    session_gauge: RwLock<Option<Arc<AtomicUsize>>>,

    /// Session ceiling from `--max-sessions`; 0 means "no ceiling configured".
    ///
    /// Atomic because `upf_self()` hands out `&'static UpfContext`, so there is no
    /// `&mut` moment after start-up in which to record it. It used to be a plain
    /// `usize` set by a `&mut self` `init` that the global could never call, so the
    /// operator's `--max-sessions` was silently discarded and `get_load`'s
    /// percentage branch was unreachable (#325).
    max_num_of_sess: AtomicUsize,

    /// Context initialized flag
    initialized: AtomicBool,
}

impl UpfContext {
    /// Create a new UPF context
    pub fn new() -> Self {
        Self {
            session_gauge: RwLock::new(None),
            max_num_of_sess: AtomicUsize::new(0),
            initialized: AtomicBool::new(false),
        }
    }

    /// Record the session ceiling and mark the context live.
    ///
    /// Takes `&self`, not `&mut self`: the only caller reaches this through
    /// `upf_self()`, which is a `&'static`. The `&mut self` version could not be
    /// called from there at all, so `--max-sessions` never arrived (#325).
    pub fn init(&self, max_sess: usize) {
        // The ceiling is stored UNCONDITIONALLY and the flag only latches liveness.
        // Gating the store on the flag would mean a context something had already
        // marked live could never record a ceiling -- harmless in production, where
        // `upf_context_init` is called exactly once from `main`, but in a test
        // binary the process-global is shared and whichever test got there first
        // would decide the ceiling for every other.
        self.max_num_of_sess.store(max_sess, Ordering::SeqCst);
        if self.initialized.swap(true, Ordering::SeqCst) {
            return;
        }
        log::info!("UPF context initialized with max {max_sess} sessions");
    }

    /// Release the context's own state. The session stores belong to the PFCP
    /// server and the data plane and are torn down with them.
    pub fn fini(&self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        *self.session_gauge.write().unwrap() = None;
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("UPF context finalized");
    }

    /// Check if context is initialized.
    ///
    /// `#[cfg(test)]` because the only reader is
    /// `the_session_ceiling_reaches_the_global_context`, and the newly-effective
    /// `dead_code` gate (see the crate attribute in `main.rs`) said so the moment it
    /// was turned on. The FLAG is production state — `init` uses it to latch
    /// double-initialisation and `fini` to refuse a second teardown — so what is
    /// test-only is this accessor, not the thing it reads. Saying that in the
    /// signature is the difference between a test affordance and the test-only
    /// reader class that #325 was.
    #[cfg(test)]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Publish the live N4 session count so [`UpfContext::get_load`] can read it.
    ///
    /// The handle is owned by `pfcp_path::PfcpServer`, which stores
    /// `sessions.len()` into it inside every write scope that changes the map's
    /// size. It is deliberately a READ HANDLE on one store and not a second store:
    /// the value is always assigned from a `len()` and never incremented, so it
    /// cannot hold a count the map never had. That is the distinction from #325's
    /// rejected option 3, whose failure mode was a SESSION present in one store and
    /// absent from the other.
    pub fn set_session_gauge(&self, gauge: Arc<AtomicUsize>) {
        *self.session_gauge.write().unwrap() = Some(gauge);
    }

    /// Live N4 session count, read from the gauge the PFCP server published.
    ///
    /// 0 before [`UpfContext::set_session_gauge`] has been called, which is the
    /// truthful answer during start-up. Before #325 this read a `sess_list` that
    /// only tests ever wrote, so it was 0 FOREVER — and `get_load` below is the
    /// production caller that turned that into a wire-visible lie.
    pub fn sess_count(&self) -> usize {
        self.session_gauge
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(|g| g.load(Ordering::Relaxed)))
            .unwrap_or(0)
    }

    /// NFProfile `load` gauge (`0..=100`) reported to the NRF on each
    /// heartbeat PATCH (TS 29.510 §5.2.2.3.2; `NFProfile.load` is a
    /// percentage `0..=100`), and the PFCP Load Control Information metric
    /// (TS 29.244 §5.19.1) under `compute-aware-upf`.
    ///
    /// Occupancy of the live N4 session store against the configured
    /// `--max-sessions` ceiling. When no ceiling is configured the raw session
    /// count is reported, saturated at 100.
    ///
    /// #325 fixed two independent defects on these four lines. The numerator came
    /// from a store nothing wrote in production, so this returned 0 for every
    /// deployment; and the denominator was a `usize` that `upf_context_init`
    /// discarded, so the percentage branch was unreachable and a UPF at 100 of 1024
    /// sessions reported `load: 100`. An SMF or NRF doing load-aware selection could
    /// act on neither.
    pub fn get_load(&self) -> u8 {
        let sessions = self.sess_count();
        // `checked_div` yields `None` iff no ceiling is configured, in which case we
        // report the raw session count.
        let load = match sessions
            .saturating_mul(100)
            .checked_div(self.max_num_of_sess.load(Ordering::Relaxed))
        {
            Some(pct) => pct.min(100),
            None => sessions.min(100),
        };
        load as u8
    }
}

impl Default for UpfContext {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Context (singleton pattern)
// ============================================================================

use std::sync::OnceLock;

static UPF_CONTEXT: OnceLock<UpfContext> = OnceLock::new();

/// Get the global UPF context
pub fn upf_self() -> &'static UpfContext {
    UPF_CONTEXT.get_or_init(UpfContext::new)
}

/// Initialize the global UPF context, recording the session ceiling.
///
/// This used to DISCARD `max_sess` behind a comment saying a `OnceLock` could not
/// be mutated. True of the old `&mut self` `UpfContext::init`, and the consequence
/// was that `--max-sessions` never reached `get_load`'s denominator (#325).
/// `max_num_of_sess` is an atomic now, so the ceiling arrives.
pub fn upf_context_init(max_sess: usize) {
    UPF_CONTEXT.get_or_init(UpfContext::new).init(max_sess);
}

/// Finalize the global UPF context
pub fn upf_context_final() {
    if let Some(ctx) = UPF_CONTEXT.get() {
        ctx.fini();
    }
    log::info!("UPF context finalized");
}

/// The one agreement about the process-global [`UPF_CONTEXT`] in tests.
///
/// `upf_self()` hands out a `&'static UpfContext`, so a test that publishes a
/// session gauge or records a session ceiling is mutating state every sibling test
/// can see. Declared HERE, beside the global it protects, rather than inside a
/// `mod tests`: a lock declared inside one module's test block is unreachable from
/// a sibling module's, so the next test that needs one declares a second — and two
/// locks are two disjoint agreements about one variable (#308).
///
/// Have any `mod tests` that touches `upf_self()` `use` this.
#[cfg(test)]
pub(crate) static UPF_GLOBAL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsn_bridge() {
        let mut bridge = TsnBridge::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);

        bridge.add_port(TsnBridgePort {
            port_id: 1,
            vlan_id: 100,
            priority: 5,
            is_trunk: false,
            allowed_vlans: vec![],
            port_type: TsnPortType::DeviceSideTt,
            time_aware_shaper_enabled: false,
            gate_control_list: vec![],
        });
        bridge.add_port(TsnBridgePort {
            port_id: 2,
            vlan_id: 200,
            priority: 3,
            is_trunk: true,
            allowed_vlans: vec![100, 200, 300],
            port_type: TsnPortType::NetworkSideTt,
            time_aware_shaper_enabled: false,
            gate_control_list: vec![],
        });

        assert_eq!(bridge.port_count(), 2);

        // VLAN 100 matches port 1 (access) and port 2 (trunk with 100 allowed)
        let egress = bridge.lookup_egress(100);
        assert_eq!(egress.len(), 2);

        // VLAN 300 matches only port 2 (trunk)
        let egress = bridge.lookup_egress(300);
        assert_eq!(egress.len(), 1);
        assert_eq!(egress[0], 2);

        // VLAN 999 matches nothing
        assert!(bridge.lookup_egress(999).is_empty());

        bridge.remove_port(1);
        assert_eq!(bridge.port_count(), 1);
    }

    #[test]
    fn test_ptp_transparent_clock() {
        let mut clock = PtpTransparentClock::default();
        assert!(!clock.enabled);

        // disabled clock ignores records
        clock.record_residence(100, 200);
        assert_eq!(clock.messages_processed, 0);

        clock.enabled = true;
        clock.record_residence(1000, 1500); // 500 ns
        clock.record_residence(2000, 2300); // 300 ns

        assert_eq!(clock.messages_processed, 2);
        assert_eq!(clock.residence_time_ns, 800);
        assert_eq!(clock.mean_path_delay_ns, 400);
    }

    /// G2-2: PFCP-session occupancy load gauge (TS 29.510 §5.2.2.3.2, `0..=100`).
    ///
    /// This is the arithmetic only. It used to drive the count by calling
    /// `ctx.sess_add` — a writer that exists ONLY in tests — so it proved the
    /// percentage while the shipped binary reported 0 for every deployment (#325).
    /// The count now comes from a gauge, and the test that the gauge is fed by the
    /// live N4 path lives in `pfcp_path`, where that path can actually be driven:
    /// `the_load_gauge_follows_the_live_n4_session_store`.
    #[test]
    fn test_get_load_gauge() {
        let gauge = |n: usize| Arc::new(AtomicUsize::new(n));

        // No gauge published yet → 0. Truthful during start-up.
        let ctx = UpfContext::new();
        assert_eq!(ctx.get_load(), 0);

        // With a ceiling, load is percentage occupancy.
        let ctx = UpfContext::new();
        ctx.init(10);
        ctx.set_session_gauge(gauge(2));
        assert_eq!(ctx.sess_count(), 2);
        assert_eq!(ctx.get_load(), 20, "2/10 sessions = 20%");

        // At the ceiling → saturates at 100%.
        let ctx = UpfContext::new();
        ctx.init(2);
        ctx.set_session_gauge(gauge(2));
        assert_eq!(ctx.get_load(), 100, "full occupancy = 100%");

        // Over the ceiling cannot exceed 100: NFProfile.load is a percentage.
        let ctx = UpfContext::new();
        ctx.init(2);
        ctx.set_session_gauge(gauge(5));
        assert_eq!(ctx.get_load(), 100, "a percentage cannot exceed 100");

        // No ceiling configured (max == 0) → raw count reported, capped at 100.
        let ctx = UpfContext::new();
        ctx.set_session_gauge(gauge(3));
        assert_eq!(ctx.get_load(), 3, "no ceiling → raw session count");
    }

    /// The ceiling has to survive the trip through the process-global, because that
    /// is the trip it did not survive: `upf_context_init` took `--max-sessions` and
    /// dropped it, so `get_load` never took its percentage branch in production
    /// however the arithmetic tested above behaved (#325).
    #[test]
    fn the_session_ceiling_reaches_the_global_context() {
        let _guard = UPF_GLOBAL_TEST_LOCK.lock().unwrap();

        upf_context_init(200);
        let ctx = upf_self();
        assert!(
            ctx.is_initialized(),
            "upf_context_init must mark the global live"
        );
        ctx.set_session_gauge(Arc::new(AtomicUsize::new(50)));
        assert_eq!(
            ctx.get_load(),
            25,
            "50 of the 200 sessions --max-sessions configured is 25%, not the raw \
             count 50 the discarded ceiling used to produce"
        );
    }
}
