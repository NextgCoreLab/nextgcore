//! SMF Context Management
//!
//! Port of src/smf/context.c, src/smf/context.h - SMF context with UE list, session list,
//! bearer list, packet filter list, and hash tables

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use crate::session_extensions::Ipv4Pool;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of DNS servers
pub const MAX_NUM_OF_DNS: usize = 2;
/// Maximum number of P-CSCF servers
pub const MAX_NUM_OF_P_CSCF: usize = 16;
/// Maximum IMSI length
pub const NEXTGCORE_MAX_IMSI_LEN: usize = 15;
/// Maximum IMSI BCD length
pub const NEXTGCORE_MAX_IMSI_BCD_LEN: usize = 15;
/// Maximum MSISDN length
pub const NEXTGCORE_MAX_MSISDN_LEN: usize = 15;
/// Maximum MSISDN BCD length
pub const NEXTGCORE_MAX_MSISDN_BCD_LEN: usize = 15;
/// Maximum IMEISV length
pub const NEXTGCORE_MAX_IMEISV_LEN: usize = 8;
/// Maximum IMEISV BCD length
pub const NEXTGCORE_MAX_IMEISV_BCD_LEN: usize = 16;
/// Maximum number of PCC rules
pub const NEXTGCORE_MAX_NUM_OF_PCC_RULE: usize = 8;
/// Maximum number of flows in NAS
pub const NEXTGCORE_MAX_NUM_OF_FLOW_IN_NAS: usize = 16;
/// Maximum number of flows in bearer
pub const NEXTGCORE_MAX_NUM_OF_FLOW_IN_BEARER: usize = 16;
/// Invalid pool ID
pub const NEXTGCORE_INVALID_POOL_ID: u64 = 0;
/// NAS PDU session identity unassigned
pub const NEXTGCORE_NAS_PDU_SESSION_IDENTITY_UNASSIGNED: u8 = 0;

// ============================================================================
// Basic Types
// ============================================================================

/// CTF (Charging Trigger Function) enabled mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CtfEnabledMode {
    #[default]
    Auto,
    Yes,
    No,
}

/// CTF configuration
#[derive(Debug, Clone, Default)]
pub struct CtfConfig {
    pub enabled: CtfEnabledMode,
}

/// PLMN ID
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PlmnId {
    pub mcc1: u8,
    pub mcc2: u8,
    pub mcc3: u8,
    pub mnc1: u8,
    pub mnc2: u8,
    pub mnc3: u8,
}

impl PlmnId {
    pub fn new(mcc: &str, mnc: &str) -> Self {
        let mcc_bytes: Vec<u8> = mcc
            .chars()
            .filter_map(|c| c.to_digit(10).map(|d| d as u8))
            .collect();
        let mnc_bytes: Vec<u8> = mnc
            .chars()
            .filter_map(|c| c.to_digit(10).map(|d| d as u8))
            .collect();

        Self {
            mcc1: mcc_bytes.first().copied().unwrap_or(0),
            mcc2: mcc_bytes.get(1).copied().unwrap_or(0),
            mcc3: mcc_bytes.get(2).copied().unwrap_or(0),
            mnc1: mnc_bytes.first().copied().unwrap_or(0),
            mnc2: mnc_bytes.get(1).copied().unwrap_or(0),
            mnc3: mnc_bytes.get(2).copied().unwrap_or(0xf),
        }
    }
}

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SNssai {
    pub sst: u8,
    pub sd: Option<u32>,
}

/// 5GS TAI (Tracking Area Identity)
#[derive(Debug, Clone, Default)]
pub struct Tai5gs {
    pub plmn_id: PlmnId,
    pub tac: u32,
}

/// NR CGI (NR Cell Global Identity)
#[derive(Debug, Clone, Default)]
pub struct NrCgi {
    pub plmn_id: PlmnId,
    pub cell_id: u64,
}

/// EPS TAI
#[derive(Debug, Clone, Default)]
pub struct EpsTai {
    pub plmn_id: PlmnId,
    pub tac: u16,
}

/// E-CGI (E-UTRAN Cell Global Identity)
#[derive(Debug, Clone, Default)]
pub struct ECgi {
    pub plmn_id: PlmnId,
    pub cell_id: u32,
}

/// GUAMI (Globally Unique AMF Identifier)
#[derive(Debug, Clone, Default)]
pub struct Guami {
    pub plmn_id: PlmnId,
    pub amf_id: AmfId,
}

/// AMF ID
#[derive(Debug, Clone, Default)]
pub struct AmfId {
    pub region: u8,
    pub set: u16,
    pub pointer: u8,
}

/// PDU Session Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PduSessionType {
    #[default]
    Ipv4,
    Ipv6,
    Ipv4v6,
    Unstructured,
    Ethernet,
}

/// Access Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessType {
    #[default]
    ThreeGppAccess,
    NonThreeGppAccess,
}

/// RAT Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RatType {
    #[default]
    Nr,
    Eutra,
    Wlan,
    Virtual,
}

/// UP Connection State
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpCnxState {
    #[default]
    Deactivated,
    Activating,
    Activated,
}

/// Resource Status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResourceStatus {
    #[default]
    Released,
    Unchanged,
    Transferred,
}

/// Max Integrity Protected Data Rate
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MaxIntegrityProtectedDataRate {
    #[default]
    Bitrate64kbps,
    MaxUeRate,
}

/// IP Address (IPv4 or IPv6)
#[derive(Debug, Clone, Default)]
pub struct IpAddr {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

/// QoS parameters
#[derive(Debug, Clone, Default)]
pub struct Qos {
    pub index: u8, // 5QI
    pub arp_priority_level: u8,
    pub arp_preempt_cap: bool,
    pub arp_preempt_vuln: bool,
    pub mbr_uplink: u64,
    pub mbr_downlink: u64,
    pub gbr_uplink: u64,
    pub gbr_downlink: u64,
}

// ============================================================================
// Rel-18 XR QoS Characteristics (TS 23.501 Table 5.7.4-1)
// ============================================================================

/// 5QI characteristics table entry for XR and standard flows.
#[derive(Debug, Clone)]
pub struct QosCharacteristics {
    /// Resource type: 0=GBR, 1=Delay-critical GBR, 2=Non-GBR
    pub resource_type: u8,
    /// Priority level (1=highest)
    pub priority_level: u8,
    /// Packet delay budget (ms)
    pub packet_delay_budget_ms: u16,
    /// Packet error rate (e.g., 1e-3 stored as exponent: 3)
    pub packet_error_rate_exp: u8,
    /// Maximum Data Burst Volume (bytes, 0 = N/A)
    pub max_data_burst_volume: u32,
    /// Default averaging window (ms)
    pub averaging_window_ms: u32,
}

impl QosCharacteristics {
    /// Look up 5QI characteristics from the 3GPP standardized table.
    pub fn from_5qi(five_qi: u8) -> Option<Self> {
        match five_qi {
            // Standard GBR 5QIs
            1 => Some(Self {
                resource_type: 0,
                priority_level: 20,
                packet_delay_budget_ms: 100,
                packet_error_rate_exp: 2,
                max_data_burst_volume: 0,
                averaging_window_ms: 2000,
            }),
            2 => Some(Self {
                resource_type: 0,
                priority_level: 40,
                packet_delay_budget_ms: 150,
                packet_error_rate_exp: 3,
                max_data_burst_volume: 0,
                averaging_window_ms: 2000,
            }),
            3 => Some(Self {
                resource_type: 0,
                priority_level: 30,
                packet_delay_budget_ms: 50,
                packet_error_rate_exp: 3,
                max_data_burst_volume: 0,
                averaging_window_ms: 2000,
            }),
            4 => Some(Self {
                resource_type: 0,
                priority_level: 50,
                packet_delay_budget_ms: 300,
                packet_error_rate_exp: 6,
                max_data_burst_volume: 0,
                averaging_window_ms: 2000,
            }),
            65 => Some(Self {
                resource_type: 0,
                priority_level: 7,
                packet_delay_budget_ms: 75,
                packet_error_rate_exp: 2,
                max_data_burst_volume: 0,
                averaging_window_ms: 2000,
            }),
            66 => Some(Self {
                resource_type: 0,
                priority_level: 20,
                packet_delay_budget_ms: 100,
                packet_error_rate_exp: 2,
                max_data_burst_volume: 0,
                averaging_window_ms: 2000,
            }),
            67 => Some(Self {
                resource_type: 0,
                priority_level: 15,
                packet_delay_budget_ms: 100,
                packet_error_rate_exp: 3,
                max_data_burst_volume: 0,
                averaging_window_ms: 2000,
            }),
            // Standard Non-GBR 5QIs
            5 => Some(Self {
                resource_type: 2,
                priority_level: 10,
                packet_delay_budget_ms: 100,
                packet_error_rate_exp: 6,
                max_data_burst_volume: 0,
                averaging_window_ms: 0,
            }),
            6 => Some(Self {
                resource_type: 2,
                priority_level: 60,
                packet_delay_budget_ms: 300,
                packet_error_rate_exp: 6,
                max_data_burst_volume: 0,
                averaging_window_ms: 0,
            }),
            7 => Some(Self {
                resource_type: 2,
                priority_level: 70,
                packet_delay_budget_ms: 100,
                packet_error_rate_exp: 3,
                max_data_burst_volume: 0,
                averaging_window_ms: 0,
            }),
            8 => Some(Self {
                resource_type: 2,
                priority_level: 80,
                packet_delay_budget_ms: 300,
                packet_error_rate_exp: 6,
                max_data_burst_volume: 0,
                averaging_window_ms: 0,
            }),
            9 => Some(Self {
                resource_type: 2,
                priority_level: 90,
                packet_delay_budget_ms: 300,
                packet_error_rate_exp: 6,
                max_data_burst_volume: 0,
                averaging_window_ms: 0,
            }),
            // Delay-critical GBR range, TS 23.501 Table 5.7.4-1.
            //
            // These four were previously wrong in every field except the
            // averaging window, and were labelled "Rel-18 XR" -- which is not
            // what the spec assigns them to. 82/83 are Discrete Automation
            // (83 also V2X platooning), 84 Intelligent transport systems,
            // 85 Electricity Distribution at high voltage. Note resource_type
            // is 1 (delay-critical GBR), not 0 (GBR).
            82 => Some(Self {
                resource_type: 1,
                priority_level: 19,
                packet_delay_budget_ms: 10,
                packet_error_rate_exp: 4,
                max_data_burst_volume: 255,
                averaging_window_ms: 2000,
            }),
            83 => Some(Self {
                resource_type: 1,
                priority_level: 22,
                packet_delay_budget_ms: 10,
                packet_error_rate_exp: 4,
                max_data_burst_volume: 1354,
                averaging_window_ms: 2000,
            }),
            84 => Some(Self {
                resource_type: 1,
                priority_level: 24,
                packet_delay_budget_ms: 30,
                packet_error_rate_exp: 5,
                max_data_burst_volume: 1354,
                averaging_window_ms: 2000,
            }),
            85 => Some(Self {
                resource_type: 1,
                priority_level: 21,
                packet_delay_budget_ms: 5,
                packet_error_rate_exp: 5,
                max_data_burst_volume: 255,
                averaging_window_ms: 2000,
            }),
            _ => None,
        }
    }

    /// Returns true if this 5QI is a GBR (Guaranteed Bit Rate) flow.
    pub fn is_gbr(&self) -> bool {
        self.resource_type == 0 || self.resource_type == 1
    }

    /// Returns true if this 5QI is an XR-specific QoS indicator.
    pub fn is_xr(five_qi: u8) -> bool {
        (82..=85).contains(&five_qi)
    }
}

// ============================================================================
// Rel-18 Energy Saving Types
// ============================================================================

/// UE power saving preference (Rel-18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PowerPreference {
    /// Normal operation
    #[default]
    Normal,
    /// Low power mode (prefer longer DRX, relaxed measurements)
    LowPower,
    /// Ultra-low power (aggressive PSM, extended eDRX)
    UltraLowPower,
}

/// Energy-aware session parameters.
#[derive(Debug, Clone, Default)]
pub struct EnergyConfig {
    /// UE power preference indication
    pub power_preference: PowerPreference,
    /// Inactivity detection timer (seconds, 0 = disabled)
    pub inactivity_timer_sec: u32,
    /// Buffered packet count suggestion (for UPF, 0 = no buffering)
    pub suggested_buffering_packets: u32,
    /// Whether to use reflective QoS to reduce signaling
    pub reflective_qos: bool,
}

// ============================================================================
// Rel-16: Network Slicing QoS Enforcement
// ============================================================================

/// Slice QoS Profile for per-slice resource enforcement (Rel-16 TS 23.501)
#[derive(Debug)]
pub struct SliceQosProfile {
    /// S-NSSAI for this slice
    pub s_nssai: SNssai,
    /// Maximum number of UEs allowed in this slice
    pub max_ues: u32,
    /// Current number of active UEs
    pub current_ues: AtomicU64,
    /// Maximum aggregate bandwidth for uplink (bps)
    pub max_ul_bandwidth_bps: u64,
    /// Maximum aggregate bandwidth for downlink (bps)
    pub max_dl_bandwidth_bps: u64,
    /// Current uplink bandwidth usage (bps)
    pub current_ul_bandwidth: AtomicU64,
    /// Current downlink bandwidth usage (bps)
    pub current_dl_bandwidth: AtomicU64,
    /// Priority level for slice (1=highest, 255=lowest)
    pub priority_level: u8,
    /// Whether slice is enabled
    pub enabled: AtomicBool,
}

impl SliceQosProfile {
    /// Create a new slice QoS profile
    pub fn new(
        s_nssai: SNssai,
        max_ues: u32,
        max_ul_bps: u64,
        max_dl_bps: u64,
        priority: u8,
    ) -> Self {
        Self {
            s_nssai,
            max_ues,
            current_ues: AtomicU64::new(0),
            max_ul_bandwidth_bps: max_ul_bps,
            max_dl_bandwidth_bps: max_dl_bps,
            current_ul_bandwidth: AtomicU64::new(0),
            current_dl_bandwidth: AtomicU64::new(0),
            priority_level: priority,
            enabled: AtomicBool::new(true),
        }
    }

    /// Check if a new session can be admitted to this slice
    pub fn can_admit_session(&self, ul_bandwidth: u64, dl_bandwidth: u64) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            return false;
        }

        let current_ues = self.current_ues.load(Ordering::Relaxed);
        if current_ues >= self.max_ues as u64 {
            return false;
        }

        let current_ul = self.current_ul_bandwidth.load(Ordering::Relaxed);
        let current_dl = self.current_dl_bandwidth.load(Ordering::Relaxed);

        if current_ul + ul_bandwidth > self.max_ul_bandwidth_bps {
            return false;
        }

        if current_dl + dl_bandwidth > self.max_dl_bandwidth_bps {
            return false;
        }

        true
    }

    /// Admit a new session to the slice
    pub fn admit_session(&self, ul_bandwidth: u64, dl_bandwidth: u64) {
        self.current_ues.fetch_add(1, Ordering::Relaxed);
        self.current_ul_bandwidth
            .fetch_add(ul_bandwidth, Ordering::Relaxed);
        self.current_dl_bandwidth
            .fetch_add(dl_bandwidth, Ordering::Relaxed);
    }

    /// Remove a session from the slice
    pub fn remove_session(&self, ul_bandwidth: u64, dl_bandwidth: u64) {
        self.current_ues.fetch_sub(1, Ordering::Relaxed);
        self.current_ul_bandwidth
            .fetch_sub(ul_bandwidth, Ordering::Relaxed);
        self.current_dl_bandwidth
            .fetch_sub(dl_bandwidth, Ordering::Relaxed);
    }
}

impl Clone for SliceQosProfile {
    fn clone(&self) -> Self {
        Self {
            s_nssai: self.s_nssai.clone(),
            max_ues: self.max_ues,
            current_ues: AtomicU64::new(self.current_ues.load(Ordering::Relaxed)),
            max_ul_bandwidth_bps: self.max_ul_bandwidth_bps,
            max_dl_bandwidth_bps: self.max_dl_bandwidth_bps,
            current_ul_bandwidth: AtomicU64::new(self.current_ul_bandwidth.load(Ordering::Relaxed)),
            current_dl_bandwidth: AtomicU64::new(self.current_dl_bandwidth.load(Ordering::Relaxed)),
            priority_level: self.priority_level,
            enabled: AtomicBool::new(self.enabled.load(Ordering::Relaxed)),
        }
    }
}

// ============================================================================
// Rel-16: URLLC QoS Constraints
// ============================================================================

/// URLLC QoS constraints per TS 23.501
/// 5QI 80-85 are reserved for URLLC with strict latency/reliability requirements
pub struct UrllcConstraints;

impl UrllcConstraints {
    /// Check if 5QI is in the URLLC/XR range (80-85)
    pub fn is_urllc_5qi(five_qi: u8) -> bool {
        (80..=85).contains(&five_qi)
    }

    /// Check if 5QI is strict URLLC (80-81), excluding XR-extended (82-85)
    /// XR 5QI 82-85 have relaxed priority/delay constraints per TS 23.501
    pub fn is_strict_urllc_5qi(five_qi: u8) -> bool {
        (80..=81).contains(&five_qi)
    }

    /// Enforce URLLC constraints on QoS flow
    /// Returns true if constraints are satisfied, false otherwise
    pub fn enforce_urllc_constraints(
        five_qi: u8,
        priority_level: u8,
        packet_delay_budget_ms: u16,
    ) -> bool {
        if !Self::is_urllc_5qi(five_qi) {
            return true; // Not URLLC, no constraints
        }

        // URLLC requirements per TS 23.501:
        // - Priority level must be ≤ 20 (higher priority)
        // - Packet delay budget must be ≤ 10ms

        if priority_level > 20 {
            log::warn!("URLLC 5QI {five_qi} requires priority level ≤ 20, got {priority_level}");
            return false;
        }

        if packet_delay_budget_ms > 10 {
            log::warn!("URLLC 5QI {five_qi} requires packet delay budget ≤ 10ms, got {packet_delay_budget_ms}ms");
            return false;
        }

        true
    }
}

// ============================================================================
// Rel-16: V2X QoS Profiles (TS 23.287)
// ============================================================================

/// V2X QoS profile for SST=3 (V2X services)
/// Defines 5QI values 75-79 for different V2X communication types
#[derive(Debug, Clone)]
pub struct V2xQosProfile {
    /// V2X communication type
    pub comm_type: V2xCommType,
    /// Recommended 5QI
    pub five_qi: u8,
    /// Priority level
    pub priority_level: u8,
    /// Packet delay budget (ms)
    pub packet_delay_budget_ms: u16,
    /// Packet error rate (10^-N)
    pub packet_error_rate_exp: u8,
}

/// V2X Communication Types (TS 23.287)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2xCommType {
    /// Vehicle-to-Vehicle
    V2V,
    /// Vehicle-to-Infrastructure
    V2I,
    /// Vehicle-to-Pedestrian
    V2P,
    /// Vehicle-to-Network
    V2N,
}

impl V2xQosProfile {
    /// Get V2X QoS profile for a communication type
    pub fn for_comm_type(comm_type: V2xCommType) -> Self {
        match comm_type {
            V2xCommType::V2V => Self {
                comm_type,
                five_qi: 75, // V2V - high priority, low latency
                priority_level: 25,
                packet_delay_budget_ms: 50,
                packet_error_rate_exp: 2,
            },
            V2xCommType::V2I => Self {
                comm_type,
                five_qi: 76, // V2I - infrastructure communication
                priority_level: 30,
                packet_delay_budget_ms: 100,
                packet_error_rate_exp: 3,
            },
            V2xCommType::V2P => Self {
                comm_type,
                five_qi: 77, // V2P - pedestrian safety
                priority_level: 20,
                packet_delay_budget_ms: 50,
                packet_error_rate_exp: 2,
            },
            V2xCommType::V2N => Self {
                comm_type,
                five_qi: 78, // V2N - network services
                priority_level: 40,
                packet_delay_budget_ms: 200,
                packet_error_rate_exp: 4,
            },
        }
    }

    /// Check if S-NSSAI is for V2X (SST=3)
    pub fn is_v2x_slice(s_nssai: &SNssai) -> bool {
        s_nssai.sst == 3
    }

    /// Get recommended 5QI for V2X slice based on priority
    pub fn get_v2x_5qi_for_priority(priority: u8) -> u8 {
        match priority {
            0..=20 => 75,  // V2V - highest priority
            21..=29 => 77, // V2P - pedestrian safety
            30..=39 => 76, // V2I - infrastructure
            _ => 78,       // V2N - network services (default)
        }
    }
}

/// Session AMBR
#[derive(Debug, Clone, Default)]
pub struct SessionAmbr {
    pub uplink: u64,
    pub downlink: u64,
}

/// Security Indication configuration
#[derive(Debug, Clone, Default)]
pub struct SecurityIndication {
    pub integrity_protection_indication: Option<String>,
    pub confidentiality_protection_indication: Option<String>,
    pub maximum_integrity_protected_data_rate_uplink: Option<String>,
    pub maximum_integrity_protected_data_rate_downlink: Option<String>,
}

/// Flow direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlowDirection {
    #[default]
    Bidirectional,
    UplinkOnly,
    DownlinkOnly,
}

/// IPFW Rule (IP Firewall Rule)
#[derive(Debug, Clone, Default)]
pub struct IpfwRule {
    pub proto: u8,
    pub src_addr: Option<Ipv4Addr>,
    pub src_mask: Option<Ipv4Addr>,
    pub dst_addr: Option<Ipv4Addr>,
    pub dst_mask: Option<Ipv4Addr>,
    pub src_addr6: Option<Ipv6Addr>,
    pub src_prefix_len6: u8,
    pub dst_addr6: Option<Ipv6Addr>,
    pub dst_prefix_len6: u8,
    pub src_port_low: u16,
    pub src_port_high: u16,
    pub dst_port_low: u16,
    pub dst_port_high: u16,
}

/// Packet Filter (alias for SmfPf for binding module)
pub type PacketFilter = SmfPf;

/// PCC Rule
#[derive(Debug, Clone, Default)]
pub struct PccRule {
    pub id: Option<String>,
    pub name: Option<String>,
    pub precedence: u32,
    pub flow_status: u8,
    pub qos: Qos,
}

// ============================================================================
// SMF UE Context
// ============================================================================

/// SMF UE context
/// Port of smf_ue_t from context.h
#[derive(Debug, Clone)]
pub struct SmfUe {
    pub id: u64,
    /// SUPI
    pub supi: Option<String>,
    /// GPSI
    pub gpsi: Option<String>,
    /// IMSI (binary)
    pub imsi: Vec<u8>,
    /// IMSI (BCD string)
    pub imsi_bcd: String,
    /// MSISDN (binary)
    pub msisdn: Vec<u8>,
    /// MSISDN (BCD string)
    pub msisdn_bcd: String,
    /// IMEISV (binary)
    pub imeisv: Vec<u8>,
    /// IMEISV (BCD string)
    pub imeisv_bcd: String,
    /// Session IDs belonging to this UE
    pub sess_ids: Vec<u64>,
}

impl SmfUe {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            supi: None,
            gpsi: None,
            imsi: Vec::new(),
            imsi_bcd: String::new(),
            msisdn: Vec::new(),
            msisdn_bcd: String::new(),
            imeisv: Vec::new(),
            imeisv_bcd: String::new(),
            sess_ids: Vec::new(),
        }
    }

    pub fn is_last_session(&self) -> bool {
        self.sess_ids.len() == 1
    }
}

// ============================================================================
// SMF Packet Filter Context
// ============================================================================

/// SMF Packet Filter context
/// Port of smf_pf_t from context.h
#[derive(Debug, Clone)]
pub struct SmfPf {
    pub id: u64,
    /// Direction (2 bits)
    pub direction: FlowDirection,
    /// Identifier (4 bits)
    pub identifier: u8,
    /// Precedence (only used in EPC)
    pub precedence: u8,
    /// SDF Filter ID
    pub sdf_filter_id: u32,
    /// IPFW rule
    pub ipfw_rule: IpfwRule,
    /// Flow description string
    pub flow_description: Option<String>,
    /// Parent bearer ID
    pub bearer_id: u64,
}

impl SmfPf {
    pub fn new(id: u64, bearer_id: u64) -> Self {
        Self {
            id,
            direction: FlowDirection::default(),
            identifier: 0,
            precedence: 0,
            sdf_filter_id: 0,
            ipfw_rule: IpfwRule::default(),
            flow_description: None,
            bearer_id,
        }
    }
}

impl Default for SmfPf {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// ============================================================================
// SMF Bearer Context
// ============================================================================

/// SMF Bearer/QoS Flow context
/// Port of smf_bearer_t from context.h
#[derive(Debug, Clone)]
pub struct SmfBearer {
    pub id: u64,
    /// QFI (5GC QoS Flow Identifier)
    pub qfi: u8,
    /// EBI (EPC EPS Bearer ID)
    pub ebi: u8,
    /// PGW S5U TEID
    pub pgw_s5u_teid: u32,
    /// PGW S5U IPv4 address
    pub pgw_s5u_addr: Option<Ipv4Addr>,
    /// PGW S5U IPv6 address
    pub pgw_s5u_addr6: Option<Ipv6Addr>,
    /// SGW S5U TEID
    pub sgw_s5u_teid: u32,
    /// SGW S5U IP
    pub sgw_s5u_ip: IpAddr,
    /// PCC Rule name (EPC)
    pub pcc_rule_name: Option<String>,
    /// PCC Rule ID (5GC)
    pub pcc_rule_id: Option<String>,
    /// QoS parameters
    pub qos: Qos,
    /// Packet filter IDs
    pub pf_ids: Vec<u64>,
    /// PF identifiers to delete
    pub pf_to_delete: Vec<u8>,
    /// Parent session ID
    pub sess_id: u64,
}

impl SmfBearer {
    /// The EBI assigned to this flow, or `None` when it has none (#117).
    ///
    /// `ebi` is a bare `u8` whose zero value is not a valid identity: TS 24.301
    /// §9.3.2 defines 0 as "no EPS bearer identity assigned" and reserves 1..=4,
    /// so an unset field and a real EBI are distinguishable without an `Option`.
    /// This accessor exists so no caller has to remember that — emitting a Mapped
    /// EPS bearer contexts IE with EBI 0 would tell the UE to build a bearer on
    /// the reserved identity.
    pub fn assigned_ebi(&self) -> Option<u8> {
        (self.ebi >= 5 && self.ebi <= 15).then_some(self.ebi)
    }

    pub fn new(id: u64, sess_id: u64) -> Self {
        Self {
            id,
            qfi: 0,
            ebi: 0,
            pgw_s5u_teid: 0,
            pgw_s5u_addr: None,
            pgw_s5u_addr6: None,
            sgw_s5u_teid: 0,
            sgw_s5u_ip: IpAddr::default(),
            pcc_rule_name: None,
            pcc_rule_id: None,
            qos: Qos::default(),
            pf_ids: Vec::new(),
            pf_to_delete: Vec::new(),
            sess_id,
        }
    }

    pub fn is_qos_flow(&self) -> bool {
        self.qfi != 0
    }
}

impl Default for SmfBearer {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// ============================================================================
// SMF Session Context
// ============================================================================

/// Policy Association info
#[derive(Debug, Clone, Default)]
pub struct PolicyAssociation {
    pub resource_uri: Option<String>,
    pub id: Option<String>,
}

impl PolicyAssociation {
    pub fn is_associated(&self) -> bool {
        self.id.is_some()
    }

    pub fn clear(&mut self) {
        self.resource_uri = None;
        self.id = None;
    }

    pub fn store(&mut self, resource_uri: &str, id: &str) {
        self.resource_uri = Some(resource_uri.to_string());
        self.id = Some(id.to_string());
    }
}

/// Data Change Subscription info
#[derive(Debug, Clone, Default)]
pub struct DataChangeSubscription {
    pub resource_uri: Option<String>,
    pub id: Option<String>,
}

impl DataChangeSubscription {
    pub fn is_subscribed(&self) -> bool {
        self.id.is_some()
    }

    pub fn clear(&mut self) {
        self.resource_uri = None;
        self.id = None;
    }

    pub fn store(&mut self, resource_uri: &str, id: &str) {
        self.resource_uri = Some(resource_uri.to_string());
        self.id = Some(id.to_string());
    }
}

/// Handover info
#[derive(Debug, Clone, Default)]
pub struct HandoverInfo {
    pub prepared: bool,
    pub data_forwarding_not_possible: bool,
    pub indirect_data_forwarding: bool,
    /// gNB N3 TEID
    pub gnb_n3_teid: u32,
    /// gNB N3 IP
    pub gnb_n3_ip: IpAddr,
    /// Local DL TEID for indirect forwarding
    pub local_dl_teid: u32,
    /// Local DL IPv4 for indirect forwarding
    pub local_dl_addr: Option<Ipv4Addr>,
    /// Local DL IPv6 for indirect forwarding
    pub local_dl_addr6: Option<Ipv6Addr>,
    /// Remote DL TEID for indirect forwarding
    pub remote_dl_teid: u32,
    /// Remote DL IP for indirect forwarding
    pub remote_dl_ip: IpAddr,
}

/// Charging info
#[derive(Debug, Clone, Default)]
pub struct ChargingInfo {
    pub id: u32,
}

/// Gy (Online Charging) info
#[derive(Debug, Clone, Default)]
pub struct GyInfo {
    pub ul_octets: u64,
    pub dl_octets: u64,
    pub duration: u64,
    pub reporting_reason: u32,
    pub final_unit: bool,
    pub last_report_ul_octets: u64,
    pub last_report_dl_octets: u64,
    pub last_report_duration: u64,
}

/// NGAP state for session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NgapState {
    #[default]
    None,
    DeleteTriggerUeRequested,
    DeleteTriggerPcfInitiated,
    ErrorIndicationReceivedFrom5gAn,
    DeleteTriggerSmfInitiated,
}

/// State machine data for session
#[derive(Debug, Clone, Default)]
pub struct SmData {
    pub gx_ccr_init_in_flight: bool,
    pub gx_cca_init_err: u32,
    pub gy_ccr_init_in_flight: bool,
    pub gy_cca_init_err: u32,
    pub s6b_aar_in_flight: bool,
    pub s6b_aaa_err: u32,
    pub gx_ccr_term_in_flight: bool,
    pub gx_cca_term_err: u32,
    pub gy_ccr_term_in_flight: bool,
    pub gy_cca_term_err: u32,
    pub s6b_str_in_flight: bool,
    pub s6b_sta_err: u32,
}

/// SMF Session context
/// Port of smf_sess_t from context.h
#[derive(Debug, Clone)]
pub struct SmfSess {
    pub id: u64,
    pub index: u32,
    /// State machine data
    pub sm_data: SmData,
    /// EPC or 5GC mode
    pub epc: bool,
    /// SBI features
    pub smpolicycontrol_features: u64,
    /// SMF N4 TEID
    pub smf_n4_teid: u32,
    /// SGW S5C TEID
    pub sgw_s5c_teid: u32,
    /// SGW S5C IP
    pub sgw_s5c_ip: IpAddr,
    /// SMF N4 SEID
    pub smf_n4_seid: u64,
    /// UPF N4 SEID
    pub upf_n4_seid: u64,
    /// Local DL TEID
    pub local_dl_teid: u32,
    /// Local DL IPv4
    pub local_dl_addr: Option<Ipv4Addr>,
    /// Local DL IPv6
    pub local_dl_addr6: Option<Ipv6Addr>,
    /// Remote DL TEID
    pub remote_dl_teid: u32,
    /// Remote DL IP
    pub remote_dl_ip: IpAddr,
    /// Local UL TEID
    pub local_ul_teid: u32,
    /// Local UL IPv4
    pub local_ul_addr: Option<Ipv4Addr>,
    /// Local UL IPv6
    pub local_ul_addr6: Option<Ipv6Addr>,
    /// Remote UL TEID
    pub remote_ul_teid: u32,
    /// Remote UL IP
    pub remote_ul_ip: IpAddr,
    /// Gx Session ID
    pub gx_sid: Option<String>,
    /// Gy Session ID
    pub gy_sid: Option<String>,
    /// S6b Session ID
    pub s6b_sid: Option<String>,
    /// PDU Session Identity
    pub psi: u8,
    /// Procedure Transaction Identity
    pub pti: u8,
    /// Request type
    pub request_type: u8,
    /// SM Context Reference
    pub sm_context_ref: Option<String>,
    /// SM Context Status URI
    pub sm_context_status_uri: Option<String>,
    /// PDU Session Reference
    pub pdu_session_ref: Option<String>,
    /// PDU Session Resource URI
    pub pdu_session_resource_uri: Option<String>,
    /// Policy Association
    pub policy_association: PolicyAssociation,
    /// Data Change Subscription
    pub data_change_subscription: DataChangeSubscription,
    /// UP Connection State
    pub up_cnx_state: UpCnxState,
    /// Serving PLMN ID
    pub serving_plmn_id: PlmnId,
    /// Home PLMN ID
    pub home_plmn_id: PlmnId,
    /// EPS TAI
    pub e_tai: EpsTai,
    /// E-CGI
    pub e_cgi: ECgi,
    /// NR TAI
    pub nr_tai: Tai5gs,
    /// NR CGI
    pub nr_cgi: NrCgi,
    /// UE location timestamp
    pub ue_location_timestamp: u64,
    /// H-SMF URI (for home-routed roaming)
    pub h_smf_uri: Option<String>,
    /// H-SMF ID
    pub h_smf_id: Option<String>,
    /// V-SMF PDU Session URI (for home-routed roaming)
    pub vsmf_pdu_session_uri: Option<String>,
    /// PCF ID
    pub pcf_id: Option<String>,
    /// AMF NF ID
    pub amf_nf_id: Option<String>,
    /// GUAMI
    pub guami: Guami,
    /// Integrity protection max data rate DL
    pub integrity_protection_mbr_dl: MaxIntegrityProtectedDataRate,
    /// Integrity protection max data rate UL
    pub integrity_protection_mbr_ul: MaxIntegrityProtectedDataRate,
    /// S-NSSAI
    pub s_nssai: SNssai,
    /// Mapped HPLMN S-NSSAI
    pub mapped_hplmn: SNssai,
    /// Mapped HPLMN presence
    pub mapped_hplmn_presence: bool,
    /// Session name (DNN/APN)
    pub session_name: Option<String>,
    /// Full DNN
    pub full_dnn: Option<String>,
    /// Session type
    pub session_type: PduSessionType,
    /// UE requested session type
    pub ue_session_type: u8,
    /// UE requested SSC mode
    pub ue_ssc_mode: u8,
    /// Session AMBR
    pub session_ambr: SessionAmbr,
    /// Session QoS
    pub session_qos: Qos,
    /// IPv4 address
    pub ipv4_addr: Option<Ipv4Addr>,
    /// IPv6 prefix
    pub ipv6_prefix: Option<(u8, Ipv6Addr)>,
    /// Access Type
    pub an_type: AccessType,
    /// GTP RAT Type
    pub gtp_rat_type: u8,
    /// SBI RAT Type
    pub sbi_rat_type: RatType,
    /// PCC Rules
    pub pcc_rules: Vec<PccRule>,
    /// Paging N1N2 message location
    pub paging_n1n2message_location: Option<String>,
    /// NGAP state
    pub ngap_state: NgapState,
    /// Handover info
    pub handover: HandoverInfo,
    /// Charging info
    pub charging: ChargingInfo,
    /// Gy info
    pub gy: GyInfo,
    /// Bearer IDs
    pub bearer_ids: Vec<u64>,
    /// QoS flows to modify list (for modification requests)
    pub qos_flow_to_modify_list: Vec<u64>,
    /// Parent UE ID
    pub smf_ue_id: u64,
    /// Resource status
    pub resource_status: ResourceStatus,
    /// N1 released flag
    pub n1_released: bool,
    /// N2 released flag
    pub n2_released: bool,
    /// Establishment accept sent flag
    pub establishment_accept_sent: bool,

    // Rel-17 Fields
    /// MBS session flag (Multicast/Broadcast Service, TS 23.247)
    pub is_mbs_session: bool,
    /// MBS session ID (if MBS)
    pub mbs_session_id: Option<String>,
    /// RedCap UE flag (reduced QoS for RedCap devices)
    pub is_redcap_ue: bool,
}

impl SmfSess {
    pub fn new(id: u64, index: u32, smf_ue_id: u64) -> Self {
        Self {
            id,
            index,
            sm_data: SmData::default(),
            epc: false,
            smpolicycontrol_features: 0,
            smf_n4_teid: 0,
            sgw_s5c_teid: 0,
            sgw_s5c_ip: IpAddr::default(),
            smf_n4_seid: 0,
            upf_n4_seid: 0,
            local_dl_teid: 0,
            local_dl_addr: None,
            local_dl_addr6: None,
            remote_dl_teid: 0,
            remote_dl_ip: IpAddr::default(),
            local_ul_teid: 0,
            local_ul_addr: None,
            local_ul_addr6: None,
            remote_ul_teid: 0,
            remote_ul_ip: IpAddr::default(),
            gx_sid: None,
            gy_sid: None,
            s6b_sid: None,
            psi: 0,
            pti: 0,
            request_type: 0,
            sm_context_ref: None,
            sm_context_status_uri: None,
            pdu_session_ref: None,
            pdu_session_resource_uri: None,
            policy_association: PolicyAssociation::default(),
            data_change_subscription: DataChangeSubscription::default(),
            up_cnx_state: UpCnxState::default(),
            serving_plmn_id: PlmnId::default(),
            home_plmn_id: PlmnId::default(),
            e_tai: EpsTai::default(),
            e_cgi: ECgi::default(),
            nr_tai: Tai5gs::default(),
            nr_cgi: NrCgi::default(),
            ue_location_timestamp: 0,
            h_smf_uri: None,
            h_smf_id: None,
            vsmf_pdu_session_uri: None,
            pcf_id: None,
            amf_nf_id: None,
            guami: Guami::default(),
            integrity_protection_mbr_dl: MaxIntegrityProtectedDataRate::default(),
            integrity_protection_mbr_ul: MaxIntegrityProtectedDataRate::default(),
            s_nssai: SNssai::default(),
            mapped_hplmn: SNssai::default(),
            mapped_hplmn_presence: false,
            session_name: None,
            full_dnn: None,
            session_type: PduSessionType::default(),
            ue_session_type: 0,
            ue_ssc_mode: 0,
            session_ambr: SessionAmbr::default(),
            session_qos: Qos::default(),
            ipv4_addr: None,
            ipv6_prefix: None,
            an_type: AccessType::default(),
            gtp_rat_type: 0,
            sbi_rat_type: RatType::default(),
            pcc_rules: Vec::new(),
            paging_n1n2message_location: None,
            ngap_state: NgapState::default(),
            handover: HandoverInfo::default(),
            charging: ChargingInfo::default(),
            gy: GyInfo::default(),
            bearer_ids: Vec::new(),
            qos_flow_to_modify_list: Vec::new(),
            smf_ue_id,
            resource_status: ResourceStatus::default(),
            n1_released: false,
            n2_released: false,
            establishment_accept_sent: false,
            is_mbs_session: false,
            mbs_session_id: None,
            is_redcap_ue: false,
        }
    }

    /// Check if this is a home-routed roaming session in V-SMF
    pub fn is_home_routed_roaming_in_vsmf(&self) -> bool {
        self.pdu_session_ref.is_some()
    }

    /// Check if this is a home-routed roaming session in H-SMF
    pub fn is_home_routed_roaming_in_hsmf(&self) -> bool {
        self.vsmf_pdu_session_uri.is_some()
    }

    /// Set IPv4 address
    pub fn set_ipv4_addr(&mut self, addr: Ipv4Addr) {
        self.ipv4_addr = Some(addr);
    }

    /// Set IPv6 prefix
    pub fn set_ipv6_prefix(&mut self, prefix_len: u8, addr: Ipv6Addr) {
        self.ipv6_prefix = Some((prefix_len, addr));
    }
}

impl Default for SmfSess {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// ============================================================================
// Rel-17 MBS (Multicast/Broadcast Service) Types (TS 23.247)
// ============================================================================

/// TMGI (Temporary Mobile Group Identity) - TS 23.247
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Tmgi {
    /// MBS Service ID (24 bits)
    pub mbs_service_id: u32,
    /// PLMN ID
    pub plmn_id: PlmnId,
}

/// MBS Session State
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MbsSessionState {
    #[default]
    Creating,
    Active,
    Releasing,
}

/// MBS Service Area for multicast delivery
#[derive(Debug, Clone, Default)]
pub struct MbsServiceArea {
    /// List of TAIs (Tracking Area Identifiers) for MBS coverage
    pub tais: Vec<u32>,
    /// List of Cell IDs for MBS coverage
    pub cell_ids: Vec<u64>,
}

/// MBS QoS Flow for multicast bearer
#[derive(Debug, Clone)]
pub struct MbsQosFlow {
    /// QoS Flow Identifier
    pub qfi: u8,
    /// 5QI (5G QoS Identifier) - e.g., 1-85
    pub fiveqi: u8,
    /// Guaranteed Flow Bit Rate (GFBR) in kbps
    pub gfbr: Option<u64>,
    /// Maximum Flow Bit Rate (MFBR) in kbps
    pub mfbr: Option<u64>,
    /// Priority level (1-127, lower = higher priority)
    pub priority: u8,
}

/// N4mb Session Context for PFCP multicast session with UPF
#[derive(Debug, Clone)]
pub struct N4mbSession {
    /// N4mb PFCP Session ID
    pub session_id: u64,
    /// UPF node ID (IPv4 or FQDN)
    pub upf_node_id: String,
    /// Multicast F-TEID (Fully Qualified Tunnel Endpoint Identifier)
    pub multicast_fteid: Option<u32>,
    /// Multicast transport IP (allocated by UPF)
    pub multicast_transport_ip: Option<std::net::Ipv4Addr>,
    /// Session state
    pub state: N4mbSessionState,
    /// QoS flows for this N4mb session
    pub qos_flows: Vec<MbsQosFlow>,
}

/// N4mb PFCP Session State
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N4mbSessionState {
    /// Session establishment in progress
    Establishing,
    /// Session established and active
    Active,
    /// Session modification in progress
    Modifying,
    /// Session release in progress
    Releasing,
}

/// MBS Session Context (Rel-17 TS 23.247)
#[derive(Debug, Clone)]
pub struct MbsSession {
    /// Session ID
    pub id: u64,
    /// TMGI (Temporary Mobile Group Identity)
    pub tmgi: Tmgi,
    /// MBS Session ID (external identifier)
    pub session_id: String,
    /// Multicast IP address for content delivery
    pub multicast_addr: Option<std::net::Ipv4Addr>,
    /// List of UE IDs that have joined this MBS session
    pub joined_ues: Vec<u64>,
    /// Session state
    pub state: MbsSessionState,
    /// N4mb PFCP Session (for multicast user plane with UPF)
    pub n4mb_session: Option<N4mbSession>,
    /// MBS Service Area (coverage area for multicast)
    pub mbs_service_area: MbsServiceArea,
    /// QoS Flow list for multicast bearer
    pub qos_flow_list: Vec<MbsQosFlow>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last state change timestamp
    pub updated_at: u64,
}

impl MbsSession {
    pub fn new(id: u64, tmgi: Tmgi, session_id: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("value expected")
            .as_secs();
        Self {
            id,
            tmgi,
            session_id,
            multicast_addr: None,
            joined_ues: Vec::new(),
            state: MbsSessionState::Creating,
            n4mb_session: None,
            mbs_service_area: MbsServiceArea::default(),
            qos_flow_list: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn ue_count(&self) -> usize {
        self.joined_ues.len()
    }

    pub fn is_active(&self) -> bool {
        self.state == MbsSessionState::Active
    }

    /// Establish N4mb session with UPF for multicast bearer
    pub fn establish_n4mb_session(&mut self, upf_node_id: String, session_id: u64) {
        let n4mb = N4mbSession {
            session_id,
            upf_node_id,
            multicast_fteid: None,
            multicast_transport_ip: None,
            state: N4mbSessionState::Establishing,
            qos_flows: self.qos_flow_list.clone(),
        };
        self.n4mb_session = Some(n4mb);
        log::info!(
            "MBS Session {} N4mb establishment initiated with UPF",
            self.id
        );
    }

    /// Activate N4mb session after successful PFCP establishment
    pub fn activate_n4mb_session(&mut self, fteid: u32, transport_ip: std::net::Ipv4Addr) -> bool {
        if let Some(ref mut n4mb) = self.n4mb_session {
            n4mb.state = N4mbSessionState::Active;
            n4mb.multicast_fteid = Some(fteid);
            n4mb.multicast_transport_ip = Some(transport_ip);
            log::info!(
                "MBS Session {} N4mb session activated (F-TEID: {}, IP: {})",
                self.id,
                fteid,
                transport_ip
            );
            return true;
        }
        false
    }

    /// Release N4mb session
    pub fn release_n4mb_session(&mut self) -> bool {
        if let Some(ref mut n4mb) = self.n4mb_session {
            n4mb.state = N4mbSessionState::Releasing;
            log::info!("MBS Session {} N4mb session release initiated", self.id);
            return true;
        }
        false
    }

    /// Add QoS flow to multicast bearer
    pub fn add_qos_flow(&mut self, qos_flow: MbsQosFlow) {
        self.qos_flow_list.push(qos_flow);
        // Sync to N4mb session if active
        if let Some(ref mut n4mb) = self.n4mb_session {
            n4mb.qos_flows = self.qos_flow_list.clone();
        }
    }

    /// Update MBS service area
    pub fn update_service_area(&mut self, tais: Vec<u32>, cell_ids: Vec<u64>) {
        self.mbs_service_area.tais = tais;
        self.mbs_service_area.cell_ids = cell_ids;
        self.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("value expected")
            .as_secs();
    }
}

// ============================================================================
// SMF Context (Main)
// ============================================================================

/// SMF Context - main context structure for SMF
/// Port of smf_context_t from context.h
/// Per-PDU-session policy binding: ties the SBI SM context to its PCF SM
/// policy association, the UE-requested N1 parameters and the QoS the PCF
/// authorized (applied to N1 NAS and N4 QERs/PDRs). Drives the GSM FSM.
///
/// Serialisable because it is one of the three things the durable snapshot
/// carries (issue #191): without it a restarted SMF cannot terminate or update
/// policy for a session that is still live. `serde(default)` throughout so a
/// snapshot written before a member existed still loads.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default = "PolicyBinding::snapshot_default")]
pub struct PolicyBinding {
    /// smPolicyId returned by the PCF (None = config-default fallback)
    pub sm_policy_id: Option<String>,
    pub supi: String,
    pub psi: u8,
    /// PTI from the UE's N1 SM container (echoed in network responses)
    pub pti: u8,
    /// Selected PDU session type (TS 24.501 §9.11.4.11)
    pub pdu_session_type: u8,
    /// Selected SSC mode
    pub ssc_mode: u8,
    pub ue_ip: [u8; 4],
    pub dnn: String,
    /// QFI of the default QoS flow
    pub qfi: u8,
    /// Authorized default 5QI
    pub five_qi: u8,
    /// Authorized session AMBR (bps)
    pub ambr_ul_bps: u64,
    pub ambr_dl_bps: u64,
    /// SM context status URI provided by the AMF (TS 29.502)
    pub sm_context_status_uri: Option<String>,
    /// GSM (5G session management) FSM for this session
    pub fsm: crate::gsm_sm::GsmFsm,
    /// EASDF DNS-context id for this session, when one was created (#114,
    /// TS 23.501 §5.6.7). `None` when the EASDF leg is disabled, the DNN is not
    /// edge-enabled, or no EASDF is registered.
    ///
    /// Held here rather than in a side map so it is removed with the binding at
    /// release: a DNS context whose session is gone is exactly the orphan the
    /// delete exists to prevent.
    pub easdf_dns_context_id: Option<String>,
    /// The EPS Bearer Identity the AMF assigned this session's default QoS flow
    /// (#117), or `None` when EPS interworking is off or the assignment failed.
    ///
    /// Held on the binding rather than only on the `SmfSess` because the binding is
    /// what the release, update and retrieve paths already key off; a value only on
    /// the session would be invisible to them.
    pub mapped_eps_bearer_id: Option<u8>,
    /// EAS address(es) the EASDF last reported for this session (#114).
    ///
    /// Recorded, not yet acted on: inserting a UL-CL toward the reported EAS is
    /// traffic-influence work with its own N4 and PSA implications. This is where
    /// that work will read from, and keeping it empty-by-default means a session
    /// that never got a report is indistinguishable from the pre-#114 state.
    pub easdf_reported_eas: Vec<String>,
    /// The session's S-NSSAI, as the create request stated it (#293).
    ///
    /// Kept here because a re-read of the subscriber's SM data has to be scoped to the
    /// same slice the session was created for: `sm-data` is one entry per S-NSSAI, and
    /// a lookup that guessed would apply another slice's session-AMBR to this session.
    /// The `sd` is the hex string as received, not a parsed integer, so the value
    /// compared against the UDM's document is the one the AMF sent rather than a
    /// re-formatting of it.
    pub sst: u8,
    pub sd: Option<String>,
    /// The `Nudm_SDM_Subscribe` subscription id for this session (#293), or `None`
    /// when the UDM leg is off, no UDM was discoverable, or the subscribe failed.
    ///
    /// Held here for the same reason as `easdf_dns_context_id`: it is removed with the
    /// binding at release, and a subscription whose session is gone is an orphan that
    /// keeps notifying a callback URI whose `smContextRef` no longer resolves.
    pub sdm_subscription_id: Option<String>,
}

impl PolicyBinding {
    /// Per-field fallback for deserialising a durable snapshot written before a
    /// member existed (issue #191).
    ///
    /// Not a `Default` impl: an empty `supi` with `psi` 0 names no session, and a
    /// binding is only ever created from a real SM context request. Only serde
    /// reaches this, and only for a member the snapshot does not carry.
    pub(crate) fn snapshot_default() -> Self {
        Self {
            sm_policy_id: None,
            supi: String::new(),
            psi: 0,
            pti: 0,
            pdu_session_type: 0,
            ssc_mode: 0,
            ue_ip: [0; 4],
            dnn: String::new(),
            qfi: 0,
            five_qi: 0,
            ambr_ul_bps: 0,
            ambr_dl_bps: 0,
            sm_context_status_uri: None,
            fsm: crate::gsm_sm::GsmFsm::new(0),
            easdf_dns_context_id: None,
            mapped_eps_bearer_id: None,
            easdf_reported_eas: Vec::new(),
            sst: 0,
            sd: None,
            sdm_subscription_id: None,
        }
    }
}

pub struct SmfContext {
    /// CTF configuration
    pub ctf_config: CtfConfig,
    /// DNS servers (IPv4)
    pub dns: [Option<String>; MAX_NUM_OF_DNS],
    /// DNS servers (IPv6)
    pub dns6: [Option<String>; MAX_NUM_OF_DNS],
    /// P-CSCF servers (IPv4)
    pub p_cscf: Vec<String>,
    /// P-CSCF servers (IPv6)
    pub p_cscf6: Vec<String>,
    /// P-CSCF index (for round-robin)
    pub p_cscf_index: usize,
    /// P-CSCF6 index (for round-robin)
    pub p_cscf6_index: usize,
    /// MTU to advertise in PCO
    pub mtu: u16,
    /// Security indication configuration
    pub security_indication: SecurityIndication,

    // Lists
    /// SMF UE list (by pool ID)
    smf_ue_list: RwLock<HashMap<u64, SmfUe>>,
    /// Session list (by pool ID)
    sess_list: RwLock<HashMap<u64, SmfSess>>,
    /// Bearer list (by pool ID)
    bearer_list: RwLock<HashMap<u64, SmfBearer>>,
    /// Packet filter list (by pool ID)
    pf_list: RwLock<HashMap<u64, SmfPf>>,
    /// MBS Session list (by pool ID) - Rel-17
    mbs_sess_list: RwLock<HashMap<u64, MbsSession>>,

    // Hash tables
    /// SUPI -> UE ID hash
    supi_hash: RwLock<HashMap<String, u64>>,
    /// IMSI -> UE ID hash
    imsi_hash: RwLock<HashMap<Vec<u8>, u64>>,
    /// IPv4 address -> Session ID hash
    ipv4_hash: RwLock<HashMap<u32, u64>>,
    /// IPv6 prefix -> Session ID hash
    ipv6_hash: RwLock<HashMap<[u8; 8], u64>>,
    /// SMF N4 SEID -> Session ID hash
    smf_n4_seid_hash: RwLock<HashMap<u64, u64>>,
    /// N1N2 message location -> Session ID hash
    n1n2message_hash: RwLock<HashMap<String, u64>>,
    /// TMGI -> MBS Session ID hash - Rel-17
    tmgi_hash: RwLock<HashMap<Tmgi, u64>>,

    // ID generators
    /// Next UE ID
    next_ue_id: AtomicUsize,
    /// Next session ID
    next_sess_id: AtomicUsize,
    /// Next bearer ID
    next_bearer_id: AtomicUsize,
    /// Next PF ID
    next_pf_id: AtomicUsize,
    /// Session index counter
    sess_index: AtomicU64,
    /// N4 SEID generator
    n4_seid_generator: AtomicU64,
    /// Next MBS session ID
    next_mbs_sess_id: AtomicUsize,

    // Pool limits
    /// Maximum number of UEs
    max_num_of_ue: usize,
    /// Maximum number of sessions
    max_num_of_sess: usize,
    /// Maximum number of bearers
    max_num_of_bearer: usize,

    /// Bitmap-based IPv4 address pool (10.45.0.0/16)
    pub ipv4_pool: Ipv4Pool,

    /// Counter for allocating GTPv1 TEIDs on the Gn interface
    pub gn_teid_counter: AtomicU32,

    /// GGSN address for the Gn interface (used in Create/Update PDP Context Response)
    pub gn_addr: std::net::Ipv4Addr,

    /// Context initialized flag
    initialized: AtomicBool,

    /// PFCP session map: sm_context_ref -> UPF SEID
    ///
    /// Previously a standalone global (`PFCP_SESSIONS`). Moved here so that
    /// test code can construct isolated `SmfContext` instances and avoid
    /// cross-test contamination from a process-wide singleton.
    pub pfcp_sessions: RwLock<HashMap<String, u64>>,

    /// SM policy bindings: sm_context_ref -> PCF policy association + GSM FSM
    pub policy_bindings: RwLock<HashMap<String, PolicyBinding>>,

    /// Sessions a restore could not fully reinstate, with whatever consumer
    /// callback could be salvaged (issue #193).
    ///
    /// Populated by [`Self::restore_from`] and drained once at boot by
    /// `restoration::notify_unrestorable_at_boot`. Not persisted: it describes one
    /// restore, not durable state, and re-notifying on every subsequent boot would
    /// tell an AMF about a context it released long ago.
    pub unrestorable_sessions: RwLock<Vec<UnrestorableSession>>,

    /// Last Recovery Time Stamp each UPF peer reported, keyed by the peer's
    /// socket address (issue #191).
    ///
    /// Persisted with the session map because it is what makes restoring that map
    /// safe: on the first Association Setup after a reload, `check_peer_restart`
    /// compares the freshly reported value against this one and flushes the
    /// restored sessions if the UPF restarted while the SMF was down (TS 29.244
    /// §5.22, TS 23.527 §4.2). Without it the restored `peer_recovery_time_stamp`
    /// is `None`, no restart is detectable, and the SMF believes in N4 sessions
    /// the UPF has already discarded.
    pub upf_recovery_time_stamps: RwLock<HashMap<String, u32>>,

    /// Durable snapshot of the PFCP session map, the policy bindings and the
    /// IPv4 pool's allocations (issue #191). Disabled unless a state file is
    /// configured, in which case behaviour is byte-identical to before.
    ///
    /// `StateStore` rather than the `read_snapshot`/`write_snapshot` free
    /// functions: it enforces "never overwrite a snapshot you could not read"
    /// internally, and a new adopter has no reason to take that on manually.
    state: nextgcore_core::state_store::StateStore,
}

/// A session the SMF restored but cannot actually serve, because the record that
/// carried its policy state did not survive (issue #193).
///
/// The typed `PolicyBinding` deserialisation is per-record precisely so one
/// schema change does not discard the whole snapshot -- but a session whose
/// binding is gone has no PCF association, no authorized QoS and no GSM FSM
/// state, so the SMF can neither modify nor cleanly release it. The consumer
/// still believes it exists.
///
/// `status_uri` is salvaged from the RAW JSON of the failed record rather than
/// from the typed value, which is the whole point: the file was already validated
/// as JSON by the store, so `smContextStatusUri` is still readable even when the
/// record as a whole is not. Without that salvage there would be nobody to tell.
#[derive(Debug, Clone)]
pub struct UnrestorableSession {
    /// The key the AMF holds.
    pub sm_context_ref: String,
    /// The AMF's status callback, if it could be salvaged.
    pub status_uri: Option<String>,
    /// What went wrong, for the operator-facing log and the notification cause.
    pub reason: String,
}

/// Why smfd durable state could not be loaded (issue #191).
#[derive(Debug, thiserror::Error)]
pub enum SmfStateError {
    /// The snapshot file itself could not be read or parsed.
    #[error(transparent)]
    Store(#[from] nextgcore_core::state_store::StateStoreError),
    /// The snapshot was written by a newer build. Refused rather than partially
    /// restored: restoring only what this build recognises and then persisting
    /// would rewrite a newer-format file in the older format, discarding the rest.
    #[error(
        "state file {path} was written by a newer smfd (snapshot version {found}; this build \
         understands {supported}). Refusing to restore or overwrite it. Run the newer build, or \
         move the file aside to start fresh."
    )]
    UnsupportedVersion {
        path: std::path::PathBuf,
        found: u64,
        supported: u64,
    },
}

impl SmfContext {
    /// Create a new SMF context
    pub fn new() -> Self {
        Self {
            ctf_config: CtfConfig::default(),
            dns: [None, None],
            dns6: [None, None],
            p_cscf: Vec::with_capacity(MAX_NUM_OF_P_CSCF),
            p_cscf6: Vec::with_capacity(MAX_NUM_OF_P_CSCF),
            p_cscf_index: 0,
            p_cscf6_index: 0,
            mtu: 0,
            security_indication: SecurityIndication::default(),
            smf_ue_list: RwLock::new(HashMap::new()),
            sess_list: RwLock::new(HashMap::new()),
            bearer_list: RwLock::new(HashMap::new()),
            pf_list: RwLock::new(HashMap::new()),
            mbs_sess_list: RwLock::new(HashMap::new()),
            supi_hash: RwLock::new(HashMap::new()),
            imsi_hash: RwLock::new(HashMap::new()),
            ipv4_hash: RwLock::new(HashMap::new()),
            ipv6_hash: RwLock::new(HashMap::new()),
            smf_n4_seid_hash: RwLock::new(HashMap::new()),
            n1n2message_hash: RwLock::new(HashMap::new()),
            tmgi_hash: RwLock::new(HashMap::new()),
            next_ue_id: AtomicUsize::new(1),
            next_sess_id: AtomicUsize::new(1),
            next_bearer_id: AtomicUsize::new(1),
            next_pf_id: AtomicUsize::new(1),
            sess_index: AtomicU64::new(1),
            n4_seid_generator: AtomicU64::new(1),
            next_mbs_sess_id: AtomicUsize::new(1),
            max_num_of_ue: 0,
            max_num_of_sess: 0,
            max_num_of_bearer: 0,
            ipv4_pool: Ipv4Pool::default_pool(),
            gn_teid_counter: AtomicU32::new(1),
            gn_addr: std::env::var("SMF_GN_ADDR")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            initialized: AtomicBool::new(false),
            pfcp_sessions: RwLock::new(HashMap::new()),
            unrestorable_sessions: RwLock::new(Vec::new()),
            policy_bindings: RwLock::new(HashMap::new()),
            upf_recovery_time_stamps: RwLock::new(HashMap::new()),
            state: nextgcore_core::state_store::StateStore::disabled(),
        }
    }

    /// Initialize the SMF context
    pub fn init(&mut self, max_ue: usize, max_sess: usize, max_bearer: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.max_num_of_ue = max_ue;
        self.max_num_of_sess = max_sess;
        self.max_num_of_bearer = max_bearer;
        self.initialized.store(true, Ordering::SeqCst);

        log::info!(
            "SMF context initialized with max {} UEs, {} sessions, {} bearers",
            self.max_num_of_ue,
            self.max_num_of_sess,
            self.max_num_of_bearer
        );
    }

    /// Finalize the SMF context
    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        // Issue #191: DISABLE the store before clearing anything. `ue_remove_all`
        // empties every list and releases every IP, and smfd has background tasks
        // (the PFCP listener, the association loop, the timer loop) that can still
        // reach a mutation during shutdown -- so a persist reached afterwards would
        // write an empty snapshot over a good one and lose every live session and
        // its address. Disabling first is the only ordering that cannot lose data
        // regardless of what runs next.
        self.state = nextgcore_core::state_store::StateStore::disabled();
        self.ue_remove_all();
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("SMF context finalized");
    }

    // ── durable state (issue #191) ───────────────────────────────────────────

    /// Snapshot document version. Bump ONLY for a change no `#[serde(default)]`
    /// can absorb; a bump makes every older snapshot unreadable.
    pub const SNAPSHOT_VERSION: u64 = 1;

    /// Point this context at a snapshot file and restore any prior state,
    /// returning how many records were installed.
    ///
    /// Call once at startup, **after** [`init`](Self::init) and **before** the SBI
    /// server or the PFCP association loop can run, so a restored session is never
    /// shadowed by a fresh one and the restored peer Recovery Time Stamps are in
    /// place for the first Association Setup.
    ///
    /// An unreadable snapshot is an **error**: the caller should refuse to start
    /// rather than come up with an empty IPv4 pool that will re-issue addresses
    /// live UEs still hold.
    pub fn set_state_file(&mut self, path: std::path::PathBuf) -> Result<usize, SmfStateError> {
        use nextgcore_core::state_store::{Loaded, StateStore};
        self.state = StateStore::new(Some(path.clone()));
        match self.state.load()? {
            Loaded::Snapshot(doc) => {
                let restored = self.restore_from(&doc, &path);
                if restored.is_err() {
                    // The store is not poisoned (the load itself succeeded), so a
                    // caller that logged and carried on could otherwise overwrite a
                    // snapshot this build cannot fully read. Disable instead.
                    self.state = StateStore::disabled();
                }
                restored
            }
            Loaded::Absent => Ok(0),
        }
    }

    /// Whether durable state is armed. `false` is the shipped default.
    pub fn state_is_enabled(&self) -> bool {
        self.state.is_enabled()
    }

    /// Serialize the three durable concerns to one snapshot document.
    ///
    /// **Takes one lock at a time, holding at most one at any instant.** This
    /// file carries several documented lock-ordering rules (see `sess_remove`,
    /// `sess_update`, `sess_find_by_ipv4`); a function holding three guards at
    /// once would be a new inversion waiting to happen. Cloning each map out and
    /// dropping its guard before taking the next means this function cannot
    /// participate in any cycle, whatever order the mutators use.
    ///
    /// The cost is that the document is not one atomic instant across all three.
    /// That is acceptable: every mutation persists immediately after its guards
    /// drop, so the next write reconciles any skew -- and the alternative risks
    /// wedging the NF, which no amount of snapshot precision is worth.
    fn snapshot(&self) -> serde_json::Value {
        // Each of these acquires and releases before the next begins.
        let pfcp_sessions: std::collections::BTreeMap<String, u64> = self
            .pfcp_sessions
            .read()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), *v)).collect())
            .unwrap_or_default();
        let policy_bindings: std::collections::BTreeMap<String, PolicyBinding> = self
            .policy_bindings
            .read()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        let upf_rts: std::collections::BTreeMap<String, u32> = self
            .upf_recovery_time_stamps
            .read()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), *v)).collect())
            .unwrap_or_default();
        // Ascending already (see `Ipv4Pool::allocated_addrs`), and as strings so
        // the file is readable by an operator diagnosing a double assignment.
        let ipv4_allocations: Vec<String> = self
            .ipv4_pool
            .allocated_addrs()
            .into_iter()
            .map(|a| a.to_string())
            .collect();

        // BTreeMap, not HashMap: a HashMap iterates in a different order on every
        // process, so the file would churn wholesale on each write and a diff
        // would never show which record actually changed.
        serde_json::json!({
            "version": Self::SNAPSHOT_VERSION,
            "pfcpSessions": pfcp_sessions,
            "policyBindings": policy_bindings,
            "ipv4Allocations": ipv4_allocations,
            "upfRecoveryTimeStamps": upf_rts,
        })
    }

    /// Restore the three durable concerns.
    ///
    /// # Why the IPv4 pool is restored by re-marking, not by counting
    ///
    /// The pool is a bitmap plus a count. Restoring the count alone would leave
    /// every bit clear, so the very next `allocate()` returns `10.45.0.2` — an
    /// address a live UE is still using. Re-marking each snapshotted address is
    /// the only restore that makes the pool's answer to "is this free?" agree with
    /// reality. `reserve` reports whether it was this call that marked the bit, so
    /// the reserved `.0.0`/`.0.1` that `allocated_addrs` also reports do not
    /// double-count.
    ///
    /// # Why a restored PFCP session is not assumed usable
    ///
    /// A restored `sm_context_ref -> SEID` mapping is SMF-side bookkeeping about
    /// state that lives on the UPF, and the UPF may have restarted while the SMF
    /// was down. That is why `upfRecoveryTimeStamps` is part of the same document:
    /// seeding it back into each `PfcpClient` (see `main`) makes the existing
    /// `check_peer_restart` comparison fire on the first Association Setup after a
    /// reload, which tears the association down and flushes exactly these restored
    /// sessions. Reconciling *which* sessions survived, and telling peers about the
    /// ones that did not, is TS 23.527 restoration signalling and belongs to #193.
    fn restore_from(
        &self,
        doc: &serde_json::Value,
        path: &std::path::Path,
    ) -> Result<usize, SmfStateError> {
        let found = doc
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(Self::SNAPSHOT_VERSION);
        if found > Self::SNAPSHOT_VERSION {
            return Err(SmfStateError::UnsupportedVersion {
                path: path.to_path_buf(),
                found,
                supported: Self::SNAPSHOT_VERSION,
            });
        }

        let pfcp_sessions: HashMap<String, u64> = doc
            .get("pfcpSessions")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        // Per-record, so one binding whose schema moved does not discard the rest:
        // the file was already validated as JSON by the store, so a bad record
        // means a schema change, not corruption.
        // #193: a skipped binding is not merely lost state. The session under the
        // same key restores independently below, so the SMF ends up holding a PDU
        // session with no PCF association, no authorized QoS and no FSM state --
        // one it can neither modify nor cleanly release -- while the AMF still
        // believes in it. The consumer callback is salvaged from the RAW record so
        // boot has somebody to tell; the record failed TYPED deserialisation, not
        // JSON parsing, so the field is still readable.
        let mut unrestorable: Vec<UnrestorableSession> = Vec::new();
        let policy_bindings: HashMap<String, PolicyBinding> = doc
            .get("policyBindings")
            .and_then(|v| v.as_object().cloned())
            .map(|obj| {
                obj.into_iter()
                    .filter_map(|(k, v)| {
                        let salvaged = v
                            .get("smContextStatusUri")
                            .and_then(|u| u.as_str())
                            .map(str::to_string);
                        match serde_json::from_value::<PolicyBinding>(v) {
                            Ok(b) => Some((k, b)),
                            Err(e) => {
                                log::warn!("skipping unreadable SMF policy binding {k}: {e}");
                                unrestorable.push(UnrestorableSession {
                                    sm_context_ref: k,
                                    status_uri: salvaged,
                                    reason: format!("policy binding could not be restored: {e}"),
                                });
                                None
                            }
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let ipv4_allocations: Vec<Ipv4Addr> = doc
            .get("ipv4Allocations")
            .and_then(|v| v.as_array().cloned())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|s| match s.parse::<Ipv4Addr>() {
                        Ok(a) => Some(a),
                        Err(e) => {
                            log::warn!("skipping unreadable SMF IPv4 allocation {s}: {e}");
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let upf_rts: HashMap<String, u32> = doc
            .get("upfRecoveryTimeStamps")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let n_sessions = pfcp_sessions.len();
        let n_bindings = policy_bindings.len();
        let n_rts = upf_rts.len();

        // One lock at a time, as in `snapshot`.
        if let Ok(mut map) = self.pfcp_sessions.write() {
            map.extend(pfcp_sessions);
        }
        if let Ok(mut map) = self.policy_bindings.write() {
            map.extend(policy_bindings);
        }
        if let Ok(mut map) = self.upf_recovery_time_stamps.write() {
            map.extend(upf_rts);
        }
        let mut n_addrs = 0usize;
        for addr in &ipv4_allocations {
            if self.ipv4_pool.reserve(*addr) {
                n_addrs += 1;
            }
        }

        // #193: only sessions that actually restored are worth signalling about --
        // an entry for a binding with no session under the same key describes
        // nothing the consumer can be told is released.
        let n_unrestorable = {
            let sessions_present: Vec<UnrestorableSession> = match self.pfcp_sessions.read() {
                Ok(map) => unrestorable
                    .into_iter()
                    .filter(|u| map.contains_key(&u.sm_context_ref))
                    .collect(),
                Err(_) => Vec::new(),
            };
            let n = sessions_present.len();
            if let Ok(mut pending) = self.unrestorable_sessions.write() {
                pending.extend(sessions_present);
            }
            n
        };
        if n_unrestorable > 0 {
            log::error!(
                "{n_unrestorable} restored PFCP session(s) have NO policy binding: the SMF can \
                 neither modify nor cleanly release them. Their consumers are notified at boot \
                 where a callback could be salvaged."
            );
        }

        let restored = n_sessions + n_bindings + n_addrs;
        log::info!(
            "SMF durable state restored: {n_sessions} PFCP session(s), {n_bindings} policy \
             binding(s), {n_addrs} IPv4 allocation(s) re-marked, {n_rts} UPF recovery time \
             stamp(s). The PFCP sessions are UNRECONCILED: they are flushed on the first \
             Association Setup if the UPF reports a changed Recovery Time Stamp."
        );
        Ok(restored)
    }

    /// Write the snapshot after a mutation. A no-op with no state file, and
    /// refused (loudly) when the previous load failed.
    ///
    /// **Every caller must have dropped its write guards first.** `persist` ->
    /// `snapshot` takes read locks on the same maps and `std::sync::RwLock` is not
    /// reentrant, so calling this while still holding `pfcp_sessions.write()` or
    /// `policy_bindings.write()` deadlocks the calling thread. Every call site
    /// closes its `if let Ok(mut …) = ….write()` block first.
    pub fn persist(&self) {
        if !self.state.is_enabled() {
            return;
        }
        let doc = self.snapshot();
        if let Err(e) = self.state.persist(&doc) {
            // The session exists in memory but not on disk: the request was
            // answered and will not survive a restart.
            log::error!("SMF state was NOT persisted: {e}");
        }
    }

    /// Record the Recovery Time Stamp a UPF peer reported, and persist it.
    ///
    /// Keyed by the peer socket address as `PfcpClient::peer()` renders it, which
    /// is what `main` uses to seed the value back after a restart.
    pub fn note_upf_recovery_time_stamp(&self, peer: &str, rts: u32) {
        let changed = {
            match self.upf_recovery_time_stamps.write() {
                Ok(mut map) => map.insert(peer.to_string(), rts) != Some(rts),
                Err(_) => false,
            }
        };
        // Only on a change: the association loop re-reports the same stamp on
        // every heartbeat, and rewriting the whole snapshot every 10s per peer
        // for an unchanged value is pure write amplification.
        if changed {
            self.persist();
        }
    }

    /// The Recovery Time Stamp last recorded for `peer`, if any.
    pub fn upf_recovery_time_stamp(&self, peer: &str) -> Option<u32> {
        self.upf_recovery_time_stamps
            .read()
            .ok()?
            .get(peer)
            .copied()
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Generate next N4 SEID
    fn next_n4_seid(&self) -> u64 {
        self.n4_seid_generator.fetch_add(1, Ordering::SeqCst)
    }

    // ========================================================================
    // UE Management
    // ========================================================================

    /// Add a new UE by SUPI
    pub fn ue_add_by_supi(&self, supi: &str) -> Option<SmfUe> {
        let mut smf_ue_list = self.smf_ue_list.write().ok()?;
        let mut supi_hash = self.supi_hash.write().ok()?;

        if smf_ue_list.len() >= self.max_num_of_ue {
            log::error!("Maximum number of UEs [{}] reached", self.max_num_of_ue);
            return None;
        }

        let id = self.next_ue_id.fetch_add(1, Ordering::SeqCst) as u64;
        let mut ue = SmfUe::new(id);
        ue.supi = Some(supi.to_string());

        supi_hash.insert(supi.to_string(), id);
        smf_ue_list.insert(id, ue.clone());

        log::info!("[Added] SMF UE by SUPI [{supi}] (id={id})");
        Some(ue)
    }

    /// Add a new UE by IMSI
    pub fn ue_add_by_imsi(&self, imsi: &[u8]) -> Option<SmfUe> {
        let mut smf_ue_list = self.smf_ue_list.write().ok()?;
        let mut imsi_hash = self.imsi_hash.write().ok()?;

        if smf_ue_list.len() >= self.max_num_of_ue {
            log::error!("Maximum number of UEs [{}] reached", self.max_num_of_ue);
            return None;
        }

        let id = self.next_ue_id.fetch_add(1, Ordering::SeqCst) as u64;
        let mut ue = SmfUe::new(id);
        ue.imsi = imsi.to_vec();
        ue.imsi_bcd = Self::buffer_to_bcd(imsi);

        imsi_hash.insert(imsi.to_vec(), id);
        smf_ue_list.insert(id, ue.clone());

        log::info!("[Added] SMF UE by IMSI [{}] (id={})", ue.imsi_bcd, id);
        Some(ue)
    }

    /// Convert binary buffer to BCD string
    fn buffer_to_bcd(buf: &[u8]) -> String {
        let mut result = String::new();
        for byte in buf {
            let low = byte & 0x0f;
            let high = (byte >> 4) & 0x0f;
            if low < 10 {
                result.push((b'0' + low) as char);
            }
            if high < 10 {
                result.push((b'0' + high) as char);
            }
        }
        result
    }

    /// Remove a UE by ID
    pub fn ue_remove(&self, id: u64) -> Option<SmfUe> {
        // First, remove all sessions for this UE (must be done before acquiring UE locks)
        self.sess_remove_all_for_ue(id);

        // Now remove the UE itself
        let mut smf_ue_list = self.smf_ue_list.write().ok()?;
        let mut supi_hash = self.supi_hash.write().ok()?;
        let mut imsi_hash = self.imsi_hash.write().ok()?;

        if let Some(ue) = smf_ue_list.remove(&id) {
            if let Some(ref supi) = ue.supi {
                supi_hash.remove(supi);
            }
            if !ue.imsi.is_empty() {
                imsi_hash.remove(&ue.imsi);
            }

            log::info!("[Removed] SMF UE (id={id})");
            return Some(ue);
        }
        None
    }

    /// Remove all UEs
    pub fn ue_remove_all(&self) {
        if let (Ok(mut smf_ue_list), Ok(mut supi_hash), Ok(mut imsi_hash)) = (
            self.smf_ue_list.write(),
            self.supi_hash.write(),
            self.imsi_hash.write(),
        ) {
            smf_ue_list.clear();
            supi_hash.clear();
            imsi_hash.clear();
        }

        // Clear sessions, bearers, and PFs
        if let Ok(mut sess_list) = self.sess_list.write() {
            sess_list.clear();
        }
        if let Ok(mut bearer_list) = self.bearer_list.write() {
            bearer_list.clear();
        }
        if let Ok(mut pf_list) = self.pf_list.write() {
            pf_list.clear();
        }
        // Clear hash tables
        if let Ok(mut ipv4_hash) = self.ipv4_hash.write() {
            ipv4_hash.clear();
        }
        if let Ok(mut ipv6_hash) = self.ipv6_hash.write() {
            ipv6_hash.clear();
        }
        if let Ok(mut smf_n4_seid_hash) = self.smf_n4_seid_hash.write() {
            smf_n4_seid_hash.clear();
        }
        if let Ok(mut n1n2message_hash) = self.n1n2message_hash.write() {
            n1n2message_hash.clear();
        }
    }

    /// Find UE by SUPI
    pub fn ue_find_by_supi(&self, supi: &str) -> Option<SmfUe> {
        // Lock order smf_ue_list < supi_hash (matches ue_add_by_supi/ue_remove);
        // taking supi_hash first would be an AB-BA deadlock vs the mutation paths.
        let smf_ue_list = self.smf_ue_list.read().ok()?;
        let supi_hash = self.supi_hash.read().ok()?;
        supi_hash
            .get(supi)
            .and_then(|&id| smf_ue_list.get(&id).cloned())
    }

    /// Find UE by IMSI
    pub fn ue_find_by_imsi(&self, imsi: &[u8]) -> Option<SmfUe> {
        // Lock order smf_ue_list < imsi_hash (matches ue_add_by_imsi/ue_remove).
        let smf_ue_list = self.smf_ue_list.read().ok()?;
        let imsi_hash = self.imsi_hash.read().ok()?;
        imsi_hash
            .get(imsi)
            .and_then(|&id| smf_ue_list.get(&id).cloned())
    }

    /// Find UE by ID
    pub fn ue_find_by_id(&self, id: u64) -> Option<SmfUe> {
        let smf_ue_list = self.smf_ue_list.read().ok()?;
        smf_ue_list.get(&id).cloned()
    }

    /// Update UE in the context
    pub fn ue_update(&self, ue: &SmfUe) -> bool {
        if let Ok(mut smf_ue_list) = self.smf_ue_list.write() {
            if let Some(existing) = smf_ue_list.get_mut(&ue.id) {
                *existing = ue.clone();
                return true;
            }
        }
        false
    }

    /// Get number of UEs
    pub fn ue_count(&self) -> usize {
        self.smf_ue_list.read().map(|l| l.len()).unwrap_or(0)
    }

    // ========================================================================
    // Session Management
    // ========================================================================

    /// Add a new session by PSI (5GC)
    pub fn sess_add_by_psi(&self, smf_ue_id: u64, psi: u8) -> Option<SmfSess> {
        let mut sess_list = self.sess_list.write().ok()?;
        let mut smf_n4_seid_hash = self.smf_n4_seid_hash.write().ok()?;
        let mut smf_ue_list = self.smf_ue_list.write().ok()?;

        if sess_list.len() >= self.max_num_of_sess {
            log::error!(
                "Maximum number of sessions [{}] reached",
                self.max_num_of_sess
            );
            return None;
        }

        let id = self.next_sess_id.fetch_add(1, Ordering::SeqCst) as u64;
        let index = self.sess_index.fetch_add(1, Ordering::SeqCst) as u32;
        let n4_seid = self.next_n4_seid();

        let mut sess = SmfSess::new(id, index, smf_ue_id);
        sess.psi = psi;
        sess.smf_n4_seid = n4_seid;
        sess.smf_n4_teid = n4_seid as u32;
        sess.sm_context_ref = Some(format!("{index}"));
        sess.pdu_session_ref = Some(format!("{index}"));
        sess.charging.id = index;

        smf_n4_seid_hash.insert(n4_seid, id);
        sess_list.insert(id, sess.clone());

        // Add session ID to UE
        if let Some(ue) = smf_ue_list.get_mut(&smf_ue_id) {
            ue.sess_ids.push(id);
        }

        log::debug!("[ue_id={smf_ue_id}, psi={psi}] SMF session added (id={id}, seid={n4_seid})");
        Some(sess)
    }

    /// Add a new session by APN (EPC)
    pub fn sess_add_by_apn(&self, smf_ue_id: u64, apn: &str, rat_type: u8) -> Option<SmfSess> {
        let mut sess_list = self.sess_list.write().ok()?;
        let mut smf_n4_seid_hash = self.smf_n4_seid_hash.write().ok()?;
        let mut smf_ue_list = self.smf_ue_list.write().ok()?;

        if sess_list.len() >= self.max_num_of_sess {
            log::error!(
                "Maximum number of sessions [{}] reached",
                self.max_num_of_sess
            );
            return None;
        }

        let id = self.next_sess_id.fetch_add(1, Ordering::SeqCst) as u64;
        let index = self.sess_index.fetch_add(1, Ordering::SeqCst) as u32;
        let n4_seid = self.next_n4_seid();

        let mut sess = SmfSess::new(id, index, smf_ue_id);
        sess.epc = true;
        sess.session_name = Some(apn.to_string());
        sess.gtp_rat_type = rat_type;
        sess.smf_n4_seid = n4_seid;
        sess.smf_n4_teid = n4_seid as u32;
        sess.charging.id = index;

        smf_n4_seid_hash.insert(n4_seid, id);
        sess_list.insert(id, sess.clone());

        // Add session ID to UE
        if let Some(ue) = smf_ue_list.get_mut(&smf_ue_id) {
            ue.sess_ids.push(id);
        }

        log::debug!("[ue_id={smf_ue_id}, apn={apn}] SMF session added (id={id}, seid={n4_seid})");
        Some(sess)
    }

    /// Remove a session by ID
    pub fn sess_remove(&self, id: u64) -> Option<SmfSess> {
        // First, remove all bearers for this session (must be done before acquiring session locks)
        self.bearer_remove_all_for_sess(id);

        // Issue #191: scoped so every guard is dropped before `persist` runs --
        // `persist` re-reads the IPv4 pool bitmap and neither `RwLock` nor `Mutex`
        // is reentrant. The `?` operators inside still return early from
        // `sess_remove`, which is the pre-#191 behaviour and needs no persist
        // because nothing was removed.
        let removed = {
            // Now remove the session itself
            let mut sess_list = self.sess_list.write().ok()?;
            let mut smf_n4_seid_hash = self.smf_n4_seid_hash.write().ok()?;
            let mut ipv4_hash = self.ipv4_hash.write().ok()?;
            let mut ipv6_hash = self.ipv6_hash.write().ok()?;
            let mut n1n2message_hash = self.n1n2message_hash.write().ok()?;
            let mut smf_ue_list = self.smf_ue_list.write().ok()?;

            match sess_list.remove(&id) {
                Some(sess) => {
                    smf_n4_seid_hash.remove(&sess.smf_n4_seid);

                    if let Some(addr) = sess.ipv4_addr {
                        ipv4_hash.remove(&u32::from(addr));
                        self.ipv4_pool.release(addr);
                    }
                    if let Some((_, addr)) = sess.ipv6_prefix {
                        let prefix: [u8; 8] = addr.octets()[..8].try_into().unwrap_or([0; 8]);
                        ipv6_hash.remove(&prefix);
                    }
                    if let Some(ref location) = sess.paging_n1n2message_location {
                        n1n2message_hash.remove(location);
                    }

                    // Remove session ID from UE
                    if let Some(ue) = smf_ue_list.get_mut(&sess.smf_ue_id) {
                        ue.sess_ids.retain(|&sid| sid != id);
                    }

                    log::info!("[Removed] SMF session (id={}, psi={})", id, sess.psi);
                    Some(sess)
                }
                None => None,
            }
        };
        // Issue #191: a released address that is not persisted stays held in the
        // snapshot forever, which leaks the pool across restarts.
        if removed.is_some() {
            self.persist();
        }
        removed
    }

    /// Remove all sessions for a UE
    fn sess_remove_all_for_ue(&self, smf_ue_id: u64) {
        let sess_ids: Vec<u64> = {
            if let Ok(sess_list) = self.sess_list.read() {
                sess_list
                    .values()
                    .filter(|s| s.smf_ue_id == smf_ue_id)
                    .map(|s| s.id)
                    .collect()
            } else {
                return;
            }
        };
        for id in sess_ids {
            self.sess_remove(id);
        }
    }

    /// Find session by ID
    pub fn sess_find_by_id(&self, id: u64) -> Option<SmfSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(&id).cloned()
    }

    /// Find session by index
    pub fn sess_find_by_index(&self, index: u32) -> Option<SmfSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list.values().find(|s| s.index == index).cloned()
    }

    /// Find session by TEID
    pub fn sess_find_by_teid(&self, teid: u32) -> Option<SmfSess> {
        self.sess_find_by_seid(teid as u64)
    }

    /// Find session by SEID
    pub fn sess_find_by_seid(&self, seid: u64) -> Option<SmfSess> {
        // Lock order sess_list < smf_n4_seid_hash (matches sess_add_*/sess_remove).
        let sess_list = self.sess_list.read().ok()?;
        let smf_n4_seid_hash = self.smf_n4_seid_hash.read().ok()?;
        smf_n4_seid_hash
            .get(&seid)
            .and_then(|&id| sess_list.get(&id).cloned())
    }

    /// Find session by APN (EPC)
    pub fn sess_find_by_apn(&self, smf_ue_id: u64, apn: &str, rat_type: u8) -> Option<SmfSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list
            .values()
            .find(|s| {
                s.smf_ue_id == smf_ue_id
                    && s.session_name.as_deref() == Some(apn)
                    && s.gtp_rat_type == rat_type
            })
            .cloned()
    }

    /// Find session by PSI (5GC)
    pub fn sess_find_by_psi(&self, smf_ue_id: u64, psi: u8) -> Option<SmfSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list
            .values()
            .find(|s| s.smf_ue_id == smf_ue_id && s.psi == psi)
            .cloned()
    }

    /// Find session by charging ID
    pub fn sess_find_by_charging_id(&self, charging_id: u32) -> Option<SmfSess> {
        self.sess_find_by_index(charging_id)
    }

    /// Find session by SM context ref
    pub fn sess_find_by_sm_context_ref(&self, sm_context_ref: &str) -> Option<SmfSess> {
        if let Ok(index) = sm_context_ref.parse::<u32>() {
            return self.sess_find_by_index(index);
        }
        None
    }

    /// Find session by PDU session ref
    pub fn sess_find_by_pdu_session_ref(&self, pdu_session_ref: &str) -> Option<SmfSess> {
        if let Ok(index) = pdu_session_ref.parse::<u32>() {
            return self.sess_find_by_index(index);
        }
        None
    }

    /// Find session by IPv4 address
    pub fn sess_find_by_ipv4(&self, addr: Ipv4Addr) -> Option<SmfSess> {
        // Lock order sess_list < ipv4_hash (matches sess_remove/sess_update).
        let sess_list = self.sess_list.read().ok()?;
        let ipv4_hash = self.ipv4_hash.read().ok()?;
        ipv4_hash
            .get(&u32::from(addr))
            .and_then(|&id| sess_list.get(&id).cloned())
    }

    /// Find session by IPv6 prefix
    pub fn sess_find_by_ipv6(&self, addr: &[u8; 8]) -> Option<SmfSess> {
        // Lock order sess_list < ipv6_hash (matches sess_remove/sess_update).
        let sess_list = self.sess_list.read().ok()?;
        let ipv6_hash = self.ipv6_hash.read().ok()?;
        ipv6_hash
            .get(addr)
            .and_then(|&id| sess_list.get(&id).cloned())
    }

    /// Find session by paging N1N2 message location
    pub fn sess_find_by_paging_n1n2message_location(&self, location: &str) -> Option<SmfSess> {
        // Lock order sess_list < n1n2message_hash (matches sess_remove/sess_update/
        // sess_set_paging_n1n2message_location).
        let sess_list = self.sess_list.read().ok()?;
        let n1n2message_hash = self.n1n2message_hash.read().ok()?;
        n1n2message_hash
            .get(location)
            .and_then(|&id| sess_list.get(&id).cloned())
    }

    /// Update session in the context
    pub fn sess_update(&self, sess: &SmfSess) -> bool {
        if let (Ok(mut sess_list), Ok(mut ipv4_hash), Ok(mut ipv6_hash), Ok(mut n1n2message_hash)) = (
            self.sess_list.write(),
            self.ipv4_hash.write(),
            self.ipv6_hash.write(),
            self.n1n2message_hash.write(),
        ) {
            if let Some(existing) = sess_list.get_mut(&sess.id) {
                // Update IPv4 hash if changed
                if existing.ipv4_addr != sess.ipv4_addr {
                    if let Some(old_addr) = existing.ipv4_addr {
                        ipv4_hash.remove(&u32::from(old_addr));
                    }
                    if let Some(new_addr) = sess.ipv4_addr {
                        ipv4_hash.insert(u32::from(new_addr), sess.id);
                    }
                }
                // Update IPv6 hash if changed
                if existing.ipv6_prefix != sess.ipv6_prefix {
                    if let Some((_, old_addr)) = existing.ipv6_prefix {
                        let prefix: [u8; 8] = old_addr.octets()[..8].try_into().unwrap_or([0; 8]);
                        ipv6_hash.remove(&prefix);
                    }
                    if let Some((_, new_addr)) = sess.ipv6_prefix {
                        let prefix: [u8; 8] = new_addr.octets()[..8].try_into().unwrap_or([0; 8]);
                        ipv6_hash.insert(prefix, sess.id);
                    }
                }
                // Update N1N2 message hash if changed
                if existing.paging_n1n2message_location != sess.paging_n1n2message_location {
                    if let Some(ref old_loc) = existing.paging_n1n2message_location {
                        n1n2message_hash.remove(old_loc);
                    }
                    if let Some(ref new_loc) = sess.paging_n1n2message_location {
                        n1n2message_hash.insert(new_loc.clone(), sess.id);
                    }
                }
                *existing = sess.clone();
                return true;
            }
        }
        false
    }

    /// Set paging N1N2 message location for session
    pub fn sess_set_paging_n1n2message_location(&self, sess_id: u64, location: &str) -> bool {
        if let (Ok(mut sess_list), Ok(mut n1n2message_hash)) =
            (self.sess_list.write(), self.n1n2message_hash.write())
        {
            if let Some(sess) = sess_list.get_mut(&sess_id) {
                // Remove old location from hash
                if let Some(ref old_loc) = sess.paging_n1n2message_location {
                    n1n2message_hash.remove(old_loc);
                }
                // Set new location
                sess.paging_n1n2message_location = Some(location.to_string());
                n1n2message_hash.insert(location.to_string(), sess_id);
                return true;
            }
        }
        false
    }

    /// Get number of sessions
    pub fn sess_count(&self) -> usize {
        self.sess_list.read().map(|l| l.len()).unwrap_or(0)
    }

    /// Get next session index (monotonically increasing, unique per SM context ref)
    pub fn next_sess_index(&self) -> u64 {
        self.sess_index.fetch_add(1, Ordering::Relaxed)
    }

    // ========================================================================
    // Bearer/QoS Flow Management
    // ========================================================================

    /// Add a new QoS flow (5GC)
    pub fn qos_flow_add(&self, sess_id: u64) -> Option<SmfBearer> {
        let mut bearer_list = self.bearer_list.write().ok()?;
        let mut sess_list = self.sess_list.write().ok()?;

        if bearer_list.len() >= self.max_num_of_bearer {
            log::error!(
                "Maximum number of bearers [{}] reached",
                self.max_num_of_bearer
            );
            return None;
        }

        let id = self.next_bearer_id.fetch_add(1, Ordering::SeqCst) as u64;
        let bearer = SmfBearer::new(id, sess_id);

        bearer_list.insert(id, bearer.clone());

        // Add bearer ID to session
        if let Some(sess) = sess_list.get_mut(&sess_id) {
            sess.bearer_ids.push(id);
        }

        log::debug!("[sess_id={sess_id}] QoS flow added (id={id})");
        Some(bearer)
    }

    /// Add a new bearer (EPC)
    pub fn bearer_add(&self, sess_id: u64) -> Option<SmfBearer> {
        self.qos_flow_add(sess_id)
    }

    /// Remove a bearer by ID
    pub fn bearer_remove(&self, id: u64) -> Option<SmfBearer> {
        // First, remove all PFs for this bearer (must be done before acquiring bearer locks)
        self.pf_remove_all_for_bearer(id);

        // Now remove the bearer itself
        let mut bearer_list = self.bearer_list.write().ok()?;
        let mut sess_list = self.sess_list.write().ok()?;

        if let Some(bearer) = bearer_list.remove(&id) {
            // Remove bearer ID from session
            if let Some(sess) = sess_list.get_mut(&bearer.sess_id) {
                sess.bearer_ids.retain(|&bid| bid != id);
            }

            log::debug!("Bearer removed (id={id})");
            return Some(bearer);
        }
        None
    }

    /// Remove all bearers for a session
    fn bearer_remove_all_for_sess(&self, sess_id: u64) {
        let bearer_ids: Vec<u64> = {
            if let Ok(bearer_list) = self.bearer_list.read() {
                bearer_list
                    .values()
                    .filter(|b| b.sess_id == sess_id)
                    .map(|b| b.id)
                    .collect()
            } else {
                return;
            }
        };
        for id in bearer_ids {
            self.bearer_remove(id);
        }
    }

    /// Find bearer by ID
    pub fn bearer_find_by_id(&self, id: u64) -> Option<SmfBearer> {
        let bearer_list = self.bearer_list.read().ok()?;
        bearer_list.get(&id).cloned()
    }

    /// Find QoS flow by ID (alias for bearer_find_by_id)
    pub fn qos_flow_find_by_id(&self, id: u64) -> Option<SmfBearer> {
        self.bearer_find_by_id(id)
    }

    /// Find QoS flow by QFI within a session
    pub fn qos_flow_find_by_qfi(&self, sess_id: u64, qfi: u8) -> Option<SmfBearer> {
        let bearer_list = self.bearer_list.read().ok()?;
        bearer_list
            .values()
            .find(|b| b.sess_id == sess_id && b.qfi == qfi)
            .cloned()
    }

    /// Find QoS flow by PCC rule ID within a session
    pub fn qos_flow_find_by_pcc_rule_id(
        &self,
        sess_id: u64,
        pcc_rule_id: &str,
    ) -> Option<SmfBearer> {
        let bearer_list = self.bearer_list.read().ok()?;
        bearer_list
            .values()
            .find(|b| b.sess_id == sess_id && b.pcc_rule_id.as_deref() == Some(pcc_rule_id))
            .cloned()
    }

    /// Find bearer by EBI within a session
    pub fn bearer_find_by_ebi(&self, sess_id: u64, ebi: u8) -> Option<SmfBearer> {
        let bearer_list = self.bearer_list.read().ok()?;
        bearer_list
            .values()
            .find(|b| b.sess_id == sess_id && b.ebi == ebi)
            .cloned()
    }

    /// Find bearer by PCC rule name within a session
    pub fn bearer_find_by_pcc_rule_name(
        &self,
        sess_id: u64,
        pcc_rule_name: &str,
    ) -> Option<SmfBearer> {
        let bearer_list = self.bearer_list.read().ok()?;
        bearer_list
            .values()
            .find(|b| b.sess_id == sess_id && b.pcc_rule_name.as_deref() == Some(pcc_rule_name))
            .cloned()
    }

    /// Find bearer by PGW S5U TEID within a session
    pub fn bearer_find_by_pgw_s5u_teid(
        &self,
        sess_id: u64,
        pgw_s5u_teid: u32,
    ) -> Option<SmfBearer> {
        let bearer_list = self.bearer_list.read().ok()?;
        bearer_list
            .values()
            .find(|b| b.sess_id == sess_id && b.pgw_s5u_teid == pgw_s5u_teid)
            .cloned()
    }

    /// Get default bearer in session
    pub fn default_bearer_in_sess(&self, sess_id: u64) -> Option<SmfBearer> {
        // Lock order bearer_list < sess_list (matches qos_flow_add/bearer_remove,
        // which hold bearer_list while taking sess_list).
        let bearer_list = self.bearer_list.read().ok()?;
        let sess_list = self.sess_list.read().ok()?;

        if let Some(sess) = sess_list.get(&sess_id) {
            if let Some(&first_bearer_id) = sess.bearer_ids.first() {
                return bearer_list.get(&first_bearer_id).cloned();
            }
        }
        None
    }

    /// Update bearer in the context
    pub fn bearer_update(&self, bearer: &SmfBearer) -> bool {
        if let Ok(mut bearer_list) = self.bearer_list.write() {
            if let Some(existing) = bearer_list.get_mut(&bearer.id) {
                *existing = bearer.clone();
                return true;
            }
        }
        false
    }

    /// Get number of bearers
    pub fn bearer_count(&self) -> usize {
        self.bearer_list.read().map(|l| l.len()).unwrap_or(0)
    }

    // ========================================================================
    // Packet Filter Management
    // ========================================================================

    /// Add a new packet filter
    pub fn pf_add(&self, bearer_id: u64) -> Option<SmfPf> {
        let mut pf_list = self.pf_list.write().ok()?;
        let mut bearer_list = self.bearer_list.write().ok()?;

        let id = self.next_pf_id.fetch_add(1, Ordering::SeqCst) as u64;
        let pf = SmfPf::new(id, bearer_id);

        pf_list.insert(id, pf.clone());

        // Add PF ID to bearer
        if let Some(bearer) = bearer_list.get_mut(&bearer_id) {
            bearer.pf_ids.push(id);
        }

        log::debug!("[bearer_id={bearer_id}] PF added (id={id})");
        Some(pf)
    }

    /// Remove a packet filter by ID
    pub fn pf_remove(&self, id: u64) -> Option<SmfPf> {
        let mut pf_list = self.pf_list.write().ok()?;
        let mut bearer_list = self.bearer_list.write().ok()?;

        if let Some(pf) = pf_list.remove(&id) {
            // Remove PF ID from bearer
            if let Some(bearer) = bearer_list.get_mut(&pf.bearer_id) {
                bearer.pf_ids.retain(|&pid| pid != id);
            }

            log::debug!("PF removed (id={id})");
            return Some(pf);
        }
        None
    }

    /// Remove all PFs for a bearer
    fn pf_remove_all_for_bearer(&self, bearer_id: u64) {
        let pf_ids: Vec<u64> = {
            if let Ok(pf_list) = self.pf_list.read() {
                pf_list
                    .values()
                    .filter(|pf| pf.bearer_id == bearer_id)
                    .map(|pf| pf.id)
                    .collect()
            } else {
                return;
            }
        };
        for id in pf_ids {
            self.pf_remove(id);
        }
    }

    /// Find PF by ID
    pub fn pf_find_by_id(&self, id: u64) -> Option<SmfPf> {
        let pf_list = self.pf_list.read().ok()?;
        pf_list.get(&id).cloned()
    }

    /// Find PF by identifier within a bearer
    pub fn pf_find_by_identifier(&self, bearer_id: u64, identifier: u8) -> Option<SmfPf> {
        let pf_list = self.pf_list.read().ok()?;
        pf_list
            .values()
            .find(|pf| pf.bearer_id == bearer_id && pf.identifier == identifier)
            .cloned()
    }

    /// Find PF by flow description within a bearer
    pub fn pf_find_by_flow(
        &self,
        bearer_id: u64,
        direction: FlowDirection,
        flow_description: &str,
    ) -> Option<SmfPf> {
        let pf_list = self.pf_list.read().ok()?;
        pf_list
            .values()
            .find(|pf| {
                pf.bearer_id == bearer_id
                    && pf.direction == direction
                    && pf.flow_description.as_deref() == Some(flow_description)
            })
            .cloned()
    }

    /// Update PF in the context
    pub fn pf_update(&self, pf: &SmfPf) -> bool {
        if let Ok(mut pf_list) = self.pf_list.write() {
            if let Some(existing) = pf_list.get_mut(&pf.id) {
                *existing = pf.clone();
                return true;
            }
        }
        false
    }

    /// Get number of PFs
    pub fn pf_count(&self) -> usize {
        self.pf_list.read().map(|l| l.len()).unwrap_or(0)
    }

    // ========================================================================
    // PCC Rule Management
    // ========================================================================

    /// Find PCC rule by ID within a session
    pub fn pcc_rule_find_by_id(&self, sess_id: u64, pcc_rule_id: &str) -> Option<PccRule> {
        let sess_list = self.sess_list.read().ok()?;
        if let Some(sess) = sess_list.get(&sess_id) {
            return sess
                .pcc_rules
                .iter()
                .find(|r| r.id.as_deref() == Some(pcc_rule_id))
                .cloned();
        }
        None
    }

    // ========================================================================
    // MBS Session Management (Rel-17 TS 23.247)
    // ========================================================================

    /// Create a new MBS session
    pub fn create_mbs_session(&self, tmgi: Tmgi, session_id: String) -> Option<MbsSession> {
        let mut mbs_sess_list = self.mbs_sess_list.write().ok()?;
        let mut tmgi_hash = self.tmgi_hash.write().ok()?;

        let id = self.next_mbs_sess_id.fetch_add(1, Ordering::SeqCst) as u64;
        let session = MbsSession::new(id, tmgi.clone(), session_id);

        tmgi_hash.insert(tmgi, id);
        mbs_sess_list.insert(id, session.clone());

        log::info!(
            "[MBS] Session created: id={} session_id={} state={:?}",
            id,
            session.session_id,
            session.state
        );
        Some(session)
    }

    /// Activate an MBS session with N4mb PFCP session
    pub fn activate_mbs_session(
        &self,
        mbs_sess_id: u64,
        multicast_addr: std::net::Ipv4Addr,
        upf_node_id: String,
        n4mb_session_id: u64,
        fteid: u32,
        transport_ip: std::net::Ipv4Addr,
    ) -> bool {
        if let Ok(mut mbs_sess_list) = self.mbs_sess_list.write() {
            if let Some(session) = mbs_sess_list.get_mut(&mbs_sess_id) {
                session.state = MbsSessionState::Active;
                session.multicast_addr = Some(multicast_addr);

                // Establish N4mb session
                session.establish_n4mb_session(upf_node_id, n4mb_session_id);
                session.activate_n4mb_session(fteid, transport_ip);

                session.updated_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("value expected")
                    .as_secs();
                log::info!(
                    "[MBS] Session activated: id={mbs_sess_id} mcast_addr={multicast_addr} n4mb_seid={n4mb_session_id}"
                );
                return true;
            }
        }
        false
    }

    /// Release an MBS session
    pub fn release_mbs_session(&self, mbs_sess_id: u64) -> Option<MbsSession> {
        let mut mbs_sess_list = self.mbs_sess_list.write().ok()?;
        let mut tmgi_hash = self.tmgi_hash.write().ok()?;

        if let Some(mut session) = mbs_sess_list.remove(&mbs_sess_id) {
            session.state = MbsSessionState::Releasing;
            tmgi_hash.remove(&session.tmgi);
            log::info!(
                "[MBS] Session released: id={} ue_count={} session_id={}",
                mbs_sess_id,
                session.ue_count(),
                session.session_id
            );
            return Some(session);
        }
        None
    }

    /// Add a UE to an MBS session
    pub fn add_ue_to_mbs(&self, mbs_sess_id: u64, ue_id: u64) -> bool {
        if let Ok(mut mbs_sess_list) = self.mbs_sess_list.write() {
            if let Some(session) = mbs_sess_list.get_mut(&mbs_sess_id) {
                if !session.joined_ues.contains(&ue_id) {
                    session.joined_ues.push(ue_id);
                    session.updated_at = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("value expected")
                        .as_secs();
                    log::debug!(
                        "[MBS] UE added to session: mbs_sess_id={} ue_id={} total_ues={}",
                        mbs_sess_id,
                        ue_id,
                        session.ue_count()
                    );
                    return true;
                }
            }
        }
        false
    }

    /// Remove a UE from an MBS session
    pub fn remove_ue_from_mbs(&self, mbs_sess_id: u64, ue_id: u64) -> bool {
        if let Ok(mut mbs_sess_list) = self.mbs_sess_list.write() {
            if let Some(session) = mbs_sess_list.get_mut(&mbs_sess_id) {
                let before = session.joined_ues.len();
                session.joined_ues.retain(|&id| id != ue_id);
                if session.joined_ues.len() < before {
                    session.updated_at = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("value expected")
                        .as_secs();
                    log::debug!(
                        "[MBS] UE removed from session: mbs_sess_id={} ue_id={} total_ues={}",
                        mbs_sess_id,
                        ue_id,
                        session.ue_count()
                    );
                    return true;
                }
            }
        }
        false
    }

    /// Find MBS session by ID
    pub fn mbs_sess_find_by_id(&self, mbs_sess_id: u64) -> Option<MbsSession> {
        let mbs_sess_list = self.mbs_sess_list.read().ok()?;
        mbs_sess_list.get(&mbs_sess_id).cloned()
    }

    /// Find MBS session by TMGI
    pub fn mbs_sess_find_by_tmgi(&self, tmgi: &Tmgi) -> Option<MbsSession> {
        // Lock order mbs_sess_list < tmgi_hash (matches create_mbs_session/release_mbs_session).
        let mbs_sess_list = self.mbs_sess_list.read().ok()?;
        let tmgi_hash = self.tmgi_hash.read().ok()?;
        tmgi_hash
            .get(tmgi)
            .and_then(|&id| mbs_sess_list.get(&id).cloned())
    }

    /// Get all active MBS sessions
    pub fn mbs_sess_active_list(&self) -> Vec<MbsSession> {
        self.mbs_sess_list
            .read()
            .map(|list| list.values().filter(|s| s.is_active()).cloned().collect())
            .expect("value expected")
    }

    /// Get number of MBS sessions
    pub fn mbs_sess_count(&self) -> usize {
        self.mbs_sess_list.read().map(|l| l.len()).unwrap_or(0)
    }

    // ========================================================================
    // Utility Functions
    // ========================================================================

    /// Get instance load percentage
    pub fn get_load(&self) -> i32 {
        let ue_count = self.ue_count();
        let sess_count = self.sess_count();
        let total = ue_count + sess_count;
        let max = self.max_num_of_ue + self.max_num_of_sess;
        if max == 0 {
            return 0;
        }
        ((total * 100) / max) as i32
    }
}

impl Default for SmfContext {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global SMF Context (Thread-safe Singleton)
// ============================================================================

/// Global SMF context
static GLOBAL_SMF_CONTEXT: std::sync::OnceLock<Arc<RwLock<SmfContext>>> =
    std::sync::OnceLock::new();

/// Get the global SMF context
pub fn smf_self() -> Arc<RwLock<SmfContext>> {
    GLOBAL_SMF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(SmfContext::new())))
        .clone()
}

/// Initialize the global SMF context
pub fn smf_context_init(max_ue: usize, max_sess: usize, max_bearer: usize) {
    let ctx = smf_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_ue, max_sess, max_bearer);
    };
}

/// The ONE agreement about this process's ambient SMF state, for tests (#308).
///
/// Four globals are involved and they cannot be guarded separately, because the
/// production paths under test read all four together:
/// - [`GLOBAL_SMF_CONTEXT`] — [`smf_context_init`] calls `SmfContext::init`, which
///   clears the UE, session, bearer, policy-binding and PFCP-session maps for the
///   WHOLE process rather than for the test that asked;
/// - `udm::UDM_ENABLED`, `easdf`'s config slot and `eps_iwk::EPS_IWK_ENABLED` — the
///   feature switches `handle_sm_context_create` / `_release` consult, so a sibling
///   that turns one ON changes what a create does in a test that never mentions it;
/// - the `UDM_SBI_ADDR` / `UDM_SBI_PORT` / `NRF_URI` environment — the fallback
///   `discover_udm_service_endpoint` resolves, which names one UDM for every `nudm`
///   service, so whoever wrote it last owns every sibling's UDM traffic.
///
/// Before #308 the writers of the last two were locked (three per-module
/// `SWITCH_LOCK`s plus a crate-root `UDM_ENV_TEST_LOCK`) and the READERS were not,
/// and the context wipe was not guarded at all. That asymmetry is not a smaller
/// version of the same protection, it is none: `cargo test --workspace` failed
/// about 1 run in 5 in three different tests, each one a locked writer and an
/// unlocked reader disagreeing about a global neither test names —
/// - a create-path test read a sibling's subscribed session-AMBR (40/80 Mbps) in
///   place of the config default, because the sibling's UDM switch was still on;
/// - a release-path test's `DELETE` landed on another test's recording UDM, which
///   then found it instead of its own `PUT`;
/// - a sibling `smf_context_init` cleared the policy bindings between a create and
///   the assertion that the create had stored one.
///
/// Four locks over one ambient state were four disjoint agreements: each
/// serialised its own writers and none could order a test that did not know about
/// it. This is deliberately ONE lock, declared beside the largest of the globals
/// it guards rather than inside any `mod tests`, so every module reaches the same
/// static (`pub(crate)`) instead of declaring its own — #276 showed that a second
/// lock over shared state HANGS the suite rather than merely flaking it.
///
/// Lock order, for a test that needs a UPF as well: take THIS one first, then
/// [`crate::pfcp_path::N4_TEST_LOCK`] (which
/// [`crate::pfcp_path::stand_in::associated_upf`] takes on the test's behalf and
/// holds for the life of the returned value). Every call site in the crate follows
/// that order; reversing it anywhere reintroduces a deadlock.
///
/// Sync `#[test]` functions take it with `blocking_lock()`, which is sound
/// precisely because they have no runtime to block.
#[cfg(test)]
pub(crate) static PROCESS_STATE_TEST_LOCK: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

/// Finalize the global SMF context
pub fn smf_context_final() {
    let ctx = smf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

/// Get instance load (for NF instance load reporting)
pub fn smf_instance_get_load() -> i32 {
    let ctx = smf_self();
    if let Ok(context) = ctx.read() {
        return context.get_load();
    }
    0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smf_context_new() {
        let ctx = SmfContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.ue_count(), 0);
        assert_eq!(ctx.sess_count(), 0);
        assert_eq!(ctx.bearer_count(), 0);
    }

    #[test]
    fn test_smf_context_init_fini() {
        let mut ctx = SmfContext::new();
        ctx.init(100, 200, 400);
        assert!(ctx.is_initialized());
        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_ue_add_remove_by_supi() {
        let mut ctx = SmfContext::new();
        ctx.init(100, 200, 400);

        let ue = ctx.ue_add_by_supi("imsi-001010000000001").unwrap();
        assert_eq!(ue.supi.as_deref(), Some("imsi-001010000000001"));
        assert_eq!(ctx.ue_count(), 1);

        let found = ctx.ue_find_by_supi("imsi-001010000000001");
        assert!(found.is_some());

        ctx.ue_remove(ue.id);
        assert_eq!(ctx.ue_count(), 0);
    }

    #[test]
    fn test_ue_add_remove_by_imsi() {
        let mut ctx = SmfContext::new();
        ctx.init(100, 200, 400);

        let imsi = vec![0x00, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ue = ctx.ue_add_by_imsi(&imsi).unwrap();
        assert_eq!(ctx.ue_count(), 1);

        let found = ctx.ue_find_by_imsi(&imsi);
        assert!(found.is_some());

        ctx.ue_remove(ue.id);
        assert_eq!(ctx.ue_count(), 0);
    }

    #[test]
    fn test_sess_add_remove_by_psi() {
        let mut ctx = SmfContext::new();
        ctx.init(100, 200, 400);

        let ue = ctx.ue_add_by_supi("imsi-001010000000001").unwrap();
        let sess = ctx.sess_add_by_psi(ue.id, 1).unwrap();
        assert_eq!(sess.psi, 1);
        assert_eq!(ctx.sess_count(), 1);

        let found = ctx.sess_find_by_psi(ue.id, 1);
        assert!(found.is_some());

        ctx.sess_remove(sess.id);
        assert_eq!(ctx.sess_count(), 0);
    }

    #[test]
    fn test_sess_add_remove_by_apn() {
        let mut ctx = SmfContext::new();
        ctx.init(100, 200, 400);

        let ue = ctx.ue_add_by_imsi(&[0x00, 0x10, 0x10]).unwrap();
        let sess = ctx.sess_add_by_apn(ue.id, "internet", 1).unwrap();
        assert_eq!(sess.session_name.as_deref(), Some("internet"));
        assert!(sess.epc);
        assert_eq!(ctx.sess_count(), 1);

        let found = ctx.sess_find_by_apn(ue.id, "internet", 1);
        assert!(found.is_some());

        ctx.sess_remove(sess.id);
        assert_eq!(ctx.sess_count(), 0);
    }

    #[test]
    fn test_sess_find_by_seid() {
        let mut ctx = SmfContext::new();
        ctx.init(100, 200, 400);

        let ue = ctx.ue_add_by_supi("imsi-001010000000001").unwrap();
        let sess = ctx.sess_add_by_psi(ue.id, 1).unwrap();
        let seid = sess.smf_n4_seid;

        let found = ctx.sess_find_by_seid(seid);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, sess.id);
    }

    #[test]
    fn test_bearer_add_remove() {
        let mut ctx = SmfContext::new();
        ctx.init(100, 200, 400);

        let ue = ctx.ue_add_by_supi("imsi-001010000000001").unwrap();
        let sess = ctx.sess_add_by_psi(ue.id, 1).unwrap();
        let bearer = ctx.qos_flow_add(sess.id).unwrap();
        assert_eq!(ctx.bearer_count(), 1);

        ctx.bearer_remove(bearer.id);
        assert_eq!(ctx.bearer_count(), 0);
    }

    #[test]
    fn test_pf_add_remove() {
        let mut ctx = SmfContext::new();
        ctx.init(100, 200, 400);

        let ue = ctx.ue_add_by_supi("imsi-001010000000001").unwrap();
        let sess = ctx.sess_add_by_psi(ue.id, 1).unwrap();
        let bearer = ctx.qos_flow_add(sess.id).unwrap();
        let pf = ctx.pf_add(bearer.id).unwrap();
        assert_eq!(ctx.pf_count(), 1);

        ctx.pf_remove(pf.id);
        assert_eq!(ctx.pf_count(), 0);
    }

    #[test]
    fn test_sess_ipv4_lookup() {
        let mut ctx = SmfContext::new();
        ctx.init(100, 200, 400);

        let ue = ctx.ue_add_by_supi("imsi-001010000000001").unwrap();
        let mut sess = ctx.sess_add_by_psi(ue.id, 1).unwrap();
        sess.ipv4_addr = Some("10.45.0.1".parse().unwrap());
        ctx.sess_update(&sess);

        let found = ctx.sess_find_by_ipv4("10.45.0.1".parse().unwrap());
        assert!(found.is_some());
        assert_eq!(found.unwrap().psi, 1);
    }

    #[test]
    fn test_cascade_removal() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.blocking_lock();
        let mut ctx = SmfContext::new();
        ctx.init(100, 200, 400);

        let ue = ctx.ue_add_by_supi("imsi-001010000000001").unwrap();
        let sess = ctx.sess_add_by_psi(ue.id, 1).unwrap();
        let bearer = ctx.qos_flow_add(sess.id).unwrap();
        let _pf = ctx.pf_add(bearer.id).unwrap();

        assert_eq!(ctx.ue_count(), 1);
        assert_eq!(ctx.sess_count(), 1);
        assert_eq!(ctx.bearer_count(), 1);
        assert_eq!(ctx.pf_count(), 1);

        // Removing UE should cascade remove session, bearer, and PF
        ctx.ue_remove(ue.id);
        assert_eq!(ctx.ue_count(), 0);
        assert_eq!(ctx.sess_count(), 0);
        assert_eq!(ctx.bearer_count(), 0);
        assert_eq!(ctx.pf_count(), 0);
    }

    // ── durable state (issue #191) ───────────────────────────────────────────
    //
    // Every test here builds its own `SmfContext`, never `smf_self()`: arming a
    // state file on the process-global context would make one test's snapshot the
    // next test's restored state.

    /// Unique snapshot path per test so parallel runs cannot collide.
    fn temp_state_path(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "nextgcore-smf-state-{}-{tag}-{nanos}.json",
            std::process::id()
        ))
    }

    fn ctx_with_state(path: &std::path::Path) -> SmfContext {
        let mut ctx = SmfContext::new();
        ctx.init(100, 200, 400);
        ctx.set_state_file(path.to_path_buf())
            .expect("arming a fresh state file must succeed");
        ctx
    }

    fn binding(
        supi: &str,
        psi: u8,
        ue_ip: [u8; 4],
        state: crate::gsm_sm::GsmState,
    ) -> PolicyBinding {
        let mut b = PolicyBinding::snapshot_default();
        b.sm_policy_id = Some(format!("pol-{supi}-{psi}"));
        b.supi = supi.to_string();
        b.psi = psi;
        b.pti = 3;
        b.pdu_session_type = 1;
        b.ssc_mode = 1;
        b.ue_ip = ue_ip;
        b.dnn = "internet".to_string();
        b.qfi = 1;
        b.five_qi = 9;
        b.ambr_ul_bps = 100_000_000;
        b.ambr_dl_bps = 200_000_000;
        b.sm_context_status_uri = Some("http://amf/status".to_string());
        b.fsm.state = state;
        b.easdf_dns_context_id = Some("dns-ctx-9".to_string());
        b
    }

    // ── #193: a session whose binding record did not survive ──

    /// A snapshot whose binding record cannot be typed still yields its consumer
    /// callback, because the file is valid JSON and only the TYPED read failed.
    ///
    /// That salvage is what makes a boot-time notification possible at all. It is
    /// asserted here, on the context, rather than only through the notifier: the
    /// notifier can be given the entry by any means, and what must hold is that
    /// `restore_from` produces it from a record it could not read.
    #[test]
    fn an_unreadable_binding_yields_its_session_and_a_salvaged_callback() {
        let path = temp_state_path("unrestorable");
        // Hand-written snapshot: `policyBindings` holds a record with a member of
        // the wrong TYPE, which is what a schema move looks like. `psi` is a u8 in
        // `PolicyBinding`, so a string fails deserialisation while the object
        // remains perfectly good JSON.
        let doc = serde_json::json!({
            "version": SmfContext::SNAPSHOT_VERSION,
            "pfcpSessions": { "orphan-ref": 0x0193_2000u64 },
            "policyBindings": {
                "orphan-ref": {
                    "psi": "not-a-number",
                    "smContextStatusUri": "http://amf.example/callbacks/sm-status"
                }
            },
            "ipv4Allocations": [],
            "upfRecoveryTimeStamps": {}
        });
        std::fs::write(&path, serde_json::to_string(&doc).expect("json")).expect("write snapshot");

        let ctx = ctx_with_state(&path);

        assert!(
            ctx.policy_bindings
                .read()
                .expect("bindings")
                .get("orphan-ref")
                .is_none(),
            "precondition: the binding record must have been skipped"
        );
        assert_eq!(
            ctx.pfcp_sessions
                .read()
                .expect("sessions")
                .get("orphan-ref")
                .copied(),
            Some(0x0193_2000),
            "the session restores independently -- which is exactly why it is left \
             unserviceable"
        );
        let pending = ctx.unrestorable_sessions.read().expect("pending").clone();
        assert_eq!(pending.len(), 1, "the orphaned session must be recorded");
        assert_eq!(pending[0].sm_context_ref, "orphan-ref");
        assert_eq!(
            pending[0].status_uri.as_deref(),
            Some("http://amf.example/callbacks/sm-status"),
            "the callback must be SALVAGED from the raw record; without it there is nobody to \
             notify and the whole boot signal is impossible"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A skipped binding with NO session under the same key is not a stranded
    /// resource: there is nothing the consumer could be told is released, so it
    /// must not be queued for notification.
    #[test]
    fn an_unreadable_binding_with_no_session_is_not_queued() {
        let path = temp_state_path("unrestorable-no-session");
        let doc = serde_json::json!({
            "version": SmfContext::SNAPSHOT_VERSION,
            "pfcpSessions": {},
            "policyBindings": {
                "binding-only-ref": {
                    "psi": "not-a-number",
                    "smContextStatusUri": "http://amf.example/callbacks/sm-status"
                }
            },
            "ipv4Allocations": [],
            "upfRecoveryTimeStamps": {}
        });
        std::fs::write(&path, serde_json::to_string(&doc).expect("json")).expect("write snapshot");

        let ctx = ctx_with_state(&path);

        assert!(
            ctx.unrestorable_sessions
                .read()
                .expect("pending")
                .is_empty(),
            "with no session there is no stranded resource, so notifying would invent one"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The whole point of #191: a session created before a restart, and the
    /// address it holds, are both still there afterwards.
    #[test]
    fn snapshot_restores_sessions_bindings_and_ip_allocations() {
        let path = temp_state_path("roundtrip");
        let addr = {
            let ctx = ctx_with_state(&path);
            let addr = ctx.ipv4_pool.allocate().expect("pool has addresses");
            // The allocate call site persists; here the pool is driven directly, so
            // the mutation is followed by the same explicit persist.
            ctx.persist();
            {
                let mut sessions = ctx.pfcp_sessions.write().unwrap();
                sessions.insert("ref-1".to_string(), 0x0102_0304_0506_0708);
            }
            ctx.persist();
            {
                let mut bindings = ctx.policy_bindings.write().unwrap();
                bindings.insert(
                    "ref-1".to_string(),
                    binding(
                        "imsi-001010000000001",
                        5,
                        addr.octets(),
                        crate::gsm_sm::GsmState::Operational,
                    ),
                );
            }
            ctx.persist();
            ctx.note_upf_recovery_time_stamp("127.0.0.1:8805", 4242);
            addr
        };

        // A cold rebuild from the same file: a different process would do exactly
        // this, and nothing carries over except the snapshot.
        let restored_ctx = ctx_with_state(&path);

        assert_eq!(
            restored_ctx
                .pfcp_sessions
                .read()
                .unwrap()
                .get("ref-1")
                .copied(),
            Some(0x0102_0304_0506_0708),
            "the UPF SEID must survive, or the SMF cannot delete the N4 session"
        );
        let b = restored_ctx
            .policy_bindings
            .read()
            .unwrap()
            .get("ref-1")
            .cloned()
            .expect("policy binding restored");
        assert_eq!(b.supi, "imsi-001010000000001");
        assert_eq!(b.psi, 5);
        assert_eq!(b.ue_ip, addr.octets());
        assert_eq!(b.ambr_dl_bps, 200_000_000);
        assert_eq!(
            b.sm_policy_id.as_deref(),
            Some("pol-imsi-001010000000001-5")
        );
        assert_eq!(b.easdf_dns_context_id.as_deref(), Some("dns-ctx-9"));
        assert_eq!(
            b.fsm.state,
            crate::gsm_sm::GsmState::Operational,
            "a binding restored into Initial would re-run establishment for a live session"
        );
        assert_eq!(
            restored_ctx.upf_recovery_time_stamp("127.0.0.1:8805"),
            Some(4242),
            "without the peer stamp the restored session map can never be checked"
        );
        // The allocation itself, not merely the copy of it inside the binding.
        assert!(
            restored_ctx.ipv4_pool.allocated_addrs().contains(&addr),
            "the pool must know {addr} is held"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The consequence that makes this a correctness fix and not just resilience:
    /// a restored allocation must not be handed to a second UE.
    #[test]
    fn a_restored_allocation_is_not_reissued() {
        let path = temp_state_path("no-reissue");
        let held = {
            let ctx = ctx_with_state(&path);
            let held: Vec<Ipv4Addr> = (0..3)
                .map(|_| ctx.ipv4_pool.allocate().expect("pool has addresses"))
                .collect();
            ctx.persist();
            held
        };
        // .0.0 and .0.1 are reserved, so the first three allocations are .0.2-.0.4.
        assert_eq!(
            held,
            vec![
                Ipv4Addr::new(10, 45, 0, 2),
                Ipv4Addr::new(10, 45, 0, 3),
                Ipv4Addr::new(10, 45, 0, 4)
            ]
        );

        let restored_ctx = ctx_with_state(&path);
        // POSITIVE assertion: the next free address is the one after the restored
        // run, not merely "different from the three". A pool that restored nothing
        // would answer .0.2 here, and a pool that restored the bits but lost the
        // count would answer .0.5 too -- so the count is checked as well.
        let fresh = restored_ctx
            .ipv4_pool
            .allocate()
            .expect("pool has addresses");
        assert_eq!(fresh, Ipv4Addr::new(10, 45, 0, 5));
        assert_eq!(
            restored_ctx.ipv4_pool.active_count(),
            4,
            "three restored plus one fresh; the reserved .0.0/.0.1 are not counted"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Releasing an address must reach the snapshot, or the pool leaks across
    /// restarts -- the mirror of the double-assignment above.
    #[test]
    fn a_released_allocation_is_not_restored() {
        let path = temp_state_path("release");
        {
            let ctx = ctx_with_state(&path);
            let ue = ctx.ue_add_by_supi("imsi-001010000000009").expect("ue");
            let mut sess = ctx.sess_add_by_psi(ue.id, 1).expect("sess");
            let addr = ctx.ipv4_pool.allocate().expect("pool has addresses");
            sess.ipv4_addr = Some(addr);
            ctx.sess_update(&sess);
            ctx.persist();
            assert!(ctx.ipv4_pool.allocated_addrs().contains(&addr));
            // sess_remove releases the address and persists.
            ctx.sess_remove(sess.id).expect("session removed");
            assert!(!ctx.ipv4_pool.allocated_addrs().contains(&addr));
        }

        let restored_ctx = ctx_with_state(&path);
        assert_eq!(
            restored_ctx.ipv4_pool.active_count(),
            0,
            "a released address must not come back as held"
        );
        assert_eq!(
            restored_ctx.ipv4_pool.allocate(),
            Some(Ipv4Addr::new(10, 45, 0, 2)),
            "the released address is reusable again"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The shipped default: no state file means no file operations at all.
    #[test]
    fn without_a_state_file_nothing_is_persisted() {
        let dir = std::env::temp_dir().join(format!(
            "nextgcore-smf-nostate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");

        // Positive control FIRST, so the absence assertion below is known to be
        // capable of failing: an armed context writing into this same directory
        // must be visible to the scan. Without this the test would also pass if
        // the scan were looking in the wrong place.
        {
            let armed = ctx_with_state(&dir.join("armed.json"));
            let _ = armed.ipv4_pool.allocate();
            armed.persist();
        }
        assert!(
            dir.join("armed.json").exists(),
            "positive control: an armed store must write into the watched directory"
        );
        std::fs::remove_file(dir.join("armed.json")).expect("clear the control");

        let mut ctx = SmfContext::new();
        ctx.init(100, 200, 400);
        assert!(!ctx.state_is_enabled());
        let _ = ctx.ipv4_pool.allocate();
        {
            let mut sessions = ctx.pfcp_sessions.write().unwrap();
            sessions.insert("ref-x".to_string(), 7);
        }
        ctx.persist();
        ctx.note_upf_recovery_time_stamp("127.0.0.1:8805", 11);
        let ue = ctx.ue_add_by_supi("imsi-001010000000002").expect("ue");
        let sess = ctx.sess_add_by_psi(ue.id, 1).expect("sess");
        ctx.sess_remove(sess.id);
        ctx.fini();

        let entries: Vec<_> = std::fs::read_dir(&dir)
            .expect("read temp dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert!(
            entries.is_empty(),
            "a memory-only SMF must touch no files, found {entries:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A snapshot from a newer build must be refused AND left alone, not
    /// partially restored and then rewritten in the older format.
    #[test]
    fn a_newer_snapshot_is_refused_and_not_overwritten() {
        let path = temp_state_path("newer");
        let doc = serde_json::json!({
            "version": SmfContext::SNAPSHOT_VERSION + 1,
            "pfcpSessions": { "ref-future": 99 },
            "policyBindings": {},
            "ipv4Allocations": ["10.45.7.7"],
            "upfRecoveryTimeStamps": {},
        });
        let before = serde_json::to_vec_pretty(&doc).expect("serialise");
        std::fs::write(&path, &before).expect("write snapshot");

        let mut ctx = SmfContext::new();
        ctx.init(100, 200, 400);
        let err = ctx
            .set_state_file(path.clone())
            .expect_err("a newer snapshot must be refused");
        assert!(
            matches!(err, SmfStateError::UnsupportedVersion { .. }),
            "got {err:?}"
        );
        assert!(
            !ctx.state_is_enabled(),
            "the store must be disabled so a later mutation cannot rewrite the file"
        );

        // Prove the refusal protects the file: a mutation after the failed load
        // must not rewrite it.
        let _ = ctx.ipv4_pool.allocate();
        ctx.persist();
        assert_eq!(
            std::fs::read(&path).expect("file still there"),
            before,
            "the newer-format file must be byte-identical after a refused load"
        );

        let _ = std::fs::remove_file(&path);
    }
}
