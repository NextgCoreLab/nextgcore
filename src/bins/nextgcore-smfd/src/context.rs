//! SMF Context Management
//!
//! Port of src/smf/context.c, src/smf/context.h - SMF context with UE list, session list,
//! bearer list, packet filter list, and hash tables

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of DNS servers
pub const MAX_NUM_OF_DNS: usize = 2;
/// Maximum number of P-CSCF servers
pub const MAX_NUM_OF_P_CSCF: usize = 16;
/// Maximum IMSI length
pub const OGS_MAX_IMSI_LEN: usize = 15;
/// Maximum IMSI BCD length
pub const OGS_MAX_IMSI_BCD_LEN: usize = 15;
/// Maximum MSISDN length
pub const OGS_MAX_MSISDN_LEN: usize = 15;
/// Maximum MSISDN BCD length
pub const OGS_MAX_MSISDN_BCD_LEN: usize = 15;
/// Maximum IMEISV length
pub const OGS_MAX_IMEISV_LEN: usize = 8;
/// Maximum IMEISV BCD length
pub const OGS_MAX_IMEISV_BCD_LEN: usize = 16;
/// Maximum number of PCC rules
pub const OGS_MAX_NUM_OF_PCC_RULE: usize = 8;
/// Maximum number of flows in NAS
pub const OGS_MAX_NUM_OF_FLOW_IN_NAS: usize = 16;
/// Maximum number of flows in bearer
pub const OGS_MAX_NUM_OF_FLOW_IN_BEARER: usize = 16;
/// Invalid pool ID
pub const OGS_INVALID_POOL_ID: u64 = 0;
/// NAS PDU session identity unassigned
pub const OGS_NAS_PDU_SESSION_IDENTITY_UNASSIGNED: u8 = 0;

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
        let mcc_bytes: Vec<u8> = mcc.chars().filter_map(|c| c.to_digit(10).map(|d| d as u8)).collect();
        let mnc_bytes: Vec<u8> = mnc.chars().filter_map(|c| c.to_digit(10).map(|d| d as u8)).collect();
        
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
    pub index: u8,  // 5QI
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
            1 => Some(Self { resource_type: 0, priority_level: 20, packet_delay_budget_ms: 100, packet_error_rate_exp: 2, max_data_burst_volume: 0, averaging_window_ms: 2000 }),
            2 => Some(Self { resource_type: 0, priority_level: 40, packet_delay_budget_ms: 150, packet_error_rate_exp: 3, max_data_burst_volume: 0, averaging_window_ms: 2000 }),
            3 => Some(Self { resource_type: 0, priority_level: 30, packet_delay_budget_ms: 50, packet_error_rate_exp: 3, max_data_burst_volume: 0, averaging_window_ms: 2000 }),
            4 => Some(Self { resource_type: 0, priority_level: 50, packet_delay_budget_ms: 300, packet_error_rate_exp: 6, max_data_burst_volume: 0, averaging_window_ms: 2000 }),
            65 => Some(Self { resource_type: 0, priority_level: 7, packet_delay_budget_ms: 75, packet_error_rate_exp: 2, max_data_burst_volume: 0, averaging_window_ms: 2000 }),
            66 => Some(Self { resource_type: 0, priority_level: 20, packet_delay_budget_ms: 100, packet_error_rate_exp: 2, max_data_burst_volume: 0, averaging_window_ms: 2000 }),
            67 => Some(Self { resource_type: 0, priority_level: 15, packet_delay_budget_ms: 100, packet_error_rate_exp: 3, max_data_burst_volume: 0, averaging_window_ms: 2000 }),
            // Standard Non-GBR 5QIs
            5 => Some(Self { resource_type: 2, priority_level: 10, packet_delay_budget_ms: 100, packet_error_rate_exp: 6, max_data_burst_volume: 0, averaging_window_ms: 0 }),
            6 => Some(Self { resource_type: 2, priority_level: 60, packet_delay_budget_ms: 300, packet_error_rate_exp: 6, max_data_burst_volume: 0, averaging_window_ms: 0 }),
            7 => Some(Self { resource_type: 2, priority_level: 70, packet_delay_budget_ms: 100, packet_error_rate_exp: 3, max_data_burst_volume: 0, averaging_window_ms: 0 }),
            8 => Some(Self { resource_type: 2, priority_level: 80, packet_delay_budget_ms: 300, packet_error_rate_exp: 6, max_data_burst_volume: 0, averaging_window_ms: 0 }),
            9 => Some(Self { resource_type: 2, priority_level: 90, packet_delay_budget_ms: 300, packet_error_rate_exp: 6, max_data_burst_volume: 0, averaging_window_ms: 0 }),
            // Rel-18 XR 5QI values (TS 23.501 Table 5.7.4-1)
            82 => Some(Self { resource_type: 0, priority_level: 21, packet_delay_budget_ms: 10, packet_error_rate_exp: 3, max_data_burst_volume: 60_000, averaging_window_ms: 2000 }),
            83 => Some(Self { resource_type: 0, priority_level: 20, packet_delay_budget_ms: 5, packet_error_rate_exp: 4, max_data_burst_volume: 1_500, averaging_window_ms: 2000 }),
            84 => Some(Self { resource_type: 0, priority_level: 22, packet_delay_budget_ms: 15, packet_error_rate_exp: 3, max_data_burst_volume: 30_000, averaging_window_ms: 2000 }),
            85 => Some(Self { resource_type: 0, priority_level: 19, packet_delay_budget_ms: 5, packet_error_rate_exp: 5, max_data_burst_volume: 500, averaging_window_ms: 2000 }),
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
// SMF Context (Main)
// ============================================================================

/// SMF Context - main context structure for SMF
/// Port of smf_context_t from context.h
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

    // Pool limits
    /// Maximum number of UEs
    max_num_of_ue: usize,
    /// Maximum number of sessions
    max_num_of_sess: usize,
    /// Maximum number of bearers
    max_num_of_bearer: usize,

    /// Context initialized flag
    initialized: AtomicBool,
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
            supi_hash: RwLock::new(HashMap::new()),
            imsi_hash: RwLock::new(HashMap::new()),
            ipv4_hash: RwLock::new(HashMap::new()),
            ipv6_hash: RwLock::new(HashMap::new()),
            smf_n4_seid_hash: RwLock::new(HashMap::new()),
            n1n2message_hash: RwLock::new(HashMap::new()),
            next_ue_id: AtomicUsize::new(1),
            next_sess_id: AtomicUsize::new(1),
            next_bearer_id: AtomicUsize::new(1),
            next_pf_id: AtomicUsize::new(1),
            sess_index: AtomicU64::new(1),
            n4_seid_generator: AtomicU64::new(1),
            max_num_of_ue: 0,
            max_num_of_sess: 0,
            max_num_of_bearer: 0,
            initialized: AtomicBool::new(false),
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

        self.ue_remove_all();
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("SMF context finalized");
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

        log::info!("[Added] SMF UE by SUPI [{}] (id={})", supi, id);
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

            log::info!("[Removed] SMF UE (id={})", id);
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
        let supi_hash = self.supi_hash.read().ok()?;
        let smf_ue_list = self.smf_ue_list.read().ok()?;
        supi_hash.get(supi).and_then(|&id| smf_ue_list.get(&id).cloned())
    }

    /// Find UE by IMSI
    pub fn ue_find_by_imsi(&self, imsi: &[u8]) -> Option<SmfUe> {
        let imsi_hash = self.imsi_hash.read().ok()?;
        let smf_ue_list = self.smf_ue_list.read().ok()?;
        imsi_hash.get(imsi).and_then(|&id| smf_ue_list.get(&id).cloned())
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
            log::error!("Maximum number of sessions [{}] reached", self.max_num_of_sess);
            return None;
        }

        let id = self.next_sess_id.fetch_add(1, Ordering::SeqCst) as u64;
        let index = self.sess_index.fetch_add(1, Ordering::SeqCst) as u32;
        let n4_seid = self.next_n4_seid();

        let mut sess = SmfSess::new(id, index, smf_ue_id);
        sess.psi = psi;
        sess.smf_n4_seid = n4_seid;
        sess.smf_n4_teid = n4_seid as u32;
        sess.sm_context_ref = Some(format!("{}", index));
        sess.pdu_session_ref = Some(format!("{}", index));
        sess.charging.id = index;

        smf_n4_seid_hash.insert(n4_seid, id);
        sess_list.insert(id, sess.clone());

        // Add session ID to UE
        if let Some(ue) = smf_ue_list.get_mut(&smf_ue_id) {
            ue.sess_ids.push(id);
        }

        log::debug!("[ue_id={}, psi={}] SMF session added (id={}, seid={})", smf_ue_id, psi, id, n4_seid);
        Some(sess)
    }

    /// Add a new session by APN (EPC)
    pub fn sess_add_by_apn(&self, smf_ue_id: u64, apn: &str, rat_type: u8) -> Option<SmfSess> {
        let mut sess_list = self.sess_list.write().ok()?;
        let mut smf_n4_seid_hash = self.smf_n4_seid_hash.write().ok()?;
        let mut smf_ue_list = self.smf_ue_list.write().ok()?;

        if sess_list.len() >= self.max_num_of_sess {
            log::error!("Maximum number of sessions [{}] reached", self.max_num_of_sess);
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

        log::debug!("[ue_id={}, apn={}] SMF session added (id={}, seid={})", smf_ue_id, apn, id, n4_seid);
        Some(sess)
    }

    /// Remove a session by ID
    pub fn sess_remove(&self, id: u64) -> Option<SmfSess> {
        // First, remove all bearers for this session (must be done before acquiring session locks)
        self.bearer_remove_all_for_sess(id);

        // Now remove the session itself
        let mut sess_list = self.sess_list.write().ok()?;
        let mut smf_n4_seid_hash = self.smf_n4_seid_hash.write().ok()?;
        let mut ipv4_hash = self.ipv4_hash.write().ok()?;
        let mut ipv6_hash = self.ipv6_hash.write().ok()?;
        let mut n1n2message_hash = self.n1n2message_hash.write().ok()?;
        let mut smf_ue_list = self.smf_ue_list.write().ok()?;

        if let Some(sess) = sess_list.remove(&id) {
            smf_n4_seid_hash.remove(&sess.smf_n4_seid);
            
            if let Some(addr) = sess.ipv4_addr {
                ipv4_hash.remove(&u32::from(addr));
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
            return Some(sess);
        }
        None
    }

    /// Remove all sessions for a UE
    fn sess_remove_all_for_ue(&self, smf_ue_id: u64) {
        let sess_ids: Vec<u64> = {
            if let Ok(sess_list) = self.sess_list.read() {
                sess_list.values()
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
        let smf_n4_seid_hash = self.smf_n4_seid_hash.read().ok()?;
        let sess_list = self.sess_list.read().ok()?;
        smf_n4_seid_hash.get(&seid).and_then(|&id| sess_list.get(&id).cloned())
    }

    /// Find session by APN (EPC)
    pub fn sess_find_by_apn(&self, smf_ue_id: u64, apn: &str, rat_type: u8) -> Option<SmfSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list.values()
            .find(|s| s.smf_ue_id == smf_ue_id 
                && s.session_name.as_deref() == Some(apn)
                && s.gtp_rat_type == rat_type)
            .cloned()
    }

    /// Find session by PSI (5GC)
    pub fn sess_find_by_psi(&self, smf_ue_id: u64, psi: u8) -> Option<SmfSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list.values()
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
        let ipv4_hash = self.ipv4_hash.read().ok()?;
        let sess_list = self.sess_list.read().ok()?;
        ipv4_hash.get(&u32::from(addr)).and_then(|&id| sess_list.get(&id).cloned())
    }

    /// Find session by IPv6 prefix
    pub fn sess_find_by_ipv6(&self, addr: &[u8; 8]) -> Option<SmfSess> {
        let ipv6_hash = self.ipv6_hash.read().ok()?;
        let sess_list = self.sess_list.read().ok()?;
        ipv6_hash.get(addr).and_then(|&id| sess_list.get(&id).cloned())
    }

    /// Find session by paging N1N2 message location
    pub fn sess_find_by_paging_n1n2message_location(&self, location: &str) -> Option<SmfSess> {
        let n1n2message_hash = self.n1n2message_hash.read().ok()?;
        let sess_list = self.sess_list.read().ok()?;
        n1n2message_hash.get(location).and_then(|&id| sess_list.get(&id).cloned())
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
        if let (Ok(mut sess_list), Ok(mut n1n2message_hash)) = (
            self.sess_list.write(),
            self.n1n2message_hash.write(),
        ) {
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


    // ========================================================================
    // Bearer/QoS Flow Management
    // ========================================================================

    /// Add a new QoS flow (5GC)
    pub fn qos_flow_add(&self, sess_id: u64) -> Option<SmfBearer> {
        let mut bearer_list = self.bearer_list.write().ok()?;
        let mut sess_list = self.sess_list.write().ok()?;

        if bearer_list.len() >= self.max_num_of_bearer {
            log::error!("Maximum number of bearers [{}] reached", self.max_num_of_bearer);
            return None;
        }

        let id = self.next_bearer_id.fetch_add(1, Ordering::SeqCst) as u64;
        let bearer = SmfBearer::new(id, sess_id);

        bearer_list.insert(id, bearer.clone());

        // Add bearer ID to session
        if let Some(sess) = sess_list.get_mut(&sess_id) {
            sess.bearer_ids.push(id);
        }

        log::debug!("[sess_id={}] QoS flow added (id={})", sess_id, id);
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

            log::debug!("Bearer removed (id={})", id);
            return Some(bearer);
        }
        None
    }

    /// Remove all bearers for a session
    fn bearer_remove_all_for_sess(&self, sess_id: u64) {
        let bearer_ids: Vec<u64> = {
            if let Ok(bearer_list) = self.bearer_list.read() {
                bearer_list.values()
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
        bearer_list.values()
            .find(|b| b.sess_id == sess_id && b.qfi == qfi)
            .cloned()
    }

    /// Find QoS flow by PCC rule ID within a session
    pub fn qos_flow_find_by_pcc_rule_id(&self, sess_id: u64, pcc_rule_id: &str) -> Option<SmfBearer> {
        let bearer_list = self.bearer_list.read().ok()?;
        bearer_list.values()
            .find(|b| b.sess_id == sess_id && b.pcc_rule_id.as_deref() == Some(pcc_rule_id))
            .cloned()
    }

    /// Find bearer by EBI within a session
    pub fn bearer_find_by_ebi(&self, sess_id: u64, ebi: u8) -> Option<SmfBearer> {
        let bearer_list = self.bearer_list.read().ok()?;
        bearer_list.values()
            .find(|b| b.sess_id == sess_id && b.ebi == ebi)
            .cloned()
    }

    /// Find bearer by PCC rule name within a session
    pub fn bearer_find_by_pcc_rule_name(&self, sess_id: u64, pcc_rule_name: &str) -> Option<SmfBearer> {
        let bearer_list = self.bearer_list.read().ok()?;
        bearer_list.values()
            .find(|b| b.sess_id == sess_id && b.pcc_rule_name.as_deref() == Some(pcc_rule_name))
            .cloned()
    }

    /// Find bearer by PGW S5U TEID within a session
    pub fn bearer_find_by_pgw_s5u_teid(&self, sess_id: u64, pgw_s5u_teid: u32) -> Option<SmfBearer> {
        let bearer_list = self.bearer_list.read().ok()?;
        bearer_list.values()
            .find(|b| b.sess_id == sess_id && b.pgw_s5u_teid == pgw_s5u_teid)
            .cloned()
    }

    /// Get default bearer in session
    pub fn default_bearer_in_sess(&self, sess_id: u64) -> Option<SmfBearer> {
        let sess_list = self.sess_list.read().ok()?;
        let bearer_list = self.bearer_list.read().ok()?;
        
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

        log::debug!("[bearer_id={}] PF added (id={})", bearer_id, id);
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

            log::debug!("PF removed (id={})", id);
            return Some(pf);
        }
        None
    }

    /// Remove all PFs for a bearer
    fn pf_remove_all_for_bearer(&self, bearer_id: u64) {
        let pf_ids: Vec<u64> = {
            if let Ok(pf_list) = self.pf_list.read() {
                pf_list.values()
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
        pf_list.values()
            .find(|pf| pf.bearer_id == bearer_id && pf.identifier == identifier)
            .cloned()
    }

    /// Find PF by flow description within a bearer
    pub fn pf_find_by_flow(&self, bearer_id: u64, direction: FlowDirection, flow_description: &str) -> Option<SmfPf> {
        let pf_list = self.pf_list.read().ok()?;
        pf_list.values()
            .find(|pf| pf.bearer_id == bearer_id 
                && pf.direction == direction 
                && pf.flow_description.as_deref() == Some(flow_description))
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
            return sess.pcc_rules.iter()
                .find(|r| r.id.as_deref() == Some(pcc_rule_id))
                .cloned();
        }
        None
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
static GLOBAL_SMF_CONTEXT: std::sync::OnceLock<Arc<RwLock<SmfContext>>> = std::sync::OnceLock::new();

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
}
