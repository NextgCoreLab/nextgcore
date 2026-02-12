//! Protocol types and structures

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of sessions per UE
pub const MAX_NUM_OF_SESS: usize = 4;
/// Maximum number of bearers per session
pub const MAX_NUM_OF_BEARER: usize = 4;
/// Number of bearers per UE
pub const BEARER_PER_UE: usize = 8;
/// Maximum number of GTP-U buffers per UE
pub const MAX_NUM_OF_GTPU_BUFFER: usize = 64;

/// Maximum number of flows in PDR
pub const MAX_NUM_OF_FLOW_IN_PDR: usize = 15;
/// Maximum number of flows in GTP
pub const MAX_NUM_OF_FLOW_IN_GTP: usize = MAX_NUM_OF_FLOW_IN_PDR;
/// Maximum number of flows in NAS
pub const MAX_NUM_OF_FLOW_IN_NAS: usize = MAX_NUM_OF_FLOW_IN_PDR;
/// Maximum number of flows in PCC rule
pub const MAX_NUM_OF_FLOW_IN_PCC_RULE: usize = MAX_NUM_OF_FLOW_IN_PDR;
/// Maximum number of flows in bearer
pub const MAX_NUM_OF_FLOW_IN_BEARER: usize = 15;

/// PLMN ID length
pub const PLMN_ID_LEN: usize = 3;
/// Maximum PLMN ID BCD length
pub const MAX_PLMN_ID_BCD_LEN: usize = 6;

/// Charging characteristics length
pub const CHRGCHARS_LEN: usize = 2;

/// Maximum IMSI BCD length
pub const MAX_IMSI_BCD_LEN: usize = 15;
/// Maximum IMEISV BCD length
pub const MAX_IMEISV_BCD_LEN: usize = 16;
/// Maximum MSISDN BCD length
pub const MAX_MSISDN_BCD_LEN: usize = 15;

/// Maximum DNN length
pub const MAX_DNN_LEN: usize = 100;
/// Maximum APN length
pub const MAX_APN_LEN: usize = MAX_DNN_LEN;
/// Maximum FQDN length
pub const MAX_FQDN_LEN: usize = 256;

/// Maximum number of algorithms
pub const MAX_NUM_OF_ALGORITHM: usize = 8;

/// Maximum number of served GUMMEI
pub const MAX_NUM_OF_SERVED_GUMMEI: usize = 8;
/// Maximum number of served GUAMI
pub const MAX_NUM_OF_SERVED_GUAMI: usize = 256;
/// Maximum number of supported TA
pub const MAX_NUM_OF_SUPPORTED_TA: usize = 256;
/// Maximum number of slice support
pub const MAX_NUM_OF_SLICE_SUPPORT: usize = 1024;

/// Maximum number of PLMN per MME
pub const MAX_NUM_OF_PLMN_PER_MME: usize = 32;
/// Maximum number of PLMN
pub const MAX_NUM_OF_PLMN: usize = 12;

/// Maximum number of TAI
pub const MAX_NUM_OF_TAI: usize = 16;
/// Maximum number of slices
pub const MAX_NUM_OF_SLICE: usize = 8;

/// Maximum QoS flow ID
pub const MAX_QOS_FLOW_ID: u8 = 63;

/// IPv4 length
pub const IPV4_LEN: usize = 4;
/// IPv6 length
pub const IPV6_LEN: usize = 16;
/// Default IPv6 prefix length
pub const IPV6_DEFAULT_PREFIX_LEN: u8 = 64;
/// IPv6 128-bit prefix length
pub const IPV6_128_PREFIX_LEN: u8 = 128;

/// Access type: 3GPP
pub const ACCESS_TYPE_3GPP: u8 = 1;
/// Access type: Non-3GPP
pub const ACCESS_TYPE_NON_3GPP: u8 = 2;
/// Access type: Both
pub const ACCESS_TYPE_BOTH_3GPP_AND_NON_3GPP: u8 = 3;

/// NAS PTI unassigned
pub const NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED: u8 = 0;
/// NAS PDU session identity unassigned
pub const NAS_PDU_SESSION_IDENTITY_UNASSIGNED: u8 = 0;

/// S-NSSAI no SD value
pub const S_NSSAI_NO_SD_VALUE: u32 = 0xffffff;

// ============================================================================
// PLMN ID
// ============================================================================

/// PLMN ID structure (3 bytes)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlmnId {
    data: [u8; 3],
}

impl PlmnId {
    /// Create a new PLMN ID from raw bytes
    pub fn from_bytes(bytes: [u8; 3]) -> Self {
        Self { data: bytes }
    }

    /// Build a PLMN ID from MCC, MNC, and MNC length
    pub fn build(mcc: u16, mnc: u16, mnc_len: u8) -> Self {
        let mut plmn = Self::default();

        let mcc1 = ((mcc / 100) % 10) as u8;
        let mcc2 = ((mcc / 10) % 10) as u8;
        let mcc3 = (mcc % 10) as u8;

        plmn.data[0] = (mcc2 << 4) | mcc1;
        plmn.data[1] = mcc3;

        if mnc_len == 2 {
            plmn.data[1] |= 0xf0;
            let mnc2 = ((mnc / 10) % 10) as u8;
            let mnc3 = (mnc % 10) as u8;
            plmn.data[2] = (mnc3 << 4) | mnc2;
        } else {
            let mnc1 = ((mnc / 100) % 10) as u8;
            let mnc2 = ((mnc / 10) % 10) as u8;
            let mnc3 = (mnc % 10) as u8;
            plmn.data[1] |= mnc1 << 4;
            plmn.data[2] = (mnc3 << 4) | mnc2;
        }

        plmn
    }

    /// Get MCC
    pub fn mcc(&self) -> u16 {
        let mcc1 = (self.data[0] & 0x0f) as u16;
        let mcc2 = ((self.data[0] >> 4) & 0x0f) as u16;
        let mcc3 = (self.data[1] & 0x0f) as u16;
        mcc1 * 100 + mcc2 * 10 + mcc3
    }

    /// Get MNC
    pub fn mnc(&self) -> u16 {
        let mnc1 = (self.data[1] >> 4) & 0x0f;
        let mnc2 = (self.data[2] & 0x0f) as u16;
        let mnc3 = ((self.data[2] >> 4) & 0x0f) as u16;

        if mnc1 == 0x0f {
            mnc2 * 10 + mnc3
        } else {
            (mnc1 as u16) * 100 + mnc2 * 10 + mnc3
        }
    }

    /// Get MNC length (2 or 3)
    pub fn mnc_len(&self) -> u8 {
        if (self.data[1] >> 4) == 0x0f {
            2
        } else {
            3
        }
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 3] {
        &self.data
    }

}

impl fmt::Display for PlmnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.mnc_len() == 2 {
            write!(f, "{:03}{:02}", self.mcc(), self.mnc())
        } else {
            write!(f, "{:03}{:03}", self.mcc(), self.mnc())
        }
    }
}

// ============================================================================
// AMF ID
// ============================================================================

/// AMF ID structure (3 bytes)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AmfId {
    region: u8,
    set1: u8,
    set2_pointer: u8,
}

impl AmfId {
    /// Build an AMF ID
    pub fn build(region: u8, set: u16, pointer: u8) -> Self {
        Self {
            region,
            set1: (set >> 2) as u8,
            set2_pointer: (((set & 0x3) as u8) << 6) | (pointer & 0x3f),
        }
    }

    /// Get region ID
    pub fn region(&self) -> u8 {
        self.region
    }

    /// Get set ID
    pub fn set_id(&self) -> u16 {
        ((self.set1 as u16) << 2) | ((self.set2_pointer >> 6) as u16)
    }

    /// Get pointer
    pub fn pointer(&self) -> u8 {
        self.set2_pointer & 0x3f
    }

    /// Convert to hex string
    pub fn to_hex_string(&self) -> String {
        format!(
            "{:02x}{:02x}{:02x}",
            self.region, self.set1, self.set2_pointer
        )
    }

    /// Parse from hex string
    pub fn from_hex_string(hex: &str) -> Option<Self> {
        if hex.len() != 6 {
            return None;
        }

        let bytes = hex::decode(hex).ok()?;
        if bytes.len() != 3 {
            return None;
        }

        Some(Self {
            region: bytes[0],
            set1: bytes[1],
            set2_pointer: bytes[2],
        })
    }
}

// ============================================================================
// GUAMI
// ============================================================================

/// GUAMI (Globally Unique AMF Identifier)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Guami {
    pub plmn_id: PlmnId,
    pub amf_id: AmfId,
}

// ============================================================================
// TAI
// ============================================================================

/// EPS TAI (Tracking Area Identity)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EpsTai {
    pub plmn_id: PlmnId,
    pub tac: u16,
}

/// 5GS TAI (Tracking Area Identity)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FiveGsTai {
    pub plmn_id: PlmnId,
    pub tac: u32, // 24 bits
}

// ============================================================================
// Cell ID
// ============================================================================

/// E-UTRAN Cell Global Identifier
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ECgi {
    pub plmn_id: PlmnId,
    pub cell_id: u32, // 28 bits
}

/// NR Cell Global Identifier
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NrCgi {
    pub plmn_id: PlmnId,
    pub cell_id: u64, // 36 bits
}

// ============================================================================
// S-NSSAI
// ============================================================================

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SNssai {
    pub sst: u8,
    pub sd: Option<u32>, // 24 bits, None = no SD
}

impl SNssai {
    /// Create a new S-NSSAI
    pub fn new(sst: u8, sd: Option<u32>) -> Self {
        Self { sst, sd }
    }

    /// Create S-NSSAI without SD
    pub fn without_sd(sst: u8) -> Self {
        Self { sst, sd: None }
    }

    /// Check if SD is present
    pub fn has_sd(&self) -> bool {
        self.sd.is_some() && self.sd != Some(S_NSSAI_NO_SD_VALUE)
    }

    /// Convert SD to hex string
    pub fn sd_to_string(&self) -> Option<String> {
        self.sd
            .filter(|&sd| sd != S_NSSAI_NO_SD_VALUE)
            .map(|sd| format!("{sd:06x}"))
    }
}

// ============================================================================
// IP Address
// ============================================================================

/// IP address (supports both IPv4 and IPv6)
#[derive(Debug, Clone, Default)]
pub struct IpAddr {
    pub addr: u32,
    pub addr6: [u8; IPV6_LEN],
    pub len: u32,
    pub ipv4: bool,
    pub ipv6: bool,
}

impl IpAddr {
    /// Create from IPv4 address
    pub fn from_ipv4(addr: Ipv4Addr) -> Self {
        Self {
            addr: u32::from(addr),
            addr6: [0; IPV6_LEN],
            len: IPV4_LEN as u32,
            ipv4: true,
            ipv6: false,
        }
    }

    /// Create from IPv6 address
    pub fn from_ipv6(addr: Ipv6Addr) -> Self {
        Self {
            addr: 0,
            addr6: addr.octets(),
            len: IPV6_LEN as u32,
            ipv4: false,
            ipv6: true,
        }
    }

    /// Create dual-stack address
    pub fn from_dual(ipv4: Ipv4Addr, ipv6: Ipv6Addr) -> Self {
        Self {
            addr: u32::from(ipv4),
            addr6: ipv6.octets(),
            len: (IPV4_LEN + IPV6_LEN) as u32,
            ipv4: true,
            ipv6: true,
        }
    }
}

// ============================================================================
// Bitrate
// ============================================================================

/// Bitrate structure (bits per second)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bitrate {
    pub downlink: u64,
    pub uplink: u64,
}

impl Bitrate {
    /// Create a new bitrate
    pub fn new(downlink: u64, uplink: u64) -> Self {
        Self { downlink, uplink }
    }

    /// Check if valid (non-zero)
    pub fn is_valid(&self) -> bool {
        self.downlink > 0 && self.uplink > 0
    }
}

// ============================================================================
// QoS
// ============================================================================

/// QoS index values
pub mod qos_index {
    pub const INDEX_1: u8 = 1;
    pub const INDEX_2: u8 = 2;
    pub const INDEX_5: u8 = 5;
}

/// Pre-emption capability/vulnerability (EPC)
pub mod epc_pre_emption {
    pub const DISABLED: u8 = 1;
    pub const ENABLED: u8 = 0;
}

/// Pre-emption capability/vulnerability (5GC)
pub mod fivegc_pre_emption {
    pub const DISABLED: u8 = 1;
    pub const ENABLED: u8 = 2;
}

/// Allocation and Retention Priority
#[derive(Debug, Clone, Copy, Default)]
pub struct Arp {
    pub priority_level: u8,
    pub pre_emption_capability: u8,
    pub pre_emption_vulnerability: u8,
}

/// QoS structure
#[derive(Debug, Clone, Default)]
pub struct Qos {
    pub index: u8,
    pub arp: Arp,
    pub mbr: Bitrate, // Maximum Bit Rate
    pub gbr: Bitrate, // Guaranteed Bit Rate
}

impl Qos {
    /// Check if valid
    pub fn is_valid(&self) -> bool {
        self.index > 0 && self.arp.priority_level > 0
    }
}

// ============================================================================
// Flow
// ============================================================================

/// Flow direction
pub mod flow_direction {
    pub const UNSPECIFIED: u8 = 0;
    pub const DOWNLINK_ONLY: u8 = 1;
    pub const UPLINK_ONLY: u8 = 2;
    pub const BIDIRECTIONAL: u8 = 3;
}

/// Flow structure
#[derive(Debug, Clone, Default)]
pub struct Flow {
    pub direction: u8,
    pub description: String,
}

impl Flow {
    /// Create a new flow
    pub fn new(direction: u8, description: String) -> Self {
        Self {
            direction,
            description,
        }
    }
}

// ============================================================================
// PDU Session Type
// ============================================================================

/// PDU session types
pub mod pdu_session_type {
    pub const IPV4: u8 = 1;
    pub const IPV6: u8 = 2;
    pub const IPV4V6: u8 = 3;
    pub const UNSTRUCTURED: u8 = 4;
    pub const ETHERNET: u8 = 5;
}

/// SSC modes
pub mod ssc_mode {
    pub const MODE_1: u8 = 1;
    pub const MODE_2: u8 = 2;
    pub const MODE_3: u8 = 3;
}

// ============================================================================
// Session
// ============================================================================

/// Session/PDN structure
#[derive(Debug, Clone, Default)]
pub struct Session {
    pub name: String,
    pub context_identifier: u32,
    pub default_dnn_indicator: bool,
    pub charging_characteristics: [u8; CHRGCHARS_LEN],
    pub charging_characteristics_presence: bool,
    pub session_type: u8,
    pub lbo_roaming_allowed: bool,
    pub ssc_mode: u8,
    pub qos: Qos,
    pub ambr: Bitrate,
    pub ue_ip: IpAddr,
    pub smf_ip: IpAddr,
}

// ============================================================================
// 6G ISAC (Integrated Sensing and Communication) Types
// ============================================================================

/// ISAC sensing configuration for 6G networks.
///
/// Defines operational parameters for integrated sensing and communication
/// at the network level.
#[derive(Debug, Clone, PartialEq)]
pub struct SensingConfig {
    /// Whether ISAC sensing is enabled
    pub enabled: bool,
    /// Sensing mode (0=passive, 1=active radar, 2=hybrid)
    pub mode: u8,
    /// Sensing bandwidth in MHz
    pub bandwidth_mhz: u32,
    /// Maximum sensing range in meters
    pub max_range_meters: f64,
    /// Minimum detection threshold in dBm
    pub detection_threshold_dbm: f32,
}

impl SensingConfig {
    /// Creates a new sensing configuration.
    pub fn new(mode: u8, bandwidth_mhz: u32, max_range_meters: f64) -> Self {
        Self {
            enabled: true,
            mode,
            bandwidth_mhz,
            max_range_meters,
            detection_threshold_dbm: -100.0,
        }
    }
}

impl Default for SensingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: 0,
            bandwidth_mhz: 100,
            max_range_meters: 1000.0,
            detection_threshold_dbm: -100.0,
        }
    }
}

/// ISAC sensing result containing detection information.
///
/// Aggregated result from ISAC operations at the network layer.
#[derive(Debug, Clone, Default)]
pub struct SensingResult {
    /// Timestamp of result (milliseconds since epoch)
    pub timestamp_ms: u64,
    /// Number of detections
    pub detection_count: u32,
    /// Average signal strength (dBm)
    pub avg_signal_strength_dbm: f32,
    /// Average range (meters)
    pub avg_range_meters: f64,
    /// Confidence level (0.0-1.0)
    pub confidence: f32,
}

impl SensingResult {
    /// Creates a new sensing result.
    pub fn new(timestamp_ms: u64, detection_count: u32) -> Self {
        Self {
            timestamp_ms,
            detection_count,
            avg_signal_strength_dbm: 0.0,
            avg_range_meters: 0.0,
            confidence: 0.0,
        }
    }
}

// ============================================================================
// 6G Semantic Communication Types
// ============================================================================

/// Semantic communication profile for network-level optimization.
///
/// Contains metadata for semantic communication optimization in the core network.
#[derive(Debug, Clone)]
pub struct SemanticProfile {
    /// Content modality (0=text, 1=image, 2=audio, 3=video, 4=sensor, 5=mixed)
    pub modality: u8,
    /// Compression level (0=none, 1=low, 2=medium, 3=high, 4=maximum)
    pub compression_level: u8,
    /// Semantic importance score (0.0-1.0)
    pub importance: f32,
    /// Context identifier
    pub context_id: u32,
    /// Minimum acceptable quality (0.0-1.0)
    pub min_quality: f32,
}

impl SemanticProfile {
    /// Creates a new semantic profile.
    pub fn new(modality: u8, compression_level: u8, importance: f32) -> Self {
        Self {
            modality,
            compression_level,
            importance: importance.clamp(0.0, 1.0),
            context_id: 0,
            min_quality: 0.7,
        }
    }
}

impl Default for SemanticProfile {
    fn default() -> Self {
        Self {
            modality: 0,
            compression_level: 2,
            importance: 0.5,
            context_id: 0,
            min_quality: 0.7,
        }
    }
}

// ============================================================================
// 6G Split-Hybrid Edge (SHE) Computing Types
// ============================================================================

/// Compute descriptor for SHE operations.
///
/// Describes computational task characteristics for edge offloading decisions.
#[derive(Debug, Clone)]
pub struct ComputeDescriptor {
    /// Task identifier
    pub task_id: u64,
    /// Task type name
    pub task_type: String,
    /// Workload in compute units
    pub workload_units: u64,
    /// Maximum latency budget (milliseconds)
    pub max_latency_ms: u32,
    /// Required accelerator (0=none, 1=gpu, 2=tpu, 3=fpga, 4=npu, 5=cpu)
    pub required_accelerator: u8,
    /// Input data size (bytes)
    pub input_size_bytes: u64,
    /// Output data size (bytes)
    pub output_size_bytes: u64,
    /// Priority (0-255, higher = more important)
    pub priority: u8,
}

impl ComputeDescriptor {
    /// Creates a new compute descriptor.
    pub fn new(task_id: u64, task_type: String, workload_units: u64) -> Self {
        Self {
            task_id,
            task_type,
            workload_units,
            max_latency_ms: 1000,
            required_accelerator: 5, // Default to CPU
            input_size_bytes: 0,
            output_size_bytes: 0,
            priority: 128,
        }
    }
}

impl Default for ComputeDescriptor {
    fn default() -> Self {
        Self {
            task_id: 0,
            task_type: String::new(),
            workload_units: 0,
            max_latency_ms: 1000,
            required_accelerator: 5,
            input_size_bytes: 0,
            output_size_bytes: 0,
            priority: 128,
        }
    }
}

// ============================================================================
// 6G Non-Terrestrial Network (NTN) Types
// ============================================================================

/// Satellite identifier for NTN operations.
///
/// Uniquely identifies a satellite in the NTN constellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SatelliteId(pub u32);

impl SatelliteId {
    /// Creates a new satellite ID.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw ID value.
    pub const fn value(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for SatelliteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sat-{:08x}", self.0)
    }
}

/// Orbital parameters for satellite positioning.
///
/// Describes satellite orbit characteristics for NTN operations.
#[derive(Debug, Clone, Copy)]
pub struct OrbitParams {
    /// Semi-major axis (kilometers)
    pub semi_major_axis_km: f64,
    /// Eccentricity (0.0-1.0)
    pub eccentricity: f64,
    /// Inclination (degrees)
    pub inclination_deg: f64,
    /// Right ascension of ascending node (degrees)
    pub raan_deg: f64,
    /// Argument of perigee (degrees)
    pub arg_perigee_deg: f64,
    /// Mean anomaly (degrees)
    pub mean_anomaly_deg: f64,
}

impl OrbitParams {
    /// Creates new orbital parameters.
    pub fn new(semi_major_axis_km: f64, eccentricity: f64, inclination_deg: f64) -> Self {
        Self {
            semi_major_axis_km,
            eccentricity,
            inclination_deg,
            raan_deg: 0.0,
            arg_perigee_deg: 0.0,
            mean_anomaly_deg: 0.0,
        }
    }
}

impl Default for OrbitParams {
    fn default() -> Self {
        // Default to LEO orbit (approx. 550km altitude)
        Self {
            semi_major_axis_km: 6371.0 + 550.0,
            eccentricity: 0.0,
            inclination_deg: 53.0,
            raan_deg: 0.0,
            arg_perigee_deg: 0.0,
            mean_anomaly_deg: 0.0,
        }
    }
}

/// Timing advance for NTN communications.
///
/// Compensates for propagation delay in satellite links.
#[derive(Debug, Clone, Copy, Default)]
pub struct TimingAdvance {
    /// Timing advance value (microseconds)
    pub value_us: u32,
    /// Whether timing advance is valid
    pub valid: bool,
}

impl TimingAdvance {
    /// Creates a new timing advance.
    pub const fn new(value_us: u32) -> Self {
        Self {
            value_us,
            valid: true,
        }
    }

    /// Returns invalid timing advance.
    pub const fn invalid() -> Self {
        Self {
            value_us: 0,
            valid: false,
        }
    }
}

// ============================================================================
// 6G AI/ML Types
// ============================================================================

/// AI/ML model metadata for network intelligence.
///
/// Describes ML models used for network optimization and analytics.
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct ModelMetadata {
    /// Model identifier
    pub model_id: u64,
    /// Model name
    pub name: String,
    /// Model version (major.minor.patch)
    pub version: (u32, u32, u32),
    /// Model type (0=classification, 1=regression, 2=clustering, 3=other)
    pub model_type: u8,
    /// Input dimension
    pub input_dim: u32,
    /// Output dimension
    pub output_dim: u32,
}

impl ModelMetadata {
    /// Creates new model metadata.
    pub fn new(model_id: u64, name: String, version: (u32, u32, u32)) -> Self {
        Self {
            model_id,
            name,
            version,
            model_type: 0,
            input_dim: 0,
            output_dim: 0,
        }
    }
}


/// ML inference request for network functions.
///
/// Request for ML inference at network elements.
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct InferenceRequest {
    /// Request ID
    pub request_id: u64,
    /// Model ID to use
    pub model_id: u64,
    /// Input data (serialized)
    pub input_data: Vec<f32>,
    /// Timestamp (milliseconds since epoch)
    pub timestamp_ms: u64,
}

impl InferenceRequest {
    /// Creates a new inference request.
    pub fn new(request_id: u64, model_id: u64, input_data: Vec<f32>) -> Self {
        Self {
            request_id,
            model_id,
            input_data,
            timestamp_ms: 0,
        }
    }
}


/// ML inference response.
///
/// Result from ML inference operation.
#[derive(Debug, Clone)]
pub struct InferenceResponse {
    /// Request ID (matches InferenceRequest)
    pub request_id: u64,
    /// Output data
    pub output_data: Vec<f32>,
    /// Confidence score (0.0-1.0)
    pub confidence: f32,
    /// Processing latency (microseconds)
    pub latency_us: u64,
}

impl InferenceResponse {
    /// Creates a new inference response.
    pub fn new(request_id: u64, output_data: Vec<f32>, confidence: f32) -> Self {
        Self {
            request_id,
            output_data,
            confidence,
            latency_us: 0,
        }
    }
}

impl Default for InferenceResponse {
    fn default() -> Self {
        Self {
            request_id: 0,
            output_data: Vec::new(),
            confidence: 0.0,
            latency_us: 0,
        }
    }
}

// Helper module for hex encoding
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }

        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ISAC tests
    #[test]
    fn test_sensing_config_new() {
        let config = SensingConfig::new(1, 200, 500.0);
        assert!(config.enabled);
        assert_eq!(config.mode, 1);
        assert_eq!(config.bandwidth_mhz, 200);
        assert_eq!(config.max_range_meters, 500.0);
    }

    #[test]
    fn test_sensing_result_new() {
        let result = SensingResult::new(1000, 5);
        assert_eq!(result.timestamp_ms, 1000);
        assert_eq!(result.detection_count, 5);
    }

    // Semantic communication tests
    #[test]
    fn test_semantic_profile_new() {
        let profile = SemanticProfile::new(1, 3, 0.8);
        assert_eq!(profile.modality, 1);
        assert_eq!(profile.compression_level, 3);
        assert_eq!(profile.importance, 0.8);
    }

    #[test]
    fn test_semantic_profile_clamping() {
        let profile = SemanticProfile::new(0, 0, 1.5);
        assert_eq!(profile.importance, 1.0);
    }

    // SHE computing tests
    #[test]
    fn test_compute_descriptor_new() {
        let desc = ComputeDescriptor::new(123, "inference".to_string(), 1000);
        assert_eq!(desc.task_id, 123);
        assert_eq!(desc.task_type, "inference");
        assert_eq!(desc.workload_units, 1000);
    }

    // NTN tests
    #[test]
    fn test_satellite_id_new() {
        let id = SatelliteId::new(42);
        assert_eq!(id.value(), 42);
        assert_eq!(id.to_string(), "sat-0000002a");
    }

    #[test]
    fn test_orbit_params_new() {
        let params = OrbitParams::new(7000.0, 0.001, 45.0);
        assert_eq!(params.semi_major_axis_km, 7000.0);
        assert_eq!(params.eccentricity, 0.001);
        assert_eq!(params.inclination_deg, 45.0);
    }

    #[test]
    fn test_timing_advance_new() {
        let ta = TimingAdvance::new(100);
        assert_eq!(ta.value_us, 100);
        assert!(ta.valid);
    }

    #[test]
    fn test_timing_advance_invalid() {
        let ta = TimingAdvance::invalid();
        assert!(!ta.valid);
    }

    // AI/ML tests
    #[test]
    fn test_model_metadata_new() {
        let meta = ModelMetadata::new(1, "test_model".to_string(), (1, 2, 3));
        assert_eq!(meta.model_id, 1);
        assert_eq!(meta.name, "test_model");
        assert_eq!(meta.version, (1, 2, 3));
    }

    #[test]
    fn test_inference_request_new() {
        let req = InferenceRequest::new(100, 1, vec![1.0, 2.0, 3.0]);
        assert_eq!(req.request_id, 100);
        assert_eq!(req.model_id, 1);
        assert_eq!(req.input_data.len(), 3);
    }

    #[test]
    fn test_inference_response_new() {
        let resp = InferenceResponse::new(100, vec![0.5, 0.3, 0.2], 0.95);
        assert_eq!(resp.request_id, 100);
        assert_eq!(resp.output_data.len(), 3);
        assert_eq!(resp.confidence, 0.95);
    }
}
