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

    /// Convert to string (e.g., "310410")
    pub fn to_string(&self) -> String {
        if self.mnc_len() == 2 {
            format!("{:03}{:02}", self.mcc(), self.mnc())
        } else {
            format!("{:03}{:03}", self.mcc(), self.mnc())
        }
    }
}

impl fmt::Display for PlmnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
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
            .map(|sd| format!("{:06x}", sd))
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
