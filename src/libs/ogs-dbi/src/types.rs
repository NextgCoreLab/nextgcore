//! Database Interface Types
//!
//! Common types and constants used throughout the database interface.
//! Ported from lib/dbi/ headers in the C implementation.

use serde::{Deserialize, Serialize};

// Key lengths (from ogs-crypt.h)
pub const OGS_KEY_LEN: usize = 16;
pub const OGS_AMF_LEN: usize = 2;
pub const OGS_RAND_LEN: usize = 16;
pub const OGS_MAX_SQN: u64 = 0xFFFFFFFFFFFF; // 48-bit max

// String lengths
pub const OGS_MAX_IMSI_LEN: usize = 15;
pub const OGS_MAX_IMSI_BCD_LEN: usize = 15;
pub const OGS_MAX_MSISDN_LEN: usize = 15;
pub const OGS_MAX_MSISDN_BCD_LEN: usize = 15;
pub const OGS_MAX_FQDN_LEN: usize = 256;
pub const OGS_MAX_IMEISV_LEN: usize = 16;
pub const OGS_MAX_IMEISV_BCD_LEN: usize = 16;
pub const OGS_IPV6_LEN: usize = 16;

// Array limits
pub const OGS_MAX_NUM_OF_MSISDN: usize = 2;
pub const OGS_MAX_NUM_OF_SLICE: usize = 8;
pub const OGS_MAX_NUM_OF_SESS: usize = 4;
pub const OGS_MAX_NUM_OF_PCC_RULE: usize = 8;
pub const OGS_MAX_NUM_OF_FLOW_IN_PCC_RULE: usize = 8;
pub const OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI: usize = 8;
pub const OGS_MAX_NUM_OF_IFC: usize = 16;
pub const OGS_MAX_NUM_OF_SPT: usize = 16;

// S-NSSAI constants
pub const OGS_S_NSSAI_NO_SD_VALUE: u32 = 0xFFFFFF;

// MongoDB field names (matching C implementation)
pub const OGS_IMSI_STRING: &str = "imsi";
pub const OGS_MSISDN_STRING: &str = "msisdn";
pub const OGS_IMEISV_STRING: &str = "imeisv";
pub const OGS_SECURITY_STRING: &str = "security";
pub const OGS_K_STRING: &str = "k";
pub const OGS_OPC_STRING: &str = "opc";
pub const OGS_OP_STRING: &str = "op";
pub const OGS_AMF_STRING: &str = "amf";
pub const OGS_RAND_STRING: &str = "rand";
pub const OGS_SQN_STRING: &str = "sqn";
pub const OGS_MME_HOST_STRING: &str = "mme_host";
pub const OGS_MME_REALM_STRING: &str = "mme_realm";
pub const OGS_MME_TIMESTAMP_STRING: &str = "mme_timestamp";
pub const OGS_PURGE_FLAG_STRING: &str = "purge_flag";
pub const OGS_ACCESS_RESTRICTION_DATA_STRING: &str = "access_restriction_data";
pub const OGS_SUBSCRIBER_STATUS_STRING: &str = "subscriber_status";
pub const OGS_OPERATOR_DETERMINED_BARRING_STRING: &str = "operator_determined_barring";
pub const OGS_NETWORK_ACCESS_MODE_STRING: &str = "network_access_mode";
pub const OGS_SUBSCRIBED_RAU_TAU_TIMER_STRING: &str = "subscribed_rau_tau_timer";
pub const OGS_AMBR_STRING: &str = "ambr";
pub const OGS_DOWNLINK_STRING: &str = "downlink";
pub const OGS_UPLINK_STRING: &str = "uplink";
pub const OGS_VALUE_STRING: &str = "value";
pub const OGS_UNIT_STRING: &str = "unit";
pub const OGS_SLICE_STRING: &str = "slice";
pub const OGS_SST_STRING: &str = "sst";
pub const OGS_SD_STRING: &str = "sd";
pub const OGS_DEFAULT_INDICATOR_STRING: &str = "default_indicator";
pub const OGS_SESSION_STRING: &str = "session";
pub const OGS_NAME_STRING: &str = "name";
pub const OGS_TYPE_STRING: &str = "type";
pub const OGS_LBO_ROAMING_ALLOWED_STRING: &str = "lbo_roaming_allowed";
pub const OGS_QOS_STRING: &str = "qos";
pub const OGS_INDEX_STRING: &str = "index";
pub const OGS_ARP_STRING: &str = "arp";
pub const OGS_PRIORITY_LEVEL_STRING: &str = "priority_level";
pub const OGS_PRE_EMPTION_CAPABILITY_STRING: &str = "pre_emption_capability";
pub const OGS_PRE_EMPTION_VULNERABILITY_STRING: &str = "pre_emption_vulnerability";
pub const OGS_SMF_STRING: &str = "smf";
pub const OGS_UE_STRING: &str = "ue";
pub const OGS_IPV4_STRING: &str = "ipv4";
pub const OGS_IPV6_STRING: &str = "ipv6";
pub const OGS_IPV4_FRAMED_ROUTES_STRING: &str = "ipv4_framed_routes";
pub const OGS_IPV6_FRAMED_ROUTES_STRING: &str = "ipv6_framed_routes";
pub const OGS_PCC_RULE_STRING: &str = "pcc_rule";
pub const OGS_MBR_STRING: &str = "mbr";
pub const OGS_GBR_STRING: &str = "gbr";
pub const OGS_FLOW_STRING: &str = "flow";
pub const OGS_DIRECTION_STRING: &str = "direction";
pub const OGS_DESCRIPTION_STRING: &str = "description";

// 24-bit unsigned integer (for SD in S-NSSAI)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OgsUint24 {
    pub v: u32, // Only lower 24 bits used
}

impl OgsUint24 {
    pub fn new(value: u32) -> Self {
        OgsUint24 { v: value & 0xFFFFFF }
    }

    pub fn to_be_bytes(&self) -> [u8; 3] {
        let bytes = self.v.to_be_bytes();
        [bytes[1], bytes[2], bytes[3]]
    }

    pub fn from_be_bytes(bytes: [u8; 3]) -> Self {
        OgsUint24 {
            v: ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32),
        }
    }

    /// Parse SD from hex string (e.g., "000001")
    pub fn from_hex_string(s: &str) -> Option<Self> {
        u32::from_str_radix(s, 16).ok().map(OgsUint24::new)
    }
}

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OgsSNssai {
    pub sst: u8,
    pub sd: OgsUint24,
}

impl OgsSNssai {
    pub fn new(sst: u8, sd: Option<u32>) -> Self {
        OgsSNssai {
            sst,
            sd: OgsUint24::new(sd.unwrap_or(OGS_S_NSSAI_NO_SD_VALUE)),
        }
    }

    pub fn has_sd(&self) -> bool {
        self.sd.v != OGS_S_NSSAI_NO_SD_VALUE
    }
}

/// MSISDN data structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsMsisdn {
    pub buf: Vec<u8>,
    pub len: usize,
    pub bcd: String,
}

/// AMBR (Aggregate Maximum Bit Rate)
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct OgsAmbr {
    pub downlink: u64,
    pub uplink: u64,
}

/// ARP (Allocation and Retention Priority)
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct OgsArp {
    pub priority_level: u8,
    pub pre_emption_capability: u8,
    pub pre_emption_vulnerability: u8,
}

/// QoS (Quality of Service)
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct OgsQos {
    pub index: u8,
    pub arp: OgsArp,
    pub mbr: OgsAmbr,
    pub gbr: OgsAmbr,
}

/// IP address structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsIp {
    pub ipv4: bool,
    pub ipv6: bool,
    pub addr: u32,
    pub addr6: [u8; OGS_IPV6_LEN],
}

/// Session data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsSession {
    pub name: Option<String>,
    pub session_type: i32,
    pub lbo_roaming_allowed: bool,
    pub qos: OgsQos,
    pub ambr: OgsAmbr,
    pub smf_ip: OgsIp,
    pub ue_ip: OgsIp,
    pub ipv4_framed_routes: Vec<String>,
    pub ipv6_framed_routes: Vec<String>,
}

/// Flow direction
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum OgsFlowDirection {
    #[default]
    Unspecified = 0,
    Downlink = 1,
    Uplink = 2,
    Bidirectional = 3,
}

/// Flow data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsFlow {
    pub direction: i32,
    pub description: Option<String>,
}

/// PCC Rule (Policy and Charging Control)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsPccRule {
    pub id: Option<String>,
    pub name: Option<String>,
    pub precedence: i32,
    pub qos: OgsQos,
    pub flow: Vec<OgsFlow>,
    pub num_of_flow: usize,
}

impl OgsPccRule {
    /// Free all allocated resources
    pub fn clear(&mut self) {
        self.id = None;
        self.name = None;
        self.flow.clear();
        self.num_of_flow = 0;
    }
}

/// Slice data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsSliceData {
    pub s_nssai: OgsSNssai,
    pub default_indicator: bool,
    pub session: Vec<OgsSession>,
    pub num_of_session: usize,
}

/// Subscription data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsSubscriptionData {
    pub imsi: Option<String>,
    pub msisdn: Vec<OgsMsisdn>,
    pub num_of_msisdn: usize,
    pub access_restriction_data: i32,
    pub subscriber_status: i32,
    pub operator_determined_barring: i32,
    pub network_access_mode: i32,
    pub subscribed_rau_tau_timer: i32,
    pub ambr: OgsAmbr,
    pub slice: Vec<OgsSliceData>,
    pub num_of_slice: usize,
    pub mme_host: Option<String>,
    pub mme_realm: Option<String>,
    pub purge_flag: bool,
}

impl OgsSubscriptionData {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all allocated resources
    pub fn clear(&mut self) {
        self.imsi = None;
        self.msisdn.clear();
        self.num_of_msisdn = 0;
        for slice in &mut self.slice {
            for session in &mut slice.session {
                session.name = None;
                session.ipv4_framed_routes.clear();
                session.ipv6_framed_routes.clear();
            }
        }
        self.slice.clear();
        self.num_of_slice = 0;
        self.mme_host = None;
        self.mme_realm = None;
    }
}

/// Session data (for session queries)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsSessionData {
    pub session: OgsSession,
    pub pcc_rule: Vec<OgsPccRule>,
    pub num_of_pcc_rule: usize,
}

impl OgsSessionData {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all allocated resources
    pub fn clear(&mut self) {
        self.session.name = None;
        self.session.ipv4_framed_routes.clear();
        self.session.ipv6_framed_routes.clear();
        for rule in &mut self.pcc_rule {
            rule.clear();
        }
        self.pcc_rule.clear();
        self.num_of_pcc_rule = 0;
    }
}

/// SPT (Service Point Trigger) type
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum OgsSptType {
    #[default]
    None = 0,
    HasMethod = 1,
    HasSessionCase = 2,
    HasSipHeader = 3,
    HasSdpLine = 4,
    HasRequestUri = 5,
}

pub const OGS_SPT_HAS_METHOD: i32 = OgsSptType::HasMethod as i32;
pub const OGS_SPT_HAS_SESSION_CASE: i32 = OgsSptType::HasSessionCase as i32;
pub const OGS_SPT_HAS_SIP_HEADER: i32 = OgsSptType::HasSipHeader as i32;
pub const OGS_SPT_HAS_SDP_LINE: i32 = OgsSptType::HasSdpLine as i32;
pub const OGS_SPT_HAS_REQUEST_URI: i32 = OgsSptType::HasRequestUri as i32;

/// SPT (Service Point Trigger)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsSpt {
    pub condition_negated: i32,
    pub group: i32,
    pub spt_type: i32,
    pub method: Option<String>,
    pub session_case: i32,
    pub header: Option<String>,
    pub header_content: Option<String>,
    pub sdp_line: Option<String>,
    pub sdp_line_content: Option<String>,
    pub request_uri: Option<String>,
}

/// Trigger Point
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsTriggerPoint {
    pub condition_type_cnf: i32,
    pub spt: Vec<OgsSpt>,
    pub num_of_spt: usize,
}

/// Application Server
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsApplicationServer {
    pub server_name: Option<String>,
    pub default_handling: i32,
}

/// IFC (Initial Filter Criteria)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsIfc {
    pub priority: i32,
    pub application_server: OgsApplicationServer,
    pub trigger_point: OgsTriggerPoint,
}

/// IMS data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsImsData {
    pub msisdn: Vec<OgsMsisdn>,
    pub num_of_msisdn: usize,
    pub ifc: Vec<OgsIfc>,
    pub num_of_ifc: usize,
}

impl OgsImsData {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all allocated resources
    pub fn clear(&mut self) {
        self.msisdn.clear();
        self.num_of_msisdn = 0;
        for ifc in &mut self.ifc {
            ifc.application_server.server_name = None;
            for spt in &mut ifc.trigger_point.spt {
                spt.method = None;
                spt.header = None;
                spt.header_content = None;
                spt.sdp_line = None;
                spt.sdp_line_content = None;
                spt.request_uri = None;
            }
        }
        self.ifc.clear();
        self.num_of_ifc = 0;
    }
}

/// Helper function to convert BCD string to buffer
pub fn ogs_bcd_to_buffer(bcd: &str, buf: &mut Vec<u8>) -> usize {
    buf.clear();
    let chars: Vec<char> = bcd.chars().collect();
    let len = chars.len();
    
    for i in (0..len).step_by(2) {
        let high = chars.get(i).and_then(|c| c.to_digit(16)).unwrap_or(0) as u8;
        let low = chars.get(i + 1).and_then(|c| c.to_digit(16)).unwrap_or(0xF) as u8;
        buf.push((high << 4) | low);
    }
    
    buf.len()
}

/// Helper function to parse SUPI type (e.g., "imsi" from "imsi-123456789012345")
pub fn ogs_id_get_type(supi: &str) -> Option<String> {
    supi.split('-').next().map(|s| s.to_string())
}

/// Helper function to parse SUPI value (e.g., "123456789012345" from "imsi-123456789012345")
pub fn ogs_id_get_value(supi: &str) -> Option<String> {
    let parts: Vec<&str> = supi.splitn(2, '-').collect();
    if parts.len() == 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// Helper function to convert hex string to bytes
pub fn ogs_ascii_to_hex(ascii: &str, buf: &mut [u8]) -> usize {
    let bytes: Vec<u8> = (0..ascii.len())
        .step_by(2)
        .filter_map(|i| {
            ascii.get(i..i + 2)
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect();
    
    let len = bytes.len().min(buf.len());
    buf[..len].copy_from_slice(&bytes[..len]);
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ogs_uint24() {
        let u = OgsUint24::new(0x123456);
        assert_eq!(u.v, 0x123456);
        
        let bytes = u.to_be_bytes();
        assert_eq!(bytes, [0x12, 0x34, 0x56]);
        
        let u2 = OgsUint24::from_be_bytes(bytes);
        assert_eq!(u2.v, 0x123456);
        
        // Test overflow handling
        let u3 = OgsUint24::new(0xFFFFFFFF);
        assert_eq!(u3.v, 0xFFFFFF);
    }

    #[test]
    fn test_ogs_id_parsing() {
        let supi = "imsi-123456789012345";
        assert_eq!(ogs_id_get_type(supi), Some("imsi".to_string()));
        assert_eq!(ogs_id_get_value(supi), Some("123456789012345".to_string()));
        
        let supi2 = "nai-user@example.com";
        assert_eq!(ogs_id_get_type(supi2), Some("nai".to_string()));
        assert_eq!(ogs_id_get_value(supi2), Some("user@example.com".to_string()));
    }

    #[test]
    fn test_ogs_ascii_to_hex() {
        let mut buf = [0u8; 16];
        let len = ogs_ascii_to_hex("465B5CE8B199B49FAA5F0A2EE238A6BC", &mut buf);
        assert_eq!(len, 16);
        assert_eq!(buf[0], 0x46);
        assert_eq!(buf[1], 0x5B);
        assert_eq!(buf[15], 0xBC);
    }

    #[test]
    fn test_s_nssai() {
        let snssai = OgsSNssai::new(1, Some(0x000001));
        assert_eq!(snssai.sst, 1);
        assert_eq!(snssai.sd.v, 0x000001);
        assert!(snssai.has_sd());
        
        let snssai2 = OgsSNssai::new(1, None);
        assert!(!snssai2.has_sd());
    }
}
