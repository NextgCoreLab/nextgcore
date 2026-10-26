//! GTP-C Message Building
//!
//! Port of src/smf/s5c-build.c, src/smf/gn-build.c - GTP-C message building for SMF
//! Handles GTPv2-C (S5/S8) and GTPv1-C (Gn) message construction
//!
//! Note: Many constants and types in this module are defined for completeness
//! per 3GPP TS 29.274 but may not yet be used in the current implementation.

#![allow(dead_code)]
#![allow(unused_imports)]

use bytes::{BufMut, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr};

// ============================================================================
// GTPv2-C Message Types
// ============================================================================

/// GTPv2-C Message types
pub mod gtp2_message_type {
    // Path Management Messages
    pub const ECHO_REQUEST: u8 = 1;
    pub const ECHO_RESPONSE: u8 = 2;
    pub const VERSION_NOT_SUPPORTED_INDICATION: u8 = 3;

    // Tunnel Management Messages
    pub const CREATE_SESSION_REQUEST: u8 = 32;
    pub const CREATE_SESSION_RESPONSE: u8 = 33;
    pub const MODIFY_BEARER_REQUEST: u8 = 34;
    pub const MODIFY_BEARER_RESPONSE: u8 = 35;
    pub const DELETE_SESSION_REQUEST: u8 = 36;
    pub const DELETE_SESSION_RESPONSE: u8 = 37;
    pub const CHANGE_NOTIFICATION_REQUEST: u8 = 38;
    pub const CHANGE_NOTIFICATION_RESPONSE: u8 = 39;

    // Bearer Management Messages
    pub const CREATE_BEARER_REQUEST: u8 = 95;
    pub const CREATE_BEARER_RESPONSE: u8 = 96;
    pub const UPDATE_BEARER_REQUEST: u8 = 97;
    pub const UPDATE_BEARER_RESPONSE: u8 = 98;
    pub const DELETE_BEARER_REQUEST: u8 = 99;
    pub const DELETE_BEARER_RESPONSE: u8 = 100;
    pub const DELETE_BEARER_COMMAND: u8 = 66;
    pub const DELETE_BEARER_FAILURE_INDICATION: u8 = 67;
    pub const BEARER_RESOURCE_COMMAND: u8 = 68;
    pub const BEARER_RESOURCE_FAILURE_INDICATION: u8 = 69;

    // Mobility Management Messages
    pub const DOWNLINK_DATA_NOTIFICATION: u8 = 176;
    pub const DOWNLINK_DATA_NOTIFICATION_ACK: u8 = 177;
    pub const DOWNLINK_DATA_NOTIFICATION_FAILURE_INDICATION: u8 = 70;
}

// ============================================================================
// GTPv2-C IE Types
// ============================================================================

/// GTPv2-C Information Element types (3GPP TS 29.274)
pub mod gtp2_ie_type {
    pub const IMSI: u8 = 1;
    pub const CAUSE: u8 = 2;
    pub const RECOVERY: u8 = 3;
    pub const APN: u8 = 71;
    pub const AMBR: u8 = 72;
    pub const EBI: u8 = 73;
    pub const IP_ADDRESS: u8 = 74;
    pub const MEI: u8 = 75;
    pub const MSISDN: u8 = 76;
    pub const INDICATION: u8 = 77;
    pub const PCO: u8 = 78;
    pub const PAA: u8 = 79;
    pub const BEARER_QOS: u8 = 80;
    pub const FLOW_QOS: u8 = 81;
    pub const RAT_TYPE: u8 = 82;
    pub const SERVING_NETWORK: u8 = 83;
    pub const BEARER_TFT: u8 = 84;
    pub const TAD: u8 = 85;
    pub const ULI: u8 = 86;
    pub const F_TEID: u8 = 87;
    pub const TMSI: u8 = 88;
    pub const GLOBAL_CN_ID: u8 = 89;
    pub const S103PDF: u8 = 90;
    pub const S1UDF: u8 = 91;
    pub const DELAY_VALUE: u8 = 92;
    pub const BEARER_CONTEXT: u8 = 93;
    pub const CHARGING_ID: u8 = 94;
    pub const CHARGING_CHARACTERISTICS: u8 = 95;
    pub const TRACE_INFORMATION: u8 = 96;
    pub const BEARER_FLAGS: u8 = 97;
    pub const PDN_TYPE: u8 = 99;
    pub const PTI: u8 = 100;
    pub const MM_CONTEXT_GSM_KEY_AND_TRIPLETS: u8 = 103;
    pub const MM_CONTEXT_UMTS_KEY_USED_CIPHER_AND_QUINTUPLETS: u8 = 104;
    pub const MM_CONTEXT_GSM_KEY_USED_CIPHER_AND_QUINTUPLETS: u8 = 105;
    pub const MM_CONTEXT_UMTS_KEY_AND_QUINTUPLETS: u8 = 106;
    pub const MM_CONTEXT_EPS_SECURITY_CONTEXT_QUADRUPLETS_AND_QUINTUPLETS: u8 = 107;
    pub const MM_CONTEXT_UMTS_KEY_QUADRUPLETS_AND_QUINTUPLETS: u8 = 108;
    pub const PDN_CONNECTION: u8 = 109;
    pub const PDU_NUMBERS: u8 = 110;
    pub const P_TMSI: u8 = 111;
    pub const P_TMSI_SIGNATURE: u8 = 112;
    pub const HOP_COUNTER: u8 = 113;
    pub const UE_TIME_ZONE: u8 = 114;
    pub const TRACE_REFERENCE: u8 = 115;
    pub const COMPLETE_REQUEST_MESSAGE: u8 = 116;
    pub const GUTI: u8 = 117;
    pub const F_CONTAINER: u8 = 118;
    pub const F_CAUSE: u8 = 119;
    pub const PLMN_ID: u8 = 120;
    pub const TARGET_IDENTIFICATION: u8 = 121;
    pub const PACKET_FLOW_ID: u8 = 123;
    pub const RAB_CONTEXT: u8 = 124;
    pub const SOURCE_RNC_PDCP_CONTEXT_INFO: u8 = 125;
    pub const PORT_NUMBER: u8 = 126;
    pub const APN_RESTRICTION: u8 = 127;
    pub const SELECTION_MODE: u8 = 128;
    pub const SOURCE_IDENTIFICATION: u8 = 129;
    pub const CHANGE_REPORTING_ACTION: u8 = 131;
    pub const FQ_CSID: u8 = 132;
    pub const CHANNEL_NEEDED: u8 = 133;
    pub const EMLPP_PRIORITY: u8 = 134;
    pub const NODE_TYPE: u8 = 135;
    pub const FQDN: u8 = 136;
    pub const TI: u8 = 137;
    pub const MBMS_SESSION_DURATION: u8 = 138;
    pub const MBMS_SERVICE_AREA: u8 = 139;
    pub const MBMS_SESSION_IDENTIFIER: u8 = 140;
    pub const MBMS_FLOW_IDENTIFIER: u8 = 141;
    pub const MBMS_IP_MULTICAST_DISTRIBUTION: u8 = 142;
    pub const MBMS_DISTRIBUTION_ACKNOWLEDGE: u8 = 143;
    pub const RFSP_INDEX: u8 = 144;
    pub const UCI: u8 = 145;
    pub const CSG_INFORMATION_REPORTING_ACTION: u8 = 146;
    pub const CSG_ID: u8 = 147;
    pub const CMI: u8 = 148;
    pub const SERVICE_INDICATOR: u8 = 149;
    pub const DETACH_TYPE: u8 = 150;
    pub const LDN: u8 = 151;
    pub const NODE_FEATURES: u8 = 152;
    pub const MBMS_TIME_TO_DATA_TRANSFER: u8 = 153;
    pub const THROTTLING: u8 = 154;
    pub const ARP: u8 = 155;
    pub const EPC_TIMER: u8 = 156;
    pub const SIGNALLING_PRIORITY_INDICATION: u8 = 157;
    pub const TMGI: u8 = 158;
    pub const ADDITIONAL_MM_CONTEXT_FOR_SRVCC: u8 = 159;
    pub const ADDITIONAL_FLAGS_FOR_SRVCC: u8 = 160;
    pub const MDT_CONFIGURATION: u8 = 162;
    pub const APCO: u8 = 163;
    pub const ABSOLUTE_TIME_OF_MBMS_DATA_TRANSFER: u8 = 164;
    pub const HENB_INFORMATION_REPORTING: u8 = 165;
    pub const IPV4_CONFIGURATION_PARAMETERS: u8 = 166;
    pub const CHANGE_TO_REPORT_FLAGS: u8 = 167;
    pub const ACTION_INDICATION: u8 = 168;
    pub const TWAN_IDENTIFIER: u8 = 169;
    pub const ULI_TIMESTAMP: u8 = 170;
    pub const MBMS_FLAGS: u8 = 171;
    pub const RAN_NAS_CAUSE: u8 = 172;
    pub const CN_OPERATOR_SELECTION_ENTITY: u8 = 173;
    pub const TWMI: u8 = 174;
    pub const NODE_NUMBER: u8 = 175;
    pub const NODE_IDENTIFIER: u8 = 176;
    pub const PRESENCE_REPORTING_AREA_ACTION: u8 = 177;
    pub const PRESENCE_REPORTING_AREA_INFORMATION: u8 = 178;
    pub const TWAN_IDENTIFIER_TIMESTAMP: u8 = 179;
    pub const OVERLOAD_CONTROL_INFORMATION: u8 = 180;
    pub const LOAD_CONTROL_INFORMATION: u8 = 181;
    pub const METRIC: u8 = 182;
    pub const SEQUENCE_NUMBER: u8 = 183;
    pub const APN_AND_RELATIVE_CAPACITY: u8 = 184;
    pub const WLAN_OFFLOADABILITY_INDICATION: u8 = 185;
    pub const PAGING_AND_SERVICE_INFORMATION: u8 = 186;
    pub const INTEGER_NUMBER: u8 = 187;
    pub const MILLISECOND_TIME_STAMP: u8 = 188;
    pub const MONITORING_EVENT_INFORMATION: u8 = 189;
    pub const ECGI_LIST: u8 = 190;
    pub const REMOTE_UE_CONTEXT: u8 = 191;
    pub const REMOTE_USER_ID: u8 = 192;
    pub const REMOTE_UE_IP_INFORMATION: u8 = 193;
    pub const CIOT_OPTIMIZATIONS_SUPPORT_INDICATION: u8 = 194;
    pub const SCEF_PDN_CONNECTION: u8 = 195;
    pub const HEADER_COMPRESSION_CONFIGURATION: u8 = 196;
    pub const EPCO: u8 = 197;
    pub const SERVING_PLMN_RATE_CONTROL: u8 = 198;
    pub const COUNTER: u8 = 199;
    pub const MAPPED_UE_USAGE_TYPE: u8 = 200;
    pub const SECONDARY_RAT_USAGE_DATA_REPORT: u8 = 201;
    pub const UP_FUNCTION_SELECTION_INDICATION_FLAGS: u8 = 202;
    pub const MAXIMUM_PACKET_LOSS_RATE: u8 = 203;
    pub const APN_RATE_CONTROL_STATUS: u8 = 204;
    pub const EXTENDED_TRACE_INFORMATION: u8 = 205;
    pub const MONITORING_EVENT_EXTENSION_INFORMATION: u8 = 206;
    pub const ADDITIONAL_RRM_POLICY_INDEX: u8 = 207;
    pub const V2X_CONTEXT: u8 = 208;
    pub const PC5_QOS_PARAMETERS: u8 = 209;
    pub const SERVICES_AUTHORIZED: u8 = 210;
    pub const BIT_RATE: u8 = 211;
    pub const PC5_QOS_FLOW: u8 = 212;
    pub const SGI_PTP_TUNNEL_ADDRESS: u8 = 213;
}

// ============================================================================
// GTPv2-C Cause Values
// ============================================================================

/// GTPv2-C Cause values: the shared TS 29.274 Table 8.4-1 enum (#1037). This
/// node's own copy was wrong from 69 up (Mandatory IE missing was sent as 69,
/// Request rejected as 84, Remote peer not responding as 106, ...).
pub use nextgcore_gtp::v2::Gtp2Cause;

// ============================================================================
// GTPv2-C RAT Types
// ============================================================================

/// GTPv2-C RAT types
pub mod gtp2_rat_type {
    pub const UTRAN: u8 = 1;
    pub const GERAN: u8 = 2;
    pub const WLAN: u8 = 3;
    pub const GAN: u8 = 4;
    pub const HSPA_EVOLUTION: u8 = 5;
    pub const EUTRAN: u8 = 6;
    pub const VIRTUAL: u8 = 7;
    pub const EUTRAN_NB_IOT: u8 = 8;
    pub const LTE_M: u8 = 9;
    pub const NR: u8 = 10;
}

/// GTPv2-C F-TEID interface types
pub mod gtp2_f_teid_interface {
    pub const S1_U_ENODEB_GTP_U: u8 = 0;
    pub const S1_U_SGW_GTP_U: u8 = 1;
    pub const S12_RNC_GTP_U: u8 = 2;
    pub const S12_SGW_GTP_U: u8 = 3;
    pub const S5_S8_SGW_GTP_U: u8 = 4;
    pub const S5_S8_PGW_GTP_U: u8 = 5;
    pub const S5_S8_SGW_GTP_C: u8 = 6;
    pub const S5_S8_PGW_GTP_C: u8 = 7;
    pub const S5_S8_SGW_PMIPV6: u8 = 8;
    pub const S5_S8_PGW_PMIPV6: u8 = 9;
    pub const S11_MME_GTP_C: u8 = 10;
    pub const S11_S4_SGW_GTP_C: u8 = 11;
    pub const S10_N26_MME_GTP_C: u8 = 12;
    pub const S3_MME_GTP_C: u8 = 13;
    pub const S3_SGSN_GTP_C: u8 = 14;
    pub const S4_SGSN_GTP_U: u8 = 15;
    pub const S4_SGW_GTP_U: u8 = 16;
    pub const S4_SGSN_GTP_C: u8 = 17;
    pub const S16_SGSN_GTP_C: u8 = 18;
    pub const ENODEB_GTP_U_FOR_DL_DATA_FORWARDING: u8 = 19;
    pub const ENODEB_GTP_U_FOR_UL_DATA_FORWARDING: u8 = 20;
    pub const RNC_GTP_U_FOR_DATA_FORWARDING: u8 = 21;
    pub const SGSN_GTP_U_FOR_DATA_FORWARDING: u8 = 22;
    pub const SGW_UPF_GTP_U_FOR_DL_DATA_FORWARDING: u8 = 23;
    pub const SM_MBMS_GW_GTP_C: u8 = 24;
    pub const SN_MBMS_GW_GTP_C: u8 = 25;
    pub const SM_MME_GTP_C: u8 = 26;
    pub const SN_SGSN_GTP_C: u8 = 27;
    pub const SGW_GTP_U_FOR_UL_DATA_FORWARDING: u8 = 28;
    pub const SN_SGSN_GTP_U: u8 = 29;
    pub const S2B_EPDG_GTP_C: u8 = 30;
    pub const S2B_U_EPDG_GTP_U: u8 = 31;
    pub const S2B_PGW_GTP_C: u8 = 32;
    pub const S2B_U_PGW_GTP_U: u8 = 33;
    pub const S2A_TWAN_GTP_U: u8 = 34;
    pub const S2A_TWAN_GTP_C: u8 = 35;
    pub const S2A_PGW_GTP_C: u8 = 36;
    pub const S2A_PGW_GTP_U: u8 = 37;
    pub const S11_MME_GTP_U: u8 = 38;
    pub const S11_SGW_GTP_U: u8 = 39;
    pub const N26_AMF_GTP_C: u8 = 40;
}

/// APN Restriction values
pub mod gtp2_apn_restriction {
    pub const NO_RESTRICTION: u8 = 0;
    pub const PUBLIC_1: u8 = 1;
    pub const PUBLIC_2: u8 = 2;
    pub const PRIVATE_1: u8 = 3;
    pub const PRIVATE_2: u8 = 4;
}

// ============================================================================
// GTPv2-C F-TEID Structure
// ============================================================================

/// F-TEID (Fully Qualified Tunnel Endpoint Identifier)
#[derive(Debug, Clone, Default)]
pub struct FTeid {
    /// Interface type (5 bits)
    pub interface_type: u8,
    /// TEID present flag
    pub teid_present: bool,
    /// IPv4 present flag
    pub ipv4_present: bool,
    /// IPv6 present flag
    pub ipv6_present: bool,
    /// TEID value
    pub teid: u32,
    /// IPv4 address
    pub ipv4_addr: Option<Ipv4Addr>,
    /// IPv6 address
    pub ipv6_addr: Option<Ipv6Addr>,
}

impl FTeid {
    /// Create a new F-TEID with IPv4 address
    pub fn new_ipv4(interface_type: u8, teid: u32, addr: Ipv4Addr) -> Self {
        Self {
            interface_type,
            teid_present: true,
            ipv4_present: true,
            ipv6_present: false,
            teid,
            ipv4_addr: Some(addr),
            ipv6_addr: None,
        }
    }

    /// Create a new F-TEID with IPv6 address
    pub fn new_ipv6(interface_type: u8, teid: u32, addr: Ipv6Addr) -> Self {
        Self {
            interface_type,
            teid_present: true,
            ipv4_present: false,
            ipv6_present: true,
            teid,
            ipv4_addr: None,
            ipv6_addr: Some(addr),
        }
    }

    /// Create a new F-TEID with both IPv4 and IPv6 addresses
    pub fn new_dual(interface_type: u8, teid: u32, ipv4: Ipv4Addr, ipv6: Ipv6Addr) -> Self {
        Self {
            interface_type,
            teid_present: true,
            ipv4_present: true,
            ipv6_present: true,
            teid,
            ipv4_addr: Some(ipv4),
            ipv6_addr: Some(ipv6),
        }
    }

    /// Encode F-TEID to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(25);

        // Flags byte: V4 | V6 | Interface Type (6 bits, TS 29.274 §8.22). It was masked
        // to 5, which sent the S2b PGW GTP-C (32) and S2b-U PGW GTP-U (33) types as 0
        // and 1, the S1-U eNodeB and S1-U SGW (#1113 audit).
        // There is no "TEID present" flag: the TEID is always there. Bit 8 is V4 alone;
        // it was also set for a TEID, so an IPv6-only F-TEID claimed an IPv4 address it
        // did not carry and failed to decode (#1113 review).
        let mut flags = self.interface_type & 0x3f;
        if self.ipv4_present {
            flags |= 0x80; // V4 flag
        }
        if self.ipv6_present {
            flags |= 0x40; // V6 flag
        }
        buf.put_u8(flags);

        // TEID (4 bytes, big-endian)
        if self.teid_present {
            buf.put_u32(self.teid);
        }

        // IPv4 address (4 bytes)
        if let Some(addr) = self.ipv4_addr {
            buf.put_slice(&addr.octets());
        }

        // IPv6 address (16 bytes)
        if let Some(addr) = self.ipv6_addr {
            buf.put_slice(&addr.octets());
        }

        buf.to_vec()
    }

    /// Get the encoded length
    pub fn len(&self) -> usize {
        let mut len = 1; // flags
        if self.teid_present {
            len += 4;
        }
        if self.ipv4_present {
            len += 4;
        }
        if self.ipv6_present {
            len += 16;
        }
        len
    }

    /// Check if F-TEID is empty
    pub fn is_empty(&self) -> bool {
        !self.teid_present && !self.ipv4_present && !self.ipv6_present
    }
}

// ============================================================================
// Bearer QoS Structure
// ============================================================================

/// Bearer QoS parameters
#[derive(Debug, Clone, Default)]
pub struct BearerQos {
    /// Pre-emption Capability (1 bit)
    pub pre_emption_capability: bool,
    /// Priority Level (4 bits)
    pub priority_level: u8,
    /// Pre-emption Vulnerability (1 bit)
    pub pre_emption_vulnerability: bool,
    /// QCI (QoS Class Identifier)
    pub qci: u8,
    /// Maximum Bit Rate Uplink (5 bytes, kbit/s: TS 29.274 §8.15)
    pub ul_mbr: u64,
    /// Maximum Bit Rate Downlink (5 bytes, kbit/s)
    pub dl_mbr: u64,
    /// Guaranteed Bit Rate Uplink (5 bytes, kbit/s)
    pub ul_gbr: u64,
    /// Guaranteed Bit Rate Downlink (5 bytes, kbit/s)
    pub dl_gbr: u64,
}

/// The largest rate a 5-octet GTPv2 Bearer or Flow QoS field holds, in kbit/s.
const GTP2_MAX_KBPS: u64 = 0xFF_FFFF_FFFF;

/// A GTPv2 Bearer/Flow QoS rate (kbit/s, TS 29.274 §8.15, §8.16) in the bit/s that
/// `context::Qos` holds everywhere else: on N4 (QER MBR/GBR), on N2 and in the
/// EPS→5GS mapping (#1165).
pub(crate) fn gtp2_kbps_to_bps(kbps: u64) -> u64 {
    kbps.saturating_mul(1000)
}

/// A `context::Qos` rate (bit/s) as a GTPv2 Bearer QoS field (kbit/s), rounded up so
/// that a non-zero rate never goes out as 0, and capped at the field's 5 octets
/// (#1165).
pub(crate) fn gtp2_bps_to_kbps(bps: u64) -> u64 {
    bps.div_ceil(1000).min(GTP2_MAX_KBPS)
}

/// Bearer QoS encoded length
pub const BEARER_QOS_LEN: usize = 22;

impl BearerQos {
    /// Create new Bearer QoS
    pub fn new(qci: u8, priority_level: u8) -> Self {
        Self {
            pre_emption_capability: false,
            priority_level,
            pre_emption_vulnerability: false,
            qci,
            ul_mbr: 0,
            dl_mbr: 0,
            ul_gbr: 0,
            dl_gbr: 0,
        }
    }

    /// The Bearer QoS IE of a bearer whose QoS this node holds in bit/s (#1165).
    pub(crate) fn from_qos(qos: &Qos) -> Self {
        Self {
            qci: qos.index,
            priority_level: qos.arp_priority_level,
            pre_emption_capability: qos.arp_preempt_cap,
            pre_emption_vulnerability: qos.arp_preempt_vuln,
            ul_mbr: gtp2_bps_to_kbps(qos.mbr_uplink),
            dl_mbr: gtp2_bps_to_kbps(qos.mbr_downlink),
            ul_gbr: gtp2_bps_to_kbps(qos.gbr_uplink),
            dl_gbr: gtp2_bps_to_kbps(qos.gbr_downlink),
        }
    }

    /// This Bearer QoS IE as the bit/s `context::Qos` the bearer stores (#1165).
    pub(crate) fn to_qos(&self) -> Qos {
        Qos {
            index: self.qci,
            arp_priority_level: self.priority_level,
            arp_preempt_cap: self.pre_emption_capability,
            arp_preempt_vuln: self.pre_emption_vulnerability,
            mbr_uplink: gtp2_kbps_to_bps(self.ul_mbr),
            mbr_downlink: gtp2_kbps_to_bps(self.dl_mbr),
            gbr_uplink: gtp2_kbps_to_bps(self.ul_gbr),
            gbr_downlink: gtp2_kbps_to_bps(self.dl_gbr),
        }
    }

    /// Encode Bearer QoS to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(BEARER_QOS_LEN);

        // First byte: spare(1) | PCI(1) | PL(4) | spare(1) | PVI(1)
        let mut flags: u8 = 0;
        if self.pre_emption_capability {
            flags |= 0x40;
        }
        flags |= (self.priority_level & 0x0f) << 2;
        if self.pre_emption_vulnerability {
            flags |= 0x01;
        }
        buf.put_u8(flags);

        // QCI (1 byte)
        buf.put_u8(self.qci);

        // MBR Uplink (5 bytes)
        buf.put_u8(((self.ul_mbr >> 32) & 0xff) as u8);
        buf.put_u32((self.ul_mbr & 0xffffffff) as u32);

        // MBR Downlink (5 bytes)
        buf.put_u8(((self.dl_mbr >> 32) & 0xff) as u8);
        buf.put_u32((self.dl_mbr & 0xffffffff) as u32);

        // GBR Uplink (5 bytes)
        buf.put_u8(((self.ul_gbr >> 32) & 0xff) as u8);
        buf.put_u32((self.ul_gbr & 0xffffffff) as u32);

        // GBR Downlink (5 bytes)
        buf.put_u8(((self.dl_gbr >> 32) & 0xff) as u8);
        buf.put_u32((self.dl_gbr & 0xffffffff) as u32);

        buf.to_vec()
    }

    /// Parse Bearer QoS from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < BEARER_QOS_LEN {
            return None;
        }

        let flags = data[0];
        let pre_emption_capability = (flags & 0x40) != 0;
        let priority_level = (flags >> 2) & 0x0f;
        let pre_emption_vulnerability = (flags & 0x01) != 0;
        let qci = data[1];

        let ul_mbr = ((data[2] as u64) << 32)
            | ((data[3] as u64) << 24)
            | ((data[4] as u64) << 16)
            | ((data[5] as u64) << 8)
            | (data[6] as u64);

        let dl_mbr = ((data[7] as u64) << 32)
            | ((data[8] as u64) << 24)
            | ((data[9] as u64) << 16)
            | ((data[10] as u64) << 8)
            | (data[11] as u64);

        let ul_gbr = ((data[12] as u64) << 32)
            | ((data[13] as u64) << 24)
            | ((data[14] as u64) << 16)
            | ((data[15] as u64) << 8)
            | (data[16] as u64);

        let dl_gbr = ((data[17] as u64) << 32)
            | ((data[18] as u64) << 24)
            | ((data[19] as u64) << 16)
            | ((data[20] as u64) << 8)
            | (data[21] as u64);

        Some(Self {
            pre_emption_capability,
            priority_level,
            pre_emption_vulnerability,
            qci,
            ul_mbr,
            dl_mbr,
            ul_gbr,
            dl_gbr,
        })
    }
}

// ============================================================================
// AMBR Structure
// ============================================================================

/// Aggregate Maximum Bit Rate
#[derive(Debug, Clone, Default)]
pub struct Ambr {
    /// Uplink AMBR (kbps)
    pub uplink: u32,
    /// Downlink AMBR (kbps)
    pub downlink: u32,
}

impl Ambr {
    /// Create new AMBR from bps values (converts to kbps)
    pub fn from_bps(uplink_bps: u64, downlink_bps: u64) -> Self {
        Self {
            uplink: (uplink_bps / 1000) as u32,
            downlink: (downlink_bps / 1000) as u32,
        }
    }

    /// Encode AMBR to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(8);
        buf.put_u32(self.uplink);
        buf.put_u32(self.downlink);
        buf.to_vec()
    }
}

// ============================================================================
// PAA (PDN Address Allocation) Structure
// ============================================================================

/// PDN Type values
pub mod pdn_type {
    pub const IPV4: u8 = 1;
    pub const IPV6: u8 = 2;
    pub const IPV4V6: u8 = 3;
    pub const NON_IP: u8 = 4;
    pub const ETHERNET: u8 = 5;
}

/// PDN Address Allocation
#[derive(Debug, Clone, Default)]
pub struct Paa {
    /// PDN Type
    pub pdn_type: u8,
    /// IPv4 address
    pub ipv4_addr: Option<Ipv4Addr>,
    /// IPv6 prefix length
    pub ipv6_prefix_len: u8,
    /// IPv6 address
    pub ipv6_addr: Option<Ipv6Addr>,
}

/// PAA IPv4 length
pub const PAA_IPV4_LEN: usize = 5;
/// PAA IPv6 length
pub const PAA_IPV6_LEN: usize = 18;
/// PAA IPv4v6 length
pub const PAA_IPV4V6_LEN: usize = 22;

impl Paa {
    /// Create IPv4 PAA
    pub fn ipv4(addr: Ipv4Addr) -> Self {
        Self {
            pdn_type: pdn_type::IPV4,
            ipv4_addr: Some(addr),
            ipv6_prefix_len: 0,
            ipv6_addr: None,
        }
    }

    /// Create IPv6 PAA
    pub fn ipv6(prefix_len: u8, addr: Ipv6Addr) -> Self {
        Self {
            pdn_type: pdn_type::IPV6,
            ipv4_addr: None,
            ipv6_prefix_len: prefix_len,
            ipv6_addr: Some(addr),
        }
    }

    /// Create IPv4v6 PAA
    pub fn ipv4v6(ipv4: Ipv4Addr, prefix_len: u8, ipv6: Ipv6Addr) -> Self {
        Self {
            pdn_type: pdn_type::IPV4V6,
            ipv4_addr: Some(ipv4),
            ipv6_prefix_len: prefix_len,
            ipv6_addr: Some(ipv6),
        }
    }

    /// Encode PAA to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(PAA_IPV4V6_LEN);
        buf.put_u8(self.pdn_type);

        match self.pdn_type {
            pdn_type::IPV4 => {
                if let Some(addr) = self.ipv4_addr {
                    buf.put_slice(&addr.octets());
                }
            }
            pdn_type::IPV6 => {
                buf.put_u8(self.ipv6_prefix_len);
                if let Some(addr) = self.ipv6_addr {
                    buf.put_slice(&addr.octets());
                }
            }
            pdn_type::IPV4V6 => {
                buf.put_u8(self.ipv6_prefix_len);
                if let Some(addr) = self.ipv6_addr {
                    buf.put_slice(&addr.octets());
                }
                if let Some(addr) = self.ipv4_addr {
                    buf.put_slice(&addr.octets());
                }
            }
            _ => {}
        }

        buf.to_vec()
    }

    /// Get encoded length
    pub fn len(&self) -> usize {
        match self.pdn_type {
            pdn_type::IPV4 => PAA_IPV4_LEN,
            pdn_type::IPV6 => PAA_IPV6_LEN,
            pdn_type::IPV4V6 => PAA_IPV4V6_LEN,
            _ => 1,
        }
    }

    /// Check if PAA is empty
    pub fn is_empty(&self) -> bool {
        self.pdn_type == 0
    }
}

// ============================================================================
// GTPv2-C Message Builder
// ============================================================================

/// GTPv2-C Message Builder
#[derive(Debug, Clone, Default)]
pub struct Gtp2MessageBuilder {
    /// Message type
    message_type: u8,
    /// TEID
    teid: u32,
    /// Sequence number
    sequence: u32,
    /// IEs buffer
    ies: BytesMut,
}

impl Gtp2MessageBuilder {
    /// Create a new GTPv2-C message builder
    pub fn new(message_type: u8) -> Self {
        Self {
            message_type,
            teid: 0,
            sequence: 0,
            ies: BytesMut::with_capacity(1024),
        }
    }

    /// Set TEID
    pub fn teid(mut self, teid: u32) -> Self {
        self.teid = teid;
        self
    }

    /// Set sequence number
    pub fn sequence(mut self, seq: u32) -> Self {
        self.sequence = seq;
        self
    }

    /// Add Cause IE
    pub fn add_cause(mut self, cause: Gtp2Cause) -> Self {
        self.add_ie(gtp2_ie_type::CAUSE, 0, &[cause as u8, 0]);
        self
    }

    /// Add Cause IE with raw value
    pub fn add_cause_raw(mut self, cause: u8) -> Self {
        self.add_ie(gtp2_ie_type::CAUSE, 0, &[cause, 0]);
        self
    }

    /// Add EBI (EPS Bearer ID) IE
    pub fn add_ebi(mut self, ebi: u8, instance: u8) -> Self {
        self.add_ie(gtp2_ie_type::EBI, instance, &[ebi & 0x0f]);
        self
    }

    /// Add F-TEID IE
    pub fn add_f_teid(mut self, f_teid: &FTeid, instance: u8) -> Self {
        self.add_ie(gtp2_ie_type::F_TEID, instance, &f_teid.encode());
        self
    }

    /// Add PAA IE
    pub fn add_paa(mut self, paa: &Paa) -> Self {
        self.add_ie(gtp2_ie_type::PAA, 0, &paa.encode());
        self
    }

    /// Add APN Restriction IE
    pub fn add_apn_restriction(mut self, restriction: u8) -> Self {
        self.add_ie(gtp2_ie_type::APN_RESTRICTION, 0, &[restriction]);
        self
    }

    /// Add AMBR IE
    pub fn add_ambr(mut self, ambr: &Ambr) -> Self {
        self.add_ie(gtp2_ie_type::AMBR, 0, &ambr.encode());
        self
    }

    /// Add Bearer QoS IE
    pub fn add_bearer_qos(mut self, qos: &BearerQos, instance: u8) -> Self {
        self.add_ie(gtp2_ie_type::BEARER_QOS, instance, &qos.encode());
        self
    }

    /// Add Charging ID IE
    pub fn add_charging_id(mut self, charging_id: u32) -> Self {
        let mut buf = [0u8; 4];
        buf[0] = ((charging_id >> 24) & 0xff) as u8;
        buf[1] = ((charging_id >> 16) & 0xff) as u8;
        buf[2] = ((charging_id >> 8) & 0xff) as u8;
        buf[3] = (charging_id & 0xff) as u8;
        self.add_ie(gtp2_ie_type::CHARGING_ID, 0, &buf);
        self
    }

    /// Add PTI (Procedure Transaction ID) IE
    pub fn add_pti(mut self, pti: u8) -> Self {
        self.add_ie(gtp2_ie_type::PTI, 0, &[pti]);
        self
    }

    /// Add PCO (Protocol Configuration Options) IE
    pub fn add_pco(mut self, pco: &[u8]) -> Self {
        self.add_ie(gtp2_ie_type::PCO, 0, pco);
        self
    }

    /// Add APCO (Additional Protocol Configuration Options) IE
    pub fn add_apco(mut self, apco: &[u8]) -> Self {
        self.add_ie(gtp2_ie_type::APCO, 0, apco);
        self
    }

    /// Add ePCO (Extended Protocol Configuration Options) IE
    pub fn add_epco(mut self, epco: &[u8]) -> Self {
        self.add_ie(gtp2_ie_type::EPCO, 0, epco);
        self
    }

    /// Add MSISDN IE
    pub fn add_msisdn(mut self, msisdn: &[u8]) -> Self {
        self.add_ie(gtp2_ie_type::MSISDN, 0, msisdn);
        self
    }

    /// Add raw IE
    fn add_ie(&mut self, ie_type: u8, instance: u8, data: &[u8]) {
        // IE Type (1 byte)
        self.ies.put_u8(ie_type);
        // IE Length (2 bytes)
        self.ies.put_u16(data.len() as u16);
        // Spare (4 bits) + Instance (4 bits)
        self.ies.put_u8(instance & 0x0f);
        // IE Data
        self.ies.put_slice(data);
    }

    /// Start a grouped IE (Bearer Context)
    pub fn start_bearer_context(self, instance: u8) -> BearerContextBuilder {
        BearerContextBuilder {
            parent: self,
            instance,
            ies: BytesMut::with_capacity(256),
        }
    }

    /// Build the GTPv2-C message
    pub fn build(self) -> Vec<u8> {
        let ie_len = self.ies.len();
        let msg_len = ie_len + 8; // 8 = TEID(4) + Seq(3) + Spare(1)

        let mut buf = BytesMut::with_capacity(12 + ie_len);

        // Version (3 bits) = 2, P (1 bit) = 0, T (1 bit) = 1, Spare (3 bits) = 0
        // = 0b01001000 = 0x48
        buf.put_u8(0x48);

        // Message Type
        buf.put_u8(self.message_type);

        // Message Length (excluding first 4 bytes)
        buf.put_u16(msg_len as u16);

        // TEID
        buf.put_u32(self.teid);

        // Sequence Number (3 bytes)
        buf.put_u8(((self.sequence >> 16) & 0xff) as u8);
        buf.put_u8(((self.sequence >> 8) & 0xff) as u8);
        buf.put_u8((self.sequence & 0xff) as u8);

        // Spare
        buf.put_u8(0);

        // IEs
        buf.put_slice(&self.ies);

        buf.to_vec()
    }
}

// ============================================================================
// Bearer Context Builder
// ============================================================================

/// Bearer Context Builder for grouped IEs
pub struct BearerContextBuilder {
    parent: Gtp2MessageBuilder,
    instance: u8,
    ies: BytesMut,
}

impl BearerContextBuilder {
    /// Add EBI to bearer context
    pub fn add_ebi(mut self, ebi: u8) -> Self {
        self.add_ie(gtp2_ie_type::EBI, 0, &[ebi & 0x0f]);
        self
    }

    /// Add Cause to bearer context
    pub fn add_cause(mut self, cause: Gtp2Cause) -> Self {
        self.add_ie(gtp2_ie_type::CAUSE, 0, &[cause as u8, 0]);
        self
    }

    /// Add Cause with raw value to bearer context
    pub fn add_cause_raw(mut self, cause: u8) -> Self {
        self.add_ie(gtp2_ie_type::CAUSE, 0, &[cause, 0]);
        self
    }

    /// Add F-TEID to bearer context
    pub fn add_f_teid(mut self, f_teid: &FTeid, instance: u8) -> Self {
        self.add_ie(gtp2_ie_type::F_TEID, instance, &f_teid.encode());
        self
    }

    /// Add Bearer QoS to bearer context
    pub fn add_bearer_qos(mut self, qos: &BearerQos) -> Self {
        self.add_ie(gtp2_ie_type::BEARER_QOS, 0, &qos.encode());
        self
    }

    /// Add Charging ID to bearer context
    pub fn add_charging_id(mut self, charging_id: u32) -> Self {
        let mut buf = [0u8; 4];
        buf[0] = ((charging_id >> 24) & 0xff) as u8;
        buf[1] = ((charging_id >> 16) & 0xff) as u8;
        buf[2] = ((charging_id >> 8) & 0xff) as u8;
        buf[3] = (charging_id & 0xff) as u8;
        self.add_ie(gtp2_ie_type::CHARGING_ID, 0, &buf);
        self
    }

    /// Add TFT to bearer context
    pub fn add_tft(mut self, tft: &[u8]) -> Self {
        self.add_ie(gtp2_ie_type::BEARER_TFT, 0, tft);
        self
    }

    /// Add raw IE to bearer context
    fn add_ie(&mut self, ie_type: u8, instance: u8, data: &[u8]) {
        self.ies.put_u8(ie_type);
        self.ies.put_u16(data.len() as u16);
        self.ies.put_u8(instance & 0x0f);
        self.ies.put_slice(data);
    }

    /// End bearer context and return to parent builder
    pub fn end(mut self) -> Gtp2MessageBuilder {
        // Add the bearer context as a grouped IE to parent
        self.parent
            .add_ie(gtp2_ie_type::BEARER_CONTEXT, self.instance, &self.ies);
        self.parent
    }
}

// ============================================================================
// High-Level Message Building Functions
// ============================================================================

use crate::context::{PduSessionType, Qos, SmfBearer, SmfSess};

/// IE instances of the Create Session Response, TS 29.274 Tables 7.2.2-1 and 7.2.2-2.
pub mod csr_instance {
    /// "PGW S5/S8/S2a/S2b F-TEID for PMIP based interface or for GTP based Control
    /// Plane interface" (Table 7.2.2-1).
    pub const PGW_CONTROL_F_TEID: u8 = 1;
    /// "S5/S8-U PGW F-TEID" in Bearer Context created (Table 7.2.2-2).
    pub const BC_S5_S8_U_PGW_F_TEID: u8 = 2;
    /// "S2b-U PGW F-TEID" in Bearer Context created (Table 7.2.2-2).
    pub const BC_S2B_U_PGW_F_TEID: u8 = 4;
}

/// IE instances in the Bearer Context of a Create Bearer Request, TS 29.274
/// Table 7.2.3-2. Instance 0 is the S1-U SGW F-TEID, which only an SGW writes.
pub mod cbr_instance {
    /// "S5/S8-U PGW F-TEID".
    pub const BC_S5_S8_U_PGW_F_TEID: u8 = 1;
    /// "S2b-U PGW F-TEID".
    pub const BC_S2B_U_PGW_F_TEID: u8 = 4;
}

/// Build Create Session Response message
/// Port of smf_s5c_build_create_session_response
pub fn build_create_session_response(
    sess: &SmfSess,
    bearers: &[SmfBearer],
    smf_addr: Option<Ipv4Addr>,
    smf_addr6: Option<Ipv6Addr>,
    pco: Option<&[u8]>,
    apco: Option<&[u8]>,
    epco: Option<&[u8]>,
    include_ambr: bool,
    include_bearer_qos: bool,
) -> Vec<u8> {
    let mut builder =
        Gtp2MessageBuilder::new(gtp2_message_type::CREATE_SESSION_RESPONSE).teid(sess.sgw_s5c_teid);

    // Cause
    let cause = if sess.ue_session_type != sess.session_type as u8 {
        Gtp2Cause::NewPdnTypeDueToNetworkPreference
    } else {
        Gtp2Cause::RequestAccepted
    };
    builder = builder.add_cause(cause);

    // The PGW's own control-plane F-TEID, "PGW S5/S8/S2a/S2b F-TEID for PMIP based
    // interface or for GTP based Control Plane interface", is instance 1 of TS 29.274
    // Table 7.2.2-1. Instance 0 is the "Sender F-TEID for Control Plane", which is sent
    // on S11/S4 only ("For the S5/S8/S2a/S2b interfaces it is not needed"), so a PGW
    // sends no instance-0 F-TEID at all. It was written at instance 0, where the SGW-C
    // reading instance 1 found nothing, stored PGW S5-C TEID 0 and relayed no Delete
    // Session: the PGW session leaked on every detach (#1113).
    let interface_type = match sess.gtp_rat_type {
        gtp2_rat_type::EUTRAN => gtp2_f_teid_interface::S5_S8_PGW_GTP_C,
        gtp2_rat_type::WLAN => gtp2_f_teid_interface::S2B_PGW_GTP_C,
        _ => gtp2_f_teid_interface::S5_S8_PGW_GTP_C,
    };

    if let Some(addr) = smf_addr {
        let f_teid = FTeid::new_ipv4(interface_type, sess.smf_n4_teid, addr);
        builder = builder.add_f_teid(&f_teid, csr_instance::PGW_CONTROL_F_TEID);
    } else if let Some(addr) = smf_addr6 {
        let f_teid = FTeid::new_ipv6(interface_type, sess.smf_n4_teid, addr);
        builder = builder.add_f_teid(&f_teid, csr_instance::PGW_CONTROL_F_TEID);
    }

    // PAA (PDN Address Allocation)
    let paa = match sess.session_type {
        PduSessionType::Ipv4 => {
            if let Some(addr) = sess.ipv4_addr {
                Paa::ipv4(addr)
            } else {
                Paa::ipv4(Ipv4Addr::UNSPECIFIED)
            }
        }
        PduSessionType::Ipv6 => {
            if let Some((prefix_len, addr)) = sess.ipv6_prefix {
                Paa::ipv6(prefix_len, addr)
            } else {
                Paa::ipv6(64, Ipv6Addr::UNSPECIFIED)
            }
        }
        PduSessionType::Ipv4v6 => {
            let ipv4 = sess.ipv4_addr.unwrap_or(Ipv4Addr::UNSPECIFIED);
            let (prefix_len, ipv6) = sess.ipv6_prefix.unwrap_or((64, Ipv6Addr::UNSPECIFIED));
            Paa::ipv4v6(ipv4, prefix_len, ipv6)
        }
        _ => Paa::ipv4(Ipv4Addr::UNSPECIFIED),
    };
    builder = builder.add_paa(&paa);

    // APN Restriction (only for E-UTRAN)
    if sess.gtp_rat_type == gtp2_rat_type::EUTRAN {
        builder = builder.add_apn_restriction(gtp2_apn_restriction::NO_RESTRICTION);
    }

    // AMBR
    if include_ambr && (sess.session_ambr.uplink > 0 || sess.session_ambr.downlink > 0) {
        let ambr = Ambr::from_bps(sess.session_ambr.uplink, sess.session_ambr.downlink);
        builder = builder.add_ambr(&ambr);
    }

    // PCO
    if let Some(pco_data) = pco {
        builder = builder.add_pco(pco_data);
    }

    // APCO
    if let Some(apco_data) = apco {
        builder = builder.add_apco(apco_data);
    }

    // ePCO
    if let Some(epco_data) = epco {
        builder = builder.add_epco(epco_data);
    }

    // Bearer Contexts Created
    for bearer in bearers {
        let bearer_f_teid_interface = match sess.gtp_rat_type {
            gtp2_rat_type::EUTRAN => gtp2_f_teid_interface::S5_S8_PGW_GTP_U,
            gtp2_rat_type::WLAN => gtp2_f_teid_interface::S2B_U_PGW_GTP_U,
            _ => gtp2_f_teid_interface::S5_S8_PGW_GTP_U,
        };

        let mut bc_builder = builder
            .start_bearer_context(0)
            .add_ebi(bearer.ebi)
            .add_cause(Gtp2Cause::RequestAccepted);

        // Bearer QoS
        if include_bearer_qos {
            // #1165: held in bit/s, coded in kbit/s (TS 29.274 §8.15).
            bc_builder = bc_builder.add_bearer_qos(&BearerQos::from_qos(&bearer.qos));
        }

        // Charging ID
        bc_builder = bc_builder.add_charging_id(sess.charging.id);

        // PGW user-plane F-TEID, at the instance TS 29.274 Table 7.2.2-2 assigns its
        // interface: S5/S8-U PGW is instance 2 and S2b-U PGW instance 4. Instance 0 is
        // the S1-U SGW F-TEID's slot, which is where this used to be written -- so an
        // SGW-C reading instance 2 (as sgwcd does, per the table) found no PGW-U
        // endpoint and provisioned an uplink that forwarded nowhere (#303).
        let pgw_u_instance = match sess.gtp_rat_type {
            gtp2_rat_type::WLAN => csr_instance::BC_S2B_U_PGW_F_TEID,
            _ => csr_instance::BC_S5_S8_U_PGW_F_TEID,
        };
        if let Some(addr) = bearer.pgw_s5u_addr {
            let f_teid = FTeid::new_ipv4(bearer_f_teid_interface, bearer.pgw_s5u_teid, addr);
            bc_builder = bc_builder.add_f_teid(&f_teid, pgw_u_instance);
        } else if let Some(addr) = bearer.pgw_s5u_addr6 {
            let f_teid = FTeid::new_ipv6(bearer_f_teid_interface, bearer.pgw_s5u_teid, addr);
            bc_builder = bc_builder.add_f_teid(&f_teid, pgw_u_instance);
        }

        builder = bc_builder.end();
    }

    builder.build()
}

/// Build Delete Session Response message
/// Port of smf_s5c_build_delete_session_response
pub fn build_delete_session_response(
    teid: u32,
    pco: Option<&[u8]>,
    epco: Option<&[u8]>,
) -> Vec<u8> {
    let mut builder = Gtp2MessageBuilder::new(gtp2_message_type::DELETE_SESSION_RESPONSE)
        .teid(teid)
        .add_cause(Gtp2Cause::RequestAccepted);

    // PCO
    if let Some(pco_data) = pco {
        builder = builder.add_pco(pco_data);
    }

    // ePCO
    if let Some(epco_data) = epco {
        builder = builder.add_epco(epco_data);
    }

    builder.build()
}

/// Build Modify Bearer Response message
/// Port of smf_s5c_build_modify_bearer_response
pub fn build_modify_bearer_response(
    sess: &SmfSess,
    bearers: &[SmfBearer],
    msisdn: Option<&[u8]>,
    sgw_relocation: bool,
) -> Vec<u8> {
    let mut builder = Gtp2MessageBuilder::new(gtp2_message_type::MODIFY_BEARER_RESPONSE)
        .teid(sess.sgw_s5c_teid)
        .add_cause(Gtp2Cause::RequestAccepted);

    if sgw_relocation {
        // Add MSISDN if present
        if let Some(msisdn_data) = msisdn {
            builder = builder.add_msisdn(msisdn_data);
        }

        // Bearer Contexts modified (instance 0). Cause is mandatory in each one
        // (TS 29.274 Table 7.2.8-2), and was missing (#1113 audit).
        for bearer in bearers {
            let bc_builder = builder
                .start_bearer_context(0)
                .add_ebi(bearer.ebi)
                .add_cause(Gtp2Cause::RequestAccepted)
                .add_charging_id(sess.charging.id);
            builder = bc_builder.end();
        }
    }

    builder.build()
}

/// Build Create Bearer Request message
/// Port of smf_s5c_build_create_bearer_request
pub fn build_create_bearer_request(
    sess: &SmfSess,
    bearer: &SmfBearer,
    linked_ebi: u8,
    tft: &[u8],
    pti: Option<u8>,
) -> Vec<u8> {
    let mut builder =
        Gtp2MessageBuilder::new(gtp2_message_type::CREATE_BEARER_REQUEST).teid(sess.sgw_s5c_teid);
    // TS 29.274 Table 7.2.3-1: the PTI is present when the procedure answers a UE's
    // Bearer Resource Command (TS 23.401 §5.4.5), so the UE can correlate the activation
    // with its own request.
    if let Some(pti) = pti {
        builder = builder.add_pti(pti);
    }
    builder = builder.add_ebi(linked_ebi, 0); // Linked EPS Bearer ID

    // Bearer Context
    let bearer_f_teid_interface = match sess.gtp_rat_type {
        gtp2_rat_type::EUTRAN => gtp2_f_teid_interface::S5_S8_PGW_GTP_U,
        gtp2_rat_type::WLAN => gtp2_f_teid_interface::S2B_U_PGW_GTP_U,
        _ => gtp2_f_teid_interface::S5_S8_PGW_GTP_U,
    };
    // #619: the bearer's rates are held in bit/s, as the 5GC flows' are and as N4 and
    // the EPS→5GS mapping (#583) read them; TS 29.274 §8.15 codes them in kbit/s.
    let bearer_qos = BearerQos::from_qos(&bearer.qos);

    // TS 29.274 §7.2.3: the EBI of a bearer to be created is set to 0 by the PGW. The
    // MME assigns it and returns it in the Create Bearer Response. Table 7.2.3-2: the
    // TFT is mandatory, and so is the Charging Id on S5/S8 ("shall be sent on the
    // S5/S8 interface"); neither was (#1113 review).
    let mut bc_builder = builder
        .start_bearer_context(0)
        .add_ebi(bearer.ebi)
        .add_tft(tft);

    // The PGW user-plane F-TEID, at its Table 7.2.3-2 instance: 1 for S5/S8-U and 4
    // for S2b-U. It was written at instance 0, the S1-U SGW F-TEID's slot (#1113).
    let pgw_u_instance = match sess.gtp_rat_type {
        gtp2_rat_type::WLAN => cbr_instance::BC_S2B_U_PGW_F_TEID,
        _ => cbr_instance::BC_S5_S8_U_PGW_F_TEID,
    };
    if let Some(addr) = bearer.pgw_s5u_addr {
        let f_teid = FTeid::new_ipv4(bearer_f_teid_interface, bearer.pgw_s5u_teid, addr);
        bc_builder = bc_builder.add_f_teid(&f_teid, pgw_u_instance);
    } else if let Some(addr) = bearer.pgw_s5u_addr6 {
        let f_teid = FTeid::new_ipv6(bearer_f_teid_interface, bearer.pgw_s5u_teid, addr);
        bc_builder = bc_builder.add_f_teid(&f_teid, pgw_u_instance);
    }

    bc_builder = bc_builder
        .add_bearer_qos(&bearer_qos)
        .add_charging_id(sess.charging.id);

    builder = bc_builder.end();
    builder.build()
}

/// Build Update Bearer Request message
/// Port of smf_s5c_build_update_bearer_request
pub fn build_update_bearer_request(
    sess: &SmfSess,
    bearer: &SmfBearer,
    pti: Option<u8>,
    tft: Option<&[u8]>,
    include_qos: bool,
) -> Vec<u8> {
    let mut builder =
        Gtp2MessageBuilder::new(gtp2_message_type::UPDATE_BEARER_REQUEST).teid(sess.sgw_s5c_teid);

    // APN-AMBR: M in TS 29.274 Table 7.2.15-1 (#619). It was sent only when non-zero,
    // and an MME answers a request without it with cause 70 and Offending IE 72.
    let ambr = Ambr::from_bps(sess.session_ambr.uplink, sess.session_ambr.downlink);
    builder = builder.add_ambr(&ambr);

    // PTI
    if let Some(pti_val) = pti {
        builder = builder.add_pti(pti_val);
    }

    // Bearer Context
    let mut bc_builder = builder.start_bearer_context(0).add_ebi(bearer.ebi);

    // Bearer QoS
    if include_qos {
        // #1165: held in bit/s, coded in kbit/s (TS 29.274 §8.15).
        bc_builder = bc_builder.add_bearer_qos(&BearerQos::from_qos(&bearer.qos));
    }

    // TFT
    if let Some(tft_data) = tft {
        bc_builder = bc_builder.add_tft(tft_data);
    }

    builder = bc_builder.end();
    builder.build()
}

/// Build Delete Bearer Request message
/// Port of smf_s5c_build_delete_bearer_request
pub fn build_delete_bearer_request(
    sess: &SmfSess,
    bearer_ebi: u8,
    linked_ebi: u8,
    pti: Option<u8>,
    cause: Option<Gtp2Cause>,
) -> Vec<u8> {
    let mut builder =
        Gtp2MessageBuilder::new(gtp2_message_type::DELETE_BEARER_REQUEST).teid(sess.sgw_s5c_teid);

    if bearer_ebi == linked_ebi {
        // Default bearer - use Linked EPS Bearer ID
        builder = builder.add_ebi(bearer_ebi, 0);
    } else {
        // Dedicated bearer - use EPS Bearer IDs (instance 1, TS 29.274 Table 7.2.9.2-1)
        builder = builder.add_ebi(bearer_ebi, 1);
    }

    // PTI
    if let Some(pti_val) = pti {
        builder = builder.add_pti(pti_val);
    }

    // Cause
    if let Some(cause_val) = cause {
        builder = builder.add_cause(cause_val);
    }

    builder.build()
}

/// Build error message response
pub fn build_error_message(message_type: u8, teid: u32, cause: Gtp2Cause) -> Vec<u8> {
    Gtp2MessageBuilder::new(message_type)
        .teid(teid)
        .add_cause(cause)
        .build()
}

/// Build Echo Response message
pub fn build_echo_response(recovery: u8) -> Vec<u8> {
    let mut builder = Gtp2MessageBuilder::new(gtp2_message_type::ECHO_RESPONSE);
    // Add recovery IE
    builder.add_ie(gtp2_ie_type::RECOVERY, 0, &[recovery]);
    builder.build()
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_f_teid_ipv4() {
        let f_teid = FTeid::new_ipv4(
            gtp2_f_teid_interface::S5_S8_PGW_GTP_C,
            0x12345678,
            Ipv4Addr::new(192, 168, 1, 1),
        );

        assert_eq!(
            f_teid.interface_type,
            gtp2_f_teid_interface::S5_S8_PGW_GTP_C
        );
        assert!(f_teid.teid_present);
        assert!(f_teid.ipv4_present);
        assert!(!f_teid.ipv6_present);
        assert_eq!(f_teid.teid, 0x12345678);
        assert_eq!(f_teid.ipv4_addr, Some(Ipv4Addr::new(192, 168, 1, 1)));

        let encoded = f_teid.encode();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_f_teid_ipv6() {
        let f_teid = FTeid::new_ipv6(
            gtp2_f_teid_interface::S5_S8_PGW_GTP_U,
            0xabcdef00,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        );

        assert!(f_teid.ipv6_present);
        assert!(!f_teid.ipv4_present);
        assert_eq!(f_teid.teid, 0xabcdef00);
    }

    #[test]
    fn test_bearer_qos_encode_decode() {
        let qos = BearerQos {
            pre_emption_capability: true,
            priority_level: 5,
            pre_emption_vulnerability: false,
            qci: 9,
            ul_mbr: 100000,
            dl_mbr: 200000,
            ul_gbr: 50000,
            dl_gbr: 100000,
        };

        let encoded = qos.encode();
        assert_eq!(encoded.len(), BEARER_QOS_LEN);

        let decoded = BearerQos::parse(&encoded).unwrap();
        assert_eq!(decoded.pre_emption_capability, qos.pre_emption_capability);
        assert_eq!(decoded.priority_level, qos.priority_level);
        assert_eq!(
            decoded.pre_emption_vulnerability,
            qos.pre_emption_vulnerability
        );
        assert_eq!(decoded.qci, qos.qci);
        assert_eq!(decoded.ul_mbr, qos.ul_mbr);
        assert_eq!(decoded.dl_mbr, qos.dl_mbr);
        assert_eq!(decoded.ul_gbr, qos.ul_gbr);
        assert_eq!(decoded.dl_gbr, qos.dl_gbr);
    }

    #[test]
    fn test_ambr() {
        let ambr = Ambr::from_bps(100_000_000, 50_000_000);
        assert_eq!(ambr.uplink, 100_000);
        assert_eq!(ambr.downlink, 50_000);

        let encoded = ambr.encode();
        assert_eq!(encoded.len(), 8);
    }

    #[test]
    fn test_paa_ipv4() {
        let paa = Paa::ipv4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(paa.pdn_type, pdn_type::IPV4);
        assert_eq!(paa.len(), PAA_IPV4_LEN);

        let encoded = paa.encode();
        assert_eq!(encoded.len(), PAA_IPV4_LEN);
        assert_eq!(encoded[0], pdn_type::IPV4);
    }

    #[test]
    fn test_paa_ipv6() {
        let paa = Paa::ipv6(64, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(paa.pdn_type, pdn_type::IPV6);
        assert_eq!(paa.len(), PAA_IPV6_LEN);
    }

    #[test]
    fn test_paa_ipv4v6() {
        let paa = Paa::ipv4v6(
            Ipv4Addr::new(10, 0, 0, 1),
            64,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        );
        assert_eq!(paa.pdn_type, pdn_type::IPV4V6);
        assert_eq!(paa.len(), PAA_IPV4V6_LEN);
    }

    #[test]
    fn test_gtp2_message_builder() {
        let msg = Gtp2MessageBuilder::new(gtp2_message_type::CREATE_SESSION_RESPONSE)
            .teid(0x12345678)
            .sequence(1)
            .add_cause(Gtp2Cause::RequestAccepted)
            .build();

        // Check header
        assert_eq!(msg[0], 0x48); // Version 2, T=1
        assert_eq!(msg[1], gtp2_message_type::CREATE_SESSION_RESPONSE);
        // TEID at bytes 4-7
        assert_eq!(msg[4], 0x12);
        assert_eq!(msg[5], 0x34);
        assert_eq!(msg[6], 0x56);
        assert_eq!(msg[7], 0x78);
    }

    #[test]
    fn test_bearer_context_builder() {
        let msg = Gtp2MessageBuilder::new(gtp2_message_type::CREATE_SESSION_RESPONSE)
            .teid(0x12345678)
            .start_bearer_context(0)
            .add_ebi(5)
            .add_cause(Gtp2Cause::RequestAccepted)
            .end()
            .build();

        assert!(!msg.is_empty());
        assert_eq!(msg[1], gtp2_message_type::CREATE_SESSION_RESPONSE);
    }

    /// #1037, TS 29.274 §5.5.1 / §8.4 / Table 8.4-1: the Cause IE a PGW-C
    /// refusal carries, golden bytes. Before, "Mandatory IE missing" went out as
    /// 69 (Mandatory IE incorrect) and "Remote peer not responding" as 106.
    #[test]
    fn refusal_causes_are_their_table_8_4_1_octets_on_the_wire() {
        for (cause, octet) in [
            (Gtp2Cause::MandatoryIeMissing, 0x46u8),
            (Gtp2Cause::RemotePeerNotResponding, 0x64),
            (Gtp2Cause::RequestRejectedReasonNotSpecified, 0x5e),
            (Gtp2Cause::ConditionalIeMissing, 0x67),
        ] {
            let msg = build_error_message(
                gtp2_message_type::CREATE_SESSION_RESPONSE,
                0x0102_0304,
                cause,
            );
            // Header with TEID (12 octets), then the Cause IE: type 2, length 2,
            // instance 0, the cause, PCE/BCE/CS clear.
            assert_eq!(msg[0], 0x48, "{cause:?}");
            assert_eq!(&msg[4..8], &[0x01, 0x02, 0x03, 0x04]);
            assert_eq!(
                &msg[12..],
                &[0x02, 0x00, 0x02, 0x00, octet, 0x00],
                "{cause:?}"
            );
        }
    }

    #[test]
    fn test_gtp2_cause_from_u8() {
        assert_eq!(Gtp2Cause::from_wire(16), Gtp2Cause::RequestAccepted);
        assert_eq!(Gtp2Cause::from_wire(64), Gtp2Cause::ContextNotFound);
        // #1037, TS 29.274 Table 8.4-1: 69 is Mandatory IE incorrect, 70 missing.
        assert_eq!(Gtp2Cause::from_wire(69), Gtp2Cause::MandatoryIeIncorrect);
        assert_eq!(Gtp2Cause::from_wire(70), Gtp2Cause::MandatoryIeMissing);
        assert_eq!(Gtp2Cause::from_wire(255), Gtp2Cause::UndefinedValue);
    }

    /// A session and its default bearer with every value the S5/S8 builders put on
    /// the wire chosen, so the golden bytes below are fully determined (#1113).
    fn golden_session(rat: u8) -> (SmfSess, SmfBearer) {
        let mut sess = SmfSess::default();
        sess.sgw_s5c_teid = 0x0000_0003;
        sess.smf_n4_teid = 0x0000_0042;
        sess.gtp_rat_type = rat;
        sess.session_type = PduSessionType::Ipv4;
        sess.ue_session_type = PduSessionType::Ipv4 as u8;
        sess.ipv4_addr = Some(Ipv4Addr::new(10, 45, 0, 4));
        sess.charging.id = 0x0000_0007;
        let mut bearer = SmfBearer::new(1, sess.id);
        bearer.ebi = 5;
        bearer.pgw_s5u_teid = 0x0000_0099;
        bearer.pgw_s5u_addr = Some(Ipv4Addr::new(10, 10, 0, 67));
        (sess, bearer)
    }

    const GOLDEN_SMF_ADDR: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 66);

    /// #1113, TS 29.274 Tables 7.2.2-1 / 7.2.2-2: the S5/S8 Create Session Response,
    /// golden bytes. The PGW's control F-TEID is the instance-1 IE ("PGW S5/S8/S2a/S2b
    /// F-TEID ... for GTP based Control Plane interface"); a PGW sends no instance-0
    /// "Sender F-TEID", which is an S11/S4 IE. The PGW-U F-TEID is instance 2 of the
    /// Bearer Context created. It went out at instance 0, the SGW-C stored PGW S5-C TEID
    /// 0, and every detach left the PGW session behind.
    #[test]
    fn s5_create_session_response_is_table_7_2_2_1_on_the_wire() {
        let (sess, bearer) = golden_session(gtp2_rat_type::EUTRAN);
        let msg = build_create_session_response(
            &sess,
            &[bearer],
            Some(GOLDEN_SMF_ADDR),
            None,
            None,
            None,
            None,
            false,
            false,
        );
        #[rustfmt::skip]
        let expected: &[u8] = &[
            // Header: v2, T=1; type 33; length 77; SGW S5-C TEID 3; sequence 0.
            0x48, 0x21, 0x00, 0x4d, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
            // Cause (2), instance 0: Request accepted (16).
            0x02, 0x00, 0x02, 0x00, 0x10, 0x00,
            // F-TEID (87), INSTANCE 1: V4, interface 7 (S5/S8 PGW GTP-C), TEID 0x42, 10.10.0.66.
            0x57, 0x00, 0x09, 0x01, 0x87, 0x00, 0x00, 0x00, 0x42, 0x0a, 0x0a, 0x00, 0x42,
            // PAA (79), instance 0: IPv4, 10.45.0.4.
            0x4f, 0x00, 0x05, 0x00, 0x01, 0x0a, 0x2d, 0x00, 0x04,
            // APN Restriction (127), instance 0: no restriction.
            0x7f, 0x00, 0x01, 0x00, 0x00,
            // Bearer Context (93), instance 0 ("Bearer Contexts created"), 32 octets:
            0x5d, 0x00, 0x20, 0x00,
            //   EBI (73): 5.
            0x49, 0x00, 0x01, 0x00, 0x05,
            //   Cause: Request accepted.
            0x02, 0x00, 0x02, 0x00, 0x10, 0x00,
            //   Charging ID (94): 7.
            0x5e, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x07,
            //   F-TEID, INSTANCE 2: V4, interface 5 (S5/S8 PGW GTP-U), TEID 0x99, 10.10.0.67.
            0x57, 0x00, 0x09, 0x02, 0x85, 0x00, 0x00, 0x00, 0x99, 0x0a, 0x0a, 0x00, 0x43,
        ];
        assert_eq!(msg, expected);
    }

    /// #1113: over S2b the same Table 7.2.2-1 IE carries the PGW's S2b control F-TEID,
    /// still at instance 1, and the PGW-U's S2b-U F-TEID is instance 4 of the Bearer
    /// Context created (Table 7.2.2-2).
    #[test]
    fn s2b_create_session_response_uses_instances_1_and_4() {
        let (sess, bearer) = golden_session(gtp2_rat_type::WLAN);
        let msg = build_create_session_response(
            &sess,
            &[bearer],
            Some(GOLDEN_SMF_ADDR),
            None,
            None,
            None,
            None,
            false,
            false,
        );
        // F-TEID, instance 1, interface 32 (S2b PGW GTP-C), right after the Cause.
        assert_eq!(
            &msg[18..31],
            &[0x57, 0x00, 0x09, 0x01, 0xa0, 0x00, 0x00, 0x00, 0x42, 0x0a, 0x0a, 0x00, 0x42]
        );
        // No APN Restriction off E-UTRAN, so the Bearer Context follows the PAA; its last
        // IE is the F-TEID at instance 4, interface 33 (S2b-U PGW GTP-U).
        assert_eq!(
            &msg[msg.len() - 13..],
            &[0x57, 0x00, 0x09, 0x04, 0xa1, 0x00, 0x00, 0x00, 0x99, 0x0a, 0x0a, 0x00, 0x43]
        );
        assert!(
            !msg.windows(4).any(|w| w == [0x57, 0x00, 0x09, 0x00]),
            "no F-TEID at instance 0 anywhere: that is the S11/S4 Sender F-TEID"
        );
    }

    /// #1113 audit, TS 29.274 Table 7.2.3-2: the Bearer Context of a Create Bearer
    /// Request carries the mandatory TFT, the PGW's user-plane F-TEID at instance 1
    /// (S5/S8-U PGW) -- instance 0 is the S1-U SGW F-TEID, which only the SGW writes --
    /// the Bearer QoS, and the Charging Id that "shall be sent on the S5/S8 interface".
    /// Golden bytes.
    #[test]
    fn create_bearer_request_carries_the_pgw_s5u_fteid_at_instance_1() {
        let (sess, mut bearer) = golden_session(gtp2_rat_type::EUTRAN);
        bearer.ebi = 0;
        bearer.qos.index = 9;
        bearer.qos.arp_priority_level = 1;
        // Create new TFT, one bidirectional filter (id 1, precedence 16): UDP
        // (TS 24.008 §10.5.6.12).
        let tft = [0x21, 0x31, 0x10, 0x02, 0x30, 0x11];
        let msg = build_create_bearer_request(&sess, &bearer, 5, &tft, None);
        #[rustfmt::skip]
        let expected: &[u8] = &[
            // Header: type 95; length 79; SGW S5-C TEID 3.
            0x48, 0x5f, 0x00, 0x4f, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
            // Linked EBI (73), instance 0: 5.
            0x49, 0x00, 0x01, 0x00, 0x05,
            // Bearer Context (93), instance 0, 62 octets:
            0x5d, 0x00, 0x3e, 0x00,
            //   EBI: 0 (the MME assigns it).
            0x49, 0x00, 0x01, 0x00, 0x00,
            //   Bearer TFT (84).
            0x54, 0x00, 0x06, 0x00, 0x21, 0x31, 0x10, 0x02, 0x30, 0x11,
            //   F-TEID, INSTANCE 1: interface 5 (S5/S8 PGW GTP-U), TEID 0x99, 10.10.0.67.
            0x57, 0x00, 0x09, 0x01, 0x85, 0x00, 0x00, 0x00, 0x99, 0x0a, 0x0a, 0x00, 0x43,
            //   Bearer QoS (80): PL 1, QCI 9, rates 0.
            0x50, 0x00, 0x16, 0x00, 0x04, 0x09,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            //   Charging ID (94): 7.
            0x5e, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x07,
        ];
        assert_eq!(msg, expected);
    }

    /// #1165, TS 29.274 §8.15: every Bearer QoS this PGW-C sends codes the bearer's
    /// bit/s rates in kbit/s: the Create Session Response, the Create Bearer Request and
    /// the Update Bearer Request. Two of the three sent the bit/s values unconverted. A
    /// rate that is not a whole kbit/s rounds up, so a non-zero rate never becomes 0, and
    /// one past the 5-octet field is capped.
    /// #619, TS 29.274 Table 7.2.15-1: the Update Bearer Request always carries the
    /// APN-AMBR (M), in kbit/s, also for a session whose AMBR is zero. The Bearer
    /// Context is at instance 0 with the EBI. The TFT and the Bearer QoS are there
    /// only when given, and the PTI only when a Command carried one.
    #[test]
    fn the_update_bearer_request_always_carries_the_apn_ambr() {
        let (mut sess, bearer) = golden_session(gtp2_rat_type::EUTRAN);
        let ambr_of = |msg: Vec<u8>| {
            let mut bytes = bytes::Bytes::from(msg);
            let m = nextgcore_gtp::v2::Gtp2Message::decode(&mut bytes).expect("decode");
            let ambr = m
                .get_ie(nextgcore_gtp::v2::Gtp2IeType::Ambr as u8, 0)
                .map(|ie| ie.value.to_vec());
            let pti = m
                .get_ie(nextgcore_gtp::v2::Gtp2IeType::Pti as u8, 0)
                .is_some();
            let bc = m
                .bearer_context(0)
                .unwrap()
                .expect("Bearer Context at instance 0");
            let has = |t: nextgcore_gtp::v2::Gtp2IeType| bc.get_ie(t as u8, 0).is_some();
            (
                ambr,
                pti,
                bc.ebi().unwrap(),
                has(nextgcore_gtp::v2::Gtp2IeType::BearerTft),
                has(nextgcore_gtp::v2::Gtp2IeType::BearerQos),
            )
        };
        sess.session_ambr.uplink = 0;
        sess.session_ambr.downlink = 0;
        let ebi = bearer.ebi;
        assert_eq!(
            ambr_of(build_update_bearer_request(
                &sess, &bearer, None, None, false
            )),
            (Some(vec![0; 8]), false, ebi, false, false),
            "a zero APN-AMBR is still sent"
        );
        sess.session_ambr.uplink = 1_000_000;
        sess.session_ambr.downlink = 2_000_000;
        let tft = [0x21, 0x31, 0x10, 0x02, 0x30, 0x11];
        assert_eq!(
            ambr_of(build_update_bearer_request(
                &sess,
                &bearer,
                Some(7),
                Some(&tft),
                true
            )),
            (
                Some(vec![0, 0, 0x03, 0xe8, 0, 0, 0x07, 0xd0]),
                true,
                ebi,
                true,
                true
            ),
            "kbit/s, with the PTI, TFT and Bearer QoS given"
        );
    }

    #[test]
    fn every_bearer_qos_sent_is_in_kbps() {
        let (sess, mut bearer) = golden_session(gtp2_rat_type::EUTRAN);
        bearer.qos.index = 1;
        bearer.qos.mbr_uplink = 128_000;
        bearer.qos.mbr_downlink = 256_000;
        bearer.qos.gbr_uplink = 64_000;
        bearer.qos.gbr_downlink = 1;
        let sent = |msg: Vec<u8>| {
            let mut bytes = bytes::Bytes::from(msg);
            let decoded = nextgcore_gtp::v2::Gtp2Message::decode(&mut bytes).expect("decode");
            let q = decoded
                .bearer_context(0)
                .expect("decodes")
                .expect("a bearer context")
                .bearer_qos()
                .expect("decodes")
                .expect("a Bearer QoS");
            (q.mbr_ul, q.mbr_dl, q.gbr_ul, q.gbr_dl)
        };
        let expected = (128, 256, 64, 1);
        assert_eq!(
            sent(build_create_session_response(
                &sess,
                std::slice::from_ref(&bearer),
                Some(Ipv4Addr::new(10, 10, 0, 66)),
                None,
                None,
                None,
                None,
                false,
                true,
            )),
            expected,
            "Create Session Response"
        );
        let tft = [0x21, 0x31, 0x10, 0x02, 0x30, 0x11];
        assert_eq!(
            sent(build_create_bearer_request(&sess, &bearer, 5, &tft, None)),
            expected,
            "Create Bearer Request"
        );
        assert_eq!(
            sent(build_update_bearer_request(
                &sess, &bearer, None, None, true
            )),
            expected,
            "Update Bearer Request"
        );

        bearer.qos.mbr_downlink = u64::MAX;
        let q = BearerQos::from_qos(&bearer.qos);
        assert_eq!(q.dl_mbr, 0xFF_FFFF_FFFF, "capped at the 5-octet field");
        assert_eq!(
            BearerQos::new(9, 1).to_qos().mbr_uplink,
            0,
            "zero stays zero"
        );
        let back = BearerQos {
            ul_gbr: 64,
            ..BearerQos::new(1, 1)
        }
        .to_qos();
        assert_eq!(back.gbr_uplink, 64_000, "kbit/s received, bit/s stored");
    }

    /// #1113 review, TS 29.274 §8.22: octet 5 is V4 (bit 8), V6 (bit 7) and the
    /// interface type; there is no TEID flag. An IPv6-only F-TEID set V4 as well, and
    /// went out claiming an IPv4 address it did not carry.
    #[test]
    fn ipv6_only_and_dual_stack_fteids_are_section_8_22_on_the_wire() {
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x66);
        let mut expected = vec![0x47, 0x00, 0x00, 0x00, 0x42];
        expected.extend(v6.octets());
        assert_eq!(
            FTeid::new_ipv6(gtp2_f_teid_interface::S5_S8_PGW_GTP_C, 0x42, v6).encode(),
            expected,
            "V6 only: flags 0x47, 21 octets"
        );
        let v4 = Ipv4Addr::new(10, 10, 0, 66);
        let mut expected = vec![0xc5, 0x00, 0x00, 0x00, 0x99, 0x0a, 0x0a, 0x00, 0x42];
        expected.extend(v6.octets());
        assert_eq!(
            FTeid::new_dual(gtp2_f_teid_interface::S5_S8_PGW_GTP_U, 0x99, v4, v6).encode(),
            expected,
            "V4 and V6: flags 0xc5, IPv4 before IPv6"
        );

        // The Create Session Response of a PGW-C on an IPv6 S5/S8 decodes, and its
        // control F-TEID is the instance-1 one.
        let (sess, bearer) = golden_session(gtp2_rat_type::EUTRAN);
        let msg = build_create_session_response(
            &sess,
            &[bearer],
            None,
            Some(v6),
            None,
            None,
            None,
            false,
            false,
        );
        let mut bytes = bytes::Bytes::from(msg);
        let decoded = nextgcore_gtp::v2::Gtp2Message::decode(&mut bytes).expect("decode");
        let ft = nextgcore_gtp::v2::Gtp2FTeidIe::decode(
            &decoded
                .get_ie(nextgcore_gtp::v2::Gtp2IeType::FTeid as u8, 1)
                .expect("instance 1")
                .value,
        )
        .expect("an IPv6-only F-TEID decodes");
        assert_eq!(
            (ft.teid, ft.ipv4_addr, ft.ipv6_addr),
            (0x42, None, Some(v6.octets()))
        );
    }

    /// #1113 audit, TS 29.274 Table 7.2.8-2: each "Bearer Context modified" of a
    /// Modify Bearer Response carries a Cause, which is mandatory there.
    #[test]
    fn modify_bearer_response_bearer_context_carries_its_cause() {
        let (sess, bearer) = golden_session(gtp2_rat_type::EUTRAN);
        let msg = build_modify_bearer_response(&sess, &[bearer], None, true);
        #[rustfmt::skip]
        let expected: &[u8] = &[
            // Header: type 35; length 37; SGW S5-C TEID 3.
            0x48, 0x23, 0x00, 0x25, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
            // Cause: Request accepted.
            0x02, 0x00, 0x02, 0x00, 0x10, 0x00,
            // Bearer Context (93), instance 0, 19 octets: EBI 5, Cause, Charging ID 7.
            0x5d, 0x00, 0x13, 0x00,
            0x49, 0x00, 0x01, 0x00, 0x05,
            0x02, 0x00, 0x02, 0x00, 0x10, 0x00,
            0x5e, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x07,
        ];
        assert_eq!(msg, expected);
    }

    #[test]
    fn test_build_delete_session_response() {
        let msg = build_delete_session_response(0x12345678, None, None);

        assert!(!msg.is_empty());
        assert_eq!(msg[1], gtp2_message_type::DELETE_SESSION_RESPONSE);
    }

    #[test]
    fn test_build_error_message() {
        let msg = build_error_message(
            gtp2_message_type::CREATE_SESSION_RESPONSE,
            0x12345678,
            Gtp2Cause::MandatoryIeMissing,
        );

        assert!(!msg.is_empty());
        assert_eq!(msg[1], gtp2_message_type::CREATE_SESSION_RESPONSE);
    }

    #[test]
    fn test_build_echo_response() {
        let msg = build_echo_response(1);

        assert!(!msg.is_empty());
        assert_eq!(msg[1], gtp2_message_type::ECHO_RESPONSE);
    }

    #[test]
    fn test_message_type_constants() {
        assert_eq!(gtp2_message_type::ECHO_REQUEST, 1);
        assert_eq!(gtp2_message_type::CREATE_SESSION_REQUEST, 32);
        assert_eq!(gtp2_message_type::CREATE_SESSION_RESPONSE, 33);
        assert_eq!(gtp2_message_type::DELETE_SESSION_REQUEST, 36);
        assert_eq!(gtp2_message_type::DELETE_SESSION_RESPONSE, 37);
        assert_eq!(gtp2_message_type::CREATE_BEARER_REQUEST, 95);
        assert_eq!(gtp2_message_type::UPDATE_BEARER_REQUEST, 97);
        assert_eq!(gtp2_message_type::DELETE_BEARER_REQUEST, 99);
    }

    #[test]
    fn test_ie_type_constants() {
        assert_eq!(gtp2_ie_type::CAUSE, 2);
        assert_eq!(gtp2_ie_type::EBI, 73);
        assert_eq!(gtp2_ie_type::F_TEID, 87);
        assert_eq!(gtp2_ie_type::BEARER_CONTEXT, 93);
        assert_eq!(gtp2_ie_type::PAA, 79);
    }

    #[test]
    fn test_rat_type_constants() {
        assert_eq!(gtp2_rat_type::EUTRAN, 6);
        assert_eq!(gtp2_rat_type::WLAN, 3);
        assert_eq!(gtp2_rat_type::NR, 10);
    }
}
