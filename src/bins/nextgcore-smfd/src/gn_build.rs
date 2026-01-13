//! GTP v1 (Gn/Gp) Message Building for SMF

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
//!
//! Port of src/smf/gn-build.c - GTPv1-C message building for GGSN interworking
//!
//! The Gn interface connects SGSN to GGSN in 2G/3G networks.
//! The Gp interface is used between SGSNs/GGSNs in different PLMNs.
//!
//! This module enables the SMF to act as a GGSN for legacy 2G/3G devices
//! connecting through an SGSN.
//!
//! Reference: 3GPP TS 29.060 (GTPv1-C), 3GPP TS 23.401 Annex E (QoS mapping)

use bytes::{Bytes, BytesMut, BufMut};
use std::net::{Ipv4Addr, Ipv6Addr};

// ============================================================================
// GTPv1-C Constants
// ============================================================================

/// GTPv1-C version
pub const GTP1_VERSION: u8 = 1;

/// GTPv1-C Message Types
pub mod msg_type {
    pub const ECHO_REQUEST: u8 = 1;
    pub const ECHO_RESPONSE: u8 = 2;
    pub const CREATE_PDP_CONTEXT_REQUEST: u8 = 16;
    pub const CREATE_PDP_CONTEXT_RESPONSE: u8 = 17;
    pub const UPDATE_PDP_CONTEXT_REQUEST: u8 = 18;
    pub const UPDATE_PDP_CONTEXT_RESPONSE: u8 = 19;
    pub const DELETE_PDP_CONTEXT_REQUEST: u8 = 20;
    pub const DELETE_PDP_CONTEXT_RESPONSE: u8 = 21;
    pub const PDU_NOTIFICATION_REQUEST: u8 = 27;
    pub const PDU_NOTIFICATION_RESPONSE: u8 = 28;
    pub const PDU_NOTIFICATION_REJECT_REQUEST: u8 = 29;
    pub const PDU_NOTIFICATION_REJECT_RESPONSE: u8 = 30;
}

/// GTPv1-C IE Types
pub mod ie_type {
    pub const CAUSE: u8 = 1;
    pub const IMSI: u8 = 2;
    pub const RAI: u8 = 3;
    pub const TLLI: u8 = 4;
    pub const P_TMSI: u8 = 5;
    pub const RECOVERY: u8 = 14;
    pub const SELECTION_MODE: u8 = 15;
    pub const TEID_DATA_I: u8 = 16;
    pub const TEID_CONTROL: u8 = 17;
    pub const NSAPI: u8 = 20;
    pub const CHARGING_CHARACTERISTICS: u8 = 26;
    pub const END_USER_ADDRESS: u8 = 128;
    pub const ACCESS_POINT_NAME: u8 = 131;
    pub const PROTOCOL_CONFIG_OPTIONS: u8 = 132;
    pub const GSN_ADDRESS: u8 = 133;
    pub const MSISDN: u8 = 134;
    pub const QOS_PROFILE: u8 = 135;
    pub const AUTHENTICATION_QUINTUPLET: u8 = 136;
    pub const TRAFFIC_FLOW_TEMPLATE: u8 = 137;
    pub const TRIGGER_ID: u8 = 142;
    pub const OMC_IDENTITY: u8 = 143;
    pub const RAT_TYPE: u8 = 151;
    pub const USER_LOCATION_INFO: u8 = 152;
    pub const MS_TIMEZONE: u8 = 153;
    pub const IMEI: u8 = 154;
    pub const CAMEL_CHARGING_INFO: u8 = 155;
    pub const ADDITIONAL_TRACE_INFO: u8 = 162;
    pub const CORRELATION_ID: u8 = 183;
    pub const BEARER_CONTROL_MODE: u8 = 184;
    pub const EVOLVED_ARP: u8 = 191;
    pub const EXTENDED_COMMON_FLAGS: u8 = 192;
    pub const USER_CSG_INFO: u8 = 193;
    pub const APN_AMBR: u8 = 197;
    pub const GGSN_BACK_OFF_TIME: u8 = 202;
}

/// GTPv1-C Cause Values
pub mod cause {
    pub const REQUEST_IMSI: u8 = 0;
    pub const REQUEST_IMEI: u8 = 1;
    pub const REQUEST_IMSI_AND_IMEI: u8 = 2;
    pub const NO_IDENTITY_NEEDED: u8 = 3;
    pub const MS_REFUSES: u8 = 4;
    pub const REQUEST_ACCEPTED: u8 = 128;
    pub const NEW_PDP_TYPE_DUE_TO_NETWORK_PREFERENCE: u8 = 129;
    pub const NEW_PDP_TYPE_DUE_TO_SUBSCRIPTION: u8 = 130;
    pub const NON_EXISTENT: u8 = 192;
    pub const INVALID_MESSAGE_FORMAT: u8 = 193;
    pub const IMSI_NOT_KNOWN: u8 = 194;
    pub const MS_IS_GPRS_DETACHED: u8 = 195;
    pub const MS_IS_NOT_GPRS_RESPONDING: u8 = 196;
    pub const MS_REFUSES_2: u8 = 197;
    pub const VERSION_NOT_SUPPORTED: u8 = 198;
    pub const NO_RESOURCES_AVAILABLE: u8 = 199;
    pub const SERVICE_NOT_SUPPORTED: u8 = 200;
    pub const MANDATORY_IE_INCORRECT: u8 = 201;
    pub const MANDATORY_IE_MISSING: u8 = 202;
    pub const OPTIONAL_IE_INCORRECT: u8 = 203;
    pub const SYSTEM_FAILURE: u8 = 204;
    pub const ROAMING_RESTRICTION: u8 = 205;
    pub const P_TMSI_SIGNATURE_MISMATCH: u8 = 206;
    pub const GPRS_CONNECTION_SUSPENDED: u8 = 207;
    pub const AUTHENTICATION_FAILURE: u8 = 208;
    pub const USER_AUTHENTICATION_FAILED: u8 = 209;
    pub const CONTEXT_NOT_FOUND: u8 = 210;
    pub const ALL_DYNAMIC_PDP_ADDRESSES_OCCUPIED: u8 = 211;
    pub const NO_MEMORY: u8 = 212;
    pub const RELOCATION_FAILURE: u8 = 213;
    pub const UNKNOWN_MANDATORY_EXTENSION_HEADER: u8 = 214;
    pub const SEMANTIC_ERROR_TFT: u8 = 215;
    pub const SYNTACTIC_ERROR_TFT: u8 = 216;
    pub const SEMANTIC_ERROR_PACKET_FILTER: u8 = 217;
    pub const SYNTACTIC_ERROR_PACKET_FILTER: u8 = 218;
    pub const MISSING_OR_UNKNOWN_APN: u8 = 219;
    pub const UNKNOWN_PDP_ADDRESS_OR_TYPE: u8 = 220;
    pub const PDP_CONTEXT_WITHOUT_TFT_ACTIVATED: u8 = 221;
    pub const APN_ACCESS_DENIED: u8 = 222;
    pub const APN_INCOMPATIBLE_WITH_ACTIVE_PDP_CONTEXTS: u8 = 223;
    pub const MS_MBMS_CAPABILITIES_INSUFFICIENT: u8 = 224;
    pub const INVALID_CORRELATION_ID: u8 = 225;
    pub const INVALID_BEARER_ID: u8 = 226;
}

// ============================================================================
// QoS Profile Mapping (3GPP TS 23.401 Annex E)
// ============================================================================

/// Traffic Class values
pub mod traffic_class {
    pub const CONVERSATIONAL: u8 = 1;
    pub const STREAMING: u8 = 2;
    pub const INTERACTIVE: u8 = 3;
    pub const BACKGROUND: u8 = 4;
}

/// Delivery Order values
pub mod delivery_order {
    pub const WITH_ORDER: u8 = 1;
    pub const WITHOUT_ORDER: u8 = 2;
}

/// Source Statistics Descriptor values
pub mod source_stats_desc {
    pub const UNKNOWN: u8 = 0;
    pub const SPEECH: u8 = 1;
}

/// QoS Profile data structure (decoded)
#[derive(Debug, Clone, Default)]
pub struct QosProfileDecoded {
    /// Allocation/Retention Priority (1-15)
    pub arp: u8,
    /// Delay class (1-4)
    pub delay_class: u8,
    /// Reliability class (1-5)
    pub reliability_class: u8,
    /// Peak throughput (1-9)
    pub peak_throughput: u8,
    /// Precedence class (1-3)
    pub precedence_class: u8,
    /// Mean throughput (1-18, 31=best effort)
    pub mean_throughput: u8,
    /// Traffic class (1-4)
    pub traffic_class: u8,
    /// Delivery order (1-2)
    pub delivery_order: u8,
    /// Delivery of erroneous SDUs (1-3)
    pub delivery_erroneous_sdu: u8,
    /// Maximum SDU size (octets, encoded)
    pub max_sdu_size: u8,
    /// Maximum bit rate uplink (kbps)
    pub max_bitrate_ul: u32,
    /// Maximum bit rate downlink (kbps)
    pub max_bitrate_dl: u32,
    /// SDU error ratio (encoded)
    pub sdu_error_ratio: u8,
    /// Residual BER (encoded)
    pub residual_ber: u8,
    /// Traffic handling priority (1-3)
    pub traffic_handling_priority: u8,
    /// Transfer delay (ms)
    pub transfer_delay: u16,
    /// Guaranteed bit rate uplink (kbps)
    pub guaranteed_bitrate_ul: u32,
    /// Guaranteed bit rate downlink (kbps)
    pub guaranteed_bitrate_dl: u32,
    /// Signalling indication
    pub signalling_indication: bool,
    /// Source statistics descriptor
    pub source_statistics_descriptor: u8,
}

impl QosProfileDecoded {
    /// Map EPS QCI to GTPv1 QoS profile (3GPP TS 23.401 Annex E Table E.3)
    pub fn from_qci(qci: u8, arp: u8) -> Self {
        let mut profile = Self::default();
        profile.arp = arp;
        profile.delivery_order = delivery_order::WITHOUT_ORDER;
        profile.delivery_erroneous_sdu = 2; // No

        match qci {
            1 => {
                // Conversational Voice
                profile.traffic_class = traffic_class::CONVERSATIONAL;
                profile.source_statistics_descriptor = source_stats_desc::SPEECH;
                profile.transfer_delay = 150;
                profile.delay_class = 1;
            }
            2 => {
                // Conversational Video
                profile.traffic_class = traffic_class::CONVERSATIONAL;
                profile.source_statistics_descriptor = source_stats_desc::UNKNOWN;
                profile.transfer_delay = 150;
                profile.delay_class = 1;
            }
            3 => {
                // Real Time Gaming
                profile.traffic_class = traffic_class::CONVERSATIONAL;
                profile.source_statistics_descriptor = source_stats_desc::UNKNOWN;
                profile.transfer_delay = 80;
                profile.delay_class = 1;
            }
            4 => {
                // Non-Conversational Video (Buffered Streaming)
                profile.traffic_class = traffic_class::STREAMING;
                profile.source_statistics_descriptor = source_stats_desc::UNKNOWN;
                profile.sdu_error_ratio = 5; // 10^-5
                profile.delay_class = 1;
            }
            5 => {
                // IMS Signalling
                profile.traffic_class = traffic_class::INTERACTIVE;
                profile.traffic_handling_priority = 1;
                profile.signalling_indication = true;
                profile.delay_class = 1;
            }
            6 => {
                // Video (Buffered Streaming) / TCP-based
                profile.traffic_class = traffic_class::INTERACTIVE;
                profile.traffic_handling_priority = 1;
                profile.delay_class = 1;
            }
            7 => {
                // Voice, Video, Interactive Gaming
                profile.traffic_class = traffic_class::INTERACTIVE;
                profile.traffic_handling_priority = 2;
                profile.delay_class = 2;
            }
            8 => {
                // Video (Buffered Streaming) / TCP
                profile.traffic_class = traffic_class::INTERACTIVE;
                profile.traffic_handling_priority = 3;
                profile.delay_class = 3;
            }
            9 | _ => {
                // Default bearer / Best Effort
                profile.traffic_class = traffic_class::BACKGROUND;
                profile.delay_class = 4;
            }
        }

        profile
    }

    /// Encode QoS profile to bytes (3GPP TS 24.008 10.5.6.5)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(21);

        // Octet 3: Reliability class (3 bits) + Delay class (3 bits) + spare (2 bits)
        buf.push(
            ((self.delay_class & 0x07) << 3)
                | (self.reliability_class & 0x07)
        );

        // Octet 4: Peak throughput (4 bits) + spare + precedence class (3 bits)
        buf.push(
            ((self.peak_throughput & 0x0F) << 4)
                | (self.precedence_class & 0x07)
        );

        // Octet 5: Mean throughput (5 bits) + spare
        buf.push(self.mean_throughput & 0x1F);

        // Octet 6: Traffic class (3 bits) + Delivery order (2 bits) + Delivery erroneous SDU (3 bits)
        buf.push(
            ((self.traffic_class & 0x07) << 5)
                | ((self.delivery_order & 0x03) << 3)
                | (self.delivery_erroneous_sdu & 0x07)
        );

        // Octet 7: Maximum SDU size
        buf.push(self.max_sdu_size);

        // Octet 8: Maximum bit rate for uplink
        buf.push(encode_bitrate_octet(self.max_bitrate_ul));

        // Octet 9: Maximum bit rate for downlink
        buf.push(encode_bitrate_octet(self.max_bitrate_dl));

        // Octet 10: Residual BER (4 bits) + SDU error ratio (4 bits)
        buf.push(
            ((self.residual_ber & 0x0F) << 4)
                | (self.sdu_error_ratio & 0x0F)
        );

        // Octet 11: Transfer delay (6 bits) + Traffic handling priority (2 bits)
        buf.push(
            ((encode_transfer_delay(self.transfer_delay) & 0x3F) << 2)
                | (self.traffic_handling_priority & 0x03)
        );

        // Octet 12: Guaranteed bit rate for uplink
        buf.push(encode_bitrate_octet(self.guaranteed_bitrate_ul));

        // Octet 13: Guaranteed bit rate for downlink
        buf.push(encode_bitrate_octet(self.guaranteed_bitrate_dl));

        // Octet 14: Signalling indication (1 bit) + Source statistics descriptor (4 bits) + spare
        buf.push(
            (if self.signalling_indication { 0x10 } else { 0x00 })
                | (self.source_statistics_descriptor & 0x0F)
        );

        // Extended octets for higher bit rates would go here

        buf
    }
}

/// Encode bit rate to single octet (3GPP TS 24.008)
fn encode_bitrate_octet(kbps: u32) -> u8 {
    if kbps == 0 {
        0x00 // Subscribed / value not available
    } else if kbps <= 63 {
        kbps as u8
    } else if kbps <= 568 {
        (64 + (kbps - 64) / 8) as u8
    } else if kbps <= 8640 {
        (128 + (kbps - 576) / 64) as u8
    } else {
        0xFE // 8640 kbps
    }
}

/// Encode transfer delay (3GPP TS 24.008)
fn encode_transfer_delay(ms: u16) -> u8 {
    if ms <= 150 {
        (ms / 10) as u8
    } else if ms <= 950 {
        (16 + (ms - 200) / 50) as u8
    } else {
        (32 + (ms - 1000) / 100) as u8
    }
}

// ============================================================================
// Message Building Functions
// ============================================================================

/// Build GTPv1-C header
pub fn build_header(
    msg_type: u8,
    teid: u32,
    seq_num: u16,
    payload_len: u16,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12);

    // Flags: Version (3 bits) | PT (1 bit) | spare (1 bit) | E (1 bit) | S (1 bit) | PN (1 bit)
    // Version = 1, PT = 1 (GTP), E = 0, S = 1 (sequence number present), PN = 0
    buf.push(0x32); // 0b0011_0010

    // Message Type
    buf.push(msg_type);

    // Length (payload + 4 bytes for seq, npdu, ext header)
    let total_len = payload_len + 4;
    buf.extend_from_slice(&total_len.to_be_bytes());

    // TEID
    buf.extend_from_slice(&teid.to_be_bytes());

    // Sequence Number
    buf.extend_from_slice(&seq_num.to_be_bytes());

    // N-PDU Number (not used)
    buf.push(0x00);

    // Next Extension Header Type (no extension)
    buf.push(0x00);

    buf
}

/// Build Create PDP Context Response
pub fn build_create_pdp_context_response(
    cause: u8,
    teid_data: u32,
    teid_control: u32,
    nsapi: u8,
    reordering_required: bool,
    ggsn_addr_control: Option<&Ipv4Addr>,
    ggsn_addr_user: Option<&Ipv4Addr>,
    qos_profile: &QosProfileDecoded,
    charging_id: u32,
    pco: Option<&[u8]>,
    user_addr_ipv4: Option<Ipv4Addr>,
    user_addr_ipv6: Option<Ipv6Addr>,
) -> Vec<u8> {
    let mut payload = Vec::new();

    // Cause IE (TV, 2 bytes)
    payload.push(ie_type::CAUSE);
    payload.push(cause);

    // If accepted, add the remaining IEs
    if cause == cause::REQUEST_ACCEPTED {
        // Reordering Required IE (TV, 2 bytes)
        // Using Recovery IE type for simplicity (would be custom in full impl)
        payload.push(ie_type::RECOVERY);
        payload.push(if reordering_required { 0x01 } else { 0x00 });

        // TEID Data I IE (TV, 5 bytes)
        payload.push(ie_type::TEID_DATA_I);
        payload.extend_from_slice(&teid_data.to_be_bytes());

        // TEID Control Plane IE (TV, 5 bytes)
        payload.push(ie_type::TEID_CONTROL);
        payload.extend_from_slice(&teid_control.to_be_bytes());

        // NSAPI IE (TV, 2 bytes)
        payload.push(ie_type::NSAPI);
        payload.push(nsapi);

        // Charging ID IE (TV, 5 bytes - using trigger ID type)
        payload.push(ie_type::TRIGGER_ID);
        payload.extend_from_slice(&charging_id.to_be_bytes());

        // End User Address IE (TLV)
        if let Some(ipv4) = user_addr_ipv4 {
            payload.push(ie_type::END_USER_ADDRESS);
            payload.extend_from_slice(&6u16.to_be_bytes()); // Length
            payload.push(0xF1); // Spare + PDP Type Organization (IETF)
            payload.push(0x21); // PDP Type Number (IPv4)
            payload.extend_from_slice(&ipv4.octets());
        } else if let Some(ipv6) = user_addr_ipv6 {
            payload.push(ie_type::END_USER_ADDRESS);
            payload.extend_from_slice(&18u16.to_be_bytes()); // Length
            payload.push(0xF1); // Spare + PDP Type Organization (IETF)
            payload.push(0x57); // PDP Type Number (IPv6)
            payload.extend_from_slice(&ipv6.octets());
        }

        // GGSN Address for signalling IE (TLV)
        if let Some(addr) = ggsn_addr_control {
            payload.push(ie_type::GSN_ADDRESS);
            payload.extend_from_slice(&4u16.to_be_bytes());
            payload.extend_from_slice(&addr.octets());
        }

        // GGSN Address for user traffic IE (TLV)
        if let Some(addr) = ggsn_addr_user {
            payload.push(ie_type::GSN_ADDRESS);
            payload.extend_from_slice(&4u16.to_be_bytes());
            payload.extend_from_slice(&addr.octets());
        }

        // QoS Profile IE (TLV)
        let qos_bytes = qos_profile.encode();
        payload.push(ie_type::QOS_PROFILE);
        payload.extend_from_slice(&(qos_bytes.len() as u16 + 1).to_be_bytes());
        payload.push(qos_profile.arp);
        payload.extend_from_slice(&qos_bytes);

        // Protocol Configuration Options IE (TLV)
        if let Some(pco_data) = pco {
            payload.push(ie_type::PROTOCOL_CONFIG_OPTIONS);
            payload.extend_from_slice(&(pco_data.len() as u16).to_be_bytes());
            payload.extend_from_slice(pco_data);
        }
    }

    payload
}

/// Build Delete PDP Context Response
pub fn build_delete_pdp_context_response(cause: u8) -> Vec<u8> {
    let mut payload = Vec::new();

    // Cause IE (TV, 2 bytes)
    payload.push(ie_type::CAUSE);
    payload.push(cause);

    payload
}

/// Build Update PDP Context Response
pub fn build_update_pdp_context_response(
    cause: u8,
    teid_data: u32,
    teid_control: u32,
    ggsn_addr_control: Option<&Ipv4Addr>,
    ggsn_addr_user: Option<&Ipv4Addr>,
    qos_profile: Option<&QosProfileDecoded>,
) -> Vec<u8> {
    let mut payload = Vec::new();

    // Cause IE
    payload.push(ie_type::CAUSE);
    payload.push(cause);

    if cause == cause::REQUEST_ACCEPTED {
        // Recovery IE (for recovery counter, simplified)
        payload.push(ie_type::RECOVERY);
        payload.push(0x00);

        // TEID Data I
        payload.push(ie_type::TEID_DATA_I);
        payload.extend_from_slice(&teid_data.to_be_bytes());

        // TEID Control
        payload.push(ie_type::TEID_CONTROL);
        payload.extend_from_slice(&teid_control.to_be_bytes());

        // GGSN Addresses
        if let Some(addr) = ggsn_addr_control {
            payload.push(ie_type::GSN_ADDRESS);
            payload.extend_from_slice(&4u16.to_be_bytes());
            payload.extend_from_slice(&addr.octets());
        }

        if let Some(addr) = ggsn_addr_user {
            payload.push(ie_type::GSN_ADDRESS);
            payload.extend_from_slice(&4u16.to_be_bytes());
            payload.extend_from_slice(&addr.octets());
        }

        // QoS Profile
        if let Some(qos) = qos_profile {
            let qos_bytes = qos.encode();
            payload.push(ie_type::QOS_PROFILE);
            payload.extend_from_slice(&(qos_bytes.len() as u16 + 1).to_be_bytes());
            payload.push(qos.arp);
            payload.extend_from_slice(&qos_bytes);
        }
    }

    payload
}

/// Build Echo Response
pub fn build_echo_response(recovery: u8) -> Vec<u8> {
    let mut payload = Vec::new();

    // Recovery IE
    payload.push(ie_type::RECOVERY);
    payload.push(recovery);

    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qos_from_qci() {
        let qos = QosProfileDecoded::from_qci(1, 5);
        assert_eq!(qos.traffic_class, traffic_class::CONVERSATIONAL);
        assert_eq!(qos.source_statistics_descriptor, source_stats_desc::SPEECH);
        assert_eq!(qos.arp, 5);
    }

    #[test]
    fn test_encode_bitrate() {
        assert_eq!(encode_bitrate_octet(0), 0x00);
        assert_eq!(encode_bitrate_octet(32), 32);
        assert_eq!(encode_bitrate_octet(63), 63);
        assert_eq!(encode_bitrate_octet(128), 72); // 64 + (128-64)/8
    }

    #[test]
    fn test_build_header() {
        let header = build_header(msg_type::CREATE_PDP_CONTEXT_RESPONSE, 0x12345678, 1, 100);
        assert_eq!(header[0], 0x32); // Flags
        assert_eq!(header[1], msg_type::CREATE_PDP_CONTEXT_RESPONSE);
        assert_eq!(header.len(), 12);
    }

    #[test]
    fn test_build_echo_response() {
        let payload = build_echo_response(5);
        assert_eq!(payload[0], ie_type::RECOVERY);
        assert_eq!(payload[1], 5);
    }

    #[test]
    fn test_build_delete_response() {
        let payload = build_delete_pdp_context_response(cause::REQUEST_ACCEPTED);
        assert_eq!(payload[0], ie_type::CAUSE);
        assert_eq!(payload[1], cause::REQUEST_ACCEPTED);
    }
}
