//! SGWC S11 Message Builder
//!
//! Port of src/sgwc/s11-build.c - Build GTPv2-C messages for S11 interface

use crate::context::{sgwc_self, SgwcBearer, SgwcSess};
use crate::s11_handler::gtp_cause;

// ============================================================================
// GTP Message Types
// ============================================================================

pub mod gtp_type {
    pub const CREATE_SESSION_RESPONSE: u8 = 33;
    pub const MODIFY_BEARER_RESPONSE: u8 = 35;
    pub const DELETE_SESSION_RESPONSE: u8 = 37;
    pub const DOWNLINK_DATA_NOTIFICATION: u8 = 176;
    pub const RELEASE_ACCESS_BEARERS_RESPONSE: u8 = 171;
    pub const CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE: u8 = 167;
    pub const DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE: u8 = 169;
}

// ============================================================================
// GTP F-TEID Interface Types
// ============================================================================

pub mod f_teid_interface {
    pub const S11_S4_SGW_GTP_C: u8 = 7;
    pub const S5_S8_SGW_GTP_C: u8 = 6;
    pub const S1_U_SGW_GTP_U: u8 = 1;
    pub const S5_S8_SGW_GTP_U: u8 = 4;
}

// ============================================================================
// Message Builder Result
// ============================================================================

/// Built GTP message
#[derive(Debug, Clone)]
pub struct GtpMessage {
    pub msg_type: u8,
    pub teid: u32,
    pub data: Vec<u8>,
}

impl GtpMessage {
    pub fn new(msg_type: u8, teid: u32) -> Self {
        Self {
            msg_type,
            teid,
            data: Vec::new(),
        }
    }
}

// ============================================================================
// S11 Message Builders
// ============================================================================

/// Build Create Session Response
/// Port of sgwc_s11_build_create_session_response
pub fn build_create_session_response(sess: &SgwcSess) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let sgwc_ue = ctx.ue_find_by_id(sess.sgwc_ue_id)?;
    let mut msg = GtpMessage::new(gtp_type::CREATE_SESSION_RESPONSE, sgwc_ue.mme_s11_teid);

    // Build message data (simplified - actual implementation would use proper TLV encoding)
    let mut data = Vec::new();

    // Cause IE
    data.push(gtp_cause::REQUEST_ACCEPTED);

    // F-TEID for S11 SGW GTP-C
    data.extend_from_slice(&sgwc_ue.sgw_s11_teid.to_be_bytes());

    // F-TEID for S5/S8 SGW GTP-C
    data.extend_from_slice(&sess.sgw_s5c_teid.to_be_bytes());

    // PDN Address Allocation
    data.push(sess.paa.pdn_type);
    if let Some(ipv4) = sess.paa.ipv4_addr {
        data.extend_from_slice(&ipv4.octets());
    }

    // Bearer Contexts Created
    for bearer_id in &sess.bearer_ids {
        if let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) {
            // EBI
            data.push(bearer.ebi);

            // S1-U SGW F-TEID
            if let Some(dl_tunnel) = ctx.dl_tunnel_in_bearer(bearer.id) {
                data.extend_from_slice(&dl_tunnel.local_teid.to_be_bytes());
            }

            // S5/S8-U SGW F-TEID
            if let Some(ul_tunnel) = ctx.ul_tunnel_in_bearer(bearer.id) {
                data.extend_from_slice(&ul_tunnel.local_teid.to_be_bytes());
            }
        }
    }

    msg.data = data;
    log::debug!(
        "Built Create Session Response: teid={}, data_len={}",
        msg.teid,
        msg.data.len()
    );

    Some(msg)
}

/// Build Modify Bearer Response
/// Port of sgwc_s11_build_modify_bearer_response (implicit in handler)
pub fn build_modify_bearer_response(sess: &SgwcSess, cause: u8) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let sgwc_ue = ctx.ue_find_by_id(sess.sgwc_ue_id)?;
    let mut msg = GtpMessage::new(gtp_type::MODIFY_BEARER_RESPONSE, sgwc_ue.mme_s11_teid);

    let mut data = Vec::new();

    // Cause IE
    data.push(cause);

    // Bearer Contexts Modified
    for bearer_id in &sess.bearer_ids {
        if let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) {
            // EBI
            data.push(bearer.ebi);
            // Cause
            data.push(gtp_cause::REQUEST_ACCEPTED);
        }
    }

    msg.data = data;
    log::debug!(
        "Built Modify Bearer Response: teid={}, data_len={}",
        msg.teid,
        msg.data.len()
    );

    Some(msg)
}

/// Build Delete Session Response
/// Port of sgwc_s11_build_delete_session_response (implicit in handler)
pub fn build_delete_session_response(sess: &SgwcSess, cause: u8) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let sgwc_ue = ctx.ue_find_by_id(sess.sgwc_ue_id)?;
    let mut msg = GtpMessage::new(gtp_type::DELETE_SESSION_RESPONSE, sgwc_ue.mme_s11_teid);

    let mut data = Vec::new();

    // Cause IE
    data.push(cause);

    msg.data = data;
    log::debug!(
        "Built Delete Session Response: teid={}, data_len={}",
        msg.teid,
        msg.data.len()
    );

    Some(msg)
}

/// Build Downlink Data Notification
/// Port of sgwc_s11_build_downlink_data_notification
pub fn build_downlink_data_notification(cause_value: u8, bearer: &SgwcBearer) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let sgwc_ue = ctx.ue_find_by_id(bearer.sgwc_ue_id)?;
    let mut msg = GtpMessage::new(gtp_type::DOWNLINK_DATA_NOTIFICATION, sgwc_ue.mme_s11_teid);

    let mut data = Vec::new();

    // Cause IE (if error indication)
    if cause_value != gtp_cause::REQUEST_ACCEPTED {
        data.push(cause_value);
    }

    // EPS Bearer ID
    data.push(bearer.ebi);

    // ARP (Allocation and Retention Priority) - simplified
    data.push(0); // Priority level
    data.push(0); // Pre-emption capability/vulnerability

    msg.data = data;

    log::info!(
        "Downlink Data Notification [bearer_id={}]",
        bearer.id
    );
    log::info!(
        "    MME_S11_TEID[{}] SGW_S11_TEID[{}]",
        sgwc_ue.mme_s11_teid,
        sgwc_ue.sgw_s11_teid
    );

    Some(msg)
}

/// Build Release Access Bearers Response
pub fn build_release_access_bearers_response(
    sgwc_ue_id: u64,
    cause: u8,
) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let sgwc_ue = ctx.ue_find_by_id(sgwc_ue_id)?;
    let mut msg = GtpMessage::new(
        gtp_type::RELEASE_ACCESS_BEARERS_RESPONSE,
        sgwc_ue.mme_s11_teid,
    );

    let mut data = Vec::new();

    // Cause IE
    data.push(cause);

    msg.data = data;
    log::debug!(
        "Built Release Access Bearers Response: teid={}, data_len={}",
        msg.teid,
        msg.data.len()
    );

    Some(msg)
}

/// Build Create Indirect Data Forwarding Tunnel Response
pub fn build_create_indirect_data_forwarding_tunnel_response(
    sgwc_ue_id: u64,
    cause: u8,
) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let sgwc_ue = ctx.ue_find_by_id(sgwc_ue_id)?;
    let mut msg = GtpMessage::new(
        gtp_type::CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE,
        sgwc_ue.mme_s11_teid,
    );

    let mut data = Vec::new();

    // Cause IE
    data.push(cause);

    // Bearer Contexts would be added here with indirect tunnel TEIDs

    msg.data = data;
    log::debug!(
        "Built Create Indirect Data Forwarding Tunnel Response: teid={}, data_len={}",
        msg.teid,
        msg.data.len()
    );

    Some(msg)
}

/// Build Delete Indirect Data Forwarding Tunnel Response
pub fn build_delete_indirect_data_forwarding_tunnel_response(
    sgwc_ue_id: u64,
    cause: u8,
) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let sgwc_ue = ctx.ue_find_by_id(sgwc_ue_id)?;
    let mut msg = GtpMessage::new(
        gtp_type::DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE,
        sgwc_ue.mme_s11_teid,
    );

    let mut data = Vec::new();

    // Cause IE
    data.push(cause);

    msg.data = data;
    log::debug!(
        "Built Delete Indirect Data Forwarding Tunnel Response: teid={}, data_len={}",
        msg.teid,
        msg.data.len()
    );

    Some(msg)
}

// ============================================================================
// S5C Message Types (SGW-C → PGW-C)
// ============================================================================

pub mod s5c_gtp_type {
    pub const CREATE_SESSION_REQUEST: u8 = 32;
    pub const MODIFY_BEARER_REQUEST: u8 = 34;
    pub const DELETE_SESSION_REQUEST: u8 = 36;
    pub const CREATE_BEARER_RESPONSE: u8 = 96;
    pub const UPDATE_BEARER_RESPONSE: u8 = 98;
    pub const DELETE_BEARER_RESPONSE: u8 = 100;
}

// ============================================================================
// GTPv2-C IE Types (TS 29.274 Table 8.1-1)
// ============================================================================

pub mod ie_type {
    pub const CAUSE: u8 = 2;
    pub const EBI: u8 = 73;
    pub const F_TEID: u8 = 87;
    pub const BEARER_CONTEXT: u8 = 93;
    pub const APN: u8 = 71;
    pub const AMBR: u8 = 72;
    pub const PDN_TYPE: u8 = 99;
    pub const PAA: u8 = 79;
    pub const SELECTION_MODE: u8 = 128;
    pub const INDICATION: u8 = 77;
    pub const BEARER_QOS: u8 = 80;
}

// ============================================================================
// S5C GTPv2-C IE Encoder
// ============================================================================

/// Encode a GTPv2-C IE (Type, Length, Spare+Instance, Value)
fn encode_ie(ie_type: u8, instance: u8, value: &[u8]) -> Vec<u8> {
    let mut ie = Vec::with_capacity(4 + value.len());
    ie.push(ie_type);
    let len = value.len() as u16;
    ie.extend_from_slice(&len.to_be_bytes());
    ie.push(instance & 0x0F); // spare(4 bits) + instance(4 bits)
    ie.extend_from_slice(value);
    ie
}

/// Encode F-TEID IE (TS 29.274 section 8.22)
fn encode_f_teid(interface_type: u8, teid: u32, ipv4: Option<[u8; 4]>) -> Vec<u8> {
    let mut val = Vec::new();
    let mut flags = interface_type & 0x3F;
    if ipv4.is_some() {
        flags |= 0x80; // V4 flag
    }
    val.push(flags);
    val.extend_from_slice(&teid.to_be_bytes());
    if let Some(addr) = ipv4 {
        val.extend_from_slice(&addr);
    }
    val
}

/// Encode APN in DNS label format
fn encode_apn_dns(apn: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for label in apn.split('.') {
        result.push(label.len() as u8);
        result.extend_from_slice(label.as_bytes());
    }
    result
}

// ============================================================================
// S5C Message Builders (SGW-C → PGW-C)
// ============================================================================

/// Build Create Session Request to P-GW (S5C)
/// Port of sgwc_s5c_build_create_session_request
pub fn build_s5c_create_session_request(sess: &SgwcSess) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let _sgwc_ue = ctx.ue_find_by_id(sess.sgwc_ue_id)?;
    let mut msg = GtpMessage::new(s5c_gtp_type::CREATE_SESSION_REQUEST, sess.pgw_s5c_teid);
    let mut data = Vec::new();

    // F-TEID for S5/S8 SGW GTP-C (sender)
    let fteid = encode_f_teid(
        f_teid_interface::S5_S8_SGW_GTP_C,
        sess.sgw_s5c_teid,
        None, // IP resolved at socket level
    );
    data.extend_from_slice(&encode_ie(ie_type::F_TEID, 0, &fteid));

    // APN
    if let Some(apn) = sess.apn() {
        let apn_bytes = encode_apn_dns(apn);
        data.extend_from_slice(&encode_ie(ie_type::APN, 0, &apn_bytes));
    }

    // PDN Type
    data.extend_from_slice(&encode_ie(ie_type::PDN_TYPE, 0, &[sess.paa.pdn_type]));

    // Bearer Contexts to be created
    for bearer_id in &sess.bearer_ids {
        if let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) {
            let mut bc = Vec::new();
            // EBI
            bc.extend_from_slice(&encode_ie(ie_type::EBI, 0, &[bearer.ebi]));
            // S5/S8-U SGW F-TEID
            if let Some(ul_tunnel) = ctx.ul_tunnel_in_bearer(bearer.id) {
                let ft = encode_f_teid(
                    f_teid_interface::S5_S8_SGW_GTP_U,
                    ul_tunnel.local_teid,
                    None,
                );
                bc.extend_from_slice(&encode_ie(ie_type::F_TEID, 2, &ft));
            }
            // Bearer QoS (simplified: 22 bytes, QCI=9 default)
            let qos = vec![0u8; 22];
            bc.extend_from_slice(&encode_ie(ie_type::BEARER_QOS, 0, &qos));

            data.extend_from_slice(&encode_ie(ie_type::BEARER_CONTEXT, 0, &bc));
        }
    }

    msg.data = data;
    log::debug!(
        "Built S5C Create Session Request: pgw_teid={}, data_len={}",
        sess.pgw_s5c_teid,
        msg.data.len()
    );
    Some(msg)
}

/// Build Modify Bearer Request to P-GW (S5C)
/// Port of sgwc_s5c_build_modify_bearer_request
pub fn build_s5c_modify_bearer_request(sess: &SgwcSess) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let _sgwc_ue = ctx.ue_find_by_id(sess.sgwc_ue_id)?;
    let mut msg = GtpMessage::new(s5c_gtp_type::MODIFY_BEARER_REQUEST, sess.pgw_s5c_teid);
    let mut data = Vec::new();

    // Indication Flags (e.g., Operation Indication)
    let indication = [0u8; 4]; // Simplified: flags cleared
    data.extend_from_slice(&encode_ie(ie_type::INDICATION, 0, &indication));

    // Bearer Contexts to be modified
    for bearer_id in &sess.bearer_ids {
        if let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) {
            let mut bc = Vec::new();
            // EBI
            bc.extend_from_slice(&encode_ie(ie_type::EBI, 0, &[bearer.ebi]));
            // S5/S8-U SGW F-TEID (updated with eNB/gNB TEID)
            if let Some(ul_tunnel) = ctx.ul_tunnel_in_bearer(bearer.id) {
                let ft = encode_f_teid(
                    f_teid_interface::S5_S8_SGW_GTP_U,
                    ul_tunnel.local_teid,
                    None,
                );
                bc.extend_from_slice(&encode_ie(ie_type::F_TEID, 2, &ft));
            }
            data.extend_from_slice(&encode_ie(ie_type::BEARER_CONTEXT, 0, &bc));
        }
    }

    msg.data = data;
    log::debug!(
        "Built S5C Modify Bearer Request: pgw_teid={}, data_len={}",
        sess.pgw_s5c_teid,
        msg.data.len()
    );
    Some(msg)
}

/// Build Delete Session Request to P-GW (S5C)
/// Port of sgwc_s5c_build_delete_session_request
pub fn build_s5c_delete_session_request(sess: &SgwcSess) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let _sgwc_ue = ctx.ue_find_by_id(sess.sgwc_ue_id)?;
    let mut msg = GtpMessage::new(s5c_gtp_type::DELETE_SESSION_REQUEST, sess.pgw_s5c_teid);
    let mut data = Vec::new();

    // Linked EBI (first bearer)
    if let Some(first_bearer_id) = sess.bearer_ids.first() {
        if let Some(bearer) = ctx.bearer_find_by_id(*first_bearer_id) {
            data.extend_from_slice(&encode_ie(ie_type::EBI, 0, &[bearer.ebi]));
        }
    }

    // Indication: OI flag (Operation Indication)
    let indication = [0x00, 0x00, 0x00, 0x08u8]; // OI=1
    data.extend_from_slice(&encode_ie(ie_type::INDICATION, 0, &indication));

    msg.data = data;
    log::debug!(
        "Built S5C Delete Session Request: pgw_teid={}, data_len={}",
        sess.pgw_s5c_teid,
        msg.data.len()
    );
    Some(msg)
}

/// Build Create Bearer Response to P-GW (S5C)
pub fn build_s5c_create_bearer_response(sess: &SgwcSess, cause: u8) -> Option<GtpMessage> {
    let ctx = sgwc_self();

    let _sgwc_ue = ctx.ue_find_by_id(sess.sgwc_ue_id)?;
    let mut msg = GtpMessage::new(s5c_gtp_type::CREATE_BEARER_RESPONSE, sess.pgw_s5c_teid);
    let mut data = Vec::new();

    // Cause
    data.extend_from_slice(&encode_ie(ie_type::CAUSE, 0, &[cause, 0]));

    // Bearer Contexts
    for bearer_id in &sess.bearer_ids {
        if let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) {
            let mut bc = Vec::new();
            bc.extend_from_slice(&encode_ie(ie_type::EBI, 0, &[bearer.ebi]));
            bc.extend_from_slice(&encode_ie(ie_type::CAUSE, 0, &[gtp_cause::REQUEST_ACCEPTED, 0]));
            if let Some(ul_tunnel) = ctx.ul_tunnel_in_bearer(bearer.id) {
                let ft = encode_f_teid(
                    f_teid_interface::S5_S8_SGW_GTP_U,
                    ul_tunnel.local_teid,
                    None,
                );
                bc.extend_from_slice(&encode_ie(ie_type::F_TEID, 2, &ft));
            }
            data.extend_from_slice(&encode_ie(ie_type::BEARER_CONTEXT, 0, &bc));
        }
    }

    msg.data = data;
    log::debug!(
        "Built S5C Create Bearer Response: pgw_teid={}, data_len={}",
        sess.pgw_s5c_teid,
        msg.data.len()
    );
    Some(msg)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtp_message_new() {
        let msg = GtpMessage::new(gtp_type::CREATE_SESSION_RESPONSE, 12345);
        assert_eq!(msg.msg_type, gtp_type::CREATE_SESSION_RESPONSE);
        assert_eq!(msg.teid, 12345);
        assert!(msg.data.is_empty());
    }

    #[test]
    fn test_encode_ie() {
        let ie = encode_ie(ie_type::EBI, 0, &[5]);
        assert_eq!(ie[0], ie_type::EBI);
        assert_eq!(u16::from_be_bytes([ie[1], ie[2]]), 1); // length = 1
        assert_eq!(ie[3], 0); // instance
        assert_eq!(ie[4], 5); // value
    }

    #[test]
    fn test_encode_f_teid() {
        let ft = encode_f_teid(f_teid_interface::S5_S8_SGW_GTP_C, 0x1234, Some([10, 0, 0, 1]));
        assert_eq!(ft[0] & 0x80, 0x80); // V4 flag set
        assert_eq!(ft[0] & 0x3F, f_teid_interface::S5_S8_SGW_GTP_C);
        assert_eq!(u32::from_be_bytes([ft[1], ft[2], ft[3], ft[4]]), 0x1234);
        assert_eq!(&ft[5..9], &[10, 0, 0, 1]);
    }

    #[test]
    fn test_encode_apn_dns() {
        let apn = encode_apn_dns("internet");
        assert_eq!(apn[0], 8); // "internet" length
        assert_eq!(&apn[1..9], b"internet");

        let apn2 = encode_apn_dns("ims.mnc001.mcc001.3gppnetwork.org");
        assert_eq!(apn2[0], 3); // "ims" length
    }
}
