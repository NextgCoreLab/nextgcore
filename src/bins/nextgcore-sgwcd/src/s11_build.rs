//! SGWC S11 / S5-C Message Builders (TS 29.274)
//!
//! Port of src/sgwc/s11-build.c and src/sgwc/s5c-build.c. All messages are
//! built with the ogs-gtp GTPv2-C codec (proper TLV framing); there is no
//! hand-rolled byte layout in this module.

use std::net::{Ipv4Addr, Ipv6Addr};

use ogs_gtp::v2::header::{Gtp2Header, Gtp2MessageType};
use ogs_gtp::v2::ie::{
    Gtp2AmbrIe, Gtp2ApnIe, Gtp2ApnRestrictionIe, Gtp2BearerContextIe, Gtp2BearerQosIe, Gtp2CauseIe,
    Gtp2EbiIe, Gtp2FTeidIe, Gtp2IeType, Gtp2IndicationIe, Gtp2PaaIe, Gtp2PdnTypeIe, Gtp2RatTypeIe,
    Gtp2RecoveryIe, Gtp2SelectionModeIe,
};
use ogs_gtp::v2::message::Gtp2Message;

use crate::context::{sgwc_self, SgwcBearer, SgwcSess, SgwcTunnel};
use crate::s11_handler::gtp_cause;

// ============================================================================
// GTP F-TEID Interface Types (TS 29.274 Section 8.22)
// ============================================================================

pub mod f_teid_interface {
    pub const S1_U_ENODEB_GTP_U: u8 = 0;
    pub const S1_U_SGW_GTP_U: u8 = 1;
    pub const S5_S8_SGW_GTP_U: u8 = 4;
    pub const S5_S8_PGW_GTP_U: u8 = 5;
    pub const S5_S8_SGW_GTP_C: u8 = 6;
    pub const S5_S8_PGW_GTP_C: u8 = 7;
    pub const S11_MME_GTP_C: u8 = 10;
    pub const S11_S4_SGW_GTP_C: u8 = 11;
    pub const SGW_GTP_U_DL_DATA_FORWARDING: u8 = 22;
    pub const SGW_GTP_U_UL_DATA_FORWARDING: u8 = 23;
}

/// RAT Type values (TS 29.274 Section 8.17)
pub mod rat_type {
    pub const EUTRAN: u8 = 6;
}

// ============================================================================
// Helpers
// ============================================================================

/// Build an F-TEID IE from explicit local addresses. At least one address
/// family must be present (TS 29.274 Section 8.22).
pub fn fteid(
    interface_type: u8,
    teid: u32,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
) -> Result<Gtp2FTeidIe, String> {
    match (ipv4, ipv6) {
        (Some(v4), Some(v6)) => Ok(Gtp2FTeidIe::new_dual(
            interface_type,
            teid,
            v4.octets(),
            v6.octets(),
        )),
        (Some(v4), None) => Ok(Gtp2FTeidIe::new_ipv4(interface_type, teid, v4.octets())),
        (None, Some(v6)) => Ok(Gtp2FTeidIe::new_ipv6(interface_type, teid, v6.octets())),
        (None, None) => Err(format!(
            "F-TEID interface type {interface_type} has no local address configured"
        )),
    }
}

/// Build an F-TEID IE for a tunnel's local endpoint
fn fteid_from_tunnel(interface_type: u8, tunnel: &SgwcTunnel) -> Result<Gtp2FTeidIe, String> {
    fteid(
        interface_type,
        tunnel.local_teid,
        tunnel.local_addr,
        tunnel.local_addr6,
    )
}

/// Build the PAA IE from session state, if an address has been allocated
fn paa_ie(sess: &SgwcSess) -> Option<Gtp2PaaIe> {
    match (sess.paa.pdn_type, sess.paa.ipv4_addr, sess.paa.ipv6_addr) {
        (1, Some(v4), _) => Some(Gtp2PaaIe::ipv4(v4.octets())),
        (2, _, Some(v6)) => Some(Gtp2PaaIe::ipv6(64, v6.octets())),
        (3, Some(v4), Some(v6)) => Some(Gtp2PaaIe::ipv4v6(v4.octets(), 64, v6.octets())),
        _ => None,
    }
}

/// Build the Bearer QoS IE from bearer state
fn bearer_qos_ie(bearer: &SgwcBearer) -> Gtp2BearerQosIe {
    let mut qos = Gtp2BearerQosIe::new(
        bearer.qci,
        bearer.mbr_ul,
        bearer.mbr_dl,
        bearer.gbr_ul,
        bearer.gbr_dl,
    );
    qos.pl = bearer.arp_priority_level;
    qos.pci = bearer.arp_pci;
    qos.pvi = bearer.arp_pvi;
    qos
}

/// Build the ARP IE (TS 29.274 Section 8.55): one octet with the same
/// PCI/PL/PVI layout as the Bearer QoS ARP octet.
fn arp_ie(bearer: &SgwcBearer) -> ogs_gtp::v2::ie::Gtp2Ie {
    let mut arp = 0u8;
    if bearer.arp_pci {
        arp |= 0x40;
    }
    arp |= (bearer.arp_priority_level & 0x0F) << 2;
    if bearer.arp_pvi {
        arp |= 0x01;
    }
    ogs_gtp::v2::ie::Gtp2Ie::from_slice(Gtp2IeType::Arp as u8, 0, &[arp])
}

fn new_message(message_type: Gtp2MessageType, teid: u32, sequence_number: u32) -> Gtp2Message {
    Gtp2Message::new(Gtp2Header::new(message_type as u8, teid, sequence_number))
}

// ============================================================================
// Generic triggered error message
// ============================================================================

/// Build a triggered (response) message that carries only a Cause IE.
/// Used for all reject paths (TS 29.274 Section 7.7).
pub fn build_error_response(
    response_type: u8,
    teid: u32,
    sequence_number: u32,
    cause: u8,
    offending_ie_type: Option<u8>,
) -> Gtp2Message {
    let mut msg = Gtp2Message::new(Gtp2Header::new(response_type, teid, sequence_number));
    let cause_ie = match offending_ie_type {
        Some(ie_type) => Gtp2CauseIe::with_offending_ie(cause, ie_type, 0, 0),
        None => Gtp2CauseIe::new(cause),
    };
    msg.add_ie(cause_ie.to_ie(0));
    msg
}

// ============================================================================
// S11 Triggered Messages (SGW -> MME)
// ============================================================================

/// Build Create Session Response (TS 29.274 Section 7.2.2)
/// Port of sgwc_s11_build_create_session_response
pub fn build_create_session_response(
    sess: &SgwcSess,
    sequence_number: u32,
    restart_counter: u8,
) -> Result<Gtp2Message, String> {
    let ctx = sgwc_self();
    let sgwc_ue = ctx
        .ue_find_by_id(sess.sgwc_ue_id)
        .ok_or_else(|| "UE not found".to_string())?;

    let mut msg = new_message(
        Gtp2MessageType::CreateSessionResponse,
        sgwc_ue.mme_s11_teid,
        sequence_number,
    );

    // Cause (M)
    msg.add_ie(Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED).to_ie(0));

    // Sender F-TEID for control plane: S11/S4 SGW GTP-C (C, instance 0)
    let s11_addr = ctx.s11_address();
    msg.add_ie(
        fteid(
            f_teid_interface::S11_S4_SGW_GTP_C,
            sgwc_ue.sgw_s11_teid,
            s11_addr,
            None,
        )?
        .to_ie(0),
    );

    // PGW S5/S8 F-TEID for control plane (C, instance 1) when known
    if sess.pgw_s5c_teid != 0 {
        if let Ok(pgw_fteid) = fteid(
            f_teid_interface::S5_S8_PGW_GTP_C,
            sess.pgw_s5c_teid,
            sess.pgw_addr,
            None,
        ) {
            msg.add_ie(pgw_fteid.to_ie(1));
        }
    }

    // PAA (C, instance 0)
    if let Some(paa) = paa_ie(sess) {
        msg.add_ie(paa.to_ie(0));
    }

    // APN Restriction (C, instance 0)
    let mut restriction_buf = bytes::BytesMut::new();
    Gtp2ApnRestrictionIe::new(0).encode(&mut restriction_buf, 0);
    {
        let mut b = restriction_buf.freeze();
        msg.add_ie(ogs_gtp::v2::ie::Gtp2Ie::decode(&mut b).map_err(|e| e.to_string())?);
    }

    // APN-AMBR (C, instance 0)
    if sess.ambr_ul != 0 || sess.ambr_dl != 0 {
        let mut ambr_buf = bytes::BytesMut::new();
        Gtp2AmbrIe::new(sess.ambr_ul, sess.ambr_dl).encode(&mut ambr_buf, 0);
        let mut b = ambr_buf.freeze();
        msg.add_ie(ogs_gtp::v2::ie::Gtp2Ie::decode(&mut b).map_err(|e| e.to_string())?);
    }

    // Bearer Contexts created (M, instance 0): one grouped IE per bearer
    let mut bearer_count = 0;
    for bearer_id in &sess.bearer_ids {
        let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) else {
            continue;
        };
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(bearer.ebi);
        bc.set_cause(&Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED));

        // S1-U SGW F-TEID (instance 0): uplink tunnel local endpoint
        if let Some(ul_tunnel) = ctx.ul_tunnel_in_bearer(bearer.id) {
            bc.set_fteid(
                0,
                &fteid_from_tunnel(f_teid_interface::S1_U_SGW_GTP_U, &ul_tunnel)?,
            );
        }
        msg.add_bearer_context(0, &bc);
        bearer_count += 1;
    }
    if bearer_count == 0 {
        return Err("Create Session Response requires at least one bearer context".to_string());
    }

    // Recovery (C)
    let mut rec_buf = bytes::BytesMut::new();
    Gtp2RecoveryIe::new(restart_counter).encode(&mut rec_buf, 0);
    let mut b = rec_buf.freeze();
    msg.add_ie(ogs_gtp::v2::ie::Gtp2Ie::decode(&mut b).map_err(|e| e.to_string())?);

    Ok(msg)
}

/// Build Modify Bearer Response (TS 29.274 Section 7.2.8)
pub fn build_modify_bearer_response(
    sess: &SgwcSess,
    sequence_number: u32,
    cause: u8,
) -> Result<Gtp2Message, String> {
    let ctx = sgwc_self();
    let sgwc_ue = ctx
        .ue_find_by_id(sess.sgwc_ue_id)
        .ok_or_else(|| "UE not found".to_string())?;

    let mut msg = new_message(
        Gtp2MessageType::ModifyBearerResponse,
        sgwc_ue.mme_s11_teid,
        sequence_number,
    );

    // Cause (M)
    msg.add_ie(Gtp2CauseIe::new(cause).to_ie(0));

    // Bearer Contexts modified (C, instance 0)
    if cause == gtp_cause::REQUEST_ACCEPTED {
        for bearer_id in &sess.bearer_ids {
            let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) else {
                continue;
            };
            let mut bc = Gtp2BearerContextIe::new();
            bc.set_ebi(bearer.ebi);
            bc.set_cause(&Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED));
            if let Some(ul_tunnel) = ctx.ul_tunnel_in_bearer(bearer.id) {
                if let Ok(ft) = fteid_from_tunnel(f_teid_interface::S1_U_SGW_GTP_U, &ul_tunnel) {
                    bc.set_fteid(0, &ft);
                }
            }
            msg.add_bearer_context(0, &bc);
        }
    }

    Ok(msg)
}

/// Build Delete Session Response (TS 29.274 Section 7.2.10)
pub fn build_delete_session_response(
    mme_s11_teid: u32,
    sequence_number: u32,
    cause: u8,
) -> Gtp2Message {
    build_error_response(
        Gtp2MessageType::DeleteSessionResponse as u8,
        mme_s11_teid,
        sequence_number,
        cause,
        None,
    )
}

/// Build Release Access Bearers Response (TS 29.274 Section 7.2.22)
pub fn build_release_access_bearers_response(
    mme_s11_teid: u32,
    sequence_number: u32,
    cause: u8,
) -> Gtp2Message {
    build_error_response(
        Gtp2MessageType::ReleaseAccessBearersResponse as u8,
        mme_s11_teid,
        sequence_number,
        cause,
        None,
    )
}

/// Build Downlink Data Notification (TS 29.274 Section 7.2.11)
/// `cause` is present only when the DDN is triggered by an Error Indication
/// (per the Cause IE condition in Table 7.2.11-1).
pub fn build_downlink_data_notification(
    bearer: &SgwcBearer,
    sequence_number: u32,
    cause: Option<u8>,
) -> Result<Gtp2Message, String> {
    let ctx = sgwc_self();
    let sgwc_ue = ctx
        .ue_find_by_id(bearer.sgwc_ue_id)
        .ok_or_else(|| "UE not found".to_string())?;

    let mut msg = new_message(
        Gtp2MessageType::DownlinkDataNotification,
        sgwc_ue.mme_s11_teid,
        sequence_number,
    );

    // Cause (C)
    if let Some(cause) = cause {
        msg.add_ie(Gtp2CauseIe::new(cause).to_ie(0));
    }

    // EPS Bearer ID (C, instance 0)
    msg.add_ie(Gtp2EbiIe::new(bearer.ebi).to_ie(0));

    // Allocation/Retention Priority (C, instance 0)
    msg.add_ie(arp_ie(bearer));

    Ok(msg)
}

/// Build Create Indirect Data Forwarding Tunnel Response (TS 29.274 Section 7.2.18)
pub fn build_create_indirect_data_forwarding_tunnel_response(
    sgwc_ue_id: u64,
    sequence_number: u32,
    cause: u8,
) -> Result<Gtp2Message, String> {
    let ctx = sgwc_self();
    let sgwc_ue = ctx
        .ue_find_by_id(sgwc_ue_id)
        .ok_or_else(|| "UE not found".to_string())?;

    let mut msg = new_message(
        Gtp2MessageType::CreateIndirectDataForwardingTunnelResponse,
        sgwc_ue.mme_s11_teid,
        sequence_number,
    );

    // Cause (M)
    msg.add_ie(Gtp2CauseIe::new(cause).to_ie(0));

    // Sender F-TEID (C, instance 0)
    if let Ok(sender) = fteid(
        f_teid_interface::S11_S4_SGW_GTP_C,
        sgwc_ue.sgw_s11_teid,
        ctx.s11_address(),
        None,
    ) {
        msg.add_ie(sender.to_ie(0));
    }

    // Bearer Contexts (C): one per bearer with allocated forwarding tunnels
    if cause == gtp_cause::REQUEST_ACCEPTED {
        for sess_id in &sgwc_ue.sess_ids {
            let Some(sess) = ctx.sess_find_by_id(*sess_id) else {
                continue;
            };
            for bearer_id in &sess.bearer_ids {
                let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) else {
                    continue;
                };
                let mut bc = Gtp2BearerContextIe::new();
                bc.set_ebi(bearer.ebi);
                bc.set_cause(&Gtp2CauseIe::new(gtp_cause::REQUEST_ACCEPTED));

                // DL / UL data forwarding F-TEIDs when tunnels exist
                for tunnel_id in &bearer.tunnel_ids {
                    let Some(tunnel) = ctx.tunnel_find_by_id(*tunnel_id) else {
                        continue;
                    };
                    match tunnel.interface_type {
                        crate::context::gtp_interface::SGW_GTP_U_DL_DATA_FORWARDING => {
                            if let Ok(ft) = fteid_from_tunnel(
                                f_teid_interface::SGW_GTP_U_DL_DATA_FORWARDING,
                                &tunnel,
                            ) {
                                bc.set_fteid(0, &ft);
                            }
                        }
                        crate::context::gtp_interface::SGW_GTP_U_UL_DATA_FORWARDING => {
                            if let Ok(ft) = fteid_from_tunnel(
                                f_teid_interface::SGW_GTP_U_UL_DATA_FORWARDING,
                                &tunnel,
                            ) {
                                bc.set_fteid(1, &ft);
                            }
                        }
                        _ => {}
                    }
                }
                msg.add_bearer_context(0, &bc);
            }
        }
    }

    Ok(msg)
}

/// Build Delete Indirect Data Forwarding Tunnel Response (TS 29.274 Section 7.2.20)
pub fn build_delete_indirect_data_forwarding_tunnel_response(
    mme_s11_teid: u32,
    sequence_number: u32,
    cause: u8,
) -> Gtp2Message {
    build_error_response(
        Gtp2MessageType::DeleteIndirectDataForwardingTunnelResponse as u8,
        mme_s11_teid,
        sequence_number,
        cause,
        None,
    )
}

// ============================================================================
// S5-C Messages (SGW-C -> PGW-C)
// ============================================================================

/// Build Create Session Request toward the PGW (TS 29.274 Section 7.2.1)
/// Port of sgwc_s5c_build_create_session_request
pub fn build_s5c_create_session_request(
    sess: &SgwcSess,
    sequence_number: u32,
) -> Result<Gtp2Message, String> {
    let ctx = sgwc_self();
    let sgwc_ue = ctx
        .ue_find_by_id(sess.sgwc_ue_id)
        .ok_or_else(|| "UE not found".to_string())?;

    // Initial request: peer TEID is zero until the PGW allocates one
    let mut msg = new_message(
        Gtp2MessageType::CreateSessionRequest,
        sess.pgw_s5c_teid,
        sequence_number,
    );

    // IMSI (C, instance 0)
    if !sgwc_ue.imsi.is_empty() {
        msg.add_ie(ogs_gtp::v2::ie::Gtp2Ie::from_slice(
            Gtp2IeType::Imsi as u8,
            0,
            &sgwc_ue.imsi,
        ));
    }

    // RAT Type (M, instance 0)
    let rat = if sgwc_ue.rat_type != 0 {
        sgwc_ue.rat_type
    } else {
        rat_type::EUTRAN
    };
    let mut rat_buf = bytes::BytesMut::new();
    Gtp2RatTypeIe::new(rat).encode(&mut rat_buf, 0);
    let mut b = rat_buf.freeze();
    msg.add_ie(ogs_gtp::v2::ie::Gtp2Ie::decode(&mut b).map_err(|e| e.to_string())?);

    // Sender F-TEID for control plane (M, instance 0): S5/S8 SGW GTP-C
    msg.add_ie(
        fteid(
            f_teid_interface::S5_S8_SGW_GTP_C,
            sess.sgw_s5c_teid,
            ctx.s11_address(),
            None,
        )?
        .to_ie(0),
    );

    // APN (M, instance 0)
    let apn = sess.apn().ok_or_else(|| "Session has no APN".to_string())?;
    let mut apn_buf = bytes::BytesMut::new();
    Gtp2ApnIe::from_string(apn).encode(&mut apn_buf, 0);
    let mut b = apn_buf.freeze();
    msg.add_ie(ogs_gtp::v2::ie::Gtp2Ie::decode(&mut b).map_err(|e| e.to_string())?);

    // Selection Mode (C, instance 0)
    let mut sel_buf = bytes::BytesMut::new();
    Gtp2SelectionModeIe::new(0).encode(&mut sel_buf, 0);
    let mut b = sel_buf.freeze();
    msg.add_ie(ogs_gtp::v2::ie::Gtp2Ie::decode(&mut b).map_err(|e| e.to_string())?);

    // PDN Type (C, instance 0)
    if sess.paa.pdn_type != 0 {
        let mut pdn_buf = bytes::BytesMut::new();
        Gtp2PdnTypeIe::new(sess.paa.pdn_type).encode(&mut pdn_buf, 0);
        let mut b = pdn_buf.freeze();
        msg.add_ie(ogs_gtp::v2::ie::Gtp2Ie::decode(&mut b).map_err(|e| e.to_string())?);
    }

    // PAA (C, instance 0)
    if let Some(paa) = paa_ie(sess) {
        msg.add_ie(paa.to_ie(0));
    }

    // APN-AMBR (C, instance 0)
    let mut ambr_buf = bytes::BytesMut::new();
    Gtp2AmbrIe::new(sess.ambr_ul, sess.ambr_dl).encode(&mut ambr_buf, 0);
    let mut b = ambr_buf.freeze();
    msg.add_ie(ogs_gtp::v2::ie::Gtp2Ie::decode(&mut b).map_err(|e| e.to_string())?);

    // Bearer Contexts to be created (M, instance 0)
    let mut bearer_count = 0;
    for bearer_id in &sess.bearer_ids {
        let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) else {
            continue;
        };
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(bearer.ebi);
        bc.set_bearer_qos(&bearer_qos_ie(&bearer));
        // S5/S8-U SGW F-TEID (instance 2): downlink tunnel local endpoint
        if let Some(dl_tunnel) = ctx.dl_tunnel_in_bearer(bearer.id) {
            if let Ok(ft) = fteid_from_tunnel(f_teid_interface::S5_S8_SGW_GTP_U, &dl_tunnel) {
                bc.set_fteid(2, &ft);
            }
        }
        msg.add_bearer_context(0, &bc);
        bearer_count += 1;
    }
    if bearer_count == 0 {
        return Err("Create Session Request requires at least one bearer context".to_string());
    }

    Ok(msg)
}

/// Build Modify Bearer Request toward the PGW (TS 29.274 Section 7.2.7)
pub fn build_s5c_modify_bearer_request(
    sess: &SgwcSess,
    sequence_number: u32,
) -> Result<Gtp2Message, String> {
    let ctx = sgwc_self();

    let mut msg = new_message(
        Gtp2MessageType::ModifyBearerRequest,
        sess.pgw_s5c_teid,
        sequence_number,
    );

    // Bearer Contexts to be modified (C, instance 0)
    let mut bearer_count = 0;
    for bearer_id in &sess.bearer_ids {
        let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) else {
            continue;
        };
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(bearer.ebi);
        if let Some(dl_tunnel) = ctx.dl_tunnel_in_bearer(bearer.id) {
            if let Ok(ft) = fteid_from_tunnel(f_teid_interface::S5_S8_SGW_GTP_U, &dl_tunnel) {
                bc.set_fteid(2, &ft);
            }
        }
        msg.add_bearer_context(0, &bc);
        bearer_count += 1;
    }
    if bearer_count == 0 {
        return Err("Modify Bearer Request requires at least one bearer context".to_string());
    }

    Ok(msg)
}

/// Build Delete Session Request toward the PGW (TS 29.274 Section 7.2.9)
pub fn build_s5c_delete_session_request(
    sess: &SgwcSess,
    sequence_number: u32,
) -> Result<Gtp2Message, String> {
    let ctx = sgwc_self();

    let mut msg = new_message(
        Gtp2MessageType::DeleteSessionRequest,
        sess.pgw_s5c_teid,
        sequence_number,
    );

    // Linked EPS Bearer ID (C, instance 0): default bearer
    let default_bearer = ctx
        .default_bearer_in_sess(sess.id)
        .ok_or_else(|| "Session has no default bearer".to_string())?;
    msg.add_ie(Gtp2EbiIe::new(default_bearer.ebi).to_ie(0));

    // Indication flags: Operation Indication (C)
    msg.add_ie(
        Gtp2IndicationIe {
            oi: true,
            ..Default::default()
        }
        .to_ie(0),
    );

    Ok(msg)
}

/// Build Create Bearer Response toward the PGW (TS 29.274 Section 7.2.4)
pub fn build_s5c_create_bearer_response(
    sess: &SgwcSess,
    sequence_number: u32,
    cause: u8,
) -> Result<Gtp2Message, String> {
    let ctx = sgwc_self();

    let mut msg = new_message(
        Gtp2MessageType::CreateBearerResponse,
        sess.pgw_s5c_teid,
        sequence_number,
    );

    // Cause (M)
    msg.add_ie(Gtp2CauseIe::new(cause).to_ie(0));

    // Bearer Contexts (M, instance 0)
    for bearer_id in &sess.bearer_ids {
        let Some(bearer) = ctx.bearer_find_by_id(*bearer_id) else {
            continue;
        };
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(bearer.ebi);
        bc.set_cause(&Gtp2CauseIe::new(cause));
        if let Some(dl_tunnel) = ctx.dl_tunnel_in_bearer(bearer.id) {
            if let Ok(ft) = fteid_from_tunnel(f_teid_interface::S5_S8_SGW_GTP_U, &dl_tunnel) {
                bc.set_fteid(2, &ft);
            }
        }
        msg.add_bearer_context(0, &bc);
    }

    Ok(msg)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    /// Create a UE + session + bearer in the global context with realistic
    /// addressing, returning (ue_id, sess). IMSIs must be unique per test.
    fn provision(imsi: &[u8]) -> (u64, SgwcSess) {
        let ctx = sgwc_self();
        ctx.set_s11_address(Some(Ipv4Addr::new(10, 11, 0, 5)));

        let ue = ctx.ue_add(imsi).unwrap();
        let mut ue = ctx.ue_find_by_id(ue.id).unwrap();
        ue.mme_s11_teid = 0x0a0b0c0d;
        ue.rat_type = rat_type::EUTRAN;
        ctx.ue_update(&ue);

        let sess = ctx.sess_add(ue.id, "internet").unwrap();
        let mut sess = ctx.sess_find_by_id(sess.id).unwrap();
        sess.paa.pdn_type = 1;
        sess.paa.ipv4_addr = Some(Ipv4Addr::new(10, 45, 0, 2));
        sess.ambr_ul = 1_000_000;
        sess.ambr_dl = 2_000_000;
        ctx.sess_update(&sess);

        let bearer = ctx.bearer_add(sess.id).unwrap();
        let mut bearer = ctx.bearer_find_by_id(bearer.id).unwrap();
        bearer.ebi = 5;
        bearer.qci = 9;
        bearer.arp_priority_level = 8;
        ctx.bearer_update(&bearer);

        // Give both tunnels local endpoints as the dispatcher would
        for tunnel_id in &bearer.tunnel_ids {
            let mut tunnel = ctx.tunnel_find_by_id(*tunnel_id).unwrap();
            tunnel.local_teid = 0x100 + *tunnel_id as u32;
            tunnel.local_addr = Some(Ipv4Addr::new(10, 11, 0, 7));
            ctx.tunnel_update(&tunnel);
        }

        let sess = ctx.sess_find_by_id(sess.id).unwrap();
        (ue.id, sess)
    }

    fn round_trip(msg: &Gtp2Message) -> Gtp2Message {
        let encoded = msg.encode();
        let mut bytes: Bytes = encoded.freeze();
        Gtp2Message::decode(&mut bytes).unwrap()
    }

    #[test]
    fn test_create_session_response_round_trip() {
        let (_, sess) = provision(&[0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x01]);
        let msg = build_create_session_response(&sess, 0x123456, 7).unwrap();
        let decoded = round_trip(&msg);

        assert_eq!(
            decoded.header.message_type,
            Gtp2MessageType::CreateSessionResponse as u8
        );
        assert_eq!(decoded.header.teid, Some(0x0a0b0c0d));
        assert_eq!(decoded.header.sequence_number, 0x123456);

        // Cause M
        let cause_ie = decoded.get_ie(Gtp2IeType::Cause as u8, 0).unwrap();
        assert_eq!(
            Gtp2CauseIe::decode(&cause_ie.value).unwrap().cause,
            gtp_cause::REQUEST_ACCEPTED
        );

        // Sender F-TEID (S11/S4 SGW GTP-C)
        let fteid_ie = decoded.get_ie(Gtp2IeType::FTeid as u8, 0).unwrap();
        let ft = Gtp2FTeidIe::decode(&fteid_ie.value).unwrap();
        assert_eq!(ft.interface_type, f_teid_interface::S11_S4_SGW_GTP_C);
        assert_eq!(ft.ipv4_addr, Some([10, 11, 0, 5]));
        assert_ne!(ft.teid, 0);

        // PAA
        let paa_raw = decoded.get_ie(Gtp2IeType::Paa as u8, 0).unwrap();
        let paa = Gtp2PaaIe::decode(&paa_raw.value).unwrap();
        assert_eq!(paa.ipv4_addr, Some([10, 45, 0, 2]));

        // Bearer Context M with EBI + Cause + S1-U SGW F-TEID
        let bc = decoded.bearer_context(0).unwrap().unwrap();
        assert_eq!(bc.ebi().unwrap(), 5);
        assert_eq!(
            bc.cause().unwrap().unwrap().cause,
            gtp_cause::REQUEST_ACCEPTED
        );
        let s1u = bc.fteid(0).unwrap().unwrap();
        assert_eq!(s1u.interface_type, f_teid_interface::S1_U_SGW_GTP_U);
        assert_ne!(s1u.teid, 0);
        assert!(s1u.ipv4_addr.is_some());

        // Recovery
        assert!(decoded.get_ie(Gtp2IeType::Recovery as u8, 0).is_some());
    }

    #[test]
    fn test_modify_bearer_response_round_trip() {
        let (_, sess) = provision(&[0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02]);
        let msg = build_modify_bearer_response(&sess, 2, gtp_cause::REQUEST_ACCEPTED).unwrap();
        let decoded = round_trip(&msg);

        assert_eq!(
            decoded.header.message_type,
            Gtp2MessageType::ModifyBearerResponse as u8
        );
        let cause_ie = decoded.get_ie(Gtp2IeType::Cause as u8, 0).unwrap();
        assert_eq!(
            Gtp2CauseIe::decode(&cause_ie.value).unwrap().cause,
            gtp_cause::REQUEST_ACCEPTED
        );
        let bc = decoded.bearer_context(0).unwrap().unwrap();
        assert_eq!(bc.ebi().unwrap(), 5);
        assert!(bc.cause().unwrap().is_some());
    }

    #[test]
    fn test_modify_bearer_response_reject_has_no_bearer_context() {
        let (_, sess) = provision(&[0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x03]);
        let msg = build_modify_bearer_response(&sess, 3, gtp_cause::CONTEXT_NOT_FOUND).unwrap();
        let decoded = round_trip(&msg);
        assert_eq!(
            Gtp2CauseIe::decode(&decoded.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                .unwrap()
                .cause,
            gtp_cause::CONTEXT_NOT_FOUND
        );
        assert!(decoded.bearer_context(0).unwrap().is_none());
    }

    #[test]
    fn test_delete_session_response_round_trip() {
        let msg = build_delete_session_response(0xABCD, 4, gtp_cause::REQUEST_ACCEPTED);
        let decoded = round_trip(&msg);
        assert_eq!(
            decoded.header.message_type,
            Gtp2MessageType::DeleteSessionResponse as u8
        );
        assert_eq!(decoded.header.teid, Some(0xABCD));
        assert_eq!(
            Gtp2CauseIe::decode(&decoded.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                .unwrap()
                .cause,
            gtp_cause::REQUEST_ACCEPTED
        );
    }

    #[test]
    fn test_release_access_bearers_response_round_trip() {
        let msg = build_release_access_bearers_response(0x42, 5, gtp_cause::REQUEST_ACCEPTED);
        let decoded = round_trip(&msg);
        assert_eq!(
            decoded.header.message_type,
            Gtp2MessageType::ReleaseAccessBearersResponse as u8
        );
    }

    #[test]
    fn test_downlink_data_notification_round_trip() {
        let (_, sess) = provision(&[0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x04]);
        let ctx = sgwc_self();
        let bearer = ctx.bearer_find_by_id(sess.bearer_ids[0]).unwrap();

        // Normal DDN: no Cause IE
        let msg = build_downlink_data_notification(&bearer, 6, None).unwrap();
        let decoded = round_trip(&msg);
        assert_eq!(
            decoded.header.message_type,
            Gtp2MessageType::DownlinkDataNotification as u8
        );
        assert!(decoded.get_ie(Gtp2IeType::Cause as u8, 0).is_none());
        let ebi_ie = decoded.get_ie(Gtp2IeType::Ebi as u8, 0).unwrap();
        assert_eq!(Gtp2EbiIe::decode(&ebi_ie.value).unwrap().ebi, 5);
        let arp = decoded.get_ie(Gtp2IeType::Arp as u8, 0).unwrap();
        assert_eq!(arp.value[0] >> 2 & 0x0F, 8); // priority level

        // Error-indication-triggered DDN carries Cause
        let msg = build_downlink_data_notification(
            &bearer,
            7,
            Some(gtp_cause::ERROR_INDICATION_FROM_RNC_ENODEB),
        )
        .unwrap();
        let decoded = round_trip(&msg);
        assert!(decoded.get_ie(Gtp2IeType::Cause as u8, 0).is_some());
    }

    #[test]
    fn test_indirect_tunnel_responses_round_trip() {
        let (ue_id, _) = provision(&[0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x05]);
        let msg = build_create_indirect_data_forwarding_tunnel_response(
            ue_id,
            8,
            gtp_cause::REQUEST_ACCEPTED,
        )
        .unwrap();
        let decoded = round_trip(&msg);
        assert_eq!(
            decoded.header.message_type,
            Gtp2MessageType::CreateIndirectDataForwardingTunnelResponse as u8
        );
        assert!(decoded.get_ie(Gtp2IeType::Cause as u8, 0).is_some());

        let msg = build_delete_indirect_data_forwarding_tunnel_response(
            0x77,
            9,
            gtp_cause::REQUEST_ACCEPTED,
        );
        let decoded = round_trip(&msg);
        assert_eq!(
            decoded.header.message_type,
            Gtp2MessageType::DeleteIndirectDataForwardingTunnelResponse as u8
        );
    }

    #[test]
    fn test_error_response_with_offending_ie() {
        let msg = build_error_response(
            Gtp2MessageType::CreateSessionResponse as u8,
            0,
            10,
            gtp_cause::MANDATORY_IE_MISSING,
            Some(Gtp2IeType::Imsi as u8),
        );
        let decoded = round_trip(&msg);
        let cause = Gtp2CauseIe::decode(&decoded.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
            .unwrap();
        assert_eq!(cause.cause, gtp_cause::MANDATORY_IE_MISSING);
        assert_eq!(cause.offending_ie_type, Some(Gtp2IeType::Imsi as u8));
    }

    #[test]
    fn test_s5c_create_session_request_round_trip() {
        let (_, sess) = provision(&[0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x06]);
        let msg = build_s5c_create_session_request(&sess, 11).unwrap();
        let decoded = round_trip(&msg);

        assert_eq!(
            decoded.header.message_type,
            Gtp2MessageType::CreateSessionRequest as u8
        );
        // Mandatory IEs per TS 29.274 Table 7.2.1-1
        assert!(decoded.get_ie(Gtp2IeType::Imsi as u8, 0).is_some());
        assert!(decoded.get_ie(Gtp2IeType::RatType as u8, 0).is_some());
        assert!(decoded.get_ie(Gtp2IeType::FTeid as u8, 0).is_some());
        assert!(decoded.get_ie(Gtp2IeType::Apn as u8, 0).is_some());
        let bc = decoded.bearer_context(0).unwrap().unwrap();
        assert_eq!(bc.ebi().unwrap(), 5);
        let qos = bc.bearer_qos().unwrap().unwrap();
        assert_eq!(qos.qci, 9);
        assert_eq!(qos.pl, 8);
        let s5u = bc.fteid(2).unwrap().unwrap();
        assert_eq!(s5u.interface_type, f_teid_interface::S5_S8_SGW_GTP_U);
    }

    #[test]
    fn test_s5c_delete_session_request_round_trip() {
        let (_, sess) = provision(&[0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x07]);
        let msg = build_s5c_delete_session_request(&sess, 12).unwrap();
        let decoded = round_trip(&msg);
        assert_eq!(
            decoded.header.message_type,
            Gtp2MessageType::DeleteSessionRequest as u8
        );
        let ebi = decoded.get_ie(Gtp2IeType::Ebi as u8, 0).unwrap();
        assert_eq!(Gtp2EbiIe::decode(&ebi.value).unwrap().ebi, 5);
        let ind = decoded.get_ie(Gtp2IeType::Indication as u8, 0).unwrap();
        assert!(Gtp2IndicationIe::decode(&ind.value).unwrap().oi);
    }

    #[test]
    fn test_s5c_modify_bearer_and_create_bearer_response_round_trip() {
        let (_, sess) = provision(&[0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x08]);

        let msg = build_s5c_modify_bearer_request(&sess, 13).unwrap();
        let decoded = round_trip(&msg);
        assert_eq!(
            decoded.header.message_type,
            Gtp2MessageType::ModifyBearerRequest as u8
        );
        assert!(decoded.bearer_context(0).unwrap().is_some());

        let msg = build_s5c_create_bearer_response(&sess, 14, gtp_cause::REQUEST_ACCEPTED).unwrap();
        let decoded = round_trip(&msg);
        assert_eq!(
            decoded.header.message_type,
            Gtp2MessageType::CreateBearerResponse as u8
        );
        let bc = decoded.bearer_context(0).unwrap().unwrap();
        assert!(bc.cause().unwrap().is_some());
    }
}
