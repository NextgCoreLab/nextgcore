//! NGAP ASN.1 Encoding for AMF
//!
//! This module provides ASN.1 APER encoding for NGAP messages
//! using the ogs-ngap crate. This ensures wire compatibility with
//! the gNB (nextgsim-gnb) which also uses proper ASN.1 encoding.

use ogs_asn1c::ngap::cause::{
    Cause, CauseMisc, CauseNas, CauseProtocol, CauseRadioNetwork, CauseTransport,
};
use ogs_ngap::transfer::{
    AllocationAndRetentionPriority, GtpTunnel, NonDynamic5qiDescriptor,
    PduSessionResourceReleaseCommandTransfer, PduSessionResourceSetupRequestTransfer,
    PduSessionResourceSetupResponseTransfer, PduSessionType, PreEmptionCapability,
    PreEmptionVulnerability, QosCharacteristics, QosFlowLevelQosParameters,
    QosFlowSetupRequestItem, TransportLayerAddress, UpTransportLayerInformation,
};
use ogs_ngap::{builder, parser, types::*, NgapMessage};

use crate::context::AmfContext;

/// Build an NG Setup Response PDU with proper ASN.1 APER encoding
///
/// This is sent by AMF to gNB in response to a successful NG Setup Request.
/// The message follows 3GPP TS 38.413 Section 9.2.6.2.
pub fn build_ng_setup_response_asn1(ctx: &AmfContext) -> Option<Vec<u8>> {
    let amf_name = ctx.amf_name.as_deref().unwrap_or("AMF").to_string();

    let served_guami_list = ctx
        .served_guami
        .iter()
        .take(ctx.num_of_served_guami)
        .map(|guami| {
            let plmn_bytes = encode_plmn_id(&guami.plmn_id);
            ServedGuamiItem {
                guami: Guami {
                    plmn_identity: plmn_bytes,
                    amf_region_id: guami.amf_id.region,
                    amf_set_id: guami.amf_id.set,
                    amf_pointer: guami.amf_id.pointer,
                },
                backup_amf_name: None,
            }
        })
        .collect();

    let plmn_support_list = ctx
        .plmn_support
        .iter()
        .take(ctx.num_of_plmn_support)
        .map(|plmn_support| {
            let plmn_bytes = encode_plmn_id(&plmn_support.plmn_id);
            let slice_support_list = plmn_support
                .s_nssai
                .iter()
                .take(plmn_support.num_of_s_nssai)
                .map(|s_nssai| {
                    let sd = s_nssai.sd.map(|sd_val| {
                        [
                            ((sd_val >> 16) & 0xFF) as u8,
                            ((sd_val >> 8) & 0xFF) as u8,
                            (sd_val & 0xFF) as u8,
                        ]
                    });
                    SNssai {
                        sst: s_nssai.sst,
                        sd,
                    }
                })
                .collect();
            PlmnSupportItem {
                plmn_identity: plmn_bytes,
                slice_support_list,
            }
        })
        .collect();

    let msg = NgSetupResponse {
        amf_name,
        served_guami_list,
        relative_amf_capacity: ctx.relative_capacity,
        plmn_support_list,
    };

    match builder::build_ng_setup_response(&msg) {
        Ok(bytes) => {
            log::debug!(
                "Built NG Setup Response: {} bytes, hex: {:02x?}",
                bytes.len(),
                &bytes[..bytes.len().min(32)]
            );
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode NG Setup Response: {e:?}");
            None
        }
    }
}

/// Build an NG Setup Failure PDU with proper ASN.1 APER encoding
///
/// This is sent by AMF to gNB when NG Setup fails.
/// The message follows 3GPP TS 38.413 Section 9.2.6.3.
pub fn build_ng_setup_failure_asn1(
    cause_group: u8,
    cause_value: i64,
    time_to_wait: Option<u8>,
) -> Vec<u8> {
    let cause = build_cause(cause_group, cause_value);

    let ttw = time_to_wait.map(|ttw| match ttw {
        0 => TimeToWait::V1s,
        1 => TimeToWait::V2s,
        2 => TimeToWait::V5s,
        3 => TimeToWait::V10s,
        4 => TimeToWait::V20s,
        _ => TimeToWait::V60s,
    });

    let msg = NgSetupFailure {
        cause,
        time_to_wait: ttw,
        criticality_diagnostics: None,
    };

    match builder::build_ng_setup_failure(&msg) {
        Ok(bytes) => {
            log::debug!("Built NG Setup Failure: {} bytes", bytes.len());
            bytes
        }
        Err(e) => {
            log::error!("Failed to encode NG Setup Failure: {e:?}");
            Vec::new()
        }
    }
}

/// Build Cause from group and value
fn build_cause(group: u8, value: i64) -> Cause {
    match group {
        0 => Cause::RadioNetwork(radio_network_cause(value as u8)),
        1 => Cause::Transport(transport_cause(value as u8)),
        2 => Cause::Nas(nas_cause(value as u8)),
        3 => Cause::Protocol(protocol_cause(value as u8)),
        4 => Cause::Misc(misc_cause(value as u8)),
        _ => Cause::Misc(CauseMisc::Unspecified),
    }
}

fn radio_network_cause(v: u8) -> CauseRadioNetwork {
    // Safe conversion via the library's TryFrom; unknown values map to the
    // 3GPP "unspecified" fallback rather than invoking undefined behaviour.
    CauseRadioNetwork::try_from(v as i64).unwrap_or(CauseRadioNetwork::Unspecified)
}

fn transport_cause(v: u8) -> CauseTransport {
    match v {
        0 => CauseTransport::TransportResourceUnavailable,
        _ => CauseTransport::Unspecified,
    }
}

fn nas_cause(v: u8) -> CauseNas {
    match v {
        0 => CauseNas::NormalRelease,
        1 => CauseNas::AuthenticationFailure,
        2 => CauseNas::Deregister,
        _ => CauseNas::Unspecified,
    }
}

fn protocol_cause(v: u8) -> CauseProtocol {
    // Safe conversion via the library's TryFrom; unknown values map to the
    // 3GPP "unspecified" fallback rather than invoking undefined behaviour.
    CauseProtocol::try_from(v as i64).unwrap_or(CauseProtocol::Unspecified)
}

fn misc_cause(v: u8) -> CauseMisc {
    // Safe conversion via the library's TryFrom; unknown values map to the
    // 3GPP "unspecified" fallback rather than invoking undefined behaviour.
    CauseMisc::try_from(v as i64).unwrap_or(CauseMisc::Unspecified)
}

/// Encode PLMN ID to 3-byte format per 3GPP TS 24.501
fn encode_plmn_id(plmn_id: &crate::context::PlmnId) -> [u8; 3] {
    let mut bytes = [0u8; 3];

    // Byte 0: MCC digit 2 (high nibble) | MCC digit 1 (low nibble)
    bytes[0] = (plmn_id.mcc2 << 4) | plmn_id.mcc1;

    // Byte 1: MNC digit 3 (high nibble) | MCC digit 3 (low nibble)
    // For 2-digit MNC, MNC digit 3 is 0xF
    bytes[1] = (plmn_id.mnc3 << 4) | plmn_id.mcc3;

    // Byte 2: MNC digit 2 (high nibble) | MNC digit 1 (low nibble)
    bytes[2] = (plmn_id.mnc2 << 4) | plmn_id.mnc1;

    bytes
}

/// Decode PLMN ID from 3 bytes
fn decode_plmn_id(bytes: &[u8]) -> crate::context::PlmnId {
    if bytes.len() < 3 {
        return crate::context::PlmnId::default();
    }

    crate::context::PlmnId {
        mcc1: bytes[0] & 0x0F,
        mcc2: (bytes[0] >> 4) & 0x0F,
        mcc3: bytes[1] & 0x0F,
        mnc1: bytes[2] & 0x0F,
        mnc2: (bytes[2] >> 4) & 0x0F,
        mnc3: (bytes[1] >> 4) & 0x0F,
    }
}

/// Decode an NG Setup Request from ASN.1 APER bytes
pub fn parse_ng_setup_request_asn1(data: &[u8]) -> Option<crate::ngap_handler::NgSetupRequest> {
    let decoded = match parser::decode_ngap_pdu(data) {
        Ok(msg) => msg,
        Err(e) => {
            log::error!("Failed to decode NGAP PDU: {e:?}");
            return None;
        }
    };

    let req = match decoded {
        NgapMessage::NgSetupRequest(r) => r,
        _ => {
            log::error!("Expected NgSetupRequest");
            return None;
        }
    };

    let mut result = crate::ngap_handler::NgSetupRequest::default();
    result.global_ran_node_id_present = true;

    match &req.global_ran_node_id {
        GlobalRanNodeId::GlobalGnbId {
            plmn_identity,
            gnb_id,
            gnb_id_len,
        } => {
            result.plmn_id = decode_plmn_id(plmn_identity);
            result.gnb_id = *gnb_id;
            result.gnb_id_len = *gnb_id_len;
        }
        GlobalRanNodeId::GlobalNgEnbId { plmn_identity, .. } => {
            result.plmn_id = decode_plmn_id(plmn_identity);
        }
    }

    if let Some(name) = req.ran_node_name {
        result.ran_node_name = Some(name);
    }

    result.supported_ta_list = req
        .supported_ta_list
        .iter()
        .map(|ta_item| {
            let tac = ((ta_item.tac[0] as u32) << 16)
                | ((ta_item.tac[1] as u32) << 8)
                | (ta_item.tac[2] as u32);

            let bplmn_list: Vec<crate::context::BplmnEntry> = ta_item
                .broadcast_plmn_list
                .iter()
                .map(|bp| {
                    let plmn_id = decode_plmn_id(&bp.plmn_identity);
                    let s_nssai: Vec<crate::context::SNssai> = bp
                        .tai_slice_support_list
                        .iter()
                        .map(|slice| crate::context::SNssai {
                            sst: slice.sst,
                            sd: slice.sd.map(|sd| {
                                ((sd[0] as u32) << 16) | ((sd[1] as u32) << 8) | (sd[2] as u32)
                            }),
                        })
                        .collect();
                    crate::context::BplmnEntry {
                        plmn_id,
                        num_of_s_nssai: s_nssai.len(),
                        s_nssai,
                    }
                })
                .collect();

            crate::context::SupportedTa {
                tac,
                num_of_bplmn_list: bplmn_list.len(),
                bplmn_list,
            }
        })
        .collect();

    result.default_paging_drx = req.default_paging_drx as u8;

    Some(result)
}

/// Parsed Initial UE Message data
#[derive(Debug, Clone)]
pub struct InitialUeMessageData {
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// NAS PDU
    pub nas_pdu: Vec<u8>,
    /// PLMN ID from NR-CGI
    pub plmn_id: crate::context::PlmnId,
    /// NR Cell Identity (36 bits)
    pub nr_cell_identity: u64,
    /// TAC from TAI
    pub tac: u32,
    /// RRC Establishment Cause
    pub rrc_establishment_cause: u8,
    /// UE Context Request flag
    pub ue_context_request: bool,
}

/// Parse an Initial UE Message from ASN.1 APER bytes
pub fn parse_initial_ue_message_asn1(data: &[u8]) -> Option<InitialUeMessageData> {
    let decoded = match parser::decode_ngap_pdu(data) {
        Ok(msg) => msg,
        Err(e) => {
            log::error!("Failed to decode NGAP PDU: {e:?}");
            return None;
        }
    };

    let msg = match decoded {
        NgapMessage::InitialUeMessage(m) => m,
        _ => {
            log::error!("Expected InitialUEMessage");
            return None;
        }
    };

    let (plmn_id, nr_cell_identity, tac) = match &msg.user_location_info {
        UserLocationInformation::Nr {
            nr_cgi_plmn,
            nr_cell_identity,
            tai_tac,
            ..
        } => {
            let plmn_id = decode_plmn_id(nr_cgi_plmn);
            let tac =
                ((tai_tac[0] as u32) << 16) | ((tai_tac[1] as u32) << 8) | (tai_tac[2] as u32);
            (plmn_id, *nr_cell_identity, tac)
        }
    };

    let rrc_establishment_cause = msg.rrc_establishment_cause as u8;
    let ue_context_request = msg.ue_context_request.unwrap_or(false);

    log::info!(
        "Parsed Initial UE Message: ran_ue_ngap_id={}, nas_pdu_len={}, plmn={}{}{}-{}{}{}, nci=0x{:x}, tac={}, cause={}",
        msg.ran_ue_ngap_id,
        msg.nas_pdu.len(),
        plmn_id.mcc1, plmn_id.mcc2, plmn_id.mcc3,
        plmn_id.mnc1, plmn_id.mnc2, if plmn_id.mnc3 == 0xF { "".to_string() } else { format!("{}", plmn_id.mnc3) },
        nr_cell_identity,
        tac,
        rrc_establishment_cause
    );

    Some(InitialUeMessageData {
        ran_ue_ngap_id: msg.ran_ue_ngap_id,
        nas_pdu: msg.nas_pdu,
        plmn_id,
        nr_cell_identity,
        tac,
        rrc_establishment_cause,
        ue_context_request,
    })
}

/// Build a Downlink NAS Transport PDU with proper ASN.1 APER encoding
///
/// This is sent by AMF to gNB to deliver NAS messages to the UE.
/// The message follows 3GPP TS 38.413 Section 8.6.2.
pub fn build_downlink_nas_transport_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    nas_pdu: &[u8],
) -> Option<Vec<u8>> {
    let msg = DownlinkNasTransport {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        nas_pdu: nas_pdu.to_vec(),
    };

    match builder::build_downlink_nas_transport(&msg) {
        Ok(bytes) => {
            log::debug!(
                "Built Downlink NAS Transport: {} bytes, amf_ue_ngap_id={}, ran_ue_ngap_id={}, nas_pdu_len={}",
                bytes.len(),
                amf_ue_ngap_id,
                ran_ue_ngap_id,
                nas_pdu.len()
            );
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode Downlink NAS Transport: {e:?}");
            None
        }
    }
}

/// Build a PDU Session Resource Setup Request with proper ASN.1 APER encoding
///
/// This is sent by AMF to gNB to establish PDU session resources.
/// The message follows 3GPP TS 38.413 Section 8.2.1.
pub fn build_pdu_session_resource_setup_request_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    pdu_session_id: u8,
    s_nssai_sst: u8,
    s_nssai_sd: Option<u32>,
    nas_pdu: Option<&[u8]>,
    n2_sm_transfer: &[u8],
) -> Option<Vec<u8>> {
    let sd = s_nssai_sd.map(|sd_val| {
        [
            ((sd_val >> 16) & 0xFF) as u8,
            ((sd_val >> 8) & 0xFF) as u8,
            (sd_val & 0xFF) as u8,
        ]
    });

    let item = PduSessionResourceSetupItem {
        pdu_session_id,
        nas_pdu: None,
        s_nssai: SNssai {
            sst: s_nssai_sst,
            sd,
        },
        transfer: n2_sm_transfer.to_vec(),
    };

    let msg = PduSessionResourceSetupRequest {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        pdu_session_list: vec![item],
        nas_pdu: nas_pdu.map(|p| p.to_vec()),
    };

    match builder::build_pdu_session_resource_setup_request(&msg) {
        Ok(bytes) => {
            log::debug!(
                "Built PDU Session Resource Setup Request: {} bytes, amf_ue_ngap_id={}, psi={}",
                bytes.len(),
                amf_ue_ngap_id,
                pdu_session_id
            );
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode PDU Session Resource Setup Request: {e:?}");
            None
        }
    }
}

/// Convert an AMF-context S-NSSAI (SD packed as a u32) to the ogs-ngap wire
/// S-NSSAI (SD as a 3-byte big-endian array).
fn amf_snssai_to_ngap(s: &crate::context::SNssai) -> SNssai {
    SNssai {
        sst: s.sst,
        sd: s.sd.map(|sd_val| {
            [
                ((sd_val >> 16) & 0xFF) as u8,
                ((sd_val >> 8) & 0xFF) as u8,
                (sd_val & 0xFF) as u8,
            ]
        }),
    }
}

/// Map the 8-bit replayed NAS UE security capability octet (TS 24.501
/// §9.11.3.54, bit 8 = algorithm 0) onto the 16-bit NGAP BIT STRING field
/// (TS 38.413 §9.3.1.86), where algorithm 0 is the most significant bit. The
/// NAS octet maps verbatim onto the top 8 bits of the 16-bit field.
fn nas_caps_octet_to_ngap_bits(octet: u8) -> u16 {
    (octet as u16) << 8
}

/// Build an Initial Context Setup Request with proper ASN.1 APER encoding
/// (TS 38.413 §8.3.1 / §9.2.2.1).
///
/// The GUAMI is taken from the AMF's first served GUAMI. The replayed UE
/// security capabilities and KgNB (the UE Security Key) come from the live
/// AMF UE security context — nothing is hardcoded. The protected initial
/// Registration Accept rides inside the request as the NAS-PDU
/// (TS 23.502 §4.2.2.2.2 step 16).
#[allow(clippy::too_many_arguments)]
pub fn build_initial_context_setup_request_asn1(
    ctx: &AmfContext,
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    allowed_nssai: &[crate::context::SNssai],
    ue_security_capability: &crate::context::UeSecurityCapability,
    security_key: &[u8; 32],
    nas_pdu: Option<&[u8]>,
    ue_ambr: Option<(u64, u64)>,
) -> Option<Vec<u8>> {
    // GUAMI (mandatory): the AMF's first served GUAMI.
    let served = ctx.served_guami.first()?;
    let guami = Guami {
        plmn_identity: encode_plmn_id(&served.plmn_id),
        amf_region_id: served.amf_id.region,
        amf_set_id: served.amf_id.set,
        amf_pointer: served.amf_id.pointer,
    };

    let allowed: Vec<SNssai> = allowed_nssai.iter().map(amf_snssai_to_ngap).collect();

    // Replayed UE security capabilities (TS 38.413 §9.3.1.86). 5G fields carry
    // the verbatim NAS algorithm octets; E-UTRA fields carry the EEA/EIA octets.
    let ue_security_capabilities = UeSecurityCapabilities {
        nr_encryption_algorithms: nas_caps_octet_to_ngap_bits(ue_security_capability.ea),
        nr_integrity_algorithms: nas_caps_octet_to_ngap_bits(ue_security_capability.ia),
        eutra_encryption_algorithms: nas_caps_octet_to_ngap_bits(ue_security_capability.eea),
        eutra_integrity_algorithms: nas_caps_octet_to_ngap_bits(ue_security_capability.eia),
    };

    let msg = InitialContextSetupRequest {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        guami,
        allowed_nssai: allowed,
        ue_security_capabilities,
        security_key: *security_key,
        nas_pdu: nas_pdu.map(|p| p.to_vec()),
        ue_ambr: ue_ambr.map(|(dl, ul)| UeAmbrInfo { dl, ul }),
    };

    match builder::build_initial_context_setup_request(&msg) {
        Ok(bytes) => {
            log::debug!(
                "Built Initial Context Setup Request: {} bytes, amf_ue_ngap_id={amf_ue_ngap_id}, \
                 ran_ue_ngap_id={ran_ue_ngap_id}, allowed_nssai={}, nas_pdu={}",
                bytes.len(),
                allowed_nssai.len(),
                nas_pdu.map(|p| p.len()).unwrap_or(0)
            );
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode Initial Context Setup Request: {e:?}");
            None
        }
    }
}

/// Decode an Initial Context Setup Response (gNB -> AMF, TS 38.413 §9.2.2.2).
/// Returns (amf_ue_ngap_id, ran_ue_ngap_id) on success.
pub fn parse_initial_context_setup_response_asn1(data: &[u8]) -> Option<(u64, u32)> {
    match parser::decode_ngap_pdu(data) {
        Ok(NgapMessage::InitialContextSetupResponse(resp)) => {
            Some((resp.amf_ue_ngap_id, resp.ran_ue_ngap_id))
        }
        Ok(other) => {
            log::warn!("Expected InitialContextSetupResponse, got {other:?}");
            None
        }
        Err(e) => {
            log::warn!("Failed to decode Initial Context Setup Response: {e:?}");
            None
        }
    }
}

/// Decode an Initial Context Setup Failure (gNB -> AMF, TS 38.413 §9.2.2.3).
/// Returns (amf_ue_ngap_id, ran_ue_ngap_id) on success.
pub fn parse_initial_context_setup_failure_asn1(data: &[u8]) -> Option<(u64, u32)> {
    match parser::decode_ngap_pdu(data) {
        Ok(NgapMessage::InitialContextSetupFailure(fail)) => {
            Some((fail.amf_ue_ngap_id, fail.ran_ue_ngap_id))
        }
        Ok(other) => {
            log::warn!("Expected InitialContextSetupFailure, got {other:?}");
            None
        }
        Err(e) => {
            log::warn!("Failed to decode Initial Context Setup Failure: {e:?}");
            None
        }
    }
}

/// Build a PDU Session Resource Release Command with proper ASN.1 APER encoding
///
/// Sent by AMF to gNB to release PDU session resources.
pub fn build_pdu_session_resource_release_command_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    pdu_session_ids: &[u8],
) -> Option<Vec<u8>> {
    // Per-session PDUSessionResourceReleaseCommandTransfer with mandatory Cause
    // (TS 38.413 Section 9.3.4.11), APER-encoded via ogs-ngap::transfer
    let release_transfer = PduSessionResourceReleaseCommandTransfer {
        cause: Cause::Nas(CauseNas::NormalRelease),
    };
    let transfer_bytes = match release_transfer.encode() {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("Failed to encode PDUSessionResourceReleaseCommandTransfer: {e:?}");
            return None;
        }
    };

    let pdu_session_list = pdu_session_ids
        .iter()
        .map(|&psi| PduSessionResourceReleaseItem {
            pdu_session_id: psi,
            transfer: transfer_bytes.clone(),
        })
        .collect();

    let msg = PduSessionResourceReleaseCommand {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        nas_pdu: None,
        pdu_session_list,
    };

    match builder::build_pdu_session_resource_release_command(&msg) {
        Ok(bytes) => {
            log::debug!(
                "Built PDU Session Resource Release Command: {} bytes, amf_ue_ngap_id={}, psi_count={}",
                bytes.len(), amf_ue_ngap_id, pdu_session_ids.len()
            );
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode PDU Session Resource Release Command: {e:?}");
            None
        }
    }
}

/// Build a PDU Session Resource Modify Request with proper ASN.1 APER encoding
///
/// Sent by AMF to gNB to modify PDU session resources (e.g., QoS changes).
/// The message follows 3GPP TS 38.413 Section 8.2.3.
pub fn build_pdu_session_resource_modify_request_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    pdu_session_id: u8,
    nas_pdu: Option<&[u8]>,
    n2_sm_transfer: &[u8],
) -> Option<Vec<u8>> {
    let item = PduSessionResourceModifyItem {
        pdu_session_id,
        nas_pdu: nas_pdu.map(|p| p.to_vec()),
        transfer: n2_sm_transfer.to_vec(),
    };

    let msg = PduSessionResourceModifyRequest {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        pdu_session_list: vec![item],
    };

    match builder::build_pdu_session_resource_modify_request(&msg) {
        Ok(bytes) => {
            log::debug!(
                "Built PDU Session Resource Modify Request: {} bytes, amf_ue_ngap_id={}, psi={}",
                bytes.len(),
                amf_ue_ngap_id,
                pdu_session_id
            );
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode PDU Session Resource Modify Request: {e:?}");
            None
        }
    }
}

/// Parsed Uplink NAS Transport data
#[derive(Debug, Clone)]
pub struct UplinkNasTransportData {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u32,
    /// NAS PDU
    pub nas_pdu: Vec<u8>,
}

/// Parse an Uplink NAS Transport message from ASN.1 APER bytes
pub fn parse_uplink_nas_transport_asn1(data: &[u8]) -> Option<UplinkNasTransportData> {
    let decoded = match parser::decode_ngap_pdu(data) {
        Ok(msg) => msg,
        Err(e) => {
            log::error!("Failed to decode NGAP PDU: {e:?}");
            return None;
        }
    };

    let msg = match decoded {
        NgapMessage::UplinkNasTransport(m) => m,
        _ => {
            log::error!("Expected UplinkNASTransport");
            return None;
        }
    };

    log::info!(
        "Parsed Uplink NAS Transport: amf_ue_ngap_id={}, ran_ue_ngap_id={}, nas_pdu_len={}",
        msg.amf_ue_ngap_id,
        msg.ran_ue_ngap_id,
        msg.nas_pdu.len()
    );

    Some(UplinkNasTransportData {
        amf_ue_ngap_id: msg.amf_ue_ngap_id,
        ran_ue_ngap_id: msg.ran_ue_ngap_id,
        nas_pdu: msg.nas_pdu,
    })
}

/// Build a Paging message with proper ASN.1 APER encoding
///
/// Sent by AMF to gNBs to page a UE in CM-IDLE state.
/// The message follows 3GPP TS 38.413 Section 8.7.2.
pub fn build_paging_asn1(
    amf_set_id: u16,
    amf_pointer: u8,
    tmsi: u32,
    plmn_id: &crate::context::PlmnId,
    tac: u32,
) -> Option<Vec<u8>> {
    let plmn_bytes = encode_plmn_id(plmn_id);

    let msg = Paging {
        ue_paging_identity: UePagingIdentity::FiveGSTmsi {
            amf_set_id,
            amf_pointer,
            tmsi,
        },
        tai_list: vec![TaiListItem {
            tai_plmn: plmn_bytes,
            tai_tac: [(tac >> 16) as u8, (tac >> 8) as u8, tac as u8],
        }],
        paging_drx: None,
        paging_priority: None,
        ue_radio_capability: None,
        paging_origin: None,
        assistance_data: None,
    };

    match builder::build_paging(&msg) {
        Ok(bytes) => {
            log::debug!(
                "Built Paging: {} bytes, amf_set_id={}, tmsi=0x{:08x}, tac={}",
                bytes.len(),
                amf_set_id,
                tmsi,
                tac
            );
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode Paging: {e:?}");
            None
        }
    }
}

/// Extract AMF UE NGAP ID from a UE Context Release Request
pub fn extract_amf_ue_ngap_id(data: &[u8]) -> Option<u64> {
    match parser::decode_ngap_pdu(data) {
        Ok(NgapMessage::UeContextReleaseRequest(req)) => Some(req.amf_ue_ngap_id),
        Ok(_) => {
            log::warn!("Expected UeContextReleaseRequest");
            None
        }
        Err(e) => {
            log::warn!("Failed to extract AMF UE NGAP ID: {e}");
            None
        }
    }
}

/// Extract RAN UE NGAP ID from a UE Context Release Request
pub fn extract_ran_ue_ngap_id(data: &[u8]) -> Option<u32> {
    match parser::decode_ngap_pdu(data) {
        Ok(NgapMessage::UeContextReleaseRequest(req)) => Some(req.ran_ue_ngap_id),
        Ok(_) => {
            log::warn!("Expected UeContextReleaseRequest");
            None
        }
        Err(e) => {
            log::warn!("Failed to extract RAN UE NGAP ID: {e}");
            None
        }
    }
}

/// Build a UE Context Release Command with proper ASN.1 APER encoding
///
/// `cause_group`/`cause_value` follow the TS 38.413 Section 9.3.1.2 cause groups
/// (0=RadioNetwork, 1=Transport, 2=NAS, 3=Protocol, 4=Misc).
pub fn build_ue_context_release_command_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    cause_group: u8,
    cause_value: i64,
) -> Option<Vec<u8>> {
    let msg = UeContextReleaseCommand {
        ue_ngap_ids: UeNgapIds::Pair {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
        },
        cause: build_cause(cause_group, cause_value),
    };

    match builder::build_ue_context_release_command(&msg) {
        Ok(bytes) => {
            log::debug!(
                "Built UE Context Release Command: {} bytes, AMF UE NGAP ID={}, RAN UE NGAP ID={}",
                bytes.len(),
                amf_ue_ngap_id,
                ran_ue_ngap_id
            );
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode UE Context Release Command: {e}");
            None
        }
    }
}

/// Build an NG Reset Acknowledge with proper ASN.1 APER encoding
///
/// `connections` echoes the UE-associated logical NG-connection list of a
/// partial NG Reset (TS 38.413 Section 8.7.4.2.2); `None` for a full reset.
pub fn build_ng_reset_acknowledge_asn1(
    connections: Option<Vec<UeAssociatedLogicalNgConnectionItem>>,
) -> Option<Vec<u8>> {
    let msg = NgResetAcknowledge {
        connections,
        criticality_diagnostics: None,
    };

    match builder::build_ng_reset_acknowledge(&msg) {
        Ok(bytes) => {
            log::debug!("Built NG Reset Acknowledge: {} bytes", bytes.len());
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode NG Reset Acknowledge: {e:?}");
            None
        }
    }
}

/// Build an APER-encoded PDUSessionResourceSetupRequestTransfer
/// (TS 38.413 Section 9.3.4.1) carrying the UPF N3 tunnel endpoint.
///
/// Used as the N2 SM information container when the AMF must synthesize
/// the transfer itself (SMF-unreachable fallback). The normal path forwards
/// the SMF-produced transfer opaquely.
pub fn build_n2_sm_setup_request_transfer(
    upf_teid: u32,
    upf_addr: [u8; 4],
    qfi: u8,
    five_qi: u16,
    arp_priority_level: u8,
) -> Option<Vec<u8>> {
    let transfer = PduSessionResourceSetupRequestTransfer {
        pdu_session_aggregate_maximum_bit_rate: None,
        ul_ngu_up_tnl_information: UpTransportLayerInformation::GtpTunnel(GtpTunnel {
            transport_layer_address: TransportLayerAddress::from_ipv4(upf_addr),
            gtp_teid: upf_teid.to_be_bytes(),
        }),
        data_forwarding_not_possible: false,
        pdu_session_type: PduSessionType::Ipv4,
        security_indication: None,
        network_instance: None,
        qos_flow_setup_request_list: vec![QosFlowSetupRequestItem {
            qos_flow_identifier: qfi,
            qos_flow_level_qos_parameters: QosFlowLevelQosParameters {
                qos_characteristics: QosCharacteristics::NonDynamic5qi(
                    NonDynamic5qiDescriptor::new(five_qi),
                ),
                allocation_and_retention_priority: AllocationAndRetentionPriority {
                    priority_level_arp: arp_priority_level,
                    pre_emption_capability: PreEmptionCapability::ShallNotTriggerPreEmption,
                    pre_emption_vulnerability: PreEmptionVulnerability::NotPreEmptable,
                },
                gbr_qos_information: None,
                reflective_qos_attribute: false,
                additional_qos_flow_information: false,
            },
            e_rab_id: None,
        }],
    };

    match transfer.encode() {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            log::error!("Failed to encode PDUSessionResourceSetupRequestTransfer: {e:?}");
            None
        }
    }
}

/// gNB DL tunnel endpoint extracted from a setup-response transfer
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnbN3Endpoint {
    /// gNB GTP-U TEID
    pub teid: u32,
    /// gNB transport address (IPv4 when 4 octets)
    pub address: Vec<u8>,
    /// Associated QoS flow identifiers
    pub qfis: Vec<u8>,
}

/// Decode an APER PDUSessionResourceSetupResponseTransfer
/// (TS 38.413 Section 9.3.4.2) and extract the gNB DL N3 endpoint.
pub fn parse_n2_sm_setup_response_transfer(data: &[u8]) -> Option<GnbN3Endpoint> {
    let transfer = match PduSessionResourceSetupResponseTransfer::decode(data) {
        Ok(t) => t,
        Err(e) => {
            log::warn!("Failed to decode PDUSessionResourceSetupResponseTransfer: {e:?}");
            return None;
        }
    };

    let UpTransportLayerInformation::GtpTunnel(tunnel) = &transfer
        .dl_qos_flow_per_tnl_information
        .up_transport_layer_information;

    Some(GnbN3Endpoint {
        teid: u32::from_be_bytes(tunnel.gtp_teid),
        address: tunnel.transport_layer_address.octets.clone(),
        qfis: transfer
            .dl_qos_flow_per_tnl_information
            .associated_qos_flow_list
            .iter()
            .map(|f| f.qos_flow_identifier)
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{AmfId, Guami, PlmnId, PlmnSupport, SNssai};

    fn create_test_context() -> AmfContext {
        let mut ctx = AmfContext::new();
        ctx.amf_name = Some("AMF-Test".to_string());
        ctx.relative_capacity = 255;
        ctx.num_of_served_guami = 1;
        ctx.served_guami.push(Guami {
            plmn_id: PlmnId::new("999", "70"),
            amf_id: AmfId {
                region: 2,
                set: 1,
                pointer: 0,
            },
        });
        ctx.num_of_plmn_support = 1;
        ctx.plmn_support.push(PlmnSupport {
            plmn_id: PlmnId::new("999", "70"),
            num_of_s_nssai: 1,
            s_nssai: vec![SNssai { sst: 1, sd: None }],
        });
        ctx
    }

    #[test]
    fn test_build_ng_setup_response_asn1() {
        let ctx = create_test_context();
        let response = build_ng_setup_response_asn1(&ctx);

        assert!(response.is_some());
        let bytes = response.unwrap();
        assert!(!bytes.is_empty());

        // Verify we can decode it back
        let decoded = parser::decode_ngap_pdu(&bytes).expect("Should decode successfully");
        match decoded {
            NgapMessage::NgSetupResponse(resp) => {
                assert_eq!(resp.amf_name, "AMF-Test");
                assert_eq!(resp.relative_amf_capacity, 255);
            }
            _ => panic!("Expected NgSetupResponse"),
        }
    }

    #[test]
    fn test_build_ng_setup_failure_asn1() {
        let bytes = build_ng_setup_failure_asn1(4, 0, Some(2)); // Misc, Unspecified, 5s wait

        assert!(!bytes.is_empty());

        let decoded = parser::decode_ngap_pdu(&bytes).expect("Should decode successfully");
        match decoded {
            NgapMessage::NgSetupFailure(failure) => {
                assert_eq!(failure.time_to_wait, Some(TimeToWait::V5s));
            }
            _ => panic!("Expected NgSetupFailure"),
        }
    }

    #[test]
    fn test_encode_plmn_id() {
        let plmn = PlmnId::new("999", "70");
        let bytes = encode_plmn_id(&plmn);

        // PLMN 999-70 should encode as:
        // Byte 0: MCC2 (9) << 4 | MCC1 (9) = 0x99
        // Byte 1: MNC3 (F) << 4 | MCC3 (9) = 0xF9
        // Byte 2: MNC2 (0) << 4 | MNC1 (7) = 0x07
        assert_eq!(bytes[0], 0x99);
        assert_eq!(bytes[1], 0xF9);
        assert_eq!(bytes[2], 0x07);
    }

    #[test]
    fn test_decode_plmn_id() {
        let bytes = [0x99, 0xF9, 0x70]; // PLMN 999-70
        let plmn = decode_plmn_id(&bytes);

        assert_eq!(plmn.mcc1, 9);
        assert_eq!(plmn.mcc2, 9);
        assert_eq!(plmn.mcc3, 9);
        assert_eq!(plmn.mnc1, 0);
        assert_eq!(plmn.mnc2, 7);
        assert_eq!(plmn.mnc3, 0xF); // 2-digit MNC indicator
    }

    #[test]
    fn test_ng_setup_failure_real_causes_roundtrip() {
        // Protocol / semantic-error (missing mandatory IE)
        let bytes = build_ng_setup_failure_asn1(3, 4, Some(0));
        match parser::decode_ngap_pdu(&bytes).expect("decode") {
            NgapMessage::NgSetupFailure(f) => {
                assert_eq!(f.cause, Cause::Protocol(CauseProtocol::SemanticError));
                assert_eq!(f.time_to_wait, Some(TimeToWait::V1s));
            }
            other => panic!("Expected NgSetupFailure, got {other:?}"),
        }

        // Misc / unknown-PLMN-or-SNPN (no served TAI overlap)
        let bytes = build_ng_setup_failure_asn1(4, 4, Some(0));
        match parser::decode_ngap_pdu(&bytes).expect("decode") {
            NgapMessage::NgSetupFailure(f) => {
                assert_eq!(f.cause, Cause::Misc(CauseMisc::UnknownPlmnOrSnpn));
            }
            other => panic!("Expected NgSetupFailure, got {other:?}"),
        }
    }

    #[test]
    fn test_build_ue_context_release_command_cause_roundtrip() {
        // group 0 = RadioNetwork, value 20 = user-inactivity
        let bytes = build_ue_context_release_command_asn1(42, 1001, 0, 20).expect("build");
        match parser::decode_ngap_pdu(&bytes).expect("decode") {
            NgapMessage::UeContextReleaseCommand(cmd) => {
                assert_eq!(
                    cmd.cause,
                    Cause::RadioNetwork(CauseRadioNetwork::UserInactivity)
                );
                match cmd.ue_ngap_ids {
                    UeNgapIds::Pair {
                        amf_ue_ngap_id,
                        ran_ue_ngap_id,
                    } => {
                        assert_eq!(amf_ue_ngap_id, 42);
                        assert_eq!(ran_ue_ngap_id, 1001);
                    }
                    other => panic!("Expected Pair, got {other:?}"),
                }
            }
            other => panic!("Expected UeContextReleaseCommand, got {other:?}"),
        }
    }

    #[test]
    fn test_build_ng_reset_acknowledge_full_roundtrip() {
        let bytes = build_ng_reset_acknowledge_asn1(None).expect("build");
        match parser::decode_ngap_pdu(&bytes).expect("decode") {
            NgapMessage::NgResetAcknowledge(ack) => {
                assert!(ack.connections.is_none());
            }
            other => panic!("Expected NgResetAcknowledge, got {other:?}"),
        }
    }

    #[test]
    fn test_build_ng_reset_acknowledge_partial_roundtrip() {
        let connections = vec![
            UeAssociatedLogicalNgConnectionItem {
                amf_ue_ngap_id: Some(7),
                ran_ue_ngap_id: Some(70),
            },
            UeAssociatedLogicalNgConnectionItem {
                amf_ue_ngap_id: Some(8),
                ran_ue_ngap_id: None,
            },
        ];
        let bytes = build_ng_reset_acknowledge_asn1(Some(connections.clone())).expect("build");
        match parser::decode_ngap_pdu(&bytes).expect("decode") {
            NgapMessage::NgResetAcknowledge(ack) => {
                assert_eq!(ack.connections, Some(connections));
            }
            other => panic!("Expected NgResetAcknowledge, got {other:?}"),
        }
    }

    #[test]
    fn test_n2_sm_setup_request_transfer_roundtrip() {
        let bytes = build_n2_sm_setup_request_transfer(0x0000_0001, [127, 0, 0, 1], 9, 9, 8)
            .expect("build");
        let decoded =
            PduSessionResourceSetupRequestTransfer::decode(&bytes).expect("transfer decode");

        let UpTransportLayerInformation::GtpTunnel(tunnel) = &decoded.ul_ngu_up_tnl_information;
        assert_eq!(tunnel.gtp_teid, [0, 0, 0, 1]);
        assert_eq!(tunnel.transport_layer_address.octets, vec![127, 0, 0, 1]);
        assert_eq!(tunnel.transport_layer_address.bit_len, 32);
        assert_eq!(decoded.pdu_session_type, PduSessionType::Ipv4);
        assert_eq!(decoded.qos_flow_setup_request_list.len(), 1);
        let flow = &decoded.qos_flow_setup_request_list[0];
        assert_eq!(flow.qos_flow_identifier, 9);
        match &flow.qos_flow_level_qos_parameters.qos_characteristics {
            QosCharacteristics::NonDynamic5qi(desc) => assert_eq!(desc.five_qi, 9),
            other => panic!("Expected NonDynamic5qi, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_n2_sm_setup_response_transfer() {
        use ogs_ngap::transfer::{AssociatedQosFlowItem, QosFlowPerTnlInformation};

        let response = PduSessionResourceSetupResponseTransfer {
            dl_qos_flow_per_tnl_information: QosFlowPerTnlInformation {
                up_transport_layer_information: UpTransportLayerInformation::GtpTunnel(GtpTunnel {
                    transport_layer_address: TransportLayerAddress::from_ipv4([10, 45, 0, 3]),
                    gtp_teid: [0xde, 0xad, 0xbe, 0xef],
                }),
                associated_qos_flow_list: vec![AssociatedQosFlowItem {
                    qos_flow_identifier: 9,
                    qos_flow_mapping_indication: None,
                }],
            },
            additional_dl_qos_flow_per_tnl_information: None,
            security_result: None,
            qos_flow_failed_to_setup_list: Vec::new(),
        };
        let bytes = response.encode().expect("encode");

        let endpoint = parse_n2_sm_setup_response_transfer(&bytes).expect("parse");
        assert_eq!(endpoint.teid, 0xdeadbeef);
        assert_eq!(endpoint.address, vec![10, 45, 0, 3]);
        assert_eq!(endpoint.qfis, vec![9]);

        // Strict: garbage bytes are rejected, not best-effort parsed
        assert!(parse_n2_sm_setup_response_transfer(&[0x09, 0x00, 0x00]).is_none());
    }

    #[test]
    fn test_release_command_carries_release_transfer() {
        use ogs_asn1c::ngap::pdu::{InitiatingMessageValue, NgapPdu};
        use ogs_asn1c::per::{AperDecode, AperDecoder};

        let bytes = build_pdu_session_resource_release_command_asn1(42, 1001, &[5]).expect("build");

        // ogs-asn1c maps InitiatingMessage procedure code 28 to the generic
        // `Other` container and the ogs-ngap dispatch does not cover it (lib
        // gap, reported); re-tag the value so the typed release-command parse
        // path is exercised via decode_ngap_pdu_raw.
        let mut decoder = AperDecoder::new(&bytes);
        let pdu = NgapPdu::decode_aper(&mut decoder).expect("pdu decode");
        let pdu = match pdu {
            NgapPdu::InitiatingMessage(mut msg) => {
                if let InitiatingMessageValue::Other(ies) = msg.value {
                    msg.value = InitiatingMessageValue::PduSessionResourceReleaseCommand(ies);
                }
                NgapPdu::InitiatingMessage(msg)
            }
            other => other,
        };

        match parser::decode_ngap_pdu_raw(pdu).expect("decode") {
            NgapMessage::PduSessionResourceReleaseCommand(cmd) => {
                assert_eq!(cmd.pdu_session_list.len(), 1);
                let item = &cmd.pdu_session_list[0];
                assert_eq!(item.pdu_session_id, 5);
                let transfer = PduSessionResourceReleaseCommandTransfer::decode(&item.transfer)
                    .expect("transfer decode");
                assert_eq!(transfer.cause, Cause::Nas(CauseNas::NormalRelease));
            }
            other => panic!("Expected PduSessionResourceReleaseCommand, got {other:?}"),
        }
    }

    // ========================================================================
    // T0.1: Initial Context Setup Request (TS 38.413 §8.3.1)
    // ========================================================================

    #[test]
    fn test_build_initial_context_setup_request_mandatory_ies_and_kgnb() {
        let ctx = create_test_context();

        // A non-zero KgNB (would be the KDF output in production).
        let kgnb = [0xABu8; 32];
        // Replayed UE security capabilities (EA0-3 / IA0-3 on the wire octet).
        let sec_cap = crate::context::UeSecurityCapability {
            ea: 0xF0,
            ia: 0xF0,
            eea: 0x00,
            eia: 0x00,
        };
        let allowed = vec![crate::context::SNssai {
            sst: 1,
            sd: Some(0x010203),
        }];
        // Piggybacked (already-protected) Registration Accept stand-in.
        let nas_pdu = vec![0x7E, 0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x42];

        let bytes = build_initial_context_setup_request_asn1(
            &ctx,
            0x0000_0001,
            0x0000_0002,
            &allowed,
            &sec_cap,
            &kgnb,
            Some(&nas_pdu),
            Some((1_000_000_000, 500_000_000)),
        )
        .expect("build ICS request");
        assert!(!bytes.is_empty());

        // Strict peer: the gNB-side parser must accept it and recover every IE.
        let decoded = parser::decode_ngap_pdu(&bytes).expect("decode ICS request");
        let req = match decoded {
            NgapMessage::InitialContextSetupRequest(r) => r,
            other => panic!("Expected InitialContextSetupRequest, got {other:?}"),
        };

        // Mandatory IEs
        assert_eq!(req.amf_ue_ngap_id, 1);
        assert_eq!(req.ran_ue_ngap_id, 2);
        // GUAMI from the AMF's served GUAMI (region 2, set 1, pointer 0)
        assert_eq!(req.guami.amf_region_id, 2);
        assert_eq!(req.guami.amf_set_id, 1);
        assert_eq!(req.guami.amf_pointer, 0);
        assert_eq!(req.guami.plmn_identity, encode_plmn_id(&PlmnId::new("999", "70")));
        // Allowed NSSAI round-trips with the SD packed as 3 bytes
        assert_eq!(req.allowed_nssai.len(), 1);
        assert_eq!(req.allowed_nssai[0].sst, 1);
        assert_eq!(req.allowed_nssai[0].sd, Some([0x01, 0x02, 0x03]));
        // Replayed UE security capabilities: NAS octet maps onto the top byte
        assert_eq!(req.ue_security_capabilities.nr_encryption_algorithms, 0xF000);
        assert_eq!(req.ue_security_capabilities.nr_integrity_algorithms, 0xF000);
        // UE Security Key = KgNB, non-zero and exactly the derived value
        assert_eq!(req.security_key, kgnb);
        assert_ne!(req.security_key, [0u8; 32]);
        // Piggybacked Registration Accept survives the round-trip
        assert_eq!(req.nas_pdu.as_deref(), Some(nas_pdu.as_slice()));
        // UE-AMBR survives the round-trip
        let ambr = req.ue_ambr.expect("UE-AMBR present");
        assert_eq!(ambr.dl, 1_000_000_000);
        assert_eq!(ambr.ul, 500_000_000);
    }

    #[test]
    fn test_build_initial_context_setup_request_requires_served_guami() {
        // No served GUAMI -> cannot build a valid ICS request (mandatory IE).
        let mut ctx = AmfContext::new();
        ctx.num_of_served_guami = 0;
        let sec_cap = crate::context::UeSecurityCapability::default();
        let result = build_initial_context_setup_request_asn1(
            &ctx,
            1,
            2,
            &[],
            &sec_cap,
            &[0u8; 32],
            None,
            None,
        );
        assert!(result.is_none());
    }

    // ========================================================================
    // T1.7: Cause conversion safety (no unsafe transmute on wire-decoded data)
    // ========================================================================

    #[test]
    fn test_cause_value_conversions_in_range() {
        // Every group maps a known wire value to the expected typed cause.
        // group 0 = RadioNetwork, value 20 = user-inactivity
        assert_eq!(
            build_cause(0, 20),
            Cause::RadioNetwork(CauseRadioNetwork::UserInactivity)
        );
        // RadioNetwork extension boundary (value 46)
        assert_eq!(
            build_cause(0, 46),
            Cause::RadioNetwork(CauseRadioNetwork::ReleaseDueToPreEmption)
        );
        // group 1 = Transport
        assert_eq!(
            build_cause(1, 0),
            Cause::Transport(CauseTransport::TransportResourceUnavailable)
        );
        // group 2 = NAS
        assert_eq!(build_cause(2, 1), Cause::Nas(CauseNas::AuthenticationFailure));
        // group 3 = Protocol, value 4 = semantic-error
        assert_eq!(
            build_cause(3, 4),
            Cause::Protocol(CauseProtocol::SemanticError)
        );
        // group 4 = Misc, value 4 = unknown-PLMN-or-SNPN
        assert_eq!(build_cause(4, 4), Cause::Misc(CauseMisc::UnknownPlmnOrSnpn));
    }

    #[test]
    fn test_out_of_range_cause_values_fall_back_safely() {
        // Out-of-range values (would have been UB under the old transmute) must
        // map to the per-group "unspecified" fallback, not undefined behaviour.

        // RadioNetwork: valid 0..=46; 47 and the max u8 fall back.
        assert_eq!(
            radio_network_cause(47),
            CauseRadioNetwork::Unspecified
        );
        assert_eq!(
            radio_network_cause(u8::MAX),
            CauseRadioNetwork::Unspecified
        );
        assert_eq!(
            build_cause(0, 200),
            Cause::RadioNetwork(CauseRadioNetwork::Unspecified)
        );

        // Protocol: valid 0..=6; 7 and beyond fall back.
        assert_eq!(protocol_cause(7), CauseProtocol::Unspecified);
        assert_eq!(protocol_cause(u8::MAX), CauseProtocol::Unspecified);
        assert_eq!(
            build_cause(3, 7),
            Cause::Protocol(CauseProtocol::Unspecified)
        );

        // Misc: valid 0..=5; 6 and beyond fall back.
        assert_eq!(misc_cause(6), CauseMisc::Unspecified);
        assert_eq!(misc_cause(u8::MAX), CauseMisc::Unspecified);
        assert_eq!(build_cause(4, 99), Cause::Misc(CauseMisc::Unspecified));

        // Unknown cause group falls back to Misc/Unspecified.
        assert_eq!(build_cause(9, 0), Cause::Misc(CauseMisc::Unspecified));
    }

    #[test]
    fn test_out_of_range_cause_value_encodes_and_decodes_safely() {
        // End-to-end: an out-of-range RadioNetwork value must not UB; it
        // degrades to Unspecified and still round-trips through the encoder.
        let bytes = build_ng_setup_failure_asn1(0, 250, Some(0));
        match parser::decode_ngap_pdu(&bytes).expect("decode") {
            NgapMessage::NgSetupFailure(f) => {
                assert_eq!(
                    f.cause,
                    Cause::RadioNetwork(CauseRadioNetwork::Unspecified)
                );
            }
            other => panic!("Expected NgSetupFailure, got {other:?}"),
        }
    }

    #[test]
    fn test_initial_context_setup_response_failure_roundtrip() {
        // Build a Response/Failure with the ogs-ngap builder, then ensure the
        // AMF-side parse helpers recover the UE NGAP IDs (used to gate the
        // registration on the ICS Response).
        let resp = builder::build_initial_context_setup_response(
            &ogs_ngap::types::InitialContextSetupResponse {
                amf_ue_ngap_id: 7,
                ran_ue_ngap_id: 9,
            },
        )
        .expect("build ICS response");
        assert_eq!(
            parse_initial_context_setup_response_asn1(&resp),
            Some((7, 9))
        );

        let fail = builder::build_initial_context_setup_failure(
            &ogs_ngap::types::InitialContextSetupFailure {
                amf_ue_ngap_id: 11,
                ran_ue_ngap_id: 13,
                cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            },
        )
        .expect("build ICS failure");
        assert_eq!(
            parse_initial_context_setup_failure_asn1(&fail),
            Some((11, 13))
        );
    }
}
