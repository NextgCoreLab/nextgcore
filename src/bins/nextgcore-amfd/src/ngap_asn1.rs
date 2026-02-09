//! NGAP ASN.1 Encoding for AMF
//!
//! This module provides proper ASN.1 APER encoding for NGAP messages
//! using the nextgsim-ngap crate. This ensures wire compatibility with
//! the gNB (nextgsim-gnb) which also uses proper ASN.1 encoding.
//!
//! The simplified proprietary encoding in ngap_build.rs is replaced by
//! proper 3GPP-compliant ASN.1 encoding.

use bitvec::prelude::*;
use nextgsim_ngap::codec::*;

use crate::context::AmfContext;

/// Build an NG Setup Response PDU with proper ASN.1 APER encoding
///
/// This is sent by AMF to gNB in response to a successful NG Setup Request.
/// The message follows 3GPP TS 38.413 Section 9.2.6.2.
pub fn build_ng_setup_response_asn1(ctx: &AmfContext) -> Option<Vec<u8>> {
    let mut protocol_ies = Vec::new();

    // IE: AMFName (mandatory)
    let amf_name = ctx.amf_name.as_ref().map(|s| s.as_str()).unwrap_or("AMF");
    protocol_ies.push(NGSetupResponseProtocolIEs_Entry {
        id: ProtocolIE_ID(ID_AMF_NAME),
        criticality: Criticality(Criticality::REJECT),
        value: NGSetupResponseProtocolIEs_EntryValue::Id_AMFName(AMFName(amf_name.to_string())),
    });

    // IE: ServedGUAMIList (mandatory)
    let served_guami_list = build_served_guami_list(ctx);
    protocol_ies.push(NGSetupResponseProtocolIEs_Entry {
        id: ProtocolIE_ID(ID_SERVED_GUAMI_LIST),
        criticality: Criticality(Criticality::REJECT),
        value: NGSetupResponseProtocolIEs_EntryValue::Id_ServedGUAMIList(served_guami_list),
    });

    // IE: RelativeAMFCapacity (mandatory)
    protocol_ies.push(NGSetupResponseProtocolIEs_Entry {
        id: ProtocolIE_ID(ID_RELATIVE_AMF_CAPACITY),
        criticality: Criticality(Criticality::IGNORE),
        value: NGSetupResponseProtocolIEs_EntryValue::Id_RelativeAMFCapacity(RelativeAMFCapacity(
            ctx.relative_capacity,
        )),
    });

    // IE: PLMNSupportList (mandatory)
    let plmn_support_list = build_plmn_support_list(ctx);
    protocol_ies.push(NGSetupResponseProtocolIEs_Entry {
        id: ProtocolIE_ID(ID_PLMN_SUPPORT_LIST),
        criticality: Criticality(Criticality::REJECT),
        value: NGSetupResponseProtocolIEs_EntryValue::Id_PLMNSupportList(plmn_support_list),
    });

    let ng_setup_response = NGSetupResponse {
        protocol_i_es: NGSetupResponseProtocolIEs(protocol_ies),
    };

    let successful_outcome = SuccessfulOutcome {
        procedure_code: ProcedureCode(ID_NG_SETUP),
        criticality: Criticality(Criticality::REJECT),
        value: SuccessfulOutcomeValue::Id_NGSetup(ng_setup_response),
    };

    let pdu = NGAP_PDU::SuccessfulOutcome(successful_outcome);

    match encode_ngap_pdu(&pdu) {
        Ok(bytes) => {
            log::debug!(
                "Built NG Setup Response: {} bytes, hex: {:02x?}",
                bytes.len(),
                &bytes[..bytes.len().min(32)]
            );
            Some(bytes)
        }
        Err(e) => {
            log::error!("Failed to encode NG Setup Response: {:?}", e);
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
    let mut protocol_ies = Vec::new();

    // IE: Cause (mandatory)
    let cause = build_cause(cause_group, cause_value);
    protocol_ies.push(NGSetupFailureProtocolIEs_Entry {
        id: ProtocolIE_ID(ID_CAUSE),
        criticality: Criticality(Criticality::IGNORE),
        value: NGSetupFailureProtocolIEs_EntryValue::Id_Cause(cause),
    });

    // IE: TimeToWait (optional)
    if let Some(ttw) = time_to_wait {
        let ttw_value = match ttw {
            0 => TimeToWait::V1S,
            1 => TimeToWait::V2S,
            2 => TimeToWait::V5S,
            3 => TimeToWait::V10S,
            4 => TimeToWait::V20S,
            _ => TimeToWait::V60S,
        };
        protocol_ies.push(NGSetupFailureProtocolIEs_Entry {
            id: ProtocolIE_ID(ID_TIME_TO_WAIT),
            criticality: Criticality(Criticality::IGNORE),
            value: NGSetupFailureProtocolIEs_EntryValue::Id_TimeToWait(TimeToWait(ttw_value)),
        });
    }

    let ng_setup_failure = NGSetupFailure {
        protocol_i_es: NGSetupFailureProtocolIEs(protocol_ies),
    };

    let unsuccessful_outcome = UnsuccessfulOutcome {
        procedure_code: ProcedureCode(ID_NG_SETUP),
        criticality: Criticality(Criticality::REJECT),
        value: UnsuccessfulOutcomeValue::Id_NGSetup(ng_setup_failure),
    };

    let pdu = NGAP_PDU::UnsuccessfulOutcome(unsuccessful_outcome);

    match encode_ngap_pdu(&pdu) {
        Ok(bytes) => {
            log::debug!("Built NG Setup Failure: {} bytes", bytes.len());
            bytes
        }
        Err(e) => {
            log::error!("Failed to encode NG Setup Failure: {:?}", e);
            Vec::new()
        }
    }
}

/// Build ServedGUAMIList from AMF context
fn build_served_guami_list(ctx: &AmfContext) -> ServedGUAMIList {
    let items: Vec<ServedGUAMIItem> = ctx
        .served_guami
        .iter()
        .take(ctx.num_of_served_guami)
        .map(|guami| {
            // Build PLMN Identity (3 bytes)
            let plmn_bytes = encode_plmn_id(&guami.plmn_id);

            // Build AMF Region ID (8 bits)
            let mut amf_region_id_bits: BitVec<u8, Msb0> = BitVec::new();
            for i in (0..8).rev() {
                amf_region_id_bits.push((guami.amf_id.region >> i) & 1 == 1);
            }

            // Build AMF Set ID (10 bits)
            let mut amf_set_id_bits: BitVec<u8, Msb0> = BitVec::new();
            for i in (0..10).rev() {
                amf_set_id_bits.push((guami.amf_id.set >> i) & 1 == 1);
            }

            // Build AMF Pointer (6 bits)
            let mut amf_pointer_bits: BitVec<u8, Msb0> = BitVec::new();
            for i in (0..6).rev() {
                amf_pointer_bits.push((guami.amf_id.pointer >> i) & 1 == 1);
            }

            ServedGUAMIItem {
                guami: GUAMI {
                    plmn_identity: PLMNIdentity(plmn_bytes.to_vec()),
                    amf_region_id: AMFRegionID(amf_region_id_bits),
                    amf_set_id: AMFSetID(amf_set_id_bits),
                    amf_pointer: AMFPointer(amf_pointer_bits),
                    ie_extensions: None,
                },
                backup_amf_name: None,
                ie_extensions: None,
            }
        })
        .collect();

    ServedGUAMIList(items)
}

/// Build PLMNSupportList from AMF context
fn build_plmn_support_list(ctx: &AmfContext) -> PLMNSupportList {
    let items: Vec<PLMNSupportItem> = ctx
        .plmn_support
        .iter()
        .take(ctx.num_of_plmn_support)
        .map(|plmn_support| {
            let plmn_bytes = encode_plmn_id(&plmn_support.plmn_id);

            let slice_support_list: Vec<SliceSupportItem> = plmn_support
                .s_nssai
                .iter()
                .take(plmn_support.num_of_s_nssai)
                .map(|s_nssai| {
                    let sd = s_nssai.sd.map(|sd_val| {
                        SD(vec![
                            ((sd_val >> 16) & 0xFF) as u8,
                            ((sd_val >> 8) & 0xFF) as u8,
                            (sd_val & 0xFF) as u8,
                        ])
                    });

                    SliceSupportItem {
                        s_nssai: S_NSSAI {
                            sst: SST(vec![s_nssai.sst]),
                            sd,
                            ie_extensions: None,
                        },
                        ie_extensions: None,
                    }
                })
                .collect();

            PLMNSupportItem {
                plmn_identity: PLMNIdentity(plmn_bytes.to_vec()),
                slice_support_list: SliceSupportList(slice_support_list),
                ie_extensions: None,
            }
        })
        .collect();

    PLMNSupportList(items)
}

/// Build Cause from group and value
fn build_cause(group: u8, value: i64) -> Cause {
    match group {
        0 => Cause::RadioNetwork(CauseRadioNetwork(value as u8)),
        1 => Cause::Transport(CauseTransport(value as u8)),
        2 => Cause::Nas(CauseNas(value as u8)),
        3 => Cause::Protocol(CauseProtocol(value as u8)),
        4 => Cause::Misc(CauseMisc(value as u8)),
        _ => Cause::Misc(CauseMisc(CauseMisc::UNSPECIFIED)),
    }
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

/// Decode an NG Setup Request from ASN.1 APER bytes
pub fn parse_ng_setup_request_asn1(
    data: &[u8],
) -> Option<crate::ngap_handler::NgSetupRequest> {
    let pdu = match decode_ngap_pdu(data) {
        Ok(pdu) => pdu,
        Err(e) => {
            log::error!("Failed to decode NGAP PDU: {:?}", e);
            return None;
        }
    };

    let initiating_message = match pdu {
        NGAP_PDU::InitiatingMessage(msg) => msg,
        _ => {
            log::error!("Expected InitiatingMessage, got {:?}", pdu);
            return None;
        }
    };

    let ng_setup_request = match initiating_message.value {
        InitiatingMessageValue::Id_NGSetup(req) => req,
        _ => {
            log::error!("Expected NGSetupRequest");
            return None;
        }
    };

    let mut result = crate::ngap_handler::NgSetupRequest::default();

    for ie in &ng_setup_request.protocol_i_es.0 {
        match &ie.value {
            NGSetupRequestProtocolIEs_EntryValue::Id_GlobalRANNodeID(global_ran_node_id) => {
                result.global_ran_node_id_present = true;
                if let GlobalRANNodeID::GlobalGNB_ID(global_gnb_id) = global_ran_node_id {
                    // Parse PLMN ID
                    if global_gnb_id.plmn_identity.0.len() >= 3 {
                        result.plmn_id =
                            decode_plmn_id(&global_gnb_id.plmn_identity.0);
                    }

                    // Parse gNB ID
                    match &global_gnb_id.gnb_id {
                        GNB_ID::GNB_ID(gnb_id_bits) => {
                            result.gnb_id_len = gnb_id_bits.0.len() as u8;
                            let mut gnb_id: u32 = 0;
                            for bit in gnb_id_bits.0.iter() {
                                gnb_id = (gnb_id << 1) | (*bit as u32);
                            }
                            result.gnb_id = gnb_id;
                        }
                        _ => {}
                    }
                }
            }
            NGSetupRequestProtocolIEs_EntryValue::Id_RANNodeName(name) => {
                result.ran_node_name = Some(name.0.clone());
            }
            NGSetupRequestProtocolIEs_EntryValue::Id_SupportedTAList(ta_list) => {
                result.supported_ta_list = parse_supported_ta_list(ta_list);
            }
            NGSetupRequestProtocolIEs_EntryValue::Id_DefaultPagingDRX(drx) => {
                result.default_paging_drx = drx.0;
            }
            _ => {}
        }
    }

    Some(result)
}

/// Parse SupportedTAList from NGAP
fn parse_supported_ta_list(
    ta_list: &SupportedTAList,
) -> Vec<crate::context::SupportedTa> {
    ta_list
        .0
        .iter()
        .map(|ta_item| {
            let tac = if ta_item.tac.0.len() >= 3 {
                ((ta_item.tac.0[0] as u32) << 16)
                    | ((ta_item.tac.0[1] as u32) << 8)
                    | (ta_item.tac.0[2] as u32)
            } else {
                0
            };

            let bplmn_list: Vec<crate::context::BplmnEntry> = ta_item
                .broadcast_plmn_list
                .0
                .iter()
                .map(|bp| {
                    let plmn_id = decode_plmn_id(&bp.plmn_identity.0);

                    let s_nssai: Vec<crate::context::SNssai> = bp
                        .tai_slice_support_list
                        .0
                        .iter()
                        .map(|slice| {
                            let sst = slice.s_nssai.sst.0.first().copied().unwrap_or(0);
                            let sd = slice.s_nssai.sd.as_ref().and_then(|sd| {
                                if sd.0.len() >= 3 {
                                    Some(
                                        ((sd.0[0] as u32) << 16)
                                            | ((sd.0[1] as u32) << 8)
                                            | (sd.0[2] as u32),
                                    )
                                } else {
                                    None
                                }
                            });
                            crate::context::SNssai { sst, sd }
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
        .collect()
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
    let pdu = match decode_ngap_pdu(data) {
        Ok(pdu) => pdu,
        Err(e) => {
            log::error!("Failed to decode NGAP PDU: {:?}", e);
            return None;
        }
    };

    let initiating_message = match pdu {
        NGAP_PDU::InitiatingMessage(msg) => msg,
        _ => {
            log::error!("Expected InitiatingMessage, got {:?}", pdu);
            return None;
        }
    };

    let initial_ue_message = match initiating_message.value {
        InitiatingMessageValue::Id_InitialUEMessage(msg) => msg,
        _ => {
            log::error!("Expected InitialUEMessage");
            return None;
        }
    };

    let mut ran_ue_ngap_id: Option<u32> = None;
    let mut nas_pdu: Option<Vec<u8>> = None;
    let mut plmn_id = crate::context::PlmnId::default();
    let mut nr_cell_identity: u64 = 0;
    let mut tac: u32 = 0;
    let mut rrc_establishment_cause: u8 = 0;
    let mut ue_context_request = false;

    for ie in &initial_ue_message.protocol_i_es.0 {
        match &ie.value {
            InitialUEMessageProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(id) => {
                ran_ue_ngap_id = Some(id.0);
            }
            InitialUEMessageProtocolIEs_EntryValue::Id_NAS_PDU(pdu) => {
                nas_pdu = Some(pdu.0.clone());
            }
            InitialUEMessageProtocolIEs_EntryValue::Id_UserLocationInformation(info) => {
                if let UserLocationInformation::UserLocationInformationNR(nr_info) = info {
                    // Parse NR-CGI
                    if nr_info.nr_cgi.plmn_identity.0.len() >= 3 {
                        plmn_id = decode_plmn_id(&nr_info.nr_cgi.plmn_identity.0);
                    }
                    // Parse NR Cell Identity (36 bits from BitVec)
                    for (i, bit) in nr_info.nr_cgi.nr_cell_identity.0.iter().take(36).enumerate() {
                        if *bit {
                            nr_cell_identity |= 1 << (35 - i);
                        }
                    }
                    // Parse TAC
                    if nr_info.tai.tac.0.len() >= 3 {
                        tac = ((nr_info.tai.tac.0[0] as u32) << 16)
                            | ((nr_info.tai.tac.0[1] as u32) << 8)
                            | (nr_info.tai.tac.0[2] as u32);
                    }
                }
            }
            InitialUEMessageProtocolIEs_EntryValue::Id_RRCEstablishmentCause(cause) => {
                rrc_establishment_cause = cause.0;
            }
            InitialUEMessageProtocolIEs_EntryValue::Id_UEContextRequest(req) => {
                ue_context_request = req.0 == UEContextRequest::REQUESTED;
            }
            _ => {}
        }
    }

    let ran_ue_ngap_id = ran_ue_ngap_id?;
    let nas_pdu = nas_pdu?;

    log::info!(
        "Parsed Initial UE Message: ran_ue_ngap_id={}, nas_pdu_len={}, plmn={}{}{}-{}{}{}, nci=0x{:x}, tac={}, cause={}",
        ran_ue_ngap_id,
        nas_pdu.len(),
        plmn_id.mcc1, plmn_id.mcc2, plmn_id.mcc3,
        plmn_id.mnc1, plmn_id.mnc2, if plmn_id.mnc3 == 0xF { "".to_string() } else { format!("{}", plmn_id.mnc3) },
        nr_cell_identity,
        tac,
        rrc_establishment_cause
    );

    Some(InitialUeMessageData {
        ran_ue_ngap_id,
        nas_pdu,
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
    let mut protocol_ies = Vec::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    protocol_ies.push(DownlinkNASTransportProtocolIEs_Entry {
        id: ProtocolIE_ID(ID_AMF_UE_NGAP_ID),
        criticality: Criticality(Criticality::REJECT),
        value: DownlinkNASTransportProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(AMF_UE_NGAP_ID(
            amf_ue_ngap_id,
        )),
    });

    // IE: RAN-UE-NGAP-ID (mandatory)
    protocol_ies.push(DownlinkNASTransportProtocolIEs_Entry {
        id: ProtocolIE_ID(ID_RAN_UE_NGAP_ID),
        criticality: Criticality(Criticality::REJECT),
        value: DownlinkNASTransportProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(RAN_UE_NGAP_ID(
            ran_ue_ngap_id,
        )),
    });

    // IE: NAS-PDU (mandatory)
    protocol_ies.push(DownlinkNASTransportProtocolIEs_Entry {
        id: ProtocolIE_ID(ID_NAS_PDU),
        criticality: Criticality(Criticality::REJECT),
        value: DownlinkNASTransportProtocolIEs_EntryValue::Id_NAS_PDU(NAS_PDU(nas_pdu.to_vec())),
    });

    let downlink_nas_transport = DownlinkNASTransport {
        protocol_i_es: DownlinkNASTransportProtocolIEs(protocol_ies),
    };

    let initiating_message = InitiatingMessage {
        procedure_code: ProcedureCode(ID_DOWNLINK_NAS_TRANSPORT),
        criticality: Criticality(Criticality::IGNORE),
        value: InitiatingMessageValue::Id_DownlinkNASTransport(downlink_nas_transport),
    };

    let pdu = NGAP_PDU::InitiatingMessage(initiating_message);

    match encode_ngap_pdu(&pdu) {
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
            log::error!("Failed to encode Downlink NAS Transport: {:?}", e);
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
    let mut protocol_ies = Vec::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    protocol_ies.push(PDUSessionResourceSetupRequestProtocolIEs_Entry {
        id: ProtocolIE_ID(ID_AMF_UE_NGAP_ID),
        criticality: Criticality(Criticality::REJECT),
        value: PDUSessionResourceSetupRequestProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(
            AMF_UE_NGAP_ID(amf_ue_ngap_id),
        ),
    });

    // IE: RAN-UE-NGAP-ID (mandatory)
    protocol_ies.push(PDUSessionResourceSetupRequestProtocolIEs_Entry {
        id: ProtocolIE_ID(ID_RAN_UE_NGAP_ID),
        criticality: Criticality(Criticality::REJECT),
        value: PDUSessionResourceSetupRequestProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(
            RAN_UE_NGAP_ID(ran_ue_ngap_id),
        ),
    });

    // IE: NAS-PDU (optional, common for all sessions)
    if let Some(pdu) = nas_pdu {
        protocol_ies.push(PDUSessionResourceSetupRequestProtocolIEs_Entry {
            id: ProtocolIE_ID(ID_NAS_PDU),
            criticality: Criticality(Criticality::REJECT),
            value: PDUSessionResourceSetupRequestProtocolIEs_EntryValue::Id_NAS_PDU(
                NAS_PDU(pdu.to_vec()),
            ),
        });
    }

    // IE: PDUSessionResourceSetupListSUReq (mandatory)
    let sd = s_nssai_sd.map(|sd_val| {
        SD(vec![
            ((sd_val >> 16) & 0xFF) as u8,
            ((sd_val >> 8) & 0xFF) as u8,
            (sd_val & 0xFF) as u8,
        ])
    });

    let item = PDUSessionResourceSetupItemSUReq {
        pdu_session_id: PDUSessionID(pdu_session_id),
        pdu_session_nas_pdu: None,
        s_nssai: S_NSSAI {
            sst: SST(vec![s_nssai_sst]),
            sd,
            ie_extensions: None,
        },
        pdu_session_resource_setup_request_transfer:
            PDUSessionResourceSetupItemSUReqPDUSessionResourceSetupRequestTransfer(
                n2_sm_transfer.to_vec(),
            ),
        ie_extensions: None,
    };

    let list = PDUSessionResourceSetupListSUReq(vec![item]);
    protocol_ies.push(PDUSessionResourceSetupRequestProtocolIEs_Entry {
        id: ProtocolIE_ID(ID_PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ),
        criticality: Criticality(Criticality::REJECT),
        value: PDUSessionResourceSetupRequestProtocolIEs_EntryValue::Id_PDUSessionResourceSetupListSUReq(list),
    });

    let request = PDUSessionResourceSetupRequest {
        protocol_i_es: PDUSessionResourceSetupRequestProtocolIEs(protocol_ies),
    };

    let initiating_message = InitiatingMessage {
        procedure_code: ProcedureCode(ID_PDU_SESSION_RESOURCE_SETUP),
        criticality: Criticality(Criticality::REJECT),
        value: InitiatingMessageValue::Id_PDUSessionResourceSetup(request),
    };

    let pdu = NGAP_PDU::InitiatingMessage(initiating_message);

    match encode_ngap_pdu(&pdu) {
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
            log::error!("Failed to encode PDU Session Resource Setup Request: {:?}", e);
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
    let pdu = match decode_ngap_pdu(data) {
        Ok(pdu) => pdu,
        Err(e) => {
            log::error!("Failed to decode NGAP PDU: {:?}", e);
            return None;
        }
    };

    let initiating_message = match pdu {
        NGAP_PDU::InitiatingMessage(msg) => msg,
        _ => {
            log::error!("Expected InitiatingMessage, got {:?}", pdu);
            return None;
        }
    };

    let uplink_nas_transport = match initiating_message.value {
        InitiatingMessageValue::Id_UplinkNASTransport(msg) => msg,
        _ => {
            log::error!("Expected UplinkNASTransport");
            return None;
        }
    };

    let mut amf_ue_ngap_id: Option<u64> = None;
    let mut ran_ue_ngap_id: Option<u32> = None;
    let mut nas_pdu: Option<Vec<u8>> = None;

    for ie in &uplink_nas_transport.protocol_i_es.0 {
        match &ie.value {
            UplinkNASTransportProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(id) => {
                amf_ue_ngap_id = Some(id.0);
            }
            UplinkNASTransportProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(id) => {
                ran_ue_ngap_id = Some(id.0);
            }
            UplinkNASTransportProtocolIEs_EntryValue::Id_NAS_PDU(pdu) => {
                nas_pdu = Some(pdu.0.clone());
            }
            _ => {}
        }
    }

    let amf_ue_ngap_id = amf_ue_ngap_id?;
    let ran_ue_ngap_id = ran_ue_ngap_id?;
    let nas_pdu = nas_pdu?;

    log::info!(
        "Parsed Uplink NAS Transport: amf_ue_ngap_id={}, ran_ue_ngap_id={}, nas_pdu_len={}",
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        nas_pdu.len()
    );

    Some(UplinkNasTransportData {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        nas_pdu,
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

        // First byte should indicate SuccessfulOutcome (0x20)
        assert_eq!(bytes[0] & 0xE0, 0x20, "Should be SuccessfulOutcome");

        // Verify we can decode it back
        let pdu = decode_ngap_pdu(&bytes).expect("Should decode successfully");
        match pdu {
            NGAP_PDU::SuccessfulOutcome(outcome) => {
                assert_eq!(outcome.procedure_code.0, ID_NG_SETUP);
            }
            _ => panic!("Expected SuccessfulOutcome"),
        }
    }

    #[test]
    fn test_build_ng_setup_failure_asn1() {
        let bytes = build_ng_setup_failure_asn1(4, 0, Some(2)); // Misc, Unspecified, 5s wait

        assert!(!bytes.is_empty());

        // Verify we can decode it back
        let pdu = decode_ngap_pdu(&bytes).expect("Should decode successfully");
        match pdu {
            NGAP_PDU::UnsuccessfulOutcome(outcome) => {
                assert_eq!(outcome.procedure_code.0, ID_NG_SETUP);
            }
            _ => panic!("Expected UnsuccessfulOutcome"),
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
}
