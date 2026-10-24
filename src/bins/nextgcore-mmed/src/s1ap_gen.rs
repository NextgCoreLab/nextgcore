//! mmed's S1AP on the generated codec (`nextgcore-s1ap-gen`, #514).
//!
//! #514 moves mmed's S1AP off the hand-written `nextgcore-s1ap` codec one
//! message family at a time, as #417 did for amfd's NGAP. Each family keeps the
//! hand-written code as a byte-equivalence oracle in its tests until the final
//! deletion pass.
//!
//! Stage 2 is the S1 Setup family (TS 36.413 §8.7.3): the S1 SETUP REQUEST
//! decode, with §10.3.4 / §10.3.5 handling, and the S1 SETUP RESPONSE / S1
//! SETUP FAILURE encodes. Stage 3 is NAS transport (§8.6.2): the INITIAL UE
//! MESSAGE and UPLINK NAS TRANSPORT decodes and the DOWNLINK NAS TRANSPORT
//! encode. Stage 4 is Initial Context Setup (§8.3.1): the INITIAL CONTEXT SETUP
//! REQUEST encode and the RESPONSE / FAILURE decodes. Stage 5 is UE Context
//! Release (§8.3.2, §8.3.3): the UE CONTEXT RELEASE COMMAND encode and the
//! REQUEST / COMPLETE decodes. Stage 6 is E-RAB management (§8.2.1-§8.2.3):
//! the E-RAB SETUP / MODIFY REQUEST and E-RAB RELEASE COMMAND encodes and their
//! responses' decodes. Stage 7 is Paging (§8.5): the PAGING encode. Stage 8a
//! is the handover family's simpler half (§8.4): HANDOVER NOTIFY, HANDOVER
//! CANCEL, HANDOVER FAILURE and ENB STATUS TRANSFER decodes, and HANDOVER
//! PREPARATION FAILURE, HANDOVER CANCEL ACKNOWLEDGE and MME STATUS TRANSFER
//! encodes. Stage 9 is Reset and Error Indication (§8.7.1, §8.7.2): the RESET
//! and ERROR INDICATION decodes and the RESET ACKNOWLEDGE and ERROR INDICATION
//! encodes. Stage 10 is Path Switch (§8.4.4): the PATH SWITCH REQUEST decode
//! and its ACKNOWLEDGE / FAILURE encodes. Stage 8b is the rest of handover
//! preparation (§8.4.1, §8.4.2): the HANDOVER REQUIRED and HANDOVER REQUEST
//! ACKNOWLEDGE decodes and the HANDOVER REQUEST and HANDOVER COMMAND encodes.

use bitvec::prelude::{BitVec, Msb0};
use nextgcore_s1ap::{
    Cause, EnbId, EutranCgi, GlobalEnbId, InitialUeMessage, PagingDrx, RrcEstablishmentCause,
    S1SetupRequest, STmsi, SupportedTaItem, Tai, TimeToWait,
};
use nextgcore_s1ap_gen::generated as g;
use nextgcore_s1ap_gen::UnknownIe;

/// `id-S1Setup` (TS 36.413 §9.3.7).
pub const PROC_S1_SETUP: u8 = 17;

// ProtocolIE-IDs used by the S1 Setup family (TS 36.413 §9.3.7).
const ID_CAUSE: u16 = 2;
const ID_CRITICALITY_DIAGNOSTICS: u16 = 58;
const ID_GLOBAL_ENB_ID: u16 = 59;
const ID_ENB_NAME: u16 = 60;
const ID_MME_NAME: u16 = 61;
const ID_SUPPORTED_TAS: u16 = 64;
const ID_TIME_TO_WAIT: u16 = 65;
const ID_RELATIVE_MME_CAPACITY: u16 = 87;
const ID_SERVED_GUMMEIS: u16 = 105;
const ID_DEFAULT_PAGING_DRX: u16 = 137;

const REJECT: u8 = g::Criticality::REJECT;
const IGNORE: u8 = g::Criticality::IGNORE;
const NOTIFY: u8 = g::Criticality::NOTIFY;

/// One IE that §10.3.4 / §10.3.5 handling reports in Criticality Diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosedIe {
    /// Criticality the IE carries (or, for a missing IE, its object-set
    /// criticality).
    pub criticality: u8,
    /// Its ProtocolIE-ID.
    pub id: u16,
    /// `TypeOfError`: 0 = not-understood, 1 = missing.
    pub type_of_error: u8,
}

/// Outcome of decoding an S1 SETUP REQUEST with TS 36.413 §10.3.4 / §10.3.5.
#[derive(Debug, Clone)]
pub enum SetupRequestDecode {
    /// Proceed with the procedure. `notify` lists unknown IEs marked
    /// ignore-and-notify, to be reported in the response's Criticality
    /// Diagnostics (§10.3.4.2, Class 1 procedure with a response message).
    Proceed {
        /// The request, in the handler's existing type.
        request: S1SetupRequest,
        /// IEs to report.
        notify: Vec<DiagnosedIe>,
    },
    /// Terminate the procedure with S1 SETUP FAILURE, cause protocol /
    /// abstract-syntax-error-reject, carrying these IEs in its diagnostics.
    Reject(Vec<DiagnosedIe>),
    /// Not decodable at all (transfer syntax error).
    Undecodable,
}

fn bits_to_u32(bits: &BitVec<u8, Msb0>) -> u32 {
    bits.iter().fold(0u32, |acc, b| (acc << 1) | u32::from(*b))
}

/// The low `width` bits of `value`, most significant first.
fn u32_to_bits(value: u32, width: usize) -> BitVec<u8, Msb0> {
    (0..width).rev().map(|i| (value >> i) & 1 == 1).collect()
}

fn plmn(bytes: &[u8]) -> Option<[u8; 3]> {
    bytes.try_into().ok()
}

/// Sort unknown IEs by criticality (§10.3.4.2 for an initiating message of a
/// Class 1 procedure): `reject` ends the procedure, `notify` is reported,
/// `ignore` is dropped.
fn classify_unknown(unknown: &[UnknownIe]) -> (Vec<DiagnosedIe>, Vec<DiagnosedIe>) {
    let mut reject = Vec::new();
    let mut notify = Vec::new();
    for ie in unknown {
        let id = u16::try_from(ie.id).unwrap_or(u16::MAX);
        // A container always carries a criticality in S1AP; if one is absent,
        // treat it as reject, the conservative reading.
        let criticality = ie.criticality.unwrap_or(REJECT);
        let diag = DiagnosedIe {
            criticality,
            id,
            type_of_error: g::TypeOfError::NOT_UNDERSTOOD,
        };
        match criticality {
            IGNORE => {}
            NOTIFY => notify.push(diag),
            _ => reject.push(diag),
        }
    }
    (reject, notify)
}

/// Decode an S1 SETUP REQUEST with the generated codec, applying TS 36.413
/// §10.3.4 to unknown IEs and §10.3.5 to missing ones.
///
/// Missing GlobalENB-ID or SupportedTAs (both criticality reject) rejects the
/// procedure. A missing DefaultPagingDRX (criticality ignore) is not reported
/// and the request proceeds with v128; it is mandatory in the object set, so a
/// conformant eNB always sends it.
pub fn decode_s1_setup_request(bytes: &[u8]) -> SetupRequestDecode {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return SetupRequestDecode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return SetupRequestDecode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_S1Setup(req) = msg.value else {
        return SetupRequestDecode::Undecodable;
    };

    let (mut reject, notify) = classify_unknown(&unknown);

    let mut global_enb_id = None;
    let mut enb_name = None;
    let mut supported_tas = None;
    let mut default_paging_drx = None;
    for ie in req.protocol_i_es.0 {
        match ie.value {
            g::S1SetupRequestProtocolIEs_EntryValue::Id_Global_ENB_ID(v) => {
                let enb_id = match v.enb_id {
                    g::ENB_ID::MacroENB_ID(b) => Some(EnbId::Macro(bits_to_u32(&b.0))),
                    g::ENB_ID::HomeENB_ID(b) => Some(EnbId::Home(bits_to_u32(&b.0))),
                    // Short / long macro eNB IDs (extension alternatives) have no
                    // representation in the handler's type; an eNB using one is
                    // refused as not understood rather than mis-identified.
                    _ => None,
                };
                match (plmn(&v.plm_nidentity.0), enb_id) {
                    (Some(plmn_identity), Some(enb_id)) => {
                        global_enb_id = Some(GlobalEnbId {
                            plmn_identity,
                            enb_id,
                        });
                    }
                    _ => reject.push(DiagnosedIe {
                        criticality: REJECT,
                        id: ID_GLOBAL_ENB_ID,
                        type_of_error: g::TypeOfError::NOT_UNDERSTOOD,
                    }),
                }
            }
            g::S1SetupRequestProtocolIEs_EntryValue::Id_eNBname(v) => enb_name = Some(v.0),
            g::S1SetupRequestProtocolIEs_EntryValue::Id_SupportedTAs(v) => {
                supported_tas = Some(
                    v.0.into_iter()
                        .filter_map(|item| {
                            let tac = u16::from_be_bytes(item.tac.0.as_slice().try_into().ok()?);
                            let broadcast_plmns = item
                                .broadcast_plm_ns
                                .0
                                .iter()
                                .filter_map(|p| plmn(&p.0))
                                .collect();
                            Some(SupportedTaItem {
                                tac,
                                broadcast_plmns,
                            })
                        })
                        .collect::<Vec<_>>(),
                );
            }
            g::S1SetupRequestProtocolIEs_EntryValue::Id_DefaultPagingDRX(v) => {
                default_paging_drx = Some(match v.0 {
                    g::PagingDRX::V32 => PagingDrx::V32,
                    g::PagingDRX::V64 => PagingDrx::V64,
                    g::PagingDRX::V256 => PagingDrx::V256,
                    _ => PagingDrx::V128,
                });
            }
            // CSG list, UE retention, NB-IoT DRX, connected en-gNBs: understood,
            // not used by this MME.
            _ => {}
        }
    }

    for (present, id) in [
        (global_enb_id.is_some(), ID_GLOBAL_ENB_ID),
        (supported_tas.is_some(), ID_SUPPORTED_TAS),
    ] {
        if !present && !reject.iter().any(|d| d.id == id) {
            reject.push(DiagnosedIe {
                criticality: REJECT,
                id,
                type_of_error: g::TypeOfError::MISSING,
            });
        }
    }
    if !reject.is_empty() {
        return SetupRequestDecode::Reject(reject);
    }
    let (Some(global_enb_id), Some(supported_tas)) = (global_enb_id, supported_tas) else {
        return SetupRequestDecode::Undecodable;
    };
    SetupRequestDecode::Proceed {
        request: S1SetupRequest {
            global_enb_id,
            enb_name,
            supported_tas,
            default_paging_drx: default_paging_drx.unwrap_or(PagingDrx::V128),
        },
        notify,
    }
}

/// Criticality Diagnostics for an S1 SETUP REQUEST (procedure 17,
/// initiating-message, criticality reject) naming `ies` (§9.2.1.21). The
/// IE list is capped at its SIZE(1..maxnoofErrors = 256).
fn diagnostics(ies: &[DiagnosedIe]) -> g::CriticalityDiagnostics {
    diagnostics_for(
        PROC_S1_SETUP,
        g::TriggeringMessage::INITIATING_MESSAGE,
        REJECT,
        ies,
    )
}

/// Criticality Diagnostics (§9.2.1.21) for any procedure, triggering message
/// and procedure criticality.
fn diagnostics_for(
    procedure_code: u8,
    triggering_message: u8,
    procedure_criticality: u8,
    ies: &[DiagnosedIe],
) -> g::CriticalityDiagnostics {
    g::CriticalityDiagnostics {
        procedure_code: Some(g::ProcedureCode(procedure_code)),
        triggering_message: Some(g::TriggeringMessage(triggering_message)),
        procedure_criticality: Some(g::Criticality(procedure_criticality)),
        i_es_criticality_diagnostics: (!ies.is_empty()).then(|| {
            g::CriticalityDiagnostics_IE_List(
                ies.iter()
                    .take(256)
                    .map(|d| g::CriticalityDiagnostics_IE_Item {
                        ie_criticality: g::Criticality(d.criticality),
                        ie_id: g::ProtocolIE_ID(d.id),
                        type_of_error: g::TypeOfError(d.type_of_error),
                        ie_extensions: None,
                    })
                    .collect(),
            )
        }),
        ie_extensions: None,
    }
}

/// One served GUMMEI, in the MME context's terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedGummei {
    /// Served PLMNs, already TBCD-encoded.
    pub plmns: Vec<[u8; 3]>,
    /// MME Group IDs.
    pub group_ids: Vec<u16>,
    /// MME Codes.
    pub codes: Vec<u8>,
}

/// Encode an S1 SETUP RESPONSE (TS 36.413 §9.1.8.5) with the generated codec.
///
/// IE order follows `S1SetupResponseIEs`; criticalities follow the object set:
/// MMEname ignore, ServedGUMMEIs reject, RelativeMMECapacity ignore,
/// CriticalityDiagnostics ignore.
pub fn build_s1_setup_response(
    mme_name: Option<&str>,
    gummeis: &[ServedGummei],
    relative_mme_capacity: u8,
    notify: &[DiagnosedIe],
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::S1SetupResponseProtocolIEs_EntryValue as V;
    let mut ies = Vec::new();
    let mut push = |id: u16, criticality: u8, value: V| {
        ies.push(g::S1SetupResponseProtocolIEs_Entry {
            id: g::ProtocolIE_ID(id),
            criticality: g::Criticality(criticality),
            value,
        });
    };
    if let Some(name) = mme_name {
        push(
            ID_MME_NAME,
            IGNORE,
            V::Id_MMEname(g::MMEname(name.to_owned())),
        );
    }
    push(
        ID_SERVED_GUMMEIS,
        REJECT,
        V::Id_ServedGUMMEIs(g::ServedGUMMEIs(
            gummeis
                .iter()
                .map(|s| g::ServedGUMMEIsItem {
                    served_plm_ns: g::ServedPLMNs(
                        s.plmns.iter().map(|p| g::TBCD_STRING(p.to_vec())).collect(),
                    ),
                    served_group_i_ds: g::ServedGroupIDs(
                        s.group_ids
                            .iter()
                            .map(|id| g::MME_Group_ID(id.to_be_bytes().to_vec()))
                            .collect(),
                    ),
                    served_mme_cs: g::ServedMMECs(
                        s.codes.iter().map(|c| g::MME_Code(vec![*c])).collect(),
                    ),
                    ie_extensions: None,
                })
                .collect(),
        )),
    );
    push(
        ID_RELATIVE_MME_CAPACITY,
        IGNORE,
        V::Id_RelativeMMECapacity(g::RelativeMMECapacity(relative_mme_capacity)),
    );
    if !notify.is_empty() {
        push(
            ID_CRITICALITY_DIAGNOSTICS,
            IGNORE,
            V::Id_CriticalityDiagnostics(diagnostics(notify)),
        );
    }
    encode_pdu(&g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
        procedure_code: g::ProcedureCode(PROC_S1_SETUP),
        criticality: g::Criticality(REJECT),
        value: g::SuccessfulOutcomeValue::Id_S1Setup(g::S1SetupResponse {
            protocol_i_es: g::S1SetupResponseProtocolIEs(ies),
        }),
    }))
}

/// The generated Cause for a hand-written one: same CHOICE alternative, same
/// ENUMERATED index (the hand-written enums' discriminants are the indices).
pub fn generated_cause(cause: Cause) -> g::Cause {
    match cause {
        Cause::RadioNetwork(v) => g::Cause::RadioNetwork(g::CauseRadioNetwork(v as u8)),
        Cause::Transport(v) => g::Cause::Transport(g::CauseTransport(v as u8)),
        Cause::Nas(v) => g::Cause::Nas(g::CauseNas(v as u8)),
        Cause::Protocol(v) => g::Cause::Protocol(g::CauseProtocol(v as u8)),
        Cause::Misc(v) => g::Cause::Misc(g::CauseMisc(v as u8)),
    }
}

/// Encode an S1 SETUP FAILURE (TS 36.413 §9.1.8.6) with the generated codec.
///
/// IE order follows `S1SetupFailureIEs`, every IE criticality ignore. `reject`,
/// when non-empty, is reported in Criticality Diagnostics (§10.3.4.2).
pub fn build_s1_setup_failure(
    cause: Cause,
    time_to_wait: Option<TimeToWait>,
    reject: &[DiagnosedIe],
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::S1SetupFailureProtocolIEs_EntryValue as V;
    let mut ies = vec![g::S1SetupFailureProtocolIEs_Entry {
        id: g::ProtocolIE_ID(ID_CAUSE),
        criticality: g::Criticality(IGNORE),
        value: V::Id_Cause(generated_cause(cause)),
    }];
    if let Some(ttw) = time_to_wait {
        ies.push(g::S1SetupFailureProtocolIEs_Entry {
            id: g::ProtocolIE_ID(ID_TIME_TO_WAIT),
            criticality: g::Criticality(IGNORE),
            value: V::Id_TimeToWait(g::TimeToWait(ttw as u8)),
        });
    }
    if !reject.is_empty() {
        ies.push(g::S1SetupFailureProtocolIEs_Entry {
            id: g::ProtocolIE_ID(ID_CRITICALITY_DIAGNOSTICS),
            criticality: g::Criticality(IGNORE),
            value: V::Id_CriticalityDiagnostics(diagnostics(reject)),
        });
    }
    encode_pdu(&g::S1AP_PDU::UnsuccessfulOutcome(g::UnsuccessfulOutcome {
        procedure_code: g::ProcedureCode(PROC_S1_SETUP),
        criticality: g::Criticality(REJECT),
        value: g::UnsuccessfulOutcomeValue::Id_S1Setup(g::S1SetupFailure {
            protocol_i_es: g::S1SetupFailureProtocolIEs(ies),
        }),
    }))
}

/// Encode an S1 SETUP REQUEST with the generated codec. mmed never sends one;
/// tests use it to build requests the way a conformant eNB would.
#[cfg(test)]
pub fn build_s1_setup_request(req: &S1SetupRequest) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::S1SetupRequestProtocolIEs_EntryValue as V;
    let enb_id = match req.global_enb_id.enb_id {
        EnbId::Macro(id) => g::ENB_ID::MacroENB_ID(g::ENB_ID_macroENB_ID(u32_to_bits(id, 20))),
        EnbId::Home(id) => g::ENB_ID::HomeENB_ID(g::ENB_ID_homeENB_ID(u32_to_bits(id, 28))),
    };
    let mut ies = vec![g::S1SetupRequestProtocolIEs_Entry {
        id: g::ProtocolIE_ID(ID_GLOBAL_ENB_ID),
        criticality: g::Criticality(REJECT),
        value: V::Id_Global_ENB_ID(g::Global_ENB_ID {
            plm_nidentity: g::TBCD_STRING(req.global_enb_id.plmn_identity.to_vec()),
            enb_id,
            ie_extensions: None,
        }),
    }];
    if let Some(name) = &req.enb_name {
        ies.push(g::S1SetupRequestProtocolIEs_Entry {
            id: g::ProtocolIE_ID(ID_ENB_NAME),
            criticality: g::Criticality(IGNORE),
            value: V::Id_eNBname(g::ENBname(name.clone())),
        });
    }
    ies.push(g::S1SetupRequestProtocolIEs_Entry {
        id: g::ProtocolIE_ID(ID_SUPPORTED_TAS),
        criticality: g::Criticality(REJECT),
        value: V::Id_SupportedTAs(g::SupportedTAs(
            req.supported_tas
                .iter()
                .map(|ta| g::SupportedTAs_Item {
                    tac: g::TAC(ta.tac.to_be_bytes().to_vec()),
                    broadcast_plm_ns: g::BPLMNs(
                        ta.broadcast_plmns
                            .iter()
                            .map(|p| g::TBCD_STRING(p.to_vec()))
                            .collect(),
                    ),
                    ie_extensions: None,
                })
                .collect(),
        )),
    });
    ies.push(g::S1SetupRequestProtocolIEs_Entry {
        id: g::ProtocolIE_ID(ID_DEFAULT_PAGING_DRX),
        criticality: g::Criticality(IGNORE),
        value: V::Id_DefaultPagingDRX(g::PagingDRX(req.default_paging_drx as u8)),
    });
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_S1_SETUP),
        criticality: g::Criticality(REJECT),
        value: g::InitiatingMessageValue::Id_S1Setup(g::S1SetupRequest {
            protocol_i_es: g::S1SetupRequestProtocolIEs(ies),
        }),
    }))
}

/// Whether `bytes` is an initiating-message S1 SETUP REQUEST: the CHOICE index
/// (ext bit + 2-bit index, octet-aligned) is 0 and the procedure code 17.
pub fn is_s1_setup_request(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x00 && bytes[1] == PROC_S1_SETUP
}

// ============================================================================
// NAS transport (TS 36.413 §8.6.2) -- stage 3
// ============================================================================

/// `id-initialUEMessage`, `id-downlinkNASTransport`, `id-uplinkNASTransport`.
pub const PROC_INITIAL_UE_MESSAGE: u8 = 12;
/// `id-downlinkNASTransport`.
pub const PROC_DOWNLINK_NAS_TRANSPORT: u8 = 11;
/// `id-uplinkNASTransport`.
pub const PROC_UPLINK_NAS_TRANSPORT: u8 = 13;

const ID_MME_UE_S1AP_ID: u16 = 0;
const ID_ENB_UE_S1AP_ID: u16 = 8;
const ID_NAS_PDU: u16 = 26;
const ID_TAI: u16 = 67;
const ID_EUTRAN_CGI: u16 = 100;
const ID_S_TMSI: u16 = 96;

/// Outcome of decoding a UE-associated initiating message of a Class 2
/// procedure (no response message) under TS 36.413 §10.3.4.2 / §10.3.5.
#[derive(Debug, Clone)]
pub enum Class2Decode<T> {
    /// Run the procedure. `notify` lists unknown ignore-and-notify IEs, to be
    /// reported in an ERROR INDICATION (no response message exists).
    Proceed {
        /// The message.
        msg: T,
        /// IEs to report.
        notify: Vec<DiagnosedIe>,
    },
    /// Do not run the procedure; answer with an ERROR INDICATION naming `ies`,
    /// carrying whichever UE S1AP IDs could be read.
    Reject {
        /// IEs to report.
        ies: Vec<DiagnosedIe>,
        /// eNB-UE-S1AP-ID, if read.
        enb_ue_s1ap_id: Option<u32>,
        /// MME-UE-S1AP-ID, if read.
        mme_ue_s1ap_id: Option<u32>,
    },
    /// Not decodable (transfer syntax error).
    Undecodable,
}

/// An UPLINK NAS TRANSPORT whose ignore-criticality location IEs may be
/// missing (§10.3.5: a missing `ignore` IE is ignored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UplinkNas {
    /// MME-UE-S1AP-ID.
    pub mme_ue_s1ap_id: u32,
    /// eNB-UE-S1AP-ID.
    pub enb_ue_s1ap_id: u32,
    /// The NAS-PDU.
    pub nas_pdu: Vec<u8>,
    /// EUTRAN-CGI, if present.
    pub eutran_cgi: Option<EutranCgi>,
    /// TAI, if present.
    pub tai: Option<Tai>,
}

fn tai_from(v: &g::TAI) -> Option<Tai> {
    Some(Tai {
        plmn_identity: plmn(&v.plm_nidentity.0)?,
        tac: u16::from_be_bytes(v.tac.0.as_slice().try_into().ok()?),
    })
}

fn cgi_from(v: &g::EUTRAN_CGI) -> Option<EutranCgi> {
    Some(EutranCgi {
        plmn_identity: plmn(&v.plm_nidentity.0)?,
        cell_identity: bits_to_u32(&v.cell_id.0),
    })
}

fn rrc_cause_from(v: u8) -> RrcEstablishmentCause {
    match v {
        g::RRC_Establishment_Cause::EMERGENCY => RrcEstablishmentCause::Emergency,
        g::RRC_Establishment_Cause::HIGH_PRIORITY_ACCESS => {
            RrcEstablishmentCause::HighPriorityAccess
        }
        g::RRC_Establishment_Cause::MT_ACCESS => RrcEstablishmentCause::MtAccess,
        g::RRC_Establishment_Cause::MO_DATA => RrcEstablishmentCause::MoData,
        g::RRC_Establishment_Cause::DELAY_TOLERANT_ACCESS => {
            RrcEstablishmentCause::DelayTolerantAccess
        }
        g::RRC_Establishment_Cause::MO_VOICE_CALL => RrcEstablishmentCause::MoVoiceCall,
        g::RRC_Establishment_Cause::MO_EXCEPTION_DATA => RrcEstablishmentCause::MoExceptionData,
        _ => RrcEstablishmentCause::MoSignalling,
    }
}

fn missing(reject: &mut Vec<DiagnosedIe>, present: bool, id: u16) {
    if !present && !reject.iter().any(|d| d.id == id) {
        reject.push(DiagnosedIe {
            criticality: REJECT,
            id,
            type_of_error: g::TypeOfError::MISSING,
        });
    }
}

fn not_understood(reject: &mut Vec<DiagnosedIe>, id: u16) {
    reject.push(DiagnosedIe {
        criticality: REJECT,
        id,
        type_of_error: g::TypeOfError::NOT_UNDERSTOOD,
    });
}

/// Decode an INITIAL UE MESSAGE (TS 36.413 §9.1.7.1) with §10.3.4.2 / §10.3.5.
///
/// Mandatory `reject` IEs (eNB-UE-S1AP-ID, NAS-PDU, TAI) missing or not
/// understood reject the message. A missing EUTRAN-CGI or RRC Establishment
/// Cause (both `ignore`) is ignored: the cell identity is then 0 and the cause
/// mo-Signalling, since the handler's type has no "absent".
pub fn decode_initial_ue_message(bytes: &[u8]) -> Class2Decode<InitialUeMessage> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return Class2Decode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return Class2Decode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_initialUEMessage(m) = msg.value else {
        return Class2Decode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut enb_ue_id, mut nas, mut tai, mut cgi, mut cause, mut s_tmsi) =
        (None, None, None, None, None, None);
    use g::InitialUEMessageProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_eNB_UE_S1AP_ID(v) => enb_ue_id = Some(v.0),
            V::Id_NAS_PDU(v) => nas = Some(v.0),
            V::Id_TAI(v) => match tai_from(&v) {
                Some(t) => tai = Some(t),
                None => not_understood(&mut reject, ID_TAI),
            },
            V::Id_EUTRAN_CGI(v) => cgi = cgi_from(&v),
            V::Id_RRC_Establishment_Cause(v) => cause = Some(rrc_cause_from(v.0)),
            V::Id_S_TMSI(v) => match (v.mmec.0.first(), <[u8; 4]>::try_from(v.m_tmsi.0.as_slice()))
            {
                (Some(mmec), Ok(m_tmsi)) => {
                    s_tmsi = Some(STmsi {
                        mmec: *mmec,
                        m_tmsi: u32::from_be_bytes(m_tmsi),
                    });
                }
                _ => not_understood(&mut reject, ID_S_TMSI),
            },
            // GUMMEI, CSG, cell access mode, relay, coverage, NB-IoT, IAB, ...:
            // understood, not used by this MME.
            _ => {}
        }
    }
    missing(&mut reject, enb_ue_id.is_some(), ID_ENB_UE_S1AP_ID);
    missing(&mut reject, nas.is_some(), ID_NAS_PDU);
    missing(&mut reject, tai.is_some(), ID_TAI);
    if !reject.is_empty() {
        return Class2Decode::Reject {
            ies: reject,
            enb_ue_s1ap_id: enb_ue_id,
            mme_ue_s1ap_id: None,
        };
    }
    let (Some(enb_ue_s1ap_id), Some(nas_pdu), Some(tai)) = (enb_ue_id, nas, tai) else {
        return Class2Decode::Undecodable;
    };
    let eutran_cgi = cgi.unwrap_or(EutranCgi {
        plmn_identity: tai.plmn_identity,
        cell_identity: 0,
    });
    Class2Decode::Proceed {
        msg: InitialUeMessage {
            enb_ue_s1ap_id,
            nas_pdu,
            tai,
            eutran_cgi,
            rrc_establishment_cause: cause.unwrap_or(RrcEstablishmentCause::MoSignalling),
            s_tmsi,
        },
        notify,
    }
}

/// Decode an UPLINK NAS TRANSPORT (TS 36.413 §9.1.7.3) with §10.3.4.2 /
/// §10.3.5. EUTRAN-CGI and TAI are `ignore`: missing, they are `None` and the
/// stored location is left as it is.
pub fn decode_uplink_nas_transport(bytes: &[u8]) -> Class2Decode<UplinkNas> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return Class2Decode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return Class2Decode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_uplinkNASTransport(m) = msg.value else {
        return Class2Decode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut mme_id, mut enb_id, mut nas, mut cgi, mut tai) = (None, None, None, None, None);
    use g::UplinkNASTransportProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme_id = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb_id = Some(v.0),
            V::Id_NAS_PDU(v) => nas = Some(v.0),
            V::Id_EUTRAN_CGI(v) => cgi = cgi_from(&v),
            V::Id_TAI(v) => tai = tai_from(&v),
            _ => {}
        }
    }
    missing(&mut reject, mme_id.is_some(), ID_MME_UE_S1AP_ID);
    missing(&mut reject, enb_id.is_some(), ID_ENB_UE_S1AP_ID);
    missing(&mut reject, nas.is_some(), ID_NAS_PDU);
    if !reject.is_empty() {
        return Class2Decode::Reject {
            ies: reject,
            enb_ue_s1ap_id: enb_id,
            mme_ue_s1ap_id: mme_id,
        };
    }
    let (Some(mme_ue_s1ap_id), Some(enb_ue_s1ap_id), Some(nas_pdu)) = (mme_id, enb_id, nas) else {
        return Class2Decode::Undecodable;
    };
    Class2Decode::Proceed {
        msg: UplinkNas {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            nas_pdu,
            eutran_cgi: cgi,
            tai,
        },
        notify,
    }
}

/// Criticality Diagnostics in the hand-written type, for the ERROR INDICATION
/// (still built by the hand-written codec until its own stage).
pub fn error_indication_diagnostics(
    procedure_code: u8,
    ies: &[DiagnosedIe],
) -> nextgcore_s1ap::CriticalityDiagnostics {
    error_indication_diagnostics_for(
        procedure_code,
        nextgcore_s1ap::triggering_message::INITIATING_MESSAGE,
        IGNORE,
        ies,
    )
}

/// [`error_indication_diagnostics`] for any triggering message and procedure
/// criticality.
pub fn error_indication_diagnostics_for(
    procedure_code: u8,
    triggering_message: u8,
    procedure_criticality: u8,
    ies: &[DiagnosedIe],
) -> nextgcore_s1ap::CriticalityDiagnostics {
    nextgcore_s1ap::CriticalityDiagnostics {
        procedure_code: Some(procedure_code),
        triggering_message: Some(triggering_message),
        procedure_criticality: Some(procedure_criticality),
        ies: ies
            .iter()
            .take(256)
            .map(|d| nextgcore_s1ap::IeCriticalityDiagnostics {
                ie_criticality: match d.criticality {
                    IGNORE => nextgcore_s1ap::Criticality::Ignore,
                    NOTIFY => nextgcore_s1ap::Criticality::Notify,
                    _ => nextgcore_s1ap::Criticality::Reject,
                },
                ie_id: d.id,
                type_of_error: if d.type_of_error == g::TypeOfError::MISSING {
                    nextgcore_s1ap::TypeOfError::Missing
                } else {
                    nextgcore_s1ap::TypeOfError::NotUnderstood
                },
            })
            .collect(),
    }
}

/// Encode a DOWNLINK NAS TRANSPORT (TS 36.413 §9.1.7.2) with the generated
/// codec: MME-UE-S1AP-ID reject, eNB-UE-S1AP-ID reject, NAS-PDU reject. Unlike
/// the hand-written encoder, a NAS-PDU past 16 KB is carried (X.691 §11.9.3.8).
pub fn build_downlink_nas_transport(
    enb_ue_s1ap_id: u32,
    mme_ue_s1ap_id: u32,
    nas_pdu: &[u8],
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::DownlinkNASTransportProtocolIEs_EntryValue as V;
    let ie = |id: u16, value: V| g::DownlinkNASTransportProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(REJECT),
        value,
    };
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_DOWNLINK_NAS_TRANSPORT),
        criticality: g::Criticality(IGNORE),
        value: g::InitiatingMessageValue::Id_downlinkNASTransport(g::DownlinkNASTransport {
            protocol_i_es: g::DownlinkNASTransportProtocolIEs(vec![
                ie(
                    ID_MME_UE_S1AP_ID,
                    V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(mme_ue_s1ap_id)),
                ),
                ie(
                    ID_ENB_UE_S1AP_ID,
                    V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(enb_ue_s1ap_id)),
                ),
                ie(ID_NAS_PDU, V::Id_NAS_PDU(g::NAS_PDU(nas_pdu.to_vec()))),
            ]),
        }),
    }))
}

/// Whether `bytes` is an initiating message of `procedure_code`.
pub fn is_initiating(bytes: &[u8], procedure_code: u8) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x00 && bytes[1] == procedure_code
}

// ============================================================================
// Initial Context Setup (TS 36.413 §8.3.1) -- stage 4
// ============================================================================

/// `id-InitialContextSetup`.
pub const PROC_INITIAL_CONTEXT_SETUP: u8 = 9;

const ID_UE_AMBR: u16 = 66;
const ID_ERAB_TO_BE_SETUP_LIST_CTXT_SU_REQ: u16 = 24;
const ID_ERAB_TO_BE_SETUP_ITEM_CTXT_SU_REQ: u16 = 52;
const ID_UE_SECURITY_CAPABILITIES: u16 = 107;
const ID_SECURITY_KEY: u16 = 73;

fn bytes_to_bits(bytes: &[u8]) -> BitVec<u8, Msb0> {
    BitVec::from_slice(bytes)
}

fn bits_to_bytes(bits: &BitVec<u8, Msb0>) -> Vec<u8> {
    bits.clone().into_vec()
}

/// E-RAB Level QoS Parameters (TS 36.413 §9.2.1.15) in the generated type.
fn erab_qos(q: &nextgcore_s1ap::ErabLevelQosParameters) -> g::E_RABLevelQoSParameters {
    g::E_RABLevelQoSParameters {
        qci: g::QCI(q.qci),
        allocation_retention_priority: g::AllocationAndRetentionPriority {
            priority_level: g::PriorityLevel(q.arp.priority_level),
            pre_emption_capability: g::Pre_emptionCapability(u8::from(
                q.arp.pre_emption_capability,
            )),
            pre_emption_vulnerability: g::Pre_emptionVulnerability(u8::from(
                q.arp.pre_emption_vulnerability,
            )),
            ie_extensions: None,
        },
        gbr_qos_information: q.gbr_qos_info.as_ref().map(|gbr| g::GBR_QosInformation {
            e_rab_maximum_bitrate_dl: g::BitRate(gbr.erab_max_bitrate_dl),
            e_rab_maximum_bitrate_ul: g::BitRate(gbr.erab_max_bitrate_ul),
            e_rab_guaranteed_bitrate_dl: g::BitRate(gbr.erab_guaranteed_bitrate_dl),
            e_rab_guaranteed_bitrate_ul: g::BitRate(gbr.erab_guaranteed_bitrate_ul),
            ie_extensions: None,
        }),
        ie_extensions: None,
    }
}

/// Encode an INITIAL CONTEXT SETUP REQUEST (TS 36.413 §9.1.4.1) with the
/// generated codec. IE order follows `InitialContextSetupRequestIEs`, every IE
/// criticality reject; each E-RAB item is criticality reject.
pub fn build_initial_context_setup_request(
    req: &nextgcore_s1ap::InitialContextSetupRequest,
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::InitialContextSetupRequestProtocolIEs_EntryValue as V;
    let ie = |id: u16, value: V| g::InitialContextSetupRequestProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(REJECT),
        value,
    };
    let erabs = req
        .erab_list
        .iter()
        .map(|e| g::E_RABToBeSetupListCtxtSUReq_Entry {
            id: g::ProtocolIE_ID(ID_ERAB_TO_BE_SETUP_ITEM_CTXT_SU_REQ),
            criticality: g::Criticality(REJECT),
            value: g::E_RABToBeSetupListCtxtSUReq_EntryValue::Id_E_RABToBeSetupItemCtxtSUReq(
                g::E_RABToBeSetupItemCtxtSUReq {
                    e_rab_id: g::E_RAB_ID(e.erab_id),
                    e_ra_blevel_qo_s_parameters: erab_qos(&e.erab_qos),
                    transport_layer_address: g::TransportLayerAddress(bytes_to_bits(
                        &e.transport_layer_address,
                    )),
                    gtp_teid: g::GTP_TEID(e.gtp_teid.to_be_bytes().to_vec()),
                    nas_pdu: e.nas_pdu.as_ref().map(|n| g::NAS_PDU(n.clone())),
                    ie_extensions: None,
                },
            ),
        })
        .collect();
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_INITIAL_CONTEXT_SETUP),
        criticality: g::Criticality(REJECT),
        value: g::InitiatingMessageValue::Id_InitialContextSetup(g::InitialContextSetupRequest {
            protocol_i_es: g::InitialContextSetupRequestProtocolIEs(vec![
                ie(
                    ID_MME_UE_S1AP_ID,
                    V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(req.mme_ue_s1ap_id)),
                ),
                ie(
                    ID_ENB_UE_S1AP_ID,
                    V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(req.enb_ue_s1ap_id)),
                ),
                ie(
                    ID_UE_AMBR,
                    V::Id_uEaggregateMaximumBitrate(ambr(&req.ue_ambr)),
                ),
                ie(
                    ID_ERAB_TO_BE_SETUP_LIST_CTXT_SU_REQ,
                    V::Id_E_RABToBeSetupListCtxtSUReq(g::E_RABToBeSetupListCtxtSUReq(erabs)),
                ),
                ie(
                    ID_UE_SECURITY_CAPABILITIES,
                    V::Id_UESecurityCapabilities(g::UESecurityCapabilities {
                        encryption_algorithms: g::EncryptionAlgorithms(bytes_to_bits(
                            &req.ue_security_capabilities
                                .encryption_algorithms
                                .to_be_bytes(),
                        )),
                        integrity_protection_algorithms: g::IntegrityProtectionAlgorithms(
                            bytes_to_bits(
                                &req.ue_security_capabilities
                                    .integrity_algorithms
                                    .to_be_bytes(),
                            ),
                        ),
                        ie_extensions: None,
                    }),
                ),
                ie(
                    ID_SECURITY_KEY,
                    V::Id_SecurityKey(g::SecurityKey(bytes_to_bits(&req.security_key))),
                ),
            ]),
        }),
    }))
}

/// The domain `Cause` for a generated one. A value the domain enums do not
/// define (a later release's addition) maps to `None`, which is how the
/// hand-written decoder this replaced treated it (#514 stage 13).
fn domain_cause(cause: &g::Cause) -> Option<Cause> {
    use nextgcore_s1ap::{CauseMisc, CauseNas, CauseProtocol, CauseRadioNetwork, CauseTransport};
    Some(match cause {
        g::Cause::RadioNetwork(v) => {
            Cause::RadioNetwork(CauseRadioNetwork::try_from(i64::from(v.0)).ok()?)
        }
        g::Cause::Transport(v) => Cause::Transport(CauseTransport::try_from(i64::from(v.0)).ok()?),
        g::Cause::Nas(v) => Cause::Nas(CauseNas::try_from(i64::from(v.0)).ok()?),
        g::Cause::Protocol(v) => Cause::Protocol(CauseProtocol::try_from(i64::from(v.0)).ok()?),
        g::Cause::Misc(v) => Cause::Misc(CauseMisc::try_from(i64::from(v.0)).ok()?),
    })
}

// ============================================================================
// PDUs no family decode took (#514 stage 13)
// ============================================================================

/// What an S1AP PDU is when none of the generated message decodes took it.
///
/// This replaced the hand-written `decode_s1ap_pdu` fallback: the generated
/// family decodes above own every message mmed implements, so a PDU reaching
/// here is either malformed, a message only the MME sends, or a procedure mmed
/// does not implement. Only the S1AP-PDU header is read (X.691 §23 CHOICE,
/// §13 INTEGER, §14 ENUMERATED, §10.2 open type), never a message value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unmatched {
    /// The S1AP-PDU header itself does not decode (TS 36.413 §10.2).
    TransferSyntaxError,
    /// A message of a procedure mmed implements whose value did not decode.
    Undecodable {
        procedure_code: u8,
        triggering_message: u8,
    },
    /// A message only the MME originates, received from an eNB.
    MmeOriginated { procedure_code: u8 },
    /// A procedure code mmed does not comprehend (TS 36.413 §10.3.4.1), with
    /// the criticality the sender marked it with (0 reject, 1 ignore, 2 notify).
    UnknownProcedure {
        procedure_code: u8,
        triggering_message: u8,
        criticality: u8,
    },
}

/// Procedure codes mmed implements in some direction.
const IMPLEMENTED_PROCEDURES: &[u8] = &[
    PROC_HANDOVER_PREPARATION,
    PROC_HANDOVER_RESOURCE_ALLOCATION,
    PROC_HANDOVER_NOTIFICATION,
    PROC_PATH_SWITCH_REQUEST,
    PROC_HANDOVER_CANCEL,
    PROC_E_RAB_SETUP,
    PROC_E_RAB_MODIFY,
    PROC_E_RAB_RELEASE,
    PROC_INITIAL_CONTEXT_SETUP,
    PROC_PAGING,
    PROC_DOWNLINK_NAS_TRANSPORT,
    PROC_INITIAL_UE_MESSAGE,
    PROC_UPLINK_NAS_TRANSPORT,
    PROC_RESET,
    PROC_ERROR_INDICATION,
    PROC_NAS_NON_DELIVERY_INDICATION,
    PROC_S1_SETUP,
    PROC_UE_CONTEXT_RELEASE_REQUEST,
    PROC_UE_CONTEXT_MODIFICATION,
    PROC_UE_CAPABILITY_INFO_INDICATION,
    PROC_UE_CONTEXT_RELEASE,
    PROC_ENB_STATUS_TRANSFER,
    PROC_MME_STATUS_TRANSFER,
    PROC_ENB_CONFIGURATION_UPDATE,
    PROC_MME_CONFIGURATION_UPDATE,
    PROC_OVERLOAD_START,
    PROC_OVERLOAD_STOP,
    PROC_WRITE_REPLACE_WARNING,
    PROC_KILL,
    PROC_E_RAB_RELEASE_INDICATION,
    PROC_E_RAB_MODIFICATION_INDICATION,
    PROC_LOCATION_REPORTING_CONTROL,
    PROC_LOCATION_REPORTING_FAILURE_INDICATION,
    PROC_LOCATION_REPORT,
];

/// `(triggering message, procedure code)` of every message only the MME sends.
const MME_ORIGINATED: &[(u8, u8)] = &[
    (0, PROC_DOWNLINK_NAS_TRANSPORT),
    (0, PROC_INITIAL_CONTEXT_SETUP),
    (0, PROC_UE_CONTEXT_RELEASE),
    (0, PROC_E_RAB_SETUP),
    (0, PROC_E_RAB_MODIFY),
    (0, PROC_E_RAB_RELEASE),
    (0, PROC_PAGING),
    (0, PROC_HANDOVER_RESOURCE_ALLOCATION),
    (0, PROC_MME_STATUS_TRANSFER),
    (0, PROC_MME_CONFIGURATION_UPDATE),
    (0, PROC_UE_CONTEXT_MODIFICATION),
    (0, PROC_OVERLOAD_START),
    (0, PROC_OVERLOAD_STOP),
    (0, PROC_WRITE_REPLACE_WARNING),
    (0, PROC_KILL),
    (0, PROC_LOCATION_REPORTING_CONTROL),
    (1, PROC_S1_SETUP),
    (1, PROC_E_RAB_MODIFICATION_INDICATION),
    (1, PROC_HANDOVER_PREPARATION),
    (1, PROC_PATH_SWITCH_REQUEST),
    (1, PROC_HANDOVER_CANCEL),
    (1, PROC_ENB_CONFIGURATION_UPDATE),
    (2, PROC_S1_SETUP),
    (2, PROC_HANDOVER_PREPARATION),
    (2, PROC_PATH_SWITCH_REQUEST),
    (2, PROC_ENB_CONFIGURATION_UPDATE),
];

/// Reads the S1AP-PDU header: `(triggering message, procedure code,
/// criticality)` when the CHOICE index, the two header fields and the open
/// type's length all decode and the length matches the bytes that follow.
pub fn pdu_header(bytes: &[u8]) -> Option<(u8, u8, u8)> {
    // Octet 0: extension bit 0, then the 2-bit CHOICE index, then padding.
    let first = *bytes.first()?;
    if first & 0x80 != 0 || first & 0x1f != 0 {
        return None;
    }
    let triggering_message = (first >> 5) & 0x03;
    if triggering_message > 2 {
        return None;
    }
    // Octet 1: ProcedureCode INTEGER (0..255), one aligned octet.
    let procedure_code = *bytes.get(1)?;
    // Octet 2: Criticality ENUMERATED {reject, ignore, notify} in 2 bits.
    let crit = *bytes.get(2)?;
    if crit & 0x3f != 0 || (crit >> 6) > 2 {
        return None;
    }
    // Octet 3..: the open type's length determinant (X.691 §11.9.3.6/7).
    let rest = bytes.get(3..)?;
    let (len, header) = match *rest.first()? {
        b if b & 0x80 == 0 => (usize::from(b), 1),
        b if b & 0xc0 == 0x80 => (usize::from(b & 0x3f) << 8 | usize::from(*rest.get(1)?), 2),
        // Fragmented values are not reassembled here; a value that large is
        // not a header question, so say only that the header decodes.
        _ => return Some((triggering_message, procedure_code, crit >> 6)),
    };
    if rest.len() != header + len {
        return None;
    }
    Some((triggering_message, procedure_code, crit >> 6))
}

/// Classifies a PDU none of the generated message decodes took.
pub fn classify_unmatched(bytes: &[u8]) -> Unmatched {
    let Some((triggering_message, procedure_code, criticality)) = pdu_header(bytes) else {
        return Unmatched::TransferSyntaxError;
    };
    if MME_ORIGINATED.contains(&(triggering_message, procedure_code)) {
        Unmatched::MmeOriginated { procedure_code }
    } else if IMPLEMENTED_PROCEDURES.contains(&procedure_code) {
        Unmatched::Undecodable {
            procedure_code,
            triggering_message,
        }
    } else {
        Unmatched::UnknownProcedure {
            procedure_code,
            triggering_message,
            criticality,
        }
    }
}

/// Outcome of decoding a response message (TS 36.413 §10.3.4.2 / §10.3.5).
#[derive(Debug, Clone)]
pub enum ResponseDecode<T> {
    /// Act on the response; report `notify` IEs in an ERROR INDICATION.
    Decoded {
        /// The response.
        msg: T,
        /// IEs to report.
        notify: Vec<DiagnosedIe>,
    },
    /// An unknown `reject` IE: the procedure is unsuccessfully terminated and
    /// handled locally; nothing is sent.
    Failed(Vec<DiagnosedIe>),
    /// Not decodable, or the UE it concerns cannot be identified.
    Undecodable,
}

/// Decode an INITIAL CONTEXT SETUP RESPONSE (TS 36.413 §9.1.4.2). Every IE is
/// criticality ignore, so a missing one is ignored; a response that names no
/// MME-UE-S1AP-ID concerns no UE we can find, and is `Undecodable`.
pub fn decode_initial_context_setup_response(
    bytes: &[u8],
) -> ResponseDecode<nextgcore_s1ap::InitialContextSetupResponse> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return ResponseDecode::Undecodable;
    };
    let g::S1AP_PDU::SuccessfulOutcome(msg) = pdu else {
        return ResponseDecode::Undecodable;
    };
    let g::SuccessfulOutcomeValue::Id_InitialContextSetup(rsp) = msg.value else {
        return ResponseDecode::Undecodable;
    };
    let (reject, notify) = classify_unknown(&unknown);
    if !reject.is_empty() {
        return ResponseDecode::Failed(reject);
    }
    let (mut mme, mut enb, mut setup, mut failed) = (None, 0, Vec::new(), Vec::new());
    use g::InitialContextSetupResponseProtocolIEs_EntryValue as V;
    for ie in rsp.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = v.0,
            V::Id_E_RABSetupListCtxtSURes(list) => {
                for entry in list.0 {
                    let g::E_RABSetupListCtxtSURes_EntryValue::Id_E_RABSetupItemCtxtSURes(item) =
                        entry.value;
                    let Ok(teid) = <[u8; 4]>::try_from(item.gtp_teid.0.as_slice()) else {
                        return ResponseDecode::Undecodable;
                    };
                    setup.push(nextgcore_s1ap::ErabSetupItem {
                        erab_id: item.e_rab_id.0,
                        transport_layer_address: bits_to_bytes(&item.transport_layer_address.0),
                        gtp_teid: u32::from_be_bytes(teid),
                    });
                }
            }
            V::Id_E_RABFailedToSetupListCtxtSURes(list) => {
                for entry in list.0 {
                    let g::E_RABList_EntryValue::Id_E_RABItem(item) = entry.value;
                    let Some(cause) = domain_cause(&item.cause) else {
                        return ResponseDecode::Undecodable;
                    };
                    failed.push(nextgcore_s1ap::ErabFailedItem {
                        erab_id: item.e_rab_id.0,
                        cause,
                    });
                }
            }
            _ => {}
        }
    }
    let Some(mme_ue_s1ap_id) = mme else {
        return ResponseDecode::Undecodable;
    };
    ResponseDecode::Decoded {
        msg: nextgcore_s1ap::InitialContextSetupResponse {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: enb,
            erab_setup_list: setup,
            erab_failed_list: failed,
        },
        notify,
    }
}

/// Decode an INITIAL CONTEXT SETUP FAILURE (TS 36.413 §9.1.4.3), with the same
/// rules as [`decode_initial_context_setup_response`]. A missing Cause
/// (criticality ignore) is read as radioNetwork / unspecified.
pub fn decode_initial_context_setup_failure(
    bytes: &[u8],
) -> ResponseDecode<nextgcore_s1ap::InitialContextSetupFailure> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return ResponseDecode::Undecodable;
    };
    let g::S1AP_PDU::UnsuccessfulOutcome(msg) = pdu else {
        return ResponseDecode::Undecodable;
    };
    let g::UnsuccessfulOutcomeValue::Id_InitialContextSetup(f) = msg.value else {
        return ResponseDecode::Undecodable;
    };
    let (reject, notify) = classify_unknown(&unknown);
    if !reject.is_empty() {
        return ResponseDecode::Failed(reject);
    }
    let (mut mme, mut enb, mut cause) = (None, 0, None);
    use g::InitialContextSetupFailureProtocolIEs_EntryValue as V;
    for ie in f.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = v.0,
            V::Id_Cause(c) => cause = domain_cause(&c),
            _ => {}
        }
    }
    let Some(mme_ue_s1ap_id) = mme else {
        return ResponseDecode::Undecodable;
    };
    ResponseDecode::Decoded {
        msg: nextgcore_s1ap::InitialContextSetupFailure {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: enb,
            cause: cause.unwrap_or(Cause::RadioNetwork(
                nextgcore_s1ap::CauseRadioNetwork::Unspecified,
            )),
        },
        notify,
    }
}

/// Whether `bytes` is a successful (`0x20`) or unsuccessful (`0x40`) outcome of
/// `procedure_code`: the CHOICE index sits in bits 7..6 after the extension bit.
pub fn is_outcome(bytes: &[u8], successful: bool, procedure_code: u8) -> bool {
    bytes.len() >= 2
        && bytes[0] == if successful { 0x20 } else { 0x40 }
        && bytes[1] == procedure_code
}

// ============================================================================
// UE Context Release (TS 36.413 §8.3.2, §8.3.3) -- stage 5
// ============================================================================

/// `id-UEContextRelease` (Class 1: Command, Complete).
pub const PROC_UE_CONTEXT_RELEASE: u8 = 23;
/// `id-UEContextReleaseRequest` (Class 2).
pub const PROC_UE_CONTEXT_RELEASE_REQUEST: u8 = 18;

const ID_UE_S1AP_IDS: u16 = 99;

/// Encode a UE CONTEXT RELEASE COMMAND (TS 36.413 §9.1.4.6) with the generated
/// codec: UE-S1AP-IDs reject, Cause ignore; procedure criticality reject.
pub fn build_ue_context_release_command(
    ids: &nextgcore_s1ap::UeS1apIds,
    cause: Cause,
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::UEContextReleaseCommandProtocolIEs_EntryValue as V;
    let ue_ids = match *ids {
        nextgcore_s1ap::UeS1apIds::Pair {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
        } => g::UE_S1AP_IDs::UE_S1AP_ID_pair(g::UE_S1AP_ID_pair {
            mme_ue_s1ap_id: g::MME_UE_S1AP_ID(mme_ue_s1ap_id),
            enb_ue_s1ap_id: g::ENB_UE_S1AP_ID(enb_ue_s1ap_id),
            ie_extensions: None,
        }),
        nextgcore_s1ap::UeS1apIds::MmeOnly { mme_ue_s1ap_id } => {
            g::UE_S1AP_IDs::MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(mme_ue_s1ap_id))
        }
    };
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_UE_CONTEXT_RELEASE),
        criticality: g::Criticality(REJECT),
        value: g::InitiatingMessageValue::Id_UEContextRelease(g::UEContextReleaseCommand {
            protocol_i_es: g::UEContextReleaseCommandProtocolIEs(vec![
                g::UEContextReleaseCommandProtocolIEs_Entry {
                    id: g::ProtocolIE_ID(ID_UE_S1AP_IDS),
                    criticality: g::Criticality(REJECT),
                    value: V::Id_UE_S1AP_IDs(ue_ids),
                },
                g::UEContextReleaseCommandProtocolIEs_Entry {
                    id: g::ProtocolIE_ID(ID_CAUSE),
                    criticality: g::Criticality(IGNORE),
                    value: V::Id_Cause(generated_cause(cause)),
                },
            ]),
        }),
    }))
}

/// Decode a UE CONTEXT RELEASE REQUEST (TS 36.413 §9.1.4.5), the initiating
/// message of a Class 2 procedure, with §10.3.4.2 / §10.3.5.
///
/// MME-UE-S1AP-ID and eNB-UE-S1AP-ID are `reject`: missing, the request is
/// not run. Cause is `ignore`: missing, it reads as radioNetwork / unspecified.
/// GW Context Release Indication and the Secondary RAT report are understood
/// and not used by this MME.
pub fn decode_ue_context_release_request(
    bytes: &[u8],
) -> Class2Decode<nextgcore_s1ap::UeContextReleaseRequest> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return Class2Decode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return Class2Decode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_UEContextReleaseRequest(m) = msg.value else {
        return Class2Decode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut mme_id, mut enb_id, mut cause) = (None, None, None);
    use g::UEContextReleaseRequestProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme_id = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb_id = Some(v.0),
            V::Id_Cause(c) => cause = domain_cause(&c),
            _ => {}
        }
    }
    missing(&mut reject, mme_id.is_some(), ID_MME_UE_S1AP_ID);
    missing(&mut reject, enb_id.is_some(), ID_ENB_UE_S1AP_ID);
    if !reject.is_empty() {
        return Class2Decode::Reject {
            ies: reject,
            enb_ue_s1ap_id: enb_id,
            mme_ue_s1ap_id: mme_id,
        };
    }
    let (Some(mme_ue_s1ap_id), Some(enb_ue_s1ap_id)) = (mme_id, enb_id) else {
        return Class2Decode::Undecodable;
    };
    Class2Decode::Proceed {
        msg: nextgcore_s1ap::UeContextReleaseRequest {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            cause: cause.unwrap_or(Cause::RadioNetwork(
                nextgcore_s1ap::CauseRadioNetwork::Unspecified,
            )),
        },
        notify,
    }
}

/// A UE CONTEXT RELEASE COMPLETE whose UE S1AP IDs, both criticality
/// `ignore`, may be missing (§10.3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseComplete {
    /// MME-UE-S1AP-ID, if present.
    pub mme_ue_s1ap_id: Option<u32>,
    /// eNB-UE-S1AP-ID, if present.
    pub enb_ue_s1ap_id: Option<u32>,
}

/// Decode a UE CONTEXT RELEASE COMPLETE (TS 36.413 §9.1.4.7), a response
/// message: an unknown `reject` IE fails the procedure locally. A complete
/// that carries neither UE S1AP ID identifies no UE and is `Undecodable`.
pub fn decode_ue_context_release_complete(bytes: &[u8]) -> ResponseDecode<ReleaseComplete> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return ResponseDecode::Undecodable;
    };
    let g::S1AP_PDU::SuccessfulOutcome(msg) = pdu else {
        return ResponseDecode::Undecodable;
    };
    let g::SuccessfulOutcomeValue::Id_UEContextRelease(c) = msg.value else {
        return ResponseDecode::Undecodable;
    };
    let (reject, notify) = classify_unknown(&unknown);
    if !reject.is_empty() {
        return ResponseDecode::Failed(reject);
    }
    let (mut mme, mut enb) = (None, None);
    use g::UEContextReleaseCompleteProtocolIEs_EntryValue as V;
    for ie in c.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = Some(v.0),
            _ => {}
        }
    }
    if mme.is_none() && enb.is_none() {
        return ResponseDecode::Undecodable;
    }
    ResponseDecode::Decoded {
        msg: ReleaseComplete {
            mme_ue_s1ap_id: mme,
            enb_ue_s1ap_id: enb,
        },
        notify,
    }
}

// ============================================================================
// E-RAB management (TS 36.413 §8.2.1-§8.2.3) -- stage 6
// ============================================================================

/// `id-E-RABSetup`.
pub const PROC_E_RAB_SETUP: u8 = 5;
/// `id-E-RABModify`.
pub const PROC_E_RAB_MODIFY: u8 = 6;
/// `id-E-RABRelease`.
pub const PROC_E_RAB_RELEASE: u8 = 7;

const ID_ERAB_TO_BE_SETUP_LIST_BEARER_SU_REQ: u16 = 16;
const ID_ERAB_TO_BE_SETUP_ITEM_BEARER_SU_REQ: u16 = 17;
const ID_ERAB_TO_BE_MODIFIED_LIST_BEARER_MOD_REQ: u16 = 30;
const ID_ERAB_TO_BE_MODIFIED_ITEM_BEARER_MOD_REQ: u16 = 36;
const ID_ERAB_TO_BE_RELEASED_LIST: u16 = 33;
const ID_ERAB_ITEM: u16 = 35;

/// The largest legacy Bit Rate (TS 36.413 §9.2.1.20, BitRate ::= INTEGER
/// (0..10000000000)).
const MAX_BIT_RATE: u64 = 10_000_000_000;

/// The UE Aggregate Maximum Bit Rate IE (TS 36.413 §9.2.1.20). A direction above
/// 10 Gbit/s puts the legacy Bit Rate at its maximum and adds the Rel-15
/// Extended UE Aggregate Maximum Bit Rate for that direction (criticality
/// ignore, so a legacy eNB reads the maximum and an EN-DC one the real value).
fn ambr(a: &nextgcore_s1ap::UeAmbr) -> g::UEAggregateMaximumBitrate {
    use g::UEAggregateMaximumBitrateIE_Extensions_EntryExtensionValue as X;
    let mut ext = Vec::new();
    for (v, id, value) in [
        (
            a.dl,
            259,
            X::Id_extended_uEaggregateMaximumBitRateDL as fn(_) -> X,
        ),
        (a.ul, 260, X::Id_extended_uEaggregateMaximumBitRateUL),
    ] {
        if v > MAX_BIT_RATE {
            ext.push(g::UEAggregateMaximumBitrateIE_Extensions_Entry {
                id: g::ProtocolExtensionID(id),
                criticality: g::Criticality(IGNORE),
                extension_value: value(g::ExtendedBitRate(v)),
            });
        }
    }
    g::UEAggregateMaximumBitrate {
        u_eaggregate_maximum_bit_rate_dl: g::BitRate(a.dl.min(MAX_BIT_RATE)),
        u_eaggregate_maximum_bit_rate_ul: g::BitRate(a.ul.min(MAX_BIT_RATE)),
        ie_extensions: (!ext.is_empty()).then_some(g::UEAggregateMaximumBitrateIE_Extensions(ext)),
    }
}

fn erab_list(items: &[nextgcore_s1ap::ErabItem]) -> g::E_RABList {
    g::E_RABList(
        items
            .iter()
            .map(|i| g::E_RABList_Entry {
                id: g::ProtocolIE_ID(ID_ERAB_ITEM),
                criticality: g::Criticality(IGNORE),
                value: g::E_RABList_EntryValue::Id_E_RABItem(g::E_RABItem {
                    e_rab_id: g::E_RAB_ID(i.erab_id),
                    cause: generated_cause(i.cause),
                    ie_extensions: None,
                }),
            })
            .collect(),
    )
}

/// Encode an E-RAB SETUP REQUEST (TS 36.413 §9.1.3.1): every IE and item
/// criticality reject; procedure criticality reject.
pub fn build_erab_setup_request(
    req: &nextgcore_s1ap::ErabSetupRequest,
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::E_RABSetupRequestProtocolIEs_EntryValue as V;
    let ie = |id: u16, value: V| g::E_RABSetupRequestProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(REJECT),
        value,
    };
    let items = req
        .erab_list
        .iter()
        .map(|e| g::E_RABToBeSetupListBearerSUReq_Entry {
            id: g::ProtocolIE_ID(ID_ERAB_TO_BE_SETUP_ITEM_BEARER_SU_REQ),
            criticality: g::Criticality(REJECT),
            value: g::E_RABToBeSetupListBearerSUReq_EntryValue::Id_E_RABToBeSetupItemBearerSUReq(
                g::E_RABToBeSetupItemBearerSUReq {
                    e_rab_id: g::E_RAB_ID(e.erab_id),
                    e_ra_blevel_qo_s_parameters: erab_qos(&e.erab_qos),
                    transport_layer_address: g::TransportLayerAddress(bytes_to_bits(
                        &e.transport_layer_address,
                    )),
                    gtp_teid: g::GTP_TEID(e.gtp_teid.to_be_bytes().to_vec()),
                    // NAS-PDU is mandatory in an E-RAB SETUP item.
                    nas_pdu: g::NAS_PDU(e.nas_pdu.clone().unwrap_or_default()),
                    ie_extensions: None,
                },
            ),
        })
        .collect();
    let mut ies = vec![
        ie(
            ID_MME_UE_S1AP_ID,
            V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(req.mme_ue_s1ap_id)),
        ),
        ie(
            ID_ENB_UE_S1AP_ID,
            V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(req.enb_ue_s1ap_id)),
        ),
    ];
    if let Some(a) = &req.ue_ambr {
        ies.push(ie(ID_UE_AMBR, V::Id_uEaggregateMaximumBitrate(ambr(a))));
    }
    ies.push(ie(
        ID_ERAB_TO_BE_SETUP_LIST_BEARER_SU_REQ,
        V::Id_E_RABToBeSetupListBearerSUReq(g::E_RABToBeSetupListBearerSUReq(items)),
    ));
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_E_RAB_SETUP),
        criticality: g::Criticality(REJECT),
        value: g::InitiatingMessageValue::Id_E_RABSetup(g::E_RABSetupRequest {
            protocol_i_es: g::E_RABSetupRequestProtocolIEs(ies),
        }),
    }))
}

/// Encode an E-RAB MODIFY REQUEST (TS 36.413 §9.1.3.3): every IE and item
/// criticality reject; procedure criticality reject.
pub fn build_erab_modify_request(
    req: &nextgcore_s1ap::ErabModifyRequest,
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::E_RABModifyRequestProtocolIEs_EntryValue as V;
    let ie = |id: u16, value: V| g::E_RABModifyRequestProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(REJECT),
        value,
    };
    let items = req
        .erab_list
        .iter()
        .map(|e| g::E_RABToBeModifiedListBearerModReq_Entry {
            id: g::ProtocolIE_ID(ID_ERAB_TO_BE_MODIFIED_ITEM_BEARER_MOD_REQ),
            criticality: g::Criticality(REJECT),
            value:
                g::E_RABToBeModifiedListBearerModReq_EntryValue::Id_E_RABToBeModifiedItemBearerModReq(
                    g::E_RABToBeModifiedItemBearerModReq {
                        e_rab_id: g::E_RAB_ID(e.erab_id),
                        e_rab_level_qo_s_parameters: erab_qos(&e.erab_qos),
                        nas_pdu: g::NAS_PDU(e.nas_pdu.clone()),
                        ie_extensions: None,
                    },
                ),
        })
        .collect();
    let mut ies = vec![
        ie(
            ID_MME_UE_S1AP_ID,
            V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(req.mme_ue_s1ap_id)),
        ),
        ie(
            ID_ENB_UE_S1AP_ID,
            V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(req.enb_ue_s1ap_id)),
        ),
    ];
    if let Some(a) = &req.ue_ambr {
        ies.push(ie(ID_UE_AMBR, V::Id_uEaggregateMaximumBitrate(ambr(a))));
    }
    ies.push(ie(
        ID_ERAB_TO_BE_MODIFIED_LIST_BEARER_MOD_REQ,
        V::Id_E_RABToBeModifiedListBearerModReq(g::E_RABToBeModifiedListBearerModReq(items)),
    ));
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_E_RAB_MODIFY),
        criticality: g::Criticality(REJECT),
        value: g::InitiatingMessageValue::Id_E_RABModify(g::E_RABModifyRequest {
            protocol_i_es: g::E_RABModifyRequestProtocolIEs(ies),
        }),
    }))
}

/// Encode an E-RAB RELEASE COMMAND (TS 36.413 §9.1.3.5): the UE IDs and
/// UE-AMBR reject, E-RABToBeReleasedList and NAS-PDU ignore (each E-RAB item
/// ignore); procedure criticality reject.
pub fn build_erab_release_command(
    cmd: &nextgcore_s1ap::ErabReleaseCommand,
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::E_RABReleaseCommandProtocolIEs_EntryValue as V;
    let ie = |id: u16, criticality: u8, value: V| g::E_RABReleaseCommandProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(criticality),
        value,
    };
    let mut ies = vec![
        ie(
            ID_MME_UE_S1AP_ID,
            REJECT,
            V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(cmd.mme_ue_s1ap_id)),
        ),
        ie(
            ID_ENB_UE_S1AP_ID,
            REJECT,
            V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(cmd.enb_ue_s1ap_id)),
        ),
    ];
    if let Some(a) = &cmd.ue_ambr {
        ies.push(ie(
            ID_UE_AMBR,
            REJECT,
            V::Id_uEaggregateMaximumBitrate(ambr(a)),
        ));
    }
    ies.push(ie(
        ID_ERAB_TO_BE_RELEASED_LIST,
        IGNORE,
        V::Id_E_RABToBeReleasedList(erab_list(&cmd.erab_list)),
    ));
    if let Some(nas) = &cmd.nas_pdu {
        ies.push(ie(
            ID_NAS_PDU,
            IGNORE,
            V::Id_NAS_PDU(g::NAS_PDU(nas.clone())),
        ));
    }
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_E_RAB_RELEASE),
        criticality: g::Criticality(REJECT),
        value: g::InitiatingMessageValue::Id_E_RABRelease(g::E_RABReleaseCommand {
            protocol_i_es: g::E_RABReleaseCommandProtocolIEs(ies),
        }),
    }))
}

fn failed_items(list: g::E_RABList) -> Option<Vec<nextgcore_s1ap::ErabFailedItem>> {
    list.0
        .into_iter()
        .map(|entry| {
            let g::E_RABList_EntryValue::Id_E_RABItem(item) = entry.value;
            Some(nextgcore_s1ap::ErabFailedItem {
                erab_id: item.e_rab_id.0,
                cause: domain_cause(&item.cause)?,
            })
        })
        .collect()
}

/// The successful outcome of `procedure_code` with its unknown IEs, or `None`
/// if `bytes` is not one.
fn successful_outcome(bytes: &[u8]) -> Option<(g::SuccessfulOutcomeValue, Vec<UnknownIe>)> {
    let (pdu, unknown) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes).ok()?;
    let g::S1AP_PDU::SuccessfulOutcome(msg) = pdu else {
        return None;
    };
    Some((msg.value, unknown))
}

/// Decode an E-RAB SETUP RESPONSE (TS 36.413 §9.1.3.2), a response message:
/// every IE is `ignore`; one naming no MME-UE-S1AP-ID is `Undecodable`.
pub fn decode_erab_setup_response(
    bytes: &[u8],
) -> ResponseDecode<nextgcore_s1ap::ErabSetupResponse> {
    let Some((g::SuccessfulOutcomeValue::Id_E_RABSetup(rsp), unknown)) = successful_outcome(bytes)
    else {
        return ResponseDecode::Undecodable;
    };
    let (reject, notify) = classify_unknown(&unknown);
    if !reject.is_empty() {
        return ResponseDecode::Failed(reject);
    }
    let (mut mme, mut enb, mut setup, mut failed) = (None, 0, Vec::new(), Vec::new());
    use g::E_RABSetupResponseProtocolIEs_EntryValue as V;
    for ie in rsp.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = v.0,
            V::Id_E_RABSetupListBearerSURes(list) => {
                for entry in list.0 {
                    let g::E_RABSetupListBearerSURes_EntryValue::Id_E_RABSetupItemBearerSURes(item) =
                        entry.value;
                    let Ok(teid) = <[u8; 4]>::try_from(item.gtp_teid.0.as_slice()) else {
                        return ResponseDecode::Undecodable;
                    };
                    setup.push(nextgcore_s1ap::ErabSetupItem {
                        erab_id: item.e_rab_id.0,
                        transport_layer_address: bits_to_bytes(&item.transport_layer_address.0),
                        gtp_teid: u32::from_be_bytes(teid),
                    });
                }
            }
            V::Id_E_RABFailedToSetupListBearerSURes(list) => match failed_items(list) {
                Some(items) => failed = items,
                None => return ResponseDecode::Undecodable,
            },
            _ => {}
        }
    }
    let Some(mme_ue_s1ap_id) = mme else {
        return ResponseDecode::Undecodable;
    };
    ResponseDecode::Decoded {
        msg: nextgcore_s1ap::ErabSetupResponse {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: enb,
            erab_setup_list: setup,
            erab_failed_list: failed,
        },
        notify,
    }
}

/// Decode an E-RAB MODIFY RESPONSE (TS 36.413 §9.1.3.4), with the rules of
/// [`decode_erab_setup_response`].
pub fn decode_erab_modify_response(
    bytes: &[u8],
) -> ResponseDecode<nextgcore_s1ap::ErabModifyResponse> {
    let Some((g::SuccessfulOutcomeValue::Id_E_RABModify(rsp), unknown)) = successful_outcome(bytes)
    else {
        return ResponseDecode::Undecodable;
    };
    let (reject, notify) = classify_unknown(&unknown);
    if !reject.is_empty() {
        return ResponseDecode::Failed(reject);
    }
    let (mut mme, mut enb, mut modified, mut failed) = (None, 0, Vec::new(), Vec::new());
    use g::E_RABModifyResponseProtocolIEs_EntryValue as V;
    for ie in rsp.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = v.0,
            V::Id_E_RABModifyListBearerModRes(list) => {
                modified = list
                    .0
                    .into_iter()
                    .map(|entry| {
                        let g::E_RABModifyListBearerModRes_EntryValue::Id_E_RABModifyItemBearerModRes(
                            item,
                        ) = entry.value;
                        item.e_rab_id.0
                    })
                    .collect();
            }
            V::Id_E_RABFailedToModifyList(list) => match failed_items(list) {
                Some(items) => failed = items,
                None => return ResponseDecode::Undecodable,
            },
            _ => {}
        }
    }
    let Some(mme_ue_s1ap_id) = mme else {
        return ResponseDecode::Undecodable;
    };
    ResponseDecode::Decoded {
        msg: nextgcore_s1ap::ErabModifyResponse {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: enb,
            erab_modify_list: modified,
            erab_failed_list: failed,
        },
        notify,
    }
}

/// Decode an E-RAB RELEASE RESPONSE (TS 36.413 §9.1.3.6), with the rules of
/// [`decode_erab_setup_response`].
pub fn decode_erab_release_response(
    bytes: &[u8],
) -> ResponseDecode<nextgcore_s1ap::ErabReleaseResponse> {
    let Some((g::SuccessfulOutcomeValue::Id_E_RABRelease(rsp), unknown)) =
        successful_outcome(bytes)
    else {
        return ResponseDecode::Undecodable;
    };
    let (reject, notify) = classify_unknown(&unknown);
    if !reject.is_empty() {
        return ResponseDecode::Failed(reject);
    }
    let (mut mme, mut enb, mut released, mut failed) = (None, 0, Vec::new(), Vec::new());
    use g::E_RABReleaseResponseProtocolIEs_EntryValue as V;
    for ie in rsp.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = v.0,
            V::Id_E_RABReleaseListBearerRelComp(list) => {
                released = list
                    .0
                    .into_iter()
                    .map(|entry| {
                        let g::E_RABReleaseListBearerRelComp_EntryValue::Id_E_RABReleaseItemBearerRelComp(
                            item,
                        ) = entry.value;
                        item.e_rab_id.0
                    })
                    .collect();
            }
            V::Id_E_RABFailedToReleaseList(list) => match failed_items(list) {
                Some(items) => failed = items,
                None => return ResponseDecode::Undecodable,
            },
            _ => {}
        }
    }
    let Some(mme_ue_s1ap_id) = mme else {
        return ResponseDecode::Undecodable;
    };
    ResponseDecode::Decoded {
        msg: nextgcore_s1ap::ErabReleaseResponse {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: enb,
            erab_release_list: released,
            erab_failed_list: failed,
        },
        notify,
    }
}

// ============================================================================
// Paging (TS 36.413 §8.5) -- stage 7
// ============================================================================

/// `id-Paging`.
pub const PROC_PAGING: u8 = 10;

const ID_UE_PAGING_ID: u16 = 43;
const ID_PAGING_DRX: u16 = 44;
const ID_TAI_LIST: u16 = 46;
const ID_TAI_ITEM: u16 = 47;
const ID_UE_IDENTITY_INDEX_VALUE: u16 = 80;
const ID_CN_DOMAIN: u16 = 109;

/// Encode a PAGING (TS 36.413 §9.1.6) with the generated codec. IE order
/// follows `PagingIEs`; every IE, and each TAI item, criticality ignore;
/// procedure criticality ignore.
pub fn build_paging(msg: &nextgcore_s1ap::Paging) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::PagingProtocolIEs_EntryValue as V;
    let ie = |id: u16, value: V| g::PagingProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(IGNORE),
        value,
    };
    let paging_id = match &msg.ue_paging_id {
        nextgcore_s1ap::UePagingId::STmsi(s) => g::UEPagingID::S_TMSI(g::S_TMSI {
            mmec: g::MME_Code(vec![s.mmec]),
            m_tmsi: g::M_TMSI(s.m_tmsi.to_be_bytes().to_vec()),
            ie_extensions: None,
        }),
        nextgcore_s1ap::UePagingId::Imsi(imsi) => g::UEPagingID::IMSI(g::IMSI(imsi.clone())),
    };
    let tais = msg
        .tai_list
        .iter()
        .map(|t| g::TAIList_Entry {
            id: g::ProtocolIE_ID(ID_TAI_ITEM),
            criticality: g::Criticality(IGNORE),
            value: g::TAIList_EntryValue::Id_TAIItem(g::TAIItem {
                tai: g::TAI {
                    plm_nidentity: g::TBCD_STRING(t.plmn_identity.to_vec()),
                    tac: g::TAC(t.tac.to_be_bytes().to_vec()),
                    ie_extensions: None,
                },
                ie_extensions: None,
            }),
        })
        .collect();
    let mut ies = vec![
        ie(
            ID_UE_IDENTITY_INDEX_VALUE,
            V::Id_UEIdentityIndexValue(g::UEIdentityIndexValue(u32_to_bits(
                u32::from(msg.ue_identity_index),
                10,
            ))),
        ),
        ie(ID_UE_PAGING_ID, V::Id_UEPagingID(paging_id)),
    ];
    if let Some(drx) = msg.paging_drx {
        ies.push(ie(ID_PAGING_DRX, V::Id_pagingDRX(g::PagingDRX(drx as u8))));
    }
    ies.push(ie(
        ID_CN_DOMAIN,
        V::Id_CNDomain(g::CNDomain(msg.cn_domain as u8)),
    ));
    ies.push(ie(ID_TAI_LIST, V::Id_TAIList(g::TAIList(tais))));
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_PAGING),
        criticality: g::Criticality(IGNORE),
        value: g::InitiatingMessageValue::Id_Paging(g::Paging {
            protocol_i_es: g::PagingProtocolIEs(ies),
        }),
    }))
}

// ============================================================================
// Handover, part 1 (TS 36.413 §8.4.1-§8.4.7) -- stage 8a
// ============================================================================

/// `id-HandoverPreparation`.
pub const PROC_HANDOVER_PREPARATION: u8 = 0;
/// `id-HandoverResourceAllocation`.
pub const PROC_HANDOVER_RESOURCE_ALLOCATION: u8 = 1;
/// `id-HandoverNotification`.
pub const PROC_HANDOVER_NOTIFICATION: u8 = 2;
/// `id-HandoverCancel`.
pub const PROC_HANDOVER_CANCEL: u8 = 4;
/// `id-eNBStatusTransfer`.
pub const PROC_ENB_STATUS_TRANSFER: u8 = 24;
/// `id-MMEStatusTransfer`.
pub const PROC_MME_STATUS_TRANSFER: u8 = 25;

const ID_ENB_STATUS_TRANSFER_CONTAINER: u16 = 90;

/// Encode a HANDOVER PREPARATION FAILURE (TS 36.413 §9.1.5.3): every IE
/// criticality ignore; procedure criticality reject.
pub fn build_handover_preparation_failure(
    msg: &nextgcore_s1ap::HandoverPreparationFailure,
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    build_handover_preparation_failure_with_diagnostics(msg, &[])
}

/// Encode a HANDOVER CANCEL ACKNOWLEDGE (TS 36.413 §9.1.5.11): every IE
/// criticality ignore; procedure criticality reject. `notify` IEs of the
/// HANDOVER CANCEL are reported in its Criticality Diagnostics (§10.3.4.2).
pub fn build_handover_cancel_acknowledge(
    msg: &nextgcore_s1ap::HandoverCancelAcknowledge,
    notify: &[DiagnosedIe],
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::HandoverCancelAcknowledgeProtocolIEs_EntryValue as V;
    let ie = |id: u16, value: V| g::HandoverCancelAcknowledgeProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(IGNORE),
        value,
    };
    let mut ies = vec![
        ie(
            ID_MME_UE_S1AP_ID,
            V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id)),
        ),
        ie(
            ID_ENB_UE_S1AP_ID,
            V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id)),
        ),
    ];
    if !notify.is_empty() {
        ies.push(ie(
            ID_CRITICALITY_DIAGNOSTICS,
            V::Id_CriticalityDiagnostics(diagnostics_for(
                PROC_HANDOVER_CANCEL,
                g::TriggeringMessage::INITIATING_MESSAGE,
                REJECT,
                notify,
            )),
        ));
    }
    encode_pdu(&g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
        procedure_code: g::ProcedureCode(PROC_HANDOVER_CANCEL),
        criticality: g::Criticality(REJECT),
        value: g::SuccessfulOutcomeValue::Id_HandoverCancel(g::HandoverCancelAcknowledge {
            protocol_i_es: g::HandoverCancelAcknowledgeProtocolIEs(ies),
        }),
    }))
}

/// The `ENB-StatusTransfer-TransparentContainer` the hand-written type holds
/// as raw APER, as the generated value.
fn status_container_from(
    raw: &[u8],
) -> Result<g::ENB_StatusTransfer_TransparentContainer, asn1_codecs::PerCodecError> {
    use asn1_codecs::aper::AperCodec;
    let mut data = asn1_codecs::PerCodecData::from_slice_aper(raw);
    g::ENB_StatusTransfer_TransparentContainer::aper_decode(&mut data)
}

/// The generated container as the raw APER the hand-written type holds.
fn status_container_raw(c: &g::ENB_StatusTransfer_TransparentContainer) -> Option<Vec<u8>> {
    use asn1_codecs::aper::AperCodec;
    let mut data = asn1_codecs::PerCodecData::new_aper();
    c.aper_encode(&mut data).ok()?;
    Some(data.into_bytes())
}

/// Encode an MME STATUS TRANSFER (TS 36.413 §9.1.5.7): every IE criticality
/// reject; procedure criticality ignore. The container is relayed as received.
pub fn build_mme_status_transfer(
    msg: &nextgcore_s1ap::MmeStatusTransfer,
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::MMEStatusTransferProtocolIEs_EntryValue as V;
    let ie = |id: u16, value: V| g::MMEStatusTransferProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(REJECT),
        value,
    };
    let container = status_container_from(&msg.status_transfer_container)?;
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_MME_STATUS_TRANSFER),
        criticality: g::Criticality(IGNORE),
        value: g::InitiatingMessageValue::Id_MMEStatusTransfer(g::MMEStatusTransfer {
            protocol_i_es: g::MMEStatusTransferProtocolIEs(vec![
                ie(
                    ID_MME_UE_S1AP_ID,
                    V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id)),
                ),
                ie(
                    ID_ENB_UE_S1AP_ID,
                    V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id)),
                ),
                ie(
                    ID_ENB_STATUS_TRANSFER_CONTAINER,
                    V::Id_eNB_StatusTransfer_TransparentContainer(container),
                ),
            ]),
        }),
    }))
}

/// Decode an ENB STATUS TRANSFER (TS 36.413 §9.1.5.6), the initiating message
/// of a Class 2 procedure: all three IEs are `reject`, so any missing one
/// means the message is not acted on.
pub fn decode_enb_status_transfer(bytes: &[u8]) -> Class2Decode<nextgcore_s1ap::EnbStatusTransfer> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return Class2Decode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return Class2Decode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_eNBStatusTransfer(m) = msg.value else {
        return Class2Decode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut mme, mut enb, mut container) = (None, None, None);
    use g::ENBStatusTransferProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = Some(v.0),
            V::Id_eNB_StatusTransfer_TransparentContainer(c) => match status_container_raw(&c) {
                Some(raw) => container = Some(raw),
                None => not_understood(&mut reject, ID_ENB_STATUS_TRANSFER_CONTAINER),
            },
        }
    }
    missing(&mut reject, mme.is_some(), ID_MME_UE_S1AP_ID);
    missing(&mut reject, enb.is_some(), ID_ENB_UE_S1AP_ID);
    missing(
        &mut reject,
        container.is_some(),
        ID_ENB_STATUS_TRANSFER_CONTAINER,
    );
    if !reject.is_empty() {
        return Class2Decode::Reject {
            ies: reject,
            enb_ue_s1ap_id: enb,
            mme_ue_s1ap_id: mme,
        };
    }
    let (Some(mme_ue_s1ap_id), Some(enb_ue_s1ap_id), Some(status_transfer_container)) =
        (mme, enb, container)
    else {
        return Class2Decode::Undecodable;
    };
    Class2Decode::Proceed {
        msg: nextgcore_s1ap::EnbStatusTransfer {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            status_transfer_container,
        },
        notify,
    }
}

/// A HANDOVER NOTIFY whose `ignore` location IEs may be missing (§10.3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoverNotifyAt {
    /// MME-UE-S1AP-ID.
    pub mme_ue_s1ap_id: u32,
    /// eNB-UE-S1AP-ID.
    pub enb_ue_s1ap_id: u32,
    /// EUTRAN-CGI and TAI, when both are present.
    pub location: Option<(Tai, EutranCgi)>,
}

/// Decode a HANDOVER NOTIFY (TS 36.413 §9.1.5.10), the initiating message of a
/// Class 2 procedure. The UE IDs are `reject`; EUTRAN-CGI and TAI are `ignore`,
/// so without both the notify still completes the handover.
pub fn decode_handover_notify(bytes: &[u8]) -> Class2Decode<HandoverNotifyAt> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return Class2Decode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return Class2Decode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_HandoverNotification(m) = msg.value else {
        return Class2Decode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut mme, mut enb, mut cgi, mut tai) = (None, None, None, None);
    use g::HandoverNotifyProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = Some(v.0),
            V::Id_EUTRAN_CGI(v) => cgi = cgi_from(&v),
            V::Id_TAI(v) => tai = tai_from(&v),
            _ => {}
        }
    }
    missing(&mut reject, mme.is_some(), ID_MME_UE_S1AP_ID);
    missing(&mut reject, enb.is_some(), ID_ENB_UE_S1AP_ID);
    if !reject.is_empty() {
        return Class2Decode::Reject {
            ies: reject,
            enb_ue_s1ap_id: enb,
            mme_ue_s1ap_id: mme,
        };
    }
    let (Some(mme_ue_s1ap_id), Some(enb_ue_s1ap_id)) = (mme, enb) else {
        return Class2Decode::Undecodable;
    };
    Class2Decode::Proceed {
        msg: HandoverNotifyAt {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            location: tai.zip(cgi),
        },
        notify,
    }
}

/// Decode a HANDOVER CANCEL (TS 36.413 §9.1.5.10), the initiating message of a
/// Class 1 procedure. The UE IDs are `reject`; a missing Cause (`ignore`) reads
/// as radioNetwork / unspecified. `notify` IEs go in the acknowledge.
pub fn decode_handover_cancel(bytes: &[u8]) -> Class2Decode<nextgcore_s1ap::HandoverCancel> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return Class2Decode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return Class2Decode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_HandoverCancel(m) = msg.value else {
        return Class2Decode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut mme, mut enb, mut cause) = (None, None, None);
    use g::HandoverCancelProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = Some(v.0),
            V::Id_Cause(c) => cause = domain_cause(&c),
        }
    }
    missing(&mut reject, mme.is_some(), ID_MME_UE_S1AP_ID);
    missing(&mut reject, enb.is_some(), ID_ENB_UE_S1AP_ID);
    if !reject.is_empty() {
        return Class2Decode::Reject {
            ies: reject,
            enb_ue_s1ap_id: enb,
            mme_ue_s1ap_id: mme,
        };
    }
    let (Some(mme_ue_s1ap_id), Some(enb_ue_s1ap_id)) = (mme, enb) else {
        return Class2Decode::Undecodable;
    };
    Class2Decode::Proceed {
        msg: nextgcore_s1ap::HandoverCancel {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            cause: cause.unwrap_or(Cause::RadioNetwork(
                nextgcore_s1ap::CauseRadioNetwork::Unspecified,
            )),
        },
        notify,
    }
}

/// Decode a HANDOVER FAILURE (TS 36.413 §9.1.5.5), the unsuccessful outcome
/// of Handover Resource Allocation: a response message. Its IEs are `ignore`;
/// one naming no MME-UE-S1AP-ID is `Undecodable`, a missing Cause reads as
/// radioNetwork / unspecified.
pub fn decode_handover_failure(bytes: &[u8]) -> ResponseDecode<nextgcore_s1ap::HandoverFailure> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return ResponseDecode::Undecodable;
    };
    let g::S1AP_PDU::UnsuccessfulOutcome(msg) = pdu else {
        return ResponseDecode::Undecodable;
    };
    let g::UnsuccessfulOutcomeValue::Id_HandoverResourceAllocation(f) = msg.value else {
        return ResponseDecode::Undecodable;
    };
    let (reject, notify) = classify_unknown(&unknown);
    if !reject.is_empty() {
        return ResponseDecode::Failed(reject);
    }
    let (mut mme, mut cause) = (None, None);
    use g::HandoverFailureProtocolIEs_EntryValue as V;
    for ie in f.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_Cause(c) => cause = domain_cause(&c),
            _ => {}
        }
    }
    let Some(mme_ue_s1ap_id) = mme else {
        return ResponseDecode::Undecodable;
    };
    ResponseDecode::Decoded {
        msg: nextgcore_s1ap::HandoverFailure {
            mme_ue_s1ap_id,
            cause: cause.unwrap_or(Cause::RadioNetwork(
                nextgcore_s1ap::CauseRadioNetwork::Unspecified,
            )),
        },
        notify,
    }
}

// ============================================================================
// Handover, part 2 (TS 36.413 §8.4.1, §8.4.2) -- stage 8b
// ============================================================================

const ID_HANDOVER_TYPE: u16 = 1;
const ID_TARGET_ID: u16 = 4;
const ID_ERAB_SUBJECT_TO_DATA_FORWARDING_LIST: u16 = 12;
const ID_ERAB_TO_RELEASE_LIST_HO_CMD: u16 = 13;
const ID_ERAB_DATA_FORWARDING_ITEM: u16 = 14;
const ID_ERAB_ADMITTED_LIST: u16 = 18;
const ID_ERAB_FAILED_TO_SETUP_LIST_HO_REQ_ACK: u16 = 19;
const ID_ERAB_ADMITTED_ITEM: u16 = 20;
const ID_ERAB_TO_BE_SETUP_ITEM_HO_REQ: u16 = 27;
const ID_ERAB_TO_BE_SETUP_LIST_HO_REQ: u16 = 53;
const ID_DIRECT_FORWARDING_PATH_AVAILABILITY: u16 = 79;
const ID_SOURCE_TO_TARGET_CONTAINER: u16 = 104;
const ID_TARGET_TO_SOURCE_CONTAINER: u16 = 123;

/// Outcome of decoding a HANDOVER REQUIRED (TS 36.413 §9.1.5.1), the
/// initiating message of a Class 1 procedure with both a response (HANDOVER
/// COMMAND) and a failure (HANDOVER PREPARATION FAILURE).
#[derive(Debug, Clone)]
pub enum HandoverRequiredDecode {
    /// Run the procedure. `notify` IEs go in the HANDOVER COMMAND's (or the
    /// HANDOVER PREPARATION FAILURE's) Criticality Diagnostics (§10.3.4.2).
    Proceed {
        /// The message, in the handler's existing type.
        msg: nextgcore_s1ap::HandoverRequired,
        /// IEs to report.
        notify: Vec<DiagnosedIe>,
    },
    /// The Target ID is well formed but names a target the handler's type
    /// cannot represent (an NG-RAN node, or a short / long macro eNB ID): the
    /// MME answers HANDOVER PREPARATION FAILURE, unknown-targetID.
    UnsupportedTarget {
        /// MME-UE-S1AP-ID.
        mme_ue_s1ap_id: u32,
        /// eNB-UE-S1AP-ID.
        enb_ue_s1ap_id: u32,
    },
    /// The Target ID names a gNB (TargetNgRanNode-ID, TS 36.413 §9.2.1.6): an
    /// EPS to 5GS handover, which this MME prepares over N26 as the source
    /// (#584, TS 23.502 §4.11.1.2.2).
    ToFivegs {
        /// The message.
        msg: HandoverRequiredTo5gs,
        /// IEs to report.
        notify: Vec<DiagnosedIe>,
    },
    /// A `reject` IE is missing or not understood: answer HANDOVER PREPARATION
    /// FAILURE naming `ies` (§10.3.4.2 / §10.3.5).
    Reject {
        /// IEs to report.
        ies: Vec<DiagnosedIe>,
        /// eNB-UE-S1AP-ID, if read.
        enb_ue_s1ap_id: Option<u32>,
        /// MME-UE-S1AP-ID, if read.
        mme_ue_s1ap_id: Option<u32>,
    },
    /// Not decodable (transfer syntax error).
    Undecodable,
}

/// A HANDOVER REQUIRED towards a gNB (#584).
#[derive(Debug, Clone)]
pub struct HandoverRequiredTo5gs {
    /// MME-UE-S1AP-ID.
    pub mme_ue_s1ap_id: u32,
    /// eNB-UE-S1AP-ID.
    pub enb_ue_s1ap_id: u32,
    /// Handover Type.
    pub handover_type: nextgcore_s1ap::HandoverType,
    /// Cause (radioNetwork / unspecified when missing).
    pub cause: Cause,
    /// The target gNB and its selected 5GS TAI.
    pub target: crate::n26_build::GnbTarget,
    /// Direct Forwarding Path Availability present.
    pub direct_forwarding: bool,
    /// The Source to Target Transparent Container, for the target NG-RAN.
    pub source_to_target_container: Vec<u8>,
}

/// The gNB a TargetNgRanNode-ID names: `Err(())` for an ng-eNB (well formed,
/// not served), `Ok(None)` for a malformed one.
fn gnb_target_from(t: &g::TargetNgRanNode_ID) -> Result<Option<crate::n26_build::GnbTarget>, ()> {
    let g::Global_RAN_NODE_ID::GNB(gnb) = &t.global_ran_node_id else {
        return Err(());
    };
    let g::GNB_Identity::GNB_ID(id) = &gnb.global_g_nb_id.gnb_id;
    let (Some(plmn), Some(_), Ok(tac)) = (
        plmn(&gnb.global_g_nb_id.plmn_identity.0),
        plmn(&t.selected_tai.plm_nidentity.0),
        <[u8; 3]>::try_from(t.selected_tai.five_gstac.0.as_slice()),
    ) else {
        return Ok(None);
    };
    let len = id.0.len();
    if !(22..=32).contains(&len) {
        return Ok(None);
    }
    Ok(Some(crate::n26_build::GnbTarget {
        plmn,
        gnb_id: bits_to_u32(&id.0),
        gnb_id_len: len as u8,
        tac,
    }))
}

fn handover_type_from(v: u8) -> Option<nextgcore_s1ap::HandoverType> {
    use nextgcore_s1ap::HandoverType as H;
    Some(match v {
        g::HandoverType::INTRALTE => H::IntraLte,
        g::HandoverType::LTETOUTRAN => H::LteToUtran,
        g::HandoverType::LTETOGERAN => H::LteToGeran,
        g::HandoverType::UTRANTOLTE => H::UtranToLte,
        g::HandoverType::GERANTOLTE => H::GeranToLte,
        g::HandoverType::EPS_TO_5GS => H::EpsTo5gs,
        g::HandoverType::FIVEGS_TO_EPS => H::FiveGsToEps,
        _ => return None,
    })
}

fn handover_type_to(t: nextgcore_s1ap::HandoverType) -> g::HandoverType {
    g::HandoverType(t as u8)
}

fn u16_from(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.try_into().ok()?))
}

/// The handler's `TargetId` for a generated one; `Err(())` for a well-formed
/// target the handler's type has no variant for, `Ok(None)` for a malformed
/// one.
fn target_id_from(t: &g::TargetID) -> Result<Option<nextgcore_s1ap::TargetId>, ()> {
    use nextgcore_s1ap::TargetId as T;
    Ok(match t {
        g::TargetID::TargeteNB_ID(v) => {
            let enb_id = match &v.global_enb_id.enb_id {
                g::ENB_ID::MacroENB_ID(b) => EnbId::Macro(bits_to_u32(&b.0)),
                g::ENB_ID::HomeENB_ID(b) => EnbId::Home(bits_to_u32(&b.0)),
                _ => return Err(()),
            };
            let (Some(plmn_identity), Some(selected_tai)) = (
                plmn(&v.global_enb_id.plm_nidentity.0),
                tai_from(&v.selected_tai),
            ) else {
                return Ok(None);
            };
            Some(T::TargetEnbId {
                global_enb_id: GlobalEnbId {
                    plmn_identity,
                    enb_id,
                },
                selected_tai,
            })
        }
        g::TargetID::TargetRNC_ID(v) => {
            let (Some(plmn_identity), Some(lac)) =
                (plmn(&v.lai.plm_nidentity.0), u16_from(&v.lai.lac.0))
            else {
                return Ok(None);
            };
            Some(T::TargetRncId {
                plmn_identity,
                lac,
                rac: v.rac.as_ref().and_then(|r| r.0.first().copied()),
                // The hand-written parser let an Extended RNC-ID replace the
                // RNC-ID (TS 36.413 §9.2.1.6); kept.
                rnc_id: v.extended_rnc_id.as_ref().map_or(v.rnc_id.0, |e| e.0),
            })
        }
        g::TargetID::CGI(v) => {
            let (Some(plmn_identity), Some(lac), Some(ci)) = (
                plmn(&v.plm_nidentity.0),
                u16_from(&v.lac.0),
                u16_from(&v.ci.0),
            ) else {
                return Ok(None);
            };
            Some(T::Cgi {
                plmn_identity,
                lac,
                ci,
                rac: v.rac.as_ref().and_then(|r| r.0.first().copied()),
            })
        }
        g::TargetID::TargetgNgRanNode_ID(_) => return Err(()),
    })
}

/// Decode a HANDOVER REQUIRED (TS 36.413 §9.1.5.1) with §10.3.4.2 / §10.3.5.
///
/// The UE IDs, Handover Type, Target ID and Source-to-Target container are
/// `reject`; a missing Cause (`ignore`) reads as radioNetwork / unspecified;
/// Direct Forwarding Path Availability is optional `ignore`. The SRVCC, CSG and
/// secondary-container IEs are understood but not acted on, as before.
pub fn decode_handover_required(bytes: &[u8]) -> HandoverRequiredDecode {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return HandoverRequiredDecode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return HandoverRequiredDecode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_HandoverPreparation(m) = msg.value else {
        return HandoverRequiredDecode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut mme, mut enb, mut ho_type, mut cause, mut target, mut direct, mut container) =
        (None, None, None, None, None, None, None);
    let mut unsupported_target = false;
    let mut gnb_target = None;
    use g::HandoverRequiredProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = Some(v.0),
            V::Id_HandoverType(v) => match handover_type_from(v.0) {
                Some(t) => ho_type = Some(t),
                None => not_understood(&mut reject, ID_HANDOVER_TYPE),
            },
            V::Id_Cause(c) => cause = domain_cause(&c),
            V::Id_TargetID(g::TargetID::TargetgNgRanNode_ID(t)) => match gnb_target_from(&t) {
                Ok(Some(t)) => gnb_target = Some(t),
                Ok(None) => not_understood(&mut reject, ID_TARGET_ID),
                Err(()) => unsupported_target = true,
            },
            V::Id_TargetID(t) => match target_id_from(&t) {
                Ok(Some(t)) => target = Some(t),
                Ok(None) => not_understood(&mut reject, ID_TARGET_ID),
                Err(()) => unsupported_target = true,
            },
            V::Id_Direct_Forwarding_Path_Availability(v) => {
                // An unknown extension value of an `ignore` IE is ignored.
                if v.0 == g::Direct_Forwarding_Path_Availability::DIRECT_PATH_AVAILABLE {
                    direct =
                        Some(nextgcore_s1ap::DirectForwardingPathAvailability::DirectPathAvailable);
                }
            }
            V::Id_Source_ToTarget_TransparentContainer(c) => container = Some(c.0),
            _ => {}
        }
    }
    missing(&mut reject, mme.is_some(), ID_MME_UE_S1AP_ID);
    missing(&mut reject, enb.is_some(), ID_ENB_UE_S1AP_ID);
    missing(&mut reject, ho_type.is_some(), ID_HANDOVER_TYPE);
    missing(
        &mut reject,
        target.is_some() || unsupported_target || gnb_target.is_some(),
        ID_TARGET_ID,
    );
    missing(
        &mut reject,
        container.is_some(),
        ID_SOURCE_TO_TARGET_CONTAINER,
    );
    if !reject.is_empty() {
        return HandoverRequiredDecode::Reject {
            ies: reject,
            enb_ue_s1ap_id: enb,
            mme_ue_s1ap_id: mme,
        };
    }
    let (Some(mme_ue_s1ap_id), Some(enb_ue_s1ap_id), Some(handover_type), Some(container)) =
        (mme, enb, ho_type, container)
    else {
        return HandoverRequiredDecode::Undecodable;
    };
    if let Some(target) = gnb_target {
        return HandoverRequiredDecode::ToFivegs {
            msg: HandoverRequiredTo5gs {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id,
                handover_type,
                cause: cause.unwrap_or(Cause::RadioNetwork(
                    nextgcore_s1ap::CauseRadioNetwork::Unspecified,
                )),
                target,
                direct_forwarding: direct.is_some(),
                source_to_target_container: container,
            },
            notify,
        };
    }
    let Some(target_id) = target else {
        return HandoverRequiredDecode::UnsupportedTarget {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
        };
    };
    HandoverRequiredDecode::Proceed {
        msg: nextgcore_s1ap::HandoverRequired {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            handover_type,
            cause: cause.unwrap_or(Cause::RadioNetwork(
                nextgcore_s1ap::CauseRadioNetwork::Unspecified,
            )),
            target_id,
            direct_forwarding_path_availability: direct,
            source_to_target_container: container,
        },
        notify,
    }
}

/// Encode a HANDOVER PREPARATION FAILURE (TS 36.413 §9.1.5.3) carrying, when
/// `reject` is non-empty, the HANDOVER REQUIRED's IEs that caused it.
pub fn build_handover_preparation_failure_with_diagnostics(
    msg: &nextgcore_s1ap::HandoverPreparationFailure,
    reject: &[DiagnosedIe],
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::HandoverPreparationFailureProtocolIEs_EntryValue as V;
    let ie = |id: u16, value: V| g::HandoverPreparationFailureProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(IGNORE),
        value,
    };
    let mut ies = vec![
        ie(
            ID_MME_UE_S1AP_ID,
            V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id)),
        ),
        ie(
            ID_ENB_UE_S1AP_ID,
            V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id)),
        ),
        ie(ID_CAUSE, V::Id_Cause(generated_cause(msg.cause))),
    ];
    if !reject.is_empty() {
        ies.push(ie(
            ID_CRITICALITY_DIAGNOSTICS,
            V::Id_CriticalityDiagnostics(diagnostics_for(
                PROC_HANDOVER_PREPARATION,
                g::TriggeringMessage::INITIATING_MESSAGE,
                REJECT,
                reject,
            )),
        ));
    }
    encode_pdu(&g::S1AP_PDU::UnsuccessfulOutcome(g::UnsuccessfulOutcome {
        procedure_code: g::ProcedureCode(PROC_HANDOVER_PREPARATION),
        criticality: g::Criticality(REJECT),
        value: g::UnsuccessfulOutcomeValue::Id_HandoverPreparation(g::HandoverPreparationFailure {
            protocol_i_es: g::HandoverPreparationFailureProtocolIEs(ies),
        }),
    }))
}

fn teid(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

fn transport(addr: &[u8]) -> g::TransportLayerAddress {
    g::TransportLayerAddress(bytes_to_bits(addr))
}

fn gtp_teid(t: u32) -> g::GTP_TEID {
    g::GTP_TEID(t.to_be_bytes().to_vec())
}

/// Encode a HANDOVER REQUEST (TS 36.413 §9.1.5.4). IE order follows
/// `HandoverRequestIEs`; Cause is `ignore`, every other IE and each E-RAB item
/// `reject`; procedure criticality reject.
pub fn build_handover_request(
    msg: &nextgcore_s1ap::HandoverRequest,
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::HandoverRequestProtocolIEs_EntryValue as V;
    let ie = |id: u16, criticality: u8, value: V| g::HandoverRequestProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(criticality),
        value,
    };
    let erabs = msg
        .erab_list
        .iter()
        .map(|e| g::E_RABToBeSetupListHOReq_Entry {
            id: g::ProtocolIE_ID(ID_ERAB_TO_BE_SETUP_ITEM_HO_REQ),
            criticality: g::Criticality(REJECT),
            value: g::E_RABToBeSetupListHOReq_EntryValue::Id_E_RABToBeSetupItemHOReq(
                g::E_RABToBeSetupItemHOReq {
                    e_rab_id: g::E_RAB_ID(e.erab_id),
                    transport_layer_address: transport(&e.transport_layer_address),
                    gtp_teid: gtp_teid(e.gtp_teid),
                    e_ra_blevel_qos_parameters: erab_qos(&e.erab_qos),
                    ie_extensions: None,
                },
            ),
        })
        .collect();
    let sec = &msg.ue_security_capabilities;
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_HANDOVER_RESOURCE_ALLOCATION),
        criticality: g::Criticality(REJECT),
        value: g::InitiatingMessageValue::Id_HandoverResourceAllocation(g::HandoverRequest {
            protocol_i_es: g::HandoverRequestProtocolIEs(vec![
                ie(
                    ID_MME_UE_S1AP_ID,
                    REJECT,
                    V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id)),
                ),
                ie(
                    ID_HANDOVER_TYPE,
                    REJECT,
                    V::Id_HandoverType(handover_type_to(msg.handover_type)),
                ),
                ie(ID_CAUSE, IGNORE, V::Id_Cause(generated_cause(msg.cause))),
                ie(
                    ID_UE_AMBR,
                    REJECT,
                    V::Id_uEaggregateMaximumBitrate(ambr(&msg.ue_ambr)),
                ),
                ie(
                    ID_ERAB_TO_BE_SETUP_LIST_HO_REQ,
                    REJECT,
                    V::Id_E_RABToBeSetupListHOReq(g::E_RABToBeSetupListHOReq(erabs)),
                ),
                ie(
                    ID_SOURCE_TO_TARGET_CONTAINER,
                    REJECT,
                    V::Id_Source_ToTarget_TransparentContainer(
                        g::Source_ToTarget_TransparentContainer(
                            msg.source_to_target_container.clone(),
                        ),
                    ),
                ),
                ie(
                    ID_UE_SECURITY_CAPABILITIES,
                    REJECT,
                    V::Id_UESecurityCapabilities(g::UESecurityCapabilities {
                        encryption_algorithms: g::EncryptionAlgorithms(bytes_to_bits(
                            &sec.encryption_algorithms.to_be_bytes(),
                        )),
                        integrity_protection_algorithms: g::IntegrityProtectionAlgorithms(
                            bytes_to_bits(&sec.integrity_algorithms.to_be_bytes()),
                        ),
                        ie_extensions: None,
                    }),
                ),
                ie(
                    ID_SECURITY_CONTEXT,
                    REJECT,
                    V::Id_SecurityContext(g::SecurityContext {
                        next_hop_chaining_count: g::SecurityContextNextHopChainingCount(
                            msg.security_context.next_hop_chaining_count,
                        ),
                        next_hop_parameter: g::SecurityKey(bytes_to_bits(
                            &msg.security_context.next_hop_parameter,
                        )),
                        ie_extensions: None,
                    }),
                ),
            ]),
        }),
    }))
}

/// Decode a HANDOVER REQUEST ACKNOWLEDGE (TS 36.413 §9.1.5.5), a response
/// message. The Target-to-Source container is `reject`: missing, the response
/// is handled locally (`Failed`). The other IEs are `ignore`: a missing E-RAB
/// Admitted List reads as empty; a missing UE S1AP ID, which the handler needs
/// to address the target, is `Undecodable`.
pub fn decode_handover_request_acknowledge(
    bytes: &[u8],
) -> ResponseDecode<nextgcore_s1ap::HandoverRequestAcknowledge> {
    let Some((g::SuccessfulOutcomeValue::Id_HandoverResourceAllocation(ack), unknown)) =
        successful_outcome(bytes)
    else {
        return ResponseDecode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut mme, mut enb, mut admitted, mut failed, mut container) =
        (None, None, None, None, None);
    use g::HandoverRequestAcknowledgeProtocolIEs_EntryValue as V;
    for ie in ack.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = Some(v.0),
            V::Id_E_RABAdmittedList(l) => {
                let mut items = Vec::new();
                for entry in l.0 {
                    let g::E_RABAdmittedList_EntryValue::Id_E_RABAdmittedItem(i) = entry.value;
                    let Some(t) = teid(&i.gtp_teid.0) else {
                        return ResponseDecode::Undecodable;
                    };
                    items.push(nextgcore_s1ap::ErabAdmittedItem {
                        erab_id: i.e_rab_id.0,
                        transport_layer_address: bits_to_bytes(&i.transport_layer_address.0),
                        gtp_teid: t,
                        dl_transport_layer_address: i
                            .dl_transport_layer_address
                            .as_ref()
                            .map(|a| bits_to_bytes(&a.0)),
                        dl_gtp_teid: i.dl_g_tp_teid.as_ref().and_then(|t| teid(&t.0)),
                        ul_transport_layer_address: i
                            .ul_transport_layer_address
                            .as_ref()
                            .map(|a| bits_to_bytes(&a.0)),
                        ul_gtp_teid: i.ul_gtp_teid.as_ref().and_then(|t| teid(&t.0)),
                    });
                }
                admitted = Some(items);
            }
            V::Id_E_RABFailedToSetupListHOReqAck(l) => {
                failed = Some(
                    l.0.into_iter()
                        .map(|entry| {
                            let g::E_RABFailedtoSetupListHOReqAck_EntryValue::Id_E_RABFailedtoSetupItemHOReqAck(i) =
                                entry.value;
                            nextgcore_s1ap::ErabFailedItem {
                                erab_id: i.e_rab_id.0,
                                cause: domain_cause(&i.cause).unwrap_or(Cause::RadioNetwork(
                                    nextgcore_s1ap::CauseRadioNetwork::Unspecified,
                                )),
                            }
                        })
                        .collect::<Vec<_>>(),
                );
            }
            V::Id_Target_ToSource_TransparentContainer(c) => container = Some(c.0),
            _ => {}
        }
    }
    missing(
        &mut reject,
        container.is_some(),
        ID_TARGET_TO_SOURCE_CONTAINER,
    );
    if !reject.is_empty() {
        return ResponseDecode::Failed(reject);
    }
    let (Some(mme_ue_s1ap_id), Some(enb_ue_s1ap_id), Some(target_to_source_container)) =
        (mme, enb, container)
    else {
        return ResponseDecode::Undecodable;
    };
    ResponseDecode::Decoded {
        msg: nextgcore_s1ap::HandoverRequestAcknowledge {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            erab_admitted_list: admitted.unwrap_or_default(),
            erab_failed_list: failed.unwrap_or_default(),
            target_to_source_container,
        },
        notify,
    }
}

/// Encode a HANDOVER COMMAND (TS 36.413 §9.1.5.2). The UE IDs, Handover Type
/// and Target-to-Source container are `reject`; the forwarding and release
/// lists (and each of their items) `ignore`; procedure criticality reject.
/// `notify` IEs of the HANDOVER REQUIRED go in its Criticality Diagnostics
/// (§10.3.4.2).
pub fn build_handover_command(
    msg: &nextgcore_s1ap::HandoverCommand,
    notify: &[DiagnosedIe],
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::HandoverCommandProtocolIEs_EntryValue as V;
    let ie = |id: u16, criticality: u8, value: V| g::HandoverCommandProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(criticality),
        value,
    };
    let mut ies = vec![
        ie(
            ID_MME_UE_S1AP_ID,
            REJECT,
            V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id)),
        ),
        ie(
            ID_ENB_UE_S1AP_ID,
            REJECT,
            V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id)),
        ),
        ie(
            ID_HANDOVER_TYPE,
            REJECT,
            V::Id_HandoverType(handover_type_to(msg.handover_type)),
        ),
    ];
    if !msg.erab_subject_to_forwarding_list.is_empty() {
        ies.push(ie(
            ID_ERAB_SUBJECT_TO_DATA_FORWARDING_LIST,
            IGNORE,
            V::Id_E_RABSubjecttoDataForwardingList(g::E_RABSubjecttoDataForwardingList(
                msg.erab_subject_to_forwarding_list
                    .iter()
                    .map(|f| g::E_RABSubjecttoDataForwardingList_Entry {
                        id: g::ProtocolIE_ID(ID_ERAB_DATA_FORWARDING_ITEM),
                        criticality: g::Criticality(IGNORE),
                        value:
                            g::E_RABSubjecttoDataForwardingList_EntryValue::Id_E_RABDataForwardingItem(
                                g::E_RABDataForwardingItem {
                                    e_rab_id: g::E_RAB_ID(f.erab_id),
                                    dl_transport_layer_address: f
                                        .dl_transport_layer_address
                                        .as_deref()
                                        .map(transport),
                                    dl_g_tp_teid: f.dl_gtp_teid.map(gtp_teid),
                                    ul_transport_layer_address: f
                                        .ul_transport_layer_address
                                        .as_deref()
                                        .map(transport),
                                    ul_gtp_teid: f.ul_gtp_teid.map(gtp_teid),
                                    ie_extensions: None,
                                },
                            ),
                    })
                    .collect(),
            )),
        ));
    }
    if !msg.erab_to_release_list.is_empty() {
        ies.push(ie(
            ID_ERAB_TO_RELEASE_LIST_HO_CMD,
            IGNORE,
            V::Id_E_RABtoReleaseListHOCmd(erab_list(&msg.erab_to_release_list)),
        ));
    }
    ies.push(ie(
        ID_TARGET_TO_SOURCE_CONTAINER,
        REJECT,
        V::Id_Target_ToSource_TransparentContainer(g::Target_ToSource_TransparentContainer(
            msg.target_to_source_container.clone(),
        )),
    ));
    if !notify.is_empty() {
        ies.push(ie(
            ID_CRITICALITY_DIAGNOSTICS,
            IGNORE,
            V::Id_CriticalityDiagnostics(diagnostics_for(
                PROC_HANDOVER_PREPARATION,
                g::TriggeringMessage::INITIATING_MESSAGE,
                REJECT,
                notify,
            )),
        ));
    }
    encode_pdu(&g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
        procedure_code: g::ProcedureCode(PROC_HANDOVER_PREPARATION),
        criticality: g::Criticality(REJECT),
        value: g::SuccessfulOutcomeValue::Id_HandoverPreparation(g::HandoverCommand {
            protocol_i_es: g::HandoverCommandProtocolIEs(ies),
        }),
    }))
}

// ============================================================================
// Reset and Error Indication (TS 36.413 §8.7.1, §8.7.2) -- stage 9
// ============================================================================

/// `id-Reset`.
pub const PROC_RESET: u8 = 14;
/// `id-ErrorIndication`.
pub const PROC_ERROR_INDICATION: u8 = 15;

const ID_UE_ASSOCIATED_CONNECTION_ITEM: u16 = 91;
const ID_RESET_TYPE: u16 = 92;
const ID_UE_ASSOCIATED_CONNECTION_LIST_RES_ACK: u16 = 93;

/// Criticality Diagnostics in the hand-written type, as the generated one.
fn diagnostics_from(d: &nextgcore_s1ap::CriticalityDiagnostics) -> g::CriticalityDiagnostics {
    g::CriticalityDiagnostics {
        procedure_code: d.procedure_code.map(g::ProcedureCode),
        triggering_message: d.triggering_message.map(g::TriggeringMessage),
        procedure_criticality: d.procedure_criticality.map(g::Criticality),
        i_es_criticality_diagnostics: (!d.ies.is_empty()).then(|| {
            g::CriticalityDiagnostics_IE_List(
                d.ies
                    .iter()
                    .take(256)
                    .map(|i| g::CriticalityDiagnostics_IE_Item {
                        ie_criticality: g::Criticality(match i.ie_criticality {
                            nextgcore_s1ap::Criticality::Reject => REJECT,
                            nextgcore_s1ap::Criticality::Ignore => IGNORE,
                            nextgcore_s1ap::Criticality::Notify => NOTIFY,
                        }),
                        ie_id: g::ProtocolIE_ID(i.ie_id),
                        type_of_error: g::TypeOfError(match i.type_of_error {
                            nextgcore_s1ap::TypeOfError::NotUnderstood => {
                                g::TypeOfError::NOT_UNDERSTOOD
                            }
                            nextgcore_s1ap::TypeOfError::Missing => g::TypeOfError::MISSING,
                        }),
                        ie_extensions: None,
                    })
                    .collect(),
            )
        }),
        ie_extensions: None,
    }
}

/// Encode an ERROR INDICATION (TS 36.413 §9.1.8.4): every IE optional and
/// criticality ignore; procedure criticality ignore.
pub fn build_error_indication(
    msg: &nextgcore_s1ap::ErrorIndication,
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::ErrorIndicationProtocolIEs_EntryValue as V;
    let ie = |id: u16, value: V| g::ErrorIndicationProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(IGNORE),
        value,
    };
    let mut ies = Vec::new();
    if let Some(id) = msg.mme_ue_s1ap_id {
        ies.push(ie(
            ID_MME_UE_S1AP_ID,
            V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(id)),
        ));
    }
    if let Some(id) = msg.enb_ue_s1ap_id {
        ies.push(ie(
            ID_ENB_UE_S1AP_ID,
            V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(id)),
        ));
    }
    if let Some(c) = msg.cause {
        ies.push(ie(ID_CAUSE, V::Id_Cause(generated_cause(c))));
    }
    if let Some(d) = &msg.criticality_diagnostics {
        ies.push(ie(
            ID_CRITICALITY_DIAGNOSTICS,
            V::Id_CriticalityDiagnostics(diagnostics_from(d)),
        ));
    }
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_ERROR_INDICATION),
        criticality: g::Criticality(IGNORE),
        value: g::InitiatingMessageValue::Id_ErrorIndication(g::ErrorIndication {
            protocol_i_es: g::ErrorIndicationProtocolIEs(ies),
        }),
    }))
}

fn hand_written_diagnostics(
    d: &g::CriticalityDiagnostics,
) -> nextgcore_s1ap::CriticalityDiagnostics {
    nextgcore_s1ap::CriticalityDiagnostics {
        procedure_code: d.procedure_code.as_ref().map(|p| p.0),
        triggering_message: d.triggering_message.as_ref().map(|t| t.0),
        procedure_criticality: d.procedure_criticality.as_ref().map(|c| c.0),
        ies: d
            .i_es_criticality_diagnostics
            .as_ref()
            .map(|l| {
                l.0.iter()
                    .map(|i| nextgcore_s1ap::IeCriticalityDiagnostics {
                        ie_criticality: match i.ie_criticality.0 {
                            IGNORE => nextgcore_s1ap::Criticality::Ignore,
                            NOTIFY => nextgcore_s1ap::Criticality::Notify,
                            _ => nextgcore_s1ap::Criticality::Reject,
                        },
                        ie_id: i.ie_id.0,
                        type_of_error: if i.type_of_error.0 == g::TypeOfError::MISSING {
                            nextgcore_s1ap::TypeOfError::Missing
                        } else {
                            nextgcore_s1ap::TypeOfError::NotUnderstood
                        },
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// Decode an ERROR INDICATION (TS 36.413 §9.1.8.4): every IE is optional and
/// `ignore`. Unknown IEs are returned for logging only — an ERROR INDICATION
/// is never answered with another.
pub fn decode_error_indication(
    bytes: &[u8],
) -> Option<(nextgcore_s1ap::ErrorIndication, Vec<UnknownIe>)> {
    let (pdu, unknown) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes).ok()?;
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return None;
    };
    let g::InitiatingMessageValue::Id_ErrorIndication(m) = msg.value else {
        return None;
    };
    let mut out = nextgcore_s1ap::ErrorIndication {
        mme_ue_s1ap_id: None,
        enb_ue_s1ap_id: None,
        cause: None,
        criticality_diagnostics: None,
    };
    use g::ErrorIndicationProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => out.mme_ue_s1ap_id = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => out.enb_ue_s1ap_id = Some(v.0),
            V::Id_Cause(c) => out.cause = domain_cause(&c),
            V::Id_CriticalityDiagnostics(d) => {
                out.criticality_diagnostics = Some(hand_written_diagnostics(&d));
            }
            V::Id_S_TMSI(_) => {}
        }
    }
    Some((out, unknown))
}

/// Decode a RESET (TS 36.413 §9.1.8.1), the initiating message of a Class 1
/// procedure. ResetType is `reject`: missing, the reset is not run; a missing
/// Cause (`ignore`) reads as radioNetwork / unspecified.
pub fn decode_reset(bytes: &[u8]) -> Class2Decode<nextgcore_s1ap::Reset> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return Class2Decode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return Class2Decode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_Reset(m) = msg.value else {
        return Class2Decode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut cause, mut reset_type) = (None, None);
    use g::ResetProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_Cause(c) => cause = domain_cause(&c),
            V::Id_ResetType(t) => {
                reset_type = Some(match t {
                    g::ResetType::S1_Interface(_) => nextgcore_s1ap::ResetType::S1Interface,
                    g::ResetType::PartOfS1_Interface(list) => {
                        nextgcore_s1ap::ResetType::PartOfS1Interface(
                            list.0
                                .into_iter()
                                .map(|e| {
                                    let g::UE_associatedLogicalS1_ConnectionListRes_EntryValue::Id_UE_associatedLogicalS1_ConnectionItem(i) = e.value;
                                    nextgcore_s1ap::UeAssociatedLogicalS1Connection {
                                        mme_ue_s1ap_id: i.mme_ue_s1ap_id.map(|v| v.0),
                                        enb_ue_s1ap_id: i.enb_ue_s1ap_id.map(|v| v.0),
                                    }
                                })
                                .collect(),
                        )
                    }
                });
            }
        }
    }
    missing(&mut reject, reset_type.is_some(), ID_RESET_TYPE);
    if !reject.is_empty() {
        return Class2Decode::Reject {
            ies: reject,
            enb_ue_s1ap_id: None,
            mme_ue_s1ap_id: None,
        };
    }
    let Some(reset_type) = reset_type else {
        return Class2Decode::Undecodable;
    };
    Class2Decode::Proceed {
        msg: nextgcore_s1ap::Reset {
            cause: cause.unwrap_or(Cause::RadioNetwork(
                nextgcore_s1ap::CauseRadioNetwork::Unspecified,
            )),
            reset_type,
        },
        notify,
    }
}

/// Encode a RESET ACKNOWLEDGE (TS 36.413 §9.1.8.2): its IEs ignore, each
/// connection item ignore; procedure criticality reject. `notify` IEs of the
/// RESET are reported in its Criticality Diagnostics (§10.3.4.2).
pub fn build_reset_acknowledge(
    msg: &nextgcore_s1ap::ResetAcknowledge,
    notify: &[DiagnosedIe],
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::ResetAcknowledgeProtocolIEs_EntryValue as V;
    let ie = |id: u16, value: V| g::ResetAcknowledgeProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(IGNORE),
        value,
    };
    let mut ies = Vec::new();
    if !msg.ue_associated_connections.is_empty() {
        ies.push(ie(
            ID_UE_ASSOCIATED_CONNECTION_LIST_RES_ACK,
            V::Id_UE_associatedLogicalS1_ConnectionListResAck(
                g::UE_associatedLogicalS1_ConnectionListResAck(
                    msg.ue_associated_connections
                        .iter()
                        .map(|c| g::UE_associatedLogicalS1_ConnectionListResAck_Entry {
                            id: g::ProtocolIE_ID(ID_UE_ASSOCIATED_CONNECTION_ITEM),
                            criticality: g::Criticality(IGNORE),
                            value: g::UE_associatedLogicalS1_ConnectionListResAck_EntryValue::Id_UE_associatedLogicalS1_ConnectionItem(
                                g::UE_associatedLogicalS1_ConnectionItem {
                                    mme_ue_s1ap_id: c.mme_ue_s1ap_id.map(g::MME_UE_S1AP_ID),
                                    enb_ue_s1ap_id: c.enb_ue_s1ap_id.map(g::ENB_UE_S1AP_ID),
                                    ie_extensions: None,
                                },
                            ),
                        })
                        .collect(),
                ),
            ),
        ));
    }
    if !notify.is_empty() {
        ies.push(ie(
            ID_CRITICALITY_DIAGNOSTICS,
            V::Id_CriticalityDiagnostics(diagnostics_for(
                PROC_RESET,
                g::TriggeringMessage::INITIATING_MESSAGE,
                REJECT,
                notify,
            )),
        ));
    }
    encode_pdu(&g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
        procedure_code: g::ProcedureCode(PROC_RESET),
        criticality: g::Criticality(REJECT),
        value: g::SuccessfulOutcomeValue::Id_Reset(g::ResetAcknowledge {
            protocol_i_es: g::ResetAcknowledgeProtocolIEs(ies),
        }),
    }))
}

// ============================================================================
// Path Switch (TS 36.413 §8.4.4) -- stage 10
// ============================================================================

/// `id-PathSwitchRequest`.
pub const PROC_PATH_SWITCH_REQUEST: u8 = 3;

const ID_ERAB_TO_BE_SWITCHED_DL_LIST: u16 = 22;
const ID_SECURITY_CONTEXT: u16 = 40;
const ID_SOURCE_MME_UE_S1AP_ID: u16 = 88;
const ID_ERAB_TO_BE_SWITCHED_UL_ITEM: u16 = 94;
const ID_ERAB_TO_BE_SWITCHED_UL_LIST: u16 = 95;

/// A PATH SWITCH REQUEST whose `ignore` IEs may be absent (#584).
///
/// TS 36.413 §9.1.5.8 marks EUTRAN-CGI, TAI and UE Security Capabilities
/// criticality `ignore`, and §10.3.5 says a missing `ignore` IE is ignored:
/// the procedure runs on what is there. The shared `PathSwitchRequest` type
/// has no "absent" for them, so this mmed-local type carries `Option`s and the
/// handler leaves the stored location as it is, or skips the §7.2.4.3.2
/// comparison, for whichever one is missing.
#[derive(Debug, Clone)]
pub struct PathSwitchRequestAt {
    /// eNB-UE-S1AP-ID (reject).
    pub enb_ue_s1ap_id: u32,
    /// E-RABToBeSwitchedDLList (reject).
    pub erab_switched_dl_list: Vec<nextgcore_s1ap::ErabSwitchedItem>,
    /// SourceMME-UE-S1AP-ID (reject).
    pub source_mme_ue_s1ap_id: u32,
    /// EUTRAN-CGI (ignore), if present.
    pub eutran_cgi: Option<EutranCgi>,
    /// TAI (ignore), if present.
    pub tai: Option<Tai>,
    /// UE Security Capabilities (ignore), if present.
    pub ue_security_capabilities: Option<nextgcore_s1ap::UeSecurityCapabilities>,
}

impl From<&nextgcore_s1ap::PathSwitchRequest> for PathSwitchRequestAt {
    fn from(m: &nextgcore_s1ap::PathSwitchRequest) -> Self {
        Self {
            enb_ue_s1ap_id: m.enb_ue_s1ap_id,
            erab_switched_dl_list: m.erab_switched_dl_list.clone(),
            source_mme_ue_s1ap_id: m.source_mme_ue_s1ap_id,
            eutran_cgi: Some(m.eutran_cgi.clone()),
            tai: Some(m.tai.clone()),
            ue_security_capabilities: Some(m.ue_security_capabilities),
        }
    }
}

/// Decode a PATH SWITCH REQUEST (TS 36.413 §9.1.5.8), the initiating message of
/// a Class 1 procedure. eNB-UE-S1AP-ID, E-RABToBeSwitchedDLList and
/// SourceMME-UE-S1AP-ID are `reject`: missing, the request fails. EUTRAN-CGI,
/// TAI and UE Security Capabilities are `ignore`: missing (or present but not
/// mappable), each is `None` and the procedure runs without it (§10.3.5, #584).
pub fn decode_path_switch_request(bytes: &[u8]) -> Class2Decode<PathSwitchRequestAt> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return Class2Decode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return Class2Decode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_PathSwitchRequest(m) = msg.value else {
        return Class2Decode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut enb, mut list, mut source_mme, mut cgi, mut tai, mut sec) =
        (None, None, None, None, None, None);
    use g::PathSwitchRequestProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_eNB_UE_S1AP_ID(v) => enb = Some(v.0),
            V::Id_SourceMME_UE_S1AP_ID(v) => source_mme = Some(v.0),
            V::Id_EUTRAN_CGI(v) => cgi = cgi_from(&v),
            V::Id_TAI(v) => tai = tai_from(&v),
            V::Id_UESecurityCapabilities(v) => {
                let bits16 = |b: &BitVec<u8, Msb0>| -> Option<u16> {
                    let bytes = bits_to_bytes(b);
                    Some(u16::from_be_bytes(bytes.get(..2)?.try_into().ok()?))
                };
                sec = bits16(&v.encryption_algorithms.0)
                    .zip(bits16(&v.integrity_protection_algorithms.0))
                    .map(|(e, i)| nextgcore_s1ap::UeSecurityCapabilities {
                        encryption_algorithms: e,
                        integrity_algorithms: i,
                    });
            }
            V::Id_E_RABToBeSwitchedDLList(l) => {
                let mut items = Vec::new();
                for entry in l.0 {
                    let g::E_RABToBeSwitchedDLList_EntryValue::Id_E_RABToBeSwitchedDLItem(item) =
                        entry.value;
                    let Ok(teid) = <[u8; 4]>::try_from(item.gtp_teid.0.as_slice()) else {
                        return Class2Decode::Undecodable;
                    };
                    items.push(nextgcore_s1ap::ErabSwitchedItem {
                        erab_id: item.e_rab_id.0,
                        transport_layer_address: bits_to_bytes(&item.transport_layer_address.0),
                        gtp_teid: u32::from_be_bytes(teid),
                    });
                }
                list = Some(items);
            }
            _ => {}
        }
    }
    missing(&mut reject, enb.is_some(), ID_ENB_UE_S1AP_ID);
    missing(&mut reject, list.is_some(), ID_ERAB_TO_BE_SWITCHED_DL_LIST);
    missing(&mut reject, source_mme.is_some(), ID_SOURCE_MME_UE_S1AP_ID);
    if !reject.is_empty() {
        return Class2Decode::Reject {
            ies: reject,
            enb_ue_s1ap_id: enb,
            mme_ue_s1ap_id: source_mme,
        };
    }
    let (Some(enb_ue_s1ap_id), Some(erab_switched_dl_list), Some(source_mme_ue_s1ap_id)) =
        (enb, list, source_mme)
    else {
        return Class2Decode::Undecodable;
    };
    Class2Decode::Proceed {
        msg: PathSwitchRequestAt {
            enb_ue_s1ap_id,
            erab_switched_dl_list,
            source_mme_ue_s1ap_id,
            eutran_cgi: cgi,
            tai,
            ue_security_capabilities: sec,
        },
        notify,
    }
}

/// Encode a PATH SWITCH REQUEST ACKNOWLEDGE (TS 36.413 §9.1.5.9): the UE IDs
/// and the UL list ignore (each item ignore), Security Context reject;
/// procedure criticality reject. `notify` IEs of the request are reported in
/// its Criticality Diagnostics.
pub fn build_path_switch_request_acknowledge(
    msg: &nextgcore_s1ap::PathSwitchRequestAcknowledge,
    notify: &[DiagnosedIe],
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    build_path_switch_request_acknowledge_releasing(msg, None, &[], notify)
}

/// [`build_path_switch_request_acknowledge`] with an E-RAB To Be Released List
/// (TS 36.413 §9.1.5.9, criticality ignore) naming `released`, when non-empty:
/// E-RABs the core did not switch, which the eNB then considers released
/// (§8.4.4.2, #730).
///
/// `ue_ambr`, when present, is the UE Aggregate Maximum Bit Rate (criticality
/// ignore): TS 23.401 §5.5.1.1.2 step 6, "If the UE-AMBR has changed, e.g. all the
/// bearers for an APN have been released, the MME shall provide the updated value
/// of the UE-AMBR to the target eNodeB".
pub fn build_path_switch_request_acknowledge_releasing(
    msg: &nextgcore_s1ap::PathSwitchRequestAcknowledge,
    ue_ambr: Option<&nextgcore_s1ap::UeAmbr>,
    released: &[nextgcore_s1ap::ErabItem],
    notify: &[DiagnosedIe],
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::PathSwitchRequestAcknowledgeProtocolIEs_EntryValue as V;
    let ie =
        |id: u16, criticality: u8, value: V| g::PathSwitchRequestAcknowledgeProtocolIEs_Entry {
            id: g::ProtocolIE_ID(id),
            criticality: g::Criticality(criticality),
            value,
        };
    let mut ies = vec![
        ie(
            ID_MME_UE_S1AP_ID,
            IGNORE,
            V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id)),
        ),
        ie(
            ID_ENB_UE_S1AP_ID,
            IGNORE,
            V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id)),
        ),
    ];
    if let Some(a) = ue_ambr {
        ies.push(ie(
            ID_UE_AMBR,
            IGNORE,
            V::Id_uEaggregateMaximumBitrate(ambr(a)),
        ));
    }
    if !msg.erab_switched_ul_list.is_empty() {
        ies.push(ie(
            ID_ERAB_TO_BE_SWITCHED_UL_LIST,
            IGNORE,
            V::Id_E_RABToBeSwitchedULList(g::E_RABToBeSwitchedULList(
                msg.erab_switched_ul_list
                    .iter()
                    .map(|e| g::E_RABToBeSwitchedULList_Entry {
                        id: g::ProtocolIE_ID(ID_ERAB_TO_BE_SWITCHED_UL_ITEM),
                        criticality: g::Criticality(IGNORE),
                        value: g::E_RABToBeSwitchedULList_EntryValue::Id_E_RABToBeSwitchedULItem(
                            g::E_RABToBeSwitchedULItem {
                                e_rab_id: g::E_RAB_ID(e.erab_id),
                                transport_layer_address: g::TransportLayerAddress(bytes_to_bits(
                                    &e.transport_layer_address,
                                )),
                                gtp_teid: g::GTP_TEID(e.gtp_teid.to_be_bytes().to_vec()),
                                ie_extensions: None,
                            },
                        ),
                    })
                    .collect(),
            )),
        ));
    }
    if !released.is_empty() {
        ies.push(ie(
            ID_ERAB_TO_BE_RELEASED_LIST,
            IGNORE,
            V::Id_E_RABToBeReleasedList(erab_list(released)),
        ));
    }
    ies.push(ie(
        ID_SECURITY_CONTEXT,
        REJECT,
        V::Id_SecurityContext(g::SecurityContext {
            next_hop_chaining_count: g::SecurityContextNextHopChainingCount(
                msg.security_context.next_hop_chaining_count,
            ),
            next_hop_parameter: g::SecurityKey(bytes_to_bits(
                &msg.security_context.next_hop_parameter,
            )),
            ie_extensions: None,
        }),
    ));
    if !notify.is_empty() {
        ies.push(ie(
            ID_CRITICALITY_DIAGNOSTICS,
            IGNORE,
            V::Id_CriticalityDiagnostics(diagnostics_for(
                PROC_PATH_SWITCH_REQUEST,
                g::TriggeringMessage::INITIATING_MESSAGE,
                REJECT,
                notify,
            )),
        ));
    }
    encode_pdu(&g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
        procedure_code: g::ProcedureCode(PROC_PATH_SWITCH_REQUEST),
        criticality: g::Criticality(REJECT),
        value: g::SuccessfulOutcomeValue::Id_PathSwitchRequest(g::PathSwitchRequestAcknowledge {
            protocol_i_es: g::PathSwitchRequestAcknowledgeProtocolIEs(ies),
        }),
    }))
}

/// Encode a PATH SWITCH REQUEST FAILURE (TS 36.413 §9.1.5.10): every IE
/// ignore; procedure criticality reject. `reject` (when non-empty) names the
/// request's IEs that caused the failure (§10.3.4.2 / §10.3.5).
pub fn build_path_switch_request_failure(
    msg: &nextgcore_s1ap::PathSwitchRequestFailure,
    reject: &[DiagnosedIe],
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::PathSwitchRequestFailureProtocolIEs_EntryValue as V;
    let ie = |id: u16, value: V| g::PathSwitchRequestFailureProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(IGNORE),
        value,
    };
    let mut ies = vec![
        ie(
            ID_MME_UE_S1AP_ID,
            V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id)),
        ),
        ie(
            ID_ENB_UE_S1AP_ID,
            V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id)),
        ),
        ie(ID_CAUSE, V::Id_Cause(generated_cause(msg.cause))),
    ];
    if !reject.is_empty() {
        ies.push(ie(
            ID_CRITICALITY_DIAGNOSTICS,
            V::Id_CriticalityDiagnostics(diagnostics_for(
                PROC_PATH_SWITCH_REQUEST,
                g::TriggeringMessage::INITIATING_MESSAGE,
                REJECT,
                reject,
            )),
        ));
    }
    encode_pdu(&g::S1AP_PDU::UnsuccessfulOutcome(g::UnsuccessfulOutcome {
        procedure_code: g::ProcedureCode(PROC_PATH_SWITCH_REQUEST),
        criticality: g::Criticality(REJECT),
        value: g::UnsuccessfulOutcomeValue::Id_PathSwitchRequest(g::PathSwitchRequestFailure {
            protocol_i_es: g::PathSwitchRequestFailureProtocolIEs(ies),
        }),
    }))
}

// ============================================================================
// The rest (TS 36.413 §8.3.4, §8.6.2.4, §8.7.4, §8.7.6, §8.9, §8.12) -- stage 12
// ============================================================================

/// `id-NASNonDeliveryIndication`.
pub const PROC_NAS_NON_DELIVERY_INDICATION: u8 = 16;
/// `id-UEContextModification`.
pub const PROC_UE_CONTEXT_MODIFICATION: u8 = 21;
/// `id-UECapabilityInfoIndication`.
pub const PROC_UE_CAPABILITY_INFO_INDICATION: u8 = 22;
/// `id-ENBConfigurationUpdate`.
pub const PROC_ENB_CONFIGURATION_UPDATE: u8 = 29;
/// `id-MMEConfigurationUpdate`.
pub const PROC_MME_CONFIGURATION_UPDATE: u8 = 30;
/// `id-OverloadStart`.
pub const PROC_OVERLOAD_START: u8 = 34;
/// `id-OverloadStop`.
pub const PROC_OVERLOAD_STOP: u8 = 35;
/// `id-WriteReplaceWarning`.
pub const PROC_WRITE_REPLACE_WARNING: u8 = 36;
/// `id-Kill`.
pub const PROC_KILL: u8 = 43;

const ID_SUBSCRIBER_PROFILE_ID_FOR_RFP: u16 = 106;
const ID_UE_RADIO_CAPABILITY: u16 = 74;
const ID_OVERLOAD_RESPONSE: u16 = 101;
const ID_CS_FALLBACK_INDICATOR: u16 = 108;
const ID_MESSAGE_IDENTIFIER: u16 = 111;
const ID_SERIAL_NUMBER: u16 = 112;
const ID_WARNING_AREA_LIST: u16 = 113;
const ID_REPETITION_PERIOD: u16 = 114;
const ID_NUMBER_OF_BROADCAST_REQUEST: u16 = 115;
const ID_WARNING_TYPE: u16 = 116;
const ID_WARNING_SECURITY_INFO: u16 = 117;
const ID_DATA_CODING_SCHEME: u16 = 118;
const ID_WARNING_MESSAGE_CONTENTS: u16 = 119;
const ID_CONCURRENT_WARNING_MESSAGE_INDICATOR: u16 = 142;
const ID_KILL_ALL_WARNING_MESSAGES: u16 = 191;

/// Encode an ENB CONFIGURATION UPDATE ACKNOWLEDGE (TS 36.413 §9.1.8.8);
/// `notify` IEs of the update go in its Criticality Diagnostics (§10.3.4.2).
pub fn build_enb_configuration_update_acknowledge(
    notify: &[DiagnosedIe],
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::ENBConfigurationUpdateAcknowledgeProtocolIEs_EntryValue as V;
    let mut ies = Vec::new();
    if !notify.is_empty() {
        ies.push(g::ENBConfigurationUpdateAcknowledgeProtocolIEs_Entry {
            id: g::ProtocolIE_ID(ID_CRITICALITY_DIAGNOSTICS),
            criticality: g::Criticality(IGNORE),
            value: V::Id_CriticalityDiagnostics(diagnostics_for(
                PROC_ENB_CONFIGURATION_UPDATE,
                g::TriggeringMessage::INITIATING_MESSAGE,
                REJECT,
                notify,
            )),
        });
    }
    encode_pdu(&g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
        procedure_code: g::ProcedureCode(PROC_ENB_CONFIGURATION_UPDATE),
        criticality: g::Criticality(REJECT),
        value: g::SuccessfulOutcomeValue::Id_ENBConfigurationUpdate(
            g::ENBConfigurationUpdateAcknowledge {
                protocol_i_es: g::ENBConfigurationUpdateAcknowledgeProtocolIEs(ies),
            },
        ),
    }))
}

/// Encode an ENB CONFIGURATION UPDATE FAILURE (TS 36.413 §9.1.8.9): every IE
/// ignore; `reject` names the update's IEs that caused it.
pub fn build_enb_configuration_update_failure(
    cause: Cause,
    time_to_wait: Option<TimeToWait>,
    reject: &[DiagnosedIe],
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::ENBConfigurationUpdateFailureProtocolIEs_EntryValue as V;
    let ie = |id: u16, value: V| g::ENBConfigurationUpdateFailureProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(IGNORE),
        value,
    };
    let mut ies = vec![ie(ID_CAUSE, V::Id_Cause(generated_cause(cause)))];
    if let Some(ttw) = time_to_wait {
        ies.push(ie(
            ID_TIME_TO_WAIT,
            V::Id_TimeToWait(g::TimeToWait(ttw as u8)),
        ));
    }
    if !reject.is_empty() {
        ies.push(ie(
            ID_CRITICALITY_DIAGNOSTICS,
            V::Id_CriticalityDiagnostics(diagnostics_for(
                PROC_ENB_CONFIGURATION_UPDATE,
                g::TriggeringMessage::INITIATING_MESSAGE,
                REJECT,
                reject,
            )),
        ));
    }
    encode_pdu(&g::S1AP_PDU::UnsuccessfulOutcome(g::UnsuccessfulOutcome {
        procedure_code: g::ProcedureCode(PROC_ENB_CONFIGURATION_UPDATE),
        criticality: g::Criticality(REJECT),
        value: g::UnsuccessfulOutcomeValue::Id_ENBConfigurationUpdate(
            g::ENBConfigurationUpdateFailure {
                protocol_i_es: g::ENBConfigurationUpdateFailureProtocolIEs(ies),
            },
        ),
    }))
}

/// Outcome of decoding an ENB CONFIGURATION UPDATE (TS 36.413 §9.1.8.7), the
/// initiating message of a Class 1 procedure with a response and a failure.
#[derive(Debug, Clone)]
pub enum ConfigUpdateDecode {
    /// Run the procedure; report `notify` IEs in the acknowledge.
    Proceed {
        /// The update, in the handler's existing type.
        msg: nextgcore_s1ap::EnbConfigurationUpdate,
        /// IEs to report.
        notify: Vec<DiagnosedIe>,
    },
    /// Answer ENB CONFIGURATION UPDATE FAILURE naming `ies`.
    Reject(Vec<DiagnosedIe>),
    /// Not decodable.
    Undecodable,
}

fn supported_tas_from(v: g::SupportedTAs) -> Vec<SupportedTaItem> {
    v.0.into_iter()
        .filter_map(|item| {
            Some(SupportedTaItem {
                tac: u16::from_be_bytes(item.tac.0.as_slice().try_into().ok()?),
                broadcast_plmns: item
                    .broadcast_plm_ns
                    .0
                    .iter()
                    .filter_map(|p| plmn(&p.0))
                    .collect(),
            })
        })
        .collect()
}

fn paging_drx_from(v: &g::PagingDRX) -> PagingDrx {
    match v.0 {
        g::PagingDRX::V32 => PagingDrx::V32,
        g::PagingDRX::V64 => PagingDrx::V64,
        g::PagingDRX::V256 => PagingDrx::V256,
        _ => PagingDrx::V128,
    }
}

/// Decode an ENB CONFIGURATION UPDATE (TS 36.413 §9.1.8.7). Every IE is
/// optional; SupportedTAs and CSG-IdList are `reject`, the others `ignore`.
pub fn decode_enb_configuration_update(bytes: &[u8]) -> ConfigUpdateDecode {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return ConfigUpdateDecode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return ConfigUpdateDecode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_ENBConfigurationUpdate(m) = msg.value else {
        return ConfigUpdateDecode::Undecodable;
    };
    let (reject, notify) = classify_unknown(&unknown);
    if !reject.is_empty() {
        return ConfigUpdateDecode::Reject(reject);
    }
    let mut update = nextgcore_s1ap::EnbConfigurationUpdate {
        enb_name: None,
        supported_tas: None,
        default_paging_drx: None,
    };
    use g::ENBConfigurationUpdateProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_eNBname(v) => update.enb_name = Some(v.0),
            V::Id_SupportedTAs(v) => update.supported_tas = Some(supported_tas_from(v)),
            V::Id_DefaultPagingDRX(v) => update.default_paging_drx = Some(paging_drx_from(&v)),
            // CSG list, NB-IoT DRX, connected en-gNBs: understood, not used.
            _ => {}
        }
    }
    ConfigUpdateDecode::Proceed {
        msg: update,
        notify,
    }
}

/// Encode a UE CONTEXT MODIFICATION REQUEST (TS 36.413 §9.1.4.6). IE order
/// follows `UEContextModificationRequestIEs`; Subscriber Profile ID and UE
/// AMBR are `ignore`, every other IE `reject`; procedure criticality reject.
pub fn build_ue_context_modification_request(
    msg: &nextgcore_s1ap::UeContextModificationRequest,
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::UEContextModificationRequestProtocolIEs_EntryValue as V;
    let ie =
        |id: u16, criticality: u8, value: V| g::UEContextModificationRequestProtocolIEs_Entry {
            id: g::ProtocolIE_ID(id),
            criticality: g::Criticality(criticality),
            value,
        };
    let mut ies = vec![
        ie(
            ID_MME_UE_S1AP_ID,
            REJECT,
            V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id)),
        ),
        ie(
            ID_ENB_UE_S1AP_ID,
            REJECT,
            V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id)),
        ),
    ];
    if let Some(key) = &msg.security_key {
        ies.push(ie(
            ID_SECURITY_KEY,
            REJECT,
            V::Id_SecurityKey(g::SecurityKey(bytes_to_bits(key))),
        ));
    }
    if let Some(spid) = msg.subscriber_profile_id_for_rfp {
        ies.push(ie(
            ID_SUBSCRIBER_PROFILE_ID_FOR_RFP,
            IGNORE,
            V::Id_SubscriberProfileIDforRFP(g::SubscriberProfileIDforRFP(spid)),
        ));
    }
    if let Some(a) = &msg.ue_ambr {
        ies.push(ie(
            ID_UE_AMBR,
            IGNORE,
            V::Id_uEaggregateMaximumBitrate(ambr(a)),
        ));
    }
    if let Some(csfb) = msg.cs_fallback_indicator {
        ies.push(ie(
            ID_CS_FALLBACK_INDICATOR,
            REJECT,
            V::Id_CSFallbackIndicator(g::CSFallbackIndicator(match csfb {
                nextgcore_s1ap::CsFallbackIndicator::CsFallbackRequired => {
                    g::CSFallbackIndicator::CS_FALLBACK_REQUIRED
                }
                nextgcore_s1ap::CsFallbackIndicator::CsFallbackHighPriority => {
                    g::CSFallbackIndicator::CS_FALLBACK_HIGH_PRIORITY
                }
            })),
        ));
    }
    if let Some(sec) = &msg.ue_security_capabilities {
        ies.push(ie(
            ID_UE_SECURITY_CAPABILITIES,
            REJECT,
            V::Id_UESecurityCapabilities(g::UESecurityCapabilities {
                encryption_algorithms: g::EncryptionAlgorithms(bytes_to_bits(
                    &sec.encryption_algorithms.to_be_bytes(),
                )),
                integrity_protection_algorithms: g::IntegrityProtectionAlgorithms(bytes_to_bits(
                    &sec.integrity_algorithms.to_be_bytes(),
                )),
                ie_extensions: None,
            }),
        ));
    }
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_UE_CONTEXT_MODIFICATION),
        criticality: g::Criticality(REJECT),
        value: g::InitiatingMessageValue::Id_UEContextModification(
            g::UEContextModificationRequest {
                protocol_i_es: g::UEContextModificationRequestProtocolIEs(ies),
            },
        ),
    }))
}

/// Encode an OVERLOAD START (TS 36.413 §9.1.8.13): Overload Response `reject`;
/// procedure criticality ignore.
pub fn build_overload_start(
    action: nextgcore_s1ap::OverloadAction,
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_OVERLOAD_START),
        criticality: g::Criticality(IGNORE),
        value: g::InitiatingMessageValue::Id_OverloadStart(g::OverloadStart {
            protocol_i_es: g::OverloadStartProtocolIEs(vec![g::OverloadStartProtocolIEs_Entry {
                id: g::ProtocolIE_ID(ID_OVERLOAD_RESPONSE),
                criticality: g::Criticality(REJECT),
                value: g::OverloadStartProtocolIEs_EntryValue::Id_OverloadResponse(
                    g::OverloadResponse::OverloadAction(g::OverloadAction(action as u8)),
                ),
            }]),
        }),
    }))
}

/// Encode an OVERLOAD STOP (TS 36.413 §9.1.8.14): no IEs; procedure
/// criticality reject.
pub fn build_overload_stop() -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_OVERLOAD_STOP),
        criticality: g::Criticality(REJECT),
        value: g::InitiatingMessageValue::Id_OverloadStop(g::OverloadStop {
            protocol_i_es: g::OverloadStopProtocolIEs(vec![]),
        }),
    }))
}

fn warning_area(a: &nextgcore_s1ap::WarningAreaList) -> g::WarningAreaList {
    use nextgcore_s1ap::WarningAreaList as W;
    match a {
        W::CellIdList(cells) => g::WarningAreaList::CellIDList(g::ECGIList(
            cells
                .iter()
                .map(|c| g::EUTRAN_CGI {
                    plm_nidentity: g::TBCD_STRING(c.plmn_identity.to_vec()),
                    cell_id: g::CellIdentity(u32_to_bits(c.cell_identity, 28)),
                    ie_extensions: None,
                })
                .collect(),
        )),
        W::TrackingAreaListForWarning(tais) => {
            g::WarningAreaList::TrackingAreaListforWarning(g::TAIListforWarning(
                tais.iter()
                    .map(|t| g::TAI {
                        plm_nidentity: g::TBCD_STRING(t.plmn_identity.to_vec()),
                        tac: g::TAC(t.tac.to_be_bytes().to_vec()),
                        ie_extensions: None,
                    })
                    .collect(),
            ))
        }
        W::EmergencyAreaIdList(ids) => g::WarningAreaList::EmergencyAreaIDList(
            g::EmergencyAreaIDList(ids.iter().map(|i| g::EmergencyAreaID(i.to_vec())).collect()),
        ),
    }
}

fn bits16(v: u16) -> BitVec<u8, Msb0> {
    bytes_to_bits(&v.to_be_bytes())
}

/// Encode a WRITE-REPLACE WARNING REQUEST (TS 36.413 §9.1.13.1). IE order
/// follows `WriteReplaceWarningRequestIEs`; the area, warning type, security
/// info, coding scheme and contents are `ignore`, the others `reject`;
/// procedure criticality reject.
pub fn build_write_replace_warning_request(
    msg: &nextgcore_s1ap::WriteReplaceWarningRequest,
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::WriteReplaceWarningRequestProtocolIEs_EntryValue as V;
    let ie = |id: u16, criticality: u8, value: V| g::WriteReplaceWarningRequestProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(criticality),
        value,
    };
    let mut ies = vec![
        ie(
            ID_MESSAGE_IDENTIFIER,
            REJECT,
            V::Id_MessageIdentifier(g::MessageIdentifier(bits16(msg.message_identifier))),
        ),
        ie(
            ID_SERIAL_NUMBER,
            REJECT,
            V::Id_SerialNumber(g::SerialNumber(bits16(msg.serial_number))),
        ),
    ];
    if let Some(area) = &msg.warning_area {
        ies.push(ie(
            ID_WARNING_AREA_LIST,
            IGNORE,
            V::Id_WarningAreaList(warning_area(area)),
        ));
    }
    ies.push(ie(
        ID_REPETITION_PERIOD,
        REJECT,
        V::Id_RepetitionPeriod(g::RepetitionPeriod(msg.repetition_period)),
    ));
    ies.push(ie(
        ID_NUMBER_OF_BROADCAST_REQUEST,
        REJECT,
        V::Id_NumberofBroadcastRequest(g::NumberofBroadcastRequest(
            msg.number_of_broadcast_request,
        )),
    ));
    if let Some(t) = msg.warning_type {
        ies.push(ie(
            ID_WARNING_TYPE,
            IGNORE,
            V::Id_WarningType(g::WarningType(t.to_vec())),
        ));
    }
    if let Some(info) = &msg.warning_security_info {
        ies.push(ie(
            ID_WARNING_SECURITY_INFO,
            IGNORE,
            V::Id_WarningSecurityInfo(g::WarningSecurityInfo(info.to_vec())),
        ));
    }
    if let Some(dcs) = msg.data_coding_scheme {
        ies.push(ie(
            ID_DATA_CODING_SCHEME,
            IGNORE,
            V::Id_DataCodingScheme(g::DataCodingScheme(bytes_to_bits(&[dcs]))),
        ));
    }
    if let Some(contents) = &msg.warning_message_contents {
        ies.push(ie(
            ID_WARNING_MESSAGE_CONTENTS,
            IGNORE,
            V::Id_WarningMessageContents(g::WarningMessageContents(contents.clone())),
        ));
    }
    if msg.concurrent_warning_message_indicator {
        ies.push(ie(
            ID_CONCURRENT_WARNING_MESSAGE_INDICATOR,
            REJECT,
            V::Id_ConcurrentWarningMessageIndicator(g::ConcurrentWarningMessageIndicator(
                g::ConcurrentWarningMessageIndicator::TRUE,
            )),
        ));
    }
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_WRITE_REPLACE_WARNING),
        criticality: g::Criticality(REJECT),
        value: g::InitiatingMessageValue::Id_WriteReplaceWarning(g::WriteReplaceWarningRequest {
            protocol_i_es: g::WriteReplaceWarningRequestProtocolIEs(ies),
        }),
    }))
}

/// Encode a KILL REQUEST (TS 36.413 §9.1.13.3): the area `ignore`, the others
/// `reject`; procedure criticality reject.
pub fn build_kill_request(
    msg: &nextgcore_s1ap::KillRequest,
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::KillRequestProtocolIEs_EntryValue as V;
    let ie = |id: u16, criticality: u8, value: V| g::KillRequestProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(criticality),
        value,
    };
    let mut ies = vec![
        ie(
            ID_MESSAGE_IDENTIFIER,
            REJECT,
            V::Id_MessageIdentifier(g::MessageIdentifier(bits16(msg.message_identifier))),
        ),
        ie(
            ID_SERIAL_NUMBER,
            REJECT,
            V::Id_SerialNumber(g::SerialNumber(bits16(msg.serial_number))),
        ),
    ];
    if let Some(area) = &msg.warning_area {
        ies.push(ie(
            ID_WARNING_AREA_LIST,
            IGNORE,
            V::Id_WarningAreaList(warning_area(area)),
        ));
    }
    if msg.kill_all_warning_messages {
        ies.push(ie(
            ID_KILL_ALL_WARNING_MESSAGES,
            REJECT,
            V::Id_KillAllWarningMessages(g::KillAllWarningMessages(
                g::KillAllWarningMessages::TRUE,
            )),
        ));
    }
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_KILL),
        criticality: g::Criticality(REJECT),
        value: g::InitiatingMessageValue::Id_Kill(g::KillRequest {
            protocol_i_es: g::KillRequestProtocolIEs(ies),
        }),
    }))
}

/// Decode a NAS NON DELIVERY INDICATION (TS 36.413 §9.1.7.5), Class 2. The UE
/// IDs are `reject`; NAS-PDU and Cause are `ignore` (missing → empty /
/// radioNetwork-unspecified).
pub fn decode_nas_non_delivery_indication(
    bytes: &[u8],
) -> Class2Decode<nextgcore_s1ap::NasNonDeliveryIndication> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return Class2Decode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return Class2Decode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_NASNonDeliveryIndication(m) = msg.value else {
        return Class2Decode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut mme, mut enb, mut nas, mut cause) = (None, None, None, None);
    use g::NASNonDeliveryIndicationProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = Some(v.0),
            V::Id_NAS_PDU(v) => nas = Some(v.0),
            V::Id_Cause(c) => cause = domain_cause(&c),
        }
    }
    missing(&mut reject, mme.is_some(), ID_MME_UE_S1AP_ID);
    missing(&mut reject, enb.is_some(), ID_ENB_UE_S1AP_ID);
    if !reject.is_empty() {
        return Class2Decode::Reject {
            ies: reject,
            enb_ue_s1ap_id: enb,
            mme_ue_s1ap_id: mme,
        };
    }
    let (Some(mme_ue_s1ap_id), Some(enb_ue_s1ap_id)) = (mme, enb) else {
        return Class2Decode::Undecodable;
    };
    Class2Decode::Proceed {
        msg: nextgcore_s1ap::NasNonDeliveryIndication {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            nas_pdu: nas.unwrap_or_default(),
            cause: cause.unwrap_or(Cause::RadioNetwork(
                nextgcore_s1ap::CauseRadioNetwork::Unspecified,
            )),
        },
        notify,
    }
}

/// Decode a UE CAPABILITY INFO INDICATION (TS 36.413 §9.1.10), Class 2. The UE
/// IDs are `reject`; UE Radio Capability is `ignore` — missing, the indication
/// carries nothing to store and is `Undecodable`.
pub fn decode_ue_capability_info_indication(
    bytes: &[u8],
) -> Class2Decode<nextgcore_s1ap::UeCapabilityInfoIndication> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return Class2Decode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return Class2Decode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_UECapabilityInfoIndication(m) = msg.value else {
        return Class2Decode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut mme, mut enb, mut cap) = (None, None, None);
    use g::UECapabilityInfoIndicationProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = Some(v.0),
            V::Id_UERadioCapability(v) => cap = Some(v.0),
            _ => {}
        }
    }
    missing(&mut reject, mme.is_some(), ID_MME_UE_S1AP_ID);
    missing(&mut reject, enb.is_some(), ID_ENB_UE_S1AP_ID);
    if !reject.is_empty() {
        return Class2Decode::Reject {
            ies: reject,
            enb_ue_s1ap_id: enb,
            mme_ue_s1ap_id: mme,
        };
    }
    let (Some(mme_ue_s1ap_id), Some(enb_ue_s1ap_id), Some(ue_radio_capability)) = (mme, enb, cap)
    else {
        return Class2Decode::Undecodable;
    };
    Class2Decode::Proceed {
        msg: nextgcore_s1ap::UeCapabilityInfoIndication {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            ue_radio_capability,
        },
        notify,
    }
}

/// Decode a RESET ACKNOWLEDGE (TS 36.413 §9.1.8.2), a response: its IEs are
/// optional `ignore`.
pub fn decode_reset_acknowledge(bytes: &[u8]) -> ResponseDecode<nextgcore_s1ap::ResetAcknowledge> {
    let Some((g::SuccessfulOutcomeValue::Id_Reset(ack), unknown)) = successful_outcome(bytes)
    else {
        return ResponseDecode::Undecodable;
    };
    let (reject, notify) = classify_unknown(&unknown);
    if !reject.is_empty() {
        return ResponseDecode::Failed(reject);
    }
    let mut ue_associated_connections = Vec::new();
    use g::ResetAcknowledgeProtocolIEs_EntryValue as V;
    for ie in ack.protocol_i_es.0 {
        if let V::Id_UE_associatedLogicalS1_ConnectionListResAck(list) = ie.value {
            for e in list.0 {
                let g::UE_associatedLogicalS1_ConnectionListResAck_EntryValue::Id_UE_associatedLogicalS1_ConnectionItem(i) = e.value;
                ue_associated_connections.push(nextgcore_s1ap::UeAssociatedLogicalS1Connection {
                    mme_ue_s1ap_id: i.mme_ue_s1ap_id.map(|v| v.0),
                    enb_ue_s1ap_id: i.enb_ue_s1ap_id.map(|v| v.0),
                });
            }
        }
    }
    ResponseDecode::Decoded {
        msg: nextgcore_s1ap::ResetAcknowledge {
            ue_associated_connections,
        },
        notify,
    }
}

/// Decode an MME CONFIGURATION UPDATE ACKNOWLEDGE (TS 36.413 §9.1.8.11), a
/// response: its one IE is optional `ignore`.
pub fn decode_mme_configuration_update_acknowledge(bytes: &[u8]) -> ResponseDecode<()> {
    let Some((g::SuccessfulOutcomeValue::Id_MMEConfigurationUpdate(_), unknown)) =
        successful_outcome(bytes)
    else {
        return ResponseDecode::Undecodable;
    };
    let (reject, notify) = classify_unknown(&unknown);
    if !reject.is_empty() {
        return ResponseDecode::Failed(reject);
    }
    ResponseDecode::Decoded { msg: (), notify }
}

fn unsuccessful_outcome(bytes: &[u8]) -> Option<(g::UnsuccessfulOutcomeValue, Vec<UnknownIe>)> {
    let (pdu, unknown) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes).ok()?;
    let g::S1AP_PDU::UnsuccessfulOutcome(msg) = pdu else {
        return None;
    };
    Some((msg.value, unknown))
}

/// Decode an MME CONFIGURATION UPDATE FAILURE (TS 36.413 §9.1.8.12), a
/// response: every IE `ignore` (missing Cause → radioNetwork / unspecified).
pub fn decode_mme_configuration_update_failure(
    bytes: &[u8],
) -> ResponseDecode<nextgcore_s1ap::MmeConfigurationUpdateFailure> {
    let Some((g::UnsuccessfulOutcomeValue::Id_MMEConfigurationUpdate(f), unknown)) =
        unsuccessful_outcome(bytes)
    else {
        return ResponseDecode::Undecodable;
    };
    let (reject, notify) = classify_unknown(&unknown);
    if !reject.is_empty() {
        return ResponseDecode::Failed(reject);
    }
    let (mut cause, mut time_to_wait, mut diag) = (None, None, None);
    use g::MMEConfigurationUpdateFailureProtocolIEs_EntryValue as V;
    for ie in f.protocol_i_es.0 {
        match ie.value {
            V::Id_Cause(c) => cause = domain_cause(&c),
            V::Id_TimeToWait(t) => time_to_wait = time_to_wait_from(t.0),
            V::Id_CriticalityDiagnostics(d) => diag = Some(hand_written_diagnostics(&d)),
        }
    }
    ResponseDecode::Decoded {
        msg: nextgcore_s1ap::MmeConfigurationUpdateFailure {
            cause: cause.unwrap_or(Cause::RadioNetwork(
                nextgcore_s1ap::CauseRadioNetwork::Unspecified,
            )),
            time_to_wait,
            criticality_diagnostics: diag,
        },
        notify,
    }
}

fn time_to_wait_from(v: u8) -> Option<TimeToWait> {
    Some(match v {
        0 => TimeToWait::V1s,
        1 => TimeToWait::V2s,
        2 => TimeToWait::V5s,
        3 => TimeToWait::V10s,
        4 => TimeToWait::V20s,
        5 => TimeToWait::V60s,
        _ => return None,
    })
}

/// Decode a UE CONTEXT MODIFICATION RESPONSE (TS 36.413 §9.1.4.7), a
/// response: every IE `ignore`; one naming no MME-UE-S1AP-ID is
/// `Undecodable`.
pub fn decode_ue_context_modification_response(
    bytes: &[u8],
) -> ResponseDecode<nextgcore_s1ap::UeContextModificationResponse> {
    let Some((g::SuccessfulOutcomeValue::Id_UEContextModification(r), unknown)) =
        successful_outcome(bytes)
    else {
        return ResponseDecode::Undecodable;
    };
    let (reject, notify) = classify_unknown(&unknown);
    if !reject.is_empty() {
        return ResponseDecode::Failed(reject);
    }
    let (mut mme, mut enb, mut diag) = (None, None, None);
    use g::UEContextModificationResponseProtocolIEs_EntryValue as V;
    for ie in r.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = Some(v.0),
            V::Id_CriticalityDiagnostics(d) => diag = Some(hand_written_diagnostics(&d)),
        }
    }
    let Some(mme_ue_s1ap_id) = mme else {
        return ResponseDecode::Undecodable;
    };
    ResponseDecode::Decoded {
        msg: nextgcore_s1ap::UeContextModificationResponse {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: enb.unwrap_or(0),
            criticality_diagnostics: diag,
        },
        notify,
    }
}

/// Decode a UE CONTEXT MODIFICATION FAILURE (TS 36.413 §9.1.4.8), a
/// response: every IE `ignore`.
pub fn decode_ue_context_modification_failure(
    bytes: &[u8],
) -> ResponseDecode<nextgcore_s1ap::UeContextModificationFailure> {
    let Some((g::UnsuccessfulOutcomeValue::Id_UEContextModification(f), unknown)) =
        unsuccessful_outcome(bytes)
    else {
        return ResponseDecode::Undecodable;
    };
    let (reject, notify) = classify_unknown(&unknown);
    if !reject.is_empty() {
        return ResponseDecode::Failed(reject);
    }
    let (mut mme, mut enb, mut cause, mut diag) = (None, None, None, None);
    use g::UEContextModificationFailureProtocolIEs_EntryValue as V;
    for ie in f.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = Some(v.0),
            V::Id_Cause(c) => cause = domain_cause(&c),
            V::Id_CriticalityDiagnostics(d) => diag = Some(hand_written_diagnostics(&d)),
        }
    }
    let Some(mme_ue_s1ap_id) = mme else {
        return ResponseDecode::Undecodable;
    };
    ResponseDecode::Decoded {
        msg: nextgcore_s1ap::UeContextModificationFailure {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: enb.unwrap_or(0),
            cause: cause.unwrap_or(Cause::RadioNetwork(
                nextgcore_s1ap::CauseRadioNetwork::Unspecified,
            )),
            criticality_diagnostics: diag,
        },
        notify,
    }
}

fn ecgi_from(v: &g::EUTRAN_CGI) -> Option<EutranCgi> {
    cgi_from(v)
}

fn u16_bits(b: &BitVec<u8, Msb0>) -> Option<u16> {
    u16_from(bits_to_bytes(b).get(..2)?)
}

fn eai(v: &g::EmergencyAreaID) -> Option<[u8; 3]> {
    v.0.as_slice().try_into().ok()
}

fn completed_area(
    a: g::BroadcastCompletedAreaList,
) -> Option<nextgcore_s1ap::BroadcastCompletedAreaList> {
    use nextgcore_s1ap::BroadcastCompletedAreaList as B;
    Some(match a {
        g::BroadcastCompletedAreaList::CellID_Broadcast(l) => B::CellIdBroadcast(
            l.0.iter()
                .map(|i| ecgi_from(&i.ecgi))
                .collect::<Option<_>>()?,
        ),
        g::BroadcastCompletedAreaList::TAI_Broadcast(l) => B::TaiBroadcast(
            l.0.iter()
                .map(|i| {
                    Some(nextgcore_s1ap::TaiBroadcastItem {
                        tai: tai_from(&i.tai)?,
                        completed_cells: i
                            .completed_cellin_tai
                            .0
                            .iter()
                            .map(|c| ecgi_from(&c.ecgi))
                            .collect::<Option<_>>()?,
                    })
                })
                .collect::<Option<_>>()?,
        ),
        g::BroadcastCompletedAreaList::EmergencyAreaID_Broadcast(l) => B::EmergencyAreaIdBroadcast(
            l.0.iter()
                .map(|i| {
                    Some(nextgcore_s1ap::EmergencyAreaIdBroadcastItem {
                        emergency_area_id: eai(&i.emergency_area_id)?,
                        completed_cells: i
                            .completed_cellin_eai
                            .0
                            .iter()
                            .map(|c| ecgi_from(&c.ecgi))
                            .collect::<Option<_>>()?,
                    })
                })
                .collect::<Option<_>>()?,
        ),
    })
}

fn cancelled_cell(
    ecgi: &g::EUTRAN_CGI,
    n: &g::NumberOfBroadcasts,
) -> Option<nextgcore_s1ap::CellIdCancelledItem> {
    Some(nextgcore_s1ap::CellIdCancelledItem {
        ecgi: ecgi_from(ecgi)?,
        number_of_broadcasts: n.0,
    })
}

fn cancelled_area(
    a: g::BroadcastCancelledAreaList,
) -> Option<nextgcore_s1ap::BroadcastCancelledAreaList> {
    use nextgcore_s1ap::BroadcastCancelledAreaList as B;
    Some(match a {
        g::BroadcastCancelledAreaList::CellID_Cancelled(l) => B::CellIdCancelled(
            l.0.iter()
                .map(|i| cancelled_cell(&i.ecgi, &i.number_of_broadcasts))
                .collect::<Option<_>>()?,
        ),
        g::BroadcastCancelledAreaList::TAI_Cancelled(l) => B::TaiCancelled(
            l.0.iter()
                .map(|i| {
                    Some(nextgcore_s1ap::TaiCancelledItem {
                        tai: tai_from(&i.tai)?,
                        cancelled_cells: i
                            .cancelled_cellin_tai
                            .0
                            .iter()
                            .map(|c| cancelled_cell(&c.ecgi, &c.number_of_broadcasts))
                            .collect::<Option<_>>()?,
                    })
                })
                .collect::<Option<_>>()?,
        ),
        g::BroadcastCancelledAreaList::EmergencyAreaID_Cancelled(l) => B::EmergencyAreaIdCancelled(
            l.0.iter()
                .map(|i| {
                    Some(nextgcore_s1ap::EmergencyAreaIdCancelledItem {
                        emergency_area_id: eai(&i.emergency_area_id)?,
                        cancelled_cells: i
                            .cancelled_cellin_eai
                            .0
                            .iter()
                            .map(|c| cancelled_cell(&c.ecgi, &c.number_of_broadcasts))
                            .collect::<Option<_>>()?,
                    })
                })
                .collect::<Option<_>>()?,
        ),
    })
}

/// Decode a WRITE-REPLACE WARNING RESPONSE (TS 36.413 §9.1.13.2), a response:
/// Message Identifier and Serial Number are `reject` (missing → handled
/// locally); the completed area list and diagnostics `ignore`.
pub fn decode_write_replace_warning_response(
    bytes: &[u8],
) -> ResponseDecode<nextgcore_s1ap::WriteReplaceWarningResponse> {
    let Some((g::SuccessfulOutcomeValue::Id_WriteReplaceWarning(r), unknown)) =
        successful_outcome(bytes)
    else {
        return ResponseDecode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut mid, mut sn, mut area, mut diag) = (None, None, None, None);
    use g::WriteReplaceWarningResponseProtocolIEs_EntryValue as V;
    for ie in r.protocol_i_es.0 {
        match ie.value {
            V::Id_MessageIdentifier(v) => mid = u16_bits(&v.0),
            V::Id_SerialNumber(v) => sn = u16_bits(&v.0),
            V::Id_BroadcastCompletedAreaList(a) => area = completed_area(a),
            V::Id_CriticalityDiagnostics(d) => diag = Some(hand_written_diagnostics(&d)),
        }
    }
    missing(&mut reject, mid.is_some(), ID_MESSAGE_IDENTIFIER);
    missing(&mut reject, sn.is_some(), ID_SERIAL_NUMBER);
    if !reject.is_empty() {
        return ResponseDecode::Failed(reject);
    }
    let (Some(message_identifier), Some(serial_number)) = (mid, sn) else {
        return ResponseDecode::Undecodable;
    };
    ResponseDecode::Decoded {
        msg: nextgcore_s1ap::WriteReplaceWarningResponse {
            message_identifier,
            serial_number,
            broadcast_completed_area: area,
            criticality_diagnostics: diag,
        },
        notify,
    }
}

/// Decode a KILL RESPONSE (TS 36.413 §9.1.13.4), a response: Message
/// Identifier and Serial Number are `reject`; the cancelled area list and
/// diagnostics `ignore`.
pub fn decode_kill_response(bytes: &[u8]) -> ResponseDecode<nextgcore_s1ap::KillResponse> {
    let Some((g::SuccessfulOutcomeValue::Id_Kill(r), unknown)) = successful_outcome(bytes) else {
        return ResponseDecode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut mid, mut sn, mut area, mut diag) = (None, None, None, None);
    use g::KillResponseProtocolIEs_EntryValue as V;
    for ie in r.protocol_i_es.0 {
        match ie.value {
            V::Id_MessageIdentifier(v) => mid = u16_bits(&v.0),
            V::Id_SerialNumber(v) => sn = u16_bits(&v.0),
            V::Id_BroadcastCancelledAreaList(a) => area = cancelled_area(a),
            V::Id_CriticalityDiagnostics(d) => diag = Some(hand_written_diagnostics(&d)),
        }
    }
    missing(&mut reject, mid.is_some(), ID_MESSAGE_IDENTIFIER);
    missing(&mut reject, sn.is_some(), ID_SERIAL_NUMBER);
    if !reject.is_empty() {
        return ResponseDecode::Failed(reject);
    }
    let (Some(message_identifier), Some(serial_number)) = (mid, sn) else {
        return ResponseDecode::Undecodable;
    };
    ResponseDecode::Decoded {
        msg: nextgcore_s1ap::KillResponse {
            message_identifier,
            serial_number,
            broadcast_cancelled_area: area,
            criticality_diagnostics: diag,
        },
        notify,
    }
}

// ============================================================================
// E-RAB Release Indication, E-RAB Modification Indication and Location
// Reporting (TS 36.413 §8.2.3.2, §8.2.4, §8.11) -- #584
// ============================================================================

/// `id-E-RABReleaseIndication`.
pub const PROC_E_RAB_RELEASE_INDICATION: u8 = 8;
/// `id-LocationReportingControl`.
pub const PROC_LOCATION_REPORTING_CONTROL: u8 = 31;
/// `id-LocationReportingFailureIndication`.
pub const PROC_LOCATION_REPORTING_FAILURE_INDICATION: u8 = 32;
/// `id-LocationReport`.
pub const PROC_LOCATION_REPORT: u8 = 33;
/// `id-E-RABModificationIndication`.
pub const PROC_E_RAB_MODIFICATION_INDICATION: u8 = 50;

const ID_REQUEST_TYPE: u16 = 98;
const ID_ERAB_RELEASED_LIST: u16 = 110;
const ID_ERAB_TO_BE_MODIFIED_LIST_BEARER_MOD_IND: u16 = 199;
const ID_ERAB_MODIFY_LIST_BEARER_MOD_CONF: u16 = 203;
const ID_ERAB_MODIFY_ITEM_BEARER_MOD_CONF: u16 = 204;
const ID_ERAB_FAILED_TO_MODIFY_LIST_BEARER_MOD_CONF: u16 = 205;
const ID_ERAB_TO_BE_RELEASED_LIST_BEARER_MOD_CONF: u16 = 210;

/// One E-RAB of an E-RAB RELEASE INDICATION's E-RAB Released List.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleasedErab {
    /// E-RAB ID (= EBI).
    pub erab_id: u8,
    /// Cause, when this MME's cause enumeration has the value.
    pub cause: Option<Cause>,
}

/// An E-RAB RELEASE INDICATION (TS 36.413 §9.1.3.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErabReleaseIndication {
    /// MME-UE-S1AP-ID (reject).
    pub mme_ue_s1ap_id: u32,
    /// eNB-UE-S1AP-ID (reject).
    pub enb_ue_s1ap_id: u32,
    /// E-RAB Released List (ignore). Empty when the list was missing, which
    /// §10.3.5 has the MME ignore.
    pub released: Vec<ReleasedErab>,
    /// User Location Information (ignore, optional).
    pub location: Option<(Tai, EutranCgi)>,
}

fn user_location(v: &g::UserLocationInformation) -> Option<(Tai, EutranCgi)> {
    tai_from(&v.tai).zip(cgi_from(&v.eutran_cgi))
}

/// Decode an E-RAB RELEASE INDICATION (TS 36.413 §9.1.3.7), the initiating
/// message of a Class 2 procedure, with §10.3.4.2 / §10.3.5.
pub fn decode_erab_release_indication(bytes: &[u8]) -> Class2Decode<ErabReleaseIndication> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return Class2Decode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return Class2Decode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_E_RABReleaseIndication(m) = msg.value else {
        return Class2Decode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut mme, mut enb, mut released, mut location) = (None, None, Vec::new(), None);
    use g::E_RABReleaseIndicationProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = Some(v.0),
            V::Id_E_RABReleasedList(l) => {
                released =
                    l.0.into_iter()
                        .map(|entry| {
                            let g::E_RABList_EntryValue::Id_E_RABItem(item) = entry.value;
                            ReleasedErab {
                                erab_id: item.e_rab_id.0,
                                cause: domain_cause(&item.cause),
                            }
                        })
                        .collect();
            }
            V::Id_UserLocationInformation(v) => location = user_location(&v),
            _ => {}
        }
    }
    missing(&mut reject, mme.is_some(), ID_MME_UE_S1AP_ID);
    missing(&mut reject, enb.is_some(), ID_ENB_UE_S1AP_ID);
    if !reject.is_empty() {
        return Class2Decode::Reject {
            ies: reject,
            enb_ue_s1ap_id: enb,
            mme_ue_s1ap_id: mme,
        };
    }
    let (Some(mme_ue_s1ap_id), Some(enb_ue_s1ap_id)) = (mme, enb) else {
        return Class2Decode::Undecodable;
    };
    Class2Decode::Proceed {
        msg: ErabReleaseIndication {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            released,
            location,
        },
        notify,
    }
}

/// An E-RAB MODIFICATION INDICATION (TS 36.413 §9.1.3.8).
#[derive(Debug, Clone)]
pub struct ErabModificationIndication {
    /// MME-UE-S1AP-ID (reject).
    pub mme_ue_s1ap_id: u32,
    /// eNB-UE-S1AP-ID (reject).
    pub enb_ue_s1ap_id: u32,
    /// E-RAB to be Modified List (reject): each E-RAB's new downlink endpoint.
    pub to_be_modified: Vec<nextgcore_s1ap::ErabSwitchedItem>,
    /// E-RAB not to be Modified List (reject, optional).
    pub not_to_be_modified: Vec<nextgcore_s1ap::ErabSwitchedItem>,
    /// User Location Information (ignore, optional).
    pub location: Option<(Tai, EutranCgi)>,
}

/// Decode an E-RAB MODIFICATION INDICATION (TS 36.413 §9.1.3.8), the
/// initiating message of a Class 1 procedure with no failure message. A
/// missing or not understood `reject` IE is `Reject` (answered by ERROR
/// INDICATION, §10.3.4.2); `notify` IEs go in the confirm.
pub fn decode_erab_modification_indication(
    bytes: &[u8],
) -> Class2Decode<ErabModificationIndication> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return Class2Decode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return Class2Decode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_E_RABModificationIndication(m) = msg.value else {
        return Class2Decode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut mme, mut enb, mut modify, mut keep, mut location) =
        (None, None, None, Vec::new(), None);
    let item = |erab_id: u8, addr: &g::TransportLayerAddress, t: &g::GTP_TEID| {
        Some(nextgcore_s1ap::ErabSwitchedItem {
            erab_id,
            transport_layer_address: bits_to_bytes(&addr.0),
            gtp_teid: teid(&t.0)?,
        })
    };
    use g::E_RABModificationIndicationProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = Some(v.0),
            V::Id_E_RABToBeModifiedListBearerModInd(l) => {
                let items: Option<Vec<_>> = l
                    .0
                    .iter()
                    .map(|e| {
                        let g::E_RABToBeModifiedListBearerModInd_EntryValue::Id_E_RABToBeModifiedItemBearerModInd(i) = &e.value;
                        item(i.e_rab_id.0, &i.transport_layer_address, &i.dl_gtp_teid)
                    })
                    .collect();
                match items {
                    Some(items) => modify = Some(items),
                    None => not_understood(&mut reject, ID_ERAB_TO_BE_MODIFIED_LIST_BEARER_MOD_IND),
                }
            }
            V::Id_E_RABNotToBeModifiedListBearerModInd(l) => {
                keep = l
                    .0
                    .iter()
                    .filter_map(|e| {
                        let g::E_RABNotToBeModifiedListBearerModInd_EntryValue::Id_E_RABNotToBeModifiedItemBearerModInd(i) = &e.value;
                        item(i.e_rab_id.0, &i.transport_layer_address, &i.dl_gtp_teid)
                    })
                    .collect();
            }
            V::Id_UserLocationInformation(v) => location = user_location(&v),
            // CSG membership, BBF tunnel information, secondary RAT usage:
            // understood, not used by this MME.
            _ => {}
        }
    }
    missing(&mut reject, mme.is_some(), ID_MME_UE_S1AP_ID);
    missing(&mut reject, enb.is_some(), ID_ENB_UE_S1AP_ID);
    missing(
        &mut reject,
        modify.is_some(),
        ID_ERAB_TO_BE_MODIFIED_LIST_BEARER_MOD_IND,
    );
    if !reject.is_empty() {
        return Class2Decode::Reject {
            ies: reject,
            enb_ue_s1ap_id: enb,
            mme_ue_s1ap_id: mme,
        };
    }
    let (Some(mme_ue_s1ap_id), Some(enb_ue_s1ap_id), Some(to_be_modified)) = (mme, enb, modify)
    else {
        return Class2Decode::Undecodable;
    };
    Class2Decode::Proceed {
        msg: ErabModificationIndication {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            to_be_modified,
            not_to_be_modified: keep,
            location,
        },
        notify,
    }
}

/// An E-RAB MODIFICATION CONFIRM (TS 36.413 §9.1.3.9).
#[derive(Debug, Clone, Default)]
pub struct ErabModificationConfirm {
    /// MME-UE-S1AP-ID.
    pub mme_ue_s1ap_id: u32,
    /// eNB-UE-S1AP-ID.
    pub enb_ue_s1ap_id: u32,
    /// E-RABs successfully modified.
    pub modified: Vec<u8>,
    /// E-RABs that could not be modified, with the cause.
    pub failed: Vec<nextgcore_s1ap::ErabItem>,
    /// E-RABs the EPC has already released (§8.2.4.2).
    pub to_be_released: Vec<nextgcore_s1ap::ErabItem>,
}

/// Encode an E-RAB MODIFICATION CONFIRM (TS 36.413 §9.1.3.9): every IE
/// criticality ignore; procedure criticality reject. `notify` IEs of the
/// indication go in its Criticality Diagnostics.
pub fn build_erab_modification_confirm(
    msg: &ErabModificationConfirm,
    notify: &[DiagnosedIe],
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::E_RABModificationConfirmProtocolIEs_EntryValue as V;
    let ie = |id: u16, value: V| g::E_RABModificationConfirmProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(IGNORE),
        value,
    };
    let mut ies = vec![
        ie(
            ID_MME_UE_S1AP_ID,
            V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(msg.mme_ue_s1ap_id)),
        ),
        ie(
            ID_ENB_UE_S1AP_ID,
            V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(msg.enb_ue_s1ap_id)),
        ),
    ];
    if !msg.modified.is_empty() {
        ies.push(ie(
            ID_ERAB_MODIFY_LIST_BEARER_MOD_CONF,
            V::Id_E_RABModifyListBearerModConf(g::E_RABModifyListBearerModConf(
                msg.modified
                    .iter()
                    .map(|id| g::E_RABModifyListBearerModConf_Entry {
                        id: g::ProtocolIE_ID(ID_ERAB_MODIFY_ITEM_BEARER_MOD_CONF),
                        criticality: g::Criticality(IGNORE),
                        value:
                            g::E_RABModifyListBearerModConf_EntryValue::Id_E_RABModifyItemBearerModConf(
                                g::E_RABModifyItemBearerModConf {
                                    e_rab_id: g::E_RAB_ID(*id),
                                    ie_extensions: None,
                                },
                            ),
                    })
                    .collect(),
            )),
        ));
    }
    if !msg.failed.is_empty() {
        ies.push(ie(
            ID_ERAB_FAILED_TO_MODIFY_LIST_BEARER_MOD_CONF,
            V::Id_E_RABFailedToModifyListBearerModConf(erab_list(&msg.failed)),
        ));
    }
    if !msg.to_be_released.is_empty() {
        ies.push(ie(
            ID_ERAB_TO_BE_RELEASED_LIST_BEARER_MOD_CONF,
            V::Id_E_RABToBeReleasedListBearerModConf(erab_list(&msg.to_be_released)),
        ));
    }
    if !notify.is_empty() {
        ies.push(ie(
            ID_CRITICALITY_DIAGNOSTICS,
            V::Id_CriticalityDiagnostics(diagnostics_for(
                PROC_E_RAB_MODIFICATION_INDICATION,
                g::TriggeringMessage::INITIATING_MESSAGE,
                REJECT,
                notify,
            )),
        ));
    }
    encode_pdu(&g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
        procedure_code: g::ProcedureCode(PROC_E_RAB_MODIFICATION_INDICATION),
        criticality: g::Criticality(REJECT),
        value: g::SuccessfulOutcomeValue::Id_E_RABModificationIndication(
            g::E_RABModificationConfirm {
                protocol_i_es: g::E_RABModificationConfirmProtocolIEs(ies),
            },
        ),
    }))
}

/// Encode a LOCATION REPORTING CONTROL (TS 36.413 §9.1.15.1): the UE IDs
/// reject, Request Type ignore; procedure criticality ignore. `event_type` is
/// a `g::EventType` value (direct, change-of-serve-cell,
/// stop-change-of-serve-cell); the report area is always ECGI, the only one
/// §9.2.1.34 defines.
pub fn build_location_reporting_control(
    mme_ue_s1ap_id: u32,
    enb_ue_s1ap_id: u32,
    event_type: u8,
) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    use g::LocationReportingControlProtocolIEs_EntryValue as V;
    let ie = |id: u16, criticality: u8, value: V| g::LocationReportingControlProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(criticality),
        value,
    };
    let ies = vec![
        ie(
            ID_MME_UE_S1AP_ID,
            REJECT,
            V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(mme_ue_s1ap_id)),
        ),
        ie(
            ID_ENB_UE_S1AP_ID,
            REJECT,
            V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(enb_ue_s1ap_id)),
        ),
        ie(
            ID_REQUEST_TYPE,
            IGNORE,
            V::Id_RequestType(g::RequestType {
                event_type: g::EventType(event_type),
                report_area: g::ReportArea(g::ReportArea::ECGI),
                ie_extensions: None,
            }),
        ),
    ];
    encode_pdu(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(PROC_LOCATION_REPORTING_CONTROL),
        criticality: g::Criticality(IGNORE),
        value: g::InitiatingMessageValue::Id_LocationReportingControl(
            g::LocationReportingControl {
                protocol_i_es: g::LocationReportingControlProtocolIEs(ies),
            },
        ),
    }))
}

/// A LOCATION REPORT (TS 36.413 §9.1.15.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationReport {
    /// MME-UE-S1AP-ID (reject).
    pub mme_ue_s1ap_id: u32,
    /// eNB-UE-S1AP-ID (reject).
    pub enb_ue_s1ap_id: u32,
    /// EUTRAN-CGI (ignore), if present.
    pub eutran_cgi: Option<EutranCgi>,
    /// TAI (ignore), if present.
    pub tai: Option<Tai>,
    /// The Request Type's event type the report answers (ignore), if present.
    pub event_type: Option<u8>,
}

/// Decode a LOCATION REPORT (TS 36.413 §9.1.15.3), a Class 2 initiating
/// message. EUTRAN-CGI, TAI and Request Type are `ignore`: missing, they are
/// `None` (§10.3.5).
pub fn decode_location_report(bytes: &[u8]) -> Class2Decode<LocationReport> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return Class2Decode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return Class2Decode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_LocationReport(m) = msg.value else {
        return Class2Decode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut mme, mut enb, mut cgi, mut tai, mut event) = (None, None, None, None, None);
    use g::LocationReportProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = Some(v.0),
            V::Id_EUTRAN_CGI(v) => cgi = cgi_from(&v),
            V::Id_TAI(v) => tai = tai_from(&v),
            V::Id_RequestType(v) => event = Some(v.event_type.0),
            _ => {}
        }
    }
    missing(&mut reject, mme.is_some(), ID_MME_UE_S1AP_ID);
    missing(&mut reject, enb.is_some(), ID_ENB_UE_S1AP_ID);
    if !reject.is_empty() {
        return Class2Decode::Reject {
            ies: reject,
            enb_ue_s1ap_id: enb,
            mme_ue_s1ap_id: mme,
        };
    }
    let (Some(mme_ue_s1ap_id), Some(enb_ue_s1ap_id)) = (mme, enb) else {
        return Class2Decode::Undecodable;
    };
    Class2Decode::Proceed {
        msg: LocationReport {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            eutran_cgi: cgi,
            tai,
            event_type: event,
        },
        notify,
    }
}

/// A LOCATION REPORTING FAILURE INDICATION (TS 36.413 §9.1.15.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationReportingFailure {
    /// MME-UE-S1AP-ID (reject).
    pub mme_ue_s1ap_id: u32,
    /// eNB-UE-S1AP-ID (reject).
    pub enb_ue_s1ap_id: u32,
    /// Cause (ignore), if present and in this MME's enumeration.
    pub cause: Option<Cause>,
}

/// Decode a LOCATION REPORTING FAILURE INDICATION (TS 36.413 §9.1.15.2), a
/// Class 2 initiating message.
pub fn decode_location_reporting_failure_indication(
    bytes: &[u8],
) -> Class2Decode<LocationReportingFailure> {
    let Ok((pdu, unknown)) = nextgcore_s1ap_gen::decode_with_unknown_ies(bytes) else {
        return Class2Decode::Undecodable;
    };
    let g::S1AP_PDU::InitiatingMessage(msg) = pdu else {
        return Class2Decode::Undecodable;
    };
    let g::InitiatingMessageValue::Id_LocationReportingFailureIndication(m) = msg.value else {
        return Class2Decode::Undecodable;
    };
    let (mut reject, notify) = classify_unknown(&unknown);
    let (mut mme, mut enb, mut cause) = (None, None, None);
    use g::LocationReportingFailureIndicationProtocolIEs_EntryValue as V;
    for ie in m.protocol_i_es.0 {
        match ie.value {
            V::Id_MME_UE_S1AP_ID(v) => mme = Some(v.0),
            V::Id_eNB_UE_S1AP_ID(v) => enb = Some(v.0),
            V::Id_Cause(c) => cause = domain_cause(&c),
        }
    }
    missing(&mut reject, mme.is_some(), ID_MME_UE_S1AP_ID);
    missing(&mut reject, enb.is_some(), ID_ENB_UE_S1AP_ID);
    if !reject.is_empty() {
        return Class2Decode::Reject {
            ies: reject,
            enb_ue_s1ap_id: enb,
            mme_ue_s1ap_id: mme,
        };
    }
    let (Some(mme_ue_s1ap_id), Some(enb_ue_s1ap_id)) = (mme, enb) else {
        return Class2Decode::Undecodable;
    };
    Class2Decode::Proceed {
        msg: LocationReportingFailure {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            cause,
        },
        notify,
    }
}

#[cfg(test)]
pub(crate) mod test_codec;

/// Encode a PDU a production builder made. Under `cfg(test)` every one is
/// first checked against the TS 36.413 object sets (#737): the criticality of
/// each IE must be the schema's.
fn encode_pdu(pdu: &g::S1AP_PDU) -> Result<Vec<u8>, asn1_codecs::PerCodecError> {
    #[cfg(test)]
    criticality_oracle::assert_matches_ts_36_413(pdu);
    nextgcore_s1ap_gen::encode(pdu)
}

#[cfg(test)]
pub(crate) mod criticality_oracle;

#[cfg(test)]
mod golden_x691_tests;

#[cfg(test)]
mod codec_sweep_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod nas_tests;

#[cfg(test)]
mod ics_tests;

#[cfg(test)]
mod release_tests;

#[cfg(test)]
mod erab_tests;

#[cfg(test)]
mod paging_tests;

#[cfg(test)]
pub(crate) mod handover_tests;

#[cfg(test)]
mod reset_tests;

#[cfg(test)]
mod path_switch_tests;

#[cfg(test)]
mod rest_tests;

#[cfg(test)]
mod handover2_tests;

#[cfg(test)]
mod unmatched_tests;

#[cfg(test)]
mod eps_procs_tests;
