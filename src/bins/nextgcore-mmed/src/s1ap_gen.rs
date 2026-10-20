//! mmed's S1AP on the generated codec (`nextgcore-s1ap-gen`, #514).
//!
//! #514 moves mmed's S1AP off the hand-written `nextgcore-s1ap` codec one
//! message family at a time, as #417 did for amfd's NGAP. Each family keeps the
//! hand-written code as a byte-equivalence oracle in its tests until the final
//! deletion pass.
//!
//! Stage 2 (this module's first contents) is the S1 Setup family (TS 36.413
//! §8.7.3): the S1 SETUP REQUEST decode, with §10.3.4 / §10.3.5 handling, and
//! the S1 SETUP RESPONSE / S1 SETUP FAILURE encodes.

use bitvec::prelude::{BitVec, Msb0};
use nextgcore_s1ap::{
    Cause, EnbId, GlobalEnbId, PagingDrx, S1SetupRequest, SupportedTaItem, TimeToWait,
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

#[cfg(test)]
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
    g::CriticalityDiagnostics {
        procedure_code: Some(g::ProcedureCode(PROC_S1_SETUP)),
        triggering_message: Some(g::TriggeringMessage(
            g::TriggeringMessage::INITIATING_MESSAGE,
        )),
        procedure_criticality: Some(g::Criticality(REJECT)),
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
    nextgcore_s1ap_gen::encode(&g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
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
    nextgcore_s1ap_gen::encode(&g::S1AP_PDU::UnsuccessfulOutcome(g::UnsuccessfulOutcome {
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
    nextgcore_s1ap_gen::encode(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
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

#[cfg(test)]
mod tests;
