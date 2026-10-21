//! NGAP ASN.1 Encoding for AMF
//!
//! This module provides ASN.1 APER encoding for NGAP messages
//! using the nextgcore-ngap crate. This ensures wire compatibility with
//! the gNB (nextgsim-gnb) which also uses proper ASN.1 encoding.
//!
//! #417 is migrating these builders, one procedure family at a time, onto the
//! codec generated from the TS 38.413 ASN.1 (`nextgcore-ngap-gen`). Migrated so
//! far: the whole NG Setup family -- the Response and Failure encoders (stage 2)
//! and the Request decoder (stage 3), which applies TS 38.413 §10.3.4/§10.3.5 to
//! not-comprehended and missing IEs ([`decode_ng_setup_request_asn1`]) -- and
//! the UE Context Release family (stage 4): the Command encoder and the Request
//! and Complete decoders ([`decode_ue_context_release_request_asn1`],
//! [`decode_ue_context_release_complete_asn1`]), which report through an Error
//! Indication where §10.3.4.2 says to -- and the PDU Session Resource Release
//! pair (stage 5): the Command encoder, whose per-session transfer goes through
//! [`nextgcore_ngap_gen::encode_contained`], and the Response decoder
//! ([`decode_pdu_session_resource_release_response_asn1`]) -- and the PDU
//! Session Resource Setup pair (stage 6): the Request encoder, the Response
//! decoder ([`decode_pdu_session_resource_setup_response_asn1`]), and the
//! Setup Request / Response transfers
//! ([`build_n2_sm_setup_request_transfer`],
//! [`parse_n2_sm_setup_response_transfer`]).

use nextgcore_asn1c::ngap::cause::{
    Cause, CauseMisc, CauseNas, CauseProtocol, CauseRadioNetwork, CauseTransport,
};
use nextgcore_ngap::types::*;
// Only the hand-written oracles the tests compare the generated codec with:
// since #417's Overload stage no production builder here is hand-written.
#[cfg(test)]
use nextgcore_ngap::{builder, parser, NgapMessage};

use nextgcore_ngap_gen::generated as ngap_gen;

use crate::context::AmfContext;

/// Build an NG Setup Response PDU with proper ASN.1 APER encoding
///
/// This is sent by AMF to gNB in response to a successful NG Setup Request.
/// The message follows 3GPP TS 38.413 Section 9.2.6.2.
///
/// #417 stage 2: encoded by the codec GENERATED from the TS 38.413 ASN.1
/// (`nextgcore-ngap-gen`), not the hand-written `nextgcore-ngap` builder. The
/// bytes are unchanged -- `ng_setup_generated_matches_hand_written_*` below pins
/// that against the hand-written encoder over a matrix of contexts.
pub fn build_ng_setup_response_asn1(ctx: &AmfContext) -> Option<Vec<u8>> {
    build_ng_setup_response_with_diagnostics_asn1(ctx, &[])
}

/// [`build_ng_setup_response_asn1`], additionally reporting `diagnostics` --
/// not-comprehended IEs of the request marked "ignore IE and notify sender" --
/// in a Criticality Diagnostics IE, as TS 38.413 §10.3.4.2 requires of the
/// response message. With no diagnostics the IE is absent and the bytes are
/// exactly [`build_ng_setup_response_asn1`]'s.
pub fn build_ng_setup_response_with_diagnostics_asn1(
    ctx: &AmfContext,
    diagnostics: &[IeDiagnostic],
) -> Option<Vec<u8>> {
    use ngap_gen::{
        AMFName, AMFPointer, AMFRegionID, AMFSetID, NGSetupResponse, NGSetupResponseProtocolIEs,
        NGSetupResponseProtocolIEs_Entry as Entry, NGSetupResponseProtocolIEs_EntryValue as Ie,
        PLMNSupportItem, PLMNSupportList, ProtocolIE_ID, RelativeAMFCapacity, ServedGUAMIItem,
        ServedGUAMIList, SliceSupportItem, SliceSupportList, GUAMI, NGAP_PDU,
    };

    let amf_name = ctx.amf_name.as_deref().unwrap_or("AMF").to_string();

    let served_guami_list = ctx
        .served_guami
        .iter()
        .take(ctx.num_of_served_guami)
        .map(|guami| ServedGUAMIItem {
            guami: GUAMI {
                plmn_identity: ngap_gen::PLMNIdentity(encode_plmn_id(&guami.plmn_id).to_vec()),
                amf_region_id: AMFRegionID(low_bits(u64::from(guami.amf_id.region), 8)),
                amf_set_id: AMFSetID(low_bits(u64::from(guami.amf_id.set), 10)),
                amf_pointer: AMFPointer(low_bits(u64::from(guami.amf_id.pointer), 6)),
                ie_extensions: None,
            },
            backup_amf_name: None,
            ie_extensions: None,
        })
        .collect::<Vec<_>>();

    let plmn_support_list = ctx
        .plmn_support
        .iter()
        .take(ctx.num_of_plmn_support)
        .map(|plmn_support| PLMNSupportItem {
            plmn_identity: ngap_gen::PLMNIdentity(encode_plmn_id(&plmn_support.plmn_id).to_vec()),
            slice_support_list: SliceSupportList(
                plmn_support
                    .s_nssai
                    .iter()
                    .take(plmn_support.num_of_s_nssai)
                    .map(|s_nssai| SliceSupportItem {
                        s_nssai: generated_s_nssai(s_nssai),
                        ie_extensions: None,
                    })
                    .collect(),
            ),
            ie_extensions: None,
        })
        .collect::<Vec<_>>();

    // amfd-09 (TS 38.413 §9.2.6.2): a strict-peer gNB needs a non-empty
    // PLMNSupportList with slice support for load-balancing / slice selection.
    // An empty list is an AMF misconfiguration; surface it loudly at build time
    // rather than letting the gNB reject the response on the wire.
    if ctx.num_of_plmn_support == 0 {
        log::error!(
            "NG Setup Response built with an EMPTY PLMNSupportList \
             (num_of_plmn_support=0); check AMF slice configuration"
        );
        debug_assert!(
            ctx.num_of_plmn_support > 0,
            "NGSetupResponse PLMNSupportList must not be empty (TS 38.413 §9.2.6.2)"
        );
    }

    // No SIZE checks here: an empty or over-long ServedGUAMIList,
    // PLMNSupportList or SliceSupportList is refused by the generated encoder
    // itself (nextgsim #212), which is the `Err` arm below.

    // IE order and criticalities as TS 38.413 §9.2.6.2 lists them, and as the
    // hand-written builder emitted them.
    let entry = |id: u16, criticality: u8, value: Ie| Entry {
        id: ProtocolIE_ID(id),
        criticality: ngap_gen::Criticality(criticality),
        value,
    };
    let reject = ngap_gen::Criticality::REJECT;
    let ignore = ngap_gen::Criticality::IGNORE;
    let mut ies = vec![
        entry(
            ngap_gen::ID_AMF_NAME,
            reject,
            Ie::Id_AMFName(AMFName(amf_name)),
        ),
        entry(
            ngap_gen::ID_SERVED_GUAMI_LIST,
            reject,
            Ie::Id_ServedGUAMIList(ServedGUAMIList(served_guami_list)),
        ),
        entry(
            ngap_gen::ID_RELATIVE_AMF_CAPACITY,
            ignore,
            Ie::Id_RelativeAMFCapacity(RelativeAMFCapacity(ctx.relative_capacity)),
        ),
        entry(
            ngap_gen::ID_PLMN_SUPPORT_LIST,
            reject,
            Ie::Id_PLMNSupportList(PLMNSupportList(plmn_support_list)),
        ),
    ];
    if !diagnostics.is_empty() {
        ies.push(entry(
            ngap_gen::ID_CRITICALITY_DIAGNOSTICS,
            ignore,
            Ie::Id_CriticalityDiagnostics(generated_criticality_diagnostics(diagnostics)),
        ));
    }
    let pdu = NGAP_PDU::SuccessfulOutcome(ngap_gen::SuccessfulOutcome {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_NG_SETUP),
        criticality: ngap_gen::Criticality(reject),
        value: ngap_gen::SuccessfulOutcomeValue::Id_NGSetup(NGSetupResponse {
            protocol_i_es: NGSetupResponseProtocolIEs(ies),
        }),
    });

    match nextgcore_ngap_gen::encode(&pdu) {
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
///
/// #417 stage 2: encoded by the generated codec, like the Response above. The
/// (group, value) -> Cause mapping is still [`build_cause`], shared with the
/// UE Context Release Command, so both messages clamp an out-of-range value the
/// same way; only the encoding moved. Every cause, extension values such as
/// radioNetwork 45/46 included, goes through the generated codec (nextgsim #213).
pub fn build_ng_setup_failure_asn1(
    cause_group: u8,
    cause_value: i64,
    time_to_wait: Option<u8>,
) -> Vec<u8> {
    build_ng_setup_failure_with_diagnostics_asn1(cause_group, cause_value, time_to_wait, &[])
}

/// [`build_ng_setup_failure_asn1`], additionally reporting `diagnostics` in a
/// Criticality Diagnostics IE -- the not-comprehended or missing IEs that made
/// the AMF reject the request (TS 38.413 §10.3.4.2, §10.3.5), or the
/// "ignore IE and notify sender" ones it is answering. With no diagnostics the
/// IE is absent and the bytes are exactly [`build_ng_setup_failure_asn1`]'s.
pub fn build_ng_setup_failure_with_diagnostics_asn1(
    cause_group: u8,
    cause_value: i64,
    time_to_wait: Option<u8>,
    diagnostics: &[IeDiagnostic],
) -> Vec<u8> {
    use ngap_gen::{
        NGSetupFailure, NGSetupFailureProtocolIEs, NGSetupFailureProtocolIEs_Entry as Entry,
        NGSetupFailureProtocolIEs_EntryValue as Ie, ProtocolIE_ID, NGAP_PDU,
    };

    let cause = generated_cause(build_cause(cause_group, cause_value));

    let ignore = ngap_gen::Criticality::IGNORE;
    let mut ies = vec![Entry {
        id: ProtocolIE_ID(ngap_gen::ID_CAUSE),
        criticality: ngap_gen::Criticality(ignore),
        value: Ie::Id_Cause(cause),
    }];
    // TimeToWait ENUMERATED { v1s, v2s, v5s, v10s, v20s, v60s, ... }: a wire
    // value above v20s (4) means v60s, as before.
    if let Some(ttw) = time_to_wait {
        ies.push(Entry {
            id: ProtocolIE_ID(ngap_gen::ID_TIME_TO_WAIT),
            criticality: ngap_gen::Criticality(ignore),
            value: Ie::Id_TimeToWait(ngap_gen::TimeToWait(ttw.min(ngap_gen::TimeToWait::V60S))),
        });
    }
    // IE order as TS 38.413 §9.2.6.3 lists it: Cause, Time to Wait, Criticality
    // Diagnostics.
    if !diagnostics.is_empty() {
        ies.push(Entry {
            id: ProtocolIE_ID(ngap_gen::ID_CRITICALITY_DIAGNOSTICS),
            criticality: ngap_gen::Criticality(ignore),
            value: Ie::Id_CriticalityDiagnostics(generated_criticality_diagnostics(diagnostics)),
        });
    }

    let pdu = NGAP_PDU::UnsuccessfulOutcome(ngap_gen::UnsuccessfulOutcome {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_NG_SETUP),
        criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
        value: ngap_gen::UnsuccessfulOutcomeValue::Id_NGSetup(NGSetupFailure {
            protocol_i_es: NGSetupFailureProtocolIEs(ies),
        }),
    });

    match nextgcore_ngap_gen::encode(&pdu) {
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

/// The low `n` bits of `value`, most significant first -- the generated
/// codec's fixed-size BIT STRING. Truncates exactly as the hand-written
/// encoder's `write_bits` did, so an out-of-range AMF Set ID keeps its wire form.
fn low_bits(value: u64, n: usize) -> bitvec::vec::BitVec<u8, bitvec::order::Msb0> {
    (0..n).rev().map(|i| (value >> i) & 1 == 1).collect()
}

/// An AMF-context S-NSSAI as the generated `S-NSSAI` (TS 38.413 §9.3.1.24).
fn generated_s_nssai(s_nssai: &crate::context::SNssai) -> ngap_gen::S_NSSAI {
    ngap_gen::S_NSSAI {
        sst: ngap_gen::SST(vec![s_nssai.sst]),
        sd: s_nssai.sd.map(|sd| {
            ngap_gen::SD(vec![
                ((sd >> 16) & 0xFF) as u8,
                ((sd >> 8) & 0xFF) as u8,
                (sd & 0xFF) as u8,
            ])
        }),
        ie_extensions: None,
    }
}

/// The hand-written [`Cause`] as the generated one, carrying each value over as
/// its wire number. Extension values (radioNetwork 45/46) encode past the root
/// like any other (nextgsim #213), so the mapping is total.
fn generated_cause(cause: Cause) -> ngap_gen::Cause {
    match cause {
        Cause::RadioNetwork(v) => {
            ngap_gen::Cause::RadioNetwork(ngap_gen::CauseRadioNetwork(v as u8))
        }
        Cause::Transport(v) => ngap_gen::Cause::Transport(ngap_gen::CauseTransport(v as u8)),
        Cause::Nas(v) => ngap_gen::Cause::Nas(ngap_gen::CauseNas(v as u8)),
        Cause::Protocol(v) => ngap_gen::Cause::Protocol(ngap_gen::CauseProtocol(v as u8)),
        Cause::Misc(v) => ngap_gen::Cause::Misc(ngap_gen::CauseMisc(v as u8)),
    }
}

/// One entry of a Criticality Diagnostics IE (TS 38.413 §9.3.1.3): an IE of a
/// received message that was not comprehended or was missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IeDiagnostic {
    /// The ProtocolIE-ID of the offending IE.
    pub ie_id: u16,
    /// Its criticality as a `Criticality` index ([`ngap_gen::Criticality`]):
    /// 0 = reject, 2 = notify. "ignore" is never reported (§9.3.1.3).
    pub criticality: u8,
    /// [`ngap_gen::TypeOfError`]: 0 = not-understood, 1 = missing.
    pub type_of_error: u8,
}

/// maxnoofErrors (TS 38.413 §9.4): at most this many IEs per Criticality
/// Diagnostics IE.
const MAX_NOOF_ERRORS: usize = 256;

/// `diagnostics` as the generated Criticality Diagnostics IE. Only the
/// Information Element Criticality Diagnostics list is filled: Procedure Code
/// and Triggering Message are for an Error Indication, "not within the response
/// message of the same procedure that caused the error" (§9.3.1.3). Truncated
/// to maxnoofErrors, which the SIZE of the list would otherwise refuse.
fn generated_criticality_diagnostics(
    diagnostics: &[IeDiagnostic],
) -> ngap_gen::CriticalityDiagnostics {
    generated_criticality_diagnostics_for(None, diagnostics)
}

/// [`generated_criticality_diagnostics`], with Procedure Code, Triggering
/// Message and Procedure Criticality filled from `procedure` when the report
/// travels in an Error Indication (§10.3.4.2: "the Procedure Code IE, the
/// Triggering Message IE, Procedure Criticality IE, and the Information Element
/// Criticality Diagnostics IE shall be included").
fn generated_criticality_diagnostics_for(
    procedure: Option<&ReportedProcedure>,
    diagnostics: &[IeDiagnostic],
) -> ngap_gen::CriticalityDiagnostics {
    ngap_gen::CriticalityDiagnostics {
        procedure_code: procedure.map(|p| ngap_gen::ProcedureCode(p.procedure_code)),
        triggering_message: procedure.map(|p| ngap_gen::TriggeringMessage(p.triggering_message)),
        procedure_criticality: procedure.map(|p| ngap_gen::Criticality(p.procedure_criticality)),
        i_es_criticality_diagnostics: Some(ngap_gen::CriticalityDiagnostics_IE_List(
            diagnostics
                .iter()
                .take(MAX_NOOF_ERRORS)
                .map(|d| ngap_gen::CriticalityDiagnostics_IE_Item {
                    ie_criticality: ngap_gen::Criticality(d.criticality),
                    ie_id: ngap_gen::ProtocolIE_ID(d.ie_id),
                    type_of_error: ngap_gen::TypeOfError(d.type_of_error),
                    ie_extensions: None,
                })
                .collect(),
        )),
        ie_extensions: None,
    }
}

/// Sort the not-comprehended IEs [`nextgcore_ngap_gen::decode_with_unknown_ies`]
/// skipped by their criticality (TS 38.413 §10.3.4.2): "ignore" ones are
/// dropped, and the "reject" and "ignore IE and notify sender" ones come back as
/// `(reject, notify)` diagnostics. `None` when an IE id is outside ProtocolIE-ID,
/// which no well-formed container can carry. `message` names the PDU in logs.
fn classify_unknown_ies(
    unknown: &[nextgcore_ngap_gen::UnknownIe],
    message: &str,
) -> Option<(Vec<IeDiagnostic>, Vec<IeDiagnostic>)> {
    let mut reject = Vec::new();
    let mut notify = Vec::new();
    for ie in unknown {
        let Ok(ie_id) = u16::try_from(ie.id) else {
            log::error!("{message} IE id {} is outside ProtocolIE-ID", ie.id);
            return None;
        };
        // A container that carried no criticality cannot have marked the IE
        // ignorable, so it is not.
        let criticality = ie.criticality.unwrap_or(ngap_gen::Criticality::REJECT);
        let diagnostic = IeDiagnostic {
            ie_id,
            criticality,
            type_of_error: ngap_gen::TypeOfError::NOT_UNDERSTOOD,
        };
        match criticality {
            ngap_gen::Criticality::IGNORE => {
                log::debug!("{message}: ignoring not-comprehended IE {ie_id}");
            }
            ngap_gen::Criticality::NOTIFY => {
                log::warn!("{message}: ignoring not-comprehended IE {ie_id}, and reporting it");
                notify.push(diagnostic);
            }
            _ => {
                log::warn!("{message}: not-comprehended IE {ie_id} is marked reject");
                reject.push(diagnostic);
            }
        }
    }
    Some((reject, notify))
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
///
/// `pub(crate)` for #399: the PWS indication path needs the PLMN out of a PDU's
/// own Global RAN Node ID IE (TS 38.413 §9.3.1.5) to render a TS 29.571
/// `GlobalRanNodeId` for the notification.
pub(crate) fn decode_plmn_id(bytes: &[u8]) -> crate::context::PlmnId {
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

/// How a received NG Setup Request is to be answered.
#[derive(Debug)]
pub enum NgSetupRequestDecode {
    /// Decoded; run the procedure. `notify` lists the not-comprehended IEs
    /// marked "ignore IE and notify sender", which the answer -- Response or
    /// Failure -- must report in its Criticality Diagnostics (§10.3.4.2).
    Proceed {
        /// The request, as the NG Setup handler consumes it.
        request: crate::ngap_handler::NgSetupRequest,
        /// IEs to report as ignored.
        notify: Vec<IeDiagnostic>,
    },
    /// A not-comprehended IE marked "reject" (§10.3.4.2), or a missing IE
    /// whose criticality is "reject" (§10.3.5): none of the request may be
    /// executed, and NG Setup Failure reports these IEs.
    Reject(Vec<IeDiagnostic>),
    /// Not decodable, or naming something amfd cannot represent (a RAN node
    /// other than a gNB or ng-eNB, a PagingDRX extension value).
    Undecodable,
}

/// Decode an NG Setup Request (TS 38.413 §9.2.6.1) with the GENERATED codec
/// (#417 stage 3), applying the criticality rules of §10.3.4.2 and §10.3.5.
///
/// The hand-written parser this replaced ignored a not-comprehended IE marked
/// "ignore" or "notify" alike, and turned one marked "reject" -- or a missing
/// mandatory IE -- into an undecodable request answered with
/// protocol/semantic-error. Now: "ignore" is ignored; "notify" proceeds and is
/// reported; "reject" and a missing GlobalRANNodeID or SupportedTAList (both
/// criticality reject, §9.2.6.1) reject the request with those IEs listed.
/// Everything the old parser produced from a request it accepted is produced
/// identically -- `ng_setup_request_generated_decode_matches_hand_written`.
pub fn decode_ng_setup_request_asn1(data: &[u8]) -> NgSetupRequestDecode {
    use ngap_gen::{
        GlobalRANNodeID, InitiatingMessageValue, NGSetupRequestProtocolIEs_EntryValue as Ie,
        GNB_ID, NGAP_PDU,
    };
    use NgSetupRequestDecode::{Proceed, Reject, Undecodable};

    let (pdu, unknown) = match nextgcore_ngap_gen::decode_with_unknown_ies(data) {
        Ok(decoded) => decoded,
        Err(e) => {
            log::error!("Failed to decode NGAP PDU: {e:?}");
            return Undecodable;
        }
    };
    let NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        value: InitiatingMessageValue::Id_NGSetup(req),
        ..
    }) = pdu
    else {
        log::error!("Expected NgSetupRequest");
        return Undecodable;
    };

    let Some((mut reject, notify)) = classify_unknown_ies(&unknown, "NG Setup Request") else {
        return Undecodable;
    };

    let mut global_ran_node_id = None;
    let mut ran_node_name = None;
    let mut supported_ta_list = None;
    // DefaultPagingDRX is mandatory but criticality ignore (§9.2.6.1); absent,
    // it defaults as the hand-written parser defaulted it.
    let mut default_paging_drx = ngap_gen::PagingDRX::V128;
    for entry in req.protocol_i_es.0 {
        match entry.value {
            Ie::Id_GlobalRANNodeID(v) => global_ran_node_id = Some(v),
            Ie::Id_RANNodeName(v) => ran_node_name = Some(v.0),
            Ie::Id_SupportedTAList(v) => supported_ta_list = Some(v),
            Ie::Id_DefaultPagingDRX(v) => default_paging_drx = v.0,
            // Comprehended, and not used by the AMF.
            Ie::Id_UERetentionInformation(_)
            | Ie::Id_NB_IoT_DefaultPagingDRX(_)
            | Ie::Id_Extended_RANNodeName(_) => {}
        }
    }
    let missing = |ie_id: u16| IeDiagnostic {
        ie_id,
        criticality: ngap_gen::Criticality::REJECT,
        type_of_error: ngap_gen::TypeOfError::MISSING,
    };
    if global_ran_node_id.is_none() {
        reject.push(missing(ngap_gen::ID_GLOBAL_RAN_NODE_ID));
    }
    if supported_ta_list.is_none() {
        reject.push(missing(ngap_gen::ID_SUPPORTED_TA_LIST));
    }
    let (Some(global_ran_node_id), Some(supported_ta_list)) =
        (global_ran_node_id, supported_ta_list)
    else {
        return Reject(reject);
    };
    if !reject.is_empty() {
        return Reject(reject);
    }

    let mut request = crate::ngap_handler::NgSetupRequest {
        global_ran_node_id_present: true,
        ran_node_name,
        ..Default::default()
    };
    match global_ran_node_id {
        GlobalRANNodeID::GlobalGNB_ID(gnb) => {
            request.plmn_id = decode_plmn_id(&gnb.plmn_identity.0);
            // GNB-ID's choice-Extensions alternative is uninhabited: its
            // object set is empty, so since nextgsim #218 its value type has no
            // variants and a choice extension on the wire fails the decode
            // above (Undecodable) instead of reaching here. A schema that
            // defines one makes this pattern refutable, and this line stops
            // compiling, which is where it should be handled.
            let GNB_ID::GNB_ID(bits) = gnb.gnb_id;
            // SIZE(22..32), so it fits: the decoder enforces the bound.
            request.gnb_id_len = bits.0.len() as u8;
            request.gnb_id = bits
                .0
                .iter()
                .fold(0u32, |id, bit| (id << 1) | u32::from(*bit));
        }
        GlobalRANNodeID::GlobalNgENB_ID(ng_enb) => {
            request.plmn_id = decode_plmn_id(&ng_enb.plmn_identity.0);
        }
        other => {
            log::error!("NG Setup Request from an unsupported RAN node type: {other:?}");
            return Undecodable;
        }
    }

    // TAC SIZE(3), SST SIZE(1), SD SIZE(3): the decoder enforces each bound.
    let octets = |bytes: &[u8]| bytes.iter().fold(0u32, |v, b| (v << 8) | u32::from(*b));
    request.supported_ta_list = supported_ta_list
        .0
        .iter()
        .map(|ta| {
            let bplmn_list: Vec<crate::context::BplmnEntry> = ta
                .broadcast_plmn_list
                .0
                .iter()
                .map(|bp| {
                    let s_nssai: Vec<crate::context::SNssai> = bp
                        .tai_slice_support_list
                        .0
                        .iter()
                        .map(|item| crate::context::SNssai {
                            sst: octets(&item.s_nssai.sst.0) as u8,
                            sd: item.s_nssai.sd.as_ref().map(|sd| octets(&sd.0)),
                        })
                        .collect();
                    crate::context::BplmnEntry {
                        plmn_id: decode_plmn_id(&bp.plmn_identity.0),
                        num_of_s_nssai: s_nssai.len(),
                        s_nssai,
                    }
                })
                .collect();
            crate::context::SupportedTa {
                tac: octets(&ta.tac.0),
                num_of_bplmn_list: bplmn_list.len(),
                bplmn_list,
            }
        })
        .collect();

    // PagingDRX is extensible; an extension value is one the hand-written
    // parser refused, and the AMF has no representation for it.
    if default_paging_drx > ngap_gen::PagingDRX::V256 {
        log::error!("NG Setup Request: PagingDRX extension value {default_paging_drx}");
        return Undecodable;
    }
    request.default_paging_drx = default_paging_drx;

    Proceed { request, notify }
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

/// Parse an Initial UE Message with the HAND-WRITTEN codec: the pre-#417
/// path, kept as the oracle `decode_initial_ue_message_asn1` is checked against.
#[cfg(test)]
pub(crate) fn parse_initial_ue_message_asn1(data: &[u8]) -> Option<InitialUeMessageData> {
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
    use ngap_gen::{
        DownlinkNASTransport, DownlinkNASTransportProtocolIEs,
        DownlinkNASTransportProtocolIEs_Entry as Entry,
        DownlinkNASTransportProtocolIEs_EntryValue as Ie, ProtocolIE_ID, NGAP_PDU,
    };

    // IE order and criticalities as TS 38.413 §9.2.5.2 lists them. The
    // generated encoder refuses an AMF UE NGAP ID past 2^40-1, as the
    // hand-written one did, and fragments a NAS-PDU of 16K octets or more
    // (X.691 §11.9.3.8, nextgsim #222).
    let ie = |id: u16, criticality: u8, value: Ie| Entry {
        id: ProtocolIE_ID(id),
        criticality: ngap_gen::Criticality(criticality),
        value,
    };
    let pdu = NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_DOWNLINK_NAS_TRANSPORT),
        criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
        value: ngap_gen::InitiatingMessageValue::Id_DownlinkNASTransport(DownlinkNASTransport {
            protocol_i_es: DownlinkNASTransportProtocolIEs(vec![
                ie(
                    ngap_gen::ID_AMF_UE_NGAP_ID,
                    ngap_gen::Criticality::REJECT,
                    Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(amf_ue_ngap_id)),
                ),
                ie(
                    ngap_gen::ID_RAN_UE_NGAP_ID,
                    ngap_gen::Criticality::REJECT,
                    Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(ran_ue_ngap_id)),
                ),
                ie(
                    ngap_gen::ID_NAS_PDU,
                    ngap_gen::Criticality::REJECT,
                    Ie::Id_NAS_PDU(ngap_gen::NAS_PDU(nas_pdu.to_vec())),
                ),
            ]),
        }),
    });

    match nextgcore_ngap_gen::encode(&pdu) {
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
///
/// #417 stage 6: encoded by the generated codec. The N2 SM transfer is the
/// SMF's, carried as the item's `OCTET STRING (CONTAINING ...)` without being
/// re-encoded. The bytes are the hand-written encoder's for every request the
/// AMF sends (no message-level NAS-PDU) --
/// `pdu_session_resource_setup_request_generated_matches_hand_written` pins it.
/// A message-level NAS-PDU now goes where §9.4.1 puts it, before the session
/// list in object-set order; the hand-written encoder appended it after, which
/// a receiver must treat as an abstract syntax error (§10.3.6).
pub fn build_pdu_session_resource_setup_request_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    pdu_session_id: u8,
    s_nssai_sst: u8,
    s_nssai_sd: Option<u32>,
    nas_pdu: Option<&[u8]>,
    n2_sm_transfer: &[u8],
) -> Option<Vec<u8>> {
    use ngap_gen::{
        PDUSessionResourceSetupItemSUReq,
        PDUSessionResourceSetupItemSUReqPDUSessionResourceSetupRequestTransfer as Transfer,
        PDUSessionResourceSetupRequest, PDUSessionResourceSetupRequestProtocolIEs,
        PDUSessionResourceSetupRequestProtocolIEs_Entry as Entry,
        PDUSessionResourceSetupRequestProtocolIEs_EntryValue as Ie, ProtocolIE_ID, NGAP_PDU,
    };

    let item = PDUSessionResourceSetupItemSUReq {
        pdu_session_id: ngap_gen::PDUSessionID(pdu_session_id),
        pdu_session_nas_pdu: None,
        s_nssai: generated_s_nssai(&crate::context::SNssai {
            sst: s_nssai_sst,
            sd: s_nssai_sd,
        }),
        pdu_session_resource_setup_request_transfer: Transfer(n2_sm_transfer.to_vec()),
        ie_extensions: None,
    };

    let reject = ngap_gen::Criticality(ngap_gen::Criticality::REJECT);
    // IE order and criticalities as TS 38.413 §9.2.1.1 lists them; the AMF
    // sends neither the RAN Paging Priority nor a UE AMBR here.
    let mut ies = vec![
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_AMF_UE_NGAP_ID),
            criticality: reject.clone(),
            value: Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(amf_ue_ngap_id)),
        },
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_RAN_UE_NGAP_ID),
            criticality: reject.clone(),
            value: Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(ran_ue_ngap_id)),
        },
    ];
    if let Some(nas_pdu) = nas_pdu {
        ies.push(Entry {
            id: ProtocolIE_ID(ngap_gen::ID_NAS_PDU),
            criticality: reject.clone(),
            value: Ie::Id_NAS_PDU(ngap_gen::NAS_PDU(nas_pdu.to_vec())),
        });
    }
    ies.push(Entry {
        id: ProtocolIE_ID(ngap_gen::ID_PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ),
        criticality: reject.clone(),
        value: Ie::Id_PDUSessionResourceSetupListSUReq(ngap_gen::PDUSessionResourceSetupListSUReq(
            vec![item],
        )),
    });
    let pdu = NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_PDU_SESSION_RESOURCE_SETUP),
        criticality: reject,
        value: ngap_gen::InitiatingMessageValue::Id_PDUSessionResourceSetup(
            PDUSessionResourceSetupRequest {
                protocol_i_es: PDUSessionResourceSetupRequestProtocolIEs(ies),
            },
        ),
    });

    match nextgcore_ngap_gen::encode(&pdu) {
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

/// Map the 8-bit replayed NAS UE security capability octet (TS 24.501
/// §9.11.3.54, bit 8 / 0x80 = the null algorithm xEA0/xIA0) onto the 16-bit
/// NGAP BIT STRING field (TS 38.413 §9.3.1.86). In NGAP the null algorithm is
/// NOT representable ("all bits equal to 0 – UE supports no other algorithm
/// than NEA0") and the first/most-significant bit is 128-xEA1. So we drop the
/// NAS MSB (xEA0) and left-align: NAS bit 7 (0x40, 128-xEA1) lands on the NGAP
/// MSB (0x8000). A left shift of 9 does exactly this — the xEA0 bit shifts out
/// of the u16 and each remaining algorithm bit moves to its NGAP position.
fn nas_caps_octet_to_ngap_bits(octet: u8) -> u16 {
    (octet as u16) << 9
}

/// Build an Initial Context Setup Request (TS 38.413 §8.3.1 / §9.2.2.1) with the
/// GENERATED codec (#417 stage 7).
///
/// The GUAMI is taken from the AMF's first served GUAMI. The replayed UE
/// security capabilities and KgNB (the UE Security Key) come from the live
/// AMF UE security context -- nothing is hardcoded. The protected initial
/// Registration Accept rides inside the request as the NAS-PDU
/// (TS 23.502 §4.2.2.2.2 step 16).
///
/// The IEs go in object-set order with the object set's criticalities (§9.4.1,
/// `InitialContextSetupRequestIEs`). The hand-written encoder this replaced got
/// two of those wrong on every production request: it appended the UE AMBR
/// AFTER the NAS-PDU, where the object set puts it fourth, and it marked the
/// NAS-PDU "reject" where the object set says "ignore". Every other byte is
/// unchanged: `initial_context_setup_request_generated_matches_hand_written`.
///
/// amfd-08: the OPTIONAL Mobility Restriction List and Masked IMEISV IEs are
/// not emitted. Both are optional in TS 38.413 §9.2.2.1, so omitting them is
/// conformant for the non-roaming / no-forbidden-area case. No PDU Session
/// Resource Setup List is sent either -- sessions are set up afterwards with
/// their own PDU Session Resource Setup -- so the UE AMBR, which §9.2.2.1 makes
/// conditional on that list, is sent only when the subscription carries one.
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
    build_initial_context_setup_request_with_sessions_asn1(
        ctx,
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        allowed_nssai,
        ue_security_capability,
        security_key,
        nas_pdu,
        ue_ambr,
        &[],
    )
}

/// One PDU session to set up inside an Initial Context Setup Request
/// (TS 38.413 §9.2.2.1, PDUSessionResourceSetupItemCxtReq): its ID, S-NSSAI and
/// the PDUSessionResourceSetupRequestTransfer the SMF supplied, relayed as is.
#[derive(Debug, Clone)]
pub struct CxtReqSession {
    pub pdu_session_id: u8,
    pub s_nssai: crate::context::SNssai,
    pub transfer: Vec<u8>,
}

/// [`build_initial_context_setup_request_asn1`] plus a PDU Session Resource
/// Setup Request List, as the Service Request answering a page needs (TS 23.502
/// §4.2.3.2 step 12: the N2 Request carries the N2 SM information). An empty
/// `sessions` omits the IE, so the original builder is exactly this with `&[]`.
#[allow(clippy::too_many_arguments)]
pub fn build_initial_context_setup_request_with_sessions_asn1(
    ctx: &AmfContext,
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    allowed_nssai: &[crate::context::SNssai],
    ue_security_capability: &crate::context::UeSecurityCapability,
    security_key: &[u8; 32],
    nas_pdu: Option<&[u8]>,
    ue_ambr: Option<(u64, u64)>,
    sessions: &[CxtReqSession],
) -> Option<Vec<u8>> {
    use ngap_gen::{
        InitialContextSetupRequest, InitialContextSetupRequestProtocolIEs,
        InitialContextSetupRequestProtocolIEs_Entry as Entry,
        InitialContextSetupRequestProtocolIEs_EntryValue as Ie, ProtocolIE_ID, NGAP_PDU,
    };

    // GUAMI (mandatory): the AMF's first served GUAMI.
    let served = ctx.served_guami.first()?;

    let reject = ngap_gen::Criticality(ngap_gen::Criticality::REJECT);
    let entry = |id: u16, criticality: &ngap_gen::Criticality, value: Ie| Entry {
        id: ProtocolIE_ID(id),
        criticality: criticality.clone(),
        value,
    };
    let mut ies = vec![
        entry(
            ngap_gen::ID_AMF_UE_NGAP_ID,
            &reject,
            Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(amf_ue_ngap_id)),
        ),
        entry(
            ngap_gen::ID_RAN_UE_NGAP_ID,
            &reject,
            Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(ran_ue_ngap_id)),
        ),
    ];
    // BitRate ::= INTEGER (0..4000000000000, ...) (§9.3.1.4). Since nextgsim
    // #235 the codec encodes a value past the root as an extension value --
    // valid ASN.1, but the extension marker is for later releases and none
    // defines a bit rate past 4 Tbit/s. Refuse it here, as before.
    if let Some((dl, ul)) = ue_ambr {
        if dl > MAX_BIT_RATE || ul > MAX_BIT_RATE {
            log::error!(
                "Failed to encode InitialContextSetupRequest: UE AMBR {dl}/{ul} past {MAX_BIT_RATE}"
            );
            return None;
        }
        ies.push(entry(
            ngap_gen::ID_UE_AGGREGATE_MAXIMUM_BIT_RATE,
            &reject,
            Ie::Id_UEAggregateMaximumBitRate(ngap_gen::UEAggregateMaximumBitRate {
                ue_aggregate_maximum_bit_rate_dl: ngap_gen::BitRate(dl),
                ue_aggregate_maximum_bit_rate_ul: ngap_gen::BitRate(ul),
                ie_extensions: None,
            }),
        ));
    }
    ies.push(entry(
        ngap_gen::ID_GUAMI,
        &reject,
        Ie::Id_GUAMI(ngap_gen::GUAMI {
            plmn_identity: ngap_gen::PLMNIdentity(encode_plmn_id(&served.plmn_id).to_vec()),
            amf_region_id: ngap_gen::AMFRegionID(low_bits(u64::from(served.amf_id.region), 8)),
            amf_set_id: ngap_gen::AMFSetID(low_bits(u64::from(served.amf_id.set), 10)),
            amf_pointer: ngap_gen::AMFPointer(low_bits(u64::from(served.amf_id.pointer), 6)),
            ie_extensions: None,
        }),
    ));
    // PDUSessionResourceSetupListCxtReq (id 71, reject): object-set position
    // right after the GUAMI (InitialContextSetupRequestIEs, TS 38.413 §9.4.4).
    if !sessions.is_empty() {
        let items = sessions
            .iter()
            .map(|s| ngap_gen::PDUSessionResourceSetupItemCxtReq {
                pdu_session_id: ngap_gen::PDUSessionID(s.pdu_session_id),
                nas_pdu: None,
                s_nssai: generated_s_nssai(&s.s_nssai),
                pdu_session_resource_setup_request_transfer:
                    ngap_gen::PDUSessionResourceSetupItemCxtReqPDUSessionResourceSetupRequestTransfer(
                        s.transfer.clone(),
                    ),
                ie_extensions: None,
            })
            .collect();
        ies.push(entry(
            ngap_gen::ID_PDU_SESSION_RESOURCE_SETUP_LIST_CXT_REQ,
            &reject,
            Ie::Id_PDUSessionResourceSetupListCxtReq(ngap_gen::PDUSessionResourceSetupListCxtReq(
                items,
            )),
        ));
    }
    ies.push(entry(
        ngap_gen::ID_ALLOWED_NSSAI,
        &reject,
        Ie::Id_AllowedNSSAI(ngap_gen::AllowedNSSAI(
            allowed_nssai
                .iter()
                .map(|s| ngap_gen::AllowedNSSAI_Item {
                    s_nssai: generated_s_nssai(s),
                    ie_extensions: None,
                })
                .collect(),
        )),
    ));
    // Replayed UE security capabilities (TS 38.413 §9.3.1.86). 5G fields carry
    // the NAS algorithm octets; E-UTRA fields carry the EEA/EIA octets.
    let algorithms = |octet: u8| low_bits(u64::from(nas_caps_octet_to_ngap_bits(octet)), 16);
    ies.push(entry(
        ngap_gen::ID_UE_SECURITY_CAPABILITIES,
        &reject,
        Ie::Id_UESecurityCapabilities(ngap_gen::UESecurityCapabilities {
            n_rencryption_algorithms: ngap_gen::NRencryptionAlgorithms(algorithms(
                ue_security_capability.ea,
            )),
            n_rintegrity_protection_algorithms: ngap_gen::NRintegrityProtectionAlgorithms(
                algorithms(ue_security_capability.ia),
            ),
            eutr_aencryption_algorithms: ngap_gen::EUTRAencryptionAlgorithms(algorithms(
                ue_security_capability.eea,
            )),
            eutr_aintegrity_protection_algorithms: ngap_gen::EUTRAintegrityProtectionAlgorithms(
                algorithms(ue_security_capability.eia),
            ),
            ie_extensions: None,
        }),
    ));
    ies.push(entry(
        ngap_gen::ID_SECURITY_KEY,
        &reject,
        Ie::Id_SecurityKey(ngap_gen::SecurityKey(bitvec::vec::BitVec::<
            u8,
            bitvec::order::Msb0,
        >::from_slice(security_key))),
    ));
    if let Some(nas_pdu) = nas_pdu {
        ies.push(entry(
            ngap_gen::ID_NAS_PDU,
            &ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
            Ie::Id_NAS_PDU(ngap_gen::NAS_PDU(nas_pdu.to_vec())),
        ));
    }

    let pdu = NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_INITIAL_CONTEXT_SETUP),
        criticality: reject,
        value: ngap_gen::InitiatingMessageValue::Id_InitialContextSetup(
            InitialContextSetupRequest {
                protocol_i_es: InitialContextSetupRequestProtocolIEs(ies),
            },
        ),
    });
    // Never log the PDU or the IE values: the Security Key is in it.
    match nextgcore_ngap_gen::encode(&pdu) {
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
        Err(_) => {
            // The error's Debug form names the failing field and may carry its
            // value; the Security Key must not reach a log.
            log::error!(
                "Failed to encode Initial Context Setup Request for amf_ue_ngap_id={amf_ue_ngap_id}"
            );
            None
        }
    }
}

/// One PDU session a HandoverRequest asks the target gNB to set up.
#[derive(Debug, Clone)]
pub struct HandoverRequestSession {
    /// PDU Session ID.
    pub pdu_session_id: u8,
    /// The S-NSSAI associated with the session's N2 SM information (TS 23.502
    /// §4.11.1.2.2.2 step 9 / NOTE 4).
    pub s_nssai: crate::context::SNssai,
    /// The SMF's `PDUSessionResourceSetupRequestTransfer`, carried opaquely as the
    /// `handoverRequestTransfer` (an OCTET STRING CONTAINING it, §9.3.4.1).
    pub transfer: Vec<u8>,
}

/// What an **EPS→5GS** HandoverRequest carries (TS 38.413 §9.2.3.4, TS 33.501 §8.4.2
/// step 4).
#[derive(Debug, Clone)]
pub struct EpsToFivegsHandoverRequest {
    /// AMF UE NGAP ID the target AMF allocated for the arriving UE.
    pub amf_ue_ngap_id: u64,
    /// UE-AMBR (downlink, uplink) in bps.
    pub ue_ambr_bps: (u64, u64),
    /// UE security capabilities as TS 24.501 §9.11.3.54 octets (5G-EA, 5G-IA, EEA, EIA).
    pub ue_security_capability: crate::context::UeSecurityCapability,
    /// The NH the gNB derives K_gNB from: the **temporary K_gNB**, with NCC = 0
    /// (§8.4.2 step 4: "the {NCC=0, NH=derived temporary K_(gNB)}").
    pub next_hop: [u8; 32],
    /// The S1 mode to N1 mode NAS transparent container value part, carried as `NASC`.
    pub nas_container: Vec<u8>,
    /// The PDU sessions to set up.
    pub sessions: Vec<HandoverRequestSession>,
    /// Allowed NSSAI.
    pub allowed_nssai: Vec<crate::context::SNssai>,
    /// The Source to Target transparent container the MME relayed from the source eNB.
    pub source_to_target_container: Vec<u8>,
}

/// The HANDOVER COMMAND for a 5GS→EPS handover the target MME accepted (TS 38.413 §9.2.3.2,
/// TS 23.502 §4.11.1.2.1 step 11), #476.
///
/// | IE | value | why |
/// |---|---|---|
/// | Handover Type | `fivegs-to-eps` | §9.3.1.22 |
/// | NAS Security Parameters from NG-RAN | the 8 LSB of the DL NAS COUNT used for K_ASME' | `C-iftoEPS`; TS 33.501 §8.3.2 step 7 — the value part of TS 24.501 §9.11.2.7, one Sequence number octet |
/// | Target to Source Transparent Container | the target eNB's, relayed verbatim | §9.3.1.21: a TS 36.413 structure the AMF does not decode |
///
/// No PDU Session Resource Handover List: it carries forwarding tunnels
/// (`HandoverCommandTransfer`), and this AMF requests no data forwarding toward EPS — the
/// IE is `optional`, and leaving it out is what tells the gNB nothing is forwarded.
pub fn build_fivegs_to_eps_handover_command_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    nas_count_lsb: u8,
    target_to_source_container: &[u8],
) -> Option<Vec<u8>> {
    use ngap_gen::{
        HandoverCommand, HandoverCommandProtocolIEs, HandoverCommandProtocolIEs_Entry as Entry,
        HandoverCommandProtocolIEs_EntryValue as Ie, ProtocolIE_ID, NGAP_PDU,
    };
    let reject = ngap_gen::Criticality(ngap_gen::Criticality::REJECT);
    let entry = |id: u16, value: Ie| Entry {
        id: ProtocolIE_ID(id),
        criticality: reject.clone(),
        value,
    };
    let ies = vec![
        entry(
            ngap_gen::ID_AMF_UE_NGAP_ID,
            Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(amf_ue_ngap_id)),
        ),
        entry(
            ngap_gen::ID_RAN_UE_NGAP_ID,
            Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(ran_ue_ngap_id)),
        ),
        entry(
            ngap_gen::ID_HANDOVER_TYPE,
            Ie::Id_HandoverType(ngap_gen::HandoverType(
                ngap_gen::HandoverType::FIVEGS_TO_EPS,
            )),
        ),
        entry(
            ngap_gen::ID_NAS_SECURITY_PARAMETERS_FROM_NGRAN,
            Ie::Id_NASSecurityParametersFromNGRAN(ngap_gen::NASSecurityParametersFromNGRAN(vec![
                nas_count_lsb,
            ])),
        ),
        entry(
            ngap_gen::ID_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER,
            Ie::Id_TargetToSource_TransparentContainer(
                ngap_gen::TargetToSource_TransparentContainer(target_to_source_container.to_vec()),
            ),
        ),
    ];
    let pdu = NGAP_PDU::SuccessfulOutcome(ngap_gen::SuccessfulOutcome {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_HANDOVER_PREPARATION),
        criticality: reject.clone(),
        value: ngap_gen::SuccessfulOutcomeValue::Id_HandoverPreparation(HandoverCommand {
            protocol_i_es: HandoverCommandProtocolIEs(ies),
        }),
    });
    match nextgcore_ngap_gen::encode(&pdu) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            log::error!("Failed to encode the 5GS→EPS HandoverCommand: {e:?}");
            None
        }
    }
}

/// Build an **EPS→5GS HandoverRequest** (TS 38.413 §8.4.2 / §9.2.3.4) with the GENERATED
/// codec (#418).
///
/// The IEs go in object-set order with the object set's criticalities
/// (`HandoverRequestIEs`, §9.4.1). Against TS 33.501 §8.4.2 step 4, which fixes what an
/// EPS→5GS one must carry beyond an intra-5GS HandoverRequest:
///
/// | IE | value | why |
/// |---|---|---|
/// | Handover Type | `eps-to-5gs` | §9.3.1.22 |
/// | Security Context | NCC = **0**, NH = the temporary K_gNB | step 4: "{NCC=0, NH=derived temporary K_(gNB)}" |
/// | New Security Context Indicator | `true` | step 4: "the New Security Context Indicator (NSCI)" — the gNB then sets keySetChangeIndicator |
/// | NASC | the S1 mode to N1 mode NAS transparent container | step 4: "The target AMF sends the NAS Container created in step 3" |
///
/// The Cause is `handover-desirable-for-radio-reason`: the source eNB's S1AP cause reaches
/// the MME, not this AMF, and that NGAP value is the generic reason a handover was started.
///
/// Built here rather than by `nextgcore-ngap`'s hand-written `build_handover_request`, which
/// has no NASC or NSCI members: #417's direction is that new NGAP paths use the generated
/// codec, and adding two fields to a hand-written encoder #417 is retiring would be the
/// wrong direction. Never logs the PDU: the Security Context carries key material.
pub fn build_eps_to_5gs_handover_request_asn1(
    ctx: &AmfContext,
    request: &EpsToFivegsHandoverRequest,
) -> Option<Vec<u8>> {
    use ngap_gen::{
        HandoverRequest, HandoverRequestProtocolIEs, HandoverRequestProtocolIEs_Entry as Entry,
        HandoverRequestProtocolIEs_EntryValue as Ie, ProtocolIE_ID, NGAP_PDU,
    };
    let served = ctx.served_guami.first()?;
    let reject = ngap_gen::Criticality(ngap_gen::Criticality::REJECT);
    let ignore = ngap_gen::Criticality(ngap_gen::Criticality::IGNORE);
    let entry = |id: u16, criticality: &ngap_gen::Criticality, value: Ie| Entry {
        id: ProtocolIE_ID(id),
        criticality: criticality.clone(),
        value,
    };
    let algorithms = |octet: u8| low_bits(u64::from(nas_caps_octet_to_ngap_bits(octet)), 16);
    let caps = &request.ue_security_capability;
    let sessions: Vec<ngap_gen::PDUSessionResourceSetupItemHOReq> = request
        .sessions
        .iter()
        .map(|sess| ngap_gen::PDUSessionResourceSetupItemHOReq {
            pdu_session_id: ngap_gen::PDUSessionID(sess.pdu_session_id),
            s_nssai: generated_s_nssai(&sess.s_nssai),
            handover_request_transfer:
                ngap_gen::PDUSessionResourceSetupItemHOReqHandoverRequestTransfer(
                    sess.transfer.clone(),
                ),
            ie_extensions: None,
        })
        .collect();
    let ies = vec![
        entry(
            ngap_gen::ID_AMF_UE_NGAP_ID,
            &reject,
            Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(request.amf_ue_ngap_id)),
        ),
        entry(
            ngap_gen::ID_HANDOVER_TYPE,
            &reject,
            Ie::Id_HandoverType(ngap_gen::HandoverType(ngap_gen::HandoverType::EPS_TO_5GS)),
        ),
        entry(
            ngap_gen::ID_CAUSE,
            &ignore,
            Ie::Id_Cause(generated_cause(Cause::RadioNetwork(
                CauseRadioNetwork::HandoverDesirableForRadioReason,
            ))),
        ),
        entry(
            ngap_gen::ID_UE_AGGREGATE_MAXIMUM_BIT_RATE,
            &reject,
            // Derived from the EPS APN-AMBRs, whose sum can pass what §9.3.1.4
            // defines; clamp rather than refuse the handover, and never let
            // the codec emit an undefined extension value (nextgsim #235).
            Ie::Id_UEAggregateMaximumBitRate(ngap_gen::UEAggregateMaximumBitRate {
                ue_aggregate_maximum_bit_rate_dl: ngap_gen::BitRate(
                    request.ue_ambr_bps.0.min(MAX_BIT_RATE),
                ),
                ue_aggregate_maximum_bit_rate_ul: ngap_gen::BitRate(
                    request.ue_ambr_bps.1.min(MAX_BIT_RATE),
                ),
                ie_extensions: None,
            }),
        ),
        entry(
            ngap_gen::ID_UE_SECURITY_CAPABILITIES,
            &reject,
            Ie::Id_UESecurityCapabilities(ngap_gen::UESecurityCapabilities {
                n_rencryption_algorithms: ngap_gen::NRencryptionAlgorithms(algorithms(caps.ea)),
                n_rintegrity_protection_algorithms: ngap_gen::NRintegrityProtectionAlgorithms(
                    algorithms(caps.ia),
                ),
                eutr_aencryption_algorithms: ngap_gen::EUTRAencryptionAlgorithms(algorithms(
                    caps.eea,
                )),
                eutr_aintegrity_protection_algorithms: ngap_gen::EUTRAintegrityProtectionAlgorithms(
                    algorithms(caps.eia),
                ),
                ie_extensions: None,
            }),
        ),
        entry(
            ngap_gen::ID_SECURITY_CONTEXT,
            &reject,
            Ie::Id_SecurityContext(ngap_gen::SecurityContext {
                next_hop_chaining_count: ngap_gen::NextHopChainingCount(0),
                next_hop_nh: ngap_gen::SecurityKey(
                    bitvec::vec::BitVec::<u8, bitvec::order::Msb0>::from_slice(&request.next_hop),
                ),
                ie_extensions: None,
            }),
        ),
        entry(
            ngap_gen::ID_NEW_SECURITY_CONTEXT_IND,
            &reject,
            Ie::Id_NewSecurityContextInd(ngap_gen::NewSecurityContextInd(
                ngap_gen::NewSecurityContextInd::TRUE,
            )),
        ),
        entry(
            ngap_gen::ID_NASC,
            &reject,
            Ie::Id_NASC(ngap_gen::NAS_PDU(request.nas_container.clone())),
        ),
        entry(
            ngap_gen::ID_PDU_SESSION_RESOURCE_SETUP_LIST_HO_REQ,
            &reject,
            Ie::Id_PDUSessionResourceSetupListHOReq(ngap_gen::PDUSessionResourceSetupListHOReq(
                sessions,
            )),
        ),
        entry(
            ngap_gen::ID_ALLOWED_NSSAI,
            &reject,
            Ie::Id_AllowedNSSAI(ngap_gen::AllowedNSSAI(
                request
                    .allowed_nssai
                    .iter()
                    .map(|s| ngap_gen::AllowedNSSAI_Item {
                        s_nssai: generated_s_nssai(s),
                        ie_extensions: None,
                    })
                    .collect(),
            )),
        ),
        entry(
            ngap_gen::ID_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER,
            &reject,
            Ie::Id_SourceToTarget_TransparentContainer(
                ngap_gen::SourceToTarget_TransparentContainer(
                    request.source_to_target_container.clone(),
                ),
            ),
        ),
        entry(
            ngap_gen::ID_GUAMI,
            &reject,
            Ie::Id_GUAMI(ngap_gen::GUAMI {
                plmn_identity: ngap_gen::PLMNIdentity(encode_plmn_id(&served.plmn_id).to_vec()),
                amf_region_id: ngap_gen::AMFRegionID(low_bits(u64::from(served.amf_id.region), 8)),
                amf_set_id: ngap_gen::AMFSetID(low_bits(u64::from(served.amf_id.set), 10)),
                amf_pointer: ngap_gen::AMFPointer(low_bits(u64::from(served.amf_id.pointer), 6)),
                ie_extensions: None,
            }),
        ),
    ];
    let pdu = NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_HANDOVER_RESOURCE_ALLOCATION),
        criticality: reject,
        value: ngap_gen::InitiatingMessageValue::Id_HandoverResourceAllocation(HandoverRequest {
            protocol_i_es: HandoverRequestProtocolIEs(ies),
        }),
    });
    match nextgcore_ngap_gen::encode(&pdu) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            // The error's Debug form may name a failing value; the NH must not reach a log.
            log::error!(
                "Failed to encode the EPS→5GS HandoverRequest for amf_ue_ngap_id={}",
                request.amf_ue_ngap_id
            );
            None
        }
    }
}

/// What an Initial Context Setup Response or Failure decodes to (TS 38.413
/// §10.3.4.2 / §10.3.5 for a RESPONSE message; every IE in both carries
/// criticality ignore).
#[derive(Debug, Clone, PartialEq)]
pub enum InitialContextSetupOutcomeDecode {
    /// Decoded. The IDs are `None` when the gNB left them out: they are
    /// criticality ignore, so their absence does not fail the message (§10.3.5),
    /// and the handler decides what it can do without them.
    Decoded {
        /// The AMF UE NGAP ID the gNB names.
        amf_ue_ngap_id: Option<u64>,
        /// The RAN UE NGAP ID the gNB names.
        ran_ue_ngap_id: Option<u32>,
        /// The Failure's Cause as `(group, value)`; `None` for a Response, or a
        /// Failure that left it out.
        cause: Option<(u8, i64)>,
        /// The Error Indication reporting not-comprehended IEs marked "ignore IE
        /// and notify sender", if any (§10.3.4.2).
        error_indication: Option<CriticalityErrorIndication>,
        /// The Response's PDU Session Resource Setup List: each session's ID and
        /// its PDUSessionResourceSetupResponseTransfer, which the SMF needs to
        /// point the downlink at the gNB (#540). Empty for a Failure.
        setup_sessions: Vec<(u8, Vec<u8>)>,
    },
    /// A not-comprehended IE was marked "reject": the procedure is
    /// "unsuccessfully terminated" and handled locally (§10.3.4.2), with no
    /// message to the gNB. The IEs are for the log.
    Failed(Vec<IeDiagnostic>),
    /// Not decodable, or not the expected message.
    Undecodable,
}

/// Decode an Initial Context Setup Response (gNB -> AMF, TS 38.413 §9.2.2.2)
/// with the GENERATED codec (#417 stage 7), applying §10.3.4.2 for a response.
///
/// The hand-written parser this replaced refused the message on a missing ID
/// and on a not-comprehended IE marked reject, and accepted one marked "ignore
/// IE and notify sender" without reporting it. Every message it accepted
/// decodes to the same IDs:
/// `initial_context_setup_response_generated_decode_matches_hand_written`.
pub fn decode_initial_context_setup_response_asn1(data: &[u8]) -> InitialContextSetupOutcomeDecode {
    use ngap_gen::{
        InitialContextSetupResponseProtocolIEs_EntryValue as Ie, SuccessfulOutcomeValue,
    };
    use InitialContextSetupOutcomeDecode::{Decoded, Failed, Undecodable};

    let (pdu, unknown) = match nextgcore_ngap_gen::decode_with_unknown_ies(data) {
        Ok(decoded) => decoded,
        Err(e) => {
            log::warn!("Failed to decode Initial Context Setup Response: {e:?}");
            return Undecodable;
        }
    };
    let ngap_gen::NGAP_PDU::SuccessfulOutcome(ngap_gen::SuccessfulOutcome {
        criticality,
        value: SuccessfulOutcomeValue::Id_InitialContextSetup(response),
        ..
    }) = pdu
    else {
        log::warn!("Expected InitialContextSetupResponse");
        return Undecodable;
    };
    let Some((reject, notify)) = classify_unknown_ies(&unknown, "Initial Context Setup Response")
    else {
        return Undecodable;
    };
    if !reject.is_empty() {
        return Failed(reject);
    }

    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut setup_sessions = Vec::new();
    for entry in response.protocol_i_es.0 {
        match entry.value {
            Ie::Id_AMF_UE_NGAP_ID(v) => amf_ue_ngap_id = Some(v.0),
            Ie::Id_RAN_UE_NGAP_ID(v) => ran_ue_ngap_id = Some(v.0),
            // Comprehended, and not used: the AMF's request carries no PDU
            // Session Resource Setup List, so these lists answer nothing.
            Ie::Id_PDUSessionResourceSetupListCxtRes(list) => {
                setup_sessions = list
                    .0
                    .into_iter()
                    .map(|item| {
                        (
                            item.pdu_session_id.0,
                            item.pdu_session_resource_setup_response_transfer.0,
                        )
                    })
                    .collect();
            }
            Ie::Id_PDUSessionResourceFailedToSetupListCxtRes(_)
            | Ie::Id_CriticalityDiagnostics(_) => {}
        }
    }
    Decoded {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        cause: None,
        setup_sessions,
        error_indication: ics_error_indication(
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            ngap_gen::TriggeringMessage::SUCCESSFUL_OUTCOME,
            criticality.0,
            notify,
        ),
    }
}

/// Decode an Initial Context Setup Failure (gNB -> AMF, TS 38.413 §9.2.2.3)
/// with the GENERATED codec (#417 stage 7), applying §10.3.4.2 for a response
/// (an unsuccessful outcome is a response message too).
///
/// As for the Response: the hand-written parser refused a missing ID or a
/// not-comprehended IE marked reject, accepted a notify one without reporting
/// it, and every message it accepted decodes to the same IDs and Cause:
/// `initial_context_setup_failure_generated_decode_matches_hand_written`.
pub fn decode_initial_context_setup_failure_asn1(data: &[u8]) -> InitialContextSetupOutcomeDecode {
    use ngap_gen::{
        InitialContextSetupFailureProtocolIEs_EntryValue as Ie, UnsuccessfulOutcomeValue,
    };
    use InitialContextSetupOutcomeDecode::{Decoded, Failed, Undecodable};

    let (pdu, unknown) = match nextgcore_ngap_gen::decode_with_unknown_ies(data) {
        Ok(decoded) => decoded,
        Err(e) => {
            log::warn!("Failed to decode Initial Context Setup Failure: {e:?}");
            return Undecodable;
        }
    };
    let ngap_gen::NGAP_PDU::UnsuccessfulOutcome(ngap_gen::UnsuccessfulOutcome {
        criticality,
        value: UnsuccessfulOutcomeValue::Id_InitialContextSetup(failure),
        ..
    }) = pdu
    else {
        log::warn!("Expected InitialContextSetupFailure");
        return Undecodable;
    };
    let Some((reject, notify)) = classify_unknown_ies(&unknown, "Initial Context Setup Failure")
    else {
        return Undecodable;
    };
    if !reject.is_empty() {
        return Failed(reject);
    }

    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut cause = None;
    for entry in failure.protocol_i_es.0 {
        match entry.value {
            Ie::Id_AMF_UE_NGAP_ID(v) => amf_ue_ngap_id = Some(v.0),
            Ie::Id_RAN_UE_NGAP_ID(v) => ran_ue_ngap_id = Some(v.0),
            Ie::Id_Cause(c) => cause = cause_pair(&c),
            // Comprehended, and not used (no PDU Session Resource Setup List
            // was requested).
            Ie::Id_PDUSessionResourceFailedToSetupListCxtFail(_)
            | Ie::Id_CriticalityDiagnostics(_) => {}
        }
    }
    Decoded {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        cause,
        setup_sessions: Vec::new(),
        error_indication: ics_error_indication(
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            ngap_gen::TriggeringMessage::UNSUCCESSFUL_OUTCOME,
            criticality.0,
            notify,
        ),
    }
}

/// The Error Indication reporting an Initial Context Setup response's "ignore
/// IE and notify sender" IEs (§10.3.4.2), or `None` when there are none.
fn ics_error_indication(
    amf_ue_ngap_id: Option<u64>,
    ran_ue_ngap_id: Option<u32>,
    triggering_message: u8,
    procedure_criticality: u8,
    notify: Vec<IeDiagnostic>,
) -> Option<CriticalityErrorIndication> {
    if notify.is_empty() {
        return None;
    }
    Some(CriticalityErrorIndication {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        cause_protocol: ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
        procedure: ReportedProcedure {
            procedure_code: ngap_gen::ID_INITIAL_CONTEXT_SETUP,
            triggering_message,
            procedure_criticality,
        },
        diagnostics: notify,
    })
}

/// The `PDUSessionResourceReleaseCommandTransfer` (TS 38.413 §9.3.4.12) the
/// AMF sends for every session it releases: just the Cause, as the contents of
/// the item's `OCTET STRING (CONTAINING ...)`.
///
/// #417 stage 5: encoded by the generated codec through
/// [`nextgcore_ngap_gen::encode_contained`], the helper the Setup and Modify
/// transfers will go through as well.
fn release_command_transfer(cause: Cause) -> Option<Vec<u8>> {
    let transfer = ngap_gen::PDUSessionResourceReleaseCommandTransfer {
        cause: generated_cause(cause),
        ie_extensions: None,
    };
    match nextgcore_ngap_gen::encode_contained(&transfer) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            log::error!("Failed to encode PDUSessionResourceReleaseCommandTransfer: {e:?}");
            None
        }
    }
}

/// Build a PDU Session Resource Release Command with proper ASN.1 APER encoding
///
/// Sent by AMF to gNB to release PDU session resources.
///
/// #417 stage 5: encoded by the generated codec, every session's transfer
/// carrying Cause nas/normal-release as before. The bytes are unchanged --
/// `pdu_session_resource_release_command_generated_matches_hand_written` pins
/// that -- and an empty or over-long session list (SIZE(1..256)) is refused,
/// as the hand-written encoder refused it.
pub fn build_pdu_session_resource_release_command_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    pdu_session_ids: &[u8],
) -> Option<Vec<u8>> {
    use ngap_gen::{
        PDUSessionResourceReleaseCommand, PDUSessionResourceReleaseCommandProtocolIEs,
        PDUSessionResourceReleaseCommandProtocolIEs_Entry as Entry,
        PDUSessionResourceReleaseCommandProtocolIEs_EntryValue as Ie,
        PDUSessionResourceToReleaseItemRelCmd,
        PDUSessionResourceToReleaseItemRelCmdPDUSessionResourceReleaseCommandTransfer as Transfer,
        ProtocolIE_ID, NGAP_PDU,
    };

    let transfer = release_command_transfer(Cause::Nas(CauseNas::NormalRelease))?;
    let items = pdu_session_ids
        .iter()
        .map(|&psi| PDUSessionResourceToReleaseItemRelCmd {
            pdu_session_id: ngap_gen::PDUSessionID(psi),
            pdu_session_resource_release_command_transfer: Transfer(transfer.clone()),
            ie_extensions: None,
        })
        .collect();

    let reject = ngap_gen::Criticality(ngap_gen::Criticality::REJECT);
    // IE order and criticalities as TS 38.413 §9.2.1.3 lists them; the AMF
    // sends neither the RAN Paging Priority nor a NAS-PDU here.
    let ies = vec![
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_AMF_UE_NGAP_ID),
            criticality: reject.clone(),
            value: Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(amf_ue_ngap_id)),
        },
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_RAN_UE_NGAP_ID),
            criticality: reject.clone(),
            value: Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(ran_ue_ngap_id)),
        },
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_PDU_SESSION_RESOURCE_TO_RELEASE_LIST_REL_CMD),
            criticality: reject.clone(),
            value: Ie::Id_PDUSessionResourceToReleaseListRelCmd(
                ngap_gen::PDUSessionResourceToReleaseListRelCmd(items),
            ),
        },
    ];
    let pdu = NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_PDU_SESSION_RESOURCE_RELEASE),
        criticality: reject,
        value: ngap_gen::InitiatingMessageValue::Id_PDUSessionResourceRelease(
            PDUSessionResourceReleaseCommand {
                protocol_i_es: PDUSessionResourceReleaseCommandProtocolIEs(ies),
            },
        ),
    });

    match nextgcore_ngap_gen::encode(&pdu) {
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

/// One session a PDU Session Resource Release Response reports released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasedPduSession {
    /// The PDU Session ID.
    pub pdu_session_id: u8,
    /// The `PDUSessionResourceReleaseResponseTransfer` octets, exactly as
    /// received: the AMF relays N2 SM information to the SMF opaquely
    /// (TS 23.502) and never re-encodes it.
    pub transfer: Vec<u8>,
}

/// How a received PDU Session Resource Release Response is to be handled.
#[derive(Debug)]
pub enum PduSessionResourceReleaseResponseDecode {
    /// Decoded. Every IE of the response is mandatory or optional with
    /// criticality ignore (§9.2.1.4), so a missing one is ignored (§10.3.5)
    /// and comes back `None` / empty. When `error_indication` is set, the
    /// response carried not-comprehended IEs marked "ignore IE and notify
    /// sender", which §10.3.4.2 reports in an Error Indication.
    Released {
        /// The AMF UE NGAP ID the gNB names.
        amf_ue_ngap_id: Option<u64>,
        /// The RAN UE NGAP ID the gNB names.
        ran_ue_ngap_id: Option<u32>,
        /// The sessions released, in the order received.
        released: Vec<ReleasedPduSession>,
        /// The Error Indication to send, if any.
        error_indication: Option<CriticalityErrorIndication>,
    },
    /// The response carried a not-comprehended IE marked "reject": the
    /// procedure is "unsuccessfully terminated" and handled locally
    /// (§10.3.4.2), with no message to the gNB. The IEs are for the log.
    Failed(Vec<IeDiagnostic>),
    /// Not decodable.
    Undecodable,
}

/// Decode a PDU Session Resource Release Response (gNB -> AMF, TS 38.413
/// §9.2.1.4) with the GENERATED codec (#417 stage 5), applying the §10.3.4.2
/// and §10.3.5 rules for a RESPONSE message.
///
/// The hand-written parser this replaced refused the message on a missing ID
/// and on any not-comprehended IE marked reject, and ignored one marked notify
/// without reporting it. Every response it accepted decodes to the same UE and
/// the same sessions and transfers:
/// `pdu_session_resource_release_response_generated_decode_matches_hand_written`.
///
/// A released item's `iE-Extensions` entries are not-comprehended IEs like any
/// other: the item's extension object set is empty in Rel-17, so every entry
/// is unknown, and since nextgsim #218 the codec skips it as an open type and
/// reports it with its criticality -- ignore drops it, notify reports it,
/// reject fails the procedure. (Before #218 such an entry decoded as zero bits
/// and the rest of the list was misread; the hand-written parser never read
/// the presence bit and misread it too.)
pub fn decode_pdu_session_resource_release_response_asn1(
    data: &[u8],
) -> PduSessionResourceReleaseResponseDecode {
    use ngap_gen::{
        PDUSessionResourceReleaseResponseProtocolIEs_EntryValue as Ie, SuccessfulOutcomeValue,
    };
    use PduSessionResourceReleaseResponseDecode::{Failed, Released, Undecodable};

    let (pdu, unknown) = match nextgcore_ngap_gen::decode_with_unknown_ies(data) {
        Ok(decoded) => decoded,
        Err(e) => {
            log::warn!("Failed to decode PDU Session Resource Release Response: {e:?}");
            return Undecodable;
        }
    };
    let ngap_gen::NGAP_PDU::SuccessfulOutcome(ngap_gen::SuccessfulOutcome {
        criticality,
        value: SuccessfulOutcomeValue::Id_PDUSessionResourceRelease(response),
        ..
    }) = pdu
    else {
        log::warn!("Expected PduSessionResourceReleaseResponse");
        return Undecodable;
    };
    let Some((reject, notify)) =
        classify_unknown_ies(&unknown, "PDU Session Resource Release Response")
    else {
        return Undecodable;
    };
    if !reject.is_empty() {
        return Failed(reject);
    }

    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut released = Vec::new();
    for entry in response.protocol_i_es.0 {
        match entry.value {
            Ie::Id_AMF_UE_NGAP_ID(v) => amf_ue_ngap_id = Some(v.0),
            Ie::Id_RAN_UE_NGAP_ID(v) => ran_ue_ngap_id = Some(v.0),
            Ie::Id_PDUSessionResourceReleasedListRelRes(list) => {
                for item in list.0 {
                    released.push(ReleasedPduSession {
                        pdu_session_id: item.pdu_session_id.0,
                        transfer: item.pdu_session_resource_release_response_transfer.0,
                    });
                }
            }
            // Comprehended, and not used by the AMF.
            Ie::Id_UserLocationInformation(_) | Ie::Id_CriticalityDiagnostics(_) => {}
        }
    }
    let error_indication = if notify.is_empty() {
        None
    } else {
        Some(CriticalityErrorIndication {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            cause_protocol: ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
            procedure: ReportedProcedure {
                procedure_code: ngap_gen::ID_PDU_SESSION_RESOURCE_RELEASE,
                triggering_message: ngap_gen::TriggeringMessage::SUCCESSFUL_OUTCOME,
                procedure_criticality: criticality.0,
            },
            diagnostics: notify,
        })
    };
    Released {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        released,
        error_indication,
    }
}

/// One session a PDU Session Resource Setup Response reports set up, or
/// failed to set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupResponsePduSession {
    /// The PDU Session ID.
    pub pdu_session_id: u8,
    /// The `PDUSessionResourceSetupResponseTransfer` (set up) or
    /// `PDUSessionResourceSetupUnsuccessfulTransfer` (failed) octets, exactly as
    /// received: the AMF relays N2 SM information to the SMF opaquely
    /// (TS 23.502) and never re-encodes it.
    pub transfer: Vec<u8>,
}

/// How a received PDU Session Resource Setup Response is to be handled.
#[derive(Debug)]
pub enum PduSessionResourceSetupResponseDecode {
    /// Decoded. Every IE of the response has criticality ignore (§9.2.1.2), so
    /// a missing one is ignored (§10.3.5) and comes back `None` / empty. When
    /// `error_indication` is set, the response carried not-comprehended IEs
    /// marked "ignore IE and notify sender", which §10.3.4.2 reports in an
    /// Error Indication.
    Decoded {
        /// The AMF UE NGAP ID the gNB names.
        amf_ue_ngap_id: Option<u64>,
        /// The RAN UE NGAP ID the gNB names.
        ran_ue_ngap_id: Option<u32>,
        /// The sessions set up, in the order received.
        setup: Vec<SetupResponsePduSession>,
        /// The sessions that failed to set up, in the order received.
        failed: Vec<SetupResponsePduSession>,
        /// The Error Indication to send, if any.
        error_indication: Option<CriticalityErrorIndication>,
    },
    /// The response carried a not-comprehended IE marked "reject": the
    /// procedure is "unsuccessfully terminated" and handled locally
    /// (§10.3.4.2), with no message to the gNB. The IEs are for the log.
    Failed(Vec<IeDiagnostic>),
    /// Not decodable.
    Undecodable,
}

/// Decode a PDU Session Resource Setup Response (gNB -> AMF, TS 38.413
/// §9.2.1.2) with the GENERATED codec (#417 stage 6), applying the §10.3.4.2
/// and §10.3.5 rules for a RESPONSE message.
///
/// The hand-written parser this replaced refused the message on a missing ID
/// and on any not-comprehended IE marked reject, and ignored one marked notify
/// without reporting it. Every response it accepted decodes to the same UE and
/// the same sessions and transfers, in both lists:
/// `pdu_session_resource_setup_response_generated_decode_matches_hand_written`.
///
/// An item's `iE-Extensions` entries are handled as a released item's are
/// (stage 5): both extension object sets are empty in Rel-17, so every entry
/// is a not-comprehended IE, skipped and classified by its criticality since
/// nextgsim #218.
pub fn decode_pdu_session_resource_setup_response_asn1(
    data: &[u8],
) -> PduSessionResourceSetupResponseDecode {
    use ngap_gen::{
        PDUSessionResourceSetupResponseProtocolIEs_EntryValue as Ie, SuccessfulOutcomeValue,
    };
    use PduSessionResourceSetupResponseDecode::{Decoded, Failed, Undecodable};

    let (pdu, unknown) = match nextgcore_ngap_gen::decode_with_unknown_ies(data) {
        Ok(decoded) => decoded,
        Err(e) => {
            log::warn!("Failed to decode PDU Session Resource Setup Response: {e:?}");
            return Undecodable;
        }
    };
    let ngap_gen::NGAP_PDU::SuccessfulOutcome(ngap_gen::SuccessfulOutcome {
        criticality,
        value: SuccessfulOutcomeValue::Id_PDUSessionResourceSetup(response),
        ..
    }) = pdu
    else {
        log::warn!("Expected PduSessionResourceSetupResponse");
        return Undecodable;
    };
    let Some((reject, notify)) =
        classify_unknown_ies(&unknown, "PDU Session Resource Setup Response")
    else {
        return Undecodable;
    };
    if !reject.is_empty() {
        return Failed(reject);
    }

    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut setup = Vec::new();
    let mut failed = Vec::new();
    for entry in response.protocol_i_es.0 {
        match entry.value {
            Ie::Id_AMF_UE_NGAP_ID(v) => amf_ue_ngap_id = Some(v.0),
            Ie::Id_RAN_UE_NGAP_ID(v) => ran_ue_ngap_id = Some(v.0),
            Ie::Id_PDUSessionResourceSetupListSURes(list) => {
                for item in list.0 {
                    setup.push(SetupResponsePduSession {
                        pdu_session_id: item.pdu_session_id.0,
                        transfer: item.pdu_session_resource_setup_response_transfer.0,
                    });
                }
            }
            Ie::Id_PDUSessionResourceFailedToSetupListSURes(list) => {
                for item in list.0 {
                    failed.push(SetupResponsePduSession {
                        pdu_session_id: item.pdu_session_id.0,
                        transfer: item.pdu_session_resource_setup_unsuccessful_transfer.0,
                    });
                }
            }
            // Comprehended, and not used by the AMF.
            Ie::Id_UserLocationInformation(_) | Ie::Id_CriticalityDiagnostics(_) => {}
        }
    }
    let error_indication = if notify.is_empty() {
        None
    } else {
        Some(CriticalityErrorIndication {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            cause_protocol: ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
            procedure: ReportedProcedure {
                procedure_code: ngap_gen::ID_PDU_SESSION_RESOURCE_SETUP,
                triggering_message: ngap_gen::TriggeringMessage::SUCCESSFUL_OUTCOME,
                procedure_criticality: criticality.0,
            },
            diagnostics: notify,
        })
    };
    Decoded {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        setup,
        failed,
        error_indication,
    }
}

/// Build a PDU Session Resource Modify Request (AMF -> gNB, TS 38.413
/// §9.2.1.5) with the GENERATED codec (#417).
///
/// Sent to modify PDU session resources (e.g. a QoS change the SMF decided).
/// IE order and criticalities are the PDUSessionResourceModifyRequestIEs object
/// set's; the AMF sends no RAN Paging Priority. The bytes are the hand-written
/// encoder's: `pdu_session_resource_modify_request_generated_matches_hand_written`.
pub fn build_pdu_session_resource_modify_request_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    pdu_session_id: u8,
    nas_pdu: Option<&[u8]>,
    n2_sm_transfer: &[u8],
) -> Option<Vec<u8>> {
    use ngap_gen::{
        PDUSessionResourceModifyItemModReq,
        PDUSessionResourceModifyItemModReqPDUSessionResourceModifyRequestTransfer as Transfer,
        PDUSessionResourceModifyRequest, PDUSessionResourceModifyRequestProtocolIEs,
        PDUSessionResourceModifyRequestProtocolIEs_Entry as Entry,
        PDUSessionResourceModifyRequestProtocolIEs_EntryValue as Ie, ProtocolIE_ID, NGAP_PDU,
    };

    let reject = ngap_gen::Criticality(ngap_gen::Criticality::REJECT);
    let item = PDUSessionResourceModifyItemModReq {
        pdu_session_id: ngap_gen::PDUSessionID(pdu_session_id),
        nas_pdu: nas_pdu.map(|p| ngap_gen::NAS_PDU(p.to_vec())),
        pdu_session_resource_modify_request_transfer: Transfer(n2_sm_transfer.to_vec()),
        ie_extensions: None,
    };
    let ies = vec![
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_AMF_UE_NGAP_ID),
            criticality: reject.clone(),
            value: Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(amf_ue_ngap_id)),
        },
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_RAN_UE_NGAP_ID),
            criticality: reject.clone(),
            value: Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(ran_ue_ngap_id)),
        },
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_REQ),
            criticality: reject.clone(),
            value: Ie::Id_PDUSessionResourceModifyListModReq(
                ngap_gen::PDUSessionResourceModifyListModReq(vec![item]),
            ),
        },
    ];
    let pdu = NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_PDU_SESSION_RESOURCE_MODIFY),
        criticality: reject,
        value: ngap_gen::InitiatingMessageValue::Id_PDUSessionResourceModify(
            PDUSessionResourceModifyRequest {
                protocol_i_es: PDUSessionResourceModifyRequestProtocolIEs(ies),
            },
        ),
    });
    match nextgcore_ngap_gen::encode(&pdu) {
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

/// One PDU session of a Modify-family message, with its N2 SM transfer octets
/// exactly as received or as the SMF built them: the AMF relays N2 SM
/// information opaquely (TS 23.502) and never re-encodes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyPduSession {
    /// The PDU Session ID.
    pub pdu_session_id: u8,
    /// The transfer octets.
    pub transfer: Vec<u8>,
}

/// How a received PDU Session Resource Modify Response is to be handled.
#[derive(Debug)]
pub enum PduSessionResourceModifyResponseDecode {
    /// Decoded. Every IE of the response has criticality ignore (§9.2.1.6), so
    /// a missing one is ignored (§10.3.5). When `error_indication` is set, the
    /// response carried not-comprehended IEs marked "ignore IE and notify
    /// sender", reported in an Error Indication (§10.3.4.2).
    Decoded {
        /// The AMF UE NGAP ID the gNB names.
        amf_ue_ngap_id: Option<u64>,
        /// The RAN UE NGAP ID the gNB names.
        ran_ue_ngap_id: Option<u32>,
        /// Modified sessions with their PDUSessionResourceModifyResponseTransfer.
        modified: Vec<ModifyPduSession>,
        /// Sessions that failed to modify, with their
        /// PDUSessionResourceModifyUnsuccessfulTransfer.
        failed: Vec<ModifyPduSession>,
        /// The Error Indication to send, if any.
        error_indication: Option<CriticalityErrorIndication>,
    },
    /// A not-comprehended IE marked "reject": the procedure is unsuccessfully
    /// terminated and handled locally (§10.3.4.2), with no message to the gNB.
    Failed(Vec<IeDiagnostic>),
    /// Not decodable.
    Undecodable,
}

/// Decode a PDU Session Resource Modify Response (gNB -> AMF, TS 38.413
/// §9.2.1.6) with the GENERATED codec (#417), applying the §10.3.4.2 and
/// §10.3.5 rules for a RESPONSE message.
///
/// Every response the hand-written parser accepted decodes to the same UE and
/// sessions: `pdu_session_resource_modify_response_generated_decode_matches_hand_written`.
pub fn decode_pdu_session_resource_modify_response_asn1(
    data: &[u8],
) -> PduSessionResourceModifyResponseDecode {
    use ngap_gen::{
        PDUSessionResourceModifyResponseProtocolIEs_EntryValue as Ie, SuccessfulOutcomeValue,
    };
    use PduSessionResourceModifyResponseDecode::{Decoded, Failed, Undecodable};

    let (pdu, unknown) = match nextgcore_ngap_gen::decode_with_unknown_ies(data) {
        Ok(decoded) => decoded,
        Err(e) => {
            log::warn!("Failed to decode PDU Session Resource Modify Response: {e:?}");
            return Undecodable;
        }
    };
    let ngap_gen::NGAP_PDU::SuccessfulOutcome(ngap_gen::SuccessfulOutcome {
        criticality,
        value: SuccessfulOutcomeValue::Id_PDUSessionResourceModify(response),
        ..
    }) = pdu
    else {
        log::warn!("Expected PduSessionResourceModifyResponse");
        return Undecodable;
    };
    let Some((reject, notify)) =
        classify_unknown_ies(&unknown, "PDU Session Resource Modify Response")
    else {
        return Undecodable;
    };
    if !reject.is_empty() {
        return Failed(reject);
    }

    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut modified = Vec::new();
    let mut failed = Vec::new();
    for entry in response.protocol_i_es.0 {
        match entry.value {
            Ie::Id_AMF_UE_NGAP_ID(v) => amf_ue_ngap_id = Some(v.0),
            Ie::Id_RAN_UE_NGAP_ID(v) => ran_ue_ngap_id = Some(v.0),
            Ie::Id_PDUSessionResourceModifyListModRes(list) => {
                for item in list.0 {
                    modified.push(ModifyPduSession {
                        pdu_session_id: item.pdu_session_id.0,
                        transfer: item.pdu_session_resource_modify_response_transfer.0,
                    });
                }
            }
            Ie::Id_PDUSessionResourceFailedToModifyListModRes(list) => {
                for item in list.0 {
                    failed.push(ModifyPduSession {
                        pdu_session_id: item.pdu_session_id.0,
                        transfer: item.pdu_session_resource_modify_unsuccessful_transfer.0,
                    });
                }
            }
            // Comprehended, and not used by the AMF.
            Ie::Id_UserLocationInformation(_) | Ie::Id_CriticalityDiagnostics(_) => {}
        }
    }
    let error_indication = if notify.is_empty() {
        None
    } else {
        Some(CriticalityErrorIndication {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            cause_protocol: ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
            procedure: ReportedProcedure {
                procedure_code: ngap_gen::ID_PDU_SESSION_RESOURCE_MODIFY,
                triggering_message: ngap_gen::TriggeringMessage::SUCCESSFUL_OUTCOME,
                procedure_criticality: criticality.0,
            },
            diagnostics: notify,
        })
    };
    Decoded {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        modified,
        failed,
        error_indication,
    }
}

/// How a received PDU Session Resource Modify Indication is to be handled.
/// The procedure is class 1 (§8.2.4): its response is the PDU Session Resource
/// Modify Confirm, and it has no unsuccessful outcome.
#[derive(Debug)]
pub enum PduSessionResourceModifyIndicationDecode {
    /// Decoded; relay each session to the SMF and answer with a Modify Confirm.
    /// `notify` lists not-comprehended "ignore IE and notify sender" IEs, which
    /// §10.3.4.2 reports in the Criticality Diagnostics of the response.
    Proceed {
        /// The AMF UE NGAP ID.
        amf_ue_ngap_id: u64,
        /// The RAN UE NGAP ID.
        ran_ue_ngap_id: u32,
        /// The sessions with their PDUSessionResourceModifyIndicationTransfer.
        sessions: Vec<ModifyPduSession>,
        /// IEs to report in the Confirm's Criticality Diagnostics.
        notify: Vec<IeDiagnostic>,
    },
    /// A not-comprehended IE marked "reject", or a missing mandatory IE whose
    /// criticality is reject: the procedure is not executed. With no
    /// unsuccessful outcome to carry it, §10.3.4.2 reports it in an Error
    /// Indication.
    Reject(CriticalityErrorIndication),
    /// Not decodable.
    Undecodable,
}

/// Decode a PDU Session Resource Modify Indication (gNB -> AMF, TS 38.413
/// §9.2.1.7) with the GENERATED codec (#417), applying §10.3.4.2 and §10.3.5.
///
/// Every indication the hand-written parser accepted decodes to the same UE and
/// sessions: `pdu_session_resource_modify_indication_generated_decode_matches_hand_written`.
pub fn decode_pdu_session_resource_modify_indication_asn1(
    data: &[u8],
) -> PduSessionResourceModifyIndicationDecode {
    use ngap_gen::{
        InitiatingMessageValue, PDUSessionResourceModifyIndicationProtocolIEs_EntryValue as Ie,
    };
    use PduSessionResourceModifyIndicationDecode::{Proceed, Reject, Undecodable};

    let (pdu, unknown) = match nextgcore_ngap_gen::decode_with_unknown_ies(data) {
        Ok(decoded) => decoded,
        Err(e) => {
            log::warn!("Failed to decode PDU Session Resource Modify Indication: {e:?}");
            return Undecodable;
        }
    };
    let ngap_gen::NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        criticality,
        value: InitiatingMessageValue::Id_PDUSessionResourceModifyIndication(msg),
        ..
    }) = pdu
    else {
        log::warn!("Expected PduSessionResourceModifyIndication");
        return Undecodable;
    };
    let Some((mut reject, notify)) =
        classify_unknown_ies(&unknown, "PDU Session Resource Modify Indication")
    else {
        return Undecodable;
    };

    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut sessions = None;
    for entry in msg.protocol_i_es.0 {
        match entry.value {
            Ie::Id_AMF_UE_NGAP_ID(v) => amf_ue_ngap_id = Some(v.0),
            Ie::Id_RAN_UE_NGAP_ID(v) => ran_ue_ngap_id = Some(v.0),
            Ie::Id_PDUSessionResourceModifyListModInd(list) => {
                sessions = Some(
                    list.0
                        .into_iter()
                        .map(|item| ModifyPduSession {
                            pdu_session_id: item.pdu_session_id.0,
                            transfer: item.pdu_session_resource_modify_indication_transfer.0,
                        })
                        .collect::<Vec<_>>(),
                );
            }
            // Comprehended, and not used by the AMF.
            Ie::Id_UserLocationInformation(_) => {}
        }
    }
    // All three are mandatory with criticality reject (§9.2.1.7, §10.3.5).
    if amf_ue_ngap_id.is_none() {
        reject.push(missing_ie(ngap_gen::ID_AMF_UE_NGAP_ID));
    }
    if ran_ue_ngap_id.is_none() {
        reject.push(missing_ie(ngap_gen::ID_RAN_UE_NGAP_ID));
    }
    if sessions.is_none() {
        reject.push(missing_ie(
            ngap_gen::ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_IND,
        ));
    }
    let (Some(amf_ue_ngap_id), Some(ran_ue_ngap_id), Some(sessions), true) =
        (amf_ue_ngap_id, ran_ue_ngap_id, sessions, reject.is_empty())
    else {
        return Reject(CriticalityErrorIndication {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            cause_protocol: ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT,
            procedure: ReportedProcedure {
                procedure_code: ngap_gen::ID_PDU_SESSION_RESOURCE_MODIFY_INDICATION,
                triggering_message: ngap_gen::TriggeringMessage::INITIATING_MESSAGE,
                procedure_criticality: criticality.0,
            },
            diagnostics: reject,
        });
    };
    Proceed {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        sessions,
        notify,
    }
}

/// Build a PDU Session Resource Modify Confirm (AMF -> gNB, TS 38.413
/// §9.2.1.8) with the GENERATED codec: the response to a Modify Indication
/// (§8.2.4.2). `confirmed` carries the SMF's
/// PDUSessionResourceModifyConfirmTransfer per session, `failed` its
/// PDUSessionResourceModifyIndicationUnsuccessfulTransfer, and `notify` the
/// not-comprehended IEs §10.3.4.2 reports in the Criticality Diagnostics.
/// Every IE has criticality ignore (PDUSessionResourceModifyConfirmIEs); an
/// empty list is left out, as both lists are optional.
pub fn build_pdu_session_resource_modify_confirm_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    confirmed: &[ModifyPduSession],
    failed: &[ModifyPduSession],
    notify: &[IeDiagnostic],
) -> Option<Vec<u8>> {
    use ngap_gen::{
        PDUSessionResourceFailedToModifyItemModCfm,
        PDUSessionResourceFailedToModifyItemModCfmPDUSessionResourceModifyIndicationUnsuccessfulTransfer as FailedTransfer,
        PDUSessionResourceModifyConfirm, PDUSessionResourceModifyConfirmProtocolIEs,
        PDUSessionResourceModifyConfirmProtocolIEs_Entry as Entry,
        PDUSessionResourceModifyConfirmProtocolIEs_EntryValue as Ie,
        PDUSessionResourceModifyItemModCfm,
        PDUSessionResourceModifyItemModCfmPDUSessionResourceModifyConfirmTransfer as CfmTransfer,
        ProtocolIE_ID, NGAP_PDU,
    };

    let ignore = ngap_gen::Criticality(ngap_gen::Criticality::IGNORE);
    let mut ies = vec![
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_AMF_UE_NGAP_ID),
            criticality: ignore.clone(),
            value: Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(amf_ue_ngap_id)),
        },
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_RAN_UE_NGAP_ID),
            criticality: ignore.clone(),
            value: Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(ran_ue_ngap_id)),
        },
    ];
    if !confirmed.is_empty() {
        ies.push(Entry {
            id: ProtocolIE_ID(ngap_gen::ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_CFM),
            criticality: ignore.clone(),
            value: Ie::Id_PDUSessionResourceModifyListModCfm(
                ngap_gen::PDUSessionResourceModifyListModCfm(
                    confirmed
                        .iter()
                        .map(|s| PDUSessionResourceModifyItemModCfm {
                            pdu_session_id: ngap_gen::PDUSessionID(s.pdu_session_id),
                            pdu_session_resource_modify_confirm_transfer: CfmTransfer(
                                s.transfer.clone(),
                            ),
                            ie_extensions: None,
                        })
                        .collect(),
                ),
            ),
        });
    }
    if !failed.is_empty() {
        ies.push(Entry {
            id: ProtocolIE_ID(ngap_gen::ID_PDU_SESSION_RESOURCE_FAILED_TO_MODIFY_LIST_MOD_CFM),
            criticality: ignore.clone(),
            value: Ie::Id_PDUSessionResourceFailedToModifyListModCfm(
                ngap_gen::PDUSessionResourceFailedToModifyListModCfm(
                    failed
                        .iter()
                        .map(|s| PDUSessionResourceFailedToModifyItemModCfm {
                            pdu_session_id: ngap_gen::PDUSessionID(s.pdu_session_id),
                            pdu_session_resource_modify_indication_unsuccessful_transfer:
                                FailedTransfer(s.transfer.clone()),
                            ie_extensions: None,
                        })
                        .collect(),
                ),
            ),
        });
    }
    if !notify.is_empty() {
        ies.push(Entry {
            id: ProtocolIE_ID(ngap_gen::ID_CRITICALITY_DIAGNOSTICS),
            criticality: ignore,
            value: Ie::Id_CriticalityDiagnostics(generated_criticality_diagnostics(notify)),
        });
    }
    let pdu = NGAP_PDU::SuccessfulOutcome(ngap_gen::SuccessfulOutcome {
        procedure_code: ngap_gen::ProcedureCode(
            ngap_gen::ID_PDU_SESSION_RESOURCE_MODIFY_INDICATION,
        ),
        criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
        value: ngap_gen::SuccessfulOutcomeValue::Id_PDUSessionResourceModifyIndication(
            PDUSessionResourceModifyConfirm {
                protocol_i_es: PDUSessionResourceModifyConfirmProtocolIEs(ies),
            },
        ),
    });
    match nextgcore_ngap_gen::encode(&pdu) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            log::error!("Failed to encode PDU Session Resource Modify Confirm: {e:?}");
            None
        }
    }
}

/// A PDUSessionResourceModifyIndicationUnsuccessfulTransfer (§9.3.4.21) with
/// `cause`, for a session the SMF could not answer: the gNB is told the
/// modification failed rather than left without a Confirm entry.
pub fn modify_indication_unsuccessful_transfer(cause: Cause) -> Option<Vec<u8>> {
    let transfer = ngap_gen::PDUSessionResourceModifyIndicationUnsuccessfulTransfer {
        cause: generated_cause(cause),
        ie_extensions: None,
    };
    match nextgcore_ngap_gen::encode_contained(&transfer) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            log::error!(
                "Failed to encode PDUSessionResourceModifyIndicationUnsuccessfulTransfer: {e:?}"
            );
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
    /// User Location Information, MANDATORY on this message
    /// (TS 38.413 §9.2.5.3, `38413-j30.txt:14672-14673`: presence `M`).
    ///
    /// Kept rather than dropped because this is where the AMF learns that a UE
    /// which moved while in CM-IDLE is now somewhere else — TS 23.502 §4.2.3.2
    /// step 2 says the location *"relates to the cell in which the UE is
    /// camping"* (`23502-k20.txt:6155`), present tense. Before #406 this field
    /// did not exist, so `handle_service_request_nas`'s `LOCATION_REPORT`
    /// reported the TAI stored at registration, and #400's presence events
    /// declined to fire from that site at all for exactly that reason.
    ///
    /// Nothing extra is decoded off the wire for this: the NGAP parser already
    /// decodes the IE.
    ///
    /// `None` when the gNB omitted it -- it is mandatory with criticality
    /// ignore (TS 38.413 §9.2.5.3), so its absence is ignored (§10.3.5) and the
    /// NAS is still delivered -- or when it is not an NR location, which this
    /// AMF has no representation for. The hand-written parser refused the whole
    /// message in both cases, dropping the NAS PDU it carried.
    pub user_location_info: Option<UserLocationInformation>,
}

/// Parse an Uplink NAS Transport with the HAND-WRITTEN codec: the pre-#417
/// path, kept as the oracle `decode_uplink_nas_transport_asn1` is checked
/// against.
#[cfg(test)]
pub(crate) fn parse_uplink_nas_transport_asn1(data: &[u8]) -> Option<UplinkNasTransportData> {
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
        user_location_info: Some(msg.user_location_info),
    })
}

/// A generated NR [`ngap_gen::UserLocationInformation`] as the hand-written
/// one. `None` for an E-UTRA, N3IWF or choice-extension location, which this
/// AMF has no representation for, or for a field of the wrong size.
fn hand_written_user_location(
    uli: &ngap_gen::UserLocationInformation,
) -> Option<UserLocationInformation> {
    let ngap_gen::UserLocationInformation::UserLocationInformationNR(nr) = uli else {
        return None;
    };
    let nr_cgi_plmn: [u8; 3] = nr.nr_cgi.plmn_identity.0.as_slice().try_into().ok()?;
    let tai_plmn: [u8; 3] = nr.tai.plmn_identity.0.as_slice().try_into().ok()?;
    let tai_tac: [u8; 3] = nr.tai.tac.0.as_slice().try_into().ok()?;
    let bits = &nr.nr_cgi.nr_cell_identity.0;
    if bits.len() != 36 {
        return None;
    }
    let nr_cell_identity = bits.iter().fold(0u64, |acc, b| (acc << 1) | u64::from(*b));
    Some(UserLocationInformation::Nr {
        nr_cgi_plmn,
        nr_cell_identity,
        tai_plmn,
        tai_tac,
    })
}

/// How a received NAS transport message (Initial UE Message, Uplink NAS
/// Transport) is to be handled. Both are class 2 procedures with no response
/// message, so TS 38.413 §10.3.4.2 reports through an Error Indication.
#[derive(Debug)]
pub enum NasTransportDecode<T> {
    /// Decoded; deliver the NAS. When `error_indication` is set, the message
    /// carried not-comprehended IEs marked "ignore IE and notify sender",
    /// reported in an Error Indication while the procedure goes on.
    Proceed {
        /// The decoded message.
        message: T,
        /// The Error Indication to send, if any.
        error_indication: Option<CriticalityErrorIndication>,
    },
    /// A not-comprehended IE marked "reject", or a missing mandatory IE whose
    /// criticality is reject: none of the message is executed and the
    /// procedure is terminated with an Error Indication (§10.3.4.2, §10.3.5).
    Reject(CriticalityErrorIndication),
    /// Not decodable, or not something this AMF can act on.
    Undecodable,
}

fn missing_ie(ie_id: u16) -> IeDiagnostic {
    IeDiagnostic {
        ie_id,
        criticality: ngap_gen::Criticality::REJECT,
        type_of_error: ngap_gen::TypeOfError::MISSING,
    }
}

/// Decode an Initial UE Message (TS 38.413 §9.2.5.1) with the GENERATED codec
/// (#417), applying §10.3.4.2 and §10.3.5.
///
/// The hand-written parser this replaced comprehended only RAN UE NGAP ID,
/// NAS-PDU, User Location Information, RRC Establishment Cause, UE Context
/// Request and Allowed NSSAI. Every other IE of the message that is marked
/// "reject" -- 5G-S-TMSI, IAB Node Indication, CE-mode-B Support Indicator,
/// NPN Access Information -- it treated as not comprehended and refused the
/// whole message, dropping the UE's registration or service request without
/// telling the gNB. Those are comprehended here. Every message it accepted
/// decodes identically: `initial_ue_message_generated_decode_matches_hand_written`.
pub fn decode_initial_ue_message_asn1(data: &[u8]) -> NasTransportDecode<InitialUeMessageData> {
    use ngap_gen::{InitialUEMessageProtocolIEs_EntryValue as Ie, InitiatingMessageValue};
    use NasTransportDecode::{Proceed, Reject, Undecodable};

    let (pdu, unknown) = match nextgcore_ngap_gen::decode_with_unknown_ies(data) {
        Ok(decoded) => decoded,
        Err(e) => {
            log::error!("Failed to decode Initial UE Message: {e:?}");
            return Undecodable;
        }
    };
    let ngap_gen::NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        criticality,
        value: InitiatingMessageValue::Id_InitialUEMessage(msg),
        ..
    }) = pdu
    else {
        log::error!("Expected InitialUEMessage");
        return Undecodable;
    };
    let Some((mut reject, notify)) = classify_unknown_ies(&unknown, "Initial UE Message") else {
        return Undecodable;
    };

    let mut ran_ue_ngap_id = None;
    let mut nas_pdu = None;
    let mut uli = None;
    // Mandatory with criticality ignore: absent is ignored (§10.3.5), and the
    // hand-written parser defaulted it the same way.
    let mut rrc_establishment_cause = RrcEstablishmentCause::default() as u8;
    let mut ue_context_request = false;
    for entry in msg.protocol_i_es.0 {
        match entry.value {
            Ie::Id_RAN_UE_NGAP_ID(v) => ran_ue_ngap_id = Some(v.0),
            Ie::Id_NAS_PDU(v) => nas_pdu = Some(v.0),
            Ie::Id_UserLocationInformation(v) => uli = Some(v),
            // Carried as its wire value, extension values included: the
            // hand-written parser read mo-ExceptionData (11) as notAvailable.
            Ie::Id_RRCEstablishmentCause(v) => rrc_establishment_cause = v.0,
            Ie::Id_UEContextRequest(_) => ue_context_request = true,
            // Comprehended; the AMF takes the UE's identity and slices from
            // the NAS message it carries.
            _ => {}
        }
    }
    if ran_ue_ngap_id.is_none() {
        reject.push(missing_ie(ngap_gen::ID_RAN_UE_NGAP_ID));
    }
    if nas_pdu.is_none() {
        reject.push(missing_ie(ngap_gen::ID_NAS_PDU));
    }
    if uli.is_none() {
        reject.push(missing_ie(ngap_gen::ID_USER_LOCATION_INFORMATION));
    }
    let report = |cause_protocol: u8, diagnostics: Vec<IeDiagnostic>| CriticalityErrorIndication {
        amf_ue_ngap_id: None,
        ran_ue_ngap_id,
        cause_protocol,
        procedure: ReportedProcedure {
            procedure_code: ngap_gen::ID_INITIAL_UE_MESSAGE,
            triggering_message: ngap_gen::TriggeringMessage::INITIATING_MESSAGE,
            procedure_criticality: criticality.0,
        },
        diagnostics,
    };
    let (Some(ran_ue_ngap_id), Some(nas_pdu), Some(uli), true) =
        (ran_ue_ngap_id, nas_pdu, uli, reject.is_empty())
    else {
        return Reject(report(
            ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT,
            reject,
        ));
    };
    let Some(UserLocationInformation::Nr {
        nr_cgi_plmn,
        nr_cell_identity,
        tai_tac,
        ..
    }) = hand_written_user_location(&uli)
    else {
        log::error!("Initial UE Message: only an NR User Location Information is supported");
        return Undecodable;
    };
    let plmn_id = decode_plmn_id(&nr_cgi_plmn);
    let tac = (u32::from(tai_tac[0]) << 16) | (u32::from(tai_tac[1]) << 8) | u32::from(tai_tac[2]);
    log::info!(
        "Decoded Initial UE Message: ran_ue_ngap_id={ran_ue_ngap_id}, nas_pdu_len={}, nci=0x{nr_cell_identity:x}, tac={tac}, cause={rrc_establishment_cause}",
        nas_pdu.len()
    );
    let error_indication = (!notify.is_empty()).then(|| {
        report(
            ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
            notify,
        )
    });
    Proceed {
        message: InitialUeMessageData {
            ran_ue_ngap_id,
            nas_pdu,
            plmn_id,
            nr_cell_identity,
            tac,
            rrc_establishment_cause,
            ue_context_request,
        },
        error_indication,
    }
}

/// Decode an Uplink NAS Transport (TS 38.413 §9.2.5.3) with the GENERATED
/// codec (#417), applying §10.3.4.2 and §10.3.5.
///
/// The hand-written parser this replaced refused the message -- dropping the
/// NAS PDU -- when User Location Information was absent (it is mandatory with
/// criticality ignore, so its absence is to be ignored), when it was not an NR
/// location, and on the W-AGF / TNGF / TWIF Identity Information IEs, which it
/// did not comprehend and which carry criticality reject. Every message it
/// accepted decodes identically:
/// `uplink_nas_transport_generated_decode_matches_hand_written`.
pub fn decode_uplink_nas_transport_asn1(data: &[u8]) -> NasTransportDecode<UplinkNasTransportData> {
    use ngap_gen::{InitiatingMessageValue, UplinkNASTransportProtocolIEs_EntryValue as Ie};
    use NasTransportDecode::{Proceed, Reject, Undecodable};

    let (pdu, unknown) = match nextgcore_ngap_gen::decode_with_unknown_ies(data) {
        Ok(decoded) => decoded,
        Err(e) => {
            log::error!("Failed to decode Uplink NAS Transport: {e:?}");
            return Undecodable;
        }
    };
    let ngap_gen::NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        criticality,
        value: InitiatingMessageValue::Id_UplinkNASTransport(msg),
        ..
    }) = pdu
    else {
        log::error!("Expected UplinkNASTransport");
        return Undecodable;
    };
    let Some((mut reject, notify)) = classify_unknown_ies(&unknown, "Uplink NAS Transport") else {
        return Undecodable;
    };

    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut nas_pdu = None;
    let mut user_location_info = None;
    for entry in msg.protocol_i_es.0 {
        match entry.value {
            Ie::Id_AMF_UE_NGAP_ID(v) => amf_ue_ngap_id = Some(v.0),
            Ie::Id_RAN_UE_NGAP_ID(v) => ran_ue_ngap_id = Some(v.0),
            Ie::Id_NAS_PDU(v) => nas_pdu = Some(v.0),
            Ie::Id_UserLocationInformation(v) => {
                user_location_info = hand_written_user_location(&v);
                if user_location_info.is_none() {
                    log::warn!(
                        "Uplink NAS Transport: not an NR User Location Information; \
                         delivering the NAS without a location"
                    );
                }
            }
            // Comprehended: the non-3GPP interworking identities, which this
            // AMF (3GPP access only) has no use for.
            Ie::Id_W_AGFIdentityInformation(_)
            | Ie::Id_TNGFIdentityInformation(_)
            | Ie::Id_TWIFIdentityInformation(_) => {}
        }
    }
    if amf_ue_ngap_id.is_none() {
        reject.push(missing_ie(ngap_gen::ID_AMF_UE_NGAP_ID));
    }
    if ran_ue_ngap_id.is_none() {
        reject.push(missing_ie(ngap_gen::ID_RAN_UE_NGAP_ID));
    }
    if nas_pdu.is_none() {
        reject.push(missing_ie(ngap_gen::ID_NAS_PDU));
    }
    let report = |cause_protocol: u8, diagnostics: Vec<IeDiagnostic>| CriticalityErrorIndication {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        cause_protocol,
        procedure: ReportedProcedure {
            procedure_code: ngap_gen::ID_UPLINK_NAS_TRANSPORT,
            triggering_message: ngap_gen::TriggeringMessage::INITIATING_MESSAGE,
            procedure_criticality: criticality.0,
        },
        diagnostics,
    };
    let (Some(amf_ue_ngap_id), Some(ran_ue_ngap_id), Some(nas_pdu), true) =
        (amf_ue_ngap_id, ran_ue_ngap_id, nas_pdu, reject.is_empty())
    else {
        return Reject(report(
            ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT,
            reject,
        ));
    };
    log::info!(
        "Decoded Uplink NAS Transport: amf_ue_ngap_id={amf_ue_ngap_id}, ran_ue_ngap_id={ran_ue_ngap_id}, nas_pdu_len={}",
        nas_pdu.len()
    );
    let error_indication = (!notify.is_empty()).then(|| {
        report(
            ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
            notify,
        )
    });
    Proceed {
        message: UplinkNasTransportData {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            nas_pdu,
            user_location_info,
        },
        error_indication,
    }
}

/// Build a Paging message with proper ASN.1 APER encoding
///
/// Sent by AMF to gNBs to page a UE in CM-IDLE state.
/// The message follows 3GPP TS 38.413 Section 8.7.2.
///
/// #417 Paging stage: encoded by the codec GENERATED from the TS 38.413 ASN.1
/// ([`build_paging_generated`]), not the hand-written `nextgcore-ngap` builder.
/// The bytes are unchanged -- `paging_generated_matches_hand_written` pins that
/// against the hand-written encoder.
pub fn build_paging_asn1(
    amf_set_id: u16,
    amf_pointer: u8,
    tmsi: u32,
    plmn_id: &crate::context::PlmnId,
    tac: u32,
) -> Option<Vec<u8>> {
    let msg = Paging {
        ue_paging_identity: UePagingIdentity::FiveGSTmsi {
            amf_set_id,
            amf_pointer,
            tmsi,
        },
        tai_list: vec![TaiListItem {
            tai_plmn: encode_plmn_id(plmn_id),
            tai_tac: [(tac >> 16) as u8, (tac >> 8) as u8, tac as u8],
        }],
        paging_drx: None,
        paging_priority: None,
        ue_radio_capability: None,
        paging_origin: None,
        assistance_data: None,
    };
    let bytes = build_paging_generated(&msg)?;
    log::debug!(
        "Built Paging: {} bytes, amf_set_id={amf_set_id}, tmsi=0x{tmsi:08x}, tac={tac}",
        bytes.len()
    );
    Some(bytes)
}

/// A Paging PDU (TS 38.413 §9.2.4.1) built with the generated codec, from the
/// same [`Paging`] the hand-written builder takes.
///
/// IE order and criticalities are the `PagingIEs` object set's: every IE is
/// criticality ignore, and the procedure itself is ignore (§9.2.4.1).
///
/// `ue_radio_capability` and `assistance_data` are already APER-encoded
/// `UERadioCapabilityForPaging` / `AssistanceDataForPaging` SEQUENCE values,
/// as the hand-written builder takes them. They are decoded into their
/// generated types and re-encoded, so a value that is not a well-formed
/// encoding of its type is refused (`None`) here, where the hand-written
/// builder copied whatever bytes it was given onto the wire verbatim.
pub fn build_paging_generated(msg: &Paging) -> Option<Vec<u8>> {
    use ngap_gen::{
        PagingProtocolIEs, PagingProtocolIEs_Entry as Entry, PagingProtocolIEs_EntryValue as Ie,
        ProtocolIE_ID, NGAP_PDU,
    };

    let UePagingIdentity::FiveGSTmsi {
        amf_set_id,
        amf_pointer,
        tmsi,
    } = &msg.ue_paging_identity;
    let identity = ngap_gen::UEPagingIdentity::FiveG_S_TMSI(ngap_gen::FiveG_S_TMSI {
        amf_set_id: ngap_gen::AMFSetID(low_bits(u64::from(*amf_set_id), 10)),
        amf_pointer: ngap_gen::AMFPointer(low_bits(u64::from(*amf_pointer), 6)),
        five_g_tmsi: ngap_gen::FiveG_TMSI(tmsi.to_be_bytes().to_vec()),
        ie_extensions: None,
    });

    let tai_list = ngap_gen::TAIListForPaging(
        msg.tai_list
            .iter()
            .map(|tai| ngap_gen::TAIListForPagingItem {
                tai: ngap_gen::TAI {
                    plmn_identity: ngap_gen::PLMNIdentity(tai.tai_plmn.to_vec()),
                    tac: ngap_gen::TAC(tai.tai_tac.to_vec()),
                    ie_extensions: None,
                },
                ie_extensions: None,
            })
            .collect(),
    );

    let entry = |id: u16, value: Ie| Entry {
        id: ProtocolIE_ID(id),
        criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
        value,
    };
    let mut ies = vec![entry(
        ngap_gen::ID_UE_PAGING_IDENTITY,
        Ie::Id_UEPagingIdentity(identity),
    )];
    if let Some(drx) = msg.paging_drx {
        ies.push(entry(
            ngap_gen::ID_PAGING_DRX,
            Ie::Id_PagingDRX(ngap_gen::PagingDRX(drx as u8)),
        ));
    }
    ies.push(entry(
        ngap_gen::ID_TAI_LIST_FOR_PAGING,
        Ie::Id_TAIListForPaging(tai_list),
    ));
    if let Some(priority) = msg.paging_priority {
        // `PagingPriority` names priolevel1..8 with discriminants 1..8; the
        // ENUMERATED root numbers them 0..7.
        ies.push(entry(
            ngap_gen::ID_PAGING_PRIORITY,
            Ie::Id_PagingPriority(ngap_gen::PagingPriority(priority as u8 - 1)),
        ));
    }
    if let Some(radio_cap) = &msg.ue_radio_capability {
        let value = match nextgcore_ngap_gen::decode_contained::<ngap_gen::UERadioCapabilityForPaging>(
            radio_cap,
        ) {
            Ok(value) => value,
            Err(e) => {
                log::error!("Paging: UERadioCapabilityForPaging is not a valid encoding: {e:?}");
                return None;
            }
        };
        ies.push(entry(
            ngap_gen::ID_UE_RADIO_CAPABILITY_FOR_PAGING,
            Ie::Id_UERadioCapabilityForPaging(value),
        ));
    }
    if let Some(origin) = msg.paging_origin {
        ies.push(entry(
            ngap_gen::ID_PAGING_ORIGIN,
            Ie::Id_PagingOrigin(ngap_gen::PagingOrigin(origin as u8)),
        ));
    }
    if let Some(assistance) = &msg.assistance_data {
        let value = match nextgcore_ngap_gen::decode_contained::<ngap_gen::AssistanceDataForPaging>(
            assistance,
        ) {
            Ok(value) => value,
            Err(e) => {
                log::error!("Paging: AssistanceDataForPaging is not a valid encoding: {e:?}");
                return None;
            }
        };
        ies.push(entry(
            ngap_gen::ID_ASSISTANCE_DATA_FOR_PAGING,
            Ie::Id_AssistanceDataForPaging(value),
        ));
    }

    let pdu = NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_PAGING),
        criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
        value: ngap_gen::InitiatingMessageValue::Id_Paging(ngap_gen::Paging {
            protocol_i_es: PagingProtocolIEs(ies),
        }),
    });
    match nextgcore_ngap_gen::encode(&pdu) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            log::error!("Failed to encode Paging: {e:?}");
            None
        }
    }
}

/// The raw value of the protocol IE `id` in an NGAP PDU of any procedure.
///
/// Walks the decoded `ProtocolIE-Container` rather than the procedure's typed
/// form, so it works for every UE-associated message -- including procedures the
/// AMF does not handle, which is exactly when the Error Indication path needs the
/// IDs (#447). `None` when the PDU does not decode or carries no such IE.
fn find_protocol_ie_value(data: &[u8], id: nextgcore_asn1c::ngap::ProtocolIeId) -> Option<Vec<u8>> {
    use nextgcore_asn1c::ngap::pdu::NgapPdu;
    use nextgcore_asn1c::per::{AperDecode, AperDecoder};

    let pdu = match NgapPdu::decode_aper(&mut AperDecoder::new(data)) {
        Ok(pdu) => pdu,
        Err(e) => {
            log::debug!("NGAP PDU undecodable while looking for IE {}: {e:?}", id.0);
            return None;
        }
    };
    pdu.protocol_ies().find(id).map(|ie| ie.value.clone())
}

/// Extract the AMF-UE-NGAP-ID (IE 10) from any UE-associated NGAP PDU.
pub fn extract_amf_ue_ngap_id(data: &[u8]) -> Option<u64> {
    use nextgcore_asn1c::ngap::{AmfUeNgapId, ProtocolIeId};
    use nextgcore_asn1c::per::{AperDecode, AperDecoder};

    let value = find_protocol_ie_value(data, ProtocolIeId::AMF_UE_NGAP_ID)?;
    AmfUeNgapId::decode_aper(&mut AperDecoder::new(&value))
        .ok()
        .map(|id| id.0)
}

/// Extract the `MBS-SessionID` (IE 299) from any MBS NGAP PDU as a [`crate::ngap_mcast::Tmgi`].
///
/// Every MBS message carries it, and it is what identifies the session: one gNB
/// can hold several MBS sessions, so the SCTP association alone does not.
///
/// The IE is located by walking the decoded `ProtocolIE-Container` rather than
/// by byte offset, because the container is APER and the preceding IEs are
/// variable-length. MBS procedures are absent from the generated
/// `*Value` enums, so they arrive as the `Other` variant -- which is also how
/// the builders encode them.
pub fn extract_mbs_session_id(data: &[u8]) -> Option<crate::ngap_mcast::Tmgi> {
    use nextgcore_asn1c::ngap::pdu::{
        InitiatingMessageValue, NgapPdu, SuccessfulOutcomeValue, UnsuccessfulOutcomeValue,
    };
    use nextgcore_asn1c::per::{AperDecode, AperDecoder};

    let mut decoder = AperDecoder::new(data);
    let pdu = NgapPdu::decode_aper(&mut decoder).ok()?;
    let ies = match pdu {
        NgapPdu::InitiatingMessage(m) => match m.value {
            InitiatingMessageValue::Other(ies) => ies,
            _ => return None,
        },
        NgapPdu::SuccessfulOutcome(m) => match m.value {
            SuccessfulOutcomeValue::Other(ies) => ies,
            _ => return None,
        },
        NgapPdu::UnsuccessfulOutcome(m) => match m.value {
            UnsuccessfulOutcomeValue::Other(ies) => ies,
            _ => return None,
        },
    };

    let field = ies
        .ies
        .iter()
        .find(|ie| ie.id.0 == nextgcore_ngap::ie::IE_ID_MBS_SESSION_ID)?;

    // MBS-SessionID ::= SEQUENCE { pLMNIdentity OCTET STRING (SIZE(3)),
    //   mBS-ServiceID OCTET STRING (SIZE(3)), ... } plus an optional NID,
    // matching `MbsSessionId::encode`'s preamble.
    let mut ie_decoder = AperDecoder::new(&field.value);
    let _ext = ie_decoder.read_bit().ok()?;
    let _nid_present = ie_decoder.read_bit().ok()?;
    let plmn = ie_decoder.decode_octet_string(Some(3), Some(3)).ok()?;
    let service = ie_decoder.decode_octet_string(Some(3), Some(3)).ok()?;

    Some(crate::ngap_mcast::Tmgi {
        plmn_id: plmn.try_into().ok()?,
        mbs_service_id: service.try_into().ok()?,
    })
}

/// Extract the RAN-UE-NGAP-ID (IE 85) from any UE-associated NGAP PDU.
pub fn extract_ran_ue_ngap_id(data: &[u8]) -> Option<u32> {
    use nextgcore_asn1c::ngap::{ProtocolIeId, RanUeNgapId};
    use nextgcore_asn1c::per::{AperDecode, AperDecoder};

    let value = find_protocol_ie_value(data, ProtocolIeId::RAN_UE_NGAP_ID)?;
    RanUeNgapId::decode_aper(&mut AperDecoder::new(&value))
        .ok()
        .map(|id| id.0)
}

/// Build a UE Context Release Command with proper ASN.1 APER encoding
///
/// `cause_group`/`cause_value` follow the TS 38.413 Section 9.3.1.2 cause groups
/// (0=RadioNetwork, 1=Transport, 2=NAS, 3=Protocol, 4=Misc).
///
/// #417 stage 4: encoded by the generated codec. The (group, value) -> Cause
/// mapping is still [`build_cause`], shared with NG Setup Failure, so an
/// out-of-range value clamps exactly as before; the bytes are unchanged --
/// `ue_context_release_command_generated_matches_hand_written` pins that.
pub fn build_ue_context_release_command_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    cause_group: u8,
    cause_value: i64,
) -> Option<Vec<u8>> {
    use ngap_gen::{
        ProtocolIE_ID, UEContextReleaseCommand, UEContextReleaseCommandProtocolIEs,
        UEContextReleaseCommandProtocolIEs_Entry as Entry,
        UEContextReleaseCommandProtocolIEs_EntryValue as Ie, NGAP_PDU,
    };

    // AMF-UE-NGAP-ID is INTEGER (0..2^40-1): the generated encoder refuses a
    // larger value, as the hand-written one did.

    // IE order and criticalities as TS 38.413 §9.2.2.5 lists them.
    let ies = vec![
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_UE_NGAP_I_DS),
            criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
            value: Ie::Id_UE_NGAP_IDs(ngap_gen::UE_NGAP_IDs::UE_NGAP_ID_pair(
                ngap_gen::UE_NGAP_ID_pair {
                    amf_ue_ngap_id: ngap_gen::AMF_UE_NGAP_ID(amf_ue_ngap_id),
                    ran_ue_ngap_id: ngap_gen::RAN_UE_NGAP_ID(ran_ue_ngap_id),
                    ie_extensions: None,
                },
            )),
        },
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_CAUSE),
            criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
            value: Ie::Id_Cause(generated_cause(build_cause(cause_group, cause_value))),
        },
    ];
    let pdu = NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_UE_CONTEXT_RELEASE),
        criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
        value: ngap_gen::InitiatingMessageValue::Id_UEContextRelease(UEContextReleaseCommand {
            protocol_i_es: UEContextReleaseCommandProtocolIEs(ies),
        }),
    });

    match nextgcore_ngap_gen::encode(&pdu) {
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
            log::error!("Failed to encode UE Context Release Command: {e:?}");
            None
        }
    }
}

/// The procedure a criticality report is about, as an Error Indication's
/// Criticality Diagnostics names it (TS 38.413 §9.3.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportedProcedure {
    /// The Procedure Code of the message that caused the error.
    pub procedure_code: u8,
    /// [`ngap_gen::TriggeringMessage`]: 0 = initiating, 1 = successful outcome.
    pub triggering_message: u8,
    /// The procedure criticality the message was received with.
    pub procedure_criticality: u8,
}

/// An ERROR INDICATION (TS 38.413 §9.2.6.13) reporting not-comprehended or
/// missing IEs of a received message, for the procedures whose criticality
/// handling has to go through the Error Indication procedure (§10.3.4.2,
/// §10.3.5): a message with no response to carry the report, or a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalityErrorIndication {
    /// The UE's AMF UE NGAP ID, when the message carried a comprehended one.
    pub amf_ue_ngap_id: Option<u64>,
    /// The UE's RAN UE NGAP ID, when the message carried a comprehended one.
    pub ran_ue_ngap_id: Option<u32>,
    /// [`ngap_gen::CauseProtocol`]: abstract-syntax-error-reject when the
    /// procedure was terminated, abstract-syntax-error-ignore-and-notify when
    /// it went on.
    pub cause_protocol: u8,
    /// The procedure the report is about.
    pub procedure: ReportedProcedure,
    /// The IEs reported.
    pub diagnostics: Vec<IeDiagnostic>,
}

/// Encode a [`CriticalityErrorIndication`] with the generated codec. IE order
/// as TS 38.413 §9.2.6.13 lists it: AMF UE NGAP ID, RAN UE NGAP ID, Cause,
/// Criticality Diagnostics.
pub fn build_criticality_error_indication_asn1(
    report: &CriticalityErrorIndication,
) -> Option<Vec<u8>> {
    use ngap_gen::{
        ErrorIndication, ErrorIndicationProtocolIEs, ErrorIndicationProtocolIEs_Entry as Entry,
        ErrorIndicationProtocolIEs_EntryValue as Ie, ProtocolIE_ID, NGAP_PDU,
    };

    let ignore = ngap_gen::Criticality(ngap_gen::Criticality::IGNORE);
    let mut ies = Vec::new();
    if let Some(id) = report.amf_ue_ngap_id {
        ies.push(Entry {
            id: ProtocolIE_ID(ngap_gen::ID_AMF_UE_NGAP_ID),
            criticality: ignore.clone(),
            value: Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(id)),
        });
    }
    if let Some(id) = report.ran_ue_ngap_id {
        ies.push(Entry {
            id: ProtocolIE_ID(ngap_gen::ID_RAN_UE_NGAP_ID),
            criticality: ignore.clone(),
            value: Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(id)),
        });
    }
    ies.push(Entry {
        id: ProtocolIE_ID(ngap_gen::ID_CAUSE),
        criticality: ignore.clone(),
        value: Ie::Id_Cause(ngap_gen::Cause::Protocol(ngap_gen::CauseProtocol(
            report.cause_protocol,
        ))),
    });
    ies.push(Entry {
        id: ProtocolIE_ID(ngap_gen::ID_CRITICALITY_DIAGNOSTICS),
        criticality: ignore,
        value: Ie::Id_CriticalityDiagnostics(generated_criticality_diagnostics_for(
            Some(&report.procedure),
            &report.diagnostics,
        )),
    });
    let pdu = NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_ERROR_INDICATION),
        criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
        value: ngap_gen::InitiatingMessageValue::Id_ErrorIndication(ErrorIndication {
            protocol_i_es: ErrorIndicationProtocolIEs(ies),
        }),
    });
    match nextgcore_ngap_gen::encode(&pdu) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            log::error!("Failed to encode Error Indication: {e:?}");
            None
        }
    }
}

/// A generated [`ngap_gen::Cause`] as the `(group, value)` pair TS 29.518's
/// `NgApCause` carries, with the group indices of `ngap_handler::cause_group`.
/// `None` for a choice extension, which has no group.
fn cause_pair(cause: &ngap_gen::Cause) -> Option<(u8, i64)> {
    use crate::ngap_handler::cause_group;
    Some(match cause {
        ngap_gen::Cause::RadioNetwork(v) => (cause_group::RADIO_NETWORK, i64::from(v.0)),
        ngap_gen::Cause::Transport(v) => (cause_group::TRANSPORT, i64::from(v.0)),
        ngap_gen::Cause::Nas(v) => (cause_group::NAS, i64::from(v.0)),
        ngap_gen::Cause::Protocol(v) => (cause_group::PROTOCOL, i64::from(v.0)),
        ngap_gen::Cause::Misc(v) => (cause_group::MISC, i64::from(v.0)),
        ngap_gen::Cause::Choice_Extensions(_) => return None,
    })
}

/// How a received UE Context Release Request is to be handled.
#[derive(Debug)]
pub enum UeContextReleaseRequestDecode {
    /// Decoded; run the procedure. When `error_indication` is set, the request
    /// carried not-comprehended IEs marked "ignore IE and notify sender", which
    /// -- the procedure having no response message -- are reported in an
    /// Error Indication (§10.3.4.2).
    Proceed {
        /// The UE's AMF UE NGAP ID.
        amf_ue_ngap_id: u64,
        /// The UE's RAN UE NGAP ID.
        ran_ue_ngap_id: u32,
        /// The Cause as `(group, value)`. `None` when it is absent -- it is
        /// mandatory with criticality ignore (§9.2.2.4), so its absence is
        /// ignored (§10.3.5) -- or a choice extension.
        cause: Option<(u8, i64)>,
        /// The Error Indication to send, if any.
        error_indication: Option<CriticalityErrorIndication>,
    },
    /// A not-comprehended IE marked "reject", or a missing AMF or RAN UE NGAP
    /// ID (both criticality reject): none of the request may be executed, and
    /// -- the procedure having no unsuccessful outcome -- the procedure is
    /// terminated with an Error Indication (§10.3.4.2, §10.3.5).
    Reject(CriticalityErrorIndication),
    /// Not decodable.
    Undecodable,
}

/// Decode a UE Context Release Request (TS 38.413 §9.2.2.4) with the
/// GENERATED codec (#417 stage 4), applying §10.3.4.2 and §10.3.5 for a
/// procedure with no response message.
///
/// The hand-written parser this replaced ignored a not-comprehended IE marked
/// "ignore" or "notify" alike, and refused the request outright -- so nothing
/// was released and nothing told the gNB -- on an IE marked "reject", on a
/// missing IE, and on the optional PDU Session Resource List, which it did not
/// comprehend and which carries criticality reject. Every request it accepted
/// decodes identically: `ue_context_release_request_generated_decode_matches_hand_written`.
pub fn decode_ue_context_release_request_asn1(data: &[u8]) -> UeContextReleaseRequestDecode {
    use ngap_gen::{InitiatingMessageValue, UEContextReleaseRequestProtocolIEs_EntryValue as Ie};
    use UeContextReleaseRequestDecode::{Proceed, Reject, Undecodable};

    let (pdu, unknown) = match nextgcore_ngap_gen::decode_with_unknown_ies(data) {
        Ok(decoded) => decoded,
        Err(e) => {
            log::warn!("Failed to decode UE Context Release Request: {e:?}");
            return Undecodable;
        }
    };
    let ngap_gen::NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        criticality,
        value: InitiatingMessageValue::Id_UEContextReleaseRequest(req),
        ..
    }) = pdu
    else {
        log::warn!("Expected UeContextReleaseRequest");
        return Undecodable;
    };
    let Some((mut reject, notify)) = classify_unknown_ies(&unknown, "UE Context Release Request")
    else {
        return Undecodable;
    };

    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut cause = None;
    for entry in req.protocol_i_es.0 {
        match entry.value {
            Ie::Id_AMF_UE_NGAP_ID(v) => amf_ue_ngap_id = Some(v.0),
            Ie::Id_RAN_UE_NGAP_ID(v) => ran_ue_ngap_id = Some(v.0),
            Ie::Id_Cause(v) => cause = cause_pair(&v),
            // Comprehended. The AMF releases every PDU session of the UE, so
            // which ones the gNB asked for does not change what it does.
            Ie::Id_PDUSessionResourceListCxtRelReq(_) => {}
        }
    }
    let missing = |ie_id: u16| IeDiagnostic {
        ie_id,
        criticality: ngap_gen::Criticality::REJECT,
        type_of_error: ngap_gen::TypeOfError::MISSING,
    };
    if amf_ue_ngap_id.is_none() {
        reject.push(missing(ngap_gen::ID_AMF_UE_NGAP_ID));
    }
    if ran_ue_ngap_id.is_none() {
        reject.push(missing(ngap_gen::ID_RAN_UE_NGAP_ID));
    }

    let report = |cause_protocol: u8, diagnostics: Vec<IeDiagnostic>| CriticalityErrorIndication {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        cause_protocol,
        procedure: ReportedProcedure {
            procedure_code: ngap_gen::ID_UE_CONTEXT_RELEASE_REQUEST,
            triggering_message: ngap_gen::TriggeringMessage::INITIATING_MESSAGE,
            procedure_criticality: criticality.0,
        },
        diagnostics,
    };
    let (Some(amf_ue_ngap_id), Some(ran_ue_ngap_id), true) =
        (amf_ue_ngap_id, ran_ue_ngap_id, reject.is_empty())
    else {
        return Reject(report(
            ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT,
            reject,
        ));
    };
    if cause.is_none() {
        log::warn!("UE Context Release Request carries no usable Cause; releasing anyway");
    }
    let error_indication = (!notify.is_empty()).then(|| {
        report(
            ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
            notify,
        )
    });
    Proceed {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        cause,
        error_indication,
    }
}

/// How a received UE Context Release Complete is to be handled.
#[derive(Debug)]
pub enum UeContextReleaseCompleteDecode {
    /// Decoded. Both IDs are mandatory with criticality ignore (§9.2.2.6), so
    /// a missing one is ignored (§10.3.5) and comes back `None`. When
    /// `error_indication` is set, the response carried not-comprehended IEs
    /// marked "ignore IE and notify sender", reported in an Error Indication
    /// (§10.3.4.2).
    Complete {
        /// The AMF UE NGAP ID the gNB names.
        amf_ue_ngap_id: Option<u64>,
        /// The RAN UE NGAP ID the gNB names.
        ran_ue_ngap_id: Option<u32>,
        /// The Error Indication to send, if any.
        error_indication: Option<CriticalityErrorIndication>,
    },
    /// The response carried a not-comprehended IE marked "reject": the
    /// procedure is "unsuccessfully terminated" and handled locally
    /// (§10.3.4.2), with no message to the gNB. The IEs are for the log.
    Failed(Vec<IeDiagnostic>),
    /// Not decodable.
    Undecodable,
}

/// Decode a UE Context Release Complete (gNB -> AMF, TS 38.413 §9.2.2.6) with
/// the GENERATED codec (#417 stage 4), applying the §10.3.4.2 rules for a
/// RESPONSE message.
///
/// The hand-written parser this replaced refused the message on a missing ID,
/// on an IE marked "reject" it did not comprehend, and on the optional PDU
/// Session Resource List, which it did not comprehend and which carries
/// criticality reject -- each of which made the AMF fall back to supervising
/// every UE of the association. Every message it accepted decodes identically:
/// `ue_context_release_complete_generated_decode_matches_hand_written`.
pub fn decode_ue_context_release_complete_asn1(data: &[u8]) -> UeContextReleaseCompleteDecode {
    use ngap_gen::{SuccessfulOutcomeValue, UEContextReleaseCompleteProtocolIEs_EntryValue as Ie};
    use UeContextReleaseCompleteDecode::{Complete, Failed, Undecodable};

    let (pdu, unknown) = match nextgcore_ngap_gen::decode_with_unknown_ies(data) {
        Ok(decoded) => decoded,
        Err(e) => {
            log::warn!("Failed to decode UE Context Release Complete: {e:?}");
            return Undecodable;
        }
    };
    let ngap_gen::NGAP_PDU::SuccessfulOutcome(ngap_gen::SuccessfulOutcome {
        criticality,
        value: SuccessfulOutcomeValue::Id_UEContextRelease(complete),
        ..
    }) = pdu
    else {
        log::warn!("Expected UeContextReleaseComplete");
        return Undecodable;
    };
    let Some((reject, notify)) = classify_unknown_ies(&unknown, "UE Context Release Complete")
    else {
        return Undecodable;
    };
    if !reject.is_empty() {
        return Failed(reject);
    }

    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    for entry in complete.protocol_i_es.0 {
        match entry.value {
            Ie::Id_AMF_UE_NGAP_ID(v) => amf_ue_ngap_id = Some(v.0),
            Ie::Id_RAN_UE_NGAP_ID(v) => ran_ue_ngap_id = Some(v.0),
            // Comprehended, and not used by the AMF.
            Ie::Id_UserLocationInformation(_)
            | Ie::Id_InfoOnRecommendedCellsAndRANNodesForPaging(_)
            | Ie::Id_PDUSessionResourceListCxtRelCpl(_)
            | Ie::Id_CriticalityDiagnostics(_)
            | Ie::Id_PagingAssisDataforCEcapabUE(_) => {}
        }
    }
    let error_indication = if notify.is_empty() {
        None
    } else {
        Some(CriticalityErrorIndication {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            cause_protocol: ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
            procedure: ReportedProcedure {
                procedure_code: ngap_gen::ID_UE_CONTEXT_RELEASE,
                triggering_message: ngap_gen::TriggeringMessage::SUCCESSFUL_OUTCOME,
                procedure_criticality: criticality.0,
            },
            diagnostics: notify,
        })
    };
    Complete {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        error_indication,
    }
}

/// How a received NG Reset is to be handled.
#[derive(Debug)]
pub enum NgResetDecode {
    /// Decoded; run the procedure and answer with an NG Reset Acknowledge.
    /// `notify` lists the not-comprehended IEs marked "ignore IE and notify
    /// sender", which -- NG Reset having a response message -- go in the
    /// Acknowledge's Criticality Diagnostics (§10.3.4.2).
    Proceed {
        /// The reset, as the handler consumes it. A missing or choice-extension
        /// Cause (mandatory, criticality ignore, §9.2.6.11) is ignored per
        /// §10.3.5 and comes back as misc/unspecified.
        reset: NgReset,
        /// Diagnostics for the Acknowledge.
        notify: Vec<IeDiagnostic>,
    },
    /// A not-comprehended IE marked "reject", or a missing Reset Type
    /// (criticality reject): none of the reset may be executed, and -- the
    /// procedure having no unsuccessful outcome -- it is terminated with an
    /// Error Indication (§10.3.4.2, §10.3.5).
    Reject(CriticalityErrorIndication),
    /// Not decodable.
    Undecodable,
}

/// Decode an NG Reset (TS 38.413 §9.2.6.11) with the GENERATED codec (#417),
/// applying §10.3.4.2 and §10.3.5.
///
/// The hand-written parser this replaced refused the whole message on any
/// not-comprehended IE, whatever its criticality, so the gNB's reset was never
/// executed and never acknowledged. Every reset it accepted decodes
/// identically: `ng_reset_generated_decode_matches_hand_written`.
pub fn decode_ng_reset_asn1(data: &[u8]) -> NgResetDecode {
    use ngap_gen::{InitiatingMessageValue, NGResetProtocolIEs_EntryValue as Ie};
    use NgResetDecode::{Proceed, Reject, Undecodable};

    let (pdu, unknown) = match nextgcore_ngap_gen::decode_with_unknown_ies(data) {
        Ok(decoded) => decoded,
        Err(e) => {
            log::warn!("Failed to decode NG Reset: {e:?}");
            return Undecodable;
        }
    };
    let ngap_gen::NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        criticality,
        value: InitiatingMessageValue::Id_NGReset(reset),
        ..
    }) = pdu
    else {
        log::warn!("Expected NGReset");
        return Undecodable;
    };
    let Some((mut reject, notify)) = classify_unknown_ies(&unknown, "NG Reset") else {
        return Undecodable;
    };

    let mut cause = None;
    let mut reset_type = None;
    for entry in reset.protocol_i_es.0 {
        match entry.value {
            Ie::Id_Cause(v) => cause = cause_pair(&v),
            Ie::Id_ResetType(v) => {
                reset_type = Some(match v {
                    ngap_gen::ResetType::NG_Interface(_) => ResetType::NgInterface,
                    ngap_gen::ResetType::PartOfNG_Interface(list) => ResetType::PartOfNgInterface(
                        list.0
                            .into_iter()
                            .map(|item| UeAssociatedLogicalNgConnectionItem {
                                amf_ue_ngap_id: item.amf_ue_ngap_id.map(|id| id.0),
                                ran_ue_ngap_id: item.ran_ue_ngap_id.map(|id| id.0),
                            })
                            .collect(),
                    ),
                    // The choice extension's object set is empty, so its open
                    // type cannot be decoded and never gets here.
                    ngap_gen::ResetType::Choice_Extensions(_) => {
                        log::warn!("NG Reset Type is a choice extension");
                        return Undecodable;
                    }
                })
            }
        }
    }
    if reset_type.is_none() {
        reject.push(IeDiagnostic {
            ie_id: ngap_gen::ID_RESET_TYPE,
            criticality: ngap_gen::Criticality::REJECT,
            type_of_error: ngap_gen::TypeOfError::MISSING,
        });
    }
    let (Some(reset_type), true) = (reset_type, reject.is_empty()) else {
        return Reject(CriticalityErrorIndication {
            amf_ue_ngap_id: None,
            ran_ue_ngap_id: None,
            cause_protocol: ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT,
            procedure: ReportedProcedure {
                procedure_code: ngap_gen::ID_NG_RESET,
                triggering_message: ngap_gen::TriggeringMessage::INITIATING_MESSAGE,
                procedure_criticality: criticality.0,
            },
            diagnostics: reject,
        });
    };
    let cause = match cause {
        Some((group, value)) => build_cause(group, value),
        None => {
            log::warn!("NG Reset carries no usable Cause; resetting anyway");
            Cause::Misc(CauseMisc::Unspecified)
        }
    };
    Proceed {
        reset: NgReset { cause, reset_type },
        notify,
    }
}

/// Build an NG Reset Acknowledge (TS 38.413 §9.2.6.12) with the GENERATED
/// codec (#417).
///
/// `connections` echoes the UE-associated logical NG-connection list of a
/// partial NG Reset (§8.7.4.2.2); `None` for a full reset. `notify` is the
/// reset's "ignore IE and notify sender" IEs, reported in the Criticality
/// Diagnostics (§10.3.4.2); empty for none. Byte-identical to the hand-written
/// builder it replaced: `ng_reset_acknowledge_generated_matches_hand_written`.
pub fn build_ng_reset_acknowledge_asn1(
    connections: Option<Vec<UeAssociatedLogicalNgConnectionItem>>,
    notify: &[IeDiagnostic],
) -> Option<Vec<u8>> {
    use ngap_gen::{
        NGResetAcknowledge, NGResetAcknowledgeProtocolIEs,
        NGResetAcknowledgeProtocolIEs_Entry as Entry,
        NGResetAcknowledgeProtocolIEs_EntryValue as Ie, ProtocolIE_ID, NGAP_PDU,
    };

    let ignore = ngap_gen::Criticality(ngap_gen::Criticality::IGNORE);
    let mut ies = Vec::new();
    if let Some(connections) = connections {
        ies.push(Entry {
            id: ProtocolIE_ID(ngap_gen::ID_UE_ASSOCIATED_LOGICAL_NG_CONNECTION_LIST),
            criticality: ignore.clone(),
            value: Ie::Id_UE_associatedLogicalNG_connectionList(
                ngap_gen::UE_associatedLogicalNG_connectionList(
                    connections
                        .into_iter()
                        .map(|item| ngap_gen::UE_associatedLogicalNG_connectionItem {
                            amf_ue_ngap_id: item.amf_ue_ngap_id.map(ngap_gen::AMF_UE_NGAP_ID),
                            ran_ue_ngap_id: item.ran_ue_ngap_id.map(ngap_gen::RAN_UE_NGAP_ID),
                            ie_extensions: None,
                        })
                        .collect(),
                ),
            ),
        });
    }
    if !notify.is_empty() {
        ies.push(Entry {
            id: ProtocolIE_ID(ngap_gen::ID_CRITICALITY_DIAGNOSTICS),
            criticality: ignore,
            value: Ie::Id_CriticalityDiagnostics(generated_criticality_diagnostics(notify)),
        });
    }
    let pdu = NGAP_PDU::SuccessfulOutcome(ngap_gen::SuccessfulOutcome {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_NG_RESET),
        criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
        value: ngap_gen::SuccessfulOutcomeValue::Id_NGReset(NGResetAcknowledge {
            protocol_i_es: NGResetAcknowledgeProtocolIEs(ies),
        }),
    });
    match nextgcore_ngap_gen::encode(&pdu) {
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

/// Build an AMF-initiated OVERLOAD START (TS 38.413 §9.2.6.10) carrying a
/// percentage traffic-load reduction request, with the GENERATED codec (#417).
///
/// AMF Traffic Load Reduction Indication is INTEGER (1..99), criticality
/// ignore; `reduce_percent` is clamped into that range, as the hand-written
/// builder did. Byte-identical to it over 0..=255:
/// `overload_generated_matches_hand_written`.
pub fn build_overload_start_asn1(reduce_percent: u8) -> Option<Vec<u8>> {
    use ngap_gen::{
        OverloadStart, OverloadStartProtocolIEs, OverloadStartProtocolIEs_Entry as Entry,
        OverloadStartProtocolIEs_EntryValue as Ie, ProtocolIE_ID, NGAP_PDU,
    };
    let pdu = NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_OVERLOAD_START),
        criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
        value: ngap_gen::InitiatingMessageValue::Id_OverloadStart(OverloadStart {
            protocol_i_es: OverloadStartProtocolIEs(vec![Entry {
                id: ProtocolIE_ID(ngap_gen::ID_AMF_TRAFFIC_LOAD_REDUCTION_INDICATION),
                criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
                value: Ie::Id_AMFTrafficLoadReductionIndication(
                    ngap_gen::TrafficLoadReductionIndication(reduce_percent.clamp(1, 99)),
                ),
            }]),
        }),
    });
    match nextgcore_ngap_gen::encode(&pdu) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            log::error!("Failed to encode OverloadStart: {e:?}");
            None
        }
    }
}

/// Build an AMF-initiated OVERLOAD STOP (TS 38.413 §9.2.6.11), with the
/// GENERATED codec (#417). OverloadStopIEs is an empty, extensible object set,
/// so the message is an empty IE container under procedure criticality reject.
pub fn build_overload_stop_asn1() -> Option<Vec<u8>> {
    let pdu = ngap_gen::NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_OVERLOAD_STOP),
        criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
        value: ngap_gen::InitiatingMessageValue::Id_OverloadStop(ngap_gen::OverloadStop {
            protocol_i_es: ngap_gen::OverloadStopProtocolIEs(Vec::new()),
        }),
    });
    match nextgcore_ngap_gen::encode(&pdu) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            log::error!("Failed to encode OverloadStop: {e:?}");
            None
        }
    }
}

/// The hand-written Cause a generated one maps to; misc/unspecified for a
/// choice extension, which has no group.
fn hand_written_cause(cause: &ngap_gen::Cause) -> Cause {
    match cause_pair(cause) {
        Some((group, value)) => build_cause(group, value),
        None => Cause::Misc(CauseMisc::Unspecified),
    }
}

/// The [`CriticalityErrorIndication`] reporting `diagnostics` of a received
/// handover-family message.
fn handover_report(
    procedure_code: u8,
    triggering_message: u8,
    procedure_criticality: u8,
    ids: (Option<u64>, Option<u32>),
    cause_protocol: u8,
    diagnostics: Vec<IeDiagnostic>,
) -> CriticalityErrorIndication {
    CriticalityErrorIndication {
        amf_ue_ngap_id: ids.0,
        ran_ue_ngap_id: ids.1,
        cause_protocol,
        procedure: ReportedProcedure {
            procedure_code,
            triggering_message,
            procedure_criticality,
        },
        diagnostics,
    }
}

/// Decode a HANDOVER CANCEL (TS 38.413 §9.2.3.8) with the GENERATED codec
/// (#417), applying §10.3.4.2/§10.3.5. Both UE NGAP IDs are mandatory with
/// criticality reject; Cause is criticality ignore. The procedure has a
/// response (HANDOVER CANCEL ACKNOWLEDGE) and no unsuccessful outcome: a
/// "notify" IE comes back in `error_indication` for the caller to report in
/// the Acknowledge's Criticality Diagnostics, and a "reject" one terminates
/// the procedure with an Error Indication.
pub fn decode_handover_cancel_asn1(data: &[u8]) -> NasTransportDecode<HandoverCancel> {
    use ngap_gen::HandoverCancelProtocolIEs_EntryValue as Ie;
    let Some((criticality, ies, mut reject, notify)) =
        decode_initiating(data, "Handover Cancel", |v| match v {
            ngap_gen::InitiatingMessageValue::Id_HandoverCancel(m) => Some(m.protocol_i_es.0),
            _ => None,
        })
    else {
        return NasTransportDecode::Undecodable;
    };
    let (mut amf, mut ran, mut cause) = (None, None, None);
    for entry in ies {
        match entry.value {
            Ie::Id_AMF_UE_NGAP_ID(v) => amf = Some(v.0),
            Ie::Id_RAN_UE_NGAP_ID(v) => ran = Some(v.0),
            Ie::Id_Cause(v) => cause = Some(hand_written_cause(&v)),
        }
    }
    if amf.is_none() {
        reject.push(missing_ie(ngap_gen::ID_AMF_UE_NGAP_ID));
    }
    if ran.is_none() {
        reject.push(missing_ie(ngap_gen::ID_RAN_UE_NGAP_ID));
    }
    let report = |cause_protocol, diagnostics| {
        handover_report(
            ngap_gen::ID_HANDOVER_CANCEL,
            ngap_gen::TriggeringMessage::INITIATING_MESSAGE,
            criticality,
            (amf, ran),
            cause_protocol,
            diagnostics,
        )
    };
    let (Some(amf_ue_ngap_id), Some(ran_ue_ngap_id), true) = (amf, ran, reject.is_empty()) else {
        return NasTransportDecode::Reject(report(
            ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT,
            reject,
        ));
    };
    NasTransportDecode::Proceed {
        message: HandoverCancel {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            cause: cause.unwrap_or(Cause::Misc(CauseMisc::Unspecified)),
        },
        error_indication: (!notify.is_empty()).then(|| {
            report(
                ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
                notify,
            )
        }),
    }
}

/// Decode a HANDOVER NOTIFY (TS 38.413 §9.2.3.7) with the GENERATED codec
/// (#417), applying §10.3.4.2/§10.3.5 for a procedure with no response: both
/// UE NGAP IDs are criticality reject, so their absence -- like a
/// not-comprehended "reject" IE -- terminates it with an Error Indication;
/// User Location Information is criticality ignore, so an absent or
/// non-NR one is ignored and comes back as `None`.
pub fn decode_handover_notify_asn1(
    data: &[u8],
) -> NasTransportDecode<(u64, u32, Option<UserLocationInformation>)> {
    use ngap_gen::HandoverNotifyProtocolIEs_EntryValue as Ie;
    let Some((criticality, ies, mut reject, notify)) =
        decode_initiating(data, "Handover Notify", |v| match v {
            ngap_gen::InitiatingMessageValue::Id_HandoverNotification(m) => Some(m.protocol_i_es.0),
            _ => None,
        })
    else {
        return NasTransportDecode::Undecodable;
    };
    let (mut amf, mut ran, mut uli) = (None, None, None);
    for entry in ies {
        match entry.value {
            Ie::Id_AMF_UE_NGAP_ID(v) => amf = Some(v.0),
            Ie::Id_RAN_UE_NGAP_ID(v) => ran = Some(v.0),
            Ie::Id_UserLocationInformation(v) => uli = hand_written_user_location(&v),
            // Comprehended; the AMF does not act on it.
            Ie::Id_NotifySourceNGRANNode(_) => {}
        }
    }
    if amf.is_none() {
        reject.push(missing_ie(ngap_gen::ID_AMF_UE_NGAP_ID));
    }
    if ran.is_none() {
        reject.push(missing_ie(ngap_gen::ID_RAN_UE_NGAP_ID));
    }
    let report = |cause_protocol, diagnostics| {
        handover_report(
            ngap_gen::ID_HANDOVER_NOTIFICATION,
            ngap_gen::TriggeringMessage::INITIATING_MESSAGE,
            criticality,
            (amf, ran),
            cause_protocol,
            diagnostics,
        )
    };
    let (Some(amf_ue_ngap_id), Some(ran_ue_ngap_id), true) = (amf, ran, reject.is_empty()) else {
        return NasTransportDecode::Reject(report(
            ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT,
            reject,
        ));
    };
    NasTransportDecode::Proceed {
        message: (amf_ue_ngap_id, ran_ue_ngap_id, uli),
        error_indication: (!notify.is_empty()).then(|| {
            report(
                ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
                notify,
            )
        }),
    }
}

/// The value of a BIT STRING as an unsigned integer, most significant bit first.
fn bits_value(bits: &bitvec::prelude::BitSlice<u8, bitvec::prelude::Msb0>) -> u32 {
    bits.iter().fold(0u32, |v, bit| (v << 1) | u32::from(*bit))
}

/// A generated NgENB-ID's value (macro 20, short macro 18 or long macro 21 bits).
/// `None` for the uninhabitable choice extension.
fn ng_enb_id_value(id: &ngap_gen::NgENB_ID) -> Option<u32> {
    Some(match id {
        ngap_gen::NgENB_ID::MacroNgENB_ID(b) => bits_value(&b.0),
        ngap_gen::NgENB_ID::ShortMacroNgENB_ID(b) => bits_value(&b.0),
        ngap_gen::NgENB_ID::LongMacroNgENB_ID(b) => bits_value(&b.0),
        #[allow(unreachable_patterns)]
        _ => return None,
    })
}

/// The hand-written GlobalRanNodeId a generated GlobalRANNodeID maps to: a gNB or
/// an ng-eNB; `None` for an N3IWF or a choice extension, which a handover target
/// cannot be.
fn hand_written_global_ran_node_id(id: &ngap_gen::GlobalRANNodeID) -> Option<GlobalRanNodeId> {
    match id {
        ngap_gen::GlobalRANNodeID::GlobalGNB_ID(gnb) => {
            let bits = match &gnb.gnb_id {
                ngap_gen::GNB_ID::GNB_ID(bits) => bits,
                #[allow(unreachable_patterns)]
                _ => return None,
            };
            Some(GlobalRanNodeId::GlobalGnbId {
                plmn_identity: gnb.plmn_identity.0.as_slice().try_into().ok()?,
                gnb_id: bits_value(&bits.0),
                gnb_id_len: bits.0.len() as u8,
            })
        }
        ngap_gen::GlobalRANNodeID::GlobalNgENB_ID(enb) => Some(GlobalRanNodeId::GlobalNgEnbId {
            plmn_identity: enb.plmn_identity.0.as_slice().try_into().ok()?,
            ng_enb_id: ng_enb_id_value(&enb.ng_enb_id)?,
        }),
        _ => None,
    }
}

/// The hand-written TargetId a generated TargetID maps to (TS 38.413 §9.3.1.25).
///
/// The hand-written decoder this replaces read `targeteNB-ID` wrongly: it took
/// three PLMN octets straight after the SEQUENCE preamble, skipping the
/// GlobalNgENB-ID's own extension and optional bits and its ngENB-ID CHOICE,
/// then 32 raw bits as the eNB id, then a 5GS TAI with a 3-octet TAC where
/// EPS-TAI has a 2-octet one. So a 5GS-to-EPS HANDOVER REQUIRED naming its
/// target as an eNB decoded to a garbage PLMN and eNB id, which the AMF then
/// relayed to the MME in the Forward Relocation's Target Identification. The
/// EPS TAC goes into the low two octets of `tai_tac`.
fn hand_written_target_id(target: &ngap_gen::TargetID) -> Option<TargetId> {
    match target {
        ngap_gen::TargetID::TargetRANNodeID(t) => Some(TargetId::TargetRanNodeId {
            global_ran_node_id: hand_written_global_ran_node_id(&t.global_ran_node_id)?,
            selected_tai: TaiListItem {
                tai_plmn: t.selected_tai.plmn_identity.0.as_slice().try_into().ok()?,
                tai_tac: t.selected_tai.tac.0.as_slice().try_into().ok()?,
            },
        }),
        ngap_gen::TargetID::TargeteNB_ID(t) => {
            let tac: [u8; 2] = t.selected_eps_tai.eps_tac.0.as_slice().try_into().ok()?;
            Some(TargetId::TargetGlobalNgEnbId {
                plmn_identity: t.global_enb_id.plmn_identity.0.as_slice().try_into().ok()?,
                ng_enb_id: ng_enb_id_value(&t.global_enb_id.ng_enb_id)?,
                selected_tai: TaiListItem {
                    tai_plmn: t
                        .selected_eps_tai
                        .plmn_identity
                        .0
                        .as_slice()
                        .try_into()
                        .ok()?,
                    tai_tac: [0, tac[0], tac[1]],
                },
            })
        }
        #[allow(unreachable_patterns)]
        _ => None,
    }
}

/// A [`CriticalityErrorIndication`]'s report as the hand-written Criticality
/// Diagnostics a HANDOVER PREPARATION FAILURE carries.
pub fn hand_written_diagnostics(report: &CriticalityErrorIndication) -> CriticalityDiagnostics {
    CriticalityDiagnostics {
        procedure_code: Some(report.procedure.procedure_code),
        triggering_message: Some(report.procedure.triggering_message),
        procedure_criticality: Some(report.procedure.procedure_criticality),
        ies: report
            .diagnostics
            .iter()
            .map(|ie| IeCriticalityDiagnostics {
                ie_criticality: match ie.criticality {
                    ngap_gen::Criticality::REJECT => {
                        nextgcore_asn1c::ngap::types::Criticality::Reject
                    }
                    ngap_gen::Criticality::IGNORE => {
                        nextgcore_asn1c::ngap::types::Criticality::Ignore
                    }
                    _ => nextgcore_asn1c::ngap::types::Criticality::Notify,
                },
                ie_id: ie.ie_id,
                type_of_error: if ie.type_of_error == ngap_gen::TypeOfError::MISSING {
                    TypeOfError::Missing
                } else {
                    TypeOfError::NotUnderstood
                },
            })
            .collect(),
    }
}

/// Decode a HANDOVER REQUIRED (TS 38.413 §9.2.3.1) with the GENERATED codec
/// (#417), applying §10.3.4.2 and §10.3.5. Handover Preparation is a Class 1
/// procedure whose unsuccessful outcome is HANDOVER PREPARATION FAILURE, so a
/// not-comprehended "reject" IE, or a missing one of the six mandatory
/// criticality-reject IEs, comes back as `Reject` for the caller to answer
/// with that failure (or an Error Indication when the UE cannot be named); a
/// "notify" IE comes back in `error_indication`. Cause and Direct Forwarding
/// Path Availability are criticality ignore: a missing Cause is
/// misc/unspecified. A TargetID this AMF cannot represent (an N3IWF, a
/// choice extension) is `Undecodable`, as the hand-written parser had it.
pub fn decode_handover_required_asn1(data: &[u8]) -> NasTransportDecode<HandoverRequired> {
    use ngap_gen::HandoverRequiredProtocolIEs_EntryValue as Ie;
    let Some((criticality, ies, mut reject, notify)) =
        decode_initiating(data, "Handover Required", |v| match v {
            ngap_gen::InitiatingMessageValue::Id_HandoverPreparation(m) => Some(m.protocol_i_es.0),
            _ => None,
        })
    else {
        return NasTransportDecode::Undecodable;
    };
    let (mut amf, mut ran, mut ho_type, mut cause, mut target) = (None, None, None, None, None);
    let (mut sessions, mut container, mut direct) = (None, None, None);
    for entry in ies {
        match entry.value {
            Ie::Id_AMF_UE_NGAP_ID(v) => amf = Some(v.0),
            Ie::Id_RAN_UE_NGAP_ID(v) => ran = Some(v.0),
            Ie::Id_HandoverType(v) => {
                ho_type = Some(match v.0 {
                    ngap_gen::HandoverType::INTRA5GS => HandoverType::Intra5gs,
                    ngap_gen::HandoverType::FIVEGS_TO_EPS => HandoverType::FivegsToEps,
                    ngap_gen::HandoverType::EPS_TO_5GS => HandoverType::EpsTo5gs,
                    other => {
                        // 5GS-to-UTRAN and later: no hand-written value, as before.
                        log::warn!("Handover Required with an unsupported HandoverType {other}");
                        return NasTransportDecode::Undecodable;
                    }
                })
            }
            Ie::Id_Cause(v) => cause = Some(hand_written_cause(&v)),
            Ie::Id_TargetID(v) => match hand_written_target_id(&v) {
                Some(t) => target = Some(t),
                None => {
                    log::warn!("Handover Required names a target this AMF cannot represent");
                    return NasTransportDecode::Undecodable;
                }
            },
            Ie::Id_DirectForwardingPathAvailability(_) => direct = Some(
                nextgcore_asn1c::ngap::ies::DirectForwardingPathAvailability::DirectPathAvailable,
            ),
            Ie::Id_PDUSessionResourceListHORqd(v) => {
                sessions = Some(
                    v.0.iter()
                        .map(|item| PduSessionResourceItemHoRqd {
                            pdu_session_id: item.pdu_session_id.0,
                            transfer: item.handover_required_transfer.0.clone(),
                        })
                        .collect::<Vec<_>>(),
                )
            }
            Ie::Id_SourceToTarget_TransparentContainer(v) => container = Some(v.0),
        }
    }
    for (present, id) in [
        (amf.is_some(), ngap_gen::ID_AMF_UE_NGAP_ID),
        (ran.is_some(), ngap_gen::ID_RAN_UE_NGAP_ID),
        (ho_type.is_some(), ngap_gen::ID_HANDOVER_TYPE),
        (target.is_some(), ngap_gen::ID_TARGET_ID),
        (
            sessions.is_some(),
            ngap_gen::ID_PDU_SESSION_RESOURCE_LIST_HO_RQD,
        ),
        (
            container.is_some(),
            ngap_gen::ID_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER,
        ),
    ] {
        if !present {
            reject.push(missing_ie(id));
        }
    }
    let report = |cause_protocol, diagnostics| {
        handover_report(
            ngap_gen::ID_HANDOVER_PREPARATION,
            ngap_gen::TriggeringMessage::INITIATING_MESSAGE,
            criticality,
            (amf, ran),
            cause_protocol,
            diagnostics,
        )
    };
    let (
        Some(amf_ue_ngap_id),
        Some(ran_ue_ngap_id),
        Some(handover_type),
        Some(target_id),
        Some(pdu_session_list),
        Some(source_to_target_container),
        true,
    ) = (
        amf,
        ran,
        ho_type,
        target,
        sessions,
        container,
        reject.is_empty(),
    )
    else {
        return NasTransportDecode::Reject(report(
            ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT,
            reject,
        ));
    };
    NasTransportDecode::Proceed {
        message: HandoverRequired {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            handover_type,
            cause: cause.unwrap_or(Cause::Misc(CauseMisc::Unspecified)),
            target_id,
            pdu_session_list,
            source_to_target_container,
            direct_forwarding_path_availability: direct,
        },
        error_indication: (!notify.is_empty()).then(|| {
            report(
                ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
                notify,
            )
        }),
    }
}

/// Decode a HANDOVER FAILURE (TS 38.413 §9.2.3.4) with the GENERATED codec
/// (#417). It is the unsuccessful outcome of Handover Resource Allocation, a
/// response: a not-comprehended "reject" IE means local error handling only
/// (§10.3.4.2), returned as `Reject` for the caller to drop; a "notify" one is
/// reported in an Error Indication. Every IE is criticality ignore, so a
/// missing AMF UE NGAP ID makes the failure unattributable (`Undecodable`)
/// and a missing Cause is misc/unspecified.
pub fn decode_handover_failure_asn1(data: &[u8]) -> NasTransportDecode<HandoverFailure> {
    use ngap_gen::HandoverFailureProtocolIEs_EntryValue as Ie;
    let (pdu, unknown) = match nextgcore_ngap_gen::decode_with_unknown_ies(data) {
        Ok(decoded) => decoded,
        Err(e) => {
            log::warn!("Failed to decode Handover Failure: {e:?}");
            return NasTransportDecode::Undecodable;
        }
    };
    let ngap_gen::NGAP_PDU::UnsuccessfulOutcome(ngap_gen::UnsuccessfulOutcome {
        criticality,
        value: ngap_gen::UnsuccessfulOutcomeValue::Id_HandoverResourceAllocation(failure),
        ..
    }) = pdu
    else {
        log::warn!("Expected HandoverFailure");
        return NasTransportDecode::Undecodable;
    };
    let Some((reject, notify)) = classify_unknown_ies(&unknown, "Handover Failure") else {
        return NasTransportDecode::Undecodable;
    };
    let (mut amf, mut cause) = (None, None);
    for entry in failure.protocol_i_es.0 {
        match entry.value {
            Ie::Id_AMF_UE_NGAP_ID(v) => amf = Some(v.0),
            Ie::Id_Cause(v) => cause = Some(hand_written_cause(&v)),
            Ie::Id_CriticalityDiagnostics(_)
            | Ie::Id_TargettoSource_Failure_TransparentContainer(_) => {}
        }
    }
    let report = |cause_protocol, diagnostics| {
        handover_report(
            ngap_gen::ID_HANDOVER_RESOURCE_ALLOCATION,
            ngap_gen::TriggeringMessage::UNSUCCESSFUL_OUTCOME,
            criticality.0,
            (amf, None),
            cause_protocol,
            diagnostics,
        )
    };
    if !reject.is_empty() {
        return NasTransportDecode::Reject(report(
            ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT,
            reject,
        ));
    }
    let Some(amf_ue_ngap_id) = amf else {
        log::warn!("Handover Failure carries no AMF UE NGAP ID");
        return NasTransportDecode::Undecodable;
    };
    NasTransportDecode::Proceed {
        message: HandoverFailure {
            amf_ue_ngap_id,
            cause: cause.unwrap_or(Cause::Misc(CauseMisc::Unspecified)),
            criticality_diagnostics: None,
        },
        error_indication: (!notify.is_empty()).then(|| {
            report(
                ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
                notify,
            )
        }),
    }
}

/// Decode an initiating message with unknown-IE skipping: its procedure
/// criticality, its IE entries (extracted by `pick`), and its not-comprehended
/// IEs sorted into `(reject, notify)`. `None` when it does not decode or is not
/// the message `pick` selects.
fn decode_initiating<E>(
    data: &[u8],
    message: &str,
    pick: impl FnOnce(ngap_gen::InitiatingMessageValue) -> Option<Vec<E>>,
) -> Option<(u8, Vec<E>, Vec<IeDiagnostic>, Vec<IeDiagnostic>)> {
    let (pdu, unknown) = match nextgcore_ngap_gen::decode_with_unknown_ies(data) {
        Ok(decoded) => decoded,
        Err(e) => {
            log::warn!("Failed to decode {message}: {e:?}");
            return None;
        }
    };
    let ngap_gen::NGAP_PDU::InitiatingMessage(msg) = pdu else {
        log::warn!("Expected {message}");
        return None;
    };
    let criticality = msg.criticality.0;
    let Some(ies) = pick(msg.value) else {
        log::warn!("Expected {message}");
        return None;
    };
    let (reject, notify) = classify_unknown_ies(&unknown, message)?;
    Some((criticality, ies, reject, notify))
}

/// A hand-written Criticality Diagnostics as the generated IE, field for field.
fn generated_diagnostics_from(diag: &CriticalityDiagnostics) -> ngap_gen::CriticalityDiagnostics {
    ngap_gen::CriticalityDiagnostics {
        procedure_code: diag.procedure_code.map(ngap_gen::ProcedureCode),
        triggering_message: diag.triggering_message.map(ngap_gen::TriggeringMessage),
        procedure_criticality: diag.procedure_criticality.map(ngap_gen::Criticality),
        i_es_criticality_diagnostics: (!diag.ies.is_empty()).then(|| {
            ngap_gen::CriticalityDiagnostics_IE_List(
                diag.ies
                    .iter()
                    .map(|ie| ngap_gen::CriticalityDiagnostics_IE_Item {
                        ie_criticality: ngap_gen::Criticality(ie.ie_criticality as u8),
                        ie_id: ngap_gen::ProtocolIE_ID(ie.ie_id),
                        type_of_error: ngap_gen::TypeOfError(match ie.type_of_error {
                            TypeOfError::NotUnderstood => ngap_gen::TypeOfError::NOT_UNDERSTOOD,
                            TypeOfError::Missing => ngap_gen::TypeOfError::MISSING,
                        }),
                        ie_extensions: None,
                    })
                    .collect(),
            )
        }),
        ie_extensions: None,
    }
}

/// Build a HANDOVER PREPARATION FAILURE (TS 38.413 §9.2.3.6) with the
/// GENERATED codec (#417). Every IE is criticality ignore. Byte-identical to
/// the hand-written builder: `handover_preparation_failure_generated_matches_hand_written`.
pub fn build_handover_preparation_failure_asn1(
    msg: &HandoverPreparationFailure,
) -> Option<Vec<u8>> {
    use ngap_gen::{
        HandoverPreparationFailureProtocolIEs_Entry as Entry,
        HandoverPreparationFailureProtocolIEs_EntryValue as Ie, ProtocolIE_ID,
    };
    let ignore = || ngap_gen::Criticality(ngap_gen::Criticality::IGNORE);
    let mut ies = vec![
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_AMF_UE_NGAP_ID),
            criticality: ignore(),
            value: Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(msg.amf_ue_ngap_id)),
        },
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_RAN_UE_NGAP_ID),
            criticality: ignore(),
            value: Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(msg.ran_ue_ngap_id)),
        },
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_CAUSE),
            criticality: ignore(),
            value: Ie::Id_Cause(generated_cause(msg.cause)),
        },
    ];
    if let Some(diag) = &msg.criticality_diagnostics {
        ies.push(Entry {
            id: ProtocolIE_ID(ngap_gen::ID_CRITICALITY_DIAGNOSTICS),
            criticality: ignore(),
            value: Ie::Id_CriticalityDiagnostics(generated_diagnostics_from(diag)),
        });
    }
    let pdu = ngap_gen::NGAP_PDU::UnsuccessfulOutcome(ngap_gen::UnsuccessfulOutcome {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_HANDOVER_PREPARATION),
        criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
        value: ngap_gen::UnsuccessfulOutcomeValue::Id_HandoverPreparation(
            ngap_gen::HandoverPreparationFailure {
                protocol_i_es: ngap_gen::HandoverPreparationFailureProtocolIEs(ies),
            },
        ),
    });
    match nextgcore_ngap_gen::encode(&pdu) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            log::error!("Failed to encode Handover Preparation Failure: {e:?}");
            None
        }
    }
}

/// Build a HANDOVER CANCEL ACKNOWLEDGE (TS 38.413 §9.2.3.9) with the GENERATED
/// codec (#417), reporting `notify` -- the Cancel's "ignore IE and notify
/// sender" IEs -- in Criticality Diagnostics (§10.3.4.2). Every IE is
/// criticality ignore.
pub fn build_handover_cancel_acknowledge_asn1(
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u32,
    notify: &[IeDiagnostic],
) -> Option<Vec<u8>> {
    use ngap_gen::{
        HandoverCancelAcknowledgeProtocolIEs_Entry as Entry,
        HandoverCancelAcknowledgeProtocolIEs_EntryValue as Ie, ProtocolIE_ID,
    };
    let ignore = || ngap_gen::Criticality(ngap_gen::Criticality::IGNORE);
    let mut ies = vec![
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_AMF_UE_NGAP_ID),
            criticality: ignore(),
            value: Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(amf_ue_ngap_id)),
        },
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_RAN_UE_NGAP_ID),
            criticality: ignore(),
            value: Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(ran_ue_ngap_id)),
        },
    ];
    if !notify.is_empty() {
        ies.push(Entry {
            id: ProtocolIE_ID(ngap_gen::ID_CRITICALITY_DIAGNOSTICS),
            criticality: ignore(),
            value: Ie::Id_CriticalityDiagnostics(generated_criticality_diagnostics(notify)),
        });
    }
    let pdu = ngap_gen::NGAP_PDU::SuccessfulOutcome(ngap_gen::SuccessfulOutcome {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_HANDOVER_CANCEL),
        criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
        value: ngap_gen::SuccessfulOutcomeValue::Id_HandoverCancel(
            ngap_gen::HandoverCancelAcknowledge {
                protocol_i_es: ngap_gen::HandoverCancelAcknowledgeProtocolIEs(ies),
            },
        ),
    });
    match nextgcore_ngap_gen::encode(&pdu) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            log::error!("Failed to encode Handover Cancel Acknowledge: {e:?}");
            None
        }
    }
}

/// The largest QoS Flow Identifier: a QFI is six bits (TS 23.501 §5.7.1.1).
pub const MAX_QFI: u8 = 63;

/// The largest Bit Rate TS 38.413 §9.3.1.4 defines (bit/s): BitRate is
/// INTEGER (0..4000000000000, ...), and no release defines an extension value.
pub const MAX_BIT_RATE: u64 = 4_000_000_000_000;

/// Build an APER-encoded PDUSessionResourceSetupRequestTransfer
/// (TS 38.413 Section 9.3.4.1) carrying the UPF N3 tunnel endpoint.
///
/// Nothing in the AMF calls this: the N2 SM information the AMF sends is the
/// SMF's transfer, relayed opaquely, and there is no SMF-unreachable fallback
/// that synthesizes one (an unreachable SMF ends in a PDU Session
/// Establishment Reject). It is kept, encoded by the generated codec (#417
/// stage 6) through [`nextgcore_ngap_gen::encode_contained`], as the AMF-side
/// reference for the transfer the SMF builds the same way.
///
/// The bytes are the hand-written transfer encoder's for every input --
/// `n2_sm_setup_request_transfer_generated_matches_hand_written` pins it -- and
/// it refuses what that encoder refused: a QFI past 63, a 5QI past 255, a
/// Priority Level ARP outside 1..15.
pub fn build_n2_sm_setup_request_transfer(
    upf_teid: u32,
    upf_addr: [u8; 4],
    qfi: u8,
    five_qi: u16,
    arp_priority_level: u8,
) -> Option<Vec<u8>> {
    use ngap_gen::{
        PDUSessionResourceSetupRequestTransferProtocolIEs_Entry as Entry,
        PDUSessionResourceSetupRequestTransferProtocolIEs_EntryValue as Ie, ProtocolIE_ID,
    };

    // A QFI is six bits (TS 23.501 §5.7.1.1). QosFlowIdentifier is
    // INTEGER (0..63, ...), so since nextgsim #235 the codec encodes 64..255 as
    // an extension value instead of refusing it -- conformant ASN.1, but not a
    // QFI any 5GS node can hold. Refuse it here, as the hand-written encoder did.
    if qfi > MAX_QFI {
        log::error!(
            "Failed to encode PDUSessionResourceSetupRequestTransfer: QFI {qfi} > {MAX_QFI}"
        );
        return None;
    }
    // FiveQI is INTEGER (0..255, ...) and the generated type a u8, so a 5QI
    // past 255 cannot be carried; the codec itself refuses a Priority Level ARP
    // outside 1..15.
    let Ok(five_qi) = u8::try_from(five_qi) else {
        log::error!("Failed to encode PDUSessionResourceSetupRequestTransfer: 5QI {five_qi} > 255");
        return None;
    };
    let flow = ngap_gen::QosFlowSetupRequestItem {
        qos_flow_identifier: ngap_gen::QosFlowIdentifier(qfi),
        qos_flow_level_qos_parameters: ngap_gen::QosFlowLevelQosParameters {
            qos_characteristics: ngap_gen::QosCharacteristics::NonDynamic5QI(
                ngap_gen::NonDynamic5QIDescriptor {
                    five_qi: ngap_gen::FiveQI(five_qi),
                    priority_level_qos: None,
                    averaging_window: None,
                    maximum_data_burst_volume: None,
                    ie_extensions: None,
                },
            ),
            allocation_and_retention_priority: ngap_gen::AllocationAndRetentionPriority {
                priority_level_arp: ngap_gen::PriorityLevelARP(arp_priority_level),
                pre_emption_capability: ngap_gen::Pre_emptionCapability(
                    ngap_gen::Pre_emptionCapability::SHALL_NOT_TRIGGER_PRE_EMPTION,
                ),
                pre_emption_vulnerability: ngap_gen::Pre_emptionVulnerability(
                    ngap_gen::Pre_emptionVulnerability::NOT_PRE_EMPTABLE,
                ),
                ie_extensions: None,
            },
            gbr_qos_information: None,
            reflective_qos_attribute: None,
            additional_qos_flow_information: None,
            ie_extensions: None,
        },
        e_rab_id: None,
        ie_extensions: None,
    };

    let reject = ngap_gen::Criticality(ngap_gen::Criticality::REJECT);
    // Object-set order (§9.3.4.1): UL NG-U UP TNL Information, PDU Session
    // Type, QoS Flow Setup Request List -- the three mandatory IEs, all reject.
    let ies = vec![
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_UL_NGU_UP_TNL_INFORMATION),
            criticality: reject.clone(),
            value: Ie::Id_UL_NGU_UP_TNLInformation(generated_gtp_tunnel(&upf_addr, 32, upf_teid)),
        },
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_PDU_SESSION_TYPE),
            criticality: reject.clone(),
            value: Ie::Id_PDUSessionType(ngap_gen::PDUSessionType(ngap_gen::PDUSessionType::IPV4)),
        },
        Entry {
            id: ProtocolIE_ID(ngap_gen::ID_QOS_FLOW_SETUP_REQUEST_LIST),
            criticality: reject,
            value: Ie::Id_QosFlowSetupRequestList(ngap_gen::QosFlowSetupRequestList(vec![flow])),
        },
    ];
    let transfer = ngap_gen::PDUSessionResourceSetupRequestTransfer {
        protocol_i_es: ngap_gen::PDUSessionResourceSetupRequestTransferProtocolIEs(ies),
    };

    match nextgcore_ngap_gen::encode_contained(&transfer) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            log::error!("Failed to encode PDUSessionResourceSetupRequestTransfer: {e:?}");
            None
        }
    }
}

/// A GTP tunnel endpoint as the generated `UPTransportLayerInformation`
/// (TS 38.413 §9.3.2.2): the first `bit_len` bits of `address` (32 for IPv4,
/// 128 for IPv6, 160 for both, TS 38.414 §5.1) and the TEID.
fn generated_gtp_tunnel(
    address: &[u8],
    bit_len: usize,
    teid: u32,
) -> ngap_gen::UPTransportLayerInformation {
    let bits = (0..bit_len)
        .map(|i| address[i / 8] & (0x80 >> (i % 8)) != 0)
        .collect();
    ngap_gen::UPTransportLayerInformation::GTPTunnel(ngap_gen::GTPTunnel {
        transport_layer_address: ngap_gen::TransportLayerAddress(bits),
        gtp_teid: ngap_gen::GTP_TEID(teid.to_be_bytes().to_vec()),
        ie_extensions: None,
    })
}

/// A Transport Layer Address's bits as octets, MSB first, the last octet
/// zero-padded -- the form the hand-written codec returned.
fn transport_layer_address_octets(address: &ngap_gen::TransportLayerAddress) -> Vec<u8> {
    address
        .0
        .chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0u8, |octet, (i, bit)| octet | (u8::from(*bit) << (7 - i)))
        })
        .collect()
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
///
/// The AMF only logs the result: the transfer is the SMF's, relayed whatever
/// this says. #417 stage 6 decodes it with the generated codec, skipping
/// protocol extensions the schema does not know; the hand-written decoder
/// consumes them too since #469 (it used to read past the extension
/// container). Every transfer that decoder accepted gives the same endpoint
/// (`n2_sm_setup_response_transfer_generated_matches_hand_written`).
///
/// It also reads the optional Additional DL QoS Flow per TNL Information as the
/// list it is (`QosFlowPerTNLInformationList`, §9.3.4.2), as the hand-written
/// codec now does too (#462; it used to read a single element and misread a
/// dual-connectivity gNB's additional tunnel).
///
/// Since nextgsim #226 the fork octet-aligns a variable-size BIT STRING
/// whatever its length (X.691 §16.11), as the hand-written codec does, so the
/// two read a Transport Layer Address of any length the same way, 16 bits or
/// fewer included (`transport_layer_addresses_of_16_bits_or_fewer_agree`).
///
/// A DL tunnel's `iE-Extensions` entries are skipped like the transfer's own
/// unknown extensions: GTPTunnel's extension object set is empty, so every
/// entry is unknown, and since nextgsim #218 the codec skips it as an open type
/// instead of reading it as zero bits. Their criticality is not acted on here:
/// the transfer is the SMF's to interpret, and the AMF relays it opaquely
/// (TS 23.502), so this parse only feeds the AMF's log.
pub fn parse_n2_sm_setup_response_transfer(data: &[u8]) -> Option<GnbN3Endpoint> {
    let transfer = match nextgcore_ngap_gen::decode_contained_with_unknown_ies::<
        ngap_gen::PDUSessionResourceSetupResponseTransfer,
    >(data)
    {
        Ok((t, _unknown)) => t,
        Err(e) => {
            log::warn!("Failed to decode PDUSessionResourceSetupResponseTransfer: {e:?}");
            return None;
        }
    };

    let dl = transfer.dl_qos_flow_per_tnl_information;
    // UPTransportLayerInformation's choice-Extensions alternative is
    // uninhabited (empty object set, nextgsim #218), so a choice extension on
    // the wire fails the decode above instead of reaching here; a schema that
    // defines one makes this pattern refutable and stops it compiling.
    let ngap_gen::UPTransportLayerInformation::GTPTunnel(tunnel) =
        dl.up_transport_layer_information;
    let teid: [u8; 4] = tunnel.gtp_teid.0.as_slice().try_into().ok()?;

    Some(GnbN3Endpoint {
        teid: u32::from_be_bytes(teid),
        address: transport_layer_address_octets(&tunnel.transport_layer_address),
        qfis: dl
            .associated_qos_flow_list
            .0
            .iter()
            .map(|f| f.qos_flow_identifier.0)
            .collect(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::context::{AmfId, Guami, PlmnId, PlmnSupport, SNssai};
    use nextgcore_ngap::transfer::{
        AllocationAndRetentionPriority, GtpTunnel, NonDynamic5qiDescriptor,
        PduSessionResourceSetupRequestTransfer, PduSessionResourceSetupResponseTransfer,
        PduSessionType, PreEmptionCapability, PreEmptionVulnerability, QosCharacteristics,
        QosFlowLevelQosParameters, QosFlowSetupRequestItem, TransportLayerAddress,
        UpTransportLayerInformation,
    };

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

    /// The hand-written NG Setup encoders exactly as they were before #417
    /// stage 2 moved the family onto the generated codec, and the decoder as it
    /// was before stage 3 -- kept verbatim as the ORACLE the generated output is
    /// compared against.
    mod hand_written_oracle {
        use super::super::*;

        /// Convert an AMF-context S-NSSAI (SD packed as a u32) to the nextgcore-ngap wire
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

        /// The Initial Context Setup Request encoder and Response/Failure parsers as
        /// they were before #417 stage 7 moved the family onto the generated codec.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn hand_written_initial_context_setup_request(
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
                eutra_encryption_algorithms: nas_caps_octet_to_ngap_bits(
                    ue_security_capability.eea,
                ),
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
        pub(crate) fn hand_written_parse_initial_context_setup_response(
            data: &[u8],
        ) -> Option<(u64, u32)> {
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
        pub(crate) fn hand_written_parse_initial_context_setup_failure(
            data: &[u8],
        ) -> Option<(u64, u32)> {
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

        /// The PDU Session Resource Setup Request encoder as it was before
        /// #417 stage 6 moved it onto the generated codec.
        pub(crate) fn hand_written_pdu_session_resource_setup_request(
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
            builder::build_pdu_session_resource_setup_request(&msg).ok()
        }

        /// The PDU Session Resource Setup Response decode as the handler did it
        /// before #417 stage 6: the UE, the set-up and the failed sessions with
        /// their transfers, or nothing when the parser refused the message.
        #[allow(clippy::type_complexity)]
        pub(crate) fn hand_written_parse_pdu_session_resource_setup_response(
            data: &[u8],
        ) -> Option<(u64, u32, Vec<(u8, Vec<u8>)>, Vec<(u8, Vec<u8>)>)> {
            match parser::decode_ngap_pdu(data) {
                Ok(NgapMessage::PduSessionResourceSetupResponse(r)) => Some((
                    r.amf_ue_ngap_id,
                    r.ran_ue_ngap_id,
                    r.setup_list
                        .into_iter()
                        .map(|i| (i.pdu_session_id, i.transfer))
                        .collect(),
                    r.failed_list
                        .into_iter()
                        .map(|i| (i.pdu_session_id, i.transfer))
                        .collect(),
                )),
                _ => None,
            }
        }

        /// `build_n2_sm_setup_request_transfer` as it was before #417 stage 6.
        pub(crate) fn hand_written_n2_sm_setup_request_transfer(
            upf_teid: u32,
            upf_addr: [u8; 4],
            qfi: u8,
            five_qi: u16,
            arp_priority_level: u8,
        ) -> Option<Vec<u8>> {
            use nextgcore_ngap::transfer::{
                AllocationAndRetentionPriority, GtpTunnel, NonDynamic5qiDescriptor,
                PduSessionResourceSetupRequestTransfer, PduSessionType, PreEmptionCapability,
                PreEmptionVulnerability, QosCharacteristics, QosFlowLevelQosParameters,
                QosFlowSetupRequestItem, TransportLayerAddress, UpTransportLayerInformation,
            };
            PduSessionResourceSetupRequestTransfer {
                pdu_session_aggregate_maximum_bit_rate: None,
                ul_ngu_up_tnl_information: UpTransportLayerInformation::GtpTunnel(GtpTunnel {
                    transport_layer_address: TransportLayerAddress::from_ipv4(upf_addr),
                    gtp_teid: upf_teid.to_be_bytes(),
                }),
                data_forwarding_not_possible: false,
                direct_forwarding_path_availability: false,
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
            }
            .encode()
            .ok()
        }

        /// `parse_n2_sm_setup_response_transfer` as it was before #417 stage 6.
        pub(crate) fn hand_written_parse_n2_sm_setup_response_transfer(
            data: &[u8],
        ) -> Option<GnbN3Endpoint> {
            use nextgcore_ngap::transfer::{
                PduSessionResourceSetupResponseTransfer, UpTransportLayerInformation,
            };
            let transfer = PduSessionResourceSetupResponseTransfer::decode(data).ok()?;
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

        /// The UE Context Release Command encoder as it was before #417 stage 4
        /// moved it onto the generated codec.
        pub(crate) fn hand_written_ue_context_release_command(
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
            builder::build_ue_context_release_command(&msg).ok()
        }

        /// The PDU Session Resource Release Command encoder as it was before
        /// #417 stage 5 moved it onto the generated codec.
        pub(crate) fn hand_written_pdu_session_resource_release_command(
            amf_ue_ngap_id: u64,
            ran_ue_ngap_id: u32,
            pdu_session_ids: &[u8],
        ) -> Option<Vec<u8>> {
            use nextgcore_ngap::transfer::PduSessionResourceReleaseCommandTransfer;
            let release_transfer = PduSessionResourceReleaseCommandTransfer {
                cause: Cause::Nas(CauseNas::NormalRelease),
            };
            let transfer_bytes = release_transfer.encode().ok()?;
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
            builder::build_pdu_session_resource_release_command(&msg).ok()
        }

        /// The PDU Session Resource Release Response decode as the handler did
        /// it before #417 stage 5: the UE, and each released session with its
        /// transfer, or nothing when the parser refused the message.
        pub(crate) fn hand_written_parse_pdu_session_resource_release_response(
            data: &[u8],
        ) -> Option<(u64, u32, Vec<(u8, Vec<u8>)>)> {
            match parser::decode_ngap_pdu(data) {
                Ok(NgapMessage::PduSessionResourceReleaseResponse(r)) => Some((
                    r.amf_ue_ngap_id,
                    r.ran_ue_ngap_id,
                    r.released_list
                        .into_iter()
                        .map(|i| (i.pdu_session_id, i.transfer))
                        .collect(),
                )),
                _ => None,
            }
        }

        /// The UE Context Release Complete decoder as it was before #417 stage 4.
        pub(crate) fn hand_written_parse_ue_context_release_complete(data: &[u8]) -> Option<u64> {
            match parser::decode_ngap_pdu(data) {
                Ok(NgapMessage::UeContextReleaseComplete(complete)) => {
                    Some(complete.amf_ue_ngap_id)
                }
                _ => None,
            }
        }

        /// The AMF UE NGAP ID extraction as it was before #447 made the production
        /// extractor procedure-agnostic. Kept because it is half of what the
        /// pre-stage-4 Release Request path could read, which stage 4's equivalence
        /// tests compare against: it only answers for a request the hand-written
        /// parser accepted.
        pub(crate) fn hand_written_extract_amf_ue_ngap_id(data: &[u8]) -> Option<u64> {
            match parser::decode_ngap_pdu(data) {
                Ok(NgapMessage::UeContextReleaseRequest(req)) => Some(req.amf_ue_ngap_id),
                _ => None,
            }
        }

        /// The RAN UE NGAP ID counterpart of [`hand_written_extract_amf_ue_ngap_id`].
        pub(crate) fn hand_written_extract_ran_ue_ngap_id(data: &[u8]) -> Option<u32> {
            match parser::decode_ngap_pdu(data) {
                Ok(NgapMessage::UeContextReleaseRequest(req)) => Some(req.ran_ue_ngap_id),
                _ => None,
            }
        }

        /// The UE Context Release Request Cause extraction as it was before #417
        /// stage 4.
        pub(crate) fn hand_written_extract_release_request_cause(data: &[u8]) -> Option<(u8, i64)> {
            let cause = match parser::decode_ngap_pdu(data) {
                Ok(NgapMessage::UeContextReleaseRequest(req)) => req.cause,
                _ => return None,
            };
            Some(match cause {
                Cause::RadioNetwork(v) => {
                    (crate::ngap_handler::cause_group::RADIO_NETWORK, v as i64)
                }
                Cause::Transport(v) => (crate::ngap_handler::cause_group::TRANSPORT, v as i64),
                Cause::Nas(v) => (crate::ngap_handler::cause_group::NAS, v as i64),
                Cause::Protocol(v) => (crate::ngap_handler::cause_group::PROTOCOL, v as i64),
                Cause::Misc(v) => (crate::ngap_handler::cause_group::MISC, v as i64),
            })
        }

        /// The NG Setup Request decoder as it was before #417 stage 3 moved it
        /// onto the generated codec.
        pub(super) fn hand_written_parse_ng_setup_request(
            data: &[u8],
        ) -> Option<crate::ngap_handler::NgSetupRequest> {
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
                                        ((sd[0] as u32) << 16)
                                            | ((sd[1] as u32) << 8)
                                            | (sd[2] as u32)
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

        /// An NG Setup Failure carrying a Criticality Diagnostics IE, built by
        /// the hand-written `builder::build_ng_setup_failure` -- the oracle for
        /// the stage 3 diagnostics. (Until #445 that builder dropped
        /// `criticality_diagnostics`, and this oracle assembled the PDU from the
        /// IE encoders instead.)
        pub(super) fn hand_written_ng_setup_failure_with_diagnostics(
            cause_group: u8,
            cause_value: i64,
            diagnostics: &[IeDiagnostic],
        ) -> Vec<u8> {
            use nextgcore_asn1c::ngap::types::Criticality;

            let ies = diagnostics
                .iter()
                .map(|d| IeCriticalityDiagnostics {
                    ie_criticality: match d.criticality {
                        0 => Criticality::Reject,
                        1 => Criticality::Ignore,
                        _ => Criticality::Notify,
                    },
                    ie_id: d.ie_id,
                    type_of_error: match d.type_of_error {
                        0 => TypeOfError::NotUnderstood,
                        _ => TypeOfError::Missing,
                    },
                })
                .collect();
            builder::build_ng_setup_failure(&NgSetupFailure {
                cause: build_cause(cause_group, cause_value),
                time_to_wait: Some(TimeToWait::V1s),
                criticality_diagnostics: Some(CriticalityDiagnostics {
                    ies,
                    ..Default::default()
                }),
            })
            .expect("hand-written NG Setup Failure")
        }

        /// Build an NG Setup Response PDU with proper ASN.1 APER encoding
        ///
        /// This is sent by AMF to gNB in response to a successful NG Setup Request.
        /// The message follows 3GPP TS 38.413 Section 9.2.6.2.
        pub(super) fn hand_written_ng_setup_response(ctx: &AmfContext) -> Option<Vec<u8>> {
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

            // amfd-09 (TS 38.413 §9.2.6.2): a strict-peer gNB needs a non-empty
            // PLMNSupportList with slice support for load-balancing / slice selection.
            // An empty list is an AMF misconfiguration; surface it loudly at build time
            // rather than letting the gNB reject the response on the wire.
            if ctx.num_of_plmn_support == 0 {
                log::error!(
                    "NG Setup Response built with an EMPTY PLMNSupportList \
                     (num_of_plmn_support=0); check AMF slice configuration"
                );
                debug_assert!(
                    ctx.num_of_plmn_support > 0,
                    "NGSetupResponse PLMNSupportList must not be empty (TS 38.413 §9.2.6.2)"
                );
            }

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
        pub(super) fn hand_written_ng_setup_failure(
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
    }

    /// A context exercising every field the Response encodes: several GUAMIs
    /// at the bit-width edges, 2- and 3-digit MNCs, slices with and without SD.
    fn rich_context() -> AmfContext {
        let mut ctx = AmfContext::new();
        ctx.amf_name = Some("nextgcore_amf-0 west".to_string());
        ctx.relative_capacity = 0;
        for (plmn, region, set, pointer) in [
            (PlmnId::new("001", "01"), 0u8, 0u16, 0u8),
            (PlmnId::new("310", "260"), 255, 1023, 63),
            (PlmnId::new("999", "70"), 0x5a, 0x2a5, 0x15),
        ] {
            ctx.served_guami.push(Guami {
                plmn_id: plmn,
                amf_id: AmfId {
                    region,
                    set,
                    pointer,
                },
            });
        }
        ctx.num_of_served_guami = 3;
        ctx.plmn_support.push(PlmnSupport {
            plmn_id: PlmnId::new("001", "01"),
            num_of_s_nssai: 3,
            s_nssai: vec![
                SNssai { sst: 1, sd: None },
                SNssai {
                    sst: 2,
                    sd: Some(0x000001),
                },
                SNssai {
                    sst: 255,
                    sd: Some(0xffffff),
                },
            ],
        });
        ctx.plmn_support.push(PlmnSupport {
            plmn_id: PlmnId::new("310", "260"),
            num_of_s_nssai: 1,
            s_nssai: vec![SNssai {
                sst: 3,
                sd: Some(0x123456),
            }],
        });
        ctx.num_of_plmn_support = 2;
        ctx
    }

    /// #417 stage 2: the generated Response is byte-identical to the
    /// hand-written one across every shape the AMF context can take.
    #[test]
    fn ng_setup_generated_matches_hand_written_response() {
        let mut cases = vec![create_test_context(), rich_context()];

        let mut no_name = create_test_context();
        no_name.amf_name = None; // falls back to "AMF"
        cases.push(no_name);

        // Values wider than their BIT STRING: both encoders keep the low bits.
        let mut overwide = create_test_context();
        overwide.served_guami[0].amf_id.set = 1024 + 5;
        overwide.served_guami[0].amf_id.pointer = 64 + 3;
        cases.push(overwide);

        // `take(num_of_*)` bounds the lists, not their Vec length.
        let mut truncated = rich_context();
        truncated.num_of_served_guami = 2;
        truncated.plmn_support[0].num_of_s_nssai = 1;
        cases.push(truncated);

        // An empty ServedGUAMIList violates SIZE(1..256): both refuse.
        let mut no_guami = create_test_context();
        no_guami.num_of_served_guami = 0;
        cases.push(no_guami);

        // Over-long AMF name (SIZE(1..150, ...)): both refuse.
        let mut long_name = create_test_context();
        long_name.amf_name = Some("a".repeat(151));
        cases.push(long_name);

        // An empty PLMNSupportList / SliceSupportList: both refuse. (Built with
        // a non-zero num_of_plmn_support so the amfd-09 debug_assert is not hit.)
        let mut no_slices = create_test_context();
        no_slices.plmn_support[0].num_of_s_nssai = 0;
        cases.push(no_slices);

        // Upper bounds: 13 PLMNs (SIZE(1..12)) and 257 GUAMIs (SIZE(1..256)).
        let mut many_plmns = create_test_context();
        let first = many_plmns.plmn_support[0].clone();
        many_plmns.plmn_support = vec![first; 13];
        many_plmns.num_of_plmn_support = 13;
        cases.push(many_plmns);
        let mut many_guamis = create_test_context();
        let first = many_guamis.served_guami[0].clone();
        many_guamis.served_guami = vec![first; 257];
        many_guamis.num_of_served_guami = 257;
        cases.push(many_guamis);

        // At the upper bounds exactly: both encode.
        let mut at_bounds = create_test_context();
        let first = at_bounds.plmn_support[0].clone();
        at_bounds.plmn_support = vec![first; 12];
        at_bounds.num_of_plmn_support = 12;
        let first = at_bounds.served_guami[0].clone();
        at_bounds.served_guami = vec![first; 256];
        at_bounds.num_of_served_guami = 256;
        at_bounds.amf_name = Some("a".repeat(150));
        cases.push(at_bounds);

        for (i, ctx) in cases.iter().enumerate() {
            assert_eq!(
                build_ng_setup_response_asn1(ctx),
                hand_written_oracle::hand_written_ng_setup_response(ctx),
                "case {i}: generated NG Setup Response differs from hand-written"
            );
        }
        for refused in [5, 6, 7, 8, 9] {
            assert!(
                build_ng_setup_response_asn1(&cases[refused]).is_none(),
                "case {refused}"
            );
        }
        assert!(
            build_ng_setup_response_asn1(&cases[10]).is_some(),
            "at bounds"
        );
    }

    /// AMFName is `PrintableString (SIZE(1..150, ...))`. X.691 §30.5.7 aligns
    /// its content by the type's upper bound, not by the value's length, so a
    /// one-character name is `00 00 41`, not `00 20 80`. The fork aligned by
    /// value length until nextgsim #246 (PR #247); every length 1..=150 must
    /// now agree with the hand-written encoder, which always aligned correctly.
    #[test]
    fn ng_setup_response_amf_name_of_every_length_matches_hand_written() {
        for len in 1..=150usize {
            let mut ctx = create_test_context();
            // Printable characters across the PrintableString alphabet.
            let alphabet = b"AZaz09 '()+,-./:=?";
            let name: String = (0..len)
                .map(|i| alphabet[i % alphabet.len()] as char)
                .collect();
            ctx.amf_name = Some(name);
            assert_eq!(
                build_ng_setup_response_asn1(&ctx),
                hand_written_oracle::hand_written_ng_setup_response(&ctx),
                "AMF name of length {len}"
            );
        }
    }

    /// RANNodeName is `PrintableString (SIZE(1..150, ...))`: the generated
    /// decode must read every length the hand-written encoder writes (#246).
    #[test]
    fn ng_setup_request_ran_node_name_of_every_length_matches_hand_written() {
        for len in 1..=150usize {
            let mut ies = baseline_request_ies();
            ies.ran_node_name = Some("g".repeat(len));
            let data = nextgcore_ngap::builder::build_ng_setup_request(&ies).expect("build");
            let generated = proceed_or_none(&data);
            assert!(generated.is_some(), "RAN node name of length {len} decodes");
            assert_eq!(
                format!("{generated:?}"),
                format!(
                    "{:?}",
                    hand_written_oracle::hand_written_parse_ng_setup_request(&data)
                ),
                "RAN node name of length {len}"
            );
        }
    }

    /// The Paging matrix: every field the hand-written `Paging` carries, one
    /// varied at a time against a 5G-S-TMSI baseline.
    fn paging_cases() -> Vec<Paging> {
        let tai = |n: u8| TaiListItem {
            tai_plmn: [0x00, 0xf1, 0x10],
            tai_tac: [0x00, n, 0x01],
        };
        let base = || Paging {
            ue_paging_identity: UePagingIdentity::FiveGSTmsi {
                amf_set_id: 0x001,
                amf_pointer: 0x01,
                tmsi: 0x1234_5678,
            },
            paging_drx: None,
            tai_list: vec![tai(0)],
            paging_priority: None,
            ue_radio_capability: None,
            paging_origin: None,
            assistance_data: None,
        };
        let mut cases = vec![base()];
        // 5G-S-TMSI at its bit-width edges, and wider than its BIT STRINGs
        // (both encoders keep the low bits).
        for (set, pointer, tmsi) in [
            (0u16, 0u8, 0u32),
            (1023, 63, u32::MAX),
            (0x2a5, 0x15, 0x8000_0001),
            (1024 + 5, 64 + 3, 0x0102_0304),
        ] {
            let mut c = base();
            c.ue_paging_identity = UePagingIdentity::FiveGSTmsi {
                amf_set_id: set,
                amf_pointer: pointer,
                tmsi,
            };
            cases.push(c);
        }
        // TAIListForPaging SIZE(1..16): every length, plus 0 and 17 (refused).
        for n in 0..=17u8 {
            let mut c = base();
            c.tai_list = (0..n).map(tai).collect();
            cases.push(c);
        }
        for drx in [
            PagingDrx::V32,
            PagingDrx::V64,
            PagingDrx::V128,
            PagingDrx::V256,
        ] {
            let mut c = base();
            c.paging_drx = Some(drx);
            cases.push(c);
        }
        for priority in [
            PagingPriority::Priolevel1,
            PagingPriority::Priolevel2,
            PagingPriority::Priolevel3,
            PagingPriority::Priolevel4,
            PagingPriority::Priolevel5,
            PagingPriority::Priolevel6,
            PagingPriority::Priolevel7,
            PagingPriority::Priolevel8,
        ] {
            let mut c = base();
            c.paging_priority = Some(priority);
            cases.push(c);
        }
        // UERadioCapabilityForPaging SEQUENCE values: none, NR only, E-UTRA
        // only, both (ext bit 0, presence bits, then each OCTET STRING).
        for radio_cap in [
            vec![0x00],
            vec![0x40, 0x02, 0x01, 0x02],
            vec![0x20, 0x01, 0xaa],
            vec![0x60, 0x02, 0x01, 0x02, 0x03, 0x0a, 0x0b, 0x0c],
        ] {
            let mut c = base();
            c.ue_radio_capability = Some(radio_cap);
            cases.push(c);
        }
        let mut origin = base();
        origin.paging_origin = Some(PagingOrigin::Non3gpp);
        cases.push(origin);
        // AssistanceDataForPaging {}: ext bit 0, three absent optionals.
        let mut assistance = base();
        assistance.assistance_data = Some(vec![0x00]);
        cases.push(assistance);
        // Everything at once, at the 16-TAI bound.
        let mut all = base();
        all.paging_drx = Some(PagingDrx::V256);
        all.tai_list = (0..16).map(tai).collect();
        all.paging_priority = Some(PagingPriority::Priolevel8);
        all.ue_radio_capability = Some(vec![0x40, 0x02, 0x01, 0x02]);
        all.paging_origin = Some(PagingOrigin::Non3gpp);
        all.assistance_data = Some(vec![0x00]);
        cases.push(all);
        cases
    }

    /// #417 Paging stage: the generated Paging is byte-identical to the
    /// hand-written one across the whole matrix, and both refuse the same
    /// inputs (an empty or 17-entry TAI list).
    #[test]
    fn paging_generated_matches_hand_written() {
        let cases = paging_cases();
        let mut refused = 0;
        for (i, msg) in cases.iter().enumerate() {
            let generated = build_paging_generated(msg);
            let hand_written = builder::build_paging(msg).ok();
            assert_eq!(generated, hand_written, "case {i}: {msg:?}");
            refused += usize::from(generated.is_none());
        }
        assert_eq!(refused, 2, "exactly the 0- and 17-TAI lists are refused");
    }

    /// The production Paging, worked out by hand from X.691 (APER):
    /// `00` initiatingMessage, `18` procedure 24, `40` ignore, `19` length 25;
    /// `00` extension bit, `00 02` two IEs. UEPagingIdentity (115, ignore,
    /// 7 octets): CHOICE index 0, FiveG-S-TMSI extension and presence bits,
    /// AMF Set ID 0000000001, AMF Pointer 000001, pad -- `00 08 20` -- then the
    /// octet-aligned 5G-TMSI `12 34 56 78`. TAIListForPaging (103, ignore,
    /// 7 octets): count-1 = 0 in 4 bits, item and TAI extension and presence
    /// bits -- `00` -- PLMN 001/01 `00 f1 10`, TAC 1 `00 00 01`.
    #[test]
    fn paging_production_shape_is_the_hand_derived_golden() {
        let bytes =
            build_paging_asn1(1, 1, 0x1234_5678, &PlmnId::new("001", "01"), 1).expect("paging");
        assert_eq!(
            bytes,
            [
                0x00, 0x18, 0x40, 0x19, 0x00, 0x00, 0x02, // PDU, Paging, 2 IEs
                0x00, 0x73, 0x40, 0x07, 0x00, 0x08, 0x20, 0x12, 0x34, 0x56, 0x78, 0x00, 0x67, 0x40,
                0x07, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x01,
            ]
        );
    }

    /// PagingPriority: priolevel N is ENUMERATED index N-1 (TS 38.413
    /// §9.3.1.78). Both encoders must put priolevel1 on the wire as index 0 and
    /// priolevel8 as index 7, which the generated decoder reads back by name.
    #[test]
    fn paging_priority_levels_are_root_indices_0_to_7() {
        for (priority, index) in [
            (
                PagingPriority::Priolevel1,
                ngap_gen::PagingPriority::PRIOLEVEL1,
            ),
            (
                PagingPriority::Priolevel2,
                ngap_gen::PagingPriority::PRIOLEVEL2,
            ),
            (
                PagingPriority::Priolevel8,
                ngap_gen::PagingPriority::PRIOLEVEL8,
            ),
        ] {
            let mut msg = paging_cases().remove(0);
            msg.paging_priority = Some(priority);
            for (who, bytes) in [
                (
                    "generated",
                    build_paging_generated(&msg).expect("generated"),
                ),
                (
                    "hand-written",
                    builder::build_paging(&msg).expect("hand-written"),
                ),
            ] {
                let ngap_gen::NGAP_PDU::InitiatingMessage(init) =
                    nextgcore_ngap_gen::decode(&bytes).expect("decode")
                else {
                    panic!("{who}: not an initiating message");
                };
                let ngap_gen::InitiatingMessageValue::Id_Paging(paging) = init.value else {
                    panic!("{who}: not a Paging");
                };
                let got = paging.protocol_i_es.0.iter().find_map(|e| match &e.value {
                    ngap_gen::PagingProtocolIEs_EntryValue::Id_PagingPriority(p) => Some(p.0),
                    _ => None,
                });
                assert_eq!(got, Some(index), "{who}: {priority:?}");
            }
        }
    }

    /// A UERadioCapabilityForPaging that is not a valid encoding of its type
    /// is refused by the generated builder, where the hand-written one copied
    /// the bytes onto the wire verbatim.
    #[test]
    fn paging_refuses_a_malformed_radio_capability() {
        let mut msg = paging_cases().remove(0);
        // Presence bit for the NR member set, then nothing: truncated.
        msg.ue_radio_capability = Some(vec![0x40]);
        assert!(build_paging_generated(&msg).is_none());
        assert!(builder::build_paging(&msg).is_ok());
    }

    /// #417 stage 2: the generated Failure is byte-identical to the
    /// hand-written one for every cause group, in- and out-of-range values
    /// (including radioNetwork extension values 45/46), and every TimeToWait.
    #[test]
    fn ng_setup_generated_matches_hand_written_failure() {
        let values: [i64; 18] = [
            -1, 0, 1, 2, 3, 4, 5, 6, 7, 20, 44, 45, 46, 47, 200, 255, 256, 1000,
        ];
        let waits = [
            None,
            Some(0),
            Some(1),
            Some(2),
            Some(3),
            Some(4),
            Some(5),
            Some(6),
            Some(255),
        ];
        for group in 0u8..=6 {
            for &value in &values {
                for &ttw in &waits {
                    assert_eq!(
                        build_ng_setup_failure_asn1(group, value, ttw),
                        hand_written_oracle::hand_written_ng_setup_failure(group, value, ttw),
                        "group {group} value {value} ttw {ttw:?}"
                    );
                }
            }
        }
    }

    /// Every cause the AMF can produce -- radioNetwork extension values 45/46
    /// included -- is encoded by the generated codec and decodes back to the
    /// same (group, wire value). Stage 2 sent 45/46 to a hand-written fallback,
    /// which emitted the same bytes and so was invisible to the equivalence
    /// test; with the fallback deleted there is one path, and this pins that it
    /// carries every value.
    #[test]
    fn ng_setup_failure_every_cause_takes_the_generated_codec() {
        use ngap_gen::{NGSetupFailureProtocolIEs_EntryValue as Ie, UnsuccessfulOutcomeValue};
        for (group, last) in [(0u8, 46i64), (1, 1), (2, 3), (3, 6), (4, 5)] {
            for value in 0..=last {
                let bytes = build_ng_setup_failure_asn1(group, value, None);
                let pdu = nextgcore_ngap_gen::decode(&bytes)
                    .unwrap_or_else(|e| panic!("group {group} value {value}: {e:?}"));
                let ngap_gen::NGAP_PDU::UnsuccessfulOutcome(outcome) = pdu else {
                    panic!("group {group} value {value}: not an unsuccessfulOutcome");
                };
                let UnsuccessfulOutcomeValue::Id_NGSetup(failure) = outcome.value else {
                    panic!("group {group} value {value}: not NG Setup Failure");
                };
                let cause = failure
                    .protocol_i_es
                    .0
                    .iter()
                    .find_map(|e| match &e.value {
                        Ie::Id_Cause(c) => Some(c.clone()),
                        _ => None,
                    })
                    .expect("Cause IE");
                let decoded = match cause {
                    ngap_gen::Cause::RadioNetwork(c) => (0, c.0),
                    ngap_gen::Cause::Transport(c) => (1, c.0),
                    ngap_gen::Cause::Nas(c) => (2, c.0),
                    ngap_gen::Cause::Protocol(c) => (3, c.0),
                    ngap_gen::Cause::Misc(c) => (4, c.0),
                    other => panic!("group {group} value {value}: {other:?}"),
                };
                assert_eq!(decoded, (group, value as u8), "group {group} value {value}");
            }
        }
    }

    /// Golden bytes, so the equivalence above cannot pass by both encoders
    /// drifting together. Byte 0 is the CHOICE index (1 = successfulOutcome,
    /// 2 = unsuccessfulOutcome) and byte 1 the procedure code, id-NGSetup = 21.
    #[test]
    fn ng_setup_generated_golden_bytes() {
        let response = build_ng_setup_response_asn1(&create_test_context()).expect("build");
        assert_eq!(hex(&response), GOLDEN_RESPONSE);
        assert_eq!(
            response[0], 0x20,
            "successfulOutcome CHOICE index in byte 0"
        );
        assert_eq!(response[1], 21, "id-NGSetup");

        let failure = build_ng_setup_failure_asn1(4, 4, Some(2));
        assert_eq!(hex(&failure), GOLDEN_FAILURE);
        assert_eq!(
            failure[0], 0x40,
            "unsuccessfulOutcome CHOICE index in byte 0"
        );
        assert_eq!(failure[1], 21, "id-NGSetup");
    }

    const GOLDEN_RESPONSE: &str =
        "2015002e0000040001000a0380414d462d5465737400600008000099f90702004000564001ff005000080099f90700000008";
    const GOLDEN_FAILURE: &str = "4015000d000002000f400188006b400120";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A well-formed NG Setup Request from a gNB serving TAC 1 in 999/70.
    fn baseline_request_ies() -> NgSetupRequest {
        NgSetupRequest {
            global_ran_node_id: GlobalRanNodeId::GlobalGnbId {
                plmn_identity: [0x99, 0xf9, 0x07],
                gnb_id: 1,
                gnb_id_len: 32,
            },
            ran_node_name: None,
            supported_ta_list: vec![SupportedTaItem {
                tac: [0, 0, 1],
                broadcast_plmn_list: vec![BroadcastPlmnItem {
                    plmn_identity: [0x99, 0xf9, 0x07],
                    tai_slice_support_list: vec![nextgcore_ngap::types::SNssai {
                        sst: 1,
                        sd: None,
                    }],
                }],
            }],
            default_paging_drx: PagingDrx::V128,
        }
    }

    pub(crate) fn baseline_request() -> Vec<u8> {
        nextgcore_ngap::builder::build_ng_setup_request(&baseline_request_ies()).expect("build")
    }

    /// `request` with one more protocol IE appended: `id`, criticality octet
    /// (0x00 reject, 0x40 ignore, 0x80 notify), a one-octet value. Layout:
    /// [0]=CHOICE, [1]=procedure code, [2]=criticality, [3]=open-type length
    /// (short form), [4]=SEQUENCE extension bit + padding, [5..7]=IE count,
    /// then the IEs.
    pub(crate) fn with_unknown_ie(request: &[u8], id: u16, criticality: u8) -> Vec<u8> {
        let mut spliced = request.to_vec();
        assert!(
            spliced[3] < 0x7b,
            "short-form length leaves room for 5 octets"
        );
        let count = u16::from_be_bytes([spliced[5], spliced[6]]) + 1;
        spliced[5..7].copy_from_slice(&count.to_be_bytes());
        let [hi, lo] = id.to_be_bytes();
        spliced.extend_from_slice(&[hi, lo, criticality, 0x01, 0x00]);
        spliced[3] += 5;
        spliced
    }

    /// `request` with the protocol IE `id` removed, re-encoded by the
    /// generated codec.
    fn without_ie(request: &[u8], id: u16) -> Vec<u8> {
        let mut pdu = nextgcore_ngap_gen::decode(request).expect("decode");
        let ngap_gen::NGAP_PDU::InitiatingMessage(ref mut msg) = pdu else {
            panic!("initiatingMessage");
        };
        let ngap_gen::InitiatingMessageValue::Id_NGSetup(ref mut req) = msg.value else {
            panic!("NG Setup Request");
        };
        req.protocol_i_es.0.retain(|e| e.id.0 != id);
        nextgcore_ngap_gen::encode(&pdu).expect("encode")
    }

    /// The decode outcome flattened to what the hand-written parser could say:
    /// a request, or nothing. A `Reject` never comes out of a request the old
    /// parser accepted, so it is a test failure here.
    fn proceed_or_none(data: &[u8]) -> Option<crate::ngap_handler::NgSetupRequest> {
        match decode_ng_setup_request_asn1(data) {
            NgSetupRequestDecode::Proceed { request, notify } => {
                assert!(notify.is_empty(), "no IE to report in {data:02x?}");
                Some(request)
            }
            NgSetupRequestDecode::Undecodable => None,
            NgSetupRequestDecode::Reject(d) => panic!("unexpected Reject({d:?}) for {data:02x?}"),
        }
    }

    /// #417 stage 3: the generated decode yields exactly what the hand-written
    /// parser yielded, request for request, and refuses what it refused.
    #[test]
    fn ng_setup_request_generated_decode_matches_hand_written() {
        let mut requests = Vec::new();
        for (gnb_id, gnb_id_len) in [
            (0u32, 22u8),
            (0x3f_ffff, 22),
            (0x1_2345, 25),
            (u32::MAX, 32),
        ] {
            let mut ies = baseline_request_ies();
            ies.global_ran_node_id = GlobalRanNodeId::GlobalGnbId {
                plmn_identity: [0x13, 0x00, 0x62],
                gnb_id,
                gnb_id_len,
            };
            requests.push(ies);
        }
        let mut ng_enb = baseline_request_ies();
        ng_enb.global_ran_node_id = GlobalRanNodeId::GlobalNgEnbId {
            plmn_identity: [0x00, 0xf1, 0x10],
            ng_enb_id: 0xabcde,
        };
        requests.push(ng_enb);
        for drx in [
            PagingDrx::V32,
            PagingDrx::V64,
            PagingDrx::V128,
            PagingDrx::V256,
        ] {
            let mut ies = baseline_request_ies();
            ies.default_paging_drx = drx;
            ies.ran_node_name = Some("gnb-west 1".to_string());
            requests.push(ies);
        }
        let mut rich = baseline_request_ies();
        rich.ran_node_name = Some("x".repeat(150));
        rich.supported_ta_list = (0..3u8)
            .map(|t| SupportedTaItem {
                tac: [t, 0xff, 0x10],
                broadcast_plmn_list: vec![
                    BroadcastPlmnItem {
                        plmn_identity: [0x99, 0xf9, 0x07],
                        tai_slice_support_list: vec![
                            nextgcore_ngap::types::SNssai { sst: 1, sd: None },
                            nextgcore_ngap::types::SNssai {
                                sst: 255,
                                sd: Some([0x00, 0x00, 0x01]),
                            },
                        ],
                    },
                    BroadcastPlmnItem {
                        plmn_identity: [0x13, 0x00, 0x62],
                        tai_slice_support_list: vec![nextgcore_ngap::types::SNssai {
                            sst: 2,
                            sd: Some([0xff, 0xff, 0xff]),
                        }],
                    },
                ],
            })
            .collect();
        requests.push(rich);

        let mut inputs: Vec<Vec<u8>> = requests
            .iter()
            .map(|r| nextgcore_ngap::builder::build_ng_setup_request(r).expect("build"))
            .collect();
        // Refused by both: garbage, a truncation, and a PDU that is not a request.
        inputs.push(vec![0x00, 0x15, 0x00, 0x01, 0xff]);
        let baseline = baseline_request();
        inputs.push(baseline[..baseline.len() - 1].to_vec());
        inputs.push(build_ng_setup_response_asn1(&create_test_context()).expect("response"));
        inputs.push(Vec::new());

        for (i, data) in inputs.iter().enumerate() {
            assert_eq!(
                format!("{:?}", proceed_or_none(data)),
                format!(
                    "{:?}",
                    hand_written_oracle::hand_written_parse_ng_setup_request(data)
                ),
                "input {i}: {data:02x?}"
            );
        }
        for (i, data) in inputs.iter().enumerate().take(requests.len()) {
            assert!(proceed_or_none(data).is_some(), "request {i} decodes");
        }
    }

    /// §10.3.4.2 "Ignore IE": a not-comprehended IE marked ignore is dropped,
    /// and the procedure runs on the rest as if it had not been sent.
    #[test]
    fn ng_setup_request_unknown_ignore_ie_proceeds_silently() {
        let baseline = baseline_request();
        let spliced = with_unknown_ie(&baseline, 9999, 0x40);
        let NgSetupRequestDecode::Proceed { request, notify } =
            decode_ng_setup_request_asn1(&spliced)
        else {
            panic!("an ignorable unknown IE must not stop the procedure");
        };
        assert!(notify.is_empty(), "ignore is not reported: {notify:?}");
        assert_eq!(
            format!("{request:?}"),
            format!("{:?}", proceed_or_none(&baseline).expect("baseline")),
        );
    }

    /// §10.3.4.2 "Ignore IE and Notify Sender": the procedure runs, and the IE
    /// is handed back to be reported as not understood.
    #[test]
    fn ng_setup_request_unknown_notify_ie_proceeds_and_is_reported() {
        let baseline = baseline_request();
        let spliced = with_unknown_ie(&baseline, 9999, 0x80);
        let NgSetupRequestDecode::Proceed { request, notify } =
            decode_ng_setup_request_asn1(&spliced)
        else {
            panic!("a notify unknown IE must not stop the procedure");
        };
        assert_eq!(
            notify,
            vec![IeDiagnostic {
                ie_id: 9999,
                criticality: ngap_gen::Criticality::NOTIFY,
                type_of_error: ngap_gen::TypeOfError::NOT_UNDERSTOOD,
            }]
        );
        assert_eq!(
            format!("{request:?}"),
            format!("{:?}", proceed_or_none(&baseline).expect("baseline")),
        );
    }

    /// §10.3.4.2 "Reject IE": none of the request is executed, and the IE is
    /// reported -- alongside a notify IE, which does not soften it.
    #[test]
    fn ng_setup_request_unknown_reject_ie_rejects_the_request() {
        let baseline = baseline_request();
        let spliced = with_unknown_ie(&baseline, 9999, 0x00);
        let reject_9999 = IeDiagnostic {
            ie_id: 9999,
            criticality: ngap_gen::Criticality::REJECT,
            type_of_error: ngap_gen::TypeOfError::NOT_UNDERSTOOD,
        };
        assert!(
            matches!(decode_ng_setup_request_asn1(&spliced), NgSetupRequestDecode::Reject(ref d) if *d == [reject_9999]),
            "{:?}",
            decode_ng_setup_request_asn1(&spliced)
        );
        let both = with_unknown_ie(&with_unknown_ie(&baseline, 9998, 0x80), 9999, 0x00);
        assert!(
            matches!(decode_ng_setup_request_asn1(&both), NgSetupRequestDecode::Reject(ref d) if *d == [reject_9999]),
            "{:?}",
            decode_ng_setup_request_asn1(&both)
        );
    }

    /// §10.3.5: GlobalRANNodeID and SupportedTAList are criticality reject
    /// (§9.2.6.1), so either one missing rejects the request, reported as
    /// missing. DefaultPagingDRX is criticality ignore: absent, it defaults.
    #[test]
    fn ng_setup_request_missing_mandatory_ie_is_rejected_as_missing() {
        let baseline = baseline_request();
        for id in [
            ngap_gen::ID_GLOBAL_RAN_NODE_ID,
            ngap_gen::ID_SUPPORTED_TA_LIST,
        ] {
            let data = without_ie(&baseline, id);
            let expected = vec![IeDiagnostic {
                ie_id: id,
                criticality: ngap_gen::Criticality::REJECT,
                type_of_error: ngap_gen::TypeOfError::MISSING,
            }];
            assert!(
                matches!(decode_ng_setup_request_asn1(&data), NgSetupRequestDecode::Reject(ref d) if *d == expected),
                "IE {id}: {:?}",
                decode_ng_setup_request_asn1(&data)
            );
        }
        let no_drx = without_ie(&baseline, ngap_gen::ID_DEFAULT_PAGING_DRX);
        let request = proceed_or_none(&no_drx).expect("DefaultPagingDRX absent still proceeds");
        assert_eq!(request.default_paging_drx, ngap_gen::PagingDRX::V128);
    }

    fn reject_and_missing() -> Vec<IeDiagnostic> {
        vec![
            IeDiagnostic {
                ie_id: 9999,
                criticality: ngap_gen::Criticality::REJECT,
                type_of_error: ngap_gen::TypeOfError::NOT_UNDERSTOOD,
            },
            IeDiagnostic {
                ie_id: ngap_gen::ID_SUPPORTED_TA_LIST,
                criticality: ngap_gen::Criticality::REJECT,
                type_of_error: ngap_gen::TypeOfError::MISSING,
            },
            IeDiagnostic {
                ie_id: 9998,
                criticality: ngap_gen::Criticality::NOTIFY,
                type_of_error: ngap_gen::TypeOfError::NOT_UNDERSTOOD,
            },
        ]
    }

    /// The Failure's Criticality Diagnostics IE is the one the hand-written
    /// encoder would have built, byte for byte, and without diagnostics the
    /// Failure is unchanged.
    #[test]
    fn ng_setup_failure_diagnostics_match_hand_written() {
        let all = reject_and_missing();
        for diagnostics in [&all[..1], &all[..]] {
            assert_eq!(
                build_ng_setup_failure_with_diagnostics_asn1(
                    3,
                    crate::ngap_handler::protocol_cause::ABSTRACT_SYNTAX_ERROR_REJECT,
                    Some(0),
                    diagnostics,
                ),
                hand_written_oracle::hand_written_ng_setup_failure_with_diagnostics(
                    3,
                    crate::ngap_handler::protocol_cause::ABSTRACT_SYNTAX_ERROR_REJECT,
                    diagnostics,
                ),
                "{diagnostics:?}"
            );
        }
        assert_eq!(
            build_ng_setup_failure_with_diagnostics_asn1(4, 4, Some(2), &[]),
            build_ng_setup_failure_asn1(4, 4, Some(2)),
        );
    }

    /// The Response reports notify IEs in Criticality Diagnostics (id 19,
    /// criticality ignore), which a peer on either codec decodes; without them
    /// the bytes are the stage 2 Response's; and the list is cut at
    /// maxnoofErrors rather than refused.
    #[test]
    fn ng_setup_response_reports_notify_ies_in_criticality_diagnostics() {
        use ngap_gen::{NGSetupResponseProtocolIEs_EntryValue as Ie, SuccessfulOutcomeValue};
        let ctx = create_test_context();
        assert_eq!(
            build_ng_setup_response_with_diagnostics_asn1(&ctx, &[]),
            build_ng_setup_response_asn1(&ctx)
        );
        let notify = vec![reject_and_missing()[2]];
        let many = vec![notify[0]; 300];
        for (diagnostics, reported) in [(&notify, 1usize), (&many, 256)] {
            let bytes =
                build_ng_setup_response_with_diagnostics_asn1(&ctx, diagnostics).expect("build");
            assert!(
                matches!(
                    parser::decode_ngap_pdu(&bytes),
                    Ok(NgapMessage::NgSetupResponse(_))
                ),
                "the hand-written decoder still reads the Response"
            );
            let ngap_gen::NGAP_PDU::SuccessfulOutcome(outcome) =
                nextgcore_ngap_gen::decode(&bytes).expect("decode")
            else {
                panic!("successfulOutcome");
            };
            let SuccessfulOutcomeValue::Id_NGSetup(response) = outcome.value else {
                panic!("NG Setup Response");
            };
            let last = response.protocol_i_es.0.last().expect("IEs");
            assert_eq!(last.id.0, ngap_gen::ID_CRITICALITY_DIAGNOSTICS, "last IE");
            assert_eq!(last.criticality.0, ngap_gen::Criticality::IGNORE);
            let Ie::Id_CriticalityDiagnostics(cd) = &last.value else {
                panic!("Criticality Diagnostics");
            };
            assert_eq!(cd.procedure_code, None);
            assert_eq!(cd.triggering_message, None);
            let list = &cd.i_es_criticality_diagnostics.as_ref().expect("IE list").0;
            assert_eq!(list.len(), reported);
            assert_eq!(list[0].ie_id.0, 9998);
            assert_eq!(list[0].ie_criticality.0, ngap_gen::Criticality::NOTIFY);
            assert_eq!(
                list[0].type_of_error.0,
                ngap_gen::TypeOfError::NOT_UNDERSTOOD
            );
        }
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

    /// amfd-09 — NG Setup Response field-completeness regression guard
    /// (TS 38.413 §9.2.6.2). Every NGSetupResponse must carry amfName, a
    /// non-empty servedGUAMIList, a non-empty PLMNSupportList with slice
    /// support, and a relativeAMFCapacity in range, so a strict-peer gNB can
    /// load-balance and select slices.
    #[test]
    fn amfd09_ng_setup_response_field_completeness() {
        let ctx = create_test_context();
        let bytes = build_ng_setup_response_asn1(&ctx).expect("build NG Setup Response");

        let decoded = parser::decode_ngap_pdu(&bytes).expect("decode");
        let NgapMessage::NgSetupResponse(resp) = decoded else {
            panic!("expected NgSetupResponse");
        };

        // amfName present and as configured.
        assert_eq!(resp.amf_name, "AMF-Test", "amfName missing/incorrect");
        // servedGUAMIList non-empty.
        assert!(
            !resp.served_guami_list.is_empty(),
            "servedGUAMIList must be present and non-empty"
        );
        // relativeAMFCapacity in range 0..=255 (u8) — assert the configured value.
        assert_eq!(resp.relative_amf_capacity, 255, "relativeAMFCapacity");
        // PLMNSupportList non-empty, with at least one slice in slice support.
        assert!(
            !resp.plmn_support_list.is_empty(),
            "PLMNSupportList must be present and non-empty"
        );
        assert!(
            resp.plmn_support_list
                .iter()
                .all(|p| !p.slice_support_list.is_empty()),
            "every PLMNSupportItem must carry at least one S-NSSAI"
        );
        assert_eq!(resp.plmn_support_list[0].slice_support_list[0].sst, 1);
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
        let bytes = build_ng_reset_acknowledge_asn1(None, &[]).expect("build");
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
        let bytes = build_ng_reset_acknowledge_asn1(Some(connections.clone()), &[]).expect("build");
        match parser::decode_ngap_pdu(&bytes).expect("decode") {
            NgapMessage::NgResetAcknowledge(ack) => {
                assert_eq!(ack.connections, Some(connections));
            }
            other => panic!("Expected NgResetAcknowledge, got {other:?}"),
        }
    }

    /// The NG Resets the equivalence tests sweep: both reset types, connection
    /// lists of 1, 2 and 16 items, every presence combination of the two
    /// optional IDs, and IDs at the edges of their ranges, under a Cause from
    /// every group.
    fn ng_reset_matrix() -> Vec<NgReset> {
        let causes = [
            Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            Cause::Transport(CauseTransport::TransportResourceUnavailable),
            Cause::Nas(CauseNas::NormalRelease),
            Cause::Protocol(CauseProtocol::SemanticError),
            Cause::Misc(CauseMisc::OmIntervention),
        ];
        let ids: [(Option<u64>, Option<u32>); 5] = [
            (Some(0), Some(0)),
            (Some((1u64 << 40) - 1), Some(u32::MAX)),
            (Some(7), None),
            (None, Some(70)),
            (Some(256), Some(65_536)),
        ];
        let mut out = Vec::new();
        for cause in causes {
            out.push(NgReset {
                cause,
                reset_type: ResetType::NgInterface,
            });
            for (amf, ran) in ids {
                out.push(NgReset {
                    cause,
                    reset_type: ResetType::PartOfNgInterface(vec![
                        UeAssociatedLogicalNgConnectionItem {
                            amf_ue_ngap_id: amf,
                            ran_ue_ngap_id: ran,
                        },
                    ]),
                });
            }
            out.push(NgReset {
                cause,
                reset_type: ResetType::PartOfNgInterface(
                    ids.iter()
                        .take(2)
                        .map(|&(amf, ran)| UeAssociatedLogicalNgConnectionItem {
                            amf_ue_ngap_id: amf,
                            ran_ue_ngap_id: ran,
                        })
                        .collect(),
                ),
            });
            out.push(NgReset {
                cause,
                reset_type: ResetType::PartOfNgInterface(
                    (0..16)
                        .map(|i| UeAssociatedLogicalNgConnectionItem {
                            amf_ue_ngap_id: Some(1000 + i),
                            ran_ue_ngap_id: (i % 2 == 0).then_some(i as u32),
                        })
                        .collect(),
                ),
            });
        }
        out
    }

    /// #417: every NG Reset the hand-written parser accepted decodes, through
    /// the generated codec, to the same reset -- with nothing to report.
    #[test]
    fn ng_reset_generated_decode_matches_hand_written() {
        let matrix = ng_reset_matrix();
        assert_eq!(matrix.len(), 40);
        for reset in matrix {
            let bytes = builder::build_ng_reset(&reset).expect("hand-written build");
            let NgapMessage::NgReset(old) = parser::decode_ngap_pdu(&bytes).expect("old decode")
            else {
                panic!("old parser: not an NG Reset");
            };
            let NgResetDecode::Proceed { reset: new, notify } = decode_ng_reset_asn1(&bytes) else {
                panic!("generated decode did not proceed for {reset:?}");
            };
            assert!(notify.is_empty());
            assert_eq!(new.reset_type, old.reset_type, "{bytes:02x?}");
            assert_eq!(format!("{:?}", new.cause), format!("{:?}", old.cause));
        }
    }

    /// #417: the generated NG Reset Acknowledge is byte-identical to the
    /// hand-written builder for every connection list the matrix holds, and for
    /// a full reset.
    #[test]
    fn ng_reset_acknowledge_generated_matches_hand_written() {
        for reset in ng_reset_matrix() {
            let connections = match reset.reset_type {
                ResetType::NgInterface => None,
                ResetType::PartOfNgInterface(items) => Some(items),
            };
            let old = builder::build_ng_reset_acknowledge(&NgResetAcknowledge {
                connections: connections.clone(),
                criticality_diagnostics: None,
            })
            .expect("hand-written build");
            let new = build_ng_reset_acknowledge_asn1(connections, &[]).expect("generated build");
            assert_eq!(new, old);
        }
    }

    /// The full-reset Acknowledge, derived from X.691 by hand: successfulOutcome
    /// (CHOICE index 1 of 3, extensible: `0 01` + pad = 0x20), procedure code
    /// 20, criticality reject (0x00), a 3-octet open type holding the SEQUENCE
    /// extension bit (0, padded) and an empty IE container (count 0x0000).
    #[test]
    fn ng_reset_acknowledge_golden_bytes() {
        assert_eq!(
            build_ng_reset_acknowledge_asn1(None, &[]).expect("build"),
            [0x20, 0x14, 0x00, 0x03, 0x00, 0x00, 0x00]
        );
    }

    /// The partial forms, derived from X.691 by hand. The connection list is
    /// SIZE (1..maxnoofNGConnectionsToReset = 65536); its upper bound is 64K,
    /// so §11.9.4.2 encodes the count as a general length determinant (`01`
    /// for one item), not the two-octet constrained count (`00 00`) the
    /// hand-written codec wrote before #417 -- which made the AMF misread a
    /// conformant gNB's partial NG Reset and send a non-conformant Acknowledge.
    /// The item: `60` = extension bit 0, AMF and RAN UE NGAP ID present, no
    /// iE-Extensions, then each ID as a 1-octet length-in-bits field (all zero)
    /// and its aligned value octet `00`.
    #[test]
    fn ng_reset_partial_golden_bytes() {
        let item = UeAssociatedLogicalNgConnectionItem {
            amf_ue_ngap_id: Some(0),
            ran_ue_ngap_id: Some(0),
        };
        // ResetType = partOfNG-Interface (CHOICE 1 of 3, no extension marker:
        // `01` + pad = 0x40), count 1, the item.
        let reset = builder::build_ng_reset(&NgReset {
            cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            reset_type: ResetType::PartOfNgInterface(vec![item.clone()]),
        })
        .expect("build");
        assert_eq!(
            reset,
            [
                0x00, 0x14, 0x00, 0x13, 0x00, 0x00, 0x02, // header, 2 IEs
                0x00, 0x0f, 0x40, 0x02, 0x00, 0x00, // Cause radioNetwork/unspecified
                0x00, 0x58, 0x00, 0x06, 0x40, 0x01, 0x60, 0x00, 0x00, 0x00, // ResetType
            ]
        );
        assert!(matches!(
            decode_ng_reset_asn1(&reset),
            NgResetDecode::Proceed { reset: NgReset { reset_type: ResetType::PartOfNgInterface(ref l), .. }, .. }
                if *l == vec![item.clone()]
        ));
        assert_eq!(
            build_ng_reset_acknowledge_asn1(Some(vec![item]), &[]).expect("ack"),
            [
                0x20, 0x14, 0x00, 0x0c, 0x00, 0x00, 0x01, // header, 1 IE
                0x00, 0x6f, 0x40, 0x05, 0x01, 0x60, 0x00, 0x00, 0x00, // the list
            ]
        );
    }

    /// §10.3.4.2 for NG Reset: an unknown "ignore" IE is dropped, a "notify"
    /// one is reported in the Acknowledge, a "reject" one -- or a missing
    /// Reset Type -- terminates the procedure with an Error Indication.
    #[test]
    fn ng_reset_unknown_and_missing_ies_follow_their_criticality() {
        let base = builder::build_ng_reset(&NgReset {
            cause: Cause::Misc(CauseMisc::Unspecified),
            reset_type: ResetType::NgInterface,
        })
        .expect("build");

        let ignored = with_unknown_ie(&base, 9999, 0x40);
        assert!(matches!(
            decode_ng_reset_asn1(&ignored),
            NgResetDecode::Proceed { ref notify, .. } if notify.is_empty()
        ));

        let notified = with_unknown_ie(&base, 9999, 0x80);
        let NgResetDecode::Proceed { notify, .. } = decode_ng_reset_asn1(&notified) else {
            panic!("notify must proceed");
        };
        assert_eq!(notify.len(), 1);
        assert_eq!(notify[0].ie_id, 9999);
        // ... and the Acknowledge carries it.
        let ack = build_ng_reset_acknowledge_asn1(None, &notify).expect("ack");
        let ngap_gen::NGAP_PDU::SuccessfulOutcome(out) = nextgcore_ngap_gen::decode(&ack).unwrap()
        else {
            panic!("successfulOutcome");
        };
        let ngap_gen::SuccessfulOutcomeValue::Id_NGReset(ack) = out.value else {
            panic!("NG Reset Acknowledge");
        };
        let diag = ack
            .protocol_i_es
            .0
            .iter()
            .find_map(|e| match &e.value {
                ngap_gen::NGResetAcknowledgeProtocolIEs_EntryValue::Id_CriticalityDiagnostics(
                    d,
                ) => Some(d.clone()),
                _ => None,
            })
            .expect("Criticality Diagnostics");
        let item = &diag.i_es_criticality_diagnostics.unwrap().0[0];
        assert_eq!(item.ie_id.0, 9999);
        assert_eq!(item.ie_criticality.0, ngap_gen::Criticality::NOTIFY);

        let rejected = with_unknown_ie(&base, 9999, 0x00);
        let NgResetDecode::Reject(report) = decode_ng_reset_asn1(&rejected) else {
            panic!("reject must terminate the procedure");
        };
        assert_eq!(report.procedure.procedure_code, ngap_gen::ID_NG_RESET);
        assert_eq!(report.diagnostics[0].ie_id, 9999);

        // Reset Type removed: mandatory with criticality reject.
        let mut pdu = nextgcore_ngap_gen::decode(&base).expect("decode");
        let ngap_gen::NGAP_PDU::InitiatingMessage(ref mut msg) = pdu else {
            panic!("initiatingMessage");
        };
        let ngap_gen::InitiatingMessageValue::Id_NGReset(ref mut req) = msg.value else {
            panic!("NG Reset");
        };
        req.protocol_i_es
            .0
            .retain(|e| e.id.0 != ngap_gen::ID_RESET_TYPE);
        let no_type = nextgcore_ngap_gen::encode(&pdu).expect("encode");
        let NgResetDecode::Reject(report) = decode_ng_reset_asn1(&no_type) else {
            panic!("a missing Reset Type must reject");
        };
        assert_eq!(report.diagnostics[0].ie_id, ngap_gen::ID_RESET_TYPE);
        assert_eq!(
            report.diagnostics[0].type_of_error,
            ngap_gen::TypeOfError::MISSING
        );
    }

    /// #417: the generated OVERLOAD START is byte-identical to the
    /// hand-written builder for every input percentage (clamped to 1..99 by
    /// both), and OVERLOAD STOP is too.
    #[test]
    fn overload_generated_matches_hand_written() {
        for percent in 0..=u8::MAX {
            let old = builder::build_overload_start(&OverloadStart {
                traffic_load_reduction: Some(percent.clamp(1, 99)),
            })
            .expect("hand-written build");
            assert_eq!(
                build_overload_start_asn1(percent).expect("generated"),
                old,
                "{percent}"
            );
        }
        let old = builder::build_overload_stop(&OverloadStop {}).expect("hand-written build");
        assert_eq!(build_overload_stop_asn1().expect("generated"), old);
    }

    /// Both messages, derived from X.691 by hand.
    ///
    /// OVERLOAD START, 40%: initiatingMessage (0x00), procedure code 22 (0x16),
    /// criticality ignore (0x40), an 8-octet open type: SEQUENCE extension bit
    /// (0, padded), IE count 1 (00 01), then IE id 9 (00 09), criticality
    /// ignore (0x40), a 1-octet value: TrafficLoadReductionIndication
    /// INTEGER (1..99) holds 40 - 1 = 39 in 7 bits, `0100111` + pad = 0x4e.
    ///
    /// OVERLOAD STOP: procedure code 23 (0x17), criticality reject (0x00), a
    /// 3-octet open type holding the extension bit and an empty container.
    #[test]
    fn overload_golden_bytes() {
        assert_eq!(
            build_overload_start_asn1(40).expect("start"),
            [0x00, 0x16, 0x40, 0x08, 0x00, 0x00, 0x01, 0x00, 0x09, 0x40, 0x01, 0x4e]
        );
        assert_eq!(
            build_overload_stop_asn1().expect("stop"),
            [0x00, 0x17, 0x00, 0x03, 0x00, 0x00, 0x00]
        );
    }

    fn ho_causes() -> Vec<Cause> {
        vec![
            Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            Cause::RadioNetwork(CauseRadioNetwork::HoTargetNotAllowed),
            Cause::Transport(CauseTransport::TransportResourceUnavailable),
            Cause::Nas(CauseNas::NormalRelease),
            Cause::Protocol(CauseProtocol::SemanticError),
            Cause::Misc(CauseMisc::Unspecified),
        ]
    }

    const HO_IDS: [(u64, u32); 4] = [(0, 0), ((1 << 40) - 1, u32::MAX), (256, 65_536), (7, 70)];

    /// #417: HANDOVER PREPARATION FAILURE and HANDOVER CANCEL ACKNOWLEDGE are
    /// byte-identical to the hand-written builders over every ID edge and Cause
    /// group.
    #[test]
    fn handover_preparation_failure_generated_matches_hand_written() {
        for (amf, ran) in HO_IDS {
            for cause in ho_causes() {
                let msg = HandoverPreparationFailure {
                    amf_ue_ngap_id: amf,
                    ran_ue_ngap_id: ran,
                    cause,
                    criticality_diagnostics: None,
                };
                let old = builder::build_handover_preparation_failure(&msg).expect("hand-written");
                assert_eq!(
                    build_handover_preparation_failure_asn1(&msg).expect("generated"),
                    old
                );
            }
            let old = builder::build_handover_cancel_acknowledge(&HandoverCancelAcknowledge {
                amf_ue_ngap_id: amf,
                ran_ue_ngap_id: ran,
                criticality_diagnostics: None,
            })
            .expect("hand-written");
            assert_eq!(
                build_handover_cancel_acknowledge_asn1(amf, ran, &[]).expect("generated"),
                old
            );
        }
    }

    /// #417: HANDOVER CANCEL, HANDOVER NOTIFY and HANDOVER FAILURE decode,
    /// through the generated codec, to what the hand-written parser read.
    #[test]
    fn handover_messages_generated_decode_matches_hand_written() {
        let uli = UserLocationInformation::Nr {
            nr_cgi_plmn: [0x99, 0xf9, 0x07],
            nr_cell_identity: 0x0_0000_0010,
            tai_plmn: [0x99, 0xf9, 0x07],
            tai_tac: [0x00, 0x00, 0x01],
        };
        for (amf, ran) in HO_IDS {
            for cause in ho_causes() {
                let bytes = builder::build_handover_cancel(&HandoverCancel {
                    amf_ue_ngap_id: amf,
                    ran_ue_ngap_id: ran,
                    cause,
                })
                .expect("build");
                let NgapMessage::HandoverCancel(old) = parser::decode_ngap_pdu(&bytes).unwrap()
                else {
                    panic!("old: not a cancel");
                };
                let NasTransportDecode::Proceed {
                    message,
                    error_indication: None,
                } = decode_handover_cancel_asn1(&bytes)
                else {
                    panic!("cancel did not proceed");
                };
                assert_eq!(
                    (message.amf_ue_ngap_id, message.ran_ue_ngap_id),
                    (old.amf_ue_ngap_id, old.ran_ue_ngap_id)
                );
                assert_eq!(format!("{:?}", message.cause), format!("{:?}", old.cause));

                let bytes = builder::build_handover_failure(&HandoverFailure {
                    amf_ue_ngap_id: amf,
                    cause,
                    criticality_diagnostics: None,
                })
                .expect("build");
                let NgapMessage::HandoverFailure(old) = parser::decode_ngap_pdu(&bytes).unwrap()
                else {
                    panic!("old: not a failure");
                };
                let NasTransportDecode::Proceed {
                    message,
                    error_indication: None,
                } = decode_handover_failure_asn1(&bytes)
                else {
                    panic!("failure did not proceed");
                };
                assert_eq!(message.amf_ue_ngap_id, old.amf_ue_ngap_id);
                assert_eq!(format!("{:?}", message.cause), format!("{:?}", old.cause));
            }
            let bytes = builder::build_handover_notify(&HandoverNotify {
                amf_ue_ngap_id: amf,
                ran_ue_ngap_id: ran,
                user_location_info: uli.clone(),
            })
            .expect("build");
            let NgapMessage::HandoverNotify(old) = parser::decode_ngap_pdu(&bytes).unwrap() else {
                panic!("old: not a notify");
            };
            let NasTransportDecode::Proceed {
                message: (a, r, l),
                error_indication: None,
            } = decode_handover_notify_asn1(&bytes)
            else {
                panic!("notify did not proceed");
            };
            assert_eq!((a, r), (old.amf_ue_ngap_id, old.ran_ue_ngap_id));
            assert_eq!(
                format!("{l:?}"),
                format!("{:?}", Some(old.user_location_info))
            );
        }
    }

    /// HANDOVER PREPARATION FAILURE and HANDOVER CANCEL ACKNOWLEDGE, derived
    /// from X.691 by hand for AMF UE NGAP ID 1, RAN UE NGAP ID 2, Cause
    /// radioNetwork/unspecified.
    ///
    /// Failure: unsuccessfulOutcome (CHOICE 2 of 3, extensible: `0 10` + pad =
    /// 0x40), procedure code 12, criticality reject, then 3 IEs, each
    /// criticality ignore (0x40): AMF UE NGAP ID 10 = `00 0a 40 02 00 01`
    /// (INTEGER 0..2^40-1: 3-bit octet count 0 + pad, value 01), RAN UE NGAP ID
    /// 85 = `00 55 40 02 00 02`, Cause 15 = `00 0f 40 02 00 00`.
    /// Cancel Ack: successfulOutcome (0x20), procedure code 10, reject, two IEs.
    #[test]
    fn handover_failure_and_cancel_ack_golden_bytes() {
        let failure = build_handover_preparation_failure_asn1(&HandoverPreparationFailure {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            criticality_diagnostics: None,
        })
        .expect("build");
        assert_eq!(
            failure,
            [
                0x40, 0x0c, 0x00, 0x15, 0x00, 0x00, 0x03, //
                0x00, 0x0a, 0x40, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x40, 0x02, 0x00, 0x02, //
                0x00, 0x0f, 0x40, 0x02, 0x00, 0x00,
            ]
        );
        assert_eq!(
            build_handover_cancel_acknowledge_asn1(1, 2, &[]).expect("build"),
            [
                0x20, 0x0a, 0x00, 0x0f, 0x00, 0x00, 0x02, //
                0x00, 0x0a, 0x40, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x40, 0x02, 0x00, 0x02,
            ]
        );
    }

    /// §10.3.4.2 for the three received messages: Cancel (response, no
    /// unsuccessful outcome) and Notify (no response) are terminated by a
    /// "reject" IE and report "notify" ones; Failure (a response) only reports
    /// "notify" ones and leaves a "reject" one to local handling.
    #[test]
    fn handover_messages_follow_unknown_ie_criticality() {
        let cancel = builder::build_handover_cancel(&HandoverCancel {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            cause: Cause::Misc(CauseMisc::Unspecified),
        })
        .unwrap();
        assert!(matches!(
            decode_handover_cancel_asn1(&with_unknown_ie(&cancel, 9999, 0x00)),
            NasTransportDecode::Reject(ref r) if r.procedure.procedure_code == ngap_gen::ID_HANDOVER_CANCEL
        ));
        let NasTransportDecode::Proceed {
            error_indication: Some(report),
            ..
        } = decode_handover_cancel_asn1(&with_unknown_ie(&cancel, 9999, 0x80))
        else {
            panic!("notify must proceed and be reported");
        };
        // ... in the Acknowledge.
        let ack = build_handover_cancel_acknowledge_asn1(1, 2, &report.diagnostics).unwrap();
        assert!(
            ack.windows(2).any(|w| w == [0x00, 0x13]),
            "Criticality Diagnostics IE 19"
        );

        let notify = builder::build_handover_notify(&HandoverNotify {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            user_location_info: UserLocationInformation::Nr {
                nr_cgi_plmn: [0x99, 0xf9, 0x07],
                nr_cell_identity: 1,
                tai_plmn: [0x99, 0xf9, 0x07],
                tai_tac: [0, 0, 1],
            },
        })
        .unwrap();
        assert!(matches!(
            decode_handover_notify_asn1(&with_unknown_ie(&notify, 9999, 0x00)),
            NasTransportDecode::Reject(_)
        ));
        assert!(matches!(
            decode_handover_notify_asn1(&with_unknown_ie(&notify, 9999, 0x80)),
            NasTransportDecode::Proceed {
                error_indication: Some(_),
                ..
            }
        ));

        let failure = builder::build_handover_failure(&HandoverFailure {
            amf_ue_ngap_id: 1,
            cause: Cause::Misc(CauseMisc::Unspecified),
            criticality_diagnostics: None,
        })
        .unwrap();
        assert!(matches!(
            decode_handover_failure_asn1(&with_unknown_ie(&failure, 9999, 0x00)),
            NasTransportDecode::Reject(_)
        ));
        assert!(matches!(
            decode_handover_failure_asn1(&with_unknown_ie(&failure, 9999, 0x40)),
            NasTransportDecode::Proceed {
                error_indication: None,
                ..
            }
        ));
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
        use nextgcore_ngap::transfer::{AssociatedQosFlowItem, QosFlowPerTnlInformation};

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
            additional_dl_qos_flow_per_tnl_information: Vec::new(),
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
        use nextgcore_asn1c::ngap::pdu::{InitiatingMessageValue, NgapPdu};
        use nextgcore_asn1c::per::{AperDecode, AperDecoder};

        let bytes = build_pdu_session_resource_release_command_asn1(42, 1001, &[5]).expect("build");

        // nextgcore-asn1c maps InitiatingMessage procedure code 28 to the generic
        // `Other` container and the nextgcore-ngap dispatch does not cover it (lib
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
                let transfer =
                    nextgcore_ngap::transfer::PduSessionResourceReleaseCommandTransfer::decode(
                        &item.transfer,
                    )
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
        assert_eq!(
            req.guami.plmn_identity,
            encode_plmn_id(&PlmnId::new("999", "70"))
        );
        // Allowed NSSAI round-trips with the SD packed as 3 bytes
        assert_eq!(req.allowed_nssai.len(), 1);
        assert_eq!(req.allowed_nssai[0].sst, 1);
        assert_eq!(req.allowed_nssai[0].sd, Some([0x01, 0x02, 0x03]));
        // Replayed UE security capabilities: NGAP §9.3.1.86 drops the null
        // algorithm (NAS 0xF0 = EA0|EA1|EA2|EA3 -> NEA1|NEA2|NEA3 = 0xE000).
        assert_eq!(
            req.ue_security_capabilities.nr_encryption_algorithms,
            0xE000
        );
        assert_eq!(req.ue_security_capabilities.nr_integrity_algorithms, 0xE000);
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
        assert_eq!(
            build_cause(2, 1),
            Cause::Nas(CauseNas::AuthenticationFailure)
        );
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
        assert_eq!(radio_network_cause(47), CauseRadioNetwork::Unspecified);
        assert_eq!(radio_network_cause(u8::MAX), CauseRadioNetwork::Unspecified);
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
                assert_eq!(f.cause, Cause::RadioNetwork(CauseRadioNetwork::Unspecified));
            }
            other => panic!("Expected NgSetupFailure, got {other:?}"),
        }
    }

    #[test]
    fn test_initial_context_setup_response_failure_roundtrip() {
        // Build a Response/Failure with the nextgcore-ngap builder, then ensure the
        // AMF-side parse helpers recover the UE NGAP IDs (used to gate the
        // registration on the ICS Response).
        let resp = builder::build_initial_context_setup_response(
            &nextgcore_ngap::types::InitialContextSetupResponse {
                amf_ue_ngap_id: 7,
                ran_ue_ngap_id: 9,
            },
        )
        .expect("build ICS response");
        assert_eq!(
            hand_written_oracle::hand_written_parse_initial_context_setup_response(&resp),
            Some((7, 9))
        );
        assert!(matches!(
            decode_initial_context_setup_response_asn1(&resp),
            InitialContextSetupOutcomeDecode::Decoded {
                amf_ue_ngap_id: Some(7),
                ran_ue_ngap_id: Some(9),
                cause: None,
                error_indication: None,
                ..
            }
        ));

        let fail = builder::build_initial_context_setup_failure(
            &nextgcore_ngap::types::InitialContextSetupFailure {
                amf_ue_ngap_id: 11,
                ran_ue_ngap_id: 13,
                cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            },
        )
        .expect("build ICS failure");
        assert_eq!(
            hand_written_oracle::hand_written_parse_initial_context_setup_failure(&fail),
            Some((11, 13))
        );
        assert!(matches!(
            decode_initial_context_setup_failure_asn1(&fail),
            InitialContextSetupOutcomeDecode::Decoded {
                amf_ue_ngap_id: Some(11),
                ran_ue_ngap_id: Some(13),
                cause: Some((crate::ngap_handler::cause_group::RADIO_NETWORK, 0)),
                error_indication: None,
                ..
            }
        ));
    }

    // ====================================================================
    // #417 stage 4: the UE Context Release family on the generated codec
    // ====================================================================

    use hand_written_oracle::{
        hand_written_extract_amf_ue_ngap_id, hand_written_extract_ran_ue_ngap_id,
        hand_written_extract_release_request_cause, hand_written_parse_ue_context_release_complete,
        hand_written_ue_context_release_command,
    };

    /// The upper bound of AMF-UE-NGAP-ID, INTEGER (0..1099511627775) (TS 38.413
    /// §9.3.3.1).
    const MAX_AMF_UE_NGAP_ID: u64 = (1 << 40) - 1;

    /// AMF UE NGAP IDs at every APER length boundary of INTEGER (0..2^40-1),
    /// and past the upper bound.
    const AMF_IDS: [u64; 12] = [
        0,
        1,
        255,
        256,
        65_535,
        65_536,
        16_777_215,
        16_777_216,
        u32::MAX as u64,
        1 << 32,
        MAX_AMF_UE_NGAP_ID,
        MAX_AMF_UE_NGAP_ID + 1,
    ];

    /// RAN UE NGAP IDs at every APER length boundary of INTEGER (0..2^32-1).
    const RAN_IDS: [u32; 8] = [0, 1, 255, 256, 65_535, 65_536, 16_777_216, u32::MAX];

    /// #417 stage 4: the generated UE Context Release Command is byte for byte
    /// the hand-written one -- every cause group and value the AMF can be
    /// handed (out-of-range ones included, which both clamp through
    /// `build_cause`), and every ID length -- and both refuse the same
    /// out-of-range AMF UE NGAP ID.
    #[test]
    fn ue_context_release_command_generated_matches_hand_written() {
        let mut compared = 0;
        for group in 0..=5u8 {
            for value in -1..=1000i64 {
                assert_eq!(
                    build_ue_context_release_command_asn1(42, 1001, group, value),
                    hand_written_ue_context_release_command(42, 1001, group, value),
                    "group {group} value {value}"
                );
                compared += 1;
            }
        }
        for amf in AMF_IDS {
            for ran in RAN_IDS {
                for (group, value) in [(2u8, 0i64), (0, 20), (0, 46), (3, 1), (4, 0)] {
                    assert_eq!(
                        build_ue_context_release_command_asn1(amf, ran, group, value),
                        hand_written_ue_context_release_command(amf, ran, group, value),
                        "AMF {amf} RAN {ran} group {group} value {value}"
                    );
                    compared += 1;
                }
            }
        }
        assert_eq!(compared, 6 * 1002 + 12 * 8 * 5);
        assert_eq!(
            build_ue_context_release_command_asn1(MAX_AMF_UE_NGAP_ID + 1, 1, 2, 0),
            None,
            "an AMF UE NGAP ID past 2^40-1 is refused, as before"
        );
    }

    /// The bytes themselves, so the generated and hand-written encoders cannot
    /// drift together: NAS normal-release, and radioNetwork 46
    /// (release-due-to-pre-emption), an extension value (nextgsim #213).
    #[test]
    fn ue_context_release_command_golden_bytes() {
        assert_eq!(
            build_ue_context_release_command_asn1(42, 1001, 2, 0).expect("encode"),
            GOLDEN_RELEASE_COMMAND_NAS_NORMAL
        );
        assert_eq!(
            build_ue_context_release_command_asn1(42, 1001, 0, 46).expect("encode"),
            GOLDEN_RELEASE_COMMAND_PRE_EMPTION
        );
    }

    const GOLDEN_RELEASE_COMMAND_NAS_NORMAL: &[u8] = &[
        0x00, 0x29, 0x00, 0x11, 0x00, 0x00, 0x02, 0x00, 0x72, 0x00, 0x05, 0x00, 0x2a, 0x40, 0x03,
        0xe9, 0x00, 0x0f, 0x40, 0x01, 0x40,
    ];
    const GOLDEN_RELEASE_COMMAND_PRE_EMPTION: &[u8] = &[
        0x00, 0x29, 0x00, 0x12, 0x00, 0x00, 0x02, 0x00, 0x72, 0x00, 0x05, 0x00, 0x2a, 0x40, 0x03,
        0xe9, 0x00, 0x0f, 0x40, 0x02, 0x10, 0x20,
    ];

    /// A UE Context Release Request built by the hand-written encoder.
    fn release_request(amf: u64, ran: u32, group: u8, value: i64) -> Vec<u8> {
        nextgcore_ngap::builder::build_ue_context_release_request(&UeContextReleaseRequest {
            amf_ue_ngap_id: amf,
            ran_ue_ngap_id: ran,
            cause: build_cause(group, value),
        })
        .expect("encode")
    }

    /// A UE Context Release Complete built by the hand-written encoder.
    fn release_complete(amf: u64, ran: u32) -> Vec<u8> {
        nextgcore_ngap::builder::build_ue_context_release_complete(&UeContextReleaseComplete {
            amf_ue_ngap_id: amf,
            ran_ue_ngap_id: ran,
        })
        .expect("encode")
    }

    /// A UE Context Release Request built by the generated encoder from `ies`.
    fn generated_release_request(
        ies: Vec<ngap_gen::UEContextReleaseRequestProtocolIEs_EntryValue>,
    ) -> Vec<u8> {
        use ngap_gen::UEContextReleaseRequestProtocolIEs_EntryValue as Ie;
        let entries = ies
            .into_iter()
            .map(|value| {
                let (id, criticality) = match &value {
                    Ie::Id_AMF_UE_NGAP_ID(_) => (ngap_gen::ID_AMF_UE_NGAP_ID, 0),
                    Ie::Id_RAN_UE_NGAP_ID(_) => (ngap_gen::ID_RAN_UE_NGAP_ID, 0),
                    Ie::Id_PDUSessionResourceListCxtRelReq(_) => {
                        (ngap_gen::ID_PDU_SESSION_RESOURCE_LIST_CXT_REL_REQ, 0)
                    }
                    Ie::Id_Cause(_) => (ngap_gen::ID_CAUSE, 1),
                };
                ngap_gen::UEContextReleaseRequestProtocolIEs_Entry {
                    id: ngap_gen::ProtocolIE_ID(id),
                    criticality: ngap_gen::Criticality(criticality),
                    value,
                }
            })
            .collect();
        nextgcore_ngap_gen::encode(&ngap_gen::NGAP_PDU::InitiatingMessage(
            ngap_gen::InitiatingMessage {
                procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_UE_CONTEXT_RELEASE_REQUEST),
                criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
                value: ngap_gen::InitiatingMessageValue::Id_UEContextReleaseRequest(
                    ngap_gen::UEContextReleaseRequest {
                        protocol_i_es: ngap_gen::UEContextReleaseRequestProtocolIEs(entries),
                    },
                ),
            },
        ))
        .expect("encode")
    }

    /// A UE Context Release Complete built by the generated encoder from `ies`.
    fn generated_release_complete(
        ies: Vec<ngap_gen::UEContextReleaseCompleteProtocolIEs_EntryValue>,
    ) -> Vec<u8> {
        use ngap_gen::UEContextReleaseCompleteProtocolIEs_EntryValue as Ie;
        let entries = ies
            .into_iter()
            .map(|value| {
                let (id, criticality) = match &value {
                    Ie::Id_AMF_UE_NGAP_ID(_) => (ngap_gen::ID_AMF_UE_NGAP_ID, 1),
                    Ie::Id_RAN_UE_NGAP_ID(_) => (ngap_gen::ID_RAN_UE_NGAP_ID, 1),
                    Ie::Id_PDUSessionResourceListCxtRelCpl(_) => {
                        (ngap_gen::ID_PDU_SESSION_RESOURCE_LIST_CXT_REL_CPL, 0)
                    }
                    other => panic!("not used by these tests: {other:?}"),
                };
                ngap_gen::UEContextReleaseCompleteProtocolIEs_Entry {
                    id: ngap_gen::ProtocolIE_ID(id),
                    criticality: ngap_gen::Criticality(criticality),
                    value,
                }
            })
            .collect();
        nextgcore_ngap_gen::encode(&ngap_gen::NGAP_PDU::SuccessfulOutcome(
            ngap_gen::SuccessfulOutcome {
                procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_UE_CONTEXT_RELEASE),
                criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
                value: ngap_gen::SuccessfulOutcomeValue::Id_UEContextRelease(
                    ngap_gen::UEContextReleaseComplete {
                        protocol_i_es: ngap_gen::UEContextReleaseCompleteProtocolIEs(entries),
                    },
                ),
            },
        ))
        .expect("encode")
    }

    /// What the hand-written Release Request path could say: the three things
    /// the handler read, each `None` when the message was refused.
    fn hand_written_request_view(data: &[u8]) -> Option<(u64, u32, Option<(u8, i64)>)> {
        Some((
            hand_written_extract_amf_ue_ngap_id(data)?,
            hand_written_extract_ran_ue_ngap_id(data)?,
            hand_written_extract_release_request_cause(data),
        ))
    }

    /// The new decode flattened to the same view. A `Reject` never comes out
    /// of a request the old parser accepted, so it is a failure here.
    fn generated_request_view(data: &[u8]) -> Option<(u64, u32, Option<(u8, i64)>)> {
        match decode_ue_context_release_request_asn1(data) {
            UeContextReleaseRequestDecode::Proceed {
                amf_ue_ngap_id,
                ran_ue_ngap_id,
                cause,
                ..
            } => Some((amf_ue_ngap_id, ran_ue_ngap_id, cause)),
            UeContextReleaseRequestDecode::Undecodable => None,
            UeContextReleaseRequestDecode::Reject(r) => {
                panic!("unexpected Reject({r:?}) for {data:02x?}")
            }
        }
    }

    /// The request corpus both decoders are compared over: every ID length,
    /// every cause the AMF's `build_cause` can produce (extension values
    /// included), and requests carrying a not-comprehended IE marked ignore or
    /// notify, which the old parser accepted.
    fn release_request_corpus() -> Vec<Vec<u8>> {
        let mut corpus = Vec::new();
        for amf in &AMF_IDS[..AMF_IDS.len() - 1] {
            for ran in RAN_IDS {
                corpus.push(release_request(*amf, ran, 0, 21));
            }
        }
        for group in 0..=4u8 {
            for value in 0..=50i64 {
                corpus.push(release_request(7, 9, group, value));
            }
        }
        let base = release_request(7, 9, 0, 21);
        for criticality in [0x40, 0x80] {
            corpus.push(with_unknown_ie(&base, 9999, criticality));
        }
        corpus
    }

    /// #417 stage 4: for every request the hand-written path accepted, the
    /// generated decode yields the same AMF UE NGAP ID, RAN UE NGAP ID and
    /// Cause; and what it refused as malformed is still undecodable.
    #[test]
    fn ue_context_release_request_generated_decode_matches_hand_written() {
        let corpus = release_request_corpus();
        for data in &corpus {
            let old = hand_written_request_view(data);
            assert!(
                old.is_some(),
                "the corpus holds accepted requests: {data:02x?}"
            );
            assert_eq!(generated_request_view(data), old, "{data:02x?}");
        }
        assert_eq!(corpus.len(), 11 * 8 + 5 * 51 + 2);

        // Malformed: truncated, and an empty buffer.
        let base = release_request(7, 9, 0, 21);
        for data in [&base[..base.len() - 1], &base[..4], &[][..]] {
            assert_eq!(hand_written_request_view(data), None);
            assert_eq!(generated_request_view(data), None, "{data:02x?}");
        }
    }

    /// Release Request has no response message, so a not-comprehended IE
    /// marked "ignore IE and notify sender" is reported in an Error Indication
    /// carrying the Procedure Code, Triggering Message, Procedure Criticality
    /// and the IE (§10.3.4.2) -- and the release goes on.
    #[test]
    fn a_release_request_notify_ie_is_reported_in_an_error_indication() {
        let data = with_unknown_ie(&release_request(7, 9, 0, 21), 9999, 0x80);
        let UeContextReleaseRequestDecode::Proceed {
            amf_ue_ngap_id: 7,
            ran_ue_ngap_id: 9,
            cause: Some((0, 21)),
            error_indication: Some(report),
        } = decode_ue_context_release_request_asn1(&data)
        else {
            panic!("expected Proceed with an Error Indication");
        };
        assert_eq!(
            report,
            CriticalityErrorIndication {
                amf_ue_ngap_id: Some(7),
                ran_ue_ngap_id: Some(9),
                cause_protocol: ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
                procedure: ReportedProcedure {
                    procedure_code: 42,
                    triggering_message: ngap_gen::TriggeringMessage::INITIATING_MESSAGE,
                    procedure_criticality: ngap_gen::Criticality::IGNORE,
                },
                diagnostics: vec![IeDiagnostic {
                    ie_id: 9999,
                    criticality: ngap_gen::Criticality::NOTIFY,
                    type_of_error: ngap_gen::TypeOfError::NOT_UNDERSTOOD,
                }],
            }
        );
        // And "ignore" is ignored, with nothing to report.
        let ignored = with_unknown_ie(&release_request(7, 9, 0, 21), 9999, 0x40);
        assert!(matches!(
            decode_ue_context_release_request_asn1(&ignored),
            UeContextReleaseRequestDecode::Proceed {
                error_indication: None,
                ..
            }
        ));
    }

    /// A not-comprehended IE marked "reject", and a missing AMF or RAN UE NGAP
    /// ID, terminate the procedure with an Error Indication (§10.3.4.2,
    /// §10.3.5): the hand-written path refused all three silently, releasing
    /// nothing and telling the gNB nothing.
    #[test]
    fn a_release_request_the_amf_must_reject_ends_in_an_error_indication() {
        use ngap_gen::UEContextReleaseRequestProtocolIEs_EntryValue as Ie;
        let reject_procedure = ReportedProcedure {
            procedure_code: 42,
            triggering_message: ngap_gen::TriggeringMessage::INITIATING_MESSAGE,
            procedure_criticality: ngap_gen::Criticality::IGNORE,
        };

        let unknown_reject = with_unknown_ie(&release_request(7, 9, 0, 21), 9999, 0x00);
        assert_eq!(hand_written_request_view(&unknown_reject), None);
        let UeContextReleaseRequestDecode::Reject(report) =
            decode_ue_context_release_request_asn1(&unknown_reject)
        else {
            panic!("expected Reject");
        };
        assert_eq!(
            report,
            CriticalityErrorIndication {
                amf_ue_ngap_id: Some(7),
                ran_ue_ngap_id: Some(9),
                cause_protocol: ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT,
                procedure: reject_procedure,
                diagnostics: vec![IeDiagnostic {
                    ie_id: 9999,
                    criticality: ngap_gen::Criticality::REJECT,
                    type_of_error: ngap_gen::TypeOfError::NOT_UNDERSTOOD,
                }],
            }
        );

        let no_amf_id = generated_release_request(vec![
            Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(9)),
            Ie::Id_Cause(ngap_gen::Cause::Nas(ngap_gen::CauseNas(0))),
        ]);
        assert_eq!(hand_written_request_view(&no_amf_id), None);
        let UeContextReleaseRequestDecode::Reject(report) =
            decode_ue_context_release_request_asn1(&no_amf_id)
        else {
            panic!("expected Reject");
        };
        assert_eq!(
            report,
            CriticalityErrorIndication {
                amf_ue_ngap_id: None,
                ran_ue_ngap_id: Some(9),
                cause_protocol: ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT,
                procedure: reject_procedure,
                diagnostics: vec![IeDiagnostic {
                    ie_id: ngap_gen::ID_AMF_UE_NGAP_ID,
                    criticality: ngap_gen::Criticality::REJECT,
                    type_of_error: ngap_gen::TypeOfError::MISSING,
                }],
            }
        );

        let no_ran_id = generated_release_request(vec![
            Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(7)),
            Ie::Id_Cause(ngap_gen::Cause::Nas(ngap_gen::CauseNas(0))),
        ]);
        let UeContextReleaseRequestDecode::Reject(report) =
            decode_ue_context_release_request_asn1(&no_ran_id)
        else {
            panic!("expected Reject");
        };
        assert_eq!(report.amf_ue_ngap_id, Some(7));
        assert_eq!(report.ran_ue_ngap_id, None);
        assert_eq!(report.diagnostics[0].ie_id, ngap_gen::ID_RAN_UE_NGAP_ID);
        assert_eq!(
            report.diagnostics[0].type_of_error,
            ngap_gen::TypeOfError::MISSING
        );
    }

    /// Two requests the hand-written parser refused that the AMF must act on:
    /// one without a Cause (mandatory, criticality ignore -- its absence is
    /// ignored, §10.3.5), and one carrying the optional PDU Session Resource
    /// List, which the old parser did not comprehend and, its criticality
    /// being reject, refused the whole request over.
    #[test]
    fn release_requests_the_old_parser_refused_are_now_released() {
        use ngap_gen::UEContextReleaseRequestProtocolIEs_EntryValue as Ie;
        let no_cause = generated_release_request(vec![
            Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(7)),
            Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(9)),
        ]);
        assert_eq!(hand_written_request_view(&no_cause), None);
        assert_eq!(generated_request_view(&no_cause), Some((7, 9, None)));

        let with_sessions = generated_release_request(vec![
            Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(7)),
            Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(9)),
            Ie::Id_PDUSessionResourceListCxtRelReq(ngap_gen::PDUSessionResourceListCxtRelReq(
                vec![ngap_gen::PDUSessionResourceItemCxtRelReq {
                    pdu_session_id: ngap_gen::PDUSessionID(5),
                    ie_extensions: None,
                }],
            )),
            Ie::Id_Cause(ngap_gen::Cause::RadioNetwork(ngap_gen::CauseRadioNetwork(
                21,
            ))),
        ]);
        assert_eq!(hand_written_request_view(&with_sessions), None);
        assert_eq!(
            generated_request_view(&with_sessions),
            Some((7, 9, Some((0, 21))))
        );
    }

    /// The new Release Complete decode flattened to what the hand-written
    /// parser could say: the AMF UE NGAP ID, or nothing.
    fn generated_complete_view(data: &[u8]) -> Option<u64> {
        match decode_ue_context_release_complete_asn1(data) {
            UeContextReleaseCompleteDecode::Complete { amf_ue_ngap_id, .. } => amf_ue_ngap_id,
            UeContextReleaseCompleteDecode::Failed(_)
            | UeContextReleaseCompleteDecode::Undecodable => None,
        }
    }

    /// #417 stage 4: for every Release Complete the hand-written parser
    /// accepted, the generated decode names the same UE; what it refused as
    /// malformed, or over a not-comprehended IE marked reject, still names none.
    #[test]
    fn ue_context_release_complete_generated_decode_matches_hand_written() {
        let mut corpus = Vec::new();
        for amf in &AMF_IDS[..AMF_IDS.len() - 1] {
            for ran in RAN_IDS {
                corpus.push(release_complete(*amf, ran));
            }
        }
        let base = release_complete(7, 9);
        for criticality in [0x40, 0x80] {
            corpus.push(with_unknown_ie(&base, 9999, criticality));
        }
        for data in &corpus {
            let old = hand_written_parse_ue_context_release_complete(data);
            assert!(
                old.is_some(),
                "the corpus holds accepted messages: {data:02x?}"
            );
            assert_eq!(generated_complete_view(data), old, "{data:02x?}");
        }
        let refused = [
            base[..base.len() - 1].to_vec(),
            with_unknown_ie(&base, 9999, 0x00),
        ];
        for data in &refused {
            assert_eq!(hand_written_parse_ue_context_release_complete(data), None);
            assert_eq!(generated_complete_view(data), None, "{data:02x?}");
        }
        assert!(matches!(
            decode_ue_context_release_complete_asn1(&refused[1]),
            UeContextReleaseCompleteDecode::Failed(ref d) if d[0].ie_id == 9999
        ));
    }

    /// A Release Complete is a response, so §10.3.4.2 reports a "notify" IE in
    /// an Error Indication -- Triggering Message successful-outcome, Procedure
    /// Criticality reject -- and names the UE all the same.
    #[test]
    fn a_release_complete_notify_ie_is_reported_in_an_error_indication() {
        let data = with_unknown_ie(&release_complete(7, 9), 9999, 0x80);
        let UeContextReleaseCompleteDecode::Complete {
            amf_ue_ngap_id: Some(7),
            ran_ue_ngap_id: Some(9),
            error_indication: Some(report),
        } = decode_ue_context_release_complete_asn1(&data)
        else {
            panic!("expected Complete with an Error Indication");
        };
        assert_eq!(
            report.procedure,
            ReportedProcedure {
                procedure_code: 41,
                triggering_message: ngap_gen::TriggeringMessage::SUCCESSFUL_OUTCOME,
                procedure_criticality: ngap_gen::Criticality::REJECT,
            }
        );
        assert_eq!(
            report.cause_protocol,
            ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY
        );
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].ie_id, 9999);
    }

    /// Two Release Completes the hand-written parser refused -- one missing the
    /// RAN UE NGAP ID (criticality ignore, so its absence is ignored), one
    /// carrying the optional PDU Session Resource List (criticality reject, not
    /// comprehended by the old parser) -- now name their UE.
    #[test]
    fn release_completes_the_old_parser_refused_now_name_their_ue() {
        use ngap_gen::UEContextReleaseCompleteProtocolIEs_EntryValue as Ie;
        let no_ran_id =
            generated_release_complete(vec![Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(7))]);
        assert_eq!(
            hand_written_parse_ue_context_release_complete(&no_ran_id),
            None
        );
        assert!(matches!(
            decode_ue_context_release_complete_asn1(&no_ran_id),
            UeContextReleaseCompleteDecode::Complete {
                amf_ue_ngap_id: Some(7),
                ran_ue_ngap_id: None,
                error_indication: None,
            }
        ));

        let with_sessions = generated_release_complete(vec![
            Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(7)),
            Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(9)),
            Ie::Id_PDUSessionResourceListCxtRelCpl(ngap_gen::PDUSessionResourceListCxtRelCpl(
                vec![ngap_gen::PDUSessionResourceItemCxtRelCpl {
                    pdu_session_id: ngap_gen::PDUSessionID(5),
                    ie_extensions: None,
                }],
            )),
        ]);
        assert_eq!(
            hand_written_parse_ue_context_release_complete(&with_sessions),
            None
        );
        assert_eq!(generated_complete_view(&with_sessions), Some(7));
    }

    /// The criticality Error Indication decodes, under the generated codec and
    /// the hand-written parser alike, to exactly what was reported: both IDs,
    /// the protocol Cause, and Criticality Diagnostics with all four members
    /// §10.3.4.2 requires for an Error Indication.
    #[test]
    fn the_criticality_error_indication_carries_the_whole_report() {
        let report = CriticalityErrorIndication {
            amf_ue_ngap_id: Some(7),
            ran_ue_ngap_id: Some(9),
            cause_protocol: ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT,
            procedure: ReportedProcedure {
                procedure_code: 42,
                triggering_message: ngap_gen::TriggeringMessage::INITIATING_MESSAGE,
                procedure_criticality: ngap_gen::Criticality::IGNORE,
            },
            diagnostics: vec![IeDiagnostic {
                ie_id: 9999,
                criticality: ngap_gen::Criticality::REJECT,
                type_of_error: ngap_gen::TypeOfError::NOT_UNDERSTOOD,
            }],
        };
        let bytes = build_criticality_error_indication_asn1(&report).expect("encode");
        assert_eq!(bytes, GOLDEN_CRITICALITY_ERROR_INDICATION);

        let ngap_gen::NGAP_PDU::InitiatingMessage(msg) =
            nextgcore_ngap_gen::decode(&bytes).expect("generated decode")
        else {
            panic!("initiatingMessage");
        };
        assert_eq!(msg.procedure_code.0, ngap_gen::ID_ERROR_INDICATION);
        let ngap_gen::InitiatingMessageValue::Id_ErrorIndication(ei) = msg.value else {
            panic!("ErrorIndication");
        };
        let mut diagnostics = None;
        for entry in ei.protocol_i_es.0 {
            if let ngap_gen::ErrorIndicationProtocolIEs_EntryValue::Id_CriticalityDiagnostics(d) =
                entry.value
            {
                diagnostics = Some(d);
            }
        }
        let d = diagnostics.expect("Criticality Diagnostics");
        assert_eq!(d.procedure_code.map(|p| p.0), Some(42));
        assert_eq!(
            d.triggering_message.map(|t| t.0),
            Some(ngap_gen::TriggeringMessage::INITIATING_MESSAGE)
        );
        assert_eq!(
            d.procedure_criticality.map(|c| c.0),
            Some(ngap_gen::Criticality::IGNORE)
        );
        let items = d.i_es_criticality_diagnostics.expect("IE list").0;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].ie_id.0, 9999);

        match parser::decode_ngap_pdu(&bytes).expect("hand-written decode") {
            NgapMessage::ErrorIndication(ei) => {
                assert_eq!(ei.amf_ue_ngap_id, Some(7));
                assert_eq!(ei.ran_ue_ngap_id, Some(9));
                assert_eq!(
                    ei.cause,
                    Some(Cause::Protocol(CauseProtocol::AbstractSyntaxErrorReject))
                );
            }
            other => panic!("Expected ErrorIndication, got {other:?}"),
        }
    }

    const GOLDEN_CRITICALITY_ERROR_INDICATION: &[u8] = &[
        0x00, 0x09, 0x40, 0x20, 0x00, 0x00, 0x04, 0x00, 0x0a, 0x40, 0x02, 0x00, 0x07, 0x00, 0x55,
        0x40, 0x02, 0x00, 0x09, 0x00, 0x0f, 0x40, 0x01, 0x62, 0x00, 0x13, 0x40, 0x08, 0x78, 0x2a,
        0x10, 0x00, 0x00, 0x27, 0x0f, 0x00,
    ];

    // ====================================================================
    // #417 stage 5: the PDU Session Resource Release pair on the generated
    // codec
    // ====================================================================

    use hand_written_oracle::{
        hand_written_parse_pdu_session_resource_release_response,
        hand_written_pdu_session_resource_release_command,
    };

    /// PDU Session ID lists at every length boundary of
    /// PDUSessionResourceToReleaseListRelCmd, SIZE(1..maxnoofPDUSessions = 256),
    /// and one past each end.
    fn psi_lists() -> Vec<Vec<u8>> {
        [0usize, 1, 2, 15, 16, 127, 128, 129, 255, 256, 257]
            .into_iter()
            .map(|n| (0..n).map(|i| (i % 256) as u8).collect())
            .collect()
    }

    /// #417 stage 5: the generated PDU Session Resource Release Command is byte
    /// for byte the hand-written one -- every PDU Session ID, every list length
    /// SIZE(1..256) allows, every UE NGAP ID length -- and both refuse the same
    /// inputs: an empty or 257-entry list, and an AMF UE NGAP ID past 2^40-1.
    #[test]
    fn pdu_session_resource_release_command_generated_matches_hand_written() {
        let mut compared = 0;
        let mut refused = 0;
        let mut check = |amf: u64, ran: u32, psis: &[u8]| {
            let new = build_pdu_session_resource_release_command_asn1(amf, ran, psis);
            let old = hand_written_pdu_session_resource_release_command(amf, ran, psis);
            assert_eq!(new, old, "AMF {amf} RAN {ran} PSIs {psis:?}");
            if new.is_none() {
                refused += 1;
            }
            compared += 1;
        };
        for psi in 0..=255u8 {
            check(42, 1001, &[psi]);
        }
        for psis in psi_lists() {
            check(42, 1001, &psis);
        }
        for amf in AMF_IDS {
            for ran in RAN_IDS {
                check(amf, ran, &[5]);
                check(amf, ran, &[1, 2, 3]);
            }
        }
        assert_eq!(compared, 256 + 11 + 12 * 8 * 2);
        // The empty and the 257-entry list, and the 16 out-of-range AMF IDs.
        assert_eq!(refused, 2 + 8 * 2);
        assert_eq!(
            build_pdu_session_resource_release_command_asn1(42, 1001, &[]),
            None
        );
        assert_eq!(
            build_pdu_session_resource_release_command_asn1(42, 1001, &[0; 257]),
            None
        );
    }

    /// The bytes themselves, so the generated and hand-written encoders cannot
    /// drift together: one session, and two.
    #[test]
    fn pdu_session_resource_release_command_golden_bytes() {
        assert_eq!(
            build_pdu_session_resource_release_command_asn1(42, 1001, &[5]).expect("encode"),
            GOLDEN_PDU_SESSION_RELEASE_COMMAND_ONE
        );
        assert_eq!(
            build_pdu_session_resource_release_command_asn1(42, 1001, &[1, 2]).expect("encode"),
            GOLDEN_PDU_SESSION_RELEASE_COMMAND_TWO
        );
    }

    // initiatingMessage, procedure 28, criticality reject, length; 3 IEs:
    // AMF UE NGAP ID 42, RAN UE NGAP ID 1001, then the To Release list --
    // count-1, per item the two preamble bits, the PSI, and the transfer
    // [0x10]: extension and iE-Extensions bits, Cause choice 2 (nas), value 0
    // (normal-release).
    const GOLDEN_PDU_SESSION_RELEASE_COMMAND_ONE: &[u8] = &[
        0x00, 0x1c, 0x00, 0x19, 0x00, 0x00, 0x03, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x2a, 0x00, 0x55,
        0x00, 0x03, 0x40, 0x03, 0xe9, 0x00, 0x4f, 0x00, 0x05, 0x00, 0x00, 0x05, 0x01, 0x10,
    ];
    const GOLDEN_PDU_SESSION_RELEASE_COMMAND_TWO: &[u8] = &[
        0x00, 0x1c, 0x00, 0x1d, 0x00, 0x00, 0x03, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x2a, 0x00, 0x55,
        0x00, 0x03, 0x40, 0x03, 0xe9, 0x00, 0x4f, 0x00, 0x09, 0x01, 0x00, 0x01, 0x01, 0x10, 0x00,
        0x02, 0x01, 0x10,
    ];

    /// The transfer helper on its own: for every cause the AMF's `build_cause`
    /// can produce, the generated PDUSessionResourceReleaseCommandTransfer is
    /// the hand-written one, and it decodes back through
    /// [`nextgcore_ngap_gen::decode_contained`] to the same Cause -- the round
    /// trip the Setup and Modify transfers will rely on.
    #[test]
    fn release_command_transfer_generated_matches_hand_written() {
        use nextgcore_ngap::transfer::PduSessionResourceReleaseCommandTransfer;
        let mut compared = 0;
        for group in 0..=4u8 {
            for value in 0..=46i64 {
                let cause = build_cause(group, value);
                let new = release_command_transfer(cause).expect("encode");
                let old = PduSessionResourceReleaseCommandTransfer { cause }
                    .encode()
                    .expect("hand-written encode");
                assert_eq!(new, old, "group {group} value {value}");
                let back = nextgcore_ngap_gen::decode_contained::<
                    ngap_gen::PDUSessionResourceReleaseCommandTransfer,
                >(&new)
                .expect("decode");
                assert_eq!(
                    back.cause,
                    generated_cause(cause),
                    "group {group} value {value}"
                );
                compared += 1;
            }
        }
        assert_eq!(compared, 5 * 47);
    }

    /// A PDU Session Resource Release Response built by the hand-written
    /// encoder.
    pub(crate) fn release_response(amf: u64, ran: u32, released: &[(u8, Vec<u8>)]) -> Vec<u8> {
        nextgcore_ngap::builder::build_pdu_session_resource_release_response(
            &PduSessionResourceReleaseResponse {
                amf_ue_ngap_id: amf,
                ran_ue_ngap_id: ran,
                released_list: released
                    .iter()
                    .map(|(psi, transfer)| PduSessionResourceReleasedItem {
                        pdu_session_id: *psi,
                        transfer: transfer.clone(),
                    })
                    .collect(),
            },
        )
        .expect("encode")
    }

    /// A PDU Session Resource Release Response built by the generated encoder
    /// from `ies`. Every IE of the response has criticality ignore (§9.2.1.4).
    pub(crate) fn generated_release_response(
        ies: Vec<ngap_gen::PDUSessionResourceReleaseResponseProtocolIEs_EntryValue>,
    ) -> Vec<u8> {
        use ngap_gen::PDUSessionResourceReleaseResponseProtocolIEs_EntryValue as Ie;
        let entries = ies
            .into_iter()
            .map(|value| {
                let id = match &value {
                    Ie::Id_AMF_UE_NGAP_ID(_) => ngap_gen::ID_AMF_UE_NGAP_ID,
                    Ie::Id_RAN_UE_NGAP_ID(_) => ngap_gen::ID_RAN_UE_NGAP_ID,
                    Ie::Id_PDUSessionResourceReleasedListRelRes(_) => {
                        ngap_gen::ID_PDU_SESSION_RESOURCE_RELEASED_LIST_REL_RES
                    }
                    Ie::Id_UserLocationInformation(_) => ngap_gen::ID_USER_LOCATION_INFORMATION,
                    Ie::Id_CriticalityDiagnostics(_) => ngap_gen::ID_CRITICALITY_DIAGNOSTICS,
                };
                ngap_gen::PDUSessionResourceReleaseResponseProtocolIEs_Entry {
                    id: ngap_gen::ProtocolIE_ID(id),
                    criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
                    value,
                }
            })
            .collect();
        nextgcore_ngap_gen::encode(&ngap_gen::NGAP_PDU::SuccessfulOutcome(
            ngap_gen::SuccessfulOutcome {
                procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_PDU_SESSION_RESOURCE_RELEASE),
                criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
                value: ngap_gen::SuccessfulOutcomeValue::Id_PDUSessionResourceRelease(
                    ngap_gen::PDUSessionResourceReleaseResponse {
                        protocol_i_es: ngap_gen::PDUSessionResourceReleaseResponseProtocolIEs(
                            entries,
                        ),
                    },
                ),
            },
        ))
        .expect("encode")
    }

    /// The generated released list for `released`.
    pub(crate) fn generated_released_list(
        released: &[(u8, Vec<u8>)],
    ) -> ngap_gen::PDUSessionResourceReleaseResponseProtocolIEs_EntryValue {
        ngap_gen::PDUSessionResourceReleaseResponseProtocolIEs_EntryValue::Id_PDUSessionResourceReleasedListRelRes(
            ngap_gen::PDUSessionResourceReleasedListRelRes(
                released
                    .iter()
                    .map(|(psi, transfer)| ngap_gen::PDUSessionResourceReleasedItemRelRes {
                        pdu_session_id: ngap_gen::PDUSessionID(*psi),
                        pdu_session_resource_release_response_transfer:
                            ngap_gen::PDUSessionResourceReleasedItemRelResPDUSessionResourceReleaseResponseTransfer(
                                transfer.clone(),
                            ),
                        ie_extensions: None,
                    })
                    .collect(),
            ),
        )
    }

    /// The new decode flattened to what the hand-written path could say. A
    /// response the old parser accepted always names both IDs, so a missing
    /// one here is `None` too.
    fn generated_response_view(data: &[u8]) -> Option<(u64, u32, Vec<(u8, Vec<u8>)>)> {
        match decode_pdu_session_resource_release_response_asn1(data) {
            PduSessionResourceReleaseResponseDecode::Released {
                amf_ue_ngap_id: Some(amf),
                ran_ue_ngap_id: Some(ran),
                released,
                ..
            } => Some((
                amf,
                ran,
                released
                    .into_iter()
                    .map(|r| (r.pdu_session_id, r.transfer))
                    .collect(),
            )),
            _ => None,
        }
    }

    /// Release Response Transfers at every length determinant boundary of an
    /// unconstrained OCTET STRING -- empty, short form, 127/128, and past the
    /// one-octet form -- with the genuine one-zero-octet encoding of a bare
    /// PDUSessionResourceReleaseResponseTransfer among them.
    fn response_transfers() -> Vec<Vec<u8>> {
        vec![
            vec![],
            vec![0x00],
            vec![0x31],
            vec![0xab; 127],
            vec![0xcd; 128],
            vec![0xef; 300],
        ]
    }

    /// #417 stage 5: for every Release Response the hand-written parser
    /// accepted -- every ID length, lists of 1, 2 and 256 sessions, every
    /// transfer length form, a not-comprehended IE marked ignore or notify,
    /// and the optional User Location Information and Criticality Diagnostics
    /// it skipped as unknown -- the generated decode names the same UE and the
    /// same sessions with the same transfer octets; what it refused as
    /// malformed, or over a not-comprehended IE marked reject, still yields
    /// nothing to relay.
    #[test]
    fn pdu_session_resource_release_response_generated_decode_matches_hand_written() {
        use ngap_gen::PDUSessionResourceReleaseResponseProtocolIEs_EntryValue as Ie;
        let mut corpus = Vec::new();
        for amf in &AMF_IDS[..AMF_IDS.len() - 1] {
            for ran in RAN_IDS {
                corpus.push(release_response(*amf, ran, &[(5, vec![0x00])]));
            }
        }
        for transfer in response_transfers() {
            corpus.push(release_response(7, 9, &[(3, transfer.clone())]));
            corpus.push(release_response(
                7,
                9,
                &[(3, transfer.clone()), (4, vec![0x00])],
            ));
        }
        let all: Vec<(u8, Vec<u8>)> = (0..=255u8).map(|psi| (psi, vec![psi])).collect();
        corpus.push(release_response(7, 9, &all));
        let base = release_response(7, 9, &[(5, vec![0x00])]);
        for criticality in [0x40, 0x80] {
            corpus.push(with_unknown_ie(&base, 9999, criticality));
        }
        let uli = ngap_gen::UserLocationInformation::UserLocationInformationNR(
            ngap_gen::UserLocationInformationNR {
                nr_cgi: ngap_gen::NR_CGI {
                    plmn_identity: ngap_gen::PLMNIdentity(vec![0x99, 0xf9, 0x07]),
                    nr_cell_identity: ngap_gen::NRCellIdentity(low_bits(0x12345, 36)),
                    ie_extensions: None,
                },
                tai: ngap_gen::TAI {
                    plmn_identity: ngap_gen::PLMNIdentity(vec![0x99, 0xf9, 0x07]),
                    tac: ngap_gen::TAC(vec![0x00, 0x00, 0x01]),
                    ie_extensions: None,
                },
                time_stamp: None,
                ie_extensions: None,
            },
        );
        corpus.push(generated_release_response(vec![
            Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(7)),
            Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(9)),
            generated_released_list(&[(5, vec![0x00])]),
            Ie::Id_UserLocationInformation(uli),
            Ie::Id_CriticalityDiagnostics(generated_criticality_diagnostics(&[IeDiagnostic {
                ie_id: 9999,
                criticality: ngap_gen::Criticality::IGNORE,
                type_of_error: ngap_gen::TypeOfError::NOT_UNDERSTOOD,
            }])),
        ]));
        for data in &corpus {
            let old = hand_written_parse_pdu_session_resource_release_response(data);
            assert!(
                old.is_some(),
                "the corpus holds accepted messages: {data:02x?}"
            );
            assert_eq!(generated_response_view(data), old, "{data:02x?}");
        }
        assert_eq!(corpus.len(), 11 * 8 + 6 * 2 + 1 + 2 + 1);

        let refused = [
            base[..base.len() - 1].to_vec(),
            with_unknown_ie(&base, 9999, 0x00),
        ];
        for data in &refused {
            assert_eq!(
                hand_written_parse_pdu_session_resource_release_response(data),
                None
            );
            assert_eq!(generated_response_view(data), None, "{data:02x?}");
        }
        assert!(matches!(
            decode_pdu_session_resource_release_response_asn1(&refused[1]),
            PduSessionResourceReleaseResponseDecode::Failed(ref d) if d[0].ie_id == 9999
        ));
    }

    /// A Release Response is a response, so §10.3.4.2 reports a "notify" IE in
    /// an Error Indication -- Procedure Code 28, Triggering Message
    /// successful-outcome, Procedure Criticality as received -- and the
    /// sessions are released all the same.
    #[test]
    fn a_release_response_notify_ie_is_reported_in_an_error_indication() {
        let data = with_unknown_ie(&release_response(7, 9, &[(5, vec![0x00])]), 9999, 0x80);
        let PduSessionResourceReleaseResponseDecode::Released {
            amf_ue_ngap_id: Some(7),
            ran_ue_ngap_id: Some(9),
            released,
            error_indication: Some(report),
        } = decode_pdu_session_resource_release_response_asn1(&data)
        else {
            panic!("expected Released with an Error Indication");
        };
        assert_eq!(
            released,
            vec![ReleasedPduSession {
                pdu_session_id: 5,
                transfer: vec![0x00]
            }]
        );
        assert_eq!(
            report.procedure,
            ReportedProcedure {
                procedure_code: 28,
                triggering_message: ngap_gen::TriggeringMessage::SUCCESSFUL_OUTCOME,
                procedure_criticality: ngap_gen::Criticality::REJECT,
            }
        );
        assert_eq!(
            report.cause_protocol,
            ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY
        );
        assert_eq!(
            (report.amf_ue_ngap_id, report.ran_ue_ngap_id),
            (Some(7), Some(9))
        );
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].ie_id, 9999);
        assert_eq!(
            report.diagnostics[0].criticality,
            ngap_gen::Criticality::NOTIFY
        );
        // An "ignore" IE is dropped without a report.
        let ignored = with_unknown_ie(&release_response(7, 9, &[(5, vec![0x00])]), 9999, 0x40);
        assert!(matches!(
            decode_pdu_session_resource_release_response_asn1(&ignored),
            PduSessionResourceReleaseResponseDecode::Released {
                error_indication: None,
                ..
            }
        ));
    }

    /// Responses the hand-written parser refused although every IE of a
    /// Release Response has criticality ignore (§9.2.1.4), so a missing one is
    /// ignored (§10.3.5): one with no RAN UE NGAP ID still releases its
    /// sessions, and one with no AMF UE NGAP ID decodes with `None` -- which
    /// the handler then cannot relay, since that ID is what names the UE.
    #[test]
    fn release_responses_missing_an_id_are_no_longer_refused() {
        use ngap_gen::PDUSessionResourceReleaseResponseProtocolIEs_EntryValue as Ie;
        let no_ran_id = generated_release_response(vec![
            Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(7)),
            generated_released_list(&[(5, vec![0x00])]),
        ]);
        assert_eq!(
            hand_written_parse_pdu_session_resource_release_response(&no_ran_id),
            None
        );
        let PduSessionResourceReleaseResponseDecode::Released {
            amf_ue_ngap_id: Some(7),
            ran_ue_ngap_id: None,
            released,
            error_indication: None,
        } = decode_pdu_session_resource_release_response_asn1(&no_ran_id)
        else {
            panic!("expected Released without a RAN UE NGAP ID");
        };
        assert_eq!(released.len(), 1);

        let no_amf_id = generated_release_response(vec![
            Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(9)),
            generated_released_list(&[(5, vec![0x00])]),
        ]);
        assert_eq!(
            hand_written_parse_pdu_session_resource_release_response(&no_amf_id),
            None
        );
        assert!(matches!(
            decode_pdu_session_resource_release_response_asn1(&no_amf_id),
            PduSessionResourceReleaseResponseDecode::Released {
                amf_ue_ngap_id: None,
                ran_ue_ngap_id: Some(9),
                ..
            }
        ));
    }

    /// `base` with the value of its protocol IE `id` replaced by `value`,
    /// re-encoded by the hand-written PER layer -- for wire forms neither
    /// encoder produces.
    fn with_ie_value(base: &[u8], id: u16, value: Vec<u8>) -> Vec<u8> {
        use nextgcore_asn1c::ngap::pdu::{InitiatingMessageValue, NgapPdu, SuccessfulOutcomeValue};
        use nextgcore_asn1c::per::{AperDecode, AperDecoder, AperEncode, AperEncoder};
        let mut decoder = AperDecoder::new(base);
        let mut pdu = NgapPdu::decode_aper(&mut decoder).expect("decode");
        let container = match &mut pdu {
            NgapPdu::SuccessfulOutcome(msg) => match &mut msg.value {
                SuccessfulOutcomeValue::PduSessionResourceReleaseResponse(c)
                | SuccessfulOutcomeValue::PduSessionResourceSetupResponse(c)
                | SuccessfulOutcomeValue::Other(c) => c,
                other => panic!("unexpected {other:?}"),
            },
            NgapPdu::InitiatingMessage(msg) => match &mut msg.value {
                InitiatingMessageValue::NgSetupRequest(c) => c,
                other => panic!("unexpected {other:?}"),
            },
            other => panic!("unexpected {other:?}"),
        };
        let field = container
            .ies
            .iter_mut()
            .find(|f| f.id.0 == id)
            .expect("IE present");
        field.value = value;
        let mut encoder = AperEncoder::new();
        pdu.encode_aper(&mut encoder).expect("encode");
        encoder.align();
        encoder.into_bytes().to_vec()
    }

    /// A PSI item list whose first item (PSI 5) carries an iE-Extensions
    /// container -- one entry, id 9, of `criticality` -- in its real wire form,
    /// followed by a plain second item (PSI 6). Shared by the Release (stage 5)
    /// and Setup (stage 6) Response tests: both items' extension object sets are
    /// empty in Rel-17, and the two lists share this layout.
    ///
    /// SIZE(1..256) count-1 = 1. Item 1: extension bit 0, iE-Extensions present
    /// 1, padding; PSI 5; transfer length 1, 0x00; container count-1 = 0 on 16
    /// bits; ProtocolExtensionID 9; criticality in the top two bits, padding;
    /// open type length 1, 0x00. Item 2: both bits 0, padding; PSI 6; transfer
    /// length 1, 0x00.
    fn psi_list_with_item_extension(criticality: u8) -> Vec<u8> {
        vec![
            0x01,
            0x40,
            0x05,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x09,
            criticality << 6,
            0x01,
            0x00,
            0x00,
            0x06,
            0x01,
            0x00,
        ]
    }

    /// The same two items with no extension.
    const PLAIN_PSI_LIST: [u8; 9] = [0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x06, 0x01, 0x00];

    /// Since nextgsim #218 a released item's iE-Extensions entry is a
    /// not-comprehended IE like any other, classified by its criticality per
    /// TS 38.413 §10.3.4.2 for a response message: ignore relays both sessions,
    /// notify relays them and reports the IE in an Error Indication, reject
    /// fails the procedure. Before #218 the codec decoded the entry as zero bits
    /// and returned a session 9 the gNB never named, so stage 5 refused the
    /// message; the hand-written parser, which never read the presence bit,
    /// misread the list as sessions 5 and 0 whatever the criticality.
    #[test]
    fn a_released_item_extension_is_classified_by_its_criticality() {
        use PduSessionResourceReleaseResponseDecode::{Failed, Released};
        let base = release_response(7, 9, &[(5, vec![0x00])]);
        let splice = |list: Vec<u8>| {
            with_ie_value(
                &base,
                ngap_gen::ID_PDU_SESSION_RESOURCE_RELEASED_LIST_REL_RES,
                list,
            )
        };
        let both = vec![
            ReleasedPduSession {
                pdu_session_id: 5,
                transfer: vec![0x00],
            },
            ReleasedPduSession {
                pdu_session_id: 6,
                transfer: vec![0x00],
            },
        ];
        let item_ie = |criticality| IeDiagnostic {
            ie_id: 9,
            criticality,
            type_of_error: ngap_gen::TypeOfError::NOT_UNDERSTOOD,
        };

        match decode_pdu_session_resource_release_response_asn1(&splice(
            psi_list_with_item_extension(ngap_gen::Criticality::IGNORE),
        )) {
            Released {
                amf_ue_ngap_id: Some(7),
                ran_ue_ngap_id: Some(9),
                released,
                error_indication: None,
            } => assert_eq!(released, both),
            other => panic!("ignore: {other:?}"),
        }
        match decode_pdu_session_resource_release_response_asn1(&splice(
            psi_list_with_item_extension(ngap_gen::Criticality::NOTIFY),
        )) {
            Released {
                released,
                error_indication: Some(report),
                ..
            } => {
                assert_eq!(released, both);
                assert_eq!(
                    report.diagnostics,
                    vec![item_ie(ngap_gen::Criticality::NOTIFY)]
                );
                assert_eq!(
                    report.cause_protocol,
                    ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY
                );
            }
            other => panic!("notify: {other:?}"),
        }
        match decode_pdu_session_resource_release_response_asn1(&splice(
            psi_list_with_item_extension(ngap_gen::Criticality::REJECT),
        )) {
            Failed(ies) => assert_eq!(ies, vec![item_ie(ngap_gen::Criticality::REJECT)]),
            other => panic!("reject: {other:?}"),
        }

        assert_eq!(
            hand_written_parse_pdu_session_resource_release_response(&splice(
                psi_list_with_item_extension(ngap_gen::Criticality::IGNORE)
            )),
            Some((7, 9, vec![(5, vec![0x00]), (0, vec![])])),
            "the old parser's misread"
        );
        // The same splice without the extension decodes identically on both
        // paths, so the splicing itself is sound.
        let plain = splice(PLAIN_PSI_LIST.to_vec());
        assert_eq!(
            generated_response_view(&plain),
            Some((7, 9, vec![(5, vec![0x00]), (6, vec![0x00])]))
        );
        assert_eq!(
            hand_written_parse_pdu_session_resource_release_response(&plain),
            Some((7, 9, vec![(5, vec![0x00]), (6, vec![0x00])]))
        );
    }

    // ====================================================================
    // #417 stage 6: the PDU Session Resource Setup pair, and its transfers,
    // on the generated codec
    // ====================================================================

    use hand_written_oracle::{
        hand_written_n2_sm_setup_request_transfer,
        hand_written_parse_n2_sm_setup_response_transfer,
        hand_written_parse_pdu_session_resource_setup_response,
        hand_written_pdu_session_resource_setup_request,
    };

    /// N2 SM transfers at every length determinant boundary of an unconstrained
    /// OCTET STRING -- empty, one octet, the short form's 127 and the long
    /// form's 128, the longest whose Setup Request still needs no fragmented
    /// outer length with an SD, and the first that does (X.691 §11.9.3.8,
    /// encodable since nextgsim #223; see
    /// `a_setup_request_past_16k_octets_matches_the_hand_written_fragmenting_encoder`)
    /// -- and the transfer the SMF actually builds.
    fn setup_transfers() -> Vec<Vec<u8>> {
        vec![
            vec![],
            vec![0x00],
            vec![0x5a; 127],
            vec![0x5b; 128],
            vec![0x5c; 16_352],
            vec![0x5d; 16_353],
            build_n2_sm_setup_request_transfer(0x0001_0001, [10, 45, 0, 7], 9, 9, 8)
                .expect("transfer"),
        ]
    }

    /// #417 stage 6: the generated PDU Session Resource Setup Request is byte
    /// for byte the hand-written one for every request the AMF sends -- no
    /// message-level NAS-PDU, as the only caller passes `None` -- across every
    /// PDU Session ID, every SST with and without an SD (24-bit SD extremes,
    /// and a u32 past 24 bits that both encoders mask), every transfer length
    /// form, and every UE NGAP ID length; and both refuse the same out-of-range
    /// AMF UE NGAP IDs.
    #[test]
    fn pdu_session_resource_setup_request_generated_matches_hand_written() {
        let mut compared = 0;
        let mut refused = 0;
        let mut check = |amf: u64, ran: u32, psi: u8, sst: u8, sd: Option<u32>, t: &[u8]| {
            let new =
                build_pdu_session_resource_setup_request_asn1(amf, ran, psi, sst, sd, None, t);
            let old =
                hand_written_pdu_session_resource_setup_request(amf, ran, psi, sst, sd, None, t);
            assert_eq!(
                new,
                old,
                "AMF {amf} RAN {ran} PSI {psi} SST {sst} SD {sd:?} T {}",
                t.len()
            );
            if new.is_none() {
                refused += 1;
            }
            compared += 1;
        };
        let transfer = vec![0x00];
        for psi in 0..=255u8 {
            check(42, 1001, psi, 1, None, &transfer);
        }
        for sst in 0..=255u8 {
            for sd in [
                None,
                Some(0),
                Some(0x00_0102),
                Some(0xff_ffff),
                Some(u32::MAX),
            ] {
                check(42, 1001, 5, sst, sd, &transfer);
            }
        }
        for t in setup_transfers() {
            check(42, 1001, 5, 1, Some(1), &t);
        }
        for amf in AMF_IDS {
            for ran in RAN_IDS {
                check(amf, ran, 5, 1, None, &transfer);
            }
        }
        assert_eq!(compared, 256 + 256 * 5 + 7 + 12 * 8);
        // The out-of-range AMF UE NGAP IDs, with every RAN UE NGAP ID.
        assert_eq!(refused, 8);
    }

    /// A message-level NAS-PDU goes where §9.4.1 puts it -- the IEs "in the
    /// order they appear in object set definitions": AMF UE NGAP ID, RAN UE
    /// NGAP ID, NAS-PDU, then the session list. The hand-written encoder
    /// appended it after the list, which a receiver must treat as an abstract
    /// syntax error (§10.3.6). No caller sends one today, so nothing on the
    /// wire changes; the IEs themselves are the same either way. (The
    /// hand-written parser cannot say: it has no arm for a Setup Request.)
    #[test]
    fn pdu_session_resource_setup_request_nas_pdu_is_in_object_set_order() {
        let nas = [0x7e, 0x00, 0x68, 0x01];
        let transfer = [0x00];
        let ie_order = |data: &[u8]| -> Vec<u16> {
            let ngap_gen::NGAP_PDU::InitiatingMessage(msg) =
                nextgcore_ngap_gen::decode(data).expect("decode")
            else {
                panic!("initiatingMessage");
            };
            let ngap_gen::InitiatingMessageValue::Id_PDUSessionResourceSetup(req) = msg.value
            else {
                panic!("PDU Session Resource Setup Request");
            };
            req.protocol_i_es.0.iter().map(|e| e.id.0).collect()
        };
        let new = build_pdu_session_resource_setup_request_asn1(
            42,
            1001,
            5,
            1,
            None,
            Some(&nas),
            &transfer,
        )
        .expect("encode");
        let old = hand_written_pdu_session_resource_setup_request(
            42,
            1001,
            5,
            1,
            None,
            Some(&nas),
            &transfer,
        )
        .expect("encode");
        assert_eq!(ie_order(&new), vec![10, 85, 38, 74]);
        assert_eq!(ie_order(&old), vec![10, 85, 74, 38], "the old order");
        assert_ne!(new, old);
        // The IEs, keyed by id: the same set either way.
        let content = |data: &[u8]| {
            let ngap_gen::NGAP_PDU::InitiatingMessage(msg) =
                nextgcore_ngap_gen::decode(data).expect("decode")
            else {
                panic!("initiatingMessage");
            };
            let ngap_gen::InitiatingMessageValue::Id_PDUSessionResourceSetup(req) = msg.value
            else {
                panic!("PDU Session Resource Setup Request");
            };
            let mut ies = req.protocol_i_es.0;
            ies.sort_by_key(|e| e.id.0);
            ies
        };
        assert_eq!(content(&new), content(&old));
        assert!(content(&new).iter().any(|e| matches!(
            &e.value,
            ngap_gen::PDUSessionResourceSetupRequestProtocolIEs_EntryValue::Id_NAS_PDU(n)
                if n.0 == nas
        )));
    }

    /// The bytes themselves, so the generated and hand-written encoders cannot
    /// drift together.
    #[test]
    fn pdu_session_resource_setup_request_golden_bytes() {
        assert_eq!(
            build_pdu_session_resource_setup_request_asn1(
                42,
                1001,
                5,
                1,
                Some(0x00_0102),
                None,
                &[0xab, 0xcd]
            )
            .expect("encode"),
            GOLDEN_PDU_SESSION_SETUP_REQUEST
        );
    }

    // initiatingMessage, procedure 29, criticality reject, length 31; 3 IEs:
    // AMF UE NGAP ID 42, RAN UE NGAP ID 1001, then the Setup List SUReq (IE 74,
    // reject, length 11): count-1 = 0; item preamble (extension, NAS-PDU
    // absent, iE-Extensions absent) and padding; PSI 5; S-NSSAI preamble
    // (extension, SD present, iE-Extensions absent) followed unaligned by SST 1
    // -- 010 0000 0001, padded: 0x40 0x20; SD 00 01 02; the transfer, length 2,
    // ab cd.
    const GOLDEN_PDU_SESSION_SETUP_REQUEST: &[u8] = &[
        0x00, 0x1d, 0x00, 0x1f, 0x00, 0x00, 0x03, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x2a, 0x00, 0x55,
        0x00, 0x03, 0x40, 0x03, 0xe9, 0x00, 0x4a, 0x00, 0x0b, 0x00, 0x00, 0x05, 0x40, 0x20, 0x00,
        0x01, 0x02, 0x02, 0xab, 0xcd,
    ];

    /// A PDU Session Resource Setup Response built by the hand-written encoder;
    /// an empty list is left out, as that encoder leaves it out.
    pub(crate) fn setup_response(
        amf: u64,
        ran: u32,
        setup: &[(u8, Vec<u8>)],
        failed: &[(u8, Vec<u8>)],
    ) -> Vec<u8> {
        nextgcore_ngap::builder::build_pdu_session_resource_setup_response(
            &PduSessionResourceSetupResponse {
                amf_ue_ngap_id: amf,
                ran_ue_ngap_id: ran,
                setup_list: setup
                    .iter()
                    .map(|(psi, transfer)| PduSessionResourceSetupResponseItem {
                        pdu_session_id: *psi,
                        transfer: transfer.clone(),
                    })
                    .collect(),
                failed_list: failed
                    .iter()
                    .map(|(psi, transfer)| PduSessionResourceFailedItem {
                        pdu_session_id: *psi,
                        transfer: transfer.clone(),
                    })
                    .collect(),
            },
        )
        .expect("encode")
    }

    /// A PDU Session Resource Setup Response built by the generated encoder
    /// from `ies`. Every IE of the response has criticality ignore (§9.2.1.2).
    pub(crate) fn generated_setup_response(
        ies: Vec<ngap_gen::PDUSessionResourceSetupResponseProtocolIEs_EntryValue>,
    ) -> Vec<u8> {
        use ngap_gen::PDUSessionResourceSetupResponseProtocolIEs_EntryValue as Ie;
        let entries = ies
            .into_iter()
            .map(|value| {
                let id = match &value {
                    Ie::Id_AMF_UE_NGAP_ID(_) => ngap_gen::ID_AMF_UE_NGAP_ID,
                    Ie::Id_RAN_UE_NGAP_ID(_) => ngap_gen::ID_RAN_UE_NGAP_ID,
                    Ie::Id_PDUSessionResourceSetupListSURes(_) => {
                        ngap_gen::ID_PDU_SESSION_RESOURCE_SETUP_LIST_SU_RES
                    }
                    Ie::Id_PDUSessionResourceFailedToSetupListSURes(_) => {
                        ngap_gen::ID_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_SU_RES
                    }
                    Ie::Id_UserLocationInformation(_) => ngap_gen::ID_USER_LOCATION_INFORMATION,
                    Ie::Id_CriticalityDiagnostics(_) => ngap_gen::ID_CRITICALITY_DIAGNOSTICS,
                };
                ngap_gen::PDUSessionResourceSetupResponseProtocolIEs_Entry {
                    id: ngap_gen::ProtocolIE_ID(id),
                    criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
                    value,
                }
            })
            .collect();
        nextgcore_ngap_gen::encode(&ngap_gen::NGAP_PDU::SuccessfulOutcome(
            ngap_gen::SuccessfulOutcome {
                procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_PDU_SESSION_RESOURCE_SETUP),
                criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
                value: ngap_gen::SuccessfulOutcomeValue::Id_PDUSessionResourceSetup(
                    ngap_gen::PDUSessionResourceSetupResponse {
                        protocol_i_es: ngap_gen::PDUSessionResourceSetupResponseProtocolIEs(
                            entries,
                        ),
                    },
                ),
            },
        ))
        .expect("encode")
    }

    /// The generated failed-to-set-up list for `failed`.
    pub(crate) fn generated_failed_list(
        failed: &[(u8, Vec<u8>)],
    ) -> ngap_gen::PDUSessionResourceSetupResponseProtocolIEs_EntryValue {
        ngap_gen::PDUSessionResourceSetupResponseProtocolIEs_EntryValue::Id_PDUSessionResourceFailedToSetupListSURes(
            ngap_gen::PDUSessionResourceFailedToSetupListSURes(
                failed
                    .iter()
                    .map(|(psi, transfer)| ngap_gen::PDUSessionResourceFailedToSetupItemSURes {
                        pdu_session_id: ngap_gen::PDUSessionID(*psi),
                        pdu_session_resource_setup_unsuccessful_transfer:
                            ngap_gen::PDUSessionResourceFailedToSetupItemSUResPDUSessionResourceSetupUnsuccessfulTransfer(
                                transfer.clone(),
                            ),
                        ie_extensions: None,
                    })
                    .collect(),
            ),
        )
    }

    /// The generated set-up list for `setup`.
    pub(crate) fn generated_setup_list(
        setup: &[(u8, Vec<u8>)],
    ) -> ngap_gen::PDUSessionResourceSetupResponseProtocolIEs_EntryValue {
        ngap_gen::PDUSessionResourceSetupResponseProtocolIEs_EntryValue::Id_PDUSessionResourceSetupListSURes(
            ngap_gen::PDUSessionResourceSetupListSURes(
                setup
                    .iter()
                    .map(|(psi, transfer)| ngap_gen::PDUSessionResourceSetupItemSURes {
                        pdu_session_id: ngap_gen::PDUSessionID(*psi),
                        pdu_session_resource_setup_response_transfer:
                            ngap_gen::PDUSessionResourceSetupItemSUResPDUSessionResourceSetupResponseTransfer(
                                transfer.clone(),
                            ),
                        ie_extensions: None,
                    })
                    .collect(),
            ),
        )
    }

    /// The new decode flattened to what the hand-written path could say. A
    /// response the old parser accepted always names both IDs, so a missing
    /// one here is `None` too.
    #[allow(clippy::type_complexity)]
    fn generated_setup_response_view(
        data: &[u8],
    ) -> Option<(u64, u32, Vec<(u8, Vec<u8>)>, Vec<(u8, Vec<u8>)>)> {
        match decode_pdu_session_resource_setup_response_asn1(data) {
            PduSessionResourceSetupResponseDecode::Decoded {
                amf_ue_ngap_id: Some(amf),
                ran_ue_ngap_id: Some(ran),
                setup,
                failed,
                ..
            } => Some((
                amf,
                ran,
                setup
                    .into_iter()
                    .map(|r| (r.pdu_session_id, r.transfer))
                    .collect(),
                failed
                    .into_iter()
                    .map(|r| (r.pdu_session_id, r.transfer))
                    .collect(),
            )),
            _ => None,
        }
    }

    /// #417 stage 6: for every Setup Response the hand-written parser accepted
    /// -- every ID length, set-up and failed lists of 1, 2 and 256 sessions
    /// alone and together, neither list, every transfer length form, a
    /// not-comprehended IE marked ignore or notify, and the optional User
    /// Location Information and Criticality Diagnostics it skipped as unknown
    /// -- the generated decode names the same UE and the same sessions with the
    /// same transfer octets; what it refused as malformed, or over a
    /// not-comprehended IE marked reject, still yields nothing to relay.
    #[test]
    fn pdu_session_resource_setup_response_generated_decode_matches_hand_written() {
        use ngap_gen::PDUSessionResourceSetupResponseProtocolIEs_EntryValue as Ie;
        let mut corpus = Vec::new();
        for amf in &AMF_IDS[..AMF_IDS.len() - 1] {
            for ran in RAN_IDS {
                corpus.push(setup_response(*amf, ran, &[(5, vec![0x00])], &[]));
            }
        }
        for t in response_transfers() {
            corpus.push(setup_response(7, 9, &[(3, t.clone())], &[]));
            corpus.push(setup_response(7, 9, &[], &[(3, t.clone())]));
            corpus.push(setup_response(
                7,
                9,
                &[(3, t.clone()), (4, vec![0x00])],
                &[(6, t)],
            ));
        }
        let all: Vec<(u8, Vec<u8>)> = (0..=255u8).map(|psi| (psi, vec![psi])).collect();
        corpus.push(setup_response(7, 9, &all, &[]));
        corpus.push(setup_response(7, 9, &[], &all));
        corpus.push(setup_response(7, 9, &[], &[]));
        let base = setup_response(7, 9, &[(5, vec![0x00])], &[(6, vec![0x01])]);
        for criticality in [0x40, 0x80] {
            corpus.push(with_unknown_ie(&base, 9999, criticality));
        }
        corpus.push(generated_setup_response(vec![
            Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(7)),
            Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(9)),
            generated_setup_list(&[(5, vec![0x00])]),
            Ie::Id_CriticalityDiagnostics(generated_criticality_diagnostics(&[IeDiagnostic {
                ie_id: 9999,
                criticality: ngap_gen::Criticality::IGNORE,
                type_of_error: ngap_gen::TypeOfError::NOT_UNDERSTOOD,
            }])),
        ]));
        for data in &corpus {
            let old = hand_written_parse_pdu_session_resource_setup_response(data);
            assert!(
                old.is_some(),
                "the corpus holds accepted messages: {data:02x?}"
            );
            assert_eq!(generated_setup_response_view(data), old, "{data:02x?}");
        }
        assert_eq!(corpus.len(), 11 * 8 + 6 * 3 + 3 + 2 + 1);

        let refused = [
            base[..base.len() - 1].to_vec(),
            with_unknown_ie(&base, 9999, 0x00),
        ];
        for data in &refused {
            assert_eq!(
                hand_written_parse_pdu_session_resource_setup_response(data),
                None
            );
            assert_eq!(generated_setup_response_view(data), None, "{data:02x?}");
        }
        assert!(matches!(
            decode_pdu_session_resource_setup_response_asn1(&refused[1]),
            PduSessionResourceSetupResponseDecode::Failed(ref d) if d[0].ie_id == 9999
        ));
    }

    /// A Setup Response is a response, so §10.3.4.2 reports a "notify" IE in an
    /// Error Indication -- Procedure Code 29, Triggering Message
    /// successful-outcome, Procedure Criticality as received -- and both lists
    /// come through all the same. An "ignore" IE is dropped without a report.
    #[test]
    fn a_setup_response_notify_ie_is_reported_in_an_error_indication() {
        let base = setup_response(7, 9, &[(5, vec![0x00])], &[(6, vec![0x01])]);
        let PduSessionResourceSetupResponseDecode::Decoded {
            amf_ue_ngap_id: Some(7),
            ran_ue_ngap_id: Some(9),
            setup,
            failed,
            error_indication: Some(report),
        } = decode_pdu_session_resource_setup_response_asn1(&with_unknown_ie(&base, 9999, 0x80))
        else {
            panic!("expected Decoded with an Error Indication");
        };
        assert_eq!(
            setup,
            vec![SetupResponsePduSession {
                pdu_session_id: 5,
                transfer: vec![0x00]
            }]
        );
        assert_eq!(
            failed,
            vec![SetupResponsePduSession {
                pdu_session_id: 6,
                transfer: vec![0x01]
            }]
        );
        assert_eq!(
            report.procedure,
            ReportedProcedure {
                procedure_code: 29,
                triggering_message: ngap_gen::TriggeringMessage::SUCCESSFUL_OUTCOME,
                procedure_criticality: ngap_gen::Criticality::REJECT,
            }
        );
        assert_eq!(
            report.cause_protocol,
            ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY
        );
        assert_eq!(
            (report.amf_ue_ngap_id, report.ran_ue_ngap_id),
            (Some(7), Some(9))
        );
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].ie_id, 9999);
        assert_eq!(
            report.diagnostics[0].criticality,
            ngap_gen::Criticality::NOTIFY
        );
        assert!(matches!(
            decode_pdu_session_resource_setup_response_asn1(&with_unknown_ie(&base, 9999, 0x40)),
            PduSessionResourceSetupResponseDecode::Decoded {
                error_indication: None,
                ..
            }
        ));
    }

    /// Responses the hand-written parser refused although every IE of a Setup
    /// Response has criticality ignore (§9.2.1.2), so a missing one is ignored
    /// (§10.3.5): one with no RAN UE NGAP ID still yields its sessions, and one
    /// with no AMF UE NGAP ID decodes with `None` -- which the handler then
    /// cannot relay, since that ID is what names the UE.
    #[test]
    fn setup_responses_missing_an_id_are_no_longer_refused() {
        use ngap_gen::PDUSessionResourceSetupResponseProtocolIEs_EntryValue as Ie;
        let no_ran_id = generated_setup_response(vec![
            Ie::Id_AMF_UE_NGAP_ID(ngap_gen::AMF_UE_NGAP_ID(7)),
            generated_setup_list(&[(5, vec![0x00])]),
        ]);
        assert_eq!(
            hand_written_parse_pdu_session_resource_setup_response(&no_ran_id),
            None
        );
        let PduSessionResourceSetupResponseDecode::Decoded {
            amf_ue_ngap_id: Some(7),
            ran_ue_ngap_id: None,
            setup,
            error_indication: None,
            ..
        } = decode_pdu_session_resource_setup_response_asn1(&no_ran_id)
        else {
            panic!("expected Decoded without a RAN UE NGAP ID");
        };
        assert_eq!(setup.len(), 1);

        let no_amf_id = generated_setup_response(vec![
            Ie::Id_RAN_UE_NGAP_ID(ngap_gen::RAN_UE_NGAP_ID(9)),
            generated_setup_list(&[(5, vec![0x00])]),
        ]);
        assert_eq!(
            hand_written_parse_pdu_session_resource_setup_response(&no_amf_id),
            None
        );
        assert!(matches!(
            decode_pdu_session_resource_setup_response_asn1(&no_amf_id),
            PduSessionResourceSetupResponseDecode::Decoded {
                amf_ue_ngap_id: None,
                ran_ue_ngap_id: Some(9),
                ..
            }
        ));
    }

    /// An item of either list carrying an iE-Extensions entry (id 9) is
    /// classified by its criticality, as a released item's is (stage 5): ignore
    /// relays both sessions, notify relays them and reports the IE in an Error
    /// Indication, reject fails the procedure. Before nextgsim #218 the codec
    /// decoded the entry as zero bits, and the misparse could surface as a
    /// phantom "IE 256 marked reject" read from the next item, so stage 6
    /// refused the message ahead of classifying unknown IEs. The hand-written
    /// parser never read the presence bit and misread the list as sessions 5
    /// and 0.
    #[test]
    fn a_setup_response_item_extension_is_classified_by_its_criticality() {
        use PduSessionResourceSetupResponseDecode::{Decoded, Failed};
        let base = setup_response(7, 9, &[(5, vec![0x00])], &[(5, vec![0x00])]);
        let both = vec![
            SetupResponsePduSession {
                pdu_session_id: 5,
                transfer: vec![0x00],
            },
            SetupResponsePduSession {
                pdu_session_id: 6,
                transfer: vec![0x00],
            },
        ];
        let item_ie = |criticality| IeDiagnostic {
            ie_id: 9,
            criticality,
            type_of_error: ngap_gen::TypeOfError::NOT_UNDERSTOOD,
        };
        for id in [
            ngap_gen::ID_PDU_SESSION_RESOURCE_SETUP_LIST_SU_RES,
            ngap_gen::ID_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_SU_RES,
        ] {
            let in_list =
                |decoded_setup: &Vec<SetupResponsePduSession>,
                 decoded_failed: &Vec<SetupResponsePduSession>| {
                    if id == ngap_gen::ID_PDU_SESSION_RESOURCE_SETUP_LIST_SU_RES {
                        decoded_setup.clone()
                    } else {
                        decoded_failed.clone()
                    }
                };
            let splice =
                |criticality| with_ie_value(&base, id, psi_list_with_item_extension(criticality));

            match decode_pdu_session_resource_setup_response_asn1(&splice(
                ngap_gen::Criticality::IGNORE,
            )) {
                Decoded {
                    amf_ue_ngap_id: Some(7),
                    ran_ue_ngap_id: Some(9),
                    setup,
                    failed,
                    error_indication: None,
                } => assert_eq!(in_list(&setup, &failed), both, "IE {id}"),
                other => panic!("ignore, IE {id}: {other:?}"),
            }
            match decode_pdu_session_resource_setup_response_asn1(&splice(
                ngap_gen::Criticality::NOTIFY,
            )) {
                Decoded {
                    setup,
                    failed,
                    error_indication: Some(report),
                    ..
                } => {
                    assert_eq!(in_list(&setup, &failed), both, "IE {id}");
                    assert_eq!(
                        report.diagnostics,
                        vec![item_ie(ngap_gen::Criticality::NOTIFY)],
                        "IE {id}"
                    );
                }
                other => panic!("notify, IE {id}: {other:?}"),
            }
            match decode_pdu_session_resource_setup_response_asn1(&splice(
                ngap_gen::Criticality::REJECT,
            )) {
                Failed(ies) => {
                    assert_eq!(ies, vec![item_ie(ngap_gen::Criticality::REJECT)], "IE {id}")
                }
                other => panic!("reject, IE {id}: {other:?}"),
            }

            let old = hand_written_parse_pdu_session_resource_setup_response(&splice(
                ngap_gen::Criticality::IGNORE,
            ))
            .expect("old");
            let misread = vec![(5, vec![0x00]), (0, vec![])];
            assert!(
                old.2 == misread || old.3 == misread,
                "the old parser's misread: {old:?}"
            );
            // The same splice without the extension decodes identically on
            // both paths, so the splicing itself is sound.
            let ok = with_ie_value(&base, id, PLAIN_PSI_LIST.to_vec());
            assert_eq!(
                generated_setup_response_view(&ok),
                hand_written_parse_pdu_session_resource_setup_response(&ok),
                "IE {id}"
            );
            assert!(generated_setup_response_view(&ok).is_some());
        }
    }

    /// #417 stage 6: the generated Setup Request Transfer the AMF's builder
    /// produces is byte for byte the hand-written one across every QFI, every
    /// 5QI the u16 can carry up to 300, every Priority Level ARP, TEIDs and
    /// addresses at their extremes; and both refuse the same inputs: a QFI
    /// past 63, a 5QI past 255, an ARP of 0 or past 15.
    /// A QFI is six bits (TS 23.501 §5.7.1.1). QosFlowIdentifier is
    /// INTEGER (0..63, ...), so the generated codec would encode 64 as an
    /// extension value; the builder must refuse it before the codec sees it.
    #[test]
    fn a_qfi_past_63_is_refused_although_the_codec_could_extend_it() {
        assert!(build_n2_sm_setup_request_transfer(1, [10, 0, 0, 1], MAX_QFI, 9, 8).is_some());
        assert!(build_n2_sm_setup_request_transfer(1, [10, 0, 0, 1], MAX_QFI + 1, 9, 8).is_none());
    }

    #[test]
    fn n2_sm_setup_request_transfer_generated_matches_hand_written() {
        let mut compared = 0;
        let mut refused = 0;
        let mut check = |teid: u32, addr: [u8; 4], qfi: u8, five_qi: u16, arp: u8| {
            let new = build_n2_sm_setup_request_transfer(teid, addr, qfi, five_qi, arp);
            let old = hand_written_n2_sm_setup_request_transfer(teid, addr, qfi, five_qi, arp);
            assert_eq!(
                new, old,
                "TEID {teid} addr {addr:?} QFI {qfi} 5QI {five_qi} ARP {arp}"
            );
            if new.is_none() {
                refused += 1;
            }
            compared += 1;
        };
        for qfi in 0..=255u8 {
            check(1, [10, 0, 0, 1], qfi, 9, 8);
        }
        for five_qi in 0..=300u16 {
            check(1, [10, 0, 0, 1], 1, five_qi, 8);
        }
        for arp in 0..=255u8 {
            check(1, [10, 0, 0, 1], 1, 9, arp);
        }
        for teid in [0, 1, 0xffff, 0x1_0000, u32::MAX] {
            for addr in [[0; 4], [255; 4], [127, 0, 0, 1]] {
                check(teid, addr, 63, 255, 15);
            }
        }
        assert_eq!(compared, 256 + 301 + 256 + 15);
        // QFI 64..=255, 5QI 256..=300, ARP 0 and 16..=255.
        assert_eq!(refused, 192 + 45 + 1 + 240);
    }

    /// The hand-written transfer `t` as the generated
    /// PDUSessionResourceSetupRequestTransfer, member for member -- the
    /// converter the transfer-codec comparison below runs through.
    fn generated_request_transfer(
        t: &PduSessionResourceSetupRequestTransfer,
    ) -> ngap_gen::PDUSessionResourceSetupRequestTransfer {
        use nextgcore_ngap::transfer::{
            Dynamic5qiDescriptor, GbrQosInformation, SecurityIndication,
        };
        use ngap_gen::{
            PDUSessionResourceSetupRequestTransferProtocolIEs_Entry as Entry,
            PDUSessionResourceSetupRequestTransferProtocolIEs_EntryValue as Ie,
        };
        let reject = ngap_gen::Criticality(ngap_gen::Criticality::REJECT);
        let entry = |id: u16, value: Ie| Entry {
            id: ngap_gen::ProtocolIE_ID(id),
            criticality: reject.clone(),
            value,
        };
        let tunnel = |info: &UpTransportLayerInformation| {
            let UpTransportLayerInformation::GtpTunnel(g) = info;
            generated_gtp_tunnel(
                &g.transport_layer_address.octets,
                g.transport_layer_address.bit_len,
                u32::from_be_bytes(g.gtp_teid),
            )
        };
        let non_dynamic = |d: &NonDynamic5qiDescriptor| ngap_gen::NonDynamic5QIDescriptor {
            five_qi: ngap_gen::FiveQI(d.five_qi as u8),
            priority_level_qos: d.priority_level_qos.map(ngap_gen::PriorityLevelQos),
            averaging_window: d.averaging_window.map(ngap_gen::AveragingWindow),
            maximum_data_burst_volume: d
                .maximum_data_burst_volume
                .map(ngap_gen::MaximumDataBurstVolume),
            ie_extensions: None,
        };
        let dynamic = |d: &Dynamic5qiDescriptor| ngap_gen::Dynamic5QIDescriptor {
            priority_level_qos: ngap_gen::PriorityLevelQos(d.priority_level_qos),
            packet_delay_budget: ngap_gen::PacketDelayBudget(d.packet_delay_budget),
            packet_error_rate: ngap_gen::PacketErrorRate {
                per_scalar: ngap_gen::PacketErrorRatePERScalar(d.per_scalar),
                per_exponent: ngap_gen::PacketErrorRatePERExponent(d.per_exponent),
                ie_extensions: None,
            },
            five_qi: d.five_qi.map(|q| ngap_gen::FiveQI(q as u8)),
            delay_critical: d.delay_critical.map(|c| ngap_gen::DelayCritical(c as u8)),
            averaging_window: d.averaging_window.map(ngap_gen::AveragingWindow),
            maximum_data_burst_volume: d
                .maximum_data_burst_volume
                .map(ngap_gen::MaximumDataBurstVolume),
            ie_extensions: None,
        };
        let gbr = |g: &GbrQosInformation| ngap_gen::GBR_QosInformation {
            maximum_flow_bit_rate_dl: ngap_gen::BitRate(g.maximum_flow_bit_rate_dl),
            maximum_flow_bit_rate_ul: ngap_gen::BitRate(g.maximum_flow_bit_rate_ul),
            guaranteed_flow_bit_rate_dl: ngap_gen::BitRate(g.guaranteed_flow_bit_rate_dl),
            guaranteed_flow_bit_rate_ul: ngap_gen::BitRate(g.guaranteed_flow_bit_rate_ul),
            notification_control: g
                .notification_control
                .then_some(ngap_gen::NotificationControl(
                    ngap_gen::NotificationControl::NOTIFICATION_REQUESTED,
                )),
            maximum_packet_loss_rate_dl: g
                .maximum_packet_loss_rate_dl
                .map(ngap_gen::PacketLossRate),
            maximum_packet_loss_rate_ul: g
                .maximum_packet_loss_rate_ul
                .map(ngap_gen::PacketLossRate),
            ie_extensions: None,
        };
        let security = |s: &SecurityIndication| ngap_gen::SecurityIndication {
            integrity_protection_indication: ngap_gen::IntegrityProtectionIndication(
                s.integrity_protection_indication as u8,
            ),
            confidentiality_protection_indication: ngap_gen::ConfidentialityProtectionIndication(
                s.confidentiality_protection_indication as u8,
            ),
            maximum_integrity_protected_data_rate_ul: s
                .maximum_integrity_protected_data_rate_ul
                .map(|r| ngap_gen::MaximumIntegrityProtectedDataRate(r as u8)),
            ie_extensions: None,
        };
        let flows = t
            .qos_flow_setup_request_list
            .iter()
            .map(|f| {
                let q = &f.qos_flow_level_qos_parameters;
                let arp = &q.allocation_and_retention_priority;
                ngap_gen::QosFlowSetupRequestItem {
                    qos_flow_identifier: ngap_gen::QosFlowIdentifier(f.qos_flow_identifier),
                    qos_flow_level_qos_parameters: ngap_gen::QosFlowLevelQosParameters {
                        qos_characteristics: match &q.qos_characteristics {
                            QosCharacteristics::NonDynamic5qi(d) => {
                                ngap_gen::QosCharacteristics::NonDynamic5QI(non_dynamic(d))
                            }
                            QosCharacteristics::Dynamic5qi(d) => {
                                ngap_gen::QosCharacteristics::Dynamic5QI(dynamic(d))
                            }
                        },
                        allocation_and_retention_priority:
                            ngap_gen::AllocationAndRetentionPriority {
                                priority_level_arp: ngap_gen::PriorityLevelARP(
                                    arp.priority_level_arp,
                                ),
                                pre_emption_capability: ngap_gen::Pre_emptionCapability(
                                    arp.pre_emption_capability as u8,
                                ),
                                pre_emption_vulnerability: ngap_gen::Pre_emptionVulnerability(
                                    arp.pre_emption_vulnerability as u8,
                                ),
                                ie_extensions: None,
                            },
                        gbr_qos_information: q.gbr_qos_information.as_ref().map(gbr),
                        reflective_qos_attribute: q.reflective_qos_attribute.then_some(
                            ngap_gen::ReflectiveQosAttribute(
                                ngap_gen::ReflectiveQosAttribute::SUBJECT_TO,
                            ),
                        ),
                        additional_qos_flow_information: q
                            .additional_qos_flow_information
                            .then_some(ngap_gen::AdditionalQosFlowInformation(
                                ngap_gen::AdditionalQosFlowInformation::MORE_LIKELY,
                            )),
                        ie_extensions: None,
                    },
                    e_rab_id: f.e_rab_id.map(ngap_gen::E_RAB_ID),
                    ie_extensions: None,
                }
            })
            .collect();

        let mut ies = Vec::new();
        if let Some(ambr) = t.pdu_session_aggregate_maximum_bit_rate {
            ies.push(entry(
                ngap_gen::ID_PDU_SESSION_AGGREGATE_MAXIMUM_BIT_RATE,
                Ie::Id_PDUSessionAggregateMaximumBitRate(
                    ngap_gen::PDUSessionAggregateMaximumBitRate {
                        pdu_session_aggregate_maximum_bit_rate_dl: ngap_gen::BitRate(ambr.dl),
                        pdu_session_aggregate_maximum_bit_rate_ul: ngap_gen::BitRate(ambr.ul),
                        ie_extensions: None,
                    },
                ),
            ));
        }
        ies.push(entry(
            ngap_gen::ID_UL_NGU_UP_TNL_INFORMATION,
            Ie::Id_UL_NGU_UP_TNLInformation(tunnel(&t.ul_ngu_up_tnl_information)),
        ));
        if t.data_forwarding_not_possible {
            ies.push(entry(
                ngap_gen::ID_DATA_FORWARDING_NOT_POSSIBLE,
                Ie::Id_DataForwardingNotPossible(ngap_gen::DataForwardingNotPossible(
                    ngap_gen::DataForwardingNotPossible::DATA_FORWARDING_NOT_POSSIBLE,
                )),
            ));
        }
        ies.push(entry(
            ngap_gen::ID_PDU_SESSION_TYPE,
            Ie::Id_PDUSessionType(ngap_gen::PDUSessionType(t.pdu_session_type as u8)),
        ));
        if let Some(s) = &t.security_indication {
            ies.push(entry(
                ngap_gen::ID_SECURITY_INDICATION,
                Ie::Id_SecurityIndication(security(s)),
            ));
        }
        if let Some(n) = t.network_instance {
            ies.push(entry(
                ngap_gen::ID_NETWORK_INSTANCE,
                Ie::Id_NetworkInstance(ngap_gen::NetworkInstance(n)),
            ));
        }
        ies.push(entry(
            ngap_gen::ID_QOS_FLOW_SETUP_REQUEST_LIST,
            Ie::Id_QosFlowSetupRequestList(ngap_gen::QosFlowSetupRequestList(flows)),
        ));
        ngap_gen::PDUSessionResourceSetupRequestTransfer {
            protocol_i_es: ngap_gen::PDUSessionResourceSetupRequestTransferProtocolIEs(ies),
        }
    }

    /// A non-GBR flow: `qfi`, non-dynamic `five_qi`, ARP `arp`.
    fn non_gbr_flow(qfi: u8, five_qi: u16, arp: u8) -> QosFlowSetupRequestItem {
        QosFlowSetupRequestItem {
            qos_flow_identifier: qfi,
            qos_flow_level_qos_parameters: QosFlowLevelQosParameters {
                qos_characteristics: QosCharacteristics::NonDynamic5qi(
                    NonDynamic5qiDescriptor::new(five_qi),
                ),
                allocation_and_retention_priority: AllocationAndRetentionPriority {
                    priority_level_arp: arp,
                    pre_emption_capability: PreEmptionCapability::ShallNotTriggerPreEmption,
                    pre_emption_vulnerability: PreEmptionVulnerability::NotPreEmptable,
                },
                gbr_qos_information: None,
                reflective_qos_attribute: false,
                additional_qos_flow_information: false,
            },
            e_rab_id: None,
        }
    }

    /// A UL tunnel of `bit_len` address bits taken from `octets`.
    fn ul_tunnel(octets: &[u8], bit_len: usize, teid: u32) -> UpTransportLayerInformation {
        let mut octets = octets[..bit_len.div_ceil(8)].to_vec();
        if !bit_len.is_multiple_of(8) {
            let last = octets.len() - 1;
            octets[last] &= 0xff << (8 - bit_len % 8);
        }
        UpTransportLayerInformation::GtpTunnel(GtpTunnel {
            transport_layer_address: TransportLayerAddress { octets, bit_len },
            gtp_teid: teid.to_be_bytes(),
        })
    }

    /// The Setup Request Transfer variant matrix: UL tunnels with IPv4, IPv6
    /// and IPv4v6 (160-bit) addresses and the 17/33/159-bit boundaries, every
    /// PDU Session Type, the optional AMBR / Data Forwarding Not Possible /
    /// Security Indication / Network Instance at their extremes, and QoS flow
    /// lists of 1, 2 and 64 flows -- non-GBR over every non-dynamic 5QI, GBR
    /// with and without its optional members, dynamic 5QI descriptors at their
    /// bounds, every ARP level and pre-emption combination, reflective QoS,
    /// additional-flow and E-RAB ID.
    fn request_transfer_variants() -> Vec<PduSessionResourceSetupRequestTransfer> {
        use nextgcore_ngap::transfer::{
            DelayCritical, Dynamic5qiDescriptor, GbrQosInformation,
            MaximumIntegrityProtectedDataRate, PduSessionAggregateMaximumBitRate,
            ProtectionIndication, SecurityIndication,
        };
        let base = |flows: Vec<QosFlowSetupRequestItem>| PduSessionResourceSetupRequestTransfer {
            pdu_session_aggregate_maximum_bit_rate: None,
            ul_ngu_up_tnl_information: ul_tunnel(&[10, 45, 0, 7], 32, 0x0001_0001),
            data_forwarding_not_possible: false,
            direct_forwarding_path_availability: false,
            pdu_session_type: PduSessionType::Ipv4,
            security_indication: None,
            network_instance: None,
            qos_flow_setup_request_list: flows,
        };
        let mut v = Vec::new();
        let v6: Vec<u8> = (0..16).map(|i| 0x20 + i).collect();
        let dual: Vec<u8> = [10, 45, 0, 7]
            .into_iter()
            .chain(v6.iter().copied())
            .collect();
        let ones = [0xffu8; 20];
        for (octets, bits) in [
            (&[10, 45, 0, 7][..], 32),
            (&v6[..], 128),
            (&dual[..], 160),
            (&ones[..], 17),
            (&ones[..], 33),
            (&ones[..], 159),
        ] {
            for teid in [0, u32::MAX] {
                let mut t = base(vec![non_gbr_flow(1, 9, 8)]);
                t.ul_ngu_up_tnl_information = ul_tunnel(octets, bits, teid);
                v.push(t);
            }
        }
        for ty in [
            PduSessionType::Ipv4,
            PduSessionType::Ipv6,
            PduSessionType::Ipv4v6,
            PduSessionType::Ethernet,
            PduSessionType::Unstructured,
        ] {
            let mut t = base(vec![non_gbr_flow(1, 9, 8)]);
            t.pdu_session_type = ty;
            v.push(t);
        }
        for (dl, ul) in [
            (0, 0),
            (1, 1),
            (1 << 32, 1_000_000_000),
            (4_000_000_000_000, 4_000_000_000_000),
        ] {
            let mut t = base(vec![non_gbr_flow(1, 9, 8)]);
            t.pdu_session_aggregate_maximum_bit_rate =
                Some(PduSessionAggregateMaximumBitRate { dl, ul });
            v.push(t);
        }
        let mut t = base(vec![non_gbr_flow(1, 9, 8)]);
        t.data_forwarding_not_possible = true;
        v.push(t);
        let indications = [
            ProtectionIndication::Required,
            ProtectionIndication::Preferred,
            ProtectionIndication::NotNeeded,
        ];
        for integrity in indications {
            for confidentiality in indications {
                for rate in [
                    None,
                    Some(MaximumIntegrityProtectedDataRate::Bitrate64kbs),
                    Some(MaximumIntegrityProtectedDataRate::MaximumUeRate),
                ] {
                    let mut t = base(vec![non_gbr_flow(1, 9, 8)]);
                    t.security_indication = Some(SecurityIndication {
                        integrity_protection_indication: integrity,
                        confidentiality_protection_indication: confidentiality,
                        maximum_integrity_protected_data_rate_ul: rate,
                    });
                    v.push(t);
                }
            }
        }
        for n in [1, 2, 255, 256] {
            let mut t = base(vec![non_gbr_flow(1, 9, 8)]);
            t.network_instance = Some(n);
            v.push(t);
        }
        // Every non-dynamic 5QI, and the optional members at their bounds.
        for five_qi in 0..=255u16 {
            v.push(base(vec![non_gbr_flow((five_qi % 64) as u8, five_qi, 1)]));
        }
        for (p, w, b) in [(1, 0, 0), (127, 4095, 4095), (64, 2000, 255)] {
            let mut f = non_gbr_flow(5, 9, 8);
            f.qos_flow_level_qos_parameters.qos_characteristics =
                QosCharacteristics::NonDynamic5qi(NonDynamic5qiDescriptor {
                    five_qi: 9,
                    priority_level_qos: Some(p),
                    averaging_window: Some(w),
                    maximum_data_burst_volume: Some(b),
                });
            v.push(base(vec![f]));
        }
        // Every ARP level and pre-emption combination.
        for arp in 1..=15u8 {
            for cap in [
                PreEmptionCapability::ShallNotTriggerPreEmption,
                PreEmptionCapability::MayTriggerPreEmption,
            ] {
                for vul in [
                    PreEmptionVulnerability::NotPreEmptable,
                    PreEmptionVulnerability::PreEmptable,
                ] {
                    let mut f = non_gbr_flow(5, 9, arp);
                    f.qos_flow_level_qos_parameters
                        .allocation_and_retention_priority = AllocationAndRetentionPriority {
                        priority_level_arp: arp,
                        pre_emption_capability: cap,
                        pre_emption_vulnerability: vul,
                    };
                    v.push(base(vec![f]));
                }
            }
        }
        // GBR flows (5QI 1 conversational voice), optional members off and on,
        // loss rates at the root's bounds (#462).
        for (notification, dl_loss, ul_loss) in [
            (false, None, None),
            (true, Some(0), None),
            (true, None, Some(1000)),
            (true, Some(0), Some(1000)),
            (false, Some(1000), Some(0)),
            (true, Some(255), Some(256)),
        ] {
            for rate in [0u64, 64_000, 4_000_000_000_000] {
                let mut f = non_gbr_flow(1, 1, 2);
                f.qos_flow_level_qos_parameters.gbr_qos_information = Some(GbrQosInformation {
                    maximum_flow_bit_rate_dl: rate,
                    maximum_flow_bit_rate_ul: rate,
                    guaranteed_flow_bit_rate_dl: rate / 2,
                    guaranteed_flow_bit_rate_ul: rate / 2,
                    notification_control: notification,
                    maximum_packet_loss_rate_dl: dl_loss,
                    maximum_packet_loss_rate_ul: ul_loss,
                });
                v.push(base(vec![f]));
            }
        }
        // Dynamic 5QI descriptors at their bounds.
        for (p, pdb, s, e, q, dc, w, b) in [
            (1, 0, 0, 0, None, None, None, None),
            (
                127,
                1023,
                9,
                9,
                Some(255),
                Some(DelayCritical::DelayCritical),
                Some(4095),
                Some(4095),
            ),
            (
                20,
                100,
                1,
                6,
                Some(0),
                Some(DelayCritical::NonDelayCritical),
                Some(0),
                Some(0),
            ),
        ] {
            let mut f = non_gbr_flow(7, 9, 8);
            f.qos_flow_level_qos_parameters.qos_characteristics =
                QosCharacteristics::Dynamic5qi(Dynamic5qiDescriptor {
                    priority_level_qos: p,
                    packet_delay_budget: pdb,
                    per_scalar: s,
                    per_exponent: e,
                    five_qi: q,
                    delay_critical: dc,
                    averaging_window: w,
                    maximum_data_burst_volume: b,
                });
            v.push(base(vec![f]));
        }
        // Reflective QoS, additional flow information, E-RAB IDs.
        for (reflective, additional, erab) in [
            (true, false, None),
            (false, true, Some(0)),
            (true, true, Some(15)),
        ] {
            let mut f = non_gbr_flow(3, 9, 8);
            f.qos_flow_level_qos_parameters.reflective_qos_attribute = reflective;
            f.qos_flow_level_qos_parameters
                .additional_qos_flow_information = additional;
            f.e_rab_id = erab;
            v.push(base(vec![f]));
        }
        // Lists of 2 and of maxnoofQosFlows = 64 flows.
        v.push(base(vec![non_gbr_flow(1, 9, 8), non_gbr_flow(2, 5, 1)]));
        v.push(base((0..64u8).map(|q| non_gbr_flow(q, 9, 8)).collect()));
        // Everything at once.
        let mut t = base(vec![non_gbr_flow(1, 9, 8), non_gbr_flow(2, 1, 2)]);
        t.pdu_session_aggregate_maximum_bit_rate = Some(PduSessionAggregateMaximumBitRate {
            dl: 1_000_000_000,
            ul: 500_000_000,
        });
        t.ul_ngu_up_tnl_information = ul_tunnel(&dual, 160, 0xdead_beef);
        t.data_forwarding_not_possible = true;
        t.pdu_session_type = PduSessionType::Ipv4v6;
        t.security_indication = Some(SecurityIndication {
            integrity_protection_indication: ProtectionIndication::Required,
            confidentiality_protection_indication: ProtectionIndication::Preferred,
            maximum_integrity_protected_data_rate_ul: Some(
                MaximumIntegrityProtectedDataRate::MaximumUeRate,
            ),
        });
        t.network_instance = Some(17);
        v.push(t);
        v
    }

    /// #417 stage 6: the generated codec encodes every Setup Request Transfer of
    /// the variant matrix exactly as the hand-written transfer codec does --
    /// the codec the SMF builds its transfer with -- and decodes the
    /// hand-written bytes back to the same value. A list of 65 flows, one past
    /// maxnoofQosFlows, both refuse.
    #[test]
    fn setup_request_transfer_codecs_agree_over_the_variant_matrix() {
        let variants = request_transfer_variants();
        for t in &variants {
            let old = t.encode().expect("hand-written encode");
            let generated = generated_request_transfer(t);
            let new = nextgcore_ngap_gen::encode_contained(&generated).expect("generated encode");
            assert_eq!(new, old, "{t:?}");
            let back = nextgcore_ngap_gen::decode_contained::<
                ngap_gen::PDUSessionResourceSetupRequestTransfer,
            >(&old)
            .expect("generated decode");
            assert_eq!(back, generated, "{t:?}");
        }
        assert_eq!(
            variants.len(),
            12 + 5 + 4 + 1 + 27 + 4 + 256 + 3 + 60 + 18 + 3 + 3 + 2 + 1
        );

        let mut too_many = variants[0].clone();
        too_many.qos_flow_setup_request_list =
            (0..65u8).map(|q| non_gbr_flow(q % 64, 9, 8)).collect();
        assert!(too_many.encode().is_err());
        assert!(
            nextgcore_ngap_gen::encode_contained(&generated_request_transfer(&too_many)).is_err()
        );
    }

    /// A PDUSessionResourceSetupResponseTransfer from the hand-written codec:
    /// DL tunnel `bits` bits of `address`, TEID, and the associated `qfis`.
    fn hand_written_response_transfer(
        address: &[u8],
        bits: usize,
        teid: u32,
        qfis: &[u8],
    ) -> PduSessionResourceSetupResponseTransfer {
        use nextgcore_ngap::transfer::{AssociatedQosFlowItem, QosFlowPerTnlInformation};
        PduSessionResourceSetupResponseTransfer {
            dl_qos_flow_per_tnl_information: QosFlowPerTnlInformation {
                up_transport_layer_information: ul_tunnel(address, bits, teid),
                associated_qos_flow_list: qfis
                    .iter()
                    .map(|&q| AssociatedQosFlowItem {
                        qos_flow_identifier: q,
                        qos_flow_mapping_indication: None,
                    })
                    .collect(),
            },
            additional_dl_qos_flow_per_tnl_information: Vec::new(),
            security_result: None,
            qos_flow_failed_to_setup_list: Vec::new(),
        }
    }

    /// #417 stage 6: for every Setup Response Transfer the hand-written decoder
    /// accepted -- IPv4/IPv6/IPv4v6 and odd-length addresses of more than 16
    /// bits (shorter ones: `transport_layer_addresses_of_16_bits_or_fewer_agree`), TEID extremes,
    /// 1, 2 and 64 associated flows with and without a mapping indication, a
    /// Security Result, a failed-flow list with causes -- the generated decode
    /// gives the same endpoint; garbage stays refused.
    #[test]
    fn n2_sm_setup_response_transfer_generated_matches_hand_written() {
        use nextgcore_ngap::transfer::{
            AssociatedQosFlowItem, ProtectionResult, QosFlowMappingIndication,
            QosFlowWithCauseItem, SecurityResult,
        };
        let v6: Vec<u8> = (0..16).map(|i| 0x20 + i).collect();
        let dual: Vec<u8> = [10, 45, 0, 3]
            .into_iter()
            .chain(v6.iter().copied())
            .collect();
        let ones = [0xffu8; 20];
        let mut corpus = Vec::new();
        for (octets, bits) in [
            (&[10, 45, 0, 3][..], 32),
            (&v6[..], 128),
            (&dual[..], 160),
            (&ones[..], 17),
            (&ones[..], 33),
            (&ones[..], 159),
        ] {
            for teid in [0, 0xdead_beef, u32::MAX] {
                corpus.push(hand_written_response_transfer(octets, bits, teid, &[9]));
            }
        }
        corpus.push(hand_written_response_transfer(
            &[10, 0, 0, 1],
            32,
            1,
            &[1, 2],
        ));
        corpus.push(hand_written_response_transfer(
            &[10, 0, 0, 1],
            32,
            1,
            &(0..64).collect::<Vec<u8>>(),
        ));
        for mapping in [QosFlowMappingIndication::Ul, QosFlowMappingIndication::Dl] {
            let mut t = hand_written_response_transfer(&[10, 0, 0, 1], 32, 1, &[]);
            t.dl_qos_flow_per_tnl_information.associated_qos_flow_list =
                vec![AssociatedQosFlowItem {
                    qos_flow_identifier: 5,
                    qos_flow_mapping_indication: Some(mapping),
                }];
            corpus.push(t);
        }
        for (i, c) in [
            (ProtectionResult::Performed, ProtectionResult::NotPerformed),
            (ProtectionResult::NotPerformed, ProtectionResult::Performed),
        ] {
            let mut t = hand_written_response_transfer(&[10, 0, 0, 1], 32, 1, &[9]);
            t.security_result = Some(SecurityResult {
                integrity_protection_result: i,
                confidentiality_protection_result: c,
            });
            t.qos_flow_failed_to_setup_list = vec![
                QosFlowWithCauseItem {
                    qos_flow_identifier: 2,
                    cause: build_cause(0, 46),
                },
                QosFlowWithCauseItem {
                    qos_flow_identifier: 63,
                    cause: build_cause(1, 0),
                },
            ];
            corpus.push(t);
        }
        for t in &corpus {
            let bytes = t.encode().expect("encode");
            let old = hand_written_parse_n2_sm_setup_response_transfer(&bytes);
            assert!(old.is_some(), "the corpus holds accepted transfers: {t:?}");
            assert_eq!(parse_n2_sm_setup_response_transfer(&bytes), old, "{t:?}");
        }
        assert_eq!(corpus.len(), 18 + 2 + 2 + 2);
        for garbage in [&[][..], &[0x09, 0x00, 0x00][..], &[0xff; 3][..]] {
            assert_eq!(
                hand_written_parse_n2_sm_setup_response_transfer(garbage),
                None
            );
            assert_eq!(parse_n2_sm_setup_response_transfer(garbage), None);
        }
    }

    /// A conformant Setup Response Transfer from a dual-connectivity gNB: the
    /// DL tunnel plus one Additional DL QoS Flow per TNL Information, which is a
    /// `QosFlowPerTNLInformationList` (§9.3.4.2), encoded by the generated codec
    /// -- as nextgsim's gNB encodes it.
    fn dual_connectivity_response_transfer() -> Vec<u8> {
        let per_tnl = |address: [u8; 4], teid: u32, qfi: u8| ngap_gen::QosFlowPerTNLInformation {
            up_transport_layer_information: generated_gtp_tunnel(&address, 32, teid),
            associated_qos_flow_list: ngap_gen::AssociatedQosFlowList(vec![
                ngap_gen::AssociatedQosFlowItem {
                    qos_flow_identifier: ngap_gen::QosFlowIdentifier(qfi),
                    qos_flow_mapping_indication: None,
                    ie_extensions: None,
                },
            ]),
            ie_extensions: None,
        };
        nextgcore_ngap_gen::encode_contained(&ngap_gen::PDUSessionResourceSetupResponseTransfer {
            dl_qos_flow_per_tnl_information: per_tnl([10, 45, 0, 3], 0xdead_beef, 9),
            additional_dl_qos_flow_per_tnl_information: Some(
                ngap_gen::QosFlowPerTNLInformationList(vec![
                    ngap_gen::QosFlowPerTNLInformationItem {
                        qos_flow_per_tnl_information: per_tnl([10, 45, 0, 4], 0x0000_0002, 9),
                        ie_extensions: None,
                    },
                ]),
            ),
            security_result: Some(ngap_gen::SecurityResult {
                integrity_protection_result: ngap_gen::IntegrityProtectionResult(
                    ngap_gen::IntegrityProtectionResult::PERFORMED,
                ),
                confidentiality_protection_result: ngap_gen::ConfidentialityProtectionResult(
                    ngap_gen::ConfidentialityProtectionResult::PERFORMED,
                ),
                ie_extensions: None,
            }),
            qos_flow_failed_to_setup_list: None,
            ie_extensions: None,
        })
        .expect("encode")
    }

    /// The Additional DL QoS Flow per TNL Information is a list, and both
    /// decoders read it as one. Until #462 the hand-written decoder read a
    /// single element, without the list's count or the item's preamble, and
    /// misread the additional tunnel -- a 2-bit address, the second tunnel's
    /// address octets taken for its TEID, QFI 0. The DL endpoint the AMF logs
    /// precedes it, so both always gave the same one.
    #[test]
    fn a_dual_connectivity_setup_response_transfer_reads_its_additional_list() {
        let bytes = dual_connectivity_response_transfer();
        let endpoint = Some(GnbN3Endpoint {
            teid: 0xdead_beef,
            address: vec![10, 45, 0, 3],
            qfis: vec![9],
        });
        assert_eq!(parse_n2_sm_setup_response_transfer(&bytes), endpoint);
        assert_eq!(
            hand_written_parse_n2_sm_setup_response_transfer(&bytes),
            endpoint
        );

        let generated = nextgcore_ngap_gen::decode_contained::<
            ngap_gen::PDUSessionResourceSetupResponseTransfer,
        >(&bytes)
        .expect("decode");
        let additional = generated
            .additional_dl_qos_flow_per_tnl_information
            .expect("additional")
            .0;
        assert_eq!(additional.len(), 1);
        let ngap_gen::UPTransportLayerInformation::GTPTunnel(ref tunnel) = additional[0]
            .qos_flow_per_tnl_information
            .up_transport_layer_information
        else {
            panic!("GTP tunnel");
        };
        assert_eq!(
            transport_layer_address_octets(&tunnel.transport_layer_address),
            vec![10, 45, 0, 4]
        );
        assert_eq!(tunnel.gtp_teid.0, vec![0, 0, 0, 2]);

        let old = PduSessionResourceSetupResponseTransfer::decode(&bytes).expect("old decode");
        assert_eq!(old.additional_dl_qos_flow_per_tnl_information.len(), 1);
        let UpTransportLayerInformation::GtpTunnel(ref t) =
            old.additional_dl_qos_flow_per_tnl_information[0].up_transport_layer_information;
        assert_eq!(t.transport_layer_address.octets, vec![10, 45, 0, 4]);
        assert_eq!(t.transport_layer_address.bit_len, 32);
        assert_eq!(t.gtp_teid, [0, 0, 0, 2]);
        assert_eq!(
            old.additional_dl_qos_flow_per_tnl_information[0].associated_qos_flow_list[0]
                .qos_flow_identifier,
            9
        );
        // And the hand-written encoder produces the generated bytes.
        assert_eq!(old.encode().expect("old encode"), bytes);
    }

    /// X.691 §16.11 octet-aligns a variable-size BIT STRING whatever its
    /// length, as the hand-written codec does. The fork used to align only
    /// strings longer than 16 bits, so a Transport Layer Address of 16 bits or
    /// fewer encoded differently and was misread; since nextgsim #226 (PR #227)
    /// both codecs give the same bytes and the same endpoint. From 17 bits up
    /// the variant matrix above covers it.
    #[test]
    fn transport_layer_addresses_of_16_bits_or_fewer_agree() {
        for bits in [1usize, 8, 15, 16] {
            let mut t = request_transfer_variants()[0].clone();
            t.ul_ngu_up_tnl_information = ul_tunnel(&[0xff; 20], bits, 0);
            let old = t.encode().expect("hand-written encode");
            let new = nextgcore_ngap_gen::encode_contained(&generated_request_transfer(&t))
                .expect("generated encode");
            assert_eq!(new, old, "{bits} bits");
            let response = hand_written_response_transfer(&[0xff; 20], bits, 0, &[9])
                .encode()
                .expect("encode");
            let parsed = parse_n2_sm_setup_response_transfer(&response);
            assert!(parsed.is_some(), "{bits} bits");
            assert_eq!(
                parsed,
                hand_written_parse_n2_sm_setup_response_transfer(&response),
                "{bits} bits"
            );
        }
    }

    /// PacketLossRate is INTEGER (0..1000, ...) -- extensible, so its encoding
    /// starts with an extension bit. Until #462 the hand-written transfer codec
    /// encoded and decoded it as the non-extensible (0..1000); the bit shows
    /// when it lands on an octet boundary, as it does for the UL rate right
    /// after an aligned DL rate, where the conformant encoding is one octet
    /// longer. Now both codecs give the same bytes and read each other's form.
    #[test]
    fn packet_loss_rate_carries_its_extension_bit() {
        use nextgcore_ngap::transfer::GbrQosInformation;
        let mut f = non_gbr_flow(1, 1, 2);
        f.qos_flow_level_qos_parameters.gbr_qos_information = Some(GbrQosInformation {
            maximum_flow_bit_rate_dl: 64_000,
            maximum_flow_bit_rate_ul: 64_000,
            guaranteed_flow_bit_rate_dl: 32_000,
            guaranteed_flow_bit_rate_ul: 32_000,
            notification_control: true,
            maximum_packet_loss_rate_dl: Some(0),
            maximum_packet_loss_rate_ul: Some(1000),
        });
        let mut t = request_transfer_variants()[0].clone();
        t.qos_flow_setup_request_list = vec![f];
        let old = t.encode().expect("hand-written encode");
        let generated = generated_request_transfer(&t);
        let new = nextgcore_ngap_gen::encode_contained(&generated).expect("generated encode");
        assert_eq!(new, old);
        // DL rate 0 then UL rate 1000 = 0x03e8: the UL rate's extension bit (0)
        // takes an octet of its own, then the value is aligned.
        assert_eq!(
            &new[new.len() - 6..],
            &[0x00, 0x00, 0x00, 0x00, 0x03, 0xe8][..]
        );
        let back = nextgcore_ngap_gen::decode_contained::<
            ngap_gen::PDUSessionResourceSetupRequestTransfer,
        >(&old)
        .expect("generated decode");
        assert_eq!(back, generated);
        assert_eq!(
            PduSessionResourceSetupRequestTransfer::decode(&new).expect("hand-written decode"),
            t,
            "the hand-written decoder reads the conformant form back"
        );
    }

    /// Past 16,383 octets an APER length determinant is fragmented (X.691
    /// §11.9.3.8): 16K/32K/48K/64K pieces, then the remainder with its own
    /// determinant. The hand-written encoder always fragmented; the fork has
    /// since nextgsim #223 (#222), so the 16,383-octet ceiling stage 6 had to
    /// accept is gone and the generated Setup Request is byte for byte the
    /// hand-written one on both sides of the boundary -- the transfer alone
    /// fragmenting (16,384+) and the outer initiating-message value
    /// fragmenting (16,353+, the transfer plus 31 octets with an SD) -- across
    /// one, two, three and four 16K fragments and a non-zero remainder past
    /// 64K. Each also decodes back, through the generated decoder, to the
    /// transfer it carried. Before #223 every length here but 16,352 was
    /// refused.
    #[test]
    fn a_setup_request_past_16k_octets_matches_the_hand_written_fragmenting_encoder() {
        for n in [
            16_352, 16_353, 16_383, 16_384, 16_385, 20_000, 32_767, 32_768, 49_152, 65_535, 65_536,
            70_000,
        ] {
            let transfer: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let generated = build_pdu_session_resource_setup_request_asn1(
                42,
                1001,
                5,
                1,
                Some(1),
                None,
                &transfer,
            )
            .unwrap_or_else(|| panic!("generated refused a {n}-octet transfer"));
            let oracle = hand_written_pdu_session_resource_setup_request(
                42,
                1001,
                5,
                1,
                Some(1),
                None,
                &transfer,
            )
            .expect("the hand-written encoder fragments");
            assert!(generated == oracle, "{n}-octet transfer: bytes differ");
            if n > 16_352 {
                // The outer initiating-message length is itself fragmented:
                // byte 3 is its first octet, 0b11 + multiplier.
                assert!(generated[3] >= 0xC0, "{n}: outer length not fragmented");
            }
            let ngap_gen::NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
                value: ngap_gen::InitiatingMessageValue::Id_PDUSessionResourceSetup(request),
                ..
            }) = nextgcore_ngap_gen::decode(&generated).expect("generated decode")
            else {
                panic!("{n}: not a Setup Request");
            };
            let carried = request
                .protocol_i_es
                .0
                .into_iter()
                .find_map(|ie| match ie.value {
                    ngap_gen::PDUSessionResourceSetupRequestProtocolIEs_EntryValue::Id_PDUSessionResourceSetupListSUReq(
                        list,
                    ) => Some(list.0[0].pdu_session_resource_setup_request_transfer.0.clone()),
                    _ => None,
                })
                .expect("setup list");
            assert!(carried == transfer, "{n}: transfer not decoded back intact");
        }
    }

    /// The decode side of the same boundary: a Setup Response whose transfers
    /// pass 16,383 octets -- set-up and failed lists, a fragmented transfer
    /// and a fragmented outer length -- decodes through the generated decoder
    /// to exactly what the hand-written parser reads, whether the hand-written
    /// or the generated encoder framed it. Before nextgsim #223 the fork read
    /// the next fragment header as content (#222), so a fragmented open type
    /// decoded without error to corrupted octets.
    #[test]
    fn a_setup_response_past_16k_octets_decodes_as_the_hand_written_parser_reads_it() {
        for n in [
            16_383, 16_384, 16_385, 20_000, 32_768, 49_152, 65_536, 70_000,
        ] {
            let t: Vec<u8> = (0..n).map(|i| (i % 241) as u8).collect();
            let expected = Some((7, 9, vec![(3, t.clone())], vec![(6, t.clone())]));
            let hand_built = setup_response(7, 9, &[(3, t.clone())], &[(6, t.clone())]);
            assert_eq!(
                hand_written_parse_pdu_session_resource_setup_response(&hand_built),
                expected,
                "{n}: the oracle reads its own framing"
            );
            assert!(
                generated_setup_response_view(&hand_built) == expected,
                "{n}: generated decode of the hand-written framing differs"
            );
            let generated_built = generated_setup_response(vec![
                ngap_gen::PDUSessionResourceSetupResponseProtocolIEs_EntryValue::Id_AMF_UE_NGAP_ID(
                    ngap_gen::AMF_UE_NGAP_ID(7),
                ),
                ngap_gen::PDUSessionResourceSetupResponseProtocolIEs_EntryValue::Id_RAN_UE_NGAP_ID(
                    ngap_gen::RAN_UE_NGAP_ID(9),
                ),
                generated_setup_list(&[(3, t.clone())]),
                generated_failed_list(&[(6, t.clone())]),
            ]);
            // The two framings are not byte-identical at ANY length: the
            // hand-written builder marks both UE NGAP IDs criticality reject,
            // where §9.2.1.2 gives every IE of this message criticality
            // ignore. amfd only decodes this message, so the point here is
            // that both framings decode alike past 16K.
            assert!(
                generated_setup_response_view(&generated_built) == expected,
                "{n}: generated decode of the generated framing differs"
            );
        }
    }

    /// A transfer whose iE-Extensions carries an extension the schema does not
    /// know -- here the MBS Support Indicator (id 309) relabelled 9999 on the
    /// wire -- decodes to the same endpoint: the hand-written decoder never
    /// read the extension container, and the generated one skips the unknown
    /// entry. So does one whose DL GTP tunnel carries an iE-Extensions entry:
    /// GTPTunnel's extension object set is empty, and since nextgsim #218 the
    /// codec skips the entry as an open type instead of reading it as zero bits
    /// and the associated QoS flow list after it from the wrong offset.
    #[test]
    fn setup_response_transfer_extensions_are_skipped() {
        let mut transfer = nextgcore_ngap_gen::decode_contained::<
            ngap_gen::PDUSessionResourceSetupResponseTransfer,
        >(
            &hand_written_response_transfer(&[10, 45, 0, 3], 32, 7, &[9])
                .encode()
                .expect("encode"),
        )
        .expect("decode");
        transfer.ie_extensions = Some(ngap_gen::PDUSessionResourceSetupResponseTransferIE_Extensions(vec![
            ngap_gen::PDUSessionResourceSetupResponseTransferIE_Extensions_Entry {
                id: ngap_gen::ProtocolExtensionID(ngap_gen::ID_MBS_SUPPORT_INDICATOR),
                criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
                extension_value:
                    ngap_gen::PDUSessionResourceSetupResponseTransferIE_Extensions_EntryExtensionValue::Id_MBS_SupportIndicator(
                        ngap_gen::MBS_SupportIndicator(ngap_gen::MBS_SupportIndicator::TRUE),
                    ),
            },
        ]));
        let known = nextgcore_ngap_gen::encode_contained(&transfer).expect("encode");
        // The extension id is the only 309 (0x0135) on the wire: relabel it.
        let at = known
            .windows(2)
            .rposition(|w| w == [0x01, 0x35])
            .expect("id 309");
        let mut unknown = known.clone();
        unknown[at..at + 2].copy_from_slice(&9999u16.to_be_bytes());
        let endpoint = Some(GnbN3Endpoint {
            teid: 7,
            address: vec![10, 45, 0, 3],
            qfis: vec![9],
        });
        assert_eq!(parse_n2_sm_setup_response_transfer(&known), endpoint);
        assert_eq!(parse_n2_sm_setup_response_transfer(&unknown), endpoint);
        assert_eq!(
            hand_written_parse_n2_sm_setup_response_transfer(&unknown),
            endpoint
        );
        assert!(
            nextgcore_ngap_gen::decode_contained::<ngap_gen::PDUSessionResourceSetupResponseTransfer>(
                &unknown
            )
            .is_err(),
            "the default decode fails on the unknown id, so the skip is what decodes it"
        );

        // A DL GTP tunnel carrying an iE-Extensions entry, in its real wire
        // form. GTPTunnel's extension value type has no variants, so no typed
        // value can carry one: the transfer is written bit by bit, and the
        // writer is proven against the codec on the same transfer without the
        // extension, where the two must agree byte for byte.
        let tunnel_transfer = |extension: Option<&[u8]>| {
            let mut w = BitWriter::default();
            w.bits(0, 1); // PDUSessionResourceSetupResponseTransfer: extension bit
            w.bits(0, 4); // ...its four OPTIONALs absent
            w.bits(0, 2); // QosFlowPerTNLInformation: extension bit, iE-Extensions absent
            w.bits(0, 1); // UPTransportLayerInformation: gTPTunnel
            w.bits(0, 1); // GTPTunnel: extension bit
            w.bits(u64::from(extension.is_some()), 1); // ...iE-Extensions present
            w.bits(0, 1); // TransportLayerAddress: SIZE extension bit
            w.bits(31, 8); // ...length 32, as 32 - 1 over SIZE(1..160)
            w.align();
            w.octets(&[10, 45, 0, 3]);
            w.octets(&7u32.to_be_bytes()); // GTP-TEID, SIZE(4), already aligned
            if let Some(container) = extension {
                w.octets(container); // starts and ends octet-aligned
            }
            w.bits(0, 6); // AssociatedQosFlowList: count - 1 over SIZE(1..64)
            w.bits(0, 3); // AssociatedQosFlowItem: extension bit, two OPTIONALs absent
            w.bits(0, 1); // QosFlowIdentifier: extension bit
            w.bits(9, 6); // ...QFI 9
            w.align();
            w.into_bytes()
        };
        let mut no_extension = transfer.clone();
        no_extension.ie_extensions = None;
        assert_eq!(
            tunnel_transfer(None),
            nextgcore_ngap_gen::encode_contained(&no_extension).expect("encode"),
            "the bit writer agrees with the codec"
        );
        // A one-entry ProtocolExtensionContainer, as the codec encodes it for a
        // set it does know -- the wire form does not depend on the set -- with
        // the id relabelled to 9 and the given criticality.
        let container = |criticality: u8| {
            let mut bytes = nextgcore_ngap_gen::encode_contained(
                transfer.ie_extensions.as_ref().expect("the MBS extension"),
            )
            .expect("encode");
            assert_eq!(&bytes[..4], &[0x00, 0x00, 0x01, 0x35], "count - 1, id 309");
            bytes[2..4].copy_from_slice(&9u16.to_be_bytes());
            bytes[4] = criticality << 6;
            bytes
        };
        for criticality in [
            ngap_gen::Criticality::IGNORE,
            ngap_gen::Criticality::NOTIFY,
            ngap_gen::Criticality::REJECT,
        ] {
            let extended = tunnel_transfer(Some(&container(criticality)));
            assert_eq!(
                parse_n2_sm_setup_response_transfer(&extended),
                endpoint,
                "criticality {criticality}"
            );
            assert!(
                nextgcore_ngap_gen::decode_contained::<
                    ngap_gen::PDUSessionResourceSetupResponseTransfer,
                >(&extended)
                .is_err(),
                "the default decode refuses the unknown entry, so the skip is what decodes it"
            );
        }
        let plain = hand_written_response_transfer(&[10, 45, 0, 3], 32, 7, &[9])
            .encode()
            .expect("encode");
        assert_eq!(parse_n2_sm_setup_response_transfer(&plain), endpoint);
    }

    /// A choice extension where the schema defines none -- GNB-ID's and
    /// UPTransportLayerInformation's choice-Extensions, both with empty object
    /// sets -- is refused as it was before nextgsim #218, now by the decode
    /// itself: the alternative's value type has no variants, so the AMF's
    /// pattern on the other alternative is irrefutable and the refusal cannot
    /// come from it. Each wire form is written bit by bit, and the writer is
    /// proven on the same value with the ordinary alternative.
    #[test]
    fn an_undefined_choice_extension_is_refused_by_the_decode() {
        // ProtocolIE-SingleContainer: id 9 on 16 aligned bits, criticality
        // ignore and padding, open type length 1, 0x00.
        let single_container = [0x00, 0x09, 0x40, 0x01, 0x00];

        // GlobalRANNodeID of the baseline NG Setup Request.
        let global_ran_node_id = |choice_extension: bool| {
            let mut w = BitWriter::default();
            w.bits(0, 2); // GlobalRANNodeID: globalGNB-ID
            w.bits(0, 2); // GlobalGNB-ID: extension bit, iE-Extensions absent
            w.align();
            w.octets(&[0x99, 0xf9, 0x07]); // PLMNIdentity, SIZE(3)
            if choice_extension {
                w.bits(1, 1); // GNB-ID: choice-Extensions
                w.align();
                w.octets(&single_container);
            } else {
                w.bits(0, 1); // GNB-ID: gNB-ID
                w.bits(32 - 22, 4); // BIT STRING SIZE(22..32): length 32
                w.align();
                w.octets(&1u32.to_be_bytes()); // gNB ID 1
            }
            w.into_bytes()
        };
        let baseline = baseline_request();
        let plain = with_ie_value(
            &baseline,
            ngap_gen::ID_GLOBAL_RAN_NODE_ID,
            global_ran_node_id(false),
        );
        assert_eq!(plain, baseline, "the bit writer agrees with the encoder");
        let extended = with_ie_value(
            &baseline,
            ngap_gen::ID_GLOBAL_RAN_NODE_ID,
            global_ran_node_id(true),
        );
        assert!(
            matches!(
                decode_ng_setup_request_asn1(&extended),
                NgSetupRequestDecode::Undecodable
            ),
            "{:?}",
            decode_ng_setup_request_asn1(&extended)
        );

        // A Setup Response Transfer whose DL UPTransportLayerInformation is
        // a choice extension.
        let transfer = |choice_extension: bool| {
            let mut w = BitWriter::default();
            w.bits(0, 5); // transfer: extension bit, four OPTIONALs absent
            w.bits(0, 2); // QosFlowPerTNLInformation: extension bit, no iE-Extensions
            if choice_extension {
                w.bits(1, 1); // UPTransportLayerInformation: choice-Extensions
                w.align();
                w.octets(&single_container);
            } else {
                w.bits(0, 1); // UPTransportLayerInformation: gTPTunnel
                w.bits(0, 2); // GTPTunnel: extension bit, no iE-Extensions
                w.bits(0, 1); // TransportLayerAddress: SIZE extension bit
                w.bits(31, 8); // ...length 32
                w.align();
                w.octets(&[10, 45, 0, 3]);
                w.octets(&7u32.to_be_bytes());
            }
            w.bits(0, 6); // AssociatedQosFlowList: one item
            w.bits(0, 4); // item: extension bit, two OPTIONALs absent; QFI extension bit
            w.bits(9, 6); // QFI 9
            w.align();
            w.into_bytes()
        };
        assert_eq!(
            parse_n2_sm_setup_response_transfer(&transfer(false)),
            Some(GnbN3Endpoint {
                teid: 7,
                address: vec![10, 45, 0, 3],
                qfis: vec![9],
            })
        );
        assert_eq!(parse_n2_sm_setup_response_transfer(&transfer(true)), None);
    }

    /// An MSB-first bit writer for wire forms no typed value can produce.
    #[derive(Default)]
    struct BitWriter {
        bytes: Vec<u8>,
        used: u32,
    }

    impl BitWriter {
        fn bits(&mut self, value: u64, n: u32) {
            for i in (0..n).rev() {
                if self.used.is_multiple_of(8) {
                    self.bytes.push(0);
                }
                if (value >> i) & 1 == 1 {
                    *self.bytes.last_mut().expect("pushed") |= 0x80 >> (self.used % 8);
                }
                self.used += 1;
            }
        }

        fn align(&mut self) {
            self.used = self.used.div_ceil(8) * 8;
        }

        fn octets(&mut self, octets: &[u8]) {
            assert_eq!(self.used % 8, 0, "octets() needs an aligned writer");
            self.bytes.extend_from_slice(octets);
            self.used += 8 * octets.len() as u32;
        }

        fn into_bytes(self) -> Vec<u8> {
            self.bytes
        }
    }

    // ====================================================================
    // #417 stage 7: Initial Context Setup on the generated codec
    // ====================================================================

    use hand_written_oracle::{
        hand_written_initial_context_setup_request,
        hand_written_parse_initial_context_setup_failure,
        hand_written_parse_initial_context_setup_response,
    };

    /// `InitialContextSetupRequestIEs` object-set order (`ngap-17.9.asn`) of the
    /// IEs the AMF sends: AMF/RAN UE NGAP ID, UE AMBR, GUAMI, Allowed NSSAI, UE
    /// Security Capabilities, Security Key, NAS-PDU.
    const ICS_REQUEST_ORDER: [u16; 8] = [10, 85, 110, 28, 0, 119, 94, 38];

    /// `BitRate`'s upper bound, INTEGER (0..4000000000000, ...) (§9.3.1.4).
    const BIT_RATE_MAX: u64 = 4_000_000_000_000;

    /// The hand-written ICS Request with its two wire deviations corrected --
    /// the IEs put in object-set order and the NAS-PDU marked "ignore" -- done
    /// with the HAND-WRITTEN PDU layer (nextgcore-asn1c), so the expectation owes
    /// nothing to the generated codec. Every IE value stays the hand-written
    /// encoder's own octets.
    fn hand_written_ics_corrected(bytes: &[u8]) -> Vec<u8> {
        use nextgcore_asn1c::ngap::{InitiatingMessageValue, NgapPdu};
        use nextgcore_asn1c::per::{AperDecode, AperDecoder, AperEncode, AperEncoder};
        let mut pdu = NgapPdu::decode_aper(&mut AperDecoder::new(bytes)).expect("decode");
        let NgapPdu::InitiatingMessage(ref mut msg) = pdu else {
            panic!("initiatingMessage");
        };
        let InitiatingMessageValue::InitialContextSetupRequest(ref mut container) = msg.value
        else {
            panic!("Initial Context Setup Request");
        };
        let rank = |id: u16| {
            ICS_REQUEST_ORDER
                .iter()
                .position(|&known| known == id)
                .expect("an IE the AMF sends")
        };
        container.ies.sort_by_key(|field| rank(field.id.0));
        for field in &mut container.ies {
            if field.id.0 == ngap_gen::ID_NAS_PDU {
                field.criticality = nextgcore_asn1c::ngap::Criticality::Ignore;
            }
        }
        let mut encoder = AperEncoder::new();
        pdu.encode_aper(&mut encoder).expect("encode");
        encoder.align();
        encoder.into_bytes().to_vec()
    }

    /// The IE ids and criticalities of an encoded PDU, read by the hand-written
    /// PDU layer.
    fn raw_ies(bytes: &[u8]) -> Vec<(u16, nextgcore_asn1c::ngap::Criticality)> {
        use nextgcore_asn1c::ngap::NgapPdu;
        use nextgcore_asn1c::per::{AperDecode, AperDecoder};
        NgapPdu::decode_aper(&mut AperDecoder::new(bytes))
            .expect("decode")
            .protocol_ies()
            .ies
            .iter()
            .map(|field| (field.id.0, field.criticality))
            .collect()
    }

    /// One Initial Context Setup Request the AMF can be asked to build.
    struct IcsCase {
        ctx: AmfContext,
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        allowed: Vec<crate::context::SNssai>,
        caps: crate::context::UeSecurityCapability,
        key: [u8; 32],
        nas: Option<Vec<u8>>,
        ambr: Option<(u64, u64)>,
    }

    impl IcsCase {
        fn build(
            &self,
            f: fn(
                &AmfContext,
                u64,
                u32,
                &[crate::context::SNssai],
                &crate::context::UeSecurityCapability,
                &[u8; 32],
                Option<&[u8]>,
                Option<(u64, u64)>,
            ) -> Option<Vec<u8>>,
        ) -> Option<Vec<u8>> {
            f(
                &self.ctx,
                self.amf_ue_ngap_id,
                self.ran_ue_ngap_id,
                &self.allowed,
                &self.caps,
                &self.key,
                self.nas.as_deref(),
                self.ambr,
            )
        }

        /// The case without its key, for a failure message: the Security Key
        /// never goes into test output.
        fn describe(&self) -> String {
            format!(
                "amf={} ran={} guami={:?} nssai={:?} caps=({:02x},{:02x},{:02x},{:02x}) nas_len={:?} \
                 ambr={:?}",
                self.amf_ue_ngap_id,
                self.ran_ue_ngap_id,
                self.ctx.served_guami.first().map(|g| (g.amf_id.region, g.amf_id.set, g.amf_id.pointer)),
                self.allowed,
                self.caps.ea,
                self.caps.ia,
                self.caps.eea,
                self.caps.eia,
                self.nas.as_ref().map(Vec::len),
                self.ambr
            )
        }
    }

    fn ics_baseline() -> IcsCase {
        IcsCase {
            ctx: create_test_context(),
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            allowed: vec![crate::context::SNssai {
                sst: 1,
                sd: Some(0x010203),
            }],
            caps: crate::context::UeSecurityCapability {
                ea: 0xF0,
                ia: 0xF0,
                eea: 0xF0,
                eia: 0x70,
            },
            key: core::array::from_fn(|i| i as u8),
            nas: Some(vec![
                0x7E, 0x02, 0x11, 0x22, 0x33, 0x44, 0x01, 0x7E, 0x00, 0x42,
            ]),
            ambr: Some((1_000_000_000, 500_000_000)),
        }
    }

    /// Every field variant the AMF can produce, one dimension at a time from
    /// the baseline, each with and without the NAS-PDU and UE AMBR.
    fn ics_cases() -> Vec<IcsCase> {
        let mut cases = Vec::new();
        let mut push = |mutate: &dyn Fn(&mut IcsCase)| {
            for nas in [true, false] {
                for ambr in [true, false] {
                    let mut case = ics_baseline();
                    mutate(&mut case);
                    if !nas {
                        case.nas = None;
                    }
                    if !ambr {
                        case.ambr = None;
                    }
                    cases.push(case);
                }
            }
        };
        push(&|_| {});
        // Every served-GUAMI bit-width edge, 2- and 3-digit MNCs.
        for guami in rich_context().served_guami {
            push(&|c| {
                c.ctx.served_guami = vec![guami.clone()];
            });
        }
        for &amf in &AMF_IDS {
            for &ran in &RAN_IDS {
                push(&|c| {
                    c.amf_ue_ngap_id = amf;
                    c.ran_ue_ngap_id = ran;
                });
            }
        }
        // Allowed NSSAI of every length SIZE(1..8) allows, and either side of it.
        for len in 0..=9usize {
            push(&|c| {
                c.allowed = (0..len)
                    .map(|i| crate::context::SNssai {
                        sst: i as u8,
                        sd: (i % 2 == 1).then_some(0xFFFFFF - i as u32),
                    })
                    .collect();
            });
        }
        // Every value of each algorithm octet, the others fixed; and the
        // emergency null-only set (#361).
        for octet in 0..=255u8 {
            push(&|c| c.caps.ea = octet);
            push(&|c| c.caps.ia = octet);
            push(&|c| c.caps.eea = octet);
            push(&|c| c.caps.eia = octet);
        }
        push(&|c| {
            c.caps = crate::context::UeSecurityCapability {
                ea: 0x80,
                ia: 0x80,
                eea: 0x80,
                eia: 0x80,
            };
        });
        for key in [[0u8; 32], [0xFF; 32], [0x80; 32], [0x01; 32]] {
            push(&|c| c.key = key);
        }
        // NAS-PDU lengths at every APER length-determinant form.
        for len in [0usize, 1, 127, 128, 255, 256, 16_383, 16_384] {
            push(&|c| c.nas = Some((0..len).map(|i| i as u8).collect()));
        }
        // BitRate ::= INTEGER (0..4000000000000, ...) at its length edges, its
        // bound and past it.
        for (dl, ul) in [
            (0u64, 0u64),
            (1, 255),
            (256, 65_535),
            (65_536, 16_777_215),
            (u32::MAX as u64, 1 << 32),
            (BIT_RATE_MAX, BIT_RATE_MAX),
            (BIT_RATE_MAX + 1, 0),
            (0, BIT_RATE_MAX + 1),
            (i64::MAX as u64 + 1, 0),
            (u64::MAX, u64::MAX),
        ] {
            push(&|c| c.ambr = Some((dl, ul)));
        }
        cases
    }

    /// #417 stage 7: the generated Initial Context Setup Request is the
    /// hand-written one with exactly its two wire deviations corrected -- IEs in
    /// object-set order, NAS-PDU criticality ignore (§9.4.1,
    /// `InitialContextSetupRequestIEs`) -- across every field variant the AMF
    /// can produce, and both refuse the same inputs. Where neither deviation
    /// applies (no NAS-PDU, no UE AMBR) the bytes are identical outright.
    #[test]
    fn initial_context_setup_request_generated_matches_hand_written() {
        let (mut compared, mut refused, mut identical, mut fragmented) = (0, 0, 0, 0);
        for case in ics_cases() {
            let generated = case.build(build_initial_context_setup_request_asn1);
            let oracle = case.build(hand_written_initial_context_setup_request);
            match (generated, oracle) {
                (Some(generated), Some(oracle)) => {
                    assert!(
                        generated == hand_written_ics_corrected(&oracle),
                        "differs beyond IE order and NAS-PDU criticality: {}",
                        case.describe()
                    );
                    if case.nas.is_none() && case.ambr.is_none() {
                        assert!(generated == oracle, "not identical: {}", case.describe());
                        identical += 1;
                    }
                    // A NAS-PDU of ~16 KB fragments the outer initiatingMessage
                    // length (X.691 §11.9.3.8; byte 3 is its first octet). Since
                    // nextgsim #223 the generated encoder fragments it too, so
                    // these are compared byte for byte like every other case.
                    if oracle[3] >= 0xC0 {
                        fragmented += 1;
                    }
                    compared += 1;
                }
                (None, None) => refused += 1,
                (generated, oracle) => panic!(
                    "generated {} but hand-written {}: {}",
                    if generated.is_some() {
                        "encoded"
                    } else {
                        "refused"
                    },
                    if oracle.is_some() {
                        "encoded"
                    } else {
                        "refused"
                    },
                    case.describe()
                ),
            }
        }
        assert!(
            compared > 2000 && identical > 500 && refused > 0 && fragmented > 0,
            "{compared}/{identical}/{refused}/{fragmented}"
        );
    }

    /// The two corrections themselves, on the production shape (NAS-PDU and UE
    /// AMBR both present): the IE order and criticalities are the object set's,
    /// and they are NOT the hand-written encoder's.
    #[test]
    fn initial_context_setup_request_ie_order_and_criticality_are_the_object_sets() {
        use nextgcore_asn1c::ngap::Criticality::{Ignore, Reject};
        let case = ics_baseline();
        let generated = case
            .build(build_initial_context_setup_request_asn1)
            .expect("build");
        assert_eq!(
            raw_ies(&generated),
            vec![
                (10, Reject),
                (85, Reject),
                (110, Reject),
                (28, Reject),
                (0, Reject),
                (119, Reject),
                (94, Reject),
                (38, Ignore),
            ]
        );
        let oracle = case
            .build(hand_written_initial_context_setup_request)
            .expect("build");
        assert_eq!(
            raw_ies(&oracle),
            vec![
                (10, Reject),
                (85, Reject),
                (28, Reject),
                (0, Reject),
                (119, Reject),
                (94, Reject),
                // NAS-PDU criticality is now the object set's (ignore) in the
                // hand-written encoder too; only its IE order still deviates.
                (38, Ignore),
                (110, Reject),
            ],
            "the hand-written encoder's remaining deviation (UE AMBR order), pinned"
        );
    }

    /// Golden bytes for the production shape, so the generated encoder and the
    /// corrected oracle cannot drift together. The key is the synthetic
    /// 0x00..0x1f, not a derived one.
    #[test]
    fn initial_context_setup_request_golden_bytes() {
        let generated = ics_baseline()
            .build(build_initial_context_setup_request_asn1)
            .expect("build");
        let hex: String = generated.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, GOLDEN_ICS_REQUEST);
        // InitiatingMessage (CHOICE 0), procedure 14, criticality reject.
        assert_eq!(&generated[..3], &[0x00, 0x0e, 0x00]);
    }

    const GOLDEN_ICS_REQUEST: &str = "000e0071000008000a00020001005500020002006e000a0c3b9aca00301dcd6500001c00070099f907020040000000050201010203007700091c000e000700038000005e0020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0026400b0a7e0211223344017e0042";

    /// The Security Key IE carries the KgNB as its 256 bits, verbatim, and the
    /// UE Security Capabilities drop the NAS null-algorithm bit (§9.3.1.86).
    #[test]
    fn initial_context_setup_request_carries_the_key_and_capabilities() {
        let case = ics_baseline();
        let bytes = case
            .build(build_initial_context_setup_request_asn1)
            .expect("build");
        let pdu = nextgcore_ngap_gen::decode(&bytes).expect("decode");
        let ngap_gen::NGAP_PDU::InitiatingMessage(ngap_gen::InitiatingMessage {
            value: ngap_gen::InitiatingMessageValue::Id_InitialContextSetup(req),
            ..
        }) = pdu
        else {
            panic!("Initial Context Setup Request");
        };
        use ngap_gen::InitialContextSetupRequestProtocolIEs_EntryValue as Ie;
        let mut seen_key = false;
        for entry in req.protocol_i_es.0 {
            match entry.value {
                Ie::Id_SecurityKey(key) => {
                    assert!(key.0.len() == 256 && key.0.as_raw_slice() == case.key);
                    seen_key = true;
                }
                Ie::Id_UESecurityCapabilities(caps) => {
                    // NAS 0xF0 = xEA0..xEA3 -> NGAP 128-NEA1..3 = 0xE000.
                    assert_eq!(caps.n_rencryption_algorithms.0.as_raw_slice(), [0xE0, 0x00]);
                    assert_eq!(
                        caps.eutr_aintegrity_protection_algorithms.0.as_raw_slice(),
                        [0xE0, 0x00]
                    );
                }
                _ => {}
            }
        }
        assert!(seen_key);
    }

    /// An ICS Response or Failure with one more IE: `id`, `criticality`, a
    /// one-octet value -- spliced with the hand-written PDU layer, so any
    /// length form works.
    pub(crate) fn ics_outcome_with_raw_ie(bytes: &[u8], id: u16, criticality: u8) -> Vec<u8> {
        use nextgcore_asn1c::ngap::{
            Criticality, NgapPdu, ProtocolIeField, ProtocolIeId, SuccessfulOutcomeValue,
            UnsuccessfulOutcomeValue,
        };
        use nextgcore_asn1c::per::{AperDecode, AperDecoder, AperEncode, AperEncoder};
        let mut pdu = NgapPdu::decode_aper(&mut AperDecoder::new(bytes)).expect("decode");
        let container = match pdu {
            NgapPdu::SuccessfulOutcome(ref mut m) => match m.value {
                SuccessfulOutcomeValue::InitialContextSetupResponse(ref mut c) => c,
                _ => panic!("ICS Response"),
            },
            NgapPdu::UnsuccessfulOutcome(ref mut m) => match m.value {
                UnsuccessfulOutcomeValue::InitialContextSetupFailure(ref mut c) => c,
                _ => panic!("ICS Failure"),
            },
            _ => panic!("an outcome"),
        };
        container.ies.push(ProtocolIeField {
            id: ProtocolIeId(id),
            criticality: match criticality {
                0 => Criticality::Reject,
                1 => Criticality::Ignore,
                _ => Criticality::Notify,
            },
            value: vec![0x00],
        });
        let mut encoder = AperEncoder::new();
        pdu.encode_aper(&mut encoder).expect("encode");
        encoder.align();
        encoder.into_bytes().to_vec()
    }

    /// `bytes` with every IE `id` removed, by the hand-written PDU layer.
    pub(crate) fn ics_outcome_without_ie(bytes: &[u8], id: u16) -> Vec<u8> {
        use nextgcore_asn1c::ngap::{NgapPdu, SuccessfulOutcomeValue, UnsuccessfulOutcomeValue};
        use nextgcore_asn1c::per::{AperDecode, AperDecoder, AperEncode, AperEncoder};
        let mut pdu = NgapPdu::decode_aper(&mut AperDecoder::new(bytes)).expect("decode");
        match pdu {
            NgapPdu::SuccessfulOutcome(ref mut m) => {
                if let SuccessfulOutcomeValue::InitialContextSetupResponse(ref mut c) = m.value {
                    c.ies.retain(|f| f.id.0 != id);
                }
            }
            NgapPdu::UnsuccessfulOutcome(ref mut m) => {
                if let UnsuccessfulOutcomeValue::InitialContextSetupFailure(ref mut c) = m.value {
                    c.ies.retain(|f| f.id.0 != id);
                }
            }
            _ => panic!("an outcome"),
        }
        let mut encoder = AperEncoder::new();
        pdu.encode_aper(&mut encoder).expect("encode");
        encoder.align();
        encoder.into_bytes().to_vec()
    }

    pub(crate) fn ics_response_pdu(amf_ue_ngap_id: u64, ran_ue_ngap_id: u32) -> Vec<u8> {
        builder::build_initial_context_setup_response(
            &nextgcore_ngap::types::InitialContextSetupResponse {
                amf_ue_ngap_id,
                ran_ue_ngap_id,
            },
        )
        .expect("build ICS Response")
    }

    pub(crate) fn ics_failure_pdu(
        amf_ue_ngap_id: u64,
        ran_ue_ngap_id: u32,
        cause: Cause,
    ) -> Vec<u8> {
        builder::build_initial_context_setup_failure(
            &nextgcore_ngap::types::InitialContextSetupFailure {
                amf_ue_ngap_id,
                ran_ue_ngap_id,
                cause,
            },
        )
        .expect("build ICS Failure")
    }

    /// #417 stage 7: every ICS Response the hand-written parser accepted decodes
    /// to the same IDs under the generated codec, at every ID length.
    #[test]
    fn initial_context_setup_response_generated_decode_matches_hand_written() {
        let mut compared = 0;
        for &amf in &AMF_IDS[..AMF_IDS.len() - 1] {
            for &ran in &RAN_IDS {
                let pdu = ics_response_pdu(amf, ran);
                let old = hand_written_parse_initial_context_setup_response(&pdu);
                assert_eq!(old, Some((amf, ran)));
                assert_eq!(
                    decode_initial_context_setup_response_asn1(&pdu),
                    InitialContextSetupOutcomeDecode::Decoded {
                        amf_ue_ngap_id: Some(amf),
                        ran_ue_ngap_id: Some(ran),
                        cause: None,
                        error_indication: None,
                        setup_sessions: Vec::new(),
                    }
                );
                compared += 1;
            }
        }
        assert_eq!(compared, 88);
    }

    /// #417 stage 7: every ICS Failure the hand-written parser accepted decodes
    /// to the same IDs, and to the Cause it carries, for every cause group and
    /// value the hand-written encoder can produce.
    #[test]
    fn initial_context_setup_failure_generated_decode_matches_hand_written() {
        let mut compared = 0;
        for group in 0..=4u8 {
            for value in 0..=50i64 {
                let cause = build_cause(group, value);
                for (amf, ran) in [
                    (0, 0),
                    (1, 1),
                    (MAX_AMF_UE_NGAP_ID, u32::MAX),
                    (65_536, 256),
                ] {
                    let pdu = ics_failure_pdu(amf, ran, cause);
                    assert_eq!(
                        hand_written_parse_initial_context_setup_failure(&pdu),
                        Some((amf, ran))
                    );
                    let expected_cause = match parser::decode_ngap_pdu(&pdu) {
                        Ok(NgapMessage::InitialContextSetupFailure(f)) => match f.cause {
                            Cause::RadioNetwork(v) => {
                                (crate::ngap_handler::cause_group::RADIO_NETWORK, v as i64)
                            }
                            Cause::Transport(v) => {
                                (crate::ngap_handler::cause_group::TRANSPORT, v as i64)
                            }
                            Cause::Nas(v) => (crate::ngap_handler::cause_group::NAS, v as i64),
                            Cause::Protocol(v) => {
                                (crate::ngap_handler::cause_group::PROTOCOL, v as i64)
                            }
                            Cause::Misc(v) => (crate::ngap_handler::cause_group::MISC, v as i64),
                        },
                        other => panic!("hand-written parse: {other:?}"),
                    };
                    assert_eq!(
                        decode_initial_context_setup_failure_asn1(&pdu),
                        InitialContextSetupOutcomeDecode::Decoded {
                            amf_ue_ngap_id: Some(amf),
                            ran_ue_ngap_id: Some(ran),
                            cause: Some(expected_cause),
                            error_indication: None,
                            setup_sessions: Vec::new(),
                        },
                        "group {group} value {value}"
                    );
                    compared += 1;
                }
            }
        }
        assert_eq!(compared, 5 * 51 * 4);
    }

    /// TS 38.413 §10.3.4.2 for the two RESPONSE messages: a not-comprehended IE
    /// marked ignore is dropped; notify is reported in an Error Indication
    /// naming procedure 14 and the triggering message; reject terminates the
    /// procedure, handled locally.
    #[test]
    fn initial_context_setup_outcomes_apply_criticality_to_unknown_ies() {
        let diag = |criticality| IeDiagnostic {
            ie_id: 9999,
            criticality,
            type_of_error: ngap_gen::TypeOfError::NOT_UNDERSTOOD,
        };
        let cases: [(
            Vec<u8>,
            fn(&[u8]) -> InitialContextSetupOutcomeDecode,
            u8,
            Option<(u8, i64)>,
        ); 2] = [
            (
                ics_response_pdu(7, 9),
                decode_initial_context_setup_response_asn1,
                ngap_gen::TriggeringMessage::SUCCESSFUL_OUTCOME,
                None,
            ),
            (
                ics_failure_pdu(7, 9, Cause::RadioNetwork(CauseRadioNetwork::Unspecified)),
                decode_initial_context_setup_failure_asn1,
                ngap_gen::TriggeringMessage::UNSUCCESSFUL_OUTCOME,
                Some((crate::ngap_handler::cause_group::RADIO_NETWORK, 0)),
            ),
        ];
        for (pdu, decode, triggering_message, cause) in cases {
            // The hand-written parsers, for the record: they refused the reject
            // case (which comes to the same local handling) and accepted the
            // other two, reporting nothing.
            let old = |criticality| {
                let spliced = ics_outcome_with_raw_ie(&pdu, 9999, criticality);
                hand_written_parse_initial_context_setup_response(&spliced)
                    .or(hand_written_parse_initial_context_setup_failure(&spliced))
            };
            assert_eq!(old(ngap_gen::Criticality::REJECT), None);
            assert_eq!(old(ngap_gen::Criticality::IGNORE), Some((7, 9)));
            assert_eq!(old(ngap_gen::Criticality::NOTIFY), Some((7, 9)));
            let decoded = |criticality| decode(&ics_outcome_with_raw_ie(&pdu, 9999, criticality));
            assert_eq!(
                decoded(ngap_gen::Criticality::IGNORE),
                InitialContextSetupOutcomeDecode::Decoded {
                    amf_ue_ngap_id: Some(7),
                    ran_ue_ngap_id: Some(9),
                    cause,
                    error_indication: None,
                    setup_sessions: Vec::new(),
                }
            );
            assert_eq!(
                decoded(ngap_gen::Criticality::NOTIFY),
                InitialContextSetupOutcomeDecode::Decoded {
                    amf_ue_ngap_id: Some(7),
                    ran_ue_ngap_id: Some(9),
                    cause,
                    error_indication: Some(CriticalityErrorIndication {
                        amf_ue_ngap_id: Some(7),
                        ran_ue_ngap_id: Some(9),
                        cause_protocol:
                            ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
                        procedure: ReportedProcedure {
                            procedure_code: ngap_gen::ID_INITIAL_CONTEXT_SETUP,
                            triggering_message,
                            procedure_criticality: ngap_gen::Criticality::REJECT,
                        },
                        diagnostics: vec![diag(ngap_gen::Criticality::NOTIFY)],
                    }),
                    setup_sessions: Vec::new(),
                }
            );
            assert_eq!(
                decoded(ngap_gen::Criticality::REJECT),
                InitialContextSetupOutcomeDecode::Failed(vec![diag(ngap_gen::Criticality::REJECT)])
            );
        }
    }

    /// Both IDs are criticality ignore (§10.3.5): a Response or Failure missing
    /// one still decodes, with that ID `None`, where the hand-written parser
    /// refused the message.
    #[test]
    fn initial_context_setup_outcomes_missing_ids_still_decode() {
        let response = ics_response_pdu(7, 9);
        let failure = ics_failure_pdu(7, 9, Cause::Nas(CauseNas::NormalRelease));
        for (id, amf, ran) in [
            (ngap_gen::ID_RAN_UE_NGAP_ID, Some(7), None),
            (ngap_gen::ID_AMF_UE_NGAP_ID, None, Some(9)),
        ] {
            let r = ics_outcome_without_ie(&response, id);
            assert_eq!(hand_written_parse_initial_context_setup_response(&r), None);
            assert!(matches!(
                decode_initial_context_setup_response_asn1(&r),
                InitialContextSetupOutcomeDecode::Decoded { amf_ue_ngap_id, ran_ue_ngap_id, .. }
                    if amf_ue_ngap_id == amf && ran_ue_ngap_id == ran
            ));
            let f = ics_outcome_without_ie(&failure, id);
            assert_eq!(hand_written_parse_initial_context_setup_failure(&f), None);
            assert!(matches!(
                decode_initial_context_setup_failure_asn1(&f),
                InitialContextSetupOutcomeDecode::Decoded { amf_ue_ngap_id, ran_ue_ngap_id, .. }
                    if amf_ue_ngap_id == amf && ran_ue_ngap_id == ran
            ));
        }
        // Not the expected message at all.
        assert_eq!(
            decode_initial_context_setup_response_asn1(&failure),
            InitialContextSetupOutcomeDecode::Undecodable
        );
        assert_eq!(
            decode_initial_context_setup_failure_asn1(&response),
            InitialContextSetupOutcomeDecode::Undecodable
        );
        assert_eq!(
            decode_initial_context_setup_response_asn1(&[0x20, 0x0e]),
            InitialContextSetupOutcomeDecode::Undecodable
        );
    }

    /// A UE AMBR past what §9.3.1.4 defines is clamped in the EPS→5GS
    /// HandoverRequest (the sum of EPS APN-AMBRs can pass it), never emitted as
    /// a BitRate extension value: the bytes equal those for exactly the bound.
    #[test]
    fn the_eps_to_5gs_handover_request_clamps_the_ue_ambr_to_the_bit_rate_bound() {
        let ctx = create_test_context();
        let request = |ambr| EpsToFivegsHandoverRequest {
            amf_ue_ngap_id: 7,
            ue_ambr_bps: ambr,
            ue_security_capability: crate::context::UeSecurityCapability {
                ea: 0xE0,
                ia: 0x60,
                eea: 0xF0,
                eia: 0x70,
            },
            next_hop: [0; 32],
            nas_container: vec![0; 8],
            sessions: vec![HandoverRequestSession {
                pdu_session_id: 5,
                s_nssai: SNssai { sst: 1, sd: None },
                transfer: vec![0x00, 0x00, 0x04, 0x00, 0x82, 0x00, 0x0A],
            }],
            allowed_nssai: vec![SNssai { sst: 1, sd: None }],
            source_to_target_container: vec![0x40],
        };
        let at_bound =
            build_eps_to_5gs_handover_request_asn1(&ctx, &request((MAX_BIT_RATE, MAX_BIT_RATE)))
                .expect("encodes at the bound");
        let past =
            build_eps_to_5gs_handover_request_asn1(&ctx, &request((MAX_BIT_RATE + 1, u64::MAX)))
                .expect("clamped, so it still encodes");
        assert_eq!(past, at_bound);
    }

    /// The Initial Context Setup Request refuses a UE AMBR past the bound
    /// rather than letting the codec extend it.
    #[test]
    fn initial_context_setup_request_refuses_a_ue_ambr_past_the_bit_rate_bound() {
        let mut case = ics_baseline();
        case.ambr = Some((MAX_BIT_RATE, MAX_BIT_RATE));
        assert!(case
            .build(build_initial_context_setup_request_asn1)
            .is_some());
        case.ambr = Some((MAX_BIT_RATE + 1, 0));
        assert!(case
            .build(build_initial_context_setup_request_asn1)
            .is_none());
        case.ambr = Some((0, MAX_BIT_RATE + 1));
        assert!(case
            .build(build_initial_context_setup_request_asn1)
            .is_none());
    }

    /// #418: the EPS→5GS HandoverRequest, against TS 38.413 §9.2.3.4 and TS 33.501 §8.4.2
    /// step 4, decoded by an INDEPENDENT codec — `nextgcore-ngap`'s hand-written parser —
    /// for every IE it models, and by the generated decoder for the two it has no member
    /// for (NSCI and NASC). An encoder checked only against its own decoder proves nothing
    /// about the wire (the S1AP lesson of #455).
    #[test]
    fn the_eps_to_5gs_handover_request_carries_ts33501_8_4_2_step_4() {
        let ctx = create_test_context();
        let request = EpsToFivegsHandoverRequest {
            amf_ue_ngap_id: 0x418,
            ue_ambr_bps: (100_000_000, 50_000_000),
            ue_security_capability: crate::context::UeSecurityCapability {
                ea: 0xE0,
                ia: 0x60,
                eea: 0xF0,
                eia: 0x70,
            },
            next_hop: [0x7A; 32],
            nas_container: vec![0x01, 0x02, 0x03, 0x04, 0x22, 0x2B, 0x00, 0x00],
            sessions: vec![HandoverRequestSession {
                pdu_session_id: 5,
                s_nssai: SNssai {
                    sst: 1,
                    sd: Some(1),
                },
                transfer: vec![0x00, 0x00, 0x04, 0x00, 0x82, 0x00, 0x0A],
            }],
            allowed_nssai: vec![SNssai {
                sst: 1,
                sd: Some(1),
            }],
            source_to_target_container: vec![0x40, 0x41, 0x42],
        };
        let bytes = build_eps_to_5gs_handover_request_asn1(&ctx, &request).expect("encodes");
        // NGAP-PDU CHOICE initiatingMessage (index 0, extension bit 0), procedure code 13
        // (id-HandoverResourceAllocation), criticality reject (0).
        assert_eq!(&bytes[..3], &[0x00, 0x0D, 0x00]);

        // The independent half: `nextgcore-ngap`'s hand-written ENCODER, fed the same
        // fields, must produce exactly these bytes once the two IEs it has no member for
        // (NSCI, id 41; NASC, id 37) are taken out of the generated PDU. The hand-written
        // parser cannot be the oracle here: it correctly refuses NSCI, a not-comprehended
        // IE marked reject (TS 38.413 §10.3.4).
        let hand_written = builder::build_handover_request(&HandoverRequest {
            amf_ue_ngap_id: 0x418,
            handover_type: HandoverType::EpsTo5gs,
            cause: Cause::RadioNetwork(CauseRadioNetwork::HandoverDesirableForRadioReason),
            ue_ambr: UeAmbrInfo {
                dl: 100_000_000,
                ul: 50_000_000,
            },
            ue_security_capabilities: UeSecurityCapabilities {
                nr_encryption_algorithms: nas_caps_octet_to_ngap_bits(0xE0),
                nr_integrity_algorithms: nas_caps_octet_to_ngap_bits(0x60),
                eutra_encryption_algorithms: nas_caps_octet_to_ngap_bits(0xF0),
                eutra_integrity_algorithms: nas_caps_octet_to_ngap_bits(0x70),
            },
            security_context: SecurityContext {
                next_hop_chaining_count: 0,
                next_hop: [0x7A; 32],
            },
            pdu_session_list: vec![PduSessionResourceSetupItemHoReq {
                pdu_session_id: 5,
                s_nssai: nextgcore_ngap::types::SNssai {
                    sst: 1,
                    sd: Some([0, 0, 1]),
                },
                transfer: vec![0x00, 0x00, 0x04, 0x00, 0x82, 0x00, 0x0A],
            }],
            allowed_nssai: vec![nextgcore_ngap::types::SNssai {
                sst: 1,
                sd: Some([0, 0, 1]),
            }],
            source_to_target_container: vec![0x40, 0x41, 0x42],
            guami: nextgcore_ngap::types::Guami {
                plmn_identity: encode_plmn_id(&PlmnId::new("999", "70")),
                amf_region_id: 2,
                amf_set_id: 1,
                amf_pointer: 0,
            },
        })
        .expect("hand-written encode");
        let mut stripped = nextgcore_ngap_gen::decode(&bytes).expect("generated decode");
        if let ngap_gen::NGAP_PDU::InitiatingMessage(ref mut init) = stripped {
            if let ngap_gen::InitiatingMessageValue::Id_HandoverResourceAllocation(ref mut req) =
                init.value
            {
                req.protocol_i_es.0.retain(|ie| {
                    ie.id.0 != ngap_gen::ID_NEW_SECURITY_CONTEXT_IND && ie.id.0 != ngap_gen::ID_NASC
                });
            }
        }
        assert_eq!(
            nextgcore_ngap_gen::encode(&stripped).expect("re-encode"),
            hand_written,
            "every IE both encoders model -- type, cause, UE-AMBR, capabilities, NCC 0 and the \
             NH, the session and its transfer, NSSAI, container, GUAMI -- is byte-identical to \
             the independent hand-written encoder"
        );
        // The hand-written parser reads the stripped form, naming the values §8.4.2 step 4
        // fixes.
        let hr = match parser::decode_ngap_pdu(&hand_written) {
            Ok(NgapMessage::HandoverRequest(hr)) => hr,
            other => panic!("hand-written parse: {other:?}"),
        };
        assert_eq!(hr.handover_type as u8, 2, "eps-to-5gs (§9.3.1.22)");
        assert_eq!(
            hr.security_context.next_hop_chaining_count, 0,
            "§8.4.2 step 4: NCC = 0"
        );

        // The two IEs the hand-written types lack, through the generated decoder.
        let pdu = nextgcore_ngap_gen::decode(&bytes).expect("generated decode");
        let ngap_gen::NGAP_PDU::InitiatingMessage(init) = pdu else {
            panic!("initiating message expected");
        };
        let ngap_gen::InitiatingMessageValue::Id_HandoverResourceAllocation(req) = init.value
        else {
            panic!("HandoverRequest expected");
        };
        let mut nsci = false;
        let mut nasc = None;
        for ie in req.protocol_i_es.0 {
            match ie.value {
                ngap_gen::HandoverRequestProtocolIEs_EntryValue::Id_NewSecurityContextInd(v) => {
                    nsci = v.0 == ngap_gen::NewSecurityContextInd::TRUE;
                    assert_eq!(ie.criticality.0, ngap_gen::Criticality::REJECT);
                }
                ngap_gen::HandoverRequestProtocolIEs_EntryValue::Id_NASC(v) => {
                    assert_eq!(ie.criticality.0, ngap_gen::Criticality::REJECT);
                    nasc = Some(v.0);
                }
                _ => {}
            }
        }
        assert!(
            nsci,
            "§8.4.2 step 4: the New Security Context Indicator is sent"
        );
        assert_eq!(
            nasc,
            Some(vec![0x01, 0x02, 0x03, 0x04, 0x22, 0x2B, 0x00, 0x00]),
            "§8.4.2 step 4: the NAS Container goes to the gNB as NASC"
        );
    }

    // ------------------------------------------------------------------
    // #417: the NAS transport family on the generated codec.
    // ------------------------------------------------------------------

    use nextgcore_ngap::types::{
        InitialUeMessage as HwInitialUe, RrcEstablishmentCause as HwCause, SNssai as HwSNssai,
        UplinkNasTransport as HwUplinkNas, UserLocationInformation as HwUli,
    };

    fn nas_uli(plmn: [u8; 3], nci: u64, tac: u32) -> HwUli {
        HwUli::Nr {
            nr_cgi_plmn: plmn,
            nr_cell_identity: nci,
            tai_plmn: plmn,
            tai_tac: [(tac >> 16) as u8, (tac >> 8) as u8, tac as u8],
        }
    }

    fn rrc_cause(v: u8) -> HwCause {
        use HwCause::*;
        [
            Emergency,
            HighPriorityAccess,
            MtAccess,
            MoSignalling,
            MoData,
            MoVoiceCall,
            MoVideoCall,
            MoSms,
            MpsPriorityAccess,
            McsPriorityAccess,
            NotAvailable,
        ][usize::from(v)]
    }

    /// Initial UE Messages the hand-written encoder builds, varied one field at
    /// a time around a baseline: every RAN UE NGAP ID length, NAS-PDU length
    /// forms, both MNC lengths, NR cell identity and TAC edges, every RRC
    /// Establishment Cause, UE Context Request on and off, Allowed NSSAI of 0, 1
    /// and 3 slices with and without an SD.
    pub(crate) fn initial_ue_corpus() -> Vec<Vec<u8>> {
        let base = HwInitialUe {
            ran_ue_ngap_id: 77,
            nas_pdu: vec![0x7e, 0x00, 0x41, 0x09, 0x00],
            user_location_info: nas_uli([0x00, 0xf1, 0x10], 0x0006_6666, 0x00040f),
            rrc_establishment_cause: HwCause::MoSignalling,
            ue_context_request: None,
            allowed_nssai: Vec::new(),
        };
        // The baseline first: the criticality tests edit `corpus[0]`.
        let mut variants = vec![base.clone()];
        for ran in [0u32, 1, 255, 256, 65_535, 65_536, 16_777_216, u32::MAX] {
            variants.push(HwInitialUe {
                ran_ue_ngap_id: ran,
                ..base.clone()
            });
        }
        for len in [1usize, 2, 127, 128, 255, 256, 1_000, 16_383] {
            variants.push(HwInitialUe {
                nas_pdu: vec![0x7e; len],
                ..base.clone()
            });
        }
        for plmn in [
            [0x00, 0xf1, 0x10],
            [0x13, 0x00, 0x14],
            [0x99, 0xf9, 0x07],
            [0xff, 0xff, 0xff],
        ] {
            variants.push(HwInitialUe {
                user_location_info: nas_uli(plmn, 1, 1),
                ..base.clone()
            });
        }
        for (nci, tac) in [
            (0u64, 0u32),
            (1, 1),
            ((1 << 36) - 1, 0xff_ffff),
            (0x8_0000_0001, 0x80_0001),
        ] {
            variants.push(HwInitialUe {
                user_location_info: nas_uli([0x00, 0xf1, 0x10], nci, tac),
                ..base.clone()
            });
        }
        for v in 0..=10 {
            variants.push(HwInitialUe {
                rrc_establishment_cause: rrc_cause(v),
                ..base.clone()
            });
        }
        variants.push(HwInitialUe {
            ue_context_request: Some(true),
            ..base.clone()
        });
        let slice = |sst: u8, sd: Option<[u8; 3]>| HwSNssai { sst, sd };
        for nssai in [
            vec![slice(1, None)],
            vec![
                slice(1, Some([0, 0, 1])),
                slice(2, None),
                slice(255, Some([0xff; 3])),
            ],
        ] {
            variants.push(HwInitialUe {
                allowed_nssai: nssai,
                ..base.clone()
            });
        }
        variants
            .iter()
            .map(|m| nextgcore_ngap::builder::build_initial_ue_message(m).expect("build"))
            .collect()
    }

    /// The generated decode flattened to what the hand-written parser could
    /// say. A `Reject` or a report never comes out of a message the old parser
    /// accepted, so either is a test failure here.
    fn generated_initial_ue_view(data: &[u8]) -> Option<String> {
        match decode_initial_ue_message_asn1(data) {
            NasTransportDecode::Proceed {
                message,
                error_indication: None,
            } => Some(format!("{message:?}")),
            NasTransportDecode::Undecodable => None,
            other => panic!("unexpected {other:?} for {data:02x?}"),
        }
    }

    #[test]
    fn initial_ue_message_generated_decode_matches_hand_written() {
        let corpus = initial_ue_corpus();
        assert_eq!(corpus.len(), 1 + 8 + 8 + 4 + 4 + 11 + 1 + 2);
        for data in &corpus {
            let old = parse_initial_ue_message_asn1(data).map(|m| format!("{m:?}"));
            assert!(
                old.is_some(),
                "the corpus holds accepted messages: {data:02x?}"
            );
            assert_eq!(generated_initial_ue_view(data), old, "{data:02x?}");
        }
        // Every truncation of a valid message, and junk, is refused by both.
        let base = &corpus[0];
        for cut in 0..base.len() {
            let data = &base[..cut];
            assert!(parse_initial_ue_message_asn1(data).is_none(), "{data:02x?}");
            assert_eq!(generated_initial_ue_view(data), None, "{data:02x?}");
        }
    }

    /// Uplink NAS Transports the hand-written encoder builds: AMF and RAN UE
    /// NGAP ID lengths, NAS-PDU length forms, and location edges.
    fn uplink_nas_corpus() -> Vec<Vec<u8>> {
        let base = HwUplinkNas {
            amf_ue_ngap_id: 9,
            ran_ue_ngap_id: 77,
            nas_pdu: vec![0x7e, 0x02, 0x11, 0x22, 0x33, 0x44, 0x01, 0x7e, 0x00, 0x67],
            user_location_info: nas_uli([0x00, 0xf1, 0x10], 0x0006_6666, 0x00040f),
        };
        let mut variants = vec![base.clone()];
        for amf in [0u64, 1, 255, 256, 65_536, (1 << 32) + 7, (1 << 40) - 1] {
            variants.push(HwUplinkNas {
                amf_ue_ngap_id: amf,
                ..base.clone()
            });
        }
        for ran in [0u32, 256, 65_536, u32::MAX] {
            variants.push(HwUplinkNas {
                ran_ue_ngap_id: ran,
                ..base.clone()
            });
        }
        for len in [1usize, 127, 128, 16_383] {
            variants.push(HwUplinkNas {
                nas_pdu: vec![0x7e; len],
                ..base.clone()
            });
        }
        for (nci, tac) in [(0u64, 0u32), ((1 << 36) - 1, 0xff_ffff)] {
            variants.push(HwUplinkNas {
                user_location_info: nas_uli([0x13, 0x00, 0x14], nci, tac),
                ..base.clone()
            });
        }
        variants
            .iter()
            .map(|m| nextgcore_ngap::builder::build_uplink_nas_transport(m).expect("build"))
            .collect()
    }

    fn generated_uplink_nas_view(data: &[u8]) -> Option<String> {
        match decode_uplink_nas_transport_asn1(data) {
            NasTransportDecode::Proceed {
                message,
                error_indication: None,
            } => Some(format!("{message:?}")),
            NasTransportDecode::Undecodable => None,
            other => panic!("unexpected {other:?} for {data:02x?}"),
        }
    }

    #[test]
    fn uplink_nas_transport_generated_decode_matches_hand_written() {
        let corpus = uplink_nas_corpus();
        assert_eq!(corpus.len(), 1 + 7 + 4 + 4 + 2);
        for data in &corpus {
            let old = parse_uplink_nas_transport_asn1(data).map(|m| format!("{m:?}"));
            assert!(
                old.is_some(),
                "the corpus holds accepted messages: {data:02x?}"
            );
            assert_eq!(generated_uplink_nas_view(data), old, "{data:02x?}");
        }
        let base = &corpus[0];
        for cut in 0..base.len() {
            let data = &base[..cut];
            assert!(
                parse_uplink_nas_transport_asn1(data).is_none(),
                "{data:02x?}"
            );
            assert_eq!(generated_uplink_nas_view(data), None, "{data:02x?}");
        }
    }

    /// The generated Downlink NAS Transport is the hand-written one byte for
    /// byte: every AMF and RAN UE NGAP ID length, and NAS-PDU lengths across
    /// every length-determinant form, past 16K into fragmentation (X.691
    /// §11.9.3.8). Both refuse an AMF UE NGAP ID past 2^40-1.
    #[test]
    fn downlink_nas_transport_generated_matches_hand_written() {
        let hand_written = |amf: u64, ran: u32, nas: &[u8]| {
            nextgcore_ngap::builder::build_downlink_nas_transport(&DownlinkNasTransport {
                amf_ue_ngap_id: amf,
                ran_ue_ngap_id: ran,
                nas_pdu: nas.to_vec(),
            })
            .ok()
        };
        let mut compared = 0;
        let nas = [0x7e, 0x00, 0x42];
        for amf in [
            0u64,
            1,
            255,
            256,
            65_535,
            65_536,
            (1 << 24),
            (1 << 32),
            (1 << 40) - 1,
            1 << 40,
        ] {
            for ran in [0u32, 1, 255, 256, 65_536, u32::MAX] {
                assert_eq!(
                    build_downlink_nas_transport_asn1(amf, ran, &nas),
                    hand_written(amf, ran, &nas),
                    "amf={amf} ran={ran}"
                );
                compared += 1;
            }
        }
        for len in [
            0usize, 1, 127, 128, 255, 256, 16_383, 16_384, 16_385, 32_768, 49_152, 65_536, 70_000,
        ] {
            let nas = vec![0xa5; len];
            let new = build_downlink_nas_transport_asn1(7, 9, &nas);
            assert!(new.is_some(), "len={len}");
            assert_eq!(new, hand_written(7, 9, &nas), "len={len}");
            compared += 1;
        }
        assert_eq!(compared, 10 * 6 + 13);
        assert_eq!(build_downlink_nas_transport_asn1(1 << 40, 1, &[0x7e]), None);
    }

    /// Pinned from X.691 by hand: initiatingMessage (00), procedure code 4,
    /// criticality ignore (40), value length 22; the SEQUENCE extension bit and
    /// IE count 3; AMF-UE-NGAP-ID 10 (reject) = 1 in a 3-bit length plus one
    /// octet; RAN-UE-NGAP-ID 85 (reject) = 2 in a 2-bit length plus one octet;
    /// NAS-PDU 38 (reject) = length 2, 7e 00.
    #[test]
    fn downlink_nas_transport_golden_bytes() {
        assert_eq!(
            build_downlink_nas_transport_asn1(1, 2, &[0x7e, 0x00]).expect("encode"),
            [
                0x00, 0x04, 0x40, 0x16, 0x00, 0x00, 0x03, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, 0x00,
                0x55, 0x00, 0x02, 0x00, 0x02, 0x00, 0x26, 0x00, 0x03, 0x02, 0x7e, 0x00,
            ]
        );
    }

    /// The baseline Initial UE Message re-encoded with `edit` applied to its
    /// generated IE list.
    pub(crate) fn initial_ue_edited(
        edit: impl FnOnce(&mut Vec<ngap_gen::InitialUEMessageProtocolIEs_Entry>),
    ) -> Vec<u8> {
        let mut pdu = nextgcore_ngap_gen::decode(&initial_ue_corpus()[0]).expect("decode");
        let ngap_gen::NGAP_PDU::InitiatingMessage(ref mut msg) = pdu else {
            panic!("initiatingMessage");
        };
        let ngap_gen::InitiatingMessageValue::Id_InitialUEMessage(ref mut m) = msg.value else {
            panic!("InitialUEMessage");
        };
        edit(&mut m.protocol_i_es.0);
        nextgcore_ngap_gen::encode(&pdu).expect("encode")
    }

    /// The hand-written parser refused an Initial UE Message carrying a
    /// 5G-S-TMSI -- the IE a gNB includes for a UE resuming from CM-IDLE with
    /// its 5G-S-TMSI (TS 38.413 §9.2.5.1) -- because it did not comprehend the
    /// IE and its criticality is reject. The generated decode comprehends it.
    #[test]
    fn an_initial_ue_message_with_a_5g_s_tmsi_is_decoded() {
        use bitvec::prelude::*;
        let data = initial_ue_edited(|ies| {
            ies.push(ngap_gen::InitialUEMessageProtocolIEs_Entry {
                id: ngap_gen::ProtocolIE_ID(ngap_gen::ID_FIVE_G_S_TMSI),
                criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
                value: ngap_gen::InitialUEMessageProtocolIEs_EntryValue::Id_FiveG_S_TMSI(
                    ngap_gen::FiveG_S_TMSI {
                        amf_set_id: ngap_gen::AMFSetID(bitvec![u8, Msb0; 0; 10]),
                        amf_pointer: ngap_gen::AMFPointer(bitvec![u8, Msb0; 0; 6]),
                        five_g_tmsi: ngap_gen::FiveG_TMSI(vec![0x12, 0x34, 0x56, 0x78]),
                        ie_extensions: None,
                    },
                ),
            })
        });
        assert!(
            parse_initial_ue_message_asn1(&data).is_none(),
            "the oracle refuses it: that is the defect"
        );
        let NasTransportDecode::Proceed {
            message,
            error_indication: None,
        } = decode_initial_ue_message_asn1(&data)
        else {
            panic!("a 5G-S-TMSI must not stop the Initial UE Message");
        };
        assert_eq!(message.ran_ue_ngap_id, 77);
        assert_eq!(message.nas_pdu, [0x7e, 0x00, 0x41, 0x09, 0x00]);
    }

    /// §10.3.4.2 and §10.3.5 for the Initial UE Message, a procedure with no
    /// response message: "ignore" is dropped; "notify" proceeds and reports
    /// procedure 15 in an Error Indication; "reject", or a missing NAS-PDU or
    /// User Location Information (both criticality reject), terminates it with
    /// one; a missing RRC Establishment Cause (criticality ignore) is ignored.
    #[test]
    fn initial_ue_message_criticality_handling() {
        let base = &initial_ue_corpus()[0];
        let report = |cause_protocol, diagnostics| CriticalityErrorIndication {
            amf_ue_ngap_id: None,
            ran_ue_ngap_id: Some(77),
            cause_protocol,
            procedure: ReportedProcedure {
                procedure_code: 15,
                triggering_message: ngap_gen::TriggeringMessage::INITIATING_MESSAGE,
                procedure_criticality: ngap_gen::Criticality::IGNORE,
            },
            diagnostics,
        };
        let not_understood = |criticality| {
            vec![IeDiagnostic {
                ie_id: 9999,
                criticality,
                type_of_error: ngap_gen::TypeOfError::NOT_UNDERSTOOD,
            }]
        };

        assert!(matches!(
            decode_initial_ue_message_asn1(&with_unknown_ie(base, 9999, 0x40)),
            NasTransportDecode::Proceed {
                error_indication: None,
                ..
            }
        ));
        let NasTransportDecode::Proceed {
            message,
            error_indication: Some(r),
        } = decode_initial_ue_message_asn1(&with_unknown_ie(base, 9999, 0x80))
        else {
            panic!("notify proceeds with a report");
        };
        assert_eq!(message.ran_ue_ngap_id, 77);
        assert_eq!(
            r,
            report(
                ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
                not_understood(ngap_gen::Criticality::NOTIFY)
            )
        );
        let NasTransportDecode::Reject(r) =
            decode_initial_ue_message_asn1(&with_unknown_ie(base, 9999, 0x00))
        else {
            panic!("reject terminates the procedure");
        };
        assert_eq!(
            r,
            report(
                ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT,
                not_understood(ngap_gen::Criticality::REJECT)
            )
        );

        for missing in [ngap_gen::ID_NAS_PDU, ngap_gen::ID_USER_LOCATION_INFORMATION] {
            let data = initial_ue_edited(|ies| ies.retain(|e| e.id.0 != missing));
            let NasTransportDecode::Reject(r) = decode_initial_ue_message_asn1(&data) else {
                panic!("missing IE {missing} is rejected");
            };
            assert_eq!(
                r.diagnostics,
                [IeDiagnostic {
                    ie_id: missing,
                    criticality: ngap_gen::Criticality::REJECT,
                    type_of_error: ngap_gen::TypeOfError::MISSING,
                }]
            );
        }
        let data =
            initial_ue_edited(|ies| ies.retain(|e| e.id.0 != ngap_gen::ID_RRC_ESTABLISHMENT_CAUSE));
        let NasTransportDecode::Proceed {
            message,
            error_indication: None,
        } = decode_initial_ue_message_asn1(&data)
        else {
            panic!("a missing RRC Establishment Cause is ignored");
        };
        assert_eq!(
            message.rrc_establishment_cause,
            ngap_gen::RRCEstablishmentCause::MO_SIGNALLING
        );
    }

    /// RRC Establishment Cause is carried as its wire value, extension values
    /// included: mo-ExceptionData (11, Rel-15) is not folded into notAvailable
    /// as the hand-written parser folded it.
    #[test]
    fn an_extension_rrc_establishment_cause_is_kept() {
        let data = initial_ue_edited(|ies| {
            for e in ies.iter_mut() {
                if let ngap_gen::InitialUEMessageProtocolIEs_EntryValue::Id_RRCEstablishmentCause(
                    c,
                ) = &mut e.value
                {
                    c.0 = ngap_gen::RRCEstablishmentCause::MO_EXCEPTION_DATA;
                }
            }
        });
        let NasTransportDecode::Proceed { message, .. } = decode_initial_ue_message_asn1(&data)
        else {
            panic!("decodes");
        };
        assert_eq!(message.rrc_establishment_cause, 11);
        assert_eq!(
            parse_initial_ue_message_asn1(&data).map(|m| m.rrc_establishment_cause),
            Some(10),
            "the oracle folded it into notAvailable"
        );
    }

    /// §10.3.4.2 and §10.3.5 for the Uplink NAS Transport. Its User Location
    /// Information is mandatory with criticality IGNORE, so a message without
    /// one delivers its NAS -- the hand-written parser refused it.
    #[test]
    fn uplink_nas_transport_criticality_handling() {
        let base = &uplink_nas_corpus()[0];
        let edited = |edit: &dyn Fn(&mut Vec<ngap_gen::UplinkNASTransportProtocolIEs_Entry>)| {
            let mut pdu = nextgcore_ngap_gen::decode(base).expect("decode");
            let ngap_gen::NGAP_PDU::InitiatingMessage(ref mut msg) = pdu else {
                panic!("initiatingMessage");
            };
            let ngap_gen::InitiatingMessageValue::Id_UplinkNASTransport(ref mut m) = msg.value
            else {
                panic!("UplinkNASTransport");
            };
            edit(&mut m.protocol_i_es.0);
            nextgcore_ngap_gen::encode(&pdu).expect("encode")
        };

        let no_uli =
            edited(&|ies| ies.retain(|e| e.id.0 != ngap_gen::ID_USER_LOCATION_INFORMATION));
        assert!(
            parse_uplink_nas_transport_asn1(&no_uli).is_none(),
            "the oracle refuses it"
        );
        let NasTransportDecode::Proceed {
            message,
            error_indication: None,
        } = decode_uplink_nas_transport_asn1(&no_uli)
        else {
            panic!("a missing User Location Information is ignored");
        };
        assert!(message.user_location_info.is_none());
        assert_eq!(message.nas_pdu.len(), 10);

        let NasTransportDecode::Reject(r) = decode_uplink_nas_transport_asn1(&edited(&|ies| {
            ies.retain(|e| e.id.0 != ngap_gen::ID_NAS_PDU)
        })) else {
            panic!("a missing NAS-PDU is rejected");
        };
        assert_eq!((r.amf_ue_ngap_id, r.ran_ue_ngap_id), (Some(9), Some(77)));
        assert_eq!(r.procedure.procedure_code, 46);
        assert_eq!(r.diagnostics[0].ie_id, ngap_gen::ID_NAS_PDU);

        let NasTransportDecode::Proceed {
            error_indication: Some(r),
            ..
        } = decode_uplink_nas_transport_asn1(&with_unknown_ie(base, 9999, 0x80))
        else {
            panic!("notify proceeds with a report");
        };
        assert_eq!(
            r.cause_protocol,
            ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY
        );
        assert!(matches!(
            decode_uplink_nas_transport_asn1(&with_unknown_ie(base, 9999, 0x00)),
            NasTransportDecode::Reject(_)
        ));
    }

    // ------------------------------------------------------------------
    // #417 / #525: the PDU Session Resource Modify family
    // ------------------------------------------------------------------

    fn modify_response_bytes(
        amf: u64,
        ran: u32,
        modified: &[(u8, Vec<u8>)],
        failed: &[(u8, Vec<u8>)],
    ) -> Vec<u8> {
        nextgcore_ngap::builder::build_pdu_session_resource_modify_response(
            &PduSessionResourceModifyResponse {
                amf_ue_ngap_id: amf,
                ran_ue_ngap_id: ran,
                modify_list: modified
                    .iter()
                    .map(|(psi, t)| PduSessionResourceModifyResponseItem {
                        pdu_session_id: *psi,
                        transfer: t.clone(),
                    })
                    .collect(),
                failed_list: failed
                    .iter()
                    .map(|(psi, t)| PduSessionResourceFailedItem {
                        pdu_session_id: *psi,
                        transfer: t.clone(),
                    })
                    .collect(),
            },
        )
        .expect("build Modify Response")
    }

    /// A Modify Indication built by the hand-written builder (a gNB stand-in).
    pub(crate) fn modify_indication_bytes(
        amf: u64,
        ran: u32,
        sessions: &[(u8, Vec<u8>)],
    ) -> Vec<u8> {
        nextgcore_ngap::builder::build_pdu_session_resource_modify_indication(
            &PduSessionResourceModifyIndication {
                amf_ue_ngap_id: amf,
                ran_ue_ngap_id: ran,
                modify_list: sessions
                    .iter()
                    .map(|(psi, t)| PduSessionResourceModifyIndicationItem {
                        pdu_session_id: *psi,
                        transfer: t.clone(),
                    })
                    .collect(),
            },
        )
        .expect("build Modify Indication")
    }

    /// The Modify Request the hand-written encoder produced before #417 moved it.
    fn hand_written_modify_request(
        amf: u64,
        ran: u32,
        psi: u8,
        nas: Option<&[u8]>,
        transfer: &[u8],
    ) -> Option<Vec<u8>> {
        nextgcore_ngap::builder::build_pdu_session_resource_modify_request(
            &PduSessionResourceModifyRequest {
                amf_ue_ngap_id: amf,
                ran_ue_ngap_id: ran,
                pdu_session_list: vec![PduSessionResourceModifyItem {
                    pdu_session_id: psi,
                    nas_pdu: nas.map(<[u8]>::to_vec),
                    transfer: transfer.to_vec(),
                }],
            },
        )
        .ok()
    }

    /// The generated Modify Request is byte for byte the hand-written one: every
    /// PSI, every ID length, NAS-PDU absent or at each length form, and each
    /// transfer length form; both refuse the out-of-range AMF UE NGAP ID.
    #[test]
    fn pdu_session_resource_modify_request_generated_matches_hand_written() {
        let nas_forms: [Option<Vec<u8>>; 5] = [
            None,
            Some(vec![0x7e]),
            Some(vec![0x7e; 127]),
            Some(vec![0x7e; 128]),
            Some(vec![0x7e; 16_384]),
        ];
        let mut compared = 0;
        let mut refused = 0;
        let mut check = |amf: u64, ran: u32, psi: u8, nas: Option<&[u8]>, t: &[u8]| {
            let new = build_pdu_session_resource_modify_request_asn1(amf, ran, psi, nas, t);
            let old = hand_written_modify_request(amf, ran, psi, nas, t);
            assert_eq!(
                new,
                old,
                "amf={amf} ran={ran} psi={psi} nas={:?}",
                nas.map(<[u8]>::len)
            );
            if new.is_some() {
                compared += 1;
            } else {
                refused += 1;
            }
        };
        for amf in AMF_IDS {
            for ran in RAN_IDS {
                check(amf, ran, 5, None, &[0x00]);
            }
        }
        for psi in 0..=255u8 {
            check(1, 1, psi, Some(&[0x7e, 0x00]), &[psi]);
        }
        for nas in &nas_forms {
            for t in response_transfers() {
                check(7, 9, 5, nas.as_deref(), &t);
            }
        }
        assert_eq!(
            refused,
            RAN_IDS.len(),
            "only the out-of-range AMF UE NGAP ID is refused"
        );
        assert!(compared > 300, "{compared}");
    }

    /// A Modify Request derived by hand from X.691 (APER) and TS 38.413:
    /// `00` initiatingMessage, `1a` procedure 26, `00` reject, `18` open-type
    /// length 24; `00 00 03` SEQUENCE preamble + 3 IEs; AMF-UE-NGAP-ID (10,
    /// reject) `00 01`; RAN-UE-NGAP-ID (85, reject) `00 01`;
    /// PDUSessionResourceModifyListModReq (64, reject): count-1 `00`, item
    /// preamble (no NAS-PDU, no extensions) `00`, PSI `05`, transfer `01 aa`.
    #[test]
    fn a_modify_request_matches_hand_derived_octets() {
        assert_eq!(
            build_pdu_session_resource_modify_request_asn1(1, 1, 5, None, &[0xaa]).unwrap(),
            [
                0x00, 0x1a, 0x00, 0x18, 0x00, 0x00, 0x03, //
                0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x00, 0x02, 0x00, 0x01, //
                0x00, 0x40, 0x00, 0x05, 0x00, 0x00, 0x05, 0x01, 0xaa,
            ]
        );
    }

    /// `(amf, ran, modified, failed)` from the hand-written Modify Response parser.
    #[allow(clippy::type_complexity)]
    fn hand_written_modify_response_view(
        data: &[u8],
    ) -> Option<(u64, u32, Vec<(u8, Vec<u8>)>, Vec<(u8, Vec<u8>)>)> {
        match parser::decode_ngap_pdu(data) {
            Ok(NgapMessage::PduSessionResourceModifyResponse(r)) => Some((
                r.amf_ue_ngap_id,
                r.ran_ue_ngap_id,
                r.modify_list
                    .into_iter()
                    .map(|i| (i.pdu_session_id, i.transfer))
                    .collect(),
                r.failed_list
                    .into_iter()
                    .map(|i| (i.pdu_session_id, i.transfer))
                    .collect(),
            )),
            _ => None,
        }
    }

    #[allow(clippy::type_complexity)]
    fn generated_modify_response_view(
        data: &[u8],
    ) -> Option<(u64, u32, Vec<(u8, Vec<u8>)>, Vec<(u8, Vec<u8>)>)> {
        match decode_pdu_session_resource_modify_response_asn1(data) {
            PduSessionResourceModifyResponseDecode::Decoded {
                amf_ue_ngap_id: Some(amf),
                ran_ue_ngap_id: Some(ran),
                modified,
                failed,
                error_indication: None,
            } => Some((
                amf,
                ran,
                modified
                    .into_iter()
                    .map(|s| (s.pdu_session_id, s.transfer))
                    .collect(),
                failed
                    .into_iter()
                    .map(|s| (s.pdu_session_id, s.transfer))
                    .collect(),
            )),
            _ => None,
        }
    }

    /// Every Modify Response the hand-written parser accepted decodes to the
    /// same UE and sessions, in both lists.
    #[test]
    fn pdu_session_resource_modify_response_generated_decode_matches_hand_written() {
        let mut corpus = Vec::new();
        for amf in &AMF_IDS[..AMF_IDS.len() - 1] {
            for ran in RAN_IDS {
                corpus.push(modify_response_bytes(*amf, ran, &[(5, vec![0x00])], &[]));
            }
        }
        for t in response_transfers() {
            corpus.push(modify_response_bytes(7, 9, &[(3, t.clone())], &[]));
            corpus.push(modify_response_bytes(7, 9, &[], &[(4, t.clone())]));
            corpus.push(modify_response_bytes(7, 9, &[(3, t.clone())], &[(4, t)]));
        }
        let all: Vec<(u8, Vec<u8>)> = (0..=255u8).map(|psi| (psi, vec![psi])).collect();
        corpus.push(modify_response_bytes(7, 9, &all, &[]));
        corpus.push(modify_response_bytes(7, 9, &[], &all));
        for data in &corpus {
            let old = hand_written_modify_response_view(data);
            assert!(
                old.is_some(),
                "the corpus holds accepted messages: {data:02x?}"
            );
            assert_eq!(generated_modify_response_view(data), old, "{data:02x?}");
        }
    }

    /// §10.3.4.2 for the Modify Response (a response message): "notify" is
    /// reported in an Error Indication (procedure 26, successful-outcome) and
    /// the sessions are still decoded; "reject" is handled locally.
    #[test]
    fn modify_response_unknown_ies_follow_the_response_rules() {
        let base = modify_response_bytes(7, 9, &[(5, vec![0x00])], &[]);
        let PduSessionResourceModifyResponseDecode::Decoded {
            modified,
            error_indication: Some(report),
            ..
        } = decode_pdu_session_resource_modify_response_asn1(&with_unknown_ie(&base, 9999, 0x80))
        else {
            panic!("expected Decoded with an Error Indication");
        };
        assert_eq!(modified.len(), 1);
        assert_eq!(
            report.procedure,
            ReportedProcedure {
                procedure_code: ngap_gen::ID_PDU_SESSION_RESOURCE_MODIFY,
                triggering_message: ngap_gen::TriggeringMessage::SUCCESSFUL_OUTCOME,
                procedure_criticality: ngap_gen::Criticality::REJECT,
            }
        );
        assert_eq!(report.diagnostics[0].ie_id, 9999);
        assert!(matches!(
            decode_pdu_session_resource_modify_response_asn1(&with_unknown_ie(&base, 9999, 0x40)),
            PduSessionResourceModifyResponseDecode::Decoded {
                error_indication: None,
                ..
            }
        ));
        assert!(matches!(
            decode_pdu_session_resource_modify_response_asn1(&with_unknown_ie(&base, 9999, 0x00)),
            PduSessionResourceModifyResponseDecode::Failed(ref d) if d[0].ie_id == 9999
        ));
    }

    /// Every Modify Indication the hand-written parser accepted decodes to the
    /// same UE and sessions.
    #[test]
    fn pdu_session_resource_modify_indication_generated_decode_matches_hand_written() {
        let mut corpus = Vec::new();
        for amf in &AMF_IDS[..AMF_IDS.len() - 1] {
            for ran in RAN_IDS {
                corpus.push(modify_indication_bytes(*amf, ran, &[(5, vec![0x00])]));
            }
        }
        for t in response_transfers() {
            corpus.push(modify_indication_bytes(7, 9, &[(3, t)]));
        }
        let all: Vec<(u8, Vec<u8>)> = (0..=255u8).map(|psi| (psi, vec![psi])).collect();
        corpus.push(modify_indication_bytes(7, 9, &all));
        for data in &corpus {
            let Ok(NgapMessage::PduSessionResourceModifyIndication(old)) =
                parser::decode_ngap_pdu(data)
            else {
                panic!("the corpus holds accepted messages: {data:02x?}");
            };
            let PduSessionResourceModifyIndicationDecode::Proceed {
                amf_ue_ngap_id,
                ran_ue_ngap_id,
                sessions,
                notify,
            } = decode_pdu_session_resource_modify_indication_asn1(data)
            else {
                panic!("generated decode refused {data:02x?}");
            };
            assert!(notify.is_empty());
            assert_eq!(
                (amf_ue_ngap_id, ran_ue_ngap_id),
                (old.amf_ue_ngap_id, old.ran_ue_ngap_id)
            );
            let old: Vec<(u8, Vec<u8>)> = old
                .modify_list
                .into_iter()
                .map(|i| (i.pdu_session_id, i.transfer))
                .collect();
            let new: Vec<(u8, Vec<u8>)> = sessions
                .into_iter()
                .map(|s| (s.pdu_session_id, s.transfer))
                .collect();
            assert_eq!(new, old);
        }
    }

    /// §10.3.4.2 / §10.3.5 for the Modify Indication (class 1, no unsuccessful
    /// outcome): "notify" proceeds and is carried to the Confirm; "reject" or a
    /// missing mandatory IE is reported in an Error Indication (procedure 27,
    /// initiating-message) and the procedure is not run.
    #[test]
    fn modify_indication_unknown_and_missing_ies_follow_the_class_1_rules() {
        use PduSessionResourceModifyIndicationDecode::{Proceed, Reject};
        let base = modify_indication_bytes(7, 9, &[(5, vec![0x00])]);
        let Proceed {
            notify, sessions, ..
        } = decode_pdu_session_resource_modify_indication_asn1(&with_unknown_ie(&base, 9999, 0x80))
        else {
            panic!("a notify IE must not stop the procedure");
        };
        assert_eq!(sessions.len(), 1);
        assert_eq!(notify.len(), 1);
        assert_eq!(notify[0].ie_id, 9999);
        assert_eq!(notify[0].criticality, ngap_gen::Criticality::NOTIFY);

        let Reject(report) =
            decode_pdu_session_resource_modify_indication_asn1(&with_unknown_ie(&base, 9999, 0x00))
        else {
            panic!("a reject IE stops the procedure");
        };
        assert_eq!(
            report.procedure,
            ReportedProcedure {
                procedure_code: ngap_gen::ID_PDU_SESSION_RESOURCE_MODIFY_INDICATION,
                triggering_message: ngap_gen::TriggeringMessage::INITIATING_MESSAGE,
                procedure_criticality: ngap_gen::Criticality::REJECT,
            }
        );
        assert_eq!(
            report.cause_protocol,
            ngap_gen::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT
        );

        // The same indication with its AMF UE NGAP ID removed, re-encoded.
        let mut pdu = nextgcore_ngap_gen::decode(&base).expect("decode");
        let ngap_gen::NGAP_PDU::InitiatingMessage(ref mut msg) = pdu else {
            panic!("initiatingMessage");
        };
        let ngap_gen::InitiatingMessageValue::Id_PDUSessionResourceModifyIndication(ref mut ind) =
            msg.value
        else {
            panic!("Modify Indication");
        };
        ind.protocol_i_es
            .0
            .retain(|e| e.id.0 != ngap_gen::ID_AMF_UE_NGAP_ID);
        let no_amf_id = nextgcore_ngap_gen::encode(&pdu).expect("encode");
        let Reject(missing) = decode_pdu_session_resource_modify_indication_asn1(&no_amf_id) else {
            panic!("a missing AMF UE NGAP ID (criticality reject) stops the procedure");
        };
        assert_eq!(
            missing.diagnostics,
            vec![IeDiagnostic {
                ie_id: ngap_gen::ID_AMF_UE_NGAP_ID,
                criticality: ngap_gen::Criticality::REJECT,
                type_of_error: ngap_gen::TypeOfError::MISSING,
            }]
        );
        assert_eq!(
            (missing.amf_ue_ngap_id, missing.ran_ue_ngap_id),
            (None, Some(9))
        );
    }

    /// A Modify Confirm derived by hand: `20` successfulOutcome, `1b`
    /// procedure 27, `00` reject, `18` length 24; `00 00 03`; AMF-UE-NGAP-ID
    /// (10, ignore `40`) `00 01`; RAN-UE-NGAP-ID (85, ignore) `00 01`;
    /// PDUSessionResourceModifyListModCfm (62, ignore): count-1 `00`, item
    /// preamble `00`, PSI `05`, transfer `01 bb`.
    #[test]
    fn a_modify_confirm_matches_hand_derived_octets() {
        let confirmed = [ModifyPduSession {
            pdu_session_id: 5,
            transfer: vec![0xbb],
        }];
        assert_eq!(
            build_pdu_session_resource_modify_confirm_asn1(1, 1, &confirmed, &[], &[]).unwrap(),
            [
                0x20, 0x1b, 0x00, 0x18, 0x00, 0x00, 0x03, //
                0x00, 0x0a, 0x40, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x40, 0x02, 0x00, 0x01, //
                0x00, 0x3e, 0x40, 0x05, 0x00, 0x00, 0x05, 0x01, 0xbb,
            ]
        );
    }

    /// The Confirm carries both lists and, for a "notify" IE of the indication,
    /// the Criticality Diagnostics (§10.3.4.2: in the response, not an Error
    /// Indication); it decodes back to what was put in.
    #[test]
    fn a_modify_confirm_carries_both_lists_and_the_notify_diagnostics() {
        use ngap_gen::PDUSessionResourceModifyConfirmProtocolIEs_EntryValue as Ie;
        let notify = [IeDiagnostic {
            ie_id: 9999,
            criticality: ngap_gen::Criticality::NOTIFY,
            type_of_error: ngap_gen::TypeOfError::NOT_UNDERSTOOD,
        }];
        let bytes = build_pdu_session_resource_modify_confirm_asn1(
            7,
            9,
            &[ModifyPduSession {
                pdu_session_id: 2,
                transfer: vec![0x21],
            }],
            &[ModifyPduSession {
                pdu_session_id: 3,
                transfer: vec![0x31, 0x32],
            }],
            &notify,
        )
        .unwrap();
        let ngap_gen::NGAP_PDU::SuccessfulOutcome(out) =
            nextgcore_ngap_gen::decode(&bytes).unwrap()
        else {
            panic!("successfulOutcome");
        };
        let ngap_gen::SuccessfulOutcomeValue::Id_PDUSessionResourceModifyIndication(cfm) =
            out.value
        else {
            panic!("Modify Confirm");
        };
        let ids: Vec<u16> = cfm.protocol_i_es.0.iter().map(|e| e.id.0).collect();
        assert_eq!(ids, vec![10, 85, 62, 131, 19], "object-set order");
        let mut saw_diag = false;
        for e in cfm.protocol_i_es.0 {
            assert_eq!(e.criticality.0, ngap_gen::Criticality::IGNORE);
            match e.value {
                Ie::Id_PDUSessionResourceModifyListModCfm(l) => {
                    assert_eq!(l.0[0].pdu_session_id.0, 2);
                    assert_eq!(
                        l.0[0].pdu_session_resource_modify_confirm_transfer.0,
                        vec![0x21]
                    );
                }
                Ie::Id_PDUSessionResourceFailedToModifyListModCfm(l) => {
                    assert_eq!(l.0[0].pdu_session_id.0, 3);
                    assert_eq!(
                        l.0[0]
                            .pdu_session_resource_modify_indication_unsuccessful_transfer
                            .0,
                        vec![0x31, 0x32]
                    );
                }
                Ie::Id_CriticalityDiagnostics(d) => {
                    saw_diag = true;
                    assert!(d.procedure_code.is_none(), "§9.3.1.3: not in a response");
                    assert_eq!(d.i_es_criticality_diagnostics.unwrap().0[0].ie_id.0, 9999);
                }
                _ => {}
            }
        }
        assert!(saw_diag);
        // Neither list present when there is nothing to put in it.
        let empty = build_pdu_session_resource_modify_confirm_asn1(7, 9, &[], &[], &[]).unwrap();
        let ngap_gen::NGAP_PDU::SuccessfulOutcome(out) =
            nextgcore_ngap_gen::decode(&empty).unwrap()
        else {
            panic!("successfulOutcome");
        };
        let ngap_gen::SuccessfulOutcomeValue::Id_PDUSessionResourceModifyIndication(cfm) =
            out.value
        else {
            panic!("Modify Confirm");
        };
        assert_eq!(cfm.protocol_i_es.0.len(), 2);
    }

    /// The Unsuccessful Transfer the AMF builds for a session the SMF did not
    /// answer, derived by hand: SEQUENCE preamble `00` (extension, no
    /// iE-Extensions), Cause CHOICE index 4 (misc, 3 bits `100`), misc
    /// ENUMERATED extension bit `0` + index 5 unspecified (`101`): `0010 0010 1`
    /// -> `22 80`.
    #[test]
    fn the_amf_built_modify_indication_unsuccessful_transfer_matches_hand_derived_octets() {
        assert_eq!(
            modify_indication_unsuccessful_transfer(Cause::Misc(CauseMisc::Unspecified)).unwrap(),
            [0x22, 0x80]
        );
    }
}

#[cfg(test)]
mod handover_required_tests {
    //! #417 handover part 3b: HANDOVER REQUIRED decode via the generated codec.
    use super::tests::with_unknown_ie;
    use super::*;

    fn required(target_id: TargetId, sessions: u8, direct: bool) -> HandoverRequired {
        HandoverRequired {
            amf_ue_ngap_id: 0x1_0000_0001,
            ran_ue_ngap_id: 7,
            handover_type: HandoverType::Intra5gs,
            cause: Cause::RadioNetwork(CauseRadioNetwork::HandoverDesirableForRadioReason),
            target_id,
            pdu_session_list: (1..=sessions)
                .map(|psi| PduSessionResourceItemHoRqd {
                    pdu_session_id: psi,
                    transfer: vec![0x00, psi],
                })
                .collect(),
            source_to_target_container: vec![0xAB; 5],
            direct_forwarding_path_availability: direct.then_some(
                nextgcore_asn1c::ngap::ies::DirectForwardingPathAvailability::DirectPathAvailable,
            ),
        }
    }

    fn gnb_target(gnb_id: u32, gnb_id_len: u8) -> TargetId {
        TargetId::TargetRanNodeId {
            global_ran_node_id: GlobalRanNodeId::GlobalGnbId {
                plmn_identity: [0x99, 0xF9, 0x07],
                gnb_id,
                gnb_id_len,
            },
            selected_tai: TaiListItem {
                tai_plmn: [0x99, 0xF9, 0x07],
                tai_tac: [0x00, 0x00, 0x07],
            },
        }
    }

    /// What the hand-written parser and the generated decoder say about the same
    /// bytes, flattened to comparable values.
    fn view(r: &HandoverRequired) -> String {
        format!(
            "{} {} {:?} {:?} {:?} {:?} {:?} {:?}",
            r.amf_ue_ngap_id,
            r.ran_ue_ngap_id,
            r.handover_type,
            r.cause,
            r.target_id,
            r.pdu_session_list
                .iter()
                .map(|s| (s.pdu_session_id, s.transfer.clone()))
                .collect::<Vec<_>>(),
            r.source_to_target_container,
            r.direct_forwarding_path_availability.is_some(),
        )
    }

    fn generated(data: &[u8]) -> HandoverRequired {
        match decode_handover_required_asn1(data) {
            NasTransportDecode::Proceed {
                message,
                error_indication: None,
            } => message,
            other => panic!("expected a clean decode, got {other:?}"),
        }
    }

    /// Every Handover Required naming a gNB target the hand-written parser
    /// accepted decodes to the same values through the generated codec: gNB id
    /// lengths 22..32 at their extremes, 1..4 sessions, both handover types the
    /// gNB path takes, with and without Direct Forwarding Path Availability.
    #[test]
    fn handover_required_generated_decode_matches_hand_written() {
        let mut cases = 0;
        for len in [22u8, 25, 32] {
            for gnb_id in [0u32, 1, ((1u64 << len) - 1) as u32] {
                // SIZE(1..256): an empty list is refused by the hand-written
                // builder itself, so the sweep starts at one session.
                for sessions in 1..=4 {
                    for direct in [false, true] {
                        for ho_type in [HandoverType::Intra5gs, HandoverType::FivegsToEps] {
                            let mut msg = required(gnb_target(gnb_id, len), sessions, direct);
                            msg.handover_type = ho_type;
                            let bytes = builder::build_handover_required(&msg).expect("build");
                            let Ok(NgapMessage::HandoverRequired(old)) =
                                parser::decode_ngap_pdu(&bytes)
                            else {
                                panic!("hand-written parser refused {len}/{gnb_id}/{sessions}");
                            };
                            assert_eq!(view(&generated(&bytes)), view(&old));
                            cases += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 3 * 3 * 4 * 2 * 2);
    }

    /// The targeteNB-ID form (TS 38.413 §9.3.1.25), octets derived by hand from
    /// X.691: CHOICE index 1 of 3 (`01`); TargeteNB-ID and GlobalNgENB-ID each
    /// open with an extension bit and an optional bitmap (`0000`), padding ->
    /// `40`; PLMN (fixed 3, aligned) `99 F9 07`; ngENB-ID CHOICE macro (`00`),
    /// padding, BIT STRING(20) 0x12345 (fixed > 16 bits, aligned) `00 12 34 5`;
    /// EPS-TAI's extension and optional bits `00`, padding -> `50`; PLMN
    /// `99 F9 07`; ePS-TAC (fixed 2, unaligned) `00 07`.
    #[test]
    fn an_enb_target_decodes_to_its_plmn_enb_id_and_eps_tac() {
        const GOLDEN: [u8; 13] = [
            0x40, 0x99, 0xF9, 0x07, 0x00, 0x12, 0x34, 0x50, 0x99, 0xF9, 0x07, 0x00, 0x07,
        ];
        let target = ngap_gen::TargetID::TargeteNB_ID(ngap_gen::TargeteNB_ID {
            global_enb_id: ngap_gen::GlobalNgENB_ID {
                plmn_identity: ngap_gen::PLMNIdentity(vec![0x99, 0xF9, 0x07]),
                ng_enb_id: ngap_gen::NgENB_ID::MacroNgENB_ID(ngap_gen::NgENB_ID_macroNgENB_ID(
                    bitvec::bitvec![u8, bitvec::prelude::Msb0;
                        0,0,0,1, 0,0,1,0, 0,0,1,1, 0,1,0,0, 0,1,0,1],
                )),
                ie_extensions: None,
            },
            selected_eps_tai: ngap_gen::EPS_TAI {
                plmn_identity: ngap_gen::PLMNIdentity(vec![0x99, 0xF9, 0x07]),
                eps_tac: ngap_gen::EPS_TAC(vec![0x00, 0x07]),
                ie_extensions: None,
            },
            ie_extensions: None,
        });
        assert_eq!(
            nextgcore_ngap_gen::encode_contained(&target).expect("encode"),
            GOLDEN
        );

        // The same TargetID inside a whole Handover Required: start from one the
        // hand-written builder made and replace its TargetID IE.
        let base = builder::build_handover_required(&required(gnb_target(1, 22), 1, false))
            .expect("build");
        let mut pdu = nextgcore_ngap_gen::decode(&base).expect("decode");
        let ngap_gen::NGAP_PDU::InitiatingMessage(ref mut msg) = pdu else {
            panic!("initiatingMessage");
        };
        let ngap_gen::InitiatingMessageValue::Id_HandoverPreparation(ref mut req) = msg.value
        else {
            panic!("Handover Required");
        };
        for e in req.protocol_i_es.0.iter_mut() {
            if let ngap_gen::HandoverRequiredProtocolIEs_EntryValue::Id_TargetID(ref mut t) =
                e.value
            {
                *t = target.clone();
            }
        }
        let bytes = nextgcore_ngap_gen::encode(&pdu).expect("encode");
        let TargetId::TargetGlobalNgEnbId {
            plmn_identity,
            ng_enb_id,
            selected_tai,
        } = generated(&bytes).target_id
        else {
            panic!("an eNB target");
        };
        assert_eq!(plmn_identity, [0x99, 0xF9, 0x07]);
        assert_eq!(ng_enb_id, 0x12345);
        assert_eq!(selected_tai.tai_plmn, [0x99, 0xF9, 0x07]);
        assert_eq!(selected_tai.tai_tac, [0x00, 0x00, 0x07]);
        // The hand-written parser misreads this conformant encoding.
        let misread = match parser::decode_ngap_pdu(&bytes) {
            Ok(NgapMessage::HandoverRequired(old)) => match old.target_id {
                TargetId::TargetGlobalNgEnbId {
                    plmn_identity,
                    ng_enb_id,
                    ..
                } => plmn_identity != [0x99, 0xF9, 0x07] || ng_enb_id != 0x12345,
                _ => true,
            },
            _ => true,
        };
        assert!(
            misread,
            "the hand-written TargetID decoder was expected to misread"
        );
    }

    fn without(bytes: &[u8], id: u16) -> Vec<u8> {
        let mut pdu = nextgcore_ngap_gen::decode(bytes).expect("decode");
        let ngap_gen::NGAP_PDU::InitiatingMessage(ref mut msg) = pdu else {
            panic!("initiatingMessage");
        };
        let ngap_gen::InitiatingMessageValue::Id_HandoverPreparation(ref mut req) = msg.value
        else {
            panic!("Handover Required");
        };
        req.protocol_i_es.0.retain(|e| e.id.0 != id);
        nextgcore_ngap_gen::encode(&pdu).expect("encode")
    }

    /// TS 38.413 §10.3.4.2 / §10.3.5 for a Class 1 initiating message.
    #[test]
    fn handover_required_follows_ie_criticality() {
        let base = builder::build_handover_required(&required(gnb_target(1, 22), 1, false))
            .expect("build");
        // ignore: dropped, no report.
        assert!(matches!(
            decode_handover_required_asn1(&with_unknown_ie(&base, 9999, 0x40)),
            NasTransportDecode::Proceed {
                error_indication: None,
                ..
            }
        ));
        // notify: proceeds, reported.
        let NasTransportDecode::Proceed {
            error_indication: Some(report),
            ..
        } = decode_handover_required_asn1(&with_unknown_ie(&base, 9999, 0x80))
        else {
            panic!("notify must proceed and be reported");
        };
        assert_eq!(report.diagnostics[0].ie_id, 9999);
        assert_eq!(
            report.procedure.procedure_code,
            ngap_gen::ID_HANDOVER_PREPARATION
        );
        assert_eq!(
            hand_written_diagnostics(&report).ies[0].ie_criticality,
            nextgcore_asn1c::ngap::types::Criticality::Notify
        );
        // reject: rejected, naming the IE and both UE ids.
        let NasTransportDecode::Reject(report) =
            decode_handover_required_asn1(&with_unknown_ie(&base, 9999, 0x00))
        else {
            panic!("reject must reject");
        };
        assert_eq!(report.amf_ue_ngap_id, Some(0x1_0000_0001));
        assert_eq!(report.ran_ue_ngap_id, Some(7));
        let diag = hand_written_diagnostics(&report);
        assert_eq!(diag.ies[0].ie_id, 9999);
        assert_eq!(
            diag.ies[0].ie_criticality,
            nextgcore_asn1c::ngap::types::Criticality::Reject
        );
        assert_eq!(diag.ies[0].type_of_error, TypeOfError::NotUnderstood);
        assert_eq!(diag.procedure_code, Some(ngap_gen::ID_HANDOVER_PREPARATION));
        // A missing mandatory reject IE is rejected as Missing; a missing Cause
        // (criticality ignore) is misc/unspecified.
        for id in [
            ngap_gen::ID_HANDOVER_TYPE,
            ngap_gen::ID_TARGET_ID,
            ngap_gen::ID_PDU_SESSION_RESOURCE_LIST_HO_RQD,
            ngap_gen::ID_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER,
        ] {
            let NasTransportDecode::Reject(r) = decode_handover_required_asn1(&without(&base, id))
            else {
                panic!("missing {id} must reject");
            };
            assert_eq!(r.diagnostics[0].ie_id, id);
            assert_eq!(
                r.diagnostics[0].type_of_error,
                ngap_gen::TypeOfError::MISSING
            );
        }
        assert_eq!(
            generated(&without(&base, ngap_gen::ID_CAUSE)).cause,
            Cause::Misc(CauseMisc::Unspecified)
        );
    }
}
