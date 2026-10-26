//! SBc-AP procedures toward the CBC (#1071, TS 29.168 §4.3).
//!
//! [`handle_sbcap_pdu`] takes one SBc-AP PDU from a CBC association and returns
//! the PDUs to send back on it:
//! - WRITE-REPLACE WARNING REQUEST (§4.3.3): decoded into [`SbcPwsData`], fanned out
//!   by `sbc_handler`, answered at once with WRITE-REPLACE WARNING RESPONSE;
//! - STOP WARNING REQUEST (§4.3.3A): likewise, answered with STOP WARNING RESPONSE;
//! - ERROR INDICATION from the CBC (§4.3.3B): logged;
//! - an undecodable PDU: ERROR INDICATION, cause "Transfer syntax error" (§4.5.2);
//! - a request missing its Message Identifier or Serial Number, which the response
//!   cannot be built without: ERROR INDICATION, "Missing mandatory element", with
//!   the procedure in its Criticality Diagnostics (§4.5.3.3);
//! - any other message the MME does not expect from a CBC: ERROR INDICATION,
//!   "Message not compatible with receiver state".
//!
//! The responses' Cause follows §4.3.3.2 / §4.3.4.3.6: "Message accepted" when the
//! request reached an eNB, with the Unknown Tracking Area List only then; "Tracking
//! area not valid" when every requested TAI is unknown; otherwise the fan-out's own
//! failure cause.

use nextgcore_sbcap_gen::generated as g;

use crate::context::{EpsTai, MmeContext, PlmnId};
use crate::sbc_message::{SbcCause, SbcPwsData};

/// Procedure codes (TS 29.168 §4.4.7, SBC-AP-Constants).
pub mod procedure {
    pub const WRITE_REPLACE_WARNING: u8 = 0;
    pub const STOP_WARNING: u8 = 1;
    pub const ERROR_INDICATION: u8 = 2;
    pub const PWS_RESTART_INDICATION: u8 = 5;
    pub const PWS_FAILURE_INDICATION: u8 = 6;
}

/// Protocol IE ids (TS 29.168 §4.4.7).
mod ie {
    pub const CAUSE: u16 = 1;
    pub const CRITICALITY_DIAGNOSTICS: u16 = 2;
    pub const MESSAGE_IDENTIFIER: u16 = 5;
    pub const SERIAL_NUMBER: u16 = 11;
    pub const UNKNOWN_TRACKING_AREA_LIST: u16 = 22;
}

fn bits16(v: &bitvec::vec::BitVec<u8, bitvec::order::Msb0>) -> Option<u16> {
    (v.len() == 16).then(|| {
        v.as_raw_slice()
            .first()
            .copied()
            .map(u16::from)
            .unwrap_or(0)
            << 8
            | v.as_raw_slice().get(1).copied().map(u16::from).unwrap_or(0)
    })
}

fn to_bits16(v: u16) -> bitvec::vec::BitVec<u8, bitvec::order::Msb0> {
    bitvec::vec::BitVec::from_slice(&v.to_be_bytes())
}

fn bits_value(v: &bitvec::vec::BitVec<u8, bitvec::order::Msb0>) -> u32 {
    v.iter().fold(0u32, |acc, b| (acc << 1) | u32::from(*b))
}

fn plmn_of(t: &g::TBCD_STRING) -> Option<PlmnId> {
    let b: [u8; 3] = t.0.as_slice().try_into().ok()?;
    Some(crate::s1ap_build::decode_plmn_id(&b))
}

fn tai_of(t: &g::TAI) -> Option<EpsTai> {
    let tac: [u8; 2] = t.tac.0.as_slice().try_into().ok()?;
    Some(EpsTai {
        plmn_id: plmn_of(&t.plm_nidentity)?,
        tac: u16::from_be_bytes(tac),
    })
}

fn to_tai(t: &EpsTai) -> g::TAI {
    g::TAI {
        plm_nidentity: g::TBCD_STRING(crate::s1ap_build::encode_plmn_id(&t.plmn_id).to_vec()),
        tac: g::TAC(t.tac.to_be_bytes().to_vec()),
        ie_extensions: None,
    }
}

/// The Global eNB ID as the S1AP side names it.
pub(crate) fn global_enb_of(id: &g::Global_ENB_ID) -> Option<(PlmnId, nextgcore_s1ap::EnbId)> {
    use nextgcore_s1ap::EnbId;
    let enb = match &id.enb_id {
        g::ENB_ID::MacroENB_ID(b) => EnbId::Macro(bits_value(&b.0)),
        g::ENB_ID::HomeENB_ID(b) => EnbId::Home(bits_value(&b.0)),
        g::ENB_ID::Short_macroENB_ID(b) => EnbId::ShortMacro(bits_value(&b.0)),
        g::ENB_ID::Long_macroENB_ID(b) => EnbId::LongMacro(bits_value(&b.0)),
    };
    Some((plmn_of(&id.plm_nidentity)?, enb))
}

fn ecgi_of(c: &g::EUTRAN_CGI) -> Option<nextgcore_s1ap::EutranCgi> {
    Some(nextgcore_s1ap::EutranCgi {
        plmn_identity: c.plm_nidentity.0.as_slice().try_into().ok()?,
        cell_identity: bits_value(&c.cell_id.0),
    })
}

/// The SBc-AP Warning Area List as the S1AP one (the same three alternatives,
/// TS 29.168 refers to TS 36.413 for it). `None` when an entry is malformed.
fn warning_area_of(w: &g::Warning_Area_List) -> Option<nextgcore_s1ap::WarningAreaList> {
    use nextgcore_s1ap::{Tai, WarningAreaList as W};
    Some(match w {
        g::Warning_Area_List::Cell_ID_List(l) => {
            W::CellIdList(l.0.iter().map(ecgi_of).collect::<Option<Vec<_>>>()?)
        }
        g::Warning_Area_List::Tracking_Area_List_for_Warning(l) => W::TrackingAreaListForWarning(
            l.0.iter()
                .map(|t| {
                    let tai = tai_of(t)?;
                    Some(Tai {
                        plmn_identity: crate::s1ap_build::encode_plmn_id(&tai.plmn_id),
                        tac: tai.tac,
                    })
                })
                .collect::<Option<Vec<_>>>()?,
        ),
        g::Warning_Area_List::Emergency_Area_ID_List(l) => W::EmergencyAreaIdList(
            l.0.iter()
                .map(|e| e.0.as_slice().try_into().ok())
                .collect::<Option<Vec<[u8; 3]>>>()?,
        ),
    })
}

/// What a request decoded to.
enum Decoded {
    Request(SbcPwsData),
    /// A mandatory IE is absent or malformed: the response carries this cause
    /// (both identifiers are known).
    Refused(SbcPwsData, SbcCause),
    /// No Message Identifier or Serial Number: no response can be built.
    NoIdentifiers,
}

fn write_replace(req: &g::Write_Replace_Warning_Request) -> Decoded {
    use g::Write_Replace_Warning_RequestProtocolIEs_EntryValue as V;
    let (mut id, mut serial) = (None, None);
    let (mut repetition, mut broadcasts) = (None, None);
    let mut pws = SbcPwsData::default();
    let mut malformed = false;
    for e in &req.protocol_i_es.0 {
        match &e.value {
            V::Id_Message_Identifier(m) => id = bits16(&m.0),
            V::Id_Serial_Number(s) => serial = bits16(&s.0),
            V::Id_List_of_TAIs(l) => {
                for t in &l.0 {
                    match tai_of(&t.tai) {
                        Some(tai) => pws.add_tai(tai),
                        None => malformed = true,
                    }
                }
            }
            V::Id_Warning_Area_List(w) => pws.warning_area = warning_area_of(w),
            V::Id_Repetition_Period(r) => repetition = Some(u32::from(r.0)),
            V::Id_Extended_Repetition_Period(r) => pws.extended_repetition_period = Some(r.0),
            V::Id_Number_of_Broadcasts_Requested(n) => broadcasts = Some(u32::from(n.0)),
            V::Id_Warning_Type(w) => {
                pws.warning_type = <[u8; 2]>::try_from(w.0.as_slice())
                    .ok()
                    .map(crate::sbc_message::EtwsWarningType::decode)
            }
            V::Id_Warning_Security_Information(w) => {
                pws.warning_security_info = w.0.as_slice().try_into().ok()
            }
            V::Id_Data_Coding_Scheme(d) => {
                pws.data_coding_scheme = d.0.as_raw_slice().first().copied().unwrap_or(0)
            }
            V::Id_Warning_Message_Content(c) => pws.set_message(&c.0, pws.data_coding_scheme),
            V::Id_Concurrent_Warning_Message_Indicator(_) => {
                pws.concurrent_warning_message_indicator = true
            }
            V::Id_Send_Write_Replace_Warning_Indication(_) => {
                pws.send_write_replace_warning_indication = true
            }
            V::Id_Global_ENB_ID(g_id) => pws.global_enb = global_enb_of(g_id),
            V::Id_Omc_Id(_) | V::Id_Warning_Area_Coordinates(_) => {}
        }
    }
    // The content's coding scheme may come after the content.
    pws.message_length = pws.message_contents.len() as u32;
    let (Some(id), Some(serial)) = (id, serial) else {
        return Decoded::NoIdentifiers;
    };
    pws.message_id = id;
    pws.serial_number = serial;
    match (repetition, broadcasts) {
        (Some(r), Some(n)) if !malformed => {
            pws.repetition_period = r;
            pws.number_of_broadcast = n;
            Decoded::Request(pws)
        }
        (Some(_), Some(_)) => Decoded::Refused(pws, SbcCause::ParameterValueInvalid),
        _ => Decoded::Refused(pws, SbcCause::MissingMandatoryElement),
    }
}

fn stop_warning(req: &g::Stop_Warning_Request) -> Decoded {
    use g::Stop_Warning_RequestProtocolIEs_EntryValue as V;
    let (mut id, mut serial) = (None, None);
    let mut pws = SbcPwsData::default();
    let mut malformed = false;
    for e in &req.protocol_i_es.0 {
        match &e.value {
            V::Id_Message_Identifier(m) => id = bits16(&m.0),
            V::Id_Serial_Number(s) => serial = bits16(&s.0),
            V::Id_List_of_TAIs(l) => {
                for t in &l.0 {
                    match tai_of(&t.tai) {
                        Some(tai) => pws.add_tai(tai),
                        None => malformed = true,
                    }
                }
            }
            V::Id_Warning_Area_List(w) => pws.warning_area = warning_area_of(w),
            V::Id_Stop_All_Indicator(_) => pws.stop_all = true,
            V::Id_Omc_Id(_) | V::Id_Send_Stop_Warning_Indication(_) => {}
        }
    }
    let (Some(id), Some(serial)) = (id, serial) else {
        return Decoded::NoIdentifiers;
    };
    pws.message_id = id;
    pws.serial_number = serial;
    if malformed {
        Decoded::Refused(pws, SbcCause::ParameterValueInvalid)
    } else {
        Decoded::Request(pws)
    }
}

/// The Cause and Unknown Tracking Area List of a response (TS 29.168 §4.3.3.2,
/// §4.3.4.3.6).
fn outcome(
    pws: &SbcPwsData,
    cause: Option<SbcCause>,
    unknown: Vec<EpsTai>,
) -> (SbcCause, Vec<EpsTai>) {
    if pws.no_of_tai > 0 && unknown.len() == pws.tai.len() {
        return (SbcCause::TrackingAreaNotValid, Vec::new());
    }
    match cause {
        None => (SbcCause::MessageAccepted, unknown),
        Some(c) => (c, Vec::new()),
    }
}

fn successful(code: u8, value: g::SuccessfulOutcomeValue) -> g::SBC_AP_PDU {
    g::SBC_AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
        procedure_code: g::ProcedureCode(code),
        criticality: g::Criticality(g::Criticality::REJECT),
        value,
    })
}

fn write_replace_response(
    id: u16,
    serial: u16,
    cause: SbcCause,
    unknown: &[EpsTai],
) -> g::SBC_AP_PDU {
    use g::Write_Replace_Warning_ResponseProtocolIEs_EntryValue as V;
    let entry = |id: u16, crit: u8, value: V| g::Write_Replace_Warning_ResponseProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(crit),
        value,
    };
    let mut ies = vec![
        entry(
            ie::MESSAGE_IDENTIFIER,
            g::Criticality::REJECT,
            V::Id_Message_Identifier(g::Message_Identifier(to_bits16(id))),
        ),
        entry(
            ie::SERIAL_NUMBER,
            g::Criticality::REJECT,
            V::Id_Serial_Number(g::Serial_Number(to_bits16(serial))),
        ),
        entry(
            ie::CAUSE,
            g::Criticality::REJECT,
            V::Id_Cause(g::Cause(cause as u8)),
        ),
    ];
    if !unknown.is_empty() {
        ies.push(entry(
            ie::UNKNOWN_TRACKING_AREA_LIST,
            g::Criticality::IGNORE,
            V::Id_Unknown_Tracking_Area_List(tai_list(unknown)),
        ));
    }
    successful(
        procedure::WRITE_REPLACE_WARNING,
        g::SuccessfulOutcomeValue::Id_Write_Replace_Warning(g::Write_Replace_Warning_Response {
            protocol_i_es: g::Write_Replace_Warning_ResponseProtocolIEs(ies),
            protocol_extensions: None,
        }),
    )
}

fn stop_warning_response(
    id: u16,
    serial: u16,
    cause: SbcCause,
    unknown: &[EpsTai],
) -> g::SBC_AP_PDU {
    use g::Stop_Warning_ResponseProtocolIEs_EntryValue as V;
    let entry = |id: u16, crit: u8, value: V| g::Stop_Warning_ResponseProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(crit),
        value,
    };
    let mut ies = vec![
        entry(
            ie::MESSAGE_IDENTIFIER,
            g::Criticality::REJECT,
            V::Id_Message_Identifier(g::Message_Identifier(to_bits16(id))),
        ),
        entry(
            ie::SERIAL_NUMBER,
            g::Criticality::REJECT,
            V::Id_Serial_Number(g::Serial_Number(to_bits16(serial))),
        ),
        entry(
            ie::CAUSE,
            g::Criticality::REJECT,
            V::Id_Cause(g::Cause(cause as u8)),
        ),
    ];
    if !unknown.is_empty() {
        ies.push(entry(
            ie::UNKNOWN_TRACKING_AREA_LIST,
            g::Criticality::IGNORE,
            V::Id_Unknown_Tracking_Area_List(tai_list(unknown)),
        ));
    }
    successful(
        procedure::STOP_WARNING,
        g::SuccessfulOutcomeValue::Id_Stop_Warning(g::Stop_Warning_Response {
            protocol_i_es: g::Stop_Warning_ResponseProtocolIEs(ies),
            protocol_extensions: None,
        }),
    )
}

fn tai_list(tais: &[EpsTai]) -> g::List_of_TAIs {
    g::List_of_TAIs(
        tais.iter()
            .map(|t| g::List_of_TAIs_Entry { tai: to_tai(t) })
            .collect(),
    )
}

/// ERROR INDICATION (TS 29.168 §4.3.4.2A.1) with `cause` and, when the error is
/// tied to one, the procedure in the Criticality Diagnostics.
pub(crate) fn error_indication(cause: SbcCause, procedure_code: Option<u8>) -> g::SBC_AP_PDU {
    use g::Error_IndicationProtocolIEs_EntryValue as V;
    let mut ies = vec![g::Error_IndicationProtocolIEs_Entry {
        id: g::ProtocolIE_ID(ie::CAUSE),
        criticality: g::Criticality(g::Criticality::IGNORE),
        value: V::Id_Cause(g::Cause(cause as u8)),
    }];
    if let Some(code) = procedure_code {
        ies.push(g::Error_IndicationProtocolIEs_Entry {
            id: g::ProtocolIE_ID(ie::CRITICALITY_DIAGNOSTICS),
            criticality: g::Criticality(g::Criticality::IGNORE),
            value: V::Id_Criticality_Diagnostics(g::Criticality_Diagnostics {
                procedure_code: Some(g::ProcedureCode(code)),
                triggering_message: Some(g::TriggeringMessage(
                    g::TriggeringMessage::INITIATING_MESSAGE,
                )),
                procedure_criticality: Some(g::Criticality(g::Criticality::REJECT)),
                ie_criticality_diagnostics: None,
                ie_extensions: None,
            }),
        });
    }
    g::SBC_AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(procedure::ERROR_INDICATION),
        criticality: g::Criticality(g::Criticality::IGNORE),
        value: g::InitiatingMessageValue::Id_Error_Indication(g::Error_Indication {
            protocol_i_es: g::Error_IndicationProtocolIEs(ies),
        }),
    })
}

fn encoded(pdu: &g::SBC_AP_PDU) -> Vec<Vec<u8>> {
    match nextgcore_sbcap_gen::encode(pdu) {
        Ok(b) => vec![b],
        Err(e) => {
            log::error!("SBc-AP: an answer did not encode: {e:?}");
            Vec::new()
        }
    }
}

/// Handle one SBc-AP PDU from a CBC; returns the PDUs to send back on its
/// association.
pub fn handle_sbcap_pdu(ctx: &MmeContext, bytes: &[u8]) -> Vec<Vec<u8>> {
    handle_sbcap_pdu_with(ctx, bytes, &mut crate::sbc_handler::transport_sender)
}

/// [`handle_sbcap_pdu`] with the eNB-side sender injected (tests record it).
pub(crate) fn handle_sbcap_pdu_with(
    ctx: &MmeContext,
    bytes: &[u8],
    send: crate::sbc_handler::PduSender,
) -> Vec<Vec<u8>> {
    let pdu = match nextgcore_sbcap_gen::decode(bytes) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("SBc-AP: undecodable PDU ({} octets): {e:?}", bytes.len());
            return encoded(&error_indication(SbcCause::TransferSyntaxError, None));
        }
    };
    let g::SBC_AP_PDU::InitiatingMessage(msg) = pdu else {
        log::warn!("SBc-AP: an outcome from the CBC, which this MME never asked for");
        return encoded(&error_indication(
            SbcCause::MessageNotCompatibleWithReceiverState,
            None,
        ));
    };
    match &msg.value {
        g::InitiatingMessageValue::Id_Write_Replace_Warning(req) => match write_replace(req) {
            Decoded::Request(pws) => {
                let (cause, unknown) =
                    match crate::sbc_handler::handle_write_replace_warning_request_with(
                        ctx, &pws, send,
                    ) {
                        Ok(r) => outcome(&pws, r.cause, r.unknown_tai_list),
                        Err(c) => (c, Vec::new()),
                    };
                log::info!(
                    "SBc-AP WRITE-REPLACE WARNING {:#06x}/{:#06x}: cause {cause:?}",
                    pws.message_id,
                    pws.serial_number
                );
                encoded(&write_replace_response(
                    pws.message_id,
                    pws.serial_number,
                    cause,
                    &unknown,
                ))
            }
            Decoded::Refused(pws, cause) => {
                log::warn!(
                    "SBc-AP WRITE-REPLACE WARNING {:#06x}/{:#06x} refused: {cause:?}",
                    pws.message_id,
                    pws.serial_number
                );
                encoded(&write_replace_response(
                    pws.message_id,
                    pws.serial_number,
                    cause,
                    &[],
                ))
            }
            Decoded::NoIdentifiers => encoded(&error_indication(
                SbcCause::MissingMandatoryElement,
                Some(procedure::WRITE_REPLACE_WARNING),
            )),
        },
        g::InitiatingMessageValue::Id_Stop_Warning(req) => match stop_warning(req) {
            Decoded::Request(pws) => {
                let (cause, unknown) =
                    match crate::sbc_handler::handle_stop_warning_request_with(ctx, &pws, send) {
                        Ok(r) => outcome(&pws, r.cause, r.unknown_tai_list),
                        Err(c) => (c, Vec::new()),
                    };
                log::info!(
                    "SBc-AP STOP WARNING {:#06x}/{:#06x}: cause {cause:?}",
                    pws.message_id,
                    pws.serial_number
                );
                encoded(&stop_warning_response(
                    pws.message_id,
                    pws.serial_number,
                    cause,
                    &unknown,
                ))
            }
            Decoded::Refused(pws, cause) => encoded(&stop_warning_response(
                pws.message_id,
                pws.serial_number,
                cause,
                &[],
            )),
            Decoded::NoIdentifiers => encoded(&error_indication(
                SbcCause::MissingMandatoryElement,
                Some(procedure::STOP_WARNING),
            )),
        },
        g::InitiatingMessageValue::Id_Error_Indication(ei) => {
            let cause = ei.protocol_i_es.0.iter().find_map(|e| match &e.value {
                g::Error_IndicationProtocolIEs_EntryValue::Id_Cause(c) => Some(c.0),
                _ => None,
            });
            log::warn!("SBc-AP ERROR INDICATION from the CBC: cause {cause:?}");
            Vec::new()
        }
        _ => {
            log::warn!(
                "SBc-AP: procedure {} is the MME's to send, not the CBC's",
                msg.procedure_code.0
            );
            encoded(&error_indication(
                SbcCause::MessageNotCompatibleWithReceiverState,
                Some(msg.procedure_code.0),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextgcore_s1ap::S1apMessage;

    /// The PLMN of the test eNBs (MCC 001, MNC 01), as encoded on the wire.
    const PLMN: [u8; 3] = [0x00, 0xf1, 0x10];

    fn ctx_with_enbs(ids: &[u32]) -> (MmeContext, Vec<u64>) {
        let ctx = MmeContext::new();
        ctx.init();
        let pools = ids
            .iter()
            .enumerate()
            .map(|(n, id)| {
                let pool = ctx.enb_add(format!("127.0.0.{}:36412", n + 1).parse().unwrap());
                ctx.enb_set_s1_connected_for_test(pool, &PLMN, nextgcore_s1ap::EnbId::Macro(*id));
                if let Some(enb) = ctx.enb_pool.write().unwrap().get_mut(&pool) {
                    enb.supported_ta_list = vec![tai(1)];
                }
                pool
            })
            .collect();
        (ctx, pools)
    }

    fn tai(tac: u16) -> EpsTai {
        EpsTai {
            plmn_id: crate::s1ap_build::decode_plmn_id(&PLMN),
            tac,
        }
    }

    fn wire_tai(tac: u16) -> g::TAI {
        to_tai(&tai(tac))
    }

    fn macro_enb(id: u32) -> g::Global_ENB_ID {
        let mut b =
            bitvec::vec::BitVec::<u8, bitvec::order::Msb0>::from_slice(&(id << 12).to_be_bytes());
        b.truncate(20);
        g::Global_ENB_ID {
            plm_nidentity: g::TBCD_STRING(PLMN.to_vec()),
            enb_id: g::ENB_ID::MacroENB_ID(g::ENB_ID_macroENB_ID(b)),
            ie_extensions: None,
        }
    }

    type WrIe = g::Write_Replace_Warning_RequestProtocolIEs_EntryValue;

    fn wrwr(ies: Vec<(u16, WrIe)>) -> Vec<u8> {
        let entries = ies
            .into_iter()
            .map(
                |(id, value)| g::Write_Replace_Warning_RequestProtocolIEs_Entry {
                    id: g::ProtocolIE_ID(id),
                    criticality: g::Criticality(g::Criticality::REJECT),
                    value,
                },
            )
            .collect();
        nextgcore_sbcap_gen::encode(&g::SBC_AP_PDU::InitiatingMessage(g::InitiatingMessage {
            procedure_code: g::ProcedureCode(procedure::WRITE_REPLACE_WARNING),
            criticality: g::Criticality(g::Criticality::REJECT),
            value: g::InitiatingMessageValue::Id_Write_Replace_Warning(
                g::Write_Replace_Warning_Request {
                    protocol_i_es: g::Write_Replace_Warning_RequestProtocolIEs(entries),
                    protocol_extensions: None,
                },
            ),
        }))
        .unwrap()
    }

    /// Message Identifier 0x1112 (CMAS presidential), Serial Number 0x3001,
    /// Repetition Period 10, one broadcast, and `extra`.
    fn wrwr_with(extra: Vec<(u16, WrIe)>, repetition: bool) -> Vec<u8> {
        let mut ies = vec![
            (
                5,
                WrIe::Id_Message_Identifier(g::Message_Identifier(to_bits16(0x1112))),
            ),
            (
                11,
                WrIe::Id_Serial_Number(g::Serial_Number(to_bits16(0x3001))),
            ),
            (
                7,
                WrIe::Id_Number_of_Broadcasts_Requested(g::Number_of_Broadcasts_Requested(1)),
            ),
            (
                16,
                WrIe::Id_Warning_Message_Content(g::Warning_Message_Content(b"test".to_vec())),
            ),
        ];
        if repetition {
            ies.push((10, WrIe::Id_Repetition_Period(g::Repetition_Period(10))));
        }
        ies.extend(extra);
        wrwr(ies)
    }

    /// (procedure code, message id, serial, cause, unknown TAIs) of a response.
    fn response(bytes: &[u8]) -> (u8, u16, u16, u8, usize) {
        let g::SBC_AP_PDU::SuccessfulOutcome(o) = nextgcore_sbcap_gen::decode(bytes).unwrap()
        else {
            panic!("a successful outcome");
        };
        let (mut id, mut serial, mut cause, mut unknown) = (0, 0, 255, 0);
        match o.value {
            g::SuccessfulOutcomeValue::Id_Write_Replace_Warning(r) => {
                use g::Write_Replace_Warning_ResponseProtocolIEs_EntryValue as V;
                for e in r.protocol_i_es.0 {
                    match e.value {
                        V::Id_Message_Identifier(m) => id = bits16(&m.0).unwrap(),
                        V::Id_Serial_Number(s) => serial = bits16(&s.0).unwrap(),
                        V::Id_Cause(c) => cause = c.0,
                        V::Id_Unknown_Tracking_Area_List(l) => unknown = l.0.len(),
                        V::Id_Criticality_Diagnostics(_) => {}
                    }
                }
            }
            g::SuccessfulOutcomeValue::Id_Stop_Warning(r) => {
                use g::Stop_Warning_ResponseProtocolIEs_EntryValue as V;
                for e in r.protocol_i_es.0 {
                    match e.value {
                        V::Id_Message_Identifier(m) => id = bits16(&m.0).unwrap(),
                        V::Id_Serial_Number(s) => serial = bits16(&s.0).unwrap(),
                        V::Id_Cause(c) => cause = c.0,
                        V::Id_Unknown_Tracking_Area_List(l) => unknown = l.0.len(),
                        V::Id_Criticality_Diagnostics(_) => {}
                    }
                }
            }
        }
        (o.procedure_code.0, id, serial, cause, unknown)
    }

    /// (cause, procedure code in the diagnostics) of an ERROR INDICATION.
    fn error(bytes: &[u8]) -> (Option<u8>, Option<u8>) {
        let g::SBC_AP_PDU::InitiatingMessage(m) = nextgcore_sbcap_gen::decode(bytes).unwrap()
        else {
            panic!("an initiating message");
        };
        assert_eq!(m.procedure_code.0, procedure::ERROR_INDICATION);
        let g::InitiatingMessageValue::Id_Error_Indication(ei) = m.value else {
            panic!("an ERROR INDICATION");
        };
        let mut out = (None, None);
        for e in ei.protocol_i_es.0 {
            match e.value {
                g::Error_IndicationProtocolIEs_EntryValue::Id_Cause(c) => out.0 = Some(c.0),
                g::Error_IndicationProtocolIEs_EntryValue::Id_Criticality_Diagnostics(d) => {
                    out.1 = d.procedure_code.map(|p| p.0)
                }
            }
        }
        out
    }

    fn run(ctx: &MmeContext, bytes: &[u8]) -> (Vec<Vec<u8>>, Vec<(u64, Vec<u8>)>) {
        let mut sent = Vec::new();
        let out = handle_sbcap_pdu_with(ctx, bytes, &mut |enb, pdu| {
            sent.push((enb, pdu));
            true
        });
        (out, sent)
    }

    /// TS 29.168 §4.3.3.2: the request reaches the eNB of its TAI, the CBC's
    /// Warning Area List (here one cell) is the eNB's (TS 36.413 §9.2.1.46), and the
    /// response echoes the identifiers with "Message accepted" (0).
    #[test]
    fn a_write_replace_warning_is_forwarded_and_accepted() {
        let (ctx, pools) = ctx_with_enbs(&[0x1234]);
        let mut cell = bitvec::vec::BitVec::<u8, bitvec::order::Msb0>::from_slice(
            &0x0123_4560u32.to_be_bytes(),
        );
        cell.truncate(28);
        let bytes = wrwr_with(
            vec![
                (
                    14,
                    WrIe::Id_List_of_TAIs(g::List_of_TAIs(vec![g::List_of_TAIs_Entry {
                        tai: wire_tai(1),
                    }])),
                ),
                (
                    15,
                    WrIe::Id_Warning_Area_List(g::Warning_Area_List::Cell_ID_List(g::ECGIList(
                        vec![g::EUTRAN_CGI {
                            plm_nidentity: g::TBCD_STRING(PLMN.to_vec()),
                            cell_id: g::CellIdentity(cell),
                            ie_extensions: None,
                        }],
                    ))),
                ),
            ],
            true,
        );
        let (out, sent) = run(&ctx, &bytes);
        assert_eq!(response(&out[0]), (0, 0x1112, 0x3001, 0, 0));
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, pools[0]);
        let S1apMessage::WriteReplaceWarningRequest(req) =
            crate::s1ap_gen::test_codec::decode_s1ap_pdu(&sent[0].1).unwrap()
        else {
            panic!("an S1AP WRITE-REPLACE WARNING REQUEST");
        };
        assert_eq!(
            (req.message_identifier, req.serial_number),
            (0x1112, 0x3001)
        );
        assert_eq!(
            req.warning_area,
            Some(nextgcore_s1ap::WarningAreaList::CellIdList(vec![
                nextgcore_s1ap::EutranCgi {
                    plmn_identity: PLMN,
                    cell_identity: 0x0012_3456,
                }
            ])),
            "the CBC's cell, not the whole tracking area"
        );
    }

    /// TS 29.168 §4.3.3.2 / TS 23.007 §15A.1.2: with a Global eNB ID the request
    /// goes only to that eNB, though both serve the area.
    #[test]
    fn a_global_enb_id_names_the_only_enb_it_goes_to() {
        let (ctx, pools) = ctx_with_enbs(&[0x1234, 0x5678]);
        let bytes = wrwr_with(vec![(28, WrIe::Id_Global_ENB_ID(macro_enb(0x5678)))], true);
        let (out, sent) = run(&ctx, &bytes);
        assert_eq!(response(&out[0]).3, 0);
        assert_eq!(
            sent.iter().map(|s| s.0).collect::<Vec<_>>(),
            vec![pools[1]],
            "only eNB 0x5678"
        );
    }

    /// TS 29.168 §4.3.4.3.6: an unknown TAI is listed with "Message accepted"; all
    /// TAIs unknown is "Tracking area not valid" (4), without the list.
    #[test]
    fn unknown_tracking_areas_are_reported_as_section_4_3_4_3_6_says() {
        let (ctx, _) = ctx_with_enbs(&[0x1234]);
        let list = |tacs: &[u16]| {
            (
                14,
                WrIe::Id_List_of_TAIs(g::List_of_TAIs(
                    tacs.iter()
                        .map(|t| g::List_of_TAIs_Entry { tai: wire_tai(*t) })
                        .collect(),
                )),
            )
        };
        let (out, _) = run(&ctx, &wrwr_with(vec![list(&[1, 9])], true));
        assert_eq!(response(&out[0]).3, 0);
        assert_eq!(response(&out[0]).4, 1, "TAI 9 is unknown");
        let (out, sent) = run(&ctx, &wrwr_with(vec![list(&[9])], true));
        assert_eq!(response(&out[0]).3, 4);
        assert_eq!(response(&out[0]).4, 0);
        assert!(sent.is_empty());
    }

    /// TS 29.168 §4.3.3.3, §4.5.3.3: a missing Repetition Period is answered with
    /// the response and "Missing mandatory element" (6), nothing forwarded; with
    /// no Serial Number no response can be built, so ERROR INDICATION (6) names the
    /// procedure. An undecodable PDU is "Transfer syntax error" (13).
    #[test]
    fn malformed_requests_are_answered_as_section_4_5_says() {
        let (ctx, _) = ctx_with_enbs(&[0x1234]);
        let (out, sent) = run(&ctx, &wrwr_with(vec![], false));
        assert_eq!(response(&out[0]), (0, 0x1112, 0x3001, 6, 0));
        assert!(sent.is_empty());
        let no_serial = wrwr(vec![
            (
                5,
                WrIe::Id_Message_Identifier(g::Message_Identifier(to_bits16(0x1112))),
            ),
            (10, WrIe::Id_Repetition_Period(g::Repetition_Period(10))),
            (
                7,
                WrIe::Id_Number_of_Broadcasts_Requested(g::Number_of_Broadcasts_Requested(1)),
            ),
        ]);
        let (out, _) = run(&ctx, &no_serial);
        assert_eq!(
            error(&out[0]),
            (Some(6), Some(procedure::WRITE_REPLACE_WARNING))
        );
        let (out, _) = run(&ctx, &[0xff, 0x00]);
        assert_eq!(error(&out[0]), (Some(13), None));
    }

    /// TS 29.168 §4.3.4.3.8: Stop-All asks the eNB to kill every warning
    /// (TS 36.413 Kill-all-Warning-Messages); the response accepts.
    #[test]
    fn a_stop_all_warning_kills_everything_at_the_enb() {
        use g::Stop_Warning_RequestProtocolIEs_EntryValue as V;
        let (ctx, _) = ctx_with_enbs(&[0x1234]);
        let entry = |id: u16, value: V| g::Stop_Warning_RequestProtocolIEs_Entry {
            id: g::ProtocolIE_ID(id),
            criticality: g::Criticality(g::Criticality::REJECT),
            value,
        };
        let bytes =
            nextgcore_sbcap_gen::encode(&g::SBC_AP_PDU::InitiatingMessage(g::InitiatingMessage {
                procedure_code: g::ProcedureCode(procedure::STOP_WARNING),
                criticality: g::Criticality(g::Criticality::REJECT),
                value: g::InitiatingMessageValue::Id_Stop_Warning(g::Stop_Warning_Request {
                    protocol_i_es: g::Stop_Warning_RequestProtocolIEs(vec![
                        entry(
                            5,
                            V::Id_Message_Identifier(g::Message_Identifier(to_bits16(0x1112))),
                        ),
                        entry(11, V::Id_Serial_Number(g::Serial_Number(to_bits16(0x3001)))),
                        entry(27, V::Id_Stop_All_Indicator(g::Stop_All_Indicator(0))),
                    ]),
                    protocol_extensions: None,
                }),
            }))
            .unwrap();
        let (out, sent) = run(&ctx, &bytes);
        assert_eq!(response(&out[0]), (1, 0x1112, 0x3001, 0, 0));
        let S1apMessage::KillRequest(kill) =
            crate::s1ap_gen::test_codec::decode_s1ap_pdu(&sent[0].1).unwrap()
        else {
            panic!("an S1AP KILL REQUEST");
        };
        assert!(kill.kill_all_warning_messages);
    }

    /// A PWS RESTART INDICATION is the MME's to send: from a CBC it is answered
    /// with ERROR INDICATION, "Message not compatible with receiver state" (15).
    #[test]
    fn an_indication_from_the_cbc_is_refused() {
        let (ctx, _) = ctx_with_enbs(&[]);
        let pdu = g::SBC_AP_PDU::InitiatingMessage(g::InitiatingMessage {
            procedure_code: g::ProcedureCode(procedure::PWS_FAILURE_INDICATION),
            criticality: g::Criticality(g::Criticality::IGNORE),
            value: g::InitiatingMessageValue::Id_PWS_Failure_Indication(
                g::PWS_Failure_Indication {
                    protocol_i_es: g::PWS_Failure_IndicationProtocolIEs(vec![
                        g::PWS_Failure_IndicationProtocolIEs_Entry {
                            id: g::ProtocolIE_ID(28),
                            criticality: g::Criticality(g::Criticality::REJECT),
                            value:
                                g::PWS_Failure_IndicationProtocolIEs_EntryValue::Id_Global_ENB_ID(
                                    macro_enb(1),
                                ),
                        },
                    ]),
                    protocol_extensions: None,
                },
            ),
        });
        let (out, _) = run(&ctx, &nextgcore_sbcap_gen::encode(&pdu).unwrap());
        assert_eq!(
            error(&out[0]),
            (Some(15), Some(procedure::PWS_FAILURE_INDICATION))
        );
    }
}
