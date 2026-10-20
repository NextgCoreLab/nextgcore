//! NRPPa from NG-RAN to this LMF: the E-CID Measurement Report, decoded with the
//! generated `nextgcore-nrppa-gen` codec (#515 stage 3), and the ERROR INDICATION
//! TS 38.455 §10 has the LMF answer an erroneous one with.
//!
//! # Error handling
//!
//! TS 38.455 §10 applies TS 38.413 §10, adding that the NRPPa Transaction ID goes
//! into the Criticality Diagnostics. E-CID Measurement Report is a Class 2
//! procedure (no response message), so per TS 38.413 §10.3.4.2 / §10.3.5:
//!
//! - an unknown IE with criticality **ignore** is dropped;
//! - **ignore and notify**: the report is processed, and the IE is reported in an
//!   ERROR INDICATION;
//! - **reject**, or a missing mandatory IE whose criticality is reject (both UE
//!   measurement ids): the report is not processed, and the IEs are reported in an
//!   ERROR INDICATION with cause protocol / abstract-syntax-error-reject;
//! - a missing E-CID-MeasurementResult (mandatory, criticality ignore) is ignored:
//!   the report is processed and contributes no measurement.

use crate::CellMeasurement;
use nextgcore_nrppa_gen::generated as nrppa;
use nextgcore_nrppa_gen::UnknownIe;

const REJECT: u8 = 0;
const IGNORE: u8 = 1;
const NOTIFY: u8 = 2;

/// What an uplink E-CID Measurement Report amounts to once TS 38.413 §10 is applied.
#[derive(Debug, Clone)]
pub enum EcidReportOutcome {
    /// The report is processed. `error_indication` carries the ERROR INDICATION
    /// to send back when an IE was marked ignore-and-notify.
    Accepted {
        lmf_measurement_id: u64,
        cells: Vec<CellMeasurement>,
        error_indication: Option<Vec<u8>>,
    },
    /// The report is not processed; `error_indication` is the ERROR INDICATION
    /// TS 38.413 §10.3.4.2 requires in reply.
    Rejected {
        error_indication: Vec<u8>,
        reason: String,
    },
}

/// One IE named in Criticality Diagnostics.
struct Diag {
    criticality: u8,
    id: u16,
    missing: bool,
}

/// Decode an NRPPa PDU as an E-CID Measurement Report and apply TS 38.413 §10.
///
/// `Err` means the octets are not an E-CID Measurement Report at all (undecodable,
/// or another procedure); there is then no report to answer.
pub fn decode_ecid_report(bytes: &[u8]) -> Result<EcidReportOutcome, String> {
    let (pdu, unknown) = nextgcore_nrppa_gen::decode_with_unknown_ies(bytes)
        .map_err(|e| format!("NRPPa APER decode: {e:?}"))?;
    let nrppa::NRPPA_PDU::InitiatingMessage(msg) = pdu else {
        return Err("PDU is not an E-CID measurement report".to_string());
    };
    let nrppa::InitiatingMessageValue::Id_e_CIDMeasurementReport(report) = msg.value else {
        return Err("PDU is not an E-CID measurement report".to_string());
    };
    let txn = msg.nrppatransaction_id.0;

    let mut lmf_id = None;
    let mut ran_id = None;
    let mut result = None;
    for ie in report.protocol_i_es.0 {
        use nrppa::E_CIDMeasurementReportProtocolIEs_EntryValue as V;
        match ie.value {
            V::Id_LMF_UE_Measurement_ID(id) => lmf_id = Some(id.0),
            V::Id_RAN_UE_Measurement_ID(id) => ran_id = Some(id.0),
            V::Id_E_CID_MeasurementResult(r) => result = Some(r),
            V::Id_Cell_Portion_ID(_) => {}
        }
    }

    let mut rejected: Vec<Diag> = Vec::new();
    let mut notified: Vec<Diag> = Vec::new();
    for UnknownIe {
        id, criticality, ..
    } in &unknown
    {
        let id = u16::try_from(*id).unwrap_or(u16::MAX);
        match criticality {
            Some(IGNORE) => {}
            Some(NOTIFY) => notified.push(Diag {
                criticality: NOTIFY,
                id,
                missing: false,
            }),
            // reject, or no criticality at all (every NRPPa IE container carries
            // one, so its absence is itself an abstract syntax error)
            _ => rejected.push(Diag {
                criticality: REJECT,
                id,
                missing: false,
            }),
        }
    }
    if lmf_id.is_none() {
        rejected.push(Diag {
            criticality: REJECT,
            id: nrppa::ID_LMF_UE_MEASUREMENT_ID,
            missing: true,
        });
    }
    if ran_id.is_none() {
        rejected.push(Diag {
            criticality: REJECT,
            id: nrppa::ID_RAN_UE_MEASUREMENT_ID,
            missing: true,
        });
    }

    if !rejected.is_empty() {
        let ids: Vec<String> = rejected.iter().map(|d| d.id.to_string()).collect();
        return Ok(EcidReportOutcome::Rejected {
            error_indication: build_error_indication(
                txn,
                nrppa::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT,
                &rejected,
            )?,
            reason: format!(
                "E-CID Measurement Report rejected (TS 38.413 §10.3.4.2): IE(s) {} unknown with \
                 criticality reject or missing",
                ids.join(", ")
            ),
        });
    }

    let error_indication = if notified.is_empty() {
        None
    } else {
        Some(build_error_indication(
            txn,
            nrppa::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
            &notified,
        )?)
    };
    Ok(EcidReportOutcome::Accepted {
        lmf_measurement_id: u64::from(lmf_id.unwrap_or_default()),
        cells: result.map(|r| vec![to_cell(&r)]).unwrap_or_default(),
        error_indication,
    })
}

/// The same `CellMeasurement` the pre-#515 adapter produced from a decoded result.
fn to_cell(result: &nrppa::E_CID_MeasurementResult) -> CellMeasurement {
    let mut rsrp: Option<i16> = None;
    let mut rsrq: Option<i16> = None;
    let mut timing_advance: Option<u32> = None;
    let mut aoa: Option<f64> = None;
    if let Some(measured) = &result.measured_results {
        for value in &measured.0 {
            use nrppa::MeasuredResultsValue as M;
            match value {
                M::ValueAngleOfArrival_EUTRA(deg) => {
                    aoa.get_or_insert(f64::from(deg.0));
                }
                M::ValueTimingAdvanceType1_EUTRA(ta) => {
                    timing_advance.get_or_insert(u32::from(ta.0));
                }
                M::ValueTimingAdvanceType2_EUTRA(ta) => {
                    timing_advance.get_or_insert(u32::from(ta.0));
                }
                M::ResultRSRP_EUTRA(items) => {
                    // value_rsrp_eutra 0..97 -> -140..-43 dBm; the strongest item wins.
                    if let Some(best) = items.0.iter().map(|i| i.value_rsrp_eutra.0).max() {
                        let dbm = i16::from(best) - 140;
                        rsrp = Some(rsrp.map_or(dbm, |cur: i16| cur.max(dbm)));
                    }
                }
                M::ResultRSRQ_EUTRA(items) => {
                    // raw 0..34 index; the strongest item of the first list wins.
                    if let Some(best) = items.0.iter().map(|i| i.value_rsrq_eutra.0).max() {
                        rsrq.get_or_insert(i16::from(best));
                    }
                }
                // NR measurement extensions (AoA-NR etc.) carry no field the
                // E-CID solver reads; the pre-#515 decoder refused the whole
                // report on them.
                M::Choice_Extension(_) => {}
            }
        }
    }
    CellMeasurement {
        nr_cgi: cgi_to_string(&result.serving_cell_id),
        rsrp,
        rsrq,
        timing_advance,
        aoa,
        rtt_ns: None,
        rstd_ns: None,
    }
}

/// `<plmn hex>-<9 hex digits>` for an NR cell, `<plmn hex>-e<7 hex digits>` for
/// an E-UTRA one -- the spelling the cell registry is keyed by.
fn cgi_to_string(cgi: &nrppa::NG_RAN_CGI) -> String {
    let plmn: String = cgi
        .plmn_identity
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let bits = |v: &bitvec::vec::BitVec<u8, bitvec::order::Msb0>| {
        v.iter().fold(0u64, |acc, b| (acc << 1) | u64::from(*b))
    };
    match &cgi.ng_ra_ncell {
        nrppa::NG_RANCell::NR_CellID(id) => format!("{plmn}-{:09x}", bits(&id.0)),
        nrppa::NG_RANCell::EUTRA_CellID(id) => format!("{plmn}-e{:07x}", bits(&id.0)),
        nrppa::NG_RANCell::Choice_Extension(_) => format!("{plmn}-unknown"),
    }
}

/// An NRPPa ERROR INDICATION (TS 38.455 §8.3.1, procedure 0, criticality ignore)
/// reporting `diags` for the E-CID Measurement Report with transaction `txn`.
fn build_error_indication(txn: u16, cause: u8, diags: &[Diag]) -> Result<Vec<u8>, String> {
    use nrppa::ErrorIndicationProtocolIEs_EntryValue as V;
    let list = diags
        .iter()
        .take(256) // maxNrOfErrors
        .map(|d| nrppa::CriticalityDiagnostics_IE_List_Entry {
            ie_criticality: nrppa::Criticality(d.criticality),
            ie_id: nrppa::ProtocolIE_ID(d.id),
            type_of_error: nrppa::TypeOfError(if d.missing {
                nrppa::TypeOfError::MISSING
            } else {
                nrppa::TypeOfError::NOT_UNDERSTOOD
            }),
            ie_extensions: None,
        })
        .collect();
    let diagnostics = nrppa::CriticalityDiagnostics {
        procedure_code: Some(nrppa::ProcedureCode(nrppa::ID_E_CID_MEASUREMENT_REPORT)),
        triggering_message: Some(nrppa::TriggeringMessage(
            nrppa::TriggeringMessage::INITIATING_MESSAGE,
        )),
        procedure_criticality: Some(nrppa::Criticality(IGNORE)),
        // TS 38.455 §10: an NRPPa Criticality Diagnostics also names the transaction.
        nrppatransaction_id: Some(nrppa::NRPPATransactionID(txn)),
        i_es_criticality_diagnostics: Some(nrppa::CriticalityDiagnostics_IE_List(list)),
        ie_extensions: None,
    };
    let ies = vec![
        nrppa::ErrorIndicationProtocolIEs_Entry {
            id: nrppa::ProtocolIE_ID(nrppa::ID_CAUSE),
            criticality: nrppa::Criticality(IGNORE),
            value: V::Id_Cause(nrppa::Cause::Protocol(nrppa::CauseProtocol(cause))),
        },
        nrppa::ErrorIndicationProtocolIEs_Entry {
            id: nrppa::ProtocolIE_ID(nrppa::ID_CRITICALITY_DIAGNOSTICS),
            criticality: nrppa::Criticality(IGNORE),
            value: V::Id_CriticalityDiagnostics(diagnostics),
        },
    ];
    let pdu = nrppa::NRPPA_PDU::InitiatingMessage(nrppa::InitiatingMessage {
        procedure_code: nrppa::ProcedureCode(nrppa::ID_ERROR_INDICATION),
        criticality: nrppa::Criticality(IGNORE),
        nrppatransaction_id: nrppa::NRPPATransactionID(txn),
        value: nrppa::InitiatingMessageValue::Id_errorIndication(nrppa::ErrorIndication {
            protocol_i_es: nrppa::ErrorIndicationProtocolIEs(ies),
        }),
    });
    nextgcore_nrppa_gen::encode(&pdu).map_err(|e| format!("NRPPa ERROR INDICATION encode: {e:?}"))
}

#[cfg(test)]
mod tests;
