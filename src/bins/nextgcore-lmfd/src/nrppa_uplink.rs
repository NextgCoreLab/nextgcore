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
    let mut lmf_id = None;
    let mut ran_id = None;
    let mut result = None;
    // The two PDUs that carry E-CID results (#834 review). TS 38.455 §8.2.1.2: an
    // ON DEMAND request -- the only kind this LMF sends -- is answered in the
    // E-CID MEASUREMENT INITIATION RESPONSE, so that is where a gNB puts the
    // results. Only a PERIODIC one is followed by E-CID MEASUREMENT REPORTs
    // (§8.2.3). Decoding the report alone meant a real gNB's answer was never
    // read.
    let (txn, procedure, triggering) = match pdu {
        nrppa::NRPPA_PDU::InitiatingMessage(nrppa::InitiatingMessage {
            nrppatransaction_id,
            value: nrppa::InitiatingMessageValue::Id_e_CIDMeasurementReport(report),
            ..
        }) => {
            for ie in report.protocol_i_es.0 {
                use nrppa::E_CIDMeasurementReportProtocolIEs_EntryValue as V;
                match ie.value {
                    V::Id_LMF_UE_Measurement_ID(id) => lmf_id = Some(id.0),
                    V::Id_RAN_UE_Measurement_ID(id) => ran_id = Some(id.0),
                    V::Id_E_CID_MeasurementResult(r) => result = Some(r),
                    V::Id_Cell_Portion_ID(_) => {}
                }
            }
            (
                nrppatransaction_id.0,
                nrppa::ID_E_CID_MEASUREMENT_REPORT,
                nrppa::TriggeringMessage::INITIATING_MESSAGE,
            )
        }
        nrppa::NRPPA_PDU::SuccessfulOutcome(nrppa::SuccessfulOutcome {
            nrppatransaction_id,
            value: nrppa::SuccessfulOutcomeValue::Id_e_CIDMeasurementInitiation(response),
            ..
        }) => {
            for ie in response.protocol_i_es.0 {
                use nrppa::E_CIDMeasurementInitiationResponseProtocolIEs_EntryValue as V;
                match ie.value {
                    V::Id_LMF_UE_Measurement_ID(id) => lmf_id = Some(id.0),
                    V::Id_RAN_UE_Measurement_ID(id) => ran_id = Some(id.0),
                    V::Id_E_CID_MeasurementResult(r) => result = Some(r),
                    _ => {}
                }
            }
            (
                nrppatransaction_id.0,
                nrppa::ID_E_CID_MEASUREMENT_INITIATION,
                nrppa::TriggeringMessage::SUCCESSFUL_OUTCOME,
            )
        }
        _ => {
            return Err("PDU is not an E-CID measurement report or initiation response".to_string())
        }
    };

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
                procedure,
                triggering,
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
            procedure,
            triggering,
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
/// An E-UTRA TADV report value as a round trip in ns (bin midpoint), or `None`
/// for the open-ended last value (TS 36.133 §10.3.1, #832).
fn tadv_ns(v: u16) -> Option<(f64, f64)> {
    crate::positioning::eutra_time_report_to_ns(u32::from(v), crate::positioning::EUTRA_TADV_MAX)
}

/// One NR cell of a Result SS-RSRP / SS-RSRQ / CSI-RSRP / CSI-RSRQ list (TS 38.455
/// §9.2.5): its PCI, NR-ARFCN, NR CGI when given (spelled as the serving cell's
/// `nr_cgi`), and cell-level report value (0..127), when given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrCellResult {
    pub pci: u16,
    pub arfcn: u32,
    pub cgi: Option<String>,
    pub value: Option<u8>,
}

/// The NR E-CID quantities a gNB reports in the Measured Results extension IEs (TS
/// 38.455 §9.2.5, Rel-16/17 `MeasuredResultsValue` choice-Extension), held as the
/// report values they are on the wire (#859).
///
/// The report mappings that turn them into physical quantities (#859, now that TS
/// 38.133 and TS 38.215 are vendored):
/// - Value Timing Advance NR: TS 38.133 §13.5.1, a round trip
///   ([`crate::positioning::nr_tadv_report_to_ns`]). It is the timing term of an
///   NR E-CID fix.
/// - SS/CSI-RSRP: TS 38.133 §10.1.6.1, and SS/CSI-RSRQ: §10.1.11.1. The serving
///   cell's value ranks the cell as the other adapters do.
/// - AoA NR: TS 38.133 §13.4.1, read when it is given in the GCS.
/// - UE Rx-Tx Time Difference: TS 38.133 §10.1.25.3.1, k = 5
///   ([`Self::ue_rx_tx_ns`]). It is the UE half of an RTT only (TS 38.215
///   §5.1.30): an E-CID report carries no gNB Rx–Tx to pair it with, so it does
///   not range anything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NrEcidReport {
    /// Value Timing Advance NR, `NR-TADV ::= INTEGER (0..7690)` (id 94).
    pub nr_tadv: Option<u16>,
    /// Value UE Rx-Tx Time Difference, `INTEGER (0..61565)` (id 118).
    pub ue_rx_tx_time_diff: Option<u16>,
    /// Result SS-RSRP (id 32), cell level.
    pub ss_rsrp: Vec<NrCellResult>,
    /// Result SS-RSRQ (id 33), cell level.
    pub ss_rsrq: Vec<NrCellResult>,
    /// Result CSI-RSRP (id 34), cell level.
    pub csi_rsrp: Vec<NrCellResult>,
    /// Result CSI-RSRQ (id 35), cell level.
    pub csi_rsrq: Vec<NrCellResult>,
    /// Angle of Arrival NR (id 36, UL AoA §9.2.38): azimuth 0..3599, zenith 0..1799.
    pub aoa_nr: Option<(u16, Option<u16>)>,
    /// `aoa_nr` came with an LCS to GCS Translation, so its angles are in the
    /// antenna's local coordinate system (TS 38.455 §9.2.38), not bearings.
    pub aoa_nr_lcs: bool,
}

/// TS 38.133 Table 10.1.6.1-1: RSRP_127 is "Infinity", a threshold value, not a
/// measurement report.
const NR_RSRP_NOT_A_REPORT: u8 = 127;

/// The serving cell's report value in an NR Result list (TS 38.455 §9.2.5): the
/// item whose NR CGI is `serving`; else, among the items that name no cell, the
/// strongest, since the list does not otherwise mark the serving cell. An item
/// that names another cell is a neighbour and never stands in for it. Values
/// above `max` are not measurements.
fn serving_value(list: &[NrCellResult], serving: &str, max: u8) -> Option<u8> {
    let valid = |r: &&NrCellResult| r.value.is_some_and(|v| v <= max);
    list.iter()
        .filter(valid)
        .find(|r| r.cgi.as_deref() == Some(serving))
        .or_else(|| {
            list.iter()
                .filter(valid)
                .filter(|r| r.cgi.is_none())
                .max_by_key(|r| r.value)
        })
        .and_then(|r| r.value)
}

impl NrEcidReport {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The NR-TADV round trip, (midpoint, width) in ns (TS 38.133 §13.5.1).
    pub fn rtt_ns(&self) -> Option<(f64, f64)> {
        self.nr_tadv
            .and_then(crate::positioning::nr_tadv_report_to_ns)
    }

    /// The UE Rx–Tx Time Difference in signed ns, the bin midpoint (TS 38.133
    /// §10.1.25.3.1, k = 5). `None` when not reported or open-ended.
    pub fn ue_rx_tx_ns(&self) -> Option<f64> {
        self.ue_rx_tx_time_diff
            .and_then(crate::positioning::nr_ue_rx_tx_k5_report_to_ns)
            .map(|(mid, _)| mid)
    }

    /// The serving cell's SS-RSRP, else its CSI-RSRP, in dBm as the LPP NR adapter
    /// spells it (TS 38.133 §10.1.6.1, [`crate::codec_glue::nr_rsrp_dbm`]).
    fn serving_rsrp_dbm(&self, serving: &str) -> Option<i16> {
        serving_value(&self.ss_rsrp, serving, NR_RSRP_NOT_A_REPORT - 1)
            .or_else(|| serving_value(&self.csi_rsrp, serving, NR_RSRP_NOT_A_REPORT - 1))
            .map(crate::codec_glue::nr_rsrp_dbm)
    }

    /// The serving cell's SS-RSRQ, else its CSI-RSRQ, as the raw index 0..127 of
    /// TS 38.133 §10.1.11.1 (the LPP NR adapter's spelling).
    fn serving_rsrq(&self, serving: &str) -> Option<i16> {
        serving_value(&self.ss_rsrq, serving, u8::MAX)
            .or_else(|| serving_value(&self.csi_rsrq, serving, u8::MAX))
            .map(i16::from)
    }

    /// The AoA NR azimuth as a clockwise bearing from North (TS 38.133 §13.4.1,
    /// TS 38.215 §5.2.4). `None` when it is in an LCS: turning that into a bearing
    /// needs the antenna orientation of TS 38.901 §7.1, which is not applied.
    fn bearing_deg(&self) -> Option<f64> {
        if self.aoa_nr_lcs {
            return None;
        }
        self.aoa_nr
            .and_then(|(azimuth, _)| crate::positioning::nr_azimuth_aoa_to_bearing_deg(azimuth))
    }

    /// Take one Measured Results extension. As for the E-UTRA arms, the first value
    /// of a quantity wins; the lists are kept as reported.
    fn note(&mut self, value: &nrppa::MeasuredResultsValue_choice_ExtensionValue) {
        use nrppa::MeasuredResultsValue_choice_ExtensionValue as X;
        match value {
            X::Id_NR_TADV(v) => {
                self.nr_tadv.get_or_insert(v.0);
            }
            X::Id_UE_Rx_Tx_Time_Diff(v) => {
                self.ue_rx_tx_time_diff.get_or_insert(v.0);
            }
            X::Id_ResultSS_RSRP(l) if self.ss_rsrp.is_empty() => {
                self.ss_rsrp =
                    l.0.iter()
                        .map(|i| NrCellResult {
                            pci: i.nr_pci.0,
                            arfcn: i.nr_arfcn.0,
                            cgi: i
                                .cgi_nr
                                .as_ref()
                                .map(crate::nrppa_positioning::cgi_nr_to_string),
                            value: i.value_ss_rsrp_cell.as_ref().map(|v| v.0),
                        })
                        .collect();
            }
            X::Id_ResultSS_RSRQ(l) if self.ss_rsrq.is_empty() => {
                self.ss_rsrq =
                    l.0.iter()
                        .map(|i| NrCellResult {
                            pci: i.nr_pci.0,
                            arfcn: i.nr_arfcn.0,
                            cgi: i
                                .cgi_nr
                                .as_ref()
                                .map(crate::nrppa_positioning::cgi_nr_to_string),
                            value: i.value_ss_rsrq_cell.as_ref().map(|v| v.0),
                        })
                        .collect();
            }
            X::Id_ResultCSI_RSRP(l) if self.csi_rsrp.is_empty() => {
                self.csi_rsrp =
                    l.0.iter()
                        .map(|i| NrCellResult {
                            pci: i.nr_pci.0,
                            arfcn: i.nr_arfcn.0,
                            cgi: i
                                .cgi_nr
                                .as_ref()
                                .map(crate::nrppa_positioning::cgi_nr_to_string),
                            value: i.value_csi_rsrp_cell.as_ref().map(|v| v.0),
                        })
                        .collect();
            }
            X::Id_ResultCSI_RSRQ(l) if self.csi_rsrq.is_empty() => {
                self.csi_rsrq =
                    l.0.iter()
                        .map(|i| NrCellResult {
                            pci: i.nr_pci.0,
                            arfcn: i.nr_arfcn.0,
                            cgi: i
                                .cgi_nr
                                .as_ref()
                                .map(crate::nrppa_positioning::cgi_nr_to_string),
                            value: i.value_csi_rsrq_cell.as_ref().map(|v| v.0),
                        })
                        .collect();
            }
            X::Id_AngleOfArrivalNR(a) if self.aoa_nr.is_none() => {
                self.aoa_nr = Some((a.azimuth_ao_a.0, a.zenith_ao_a.as_ref().map(|z| z.0)));
                self.aoa_nr_lcs = a.lcs_to_gcs_translation.is_some();
            }
            // Repeated lists after the first, and the per-TRP AoA (id 167), which
            // names TRPs rather than the serving cell.
            _ => {}
        }
    }
}

fn to_cell(result: &nrppa::E_CID_MeasurementResult) -> CellMeasurement {
    let mut nr = NrEcidReport::default();
    let mut rsrp: Option<i16> = None;
    let mut rsrq: Option<i16> = None;
    let mut tadv1: Option<(f64, f64)> = None;
    let mut tadv2: Option<(f64, f64)> = None;
    let mut aoa: Option<f64> = None;
    if let Some(measured) = &result.measured_results {
        for value in &measured.0 {
            use nrppa::MeasuredResultsValue as M;
            match value {
                M::ValueAngleOfArrival_EUTRA(deg) => {
                    aoa.get_or_insert(f64::from(deg.0));
                }
                // TS 36.133 §10.3.1: TADV Type 1 (eNB Rx–Tx + UE Rx–Tx) and
                // Type 2 (eNB Rx–Tx with the UE's TA applied) are both the round
                // trip, in T_s bins (#832). The open-ended last value is dropped.
                M::ValueTimingAdvanceType1_EUTRA(ta) => {
                    tadv1 = tadv1.or_else(|| tadv_ns(ta.0));
                }
                M::ValueTimingAdvanceType2_EUTRA(ta) => {
                    tadv2 = tadv2.or_else(|| tadv_ns(ta.0));
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
                // #859: the NR quantities (see `NrEcidReport`). The pre-#515
                // decoder refused the whole report on them.
                M::Choice_Extension(ext) => nr.note(&ext.value),
            }
        }
    }
    // #865 review: Type 1 (eNB Rx–Tx + UE Rx–Tx, both measured) is the more
    // accurate (TS 36.305 §8.3), so it is used whenever it is present, whatever
    // the order of the IEs.
    let eutra_tadv = tadv1.or(tadv2);
    let nr_cgi = cgi_to_string(&result.serving_cell_id);
    let eutra = matches!(
        result.serving_cell_id.ng_ra_ncell,
        nrppa::NG_RANCell::EUTRA_CellID(_)
    );
    // #859: a quantity of the serving cell's own RAT comes first, and the other
    // RAT's stands in only when it is absent. A gNB on NR gives its timing term as
    // NR-TADV (TS 38.455 §9.2.5, mapping TS 38.133 §13.5.1), an ng-eNB as TADV
    // Type 1/2.
    let (tadv, rsrp, rsrq, aoa) = if eutra {
        (
            eutra_tadv.or_else(|| nr.rtt_ns()),
            rsrp.or_else(|| nr.serving_rsrp_dbm(&nr_cgi)),
            rsrq.or_else(|| nr.serving_rsrq(&nr_cgi)),
            aoa.or_else(|| nr.bearing_deg()),
        )
    } else {
        (
            nr.rtt_ns().or(eutra_tadv),
            nr.serving_rsrp_dbm(&nr_cgi).or(rsrp),
            nr.serving_rsrq(&nr_cgi).or(rsrq),
            nr.bearing_deg().or(aoa),
        )
    };
    CellMeasurement {
        nr_cgi,
        rsrp,
        rsrq,
        timing_advance: None,
        aoa,
        rtt_ns: None,
        rstd_ns: None,
        // The NR UE Rx–Tx stays in `nr_ecid`: with no gNB Rx–Tx in an E-CID
        // report it is not a Multi-RTT half this LMF could pair (TS 38.215
        // §5.1.30, #713).
        ue_rx_tx_ns: None,
        rstd_reference: None,
        ecid_rtt_ns: tadv.map(|(mid, _)| mid),
        ecid_rtt_width_ns: tadv.map(|(_, width)| width),
        gnb_rx_tx_ns: None,
        meas_time: None,
        dl_prs_id: None,
        eutra,
        nr_ecid: (!nr.is_empty()).then_some(nr),
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
fn build_error_indication(
    txn: u16,
    procedure: u8,
    triggering: u8,
    cause: u8,
    diags: &[Diag],
) -> Result<Vec<u8>, String> {
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
        procedure_code: Some(nrppa::ProcedureCode(procedure)),
        triggering_message: Some(nrppa::TriggeringMessage(triggering)),
        // E-CID Measurement Report is class 2 (ignore), E-CID Measurement
        // Initiation class 1 (reject).
        procedure_criticality: Some(nrppa::Criticality(
            if procedure == nrppa::ID_E_CID_MEASUREMENT_INITIATION {
                REJECT
            } else {
                IGNORE
            },
        )),
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

/// Test builders on the generated codec, the reference now that the hand-written
/// NRPPa codec is gone (#515): E-CID Measurement Reports, and splicing an IE into
/// (or out of) one, which the generated encoder cannot do for an unknown id.
#[cfg(test)]
pub mod test_support {
    use super::nrppa;
    use bitvec::prelude::*;

    pub fn nr_cgi(plmn: [u8; 3], cell: u64) -> nrppa::NG_RAN_CGI {
        let mut bits: BitVec<u8, Msb0> = BitVec::new();
        for i in (0..36).rev() {
            bits.push((cell >> i) & 1 == 1);
        }
        nrppa::NG_RAN_CGI {
            plmn_identity: nrppa::PLMN_Identity(plmn.to_vec()),
            ng_ra_ncell: nrppa::NG_RANCell::NR_CellID(nrppa::NRCellIdentifier(bits)),
            ie_extensions: None,
        }
    }

    pub fn eutra_cgi(plmn: [u8; 3], cell: u32) -> nrppa::NG_RAN_CGI {
        let mut bits: BitVec<u8, Msb0> = BitVec::new();
        for i in (0..28).rev() {
            bits.push((cell >> i) & 1 == 1);
        }
        nrppa::NG_RAN_CGI {
            plmn_identity: nrppa::PLMN_Identity(plmn.to_vec()),
            ng_ra_ncell: nrppa::NG_RANCell::EUTRA_CellID(nrppa::EUTRACellIdentifier(bits)),
            ie_extensions: None,
        }
    }

    pub fn rsrp(values: &[u8]) -> nrppa::MeasuredResultsValue {
        nrppa::MeasuredResultsValue::ResultRSRP_EUTRA(nrppa::ResultRSRP_EUTRA(
            values
                .iter()
                .map(|v| nrppa::ResultRSRP_EUTRA_Item {
                    pci_eutra: nrppa::PCI_EUTRA(42),
                    earfcn: nrppa::EARFCN(1850),
                    cgi_eutra: None,
                    value_rsrp_eutra: nrppa::ValueRSRP_EUTRA(*v),
                    ie_extensions: None,
                })
                .collect(),
        ))
    }

    pub fn rsrq(values: &[u8]) -> nrppa::MeasuredResultsValue {
        nrppa::MeasuredResultsValue::ResultRSRQ_EUTRA(nrppa::ResultRSRQ_EUTRA(
            values
                .iter()
                .map(|v| nrppa::ResultRSRQ_EUTRA_Item {
                    pci_eutra: nrppa::PCI_EUTRA(42),
                    earfcn: nrppa::EARFCN(1850),
                    cgi_utra: None,
                    value_rsrq_eutra: nrppa::ValueRSRQ_EUTRA(*v),
                    ie_extensions: None,
                })
                .collect(),
        ))
    }

    pub fn ta1(v: u16) -> nrppa::MeasuredResultsValue {
        nrppa::MeasuredResultsValue::ValueTimingAdvanceType1_EUTRA(
            nrppa::MeasuredResultsValue_valueTimingAdvanceType1_EUTRA(v),
        )
    }

    pub fn ta2(v: u16) -> nrppa::MeasuredResultsValue {
        nrppa::MeasuredResultsValue::ValueTimingAdvanceType2_EUTRA(
            nrppa::MeasuredResultsValue_valueTimingAdvanceType2_EUTRA(v),
        )
    }

    pub fn aoa(v: u16) -> nrppa::MeasuredResultsValue {
        nrppa::MeasuredResultsValue::ValueAngleOfArrival_EUTRA(
            nrppa::MeasuredResultsValue_valueAngleOfArrival_EUTRA(v),
        )
    }

    /// A Measured Results extension IE (TS 38.455 §9.2.5), criticality ignore as the
    /// ASN.1 object set has it.
    pub fn nr_ext(
        id: u16,
        value: nrppa::MeasuredResultsValue_choice_ExtensionValue,
    ) -> nrppa::MeasuredResultsValue {
        nrppa::MeasuredResultsValue::Choice_Extension(
            nrppa::MeasuredResultsValue_choice_Extension {
                id: nrppa::ProtocolIE_ID(id),
                criticality: nrppa::Criticality(super::IGNORE),
                value,
            },
        )
    }

    pub fn nr_tadv(v: u16) -> nrppa::MeasuredResultsValue {
        nr_ext(
            94,
            nrppa::MeasuredResultsValue_choice_ExtensionValue::Id_NR_TADV(nrppa::NR_TADV(v)),
        )
    }

    pub fn ue_rx_tx(v: u16) -> nrppa::MeasuredResultsValue {
        nr_ext(
            118,
            nrppa::MeasuredResultsValue_choice_ExtensionValue::Id_UE_Rx_Tx_Time_Diff(
                nrppa::UE_Rx_Tx_Time_Diff(v),
            ),
        )
    }

    /// Result SS-RSRP with one item per `(pci, arfcn, cell value)`.
    pub fn ss_rsrp(items: &[(u16, u32, Option<u8>)]) -> nrppa::MeasuredResultsValue {
        let items: Vec<_> = items.iter().map(|(p, a, v)| (*p, *a, None, *v)).collect();
        ss_rsrp_named(&items)
    }

    /// Result SS-RSRP with one item per `(pci, arfcn, NR cell identity in PLMN
    /// 02 f8 39, cell value)`.
    pub fn ss_rsrp_named(
        items: &[(u16, u32, Option<u64>, Option<u8>)],
    ) -> nrppa::MeasuredResultsValue {
        nr_ext(
            32,
            nrppa::MeasuredResultsValue_choice_ExtensionValue::Id_ResultSS_RSRP(
                nrppa::ResultSS_RSRP(
                    items
                        .iter()
                        .map(|(pci, arfcn, cell, v)| nrppa::ResultSS_RSRP_Item {
                            nr_pci: nrppa::NR_PCI(*pci),
                            nr_arfcn: nrppa::NR_ARFCN(*arfcn),
                            cgi_nr: cell.map(|c| {
                                crate::nrppa_positioning::test_support::cgi_nr(
                                    [0x02, 0xf8, 0x39],
                                    c,
                                )
                            }),
                            value_ss_rsrp_cell: v.map(nrppa::ValueRSRP_NR),
                            ss_rsrp_per_ssb: None,
                            ie_extensions: None,
                        })
                        .collect(),
                ),
            ),
        )
    }

    pub fn ss_rsrq(items: &[(u16, u32, Option<u8>)]) -> nrppa::MeasuredResultsValue {
        nr_ext(
            33,
            nrppa::MeasuredResultsValue_choice_ExtensionValue::Id_ResultSS_RSRQ(
                nrppa::ResultSS_RSRQ(
                    items
                        .iter()
                        .map(|(pci, arfcn, v)| nrppa::ResultSS_RSRQ_Item {
                            nr_pci: nrppa::NR_PCI(*pci),
                            nr_arfcn: nrppa::NR_ARFCN(*arfcn),
                            cgi_nr: None,
                            value_ss_rsrq_cell: v.map(nrppa::ValueRSRQ_NR),
                            ss_rsrq_per_ssb: None,
                            ie_extensions: None,
                        })
                        .collect(),
                ),
            ),
        )
    }

    pub fn csi_rsrp(items: &[(u16, u32, Option<u8>)]) -> nrppa::MeasuredResultsValue {
        nr_ext(
            34,
            nrppa::MeasuredResultsValue_choice_ExtensionValue::Id_ResultCSI_RSRP(
                nrppa::ResultCSI_RSRP(
                    items
                        .iter()
                        .map(|(pci, arfcn, v)| nrppa::ResultCSI_RSRP_Item {
                            nr_pci: nrppa::NR_PCI(*pci),
                            nr_arfcn: nrppa::NR_ARFCN(*arfcn),
                            cgi_nr: None,
                            value_csi_rsrp_cell: v.map(nrppa::ValueRSRP_NR),
                            csi_rsrp_per_csi_rs: None,
                            ie_extensions: None,
                        })
                        .collect(),
                ),
            ),
        )
    }

    pub fn csi_rsrq(items: &[(u16, u32, Option<u8>)]) -> nrppa::MeasuredResultsValue {
        nr_ext(
            35,
            nrppa::MeasuredResultsValue_choice_ExtensionValue::Id_ResultCSI_RSRQ(
                nrppa::ResultCSI_RSRQ(
                    items
                        .iter()
                        .map(|(pci, arfcn, v)| nrppa::ResultCSI_RSRQ_Item {
                            nr_pci: nrppa::NR_PCI(*pci),
                            nr_arfcn: nrppa::NR_ARFCN(*arfcn),
                            cgi_nr: None,
                            value_csi_rsrq_cell: v.map(nrppa::ValueRSRQ_NR),
                            csi_rsrq_per_csi_rs: None,
                            ie_extensions: None,
                        })
                        .collect(),
                ),
            ),
        )
    }

    pub fn aoa_nr(azimuth: u16, zenith: Option<u16>) -> nrppa::MeasuredResultsValue {
        aoa_nr_in(azimuth, zenith, None)
    }

    /// AoA NR given in an LCS: with an LCS to GCS Translation (TS 38.455 §9.2.38).
    pub fn aoa_nr_lcs(azimuth: u16) -> nrppa::MeasuredResultsValue {
        aoa_nr_in(
            azimuth,
            None,
            Some(nrppa::LCS_to_GCS_Translation {
                alpha: nrppa::LCS_to_GCS_TranslationAlpha(900),
                beta: nrppa::LCS_to_GCS_TranslationBeta(0),
                gamma: nrppa::LCS_to_GCS_TranslationGamma(0),
                ie_extensions: None,
            }),
        )
    }

    fn aoa_nr_in(
        azimuth: u16,
        zenith: Option<u16>,
        lcs: Option<nrppa::LCS_to_GCS_Translation>,
    ) -> nrppa::MeasuredResultsValue {
        nr_ext(
            36,
            nrppa::MeasuredResultsValue_choice_ExtensionValue::Id_AngleOfArrivalNR(nrppa::UL_AoA {
                azimuth_ao_a: nrppa::UL_AoAAzimuthAoA(azimuth),
                zenith_ao_a: zenith.map(nrppa::UL_AoAZenithAoA),
                lcs_to_gcs_translation: lcs,
                ie_extensions: None,
            }),
        )
    }

    /// An E-CID Measurement Report (TS 38.455 §9.1.2.4), IEs in object-set order.
    pub fn ecid_report(
        txn: u16,
        lmf: u16,
        ran: u16,
        cgi: nrppa::NG_RAN_CGI,
        tac: [u8; 3],
        measured: Option<Vec<nrppa::MeasuredResultsValue>>,
    ) -> Vec<u8> {
        use nrppa::E_CIDMeasurementReportProtocolIEs_EntryValue as V;
        let entry =
            |id: u16, criticality: u8, value: V| nrppa::E_CIDMeasurementReportProtocolIEs_Entry {
                id: nrppa::ProtocolIE_ID(id),
                criticality: nrppa::Criticality(criticality),
                value,
            };
        let ies = vec![
            entry(
                nrppa::ID_LMF_UE_MEASUREMENT_ID,
                super::REJECT,
                V::Id_LMF_UE_Measurement_ID(nrppa::UE_Measurement_ID(lmf)),
            ),
            entry(
                nrppa::ID_RAN_UE_MEASUREMENT_ID,
                super::REJECT,
                V::Id_RAN_UE_Measurement_ID(nrppa::UE_Measurement_ID(ran)),
            ),
            entry(
                nrppa::ID_E_CID_MEASUREMENT_RESULT,
                super::IGNORE,
                V::Id_E_CID_MeasurementResult(nrppa::E_CID_MeasurementResult {
                    serving_cell_id: cgi,
                    serving_cell_tac: nrppa::TAC(tac.to_vec()),
                    ng_ran_access_point_position: None,
                    measured_results: measured.map(nrppa::MeasuredResults),
                    ie_extensions: None,
                }),
            ),
        ];
        let pdu = nrppa::NRPPA_PDU::InitiatingMessage(nrppa::InitiatingMessage {
            procedure_code: nrppa::ProcedureCode(nrppa::ID_E_CID_MEASUREMENT_REPORT),
            criticality: nrppa::Criticality(super::IGNORE),
            nrppatransaction_id: nrppa::NRPPATransactionID(txn),
            value: nrppa::InitiatingMessageValue::Id_e_CIDMeasurementReport(
                nrppa::E_CIDMeasurementReport {
                    protocol_i_es: nrppa::E_CIDMeasurementReportProtocolIEs(ies),
                },
            ),
        });
        nextgcore_nrppa_gen::encode(&pdu).expect("generated encode")
    }

    /// An E-CID Measurement Initiation Response (TS 38.455 §9.1.2.2), the answer
    /// to an on-demand request, IEs in object-set order.
    pub fn ecid_initiation_response(
        txn: u16,
        lmf: u16,
        ran: u16,
        cgi: nrppa::NG_RAN_CGI,
        tac: [u8; 3],
        measured: Option<Vec<nrppa::MeasuredResultsValue>>,
    ) -> Vec<u8> {
        use nrppa::E_CIDMeasurementInitiationResponseProtocolIEs_EntryValue as V;
        let entry = |id: u16, criticality: u8, value: V| {
            nrppa::E_CIDMeasurementInitiationResponseProtocolIEs_Entry {
                id: nrppa::ProtocolIE_ID(id),
                criticality: nrppa::Criticality(criticality),
                value,
            }
        };
        let ies = vec![
            entry(
                nrppa::ID_LMF_UE_MEASUREMENT_ID,
                super::REJECT,
                V::Id_LMF_UE_Measurement_ID(nrppa::UE_Measurement_ID(lmf)),
            ),
            entry(
                nrppa::ID_RAN_UE_MEASUREMENT_ID,
                super::REJECT,
                V::Id_RAN_UE_Measurement_ID(nrppa::UE_Measurement_ID(ran)),
            ),
            entry(
                nrppa::ID_E_CID_MEASUREMENT_RESULT,
                super::IGNORE,
                V::Id_E_CID_MeasurementResult(nrppa::E_CID_MeasurementResult {
                    serving_cell_id: cgi,
                    serving_cell_tac: nrppa::TAC(tac.to_vec()),
                    ng_ran_access_point_position: None,
                    measured_results: measured.map(nrppa::MeasuredResults),
                    ie_extensions: None,
                }),
            ),
        ];
        let pdu = nrppa::NRPPA_PDU::SuccessfulOutcome(nrppa::SuccessfulOutcome {
            procedure_code: nrppa::ProcedureCode(nrppa::ID_E_CID_MEASUREMENT_INITIATION),
            criticality: nrppa::Criticality(super::REJECT),
            nrppatransaction_id: nrppa::NRPPATransactionID(txn),
            value: nrppa::SuccessfulOutcomeValue::Id_e_CIDMeasurementInitiation(
                nrppa::E_CIDMeasurementInitiationResponse {
                    protocol_i_es: nrppa::E_CIDMeasurementInitiationResponseProtocolIEs(ies),
                },
            ),
        });
        nextgcore_nrppa_gen::encode(&pdu).expect("generated encode")
    }

    /// Split an initiating-message PDU whose open type and IEs are each shorter
    /// than 128 octets (one-octet APER lengths) into its 5-octet header and IEs.
    fn split(bytes: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
        assert!(bytes[5] < 0x80 && usize::from(bytes[5]) == bytes.len() - 6);
        let value = &bytes[6..];
        let count = usize::from(u16::from_be_bytes([value[1], value[2]]));
        let mut ies = Vec::with_capacity(count);
        let mut at = 3;
        for _ in 0..count {
            let len = usize::from(value[at + 3]);
            assert!(len < 0x80, "test PDUs keep IE values under 128 octets");
            ies.push(value[at..at + 4 + len].to_vec());
            at += 4 + len;
        }
        assert_eq!(at, value.len());
        (bytes[..5].to_vec(), ies)
    }

    fn join(header: &[u8], ies: &[Vec<u8>]) -> Vec<u8> {
        let mut value = vec![0x00];
        value.extend_from_slice(&(ies.len() as u16).to_be_bytes());
        for ie in ies {
            value.extend_from_slice(ie);
        }
        let mut out = header.to_vec();
        out.push(u8::try_from(value.len()).expect("short PDU"));
        out.extend(value);
        out
    }

    /// Append a ProtocolIE-Field with `id` and `criticality` (0 reject, 1 ignore,
    /// 2 notify) and a one-octet value: id (2 octets), criticality in the top two
    /// bits of an octet, an open-type length of 1, the value.
    pub fn splice_ie(bytes: &[u8], id: u16, criticality: u8) -> Vec<u8> {
        let (header, mut ies) = split(bytes);
        let [hi, lo] = id.to_be_bytes();
        ies.push(vec![hi, lo, criticality << 6, 0x01, 0x00]);
        join(&header, &ies)
    }

    /// Remove the ProtocolIE-Field with `id`.
    pub fn drop_ie(bytes: &[u8], id: u16) -> Vec<u8> {
        let (header, mut ies) = split(bytes);
        ies.retain(|ie| u16::from_be_bytes([ie[0], ie[1]]) != id);
        join(&header, &ies)
    }
}

#[cfg(test)]
mod tests;
