//! Codec decode glue — lmfd-05/06
//!
//! Adapts raw NRPPa APER (TS 38.455) and LPP UPER (TS 37.355) PDUs into the
//! flat [`CellMeasurement`] list expected by
//! [`crate::LmfContext::measurement_report`].
//!
//! Two public adapter functions:
//!
//! - [`nrppa_ecid_report_to_measurements`] — E-CID Measurement Report
//!   (procedure code 4): serving-cell `NgRanCgi` → `nr_cgi`; `measured_results`
//!   CHOICE → `timing_advance`, `aoa`, `rsrp`, `rsrq`.
//!
//! - [`lpp_multi_rtt_provide_to_measurements`] — ProvideLocationInformation →
//!   nr-Multi-RTT list: `nr_ue_rx_tx_time_diff` k0..k5 CHOICE → `rtt_ns`
//!   (nanoseconds); `nr_phys_cell_id` → `nr_cgi`.
//!
//! NR-DL-TDOA is **DEFERRED**: `CellMeasurement` carries no TDOA/RSTD field,
//! and the `solve_tdoa` solver remains unwired.
//!
//! Two combined decode+adapt helpers — [`decode_nrppa_ecid_report`] and
//! [`decode_lpp_multi_rtt_report`] — are used by the inbound SBI handlers in
//! `main.rs`.

use crate::CellMeasurement;
use nextgcore_asn1c::lpp::message::{LppMessage, LppMessageBody, MessageBodyC1};
use nextgcore_asn1c::lpp::nr_dl_tdoa::NrRstd;
use nextgcore_asn1c::nrppa::ies::{MeasuredResultsValue, NgRanCell};
use nextgcore_asn1c::nrppa::pdu::{parse_ecid_measurement_report, NrppaPdu};

// ---------------------------------------------------------------------------
// Timing constant
// ---------------------------------------------------------------------------

/// T_c = 1 / (480 000 × 4096) seconds, in nanoseconds (TS 38.211 §4.1).
/// Used by [`nrrstd_to_ns`] to convert k-choice RSTD / UE-Rx-Tx values.
const TC_NS: f64 = 1_000_000_000.0 / (480_000.0 * 4_096.0);

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Format an `NgRanCgi` as `"<plmn-6hex>-<cellid-9hex>"` for NR cells, or
/// `"<plmn-6hex>-e<cellid-7hex>"` for E-UTRA cells.
fn ng_ran_cgi_to_string(cgi: &nextgcore_asn1c::nrppa::ies::NgRanCgi) -> String {
    let p = &cgi.plmn_identity.0;
    let plmn = format!("{:02x}{:02x}{:02x}", p[0], p[1], p[2]);
    match cgi.ng_ran_cell {
        NgRanCell::NrCellId(id) => format!("{plmn}-{id:09x}"),
        NgRanCell::EutraCellId(id) => format!("{plmn}-e{id:07x}"),
    }
}

/// Convert an NR-UE-Rx-Tx-TimeDiff k0..k5 CHOICE value to nanoseconds as an
/// unsigned magnitude `v × 2^n × T_c`, used by the Multi-RTT path for ranging.
///
/// NOTE: per TS 38.133 §10.1.25 the UE Rx–Tx time difference is itself a SIGNED
/// quantity with the same per-arm midpoint offset as NR-RSTD; treating it as an
/// unsigned magnitude here is a known simplification of the Multi-RTT RTT model
/// (RTT = UE-Rx-Tx + gNB-Rx-Tx) and is left unchanged to avoid regressing the
/// committed Multi-RTT path — revisit alongside a proper two-sided RTT model.
/// The DL-TDOA path uses the spec-correct signed converter [`nrrstd_to_signed_ns`].
fn nrrstd_to_ns(rstd: &NrRstd) -> u64 {
    let (val, shift): (f64, u32) = match rstd {
        NrRstd::K0(v) => (*v as f64, 0),
        NrRstd::K1(v) => (*v as f64, 1),
        NrRstd::K2(v) => (*v as f64, 2),
        NrRstd::K3(v) => (*v as f64, 3),
        NrRstd::K4(v) => (*v as f64, 4),
        NrRstd::K5(v) => (*v as f64, 5),
    };
    (val * (1u64 << shift) as f64 * TC_NS) as u64
}

/// Convert an NR-RSTD k0..k5 CHOICE value to SIGNED nanoseconds (TS 37.355
/// §6.5.10, mapping table TS 38.133 §10.1.23).
///
/// NR-RSTD is a *signed* reference-signal time difference relative to the
/// DL-PRS reference TRP, but is encoded as an unsigned `INTEGER(0..maxK)` whose
/// sign is carried by a per-arm midpoint offset. The signed value is
/// `(v × 2^k − 985024) × T_c`: the offset 985024 is the LTE RSTD span
/// (15391·Ts) scaled to `T_c = Ts/64`, so `v = 985024/2^k` decodes to exactly
/// 0 ns (the reference TRP) and the range spans ≈ ±501 µs.
///
/// The exact ±1-LSB bin convention is defined by the TS 38.133 quantization
/// table (not bundled in the local `specs/`); two independent spec derivations
/// agreed on this formula to within one code, and it is validated here by
/// synthetic round-trip recovery rather than a golden vector.
fn nrrstd_to_signed_ns(rstd: &NrRstd) -> f64 {
    let (val, shift): (i64, u32) = match rstd {
        NrRstd::K0(v) => (*v as i64, 0),
        NrRstd::K1(v) => (*v as i64, 1),
        NrRstd::K2(v) => (*v as i64, 2),
        NrRstd::K3(v) => (*v as i64, 3),
        NrRstd::K4(v) => (*v as i64, 4),
        NrRstd::K5(v) => (*v as i64, 5),
    };
    ((val << shift) - 985_024) as f64 * TC_NS
}

// ---------------------------------------------------------------------------
// NRPPa E-CID adapter
// ---------------------------------------------------------------------------

/// Adapt a decoded NRPPa APER PDU carrying an E-CID Measurement Report
/// (TS 38.455 §8.6, procedure code 4) into a flat list of
/// [`CellMeasurement`]s suitable for [`crate::LmfContext::measurement_report`].
///
/// The serving cell's `NgRanCgi` is used as `nr_cgi`.  The `measured_results`
/// CHOICE variants are folded into the single serving-cell entry:
///
/// | CHOICE variant               | `CellMeasurement` field | Notes                         |
/// |------------------------------|-------------------------|-------------------------------|
/// | `ValueAngleOfArrival(deg)`   | `aoa`                   | 0..719 degrees; first wins    |
/// | `ValueTimingAdvanceType1/2`  | `timing_advance`        | 0..7690 TA units; first wins  |
/// | `ResultRsrp(items)`          | `rsrp`                  | best item, value − 140 → dBm  |
/// | `ResultRsrq(items)`          | `rsrq`                  | best item raw 0..34 index     |
///
/// Returns an empty `Vec` on decode failure or when `measured_results` is absent.
pub fn nrppa_ecid_report_to_measurements(pdu: &NrppaPdu) -> Vec<CellMeasurement> {
    let report = match parse_ecid_measurement_report(pdu) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("nrppa_ecid_report_to_measurements: E-CID parse failed: {e}");
            return vec![];
        }
    };
    let result = &report.e_cid_measurement_result;
    let nr_cgi = ng_ran_cgi_to_string(&result.serving_cell_id);

    let mut rsrp: Option<i16> = None;
    let mut rsrq: Option<i16> = None;
    let mut timing_advance: Option<u32> = None;
    let mut aoa: Option<f64> = None;

    if let Some(measured) = &result.measured_results {
        for value in &measured.values {
            match value {
                MeasuredResultsValue::ValueAngleOfArrival(deg) => {
                    aoa.get_or_insert(*deg as f64);
                }
                MeasuredResultsValue::ValueTimingAdvanceType1(ta)
                | MeasuredResultsValue::ValueTimingAdvanceType2(ta) => {
                    timing_advance.get_or_insert(*ta as u32);
                }
                MeasuredResultsValue::ResultRsrp(items) => {
                    // Take the strongest (highest-index) item.
                    // value_rsrp_eutra 0..97 → −140..−43 dBm (1 dBm steps).
                    if let Some(best) = items.iter().max_by_key(|i| i.value_rsrp_eutra) {
                        let dbm = best.value_rsrp_eutra as i16 - 140;
                        rsrp = Some(rsrp.map_or(dbm, |cur: i16| cur.max(dbm)));
                    }
                }
                MeasuredResultsValue::ResultRsrq(items) => {
                    // Take the strongest RSRQ item; raw 0..34 index; first list wins.
                    if let Some(best) = items.iter().max_by_key(|i| i.value_rsrq_eutra) {
                        rsrq.get_or_insert(best.value_rsrq_eutra as i16);
                    }
                }
            }
        }
    }

    vec![CellMeasurement {
        nr_cgi,
        rsrp,
        rsrq,
        timing_advance,
        aoa,
        rtt_ns: None,
        rstd_ns: None,
    }]
}

/// Extract the LMF correlation request-id from a decoded NRPPa E-CID report.
///
/// The `lmf-UE-Measurement-ID` IE (TS 38.455 §9.2.13) is the ID originally
/// assigned by the LMF when initiating the positioning procedure.  Returns
/// `None` if the PDU is not an E-CID measurement report.
pub fn extract_nrppa_request_id(pdu: &NrppaPdu) -> Option<u64> {
    parse_ecid_measurement_report(pdu)
        .ok()
        .map(|r| u64::from(r.lmf_ue_measurement_id.0))
}

/// Decode raw NRPPa APER bytes and adapt the E-CID measurements.
///
/// Returns `(lmf_request_id, Vec<CellMeasurement>)` on success, or an `Err`
/// description.  Used by `handle_nrppa_binary_report` in `main.rs`.
pub fn decode_nrppa_ecid_report(bytes: &[u8]) -> Result<(u64, Vec<CellMeasurement>), String> {
    let pdu = NrppaPdu::decode(bytes).map_err(|e| format!("NRPPa APER decode: {e}"))?;
    let request_id = extract_nrppa_request_id(&pdu)
        .ok_or_else(|| "PDU is not an E-CID measurement report".to_string())?;
    Ok((request_id, nrppa_ecid_report_to_measurements(&pdu)))
}

// ---------------------------------------------------------------------------
// LPP Multi-RTT adapter
// ---------------------------------------------------------------------------

/// Adapt a decoded LPP UPER PDU carrying a `ProvideLocationInformation` →
/// `nr-Multi-RTT` measurement list (TS 37.355 §6.5.10) into
/// [`CellMeasurement`]s.
///
/// Each `NrMultiRttMeasElement` produces one entry:
///
/// | PDU field                       | `CellMeasurement` field | Notes                            |
/// |---------------------------------|-------------------------|----------------------------------|
/// | `nr_phys_cell_id` (NR PCI)      | `nr_cgi`                | `"pci-<n>"`; `"prs-<id>"` fallback |
/// | `nr_ue_rx_tx_time_diff` k0..k5  | `rtt_ns`                | v × 2^k × T_c nanoseconds        |
/// | `nr_dl_prs_rsrp_result`          | `rsrp`                  | 0..127 → −140..−13 dBm           |
///
/// NR-DL-TDOA is DEFERRED; `CellMeasurement` carries no TDOA/RSTD field.
///
/// Returns an empty `Vec` when the message is not a
/// `ProvideLocationInformation`, carries no `nr-Multi-RTT` body, or when
/// `signal_measurement_information` is absent.
pub fn lpp_multi_rtt_provide_to_measurements(msg: &LppMessage) -> Vec<CellMeasurement> {
    let prov = match msg.message_body.as_ref() {
        Some(LppMessageBody::C1(MessageBodyC1::ProvideLocationInformation(p))) => p,
        _ => return vec![],
    };
    let sig_info = match prov
        .ies
        .nr_multi_rtt
        .as_ref()
        .and_then(|m| m.signal_measurement_information.as_ref())
    {
        Some(s) => s,
        None => return vec![],
    };

    sig_info
        .meas_list
        .items
        .iter()
        .map(|elem| {
            // Use NR PCI as CGI key when present; fall back to DL-PRS-ID.
            let nr_cgi = match elem.nr_phys_cell_id {
                Some(pci) => format!("pci-{pci}"),
                None => format!("prs-{}", elem.dl_prs_id),
            };
            // nr_dl_prs_rsrp_result 0..127 → −140..−13 dBm (TS 37.355 §6.5.10).
            let rsrp = elem.nr_dl_prs_rsrp_result.map(|v| v as i16 - 140);
            CellMeasurement {
                nr_cgi,
                rsrp,
                rsrq: None,
                timing_advance: None,
                aoa: None,
                rtt_ns: Some(nrrstd_to_ns(&elem.nr_ue_rx_tx_time_diff)),
                rstd_ns: None,
            }
        })
        .collect()
}

/// Extract the LPP transaction number as a correlation request-id.
///
/// The `transactionID.transactionNumber` (0..255) correlates the UE's
/// `ProvideLocationInformation` with the LMF's `RequestLocationInformation`.
/// Returns `None` when the message carries no `transactionID`.
pub fn extract_lpp_request_id(msg: &LppMessage) -> Option<u64> {
    msg.transaction_id
        .as_ref()
        .map(|t| u64::from(t.transaction_number.0))
}

/// Decode raw LPP UPER bytes and adapt nr-Multi-RTT measurements.
///
/// Returns `(request_id, Vec<CellMeasurement>)` on success, or an `Err`
/// description.  `request_id` is the LPP transaction number (0 when absent).
/// Used by `handle_lpp_binary_report` in `main.rs`.
pub fn decode_lpp_multi_rtt_report(bytes: &[u8]) -> Result<(u64, Vec<CellMeasurement>), String> {
    let msg = LppMessage::decode(bytes).map_err(|e| format!("LPP UPER decode: {e}"))?;
    let request_id = extract_lpp_request_id(&msg).unwrap_or(0);
    Ok((request_id, lpp_multi_rtt_provide_to_measurements(&msg)))
}

/// Adapt a UE NR-DL-TDOA `ProvideLocationInformation` (TS 37.355 §6.5.10) to a
/// flat [`CellMeasurement`] list for [`crate::LmfContext::measurement_report`].
///
/// The reference TRP (`dl-PRS-ReferenceInfo`) is emitted first with `rstd_ns =
/// 0` (RSTD is defined relative to it); each `NR-DL-TDOA-MeasElement` then
/// contributes one entry whose `rstd_ns` is the SIGNED time difference vs that
/// reference (see [`nrrstd_to_signed_ns`]). The CGI key is `"pci-<n>"` (NR PCI)
/// when present, else `"prs-<id>"` (DL-PRS-ID). `compute_location` feeds these
/// to the TDOA solver (reference first).
///
/// Returns an empty `Vec` when the message is not a `ProvideLocationInformation`
/// or carries no `nr-DL-TDOA` signal-measurement information.
pub fn lpp_dl_tdoa_provide_to_measurements(msg: &LppMessage) -> Vec<CellMeasurement> {
    let prov = match msg.message_body.as_ref() {
        Some(LppMessageBody::C1(MessageBodyC1::ProvideLocationInformation(p))) => p,
        _ => return vec![],
    };
    let sig_info = match prov
        .ies
        .nr_dl_tdoa
        .as_ref()
        .and_then(|m| m.signal_measurement_information.as_ref())
    {
        Some(s) => s,
        None => return vec![],
    };

    let mut out = Vec::with_capacity(sig_info.meas_list.items.len() + 1);
    // Reference TRP: RSTD ≡ 0 by definition.
    out.push(CellMeasurement {
        nr_cgi: format!("prs-{}", sig_info.dl_prs_reference_info.dl_prs_id),
        rsrp: None,
        rsrq: None,
        timing_advance: None,
        aoa: None,
        rtt_ns: None,
        rstd_ns: Some(0.0),
    });
    for elem in &sig_info.meas_list.items {
        let nr_cgi = match elem.nr_phys_cell_id {
            Some(pci) => format!("pci-{pci}"),
            None => format!("prs-{}", elem.dl_prs_id),
        };
        // nr_dl_prs_rsrp_result 0..127 → −140..−13 dBm (TS 37.355 §6.5.10).
        let rsrp = elem.nr_dl_prs_rsrp_result.map(|v| v as i16 - 140);
        out.push(CellMeasurement {
            nr_cgi,
            rsrp,
            rsrq: None,
            timing_advance: None,
            aoa: None,
            rtt_ns: None,
            rstd_ns: Some(nrrstd_to_signed_ns(&elem.nr_rstd)),
        });
    }
    out
}

/// Decode raw LPP UPER bytes and adapt NR-DL-TDOA measurements.
///
/// Returns `(request_id, Vec<CellMeasurement>)`; `request_id` is the LPP
/// transaction number (0 when absent).
pub fn decode_lpp_dl_tdoa_report(bytes: &[u8]) -> Result<(u64, Vec<CellMeasurement>), String> {
    let msg = LppMessage::decode(bytes).map_err(|e| format!("LPP UPER decode: {e}"))?;
    let request_id = extract_lpp_request_id(&msg).unwrap_or(0);
    Ok((request_id, lpp_dl_tdoa_provide_to_measurements(&msg)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        decode_nrppa_ecid_report, extract_lpp_request_id, extract_nrppa_request_id,
        lpp_dl_tdoa_provide_to_measurements, lpp_multi_rtt_provide_to_measurements,
        nrppa_ecid_report_to_measurements, nrrstd_to_ns, nrrstd_to_signed_ns, TC_NS,
    };
    use nextgcore_asn1c::lpp::ecid::{ProvideLocationInformation, ProvideLocationInformationR9};
    use nextgcore_asn1c::lpp::message::{LppMessage, LppMessageBody, MessageBodyC1};
    use nextgcore_asn1c::lpp::nr_dl_tdoa::{NrRstd, NrSlot, NrTimeStamp, NrTimingQuality};
    use nextgcore_asn1c::lpp::nr_multi_rtt::{
        NrMultiRttMeasElement, NrMultiRttMeasList, NrMultiRttProvideLocationInformation,
        NrMultiRttSignalMeasurementInformation, NrUeRxTxTimeDiff,
    };
    use nextgcore_asn1c::lpp::types::{Initiator, LppTransactionId, TransactionNumber};
    use nextgcore_asn1c::nrppa::ies::{
        ECidMeasurementResult, MeasuredResults, MeasuredResultsValue, NgRanCell, NgRanCgi,
        PlmnIdentity, ResultRsrpEutraItem, Tac, UeMeasurementId,
    };
    use nextgcore_asn1c::nrppa::pdu::{build_ecid_measurement_report, NrppaPdu};
    use nextgcore_asn1c::nrppa::types::NrppaTransactionId;

    /// `nrrstd_to_ns`: single-unit inputs verify the 2^k × T_c scaling.
    ///
    /// T_c ≈ 0.5086 ns; the (f64 → u64) truncation is intentional.
    #[test]
    fn nrrstd_k_to_ns_unit_values() {
        // K0(1) → 1 × 1 × 0.5086 ≈ 0 ns (truncated)
        assert_eq!(nrrstd_to_ns(&NrRstd::K0(1)), 0);
        // K1(1) → 1 × 2 × 0.5086 ≈ 1 ns
        assert_eq!(nrrstd_to_ns(&NrRstd::K1(1)), 1);
        // K2(1) → 1 × 4 × 0.5086 ≈ 2 ns
        assert_eq!(nrrstd_to_ns(&NrRstd::K2(1)), 2);
        // K3(1) → 1 × 8 × 0.5086 ≈ 4 ns
        assert_eq!(nrrstd_to_ns(&NrRstd::K3(1)), 4);
        // K4(1) → 1 × 16 × 0.5086 ≈ 8 ns
        assert_eq!(nrrstd_to_ns(&NrRstd::K4(1)), 8);
        // K5(1) → 1 × 32 × 0.5086 ≈ 16 ns
        assert_eq!(nrrstd_to_ns(&NrRstd::K5(1)), 16);
    }

    // Helper: a minimal NrTimeStamp (required in NrMultiRttMeasElement).
    fn sample_nr_timestamp() -> NrTimeStamp {
        NrTimeStamp {
            dl_prs_id: 5,
            nr_phys_cell_id: None,
            nr_arfcn: None,
            nr_sfn: 700,
            nr_slot: NrSlot::Scs30(11),
        }
    }

    /// NRPPa E-CID round-trip: build → APER encode → decode → adapt.
    ///
    /// Checks NR-CGI formatting, TA, AoA, and best-RSRP extraction.
    #[test]
    fn rt_nrppa_ecid_report_to_measurements() {
        // Serving cell: PLMN 02:F8:39, NR Cell ID 1 (36-bit).
        let e_cid = ECidMeasurementResult {
            serving_cell_id: NgRanCgi {
                plmn_identity: PlmnIdentity([0x02, 0xF8, 0x39]),
                ng_ran_cell: NgRanCell::NrCellId(0x000000001),
            },
            serving_cell_tac: Tac([0x00, 0x12, 0x34]),
            ng_ran_access_point_position: None,
            measured_results: Some(MeasuredResults {
                values: vec![
                    MeasuredResultsValue::ValueTimingAdvanceType1(500),
                    MeasuredResultsValue::ValueAngleOfArrival(90),
                    // Two RSRP items; value 60 should beat 55.
                    MeasuredResultsValue::ResultRsrp(vec![
                        ResultRsrpEutraItem {
                            pci_eutra: 42,
                            earfcn: 1850,
                            value_rsrp_eutra: 60,
                        },
                        ResultRsrpEutraItem {
                            pci_eutra: 43,
                            earfcn: 1850,
                            value_rsrp_eutra: 55,
                        },
                    ]),
                ],
            }),
        };

        let pdu = build_ecid_measurement_report(
            NrppaTransactionId(1),
            UeMeasurementId(42), // lmf_ue_measurement_id → correlation key
            UeMeasurementId(7),
            &e_cid,
            None,
        )
        .expect("build_ecid_measurement_report");

        // APER round-trip.
        let encoded = pdu.encode().expect("NrppaPdu::encode");
        let decoded = NrppaPdu::decode(&encoded).expect("NrppaPdu::decode");

        // extract_nrppa_request_id reads lmf_ue_measurement_id (42).
        assert_eq!(extract_nrppa_request_id(&decoded), Some(42));

        let cells = nrppa_ecid_report_to_measurements(&decoded);
        assert_eq!(cells.len(), 1, "one serving-cell entry");

        let c = &cells[0];
        // PLMN 02:F8:39 → "02f839"; NR Cell ID 1 → 9-digit hex "000000001".
        assert_eq!(c.nr_cgi, "02f839-000000001");
        assert_eq!(c.timing_advance, Some(500));
        assert_eq!(c.aoa, Some(90.0));
        // Best RSRP: value_rsrp_eutra=60 → 60 − 140 = −80 dBm.
        assert_eq!(c.rsrp, Some(-80));
        assert_eq!(c.rtt_ns, None);
    }

    /// LPP Multi-RTT round-trip: build → UPER encode → decode → adapt.
    ///
    /// Verifies k-choice → ns conversion and PCI/PRS-fallback CGI formatting.
    #[test]
    fn rt_lpp_multi_rtt_to_measurements() {
        let msg = LppMessage {
            transaction_id: Some(LppTransactionId {
                initiator: Initiator::TargetDevice,
                transaction_number: TransactionNumber(7),
            }),
            end_transaction: true,
            sequence_number: None,
            acknowledgement: None,
            message_body: Some(LppMessageBody::C1(
                MessageBodyC1::ProvideLocationInformation(ProvideLocationInformation {
                    ies: ProvideLocationInformationR9 {
                        ecid: None,
                        nr_multi_rtt: Some(NrMultiRttProvideLocationInformation {
                            signal_measurement_information: Some(
                                NrMultiRttSignalMeasurementInformation {
                                    meas_list: NrMultiRttMeasList {
                                        items: vec![
                                            // Cell 0: PCI 123, K2(300_000), RSRP 80.
                                            NrMultiRttMeasElement {
                                                dl_prs_id: 5,
                                                nr_phys_cell_id: Some(123),
                                                nr_arfcn: None,
                                                nr_ue_rx_tx_time_diff: NrUeRxTxTimeDiff::K2(
                                                    300_000,
                                                ),
                                                nr_time_stamp: sample_nr_timestamp(),
                                                nr_timing_quality: NrTimingQuality {
                                                    timing_quality_value: 12,
                                                    timing_quality_resolution: 2,
                                                },
                                                nr_dl_prs_rsrp_result: Some(80),
                                            },
                                            // Cell 1: PCI absent → prs-6 fallback, K1(200_000).
                                            NrMultiRttMeasElement {
                                                dl_prs_id: 6,
                                                nr_phys_cell_id: None,
                                                nr_arfcn: None,
                                                nr_ue_rx_tx_time_diff: NrUeRxTxTimeDiff::K1(
                                                    200_000,
                                                ),
                                                nr_time_stamp: sample_nr_timestamp(),
                                                nr_timing_quality: NrTimingQuality {
                                                    timing_quality_value: 8,
                                                    timing_quality_resolution: 1,
                                                },
                                                nr_dl_prs_rsrp_result: None,
                                            },
                                        ],
                                    },
                                },
                            ),
                        }),
                        nr_dl_tdoa: None,
                    },
                }),
            )),
        };

        // UPER round-trip.
        let encoded = msg.encode().expect("LppMessage::encode");
        let decoded = LppMessage::decode(&encoded).expect("LppMessage::decode");

        assert_eq!(extract_lpp_request_id(&decoded), Some(7));

        let cells = lpp_multi_rtt_provide_to_measurements(&decoded);
        assert_eq!(cells.len(), 2);

        // Cell 0: PCI present → "pci-123"; K2(300_000) → ~610_351 ns.
        let c0 = &cells[0];
        assert_eq!(c0.nr_cgi, "pci-123");
        // nr_dl_prs_rsrp_result=80 → 80 − 140 = −60 dBm.
        assert_eq!(c0.rsrp, Some(-60));
        let rtt0 = c0.rtt_ns.expect("rtt_ns cell 0");
        // K2(300_000): 300_000 × 4 × TC_NS = 1_200_000 × (1e9/1_966_080_000) ≈ 610_351 ns.
        assert!(
            (610_000..=611_000).contains(&rtt0),
            "K2(300_000) rtt_ns={rtt0}, expected ~610_351"
        );

        // Cell 1: PCI absent → "prs-6"; K1(200_000) → ~203_450 ns; no RSRP.
        let c1 = &cells[1];
        assert_eq!(c1.nr_cgi, "prs-6");
        assert_eq!(c1.rsrp, None);
        let rtt1 = c1.rtt_ns.expect("rtt_ns cell 1");
        // K1(200_000): 200_000 × 2 × TC_NS = 400_000 × (1e9/1_966_080_000) ≈ 203_450 ns.
        assert!(
            (203_000..=204_000).contains(&rtt1),
            "K1(200_000) rtt_ns={rtt1}, expected ~203_450"
        );
    }

    /// `nrrstd_to_signed_ns`: NR-RSTD is a SIGNED time difference; verify the
    /// midpoint-offset mapping ns = (v·2^k − 985024)·T_c at the spec endpoints.
    #[test]
    fn nrrstd_signed_endpoints() {
        // Per-arm zero point 985024/2^k decodes to exactly 0 ns (reference TRP).
        assert_eq!(nrrstd_to_signed_ns(&NrRstd::K0(985_024)), 0.0);
        assert_eq!(nrrstd_to_signed_ns(&NrRstd::K2(246_256)), 0.0); // 985024/4
        assert_eq!(nrrstd_to_signed_ns(&NrRstd::K5(30_782)), 0.0); // 985024/32
        // One k0 code = ±T_c around the midpoint (sign carried by the offset).
        assert!((nrrstd_to_signed_ns(&NrRstd::K0(985_025)) - TC_NS).abs() < 1e-9);
        assert!((nrrstd_to_signed_ns(&NrRstd::K0(985_023)) + TC_NS).abs() < 1e-9);
        // Endpoints span ≈ ±501 µs.
        assert!((nrrstd_to_signed_ns(&NrRstd::K0(0)) + 985_024.0 * TC_NS).abs() < 1e-6);
        assert!(nrrstd_to_signed_ns(&NrRstd::K0(1_970_049)) > 500_000.0);
    }

    /// LPP NR-DL-TDOA round-trip: build → UPER encode → decode → adapt.
    /// The reference TRP leads with rstd_ns 0; each element carries its signed RSTD.
    #[test]
    fn rt_lpp_dl_tdoa_to_measurements() {
        use nextgcore_asn1c::lpp::nr_dl_tdoa::{
            DlPrsIdInfo, NrDlTdoaMeasElement, NrDlTdoaMeasList,
            NrDlTdoaProvideLocationInformation, NrDlTdoaSignalMeasurementInformation,
        };
        let msg = LppMessage {
            transaction_id: Some(LppTransactionId {
                initiator: Initiator::TargetDevice,
                transaction_number: TransactionNumber(9),
            }),
            end_transaction: true,
            sequence_number: None,
            acknowledgement: None,
            message_body: Some(LppMessageBody::C1(
                MessageBodyC1::ProvideLocationInformation(ProvideLocationInformation {
                    ies: ProvideLocationInformationR9 {
                        ecid: None,
                        nr_multi_rtt: None,
                        nr_dl_tdoa: Some(NrDlTdoaProvideLocationInformation {
                            signal_measurement_information: Some(
                                NrDlTdoaSignalMeasurementInformation {
                                    dl_prs_reference_info: DlPrsIdInfo { dl_prs_id: 3 },
                                    meas_list: NrDlTdoaMeasList {
                                        items: vec![NrDlTdoaMeasElement {
                                            dl_prs_id: 7,
                                            nr_phys_cell_id: Some(123),
                                            nr_arfcn: None,
                                            nr_time_stamp: sample_nr_timestamp(),
                                            nr_rstd: NrRstd::K0(985_124),
                                            nr_timing_quality: NrTimingQuality {
                                                timing_quality_value: 10,
                                                timing_quality_resolution: 1,
                                            },
                                            nr_dl_prs_rsrp_result: Some(100),
                                        }],
                                    },
                                },
                            ),
                        }),
                    },
                }),
            )),
        };

        let encoded = msg.encode().expect("LppMessage::encode");
        let decoded = LppMessage::decode(&encoded).expect("LppMessage::decode");
        assert_eq!(extract_lpp_request_id(&decoded), Some(9));

        let cells = lpp_dl_tdoa_provide_to_measurements(&decoded);
        assert_eq!(cells.len(), 2, "reference + 1 measurement element");
        // Reference TRP first, RSTD 0.
        assert_eq!(cells[0].nr_cgi, "prs-3");
        assert_eq!(cells[0].rstd_ns, Some(0.0));
        // Element: PCI present → "pci-123"; K0(985_124) → (985124−985024)·T_c = 100·T_c.
        assert_eq!(cells[1].nr_cgi, "pci-123");
        assert_eq!(cells[1].rsrp, Some(-40)); // 100 − 140
        let rstd = cells[1].rstd_ns.expect("rstd_ns");
        assert!((rstd - 100.0 * TC_NS).abs() < 1e-6, "rstd_ns={rstd}");
    }

    /// `decode_nrppa_ecid_report`: thin wrapper returns same request-id and CGI
    /// as calling the adapter function directly.
    #[test]
    fn decode_nrppa_ecid_report_wrapper() {
        let e_cid = ECidMeasurementResult {
            serving_cell_id: NgRanCgi {
                plmn_identity: PlmnIdentity([0x00, 0xF1, 0x10]),
                ng_ran_cell: NgRanCell::NrCellId(0x000000002),
            },
            serving_cell_tac: Tac([0x00, 0x00, 0x01]),
            ng_ran_access_point_position: None,
            measured_results: None,
        };
        let pdu = build_ecid_measurement_report(
            NrppaTransactionId(0),
            UeMeasurementId(9),
            UeMeasurementId(1),
            &e_cid,
            None,
        )
        .unwrap();
        let bytes = pdu.encode().unwrap();

        let (req_id, cells) = decode_nrppa_ecid_report(&bytes).unwrap();
        assert_eq!(req_id, 9);
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0].nr_cgi, "00f110-000000002");
        assert_eq!(cells[0].timing_advance, None);
        assert_eq!(cells[0].rsrp, None);
    }
}
