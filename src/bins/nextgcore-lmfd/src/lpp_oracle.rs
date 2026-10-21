//! The pre-#515 LPP adapters and builders, kept verbatim on the hand-written
//! codec as the oracle the generated-codec versions in [`crate::codec_glue`] are
//! checked against (test-only). Deleted with the hand-written LPP codec.
#![allow(dead_code)]

use crate::codec_glue::LppMethod;
use crate::CellMeasurement;
use nextgcore_asn1c::lpp::ecid::{
    EcidRequestLocationInformation, MeasuredResultsElement, RequestLocationInformation,
    RequestLocationInformationR9,
};
use nextgcore_asn1c::lpp::message::{LppMessage, LppMessageBody, MessageBodyC1};
use nextgcore_asn1c::lpp::nr_dl_tdoa::NrRstd;
use nextgcore_asn1c::lpp::requested_measurements;
use nextgcore_asn1c::lpp::types::{Initiator, LppTransactionId, TransactionNumber};

const TC_NS: f64 = 1_000_000_000.0 / (480_000.0 * 4_096.0);

pub(crate) fn build_lpp_ecid_request(transaction_number: u8) -> Result<Vec<u8>, String> {
    let msg = LppMessage {
        transaction_id: Some(LppTransactionId {
            initiator: Initiator::LocationServer,
            transaction_number: TransactionNumber(transaction_number),
        }),
        end_transaction: false,
        sequence_number: None,
        acknowledgement: None,
        message_body: Some(LppMessageBody::C1(
            MessageBodyC1::RequestLocationInformation(RequestLocationInformation {
                ies: RequestLocationInformationR9 {
                    // requestedMeasurements: bit0 = rsrpReq, bit1 = rsrqReq.
                    ecid: Some(EcidRequestLocationInformation {
                        requested_measurements: requested_measurements(&[true, true]),
                    }),
                    nr_multi_rtt: None,
                    nr_dl_tdoa: None,
                },
            }),
        )),
    };
    msg.encode()
        .map(|b| b.to_vec())
        .map_err(|e| format!("LPP RequestLocationInformation encode: {e}"))
}

pub(crate) fn build_lpp_provide_assistance_data(
    transaction_number: u8,
    lat_deg: f64,
    lon_deg: f64,
    uncertainty_m: f64,
) -> Result<Vec<u8>, String> {
    use nextgcore_asn1c::lpp::a_gnss::common::{AGnssProvideAssistanceData, GnssCommonAssistData};
    use nextgcore_asn1c::lpp::a_gnss::reference_location::{
        AltitudeDirection, EllipsoidPointWithAltitudeAndUncertaintyEllipsoid,
        GnssReferenceLocation, LatitudeSign,
    };

    // TS 23.032 §6.1 magnitude-and-sign, as the GAD encoders in `nlmf` already do
    // for the northbound body. Reused rather than re-derived so the two cannot
    // disagree about the same coordinate.
    let (sign, degrees_latitude) = if lat_deg < 0.0 {
        (LatitudeSign::South, lat_deg.abs())
    } else {
        (LatitudeSign::North, lat_deg)
    };
    let degrees_latitude =
        ((degrees_latitude.min(90.0) / 90.0) * f64::from(1u32 << 23)).round() as u32;
    let degrees_latitude = degrees_latitude.min((1u32 << 23) - 1);
    let degrees_longitude =
        ((lon_deg.clamp(-180.0, 180.0) / 360.0) * f64::from(1u32 << 24)).round() as i32;
    let degrees_longitude = degrees_longitude.clamp(-(1i32 << 23), (1i32 << 23) - 1);

    let three_d_location = EllipsoidPointWithAltitudeAndUncertaintyEllipsoid {
        latitude_sign: sign,
        degrees_latitude,
        degrees_longitude,
        altitude_direction: AltitudeDirection::Height,
        // Altitude 0 with a MAXIMAL altitude uncertainty: the registry's coordinates
        // are 2-D in every deployment this build supports, so claiming a height would
        // be claiming knowledge. A large uncertainty says "unknown" in the only
        // vocabulary the IE has.
        altitude: 0,
        uncertainty_semi_major: crate::nlmf::encode_gad_uncertainty(uncertainty_m),
        uncertainty_semi_minor: crate::nlmf::encode_gad_uncertainty(uncertainty_m),
        // A circular uncertainty region, so the major-axis orientation is arbitrary.
        orientation_major_axis: 0,
        uncertainty_altitude: 127,
        // 68% — one standard deviation, the convention the northbound encoder uses.
        confidence: 68,
    };

    let msg = LppMessage {
        transaction_id: Some(LppTransactionId {
            // The LMF answers on the UE's transaction, so the initiator is the UE
            // that opened it. Sending `LocationServer` here would open a SECOND
            // transaction and leave the UE's request unanswered.
            initiator: Initiator::TargetDevice,
            transaction_number: TransactionNumber(transaction_number),
        }),
        // The assistance data completes the exchange the UE opened.
        end_transaction: true,
        sequence_number: None,
        acknowledgement: None,
        message_body: Some(LppMessageBody::C1(MessageBodyC1::ProvideAssistanceData(
            nextgcore_asn1c::lpp::a_gnss::body::ProvideAssistanceData {
                ies: nextgcore_asn1c::lpp::a_gnss::body::ProvideAssistanceDataR9 {
                    a_gnss: Some(AGnssProvideAssistanceData {
                        gnss_common_assist_data: Some(GnssCommonAssistData {
                            gnss_reference_time: None,
                            gnss_reference_location: Some(GnssReferenceLocation {
                                three_d_location,
                            }),
                            gnss_ionospheric_model: None,
                            gnss_earth_orientation_parameters: None,
                        }),
                        gnss_generic_assist_data: None,
                    }),
                },
            },
        ))),
    };
    msg.encode()
        .map(|b| b.to_vec())
        .map_err(|e| format!("LPP ProvideAssistanceData encode: {e}"))
}

pub(crate) fn build_lpp_request(
    method: LppMethod,
    transaction_number: u8,
) -> Result<Vec<u8>, String> {
    let ies = match method {
        LppMethod::Ecid => RequestLocationInformationR9 {
            // requestedMeasurements: bit0 = rsrpReq, bit1 = rsrqReq.
            ecid: Some(EcidRequestLocationInformation {
                requested_measurements: requested_measurements(&[true, true]),
            }),
            nr_multi_rtt: None,
            nr_dl_tdoa: None,
        },
        LppMethod::MultiRtt => RequestLocationInformationR9 {
            ecid: None,
            nr_multi_rtt: Some(
                nextgcore_asn1c::lpp::nr_multi_rtt::NrMultiRttRequestLocationInformation {
                    // The Rx-Tx time difference IS the ranging observable, so a
                    // Multi-RTT request that did not ask for it would return
                    // RSRP the E-CID path already gets.
                    rx_tx_time_diff_measurement_info_request: true,
                    // bit0 = prsrsrpReq: the PRS RSRP accompanies each range and is
                    // what the solver weights by.
                    requested_measurements: requested_measurements(&[true]),
                    // This LMF provides no PRS assistance data, so it must not claim
                    // availability -- a UE told assistance is available and given
                    // none reports nothing.
                    assistance_availability: false,
                    report_config: nextgcore_asn1c::lpp::nr_multi_rtt::NrMultiRttReportConfig {
                        // Up to 4 measurements per TRP; trilateration needs >=3
                        // TRPs and more samples per TRP only helps.
                        max_dl_prs_rx_tx_time_diff_meas_per_trp: Some(4),
                        timing_reporting_granularity_factor: None,
                    },
                    additional_paths: false,
                },
            ),
            nr_dl_tdoa: None,
        },
        LppMethod::DlTdoa => RequestLocationInformationR9 {
            ecid: None,
            nr_multi_rtt: None,
            nr_dl_tdoa: Some(
                nextgcore_asn1c::lpp::nr_dl_tdoa::NrDlTdoaRequestLocationInformation {
                    // The RSTD is the observable; without it there is nothing to
                    // multilaterate.
                    rstd_measurement_info_request: true,
                    requested_measurements: requested_measurements(&[true]),
                    assistance_availability: false,
                    additional_paths: false,
                },
            ),
        },
    };
    let msg = LppMessage {
        transaction_id: Some(LppTransactionId {
            initiator: Initiator::LocationServer,
            transaction_number: TransactionNumber(transaction_number),
        }),
        end_transaction: false,
        sequence_number: None,
        acknowledgement: None,
        message_body: Some(LppMessageBody::C1(
            MessageBodyC1::RequestLocationInformation(RequestLocationInformation { ies }),
        )),
    };
    msg.encode()
        .map(|b| b.to_vec())
        .map_err(|e| format!("LPP RequestLocationInformation ({method:?}) encode: {e}"))
}

pub(crate) fn nrrstd_to_ns(rstd: &NrRstd) -> u64 {
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

pub(crate) fn nrrstd_to_signed_ns(rstd: &NrRstd) -> f64 {
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

pub(crate) fn measured_results_element_to_cell(elem: &MeasuredResultsElement) -> CellMeasurement {
    CellMeasurement {
        nr_cgi: format!("pci-{}", elem.phys_cell_id),
        rsrp: elem.rsrp_result.map(|v| i16::from(v) - 140),
        rsrq: elem.rsrq_result.map(i16::from),
        timing_advance: elem.ue_rx_tx_time_diff.map(u32::from),
        aoa: None,
        rtt_ns: None,
        rstd_ns: None,
    }
}

pub(crate) fn lpp_ecid_provide_to_measurements(msg: &LppMessage) -> Vec<CellMeasurement> {
    let prov = match msg.message_body.as_ref() {
        Some(LppMessageBody::C1(MessageBodyC1::ProvideLocationInformation(p))) => p,
        _ => return vec![],
    };
    let sig = match prov
        .ies
        .ecid
        .as_ref()
        .and_then(|e| e.signal_measurement_information.as_ref())
    {
        Some(s) => s,
        None => return vec![],
    };

    let mut out = Vec::with_capacity(
        sig.measured_results_list.len() + usize::from(sig.primary_cell_measured_results.is_some()),
    );
    if let Some(primary) = sig.primary_cell_measured_results.as_ref() {
        out.push(measured_results_element_to_cell(primary));
    }
    for elem in &sig.measured_results_list {
        out.push(measured_results_element_to_cell(elem));
    }
    out
}

pub(crate) fn lpp_multi_rtt_provide_to_measurements(msg: &LppMessage) -> Vec<CellMeasurement> {
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

pub(crate) fn lpp_dl_tdoa_provide_to_measurements(msg: &LppMessage) -> Vec<CellMeasurement> {
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
