//! NRPPa answers to the Multi-RTT procedures this LMF initiates (#807): TRP
//! Information Exchange (TS 38.455 §8.2.8), Positioning Information Exchange
//! (§8.2.6), Positioning Activation (§8.2.9) and Measurement (§8.5.1), decoded with
//! the generated `nextgcore-nrppa-gen` codec.
//!
//! # Error handling
//!
//! Each of these is a class 1 procedure, answered by a SUCCESSFUL or UNSUCCESSFUL
//! OUTCOME. TS 38.455 §10 applies TS 38.413 §10.3.4.2 to a response: an IE the LMF
//! does not comprehend with criticality **reject**, or a missing mandatory IE with
//! criticality reject, makes the procedure "unsuccessfully terminated" and starts
//! local error handling. Here that is an `Err`, and the Multi-RTT leg goes on without
//! that gNB's answer. An unknown **ignore** or **notify** IE is dropped: no ERROR
//! INDICATION is sent for a response.

use crate::positioning::TrpCoord;
use nextgcore_nrppa_gen::generated as nrppa;
use nextgcore_nrppa_gen::UnknownIe;

const REJECT: u8 = 0;

/// The procedure code and transaction id of an NRPPa PDU, read from its header.
/// The Multi-RTT exchanges are correlated by this pair. `None` when the octets do
/// not decode.
pub fn header(bytes: &[u8]) -> Option<(Kind, u8, u16)> {
    let pdu = nextgcore_nrppa_gen::decode(bytes).ok()?;
    Some(match pdu {
        nrppa::NRPPA_PDU::InitiatingMessage(m) => (
            Kind::Initiating,
            m.procedure_code.0,
            m.nrppatransaction_id.0,
        ),
        nrppa::NRPPA_PDU::SuccessfulOutcome(m) => (
            Kind::Successful,
            m.procedure_code.0,
            m.nrppatransaction_id.0,
        ),
        nrppa::NRPPA_PDU::UnsuccessfulOutcome(m) => (
            Kind::Unsuccessful,
            m.procedure_code.0,
            m.nrppatransaction_id.0,
        ),
    })
}

/// The NRPPa PDU type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Initiating,
    Successful,
    Unsuccessful,
}

/// An SFN and slot time stamp: TS 38.455 `TimeStamp` (gNB side) or TS 37.355
/// `NR-TimeStamp-r16` (UE side). Both name the SFN and slot of the TRP the
/// measurement was made on, so two of them for one TRP are on the same clock.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SlotTime {
    /// System frame number, 0..1023.
    pub sfn: u16,
    /// Slot within the frame.
    pub slot: u8,
    /// Slots per 10 ms frame for the reported subcarrier spacing: 10, 20, 40, 80.
    pub slots_per_frame: u8,
}

/// The SFN cycle, in ms: 1024 frames of 10 ms (TS 38.211 §4.3.1).
pub const SFN_CYCLE_MS: f64 = 10_240.0;

/// `SlotTime(sfn.slot/slots-per-frame)`: compact, so a `CellMeasurement` debug line
/// stays one flat field list.
impl std::fmt::Debug for SlotTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SlotTime({}.{}/{})",
            self.sfn, self.slot, self.slots_per_frame
        )
    }
}

impl SlotTime {
    /// The start of the slot within the SFN cycle, in ms.
    pub fn ms(&self) -> f64 {
        f64::from(self.sfn) * 10.0
            + f64::from(self.slot) * 10.0 / f64::from(self.slots_per_frame.max(1))
    }

    /// The distance to `other` in ms, across the SFN wrap: two time stamps either
    /// side of SFN 1023 → 0 are close, not 10 s apart.
    pub fn distance_ms(&self, other: &SlotTime) -> f64 {
        let d = (self.ms() - other.ms()).abs() % SFN_CYCLE_MS;
        d.min(SFN_CYCLE_MS - d)
    }
}

/// What the gNB said about one of its TRPs (TS 38.455 §9.2.25 `TRP Information`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TrpInfo {
    pub trp_id: u16,
    /// NR PCI of the TRP's cell (`pCI-NR`). The UE half of a Multi-RTT
    /// measurement names its TRP by this, so it is what the two halves meet on.
    pub pci: Option<u16>,
    /// The NR CGI (`cGI-NR`), in the registry's `<plmn hex>-<9 hex>` spelling.
    pub nr_cgi: Option<String>,
    /// The TRP's position (`geographicalCoordinates`, a direct position).
    pub coord: Option<TrpCoord>,
    /// The NR CGI in the form LPP's `NCGI-r15` takes (#911).
    pub ncgi: Option<crate::dl_prs_assistance::Ncgi>,
    /// `aRFCN`, the NR-ARFCN (#911).
    pub arfcn: Option<u32>,
    /// `pRSConfiguration`, the TRP's DL-PRS (#911, TS 38.455 §9.2.44).
    pub prs: Option<nrppa::PRSConfiguration>,
    /// `sFNInitialisationTime` (TS 38.455 §9.2.36) as 32.32 fixed-point seconds
    /// since 1900 (#911).
    pub sfn_init: Option<u64>,
}

/// The PCIs that TRP Information reports on more than one TRP (#903 review). A
/// PCI names a cell, not a TRP: a multi-TRP cell has several TRPs under one PCI,
/// and PCIs are reused across sites. The UE half names its TRP by PCI, so a TRP
/// whose PCI is ambiguous cannot be paired and is not measured.
pub fn ambiguous_pcis<'a>(trps: impl Iterator<Item = &'a TrpInfo>) -> Vec<u16> {
    let mut seen: Vec<u16> = Vec::new();
    let mut twice: Vec<u16> = Vec::new();
    for pci in trps.filter_map(|t| t.pci) {
        if seen.contains(&pci) {
            if !twice.contains(&pci) {
                twice.push(pci);
            }
        } else {
            seen.push(pci);
        }
    }
    twice
}

/// The gNB half of one TRP's Multi-RTT measurement.
#[derive(Debug, Clone, PartialEq)]
pub struct GnbRxTx {
    pub trp_id: u16,
    /// gNB Rx-Tx time difference (TS 38.215 §5.2.3), signed ns. `None` for an
    /// open-ended report value (TS 38.133), which is a bin edge, not a measurement.
    pub rx_tx_ns: Option<f64>,
    /// When the gNB measured it.
    pub time: Option<SlotTime>,
}

/// The Positioning Information the serving gNB returned (TS 38.455 §9.1.1.x).
#[derive(Debug, Clone, PartialEq)]
pub struct PositioningInformation {
    pub srs_configuration: Option<nrppa::SRSConfiguration>,
    pub sfn_initialisation_time: Option<nrppa::RelativeTime1900>,
}

fn reject_unknown(unknown: &[UnknownIe], what: &str) -> Result<(), String> {
    match unknown
        .iter()
        .find(|ie| ie.criticality.is_none_or(|c| c == REJECT))
    {
        Some(ie) => Err(format!(
            "{what}: IE {} not comprehended with criticality reject; the procedure is \
             unsuccessfully terminated (TS 38.413 §10.3.4.2)",
            ie.id
        )),
        None => Ok(()),
    }
}

fn decode(bytes: &[u8]) -> Result<(nrppa::NRPPA_PDU, Vec<UnknownIe>), String> {
    nextgcore_nrppa_gen::decode_with_unknown_ies(bytes).map_err(|e| format!("NRPPa decode: {e:?}"))
}

fn cause_text(cause: &nrppa::Cause) -> String {
    format!("{cause:?}")
}

/// Decode the answer to a TRP Information Request.
pub fn decode_trp_information_response(bytes: &[u8]) -> Result<Vec<TrpInfo>, String> {
    let (pdu, unknown) = decode(bytes)?;
    match pdu {
        nrppa::NRPPA_PDU::SuccessfulOutcome(nrppa::SuccessfulOutcome {
            value: nrppa::SuccessfulOutcomeValue::Id_tRPInformationExchange(rsp),
            ..
        }) => {
            reject_unknown(&unknown, "TRP Information Response")?;
            let list = rsp.protocol_i_es.0.into_iter().find_map(|ie| match ie.value {
                nrppa::TRPInformationResponseProtocolIEs_EntryValue::Id_TRPInformationListTRPResp(l) => Some(l),
                _ => None,
            });
            let Some(list) = list else {
                return Err(
                    "TRP Information Response without the mandatory TRP Information List \
                     (criticality ignore): no TRP to use"
                        .to_string(),
                );
            };
            Ok(list
                .0
                .iter()
                .map(|e| trp_info(&e.trp_information))
                .collect())
        }
        nrppa::NRPPA_PDU::UnsuccessfulOutcome(nrppa::UnsuccessfulOutcome {
            value: nrppa::UnsuccessfulOutcomeValue::Id_tRPInformationExchange(f),
            ..
        }) => Err(format!(
            "TRP Information Failure: {}",
            f.protocol_i_es
                .0
                .iter()
                .find_map(|ie| match &ie.value {
                    nrppa::TRPInformationFailureProtocolIEs_EntryValue::Id_Cause(c) =>
                        Some(cause_text(c)),
                    _ => None,
                })
                .unwrap_or_default()
        )),
        _ => Err("not an answer to a TRP Information Request".to_string()),
    }
}

fn trp_info(t: &nrppa::TRPInformation) -> TrpInfo {
    let mut info = TrpInfo {
        trp_id: t.trp_id.0,
        ..TrpInfo::default()
    };
    for item in &t.trp_information_type_response_list.0 {
        use nrppa::TRPInformationTypeResponseItem as I;
        match item {
            I::PCI_NR(p) => info.pci = Some(p.0),
            I::CGI_NR(c) => {
                info.nr_cgi = Some(cgi_nr_to_string(c));
                info.ncgi = crate::dl_prs_assistance::Ncgi::from_nrppa(c);
            }
            I::ARFCN(a) => info.arfcn = Some(a.0),
            I::PRSConfiguration(p) => info.prs = Some(p.clone()),
            I::SFNInitialisationTime(t) => info.sfn_init = relative_time_1900(t),
            I::GeographicalCoordinates(g) => info.coord = geographical_coordinates(g),
            _ => {}
        }
    }
    info
}

/// A `RelativeTime1900` (BIT STRING (SIZE(64))) as 32.32 fixed-point seconds.
fn relative_time_1900(t: &nrppa::RelativeTime1900) -> Option<u64> {
    (t.0.len() == 64).then(|| t.0.iter().fold(0u64, |acc, b| (acc << 1) | u64::from(*b)))
}

/// `<plmn hex>-<9 hex digits>`, the spelling `nrppa_uplink` keys NR cells by.
pub fn cgi_nr_to_string(c: &nrppa::CGI_NR) -> String {
    let plmn: String = c
        .plmn_identity
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let cell = c
        .n_rcell_identifier
        .0
        .iter()
        .fold(0u64, |acc, b| (acc << 1) | u64::from(*b));
    format!("{plmn}-{cell:09x}")
}

/// A TRP's direct position as a geodetic coordinate (TS 23.032 §6.1 for the
/// ellipsoid point with altitude, §6.1 high-accuracy form for `tRPHAposition`).
/// A `referenced` position (relative to another point) is `None`: it would need the
/// reference point's coordinate, which a TRP Information Response does not carry.
fn geographical_coordinates(g: &nrppa::GeographicalCoordinates) -> Option<TrpCoord> {
    let nrppa::TRPPositionDefinitionType::Direct(direct) = &g.trp_position_definition_type else {
        return None;
    };
    match &direct.accuracy {
        nrppa::TRPPositionDirectAccuracy::TRPPosition(p) => {
            // TS 23.032 §6.1: N = ⌊2^23·|lat|/90⌋, N = ⌊2^24·lon/360⌋, altitude in m.
            // The bin's centre is taken: N names the interval [N, N+1).
            let mut lat = (f64::from(p.latitude.0) + 0.5) * 90.0 / f64::from(1u32 << 23);
            if p.latitude_sign.0 == 1 {
                lat = -lat;
            }
            let lon = (f64::from(p.longitude.0) + 0.5) * 360.0 / f64::from(1u32 << 24);
            let mut height = f64::from(p.altitude.0);
            if p.direction_of_altitude.0 == 1 {
                height = -height;
            }
            Some(TrpCoord {
                lat_deg: lat,
                lon_deg: lon,
                height_m: height,
            })
        }
        nrppa::TRPPositionDirectAccuracy::TRPHAposition(p) => {
            // High-accuracy ellipsoid point: lat = N·90/2^31, lon = N·180/2^31,
            // altitude in 0.01 m.
            let scale = f64::from(1u32 << 31);
            Some(TrpCoord {
                lat_deg: (f64::from(p.latitude.0) + 0.5) * 90.0 / scale,
                lon_deg: (f64::from(p.longitude.0) + 0.5) * 180.0 / scale,
                height_m: f64::from(p.altitude.0) / 100.0,
            })
        }
        nrppa::TRPPositionDirectAccuracy::Choice_extension(_) => None,
    }
}

/// Decode the answer to a Positioning Information Request.
pub fn decode_positioning_information_response(
    bytes: &[u8],
) -> Result<PositioningInformation, String> {
    let (pdu, unknown) = decode(bytes)?;
    match pdu {
        nrppa::NRPPA_PDU::SuccessfulOutcome(nrppa::SuccessfulOutcome {
            value: nrppa::SuccessfulOutcomeValue::Id_positioningInformationExchange(rsp),
            ..
        }) => {
            reject_unknown(&unknown, "Positioning Information Response")?;
            let mut info = PositioningInformation {
                srs_configuration: None,
                sfn_initialisation_time: None,
            };
            for ie in rsp.protocol_i_es.0 {
                use nrppa::PositioningInformationResponseProtocolIEs_EntryValue as V;
                match ie.value {
                    V::Id_SRSConfiguration(c) => info.srs_configuration = Some(c),
                    V::Id_SFNInitialisationTime(t) => info.sfn_initialisation_time = Some(t),
                    _ => {}
                }
            }
            Ok(info)
        }
        nrppa::NRPPA_PDU::UnsuccessfulOutcome(nrppa::UnsuccessfulOutcome {
            value: nrppa::UnsuccessfulOutcomeValue::Id_positioningInformationExchange(f),
            ..
        }) => Err(format!(
            "Positioning Information Failure: {}",
            f.protocol_i_es
                .0
                .iter()
                .find_map(|ie| match &ie.value {
                    nrppa::PositioningInformationFailureProtocolIEs_EntryValue::Id_Cause(c) =>
                        Some(cause_text(c)),
                    _ => None,
                })
                .unwrap_or_default()
        )),
        _ => Err("not an answer to a Positioning Information Request".to_string()),
    }
}

/// The SRS to activate for `srs`, per TS 38.455 §8.2.9: the first semi-persistent
/// positioning (or, failing one, plain) SRS resource set, else an aperiodic trigger
/// when an aperiodic set is configured. `None` when every configured set is
/// periodic: periodic SRS needs no activation.
pub fn srs_activation(
    srs: &nrppa::SRSConfiguration,
) -> Option<crate::nrppa_downlink::SrsActivation> {
    use crate::nrppa_downlink::SrsActivation;
    let mut aperiodic = false;
    for carrier in &srs.srs_carrier_list.0 {
        let config = &carrier.active_ulbwp.srs_config;
        for set in config
            .pos_srs_resource_set_list
            .iter()
            .flat_map(|l| l.0.iter())
        {
            match set.posresource_set_type {
                nrppa::PosResourceSetType::Semi_persistent(_) => {
                    return Some(SrsActivation::SemiPersistent(set.possrs_resource_set_id.0));
                }
                nrppa::PosResourceSetType::Aperiodic(_) => aperiodic = true,
                _ => {}
            }
        }
        for set in config.srs_resource_set_list.iter().flat_map(|l| l.0.iter()) {
            match set.resource_set_type {
                nrppa::ResourceSetType::Semi_persistent(_) => {
                    return Some(SrsActivation::SemiPersistent(set.srs_resource_set_id1.0));
                }
                nrppa::ResourceSetType::Aperiodic(_) => aperiodic = true,
                _ => {}
            }
        }
    }
    aperiodic.then_some(SrsActivation::Aperiodic)
}

/// Decode the answer to a Positioning Activation Request: `Ok` when the gNB
/// activated the UE's SRS.
pub fn decode_positioning_activation_response(bytes: &[u8]) -> Result<(), String> {
    let (pdu, unknown) = decode(bytes)?;
    match pdu {
        nrppa::NRPPA_PDU::SuccessfulOutcome(nrppa::SuccessfulOutcome {
            value: nrppa::SuccessfulOutcomeValue::Id_positioningActivation(_),
            ..
        }) => reject_unknown(&unknown, "Positioning Activation Response"),
        nrppa::NRPPA_PDU::UnsuccessfulOutcome(nrppa::UnsuccessfulOutcome {
            value: nrppa::UnsuccessfulOutcomeValue::Id_positioningActivation(f),
            ..
        }) => Err(format!(
            "Positioning Activation Failure: {}",
            f.protocol_i_es
                .0
                .iter()
                .find_map(|ie| match &ie.value {
                    nrppa::PositioningActivationFailureProtocolIEs_EntryValue::Id_Cause(c) =>
                        Some(cause_text(c)),
                    _ => None,
                })
                .unwrap_or_default()
        )),
        _ => Err("not an answer to a Positioning Activation Request".to_string()),
    }
}

/// Decode the answer to a Measurement Request: the gNB Rx-Tx time differences of
/// its TRPs.
///
/// `lmf_measurement_id` must be the one the request carried. A response for another
/// measurement is refused rather than used: it would pair a TRP's gNB half with a
/// different UE's UE half.
pub fn decode_measurement_response(
    bytes: &[u8],
    lmf_measurement_id: u32,
) -> Result<Vec<GnbRxTx>, String> {
    let (pdu, unknown) = decode(bytes)?;
    match pdu {
        nrppa::NRPPA_PDU::SuccessfulOutcome(nrppa::SuccessfulOutcome {
            value: nrppa::SuccessfulOutcomeValue::Id_Measurement(rsp),
            ..
        }) => {
            reject_unknown(&unknown, "Measurement Response")?;
            let mut lmf_id = None;
            let mut ran_id = None;
            let mut list = None;
            for ie in rsp.protocol_i_es.0 {
                use nrppa::MeasurementResponseProtocolIEs_EntryValue as V;
                match ie.value {
                    V::Id_LMF_Measurement_ID(id) => lmf_id = Some(id.0),
                    V::Id_RAN_Measurement_ID(id) => ran_id = Some(id.0),
                    V::Id_TRP_MeasurementResponseList(l) => list = Some(l),
                    V::Id_CriticalityDiagnostics(_) => {}
                }
            }
            // Both measurement ids are mandatory with criticality reject.
            let (Some(lmf_id), Some(_)) = (lmf_id, ran_id) else {
                return Err(
                    "Measurement Response without its LMF/RAN Measurement-ID (mandatory, \
                     criticality reject): unsuccessfully terminated (TS 38.413 §10.3.4.2)"
                        .to_string(),
                );
            };
            if lmf_id != lmf_measurement_id {
                return Err(format!(
                    "Measurement Response for LMF-Measurement-ID {lmf_id}, but the request \
                     carried {lmf_measurement_id}"
                ));
            }
            Ok(list.map(|l| gnb_rx_tx_list(&l)).unwrap_or_default())
        }
        nrppa::NRPPA_PDU::UnsuccessfulOutcome(nrppa::UnsuccessfulOutcome {
            value: nrppa::UnsuccessfulOutcomeValue::Id_Measurement(f),
            ..
        }) => Err(format!(
            "Measurement Failure: {}",
            f.protocol_i_es
                .0
                .iter()
                .find_map(|ie| match &ie.value {
                    nrppa::MeasurementFailureProtocolIEs_EntryValue::Id_Cause(c) =>
                        Some(cause_text(c)),
                    _ => None,
                })
                .unwrap_or_default()
        )),
        _ => Err("not an answer to a Measurement Request".to_string()),
    }
}

fn gnb_rx_tx_list(list: &nrppa::TRP_MeasurementResponseList) -> Vec<GnbRxTx> {
    let mut out = Vec::new();
    for item in &list.0 {
        for result in &item.measurement_result.0 {
            if let nrppa::TrpMeasuredResultsValue::GNB_RxTxTimeDiff(d) =
                &result.measured_results_value
            {
                out.push(GnbRxTx {
                    trp_id: item.trp_id.0,
                    rx_tx_ns: gnb_rx_tx_report(&d.rx_tx_time_diff)
                        .and_then(crate::codec_glue::ue_rx_tx_to_signed_ns),
                    time: time_stamp(&result.time_stamp),
                });
            }
        }
    }
    out
}

/// The (v, k) of a gNB Rx-Tx report. TS 38.455 §9.2.40 gives it the arms of the
/// UE Rx-Tx (k0..k5 in the root, kminus1..kminus6 as extensions) and refers both to
/// TS 38.133, so it is decoded by the same rule, open-ended values included.
fn gnb_rx_tx_report(m: &nrppa::GNBRxTxTimeDiffMeas) -> Option<crate::codec_glue::TimeReport> {
    use crate::codec_glue::TimeReport;
    use nrppa::GNBRxTxTimeDiffMeas as M;
    let (v, k): (u32, i8) = match m {
        M::K0(x) => (x.0, 0),
        M::K1(x) => (x.0, 1),
        M::K2(x) => (x.0, 2),
        M::K3(x) => (x.0, 3),
        M::K4(x) => (x.0, 4),
        M::K5(x) => (u32::from(x.0), 5),
        M::Choice_extension(e) => {
            use nrppa::GNBRxTxTimeDiffMeas_choice_extensionValue as E;
            match &e.value {
                E::Id_ReportingGranularitykminus1(x) => (x.0, -1),
                E::Id_ReportingGranularitykminus2(x) => (x.0, -2),
                E::Id_ReportingGranularitykminus3(x) => (x.0, -3),
                E::Id_ReportingGranularitykminus4(x) => (x.0, -4),
                E::Id_ReportingGranularitykminus5(x) => (x.0, -5),
                E::Id_ReportingGranularitykminus6(x) => (x.0, -6),
            }
        }
    };
    Some(TimeReport { v, k })
}

/// A TS 38.455 `TimeStamp` as a [`SlotTime`]. `None` for a slot index of an
/// extension subcarrier spacing (480/960 kHz), which this LMF does not pair.
fn time_stamp(t: &nrppa::TimeStamp) -> Option<SlotTime> {
    use nrppa::TimeStampSlotIndex as S;
    let (slot, slots_per_frame) = match &t.slot_index {
        S::SCS_15(s) => (s.0, 10),
        S::SCS_30(s) => (s.0, 20),
        S::SCS_60(s) => (s.0, 40),
        S::SCS_120(s) => (s.0, 80),
        S::Choice_extension(_) => return None,
    };
    Some(SlotTime {
        sfn: t.system_frame_number.0,
        slot,
        slots_per_frame,
    })
}

/// Test builders for the gNB's answers, on the generated codec.
#[cfg(test)]
pub mod test_support {
    use super::nrppa;
    use bitvec::prelude::*;

    pub fn successful(procedure: u8, txn: u16, value: nrppa::SuccessfulOutcomeValue) -> Vec<u8> {
        nextgcore_nrppa_gen::encode(&nrppa::NRPPA_PDU::SuccessfulOutcome(
            nrppa::SuccessfulOutcome {
                procedure_code: nrppa::ProcedureCode(procedure),
                criticality: nrppa::Criticality(super::REJECT),
                nrppatransaction_id: nrppa::NRPPATransactionID(txn),
                value,
            },
        ))
        .expect("generated encode")
    }

    pub fn cgi_nr(plmn: [u8; 3], cell: u64) -> nrppa::CGI_NR {
        let mut bits: BitVec<u8, Msb0> = BitVec::new();
        for i in (0..36).rev() {
            bits.push((cell >> i) & 1 == 1);
        }
        nrppa::CGI_NR {
            plmn_identity: nrppa::PLMN_Identity(plmn.to_vec()),
            n_rcell_identifier: nrppa::NRCellIdentifier(bits),
            ie_extensions: None,
        }
    }

    /// A TRP Information Response listing `(trp id, pci, high-accuracy lat/lon/alt
    /// raw values)`.
    pub fn trp_information_response(txn: u16, trps: &[(u16, u16, i32, i32, i32)]) -> Vec<u8> {
        use nrppa::TRPInformationTypeResponseItem as I;
        trp_information_response_items(
            txn,
            trps.iter()
                .map(|&(id, pci, lat, lon, alt)| {
                    (
                        id,
                        vec![
                            I::PCI_NR(nrppa::TRPInformationTypeResponseItem_pCI_NR(pci)),
                            geographical(lat, lon, alt),
                        ],
                    )
                })
                .collect(),
        )
    }

    /// A high-accuracy direct TRP position.
    pub fn geographical(lat: i32, lon: i32, alt: i32) -> nrppa::TRPInformationTypeResponseItem {
        nrppa::TRPInformationTypeResponseItem::GeographicalCoordinates(
            nrppa::GeographicalCoordinates {
                trp_position_definition_type: nrppa::TRPPositionDefinitionType::Direct(
                    nrppa::TRPPositionDirect {
                        accuracy: nrppa::TRPPositionDirectAccuracy::TRPHAposition(ha_position(
                            lat, lon, alt,
                        )),
                        ie_extensions: None,
                    },
                ),
                dlprs_resource_coordinates: None,
                ie_extensions: None,
            },
        )
    }

    /// A TRP Information Response with the given items per TRP id (#911).
    pub fn trp_information_response_items(
        txn: u16,
        trps: Vec<(u16, Vec<nrppa::TRPInformationTypeResponseItem>)>,
    ) -> Vec<u8> {
        let entries = trps
            .into_iter()
            .map(|(id, items)| nrppa::TRPInformationListTRPResp_Entry {
                trp_information: nrppa::TRPInformation {
                    trp_id: nrppa::TRP_ID(id),
                    trp_information_type_response_list: nrppa::TRPInformationTypeResponseList(
                        items,
                    ),
                    ie_extensions: None,
                },
                ie_extensions: None,
            })
            .collect();
        successful(
            nrppa::ID_T_RP_INFORMATION_EXCHANGE,
            txn,
            nrppa::SuccessfulOutcomeValue::Id_tRPInformationExchange(
                nrppa::TRPInformationResponse {
                    protocol_i_es: nrppa::TRPInformationResponseProtocolIEs(vec![
                        nrppa::TRPInformationResponseProtocolIEs_Entry {
                            id: nrppa::ProtocolIE_ID(nrppa::ID_TRP_INFORMATION_LIST_TRP_RESP),
                            criticality: nrppa::Criticality(1),
                            value: nrppa::TRPInformationResponseProtocolIEs_EntryValue::Id_TRPInformationListTRPResp(
                                nrppa::TRPInformationListTRPResp(entries),
                            ),
                        },
                    ]),
                },
            ),
        )
    }

    pub fn ha_position(
        lat: i32,
        lon: i32,
        alt: i32,
    ) -> nrppa::NGRANHighAccuracyAccessPointPosition {
        nrppa::NGRANHighAccuracyAccessPointPosition {
            latitude: nrppa::NGRANHighAccuracyAccessPointPositionLatitude(lat),
            longitude: nrppa::NGRANHighAccuracyAccessPointPositionLongitude(lon),
            altitude: nrppa::NGRANHighAccuracyAccessPointPositionAltitude(alt),
            uncertainty_semi_major:
                nrppa::NGRANHighAccuracyAccessPointPositionUncertaintySemi_major(0),
            uncertainty_semi_minor:
                nrppa::NGRANHighAccuracyAccessPointPositionUncertaintySemi_minor(0),
            orientation_of_major_axis:
                nrppa::NGRANHighAccuracyAccessPointPositionOrientationOfMajorAxis(0),
            horizontal_confidence: nrppa::NGRANHighAccuracyAccessPointPositionHorizontalConfidence(
                95,
            ),
            uncertainty_altitude: nrppa::NGRANHighAccuracyAccessPointPositionUncertaintyAltitude(0),
            vertical_confidence: nrppa::NGRANHighAccuracyAccessPointPositionVerticalConfidence(95),
            ie_extensions: None,
        }
    }

    /// One semi-persistent positioning SRS resource set `set`.
    pub fn srs_configuration(set: u8) -> nrppa::SRSConfiguration {
        nrppa::SRSConfiguration {
            srs_carrier_list: nrppa::SRSCarrier_List(vec![nrppa::SRSCarrier_List_Item {
                point_a: nrppa::SRSCarrier_List_ItemPointA(620_000),
                uplink_channel_bw_per_scs_list: nrppa::UplinkChannelBW_PerSCS_List(vec![
                    nrppa::SCS_SpecificCarrier {
                        offset_to_carrier: nrppa::SCS_SpecificCarrierOffsetToCarrier(0),
                        subcarrier_spacing: nrppa::SCS_SpecificCarrierSubcarrierSpacing(1),
                        carrier_bandwidth: nrppa::SCS_SpecificCarrierCarrierBandwidth(51),
                        ie_extensions: None,
                    },
                ]),
                active_ulbwp: nrppa::ActiveULBWP {
                    location_and_bandwidth: nrppa::ActiveULBWPLocationAndBandwidth(0),
                    subcarrier_spacing: nrppa::ActiveULBWPSubcarrierSpacing(1),
                    cyclic_prefix: nrppa::ActiveULBWPCyclicPrefix(0),
                    tx_direct_current_location: nrppa::ActiveULBWPTxDirectCurrentLocation(0),
                    shift7dot5k_hz: None,
                    srs_config: nrppa::SRSConfig {
                        srs_resource_list: None,
                        pos_srs_resource_list: None,
                        srs_resource_set_list: None,
                        pos_srs_resource_set_list: Some(nrppa::PosSRSResourceSet_List(vec![
                            nrppa::PosSRSResourceSet_Item {
                                possrs_resource_set_id:
                                    nrppa::PosSRSResourceSet_ItemPossrsResourceSetID(set),
                                poss_rs_resource_id_per_set_list:
                                    nrppa::PosSRSResourceIDPerSet_List(vec![
                                        nrppa::SRSPosResourceID(0),
                                    ]),
                                posresource_set_type: nrppa::PosResourceSetType::Semi_persistent(
                                    nrppa::PosResourceSetTypeSemi_persistent {
                                        possemi_persistent_set:
                                            nrppa::PosResourceSetTypeSemi_persistentPossemi_persistentSet(0),
                                        ie_extensions: None,
                                    },
                                ),
                                ie_extensions: None,
                            },
                        ])),
                        ie_extensions: None,
                    },
                    ie_extensions: None,
                },
                pci_nr: None,
                ie_extensions: None,
            }]),
            ie_extensions: None,
        }
    }

    pub fn positioning_information_response(txn: u16, srs: nrppa::SRSConfiguration) -> Vec<u8> {
        use nrppa::PositioningInformationResponseProtocolIEs_EntryValue as V;
        successful(
            nrppa::ID_POSITIONING_INFORMATION_EXCHANGE,
            txn,
            nrppa::SuccessfulOutcomeValue::Id_positioningInformationExchange(
                nrppa::PositioningInformationResponse {
                    protocol_i_es: nrppa::PositioningInformationResponseProtocolIEs(vec![
                        nrppa::PositioningInformationResponseProtocolIEs_Entry {
                            id: nrppa::ProtocolIE_ID(nrppa::ID_SRS_CONFIGURATION),
                            criticality: nrppa::Criticality(1),
                            value: V::Id_SRSConfiguration(srs),
                        },
                    ]),
                },
            ),
        )
    }

    /// A MEASUREMENT FAILURE (TS 38.455 §8.5.1.3).
    pub fn measurement_failure(txn: u16, lmf_measurement_id: u32) -> Vec<u8> {
        use nrppa::MeasurementFailureProtocolIEs_EntryValue as V;
        nextgcore_nrppa_gen::encode(&nrppa::NRPPA_PDU::UnsuccessfulOutcome(
            nrppa::UnsuccessfulOutcome {
                procedure_code: nrppa::ProcedureCode(nrppa::ID_MEASUREMENT),
                criticality: nrppa::Criticality(super::REJECT),
                nrppatransaction_id: nrppa::NRPPATransactionID(txn),
                value: nrppa::UnsuccessfulOutcomeValue::Id_Measurement(nrppa::MeasurementFailure {
                    protocol_i_es: nrppa::MeasurementFailureProtocolIEs(vec![
                        nrppa::MeasurementFailureProtocolIEs_Entry {
                            id: nrppa::ProtocolIE_ID(nrppa::ID_LMF_MEASUREMENT_ID),
                            criticality: nrppa::Criticality(super::REJECT),
                            value: V::Id_LMF_Measurement_ID(nrppa::Measurement_ID(
                                lmf_measurement_id,
                            )),
                        },
                        nrppa::MeasurementFailureProtocolIEs_Entry {
                            id: nrppa::ProtocolIE_ID(nrppa::ID_CAUSE),
                            criticality: nrppa::Criticality(1),
                            value: V::Id_Cause(nrppa::Cause::RadioNetwork(
                                nrppa::CauseRadioNetwork(
                                    nrppa::CauseRadioNetwork::REQUESTED_ITEM_NOT_SUPPORTED,
                                ),
                            )),
                        },
                    ]),
                }),
            },
        ))
        .expect("generated encode")
    }

    pub fn positioning_activation_response(txn: u16) -> Vec<u8> {
        successful(
            nrppa::ID_POSITIONING_ACTIVATION,
            txn,
            nrppa::SuccessfulOutcomeValue::Id_positioningActivation(
                nrppa::PositioningActivationResponse {
                    protocol_i_es: nrppa::PositioningActivationResponseProtocolIEs(vec![]),
                },
            ),
        )
    }

    /// A Measurement Response with one gNB Rx-Tx result per `(trp id, k1 report
    /// value, sfn, slot at 30 kHz)`.
    pub fn measurement_response(
        txn: u16,
        lmf_measurement_id: u32,
        results: &[(u16, u32, u16, u8)],
    ) -> Vec<u8> {
        use nrppa::MeasurementResponseProtocolIEs_EntryValue as V;
        let items = results
            .iter()
            .map(|&(trp, v, sfn, slot)| nrppa::TRP_MeasurementResponseItem {
                trp_id: nrppa::TRP_ID(trp),
                measurement_result: nrppa::TrpMeasurementResult(vec![
                    nrppa::TrpMeasurementResultItem {
                        measured_results_value: nrppa::TrpMeasuredResultsValue::GNB_RxTxTimeDiff(
                            nrppa::GNB_RxTxTimeDiff {
                                rx_tx_time_diff: nrppa::GNBRxTxTimeDiffMeas::K1(
                                    nrppa::GNBRxTxTimeDiffMeas_k1(v),
                                ),
                                additional_path_list: None,
                                ie_extensions: None,
                            },
                        ),
                        time_stamp: nrppa::TimeStamp {
                            system_frame_number: nrppa::SystemFrameNumber(sfn),
                            slot_index: nrppa::TimeStampSlotIndex::SCS_30(
                                nrppa::TimeStampSlotIndex_sCS_30(slot),
                            ),
                            measurement_time: None,
                            ie_extension: None,
                        },
                        measurement_quality: None,
                        measurement_beam_info: None,
                        ie_extensions: None,
                    },
                ]),
                ie_extensions: None,
            })
            .collect();
        let entry = |id: u16, value: V| nrppa::MeasurementResponseProtocolIEs_Entry {
            id: nrppa::ProtocolIE_ID(id),
            criticality: nrppa::Criticality(super::REJECT),
            value,
        };
        successful(
            nrppa::ID_MEASUREMENT,
            txn,
            nrppa::SuccessfulOutcomeValue::Id_Measurement(nrppa::MeasurementResponse {
                protocol_i_es: nrppa::MeasurementResponseProtocolIEs(vec![
                    entry(
                        nrppa::ID_LMF_MEASUREMENT_ID,
                        V::Id_LMF_Measurement_ID(nrppa::Measurement_ID(lmf_measurement_id)),
                    ),
                    entry(
                        nrppa::ID_RAN_MEASUREMENT_ID,
                        V::Id_RAN_Measurement_ID(nrppa::Measurement_ID(7)),
                    ),
                    entry(
                        nrppa::ID_TRP_MEASUREMENT_RESPONSE_LIST,
                        V::Id_TRP_MeasurementResponseList(nrppa::TRP_MeasurementResponseList(
                            items,
                        )),
                    ),
                ]),
            }),
        )
    }
}

#[cfg(test)]
mod tests;
