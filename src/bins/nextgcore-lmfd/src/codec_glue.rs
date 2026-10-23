//! Codec decode glue — lmfd-05/06
//!
//! Adapts raw NRPPa APER (TS 38.455) and LPP UPER (TS 37.355) PDUs into the
//! flat [`CellMeasurement`] list expected by
//! [`crate::LmfContext::measurement_report`].
//!
//! Two public adapter functions:
//!
//! - [`decode_nrppa_ecid_report`] — E-CID Measurement Report (procedure code 4),
//!   decoded and adapted by [`crate::nrppa_uplink`] on the generated NRPPa codec:
//!   serving-cell NG-RAN-CGI → `nr_cgi`; measuredResults CHOICE →
//!   `ecid_rtt_ns` (TADV, TS 36.133 §10.3.1), `aoa`, `rsrp`, `rsrq`.
//!
//! - [`lpp_multi_rtt_provide_to_measurements`] — ProvideLocationInformation →
//!   nr-Multi-RTT list: `nr-UE-RxTxTimeDiff` k-arm → `ue_rx_tx_ns` (signed
//!   nanoseconds, TS 38.133 §10.1.25.3); `nr_phys_cell_id` → `nr_cgi`. That is the
//!   UE half of an RTT only (#713).
//!
//! - [`lpp_dl_tdoa_provide_to_measurements`] — ProvideLocationInformation →
//!   nr-DL-TDOA list: the reference TRP with RSTD 0, then each neighbour's signed
//!   `nr-RSTD-r16` → `rstd_ns`. `context::try_real_solve` solves it with
//!   `solve_tdoa`; it is the high-accuracy method while Multi-RTT lacks the gNB
//!   half (#713, #807). Its reference keying is fixed by #714.
//!
//! Two combined decode+adapt helpers — [`decode_nrppa_ecid_report`] and
//! [`decode_lpp_multi_rtt_report`] — are used by the inbound SBI handlers in
//! `main.rs`.

pub use crate::sidelink_epdu::SidelinkRangingMethod;
use crate::CellMeasurement;
use nextgcore_lpp_gen::generated as lpp;

// ---------------------------------------------------------------------------
// Generated-codec envelope helpers (#515)
// ---------------------------------------------------------------------------

/// An `LPP-TransactionID` (TS 37.355 §6.2) on the generated codec.
fn transaction(initiator: u8, number: u8) -> lpp::LPP_TransactionID {
    lpp::LPP_TransactionID {
        initiator: lpp::Initiator(initiator),
        transaction_number: lpp::TransactionNumber(number),
    }
}

/// An `LPP-Message` carrying one c1 body, with no sequence number or
/// acknowledgement (this LMF does not run the LPP reliable-transport sublayer).
fn message(
    transaction_id: lpp::LPP_TransactionID,
    end_transaction: bool,
    body: lpp::LPP_MessageBody_c1,
) -> lpp::LPP_Message {
    lpp::LPP_Message {
        transaction_id: Some(transaction_id),
        end_transaction: lpp::LPP_MessageEndTransaction(end_transaction),
        sequence_number: None,
        acknowledgement: None,
        lpp_message_body: Some(lpp::LPP_MessageBody::C1(body)),
    }
}

/// UPER-encode a generated `LPP-Message`, naming what failed.
fn encode(msg: &lpp::LPP_Message, what: &str) -> Result<Vec<u8>, String> {
    nextgcore_lpp_gen::encode(msg).map_err(|e| format!("LPP {what} encode: {e:?}"))
}

/// UPER-decode one `LPP-Message` with the generated codec.
pub fn decode_lpp(bytes: &[u8]) -> Result<lpp::LPP_Message, String> {
    nextgcore_lpp_gen::decode(bytes).map_err(|e| format!("LPP UPER decode: {e:?}"))
}

/// A `BIT STRING` from flags, bit 0 first (the `requestedMeasurements` layout).
fn bits(flags: &[bool]) -> bitvec::vec::BitVec<u8, bitvec::order::Msb0> {
    flags.iter().copied().collect()
}

/// The c1 body of a decoded message, if it has one.
fn c1(msg: &lpp::LPP_Message) -> Option<&lpp::LPP_MessageBody_c1> {
    match msg.lpp_message_body.as_ref() {
        Some(lpp::LPP_MessageBody::C1(body)) => Some(body),
        _ => None,
    }
}

/// The r9 IEs of a `ProvideLocationInformation`, if the message is one.
fn provide_location_r9(msg: &lpp::LPP_Message) -> Option<&lpp::ProvideLocationInformation_r9_IEs> {
    match c1(msg)? {
        lpp::LPP_MessageBody_c1::ProvideLocationInformation(p) => match &p.critical_extensions {
            lpp::ProvideLocationInformationCriticalExtensions::C1(
                lpp::ProvideLocationInformationCriticalExtensions_c1::ProvideLocationInformation_r9(
                    ies,
                ),
            ) => Some(ies),
            _ => None,
        },
        _ => None,
    }
}

/// A `RequestLocationInformation` with the given r9 IEs, initiated by this LMF.
fn request_location(
    transaction_number: u8,
    ies: lpp::RequestLocationInformation_r9_IEs,
) -> lpp::LPP_Message {
    message(
        transaction(lpp::Initiator::LOCATION_SERVER, transaction_number),
        false,
        lpp::LPP_MessageBody_c1::RequestLocationInformation(lpp::RequestLocationInformation {
            critical_extensions: lpp::RequestLocationInformationCriticalExtensions::C1(
                lpp::RequestLocationInformationCriticalExtensions_c1::RequestLocationInformation_r9(
                    ies,
                ),
            ),
        }),
    )
}

/// Empty r9 IEs for a `RequestLocationInformation`.
fn empty_request_ies() -> lpp::RequestLocationInformation_r9_IEs {
    lpp::RequestLocationInformation_r9_IEs {
        common_i_es_request_location_information: None,
        a_gnss_request_location_information: None,
        otdoa_request_location_information: None,
        ecid_request_location_information: None,
        epdu_request_location_information: None,
        extensions: Default::default(),
    }
}

/// The E-UTRA E-CID request body (TS 37.355 §6.5.3
/// `ECID-RequestLocationInformation`): bit0 rsrpReq, bit1 rsrqReq, bit2 ueRxTxReq.
///
/// ueRxTxReq is set (#715): the UE Rx–Tx time difference is the E-CID timing
/// term (`ecid_rtt_ns`), and a conformant UE does not report what it was not
/// asked for. Without it an LPP-only E-CID session had no timing term to solve.
fn ecid_request_ies() -> lpp::RequestLocationInformation_r9_IEs {
    lpp::RequestLocationInformation_r9_IEs {
        ecid_request_location_information: Some(lpp::ECID_RequestLocationInformation {
            requested_measurements: lpp::ECID_RequestLocationInformationRequestedMeasurements(
                bits(&[true, true, true]),
            ),
        }),
        ..empty_request_ies()
    }
}

/// The NR E-CID request body (TS 37.355 Rel-16 `NR-ECID-RequestLocationInformation-r16`,
/// an extension addition of `RequestLocationInformation-r9-IEs`): bit0 ssrsrpReq,
/// bit1 ssrsrqReq (#715).
///
/// CSI-RS RSRP/RSRQ (bits 2 and 3) are not asked for. They need a CSI-RS
/// configuration the E-CID solver does not use, and the serving cell is chosen on
/// SS-RSRP. NR E-CID over LPP has no UE timing quantity at all, so the timing term
/// of an NR E-CID fix comes from the NRPPa E-CID leg (TS 38.305 §8.6).
fn nr_ecid_request_ies() -> lpp::RequestLocationInformation_r9_IEs {
    let mut ies = empty_request_ies();
    ies.extensions.nr_ecid_request_location_information_r16 =
        Some(lpp::NR_ECID_RequestLocationInformation_r16 {
            requested_measurements_r16:
                lpp::NR_ECID_RequestLocationInformation_r16RequestedMeasurements_r16(bits(&[
                    true, true,
                ])),
        });
    ies
}

/// Encode an LMF-initiated LPP `RequestLocationInformation` (TS 37.355 §6.2,
/// message body c1 index 4) requesting E-UTRA E-CID measurements (rsrpReq,
/// rsrqReq, ueRxTxReq),
/// for transport to the target UE inside a Namf_Communication
/// N1N2MessageTransfer. `transaction_number` correlates the eventual
/// `ProvideLocationInformation` response (TS 37.355 §6.1, initiator =
/// locationServer). Returns the UPER-encoded PDU.
pub fn build_lpp_ecid_request(transaction_number: u8) -> Result<Vec<u8>, String> {
    encode(
        &request_location(transaction_number, ecid_request_ies()),
        "RequestLocationInformation",
    )
}

/// Which LPP positioning method an LMF-initiated request asks for (#103).
///
/// Named separately from `positioning::PositioningMethodKind` (which describes what
/// a solver *produced*) because these are the methods this LMF can *request* over
/// LPP, and the two sets are not the same: AoA has a solver and no LPP request body
/// in this build, and asking for a method whose report it cannot decode would be
/// worse than not asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LppMethod {
    /// E-UTRA Enhanced Cell-ID (TS 37.355 §6.5.3): RSRP/RSRQ and the UE Rx–Tx.
    /// The fallback for a UE on E-UTRA (ng-eNB) access.
    Ecid,
    /// NR Enhanced Cell-ID (TS 37.355 Rel-16 `nr-ECID`, TS 38.305 §8.6): SS-RSRP
    /// and SS-RSRQ. The fallback for a UE on NR access (#715).
    NrEcid,
    /// NR Multi-RTT: UE Rx-Tx time differences against several TRPs.
    MultiRtt,
    /// NR DL-TDOA: reference-signal time differences.
    DlTdoa,
}

impl LppMethod {
    /// The TS 29.572 `PositioningMethod` string, for the response's
    /// `positioningMethod` member.
    pub fn as_spec_str(self) -> &'static str {
        match self {
            LppMethod::Ecid => "ECID",
            LppMethod::NrEcid => "NR_ECID",
            LppMethod::MultiRtt => "MULTI-RTT",
            LppMethod::DlTdoa => "DL_TDOA",
        }
    }
}

// ---------------------------------------------------------------------------
// #103: MO-LR assistance data (TS 37.355 §5.2, TS 23.273 §6.2)
// ---------------------------------------------------------------------------

/// Decode a UE-originated LPP PDU and report whether it is a
/// `RequestAssistanceData` (#103).
///
/// Before this, an MO-LR with `ueLocationServiceInd == LOCATION_ASSISTANCE_DATA`
/// answered 204 without looking at the UE's PDU at all — so a UE asking for
/// assistance got a success it could not use, and a UE asking for something else got
/// the same answer.
///
/// Returns the transaction number to answer on, so the response correlates: an
/// assistance-data response on the wrong transaction is one the UE discards.
pub fn decode_lpp_request_assistance_data(bytes: &[u8]) -> Result<u8, String> {
    let msg = decode_lpp(bytes).map_err(|e| e.replace("LPP UPER decode", "LPP decode"))?;
    let txn = msg
        .transaction_id
        .as_ref()
        .map(|t| t.transaction_number.0)
        .ok_or_else(|| "LPP message carries no transactionID to answer on".to_string())?;
    match c1(&msg) {
        Some(lpp::LPP_MessageBody_c1::RequestAssistanceData(_)) => Ok(txn),
        Some(other) => Err(format!(
            "LPP body is {}, not RequestAssistanceData",
            body_name(other)
        )),
        None => Err("LPP message carries no c1 body".to_string()),
    }
}

/// A body's name, for an error message that says what arrived instead.
fn body_name(body: &lpp::LPP_MessageBody_c1) -> &'static str {
    use lpp::LPP_MessageBody_c1 as B;
    match body {
        B::RequestCapabilities(_) => "RequestCapabilities",
        B::ProvideCapabilities(_) => "ProvideCapabilities",
        B::RequestAssistanceData(_) => "RequestAssistanceData",
        B::ProvideAssistanceData(_) => "ProvideAssistanceData",
        B::RequestLocationInformation(_) => "RequestLocationInformation",
        B::ProvideLocationInformation(_) => "ProvideLocationInformation",
        B::Abort(_) => "Abort",
        B::Error(_) => "Error",
        _ => "a spare c1 body",
    }
}

/// Build an LPP `ProvideAssistanceData` carrying a GNSS **reference location**
/// (#103, TS 37.355 §5.2).
///
/// # Why a reference location and not an ephemeris
///
/// A-GNSS assistance can be many things; what this LMF actually *knows* is where its
/// reference points are. A coarse reference position is genuine, useful assistance —
/// it is what lets a UE narrow its GNSS search — and it is derivable from the
/// configured registry with no external data source. Ephemerides, ionospheric models
/// and Earth-orientation parameters would all have to come from a GNSS data feed this
/// build has no client for, and fabricating them would be worse than omitting them.
///
/// So the response carries `gnssCommonAssistData.gnssReferenceLocation` and nothing
/// else, and that is stated rather than implied.
///
/// The uncertainty is honest too: `uncertainty_m` should be the spread of the
/// reference points the centroid was taken over, so a UE weighting the assistance by
/// its uncertainty is given the real figure rather than a confident-looking zero.
pub fn build_lpp_provide_assistance_data(
    transaction_number: u8,
    lat_deg: f64,
    lon_deg: f64,
    uncertainty_m: f64,
) -> Result<Vec<u8>, String> {
    use lpp::EllipsoidPointWithAltitudeAndUncertaintyEllipsoidAltitudeDirection as AltitudeDirection;
    use lpp::EllipsoidPointWithAltitudeAndUncertaintyEllipsoidLatitudeSign as LatitudeSign;

    // TS 23.032 §6.1 magnitude-and-sign, as the GAD encoders in `nlmf` already do
    // for the northbound body. Reused rather than re-derived so the two cannot
    // disagree about the same coordinate.
    let (sign, degrees_latitude) = if lat_deg < 0.0 {
        (LatitudeSign::SOUTH, lat_deg.abs())
    } else {
        (LatitudeSign::NORTH, lat_deg)
    };
    let degrees_latitude =
        ((degrees_latitude.min(90.0) / 90.0) * f64::from(1u32 << 23)).round() as u32;
    let degrees_latitude = degrees_latitude.min((1u32 << 23) - 1);
    let degrees_longitude =
        ((lon_deg.clamp(-180.0, 180.0) / 360.0) * f64::from(1u32 << 24)).round() as i32;
    let degrees_longitude = degrees_longitude.clamp(-(1i32 << 23), (1i32 << 23) - 1);
    let uncertainty = crate::nlmf::encode_gad_uncertainty(uncertainty_m);

    let three_dlocation = lpp::EllipsoidPointWithAltitudeAndUncertaintyEllipsoid {
        latitude_sign: LatitudeSign(sign),
        degrees_latitude: lpp::EllipsoidPointWithAltitudeAndUncertaintyEllipsoidDegreesLatitude(
            degrees_latitude,
        ),
        degrees_longitude: lpp::EllipsoidPointWithAltitudeAndUncertaintyEllipsoidDegreesLongitude(
            degrees_longitude,
        ),
        altitude_direction: AltitudeDirection(AltitudeDirection::HEIGHT),
        // Altitude 0 with a MAXIMAL altitude uncertainty: the registry's coordinates
        // are 2-D in every deployment this build supports, so claiming a height would
        // be claiming knowledge. A large uncertainty says "unknown" in the only
        // vocabulary the IE has.
        altitude: lpp::EllipsoidPointWithAltitudeAndUncertaintyEllipsoidAltitude(0),
        uncertainty_semi_major:
            lpp::EllipsoidPointWithAltitudeAndUncertaintyEllipsoidUncertaintySemiMajor(uncertainty),
        uncertainty_semi_minor:
            lpp::EllipsoidPointWithAltitudeAndUncertaintyEllipsoidUncertaintySemiMinor(uncertainty),
        // A circular uncertainty region, so the major-axis orientation is arbitrary.
        orientation_major_axis:
            lpp::EllipsoidPointWithAltitudeAndUncertaintyEllipsoidOrientationMajorAxis(0),
        uncertainty_altitude:
            lpp::EllipsoidPointWithAltitudeAndUncertaintyEllipsoidUncertaintyAltitude(127),
        // 68% — one standard deviation, the convention the northbound encoder uses.
        confidence: lpp::EllipsoidPointWithAltitudeAndUncertaintyEllipsoidConfidence(68),
    };

    let ies = lpp::ProvideAssistanceData_r9_IEs {
        common_i_es_provide_assistance_data: None,
        a_gnss_provide_assistance_data: Some(lpp::A_GNSS_ProvideAssistanceData {
            gnss_common_assist_data: Some(lpp::GNSS_CommonAssistData {
                gnss_reference_time: None,
                gnss_reference_location: Some(lpp::GNSS_ReferenceLocation { three_dlocation }),
                gnss_ionospheric_model: None,
                gnss_earth_orientation_parameters: None,
                extensions: Default::default(),
            }),
            gnss_generic_assist_data: None,
            gnss_error: None,
            extensions: Default::default(),
        }),
        otdoa_provide_assistance_data: None,
        epdu_provide_assistance_data: None,
        extensions: Default::default(),
    };
    let msg = message(
        // The LMF answers on the UE's transaction, so the initiator is the UE that
        // opened it. Sending `locationServer` here would open a SECOND transaction
        // and leave the UE's request unanswered.
        transaction(lpp::Initiator::TARGET_DEVICE, transaction_number),
        // The assistance data completes the exchange the UE opened.
        true,
        lpp::LPP_MessageBody_c1::ProvideAssistanceData(lpp::ProvideAssistanceData {
            critical_extensions: lpp::ProvideAssistanceDataCriticalExtensions::C1(
                lpp::ProvideAssistanceDataCriticalExtensions_c1::ProvideAssistanceData_r9(ies),
            ),
        }),
    );
    encode(&msg, "ProvideAssistanceData")
}

/// What this LMF knows about a UE's LPP positioning capabilities (#103).
///
/// Three values rather than a bit per method: [`Self::Unknown`] means no exchange
/// happened (or the report names nothing this LMF can request), which is not the
/// same as [`Self::EcidOnly`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UeLppCapability {
    /// No capability exchange, or one this build cannot interpret.
    #[default]
    Unknown,
    /// The UE reported E-CID capabilities and no NR high-accuracy method.
    EcidOnly,
    /// The UE reported NR Multi-RTT or NR DL-TDOA capabilities (TS 37.355 §6.5.10,
    /// Rel-16 extension additions of `ProvideCapabilities-r9-IEs`). Reachable from
    /// the wire since the generated codec carries extension additions (#515).
    AdvancedMethods,
}

/// Classify a decoded LPP `ProvideCapabilities` (#103, TS 37.355 §6.3).
///
/// On the generated codec the Rel-16 NR capability members are visible:
/// `nr-Multi-RTT-ProvideCapabilities-r16` or `nr-DL-TDOA-ProvideCapabilities-r16`
/// ⇒ [`UeLppCapability::AdvancedMethods`]; otherwise E-CID capabilities (E-UTRA
/// `ecid-ProvideCapabilities` or Rel-16 `nr-ECID-ProvideCapabilities-r16`) ⇒
/// [`UeLppCapability::EcidOnly`]; a report carrying neither (only `common` IEs, or
/// another method) says nothing this LMF can request and stays `Unknown`.
pub fn classify_ue_capability(caps: &lpp::ProvideCapabilities) -> UeLppCapability {
    let ies = match &caps.critical_extensions {
        lpp::ProvideCapabilitiesCriticalExtensions::C1(
            lpp::ProvideCapabilitiesCriticalExtensions_c1::ProvideCapabilities_r9(ies),
        ) => ies,
        _ => return UeLppCapability::Unknown,
    };
    if ies
        .extensions
        .nr_multi_rtt_provide_capabilities_r16
        .is_some()
        || ies.extensions.nr_dl_tdoa_provide_capabilities_r16.is_some()
    {
        UeLppCapability::AdvancedMethods
    } else if ies.ecid_provide_capabilities.is_some()
        || ies.extensions.nr_ecid_provide_capabilities_r16.is_some()
    {
        UeLppCapability::EcidOnly
    } else {
        UeLppCapability::Unknown
    }
}

/// Minimum reference points a multilateration method needs.
///
/// Three: both Multi-RTT trilateration and DL-TDOA hyperbolic multilateration need
/// at least three known positions to fix a 2-D point, and the solvers in
/// `positioning` enforce the same bound. Requesting a method the registry cannot
/// solve for would spend a UE measurement campaign to arrive at no fix.
pub const MIN_POINTS_FOR_MULTILATERATION: usize = 3;

/// Whether this LMF can obtain the gNB half of a Multi-RTT measurement (#713).
///
/// TS 38.305 §8.10: a Multi-RTT range is UE Rx–Tx plus gNB Rx–Tx for the same TRP.
/// The gNB half comes from the NRPPa Measurement procedure (TS 38.455), after the
/// serving gNB has configured the UE's SRS through Positioning Information
/// Exchange and Positioning Activation. This LMF implements none of those, so a
/// Multi-RTT request would collect UE halves that can never be ranged. Until it
/// does (#807), Multi-RTT is not requested.
pub const MULTI_RTT_GNB_HALF_AVAILABLE: bool = false;

/// The radio access the target UE is served on, which decides the E-CID flavour
/// (#715).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessRat {
    /// NR (gNB). E-CID is NR E-CID.
    Nr,
    /// E-UTRA connected to 5GC (ng-eNB). E-CID is E-UTRA E-CID.
    Eutra,
}

impl AccessRat {
    /// From the TS 29.572 `InputData` serving cell: `ncgi` means NR and `ecgi`
    /// alone means E-UTRA. With neither, NR, because the AMF names the serving
    /// cell of every UE it positions (`ncgi` for a gNB, `ecgi` for an ng-eNB), and
    /// NR is this 5GC's access.
    pub fn from_serving_cell(has_ncgi: bool, has_ecgi: bool) -> Self {
        if has_ecgi && !has_ncgi {
            AccessRat::Eutra
        } else {
            AccessRat::Nr
        }
    }

    /// The E-CID method for this access.
    pub fn ecid(self) -> LppMethod {
        match self {
            AccessRat::Nr => LppMethod::NrEcid,
            AccessRat::Eutra => LppMethod::Ecid,
        }
    }
}

/// Choose the LPP method for a positioning request (#103 criterion 4).
///
/// Before this the network-initiated leg always asked for E-CID with the other two
/// bodies hardcoded `None`, so a request for ≤10 m accuracy was answered by a
/// method whose output is a Timing-Advance ring hundreds of metres across — the
/// unmet-QoS-commitment defect #103 names.
///
/// The rule, in order:
///
/// Every "E-CID" below is the E-CID of the UE's access ([`AccessRat::ecid`]): NR
/// E-CID on NR, E-UTRA E-CID on an ng-eNB. Asking an NR-only UE for E-UTRA E-CID
/// gets an error or an empty report (#715).
///
/// 1. **Fewer than [`MIN_POINTS_FOR_MULTILATERATION`] reference points configured
///    ⇒ E-CID.** No amount of QoS makes a multilateration solvable against two
///    known positions, and asking anyway wastes a measurement campaign.
/// 2. **The UE reported E-CID only ⇒ E-CID.** Asking a UE for a method it has said
///    it cannot perform gets an error or an empty report.
/// 3. **High-accuracy or emergency QoS ⇒ a multilateration method.** Multi-RTT
///    when the gNB Rx–Tx half can be obtained ([`MULTI_RTT_GNB_HALF_AVAILABLE`]),
///    because its two-sided measurement cancels the clock offset. Otherwise
///    NR DL-TDOA (TS 38.305 §8.12), whose RSTDs the UE measures alone and which
///    needs no gNB measurement (#713). This depends on #714, the DL-TDOA
///    reference keying and RSTD rebasing; without it a PCI-keyed registry gives
///    wrong DL-TDOA fixes, so #713 is merged only together with or after #714.
/// 4. **Low-latency QoS ⇒ E-CID**, deliberately: one serving-cell measurement with
///    no PRS scheduling is the fastest thing available, and `LOW_DELAY` is a
///    statement about time rather than accuracy.
/// 5. **Otherwise E-CID.**
///
/// `Unknown` capability takes the high-accuracy branch rather than falling back:
/// answering a ≤10 m request with E-CID would commit to an accuracy the method
/// cannot deliver, which is worse than asking a UE a question it might decline.
/// The absence of a fallback *retry* when that request does come back empty is
/// stated as a ceiling rather than hidden here.
pub fn select_lpp_method(
    qos: crate::context::PositioningQos,
    reference_points: usize,
    capability: UeLppCapability,
    access: AccessRat,
) -> LppMethod {
    use crate::context::PositioningQos;

    if reference_points < MIN_POINTS_FOR_MULTILATERATION {
        return access.ecid();
    }
    if capability == UeLppCapability::EcidOnly {
        return access.ecid();
    }
    match qos {
        PositioningQos::HighAccuracy | PositioningQos::Emergency => {
            if MULTI_RTT_GNB_HALF_AVAILABLE {
                LppMethod::MultiRtt
            } else {
                LppMethod::DlTdoa
            }
        }
        PositioningQos::LowLatency | PositioningQos::BestEffort => access.ecid(),
    }
}

/// Encode an LMF-initiated `RequestLocationInformation` for `method` (#103).
///
/// One body per request rather than several at once: TS 37.355 permits a request to
/// ask for more than one, but this LMF's report decoders each key on their own body
/// and a combined request would make "which method answered" ambiguous — a
/// distinction the response's `positioningMethod` has to state.
///
/// The NR bodies are Rel-16 extension additions of `RequestLocationInformation-r9-IEs`
/// (TS 37.355 §6.2), which the generated codec carries since nextgsim #253.
pub fn build_lpp_request(method: LppMethod, transaction_number: u8) -> Result<Vec<u8>, String> {
    let ies = match method {
        LppMethod::Ecid => ecid_request_ies(),
        LppMethod::NrEcid => nr_ecid_request_ies(),
        LppMethod::MultiRtt => {
            let mut ies = empty_request_ies();
            ies.extensions.nr_multi_rtt_request_location_information_r16 =
                Some(lpp::NR_Multi_RTT_RequestLocationInformation_r16 {
                    // The Rx-Tx time difference IS the ranging observable, so a
                    // Multi-RTT request that did not ask for it would return RSRP
                    // the E-CID path already gets.
                    nr_ue_rx_tx_time_diff_measurement_info_request_r16: Some(
                        lpp::NR_Multi_RTT_RequestLocationInformation_r16Nr_UE_RxTxTimeDiffMeasurementInfoRequest_r16(
                            lpp::NR_Multi_RTT_RequestLocationInformation_r16Nr_UE_RxTxTimeDiffMeasurementInfoRequest_r16::TRUE,
                        ),
                    ),
                    // bit0 = prsrsrpReq: the PRS RSRP accompanies each range and is
                    // what the solver weights by.
                    nr_requested_measurements_r16:
                        lpp::NR_Multi_RTT_RequestLocationInformation_r16Nr_RequestedMeasurements_r16(
                            bits(&[true]),
                        ),
                    // This LMF provides no PRS assistance data, so it must not claim
                    // availability -- a UE told assistance is available and given
                    // none reports nothing.
                    nr_assistance_availability_r16:
                        lpp::NR_Multi_RTT_RequestLocationInformation_r16Nr_AssistanceAvailability_r16(
                            false,
                        ),
                    nr_multi_rtt_report_config_r16: lpp::NR_Multi_RTT_ReportConfig_r16 {
                        // Up to 4 measurements per TRP; trilateration needs >=3 TRPs
                        // and more samples per TRP only helps.
                        max_dl_prs_rx_tx_time_diff_meas_per_trp_r16: Some(
                            lpp::NR_Multi_RTT_ReportConfig_r16MaxDL_PRS_RxTxTimeDiffMeasPerTRP_r16(4),
                        ),
                        timing_reporting_granularity_factor_r16: None,
                    },
                    additional_paths_r16: None,
                    extensions: Default::default(),
                });
            ies
        }
        LppMethod::DlTdoa => {
            let mut ies = empty_request_ies();
            ies.extensions.nr_dl_tdoa_request_location_information_r16 =
                Some(lpp::NR_DL_TDOA_RequestLocationInformation_r16 {
                    // The RSTD is the observable; without it there is nothing to
                    // multilaterate.
                    nr_dl_prs_rstd_measurement_info_request_r16: Some(
                        lpp::NR_DL_TDOA_RequestLocationInformation_r16Nr_DL_PRS_RstdMeasurementInfoRequest_r16(
                            lpp::NR_DL_TDOA_RequestLocationInformation_r16Nr_DL_PRS_RstdMeasurementInfoRequest_r16::TRUE,
                        ),
                    ),
                    nr_requested_measurements_r16:
                        lpp::NR_DL_TDOA_RequestLocationInformation_r16Nr_RequestedMeasurements_r16(
                            bits(&[true]),
                        ),
                    nr_assistance_availability_r16:
                        lpp::NR_DL_TDOA_RequestLocationInformation_r16Nr_AssistanceAvailability_r16(
                            false,
                        ),
                    nr_dl_tdoa_report_config_r16: None,
                    additional_paths_r16: None,
                    extensions: Default::default(),
                });
            ies
        }
    };
    encode(
        &request_location(transaction_number, ies),
        &format!("RequestLocationInformation ({method:?})"),
    )
}

// ---------------------------------------------------------------------------
// Timing constant
// ---------------------------------------------------------------------------

/// T_c = 1 / (480 000 × 4096) seconds, in nanoseconds (TS 38.211 §4.1).
/// Used by [`nrrstd_to_signed_ns`] to convert k-choice RSTD / UE-Rx-Tx values.
const TC_NS: f64 = 1_000_000_000.0 / (480_000.0 * 4_096.0);

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// An NR-RSTD or NR-UE-Rx-Tx-TimeDiff report value: the reported integer `v` and
/// its granularity exponent `k`, meaning `v × 2^k × T_c`. Rel-16 arms are k0..k5;
/// the Rel-18 extension arms kMinus6..kMinus1 report finer steps (k = −6..−1).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct TimeReport {
    pub v: u32,
    pub k: i8,
}

/// `2^k` for a signed exponent.
fn pow2(k: i8) -> f64 {
    2f64.powi(i32::from(k))
}

/// Convert an `nr-UE-RxTxTimeDiff-r16` report to SIGNED nanoseconds (TS 37.355
/// `NR-Multi-RTT-MeasElement`, report mapping TS 38.133 §10.1.25.3).
///
/// The UE Rx–Tx time difference (TS 38.215 §5.1.30) is `T_UE-RX − T_UE-TX`, a
/// signed quantity. Its report mapping is the one NR-RSTD uses: the k0 range
/// `0..1970049` puts `RX-TX_TIME_DIFF_0000` at `T ≤ −985024·T_c` and steps by
/// `2^k·T_c`, so the value is `(v·2^k − 985024)·T_c` and a UE whose Rx–Tx
/// difference is about zero reports `v ≈ 985024/2^k`. Reading `v` as an unsigned
/// magnitude instead (as this LMF did before #713) turns that zero into about
/// 501 µs, a range of about 75 km.
///
/// This is one half of an RTT only. TS 38.305 §8.10 defines the Multi-RTT
/// observable as UE Rx–Tx plus the gNB Rx–Tx of the same TRP; see
/// `context::try_real_solve`, which never ranges on this half alone.
pub(crate) fn ue_rx_tx_to_signed_ns(r: TimeReport) -> Option<f64> {
    (!is_open_ended(r)).then(|| nrrstd_to_signed_ns(r))
}

/// The largest report value of the k arm (`INTEGER (0..max)` in TS 37.355): k0
/// `1970049`, k1 `985025`, …, k5 `61565`, and the Rel-18 kMinus arms
/// `1970048·2^|k| + 1`.
fn arm_max(k: i8) -> u32 {
    if k >= 0 {
        // ⌈1970049 / 2^k⌉
        let d = 1u32 << k;
        1_970_049u32.div_ceil(d)
    } else {
        1_970_048u32 * (1u32 << k.unsigned_abs()) + 1
    }
}

/// TS 38.133 §10.1.25.3 (UE Rx–Tx) and §10.1.23.3 (NR-RSTD), which share the
/// arms: the first and last report values are open-ended bins
/// (`T ≤ −985024·T_c` and `T > 985024·T_c`), not measurements. A saturated half
/// is not a usable RTT half, so it is not decoded (#812 review).
fn is_open_ended(r: TimeReport) -> bool {
    r.v == 0 || r.v >= arm_max(r.k)
}

/// Convert an NR-RSTD report to SIGNED nanoseconds (TS 37.355 §6.5.10, mapping
/// table TS 38.133 §10.1.23).
///
/// NR-RSTD is a *signed* reference-signal time difference relative to the DL-PRS
/// reference TRP, but is encoded as an unsigned `INTEGER(0..maxK)` whose sign is
/// carried by a per-arm midpoint offset. The signed value is
/// `(v × 2^k − 985024) × T_c`: the offset 985024 is the LTE RSTD span
/// (15391·Ts) scaled to `T_c = Ts/64`, so `v = 985024/2^k` decodes to exactly 0 ns
/// (the reference TRP) and the range spans ≈ ±501 µs. The Rel-18 kMinus arms keep
/// the same midpoint at their finer step.
pub(crate) fn nrrstd_to_signed_ns(r: TimeReport) -> f64 {
    (f64::from(r.v) * pow2(r.k) - 985_024.0) * TC_NS
}

/// Widen a k-arm's reported integer: the arms are `u16` or `u32` depending on
/// their range, and the conversion formula wants one type.
fn wide<T: Into<u32>>(v: T) -> u32 {
    v.into()
}

/// The (v, k) of a Multi-RTT UE Rx-Tx time difference.
fn rx_tx_report(d: &lpp::NR_Multi_RTT_MeasElement_r16Nr_UE_RxTxTimeDiff_r16) -> TimeReport {
    use lpp::NR_Multi_RTT_MeasElement_r16Nr_UE_RxTxTimeDiff_r16 as D;
    let (v, k): (u32, i8) = match d {
        D::K0_r16(x) => (wide(x.0), 0),
        D::K1_r16(x) => (wide(x.0), 1),
        D::K2_r16(x) => (wide(x.0), 2),
        D::K3_r16(x) => (wide(x.0), 3),
        D::K4_r16(x) => (wide(x.0), 4),
        D::K5_r16(x) => (wide(x.0), 5),
        D::KMinus6_r18(x) => (wide(x.0), -6),
        D::KMinus5_r18(x) => (wide(x.0), -5),
        D::KMinus4_r18(x) => (wide(x.0), -4),
        D::KMinus3_r18(x) => (wide(x.0), -3),
        D::KMinus2_r18(x) => (wide(x.0), -2),
        D::KMinus1_r18(x) => (wide(x.0), -1),
    };
    TimeReport { v, k }
}

/// The (v, k) of a DL-TDOA RSTD.
fn rstd_report(d: &lpp::NR_DL_TDOA_MeasElement_r16Nr_RSTD_r16) -> TimeReport {
    use lpp::NR_DL_TDOA_MeasElement_r16Nr_RSTD_r16 as D;
    let (v, k): (u32, i8) = match d {
        D::K0_r16(x) => (wide(x.0), 0),
        D::K1_r16(x) => (wide(x.0), 1),
        D::K2_r16(x) => (wide(x.0), 2),
        D::K3_r16(x) => (wide(x.0), 3),
        D::K4_r16(x) => (wide(x.0), 4),
        D::K5_r16(x) => (wide(x.0), 5),
        D::KMinus6_r18(x) => (wide(x.0), -6),
        D::KMinus5_r18(x) => (wide(x.0), -5),
        D::KMinus4_r18(x) => (wide(x.0), -4),
        D::KMinus3_r18(x) => (wide(x.0), -3),
        D::KMinus2_r18(x) => (wide(x.0), -2),
        D::KMinus1_r18(x) => (wide(x.0), -1),
    };
    TimeReport { v, k }
}

// ---------------------------------------------------------------------------
// NRPPa E-CID adapter
// ---------------------------------------------------------------------------

/// Decode raw NRPPa APER bytes and adapt the E-CID measurements.
///
/// Returns `(lmf_request_id, Vec<CellMeasurement>)` on success, or an `Err`
/// description.  Used by `handle_nrppa_binary_report` in `main.rs`.
///
/// Decoded with the generated NRPPa codec (#515 stage 3); a report TS 38.413
/// §10.3.4.2 says to reject is an `Err`. Callers that can answer the gNB use
/// [`crate::nrppa_uplink::decode_ecid_report`] for the ERROR INDICATION too.
pub fn decode_nrppa_ecid_report(bytes: &[u8]) -> Result<(u64, Vec<CellMeasurement>), String> {
    match crate::nrppa_uplink::decode_ecid_report(bytes)? {
        crate::nrppa_uplink::EcidReportOutcome::Accepted {
            lmf_measurement_id,
            cells,
            ..
        } => Ok((lmf_measurement_id, cells)),
        crate::nrppa_uplink::EcidReportOutcome::Rejected { reason, .. } => Err(reason),
    }
}

// ---------------------------------------------------------------------------
// LPP E-CID adapter (A4)
// ---------------------------------------------------------------------------

/// Map one LPP `MeasuredResultsElement` (TS 37.355 §6.5.3
/// `ECID-SignalMeasurementInformation`) to a [`CellMeasurement`].
///
/// | PDU field                    | `CellMeasurement` | scaling (value tables)          |
/// |------------------------------|-------------------|---------------------------------|
/// | `phys_cell_id` (0..503)      | `nr_cgi`          | `"pci-<n>"` (matches the Multi-RTT / DL-TDOA adapters, so one seeded registry serves all methods) |
/// | `rsrp_result` (0..97)        | `rsrp`            | `v − 140` → −140..−43 dBm (E-UTRA RSRP-Range, TS 36.133 §9.1.4; same convention as the NRPPa E-CID adapter in [`crate::nrppa_uplink`]) |
/// | `rsrq_result` (0..34)        | `rsrq`            | raw 0..34 index (E-UTRA RSRQ-Range, TS 36.133 §9.1.7; same as the NRPPa adapter) |
/// | `ue_rx_tx_time_diff` (0..4095) | `ecid_rtt_ns` | TS 36.133 §9.1.9.2 bins (2 T_s to 4096 T_s, then 8 T_s), midpoint in ns; the last value is open-ended and dropped (#832) |
fn measured_results_element_to_cell(elem: &lpp::MeasuredResultsElement) -> CellMeasurement {
    CellMeasurement {
        nr_cgi: format!("pci-{}", elem.phys_cell_id.0),
        rsrp: elem.rsrp_result.as_ref().map(|v| i16::from(v.0) - 140),
        rsrq: elem.rsrq_result.as_ref().map(|v| i16::from(v.0)),
        timing_advance: None,
        aoa: None,
        rtt_ns: None,
        rstd_ns: None,
        ue_rx_tx_ns: None,
        rstd_reference: None,
        // TS 36.133 §9.1.9.2: the UE Rx–Tx time difference, in T_s bins. With the
        // TA loop converged it is the UE's N_TA, the round trip (#832).
        ecid_rtt_ns: elem.ue_rx_tx_time_diff.as_ref().and_then(|v| {
            crate::positioning::eutra_time_report_to_ns(
                u32::from(v.0),
                crate::positioning::EUTRA_UE_RX_TX_MAX,
            )
            .map(|(mid, _)| mid)
        }),
        gnb_rx_tx_ns: None,
        dl_prs_id: None,
        eutra: true,
    }
}

/// Adapt a decoded LPP `ProvideLocationInformation` → `ecid-ProvideLocationInformation`
/// → `ECID-SignalMeasurementInformation` (TS 37.355 §6.5.3) into
/// [`CellMeasurement`]s.
///
/// The `primaryCellMeasuredResults` (serving cell) is emitted first, then each
/// `measuredResultsList` element, so `try_real_solve`'s ECID branch (serving =
/// best-RSRP cell that also carries a timing term + registry hit) sees the
/// serving cell.
///
/// Returns an empty `Vec` when the message is not a `ProvideLocationInformation`,
/// carries no `ecid` body, or the `ecid` body carries only an `ECID-Error`.
pub fn lpp_ecid_provide_to_measurements(msg: &lpp::LPP_Message) -> Vec<CellMeasurement> {
    let Some(sig) = provide_location_r9(msg)
        .and_then(|ies| ies.ecid_provide_location_information.as_ref())
        .and_then(|e| e.ecid_signal_measurement_information.as_ref())
    else {
        return vec![];
    };
    let mut out = Vec::with_capacity(
        sig.measured_results_list.0.len()
            + usize::from(sig.primary_cell_measured_results.is_some()),
    );
    if let Some(primary) = sig.primary_cell_measured_results.as_ref() {
        out.push(measured_results_element_to_cell(primary));
    }
    for elem in &sig.measured_results_list.0 {
        out.push(measured_results_element_to_cell(elem));
    }
    out
}

/// Decode raw LPP UPER bytes and adapt E-CID `ProvideLocationInformation`
/// measurements. `request_id` is the LPP transaction number (0 when absent).
pub fn decode_lpp_ecid_report(bytes: &[u8]) -> Result<(u64, Vec<CellMeasurement>), String> {
    let msg = decode_lpp(bytes)?;
    let request_id = extract_lpp_request_id(&msg).unwrap_or(0);
    Ok((request_id, lpp_ecid_provide_to_measurements(&msg)))
}

// ---------------------------------------------------------------------------
// LPP NR E-CID adapter (#715)
// ---------------------------------------------------------------------------

/// TS 38.133 §10.1.6.1 SS-RSRP report mapping: `SS-RSRP_v` covers
/// `−157 + v ≤ RSRP < −156 + v` dBm (0 is below −156, 127 is −31 and above).
/// The upper bound is used, the same convention as the E-UTRA `v − 140`.
fn nr_rsrp_dbm(v: u8) -> i16 {
    i16::from(v) - 156
}

/// Map one LPP `NR-MeasuredResultsElement-r16` (TS 37.355 Rel-16
/// `NR-ECID-SignalMeasurementInformation-r16`) to a [`CellMeasurement`].
///
/// | PDU field | `CellMeasurement` | scaling |
/// |---|---|---|
/// | `nr-PhysCellID-r16` (0..1007) | `nr_cgi` | `"pci-<n>"`, as the other LPP adapters |
/// | `resultsSSB-Cell-r16.nr-RSRP-r16` (0..127), else the CSI-RS cell result | `rsrp` | `v − 156` dBm ([`nr_rsrp_dbm`]) |
/// | `…nr-RSRQ-r16` (0..127) | `rsrq` | raw index (TS 38.133 §10.1.11.1), like the E-UTRA adapter's raw index |
///
/// NR E-CID carries no UE timing quantity, so `ecid_rtt_ns` stays empty. The
/// timing term of an NR E-CID fix is the gNB's, from the NRPPa E-CID leg.
fn nr_measured_results_element_to_cell(
    elem: &lpp::NR_MeasuredResultsElement_r16,
) -> CellMeasurement {
    let cell = elem
        .results_ssb_cell_r16
        .as_ref()
        .or(elem.results_csi_rs_cell_r16.as_ref());
    CellMeasurement {
        nr_cgi: format!("pci-{}", elem.nr_phys_cell_id_r16.0),
        rsrp: cell
            .and_then(|c| c.nr_rsrp_r16.as_ref())
            .map(|v| nr_rsrp_dbm(v.0)),
        rsrq: cell
            .and_then(|c| c.nr_rsrq_r16.as_ref())
            .map(|v| i16::from(v.0)),
        timing_advance: None,
        aoa: None,
        rtt_ns: None,
        rstd_ns: None,
        ue_rx_tx_ns: None,
        ecid_rtt_ns: None,
        gnb_rx_tx_ns: None,
        rstd_reference: None,
        dl_prs_id: None,
        eutra: false,
    }
}

/// Adapt an LPP `ProvideLocationInformation` → `nr-ECID-ProvideLocationInformation-r16`
/// into [`CellMeasurement`]s: the primary cell first, then the measured-results
/// list. Empty when the message carries no NR E-CID signal measurements (an
/// `NR-ECID-Error-r16` alone, or another method).
pub fn lpp_nr_ecid_provide_to_measurements(msg: &lpp::LPP_Message) -> Vec<CellMeasurement> {
    let Some(sig) = provide_location_r9(msg)
        .and_then(|ies| {
            ies.extensions
                .nr_ecid_provide_location_information_r16
                .as_ref()
        })
        .and_then(|e| e.nr_ecid_signal_measurement_information_r16.as_ref())
    else {
        return vec![];
    };
    std::iter::once(&sig.nr_primary_cell_measured_results_r16)
        .chain(
            sig.nr_measured_results_list_r16
                .iter()
                .flat_map(|l| l.0.iter()),
        )
        .map(nr_measured_results_element_to_cell)
        .collect()
}

// ---------------------------------------------------------------------------
// LPP Multi-RTT adapter
// ---------------------------------------------------------------------------

/// Adapt a decoded LPP `ProvideLocationInformation` → `nr-Multi-RTT` measurement
/// list (TS 37.355 §6.5.10) into [`CellMeasurement`]s.
///
/// | PDU field                       | `CellMeasurement` field | Notes                            |
/// |---------------------------------|-------------------------|----------------------------------|
/// | `nr-PhysCellID` (NR PCI)        | `nr_cgi`                | `"pci-<n>"`; `"prs-<id>"` fallback |
/// | `nr-UE-RxTxTimeDiff` k-arm      | `ue_rx_tx_ns`           | (v·2^k − 985024)·T_c ns, signed (TS 38.133 §10.1.25.3) |
/// | `nr-DL-PRS-RSRP-Result`         | `rsrp`                  | 0..126 → −140..−14 dBm           |
///
/// Returns an empty `Vec` when the message is not a `ProvideLocationInformation`,
/// carries no `nr-Multi-RTT` body, or its signal measurement information is absent.
pub fn lpp_multi_rtt_provide_to_measurements(msg: &lpp::LPP_Message) -> Vec<CellMeasurement> {
    let Some(sig) = provide_location_r9(msg)
        .and_then(|ies| {
            ies.extensions
                .nr_multi_rtt_provide_location_information_r16
                .as_ref()
        })
        .and_then(|m| m.nr_multi_rtt_signal_measurement_information_r16.as_ref())
    else {
        return vec![];
    };
    sig.nr_multi_rtt_meas_list_r16
        .0
        .iter()
        .map(|elem| {
            // Use NR PCI as CGI key when present; fall back to DL-PRS-ID.
            let nr_cgi = match &elem.nr_phys_cell_id_r16 {
                Some(pci) => format!("pci-{}", pci.0),
                None => format!("prs-{}", elem.dl_prs_id_r16.0),
            };
            let rsrp = elem
                .nr_dl_prs_rsrp_result_r16
                .as_ref()
                .map(|v| i16::from(v.0) - 140);
            CellMeasurement {
                nr_cgi,
                rsrp,
                rsrq: None,
                timing_advance: None,
                aoa: None,
                // The UE half of the RTT only: never an RTT by itself (#713).
                rtt_ns: None,
                rstd_ns: None,
                // None for a saturated (open-ended) report value.
                ue_rx_tx_ns: ue_rx_tx_to_signed_ns(rx_tx_report(&elem.nr_ue_rx_tx_time_diff_r16)),
                rstd_reference: None,
                ecid_rtt_ns: None,
                gnb_rx_tx_ns: None,
                dl_prs_id: Some(elem.dl_prs_id_r16.0),
                eutra: false,
            }
        })
        .collect()
}

/// Extract the LPP transaction number as a correlation request-id.
///
/// The `transactionID.transactionNumber` (0..255) correlates the UE's
/// `ProvideLocationInformation` with the LMF's `RequestLocationInformation`.
/// Returns `None` when the message carries no `transactionID`.
pub fn extract_lpp_request_id(msg: &lpp::LPP_Message) -> Option<u64> {
    msg.transaction_id
        .as_ref()
        .map(|t| u64::from(t.transaction_number.0))
}

/// Decode raw LPP UPER bytes and adapt nr-Multi-RTT measurements.
///
/// Returns `(request_id, Vec<CellMeasurement>)`; `request_id` is the LPP
/// transaction number (0 when absent). Used by `handle_lpp_binary_report`.
pub fn decode_lpp_multi_rtt_report(bytes: &[u8]) -> Result<(u64, Vec<CellMeasurement>), String> {
    let msg = decode_lpp(bytes)?;
    let request_id = extract_lpp_request_id(&msg).unwrap_or(0);
    Ok((request_id, lpp_multi_rtt_provide_to_measurements(&msg)))
}

/// Adapt a UE NR-DL-TDOA `ProvideLocationInformation` (TS 37.355 §6.5.10) to a
/// flat [`CellMeasurement`] list for [`crate::LmfContext::measurement_report`].
///
/// The reference TRP (`dl-PRS-ReferenceInfo`) is emitted first with `rstd_ns = 0`
/// (RSTD is defined relative to it); each `NR-DL-TDOA-MeasElement` then contributes
/// one entry whose `rstd_ns` is the SIGNED time difference vs that reference (see
/// [`nrrstd_to_signed_ns`]).
///
/// Keys (#714): a neighbour is `"pci-<n>"` when the UE gave its NR PCI, else
/// `"prs-<id>"`, as in the Multi-RTT adapter. The reference can only be
/// `"prs-<id>"`: `DL-PRS-ID-Info-r16` carries the DL-PRS ID and resource IDs and
/// no PCI. Every entry also carries `dl_prs_id`, so the solver can fall back to
/// `prs-<id>` for a neighbour whose PCI the registry does not hold, and can
/// rebase the RSTDs when the reference itself is not in the registry
/// (`context::tdoa_observations`).
///
/// Returns an empty `Vec` when the message is not a `ProvideLocationInformation` or
/// carries no `nr-DL-TDOA` signal-measurement information.
pub fn lpp_dl_tdoa_provide_to_measurements(msg: &lpp::LPP_Message) -> Vec<CellMeasurement> {
    let Some(sig) = provide_location_r9(msg)
        .and_then(|ies| {
            ies.extensions
                .nr_dl_tdoa_provide_location_information_r16
                .as_ref()
        })
        .and_then(|m| m.nr_dl_tdoa_signal_measurement_information_r16.as_ref())
    else {
        return vec![];
    };
    let mut out = Vec::with_capacity(sig.nr_dl_tdoa_meas_list_r16.0.len() + 1);
    let reference = sig.dl_prs_reference_info_r16.dl_prs_id_r16.0;
    // Reference TRP: RSTD ≡ 0 by definition.
    out.push(CellMeasurement {
        nr_cgi: format!("prs-{}", sig.dl_prs_reference_info_r16.dl_prs_id_r16.0),
        rsrp: None,
        rsrq: None,
        timing_advance: None,
        aoa: None,
        rtt_ns: None,
        rstd_ns: Some(0.0),
        ue_rx_tx_ns: None,
        rstd_reference: Some(reference),
        ecid_rtt_ns: None,
        gnb_rx_tx_ns: None,
        dl_prs_id: Some(sig.dl_prs_reference_info_r16.dl_prs_id_r16.0),
        eutra: false,
    });
    for elem in &sig.nr_dl_tdoa_meas_list_r16.0 {
        let nr_cgi = match &elem.nr_phys_cell_id_r16 {
            Some(pci) => format!("pci-{}", pci.0),
            None => format!("prs-{}", elem.dl_prs_id_r16.0),
        };
        let rsrp = elem
            .nr_dl_prs_rsrp_result_r16
            .as_ref()
            .map(|v| i16::from(v.0) - 140);
        out.push(CellMeasurement {
            nr_cgi,
            rsrp,
            rsrq: None,
            timing_advance: None,
            aoa: None,
            rtt_ns: None,
            // TS 38.133 §10.1.23.3: the first and last report values are
            // open-ended bins, not measurements, so they are not decoded.
            rstd_ns: Some(rstd_report(&elem.nr_rstd_r16))
                .filter(|r| !is_open_ended(*r))
                .map(nrrstd_to_signed_ns),
            ue_rx_tx_ns: None,
            rstd_reference: Some(reference),
            ecid_rtt_ns: None,
            gnb_rx_tx_ns: None,
            dl_prs_id: Some(elem.dl_prs_id_r16.0),
            eutra: false,
        });
    }
    out
}

/// Decode raw LPP UPER bytes and adapt NR-DL-TDOA measurements.
pub fn decode_lpp_dl_tdoa_report(bytes: &[u8]) -> Result<(u64, Vec<CellMeasurement>), String> {
    let msg = decode_lpp(bytes)?;
    let request_id = extract_lpp_request_id(&msg).unwrap_or(0);
    Ok((request_id, lpp_dl_tdoa_provide_to_measurements(&msg)))
}

/// Decode a UE-provided LPP `ProvideLocationInformation` (TS 37.355 §6.2) once and
/// route it through the available signal-measurement adapters, returning the first
/// non-empty [`CellMeasurement`] set: E-UTRA E-CID, NR E-CID, nr-Multi-RTT, then
/// nr-DL-TDOA.
///
/// This is the single decode entry point for the LPP PDU carried in a
/// `binaryDataLppMessage` multipart part on the MO-LR `DetermineLocation` path, and
/// for the uplink LPP `ProvideLocationInformation` delivered by the N1MessageNotify
/// callback. `request_id` is the LPP `transactionID.transactionNumber` (0 when
/// absent). Returns an `Err` only when the bytes are not a decodable
/// `LPP-Message`; a decodable message with no recognised measurements yields an
/// empty vector (the caller maps that to a no-fix outcome).
pub fn decode_lpp_provide_report(bytes: &[u8]) -> Result<(u64, Vec<CellMeasurement>), String> {
    let msg = decode_lpp(bytes)?;
    let request_id = extract_lpp_request_id(&msg).unwrap_or(0);
    let mut ecid = lpp_ecid_provide_to_measurements(&msg);
    if ecid.is_empty() {
        ecid = lpp_nr_ecid_provide_to_measurements(&msg);
    }
    let cells = if !ecid.is_empty() {
        ecid
    } else {
        let multi_rtt = lpp_multi_rtt_provide_to_measurements(&msg);
        if multi_rtt.is_empty() {
            lpp_dl_tdoa_provide_to_measurements(&msg)
        } else {
            multi_rtt
        }
    };
    Ok((request_id, cells))
}

// ---------------------------------------------------------------------------
// Sidelink ranging adapter (TS 23.586 §5.3.3, nextgsim #138)
// ---------------------------------------------------------------------------

/// One sidelink range the LMF holds for a UE.
///
/// Deliberately NOT a [`CellMeasurement`]: a sidelink range is a distance to another
/// UE, not a measurement of a cell, and feeding it into the E-CID/Multi-RTT
/// multilateration would put a peer UE's identity where a cell's global id belongs
/// and produce a position from an anchor set the LMF has no coordinates for. The
/// service is separate for that reason (see the issue: "distinct from
/// `Nlmf_Location`").
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SidelinkRange {
    /// The ranged peer's PC5 Layer-2 identity.
    pub peer_layer2_id: u32,
    /// Distance to that peer, in metres.
    pub range_m: f64,
    /// Reported accuracy, in metres.
    pub accuracy_m: f64,
    /// How it was measured, as the UE reported it.
    pub method: SidelinkRangingMethod,
    /// How many measurements the estimate rests on.
    pub measurement_count: u16,
}

impl SidelinkRange {
    fn from_result(result: &crate::sidelink_epdu::SidelinkRangingResult) -> Self {
        Self {
            peer_layer2_id: result.peer_layer2_id,
            range_m: f64::from(result.range_cm) / 100.0,
            accuracy_m: f64::from(result.accuracy_cm) / 100.0,
            method: result.method,
            measurement_count: result.measurement_count,
        }
    }
}

/// Decode raw LPP UPER bytes and adapt any sidelink ranging report.
///
/// The report rides in `epdu-ProvideLocationInformation` (TS 37.355 §6.5.7) under
/// nextg's non-standard EPDU identifier; see [`crate::sidelink_epdu`]. The message
/// is decoded with the generated codec. An empty `Vec` is the normal answer for a
/// UE that does no sidelink ranging.
///
/// Separate from [`decode_lpp_provide_report`] because the two answer different
/// questions: that one produces cell measurements a solver consumes, this one
/// produces ranges to peer UEs that no solver can consume.
pub fn decode_lpp_sidelink_ranging(bytes: &[u8]) -> Result<(u64, Vec<SidelinkRange>), String> {
    let msg = decode_lpp(bytes)?;
    let request_id = extract_lpp_request_id(&msg).unwrap_or(0);
    let ranges = match provide_location_r9(&msg).and_then(crate::sidelink_epdu::report_in) {
        Some(report) => report?
            .results
            .iter()
            .map(SidelinkRange::from_result)
            .collect(),
        None => vec![],
    };
    Ok((request_id, ranges))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        build_lpp_ecid_request, decode_lpp_ecid_report, decode_lpp_provide_report,
        decode_nrppa_ecid_report, extract_lpp_request_id, lpp_dl_tdoa_provide_to_measurements,
        lpp_multi_rtt_provide_to_measurements, nrrstd_to_signed_ns, ue_rx_tx_to_signed_ns,
        TimeReport, TC_NS,
    };

    use crate::nrppa_uplink::test_support::{aoa, ecid_report, nr_cgi, rsrp, ta1};

    /// The LMF-initiated LPP RequestLocationInformation round-trips: encode ->
    /// decode -> it is a RequestLocationInformation carrying the E-CID request,
    /// and the transaction number / locationServer initiator survive.
    #[test]
    fn lpp_ecid_request_roundtrips() {
        let bytes = build_lpp_ecid_request(7).expect("encode LPP request");
        let decoded = super::decode_lpp(&bytes).expect("decode LPP request");
        assert_eq!(extract_lpp_request_id(&decoded), Some(7));
        use nextgcore_lpp_gen::generated as lpp;
        let Some(lpp::LPP_MessageBody::C1(lpp::LPP_MessageBody_c1::RequestLocationInformation(r))) =
            &decoded.lpp_message_body
        else {
            panic!("expected RequestLocationInformation");
        };
        let lpp::RequestLocationInformationCriticalExtensions::C1(
            lpp::RequestLocationInformationCriticalExtensions_c1::RequestLocationInformation_r9(
                ies,
            ),
        ) = &r.critical_extensions
        else {
            panic!("expected the -r9 IEs");
        };
        assert!(
            ies.ecid_request_location_information.is_some(),
            "E-CID request IE present"
        );
        assert!(ies
            .extensions
            .nr_multi_rtt_request_location_information_r16
            .is_none());
        assert!(ies
            .extensions
            .nr_dl_tdoa_request_location_information_r16
            .is_none());
    }

    /// A4 golden byte-vector: a hand-built UPER LPP E-CID
    /// `ProvideLocationInformation` round-trips through the new adapter to the
    /// expected [`CellMeasurement`] values (TS 37.355 §6.5.3). Field values are
    /// anchored to the TS 36.133 value tables, NOT to the encoder:
    ///   physCellId 42        -> `"pci-42"`
    ///   rsrp-Result 60       -> 60 − 140 = −80 dBm (E-UTRA RSRP-Range §9.1.4)
    ///   rsrq-Result 20       -> raw index 20 (E-UTRA RSRQ-Range §9.1.7)
    ///   ue-RxTxTimeDiff 700  -> ecid_rtt_ns 1401·T_s (TS 36.133 §9.1.9.2, #832)
    /// The exact UPER bytes are pinned so an encoder regression is caught, then
    /// decoded through the adapter and the adapted values are asserted.
    #[test]
    fn a4_lpp_ecid_provide_golden_vector_to_measurements() {
        // Captured from the hand-written LPP encoder before it was deleted (#515):
        // the exact input this test has always decoded.
        let bytes: &[u8] = &[
            0x92, 0x13, 0x28, 0x09, 0x23, 0x8A, 0x81, 0xCE, 0x9E, 0x28, 0x57, 0x80, 0x10, 0x0E,
            0x0E, 0x74, 0x78,
        ];

        // Byte fidelity: the generated codec re-encodes the captured bytes exactly.
        assert_eq!(
            super::encode(&super::decode_lpp(bytes).expect("decodes"), "E-CID").expect("encodes"),
            bytes,
            "E-CID ProvideLocationInformation must round-trip byte-exact"
        );

        // Decode through the A4 adapter and assert the anchored values.
        let (txn, cells) = decode_lpp_ecid_report(bytes).expect("decode E-CID report");
        assert_eq!(txn, 9, "LPP transactionNumber survives");
        assert_eq!(
            cells.len(),
            2,
            "primary (serving) cell first, then the list"
        );

        assert_eq!(cells[0].nr_cgi, "pci-42");
        assert_eq!(cells[0].rsrp, Some(-80), "rsrp-Result 60 -> 60-140 dBm");
        assert_eq!(cells[0].rsrq, Some(20), "rsrq-Result raw index");
        // #832: TS 36.133 §9.1.9.2, value 700 is [1400, 1402) T_s: midpoint 1401 T_s.
        assert_eq!(cells[0].timing_advance, None);
        assert_eq!(
            cells[0].ecid_rtt_ns,
            Some(1401.0 * crate::positioning::TS_NS),
            "ue-RxTxTimeDiff -> the E-CID round trip"
        );
        assert_eq!(cells[0].rtt_ns, None);
        assert_eq!(cells[0].rstd_ns, None);

        assert_eq!(cells[1].nr_cgi, "pci-7");
        assert_eq!(cells[1].rsrp, Some(-110), "rsrp-Result 30 -> 30-140 dBm");
        assert_eq!(cells[1].rsrq, None);
        assert_eq!(cells[1].timing_advance, None);

        // The unified decode entry point also selects the E-CID measurements.
        let (_txn2, cells2) =
            decode_lpp_provide_report(bytes).expect("decode via the provide entry point");
        assert_eq!(cells2.len(), 2);
        assert_eq!(cells2[0].nr_cgi, "pci-42");
        assert_eq!(
            cells2[0].ecid_rtt_ns,
            Some(1401.0 * crate::positioning::TS_NS)
        );
    }

    /// An `ECID-Error`-only provide body (no signal measurements) adapts to an
    /// empty measurement set (never a fabricated cell).
    #[test]
    fn ecid_error_only_provide_yields_no_measurements() {
        // Captured from the hand-written LPP encoder before it was deleted (#515):
        // the exact input this test has always decoded.
        let bytes: &[u8] = &[0x92, 0x07, 0x28, 0x08, 0x80];
        let (_txn, cells) = decode_lpp_ecid_report(bytes).expect("decode");
        assert!(cells.is_empty(), "an error-only report yields no cells");
    }

    /// #713: `nr-UE-RxTxTimeDiff-r16` is signed, with the TS 38.133 §10.1.25.3
    /// midpoint. A UE whose Rx–Tx difference is about zero reports v ≈ 985024/2^k,
    /// which is ≈ 0 ns, not the ≈ 501 µs an unsigned reading gives.
    #[test]
    fn ue_rx_tx_decodes_signed_around_the_midpoint() {
        let at = |v: u32, k: i8| ue_rx_tx_to_signed_ns(TimeReport { v, k });
        for k in 0..=5i8 {
            let zero = 985_024u32 >> k;
            assert_eq!(at(zero, k), Some(0.0), "k{k}");
            // One step either side is ±2^k·T_c.
            let step = f64::from(1u32 << k) * TC_NS;
            assert!((at(zero + 1, k).unwrap() - step).abs() < 1e-9);
            assert!((at(zero - 1, k).unwrap() + step).abs() < 1e-9);
        }
        // The issue's value: v = 985024 + δ is δ·T_c, a few ns, not 501 µs.
        let near_zero = at(985_024 + 7, 0).unwrap();
        assert!((near_zero - 7.0 * TC_NS).abs() < 1e-9, "{near_zero}");
        // The first and last values are open-ended bins (TS 38.133 §10.1.25.3),
        // not measurements: not decoded. The values just inside are ≈ ±501 µs.
        for k in [0i8, 1, 2, 3, 4, 5, -1, -6] {
            assert_eq!(at(0, k), None, "k{k}");
            assert_eq!(at(super::arm_max(k), k), None, "k{k}");
            assert!(at(super::arm_max(k) - 1, k).is_some(), "k{k}");
        }
        assert_eq!(
            [0i8, 1, 2, 3, 4, 5, -6, -1].map(super::arm_max),
            [
                1_970_049,
                985_025,
                492_513,
                246_257,
                123_129,
                61_565,
                126_083_073,
                3_940_097
            ],
            "the TS 37.355 nr-UE-RxTxTimeDiff-r16 ranges"
        );
        assert!((at(1, 0).unwrap() + 985_023.0 * TC_NS).abs() < 1e-6);
    }

    /// NRPPa E-CID: generated encode → `decode_nrppa_ecid_report` → adapt.
    ///
    /// Checks NR-CGI formatting, TA, AoA, best-RSRP extraction and the request id.
    #[test]
    fn rt_nrppa_ecid_report_to_measurements() {
        let bytes = ecid_report(
            1,
            42,
            7,
            nr_cgi([0x02, 0xF8, 0x39], 0x000000001),
            [0x00, 0x12, 0x34],
            Some(vec![ta1(500), aoa(90), rsrp(&[60, 55])]),
        );
        let (request_id, cells) = decode_nrppa_ecid_report(&bytes).unwrap();
        assert_eq!(
            request_id, 42,
            "lmf-UE-Measurement-ID is the correlation key"
        );
        assert_eq!(cells.len(), 1, "one serving-cell entry");
        let c = &cells[0];
        assert_eq!(c.nr_cgi, "02f839-000000001");
        assert_eq!(c.ecid_rtt_ns, Some(1001.0 * crate::positioning::TS_NS));
        assert_eq!(c.aoa, Some(90.0));
        // Best RSRP item = 60 → 60 − 140 = −80 dBm.
        assert_eq!(c.rsrp, Some(-80));
    }

    /// LPP Multi-RTT round-trip: build → UPER encode → decode → adapt.
    ///
    /// Verifies k-choice → ns conversion and PCI/PRS-fallback CGI formatting.
    #[test]
    fn rt_lpp_multi_rtt_to_measurements() {
        // Captured from the hand-written LPP encoder before it was deleted (#515):
        // the exact input this test has always decoded.
        let decoded = super::decode_lpp(&[
            0x92, 0x0F, 0x28, 0x80, 0x0A, 0x30, 0x88, 0x01, 0x41, 0x02, 0x8F, 0x65, 0x24, 0xF8,
            0x00, 0x16, 0xBC, 0x56, 0x62, 0xA0, 0x00, 0x06, 0x13, 0x0D, 0x40, 0x00, 0x5A, 0xF1,
            0x59, 0x04,
        ])
        .expect("decodes");

        assert_eq!(extract_lpp_request_id(&decoded), Some(7));

        let cells = lpp_multi_rtt_provide_to_measurements(&decoded);
        assert_eq!(cells.len(), 2);

        // Cell 0: PCI present → "pci-123"; K2(300_000) → (1_200_000 − 985_024)·T_c
        // = 214_976·T_c ≈ 109_342 ns of UE Rx–Tx (#713: signed, and not an RTT).
        let c0 = &cells[0];
        assert_eq!(c0.nr_cgi, "pci-123");
        // nr_dl_prs_rsrp_result=80 → 80 − 140 = −60 dBm.
        assert_eq!(c0.rsrp, Some(-60));
        assert_eq!(c0.rtt_ns, None, "the UE half is not an RTT");
        let rx_tx0 = c0.ue_rx_tx_ns.expect("ue_rx_tx_ns cell 0");
        assert!((rx_tx0 - 214_976.0 * TC_NS).abs() < 1e-6, "{rx_tx0}");

        // Cell 1: PCI absent → "prs-6"; K1(200_000) → (400_000 − 985_024)·T_c, negative.
        let c1 = &cells[1];
        assert_eq!(c1.nr_cgi, "prs-6");
        assert_eq!(c1.rsrp, None);
        assert_eq!(c1.rtt_ns, None);
        let rx_tx1 = c1.ue_rx_tx_ns.expect("ue_rx_tx_ns cell 1");
        assert!((rx_tx1 + 585_024.0 * TC_NS).abs() < 1e-6, "{rx_tx1}");
    }

    /// `nrrstd_to_signed_ns`: NR-RSTD is a SIGNED time difference; verify the
    /// midpoint-offset mapping ns = (v·2^k − 985024)·T_c at the spec endpoints.
    #[test]
    fn nrrstd_signed_endpoints() {
        // Per-arm zero point 985024/2^k decodes to exactly 0 ns (reference TRP).
        assert_eq!(nrrstd_to_signed_ns(TimeReport { v: 985_024, k: 0 }), 0.0);
        assert_eq!(nrrstd_to_signed_ns(TimeReport { v: 246_256, k: 2 }), 0.0); // 985024/4
        assert_eq!(nrrstd_to_signed_ns(TimeReport { v: 30_782, k: 5 }), 0.0); // 985024/32
                                                                              // One k0 code = ±T_c around the midpoint (sign carried by the offset).
        assert!((nrrstd_to_signed_ns(TimeReport { v: 985_025, k: 0 }) - TC_NS).abs() < 1e-9);
        assert!((nrrstd_to_signed_ns(TimeReport { v: 985_023, k: 0 }) + TC_NS).abs() < 1e-9);
        // Endpoints span ≈ ±501 µs.
        assert!((nrrstd_to_signed_ns(TimeReport { v: 0, k: 0 }) + 985_024.0 * TC_NS).abs() < 1e-6);
        assert!(nrrstd_to_signed_ns(TimeReport { v: 1_970_049, k: 0 }) > 500_000.0);
    }

    /// LPP NR-DL-TDOA round-trip: build → UPER encode → decode → adapt.
    /// The reference TRP leads with rstd_ns 0; each element carries its signed RSTD.
    #[test]
    fn rt_lpp_dl_tdoa_to_measurements() {
        // Captured from the hand-written LPP encoder before it was deleted (#515):
        // the exact input this test has always decoded.
        let decoded = super::decode_lpp(&[
            0x92, 0x13, 0x28, 0x80, 0x0A, 0x20, 0x28, 0x00, 0xC0, 0x10, 0x40, 0xE3, 0xD8, 0x02,
            0xD7, 0x8A, 0xC1, 0xE1, 0x04, 0x85, 0x1C, 0x80,
        ])
        .expect("decodes");
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

    /// A5 golden vector: `decode_lpp_provide_report` decodes a UE-provided LPP
    /// `ProvideLocationInformation` (nr-Multi-RTT) ONCE and yields the exact
    /// [`CellMeasurement`]s — the byte-fidelity proof that the LPP PDU carried
    /// in a `binaryDataLppMessage` multipart part reaches the decode adapter.
    #[test]
    fn decode_lpp_provide_report_multi_rtt_golden() {
        // Captured from the hand-written LPP encoder before it was deleted (#515):
        // the exact input this test has always decoded.
        let bytes: &[u8] = &[
            0x92, 0x55, 0x28, 0x80, 0x0A, 0x1E, 0x88, 0x00, 0x41, 0x02, 0xA8, 0x22, 0x61, 0xA8,
            0x00, 0x0B, 0x5E, 0x2B, 0x20, 0xD0, 0x00,
        ];

        let (req_id, cells) = decode_lpp_provide_report(bytes).expect("decode_lpp_provide_report");
        // request_id is the LPP transaction number.
        assert_eq!(req_id, 42);
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0].nr_cgi, "pci-321");
        // nr_dl_prs_rsrp_result=80 -> 80 - 140 = -60 dBm.
        assert_eq!(cells[0].rsrp, Some(-60));
        // K1(200_000): (400_000 − 985_024)·T_c of UE Rx–Tx, signed (#713).
        assert_eq!(cells[0].rtt_ns, None);
        let rx_tx = cells[0].ue_rx_tx_ns.expect("ue_rx_tx_ns");
        assert!(
            (rx_tx + 585_024.0 * TC_NS).abs() < 1e-6,
            "ue_rx_tx_ns={rx_tx}"
        );
    }

    /// A5: a decodable LPP message with no recognised signal measurements
    /// yields an empty vector (the handler maps that to 400), NOT an error.
    #[test]
    fn decode_lpp_provide_report_empty_when_no_measurements() {
        // A RequestLocationInformation is a valid LppMessage but carries no
        // ProvideLocationInformation measurements.
        let bytes = build_lpp_ecid_request(3).expect("encode");
        let (req_id, cells) = decode_lpp_provide_report(&bytes).expect("decode");
        assert_eq!(req_id, 3);
        assert!(cells.is_empty());
    }

    /// A5: non-LPP bytes are a decode error, not a silent empty result.
    #[test]
    fn decode_lpp_provide_report_rejects_garbage() {
        assert!(decode_lpp_provide_report(&[0xde, 0xad, 0xbe, 0xef]).is_err());
    }

    /// `decode_nrppa_ecid_report` on a report with no measured results: the id and
    /// the serving cell, nothing else.
    #[test]
    fn decode_nrppa_ecid_report_wrapper() {
        let bytes = ecid_report(
            0,
            9,
            1,
            nr_cgi([0x00, 0xF1, 0x10], 0x000000002),
            [0x00, 0x00, 0x01],
            None,
        );
        let (req_id, cells) = decode_nrppa_ecid_report(&bytes).unwrap();
        assert_eq!(req_id, 9);
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0].nr_cgi, "00f110-000000002");
        assert_eq!(cells[0].timing_advance, None);
        assert_eq!(cells[0].rsrp, None);
    }

    /// #715: an NR E-CID report adapts to NR cells: `pci-<n>`, SS-RSRP mapped
    /// per TS 38.133 §10.1.6.1 (`v − 156` dBm), RSRQ raw, and no timing term,
    /// because NR E-CID over LPP has no UE timing quantity.
    #[test]
    fn an_nr_ecid_report_adapts_to_nr_cells_without_a_timing_term() {
        let bytes = crate::lpp_fixtures::nr_ecid_lpp(77, 80, 60, &[(12, 50), (13, 0)], 4);
        let (txn, cells) = decode_lpp_provide_report(&bytes).expect("decodes");
        assert_eq!(txn, 4);
        let got: Vec<_> = cells
            .iter()
            .map(|c| (c.nr_cgi.as_str(), c.rsrp, c.rsrq, c.timing_advance, c.eutra))
            .collect();
        assert_eq!(
            got,
            [
                ("pci-77", Some(-76), Some(60), None, false),
                ("pci-12", Some(-106), None, None, false),
                ("pci-13", Some(-156), None, None, false),
            ]
        );
        // The E-UTRA adapter does not mistake it for its own body.
        let msg = super::decode_lpp(&bytes).unwrap();
        assert!(super::lpp_ecid_provide_to_measurements(&msg).is_empty());
    }

    /// The E-UTRA E-CID adapter's cells are marked E-UTRA (#715).
    #[test]
    fn an_eutra_ecid_report_is_marked_eutra() {
        let bytes = crate::lpp_fixtures::ecid_lpp(42, 60, 700, 9);
        let (_, cells) = decode_lpp_ecid_report(&bytes).unwrap();
        assert!(cells.iter().all(|c| c.eutra));
    }

    /// #715: a UE that reports only NR E-CID capabilities is E-CID only, not
    /// unknown, so a high-accuracy request does not ask it for a method it lacks.
    #[test]
    fn nr_ecid_capabilities_classify_as_ecid_only() {
        use nextgcore_lpp_gen::generated as lpp;
        // commonIEs + E-UTRA E-CID, captured from the hand-written encoder.
        let Some(lpp::LPP_MessageBody::C1(lpp::LPP_MessageBody_c1::ProvideCapabilities(mut caps))) =
            super::decode_lpp(&[0x92, 0x03, 0x08, 0x48, 0x58])
                .unwrap()
                .lpp_message_body
        else {
            panic!("not ProvideCapabilities");
        };
        let lpp::ProvideCapabilitiesCriticalExtensions::C1(
            lpp::ProvideCapabilitiesCriticalExtensions_c1::ProvideCapabilities_r9(ies),
        ) = &mut caps.critical_extensions
        else {
            panic!("not r9");
        };
        ies.ecid_provide_capabilities = None;
        assert_eq!(
            super::classify_ue_capability(&caps),
            super::UeLppCapability::Unknown
        );
        let lpp::ProvideCapabilitiesCriticalExtensions::C1(
            lpp::ProvideCapabilitiesCriticalExtensions_c1::ProvideCapabilities_r9(ies),
        ) = &mut caps.critical_extensions
        else {
            panic!("not r9");
        };
        ies.extensions.nr_ecid_provide_capabilities_r16 =
            Some(lpp::NR_ECID_ProvideCapabilities_r16 {
                nr_ecid_meas_supported_r16:
                    lpp::NR_ECID_ProvideCapabilities_r16Nr_ECID_MeasSupported_r16(super::bits(&[
                        true, true,
                    ])),
                periodical_reporting_r16: None,
                triggered_reporting_r16: None,
                extensions: Default::default(),
            });
        assert_eq!(
            super::classify_ue_capability(&caps),
            super::UeLppCapability::EcidOnly
        );
    }
}
