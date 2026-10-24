//! LMF-initiated NRPPa toward NG-RAN (issue #103, TS 38.455, TS 23.273 §6.11.2).
//!
//! # What was missing
//!
//! `nextgcore-asn1c` had `build_ecid_measurement_initiation_request` (procedure
//! code 2) and `build_trp_information_request` (procedure code 16) since its NRPPa
//! codec landed. **Nothing outside that library's own tests ever called them.**
//! (#515 replaced that codec with the generated `nextgcore-nrppa-gen`.)
//! `namf_client` could build an LPP N1 transfer and nothing else, so this LMF never
//! spoke NRPPa on the downlink at all: E-CID and TRP measurements could never be
//! solicited from a gNB, and interop with third-party NG-RAN was impossible.
//!
//! `handle_n2_info_notify` was — and remains — the *uplink* receiver. This module is
//! the missing other half.
//!
//! # The transport already existed on the other side
//!
//! The AMF's `try_positioning_relay` accepts an `n2InfoContainer.nrppaInfo` carrying
//! `ngapIeType: NRPPA_PDU` and a binary part, enqueues it, and the NGAP pump
//! delivers it to the serving gNB over NGAP procedure 8 (UE-associated NRPPa
//! transport). It also echoes `nrppaInfo.nfId` into the NGAP RoutingID so the gNB's
//! reply routes back. So the only missing piece was the request the LMF sends —
//! which is why this module is small: it builds a PDU and a multipart body, and
//! everything downstream of the AMF was already there and tested.
//!
//! # Off by default
//!
//! Gated on `LMF_NRPPA_DOWNLINK=1`. #103 asks for the new N2 signalling to be
//! gated so existing E2E behaviour is unaffected until the flows are validated; this
//! is that gate, as a **runtime** switch rather than the cargo feature #103
//! suggests, per this project's convention (a feature-gated path is left uncompiled
//! by CI and rots).

use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};

use nextgcore_nrppa_gen::generated as nrppa;

/// An NRPPa transaction id (`NRPPATransactionID ::= INTEGER (0..32767)`, TS 38.455
/// §9.2.4), as handed to callers for correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NrppaTransactionId(pub u16);

/// Is the NRPPa downlink enabled for this process?
static NRPPA_DOWNLINK_ENABLED: AtomicBool = AtomicBool::new(false);

/// NRPPa transaction id, wrapping within the IE's own range (0..=32767).
static NRPPA_TRANSACTION: AtomicU16 = AtomicU16::new(0);

/// `LMF-Measurement-ID` of the next NRPPa Measurement procedure (TS 38.455
/// `Measurement-ID ::= INTEGER (1..65536, ...)`), wrapping within the root range.
static LMF_MEASUREMENT_ID: AtomicU32 = AtomicU32::new(0);

/// Enable the NRPPa downlink (called once at startup).
pub fn enable() {
    NRPPA_DOWNLINK_ENABLED.store(true, Ordering::SeqCst);
    log::info!(
        "[LMF] NRPPa downlink ENABLED: E-CID Measurement Initiation and TRP Information \
         Requests will be sent toward NG-RAN via the AMF (TS 38.455 §8.2.1/§8.2.6)"
    );
}

/// Whether the NRPPa downlink is enabled.
pub fn enabled() -> bool {
    NRPPA_DOWNLINK_ENABLED.load(Ordering::SeqCst)
}

/// Read `LMF_NRPPA_DOWNLINK` and enable accordingly. Called once from `main`.
pub fn init_from_env() {
    match std::env::var("LMF_NRPPA_DOWNLINK").as_deref() {
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("on") => enable(),
        _ => log::info!(
            "[LMF] NRPPa downlink DISABLED (set LMF_NRPPA_DOWNLINK=1 to enable): no NRPPa \
             procedure is initiated toward NG-RAN, exactly as before #103"
        ),
    }
}

/// Test-only: set the switch without going through startup. Caller holds
/// [`crate::context::PROCESS_STATE_TEST_LOCK`].
#[cfg(test)]
pub fn set_for_test(on: bool) {
    NRPPA_DOWNLINK_ENABLED.store(on, Ordering::SeqCst);
}

/// The next NRPPa transaction id.
///
/// TS 38.455 types `NRPPATransactionID` as `INTEGER (0..32767)`. The counter uses
/// the IE's whole range (#807): the Multi-RTT exchanges correlate their responses
/// by `(procedure code, transaction id)`, and a session runs several of them, so an
/// 8-bit counter would recycle an id while an exchange that used it can still be
/// waiting.
fn next_transaction_id() -> NrppaTransactionId {
    NrppaTransactionId(NRPPA_TRANSACTION.fetch_add(1, Ordering::Relaxed) & 0x7fff)
}

/// The next `LMF-Measurement-ID` (1..=65536).
pub fn next_lmf_measurement_id() -> u32 {
    LMF_MEASUREMENT_ID.fetch_add(1, Ordering::Relaxed) % 65_536 + 1
}

/// Build an `E-CIDMeasurementInitiationRequest` (TS 38.455 §8.2.1.2, procedure
/// code 2) asking the serving gNB for the quantities the E-CID solver reads.
///
/// `On demand` rather than `Periodic`: a DetermineLocation is a one-shot question,
/// and a periodic report would keep arriving after the session it answered has
/// completed — with no procedure in this build to stop it, since NRPPa
/// `E-CIDMeasurementTerminationCommand` has no builder here.
///
/// The quantities are Cell-ID, Timing Advance type 1 and RSRP: exactly what
/// `try_real_solve`'s E-CID path consumes (a serving cell plus a TA ring plus a
/// signal strength to weight by). Asking for more would produce IEs the decoder
/// discards.
pub fn build_ecid_measurement_initiation(
    lmf_ue_measurement_id: u16,
) -> Result<(NrppaTransactionId, Vec<u8>), String> {
    let txn = next_transaction_id();
    let bytes = encode_ecid_measurement_initiation(txn, lmf_ue_measurement_id)?;
    Ok((txn, bytes))
}

/// Build a `TRPInformationRequest` (TS 38.455 §8.2.6, procedure code 16) asking
/// NG-RAN for the TRP reference points this LMF needs to multilaterate.
///
/// `trp_ids` empty means "every TRP": the id-TRPList IE is OPTIONAL and omitting it
/// asks for all of them, which is what an LMF that has just started and knows no TRP
/// ids wants. Passing an empty *list* instead would ask for none.
///
/// The information types are NR-PCI and the geographical coordinate — the PCI is how
/// a measurement report names the TRP, and the coordinate is the reference point
/// itself. Without both, a response cannot fill the registry: a coordinate with no
/// id cannot be looked up, and an id with no coordinate cannot be solved against.
///
/// #911: also the NG-RAN CGI, the ARFCN, the PRS configuration and the SFN
/// initialisation time, which the DL-PRS assistance data is built from. A node
/// that cannot provide some of them leaves them out (TS 38.455 §8.2.8.3 fails the
/// procedure only when it "cannot provide any of the requested information").
pub fn build_trp_information(trp_ids: &[u16]) -> Result<(NrppaTransactionId, Vec<u8>), String> {
    let txn = next_transaction_id();
    let bytes = encode_trp_information_request(txn, trp_ids)?;
    Ok((txn, bytes))
}

// TS 38.455 §9.4.x criticality indices (ENUMERATED { reject, ignore, notify }).
const REJECT: u8 = 0;
const IGNORE: u8 = 1;

/// Encode the E-CIDMeasurementInitiationRequest on the generated NRPPa codec
/// (#515 stage 2). IE order and criticalities follow the
/// `E-CIDMeasurementInitiationRequest-IEs` object set; every IE in it is
/// criticality reject except the optional other-RAT / WLAN quantities, which
/// this LMF does not send.
fn encode_ecid_measurement_initiation(
    txn: NrppaTransactionId,
    lmf_ue_measurement_id: u16,
) -> Result<Vec<u8>, String> {
    use nrppa::E_CIDMeasurementInitiationRequestProtocolIEs_EntryValue as V;
    // UE-Measurement-ID ::= INTEGER (1..15, ..., 16..256): 16..=256 encodes as
    // an extension value. The forked encoder checks only the root bound, so a
    // value outside the whole value set (0, or 257 and up) would otherwise go out
    // as an extension value no peer can accept; refuse it here instead.
    if !(1..=256).contains(&lmf_ue_measurement_id) {
        return Err(format!(
            "NRPPa LMF-UE-Measurement-ID {lmf_ue_measurement_id} is outside 1..256 (TS 38.455 UE-Measurement-ID)"
        ));
    }
    let quantity = |value: u8| nrppa::MeasurementQuantities_Entry {
        id: nrppa::ProtocolIE_ID(nrppa::ID_MEASUREMENT_QUANTITIES_ITEM),
        criticality: nrppa::Criticality(REJECT),
        value: nrppa::MeasurementQuantities_EntryValue::Id_MeasurementQuantities_Item(
            nrppa::MeasurementQuantities_Item {
                measurement_quantities_value: nrppa::MeasurementQuantitiesValue(value),
                ie_extensions: None,
            },
        ),
    };
    let entry = |id: u16, value: V| nrppa::E_CIDMeasurementInitiationRequestProtocolIEs_Entry {
        id: nrppa::ProtocolIE_ID(id),
        criticality: nrppa::Criticality(REJECT),
        value,
    };
    let ies = vec![
        entry(
            nrppa::ID_LMF_UE_MEASUREMENT_ID,
            V::Id_LMF_UE_Measurement_ID(nrppa::UE_Measurement_ID(lmf_ue_measurement_id)),
        ),
        entry(
            nrppa::ID_REPORT_CHARACTERISTICS,
            V::Id_ReportCharacteristics(nrppa::ReportCharacteristics(
                nrppa::ReportCharacteristics::ON_DEMAND,
            )),
        ),
        // No measurementPeriodicity: TS 38.455 makes it conditional on a periodic
        // report, and this request is on demand.
        entry(
            nrppa::ID_MEASUREMENT_QUANTITIES,
            V::Id_MeasurementQuantities(nrppa::MeasurementQuantities(vec![
                quantity(nrppa::MeasurementQuantitiesValue::CELL_ID),
                quantity(nrppa::MeasurementQuantitiesValue::TIMING_ADVANCE_TYPE1),
                quantity(nrppa::MeasurementQuantitiesValue::R_SRP),
            ])),
        ),
    ];
    let pdu = nrppa::NRPPA_PDU::InitiatingMessage(nrppa::InitiatingMessage {
        procedure_code: nrppa::ProcedureCode(nrppa::ID_E_CID_MEASUREMENT_INITIATION),
        criticality: nrppa::Criticality(REJECT),
        nrppatransaction_id: nrppa::NRPPATransactionID(txn.0),
        value: nrppa::InitiatingMessageValue::Id_e_CIDMeasurementInitiation(
            nrppa::E_CIDMeasurementInitiationRequest {
                protocol_i_es: nrppa::E_CIDMeasurementInitiationRequestProtocolIEs(ies),
            },
        ),
    });
    nextgcore_nrppa_gen::encode(&pdu)
        .map_err(|e| format!("NRPPa E-CID Measurement Initiation encode: {e:?}"))
}

/// Encode the TRPInformationRequest on the generated NRPPa codec (#515 stage 2):
/// the OPTIONAL id-TRPList (criticality ignore) only when ids were given, then the
/// MANDATORY id-TRPInformationTypeListTRPReq (criticality reject) asking for the
/// NR-PCI and the geographical coordinate.
fn encode_trp_information_request(
    txn: NrppaTransactionId,
    trp_ids: &[u16],
) -> Result<Vec<u8>, String> {
    use nrppa::TRPInformationRequestProtocolIEs_EntryValue as V;
    let info_type = |value: u8| nrppa::TRPInformationTypeListTRPReq_Entry {
        id: nrppa::ProtocolIE_ID(nrppa::ID_TRP_INFORMATION_TYPE_ITEM),
        criticality: nrppa::Criticality(REJECT),
        value: nrppa::TRPInformationTypeListTRPReq_EntryValue::Id_TRPInformationTypeItem(
            nrppa::TRPInformationTypeItem(value),
        ),
    };
    let mut ies = Vec::with_capacity(2);
    if !trp_ids.is_empty() {
        ies.push(nrppa::TRPInformationRequestProtocolIEs_Entry {
            id: nrppa::ProtocolIE_ID(nrppa::ID_TRP_LIST),
            criticality: nrppa::Criticality(IGNORE),
            value: V::Id_TRPList(nrppa::TRPList(
                trp_ids
                    .iter()
                    .map(|id| nrppa::TRPItem {
                        trp_id: nrppa::TRP_ID(*id),
                        ie_extensions: None,
                    })
                    .collect(),
            )),
        });
    }
    ies.push(nrppa::TRPInformationRequestProtocolIEs_Entry {
        id: nrppa::ProtocolIE_ID(nrppa::ID_TRP_INFORMATION_TYPE_LIST_TRP_REQ),
        criticality: nrppa::Criticality(REJECT),
        value: V::Id_TRPInformationTypeListTRPReq(nrppa::TRPInformationTypeListTRPReq(vec![
            info_type(nrppa::TRPInformationTypeItem::NR_PCI),
            info_type(nrppa::TRPInformationTypeItem::N_G_RAN_CGI),
            info_type(nrppa::TRPInformationTypeItem::ARFCN),
            info_type(nrppa::TRPInformationTypeItem::P_RS_CONFIG),
            info_type(nrppa::TRPInformationTypeItem::S_FN_INIT_TIME),
            info_type(nrppa::TRPInformationTypeItem::GEO_COORD),
        ])),
    });
    let pdu = nrppa::NRPPA_PDU::InitiatingMessage(nrppa::InitiatingMessage {
        procedure_code: nrppa::ProcedureCode(nrppa::ID_T_RP_INFORMATION_EXCHANGE),
        criticality: nrppa::Criticality(REJECT),
        nrppatransaction_id: nrppa::NRPPATransactionID(txn.0),
        value: nrppa::InitiatingMessageValue::Id_tRPInformationExchange(
            nrppa::TRPInformationRequest {
                protocol_i_es: nrppa::TRPInformationRequestProtocolIEs(ies),
            },
        ),
    });
    nextgcore_nrppa_gen::encode(&pdu)
        .map_err(|e| format!("NRPPa TRP Information Request encode: {e:?}"))
}

// ---------------------------------------------------------------------------
// Multi-RTT, the gNB half (#807; TS 38.305 §8.10.3, TS 38.455 §8.2.6, §8.2.9,
// §8.2.10, §8.5.1)
// ---------------------------------------------------------------------------

/// The FR1 SRS bandwidth asked for in the Positioning Information Request, as the
/// `BandwidthSRS.fR1` enumeration index. TS 38.455 §8.2.6.2 has the gNB "take
/// this information into account", so it is a preference, not a demand. 20 MHz
/// unless `lmf.positioning.srsBandwidthMhz` says otherwise (#903 review).
static REQUESTED_SRS_BANDWIDTH_FR1: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(nrppa::BandwidthSRS_fR1::M_HZ20);

/// The `BandwidthSRS.fR1` index of `mhz` (TS 38.455: mHz5, 10, 20, 40, 50, 80,
/// 100, then the extensions 160, 200, 15, 25, 30, 60, 35, 45, 70, 90), or `None`.
pub fn fr1_srs_bandwidth(mhz: u16) -> Option<u8> {
    const ORDER: [u16; 17] = [
        5, 10, 20, 40, 50, 80, 100, 160, 200, 15, 25, 30, 60, 35, 45, 70, 90,
    ];
    ORDER.iter().position(|&m| m == mhz).map(|i| i as u8)
}

/// Set the requested FR1 SRS bandwidth (startup configuration).
pub fn set_srs_bandwidth_mhz(mhz: u16) {
    if let Some(index) = fr1_srs_bandwidth(mhz) {
        REQUESTED_SRS_BANDWIDTH_FR1.store(index, Ordering::Relaxed);
    }
}

/// Build a `POSITIONING INFORMATION REQUEST` (TS 38.455 §8.2.6, procedure code 9),
/// UE-associated, toward the serving gNB.
///
/// It carries `Requested SRS Transmission Characteristics` (semi-persistent SRS)
/// because §8.2.6.2 makes the SRS Configuration and the SFN Initialisation Time in
/// the response conditional on that IE: "it shall include the SRS Configuration IE
/// and the SFN Initialisation Time IE". The measuring gNBs need both. Semi-persistent
/// rather than periodic, so the UE transmits SRS only between the Positioning
/// Activation and Positioning Deactivation of this session (§8.2.9, §8.2.10).
pub fn build_positioning_information_request() -> Result<(NrppaTransactionId, Vec<u8>), String> {
    let txn = next_transaction_id();
    let bytes = encode_positioning_information_request(txn)?;
    Ok((txn, bytes))
}

fn encode_positioning_information_request(txn: NrppaTransactionId) -> Result<Vec<u8>, String> {
    use nrppa::PositioningInformationRequestProtocolIEs_EntryValue as V;
    let ies = vec![nrppa::PositioningInformationRequestProtocolIEs_Entry {
        id: nrppa::ProtocolIE_ID(nrppa::ID_REQUESTED_SRS_TRANSMISSION_CHARACTERISTICS),
        criticality: nrppa::Criticality(IGNORE),
        value: V::Id_RequestedSRSTransmissionCharacteristics(
            nrppa::RequestedSRSTransmissionCharacteristics {
                // Conditional on a periodic resource type only.
                number_of_transmissions: None,
                resource_type: nrppa::RequestedSRSTransmissionCharacteristicsResourceType(
                    nrppa::RequestedSRSTransmissionCharacteristicsResourceType::SEMI_PERSISTENT,
                ),
                bandwidth: nrppa::BandwidthSRS::FR1(nrppa::BandwidthSRS_fR1(
                    REQUESTED_SRS_BANDWIDTH_FR1.load(Ordering::Relaxed),
                )),
                list_of_srs_resource_set: None,
                ssb_information: None,
                ie_extensions: None,
            },
        ),
    }];
    let pdu = nrppa::NRPPA_PDU::InitiatingMessage(nrppa::InitiatingMessage {
        procedure_code: nrppa::ProcedureCode(nrppa::ID_POSITIONING_INFORMATION_EXCHANGE),
        criticality: nrppa::Criticality(REJECT),
        nrppatransaction_id: nrppa::NRPPATransactionID(txn.0),
        value: nrppa::InitiatingMessageValue::Id_positioningInformationExchange(
            nrppa::PositioningInformationRequest {
                protocol_i_es: nrppa::PositioningInformationRequestProtocolIEs(ies),
            },
        ),
    });
    nextgcore_nrppa_gen::encode(&pdu)
        .map_err(|e| format!("NRPPa Positioning Information Request encode: {e:?}"))
}

/// Which UL SRS the Positioning Activation asks the gNB to start (TS 38.455
/// §8.2.9.2): a semi-persistent resource set by its id, or an aperiodic trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrsActivation {
    /// Activate the semi-persistent SRS resource set with this id (0..15).
    SemiPersistent(u8),
    /// Trigger the aperiodic SRS. No `SRS Resource Trigger`: the gNB uses the
    /// trigger state it configured.
    Aperiodic,
}

/// Build a `POSITIONING ACTIVATION REQUEST` (TS 38.455 §8.2.9, procedure code 17),
/// UE-associated, toward the serving gNB.
pub fn build_positioning_activation_request(
    activation: SrsActivation,
) -> Result<(NrppaTransactionId, Vec<u8>), String> {
    let txn = next_transaction_id();
    let bytes = encode_positioning_activation_request(txn, activation)?;
    Ok((txn, bytes))
}

fn encode_positioning_activation_request(
    txn: NrppaTransactionId,
    activation: SrsActivation,
) -> Result<Vec<u8>, String> {
    use nrppa::PositioningActivationRequestProtocolIEs_EntryValue as V;
    let srs_type = match activation {
        SrsActivation::SemiPersistent(set) => {
            // SRSResourceSetID ::= INTEGER (0..15, ...); the forked encoder checks
            // only the root bound, so a value above it is refused here.
            if set > 15 {
                return Err(format!(
                    "SRS resource set id {set} is outside 0..15 (TS 38.455 SRSResourceSetID)"
                ));
            }
            nrppa::SRSType::SemipersistentSRS(nrppa::SemipersistentSRS {
                srs_resource_set_id: nrppa::SRSResourceSetID(set),
                ie_extensions: None,
            })
        }
        SrsActivation::Aperiodic => nrppa::SRSType::AperiodicSRS(nrppa::AperiodicSRS {
            aperiodic: nrppa::AperiodicSRSAperiodic(nrppa::AperiodicSRSAperiodic::TRUE),
            srs_resource_trigger: None,
            ie_extensions: None,
        }),
    };
    let ies = vec![nrppa::PositioningActivationRequestProtocolIEs_Entry {
        id: nrppa::ProtocolIE_ID(nrppa::ID_SRS_TYPE),
        criticality: nrppa::Criticality(REJECT),
        value: V::Id_SRSType(srs_type),
    }];
    let pdu = nrppa::NRPPA_PDU::InitiatingMessage(nrppa::InitiatingMessage {
        procedure_code: nrppa::ProcedureCode(nrppa::ID_POSITIONING_ACTIVATION),
        criticality: nrppa::Criticality(REJECT),
        nrppatransaction_id: nrppa::NRPPATransactionID(txn.0),
        value: nrppa::InitiatingMessageValue::Id_positioningActivation(
            nrppa::PositioningActivationRequest {
                protocol_i_es: nrppa::PositioningActivationRequestProtocolIEs(ies),
            },
        ),
    });
    nextgcore_nrppa_gen::encode(&pdu)
        .map_err(|e| format!("NRPPa Positioning Activation Request encode: {e:?}"))
}

/// Build a `POSITIONING DEACTIVATION` (TS 38.455 §8.2.10, procedure code 18,
/// class 2), UE-associated: stop the semi-persistent SRS this session activated,
/// or release every SRS resource when the set is not known.
pub fn build_positioning_deactivation(
    srs_resource_set: Option<u8>,
) -> Result<(NrppaTransactionId, Vec<u8>), String> {
    use nrppa::PositioningDeactivationProtocolIEs_EntryValue as V;
    let txn = next_transaction_id();
    let abort = match srs_resource_set {
        Some(set) if set <= 15 => {
            nrppa::AbortTransmission::DeactivateSRSResourceSetID(nrppa::SRSResourceSetID(set))
        }
        _ => nrppa::AbortTransmission::ReleaseALL(nrppa::AbortTransmission_releaseALL),
    };
    let pdu = nrppa::NRPPA_PDU::InitiatingMessage(nrppa::InitiatingMessage {
        procedure_code: nrppa::ProcedureCode(nrppa::ID_POSITIONING_DEACTIVATION),
        criticality: nrppa::Criticality(IGNORE),
        nrppatransaction_id: nrppa::NRPPATransactionID(txn.0),
        value: nrppa::InitiatingMessageValue::Id_positioningDeactivation(
            nrppa::PositioningDeactivation {
                protocol_i_es: nrppa::PositioningDeactivationProtocolIEs(vec![
                    nrppa::PositioningDeactivationProtocolIEs_Entry {
                        id: nrppa::ProtocolIE_ID(nrppa::ID_ABORT_TRANSMISSION),
                        criticality: nrppa::Criticality(IGNORE),
                        value: V::Id_AbortTransmission(abort),
                    },
                ]),
            },
        ),
    });
    let bytes = nextgcore_nrppa_gen::encode(&pdu)
        .map_err(|e| format!("NRPPa Positioning Deactivation encode: {e:?}"))?;
    Ok((txn, bytes))
}

/// What a `MEASUREMENT REQUEST` asks of one gNB (TS 38.455 §8.5.1).
#[derive(Clone, Copy)]
pub struct MeasurementRequest<'a> {
    /// `LMF-Measurement-ID`, echoed in the response.
    pub lmf_measurement_id: u32,
    /// The TRPs of this gNB to measure (1..=64, `maxNoOfMeasTRPs`).
    pub trp_ids: &'a [u16],
    /// The UE's SRS configuration from the Positioning Information Response. The
    /// measuring TRPs need it to find the UE's SRS (TS 38.305 §8.10.3.2 step 6).
    pub srs_configuration: Option<&'a nrppa::SRSConfiguration>,
    /// The serving cell's SFN Initialisation Time, from the same response.
    pub sfn_initialisation_time: Option<&'a nrppa::RelativeTime1900>,
    /// The time the gNB has to answer in (`Response Time`), in milliseconds.
    pub response_time_ms: Option<u32>,
}

/// Build a `MEASUREMENT REQUEST` (TS 38.455 §8.5.1, procedure code 11),
/// non-UE-associated, asking for the gNB Rx-Tx time difference (TS 38.215 §5.2.3)
/// of each listed TRP, on demand.
pub fn build_measurement_request(
    request: &MeasurementRequest<'_>,
) -> Result<(NrppaTransactionId, Vec<u8>), String> {
    let txn = next_transaction_id();
    let bytes = encode_measurement_request(txn, request)?;
    Ok((txn, bytes))
}

/// `Response Time` (TS 38.455 §9.2.x `ResponseTime`): `time` 1..128 in units of
/// 10 ms, 1 s or 10 s, rounded down so the gNB is never told it has longer than
/// the LMF will wait. `None` below 10 ms.
fn response_time(ms: u32) -> Option<nrppa::ResponseTime> {
    let (time, unit) = if ms < 10 {
        return None;
    } else if ms <= 1_280 {
        (ms / 10, nrppa::ResponseTimeTimeUnit::TEN_MILLISECONDS)
    } else if ms < 128_000 {
        (ms / 1_000, nrppa::ResponseTimeTimeUnit::SECOND)
    } else {
        (
            (ms / 10_000).min(128),
            nrppa::ResponseTimeTimeUnit::TEN_SECONDS,
        )
    };
    Some(nrppa::ResponseTime {
        time: nrppa::ResponseTimeTime(u8::try_from(time.clamp(1, 128)).unwrap_or(128)),
        time_unit: nrppa::ResponseTimeTimeUnit(unit),
        ie_extensions: None,
    })
}

fn encode_measurement_request(
    txn: NrppaTransactionId,
    request: &MeasurementRequest<'_>,
) -> Result<Vec<u8>, String> {
    use nrppa::MeasurementRequestProtocolIEs_EntryValue as V;
    if !(1..=65_536).contains(&request.lmf_measurement_id) {
        return Err(format!(
            "LMF-Measurement-ID {} is outside 1..65536 (TS 38.455 Measurement-ID)",
            request.lmf_measurement_id
        ));
    }
    if request.trp_ids.is_empty() || request.trp_ids.len() > 64 {
        return Err(format!(
            "a Measurement Request names 1..64 TRPs (maxNoOfMeasTRPs), not {}",
            request.trp_ids.len()
        ));
    }
    if let Some(bad) = request.trp_ids.iter().find(|&&t| t == 0) {
        return Err(format!(
            "TRP-ID {bad} is outside 1..65535 (TS 38.455 TRP-ID)"
        ));
    }
    let entry = |id: u16, criticality: u8, value: V| nrppa::MeasurementRequestProtocolIEs_Entry {
        id: nrppa::ProtocolIE_ID(id),
        criticality: nrppa::Criticality(criticality),
        value,
    };
    // IE order and criticality follow `MeasurementRequest-IEs`.
    let mut ies = vec![
        entry(
            nrppa::ID_LMF_MEASUREMENT_ID,
            REJECT,
            V::Id_LMF_Measurement_ID(nrppa::Measurement_ID(request.lmf_measurement_id)),
        ),
        entry(
            nrppa::ID_TRP_MEASUREMENT_REQUEST_LIST,
            REJECT,
            V::Id_TRP_MeasurementRequestList(nrppa::TRP_MeasurementRequestList(
                request
                    .trp_ids
                    .iter()
                    .map(|id| nrppa::TRP_MeasurementRequestItem {
                        trp_id: nrppa::TRP_ID(*id),
                        search_window_information: None,
                        ie_extensions: None,
                    })
                    .collect(),
            )),
        ),
        // On demand: the results come back in the MEASUREMENT RESPONSE and the
        // measurement ends there (§8.5.1.2), so there is nothing to abort later.
        entry(
            nrppa::ID_REPORT_CHARACTERISTICS,
            REJECT,
            V::Id_ReportCharacteristics(nrppa::ReportCharacteristics(
                nrppa::ReportCharacteristics::ON_DEMAND,
            )),
        ),
        entry(
            nrppa::ID_TRP_MEASUREMENT_QUANTITIES,
            REJECT,
            V::Id_TRPMeasurementQuantities(nrppa::TRPMeasurementQuantities(vec![
                nrppa::TRPMeasurementQuantitiesList_Item {
                    trp_measurement_type: nrppa::TRPMeasurementType(
                        nrppa::TRPMeasurementType::G_NB_RX_TX_TIME_DIFF,
                    ),
                    timing_reporting_granularity_factor: None,
                    ie_extensions: None,
                },
            ])),
        ),
    ];
    if let Some(t) = request.sfn_initialisation_time {
        ies.push(entry(
            nrppa::ID_SFN_INITIALISATION_TIME,
            IGNORE,
            V::Id_SFNInitialisationTime(t.clone()),
        ));
    }
    if let Some(srs) = request.srs_configuration {
        ies.push(entry(
            nrppa::ID_SRS_CONFIGURATION,
            IGNORE,
            V::Id_SRSConfiguration(srs.clone()),
        ));
    }
    if let Some(rt) = request.response_time_ms.and_then(response_time) {
        ies.push(entry(
            nrppa::ID_RESPONSE_TIME,
            IGNORE,
            V::Id_ResponseTime(rt),
        ));
    }
    let pdu = nrppa::NRPPA_PDU::InitiatingMessage(nrppa::InitiatingMessage {
        procedure_code: nrppa::ProcedureCode(nrppa::ID_MEASUREMENT),
        criticality: nrppa::Criticality(REJECT),
        nrppatransaction_id: nrppa::NRPPATransactionID(txn.0),
        value: nrppa::InitiatingMessageValue::Id_Measurement(nrppa::MeasurementRequest {
            protocol_i_es: nrppa::MeasurementRequestProtocolIEs(ies),
        }),
    });
    nextgcore_nrppa_gen::encode(&pdu)
        .map_err(|e| format!("NRPPa Measurement Request encode: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #103 criterion 3, the E-CID half: the emitted PDU decodes to the expected
    /// PROCEDURE CODE, which is what the criterion asks for — not merely that some
    /// bytes were produced.
    #[test]
    fn the_ecid_initiation_pdu_decodes_to_procedure_code_2() {
        let (txn, bytes) = build_ecid_measurement_initiation(3).expect("encode");
        match nextgcore_nrppa_gen::decode(&bytes).expect("the emitted PDU must decode") {
            nrppa::NRPPA_PDU::InitiatingMessage(m) => {
                assert_eq!(
                    m.procedure_code.0,
                    nrppa::ID_E_CID_MEASUREMENT_INITIATION,
                    "TS 38.455 §8.2.1.2 procedure code 2"
                );
                assert_eq!(
                    m.nrppatransaction_id.0, txn.0,
                    "the transaction id the caller was handed must be the one on the wire, or \
                     the uplink reply cannot be correlated"
                );
                assert!(matches!(
                    m.value,
                    nrppa::InitiatingMessageValue::Id_e_CIDMeasurementInitiation(_)
                ));
            }
            other => panic!("expected an initiating message, got {other:?}"),
        }
    }

    /// The TRP half.
    #[test]
    fn the_trp_information_pdu_decodes_to_procedure_code_16() {
        let (txn, bytes) = build_trp_information(&[1, 2]).expect("encode");
        match nextgcore_nrppa_gen::decode(&bytes).expect("the emitted PDU must decode") {
            nrppa::NRPPA_PDU::InitiatingMessage(m) => {
                assert_eq!(m.procedure_code.0, nrppa::ID_T_RP_INFORMATION_EXCHANGE);
                assert_eq!(m.nrppatransaction_id.0, txn.0);
                assert!(matches!(
                    m.value,
                    nrppa::InitiatingMessageValue::Id_tRPInformationExchange(_)
                ));
            }
            other => panic!("expected an initiating message, got {other:?}"),
        }
    }

    /// An empty id list omits the OPTIONAL id-TRPList IE, asking for every TRP.
    /// Encoding an empty list instead would ask for none — the opposite — so the two
    /// forms are pinned as producing DIFFERENT bytes.
    #[test]
    fn no_trp_ids_asks_for_all_of_them_and_differs_from_a_filtered_request() {
        let (_, all) = build_trp_information(&[]).expect("encode");
        let (_, filtered) = build_trp_information(&[7]).expect("encode");
        assert!(nextgcore_nrppa_gen::decode(&all).is_ok());
        assert!(nextgcore_nrppa_gen::decode(&filtered).is_ok());
        assert_ne!(
            all, filtered,
            "omitting id-TRPList and sending one must not encode identically"
        );
    }

    /// The production E-CID request, derived by hand from X.691 / TS 38.455
    /// (transaction 0, LMF measurement id 3, on demand, cell-ID + TA type 1 + RSRP):
    ///
    /// ```text
    /// 00 02 00 00 00 21  initiatingMessage, procedure 2, reject, transaction 0, length 33
    ///  00 00 03          SEQUENCE ext 0 + pad; 3 IEs
    ///  00 02 00 01 10    LMF-UE-Measurement-ID, reject; ext 0, 3-1 in 4 bits
    ///  00 03 00 01 00    ReportCharacteristics, reject; ext 0, onDemand
    ///  00 05 00 10       MeasurementQuantities, reject; 16 octets:
    ///   08               SIZE(1..64) count-1 = 2 in 6 bits, pad
    ///   00 0b 00 01 00   Item, reject; ext 0, no iE-Extensions, cell-ID (0)
    ///   00 0b 00 01 08   ... timingAdvanceType1 (2)
    ///   00 0b 00 01 10   ... rSRP (4)
    /// ```
    const PRODUCTION_ECID_REQUEST: [u8; 39] = [
        0x00, 0x02, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x01, 0x10, 0x00,
        0x03, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x10, 0x08, 0x00, 0x0b, 0x00, 0x01, 0x00, 0x00,
        0x0b, 0x00, 0x01, 0x08, 0x00, 0x0b, 0x00, 0x01, 0x10,
    ];

    /// The production TRP request (every TRP), transaction 3, derived by hand from
    /// X.691 (APER) and TS 38.455. #515 stage 1 derived the two-type version
    /// (NR-PCI + geographical coordinate); #911 adds four types:
    ///
    /// ```text
    /// 00 10 00 00 03 26  initiatingMessage, procedure 16, reject, transaction 3, length 38
    ///  00 00 01          SEQUENCE ext 0 + pad; 1 IE (no id-TRPList: every TRP)
    ///  00 1d 00 1f       TRPInformationTypeListTRPReq (29), reject; 31 octets:
    ///   14               SIZE(1..64) count-1 = 5 in 6 bits, pad
    ///   00 39 00 01 00   TRPInformationTypeItem (57), reject; ext 0, nrPCI (0) in 3 bits
    ///   00 39 00 01 10   ... nG-RAN-CGI (1)
    ///   00 39 00 01 20   ... arfcn (2)
    ///   00 39 00 01 30   ... pRSConfig (3)
    ///   00 39 00 01 50   ... sFNInitTime (5)
    ///   00 39 00 01 70   ... geoCoord (7)
    /// ```
    const PRODUCTION_TRP_REQUEST: [u8; 44] = [
        0x00, 0x10, 0x00, 0x00, 0x03, 0x26, 0x00, 0x00, 0x01, 0x00, 0x1d, 0x00, 0x1f, 0x14, 0x00,
        0x39, 0x00, 0x01, 0x00, 0x00, 0x39, 0x00, 0x01, 0x10, 0x00, 0x39, 0x00, 0x01, 0x20, 0x00,
        0x39, 0x00, 0x01, 0x30, 0x00, 0x39, 0x00, 0x01, 0x50, 0x00, 0x39, 0x00, 0x01, 0x70,
    ];

    #[test]
    fn the_production_ecid_request_matches_x691() {
        let bytes = encode_ecid_measurement_initiation(NrppaTransactionId(0), 3).unwrap();
        assert_eq!(bytes, PRODUCTION_ECID_REQUEST);
    }

    #[test]
    fn the_production_trp_request_matches_x691() {
        let bytes = encode_trp_information_request(NrppaTransactionId(3), &[]).unwrap();
        assert_eq!(bytes, PRODUCTION_TRP_REQUEST);
    }

    /// The measurement-id and transaction-id edges, each against octets derived
    /// by hand: the root maximum 15 (`0 1110` in 4 bits), the first extension
    /// value 16 (X.691 §12.1: extension bit 1, then an unconstrained integer --
    /// length 1, value 0x10 -- so the IE value grows to three octets), and the
    /// largest transaction id. #515 stage 2 showed the generated encoder equal to
    /// the deleted hand-written one for every id 1..=256 at seven transaction ids.
    #[test]
    fn ecid_request_edges_match_x691() {
        let mut root_max = PRODUCTION_ECID_REQUEST.to_vec();
        root_max[13] = 0x70;
        assert_eq!(
            encode_ecid_measurement_initiation(NrppaTransactionId(0), 15).unwrap(),
            root_max
        );

        let first_extension: Vec<u8> = [
            &[0x00, 0x02, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x03][..],
            &[0x00, 0x02, 0x00, 0x03, 0x80, 0x01, 0x10],
            &PRODUCTION_ECID_REQUEST[14..],
        ]
        .concat();
        assert_eq!(
            encode_ecid_measurement_initiation(NrppaTransactionId(0), 16).unwrap(),
            first_extension
        );

        let mut last_txn = PRODUCTION_ECID_REQUEST.to_vec();
        last_txn[3..5].copy_from_slice(&[0x7f, 0xff]);
        assert_eq!(
            encode_ecid_measurement_initiation(NrppaTransactionId(32767), 3).unwrap(),
            last_txn
        );
    }

    /// A measurement id outside the IE's range is refused, not truncated.
    #[test]
    fn an_out_of_range_measurement_id_is_refused() {
        assert!(encode_ecid_measurement_initiation(NrppaTransactionId(0), 0).is_err());
        assert!(encode_ecid_measurement_initiation(NrppaTransactionId(0), 257).is_err());
    }

    /// A TRP request naming one TRP, derived by hand: the OPTIONAL id-TRPList
    /// (47, ignore) carries SIZE(1..65535) count-1 = 0 (2-octet aligned), then
    /// the TRPItem (ext 0, no iE-Extensions, TRP-ID ext 0, pad) and TRP-ID 1 as
    /// 1..65535 (2-octet aligned) -- five octets -- ahead of the information-type
    /// list of [`PRODUCTION_TRP_REQUEST`].
    #[test]
    fn a_trp_request_naming_one_trp_matches_x691() {
        let expected: Vec<u8> = [
            &[0x00, 0x10, 0x00, 0x00, 0x03, 0x2f, 0x00, 0x00, 0x02][..],
            &[0x00, 0x2f, 0x40, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00],
            &PRODUCTION_TRP_REQUEST[9..],
        ]
        .concat();
        assert_eq!(
            encode_trp_information_request(NrppaTransactionId(3), &[1]).unwrap(),
            expected
        );
    }

    /// Every TRP-list shape the encoder takes round-trips: the ids decode back.
    #[test]
    fn trp_lists_round_trip_through_the_generated_codec() {
        for list in [
            vec![1u16],
            vec![255],
            vec![256],
            vec![65535],
            (1..=300).collect(),
        ] {
            let bytes = encode_trp_information_request(NrppaTransactionId(7), &list).unwrap();
            let nrppa::NRPPA_PDU::InitiatingMessage(m) =
                nextgcore_nrppa_gen::decode(&bytes).unwrap()
            else {
                panic!("not an initiating message");
            };
            let nrppa::InitiatingMessageValue::Id_tRPInformationExchange(req) = m.value else {
                panic!("not a TRP Information Request");
            };
            let ids: Vec<u16> = req
                .protocol_i_es
                .0
                .iter()
                .find_map(|ie| match &ie.value {
                    nrppa::TRPInformationRequestProtocolIEs_EntryValue::Id_TRPList(l) => {
                        Some(l.0.iter().map(|t| t.trp_id.0).collect())
                    }
                    _ => None,
                })
                .expect("the TRP list");
            assert_eq!(ids, list);
        }
    }

    /// The production path, end to end short of the network: what
    /// `initiate_positioning` hands `send_n2_nrppa_transfer` goes through the
    /// N1N2MessageTransfer multipart builder and the SBI multipart codec amfd
    /// decodes with, and the NRPPa part that comes out is the generated codec's
    /// E-CID request -- procedure 2, the caller's transaction id, the LMF's
    /// fixed measurement id -- byte for byte.
    #[test]
    fn the_n2_transfer_carries_the_generated_ecid_request() {
        use nextgcore_sbi::multipart;
        let (txn, pdu) = build_ecid_measurement_initiation(1).expect("encode");
        let request = crate::namf_client::build_n2_nrppa_transfer_request(
            "imsi-001010000000042",
            "corr-1",
            "lmf-1",
            pdu.clone(),
        );
        let boundary = multipart::generate_boundary();
        let wire = multipart::encode(
            request.http.content.as_deref(),
            &request.http.parts,
            &boundary,
        );
        let decoded =
            multipart::decode(&multipart::content_type_with_boundary(&boundary), &wire).unwrap();
        let part = decoded
            .parts
            .iter()
            .find(|p| p.content_id.as_deref() == Some(crate::namf_client::NRPPA_CONTENT_ID))
            .expect("the NRPPa part");
        assert_eq!(part.data.as_ref(), pdu.as_slice());
        match nextgcore_nrppa_gen::decode(&part.data).expect("generated decode") {
            nrppa::NRPPA_PDU::InitiatingMessage(m) => {
                assert_eq!(m.procedure_code.0, nrppa::ID_E_CID_MEASUREMENT_INITIATION);
                assert_eq!(m.nrppatransaction_id.0, txn.0);
                let nrppa::InitiatingMessageValue::Id_e_CIDMeasurementInitiation(req) = m.value
                else {
                    panic!("not an E-CID Measurement Initiation Request");
                };
                assert!(req.protocol_i_es.0.iter().any(|ie| matches!(
                    ie.value,
                    nrppa::E_CIDMeasurementInitiationRequestProtocolIEs_EntryValue::Id_LMF_UE_Measurement_ID(
                        nrppa::UE_Measurement_ID(1)
                    )
                )));
            }
            other => panic!("expected an initiating message, got {other:?}"),
        }
    }

    /// Transaction ids advance, so two outstanding requests are distinguishable.
    #[test]
    fn transaction_ids_advance() {
        let (a, _) = build_ecid_measurement_initiation(1).expect("encode");
        let (b, _) = build_ecid_measurement_initiation(1).expect("encode");
        assert_ne!(a, b);
    }

    /// #807: the Positioning Activation Request for semi-persistent SRS set 3,
    /// derived by hand from X.691 / TS 38.455:
    ///
    /// ```text
    /// 00 11 00 00 00 09  initiatingMessage, procedure 17, reject, transaction 0, length 9
    ///  00 00 01          ext 0 + pad; 1 IE
    ///  00 2c 00 02       SRSType (44), reject, 2 octets:
    ///   01 80            CHOICE semipersistentSRS (2 bits 00, no extension marker);
    ///                    SEQUENCE ext 0, iE-Extensions absent; SRSResourceSetID
    ///                    ext 0 then 3 in 4 bits: 00 0 0 0 0011 -> 0000 0001 1000 0000
    /// ```
    #[test]
    fn the_positioning_activation_request_matches_x691() {
        let bytes = encode_positioning_activation_request(
            NrppaTransactionId(0),
            SrsActivation::SemiPersistent(3),
        )
        .unwrap();
        assert_eq!(
            bytes,
            [
                0x00, 0x11, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x2c, 0x00, 0x02, 0x01,
                0x80
            ]
        );
        assert!(encode_positioning_activation_request(
            NrppaTransactionId(0),
            SrsActivation::SemiPersistent(16)
        )
        .is_err());
    }

    /// #807: the Positioning Information Request, by hand:
    ///
    /// ```text
    /// 00 09 00 00 01 09  initiatingMessage, procedure 9, reject, transaction 1, length 9
    ///  00 00 01          1 IE
    ///  00 0c 40 02       RequestedSRSTransmissionCharacteristics (12), ignore, 2 octets:
    ///   01 08            ext 0; 4 optionals absent; resourceType ext 0, semi-persistent
    ///                    (01); bandwidth CHOICE fR1 (00); fR1 ext 0, mHz20 (010):
    ///                    0 0000 0 01 00 0 010 -> 0000 0001 0000 10(00)
    /// ```
    #[test]
    fn the_positioning_information_request_matches_x691() {
        assert_eq!(
            encode_positioning_information_request(NrppaTransactionId(1)).unwrap(),
            [
                0x00, 0x09, 0x00, 0x00, 0x01, 0x09, 0x00, 0x00, 0x01, 0x00, 0x0c, 0x40, 0x02, 0x01,
                0x08
            ]
        );
    }

    /// The Measurement Request round-trips with every IE §8.5.1 needs, and refuses
    /// what the IE ranges do not admit.
    #[test]
    fn the_measurement_request_carries_what_the_trps_need() {
        let srs = crate::nrppa_positioning::test_support::srs_configuration(2);
        let req = MeasurementRequest {
            lmf_measurement_id: 65_536,
            trp_ids: &[1, 7],
            srs_configuration: Some(&srs),
            sfn_initialisation_time: None,
            response_time_ms: Some(1_500),
        };
        let bytes = encode_measurement_request(NrppaTransactionId(5), &req).unwrap();
        let nrppa::NRPPA_PDU::InitiatingMessage(m) = nextgcore_nrppa_gen::decode(&bytes).unwrap()
        else {
            panic!("not an initiating message");
        };
        assert_eq!(m.procedure_code.0, nrppa::ID_MEASUREMENT);
        let nrppa::InitiatingMessageValue::Id_Measurement(r) = m.value else {
            panic!("not a Measurement Request");
        };
        use nrppa::MeasurementRequestProtocolIEs_EntryValue as V;
        let ies = &r.protocol_i_es.0;
        assert!(matches!(
            ies[0].value,
            V::Id_LMF_Measurement_ID(nrppa::Measurement_ID(65_536))
        ));
        assert!(ies.iter().any(|ie| matches!(&ie.value, V::Id_ReportCharacteristics(c) if c.0 == nrppa::ReportCharacteristics::ON_DEMAND)));
        assert!(ies
            .iter()
            .any(|ie| matches!(&ie.value, V::Id_SRSConfiguration(c) if *c == srs)));
        // 1500 ms is 1 s in whole seconds, never more than the LMF waits.
        assert!(ies
            .iter()
            .any(|ie| matches!(&ie.value, V::Id_ResponseTime(t)
            if t.time.0 == 1 && t.time_unit.0 == nrppa::ResponseTimeTimeUnit::SECOND)));
        for bad in [
            MeasurementRequest {
                lmf_measurement_id: 0,
                ..req
            },
            MeasurementRequest {
                trp_ids: &[],
                ..req
            },
            MeasurementRequest {
                trp_ids: &[0],
                ..req
            },
        ] {
            assert!(encode_measurement_request(NrppaTransactionId(5), &bad).is_err());
        }
    }

    /// The response time is in the largest unit that does not overstate it.
    #[test]
    fn the_response_time_never_overstates_the_wait() {
        let rt = |ms| response_time(ms).map(|t| (t.time.0, t.time_unit.0));
        assert_eq!(rt(5), None);
        assert_eq!(
            rt(10),
            Some((1, nrppa::ResponseTimeTimeUnit::TEN_MILLISECONDS))
        );
        assert_eq!(
            rt(1_280),
            Some((128, nrppa::ResponseTimeTimeUnit::TEN_MILLISECONDS))
        );
        assert_eq!(rt(20_000), Some((20, nrppa::ResponseTimeTimeUnit::SECOND)));
    }

    /// #903 review MINOR 5: the requested SRS bandwidth follows the TS 38.455
    /// `BandwidthSRS.fR1` enumeration, root values first, then the extensions.
    #[test]
    fn fr1_srs_bandwidths_map_to_their_enumeration_index() {
        assert_eq!(fr1_srs_bandwidth(5), Some(0));
        assert_eq!(fr1_srs_bandwidth(20), Some(nrppa::BandwidthSRS_fR1::M_HZ20));
        assert_eq!(fr1_srs_bandwidth(100), Some(6));
        assert_eq!(fr1_srs_bandwidth(160), Some(7));
        assert_eq!(fr1_srs_bandwidth(90), Some(16));
        assert_eq!(fr1_srs_bandwidth(21), None);
    }
}
