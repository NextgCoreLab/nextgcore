//! LMF-initiated NRPPa toward NG-RAN (issue #103, TS 38.455, TS 23.273 §6.11.2).
//!
//! # What was missing
//!
//! `nextgcore-asn1c` has had `build_ecid_measurement_initiation_request` (procedure
//! code 2) and `build_trp_information_request` (procedure code 16) since the NRPPa
//! codec landed. **Nothing outside that library's own tests ever called them.**
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

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use nextgcore_asn1c::nrppa::NrppaTransactionId;
use nextgcore_nrppa_gen::generated as nrppa;

/// Is the NRPPa downlink enabled for this process?
static NRPPA_DOWNLINK_ENABLED: AtomicBool = AtomicBool::new(false);

/// NRPPa transaction id, wrapping within the IE's own range.
static NRPPA_TRANSACTION: AtomicU8 = AtomicU8::new(0);

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
/// TS 38.455 types `NRPPATransactionID` as `INTEGER (0..32767)` and the codec's
/// newtype is a `u16`, but this counter is a `u8` and therefore wraps at 256.
/// Wrapping is correct for a correlation id whose lifetime is one measurement
/// exchange, and 256 outstanding NRPPa transactions per LMF is far beyond anything
/// this build sustains — but it is a wrap rather than the IE's full range, and saying
/// so here is cheaper than a reader assuming otherwise.
fn next_transaction_id() -> NrppaTransactionId {
    NrppaTransactionId(NRPPA_TRANSACTION.fetch_add(1, Ordering::Relaxed) as u16)
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

#[cfg(test)]
mod tests {
    use super::*;
    use nextgcore_asn1c::nrppa::{InitiatingMessageValue, NrppaPdu, ProcedureCode};

    /// #103 criterion 3, the E-CID half: the emitted PDU decodes to the expected
    /// PROCEDURE CODE, which is what the criterion asks for — not merely that some
    /// bytes were produced.
    #[test]
    fn the_ecid_initiation_pdu_decodes_to_procedure_code_2() {
        let (txn, bytes) = build_ecid_measurement_initiation(3).expect("encode");
        let decoded = NrppaPdu::decode(&bytes).expect("the emitted PDU must decode");
        match decoded {
            NrppaPdu::InitiatingMessage(m) => {
                assert_eq!(
                    m.procedure_code,
                    ProcedureCode::E_CID_MEASUREMENT_INITIATION,
                    "TS 38.455 §8.2.1.2 procedure code 2"
                );
                assert_eq!(
                    m.nrppa_transaction_id, txn,
                    "the transaction id the caller was handed must be the one on the wire, or \
                     the uplink reply cannot be correlated"
                );
                assert!(matches!(
                    m.value,
                    InitiatingMessageValue::ECidMeasurementInitiationRequest(_)
                ));
            }
            other => panic!("expected an initiating message, got {other:?}"),
        }
    }

    /// The TRP half.
    #[test]
    fn the_trp_information_pdu_decodes_to_procedure_code_16() {
        let (txn, bytes) = build_trp_information(&[1, 2]).expect("encode");
        let decoded = NrppaPdu::decode(&bytes).expect("the emitted PDU must decode");
        match decoded {
            NrppaPdu::InitiatingMessage(m) => {
                assert_eq!(m.procedure_code, ProcedureCode::TRP_INFORMATION_EXCHANGE);
                assert_eq!(m.nrppa_transaction_id, txn);
                assert!(matches!(
                    m.value,
                    InitiatingMessageValue::TrpInformationRequest(_)
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
        assert!(NrppaPdu::decode(&all).is_ok());
        assert!(NrppaPdu::decode(&filtered).is_ok());
        assert_ne!(
            all, filtered,
            "omitting id-TRPList and sending one must not encode identically"
        );
    }

    /// The pre-#515 builders, verbatim, kept as the byte oracle for the generated
    /// encoders (#515 stage 2). They call `nextgcore-asn1c`'s hand-written NRPPa
    /// codec, which the stage 1 cross-checks pinned to hand-derived X.691 octets.
    mod oracle {
        use nextgcore_asn1c::nrppa::{
            build_ecid_measurement_initiation_request, build_trp_information_request,
            MeasurementQuantities, MeasurementQuantitiesItem, MeasurementQuantitiesValue,
            NrppaTransactionId, ReportCharacteristics, TrpId, TrpInformationTypeItem,
            UeMeasurementId,
        };

        pub fn ecid(txn: NrppaTransactionId, meas: u16) -> Vec<u8> {
            let quantities = MeasurementQuantities {
                items: vec![
                    MeasurementQuantitiesItem {
                        measurement_quantities_value: MeasurementQuantitiesValue::CellId,
                    },
                    MeasurementQuantitiesItem {
                        measurement_quantities_value:
                            MeasurementQuantitiesValue::TimingAdvanceType1,
                    },
                    MeasurementQuantitiesItem {
                        measurement_quantities_value: MeasurementQuantitiesValue::Rsrp,
                    },
                ],
            };
            build_ecid_measurement_initiation_request(
                txn,
                UeMeasurementId(meas),
                ReportCharacteristics::OnDemand,
                None,
                &quantities,
            )
            .unwrap()
            .encode()
            .unwrap()
            .to_vec()
        }

        pub fn trp(txn: NrppaTransactionId, trp_ids: &[u16]) -> Vec<u8> {
            let list = if trp_ids.is_empty() {
                None
            } else {
                Some(trp_ids.iter().map(|id| TrpId(*id)).collect())
            };
            build_trp_information_request(
                txn,
                list,
                vec![
                    TrpInformationTypeItem::NrPci,
                    TrpInformationTypeItem::GeoCoord,
                ],
            )
            .unwrap()
            .encode()
            .unwrap()
            .to_vec()
        }
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

    /// The production TRP request (every TRP; NR-PCI + geographical coordinate),
    /// transaction 3 -- the same octets #515 stage 1 derived by hand.
    const PRODUCTION_TRP_REQUEST: [u8; 24] = [
        0x00, 0x10, 0x00, 0x00, 0x03, 0x12, 0x00, 0x00, 0x01, 0x00, 0x1d, 0x00, 0x0b, 0x04, 0x00,
        0x39, 0x00, 0x01, 0x00, 0x00, 0x39, 0x00, 0x01, 0x70,
    ];

    #[test]
    fn the_production_ecid_request_matches_x691() {
        let bytes = encode_ecid_measurement_initiation(NrppaTransactionId(0), 3).unwrap();
        assert_eq!(bytes, PRODUCTION_ECID_REQUEST);
        assert_eq!(
            oracle::ecid(NrppaTransactionId(0), 3),
            PRODUCTION_ECID_REQUEST
        );
    }

    #[test]
    fn the_production_trp_request_matches_x691() {
        let bytes = encode_trp_information_request(NrppaTransactionId(3), &[]).unwrap();
        assert_eq!(bytes, PRODUCTION_TRP_REQUEST);
    }

    /// Every LMF-UE-Measurement-ID the IE can carry (root 1..15 and the extension
    /// 16..256) at every transaction-id edge encodes identically to the oracle.
    #[test]
    fn ecid_request_is_byte_identical_to_the_hand_written_encoder() {
        let mut n = 0;
        for txn in [0u16, 1, 127, 128, 255, 256, 32767] {
            for meas in 1u16..=256 {
                let generated =
                    encode_ecid_measurement_initiation(NrppaTransactionId(txn), meas).unwrap();
                assert_eq!(
                    generated,
                    oracle::ecid(NrppaTransactionId(txn), meas),
                    "txn {txn} measurement id {meas}"
                );
                n += 1;
            }
        }
        assert_eq!(n, 7 * 256);
    }

    /// A measurement id outside the IE's range is refused, not truncated.
    #[test]
    fn an_out_of_range_measurement_id_is_refused() {
        assert!(encode_ecid_measurement_initiation(NrppaTransactionId(0), 0).is_err());
        assert!(encode_ecid_measurement_initiation(NrppaTransactionId(0), 257).is_err());
    }

    /// Every TRP-list shape -- absent, one id at each edge, several, the extension
    /// of TRP-ID (1..65535, ...) excluded since u16 tops out at the root bound --
    /// encodes identically to the oracle.
    #[test]
    fn trp_request_is_byte_identical_to_the_hand_written_encoder() {
        let lists: Vec<Vec<u16>> = vec![
            vec![],
            vec![1],
            vec![255],
            vec![256],
            vec![65535],
            vec![1, 2, 3],
            (1..=64).collect(),
            (1..=300).collect(),
        ];
        for txn in [0u16, 255, 256, 32767] {
            for list in &lists {
                assert_eq!(
                    encode_trp_information_request(NrppaTransactionId(txn), list).unwrap(),
                    oracle::trp(NrppaTransactionId(txn), list),
                    "txn {txn} list of {}",
                    list.len()
                );
            }
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
}
