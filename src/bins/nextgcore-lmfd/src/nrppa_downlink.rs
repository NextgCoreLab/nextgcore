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

use nextgcore_asn1c::nrppa::{
    build_ecid_measurement_initiation_request, build_trp_information_request,
    MeasurementQuantities, MeasurementQuantitiesItem, MeasurementQuantitiesValue,
    NrppaTransactionId, ReportCharacteristics, TrpId, TrpInformationTypeItem, UeMeasurementId,
};

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
    let quantities = MeasurementQuantities {
        items: vec![
            MeasurementQuantitiesItem {
                measurement_quantities_value: MeasurementQuantitiesValue::CellId,
            },
            MeasurementQuantitiesItem {
                measurement_quantities_value: MeasurementQuantitiesValue::TimingAdvanceType1,
            },
            MeasurementQuantitiesItem {
                measurement_quantities_value: MeasurementQuantitiesValue::Rsrp,
            },
        ],
    };
    let txn = next_transaction_id();
    let pdu = build_ecid_measurement_initiation_request(
        txn,
        UeMeasurementId(lmf_ue_measurement_id),
        ReportCharacteristics::OnDemand,
        // No measurementPeriodicity: it is meaningful only for a periodic report,
        // and TS 38.455 makes it conditional on that. Sending one alongside
        // `OnDemand` would be a contradiction a conformant gNB may reject.
        None,
        &quantities,
    )
    .map_err(|e| format!("NRPPa E-CID Measurement Initiation encode: {e}"))?;
    let bytes = pdu
        .encode()
        .map_err(|e| format!("NRPPa PDU encode: {e}"))?
        .to_vec();
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
    let list = if trp_ids.is_empty() {
        None
    } else {
        Some(trp_ids.iter().map(|id| TrpId(*id)).collect())
    };
    let txn = next_transaction_id();
    let pdu = build_trp_information_request(
        txn,
        list,
        vec![
            TrpInformationTypeItem::NrPci,
            TrpInformationTypeItem::GeoCoord,
        ],
    )
    .map_err(|e| format!("NRPPa TRP Information Request encode: {e}"))?;
    let bytes = pdu
        .encode()
        .map_err(|e| format!("NRPPa PDU encode: {e}"))?
        .to_vec();
    Ok((txn, bytes))
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

    /// Transaction ids advance, so two outstanding requests are distinguishable.
    #[test]
    fn transaction_ids_advance() {
        let (a, _) = build_ecid_measurement_initiation(1).expect("encode");
        let (b, _) = build_ecid_measurement_initiation(1).expect("encode");
        assert_ne!(a, b);
    }
}
