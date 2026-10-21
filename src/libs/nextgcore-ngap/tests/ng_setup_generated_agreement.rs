//! #417: the hand-written NG Setup builders against the generated codec, moved
//! here from `nextgcore-ngap-gen`'s unit tests: their subject is this crate's
//! builders, so they live (and are deleted) with them. The generated codec must
//! decode what these builders put on the wire and re-encode it byte for byte.

use nextgcore_ngap::builder::build_ng_setup_response;
use nextgcore_ngap::types::{Guami, NgSetupResponse, PlmnSupportItem, SNssai, ServedGuamiItem};
use nextgcore_ngap_gen::generated;
use nextgcore_ngap_gen::{decode, encode, NGAP_PDU};

fn assert_round_trips(bytes: &[u8]) -> NGAP_PDU {
    let pdu =
        decode(bytes).unwrap_or_else(|e| panic!("generated codec rejected {bytes:02x?}: {e:?}"));
    let reencoded = encode(&pdu).expect("re-encode");
    assert_eq!(
        reencoded, bytes,
        "generated re-encoding must be byte-identical"
    );
    pdu
}

#[test]
fn hand_written_ng_setup_response_decodes_and_reencodes_identically() {
    let bytes = build_ng_setup_response(&NgSetupResponse {
        amf_name: "nextgcore-amf".to_string(),
        served_guami_list: vec![ServedGuamiItem {
            guami: Guami {
                plmn_identity: [0x00, 0xF1, 0x10],
                amf_region_id: 0x02,
                amf_set_id: 0x001,
                amf_pointer: 0x01,
            },
            backup_amf_name: None,
        }],
        relative_amf_capacity: 255,
        plmn_support_list: vec![PlmnSupportItem {
            plmn_identity: [0x00, 0xF1, 0x10],
            slice_support_list: vec![SNssai { sst: 1, sd: None }],
        }],
    })
    .expect("hand-written builder");

    let pdu = assert_round_trips(&bytes);
    assert!(
        matches!(pdu, NGAP_PDU::SuccessfulOutcome(_)),
        "NG Setup Response is a SuccessfulOutcome, got {pdu:?}"
    );
    // Outer CHOICE: extension bit 0, then index 1 in two bits -> 0b0010_0000.
    assert_eq!(
        bytes[0], 0x20,
        "byte 0 carries the SuccessfulOutcome CHOICE index"
    );
}

/// #445: the hand-written `build_ng_setup_failure` now carries Criticality
/// Diagnostics. The generated codec must decode that PDU, re-encode it byte for
/// byte, and read back every component -- so the two codecs agree on the IE,
/// not merely on its presence.
#[test]
fn hand_written_ng_setup_failure_with_diagnostics_decodes_and_reencodes_identically() {
    use generated::{NGSetupFailureProtocolIEs_EntryValue as Ie, UnsuccessfulOutcomeValue};
    use nextgcore_asn1c::ngap::cause::{Cause, CauseMisc};
    use nextgcore_asn1c::ngap::types::Criticality;
    use nextgcore_ngap::builder::build_ng_setup_failure;
    use nextgcore_ngap::types::{
        CriticalityDiagnostics, IeCriticalityDiagnostics, NgSetupFailure, TimeToWait, TypeOfError,
    };

    let bytes = build_ng_setup_failure(&NgSetupFailure {
        cause: Cause::Misc(CauseMisc::Unspecified),
        time_to_wait: Some(TimeToWait::V10s),
        criticality_diagnostics: Some(CriticalityDiagnostics {
            procedure_code: Some(21),
            triggering_message: Some(0),
            procedure_criticality: Some(0),
            ies: vec![
                IeCriticalityDiagnostics {
                    ie_criticality: Criticality::Reject,
                    ie_id: 27,
                    type_of_error: TypeOfError::Missing,
                },
                IeCriticalityDiagnostics {
                    ie_criticality: Criticality::Notify,
                    ie_id: 9999,
                    type_of_error: TypeOfError::NotUnderstood,
                },
            ],
        }),
    })
    .expect("hand-written NG Setup Failure");

    let NGAP_PDU::UnsuccessfulOutcome(outcome) = assert_round_trips(&bytes) else {
        panic!("NG Setup Failure is an UnsuccessfulOutcome");
    };
    let UnsuccessfulOutcomeValue::Id_NGSetup(failure) = outcome.value else {
        panic!("NG Setup Failure");
    };
    let ies = &failure.protocol_i_es.0;
    assert_eq!(ies.len(), 3, "Cause, TimeToWait, CriticalityDiagnostics");
    let last = ies.last().expect("IEs");
    assert_eq!(last.id.0, generated::ID_CRITICALITY_DIAGNOSTICS);
    assert_eq!(last.criticality.0, generated::Criticality::IGNORE);
    let Ie::Id_CriticalityDiagnostics(cd) = &last.value else {
        panic!("Criticality Diagnostics is the last IE");
    };
    assert_eq!(cd.procedure_code.as_ref().map(|p| p.0), Some(21));
    assert_eq!(cd.triggering_message.as_ref().map(|t| t.0), Some(0));
    assert_eq!(cd.procedure_criticality.as_ref().map(|c| c.0), Some(0));
    let list = &cd.i_es_criticality_diagnostics.as_ref().expect("IE list").0;
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].ie_id.0, 27);
    assert_eq!(list[0].ie_criticality.0, generated::Criticality::REJECT);
    assert_eq!(list[0].type_of_error.0, generated::TypeOfError::MISSING);
    assert_eq!(list[1].ie_id.0, 9999);
    assert_eq!(list[1].ie_criticality.0, generated::Criticality::NOTIFY);
    assert_eq!(
        list[1].type_of_error.0,
        generated::TypeOfError::NOT_UNDERSTOOD
    );
}
