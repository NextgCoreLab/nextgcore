//! Property tests for the oracle's hand-written S1AP APER structures, moved
//! here from `nextgcore-asn1c` when its S1AP module was deleted (#514 stage 13).

#[allow(unused_imports)]
use nextgcore_asn1c::per::*;
use proptest::prelude::*;

mod s1ap_roundtrip {
    use super::*;
    use nextgcore_s1ap_oracle::asn1::cause::*;
    use nextgcore_s1ap_oracle::asn1::ies::*;
    use nextgcore_s1ap_oracle::asn1::types::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
        #[test]
        fn prop_s1ap_criticality_roundtrip(value in 0u8..3) {
            let criticality = match value {
                0 => Criticality::Reject,
                1 => Criticality::Ignore,
                _ => Criticality::Notify,
            };
            let mut encoder = AperEncoder::new();
            criticality.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = Criticality::decode_aper(&mut decoder).unwrap();
            prop_assert_eq!(criticality, decoded);
        }

        // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
        #[test]
        fn prop_s1ap_procedure_code_roundtrip(value in 0u8..=255) {
            let code = ProcedureCode(value);
            let mut encoder = AperEncoder::new();
            code.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = ProcedureCode::decode_aper(&mut decoder).unwrap();
            prop_assert_eq!(code, decoded);
        }

        // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
        #[test]
        fn prop_s1ap_protocol_ie_id_roundtrip(value in 0u16..=65535) {
            let id = ProtocolIeId(value);
            let mut encoder = AperEncoder::new();
            id.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = ProtocolIeId::decode_aper(&mut decoder).unwrap();
            prop_assert_eq!(id, decoded);
        }

        // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
        #[test]
        fn prop_s1ap_triggering_message_roundtrip(value in 0u8..3) {
            let msg = match value {
                0 => TriggeringMessage::InitiatingMessage,
                1 => TriggeringMessage::SuccessfulOutcome,
                _ => TriggeringMessage::UnsuccessfulOutcome,
            };
            let mut encoder = AperEncoder::new();
            msg.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = TriggeringMessage::decode_aper(&mut decoder).unwrap();
            prop_assert_eq!(msg, decoded);
        }

        // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
        #[test]
        fn prop_s1ap_presence_roundtrip(value in 0u8..3) {
            let presence = match value {
                0 => Presence::Optional,
                1 => Presence::Conditional,
                _ => Presence::Mandatory,
            };
            let mut encoder = AperEncoder::new();
            presence.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = Presence::decode_aper(&mut decoder).unwrap();
            prop_assert_eq!(presence, decoded);
        }

        // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
        #[test]
        fn prop_s1ap_mme_ue_s1ap_id_roundtrip(value in any::<u32>()) {
            let id = MmeUeS1apId(value);
            let mut encoder = AperEncoder::new();
            id.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = MmeUeS1apId::decode_aper(&mut decoder).unwrap();
            prop_assert_eq!(id, decoded);
        }

        // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
        #[test]
        fn prop_s1ap_enb_ue_s1ap_id_roundtrip(value in 0u32..=16777215) {
            let id = EnbUeS1apId(value);
            let mut encoder = AperEncoder::new();
            id.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = EnbUeS1apId::decode_aper(&mut decoder).unwrap();
            prop_assert_eq!(id, decoded);
        }

        // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
        #[test]
        fn prop_s1ap_time_to_wait_roundtrip(value in 0u8..6) {
            let ttw = match value {
                0 => TimeToWait::V1s,
                1 => TimeToWait::V2s,
                2 => TimeToWait::V5s,
                3 => TimeToWait::V10s,
                4 => TimeToWait::V20s,
                _ => TimeToWait::V60s,
            };
            let mut encoder = AperEncoder::new();
            ttw.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = TimeToWait::decode_aper(&mut decoder).unwrap();
            prop_assert_eq!(ttw, decoded);
        }

        // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
        #[test]
        fn prop_s1ap_relative_mme_capacity_roundtrip(value in any::<u8>()) {
            let cap = RelativeMmeCapacity(value);
            let mut encoder = AperEncoder::new();
            cap.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = RelativeMmeCapacity::decode_aper(&mut decoder).unwrap();
            prop_assert_eq!(cap, decoded);
        }

        // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
        #[test]
        fn prop_s1ap_nas_pdu_roundtrip(data in prop::collection::vec(any::<u8>(), 0..256)) {
            let pdu = NasPdu::new(data.clone());
            let mut encoder = AperEncoder::new();
            pdu.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = NasPdu::decode_aper(&mut decoder).unwrap();
            prop_assert_eq!(pdu, decoded);
        }

        // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
        #[test]
        fn prop_s1ap_cause_transport_roundtrip(value in 0u8..2) {
            let cause_t = match value {
                0 => CauseTransport::TransportResourceUnavailable,
                _ => CauseTransport::Unspecified,
            };
            let cause = Cause::Transport(cause_t);
            let mut encoder = AperEncoder::new();
            cause.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = Cause::decode_aper(&mut decoder).unwrap();
            prop_assert_eq!(cause, decoded);
        }

        // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
        #[test]
        fn prop_s1ap_cause_nas_roundtrip(value in 0u8..4) {
            let cause_nas = match value {
                0 => CauseNas::NormalRelease,
                1 => CauseNas::AuthenticationFailure,
                2 => CauseNas::Detach,
                _ => CauseNas::Unspecified,
            };
            let cause = Cause::Nas(cause_nas);
            let mut encoder = AperEncoder::new();
            cause.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = Cause::decode_aper(&mut decoder).unwrap();
            prop_assert_eq!(cause, decoded);
        }

        // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
        #[test]
        fn prop_s1ap_cause_misc_roundtrip(value in 0u8..6) {
            let cause_m = CauseMisc::try_from(value as i64).unwrap();
            let cause = Cause::Misc(cause_m);
            let mut encoder = AperEncoder::new();
            cause.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = Cause::decode_aper(&mut decoder).unwrap();
            prop_assert_eq!(cause, decoded);
        }

        // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
        #[test]
        fn prop_s1ap_erab_id_roundtrip(value in 0u8..16) {
            let id = ERabId(value);
            let mut encoder = AperEncoder::new();
            id.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = ERabId::decode_aper(&mut decoder).unwrap();
            prop_assert_eq!(id, decoded);
        }

        // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
        #[test]
        fn prop_s1ap_qci_roundtrip(value in any::<u8>()) {
            let qci = Qci(value);
            let mut encoder = AperEncoder::new();
            qci.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = Qci::decode_aper(&mut decoder).unwrap();
            prop_assert_eq!(qci, decoded);
        }
    }
}

mod error_handling {
    use super::*;
    proptest! {
            // Feature: nextgcore-rust-conversion, Property 10: ASN.1 Error Handling Equivalence
            #[test]
            fn prop_s1ap_random_data_does_not_panic(data in prop::collection::vec(any::<u8>(), 0..64)) {
                use nextgcore_s1ap_oracle::asn1::types as s1ap_types;
                use nextgcore_s1ap_oracle::asn1::cause as s1ap_cause;
                let mut decoder = AperDecoder::new(&data);
                let _ = s1ap_types::Criticality::decode_aper(&mut decoder);
                let mut decoder = AperDecoder::new(&data);
                let _ = s1ap_types::ProcedureCode::decode_aper(&mut decoder);
                let mut decoder = AperDecoder::new(&data);
                let _ = s1ap_cause::Cause::decode_aper(&mut decoder);
                prop_assert!(true);
            }
    }
}
