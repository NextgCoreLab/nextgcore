//! Property-Based Tests for ASN.1 Codecs
//!
//! Feature: nextgcore-rust-conversion
//! - Property 9: ASN.1 Encoding Round-Trip
//! - Property 10: ASN.1 Error Handling Equivalence
//!
//! These tests verify that ASN.1 encoding/decoding produces consistent results
//! and handles errors appropriately.

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use crate::per::{AperEncoder, AperDecoder, AperEncode, AperDecode, PerError, Constraint};

    // ========================================================================
    // NGAP Property Tests - Property 9: ASN.1 Encoding Round-Trip
    // ========================================================================

    mod ngap_roundtrip {
        use super::*;
        use crate::ngap::types::*;
        use crate::ngap::cause::*;
        use crate::ngap::ies::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
            #[test]
            fn prop_ngap_criticality_roundtrip(value in 0u8..3) {
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
            fn prop_ngap_procedure_code_roundtrip(value in 0u8..=255) {
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
            fn prop_ngap_protocol_ie_id_roundtrip(value in 0u16..=65535) {
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
            fn prop_ngap_triggering_message_roundtrip(value in 0u8..3) {
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
            fn prop_ngap_presence_roundtrip(value in 0u8..3) {
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
            fn prop_ngap_amf_ue_ngap_id_roundtrip(value in 0u64..=1099511627775u64) {
                let id = AmfUeNgapId(value);
                let mut encoder = AperEncoder::new();
                id.encode_aper(&mut encoder).unwrap();
                encoder.align();
                let bytes = encoder.into_bytes();
                let mut decoder = AperDecoder::new(&bytes);
                let decoded = AmfUeNgapId::decode_aper(&mut decoder).unwrap();
                prop_assert_eq!(id, decoded);
            }

            // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
            #[test]
            fn prop_ngap_ran_ue_ngap_id_roundtrip(value in any::<u32>()) {
                let id = RanUeNgapId(value);
                let mut encoder = AperEncoder::new();
                id.encode_aper(&mut encoder).unwrap();
                encoder.align();
                let bytes = encoder.into_bytes();
                let mut decoder = AperDecoder::new(&bytes);
                let decoded = RanUeNgapId::decode_aper(&mut decoder).unwrap();
                prop_assert_eq!(id, decoded);
            }

            // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
            #[test]
            fn prop_ngap_time_to_wait_roundtrip(value in 0u8..6) {
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
            fn prop_ngap_relative_amf_capacity_roundtrip(value in any::<u8>()) {
                let cap = RelativeAmfCapacity(value);
                let mut encoder = AperEncoder::new();
                cap.encode_aper(&mut encoder).unwrap();
                encoder.align();
                let bytes = encoder.into_bytes();
                let mut decoder = AperDecoder::new(&bytes);
                let decoded = RelativeAmfCapacity::decode_aper(&mut decoder).unwrap();
                prop_assert_eq!(cap, decoded);
            }

            // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
            #[test]
            fn prop_ngap_nas_pdu_roundtrip(data in prop::collection::vec(any::<u8>(), 0..256)) {
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
            fn prop_ngap_cause_transport_roundtrip(value in 0u8..2) {
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
            fn prop_ngap_cause_nas_roundtrip(value in 0u8..4) {
                let cause_nas = match value {
                    0 => CauseNas::NormalRelease,
                    1 => CauseNas::AuthenticationFailure,
                    2 => CauseNas::Deregister,
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
            fn prop_ngap_cause_misc_roundtrip(value in 0u8..6) {
                let cause_m: CauseMisc = unsafe { std::mem::transmute(value) };
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
            fn prop_ngap_protocol_ie_field_roundtrip(
                id in 0u16..=65535u16,
                crit in 0u8..3,
                value in prop::collection::vec(any::<u8>(), 0..64),
            ) {
                let criticality = match crit {
                    0 => Criticality::Reject,
                    1 => Criticality::Ignore,
                    _ => Criticality::Notify,
                };
                let field = ProtocolIeField {
                    id: ProtocolIeId(id),
                    criticality,
                    value: value.clone(),
                };
                let mut encoder = AperEncoder::new();
                field.encode_aper(&mut encoder).unwrap();
                encoder.align();
                let bytes = encoder.into_bytes();
                let mut decoder = AperDecoder::new(&bytes);
                let decoded = ProtocolIeField::decode_aper(&mut decoder).unwrap();
                prop_assert_eq!(field, decoded);
            }

            // Feature: nextgcore-rust-conversion, Property 9: ASN.1 Encoding Round-Trip
            #[test]
            fn prop_ngap_protocol_ie_container_roundtrip(num_ies in 0usize..5) {
                let mut container = ProtocolIeContainer::new();
                for i in 0..num_ies {
                    container.push(ProtocolIeField {
                        id: ProtocolIeId(i as u16),
                        criticality: Criticality::Reject,
                        value: vec![i as u8; 4],
                    });
                }
                let mut encoder = AperEncoder::new();
                container.encode_aper(&mut encoder).unwrap();
                encoder.align();
                let bytes = encoder.into_bytes();
                let mut decoder = AperDecoder::new(&bytes);
                let decoded = ProtocolIeContainer::decode_aper(&mut decoder).unwrap();
                prop_assert_eq!(container.len(), decoded.len());
            }
        }
    }

    // ========================================================================
    // S1AP Property Tests - Property 9: ASN.1 Encoding Round-Trip
    // ========================================================================

    mod s1ap_roundtrip {
        use super::*;
        use crate::s1ap::types::*;
        use crate::s1ap::cause::*;
        use crate::s1ap::ies::*;

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
                let cause_m: CauseMisc = unsafe { std::mem::transmute(value) };
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

    // ========================================================================
    // Property 10: ASN.1 Error Handling Equivalence
    // ========================================================================

    mod error_handling {
        use super::*;
        use crate::ngap::types::*;
        use crate::ngap::cause::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            // Feature: nextgcore-rust-conversion, Property 10: ASN.1 Error Handling Equivalence
            #[test]
            fn prop_empty_buffer_error(_seed in any::<u64>()) {
                let empty: &[u8] = &[];
                let mut decoder = AperDecoder::new(empty);
                let result = Criticality::decode_aper(&mut decoder);
                prop_assert!(result.is_err());
                match result {
                    Err(PerError::BufferUnderflow { .. }) => (),
                    Err(e) => prop_assert!(false, "Expected BufferUnderflow, got {:?}", e),
                    Ok(_) => prop_assert!(false, "Expected error, got Ok"),
                }
            }

            // Feature: nextgcore-rust-conversion, Property 10: ASN.1 Error Handling Equivalence
            #[test]
            fn prop_malformed_length_determinant(first_byte in 0xC0u8..=0xFF) {
                let data = [first_byte];
                let mut decoder = AperDecoder::new(&data);
                decoder.align();
                let result = decoder.decode_length_determinant();
                prop_assert!(result.is_err());
            }

            // Feature: nextgcore-rust-conversion, Property 10: ASN.1 Error Handling Equivalence
            #[test]
            fn prop_constraint_violation_error(value in 256i64..=1000) {
                let constraint = Constraint::new(0, 255);
                let mut encoder = AperEncoder::new();
                let result = encoder.encode_constrained_whole_number(value, &constraint);
                prop_assert!(result.is_err());
                match result {
                    Err(PerError::ConstraintViolation { .. }) => (),
                    Err(e) => prop_assert!(false, "Expected ConstraintViolation, got {:?}", e),
                    Ok(_) => prop_assert!(false, "Expected error, got Ok"),
                }
            }

            // Feature: nextgcore-rust-conversion, Property 10: ASN.1 Error Handling Equivalence
            #[test]
            fn prop_random_data_does_not_panic(data in prop::collection::vec(any::<u8>(), 0..64)) {
                let mut decoder = AperDecoder::new(&data);
                let _ = Criticality::decode_aper(&mut decoder);
                let mut decoder = AperDecoder::new(&data);
                let _ = ProcedureCode::decode_aper(&mut decoder);
                let mut decoder = AperDecoder::new(&data);
                let _ = ProtocolIeId::decode_aper(&mut decoder);
                let mut decoder = AperDecoder::new(&data);
                let _ = Cause::decode_aper(&mut decoder);
                prop_assert!(true);
            }

            // Feature: nextgcore-rust-conversion, Property 10: ASN.1 Error Handling Equivalence
            #[test]
            fn prop_s1ap_random_data_does_not_panic(data in prop::collection::vec(any::<u8>(), 0..64)) {
                use crate::s1ap::types as s1ap_types;
                use crate::s1ap::cause as s1ap_cause;
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
}
