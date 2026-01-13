//! Property-Based Tests for GTP Protocol Messages
//!
//! Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
//!
//! These tests verify that GTPv1 and GTPv2 protocol messages can be encoded
//! and decoded correctly, producing equivalent message structures.
//!
//! Validates: Requirements 4.1, 4.2

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use bytes::{Bytes, BytesMut};

    // ========================================================================
    // GTPv1 Property Tests
    // ========================================================================

    mod gtpv1_props {
        use super::*;
        use crate::v1::header::{Gtp1Header, Gtp1cMessageType, Gtp1uMessageType, GTP1_VERSION_1};
        use crate::v1::message::{Gtp1Message, ErrorIndication};

        // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
        // Test: GTPv1 Echo Request round-trip
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_gtpv1_echo_request_round_trip(
                teid in any::<u32>(),
                sequence_number in any::<u16>(),
            ) {
                let msg = Gtp1Message::echo_request(teid, sequence_number);
                let encoded = msg.encode();
                
                let mut bytes = encoded.freeze();
                let decoded = Gtp1Message::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.header.message_type, Gtp1cMessageType::EchoRequest as u8);
                prop_assert_eq!(decoded.header.teid, teid);
                prop_assert_eq!(decoded.header.sequence_number, Some(sequence_number));
                prop_assert_eq!(decoded.header.version, GTP1_VERSION_1);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: GTPv1 Echo Response round-trip
            #[test]
            fn prop_gtpv1_echo_response_round_trip(
                teid in any::<u32>(),
                sequence_number in any::<u16>(),
                recovery in any::<u8>(),
            ) {
                let msg = Gtp1Message::echo_response(teid, sequence_number, recovery);
                let encoded = msg.encode();
                
                let mut bytes = encoded.freeze();
                let decoded = Gtp1Message::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.header.message_type, Gtp1cMessageType::EchoResponse as u8);
                prop_assert_eq!(decoded.header.teid, teid);
                prop_assert_eq!(decoded.header.sequence_number, Some(sequence_number));
                
                // Verify Recovery IE
                let recovery_ie = decoded.get_ie(14);
                prop_assert!(recovery_ie.is_some());
                prop_assert_eq!(recovery_ie.unwrap().value[0], recovery);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: GTPv1-U G-PDU round-trip
            #[test]
            fn prop_gtpv1_gpdu_round_trip(
                teid in any::<u32>(),
                payload in prop::collection::vec(any::<u8>(), 1..256),
            ) {
                let payload_bytes = Bytes::from(payload.clone());
                let msg = Gtp1Message::gpdu(teid, payload_bytes);
                let encoded = msg.encode();
                
                let mut bytes = encoded.freeze();
                let decoded = Gtp1Message::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.header.message_type, Gtp1uMessageType::GPdu as u8);
                prop_assert_eq!(decoded.header.teid, teid);
                prop_assert!(decoded.payload.is_some());
                prop_assert_eq!(decoded.payload.unwrap().to_vec(), payload);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: GTPv1-U Error Indication round-trip
            #[test]
            fn prop_gtpv1_error_indication_round_trip(
                header_teid in any::<u32>(),
                peer_teid in any::<u32>(),
                // IPv4 address (4 bytes) or IPv6 address (16 bytes)
                addr_type in prop::bool::ANY,
            ) {
                let peer_addr = if addr_type {
                    vec![192, 168, 1, 1] // IPv4
                } else {
                    vec![0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01] // IPv6
                };
                
                let msg = Gtp1Message::error_indication(header_teid, peer_teid, &peer_addr);
                let encoded = msg.encode();
                
                let mut bytes = encoded.freeze();
                let decoded = Gtp1Message::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.header.message_type, Gtp1uMessageType::ErrorIndication as u8);
                
                let err_ind = ErrorIndication::decode(&decoded).unwrap();
                prop_assert_eq!(err_ind.teid, peer_teid);
                prop_assert_eq!(err_ind.gsn_address, peer_addr);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: GTPv1-U End Marker round-trip
            #[test]
            fn prop_gtpv1_end_marker_round_trip(
                teid in any::<u32>(),
            ) {
                let msg = Gtp1Message::end_marker(teid);
                let encoded = msg.encode();
                
                let mut bytes = encoded.freeze();
                let decoded = Gtp1Message::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.header.message_type, Gtp1uMessageType::EndMarker as u8);
                prop_assert_eq!(decoded.header.teid, teid);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: GTPv1 Header encode/decode is deterministic
            #[test]
            fn prop_gtpv1_header_deterministic(
                teid in any::<u32>(),
                message_type in prop::sample::select(vec![
                    Gtp1cMessageType::EchoRequest as u8,
                    Gtp1cMessageType::EchoResponse as u8,
                    Gtp1uMessageType::GPdu as u8,
                    Gtp1uMessageType::ErrorIndication as u8,
                    Gtp1uMessageType::EndMarker as u8,
                ]),
                sequence_number in any::<u16>(),
                has_seq in prop::bool::ANY,
            ) {
                let mut header = Gtp1Header::new(message_type, teid);
                if has_seq {
                    header.s = true;
                    header.sequence_number = Some(sequence_number);
                }
                header.length = 100;
                
                // Encode twice
                let mut buf1 = BytesMut::new();
                let mut buf2 = BytesMut::new();
                header.encode(&mut buf1);
                header.encode(&mut buf2);
                
                prop_assert_eq!(buf1, buf2, "Header encoding must be deterministic");
            }
        }
    }

    // ========================================================================
    // GTPv2 Property Tests
    // ========================================================================

    mod gtpv2_props {
        use super::*;
        use crate::v2::header::{Gtp2Header, Gtp2MessageType};
        use crate::v2::message::{Gtp2Message, CreateSessionRequest, CreateSessionResponse,
                                  ModifyBearerRequest, DeleteSessionRequest};
        use crate::v2::ie::{Gtp2Ie, Gtp2IeType};

        // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
        // Test: GTPv2 Echo Request round-trip
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_gtpv2_echo_request_round_trip(
                sequence_number in 0u32..0xFFFFFF,
            ) {
                let msg = Gtp2Message::echo_request(sequence_number);
                let encoded = msg.encode();
                
                let mut bytes = encoded.freeze();
                let decoded = Gtp2Message::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.header.message_type, Gtp2MessageType::EchoRequest as u8);
                prop_assert!(!decoded.header.teid_presence);
                prop_assert_eq!(decoded.header.sequence_number, sequence_number);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: GTPv2 Echo Response round-trip
            #[test]
            fn prop_gtpv2_echo_response_round_trip(
                sequence_number in 0u32..0xFFFFFF,
                recovery in any::<u8>(),
            ) {
                let msg = Gtp2Message::echo_response(sequence_number, recovery);
                let encoded = msg.encode();
                
                let mut bytes = encoded.freeze();
                let decoded = Gtp2Message::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.header.message_type, Gtp2MessageType::EchoResponse as u8);
                prop_assert!(!decoded.header.teid_presence);
                prop_assert_eq!(decoded.header.sequence_number, sequence_number);
                
                // Verify Recovery IE
                let recovery_ie = decoded.get_ie_by_type(Gtp2IeType::Recovery as u8);
                prop_assert!(recovery_ie.is_some());
                prop_assert_eq!(recovery_ie.unwrap().value[0], recovery);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: GTPv2 Create Session Request round-trip
            #[test]
            fn prop_gtpv2_create_session_request_round_trip(
                teid in any::<u32>(),
                sequence_number in 0u32..0xFFFFFF,
                recovery in any::<u8>(),
            ) {
                let mut req = CreateSessionRequest::new(teid, sequence_number);
                req.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Recovery as u8, 0, &[recovery]));
                
                let encoded = req.encode();
                let mut bytes = encoded.freeze();
                let decoded = Gtp2Message::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.header.message_type, Gtp2MessageType::CreateSessionRequest as u8);
                prop_assert!(decoded.header.teid_presence);
                prop_assert_eq!(decoded.header.teid, Some(teid));
                prop_assert_eq!(decoded.header.sequence_number, sequence_number);
                
                let decoded_req = CreateSessionRequest::decode(&decoded).unwrap();
                prop_assert_eq!(decoded_req.teid, teid);
                prop_assert_eq!(decoded_req.sequence_number, sequence_number);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: GTPv2 Create Session Response round-trip
            #[test]
            fn prop_gtpv2_create_session_response_round_trip(
                teid in any::<u32>(),
                sequence_number in 0u32..0xFFFFFF,
            ) {
                let req = CreateSessionResponse::new(teid, sequence_number);
                let encoded = req.encode();
                
                let mut bytes = encoded.freeze();
                let decoded = Gtp2Message::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.header.message_type, Gtp2MessageType::CreateSessionResponse as u8);
                prop_assert_eq!(decoded.header.teid, Some(teid));
                prop_assert_eq!(decoded.header.sequence_number, sequence_number);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: GTPv2 Modify Bearer Request round-trip
            #[test]
            fn prop_gtpv2_modify_bearer_request_round_trip(
                teid in any::<u32>(),
                sequence_number in 0u32..0xFFFFFF,
            ) {
                let req = ModifyBearerRequest::new(teid, sequence_number);
                let encoded = req.encode();
                
                let mut bytes = encoded.freeze();
                let decoded = Gtp2Message::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.header.message_type, Gtp2MessageType::ModifyBearerRequest as u8);
                prop_assert_eq!(decoded.header.teid, Some(teid));
                prop_assert_eq!(decoded.header.sequence_number, sequence_number);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: GTPv2 Delete Session Request round-trip
            #[test]
            fn prop_gtpv2_delete_session_request_round_trip(
                teid in any::<u32>(),
                sequence_number in 0u32..0xFFFFFF,
            ) {
                let req = DeleteSessionRequest::new(teid, sequence_number);
                let encoded = req.encode();
                
                let mut bytes = encoded.freeze();
                let decoded = Gtp2Message::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.header.message_type, Gtp2MessageType::DeleteSessionRequest as u8);
                prop_assert_eq!(decoded.header.teid, Some(teid));
                prop_assert_eq!(decoded.header.sequence_number, sequence_number);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: GTPv2 Header encode/decode is deterministic
            #[test]
            fn prop_gtpv2_header_deterministic(
                teid in any::<u32>(),
                sequence_number in 0u32..0xFFFFFF,
                has_teid in prop::bool::ANY,
            ) {
                let header = if has_teid {
                    let mut h = Gtp2Header::new(Gtp2MessageType::CreateSessionRequest as u8, teid, sequence_number);
                    h.length = 100;
                    h
                } else {
                    let mut h = Gtp2Header::new_no_teid(Gtp2MessageType::EchoRequest as u8, sequence_number);
                    h.length = 0;
                    h
                };
                
                // Encode twice
                let mut buf1 = BytesMut::new();
                let mut buf2 = BytesMut::new();
                header.encode(&mut buf1);
                header.encode(&mut buf2);
                
                prop_assert_eq!(buf1, buf2, "Header encoding must be deterministic");
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: GTPv2 message with multiple IEs round-trip
            #[test]
            fn prop_gtpv2_multiple_ies_round_trip(
                teid in any::<u32>(),
                sequence_number in 0u32..0xFFFFFF,
                ie_values in prop::collection::vec(any::<u8>(), 1..5),
            ) {
                let mut req = CreateSessionRequest::new(teid, sequence_number);
                
                // Add multiple IEs with different types
                for (i, value) in ie_values.iter().enumerate() {
                    let ie_type = match i % 3 {
                        0 => Gtp2IeType::Recovery as u8,
                        1 => Gtp2IeType::Ebi as u8,
                        _ => Gtp2IeType::RatType as u8,
                    };
                    req.add_ie(Gtp2Ie::from_slice(ie_type, i as u8, &[*value]));
                }
                
                let encoded = req.encode();
                let mut bytes = encoded.freeze();
                let decoded = Gtp2Message::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.ies.len(), ie_values.len());
            }
        }
    }
}
