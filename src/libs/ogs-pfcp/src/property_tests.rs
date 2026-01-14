//! Property-Based Tests for PFCP Protocol Messages
//!
//! Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
//!
//! These tests verify that PFCP protocol messages can be encoded
//! and decoded correctly, producing equivalent message structures.
//!
//! Validates: Requirements 4.3

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use bytes::BytesMut;

    // ========================================================================
    // PFCP Message Property Tests
    // ========================================================================

    mod pfcp_props {
        use super::*;
        use crate::header::{PfcpHeader, PfcpMessageType};
        use crate::message::{
            PfcpMessage, HeartbeatRequest, HeartbeatResponse,
            AssociationSetupRequest, AssociationSetupResponse,
            AssociationReleaseRequest, AssociationReleaseResponse,
            SessionEstablishmentRequest, SessionEstablishmentResponse,
            SessionDeletionRequest, SessionDeletionResponse,
            build_message, parse_message,
        };
        use crate::types::{NodeId, FSeid, PfcpCause};
        

        // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
        // Test: PFCP Heartbeat Request round-trip
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_pfcp_heartbeat_request_round_trip(
                recovery_time_stamp in any::<u32>(),
                sequence_number in 0u32..0xFFFFFF, // 24-bit sequence number
            ) {
                let msg = PfcpMessage::HeartbeatRequest(HeartbeatRequest::new(recovery_time_stamp));
                let buf = build_message(&msg, sequence_number, None);
                
                let mut bytes = buf.freeze();
                let (header, decoded) = parse_message(&mut bytes).unwrap();
                
                prop_assert_eq!(header.message_type, PfcpMessageType::HeartbeatRequest);
                prop_assert_eq!(header.sequence_number, sequence_number);
                prop_assert!(!header.seid_presence);
                
                if let PfcpMessage::HeartbeatRequest(req) = decoded {
                    prop_assert_eq!(req.recovery_time_stamp, recovery_time_stamp);
                } else {
                    prop_assert!(false, "Wrong message type decoded");
                }
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: PFCP Heartbeat Response round-trip
            #[test]
            fn prop_pfcp_heartbeat_response_round_trip(
                recovery_time_stamp in any::<u32>(),
                sequence_number in 0u32..0xFFFFFF, // 24-bit sequence number
            ) {
                let msg = PfcpMessage::HeartbeatResponse(HeartbeatResponse::new(recovery_time_stamp));
                let buf = build_message(&msg, sequence_number, None);
                
                let mut bytes = buf.freeze();
                let (header, decoded) = parse_message(&mut bytes).unwrap();
                
                prop_assert_eq!(header.message_type, PfcpMessageType::HeartbeatResponse);
                prop_assert_eq!(header.sequence_number, sequence_number);
                
                if let PfcpMessage::HeartbeatResponse(resp) = decoded {
                    prop_assert_eq!(resp.recovery_time_stamp, recovery_time_stamp);
                } else {
                    prop_assert!(false, "Wrong message type decoded");
                }
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: PFCP Association Setup Request round-trip with IPv4 Node ID
            #[test]
            fn prop_pfcp_association_setup_request_ipv4_round_trip(
                ip_bytes in prop::array::uniform4(any::<u8>()),
                recovery_time_stamp in any::<u32>(),
                sequence_number in 0u32..0xFFFFFF, // 24-bit sequence number
            ) {
                let node_id = NodeId::new_ipv4(ip_bytes);
                let msg = PfcpMessage::AssociationSetupRequest(
                    AssociationSetupRequest::new(node_id.clone(), recovery_time_stamp)
                );
                let buf = build_message(&msg, sequence_number, None);
                
                let mut bytes = buf.freeze();
                let (header, decoded) = parse_message(&mut bytes).unwrap();
                
                prop_assert_eq!(header.message_type, PfcpMessageType::AssociationSetupRequest);
                prop_assert_eq!(header.sequence_number, sequence_number);
                
                if let PfcpMessage::AssociationSetupRequest(req) = decoded {
                    prop_assert_eq!(req.node_id, node_id);
                    prop_assert_eq!(req.recovery_time_stamp, recovery_time_stamp);
                } else {
                    prop_assert!(false, "Wrong message type decoded");
                }
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: PFCP Association Setup Response round-trip
            #[test]
            fn prop_pfcp_association_setup_response_round_trip(
                ip_bytes in prop::array::uniform4(any::<u8>()),
                recovery_time_stamp in any::<u32>(),
                sequence_number in 0u32..0xFFFFFF, // 24-bit sequence number
                cause_val in 1u8..20,
            ) {
                let node_id = NodeId::new_ipv4(ip_bytes);
                let cause = PfcpCause::try_from(cause_val).unwrap_or(PfcpCause::RequestAccepted);
                let msg = PfcpMessage::AssociationSetupResponse(
                    AssociationSetupResponse::new(node_id.clone(), cause, recovery_time_stamp)
                );
                let buf = build_message(&msg, sequence_number, None);
                
                let mut bytes = buf.freeze();
                let (header, decoded) = parse_message(&mut bytes).unwrap();
                
                prop_assert_eq!(header.message_type, PfcpMessageType::AssociationSetupResponse);
                
                if let PfcpMessage::AssociationSetupResponse(resp) = decoded {
                    prop_assert_eq!(resp.node_id, node_id);
                    prop_assert_eq!(resp.recovery_time_stamp, recovery_time_stamp);
                    prop_assert_eq!(resp.cause, cause);
                } else {
                    prop_assert!(false, "Wrong message type decoded");
                }
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: PFCP Association Release Request round-trip
            #[test]
            fn prop_pfcp_association_release_request_round_trip(
                ip_bytes in prop::array::uniform4(any::<u8>()),
                sequence_number in 0u32..0xFFFFFF, // 24-bit sequence number
            ) {
                let node_id = NodeId::new_ipv4(ip_bytes);
                let msg = PfcpMessage::AssociationReleaseRequest(
                    AssociationReleaseRequest::new(node_id.clone())
                );
                let buf = build_message(&msg, sequence_number, None);
                
                let mut bytes = buf.freeze();
                let (header, decoded) = parse_message(&mut bytes).unwrap();
                
                prop_assert_eq!(header.message_type, PfcpMessageType::AssociationReleaseRequest);
                
                if let PfcpMessage::AssociationReleaseRequest(req) = decoded {
                    prop_assert_eq!(req.node_id, node_id);
                } else {
                    prop_assert!(false, "Wrong message type decoded");
                }
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: PFCP Association Release Response round-trip
            #[test]
            fn prop_pfcp_association_release_response_round_trip(
                ip_bytes in prop::array::uniform4(any::<u8>()),
                sequence_number in 0u32..0xFFFFFF, // 24-bit sequence number
            ) {
                let node_id = NodeId::new_ipv4(ip_bytes);
                let msg = PfcpMessage::AssociationReleaseResponse(
                    AssociationReleaseResponse::new(node_id.clone(), PfcpCause::RequestAccepted)
                );
                let buf = build_message(&msg, sequence_number, None);
                
                let mut bytes = buf.freeze();
                let (header, decoded) = parse_message(&mut bytes).unwrap();
                
                prop_assert_eq!(header.message_type, PfcpMessageType::AssociationReleaseResponse);
                
                if let PfcpMessage::AssociationReleaseResponse(resp) = decoded {
                    prop_assert_eq!(resp.node_id, node_id);
                    prop_assert_eq!(resp.cause, PfcpCause::RequestAccepted);
                } else {
                    prop_assert!(false, "Wrong message type decoded");
                }
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: PFCP Session Establishment Request round-trip
            #[test]
            fn prop_pfcp_session_establishment_request_round_trip(
                ip_bytes in prop::array::uniform4(any::<u8>()),
                seid in any::<u64>(),
                sequence_number in 0u32..0xFFFFFF, // 24-bit sequence number
            ) {
                let node_id = NodeId::new_ipv4(ip_bytes);
                let cp_f_seid = FSeid::new_ipv4(seid, ip_bytes);
                let msg = PfcpMessage::SessionEstablishmentRequest(
                    SessionEstablishmentRequest::new(node_id.clone(), cp_f_seid.clone())
                );
                let buf = build_message(&msg, sequence_number, Some(seid));
                
                let mut bytes = buf.freeze();
                let (header, decoded) = parse_message(&mut bytes).unwrap();
                
                prop_assert_eq!(header.message_type, PfcpMessageType::SessionEstablishmentRequest);
                prop_assert!(header.seid_presence);
                prop_assert_eq!(header.seid, Some(seid));
                
                if let PfcpMessage::SessionEstablishmentRequest(req) = decoded {
                    prop_assert_eq!(req.node_id, node_id);
                    prop_assert_eq!(req.cp_f_seid, cp_f_seid);
                } else {
                    prop_assert!(false, "Wrong message type decoded");
                }
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: PFCP Session Establishment Response round-trip
            #[test]
            fn prop_pfcp_session_establishment_response_round_trip(
                seid in any::<u64>(),
                sequence_number in 0u32..0xFFFFFF, // 24-bit sequence number
            ) {
                let msg = PfcpMessage::SessionEstablishmentResponse(
                    SessionEstablishmentResponse::new(PfcpCause::RequestAccepted)
                );
                let buf = build_message(&msg, sequence_number, Some(seid));
                
                let mut bytes = buf.freeze();
                let (header, decoded) = parse_message(&mut bytes).unwrap();
                
                prop_assert_eq!(header.message_type, PfcpMessageType::SessionEstablishmentResponse);
                
                if let PfcpMessage::SessionEstablishmentResponse(resp) = decoded {
                    prop_assert_eq!(resp.cause, PfcpCause::RequestAccepted);
                } else {
                    prop_assert!(false, "Wrong message type decoded");
                }
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: PFCP Session Deletion Request round-trip
            #[test]
            fn prop_pfcp_session_deletion_request_round_trip(
                seid in any::<u64>(),
                sequence_number in 0u32..0xFFFFFF, // 24-bit sequence number
            ) {
                let msg = PfcpMessage::SessionDeletionRequest(SessionDeletionRequest::new());
                let buf = build_message(&msg, sequence_number, Some(seid));
                
                let mut bytes = buf.freeze();
                let (header, decoded) = parse_message(&mut bytes).unwrap();
                
                prop_assert_eq!(header.message_type, PfcpMessageType::SessionDeletionRequest);
                prop_assert!(header.seid_presence);
                prop_assert_eq!(header.seid, Some(seid));
                
                prop_assert!(matches!(decoded, PfcpMessage::SessionDeletionRequest(_)));
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: PFCP Session Deletion Response round-trip
            #[test]
            fn prop_pfcp_session_deletion_response_round_trip(
                seid in any::<u64>(),
                sequence_number in 0u32..0xFFFFFF, // 24-bit sequence number
            ) {
                let msg = PfcpMessage::SessionDeletionResponse(
                    SessionDeletionResponse::new(PfcpCause::RequestAccepted)
                );
                let buf = build_message(&msg, sequence_number, Some(seid));
                
                let mut bytes = buf.freeze();
                let (header, decoded) = parse_message(&mut bytes).unwrap();
                
                prop_assert_eq!(header.message_type, PfcpMessageType::SessionDeletionResponse);
                
                if let PfcpMessage::SessionDeletionResponse(resp) = decoded {
                    prop_assert_eq!(resp.cause, PfcpCause::RequestAccepted);
                } else {
                    prop_assert!(false, "Wrong message type decoded");
                }
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: PFCP Header encode/decode is deterministic
            #[test]
            fn prop_pfcp_header_deterministic(
                sequence_number in 0u32..0xFFFFFF, // 24-bit sequence number
                seid in any::<u64>(),
                has_seid in prop::bool::ANY,
            ) {
                let header = if has_seid {
                    let mut h = PfcpHeader::new_with_seid(PfcpMessageType::SessionEstablishmentRequest, seid, sequence_number);
                    h.length = 100;
                    h
                } else {
                    let mut h = PfcpHeader::new(PfcpMessageType::HeartbeatRequest, sequence_number);
                    h.length = 8;
                    h
                };
                
                // Encode twice
                let mut buf1 = BytesMut::new();
                let mut buf2 = BytesMut::new();
                header.encode(&mut buf1);
                header.encode(&mut buf2);
                
                prop_assert_eq!(buf1, buf2, "Header encoding must be deterministic");
            }
        }
    }
}
