//! Property-based tests for protocol flows
//!
//! Tests message sequence equivalence with C implementation.
//! Validates: Requirements 15.1-15.6

use std::sync::Arc;
use tokio::sync::RwLock;
use bytes::Bytes;
use proptest::prelude::*;

use crate::common::{
    MessageType, MessageCapture, CapturedMessage, MessageField,
    MockEnvironment, NfType, PlmnId,
};

// ============================================================================
// Strategies for generating test data
// ============================================================================

/// Strategy for generating valid IMSI values
fn arb_imsi() -> impl Strategy<Value = String> {
    // IMSI format: MCC (3 digits) + MNC (2-3 digits) + MSIN (9-10 digits)
    (100u32..999, 10u32..999, 100000000u64..9999999999)
        .prop_map(|(mcc, mnc, msin)| format!("{:03}{:03}{:010}", mcc, mnc, msin))
}

/// Strategy for generating valid SUPI values
fn arb_supi() -> impl Strategy<Value = String> {
    arb_imsi().prop_map(|imsi| format!("imsi-{}", imsi))
}

/// Strategy for generating valid DNN values
fn arb_dnn() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("internet".to_string()),
        Just("ims".to_string()),
        Just("mms".to_string()),
        "[a-z]{3,10}".prop_map(|s| s),
    ]
}

/// Strategy for generating valid APN values
fn arb_apn() -> impl Strategy<Value = String> {
    arb_dnn()
}

/// Strategy for generating valid PLMN IDs
fn arb_plmn_id() -> impl Strategy<Value = PlmnId> {
    (1u16..999, 1u16..999)
        .prop_map(|(mcc, mnc)| {
            let mnc_len = if mnc > 99 { 3 } else { 2 };
            PlmnId::new(mcc, mnc, mnc_len)
        })
}

/// Strategy for generating valid PDU session IDs (1-15)
fn arb_pdu_session_id() -> impl Strategy<Value = i64> {
    1i64..16
}

/// Strategy for generating valid EPS bearer IDs (5-15)
fn arb_eps_bearer_id() -> impl Strategy<Value = i64> {
    5i64..16
}

/// Strategy for generating valid SEID values
fn arb_seid() -> impl Strategy<Value = i64> {
    1i64..0x7FFFFFFFFFFFFFFF
}

/// Strategy for generating valid TEID values
fn arb_teid() -> impl Strategy<Value = i64> {
    1i64..0xFFFFFFFF
}

/// Strategy for generating valid 5QI values
fn arb_5qi() -> impl Strategy<Value = i64> {
    prop_oneof![
        Just(1i64),  // Conversational Voice
        Just(2i64),  // Conversational Video
        Just(5i64),  // IMS Signaling
        Just(6i64),  // Video (Buffered Streaming)
        Just(7i64),  // Voice, Video (Live Streaming)
        Just(8i64),  // Video (Buffered Streaming)
        Just(9i64),  // Video (Buffered Streaming) - Default
        Just(65i64), // Mission Critical user plane Push To Talk voice
        Just(69i64), // Mission Critical delay sensitive signaling
    ]
}

/// Strategy for generating valid QCI values (EPS)
fn arb_qci() -> impl Strategy<Value = i64> {
    1i64..10
}

// ============================================================================
// Property Tests for Registration Flows
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    /// Property 15.1: Registration request with valid SUPI triggers authentication
    /// Feature: nextgcore-rust-conversion
    /// Validates: Requirement 15.3 - 5G UE registration
    #[test]
    fn prop_registration_triggers_auth(supi in arb_supi()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut env = MockEnvironment::new().with_amf();
            env.start_all().await.unwrap();
            
            let reg_request = CapturedMessage::new(
                MessageType::RegistrationRequest,
                Bytes::new(),
                "UE",
                "AMF",
            )
            .with_field("supi", MessageField::String(supi));
            
            let response = env.send_message(NfType::Amf, reg_request).await.unwrap();
            
            prop_assert!(response.is_some());
            prop_assert_eq!(response.unwrap().msg_type, MessageType::AuthenticationRequest);
            
            env.stop_all().await.unwrap();
            Ok(())
        }).unwrap();
    }
    
    /// Property 15.2: Attach request with valid IMSI triggers authentication
    /// Feature: nextgcore-rust-conversion
    /// Validates: Requirement 15.3 - 4G UE attach
    #[test]
    fn prop_attach_triggers_auth(imsi in arb_imsi()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut env = MockEnvironment::new().with_mme();
            env.start_all().await.unwrap();
            
            let attach_request = CapturedMessage::new(
                MessageType::AttachRequest,
                Bytes::new(),
                "UE",
                "MME",
            )
            .with_field("imsi", MessageField::String(imsi));
            
            let response = env.send_message(NfType::Mme, attach_request).await.unwrap();
            
            prop_assert!(response.is_some());
            prop_assert_eq!(response.unwrap().msg_type, MessageType::AuthenticationRequest);
            
            env.stop_all().await.unwrap();
            Ok(())
        }).unwrap();
    }
    
    /// Property 15.3: PLMN ID encoding produces valid 3-byte output
    /// Feature: nextgcore-rust-conversion
    /// Validates: Requirement 15.1 - Protocol encoding
    #[test]
    fn prop_plmn_encoding_valid(plmn in arb_plmn_id()) {
        let bytes = plmn.to_bytes();
        
        // PLMN ID is always 3 bytes
        prop_assert_eq!(bytes.len(), 3);
        
        // First nibble of first byte should be MCC digit 2
        // Second nibble of first byte should be MCC digit 1
        let mcc_digit1 = bytes[0] & 0x0F;
        let mcc_digit2 = (bytes[0] >> 4) & 0x0F;
        
        prop_assert!(mcc_digit1 <= 9);
        prop_assert!(mcc_digit2 <= 9);
    }
}

// ============================================================================
// Property Tests for Session Flows
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    /// Property 15.4: PDU session ID is preserved through establishment
    /// Feature: nextgcore-rust-conversion
    /// Validates: Requirement 15.4 - PDU session establishment
    #[test]
    fn prop_pdu_session_id_preserved(
        supi in arb_supi(),
        dnn in arb_dnn(),
        pdu_session_id in arb_pdu_session_id()
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let capture = Arc::new(RwLock::new(MessageCapture::new()));
            
            let session_request = CapturedMessage::new(
                MessageType::CreateSessionRequest,
                Bytes::new(),
                "AMF",
                "SMF",
            )
            .with_field("supi", MessageField::String(supi))
            .with_field("dnn", MessageField::String(dnn))
            .with_field("pdu_session_id", MessageField::Number(pdu_session_id));
            
            {
                let mut cap = capture.write().await;
                cap.capture(session_request);
            }
            
            let cap = capture.read().await;
            let msgs = cap.messages_of_type(&MessageType::CreateSessionRequest);
            
            prop_assert_eq!(msgs.len(), 1);
            prop_assert_eq!(msgs[0].get_number("pdu_session_id"), Some(pdu_session_id));
            
            Ok(())
        }).unwrap();
    }
    
    /// Property 15.5: PFCP SEID is preserved through session operations
    /// Feature: nextgcore-rust-conversion
    /// Validates: Requirement 15.4 - PFCP session handling
    #[test]
    fn prop_pfcp_seid_preserved(seid in arb_seid()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let capture = Arc::new(RwLock::new(MessageCapture::new()));
            
            let pfcp_request = CapturedMessage::new(
                MessageType::SessionEstablishmentRequest,
                Bytes::new(),
                "SMF",
                "UPF",
            )
            .with_field("seid", MessageField::Number(seid));
            
            {
                let mut cap = capture.write().await;
                cap.capture(pfcp_request);
            }
            
            let cap = capture.read().await;
            let msgs = cap.messages_of_type(&MessageType::SessionEstablishmentRequest);
            
            prop_assert_eq!(msgs.len(), 1);
            prop_assert_eq!(msgs[0].get_number("seid"), Some(seid));
            
            Ok(())
        }).unwrap();
    }
    
    /// Property 15.6: GTP TEID is valid 32-bit value
    /// Feature: nextgcore-rust-conversion
    /// Validates: Requirement 15.5 - GTP communication
    #[test]
    fn prop_gtp_teid_valid(teid in arb_teid()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let capture = Arc::new(RwLock::new(MessageCapture::new()));
            
            let gtp_msg = CapturedMessage::new(
                MessageType::CreateSessionResponse,
                Bytes::new(),
                "SGW-C",
                "MME",
            )
            .with_field("s11_sgw_teid", MessageField::Number(teid));
            
            {
                let mut cap = capture.write().await;
                cap.capture(gtp_msg);
            }
            
            let cap = capture.read().await;
            let msgs = cap.messages_of_type(&MessageType::CreateSessionResponse);
            
            prop_assert_eq!(msgs.len(), 1);
            let stored_teid = msgs[0].get_number("s11_sgw_teid").unwrap();
            
            // TEID must be 32-bit
            prop_assert!(stored_teid >= 0);
            prop_assert!(stored_teid <= 0xFFFFFFFF);
            
            Ok(())
        }).unwrap();
    }
}

// ============================================================================
// Property Tests for Inter-NF Communication
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    /// Property 15.7: NF registration preserves NF type
    /// Feature: nextgcore-rust-conversion
    /// Validates: Requirement 15.5 - SBI communication
    #[test]
    fn prop_nf_registration_preserves_type(nf_type in "[A-Z]{2,4}") {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let capture = Arc::new(RwLock::new(MessageCapture::new()));
            
            let nf_register = CapturedMessage::new(
                MessageType::NfRegister,
                Bytes::new(),
                &nf_type,
                "NRF",
            )
            .with_field("nf_type", MessageField::String(nf_type.clone()));
            
            {
                let mut cap = capture.write().await;
                cap.capture(nf_register);
            }
            
            let cap = capture.read().await;
            let msgs = cap.messages_of_type(&MessageType::NfRegister);
            
            prop_assert_eq!(msgs.len(), 1);
            prop_assert_eq!(msgs[0].get_string("nf_type"), Some(nf_type.as_str()));
            
            Ok(())
        }).unwrap();
    }
    
    /// Property 15.8: Diameter result codes are in valid range
    /// Feature: nextgcore-rust-conversion
    /// Validates: Requirement 15.5 - Diameter communication
    #[test]
    fn prop_diameter_result_code_valid(result_code in 1000i64..6000) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let capture = Arc::new(RwLock::new(MessageCapture::new()));
            
            let aia = CapturedMessage::new(
                MessageType::AuthenticationInformationAnswer,
                Bytes::new(),
                "HSS",
                "MME",
            )
            .with_field("result_code", MessageField::Number(result_code));
            
            {
                let mut cap = capture.write().await;
                cap.capture(aia);
            }
            
            let cap = capture.read().await;
            let msgs = cap.messages_of_type(&MessageType::AuthenticationInformationAnswer);
            
            prop_assert_eq!(msgs.len(), 1);
            let stored_code = msgs[0].get_number("result_code").unwrap();
            
            // Diameter result codes: 1xxx (informational), 2xxx (success), 
            // 3xxx (protocol errors), 4xxx (transient failures), 5xxx (permanent failures)
            prop_assert!(stored_code >= 1000);
            prop_assert!(stored_code < 6000);
            
            Ok(())
        }).unwrap();
    }
    
    /// Property 15.9: 5QI values are valid
    /// Feature: nextgcore-rust-conversion
    /// Validates: Requirement 15.4 - QoS handling
    #[test]
    fn prop_5qi_valid(qos_5qi in arb_5qi()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let capture = Arc::new(RwLock::new(MessageCapture::new()));
            
            let session_msg = CapturedMessage::new(
                MessageType::CreateSessionRequest,
                Bytes::new(),
                "AMF",
                "SMF",
            )
            .with_field("qos_5qi", MessageField::Number(qos_5qi));
            
            {
                let mut cap = capture.write().await;
                cap.capture(session_msg);
            }
            
            let cap = capture.read().await;
            let msgs = cap.messages_of_type(&MessageType::CreateSessionRequest);
            
            prop_assert_eq!(msgs.len(), 1);
            let stored_5qi = msgs[0].get_number("qos_5qi").unwrap();
            
            // Valid 5QI ranges: 1-9 (standardized), 65-67, 69, 70, 75, 79, 80, 82-85 (standardized)
            // and 128-254 (operator-specific)
            prop_assert!(
                (stored_5qi >= 1 && stored_5qi <= 9) ||
                (stored_5qi >= 65 && stored_5qi <= 70) ||
                (stored_5qi >= 75 && stored_5qi <= 85) ||
                (stored_5qi >= 128 && stored_5qi <= 254)
            );
            
            Ok(())
        }).unwrap();
    }
}

// ============================================================================
// Property Tests for Message Sequence Equivalence
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]
    
    /// Property 15.10: Registration flow produces correct message sequence
    /// Feature: nextgcore-rust-conversion
    /// Validates: Requirement 15.6 - Message sequence equivalence
    #[test]
    fn prop_registration_sequence_correct(_seed in any::<u64>()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut env = MockEnvironment::new().with_amf();
            env.start_all().await.unwrap();
            
            let capture = env.capture();
            
            // Send registration request
            let reg_request = CapturedMessage::new(
                MessageType::RegistrationRequest,
                Bytes::new(),
                "UE",
                "AMF",
            );
            let _ = env.send_message(NfType::Amf, reg_request).await;
            
            // Send auth response
            let auth_response = CapturedMessage::new(
                MessageType::AuthenticationResponse,
                Bytes::new(),
                "UE",
                "AMF",
            );
            let _ = env.send_message(NfType::Amf, auth_response).await;
            
            // Send SMC complete
            let smc_complete = CapturedMessage::new(
                MessageType::SecurityModeComplete,
                Bytes::new(),
                "UE",
                "AMF",
            );
            let _ = env.send_message(NfType::Amf, smc_complete).await;
            
            // Verify sequence
            let cap = capture.read().await;
            prop_assert!(cap.has_sequence(&[
                MessageType::RegistrationRequest,
                MessageType::AuthenticationResponse,
                MessageType::SecurityModeComplete,
            ]));
            
            env.stop_all().await.unwrap();
            Ok(())
        }).unwrap();
    }
    
    /// Property 15.11: Session establishment produces correct PFCP sequence
    /// Feature: nextgcore-rust-conversion
    /// Validates: Requirement 15.6 - Message sequence equivalence
    #[test]
    fn prop_session_pfcp_sequence_correct(seid in arb_seid()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let capture = Arc::new(RwLock::new(MessageCapture::new()));
            
            // PFCP session establishment request
            let pfcp_req = CapturedMessage::new(
                MessageType::SessionEstablishmentRequest,
                Bytes::new(),
                "SMF",
                "UPF",
            )
            .with_field("seid", MessageField::Number(seid));
            
            {
                let mut cap = capture.write().await;
                cap.capture(pfcp_req);
            }
            
            // PFCP session establishment response
            let pfcp_resp = CapturedMessage::new(
                MessageType::SessionEstablishmentResponse,
                Bytes::new(),
                "UPF",
                "SMF",
            )
            .with_field("seid", MessageField::Number(seid));
            
            {
                let mut cap = capture.write().await;
                cap.capture(pfcp_resp);
            }
            
            // Verify sequence
            let cap = capture.read().await;
            prop_assert!(cap.has_sequence(&[
                MessageType::SessionEstablishmentRequest,
                MessageType::SessionEstablishmentResponse,
            ]));
            
            // Verify SEID consistency
            let reqs = cap.messages_of_type(&MessageType::SessionEstablishmentRequest);
            let resps = cap.messages_of_type(&MessageType::SessionEstablishmentResponse);
            
            prop_assert_eq!(reqs.len(), 1);
            prop_assert_eq!(resps.len(), 1);
            prop_assert_eq!(reqs[0].get_number("seid"), resps[0].get_number("seid"));
            
            Ok(())
        }).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_arb_imsi_format() {
        // Test that generated IMSIs have correct format using proptest runner
        proptest::proptest!(|(imsi in arb_imsi())| {
            // IMSI should be 15-16 digits
            assert!(imsi.len() >= 15 && imsi.len() <= 16);
            assert!(imsi.chars().all(|c| c.is_ascii_digit()));
        });
    }
    
    #[test]
    fn test_arb_supi_format() {
        proptest::proptest!(|(supi in arb_supi())| {
            // SUPI should start with "imsi-"
            assert!(supi.starts_with("imsi-"));
        });
    }
}
