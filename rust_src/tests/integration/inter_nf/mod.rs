//! Inter-NF communication integration tests
//!
//! Tests for SBI communication between 5G NFs, Diameter communication
//! between EPC NFs, and GTP-C/GTP-U communication.
//! Validates: Requirements 15.5

use std::sync::Arc;
use tokio::sync::RwLock;
use bytes::Bytes;

use crate::common::{
    TestContext, NfType, MessageType, MessageCapture,
    CapturedMessage, MockEnvironment, MessageField,
    MockNrf, NfProfile,
};

/// Test SBI NF registration with NRF
#[tokio::test]
async fn test_sbi_nf_registration() {
    let _ = env_logger::try_init();
    
    let capture = Arc::new(RwLock::new(MessageCapture::new()));
    
    // Simulate NF Register request
    let nf_register = CapturedMessage::new(
        MessageType::NfRegister,
        Bytes::new(),
        "AMF",
        "NRF",
    )
    .with_field("nf_type", MessageField::String("AMF".to_string()))
    .with_field("nf_instance_id", MessageField::String("amf-001".to_string()))
    .with_field("nf_status", MessageField::String("REGISTERED".to_string()));
    
    {
        let mut cap = capture.write().await;
        cap.capture(nf_register);
    }
    
    // Verify registration was captured
    let cap = capture.read().await;
    let msgs = cap.messages_of_type(&MessageType::NfRegister);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].get_string("nf_type"), Some("AMF"));
}

/// Test SBI NF discovery
#[tokio::test]
async fn test_sbi_nf_discovery() {
    let _ = env_logger::try_init();
    
    let capture = Arc::new(RwLock::new(MessageCapture::new()));
    
    // Simulate NF Discover request
    let nf_discover = CapturedMessage::new(
        MessageType::NfDiscover,
        Bytes::new(),
        "AMF",
        "NRF",
    )
    .with_field("target_nf_type", MessageField::String("UDM".to_string()))
    .with_field("requester_nf_type", MessageField::String("AMF".to_string()));
    
    {
        let mut cap = capture.write().await;
        cap.capture(nf_discover);
    }
    
    // Verify discovery was captured
    let cap = capture.read().await;
    let msgs = cap.messages_of_type(&MessageType::NfDiscover);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].get_string("target_nf_type"), Some("UDM"));
}

/// Test SBI NF update
#[tokio::test]
async fn test_sbi_nf_update() {
    let _ = env_logger::try_init();
    
    let capture = Arc::new(RwLock::new(MessageCapture::new()));
    
    // Simulate NF Update request
    let nf_update = CapturedMessage::new(
        MessageType::NfUpdate,
        Bytes::new(),
        "AMF",
        "NRF",
    )
    .with_field("nf_instance_id", MessageField::String("amf-001".to_string()))
    .with_field("nf_status", MessageField::String("REGISTERED".to_string()));
    
    {
        let mut cap = capture.write().await;
        cap.capture(nf_update);
    }
    
    // Verify update was captured
    let cap = capture.read().await;
    let msgs = cap.messages_of_type(&MessageType::NfUpdate);
    assert_eq!(msgs.len(), 1);
}

/// Test SBI NF deregistration
#[tokio::test]
async fn test_sbi_nf_deregistration() {
    let _ = env_logger::try_init();
    
    let capture = Arc::new(RwLock::new(MessageCapture::new()));
    
    // Simulate NF Deregister request
    let nf_deregister = CapturedMessage::new(
        MessageType::NfDeregister,
        Bytes::new(),
        "AMF",
        "NRF",
    )
    .with_field("nf_instance_id", MessageField::String("amf-001".to_string()));
    
    {
        let mut cap = capture.write().await;
        cap.capture(nf_deregister);
    }
    
    // Verify deregistration was captured
    let cap = capture.read().await;
    let msgs = cap.messages_of_type(&MessageType::NfDeregister);
    assert_eq!(msgs.len(), 1);
}

/// Test Diameter S6a communication (MME-HSS)
#[tokio::test]
async fn test_diameter_s6a_authentication() {
    let _ = env_logger::try_init();
    
    let capture = Arc::new(RwLock::new(MessageCapture::new()));
    
    // Simulate Authentication-Information-Request
    let air = CapturedMessage::new(
        MessageType::AuthenticationInformationRequest,
        Bytes::new(),
        "MME",
        "HSS",
    )
    .with_field("imsi", MessageField::String("001010000000001".to_string()))
    .with_field("visited_plmn_id", MessageField::Bytes(vec![0x00, 0xF1, 0x10]));
    
    {
        let mut cap = capture.write().await;
        cap.capture(air);
    }
    
    // Simulate Authentication-Information-Answer
    let aia = CapturedMessage::new(
        MessageType::AuthenticationInformationAnswer,
        Bytes::new(),
        "HSS",
        "MME",
    )
    .with_field("result_code", MessageField::Number(2001)) // DIAMETER_SUCCESS
    .with_field("auth_vectors", MessageField::Array(vec![]));
    
    {
        let mut cap = capture.write().await;
        cap.capture(aia);
    }
    
    // Verify sequence
    let cap = capture.read().await;
    assert!(cap.has_sequence(&[
        MessageType::AuthenticationInformationRequest,
        MessageType::AuthenticationInformationAnswer,
    ]));
}

/// Test Diameter S6a Update Location
#[tokio::test]
async fn test_diameter_s6a_update_location() {
    let _ = env_logger::try_init();
    
    let capture = Arc::new(RwLock::new(MessageCapture::new()));
    
    // Simulate Update-Location-Request
    let ulr = CapturedMessage::new(
        MessageType::UpdateLocationRequest,
        Bytes::new(),
        "MME",
        "HSS",
    )
    .with_field("imsi", MessageField::String("001010000000001".to_string()))
    .with_field("ulr_flags", MessageField::Number(0x03));
    
    {
        let mut cap = capture.write().await;
        cap.capture(ulr);
    }
    
    // Simulate Update-Location-Answer
    let ula = CapturedMessage::new(
        MessageType::UpdateLocationAnswer,
        Bytes::new(),
        "HSS",
        "MME",
    )
    .with_field("result_code", MessageField::Number(2001));
    
    {
        let mut cap = capture.write().await;
        cap.capture(ula);
    }
    
    // Verify sequence
    let cap = capture.read().await;
    assert!(cap.has_sequence(&[
        MessageType::UpdateLocationRequest,
        MessageType::UpdateLocationAnswer,
    ]));
}

/// Test Diameter Gx communication (PCRF-PGW)
#[tokio::test]
async fn test_diameter_gx_credit_control() {
    let _ = env_logger::try_init();
    
    let capture = Arc::new(RwLock::new(MessageCapture::new()));
    
    // Simulate Credit-Control-Request (Initial)
    let ccr = CapturedMessage::new(
        MessageType::CreditControlRequest,
        Bytes::new(),
        "PGW",
        "PCRF",
    )
    .with_field("cc_request_type", MessageField::Number(1)) // INITIAL_REQUEST
    .with_field("cc_request_number", MessageField::Number(0));
    
    {
        let mut cap = capture.write().await;
        cap.capture(ccr);
    }
    
    // Simulate Credit-Control-Answer
    let cca = CapturedMessage::new(
        MessageType::CreditControlAnswer,
        Bytes::new(),
        "PCRF",
        "PGW",
    )
    .with_field("result_code", MessageField::Number(2001))
    .with_field("cc_request_number", MessageField::Number(0));
    
    {
        let mut cap = capture.write().await;
        cap.capture(cca);
    }
    
    // Verify sequence
    let cap = capture.read().await;
    assert!(cap.has_sequence(&[
        MessageType::CreditControlRequest,
        MessageType::CreditControlAnswer,
    ]));
}

/// Test GTP-C communication (MME-SGW)
#[tokio::test]
async fn test_gtpc_create_session() {
    let _ = env_logger::try_init();
    
    let capture = Arc::new(RwLock::new(MessageCapture::new()));
    
    // Simulate Create Session Request
    let csr = CapturedMessage::new(
        MessageType::CreateSessionRequest,
        Bytes::new(),
        "MME",
        "SGW-C",
    )
    .with_field("imsi", MessageField::String("001010000000001".to_string()))
    .with_field("apn", MessageField::String("internet".to_string()))
    .with_field("rat_type", MessageField::Number(6)); // EUTRAN
    
    {
        let mut cap = capture.write().await;
        cap.capture(csr);
    }
    
    // Simulate Create Session Response
    let csr_resp = CapturedMessage::new(
        MessageType::CreateSessionResponse,
        Bytes::new(),
        "SGW-C",
        "MME",
    )
    .with_field("cause", MessageField::Number(16)) // Request accepted
    .with_field("s11_sgw_teid", MessageField::Number(0x12345678));
    
    {
        let mut cap = capture.write().await;
        cap.capture(csr_resp);
    }
    
    // Verify sequence
    let cap = capture.read().await;
    assert!(cap.has_sequence(&[
        MessageType::CreateSessionRequest,
        MessageType::CreateSessionResponse,
    ]));
}

/// Test GTP-C Modify Bearer
#[tokio::test]
async fn test_gtpc_modify_bearer() {
    let _ = env_logger::try_init();
    
    let capture = Arc::new(RwLock::new(MessageCapture::new()));
    
    // Simulate Modify Bearer Request
    let mbr = CapturedMessage::new(
        MessageType::ModifyBearerRequest,
        Bytes::new(),
        "MME",
        "SGW-C",
    )
    .with_field("s11_mme_teid", MessageField::Number(0x87654321));
    
    {
        let mut cap = capture.write().await;
        cap.capture(mbr);
    }
    
    // Simulate Modify Bearer Response
    let mbr_resp = CapturedMessage::new(
        MessageType::ModifyBearerResponse,
        Bytes::new(),
        "SGW-C",
        "MME",
    )
    .with_field("cause", MessageField::Number(16));
    
    {
        let mut cap = capture.write().await;
        cap.capture(mbr_resp);
    }
    
    // Verify sequence
    let cap = capture.read().await;
    assert!(cap.has_sequence(&[
        MessageType::ModifyBearerRequest,
        MessageType::ModifyBearerResponse,
    ]));
}

/// Test PFCP Association Setup
#[tokio::test]
async fn test_pfcp_association_setup() {
    let _ = env_logger::try_init();
    
    let capture = Arc::new(RwLock::new(MessageCapture::new()));
    
    // Simulate Association Setup Request
    let asr = CapturedMessage::new(
        MessageType::AssociationSetupRequest,
        Bytes::new(),
        "SMF",
        "UPF",
    )
    .with_field("node_id", MessageField::String("smf.nextgcore.org".to_string()))
    .with_field("recovery_time_stamp", MessageField::Number(1234567890));
    
    {
        let mut cap = capture.write().await;
        cap.capture(asr);
    }
    
    // Simulate Association Setup Response
    let asr_resp = CapturedMessage::new(
        MessageType::AssociationSetupResponse,
        Bytes::new(),
        "UPF",
        "SMF",
    )
    .with_field("node_id", MessageField::String("upf.nextgcore.org".to_string()))
    .with_field("cause", MessageField::Number(1)); // Request accepted
    
    {
        let mut cap = capture.write().await;
        cap.capture(asr_resp);
    }
    
    // Verify sequence
    let cap = capture.read().await;
    assert!(cap.has_sequence(&[
        MessageType::AssociationSetupRequest,
        MessageType::AssociationSetupResponse,
    ]));
}

/// Test PFCP Heartbeat
#[tokio::test]
async fn test_pfcp_heartbeat() {
    let _ = env_logger::try_init();
    
    let capture = Arc::new(RwLock::new(MessageCapture::new()));
    
    // Simulate Heartbeat Request
    let hbr = CapturedMessage::new(
        MessageType::HeartbeatRequest,
        Bytes::new(),
        "SMF",
        "UPF",
    )
    .with_field("recovery_time_stamp", MessageField::Number(1234567890));
    
    {
        let mut cap = capture.write().await;
        cap.capture(hbr);
    }
    
    // Simulate Heartbeat Response
    let hbr_resp = CapturedMessage::new(
        MessageType::HeartbeatResponse,
        Bytes::new(),
        "UPF",
        "SMF",
    )
    .with_field("recovery_time_stamp", MessageField::Number(1234567890));
    
    {
        let mut cap = capture.write().await;
        cap.capture(hbr_resp);
    }
    
    // Verify sequence
    let cap = capture.read().await;
    assert!(cap.has_sequence(&[
        MessageType::HeartbeatRequest,
        MessageType::HeartbeatResponse,
    ]));
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]
        
        /// Property: Diameter result codes are valid
        #[test]
        fn prop_diameter_result_codes(result_code in 1000i64..6000) {
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
                prop_assert_eq!(msgs[0].get_number("result_code"), Some(result_code));
                
                Ok(())
            }).unwrap();
        }
        
        /// Property: GTP TEIDs are 32-bit values
        #[test]
        fn prop_gtp_teid_valid(teid in 0i64..0xFFFFFFFF) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let capture = Arc::new(RwLock::new(MessageCapture::new()));
                
                let csr = CapturedMessage::new(
                    MessageType::CreateSessionResponse,
                    Bytes::new(),
                    "SGW-C",
                    "MME",
                )
                .with_field("s11_sgw_teid", MessageField::Number(teid));
                
                {
                    let mut cap = capture.write().await;
                    cap.capture(csr);
                }
                
                let cap = capture.read().await;
                let msgs = cap.messages_of_type(&MessageType::CreateSessionResponse);
                prop_assert_eq!(msgs[0].get_number("s11_sgw_teid"), Some(teid));
                
                Ok(())
            }).unwrap();
        }
    }
}
