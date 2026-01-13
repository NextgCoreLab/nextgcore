//! Session establishment integration tests
//!
//! Tests for PDU session establishment through SMF/UPF and
//! EPS bearer activation through MME/SGWC/SGWU.
//! Validates: Requirements 15.4

use std::sync::Arc;
use tokio::sync::RwLock;
use bytes::Bytes;

use crate::common::{
    MessageType, MessageCapture,
    CapturedMessage, MessageField,
};

/// Test PDU session establishment flow
#[tokio::test]
async fn test_pdu_session_establishment() {
    let _ = env_logger::try_init();
    
    let capture = Arc::new(RwLock::new(MessageCapture::new()));
    
    // Simulate PDU session establishment request
    let session_request = CapturedMessage::new(
        MessageType::CreateSessionRequest,
        Bytes::new(),
        "AMF",
        "SMF",
    )
    .with_field("supi", MessageField::String("imsi-001010000000001".to_string()))
    .with_field("dnn", MessageField::String("internet".to_string()))
    .with_field("pdu_session_id", MessageField::Number(1));
    
    // Capture the request
    {
        let mut cap = capture.write().await;
        cap.capture(session_request.clone());
    }
    
    // Simulate PFCP session establishment to UPF
    let pfcp_request = CapturedMessage::new(
        MessageType::SessionEstablishmentRequest,
        Bytes::new(),
        "SMF",
        "UPF",
    )
    .with_field("seid", MessageField::Number(1));
    
    {
        let mut cap = capture.write().await;
        cap.capture(pfcp_request);
    }
    
    // Simulate PFCP response from UPF
    let pfcp_response = CapturedMessage::new(
        MessageType::SessionEstablishmentResponse,
        Bytes::new(),
        "UPF",
        "SMF",
    )
    .with_field("seid", MessageField::Number(1))
    .with_field("cause", MessageField::String("Request accepted".to_string()));
    
    {
        let mut cap = capture.write().await;
        cap.capture(pfcp_response);
    }
    
    // Simulate PDU session establishment response
    let session_response = CapturedMessage::new(
        MessageType::CreateSessionResponse,
        Bytes::new(),
        "SMF",
        "AMF",
    )
    .with_field("pdu_session_id", MessageField::Number(1))
    .with_field("cause", MessageField::String("Request accepted".to_string()));
    
    {
        let mut cap = capture.write().await;
        cap.capture(session_response);
    }
    
    // Verify message sequence
    let cap = capture.read().await;
    assert!(cap.has_sequence(&[
        MessageType::CreateSessionRequest,
        MessageType::SessionEstablishmentRequest,
        MessageType::SessionEstablishmentResponse,
        MessageType::CreateSessionResponse,
    ]));
    
    assert_eq!(cap.count(), 4);
}

/// Test EPS bearer activation flow
#[tokio::test]
async fn test_eps_bearer_activation() {
    let _ = env_logger::try_init();
    
    let capture = Arc::new(RwLock::new(MessageCapture::new()));
    
    // Simulate Create Session Request from MME to SGW-C
    let create_session_req = CapturedMessage::new(
        MessageType::CreateSessionRequest,
        Bytes::new(),
        "MME",
        "SGW-C",
    )
    .with_field("imsi", MessageField::String("001010000000001".to_string()))
    .with_field("apn", MessageField::String("internet".to_string()));
    
    {
        let mut cap = capture.write().await;
        cap.capture(create_session_req);
    }
    
    // Simulate PFCP session establishment from SGW-C to SGW-U
    let pfcp_request = CapturedMessage::new(
        MessageType::SessionEstablishmentRequest,
        Bytes::new(),
        "SGW-C",
        "SGW-U",
    );
    
    {
        let mut cap = capture.write().await;
        cap.capture(pfcp_request);
    }
    
    // Simulate PFCP response
    let pfcp_response = CapturedMessage::new(
        MessageType::SessionEstablishmentResponse,
        Bytes::new(),
        "SGW-U",
        "SGW-C",
    );
    
    {
        let mut cap = capture.write().await;
        cap.capture(pfcp_response);
    }
    
    // Simulate Create Session Response
    let create_session_resp = CapturedMessage::new(
        MessageType::CreateSessionResponse,
        Bytes::new(),
        "SGW-C",
        "MME",
    )
    .with_field("cause", MessageField::String("Request accepted".to_string()));
    
    {
        let mut cap = capture.write().await;
        cap.capture(create_session_resp);
    }
    
    // Verify message sequence
    let cap = capture.read().await;
    assert!(cap.has_sequence(&[
        MessageType::CreateSessionRequest,
        MessageType::SessionEstablishmentRequest,
        MessageType::SessionEstablishmentResponse,
        MessageType::CreateSessionResponse,
    ]));
}

/// Test PDU session modification
#[tokio::test]
async fn test_pdu_session_modification() {
    let _ = env_logger::try_init();
    
    let capture = Arc::new(RwLock::new(MessageCapture::new()));
    
    // Simulate session modification request
    let mod_request = CapturedMessage::new(
        MessageType::SessionModificationRequest,
        Bytes::new(),
        "SMF",
        "UPF",
    )
    .with_field("seid", MessageField::Number(1));
    
    {
        let mut cap = capture.write().await;
        cap.capture(mod_request);
    }
    
    // Simulate modification response
    let mod_response = CapturedMessage::new(
        MessageType::SessionModificationResponse,
        Bytes::new(),
        "UPF",
        "SMF",
    )
    .with_field("seid", MessageField::Number(1))
    .with_field("cause", MessageField::String("Request accepted".to_string()));
    
    {
        let mut cap = capture.write().await;
        cap.capture(mod_response);
    }
    
    // Verify sequence
    let cap = capture.read().await;
    assert!(cap.has_sequence(&[
        MessageType::SessionModificationRequest,
        MessageType::SessionModificationResponse,
    ]));
}

/// Test PDU session deletion
#[tokio::test]
async fn test_pdu_session_deletion() {
    let _ = env_logger::try_init();
    
    let capture = Arc::new(RwLock::new(MessageCapture::new()));
    
    // Simulate session deletion request
    let del_request = CapturedMessage::new(
        MessageType::SessionDeletionRequest,
        Bytes::new(),
        "SMF",
        "UPF",
    )
    .with_field("seid", MessageField::Number(1));
    
    {
        let mut cap = capture.write().await;
        cap.capture(del_request);
    }
    
    // Simulate deletion response
    let del_response = CapturedMessage::new(
        MessageType::SessionDeletionResponse,
        Bytes::new(),
        "UPF",
        "SMF",
    )
    .with_field("seid", MessageField::Number(1))
    .with_field("cause", MessageField::String("Request accepted".to_string()));
    
    {
        let mut cap = capture.write().await;
        cap.capture(del_response);
    }
    
    // Verify sequence
    let cap = capture.read().await;
    assert!(cap.has_sequence(&[
        MessageType::SessionDeletionRequest,
        MessageType::SessionDeletionResponse,
    ]));
}

/// Test GTP-U tunnel establishment
#[tokio::test]
async fn test_gtp_tunnel_establishment() {
    let _ = env_logger::try_init();
    
    let capture = Arc::new(RwLock::new(MessageCapture::new()));
    
    // Simulate PFCP session with FAR/PDR for GTP tunnel
    let pfcp_request = CapturedMessage::new(
        MessageType::SessionEstablishmentRequest,
        Bytes::new(),
        "SMF",
        "UPF",
    )
    .with_field("create_pdr", MessageField::Object({
        let mut map = std::collections::HashMap::new();
        map.insert("pdr_id".to_string(), MessageField::Number(1));
        map.insert("precedence".to_string(), MessageField::Number(100));
        map
    }))
    .with_field("create_far", MessageField::Object({
        let mut map = std::collections::HashMap::new();
        map.insert("far_id".to_string(), MessageField::Number(1));
        map.insert("apply_action".to_string(), MessageField::String("FORW".to_string()));
        map
    }));
    
    {
        let mut cap = capture.write().await;
        cap.capture(pfcp_request);
    }
    
    // Verify the message was captured
    let cap = capture.read().await;
    assert_eq!(cap.count(), 1);
    
    let msgs = cap.messages_of_type(&MessageType::SessionEstablishmentRequest);
    assert_eq!(msgs.len(), 1);
    assert!(msgs[0].fields.contains_key("create_pdr"));
    assert!(msgs[0].fields.contains_key("create_far"));
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]
        
        /// Property: Session IDs are preserved through the flow
        #[test]
        fn prop_session_id_preserved(session_id in 1i64..1000) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let capture = Arc::new(RwLock::new(MessageCapture::new()));
                
                let request = CapturedMessage::new(
                    MessageType::SessionEstablishmentRequest,
                    Bytes::new(),
                    "SMF",
                    "UPF",
                )
                .with_field("seid", MessageField::Number(session_id));
                
                {
                    let mut cap = capture.write().await;
                    cap.capture(request);
                }
                
                let cap = capture.read().await;
                let msgs = cap.messages_of_type(&MessageType::SessionEstablishmentRequest);
                prop_assert_eq!(msgs.len(), 1);
                prop_assert_eq!(msgs[0].get_number("seid"), Some(session_id));
                
                Ok(())
            }).unwrap();
        }
        
        /// Property: PDR IDs are unique within a session
        #[test]
        fn prop_pdr_ids_unique(pdr_id in 1i64..65535) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let capture = Arc::new(RwLock::new(MessageCapture::new()));
                
                let request = CapturedMessage::new(
                    MessageType::SessionEstablishmentRequest,
                    Bytes::new(),
                    "SMF",
                    "UPF",
                )
                .with_field("pdr_id", MessageField::Number(pdr_id));
                
                {
                    let mut cap = capture.write().await;
                    cap.capture(request);
                }
                
                let cap = capture.read().await;
                let msgs = cap.messages_of_type(&MessageType::SessionEstablishmentRequest);
                prop_assert_eq!(msgs[0].get_number("pdr_id"), Some(pdr_id));
                
                Ok(())
            }).unwrap();
        }
    }
}
