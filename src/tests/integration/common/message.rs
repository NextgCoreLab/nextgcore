//! Message verification utilities
//!
//! Provides utilities for verifying protocol messages in integration tests.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use bytes::Bytes;

/// Message type for verification
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MessageType {
    // NAS 5GS messages
    RegistrationRequest,
    RegistrationAccept,
    RegistrationComplete,
    RegistrationReject,
    AuthenticationRequest,
    AuthenticationResponse,
    SecurityModeCommand,
    SecurityModeComplete,
    DeregistrationRequest,
    DeregistrationAccept,
    
    // NAS EPS messages
    AttachRequest,
    AttachAccept,
    AttachComplete,
    AttachReject,
    
    // NGAP messages
    NgSetupRequest,
    NgSetupResponse,
    InitialUeMessage,
    DownlinkNasTransport,
    UplinkNasTransport,
    InitialContextSetupRequest,
    InitialContextSetupResponse,
    UeContextReleaseCommand,
    UeContextReleaseComplete,
    
    // S1AP messages
    S1SetupRequest,
    S1SetupResponse,
    InitialUeMessageS1,
    DownlinkNasTransportS1,
    UplinkNasTransportS1,
    
    // GTP-C messages
    CreateSessionRequest,
    CreateSessionResponse,
    DeleteSessionRequest,
    DeleteSessionResponse,
    ModifyBearerRequest,
    ModifyBearerResponse,
    
    // PFCP messages
    AssociationSetupRequest,
    AssociationSetupResponse,
    SessionEstablishmentRequest,
    SessionEstablishmentResponse,
    SessionModificationRequest,
    SessionModificationResponse,
    SessionDeletionRequest,
    SessionDeletionResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    
    // SBI messages
    NfRegister,
    NfUpdate,
    NfDeregister,
    NfDiscover,
    
    // Diameter messages
    AuthenticationInformationRequest,
    AuthenticationInformationAnswer,
    UpdateLocationRequest,
    UpdateLocationAnswer,
    CreditControlRequest,
    CreditControlAnswer,
    
    // Unknown
    Unknown(String),
}

/// Captured message for verification
#[derive(Debug, Clone)]
pub struct CapturedMessage {
    /// Message type
    pub msg_type: MessageType,
    
    /// Raw message bytes
    pub raw: Bytes,
    
    /// Decoded fields (if available)
    pub fields: HashMap<String, MessageField>,
    
    /// Timestamp
    pub timestamp: std::time::Instant,
    
    /// Source
    pub source: String,
    
    /// Destination
    pub destination: String,
}

/// Message field value
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageField {
    String(String),
    Number(i64),
    Float(f64),
    Bool(bool),
    Bytes(Vec<u8>),
    Array(Vec<MessageField>),
    Object(HashMap<String, MessageField>),
}

impl CapturedMessage {
    /// Create a new captured message
    pub fn new(msg_type: MessageType, raw: Bytes, source: &str, destination: &str) -> Self {
        Self {
            msg_type,
            raw,
            fields: HashMap::new(),
            timestamp: std::time::Instant::now(),
            source: source.to_string(),
            destination: destination.to_string(),
        }
    }
    
    /// Add a field to the message
    pub fn with_field(mut self, name: &str, value: MessageField) -> Self {
        self.fields.insert(name.to_string(), value);
        self
    }
    
    /// Get a field value
    pub fn get_field(&self, name: &str) -> Option<&MessageField> {
        self.fields.get(name)
    }
    
    /// Get a string field
    pub fn get_string(&self, name: &str) -> Option<&str> {
        match self.fields.get(name) {
            Some(MessageField::String(s)) => Some(s),
            _ => None,
        }
    }
    
    /// Get a number field
    pub fn get_number(&self, name: &str) -> Option<i64> {
        match self.fields.get(name) {
            Some(MessageField::Number(n)) => Some(*n),
            _ => None,
        }
    }
}

/// Message capture buffer for collecting messages during tests
#[derive(Debug, Default)]
pub struct MessageCapture {
    messages: Vec<CapturedMessage>,
}

impl MessageCapture {
    /// Create a new message capture buffer
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }
    
    /// Capture a message
    pub fn capture(&mut self, msg: CapturedMessage) {
        log::debug!("Captured message: {:?} from {} to {}", 
            msg.msg_type, msg.source, msg.destination);
        self.messages.push(msg);
    }
    
    /// Get all captured messages
    pub fn messages(&self) -> &[CapturedMessage] {
        &self.messages
    }
    
    /// Get messages of a specific type
    pub fn messages_of_type(&self, msg_type: &MessageType) -> Vec<&CapturedMessage> {
        self.messages.iter()
            .filter(|m| &m.msg_type == msg_type)
            .collect()
    }
    
    /// Get messages from a specific source
    pub fn messages_from(&self, source: &str) -> Vec<&CapturedMessage> {
        self.messages.iter()
            .filter(|m| m.source == source)
            .collect()
    }
    
    /// Get messages to a specific destination
    pub fn messages_to(&self, destination: &str) -> Vec<&CapturedMessage> {
        self.messages.iter()
            .filter(|m| m.destination == destination)
            .collect()
    }
    
    /// Clear all captured messages
    pub fn clear(&mut self) {
        self.messages.clear();
    }
    
    /// Get the count of captured messages
    pub fn count(&self) -> usize {
        self.messages.len()
    }
    
    /// Check if a message sequence was observed
    pub fn has_sequence(&self, sequence: &[MessageType]) -> bool {
        if sequence.is_empty() {
            return true;
        }
        
        let mut seq_idx = 0;
        for msg in &self.messages {
            if msg.msg_type == sequence[seq_idx] {
                seq_idx += 1;
                if seq_idx == sequence.len() {
                    return true;
                }
            }
        }
        
        false
    }
}

/// Message verifier for checking message content
pub struct MessageVerifier<'a> {
    message: &'a CapturedMessage,
}

impl<'a> MessageVerifier<'a> {
    /// Create a new message verifier
    pub fn new(message: &'a CapturedMessage) -> Self {
        Self { message }
    }
    
    /// Verify the message type
    pub fn has_type(&self, expected: &MessageType) -> bool {
        &self.message.msg_type == expected
    }
    
    /// Verify a field exists
    pub fn has_field(&self, name: &str) -> bool {
        self.message.fields.contains_key(name)
    }
    
    /// Verify a field has a specific string value
    pub fn field_equals_string(&self, name: &str, expected: &str) -> bool {
        self.message.get_string(name) == Some(expected)
    }
    
    /// Verify a field has a specific number value
    pub fn field_equals_number(&self, name: &str, expected: i64) -> bool {
        self.message.get_number(name) == Some(expected)
    }
    
    /// Verify the message source
    pub fn from_source(&self, expected: &str) -> bool {
        self.message.source == expected
    }
    
    /// Verify the message destination
    pub fn to_destination(&self, expected: &str) -> bool {
        self.message.destination == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_message_capture() {
        let mut capture = MessageCapture::new();
        
        let msg1 = CapturedMessage::new(
            MessageType::RegistrationRequest,
            Bytes::from_static(b"test1"),
            "UE",
            "AMF",
        );
        
        let msg2 = CapturedMessage::new(
            MessageType::RegistrationAccept,
            Bytes::from_static(b"test2"),
            "AMF",
            "UE",
        );
        
        capture.capture(msg1);
        capture.capture(msg2);
        
        assert_eq!(capture.count(), 2);
        assert_eq!(capture.messages_of_type(&MessageType::RegistrationRequest).len(), 1);
        assert_eq!(capture.messages_from("UE").len(), 1);
        assert_eq!(capture.messages_to("AMF").len(), 1);
    }
    
    #[test]
    fn test_message_sequence() {
        let mut capture = MessageCapture::new();
        
        capture.capture(CapturedMessage::new(
            MessageType::RegistrationRequest,
            Bytes::new(),
            "UE", "AMF",
        ));
        capture.capture(CapturedMessage::new(
            MessageType::AuthenticationRequest,
            Bytes::new(),
            "AMF", "UE",
        ));
        capture.capture(CapturedMessage::new(
            MessageType::AuthenticationResponse,
            Bytes::new(),
            "UE", "AMF",
        ));
        capture.capture(CapturedMessage::new(
            MessageType::RegistrationAccept,
            Bytes::new(),
            "AMF", "UE",
        ));
        
        // Valid sequence
        assert!(capture.has_sequence(&[
            MessageType::RegistrationRequest,
            MessageType::AuthenticationRequest,
            MessageType::AuthenticationResponse,
            MessageType::RegistrationAccept,
        ]));
        
        // Partial sequence
        assert!(capture.has_sequence(&[
            MessageType::RegistrationRequest,
            MessageType::RegistrationAccept,
        ]));
        
        // Invalid sequence (wrong order)
        assert!(!capture.has_sequence(&[
            MessageType::RegistrationAccept,
            MessageType::RegistrationRequest,
        ]));
    }
    
    #[test]
    fn test_message_fields() {
        let msg = CapturedMessage::new(
            MessageType::RegistrationRequest,
            Bytes::new(),
            "UE", "AMF",
        )
        .with_field("imsi", MessageField::String("001010000000001".to_string()))
        .with_field("mcc", MessageField::Number(1))
        .with_field("mnc", MessageField::Number(1));
        
        let verifier = MessageVerifier::new(&msg);
        
        assert!(verifier.has_type(&MessageType::RegistrationRequest));
        assert!(verifier.has_field("imsi"));
        assert!(verifier.field_equals_string("imsi", "001010000000001"));
        assert!(verifier.field_equals_number("mcc", 1));
        assert!(verifier.from_source("UE"));
        assert!(verifier.to_destination("AMF"));
    }
}
