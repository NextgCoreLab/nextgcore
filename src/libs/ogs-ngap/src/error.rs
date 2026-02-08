//! NGAP Error Types

use ogs_asn1c::PerError;
use thiserror::Error;

/// Errors that can occur during NGAP message processing
#[derive(Error, Debug)]
pub enum NgapError {
    /// ASN.1 encoding/decoding error
    #[error("ASN.1 codec error: {0}")]
    Asn1(#[from] PerError),

    /// Missing mandatory IE
    #[error("Missing mandatory IE: {ie_name} (id={ie_id})")]
    MissingMandatoryIe { ie_name: &'static str, ie_id: u16 },

    /// Unexpected message type
    #[error("Unexpected message type: expected {expected}, got {got}")]
    UnexpectedMessageType {
        expected: &'static str,
        got: String,
    },

    /// Unexpected procedure code
    #[error("Unexpected procedure code: expected {expected}, got {got}")]
    UnexpectedProcedureCode { expected: u8, got: u8 },

    /// Invalid IE value
    #[error("Invalid IE value for {ie_name}: {reason}")]
    InvalidIeValue {
        ie_name: &'static str,
        reason: String,
    },

    /// Encoding error
    #[error("Encoding error: {0}")]
    EncodingError(String),
}

pub type NgapResult<T> = Result<T, NgapError>;
