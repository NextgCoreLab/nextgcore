//! GTP Error types

use thiserror::Error;

/// GTP Error type
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum GtpError {
    /// Buffer too short for operation
    #[error("Buffer too short: need {needed} bytes, have {available}")]
    BufferTooShort { needed: usize, available: usize },

    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidFormat(String),

    /// Invalid header
    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    /// Invalid message type
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),

    /// Invalid IE type
    #[error("Invalid IE type: {0}")]
    InvalidIeType(u8),

    /// Missing mandatory IE
    #[error("Missing mandatory IE: {0}")]
    MissingMandatoryIe(String),

    /// Invalid IE length
    #[error("Invalid IE length: expected {expected}, got {actual}")]
    InvalidIeLength { expected: usize, actual: usize },

    /// Invalid version
    #[error("Invalid GTP version: {0}")]
    InvalidVersion(u8),

    /// Encoding error
    #[error("Encoding error: {0}")]
    EncodingError(String),

    /// Decoding error
    #[error("Decoding error: {0}")]
    DecodingError(String),

    /// Invalid cause value
    #[error("Invalid cause value: {0}")]
    InvalidCause(u8),

    /// Invalid TEID
    #[error("Invalid TEID")]
    InvalidTeid,

    /// Invalid sequence number
    #[error("Invalid sequence number")]
    InvalidSequenceNumber,

    /// Invalid PDN type
    #[error("Invalid PDN type: {0}")]
    InvalidPdnType(u8),

    /// Resource exhausted
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),
}

/// GTP Result type
pub type GtpResult<T> = Result<T, GtpError>;
