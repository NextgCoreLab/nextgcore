//! PFCP Error Types
//!
//! Error types for PFCP protocol operations.

use thiserror::Error;

/// PFCP Error type
#[derive(Debug, Error)]
pub enum PfcpError {
    /// Buffer too short for operation
    #[error("Buffer too short: needed {needed} bytes, available {available}")]
    BufferTooShort { needed: usize, available: usize },

    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidFormat(String),

    /// Invalid message type
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),

    /// Invalid IE type
    #[error("Invalid IE type: {0}")]
    InvalidIeType(u16),

    /// Invalid cause value
    #[error("Invalid cause value: {0}")]
    InvalidCause(u8),

    /// Invalid node ID type
    #[error("Invalid node ID type: {0}")]
    InvalidNodeIdType(u8),

    /// Invalid interface type
    #[error("Invalid interface type: {0}")]
    InvalidInterfaceType(u8),

    /// Encoding error
    #[error("Encoding error: {0}")]
    EncodingError(String),

    /// Decoding error
    #[error("Decoding error: {0}")]
    DecodingError(String),

    /// Missing mandatory IE
    #[error("Missing mandatory IE: {0}")]
    MissingMandatoryIe(String),

    /// Version not supported
    #[error("PFCP version not supported: {0}")]
    VersionNotSupported(u8),
}

/// PFCP Result type
pub type PfcpResult<T> = Result<T, PfcpError>;
