//! NAS error types

use thiserror::Error;

/// NAS error type
#[derive(Error, Debug)]
pub enum NasError {
    /// Buffer too short for decoding
    #[error("Buffer too short: expected {expected} bytes, got {actual}")]
    BufferTooShort { expected: usize, actual: usize },

    /// Invalid message type
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),

    /// Invalid protocol discriminator
    #[error("Invalid protocol discriminator: {0}")]
    InvalidProtocolDiscriminator(u8),

    /// Invalid security header type
    #[error("Invalid security header type: {0}")]
    InvalidSecurityHeaderType(u8),

    /// Invalid IE type
    #[error("Invalid IE type: {0}")]
    InvalidIeType(u8),

    /// Invalid IE length
    #[error("Invalid IE length: expected {expected}, got {actual}")]
    InvalidIeLength { expected: usize, actual: usize },

    /// Missing mandatory IE
    #[error("Missing mandatory IE: {0}")]
    MissingMandatoryIe(&'static str),

    /// Invalid mobile identity type
    #[error("Invalid mobile identity type: {0}")]
    InvalidMobileIdentityType(u8),

    /// Invalid registration type
    #[error("Invalid registration type: {0}")]
    InvalidRegistrationType(u8),

    /// Encoding error
    #[error("Encoding error: {0}")]
    EncodingError(String),

    /// Decoding error
    #[error("Decoding error: {0}")]
    DecodingError(String),

    /// Security error
    #[error("Security error: {0}")]
    SecurityError(String),

    /// MAC verification failed
    #[error("MAC verification failed")]
    MacVerificationFailed,
}

/// NAS result type
pub type NasResult<T> = Result<T, NasError>;
