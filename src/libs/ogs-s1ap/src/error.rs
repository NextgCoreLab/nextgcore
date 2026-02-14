//! S1AP Error Types

use std::fmt;

/// S1AP Result type
pub type S1apResult<T> = Result<T, S1apError>;

/// S1AP Error
#[derive(Debug)]
pub enum S1apError {
    /// ASN.1 encoding/decoding error
    AsnError(String),
    /// Invalid IE value
    InvalidIeValue { ie_name: &'static str, reason: String },
    /// Missing mandatory IE
    MissingMandatoryIe(&'static str),
    /// Protocol error
    ProtocolError(String),
    /// IO error
    Io(std::io::Error),
}

impl fmt::Display for S1apError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            S1apError::AsnError(msg) => write!(f, "ASN.1 error: {msg}"),
            S1apError::InvalidIeValue { ie_name, reason } => {
                write!(f, "Invalid IE value for {ie_name}: {reason}")
            }
            S1apError::MissingMandatoryIe(ie_name) => {
                write!(f, "Missing mandatory IE: {ie_name}")
            }
            S1apError::ProtocolError(msg) => write!(f, "Protocol error: {msg}"),
            S1apError::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for S1apError {}

impl From<std::io::Error> for S1apError {
    fn from(e: std::io::Error) -> Self {
        S1apError::Io(e)
    }
}

impl From<ogs_asn1c::per::PerError> for S1apError {
    fn from(e: ogs_asn1c::per::PerError) -> Self {
        S1apError::AsnError(e.to_string())
    }
}
