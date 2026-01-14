//! SBI Error Types
//!
//! Error types for the SBI library

use thiserror::Error;

/// SBI Error type
#[derive(Error, Debug)]
pub enum SbiError {
    /// HTTP/2 connection error
    #[error("HTTP/2 connection error: {0}")]
    ConnectionError(String),

    /// Request timeout
    #[error("Request timeout")]
    Timeout,

    /// Invalid URI
    #[error("Invalid URI: {0}")]
    InvalidUri(String),

    /// Invalid method
    #[error("Invalid HTTP method: {0}")]
    InvalidMethod(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// HTTP error with status code
    #[error("HTTP error: {status} - {message}")]
    HttpError {
        status: u16,
        message: String,
    },

    /// Server error
    #[error("Server error: {0}")]
    ServerError(String),

    /// Client error
    #[error("Client error: {0}")]
    ClientError(String),

    /// TLS/SSL error
    #[error("TLS error: {0}")]
    TlsError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Hyper error
    #[error("Hyper error: {0}")]
    HyperError(String),

    /// Invalid response
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// Service unavailable
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Discovery failed
    #[error("NF discovery failed: {0}")]
    DiscoveryFailed(String),

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Authorization failed
    #[error("Authorization failed: {0}")]
    AuthorizationFailed(String),

    /// Resource not found
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Conflict
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl SbiError {
    /// Create an HTTP error from status code
    pub fn from_status(status: u16, message: impl Into<String>) -> Self {
        Self::HttpError {
            status,
            message: message.into(),
        }
    }

    /// Get the HTTP status code if this is an HTTP error
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::HttpError { status, .. } => Some(*status),
            Self::NotFound(_) => Some(404),
            Self::Conflict(_) => Some(409),
            Self::AuthenticationFailed(_) => Some(401),
            Self::AuthorizationFailed(_) => Some(403),
            Self::ServiceUnavailable(_) => Some(503),
            Self::Timeout => Some(408),
            _ => None,
        }
    }

    /// Check if this is a retryable error
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Timeout
                | Self::ConnectionError(_)
                | Self::ServiceUnavailable(_)
                | Self::HttpError { status: 503, .. }
                | Self::HttpError { status: 429, .. }
        )
    }
}

/// Result type for SBI operations
pub type SbiResult<T> = Result<T, SbiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_code() {
        let err = SbiError::from_status(404, "Not found");
        assert_eq!(err.status_code(), Some(404));

        let err = SbiError::NotFound("resource".to_string());
        assert_eq!(err.status_code(), Some(404));
    }

    #[test]
    fn test_retryable_errors() {
        assert!(SbiError::Timeout.is_retryable());
        assert!(SbiError::ServiceUnavailable("test".to_string()).is_retryable());
        assert!(!SbiError::NotFound("test".to_string()).is_retryable());
    }
}
