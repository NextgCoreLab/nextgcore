//! NextGCore SBI (Service Based Interface) Library
//!
//! This crate provides HTTP/2 SBI operations for 5G core network functions.
//! It implements the 3GPP Service Based Interface using hyper and h2 crates.
//!
//! # Features
//!
//! - HTTP/2 client and server using hyper
//! - OpenAPI message serialization using serde_json
//! - Service types and constants matching 3GPP specifications
//! - NF instance and service discovery context management
//!
//! # Example
//!
//! ```rust,no_run
//! use ogs_sbi::{SbiClient, SbiClientConfig, SbiRequest, SbiResponse};
//!
//! async fn example() {
//!     // Create a client
//!     let client = SbiClient::with_host_port("localhost", 7777);
//!     
//!     // Send a GET request
//!     let response = client.get("/nnrf-nfm/v1/nf-instances").await;
//! }
//! ```
//!
//! # Modules
//!
//! - [`types`] - Service types, NF types, and enumerations
//! - [`constants`] - HTTP status codes, methods, headers, and other constants
//! - [`message`] - SBI message structures (request, response, headers)
//! - [`client`] - HTTP/2 client implementation
//! - [`server`] - HTTP/2 server implementation
//! - [`context`] - NF instance and service discovery context
//! - [`error`] - Error types

pub mod constants;
pub mod context;
pub mod error;
pub mod message;
pub mod types;

pub mod client;
pub mod server;

// Re-export commonly used types
pub use client::{SbiClient, SbiClientConfig};
pub use context::{global_context, NfInstance, NfService, NfStatus, NfSubscription, SbiContext};
pub use error::{SbiError, SbiResult};
pub use message::{
    Guami, InvalidParam, PlmnId, ProblemDetails, SNssai, SbiDiscoveryOption, SbiHeader,
    SbiHttpMessage, SbiMessageParams, SbiPart, SbiRequest, SbiResponse, Tai,
};
pub use server::{send_error, SbiRequestHandler, SbiServer, SbiServerConfig, StreamId};
pub use types::{NfType, SbiAppError, SbiServiceType, UriScheme};

/// Initialize the SBI library
pub fn init() {
    // Initialize global context
    let _ = global_context();
}

/// Finalize the SBI library
pub fn finalize() {
    // Cleanup if needed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        init();
        let _ctx = global_context();
        // Context is initialized
    }

    #[test]
    fn test_service_type_roundtrip() {
        let service_type = SbiServiceType::NnrfNfm;
        let name = service_type.to_name();
        let parsed = SbiServiceType::from_name(name);
        assert_eq!(parsed, Some(service_type));
    }

    #[test]
    fn test_request_builder() {
        let request = SbiRequest::get("/test")
            .with_param("key", "value")
            .with_header("Accept", "application/json");

        assert_eq!(request.header.method, "GET");
        assert_eq!(request.header.uri, "/test");
        assert_eq!(request.http.get_param("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_response_builder() {
        let response = SbiResponse::ok()
            .with_body(r#"{"status":"ok"}"#, "application/json");

        assert!(response.is_success());
        assert_eq!(response.status, 200);
    }

    #[test]
    fn test_problem_details_serialization() {
        let problem = ProblemDetails::with_status(404)
            .with_title("Not Found")
            .with_detail("The requested resource was not found")
            .with_cause("RESOURCE_NOT_FOUND");

        let json = serde_json::to_string(&problem).unwrap();
        assert!(json.contains("404"));
        assert!(json.contains("Not Found"));
        assert!(json.contains("RESOURCE_NOT_FOUND"));

        let parsed: ProblemDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, Some(404));
    }
}
