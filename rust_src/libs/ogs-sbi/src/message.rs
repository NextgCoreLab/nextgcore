//! SBI Message Structures
//!
//! This module defines the core message structures for SBI communication,
//! matching the C implementation in lib/sbi/message.h

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::constants::limits;
use crate::types::NfType;

/// SBI Header - matches ogs_sbi_header_t
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SbiHeader {
    /// HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS)
    pub method: String,
    /// Full URI
    pub uri: String,
    /// Service name
    pub service_name: Option<String>,
    /// API version
    pub api_version: Option<String>,
    /// Resource path components
    pub resource: Vec<String>,
}

impl SbiHeader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new header with method and URI
    pub fn with_method_uri(method: impl Into<String>, uri: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            uri: uri.into(),
            ..Default::default()
        }
    }

    /// Add a resource component
    pub fn add_resource(&mut self, component: impl Into<String>) {
        if self.resource.len() < limits::MAX_NUM_OF_RESOURCE_COMPONENT {
            self.resource.push(component.into());
        }
    }

    /// Build the resource path from components
    pub fn resource_path(&self) -> String {
        self.resource.join("/")
    }
}

/// SBI Part - for multipart messages, matches ogs_sbi_part_t
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SbiPart {
    /// Content ID
    pub content_id: Option<String>,
    /// Content type
    pub content_type: Option<String>,
    /// Binary content
    #[serde(skip)]
    pub data: Bytes,
}

impl SbiPart {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_content(content_id: impl Into<String>, content_type: impl Into<String>, data: Bytes) -> Self {
        Self {
            content_id: Some(content_id.into()),
            content_type: Some(content_type.into()),
            data,
        }
    }
}

/// SBI HTTP Message - matches ogs_sbi_http_message_t
#[derive(Debug, Clone, Default)]
pub struct SbiHttpMessage {
    /// Query parameters
    pub params: HashMap<String, String>,
    /// HTTP headers
    pub headers: HashMap<String, String>,
    /// Body content
    pub content: Option<String>,
    /// Multipart parts
    pub parts: Vec<SbiPart>,
}

impl SbiHttpMessage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a query parameter
    pub fn set_param(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.params.insert(key.into(), value.into());
    }

    /// Get a query parameter
    pub fn get_param(&self, key: &str) -> Option<&String> {
        self.params.get(key)
    }

    /// Set a header
    pub fn set_header(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.headers.insert(key.into(), value.into());
    }

    /// Get a header
    pub fn get_header(&self, key: &str) -> Option<&String> {
        self.headers.get(key)
    }

    /// Set the body content
    pub fn set_content(&mut self, content: impl Into<String>) {
        self.content = Some(content.into());
    }

    /// Get content length
    pub fn content_length(&self) -> usize {
        self.content.as_ref().map(|c| c.len()).unwrap_or(0)
    }

    /// Add a multipart part
    pub fn add_part(&mut self, part: SbiPart) {
        if self.parts.len() < limits::MAX_NUM_OF_PART {
            self.parts.push(part);
        }
    }
}

/// SBI Request - matches ogs_sbi_request_t
#[derive(Debug, Clone, Default)]
pub struct SbiRequest {
    /// Request header
    pub header: SbiHeader,
    /// HTTP message (params, headers, body)
    pub http: SbiHttpMessage,
}

impl SbiRequest {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a GET request
    pub fn get(uri: impl Into<String>) -> Self {
        Self {
            header: SbiHeader::with_method_uri("GET", uri),
            http: SbiHttpMessage::new(),
        }
    }

    /// Create a POST request
    pub fn post(uri: impl Into<String>) -> Self {
        Self {
            header: SbiHeader::with_method_uri("POST", uri),
            http: SbiHttpMessage::new(),
        }
    }

    /// Create a PUT request
    pub fn put(uri: impl Into<String>) -> Self {
        Self {
            header: SbiHeader::with_method_uri("PUT", uri),
            http: SbiHttpMessage::new(),
        }
    }

    /// Create a DELETE request
    pub fn delete(uri: impl Into<String>) -> Self {
        Self {
            header: SbiHeader::with_method_uri("DELETE", uri),
            http: SbiHttpMessage::new(),
        }
    }

    /// Create a PATCH request
    pub fn patch(uri: impl Into<String>) -> Self {
        Self {
            header: SbiHeader::with_method_uri("PATCH", uri),
            http: SbiHttpMessage::new(),
        }
    }

    /// Set JSON body content
    pub fn with_json_body<T: Serialize>(mut self, body: &T) -> Result<Self, serde_json::Error> {
        let json = serde_json::to_string(body)?;
        self.http.set_content(json);
        self.http.set_header("Content-Type", "application/json");
        Ok(self)
    }

    /// Set raw body content
    pub fn with_body(mut self, content: impl Into<String>, content_type: impl Into<String>) -> Self {
        self.http.set_content(content);
        self.http.set_header("Content-Type", content_type);
        self
    }

    /// Add a query parameter
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.http.set_param(key, value);
        self
    }

    /// Add a header
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.http.set_header(key, value);
        self
    }
}

/// SBI Response - matches ogs_sbi_response_t
#[derive(Debug, Clone, Default)]
pub struct SbiResponse {
    /// Response header
    pub header: SbiHeader,
    /// HTTP message (params, headers, body)
    pub http: SbiHttpMessage,
    /// HTTP status code
    pub status: u16,
}

impl SbiResponse {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a response with status code
    pub fn with_status(status: u16) -> Self {
        Self {
            status,
            ..Default::default()
        }
    }

    /// Create a successful response (200 OK)
    pub fn ok() -> Self {
        Self::with_status(200)
    }

    /// Create a created response (201 Created)
    pub fn created() -> Self {
        Self::with_status(201)
    }

    /// Create a no content response (204 No Content)
    pub fn no_content() -> Self {
        Self::with_status(204)
    }

    /// Create a bad request response (400 Bad Request)
    pub fn bad_request() -> Self {
        Self::with_status(400)
    }

    /// Create a not found response (404 Not Found)
    pub fn not_found() -> Self {
        Self::with_status(404)
    }

    /// Create an internal server error response (500 Internal Server Error)
    pub fn internal_error() -> Self {
        Self::with_status(500)
    }

    /// Set JSON body content
    pub fn with_json_body<T: Serialize>(mut self, body: &T) -> Result<Self, serde_json::Error> {
        let json = serde_json::to_string(body)?;
        self.http.set_content(json);
        self.http.set_header("Content-Type", "application/json");
        Ok(self)
    }

    /// Set raw body content
    pub fn with_body(mut self, content: impl Into<String>, content_type: impl Into<String>) -> Self {
        self.http.set_content(content);
        self.http.set_header("Content-Type", content_type);
        self
    }

    /// Add a header
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.http.set_header(key, value);
        self
    }

    /// Check if response is successful (2xx)
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Parse JSON body
    pub fn json_body<T: for<'de> Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        let content = self.http.content.as_deref().unwrap_or("{}");
        serde_json::from_str(content)
    }
}

/// Discovery Option - matches ogs_sbi_discovery_option_t
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SbiDiscoveryOption {
    /// Target NF instance ID
    pub target_nf_instance_id: Option<String>,
    /// Requester NF instance ID
    pub requester_nf_instance_id: Option<String>,
    /// Service names
    pub service_names: Vec<String>,
    /// S-NSSAIs
    pub snssais: Vec<SNssai>,
    /// DNN
    pub dnn: Option<String>,
    /// TAI presence flag
    pub tai_presence: bool,
    /// TAI
    pub tai: Option<Tai>,
    /// GUAMI presence flag
    pub guami_presence: bool,
    /// GUAMI
    pub guami: Option<Guami>,
    /// Target PLMN list
    pub target_plmn_list: Vec<PlmnId>,
    /// Requester PLMN list
    pub requester_plmn_list: Vec<PlmnId>,
    /// HNRF URI
    pub hnrf_uri: Option<String>,
    /// Requester features
    pub requester_features: u64,
}

impl SbiDiscoveryOption {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_target_nf_instance_id(mut self, id: impl Into<String>) -> Self {
        self.target_nf_instance_id = Some(id.into());
        self
    }

    pub fn with_service_name(mut self, name: impl Into<String>) -> Self {
        self.service_names.push(name.into());
        self
    }

    pub fn with_dnn(mut self, dnn: impl Into<String>) -> Self {
        self.dnn = Some(dnn.into());
        self
    }
}

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SNssai {
    /// Slice/Service Type (SST)
    pub sst: u8,
    /// Slice Differentiator (SD) - optional, 3 bytes
    pub sd: Option<[u8; 3]>,
}

impl SNssai {
    pub fn new(sst: u8) -> Self {
        Self { sst, sd: None }
    }

    pub fn with_sd(sst: u8, sd: [u8; 3]) -> Self {
        Self { sst, sd: Some(sd) }
    }
}

/// TAI (Tracking Area Identity)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tai {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// TAC (Tracking Area Code)
    pub tac: [u8; 3],
}

/// PLMN ID (Public Land Mobile Network Identity)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PlmnId {
    /// Mobile Country Code (MCC) - 3 digits
    pub mcc: [u8; 3],
    /// Mobile Network Code (MNC) - 2 or 3 digits
    pub mnc: Vec<u8>,
}

impl PlmnId {
    pub fn new(mcc: [u8; 3], mnc: Vec<u8>) -> Self {
        Self { mcc, mnc }
    }
}

/// GUAMI (Globally Unique AMF Identifier)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Guami {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// AMF ID
    pub amf_id: [u8; 3],
}

/// SBI Message Parameters - matches param struct in ogs_sbi_message_t
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SbiMessageParams {
    /// Target NF type for discovery
    pub target_nf_type: Option<NfType>,
    /// Requester NF type
    pub requester_nf_type: Option<NfType>,
    /// Discovery options
    pub discovery_option: Option<SbiDiscoveryOption>,
    /// NF ID
    pub nf_id: Option<String>,
    /// NF type
    pub nf_type: Option<NfType>,
    /// Limit for results
    pub limit: Option<i32>,
    /// DNN
    pub dnn: Option<String>,
    /// Fields to return
    pub fields: Vec<String>,
    /// Dataset names
    pub dataset_names: Vec<String>,
    /// PLMN ID presence
    pub plmn_id_presence: bool,
    /// PLMN ID
    pub plmn_id: Option<PlmnId>,
    /// S-NSSAI presence
    pub snssai_presence: bool,
    /// S-NSSAI
    pub s_nssai: Option<SNssai>,
    /// IPv4 address
    pub ipv4addr: Option<String>,
    /// IPv6 prefix
    pub ipv6prefix: Option<String>,
    /// Home PLMN ID presence
    pub home_plmn_id_presence: bool,
    /// Home PLMN ID
    pub home_plmn_id: Option<PlmnId>,
    /// TAI presence
    pub tai_presence: bool,
    /// TAI
    pub tai: Option<Tai>,
}

/// Problem Details - RFC 7807 compliant error response
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProblemDetails {
    /// A URI reference that identifies the problem type
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub problem_type: Option<String>,
    /// A short, human-readable summary of the problem type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The HTTP status code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<i32>,
    /// A human-readable explanation specific to this occurrence
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// A URI reference that identifies the specific occurrence
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Application-specific error cause
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    /// Invalid parameters
    #[serde(rename = "invalidParams", skip_serializing_if = "Option::is_none")]
    pub invalid_params: Option<Vec<InvalidParam>>,
}

impl ProblemDetails {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_status(status: i32) -> Self {
        Self {
            status: Some(status),
            ..Default::default()
        }
    }

    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_cause(mut self, cause: impl Into<String>) -> Self {
        self.cause = Some(cause.into());
        self
    }
}

/// Invalid Parameter for ProblemDetails
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvalidParam {
    /// Parameter name
    pub param: String,
    /// Reason why the parameter is invalid
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbi_header() {
        let mut header = SbiHeader::with_method_uri("GET", "/nrf/v1/nf-instances");
        header.service_name = Some("nnrf-nfm".to_string());
        header.api_version = Some("v1".to_string());
        header.add_resource("nf-instances");
        
        assert_eq!(header.method, "GET");
        assert_eq!(header.resource.len(), 1);
    }

    #[test]
    fn test_sbi_request() {
        let request = SbiRequest::get("/test")
            .with_param("key", "value")
            .with_header("Accept", "application/json");
        
        assert_eq!(request.header.method, "GET");
        assert_eq!(request.http.get_param("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_sbi_response() {
        let response = SbiResponse::ok()
            .with_body(r#"{"status":"ok"}"#, "application/json");
        
        assert!(response.is_success());
        assert_eq!(response.status, 200);
    }

    #[test]
    fn test_problem_details() {
        let problem = ProblemDetails::with_status(404)
            .with_title("Not Found")
            .with_detail("The requested resource was not found");
        
        let json = serde_json::to_string(&problem).unwrap();
        assert!(json.contains("404"));
        assert!(json.contains("Not Found"));
    }

    #[test]
    fn test_snssai() {
        let snssai = SNssai::with_sd(1, [0x00, 0x00, 0x01]);
        assert_eq!(snssai.sst, 1);
        assert_eq!(snssai.sd, Some([0x00, 0x00, 0x01]));
    }
}
