//! SBI Message Structures
//!
//! This module defines the core message structures for SBI communication,
//! matching the C implementation in lib/sbi/message.h

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::constants::{custom_header, discovery_header, limits};
use crate::types::NfType;

/// Decomposed API URI per TS 29.501 Section 4.4.1:
/// `{apiRoot}/{apiName}/{apiVersion}/{apiSpecificResourceUriPart}`
///
/// `apiRoot` is `scheme://host[:port]` plus an optional deployment-specific
/// path prefix; the version segment (`v1`, `v2`, ...) anchors the split so a
/// prefix never gets mistaken for the apiName.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UriComponents {
    /// `scheme://authority[/prefix]` — None for relative URIs without prefix
    pub api_root: Option<String>,
    /// Service API name, e.g. `nnrf-disc`
    pub api_name: Option<String>,
    /// Major-version segment, e.g. `v1`
    pub api_version: Option<String>,
    /// Resource path segments after the version
    pub resource: Vec<String>,
    /// Raw query string (without `?`), if present
    pub query: Option<String>,
}

impl UriComponents {
    /// Decompose an absolute or relative SBI request URI.
    pub fn parse(uri: &str) -> Self {
        let (uri, query) = match uri.split_once('?') {
            Some((u, q)) => (u, Some(q.to_string())),
            None => (uri, None),
        };

        // Split off scheme://authority when the URI is absolute.
        let (authority, path) = if let Some(rest) = uri
            .strip_prefix("http://")
            .map(|r| ("http://", r))
            .or_else(|| uri.strip_prefix("https://").map(|r| ("https://", r)))
        {
            let (scheme, rest) = rest;
            match rest.split_once('/') {
                Some((auth, path)) => (Some(format!("{scheme}{auth}")), path),
                None => (Some(format!("{scheme}{rest}")), ""),
            }
        } else {
            (None, uri.trim_start_matches('/'))
        };

        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        // The version segment anchors the apiName: everything before
        // `{apiName}/{apiVersion}` belongs to the apiRoot prefix.
        let version_idx = segments
            .iter()
            .position(|s| Self::is_version_segment(s))
            .filter(|&i| i >= 1);

        match version_idx {
            Some(i) => {
                let prefix = &segments[..i - 1];
                let api_root = match (&authority, prefix.is_empty()) {
                    (Some(auth), true) => Some(auth.clone()),
                    (Some(auth), false) => Some(format!("{}/{}", auth, prefix.join("/"))),
                    (None, true) => None,
                    (None, false) => Some(format!("/{}", prefix.join("/"))),
                };
                Self {
                    api_root,
                    api_name: Some(segments[i - 1].to_string()),
                    api_version: Some(segments[i].to_string()),
                    resource: segments[i + 1..].iter().map(|s| s.to_string()).collect(),
                    query,
                }
            }
            None => Self {
                // No version segment: treat the first segment as the apiName
                // and the remainder as resource components.
                api_root: authority,
                api_name: segments.first().map(|s| s.to_string()),
                api_version: None,
                resource: segments.iter().skip(1).map(|s| s.to_string()).collect(),
                query,
            },
        }
    }

    /// True for an apiVersion path segment: `v` followed by digits.
    fn is_version_segment(s: &str) -> bool {
        s.len() >= 2
            && (s.starts_with('v') || s.starts_with('V'))
            && s[1..].chars().all(|c| c.is_ascii_digit())
    }
}

/// SBI Header - matches nextgcore_sbi_header_t
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

    /// Decompose `self.uri` per TS 29.501 Section 4.4.1 and populate
    /// `service_name`, `api_version` and `resource` from it.
    /// Returns the full decomposition (including the apiRoot, which has no
    /// field on the header itself).
    pub fn decompose_uri(&mut self) -> UriComponents {
        let components = UriComponents::parse(&self.uri);
        self.service_name = components.api_name.clone();
        self.api_version = components.api_version.clone();
        self.resource = components.resource.clone();
        components
    }
}

/// SBI Part - for multipart messages, matches nextgcore_sbi_part_t
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

    pub fn with_content(
        content_id: impl Into<String>,
        content_type: impl Into<String>,
        data: Bytes,
    ) -> Self {
        Self {
            content_id: Some(content_id.into()),
            content_type: Some(content_type.into()),
            data,
        }
    }
}

/// SBI HTTP Message - matches nextgcore_sbi_http_message_t
#[derive(Debug, Clone, Default)]
pub struct SbiHttpMessage {
    /// Query parameters
    pub params: HashMap<String, String>,
    /// HTTP headers
    pub headers: HashMap<String, String>,
    /// Body content
    pub content: Option<String>,
    /// Binary body content, for responses whose payload is not text.
    ///
    /// `content` is a `String`, so it cannot carry an arbitrary octet stream —
    /// a downloadable artefact (e.g. the NWDAF's ONNX model file, TS 29.520
    /// §4.2.2.5) would otherwise have to be base64'd into JSON or wrapped in
    /// `multipart/related`, neither of which is what a consumer dereferencing a
    /// file URL expects. When this is set and [`Self::parts`] is empty, the
    /// server writes these bytes as the whole body verbatim.
    ///
    /// Defaults to `None`, so every existing response is byte-unchanged.
    pub binary_content: Option<Bytes>,
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

    /// Set a header.
    ///
    /// Header names are case-insensitive (RFC 9110) and hyper lowercases all
    /// HTTP/2 header names on the wire, so the key is normalized to lowercase
    /// on insert and any case-variant duplicate already in the map is
    /// replaced. Lookups via [`get_header`](Self::get_header) accept any
    /// spelling.
    pub fn set_header(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into().to_ascii_lowercase();
        self.headers.retain(|k, _| !k.eq_ignore_ascii_case(&key));
        self.headers.insert(key, value.into());
    }

    /// Get a header by name, case-insensitively.
    ///
    /// Tries the normalized (lowercase) spelling first, then falls back to a
    /// case-insensitive scan so keys inserted directly into the `headers` map
    /// (bypassing [`set_header`](Self::set_header)) are still found.
    pub fn get_header(&self, key: &str) -> Option<&String> {
        if let Some(v) = self.headers.get(key) {
            return Some(v);
        }
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
    }

    /// Remove a header by name, case-insensitively.
    /// Returns the removed value (the last one, if duplicates existed).
    pub fn remove_header(&mut self, key: &str) -> Option<String> {
        let mut removed = None;
        self.headers.retain(|k, v| {
            if k.eq_ignore_ascii_case(key) {
                removed = Some(v.clone());
                false
            } else {
                true
            }
        });
        removed
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

    /// Iterate over all `3gpp-Sbi-*` custom headers (TS 29.500 Section 5.2.3)
    /// present on this message, regardless of the stored case.
    pub fn custom_sbi_headers(&self) -> impl Iterator<Item = (&String, &String)> {
        self.headers.iter().filter(|(k, _)| {
            k.get(..custom_header::PREFIX.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(custom_header::PREFIX))
        })
    }

    /// Get the `3gpp-Sbi-Target-apiRoot` header (TS 29.500 Section 5.2.3.2.4)
    pub fn target_apiroot(&self) -> Option<&String> {
        self.get_header(custom_header::TARGET_APIROOT)
    }

    /// Set the `3gpp-Sbi-Target-apiRoot` header for indirect communication
    /// via SCP/SEPP.
    pub fn set_target_apiroot(&mut self, api_root: impl Into<String>) {
        self.set_header(custom_header::TARGET_APIROOT, api_root);
    }

    /// Get the `3gpp-Sbi-Callback` header (TS 29.500 Section 5.2.3.2.3)
    pub fn callback(&self) -> Option<&String> {
        self.get_header(custom_header::CALLBACK)
    }

    /// Set the `3gpp-Sbi-Callback` header identifying a notification callback.
    pub fn set_callback(&mut self, callback: impl Into<String>) {
        self.set_header(custom_header::CALLBACK, callback);
    }

    /// Get the `3gpp-Sbi-Message-Priority` header (TS 29.500 Section
    /// 5.2.3.2.2) parsed as its 0..=31 priority value. Returns None when the
    /// header is absent or out of range.
    pub fn message_priority(&self) -> Option<u8> {
        self.get_header(custom_header::MESSAGE_PRIORITY)?
            .trim()
            .parse::<u8>()
            .ok()
            .filter(|p| *p <= 31)
    }

    /// Set the `3gpp-Sbi-Message-Priority` header (clamped to the spec
    /// maximum of 31).
    pub fn set_message_priority(&mut self, priority: u8) {
        self.set_header(
            custom_header::MESSAGE_PRIORITY,
            priority.min(31).to_string(),
        );
    }

    /// Get the `3gpp-Sbi-Routing-Binding` header (TS 29.500 Section 6.12)
    pub fn routing_binding(&self) -> Option<&String> {
        self.get_header(custom_header::ROUTING_BINDING)
    }

    /// Set the `3gpp-Sbi-Routing-Binding` header.
    pub fn set_routing_binding(&mut self, binding: impl Into<String>) {
        self.set_header(custom_header::ROUTING_BINDING, binding);
    }

    /// Get the `3gpp-Sbi-Binding` header (TS 29.500 Section 6.12)
    pub fn binding(&self) -> Option<&String> {
        self.get_header(custom_header::BINDING)
    }

    /// Set the `3gpp-Sbi-Binding` header.
    pub fn set_binding(&mut self, binding: impl Into<String>) {
        self.set_header(custom_header::BINDING, binding);
    }

    /// Get the `3gpp-Sbi-Producer-Id` header.
    pub fn producer_id(&self) -> Option<&String> {
        self.get_header(custom_header::PRODUCER_ID)
    }

    /// Set the `3gpp-Sbi-Producer-Id` header.
    pub fn set_producer_id(&mut self, producer_id: impl Into<String>) {
        self.set_header(custom_header::PRODUCER_ID, producer_id);
    }

    /// Get the `3gpp-Sbi-Discovery-target-nf-type` header value.
    pub fn discovery_target_nf_type(&self) -> Option<&String> {
        self.get_header(discovery_header::TARGET_NF_TYPE)
    }

    /// Set the `3gpp-Sbi-Discovery-target-nf-type` header.
    pub fn set_discovery_target_nf_type(&mut self, nf_type: NfType) {
        self.set_header(discovery_header::TARGET_NF_TYPE, nf_type.to_str());
    }

    /// Get the `3gpp-Sbi-Discovery-requester-nf-type` header value.
    pub fn discovery_requester_nf_type(&self) -> Option<&String> {
        self.get_header(discovery_header::REQUESTER_NF_TYPE)
    }

    /// Set the `3gpp-Sbi-Discovery-requester-nf-type` header.
    pub fn set_discovery_requester_nf_type(&mut self, nf_type: NfType) {
        self.set_header(discovery_header::REQUESTER_NF_TYPE, nf_type.to_str());
    }
}

/// SBI Request - matches nextgcore_sbi_request_t
#[derive(Debug, Clone, Default)]
pub struct SbiRequest {
    /// Request header
    pub header: SbiHeader,
    /// HTTP message (params, headers, body)
    pub http: SbiHttpMessage,
    /// Correlation / request ID for distributed tracing (T6.4).
    ///
    /// Populated by the server glue in `convert_request`: taken from
    /// the incoming `x-request-id` header, extracted from the W3C
    /// `traceparent` trace-id field (the 16-byte hex segment), or
    /// generated as a 32-hex-char string from the wall-clock nanoseconds
    /// when neither header is present.  The client propagates the same
    /// value outbound via the `x-request-id` header when forwarding.
    ///
    /// Defaults to an empty string when an `SbiRequest` is constructed
    /// outside the server path (builder methods, unit tests, NF handlers
    /// constructing outbound requests) so existing code needs no changes.
    pub correlation_id: String,
    /// RFC 5705 TLS exporter secret derived from the N32-c TLS connection
    /// (T1.5b / TS 33.501 §13.2.4.4). Present only on requests received over
    /// TLS; `None` for plaintext connections and for requests constructed
    /// programmatically. The SEPP N32-c handler consumes this to derive the
    /// N32-f session key via `set_n32c_tls_exporter_secret`.
    pub tls_exporter_secret: Option<Vec<u8>>,
    /// NF Instance ID from the URI SubjectAltName of the peer's **verified**
    /// client certificate (issue #186, TS 33.310, TS 33.501 §13.4.1.1).
    ///
    /// `Some` only when the listener runs mTLS (`verify_client = true`), rustls
    /// verified the client's chain, and that certificate carries a URI SAN.
    /// `None` for plaintext connections, for TLS without client authentication,
    /// for a certificate with no URI SAN, and for requests built
    /// programmatically.
    ///
    /// This is an identity **this process** verified, so it outranks any
    /// forwarded-certificate header, which is only as trustworthy as the
    /// terminator that set it.
    pub peer_cert_nf_instance_id: Option<String>,
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
            ..Self::default()
        }
    }

    /// Create a POST request
    pub fn post(uri: impl Into<String>) -> Self {
        Self {
            header: SbiHeader::with_method_uri("POST", uri),
            http: SbiHttpMessage::new(),
            ..Self::default()
        }
    }

    /// Create a PUT request
    pub fn put(uri: impl Into<String>) -> Self {
        Self {
            header: SbiHeader::with_method_uri("PUT", uri),
            http: SbiHttpMessage::new(),
            ..Self::default()
        }
    }

    /// Create a DELETE request
    pub fn delete(uri: impl Into<String>) -> Self {
        Self {
            header: SbiHeader::with_method_uri("DELETE", uri),
            http: SbiHttpMessage::new(),
            ..Self::default()
        }
    }

    /// Create a PATCH request
    pub fn patch(uri: impl Into<String>) -> Self {
        Self {
            header: SbiHeader::with_method_uri("PATCH", uri),
            http: SbiHttpMessage::new(),
            ..Self::default()
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
    pub fn with_body(
        mut self,
        content: impl Into<String>,
        content_type: impl Into<String>,
    ) -> Self {
        self.http.set_content(content);
        self.http.set_header("Content-Type", content_type);
        self
    }

    /// Add a query parameter.
    ///
    /// **The value is RAW.** `SbiClient` percent-encodes both key and value when
    /// it assembles the URI (issue #101), so a caller must NOT pre-encode --
    /// doing so double-encodes (`{` -> `%7B` -> `%257B`) and the peer decodes it
    /// once, back to `%7B`.
    ///
    /// This contract is asymmetric with hand-built URI strings: a caller that
    /// formats a path itself and passes it to `SbiClient::get` bypasses the
    /// client's encoder and MUST encode with
    /// [`crate::uri_encode::encode_query_value`] (pcfd's nudr-dr queries do
    /// exactly that).
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.http.set_param(key, value);
        self
    }

    /// Add a header
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.http.set_header(key, value);
        self
    }

    /// Attach a binary multipart part (e.g. an N1 NAS or N2 NGAP container).
    /// The body is sent as `multipart/related` with the JSON content as the
    /// root part (TS 29.500 Section 6.1.2.3).
    pub fn with_part(mut self, part: SbiPart) -> Self {
        self.http.add_part(part);
        self
    }

    /// Decompose the request URI per TS 29.501 Section 4.4.1, populating the
    /// header's `service_name`, `api_version` and `resource` fields.
    pub fn decompose_uri(&mut self) -> UriComponents {
        self.header.decompose_uri()
    }
}

/// SBI Response - matches nextgcore_sbi_response_t
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

    /// Set a JSON body served as `application/3gppHal+json` (issue #82).
    ///
    /// A handful of 3GPP resources are declared HAL-only rather than plain JSON —
    /// e.g. the `201 UEAuthenticationCtx` of `POST /nausf-auth/v1/ue-authentications`
    /// (`TS29509_Nausf_UEAuthentication.yaml:44-48`), whose body carries a `_links`
    /// map the consumer must follow to continue authentication. A strict client
    /// content-negotiating on the HAL type can reject or mis-parse such a body
    /// served as `application/json`.
    ///
    /// Deliberately a SEPARATE method rather than a change to
    /// [`with_json_body`](Self::with_json_body): plain `application/json` is right
    /// for the overwhelming majority of SBI responses, so the HAL type is opt-in at
    /// the call site that the spec declares it for.
    pub fn with_hal_json_body<T: Serialize>(mut self, body: &T) -> Result<Self, serde_json::Error> {
        let json = serde_json::to_string(body)?;
        self.http.set_content(json);
        self.http.set_header(
            crate::constants::header::CONTENT_TYPE,
            crate::constants::content_type::APPLICATION_3GPP_HAL_JSON,
        );
        Ok(self)
    }

    /// Set raw body content
    pub fn with_body(
        mut self,
        content: impl Into<String>,
        content_type: impl Into<String>,
    ) -> Self {
        self.http.set_content(content);
        self.http.set_header("Content-Type", content_type);
        self
    }

    /// Add a header
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.http.set_header(key, value);
        self
    }

    /// Set a ProblemDetails body with the `application/problem+json` content
    /// type required for SBI error responses (TS 29.500 Section 5.2.7).
    /// When the problem carries a status it also becomes the response status.
    pub fn with_problem(mut self, problem: &ProblemDetails) -> Self {
        if let Some(status) = problem.status {
            self.status = status as u16;
        }
        match serde_json::to_string(problem) {
            Ok(json) => {
                self.http.set_content(json);
                self.http.set_header(
                    crate::constants::header::CONTENT_TYPE,
                    crate::constants::content_type::APPLICATION_PROBLEM_JSON,
                );
            }
            Err(e) => log::error!("Failed to serialize ProblemDetails: {e}"),
        }
        self
    }

    /// Attach a binary multipart part (e.g. an N1 NAS or N2 NGAP container).
    /// The body is sent as `multipart/related` with the JSON content as the
    /// root part (TS 29.500 Section 6.1.2.3).
    pub fn with_part(mut self, part: SbiPart) -> Self {
        self.http.add_part(part);
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

/// Discovery Option - matches nextgcore_sbi_discovery_option_t
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

    /// Inject this discovery option as `3gpp-Sbi-Discovery-*` headers
    /// (TS 29.500 Section 5.2.3.2.7, delegated discovery via SCP).
    ///
    /// Structured values (S-NSSAIs, TAI, GUAMI, PLMN lists) are carried as
    /// their JSON representation; list-valued simple parameters are
    /// comma-separated; requester-features is the hexadecimal
    /// SupportedFeatures form.
    pub fn inject_headers(&self, http: &mut SbiHttpMessage) {
        if let Some(ref id) = self.target_nf_instance_id {
            http.set_header(discovery_header::TARGET_NF_INSTANCE_ID, id.clone());
        }
        if let Some(ref id) = self.requester_nf_instance_id {
            http.set_header(discovery_header::REQUESTER_NF_INSTANCE_ID, id.clone());
        }
        if !self.service_names.is_empty() {
            http.set_header(
                discovery_header::SERVICE_NAMES,
                self.service_names.join(","),
            );
        }
        if !self.snssais.is_empty() {
            if let Ok(json) = serde_json::to_string(&self.snssais) {
                http.set_header(discovery_header::SNSSAIS, json);
            }
        }
        if let Some(ref dnn) = self.dnn {
            http.set_header(discovery_header::DNN, dnn.clone());
        }
        if self.tai_presence {
            if let Some(ref tai) = self.tai {
                if let Ok(json) = serde_json::to_string(tai) {
                    http.set_header(discovery_header::TAI, json);
                }
            }
        }
        if self.guami_presence {
            if let Some(ref guami) = self.guami {
                if let Ok(json) = serde_json::to_string(guami) {
                    http.set_header(discovery_header::GUAMI, json);
                }
            }
        }
        if !self.target_plmn_list.is_empty() {
            if let Ok(json) = serde_json::to_string(&self.target_plmn_list) {
                http.set_header(discovery_header::TARGET_PLMN_LIST, json);
            }
        }
        if !self.requester_plmn_list.is_empty() {
            if let Ok(json) = serde_json::to_string(&self.requester_plmn_list) {
                http.set_header(discovery_header::REQUESTER_PLMN_LIST, json);
            }
        }
        if let Some(ref uri) = self.hnrf_uri {
            http.set_header(discovery_header::HNRF_URI, uri.clone());
        }
        if self.requester_features != 0 {
            http.set_header(
                discovery_header::REQUESTER_FEATURES,
                format!("{:x}", self.requester_features),
            );
        }
    }

    /// Parse the `3gpp-Sbi-Discovery-*` headers from a message,
    /// case-insensitively. Returns None when no discovery header is present.
    pub fn from_headers(http: &SbiHttpMessage) -> Option<Self> {
        if !http.headers.keys().any(|k| {
            k.get(..discovery_header::PREFIX.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(discovery_header::PREFIX))
        }) {
            return None;
        }

        let mut option = Self::new();
        if let Some(id) = http.get_header(discovery_header::TARGET_NF_INSTANCE_ID) {
            option.target_nf_instance_id = Some(id.clone());
        }
        if let Some(id) = http.get_header(discovery_header::REQUESTER_NF_INSTANCE_ID) {
            option.requester_nf_instance_id = Some(id.clone());
        }
        if let Some(names) = http.get_header(discovery_header::SERVICE_NAMES) {
            option.service_names = names
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Some(json) = http.get_header(discovery_header::SNSSAIS) {
            if let Ok(snssais) = serde_json::from_str(json) {
                option.snssais = snssais;
            }
        }
        if let Some(dnn) = http.get_header(discovery_header::DNN) {
            option.dnn = Some(dnn.clone());
        }
        if let Some(json) = http.get_header(discovery_header::TAI) {
            if let Ok(tai) = serde_json::from_str(json) {
                option.tai = Some(tai);
                option.tai_presence = true;
            }
        }
        if let Some(json) = http.get_header(discovery_header::GUAMI) {
            if let Ok(guami) = serde_json::from_str(json) {
                option.guami = Some(guami);
                option.guami_presence = true;
            }
        }
        if let Some(json) = http.get_header(discovery_header::TARGET_PLMN_LIST) {
            if let Ok(list) = serde_json::from_str(json) {
                option.target_plmn_list = list;
            }
        }
        if let Some(json) = http.get_header(discovery_header::REQUESTER_PLMN_LIST) {
            if let Ok(list) = serde_json::from_str(json) {
                option.requester_plmn_list = list;
            }
        }
        if let Some(uri) = http.get_header(discovery_header::HNRF_URI) {
            option.hnrf_uri = Some(uri.clone());
        }
        if let Some(features) = http.get_header(discovery_header::REQUESTER_FEATURES) {
            option.requester_features =
                u64::from_str_radix(features.trim(), 16).unwrap_or_default();
        }
        Some(option)
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

/// SBI Message Parameters - matches param struct in nextgcore_sbi_message_t
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

/// Serialize the ProblemDetails `type` member, defaulting to `about:blank`
/// when unset (sbi-07).
///
/// TS 29.500 §5.2.7 / TS 29.571 §5.2.4.1 inherit RFC 7807, under which a
/// missing `type` is semantically equivalent to `about:blank`. We make that
/// explicit on the wire so peers and tooling always observe a well-formed
/// problem type. Deserialization is unaffected (the field stays optional).
fn serialize_problem_type<S>(value: &Option<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(t) => serializer.serialize_str(t),
        None => serializer.serialize_str("about:blank"),
    }
}

/// Problem Details - RFC 7807 compliant error response
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProblemDetails {
    /// A URI reference that identifies the problem type. Defaults to
    /// `about:blank` on the wire when unset (TS 29.571 §5.2.4.1 / RFC 7807).
    #[serde(rename = "type", default, serialize_with = "serialize_problem_type")]
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
    /// Features supported by the producer (TS 29.571 SupportedFeatures)
    #[serde(rename = "supportedFeatures", skip_serializing_if = "Option::is_none")]
    pub supported_features: Option<String>,
    /// NF instance ID of the NF that generated the problem
    #[serde(rename = "nfId", skip_serializing_if = "Option::is_none")]
    pub nf_id: Option<String>,
    /// OAuth2 access token error details (TS 29.510 AccessTokenErr)
    #[serde(rename = "accessTokenError", skip_serializing_if = "Option::is_none")]
    pub access_token_error: Option<crate::oauth::AccessTokenError>,
    /// OAuth2 access token request to be (re)tried by the consumer
    /// (TS 29.571 §5.2.4.1, TS 29.510 AccessTokenReq).
    #[serde(rename = "accessTokenRequest", skip_serializing_if = "Option::is_none")]
    pub access_token_request: Option<crate::oauth::AccessTokenRequest>,
    /// NF Instance ID of the NRF that returned an OAuth2 problem
    /// (TS 29.571 §5.2.4.1 `nrfId`).
    #[serde(rename = "nrfId", skip_serializing_if = "Option::is_none")]
    pub nrf_id: Option<String>,
    /// Target SCP apiRoot for indirect-communication redirection
    /// (TS 29.571 §5.2.4.1 `targetScp`, TS 29.500 §6.10.9).
    #[serde(rename = "targetScp", skip_serializing_if = "Option::is_none")]
    pub target_scp: Option<String>,
    /// Target SEPP apiRoot for inter-PLMN redirection
    /// (TS 29.571 §5.2.4.1 `targetSepp`, TS 29.500 §6.10.9).
    #[serde(rename = "targetSepp", skip_serializing_if = "Option::is_none")]
    pub target_sepp: Option<String>,
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

    pub fn with_supported_features(mut self, features: impl Into<String>) -> Self {
        self.supported_features = Some(features.into());
        self
    }

    pub fn with_nf_id(mut self, nf_id: impl Into<String>) -> Self {
        self.nf_id = Some(nf_id.into());
        self
    }

    pub fn with_access_token_error(mut self, error: crate::oauth::AccessTokenError) -> Self {
        self.access_token_error = Some(error);
        self
    }

    /// Set an explicit problem `type` URI. When left unset, the `type` member
    /// still serializes as `about:blank` (sbi-07).
    pub fn with_type(mut self, problem_type: impl Into<String>) -> Self {
        self.problem_type = Some(problem_type.into());
        self
    }

    /// Attach the OAuth2 access token request the consumer should (re)try
    /// (TS 29.571 `accessTokenRequest`).
    pub fn with_access_token_request(mut self, request: crate::oauth::AccessTokenRequest) -> Self {
        self.access_token_request = Some(request);
        self
    }

    /// Set the NRF instance ID that produced an OAuth2 problem
    /// (TS 29.571 `nrfId`).
    pub fn with_nrf_id(mut self, nrf_id: impl Into<String>) -> Self {
        self.nrf_id = Some(nrf_id.into());
        self
    }

    /// Set the target SCP apiRoot for an indirect-communication redirect
    /// (TS 29.571 `targetScp`).
    pub fn with_target_scp(mut self, target_scp: impl Into<String>) -> Self {
        self.target_scp = Some(target_scp.into());
        self
    }

    /// Set the target SEPP apiRoot for an inter-PLMN redirect
    /// (TS 29.571 `targetSepp`).
    pub fn with_target_sepp(mut self, target_sepp: impl Into<String>) -> Self {
        self.target_sepp = Some(target_sepp.into());
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
        let response = SbiResponse::ok().with_body(r#"{"status":"ok"}"#, "application/json");

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

    #[test]
    fn test_header_lookup_case_insensitive() {
        let mut http = SbiHttpMessage::new();

        // Canonical mixed-case spelling on insert, lowercase on lookup —
        // the form hyper delivers for HTTP/2.
        http.set_header("3gpp-Sbi-Target-apiRoot", "https://amf.example:7777");
        assert_eq!(
            http.get_header("3gpp-sbi-target-apiroot")
                .map(String::as_str),
            Some("https://amf.example:7777")
        );
        // Mixed-case lookup of a lowercased (wire-form) header.
        assert_eq!(
            http.get_header("3GPP-SBI-TARGET-APIROOT")
                .map(String::as_str),
            Some("https://amf.example:7777")
        );

        // set_header replaces case-variant duplicates instead of stacking.
        http.set_header("3GPP-Sbi-Target-APIROOT", "https://other:80");
        assert_eq!(http.headers.len(), 1);
        assert_eq!(
            http.target_apiroot().map(String::as_str),
            Some("https://other:80")
        );

        // Keys inserted directly into the map (bypassing set_header) are
        // still found case-insensitively via the fallback scan.
        http.headers
            .insert("Content-Type".to_string(), "application/json".to_string());
        assert_eq!(
            http.get_header("content-type").map(String::as_str),
            Some("application/json")
        );

        // remove_header is case-insensitive too.
        assert!(http.remove_header("CONTENT-TYPE").is_some());
        assert!(http.get_header("Content-Type").is_none());
    }

    #[test]
    fn test_custom_sbi_header_accessors() {
        let mut http = SbiHttpMessage::new();
        http.set_callback("Nsmf_PDUSession_StatusNotify");
        http.set_message_priority(40); // clamped to 31
        http.set_routing_binding("bl=nf-instance; nfinst=54804518");
        http.set_binding("bl=nf-set; nfset=set1.smfset.5gc.mnc012.mcc345");
        http.set_producer_id("3fa85f64-5717-4562-b3fc-2c963f66afa6");

        assert_eq!(
            http.callback().map(String::as_str),
            Some("Nsmf_PDUSession_StatusNotify")
        );
        assert_eq!(http.message_priority(), Some(31));
        assert!(http.routing_binding().is_some());
        assert!(http.binding().is_some());
        assert!(http.producer_id().is_some());

        // All five are enumerable through the generic 3gpp-Sbi-* iterator.
        assert_eq!(http.custom_sbi_headers().count(), 5);

        // Out-of-range priorities parse to None.
        http.set_header("3gpp-Sbi-Message-Priority", "99");
        assert_eq!(http.message_priority(), None);
    }

    #[test]
    fn test_discovery_option_header_round_trip() {
        let mut option = SbiDiscoveryOption::new()
            .with_target_nf_instance_id("9e1e2b3c-0001-4a7e-9f00-aaaabbbbcccc")
            .with_service_name("nudm-uecm")
            .with_service_name("nudm-sdm")
            .with_dnn("internet");
        option.requester_nf_instance_id = Some("9e1e2b3c-0002-4a7e-9f00-ddddeeeeffff".into());
        option.snssais.push(SNssai::with_sd(1, [0x00, 0x00, 0x01]));
        option.tai = Some(Tai {
            plmn_id: PlmnId::new([9, 9, 9], vec![7, 0]),
            tac: [0, 0, 1],
        });
        option.tai_presence = true;
        option.hnrf_uri = Some("https://nrf.hplmn:7777".into());
        option.requester_features = 0x2b;

        let mut http = SbiHttpMessage::new();
        option.inject_headers(&mut http);

        // Lookups survive any casing (hyper lowercases on the wire).
        assert_eq!(
            http.get_header("3GPP-SBI-DISCOVERY-DNN")
                .map(String::as_str),
            Some("internet")
        );

        let parsed = SbiDiscoveryOption::from_headers(&http).unwrap();
        assert_eq!(parsed.target_nf_instance_id, option.target_nf_instance_id);
        assert_eq!(
            parsed.requester_nf_instance_id,
            option.requester_nf_instance_id
        );
        assert_eq!(parsed.service_names, vec!["nudm-uecm", "nudm-sdm"]);
        assert_eq!(parsed.snssais, option.snssais);
        assert_eq!(parsed.dnn.as_deref(), Some("internet"));
        assert!(parsed.tai_presence);
        assert_eq!(parsed.tai, option.tai);
        assert_eq!(parsed.hnrf_uri, option.hnrf_uri);
        assert_eq!(parsed.requester_features, 0x2b);

        // No discovery headers -> None.
        assert!(SbiDiscoveryOption::from_headers(&SbiHttpMessage::new()).is_none());
    }

    #[test]
    fn test_uri_components_relative() {
        let c = UriComponents::parse("/nsmf-pdusession/v1/sm-contexts/123/modify?k=v");
        assert_eq!(c.api_root, None);
        assert_eq!(c.api_name.as_deref(), Some("nsmf-pdusession"));
        assert_eq!(c.api_version.as_deref(), Some("v1"));
        assert_eq!(c.resource, vec!["sm-contexts", "123", "modify"]);
        assert_eq!(c.query.as_deref(), Some("k=v"));
    }

    #[test]
    fn test_uri_components_absolute_with_prefix() {
        // apiRoot may carry a deployment-specific path prefix; the version
        // segment anchors the apiName split (TS 29.501 §4.4.1).
        let c = UriComponents::parse("https://nrf.5gc:7777/prefix/a/nnrf-disc/v2/nf-instances");
        assert_eq!(c.api_root.as_deref(), Some("https://nrf.5gc:7777/prefix/a"));
        assert_eq!(c.api_name.as_deref(), Some("nnrf-disc"));
        assert_eq!(c.api_version.as_deref(), Some("v2"));
        assert_eq!(c.resource, vec!["nf-instances"]);
        assert_eq!(c.query, None);

        let c =
            UriComponents::parse("http://amf:80/namf-comm/v1/ue-contexts/imsi-1/n1-n2-messages");
        assert_eq!(c.api_root.as_deref(), Some("http://amf:80"));
        assert_eq!(c.api_name.as_deref(), Some("namf-comm"));
        assert_eq!(c.api_version.as_deref(), Some("v1"));
        assert_eq!(c.resource, vec!["ue-contexts", "imsi-1", "n1-n2-messages"]);
    }

    #[test]
    fn test_uri_components_no_version_segment() {
        let c = UriComponents::parse("/health");
        assert_eq!(c.api_name.as_deref(), Some("health"));
        assert_eq!(c.api_version, None);
        assert!(c.resource.is_empty());

        let c = UriComponents::parse("");
        assert_eq!(c.api_name, None);
    }

    #[test]
    fn test_header_decompose_uri() {
        let mut request = SbiRequest::get("/nausf-auth/v1/ue-authentications");
        let components = request.decompose_uri();
        assert_eq!(request.header.service_name.as_deref(), Some("nausf-auth"));
        assert_eq!(request.header.api_version.as_deref(), Some("v1"));
        assert_eq!(request.header.resource, vec!["ue-authentications"]);
        assert_eq!(components.api_root, None);
    }

    #[test]
    fn test_problem_details_extended_fields() {
        let problem = ProblemDetails::with_status(403)
            .with_cause("OAUTH2_REQUIRED")
            .with_supported_features("2b")
            .with_nf_id("3fa85f64-5717-4562-b3fc-2c963f66afa6")
            .with_access_token_error(crate::oauth::AccessTokenError {
                error: "invalid_scope".to_string(),
                error_description: Some("scope not granted".to_string()),
                error_uri: None,
            });

        let json = serde_json::to_string(&problem).unwrap();
        assert!(json.contains("\"supportedFeatures\":\"2b\""));
        assert!(json.contains("\"nfId\""));
        assert!(json.contains("\"accessTokenError\""));
        assert!(json.contains("invalid_scope"));

        let parsed: ProblemDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.supported_features.as_deref(), Some("2b"));
        assert_eq!(parsed.access_token_error.unwrap().error, "invalid_scope");

        // Absent optional fields are skipped entirely.
        let bare = serde_json::to_string(&ProblemDetails::with_status(404)).unwrap();
        assert!(!bare.contains("supportedFeatures"));
        assert!(!bare.contains("nfId"));
        assert!(!bare.contains("accessTokenError"));
    }

    #[test]
    fn test_problem_details_default_type_about_blank() {
        // sbi-07: with no explicit `type`, serialization emits about:blank.
        let json = serde_json::to_string(&ProblemDetails::with_status(404)).unwrap();
        assert!(
            json.contains(r#""type":"about:blank""#),
            "default type must be about:blank, got: {json}"
        );

        // An explicit type is preserved verbatim.
        let typed = ProblemDetails::with_status(403).with_type("https://example.com/probs/oauth2");
        let json = serde_json::to_string(&typed).unwrap();
        assert!(json.contains(r#""type":"https://example.com/probs/oauth2""#));

        // Round-trip: about:blank deserializes back into the optional field.
        let bare = serde_json::to_string(&ProblemDetails::with_status(500)).unwrap();
        let parsed: ProblemDetails = serde_json::from_str(&bare).unwrap();
        assert_eq!(parsed.problem_type.as_deref(), Some("about:blank"));
        assert_eq!(parsed.status, Some(500));
    }

    #[test]
    fn test_problem_details_new_29571_members() {
        // sbi-07: the added TS 29.571 members serialize with the spec member
        // names and are absent when unset (additive).
        let problem = ProblemDetails::with_status(307)
            .with_nrf_id("nrf-1")
            .with_target_scp("https://scp1.operator.com")
            .with_target_sepp("https://sepp1.operator.com")
            .with_access_token_request(crate::oauth::AccessTokenRequest {
                grant_type: "client_credentials".to_string(),
                nf_instance_id: "amf-1".to_string(),
                nf_type: NfType::Amf,
                target_nf_type: NfType::Udm,
                scope: "nudm-sdm".to_string(),
                target_nf_instance_id: None,
                cca: None,
            });
        let json = serde_json::to_string(&problem).unwrap();
        assert!(json.contains(r#""nrfId":"nrf-1""#));
        assert!(json.contains(r#""targetScp":"https://scp1.operator.com""#));
        assert!(json.contains(r#""targetSepp":"https://sepp1.operator.com""#));
        assert!(json.contains(r#""accessTokenRequest""#));

        // A spec example with the new members deserializes successfully.
        let parsed: ProblemDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.nrf_id.as_deref(), Some("nrf-1"));
        assert_eq!(
            parsed.target_scp.as_deref(),
            Some("https://scp1.operator.com")
        );
        assert_eq!(parsed.access_token_request.unwrap().nf_instance_id, "amf-1");

        // Unset members are skipped entirely.
        let bare = serde_json::to_string(&ProblemDetails::with_status(404)).unwrap();
        assert!(!bare.contains("nrfId"));
        assert!(!bare.contains("targetScp"));
        assert!(!bare.contains("targetSepp"));
        assert!(!bare.contains("accessTokenRequest"));
    }

    #[test]
    fn test_response_with_problem_content_type() {
        let problem = ProblemDetails::with_status(404).with_cause("RESOURCE_NOT_FOUND");
        let response = SbiResponse::new().with_problem(&problem);
        assert_eq!(response.status, 404);
        assert_eq!(
            response.http.get_header("content-type").map(String::as_str),
            Some(crate::constants::content_type::APPLICATION_PROBLEM_JSON)
        );
        assert!(response
            .http
            .content
            .unwrap()
            .contains("RESOURCE_NOT_FOUND"));
    }

    /// Issue #82: `with_hal_json_body` serves `application/3gppHal+json` for the
    /// handful of resources 3GPP declares HAL-only, and — the regression half —
    /// `with_json_body` still defaults to plain `application/json` for everything
    /// else. The HAL type is opt-in per call site precisely so this stays true.
    #[test]
    fn test_hal_json_body_is_opt_in_and_json_stays_the_default() {
        let body = serde_json::json!({ "authType": "5G_AKA", "_links": { "5g-aka": {} } });

        let hal = SbiResponse::with_status(201)
            .with_hal_json_body(&body)
            .expect("serializes");
        assert_eq!(
            hal.http.get_header("content-type").map(String::as_str),
            Some(crate::constants::content_type::APPLICATION_3GPP_HAL_JSON)
        );

        let plain = SbiResponse::with_status(200)
            .with_json_body(&body)
            .expect("serializes");
        assert_eq!(
            plain.http.get_header("content-type").map(String::as_str),
            Some(crate::constants::content_type::APPLICATION_JSON),
            "with_json_body must keep its application/json default"
        );

        // Only the media type differs; the serialized body is identical.
        assert_eq!(hal.http.content, plain.http.content);
    }
}
