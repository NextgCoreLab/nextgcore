//! SCP HTTP/2 Forwarding Engine (TS 29.500 §6.10)
//!
//! Real proxy data path for the SCP, replacing the former comment stubs in
//! `sbi_path.rs`:
//!
//! - **Model C** (indirect communication without delegated discovery): the
//!   consumer sets `3gpp-Sbi-Target-apiRoot`; the SCP opens an HTTP/2 client
//!   connection to that apiRoot and relays the request/response.
//! - **Model D** (indirect communication with delegated discovery): the
//!   consumer sets `3gpp-Sbi-Discovery-*` headers; the SCP queries the NRF
//!   (`nnrf-disc`), parses the SearchResult, selects a producer, forwards,
//!   and returns `3gpp-Sbi-Producer-Id` to the consumer.
//! - **Binding stickiness** (TS 29.500 §6.12): a `3gpp-Sbi-Binding` header on
//!   a producer response is cached; a later request carrying the same value
//!   in `3gpp-Sbi-Routing-Binding` is routed to the same producer without a
//!   new discovery.
//! - **Oci/Lci** (`3gpp-Sbi-Oci`, `3gpp-Sbi-Lci`) and all other end-to-end
//!   headers are propagated untouched in both directions.
//!
//! Header handling is case-insensitive throughout (hyper lowercases all
//! HTTP/2 header names on the wire). Hop-by-hop headers (RFC 9110 §7.6.1)
//! and the SCP-consumed `3gpp-Sbi-Target-apiRoot` / `3gpp-Sbi-Discovery-*` /
//! `3gpp-Sbi-Routing-Binding` headers are stripped before forwarding.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use ogs_sbi::client::{SbiClient, SbiClientConfig};
use ogs_sbi::constants::{custom_header, discovery_header};
use ogs_sbi::message::{ProblemDetails, SbiRequest, SbiResponse};
use ogs_sbi::types::UriScheme;
use ogs_sbi::SbiError;

use crate::sbi_path::{parse_search_result, select_nf_instance};

/// Default upstream connect timeout (bounded per TS 29.500 §6.11 guidance).
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Default upstream request timeout.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Hop-by-hop headers that must not be forwarded by a proxy
/// (RFC 9110 §7.6.1; `host`/`content-length` are recomputed by the client).
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

/// SCP proxy configuration.
#[derive(Debug, Clone)]
pub struct ScpProxyConfig {
    /// NRF base URI for Model D delegated discovery
    /// (e.g. `http://127.0.0.1:7777`). When unset, Model D requests are
    /// rejected with 503.
    pub nrf_uri: Option<String>,
    /// Upstream connect timeout.
    pub connect_timeout: Duration,
    /// Upstream request timeout.
    pub request_timeout: Duration,
}

impl Default for ScpProxyConfig {
    fn default() -> Self {
        Self {
            nrf_uri: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }
}

/// A parsed `apiRoot` per TS 29.501 §4.4.1:
/// `scheme://host[:port][/deployment-prefix]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiRoot {
    pub scheme: UriScheme,
    pub host: String,
    pub port: u16,
    /// Optional deployment-specific path prefix (leading `/`, no trailing).
    pub prefix: String,
}

impl ApiRoot {
    /// Parse an apiRoot URI. Rejects anything without an `http`/`https`
    /// scheme or with an empty/invalid authority.
    pub fn parse(uri: &str) -> Result<Self, String> {
        let uri = uri.trim();
        let (scheme, rest) = if let Some(rest) = uri.strip_prefix("https://") {
            (UriScheme::Https, rest)
        } else if let Some(rest) = uri.strip_prefix("http://") {
            (UriScheme::Http, rest)
        } else {
            return Err(format!("apiRoot has no http/https scheme: {uri}"));
        };

        let (authority, path) = match rest.split_once('/') {
            Some((a, p)) => (a, format!("/{p}")),
            None => (rest, String::new()),
        };
        if authority.is_empty() {
            return Err(format!("apiRoot has empty authority: {uri}"));
        }

        let (host, port) = match authority.rsplit_once(':') {
            // Avoid mis-parsing a bare IPv6 literal as host:port
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                let port: u16 = p
                    .parse()
                    .map_err(|_| format!("apiRoot has invalid port: {uri}"))?;
                (h.to_string(), port)
            }
            _ => {
                let default_port = match scheme {
                    UriScheme::Https => 443,
                    UriScheme::Http => 80,
                };
                (authority.to_string(), default_port)
            }
        };

        Ok(Self {
            scheme,
            host,
            port,
            prefix: path.trim_end_matches('/').to_string(),
        })
    }

    /// Canonical `scheme://host:port[/prefix]` form (used as client-cache and
    /// binding-cache value).
    pub fn to_uri(&self) -> String {
        format!("{}://{}:{}{}", self.scheme, self.host, self.port, self.prefix)
    }
}

/// Normalize a `3gpp-Sbi-Binding` / `3gpp-Sbi-Routing-Binding` value for use
/// as a cache key: lowercase with all whitespace removed, so
/// `bl=nf-instance; nfinst=X` and `BL=NF-INSTANCE;NFINST=X` match.
fn normalize_binding(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// True for header names a proxy must not forward, in either direction:
/// HTTP/2 pseudo-headers and RFC 9110 hop-by-hop headers.
fn is_hop_by_hop(name: &str) -> bool {
    name.starts_with(':')
        || HOP_BY_HOP_HEADERS
            .iter()
            .any(|h| name.eq_ignore_ascii_case(h))
}

/// True for request headers the SCP itself consumes and must strip before
/// forwarding to the producer (TS 29.500 §5.2.3.2.4 / §5.2.3.2.7 / §6.12).
fn is_scp_consumed(name: &str) -> bool {
    let lower_eq = |c: &str| name.eq_ignore_ascii_case(c);
    lower_eq(custom_header::TARGET_APIROOT)
        || lower_eq(custom_header::ROUTING_BINDING)
        || name
            .get(..discovery_header::PREFIX.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(discovery_header::PREFIX))
}

/// Copy request headers for forwarding: drops pseudo/hop-by-hop headers and
/// the SCP-consumed routing headers; everything else (including
/// `3gpp-Sbi-Oci`, `3gpp-Sbi-Lci`, `3gpp-Sbi-Binding`, `Authorization`, ...)
/// passes through untouched.
pub fn forwardable_request_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(k, _)| !is_hop_by_hop(k) && !is_scp_consumed(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Copy response headers for relaying back to the consumer: drops only
/// pseudo/hop-by-hop headers; `3gpp-Sbi-Binding`, `3gpp-Sbi-Oci`,
/// `3gpp-Sbi-Lci` and all other end-to-end headers are relayed untouched.
pub fn relayable_response_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(k, _)| !is_hop_by_hop(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Build a ProblemDetails error response (`application/problem+json`,
/// TS 29.500 §5.2.7).
fn problem_response(status: u16, title: &str, detail: &str, cause: &str) -> SbiResponse {
    let problem = ProblemDetails::with_status(status as i32)
        .with_title(title)
        .with_detail(detail)
        .with_cause(cause);
    SbiResponse::with_status(status).with_problem(&problem)
}

/// Map an upstream client error to the proxy error response:
/// timeout → 504 Gateway Timeout, anything else → 502 Bad Gateway.
fn upstream_error_response(target: &str, err: &SbiError) -> SbiResponse {
    match err {
        SbiError::Timeout => problem_response(
            504,
            "Gateway Timeout",
            &format!("Timeout forwarding request to {target}"),
            "TARGET_NF_NOT_REACHABLE",
        ),
        other => problem_response(
            502,
            "Bad Gateway",
            &format!("Failed to forward request to {target}: {other}"),
            "TARGET_NF_NOT_REACHABLE",
        ),
    }
}

/// How the proxy decided where to route a request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RouteDecision {
    /// Model C: `3gpp-Sbi-Target-apiRoot` was present.
    TargetApiRoot(ApiRoot),
    /// §6.12 stickiness: `3gpp-Sbi-Routing-Binding` matched a cached binding.
    StickyBinding(ApiRoot),
    /// Model D: delegated discovery is required.
    Discover,
    /// Neither Target-apiRoot, usable Routing-Binding, nor Discovery headers.
    Reject,
}

/// The SCP proxy: per-request async forwarding engine.
pub struct ScpProxy {
    config: ScpProxyConfig,
    /// HTTP/2 client cache keyed by `scheme://host:port`.
    clients: RwLock<HashMap<String, Arc<SbiClient>>>,
    /// Binding stickiness cache: normalized `3gpp-Sbi-Binding` value →
    /// producer apiRoot it was returned from (TS 29.500 §6.12).
    bindings: RwLock<HashMap<String, ApiRoot>>,
}

impl ScpProxy {
    pub fn new(config: ScpProxyConfig) -> Self {
        Self {
            config,
            clients: RwLock::new(HashMap::new()),
            bindings: RwLock::new(HashMap::new()),
        }
    }

    /// Look up a producer apiRoot previously learnt from a
    /// `3gpp-Sbi-Binding` response header.
    pub fn binding_lookup(&self, routing_binding: &str) -> Option<ApiRoot> {
        self.bindings
            .read()
            .ok()?
            .get(&normalize_binding(routing_binding))
            .cloned()
    }

    /// Record a `3gpp-Sbi-Binding` value from a producer response so later
    /// requests carrying it in `3gpp-Sbi-Routing-Binding` stick to the same
    /// producer.
    pub fn binding_store(&self, binding: &str, target: &ApiRoot) {
        if let Ok(mut map) = self.bindings.write() {
            map.insert(normalize_binding(binding), target.clone());
        }
    }

    /// Get or create a pooled HTTP/2 client for a target authority.
    fn client_for(&self, target: &ApiRoot) -> Arc<SbiClient> {
        let key = format!("{}://{}:{}", target.scheme, target.host, target.port);
        if let Ok(clients) = self.clients.read() {
            if let Some(client) = clients.get(&key) {
                return client.clone();
            }
        }
        let mut config = SbiClientConfig::new(target.host.clone(), target.port)
            .with_connect_timeout(self.config.connect_timeout)
            .with_request_timeout(self.config.request_timeout);
        config.scheme = target.scheme;
        let client = Arc::new(SbiClient::new(config));
        if let Ok(mut clients) = self.clients.write() {
            clients.insert(key, client.clone());
        }
        client
    }

    /// Decide how to route an incoming request (TS 29.500 §6.10.2):
    /// Target-apiRoot wins; otherwise a Routing-Binding that matches a cached
    /// Binding; otherwise delegated discovery when Discovery headers are
    /// present; otherwise the request is malformed.
    fn route(&self, request: &SbiRequest) -> RouteDecision {
        if let Some(api_root) = request.http.target_apiroot() {
            return match ApiRoot::parse(api_root) {
                Ok(target) => RouteDecision::TargetApiRoot(target),
                Err(_) => RouteDecision::Reject,
            };
        }

        if let Some(routing_binding) = request.http.routing_binding() {
            if let Some(target) = self.binding_lookup(routing_binding) {
                return RouteDecision::StickyBinding(target);
            }
        }

        let has_discovery = request.http.headers.keys().any(|k| {
            k.get(..discovery_header::PREFIX.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(discovery_header::PREFIX))
        });
        if has_discovery {
            RouteDecision::Discover
        } else {
            RouteDecision::Reject
        }
    }

    /// Model D delegated discovery (TS 29.500 §6.10.3, TS 29.510 §5.3.2):
    /// query the NRF's `nnrf-disc` service with the parameters carried in
    /// the `3gpp-Sbi-Discovery-*` request headers, parse the SearchResult,
    /// and select a producer. The requester identity comes from
    /// `3gpp-Sbi-Discovery-requester-nf-type` (NOT User-Agent).
    async fn discover(
        &self,
        request: &SbiRequest,
    ) -> Result<(ApiRoot, String /* producer NF instance id */), SbiResponse> {
        let target_nf_type = request
            .http
            .get_header(discovery_header::TARGET_NF_TYPE)
            .cloned()
            .ok_or_else(|| {
                problem_response(
                    400,
                    "Bad Request",
                    "3gpp-Sbi-Discovery-target-nf-type header is required for delegated discovery",
                    "MANDATORY_IE_MISSING",
                )
            })?;
        let requester_nf_type = request
            .http
            .get_header(discovery_header::REQUESTER_NF_TYPE)
            .cloned()
            .ok_or_else(|| {
                problem_response(
                    400,
                    "Bad Request",
                    "3gpp-Sbi-Discovery-requester-nf-type header is required for delegated discovery",
                    "MANDATORY_IE_MISSING",
                )
            })?;

        let nrf_uri = self.config.nrf_uri.as_deref().ok_or_else(|| {
            problem_response(
                503,
                "Service Unavailable",
                "SCP has no NRF configured for delegated discovery",
                "NRF_NOT_AVAILABLE",
            )
        })?;
        let nrf = ApiRoot::parse(nrf_uri).map_err(|e| {
            problem_response(
                503,
                "Service Unavailable",
                &format!("SCP NRF URI is invalid: {e}"),
                "NRF_NOT_AVAILABLE",
            )
        })?;

        let mut disc = SbiRequest::get(format!("{}/nnrf-disc/v1/nf-instances", nrf.prefix))
            .with_param("target-nf-type", target_nf_type)
            .with_param("requester-nf-type", requester_nf_type);
        if let Some(names) = request.http.get_header(discovery_header::SERVICE_NAMES) {
            disc = disc.with_param("service-names", names.clone());
        }
        if let Some(id) = request
            .http
            .get_header(discovery_header::TARGET_NF_INSTANCE_ID)
        {
            disc = disc.with_param("target-nf-instance-id", id.clone());
        }
        if let Some(id) = request
            .http
            .get_header(discovery_header::REQUESTER_NF_INSTANCE_ID)
        {
            disc = disc.with_param("requester-nf-instance-id", id.clone());
        }
        if let Some(dnn) = request.http.get_header(discovery_header::DNN) {
            disc = disc.with_param("dnn", dnn.clone());
        }
        if let Some(snssais) = request.http.get_header(discovery_header::SNSSAIS) {
            disc = disc.with_param("snssais", snssais.clone());
        }

        let response = self
            .client_for(&nrf)
            .send_request(disc)
            .await
            .map_err(|e| upstream_error_response(&nrf.to_uri(), &e))?;

        if response.status != 200 {
            return Err(problem_response(
                502,
                "Bad Gateway",
                &format!("NRF discovery failed with status {}", response.status),
                "NF_DISCOVERY_FAILURE",
            ));
        }

        let body = response.http.content.as_deref().unwrap_or("");
        let candidates = parse_search_result(body.as_bytes());
        let selected = select_nf_instance(&candidates).ok_or_else(|| {
            problem_response(
                502,
                "Bad Gateway",
                "NRF discovery returned no usable NF instance",
                "NF_DISCOVERY_FAILURE",
            )
        })?;

        let target = ApiRoot {
            scheme: UriScheme::Http,
            host: selected.host.clone(),
            port: selected.port,
            prefix: String::new(),
        };
        Ok((target, selected.nf_instance_id.clone()))
    }

    /// Forward a request to the selected producer and relay its response.
    ///
    /// Success and error (4xx/5xx) producer responses are both relayed
    /// verbatim — status, end-to-end headers, and body — so upstream
    /// ProblemDetails bodies reach the consumer unmodified. Only transport
    /// failures synthesize a 502/504 at the SCP.
    async fn forward(
        &self,
        request: &SbiRequest,
        target: &ApiRoot,
        producer_id: Option<&str>,
    ) -> SbiResponse {
        let mut fwd = SbiRequest::default();
        fwd.header.method = request.header.method.clone();
        fwd.header.uri = format!("{}{}", target.prefix, request.header.uri);
        fwd.http.params = request.http.params.clone();
        fwd.http.headers = forwardable_request_headers(&request.http.headers);
        fwd.http.content = request.http.content.clone();
        fwd.http.parts = request.http.parts.clone();

        let result = self.client_for(target).send_request(fwd).await;

        let upstream = match result {
            Ok(response) => response,
            Err(e) => return upstream_error_response(&target.to_uri(), &e),
        };

        // §6.12: learn the producer's Binding for later Routing-Binding
        // stickiness, and still relay the header to the consumer.
        if let Some(binding) = upstream.http.binding() {
            self.binding_store(binding, target);
        }

        let mut relayed = SbiResponse::with_status(upstream.status);
        relayed.http.headers = relayable_response_headers(&upstream.http.headers);
        relayed.http.content = upstream.http.content.clone();
        relayed.http.parts = upstream.http.parts.clone();

        // Model D: tell the consumer which producer was selected
        // (TS 29.500 §5.2.3.2.6).
        if let Some(id) = producer_id {
            if !id.is_empty() {
                relayed.http.set_header(custom_header::PRODUCER_ID, id);
            }
        }

        relayed
    }

    /// Handle one inbound SBI request end-to-end (the server handler entry
    /// point).
    pub async fn handle(&self, request: SbiRequest) -> SbiResponse {
        match self.route(&request) {
            RouteDecision::TargetApiRoot(target) => {
                log::debug!(
                    "SCP Model C: {} {} -> {}",
                    request.header.method,
                    request.header.uri,
                    target.to_uri()
                );
                self.forward(&request, &target, None).await
            }
            RouteDecision::StickyBinding(target) => {
                log::debug!(
                    "SCP binding stickiness: {} {} -> {}",
                    request.header.method,
                    request.header.uri,
                    target.to_uri()
                );
                self.forward(&request, &target, None).await
            }
            RouteDecision::Discover => match self.discover(&request).await {
                Ok((target, producer_id)) => {
                    log::debug!(
                        "SCP Model D: {} {} -> {} (producer {})",
                        request.header.method,
                        request.header.uri,
                        target.to_uri(),
                        producer_id
                    );
                    self.forward(&request, &target, Some(&producer_id)).await
                }
                Err(error_response) => error_response,
            },
            RouteDecision::Reject => problem_response(
                400,
                "Bad Request",
                "Request carries neither a valid 3gpp-Sbi-Target-apiRoot, a known \
                 3gpp-Sbi-Routing-Binding, nor 3gpp-Sbi-Discovery-* headers",
                "MANDATORY_IE_MISSING",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};

    // ------------------------------------------------------------------
    // Unit tests: parsing, header stripping, binding normalization
    // ------------------------------------------------------------------

    #[test]
    fn test_apiroot_parse_variants() {
        let r = ApiRoot::parse("http://10.0.0.1:7778").unwrap();
        assert_eq!(r.scheme, UriScheme::Http);
        assert_eq!(r.host, "10.0.0.1");
        assert_eq!(r.port, 7778);
        assert_eq!(r.prefix, "");

        let r = ApiRoot::parse("https://udm.5gc.example.org").unwrap();
        assert_eq!(r.scheme, UriScheme::Https);
        assert_eq!(r.port, 443);

        let r = ApiRoot::parse("http://smf.local").unwrap();
        assert_eq!(r.port, 80);

        let r = ApiRoot::parse("http://nrf:7777/prefix/a/").unwrap();
        assert_eq!(r.prefix, "/prefix/a");
        assert_eq!(r.to_uri(), "http://nrf:7777/prefix/a");

        assert!(ApiRoot::parse("ftp://x:21").is_err());
        assert!(ApiRoot::parse("no-scheme").is_err());
        assert!(ApiRoot::parse("http://").is_err());
        // A numeric port that overflows u16 is rejected; a non-numeric
        // ":suffix" is treated as part of the (opaque) host, default port.
        assert!(ApiRoot::parse("http://h:99999").is_err());
        assert_eq!(ApiRoot::parse("http://h:notaport").unwrap().port, 80);
    }

    #[test]
    fn test_forwardable_request_headers_strip() {
        let mut headers = HashMap::new();
        headers.insert(":authority".to_string(), "scp:7777".to_string());
        headers.insert("connection".to_string(), "keep-alive".to_string());
        headers.insert("Transfer-Encoding".to_string(), "chunked".to_string());
        headers.insert("content-length".to_string(), "42".to_string());
        headers.insert(
            "3gpp-sbi-target-apiroot".to_string(),
            "http://udm:7777".to_string(),
        );
        // Case-variant SCP-consumed headers must also be stripped
        // (hyper lowercases on the wire, but in-process casing varies).
        headers.insert(
            "3GPP-SBI-DISCOVERY-TARGET-NF-TYPE".to_string(),
            "UDM".to_string(),
        );
        headers.insert(
            "3gpp-Sbi-Routing-Binding".to_string(),
            "bl=nf-instance; nfinst=x".to_string(),
        );
        // End-to-end headers must pass through untouched.
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("3gpp-sbi-oci".to_string(), "Timestamp: x; oci".to_string());
        headers.insert("3gpp-Sbi-Lci".to_string(), "Timestamp: y; lci".to_string());
        headers.insert("authorization".to_string(), "Bearer tok".to_string());

        let fwd = forwardable_request_headers(&headers);
        assert!(!fwd.keys().any(|k| k.starts_with(':')));
        assert!(!fwd.contains_key("connection"));
        assert!(!fwd.contains_key("Transfer-Encoding"));
        assert!(!fwd.contains_key("content-length"));
        assert!(!fwd.contains_key("3gpp-sbi-target-apiroot"));
        assert!(!fwd.contains_key("3GPP-SBI-DISCOVERY-TARGET-NF-TYPE"));
        assert!(!fwd.contains_key("3gpp-Sbi-Routing-Binding"));
        assert_eq!(fwd.get("content-type").map(String::as_str), Some("application/json"));
        assert_eq!(fwd.get("3gpp-sbi-oci").map(String::as_str), Some("Timestamp: x; oci"));
        assert_eq!(fwd.get("3gpp-Sbi-Lci").map(String::as_str), Some("Timestamp: y; lci"));
        assert_eq!(fwd.get("authorization").map(String::as_str), Some("Bearer tok"));
    }

    #[test]
    fn test_relayable_response_headers_keep_sbi_custom() {
        let mut headers = HashMap::new();
        headers.insert("connection".to_string(), "close".to_string());
        headers.insert("content-length".to_string(), "10".to_string());
        headers.insert(
            "3gpp-sbi-binding".to_string(),
            "bl=nf-instance; nfinst=abc".to_string(),
        );
        headers.insert("3gpp-sbi-oci".to_string(), "oci-val".to_string());
        headers.insert("3gpp-sbi-lci".to_string(), "lci-val".to_string());

        let relayed = relayable_response_headers(&headers);
        assert!(!relayed.contains_key("connection"));
        assert!(!relayed.contains_key("content-length"));
        // Binding/Oci/Lci are end-to-end: relayed untouched.
        assert_eq!(
            relayed.get("3gpp-sbi-binding").map(String::as_str),
            Some("bl=nf-instance; nfinst=abc")
        );
        assert_eq!(relayed.get("3gpp-sbi-oci").map(String::as_str), Some("oci-val"));
        assert_eq!(relayed.get("3gpp-sbi-lci").map(String::as_str), Some("lci-val"));
    }

    #[test]
    fn test_normalize_binding_and_cache() {
        assert_eq!(
            normalize_binding("BL=NF-Instance; NFINST=54804518"),
            "bl=nf-instance;nfinst=54804518"
        );

        let proxy = ScpProxy::new(ScpProxyConfig::default());
        let target = ApiRoot::parse("http://smf1:7778").unwrap();
        proxy.binding_store("bl=nf-instance; nfinst=54804518", &target);
        // Lookup with different casing/whitespace still hits.
        let hit = proxy.binding_lookup("BL=nf-instance;NFINST=54804518").unwrap();
        assert_eq!(hit, target);
        assert!(proxy.binding_lookup("bl=nf-set;nfset=other").is_none());
    }

    #[test]
    fn test_route_decision_priority() {
        let proxy = ScpProxy::new(ScpProxyConfig::default());

        // Target-apiRoot wins even when discovery headers are present.
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http.set_target_apiroot("http://udm:7777");
        req.http
            .set_header(discovery_header::TARGET_NF_TYPE, "UDM");
        assert!(matches!(
            proxy.route(&req),
            RouteDecision::TargetApiRoot(_)
        ));

        // Discovery headers alone -> Discover.
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http
            .set_header(discovery_header::TARGET_NF_TYPE, "UDM");
        assert_eq!(proxy.route(&req), RouteDecision::Discover);

        // Unknown Routing-Binding with no discovery headers -> Reject.
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http.set_routing_binding("bl=nf-instance; nfinst=unknown");
        assert_eq!(proxy.route(&req), RouteDecision::Reject);

        // Known Routing-Binding -> StickyBinding.
        let target = ApiRoot::parse("http://udm2:7777").unwrap();
        proxy.binding_store("bl=nf-instance; nfinst=known", &target);
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http.set_routing_binding("bl=nf-instance; nfinst=known");
        assert!(matches!(proxy.route(&req), RouteDecision::StickyBinding(t) if t == target));

        // Nothing at all -> Reject.
        let req = SbiRequest::get("/nudm-sdm/v1/x");
        assert_eq!(proxy.route(&req), RouteDecision::Reject);
    }

    // ------------------------------------------------------------------
    // Strict-peer tests: missing mandatory headers -> 400 ProblemDetails
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_reject_without_routing_headers_is_400_problem() {
        let proxy = ScpProxy::new(ScpProxyConfig::default());
        let response = proxy.handle(SbiRequest::get("/nudm-sdm/v1/x")).await;
        assert_eq!(response.status, 400);
        assert_eq!(
            response.http.get_header("content-type").map(String::as_str),
            Some("application/problem+json")
        );
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.status, Some(400));
        assert_eq!(problem.cause.as_deref(), Some("MANDATORY_IE_MISSING"));
    }

    #[tokio::test]
    async fn test_discovery_missing_requester_nf_type_is_400() {
        let proxy = ScpProxy::new(ScpProxyConfig {
            nrf_uri: Some("http://127.0.0.1:1".into()),
            ..Default::default()
        });
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http
            .set_header(discovery_header::TARGET_NF_TYPE, "UDM");
        let response = proxy.handle(req).await;
        assert_eq!(response.status, 400);
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("MANDATORY_IE_MISSING"));
        assert!(problem
            .detail
            .as_deref()
            .unwrap()
            .contains("requester-nf-type"));
    }

    #[tokio::test]
    async fn test_discovery_without_nrf_configured_is_503() {
        let proxy = ScpProxy::new(ScpProxyConfig::default());
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http
            .set_header(discovery_header::TARGET_NF_TYPE, "UDM");
        req.http
            .set_header(discovery_header::REQUESTER_NF_TYPE, "AMF");
        let response = proxy.handle(req).await;
        assert_eq!(response.status, 503);
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("NRF_NOT_AVAILABLE"));
    }

    #[tokio::test]
    async fn test_invalid_target_apiroot_is_400() {
        let proxy = ScpProxy::new(ScpProxyConfig::default());
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http.set_target_apiroot("not-a-uri");
        let response = proxy.handle(req).await;
        assert_eq!(response.status, 400);
    }

    // ------------------------------------------------------------------
    // HTTP-level integration tests: real HTTP/2 hops through the SCP
    // (ephemeral ports, bounded timeouts, fully async — no blocking threads)
    // ------------------------------------------------------------------

    /// Reserve an ephemeral localhost port.
    fn ephemeral_port() -> u16 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        port
    }

    /// Start a mock producer that echoes the request (method, uri, body and
    /// selected headers) as JSON and returns Binding/Oci headers.
    async fn start_mock_producer(port: u16) -> ogs_sbi::server::SbiServer {
        let server = ogs_sbi::server::SbiServer::new(ogs_sbi::server::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
        ));
        server
            .start(|request: SbiRequest| async move {
                let echoed = serde_json::json!({
                    "method": request.header.method,
                    "uri": request.header.uri,
                    "body": request.http.content,
                    "sawTargetApiroot": request.http.target_apiroot().is_some(),
                    "sawDiscovery": request.http.headers.keys()
                        .any(|k| k.to_ascii_lowercase().starts_with("3gpp-sbi-discovery-")),
                    "sawRoutingBinding": request.http.routing_binding().is_some(),
                    "oci": request.http.get_header("3gpp-Sbi-Oci"),
                    "lci": request.http.get_header("3gpp-Sbi-Lci"),
                    "param": request.http.get_param("k"),
                });
                SbiResponse::ok()
                    .with_body(echoed.to_string(), "application/json")
                    .with_header("3gpp-Sbi-Binding", "bl=nf-instance; nfinst=producer-1")
                    .with_header("3gpp-Sbi-Oci", "producer-oci")
                    .with_header("3gpp-Sbi-Lci", "producer-lci")
            })
            .await
            .expect("producer start");
        server
    }

    /// Start the SCP itself: an SbiServer fronting a ScpProxy.
    async fn start_scp(port: u16, config: ScpProxyConfig) -> ogs_sbi::server::SbiServer {
        let proxy = Arc::new(ScpProxy::new(config));
        let server = ogs_sbi::server::SbiServer::new(ogs_sbi::server::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
        ));
        server
            .start(move |request: SbiRequest| {
                let proxy = proxy.clone();
                async move { proxy.handle(request).await }
            })
            .await
            .expect("scp start");
        server
    }

    fn fast_client(port: u16) -> SbiClient {
        SbiClient::new(
            SbiClientConfig::new("127.0.0.1", port)
                .with_connect_timeout(Duration::from_secs(2))
                .with_request_timeout(Duration::from_secs(5)),
        )
    }

    #[tokio::test]
    async fn test_model_c_forwarding_end_to_end() {
        let producer_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let producer = start_mock_producer(producer_port).await;
        let scp = start_scp(scp_port, ScpProxyConfig::default()).await;

        let request = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_body(r#"{"hello":"world"}"#, "application/json")
            .with_param("k", "v")
            .with_header(
                "3gpp-Sbi-Target-apiRoot",
                format!("http://127.0.0.1:{producer_port}"),
            )
            .with_header("3gpp-Sbi-Oci", "consumer-oci")
            .with_header("3gpp-Sbi-Lci", "consumer-lci");

        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("model C roundtrip");

        assert_eq!(response.status, 200);
        let echoed: serde_json::Value = response.json_body().unwrap();
        // Method, path, query and body all relayed.
        assert_eq!(echoed["method"], "POST");
        assert_eq!(echoed["uri"], "/nudm-uecm/v1/registrations");
        assert_eq!(echoed["body"], r#"{"hello":"world"}"#);
        assert_eq!(echoed["param"], "v");
        // SCP-consumed header stripped before the producer saw it.
        assert_eq!(echoed["sawTargetApiroot"], false);
        // Oci/Lci propagated untouched to the producer...
        assert_eq!(echoed["oci"], "consumer-oci");
        assert_eq!(echoed["lci"], "consumer-lci");
        // ...and from the producer back to the consumer.
        assert_eq!(
            response.http.get_header("3gpp-Sbi-Oci").map(String::as_str),
            Some("producer-oci")
        );
        assert_eq!(
            response.http.get_header("3gpp-Sbi-Lci").map(String::as_str),
            Some("producer-lci")
        );
        // The producer's Binding header is relayed to the consumer.
        assert_eq!(
            response.http.binding().map(String::as_str),
            Some("bl=nf-instance; nfinst=producer-1")
        );
        // Model C adds no Producer-Id.
        assert!(response.http.producer_id().is_none());

        scp.stop().await.expect("scp stop");
        producer.stop().await.expect("producer stop");
    }

    /// Start a mock NRF whose nnrf-disc answers with a single-producer
    /// SearchResult, counting how many discovery queries it served.
    async fn start_mock_nrf(
        port: u16,
        producer_port: u16,
        hits: Arc<AtomicU64>,
    ) -> ogs_sbi::server::SbiServer {
        let server = ogs_sbi::server::SbiServer::new(ogs_sbi::server::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
        ));
        server
            .start(move |request: SbiRequest| {
                let hits = hits.clone();
                async move {
                    assert_eq!(request.header.uri, "/nnrf-disc/v1/nf-instances");
                    // The SCP must put the requester identity from the
                    // Discovery-requester-nf-type header into the query.
                    assert_eq!(
                        request.http.get_param("target-nf-type").map(String::as_str),
                        Some("UDM")
                    );
                    assert_eq!(
                        request
                            .http
                            .get_param("requester-nf-type")
                            .map(String::as_str),
                        Some("AMF")
                    );
                    hits.fetch_add(1, Ordering::SeqCst);
                    let search_result = serde_json::json!({
                        "validityPeriod": 3600,
                        "nfInstances": [{
                            "nfInstanceId": "udm-instance-1",
                            "nfType": "UDM",
                            "nfStatus": "REGISTERED",
                            "ipv4Addresses": ["127.0.0.1"],
                            "priority": 1,
                            "capacity": 100,
                            "load": 0,
                            "nfServices": [{
                                "serviceInstanceId": "nudm-uecm-1",
                                "serviceName": "nudm-uecm",
                                "ipEndPoints": [{"ipv4Address": "127.0.0.1", "port": producer_port}]
                            }]
                        }]
                    });
                    SbiResponse::ok().with_body(search_result.to_string(), "application/json")
                }
            })
            .await
            .expect("nrf start");
        server
    }

    #[tokio::test]
    async fn test_model_d_discovery_forwarding_and_binding_stickiness() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let nrf_hits = Arc::new(AtomicU64::new(0));

        let producer = start_mock_producer(producer_port).await;
        let nrf = start_mock_nrf(nrf_port, producer_port, nrf_hits.clone()).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                ..Default::default()
            },
        )
        .await;

        // --- Model D: delegated discovery ---
        let request = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_body(r#"{"amf":"reg"}"#, "application/json")
            .with_header("3gpp-Sbi-Discovery-target-nf-type", "UDM")
            .with_header("3gpp-Sbi-Discovery-requester-nf-type", "AMF")
            .with_header("3gpp-Sbi-Discovery-service-names", "nudm-uecm");

        let client = fast_client(scp_port);
        let response = client.send_request(request).await.expect("model D roundtrip");

        assert_eq!(response.status, 200);
        assert_eq!(nrf_hits.load(Ordering::SeqCst), 1);
        // Producer-Id of the selected producer is returned to the consumer.
        assert_eq!(
            response.http.producer_id().map(String::as_str),
            Some("udm-instance-1")
        );
        let echoed: serde_json::Value = response.json_body().unwrap();
        assert_eq!(echoed["body"], r#"{"amf":"reg"}"#);
        // Discovery headers were consumed by the SCP, not forwarded.
        assert_eq!(echoed["sawDiscovery"], false);
        // Producer announced its Binding; SCP relays it.
        let binding = response.http.binding().cloned().expect("binding relayed");

        // --- §6.12 stickiness: Routing-Binding routes without rediscovery ---
        let sticky = SbiRequest::get("/nudm-uecm/v1/registrations/1")
            .with_header("3gpp-Sbi-Routing-Binding", binding);
        let response = client.send_request(sticky).await.expect("sticky roundtrip");
        assert_eq!(response.status, 200);
        let echoed: serde_json::Value = response.json_body().unwrap();
        assert_eq!(echoed["uri"], "/nudm-uecm/v1/registrations/1");
        // Routing-Binding was consumed by the SCP, not forwarded.
        assert_eq!(echoed["sawRoutingBinding"], false);
        // No new NRF discovery happened.
        assert_eq!(nrf_hits.load(Ordering::SeqCst), 1);

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    #[tokio::test]
    async fn test_upstream_error_body_is_preserved() {
        // A producer that always answers 409 with a ProblemDetails body:
        // the SCP must relay it verbatim, not replace it.
        let producer_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let server = ogs_sbi::server::SbiServer::new(ogs_sbi::server::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], producer_port)),
        ));
        server
            .start(|_request: SbiRequest| async move {
                SbiResponse::with_status(409).with_body(
                    r#"{"status":409,"cause":"DUPLICATE_REGISTRATION"}"#,
                    "application/problem+json",
                )
            })
            .await
            .expect("producer start");
        let scp = start_scp(scp_port, ScpProxyConfig::default()).await;

        let request = SbiRequest::post("/nudm-uecm/v1/registrations").with_header(
            "3gpp-Sbi-Target-apiRoot",
            format!("http://127.0.0.1:{producer_port}"),
        );
        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("error relay roundtrip");

        assert_eq!(response.status, 409);
        assert!(response
            .http
            .content
            .as_deref()
            .unwrap()
            .contains("DUPLICATE_REGISTRATION"));

        scp.stop().await.expect("scp stop");
        server.stop().await.expect("producer stop");
    }

    #[tokio::test]
    async fn test_unreachable_target_is_502_problem() {
        // Port 1 on localhost refuses connections immediately.
        let proxy = ScpProxy::new(ScpProxyConfig {
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_millis(500),
            ..Default::default()
        });
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http.set_target_apiroot("http://127.0.0.1:1");
        let response = proxy.handle(req).await;
        assert_eq!(response.status, 502);
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("TARGET_NF_NOT_REACHABLE"));
    }

    #[tokio::test]
    async fn test_slow_producer_is_504_within_bounded_timeout() {
        // A producer that never answers within the SCP's request timeout.
        let producer_port = ephemeral_port();
        let server = ogs_sbi::server::SbiServer::new(ogs_sbi::server::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], producer_port)),
        ));
        server
            .start(|_request: SbiRequest| async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                SbiResponse::ok()
            })
            .await
            .expect("producer start");

        let proxy = ScpProxy::new(ScpProxyConfig {
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_millis(300),
            ..Default::default()
        });
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http
            .set_target_apiroot(format!("http://127.0.0.1:{producer_port}"));

        let started = std::time::Instant::now();
        let response = proxy.handle(req).await;
        assert_eq!(response.status, 504);
        // Bounded: the proxy gave up at its request timeout, not the
        // producer's sleep.
        assert!(started.elapsed() < Duration::from_secs(3));
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("TARGET_NF_NOT_REACHABLE"));

        server.stop().await.expect("producer stop");
    }

    #[tokio::test]
    async fn test_nrf_returning_no_candidates_is_502() {
        let nrf_port = ephemeral_port();
        let server = ogs_sbi::server::SbiServer::new(ogs_sbi::server::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], nrf_port)),
        ));
        server
            .start(|_request: SbiRequest| async move {
                SbiResponse::ok().with_body(r#"{"nfInstances":[]}"#, "application/json")
            })
            .await
            .expect("nrf start");

        let proxy = ScpProxy::new(ScpProxyConfig {
            nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_millis(500),
        });
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http
            .set_header(discovery_header::TARGET_NF_TYPE, "UDM");
        req.http
            .set_header(discovery_header::REQUESTER_NF_TYPE, "AMF");
        let response = proxy.handle(req).await;
        assert_eq!(response.status, 502);
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("NF_DISCOVERY_FAILURE"));

        server.stop().await.expect("nrf stop");
    }
}
