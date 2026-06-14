//! SBI HTTP/2 Client
//!
//! HTTP/2 client implementation using hyper for SBI communication.
//! Matches the interface in lib/sbi/client.h

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http2::SendRequest;
use hyper::{Method, Request, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

use crate::error::{SbiError, SbiResult};
use crate::message::{SbiRequest, SbiResponse};
use crate::oauth::OAuth2Client;
use crate::tls;
use crate::types::{NfType, UriScheme};

/// Generate a simple 8-byte span ID from the current timestamp nanoseconds.
/// In production this would use the OTel SDK's span ID generator.
fn new_span_id() -> [u8; 8] {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("value expected")
        .as_nanos() as u64;
    ns.to_be_bytes()
}

/// Default connection timeout in seconds
const DEFAULT_CONNECT_TIMEOUT: u64 = 5;
/// Default request timeout in seconds
const DEFAULT_REQUEST_TIMEOUT: u64 = 30;
/// Default number of pooled HTTP/2 connections per target.
///
/// Each connection multiplexes many concurrent streams, so a small pool is
/// plenty. The pool's purpose is not raw stream throughput (HTTP/2 already
/// multiplexes) but to ensure a (re)connect on one slot does not serialize
/// every concurrent request behind a single mutex during connection churn.
const DEFAULT_POOL_SIZE: usize = 4;

/// SBI Client configuration
#[derive(Debug, Clone)]
pub struct SbiClientConfig {
    /// URI scheme (http or https)
    pub scheme: UriScheme,
    /// Target host (FQDN or IP)
    pub host: String,
    /// Target port
    pub port: u16,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Request timeout
    pub request_timeout: Duration,
    /// Skip TLS verification (for testing)
    pub insecure_skip_verify: bool,
    /// CA certificate path
    pub ca_cert: Option<String>,
    /// Client certificate path
    pub client_cert: Option<String>,
    /// Client private key path
    pub client_key: Option<String>,
    /// Number of pooled HTTP/2 connections to the target (min 1).
    pub pool_size: usize,
}

impl Default for SbiClientConfig {
    fn default() -> Self {
        Self {
            scheme: UriScheme::Http,
            host: "localhost".to_string(),
            port: 80,
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT),
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT),
            insecure_skip_verify: false,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            pool_size: DEFAULT_POOL_SIZE,
        }
    }
}

impl SbiClientConfig {
    /// Create a new client configuration
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            ..Default::default()
        }
    }

    /// Set the URI scheme
    pub fn with_scheme(mut self, scheme: UriScheme) -> Self {
        self.scheme = scheme;
        self
    }

    /// Set HTTPS scheme
    pub fn with_https(mut self) -> Self {
        self.scheme = UriScheme::Https;
        self
    }

    /// Set connection timeout
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set request timeout
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Set the connection pool size (clamped to a minimum of 1).
    pub fn with_pool_size(mut self, pool_size: usize) -> Self {
        self.pool_size = pool_size.max(1);
        self
    }

    /// Build the base URI
    pub fn base_uri(&self) -> String {
        format!("{}://{}:{}", self.scheme, self.host, self.port)
    }
}

/// Connection state for HTTP/2
struct ConnectionState {
    sender: SendRequest<Full<Bytes>>,
}

/// SBI Client - HTTP/2 client for SBI communication
/// Matches ogs_sbi_client_t
pub struct SbiClient {
    /// Client configuration
    config: SbiClientConfig,
    /// Pool of lazily-initialized HTTP/2 connections. Each slot is an
    /// independent multiplexed connection; requests round-robin across slots so
    /// a (re)connect on one slot does not block requests routed to others.
    pool: Arc<Vec<Mutex<Option<ConnectionState>>>>,
    /// Round-robin cursor for slot selection.
    next_slot: Arc<AtomicUsize>,
    /// OAuth2 client for automatic token attachment
    oauth2: Option<Arc<OAuth2Client>>,
    /// Target NF type for OAuth2 scope resolution
    target_nf_type: Option<NfType>,
}

impl SbiClient {
    /// Create a new SBI client
    pub fn new(config: SbiClientConfig) -> Self {
        let pool_size = config.pool_size.max(1);
        let pool = (0..pool_size).map(|_| Mutex::new(None)).collect();
        Self {
            config,
            pool: Arc::new(pool),
            next_slot: Arc::new(AtomicUsize::new(0)),
            oauth2: None,
            target_nf_type: None,
        }
    }

    /// Create a client with host and port
    pub fn with_host_port(host: impl Into<String>, port: u16) -> Self {
        Self::new(SbiClientConfig::new(host, port))
    }

    /// Attach an OAuth2 client for automatic Bearer token attachment.
    ///
    /// When set, the client will request a token from the NRF before each
    /// SBI request that does not already carry an Authorization header.
    pub fn with_oauth2(mut self, oauth2: Arc<OAuth2Client>, target_nf_type: NfType) -> Self {
        self.oauth2 = Some(oauth2);
        self.target_nf_type = Some(target_nf_type);
        self
    }

    /// Get the client configuration
    pub fn config(&self) -> &SbiClientConfig {
        &self.config
    }

    /// Build a TLS connector from the client config
    fn build_tls_connector(&self) -> SbiResult<TlsConnector> {
        let client_config = if let (Some(cert_path), Some(key_path)) =
            (&self.config.client_cert, &self.config.client_key)
        {
            // mTLS: client certificate authentication
            let certs = tls::load_certs(cert_path)?;
            let key = tls::load_private_key(key_path)?;
            tls::build_client_config_mtls(
                certs,
                key,
                self.config.ca_cert.as_deref(),
                self.config.insecure_skip_verify,
            )?
        } else {
            tls::build_client_config(
                self.config.ca_cert.as_deref(),
                self.config.insecure_skip_verify,
            )?
        };

        Ok(TlsConnector::from(Arc::new(client_config)))
    }

    /// Connect to the server
    async fn connect(&self) -> SbiResult<SendRequest<Full<Bytes>>> {
        let addr = format!("{}:{}", self.config.host, self.config.port);

        let stream = tokio::time::timeout(self.config.connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| SbiError::Timeout)?
            .map_err(|e| SbiError::ConnectionError(e.to_string()))?;

        if self.config.scheme == UriScheme::Https {
            let connector = self.build_tls_connector()?;
            let server_name = ServerName::try_from(self.config.host.clone())
                .map_err(|e| SbiError::TlsError(format!("Invalid server name: {e}")))?;

            let tls_stream = tokio::time::timeout(
                self.config.connect_timeout,
                connector.connect(server_name, stream),
            )
            .await
            .map_err(|_| SbiError::Timeout)?
            .map_err(|e| SbiError::TlsError(format!("TLS handshake failed: {e}")))?;

            let io = TokioIo::new(tls_stream);

            let (sender, conn) =
                hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                    .await
                    .map_err(|e| SbiError::ConnectionError(e.to_string()))?;

            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    eprintln!("HTTP/2 TLS connection error: {e}");
                }
            });

            Ok(sender)
        } else {
            let io = TokioIo::new(stream);

            let (sender, conn) =
                hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                    .await
                    .map_err(|e| SbiError::ConnectionError(e.to_string()))?;

            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    eprintln!("HTTP/2 connection error: {e}");
                }
            });

            Ok(sender)
        }
    }

    /// Get or create a connection from the pool.
    ///
    /// Picks a slot round-robin, reuses its cached multiplexed connection when
    /// the sender is still ready, and otherwise (re)connects that slot. Only the
    /// chosen slot's mutex is held across the connect, so concurrent requests
    /// routed to other slots are not blocked during connection establishment.
    async fn get_connection(&self) -> SbiResult<SendRequest<Full<Bytes>>> {
        let slot = self.next_slot.fetch_add(1, Ordering::Relaxed) % self.pool.len();
        let mut conn_guard = self.pool[slot].lock().await;

        if let Some(ref state) = *conn_guard {
            if state.sender.is_ready() {
                return Ok(state.sender.clone());
            }
        }

        // Slot empty or its connection is no longer usable — (re)connect it.
        let sender = self.connect().await?;
        *conn_guard = Some(ConnectionState {
            sender: sender.clone(),
        });
        Ok(sender)
    }

    /// Send an SBI request and receive a response
    pub async fn send_request(&self, mut request: SbiRequest) -> SbiResult<SbiResponse> {
        // Automatically attach Bearer token if OAuth2 is configured
        // and the request does not already carry an Authorization header
        if let (Some(oauth2), Some(target_nf_type)) = (&self.oauth2, &self.target_nf_type) {
            // get_header() is case-insensitive: an "authorization" header
            // copied from a hyper (lowercased HTTP/2) message also counts.
            if request.http.get_header("Authorization").is_none() {
                // Derive scope from the request URI service name
                let scope = derive_scope_from_uri(&request.header.uri);
                if !scope.is_empty() {
                    match oauth2.authorization_header(*target_nf_type, &scope).await {
                        Ok(auth_value) => {
                            request.http.set_header("Authorization", auth_value);
                        }
                        Err(e) => {
                            log::warn!("OAuth2 token request failed, sending without token: {e}");
                        }
                    }
                }
            }
        }

        // G32/G43: Propagate W3C traceparent header for distributed tracing.
        // If the incoming request already carries a traceparent (set by caller)
        // we respect it; otherwise we generate a new child span.
        if request.http.get_header("traceparent").is_none() {
            // Generate a minimal traceparent from thread-local trace context.
            // If no ambient trace context is set we start a new trace with a
            // sampled root span (flags=01).
            let trace_id: [u8; 16] = {
                let ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("value expected")
                    .as_nanos();
                ns.to_be_bytes()
            };
            let span_id = new_span_id();
            let traceparent = format!("00-{}-{}-01", hex::encode(trace_id), hex::encode(span_id),);
            request.http.set_header("traceparent", traceparent);
        }

        let mut sender = self.get_connection().await?;

        // Build the URI
        let uri_str = if request.header.uri.starts_with("http") {
            request.header.uri.clone()
        } else {
            format!("{}{}", self.config.base_uri(), request.header.uri)
        };

        // Add query parameters
        let uri_with_params = if request.http.params.is_empty() {
            uri_str
        } else {
            let params: Vec<String> = request
                .http
                .params
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            format!("{}?{}", uri_str, params.join("&"))
        };

        let uri: Uri = uri_with_params
            .parse()
            .map_err(|e| SbiError::InvalidUri(format!("{uri_with_params}: {e}")))?;

        // Build the HTTP method
        let method = match request.header.method.to_uppercase().as_str() {
            "GET" => Method::GET,
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "DELETE" => Method::DELETE,
            "PATCH" => Method::PATCH,
            "OPTIONS" => Method::OPTIONS,
            other => return Err(SbiError::InvalidMethod(other.to_string())),
        };

        // Build the request body. Binary N1/N2 parts are encoded as
        // multipart/related with the JSON content as the root part
        // (TS 29.500 §6.1.2.3).
        let body_bytes: Bytes = if !request.http.parts.is_empty() {
            let boundary = crate::multipart::generate_boundary();
            request.http.set_header(
                crate::constants::header::CONTENT_TYPE,
                crate::multipart::content_type_with_boundary(&boundary),
            );
            Bytes::from(crate::multipart::encode(
                request.http.content.as_deref(),
                &request.http.parts,
                &boundary,
            ))
        } else {
            request
                .http
                .content
                .as_deref()
                .map(|c| Bytes::from(c.to_owned()))
                .unwrap_or_default()
        };
        let body = Full::new(body_bytes);

        // Build the HTTP request
        let mut req_builder = Request::builder().method(method).uri(uri);

        // Add headers
        for (key, value) in &request.http.headers {
            req_builder = req_builder.header(key.as_str(), value.as_str());
        }

        let http_request = req_builder
            .body(body)
            .map_err(|e| SbiError::ClientError(e.to_string()))?;

        // Send the request with timeout
        let response = tokio::time::timeout(
            self.config.request_timeout,
            sender.send_request(http_request),
        )
        .await
        .map_err(|_| SbiError::Timeout)?
        .map_err(|e| SbiError::HyperError(e.to_string()))?;

        // Convert to SbiResponse
        self.convert_response(response).await
    }

    /// Convert hyper response to SbiResponse
    async fn convert_response(
        &self,
        response: hyper::Response<Incoming>,
    ) -> SbiResult<SbiResponse> {
        let status = response.status().as_u16();

        // Extract headers
        let mut headers = HashMap::new();
        for (key, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                headers.insert(key.to_string(), v.to_string());
            }
        }

        // Read body
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| SbiError::InvalidResponse(e.to_string()))?
            .to_bytes();

        let mut sbi_response = SbiResponse::with_status(status);
        sbi_response.http.headers = headers;

        // multipart/related responses (N1/N2 binary containers, TS 29.500
        // §6.1.2.3) are decoded into the JSON root + binary parts before any
        // UTF-8 conversion so binary content survives byte-exact.
        if !body_bytes.is_empty() {
            let multipart_content_type = sbi_response
                .http
                .get_header(crate::constants::header::CONTENT_TYPE)
                .filter(|ct| crate::multipart::is_multipart_related(ct))
                .cloned();
            match multipart_content_type {
                Some(ct) => {
                    let decoded = crate::multipart::decode(&ct, &body_bytes)?;
                    sbi_response.http.content = decoded.json;
                    for part in decoded.parts {
                        sbi_response.http.add_part(part);
                    }
                }
                None => {
                    sbi_response.http.content =
                        Some(String::from_utf8_lossy(&body_bytes).to_string());
                }
            }
        }

        Ok(sbi_response)
    }

    /// Send a GET request
    pub async fn get(&self, path: &str) -> SbiResult<SbiResponse> {
        self.send_request(SbiRequest::get(path)).await
    }

    /// Send a POST request with JSON body
    pub async fn post_json<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> SbiResult<SbiResponse> {
        let request = SbiRequest::post(path).with_json_body(body)?;
        self.send_request(request).await
    }

    /// Send a PUT request with JSON body
    pub async fn put_json<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> SbiResult<SbiResponse> {
        let request = SbiRequest::put(path).with_json_body(body)?;
        self.send_request(request).await
    }

    /// Send a DELETE request
    pub async fn delete(&self, path: &str) -> SbiResult<SbiResponse> {
        self.send_request(SbiRequest::delete(path)).await
    }

    /// Send a PATCH request with JSON body
    pub async fn patch_json<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> SbiResult<SbiResponse> {
        let request = SbiRequest::patch(path).with_json_body(body)?;
        self.send_request(request).await
    }

    /// Close all pooled connections.
    pub async fn close(&self) {
        for slot in self.pool.iter() {
            let mut conn_guard = slot.lock().await;
            *conn_guard = None;
        }
    }
}

/// Client callback type for async responses
pub type ClientCallback = Box<dyn Fn(SbiResult<SbiResponse>) + Send + Sync>;

/// Derive the OAuth2 scope from the request URI.
///
/// The scope is the SBI service name (the apiName of the TS 29.501 §4.4
/// URI structure). For example, `/nsmf-pdusession/v1/sm-contexts` yields
/// `nsmf-pdusession`.
fn derive_scope_from_uri(uri: &str) -> String {
    crate::message::UriComponents::parse(uri)
        .api_name
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config() {
        let config = SbiClientConfig::new("localhost", 8080)
            .with_https()
            .with_connect_timeout(Duration::from_secs(10));

        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 8080);
        assert_eq!(config.scheme, UriScheme::Https);
        assert_eq!(config.base_uri(), "https://localhost:8080");
    }

    #[test]
    fn test_client_creation() {
        let client = SbiClient::with_host_port("127.0.0.1", 7777);
        assert_eq!(client.config().host, "127.0.0.1");
        assert_eq!(client.config().port, 7777);
        // Default pool is created with DEFAULT_POOL_SIZE slots.
        assert_eq!(client.pool.len(), DEFAULT_POOL_SIZE);
    }

    #[test]
    fn test_pool_size_config() {
        // Explicit pool size is honored.
        let client = SbiClient::new(SbiClientConfig::new("h", 1).with_pool_size(2));
        assert_eq!(client.pool.len(), 2);

        // pool_size of 0 is clamped to a single slot (never an empty pool,
        // which would panic on the modulo in get_connection).
        let client0 = SbiClient::new(SbiClientConfig::new("h", 1).with_pool_size(0));
        assert_eq!(client0.pool.len(), 1);
    }

    #[test]
    fn test_derive_scope_from_uri() {
        assert_eq!(
            derive_scope_from_uri("/nsmf-pdusession/v1/sm-contexts"),
            "nsmf-pdusession"
        );
        assert_eq!(
            derive_scope_from_uri("/nudm-uecm/v1/imsi-123/registrations/amf-3gpp-access"),
            "nudm-uecm"
        );
        assert_eq!(derive_scope_from_uri("/"), "");
        assert_eq!(derive_scope_from_uri(""), "");
        assert_eq!(
            derive_scope_from_uri("/nbsf-management/v1/pcfBindings?ipv4Addr=10.0.0.1"),
            "nbsf-management"
        );
    }

    // --- T1.1: automatic OAuth2 token acquisition + attachment ---

    /// A combined stub that serves the NRF token endpoint
    /// (`/nnrf-oauth2/v1/access-token`) and echoes the request's
    /// `authorization` header back as the response body for every other path.
    /// Returns the bound socket address.
    async fn serve_token_and_echo(token: &'static str) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                        let path = req.uri().path().to_string();
                        let auth = req
                            .headers()
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("<none>")
                            .to_string();
                        async move {
                            let body = if path == "/nnrf-oauth2/v1/access-token" {
                                format!(
                                    r#"{{"access_token":"{token}","token_type":"Bearer","expires_in":3600}}"#
                                )
                            } else {
                                // Echo the authorization header the client sent.
                                format!(r#"{{"authorization":"{auth}"}}"#)
                            };
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                http_body_util::Full::new(bytes::Bytes::from(body)),
                            ))
                        }
                    });
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, svc)
                    .await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_oauth2_token_attached_when_enabled() {
        let addr = serve_token_and_echo("test-access-token").await;
        let nrf_uri = format!("http://{addr}");

        // Point both the NRF (token source) and the target NF at the stub.
        let oauth2 = Arc::new(OAuth2Client::new(nrf_uri, "amf-instance-1", NfType::Amf));
        let client = SbiClient::with_host_port("127.0.0.1", addr.port())
            .with_oauth2(oauth2.clone(), NfType::Udm);

        // A request without an Authorization header gets a Bearer token
        // acquired from the NRF and attached automatically.
        let request = SbiRequest::get("/nudm-sdm/v1/imsi-1/am-data");
        let response = client.send_request(request).await.expect("request sent");
        let body = response.http.content.as_deref().expect("echo body");
        assert!(
            body.contains("Bearer test-access-token"),
            "expected attached bearer token, got: {body}"
        );

        // The token was cached for (target NF type, scope).
        assert!(oauth2.get_token(NfType::Udm, "nudm-sdm").await.is_ok());
    }

    #[tokio::test]
    async fn test_oauth2_not_attached_when_disabled() {
        let addr = serve_token_and_echo("test-access-token").await;

        // No OAuth2 configured on the client (default off): no token attached.
        let client = SbiClient::with_host_port("127.0.0.1", addr.port());
        let request = SbiRequest::get("/nudm-sdm/v1/imsi-1/am-data");
        let response = client.send_request(request).await.expect("request sent");
        let body = response.http.content.as_deref().expect("echo body");
        assert!(
            body.contains("<none>"),
            "expected no authorization header, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_oauth2_explicit_header_not_overwritten() {
        let addr = serve_token_and_echo("nrf-token").await;
        let nrf_uri = format!("http://{addr}");
        let oauth2 = Arc::new(OAuth2Client::new(nrf_uri, "amf-instance-1", NfType::Amf));
        let client = SbiClient::with_host_port("127.0.0.1", addr.port())
            .with_oauth2(oauth2, NfType::Udm);

        // A caller-supplied Authorization header is respected (not replaced by
        // an NRF-acquired token).
        let request = SbiRequest::get("/nudm-sdm/v1/imsi-1/am-data")
            .with_header("Authorization", "Bearer caller-supplied");
        let response = client.send_request(request).await.expect("request sent");
        let body = response.http.content.as_deref().expect("echo body");
        assert!(
            body.contains("Bearer caller-supplied"),
            "caller header should be preserved, got: {body}"
        );
    }
}
