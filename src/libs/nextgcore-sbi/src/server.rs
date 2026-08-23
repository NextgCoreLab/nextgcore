//! SBI HTTP/2 Server
//!
//! HTTP/2 server implementation using hyper for SBI communication.
//! Matches the interface in lib/sbi/server.h

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::Service;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use tokio_rustls::TlsAcceptor;

use crate::error::{SbiError, SbiResult};
use crate::message::{SbiHttpMessage, SbiRequest, SbiResponse};
use crate::tls;
use crate::types::{NfType, UriScheme};

/// Default maximum size, in bytes, of a request body the server will buffer
/// before rejecting with 413 Payload Too Large. 1 MiB comfortably covers
/// every JSON / multipart SBI body (TS 29.500) while bounding the memory a
/// single request can pin, closing the unbounded-`collect()` DoS.
pub const DEFAULT_MAX_REQUEST_BODY_SIZE: usize = 1024 * 1024;

/// Default cap on concurrent HTTP/2 streams per connection. Bounds the number
/// of in-flight requests one peer can open and the per-connection state the
/// server keeps, mitigating stream-flood DoS.
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 128;

/// Default maximum HTTP/2 frame size the server will accept (16 KiB — the
/// HTTP/2 spec minimum, RFC 7540 §4.2). Keeps per-frame buffering small.
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16 * 1024;

/// Default cap on the total decoded size of a request header list (8 KiB),
/// bounding HPACK-decompressed header memory per request.
pub const DEFAULT_MAX_HEADER_LIST_SIZE: u32 = 8 * 1024;

/// Server configuration
#[derive(Debug, Clone)]
pub struct SbiServerConfig {
    /// Bind address
    pub addr: SocketAddr,
    /// URI scheme
    pub scheme: UriScheme,
    /// Interface name (optional)
    pub interface: Option<String>,
    /// TLS private key path
    pub private_key: Option<String>,
    /// TLS certificate path
    pub cert: Option<String>,
    /// Verify client certificates
    pub verify_client: bool,
    /// CA certificate for client verification
    pub verify_client_cacert: Option<String>,
    /// Require a valid OAuth2 bearer token on incoming requests (default false).
    /// When true, verification keys come from `oauth2_jwks` (static) or
    /// `oauth2_jwks_uri` (fetched live); with neither configured the server
    /// fails closed and rejects every request with 503.
    pub require_oauth2: bool,
    /// JWKS (NRF public keys) used to verify access tokens when
    /// `require_oauth2` is enabled. Takes precedence over `oauth2_jwks_uri`.
    pub oauth2_jwks: Option<serde_json::Value>,
    /// URI of the NRF's JWKS endpoint (`http://<nrf>/nnrf-oauth2/v1/jwks`).
    /// When `require_oauth2` is enabled and `oauth2_jwks` is unset, keys are
    /// fetched from here on first use and cached (see [`JwksCache`]).
    pub oauth2_jwks_uri: Option<String>,
    /// Expected OAuth2 `aud` (audience) claim, per RFC 7519 §4.1.3 and
    /// TS 33.501 §13.4.1.2. When `Some`, a verified access token is rejected
    /// unless its `aud` includes this value — normally the NF's own type
    /// (e.g. "UDM") or NF Instance ID. `None` (default) skips the audience
    /// check, preserving prior behaviour. Only consulted when
    /// `require_oauth2` is enabled.
    pub oauth2_expected_audience: Option<String>,
    /// Maximum request body size, in bytes, accepted before the body is
    /// buffered. Oversize requests are rejected with 413 (ProblemDetails)
    /// without allocating the full body. Defaults to
    /// [`DEFAULT_MAX_REQUEST_BODY_SIZE`].
    pub max_request_body_size: usize,
    /// Cap on concurrent HTTP/2 streams per connection. `None` leaves hyper's
    /// own default in place. Defaults to
    /// `Some(`[`DEFAULT_MAX_CONCURRENT_STREAMS`]`)`.
    pub max_concurrent_streams: Option<u32>,
    /// Maximum HTTP/2 frame size accepted. `None` keeps hyper's default.
    /// Defaults to `Some(`[`DEFAULT_MAX_FRAME_SIZE`]`)`.
    pub max_frame_size: Option<u32>,
    /// Cap on the decoded HTTP/2 header-list size. `None` keeps hyper's
    /// default. Defaults to `Some(`[`DEFAULT_MAX_HEADER_LIST_SIZE`]`)`.
    pub max_header_list_size: Option<u32>,
    /// This NF's type, used to stamp the `Server` response header (sbi-02,
    /// TS 29.500 §6.10.8.2). `None` (default) emits no `Server` header,
    /// preserving the prior behaviour.
    pub server_nf_type: Option<NfType>,
    /// This NF's instance ID / FQDN, combined with `server_nf_type` as the
    /// `Server` value `<NFTYPE>-<id>` (sbi-02).
    pub server_nf_id: Option<String>,
}

impl Default for SbiServerConfig {
    fn default() -> Self {
        Self {
            addr: SocketAddr::from(([127, 0, 0, 1], 7777)),
            scheme: UriScheme::Http,
            interface: None,
            private_key: None,
            cert: None,
            verify_client: false,
            verify_client_cacert: None,
            require_oauth2: false,
            oauth2_jwks: None,
            oauth2_jwks_uri: None,
            oauth2_expected_audience: None,
            max_request_body_size: DEFAULT_MAX_REQUEST_BODY_SIZE,
            max_concurrent_streams: Some(DEFAULT_MAX_CONCURRENT_STREAMS),
            max_frame_size: Some(DEFAULT_MAX_FRAME_SIZE),
            max_header_list_size: Some(DEFAULT_MAX_HEADER_LIST_SIZE),
            server_nf_type: None,
            server_nf_id: None,
        }
    }
}

impl SbiServerConfig {
    /// Create a new server configuration
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            ..Default::default()
        }
    }

    /// Create configuration with host and port
    pub fn with_host_port(host: impl AsRef<str>, port: u16) -> SbiResult<Self> {
        let addr: SocketAddr = format!("{}:{}", host.as_ref(), port)
            .parse()
            .map_err(|e| SbiError::InvalidUri(format!("Invalid address: {e}")))?;
        Ok(Self::new(addr))
    }

    /// Set the interface name
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = Some(interface.into());
        self
    }

    /// Enable HTTPS with certificates
    pub fn with_tls(mut self, private_key: impl Into<String>, cert: impl Into<String>) -> Self {
        self.scheme = UriScheme::Https;
        self.private_key = Some(private_key.into());
        self.cert = Some(cert.into());
        self
    }

    /// Set the maximum buffered request body size, in bytes (T1.4).
    pub fn with_max_request_body_size(mut self, bytes: usize) -> Self {
        self.max_request_body_size = bytes;
        self
    }

    /// Set the expected OAuth2 `aud` claim this NF will accept (T1.2).
    ///
    /// Typically the NF's own type string (e.g. "UDM") or NF Instance ID.
    /// Only enforced when `require_oauth2` is also enabled.
    pub fn with_expected_audience(mut self, audience: impl Into<String>) -> Self {
        self.oauth2_expected_audience = Some(audience.into());
        self
    }

    /// Set the expected OAuth2 `aud` claim from an [`NfType`] (T1.2).
    pub fn with_expected_audience_nf_type(mut self, nf_type: NfType) -> Self {
        self.oauth2_expected_audience = Some(nf_type.to_str().to_string());
        self
    }

    /// Set this NF's identity for the `Server` response header (sbi-02).
    ///
    /// Per TS 29.500 §6.10.8.2 the originator of a response should set
    /// `Server: <NFType>-<identity>` where identity is the NF Instance ID (or
    /// FQDN for SCP/SEPP), e.g. `SMF-54804518-...` or `SCP-scp1.operator.com`.
    /// When set, every response without a handler-supplied `Server` header
    /// carries this value. Unset (default) emits no `Server` header.
    pub fn with_server_identity(mut self, nf_type: NfType, nf_id: impl Into<String>) -> Self {
        self.server_nf_type = Some(nf_type);
        self.server_nf_id = Some(nf_id.into());
        self
    }

    /// Resolve the configured `(NfType, id)` server identity, if any (sbi-02).
    fn server_identity(&self) -> Option<(NfType, String)> {
        match (self.server_nf_type, &self.server_nf_id) {
            (Some(nf_type), Some(id)) => Some((nf_type, id.clone())),
            _ => None,
        }
    }
}

/// Request handler trait
pub trait SbiRequestHandler: Send + Sync + 'static {
    /// Handle an incoming SBI request
    fn handle(&self, request: SbiRequest) -> Pin<Box<dyn Future<Output = SbiResponse> + Send>>;
}

/// Function-based request handler
impl<F, Fut> SbiRequestHandler for F
where
    F: Fn(SbiRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = SbiResponse> + Send + 'static,
{
    fn handle(&self, request: SbiRequest) -> Pin<Box<dyn Future<Output = SbiResponse> + Send>> {
        Box::pin(self(request))
    }
}

/// Where the server gets OAuth2 verification keys when `require_oauth2` is
/// enabled.
enum OAuthKeySource {
    /// A JWKS document provisioned in the server config.
    Static(serde_json::Value),
    /// Keys fetched live from the NRF's JWKS endpoint and cached.
    Remote(crate::oauth::JwksCache),
    /// `require_oauth2` is set but no JWKS or JWKS URI was configured:
    /// fail closed, rejecting every request.
    Unconfigured,
}

/// OAuth2 enforcement for incoming requests: a key source plus the optional
/// expected `aud` claim (T1.2).
struct OAuthVerifier {
    keys: OAuthKeySource,
    /// Expected audience (the NF's own type/instanceId); `None` skips the
    /// audience check, preserving prior behaviour.
    expected_audience: Option<String>,
}

impl OAuthVerifier {
    /// Resolve the verification source from the server config, or `None`
    /// when OAuth2 enforcement is disabled.
    fn from_config(config: &SbiServerConfig) -> Option<Self> {
        if !config.require_oauth2 {
            return None;
        }
        let keys = match (&config.oauth2_jwks, &config.oauth2_jwks_uri) {
            (Some(jwks), _) => OAuthKeySource::Static(jwks.clone()),
            (None, Some(uri)) => OAuthKeySource::Remote(crate::oauth::JwksCache::new(uri.clone())),
            (None, None) => {
                log::error!(
                    "require_oauth2 is enabled with no oauth2_jwks/oauth2_jwks_uri; \
                     rejecting all requests"
                );
                OAuthKeySource::Unconfigured
            }
        };
        Some(Self {
            keys,
            expected_audience: config.oauth2_expected_audience.clone(),
        })
    }

    /// Verify the bearer token's signature, expiry and (when configured)
    /// audience, and — when `required_scope` is `Some` — that the token's scope
    /// authorizes the invoked service (TS 33.501 §13.4.1.2, TS 29.510
    /// §5.4.2.2.2). `required_scope` is the invoked apiName (service name);
    /// `None` (e.g. a non-service path) skips only the scope check.
    async fn authorize(
        &self,
        auth_header: Option<&str>,
        required_scope: Option<&str>,
    ) -> SbiResult<()> {
        let aud = self.expected_audience.as_deref();
        let claims = match &self.keys {
            OAuthKeySource::Static(jwks) => {
                crate::oauth::authorize_bearer_aud(auth_header, jwks, aud)?
            }
            OAuthKeySource::Remote(cache) => cache.authorize_aud(auth_header, aud).await?,
            OAuthKeySource::Unconfigured => {
                return Err(SbiError::ServerError(
                    "require_oauth2 is enabled but neither oauth2_jwks nor oauth2_jwks_uri is configured".into(),
                ))
            }
        };
        if let Some(scope) = required_scope {
            crate::oauth::check_token_scope(&claims.scope, scope)?;
        }
        Ok(())
    }
}

/// Hyper service wrapper
struct SbiService<H: SbiRequestHandler> {
    handler: Arc<H>,
    /// When `Some`, every request must carry a valid OAuth2 bearer token;
    /// bad tokens are rejected with 401, unavailable keys with 503.
    oauth: Option<Arc<OAuthVerifier>>,
    /// Maximum request body size, in bytes, buffered before rejecting with
    /// 413 (T1.4).
    max_request_body_size: usize,
    /// RFC 5705 TLS exporter secret extracted from the N32-c TLS connection
    /// once per connection (T1.5b). Shared across all multiplexed requests on
    /// the same HTTP/2 connection and threaded into each `SbiRequest`.
    tls_exporter_secret: Option<Vec<u8>>,
    /// This NF's `(NfType, id)` identity for the `Server` response header
    /// (sbi-02). `None` emits no `Server` header.
    server_identity: Option<(NfType, String)>,
}

impl<H: SbiRequestHandler> Clone for SbiService<H> {
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
            oauth: self.oauth.clone(),
            max_request_body_size: self.max_request_body_size,
            tls_exporter_secret: self.tls_exporter_secret.clone(),
            server_identity: self.server_identity.clone(),
        }
    }
}

impl<H: SbiRequestHandler> Service<Request<Incoming>> for SbiService<H> {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let handler = self.handler.clone();
        let oauth = self.oauth.clone();
        let max_body = self.max_request_body_size;
        let tls_exporter_secret = self.tls_exporter_secret.clone();
        let server_identity = self.server_identity.clone();
        let path = req.uri().path().to_string();

        Box::pin(async move {
            // Health/readiness probe — handled before the NF handler
            if path == "/health" || path == "/ready" || path == "/live" {
                let body = Full::new(Bytes::from(r#"{"status":"healthy"}"#));
                return Ok(Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(body)
                    .expect("value expected"));
            }

            // Convert hyper request to SbiRequest, enforcing the body-size cap
            // BEFORE buffering (T1.4). An oversize body is rejected with 413
            // ProblemDetails without allocating the full body.
            let sbi_request = match convert_request(req, max_body, tls_exporter_secret).await {
                Ok(request) => request,
                Err(ConvertRequestError::BodyTooLarge) => {
                    let body = serde_json::json!({
                        "title": "Payload Too Large",
                        "status": 413,
                        "detail": format!(
                            "request body exceeds the maximum of {max_body} bytes"
                        ),
                        "cause": "PAYLOAD_TOO_LARGE",
                    })
                    .to_string();
                    let resp =
                        SbiResponse::with_status(413).with_body(body, "application/problem+json");
                    return Ok(convert_response_with_identity(
                        resp,
                        server_identity.as_ref(),
                    ));
                }
            };

            // OAuth2 enforcement (opt-in). Verify the bearer token against the
            // configured key material before dispatching to the NF handler.
            // An invalid token is the caller's fault (401); not being able to
            // obtain verification keys is ours (503).
            if let Some(verifier) = &oauth {
                // get_header() is case-insensitive, covering both hyper's
                // lowercased HTTP/2 names and in-process constructed requests.
                let auth = sbi_request
                    .http
                    .get_header("authorization")
                    .map(|s| s.as_str());
                // TS 33.501 §13.4.1.2: reject a token whose scope does not
                // authorize the invoked service (the decomposed apiName).
                let required_scope = sbi_request.header.service_name.as_deref();
                if let Err(e) = verifier.authorize(auth, required_scope).await {
                    let (status, title) = match e {
                        SbiError::AuthorizationFailed(_) => (401, "Unauthorized"),
                        _ => (503, "Service Unavailable"),
                    };
                    let body = serde_json::json!({
                        "title": title, "status": status, "detail": e.to_string()
                    })
                    .to_string();
                    let mut resp = SbiResponse::with_status(status)
                        .with_body(body, "application/problem+json");
                    if status == 401 {
                        // RFC 6750 §3 (TS 29.500 Table 5.2.2.2-1): a rejected or
                        // absent bearer token MUST carry a WWW-Authenticate: Bearer
                        // challenge so the consumer/SCP can classify and retry.
                        resp = resp.with_header(
                            "WWW-Authenticate",
                            format!(
                                "Bearer realm=\"5gc-sbi\", error=\"invalid_token\", error_description=\"{e}\""
                            ),
                        );
                    }
                    return Ok(convert_response_with_identity(
                        resp,
                        server_identity.as_ref(),
                    ));
                }
            }

            // Call the handler, guarded against panics (T1.3). A panic in any
            // NF handler becomes a 500 application/problem+json instead of
            // tearing down the whole HTTP/2 connection task (which would drop
            // every other multiplexed request on the same connection).
            let sbi_response = match catch_handler_panic(handler.handle(sbi_request)).await {
                Ok(response) => response,
                Err(()) => {
                    let body = serde_json::json!({
                        "title": "Internal Server Error",
                        "status": 500,
                        "detail": "the request handler panicked",
                        "cause": "INTERNAL_ERROR",
                    })
                    .to_string();
                    SbiResponse::with_status(500).with_body(body, "application/problem+json")
                }
            };

            // Convert SbiResponse to hyper response, stamping the Server
            // header (sbi-02) when a server identity is configured.
            let response = convert_response_with_identity(sbi_response, server_identity.as_ref());

            Ok(response)
        })
    }
}

/// Drive a handler future to completion, converting a panic into `Err(())`.
///
/// `AssertUnwindSafe` is sound here: on a caught panic we discard the future
/// and any partially-mutated state it owned and synthesize a fresh 500
/// response, so no logically-inconsistent state is observed afterwards.
async fn catch_handler_panic<F>(fut: F) -> Result<SbiResponse, ()>
where
    F: Future<Output = SbiResponse>,
{
    use std::panic::AssertUnwindSafe;
    use std::task::Poll;

    let mut fut = Box::pin(fut);
    std::future::poll_fn(move |cx| {
        match std::panic::catch_unwind(AssertUnwindSafe(|| fut.as_mut().poll(cx))) {
            Ok(Poll::Ready(response)) => Poll::Ready(Ok(response)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(panic) => {
                let detail = panic_message(&panic);
                log::error!("SBI request handler panicked: {detail}");
                Poll::Ready(Err(()))
            }
        }
    })
    .await
}

/// Best-effort extraction of a human-readable message from a caught panic.
fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// Why [`convert_request`] could not produce an `SbiRequest`.
enum ConvertRequestError {
    /// The request body exceeded the configured maximum size (T1.4).
    BodyTooLarge,
}

/// HTTP/2 server-side resource limits applied to every accepted connection
/// (T1.4). Copied into each connection task so a single peer cannot exhaust
/// memory via stream floods or oversized frames/header lists.
#[derive(Debug, Clone, Copy)]
struct Http2Limits {
    max_concurrent_streams: Option<u32>,
    max_frame_size: Option<u32>,
    max_header_list_size: Option<u32>,
}

impl Http2Limits {
    fn from_config(config: &SbiServerConfig) -> Self {
        Self {
            max_concurrent_streams: config.max_concurrent_streams,
            max_frame_size: config.max_frame_size,
            max_header_list_size: config.max_header_list_size,
        }
    }

    /// Apply the configured limits to a hyper HTTP/2 server builder. Each
    /// `None` leaves hyper's own default untouched.
    fn apply<E>(&self, builder: &mut http2::Builder<E>) {
        if let Some(max) = self.max_concurrent_streams {
            builder.max_concurrent_streams(max);
        }
        if let Some(sz) = self.max_frame_size {
            builder.max_frame_size(sz);
        }
        if let Some(sz) = self.max_header_list_size {
            builder.max_header_list_size(sz);
        }
    }
}

/// Convert hyper request to SbiRequest, enforcing `max_body_size` (T1.4).
///
/// The body is read through [`Limited`], which yields an error as soon as the
/// accumulated body exceeds `max_body_size` rather than buffering an unbounded
/// amount first — this is what closes the memory-exhaustion DoS. An oversize
/// body surfaces as [`ConvertRequestError::BodyTooLarge`] (mapped to 413 by
/// the caller). Any other body-read error is treated as an empty body, matching
/// the previous behaviour.
///
/// `tls_exporter_secret` is the RFC 5705 keying material derived from the
/// N32-c TLS connection (T1.5b); `None` for plaintext connections.
///
/// Correlation ID extraction order (T6.4):
/// 1. `x-request-id` header (verbatim)
/// 2. `traceparent` trace-id field (the 32-hex-char segment after `00-`)
/// 3. Synthesised from wall-clock nanoseconds as 32 hex chars
async fn convert_request(
    req: Request<Incoming>,
    max_body_size: usize,
    tls_exporter_secret: Option<Vec<u8>>,
) -> Result<SbiRequest, ConvertRequestError> {
    let method = req.method().to_string();
    let uri = req.uri().path().to_string();

    // Extract headers
    let mut http = SbiHttpMessage::new();
    for (key, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            http.set_header(key.to_string(), v.to_string());
        }
    }

    // ── T6.4: correlation / request-ID extraction ──────────────────────────
    // Prefer an explicit x-request-id, fall back to the trace-id embedded in
    // a W3C traceparent, and synthesise one from the clock when neither is
    // present. The chosen id is threaded into structured log lines and echoed
    // outbound by the SBI client.
    let correlation_id = extract_or_generate_correlation_id(&http);

    // Extract query parameters
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                http.set_param(key.to_string(), value.to_string());
            }
        }
    }

    // Read body under a size cap. multipart/related bodies (N1/N2 binary
    // containers, TS 29.500 §6.1.2.3) are decoded into the JSON root + binary
    // parts before any UTF-8 conversion so binary content survives byte-exact.
    let limited = Limited::new(req.into_body(), max_body_size);
    match limited.collect().await {
        Ok(body) => {
            let bytes = body.to_bytes();
            if !bytes.is_empty() {
                let multipart_content_type = http
                    .get_header(crate::constants::header::CONTENT_TYPE)
                    .filter(|ct| crate::multipart::is_multipart_related(ct))
                    .cloned();
                match multipart_content_type {
                    Some(ct) => match crate::multipart::decode(&ct, &bytes) {
                        Ok(decoded) => {
                            http.content = decoded.json;
                            for part in decoded.parts {
                                http.add_part(part);
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                "cid={correlation_id} Failed to decode multipart request body \
                                 on {uri}: {e}"
                            );
                            http.set_content(String::from_utf8_lossy(&bytes).to_string());
                        }
                    },
                    None => http.set_content(String::from_utf8_lossy(&bytes).to_string()),
                }
            }
        }
        Err(e) => {
            // Limited returns a boxed LengthLimitError once the cap is passed;
            // distinguish that from a generic transport error.
            if e.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                log::warn!(
                    "cid={correlation_id} method={method} path={uri} \
                     reason=PAYLOAD_TOO_LARGE: body exceeds {max_body_size}-byte limit"
                );
                return Err(ConvertRequestError::BodyTooLarge);
            }
            log::warn!(
                "cid={correlation_id} method={method} path={uri} \
                 reason=BODY_READ_ERROR: {e}"
            );
        }
    }

    // Decompose the URI per TS 29.501 §4.4 so handlers get service name,
    // API version and resource components without re-parsing the path.
    let mut header = crate::message::SbiHeader::with_method_uri(method, uri);
    header.decompose_uri();

    Ok(SbiRequest {
        header,
        http,
        correlation_id,
        tls_exporter_secret,
    })
}

/// Extract or generate a correlation ID for request tracing (T6.4).
///
/// Priority:
/// 1. `x-request-id` header (verbatim, at most 128 chars to bound memory)
/// 2. Trace-id field from W3C `traceparent` (`00-<trace-id>-<span>-<flags>`)
/// 3. 32 hex chars synthesised from wall-clock nanoseconds (128-bit ns value
///    in big-endian, giving monotonically-ish increasing IDs without any new
///    dependency).
pub(crate) fn extract_or_generate_correlation_id(http: &SbiHttpMessage) -> String {
    // 1. Explicit request ID header (preferred).
    if let Some(id) = http.get_header("x-request-id") {
        let id = id.trim();
        if !id.is_empty() {
            return id.chars().take(128).collect();
        }
    }

    // 2. W3C traceparent: "00-<32-hex-trace-id>-<16-hex-span-id>-<2-hex-flags>"
    if let Some(tp) = http.get_header("traceparent") {
        let parts: Vec<&str> = tp.splitn(4, '-').collect();
        if parts.len() == 4 && parts[1].len() == 32 {
            return parts[1].to_string();
        }
    }

    // 3. Synthesise from wall-clock nanoseconds (no new deps: just hex + time).
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{ns:032x}")
}

/// Convert SbiResponse to hyper response
fn convert_response(mut sbi_response: SbiResponse) -> Response<Full<Bytes>> {
    // TS 29.500 §5.2.7: 4xx/5xx bodies carry ProblemDetails as
    // application/problem+json. Fill in the content type when the handler
    // attached an error body without declaring one.
    if sbi_response.status >= 400
        && sbi_response.http.content.is_some()
        && sbi_response
            .http
            .get_header(crate::constants::header::CONTENT_TYPE)
            .is_none()
    {
        sbi_response.http.set_header(
            crate::constants::header::CONTENT_TYPE,
            crate::constants::content_type::APPLICATION_PROBLEM_JSON,
        );
    }

    // Encode binary parts as multipart/related (TS 29.500 §6.1.2.3) with the
    // JSON content as the root part.
    let body_bytes: Bytes = if !sbi_response.http.parts.is_empty() {
        let boundary = crate::multipart::generate_boundary();
        sbi_response.http.set_header(
            crate::constants::header::CONTENT_TYPE,
            crate::multipart::content_type_with_boundary(&boundary),
        );
        Bytes::from(crate::multipart::encode(
            sbi_response.http.content.as_deref(),
            &sbi_response.http.parts,
            &boundary,
        ))
    } else if let Some(binary) = sbi_response.http.binary_content.clone() {
        // A non-text body (e.g. a downloadable model artefact) goes out
        // verbatim. Checked after `parts` so multipart still wins, and before
        // `content` so a handler cannot accidentally send both.
        binary
    } else {
        sbi_response
            .http
            .content
            .as_deref()
            .map(|c| Bytes::from(c.to_owned()))
            .unwrap_or_default()
    };

    let mut builder = Response::builder().status(sbi_response.status);

    // Add headers
    for (key, value) in &sbi_response.http.headers {
        builder = builder.header(key.as_str(), value.as_str());
    }

    builder.body(Full::new(body_bytes)).unwrap_or_else(|_| {
        Response::builder()
            .status(500)
            .header(
                "content-type",
                crate::constants::content_type::APPLICATION_PROBLEM_JSON,
            )
            .body(Full::new(Bytes::from(
                r#"{"title":"Internal Server Error","status":500}"#,
            )))
            .expect("value expected")
    })
}

/// Convert an [`SbiResponse`] to a hyper response, stamping the `Server`
/// header (sbi-02) from the NF identity when one is configured and the handler
/// did not already set a `Server` header.
///
/// TS 29.500 §6.10.8.2: a response originator should set
/// `Server: <NFType>-<identity>`. Applied to all responses (error and
/// success); harmless on 2xx and aids troubleshooting. With `identity == None`
/// no header is added, preserving prior behaviour.
fn convert_response_with_identity(
    mut sbi_response: SbiResponse,
    identity: Option<&(NfType, String)>,
) -> Response<Full<Bytes>> {
    if let Some((nf_type, nf_id)) = identity {
        if sbi_response.http.get_header("Server").is_none() {
            sbi_response
                .http
                .set_header("Server", format!("{}-{}", nf_type.as_server_token(), nf_id));
        }
    }
    convert_response(sbi_response)
}

/// Server state
enum ServerState {
    Stopped,
    Running(oneshot::Sender<()>),
}

/// SBI Server - HTTP/2 server for SBI communication
/// Matches nextgcore_sbi_server_t
pub struct SbiServer {
    /// Server configuration
    config: SbiServerConfig,
    /// Server state
    state: Arc<Mutex<ServerState>>,
}

impl SbiServer {
    /// Create a new SBI server
    pub fn new(config: SbiServerConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(ServerState::Stopped)),
        }
    }

    /// Create a server with address
    pub fn with_addr(addr: SocketAddr) -> Self {
        Self::new(SbiServerConfig::new(addr))
    }

    /// Get the server configuration
    pub fn config(&self) -> &SbiServerConfig {
        &self.config
    }

    /// Build a TLS acceptor from the server config
    fn build_tls_acceptor(&self) -> SbiResult<TlsAcceptor> {
        let cert_path = self
            .config
            .cert
            .as_ref()
            .ok_or_else(|| SbiError::TlsError("TLS certificate path not configured".into()))?;
        let key_path = self
            .config
            .private_key
            .as_ref()
            .ok_or_else(|| SbiError::TlsError("TLS private key path not configured".into()))?;

        let certs = tls::load_certs(cert_path)?;
        let key = tls::load_private_key(key_path)?;

        let mut server_config = if self.config.verify_client {
            let ca_path = self.config.verify_client_cacert.as_ref().ok_or_else(|| {
                SbiError::TlsError(
                    "Client CA certificate required for mTLS but not configured".into(),
                )
            })?;
            tls::build_server_config_mtls(certs, key, ca_path)?
        } else {
            tls::build_server_config(certs, key)?
        };

        server_config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }

    /// Start the server with a request handler
    pub async fn start<H: SbiRequestHandler>(&self, handler: H) -> SbiResult<()> {
        let mut state = self.state.lock().await;

        if matches!(*state, ServerState::Running(_)) {
            return Err(SbiError::ServerError("Server already running".to_string()));
        }

        let listener = TcpListener::bind(self.config.addr)
            .await
            .map_err(|e| SbiError::ServerError(format!("Failed to bind: {e}")))?;

        let tls_acceptor = if self.config.scheme == UriScheme::Https {
            Some(self.build_tls_acceptor()?)
        } else {
            None
        };

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        *state = ServerState::Running(shutdown_tx);
        drop(state);

        let handler = Arc::new(handler);

        // Resolve the OAuth2 verification source once: Some(_) enables
        // per-request bearer verification, None leaves the server open.
        let oauth: Option<Arc<OAuthVerifier>> =
            OAuthVerifier::from_config(&self.config).map(Arc::new);

        // Capture the DoS-relevant limits so each spawned connection task gets
        // a consistently-configured HTTP/2 builder and per-request body cap
        // (T1.4) without borrowing `self`.
        let max_request_body_size = self.config.max_request_body_size;
        let http2_limits = Http2Limits::from_config(&self.config);
        // sbi-02: resolve the NF identity once for Server-header stamping.
        let server_identity = self.config.server_identity();

        // Spawn the server task
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let handler_ref = handler.clone();
                                let oauth_ref = oauth.clone();
                                let http2_limits = http2_limits;
                                let server_identity_ref = server_identity.clone();

                                if let Some(ref acceptor) = tls_acceptor {
                                    let acceptor = acceptor.clone();
                                    tokio::spawn(async move {
                                        match acceptor.accept(stream).await {
                                            Ok(tls_stream) => {
                                                // ── T1.5b: extract RFC 5705 exporter secret ──
                                                // `get_ref()` on a tokio_rustls server TlsStream
                                                // yields `(&TcpStream, &ServerConnection)`.
                                                // `ServerConnection` derefs to
                                                // `ConnectionCommon<ServerConnectionData>` which
                                                // exposes `export_keying_material`. We call this
                                                // BEFORE moving the stream into TokioIo so we
                                                // still hold the reference.
                                                let tls_exporter_secret = {
                                                    let (_, server_conn) = tls_stream.get_ref();
                                                    crate::tls::export_n32_master_key(
                                                        server_conn,
                                                        None,
                                                    )
                                                    .map_err(|e| {
                                                        log::warn!(
                                                            "N32 master exporter failed on \
                                                             server accept: {e}"
                                                        );
                                                    })
                                                    .ok()
                                                };
                                                let service = SbiService {
                                                    handler: handler_ref,
                                                    oauth: oauth_ref,
                                                    max_request_body_size,
                                                    tls_exporter_secret,
                                                    server_identity: server_identity_ref,
                                                };
                                                let io = TokioIo::new(tls_stream);
                                                let mut builder = http2::Builder::new(
                                                    hyper_util::rt::TokioExecutor::new()
                                                );
                                                http2_limits.apply(&mut builder);
                                                if let Err(e) = builder
                                                    .serve_connection(io, service)
                                                    .await
                                                {
                                                    eprintln!("HTTP/2 TLS connection error: {e}");
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!("TLS accept error: {e}");
                                            }
                                        }
                                    });
                                } else {
                                    let service = SbiService {
                                        handler: handler_ref,
                                        oauth: oauth_ref,
                                        max_request_body_size,
                                        // No TLS on plaintext connections.
                                        tls_exporter_secret: None,
                                        server_identity: server_identity_ref,
                                    };
                                    let io = TokioIo::new(stream);
                                    tokio::spawn(async move {
                                        let mut builder = http2::Builder::new(
                                            hyper_util::rt::TokioExecutor::new()
                                        );
                                        http2_limits.apply(&mut builder);
                                        if let Err(e) = builder
                                            .serve_connection(io, service)
                                            .await
                                        {
                                            eprintln!("HTTP/2 connection error: {e}");
                                        }
                                    });
                                }
                            }
                            Err(e) => {
                                eprintln!("Accept error: {e}");
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the server
    pub async fn stop(&self) -> SbiResult<()> {
        let mut state = self.state.lock().await;

        if let ServerState::Running(shutdown_tx) =
            std::mem::replace(&mut *state, ServerState::Stopped)
        {
            let _ = shutdown_tx.send(());
        }

        Ok(())
    }

    /// Check if the server is running
    pub async fn is_running(&self) -> bool {
        let state = self.state.lock().await;
        matches!(*state, ServerState::Running(_))
    }
}

/// Stream identifier for tracking requests
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub u64);

impl StreamId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

/// Helper function to send an error response.
///
/// The ProblemDetails body is carried as `application/problem+json` per
/// TS 29.500 §5.2.7.
pub fn send_error(status: u16, title: &str, detail: &str, cause: Option<&str>) -> SbiResponse {
    use crate::message::ProblemDetails;

    let problem = ProblemDetails::with_status(status as i32)
        .with_title(title)
        .with_detail(detail);

    let problem = if let Some(c) = cause {
        problem.with_cause(c)
    } else {
        problem
    };

    SbiResponse::with_status(status).with_problem(&problem)
}

/// Send a 400 Bad Request error response
pub fn send_bad_request(detail: &str, cause: Option<&str>) -> SbiResponse {
    send_error(400, "Bad Request", detail, cause)
}

/// Send a 401 Unauthorized error response
pub fn send_unauthorized(detail: &str, cause: Option<&str>) -> SbiResponse {
    send_error(401, "Unauthorized", detail, cause)
}

/// Send a 403 Forbidden error response
pub fn send_forbidden(detail: &str, cause: Option<&str>) -> SbiResponse {
    send_error(403, "Forbidden", detail, cause)
}

/// Send a 404 Not Found error response
pub fn send_not_found(detail: &str, cause: Option<&str>) -> SbiResponse {
    send_error(404, "Not Found", detail, cause)
}

/// Send a 405 Method Not Allowed error response
pub fn send_method_not_allowed(method: &str, resource: &str) -> SbiResponse {
    send_error(
        405,
        "Method Not Allowed",
        &format!("Method {method} not allowed for resource {resource}"),
        Some("METHOD_NOT_ALLOWED"),
    )
}

/// Send a 500 Internal Server Error response
pub fn send_internal_error(detail: &str) -> SbiResponse {
    send_error(500, "Internal Server Error", detail, Some("INTERNAL_ERROR"))
}

/// Send a 503 Service Unavailable error response
pub fn send_service_unavailable(detail: &str) -> SbiResponse {
    send_error(
        503,
        "Service Unavailable",
        detail,
        Some("SERVICE_UNAVAILABLE"),
    )
}

/// Send a 504 Gateway Timeout error response
pub fn send_gateway_timeout(detail: &str) -> SbiResponse {
    send_error(504, "Gateway Timeout", detail, Some("GATEWAY_TIMEOUT"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config() {
        let config =
            SbiServerConfig::new(SocketAddr::from(([0, 0, 0, 0], 8080))).with_interface("sbi");

        assert_eq!(config.addr.port(), 8080);
        assert_eq!(config.interface, Some("sbi".to_string()));
    }

    // --- T6.4: correlation-id extraction and generation ---

    /// Helper: build an `SbiHttpMessage` with the supplied headers.
    fn http_with_headers(headers: &[(&str, &str)]) -> crate::message::SbiHttpMessage {
        let mut http = crate::message::SbiHttpMessage::new();
        for (k, v) in headers {
            http.set_header(*k, *v);
        }
        http
    }

    #[test]
    fn test_correlation_id_from_x_request_id() {
        // An explicit x-request-id is used verbatim (T6.4 priority 1).
        let http = http_with_headers(&[("x-request-id", "my-req-123")]);
        let cid = extract_or_generate_correlation_id(&http);
        assert_eq!(cid, "my-req-123");
    }

    #[test]
    fn test_correlation_id_from_traceparent() {
        // When x-request-id is absent the trace-id segment of a W3C traceparent
        // is used (T6.4 priority 2).
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let http = http_with_headers(&[("traceparent", tp)]);
        let cid = extract_or_generate_correlation_id(&http);
        assert_eq!(cid, "4bf92f3577b34da6a3ce929d0e0e4736");
    }

    #[test]
    fn test_correlation_id_x_request_id_takes_precedence_over_traceparent() {
        // x-request-id wins over traceparent when both are present (priority 1).
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let http = http_with_headers(&[("x-request-id", "explicit-id"), ("traceparent", tp)]);
        let cid = extract_or_generate_correlation_id(&http);
        assert_eq!(cid, "explicit-id");
    }

    #[test]
    fn test_correlation_id_generated_when_no_headers() {
        // No x-request-id or traceparent: synthesise from clock (priority 3).
        let http = crate::message::SbiHttpMessage::new();
        let cid = extract_or_generate_correlation_id(&http);
        // The generated ID is 32 hex chars (128-bit nanoseconds in hex).
        assert_eq!(
            cid.len(),
            32,
            "generated cid must be 32 hex chars, got: {cid}"
        );
        assert!(
            cid.chars().all(|c| c.is_ascii_hexdigit()),
            "generated cid must be all hex digits, got: {cid}"
        );
    }

    #[test]
    fn test_correlation_id_generated_ids_are_distinct() {
        // Two consecutive synthetic IDs should differ (wall-clock advances).
        // We can't guarantee sub-nanosecond uniqueness in all environments, but
        // after a brief sleep they must differ.
        let http = crate::message::SbiHttpMessage::new();
        let cid1 = extract_or_generate_correlation_id(&http);
        std::thread::sleep(std::time::Duration::from_millis(1));
        let cid2 = extract_or_generate_correlation_id(&http);
        assert_ne!(cid1, cid2, "successive generated cids should differ");
    }

    #[test]
    fn test_correlation_id_x_request_id_truncated_to_128_chars() {
        // Pathologically long x-request-id values are capped at 128 chars.
        let long_id = "a".repeat(200);
        let http = http_with_headers(&[("x-request-id", &long_id)]);
        let cid = extract_or_generate_correlation_id(&http);
        assert_eq!(cid.len(), 128);
    }

    #[test]
    fn test_correlation_id_malformed_traceparent_falls_through_to_generated() {
        // A traceparent that does not match the 4-segment / 32-hex-char shape
        // must not be used; the function must fall through to synthesis.
        let http = http_with_headers(&[("traceparent", "not-a-real-traceparent")]);
        let cid = extract_or_generate_correlation_id(&http);
        // Falls through to synthesis: 32 hex chars.
        assert_eq!(cid.len(), 32);
        assert!(cid.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_oauth_verifier_resolution() {
        let base = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], 7777)));

        // Enforcement off: no verifier regardless of key material.
        assert!(OAuthVerifier::from_config(&base).is_none());

        // Static JWKS takes precedence over a configured URI.
        let both = SbiServerConfig {
            require_oauth2: true,
            oauth2_jwks: Some(serde_json::json!({"keys": []})),
            oauth2_jwks_uri: Some("http://nrf:7777/nnrf-oauth2/v1/jwks".into()),
            ..base.clone()
        };
        assert!(matches!(
            OAuthVerifier::from_config(&both).map(|v| v.keys),
            Some(OAuthKeySource::Static(_))
        ));

        // URI alone resolves to the live-fetching cache.
        let uri_only = SbiServerConfig {
            require_oauth2: true,
            oauth2_jwks_uri: Some("http://nrf:7777/nnrf-oauth2/v1/jwks".into()),
            ..base.clone()
        };
        assert!(matches!(
            OAuthVerifier::from_config(&uri_only).map(|v| v.keys),
            Some(OAuthKeySource::Remote(_))
        ));

        // The expected-audience field flows from config into the verifier.
        let with_aud = SbiServerConfig {
            require_oauth2: true,
            oauth2_jwks: Some(serde_json::json!({"keys": []})),
            oauth2_expected_audience: Some("UDM".into()),
            ..base.clone()
        };
        assert_eq!(
            OAuthVerifier::from_config(&with_aud)
                .and_then(|v| v.expected_audience)
                .as_deref(),
            Some("UDM")
        );

        // Enforcement with no key material fails closed.
        let neither = SbiServerConfig {
            require_oauth2: true,
            ..base
        };
        assert!(matches!(
            OAuthVerifier::from_config(&neither).map(|v| v.keys),
            Some(OAuthKeySource::Unconfigured)
        ));
    }

    #[tokio::test]
    async fn test_oauth_verifier_error_classes() {
        // Unconfigured rejects everything with a non-authorization error
        // (mapped to 503), even a syntactically plausible bearer token.
        let unconfigured = OAuthVerifier {
            keys: OAuthKeySource::Unconfigured,
            expected_audience: None,
        };
        let err = unconfigured
            .authorize(Some("Bearer a.b.c"), None)
            .await
            .unwrap_err();
        assert!(!matches!(err, SbiError::AuthorizationFailed(_)));

        // A static JWKS that can't verify the token is the caller's fault
        // (AuthorizationFailed, mapped to 401).
        let static_v = OAuthVerifier {
            keys: OAuthKeySource::Static(serde_json::json!({"keys": []})),
            expected_audience: None,
        };
        let err = static_v.authorize(None, None).await.unwrap_err();
        assert!(matches!(err, SbiError::AuthorizationFailed(_)));

        // A remote source that can't be reached is our fault (mapped to 503).
        let remote = OAuthVerifier {
            keys: OAuthKeySource::Remote(crate::oauth::JwksCache::new(
                "http://127.0.0.1:1/nnrf-oauth2/v1/jwks",
            )),
            expected_audience: None,
        };
        let err = remote
            .authorize(Some("Bearer a.b.c"), None)
            .await
            .unwrap_err();
        assert!(!matches!(err, SbiError::AuthorizationFailed(_)));
    }

    // --- sbi-02: Server response header ---

    #[test]
    fn test_server_identity_config() {
        // Default config has no server identity (no header emitted).
        let base = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], 7777)));
        assert!(base.server_identity().is_none());

        // Configured identity resolves to (NfType, id).
        let cfg = base.with_server_identity(NfType::Smf, "54804518-abcd");
        assert_eq!(
            cfg.server_identity(),
            Some((NfType::Smf, "54804518-abcd".to_string()))
        );
    }

    #[test]
    fn test_convert_response_stamps_server_header() {
        // An error response gets `Server: SMF-<id>` (uppercase) when an
        // identity is configured (TS 29.500 §6.10.8.2 EXAMPLE 3 shape).
        let identity = (NfType::Smf, "54804518-abcd".to_string());
        let resp = send_error(404, "Not Found", "missing", None);
        let hyper_resp = convert_response_with_identity(resp, Some(&identity));
        assert_eq!(
            hyper_resp
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok()),
            Some("SMF-54804518-abcd")
        );

        // A 2xx success response is stamped too (harmless, aids debugging).
        let ok = SbiResponse::ok().with_body("{}", "application/json");
        let hyper_ok = convert_response_with_identity(ok, Some(&identity));
        assert_eq!(
            hyper_ok
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok()),
            Some("SMF-54804518-abcd")
        );
    }

    /// `binary_content` carries a non-text body verbatim (the NWDAF's ONNX model
    /// artefact, issue #109), and — the part that matters for every other NF —
    /// leaving it `None` keeps the JSON path byte-identical.
    #[tokio::test]
    async fn test_convert_response_binary_body_is_verbatim_and_opt_in() {
        use http_body_util::BodyExt;

        async fn body_bytes(resp: Response<Full<Bytes>>) -> Vec<u8> {
            resp.into_body()
                .collect()
                .await
                .expect("collect body")
                .to_bytes()
                .to_vec()
        }

        // Not valid UTF-8, so this could not have gone through `content`.
        let artefact: Vec<u8> = vec![0x08, 0x01, 0xFF, 0xFE, 0x00, 0x7F];
        let mut resp = SbiResponse::with_status(200);
        resp.http
            .set_header("Content-Type", "application/octet-stream");
        resp.http.binary_content = Some(Bytes::from(artefact.clone()));
        let hyper = convert_response(resp);
        assert_eq!(hyper.status(), 200);
        assert_eq!(
            body_bytes(hyper).await,
            artefact,
            "bytes must go out unchanged"
        );

        // The default: no binary content → the text body wins, exactly as before.
        let json = SbiResponse::ok().with_body("{\"a\":1}", "application/json");
        assert!(json.http.binary_content.is_none());
        assert_eq!(
            body_bytes(convert_response(json)).await,
            b"{\"a\":1}".to_vec()
        );

        // Neither set → empty body, as before.
        assert!(body_bytes(convert_response(SbiResponse::with_status(204)))
            .await
            .is_empty());
    }

    #[test]
    fn test_convert_response_no_server_header_without_identity() {
        // No identity → no Server header (prior behaviour preserved).
        let resp = send_error(500, "Internal Server Error", "boom", None);
        let hyper_resp = convert_response_with_identity(resp, None);
        assert!(hyper_resp.headers().get("server").is_none());
    }

    #[test]
    fn test_convert_response_preserves_handler_server_header() {
        // A handler-supplied Server header is not overwritten.
        let identity = (NfType::Scp, "scp1.operator.com".to_string());
        let resp = SbiResponse::ok().with_header("Server", "custom-server/2.0");
        let hyper_resp = convert_response_with_identity(resp, Some(&identity));
        assert_eq!(
            hyper_resp
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok()),
            Some("custom-server/2.0")
        );
    }

    #[test]
    fn test_stream_id() {
        let id = StreamId::new(42);
        assert_eq!(id.0, 42);
    }

    #[test]
    fn test_send_error() {
        let response = send_error(404, "Not Found", "Resource not found", None);
        assert_eq!(response.status, 404);
    }

    #[test]
    fn test_all_error_helpers_carry_problem_json() {
        // TS 29.500 §5.2.7: every ProblemDetails-bearing 4xx/5xx the server
        // path emits must use application/problem+json.
        let responses = vec![
            send_bad_request("d", None),
            send_unauthorized("d", None),
            send_forbidden("d", Some("CAUSE")),
            send_not_found("d", None),
            send_method_not_allowed("TRACE", "/x"),
            send_internal_error("d"),
            send_service_unavailable("d"),
            send_gateway_timeout("d"),
            send_error(409, "Conflict", "d", Some("DUPLICATE")),
        ];
        for response in responses {
            assert!(response.status >= 400);
            assert_eq!(
                response.http.get_header("content-type").map(String::as_str),
                Some(crate::constants::content_type::APPLICATION_PROBLEM_JSON),
                "status {} missing problem+json content type",
                response.status
            );
            // Body parses back into ProblemDetails with the right status.
            let problem: crate::message::ProblemDetails =
                serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(problem.status, Some(response.status as i32));
        }
    }

    #[test]
    fn test_convert_response_defaults_problem_json_on_errors() {
        // A handler that attaches an error body without a content type gets
        // application/problem+json filled in.
        let response = SbiResponse::with_status(500);
        let mut response = response;
        response.http.set_content(r#"{"status":500}"#);
        let hyper_response = convert_response(response);
        assert_eq!(
            hyper_response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some(crate::constants::content_type::APPLICATION_PROBLEM_JSON)
        );

        // An explicitly declared content type is left alone (e.g. RFC 6749
        // token-endpoint errors use plain application/json).
        let response = SbiResponse::with_status(400)
            .with_body(r#"{"error":"invalid_request"}"#, "application/json");
        let hyper_response = convert_response(response);
        assert_eq!(
            hyper_response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );

        // 2xx responses are never touched.
        let response = SbiResponse::ok().with_body("{}", "application/json");
        let hyper_response = convert_response(response);
        assert_eq!(
            hyper_response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }

    #[test]
    fn test_convert_response_encodes_multipart_parts() {
        use crate::message::SbiPart;

        let response = SbiResponse::ok()
            .with_body(r#"{"n2InfoContainer":{}}"#, "application/json")
            .with_part(SbiPart::with_content(
                "ngap-sm",
                crate::constants::content_type::APPLICATION_NGAP,
                Bytes::from_static(&[0x00, 0x15, 0xff]),
            ));
        let hyper_response = convert_response(response);

        let content_type = hyper_response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();
        assert!(crate::multipart::is_multipart_related(&content_type));

        // The encoded body decodes back to the JSON root + the binary part.
        let body = hyper_response.into_body();
        let bytes = futures_body_bytes(body);
        let decoded = crate::multipart::decode(&content_type, &bytes).unwrap();
        assert_eq!(decoded.json.as_deref(), Some(r#"{"n2InfoContainer":{}}"#));
        assert_eq!(decoded.parts.len(), 1);
        assert_eq!(decoded.parts[0].content_id.as_deref(), Some("ngap-sm"));
        assert_eq!(decoded.parts[0].data.as_ref(), &[0x00, 0x15, 0xff]);
    }

    /// Collect a Full<Bytes> body synchronously for tests.
    fn futures_body_bytes(body: Full<Bytes>) -> Bytes {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("value expected")
            .block_on(async move { body.collect().await.expect("value expected").to_bytes() })
    }

    #[tokio::test]
    async fn test_multipart_and_custom_headers_over_http2() {
        use crate::client::SbiClient;
        use crate::message::SbiPart;

        // Find a free localhost port for the test server.
        let port = crate::test_support::free_port();

        let server = SbiServer::new(SbiServerConfig::new(SocketAddr::from((
            [127, 0, 0, 1],
            port,
        ))));
        server
            .start(|request: SbiRequest| async move {
                // hyper delivered the custom header lowercased; the
                // case-insensitive accessor must still find it.
                let api_root = request.http.target_apiroot().cloned().unwrap_or_default();
                // The server glue decomposed the URI per TS 29.501 §4.4.
                let service = request.header.service_name.clone().unwrap_or_default();
                // Echo the decoded binary part straight back.
                let part = request.http.parts.first().cloned();
                let mut response = SbiResponse::ok().with_body(
                    format!(r#"{{"apiRoot":"{api_root}","svc":"{service}"}}"#),
                    "application/json",
                );
                if let Some(part) = part {
                    response = response.with_part(part);
                }
                response
            })
            .await
            .expect("value expected");

        let nas_bytes: &[u8] = &[0x7e, 0x00, 0xff, 0x0d, 0x0a, 0x00];
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let request = SbiRequest::post("/namf-comm/v1/ue-contexts/imsi-1/n1-n2-messages")
            .with_json_body(&serde_json::json!({
                "n1MessageContainer": {"n1MessageContent": {"contentId": "5gnas-sm"}}
            }))
            .expect("value expected")
            .with_header("3gpp-Sbi-Target-apiRoot", "https://amf.example:7777")
            .with_part(SbiPart::with_content(
                "5gnas-sm",
                crate::constants::content_type::APPLICATION_5GNAS,
                Bytes::copy_from_slice(nas_bytes),
            ));

        let response = client.send_request(request).await.expect("value expected");
        assert!(response.is_success());
        let body = response.http.content.as_deref().expect("value expected");
        assert!(body.contains("https://amf.example:7777"));
        assert!(body.contains("namf-comm"));
        // The binary part survived client encode -> server decode -> server
        // encode -> client decode byte-exact.
        assert_eq!(response.http.parts.len(), 1);
        assert_eq!(
            response.http.parts[0].content_id.as_deref(),
            Some("5gnas-sm")
        );
        assert_eq!(response.http.parts[0].data.as_ref(), nas_bytes);

        server.stop().await.expect("value expected");
    }

    // --- T1.4: request-body size limit ---

    #[test]
    fn test_default_config_has_dos_limits() {
        let config = SbiServerConfig::default();
        assert_eq!(config.max_request_body_size, DEFAULT_MAX_REQUEST_BODY_SIZE);
        assert_eq!(
            config.max_concurrent_streams,
            Some(DEFAULT_MAX_CONCURRENT_STREAMS)
        );
        assert_eq!(config.max_frame_size, Some(DEFAULT_MAX_FRAME_SIZE));
        assert_eq!(
            config.max_header_list_size,
            Some(DEFAULT_MAX_HEADER_LIST_SIZE)
        );
    }

    /// Pick a free localhost port and start an echo server with the given
    /// config + handler, returning the bound port.
    async fn start_test_server<H: SbiRequestHandler>(
        mut config: SbiServerConfig,
        handler: H,
    ) -> (SbiServer, u16) {
        let port = crate::test_support::free_port();
        config.addr = SocketAddr::from(([127, 0, 0, 1], port));
        let server = SbiServer::new(config);
        server.start(handler).await.expect("value expected");
        (server, port)
    }

    #[tokio::test]
    async fn test_oversize_body_rejected_with_413() {
        use crate::client::SbiClient;

        // Tiny cap so the test body is unambiguously oversize.
        let config = SbiServerConfig::default().with_max_request_body_size(64);
        let (server, port) =
            start_test_server(config, |_req: SbiRequest| async move { SbiResponse::ok() }).await;

        let client = SbiClient::with_host_port("127.0.0.1", port);

        // A body well over the 64-byte cap is rejected with 413 before the
        // handler runs.
        let big = "x".repeat(10_000);
        let request = SbiRequest::post("/ntest/v1/echo").with_body(&big, "text/plain");
        let response = client.send_request(request).await.expect("value expected");
        assert_eq!(response.status, 413);
        assert_eq!(
            response.http.get_header("content-type").map(String::as_str),
            Some("application/problem+json")
        );

        // A small body under the cap still succeeds (success path preserved).
        let small = SbiRequest::post("/ntest/v1/echo").with_body("ok", "text/plain");
        let ok = client.send_request(small).await.expect("value expected");
        assert_eq!(ok.status, 200);

        server.stop().await.expect("value expected");
    }

    // --- T1.3: handler panic guard ---

    #[tokio::test]
    async fn test_catch_handler_panic_unit() {
        // A panicking future is converted to Err(()).
        let panicking = async { panic!("boom in handler") };
        assert!(catch_handler_panic(panicking).await.is_err());

        // A normal future passes its value through.
        let ok = async { SbiResponse::ok() };
        let response = catch_handler_panic(ok).await.expect("non-panicking ok");
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn test_panicking_handler_yields_500() {
        use crate::client::SbiClient;

        let (server, port) =
            start_test_server(SbiServerConfig::default(), |_req: SbiRequest| async move {
                panic!("handler blew up");
                #[allow(unreachable_code)]
                SbiResponse::ok()
            })
            .await;

        let client = SbiClient::with_host_port("127.0.0.1", port);

        // First request hits the panicking handler: 500 problem+json, and the
        // connection task survives (no torn-down connection).
        let request = SbiRequest::post("/ntest/v1/boom").with_body("{}", "application/json");
        let response = client.send_request(request).await.expect("value expected");
        assert_eq!(response.status, 500);
        assert_eq!(
            response.http.get_header("content-type").map(String::as_str),
            Some("application/problem+json")
        );
        let problem: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["status"], 500);

        // A second request still gets a 500 (the server keeps serving rather
        // than the whole connection dying after the first panic).
        let again = SbiRequest::post("/ntest/v1/boom").with_body("{}", "application/json");
        let response2 = client.send_request(again).await.expect("value expected");
        assert_eq!(response2.status, 500);

        server.stop().await.expect("value expected");
    }

    // --- T1.2: server-level expected-audience wiring ---

    /// Build an ES256 token with an explicit `aud` plus a matching JWKS.
    fn token_jwks_with_aud(aud: &str) -> (String, serde_json::Value) {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};

        let sk = SigningKey::from_slice(&[7u8; 32]).expect("valid scalar");
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"k1"}"#);
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let claims = serde_json::json!({
            "iss": "NRF", "sub": "amf-1", "aud": aud, "scope": "nudm-sdm", "exp": exp
        });
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let sig: Signature = sk.sign(format!("{header}.{payload}").as_bytes());
        let token = format!(
            "{header}.{payload}.{}",
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        );

        let point = sk.verifying_key().to_encoded_point(false);
        let jwks = serde_json::json!({"keys":[{
            "kty":"EC","crv":"P-256","alg":"ES256","kid":"k1",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }]});
        (token, jwks)
    }

    #[tokio::test]
    async fn test_server_oauth_audience_enforced() {
        // Token's aud is "UDM"; the verifier expects "UDM": authorized.
        let (token, jwks) = token_jwks_with_aud("UDM");
        let verifier = OAuthVerifier {
            keys: OAuthKeySource::Static(jwks.clone()),
            expected_audience: Some("UDM".into()),
        };
        let header = format!("Bearer {token}");
        assert!(verifier.authorize(Some(&header), None).await.is_ok());

        // Same token, but the verifier expects "AMF": rejected as
        // AuthorizationFailed (mapped to 401 on the wire).
        let wrong = OAuthVerifier {
            keys: OAuthKeySource::Static(jwks.clone()),
            expected_audience: Some("AMF".into()),
        };
        let err = wrong.authorize(Some(&header), None).await.unwrap_err();
        assert!(matches!(err, SbiError::AuthorizationFailed(_)));

        // No expectation: audience not checked (current behaviour preserved).
        let none = OAuthVerifier {
            keys: OAuthKeySource::Static(jwks),
            expected_audience: None,
        };
        assert!(none.authorize(Some(&header), None).await.is_ok());
    }

    #[tokio::test]
    async fn test_server_oauth_scope_enforced() {
        // The helper's token carries scope "nudm-sdm".
        let (token, jwks) = token_jwks_with_aud("UDM");
        let verifier = OAuthVerifier {
            keys: OAuthKeySource::Static(jwks),
            expected_audience: None,
        };
        let header = format!("Bearer {token}");

        // Invoked service is in scope -> authorized.
        assert!(verifier
            .authorize(Some(&header), Some("nudm-sdm"))
            .await
            .is_ok());

        // A different service the token is not scoped for -> 401.
        let err = verifier
            .authorize(Some(&header), Some("nudm-uecm"))
            .await
            .unwrap_err();
        assert!(matches!(err, SbiError::AuthorizationFailed(_)));

        // No required scope (e.g. a non-service path) -> scope check skipped.
        assert!(verifier.authorize(Some(&header), None).await.is_ok());
    }
}
