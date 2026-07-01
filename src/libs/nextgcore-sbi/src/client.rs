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

/// Fill an `N`-byte buffer with CSPRNG output, never returning all-zero
/// (sbi-09). W3C Trace Context forbids an all-zero trace-id/span-id; the
/// retry makes that pathological case impossible rather than merely unlikely.
fn random_nonzero_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut buf = [0u8; N];
    let mut rng = rand::rng();
    loop {
        rng.fill_bytes(&mut buf);
        if buf.iter().any(|&b| b != 0) {
            return buf;
        }
    }
}

/// Generate a random 16-byte W3C trace-id (sbi-09). Random, not clock-derived,
/// so trace-ids are unpredictable and collision-resistant under load.
fn new_trace_id() -> [u8; 16] {
    random_nonzero_bytes::<16>()
}

/// Generate a random 8-byte W3C span ID (sbi-09).
fn new_span_id() -> [u8; 8] {
    random_nonzero_bytes::<8>()
}

// ── T1.5b: TLS exporter hook (client side) ──────────────────────────────────
// The SBI client is used by every NF, but only seppd needs the N32-f TLS
// exporter secret. Rather than adding a hard compile-time dependency on the
// seppd crate from nextgcore-sbi, we let seppd register a one-time callback at
// startup. The hook receives `(peer_fqdn, secret_bytes)` and deposits it into
// the seppd-side store (`set_n32c_tls_exporter_secret`).
//
// Design: `Option<fn(&str, Vec<u8>)>` stored in a `OnceLock` so it is both
// `Send + Sync` and requires no heap allocation for the function pointer.
// Non-SEPP NFs never call `register_tls_exporter_hook`, so the lock stays
// `None` and the fast-path is a single load.

/// Type alias for the TLS exporter deposit hook.
pub type TlsExporterHook = fn(&str, Vec<u8>);

static TLS_EXPORTER_HOOK: TlsExporterHookSlot = TlsExporterHookSlot::new();

struct TlsExporterHookSlot(std::sync::OnceLock<TlsExporterHook>);

impl TlsExporterHookSlot {
    const fn new() -> Self {
        Self(std::sync::OnceLock::new())
    }

    fn load(&self) -> Option<TlsExporterHook> {
        self.0.get().copied()
    }

    fn store(&self, hook: TlsExporterHook) {
        // Ignore if already set (e.g. called twice in tests).
        let _ = self.0.set(hook);
    }
}

// SAFETY: fn pointers are Send+Sync.
unsafe impl Send for TlsExporterHookSlot {}
unsafe impl Sync for TlsExporterHookSlot {}

/// Register a hook that the SBI client calls after every successful TLS
/// handshake to deposit the RFC 5705 N32-f exporter secret.
///
/// Only seppd needs to call this. The hook is invoked with `(peer_fqdn,
/// secret_bytes)`. Call once at NF startup before the first outbound
/// connection is made. Subsequent calls are silently ignored.
///
/// # Example (seppd startup)
/// ```ignore
/// nextgcore_sbi::client::register_tls_exporter_hook(
///     nextgcore_seppd::n32c_handler::set_n32c_tls_exporter_secret
/// );
/// ```
pub fn register_tls_exporter_hook(hook: TlsExporterHook) {
    TLS_EXPORTER_HOOK.store(hook);
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

/// Maximum number of 307/308 redirects the client follows before giving up
/// (sbi-04). TS 29.500 §6.4.2.4 / §6.10.9: an SCP/SEPP may answer with a
/// redirect; the consumer re-issues to the indicated target. A small bound
/// stops a redirect loop from spinning forever.
const MAX_REDIRECTS: u32 = 3;

/// Default backoff between retry attempts when no `Retry-After` is supplied
/// (sbi-05). Only consulted when a retry actually happens, i.e. when the retry
/// policy is opted into (`max_attempts > 1`); the default policy
/// (`max_attempts == 1`) never reaches this.
const DEFAULT_RETRY_BACKOFF: Duration = Duration::from_millis(200);

/// Bounded retry / NF-reselection policy (sbi-05).
///
/// **Dormant by default**: `max_attempts == 1` means a single attempt with no
/// retry loop and no backoff — byte-for-byte and call-sequence identical to the
/// pre-sbi-05 client. Set `max_attempts > 1` (via
/// [`SbiClient::with_retry_policy`]) to enable bounded retry of retryable
/// failures (connection errors, timeouts, 429/503) per TS 29.500 §6.5.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Total attempts including the first. `1` (default) disables retry.
    pub max_attempts: u32,
    /// Backoff between attempts when the response carries no `Retry-After`.
    pub base_backoff: Duration,
    /// Honour a `Retry-After` header (delta-seconds) on 429/503 responses
    /// (RFC 9110 §10.2.3) in preference to `base_backoff`.
    pub honor_retry_after: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        // max_attempts = 1 ⇒ no retry: preserves the prior single-attempt
        // behaviour unless a caller opts in.
        Self {
            max_attempts: 1,
            base_backoff: DEFAULT_RETRY_BACKOFF,
            honor_retry_after: true,
        }
    }
}

impl RetryPolicy {
    /// Build a policy with a given attempt budget (clamped to ≥ 1).
    pub fn with_max_attempts(max_attempts: u32) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            ..Default::default()
        }
    }

    /// Set the base backoff used when no `Retry-After` is present.
    pub fn with_base_backoff(mut self, backoff: Duration) -> Self {
        self.base_backoff = backoff;
        self
    }

    /// Enable or disable honouring the `Retry-After` response header.
    pub fn with_honor_retry_after(mut self, honor: bool) -> Self {
        self.honor_retry_after = honor;
        self
    }
}

/// Where to dial for a single send attempt. `None` (the default for the first
/// attempt) uses the client's pooled connection to `config.host:config.port`;
/// `Some` is used only when following a 307/308 redirect to a different
/// authority (sbi-04), where a fresh, non-pooled connection is made.
#[derive(Debug, Clone)]
struct ConnectTarget {
    scheme: UriScheme,
    host: String,
    port: u16,
}

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
/// Matches nextgcore_sbi_client_t
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
    /// This NF's own type, used to stamp `User-Agent` on outbound requests
    /// (sbi-03). `None` (default) preserves the prior no-header behaviour.
    client_nf_type: Option<NfType>,
    /// This NF's own instance ID / FQDN, combined with `client_nf_type` as the
    /// `User-Agent` value `<NFTYPE>-<id>` (sbi-03).
    client_nf_id: Option<String>,
    /// Bounded retry / NF-reselection policy (sbi-05). Defaults to a single
    /// attempt (`max_attempts == 1`), so retry is dormant unless opted in.
    retry: RetryPolicy,
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
            client_nf_type: None,
            client_nf_id: None,
            retry: RetryPolicy::default(),
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

    /// Set this NF's own identity for the outbound `User-Agent` header (sbi-03).
    ///
    /// Per TS 29.500 Table 5.2.2.2-1, `User-Agent` should be included on every
    /// SBI request to identify the requester NF type (an SCP derives the
    /// requester NF type from it for delegated discovery, NOTE 3). When set,
    /// every request without a caller-supplied `User-Agent` carries
    /// `<NFTYPE>-<nfInstanceId>` (e.g. `AMF-<uuid>`). Unset (default) preserves
    /// the prior behaviour of emitting no `User-Agent`.
    pub fn with_client_identity(mut self, nf_type: NfType, nf_id: impl Into<String>) -> Self {
        self.client_nf_type = Some(nf_type);
        self.client_nf_id = Some(nf_id.into());
        self
    }

    /// Set the bounded retry / NF-reselection policy (sbi-05).
    ///
    /// The default policy is a single attempt (`max_attempts == 1`), i.e. retry
    /// is **dormant** and the send path is identical to the pre-sbi-05 client.
    /// Supplying a policy with `max_attempts > 1` enables bounded retry of
    /// retryable failures (connection errors, timeouts, 429/503) with backoff
    /// and optional `Retry-After` honouring.
    pub fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
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

    /// Connect to the configured server (`config.host:config.port`).
    ///
    /// Thin forwarder over [`connect_target`](Self::connect_target) with the
    /// client's configured scheme/host/port, so the pooled connection path is
    /// byte-for-byte identical to the pre-refactor inline code.
    async fn connect(&self) -> SbiResult<SendRequest<Full<Bytes>>> {
        self.connect_target(self.config.scheme, &self.config.host, self.config.port)
            .await
    }

    /// Open a fresh (non-pooled) connection to an explicit redirect target
    /// (sbi-04). Used only when following a 307/308 to a different authority.
    async fn connect_to(&self, target: &ConnectTarget) -> SbiResult<SendRequest<Full<Bytes>>> {
        self.connect_target(target.scheme, &target.host, target.port)
            .await
    }

    /// Connect to an arbitrary `scheme://host:port`, performing the TLS
    /// handshake (and N32-f exporter deposit) for `https`. The TLS material
    /// (CA / client cert / verify policy) is taken from the client config; only
    /// the dial target (scheme/host/port) is parametrised so the same logic
    /// serves both the configured target and a redirect target.
    async fn connect_target(
        &self,
        scheme: UriScheme,
        host: &str,
        port: u16,
    ) -> SbiResult<SendRequest<Full<Bytes>>> {
        let addr = format!("{host}:{port}");

        let stream = tokio::time::timeout(self.config.connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| SbiError::Timeout)?
            .map_err(|e| SbiError::ConnectionError(e.to_string()))?;

        if scheme == UriScheme::Https {
            let connector = self.build_tls_connector()?;
            let server_name = ServerName::try_from(host.to_string())
                .map_err(|e| SbiError::TlsError(format!("Invalid server name: {e}")))?;

            let tls_stream = tokio::time::timeout(
                self.config.connect_timeout,
                connector.connect(server_name, stream),
            )
            .await
            .map_err(|_| SbiError::Timeout)?
            .map_err(|e| SbiError::TlsError(format!("TLS handshake failed: {e}")))?;

            // ── T1.5b: extract RFC 5705 N32-f exporter secret (client side) ──
            // `get_ref()` on a tokio_rustls client TlsStream yields
            // `(&TcpStream, &ClientConnection)`. `ClientConnection` derefs to
            // `ConnectionCommon<ClientConnectionData>` which exposes
            // `export_keying_material`. We call this BEFORE `TokioIo::new()`
            // moves the stream, then deposit it into the SEPP-side store keyed
            // by the peer host so `take_n32c_tls_exporter_secret` can pick it
            // up during the N32-c exchange-params handshake.
            {
                let (_, client_conn) = tls_stream.get_ref();
                match crate::tls::export_n32_master_key(client_conn, None) {
                    Ok(secret) => {
                        log::debug!("N32 master key (64B) derived for peer {host}");
                        // The seppd n32c_handler consumes this via
                        // `take_n32c_tls_exporter_secret(peer_fqdn)`.
                        // We key by host (FQDN or IP) which the handler
                        // uses as the peer identifier.
                        //
                        // This import is resolved at link time only when
                        // nextgcore-seppd is in the binary; for other NFs
                        // the function is unused but not dead (the seppd
                        // crate re-exports it). We call it via the nextgcore-sbi
                        // public re-export to avoid a hard dep on seppd here.
                        // The side-channel store lives in seppd; we reach it
                        // through a thin hook registered at startup (below).
                        // For now, store it on the request side via the hook
                        // if one is registered; otherwise log and discard.
                        if let Some(hook) = TLS_EXPORTER_HOOK.load() {
                            hook(host, secret);
                        } else {
                            log::debug!(
                                "No TLS exporter hook registered; secret for {host} discarded \
                                 (non-SEPP NF)"
                            );
                        }
                    }
                    Err(e) => {
                        log::warn!("N32-f TLS exporter failed for peer {host}: {e}");
                    }
                }
            }

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

    /// Send an SBI request and receive a response.
    ///
    /// Layering (all dormant by default):
    /// * Outbound headers (OAuth2 Bearer, `User-Agent`, `x-request-id`,
    ///   `traceparent`) are stamped once in [`prepare_request`](Self::prepare_request).
    /// * **sbi-04**: 307/308 responses are followed (bounded by
    ///   [`MAX_REDIRECTS`]) in [`send_following_redirects`](Self::send_following_redirects).
    /// * **sbi-05**: retryable failures are retried per the
    ///   [`RetryPolicy`]; with the default `max_attempts == 1` the retry loop is
    ///   skipped entirely (fast path), so a normal request is byte-for-byte and
    ///   call-sequence identical to the pre-sbi-04/05 client.
    pub async fn send_request(&self, request: SbiRequest) -> SbiResult<SbiResponse> {
        if self.retry.max_attempts <= 1 {
            // Fast path: a single attempt, no retry loop, no request clone.
            return self.send_following_redirects(request).await;
        }
        self.send_with_retry(request).await
    }

    /// Stamp the standard outbound headers on `request` exactly once before the
    /// (possibly retried / redirected) send. Mutations are identical, and in the
    /// same order, to the pre-refactor inline code.
    async fn prepare_request(&self, request: &mut SbiRequest) {
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

        // ── sbi-03: stamp User-Agent with this NF's identity ─────────────────
        // TS 29.500 Table 5.2.2.2-1: User-Agent should be on every SBI request
        // to identify the requester NF type. Only set when an identity was
        // configured and the caller did not supply their own User-Agent.
        if let (Some(nf_type), Some(nf_id)) = (&self.client_nf_type, &self.client_nf_id) {
            if request
                .http
                .get_header(crate::constants::header::USER_AGENT)
                .is_none()
            {
                request.http.set_header(
                    crate::constants::header::USER_AGENT,
                    format!("{}-{}", nf_type.as_server_token(), nf_id),
                );
            }
        }

        // ── T6.4: propagate correlation / request ID outbound ────────────────
        // If the SbiRequest carries a non-empty correlation_id (set by the
        // server glue when the request arrived from a peer), echo it as
        // `x-request-id` so the downstream NF can correlate log entries.
        // Do not overwrite a caller-supplied `x-request-id`.
        if !request.correlation_id.is_empty() && request.http.get_header("x-request-id").is_none() {
            request
                .http
                .set_header("x-request-id", request.correlation_id.clone());
        }

        // G32/G43: Propagate W3C traceparent header for distributed tracing.
        // If the incoming request already carries a traceparent (set by caller)
        // we respect it; otherwise we generate a new child span. When a
        // correlation_id was extracted from an inbound traceparent trace-id we
        // reuse it here so the outbound trace-id matches the inbound one.
        if request.http.get_header("traceparent").is_none() {
            // Generate a minimal traceparent for a new trace with a sampled
            // root span (flags=01). The inbound-traceparent reuse path is the
            // guard above: a caller-supplied traceparent is left untouched.
            // sbi-09: trace-id and span-id are CSPRNG-random (W3C Trace
            // Context), not derived from the wall clock.
            let trace_id = new_trace_id();
            let span_id = new_span_id();
            let traceparent = format!("00-{}-{}-01", hex::encode(trace_id), hex::encode(span_id),);
            request.http.set_header("traceparent", traceparent);
        }
    }

    /// sbi-05 retry wrapper. Only entered when `max_attempts > 1`. Re-runs the
    /// full redirect-following send on a retryable failure (connection error,
    /// timeout, 429/503) until the attempt budget is spent, with backoff
    /// honouring `Retry-After` when present.
    async fn send_with_retry(&self, request: SbiRequest) -> SbiResult<SbiResponse> {
        let max_attempts = self.retry.max_attempts.max(1);
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let last = attempt >= max_attempts;
            match self.send_following_redirects(request.clone()).await {
                Ok(resp) => {
                    if !last && is_retryable_status(resp.status) {
                        if let Some(delay) = self.retry_delay(Some(&resp)) {
                            tokio::time::sleep(delay).await;
                        }
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    if !last && e.is_retryable() {
                        if let Some(delay) = self.retry_delay(None) {
                            tokio::time::sleep(delay).await;
                        }
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }

    /// Compute the backoff before the next retry: `Retry-After` (delta-seconds)
    /// when honoured and present, otherwise the policy's base backoff. `None`
    /// means "no wait".
    fn retry_delay(&self, response: Option<&SbiResponse>) -> Option<Duration> {
        if self.retry.honor_retry_after {
            if let Some(after) = response
                .and_then(|r| r.http.get_header("Retry-After"))
                .and_then(|v| parse_retry_after(v))
            {
                return Some(after);
            }
        }
        if self.retry.base_backoff.is_zero() {
            None
        } else {
            Some(self.retry.base_backoff)
        }
    }

    /// sbi-04 redirect follower. Stamps the outbound headers once, then sends;
    /// on a 307/308 with a usable `Location` it re-dials the indicated target
    /// (honouring `3gpp-Sbi-Target-apiRoot`), preserving method + body, bounded
    /// by [`MAX_REDIRECTS`]. A normal (non-redirect) response takes a single
    /// `send_once` call against the pooled connection — identical to before.
    async fn send_following_redirects(&self, mut request: SbiRequest) -> SbiResult<SbiResponse> {
        self.prepare_request(&mut request).await;

        // First attempt uses the pooled connection (target = None).
        let mut target: Option<ConnectTarget> = None;
        let mut redirects_left = MAX_REDIRECTS;
        loop {
            let response = self.send_once(&request, target.as_ref()).await?;

            // sbi-04: follow a 307/308 redirect when a budget remains.
            if matches!(response.status, 307 | 308) {
                match next_redirect(&response)? {
                    Some((new_uri, new_target)) => {
                        if redirects_left == 0 {
                            return Err(SbiError::ClientError(
                                "redirect loop: exceeded maximum redirects".into(),
                            ));
                        }
                        redirects_left -= 1;
                        // 307/308 preserve the method and body; re-target the
                        // request URI. The absolute Location is authoritative,
                        // so any pre-existing query params are dropped to avoid
                        // double-encoding.
                        request.header.uri = new_uri;
                        request.http.params.clear();
                        target = Some(new_target);
                        continue;
                    }
                    // 307/308 without a usable Location: nothing to follow —
                    // hand the response back to the caller verbatim.
                    None => return Ok(response),
                }
            }

            return Ok(response);
        }
    }

    /// Perform exactly one request/response round-trip over either the pooled
    /// connection (`target == None`) or a fresh connection to a redirect target
    /// (`target == Some`). Does not mutate `request`.
    async fn send_once(
        &self,
        request: &SbiRequest,
        target: Option<&ConnectTarget>,
    ) -> SbiResult<SbiResponse> {
        let mut sender = match target {
            None => self.get_connection().await?,
            Some(t) => self.connect_to(t).await?,
        };

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
        // (TS 29.500 §6.1.2.3). `send_once` never mutates `request`, so the
        // multipart Content-Type is computed locally and substituted for any
        // pre-existing Content-Type header below (matching the prior
        // set_header-then-iterate behaviour: exactly one Content-Type on the
        // wire).
        let mut multipart_content_type: Option<String> = None;
        let body_bytes: Bytes = if !request.http.parts.is_empty() {
            let boundary = crate::multipart::generate_boundary();
            multipart_content_type = Some(crate::multipart::content_type_with_boundary(&boundary));
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

        // Add headers. When a multipart body overrides Content-Type, skip any
        // caller-supplied Content-Type and stamp the multipart one once.
        for (key, value) in &request.http.headers {
            if multipart_content_type.is_some() && key.eq_ignore_ascii_case("content-type") {
                continue;
            }
            req_builder = req_builder.header(key.as_str(), value.as_str());
        }
        if let Some(ct) = multipart_content_type {
            req_builder = req_builder.header(crate::constants::header::CONTENT_TYPE, ct);
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

/// sbi-04: decide the next hop for a 307/308 response.
///
/// Returns `Some((new_request_uri, connect_target))` when the redirect is
/// followable, or `Ok(None)` when there is no usable `Location` (the caller
/// then hands the 307/308 back verbatim). The new connection target is taken
/// from `3gpp-Sbi-Target-apiRoot` when present (TS 29.500 §6.10.x indirect
/// communication), otherwise from the `Location` authority. The new request URI
/// is the absolute `Location` (307/308 preserve method + body).
fn next_redirect(response: &SbiResponse) -> SbiResult<Option<(String, ConnectTarget)>> {
    let location = match response.http.get_header(crate::constants::header::LOCATION) {
        Some(l) if !l.trim().is_empty() => l.trim().to_string(),
        _ => return Ok(None),
    };
    // A relative Location cannot be re-dialled on its own; require an absolute
    // URI (as SBI mandates for 307/308).
    if !location.starts_with("http://") && !location.starts_with("https://") {
        return Ok(None);
    }
    // `3gpp-Sbi-Target-apiRoot`, when present, selects the producer apiRoot to
    // dial for indirect communication; otherwise dial Location's authority.
    let dial_uri = response
        .http
        .target_apiroot()
        .map(String::as_str)
        .unwrap_or(location.as_str());
    let target = parse_connect_target(dial_uri)?;
    Ok(Some((location, target)))
}

/// Parse an absolute `scheme://host[:port][/...]` URI into a dial target.
/// Defaults the port to 80 (`http`) / 443 (`https`) when absent.
fn parse_connect_target(uri: &str) -> SbiResult<ConnectTarget> {
    let (scheme, rest) = if let Some(r) = uri.strip_prefix("https://") {
        (UriScheme::Https, r)
    } else if let Some(r) = uri.strip_prefix("http://") {
        (UriScheme::Http, r)
    } else {
        return Err(SbiError::InvalidUri(format!(
            "redirect target is not an absolute URI: {uri}"
        )));
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port = p.parse::<u16>().map_err(|_| {
                SbiError::InvalidUri(format!("invalid port in redirect target: {uri}"))
            })?;
            (h.to_string(), port)
        }
        None => {
            let default_port = match scheme {
                UriScheme::Https => 443,
                _ => 80,
            };
            (authority.to_string(), default_port)
        }
    };
    if host.is_empty() {
        return Err(SbiError::InvalidUri(format!(
            "redirect target has no host: {uri}"
        )));
    }
    Ok(ConnectTarget { scheme, host, port })
}

/// sbi-05: which response status codes are retryable. Mirrors the HTTP arms of
/// [`SbiError::is_retryable`] — only 429 (Too Many Requests) and 503 (Service
/// Unavailable), the codes TS 29.500 §6.5 marks for retransmission.
fn is_retryable_status(status: u16) -> bool {
    matches!(status, 429 | 503)
}

/// sbi-05: parse a `Retry-After` value (RFC 9110 §10.2.3) into a `Duration`.
/// Supports the delta-seconds form (a non-negative integer). The HTTP-date form
/// is not parsed (no date dependency in this lib) and yields `None`, so the
/// caller falls back to its base backoff.
fn parse_retry_after(value: &str) -> Option<Duration> {
    value.trim().parse::<u64>().ok().map(Duration::from_secs)
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

    // --- sbi-09: randomized W3C traceparent trace-id / span-id ---

    #[test]
    fn test_trace_and_span_ids_are_random_and_nonzero() {
        // Two generated trace-ids/span-ids differ (random, not clock-derived)
        // and are never all-zero (W3C Trace Context requirement).
        let t1 = new_trace_id();
        let t2 = new_trace_id();
        assert_ne!(t1, t2, "successive trace-ids must differ");
        assert!(t1.iter().any(|&b| b != 0), "trace-id must not be all-zero");
        assert!(t2.iter().any(|&b| b != 0));

        let s1 = new_span_id();
        let s2 = new_span_id();
        assert_ne!(s1, s2, "successive span-ids must differ");
        assert!(s1.iter().any(|&b| b != 0), "span-id must not be all-zero");

        // Hex encodings are the W3C-mandated 32 / 16 chars.
        assert_eq!(hex::encode(t1).len(), 32);
        assert_eq!(hex::encode(s1).len(), 16);
    }

    // --- sbi-03: User-Agent on outbound requests ---

    /// Serve any path by echoing the request's `user-agent` header back in the
    /// JSON body. Returns the bound socket address.
    async fn serve_user_agent_echo() -> std::net::SocketAddr {
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
                        let ua = req
                            .headers()
                            .get("user-agent")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("<none>")
                            .to_string();
                        async move {
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                http_body_util::Full::new(bytes::Bytes::from(format!(
                                    r#"{{"user-agent":"{ua}"}}"#
                                ))),
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
    async fn test_user_agent_stamped_when_identity_set() {
        let addr = serve_user_agent_echo().await;
        let client = SbiClient::with_host_port("127.0.0.1", addr.port())
            .with_client_identity(NfType::Amf, "3fa85f64-5717-4562-b3fc-2c963f66afa6");

        let request = SbiRequest::get("/nudm-sdm/v1/imsi-1/am-data");
        let response = client.send_request(request).await.expect("request sent");
        let body = response.http.content.as_deref().expect("echo body");
        assert!(
            body.contains("AMF-3fa85f64-5717-4562-b3fc-2c963f66afa6"),
            "expected stamped User-Agent, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_user_agent_absent_when_no_identity() {
        // Default client (no identity) emits no User-Agent (prior behaviour).
        let addr = serve_user_agent_echo().await;
        let client = SbiClient::with_host_port("127.0.0.1", addr.port());
        let request = SbiRequest::get("/nudm-sdm/v1/imsi-1/am-data");
        let response = client.send_request(request).await.expect("request sent");
        let body = response.http.content.as_deref().expect("echo body");
        assert!(
            body.contains("<none>"),
            "expected no User-Agent, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_user_agent_caller_value_preserved() {
        let addr = serve_user_agent_echo().await;
        let client = SbiClient::with_host_port("127.0.0.1", addr.port())
            .with_client_identity(NfType::Amf, "amf-1");
        // A caller-supplied User-Agent is not overwritten.
        let request = SbiRequest::get("/nudm-sdm/v1/imsi-1/am-data")
            .with_header("User-Agent", "custom-agent/1.0");
        let response = client.send_request(request).await.expect("request sent");
        let body = response.http.content.as_deref().expect("echo body");
        assert!(
            body.contains("custom-agent/1.0"),
            "caller User-Agent should be preserved, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_oauth2_explicit_header_not_overwritten() {
        let addr = serve_token_and_echo("nrf-token").await;
        let nrf_uri = format!("http://{addr}");
        let oauth2 = Arc::new(OAuth2Client::new(nrf_uri, "amf-instance-1", NfType::Amf));
        let client =
            SbiClient::with_host_port("127.0.0.1", addr.port()).with_oauth2(oauth2, NfType::Udm);

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

    // --- helper-fn unit tests (sbi-04 / sbi-05) ---

    #[test]
    fn test_parse_connect_target() {
        let t = parse_connect_target("http://10.0.0.1:8080/x/y").unwrap();
        assert_eq!(t.scheme, UriScheme::Http);
        assert_eq!(t.host, "10.0.0.1");
        assert_eq!(t.port, 8080);

        // Default ports per scheme when the authority omits a port.
        assert_eq!(parse_connect_target("http://nrf").unwrap().port, 80);
        let s = parse_connect_target("https://nrf.local").unwrap();
        assert_eq!(s.scheme, UriScheme::Https);
        assert_eq!(s.port, 443);

        // A relative / schemeless target is rejected.
        assert!(parse_connect_target("/relative/path").is_err());
        assert!(parse_connect_target("http://:8080").is_err());
    }

    #[test]
    fn test_is_retryable_status() {
        assert!(is_retryable_status(429));
        assert!(is_retryable_status(503));
        assert!(!is_retryable_status(200));
        assert!(!is_retryable_status(404));
        assert!(!is_retryable_status(500));
    }

    #[test]
    fn test_parse_retry_after() {
        assert_eq!(parse_retry_after("1"), Some(Duration::from_secs(1)));
        assert_eq!(parse_retry_after(" 120 "), Some(Duration::from_secs(120)));
        // HTTP-date form is not parsed (no date dep) → None (caller backs off).
        assert_eq!(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"), None);
        assert_eq!(parse_retry_after("-3"), None);
    }

    #[test]
    fn test_retry_policy_default_is_dormant() {
        // The default client uses a single-attempt (dormant) retry policy.
        let client = SbiClient::with_host_port("127.0.0.1", 1);
        assert_eq!(client.retry.max_attempts, 1);
    }

    // --- test servers for redirect / retry ---

    /// Serve a fixed `status` with the supplied headers and body on every
    /// request. Counts the requests it received in `counter`.
    async fn serve_fixed(
        status: u16,
        headers: Vec<(String, String)>,
        body: &'static str,
        counter: Arc<AtomicUsize>,
    ) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let headers = headers.clone();
                let counter = counter.clone();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let svc = hyper::service::service_fn(move |_req: hyper::Request<Incoming>| {
                        let headers = headers.clone();
                        let counter = counter.clone();
                        async move {
                            counter.fetch_add(1, Ordering::SeqCst);
                            let mut builder = hyper::Response::builder().status(status);
                            for (k, v) in &headers {
                                builder = builder.header(k.as_str(), v.as_str());
                            }
                            Ok::<_, std::convert::Infallible>(
                                builder
                                    .body(http_body_util::Full::new(bytes::Bytes::from(body)))
                                    .unwrap(),
                            )
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

    /// Serve 200 echoing the request method + body. Counts requests.
    async fn serve_echo_method_body(counter: Arc<AtomicUsize>) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let counter = counter.clone();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                        let counter = counter.clone();
                        let method = req.method().to_string();
                        async move {
                            counter.fetch_add(1, Ordering::SeqCst);
                            let body = req
                                .into_body()
                                .collect()
                                .await
                                .map(|c| c.to_bytes())
                                .unwrap_or_default();
                            let payload = format!(
                                r#"{{"method":"{method}","body":"{}"}}"#,
                                String::from_utf8_lossy(&body)
                            );
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                http_body_util::Full::new(bytes::Bytes::from(payload)),
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

    /// Serve 503 the first `fail_times` requests, then 200 (echoing body).
    async fn serve_503_then_ok(
        fail_times: usize,
        counter: Arc<AtomicUsize>,
    ) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let counter = counter.clone();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let svc = hyper::service::service_fn(move |_req: hyper::Request<Incoming>| {
                        let counter = counter.clone();
                        async move {
                            let n = counter.fetch_add(1, Ordering::SeqCst);
                            let (status, body) = if n < fail_times {
                                (503u16, "unavailable")
                            } else {
                                (200u16, "ok")
                            };
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(status)
                                    .body(http_body_util::Full::new(bytes::Bytes::from(body)))
                                    .unwrap(),
                            )
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

    // --- (a) a normal 200 request is unchanged ---

    #[tokio::test]
    async fn test_normal_request_single_call_unchanged() {
        let counter = Arc::new(AtomicUsize::new(0));
        let addr = serve_echo_method_body(counter.clone()).await;
        let client = SbiClient::with_host_port("127.0.0.1", addr.port());

        let request = SbiRequest::post("/nudm-sdm/v1/imsi-1/x").with_body("hello", "text/plain");
        let response = client.send_request(request).await.expect("request sent");
        assert_eq!(response.status, 200);
        let body = response.http.content.as_deref().unwrap();
        assert!(body.contains(r#""method":"POST""#), "got: {body}");
        assert!(body.contains(r#""body":"hello""#), "got: {body}");
        // Exactly one round-trip: no redirect, no retry.
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // --- (b) a 307/308 with target-apiRoot is followed to the new root ---

    #[tokio::test]
    async fn test_redirect_307_honours_target_apiroot() {
        // Final producer: echoes the POST body at 200.
        let final_count = Arc::new(AtomicUsize::new(0));
        let final_addr = serve_echo_method_body(final_count.clone()).await;

        // Redirector: 307 with a *bogus* Location authority but a valid
        // 3gpp-Sbi-Target-apiRoot → success proves target-apiRoot is dialled.
        let redir_count = Arc::new(AtomicUsize::new(0));
        let redir_addr = serve_fixed(
            307,
            vec![
                (
                    "Location".to_string(),
                    "http://127.0.0.1:1/redirected".to_string(),
                ),
                (
                    "3gpp-Sbi-Target-apiRoot".to_string(),
                    format!("http://{final_addr}"),
                ),
            ],
            "redirecting",
            redir_count.clone(),
        )
        .await;

        let client = SbiClient::with_host_port("127.0.0.1", redir_addr.port());
        let request =
            SbiRequest::post("/nudm-sdm/v1/imsi-1/x").with_body("payload-307", "text/plain");
        let response = client
            .send_request(request)
            .await
            .expect("redirect followed");

        assert_eq!(response.status, 200);
        let body = response.http.content.as_deref().unwrap();
        assert!(
            body.contains(r#""method":"POST""#),
            "method preserved: {body}"
        );
        assert!(body.contains("payload-307"), "body preserved: {body}");
        assert_eq!(redir_count.load(Ordering::SeqCst), 1);
        assert_eq!(final_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_redirect_308_follows_location_without_apiroot() {
        let final_count = Arc::new(AtomicUsize::new(0));
        let final_addr = serve_echo_method_body(final_count.clone()).await;

        // 308 with only a Location (no target-apiRoot): dial Location's authority.
        let redir_count = Arc::new(AtomicUsize::new(0));
        let redir_addr = serve_fixed(
            308,
            vec![(
                "Location".to_string(),
                format!("http://{final_addr}/redirected"),
            )],
            "moved",
            redir_count.clone(),
        )
        .await;

        let client = SbiClient::with_host_port("127.0.0.1", redir_addr.port());
        let response = client
            .send_request(SbiRequest::get("/nudm-sdm/v1/imsi-1/x"))
            .await
            .expect("redirect followed");
        assert_eq!(response.status, 200);
        assert_eq!(final_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_redirect_budget_exhaustion_errors() {
        // Always 307 pointing back at itself → exceeds MAX_REDIRECTS.
        let count = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let self_loc = format!("http://{addr}/loop");
        let count2 = count.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let self_loc = self_loc.clone();
                let count2 = count2.clone();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let svc = hyper::service::service_fn(move |_req: hyper::Request<Incoming>| {
                        let self_loc = self_loc.clone();
                        let count2 = count2.clone();
                        async move {
                            count2.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(307)
                                    .header("Location", self_loc.as_str())
                                    .body(http_body_util::Full::new(bytes::Bytes::from("loop")))
                                    .unwrap(),
                            )
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

        let client = SbiClient::with_host_port("127.0.0.1", addr.port());
        let err = client
            .send_request(SbiRequest::get("/x/v1/y"))
            .await
            .expect_err("redirect loop must error");
        assert!(matches!(err, SbiError::ClientError(_)), "got: {err:?}");
        // 1 initial + MAX_REDIRECTS follows = 4 round-trips.
        assert_eq!(count.load(Ordering::SeqCst), (MAX_REDIRECTS + 1) as usize);
    }

    // --- (c) max_attempts == 1 does not retry ---

    #[tokio::test]
    async fn test_max_attempts_one_does_not_retry() {
        let count = Arc::new(AtomicUsize::new(0));
        let addr = serve_fixed(503, vec![], "unavailable", count.clone()).await;
        // Default client: single attempt (dormant retry).
        let client = SbiClient::with_host_port("127.0.0.1", addr.port());
        let response = client
            .send_request(SbiRequest::get("/x/v1/y"))
            .await
            .expect("503 is returned, not retried");
        assert_eq!(response.status, 503);
        assert_eq!(count.load(Ordering::SeqCst), 1, "must not retry by default");
    }

    #[tokio::test]
    async fn test_retry_recovers_after_503() {
        let count = Arc::new(AtomicUsize::new(0));
        // 503 once, then 200.
        let addr = serve_503_then_ok(1, count.clone()).await;
        let client = SbiClient::with_host_port("127.0.0.1", addr.port()).with_retry_policy(
            RetryPolicy::with_max_attempts(3).with_base_backoff(Duration::from_millis(1)),
        );
        let response = client
            .send_request(SbiRequest::get("/x/v1/y"))
            .await
            .expect("retry recovers");
        assert_eq!(response.status, 200);
        assert_eq!(count.load(Ordering::SeqCst), 2, "one retry then success");
    }

    #[tokio::test]
    async fn test_retry_gives_up_after_budget() {
        let count = Arc::new(AtomicUsize::new(0));
        let addr = serve_fixed(503, vec![], "down", count.clone()).await;
        let client = SbiClient::with_host_port("127.0.0.1", addr.port()).with_retry_policy(
            RetryPolicy::with_max_attempts(2).with_base_backoff(Duration::from_millis(1)),
        );
        let response = client
            .send_request(SbiRequest::get("/x/v1/y"))
            .await
            .expect("returns last 503");
        assert_eq!(response.status, 503);
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "exactly max_attempts tries"
        );
    }
}
