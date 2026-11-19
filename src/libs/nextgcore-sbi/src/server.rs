//! SBI HTTP/2 Server
//!
//! HTTP/2 server implementation using hyper for SBI communication.
//! Matches the interface in lib/sbi/server.h

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::Service;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio_rustls::TlsAcceptor;

pub use crate::callback_auth::OAuth2CallbackExemption;
use crate::error::{SbiError, SbiResult};
use crate::message::{SbiHttpMessage, SbiRequest, SbiResponse};
use crate::overload::OverloadReporter;
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

/// #1811: maps a request's `(method, uri)` to the resource/operation-level
/// OAuth2 scope it needs beyond the service-level scope, if any.
pub type OAuth2ResourceScopeFn = fn(&str, &str) -> Option<&'static str>;

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
    /// With `verify_client`: request a client certificate but admit a client
    /// that presents none (#1617). A presented certificate must still verify
    /// against `verify_client_cacert`. Default `false` (a certificate is
    /// required).
    pub verify_client_optional: bool,
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
    /// #1421: callback routes this NF serves that are admitted WITHOUT a bearer
    /// token when `require_oauth2` is enabled, because the notification
    /// operation does not use OAuth 2.0 (TS 33.501 §13.4.1, TS 29.500 §6.10.7 NOTE).
    /// Each one is an exact route shape plus the NF's check of the
    /// per-subscription token in its path (see [`crate::callback_auth`]); a
    /// request that is not one of them, or whose token the NF does not hold,
    /// still needs a valid bearer. Empty by default: every route requires a
    /// token. Not consulted when `require_oauth2` is off.
    pub oauth2_callback_exemptions: Vec<OAuth2CallbackExemption>,
    /// #1811: the resource/operation-level scope a request needs on top of the
    /// service-level one (TS 33.501 §13.4.1.2, TS 29.500 §6.7.3), given its
    /// method and URI; normally [`crate::resource_scope::required_resource_scope`].
    /// When it returns `Some`, a verified token whose scope lacks that entry is
    /// refused 403 `insufficient_scope` before the handler runs. `None` (default)
    /// checks the service-level scope only. Only consulted when `require_oauth2`
    /// is enabled.
    pub oauth2_resource_scopes: Option<OAuth2ResourceScopeFn>,
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
    /// #65: producer-side overload reporter. When its metric is non-zero, every
    /// response carries `3gpp-Sbi-Oci` so consumers can apply TS 29.500 §6.4.2.2
    /// abatement.
    ///
    /// `None` (the default) now means **this process's own reporter**
    /// ([`crate::overload::self_overload_reporter`]), which #273 drives from the
    /// NF's `NFProfile.load` gauge on each heartbeat tick. That reporter sits at
    /// metric 0 until something publishes a load, so a process that never does —
    /// every test binary — still emits no OCI. `Some` overrides it for an NF that
    /// wants a reporter of its own.
    ///
    /// The NF owns the metric — see [`OverloadReporter`] for why this layer does
    /// not try to measure load itself.
    pub overload_reporter: Option<Arc<OverloadReporter>>,
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
            verify_client_optional: false,
            require_oauth2: false,
            oauth2_jwks: None,
            oauth2_jwks_uri: None,
            oauth2_expected_audience: None,
            oauth2_callback_exemptions: Vec::new(),
            oauth2_resource_scopes: None,
            max_request_body_size: DEFAULT_MAX_REQUEST_BODY_SIZE,
            max_concurrent_streams: Some(DEFAULT_MAX_CONCURRENT_STREAMS),
            max_frame_size: Some(DEFAULT_MAX_FRAME_SIZE),
            max_header_list_size: Some(DEFAULT_MAX_HEADER_LIST_SIZE),
            server_nf_type: None,
            server_nf_id: None,
            overload_reporter: None,
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

    /// Admit `exemption`'s callback route without a bearer token when its path
    /// carries a callback token the NF holds (#1421). Only consulted when
    /// `require_oauth2` is enabled.
    pub fn with_oauth2_callback_exemption(mut self, exemption: OAuth2CallbackExemption) -> Self {
        self.oauth2_callback_exemptions.push(exemption);
        self
    }

    /// [`Self::with_oauth2_callback_exemption`] for each of `exemptions`.
    pub fn with_oauth2_callback_exemptions(
        mut self,
        exemptions: impl IntoIterator<Item = OAuth2CallbackExemption>,
    ) -> Self {
        self.oauth2_callback_exemptions.extend(exemptions);
        self
    }

    /// Require, on top of the service-level scope, the resource-level scope
    /// `scopes` names for each request (#1811). Only enforced when
    /// `require_oauth2` is also enabled.
    pub fn with_oauth2_resource_scopes(mut self, scopes: OAuth2ResourceScopeFn) -> Self {
        self.oauth2_resource_scopes = Some(scopes);
        self
    }

    /// Attach a producer-side overload reporter (#65).
    ///
    /// Responses carry `3gpp-Sbi-Oci` whenever the reporter's metric is non-zero,
    /// which is the emission half of TS 29.500 §6.4 — present in `overload.rs`
    /// since sbi-08 but never reachable from a response until now.
    pub fn with_overload_reporter(mut self, reporter: Arc<OverloadReporter>) -> Self {
        self.overload_reporter = Some(reporter);
        self
    }

    /// Emit `3gpp-Sbi-Oci` from **this process's own** reporter, the one the
    /// heartbeat tick drives from the NF's `NFProfile.load` gauge (#273).
    ///
    /// This is the line an NF adds to perform the producer half of TS 29.500 §6.4
    /// with no reporter of its own to manage:
    /// [`crate::heartbeat::spawn_heartbeat_worker_with_load`] already publishes
    /// the NF's load, and this connects that to its responses.
    ///
    /// Deliberately **explicit** rather than the default for `overload_reporter ==
    /// None`. Making the fallback ambient was tried and reverted: the reporter is
    /// process-global, so one test raising the metric made every other server in
    /// the same test binary start stamping OCI, and two unrelated `server.rs`
    /// tests failed in parallel. The same mechanism in production is a daemon
    /// whose in-process test server suddenly emits overload because another test
    /// simulated load. An opt-in at the 19 daemons' own server setup is one line
    /// each and cannot surprise anything that did not ask.
    pub fn with_self_overload_reporting(mut self) -> Self {
        self.overload_reporter = Some(crate::overload::self_overload_reporter().clone());
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
    /// #1421: callback routes admitted on their own callback token instead.
    callback_exemptions: Vec<OAuth2CallbackExemption>,
    /// #1811: the resource-level scope each request needs, if any.
    resource_scopes: Option<OAuth2ResourceScopeFn>,
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
            callback_exemptions: config.oauth2_callback_exemptions.clone(),
            resource_scopes: config.oauth2_resource_scopes,
        })
    }

    /// Verify the bearer token's signature, expiry and (when configured)
    /// audience, and — when `required_scope` is `Some` — that the token's scope
    /// authorizes the invoked service (TS 33.501 §13.4.1.2, TS 29.510
    /// §5.4.2.2.2). `required_scope` is the invoked apiName (service name);
    /// `None` (e.g. a non-service path) skips only the scope check.
    /// Returns the verified token's `sub` (the consumer's NF Instance ID) so a
    /// producer can bind an authorization decision to the caller rather than
    /// merely to "a valid token exists" (issue #94). The claims used to be
    /// dropped here.
    ///
    /// #1766: a refusal says WHICH of TS 29.500 §6.7.3's cases it is, so the
    /// server can answer each with its own status and challenge. The signature
    /// and expiry are checked first and alone, so only a token that is genuinely
    /// this NRF's and current can reach the audience and scope checks.
    ///
    /// #1811: `resource_scope`, when `Some`, must ALSO be in the token's scope
    /// (TS 33.501 §13.4.1.2 "additional scope"; TS 29.500 §6.7.3 "those two
    /// scopes, together"), else 403 `insufficient_scope` naming it. It is checked
    /// after the service-level scope, so a token for another service is refused
    /// for that, and before the handler, so a refused request reads nothing.
    async fn authorize(
        &self,
        auth_header: Option<&str>,
        required_scope: Option<&str>,
        resource_scope: Option<&str>,
    ) -> Result<String, BearerRefusal> {
        let claims = match &self.keys {
            OAuthKeySource::Static(jwks) => crate::oauth::authorize_bearer_aud(auth_header, jwks, None),
            OAuthKeySource::Remote(cache) => cache.authorize_aud(auth_header, None).await,
            OAuthKeySource::Unconfigured => Err(SbiError::ServerError(
                "require_oauth2 is enabled but neither oauth2_jwks nor oauth2_jwks_uri is configured"
                    .into(),
            )),
        };
        // #1811: the resource scope is read before `bearer_decision` consumes the
        // claims, and refused only after it, so the refusal order is unchanged:
        // token, audience, service scope, then resource scope.
        let resource_refusal = match (&claims, resource_scope) {
            (Ok(c), Some(scope)) if crate::oauth::check_token_scope(&c.scope, scope).is_err() => {
                Some(BearerRefusal::InsufficientScope {
                    scope: scope.to_string(),
                    detail: format!(
                        "the access token's scope does not include {scope}, which this \
                         resource requires in addition to the service scope"
                    ),
                })
            }
            _ => None,
        };
        let sub = bearer_decision(
            claims,
            auth_header,
            self.expected_audience.as_deref(),
            required_scope,
        )?;
        match resource_refusal {
            Some(refusal) => Err(refusal),
            None => Ok(sub),
        }
    }
}

/// TS 29.500 §6.7.3's decision on a verified (or refused) bearer token, shared by
/// the server's OAuth2 gate and by every handler that runs its own (#1780): nefd's
/// `ueid`, nwdafd's `ran_congestion`.
/// - `claims` is the signature/expiry verification's result, checked with no
///   audience (`authorize_aud(header, None)`), so the audience is judged here.
/// - No Bearer token: [`BearerRefusal::Absent`] (401, no `error`).
/// - A token that does not verify: [`BearerRefusal::InvalidToken`].
/// - Another producer's `aud`: [`BearerRefusal::ClaimMismatch`].
/// - A scope without `required_scope`: [`BearerRefusal::InsufficientScope`].
/// - The keys unavailable: [`BearerRefusal::KeysUnavailable`].
///
/// Returns the token's `sub`.
pub fn bearer_decision(
    claims: SbiResult<crate::oauth::AccessTokenClaims>,
    auth_header: Option<&str>,
    expected_audience: Option<&str>,
    required_scope: Option<&str>,
) -> Result<String, BearerRefusal> {
    let claims = match claims {
        Ok(claims) => claims,
        Err(e @ SbiError::AuthorizationFailed(_)) if !bearer_presented(auth_header) => {
            return Err(BearerRefusal::Absent(e.to_string()))
        }
        Err(e @ SbiError::AuthorizationFailed(_)) => {
            return Err(BearerRefusal::InvalidToken(e.to_string()))
        }
        Err(e) => return Err(BearerRefusal::KeysUnavailable(e.to_string())),
    };
    if let Some(aud) = expected_audience {
        if let Err(e) = crate::oauth::check_audience(&claims.aud, aud) {
            return Err(BearerRefusal::ClaimMismatch {
                claim: "aud",
                detail: e.to_string(),
            });
        }
    }
    if let Some(scope) = required_scope {
        if let Err(e) = crate::oauth::check_token_scope(&claims.scope, scope) {
            return Err(BearerRefusal::InsufficientScope {
                scope: scope.to_string(),
                detail: e.to_string(),
            });
        }
    }
    Ok(claims.sub)
}

/// Whether the request presented a Bearer token at all (#1766). TS 29.500
/// §6.7.3: a request that "did not contain a token" is answered without an
/// `error` attribute. A request using another scheme carries no Bearer token
/// either (RFC 6750 §3.1), and nor does a bare `Bearer` with nothing after it.
/// Same test as nrfd's `oauth2_gate`.
fn bearer_presented(auth_header: Option<&str>) -> bool {
    auth_header.is_some_and(|h| {
        h.trim()
            .get(..7)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("bearer "))
    })
}

/// Why the OAuth2 gate refused a request (#1766). Each case has its own answer
/// in TS 29.500 §6.7.3, and a consumer tells them apart by status and the
/// challenge's `error` (RFC 6750 §3.1): only `invalid_token` means a fresh token
/// may succeed, which is what nextgcore's own client acts on (#1676).
#[derive(Debug)]
pub enum BearerRefusal {
    /// No Bearer token: 401, challenge without `error`.
    Absent(String),
    /// Malformed, forged, unknown-key or expired: 401 `invalid_token`.
    InvalidToken(String),
    /// A valid token whose `claim` names another producer: 403
    /// `ACCESS_TOKEN_CLAIM_MISMATCH` naming the claim.
    ClaimMismatch { claim: &'static str, detail: String },
    /// A valid token whose scope lacks the invoked service: 403
    /// `insufficient_scope` naming the scope needed.
    InsufficientScope { scope: String, detail: String },
    /// The verification keys could not be obtained: our fault, 503.
    KeysUnavailable(String),
}

impl BearerRefusal {
    /// The response TS 29.500 §6.7.3 prescribes for this refusal.
    pub fn into_response(self) -> SbiResponse {
        let challenge = |error: Option<&str>, extra: Option<String>| {
            let mut c = String::from("Bearer realm=\"5gc-sbi\"");
            if let Some(e) = error {
                c.push_str(&format!(", error=\"{e}\""));
            }
            if let Some(x) = extra {
                c.push_str(&x);
            }
            c
        };
        let problem = |status: u16, title: &str, detail: &str| serde_json::json!({ "title": title, "status": status, "detail": detail });
        let (status, body, www) = match self {
            Self::Absent(detail) => (
                401,
                problem(401, "Unauthorized", &detail),
                Some(challenge(None, None)),
            ),
            Self::InvalidToken(detail) => {
                let description = format!(", error_description=\"{}\"", challenge_text(&detail));
                let www = challenge(Some("invalid_token"), Some(description));
                (401, problem(401, "Unauthorized", &detail), Some(www))
            }
            Self::ClaimMismatch { claim, detail } => {
                let mut body = problem(403, "Forbidden", &detail);
                body["cause"] = "ACCESS_TOKEN_CLAIM_MISMATCH".into();
                body["invalidParams"] = serde_json::json!([{ "param": claim }]);
                (403, body, Some(challenge(Some("invalid_token"), None)))
            }
            Self::InsufficientScope { scope, detail } => {
                let scope = format!(", scope=\"{}\"", challenge_text(&scope));
                let www = challenge(Some("insufficient_scope"), Some(scope));
                (403, problem(403, "Forbidden", &detail), Some(www))
            }
            Self::KeysUnavailable(detail) => {
                (503, problem(503, "Service Unavailable", &detail), None)
            }
        };
        let resp = SbiResponse::with_status(status)
            .with_body(body.to_string(), "application/problem+json");
        match www {
            Some(www) => resp.with_header("WWW-Authenticate", www),
            None => resp,
        }
    }
}

/// `text` restricted to what an RFC 6750 §3 challenge attribute may carry
/// (%x20-21 / %x23-5B / %x5D-7E): a double quote or backslash would end or
/// escape the quoted string, so each becomes a single quote. A token's `aud`
/// is quoted JSON, and used to break the header.
fn challenge_text(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '"' | '\\' => '\'',
            ' '..='~' => c,
            _ => '?',
        })
        .collect()
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
    /// Issue #186: NF Instance ID from the verified peer certificate's URI SAN,
    /// extracted once per connection alongside the exporter secret and threaded
    /// into every request multiplexed on it.
    peer_cert_nf_instance_id: Option<String>,
    /// #1522: the NF types in the same verified certificate's RFC 9310 NFTypes
    /// extension (TS 33.310 §6.1.3c.3), empty when it has none. Read by the
    /// callback-exemption decision and (#1611) copied onto every request as
    /// [`SbiRequest::peer_cert_nf_types`].
    peer_cert_nf_types: Vec<String>,
    /// This NF's `(NfType, id)` identity for the `Server` response header
    /// (sbi-02). `None` emits no `Server` header.
    server_identity: Option<(NfType, String)>,
    /// #65: producer-side OCI source. `None` emits no `3gpp-Sbi-Oci`.
    overload_reporter: Option<Arc<OverloadReporter>>,
}

impl<H: SbiRequestHandler> Clone for SbiService<H> {
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
            oauth: self.oauth.clone(),
            max_request_body_size: self.max_request_body_size,
            tls_exporter_secret: self.tls_exporter_secret.clone(),
            peer_cert_nf_instance_id: self.peer_cert_nf_instance_id.clone(),
            peer_cert_nf_types: self.peer_cert_nf_types.clone(),
            server_identity: self.server_identity.clone(),
            overload_reporter: self.overload_reporter.clone(),
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
        let peer_cert_nf_instance_id = self.peer_cert_nf_instance_id.clone();
        let peer_cert_nf_types = self.peer_cert_nf_types.clone();
        let server_identity = self.server_identity.clone();
        let overload_reporter = self.overload_reporter.clone();
        let path = req.uri().path().to_string();
        let method = req.method().as_str().to_string();
        // #1334: every request this NF serves is counted, whichever branch below
        // answers it (a size, body, or token rejection included); the probes are not.
        let probe = path == "/health" || path == "/ready" || path == "/live";
        let started = std::time::Instant::now();
        let counted = (!probe).then(|| (method, path.clone()));

        let serve = Box::pin(async move {
            // Health/readiness probe — handled before the NF handler
            if probe {
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
            let mut sbi_request =
                match convert_request(req, max_body, tls_exporter_secret, peer_cert_nf_instance_id)
                    .await
                {
                    Ok(mut request) => {
                        // #1611: the verified leaf's RFC 9310 NF types travel with
                        // the request (the NRF binds an NFRegister's nfType to them).
                        request.peer_cert_nf_types = peer_cert_nf_types.clone();
                        request
                    }
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
                        let resp = SbiResponse::with_status(413)
                            .with_body(body, "application/problem+json");
                        return Ok(convert_response_with_identity(
                            resp,
                            server_identity.as_ref(),
                            overload_reporter.as_ref(),
                        ));
                    }
                    // #867: an incomplete request is answered 400 (TS 29.500 §5.2.7.2,
                    // INVALID_MSG_FORMAT) and never reaches the handler. The peer has
                    // usually reset the stream, so the answer may not arrive.
                    Err(ConvertRequestError::BodyReadFailed) => {
                        let body = serde_json::json!({
                            "title": "Bad Request",
                            "status": 400,
                            "detail": "the request body could not be read",
                            "cause": "INVALID_MSG_FORMAT",
                        })
                        .to_string();
                        let resp = SbiResponse::with_status(400)
                            .with_body(body, "application/problem+json");
                        return Ok(convert_response_with_identity(
                            resp,
                            server_identity.as_ref(),
                            overload_reporter.as_ref(),
                        ));
                    }
                };

            // #1934 review M1: one path shape for every check that follows. A
            // router that drops empty segments and a scope rule that does not
            // read `//` differently, so a resource scope keyed on segment
            // positions was skipped while the router still served the route.
            // Refused here, before the callback exemption, the OAuth2 checks and
            // the NF router, for every NF.
            if let Some(defect) = path_segment_refusal(&sbi_request.header.uri) {
                // The defect is in the ProblemDetails only: it is derived from the
                // path, which may carry a callback token.
                log::debug!(
                    "cid={} {} {} refused 400: malformed path",
                    sbi_request.correlation_id,
                    sbi_request.header.method,
                    crate::log_redact::redact_callback_tokens(&sbi_request.header.uri)
                );
                let body = serde_json::json!({
                    "title": "Bad Request",
                    "status": 400,
                    "detail": format!("the request path has {defect}"),
                    "cause": "INVALID_MSG_FORMAT",
                })
                .to_string();
                let resp =
                    SbiResponse::with_status(400).with_body(body, "application/problem+json");
                return Ok(convert_response_with_identity(
                    resp,
                    server_identity.as_ref(),
                    overload_reporter.as_ref(),
                ));
            }

            // OAuth2 enforcement (opt-in). Verify the bearer token against the
            // configured key material before dispatching to the NF handler.
            // An invalid token is the caller's fault (401); not being able to
            // obtain verification keys is ours (503).
            // #1421: a notification to a callback route this NF registered, whose
            // path carries a callback token the NF holds, is not an OAuth 2.0
            // protected access (TS 33.501 §13.4.1, TS 29.500 §6.10.7 NOTE): it is
            // authenticated by that token, and the bearer is not consulted.
            // #1522: an exemption may also require the connection's verified
            // mutual-TLS peer: its NF Instance ID and RFC 9310 NF types, both read
            // only from a client certificate rustls verified.
            let exempt = match &oauth {
                Some(verifier) => {
                    let peer = sbi_request.peer_cert_nf_instance_id.as_ref().map(|id| {
                        crate::callback_auth::VerifiedPeer {
                            nf_instance_id: id.clone(),
                            nf_types: peer_cert_nf_types.clone(),
                        }
                    });
                    crate::callback_auth::admits_without_bearer_from(
                        &verifier.callback_exemptions,
                        &sbi_request.header.method,
                        &sbi_request.header.uri,
                        peer.as_ref(),
                    )
                    .await
                }
                None => false,
            };
            let oauth = oauth.filter(|_| {
                if exempt {
                    log::debug!(
                        "cid={} {} {}: callback admitted on its callback token, no bearer \
                         required",
                        sbi_request.correlation_id,
                        sbi_request.header.method,
                        crate::log_redact::redact_callback_tokens(&sbi_request.header.uri)
                    );
                }
                !exempt
            });
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
                // #1811: and the resource-level scope the resource needs, if any.
                let resource_scope = verifier.resource_scopes.and_then(|scope_for| {
                    scope_for(&sbi_request.header.method, &sbi_request.header.uri)
                });
                match verifier
                    .authorize(auth, required_scope, resource_scope)
                    .await
                {
                    // Record the identity THIS PROCESS verified, so a producer can
                    // bind authorization to the caller (issue #94).
                    Ok(sub) => sbi_request.oauth2_subject = Some(sub),
                    Err(refusal) => {
                        // #1766: TS 29.500 §6.7.3 / RFC 6750 §3.1 -- 401 with no
                        // `error` for no token, 401 invalid_token for a bad one,
                        // 403 for a good token that is not for this request.
                        let resp = refusal.into_response();
                        return Ok(convert_response_with_identity(
                            resp,
                            server_identity.as_ref(),
                            overload_reporter.as_ref(),
                        ));
                    }
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
            let response = convert_response_with_identity(
                sbi_response,
                server_identity.as_ref(),
                overload_reporter.as_ref(),
            );

            Ok(response)
        });
        Box::pin(async move {
            let result: Result<Self::Response, Self::Error> = serve.await;
            if let (Some((method, path)), Ok(response)) = (counted, &result) {
                nextgcore_metrics::nf::record_sbi_request(
                    &method,
                    &path,
                    response.status().as_u16(),
                    started.elapsed(),
                );
            }
            result
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
    /// The body could not be read: the peer reset the stream or the connection
    /// failed mid-body (#867). The request is incomplete and is never dispatched.
    BodyReadFailed,
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

/// What makes the request path `path` (no query) refused before routing (a
/// phrase naming the defect, never the path itself, which may carry a callback
/// token), or `None` when it is well formed (#1934 review M1).
///
/// An SBI resource URI is `{apiRoot}/{apiName}/{apiVersion}/{apiSpecificResourceUriPart}`
/// (TS 29.501 §4.4.1), a sequence of non-empty segments. Refused:
/// - an empty segment (`//`, a leading `//`, a trailing `/`);
/// - a dot segment, `.` or `..`, also percent-encoded (RFC 3986 §3.3, §6.2.2.2).
///
/// The bare root `/` is accepted. So every NF router and every per-path check
/// (resource scopes, callback exemptions) sees the same segments, whichever way
/// each one splits.
///
/// #1939 item 1: a percent-encoded `/` (`%2F`) or `\` (`%5C`) INSIDE a segment
/// is accepted. TS 29.501 §5.2 has a resource URI variable that is a free-form
/// string carry such characters percent-encoded (TS 29.519 `{appId}`, TS 29.122
/// `{scsAsId}` / `{afId}`, TS 29.522 `{afId}`), and no router or per-path check
/// in this tree decodes a path before splitting it (they all split on the raw
/// `/` and compare raw segments), so an encoded separator is one segment to
/// every one of them. A future router that decodes a path must decode AFTER
/// splitting, segment by segment, or it reintroduces #1934's disagreement.
pub fn path_segment_refusal(path: &str) -> Option<String> {
    let rest = path.strip_prefix('/').unwrap_or(path);
    if rest.is_empty() {
        return None;
    }
    for segment in rest.split('/') {
        if segment.is_empty() {
            return Some("an empty segment".to_string());
        }
        let decoded = segment.to_ascii_lowercase().replace("%2e", ".");
        if decoded == "." || decoded == ".." {
            return Some("a dot segment".to_string());
        }
    }
    None
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
    peer_cert_nf_instance_id: Option<String>,
) -> Result<SbiRequest, ConvertRequestError> {
    let method = req.method().to_string();
    let uri = req.uri().path().to_string();

    // #259: keep the authority the peer addressed, BESIDE the path rather than
    // folded into it. hyper surfaces HTTP/2's `:authority` pseudo-header and an
    // absolute-form request target's authority through the same `uri()`, so one
    // read covers both; `Host` is the HTTP/1.1 fallback. Discarding this is what
    // made an absolute callback URI (TS 29.500 §6.10.7) unroutable at the SCP.
    let authority = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .or_else(|| {
            req.headers()
                .get(hyper::header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(str::to_owned)
        })
        .filter(|a| !a.is_empty());

    // Extract headers.
    //
    // #65: APPEND rather than set. hyper yields one entry per field LINE, so a
    // peer sending two `3gpp-Sbi-Oci` occurrences (TS 29.500 §6.4.3 — one per
    // reporting scope) arrived here as two calls; `set_header` replaces, so the
    // first scope was discarded and a producer reporting overload for two scopes
    // was read as reporting for one.
    let mut http = SbiHttpMessage::new();
    for (key, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            http.append_header(key.to_string(), v.to_string());
        }
    }

    // ── T6.4: correlation / request-ID extraction ──────────────────────────
    // Prefer an explicit x-request-id, fall back to the trace-id embedded in
    // a W3C traceparent, and synthesise one from the clock when neither is
    // present. The chosen id is threaded into structured log lines and echoed
    // outbound by the SBI client.
    let correlation_id = extract_or_generate_correlation_id(&http);

    // Extract query parameters, percent-DECODED (#65, TS 29.500 §5.2.10.2).
    //
    // Two defects fixed here, both of which made a conformant peer look
    // malformed:
    //
    // 1. Values were stored verbatim. A producer must percent-encode a query
    //    value containing reserved characters, so a JSON-valued factor (the MBS
    //    `tmgi-list`, an S-NSSAI list) arrived as `%5B%7B%22...` and every
    //    consumer that fed it to `serde_json` answered 400. Two NFs carried
    //    their own decoder to compensate; both are deleted in this change,
    //    because a local shim on top of a decoding server DOUBLE-decodes, and a
    //    value whose plaintext legitimately contains `%20` is then corrupted.
    //
    // 2. A parameter with no `=` was DROPPED. RFC 3986 permits a bare flag, and
    //    dropping it is indistinguishable from the peer never sending it. It is
    //    now stored with an empty value, so `get_param` returns `Some("")` —
    //    present-but-empty, which is what the peer said.
    //
    // The QUERY decoder is used, not the form decoder: in a query component `+`
    // is a literal plus. Decoding it as a space would corrupt every RFC 3339
    // timestamp carrying a non-UTC offset and every base64 value.
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            http.set_param(
                crate::uri_encode::decode_query_value(key),
                crate::uri_encode::decode_query_value(value),
            );
        }
    }

    // Read body under a size cap. multipart/related bodies (N1/N2 binary
    // containers, TS 29.500 §6.1.2.3) are decoded into the JSON root + binary
    // parts before any UTF-8 conversion so binary content survives byte-exact.
    // #940: the path may carry a callback token; the log lines below show it redacted.
    let logged_uri = crate::log_redact::redact_callback_tokens(&uri);
    let limited = Limited::new(req.into_body(), max_body_size);
    let declared_length: Option<usize> = http
        .get_header("content-length")
        .and_then(|v| v.trim().parse().ok());
    match limited.collect().await {
        // #867: hyper ends an HTTP/2 request body quietly when the peer resets the
        // stream with CANCEL (or NO_ERROR), so a request cut off mid-body arrives as
        // a complete one with what was sent so far, empty included. A body shorter
        // (or longer) than the Content-Length the peer declared is that case: the
        // request is incomplete and is not dispatched.
        Ok(body) => {
            let bytes = body.to_bytes();
            if declared_length.is_some_and(|n| n != bytes.len()) {
                log::warn!(
                    "cid={correlation_id} method={method} path={logged_uri} \
                     reason=BODY_READ_ERROR: {} of the {} declared body bytes arrived; the \
                     request is not dispatched",
                    bytes.len(),
                    declared_length.unwrap_or_default()
                );
                return Err(ConvertRequestError::BodyReadFailed);
            }
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
                                 on {logged_uri}: {e}"
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
                    "cid={correlation_id} method={method} path={logged_uri} \
                     reason=PAYLOAD_TOO_LARGE: body exceeds {max_body_size}-byte limit"
                );
                return Err(ConvertRequestError::BodyTooLarge);
            }
            // #867: this used to fall through and dispatch the request with an EMPTY
            // body, so a handler saw a truncated request as a complete, bodiless one
            // (a capture server in amfd's tests took it for a notification).
            log::warn!(
                "cid={correlation_id} method={method} path={logged_uri} \
                 reason=BODY_READ_ERROR: {e}; the request is not dispatched"
            );
            return Err(ConvertRequestError::BodyReadFailed);
        }
    }

    // Decompose the URI per TS 29.501 §4.4 so handlers get service name,
    // API version and resource components without re-parsing the path.
    let mut header = crate::message::SbiHeader::with_method_uri(method, uri);
    header.authority = authority;
    header.decompose_uri();

    Ok(SbiRequest {
        header,
        http,
        correlation_id,
        tls_exporter_secret,
        peer_cert_nf_instance_id,
        // #1611: set by the caller from the same verified leaf.
        peer_cert_nf_types: Vec::new(),
        // Set by the caller after the bearer token verifies; `convert_request`
        // runs before authorization, so it cannot know it here.
        oauth2_subject: None,
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
    overload: Option<&Arc<OverloadReporter>>,
) -> Response<Full<Bytes>> {
    if let Some((nf_type, nf_id)) = identity {
        if sbi_response.http.get_header("Server").is_none() {
            sbi_response
                .http
                .set_header("Server", format!("{}-{}", nf_type.as_server_token(), nf_id));
        }
    }
    // #65: stamp `3gpp-Sbi-Oci` when this NF has declared itself overloaded
    // (TS 29.500 §6.4.3.2 — an OCI may ride on any response, not only a 503).
    // A handler that set its own OCI wins: it knows a per-scope reason this
    // layer does not.
    if let Some(reporter) = overload {
        if let Some(oci) = reporter.oci() {
            if sbi_response
                .http
                .get_header(crate::constants::custom_header::OCI)
                .is_none()
            {
                sbi_response
                    .http
                    .set_header(crate::constants::custom_header::OCI, oci.to_header());
            }
        }
    }
    convert_response(sbi_response)
}

/// Server state
enum ServerState {
    Stopped,
    Running(RunningState),
}

/// First pause after an accept error (#1338).
const ACCEPT_BACKOFF_BASE: Duration = Duration::from_millis(10);
/// Longest pause after consecutive accept errors (#1338): at most one
/// accept-failure warn per second while the error persists.
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// Capped exponential pause after consecutive accept errors (#1338).
///
/// `accept()` failing with EMFILE/ENFILE (out of file descriptors) fails again
/// immediately, because the condition persists until some connection closes.
/// The accept loop used to retry at once, so it spun on the CPU and wrote one
/// warn per spin. This doubles the pause from [`ACCEPT_BACKOFF_BASE`] up to
/// [`ACCEPT_BACKOFF_MAX`], and the next successful accept resets it, the same
/// shape as the EMFILE handling in hyper's and tokio's accept-loop examples.
#[derive(Debug, Default)]
struct AcceptBackoff {
    consecutive: u32,
}

impl AcceptBackoff {
    fn on_success(&mut self) {
        self.consecutive = 0;
    }

    /// Record one more failure and return how long to pause before the next
    /// accept: 10 ms, 20 ms, 40 ms, ... capped at 1 s.
    fn on_error(&mut self) -> Duration {
        let pause = ACCEPT_BACKOFF_BASE
            .saturating_mul(1u32 << self.consecutive.min(16))
            .min(ACCEPT_BACKOFF_MAX);
        self.consecutive = self.consecutive.saturating_add(1);
        pause
    }
}

/// Everything `stop()` needs to shut a running server down gracefully (#65).
struct RunningState {
    /// Breaks the accept loop, so no NEW connection is taken.
    accept_shutdown: oneshot::Sender<()>,
    /// Broadcasts "start draining" to every live connection task, each of which
    /// answers by sending an HTTP/2 GOAWAY and finishing its in-flight streams.
    graceful: watch::Sender<bool>,
    /// Drain barrier. Every connection task holds a clone of the paired
    /// [`mpsc::Sender`]; when the last one drops, `recv()` here resolves to
    /// `None`. That is the only reliable "all connections have finished" signal —
    /// counting with an atomic races with a task that has decremented but not yet
    /// flushed its final frames.
    drain: mpsc::Receiver<()>,
}

/// How long [`SbiServer::stop`] waits for in-flight streams to finish after the
/// GOAWAY before abandoning them (#65).
///
/// A bound is required rather than optional: a peer holding a stream open (a slow
/// notification consumer, a half-dead TCP connection) would otherwise make
/// `stop()` hang forever, and `stop()` is called from test teardown and from the
/// daemons' SIGTERM path — both places where hanging is worse than dropping a
/// straggler. Exceeding it is logged at warn with the count.
const GRACEFUL_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// SBI Server - HTTP/2 server for SBI communication
/// Matches nextgcore_sbi_server_t
pub struct SbiServer {
    /// Server configuration
    config: SbiServerConfig,
    /// Server state
    state: Arc<Mutex<ServerState>>,
    /// A listener the caller bound before constructing this server, for
    /// [`SbiServer::on_listener`]. Taken by the first `start()`; `None` there
    /// means `start()` binds `config.addr` itself, which is the ordinary path.
    prebound: Arc<Mutex<Option<std::net::TcpListener>>>,
}

impl SbiServer {
    /// Create a new SBI server
    pub fn new(config: SbiServerConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(ServerState::Stopped)),
            prebound: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a server with address
    pub fn with_addr(addr: SocketAddr) -> Self {
        Self::new(SbiServerConfig::new(addr))
    }

    /// Create a server that will serve on a listener the caller has **already
    /// bound**, rather than binding `config.addr` itself (#313).
    ///
    /// # Why this exists
    ///
    /// The ordinary path picks an address and binds it inside [`start`](Self::start).
    /// For a test that needs an unused port, that means asking the OS for one
    /// (bind `:0`, read the port, drop the probe) and then binding it again —
    /// and between the drop and the real bind the port belongs to nobody, so a
    /// concurrently-starting process can take it. `cargo test --workspace` runs
    /// one test binary per crate at once, so that window is reachable: it
    /// surfaces as a bind failure inside `start()`, not as a wrong answer.
    ///
    /// Handing the server the listener removes the window entirely — the port is
    /// bound from the moment it is chosen. See
    /// [`crate::test_support::bound_listener`] for the reservation helper and
    /// [`crate::test_support::sbi_server_on_free_port`] for the whole shape.
    ///
    /// # `config.addr` is overwritten
    ///
    /// Deliberately: the listener's real local address is authoritative, and a
    /// server whose `config.addr` disagreed with the socket it serves would
    /// misreport itself in `stop()`'s log and in any URI derived from the
    /// config. That also lets a caller pass a config built with a placeholder
    /// address. If `local_addr()` fails — it does not for a bound listener —
    /// `config.addr` is left as supplied.
    ///
    /// # Restart
    ///
    /// The listener is consumed by the first `start()`. A `stop()`/`start()`
    /// cycle re-binds `config.addr` like any other server, which reopens the
    /// same window for that one re-bind; nothing in this workspace restarts a
    /// server on a reserved port.
    pub fn on_listener(mut config: SbiServerConfig, listener: std::net::TcpListener) -> Self {
        if let Ok(actual) = listener.local_addr() {
            config.addr = actual;
        }
        Self {
            config,
            state: Arc::new(Mutex::new(ServerState::Stopped)),
            prebound: Arc::new(Mutex::new(Some(listener))),
        }
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
            if self.config.verify_client_optional {
                tls::build_server_config_optional_client_auth(certs, key, ca_path)?
            } else {
                tls::build_server_config_mtls(certs, key, ca_path)?
            }
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

        // #313: serve a caller-supplied listener when one was reserved, so the
        // chosen port is never unbound between selection and use. Taken (not
        // cloned) so a later restart falls back to the ordinary bind.
        let listener = match self.prebound.lock().await.take() {
            Some(std_listener) => {
                std_listener.set_nonblocking(true).map_err(|e| {
                    SbiError::ServerError(format!(
                        "Failed to set pre-bound listener nonblocking: {e}"
                    ))
                })?;
                TcpListener::from_std(std_listener).map_err(|e| {
                    SbiError::ServerError(format!("Failed to adopt pre-bound listener: {e}"))
                })?
            }
            None => TcpListener::bind(self.config.addr)
                .await
                .map_err(|e| SbiError::ServerError(format!("Failed to bind: {e}")))?,
        };

        // For the accept-failure log line (#1338); the configured address is
        // `:0` for a test server, so ask the listener.
        let local_addr = listener
            .local_addr()
            .map_or_else(|_| self.config.addr.to_string(), |a| a.to_string());

        let tls_acceptor = if self.config.scheme == UriScheme::Https {
            Some(self.build_tls_acceptor()?)
        } else {
            None
        };

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        // #65: graceful-shutdown plumbing. `graceful_tx` tells live connections to
        // send GOAWAY and drain; `drain_tx` is cloned into each connection task
        // purely so that `stop()` can await the last clone being dropped.
        let (graceful_tx, graceful_rx) = watch::channel(false);
        let (drain_tx, drain_rx) = mpsc::channel::<()>(1);
        *state = ServerState::Running(RunningState {
            accept_shutdown: shutdown_tx,
            graceful: graceful_tx,
            drain: drain_rx,
        });
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
        // #65: the producer-side OCI source, shared by every connection.
        let overload_reporter = self.config.overload_reporter.clone();

        // Spawn the server task
        tokio::spawn(async move {
            let mut accept_backoff = AcceptBackoff::default();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer)) => {
                                accept_backoff.on_success();
                                let handler_ref = handler.clone();
                                let oauth_ref = oauth.clone();
                                let http2_limits = http2_limits;
                                let server_identity_ref = server_identity.clone();
                                let overload_reporter_ref = overload_reporter.clone();
                                // #65: one shutdown receiver and one drain token
                                // per connection. The token must be cloned HERE,
                                // not inside the spawned task: cloning inside
                                // races with `stop()` observing the channel
                                // closed before the new task has registered.
                                let conn_graceful = graceful_rx.clone();
                                let conn_drain = drain_tx.clone();

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
                                                // ── #186: NF identity from the VERIFIED
                                                // peer certificate ──
                                                // rustls has already validated the
                                                // client's chain by this point (when
                                                // verify_client is set); the leaf's URI
                                                // SubjectAltName carries the NF Instance
                                                // ID (TS 33.310). Read from the same
                                                // borrow as the exporter secret above,
                                                // for the same reason: it must happen
                                                // before the stream moves into TokioIo.
                                                let peer_cert_nf_instance_id = {
                                                    let (_, server_conn) = tls_stream.get_ref();
                                                    server_conn
                                                        .peer_certificates()
                                                        .and_then(|chain| chain.first())
                                                        .and_then(|leaf| {
                                                            crate::peer_cert::nf_instance_id_from_der(
                                                                leaf.as_ref(),
                                                            )
                                                        })
                                                };
                                                // #1522: the RFC 9310 NF types of the
                                                // same verified leaf.
                                                let peer_cert_nf_types = {
                                                    let (_, server_conn) = tls_stream.get_ref();
                                                    server_conn
                                                        .peer_certificates()
                                                        .and_then(|chain| chain.first())
                                                        .map(|leaf| {
                                                            crate::peer_cert::nf_types_from_der(
                                                                leaf.as_ref(),
                                                            )
                                                        })
                                                        .unwrap_or_default()
                                                };
                                                let service = SbiService {
                                                    handler: handler_ref,
                                                    oauth: oauth_ref,
                                                    max_request_body_size,
                                                    tls_exporter_secret,
                                                    peer_cert_nf_instance_id,
                                                    peer_cert_nf_types,
                                                    server_identity: server_identity_ref,
                                                    overload_reporter:
                                                        overload_reporter_ref,
                                                };
                                                let io = TokioIo::new(tls_stream);
                                                serve_connection_gracefully(
                                                    io,
                                                    service,
                                                    http2_limits,
                                                    conn_graceful,
                                                    conn_drain,
                                                    "SBI server HTTP/2 TLS",
                                                    peer,
                                                )
                                                .await;
                                            }
                                            Err(e) => {
                                                crate::conn_end::log_tls_accept_error(
                                                    &peer.to_string(),
                                                    &e,
                                                );
                                            }
                                        }
                                    });
                                } else {
                                    let service = SbiService {
                                        handler: handler_ref,
                                        oauth: oauth_ref,
                                        max_request_body_size,
                                        // No TLS on plaintext connections, so no
                                        // exporter secret and no peer certificate.
                                        tls_exporter_secret: None,
                                        peer_cert_nf_instance_id: None,
                                        peer_cert_nf_types: Vec::new(),
                                        server_identity: server_identity_ref,
                                        overload_reporter: overload_reporter_ref,
                                    };
                                    let io = TokioIo::new(stream);
                                    tokio::spawn(serve_connection_gracefully(
                                        io,
                                        service,
                                        http2_limits,
                                        conn_graceful,
                                        conn_drain,
                                        "SBI server HTTP/2",
                                        peer,
                                    ));
                                }
                            }
                            Err(e) => {
                                // A persistent accept error (EMFILE/ENFILE, out of
                                // fds) is returned again at once; without a pause
                                // this loop spins and floods the log.
                                let pause = accept_backoff.on_error();
                                log::warn!(
                                    "SBI server on {local_addr}: accept failed: {e} \
                                     ({} in a row; pausing {pause:?})",
                                    accept_backoff.consecutive
                                );
                                tokio::select! {
                                    _ = tokio::time::sleep(pause) => {}
                                    _ = &mut shutdown_rx => break,
                                }
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

    /// Stop the server **gracefully** (#65).
    ///
    /// Three steps, in this order (RFC 9113 §6.8):
    ///
    /// 1. break the accept loop, so no new connection is taken;
    /// 2. tell every live connection to send GOAWAY and finish its in-flight
    ///    streams;
    /// 3. wait — bounded by [`GRACEFUL_DRAIN_TIMEOUT`] — for those streams to
    ///    complete.
    ///
    /// Step 2 and step 3 are what this used to skip. Firing the accept-loop
    /// signal alone left the connection tasks detached: they were killed when the
    /// runtime dropped, so a peer with a request in flight during a restart got a
    /// transport error instead of its response, and no GOAWAY ever told it to
    /// stop opening streams.
    ///
    /// The order matters. Signalling graceful shutdown before closing the
    /// listener would let a connection accepted in between miss the signal
    /// entirely and hold the drain open until the timeout.
    pub async fn stop(&self) -> SbiResult<()> {
        let mut state = self.state.lock().await;

        let ServerState::Running(running) = std::mem::replace(&mut *state, ServerState::Stopped)
        else {
            return Ok(());
        };
        let RunningState {
            accept_shutdown,
            graceful,
            mut drain,
        } = running;

        // 1. No new connections.
        let _ = accept_shutdown.send(());
        // 2. GOAWAY + finish in-flight streams on the live ones. A send error
        //    means every connection task has already exited, which is the same
        //    end state.
        let _ = graceful.send(true);
        // 3. Drop our own token so the barrier depends only on the connections,
        //    then wait for the last one. `recv()` returns None when every cloned
        //    sender has dropped; a `Some` cannot happen (nothing ever sends).
        drop(graceful);
        match tokio::time::timeout(GRACEFUL_DRAIN_TIMEOUT, drain.recv()).await {
            Ok(_) => {}
            Err(_) => log::warn!(
                "SBI server on {} still had connections in flight after {}s of graceful \
                 shutdown; abandoning them. A peer holding a stream open (a slow notification \
                 consumer, or a half-dead TCP connection) will see a transport error.",
                self.config.addr,
                GRACEFUL_DRAIN_TIMEOUT.as_secs()
            ),
        }

        Ok(())
    }

    /// Check if the server is running
    pub async fn is_running(&self) -> bool {
        let state = self.state.lock().await;
        matches!(*state, ServerState::Running(_))
    }
}

/// Serve one HTTP/2 connection, honouring a graceful-shutdown signal (#65).
///
/// Before this existed the connection future was awaited directly in a detached
/// task, so `stop()` had no handle on it: the process dropped the listener and
/// every live connection was torn down mid-stream with no GOAWAY. A peer with a
/// request in flight saw a transport error rather than a completed response,
/// which is what makes a rolling restart lossy (RFC 9113 §6.8: an endpoint
/// shutting down gracefully sends GOAWAY so the peer stops opening new streams
/// while existing ones finish).
///
/// On the signal this calls `graceful_shutdown()` — which queues the GOAWAY —
/// and then keeps polling the same connection future, because the GOAWAY is only
/// written, and the in-flight streams only complete, while the connection is
/// still being driven. Returning here instead (the tempting one-liner) sends
/// nothing and drops everything.
///
/// `drain_token` is never used; holding it until this function returns is the
/// point. [`RunningState::drain`] resolves once every token has dropped.
async fn serve_connection_gracefully<I, H>(
    io: I,
    service: SbiService<H>,
    http2_limits: Http2Limits,
    mut graceful: watch::Receiver<bool>,
    drain_token: mpsc::Sender<()>,
    label: &'static str,
    peer: SocketAddr,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    H: SbiRequestHandler,
{
    let mut builder = http2::Builder::new(hyper_util::rt::TokioExecutor::new());
    http2_limits.apply(&mut builder);
    let conn = builder.serve_connection(io, service);
    let mut conn = std::pin::pin!(conn);

    // Two futures race: the connection finishing on its own, and the shutdown
    // signal arriving. Only the second needs handling; the first is the normal
    // keep-alive close.
    let drained = tokio::select! {
        result = conn.as_mut() => result,
        signal = graceful.changed() => {
            match signal {
                // `stop()` fired: queue the GOAWAY, then drive the connection to
                // completion so it is actually written and the in-flight streams
                // get their responses.
                Ok(()) => {
                    conn.as_mut().graceful_shutdown();
                    conn.as_mut().await
                }
                // The watch sender is gone (the server was dropped without
                // stop()). Nothing to wait for; serve the connection out.
                Err(_) => conn.as_mut().await,
            }
        }
    };
    // #1338: this was `eprintln!("{label} connection error: {e}")`, and a
    // kubelet `tcpSocket` probe (connect, close, no preface) printed it as the
    // bare `HTTP/2 connection error: connection error` every 7.5 s in every NF.
    if let Err(e) = drained {
        crate::conn_end::log_conn_end(label, &peer.to_string(), &e);
    }
    drop(drain_token);
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

/// Send a 405 Method Not Allowed error response.
///
/// Carries no `Allow` header because it does not know the resource's method
/// set. Prefer [`send_method_not_allowed_with_allow`] on any route that does:
/// RFC 9110 §15.5.6 makes `Allow` mandatory on a 405, and TS 29.500 §5.2.7.1
/// requires it of an SBI producer.
pub fn send_method_not_allowed(method: &str, resource: &str) -> SbiResponse {
    send_error(
        405,
        "Method Not Allowed",
        &format!("Method {method} not allowed for resource {resource}"),
        Some("METHOD_NOT_ALLOWED"),
    )
}

/// Send a 405 Method Not Allowed carrying the mandatory `Allow` header.
///
/// `allowed` is the set of methods the addressed resource *does* support, and is
/// rendered as the comma-separated `Allow` header RFC 9110 §15.5.6 requires (and
/// TS 29.500 §5.2.7.1 restates for SBI). A 405 without it tells the consumer
/// only that it guessed wrong, not what to do instead.
pub fn send_method_not_allowed_with_allow(
    method: &str,
    resource: &str,
    allowed: &[&str],
) -> SbiResponse {
    send_method_not_allowed(method, resource).with_header("Allow", allowed.join(", "))
}

/// Send a `404 Not Found` with cause `RESOURCE_URI_NOT_FOUND` (TS 29.500
/// §5.2.7.1): the URI does not name a resource this producer serves.
///
/// Distinct from a 405, which says the resource exists but not for that method,
/// and from a resource-specific 404 such as `CONTEXT_NOT_FOUND`, which says the
/// resource exists but holds nothing for this UE.
pub fn send_resource_uri_not_found(uri: &str) -> SbiResponse {
    send_error(
        404,
        "Not Found",
        &format!("No resource at {uri}"),
        Some("RESOURCE_URI_NOT_FOUND"),
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
mod body_read_failure_tests {
    use crate::message::{SbiRequest, SbiResponse};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    async fn h2_client(addr: std::net::SocketAddr) -> h2::client::SendRequest<bytes::Bytes> {
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (client, conn) = h2::client::handshake(tcp).await.expect("h2 handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        client.ready().await.expect("ready")
    }

    /// A POST declaring a `len`-byte body, as every nextgcore client sends one.
    fn post(addr: std::net::SocketAddr, len: usize) -> hyper::Request<()> {
        hyper::Request::post(format!("http://{addr}/notify/867"))
            .header("content-type", "application/json")
            .header("content-length", len.to_string())
            .body(())
            .expect("request")
    }

    /// #867: a request whose body the peer cuts off (RST_STREAM after a partial
    /// DATA frame) is not handed to the handler as a complete request with an
    /// empty body. A complete request on the same server still is.
    #[tokio::test]
    async fn a_request_whose_body_is_cut_off_never_reaches_the_handler() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let (_server, addr) =
            crate::test_support::sbi_server_on_free_port(move |_req: SbiRequest| {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    SbiResponse::no_content()
                }
            })
            .await;

        // Cut off after part of the body, and before any of it.
        for sent in [&b"{\"reportList\":"[..], &b""[..]] {
            let mut client = h2_client(addr).await;
            let (answer, mut body) = client.send_request(post(addr, 40), false).expect("send");
            if !sent.is_empty() {
                body.send_data(bytes::Bytes::copy_from_slice(sent), false)
                    .expect("data");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            body.send_reset(h2::Reason::CANCEL);
            let _ = tokio::time::timeout(Duration::from_secs(2), answer).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a truncated request reached the handler"
        );

        // Control: the same server dispatches a complete one.
        let mut client = h2_client(addr).await;
        let (answer, mut body) = client.send_request(post(addr, 2), false).expect("send");
        body.send_data(bytes::Bytes::from_static(b"{}"), true)
            .expect("data");
        let answer = tokio::time::timeout(Duration::from_secs(2), answer)
            .await
            .expect("answered")
            .expect("response");
        assert_eq!(answer.status(), 204);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
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

    /// The `cause` of a ProblemDetails body, if present.
    fn problem_cause(resp: &SbiResponse) -> Option<String> {
        let body = resp.http.content.as_deref()?;
        let v: serde_json::Value = serde_json::from_str(body).ok()?;
        v.get("cause")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
    }

    /// TS 29.500 §5.2.7.1 / RFC 9110 §15.5.6: a 405 must say which methods the
    /// resource does support, or the consumer learns only that it guessed wrong.
    #[test]
    fn method_not_allowed_with_allow_lists_the_supported_methods() {
        let resp = send_method_not_allowed_with_allow(
            "DELETE",
            "/nudm-uecm/v1/x/registrations",
            &["PUT", "PATCH", "GET"],
        );
        assert_eq!(resp.status, 405);
        assert_eq!(problem_cause(&resp).as_deref(), Some("METHOD_NOT_ALLOWED"));
        // set_header lowercases keys (HTTP/2 convention).
        assert_eq!(
            resp.http.headers.get("allow").map(String::as_str),
            Some("PUT, PATCH, GET"),
            "the Allow header is mandatory on a 405"
        );
    }

    /// An unknown URI is `404 RESOURCE_URI_NOT_FOUND`, not a 405: a consumer
    /// branching on the cause must be able to tell "no such resource" from
    /// "wrong method for this resource".
    #[test]
    fn resource_uri_not_found_is_404_with_the_spec_cause() {
        let resp = send_resource_uri_not_found("/nudm-sdm/v2/imsi-1/not-a-resource");
        assert_eq!(resp.status, 404);
        assert_eq!(
            problem_cause(&resp).as_deref(),
            Some("RESOURCE_URI_NOT_FOUND")
        );
        assert!(
            !resp.http.headers.contains_key("allow"),
            "a 404 must not claim a method set for a resource that does not exist"
        );
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
            callback_exemptions: Vec::new(),
            resource_scopes: None,
        };
        let err = unconfigured
            .authorize(Some("Bearer a.b.c"), None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, BearerRefusal::KeysUnavailable(_)), "{err:?}");

        // A static JWKS that can't verify the token is the caller's fault
        // (401); with no token at all it is #1766's `Absent`.
        let static_v = OAuthVerifier {
            keys: OAuthKeySource::Static(serde_json::json!({"keys": []})),
            expected_audience: None,
            callback_exemptions: Vec::new(),
            resource_scopes: None,
        };
        let err = static_v.authorize(None, None, None).await.unwrap_err();
        assert!(matches!(err, BearerRefusal::Absent(_)), "{err:?}");
        let err = static_v
            .authorize(Some("Bearer a.b.c"), None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, BearerRefusal::InvalidToken(_)), "{err:?}");

        // A remote source that can't be reached is our fault (mapped to 503).
        let remote = OAuthVerifier {
            keys: OAuthKeySource::Remote(crate::oauth::JwksCache::new(
                "http://127.0.0.1:1/nnrf-oauth2/v1/jwks",
            )),
            expected_audience: None,
            callback_exemptions: Vec::new(),
            resource_scopes: None,
        };
        let err = remote
            .authorize(Some("Bearer a.b.c"), None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, BearerRefusal::KeysUnavailable(_)), "{err:?}");
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
        let hyper_resp = convert_response_with_identity(resp, Some(&identity), None);
        assert_eq!(
            hyper_resp
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok()),
            Some("SMF-54804518-abcd")
        );

        // A 2xx success response is stamped too (harmless, aids debugging).
        let ok = SbiResponse::ok().with_body("{}", "application/json");
        let hyper_ok = convert_response_with_identity(ok, Some(&identity), None);
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
        let hyper_resp = convert_response_with_identity(resp, None, None);
        assert!(hyper_resp.headers().get("server").is_none());
    }

    #[test]
    fn test_convert_response_preserves_handler_server_header() {
        // A handler-supplied Server header is not overwritten.
        let identity = (NfType::Scp, "scp1.operator.com".to_string());
        let resp = SbiResponse::ok().with_header("Server", "custom-server/2.0");
        let hyper_resp = convert_response_with_identity(resp, Some(&identity), None);
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

        // #313: a reserved listener, so the port is never unbound between
        // selection and use.
        let (listener, addr) = crate::test_support::bound_listener().into_parts();
        let port = addr.port();

        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
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
        // #313: the reservation stays bound, and `on_listener` overwrites
        // `config.addr` from the socket, so the caller's placeholder address is
        // irrelevant.
        let (listener, addr) = crate::test_support::bound_listener().into_parts();
        config.addr = addr;
        let server = SbiServer::on_listener(config, listener);
        server.start(handler).await.expect("value expected");
        (server, addr.port())
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

    /// #1334: every request the server answers is counted for `/metrics` by service,
    /// operation template and status -- the handler's answers and the server's own
    /// rejections (413 here) alike -- with no subscriber identifier in a label, and the
    /// health probes are not counted.
    ///
    /// REVERT-VERIFIED: without the `record_sbi_request` call in `SbiService::call`
    /// no `nnef-smcontext` series is rendered and the first assertion fails.
    #[tokio::test]
    async fn served_requests_are_counted_by_service_operation_and_status_1334() {
        use crate::client::SbiClient;
        let config = SbiServerConfig::default().with_max_request_body_size(64);
        let (server, port) = start_test_server(config, |req: SbiRequest| async move {
            if req.header.uri.contains("missing") {
                SbiResponse::with_status(404)
            } else {
                SbiResponse::ok()
            }
        })
        .await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let supi = "imsi-001017777777777";
        for (path, want) in [
            (format!("/nnef-smcontext/v1/{supi}/am-data"), 200),
            (format!("/nnef-smcontext/v1/{supi}/missing"), 404),
        ] {
            let r = client
                .send_request(SbiRequest::get(&path))
                .await
                .expect("answered");
            assert_eq!(r.status, want);
        }
        let big = "x".repeat(10_000);
        let r = client
            .send_request(SbiRequest::post("/nnef-smcontext/v1/echo").with_body(&big, "text/plain"))
            .await
            .expect("answered");
        assert_eq!(r.status, 413);
        let r = client
            .send_request(SbiRequest::get("/health"))
            .await
            .expect("answered");
        assert_eq!(r.status, 200);

        let mut out = String::new();
        nextgcore_metrics::nf::render_sbi(&mut out);
        let value = |series: &str| nextgcore_metrics::nf::sample_value(&out, series);
        assert_eq!(
            value(
                r#"nextgcore_sbi_request_total{service="nnef-smcontext",operation="GET {id}/am-data",status="200"}"#
            ),
            Some(1.0),
            "{out}"
        );
        assert_eq!(
            value(
                r#"nextgcore_sbi_error_total{service="nnef-smcontext",operation="unmatched",status="404"}"#
            ),
            Some(1.0),
            "{out}"
        );
        assert_eq!(
            value(
                r#"nextgcore_sbi_error_total{service="nnef-smcontext",operation="unmatched",status="413"}"#
            ),
            Some(1.0),
            "the server's own rejection is counted too: {out}"
        );
        assert_eq!(
            value(r#"nextgcore_sbi_request_duration_seconds_count{service="nnef-smcontext"}"#),
            Some(3.0),
            "{out}"
        );
        assert!(!out.contains("health"), "probes are not counted: {out}");
        assert!(!out.contains("7777777777"), "no SUPI in a label: {out}");
        server.stop().await.expect("stopped");
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
        token_jwks_with_scope(aud, "nudm-sdm")
    }

    /// [`token_jwks_with_aud`] with an explicit `scope` claim (#1811).
    fn token_jwks_with_scope(aud: &str, scope: &str) -> (String, serde_json::Value) {
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
            "iss": "NRF", "sub": "amf-1", "aud": aud, "scope": scope, "exp": exp
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
            callback_exemptions: Vec::new(),
            resource_scopes: None,
        };
        let header = format!("Bearer {token}");
        assert!(verifier.authorize(Some(&header), None, None).await.is_ok());

        // Same token, but the verifier expects "AMF": a claims mismatch
        // (#1766: 403 ACCESS_TOKEN_CLAIM_MISMATCH on the wire).
        let wrong = OAuthVerifier {
            keys: OAuthKeySource::Static(jwks.clone()),
            expected_audience: Some("AMF".into()),
            callback_exemptions: Vec::new(),
            resource_scopes: None,
        };
        let err = wrong
            .authorize(Some(&header), None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, BearerRefusal::ClaimMismatch { claim: "aud", .. }),
            "{err:?}"
        );

        // No expectation: audience not checked (current behaviour preserved).
        let none = OAuthVerifier {
            keys: OAuthKeySource::Static(jwks),
            expected_audience: None,
            callback_exemptions: Vec::new(),
            resource_scopes: None,
        };
        assert!(none.authorize(Some(&header), None, None).await.is_ok());
    }

    #[tokio::test]
    async fn test_server_oauth_scope_enforced() {
        // The helper's token carries scope "nudm-sdm".
        let (token, jwks) = token_jwks_with_aud("UDM");
        let verifier = OAuthVerifier {
            keys: OAuthKeySource::Static(jwks),
            expected_audience: None,
            callback_exemptions: Vec::new(),
            resource_scopes: None,
        };
        let header = format!("Bearer {token}");

        // Invoked service is in scope -> authorized.
        assert!(verifier
            .authorize(Some(&header), Some("nudm-sdm"), None)
            .await
            .is_ok());

        // A different service the token is not scoped for -> #1766: 403
        // insufficient_scope naming the scope needed.
        let err = verifier
            .authorize(Some(&header), Some("nudm-uecm"), None)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, BearerRefusal::InsufficientScope { scope, .. } if scope == "nudm-uecm"),
            "{err:?}"
        );

        // No required scope (e.g. a non-service path) -> scope check skipped.
        assert!(verifier.authorize(Some(&header), None, None).await.is_ok());
    }

    /// #1811: a resource-level scope is required IN ADDITION to the service
    /// scope. A token scoped for the service alone is refused 403
    /// insufficient_scope naming the resource scope; one carrying both passes;
    /// and a resource that needs none is unaffected.
    #[tokio::test]
    async fn resource_scope_is_required_on_top_of_the_service_scope_1811() {
        use crate::resource_scope::NUDR_DR_AUTH_SUBSCRIPTION_READ as READ;
        let verifier_for = |jwks: serde_json::Value| OAuthVerifier {
            keys: OAuthKeySource::Static(jwks),
            expected_audience: None,
            callback_exemptions: Vec::new(),
            resource_scopes: Some(crate::resource_scope::required_resource_scope),
        };

        let (service_only, jwks) = token_jwks_with_scope("UDR", "nudr-dr");
        let verifier = verifier_for(jwks);
        let header = format!("Bearer {service_only}");
        let err = verifier
            .authorize(Some(&header), Some("nudr-dr"), Some(READ))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, BearerRefusal::InsufficientScope { scope, .. } if scope == READ),
            "{err:?}"
        );
        let resp = err.into_response();
        assert_eq!(resp.status, 403);
        let www = resp
            .http
            .get_header("WWW-Authenticate")
            .cloned()
            .unwrap_or_default();
        assert!(www.contains("error=\"insufficient_scope\""), "{www}");
        assert!(www.contains(&format!("scope=\"{READ}\"")), "{www}");
        assert!(verifier
            .authorize(Some(&header), Some("nudr-dr"), None)
            .await
            .is_ok());

        let (both, jwks) = token_jwks_with_scope("UDR", &format!("nudr-dr {READ}"));
        let verifier = verifier_for(jwks);
        let header = format!("Bearer {both}");
        assert!(verifier
            .authorize(Some(&header), Some("nudr-dr"), Some(READ))
            .await
            .is_ok());

        // The resource scope alone does not stand in for the service scope.
        let (resource_only, jwks) = token_jwks_with_scope("UDR", READ);
        let verifier = verifier_for(jwks);
        let header = format!("Bearer {resource_only}");
        let err = verifier
            .authorize(Some(&header), Some("nudr-dr"), Some(READ))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, BearerRefusal::InsufficientScope { scope, .. } if scope == "nudr-dr"),
            "{err:?}"
        );
    }

    /// #94: the SERVER populates `SbiRequest.oauth2_subject` from the verified
    /// token, so a producer can bind an authorization decision to the caller.
    ///
    /// Drives a real server end to end rather than calling `authorize` directly:
    /// nssfd's authorization tests set the field on a hand-built request, so they
    /// prove nssfd USES it but nothing proved the server SETS it — the recorded
    /// "the helper is tested and the wiring is not" gap. This is the test that
    /// fails if the plumbing is removed.
    #[tokio::test]
    async fn server_records_the_verified_token_subject_on_the_request() {
        let (token, jwks) = token_jwks_with_aud("UDM");

        // The handler reports back what it saw, so the assertion is on the value
        // that actually reached it.
        let seen: Arc<std::sync::Mutex<Option<Option<String>>>> =
            Arc::new(std::sync::Mutex::new(None));
        let sink = Arc::clone(&seen);

        let (listener, addr) = crate::test_support::bound_listener().into_parts();
        let port = addr.port();
        let mut cfg = SbiServerConfig::new(addr);
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        let server = SbiServer::on_listener(cfg, listener);
        server
            .start(move |req: SbiRequest| {
                let sink = Arc::clone(&sink);
                async move {
                    *sink.lock().unwrap_or_else(|e| e.into_inner()) =
                        Some(req.oauth2_subject.clone());
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("server starts");
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let client = crate::client::SbiClient::new(crate::client::SbiClientConfig::new(
            "127.0.0.1".to_string(),
            port,
        ));
        // The helper's token carries scope "nudm-sdm", so the invoked service must
        // be nudm-sdm for the scope check to pass.
        let req = SbiRequest::get("/nudm-sdm/v1/anything")
            .with_header("authorization", format!("Bearer {token}"));
        let resp = client.send_request(req).await.expect("response");
        assert_eq!(resp.status, 204, "a valid token must be accepted");

        let observed = seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .expect("the handler must have run");
        assert_eq!(
            observed.as_deref(),
            Some("amf-1"),
            "the handler must see the verified token's `sub` (issue #94)"
        );

        server.stop().await.expect("stop");
    }

    /// #1766: each TS 29.500 §6.7.3 refusal reaches the wire with its own status,
    /// challenge and ProblemDetails, and none reaches the handler. Before, every
    /// one of them was 401 `error="invalid_token"`, so a consumer could not tell
    /// a stale token from a wrong scope, and nextgcore's own client (#1676)
    /// fetched a fresh token and resent on a scope mismatch it could not fix.
    #[tokio::test]
    async fn each_bearer_refusal_gets_its_own_status_and_challenge_1766() {
        let (token, jwks) = token_jwks_with_aud("UDM");
        let reached = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits = Arc::clone(&reached);
        let (listener, addr) = crate::test_support::bound_listener().into_parts();
        let mut cfg = SbiServerConfig::new(addr);
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg.oauth2_expected_audience = Some("UDM".into());
        let server = SbiServer::on_listener(cfg, listener);
        server
            .start(move |_req: SbiRequest| {
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("server starts");
        let client = crate::client::SbiClient::new(crate::client::SbiClientConfig::new(
            "127.0.0.1".to_string(),
            addr.port(),
        ));
        let send = |path: &str, auth: Option<String>| {
            let mut req = SbiRequest::get(path);
            if let Some(a) = auth {
                req = req.with_header("authorization", a);
            }
            let client = &client;
            async move {
                let resp = client.send_request(req).await.expect("response");
                let www = resp.http.get_header("www-authenticate").cloned();
                let body: serde_json::Value =
                    serde_json::from_str(resp.http.content.as_deref().unwrap_or("null"))
                        .unwrap_or_default();
                (resp.status, www, body)
            }
        };
        let bearer = format!("Bearer {token}");

        // No token, or no BEARER token: 401 with a challenge carrying no `error`.
        for auth in [
            None,
            Some("Basic dXNlcjpwYXNz".to_string()),
            Some("Bearer ".into()),
        ] {
            let (status, www, _) = send("/nudm-sdm/v1/x", auth.clone()).await;
            assert_eq!(status, 401, "{auth:?}");
            assert_eq!(www.as_deref(), Some("Bearer realm=\"5gc-sbi\""), "{auth:?}");
        }

        // A token that does not verify: 401 invalid_token.
        let forged = format!("{}AAAA", &bearer[..bearer.len() - 4]);
        for auth in [forged, "Bearer not-a-jwt".to_string()] {
            let (status, www, _) = send("/nudm-sdm/v1/x", Some(auth.clone())).await;
            assert_eq!(status, 401, "{auth}");
            let www = www.unwrap_or_default();
            assert!(
                www.starts_with(
                    "Bearer realm=\"5gc-sbi\", error=\"invalid_token\", error_description=\""
                ),
                "{www}"
            );
        }

        // A good token whose scope lacks the invoked service: 403 insufficient_scope
        // naming the scope needed, no ProblemDetails cause (TS 29.500 defines none).
        let (status, www, body) = send("/nudm-uecm/v1/x", Some(bearer.clone())).await;
        assert_eq!(status, 403);
        assert_eq!(
            www.as_deref(),
            Some("Bearer realm=\"5gc-sbi\", error=\"insufficient_scope\", scope=\"nudm-uecm\"")
        );
        assert_eq!(body["status"], 403);
        assert!(body.get("cause").is_none(), "{body}");

        // Control: the same token on the service it is scoped for is admitted.
        assert_eq!(send("/nudm-sdm/v1/x", Some(bearer)).await.0, 204);
        assert_eq!(reached.load(std::sync::atomic::Ordering::SeqCst), 1);
        server.stop().await.expect("stop");

        // A good token minted for another producer: 403 ACCESS_TOKEN_CLAIM_MISMATCH
        // naming `aud`.
        let (other, other_jwks) = token_jwks_with_aud("AMF");
        let (listener, addr) = crate::test_support::bound_listener().into_parts();
        let mut cfg = SbiServerConfig::new(addr);
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(other_jwks);
        cfg.oauth2_expected_audience = Some("UDM".into());
        let server = SbiServer::on_listener(cfg, listener);
        server
            .start(|_req: SbiRequest| async { SbiResponse::with_status(204) })
            .await
            .expect("server starts");
        let client = crate::client::SbiClient::new(crate::client::SbiClientConfig::new(
            "127.0.0.1".to_string(),
            addr.port(),
        ));
        let req = SbiRequest::get("/nudm-sdm/v1/x")
            .with_header("authorization", format!("Bearer {other}"));
        let resp = client.send_request(req).await.expect("response");
        assert_eq!(resp.status, 403);
        assert_eq!(
            resp.http.get_header("www-authenticate").map(String::as_str),
            Some("Bearer realm=\"5gc-sbi\", error=\"invalid_token\"")
        );
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["cause"], "ACCESS_TOKEN_CLAIM_MISMATCH");
        assert_eq!(
            body["invalidParams"],
            serde_json::json!([{ "param": "aud" }])
        );
        server.stop().await.expect("stop");
    }

    /// #1766: a challenge attribute never carries a raw double quote or
    /// backslash, which would end the quoted string early.
    #[test]
    fn challenge_text_keeps_the_quoted_string_closed_1766() {
        assert_eq!(
            challenge_text("audience \"AMF\" \\ é"),
            "audience 'AMF' ' ?"
        );
    }

    /// A request that carries no token at all leaves `oauth2_subject` unset —
    /// the field must never be populated from anything the caller can assert.
    #[tokio::test]
    async fn oauth2_subject_is_absent_without_oauth2_enforcement() {
        let seen: Arc<std::sync::Mutex<Option<Option<String>>>> =
            Arc::new(std::sync::Mutex::new(None));
        let sink = Arc::clone(&seen);

        let (listener, addr) = crate::test_support::bound_listener().into_parts();
        let port = addr.port();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        server
            .start(move |req: SbiRequest| {
                let sink = Arc::clone(&sink);
                async move {
                    *sink.lock().unwrap_or_else(|e| e.into_inner()) =
                        Some(req.oauth2_subject.clone());
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("server starts");
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let client = crate::client::SbiClient::new(crate::client::SbiClientConfig::new(
            "127.0.0.1".to_string(),
            port,
        ));
        // A caller-supplied Authorization header on a listener that does NOT
        // require OAuth2 must not become an identity.
        let req = SbiRequest::get("/nudm-sdm/v1/anything")
            .with_header("authorization", "Bearer not.a.real.token");
        assert_eq!(
            client.send_request(req).await.expect("response").status,
            204
        );

        let observed = seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .expect("handler ran");
        assert!(
            observed.is_none(),
            "an unverified bearer header must NOT become an attested identity, got {observed:?}"
        );

        server.stop().await.expect("stop");
    }

    // ─── #65: query percent-decode, header multiplicity, graceful shutdown ───

    /// Capture what the handler saw, so a test can assert on the DECODED params
    /// rather than on a response the handler could have produced anyway.
    fn param_capturing_handler() -> (
        impl SbiRequestHandler,
        Arc<std::sync::Mutex<Option<SbiRequest>>>,
    ) {
        let seen = Arc::new(std::sync::Mutex::new(None));
        let sink = seen.clone();
        let handler = move |req: SbiRequest| {
            let sink = sink.clone();
            async move {
                *sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(req);
                SbiResponse::with_status(204)
            }
        };
        (handler, seen)
    }

    /// #65 acceptance: the server percent-DECODES query parameters.
    ///
    /// The query is put on the request URI verbatim so the client cannot be the
    /// thing that decodes it — the assertion is about `convert_request` and
    /// nothing else. The value is the JSON shape TS 29.500 §5.2.10.2 forces a
    /// producer to encode.
    #[tokio::test]
    async fn server_percent_decodes_query_parameters() {
        use crate::client::SbiClient;

        let (handler, seen) = param_capturing_handler();
        let (server, port) = start_test_server(SbiServerConfig::default(), handler).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // %5B%7B%22sst%22%3A1%2C%22sd%22%3A%22000001%22%7D%5D == [{"sst":1,"sd":"000001"}]
        let resp = client
            .send_request(SbiRequest::get(
                "/nnrf-disc/v1/nf-instances?snssais=%5B%7B%22sst%22%3A1%2C%22sd%22%3A%22000001%22%7D%5D",
            ))
            .await
            .expect("response");
        assert_eq!(resp.status, 204);

        let req = seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .expect("handler ran");
        let snssais = req.http.get_param("snssais").expect("param present");
        assert_eq!(
            snssais, r#"[{"sst":1,"sd":"000001"}]"#,
            "the server must decode; a verbatim value here is the #65 defect"
        );
        // The whole point: it is now parseable JSON, which is what every consumer
        // does with it.
        let parsed: serde_json::Value = serde_json::from_str(snssais).expect("valid JSON");
        assert_eq!(parsed[0]["sd"], "000001");

        server.stop().await.expect("stop");
    }

    /// #65 acceptance: an `=`-less query parameter survives as present-but-empty.
    ///
    /// It used to be dropped, which a handler cannot tell apart from the peer
    /// never having sent it.
    #[tokio::test]
    async fn server_preserves_valueless_query_flags() {
        use crate::client::SbiClient;

        let (handler, seen) = param_capturing_handler();
        let (server, port) = start_test_server(SbiServerConfig::default(), handler).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        client
            .send_request(SbiRequest::get("/x/y?flag&other=1"))
            .await
            .expect("response");

        let req = seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .expect("handler ran");
        assert_eq!(
            req.http.get_param("flag").map(String::as_str),
            Some(""),
            "a valueless flag must be present with an empty value, not absent"
        );
        assert_eq!(req.http.get_param("other").map(String::as_str), Some("1"));

        server.stop().await.expect("stop");
    }

    /// #65 acceptance: two `3gpp-Sbi-Oci` **field lines** are individually
    /// retrievable — the header map no longer collapses repeated occurrences.
    ///
    /// TS 29.500 §6.4.3 gives each occurrence an independent scope, so keeping
    /// only one is not a formatting detail: a producer reporting overload for two
    /// scopes was read as reporting for one.
    ///
    /// Driven with a RAW hyper client on purpose. `SbiClient` stores headers in a
    /// map, so it can only ever emit one field line per name — the first version
    /// of this test used it, and passed with the server-side fix reverted, because
    /// it was really only exercising `get_header_all`'s comma splitting. Two
    /// genuine field lines are the only input that can distinguish `append_header`
    /// from `set_header` on the ingest path.
    #[tokio::test]
    async fn server_keeps_every_repeated_oci_occurrence() {
        let (handler, seen) = param_capturing_handler();
        let (server, port) = start_test_server(SbiServerConfig::default(), handler).await;

        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let (mut sender, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            TokioIo::new(stream),
        )
        .await
        .expect("h2 handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // `Builder::header` APPENDS, so this is two field lines on the wire.
        let request = Request::builder()
            .method("GET")
            .uri("/x")
            .header(
                crate::constants::custom_header::OCI,
                "Timestamp: 2026-01-01T00:00:00Z; Overload-Reduction-Metric: 10; DNN: internet",
            )
            .header(
                crate::constants::custom_header::OCI,
                "Timestamp: 2026-01-01T00:00:01Z; Overload-Reduction-Metric: 60",
            )
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = sender.send_request(request).await.expect("response");
        assert_eq!(response.status().as_u16(), 204);

        let seen_req = seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .expect("handler ran");
        let all = seen_req
            .http
            .get_header_all(crate::constants::custom_header::OCI);
        assert_eq!(
            all.len(),
            2,
            "both OCI field lines must survive ingest, got {all:?}"
        );
        let metrics: Vec<u8> = all
            .iter()
            .filter_map(|v| crate::overload::Oci::parse(v))
            .map(|o| o.reduction_metric)
            .collect();
        assert_eq!(
            metrics,
            vec![10, 60],
            "each occurrence must parse independently, in arrival order"
        );
        // The scoped occurrence kept its scope parameter, which is what makes a
        // future per-DNN reaction possible.
        assert!(
            all[0].contains("DNN: internet"),
            "the scope parameter must survive verbatim, got {:?}",
            all[0]
        );

        server.stop().await.expect("stop");
    }

    /// #65 acceptance: `stop()` drains in-flight streams instead of killing them.
    ///
    /// The handler parks on a signal the test controls, so shutdown is requested
    /// while the request is genuinely mid-flight. Before the graceful path
    /// existed, the connection task was detached and the client saw a transport
    /// error here.
    ///
    /// #326: this used to assert a wall-clock LOWER BOUND on how long `stop()`
    /// blocked (`elapsed() >= 150 ms`) after an unsynchronised 80 ms sleep that
    /// merely hoped the request had reached the handler. Under a loaded
    /// whole-workspace run the 80 ms overshot, the fixed 300 ms handler was
    /// already more than 150 ms through by the time `stop()` was called, and the
    /// bound failed with nothing wrong with the drain — about 1 run in 5. The
    /// property is an ORDERING, not a duration, so it is asserted as one:
    ///
    /// - the handler signals ENTRY, so nothing has to guess when it was reached;
    /// - `stop()` runs in its own task, and the test asserts that task is STILL
    ///   PENDING while the handler is parked. That is deterministic in both
    ///   directions: the drain barrier cannot release until the connection task
    ///   returns, which cannot happen until the handler does, so no amount of
    ///   scheduling delay can make a correct `stop()` look finished.
    ///
    /// The `sleep` before the pending check is a revert-DETECTOR, not a
    /// correctness dependency: a `stop()` that skips the drain needs some slice of
    /// time to run to completion before `is_finished()` can observe it. Waiting
    /// longer never invalidates the assertion, which is the direction that makes
    /// it safe under load.
    ///
    /// Ceiling, stated rather than implied: this asserts the OBSERVABLE
    /// consequence of the GOAWAY (in-flight completes, connection then closes),
    /// not the frame itself — hyper exposes no hook to read the peer's GOAWAY, so
    /// frame-level inspection would need a raw h2 client this crate does not use.
    #[tokio::test]
    async fn stop_drains_an_in_flight_request() {
        use crate::client::SbiClient;
        use tokio::sync::Notify;

        // `entered` fires on handler entry; `release` lets the test decide when the
        // handler returns. `Notify` rather than a oneshot because the handler is an
        // `Fn` and may be called more than once, and because a `notify_one` that
        // arrives first stores its permit instead of being lost.
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());

        let handler = {
            let entered = entered.clone();
            let release = release.clone();
            move |_req: SbiRequest| {
                let entered = entered.clone();
                let release = release.clone();
                async move {
                    entered.notify_one();
                    release.notified().await;
                    SbiResponse::with_status(200).with_body("drained", "text/plain")
                }
            }
        };

        let (server, port) = start_test_server(SbiServerConfig::default(), handler).await;
        let client = Arc::new(SbiClient::with_host_port("127.0.0.1", port));

        let in_flight = {
            let client = client.clone();
            tokio::spawn(async move { client.send_request(SbiRequest::get("/slow")).await })
        };

        // Synchronised, not slept for: the handler is now definitely running and
        // parked, so the request is definitely in flight.
        entered.notified().await;

        let server = Arc::new(server);
        let stop_task = {
            let server = server.clone();
            tokio::spawn(async move { server.stop().await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !stop_task.is_finished(),
            "stop() returned while a stream was still in flight, so it did not drain"
        );

        release.notify_one();

        let response = in_flight
            .await
            .expect("task joined")
            .expect("an in-flight request must complete across a graceful shutdown");
        assert_eq!(response.status, 200);
        assert_eq!(response.http.content.as_deref(), Some("drained"));

        stop_task.await.expect("stop task joined").expect("stop");
    }

    /// #65: after a graceful stop the listener is gone, so a NEW connection is
    /// refused. Together with the drain test above this pins both halves of
    /// RFC 9113 §6.8 — finish what is in flight, accept nothing new.
    #[tokio::test]
    async fn stop_refuses_new_connections() {
        use crate::client::SbiClient;

        let (server, port) =
            start_test_server(SbiServerConfig::default(), |_req: SbiRequest| async {
                SbiResponse::with_status(204)
            })
            .await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        assert_eq!(
            client
                .send_request(SbiRequest::get("/x"))
                .await
                .expect("first response")
                .status,
            204
        );

        server.stop().await.expect("stop");

        // A fresh client cannot connect at all.
        let after = SbiClient::with_host_port("127.0.0.1", port);
        assert!(
            after.send_request(SbiRequest::get("/x")).await.is_err(),
            "the listener must be closed after stop()"
        );
    }

    /// #65: with a reporter attached and a non-zero metric, every response
    /// carries `3gpp-Sbi-Oci` — the producer half of TS 29.500 §6.4 that had no
    /// caller before.
    #[tokio::test]
    async fn responses_carry_oci_when_the_nf_reports_overload() {
        use crate::client::SbiClient;
        use crate::overload::OverloadReporter;

        let reporter = Arc::new(OverloadReporter::new());
        let config = SbiServerConfig::default().with_overload_reporter(reporter.clone());
        let (server, port) = start_test_server(config, |_req: SbiRequest| async {
            SbiResponse::with_status(204)
        })
        .await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Not overloaded: no header at all, so an NF that never sets a metric is
        // byte-identical to before.
        let quiet = client
            .send_request(SbiRequest::get("/x"))
            .await
            .expect("response");
        assert!(
            quiet
                .http
                .get_header(crate::constants::custom_header::OCI)
                .is_none(),
            "a reporter at metric 0 must emit nothing"
        );

        reporter.set_reduction_metric(40);
        reporter.set_validity_secs(75);
        let loaded = client
            .send_request(SbiRequest::get("/x"))
            .await
            .expect("response");
        let oci = loaded
            .http
            .get_header(crate::constants::custom_header::OCI)
            .expect("OCI stamped once the NF reports overload");
        let parsed = crate::overload::Oci::parse(oci).expect("parseable OCI");
        assert_eq!(parsed.reduction_metric, 40);
        assert_eq!(parsed.period_of_validity_secs, Some(75));

        server.stop().await.expect("stop");
    }
}

/// #1338: a kubelet `tcpSocket` probe against the SBI port.
#[cfg(test)]
mod tcp_probe_tests {
    use crate::message::{SbiRequest, SbiResponse};
    use std::time::Duration;

    /// The measured symptom, reproduced: a connection that is opened and closed
    /// without an HTTP/2 preface -- exactly what a `tcpSocket` probe does, four
    /// times per 30 s under the Helm chart's readiness (10 s) + liveness (30 s)
    /// probes -- ended the server's connection task with h2's `UnexpectedEof`,
    /// which was printed as the bare `HTTP/2 connection error: connection error`.
    /// It is an orderly peer close: one `debug` record naming the prober.
    #[tokio::test]
    async fn a_tcp_probe_without_a_preface_is_logged_at_debug_with_the_prober() {
        assert!(
            nextgcore_core::test_log::init(),
            "premise: the capture logger"
        );
        let (server, addr) =
            crate::test_support::sbi_server_on_free_port(|_req: SbiRequest| async {
                SbiResponse::with_status(200)
            })
            .await;

        let probe = tokio::net::TcpStream::connect(addr)
            .await
            .expect("probe connects");
        let prober = probe.local_addr().expect("probe address");
        // A watch, registered before the close that logs: the shared capture
        // buffer evicts under parallel trace output (#1360).
        let watch = nextgcore_core::test_log::watch(format!("with {prober} "));
        drop(probe); // FIN, no preface: a kubelet tcpSocket probe

        let records = crate::test_support::poll_until(
            Duration::from_secs(5),
            Duration::from_millis(20),
            || {
                let found = watch.records();
                async move { (!found.is_empty()).then_some(found) }
            },
        )
        .await
        .unwrap_or_default();
        assert_eq!(records.len(), 1, "one connection-end record: {records:?}");
        assert!(
            records[0].starts_with("DEBUG ")
                && records[0].contains(&format!("SBI server HTTP/2 connection with {prober}"))
                && records[0].contains("closed by peer")
                && records[0].contains("preface"),
            "{records:?}"
        );
        server.stop().await.expect("stop");
    }
}

/// #1338 follow-up: the `https` SBI port under a probe, and accept-error backoff.
#[cfg(test)]
mod accept_path_tests {
    use super::{AcceptBackoff, ACCEPT_BACKOFF_MAX};
    use crate::message::{SbiRequest, SbiResponse};
    use crate::server::{SbiServer, SbiServerConfig};
    use std::time::Duration;

    /// The watch's records, once at least one has arrived (5 s budget).
    async fn records_matching(watch: &nextgcore_core::test_log::Watch) -> Vec<String> {
        crate::test_support::poll_until(Duration::from_secs(5), Duration::from_millis(20), || {
            let found = watch.records();
            async move { (!found.is_empty()).then_some(found) }
        })
        .await
        .unwrap_or_default()
    }

    /// A self-signed `localhost` certificate and key, written as PEM into a
    /// temporary directory that is removed when the returned guard drops.
    /// Returns `(guard, key_path, cert_path)`.
    fn self_signed_pem() -> (tempfile::TempDir, String, String) {
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("self-signed cert");
        let dir = tempfile::Builder::new()
            .prefix("sbi-1338-tls-probe-")
            .tempdir()
            .expect("temp dir");
        let key_path = dir.path().join("key.pem");
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&key_path, key.serialize_pem()).expect("write key");
        std::fs::write(&cert_path, cert.pem()).expect("write cert");
        (
            dir,
            key_path.to_string_lossy().into_owned(),
            cert_path.to_string_lossy().into_owned(),
        )
    }

    /// The production profile serves `https`, so a kubelet `tcpSocket` probe
    /// there ends in the TLS accept, before HTTP/2 starts. A connect and close
    /// with no ClientHello must be one `debug` record naming the prober, never a
    /// `warn`: otherwise every TLS NF would warn every 7.5 s.
    #[tokio::test]
    async fn a_tcp_probe_on_a_tls_sbi_port_is_logged_at_debug_not_warn() {
        assert!(
            nextgcore_core::test_log::init(),
            "premise: the capture logger"
        );
        let (_pem_dir, key, cert) = self_signed_pem();
        let (server, addr) = crate::test_support::sbi_server_on_free_port_with(
            |addr| SbiServerConfig::new(addr).with_tls(key, cert),
            |_req: SbiRequest| async { SbiResponse::with_status(200) },
        )
        .await;

        let probe = tokio::net::TcpStream::connect(addr)
            .await
            .expect("probe connects");
        let prober = probe.local_addr().expect("probe address");
        // A watch, registered before the close that logs: the shared capture
        // buffer evicts under parallel trace output (#1360).
        let watch = nextgcore_core::test_log::watch(format!("from {prober}"));
        drop(probe); // FIN, no ClientHello: a kubelet tcpSocket probe

        let records = records_matching(&watch).await;
        assert_eq!(records.len(), 1, "one TLS-accept record: {records:?}");
        assert!(
            records[0].starts_with("DEBUG ")
                && records[0].contains(&format!("SBI server TLS accept from {prober}"))
                && records[0].contains("peer closed before the handshake"),
            "a probe on an https port is an orderly close, not a warning: {records:?}"
        );
        server.stop().await.expect("stop");
    }

    /// The backoff sequence: doubling from 10 ms, capped at 1 s, reset by a
    /// successful accept.
    #[test]
    fn accept_backoff_doubles_to_a_cap_and_resets_on_success() {
        let mut b = AcceptBackoff::default();
        let ms: Vec<u128> = (0..10).map(|_| b.on_error().as_millis()).collect();
        assert_eq!(ms, [10, 20, 40, 80, 160, 320, 640, 1000, 1000, 1000]);
        for _ in 0..100 {
            assert_eq!(b.on_error(), ACCEPT_BACKOFF_MAX, "stays capped");
        }
        b.on_success();
        assert_eq!(
            b.on_error(),
            Duration::from_millis(10),
            "reset by a success"
        );
    }

    /// Through the real accept loop: a listener whose read side is shut down
    /// fails every `accept()` at once with EINVAL, as EMFILE would. With the
    /// backoff it warns at about 0, 10, 30, 70, 150, 310, 630 and 1270 ms, so
    /// eight times in 1.4 s, and is then inside a 1 s pause. Without the
    /// backoff the loop spun: 464 warns in 500 ms when revert-checked.
    #[tokio::test]
    async fn persistent_accept_errors_are_paced_not_spun() {
        assert!(
            nextgcore_core::test_log::init(),
            "premise: the capture logger"
        );
        let (listener, addr) = crate::test_support::bound_listener().into_parts();
        socket2::SockRef::from(&listener)
            .shutdown(std::net::Shutdown::Read)
            .expect("shut the listener's read side");
        // A watch, registered before the loop starts failing: the shared
        // capture buffer evicts under parallel trace output, which once left a
        // single record of eight in CI (#1342, #1360).
        let watch = nextgcore_core::test_log::watch(format!("SBI server on {addr}: accept failed"));
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        server
            .start(|_req: SbiRequest| async { SbiResponse::with_status(200) })
            .await
            .expect("start");

        tokio::time::sleep(Duration::from_millis(1_400)).await;
        let warns: Vec<String> = watch
            .records()
            .into_iter()
            .filter(|r| r.starts_with("WARN "))
            .collect();
        let newest = warns
            .last()
            .cloned()
            .expect("premise: accept() fails on a shut-down listener");
        let in_a_row: u32 = newest
            .split_once(" in a row")
            .and_then(|(head, _)| head.rsplit_once(" ("))
            .and_then(|(_, k)| k.parse().ok())
            .unwrap_or_else(|| panic!("no '(k in a row' in {newest:?}"));
        assert!(
            in_a_row >= 2,
            "premise: accept() keeps failing on a shut-down listener: {newest:?}"
        );
        assert!(
            in_a_row <= 10,
            "accept errors are paced, not spun: {in_a_row} errors in 1.4 s"
        );
        assert_eq!(
            warns.len() as u32,
            in_a_row,
            "one warn per accept error, none lost: {warns:?}"
        );

        // stop() waits for the accept task to exit, and the task is now about
        // 130 ms into a 1 s pause. The pause races the shutdown signal, so
        // stop() returns at once instead of waiting out the pause.
        tokio::time::timeout(Duration::from_millis(300), server.stop())
            .await
            .expect("stop() is not held up by the accept pause")
            .expect("stop");
    }
}

/// #1421: callback routes an NF registers are admitted without a bearer token
/// when their path carries a callback token the NF holds; nothing else is.
#[cfg(test)]
mod oauth2_callback_exemption_tests {
    use super::{path_segment_refusal, OAuth2CallbackExemption, SbiServer, SbiServerConfig};
    use crate::message::{SbiRequest, SbiResponse};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const GOOD: &str = "0123456789abcdef0123456789abcdef";
    const CALLBACK: &str = "/nx-callback/v1/ue-1/dereg-notify";

    /// Paths the handler saw, in order.
    type Seen = Arc<Mutex<Vec<String>>>;

    async fn start(jwks: Option<serde_json::Value>) -> (SbiServer, std::net::SocketAddr, Seen) {
        let seen: Seen = Arc::default();
        let sink = Arc::clone(&seen);
        let (listener, addr) = crate::test_support::bound_listener().into_parts();
        let mut cfg = SbiServerConfig::new(addr).with_oauth2_callback_exemption(
            OAuth2CallbackExemption::new(
                "POST",
                "/nx-callback/v1/{var}/dereg-notify/{token}",
                |cb| cb.vars == ["ue-1"] && cb.token == GOOD,
            ),
        );
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = jwks;
        let server = SbiServer::on_listener(cfg, listener);
        server
            .start(move |req: SbiRequest| {
                let sink = Arc::clone(&sink);
                async move {
                    assert!(req.oauth2_subject.is_none(), "no bearer was verified");
                    sink.lock().unwrap().push(req.header.uri.clone());
                    SbiResponse::no_content()
                }
            })
            .await
            .expect("server starts");
        (server, addr, seen)
    }

    /// One request with `method` and the raw `path_and_query`, no bearer; the
    /// status and the `WWW-Authenticate` value.
    async fn send(
        addr: std::net::SocketAddr,
        method: &str,
        path_and_query: &str,
    ) -> (u16, Option<String>) {
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (client, conn) = h2::client::handshake(tcp).await.expect("h2 handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut client = client.ready().await.expect("ready");
        let req = hyper::Request::builder()
            .method(method)
            .uri(format!("http://{addr}{path_and_query}"))
            .header("content-type", "application/json")
            .body(())
            .expect("request");
        let (answer, mut body) = client.send_request(req, false).expect("send");
        body.send_data(bytes::Bytes::from_static(b"{}"), true)
            .expect("data");
        let answer = tokio::time::timeout(Duration::from_secs(5), answer)
            .await
            .expect("answered")
            .expect("response");
        let www = answer
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        (answer.status().as_u16(), www)
    }

    /// #1934 review M1: the path shapes every check must agree on.
    #[test]
    fn malformed_paths_are_refused_before_routing_1934() {
        for ok in [
            "/",
            "/nnsacf-nsac/v1/slices/local-configs/update",
            "/nudr-dr/v2/subscription-data/imsi-001010000000001/authentication-data/authentication-subscription",
            "/a/b.c/..d/x%20y",
            // #1939 item 1: an encoded separator inside an identifier.
            "/nudr-dr/v2/application-data/pfds/vendor%2Fapp",
            "/nnef-pfdmanagement/v1/applications/a%5Cb",
        ] {
            assert_eq!(path_segment_refusal(ok), None, "{ok}");
        }
        for bad in [
            "//nnsacf-nsac/v1/slices/local-configs/update",
            "/nnsacf-nsac/v1//slices/local-configs/update",
            "/nnsacf-nsac/v1/slices//local-configs/update",
            "/nnsacf-nsac/v1/slices/local-configs/update/",
            "/nnsacf-nsac/v1/slices/./local-configs/update",
            "/nnsacf-nsac/v1/x/../slices/local-configs/update",
            "/nnsacf-nsac/v1/%2e%2E/slices",
            "/nnsacf-nsac/v1/%2E/slices",
        ] {
            assert!(path_segment_refusal(bad).is_some(), "{bad}");
        }
    }

    /// #1934: the server answers 400 for a malformed path before the OAuth2
    /// check (no bearer here, and the answer is not 401) and before the handler.
    #[tokio::test]
    async fn the_server_refuses_a_malformed_path_before_auth_and_routing_1934() {
        let (server, addr, seen) = start(empty_jwks()).await;
        let before = seen.lock().unwrap().len();
        for bad in [
            format!("{CALLBACK}//{GOOD}"),
            format!("{CALLBACK}/{GOOD}/"),
            format!("{CALLBACK}/../{GOOD}"),
        ] {
            assert_eq!(send(addr, "POST", &bad).await.0, 400, "{bad}");
        }
        assert_eq!(seen.lock().unwrap().len(), before, "no handler ran");
        assert_eq!(
            send(addr, "POST", &format!("{CALLBACK}/{GOOD}")).await.0,
            204
        );
        server.stop().await.expect("stop");
    }

    fn empty_jwks() -> Option<serde_json::Value> {
        Some(serde_json::json!({"keys": []}))
    }

    #[tokio::test]
    async fn a_token_less_callback_carrying_a_held_token_reaches_the_handler() {
        let (server, addr, seen) = start(empty_jwks()).await;
        let path = format!("{CALLBACK}/{GOOD}");
        assert_eq!(send(addr, "POST", &path).await.0, 204);
        // The query is not part of the route: the handler sees the same path.
        assert_eq!(send(addr, "POST", &format!("{path}?x=1")).await.0, 204);
        assert_eq!(*seen.lock().unwrap(), vec![path.clone(), path]);
        server.stop().await.expect("stop");
    }

    /// Every request shape that is not the registered route with a held token
    /// is answered 401 Bearer, and none reaches the handler.
    #[tokio::test]
    async fn every_other_request_shape_still_needs_a_bearer() {
        let (server, addr, seen) = start(empty_jwks()).await;
        let wrong = "f".repeat(32);
        let posts = [
            // A service route.
            "/nx-svc/v1/ue-contexts/ue-1".to_string(),
            // The callback with a wrong, missing or empty token.
            format!("{CALLBACK}/{wrong}"),
            CALLBACK.to_string(),
            format!("{CALLBACK}/"),
            // Another UE's callback carrying this UE's token.
            format!("/nx-callback/v1/ue-2/dereg-notify/{GOOD}"),
            // Variant spellings of the right route.
            format!("{CALLBACK}/{GOOD}/"),
            format!("/{CALLBACK}/{GOOD}"),
            format!("/nx-callback//v1/ue-1/dereg-notify/{GOOD}"),
            format!("{CALLBACK}/{GOOD}/extra"),
            format!("{CALLBACK}/{GOOD}/../../../../nx-svc/v1/ue-contexts/ue-1"),
            format!("/nx-callback/v1/../dereg-notify/{GOOD}"),
            format!("/nx-callback/v1/./dereg-notify/{GOOD}"),
            format!("/nx%2Dcallback/v1/ue-1/dereg-notify/{GOOD}"),
            format!("/nx-callback/v1/ue%2D1/dereg-notify/{GOOD}"),
            format!("{CALLBACK}%2F{GOOD}"),
            format!("{CALLBACK}/{GOOD}%2F..%2F..%2Fnx-svc"),
            format!("/NX-CALLBACK/v1/ue-1/dereg-notify/{GOOD}"),
        ];
        for path in &posts {
            let (status, www) = send(addr, "POST", path).await;
            // #1934: a malformed spelling (empty, dot or encoded-separator
            // segment) is refused 400 before the exemption is even consulted;
            // every other one still needs a bearer.
            if path_segment_refusal(path).is_some() {
                assert_eq!(status, 400, "POST {path}");
                continue;
            }
            assert_eq!(status, 401, "POST {path}");
            assert!(
                www.as_deref().is_some_and(|w| w.starts_with("Bearer")),
                "POST {path}: {www:?}"
            );
        }
        let good = format!("{CALLBACK}/{GOOD}");
        for method in ["GET", "PUT", "PATCH", "DELETE"] {
            assert_eq!(send(addr, method, &good).await.0, 401, "{method} {good}");
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "{:?}",
            seen.lock().unwrap()
        );

        // Control: the same server admits the registered route.
        assert_eq!(send(addr, "POST", &good).await.0, 204);
        assert_eq!(*seen.lock().unwrap(), vec![good]);
        server.stop().await.expect("stop");
    }

    /// With no verification keys the server fails closed on service routes
    /// (503); a callback needs no keys, so its token alone admits it.
    #[tokio::test]
    async fn a_callback_needs_no_verification_keys() {
        let (server, addr, seen) = start(None).await;
        assert_eq!(
            send(addr, "POST", "/nx-svc/v1/ue-contexts/ue-1").await.0,
            503
        );
        assert_eq!(
            send(addr, "POST", &format!("{CALLBACK}/{}", "f".repeat(32)))
                .await
                .0,
            503
        );
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(
            send(addr, "POST", &format!("{CALLBACK}/{GOOD}")).await.0,
            204
        );
        server.stop().await.expect("stop");
    }

    /// The exemption list is opt-in: a server that registers none answers the
    /// same token-less callback 401.
    #[tokio::test]
    async fn without_a_registered_exemption_a_callback_needs_a_bearer() {
        let (listener, addr) = crate::test_support::bound_listener().into_parts();
        let mut cfg = SbiServerConfig::new(addr);
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = empty_jwks();
        assert!(cfg.oauth2_callback_exemptions.is_empty());
        let server = SbiServer::on_listener(cfg, listener);
        server
            .start(|_req: SbiRequest| async { SbiResponse::no_content() })
            .await
            .expect("server starts");
        assert_eq!(
            send(addr, "POST", &format!("{CALLBACK}/{GOOD}")).await.0,
            401
        );
        server.stop().await.expect("stop");
    }
}
