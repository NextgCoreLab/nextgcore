//! N32 HTTP server and client paths (TS 29.573).
//!
//! Server side (one listener serves both N32-c and N32-f):
//! - POST /n32c-handshake/v1/exchange-capability  (sec 6.1.5.2)
//! - POST /n32c-handshake/v1/exchange-params      (sec 6.1.5.3)
//! - POST /n32c-handshake/v1/n32f-error           (sec 6.1.5.4)
//! - POST /n32f-forward/v1/n32f-process           (sec 6.2)
//!
//! Client side: `initiate_n32c_handshake` drives exchange-capability and
//! (for PRINS) exchange-params against a peer SEPP; `forward_via_n32f`
//! sends a protected SBI request; `send_n32f_error` reports decode/verify
//! failures back to the sending SEPP.
//!
//! mTLS: the listener supports TLS with client-certificate verification
//! (`verify_client_cacert`) and the client presents a certificate when
//! `client_cert`/`client_key` are configured — both via the existing
//! rustls plumbing in nextgcore-sbi.

use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use nextgcore_sbi::message::{SbiRequest as HttpRequest, SbiResponse as HttpResponse};
use nextgcore_sbi::security::{SbiProfile, TlsPaths};
use nextgcore_sbi::server::{send_error, SbiServer, SbiServerConfig};

use crate::context::{sepp_self, PlmnId, SecurityCapability, SeppNode};
use crate::n32c_build::{
    build_security_capability_request, build_security_capability_response, PlmnIdJson,
    SecurityCapabilityRequestJson, SecurityCapabilityResponseJson,
};
use crate::n32c_handler::{
    self, SecNegotiateReqData, SecNegotiateRspData, SecParamExchReqData, SecParamExchRspData,
};
use crate::prins::{self, N32fErrorInfo, N32fErrorType, N32fReformattedMessage};

/// Bounded timeouts for all N32 client calls
const N32_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const N32_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

// ============================================================================
// Listener
// ============================================================================

/// TLS settings for the N32 listener / client
#[derive(Debug, Clone, Default)]
pub struct N32TlsConfig {
    /// Server certificate (PEM)
    pub cert: Option<String>,
    /// Server private key (PEM)
    pub key: Option<String>,
    /// CA bundle for verifying peer-SEPP client certificates; enables mTLS
    pub verify_client_cacert: Option<String>,
    /// Client certificate presented on outgoing N32 connections (mTLS)
    pub client_cert: Option<String>,
    /// Client private key for outgoing N32 connections (mTLS)
    pub client_key: Option<String>,
    /// CA bundle for verifying the peer server certificate
    pub ca_cert: Option<String>,
    /// Explicitly disable mTLS client verification on the N32-c listener.
    /// mTLS is REQUIRED by default whenever TLS is configured (TS 33.501:
    /// N32-c is a mutually-authenticated TLS connection); this escape hatch
    /// is for constrained lab setups only.
    pub allow_insecure_no_mtls: bool,
}

impl N32TlsConfig {
    /// The effective CA bundle used to verify peer-SEPP client certificates.
    /// Defaults to the explicit `verify_client_cacert`, falling back to the
    /// peer server CA bundle (`ca_cert`), so mTLS is on by default whenever
    /// any CA material is configured.
    pub fn effective_client_cacert(&self) -> Option<&str> {
        self.verify_client_cacert
            .as_deref()
            .or(self.ca_cert.as_deref())
    }
}

/// Start the N32 listener. Returns the server handle (caller stops it).
pub async fn start_n32_listener(
    host: &str,
    port: u16,
    tls: Option<&N32TlsConfig>,
) -> Result<SbiServer, String> {
    let mut config = SbiServerConfig::with_host_port(host, port).map_err(|e| e.to_string())?;
    config = config.with_interface("n32");

    let mut mtls_on = false;
    if let Some(tls_cfg) = tls {
        if let (Some(key), Some(cert)) = (&tls_cfg.key, &tls_cfg.cert) {
            config = config.with_tls(key.clone(), cert.clone());
            // N32-c MUST be mutually-authenticated TLS (TS 33.501). mTLS is
            // ON by default whenever TLS is configured; it is only skipped
            // when explicitly opted out, and even then we warn loudly.
            match tls_cfg.effective_client_cacert() {
                Some(ca) if !tls_cfg.allow_insecure_no_mtls => {
                    config.verify_client = true;
                    config.verify_client_cacert = Some(ca.to_string());
                    mtls_on = true;
                }
                Some(_) => {
                    log::warn!(
                        "N32-c mTLS explicitly DISABLED (allow_insecure_no_mtls) on \
                         {host}:{port}; peer SEPPs will NOT be client-authenticated"
                    );
                }
                None if !tls_cfg.allow_insecure_no_mtls => {
                    return Err(format!(
                        "N32-c on {host}:{port} requires mTLS but no client CA bundle \
                         (n32_mtls_cacert / n32_ca_cert) is configured; provide one or set \
                         allow_insecure_no_mtls for lab use"
                    ));
                }
                None => {
                    log::warn!(
                        "N32-c mTLS DISABLED with no client CA on {host}:{port} \
                         (allow_insecure_no_mtls)"
                    );
                }
            }
        }
    }

    let server = SbiServer::new(config);
    server
        .start(n32_request_handler)
        .await
        .map_err(|e| format!("N32 listener start failed: {e}"))?;
    log::info!("N32 listener on {host}:{port} (mTLS={mtls_on})");
    Ok(server)
}

/// Top-level N32 request router
async fn n32_request_handler(request: HttpRequest) -> HttpResponse {
    let method = request.header.method.clone();
    let path = request.header.uri.clone();
    let body = request.http.content.clone().unwrap_or_default();
    // T1.5b: real RFC 5705 exporter secret threaded in by the server glue.
    let tls_secret = request.tls_exporter_secret.clone();
    // T6.4: correlation id from inbound request.
    let cid = request.correlation_id.clone();

    if !cid.is_empty() {
        log::debug!(
            "N32 request: cid={cid} {method} {path} ({}B)",
            body.len(),
            path = nextgcore_sbi::log_redact::redact_callback_tokens(&path)
        );
    } else {
        log::debug!(
            "N32 request: {method} {path} ({}B)",
            body.len(),
            path = nextgcore_sbi::log_redact::redact_callback_tokens(&path)
        );
    }

    match (method.as_str(), path.as_str()) {
        ("POST", "/n32c-handshake/v1/exchange-capability") => {
            handle_exchange_capability(&body, &cid, &request)
        }
        ("POST", "/n32c-handshake/v1/exchange-params") => {
            handle_exchange_params(&body, tls_secret.as_deref(), &cid, &request)
        }
        ("POST", "/n32c-handshake/v1/n32f-error") => handle_n32f_error_report(&body),
        // Issue #99: N32-f context termination (TS 29.573 5.2.4). Mandatory, and
        // previously absent -- a peer's terminate request fell through to the 404
        // below, so terminated contexts and their keys persisted indefinitely.
        ("POST", "/n32c-handshake/v1/n32f-terminate") => handle_n32f_terminate(&body, &request),
        ("POST", "/n32f-forward/v1/n32f-process") => handle_n32f_process(&body).await,
        _ => send_error(
            404,
            "Not Found",
            &format!("No N32 resource at {method} {path}"),
            Some("RESOURCE_NOT_FOUND"),
        ),
    }
}

// ============================================================================
// JSON <-> internal conversions
// ============================================================================

fn plmn_from_json(j: &PlmnIdJson) -> PlmnId {
    PlmnId::new(
        j.mcc.parse().unwrap_or(0),
        j.mnc.parse().unwrap_or(0),
        j.mnc.len() as u8,
    )
}

fn req_data_from_json(j: &SecurityCapabilityRequestJson) -> SecNegotiateReqData {
    SecNegotiateReqData {
        sender: j.sender.clone(),
        supported_sec_capability_list: j
            .supported_sec_capability_list
            .iter()
            .map(|s| SecurityCapability::from_string(s))
            .collect(),
        target_apiroot_supported: j.target_apiroot_supported,
        plmn_id_list: j.plmn_id_list.iter().map(plmn_from_json).collect(),
        target_plmn_id: j.target_plmn_id.as_ref().map(plmn_from_json),
        supported_features: j.supported_features.clone(),
    }
}

fn rsp_data_from_json(j: &SecurityCapabilityResponseJson) -> SecNegotiateRspData {
    SecNegotiateRspData {
        sender: j.sender.clone(),
        selected_sec_capability: SecurityCapability::from_string(&j.selected_sec_capability),
        target_apiroot_supported: j.target_apiroot_supported,
        plmn_id_list: j.plmn_id_list.iter().map(plmn_from_json).collect(),
        supported_features: j.supported_features.clone(),
    }
}

// ============================================================================
// Server-side handlers
// ============================================================================

/// Find an existing node by sender FQDN or create one.
/// Copies the node out; no context guard is held by the caller afterwards.
fn find_or_add_node(sender: &str) -> Option<SeppNode> {
    let ctx = sepp_self();
    let context = ctx.read().ok()?;
    if let Some(node) = context.node_find_by_receiver(sender) {
        return Some(node);
    }
    context.node_add(sender)
}

fn update_node(node: &SeppNode) {
    let ctx = sepp_self();
    if let Ok(context) = ctx.read() {
        context.node_update(node);
    };
}

/// #2076: refuse an N32-c request whose claimed peer, the FQDN of the SEPP it
/// says it is (a `sender`, or the peer an `n32fContextId` belongs to), is not
/// the SEPP on the other end of this connection. A SEPP is identified by the
/// FQDN its certificate names in a dNSName SubjectAltName (TS 33.310 §6.1.4a;
/// TS 29.573 §5.2: N32-c runs over mutually authenticated TLS between the two
/// SEPPs), so the claim must be one of the verified certificate's DNS SANs,
/// compared without case or a trailing dot. With no verified client certificate
/// (an N32-c listener with `allow_insecure_no_mtls`) nothing binds the claim:
/// refused under the `production` SBI profile, admitted under `dev` (lab).
/// 403 before anything is read or changed. `Some` is the refusal.
fn refuse_unbound_peer(
    request: &HttpRequest,
    claimed: &str,
    operation: &str,
) -> Option<HttpResponse> {
    let claimed = claimed.trim().trim_end_matches('.').to_ascii_lowercase();
    match peer_binding(request, &claimed) {
        PeerBinding::Bound => return None,
        PeerBinding::NoCertificate => {
            log::warn!("{operation} from [{claimed}] refused: no verified peer SEPP certificate");
            return Some(send_error(
                403,
                "Forbidden",
                &format!("{operation}: no verified peer SEPP certificate binds [{claimed}]"),
                None,
            ));
        }
        PeerBinding::OtherPeer => {}
    }
    log::warn!(
        "{operation} refused: it claims SEPP [{claimed}], but the peer certificate names {:?}",
        request.peer_cert_dns_sans
    );
    Some(send_error(
        403,
        "Forbidden",
        &format!("{operation}: the peer certificate does not name SEPP [{claimed}]"),
        None,
    ))
}

/// [`refuse_unbound_peer`]'s decision, without its log line or its refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerBinding {
    /// The connection's verified certificate names the claimed SEPP, or there
    /// is no certificate and the `dev` profile admits that.
    Bound,
    /// No verified peer certificate, under the `production` profile.
    NoCertificate,
    /// The verified certificate names another SEPP.
    OtherPeer,
}

/// Whether the SEPP on the other end of this connection is SEPP `claimed`
/// (#2076; see [`refuse_unbound_peer`] for the rule). Logs nothing and builds
/// nothing, so a caller that must answer a refusal exactly as another outcome
/// (#2112: a foreign `n32f-terminate` as an unknown context) can.
fn peer_binding(request: &HttpRequest, claimed: &str) -> PeerBinding {
    let claimed = claimed.trim().trim_end_matches('.').to_ascii_lowercase();
    if !request.peer_cert_present {
        return if nextgcore_sbi::security::SbiProfile::resolve().is_production() {
            PeerBinding::NoCertificate
        } else {
            PeerBinding::Bound
        };
    }
    if request.peer_cert_dns_sans.contains(&claimed) {
        PeerBinding::Bound
    } else {
        PeerBinding::OtherPeer
    }
}

fn handle_exchange_capability(body: &str, cid: &str, request: &HttpRequest) -> HttpResponse {
    let json: SecurityCapabilityRequestJson = match serde_json::from_str(body) {
        Ok(j) => j,
        Err(e) => {
            log::warn!("cid={cid} reason=MALFORMED_EXCHANGE_CAPABILITY: {e}");
            return send_error(
                400,
                "Bad Request",
                &format!("Malformed SecNegotiateReqData: {e}"),
                Some("MANDATORY_IE_INCORRECT"),
            );
        }
    };
    let req_data = req_data_from_json(&json);
    // #2076: the sender is the SEPP that called, before a node is found or made.
    if let Some(refused) = refuse_unbound_peer(request, &req_data.sender, "exchange-capability") {
        return refused;
    }

    let mut node = match find_or_add_node(&req_data.sender) {
        Some(n) => n,
        None => {
            return send_error(
                500,
                "Internal Server Error",
                "Cannot allocate SEPP node",
                Some("SYSTEM_FAILURE"),
            )
        }
    };

    match n32c_handler::handle_security_capability_request(&mut node, &req_data) {
        Ok(()) => {
            // TLS selected -> handshake complete; PRINS -> awaiting exchange-params
            node.handshake_state = match node.negotiated_security_scheme {
                SecurityCapability::Tls => crate::handshake_sm::HandshakeState::Established,
                _ => crate::handshake_sm::HandshakeState::WillEstablish,
            };
            update_node(&node);
            // Peer-initiated TLS handshake completes here; register its
            // forwarding client if we learned its apiRoot.
            if node.negotiated_security_scheme == SecurityCapability::Tls
                && node.peer_api_root.is_some()
            {
                register_n32f_client_for_node(&node, false);
            }

            match build_security_capability_response(&node) {
                Some(rsp) => {
                    let rsp_json = SecurityCapabilityResponseJson::from(&rsp);
                    HttpResponse::ok()
                        .with_json_body(&rsp_json)
                        .unwrap_or_else(|_| HttpResponse::internal_error())
                }
                None => send_error(
                    500,
                    "Internal Server Error",
                    "Cannot build SecNegotiateRspData",
                    Some("SYSTEM_FAILURE"),
                ),
            }
        }
        Err(e) => {
            // Capability mismatch => negotiation failure per TS 29.573
            log::warn!("cid={cid} reason=NEGOTIATION_NOT_ALLOWED: {e}");
            send_error(400, "Bad Request", &e, Some("NEGOTIATION_NOT_ALLOWED"))
        }
    }
}

/// Handle an exchange-params request (responder side, T1.5b).
///
/// `tls_secret` is the RFC 5705 exporter secret extracted by the server
/// glue from the N32-c TLS connection. When present (real TLS transport), we
/// deposit it into the n32c_handler store keyed by the sender FQDN so
/// `resolve_exporter_secret` picks it up instead of the no-TLS fallback.
/// Resolve which peer an `exchange-params` request came from.
///
/// `sender` is OPTIONAL in `SecParamExchReqData`, so it cannot be the only source
/// of the peer's identity. In order:
///
/// 1. `sender` when present — the normal case, and the only one that needs no
///    inference.
/// 2. The host of `senderApiRoot` when present. That member is this tree's own
///    extension carrying the requester's N32-c apiRoot, and its host IS the peer's
///    FQDN.
/// 3. The single SEPP node whose N32-c is negotiated but not yet established. This
///    is what the spec relies on implicitly: `exchange-params` arrives on the same
///    N32-c TLS connection as the capability negotiation, so the peer is known from
///    the connection — an identity this server does not currently plumb through to
///    the handler. Restricted to the *single*-candidate case on purpose: with two
///    peers mid-handshake, picking one would derive keys against the wrong exporter
///    secret and produce a silently unusable N32-f context.
///
/// `None` means the request is genuinely unattributable. That is not the
/// over-rejection this fix is about — a spec-valid body from a peer that sent
/// `senderApiRoot`, or in any deployment with one handshake in flight, is accepted.
fn resolve_exchange_params_peer(req: &SecParamExchReqData) -> Option<String> {
    if let Some(sender) = req.sender.as_deref().filter(|s| !s.trim().is_empty()) {
        return Some(sender.to_string());
    }
    if let Some(root) = req.sender_api_root.as_deref() {
        if let Ok((_tls, host, _port)) = parse_api_root(root) {
            if !host.is_empty() {
                log::debug!("exchange-params omitted sender; using senderApiRoot host [{host}]");
                return Some(host);
            }
        }
    }
    let nodes = sepp_self().read().ok()?.node_list();
    single_pending_peer(&nodes)
}

/// The one SEPP node with an N32-c handshake in flight, or `None` when there is not
/// exactly one.
///
/// Split out as a pure function over the node list rather than reading the global
/// context directly, so it can be tested without mutating the process-wide peer list
/// every other test in this module shares. Doing it the other way first made a
/// pre-existing TLS-mode test fail about one run in five, because the setup had to
/// clear that list.
fn single_pending_peer(nodes: &[crate::context::SeppNode]) -> Option<String> {
    let mut pending = nodes
        .iter()
        .filter(|n| n.handshake_state != crate::handshake_sm::HandshakeState::Established)
        .filter(|n| !n.receiver.is_empty());
    let first = pending.next()?;
    if pending.next().is_some() {
        // Two candidates: picking one would derive the N32-f key hierarchy against
        // the wrong peer's exporter secret and produce a context that establishes and
        // then cannot decrypt anything.
        return None;
    }
    log::debug!(
        "exchange-params omitted sender and senderApiRoot; attributing to the single \
         in-flight N32-c association [{}]",
        first.receiver
    );
    Some(first.receiver.clone())
}

fn handle_exchange_params(
    body: &str,
    tls_secret: Option<&[u8]>,
    cid: &str,
    request: &HttpRequest,
) -> HttpResponse {
    let req: SecParamExchReqData = match serde_json::from_str(body) {
        Ok(j) => j,
        Err(e) => {
            log::warn!("cid={cid} reason=MALFORMED_EXCHANGE_PARAMS: {e}");
            return send_error(
                400,
                "Bad Request",
                &format!("Malformed SecParamExchReqData: {e}"),
                Some("MANDATORY_IE_INCORRECT"),
            );
        }
    };

    let Some(peer) = resolve_exchange_params_peer(&req) else {
        log::warn!("cid={cid} reason=UNATTRIBUTABLE_EXCHANGE_PARAMS: no sender, no senderApiRoot");
        return send_error(
            400,
            "Bad Request",
            "sender omitted and the requesting peer could not be determined from the \
             association (no senderApiRoot, and not exactly one N32-c handshake in flight)",
            Some("MANDATORY_IE_INCORRECT"),
        );
    };

    // #2076: the peer is the SEPP that called, before its secret or node is touched.
    if let Some(refused) = refuse_unbound_peer(request, &peer, "exchange-params") {
        return refused;
    }

    let mut node = match find_or_add_node(&peer) {
        Some(n) => n,
        None => {
            return send_error(
                500,
                "Internal Server Error",
                "Cannot allocate SEPP node",
                Some("SYSTEM_FAILURE"),
            )
        }
    };

    // #2096 (R30 on #2092): only once the peer is bound and its node exists, so a
    // request that goes no further leaves no secret behind.
    // T1.5b: deposit the real TLS exporter secret before the handler calls
    // `resolve_exporter_secret`, replacing the deterministic fallback.
    if let Some(secret) = tls_secret {
        log::debug!("cid={cid} depositing N32-c TLS exporter secret for peer [{peer}] (T1.5b)");
        n32c_handler::set_n32c_tls_exporter_secret(&peer, secret.to_vec());
    }

    match n32c_handler::handle_exchange_params_request(&mut node, &req) {
        Ok(rsp) => {
            node.handshake_state = crate::handshake_sm::HandshakeState::Established;
            update_node(&node);
            // Peer-initiated PRINS handshake completes here; register the
            // forwarding client (apiRoot learned from exchange-params).
            register_n32f_client_for_node(&node, false);
            HttpResponse::ok()
                .with_json_body(&rsp)
                .unwrap_or_else(|_| HttpResponse::internal_error())
        }
        Err(e) => {
            // #2087: a failed exchange-params leaves no exporter secret behind.
            let _ = n32c_handler::take_n32c_tls_exporter_secret(&peer);
            log::warn!("cid={cid} peer=[{peer}] reason=NEGOTIATION_NOT_ALLOWED: {e}");
            send_error(400, "Bad Request", &e, Some("NEGOTIATION_NOT_ALLOWED"))
        }
    }
}

/// Received n32f-error reports (consumed: logged, counted, and inspectable).
/// #2087: the latest [`MAX_RECEIVED_N32F_ERRORS`] only, oldest dropped first.
/// Nothing in production drains it, so unbounded it grew at the peer's rate.
static RECEIVED_N32F_ERRORS: LazyLock<Mutex<std::collections::VecDeque<N32fErrorInfo>>> =
    LazyLock::new(|| Mutex::new(std::collections::VecDeque::new()));

/// #2087: how many received n32f-error reports are kept for inspection.
pub const MAX_RECEIVED_N32F_ERRORS: usize = 256;

/// Drain the received n32f-error reports (used by operators/tests)
pub fn take_received_n32f_errors() -> Vec<N32fErrorInfo> {
    RECEIVED_N32F_ERRORS
        .lock()
        .map(|mut v| std::mem::take(&mut *v).into())
        .unwrap_or_default()
}

fn handle_n32f_error_report(body: &str) -> HttpResponse {
    let info: N32fErrorInfo = match serde_json::from_str(body) {
        Ok(i) => i,
        Err(e) => {
            return send_error(
                400,
                "Bad Request",
                &format!("Malformed N32fErrorInfo: {e}"),
                Some("MANDATORY_IE_INCORRECT"),
            )
        }
    };

    log::error!(
        "Peer SEPP reported N32-f failure: msg_id={} type={:?} details={:?}",
        info.n32f_message_id,
        info.n32f_error_type,
        info.error_details_list
    );

    if let Ok(mut v) = RECEIVED_N32F_ERRORS.lock() {
        if v.len() >= MAX_RECEIVED_N32F_ERRORS {
            v.pop_front();
        }
        v.push_back(info);
    }
    HttpResponse::no_content()
}

/// Reconstructed request returned by /n32f-process (the receiving SEPP
/// would forward this to the target NF; we echo it for verification).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconstructedRequestJson {
    pub method: String,
    pub url: String,
    pub headers: std::collections::HashMap<String, String>,
    /// base64url-encoded body
    pub body: Option<String>,
    pub message_id: Option<String>,
}

async fn handle_n32f_process(body: &str) -> HttpResponse {
    let json: serde_json::Value = match serde_json::from_str(body) {
        Ok(j) => j,
        Err(e) => {
            return send_error(
                400,
                "Bad Request",
                &format!("Malformed N32-f message: {e}"),
                Some("MANDATORY_IE_INCORRECT"),
            )
        }
    };

    if json.get("reformattedData").is_some() {
        // PRINS-protected message
        let msg: N32fReformattedMessage = match serde_json::from_value(json) {
            Ok(m) => m,
            Err(e) => {
                return send_error(
                    400,
                    "Bad Request",
                    &format!("Malformed N32fReformattedMessage: {e}"),
                    Some("MANDATORY_IE_INCORRECT"),
                )
            }
        };
        handle_prins_message(&msg).await
    } else if json.get("requestLine").is_some() {
        // TLS-mode pass-through envelope
        match crate::n32c_build::parse_n32f_message(body.as_bytes()) {
            Ok(msg) => {
                // Identify the sending peer from the carried sender-SEPP
                // header and enforce: TLS negotiated + handshake established.
                let sender_sepp = msg
                    .header
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("3gpp-sbi-sender-sepp"))
                    .map(|h| h.value.clone());
                if let Some(resp) = enforce_tls_mode_peer(sender_sepp.as_deref()) {
                    return resp;
                }
                // Issue #99: FORWARD to the target NF. This used to build a
                // `ReconstructedRequestJson` and return it as a 200 body -- the
                // reconstructed request was reflected to the SENDING SEPP instead
                // of being delivered, so in TLS security mode no roaming service
                // request ever traversed the SEPP-to-NF hop and nothing was ever
                // fulfilled (TS 29.573 5.3.3.1, TS 29.500 6.1.4.3.4,
                // TS 33.501 5.9.3: the SEPP is a proxy here, not an endpoint).
                let rec = prins::ReconstructedRequest {
                    method: msg.request_line.method,
                    url: msg.request_line.url,
                    headers: msg
                        .header
                        .iter()
                        .map(|h| (h.name.clone(), h.value.clone()))
                        .collect(),
                    // The TLS envelope carries the payload as text; the
                    // forwarder wants bytes.
                    body: msg.payload.map(String::into_bytes),
                    // The TLS envelope carries no messageId; it is a PRINS
                    // correlation field. Empty rather than fabricated.
                    message_id: String::new(),
                };
                log::info!(
                    "N32-f TLS-mode message accepted, forwarding to target NF: {} {}",
                    rec.method,
                    rec.url
                );
                let (status, resp_headers, resp_body) = forward_to_target_nf(&rec).await;
                // Relay the NF's REAL response verbatim. Deliberately NOT via
                // `forward_and_protect_response`, which the PRINS branch uses:
                // that wraps the response in an N32fReformattedRspMsg and
                // JOSE-protects it, which a peer that negotiated TLS cannot
                // deserialise. In TLS mode the transport IS the protection
                // (TS 33.501 5.9.3), so the two modes share the forwarding step
                // and diverge on the response step.
                let mut out = HttpResponse::with_status(status);
                for (k, v) in resp_headers {
                    out.http.set_header(k, v);
                }
                if let Some(body) = resp_body {
                    if let Ok(text) = String::from_utf8(body) {
                        out.http.set_content(text);
                    }
                }
                out
            }
            Err(e) => send_error(400, "Bad Request", &e, Some("MANDATORY_IE_INCORRECT")),
        }
    } else {
        send_error(
            400,
            "Bad Request",
            "Neither PRINS nor TLS N32-f message shape",
            Some("MANDATORY_IE_INCORRECT"),
        )
    }
}

/// `POST /n32c-handshake/v1/n32f-terminate` — N32-f context termination
/// (TS 29.573 §5.2.4, response body `N32fContextInfo` per §6.1.5.2).
///
/// Deletes the addressed N32-f context **and its keys**: the key hierarchy lives
/// inside `SeppNode::n32f_security`, so clearing that `Option` is the deletion.
/// `handshake_state` is reset too, so a later N32-f message cannot ride a context
/// whose keys are gone.
///
/// Deliberately NOT `node_remove`. TS 29.573 §5.2.4 terminates an
/// `n32fContextId`, not the peer: the peer's N32-c API root and negotiated
/// capabilities are provisioning state that must survive an N32-f teardown, or a
/// re-handshake could not find its own peer configuration. Terminating a context
/// is routine; de-provisioning a peer is not.
///
/// An unknown `n32fContextId` is 404 rather than a silent success — the peer
/// asked us to destroy keys, and letting it believe we did when we never held
/// them is exactly the wrong answer for a border function.
fn handle_n32f_terminate(body: &str, request: &HttpRequest) -> HttpResponse {
    let json: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return send_error(
                400,
                "Bad Request",
                &format!("Malformed N32fContextInfo: {e}"),
                Some("MANDATORY_IE_INCORRECT"),
            )
        }
    };
    let Some(context_id) = json
        .get("n32fContextId")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    else {
        return send_error(
            400,
            "Bad Request",
            "n32fContextId is mandatory",
            Some("MANDATORY_IE_MISSING"),
        );
    };

    let ctx = sepp_self();
    let found = {
        // Guard scoped so it drops before node_update takes the write lock.
        let context = match ctx.read() {
            Ok(c) => c,
            Err(_) => {
                return send_error(
                    500,
                    "Internal Server Error",
                    "SEPP context lock poisoned",
                    None,
                )
            }
        };
        context.node_find_by_n32f_context_id(context_id)
    };
    // #2076: only the SEPP whose context it is tears it down, before its keys go.
    // #2096 (R30 on #2092): and another peer's context is answered exactly as an
    // unknown one, so the answer does not tell a peer which context ids exist.
    // #2112: through the same code, too. The binding check is the quiet
    // `peer_binding`: no refusal is built and nothing is logged at WARN, so the
    // two cases take the same path and leave the same log line, and a peer
    // cannot fill the log by asking about other peers' contexts.
    let Some(mut node) =
        found.filter(|node| peer_binding(request, &node.receiver) == PeerBinding::Bound)
    else {
        log::debug!(
            "n32f-terminate of {context_id} answered 404: the calling SEPP has no N32-f \
             context with that id"
        );
        return send_error(
            404,
            "Not Found",
            &format!("Unknown n32fContextId {context_id}"),
            Some("CONTEXT_NOT_FOUND"),
        );
    };

    // The keys are in here. Dropping it is the key deletion; #2087: and its SEQ
    // counters and replay windows go with it.
    if let Some(old) = node.n32f_security.take() {
        crate::prins::forget_context(&old.kid);
    }
    node.handshake_state = crate::handshake_sm::HandshakeState::Initial;
    let updated = match ctx.read() {
        Ok(context) => context.node_update(&node),
        Err(_) => false,
    };
    if !updated {
        return send_error(
            500,
            "Internal Server Error",
            "failed to update SEPP node while terminating the N32-f context",
            None,
        );
    }
    log::info!("N32-f context {context_id} terminated: context and keys deleted");

    HttpResponse::ok()
        .with_json_body(&serde_json::json!({ "n32fContextId": context_id }))
        .unwrap_or_else(|_| HttpResponse::internal_error())
}

/// Enforce that a TLS-mode N32-f message comes from a known peer SEPP whose
/// N32-c handshake is Established and whose negotiated scheme is TLS. With a
/// real N32 listener mTLS verifies the transport; this additionally binds
/// the message to a completed N32-c negotiation (TS 29.573 sec 5.3).
/// Returns `Some(error_response)` to reject, `None` to accept.
fn enforce_tls_mode_peer(sender_sepp: Option<&str>) -> Option<HttpResponse> {
    let Some(sender) = sender_sepp else {
        log::error!("[DROP] TLS-mode N32-f message without 3gpp-sbi-sender-sepp header");
        return Some(send_error(
            400,
            "Bad Request",
            "Missing sender SEPP identity",
            Some("MANDATORY_IE_INCORRECT"),
        ));
    };
    let node = {
        let ctx = sepp_self();
        ctx.read()
            .ok()
            .and_then(|c| c.node_find_by_receiver(sender))
    };
    let Some(node) = node else {
        log::error!("[DROP] TLS-mode N32-f message from unknown peer SEPP [{sender}]");
        return Some(send_error(
            403,
            "Forbidden",
            "Unknown sender SEPP (no N32-c handshake)",
            Some("NEGOTIATION_NOT_ALLOWED"),
        ));
    };
    if node.handshake_state != crate::handshake_sm::HandshakeState::Established {
        log::error!(
            "[DROP] TLS-mode N32-f message from peer [{sender}] with unestablished handshake ({:?})",
            node.handshake_state
        );
        return Some(send_error(
            403,
            "Forbidden",
            "N32-c handshake not established for this peer",
            Some("NEGOTIATION_NOT_ALLOWED"),
        ));
    }
    if node.negotiated_security_scheme != SecurityCapability::Tls {
        log::error!(
            "[DROP] TLS-shaped N32-f message from peer [{sender}] but negotiated scheme is {:?}",
            node.negotiated_security_scheme
        );
        return Some(send_error(
            403,
            "Forbidden",
            "Negotiated N32-f scheme is not TLS",
            Some("NEGOTIATION_NOT_ALLOWED"),
        ));
    }
    None
}

/// Extract the n32fContextId from the (not yet authenticated) JWE AAD so
/// the security context can be located. Authenticity is established later
/// by AEAD decryption.
fn peek_context_id(msg: &N32fReformattedMessage) -> Option<String> {
    let aad = msg.reformatted_data.aad.as_ref()?;
    let bytes = crate::jose::b64url_decode(aad).ok()?;
    let block: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    block
        .get("metaData")?
        .get("n32fContextId")?
        .as_str()
        .map(|s| s.to_string())
}

async fn handle_prins_message(msg: &N32fReformattedMessage) -> HttpResponse {
    // Locate the node by the context ID we allocated
    let context_id = peek_context_id(msg);
    let node = context_id.as_ref().and_then(|id| {
        let ctx = sepp_self();
        let context = ctx.read().ok()?;
        context.node_find_by_n32f_context_id(id)
    });

    let Some(node) = node else {
        log::error!("N32-f PRINS message for unknown context [{:?}]", context_id);
        return send_error(
            400,
            "Bad Request",
            "Unknown n32fContextId",
            Some("UNAVAILABLE_PRINS_CONTEXT"),
        );
    };

    // Enforce: the N32-c handshake with this peer must be Established and
    // PRINS must be the negotiated scheme (TS 29.573 / TS 33.501). Reject a
    // PRINS-shaped N32-f message on a peer that did not negotiate PRINS or
    // whose handshake never completed.
    if node.handshake_state != crate::handshake_sm::HandshakeState::Established {
        log::error!(
            "[DROP] N32-f PRINS message from peer [{}] with unestablished handshake ({:?})",
            node.receiver,
            node.handshake_state
        );
        return send_error(
            403,
            "Forbidden",
            "N32-c handshake not established for this peer",
            Some("UNAVAILABLE_PRINS_CONTEXT"),
        );
    }
    if node.negotiated_security_scheme != SecurityCapability::Prins {
        log::error!(
            "[DROP] PRINS-shaped N32-f message from peer [{}] but negotiated scheme is {:?}",
            node.receiver,
            node.negotiated_security_scheme
        );
        return send_error(
            403,
            "Forbidden",
            "Negotiated N32-f scheme is not PRINS",
            Some("UNAVAILABLE_PRINS_CONTEXT"),
        );
    }

    let Some(prins_ctx) = crate::sbi_path::build_prins_context(node.id) else {
        return send_error(
            400,
            "Bad Request",
            "No N32-f security context",
            Some("UNAVAILABLE_PRINS_CONTEXT"),
        );
    };

    match prins::unprotect_message(&prins_ctx, msg) {
        Ok(rec) => {
            log::info!("N32-f PRINS request verified: {} {}", rec.method, rec.url);
            // TS 29.573 §6.2.4.2: forward the reconstructed request to the
            // target NF, then reformat + PRINS-protect the NF's response as an
            // N32fReformattedRspMsg and return it over N32-f.
            forward_and_protect_response(&prins_ctx, rec).await
        }
        Err(e) => {
            log::error!("N32-f PRINS verification failed: {e}");

            // Produce the n32f-error report towards the sending SEPP
            // Issue #99: name the context the failure relates to, so a peer
            // holding several can tell which one broke.
            let info = e.to_error_info(
                node.n32f_security
                    .as_ref()
                    .map(|sec| sec.local_context_id.as_str()),
            );
            if let Some(api_root) = node.peer_api_root.clone() {
                let report = info.clone();
                tokio::spawn(async move {
                    if let Err(err) = send_n32f_error(&api_root, &report).await {
                        log::warn!("n32f-error report to {api_root} failed: {err}");
                    }
                });
            } else {
                log::warn!(
                    "No peer apiRoot for node [{}]; n32f-error not deliverable",
                    node.receiver
                );
            }

            let cause = match e.error_type {
                N32fErrorType::IntegrityCheckFailed => "INTEGRITY_CHECK_FAILED",
                N32fErrorType::IntegrityCheckOnModificationsFailed => {
                    "INTEGRITY_CHECK_ON_MODIFICATIONS_FAILED"
                }
                N32fErrorType::ModificationsInstructionsFailed => {
                    "MODIFICATIONS_INSTRUCTIONS_FAILED"
                }
                N32fErrorType::DecipheringFailed => "DECIPHERING_FAILED",
                N32fErrorType::MessageReconstructionFailed => "MESSAGE_RECONSTRUCTION_FAILED",
                N32fErrorType::UnavailablePrinsContext => "UNAVAILABLE_PRINS_CONTEXT",
                N32fErrorType::PolicyMismatch => "POLICY_MISMATCH",
            };
            send_error(400, "Bad Request", &e.detail, Some(cause))
        }
    }
}

/// The receiving SEPP forwards the reconstructed SBI request to the target NF,
/// then reformats and PRINS-protects the NF's HTTP response as an
/// N32fReformattedRspMsg to return over N32-f (TS 29.573 §6.2.4.2). An
/// unresolvable/unreachable target yields a protected gateway-error response.
async fn forward_and_protect_response(
    prins_ctx: &prins::PrinsContext,
    rec: prins::ReconstructedRequest,
) -> HttpResponse {
    let (status, resp_headers, resp_body) = forward_to_target_nf(&rec).await;
    match prins::protect_response_message(prins_ctx, status, &resp_headers, resp_body.as_deref()) {
        Ok(reformatted) => HttpResponse::ok()
            .with_json_body(&reformatted)
            .unwrap_or_else(|_| HttpResponse::internal_error()),
        Err(e) => {
            log::error!("N32-f: failed to protect target-NF response: {e}");
            HttpResponse::internal_error()
        }
    }
}

// ============================================================================
// N32-f target policy (#1870)
// ============================================================================

/// Where the receiving SEPP may forward a reconstructed N32-f request, and how
/// (#1870, TS 33.501 §13.1.0 / §13.2, TS 29.573 §6.2).
///
/// The target apiRoot arrives from the PEER SEPP (in `3gpp-Sbi-Target-apiRoot`
/// or the request URL), so without a policy the SEPP dials whatever a foreign
/// network names: a server-side request forgery into the home PLMN, and a
/// cleartext copy of every header, the consumer's access token included.
///
/// Under [`SbiProfile::Production`] the target must be `https` and inside this
/// PLMN: a host under one of `home_domains` (the TS 23.003 §28.2 home network
/// domains of the serving PLMNs, `5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org`) or an
/// operator entry in `allowed_targets`. It is dialled with the profile CA and
/// this SEPP's SBI client certificate ([`TlsPaths`]), as every NF dials a peer.
/// Under [`SbiProfile::Dev`] any `http`/`https` target is dialled, as before.
#[derive(Debug, Clone)]
pub struct N32fForwardPolicy {
    /// The SBI security profile the forwarding follows.
    pub profile: SbiProfile,
    /// Home network domains a target host may sit under (lowercase, no dots at
    /// the ends). See [`home_network_domain`].
    pub home_domains: Vec<String>,
    /// Operator-declared targets inside this PLMN: `host`, `host:port`
    /// (`[v6]:port` for IPv6), or `.suffix` for every host under a domain.
    pub allowed_targets: Vec<String>,
    /// The TLS material for the SEPP-to-NF hop under production.
    pub tls: TlsPaths,
    /// The SBI ports a home-domain host, a bare-host entry or a `.suffix` entry
    /// is admitted on (#1870 review: not every port of a home host). A
    /// `host:port` entry names its own port. Default `[443]`, the https default
    /// port an apiRoot without a port uses (TS 29.501 §4.4.1).
    pub allowed_ports: Vec<u16>,
}

/// Default [`N32fForwardPolicy::allowed_ports`].
pub const DEFAULT_N32F_TARGET_PORTS: &[u16] = &[443];

impl N32fForwardPolicy {
    /// The policy for `profile` with this process's TLS paths and no targets
    /// beyond `home_domains`.
    pub fn new(
        profile: SbiProfile,
        home_domains: Vec<String>,
        allowed_targets: Vec<String>,
    ) -> Self {
        Self {
            profile,
            home_domains: home_domains
                .into_iter()
                .map(|d| d.trim_matches('.').to_ascii_lowercase())
                .filter(|d| !d.is_empty())
                .collect(),
            allowed_targets: allowed_targets
                .into_iter()
                .map(|t| t.trim().to_ascii_lowercase())
                .filter(|t| !t.is_empty())
                .collect(),
            tls: TlsPaths::from_env(),
            allowed_ports: DEFAULT_N32F_TARGET_PORTS.to_vec(),
        }
    }

    /// The same policy admitting home and bare/suffix targets on `ports`
    /// instead of [`DEFAULT_N32F_TARGET_PORTS`]. An empty list keeps the default.
    pub fn with_allowed_ports(mut self, ports: Vec<u16>) -> Self {
        if !ports.is_empty() {
            self.allowed_ports = ports;
        }
        self
    }

    /// Under production, the TLS files the SEPP-to-NF hop needs must exist at
    /// startup (#1870 review), named when one does not, rather than failing on
    /// the first forward. Dev needs none.
    pub fn check_files(&self) -> Result<(), String> {
        if !self.profile.is_production() {
            return Ok(());
        }
        check_tls_files(
            "N32-f forwarding",
            &[
                ("CA (NEXTGCORE_SBI_TLS_CA)", Some(&self.tls.ca_cert)),
                (
                    "client certificate (NEXTGCORE_SBI_TLS_CLIENT_CERT)",
                    self.tls.client_cert.as_ref(),
                ),
                (
                    "client key (NEXTGCORE_SBI_TLS_CLIENT_KEY)",
                    self.tls.client_key.as_ref(),
                ),
            ],
        )
    }

    /// Whether `host:port` is a target this PLMN owns. Production only; dev
    /// admits every target.
    fn admits(&self, host: &str, port: u16) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let under = |domain: &str| host == domain || host.ends_with(&format!(".{domain}"));
        // #1870 review: only the SBI port(s), not every port of a home host.
        let sbi_port = self.allowed_ports.contains(&port);
        if sbi_port && self.home_domains.iter().any(|d| under(d)) {
            return true;
        }
        self.allowed_targets.iter().any(|entry| {
            if let Some(suffix) = entry.strip_prefix('.') {
                return sbi_port && under(suffix.trim_end_matches('.'));
            }
            match entry.rsplit_once(':') {
                // `host:port` or `[v6]:port`; a bare IPv6 literal's last group
                // does not parse as a port unless it is bracketed.
                Some((h, p)) if (!h.contains(':') || h.ends_with(']')) => match p.parse::<u16>() {
                    Ok(p) => h == host && p == port,
                    Err(_) => sbi_port && *entry == host,
                },
                _ => sbi_port && *entry == host,
            }
        })
    }

    /// Check a peer-supplied target apiRoot and build the client for it, or say
    /// why it is refused.
    fn client_for(&self, api_root: &str) -> Result<nextgcore_sbi::client::SbiClient, String> {
        if !self.profile.is_production() {
            // Dev: the target's own scheme and no TLS material, as before. Not
            // the peer-SEPP material `n32_client` falls back to: that is N32's.
            return n32_client_with(api_root, None);
        }
        let (https, host, port) = parse_api_root(api_root)?;
        self.check_target(https, &host, port)
            .map_err(|e| format!("target apiRoot {api_root} {e}"))?;
        let mut config = nextgcore_sbi::client::SbiClientConfig::new(&host, port)
            .with_connect_timeout(N32_CONNECT_TIMEOUT)
            .with_request_timeout(N32_REQUEST_TIMEOUT)
            .with_https();
        config.ca_cert = Some(self.tls.ca_cert.clone());
        config.client_cert = self.tls.client_cert.clone();
        config.client_key = self.tls.client_key.clone();
        // #1915 / R26 MAJOR on #1901: a 307/308 (or an OCI alternate) from an
        // admitted target is re-checked against this same policy before it is
        // dialled, so an admitted host cannot bounce the roaming request (SUPI,
        // bearer) out of the PLMN or onto cleartext.
        let policy = self.clone();
        Ok(
            nextgcore_sbi::client::SbiClient::new(config).with_target_policy(std::sync::Arc::new(
                move |t: &nextgcore_sbi::client::SbiTarget| {
                    // The client hands an IPv6 host unbracketed; admission and the
                    // allowlist use the bracketed authority form.
                    let host = if t.host.parse::<std::net::Ipv6Addr>().is_ok() {
                        format!("[{}]", t.host)
                    } else {
                        t.host.clone()
                    };
                    policy.check_target(
                        t.scheme == nextgcore_sbi::types::UriScheme::Https,
                        &host,
                        t.port,
                    )
                },
            )),
        )
    }

    /// The production admission rule for one target (#1870), shared by the
    /// first dial and every redirect or alternate (#1915): `https`, a DNS name or
    /// an IP literal, and inside this PLMN on an allowed port.
    fn check_target(&self, https: bool, host: &str, port: u16) -> Result<(), String> {
        if !https {
            return Err(
                "is not https; under the production SBI profile the SEPP forwards \
                        over TLS only (TS 33.501 §13.1.0)"
                    .to_string(),
            );
        }
        // Only a DNS name or an IP literal: userinfo, a fragment or any other
        // character is a way to make the authority mean something other than
        // the name the allowlist matched.
        let literal = host.starts_with('[') && host.ends_with(']');
        let legal = |c: char| c.is_ascii_alphanumeric() || c == '.' || c == '-';
        let well_formed = if literal {
            host[1..host.len() - 1]
                .parse::<std::net::Ipv6Addr>()
                .is_ok()
        } else {
            !host.is_empty() && host.chars().all(legal)
        };
        if !well_formed {
            return Err("has a malformed host".to_string());
        }
        if !self.admits(host, port) {
            return Err(format!(
                "is not inside this PLMN (home domains {:?}, allowed targets {:?}, ports {:?}); \
                 refusing to forward a peer-supplied target",
                self.home_domains, self.allowed_targets, self.allowed_ports
            ));
        }
        Ok(())
    }
}

/// Each `(label, path)` must be configured and an existing file (#1870 review).
fn check_tls_files(what: &str, files: &[(&str, Option<&String>)]) -> Result<(), String> {
    for (label, path) in files {
        match path {
            Some(p) if std::path::Path::new(p.as_str()).is_file() => {}
            Some(p) => {
                return Err(format!(
                    "the SBI profile is production and the {what} {label} {p} does not exist"
                ))
            }
            None => {
                return Err(format!(
                    "the SBI profile is production and no {what} {label} is configured"
                ))
            }
        }
    }
    Ok(())
}

/// The TS 23.003 §28.2 home network domain of `plmn`:
/// `5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org`, a two-digit MNC padded to three.
pub fn home_network_domain(plmn: &PlmnId) -> String {
    format!("5gc.mnc{:03}.mcc{:03}.3gppnetwork.org", plmn.mnc, plmn.mcc)
}

static N32F_FORWARD_POLICY: std::sync::RwLock<Option<N32fForwardPolicy>> =
    std::sync::RwLock::new(None);

/// Install the N32-f target policy (called once from `main`).
pub fn set_n32f_forward_policy(policy: N32fForwardPolicy) {
    *N32F_FORWARD_POLICY
        .write()
        .unwrap_or_else(|e| e.into_inner()) = Some(policy);
}

/// The installed policy, or the resolved profile's with the serving PLMNs'
/// home domains when none was installed. Never "anything goes" by default.
fn n32f_forward_policy() -> N32fForwardPolicy {
    if let Some(p) = N32F_FORWARD_POLICY
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
    {
        return p;
    }
    let home_domains = sepp_self()
        .read()
        .map(|c| c.serving_plmn_ids.iter().map(home_network_domain).collect())
        .unwrap_or_default();
    N32fForwardPolicy::new(SbiProfile::resolve(), home_domains, Vec::new())
}

/// Request headers the receiving SEPP does not copy onto the SEPP-to-NF hop
/// (#1870): RFC 9110 §7.6.1 hop-by-hop fields, the length the client recomputes,
/// the N32 hop's own proxy credentials, and the SEPP routing header.
///
/// `Authorization` is deliberately NOT here. In roaming the consumer's access
/// token is minted by the home NRF for the home producer and carried through
/// both SEPPs to it (TS 33.501 §13.4.1.2), protected on N32-f (§13.2.4.4).
/// Stripping it would make the producer refuse every roaming request 401.
fn is_n32f_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
            | "3gpp-sbi-target-apiroot"
    ) || name.starts_with(':')
}

/// The headers of `rec` to copy to the target NF: [`is_n32f_hop_header`] is
/// dropped, and so is every field the request's own `Connection` names
/// (RFC 9110 §7.6.1).
fn forwardable_n32f_headers(
    headers: &std::collections::HashMap<String, String>,
) -> Vec<(String, String)> {
    let named: Vec<String> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(',').map(|t| t.trim().to_ascii_lowercase()))
        .filter(|t| !t.is_empty())
        .collect();
    headers
        .iter()
        .filter(|(k, _)| !is_n32f_hop_header(k) && !named.contains(&k.to_ascii_lowercase()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Resolve and reach the target NF for a reconstructed N32-f request, returning
/// (status, headers, body). Resolution prefers the `3gpp-Sbi-Target-apiRoot`
/// header, then the absolute URL authority. Unresolvable/unreachable targets
/// map to a synthesized problem+json response.
async fn forward_to_target_nf(
    rec: &prins::ReconstructedRequest,
) -> (u16, Vec<(String, String)>, Option<Vec<u8>>) {
    forward_to_target_nf_under(rec, &n32f_forward_policy()).await
}

/// [`forward_to_target_nf`] under an explicit policy (#1870), so a test can
/// drive the production path without a process-global.
async fn forward_to_target_nf_under(
    rec: &prins::ReconstructedRequest,
    policy: &N32fForwardPolicy,
) -> (u16, Vec<(String, String)>, Option<Vec<u8>>) {
    let api_root = rec
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("3gpp-Sbi-Target-apiRoot"))
        .map(|(_, v)| v.clone())
        .or_else(|| authority_from_url(&rec.url));

    let Some(api_root) = api_root else {
        return problem_response(400, "target NF apiRoot could not be resolved");
    };
    // #1870: a peer-supplied target is checked before anything is dialled.
    let client = match policy.client_for(&api_root) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("N32-f: refusing target NF [{api_root}]: {e}");
            return problem_response(400, &format!("bad target apiRoot: {e}"));
        }
    };

    let path = path_and_query_from_url(&rec.url);
    let mut request = match rec.method.to_ascii_uppercase().as_str() {
        "GET" => HttpRequest::get(&path),
        "POST" => HttpRequest::post(&path),
        "PUT" => HttpRequest::put(&path),
        "PATCH" => HttpRequest::patch(&path),
        "DELETE" => HttpRequest::delete(&path),
        other => return problem_response(405, &format!("unsupported method {other}")),
    };
    // #1870: hop-by-hop fields and the SEPP routing header stay on this hop.
    for (k, v) in forwardable_n32f_headers(&rec.headers) {
        request.http.set_header(k, v);
    }
    if let Some(body) = &rec.body {
        if let Ok(s) = String::from_utf8(body.clone()) {
            request.http.set_content(s);
        }
    }

    match client.send_request(request).await {
        Ok(resp) => {
            let headers: Vec<(String, String)> = resp
                .http
                .headers
                .iter()
                // Drop hop-by-hop / length headers the sending side regenerates.
                .filter(|(k, _)| {
                    !matches!(
                        k.to_ascii_lowercase().as_str(),
                        "content-length" | "transfer-encoding" | "connection"
                    )
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let body = resp.http.content.map(|c| c.into_bytes());
            (resp.status, headers, body)
        }
        Err(e) => {
            log::warn!("N32-f: forward to target NF [{api_root}] failed: {e}");
            problem_response(504, &format!("target NF unreachable: {e}"))
        }
    }
}

fn problem_response(status: u16, detail: &str) -> (u16, Vec<(String, String)>, Option<Vec<u8>>) {
    let body = serde_json::json!({ "status": status, "detail": detail });
    (
        status,
        vec![(
            "content-type".to_string(),
            "application/problem+json".to_string(),
        )],
        serde_json::to_vec(&body).ok(),
    )
}

/// Extract the `scheme://authority` prefix from an absolute URL, or `None` for
/// a relative path.
fn authority_from_url(url: &str) -> Option<String> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else {
        return None;
    };
    let authority = rest.split('/').next().unwrap_or("");
    (!authority.is_empty()).then(|| format!("{scheme}://{authority}"))
}

/// Extract the path (with query) from an absolute URL, or return a relative
/// path unchanged.
fn path_and_query_from_url(url: &str) -> String {
    match url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    {
        Some(rest) => match rest.find('/') {
            Some(idx) => rest[idx..].to_string(),
            None => "/".to_string(),
        },
        None => url.to_string(),
    }
}

// ============================================================================
// Client side (initiator)
// ============================================================================

/// Parse "http(s)://host:port" into (https, host, port)
fn parse_api_root(api_root: &str) -> Result<(bool, String, u16), String> {
    let (https, rest) = if let Some(r) = api_root.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = api_root.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("Unsupported apiRoot scheme: {api_root}"));
    };
    let rest = rest.trim_end_matches('/');
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|e| format!("bad port: {e}"))?,
        ),
        None => (rest.to_string(), if https { 443 } else { 80 }),
    };
    Ok((https, host, port))
}

static N32_CLIENT_TLS: std::sync::RwLock<Option<N32TlsConfig>> = std::sync::RwLock::new(None);

/// Install the TLS material this SEPP presents when it dials a PEER SEPP
/// (called once from `main` when `--tls` is set). A call site that has no
/// config of its own, the n32f-error report and the SBI-side forward among
/// them, then still presents the SEPP's client certificate on an `https` peer
/// instead of dialling without one (#1870).
pub fn set_n32_client_tls(tls: Option<N32TlsConfig>) {
    *N32_CLIENT_TLS.write().unwrap_or_else(|e| e.into_inner()) = tls;
}

/// A client for the PEER SEPP at `api_root`, with `tls` or, when the caller has
/// none, the installed [`set_n32_client_tls`] material.
fn n32_client(
    api_root: &str,
    tls: Option<&N32TlsConfig>,
) -> Result<nextgcore_sbi::client::SbiClient, String> {
    let installed;
    let tls = match tls {
        Some(t) => Some(t),
        None => {
            installed = N32_CLIENT_TLS
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            installed.as_ref()
        }
    };
    n32_client_with(api_root, tls)
}

/// A client for `api_root` presenting exactly `tls` (none when `None`).
fn n32_client_with(
    api_root: &str,
    tls: Option<&N32TlsConfig>,
) -> Result<nextgcore_sbi::client::SbiClient, String> {
    let (https, host, port) = parse_api_root(api_root)?;
    let mut config = nextgcore_sbi::client::SbiClientConfig::new(&host, port)
        .with_connect_timeout(N32_CONNECT_TIMEOUT)
        .with_request_timeout(N32_REQUEST_TIMEOUT);
    if https {
        config = config.with_https();
        if let Some(tls_cfg) = tls {
            // mTLS: present our client certificate to the peer SEPP
            config.client_cert = tls_cfg.client_cert.clone();
            config.client_key = tls_cfg.client_key.clone();
            config.ca_cert = tls_cfg.ca_cert.clone();
        }
    }
    Ok(nextgcore_sbi::client::SbiClient::new(config))
}

async fn post_json(
    client: &nextgcore_sbi::client::SbiClient,
    path: &str,
    body: String,
) -> Result<(u16, String), String> {
    let mut request = HttpRequest::post(path);
    request.http.set_content(body);
    request.http.set_header("Content-Type", "application/json");
    let response = client
        .send_request(request)
        .await
        .map_err(|e| format!("N32 request to {path} failed: {e}"))?;
    Ok((response.status, response.http.content.unwrap_or_default()))
}

/// Outcome of a completed N32-c handshake
#[derive(Debug, Clone)]
pub struct HandshakeOutcome {
    pub node_id: u64,
    pub security: SecurityCapability,
}

/// Register the consumer-facing N32-f forwarding client for a node whose
/// N32-c handshake just completed, so the SBI server can forward outbound
/// VPLMN requests to this peer SEPP. Idempotent.
fn register_n32f_client_for_node(node: &SeppNode, tls_enabled: bool) {
    let Some(api_root) = node.peer_api_root.as_deref() else {
        log::warn!(
            "[{}] handshake complete but no peer apiRoot; N32-f client not registered",
            node.receiver
        );
        return;
    };
    match parse_api_root(api_root) {
        Ok((https, host, port)) => {
            crate::sbi_path::register_n32f_client(
                node.id,
                &node.receiver,
                &host,
                port,
                https || tls_enabled,
                node.negotiated_security_scheme,
            );
        }
        Err(e) => log::warn!(
            "[{}] cannot register N32-f client (bad apiRoot [{api_root}]): {e}",
            node.receiver
        ),
    }
}

/// Drive the full N32-c handshake against a peer SEPP:
/// exchange-capability, then (when PRINS is selected) exchange-params with
/// N32-f context-ID exchange and session-key derivation.
pub async fn initiate_n32c_handshake(
    peer_fqdn: &str,
    peer_api_root: &str,
    local_api_root: Option<&str>,
    tls: Option<&N32TlsConfig>,
) -> Result<HandshakeOutcome, String> {
    let mut node =
        find_or_add_node(peer_fqdn).ok_or_else(|| "Cannot allocate SEPP node".to_string())?;
    node.peer_api_root = Some(peer_api_root.to_string());

    // --- Phase 1: exchange-capability ---
    let req_data = build_security_capability_request(&mut node, false)
        .ok_or("Cannot build SecNegotiateReqData (sender configured?)")?;
    let req_json = serde_json::to_string(&SecurityCapabilityRequestJson::from(&req_data))
        .map_err(|e| e.to_string())?;

    let client = n32_client(peer_api_root, tls)?;
    let (status, body) =
        post_json(&client, "/n32c-handshake/v1/exchange-capability", req_json).await?;
    if status != 200 {
        update_node(&node);
        return Err(format!(
            "exchange-capability rejected by peer: HTTP {status} ({body})"
        ));
    }

    let rsp_json: SecurityCapabilityResponseJson =
        serde_json::from_str(&body).map_err(|e| format!("bad SecNegotiateRspData: {e}"))?;
    let rsp_data = rsp_data_from_json(&rsp_json);
    n32c_handler::handle_security_capability_response(&mut node, &rsp_data)?;

    match node.negotiated_security_scheme {
        SecurityCapability::Tls => {
            node.handshake_state = crate::handshake_sm::HandshakeState::Established;
            update_node(&node);
            register_n32f_client_for_node(&node, tls.is_some());
            log::info!("[{peer_fqdn}] N32-c handshake complete: TLS");
            Ok(HandshakeOutcome {
                node_id: node.id,
                security: SecurityCapability::Tls,
            })
        }
        SecurityCapability::Prins => {
            // --- Phase 2: exchange-params (key establishment) ---
            let local_sender = {
                let ctx = sepp_self();
                let context = ctx.read().map_err(|_| "context poisoned".to_string())?;
                context.sender.clone().ok_or("sender not configured")?
            };
            // Advertise our ES256 modifications-signing raw public key inside
            // ipxProviderSecInfoList so the peer can verify our modificationsBlock
            // entries (TS 29.573 §6.1.5.2.15, TS 33.501 §13.2.4.6).
            let local_ipx = n32c_handler::local_ipx_provider_sec_info(&local_sender);
            let params_req = SecParamExchReqData {
                sender: Some(local_sender),
                n32f_context_id: prins::generate_n32f_context_id(),
                jwe_cipher_suite_list: n32c_handler::SUPPORTED_JWE_SUITES
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                jws_cipher_suite_list: n32c_handler::SUPPORTED_JWS_SUITES
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                // Advertise our protection policy so the responder can negotiate
                // the dataTypeEncPolicy (TS 29.573 §6.1.5.2.4).
                protection_policy_info: Some(n32c_handler::local_protection_policy()),
                sec_profiles: None,
                ipx_provider_sec_info_list: local_ipx,
                sender_api_root: local_api_root.map(|s| s.to_string()),
            };
            let params_body = serde_json::to_string(&params_req).map_err(|e| e.to_string())?;
            let (status, body) =
                post_json(&client, "/n32c-handshake/v1/exchange-params", params_body).await?;
            if status != 200 {
                update_node(&node);
                return Err(format!(
                    "exchange-params rejected by peer: HTTP {status} ({body})"
                ));
            }
            let params_rsp: SecParamExchRspData =
                serde_json::from_str(&body).map_err(|e| format!("bad SecParamExchRspData: {e}"))?;
            n32c_handler::handle_exchange_params_response(&mut node, &params_req, &params_rsp)?;

            node.handshake_state = crate::handshake_sm::HandshakeState::Established;
            update_node(&node);
            register_n32f_client_for_node(&node, tls.is_some());
            log::info!("[{peer_fqdn}] N32-c handshake complete: PRINS (keys established)");
            Ok(HandshakeOutcome {
                node_id: node.id,
                security: SecurityCapability::Prins,
            })
        }
        other => {
            update_node(&node);
            Err(format!("Handshake ended without security: {other:?}"))
        }
    }
}

/// Forward an SBI request to the peer SEPP over N32-f, applying the
/// negotiated protection (PRINS JWE/JWS or TLS pass-through envelope).
pub async fn forward_via_n32f(
    node_id: u64,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    tls: Option<&N32TlsConfig>,
) -> Result<(u16, String), String> {
    let node = {
        let ctx = sepp_self();
        let context = ctx.read().map_err(|_| "context poisoned".to_string())?;
        context
            .node_find(node_id)
            .ok_or_else(|| format!("No SEPP node {node_id}"))?
    };
    let api_root = node
        .peer_api_root
        .clone()
        .ok_or("Peer apiRoot not configured")?;

    let n32f_body = match node.negotiated_security_scheme {
        SecurityCapability::Prins => {
            let prins_ctx = crate::sbi_path::build_prins_context(node_id)
                .ok_or("PRINS negotiated but no N32-f security context")?;
            let msg = prins::protect_message(&prins_ctx, method, url, headers, body)
                .map_err(|e| format!("PRINS protection failed: {e}"))?;
            serde_json::to_string(&msg).map_err(|e| e.to_string())?
        }
        SecurityCapability::Tls => {
            // Carry our sender-SEPP identity so the receiver can bind the
            // message to the established N32-c TLS negotiation.
            let local_sender = {
                let ctx = sepp_self();
                ctx.read().ok().and_then(|c| c.sender.clone())
            };
            let mut tls_headers = headers.to_vec();
            if let Some(sender) = local_sender {
                if !tls_headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("3gpp-sbi-sender-sepp"))
                {
                    tls_headers.push(("3gpp-sbi-sender-sepp".to_string(), sender));
                }
            }
            let msg = crate::n32c_build::build_n32f_tls_message(method, url, &tls_headers, body);
            serde_json::to_string(&msg).map_err(|e| e.to_string())?
        }
        other => return Err(format!("No N32-f security established ({other:?})")),
    };

    let client = n32_client(&api_root, tls)?;
    let (status, resp_body) =
        post_json(&client, "/n32f-forward/v1/n32f-process", n32f_body).await?;

    // TS 29.573 §6.2.4.2: in PRINS the peer SEPP returns a protected
    // N32fReformattedRspMsg carrying the target NF's HTTP response. Unprotect
    // it to recover the real (status, body) before returning to the caller.
    if node.negotiated_security_scheme == SecurityCapability::Prins && status == 200 {
        if let Ok(reformatted) = serde_json::from_str::<N32fReformattedMessage>(&resp_body) {
            let prins_ctx = crate::sbi_path::build_prins_context(node_id)
                .ok_or("PRINS negotiated but no N32-f security context")?;
            let rec = prins::unprotect_response_message(&prins_ctx, &reformatted)
                .map_err(|e| format!("N32-f response unprotect failed: {e}"))?;
            let body = rec
                .body
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
            return Ok((rec.status_code, body));
        }
    }
    Ok((status, resp_body))
}

// ============================================================================
// Consumer-facing SBI server (C8)
//
// NFs in the home PLMN send outbound roaming requests to this server. It
// runs the SEPP forwarding pipeline: detect the VPLMN from the
// 3gpp-sbi-target-apiroot, select the peer SEPP for that PLMN, apply the
// negotiated N32-f protection (PRINS JWE/JWS or TLS pass-through), POST to
// the peer's /n32f-process, and relay the response back to the NF.
// ============================================================================

/// #1795: the consumer-facing SBI listener's configuration under the SBI
/// security profile. Under `production`: TLS from `policy`'s certificate paths
/// (whatever `--tls` said) and the client certificate verified against its CA
/// (TS 33.501 §13.1.0, §13.3). No access token is required OF the SEPP: the
/// token a home NF sends with a roaming request is for the remote producer,
/// which verifies it (TS 33.501 §13.4.1.2), so a SEPP that demanded one for
/// itself would refuse every request. A missing certificate is an error naming
/// it, never cleartext. Under `dev` the SEPP's own `--tls` applies, as before.
pub fn sbi_server_config(
    host: &str,
    port: u16,
    tls: Option<&N32TlsConfig>,
    profile: nextgcore_sbi::security::SbiProfile,
    policy: &nextgcore_sbi::security::SbiSecurityPolicy,
) -> Result<SbiServerConfig, String> {
    let mut config = SbiServerConfig::with_host_port(host, port).map_err(|e| e.to_string())?;
    config = config.with_interface("sbi");
    if let Some(tls_cfg) = tls {
        if let (Some(key), Some(cert)) = (&tls_cfg.key, &tls_cfg.cert) {
            config = config.with_tls(key.clone(), cert.clone());
        }
    }
    let policy = nextgcore_sbi::security::SbiSecurityPolicy {
        oauth2_required: false,
        ..policy.clone()
    };
    nextgcore_sbi::security::apply_sbi_security_policy(
        config,
        profile,
        &policy,
        nextgcore_sbi::types::NfType::Sepp,
        // Only read for a token requirement, which the SEPP does not have.
        "",
    )
    .map_err(|e| format!("SBI security profile: {e}"))
}

/// #1795: N32 is never cleartext under the `production` profile: N32-c is a
/// TLS connection between the SEPPs (TS 33.501 §13.2.1), so starting an N32
/// listener without `--tls` there is a startup error, not a cleartext N32.
pub fn check_n32_transport(
    profile: nextgcore_sbi::security::SbiProfile,
    tls: Option<&N32TlsConfig>,
) -> Result<(), String> {
    let has_tls = tls.is_some_and(|t| t.key.is_some() && t.cert.is_some());
    if profile.is_production() && !has_tls {
        return Err(
            "the SBI profile is production and N32 has no TLS: N32-c is TLS between the SEPPs \
             (TS 33.501 §13.2.1). Start with --tls, --tls-cert and --tls-key, or select \
             NEXTGCORE_SBI_PROFILE=dev explicitly"
                .to_string(),
        );
    }
    Ok(())
}

/// Start the consumer-facing SBI server on `host:port` with `config` from
/// [`sbi_server_config`]. Returns the handle the caller stops on shutdown.
pub async fn start_sbi_server(config: SbiServerConfig) -> Result<SbiServer, String> {
    let (host, port) = (config.addr.ip(), config.addr.port());
    let server = SbiServer::new(config);
    server
        .start(sbi_consumer_handler)
        .await
        .map_err(|e| format!("SBI server start failed: {e}"))?;
    log::info!("SEPP consumer SBI server on {host}:{port}");
    Ok(server)
}

/// Resource path of the `Nsepp_Telescopic_FQDN_Mapping` mapping document
/// (`TS29573_SeppTelescopicFqdnMapping.yaml:22-24`).
const TELESCOPIC_MAPPING_PATH: &str = "/nsepp-telescopic/v1/mapping";

/// One query parameter's raw value from a request URI, or `None`.
fn query_param<'a>(uri: &'a str, key: &str) -> Option<&'a str> {
    uri.split_once('?')?
        .1
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// `GetTelescopicMapping` (`GET /nsepp-telescopic/v1/mapping`, TS 29.573 §5.4).
///
/// The two query parameters select the two procedures, and **exactly one** must be
/// present. Both are declared optional by the schema, but §5.4.2 and §5.4.3 are
/// distinct procedures each driven by one of them: a request with neither asks
/// nothing, and a request with both asks two contradictory questions — answering
/// one of them silently would return a mapping the consumer did not unambiguously
/// request.
fn handle_telescopic_mapping(uri: &str) -> HttpResponse {
    let foreign_fqdn = query_param(uri, "foreign-fqdn").filter(|v| !v.is_empty());
    let telescopic_label = query_param(uri, "telescopic-label").filter(|v| !v.is_empty());

    match (foreign_fqdn, telescopic_label) {
        // §5.4.2: flatten a foreign FQDN into a label under our own domain.
        (Some(fqdn), None) => {
            let sepp_domain = sepp_self()
                .read()
                .ok()
                .and_then(|c| c.sender.clone())
                .filter(|s| !s.trim().is_empty());
            let Some(sepp_domain) = sepp_domain else {
                // Without our own FQDN the consumer cannot form
                // `<label>.<seppDomain>`, so a 200 carrying only the label would be
                // an answer it cannot use.
                log::error!(
                    "telescopic mapping requested but the local SEPP FQDN is unset;                      start with --sender"
                );
                return send_error(
                    500,
                    "Internal Server Error",
                    "Local SEPP FQDN not configured (--sender), so no telescopic FQDN can be                      formed",
                    Some("SYSTEM_FAILURE"),
                );
            };
            let mapping = crate::telescopic::map_foreign_fqdn(fqdn, &sepp_domain);
            log::info!(
                "telescopic mapping: [{fqdn}] -> [{}.{sepp_domain}]",
                mapping.telescopic_label.as_deref().unwrap_or("")
            );
            HttpResponse::ok()
                .with_json_body(&mapping)
                .unwrap_or_else(|_| HttpResponse::internal_error())
        }
        // §5.4.3: reverse a label a sibling SEPP does not recognise.
        (None, Some(label)) => match crate::telescopic::resolve_label(label) {
            Some(fqdn) => {
                let mapping = crate::telescopic::TelescopicMapping {
                    telescopic_label: Some(label.to_string()),
                    sepp_domain: sepp_self().read().ok().and_then(|c| c.sender.clone()),
                    foreign_fqdn: Some(fqdn),
                };
                HttpResponse::ok()
                    .with_json_body(&mapping)
                    .unwrap_or_else(|_| HttpResponse::internal_error())
            }
            None => send_error(
                404,
                "Not Found",
                &format!("No telescopic mapping for label [{label}]"),
                Some("DATA_NOT_FOUND"),
            ),
        },
        _ => send_error(
            400,
            "Bad Request",
            "Exactly one of foreign-fqdn or telescopic-label is required",
            Some("MANDATORY_IE_INCORRECT"),
        ),
    }
}

/// Consumer SBI handler: forward outbound VPLMN requests through the peer
/// SEPP via N32-f, relaying the peer's response.
async fn sbi_consumer_handler(request: HttpRequest) -> HttpResponse {
    let method = request.header.method.clone();
    let uri = request.header.uri.clone();

    // TS 29.573 §5.4: the telescopic-FQDN mapping service is served to NFs in THIS
    // PLMN, so it is answered locally and must be matched before the
    // target-apiRoot check below — a mapping GET carries no target-apiRoot and would
    // otherwise be refused 400 as "not a roaming request".
    if uri.split('?').next().unwrap_or(&uri).trim_end_matches('/') == TELESCOPIC_MAPPING_PATH {
        if !method.eq_ignore_ascii_case("GET") {
            return send_error(
                405,
                "Method Not Allowed",
                &format!("Method {method} not allowed for {TELESCOPIC_MAPPING_PATH}"),
                Some("MANDATORY_IE_INCORRECT"),
            );
        }
        return handle_telescopic_mapping(&uri);
    }

    // Liveness/local endpoints are handled by nextgcore-sbi; everything else with a
    // target-apiroot is a forwarding request.
    let target_apiroot = request
        .http
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(crate::sbi_path::headers::TARGET_APIROOT))
        .map(|(_, v): (&String, &String)| v.clone());

    let Some(target_apiroot) = target_apiroot else {
        log::debug!(
            "SBI request without target-apiRoot handled locally: {method} {}",
            nextgcore_sbi::log_redact::redact_callback_tokens(&uri)
        );
        return send_error(
            400,
            "Bad Request",
            "Missing 3gpp-sbi-target-apiroot (not a roaming request)",
            Some("MANDATORY_IE_INCORRECT"),
        );
    };

    // Select the peer SEPP by the VPLMN encoded in the target-apiRoot.
    let node = match crate::sbi_path::select_peer_for_target(&target_apiroot) {
        Ok(node) => node,
        Err(e) => {
            log::error!("SBI forward: {e}");
            return send_error(404, "Not Found", &e, Some("TARGET_NF_NOT_REACHABLE"));
        }
    };

    if node.handshake_state != crate::handshake_sm::HandshakeState::Established {
        return send_error(
            503,
            "Service Unavailable",
            &format!("N32-c to peer [{}] not established", node.receiver),
            Some("TARGET_NF_NOT_REACHABLE"),
        );
    }

    let headers: Vec<(String, String)> = request
        .http
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let body = request.http.content.clone().map(|c| c.into_bytes());

    match forward_via_n32f(node.id, &method, &uri, &headers, body.as_deref(), None).await {
        Ok((status, rsp_body)) => {
            log::info!(
                "SBI forward {method} {} -> peer [{}] status={status}",
                nextgcore_sbi::log_redact::redact_callback_tokens(&uri),
                node.receiver
            );
            let mut resp = HttpResponse::with_status(status);
            resp.http.set_content(rsp_body);
            resp.http.set_header("Content-Type", "application/json");
            resp
        }
        Err(e) => {
            log::error!("SBI forward to peer [{}] failed: {e}", node.receiver);
            send_error(502, "Bad Gateway", &e, Some("TARGET_NF_NOT_REACHABLE"))
        }
    }
}

/// POST an N32fErrorInfo report to the peer SEPP (TS 29.573 sec 6.1.5.4)
pub async fn send_n32f_error(peer_api_root: &str, info: &N32fErrorInfo) -> Result<(), String> {
    let body = serde_json::to_string(info).map_err(|e| e.to_string())?;
    let client = n32_client(peer_api_root, None)?;
    let (status, _) = post_json(&client, "/n32c-handshake/v1/n32f-error", body).await?;
    if status == 204 || status == 200 {
        Ok(())
    } else {
        Err(format!("n32f-error report rejected: HTTP {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbi_path::select_peer_for_target;

    async fn get(uri: &str) -> HttpResponse {
        sbi_consumer_handler(HttpRequest::get(uri)).await
    }

    /// #100: `GET /nsepp-telescopic/v1/mapping` is routed and answers both TS 29.573
    /// §5.4 procedures. The route did not exist — a mapping GET carries no
    /// `3gpp-Sbi-Target-apiRoot`, so before this it was refused 400 as "not a
    /// roaming request".
    // The guard is held across the awaits deliberately: the whole point is that no
    // other test rewrites `context.sender` or the mapping store mid-procedure.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn the_telescopic_mapping_route_answers_both_procedures() {
        let _g = crate::context::lock_global_test_state();
        crate::sepp_context_init(16, 16);
        crate::telescopic::clear_mappings();
        if let Ok(mut c) = sepp_self().write() {
            c.set_sender("sepp.local.example.com");
        }

        // §5.4.2: foreign FQDN -> label + our domain.
        let resp = get("/nsepp-telescopic/v1/mapping?foreign-fqdn=nrf.foreign.example.com").await;
        assert_eq!(
            resp.status, 200,
            "the mapping route must be served locally, not treated as a forwarding              request; got {:?}",
            resp.http.content
        );
        let mapping: crate::telescopic::TelescopicMapping =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let label = mapping.telescopic_label.clone().expect("telescopicLabel");
        assert_eq!(
            mapping.sepp_domain.as_deref(),
            Some("sepp.local.example.com"),
            "the consumer forms <label>.<seppDomain>, so seppDomain must be present"
        );
        assert!(
            !label.contains('.'),
            "the label must be flattened to one label; got {label}"
        );

        // §5.4.3: that same label reverses to the foreign FQDN.
        let resp = get(&format!(
            "/nsepp-telescopic/v1/mapping?telescopic-label={label}"
        ))
        .await;
        assert_eq!(resp.status, 200);
        let reversed: crate::telescopic::TelescopicMapping =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            reversed.foreign_fqdn.as_deref(),
            Some("nrf.foreign.example.com")
        );

        // An unissued label is the procedure's own "no existing mapping" -> 404.
        let resp =
            get("/nsepp-telescopic/v1/mapping?telescopic-label=tl00000000000000000000000000000000")
                .await;
        assert_eq!(resp.status, 404);

        // Exactly one parameter: neither and both are refused.
        assert_eq!(get("/nsepp-telescopic/v1/mapping").await.status, 400);
        assert_eq!(
            get(&format!(
                "/nsepp-telescopic/v1/mapping?foreign-fqdn=nrf.foreign.example.com\
                 &telescopic-label={label}"
            ))
            .await
            .status,
            400
        );

        // Wrong method on the right path is 405, not a forwarding attempt.
        let resp = sbi_consumer_handler(HttpRequest::post("/nsepp-telescopic/v1/mapping")).await;
        assert_eq!(resp.status, 405);

        crate::telescopic::clear_mappings();
    }

    /// #100: `sender` is optional in `SecParamExchReqData`
    /// (`yaml:422-455` lists `required: [n32fContextId]` only), so a body omitting
    /// it must deserialise, and the peer must be resolvable without it.
    #[test]
    fn exchange_params_without_a_sender_deserialises_and_resolves_the_peer() {
        // Deserialising is the half that used to fail outright: a bare `String`
        // field with no `serde(default)` errors on an absent member.
        let req: SecParamExchReqData =
            serde_json::from_str(r#"{"n32fContextId":"0123456789ABCDEF"}"#)
                .expect("an omitted sender must deserialise");
        assert!(req.sender.is_none());

        // Resolution 2: senderApiRoot's host stands in for the absent sender.
        let with_root = SecParamExchReqData {
            sender_api_root: Some("https://sepp.peer.example.com:9090".to_string()),
            ..req.clone()
        };
        assert_eq!(
            resolve_exchange_params_peer(&with_root).as_deref(),
            Some("sepp.peer.example.com")
        );

        // Resolution 1: an explicit sender still wins over senderApiRoot.
        let with_both = SecParamExchReqData {
            sender: Some("sepp.explicit.example.com".to_string()),
            ..with_root.clone()
        };
        assert_eq!(
            resolve_exchange_params_peer(&with_both).as_deref(),
            Some("sepp.explicit.example.com")
        );

        // Resolution 3: with one N32-c handshake in flight, attribute to it.
        let inflight = crate::context::SeppNode::new(1, "sepp.inflight.example.com");
        assert_eq!(
            single_pending_peer(std::slice::from_ref(&inflight)).as_deref(),
            Some("sepp.inflight.example.com"),
            "exchange-params arrives on an existing N32-c association"
        );

        // An ESTABLISHED association is not a candidate — it already completed
        // parameter exchange, so a further request is a new handshake, not this one.
        let mut established = crate::context::SeppNode::new(2, "sepp.done.example.com");
        established.handshake_state = crate::handshake_sm::HandshakeState::Established;
        assert_eq!(
            single_pending_peer(&[inflight.clone(), established.clone()]).as_deref(),
            Some("sepp.inflight.example.com")
        );

        // ...but NOT with two in flight, because guessing would derive keys against
        // the wrong exporter secret and yield a silently unusable N32-f context.
        let second = crate::context::SeppNode::new(3, "sepp.second.example.com");
        assert_eq!(
            single_pending_peer(&[inflight, second]),
            None,
            "two candidates must be unattributable, not a coin flip"
        );

        // And none at all is unattributable too.
        assert_eq!(single_pending_peer(&[established]), None);
    }

    #[test]
    fn test_parse_api_root() {
        assert_eq!(
            parse_api_root("http://127.0.0.1:8443").unwrap(),
            (false, "127.0.0.1".to_string(), 8443)
        );
        assert_eq!(
            parse_api_root("https://sepp.example.com:9090/").unwrap(),
            (true, "sepp.example.com".to_string(), 9090)
        );
        assert_eq!(
            parse_api_root("https://sepp.example.com").unwrap(),
            (true, "sepp.example.com".to_string(), 443)
        );
        assert!(parse_api_root("ftp://x").is_err());
    }

    #[test]
    fn test_mtls_listener_config_mapping() {
        // Verify the TLS/mTLS knobs map through to the nextgcore-sbi config
        let tls = N32TlsConfig {
            cert: Some("/tls/server.crt".into()),
            key: Some("/tls/server.key".into()),
            verify_client_cacert: Some("/tls/ca.crt".into()),
            ..Default::default()
        };
        let mut config = SbiServerConfig::with_host_port("127.0.0.1", 0).unwrap();
        config = config.with_tls(tls.key.clone().unwrap(), tls.cert.clone().unwrap());
        config.verify_client = true;
        config.verify_client_cacert = tls.verify_client_cacert.clone();

        assert_eq!(config.scheme, nextgcore_sbi::types::UriScheme::Https);
        assert!(config.verify_client);
        assert_eq!(config.verify_client_cacert.as_deref(), Some("/tls/ca.crt"));
    }

    // --- C4: mTLS is mandatory on N32-c whenever TLS is configured ---

    #[test]
    fn test_effective_client_cacert_falls_back_to_ca_cert() {
        // mTLS CA defaults to verify_client_cacert, else the server CA bundle
        let tls = N32TlsConfig {
            ca_cert: Some("/tls/peer-ca.crt".into()),
            ..Default::default()
        };
        assert_eq!(tls.effective_client_cacert(), Some("/tls/peer-ca.crt"));
        let tls2 = N32TlsConfig {
            verify_client_cacert: Some("/tls/explicit-ca.crt".into()),
            ca_cert: Some("/tls/peer-ca.crt".into()),
            ..Default::default()
        };
        assert_eq!(tls2.effective_client_cacert(), Some("/tls/explicit-ca.crt"));
    }

    #[tokio::test]
    async fn test_n32_listener_requires_mtls_when_tls_configured() {
        // TLS configured, but NO client CA and not opted out => must refuse
        // to start (N32-c MUST be mutually authenticated, TS 33.501).
        let tls = N32TlsConfig {
            cert: Some("/tls/server.crt".into()),
            key: Some("/tls/server.key".into()),
            // no verify_client_cacert, no ca_cert, allow_insecure_no_mtls=false
            ..Default::default()
        };
        let res = start_n32_listener("127.0.0.1", 0, Some(&tls)).await;
        match res {
            Err(err) => assert!(
                err.contains("requires mTLS"),
                "expected mTLS-required error, got: {err}"
            ),
            Ok(server) => {
                let _ = server.stop().await;
                panic!("listener must refuse to start without mTLS");
            }
        }
    }

    #[tokio::test]
    async fn test_n32_listener_mtls_opt_out_allowed_for_lab() {
        // Same as above but explicitly opted out => allowed (loads will fail
        // later on the bogus cert path, but the mTLS gate must not block).
        let tls = N32TlsConfig {
            cert: Some("/tls/server.crt".into()),
            key: Some("/tls/server.key".into()),
            allow_insecure_no_mtls: true,
            ..Default::default()
        };
        let res = start_n32_listener("127.0.0.1", 0, Some(&tls)).await;
        // The mTLS gate does not reject; any failure must be a TLS-load error,
        // never the "requires mTLS" gate.
        if let Err(e) = res {
            assert!(!e.contains("requires mTLS"), "mTLS gate wrongly fired: {e}");
        }
    }

    // --- C5: /n32f-process enforcement ---

    /// Ensure the shared global context is initialized. Deliberately does NOT
    /// mutate the global sender/serving-PLMN list, which other (parallel)
    /// tests rely on; these enforcement tests don't depend on a specific
    /// sender FQDN.
    fn ensure_ctx_initialized() {
        let ctx = sepp_self();
        let mut c = ctx.write().unwrap();
        if !c.is_initialized() {
            c.init(64, 256);
        }
    }

    #[tokio::test]
    async fn test_n32f_process_rejects_unestablished_prins_peer() {
        ensure_ctx_initialized();
        // Add a peer node that negotiated PRINS but is NOT established, with a
        // security context so peek-by-context-id resolves it.
        let node_id;
        {
            let ctx = sepp_self();
            let c = ctx.read().unwrap();
            let mut node = c.node_add("sepp-unestab.example.com").unwrap();
            node.negotiated_security_scheme = SecurityCapability::Prins;
            node.handshake_state = crate::handshake_sm::HandshakeState::WillEstablish;
            node.n32f_security = Some(crate::context::N32fSecurityInfo {
                local_context_id: "unestab-local-ctx".to_string(),
                peer_context_id: "unestab-peer-ctx".to_string(),
                key_material: crate::n32c_handler::derive_n32f_key_material(
                    &[0u8; 64],
                    "unestab-local-ctx-unestab-peer-ctx",
                ),
                role: crate::n32c_handler::N32fRole::Responder,
                kid: "unestab-kid".to_string(),
                jwe_cipher_suite: "A256GCM".to_string(),
                jws_cipher_suite: "ES256".to_string(),
                enc_profiles: Vec::new(),
            });
            c.node_update(&node);
            node_id = node.id;
        }
        assert!(node_id > 0);

        // Craft a PRINS-shaped message whose AAD names that local context id.
        let aad = serde_json::json!({
            "metaData": { "n32fContextId": "unestab-local-ctx" }
        });
        let msg = serde_json::json!({
            "reformattedData": {
                "protected": crate::jose::b64url_encode(br#"{"alg":"dir","enc":"A256GCM"}"#),
                "aad": crate::jose::b64url_encode(&serde_json::to_vec(&aad).unwrap()),
                "iv": crate::jose::b64url_encode(&[0u8; 12]),
                "ciphertext": crate::jose::b64url_encode(b"x"),
                "tag": crate::jose::b64url_encode(&[0u8; 16])
            }
        });
        let resp = handle_n32f_process(&serde_json::to_string(&msg).unwrap()).await;
        // Rejected at the handshake-state gate (403), not processed.
        assert_eq!(resp.status, 403, "unestablished peer must be rejected");
    }

    #[test]
    fn test_enforce_tls_mode_peer_unknown_sender_rejected() {
        ensure_ctx_initialized();
        // No node registered for this sender => rejected (403).
        let resp = enforce_tls_mode_peer(Some("sepp-stranger.example.com"))
            .expect("unknown sender must be rejected");
        assert_eq!(resp.status, 403);
    }

    #[test]
    fn test_enforce_tls_mode_peer_missing_header_rejected() {
        let resp =
            enforce_tls_mode_peer(None).expect("missing sender-sepp header must be rejected");
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn test_enforce_tls_mode_peer_established_tls_accepted() {
        ensure_ctx_initialized();
        {
            let ctx = sepp_self();
            let c = ctx.read().unwrap();
            let mut node = c.node_add("sepp-tls-ok.example.com").unwrap();
            node.negotiated_security_scheme = SecurityCapability::Tls;
            node.handshake_state = crate::handshake_sm::HandshakeState::Established;
            c.node_update(&node);
        }
        assert!(enforce_tls_mode_peer(Some("sepp-tls-ok.example.com")).is_none());
    }

    // ── issue #99: N32-f forwarding and context termination ─────────────────

    /// Register a TLS-mode peer with an N32-f security context, and return its
    /// locally-allocated context id.
    /// #2076: a request from the SEPP whose verified certificate names `fqdns`.
    fn from_sepp(mut req: HttpRequest, fqdns: &[&str]) -> HttpRequest {
        req.peer_cert_present = true;
        req.peer_cert_dns_sans = fqdns.iter().map(|f| f.to_string()).collect();
        req
    }

    fn tls_peer_with_context(receiver: &str, context_id: &str) -> u64 {
        ensure_ctx_initialized();
        let ctx = sepp_self();
        let c = ctx.read().unwrap();
        let mut node = c.node_add(receiver).unwrap();
        node.negotiated_security_scheme = SecurityCapability::Tls;
        node.handshake_state = crate::handshake_sm::HandshakeState::Established;
        node.n32f_security = Some(crate::context::N32fSecurityInfo {
            local_context_id: context_id.to_string(),
            peer_context_id: format!("peer-{context_id}"),
            key_material: crate::n32c_handler::derive_n32f_key_material(&[7u8; 64], context_id),
            role: crate::n32c_handler::N32fRole::Initiator,
            kid: context_id.to_string(),
            jwe_cipher_suite: "A256GCM".to_string(),
            jws_cipher_suite: "ES256".to_string(),
            enc_profiles: Vec::new(),
        });
        let id = node.id;
        c.node_update(&node);
        id
    }

    /// **Criterion 2, the regression guard.** The TLS-mode handler must not
    /// return the reconstructed request.
    ///
    /// It used to answer `200` with the request echoed back via
    /// `with_json_body(&rec)`, so in TLS security mode roaming SBI traffic never
    /// reached the target NF and no service request was ever fulfilled. With no
    /// resolvable target here the forward attempt fails, which is the honest
    /// outcome -- and crucially NOT a 200 carrying the request.
    #[tokio::test]
    async fn tls_mode_does_not_echo_the_reconstructed_request() {
        tls_peer_with_context("sepp-echo-guard.example.com", "ctx-echo-guard");
        // Built with the real sender-side builder, not hand-written JSON: an
        // envelope missing a field (`protocol`) is rejected at 400 before the TLS
        // branch runs, which would make this assertion vacuous.
        let msg = crate::n32c_build::build_n32f_tls_message(
            "GET",
            "/nnrf-disc/v1/nf-instances",
            &[(
                "3gpp-sbi-sender-sepp".to_string(),
                "sepp-echo-guard.example.com".to_string(),
            )],
            None,
        );
        let resp = handle_n32f_process(&serde_json::to_string(&msg).unwrap()).await;
        // Must have reached the TLS branch: a parse/authorisation rejection would
        // make the assertions below pass for the wrong reason.
        let body = resp.http.content.clone().unwrap_or_default();

        // POSITIVE evidence that the forward was ATTEMPTED, not merely that the
        // echo is gone. Without a `3gpp-Sbi-Target-apiRoot` header and with a
        // relative URL there is no target to resolve, so `forward_to_target_nf`
        // answers with its own problem response -- and that string is only
        // reachable from inside the forwarding path.
        //
        // Asserting this rather than just `status != 200` matters: an earlier
        // version of this test hand-wrote the envelope, which failed to parse at
        // 400 before the TLS branch ran, so every assertion passed for the wrong
        // reason. A vacuous guard is worse than none.
        assert!(
            body.contains("target NF apiRoot could not be resolved"),
            "the TLS branch must reach forward_to_target_nf, got {resp:?}"
        );
        assert_ne!(
            resp.status, 200,
            "a 200 here means the request was echoed rather than forwarded"
        );
        assert!(
            !body.contains("requestLine") && !body.contains("/nnrf-disc/v1/nf-instances"),
            "the response must not be the inbound reconstructed request, got {body}"
        );
    }

    /// **Criterion 3.** `n32f-terminate` returns `N32fContextInfo`, and deletes
    /// the context AND its keys -- the key hierarchy lives inside
    /// `n32f_security`, so clearing it is the deletion.
    ///
    /// Also asserts the follow-on property: a later N32-f message on the
    /// terminated context is rejected, so a peer cannot ride a context whose keys
    /// are gone.
    #[tokio::test]
    async fn n32f_terminate_returns_context_info_and_deletes_the_keys() {
        let node_id = tls_peer_with_context("sepp-term.example.com", "ctx-to-terminate");

        let resp = handle_n32f_terminate(
            &serde_json::json!({ "n32fContextId": "ctx-to-terminate" }).to_string(),
            &from_sepp(HttpRequest::default(), &["sepp-term.example.com"]),
        );
        assert_eq!(resp.status, 200, "TS 29.573 5.2.4 mandates 200");
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            body["n32fContextId"], "ctx-to-terminate",
            "the response body is an N32fContextInfo naming the terminated context"
        );

        // The context and its keys are gone...
        {
            let ctx = sepp_self();
            let c = ctx.read().unwrap();
            let node = c.node_find(node_id).expect("the PEER must survive");
            assert!(
                node.n32f_security.is_none(),
                "the N32-f context and its key material must be deleted"
            );
            assert_eq!(
                node.handshake_state,
                crate::handshake_sm::HandshakeState::Initial,
                "the handshake must be reset so the dead context cannot be ridden"
            );
        }
        // ...and the peer itself is NOT removed: its provisioning survives an
        // N32-f teardown (see handle_n32f_terminate's docs).
        assert!(
            c_node_exists(node_id),
            "terminating a context must not de-provision the peer"
        );
        // A later message on that context id no longer resolves.
        assert!(
            {
                let ctx = sepp_self();
                let c = ctx.read().unwrap();
                c.node_find_by_n32f_context_id("ctx-to-terminate").is_none()
            },
            "the terminated context must no longer resolve"
        );
    }

    fn c_node_exists(id: u64) -> bool {
        let ctx = sepp_self();
        let c = ctx.read().unwrap();
        c.node_find(id).is_some()
    }

    /// An unknown context is 404, not a silent success: the peer asked us to
    /// destroy keys, and claiming we did when we never held them is the wrong
    /// answer for a border function.
    #[test]
    fn n32f_terminate_unknown_context_is_404() {
        ensure_ctx_initialized();
        let peer = from_sepp(HttpRequest::default(), &["sepp-term.example.com"]);
        let resp = handle_n32f_terminate(
            &serde_json::json!({ "n32fContextId": "ctx-never-existed" }).to_string(),
            &peer,
        );
        assert_eq!(resp.status, 404);
        // And a missing mandatory IE is 400, not 404.
        let resp = handle_n32f_terminate("{}", &peer);
        assert_eq!(resp.status, 400);
    }

    /// #2087 (R30's audit): received n32f-error reports are bounded: past
    /// `MAX_RECEIVED_N32F_ERRORS` the oldest are dropped.
    ///
    /// REVERT-VERIFIED: with the bound removed, all of them are kept and the
    /// length assertion fails.
    #[test]
    fn received_n32f_errors_are_bounded_2087() {
        let _ = take_received_n32f_errors();
        let n = MAX_RECEIVED_N32F_ERRORS + 10;
        for i in 0..n {
            let body = serde_json::json!({
                "n32fMessageId": format!("m-2087-{i}"),
                "n32fErrorType": "INTEGRITY_CHECK_FAILED",
            })
            .to_string();
            assert_eq!(handle_n32f_error_report(&body).status, 204);
        }
        let kept: Vec<String> = take_received_n32f_errors()
            .into_iter()
            .map(|e| e.n32f_message_id)
            .filter(|id| id.starts_with("m-2087-"))
            .collect();
        assert_eq!(kept.len(), MAX_RECEIVED_N32F_ERRORS);
        assert_eq!(
            kept.last().map(String::as_str),
            Some(format!("m-2087-{}", n - 1).as_str())
        );
        assert!(
            !kept.contains(&"m-2087-0".to_string()),
            "the oldest is dropped"
        );
    }

    /// #2087 (R30's audit): a failed exchange-params leaves no TLS exporter
    /// secret behind for its peer.
    ///
    /// REVERT-VERIFIED: without the removal on failure, the secret is still
    /// there.
    #[test]
    fn a_failed_exchange_params_leaves_no_exporter_secret_2087() {
        ensure_ctx_initialized();
        let peer = "sepp-fail-2087.example.com";
        let body = serde_json::json!({
            "sender": peer, "n32fContextId": "ctx-fail-2087",
            "jweCipherSuiteList": ["BOGUS"], "jwsCipherSuiteList": ["BOGUS"],
        })
        .to_string();
        let rsp = handle_exchange_params(
            &body,
            Some(&[9u8; 64]),
            "cid",
            &from_sepp(HttpRequest::default(), &[peer]),
        );
        assert_eq!(rsp.status, 400, "{:?}", rsp.http.content);
        assert!(n32c_handler::take_n32c_tls_exporter_secret(peer).is_none());
    }

    /// **#2112** (R31 on #2110): a foreign `n32f-terminate` takes the unknown
    /// context's path, not just its answer: the same status and body, and the
    /// same log line, at DEBUG. Before, the foreign case built and discarded a
    /// 403 and logged a WARN naming both SEPPs, a timing and log-volume
    /// difference a peer could also use to fill the log.
    ///
    /// REVERT-VERIFIED: with the filter back on `refuse_unbound_peer`, the
    /// WARN naming SEPP A is logged and "no WARN" fails.
    #[test]
    fn a_foreign_n32f_terminate_is_answered_and_logged_as_an_unknown_context_2112() {
        nextgcore_core::test_log::init();
        let a = "sepp-a-2112.example.com";
        let node_id = tls_peer_with_context(a, "ctx-2112-a");
        let from_b = from_sepp(HttpRequest::default(), &["sepp-b-2112.example.com"]);
        let terminate = |id: &str| {
            handle_n32f_terminate(
                &serde_json::json!({ "n32fContextId": id }).to_string(),
                &from_b,
            )
        };
        let about_a = nextgcore_core::test_log::watch(a);
        let foreign_log = nextgcore_core::test_log::watch("ctx-2112-a");
        let unknown_log = nextgcore_core::test_log::watch("ctx-2112-none");

        let foreign = terminate("ctx-2112-a");
        let unknown = terminate("ctx-2112-none");

        let answer = |r: &HttpResponse, id: &str| {
            (
                r.status,
                r.http.content.as_deref().map(|c| c.replace(id, "ID")),
            )
        };
        assert_eq!(answer(&foreign, "ctx-2112-a").0, 404);
        assert_eq!(
            answer(&foreign, "ctx-2112-a"),
            answer(&unknown, "ctx-2112-none"),
            "the same answer"
        );
        let lines = |w: &nextgcore_core::test_log::Watch, id: &str| {
            w.records()
                .iter()
                .map(|r| r.replace(id, "ID"))
                .collect::<Vec<_>>()
        };
        let unknown_lines = lines(&unknown_log, "ctx-2112-none");
        assert_eq!(
            unknown_lines,
            [
                "DEBUG nextgcore_seppd::n32_server: n32f-terminate of ID answered 404: the \
                 calling SEPP has no N32-f context with that id"
            ],
            "an unknown context leaves one DEBUG line"
        );
        assert_eq!(
            lines(&foreign_log, "ctx-2112-a"),
            unknown_lines,
            "and a foreign one the same line"
        );
        let warns: Vec<String> = about_a
            .records()
            .into_iter()
            .filter(|r| r.starts_with("WARN"))
            .collect();
        assert_eq!(warns, Vec::<String>::new(), "no WARN names SEPP A");

        let ctx = sepp_self();
        let c = ctx.read().unwrap();
        assert!(
            c.node_find(node_id).unwrap().n32f_security.is_some(),
            "A's context is untouched"
        );
    }

    /// #2076 (R32's audit): N32-c claims are bound to the SEPP on the other end
    /// (TS 29.573 §5.2, TS 33.310 §6.1.4a). The probe: SEPP B, holding a
    /// certificate for `sepp-b.example.com`, (1) renegotiates capability as
    /// `sepp-a.example.com`, (2) sends exchange-params as SEPP A, and (3)
    /// terminates SEPP A's N32-f context. (1) and (2) are 403, (3) is the 404
    /// of an unknown context (#2096), and none changes anything: A's
    /// node keeps its negotiated scheme and its context and keys. A request
    /// with no verified certificate is refused under production. SEPP A itself
    /// (its FQDN in another case, with a trailing dot) terminates its context.
    ///
    /// REVERT-VERIFIED: with `refuse_unbound_peer` returning `None`, B's
    /// terminate is 200 and A's keys are gone. #2096: B's terminate is
    /// answered as an unknown context; with the 403 back, the body differs.
    #[tokio::test]
    async fn an_n32c_request_is_bound_to_the_peer_certificate_2076() {
        let a = "sepp-a-2076.example.com";
        let node_id = tls_peer_with_context(a, "ctx-2076");
        let from_b = |r: HttpRequest| from_sepp(r, &["sepp-b-2076.example.com"]);
        let held = || {
            let ctx = sepp_self();
            let c = ctx.read().unwrap();
            let node = c.node_find(node_id).unwrap();
            (
                node.n32f_security.is_some(),
                node.negotiated_security_scheme,
            )
        };
        let before = held();
        assert!(before.0);
        // #2087: the context has SEQ state, as after its first message.
        crate::prins::seed_context_state("ctx-2076");
        assert!(crate::prins::context_state_len("ctx-2076") > 0);

        let capability = serde_json::json!({
            "sender": a, "supportedSecCapabilityList": ["PRINS"],
        })
        .to_string();
        let rsp = handle_exchange_capability(&capability, "cid", &from_b(HttpRequest::default()));
        assert_eq!(rsp.status, 403, "(1) {:?}", rsp.http.content);
        let params = serde_json::json!({ "sender": a, "n32fContextId": "evil" }).to_string();
        let rsp = handle_exchange_params(&params, None, "cid", &from_b(HttpRequest::default()));
        assert_eq!(rsp.status, 403, "(2) {:?}", rsp.http.content);
        let terminate = serde_json::json!({ "n32fContextId": "ctx-2076" }).to_string();
        let rsp = handle_n32f_terminate(&terminate, &from_b(HttpRequest::default()));
        // #2096: answered exactly as an unknown context, so it reveals nothing.
        let unknown = handle_n32f_terminate(
            &serde_json::json!({ "n32fContextId": "ctx-2076" })
                .to_string()
                .replace("ctx-2076", "ctx-2096-none"),
            &from_b(HttpRequest::default()),
        );
        assert_eq!(rsp.status, 404, "(3) {:?}", rsp.http.content);
        assert_eq!(unknown.status, 404);
        assert_eq!(
            rsp.http
                .content
                .as_deref()
                .map(|c| c.replace("ctx-2076", "ID")),
            unknown
                .http
                .content
                .as_deref()
                .map(|c| c.replace("ctx-2096-none", "ID")),
            "another peer's context is answered as an unknown one"
        );
        assert_eq!(held(), before, "nothing of A's changed");
        assert!(crate::prins::context_state_len("ctx-2076") > 0);

        // No verified certificate at all: refused under production (as unknown).
        if nextgcore_sbi::security::SbiProfile::resolve().is_production() {
            let rsp = handle_n32f_terminate(&terminate, &HttpRequest::default());
            assert_eq!(rsp.status, 404, "{:?}", rsp.http.content);
        }
        assert!(
            refuse_unbound_peer(&HttpRequest::default(), a, "probe").is_some()
                || !nextgcore_sbi::security::SbiProfile::resolve().is_production()
        );

        let rsp = handle_n32f_terminate(
            &terminate,
            &from_sepp(HttpRequest::default(), &["other.example.com", a]),
        );
        assert_eq!(rsp.status, 200, "{:?}", rsp.http.content);
        assert!(!held().0, "A's own terminate deletes its context");
        assert_eq!(
            crate::prins::context_state_len("ctx-2076"),
            0,
            "#2087: and its SEQ counters and replay windows"
        );
        assert!(refuse_unbound_peer(
            &from_sepp(HttpRequest::default(), &[a]),
            "SEPP-A-2076.example.com.",
            "probe"
        )
        .is_none());
    }

    #[test]
    fn test_select_peer_for_target() {
        ensure_ctx_initialized();
        {
            let ctx = sepp_self();
            let c = ctx.read().unwrap();
            let mut node = c.node_add("sepp-vplmn.example.com").unwrap();
            node.add_plmn_id(crate::context::PlmnId::new(310, 260, 3));
            c.node_update(&node);
        }
        // A VPLMN target resolves to the peer serving that PLMN.
        let node =
            select_peer_for_target("nrf.5gc.mnc260.mcc310.3gppnetwork.org").expect("peer found");
        assert_eq!(node.receiver, "sepp-vplmn.example.com");

        // A non-3gppnetwork target is not in a VPLMN.
        assert!(select_peer_for_target("nf.local.example.com").is_err());
        // A VPLMN with no peer SEPP errors.
        assert!(select_peer_for_target("nrf.5gc.mnc999.mcc999.3gppnetwork.org").is_err());
    }

    // ------------------------------------------------------------------
    // #1870: a peer-supplied N32-f target is https, in-PLMN, and TLS-dialled
    // ------------------------------------------------------------------

    const HOME: &str = "5gc.mnc070.mcc999.3gppnetwork.org";

    fn production_policy(allowed: &[&str]) -> N32fForwardPolicy {
        let mut policy = N32fForwardPolicy::new(
            SbiProfile::Production,
            vec![HOME.to_string()],
            allowed.iter().map(|s| s.to_string()).collect(),
        );
        policy.tls = TlsPaths {
            cert: "/tls/sepp/server.crt".to_string(),
            key: "/tls/sepp/server.key".to_string(),
            ca_cert: "/tls/ca/ca.crt".to_string(),
            client_cert: Some("/tls/sepp/client.crt".to_string()),
            client_key: Some("/tls/sepp/client.key".to_string()),
        };
        policy
    }

    fn reconstructed(target: &str, headers: &[(&str, &str)]) -> prins::ReconstructedRequest {
        let mut map: std::collections::HashMap<String, String> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        map.insert("3gpp-Sbi-Target-apiRoot".to_string(), target.to_string());
        prins::ReconstructedRequest {
            method: "GET".to_string(),
            url: "/nudm-sdm/v2/imsi-999700000000001/am-data".to_string(),
            headers: map,
            body: None,
            message_id: String::new(),
        }
    }

    /// A loopback listener nobody accepts on: any dial leaves a connection in
    /// its backlog, so `accept` afterwards says whether one was made.
    fn bare_listener() -> (std::net::TcpListener, std::net::SocketAddr) {
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        listener.set_nonblocking(true).unwrap();
        (listener, addr)
    }

    fn was_dialled(listener: &std::net::TcpListener) -> bool {
        !matches!(
            listener.accept().map(|_| ()).map_err(|e| e.kind()),
            Err(std::io::ErrorKind::WouldBlock)
        )
    }

    /// #1870: under production an http target is refused 400 and never dialled,
    /// even when its host is allowlisted.
    #[tokio::test]
    async fn production_refuses_an_http_target_without_dialling_it_1870() {
        let (listener, addr) = bare_listener();
        let rec = reconstructed(
            &format!("http://{addr}"),
            &[("authorization", "Bearer roaming-token")],
        );
        let (status, _, body) =
            forward_to_target_nf_under(&rec, &production_policy(&["127.0.0.1"])).await;
        assert_eq!(status, 400);
        let text = String::from_utf8(body.unwrap()).unwrap();
        assert!(text.contains("not https"), "{text}");
        assert!(
            !was_dialled(&listener),
            "an http target must not be dialled"
        );
    }

    /// #1870: under production an https target outside this PLMN, or one whose
    /// authority hides another host, is refused 400 and never dialled.
    #[tokio::test]
    async fn production_refuses_a_target_outside_the_plmn_1870() {
        let (listener, addr) = bare_listener();
        let port = addr.port();
        for target in [
            format!("https://127.0.0.1:{port}"),
            format!("https://udm.{HOME}@127.0.0.1:{port}"),
        ] {
            let rec = reconstructed(&target, &[]);
            let (status, _, _) = forward_to_target_nf_under(&rec, &production_policy(&[])).await;
            assert_eq!(status, 400, "{target} must be refused");
        }
        assert!(
            !was_dialled(&listener),
            "an out-of-PLMN target must not be dialled"
        );
    }

    /// #1870: which hosts the production policy admits.
    #[test]
    fn the_production_policy_admits_only_this_plmn_1870() {
        let p = production_policy(&[
            "10.0.0.5",
            "udr.internal:8443",
            ".core.example",
            "[fd00::5]:443",
        ]);
        assert!(p.admits(&format!("udm.{HOME}"), 443));
        // #1870 review: a home host, a bare-host entry or a suffix entry only on
        // the SBI port(s), never on any port.
        assert!(
            !p.admits(&format!("udm.{HOME}"), 22),
            "a home host's non-SBI port"
        );
        assert!(
            !p.admits("10.0.0.5", 6379),
            "a bare-host entry's non-SBI port"
        );
        assert!(
            !p.admits("ausf.core.example", 8080),
            "a suffix entry's non-SBI port"
        );
        let wider = production_policy(&[]).with_allowed_ports(vec![443, 7777]);
        assert!(wider.admits(&format!("udm.{HOME}"), 7777));
        assert!(p.admits(&format!("UDM.{}.", HOME.to_uppercase()), 443));
        assert!(p.admits("10.0.0.5", 443));
        assert!(p.admits("udr.internal", 8443));
        assert!(
            !p.admits("udr.internal", 8444),
            "a host:port entry pins the port"
        );
        assert!(p.admits("ausf.core.example", 443));
        assert!(p.admits("[fd00::5]", 443));
        assert!(!p.admits("[fd00::5]", 444));
        assert!(
            !p.admits(&format!("evil{HOME}"), 443),
            "a suffix matches on a label boundary"
        );
        assert!(
            !p.admits("udm.5gc.mnc071.mcc999.3gppnetwork.org", 443),
            "another PLMN"
        );
        assert!(!p.admits("evilcore.example", 443));
        assert_eq!(home_network_domain(&PlmnId::new(999, 70, 2)), HOME);
        // A host that ENDS like a home NF but is not a DNS name is refused
        // before the suffix match can admit it.
        let hidden = format!("https://127.0.0.1#.udm.{HOME}:443");
        assert!(
            p.client_for(&hidden)
                .is_err_and(|e| e.contains("malformed")),
            "{hidden} must be refused as malformed"
        );
    }

    /// #1870: an admitted target is dialled over https with the profile CA and
    /// this SEPP's client certificate; dev keeps the target's scheme and no TLS
    /// material.
    #[test]
    fn production_dials_an_admitted_target_with_mutual_tls_1870() {
        let client = production_policy(&[])
            .client_for(&format!("https://udm.{HOME}"))
            .expect("admitted on the default SBI port");
        assert!(
            production_policy(&[])
                .client_for(&format!("https://udm.{HOME}:8443"))
                .is_err(),
            "a home host off the allowed SBI ports is refused"
        );
        let config = client.config();
        assert_eq!(config.scheme, nextgcore_sbi::types::UriScheme::Https);
        assert_eq!(config.ca_cert.as_deref(), Some("/tls/ca/ca.crt"));
        assert_eq!(config.client_cert.as_deref(), Some("/tls/sepp/client.crt"));
        assert_eq!(config.client_key.as_deref(), Some("/tls/sepp/client.key"));

        let dev = N32fForwardPolicy::new(SbiProfile::Dev, Vec::new(), Vec::new())
            .client_for("http://127.0.0.1:7777")
            .expect("dev dials anything");
        assert_eq!(dev.config().scheme, nextgcore_sbi::types::UriScheme::Http);
        assert_eq!(dev.config().client_cert, None);
    }

    /// #1870: hop-by-hop fields, the ones `Connection` names, the N32 hop's
    /// proxy credentials and the routing header stay on this hop; the
    /// consumer's end-to-end `Authorization` reaches the producer
    /// (TS 33.501 §13.4.1.2).
    #[tokio::test]
    async fn hop_by_hop_headers_stay_on_the_n32_hop_1870() {
        let (_server, addr) =
            nextgcore_sbi::test_support::sbi_server_on_free_port(|req: HttpRequest| async move {
                let names: Vec<String> = req
                    .http
                    .headers
                    .keys()
                    .map(|k| k.to_ascii_lowercase())
                    .collect();
                HttpResponse::ok()
                    .with_body(serde_json::json!(names).to_string(), "application/json")
            })
            .await;
        let rec = reconstructed(
            &format!("http://{addr}"),
            &[
                ("authorization", "Bearer roaming-token"),
                ("connection", "x-hop-secret"),
                ("x-hop-secret", "n32-only"),
                ("proxy-authorization", "Basic c2VwcDpzZWNyZXQ="),
                ("keep-alive", "timeout=5"),
                ("3gpp-sbi-message-priority", "5"),
            ],
        );
        let dev = N32fForwardPolicy::new(SbiProfile::Dev, Vec::new(), Vec::new());
        let (status, _, body) = forward_to_target_nf_under(&rec, &dev).await;
        assert_eq!(status, 200);
        let names: Vec<String> = serde_json::from_slice(&body.unwrap()).unwrap();
        for kept in ["authorization", "3gpp-sbi-message-priority"] {
            assert!(
                names.contains(&kept.to_string()),
                "{kept} must reach the NF: {names:?}"
            );
        }
        for dropped in [
            "connection",
            "x-hop-secret",
            "proxy-authorization",
            "keep-alive",
            "3gpp-sbi-target-apiroot",
        ] {
            assert!(
                !names.contains(&dropped.to_string()),
                "{dropped} leaked: {names:?}"
            );
        }
    }

    /// #1870: a peer-SEPP client built with no TLS of its own (the n32f-error
    /// report, the SBI-side forward) presents the installed N32 client
    /// certificate on https.
    #[test]
    fn a_peer_sepp_call_without_its_own_tls_presents_the_installed_one_1870() {
        let _g = crate::context::lock_global_test_state();
        set_n32_client_tls(Some(N32TlsConfig {
            client_cert: Some("/tls/n32/client.crt".to_string()),
            client_key: Some("/tls/n32/client.key".to_string()),
            ca_cert: Some("/tls/n32/ca.crt".to_string()),
            ..Default::default()
        }));
        let client = n32_client("https://sepp.peer.example:443", None).unwrap();
        let config = client.config().clone();
        set_n32_client_tls(None);
        assert_eq!(config.client_cert.as_deref(), Some("/tls/n32/client.crt"));
        assert_eq!(config.ca_cert.as_deref(), Some("/tls/n32/ca.crt"));
    }

    /// The installed peer TLS for the two site tests: a client certificate that
    /// does not exist, so a dial that USES it fails naming it.
    fn install_missing_peer_cert() -> &'static str {
        const CERT: &str = "/nonexistent/h2-1870/peer-client.crt";
        set_n32_client_tls(Some(N32TlsConfig {
            client_cert: Some(CERT.to_string()),
            client_key: Some("/nonexistent/h2-1870/peer-client.key".to_string()),
            ca_cert: Some("/nonexistent/h2-1870/peer-ca.crt".to_string()),
            ..Default::default()
        }));
        CERT
    }

    /// #1870 / R26 MAJOR 2 on #1881: the N32-f error report to the peer SEPP is
    /// dialled with the SEPP's own client certificate.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // a std guard held to serialise globals, by design
    async fn the_n32f_error_report_presents_the_sepp_certificate_1870() {
        let _g = crate::context::lock_global_test_state();
        let cert = install_missing_peer_cert();
        let (_listener, addr) = bare_listener();
        let info = N32fErrorInfo {
            n32f_message_id: "m-1870".to_string(),
            n32f_error_type: N32fErrorType::IntegrityCheckFailed,
            failed_modification_list: Vec::new(),
            error_details_list: Vec::new(),
            n32f_context_id: None,
        };
        let err = send_n32f_error(&format!("https://{addr}"), &info)
            .await
            .unwrap_err();
        set_n32_client_tls(None);
        assert!(
            err.contains(cert),
            "the report must dial with the SEPP certificate: {err}"
        );
    }

    /// #1870 / R26 MAJOR 1 on #1881: forwarded roaming traffic (the SBI-side
    /// forward, which passes no TLS of its own) is dialled with the SEPP's own
    /// client certificate.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // a std guard held to serialise globals, by design
    async fn forwarded_roaming_traffic_presents_the_sepp_certificate_1870() {
        let _g = crate::context::lock_global_test_state();
        let cert = install_missing_peer_cert();
        let (_listener, addr) = bare_listener();
        let id = tls_peer_with_context("sepp-1870.peer.example", "ctx-1870");
        {
            let ctx = sepp_self();
            let c = ctx.read().unwrap();
            let mut node = c.node_find(id).unwrap();
            node.peer_api_root = Some(format!("https://{addr}"));
            c.node_update(&node);
        }
        let err = forward_via_n32f(id, "GET", "/nudm-sdm/v2/x/am-data", &[], None, None)
            .await
            .unwrap_err();
        set_n32_client_tls(None);
        assert!(
            err.contains(cert),
            "the forward must dial with the SEPP certificate: {err}"
        );
    }

    /// #1870 review: under production the forwarding TLS files must exist at
    /// startup, named when one does not; dev needs none. (The peer-SEPP files
    /// are #1881's `n32_peer_client_tls` check.)
    #[test]
    fn production_checks_the_tls_files_at_startup_1870() {
        let dir = std::env::temp_dir().join(format!(
            "h2-1870-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = |name: &str| {
            let p = dir.join(name);
            std::fs::write(&p, "pem").unwrap();
            p.to_string_lossy().into_owned()
        };
        let mut policy = production_policy(&[]);
        policy.tls.ca_cert = file("ca.crt");
        policy.tls.client_cert = Some(file("client.crt"));
        policy.tls.client_key = Some(file("client.key"));
        assert!(policy.check_files().is_ok());
        policy.tls.client_key = Some(dir.join("absent.key").to_string_lossy().into_owned());
        let err = policy.check_files().unwrap_err();
        assert!(err.contains("absent.key"), "{err}");
        let mut dev = policy.clone();
        dev.profile = SbiProfile::Dev;
        assert!(dev.check_files().is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }
    /// A self-signed `localhost` certificate written into `dir`, as
    /// `(key_path, cert_path)`; the cert is also the CA to trust it by.
    fn localhost_pem(dir: &std::path::Path) -> (String, String) {
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        let key_path = dir.join("localhost.key");
        let cert_path = dir.join("localhost.crt");
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        std::fs::write(&cert_path, cert.pem()).unwrap();
        (
            key_path.to_string_lossy().into_owned(),
            cert_path.to_string_lossy().into_owned(),
        )
    }

    /// A TLS SbiServer on a free port answering every request with `respond`,
    /// and a counter of the requests it received.
    async fn tls_target<F>(
        pem: &(String, String),
        respond: F,
    ) -> (
        nextgcore_sbi::server::SbiServer,
        std::net::SocketAddr,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    )
    where
        F: Fn() -> HttpResponse + Send + Sync + Clone + 'static,
    {
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = hits.clone();
        let (key, cert) = pem.clone();
        let (server, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port_with(
            |addr| SbiServerConfig::new(addr).with_tls(key, cert),
            move |_req: HttpRequest| {
                let respond = respond.clone();
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    respond()
                }
            },
        )
        .await;
        (server, addr, hits)
    }

    /// #1870 / #1915, R26's redirect MAJOR on #1901: an ADMITTED target that
    /// answers 307 with an off-PLMN Location, or with a cleartext one, does not
    /// bounce the roaming request (SUPI, bearer) there. Through the real
    /// `forward_to_target_nf_under` with the production policy, neither host
    /// sees so much as a TCP connection. The control, a redirect to another
    /// ADMITTED host, is followed and served, so the zeroes are the policy's.
    #[tokio::test]
    async fn a_redirect_from_an_admitted_target_to_off_plmn_is_not_followed_1870() {
        let dir = std::env::temp_dir().join(format!(
            "h2-1870-redir-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let pem = localhost_pem(&dir);
        let (off_plmn, off_addr) = bare_listener();
        let (cleartext, clear_addr) = bare_listener();
        let (_final, final_addr, final_hits) =
            tls_target(&pem, || HttpResponse::with_status(200)).await;

        for (location, followed) in [
            // Off-PLMN: 127.0.0.1 is no home host and not allowlisted.
            (
                format!("https://127.0.0.1:{}/nudm-sdm/v2/x", off_addr.port()),
                false,
            ),
            // Cleartext: http, whatever the host.
            (
                format!("http://localhost:{}/nudm-sdm/v2/x", clear_addr.port()),
                false,
            ),
            // Control: another admitted https host.
            (
                format!("https://localhost:{}/nudm-sdm/v2/x", final_addr.port()),
                true,
            ),
        ] {
            let loc = location.clone();
            let (_admitted, admitted_addr, admitted_hits) = tls_target(&pem, move || {
                HttpResponse::with_status(307).with_header("Location", loc.clone())
            })
            .await;
            let mut policy = production_policy(&[
                &format!("localhost:{}", admitted_addr.port()),
                &format!("localhost:{}", final_addr.port()),
            ]);
            policy.tls.ca_cert = pem.1.clone();
            policy.tls.client_cert = None;
            policy.tls.client_key = None;
            let rec = reconstructed(
                &format!("https://localhost:{}", admitted_addr.port()),
                &[("authorization", "Bearer roaming-token")],
            );
            let before = final_hits.load(std::sync::atomic::Ordering::SeqCst);
            let (status, _, body) = forward_to_target_nf_under(&rec, &policy).await;
            let text = body
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
            assert_eq!(
                admitted_hits.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "{location}: the admitted host was reached"
            );
            if followed {
                assert_eq!(status, 200, "{location}: followed and served: {text}");
                assert_eq!(
                    final_hits.load(std::sync::atomic::Ordering::SeqCst),
                    before + 1
                );
            } else {
                assert_ne!(status, 200, "{location}: not followed: {text}");
                assert!(text.contains("refused"), "{location}: refused: {text}");
            }
        }
        assert!(
            !was_dialled(&off_plmn),
            "the off-PLMN host must not be dialled"
        );
        assert!(
            !was_dialled(&cleartext),
            "the cleartext host must not be dialled"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// #1795: the SEPP's listeners follow the SBI security profile.
#[cfg(test)]
mod sbi_profile_tests_1795 {
    use super::{check_n32_transport, sbi_server_config, N32TlsConfig};
    use nextgcore_sbi::security::{SbiProfile, SbiSecurityPolicy, TlsPaths};
    use nextgcore_sbi::types::UriScheme;

    fn own_tls() -> N32TlsConfig {
        N32TlsConfig {
            cert: Some("/own.crt".into()),
            key: Some("/own.key".into()),
            verify_client_cacert: None,
            client_cert: None,
            client_key: None,
            ca_cert: None,
            allow_insecure_no_mtls: false,
        }
    }

    /// REVERT-VERIFIED: with `sbi_server_config` not applying the profile, the
    /// production case serves cleartext and the first assertion fails.
    #[test]
    fn the_sbi_listener_follows_the_sbi_profile_1795() {
        let dir = std::env::temp_dir().join(format!(
            "seppd-1795-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = |n: &str| {
            let p = dir.join(n);
            std::fs::write(&p, "pem").unwrap();
            p.display().to_string()
        };
        let policy = SbiSecurityPolicy {
            tls_paths: TlsPaths {
                cert: file("sepp.crt"),
                key: file("sepp.key"),
                ca_cert: file("ca.crt"),
                client_cert: Some(file("client.crt")),
                client_key: Some(file("client.key")),
            },
            ..SbiSecurityPolicy::production()
        };
        let tls = own_tls();
        for given in [None, Some(&tls)] {
            let prod = sbi_server_config("127.0.0.1", 7777, given, SbiProfile::Production, &policy)
                .expect("production applies");
            assert_eq!(prod.scheme, UriScheme::Https, "production serves TLS");
            assert_eq!(prod.cert.as_deref(), Some(policy.tls_paths.cert.as_str()));
            assert!(prod.verify_client, "and verifies the client certificate");
            assert_eq!(
                prod.verify_client_cacert.as_deref(),
                Some(policy.tls_paths.ca_cert.as_str())
            );
            assert!(
                !prod.require_oauth2,
                "a roaming request carries the remote producer's token, not one for the SEPP"
            );
        }

        let missing = SbiSecurityPolicy {
            tls_paths: TlsPaths {
                cert: dir.join("absent.crt").display().to_string(),
                ..policy.tls_paths.clone()
            },
            ..SbiSecurityPolicy::production()
        };
        let err = sbi_server_config("127.0.0.1", 7777, None, SbiProfile::Production, &missing)
            .expect_err("no cleartext fallback");
        assert!(err.contains("absent.crt"), "{err}");

        let dev = sbi_server_config("127.0.0.1", 7777, None, SbiProfile::Dev, &policy).unwrap();
        assert_eq!(dev.scheme, UriScheme::Http, "dev stays cleartext");
        let dev_tls =
            sbi_server_config("127.0.0.1", 7777, Some(&tls), SbiProfile::Dev, &policy).unwrap();
        assert_eq!(dev_tls.cert.as_deref(), Some("/own.crt"), "dev keeps --tls");
        assert!(!dev_tls.verify_client);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// REVERT-VERIFIED: with the production arm of `check_n32_transport`
    /// removed, a cleartext N32 is admitted under production and this fails.
    #[test]
    fn n32_is_never_cleartext_under_production_1795() {
        let err = check_n32_transport(SbiProfile::Production, None)
            .expect_err("a cleartext N32 is refused under production");
        assert!(err.contains("TS 33.501 §13.2.1"), "{err}");
        check_n32_transport(SbiProfile::Production, Some(&own_tls()))
            .expect("N32 with TLS is admitted");
        check_n32_transport(SbiProfile::Dev, None).expect("dev keeps its cleartext N32");
    }
}
