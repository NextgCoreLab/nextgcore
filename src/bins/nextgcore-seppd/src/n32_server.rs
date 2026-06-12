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
//! rustls plumbing in ogs-sbi.

use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use ogs_sbi::message::{SbiRequest as HttpRequest, SbiResponse as HttpResponse};
use ogs_sbi::server::{send_error, SbiServer, SbiServerConfig};

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
}

/// Start the N32 listener. Returns the server handle (caller stops it).
pub async fn start_n32_listener(
    host: &str,
    port: u16,
    tls: Option<&N32TlsConfig>,
) -> Result<SbiServer, String> {
    let mut config =
        SbiServerConfig::with_host_port(host, port).map_err(|e| e.to_string())?;
    config = config.with_interface("n32");

    if let Some(tls_cfg) = tls {
        if let (Some(key), Some(cert)) = (&tls_cfg.key, &tls_cfg.cert) {
            config = config.with_tls(key.clone(), cert.clone());
            if let Some(ca) = &tls_cfg.verify_client_cacert {
                // mTLS on N32-c/N32-f: require and verify peer-SEPP client certs
                config.verify_client = true;
                config.verify_client_cacert = Some(ca.clone());
            }
        }
    }

    let server = SbiServer::new(config);
    server
        .start(n32_request_handler)
        .await
        .map_err(|e| format!("N32 listener start failed: {e}"))?;
    log::info!("N32 listener on {host}:{port} (mTLS={})",
        tls.is_some_and(|t| t.verify_client_cacert.is_some()));
    Ok(server)
}

/// Top-level N32 request router
async fn n32_request_handler(request: HttpRequest) -> HttpResponse {
    let method = request.header.method.clone();
    let path = request.header.uri.clone();
    let body = request.http.content.clone().unwrap_or_default();

    log::debug!("N32 request: {method} {path} ({}B)", body.len());

    match (method.as_str(), path.as_str()) {
        ("POST", "/n32c-handshake/v1/exchange-capability") => {
            handle_exchange_capability(&body)
        }
        ("POST", "/n32c-handshake/v1/exchange-params") => handle_exchange_params(&body),
        ("POST", "/n32c-handshake/v1/n32f-error") => handle_n32f_error_report(&body),
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
        target_apiroot_supported: j.target_apiroot_supported == Some(1),
        plmn_id_list: j.plmn_id_list.iter().map(plmn_from_json).collect(),
        target_plmn_id: j.target_plmn_id.as_ref().map(plmn_from_json),
        supported_features: j.supported_features.clone(),
    }
}

fn rsp_data_from_json(j: &SecurityCapabilityResponseJson) -> SecNegotiateRspData {
    SecNegotiateRspData {
        sender: j.sender.clone(),
        selected_sec_capability: SecurityCapability::from_string(&j.selected_sec_capability),
        target_apiroot_supported: j.target_apiroot_supported == Some(1),
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

fn handle_exchange_capability(body: &str) -> HttpResponse {
    let json: SecurityCapabilityRequestJson = match serde_json::from_str(body) {
        Ok(j) => j,
        Err(e) => {
            return send_error(
                400,
                "Bad Request",
                &format!("Malformed SecNegotiateReqData: {e}"),
                Some("MANDATORY_IE_INCORRECT"),
            )
        }
    };
    let req_data = req_data_from_json(&json);

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
            log::warn!("exchange-capability rejected: {e}");
            send_error(
                400,
                "Bad Request",
                &e,
                Some("NEGOTIATION_NOT_ALLOWED"),
            )
        }
    }
}

fn handle_exchange_params(body: &str) -> HttpResponse {
    let req: SecParamExchReqData = match serde_json::from_str(body) {
        Ok(j) => j,
        Err(e) => {
            return send_error(
                400,
                "Bad Request",
                &format!("Malformed SecParamExchReqData: {e}"),
                Some("MANDATORY_IE_INCORRECT"),
            )
        }
    };

    let mut node = match find_or_add_node(&req.sender) {
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

    match n32c_handler::handle_exchange_params_request(&mut node, &req) {
        Ok(rsp) => {
            node.handshake_state = crate::handshake_sm::HandshakeState::Established;
            update_node(&node);
            HttpResponse::ok()
                .with_json_body(&rsp)
                .unwrap_or_else(|_| HttpResponse::internal_error())
        }
        Err(e) => {
            log::warn!("exchange-params rejected: {e}");
            send_error(400, "Bad Request", &e, Some("NEGOTIATION_NOT_ALLOWED"))
        }
    }
}

/// Received n32f-error reports (consumed: logged, counted, and inspectable)
static RECEIVED_N32F_ERRORS: LazyLock<Mutex<Vec<N32fErrorInfo>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// Drain the received n32f-error reports (used by operators/tests)
pub fn take_received_n32f_errors() -> Vec<N32fErrorInfo> {
    RECEIVED_N32F_ERRORS
        .lock()
        .map(|mut v| std::mem::take(&mut *v))
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
        v.push(info);
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
                let headers = msg
                    .header
                    .iter()
                    .map(|h| (h.name.clone(), h.value.clone()))
                    .collect();
                let rec = ReconstructedRequestJson {
                    method: msg.request_line.method,
                    url: msg.request_line.url,
                    headers,
                    body: msg.payload,
                    message_id: None,
                };
                log::info!("N32-f TLS-mode message accepted: {} {}", rec.method, rec.url);
                HttpResponse::ok()
                    .with_json_body(&rec)
                    .unwrap_or_else(|_| HttpResponse::internal_error())
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
        log::error!(
            "N32-f PRINS message for unknown context [{:?}]",
            context_id
        );
        return send_error(
            400,
            "Bad Request",
            "Unknown n32fContextId",
            Some("UNAVAILABLE_PRINS_CONTEXT"),
        );
    };

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
            let rec_json = ReconstructedRequestJson {
                method: rec.method,
                url: rec.url,
                headers: rec.headers,
                body: rec.body.as_deref().map(crate::jose::b64url_encode),
                message_id: Some(rec.message_id),
            };
            log::info!(
                "N32-f PRINS message verified: {} {}",
                rec_json.method,
                rec_json.url
            );
            HttpResponse::ok()
                .with_json_body(&rec_json)
                .unwrap_or_else(|_| HttpResponse::internal_error())
        }
        Err(e) => {
            log::error!("N32-f PRINS verification failed: {e}");

            // Produce the n32f-error report towards the sending SEPP
            let info = e.to_error_info();
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

fn n32_client(api_root: &str, tls: Option<&N32TlsConfig>) -> Result<ogs_sbi::client::SbiClient, String> {
    let (https, host, port) = parse_api_root(api_root)?;
    let mut config = ogs_sbi::client::SbiClientConfig::new(&host, port)
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
    Ok(ogs_sbi::client::SbiClient::new(config))
}

async fn post_json(
    client: &ogs_sbi::client::SbiClient,
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
    let (status, body) = post_json(
        &client,
        "/n32c-handshake/v1/exchange-capability",
        req_json,
    )
    .await?;
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
            let params_req = SecParamExchReqData {
                sender: local_sender,
                n32f_context_id: prins::generate_n32f_context_id(),
                jwe_cipher_suite_list: n32c_handler::SUPPORTED_JWE_SUITES
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                jws_cipher_suite_list: n32c_handler::SUPPORTED_JWS_SUITES
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                modification_policy_allowed_paths: Vec::new(),
                key_nonce: n32c_handler::generate_key_nonce(),
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
            let msg = crate::n32c_build::build_n32f_tls_message(method, url, headers, body);
            serde_json::to_string(&msg).map_err(|e| e.to_string())?
        }
        other => return Err(format!("No N32-f security established ({other:?})")),
    };

    let client = n32_client(&api_root, tls)?;
    post_json(&client, "/n32f-forward/v1/n32f-process", n32f_body).await
}

/// POST an N32fErrorInfo report to the peer SEPP (TS 29.573 sec 6.1.5.4)
pub async fn send_n32f_error(
    peer_api_root: &str,
    info: &N32fErrorInfo,
) -> Result<(), String> {
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
        // Verify the TLS/mTLS knobs map through to the ogs-sbi config
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

        assert_eq!(config.scheme, ogs_sbi::types::UriScheme::Https);
        assert!(config.verify_client);
        assert_eq!(config.verify_client_cacert.as_deref(), Some("/tls/ca.crt"));
    }
}
