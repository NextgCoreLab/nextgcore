//! NextGCore NRF (Network Repository Function)
//!
//! The NRF is a 5G core network function responsible for:
//! - NF registration and deregistration
//! - NF discovery
//! - NF status notifications
//! - Subscription management

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_nrfd::{
    apply_json_patch, discover_profiles, json_merge_patch, nf_manager, nrf_context_final,
    nrf_context_init, nrf_nnrf_nfm_send_nf_status_notify_all_async, nrf_sbi_close, nrf_sbi_open,
    timer_manager, DiscoveryQuery, NfProfile, NotificationEventType, NrfSmContext, PatchError,
    SbiServerConfig,
};
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::oauth::AccessTokenResponse;
use ogs_sbi::server::{
    send_bad_request, send_error, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as OgsSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Per-process ES256 (ECDSA P-256) signing key, generated once at startup.
/// Asymmetric so consumers can verify tokens with the public key (published via
/// JWKS in a later stage) without sharing a secret.
static NRF_SIGNING_KEY: OnceLock<p256::ecdsa::SigningKey> = OnceLock::new();

/// Key id advertised in the JWT header and (later) the JWKS document.
const NRF_KID: &str = "nrf-es256";

/// The NRF's own SBI URI, set once at startup from CLI args.
static NRF_SELF_URI: OnceLock<String> = OnceLock::new();

/// The NRF's own NF Instance ID (UUID). Used as the OAuth2 `iss` claim per
/// TS 29.510 §6.3.5.2.4 (issuer = NF Instance ID of the NRF). Set from
/// `--nf-instance-id` at startup; auto-generated otherwise.
static NRF_INSTANCE_ID: OnceLock<String> = OnceLock::new();

fn nrf_instance_id() -> &'static str {
    NRF_INSTANCE_ID.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

fn nrf_self_uri() -> &'static str {
    NRF_SELF_URI
        .get()
        .map(|s| s.as_str())
        .unwrap_or("http://127.0.0.1:7777")
}

/// Decodes percent-encoding (and `+` as space) in a query parameter value.
/// Discovery parameters like `snssais` and `target-plmn-list` carry JSON in
/// the query string (TS 29.510 §6.2.3.2.3.1, content: application/json).
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn nrf_signing_key() -> &'static p256::ecdsa::SigningKey {
    NRF_SIGNING_KEY.get_or_init(|| {
        use rand::Rng;
        // Draw a random scalar; reject the (vanishingly rare) invalid ones.
        loop {
            let bytes = rand::rng().random::<[u8; 32]>();
            if let Ok(sk) = p256::ecdsa::SigningKey::from_slice(&bytes) {
                break sk;
            }
        }
    })
}

/// NextGCore NRF - Network Repository Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-nrfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Network Repository Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/nrf.yaml")]
    config: String,

    /// Log file path
    #[arg(short = 'l', long)]
    log_file: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'e', long, default_value = "info")]
    log_level: String,

    /// Disable color output
    #[arg(short = 'm', long)]
    no_color: bool,

    /// Kill running instance
    #[arg(short = 'k', long)]
    kill: bool,

    /// SBI server address
    #[arg(long, default_value = "0.0.0.0")]
    sbi_addr: String,

    /// SBI server port
    #[arg(long, default_value = "7777")]
    sbi_port: u16,

    /// Enable TLS
    #[arg(long)]
    tls: bool,

    /// TLS certificate path
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS key path
    #[arg(long)]
    tls_key: Option<String>,

    /// Enable mTLS (require client certificates)
    #[arg(long)]
    mtls: bool,

    /// CA certificate for client verification (mTLS)
    #[arg(long)]
    tls_ca_cert: Option<String>,

    /// Maximum number of UEs
    #[arg(long, default_value = "1024")]
    max_ue: usize,

    /// NF Instance ID of this NRF (UUID, used as OAuth2 token issuer).
    /// Auto-generated when not given.
    #[arg(long)]
    nf_instance_id: Option<String>,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Active NfInstanceNoHeartbeat timer id per NF instance.
///
/// get_expired_events() fires every timer left in the manager, so a heartbeat
/// refresh must DELETE the superseded expiry timer — merely starting a new one
/// leaves the old timer armed and the NF gets suspended on schedule regardless
/// of heartbeats.
static HEARTBEAT_TIMERS: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, u64>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Arm (or re-arm) the no-heartbeat expiry timer for an NF instance,
/// cancelling any previously armed timer for the same instance.
fn arm_heartbeat_timer(nf_instance_id: &str, expiry: Duration) {
    let timer_mgr = timer_manager();
    let new_id = timer_mgr.start_timer(
        nextgcore_nrfd::NrfTimerId::NfInstanceNoHeartbeat,
        expiry,
        nf_instance_id.to_string(),
    );
    if let Ok(mut timers) = HEARTBEAT_TIMERS.lock() {
        let old = match new_id {
            Some(id) => timers.insert(nf_instance_id.to_string(), id),
            None => timers.remove(nf_instance_id),
        };
        if let Some(old_id) = old {
            timer_mgr.delete_timer(old_id);
        }
    }
}

/// Cancel the no-heartbeat expiry timer for an NF instance (deregistration).
fn disarm_heartbeat_timer(nf_instance_id: &str) {
    if let Ok(mut timers) = HEARTBEAT_TIMERS.lock() {
        if let Some(old_id) = timers.remove(nf_instance_id) {
            timer_manager().delete_timer(old_id);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = ogs_metrics::otel::init_otel(
        ogs_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();

    log::info!("NextGCore NRF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize NRF context
    nrf_context_init(args.max_ue);
    log::info!("NRF context initialized (max_ue={})", args.max_ue);

    // Store the NRF's own SBI URI so notification handlers can use it
    let scheme = if args.tls { "https" } else { "http" };
    let self_uri = format!("{}://{}:{}", scheme, args.sbi_addr, args.sbi_port);
    NRF_SELF_URI.set(self_uri).ok();

    // The NRF's NF Instance ID is the OAuth2 token issuer (TS 29.510
    // §6.3.5.2.4): configured UUID or generated per process.
    if let Some(ref id) = args.nf_instance_id {
        NRF_INSTANCE_ID.set(id.clone()).ok();
    }
    log::info!("NRF NF Instance ID: {}", nrf_instance_id());

    // Initialize NRF state machine
    let mut nrf_sm = NrfSmContext::new();
    nrf_sm.init();
    log::info!("NRF state machine initialized");

    // Parse configuration (if file exists)
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
            }
            Err(e) => {
                log::warn!("Failed to read configuration file: {e}");
            }
        }
    } else {
        log::debug!("Configuration file not found: {}", args.config);
    }

    // Build SBI server configuration (legacy, for context)
    let sbi_config = SbiServerConfig {
        addr: args.sbi_addr.clone(),
        port: args.sbi_port,
        tls_enabled: args.tls,
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
    };

    // Open legacy SBI server (for context initialization)
    let _server = nrf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using ogs-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let mut sbi_server_config = OgsSbiServerConfig::new(sbi_addr);

    // Wire TLS/mTLS configuration from CLI args into the ogs-sbi server
    if args.tls {
        let cert = args
            .tls_cert
            .as_deref()
            .unwrap_or("/etc/nextgcore/tls/server.crt");
        let key = args
            .tls_key
            .as_deref()
            .unwrap_or("/etc/nextgcore/tls/server.key");
        sbi_server_config = sbi_server_config.with_tls(key, cert);
        log::info!("TLS enabled: cert={cert}, key={key}");

        if args.mtls {
            let ca = args
                .tls_ca_cert
                .as_deref()
                .unwrap_or("/etc/nextgcore/tls/ca.crt");
            sbi_server_config.verify_client = true;
            sbi_server_config.verify_client_cacert = Some(ca.to_string());
            log::info!("mTLS enabled: client CA={ca}");
        }
    }

    let sbi_server = SbiServer::new(sbi_server_config);

    sbi_server
        .start(nrf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    let scheme = if args.tls { "HTTPS" } else { "HTTP" };
    log::info!("SBI HTTP/2 {scheme} server listening on {sbi_addr}");
    log::info!("NextGCore NRF ready");

    // Main event loop (async)
    run_event_loop_async(&mut nrf_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    log::info!("SBI HTTP/2 server stopped");

    // Close legacy SBI server
    nrf_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    nrf_sm.fini();
    log::info!("NRF state machine finalized");

    // Cleanup context
    nrf_context_final();
    log::info!("NRF context finalized");

    log::info!("NextGCore NRF stopped");
    Ok(())
}

/// SBI request handler for NRF
async fn nrf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("NRF SBI request: {method} {uri}");

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Route based on service and resource
    // Expected paths:
    // - /nnrf-nfm/v1/nf-instances/{nfInstanceId}
    // - /nnrf-nfm/v1/subscriptions/{subscriptionId}
    // - /nnrf-disc/v1/nf-instances

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];
    let resource = parts[2];

    match (service, resource, method) {
        // NF Management Service (nnrf-nfm)
        ("nnrf-nfm", "nf-instances", "PUT") if parts.len() >= 4 => {
            // NF Register/Update: PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId}
            let nf_instance_id = parts[3];
            handle_nf_register(nf_instance_id, &request).await
        }
        ("nnrf-nfm", "nf-instances", "GET") if parts.len() >= 4 => {
            // NF Profile Retrieval: GET /nnrf-nfm/v1/nf-instances/{nfInstanceId}
            let nf_instance_id = parts[3];
            handle_nf_profile_retrieval(nf_instance_id).await
        }
        ("nnrf-nfm", "nf-instances", "DELETE") if parts.len() >= 4 => {
            // NF Deregister: DELETE /nnrf-nfm/v1/nf-instances/{nfInstanceId}
            let nf_instance_id = parts[3];
            handle_nf_deregister(nf_instance_id).await
        }
        ("nnrf-nfm", "nf-instances", "PATCH") if parts.len() >= 4 => {
            // NF Update: PATCH /nnrf-nfm/v1/nf-instances/{nfInstanceId}
            let nf_instance_id = parts[3];
            handle_nf_update(nf_instance_id, &request).await
        }
        ("nnrf-nfm", "nf-instances", "GET") => {
            // NF List Retrieval: GET /nnrf-nfm/v1/nf-instances
            handle_nf_list_retrieval(&request).await
        }

        // Subscriptions
        ("nnrf-nfm", "subscriptions", "POST") => {
            // Subscribe: POST /nnrf-nfm/v1/subscriptions
            handle_subscription_create(&request).await
        }
        ("nnrf-nfm", "subscriptions", "DELETE") if parts.len() >= 4 => {
            // Unsubscribe: DELETE /nnrf-nfm/v1/subscriptions/{subscriptionId}
            let subscription_id = parts[3];
            handle_subscription_delete(subscription_id).await
        }
        ("nnrf-nfm", "subscriptions", "PATCH") if parts.len() >= 4 => {
            // Update subscription: PATCH /nnrf-nfm/v1/subscriptions/{subscriptionId}
            let subscription_id = parts[3];
            handle_subscription_update(subscription_id, &request).await
        }

        // NF Discovery Service (nnrf-disc)
        ("nnrf-disc", "nf-instances", "GET") => {
            // NF Discovery: GET /nnrf-disc/v1/nf-instances?target-nf-type=...&requester-nf-type=...
            handle_nf_discover(&request).await
        }

        // OAuth2 Access Token Service (nnrf-oauth2)
        ("nnrf-oauth2", "access-token", "POST") => {
            // Access Token Request: POST /nnrf-oauth2/v1/access-token
            handle_access_token_request(&request).await
        }
        // JWKS: GET /nnrf-oauth2/v1/jwks — publishes the ES256 public key so
        // consumers can verify access tokens (no shared secret needed).
        ("nnrf-oauth2", "jwks", "GET") => handle_jwks(),

        _ => {
            log::warn!("Unknown NRF request: {method} {uri}");
            send_method_not_allowed(method, uri)
        }
    }
}

/// Handle NF Register request
async fn handle_nf_register(nf_instance_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("NF Register: {nf_instance_id}");

    // Parse the NF profile from request body
    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    // Parse as NfProfile
    let profile: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // Mandatory attribute validation (TS 29.510 Table 6.1.6.2.2-1:
    // nfInstanceId, nfType, nfStatus) -> 400 ProblemDetails.
    let nf_profile = match NfProfile::from_json(&profile) {
        Ok(p) => p,
        Err(missing) => {
            return send_bad_request(
                &format!("Missing mandatory NFProfile attribute(s): {}", missing.join(", ")),
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    // The nfInstanceId in the body must match the resource URI (TS 29.510
    // §5.2.2.2.1: the NF registers under its own NF Instance ID).
    if nf_profile.nf_instance_id != nf_instance_id {
        return send_bad_request(
            &format!(
                "Body nfInstanceId {:?} does not match resource URI {:?}",
                nf_profile.nf_instance_id, nf_instance_id
            ),
            Some("MANDATORY_IE_INCORRECT"),
        );
    }

    let nf_type = nf_profile.nf_type.clone();
    let heartbeat_timer = nf_profile.heartbeat_timer;
    let manager = nf_manager();
    // 201 Created on first registration, 200 OK on profile replacement
    // (TS 29.510 PUT response codes).
    let is_new = manager.get(nf_instance_id).is_none();

    match manager.register(nf_profile.clone()) {
        Ok(_) => {
            log::info!("NF {nf_instance_id} ({nf_type}) registered successfully");

            // Start heartbeat expiry timer if NF has heartBeatTimer
            if let Some(hb_timer) = heartbeat_timer {
                // Use 2x heartbeat interval as tolerance before declaring missed heartbeat
                let expiry_secs = (hb_timer as u64) * 2;
                arm_heartbeat_timer(nf_instance_id, Duration::from_secs(expiry_secs));
                log::info!(
                    "Heartbeat timer started for NF {nf_instance_id} ({expiry_secs} seconds, 2x {hb_timer}s interval)"
                );
            }

            // Send NF status notifications to all matching subscribers
            let notify_profile = nf_profile.clone();
            let server_uri = nrf_self_uri().to_string();
            tokio::spawn(async move {
                if let Err(e) = nrf_nnrf_nfm_send_nf_status_notify_all_async(
                    NotificationEventType::NfRegistered,
                    &notify_profile,
                    &server_uri,
                )
                .await
                {
                    log::error!("Failed to send NF_REGISTERED notifications: {e}");
                }
            });

            // 201 Created (Location header mandatory) or 200 OK, both with the
            // full stored NF profile.
            let status = if is_new { 201 } else { 200 };
            let response = SbiResponse::with_status(status);
            let response = if is_new {
                response.with_header(
                    "Location",
                    format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}"),
                )
            } else {
                response
            };
            response
                .with_json_body(&nf_profile.to_json())
                .unwrap_or_else(|_| SbiResponse::with_status(status))
        }
        Err(e) => {
            log::error!("Failed to register NF {nf_instance_id}: {e}");
            send_error(500, "Internal Server Error", &e, Some("SYSTEM_FAILURE"))
        }
    }
}

/// Handle NF Profile Retrieval request
async fn handle_nf_profile_retrieval(nf_instance_id: &str) -> SbiResponse {
    log::debug!("NF Profile Retrieval: {nf_instance_id}");

    let manager = nf_manager();

    match manager.get(nf_instance_id) {
        // Return the complete stored NFProfile (TS 29.510 GetNFInstance:
        // 200 OK with NFProfile) — full register -> GET fidelity.
        Some(profile) => SbiResponse::with_status(200)
            .with_json_body(&profile.to_json())
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("NF instance {nf_instance_id} not found"),
            Some("NF_NOT_FOUND"),
        ),
    }
}

/// Handle NF Deregister request
async fn handle_nf_deregister(nf_instance_id: &str) -> SbiResponse {
    log::info!("NF Deregister: {nf_instance_id}");

    let manager = nf_manager();

    // Fetch the profile before deregistering so we can notify subscribers
    let profile_for_notify = manager.get(nf_instance_id);

    match manager.deregister(nf_instance_id) {
        Ok(_) => {
            log::info!("NF {nf_instance_id} deregistered successfully");
            disarm_heartbeat_timer(nf_instance_id);

            // Send NF_DEREGISTERED notifications to matching subscribers
            if let Some(profile) = profile_for_notify {
                let server_uri = nrf_self_uri().to_string();
                tokio::spawn(async move {
                    if let Err(e) = nrf_nnrf_nfm_send_nf_status_notify_all_async(
                        NotificationEventType::NfDeregistered,
                        &profile,
                        &server_uri,
                    )
                    .await
                    {
                        log::error!("Failed to send NF_DEREGISTERED notifications: {e}");
                    }
                });
            }

            SbiResponse::with_status(204) // No Content
        }
        Err(e) => {
            log::error!("Failed to deregister NF {nf_instance_id}: {e}");
            send_not_found(&e, Some("NF_NOT_FOUND"))
        }
    }
}

/// Handle NF Update request (PATCH)
///
/// TS 29.510 §5.2.2.3 mandates `application/json-patch+json` (RFC 6902
/// PatchItem array) for NFUpdate. `application/merge-patch+json` (RFC 7396)
/// is additionally accepted for lenient peers; bodies without a recognized
/// content type are dispatched on shape (array => JSON Patch, object =>
/// merge patch). Success returns 200 OK with the full updated NFProfile
/// (TS 29.510 also allows 204; we return the profile for visibility).
/// A failed RFC 6902 `test` op maps to 409 Conflict (RFC 5789 §2.2);
/// malformed/inapplicable patches map to 400 ProblemDetails.
async fn handle_nf_update(nf_instance_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("NF Update: {nf_instance_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let patch: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let manager = nf_manager();

    // Copy the stored profile out; no lock is held during patch application.
    let profile = match manager.get(nf_instance_id) {
        Some(p) => p,
        None => {
            return send_not_found(
                &format!("NF instance {nf_instance_id} not found"),
                Some("NF_NOT_FOUND"),
            )
        }
    };

    // Apply the patch to a copy of the full stored document.
    let mut doc = profile.to_json();
    let content_type = request
        .http
        .get_header("content-type")
        .cloned()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let patch_result = if content_type.contains("json-patch+json") {
        apply_json_patch(&mut doc, &patch)
    } else if content_type.contains("merge-patch+json") {
        json_merge_patch(&mut doc, &patch);
        Ok(())
    } else if patch.is_array() {
        apply_json_patch(&mut doc, &patch)
    } else {
        json_merge_patch(&mut doc, &patch);
        Ok(())
    };

    match patch_result {
        Ok(()) => {}
        Err(PatchError::TestFailed(msg)) => {
            return send_error(409, "Conflict", &msg, Some("PATCH_TEST_FAILED"))
        }
        Err(PatchError::Malformed(msg)) => {
            return send_bad_request(&msg, Some("INVALID_MSG_FORMAT"))
        }
    }

    // The patched document must still be a valid NFProfile with the same
    // identity (nfInstanceId is read-only for the resource).
    let updated = match NfProfile::from_json(&doc) {
        Ok(p) => p,
        Err(missing) => {
            return send_bad_request(
                &format!(
                    "Patch removes mandatory NFProfile attribute(s): {}",
                    missing.join(", ")
                ),
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };
    if updated.nf_instance_id != nf_instance_id {
        return send_bad_request(
            "Patch must not change nfInstanceId",
            Some("MANDATORY_IE_INCORRECT"),
        );
    }

    if let Err(e) = manager.register(updated.clone()) {
        log::error!("Failed to store patched NF profile {nf_instance_id}: {e}");
        return send_error(500, "Internal Server Error", &e, Some("SYSTEM_FAILURE"));
    }

    // Refresh heartbeat timer on any PATCH (serves as heartbeat, TS 29.510
    // §5.2.2.3.2) using the updated heartBeatTimer value.
    if let Some(hb_timer) = updated.heartbeat_timer {
        let expiry_secs = (hb_timer as u64) * 2;
        arm_heartbeat_timer(nf_instance_id, Duration::from_secs(expiry_secs));
        log::debug!("Heartbeat timer refreshed for NF {nf_instance_id} ({expiry_secs}s)");
    }

    // A heartbeat on a SUSPENDED NF restores it to REGISTERED (TS 29.510)
    if manager.reactivate(nf_instance_id) {
        log::info!("NF {nf_instance_id} heartbeat received while SUSPENDED, back to REGISTERED");
    }

    // Re-read so the response reflects the live nfStatus after reactivation.
    let response_doc = manager
        .get(nf_instance_id)
        .map(|p| p.to_json())
        .unwrap_or_else(|| updated.to_json());

    SbiResponse::with_status(200)
        .with_json_body(&response_doc)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Handle NF List Retrieval request
async fn handle_nf_list_retrieval(_request: &SbiRequest) -> SbiResponse {
    log::debug!("NF List Retrieval");

    let manager = nf_manager();

    let instances: Vec<String> = manager
        .list()
        .iter()
        .map(|p| p.nf_instance_id.clone())
        .collect();

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "_links": {
                "self": "/nnrf-nfm/v1/nf-instances",
                "items": instances.iter().map(|id| format!("/nnrf-nfm/v1/nf-instances/{id}")).collect::<Vec<_>>()
            }
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Handle Subscription Create request
async fn handle_subscription_create(request: &SbiRequest) -> SbiResponse {
    log::info!("Subscription Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let subscription: serde_json::Value = match serde_json::from_str(body) {
        Ok(s) => s,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // Extract notification URI (required field)
    let notification_uri = match subscription
        .get("nfStatusNotificationUri")
        .and_then(|v| v.as_str())
    {
        Some(uri) => uri.to_string(),
        None => {
            return send_bad_request(
                "Missing nfStatusNotificationUri",
                Some("MISSING_NOTIFY_URI"),
            )
        }
    };

    // Generate subscription ID
    let subscription_id = uuid::Uuid::new_v4().to_string();

    // Parse subscription condition
    let subscr_cond =
        subscription
            .get("subscrCond")
            .map(|cond| nextgcore_nrfd::nnrf_handler::SubscrCond {
                nf_type: cond
                    .get("nfType")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                service_name: cond
                    .get("serviceName")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                nf_instance_id: cond
                    .get("nfInstanceId")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            });

    // Parse validity duration (default 86400 seconds = 24 hours)
    let validity_duration = subscription
        .get("validityTime")
        .and_then(|v| v.as_u64())
        .unwrap_or(86400);

    // Build subscription data
    let subscription_data = nextgcore_nrfd::SubscriptionData {
        id: subscription_id.clone(),
        req_nf_type: subscription
            .get("reqNfType")
            .and_then(|v| v.as_str())
            .map(String::from),
        req_nf_instance_id: subscription
            .get("reqNfInstanceId")
            .and_then(|v| v.as_str())
            .map(String::from),
        notification_uri,
        subscr_cond,
        validity_duration,
    };

    // Store the subscription in the manager
    let manager = nf_manager();
    manager.add_subscription(subscription_data);

    // Start a subscription validity timer
    let timer_mgr = timer_manager();
    timer_mgr.start_timer(
        nextgcore_nrfd::NrfTimerId::SubscriptionValidity,
        Duration::from_secs(validity_duration),
        subscription_id.clone(),
    );

    log::info!("Created subscription: {subscription_id} (validity={validity_duration}s)");

    // Return 201 Created
    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/nnrf-nfm/v1/subscriptions/{subscription_id}"),
        )
        .with_json_body(&serde_json::json!({
            "subscriptionId": subscription_id,
            "nfStatusNotificationUri": subscription.get("nfStatusNotificationUri"),
            "validityTime": subscription.get("validityTime"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// Handle Subscription Delete request
async fn handle_subscription_delete(subscription_id: &str) -> SbiResponse {
    log::info!("Subscription Delete: {subscription_id}");

    let manager = nf_manager();
    if manager.remove_subscription(subscription_id) {
        log::info!("Subscription {subscription_id} removed");
        SbiResponse::with_status(204) // No Content
    } else {
        send_not_found(
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        )
    }
}

/// Handle Subscription Update request
async fn handle_subscription_update(subscription_id: &str, _request: &SbiRequest) -> SbiResponse {
    log::info!("Subscription Update: {subscription_id}");
    SbiResponse::with_status(200)
}

/// Handle NF Discovery request (TS 29.510 §6.2.3.2.3.1 SearchNFInstances)
///
/// Implements the query parameter matrix: target-nf-type + requester-nf-type
/// (both mandatory per the OpenAPI, missing => 400 MANDATORY_QUERY_PARAM_MISSING),
/// service-names (comma-separated), snssais / target-plmn-list (JSON in query),
/// dnn, target-nf-instance-id, target-nf-fqdn, limit.
///
/// No match => 200 OK with an empty SearchResult (`nfInstances: []`): the
/// SearchResult schema (TS 29.510 Table 6.2.6.2.2) requires the array but
/// permits it to be empty, and the reference NRF (Open5GS) answers 200 OK
/// with an empty list. 404 is NOT mandated for "target NF type unregistered".
async fn handle_nf_discover(request: &SbiRequest) -> SbiResponse {
    let param = |name: &str| {
        request
            .http
            .params
            .get(name)
            .map(|s| percent_decode(s))
            .filter(|s| !s.is_empty())
    };

    let target_nf_type = param("target-nf-type").unwrap_or_default();
    let requester_nf_type = param("requester-nf-type").unwrap_or_default();

    log::info!("NF Discovery: target={target_nf_type}, requester={requester_nf_type}");

    // Both target-nf-type and requester-nf-type are `required: true`
    // (TS 29.510 SearchNFInstances).
    if target_nf_type.is_empty() {
        return send_bad_request(
            "Missing target-nf-type parameter",
            Some("MANDATORY_QUERY_PARAM_MISSING"),
        );
    }
    if requester_nf_type.is_empty() {
        return send_bad_request(
            "Missing requester-nf-type parameter",
            Some("MANDATORY_QUERY_PARAM_MISSING"),
        );
    }

    // JSON-valued query parameters (content: application/json in the spec).
    let json_array_param = |name: &str| -> Result<Vec<serde_json::Value>, String> {
        match param(name) {
            None => Ok(vec![]),
            Some(raw) => serde_json::from_str::<serde_json::Value>(&raw)
                .ok()
                .and_then(|v| v.as_array().cloned())
                .ok_or_else(|| format!("{name} must be a JSON array")),
        }
    };
    let snssais = match json_array_param("snssais") {
        Ok(v) => v,
        Err(e) => return send_bad_request(&e, Some("INVALID_QUERY_PARAM")),
    };
    let target_plmn_list = match json_array_param("target-plmn-list") {
        Ok(v) => v,
        Err(e) => return send_bad_request(&e, Some("INVALID_QUERY_PARAM")),
    };

    let query = DiscoveryQuery {
        target_nf_type,
        requester_nf_type,
        // style: form, explode: false => comma-separated list.
        service_names: param("service-names")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default(),
        snssais,
        dnn: param("dnn"),
        target_plmn_list,
        target_nf_instance_id: param("target-nf-instance-id"),
        target_nf_fqdn: param("target-nf-fqdn"),
        limit: param("limit").and_then(|v| v.parse().ok()),
    };

    let nf_instances = discover_profiles(&query);
    log::info!(
        "Found {} matching NF instances for type {}",
        nf_instances.len(),
        query.target_nf_type
    );

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "validityPeriod": 3600,
            "nfInstances": nf_instances,
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Handle OAuth2 Access Token Request
///
/// Implements the NRF's role as Authorization Server per 3GPP TS 29.510.
/// Accepts client_credentials grant and issues Bearer tokens.
/// Builds the JWK Set (RFC 7517) advertising the NRF's ES256 public key.
fn nrf_jwks_json() -> serde_json::Value {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let point = nrf_signing_key().verifying_key().to_encoded_point(false);
    let x = point.x().expect("P-256 public key has an x coordinate");
    let y = point.y().expect("P-256 public key has a y coordinate");
    serde_json::json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": NRF_KID,
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
        }]
    })
}

/// Handles `GET /nnrf-oauth2/v1/jwks`.
fn handle_jwks() -> SbiResponse {
    SbiResponse::with_status(200).with_body(nrf_jwks_json().to_string(), "application/json")
}

/// Builds an RFC 6749 §5.2 / TS 29.510 AccessTokenErr error response.
///
/// TS 29.510 (TS29510_Nnrf_AccessToken.yaml) maps token request failures to
/// 400 Bad Request with an AccessTokenErr body (`{"error": "..."}`) as
/// `application/json`, with mandatory `Cache-Control: no-store` and
/// `Pragma: no-cache` headers.
fn token_error(error: &str, description: &str) -> SbiResponse {
    let body = serde_json::json!({
        "error": error,
        "error_description": description,
    });
    SbiResponse::with_status(400)
        .with_header("Cache-Control", "no-store")
        .with_header("Pragma", "no-cache")
        .with_body(body.to_string(), "application/json")
}

async fn handle_access_token_request(request: &SbiRequest) -> SbiResponse {
    log::info!("OAuth2 Access Token Request");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    // Parse as form-urlencoded or JSON
    let (grant_type, nf_instance_id, nf_type, target_nf_type, scope) =
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) {
            (
                parsed
                    .get("grant_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                parsed
                    .get("nfInstanceId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                parsed
                    .get("nfType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                parsed
                    .get("targetNfType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                parsed
                    .get("scope")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            )
        } else {
            // Try form-urlencoded
            let mut grant_type = String::new();
            let mut nf_instance_id = String::new();
            let mut nf_type = String::new();
            let mut target_nf_type = String::new();
            let mut scope = String::new();

            for pair in body.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    match key {
                        "grant_type" => grant_type = value.to_string(),
                        "nfInstanceId" => nf_instance_id = value.to_string(),
                        "nfType" => nf_type = value.to_string(),
                        "targetNfType" => target_nf_type = value.to_string(),
                        "scope" => scope = value.replace('+', " "),
                        _ => {}
                    }
                }
            }
            (grant_type, nf_instance_id, nf_type, target_nf_type, scope)
        };

    // RFC 6749 §5.2 error responses, carried as TS 29.510 AccessTokenErr.
    if grant_type != "client_credentials" {
        return token_error(
            "unsupported_grant_type",
            &format!("Unsupported grant_type: {grant_type:?} (expected client_credentials)"),
        );
    }

    if nf_instance_id.is_empty() {
        return token_error("invalid_request", "Missing nfInstanceId");
    }
    if nf_type.is_empty() {
        return token_error("invalid_request", "Missing nfType");
    }
    if target_nf_type.is_empty() {
        return token_error("invalid_request", "Missing targetNfType");
    }
    if scope.is_empty() {
        return token_error("invalid_scope", "Missing scope");
    }

    // Verify that the requesting NF is registered: an unknown client is an
    // invalid_client error (RFC 6749 §5.2; TS 29.510 carries it in a 400
    // AccessTokenErr rather than a bare 401).
    let manager = nf_manager();
    if manager.get(&nf_instance_id).is_none() {
        return token_error(
            "invalid_client",
            &format!("NF instance {nf_instance_id} is not registered with this NRF"),
        );
    }

    // Issue a JWT access token signed with ES256 (ECDSA P-256).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("value expected")
        .as_secs();
    let expires_in = 3600u64; // 1 hour

    let header_json = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{NRF_KID}"}}"#);
    // `iss` is the NF Instance ID of the NRF (TS 29.510 §6.3.5.2.4
    // AccessTokenClaims), not a placeholder string.
    let claims_json = serde_json::json!({
        "iss": nrf_instance_id(),
        "sub": nf_instance_id,
        "aud": target_nf_type,
        "scope": scope,
        "exp": now + expires_in,
        "iat": now,
    });
    let claims_str = claims_json.to_string();

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(claims_str.as_bytes());

    // Sign header.payload with ES256 (ECDSA P-256). The JOSE signature is the
    // raw r||s (64 bytes), base64url-encoded.
    use p256::ecdsa::{signature::Signer, Signature};
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature: Signature = nrf_signing_key().sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let access_token = format!("{header_b64}.{payload_b64}.{signature_b64}");

    log::info!(
        "Issued access token for {nf_instance_id} ({nf_type}) -> {target_nf_type} scope={scope}"
    );

    let response = AccessTokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: Some(expires_in),
        scope: Some(scope),
    };

    // Cache-Control: no-store and Pragma: no-cache are mandatory on the
    // token response (TS29510_Nnrf_AccessToken.yaml response headers).
    SbiResponse::with_status(200)
        .with_header("Cache-Control", "no-store")
        .with_header("Pragma", "no-cache")
        .with_json_body(&response)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Initialize logging based on command line arguments
fn init_logging(args: &Args) -> Result<()> {
    let mut builder = env_logger::Builder::new();

    // Set log level
    let level = match args.log_level.to_lowercase().as_str() {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => log::LevelFilter::Info,
    };
    builder.filter_level(level);

    // Configure format
    builder.format_timestamp_millis();

    if args.no_color {
        builder.write_style(env_logger::WriteStyle::Never);
    }

    builder.init();

    Ok(())
}

/// Set up signal handlers for graceful shutdown
fn setup_signal_handlers(shutdown: Arc<AtomicBool>) -> Result<()> {
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::SeqCst);
        SHUTDOWN.store(true, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl+C handler")?;

    Ok(())
}

/// Async main event loop with timer integration
async fn run_event_loop_async(_nrf_sm: &mut NrfSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
    log::debug!("Entering async main event loop");

    let mut interval = tokio::time::interval(Duration::from_millis(100));

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Wait for next tick
        interval.tick().await;

        // Process timer expirations
        let expired_events = timer_manager().get_expired_events();
        for event in expired_events {
            log::debug!("Processing timer event: {event:?}");

            match event.timer_id {
                Some(nextgcore_nrfd::NrfTimerId::SubscriptionValidity) => {
                    // Subscription has expired -- remove it
                    if let Some(ref subscription_id) = event.subscription_id {
                        log::info!("Subscription {subscription_id} validity expired, removing");
                        let manager = nf_manager();
                        manager.remove_subscription(subscription_id);
                    }
                }
                Some(nextgcore_nrfd::NrfTimerId::NfInstanceNoHeartbeat) => {
                    // NF instance missed heartbeat (TS 29.510)
                    if let Some(ref nf_instance_id) = event.nf_instance_id {
                        let manager = nf_manager();

                        if manager.is_suspended(nf_instance_id) {
                            // Already SUSPENDED - now auto-deregister
                            log::warn!(
                                "NF instance {nf_instance_id} still no heartbeat after suspension, deregistering"
                            );

                            let profile = manager.get(nf_instance_id);
                            manager.deregister(nf_instance_id).ok();
                            disarm_heartbeat_timer(nf_instance_id);

                            // Send NF_DEREGISTERED notification
                            if let Some(profile) = profile {
                                let server_uri = nrf_self_uri().to_string();
                                tokio::spawn(async move {
                                    if let Err(e) = nrf_nnrf_nfm_send_nf_status_notify_all_async(
                                        NotificationEventType::NfDeregistered,
                                        &profile,
                                        &server_uri,
                                    )
                                    .await
                                    {
                                        log::error!(
                                            "Failed to send NF_DEREGISTERED notifications: {e}"
                                        );
                                    }
                                });
                            }
                        } else {
                            // First missed heartbeat - mark as SUSPENDED
                            log::warn!(
                                "NF instance {nf_instance_id} missed heartbeat, marking SUSPENDED"
                            );
                            manager.suspend(nf_instance_id);

                            // Start a grace period timer for auto-deregistration
                            // Use same interval as heartbeat for the grace period
                            if let Some(profile) = manager.get(nf_instance_id) {
                                let grace_secs = profile.heartbeat_timer.unwrap_or(10) as u64;
                                arm_heartbeat_timer(
                                    nf_instance_id,
                                    std::time::Duration::from_secs(grace_secs),
                                );
                                log::info!(
                                    "NF instance {nf_instance_id} grace period: {grace_secs}s before deregistration"
                                );
                            }
                        }
                    }
                }
                Some(nextgcore_nrfd::NrfTimerId::SbiClientWait) => {
                    log::debug!("SBI client wait timer expired");
                }
                None => {
                    log::warn!("Timer event with no timer ID");
                }
            }
        }

        // Check for shutdown
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
    }

    log::debug!("Exiting async main event loop");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-nrfd"]);
        assert_eq!(args.config, "/etc/nextgcore/nrf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 7777);
        assert!(!args.tls);
        assert_eq!(args.max_ue, 1024);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-nrfd",
            "-c",
            "/custom/nrf.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--max-ue",
            "2048",
        ]);
        assert_eq!(args.config, "/custom/nrf.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.max_ue, 2048);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-nrfd",
            "--tls",
            "--tls-cert",
            "/path/to/cert.pem",
            "--tls-key",
            "/path/to/key.pem",
        ]);
        assert!(args.tls);
        assert_eq!(args.tls_cert, Some("/path/to/cert.pem".to_string()));
        assert_eq!(args.tls_key, Some("/path/to/key.pem".to_string()));
    }

    #[test]
    fn test_jwks_public_key_verifies_signed_token() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use p256::ecdsa::signature::{Signer, Verifier};
        use p256::ecdsa::{Signature, VerifyingKey};
        use p256::EncodedPoint;

        // Sign as the token endpoint does.
        let msg = b"header.payload";
        let sig: Signature = nrf_signing_key().sign(msg);

        // Reconstruct the public key purely from the published JWKS.
        let jwks = nrf_jwks_json();
        let key = &jwks["keys"][0];
        assert_eq!(key["alg"], "ES256");
        assert_eq!(key["kid"], NRF_KID);
        let x = URL_SAFE_NO_PAD.decode(key["x"].as_str().unwrap()).unwrap();
        let y = URL_SAFE_NO_PAD.decode(key["y"].as_str().unwrap()).unwrap();
        let point = EncodedPoint::from_affine_coordinates(
            p256::FieldBytes::from_slice(&x),
            p256::FieldBytes::from_slice(&y),
            false,
        );
        let vk = VerifyingKey::from_encoded_point(&point).expect("valid JWKS key");

        // The JWKS key verifies the NRF signature — consumers can verify tokens.
        assert!(vk.verify(msg, &sig).is_ok());
        // A tampered signing input must fail verification.
        assert!(vk.verify(b"header.tampered", &sig).is_err());
    }

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(
            percent_decode("%5B%7B%22sst%22%3A1%7D%5D"),
            r#"[{"sst":1}]"#
        );
        // Malformed escapes pass through unchanged.
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn test_token_error_shape() {
        // RFC 6749 §5.2 / TS 29.510 AccessTokenErr: 400 + {"error": ...},
        // Cache-Control: no-store, Pragma: no-cache, application/json.
        let resp = token_error("invalid_client", "nope");
        assert_eq!(resp.status, 400);
        assert_eq!(
            resp.http.get_header("Cache-Control").map(String::as_str),
            Some("no-store")
        );
        assert_eq!(
            resp.http.get_header("Pragma").map(String::as_str),
            Some("no-cache")
        );
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["error"], "invalid_client");
    }

    /// Full HTTP-level lifecycle over a real HTTP/2 SBI server on an
    /// ephemeral port: register -> GET (fidelity) -> discover (filter
    /// matrix) -> PATCH (RFC 6902 + RFC 7396) -> token -> deregister.
    /// Everything is bounded by a 30s timeout; the server is stopped at the
    /// end so no blocking threads leak.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_lifecycle_register_discover_patch_deregister() {
        use serde_json::json;

        // Ephemeral port: bind a probe listener, reuse its address.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe binds");
        let addr = probe.local_addr().expect("probe addr");
        drop(probe);

        let server = SbiServer::new(OgsSbiServerConfig::new(addr));
        server
            .start(nrf_sbi_request_handler)
            .await
            .expect("SBI server starts");

        let client = ogs_sbi::client::SbiClient::with_host_port("127.0.0.1", addr.port());
        let nf_id = "5e9b1c0a-1111-4f6a-8888-0123456789ab";

        let lifecycle = async {
            // --- Register: missing mandatory attrs -> 400 ProblemDetails ---
            let bad = json!({"nfInstanceId": nf_id, "nfStatus": "REGISTERED"});
            let resp = client
                .put_json(&format!("/nnrf-nfm/v1/nf-instances/{nf_id}"), &bad)
                .await
                .expect("PUT (invalid)");
            assert_eq!(resp.status, 400);
            let problem: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(problem["status"], 400);
            assert_eq!(problem["cause"], "MANDATORY_IE_MISSING");
            assert!(problem["detail"].as_str().unwrap().contains("nfType"));

            // --- Register: full profile -> 201 + Location + full echo ---
            let profile = json!({
                "nfInstanceId": nf_id,
                "nfType": "SMF",
                "nfStatus": "REGISTERED",
                "heartBeatTimer": 10,
                "plmnList": [{"mcc": "001", "mnc": "01"}],
                "sNssais": [{"sst": 1, "sd": "010203"}],
                "ipv4Addresses": ["10.1.2.3"],
                "fqdn": "smf.example.com",
                "capacity": 100,
                "nfServices": [{
                    "serviceInstanceId": "svc-0",
                    "serviceName": "nsmf-pdusession",
                    "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                    "scheme": "http",
                    "ipEndPoints": [{"ipv4Address": "10.1.2.3", "port": 7777}]
                }],
                "smfInfo": {
                    "sNssaiSmfInfoList": [{
                        "sNssai": {"sst": 1, "sd": "010203"},
                        "dnnSmfInfoList": [{"dnn": "internet"}]
                    }]
                }
            });
            let resp = client
                .put_json(&format!("/nnrf-nfm/v1/nf-instances/{nf_id}"), &profile)
                .await
                .expect("PUT register");
            assert_eq!(resp.status, 201);
            assert!(resp
                .http
                .get_header("Location")
                .expect("Location header on 201")
                .ends_with(&format!("/nnrf-nfm/v1/nf-instances/{nf_id}")));

            // --- GET: round-trip preserves every attribute ---
            let resp = client
                .get(&format!("/nnrf-nfm/v1/nf-instances/{nf_id}"))
                .await
                .expect("GET profile");
            assert_eq!(resp.status, 200);
            let stored: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(stored, profile, "register -> GET must be lossless");

            // --- Discover: matching filters ---
            let mut req = SbiRequest::get("/nnrf-disc/v1/nf-instances");
            req.http.set_param("target-nf-type", "SMF");
            req.http.set_param("requester-nf-type", "AMF");
            req.http.set_param("service-names", "nsmf-pdusession");
            req.http.set_param("dnn", "internet");
            // [{"sst":1,"sd":"010203"}] percent-encoded
            req.http.set_param(
                "snssais",
                "%5B%7B%22sst%22%3A1%2C%22sd%22%3A%22010203%22%7D%5D",
            );
            let resp = client.send_request(req).await.expect("discover");
            assert_eq!(resp.status, 200);
            let result: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            let instances = result["nfInstances"].as_array().unwrap();
            assert!(instances
                .iter()
                .any(|p| p["nfInstanceId"] == nf_id),
                "registered SMF must be discoverable: {result}");

            // --- Discover: no match -> 200 with EMPTY SearchResult, not 404 ---
            let mut req = SbiRequest::get("/nnrf-disc/v1/nf-instances");
            req.http.set_param("target-nf-type", "AUSF");
            req.http.set_param("requester-nf-type", "AMF");
            let resp = client.send_request(req).await.expect("discover empty");
            assert_eq!(resp.status, 200);
            let result: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(result["nfInstances"], json!([]));

            // --- Discover: missing mandatory requester-nf-type -> 400 ---
            let mut req = SbiRequest::get("/nnrf-disc/v1/nf-instances");
            req.http.set_param("target-nf-type", "SMF");
            let resp = client.send_request(req).await.expect("discover invalid");
            assert_eq!(resp.status, 400);
            let problem: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(problem["cause"], "MANDATORY_QUERY_PARAM_MISSING");

            // --- PATCH: RFC 6902 json-patch+json (the TS 29.510 format) ---
            let patch = json!([
                {"op": "test", "path": "/nfStatus", "value": "REGISTERED"},
                {"op": "replace", "path": "/capacity", "value": 55},
                {"op": "add", "path": "/load", "value": 12}
            ]);
            let mut req = SbiRequest::patch(format!("/nnrf-nfm/v1/nf-instances/{nf_id}"));
            req.http
                .set_header("Content-Type", "application/json-patch+json");
            req.http.set_content(patch.to_string());
            let resp = client.send_request(req).await.expect("PATCH json-patch");
            assert_eq!(resp.status, 200);
            let updated: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(updated["capacity"], 55);
            assert_eq!(updated["load"], 12);
            // Untouched attributes survive the patch.
            assert_eq!(updated["smfInfo"], profile["smfInfo"]);

            // --- PATCH: failed RFC 6902 test op -> 409 Conflict ---
            let patch = json!([{"op": "test", "path": "/capacity", "value": 1}]);
            let mut req = SbiRequest::patch(format!("/nnrf-nfm/v1/nf-instances/{nf_id}"));
            req.http
                .set_header("Content-Type", "application/json-patch+json");
            req.http.set_content(patch.to_string());
            let resp = client.send_request(req).await.expect("PATCH failing test");
            assert_eq!(resp.status, 409);

            // --- PATCH: RFC 7396 merge-patch+json ---
            let merge = json!({"load": 70, "priority": 3});
            let mut req = SbiRequest::patch(format!("/nnrf-nfm/v1/nf-instances/{nf_id}"));
            req.http
                .set_header("Content-Type", "application/merge-patch+json");
            req.http.set_content(merge.to_string());
            let resp = client.send_request(req).await.expect("PATCH merge-patch");
            assert_eq!(resp.status, 200);
            let updated: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(updated["load"], 70);
            assert_eq!(updated["priority"], 3);
            assert_eq!(updated["capacity"], 55, "merge patch keeps earlier patch");

            // --- PATCH: removing a mandatory attribute -> 400 ---
            let patch = json!([{"op": "remove", "path": "/nfType"}]);
            let mut req = SbiRequest::patch(format!("/nnrf-nfm/v1/nf-instances/{nf_id}"));
            req.http
                .set_header("Content-Type", "application/json-patch+json");
            req.http.set_content(patch.to_string());
            let resp = client.send_request(req).await.expect("PATCH remove mandatory");
            assert_eq!(resp.status, 400);

            // --- PATCH on unknown NF -> 404 ---
            let resp = client
                .patch_json(
                    "/nnrf-nfm/v1/nf-instances/00000000-dead-beef-0000-000000000000",
                    &json!([{"op": "replace", "path": "/load", "value": 1}]),
                )
                .await
                .expect("PATCH unknown NF");
            assert_eq!(resp.status, 404);

            // --- OAuth2 token: success has iss = NRF instance UUID ---
            let resp = client
                .post_json(
                    "/nnrf-oauth2/v1/access-token",
                    &json!({
                        "grant_type": "client_credentials",
                        "nfInstanceId": nf_id,
                        "nfType": "SMF",
                        "targetNfType": "UDM",
                        "scope": "nudm-sdm"
                    }),
                )
                .await
                .expect("token request");
            assert_eq!(resp.status, 200);
            let token_resp: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            let token = token_resp["access_token"].as_str().unwrap();
            let payload_b64 = token.split('.').nth(1).unwrap();
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            let claims: serde_json::Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
            assert_eq!(claims["iss"], nrf_instance_id(), "iss must be NRF UUID");
            assert_ne!(claims["iss"], "NRF");

            // --- OAuth2 token: RFC 6749 §5.2 error JSON, not bare statuses ---
            let resp = client
                .post_json(
                    "/nnrf-oauth2/v1/access-token",
                    &json!({"grant_type": "password", "nfInstanceId": nf_id,
                            "nfType": "SMF", "targetNfType": "UDM", "scope": "x"}),
                )
                .await
                .expect("token bad grant");
            assert_eq!(resp.status, 400);
            let err: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(err["error"], "unsupported_grant_type");

            let resp = client
                .post_json(
                    "/nnrf-oauth2/v1/access-token",
                    &json!({"grant_type": "client_credentials",
                            "nfInstanceId": "11111111-2222-3333-4444-555555555555",
                            "nfType": "SMF", "targetNfType": "UDM", "scope": "nudm-sdm"}),
                )
                .await
                .expect("token unknown client");
            assert_eq!(resp.status, 400);
            let err: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(err["error"], "invalid_client");

            // --- Deregister -> 204, heartbeat timer disarmed, GET -> 404 ---
            assert!(
                HEARTBEAT_TIMERS.lock().unwrap().contains_key(nf_id),
                "registration must arm the heartbeat timer"
            );
            let resp = client
                .delete(&format!("/nnrf-nfm/v1/nf-instances/{nf_id}"))
                .await
                .expect("DELETE deregister");
            assert_eq!(resp.status, 204);
            assert!(
                !HEARTBEAT_TIMERS.lock().unwrap().contains_key(nf_id),
                "explicit deregister must cancel the heartbeat timer"
            );
            let resp = client
                .get(&format!("/nnrf-nfm/v1/nf-instances/{nf_id}"))
                .await
                .expect("GET after deregister");
            assert_eq!(resp.status, 404);
        };

        let outcome = tokio::time::timeout(Duration::from_secs(30), lifecycle).await;
        client.close().await;
        server.stop().await.expect("server stops");
        outcome.expect("lifecycle test timed out");
    }
}
