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
    nf_manager, nrf_context_final, nrf_context_init, nrf_nnrf_nfm_send_nf_status_notify_all_async,
    nrf_sbi_close, nrf_sbi_open, timer_manager, NotificationEventType, NrfSmContext,
    SbiServerConfig,
};
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::oauth::AccessTokenResponse;
use ogs_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found, send_unauthorized, SbiServer,
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

fn nrf_self_uri() -> &'static str {
    NRF_SELF_URI
        .get()
        .map(|s| s.as_str())
        .unwrap_or("http://127.0.0.1:7777")
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

    // Register the NF instance
    let manager = nf_manager();

    // Create NfProfile from JSON
    let nf_type = profile
        .get("nfType")
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN")
        .to_string();
    let nf_status = profile
        .get("nfStatus")
        .and_then(|v| v.as_str())
        .unwrap_or("REGISTERED")
        .to_string();
    let heartbeat_timer = profile
        .get("heartBeatTimer")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    let nf_profile = nextgcore_nrfd::NfProfile {
        nf_instance_id: nf_instance_id.to_string(),
        nf_type: nf_type.clone(),
        nf_status,
        heartbeat_timer,
        plmn_list: vec![],
        ipv4_addresses: vec![],
        ipv6_addresses: vec![],
        fqdn: None,
        nf_services: vec![],
    };

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

            // Return 201 Created with the NF profile
            SbiResponse::with_status(201)
                .with_header(
                    "Location",
                    format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}"),
                )
                .with_json_body(&profile)
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        Err(e) => {
            log::error!("Failed to register NF {nf_instance_id}: {e}");
            send_bad_request(&e, Some("REGISTRATION_FAILED"))
        }
    }
}

/// Handle NF Profile Retrieval request
async fn handle_nf_profile_retrieval(nf_instance_id: &str) -> SbiResponse {
    log::debug!("NF Profile Retrieval: {nf_instance_id}");

    let manager = nf_manager();

    match manager.get(nf_instance_id) {
        Some(profile) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "nfInstanceId": profile.nf_instance_id,
                "nfType": profile.nf_type,
                "nfStatus": profile.nf_status,
                "heartBeatTimer": profile.heartbeat_timer,
            }))
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
async fn handle_nf_update(nf_instance_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("NF Update: {nf_instance_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    // Parse patch items
    let _patch: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // Verify the NF exists and refresh heartbeat timer
    let manager = nf_manager();

    match manager.get(nf_instance_id) {
        Some(profile) => {
            // Refresh heartbeat timer on any PATCH (serves as heartbeat)
            if let Some(hb_timer) = profile.heartbeat_timer {
                let expiry_secs = (hb_timer as u64) * 2;
                arm_heartbeat_timer(nf_instance_id, Duration::from_secs(expiry_secs));
                log::debug!("Heartbeat timer refreshed for NF {nf_instance_id} ({expiry_secs}s)");
            }

            // A heartbeat on a SUSPENDED NF restores it to REGISTERED (TS 29.510)
            if manager.reactivate(nf_instance_id) {
                log::info!(
                    "NF {nf_instance_id} heartbeat received while SUSPENDED, back to REGISTERED"
                );
            }

            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "nfInstanceId": profile.nf_instance_id,
                    "nfType": profile.nf_type,
                    "nfStatus": profile.nf_status,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(
            &format!("NF instance {nf_instance_id} not found"),
            Some("NF_NOT_FOUND"),
        ),
    }
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

/// Handle NF Discovery request
async fn handle_nf_discover(request: &SbiRequest) -> SbiResponse {
    // Parse query parameters
    let target_nf_type = request
        .http
        .params
        .get("target-nf-type")
        .map(|s| s.as_str())
        .unwrap_or("");
    let requester_nf_type = request
        .http
        .params
        .get("requester-nf-type")
        .map(|s| s.as_str())
        .unwrap_or("");

    log::info!("NF Discovery: target={target_nf_type}, requester={requester_nf_type}");

    if target_nf_type.is_empty() {
        return send_bad_request("Missing target-nf-type parameter", Some("MISSING_PARAM"));
    }

    // Search for matching NF instances
    let manager = nf_manager();

    let matching: Vec<_> = manager
        .list()
        .iter()
        .filter(|p| p.nf_type == target_nf_type && p.nf_status == "REGISTERED")
        .cloned()
        .collect();

    log::info!(
        "Found {} matching NF instances for type {}",
        matching.len(),
        target_nf_type
    );

    // Build SearchResult response
    let nf_instances: Vec<serde_json::Value> = matching
        .iter()
        .map(|p| {
            serde_json::json!({
                "nfInstanceId": p.nf_instance_id,
                "nfType": p.nf_type,
                "nfStatus": p.nf_status,
                "heartBeatTimer": p.heartbeat_timer,
                "ipv4Addresses": p.ipv4_addresses,
                "fqdn": p.fqdn,
            })
        })
        .collect();

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

    // Validate grant_type
    if grant_type != "client_credentials" {
        return send_bad_request(
            &format!("Unsupported grant_type: {grant_type}"),
            Some("UNSUPPORTED_GRANT_TYPE"),
        );
    }

    // Validate required fields
    if nf_instance_id.is_empty() {
        return send_bad_request("Missing nfInstanceId", Some("INVALID_REQUEST"));
    }
    if nf_type.is_empty() {
        return send_bad_request("Missing nfType", Some("INVALID_REQUEST"));
    }
    if target_nf_type.is_empty() {
        return send_bad_request("Missing targetNfType", Some("INVALID_REQUEST"));
    }
    if scope.is_empty() {
        return send_bad_request("Missing scope", Some("INVALID_SCOPE"));
    }

    // Verify that the requesting NF is registered
    let manager = nf_manager();
    if manager.get(&nf_instance_id).is_none() {
        return send_unauthorized(
            &format!("NF instance {nf_instance_id} not registered"),
            Some("UNAUTHORIZED_NF"),
        );
    }

    // Issue a JWT access token signed with ES256 (ECDSA P-256).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("value expected")
        .as_secs();
    let expires_in = 3600u64; // 1 hour

    let header_json = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{NRF_KID}"}}"#);
    let claims_json = serde_json::json!({
        "iss": "NRF",
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

    SbiResponse::with_status(200)
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
}
