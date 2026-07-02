//! NextGCore AUSF (Authentication Server Function)
//!
//! The AUSF is a 5G core network function responsible for:
//! - UE authentication
//! - Authentication vector generation
//! - Key derivation (KAUSF, KSEAF)
//! - Authentication result confirmation

use anyhow::{Context, Result};
use clap::Parser;
use crate::{
    ausf_context_final, ausf_context_init, ausf_sbi_close, ausf_sbi_open, ausf_self, timer_manager,
    AusfEvent, AusfSmContext, SbiServerConfig,
};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as NextgcoreSbiServerConfig,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// NextGCore AUSF - Authentication Server Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-ausfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Authentication Server Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/ausf.yaml")]
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

    /// Maximum number of UEs
    #[arg(long, default_value = "1024")]
    max_ue: usize,
}

// ---------------------------------------------------------------------------
// Typed YAML configuration structs for NRF URI seeding
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct NrfClientYaml {
    uri: String,
}

#[derive(Debug, Default, Deserialize)]
struct SbiClientYaml {
    nrf: Option<Vec<NrfClientYaml>>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiServerYaml {
    address: Option<String>,
    port: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiYaml {
    server: Option<Vec<SbiServerYaml>>,
    client: Option<SbiClientYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct AusfSection {
    sbi: Option<SbiYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct AusfYaml {
    ausf: Option<AusfSection>,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// OAuth2 rollout (Wave-6 H8): opt-in producer verification + outbound consumer
// token install. Default OFF so the matched-sim E2E path is byte-unchanged;
// the docker `ausf-oauth2.yaml` overlay (or NEXTGCORE_SBI_OAUTH2_REQUIRE=1) sets
// `ausf.sbi.oauth2.require: true`. TS 33.501 §13.4.1, TS 29.510 §5.4.2.
// ---------------------------------------------------------------------------

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on
/// outbound SBI calls (installed only when OAuth2 enforcement is enabled).
static OAUTH2_CLIENT: std::sync::OnceLock<Option<Arc<nextgcore_sbi::oauth::OAuth2Client>>> =
    std::sync::OnceLock::new();

/// The shared OAuth2 client, if SBI OAuth2 enforcement is enabled (Wave-6 H8
/// Phase A). Outbound SBI clients attach a token via `client.with_oauth2`.
#[allow(dead_code)]
fn oauth2_client() -> Option<Arc<nextgcore_sbi::oauth::OAuth2Client>> {
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

/// Parse the opt-in `sbi.oauth2.require` knob (Wave-6 H8). Default false so the
/// matched-sim path is untouched. Honors `NEXTGCORE_SBI_OAUTH2_REQUIRE` first
/// (overlay-friendly), then the yaml `<nf>.sbi.oauth2.require` (root-key
/// agnostic: true iff any top-level section sets it).
fn oauth2_required(config_path: &str) -> bool {
    if let Ok(v) = std::env::var("NEXTGCORE_SBI_OAUTH2_REQUIRE") {
        return matches!(v.trim(), "1" | "true" | "TRUE" | "yes");
    }
    let Ok(content) = std::fs::read_to_string(config_path) else {
        return false;
    };
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&content) else {
        return false;
    };
    value.as_mapping().is_some_and(|map| {
        map.values().any(|section| {
            section
                .get("sbi")
                .and_then(|s| s.get("oauth2"))
                .and_then(|o| o.get("require"))
                .and_then(|r| r.as_bool())
                .unwrap_or(false)
        })
    })
}

/// Apply OAuth2 producer enforcement to `cfg` and install the outbound OAuth2
/// client (Wave-6 H8). The server verifies incoming Bearer tokens against the
/// NRF JWKS and requires `aud` to include NfType::Ausf; with no NRF URI
/// configured it fails closed (503, per nextgcore-sbi server.rs).
async fn apply_oauth2_enforcement(mut cfg: NextgcoreSbiServerConfig) -> NextgcoreSbiServerConfig {
    let nrf_uri = nextgcore_sbi::context::global_context().get_nrf_uri().await;
    cfg.require_oauth2 = true;
    cfg.oauth2_jwks_uri = nrf_uri
        .as_deref()
        .map(|uri| nextgcore_sbi::oauth::JwksCache::for_nrf(uri).jwks_uri().to_string());
    cfg = cfg.with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Ausf);
    if let Some(uri) = nrf_uri.as_deref() {
        let nf_instance_id = format!("ausf-{}", uuid::Uuid::new_v4());
        let _ = OAUTH2_CLIENT.set(Some(Arc::new(nextgcore_sbi::oauth::OAuth2Client::new(
            uri,
            nf_instance_id,
            nextgcore_sbi::types::NfType::Ausf,
        ))));
    }
    log::info!(
        "OAuth2 enforcement enabled (JWKS: {})",
        cfg.oauth2_jwks_uri.as_deref().unwrap_or("UNCONFIGURED")
    );
    cfg
}

#[tokio::main]
pub async fn run() -> Result<()> {
    let mut args = Args::parse();

    // Initialize logging
    init_logging(&args)?;
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = nextgcore_metrics::otel::init_otel(
        nextgcore_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();

    log::info!("NextGCore AUSF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize AUSF context
    ausf_context_init(args.max_ue);
    log::info!("AUSF context initialized (max_ue={})", args.max_ue);

    // Initialize AUSF state machine
    let mut ausf_sm = AusfSmContext::new();
    ausf_sm.init();
    log::info!("AUSF state machine initialized");

    // Parse configuration (if file exists) and seed NRF URI
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
                // Seed NRF URI into SBI context for NF registration
                if let Ok(yaml) = serde_yaml::from_str::<AusfYaml>(&content) {
                    if let Some(ausf) = yaml.ausf {
                        if let Some(sbi) = ausf.sbi {
                            // Override the advertised/bind SBI address with the
                            // routable address from config so the NRF NFProfile
                            // advertises a reachable endpoint (not 0.0.0.0).
                            if let Some(server) = sbi.server.as_ref().and_then(|s| s.first()) {
                                if let Some(addr) = &server.address {
                                    args.sbi_addr = addr.clone();
                                }
                                if let Some(port) = server.port {
                                    args.sbi_port = port;
                                }
                            }
                            if let Some(client) = sbi.client {
                                if let Some(nrf_list) = client.nrf {
                                    if let Some(nrf) = nrf_list.first() {
                                        log::info!("NRF URI configured: {}", nrf.uri);
                                        nextgcore_sbi::context::global_context()
                                            .set_nrf_uri(&nrf.uri)
                                            .await;
                                    }
                                }
                            }
                        }
                    }
                }
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
    ausf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using nextgcore-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let mut sbi_server_config = NextgcoreSbiServerConfig::new(sbi_addr);
    if oauth2_required(&args.config) {
        sbi_server_config = apply_oauth2_enforcement(sbi_server_config).await;
    }
    let sbi_server = SbiServer::new(sbi_server_config);

    sbi_server
        .start(ausf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("SBI HTTP/2 server listening on {sbi_addr}");

    // Register with NRF (B23.4)
    match register_with_nrf(&args.sbi_addr, args.sbi_port).await {
        Ok(nf_instance_id) if !nf_instance_id.is_empty() => {
            // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
            // (auth contexts vs configured capacity; TS 29.510 §5.2.2.3.2).
            nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(nf_instance_id, 5, || {
                let ctx = crate::context::ausf_self();
                let load = ctx.read().map(|c| c.get_ue_load()).unwrap_or(0);
                load.clamp(0, 100) as u8
            });
        }
        Ok(_) => {}
        Err(e) => {
            log::warn!("NRF registration failed (will operate without NRF): {e}");
        }
    }

    // Discover UDM instances from NRF
    if let Err(e) = discover_nf_from_nrf("UDM", "nudm-ueau").await {
        log::warn!("UDM discovery failed (will retry on demand): {e}");
    }

    log::info!("NextGCore AUSF ready");

    // Main event loop (async)
    run_event_loop_async(&mut ausf_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    log::info!("SBI HTTP/2 server stopped");

    // Close legacy SBI server
    ausf_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    ausf_sm.fini();
    log::info!("AUSF state machine finalized");

    // Cleanup context
    ausf_context_final();
    log::info!("AUSF context finalized");

    log::info!("NextGCore AUSF stopped");
    Ok(())
}

/// SBI request handler for AUSF
pub async fn ausf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("AUSF SBI request: {method} {uri}");

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Route based on service and resource
    // Expected paths:
    // - /nausf-auth/v1/ue-authentications
    // - /nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka-confirmation
    // - /nausf-auth/v1/ue-authentications/{authCtxId}/eap-session
    // - /nausf-sorprotection/v1/{supi}/ue-sor      (TS 29.509, F-03)
    // - /nausf-upuprotection/v1/{supi}/ue-upu      (TS 29.509, F-03)

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];
    let resource = parts[2];

    match (service, resource, method) {
        // UE Authentication Service (nausf-auth)
        // Note: Order matters - more specific patterns first
        ("nausf-auth", "ue-authentications", "POST")
            if parts.len() >= 5 && parts[4] == "eap-session" =>
        {
            // EAP Session
            let auth_ctx_id = parts[3];
            handle_eap_session(auth_ctx_id, &request).await
        }
        ("nausf-auth", "ue-authentications", "POST") => {
            // UE Authentication (5G-AKA or EAP-AKA')
            handle_ue_authentication(&request).await
        }
        ("nausf-auth", "ue-authentications", "PUT")
            if parts.len() >= 5 && parts[4] == "5g-aka-confirmation" =>
        {
            // 5G-AKA Confirmation
            let auth_ctx_id = parts[3];
            handle_5g_aka_confirmation(auth_ctx_id, &request).await
        }
        ("nausf-auth", "ue-authentications", "DELETE") if parts.len() >= 4 => {
            // Delete Authentication Context
            let auth_ctx_id = parts[3];
            handle_auth_context_delete(auth_ctx_id).await
        }

        // Nausf_SoRProtection / Nausf_UPUProtection custom operations
        // (TS 29.509; Wave-6 F-03). NOTE the path shape differs from
        // nausf-auth: the SUPI sits at parts[2] (where "ue-authentications"
        // sits for nausf-auth), so these arms match on the service prefix
        // with the custom-op name at parts[3].
        ("nausf-sorprotection", supi, "POST") if parts.len() == 4 && parts[3] == "ue-sor" => {
            crate::sor_protection::handle_sor_protect(supi, &request)
        }
        ("nausf-upuprotection", supi, "POST") if parts.len() == 4 && parts[3] == "ue-upu" => {
            crate::upu_protection::handle_upu_protect(supi, &request)
        }

        _ => {
            log::warn!("Unknown AUSF request: {method} {uri}");
            send_method_not_allowed(method, uri)
        }
    }
}

// UE Authentication handlers

pub async fn handle_ue_authentication(request: &SbiRequest) -> SbiResponse {
    log::info!("UE Authentication Request");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let auth_info: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let supi_or_suci = auth_info
        .get("supiOrSuci")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let serving_network_name = auth_info.get("servingNetworkName").and_then(|v| v.as_str());

    // Validate required fields
    if let Err(msg) = crate::nausf_handler::validate_authentication_info(
        Some(supi_or_suci),
        serving_network_name,
    ) {
        return send_bad_request(msg, Some("INVALID_REQUEST"));
    }

    let serving_network_name = serving_network_name.expect("value expected");

    // TS 33.501 §6.1.2: the AUSF checks the serving network name before
    // requesting authentication material. A malformed or non-5G SNN is
    // rejected with 403 SERVING_NETWORK_NOT_AUTHORIZED (TS 29.509 §6.1.7.3).
    if !crate::nausf_handler::validate_serving_network_name(serving_network_name) {
        return send_problem(
            403,
            "SERVING_NETWORK_NOT_AUTHORIZED",
            &format!("Invalid serving network name '{serving_network_name}'"),
        );
    }

    // ausfd-05: bind the SNN to the requesting consumer (AMF/SEAF) identity.
    // TS 33.501 §6.1.2: the AUSF shall check the SNN is allowed for the
    // requester. We resolve the consumer's PLMN set from the OAuth2 access token
    // (plmnList claim). DEFAULT-PERMISSIVE: when no token is present (or it
    // carries no plmnList) the set is empty and the SNN is allowed, so token-less
    // peers (e.g. the matched simulator) are not rejected.
    let consumer_plmns = request
        .http
        .get_header("Authorization")
        .map(|h| extract_consumer_plmns(h))
        .unwrap_or_default();
    if !crate::nausf_handler::snn_authorized_for_consumer(
        serving_network_name,
        &consumer_plmns,
    ) {
        log::warn!(
            "SNN '{serving_network_name}' not authorized for consumer PLMNs {consumer_plmns:?}"
        );
        return send_problem(
            403,
            "SERVING_NETWORK_NOT_AUTHORIZED",
            &format!("Serving network '{serving_network_name}' not allowed for consumer"),
        );
    }

    log::info!("UE Authentication: SUPI/SUCI={supi_or_suci}, SNN={serving_network_name}");

    // Find or create UE in context
    let ctx = ausf_self();
    let ausf_ue = {
        if let Ok(context) = ctx.read() {
            let existing = context.ue_find_by_suci_or_supi(supi_or_suci);
            if let Some(ue) = existing {
                Some(ue)
            } else {
                context.ue_add(supi_or_suci)
            }
        } else {
            None
        }
    };

    let mut ausf_ue = match ausf_ue {
        Some(ue) => ue,
        None => return send_bad_request("Failed to allocate UE context", Some("INTERNAL_ERROR")),
    };

    // Set serving network name
    ausf_ue.serving_network_name = Some(serving_network_name.to_string());

    // Send request to UDM to get authentication vector
    // Build UDM NUDM-UEAU request
    let resync_info = auth_info.get("resynchronizationInfo").and_then(|ri| {
        let rand = ri.get("rand")?.as_str()?.to_string();
        let auts = ri.get("auts")?.as_str()?.to_string();
        Some(crate::ResynchronizationInfo { rand, auts })
    });

    // Try to get auth vector from UDM via SBI client
    let udm_response =
        send_udm_generate_auth_data(supi_or_suci, serving_network_name, resync_info.as_ref()).await;

    match udm_response {
        Ok(UdmAuthData::FiveGAka {
            supi,
            rand,
            xres_star,
            autn,
            kausf,
        }) => {
            // Store authentication vector in UE context
            ausf_ue.auth_type = crate::AuthType::FiveGAka;
            ausf_ue.rand = rand;
            ausf_ue.xres_star = xres_star;
            ausf_ue.autn = autn;
            ausf_ue.kausf = kausf;
            ausf_ue.eap_session = None;
            if let Some(ref supi) = supi {
                ausf_ue.supi = Some(supi.clone());
            }

            // Calculate HXRES* from RAND and XRES*
            ausf_ue.calculate_hxres_star();

            // Update UE in context
            if let Ok(context) = ctx.read() {
                context.ue_update(&ausf_ue);
                if let Some(ref supi) = supi {
                    context.ue_set_supi(ausf_ue.id, supi);
                }
            }

            let rand_hex = crate::nudm_handler::bytes_to_hex(&ausf_ue.rand);
            let autn_hex = crate::nudm_handler::bytes_to_hex(&ausf_ue.autn);
            let hxres_star_hex = crate::nudm_handler::bytes_to_hex(&ausf_ue.hxres_star);
            let auth_ctx_id = ausf_ue.ctx_id.clone();

            SbiResponse::with_status(201)
                .with_header("Location", format!("/nausf-auth/v1/ue-authentications/{auth_ctx_id}"))
                .with_json_body(&serde_json::json!({
                    "authType": "5G_AKA",
                    "5gAuthData": {
                        "rand": rand_hex,
                        "hxresStar": hxres_star_hex,
                        "autn": autn_hex
                    },
                    "_links": {
                        "5g-aka": {
                            "href": format!("/nausf-auth/v1/ue-authentications/{}/5g-aka-confirmation", auth_ctx_id)
                        }
                    },
                    "servingNetworkName": serving_network_name
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        Ok(UdmAuthData::EapAkaPrime {
            supi,
            rand,
            xres,
            autn,
            ck_prime,
            ik_prime,
        }) => {
            // TS 33.501 §6.1.3.1: build EAP-Request/AKA'-Challenge from the
            // transformed AV. The peer identity for the RFC 5448 key schedule
            // is the SUPI.
            ausf_ue.auth_type = crate::AuthType::EapAkaPrime;
            if let Some(ref supi) = supi {
                ausf_ue.supi = Some(supi.clone());
            }
            let identity = ausf_ue
                .supi
                .clone()
                .unwrap_or_else(|| supi_or_suci.to_string());

            let mut session =
                crate::eap_aka_prime::EapAkaSession::new(serving_network_name);
            session.init_from_transformed_av(&rand, &autn, &xres, &ck_prime, &ik_prime, &identity);

            // KAUSF = MSB256(EMSK) is fixed by the key schedule; store it now
            ausf_ue.rand = rand;
            ausf_ue.autn = autn;
            ausf_ue.kausf = session.kausf;

            let challenge = session.generate_challenge();
            let eap_payload_b64 = nextgcore_crypt::base64::encode(&challenge.encode());
            ausf_ue.eap_session = Some(session);

            if let Ok(context) = ctx.read() {
                context.ue_update(&ausf_ue);
                if let Some(ref supi) = supi {
                    context.ue_set_supi(ausf_ue.id, supi);
                }
            }

            let auth_ctx_id = ausf_ue.ctx_id.clone();
            SbiResponse::with_status(201)
                .with_header(
                    "Location",
                    format!("/nausf-auth/v1/ue-authentications/{auth_ctx_id}"),
                )
                .with_json_body(&serde_json::json!({
                    "authType": "EAP_AKA_PRIME",
                    "5gAuthData": eap_payload_b64,
                    "_links": {
                        "eap-session": {
                            "href": format!("/nausf-auth/v1/ue-authentications/{auth_ctx_id}/eap-session")
                        }
                    },
                    "servingNetworkName": serving_network_name
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        Err(e) => {
            log::error!("Failed to get auth vector from UDM: {e}");
            // Update context anyway
            if let Ok(context) = ctx.read() {
                context.ue_update(&ausf_ue);
            }
            SbiResponse::with_status(503)
                .with_json_body(&serde_json::json!({
                    "status": 503,
                    "cause": "UDM_UNAVAILABLE",
                    "detail": format!("Failed to contact UDM: {}", e)
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(503))
        }
    }
}

/// Extract the consumer's allowed PLMN set from an OAuth2 access token (ausfd-05).
///
/// The `Authorization: Bearer <jwt>` header carries a TS 33.501 / RFC 9068 access
/// token. We decode the JWT payload (base64url, second segment) and read the
/// `plmnList` claim (array of `{mcc, mnc}` strings, TS 29.571 PlmnId). Any
/// failure (no token, unparseable JWT, absent claim) yields an empty set, which
/// the entitlement check treats as default-permissive.
///
/// NOTE: the SBI server layer does not yet surface validated token claims to the
/// handler, so this performs an unverified payload decode purely to read the
/// asserted PLMN list. Full enforcement (signature-validated claims, or an
/// NRF NF-profile PLMN lookup) is a follow-up once that plumbing exists.
fn extract_consumer_plmns(authorization: &str) -> Vec<(String, String)> {
    let token = authorization
        .strip_prefix("Bearer ")
        .or_else(|| authorization.strip_prefix("bearer "))
        .unwrap_or(authorization)
        .trim();

    let payload_b64 = match token.split('.').nth(1) {
        Some(p) if !p.is_empty() => p,
        _ => return Vec::new(),
    };

    // base64url -> standard base64 (+ padding) for the shared decoder.
    let mut std_b64 = payload_b64.replace('-', "+").replace('_', "/");
    while std_b64.len() % 4 != 0 {
        std_b64.push('=');
    }
    let bytes = match nextgcore_crypt::base64::decode(&std_b64) {
        Some(b) => b,
        None => return Vec::new(),
    };
    let json: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };

    let mut plmns = Vec::new();
    if let Some(arr) = json.get("plmnList").and_then(|v| v.as_array()) {
        for p in arr {
            if let (Some(mcc), Some(mnc)) = (
                p.get("mcc").and_then(|v| v.as_str()),
                p.get("mnc").and_then(|v| v.as_str()),
            ) {
                plmns.push((mcc.to_string(), mnc.to_string()));
            }
        }
    }
    plmns
}

/// Build an RFC 7807 / TS 29.500 ProblemDetails response.
fn send_problem(status: u16, cause: &str, detail: &str) -> SbiResponse {
    SbiResponse::with_status(status)
        .with_json_body(&serde_json::json!({
            "status": status,
            "cause": cause,
            "detail": detail
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(status))
}

pub async fn handle_5g_aka_confirmation(auth_ctx_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("5G-AKA Confirmation: auth_ctx_id={auth_ctx_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let confirmation: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // ausfd-03: distinguish null/absent resStar (→ 200 failure) from present-but-bad hex (→ 400).
    // TS 29.509 §6.1.6.2.6: "If no RES*, the null value is conveyed to the AUSF."
    let res_star_raw = confirmation.get("resStar");
    let res_star_null_or_absent = res_star_raw.is_none_or(|v| v.is_null());

    // If resStar is present and non-null, validate it is a non-empty string; if not → 400
    let res_star_hex_opt: Option<&str> = if !res_star_null_or_absent {
        match res_star_raw.and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => Some(s),
            _ => {
                return send_bad_request(
                    "ConfirmationData.resStar present but not a valid string",
                    Some("INVALID_REQUEST"),
                );
            }
        }
    } else {
        None
    };

    // Find UE by auth context ID
    let ctx = ausf_self();
    let ausf_ue = {
        if let Ok(context) = ctx.read() {
            context.ue_find_by_ctx_id(auth_ctx_id)
        } else {
            None
        }
    };

    let mut ausf_ue = match ausf_ue {
        Some(ue) => ue,
        None => {
            return send_not_found("Authentication context not found", None);
        }
    };

    // ausfd-03: null/absent resStar → 200 AUTHENTICATION_FAILURE (no kseaf, no supi)
    // TS 29.509 §6.1.6.2.8: both kseaf and supi are conditional on authentication success.
    if res_star_null_or_absent {
        log::warn!(
            "[{}] 5G-AKA: resStar null/absent → AUTHENTICATION_FAILURE",
            ausf_ue.suci
        );
        ausf_ue.auth_result = crate::AuthResult::AuthenticationFailure;
        if let Ok(context) = ctx.read() {
            context.ue_update(&ausf_ue);
        }
        if let (Some(supi), Some(snn)) =
            (ausf_ue.supi.clone(), ausf_ue.serving_network_name.clone())
        {
            tokio::spawn(async move {
                if let Err(e) = send_udm_auth_result(&supi, false, &snn, "5G_AKA").await {
                    log::warn!("Failed to notify UDM of auth result: {e}");
                }
            });
        }
        return SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({"authResult": "AUTHENTICATION_FAILURE"}))
            .unwrap_or_else(|_| SbiResponse::with_status(200));
    }

    // resStar is present and non-null from here on
    let res_star_hex = res_star_hex_opt.expect("value expected");
    log::info!("5G-AKA Confirmation: RES*={res_star_hex}");

    if ausf_ue.supi.is_none() {
        return send_bad_request("No SUPI available for UE", Some("MISSING_SUPI"));
    }

    // Decode hex; genuinely malformed non-null hex → 400 INVALID_REQUEST
    let res_star_bytes = crate::nudm_handler::hex_to_bytes(res_star_hex);
    if res_star_bytes.len() != 16 {
        return send_bad_request(
            "Invalid ConfirmationData.resStar (bad hex or wrong length)",
            Some("INVALID_REQUEST"),
        );
    }

    let mut res_star = [0u8; 16];
    res_star.copy_from_slice(&res_star_bytes);

    // ausfd-02: the AUSF compares the received RES* directly against the stored
    // XRES* using a constant-time comparison (TS 33.501 §6.1.3.2 step 11). The
    // HRES*/HXRES* comparison (step 9) is the SEAF's job; HXRES* is computed only
    // for the 201 `5gAuthData.hxresStar` body, not for this decision.
    if crate::nausf_handler::compare_res_star(&res_star, &ausf_ue.xres_star) {
        ausf_ue.auth_result = crate::AuthResult::AuthenticationSuccess;
        log::info!("[{}] 5G-AKA authentication succeeded", ausf_ue.suci);
    } else {
        ausf_ue.auth_result = crate::AuthResult::AuthenticationFailure;
        log::warn!(
            "[{}] 5G-AKA authentication failed (RES* != XRES*)",
            ausf_ue.suci
        );
    }

    let auth_success = ausf_ue.auth_result == crate::AuthResult::AuthenticationSuccess;

    // ausfd-01: calculate KSEAF only on authentication success.
    // TS 29.509 §6.1.6.2.8: kseaf is conditional "if authentication is successful".
    if auth_success {
        ausf_ue.calculate_kseaf();
    }

    // Update UE in context
    if let Ok(context) = ctx.read() {
        context.ue_update(&ausf_ue);
        // F-02 / TS 33.501 §6.14.1 (and §6.15 for UPU): a SoR/UPU-capable AUSF
        // "shall store the latest K_AUSF after the completion of the latest
        // primary authentication". The anchor store is separate from the auth
        // context and survives its deletion; counters reset to 0x0001 only
        // when this KAUSF is genuinely new (§6.14.2.3/§6.15.2.2 — a
        // retransmitted confirmation must not reset them).
        if auth_success {
            if let Some(supi) = ausf_ue.supi.as_deref() {
                context.anchor_refresh(supi, &ausf_ue.kausf);
            }
        }
    }

    // Notify UDM of authentication result (fire-and-forget)
    let supi_for_udm = ausf_ue.supi.clone().expect("value expected");
    let snn_for_udm = ausf_ue
        .serving_network_name
        .clone()
        .expect("value expected");
    tokio::spawn(async move {
        if let Err(e) =
            send_udm_auth_result(&supi_for_udm, auth_success, &snn_for_udm, "5G_AKA").await
        {
            log::warn!("Failed to notify UDM of auth result: {e}");
        }
    });

    // ausfd-01, ausfd-04: build response body conditionally.
    // TS 29.509 §6.1.6.2.8 Table 6.1.6.2.8-1:
    //   authResult — always present
    //   kseaf      — C: present if authentication successful
    //   supi       — C: present if authentication successful AND original identity was a SUCI
    let auth_result_str = if auth_success {
        "AUTHENTICATION_SUCCESS"
    } else {
        "AUTHENTICATION_FAILURE"
    };

    let mut resp_body = serde_json::Map::new();
    resp_body.insert(
        "authResult".to_string(),
        serde_json::Value::String(auth_result_str.to_string()),
    );

    if auth_success {
        resp_body.insert(
            "kseaf".to_string(),
            serde_json::Value::String(crate::nudm_handler::bytes_to_hex(&ausf_ue.kseaf)),
        );
        // ausfd-04: include supi only when the original identity was a SUCI
        if ausf_ue.suci.starts_with("suci-") {
            if let Some(ref supi_val) = ausf_ue.supi {
                resp_body.insert(
                    "supi".to_string(),
                    serde_json::Value::String(supi_val.clone()),
                );
            }
        }
    }

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::Value::Object(resp_body))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

pub async fn handle_eap_session(auth_ctx_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("EAP Session: auth_ctx_id={auth_ctx_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let eap_session: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let eap_payload = eap_session
        .get("eapPayload")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    log::info!("EAP Session: payload_len={}", eap_payload.len());

    // Find UE by auth context ID
    let ctx = ausf_self();
    let ausf_ue = {
        if let Ok(context) = ctx.read() {
            context.ue_find_by_ctx_id(auth_ctx_id)
        } else {
            None
        }
    };

    let mut ausf_ue = match ausf_ue {
        Some(ue) => ue,
        None => {
            return send_not_found("Authentication context not found", None);
        }
    };

    // Decode EAP payload (base64)
    let eap_bytes = match nextgcore_crypt::base64::decode(eap_payload) {
        Some(bytes) => bytes,
        None => {
            return send_bad_request("Invalid EAP payload encoding", Some("INVALID_EAP"));
        }
    };

    // EAP packet format: Code(1) | Identifier(1) | Length(2) | Type(1) | SubType(1) | ...
    if eap_bytes.len() < 6 {
        return send_bad_request("EAP payload too short", Some("INVALID_EAP"));
    }

    let eap_code = eap_bytes[0]; // 1=Request, 2=Response
    let eap_id = eap_bytes[1];
    let eap_type = eap_bytes[4]; // 50 = EAP-AKA'
    let eap_subtype = eap_bytes[5];

    log::debug!("EAP-AKA': code={eap_code}, id={eap_id}, type={eap_type}, subtype={eap_subtype}");

    if eap_type != 50 {
        return send_bad_request(
            &format!("Unsupported EAP type: {eap_type} (expected 50 for EAP-AKA')"),
            Some("UNSUPPORTED_EAP_TYPE"),
        );
    }

    // An EAP session must have been initiated via POST /ue-authentications
    let mut session = match ausf_ue.eap_session.clone() {
        Some(s) => s,
        None => {
            return send_bad_request(
                "No EAP-AKA' session for this authentication context",
                Some("INVALID_EAP_SESSION"),
            );
        }
    };

    let auth_ctx_id_owned = auth_ctx_id.to_string();

    match eap_subtype {
        // Challenge Response (subtype=1) - RFC 5448 / RFC 9048
        1 => {
            // ausfd-06: AT_KDF negotiation (RFC 9048 §3.2) and AT_BIDDING
            // down-protection (RFC 5448 §4) are evaluated before RES/MAC
            // verification. A bidding-down attempt or an unsupported KDF fails
            // the exchange; a supported-but-different KDF triggers a single
            // re-issue of the Challenge with the negotiated KDF.
            use crate::eap_aka_prime::KdfNegotiation;
            if let Some(packet) = crate::eap_aka_prime::EapPacket::decode(&eap_bytes) {
                match session.check_kdf_and_bidding(&packet) {
                    KdfNegotiation::BiddingDown | KdfNegotiation::Unsupported(_) => {
                        log::warn!(
                            "[{}] EAP-AKA' rejected: KDF/bidding negotiation failure",
                            ausf_ue.suci
                        );
                        ausf_ue.auth_result = crate::AuthResult::AuthenticationFailure;
                        ausf_ue.eap_session = Some(session);
                        if let Ok(context) = ctx.read() {
                            context.ue_update(&ausf_ue);
                        }
                        let eap_failure = vec![4u8, eap_id, 0, 4];
                        return SbiResponse::with_status(200)
                            .with_json_body(&serde_json::json!({
                                "authResult": "AUTHENTICATION_FAILURE",
                                "eapPayload": nextgcore_crypt::base64::encode(&eap_failure)
                            }))
                            .unwrap_or_else(|_| SbiResponse::with_status(200));
                    }
                    KdfNegotiation::Renegotiate(kdf) => {
                        log::info!("[{}] EAP-AKA' renegotiating AT_KDF -> {kdf}", ausf_ue.suci);
                        session.offered_kdf = kdf;
                        session.kdf_renegotiated = true;
                        session.identifier = session.identifier.wrapping_add(1);
                        let challenge = session.generate_challenge();
                        let eap_payload_b64 = nextgcore_crypt::base64::encode(&challenge.encode());
                        ausf_ue.eap_session = Some(session);
                        if let Ok(context) = ctx.read() {
                            context.ue_update(&ausf_ue);
                        }
                        return SbiResponse::with_status(200)
                            .with_json_body(&serde_json::json!({
                                "eapPayload": eap_payload_b64,
                                "_links": {
                                    "eap-session": {
                                        "href": format!(
                                            "/nausf-auth/v1/ue-authentications/{auth_ctx_id_owned}/eap-session"
                                        )
                                    }
                                }
                            }))
                            .unwrap_or_else(|_| SbiResponse::with_status(200));
                    }
                    KdfNegotiation::Accept => {}
                }
            }

            // Full verification: AT_MAC over the packet with zeroed MAC field
            // (K_aut from the RFC 5448 key schedule), then RES against XRES.
            let auth_success = session.process_challenge_response_bytes(&eap_bytes);

            if auth_success {
                ausf_ue.auth_result = crate::AuthResult::AuthenticationSuccess;
                ausf_ue.kausf = session.kausf;
                ausf_ue.calculate_kseaf();
                log::info!("[{}] EAP-AKA' authentication succeeded", ausf_ue.suci);
            } else {
                ausf_ue.auth_result = crate::AuthResult::AuthenticationFailure;
                log::warn!(
                    "[{}] EAP-AKA' authentication failed (AT_MAC or RES mismatch)",
                    ausf_ue.suci
                );
            }
            ausf_ue.eap_session = Some(session);

            if let Ok(context) = ctx.read() {
                context.ue_update(&ausf_ue);
                // F-02 / TS 33.501 §6.14.1: store the latest KAUSF after the
                // completion of the latest primary authentication (EAP-AKA'
                // success path; kausf comes from the RFC 5448/9048 key
                // schedule via session.kausf above). Same-KAUSF refreshes do
                // not reset the SoR/UPU counters (§6.14.2.3/§6.15.2.2).
                if auth_success {
                    if let Some(supi) = ausf_ue.supi.as_deref() {
                        context.anchor_refresh(supi, &ausf_ue.kausf);
                    }
                }
            }

            // Notify UDM of the authentication result (fire-and-forget)
            if let Some(supi) = ausf_ue.supi.clone() {
                if let Some(snn) = ausf_ue.serving_network_name.clone() {
                    let ok = auth_success;
                    tokio::spawn(async move {
                        if let Err(e) = send_udm_auth_result(&supi, ok, &snn, "EAP_AKA_PRIME").await
                        {
                            log::warn!("Failed to notify UDM of EAP auth result: {e}");
                        }
                    });
                }
            }

            if auth_success {
                // EAP-Success keeps the identifier of the last EAP-Request
                let eap_success = vec![3u8, eap_id, 0, 4];
                // ausfd-01, ausfd-04: build response body conditionally.
                // TS 29.509 §6.1.6.2.8: kSeaf conditional on success; supi conditional
                // on success AND original identity was a SUCI.
                let mut eap_body = serde_json::Map::new();
                eap_body.insert(
                    "authResult".to_string(),
                    serde_json::json!("AUTHENTICATION_SUCCESS"),
                );
                eap_body.insert(
                    "kSeaf".to_string(),
                    serde_json::json!(crate::nudm_handler::bytes_to_hex(&ausf_ue.kseaf)),
                );
                if ausf_ue.suci.starts_with("suci-") {
                    eap_body.insert("supi".to_string(), serde_json::json!(ausf_ue.supi));
                }
                eap_body.insert(
                    "eapPayload".to_string(),
                    serde_json::json!(nextgcore_crypt::base64::encode(&eap_success)),
                );
                SbiResponse::with_status(200)
                    .with_json_body(&serde_json::Value::Object(eap_body))
                    .unwrap_or_else(|_| SbiResponse::with_status(200))
            } else {
                let eap_failure = vec![4u8, eap_id, 0, 4];
                SbiResponse::with_status(200)
                    .with_json_body(&serde_json::json!({
                        "authResult": "AUTHENTICATION_FAILURE",
                        "eapPayload": nextgcore_crypt::base64::encode(&eap_failure)
                    }))
                    .unwrap_or_else(|_| SbiResponse::with_status(200))
            }
        }
        // Authentication-Reject (subtype=2)
        2 => {
            ausf_ue.auth_result = crate::AuthResult::AuthenticationFailure;
            if let Ok(context) = ctx.read() {
                context.ue_update(&ausf_ue);
            }

            let eap_failure = vec![4u8, eap_id, 0, 4];
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "authResult": "AUTHENTICATION_FAILURE",
                    "eapPayload": nextgcore_crypt::base64::encode(&eap_failure)
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        // Synchronization-Failure (subtype=4): extract AT_AUTS, resync with
        // the UDM (TS 33.102 §6.3.5) and issue a fresh challenge.
        4 => {
            log::info!(
                "[{}] EAP-AKA' synchronization failure, resyncing with UDM",
                ausf_ue.suci
            );
            let packet = crate::eap_aka_prime::EapPacket::decode(&eap_bytes);
            let auts = packet.as_ref().and_then(|p| {
                p.find_attribute(crate::eap_aka_prime::AkaPrimeAttribute::AtAuts)
                    .filter(|d| d.len() >= 14)
                    .map(|d| d[..14].to_vec())
            });
            let auts = match auts {
                Some(a) => a,
                None => {
                    return send_bad_request(
                        "Synchronization-Failure without AT_AUTS",
                        Some("INVALID_EAP"),
                    )
                }
            };

            let resync = crate::ResynchronizationInfo {
                rand: crate::nudm_handler::bytes_to_hex(&session.rand),
                auts: crate::nudm_handler::bytes_to_hex(&auts),
            };
            let identity = ausf_ue.supi.clone().unwrap_or_else(|| ausf_ue.suci.clone());
            let snn = session.serving_network_name.clone();

            match send_udm_generate_auth_data(&identity, &snn, Some(&resync)).await {
                Ok(UdmAuthData::EapAkaPrime {
                    rand,
                    xres,
                    autn,
                    ck_prime,
                    ik_prime,
                    ..
                }) => {
                    session.init_from_transformed_av(
                        &rand, &autn, &xres, &ck_prime, &ik_prime, &identity,
                    );
                    ausf_ue.rand = rand;
                    ausf_ue.autn = autn;
                    ausf_ue.kausf = session.kausf;
                    let challenge = session.generate_challenge();
                    let eap_payload_b64 = nextgcore_crypt::base64::encode(&challenge.encode());
                    ausf_ue.eap_session = Some(session);

                    if let Ok(context) = ctx.read() {
                        context.ue_update(&ausf_ue);
                    }

                    SbiResponse::with_status(200)
                        .with_json_body(&serde_json::json!({
                            "eapPayload": eap_payload_b64,
                            "_links": {
                                "eap-session": {
                                    "href": format!(
                                        "/nausf-auth/v1/ue-authentications/{auth_ctx_id_owned}/eap-session"
                                    )
                                }
                            }
                        }))
                        .unwrap_or_else(|_| SbiResponse::with_status(200))
                }
                Ok(_) => {
                    log::error!("[{}] UDM returned non-EAP AV on resync", ausf_ue.suci);
                    send_problem(500, "UNSPECIFIED", "UDM returned non-EAP AV on resync")
                }
                Err(e) => {
                    log::error!("[{}] Resync with UDM failed: {e}", ausf_ue.suci);
                    send_problem(403, "AUTHENTICATION_REJECTED", "Resynchronization failed")
                }
            }
        }
        _ => {
            log::warn!("Unsupported EAP-AKA' subtype: {eap_subtype}");
            send_bad_request(
                &format!("Unsupported EAP-AKA' subtype: {eap_subtype}"),
                Some("UNSUPPORTED_SUBTYPE"),
            )
        }
    }
}

pub async fn handle_auth_context_delete(auth_ctx_id: &str) -> SbiResponse {
    log::info!("Auth Context Delete: auth_ctx_id={auth_ctx_id}");

    // ausfd-08: TS 29.509 DELETE ue-authentications/{authCtxId} and TS 33.501
    // §6.1.4.1a context teardown — look up the UE, return 404 if absent, else
    // remove it and zeroize its key material (KAUSF/KSEAF/XRES*).
    //
    // F-02 / TS 33.501 §6.14.1: the per-SUPI SoR/UPU anchor store is
    // deliberately NOT purged here — "the AUSF shall store the latest K_AUSF
    // after the completion of the latest primary authentication" so that
    // Nausf_SoRProtection/Nausf_UPUProtection keep working after the AMF
    // deletes the authentication context. §6.1.4.1a's zeroization is scoped
    // to the authentication context (AusfUe) only.
    let ctx = ausf_self();

    let ue_id = {
        if let Ok(context) = ctx.read() {
            context.ue_find_by_ctx_id(auth_ctx_id).map(|ue| ue.id)
        } else {
            None
        }
    };

    let ue_id = match ue_id {
        Some(id) => id,
        None => {
            return send_not_found("Authentication context not found", None);
        }
    };

    let removed = {
        if let Ok(context) = ctx.read() {
            context.ue_remove(ue_id)
        } else {
            None
        }
    };

    match removed {
        Some(mut ue) => {
            // Zeroize the removed context's keys before it is dropped.
            ue.zeroize();
            log::info!("[{}] Authentication context deleted and zeroized", ue.suci);
            SbiResponse::with_status(204)
        }
        None => send_not_found("Authentication context not found", None),
    }
}

/// Validate the UDM AuthenticationInfoResult `avType` against the selected
/// `authType` (ausfd-07).
///
/// TS 29.503: `avType` ∈ {`5G_HE_AKA`, `EAP_AKA_PRIME`}; it must be consistent
/// with the AKA method the AUSF intends to run:
///   - `5G_AKA`        ↔ `5G_HE_AKA`
///   - `EAP_AKA_PRIME` ↔ `EAP_AKA_PRIME`
///
/// When `avType` is absent the check is skipped (permissive) so peers that omit
/// the optional field are not rejected; when present it must match.
fn validate_av_type(auth_type: &str, av_type: Option<&str>) -> Result<(), String> {
    let av_type = match av_type {
        Some(t) => t,
        None => return Ok(()),
    };
    let consistent = matches!(
        (auth_type, av_type),
        ("5G_AKA", "5G_HE_AKA") | ("EAP_AKA_PRIME", "EAP_AKA_PRIME")
    );
    if consistent {
        Ok(())
    } else {
        Err(format!(
            "UDM avType '{av_type}' inconsistent with authType '{auth_type}'"
        ))
    }
}

/// Build the Nudm_UEAuthentication generate-auth-data request body (ausfd-09).
///
/// `ausf_instance_id` is the AUSF's real registered NF instance id (resolved by
/// [`resolve_ausf_instance_id`]), not a hard-coded literal.
fn build_generate_auth_data_body(
    serving_network_name: &str,
    ausf_instance_id: &str,
    resync_info: Option<&crate::ResynchronizationInfo>,
) -> serde_json::Value {
    let mut body = serde_json::json!({
        "servingNetworkName": serving_network_name,
        "ausfInstanceId": ausf_instance_id
    });
    if let Some(resync) = resync_info {
        body["resynchronizationInfo"] = serde_json::json!({
            "rand": resync.rand,
            "auts": resync.auts
        });
    }
    body
}

/// Resolve the AUSF's NF instance id for outgoing Nudm requests (ausfd-09).
///
/// Returns the registered self NF instance id from the SBI context; falls back
/// to the static `"ausf-instance-id"` only when no self instance has been
/// registered yet (e.g. NRF registration disabled).
async fn resolve_ausf_instance_id() -> String {
    nextgcore_sbi::context::global_context()
        .get_self_instance()
        .await
        .map(|i| i.id)
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| "ausf-instance-id".to_string())
}

/// Authentication data received from UDM (TS 29.503 AuthenticationInfoResult)
enum UdmAuthData {
    /// 5G-AKA home environment AV (avType 5G_HE_AKA)
    FiveGAka {
        supi: Option<String>,
        rand: [u8; 16],
        xres_star: [u8; 16],
        autn: [u8; 16],
        kausf: [u8; 32],
    },
    /// EAP-AKA' transformed AV (avType EAP_AKA_PRIME): RAND, AUTN, XRES, CK', IK'
    EapAkaPrime {
        supi: Option<String>,
        rand: [u8; 16],
        xres: Vec<u8>,
        autn: [u8; 16],
        ck_prime: [u8; 16],
        ik_prime: [u8; 16],
    },
}

/// Send NUDM-UEAU generate-auth-data request to UDM via SBI client
async fn send_udm_generate_auth_data(
    supi_or_suci: &str,
    serving_network_name: &str,
    resync_info: Option<&crate::ResynchronizationInfo>,
) -> Result<UdmAuthData, String> {
    let sbi_ctx = nextgcore_sbi::context::global_context();

    // Find UDM instance via cached discovery results or env var fallback
    let (host_owned, port);
    let udm_instances = sbi_ctx
        .find_nf_instances_by_service(nextgcore_sbi::types::SbiServiceType::NudmUeau)
        .await;

    if let Some(udm_instance) = udm_instances.first() {
        let udm_service = udm_instance
            .find_service(nextgcore_sbi::types::SbiServiceType::NudmUeau)
            .ok_or("UDM instance has no nudm-ueau service")?;
        host_owned = udm_service
            .fqdn
            .clone()
            .or(udm_instance.fqdn.clone())
            .or(udm_service.ip_addresses.first().cloned())
            .or(udm_instance.ipv4_addresses.first().cloned())
            .ok_or("No UDM endpoint address available")?;
        port = udm_service.port;
    } else {
        // Fallback: use UDM_SBI_ADDR/UDM_SBI_PORT env vars
        host_owned = std::env::var("UDM_SBI_ADDR")
            .map_err(|_| "No UDM instance available and UDM_SBI_ADDR not set".to_string())?;
        port = std::env::var("UDM_SBI_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(7777);
        log::info!("Using UDM env var fallback: {host_owned}:{port}");
    }

    let client = sbi_ctx.get_client(&host_owned, port).await;

    // ausfd-09: populate ausfInstanceId from the real registered NF instance id.
    let ausf_instance_id = resolve_ausf_instance_id().await;
    let body = build_generate_auth_data_body(serving_network_name, &ausf_instance_id, resync_info);

    let path = format!("/nudm-ueau/v1/{supi_or_suci}/security-information/generate-auth-data");

    log::debug!("Sending UDM request: POST {path}");

    let response = client
        .post_json(&path, &body)
        .await
        .map_err(|e| format!("UDM request failed: {e}"))?;

    if response.status != 200 && response.status != 201 {
        return Err(format!("UDM returned status {}", response.status));
    }

    // Parse UDM response
    let response_body = response.http.content.ok_or("Empty UDM response body")?;
    let json: serde_json::Value = serde_json::from_str(&response_body)
        .map_err(|e| format!("Invalid UDM response JSON: {e}"))?;

    // Extract authentication vector
    let supi = json.get("supi").and_then(|v| v.as_str()).map(String::from);
    let auth_type = json
        .get("authType")
        .and_then(|v| v.as_str())
        .unwrap_or("5G_AKA");

    let av = json
        .get("authenticationVector")
        .ok_or("No authenticationVector in UDM response")?;

    // ausfd-07: validate the AV's avType is consistent with the selected
    // authType before trusting/storing the vector (TS 33.501 §6.1.3.2.0 step 2,
    // TS 29.503 AuthenticationInfoResult.avType).
    let av_type = av.get("avType").and_then(|v| v.as_str());
    validate_av_type(auth_type, av_type)?;

    let get_hex = |field: &str| -> Result<Vec<u8>, String> {
        let hex = av
            .get(field)
            .and_then(|v| v.as_str())
            .ok_or(format!("No {field} in authentication vector"))?;
        Ok(crate::nudm_handler::hex_to_bytes(hex))
    };

    match auth_type {
        "5G_AKA" => {
            let rand_bytes = get_hex("rand")?;
            let xres_star_bytes = get_hex("xresStar")?;
            let autn_bytes = get_hex("autn")?;
            let kausf_bytes = get_hex("kausf")?;

            if rand_bytes.len() != 16
                || xres_star_bytes.len() != 16
                || autn_bytes.len() != 16
                || kausf_bytes.len() != 32
            {
                return Err("Invalid authentication vector field lengths".to_string());
            }

            let mut rand = [0u8; 16];
            let mut xres_star = [0u8; 16];
            let mut autn = [0u8; 16];
            let mut kausf = [0u8; 32];
            rand.copy_from_slice(&rand_bytes);
            xres_star.copy_from_slice(&xres_star_bytes);
            autn.copy_from_slice(&autn_bytes);
            kausf.copy_from_slice(&kausf_bytes);

            Ok(UdmAuthData::FiveGAka {
                supi,
                rand,
                xres_star,
                autn,
                kausf,
            })
        }
        "EAP_AKA_PRIME" => {
            let rand_bytes = get_hex("rand")?;
            let xres = get_hex("xres")?;
            let autn_bytes = get_hex("autn")?;
            let ck_prime_bytes = get_hex("ckPrime")?;
            let ik_prime_bytes = get_hex("ikPrime")?;

            if rand_bytes.len() != 16
                || autn_bytes.len() != 16
                || ck_prime_bytes.len() != 16
                || ik_prime_bytes.len() != 16
                || xres.is_empty()
            {
                return Err("Invalid EAP-AKA' authentication vector field lengths".to_string());
            }

            let mut rand = [0u8; 16];
            let mut autn = [0u8; 16];
            let mut ck_prime = [0u8; 16];
            let mut ik_prime = [0u8; 16];
            rand.copy_from_slice(&rand_bytes);
            autn.copy_from_slice(&autn_bytes);
            ck_prime.copy_from_slice(&ck_prime_bytes);
            ik_prime.copy_from_slice(&ik_prime_bytes);

            Ok(UdmAuthData::EapAkaPrime {
                supi,
                rand,
                xres,
                autn,
                ck_prime,
                ik_prime,
            })
        }
        other => Err(format!("Unsupported auth type from UDM: {other}")),
    }
}

/// Send authentication result confirmation to UDM
async fn send_udm_auth_result(
    supi: &str,
    success: bool,
    serving_network_name: &str,
    auth_type: &str,
) -> Result<(), String> {
    let sbi_ctx = nextgcore_sbi::context::global_context();

    let udm_instances = sbi_ctx
        .find_nf_instances_by_service(nextgcore_sbi::types::SbiServiceType::NudmUeau)
        .await;

    let udm_instance = match udm_instances.first() {
        Some(inst) => inst,
        None => {
            log::warn!("No UDM instance available for auth result notification");
            return Err("No UDM instance available".to_string());
        }
    };

    let udm_service = udm_instance
        .find_service(nextgcore_sbi::types::SbiServiceType::NudmUeau)
        .ok_or("UDM instance has no nudm-ueau service")?;

    let host = udm_service
        .fqdn
        .as_deref()
        .or(udm_instance.fqdn.as_deref())
        .or(udm_service.ip_addresses.first().map(|s| s.as_str()))
        .or(udm_instance.ipv4_addresses.first().map(|s| s.as_str()))
        .ok_or("No UDM endpoint address available")?;
    let port = udm_service.port;

    let client = sbi_ctx.get_client(host, port).await;

    let body = serde_json::json!({
        "nfInstanceId": nextgcore_sbi::context::global_context()
            .get_self_instance()
            .await
            .map(|i| i.id)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        "success": success,
        "authType": auth_type,
        "timeStamp": crate::nudm_build::get_current_timestamp(),
        "servingNetworkName": serving_network_name
    });

    let path = format!("/nudm-ueau/v1/{supi}/auth-events");
    log::debug!("Sending UDM auth result: POST {path}");

    let response = client
        .post_json(&path, &body)
        .await
        .map_err(|e| format!("UDM auth result request failed: {e}"))?;

    if response.status != 200 && response.status != 201 {
        return Err(format!(
            "UDM auth result returned status {}",
            response.status
        ));
    }

    Ok(())
}

/// Build the TS 29.510 NFProfile the AUSF registers with the NRF.
///
/// Advertises nausf-auth plus the Wave-6 F-03 producer services
/// nausf-sorprotection / nausf-upuprotection (TS 29.509), so udmd
/// discovery-by-service works (TS 33.501 §6.14.2.1 step 8: the UDM selects
/// the AUSF holding the latest KAUSF). UDM — the consumer of both new
/// services — is included in allowedNfTypes.
fn build_nf_profile(nf_instance_id: &str, sbi_addr: &str, sbi_port: u16) -> serde_json::Value {
    let service = |name: &str| {
        serde_json::json!({
            "serviceInstanceId": format!("{nf_instance_id}-{name}"),
            "serviceName": name,
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{
                "ipv4Address": sbi_addr,
                "port": sbi_port
            }]
        })
    };
    serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "AUSF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [
            service("nausf-auth"),
            service("nausf-sorprotection"),
            service("nausf-upuprotection")
        ],
        "allowedNfTypes": ["AMF", "UDM", "SCP"],
        "heartBeatTimer": 10
    })
}

/// Register AUSF with NRF (B23.4)
///
/// Returns the NF instance ID that was registered, so callers can start a
/// heartbeat worker for the same instance.
async fn register_with_nrf(sbi_addr: &str, sbi_port: u16) -> Result<String, String> {
    let sbi_ctx = nextgcore_sbi::context::global_context();

    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => {
            log::debug!("No NRF URI configured, skipping NRF registration");
            return Ok(String::new());
        }
    };

    log::info!("Registering AUSF with NRF at {nrf_uri}");

    // Parse NRF URI for host/port
    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;

    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_instance_id = uuid::Uuid::new_v4().to_string();

    // Build NF Profile for registration
    let nf_profile = build_nf_profile(&nf_instance_id, sbi_addr, sbi_port);

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    log::debug!("NRF registration: PUT {path}");

    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("AUSF registered with NRF successfully (id={nf_instance_id})");

            // Store self instance
            let mut self_instance = nextgcore_sbi::context::NfInstance::new(
                &nf_instance_id,
                nextgcore_sbi::types::NfType::Ausf,
            );
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            for (name, service_type) in [
                ("nausf-auth", nextgcore_sbi::types::SbiServiceType::NausfAuth),
                (
                    "nausf-sorprotection",
                    nextgcore_sbi::types::SbiServiceType::NausfSorprotection,
                ),
                (
                    "nausf-upuprotection",
                    nextgcore_sbi::types::SbiServiceType::NausfUpuprotection,
                ),
            ] {
                let mut svc = nextgcore_sbi::context::NfService::new(name, service_type);
                svc.port = sbi_port;
                svc.ip_addresses = vec![sbi_addr.to_string()];
                self_instance.add_service(svc);
            }
            sbi_ctx.set_self_instance(self_instance).await;

            // Extract heartbeat interval from response
            if let Some(ref body) = response.http.content {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                    if let Some(hb) = json.get("heartBeatTimer").and_then(|v| v.as_u64()) {
                        log::debug!("NRF heartbeat interval: {hb}s");
                    }
                }
            }

            Ok(nf_instance_id)
        }
        _ => Err(format!(
            "NRF registration returned status {}",
            response.status
        )),
    }
}

/// Discover NF services from NRF
async fn discover_nf_from_nrf(target_nf_type: &str, service_name: &str) -> Result<(), String> {
    let sbi_ctx = nextgcore_sbi::context::global_context();

    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => return Ok(()), // No NRF configured
    };

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;

    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let path = format!(
        "/nnrf-disc/v1/nf-instances?target-nf-type={target_nf_type}&requester-nf-type=AUSF&service-names={service_name}"
    );

    let response = client
        .get(&path)
        .await
        .map_err(|e| format!("NRF discovery failed: {e}"))?;

    if response.status != 200 {
        return Err(format!("NRF discovery returned status {}", response.status));
    }

    let body = response
        .http
        .content
        .ok_or("Empty NRF discovery response")?;
    let json: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("Invalid NRF discovery response: {e}"))?;

    // Parse NF instances from discovery response
    if let Some(nf_instances) = json.get("nfInstances").and_then(|v| v.as_array()) {
        for nf_json in nf_instances {
            let nf_id = nf_json
                .get("nfInstanceId")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let nf_type_str = nf_json
                .get("nfType")
                .and_then(|v| v.as_str())
                .unwrap_or("UDM");

            let nf_type = match nf_type_str {
                "UDM" => nextgcore_sbi::types::NfType::Udm,
                "NRF" => nextgcore_sbi::types::NfType::Nrf,
                _ => continue,
            };

            let mut instance = nextgcore_sbi::context::NfInstance::new(nf_id, nf_type);

            if let Some(fqdn) = nf_json.get("fqdn").and_then(|v| v.as_str()) {
                instance.fqdn = Some(fqdn.to_string());
            }
            if let Some(addrs) = nf_json.get("ipv4Addresses").and_then(|v| v.as_array()) {
                instance.ipv4_addresses = addrs
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
            }

            // Parse services
            if let Some(services) = nf_json.get("nfServices").and_then(|v| v.as_array()) {
                for svc_json in services {
                    let svc_name = svc_json
                        .get("serviceName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if let Some(svc_type) =
                        nextgcore_sbi::types::SbiServiceType::from_name(svc_name)
                    {
                        let mut svc = nextgcore_sbi::context::NfService::new(svc_name, svc_type);
                        if let Some(endpoints) =
                            svc_json.get("ipEndPoints").and_then(|v| v.as_array())
                        {
                            if let Some(ep) = endpoints.first() {
                                if let Some(addr) = ep.get("ipv4Address").and_then(|v| v.as_str()) {
                                    svc.ip_addresses.push(addr.to_string());
                                }
                                if let Some(port) = ep.get("port").and_then(|v| v.as_u64()) {
                                    svc.port = port as u16;
                                }
                            }
                        }
                        instance.add_service(svc);
                    }
                }
            }

            sbi_ctx.add_nf_instance(instance).await;
            log::info!("Discovered {nf_type_str} instance: {nf_id}");
        }
    }

    Ok(())
}

/// Parse host and port from a URI string (e.g., "http://localhost:7777")
fn parse_host_port(uri: &str) -> Option<(String, u16)> {
    let without_scheme = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    let (host_port, _path) = without_scheme
        .split_once('/')
        .unwrap_or((without_scheme, ""));
    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let port: u16 = port_str.parse().ok()?;
        Some((host.to_string(), port))
    } else {
        let default_port = if uri.starts_with("https://") { 443 } else { 80 };
        Some((host_port.to_string(), default_port))
    }
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
async fn run_event_loop_async(
    ausf_sm: &mut AusfSmContext,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    log::debug!("Entering async main event loop");

    let timer_mgr = timer_manager();

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Poll with a reasonable interval
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Process timer expirations and dispatch to state machine
        let expired = timer_mgr.process_expired();
        for entry in expired {
            log::debug!(
                "AUSF timer expired: id={} type={:?} data={:?}",
                entry.id,
                entry.timer_type,
                entry.data
            );

            // Create timer event and dispatch to state machine
            let mut event = AusfEvent::sbi_timer(entry.timer_type);
            if let Some(ref nf_id) = entry.data {
                event = event.with_nf_instance(nf_id.clone());
            }

            ausf_sm.dispatch(&mut event);
        }

        // Check for shutdown
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
    }

    // Cleanup: clear all timers on shutdown
    timer_mgr.clear();
    log::debug!("Exiting async main event loop");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialise integration tests that share global env vars (UDM_SBI_ADDR/PORT)
    /// and the process-wide AUSF context.
    static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Initiate a 5G-AKA authentication session and return the confirmation href
    /// and the RAND bytes needed to compute a valid RES*.
    async fn initiate_5g_aka(
        client: &nextgcore_sbi::client::SbiClient,
        identity: &str,
        snn: &str,
    ) -> (String, [u8; 16]) {
        let resp = client
            .post_json(
                "/nausf-auth/v1/ue-authentications",
                &serde_json::json!({"supiOrSuci": identity, "servingNetworkName": snn}),
            )
            .await
            .expect("POST ue-authentications");
        assert_eq!(
            resp.status, 201,
            "initiate_5g_aka: expected 201, got {}",
            resp.status
        );
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).unwrap();
        let href = body
            .pointer("/_links/5g-aka/href")
            .and_then(|v| v.as_str())
            .expect("5g-aka link")
            .to_string();
        let rand_hex = body
            .pointer("/5gAuthData/rand")
            .and_then(|v| v.as_str())
            .expect("rand");
        let rand_bytes = crate::nudm_handler::hex_to_bytes(rand_hex);
        let mut rand = [0u8; 16];
        rand.copy_from_slice(&rand_bytes);
        (href, rand)
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-ausfd"]);
        assert_eq!(args.config, "/etc/nextgcore/ausf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 7777);
        assert!(!args.tls);
        assert_eq!(args.max_ue, 1024);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-ausfd",
            "-c",
            "/custom/ausf.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--max-ue",
            "2048",
        ]);
        assert_eq!(args.config, "/custom/ausf.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.max_ue, 2048);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-ausfd",
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

    // ========================================================================
    // HTTP-level AUSF <-> UDM authentication flow (TS 29.509 / TS 33.501)
    //
    // Real ausf_sbi_request_handler served over HTTP/2 on an ephemeral port,
    // talking to a spec-shaped mock UDM (real Milenage + 5G KDFs) on another
    // ephemeral port via the UDM_SBI_ADDR/UDM_SBI_PORT fallback.
    // ========================================================================

    /// Shared test subscriber credentials (standard 3GPP test K/OPc).
    const TEST_K: [u8; 16] = [
        0x46, 0x5B, 0x5C, 0xE8, 0xB1, 0x99, 0xB4, 0x9F, 0xAA, 0x5F, 0x0A, 0x2E, 0xE2, 0x38, 0xA6,
        0xBC,
    ];
    const TEST_OPC: [u8; 16] = [
        0xE8, 0xED, 0x28, 0x9D, 0xEB, 0xA9, 0x52, 0xE4, 0x28, 0x3B, 0x54, 0xE8, 0x8E, 0x61, 0x83,
        0xCA,
    ];
    const SUPI_5G_AKA: &str = "imsi-001010000000001";
    const SUPI_EAP: &str = "imsi-001010000000002";
    const TEST_SNN: &str = "5G:mnc001.mcc001.3gppnetwork.org";

    /// Spec-shaped mock UDM: real Milenage + TS 33.501 KDFs, AMF separation
    /// bit set, EAP_AKA_PRIME for SUPI_EAP, 5G_AKA otherwise.
    async fn mock_udm_handler(request: SbiRequest) -> SbiResponse {
        use crate::nudm_handler::bytes_to_hex;

        let uri = request.header.uri.clone();
        let path = uri.split('?').next().unwrap_or(&uri).to_string();

        if path.ends_with("/auth-events") {
            return SbiResponse::with_status(201);
        }
        if !path.contains("generate-auth-data") {
            return SbiResponse::with_status(404);
        }

        let supi = path
            .trim_start_matches('/')
            .split('/')
            .nth(2)
            .unwrap_or("")
            .to_string();
        let body: serde_json::Value = request
            .http
            .content
            .as_deref()
            .and_then(|b| serde_json::from_str(b).ok())
            .unwrap_or_default();
        let snn = body
            .get("servingNetworkName")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        let amf = [0x80u8, 0x00]; // separation bit set
        let sqn = [0x00u8, 0x00, 0x00, 0x00, 0x00, 0x21];
        let mut rand = [0u8; 16];
        nextgcore_core::rand::nextgcore_random(&mut rand);

        let (autn, ik, ck, _ak, res) =
            nextgcore_crypt::milenage::milenage_generate(&TEST_OPC, &amf, &TEST_K, &sqn, &rand)
                .expect("milenage");

        if supi == SUPI_EAP {
            let mut sqn_xor_ak = [0u8; 6];
            sqn_xor_ak.copy_from_slice(&autn[..6]);
            let (ck_prime, ik_prime) =
                nextgcore_crypt::kdf::nextgcore_kdf_ck_ik_prime(&ck, &ik, &snn, &sqn_xor_ak);
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "authType": "EAP_AKA_PRIME",
                    "authenticationVector": {
                        "avType": "EAP_AKA_PRIME",
                        "rand": bytes_to_hex(&rand),
                        "autn": bytes_to_hex(&autn),
                        "xres": bytes_to_hex(&res),
                        "ckPrime": bytes_to_hex(&ck_prime),
                        "ikPrime": bytes_to_hex(&ik_prime)
                    },
                    "supi": supi
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(500))
        } else {
            let kausf = nextgcore_crypt::kdf::nextgcore_kdf_kausf(&ck, &ik, &snn, &autn);
            let xres_star =
                nextgcore_crypt::kdf::nextgcore_kdf_xres_star(&ck, &ik, &snn, &rand, &res);
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "authType": "5G_AKA",
                    "authenticationVector": {
                        "avType": "5G_HE_AKA",
                        "rand": bytes_to_hex(&rand),
                        "autn": bytes_to_hex(&autn),
                        "xresStar": bytes_to_hex(&xres_star),
                        "kausf": bytes_to_hex(&kausf)
                    },
                    "supi": supi
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(500))
        }
    }

    fn free_port() -> u16 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        port
    }

    /// Full HTTP-level flow: 5G-AKA success + failure, EAP-AKA' success +
    /// failure, strict-peer rejections (missing attrs, bad SNN).
    ///
    /// Single test function: it owns the process-wide UDM_SBI_ADDR/PORT env
    /// fallback and the global AUSF context.
    #[tokio::test]
    async fn test_http_auth_flows_5g_aka_and_eap_aka_prime() {
        let _ = env_logger::try_init();
        let _lock = TEST_MUTEX.lock().await;
        tokio::time::timeout(Duration::from_secs(60), async {
            ausf_context_init(64);

            // --- mock UDM on an ephemeral port ---
            let udm_port = free_port();
            let udm_server = SbiServer::new(NextgcoreSbiServerConfig::new(SocketAddr::from((
                [127, 0, 0, 1],
                udm_port,
            ))));
            udm_server.start(mock_udm_handler).await.expect("udm start");
            std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDM_SBI_PORT", udm_port.to_string());

            // --- real AUSF handler on an ephemeral port ---
            let ausf_port = free_port();
            let ausf_server = SbiServer::new(NextgcoreSbiServerConfig::new(SocketAddr::from((
                [127, 0, 0, 1],
                ausf_port,
            ))));
            ausf_server
                .start(ausf_sbi_request_handler)
                .await
                .expect("ausf start");

            let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", ausf_port);

            // ---- strict-peer rejections ----
            // Missing servingNetworkName -> 400
            let resp = client
                .post_json(
                    "/nausf-auth/v1/ue-authentications",
                    &serde_json::json!({"supiOrSuci": SUPI_5G_AKA}),
                )
                .await
                .expect("send");
            assert_eq!(resp.status, 400, "missing SNN must be rejected");

            // Malformed serving network name -> 403 SERVING_NETWORK_NOT_AUTHORIZED
            let resp = client
                .post_json(
                    "/nausf-auth/v1/ue-authentications",
                    &serde_json::json!({
                        "supiOrSuci": SUPI_5G_AKA,
                        "servingNetworkName": "EPS:mnc001.mcc001.3gppnetwork.org"
                    }),
                )
                .await
                .expect("send");
            assert_eq!(resp.status, 403);
            let pd: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap();
            assert_eq!(
                pd.get("cause").and_then(|v| v.as_str()),
                Some("SERVING_NETWORK_NOT_AUTHORIZED")
            );

            // ---- 5G-AKA success ----
            let resp = client
                .post_json(
                    "/nausf-auth/v1/ue-authentications",
                    &serde_json::json!({
                        "supiOrSuci": SUPI_5G_AKA,
                        "servingNetworkName": TEST_SNN
                    }),
                )
                .await
                .expect("send");
            assert_eq!(resp.status, 201);
            let ctx_json: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().expect("body")).unwrap();
            assert_eq!(
                ctx_json.get("authType").and_then(|v| v.as_str()),
                Some("5G_AKA")
            );
            let auth_data = ctx_json.get("5gAuthData").expect("5gAuthData");
            let rand_hex = auth_data.get("rand").and_then(|v| v.as_str()).unwrap();
            let autn_hex = auth_data.get("autn").and_then(|v| v.as_str()).unwrap();
            assert!(auth_data.get("hxresStar").is_some());
            assert_eq!(autn_hex.len(), 32);
            let href = ctx_json
                .pointer("/_links/5g-aka/href")
                .and_then(|v| v.as_str())
                .expect("5g-aka link");

            // UE side: compute RES* from RAND with the shared credentials
            let rand_bytes = crate::nudm_handler::hex_to_bytes(rand_hex);
            let mut rand = [0u8; 16];
            rand.copy_from_slice(&rand_bytes);
            let (res, ck, ik, _ak, _akstar) =
                nextgcore_crypt::milenage::milenage_f2345(&TEST_OPC, &TEST_K, &rand).unwrap();
            let res_star =
                nextgcore_crypt::kdf::nextgcore_kdf_xres_star(&ck, &ik, TEST_SNN, &rand, &res);

            // Wrong RES* first -> AUTHENTICATION_FAILURE
            let resp = client
                .put_json(
                    href,
                    &serde_json::json!({
                        "resStar": "00000000000000000000000000000000"
                    }),
                )
                .await
                .expect("send");
            assert_eq!(resp.status, 200);
            let conf: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(
                conf.get("authResult").and_then(|v| v.as_str()),
                Some("AUTHENTICATION_FAILURE")
            );

            // Correct RES* -> AUTHENTICATION_SUCCESS with KSEAF
            let resp = client
                .put_json(
                    href,
                    &serde_json::json!({
                        "resStar": crate::nudm_handler::bytes_to_hex(&res_star)
                    }),
                )
                .await
                .expect("send");
            assert_eq!(resp.status, 200);
            let conf: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(
                conf.get("authResult").and_then(|v| v.as_str()),
                Some("AUTHENTICATION_SUCCESS")
            );
            // ausfd-04: SUPI_5G_AKA = "imsi-..." is not a SUCI → supi absent from response
            assert!(
                conf.get("supi").is_none(),
                "supi must be absent for SUPI-initiated auth (ausfd-04)"
            );
            let kseaf_hex = conf.get("kseaf").and_then(|v| v.as_str()).expect("kseaf");
            assert_eq!(kseaf_hex.len(), 64);

            // ---- EAP-AKA' success ----
            let resp = client
                .post_json(
                    "/nausf-auth/v1/ue-authentications",
                    &serde_json::json!({
                        "supiOrSuci": SUPI_EAP,
                        "servingNetworkName": TEST_SNN
                    }),
                )
                .await
                .expect("send");
            assert_eq!(resp.status, 201);
            let ctx_json: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().expect("body")).unwrap();
            assert_eq!(
                ctx_json.get("authType").and_then(|v| v.as_str()),
                Some("EAP_AKA_PRIME")
            );
            let eap_b64 = ctx_json
                .get("5gAuthData")
                .and_then(|v| v.as_str())
                .expect("eap payload");
            let eap_href = ctx_json
                .pointer("/_links/eap-session/href")
                .and_then(|v| v.as_str())
                .expect("eap-session link")
                .to_string();

            // UE side: decode the EAP-Request/AKA'-Challenge
            use crate::eap_aka_prime::{
                compute_mac, derive_keys_aka_prime, zero_at_mac, AkaPrimeAttribute,
                AkaPrimeSubtype, EapCode, EapPacket, EapType,
            };
            let challenge_bytes = nextgcore_crypt::base64::decode(eap_b64).expect("b64");
            let challenge = EapPacket::decode(&challenge_bytes).expect("decode");
            assert_eq!(challenge.code, EapCode::Request);
            assert_eq!(challenge.subtype, Some(AkaPrimeSubtype::Challenge));
            let at_rand = challenge.find_attribute(AkaPrimeAttribute::AtRand).unwrap();
            let at_autn = challenge.find_attribute(AkaPrimeAttribute::AtAutn).unwrap();
            let mut rand = [0u8; 16];
            rand.copy_from_slice(&at_rand[2..18]);
            let mut autn = [0u8; 16];
            autn.copy_from_slice(&at_autn[2..18]);

            // UE side: run Milenage + the RFC 5448 key schedule
            // (RES itself is unused in the failure-path exchange below)
            let (_res, ck, ik, _ak, _akstar) =
                nextgcore_crypt::milenage::milenage_f2345(&TEST_OPC, &TEST_K, &rand).unwrap();
            let mut sqn_xor_ak = [0u8; 6];
            sqn_xor_ak.copy_from_slice(&autn[..6]);
            let (ck_prime, ik_prime) =
                nextgcore_crypt::kdf::nextgcore_kdf_ck_ik_prime(&ck, &ik, TEST_SNN, &sqn_xor_ak);
            let ue_keys = derive_keys_aka_prime(&ck_prime, &ik_prime, SUPI_EAP);

            // UE side: verify the network's AT_MAC over the challenge
            let at_mac = challenge.find_attribute(AkaPrimeAttribute::AtMac).unwrap();
            let mut net_mac = [0u8; 16];
            net_mac.copy_from_slice(&at_mac[2..18]);
            let zeroed = zero_at_mac(&challenge_bytes).unwrap();
            assert_eq!(
                compute_mac(&ue_keys.k_aut, &zeroed),
                net_mac,
                "UE must be able to verify the network AT_MAC"
            );

            // Build EAP-Response/AKA'-Challenge with AT_RES + AT_MAC
            let build_eap_response = |res: &[u8], identifier: u8| -> Vec<u8> {
                let mut response = EapPacket {
                    code: EapCode::Response,
                    identifier,
                    eap_type: Some(EapType::AkaPrime),
                    subtype: Some(AkaPrimeSubtype::Challenge),
                    attributes: Vec::new(),
                };
                let res_bits = (res.len() * 8) as u16;
                let mut res_attr = Vec::new();
                res_attr.extend_from_slice(&res_bits.to_be_bytes());
                res_attr.extend_from_slice(res);
                response
                    .attributes
                    .push((AkaPrimeAttribute::AtRes as u8, res_attr));
                response
                    .attributes
                    .push((AkaPrimeAttribute::AtMac as u8, vec![0u8; 18]));
                let encoded = response.encode();
                let mac = compute_mac(&ue_keys.k_aut, &encoded);
                response.set_mac(&mac);
                response.encode()
            };

            // Failure first: wrong RES (valid MAC over that packet)
            let bad_response = build_eap_response(&[0xFFu8; 8], challenge.identifier);
            let resp = client
                .post_json(
                    &eap_href,
                    &serde_json::json!({
                        "eapPayload": nextgcore_crypt::base64::encode(&bad_response)
                    }),
                )
                .await
                .expect("send");
            assert_eq!(resp.status, 200);
            let sess: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(
                sess.get("authResult").and_then(|v| v.as_str()),
                Some("AUTHENTICATION_FAILURE")
            );
            // EAP-Failure packet returned
            let fail_payload = sess.get("eapPayload").and_then(|v| v.as_str()).unwrap();
            assert_eq!(nextgcore_crypt::base64::decode(fail_payload).unwrap()[0], 4);

            // Re-arm: a failed EAP exchange ends the session; start a new one
            let resp = client
                .post_json(
                    "/nausf-auth/v1/ue-authentications",
                    &serde_json::json!({
                        "supiOrSuci": SUPI_EAP,
                        "servingNetworkName": TEST_SNN
                    }),
                )
                .await
                .expect("send");
            assert_eq!(resp.status, 201);
            let ctx_json: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            let eap_b64 = ctx_json.get("5gAuthData").and_then(|v| v.as_str()).unwrap();
            let eap_href = ctx_json
                .pointer("/_links/eap-session/href")
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string();
            let challenge_bytes = nextgcore_crypt::base64::decode(eap_b64).unwrap();
            let challenge = EapPacket::decode(&challenge_bytes).unwrap();
            let at_rand = challenge.find_attribute(AkaPrimeAttribute::AtRand).unwrap();
            let at_autn = challenge.find_attribute(AkaPrimeAttribute::AtAutn).unwrap();
            let mut rand = [0u8; 16];
            rand.copy_from_slice(&at_rand[2..18]);
            let mut autn = [0u8; 16];
            autn.copy_from_slice(&at_autn[2..18]);
            let (res, ck, ik, _ak, _akstar) =
                nextgcore_crypt::milenage::milenage_f2345(&TEST_OPC, &TEST_K, &rand).unwrap();
            let mut sqn_xor_ak = [0u8; 6];
            sqn_xor_ak.copy_from_slice(&autn[..6]);
            let (ck_prime, ik_prime) =
                nextgcore_crypt::kdf::nextgcore_kdf_ck_ik_prime(&ck, &ik, TEST_SNN, &sqn_xor_ak);
            let ue_keys = derive_keys_aka_prime(&ck_prime, &ik_prime, SUPI_EAP);
            let build_eap_response2 = |res: &[u8], identifier: u8| -> Vec<u8> {
                let mut response = EapPacket {
                    code: EapCode::Response,
                    identifier,
                    eap_type: Some(EapType::AkaPrime),
                    subtype: Some(AkaPrimeSubtype::Challenge),
                    attributes: Vec::new(),
                };
                let res_bits = (res.len() * 8) as u16;
                let mut res_attr = Vec::new();
                res_attr.extend_from_slice(&res_bits.to_be_bytes());
                res_attr.extend_from_slice(res);
                response
                    .attributes
                    .push((AkaPrimeAttribute::AtRes as u8, res_attr));
                response
                    .attributes
                    .push((AkaPrimeAttribute::AtMac as u8, vec![0u8; 18]));
                let encoded = response.encode();
                let mac = compute_mac(&ue_keys.k_aut, &encoded);
                response.set_mac(&mac);
                response.encode()
            };
            let good_response = build_eap_response2(&res, challenge.identifier);
            let resp = client
                .post_json(
                    &eap_href,
                    &serde_json::json!({
                        "eapPayload": nextgcore_crypt::base64::encode(&good_response)
                    }),
                )
                .await
                .expect("send");
            assert_eq!(resp.status, 200);
            let sess: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(
                sess.get("authResult").and_then(|v| v.as_str()),
                Some("AUTHENTICATION_SUCCESS")
            );
            // ausfd-04: SUPI_EAP = "imsi-..." is not a SUCI → supi absent from response
            assert!(
                sess.get("supi").is_none(),
                "supi must be absent for SUPI-initiated EAP auth (ausfd-04)"
            );
            // EAP-Success packet returned
            let ok_payload = sess.get("eapPayload").and_then(|v| v.as_str()).unwrap();
            assert_eq!(nextgcore_crypt::base64::decode(ok_payload).unwrap()[0], 3);

            // UE side derives the same KSEAF: KAUSF = MSB256(EMSK)
            let mut ue_kausf = [0u8; 32];
            ue_kausf.copy_from_slice(&ue_keys.emsk[..32]);
            let ue_kseaf = nextgcore_crypt::kdf::nextgcore_kdf_kseaf(TEST_SNN, &ue_kausf);
            assert_eq!(
                sess.get("kSeaf").and_then(|v| v.as_str()),
                Some(crate::nudm_handler::bytes_to_hex(&ue_kseaf).as_str()),
                "AUSF KSEAF must match the UE-derived KSEAF"
            );

            ausf_server.stop().await.expect("stop ausf");
            udm_server.stop().await.expect("stop udm");
        })
        .await
        .expect("test timed out");
    }

    /// Acceptance tests for ausfd-01 / ausfd-03 / ausfd-04:
    ///
    /// - wrong-RES*                      → 200 AUTHENTICATION_FAILURE, kseaf absent, supi absent
    /// - correct-RES* with SUCI identity → 200 AUTHENTICATION_SUCCESS, kseaf (64 hex), supi present
    /// - correct-RES* with SUPI identity → 200 AUTHENTICATION_SUCCESS, kseaf present, supi absent
    /// - {"resStar": null}               → 200 AUTHENTICATION_FAILURE  (ausfd-03 null path)
    /// - {"resStar": "zz"}               → 400                         (ausfd-03 bad-hex path)
    #[tokio::test]
    async fn test_confirmation_response_shaping() {
        let _ = env_logger::try_init();
        let _lock = TEST_MUTEX.lock().await;

        tokio::time::timeout(Duration::from_secs(60), async {
            ausf_context_init(128);

            // Mock UDM
            let udm_port = free_port();
            let udm_server = SbiServer::new(NextgcoreSbiServerConfig::new(SocketAddr::from((
                [127, 0, 0, 1],
                udm_port,
            ))));
            udm_server.start(mock_udm_handler).await.expect("udm start");
            std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDM_SBI_PORT", udm_port.to_string());

            // Real AUSF handler
            let ausf_port = free_port();
            let ausf_server = SbiServer::new(NextgcoreSbiServerConfig::new(SocketAddr::from((
                [127, 0, 0, 1],
                ausf_port,
            ))));
            ausf_server
                .start(ausf_sbi_request_handler)
                .await
                .expect("ausf start");

            let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", ausf_port);

            // Identities distinct from the other integration test
            const SUCI_AKA: &str = "suci-0-001-01-0000-0-0-8888888801";
            const SUPI_AKA: &str = "imsi-001010008888801";

            // ----------------------------------------------------------------
            // Test: wrong-RES* → 200 AUTHENTICATION_FAILURE, kseaf absent, supi absent
            // ----------------------------------------------------------------
            let (href, _rand) = initiate_5g_aka(&client, SUCI_AKA, TEST_SNN).await;
            let resp = client
                .put_json(
                    &href,
                    &serde_json::json!({"resStar": "00000000000000000000000000000000"}),
                )
                .await
                .expect("PUT wrong RES*");
            assert_eq!(resp.status, 200, "wrong RES* must return 200");
            let body: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(
                body.get("authResult").and_then(|v| v.as_str()),
                Some("AUTHENTICATION_FAILURE"),
                "wrong RES* → AUTHENTICATION_FAILURE"
            );
            assert!(
                body.get("kseaf").is_none(),
                "kseaf must be absent on failure (ausfd-01)"
            );
            assert!(
                body.get("supi").is_none(),
                "supi must be absent on failure (ausfd-01)"
            );

            // ----------------------------------------------------------------
            // Test: correct-RES* (SUCI identity) → kseaf present (64 hex), supi present
            // ----------------------------------------------------------------
            let (href, rand) = initiate_5g_aka(&client, SUCI_AKA, TEST_SNN).await;
            let (res, ck, ik, _ak, _akstar) =
                nextgcore_crypt::milenage::milenage_f2345(&TEST_OPC, &TEST_K, &rand).unwrap();
            let res_star =
                nextgcore_crypt::kdf::nextgcore_kdf_xres_star(&ck, &ik, TEST_SNN, &rand, &res);
            let resp = client
                .put_json(
                    &href,
                    &serde_json::json!({
                        "resStar": crate::nudm_handler::bytes_to_hex(&res_star)
                    }),
                )
                .await
                .expect("PUT correct RES* SUCI");
            assert_eq!(resp.status, 200);
            let body: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(
                body.get("authResult").and_then(|v| v.as_str()),
                Some("AUTHENTICATION_SUCCESS"),
                "correct RES* (SUCI) → AUTHENTICATION_SUCCESS"
            );
            let kseaf = body
                .get("kseaf")
                .and_then(|v| v.as_str())
                .expect("kseaf must be present on SUCI success (ausfd-01)");
            assert_eq!(kseaf.len(), 64, "kseaf must be 64 hex chars");
            assert!(
                body.get("supi").is_some(),
                "supi must be present for SUCI-initiated success (ausfd-04)"
            );

            // ----------------------------------------------------------------
            // Test: correct-RES* (SUPI identity) → kseaf present, supi absent
            // ----------------------------------------------------------------
            let (href, rand) = initiate_5g_aka(&client, SUPI_AKA, TEST_SNN).await;
            let (res, ck, ik, _ak, _akstar) =
                nextgcore_crypt::milenage::milenage_f2345(&TEST_OPC, &TEST_K, &rand).unwrap();
            let res_star =
                nextgcore_crypt::kdf::nextgcore_kdf_xres_star(&ck, &ik, TEST_SNN, &rand, &res);
            let resp = client
                .put_json(
                    &href,
                    &serde_json::json!({
                        "resStar": crate::nudm_handler::bytes_to_hex(&res_star)
                    }),
                )
                .await
                .expect("PUT correct RES* SUPI");
            assert_eq!(resp.status, 200);
            let body: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(
                body.get("authResult").and_then(|v| v.as_str()),
                Some("AUTHENTICATION_SUCCESS"),
                "correct RES* (SUPI) → AUTHENTICATION_SUCCESS"
            );
            assert!(
                body.get("kseaf").is_some(),
                "kseaf must be present on SUPI success (ausfd-01)"
            );
            assert!(
                body.get("supi").is_none(),
                "supi must be absent for SUPI-initiated success (ausfd-04)"
            );

            // ----------------------------------------------------------------
            // Test: {"resStar": null} → 200 AUTHENTICATION_FAILURE  (ausfd-03 null path)
            // ----------------------------------------------------------------
            let (href, _rand) = initiate_5g_aka(&client, SUCI_AKA, TEST_SNN).await;
            let resp = client
                .put_json(&href, &serde_json::json!({"resStar": null}))
                .await
                .expect("PUT resStar:null");
            assert_eq!(resp.status, 200, "null resStar must return 200 (ausfd-03)");
            let body: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(
                body.get("authResult").and_then(|v| v.as_str()),
                Some("AUTHENTICATION_FAILURE"),
                "null resStar → AUTHENTICATION_FAILURE (ausfd-03)"
            );
            assert!(body.get("kseaf").is_none(), "kseaf absent on null resStar");
            assert!(body.get("supi").is_none(), "supi absent on null resStar");

            // ----------------------------------------------------------------
            // Test: {"resStar": "zz"} → 400 INVALID_REQUEST (ausfd-03 bad-hex path)
            // ----------------------------------------------------------------
            let (href, _rand) = initiate_5g_aka(&client, SUCI_AKA, TEST_SNN).await;
            let resp = client
                .put_json(&href, &serde_json::json!({"resStar": "zz"}))
                .await
                .expect("PUT resStar:zz");
            assert_eq!(
                resp.status, 400,
                "bad-hex resStar must return 400 (ausfd-03)"
            );

            ausf_server.stop().await.expect("stop ausf");
            udm_server.stop().await.expect("stop udm");
        })
        .await
        .expect("test_confirmation_response_shaping timed out");
    }

    // ====================================================================
    // ausfd-07: avType vs authType validation
    // ====================================================================
    #[test]
    fn test_validate_av_type() {
        // Matching pairs are accepted.
        assert!(validate_av_type("5G_AKA", Some("5G_HE_AKA")).is_ok());
        assert!(validate_av_type("EAP_AKA_PRIME", Some("EAP_AKA_PRIME")).is_ok());
        // Absent avType is permissive (optional field).
        assert!(validate_av_type("5G_AKA", None).is_ok());
        // Mismatches are rejected.
        assert!(validate_av_type("5G_AKA", Some("EAP_AKA_PRIME")).is_err());
        assert!(validate_av_type("EAP_AKA_PRIME", Some("5G_HE_AKA")).is_err());
    }

    // ====================================================================
    // ausfd-09: outgoing Nudm body carries the resolved NF instance id
    // ====================================================================
    #[test]
    fn test_build_generate_auth_data_body_uses_instance_id() {
        let body = build_generate_auth_data_body(
            "5G:mnc001.mcc001.3gppnetwork.org",
            "ausf-7c9e-real-instance-id",
            None,
        );
        assert_eq!(
            body.get("ausfInstanceId").and_then(|v| v.as_str()),
            Some("ausf-7c9e-real-instance-id"),
            "body must carry the resolved (real) NF instance id, not a literal"
        );
        assert_eq!(
            body.get("servingNetworkName").and_then(|v| v.as_str()),
            Some("5G:mnc001.mcc001.3gppnetwork.org")
        );
        assert!(body.get("resynchronizationInfo").is_none());

        // With resync info present.
        let resync = crate::ResynchronizationInfo {
            rand: "0123456789abcdef0123456789abcdef".to_string(),
            auts: "fedcba9876543210fedcba98765432".to_string(),
        };
        let body = build_generate_auth_data_body(
            "5G:mnc001.mcc001.3gppnetwork.org",
            "id-2",
            Some(&resync),
        );
        assert!(body.get("resynchronizationInfo").is_some());
    }

    // ====================================================================
    // ausfd-05: consumer PLMN extraction from an OAuth2 access token
    // ====================================================================
    #[test]
    fn test_extract_consumer_plmns() {
        // Build a JWT-shaped token whose payload carries a plmnList claim.
        let payload = serde_json::json!({"plmnList": [{"mcc": "208", "mnc": "093"}]}).to_string();
        let payload_b64 = nextgcore_crypt::base64::encode(payload.as_bytes());
        let token = format!("Bearer hdr.{payload_b64}.sig");
        let plmns = extract_consumer_plmns(&token);
        assert_eq!(plmns, vec![("208".to_string(), "093".to_string())]);

        // No token / no plmnList -> empty (default-permissive).
        assert!(extract_consumer_plmns("Bearer hdr.e30.sig").is_empty()); // {} payload
        assert!(extract_consumer_plmns("not-a-token").is_empty());
    }

    // ====================================================================
    // ausfd-08: DELETE cleans up the context (204), second DELETE -> 404
    // ====================================================================
    #[tokio::test]
    async fn test_auth_context_delete_lifecycle() {
        let _lock = TEST_MUTEX.lock().await;
        ausf_context_init(128);

        let ctx_id = {
            let ctx = ausf_self();
            let guard = ctx.read().expect("ctx read");
            let ue = guard
                .ue_add("suci-0-001-01-0000-0-0-7777777701")
                .expect("ue_add");
            ue.ctx_id
        };

        // Present before delete.
        assert!(ausf_self()
            .read()
            .unwrap()
            .ue_find_by_ctx_id(&ctx_id)
            .is_some());

        // DELETE -> 204 and context removed.
        let resp = handle_auth_context_delete(&ctx_id).await;
        assert_eq!(resp.status, 204, "first DELETE must return 204");
        assert!(
            ausf_self()
                .read()
                .unwrap()
                .ue_find_by_ctx_id(&ctx_id)
                .is_none(),
            "context must be gone after DELETE"
        );

        // Second DELETE -> 404.
        let resp = handle_auth_context_delete(&ctx_id).await;
        assert_eq!(resp.status, 404, "second DELETE must return 404");
    }

    // ====================================================================
    // F-02: SoR/UPU anchor (TS 33.501 §6.14.1) — populated by a REAL 5G-AKA
    // confirmation through the production handler, and SURVIVES the real
    // handle_auth_context_delete (auth → delete ctx → anchor still there).
    // ====================================================================
    #[tokio::test]
    async fn test_sor_upu_anchor_survives_auth_context_delete() {
        let _ = env_logger::try_init();
        let _lock = TEST_MUTEX.lock().await;

        tokio::time::timeout(Duration::from_secs(60), async {
            ausf_context_init(128);

            // Mock UDM (real Milenage + 5G KDFs) + real AUSF handler.
            let udm_port = free_port();
            let udm_server = SbiServer::new(NextgcoreSbiServerConfig::new(SocketAddr::from((
                [127, 0, 0, 1],
                udm_port,
            ))));
            udm_server.start(mock_udm_handler).await.expect("udm start");
            std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDM_SBI_PORT", udm_port.to_string());

            let ausf_port = free_port();
            let ausf_server = SbiServer::new(NextgcoreSbiServerConfig::new(SocketAddr::from((
                [127, 0, 0, 1],
                ausf_port,
            ))));
            ausf_server
                .start(ausf_sbi_request_handler)
                .await
                .expect("ausf start");
            let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", ausf_port);

            // Fresh SUPI so earlier tests cannot have seeded an anchor.
            let supi = "imsi-001010000000777";
            assert!(
                ausf_self()
                    .read()
                    .unwrap()
                    .anchor_lookup_kausf(supi)
                    .is_none(),
                "no anchor before authentication"
            );

            // Real 5G-AKA flow: initiate, compute RES* UE-side, confirm.
            let (href, rand) = initiate_5g_aka(&client, supi, TEST_SNN).await;
            let (res, ck, ik, _ak, _akstar) =
                nextgcore_crypt::milenage::milenage_f2345(&TEST_OPC, &TEST_K, &rand).unwrap();
            let res_star =
                nextgcore_crypt::kdf::nextgcore_kdf_xres_star(&ck, &ik, TEST_SNN, &rand, &res);
            let resp = client
                .put_json(
                    &href,
                    &serde_json::json!({
                        "resStar": crate::nudm_handler::bytes_to_hex(&res_star)
                    }),
                )
                .await
                .expect("confirmation");
            assert_eq!(resp.status, 200);
            let conf: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(
                conf.get("authResult").and_then(|v| v.as_str()),
                Some("AUTHENTICATION_SUCCESS")
            );

            // The production success hook stored the anchor with the UE's
            // KAUSF (TS 33.501 §6.14.1 "store the latest K_AUSF").
            let ue = ausf_self()
                .read()
                .unwrap()
                .ue_find_by_supi(supi)
                .expect("UE context after confirm");
            let anchor_kausf = ausf_self()
                .read()
                .unwrap()
                .anchor_lookup_kausf(supi)
                .expect("anchor after successful primary auth");
            assert_eq!(anchor_kausf, ue.kausf, "anchor must hold the UE's KAUSF");
            assert_ne!(anchor_kausf, [0u8; 32], "anchor KAUSF must not be zero");

            // AMF-style teardown: DELETE the auth context via the REAL handler.
            // href = /nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka
            let ctx_id = href
                .split('/')
                .nth(4)
                .expect("authCtxId in href")
                .to_string();
            let resp = handle_auth_context_delete(&ctx_id).await;
            assert_eq!(resp.status, 204, "DELETE must succeed");
            assert!(
                ausf_self()
                    .read()
                    .unwrap()
                    .ue_find_by_supi(supi)
                    .is_none(),
                "auth context must be gone (zeroized) after DELETE"
            );

            // §6.14.1: the anchor SURVIVES the auth-context deletion...
            let survived = ausf_self()
                .read()
                .unwrap()
                .anchor_lookup_kausf(supi)
                .expect("anchor must survive handle_auth_context_delete");
            assert_eq!(survived, anchor_kausf, "retained KAUSF unchanged");

            // ...and the counter lifecycle still works (first MAC would use
            // 0x0001, next 0x0002 — §6.14.2.3).
            let guard = ausf_self();
            let guard = guard.read().unwrap();
            assert_eq!(guard.anchor_next_sor_counter(supi), Ok(0x0001));
            assert_eq!(guard.anchor_next_sor_counter(supi), Ok(0x0002));
            assert_eq!(guard.anchor_next_upu_counter(supi), Ok(0x0001));
        })
        .await
        .expect("test timed out");
    }

    // ====================================================================
    // ausfd-05: serving-network-name entitlement vs consumer token PLMN
    // ====================================================================
    #[tokio::test]
    async fn test_snn_entitlement_against_consumer_token() {
        let _ = env_logger::try_init();
        let _lock = TEST_MUTEX.lock().await;

        tokio::time::timeout(Duration::from_secs(60), async {
            ausf_context_init(128);

            // Mock UDM (so the permissive/matching case can reach 201).
            let udm_port = free_port();
            let udm_server = SbiServer::new(NextgcoreSbiServerConfig::new(SocketAddr::from((
                [127, 0, 0, 1],
                udm_port,
            ))));
            udm_server.start(mock_udm_handler).await.expect("udm start");
            std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDM_SBI_PORT", udm_port.to_string());

            // Real AUSF handler.
            let ausf_port = free_port();
            let ausf_server = SbiServer::new(NextgcoreSbiServerConfig::new(SocketAddr::from((
                [127, 0, 0, 1],
                ausf_port,
            ))));
            ausf_server
                .start(ausf_sbi_request_handler)
                .await
                .expect("ausf start");
            let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", ausf_port);

            // TEST_SNN PLMN is (mcc=001, mnc=001).
            let bearer = |mcc: &str, mnc: &str| -> String {
                let payload =
                    serde_json::json!({"plmnList": [{"mcc": mcc, "mnc": mnc}]}).to_string();
                format!(
                    "Bearer h.{}.s",
                    nextgcore_crypt::base64::encode(payload.as_bytes())
                )
            };

            // Foreign PLMN in the token -> 403 SERVING_NETWORK_NOT_AUTHORIZED.
            let req = nextgcore_sbi::message::SbiRequest::post("/nausf-auth/v1/ue-authentications")
                .with_header("Authorization", bearer("208", "093"))
                .with_json_body(&serde_json::json!({
                    "supiOrSuci": SUPI_5G_AKA,
                    "servingNetworkName": TEST_SNN
                }))
                .expect("build request");
            let resp = client.send_request(req).await.expect("send");
            assert_eq!(resp.status, 403, "foreign-PLMN token must be rejected");
            let pd: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap();
            assert_eq!(
                pd.get("cause").and_then(|v| v.as_str()),
                Some("SERVING_NETWORK_NOT_AUTHORIZED")
            );

            // Matching PLMN in the token -> entitlement passes (201).
            let req = nextgcore_sbi::message::SbiRequest::post("/nausf-auth/v1/ue-authentications")
                .with_header("Authorization", bearer("001", "001"))
                .with_json_body(&serde_json::json!({
                    "supiOrSuci": SUPI_5G_AKA,
                    "servingNetworkName": TEST_SNN
                }))
                .expect("build request");
            let resp = client.send_request(req).await.expect("send");
            assert_eq!(resp.status, 201, "matching-PLMN token must be authorized");

            // No token at all -> default-permissive (201).
            let resp = client
                .post_json(
                    "/nausf-auth/v1/ue-authentications",
                    &serde_json::json!({
                        "supiOrSuci": SUPI_5G_AKA,
                        "servingNetworkName": TEST_SNN
                    }),
                )
                .await
                .expect("send");
            assert_eq!(resp.status, 201, "token-less peer must remain permissive");

            ausf_server.stop().await.expect("stop ausf");
            udm_server.stop().await.expect("stop udm");
        })
        .await
        .expect("test_snn_entitlement_against_consumer_token timed out");
    }

    // ====================================================================
    // F-03: Nausf_SoRProtection / Nausf_UPUProtection producers
    // ====================================================================

    /// The NRF registration profile must advertise both TS 29.509 protection
    /// services (falsifiable acceptance: grep for 'nausf-sorprotection') and
    /// allow UDM, their consumer (TS 33.501 §6.14.2.1 step 8).
    #[test]
    fn test_nf_profile_advertises_sor_and_upu_protection_services() {
        let profile = build_nf_profile("test-instance", "127.0.0.1", 7777);

        let service_names: Vec<&str> = profile["nfServices"]
            .as_array()
            .expect("nfServices array")
            .iter()
            .filter_map(|s| s.get("serviceName").and_then(|v| v.as_str()))
            .collect();
        assert!(service_names.contains(&"nausf-auth"));
        assert!(
            service_names.contains(&"nausf-sorprotection"),
            "NF profile must advertise nausf-sorprotection: {service_names:?}"
        );
        assert!(
            service_names.contains(&"nausf-upuprotection"),
            "NF profile must advertise nausf-upuprotection: {service_names:?}"
        );

        let allowed: Vec<&str> = profile["allowedNfTypes"]
            .as_array()
            .expect("allowedNfTypes array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            allowed.contains(&"UDM"),
            "UDM (SoR/UPU consumer) must be in allowedNfTypes: {allowed:?}"
        );

        // Every advertised service carries a versioned endpoint.
        for svc in profile["nfServices"].as_array().unwrap() {
            assert_eq!(svc["versions"][0]["apiVersionInUri"], "v1");
            assert_eq!(svc["ipEndPoints"][0]["port"], 7777);
        }
    }

    /// curl-shaped acceptance test for F-03: a real 5G-AKA authentication
    /// seeds the anchor through the production path, then the SoR and UPU
    /// custom operations are exercised over HTTP against the REAL dispatcher
    /// (`ausf_sbi_request_handler`) — no handler shortcuts.
    ///
    /// The MAC assertions recompute the expected values from the anchor's
    /// KAUSF and HAND-DERIVED wire bytes (TS 24.501 §9.11.3.51 /
    /// §9.11.3.53A), so a corrupted steering-list encoder fails this test.
    #[tokio::test]
    async fn test_sor_upu_protection_http_end_to_end() {
        let _ = env_logger::try_init();
        let _lock = TEST_MUTEX.lock().await;

        tokio::time::timeout(Duration::from_secs(60), async {
            ausf_context_init(128);

            // Mock UDM (real Milenage + 5G KDFs) + real AUSF dispatcher.
            let udm_port = free_port();
            let udm_server = SbiServer::new(NextgcoreSbiServerConfig::new(SocketAddr::from((
                [127, 0, 0, 1],
                udm_port,
            ))));
            udm_server.start(mock_udm_handler).await.expect("udm start");
            std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDM_SBI_PORT", udm_port.to_string());

            let ausf_port = free_port();
            let ausf_server = SbiServer::new(NextgcoreSbiServerConfig::new(SocketAddr::from((
                [127, 0, 0, 1],
                ausf_port,
            ))));
            ausf_server
                .start(ausf_sbi_request_handler)
                .await
                .expect("ausf start");
            let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", ausf_port);

            // ---- Seed the anchor via a REAL 5G-AKA flow (fresh SUPI). ----
            let supi = "imsi-001010000000888";
            let (href, rand) = initiate_5g_aka(&client, supi, TEST_SNN).await;
            let (res, ck, ik, _ak, _akstar) =
                nextgcore_crypt::milenage::milenage_f2345(&TEST_OPC, &TEST_K, &rand).unwrap();
            let res_star =
                nextgcore_crypt::kdf::nextgcore_kdf_xres_star(&ck, &ik, TEST_SNN, &rand, &res);
            let resp = client
                .put_json(
                    &href,
                    &serde_json::json!({
                        "resStar": crate::nudm_handler::bytes_to_hex(&res_star)
                    }),
                )
                .await
                .expect("confirmation");
            assert_eq!(resp.status, 200);
            let kausf = ausf_self()
                .read()
                .unwrap()
                .anchor_lookup_kausf(supi)
                .expect("anchor after successful primary auth");

            // ---- SoR: POST /nausf-sorprotection/v1/{supi}/ue-sor ----
            // Hand-derived P2 (TS 24.501 fig. 9.11.3.51.3 + TS 31.102
            // §4.2.5): mcc=001 mnc=01 → 00 F1 10, NR → 08 00;
            // mcc=310 mnc=410 → 13 00 14, NR|E-UTRAN → 48 00.
            const GOLDEN_P2: [u8; 10] =
                [0x00, 0xF1, 0x10, 0x08, 0x00, 0x13, 0x00, 0x14, 0x48, 0x00];
            let sor_body = serde_json::json!({
                "ackInd": true,
                "steeringContainer": [
                    {"plmnId": {"mcc": "001", "mnc": "01"}, "accessTechList": ["NR"]},
                    {"plmnId": {"mcc": "310", "mnc": "410"},
                     "accessTechList": ["NR", "EUTRAN_IN_WBS1_MODE_AND_NBS1_MODE"]}
                ]
            });
            let sor_path = format!("/nausf-sorprotection/v1/{supi}/ue-sor");
            let resp = client.post_json(&sor_path, &sor_body).await.expect("sor");
            assert_eq!(resp.status, 200, "SoR body: {:?}", resp.http.content);
            let sor: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();

            // First MAC after the fresh KAUSF uses Counter_SoR 0x0001
            // (TS 33.501 §6.14.2.3); header 0x0E = ack + list ind + PLMN
            // list type (TS 24.501 fig. 9.11.3.51.5).
            assert_eq!(sor["counterSor"], "0001");
            let expected_mac = nextgcore_crypt::kdf::nextgcore_kdf_sor_mac_iausf(
                &kausf,
                &[0x0E],
                0x0001,
                Some(&GOLDEN_P2),
            );
            assert_eq!(
                crate::nudm_handler::hex_to_bytes(sor["sorMacIausf"].as_str().unwrap()),
                expected_mac.to_vec(),
                "sorMacIausf must be reproducible from KAUSF + documented S-string"
            );
            let expected_xmac =
                nextgcore_crypt::kdf::nextgcore_kdf_sor_mac_iue(&kausf, 0x0001);
            assert_eq!(
                crate::nudm_handler::hex_to_bytes(sor["sorXmacIue"].as_str().unwrap()),
                expected_xmac.to_vec()
            );

            // Freshness: second call → counter 0x0002 and a different MAC
            // over identical input.
            let resp = client.post_json(&sor_path, &sor_body).await.expect("sor2");
            assert_eq!(resp.status, 200);
            let sor2: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(sor2["counterSor"], "0002");
            assert_ne!(sor2["sorMacIausf"], sor["sorMacIausf"]);

            // ---- UPU: POST /nausf-upuprotection/v1/{supi}/ue-upu ----
            // Hand-derived P0 (TS 24.501 fig. 9.11.3.53A.2): ME routing
            // indicator "1234" → 04 0002 21 43; default configured NSSAI
            // [{sst:1},{sst:2,sd:00007B}] → 02 0007 01 01 04 02 00 00 7B.
            const GOLDEN_UPU: [u8; 15] = [
                0x04, 0x00, 0x02, 0x21, 0x43, 0x02, 0x00, 0x07, 0x01, 0x01, 0x04, 0x02, 0x00,
                0x00, 0x7B,
            ];
            let upu_body = serde_json::json!({
                "upuAckInd": true,
                "upuDataList": [
                    {"routingId": "1234"},
                    {"defaultConfNssai": [{"sst": 1}, {"sst": 2, "sd": "00007B"}]}
                ]
            });
            let upu_path = format!("/nausf-upuprotection/v1/{supi}/ue-upu");
            let resp = client.post_json(&upu_path, &upu_body).await.expect("upu");
            assert_eq!(resp.status, 200, "UPU body: {:?}", resp.http.content);
            let upu: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(upu["counterUpu"], "0001");
            let expected_mac = nextgcore_crypt::kdf::nextgcore_kdf_upu_mac_iausf(
                &kausf,
                &GOLDEN_UPU,
                0x0001,
            );
            assert_eq!(
                crate::nudm_handler::hex_to_bytes(upu["upuMacIausf"].as_str().unwrap()),
                expected_mac.to_vec(),
                "upuMacIausf must be reproducible from KAUSF + documented S-string"
            );
            let expected_xmac =
                nextgcore_crypt::kdf::nextgcore_kdf_upu_mac_iue(&kausf, 0x0001);
            assert_eq!(
                crate::nudm_handler::hex_to_bytes(upu["upuXmacIue"].as_str().unwrap()),
                expected_xmac.to_vec()
            );

            // ---- Fail-closed over the wire ----
            // Unknown SUPI → 404 CONTEXT_NOT_FOUND, never a MAC.
            let resp = client
                .post_json("/nausf-sorprotection/v1/imsi-001019999999999/ue-sor", &sor_body)
                .await
                .expect("sor 404");
            assert_eq!(resp.status, 404);
            let pd: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap();
            assert_eq!(pd["cause"], "CONTEXT_NOT_FOUND");
            assert!(pd.get("sorMacIausf").is_none());
            let resp = client
                .post_json("/nausf-upuprotection/v1/imsi-001019999999999/ue-upu", &upu_body)
                .await
                .expect("upu 404");
            assert_eq!(resp.status, 404);

            // Missing mandatory IE → 400 MANDATORY_IE_MISSING.
            let resp = client
                .post_json(&sor_path, &serde_json::json!({"steeringContainer": []}))
                .await
                .expect("sor 400");
            assert_eq!(resp.status, 400);
            let pd: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap();
            assert_eq!(pd["cause"], "MANDATORY_IE_MISSING");
            let resp = client
                .post_json(&upu_path, &serde_json::json!({"upuAckInd": true}))
                .await
                .expect("upu 400");
            assert_eq!(resp.status, 400);

            // Wrong method on the custom op → 405 catch-all.
            let resp = client.get(&sor_path).await.expect("sor GET");
            assert_eq!(resp.status, 405);

            ausf_server.stop().await.expect("stop ausf");
            udm_server.stop().await.expect("stop udm");
        })
        .await
        .expect("test_sor_upu_protection_http_end_to_end timed out");
    }
}

#[cfg(test)]
mod oauth2_h8_tests {
    //! Wave-6 H8 (Phase B) strict-peer OAuth2 enforcement triplet: the real
    //! `ausf_sbi_request_handler` is mounted behind nextgcore-sbi's server-side
    //! OAuth2 verification (TS 33.501 §13.4.1). A missing or wrong-audience
    //! Bearer is rejected (401) before the handler runs; a valid NRF-audience
    //! token (aud=AUSF, ES256-signed against the served JWKS) passes through.
    use nextgcore_sbi::client::SbiClient;
    use nextgcore_sbi::message::SbiRequest;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use nextgcore_sbi::types::NfType;
    use std::net::SocketAddr;
    use std::time::Duration;

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn build_es256_token(sk: &p256::ecdsa::SigningKey, kid: &str, aud: &str, scope: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use p256::ecdsa::{signature::Signer, Signature};
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let header = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{kid}"}}"#);
        let claims = serde_json::json!({
            "iss": "NRF", "sub": "ausf-1", "aud": aud,
            "scope": scope, "exp": exp, "iat": 0
        })
        .to_string();
        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
        let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{h}.{p}.{s}")
    }

    fn jwks_for(sk: &p256::ecdsa::SigningKey, kid: &str) -> serde_json::Value {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let point = sk.verifying_key().to_encoded_point(false);
        serde_json::json!({"keys":[{
            "kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":kid,
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }]})
    }

    async fn start_server(jwks: serde_json::Value) -> (SbiServer, u16) {
        super::ausf_context_init(64);
        let port = free_port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Ausf);
        let server = SbiServer::new(cfg);
        server
            .start(super::ausf_sbi_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    #[test]
    fn test_oauth2_require_knob_parses_and_defaults_off() {
        let dir = std::env::temp_dir();
        let off = dir.join(format!("ausf-h8-off-{}.yaml", std::process::id()));
        std::fs::write(&off, "ausf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n").unwrap();
        assert!(!super::oauth2_required(off.to_str().unwrap()));
        let on = dir.join(format!("ausf-h8-on-{}.yaml", std::process::id()));
        std::fs::write(&on, "ausf:\n  sbi:\n    oauth2:\n      require: true\n").unwrap();
        assert!(super::oauth2_required(on.to_str().unwrap()));
        let _ = std::fs::remove_file(off);
        let _ = std::fs::remove_file(on);
    }

    #[tokio::test]
    async fn test_oauth2_missing_token_rejected_401() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (server, port) = start_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            client.get("/nausf-auth/v1/ue-authentications"),
        )
        .await
        .expect("bounded")
        .expect("response");
        assert_eq!(resp.status, 401, "unauthenticated request must be 401");
        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_oauth2_wrong_audience_rejected_401() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (server, port) = start_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let token = build_es256_token(&sk, "nrf-es256", "UDM", "nausf-auth");
        let req = SbiRequest::get("/nausf-auth/v1/ue-authentications")
            .with_header("Authorization", format!("Bearer {token}"));
        let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
            .await
            .expect("bounded")
            .expect("response");
        assert_eq!(resp.status, 401, "wrong-audience token must be 401");
        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_oauth2_valid_token_reaches_handler() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (server, port) = start_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let token = build_es256_token(&sk, "nrf-es256", "AUSF", "nausf-auth");
        let req = SbiRequest::get("/nausf-auth/v1/ue-authentications/does-not-exist")
            .with_header("Authorization", format!("Bearer {token}"));
        let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
            .await
            .expect("bounded")
            .expect("response");
        assert_ne!(resp.status, 401, "valid token must not be 401");
        assert_ne!(resp.status, 403, "valid token must not be 403");
        server.stop().await.expect("stop");
    }
}
