//! NextGCore AUSF (Authentication Server Function)
//!
//! The AUSF is a 5G core network function responsible for:
//! - UE authentication
//! - Authentication vector generation
//! - Key derivation (KAUSF, KSEAF)
//! - Authentication result confirmation

use crate::{
    ausf_context_final, ausf_context_init, ausf_sbi_close, ausf_sbi_open, ausf_self, timer_manager,
    AusfEvent, AusfSmContext, SbiServerConfig,
};
use anyhow::{Context, Result};
use clap::Parser;
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

    /// Log level (trace, debug, info, warn, error). Without it, the config
    /// file's `logger.level`, else `info`; `RUST_LOG` overrides (#691).
    #[arg(short = 'e', long)]
    log_level: Option<String>,

    /// Disable color output
    #[arg(short = 'm', long)]
    no_color: bool,

    /// Kill a running instance (NOT SUPPORTED: exits with an error;
    /// stop the NF through its supervisor)
    #[arg(short = 'k', long)]
    kill: bool,

    /// SBI bind address. Without it, `ausf.sbi.server[0].address`, else
    /// 127.0.0.1 (#1308, #1312): the command line overrides the config file.
    #[arg(long)]
    sbi_addr: Option<String>,

    /// The SBI host advertised in the NRF NFProfile and callback URIs. Without it,
    /// `NEXTGCORE_SBI_ADVERTISE`, else `ausf.sbi.server[0].advertise`, else the
    /// bind address; a wildcard is never advertised (#1312).
    #[arg(long)]
    sbi_advertise: Option<String>,

    /// SBI server port. Without it, `ausf.sbi.server[0].port`, else 7777.
    #[arg(long)]
    sbi_port: Option<u16>,

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
    /// The host advertised to the NRF and in callback URIs (#1312).
    advertise: Option<String>,
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
/// Phase A). Outbound SBI clients attach a token via [`peer_client`].
fn oauth2_client() -> Option<Arc<nextgcore_sbi::oauth::OAuth2Client>> {
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

/// Build an outbound peer SBI client for `host:port` (Wave-6 H8 Phase A).
///
/// When OAuth2 enforcement is ON, returns a fresh client carrying an NRF-issued
/// Bearer token scoped to `target` (TS 33.501 §13.4.1, TS 29.510 §5.4.2). When
/// OFF (the default), returns the process-wide pooled client unchanged, so the
/// matched-sim default path is byte-identical.
async fn peer_client(
    host: &str,
    port: u16,
    target: nextgcore_sbi::types::NfType,
) -> Arc<nextgcore_sbi::client::SbiClient> {
    match oauth2_client() {
        Some(oauth2) => Arc::new(
            nextgcore_sbi::client::SbiClient::new(nextgcore_sbi::security::sbi_peer_client_config(
                host, port,
            ))
            .with_oauth2(oauth2, target),
        ),
        None => {
            nextgcore_sbi::context::global_context()
                .get_client(host, port)
                .await
        }
    }
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
    cfg.oauth2_jwks_uri = nrf_uri.as_deref().map(|uri| {
        nextgcore_sbi::oauth::JwksCache::for_nrf(uri)
            .jwks_uri()
            .to_string()
    });
    cfg = cfg.with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Ausf);
    // #1964: nrfd pins a resource-scoped token's `aud` to the AUSF instances it
    // evaluated the scope over, so this AUSF accepts its own instance ID too.
    cfg = cfg.with_expected_audience_instance(
        nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Ausf)
            .to_string(),
    );
    if let Some(uri) = nrf_uri.as_deref() {
        let nf_instance_id =
            nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Ausf)
                .to_string();
        let _ = OAUTH2_CLIENT.set(Some(Arc::new(nextgcore_sbi::oauth::OAuth2Client::new(
            uri,
            nf_instance_id,
            nextgcore_sbi::types::NfType::Ausf,
        ))));
        // #1667: the same client gives this NF's own NRF calls their access token.
        nextgcore_sbi::nrf_tls::set_nrf_oauth2_client(OAUTH2_CLIENT.get().cloned().flatten());
    }
    log::info!(
        "OAuth2 enforcement enabled (JWKS: {})",
        cfg.oauth2_jwks_uri.as_deref().unwrap_or("UNCONFIGURED")
    );
    cfg
}

#[tokio::main]
pub async fn run() -> Result<()> {
    let args = Args::parse();

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

    // Issue: `--kill` was advertised as "Kill running instance" and did
    // NOTHING -- it logged an intention and returned success, so the process
    // exited 0 while the instance kept serving. Fail loudly instead.
    if args.kill {
        return Err(nextgcore_core::signal::kill_unsupported().into());
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
    // #1312: the YAML `server[0]`, used once the command line has had its say.
    let mut yaml_sbi = nextgcore_core::sockaddr::YamlServer::default();
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
                // Seed NRF URI into SBI context for NF registration
                {
                    // #1313 review: a config that does not parse fails startup
                    // rather than falling back to the defaults (the bind among them).
                    let yaml: AusfYaml = serde_yaml::from_str(&content).map_err(|e| {
                        anyhow::anyhow!("configuration file {} does not parse: {e}", args.config)
                    })?;
                    if let Some(ausf) = yaml.ausf {
                        if let Some(sbi) = ausf.sbi {
                            // Override the advertised/bind SBI address with the
                            // routable address from config so the NRF NFProfile
                            // advertises a reachable endpoint (not 0.0.0.0).
                            if let Some(server) = sbi.server.as_ref().and_then(|s| s.first()) {
                                yaml_sbi = nextgcore_core::sockaddr::YamlServer {
                                    address: server.address.clone(),
                                    port: server.port,
                                    advertise: server.advertise.clone(),
                                };
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
    // #1312: bind CLI, then YAML, then loopback; advertise --sbi-advertise, then
    // NEXTGCORE_SBI_ADVERTISE, then the YAML advertise, then the bind (never a wildcard).
    let sbi = nextgcore_core::sockaddr::SbiEndpoint::resolve(
        args.sbi_addr.as_deref(),
        args.sbi_port,
        args.sbi_advertise.as_deref(),
        yaml_sbi.address.as_deref(),
        yaml_sbi.port,
        yaml_sbi.advertise.as_deref(),
        7777,
    );
    let sbi_config = SbiServerConfig {
        addr: sbi.host.clone(),
        port: sbi.port,
        tls_enabled: args.tls,
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
    };

    // Open legacy SBI server (for context initialization)
    ausf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using nextgcore-sbi
    let sbi_addr: SocketAddr = nextgcore_core::sockaddr::parse_listen_addr(&sbi.host, sbi.port)
        .context("Invalid SBI address")?;
    // #1308: loopback by default; say which setting opens it to remote peers.
    nextgcore_core::sockaddr::warn_if_loopback_listener(
        "SBI",
        &sbi_addr,
        "--sbi-addr (or ausf.sbi.server[0].address in the config file)",
    );
    let mut sbi_server_config = NextgcoreSbiServerConfig::new(sbi_addr);
    // Issue #63: resolve the SBI security profile, PRODUCTION by default. The
    // production profile requires OAuth2, so the outbound token client is
    // installed too -- a producer that demands tokens must also present them.
    let sbi_profile = nextgcore_sbi::security::SbiProfile::resolve();
    if sbi_profile.is_production() || oauth2_required(&args.config) {
        sbi_server_config = apply_oauth2_enforcement(sbi_server_config).await;
    }
    let nrf_uri = nextgcore_sbi::context::global_context()
        .get_nrf_uri()
        .await
        .unwrap_or_default();
    sbi_server_config = nextgcore_sbi::security::apply_sbi_security_profile(
        sbi_server_config,
        sbi_profile,
        nextgcore_sbi::types::NfType::Ausf,
        &nrf_uri,
    )?;
    // #1791: the NFProfile advertises the scheme this listener serves.
    let sbi_scheme = sbi_server_config.scheme;
    let sbi_server = SbiServer::new(sbi_server_config);

    sbi_server
        .start(ausf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("SBI HTTP/2 server listening on {sbi_addr}");

    // #1334: the Prometheus endpoint, on NEXTGCORE_METRICS_BIND (loopback by default,
    // #837) and AUSF_METRICS_PORT (9090). Non-fatal, like smfd's.
    let _metrics = nextgcore_metrics::nf::serve_nf_metrics(
        "AUSF",
        "AUSF_METRICS_PORT",
        std::sync::Arc::new(crate::metrics::render_prometheus),
    )
    .await;

    // Register with NRF (B23.4). #1482: a failed attempt is retried in the
    // background, and the heartbeat starts after the one that succeeds.
    match sbi.registration_host() {
        Ok(host) => {
            let (host, port) = (host.to_string(), sbi.port);
            nextgcore_sbi::heartbeat::register_or_retry(
                "AUSF",
                Default::default(),
                move || {
                    let host = host.clone();
                    async move {
                        register_with_nrf(&host, port, sbi_scheme)
                            .await
                            .map(nextgcore_sbi::heartbeat::registered_id)
                    }
                },
                |nf_instance_id| {
                    // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
                    // (auth contexts vs configured capacity; TS 29.510 §5.2.2.3.2).
                    nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(
                        nf_instance_id,
                        5,
                        || {
                            let ctx = crate::context::ausf_self();
                            let load = ctx.read().map(|c| c.get_ue_load()).unwrap_or(0);
                            load.clamp(0, 100) as u8
                        },
                    );
                },
            )
            .await;
        }
        Err(e) => log::warn!("NRF registration not attempted (will operate without NRF): {e}"),
    }

    // Discover UDM instances from NRF
    // #664: an unreachable cached UDM is re-discovered and the request resent.
    register_rediscovery_hook();
    if let Err(e) = discover_nf_from_nrf("UDM", "nudm-ueau").await {
        log::warn!("UDM discovery failed (will retry on demand): {e}");
    }

    log::info!("NextGCore AUSF ready");

    // Main event loop (async)
    run_event_loop_async(&mut ausf_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // #235: NFDeregister (TS 29.510 5.2.2.2.3) BEFORE the listener goes
    // away, so the NRF stops handing this profile to consumers instead of
    // waiting out its supervision timer. Stopping the server first would
    // open the bad window: not serving, but still advertised.
    nextgcore_sbi::heartbeat::deregister_self().await;

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
    // #1334: Nausf operations and authentication results, counted by outcome.
    let operation = crate::metrics::classify(&request.header.method, &request.header.uri);
    let response = ausf_sbi_route(request).await;
    if let Some(op) = operation {
        crate::metrics::observe(op, &response);
    }
    response
}

async fn ausf_sbi_route(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!(
        "AUSF SBI request: {method} {uri}",
        uri = nextgcore_sbi::log_redact::redact_callback_tokens(uri)
    );

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
        // Issue #82: TS 29.509 §5.2.2.3 Deregister. MUST precede the generic
        // authenticate arm below, which would otherwise swallow `deregister` as
        // an `AuthenticationInfo` body and reject it 400.
        ("nausf-auth", "ue-authentications", "POST")
            if parts.len() >= 4 && parts[3] == "deregister" =>
        {
            handle_ue_authentication_deregister(&request).await
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
            handle_auth_context_delete(auth_ctx_id, &request).await
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

        // Issue #82: paths the Nausf_UEAuthentication API DECLARES but this AUSF
        // does not implement (optional Rel-16/17 features):
        //   /rg-authentications                              (yaml:381)
        //   /prose-authentications                           (yaml:451)
        //   /prose-authentications/{authCtxId}/prose-auth    (yaml:514)
        // `501 Not Implemented` is the right shape for a defined-but-unimplemented
        // resource; `405 Method Not Allowed` (the fallthrough) claims the resource
        // exists but rejects the method, which is false and misleads a consumer
        // into retrying with another verb.
        ("nausf-auth", "rg-authentications", _) | ("nausf-auth", "prose-authentications", _) => {
            log::info!(
                "AUSF: {method} {uri} is a declared but unimplemented Nausf resource",
                uri = nextgcore_sbi::log_redact::redact_callback_tokens(uri)
            );
            send_problem(
                501,
                "NOT_IMPLEMENTED",
                &format!("{resource} is declared by TS 29.509 but not implemented by this AUSF"),
            )
        }

        _ => {
            log::warn!(
                "Unknown AUSF request: {method} {uri}",
                uri = nextgcore_sbi::log_redact::redact_callback_tokens(uri)
            );
            send_method_not_allowed(method, uri)
        }
    }
}

/// Handle `POST /nausf-auth/v1/ue-authentications/deregister` — the TS 29.509
/// §5.2.2.3 Deregister service operation (issue #82).
///
/// Before this the path had no arm, so it fell through to the generic
/// authenticate handler, which parsed the `DeregistrationInfo` body as an
/// `AuthenticationInfo`, found no `servingNetworkName` and answered `400`. A
/// conformant consumer could therefore never release a security context through
/// the standard operation.
///
/// WHAT THIS CLEARS, AND WHY IT DIFFERS FROM [`handle_auth_context_delete`].
/// §5.2.2.3.1 states the purpose explicitly: the consumer (**the UDM**, not the
/// AMF) asks the AUSF "to clear the stale security context ... so as to ensure
/// only latest Kausf is maintained in the network". So unlike the AMF's
/// `DELETE ue-authentications/{authCtxId}` — which deliberately KEEPS the per-SUPI
/// SoR/UPU anchor so Nausf_SoRProtection/Nausf_UPUProtection keep working
/// (TS 33.501 §6.14.1) — deregister must purge the anchor too. Reusing the DELETE
/// teardown verbatim would leave the stale anchor `K_AUSF` behind and so fail the
/// operation's entire stated purpose.
///
/// `404` is returned only when the AUSF holds NEITHER an authentication context
/// nor an anchor for the SUPI, i.e. genuinely nothing to clear. An anchor with no
/// live authentication context is a real state to clear (the AMF may already have
/// deleted the context), so that case is a success.
pub async fn handle_ue_authentication_deregister(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let info: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // `DeregistrationInfo` requires ONLY `supi`
    // (TS29509_Nausf_UEAuthentication.yaml:796-805). Deliberately NOT routed
    // through `validate_authentication_info`: that demands `servingNetworkName`,
    // which this body does not carry and the spec does not ask for.
    let supi = match info.get("supi").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => {
            return send_bad_request(
                "supi is a mandatory IE of DeregistrationInfo",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    log::info!("[{supi}] UE Authentication Deregister");

    let ctx = ausf_self();

    let ue = ctx
        .read()
        .ok()
        .and_then(|context| context.ue_find_by_supi(supi));
    // #1907: only the UDM or the context's owner, before anything is purged.
    if let Some(refused) = refuse_deregister(ue.as_ref(), request).await {
        return refused;
    }
    // #1928: the authentication the caller was checked against; it is removed
    // only while it is still the current one.
    let checked = ue.map(|ue| (ue.id, ue.ctx_id));

    // Purge the SoR/UPU anchor: the whole point of the operation is that a stale
    // KAUSF must not survive it.
    let anchor_removed = ctx
        .read()
        .map(|context| context.anchor_remove(supi))
        .unwrap_or(false);

    let context_removed = match checked {
        Some((id, ctx_id)) => {
            let removed = ctx
                .read()
                .ok()
                .and_then(|context| context.ue_remove_if_ctx(id, &ctx_id));
            match removed {
                Some(mut ue) => {
                    // Zeroize KAUSF/KSEAF/XRES* before the context is dropped.
                    ue.zeroize();
                    true
                }
                None => false,
            }
        }
        None => false,
    };

    if !context_removed && !anchor_removed {
        log::info!("[{supi}] Deregister: no security context or anchor held → 404");
        return send_not_found(
            "No security context for the requested SUPI",
            Some("CONTEXT_NOT_FOUND"),
        );
    }

    log::info!(
        "[{supi}] Security context cleared and zeroized (auth context: {context_removed}, \
         SoR/UPU anchor: {anchor_removed})"
    );
    SbiResponse::with_status(204)
}

// UE Authentication handlers

pub async fn handle_ue_authentication(request: &SbiRequest) -> SbiResponse {
    // #1907: the caller's identity, checked before anything is read or stored.
    let owner = match caller_identity(request) {
        Ok(owner) => owner,
        Err(why) => return forbidden(&why),
    };
    // #1964: and its NF type. Authenticate is the AMF's.
    if let Some(refused) = refuse_authenticate(owner.as_deref(), request).await {
        return refused;
    }
    log::info!("UE Authentication Request");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let auth_info: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // Issue #82: `supiOrSuci` is a mandatory IE of `AuthenticationInfo`. It used
    // to default to the literal "unknown", which the validator then accepted as a
    // present value — so a body with no identity reached the UDM as a query for a
    // subscriber called "unknown" instead of being rejected. Kept as an Option so
    // absence stays distinguishable from an empty string all the way to the
    // validator.
    let supi_or_suci = auth_info.get("supiOrSuci").and_then(|v| v.as_str());
    let serving_network_name = auth_info.get("servingNetworkName").and_then(|v| v.as_str());

    // Validate required fields
    if let Err(msg) =
        crate::nausf_handler::validate_authentication_info(supi_or_suci, serving_network_name)
    {
        return send_bad_request(msg, Some("INVALID_REQUEST"));
    }
    let supi_or_suci = supi_or_suci.expect("validated non-empty above");

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
    if !crate::nausf_handler::snn_authorized_for_consumer(serving_network_name, &consumer_plmns) {
        log::warn!(
            "SNN '{serving_network_name}' not authorized for consumer PLMNs {consumer_plmns:?}"
        );
        return send_problem(
            403,
            "SERVING_NETWORK_NOT_AUTHORIZED",
            &format!("Serving network '{serving_network_name}' not allowed for consumer"),
        );
    }

    // #1948: relayed by the home SEPP, before anything is read or stored.
    if let Some(refused) = refuse_sepp_relayed(request, serving_network_name) {
        return refused;
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
    // #1872: every authentication is a new resource with its own unguessable
    // authCtxId (stored, and the previous one retired, by `ue_update` below),
    // bound to the verified identity of the NF that started it.
    ausf_ue.ctx_id = crate::context::new_auth_ctx_id();
    ausf_ue.owner = owner;

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
                context.ue_begin_authentication(&ausf_ue);
                if let Some(ref supi) = supi {
                    context.ue_set_supi(ausf_ue.id, supi);
                }
            }

            let rand_hex = crate::nudm_handler::bytes_to_hex(&ausf_ue.rand);
            let autn_hex = crate::nudm_handler::bytes_to_hex(&ausf_ue.autn);
            let hxres_star_hex = crate::nudm_handler::bytes_to_hex(&ausf_ue.hxres_star);
            let auth_ctx_id = ausf_ue.ctx_id.clone();

            // Issue #82: the 201 UEAuthenticationCtx is declared
            // `application/3gppHal+json` ONLY
            // (TS29509_Nausf_UEAuthentication.yaml:44-48) — it carries the
            // `_links` map the consumer follows to confirm, so a strict HAL
            // client may reject or mis-parse it as plain application/json.
            SbiResponse::with_status(201)
                .with_header("Location", format!("/nausf-auth/v1/ue-authentications/{auth_ctx_id}"))
                .with_hal_json_body(&serde_json::json!({
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

            let mut session = crate::eap_aka_prime::EapAkaSession::new(serving_network_name);
            session.init_from_transformed_av(&rand, &autn, &xres, &ck_prime, &ik_prime, &identity);

            // KAUSF = MSB256(EMSK) is fixed by the key schedule; store it now
            ausf_ue.rand = rand;
            ausf_ue.autn = autn;
            ausf_ue.kausf = session.kausf;

            let challenge = session.generate_challenge();
            let eap_payload_b64 = nextgcore_crypt::base64::encode(&challenge.encode());
            ausf_ue.eap_session = Some(session);

            if let Ok(context) = ctx.read() {
                context.ue_begin_authentication(&ausf_ue);
                if let Some(ref supi) = supi {
                    context.ue_set_supi(ausf_ue.id, supi);
                }
            }

            let auth_ctx_id = ausf_ue.ctx_id.clone();
            // Issue #82: HAL media type, as for the 5G-AKA branch above.
            SbiResponse::with_status(201)
                .with_header(
                    "Location",
                    format!("/nausf-auth/v1/ue-authentications/{auth_ctx_id}"),
                )
                .with_hal_json_body(&serde_json::json!({
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
                context.ue_begin_authentication(&ausf_ue);
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
    let Some(json) = token_payload(authorization) else {
        return Vec::new();
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

/// The JSON payload of a bearer token, decoded without checking the signature.
/// Read only for a token the SBI server already verified (#1948: the SEPP path
/// requires `oauth2_subject`, which it sets only after verifying).
fn token_payload(authorization: &str) -> Option<serde_json::Value> {
    let token = authorization
        .strip_prefix("Bearer ")
        .or_else(|| authorization.strip_prefix("bearer "))
        .unwrap_or(authorization)
        .trim();

    let payload_b64 = match token.split('.').nth(1) {
        Some(p) if !p.is_empty() => p,
        _ => return None,
    };

    // base64url -> standard base64 (+ padding) for the shared decoder.
    let mut std_b64 = payload_b64.replace('-', "+").replace('_', "/");
    while std_b64.len() % 4 != 0 {
        std_b64.push('=');
    }
    let bytes = nextgcore_crypt::base64::decode(&std_b64)?;
    serde_json::from_slice(&bytes).ok()
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

/// #1907: the answer to a request whose authCtxId a concurrent
/// re-authentication retired while it ran: the resource is gone (TS 29.509
/// §5.2.2.2.2), and nothing it computed was stored.
fn retired_auth_ctx() -> SbiResponse {
    send_not_found("Authentication context not found", None)
}

/// #1872/#1907: the verified identity of the NF calling, one rule for create
/// and for every later operation: the `sub` of the access token this AUSF
/// verified, else the NF Instance ID of the client certificate it verified.
///
/// When both are present they must name the same NF (as #1831 rules for the
/// NRF). The one exception is a certificate whose RFC 9310 NFTypes name only
/// the SCP, or (#1948) only the SEPP: in indirect communication, and in
/// roaming relayed by the home SEPP, the TLS peer is the relay and the token
/// names the consumer (TS 33.501 §13.4.1.2), so the token `sub` is the
/// identity.
/// `Err` is the reason a caller is refused: its token names an NF its own
/// certificate does not.
fn caller_identity(request: &SbiRequest) -> Result<Option<String>, String> {
    caller_identity_with(
        request,
        nextgcore_sbi::security::SbiProfile::resolve().is_production(),
    )
}

/// [`caller_identity`] under the profile `production` says (#2065).
///
/// Under production a certificate that names NO NF type (RFC 9310 NFTypes) is not
/// an identity: it cannot be told from an untyped relay's, which would otherwise
/// own every context started through it. With a token, the token's `sub` is the
/// caller; without one the caller is refused. Under dev it still counts as the
/// caller's (the rule of `nextgcore_sbi::owner_binding`, #2065).
fn caller_identity_with(request: &SbiRequest, production: bool) -> Result<Option<String>, String> {
    let verified = |v: &Option<String>| {
        v.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let token = verified(&request.oauth2_subject);
    let cert = verified(&request.peer_cert_nf_instance_id);
    if production && cert.is_some() && request.peer_cert_nf_types.is_empty() {
        return token.map(Some).ok_or_else(|| {
            "the client certificate names no NF type, so it cannot be told from a relay's, \
             and no access token was presented"
                .to_string()
        });
    }
    match (token, cert) {
        (Some(t), Some(c)) if !t.eq_ignore_ascii_case(&c) => {
            // #1928: a certificate naming the SCP AND another NF type could
            // otherwise present any token `sub`; only a pure SCP certificate
            // is exempt.
            // #1948: and a pure SEPP certificate: roaming signalling relayed
            // over N32-f by the home SEPP carries the visited AMF's token
            // (TS 33.501 §13.2, §13.4.1.2). What a SEPP-relayed caller may do
            // is narrowed by `refuse_sepp_relayed`.
            if relayed_by(request, "SCP") || relayed_by(request, "SEPP") {
                Ok(Some(t))
            } else {
                Err(format!(
                    "the access token names NF {t} but the client certificate names NF {c}"
                ))
            }
        }
        (Some(t), _) => Ok(Some(t)),
        (None, c) => Ok(c),
    }
}

/// #1928/#1948: whether the verified client certificate names `relay` (SCP or
/// SEPP) and no other NF type. A certificate also naming another type is that
/// NF's, not a relay's.
fn relayed_by(request: &SbiRequest, relay: &str) -> bool {
    !request.peer_cert_nf_types.is_empty()
        && request
            .peer_cert_nf_types
            .iter()
            .all(|ty| ty.eq_ignore_ascii_case(relay))
}

/// #1948: what an authentication relayed by the home SEPP needs. The SEPP sits
/// on the PLMN border and relays only inter-PLMN signalling (TS 33.501 §13.1),
/// so the caller is an NF of ANOTHER PLMN, and the only Nausf_UEAuthentication
/// consumer there is the visited AMF (TS 33.501 §6.1.2, roaming):
/// - a token this AUSF verified (its `sub` is the identity; the certificate is
///   the SEPP's);
/// - an inter-PLMN token: `consumerPlmnId` and `producerPlmnId` (TS 29.510
///   `AccessTokenClaims`) both present and different;
/// - the serving network name naming the consumer's PLMN (TS 33.501 §6.1.2:
///   the requester must be entitled to it). Unlike the direct path, this is
///   not default-permissive.
///
/// `None` unless the certificate is a pure SEPP's. `Some` is the refusal.
fn refuse_sepp_relayed(request: &SbiRequest, serving_network_name: &str) -> Option<SbiResponse> {
    if !relayed_by(request, "SEPP") {
        return None;
    }
    if request
        .oauth2_subject
        .as_deref()
        .is_none_or(|s| s.trim().is_empty())
    {
        return Some(forbidden(
            "an authentication relayed by a SEPP needs the visited AMF's verified access token",
        ));
    }
    let claims = request
        .http
        .get_header("Authorization")
        .and_then(|h| token_payload(h));
    let plmn = |name: &str| {
        let p = claims.as_ref()?.get(name)?;
        Some((
            p.get("mcc")?.as_str()?.to_string(),
            crate::nausf_handler::normalize_mnc3(p.get("mnc")?.as_str()?),
        ))
    };
    let (Some(consumer), Some(producer)) = (plmn("consumerPlmnId"), plmn("producerPlmnId")) else {
        return Some(forbidden(
            "an authentication relayed by a SEPP needs an inter-PLMN access token              (consumerPlmnId and producerPlmnId)",
        ));
    };
    if consumer == producer {
        return Some(forbidden(
            "a SEPP relays only inter-PLMN signalling; the access token's consumer is of this PLMN",
        ));
    }
    if crate::nausf_handler::parse_snn_plmn(serving_network_name) != Some(consumer.clone()) {
        log::warn!(
            "SEPP-relayed authentication refused: SNN '{serving_network_name}' is not the \
             consumer PLMN {consumer:?}"
        );
        return Some(send_problem(
            403,
            "SERVING_NETWORK_NOT_AUTHORIZED",
            &format!("Serving network '{serving_network_name}' not allowed for consumer"),
        ));
    }
    None
}

fn forbidden(detail: &str) -> SbiResponse {
    nextgcore_sbi::server::send_error(403, "Forbidden", detail, None)
}

/// #1872: refuse a caller that is not the NF that started `ue`'s current
/// authentication. A context bound to an identity is acted on only by a caller
/// proving that identity (compared case-insensitively, as NF Instance IDs are
/// UUIDs); `403`, with nothing verified, reported to the UDM or zeroized. An
/// unbound context (its creator proved no identity) binds nothing, but a
/// caller whose identities conflict is refused either way (#1907). `Some` is
/// the refusal to send.
fn refuse_foreign_caller(ue: &crate::context::AusfUe, request: &SbiRequest) -> Option<SbiResponse> {
    refuse_foreign_caller_with(
        ue,
        request,
        nextgcore_sbi::security::SbiProfile::resolve().is_production(),
    )
}

/// [`refuse_foreign_caller`] under the profile `production` says. #2065: under
/// production an UNBOUND context (one restored from before #1872, or started by a
/// caller that proved no identity under dev) is frozen, as `owner_binding` freezes
/// an ownerless resource: no caller can show it started it.
fn refuse_foreign_caller_with(
    ue: &crate::context::AusfUe,
    request: &SbiRequest,
    production: bool,
) -> Option<SbiResponse> {
    let caller = match caller_identity_with(request, production) {
        Ok(caller) => caller,
        Err(why) => {
            log::debug!("authCtxId {} refused: {why}", ue.ctx_id);
            return Some(forbidden(&why));
        }
    };
    let Some(owner) = ue.owner.as_deref() else {
        if production {
            log::debug!(
                "authCtxId {} refused: it has no verified owner and is frozen under the \
                 production profile",
                ue.ctx_id
            );
            return Some(forbidden(
                "the authentication context has no verified owner, so no caller can be \
                 shown to have started it",
            ));
        }
        return None;
    };
    if caller
        .as_deref()
        .is_some_and(|c| c.eq_ignore_ascii_case(owner))
    {
        return None;
    }
    log::debug!(
        "authCtxId {} refused: started by NF {owner}, called by {}",
        ue.ctx_id,
        caller.as_deref().unwrap_or("an unverified caller")
    );
    Some(forbidden(
        "the authentication context was started by another NF",
    ))
}

/// #1964: how long an NRF answer about a caller's NF type is reused.
const CALLER_TYPE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
/// #1964: at most this many cached answers; a full cache drops the expired ones,
/// then everything, rather than grow.
const CALLER_TYPE_CACHE_MAX: usize = 1024;

/// #1964: (NF type, NF instance ID) -> (the instance is of that type, when
/// learnt). Positive and negative answers both; a failed lookup is never cached
/// (it fails closed, and the next call asks again).
static CALLER_TYPE_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, (bool, std::time::Instant)>>,
> = std::sync::OnceLock::new();

fn caller_type_cache(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, (bool, std::time::Instant)>> {
    CALLER_TYPE_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn caller_type_key(nf_type: &str, id: &str) -> String {
    format!(
        "{}:{}",
        nf_type.to_ascii_uppercase(),
        id.to_ascii_lowercase()
    )
}

/// Tests: record that the NRF profile of `id` is of type `nf_type` (and of no
/// other type it is asked about), so a token-identified caller needs no NRF.
#[cfg(test)]
pub(crate) fn seed_caller_type_1964(id: &str, nf_type: &str) {
    let now = std::time::Instant::now();
    let mut cache = caller_type_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    for t in ["AMF", "UDM"] {
        cache.insert(
            caller_type_key(t, id),
            (t.eq_ignore_ascii_case(nf_type), now),
        );
    }
}

/// #1964: whether NF instance `id` is of type `nf_type`, per its NRF profile.
/// Asked through NFDiscovery with `target-nf-type=<nf_type>` and
/// `target-nf-instance-id=id`; the answer is yes only if the result names `id`
/// itself, so an NRF that ignores the instance filter cannot vouch for an
/// unlisted caller. `Err` when there is no NRF or it does not answer: the caller
/// then fails closed.
async fn caller_is(nf_type: &str, id: &str) -> Result<bool, String> {
    let key = caller_type_key(nf_type, id);
    if let Some((is_amf, at)) = caller_type_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .copied()
    {
        if at.elapsed() < CALLER_TYPE_TTL {
            return Ok(is_amf);
        }
    }
    let sbi_ctx = nextgcore_sbi::context::global_context();
    let nrf_uri = sbi_ctx
        .get_nrf_uri()
        .await
        .ok_or("no NRF is configured to look the caller up")?;
    let (host, port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&host, port).await;
    let path = format!(
        "/nnrf-disc/v1/nf-instances?target-nf-type={nf_type}&requester-nf-type=AUSF&target-nf-instance-id={id}"
    );
    let resp = client
        .get(&path)
        .await
        .map_err(|e| format!("NRF lookup failed: {e}"))?;
    if resp.status != 200 {
        return Err(format!("NRF lookup returned {}", resp.status));
    }
    let json: serde_json::Value = serde_json::from_str(resp.http.content.as_deref().unwrap_or(""))
        .map_err(|e| format!("NRF lookup answer does not parse: {e}"))?;
    let is_type = json["nfInstances"].as_array().is_some_and(|list| {
        list.iter().any(|p| {
            p["nfInstanceId"]
                .as_str()
                .is_some_and(|i| i.eq_ignore_ascii_case(id))
                && p["nfType"]
                    .as_str()
                    .is_some_and(|t| t.eq_ignore_ascii_case(nf_type))
        })
    });
    let mut cache = caller_type_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if cache.len() >= CALLER_TYPE_CACHE_MAX {
        cache.retain(|_, (_, at)| at.elapsed() < CALLER_TYPE_TTL);
        if cache.len() >= CALLER_TYPE_CACHE_MAX {
            cache.clear();
        }
    }
    cache.insert(key, (is_type, std::time::Instant::now()));
    Ok(is_type)
}

/// #1964: whether the caller is of type `nf_type`. A client certificate this
/// AUSF verified, naming NF types other than the SCP, answers it; relayed by an
/// SCP (its certificate is the SCP's) or identified by a token alone, the NRF
/// profile of `caller` does ([`caller_is`]). `Err` when that lookup fails.
async fn caller_has_type(
    caller: &str,
    request: &SbiRequest,
    nf_type: &str,
) -> Result<bool, String> {
    let types = &request.peer_cert_nf_types;
    let via_scp = types.iter().any(|t| t.eq_ignore_ascii_case("SCP"));
    if !types.is_empty() && !via_scp {
        return Ok(types.iter().any(|t| t.eq_ignore_ascii_case(nf_type)));
    }
    caller_is(nf_type, caller).await
}

/// #1964: authenticate (TS 29.509 §5.2.2.2, 5G-AKA / EAP-AKA' initiation) is
/// the AMF's (the SEAF), never the UDM's, though both hold `nausf-auth` and its
/// ue-authentications scope for Deregister. Which NF is calling:
/// - a client certificate this AUSF verified, naming NF types other than the
///   SCP: those types, which must include AMF;
/// - relayed by an SCP (the certificate is the SCP's) or identified by a token
///   alone: the NRF profile of that identity ([`caller_is_amf`]), cached for
///   [`CALLER_TYPE_TTL`]; a lookup that fails refuses (fail closed);
/// - no verified identity at all: admitted only under the `dev` SBI profile (a
///   plaintext stack has nothing to check), refused under `production`.
///
/// `Some` is the refusal to send, before anything is read or stored.
async fn refuse_authenticate(caller: Option<&str>, request: &SbiRequest) -> Option<SbiResponse> {
    // #1948: relayed by the home SEPP: the visited AMF is in another PLMN, so
    // this NRF holds no profile to type it by. `refuse_sepp_relayed` checks it
    // instead, once the serving network name is read.
    if relayed_by(request, "SEPP") {
        return None;
    }
    let types = &request.peer_cert_nf_types;
    let via_scp = types.iter().any(|t| t.eq_ignore_ascii_case("SCP"));
    if !types.is_empty() && !via_scp {
        if types.iter().any(|t| t.eq_ignore_ascii_case("AMF")) {
            return None;
        }
        log::debug!("authenticate refused: the caller's certificate names {types:?}, not AMF");
        return Some(forbidden(
            "authenticate is for the AMF (TS 29.509 §5.2.2.2); the caller's certificate \
             names another NF type",
        ));
    }
    let Some(id) = caller else {
        if nextgcore_sbi::security::SbiProfile::resolve().is_production() {
            return Some(forbidden(
                "authenticate needs a verified caller identity under the production profile",
            ));
        }
        return None;
    };
    match caller_has_type(id, request, "AMF").await {
        Ok(true) => None,
        Ok(false) => {
            log::debug!("authenticate refused: NF {id} is not an AMF per its NRF profile");
            Some(forbidden(
                "authenticate is for the AMF (TS 29.509 §5.2.2.2); the caller's NRF profile \
                 is not an AMF's",
            ))
        }
        Err(why) => {
            log::warn!("authenticate refused: the caller's NF type could not be checked: {why}");
            Some(forbidden(
                "authenticate is for the AMF, and the caller's NF type could not be checked",
            ))
        }
    }
}

/// #1907: who may Deregister a SUPI (TS 29.509 §5.2.2.3): "the NF Service
/// Consumer (e.g. UDM)" clearing a stale security context. A caller with a
/// verified identity must be the NF that started the UE's current
/// authentication, or be a UDM ([`caller_has_type`], #1918/#1964): by its
/// certificate's RFC 9310 NFTypes, or, reaching this AUSF through an SCP (whose
/// certificate is the SCP's) or by token alone, by its NRF profile. Not by the
/// `nausf-auth:ue-authentications` scope: the AMF holds it too (R31 M1). Any
/// other AMF is refused, so it cannot purge another UE's KAUSF; a type that
/// cannot be checked refuses. A caller with no verified identity is refused
/// (#1928). `Some` is the refusal to send, before anything is removed.
async fn refuse_deregister(
    ue: Option<&crate::context::AusfUe>,
    request: &SbiRequest,
) -> Option<SbiResponse> {
    // #1948: Deregister is the home UDM's (TS 29.509 §5.2.2.3) and so never
    // inter-PLMN: a SEPP-relayed one is refused.
    if relayed_by(request, "SEPP") {
        return Some(forbidden(
            "Deregister is the home UDM's (TS 29.509 §5.2.2.3); a SEPP relays only \
             inter-PLMN signalling",
        ));
    }
    let caller = match caller_identity(request) {
        Ok(caller) => caller,
        Err(why) => return Some(forbidden(&why)),
    };
    let owner = ue.and_then(|ue| ue.owner.as_deref());
    // #1928: never anonymous, dev included. Deregister purges the SUPI's
    // SoR/UPU anchor, the latest KAUSF (TS 33.501 §6.14.1), whether or not an
    // authentication context is bound. No NextGCore NF calls it unauthenticated.
    let Some(caller) = caller else {
        return Some(forbidden("Deregister needs a verified caller identity"));
    };
    if owner.is_some_and(|o| o.eq_ignore_ascii_case(&caller)) {
        return None;
    }
    // #1964 (R31 M1): the UDM, by NF type. Not by the ue-authentications scope,
    // which the AMF holds too (TS 29.509 OpenAPI), so it would admit every AMF.
    match caller_has_type(&caller, request, "UDM").await {
        Ok(true) => None,
        Ok(false) => {
            log::debug!(
                "Deregister refused: NF {caller} is neither the UDM nor the context's owner"
            );
            Some(forbidden(
                "Deregister is for the UDM (TS 29.509 §5.2.2.3) or the NF that started the \
                 authentication",
            ))
        }
        Err(why) => {
            log::warn!("Deregister refused: the caller's NF type could not be checked: {why}");
            Some(forbidden(
                "Deregister is for the UDM, and the caller's NF type could not be checked",
            ))
        }
    }
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
    // #1872: only the NF that started this authentication may act on it,
    // checked before anything is verified, reported or changed.
    if let Some(refused) = refuse_foreign_caller(&ausf_ue, request) {
        return refused;
    }

    // ausfd-03: null/absent resStar → 200 AUTHENTICATION_FAILURE (no kseaf, no supi)
    // TS 29.509 §6.1.6.2.8: both kseaf and supi are conditional on authentication success.
    if res_star_null_or_absent {
        log::warn!(
            "[{}] 5G-AKA: resStar null/absent → AUTHENTICATION_FAILURE",
            ausf_ue.suci
        );
        ausf_ue.auth_result = crate::AuthResult::AuthenticationFailure;
        if let Ok(context) = ctx.read() {
            if !context.ue_update(&ausf_ue) {
                // #1907: a re-authentication retired this authCtxId meanwhile.
                return retired_auth_ctx();
            }
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
    // RES* is authentication material: never logged.
    log::info!("[{}] 5G-AKA Confirmation received", ausf_ue.suci);

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
        if !context.ue_update(&ausf_ue) {
            // #1907: a re-authentication retired this authCtxId meanwhile.
            return retired_auth_ctx();
        }
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
    // #1872: only the NF that started this authentication may act on it,
    // checked before anything is verified, reported or changed.
    if let Some(refused) = refuse_foreign_caller(&ausf_ue, request) {
        return refused;
    }

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
                            if !context.ue_update(&ausf_ue) {
                                // #1907: a re-authentication retired this authCtxId meanwhile.
                                return retired_auth_ctx();
                            }
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
                            if !context.ue_update(&ausf_ue) {
                                // #1907: a re-authentication retired this authCtxId meanwhile.
                                return retired_auth_ctx();
                            }
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
                if !context.ue_update(&ausf_ue) {
                    // #1907: a re-authentication retired this authCtxId meanwhile.
                    return retired_auth_ctx();
                }
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
                if !context.ue_update(&ausf_ue) {
                    // #1907: a re-authentication retired this authCtxId meanwhile.
                    return retired_auth_ctx();
                }
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
                        if !context.ue_update(&ausf_ue) {
                            // #1907: a re-authentication retired this authCtxId meanwhile.
                            return retired_auth_ctx();
                        }
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

pub async fn handle_auth_context_delete(auth_ctx_id: &str, request: &SbiRequest) -> SbiResponse {
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
            context.ue_find_by_ctx_id(auth_ctx_id)
        } else {
            None
        }
    };

    let ue_id = match ue_id {
        Some(ue) => {
            // #1872: only the NF that started this authentication may delete
            // it, checked before anything is removed or zeroized.
            if let Some(refused) = refuse_foreign_caller(&ue, request) {
                return refused;
            }
            ue.id
        }
        None => {
            return send_not_found("Authentication context not found", None);
        }
    };

    // #1928: only while the authentication checked above is still current: a
    // re-authentication by another AMF in between keeps its context (404).
    let removed = {
        if let Ok(context) = ctx.read() {
            context.ue_remove_if_ctx(ue_id, auth_ctx_id)
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

/// The ONE agreement about the `UDM_SBI_ADDR` / `UDM_SBI_PORT` environment and the
/// process-wide AUSF context, for tests.
///
/// Moved out of `mod tests` by #308. Every writer and every reader of that
/// environment in this crate already took it, so this is a relocation and not a
/// behaviour change — but a lock declared inside a test submodule is unreachable
/// from a sibling module, and the next module that needs it declares a second one.
/// That is exactly how `smfd` ended up with four locks over one ambient state and a
/// suite that failed 1 whole-workspace run in 5. Declared beside the fallback below
/// so there is one place to find it.
#[cfg(test)]
pub(crate) static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Send NUDM-UEAU generate-auth-data request to UDM via SBI client
async fn send_udm_generate_auth_data(
    supi_or_suci: &str,
    serving_network_name: &str,
    resync_info: Option<&crate::ResynchronizationInfo>,
) -> Result<UdmAuthData, String> {
    let sbi_ctx = nextgcore_sbi::context::global_context();

    // Find UDM instance via cached discovery results or env var fallback
    let (host_owned, port);
    let mut udm_instances = sbi_ctx
        .find_nf_instances_by_service(nextgcore_sbi::types::SbiServiceType::NudmUeau)
        .await;
    // #664: a cache miss (startup discovery failed, or the last UDM was evicted
    // as unreachable) re-discovers before falling back to UDM_SBI_ADDR; before,
    // discovery ran only at startup, so one eviction meant the env var forever.
    if udm_instances.is_empty() && sbi_ctx.get_nrf_uri().await.is_some() {
        if let Err(e) = discover_nf_from_nrf("UDM", "nudm-ueau").await {
            log::warn!("UDM re-discovery failed: {e}");
        }
        udm_instances = sbi_ctx
            .find_nf_instances_by_service(nextgcore_sbi::types::SbiServiceType::NudmUeau)
            .await;
    }

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
            .or(udm_instance.ipv6_addresses.first().cloned())
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

    // Attach an NRF-issued Bearer token to the Nudm_UEAuthentication call when
    // OAuth2 enforcement is on (Wave-6 H8 Phase A); pooled/no-op otherwise.
    let client = peer_client(&host_owned, port, nextgcore_sbi::types::NfType::Udm).await;

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
        .or(udm_instance.ipv6_addresses.first().map(|s| s.as_str()))
        .ok_or("No UDM endpoint address available")?;
    let port = udm_service.port;

    // Attach an NRF-issued Bearer token to the Nudm_UEAuthentication result
    // notification when OAuth2 enforcement is on (Wave-6 H8 Phase A); pooled
    // client / no-op otherwise so the matched-sim default path is unchanged.
    let client = peer_client(host, port, nextgcore_sbi::types::NfType::Udm).await;

    let body = serde_json::json!({
        // Issue #187: fall back to the shared resolver, not a throwaway UUID. A
        // random id here named an AUSF that nothing in the deployment knows.
        "nfInstanceId": nextgcore_sbi::context::global_context()
            .get_self_instance()
            .await
            .map(|i| i.id)
            .unwrap_or_else(|| {
                nextgcore_sbi::nf_instance_id::nf_instance_id(
                    nextgcore_sbi::types::NfType::Ausf,
                )
                .to_string()
            }),
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

/// Every Nausf service this AUSF serves, with the NF types allowed to consume it
/// (TS 29.510 §6.1.6.2.3 `NFService.allowedNfTypes`).
///
/// ONE table (#392), consumed by both [`build_ausf_nf_instance`] (the typed self
/// instance) and [`build_nf_profile`] (the NFProfile PUT to the NRF), so the two
/// cannot drift.
const AUSF_SERVICES: &[(nextgcore_sbi::types::SbiServiceType, &[&str])] = &[
    // TS 29.509 Nausf_UEAuthentication, consumed by the AMF, and by the UDM
    // for Deregister (§5.2.2.3, #1918): without it here the NRF grants a UDM
    // no `nausf-auth` token at all.
    (
        nextgcore_sbi::types::SbiServiceType::NausfAuth,
        &["AMF", "UDM", "SCP"],
    ),
    // TS 29.509 Nausf_SoRProtection. Wave-6 F-03: the UDM discovers the AUSF
    // holding the latest K_AUSF BY SERVICE NAME (TS 33.501 §6.14.2.1 step 8), so
    // this must appear in the profile for SoR protection to be reachable at all.
    (
        nextgcore_sbi::types::SbiServiceType::NausfSorprotection,
        &["UDM", "SCP"],
    ),
    // TS 29.509 Nausf_UPUProtection, same discovery path.
    (
        nextgcore_sbi::types::SbiServiceType::NausfUpuprotection,
        &["UDM", "SCP"],
    ),
];

/// #1918: the resource-level scopes of an AUSF service, and the ONE NF type each
/// is registered for in `allowedOperationsPerNfType` (TS 29.510 Table
/// 6.1.6.2.3-1 NOTE 11), so the NRF grants it to that type only. The UDM
/// Deregisters (TS 29.509 §5.2.2.3) and, reaching the AUSF through an SCP,
/// presents the SCP's certificate, so its type is proven by the NRF's grant of
/// this scope instead ([`refuse_deregister`]). Spelling: the vendored OpenAPI's
/// (`nextgcore_sbi::resource_scope`).
///
/// #1964: the vendored TS 29.509 OpenAPI defines this scope for the whole
/// ue-authentications collection (authenticate, 5g-aka-confirmation,
/// eap-session, deregister), so the AMF holds it as the UDM does. It therefore
/// tells no AMF from a UDM: which operation a caller may invoke is decided by
/// its NF type ([`refuse_authenticate`], [`refuse_deregister`]).
const AUSF_RESOURCE_SCOPES: &[(&str, &str, &str)] = &[
    (
        "nausf-auth",
        nextgcore_sbi::resource_scope::NAUSF_AUTH_UE_AUTHENTICATIONS,
        "AMF",
    ),
    (
        "nausf-auth",
        nextgcore_sbi::resource_scope::NAUSF_AUTH_UE_AUTHENTICATIONS,
        "UDM",
    ),
];

/// The `allowedOperationsPerNfType` of AUSF service `name`, or `None` when the
/// service has no resource-level scope (#1918), as udrd builds its own (#1811).
///
/// NOTE 11: once the map is present it must name EVERY NF type allowed the
/// service, with all its scopes, the service-level one included: a type left
/// out is barred from the whole service. So each of `allowed` gets the
/// service-level scope, and only the type [`AUSF_RESOURCE_SCOPES`] names gets a
/// resource scope.
fn ausf_allowed_operations(name: &str, allowed: &[&str]) -> Option<serde_json::Value> {
    if !AUSF_RESOURCE_SCOPES.iter().any(|(svc, _, _)| *svc == name) {
        return None;
    }
    let map: serde_json::Map<String, serde_json::Value> = allowed
        .iter()
        .map(|nf_type| {
            let mut scopes = vec![name.to_string()];
            scopes.extend(
                AUSF_RESOURCE_SCOPES
                    .iter()
                    .filter(|(svc, _, t)| *svc == name && t == nf_type)
                    .map(|(_, scope, _)| scope.to_string()),
            );
            (nf_type.to_string(), serde_json::json!(scopes))
        })
        .collect();
    Some(serde_json::Value::Object(map))
}

/// Build this AUSF's typed self NF instance from [`AUSF_SERVICES`].
fn build_ausf_nf_instance(
    nf_instance_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
) -> nextgcore_sbi::context::NfInstance {
    let mut self_instance =
        nextgcore_sbi::context::NfInstance::new(nf_instance_id, nextgcore_sbi::types::NfType::Ausf);
    nextgcore_sbi::nf_addressing::set_instance_host(&mut self_instance, sbi_addr);
    self_instance.heartbeat_interval = 10;
    for (service_type, _allowed) in AUSF_SERVICES {
        let mut svc = nextgcore_sbi::context::NfService::new(service_type.to_name(), *service_type);
        svc.port = sbi_port;
        nextgcore_sbi::nf_addressing::set_service_host(&mut svc, sbi_addr);
        self_instance.add_service(svc);
    }
    self_instance
}

/// Build the TS 29.510 §6.1.6.2.2 NFProfile the AUSF registers with the NRF.
///
/// Advertises nausf-auth plus the Wave-6 F-03 producer services
/// nausf-sorprotection / nausf-upuprotection (TS 29.509), so udmd
/// discovery-by-service works (TS 33.501 §6.14.2.1 step 8: the UDM selects
/// the AUSF holding the latest KAUSF).
///
/// #392: rendered from [`AUSF_SERVICES`], with per-service `allowedNfTypes` and an
/// NF-level union, so the profile and the self instance cannot drift.
fn build_nf_profile(
    nf_instance_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
    scheme: nextgcore_sbi::types::UriScheme,
) -> serde_json::Value {
    let services: Vec<serde_json::Value> = AUSF_SERVICES
        .iter()
        .map(|(service_type, allowed)| {
            let name = service_type.to_name();
            let mut service = serde_json::json!({
                "serviceInstanceId": format!("{nf_instance_id}-{name}"),
                "serviceName": name,
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": scheme.as_str(),
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{
                    "ipv4Address": sbi_addr,
                    "port": sbi_port
                }],
                "allowedNfTypes": allowed,
            });
            if let Some(ops) = ausf_allowed_operations(name, allowed) {
                service["allowedOperationsPerNfType"] = ops;
            }
            service
        })
        .collect();

    let mut nf_allowed: Vec<&str> = Vec::new();
    for (_, allowed) in AUSF_SERVICES {
        for t in *allowed {
            if !nf_allowed.contains(t) {
                nf_allowed.push(t);
            }
        }
    }

    nextgcore_sbi::nf_addressing::classify_profile_host(
        serde_json::json!({
            "nfInstanceId": nf_instance_id,
            "nfType": "AUSF",
            "nfStatus": "REGISTERED",
            "ipv4Addresses": [sbi_addr],
            "nfServices": services,
            "allowedNfTypes": nf_allowed,
            "heartBeatTimer": 10
        }),
        sbi_addr,
    )
}

/// Register AUSF with NRF (B23.4)
///
/// Returns the NF instance ID that was registered, so callers can start a
/// heartbeat worker for the same instance.
async fn register_with_nrf(
    sbi_addr: &str,
    sbi_port: u16,
    sbi_scheme: nextgcore_sbi::types::UriScheme,
) -> Result<String, String> {
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

    let nf_instance_id =
        nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Ausf)
            .to_string();

    // Build NF Profile for registration
    let nf_profile = build_nf_profile(&nf_instance_id, sbi_addr, sbi_port, sbi_scheme);

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    log::debug!("NRF registration: PUT {path}");

    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("AUSF registered with NRF successfully (id={nf_instance_id})");
            // #434: what a 404 heartbeat re-registers if the NRF loses us.
            nextgcore_sbi::heartbeat::set_registered_profile(&nf_profile);

            // Store the self instance from the SAME table the profile came from:
            // this was a second hand-written service list (#392).
            sbi_ctx
                .set_self_instance(build_ausf_nf_instance(&nf_instance_id, sbi_addr, sbi_port))
                .await;

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

    // #235: the SearchResult's validityPeriod bounds how long these profiles may
    // be selected; without it a cached peer was chosen for the process lifetime.
    let validity = nextgcore_sbi::context::search_result_validity(&json);

    // #664: the answer REPLACES the cached profiles of the target type, so a
    // profile the NRF dropped (a restarted UDM's old instance id) goes too.
    let mut fresh: Vec<nextgcore_sbi::context::NfInstance> = Vec::new();
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

            // #1324: IPv4, IPv6 and FQDN alike.
            nextgcore_sbi::nf_addressing::read_instance_addresses(&mut instance, nf_json);

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
                        nextgcore_sbi::nf_addressing::read_service_addresses(&mut svc, svc_json);
                        instance.add_service(svc);
                    }
                }
            }

            log::info!(
                "Discovered {nf_type_str} instance: {nf_id} (valid for {}s)",
                validity.as_secs()
            );
            fresh.push(instance);
        }
    }
    match nextgcore_sbi::types::NfType::from_name(target_nf_type) {
        Some(target) => {
            let (mine, other): (Vec<_>, Vec<_>) =
                fresh.into_iter().partition(|i| i.nf_type == target);
            sbi_ctx.replace_nf_instances(target, mine, validity).await;
            for instance in other {
                sbi_ctx
                    .add_nf_instance_with_validity(instance, validity)
                    .await;
            }
        }
        None => {
            for instance in fresh {
                sbi_ctx
                    .add_nf_instance_with_validity(instance, validity)
                    .await;
            }
        }
    }

    Ok(())
}

/// Register [`discover_nf_from_nrf`] as the SBI client's re-discovery (#664).
fn register_rediscovery_hook() {
    nextgcore_sbi::context::global_context().set_rediscovery_hook(std::sync::Arc::new(
        |nf_type, service| {
            Box::pin(async move {
                if let Err(e) = discover_nf_from_nrf(nf_type.to_str(), &service).await {
                    log::warn!(
                        "Re-discovery of {} ({service}) failed: {e}",
                        nf_type.to_str()
                    );
                }
            })
        },
    ));
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
    // RUST_LOG if set, else --log-level: the same for every NF (#691).
    let mut builder = nextgcore_core::log::nf_log_builder(&nextgcore_core::log::nf_log_level(
        args.log_level.as_deref(),
        Some(&args.config),
    ));

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

    use super::TEST_MUTEX;

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

    /// #1308: with no flag the SBI listener binds loopback, not every interface.
    #[test]
    fn sbi_listener_defaults_to_loopback_1308() {
        let args = Args::parse_from(["nextgcore-ausfd"]);
        assert_eq!(args.sbi_addr, None);
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-ausfd"]);
        assert_eq!(args.config, "/etc/nextgcore/ausf.yaml");
        assert_eq!(args.log_level, None);
        assert_eq!(args.sbi_addr, None);
        assert_eq!(args.sbi_port, None);
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
        assert_eq!(args.log_level.as_deref(), Some("debug"));
        assert_eq!(args.sbi_addr.as_deref(), Some("0.0.0.0"));
        assert_eq!(args.sbi_port, Some(8080));
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

    /// Full HTTP-level flow: 5G-AKA success + failure, EAP-AKA' success +
    /// failure, strict-peer rejections (missing attrs, bad SNN).
    ///
    /// Single test function: it owns the process-wide UDM_SBI_ADDR/PORT env
    /// fallback and the global AUSF context.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn test_http_auth_flows_5g_aka_and_eap_aka_prime() {
        // Drives production code against a loopback PLAINTEXT peer, i.e. describes a
        // dev-profile deployment (issue #63). Declared, not inherited from the env.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        // Serialize on ausfd's global-context/env guard: re-inits the process-
        // global AUSF context and/or sets UDM/UDR_SBI_* env vars, which races any
        // other ausfd test doing the same under parallel `cargo test`.
        let _guard = crate::test_support::lock_context();
        let _ = env_logger::try_init();
        let _lock = TEST_MUTEX.lock().await;
        tokio::time::timeout(Duration::from_secs(60), async {
            ausf_context_init(64);
            // #1334: the AUSF's /metrics follows this test's authentications.
            let (metrics_addr, metrics_task) = nextgcore_metrics::nes_energy::serve_metrics(
                "127.0.0.1:0".parse().unwrap(),
                std::sync::Arc::new(crate::metrics::render_prometheus),
            )
            .await
            .expect("metrics endpoint");
            let metric =
                |b: &str, s: &str| nextgcore_metrics::nf::sample_value(b, s).unwrap_or(0.0);
            let verdicts = [
                r#"ausf_authentication_results_total{method="5g_aka",result="success"}"#,
                r#"ausf_authentication_results_total{method="5g_aka",result="failure"}"#,
                r#"ausf_authentication_results_total{method="eap_aka_prime",result="success"}"#,
                r#"ausf_operations_total{operation="authenticate",result="success"}"#,
                r#"ausf_operations_total{operation="5g_aka_confirmation",result="success"}"#,
            ];
            let before = nextgcore_metrics::nf::scrape_for_test(metrics_addr).await;
            let before: Vec<f64> = verdicts.iter().map(|s| metric(&before, s)).collect();

            // --- mock UDM on an ephemeral port ---
            let (udm_listener, udm_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let udm_port = udm_addr.port();
            let udm_server = SbiServer::on_listener(
                NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], udm_port))),
                udm_listener,
            );
            udm_server.start(mock_udm_handler).await.expect("udm start");
            std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDM_SBI_PORT", udm_port.to_string());

            // --- real AUSF handler on an ephemeral port ---
            let (ausf_listener, ausf_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let ausf_port = ausf_addr.port();
            let ausf_server = SbiServer::on_listener(
                NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], ausf_port))),
                ausf_listener,
            );
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

            // #1334: the verdicts above are counted from their authResult
            // (REVERT-VERIFIED: without `crate::metrics::observe` in
            // `ausf_sbi_request_handler` these stay where they were).
            // #1334 review: an operation label is admitted on a 2xx, so a made-up resource
            // of every service this NF serves must be answered with an error, or a client
            // could mint label values.
            for (service, version) in [
                ("nausf-auth", "v1"),
                ("nausf-sorprotection", "v1"),
                ("nausf-upuprotection", "v1"),
            ] {
                for path in [
                    format!("/{service}/{version}/madeup-resource-1334"),
                    format!("/{service}/{version}/imsi-001010000000001/madeup-resource-1334"),
                ] {
                    for request in [
                        nextgcore_sbi::message::SbiRequest::get(&path),
                        nextgcore_sbi::message::SbiRequest::post(&path)
                            .with_body("{}", "application/json"),
                    ] {
                        let resp = client.send_request(request).await.expect("answered");
                        assert!(resp.status >= 400, "{path} answered {}", resp.status);
                    }
                }
            }
            let after = nextgcore_metrics::nf::scrape_for_test(metrics_addr).await;
            assert!(
                !after.contains("madeup"),
                "no made-up resource in a label: {after}"
            );
            for (s, b) in verdicts.iter().zip(&before) {
                assert!(metric(&after, s) >= b + 1.0, "{s}: {b} -> {after}");
            }
            for name in [
                "ausf_ue_authentication_contexts",
                "ausf_kausf_anchors",
                "nextgcore_sbi_request_total",
                "nextgcore_nrf_registered",
                "nextgcore_uptime_seconds",
                "process_resident_memory_bytes",
            ] {
                assert!(
                    nextgcore_metrics::nf::has_series(&after, name),
                    "{name}:\n{after}"
                );
            }
            assert!(!after.contains("imsi-"), "no SUPI in the exposition");
            metrics_task.abort();

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
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn test_confirmation_response_shaping() {
        // Drives production code against a loopback PLAINTEXT peer, i.e. describes a
        // dev-profile deployment (issue #63). Declared, not inherited from the env.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        // Serialize on ausfd's global-context/env guard: re-inits the process-
        // global AUSF context and/or sets UDM/UDR_SBI_* env vars, which races any
        // other ausfd test doing the same under parallel `cargo test`.
        let _guard = crate::test_support::lock_context();
        let _ = env_logger::try_init();
        let _lock = TEST_MUTEX.lock().await;

        tokio::time::timeout(Duration::from_secs(60), async {
            ausf_context_init(128);

            // Mock UDM
            let (udm_listener, udm_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let udm_port = udm_addr.port();
            let udm_server = SbiServer::on_listener(
                NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], udm_port))),
                udm_listener,
            );
            udm_server.start(mock_udm_handler).await.expect("udm start");
            std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDM_SBI_PORT", udm_port.to_string());

            // Real AUSF handler
            let (ausf_listener, ausf_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let ausf_port = ausf_addr.port();
            let ausf_server = SbiServer::on_listener(
                NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], ausf_port))),
                ausf_listener,
            );
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

            // #765: an odd length and a multi-byte character used to panic the
            // handler in hex_to_bytes (a slice past the end / off a char
            // boundary). Both are a 400 like any other bad hex, and the AUSF
            // still answers afterwards.
            for bad in ["abc", "a\u{e9}b", "0".repeat(31).as_str()] {
                let (href, _rand) = initiate_5g_aka(&client, SUCI_AKA, TEST_SNN).await;
                let resp = client
                    .put_json(&href, &serde_json::json!({ "resStar": bad }))
                    .await
                    .unwrap_or_else(|e| panic!("PUT resStar:{bad:?} got no answer: {e}"));
                assert_eq!(resp.status, 400, "resStar {bad:?} must return 400 (#765)");
            }

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
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn test_auth_context_delete_lifecycle() {
        // Serialize on ausfd's global-context/env guard: re-inits the process-
        // global AUSF context and/or sets UDM/UDR_SBI_* env vars, which races any
        // other ausfd test doing the same under parallel `cargo test`.
        let _guard = crate::test_support::lock_context();
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
        let resp = handle_auth_context_delete(&ctx_id, &SbiRequest::default()).await;
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
        let resp = handle_auth_context_delete(&ctx_id, &SbiRequest::default()).await;
        assert_eq!(resp.status, 404, "second DELETE must return 404");
    }

    // ====================================================================
    // F-02: SoR/UPU anchor (TS 33.501 §6.14.1) — populated by a REAL 5G-AKA
    // confirmation through the production handler, and SURVIVES the real
    // handle_auth_context_delete (auth → delete ctx → anchor still there).
    // ====================================================================
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn test_sor_upu_anchor_survives_auth_context_delete() {
        // Drives production code against a loopback PLAINTEXT peer, i.e. describes a
        // dev-profile deployment (issue #63). Declared, not inherited from the env.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        // Serialize on ausfd's global-context/env guard: re-inits the process-
        // global AUSF context and/or sets UDM/UDR_SBI_* env vars, which races any
        // other ausfd test doing the same under parallel `cargo test`.
        let _guard = crate::test_support::lock_context();
        let _ = env_logger::try_init();
        let _lock = TEST_MUTEX.lock().await;

        tokio::time::timeout(Duration::from_secs(60), async {
            ausf_context_init(128);

            // Mock UDM (real Milenage + 5G KDFs) + real AUSF handler.
            let (udm_listener, udm_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let udm_port = udm_addr.port();
            let udm_server = SbiServer::on_listener(
                NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], udm_port))),
                udm_listener,
            );
            udm_server.start(mock_udm_handler).await.expect("udm start");
            std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDM_SBI_PORT", udm_port.to_string());

            let (ausf_listener, ausf_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let ausf_port = ausf_addr.port();
            let ausf_server = SbiServer::on_listener(
                NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], ausf_port))),
                ausf_listener,
            );
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
            let resp = handle_auth_context_delete(&ctx_id, &SbiRequest::default()).await;
            assert_eq!(resp.status, 204, "DELETE must succeed");
            assert!(
                ausf_self().read().unwrap().ue_find_by_supi(supi).is_none(),
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
    // #1872: authCtxId is an unguessable, restart-unique UUID, and each
    // authentication context is bound to the NF that started it.
    // ====================================================================

    const AMF_A_1872: &str = "18720000-0000-4000-8000-00000000000a";
    const AMF_B_1872: &str = "18720000-0000-4000-8000-00000000000b";

    fn as_nf_1872(mut req: SbiRequest, token_sub: Option<&str>, cert: Option<&str>) -> SbiRequest {
        // #1964: these callers are AMFs, as their NRF profiles would say.
        for id in token_sub.iter().chain(cert.iter()) {
            seed_caller_type_1964(id, "AMF");
        }
        req.oauth2_subject = token_sub.map(str::to_string);
        req.peer_cert_nf_instance_id = cert.map(str::to_string);
        // #2065: an AMF's certificate names its type (RFC 9310); an untyped one is
        // no identity under production, which the #2065 tests exercise on purpose.
        if cert.is_some() && req.peer_cert_nf_types.is_empty() {
            req.peer_cert_nf_types = vec!["AMF".into()];
        }
        req
    }

    /// Start a 5G-AKA through the production handler as `caller`; returns the
    /// authCtxId from the Location header and the RAND.
    async fn authenticate_1872(supi: &str, caller: SbiRequest) -> (String, [u8; 16]) {
        let req = caller.with_body(
            serde_json::json!({"supiOrSuci": supi, "servingNetworkName": TEST_SNN}).to_string(),
            "application/json",
        );
        let resp = handle_ue_authentication(&req).await;
        assert_eq!(resp.status, 201, "authenticate: {:?}", resp.http.content);
        let location = resp.http.get_header("location").expect("Location").clone();
        let ctx_id = location.rsplit('/').next().expect("authCtxId").to_string();
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).unwrap();
        let rand_bytes = crate::nudm_handler::hex_to_bytes(
            body.pointer("/5gAuthData/rand")
                .and_then(|v| v.as_str())
                .expect("rand"),
        );
        let mut rand = [0u8; 16];
        rand.copy_from_slice(&rand_bytes);
        (ctx_id, rand)
    }

    fn confirm_req_1872(rand: &[u8; 16], caller: SbiRequest) -> SbiRequest {
        let (res, ck, ik, _ak, _akstar) =
            nextgcore_crypt::milenage::milenage_f2345(&TEST_OPC, &TEST_K, rand).unwrap();
        let res_star =
            nextgcore_crypt::kdf::nextgcore_kdf_xres_star(&ck, &ik, TEST_SNN, rand, &res);
        caller.with_body(
            serde_json::json!({"resStar": crate::nudm_handler::bytes_to_hex(&res_star)})
                .to_string(),
            "application/json",
        )
    }

    /// The pool index the old authCtxId was, and a UUID per context instead.
    ///
    /// REVERT-VERIFIED: with `new_auth_ctx_id` returning a counter, the UUID
    /// parse fails.
    #[test]
    fn auth_ctx_ids_are_random_uuids_1872() {
        let mut ctx = crate::context::AusfContext::new();
        ctx.init(8);
        let a = ctx.ue_add("suci-0-001-01-0000-0-0-1872000001").unwrap();
        let b = ctx.ue_add("suci-0-001-01-0000-0-0-1872000002").unwrap();
        for ue in [&a, &b] {
            let parsed = uuid::Uuid::parse_str(&ue.ctx_id).expect("authCtxId is a UUID");
            assert_eq!(
                parsed.get_version_num(),
                4,
                "random (v4), not derived from state"
            );
        }
        assert_ne!(a.ctx_id, b.ctx_id);
        assert!(ctx.ue_find_by_ctx_id(&a.ctx_id).is_some());
        // The pool index is not an authCtxId any more.
        assert!(ctx.ue_find_by_ctx_id(&a.id.to_string()).is_none());
        assert!(ctx.ue_find_by_ctx_id("1").is_none());
    }

    /// The whole flow through the production handlers against a mock UDM:
    /// - a re-authentication gets a new authCtxId and retires the old one;
    /// - another AMF's confirmation or DELETE is refused 403 with nothing
    ///   applied (no result, no KSEAF, no anchor, context still there);
    /// - the creating AMF confirms and deletes, also through an SCP whose
    ///   certificate is not its own (the token `sub` is the identity).
    ///
    /// REVERT-VERIFIED: with `refuse_foreign_caller` returning `None`, AMF B's
    /// confirmation succeeds and the first 403 assertion fails; with
    /// `ausf_ue.ctx_id` no longer re-minted per authentication, the second
    /// authentication reuses the first authCtxId and its assertion fails; with
    /// the owner not recorded, AMF B is admitted.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn an_auth_context_answers_only_the_amf_that_started_it_1872() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _guard = crate::test_support::lock_context();
        let _lock = TEST_MUTEX.lock().await;

        tokio::time::timeout(Duration::from_secs(60), async {
            ausf_context_init(128);
            let (udm_listener, udm_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let udm_server = SbiServer::on_listener(
                NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], udm_addr.port()))),
                udm_listener,
            );
            udm_server.start(mock_udm_handler).await.expect("udm start");
            std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDM_SBI_PORT", udm_addr.port().to_string());

            let supi = "imsi-001010000001872";
            let amf_a = || as_nf_1872(SbiRequest::default(), Some(AMF_A_1872), None);
            let amf_b = || as_nf_1872(SbiRequest::default(), Some(AMF_B_1872), None);

            let (first, _) = authenticate_1872(supi, amf_a()).await;
            let (ctx_id, rand) = authenticate_1872(supi, amf_a()).await;
            assert_ne!(first, ctx_id, "a new authentication is a new resource");
            let stale = handle_5g_aka_confirmation(&first, &confirm_req_1872(&rand, amf_a())).await;
            assert_eq!(stale.status, 404, "the retired authCtxId finds nothing");
            let ue = ausf_self()
                .read()
                .unwrap()
                .ue_find_by_ctx_id(&ctx_id)
                .expect("ctx");
            assert_eq!(
                ue.owner.as_deref(),
                Some(AMF_A_1872),
                "bound to its creator"
            );

            // Another AMF: refused, nothing applied.
            for (req, what) in [
                (amf_b(), "another AMF's token"),
                (
                    as_nf_1872(SbiRequest::default(), None, Some(AMF_B_1872)),
                    "another AMF's cert",
                ),
                (SbiRequest::default(), "an unverified caller"),
            ] {
                let r = handle_5g_aka_confirmation(&ctx_id, &confirm_req_1872(&rand, req)).await;
                assert_eq!(r.status, 403, "{what} confirmation: {:?}", r.http.content);
                let ue = ausf_self()
                    .read()
                    .unwrap()
                    .ue_find_by_ctx_id(&ctx_id)
                    .expect(what);
                assert_eq!(ue.kseaf, [0u8; 32], "{what}: no KSEAF derived");
                assert!(
                    ausf_self()
                        .read()
                        .unwrap()
                        .anchor_lookup_kausf(supi)
                        .is_none(),
                    "{what}: no anchor stored"
                );
            }
            let eap = amf_b().with_body(r#"{"eapPayload":"AQ=="}"#, "application/json");
            let r = handle_eap_session(&ctx_id, &eap).await;
            assert_eq!(
                r.status, 403,
                "another AMF's EAP session: {:?}",
                r.http.content
            );
            let r = handle_auth_context_delete(&ctx_id, &amf_b()).await;
            assert_eq!(r.status, 403, "another AMF's DELETE");
            assert!(ausf_self()
                .read()
                .unwrap()
                .ue_find_by_ctx_id(&ctx_id)
                .is_some());

            // The creator, through an SCP: the certificate is the SCP's, the
            // token sub is AMF A's.
            let mut via_scp = as_nf_1872(
                SbiRequest::default(),
                Some(AMF_A_1872),
                Some("18720000-0000-4000-8000-0000000005c9"),
            );
            // #1907: the certificate's RFC 9310 NFTypes say it is an SCP's.
            via_scp.peer_cert_nf_types = vec!["SCP".into()];
            let r = handle_5g_aka_confirmation(&ctx_id, &confirm_req_1872(&rand, via_scp)).await;
            assert_eq!(r.status, 200, "the creator confirms: {:?}", r.http.content);
            let conf: serde_json::Value =
                serde_json::from_str(r.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(conf["authResult"], "AUTHENTICATION_SUCCESS");
            let upper = as_nf_1872(
                SbiRequest::default(),
                Some(&AMF_A_1872.to_uppercase()),
                None,
            );
            let r = handle_auth_context_delete(&ctx_id, &upper).await;
            assert_eq!(
                r.status, 204,
                "the creator deletes (UUIDs compare case-insensitively)"
            );
        })
        .await
        .expect("test timed out");
    }

    // ====================================================================
    // #1907: R26's #1905 minors.
    // ====================================================================

    /// (1) A copy read before a re-authentication cannot revive the retired
    /// authCtxId, or its old owner, by being written back.
    ///
    /// REVERT-VERIFIED: with `ue_update` allowed to change the authCtxId (the
    /// `new_authentication` guard removed), the stale write succeeds, the old
    /// id resolves again and the first assertion fails.
    #[test]
    fn a_stale_copy_cannot_revive_a_retired_auth_ctx_id_1907() {
        let mut ctx = crate::context::AusfContext::new();
        ctx.init(8);
        let mut first = ctx.ue_add("suci-0-001-01-0000-0-0-1907000001").unwrap();
        first.owner = Some(AMF_A_1872.into());
        assert!(ctx.ue_begin_authentication(&first));
        let stale = ctx.ue_find_by_ctx_id(&first.ctx_id).unwrap();

        // A re-authentication by AMF B retires the first authCtxId...
        let mut second = stale.clone();
        second.ctx_id = crate::context::new_auth_ctx_id();
        second.owner = Some(AMF_B_1872.into());
        assert!(ctx.ue_begin_authentication(&second));

        // ...and the request that read the first one writes back late.
        assert!(
            !ctx.ue_update(&stale),
            "a write-back for a retired authCtxId is refused"
        );
        assert!(
            ctx.ue_find_by_ctx_id(&first.ctx_id).is_none(),
            "not revived"
        );
        let current = ctx.ue_find_by_ctx_id(&second.ctx_id).expect("current");
        assert_eq!(
            current.owner.as_deref(),
            Some(AMF_B_1872),
            "owner unchanged"
        );
        // A write-back of the current one still works.
        assert!(ctx.ue_update(&current));
    }

    /// (2) A token `sub` naming another NF than the caller's own certificate is
    /// refused, on create and on later operations, unless the certificate is an
    /// SCP's.
    ///
    /// REVERT-VERIFIED: with `caller_identity` taking the token `sub` whatever
    /// the certificate says, the mismatched Subscribe-equivalent is admitted
    /// and the first assertion fails.
    #[test]
    fn a_token_naming_another_nf_than_the_certificate_is_refused_1907() {
        let mixed = as_nf_1872(SbiRequest::default(), Some(AMF_A_1872), Some(AMF_B_1872));
        let err = caller_identity(&mixed).expect_err("mismatched identities");
        assert!(err.contains("client certificate names"), "{err}");
        let mut scp = mixed.clone();
        scp.peer_cert_nf_types = vec!["SCP".into()];
        assert_eq!(
            caller_identity(&scp).unwrap().as_deref(),
            Some(AMF_A_1872),
            "through an SCP the token names the consumer"
        );
        let same = as_nf_1872(
            SbiRequest::default(),
            Some(AMF_A_1872),
            Some(&AMF_A_1872.to_uppercase()),
        );
        assert_eq!(caller_identity(&same).unwrap().as_deref(), Some(AMF_A_1872));
    }

    /// #2065: under production a certificate naming no NF type is no identity
    /// (alone: refused; with a token: the token's sub), and an unbound context is
    /// frozen; under dev both are as before. REVERT-VERIFIED: with the untyped arm
    /// removed the lone untyped certificate is accepted; with the freeze removed the
    /// unbound context admits anyone.
    #[test]
    fn an_untyped_certificate_and_an_unbound_context_under_production_2065() {
        let mut untyped = SbiRequest::default();
        untyped.peer_cert_nf_instance_id = Some(AMF_A_1872.into());
        assert!(caller_identity_with(&untyped, true).is_err());
        assert_eq!(
            caller_identity_with(&untyped, false).unwrap().as_deref(),
            Some(AMF_A_1872),
            "dev: as before"
        );
        let mut via = untyped.clone();
        via.oauth2_subject = Some(AMF_B_1872.into());
        assert_eq!(
            caller_identity_with(&via, true).unwrap().as_deref(),
            Some(AMF_B_1872),
            "with a token, the token's sub"
        );

        let mut ctx = crate::context::AusfContext::new();
        ctx.init(8);
        let unbound = ctx.ue_add("suci-0-001-01-0000-0-0-2065000001").unwrap();
        assert!(unbound.owner.is_none());
        let caller = as_nf_1872(SbiRequest::default(), Some(AMF_A_1872), None);
        let refused = refuse_foreign_caller_with(&unbound, &caller, true).expect("frozen");
        assert_eq!(refused.status, 403);
        assert!(
            refuse_foreign_caller_with(&unbound, &caller, false).is_none(),
            "dev: open"
        );
    }

    /// (2) at the handler: the authentication is refused before a context is
    /// allocated, and a later operation by a mixed caller is refused too.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn a_mixed_identity_caller_is_refused_before_anything_is_stored_1907() {
        let _guard = crate::test_support::lock_context();
        let _lock = TEST_MUTEX.lock().await;
        ausf_context_init(128);
        let suci = "suci-0-001-01-0000-0-0-1907000002";
        let req = as_nf_1872(SbiRequest::default(), Some(AMF_A_1872), Some(AMF_B_1872)).with_body(
            serde_json::json!({"supiOrSuci": suci, "servingNetworkName": TEST_SNN}).to_string(),
            "application/json",
        );
        let r = handle_ue_authentication(&req).await;
        assert_eq!(r.status, 403, "{:?}", r.http.content);
        assert!(
            ausf_self().read().unwrap().ue_find_by_suci(suci).is_none(),
            "no context allocated"
        );
    }

    /// (3) Deregister purges a SUPI's security context only for the UDM (by
    /// its certificate's NFTypes) or the AMF that started the authentication;
    /// any other AMF is refused with the context and the anchor intact.
    ///
    /// REVERT-VERIFIED: with `refuse_deregister` returning `None`, AMF B's
    /// Deregister purges A's UE and the first assertion fails.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn deregister_is_for_the_udm_or_the_owning_amf_1907() {
        let _guard = crate::test_support::lock_context();
        let _lock = TEST_MUTEX.lock().await;
        ausf_context_init(128);
        let supi = "imsi-001010000001907";
        let seed = || {
            let ctx = ausf_self();
            let guard = ctx.read().unwrap();
            let mut ue = guard.ue_add("suci-0-001-01-0000-0-0-1907000003").unwrap();
            ue.supi = Some(supi.into());
            ue.owner = Some(AMF_A_1872.into());
            assert!(guard.ue_begin_authentication(&ue));
            guard.ue_set_supi(ue.id, supi);
        };
        let deregister = |caller: SbiRequest| {
            caller.with_body(
                serde_json::json!({ "supi": supi }).to_string(),
                "application/json",
            )
        };
        let held = || ausf_self().read().unwrap().ue_find_by_supi(supi).is_some();

        seed();
        for (req, what) in [
            (
                as_nf_1872(SbiRequest::default(), Some(AMF_B_1872), None),
                "another AMF",
            ),
            (SbiRequest::default(), "an unverified caller"),
            (
                as_nf_1872(SbiRequest::default(), Some(AMF_A_1872), Some(AMF_B_1872)),
                "mixed identities",
            ),
        ] {
            let r = handle_ue_authentication_deregister(&deregister(req)).await;
            assert_eq!(r.status, 403, "{what}: {:?}", r.http.content);
            assert!(held(), "{what}: the context is intact");
        }

        // The owning AMF may.
        let r = handle_ue_authentication_deregister(&deregister(as_nf_1872(
            SbiRequest::default(),
            Some(AMF_A_1872),
            None,
        )))
        .await;
        assert_eq!(r.status, 204, "{:?}", r.http.content);
        assert!(!held());

        // So may the UDM, by its certificate's NFTypes (TS 29.509 §5.2.2.3).
        seed();
        let mut udm = as_nf_1872(
            SbiRequest::default(),
            None,
            Some("19070000-0000-4000-8000-0000000000d1"),
        );
        udm.peer_cert_nf_types = vec!["UDM".into()];
        let r = handle_ue_authentication_deregister(&deregister(udm)).await;
        assert_eq!(r.status, 204, "{:?}", r.http.content);
        assert!(!held());
    }

    /// **#1964.** Authenticate (TS 29.509 §5.2.2.2) is the AMF's, though the
    /// UDM holds `nausf-auth` and its ue-authentications scope for Deregister.
    /// A certificate naming UDM is refused; relayed by an SCP, the caller's NRF
    /// profile decides, refusing a non-AMF and refusing when it cannot be looked
    /// up; a certificate naming AMF, or an SCP-relayed AMF, passes the gate.
    ///
    /// REVERT-VERIFIED: with `refuse_authenticate` returning `None`, the UDM
    /// certificate's authenticate is not refused and the first assertion fails;
    /// with `Err` from the lookup admitted, the unlooked-up caller passes and
    /// the "could not be checked" assertion fails.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn authenticate_is_for_the_amf_only_1964() {
        let _guard = crate::test_support::lock_context();
        let _lock = TEST_MUTEX.lock().await;
        ausf_context_init(128);
        let body = |req: SbiRequest, n: u32| {
            req.with_body(
                serde_json::json!({
                    "supiOrSuci": format!("suci-0-001-01-0000-0-0-19640000{n:02}"),
                    "servingNetworkName": TEST_SNN
                })
                .to_string(),
                "application/json",
            )
        };
        let gate_refused = |r: &SbiResponse| {
            r.status == 403
                && r.http
                    .content
                    .as_deref()
                    .unwrap_or_default()
                    .contains("authenticate is for the AMF")
        };

        // A UDM, directly: its certificate names UDM.
        let mut udm = SbiRequest::default();
        udm.peer_cert_nf_instance_id = Some("19640000-0000-4000-8000-0000000000d1".into());
        udm.peer_cert_nf_types = vec!["UDM".into()];
        let r = handle_ue_authentication(&body(udm, 1)).await;
        assert!(gate_refused(&r), "a UDM certificate: {:?}", r.http.content);

        // Via the SCP: the token names the consumer, its NRF profile decides.
        let via_scp = |sub: &str| {
            let mut req = SbiRequest::default();
            req.peer_cert_nf_instance_id = Some("19640000-0000-4000-8000-0000000000c1".into());
            req.peer_cert_nf_types = vec!["SCP".into()];
            req.oauth2_subject = Some(sub.to_string());
            req
        };
        let udm_sub = "19640000-0000-4000-8000-0000000000d2";
        seed_caller_type_1964(udm_sub, "UDM");
        let r = handle_ue_authentication(&body(via_scp(udm_sub), 2)).await;
        assert!(gate_refused(&r), "a UDM via the SCP: {:?}", r.http.content);

        // A caller whose type cannot be looked up (no NRF here): refused.
        let unknown = "19640000-0000-4000-8000-0000000000e3";
        let r = handle_ue_authentication(&body(via_scp(unknown), 3)).await;
        assert!(gate_refused(&r), "{:?}", r.http.content);
        assert!(
            r.http
                .content
                .as_deref()
                .unwrap_or_default()
                .contains("could not be checked"),
            "fails closed: {:?}",
            r.http.content
        );

        // An AMF, directly or via the SCP, passes the gate (what follows is the
        // AKA itself, here without a UDM: whatever it answers, not the gate).
        let mut amf = SbiRequest::default();
        amf.peer_cert_nf_instance_id = Some("19640000-0000-4000-8000-0000000000a4".into());
        amf.peer_cert_nf_types = vec!["AMF".into()];
        let r = handle_ue_authentication(&body(amf, 4)).await;
        assert!(
            !gate_refused(&r),
            "an AMF certificate: {:?}",
            r.http.content
        );
        let amf_sub = "19640000-0000-4000-8000-0000000000a5";
        seed_caller_type_1964(amf_sub, "AMF");
        let r = handle_ue_authentication(&body(via_scp(amf_sub), 5)).await;
        assert!(
            !gate_refused(&r),
            "an AMF via the SCP: {:?}",
            r.http.content
        );
    }

    /// **#1918, #1964 (R31 M1).** Deregister is for the UDM or the owner. A UDM
    /// reaching this AUSF through an SCP (whose certificate is the SCP's) is
    /// recognised by its NRF profile and admitted. Another AMF holding the
    /// ue-authentications scope (which the AMF has, per the OpenAPI) is refused,
    /// both directly and through the SCP, with A's context intact.
    ///
    /// REVERT-VERIFIED: with the UDM check admitting any caller with the scope
    /// (the pre-R31 `has_scope`), AMF B's Deregister is 204 and the first
    /// assertion fails; with the UDM type check removed, the UDM is refused and
    /// the last assertion fails.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn deregister_is_the_udm_s_or_the_owner_s_not_another_amf_s_1964() {
        let _guard = crate::test_support::lock_context();
        let _lock = TEST_MUTEX.lock().await;
        ausf_context_init(128);
        let supi = "imsi-001010000001918";
        let ctx = ausf_self();
        {
            let guard = ctx.read().unwrap();
            let mut ue = guard.ue_add("suci-0-001-01-0000-0-0-1918000001").unwrap();
            ue.supi = Some(supi.into());
            ue.owner = Some(AMF_A_1872.into());
            assert!(guard.ue_begin_authentication(&ue));
            guard.ue_set_supi(ue.id, supi);
        }
        let held = || ausf_self().read().unwrap().ue_find_by_supi(supi).is_some();
        const SCOPE: &str = "nausf-auth nausf-auth:ue-authentications";
        let scp_cert = "19180000-0000-4000-8000-0000000000c1";
        let deregister = |mut req: SbiRequest| {
            req.oauth2_scope = Some(SCOPE.to_string());
            req.with_body(
                serde_json::json!({ "supi": supi }).to_string(),
                "application/json",
            )
        };
        let via_scp = |sub: &str| {
            let mut req = as_nf_1872(SbiRequest::default(), Some(sub), Some(scp_cert));
            req.peer_cert_nf_types = vec!["SCP".into()];
            req
        };

        // AMF B, through the SCP, with the scope: refused.
        let r = handle_ue_authentication_deregister(&deregister(via_scp(AMF_B_1872))).await;
        assert_eq!(r.status, 403, "AMF B via the SCP: {:?}", r.http.content);
        assert!(held(), "A's context is intact");

        // AMF B, directly (its certificate names AMF), with the scope: refused.
        let mut direct = as_nf_1872(SbiRequest::default(), Some(AMF_B_1872), Some(AMF_B_1872));
        direct.peer_cert_nf_types = vec!["AMF".into()];
        let r = handle_ue_authentication_deregister(&deregister(direct)).await;
        assert_eq!(r.status, 403, "AMF B directly: {:?}", r.http.content);
        assert!(held(), "A's context is intact");

        // The UDM, through the SCP: admitted by its NRF profile.
        let udm = "19180000-0000-4000-8000-0000000000d1";
        let req = via_scp(udm);
        seed_caller_type_1964(udm, "UDM");
        let r = handle_ue_authentication_deregister(&deregister(req)).await;
        assert_eq!(r.status, 204, "the UDM via the SCP: {:?}", r.http.content);
        assert!(!held(), "the stale context is cleared");
    }

    /// **#1918.** The AUSF registers the Deregister resource scope for the UDM
    /// (TS 29.510 Table 6.1.6.2.3-1 NOTE 11): `nausf-auth` admits the UDM, and
    /// its `allowedOperationsPerNfType` names every allowed type with the
    /// service scope, the UDM alone with the resource scope too. The other
    /// services carry no map.
    ///
    /// REVERT-VERIFIED: with the map not attached in `build_nf_profile`, the
    /// first map assertion fails; with UDM dropped from `AUSF_SERVICES`, the
    /// allowedNfTypes assertion fails.
    #[test]
    fn the_profile_grants_the_deregister_scope_to_the_udm_only_1918() {
        let profile = build_nf_profile(
            "ausf-1918",
            "127.0.0.1",
            7777,
            nextgcore_sbi::types::UriScheme::Http,
        );
        let services = profile["nfServices"].as_array().expect("nfServices");
        let auth = services
            .iter()
            .find(|s| s["serviceName"] == "nausf-auth")
            .expect("nausf-auth");
        let allowed: Vec<&str> = auth["allowedNfTypes"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(allowed.contains(&"UDM"), "{allowed:?}");
        let ops = &auth["allowedOperationsPerNfType"];
        assert_eq!(
            ops["UDM"],
            serde_json::json!(["nausf-auth", "nausf-auth:ue-authentications"])
        );
        // #1964: the OpenAPI's scope covers the whole collection, so the AMF
        // (authenticate) holds it as the UDM (Deregister) does; the SCP relays.
        assert_eq!(
            ops["AMF"],
            serde_json::json!(["nausf-auth", "nausf-auth:ue-authentications"])
        );
        assert_eq!(ops["SCP"], serde_json::json!(["nausf-auth"]));
        assert_eq!(
            ops.as_object().map(|m| m.len()),
            Some(allowed.len()),
            "NOTE 11: every allowed type is in the map, or it is barred"
        );
        for svc in services.iter().filter(|s| s["serviceName"] != "nausf-auth") {
            assert!(
                svc.get("allowedOperationsPerNfType").is_none(),
                "{}",
                svc["serviceName"]
            );
        }
    }

    // ====================================================================
    // #1948: a roaming authentication relayed by the home SEPP.
    // ====================================================================

    /// The home SEPP's certificate (its only NFType is SEPP) and the visited
    /// AMF's token, with `consumerPlmnId`/`producerPlmnId` claims.
    fn via_sepp_1948(
        sub: Option<&str>,
        consumer: Option<(&str, &str)>,
        producer: (&str, &str),
    ) -> SbiRequest {
        let mut req = SbiRequest::default();
        req.peer_cert_nf_instance_id = Some("19480000-0000-4000-8000-0000000000e5".into());
        req.peer_cert_nf_types = vec!["SEPP".into()];
        req.oauth2_subject = sub.map(str::to_string);
        let mut claims = serde_json::json!({
            "sub": sub, "producerPlmnId": { "mcc": producer.0, "mnc": producer.1 },
        });
        if let Some((mcc, mnc)) = consumer {
            claims["consumerPlmnId"] = serde_json::json!({ "mcc": mcc, "mnc": mnc });
        }
        let payload = nextgcore_crypt::base64::encode(claims.to_string().as_bytes());
        req.http
            .set_header("Authorization", format!("Bearer hdr.{payload}.sig"));
        req
    }

    /// #1948: a 5G-AKA relayed by the home SEPP (TS 33.501 §13.2, §6.1.2) is
    /// served: the token `sub` (the visited AMF) is the identity and owns the
    /// context, and it confirms through the SEPP. Not widened past what a SEPP
    /// relays: refused 403 with no token, with a token that is not inter-PLMN
    /// (no PLMN claims, or consumer = producer), when the serving network name
    /// is not the consumer's PLMN, and for Deregister (the home UDM's).
    ///
    /// REVERT-VERIFIED: with the SEPP left out of `caller_identity`'s relay
    /// exemption, the relayed authentication is 403; with `refuse_sepp_relayed`
    /// returning `None`, the same-PLMN token is 201; with the Deregister refusal
    /// dropped, the owner's SEPP-relayed Deregister is not refused.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn a_roaming_authentication_relayed_by_the_home_sepp_1948() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _guard = crate::test_support::lock_context();
        let _lock = TEST_MUTEX.lock().await;

        tokio::time::timeout(Duration::from_secs(60), async {
            ausf_context_init(128);
            let (udm_listener, udm_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let udm_server = SbiServer::on_listener(
                NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], udm_addr.port()))),
                udm_listener,
            );
            udm_server.start(mock_udm_handler).await.expect("udm start");
            std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDM_SBI_PORT", udm_addr.port().to_string());

            // The visited PLMN is TEST_SNN's (001/01); the home PLMN 999/70.
            let v_amf = "19480000-0000-4000-8000-0000000000a1";
            let home = ("999", "70");
            let roaming = || via_sepp_1948(Some(v_amf), Some(("001", "01")), home);
            let supi = "imsi-001010000001948";
            let auth = |req: SbiRequest, snn: &str| {
                req.with_body(
                    serde_json::json!({"supiOrSuci": supi, "servingNetworkName": snn}).to_string(),
                    "application/json",
                )
            };
            for (req, snn, what) in [
                (
                    via_sepp_1948(None, Some(("001", "01")), home),
                    TEST_SNN,
                    "no token",
                ),
                (
                    via_sepp_1948(Some(v_amf), None, home),
                    TEST_SNN,
                    "no consumerPlmnId",
                ),
                (
                    via_sepp_1948(Some(v_amf), Some(("001", "01")), ("001", "01")),
                    TEST_SNN,
                    "consumer and producer are one PLMN",
                ),
                (
                    roaming(),
                    "5G:mnc002.mcc002.3gppnetwork.org",
                    "an SNN not the consumer's",
                ),
            ] {
                let r = handle_ue_authentication(&auth(req, snn)).await;
                assert_eq!(r.status, 403, "{what}: {:?}", r.http.content);
            }
            assert!(ausf_self()
                .read()
                .unwrap()
                .ue_find_by_suci_or_supi(supi)
                .is_none());

            let (ctx_id, rand) = authenticate_1872(supi, roaming()).await;
            let ue = ausf_self()
                .read()
                .unwrap()
                .ue_find_by_ctx_id(&ctx_id)
                .expect("ctx");
            assert_eq!(ue.owner.as_deref(), Some(v_amf), "the visited AMF owns it");
            let r = handle_5g_aka_confirmation(&ctx_id, &confirm_req_1872(&rand, roaming())).await;
            assert_eq!(
                r.status, 200,
                "confirmed through the SEPP: {:?}",
                r.http.content
            );

            let r = handle_ue_authentication_deregister(&roaming().with_body(
                serde_json::json!({ "supi": supi }).to_string(),
                "application/json",
            ))
            .await;
            assert_eq!(r.status, 403, "Deregister via a SEPP: {:?}", r.http.content);
            udm_server.stop().await.ok();
        })
        .await
        .expect("no hang");
    }

    // ====================================================================
    // #1928: R26's #1919 minors.
    // ====================================================================

    /// (1) Only a certificate naming the SCP alone is exempt from the
    /// token/certificate match.
    ///
    /// REVERT-VERIFIED: with `via_scp` back to "any type is SCP", the AMF+SCP
    /// certificate is exempt and the first assertion fails.
    #[test]
    fn only_a_pure_scp_certificate_is_exempt_1928() {
        let mut mixed_types = as_nf_1872(SbiRequest::default(), Some(AMF_A_1872), Some(AMF_B_1872));
        mixed_types.peer_cert_nf_types = vec!["AMF".into(), "SCP".into()];
        assert!(
            caller_identity(&mixed_types).is_err(),
            "an AMF certificate that also says SCP is not an SCP's"
        );
        let mut scp = mixed_types.clone();
        scp.peer_cert_nf_types = vec!["SCP".into()];
        assert_eq!(caller_identity(&scp).unwrap().as_deref(), Some(AMF_A_1872));
    }

    /// (2) A DELETE checked against one authentication cannot remove the one
    /// another AMF started in between.
    ///
    /// REVERT-VERIFIED: with `ue_remove_if_ctx` ignoring the authCtxId (plain
    /// `ue_remove`), the re-authenticated context is removed and the first
    /// assertion fails.
    #[test]
    fn a_removal_spares_an_authentication_started_meanwhile_1928() {
        let mut ctx = crate::context::AusfContext::new();
        ctx.init(8);
        let mut ue = ctx.ue_add("suci-0-001-01-0000-0-0-1928000001").unwrap();
        ue.owner = Some(AMF_A_1872.into());
        assert!(ctx.ue_begin_authentication(&ue));
        let checked = ue.ctx_id.clone();

        // AMF B re-authenticates between the DELETE's check and its removal.
        let mut reauth = ue.clone();
        reauth.ctx_id = crate::context::new_auth_ctx_id();
        reauth.owner = Some(AMF_B_1872.into());
        assert!(ctx.ue_begin_authentication(&reauth));

        assert!(
            ctx.ue_remove_if_ctx(ue.id, &checked).is_none(),
            "the checked authentication is gone, so nothing is removed"
        );
        let current = ctx
            .ue_find_by_ctx_id(&reauth.ctx_id)
            .expect("B's context stays");
        assert_eq!(current.owner.as_deref(), Some(AMF_B_1872));
        assert!(ctx.ue_remove_if_ctx(ue.id, &reauth.ctx_id).is_some());
        assert!(ctx.ue_find_by_ctx_id(&reauth.ctx_id).is_none());
    }

    /// (3) An anonymous Deregister purges nothing, even of an unbound context
    /// or a bare SoR/UPU anchor (dev).
    ///
    /// REVERT-VERIFIED: with the anonymous case admitted again for unbound
    /// state, the anchor is purged and the first assertion fails.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn an_anonymous_deregister_purges_no_anchor_1928() {
        let _guard = crate::test_support::lock_context();
        let _lock = TEST_MUTEX.lock().await;
        ausf_context_init(128);
        let supi = "imsi-001010000001928";
        {
            let ctx = ausf_self();
            let guard = ctx.read().unwrap();
            guard.anchor_refresh(supi, &[7u8; 32]);
            let mut ue = guard.ue_add("suci-0-001-01-0000-0-0-1928000002").unwrap();
            ue.supi = Some(supi.into());
            assert!(guard.ue_begin_authentication(&ue)); // unbound: no owner
            guard.ue_set_supi(ue.id, supi);
        }
        let req = SbiRequest::default().with_body(
            serde_json::json!({ "supi": supi }).to_string(),
            "application/json",
        );
        let r = handle_ue_authentication_deregister(&req).await;
        assert_eq!(r.status, 403, "{:?}", r.http.content);
        assert!(
            ausf_self()
                .read()
                .unwrap()
                .anchor_lookup_kausf(supi)
                .is_some(),
            "the latest KAUSF survives an anonymous Deregister"
        );
        assert!(ausf_self().read().unwrap().ue_find_by_supi(supi).is_some());
    }

    // ====================================================================
    // Issue #82: TS 29.509 §5.2.2.3 Deregister, HAL media type, and the
    // declared-but-unimplemented resources.
    // ====================================================================

    /// **The #82 acceptance test, and the design point.** Deregister clears the
    /// stale security context INCLUDING the per-SUPI SoR/UPU anchor, which is the
    /// exact opposite of `handle_auth_context_delete` (whose companion test
    /// `test_sor_upu_anchor_survives_auth_context_delete` asserts the anchor
    /// SURVIVES).
    ///
    /// TS 29.509 §5.2.2.3.1 states the purpose: the consumer (the UDM) asks the
    /// AUSF "to clear the stale security context ... so as to ensure only latest
    /// Kausf is maintained in the network". Reusing the DELETE teardown verbatim
    /// would leave the anchor `K_AUSF` behind and fail that purpose, so the two
    /// operations deliberately differ and both are pinned.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn test_deregister_clears_context_and_the_sor_upu_anchor() {
        // Drives production code against a loopback PLAINTEXT peer, i.e. describes a
        // dev-profile deployment (issue #63). Declared, not inherited from the env.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _guard = crate::test_support::lock_context();
        let _ = env_logger::try_init();
        let _lock = TEST_MUTEX.lock().await;

        tokio::time::timeout(Duration::from_secs(60), async {
            ausf_context_init(128);

            let (udm_listener, udm_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let udm_port = udm_addr.port();
            let udm_server = SbiServer::on_listener(
                NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], udm_port))),
                udm_listener,
            );
            udm_server.start(mock_udm_handler).await.expect("udm start");
            std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDM_SBI_PORT", udm_port.to_string());

            let (ausf_listener, ausf_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let ausf_port = ausf_addr.port();
            let ausf_server = SbiServer::on_listener(
                NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], ausf_port))),
                ausf_listener,
            );
            ausf_server
                .start(ausf_sbi_request_handler)
                .await
                .expect("ausf start");
            let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", ausf_port);

            // Fresh SUPI so no earlier test can have seeded state for it.
            let supi = "imsi-001010000000821";

            // Real 5G-AKA flow so the anchor is populated by the production hook.
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

            // Both pieces of state exist before deregistration.
            let kausf = ausf_self()
                .read()
                .unwrap()
                .anchor_lookup_kausf(supi)
                .expect("anchor after successful primary auth");
            assert_ne!(kausf, [0u8; 32], "anchor KAUSF must not be zero");
            assert!(
                ausf_self().read().unwrap().ue_find_by_supi(supi).is_some(),
                "auth context exists before deregistration"
            );

            // ── UDM-style deregistration, through the REAL router ─────────────
            // `DeregistrationInfo` carries ONLY `supi` — no servingNetworkName.
            // Before #82 this fell through to the authenticate handler, which
            // demanded one and answered 400.
            // #1928: as the UDM, verified by its certificate's NFTypes. The
            // loopback client presents no certificate, so the handler is
            // called with the identity the TLS layer would have attached.
            let udm_deregister = || {
                let mut req = SbiRequest::post("/nausf-auth/v1/ue-authentications/deregister")
                    .with_body(
                        serde_json::json!({ "supi": supi }).to_string(),
                        "application/json",
                    );
                req.peer_cert_nf_instance_id = Some("19280000-0000-4000-8000-0000000000d1".into());
                req.peer_cert_nf_types = vec!["UDM".into()];
                req
            };
            let resp = ausf_sbi_request_handler(udm_deregister()).await;
            assert_eq!(
                resp.status, 204,
                "a conformant DeregistrationInfo must be 204, not the pre-#82 400"
            );

            // The authentication context is gone (and was zeroized on removal)...
            assert!(
                ausf_self().read().unwrap().ue_find_by_supi(supi).is_none(),
                "deregister must remove the authentication context"
            );
            // ...and so is the anchor: THIS is what distinguishes deregister from
            // DELETE, and what makes "only the latest KAUSF is maintained" true.
            assert!(
                ausf_self()
                    .read()
                    .unwrap()
                    .anchor_lookup_kausf(supi)
                    .is_none(),
                "deregister must purge the stale SoR/UPU anchor KAUSF (TS 29.509 §5.2.2.3.1)"
            );
            // With no anchor, the SoR/UPU counter lifecycle refuses to serve.
            assert_eq!(
                ausf_self().read().unwrap().anchor_next_sor_counter(supi),
                Err(crate::AnchorCounterError::NoAnchor),
                "no anchor means SoR/UPU can no longer be protected with a stale key"
            );

            // Nothing left to clear → 404 on a repeat.
            let resp = ausf_sbi_request_handler(udm_deregister()).await;
            assert_eq!(resp.status, 404, "a second deregister has nothing to clear");
        })
        .await
        .expect("test timed out");
    }

    /// Deregister input validation (issue #82). The load-bearing case is the
    /// LAST one: a body with `supi` and no `servingNetworkName` must NOT be run
    /// through `validate_authentication_info`, which is what produced the 400
    /// before the dedicated route existed.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn test_deregister_validation_and_unknown_supi() {
        let _guard = crate::test_support::lock_context();
        let _lock = TEST_MUTEX.lock().await;
        ausf_context_init(128);

        let post = |body: Option<serde_json::Value>| {
            // #1928: Deregister needs a verified caller; the UDM, by its
            // certificate's NFTypes (the in-process server sees no TLS).
            let mut req = SbiRequest::post("/nausf-auth/v1/ue-authentications/deregister");
            req.peer_cert_nf_instance_id = Some("19280000-0000-4000-8000-0000000000d1".into());
            req.peer_cert_nf_types = vec!["UDM".into()];
            match body {
                Some(v) => req.with_json_body(&v).expect("valid JSON"),
                None => req,
            }
        };

        // No body → 400.
        assert_eq!(
            ausf_sbi_request_handler(post(None)).await.status,
            400,
            "a missing body must be 400"
        );

        // Malformed JSON → 400.
        assert_eq!(
            ausf_sbi_request_handler(
                SbiRequest::post("/nausf-auth/v1/ue-authentications/deregister")
                    .with_body("{not json", "application/json")
            )
            .await
            .status,
            400,
            "malformed JSON must be 400"
        );

        // `supi` absent or empty → 400 (it is the only required member).
        for body in [
            serde_json::json!({}),
            serde_json::json!({ "supi": "" }),
            serde_json::json!({ "supportedFeatures": "0" }),
        ] {
            assert_eq!(
                ausf_sbi_request_handler(post(Some(body.clone())))
                    .await
                    .status,
                400,
                "a DeregistrationInfo without supi must be 400: {body}"
            );
        }

        // A well-formed body for a SUPI the AUSF holds nothing for → 404, NOT the
        // 400 the authenticate handler would have produced for the missing
        // servingNetworkName. The status is what proves the request was parsed as
        // a DeregistrationInfo.
        let resp = ausf_sbi_request_handler(post(Some(
            serde_json::json!({ "supi": "imsi-001019999999999" }),
        )))
        .await;
        assert_eq!(
            resp.status, 404,
            "an unknown SUPI is 404 (a 400 here would mean it was parsed as \
             AuthenticationInfo again)"
        );
    }

    /// Issue #82: the `201 UEAuthenticationCtx` is declared
    /// `application/3gppHal+json` ONLY (`TS29509_Nausf_UEAuthentication.yaml:44-48`)
    /// on BOTH the 5G-AKA and EAP-AKA' branches, because it carries the `_links`
    /// map the consumer must follow. A strict HAL client content-negotiating on
    /// that type can reject or mis-parse a body served as `application/json`.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn test_ue_authentication_ctx_is_served_as_hal_json() {
        // Drives production code against a loopback PLAINTEXT peer, i.e. describes a
        // dev-profile deployment (issue #63). Declared, not inherited from the env.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _guard = crate::test_support::lock_context();
        let _ = env_logger::try_init();
        let _lock = TEST_MUTEX.lock().await;

        tokio::time::timeout(Duration::from_secs(60), async {
            ausf_context_init(64);

            let (udm_listener, udm_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let udm_port = udm_addr.port();
            let udm_server = SbiServer::on_listener(
                NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], udm_port))),
                udm_listener,
            );
            udm_server.start(mock_udm_handler).await.expect("udm start");
            std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDM_SBI_PORT", udm_port.to_string());

            let (ausf_listener, ausf_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let ausf_port = ausf_addr.port();
            let ausf_server = SbiServer::on_listener(
                NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], ausf_port))),
                ausf_listener,
            );
            ausf_server
                .start(ausf_sbi_request_handler)
                .await
                .expect("ausf start");
            let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", ausf_port);

            // SUPI_5G_AKA selects 5G-AKA at the mock UDM, SUPI_EAP selects
            // EAP-AKA' — so both 201 branches are exercised.
            for (identity, expected_auth_type) in
                [(SUPI_5G_AKA, "5G_AKA"), (SUPI_EAP, "EAP_AKA_PRIME")]
            {
                let resp = client
                    .post_json(
                        "/nausf-auth/v1/ue-authentications",
                        &serde_json::json!({
                            "supiOrSuci": identity,
                            "servingNetworkName": TEST_SNN
                        }),
                    )
                    .await
                    .expect("POST ue-authentications");
                assert_eq!(resp.status, 201, "{expected_auth_type} must be 201");

                assert_eq!(
                    resp.http.get_header("Content-Type").map(String::as_str),
                    Some(nextgcore_sbi::constants::content_type::APPLICATION_3GPP_HAL_JSON),
                    "the {expected_auth_type} 201 UEAuthenticationCtx must be HAL, got {:?}",
                    resp.http.get_header("Content-Type")
                );

                // Still the same body, and it really does carry the _links map
                // that is the reason the media type is HAL.
                let body: serde_json::Value =
                    serde_json::from_str(resp.http.content.as_deref().expect("body")).unwrap();
                assert_eq!(
                    body.get("authType").and_then(|v| v.as_str()),
                    Some(expected_auth_type)
                );
                assert!(
                    body.get("_links").is_some_and(|l| l.is_object()),
                    "the HAL body must carry _links: {body}"
                );
            }
        })
        .await
        .expect("test timed out");
    }

    /// Issue #82: a body with no `supiOrSuci` is rejected 400 instead of being
    /// coerced to the literal `"unknown"` and queried against the UDM.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn test_missing_supi_or_suci_is_rejected() {
        let _guard = crate::test_support::lock_context();
        let _lock = TEST_MUTEX.lock().await;
        ausf_context_init(64);

        // No UDM is configured for this test on purpose: if the handler still
        // defaulted to "unknown" it would try to reach one, so a 400 also proves
        // no UDM query was attempted.
        for body in [
            serde_json::json!({ "servingNetworkName": TEST_SNN }),
            serde_json::json!({ "supiOrSuci": "", "servingNetworkName": TEST_SNN }),
        ] {
            let req = SbiRequest::post("/nausf-auth/v1/ue-authentications")
                .with_json_body(&body)
                .expect("valid JSON");
            let resp = ausf_sbi_request_handler(req).await;
            assert_eq!(
                resp.status, 400,
                "supiOrSuci is a mandatory IE; {body} must be 400"
            );
        }
    }

    /// Issue #82: resources TS 29.509 DECLARES but this AUSF does not implement
    /// answer `501 Not Implemented`, not `405 Method Not Allowed`. A 405 claims
    /// the resource exists but rejects the verb, which is false and invites a
    /// consumer to retry with another method.
    #[tokio::test]
    async fn test_declared_but_unimplemented_resources_are_501() {
        for path in [
            "/nausf-auth/v1/rg-authentications",
            "/nausf-auth/v1/prose-authentications",
            "/nausf-auth/v1/prose-authentications/ctx-1/prose-auth",
        ] {
            let resp = ausf_sbi_request_handler(SbiRequest::post(path)).await;
            assert_eq!(resp.status, 501, "POST {path} must be 501");
        }

        // A genuinely unknown resource is still a fallthrough, not a 501 —
        // 501 means "declared by the API but unimplemented here".
        let resp =
            ausf_sbi_request_handler(SbiRequest::post("/nausf-auth/v1/not-a-resource")).await;
        assert_ne!(
            resp.status, 501,
            "an undeclared resource must not claim 501"
        );
    }

    // ====================================================================
    // ausfd-05: serving-network-name entitlement vs consumer token PLMN
    // ====================================================================
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn test_snn_entitlement_against_consumer_token() {
        // Drives production code against a loopback PLAINTEXT peer, i.e. describes a
        // dev-profile deployment (issue #63). Declared, not inherited from the env.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        // Serialize on ausfd's global-context/env guard: re-inits the process-
        // global AUSF context and/or sets UDM/UDR_SBI_* env vars, which races any
        // other ausfd test doing the same under parallel `cargo test`.
        let _guard = crate::test_support::lock_context();
        let _ = env_logger::try_init();
        let _lock = TEST_MUTEX.lock().await;

        tokio::time::timeout(Duration::from_secs(60), async {
            ausf_context_init(128);

            // Mock UDM (so the permissive/matching case can reach 201).
            let (udm_listener, udm_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let udm_port = udm_addr.port();
            let udm_server = SbiServer::on_listener(
                NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], udm_port))),
                udm_listener,
            );
            udm_server.start(mock_udm_handler).await.expect("udm start");
            std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDM_SBI_PORT", udm_port.to_string());

            // Real AUSF handler.
            let (ausf_listener, ausf_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let ausf_port = ausf_addr.port();
            let ausf_server = SbiServer::on_listener(
                NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], ausf_port))),
                ausf_listener,
            );
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
        let profile = build_nf_profile(
            "test-instance",
            "127.0.0.1",
            7777,
            nextgcore_sbi::types::UriScheme::Http,
        );

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
            // #392: and its own consumer set (TS 29.510 §6.1.6.2.3).
            let name = svc["serviceName"].as_str().unwrap_or_default();
            assert!(
                svc["allowedNfTypes"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty()),
                "{name} must state which NF types may consume it"
            );
        }
    }

    /// #392: the typed self instance and the registered profile advertise the SAME
    /// surface, because both render `AUSF_SERVICES`.
    ///
    /// They were two hand-written service lists that happened to agree. A third
    /// Nausf service added to one and not the other would have been a silent
    /// divergence, which is the shape #237 recorded for `pcfd`.
    #[test]
    fn the_ausf_self_instance_matches_the_registered_profile() {
        let instance = build_ausf_nf_instance("ausf-test-instance", "10.45.0.16", 7777);
        let profile = build_nf_profile(
            "ausf-test-instance",
            "10.45.0.16",
            7777,
            nextgcore_sbi::types::UriScheme::Http,
        );

        let mut from_instance: Vec<String> =
            instance.services.iter().map(|s| s.name.clone()).collect();
        let mut from_profile: Vec<String> = profile["nfServices"]
            .as_array()
            .expect("nfServices")
            .iter()
            .map(|s| s["serviceName"].as_str().unwrap_or_default().to_string())
            .collect();
        from_instance.sort();
        from_profile.sort();

        assert_eq!(from_instance, from_profile);
        assert_eq!(from_instance.len(), AUSF_SERVICES.len());
        // The two services the UDM discovers BY NAME must both be present.
        assert!(from_instance.iter().any(|n| n == "nausf-sorprotection"));
        assert!(from_instance.iter().any(|n| n == "nausf-upuprotection"));
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
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global AUSF state (current-thread test)
    async fn test_sor_upu_protection_http_end_to_end() {
        // Drives production code against a loopback PLAINTEXT peer, i.e. describes a
        // dev-profile deployment (issue #63). Declared, not inherited from the env.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        // Serialize on ausfd's global-context/env guard: re-inits the process-
        // global AUSF context and/or sets UDM/UDR_SBI_* env vars, which races any
        // other ausfd test doing the same under parallel `cargo test`.
        let _guard = crate::test_support::lock_context();
        let _ = env_logger::try_init();
        let _lock = TEST_MUTEX.lock().await;

        tokio::time::timeout(Duration::from_secs(60), async {
            ausf_context_init(128);

            // Mock UDM (real Milenage + 5G KDFs) + real AUSF dispatcher.
            let (udm_listener, udm_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let udm_port = udm_addr.port();
            let udm_server = SbiServer::on_listener(
                NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], udm_port))),
                udm_listener,
            );
            udm_server.start(mock_udm_handler).await.expect("udm start");
            std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDM_SBI_PORT", udm_port.to_string());

            let (ausf_listener, ausf_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let ausf_port = ausf_addr.port();
            let ausf_server = SbiServer::on_listener(
                NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], ausf_port))),
                ausf_listener,
            );
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
            let expected_xmac = nextgcore_crypt::kdf::nextgcore_kdf_sor_mac_iue(&kausf, 0x0001);
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
                0x04, 0x00, 0x02, 0x21, 0x43, 0x02, 0x00, 0x07, 0x01, 0x01, 0x04, 0x02, 0x00, 0x00,
                0x7B,
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
            let expected_mac =
                nextgcore_crypt::kdf::nextgcore_kdf_upu_mac_iausf(&kausf, &GOLDEN_UPU, 0x0001);
            assert_eq!(
                crate::nudm_handler::hex_to_bytes(upu["upuMacIausf"].as_str().unwrap()),
                expected_mac.to_vec(),
                "upuMacIausf must be reproducible from KAUSF + documented S-string"
            );
            let expected_xmac = nextgcore_crypt::kdf::nextgcore_kdf_upu_mac_iue(&kausf, 0x0001);
            assert_eq!(
                crate::nudm_handler::hex_to_bytes(upu["upuXmacIue"].as_str().unwrap()),
                expected_xmac.to_vec()
            );

            // ---- Fail-closed over the wire ----
            // Unknown SUPI → 404 CONTEXT_NOT_FOUND, never a MAC.
            let resp = client
                .post_json(
                    "/nausf-sorprotection/v1/imsi-001019999999999/ue-sor",
                    &sor_body,
                )
                .await
                .expect("sor 404");
            assert_eq!(resp.status, 404);
            let pd: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap();
            assert_eq!(pd["cause"], "CONTEXT_NOT_FOUND");
            assert!(pd.get("sorMacIausf").is_none());
            let resp = client
                .post_json(
                    "/nausf-upuprotection/v1/imsi-001019999999999/ue-upu",
                    &upu_body,
                )
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

    fn build_es256_token(
        sk: &p256::ecdsa::SigningKey,
        kid: &str,
        aud: &str,
        scope: &str,
    ) -> String {
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
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Ausf);
        let server = SbiServer::on_listener(cfg, port_listener);
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
        std::fs::write(
            &off,
            "ausf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n",
        )
        .unwrap();
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
    async fn test_oauth2_wrong_audience_rejected_403() {
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
        assert_eq!(resp.status, 403, "wrong-audience token must be 403 (#1766)");
        // #1779 review m2: the gate's claim mismatch, not a handler's own 403.
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap_or_default();
        assert_eq!(problem["cause"], "ACCESS_TOKEN_CLAIM_MISMATCH", "{problem}");
        assert_eq!(problem["invalidParams"][0]["param"], "aud", "{problem}");
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

/// #1313 review: a config that does not parse now fails startup, so every
/// shipped config of this daemon must parse with its typed structs.
#[cfg(test)]
mod shipped_config_tests {
    #[test]
    fn the_shipped_configs_parse() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        {
            let rel = "docker/rust/configs/5gc/ausf.yaml";
            let text = std::fs::read_to_string(root.join(rel)).unwrap();
            serde_yaml::from_str::<super::AusfYaml>(&text).unwrap_or_else(|e| panic!("{rel}: {e}"));
        }
        let cm: serde_yaml::Value = serde_yaml::from_str(
            &std::fs::read_to_string(root.join("k8s/manifests/configmap.yaml")).unwrap(),
        )
        .unwrap();
        let text = cm["data"]["ausf.yaml"]
            .as_str()
            .expect("the ConfigMap's ausf.yaml");
        serde_yaml::from_str::<super::AusfYaml>(text).expect("k8s ausf.yaml");
        // #1312 (#1317 review): and as the Helm chart renders it (CI installs helm
        // and sets NEXTGCORE_HELM_REQUIRED, so this is never skipped there).
        if let Some(text) = nextgcore_core::helm_render::helm_rendered_config(&root, "ausf.yaml") {
            serde_yaml::from_str::<super::AusfYaml>(&text).expect("Helm ausf.yaml");
        }
    }
}

/// #1324: the NFProfile carries its host where its type belongs (TS 29.510
/// §6.1.6.2.2): IPv4 in ipv4Addresses, IPv6 in ipv6Addresses, an FQDN as fqdn, and
/// the service ipEndPoints likewise.
#[cfg(test)]
mod tests_nf_profile_host_kind_1324 {
    use super::*;

    #[test]
    fn the_nf_profile_carries_its_host_by_type() {
        for host in nextgcore_sbi::nf_addressing::SAMPLE_HOSTS {
            let profile = build_nf_profile("id", host, 7777, nextgcore_sbi::types::UriScheme::Http);
            let problems =
                nextgcore_sbi::nf_addressing::profile_addressing_problems(&profile, host);
            assert!(problems.is_empty(), "{host}: {problems:?}\n{profile}");
        }
    }
}

/// #1791: the registered NFProfile advertises, in every `nfServices[].scheme`,
/// the scheme this NF's SBI listener serves (TS 29.510 §6.1.6.2.3
/// `NFService.scheme`). The listener follows the SBI security profile, so under
/// `production` that is `https` and under `dev` `http`. The listener config here
/// comes from `apply_sbi_security_policy`, the step `main` runs; `main` passes the
/// config's scheme in, and the nextgcore-sbi source guard
/// `every_nf_advertises_its_listener_scheme_1791` pins that wiring.
///
/// REVERT-VERIFIED: with the builder advertising `"http"` again, the production
/// case fails here.
#[cfg(test)]
mod tests_advertised_scheme_1791 {
    use super::*;
    use nextgcore_sbi::security::{SbiProfile, SbiSecurityPolicy, TlsPaths};

    #[test]
    fn the_nf_profile_advertises_the_listener_scheme_1791() {
        let dir = std::env::temp_dir().join(format!(
            "scheme-1791-{}-{}",
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
                cert: file("nf.crt"),
                key: file("nf.key"),
                ca_cert: file("ca.crt"),
                client_cert: Some(file("client.crt")),
                client_key: Some(file("client.key")),
            },
            ..SbiSecurityPolicy::production()
        };
        let addr: std::net::SocketAddr = "127.0.0.1:7777".parse().unwrap();
        for (profile, want) in [(SbiProfile::Production, "https"), (SbiProfile::Dev, "http")] {
            let cfg = nextgcore_sbi::security::apply_sbi_security_policy(
                nextgcore_sbi::server::SbiServerConfig::new(addr),
                profile,
                &policy,
                nextgcore_sbi::types::NfType::Ausf,
                "http://127.0.0.10:7777",
            )
            .expect("the profile applies");
            let nf_profile = build_nf_profile("ausf-1791", "10.0.0.1", 7777, cfg.scheme);
            let services = nf_profile["nfServices"].as_array().expect("nfServices");
            assert!(!services.is_empty(), "the profile offers services");
            for svc in services {
                assert_eq!(
                    svc["scheme"], want,
                    "under {profile:?}, {} must advertise the listener's scheme",
                    svc["serviceName"]
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
