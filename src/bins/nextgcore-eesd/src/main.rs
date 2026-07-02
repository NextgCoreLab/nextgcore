//! NextGCore EES (Edge Enabler Server)
//!
//! The EES is an Edge Enabler Layer entity (TS 23.558 / TS 24.558 / TS 29.558),
//! NOT a 5GC NRF-discoverable NF (there is no `nfType "EES"` in TS 29.510). It
//! exposes the `eees-*` service APIs with the `{apiRoot}/<apiName>/<apiVersion>`
//! layout and self-registers toward the Edge Configuration Server (ECS) over
//! EDGE-6, not the NRF.
//!
//! Implemented (Batch 1):
//! - eesd-01: `eees-*` apiName routing + ECS-registration scaffold; the bespoke
//!   `nees-*`/NRF/`NfType::Ees` self-registration is removed.
//! - eesd-02: `EASRegistration`/`EASProfile`/`EndPoint` data model (`types.rs`)
//!   with mandatory-IE rejection (400 ProblemDetails).
//! - eesd-03: server-minted `registrationId` resource key; consumer `easId`
//!   preserved verbatim and indexed separately.
//! - eesd-08: per-operation OAuth2 authorization (`auth::require_oauth2`).
//!
//! Implemented (Batch 2):
//! - eesd-04: EAS Registration update — PUT full-replace (reject `easId` change)
//!   and PATCH RFC 7396 merge (200/204).
//! - eesd-05: full EAS Discovery (`EasDiscoveryReq`/`Resp`/filter on
//!   easId/easType/acIds/svcArea) + `/subscriptions` CRUD + notify stub.
//! - eesd-06: EEC Registration API (`eees-eecregistration`, `eec.rs`) with a
//!   server-minted `registrationId` + `expTime` lifecycle.
//! - eesd-11: `suppFeat` negotiation (echoed) + valid 3GPP ProblemDetails causes.
//! - eesd-12: EAS/EEC `expTime` + a periodic lifecycle sweep.
//!
//! Implemented (eesd-07):
//! - eesd-07: Application Context Relocation (ACR) suite (`acr.rs`) — three
//!   service APIs: `eees-appctxtreloc` (Determine/Initiate/Declare, TS 24.558
//!   §5.5), `eees-eel-acr` (EEL-managed ACR, TS 29.558 §5.11), and
//!   `eees-acrstatus-update` (ACR status update, TS 29.558 §5.12). ACR state
//!   machine keyed by (eecId, sEasId) in `EesContext`. Notification delivery
//!   is STUB (logged; no live EAS/EEC callback peer). The legacy bespoke
//!   `nees-uecontexttransfer` route is absent (removed in eesd-01).
//!
//!
//! Implemented (eesd-13):
//! - eesd-13: remaining EES service APIs (`services.rs`) — CEA
//!   (`eees-cea`, TS 29.558 §5.14), AppClientInformation
//!   (`eees-appclientinformation`, TS 29.558 §5.5), ACRManagementEvent
//!   (`eees-acrmgntevent`, TS 29.558 §5.8), EECContextRelocation
//!   (`eees-eeccontextreloc`, TS 29.558 §5.10), ACRParameterInformation
//!   (`eees-acr-param`, TS 29.558 §5.13). SessionWithQoS and TIE DEFERRED
//!   (NEF/PCF-AF exposure path missing in this repo).
//!
//! Implemented (Wave 6, D1+D2):
//! - D1: `eees-appclientinformation` bodies are spec-exact
//!   `ACInfoSubscription` (TS29558_Eees_AppClientInformation.yaml; sole
//!   mandatory IE `easId`); PUT is a validated full replace while PATCH is an
//!   RFC 7396 merge restricted to the `ACInfoSubscriptionPatch` members; the
//!   non-spec collection GET now answers 405.
//! - D2: `eees-eeccontextreloc` push takes the spec `EECContextPush`
//!   envelope ({eesId, eecCntx{eecId, cntxId}}) answering 204 (or 200
//!   `EECContextPushRes` when `acrScenariosSelReq` selects scenarios), and
//!   pull is `GET /eec-contexts?ees-id=..&eec-cntx-id=..` (both REQUIRED);
//!   the bespoke path-param pull and list are gone (404/405).
//! - D3: `eees-cea` is the spec custom operation `POST /declare` taking
//!   `CommonEASInfo` (required requestorId/easId/easEndPt/appGrpId → 204;
//!   200 `CommonEASInfoDecResp` reserved for a real `grpConnInfo` list);
//!   the fabricated `/announcements` CRUD collection is gone (404).
//! - D4: `eees-acr-param` is the spec custom operation `POST /send-acrparamsinfo`
//!   taking `ACRParamsInfo` (the consumer PUSHES ACR parameters TO the EES →
//!   204, merged into the eecId-keyed ACR state); the reversed bespoke lookup
//!   query is gone (404).
//!
//! DEFERRED (flagged): eesd-09/10 (UE location/identifier exposure —
//! NEF-path-blocked), eesd-14 (standalone conformance suite; tests colocated).

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{
    send_bad_request, send_error, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as NextgcoreSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod acr;
mod auth;
mod context;
mod ecs_registration;
mod eec;
mod services;
mod types;

use acr::{
    ACRUpdateData, AcrContextError, AcrDecReq, AcrDetermReq, AcrInitReq, AcrStatus, EELACRReq,
    EELACRResp,
};
use context::{ees_context_final, ees_context_init, ees_self, UpdateError};
use eec::EecRegistration;
use services::{
    ACInfoSubscription, ACRParamsInfo, AcrMgntEventSubsc, CommonEASInfo, EECContextPush,
    EECContextPushRes, SessionContexts,
};
use types::{cause, EasDiscoveryReq, EasDiscoveryResp, EasDiscoverySubscription, EasRegistration};

/// Interval (seconds) between lifecycle sweeps that drop expired registrations.
const LIFECYCLE_SWEEP_INTERVAL_SECS: u64 = 30;

/// Resource path prefix for EEC registration resources.
const EECREG_REGISTRATIONS_PATH: &str = "/eees-eecregistration/v1/registrations";

/// Resource path prefix for EAS discovery subscription resources.
const EASDISC_SUBSCRIPTIONS_PATH: &str = "/eees-easdiscovery/v1/subscriptions";

/// Resource path prefix (relative to the EES apiRoot) for the individual EAS
/// registration resources — `{apiRoot}/eees-easregistration/v1/registrations`.
const EASREG_REGISTRATIONS_PATH: &str = "/eees-easregistration/v1/registrations";

/// Resource path prefix for App Client Information subscriptions (eesd-13).
/// TS 29.558 §8.4.2: the Eees_AppClientInformation API is an AC-information
/// reporting subscription hosted at `/subscriptions` (not `/app-client-infos`).
const APPCLIENTINFO_RESOURCES_PATH: &str = "/eees-appclientinformation/v1/subscriptions";

/// Resource path prefix for ACR Management Event subscription resources (eesd-13).
const ACRMGNTEVENT_SUBSCRIPTIONS_PATH: &str = "/eees-acrmgntevent/v1/subscriptions";

/// NextGCore EES - Edge Enabler Server
#[derive(Parser, Debug)]
#[command(name = "nextgcore-eesd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Edge Enabler Server (TS 23.558)", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/ees.yaml")]
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

    /// SBI server address
    #[arg(long, default_value = "0.0.0.0")]
    sbi_addr: String,

    /// SBI server port
    #[arg(long, default_value = "7814")]
    sbi_port: u16,

    /// Enable TLS
    #[arg(long)]
    tls: bool,

    /// TLS certificate file
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS key file
    #[arg(long)]
    tls_key: Option<String>,

    /// Maximum EAS registrations
    #[arg(long, default_value = "512")]
    max_eas: usize,

    /// ECS apiRoot for EES self-registration over EDGE-6 (TS 29.558 §9.1).
    /// When unset, the registration request is built and logged but skipped
    /// (no live ECS peer in this stack). Replaces the former `--nrf-uri`.
    #[arg(long)]
    ecs_uri: Option<String>,

    /// EES identifier advertised to the ECS (eesId). Defaults to a fresh UUID.
    #[arg(long)]
    ees_id: Option<String>,

    /// Path to a JSON JWKS used to verify OAuth2 access tokens (CAPIF/NRF
    /// issuer). When unset, every protected operation fails closed with 401
    /// (authorization is mandatory, TS 29.558 §6).
    #[arg(long)]
    oauth2_jwks_file: Option<String>,
}

fn init_logging(level: &str) {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
        .format_timestamp_millis()
        .init();
}

fn setup_signal_handlers(shutdown: Arc<AtomicBool>) {
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        shutdown.store(true, Ordering::SeqCst);
    })
    .expect("value expected");
}

/// Load the OAuth2 verification JWKS from `path` into the process-global store.
fn load_oauth2_jwks(path: &str) {
    match std::fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(jwks) => {
                auth::set_auth_jwks(jwks);
                log::info!("Loaded OAuth2 verification JWKS from {path}");
            }
            Err(e) => log::error!("Failed to parse OAuth2 JWKS file {path}: {e}"),
        },
        Err(e) => log::error!("Failed to read OAuth2 JWKS file {path}: {e}"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    init_logging(&args.log_level);
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = nextgcore_metrics::otel::init_otel(
        nextgcore_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();

    log::info!("NextGCore EES v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Edge Enabler Server (3GPP TS 23.558)");

    ees_context_init(args.max_eas);

    let ees_id = args
        .ees_id
        .clone()
        .unwrap_or_else(|| format!("ees-{}", uuid::Uuid::new_v4()));

    // eesd-08: provision OAuth2 verification keys (fail-closed when absent).
    if let Some(path) = args.oauth2_jwks_file.as_deref() {
        load_oauth2_jwks(path);
    }
    if !auth::is_auth_configured() {
        log::warn!(
            "OAuth2 verification keys not configured: all EES operations will be rejected with \
             401 (per-operation OAuth2 is mandatory, TS 29.558 §6)"
        );
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    let addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;

    let mut sbi_server_config = NextgcoreSbiServerConfig::new(addr);
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
    }

    let sbi_server = SbiServer::new(sbi_server_config);

    log::info!("Starting EES SBI server on {addr}");
    sbi_server
        .start(ees_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    // eesd-01: self-register toward the ECS (EDGE-6), not the NRF.
    ecs_registration::start_ecs_registration(
        args.ecs_uri.as_deref(),
        &ees_id,
        &args.sbi_addr,
        args.sbi_port,
    )
    .await;

    // eesd-12: drop lapsed EAS/EEC registrations on a periodic schedule.
    spawn_lifecycle_sweep();

    log::info!("NextGCore EES ready (eesId: {ees_id})");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("Shutting down...");
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;

    ees_context_final();
    log::info!("EES shutdown complete");

    Ok(())
}

/// EES SBI request handler.
///
/// Routes on the `eees-*` apiNames with the `{apiRoot}/<apiName>/<apiVersion>`
/// layout (eesd-01). Every protected operation is gated by per-operation OAuth2
/// (eesd-08) *before* the method is dispatched. The legacy `nees-*` /
/// `uecontexttransfer` paths are gone and fall through to 404.
async fn ees_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("EES SBI: {method} {uri}");

    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // eees-easregistration (TS 29.558 §5.2) — EAS registration (EDGE-3).
        ["eees-easregistration", "v1", "registrations"] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_EASREGISTRATION) {
                return resp;
            }
            match method {
                "POST" => handle_eas_register(&request).await,
                "GET" => handle_eas_list().await,
                _ => send_method_not_allowed(method, "registrations"),
            }
        }
        ["eees-easregistration", "v1", "registrations", registration_id] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_EASREGISTRATION) {
                return resp;
            }
            match method {
                "GET" => handle_eas_get(registration_id).await,
                "DELETE" => handle_eas_deregister(registration_id).await,
                // eesd-04: full-replace (PUT) and RFC 7396 merge (PATCH).
                "PUT" => handle_eas_update(registration_id, &request).await,
                "PATCH" => handle_eas_modify(registration_id, &request).await,
                _ => send_method_not_allowed(method, "registrations/{registrationId}"),
            }
        }
        // eees-easdiscovery (TS 24.558 §5.3) — EAS discovery (EDGE-1/EDGE-3).
        ["eees-easdiscovery", "v1", "eas-profiles", "request-discovery"] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_EASDISCOVERY) {
                return resp;
            }
            match method {
                "POST" => handle_eas_discover(&request).await,
                _ => send_method_not_allowed(method, "eas-profiles/request-discovery"),
            }
        }
        // eesd-05: EAS discovery-change subscriptions.
        ["eees-easdiscovery", "v1", "subscriptions"] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_EASDISCOVERY) {
                return resp;
            }
            match method {
                "POST" => handle_disc_sub_create(&request).await,
                "GET" => handle_disc_sub_list().await,
                _ => send_method_not_allowed(method, "subscriptions"),
            }
        }
        ["eees-easdiscovery", "v1", "subscriptions", subscription_id] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_EASDISCOVERY) {
                return resp;
            }
            match method {
                "GET" => handle_disc_sub_get(subscription_id).await,
                "PUT" => handle_disc_sub_update(subscription_id, &request).await,
                "DELETE" => handle_disc_sub_delete(subscription_id).await,
                _ => send_method_not_allowed(method, "subscriptions/{subscriptionId}"),
            }
        }
        // eesd-06: eees-eecregistration (TS 24.558 §5.2) — EEC registration (EDGE-1).
        ["eees-eecregistration", "v1", "registrations"] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_EECREGISTRATION) {
                return resp;
            }
            match method {
                "POST" => handle_eec_register(&request).await,
                "GET" => handle_eec_list().await,
                _ => send_method_not_allowed(method, "registrations"),
            }
        }
        ["eees-eecregistration", "v1", "registrations", registration_id] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_EECREGISTRATION) {
                return resp;
            }
            match method {
                "GET" => handle_eec_get(registration_id).await,
                "PUT" => handle_eec_update(registration_id, &request).await,
                "PATCH" => handle_eec_modify(registration_id, &request).await,
                "DELETE" => handle_eec_deregister(registration_id).await,
                _ => send_method_not_allowed(method, "registrations/{registrationId}"),
            }
        }
        // eesd-07: eees-appctxtreloc (TS 24.558 §5.5) — EEC-triggered ACR flow.
        ["eees-appctxtreloc", "v1", "determine"] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_APPCTXTRELOC) {
                return resp;
            }
            match method {
                "POST" => handle_acr_determine(&request).await,
                _ => send_method_not_allowed(method, "determine"),
            }
        }
        ["eees-appctxtreloc", "v1", "initiate"] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_APPCTXTRELOC) {
                return resp;
            }
            match method {
                "POST" => handle_acr_initiate(&request).await,
                _ => send_method_not_allowed(method, "initiate"),
            }
        }
        ["eees-appctxtreloc", "v1", "declare"] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_APPCTXTRELOC) {
                return resp;
            }
            match method {
                "POST" => handle_acr_declare(&request).await,
                _ => send_method_not_allowed(method, "declare"),
            }
        }
        // eesd-07: eees-eel-acr (TS 29.558 §5.11) — EEL-managed ACR.
        ["eees-eel-acr", "v1", "request-eelacr"] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_EEL_ACR) {
                return resp;
            }
            match method {
                "POST" => handle_eel_acr_request(&request).await,
                _ => send_method_not_allowed(method, "request-eelacr"),
            }
        }
        // eesd-07: eees-acrstatus-update (TS 29.558 §5.12) — ACR status notification.
        ["eees-acrstatus-update", "v1", "request-acrupdate"] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_ACRSTATUS_UPDATE) {
                return resp;
            }
            match method {
                "POST" => handle_acr_status_update(&request).await,
                _ => send_method_not_allowed(method, "request-acrupdate"),
            }
        }
        // D3: eees-cea (TS 29.558 Eees_CommonEASAnnouncement) — Common EAS
        // Announcement. The yaml defines NO resources: exactly one custom
        // operation POST /declare (CommonEASInfo → 204 | 200
        // CommonEASInfoDecResp). This is a DIFFERENT API from the
        // eees-appctxtreloc /declare op above (distinct first path segment).
        ["eees-cea", "v1", "declare"] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_CEA) {
                return resp;
            }
            match method {
                "POST" => handle_cea_declare(&request).await,
                _ => send_method_not_allowed(method, "declare"),
            }
        }
        // D1: eees-appclientinformation (TS 29.558 §8.4) — AC Information
        // subscriptions hosted at /subscriptions. The yaml defines POST on the
        // collection only (no collection GET → 405).
        ["eees-appclientinformation", "v1", "subscriptions"] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_APPCLIENTINFORMATION) {
                return resp;
            }
            match method {
                "POST" => handle_acinfo_create(&request).await,
                _ => send_method_not_allowed(method, "subscriptions"),
            }
        }
        ["eees-appclientinformation", "v1", "subscriptions", subscription_id] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_APPCLIENTINFORMATION) {
                return resp;
            }
            match method {
                "GET" => handle_acinfo_get(subscription_id).await,
                // Spec ops on the individual resource: PUT full replace
                // (ACInfoSubscription) vs PATCH application/merge-patch+json
                // (ACInfoSubscriptionPatch) — distinct semantics.
                "PUT" => handle_acinfo_update(subscription_id, &request).await,
                "PATCH" => handle_acinfo_modify(subscription_id, &request).await,
                "DELETE" => handle_acinfo_delete(subscription_id).await,
                _ => send_method_not_allowed(method, "subscriptions/{subscriptionId}"),
            }
        }
        // eesd-13: eees-acrmgntevent (TS 29.558 §5.8) — ACR Management Event subscriptions.
        ["eees-acrmgntevent", "v1", "subscriptions"] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_ACRMGNTEVENT) {
                return resp;
            }
            match method {
                "POST" => handle_acrmgnt_sub_create(&request).await,
                "GET" => handle_acrmgnt_sub_list().await,
                _ => send_method_not_allowed(method, "subscriptions"),
            }
        }
        ["eees-acrmgntevent", "v1", "subscriptions", subscription_id] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_ACRMGNTEVENT) {
                return resp;
            }
            match method {
                "GET" => handle_acrmgnt_sub_get(subscription_id).await,
                "PUT" => handle_acrmgnt_sub_update(subscription_id, &request).await,
                "DELETE" => handle_acrmgnt_sub_delete(subscription_id).await,
                _ => send_method_not_allowed(method, "subscriptions/{subscriptionId}"),
            }
        }
        // D2: eees-eeccontextreloc (TS 29.558 §8.7.2) — EEC Contexts. The yaml
        // defines exactly two ops on /eec-contexts: POST (PushEecContexts,
        // EECContextPush → 200 EECContextPushRes | 204) and GET
        // (PullEecContexts with REQUIRED `ees-id` + `eec-cntx-id` query
        // params). There is NO individual /eec-contexts/{id} resource — a
        // path-param GET falls through to 404 below.
        ["eees-eeccontextreloc", "v1", "eec-contexts"] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_EECCONTEXTRELOC) {
                return resp;
            }
            match method {
                "POST" => handle_eec_context_push(&request).await,
                "GET" => handle_eec_context_pull(&request).await,
                _ => send_method_not_allowed(method, "eec-contexts"),
            }
        }
        // D4: eees-acr-param (TS 29.558 Eees_ACRParameterInformation) — ACR
        // Parameter Information. The yaml defines one custom operation
        // POST /send-acrparamsinfo (ACRParamsInfo → 204 only): the consumer
        // PUSHES ACR parameters TO the EES. The reversed bespoke lookup query
        // is gone (falls through to 404).
        ["eees-acr-param", "v1", "send-acrparamsinfo"] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_ACR_PARAM) {
                return resp;
            }
            match method {
                "POST" => handle_acr_param_send(&request).await,
                _ => send_method_not_allowed(method, "send-acrparamsinfo"),
            }
        }
        _ => send_not_found(&format!("Resource not found: {path}"), None),
    }
}

/// Spawn the periodic expTime lifecycle sweep (eesd-12).
fn spawn_lifecycle_sweep() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(Duration::from_secs(LIFECYCLE_SWEEP_INTERVAL_SECS)).await;
            let now = types::now_epoch();
            if let Ok(ctx) = ees_self().read() {
                ctx.sweep_expired(now);
            }
        }
    });
}

/// Map a context [`UpdateError`] to the appropriate RFC 7807 response.
fn update_error_response(err: UpdateError, resource: &str) -> SbiResponse {
    match err {
        UpdateError::NotFound => send_not_found(
            &format!("{resource} not found"),
            Some(cause::SUBSCRIPTION_NOT_FOUND),
        ),
        UpdateError::IdImmutable => send_error(
            403,
            "Forbidden",
            "The immutable identifier (easId/eecId) shall not be modified",
            Some(cause::MODIFICATION_NOT_ALLOWED),
        ),
        UpdateError::Invalid => send_bad_request(
            "Update failed validation",
            Some(cause::MANDATORY_IE_MISSING),
        ),
        UpdateError::Internal => send_error(
            500,
            "Internal Server Error",
            "Update failed",
            Some("UNSPECIFIED_NF_FAILURE"),
        ),
    }
}

/// Parse the request body as JSON, distinguishing a missing body and malformed
/// JSON with the right 3GPP cause. The error response is boxed (it is large
/// relative to the success value; clippy `result_large_err`).
fn parse_json_body(request: &SbiRequest) -> Result<serde_json::Value, Box<SbiResponse>> {
    let body = request.http.content.as_ref().ok_or_else(|| {
        Box::new(send_bad_request(
            "Missing request body",
            Some(cause::MANDATORY_IE_MISSING),
        ))
    })?;
    serde_json::from_str(body).map_err(|e| {
        Box::new(send_bad_request(
            &format!("Invalid JSON: {e}"),
            Some(cause::INVALID_MSG_FORMAT),
        ))
    })
}

/// eesd-02/03: handle EAS Registration (`CreateEASRegistration`).
///
/// Parses the `easProf`-wrapped `EASRegistration` body, rejects a missing
/// mandatory `easProf.easId`/`easProf.endPt` with 400 ProblemDetails
/// (`MANDATORY_IE_MISSING`), mints a server `registrationId`, preserves the
/// consumer `easId`, and echoes the stored `EASRegistration` with a `Location`
/// header keyed on the `registrationId`.
async fn handle_eas_register(request: &SbiRequest) -> SbiResponse {
    log::info!("EAS Register");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MANDATORY_IE_MISSING")),
    };

    // Distinguish malformed JSON from a structurally-missing mandatory IE.
    let value: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_MSG_FORMAT"))
        }
    };

    let mut reg: EasRegistration = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Missing or invalid mandatory IE: {e}"),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };

    // eesd-03: the consumer-provided easId is mandatory and must be non-empty.
    if reg.eas_prof.eas_id.trim().is_empty() {
        return send_bad_request(
            "Mandatory IE easProf.easId is empty",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    // eesd-02: endPt must carry at least one reachable address form.
    if reg.eas_prof.end_pt.is_empty() {
        return send_bad_request(
            "Mandatory IE easProf.endPt carries no address",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }

    // eesd-11: negotiate suppFeat (echoed in the 201 body).
    reg.supp_feat = types::negotiate_supp_feat(reg.supp_feat.as_deref());

    let ctx = ees_self();
    let stored = ctx.read().ok().and_then(|context| {
        let stored = context.eas_register(reg)?;
        // eesd-05: notify any discovery subscriptions selecting the new EAS.
        context.notify_discovery_subscribers(&stored.eas_prof);
        Some(stored)
    });

    match stored {
        Some(stored) => {
            let registration_id = stored.registration_id.clone().unwrap_or_default();
            SbiResponse::with_status(201)
                .with_header(
                    "Location",
                    format!("{EASREG_REGISTRATIONS_PATH}/{registration_id}"),
                )
                .with_json_body(&stored)
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => send_error(
            507,
            "Insufficient Storage",
            "Failed to register EAS (capacity exhausted)",
            Some(cause::INSUFFICIENT_RESOURCES),
        ),
    }
}

/// eesd-04: handle EAS Registration full-replace (`UpdateIndEASRegistration`,
/// PUT). Deserializes a full `EASRegistration`, rejects a changed `easId`
/// (immutable), preserves the `registrationId`, and returns the updated
/// representation (200).
async fn handle_eas_update(registration_id: &str, request: &SbiRequest) -> SbiResponse {
    let value = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let mut reg: EasRegistration = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Missing or invalid mandatory IE: {e}"),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };
    if reg.eas_prof.eas_id.trim().is_empty() || reg.eas_prof.end_pt.is_empty() {
        return send_bad_request(
            "Mandatory IE easProf.easId/endPt missing",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    reg.supp_feat = types::negotiate_supp_feat(reg.supp_feat.as_deref());

    let ctx = ees_self();
    let result = ctx
        .read()
        .map_err(|_| UpdateError::Internal)
        .and_then(|c| c.eas_update(registration_id, reg));
    match result {
        Ok(updated) => SbiResponse::with_status(200)
            .with_json_body(&updated)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        Err(e) => update_error_response(e, &format!("EAS registration {registration_id}")),
    }
}

/// eesd-04: handle EAS Registration merge (`ModifyIndEASRegistration`, PATCH,
/// `application/merge-patch+json`). Applies an RFC 7396 merge-patch, rejecting
/// an `easId` change, and returns the updated representation (200).
async fn handle_eas_modify(registration_id: &str, request: &SbiRequest) -> SbiResponse {
    let patch = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let ctx = ees_self();
    let result = ctx
        .read()
        .map_err(|_| UpdateError::Internal)
        .and_then(|c| c.eas_modify(registration_id, &patch));
    match result {
        Ok(updated) => SbiResponse::with_status(200)
            .with_json_body(&updated)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        Err(e) => update_error_response(e, &format!("EAS registration {registration_id}")),
    }
}

/// List all stored EAS registrations.
async fn handle_eas_list() -> SbiResponse {
    let ctx = ees_self();
    let registrations = ctx.read().map(|c| c.eas_list()).unwrap_or_default();

    SbiResponse::with_status(200)
        .with_json_body(&registrations)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Get an individual EAS registration by its server-minted `registrationId`.
async fn handle_eas_get(registration_id: &str) -> SbiResponse {
    let ctx = ees_self();
    let reg = ctx.read().ok().and_then(|c| c.eas_find(registration_id));

    match reg {
        Some(reg) => SbiResponse::with_status(200)
            .with_json_body(&reg)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("EAS registration {registration_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

/// Deregister an EAS by its `registrationId` (`DeleteIndEASRegistration`).
async fn handle_eas_deregister(registration_id: &str) -> SbiResponse {
    log::info!("EAS Deregister: {registration_id}");

    let ctx = ees_self();
    let removed = ctx
        .read()
        .ok()
        .and_then(|c| c.eas_deregister(registration_id));

    match removed {
        Some(_) => SbiResponse::with_status(204),
        None => send_not_found(
            &format!("EAS registration {registration_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

/// eesd-05: handle EAS Discovery (`GetEASDiscInfo`).
///
/// Deserializes the spec `EasDiscoveryReq` (mandatory `requestorId`), applies
/// the `easDiscoveryFilter` (easId/easType/acIds/svcArea), and returns an
/// `EasDiscoveryResp` carrying full `EASProfile`s as `discoveredEas[].eas` with
/// the negotiated `suppFeat`. No invented `distanceScore`. UE-location filtering
/// from `locInf`/NEF is DEFERRED (eesd-09).
async fn handle_eas_discover(request: &SbiRequest) -> SbiResponse {
    log::info!("EAS Discovery");

    let value = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let req: EasDiscoveryReq = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Missing or invalid mandatory IE (requestorId): {e}"),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };

    let supp_feat = types::negotiate_supp_feat(req.supp_feat.as_deref());
    let ctx = ees_self();
    let discovered_eas = ctx
        .read()
        .map(|c| {
            c.eas_discover_filter(req.eas_discovery_filter.as_ref())
                .into_iter()
                .map(|eas| types::DiscoveredEas { eas })
                .collect()
        })
        .unwrap_or_default();

    let resp = EasDiscoveryResp {
        discovered_eas,
        supp_feat,
    };
    SbiResponse::with_status(200)
        .with_json_body(&resp)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

// ---- eesd-05: EAS discovery subscription handlers --------------------------

/// `CreateEASDiscSub` (POST /subscriptions): create a discovery-change
/// subscription with a server-minted `subscriptionId` and a `Location` header.
async fn handle_disc_sub_create(request: &SbiRequest) -> SbiResponse {
    let value = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let mut sub: EasDiscoverySubscription = match serde_json::from_value(value) {
        Ok(s) => s,
        Err(e) => {
            return send_bad_request(
                &format!("Missing or invalid mandatory IE (notificationUri): {e}"),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };
    if sub.notification_uri.trim().is_empty() {
        return send_bad_request(
            "Mandatory IE notificationUri is empty",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    sub.supp_feat = types::negotiate_supp_feat(sub.supp_feat.as_deref());

    let ctx = ees_self();
    let created = ctx.read().ok().and_then(|c| c.disc_sub_create(sub));
    match created {
        Some(created) => {
            let id = created.subscription_id.clone().unwrap_or_default();
            SbiResponse::with_status(201)
                .with_header("Location", format!("{EASDISC_SUBSCRIPTIONS_PATH}/{id}"))
                .with_json_body(&created)
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => send_error(
            507,
            "Insufficient Storage",
            "Failed to create discovery subscription (capacity exhausted)",
            Some(cause::INSUFFICIENT_RESOURCES),
        ),
    }
}

async fn handle_disc_sub_list() -> SbiResponse {
    let subs = ees_self()
        .read()
        .map(|c| c.disc_sub_list())
        .unwrap_or_default();
    SbiResponse::with_status(200)
        .with_json_body(&subs)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_disc_sub_get(subscription_id: &str) -> SbiResponse {
    let sub = ees_self()
        .read()
        .ok()
        .and_then(|c| c.disc_sub_find(subscription_id));
    match sub {
        Some(sub) => SbiResponse::with_status(200)
            .with_json_body(&sub)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("Discovery subscription {subscription_id} not found"),
            Some(cause::SUBSCRIPTION_NOT_FOUND),
        ),
    }
}

async fn handle_disc_sub_update(subscription_id: &str, request: &SbiRequest) -> SbiResponse {
    let value = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let mut sub: EasDiscoverySubscription = match serde_json::from_value(value) {
        Ok(s) => s,
        Err(e) => {
            return send_bad_request(
                &format!("Missing or invalid mandatory IE: {e}"),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };
    if sub.notification_uri.trim().is_empty() {
        return send_bad_request(
            "Mandatory IE notificationUri is empty",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    sub.supp_feat = types::negotiate_supp_feat(sub.supp_feat.as_deref());

    let ctx = ees_self();
    let result = ctx
        .read()
        .map_err(|_| UpdateError::Internal)
        .and_then(|c| c.disc_sub_update(subscription_id, sub));
    match result {
        Ok(updated) => SbiResponse::with_status(200)
            .with_json_body(&updated)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        Err(e) => update_error_response(e, &format!("Discovery subscription {subscription_id}")),
    }
}

async fn handle_disc_sub_delete(subscription_id: &str) -> SbiResponse {
    let removed = ees_self()
        .read()
        .ok()
        .and_then(|c| c.disc_sub_delete(subscription_id));
    match removed {
        Some(_) => SbiResponse::with_status(204),
        None => send_not_found(
            &format!("Discovery subscription {subscription_id} not found"),
            Some(cause::SUBSCRIPTION_NOT_FOUND),
        ),
    }
}

// ---- eesd-06: EEC registration handlers ------------------------------------

/// `CreateEECReg` (POST /registrations): register an EEC with a server-minted
/// `registrationId` and an `expTime` lifecycle (minted when absent, eesd-12).
async fn handle_eec_register(request: &SbiRequest) -> SbiResponse {
    log::info!("EEC Register");
    let value = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let mut reg: EecRegistration = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Missing or invalid mandatory IE (eecId): {e}"),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };
    if let Err(detail) = reg.validate() {
        return send_bad_request(&detail, Some(cause::MANDATORY_IE_MISSING));
    }
    // eesd-12: mint an expTime when the consumer supplied none.
    if reg.exp_time.is_none() {
        reg.exp_time = Some(types::epoch_to_rfc3339(
            types::now_epoch() + eec::DEFAULT_EEC_REG_LIFETIME_SECS,
        ));
    }
    // eesd-11: negotiate suppFeat.
    reg.supp_feat = types::negotiate_supp_feat(reg.supp_feat.as_deref());

    let ctx = ees_self();
    let stored = ctx.read().ok().and_then(|c| c.eec_register(reg));
    match stored {
        Some(stored) => {
            let id = stored.registration_id.clone().unwrap_or_default();
            SbiResponse::with_status(201)
                .with_header("Location", format!("{EECREG_REGISTRATIONS_PATH}/{id}"))
                .with_json_body(&stored)
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => send_error(
            507,
            "Insufficient Storage",
            "Failed to register EEC (capacity exhausted)",
            Some(cause::INSUFFICIENT_RESOURCES),
        ),
    }
}

async fn handle_eec_list() -> SbiResponse {
    let regs = ees_self().read().map(|c| c.eec_list()).unwrap_or_default();
    SbiResponse::with_status(200)
        .with_json_body(&regs)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_eec_get(registration_id: &str) -> SbiResponse {
    let reg = ees_self()
        .read()
        .ok()
        .and_then(|c| c.eec_find(registration_id));
    match reg {
        Some(reg) => SbiResponse::with_status(200)
            .with_json_body(&reg)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("EEC registration {registration_id} not found"),
            Some(cause::SUBSCRIPTION_NOT_FOUND),
        ),
    }
}

async fn handle_eec_update(registration_id: &str, request: &SbiRequest) -> SbiResponse {
    let value = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let mut reg: EecRegistration = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Missing or invalid mandatory IE (eecId): {e}"),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };
    if let Err(detail) = reg.validate() {
        return send_bad_request(&detail, Some(cause::MANDATORY_IE_MISSING));
    }
    if reg.exp_time.is_none() {
        reg.exp_time = Some(types::epoch_to_rfc3339(
            types::now_epoch() + eec::DEFAULT_EEC_REG_LIFETIME_SECS,
        ));
    }
    reg.supp_feat = types::negotiate_supp_feat(reg.supp_feat.as_deref());

    let ctx = ees_self();
    let result = ctx
        .read()
        .map_err(|_| UpdateError::Internal)
        .and_then(|c| c.eec_update(registration_id, reg));
    match result {
        Ok(updated) => SbiResponse::with_status(200)
            .with_json_body(&updated)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        Err(e) => update_error_response(e, &format!("EEC registration {registration_id}")),
    }
}

async fn handle_eec_modify(registration_id: &str, request: &SbiRequest) -> SbiResponse {
    let patch = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let ctx = ees_self();
    let result = ctx
        .read()
        .map_err(|_| UpdateError::Internal)
        .and_then(|c| c.eec_modify(registration_id, &patch));
    match result {
        Ok(updated) => SbiResponse::with_status(200)
            .with_json_body(&updated)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        Err(e) => update_error_response(e, &format!("EEC registration {registration_id}")),
    }
}

async fn handle_eec_deregister(registration_id: &str) -> SbiResponse {
    log::info!("EEC Deregister: {registration_id}");
    let removed = ees_self()
        .read()
        .ok()
        .and_then(|c| c.eec_deregister(registration_id));
    match removed {
        Some(_) => SbiResponse::with_status(204),
        None => send_not_found(
            &format!("EEC registration {registration_id} not found"),
            Some(cause::SUBSCRIPTION_NOT_FOUND),
        ),
    }
}

// ---- eesd-07: ACR handlers --------------------------------------------------

/// Map an [`AcrContextError`] to the appropriate HTTP response.
fn acr_context_error_response(err: AcrContextError, detail: &str) -> SbiResponse {
    match err {
        AcrContextError::SEasNotFound => {
            send_not_found(detail, Some(cause::SUBSCRIPTION_NOT_FOUND))
        }
        AcrContextError::NoTEasAvailable => send_error(
            503,
            "Service Unavailable",
            detail,
            Some(cause::INSUFFICIENT_RESOURCES),
        ),
        AcrContextError::Internal => send_error(
            500,
            "Internal Server Error",
            detail,
            Some("UNSPECIFIED_NF_FAILURE"),
        ),
    }
}

/// eesd-07: `Determine` (`POST .../eees-appctxtreloc/v1/determine`).
///
/// Parses `AcrDetermReq` (TS 24.558 §6.5.5.2.2; mandatory: `requestorId`,
/// `sEasEndpoint`), selects a T-EAS from the registered pool, records
/// `DETERMINED` state, and returns **204 No Content** per the API table.
async fn handle_acr_determine(request: &SbiRequest) -> SbiResponse {
    log::info!("ACR Determine");
    let value = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let req: AcrDetermReq = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Missing or invalid mandatory IE (requestorId/sEasEndpoint): {e}"),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };
    if req.requestor_id.trim().is_empty() || req.s_eas_endpoint.is_empty() {
        return send_bad_request(
            "Mandatory IE requestorId/sEasEndpoint is empty",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    let ctx = ees_self();
    match ctx
        .read()
        .map_err(|_| AcrContextError::Internal)
        .and_then(|c| c.acr_determine(&req))
    {
        Ok(_state) => SbiResponse::with_status(204),
        Err(e) => acr_context_error_response(
            e,
            &format!(
                "ACR Determine failed: easId={:?} not registered or no T-EAS available",
                req.eas_id
            ),
        ),
    }
}

/// eesd-07: `Initiate` (`POST .../eees-appctxtreloc/v1/initiate`).
///
/// Parses `AcrInitReq` (TS 24.558 §6.5.5.2.3; mandatory: `requestorId`,
/// `tEasEndpoint`, `easNotifInd`), transitions the ACR state to `INITIATED`,
/// and returns **204 No Content**.
async fn handle_acr_initiate(request: &SbiRequest) -> SbiResponse {
    log::info!("ACR Initiate");
    let value = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let req: AcrInitReq = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!(
                    "Missing or invalid mandatory IE (requestorId/tEasEndpoint/easNotifInd): {e}"
                ),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };
    if req.requestor_id.trim().is_empty() || req.t_eas_endpoint.is_empty() {
        return send_bad_request(
            "Mandatory IE requestorId/tEasEndpoint is empty",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    let ctx = ees_self();
    let done = ctx.read().map(|c| c.acr_initiate(&req)).is_ok();
    if done {
        SbiResponse::with_status(204)
    } else {
        send_error(
            500,
            "Internal Server Error",
            "Context lock failure",
            Some("UNSPECIFIED_NF_FAILURE"),
        )
    }
}

/// eesd-07: `Declare` (`POST .../eees-appctxtreloc/v1/declare`).
///
/// Parses `AcrDecReq` (TS 24.558 §6.5.5.2.4; mandatory: `ueId`, `tEasId`,
/// `tEasEndpoint`), marks the relocation `COMPLETED`, and returns **204 No
/// Content**. The EES (stub) logs the notification to the T-EAS and ACR-status
/// subscribers.
async fn handle_acr_declare(request: &SbiRequest) -> SbiResponse {
    log::info!("ACR Declare");
    let value = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let req: AcrDecReq = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Missing or invalid mandatory IE (ueId/tEasId/tEasEndpoint): {e}"),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };
    if req.ue_id.trim().is_empty()
        || req.t_eas_id.trim().is_empty()
        || req.t_eas_endpoint.is_empty()
    {
        return send_bad_request(
            "Mandatory IE ueId/tEasId/tEasEndpoint is empty",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    let ctx = ees_self();
    let done = ctx.read().map(|c| c.acr_declare(&req)).is_ok();
    if done {
        SbiResponse::with_status(204)
    } else {
        send_error(
            500,
            "Internal Server Error",
            "Context lock failure",
            Some("UNSPECIFIED_NF_FAILURE"),
        )
    }
}

/// eesd-07: `Eees_EELManagedACR_Request`
/// (`POST .../eees-eel-acr/v1/request-eelacr`).
///
/// Parses `EELACRReq` (TS 29.558 §8.8.6.2.2; mandatory: `ueId`, `easCharacs`),
/// performs Determine + Initiate internally, and returns `EELACRResp` (200)
/// echoing the application-context store address.
async fn handle_eel_acr_request(request: &SbiRequest) -> SbiResponse {
    log::info!("EEL ACR Request");
    let value = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let req: EELACRReq = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Missing or invalid mandatory IE (ueId/easCharacs): {e}"),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };
    if req.ue_id.trim().is_empty() || req.eas_characs.is_empty() {
        return send_bad_request(
            "Mandatory IE ueId/easCharacs is empty",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    let supp_feat = types::negotiate_supp_feat(req.supp_feat.as_deref());
    let ctx = ees_self();
    match ctx
        .read()
        .map_err(|_| AcrContextError::Internal)
        .and_then(|c| c.acr_eel_request(&req.ue_id))
    {
        Ok(_state) => {
            let resp = EELACRResp {
                app_ctxt_store_addr: req.app_ctxt_store_addr.clone(),
                supp_feat,
            };
            SbiResponse::with_status(200)
                .with_json_body(&resp)
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        Err(e) => acr_context_error_response(
            e,
            &format!(
                "EEL ACR request failed for ueId={}: no T-EAS available",
                req.ue_id
            ),
        ),
    }
}

/// eesd-07: `Eees_ACRStatusUpdate_Request`
/// (`POST .../eees-acrstatus-update/v1/request-acrupdate`).
///
/// Parses `ACRUpdateData` (TS 29.558 §8.9.6.2.2; mandatory: `easId`, plus at
/// least one of `actResultInfo`/`e3SubscIds`/`e3NotificationUri`), derives the
/// ACR status from `actResultInfo.actResult`, updates the ACR state, and
/// returns **204 No Content**. The EES (stub) logs notifications.
async fn handle_acr_status_update(request: &SbiRequest) -> SbiResponse {
    log::info!("ACR Status Update");
    let value = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let req: ACRUpdateData = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Missing or invalid mandatory IE (easId): {e}"),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };
    if req.eas_id.trim().is_empty() {
        return send_bad_request(
            "Mandatory IE easId is empty",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    // Per the §8.9.6.2.2 NOTE, at least one of these must be present.
    if req.act_result_info.is_none()
        && req.e3_subsc_ids.is_none()
        && req.e3_notification_uri.is_none()
    {
        return send_bad_request(
            "At least one of actResultInfo/e3SubscIds/e3NotificationUri must be present",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    // Derive ACR status from ACTResultInfo.actResult (ACTResult enum) when present.
    let status = req
        .act_result_info
        .as_ref()
        .and_then(|v| v.get("actResult"))
        .and_then(|r| r.as_str())
        .map(|s| {
            if s.to_ascii_uppercase().contains("FAIL") {
                AcrStatus::Failed
            } else {
                AcrStatus::Completed
            }
        })
        .unwrap_or(AcrStatus::Initiated);
    let ctx = ees_self();
    if let Ok(c) = ctx.read() {
        c.acr_status_update(&req.eas_id, status);
    }
    SbiResponse::with_status(204)
}

// ---- D3: eees-cea handler ----------------------------------------------------

/// `Declare` (`POST {apiRoot}/eees-cea/v1/declare`,
/// TS29558_Eees_CommonEASAnnouncement.yaml:29-79).
///
/// Parses the spec `CommonEASInfo` (required: `requestorId`, `easId`,
/// `easEndPt`, `appGrpId`), fail-closed 400 `MANDATORY_IE_MISSING` on any
/// missing/empty required IE, records the declared common EAS (accept-and-ack),
/// and returns 204. A 200 `CommonEASInfoDecResp` is emitted only when a real
/// `grpConnInfo` list exists (the `anyOf: [required grpConnInfo]` constraint) —
/// the EES generates none today, so it always answers 204 (never an empty 200).
async fn handle_cea_declare(request: &SbiRequest) -> SbiResponse {
    log::info!("Common EAS declare");
    let value = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let info: CommonEASInfo = match serde_json::from_value(value) {
        Ok(i) => i,
        Err(e) => {
            return send_bad_request(
                &format!(
                    "Missing or invalid mandatory IE (requestorId/easId/easEndPt/appGrpId): {e}"
                ),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };
    if info.requestor_id.trim().is_empty()
        || info.eas_id.trim().is_empty()
        || info.app_grp_id.trim().is_empty()
    {
        return send_bad_request(
            "Mandatory IE requestorId/easId/appGrpId is empty",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    if info.eas_end_pt.is_empty() {
        return send_bad_request(
            "Mandatory IE easEndPt carries no address",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    if let Ok(c) = ees_self().read() {
        c.cea_declare(info);
    }
    SbiResponse::with_status(204)
}

// ---- D1: eees-appclientinformation handlers ----------------------------------

/// Parse + mandatory-IE-validate an `ACInfoSubscription` body
/// (TS29558_Eees_AppClientInformation.yaml:317-353; sole REQUIRED field
/// `easId`). Fail-closed 400 `MANDATORY_IE_MISSING` on a missing/empty
/// `easId`. The error response is boxed (clippy `result_large_err`).
fn parse_acinfo_subscription(request: &SbiRequest) -> Result<ACInfoSubscription, Box<SbiResponse>> {
    let value = parse_json_body(request)?;
    let mut sub: ACInfoSubscription = serde_json::from_value(value).map_err(|e| {
        Box::new(send_bad_request(
            &format!("Missing or invalid mandatory IE (easId): {e}"),
            Some(cause::MANDATORY_IE_MISSING),
        ))
    })?;
    if sub.eas_id.trim().is_empty() {
        return Err(Box::new(send_bad_request(
            "Mandatory IE easId is empty",
            Some(cause::MANDATORY_IE_MISSING),
        )));
    }
    // eesd-11: negotiate suppFeat (echoed in the response body).
    sub.supp_feat = types::negotiate_supp_feat(sub.supp_feat.as_deref());
    Ok(sub)
}

/// `CreateAppClientInfoSubscription`
/// (`POST .../eees-appclientinformation/v1/subscriptions`, yaml:26-73).
///
/// Parses the spec `ACInfoSubscription` (mandatory: `easId` ONLY) and returns
/// 201 + `Location` (keyed on the server-minted `subscriptionId`) + the echoed
/// `ACInfoSubscription` body. The wire body never carries the id.
async fn handle_acinfo_create(request: &SbiRequest) -> SbiResponse {
    log::info!("ACInfoSubscription create");
    let sub = match parse_acinfo_subscription(request) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let ctx = ees_self();
    match ctx.read().ok().and_then(|c| c.acinfo_create(sub.clone())) {
        Some(id) => SbiResponse::with_status(201)
            .with_header("Location", format!("{APPCLIENTINFO_RESOURCES_PATH}/{id}"))
            .with_json_body(&sub)
            .unwrap_or_else(|_| SbiResponse::with_status(201)),
        None => send_error(
            507,
            "Insufficient Storage",
            "Failed to create AC information subscription (capacity exhausted)",
            Some(cause::INSUFFICIENT_RESOURCES),
        ),
    }
}

/// `ReadIndAppClientInfoSubscription` (GET, yaml:115-156).
async fn handle_acinfo_get(subscription_id: &str) -> SbiResponse {
    let sub = ees_self()
        .read()
        .ok()
        .and_then(|c| c.acinfo_find(subscription_id));
    match sub {
        Some(sub) => SbiResponse::with_status(200)
            .with_json_body(&sub)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("AC information subscription {subscription_id} not found"),
            Some(cause::SUBSCRIPTION_NOT_FOUND),
        ),
    }
}

/// `UpdateIndAppClientInfoSubscription` (PUT full replace, yaml:158-207).
/// Validates a complete `ACInfoSubscription` and returns the replaced
/// representation (200).
async fn handle_acinfo_update(subscription_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("ACInfoSubscription replace: {subscription_id}");
    let sub = match parse_acinfo_subscription(request) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let result = ees_self()
        .read()
        .map_err(|_| UpdateError::Internal)
        .and_then(|c| c.acinfo_update(subscription_id, sub));
    match result {
        Ok(updated) => SbiResponse::with_status(200)
            .with_json_body(&updated)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        Err(e) => update_error_response(
            e,
            &format!("AC information subscription {subscription_id}"),
        ),
    }
}

/// `ModifyIndAppClientInfoSubscription` (PATCH `application/merge-patch+json`,
/// yaml:209-266). Applies an RFC 7396 merge restricted to the
/// `ACInfoSubscriptionPatch` members (yaml:355-377) and returns the merged
/// representation (200); `easId` is not patchable and is preserved.
async fn handle_acinfo_modify(subscription_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("ACInfoSubscription merge-patch: {subscription_id}");
    let patch = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let result = ees_self()
        .read()
        .map_err(|_| UpdateError::Internal)
        .and_then(|c| c.acinfo_modify(subscription_id, &patch));
    match result {
        Ok(updated) => SbiResponse::with_status(200)
            .with_json_body(&updated)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        Err(e) => update_error_response(
            e,
            &format!("AC information subscription {subscription_id}"),
        ),
    }
}

/// `DeleteIndAppClientInfoSubscription` (DELETE, yaml:268-303) → 204.
async fn handle_acinfo_delete(subscription_id: &str) -> SbiResponse {
    log::info!("ACInfoSubscription delete: {subscription_id}");
    let removed = ees_self()
        .read()
        .ok()
        .and_then(|c| c.acinfo_delete(subscription_id));
    match removed {
        Some(_) => SbiResponse::with_status(204),
        None => send_not_found(
            &format!("AC information subscription {subscription_id} not found"),
            Some(cause::SUBSCRIPTION_NOT_FOUND),
        ),
    }
}

// ---- eesd-13: eees-acrmgntevent handlers ------------------------------------

/// `CreateAcrMgntEventSubsc` (`POST .../eees-acrmgntevent/v1/subscriptions`).
///
/// Parses `AcrMgntEventSubsc` (mandatory: `notificationUri`), mints a
/// `subscriptionId`, and returns 201 + `Location` + echoed body.
async fn handle_acrmgnt_sub_create(request: &SbiRequest) -> SbiResponse {
    log::info!("ACR management event subscription create");
    let value = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let sub: AcrMgntEventSubsc = match serde_json::from_value(value) {
        Ok(s) => s,
        Err(e) => {
            return send_bad_request(
                &format!("Missing or invalid mandatory IE (notificationUri): {e}"),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };
    if sub.notification_uri.trim().is_empty() {
        return send_bad_request(
            "Mandatory IE notificationUri is empty",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    let ctx = ees_self();
    match ctx.read().ok().and_then(|c| c.acrmgnt_sub_create(sub)) {
        Some(created) => {
            let id = created.subscription_id.clone().unwrap_or_default();
            SbiResponse::with_status(201)
                .with_header(
                    "Location",
                    format!("{ACRMGNTEVENT_SUBSCRIPTIONS_PATH}/{id}"),
                )
                .with_json_body(&created)
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => send_error(
            507,
            "Insufficient Storage",
            "Failed to create ACR management event subscription (capacity exhausted)",
            Some(cause::INSUFFICIENT_RESOURCES),
        ),
    }
}

async fn handle_acrmgnt_sub_list() -> SbiResponse {
    let subs = ees_self()
        .read()
        .map(|c| c.acrmgnt_sub_list())
        .unwrap_or_default();
    SbiResponse::with_status(200)
        .with_json_body(&subs)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_acrmgnt_sub_get(subscription_id: &str) -> SbiResponse {
    let sub = ees_self()
        .read()
        .ok()
        .and_then(|c| c.acrmgnt_sub_find(subscription_id));
    match sub {
        Some(sub) => SbiResponse::with_status(200)
            .with_json_body(&sub)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("ACR management event subscription {subscription_id} not found"),
            Some(cause::SUBSCRIPTION_NOT_FOUND),
        ),
    }
}

async fn handle_acrmgnt_sub_update(subscription_id: &str, request: &SbiRequest) -> SbiResponse {
    let value = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let sub: AcrMgntEventSubsc = match serde_json::from_value(value) {
        Ok(s) => s,
        Err(e) => {
            return send_bad_request(
                &format!("Missing or invalid mandatory IE (notificationUri): {e}"),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };
    if sub.notification_uri.trim().is_empty() {
        return send_bad_request(
            "Mandatory IE notificationUri is empty",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    let ctx = ees_self();
    let result = ctx
        .read()
        .map_err(|_| UpdateError::Internal)
        .and_then(|c| c.acrmgnt_sub_update(subscription_id, sub));
    match result {
        Ok(updated) => SbiResponse::with_status(200)
            .with_json_body(&updated)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        Err(e) => update_error_response(
            e,
            &format!("ACR management event subscription {subscription_id}"),
        ),
    }
}

async fn handle_acrmgnt_sub_delete(subscription_id: &str) -> SbiResponse {
    let removed = ees_self()
        .read()
        .ok()
        .and_then(|c| c.acrmgnt_sub_delete(subscription_id));
    match removed {
        Some(_) => SbiResponse::with_status(204),
        None => send_not_found(
            &format!("ACR management event subscription {subscription_id} not found"),
            Some(cause::SUBSCRIPTION_NOT_FOUND),
        ),
    }
}

// ---- D2: eees-eeccontextreloc handlers ---------------------------------------

/// Percent-decode an RFC 3986 URI component (`%XX` triplets). A malformed
/// escape sequence is kept verbatim rather than dropped.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let (Some(h), Some(l)) = (
                bytes.get(i + 1).and_then(|b| (*b as char).to_digit(16)),
                bytes.get(i + 2).and_then(|b| (*b as char).to_digit(16)),
            ) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse the raw query string of `uri` (the part after `?`) into
/// percent-decoded `(key, value)` pairs. Returns an empty list when the URI
/// carries no query.
fn parse_query_params(uri: &str) -> Vec<(String, String)> {
    let raw = match uri.split_once('?') {
        Some((_, q)) => q,
        None => return Vec::new(),
    };
    raw.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        })
        .collect()
}

/// Find a query parameter value by (exact) key.
fn query_param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// `PushEecContexts` (`POST .../eees-eeccontextreloc/v1/eec-contexts`,
/// TS29558_Eees_EECContextRelocation.yaml:30-73).
///
/// Parses the spec `EECContextPush` envelope (required: `eesId`, `eecCntx`
/// with `eecId` AND `cntxId`), stores every carried context keyed by its
/// `cntxId`, and answers **204 No Content** — or **200** with an
/// `EECContextPushRes` ONLY when `acrScenariosSelReq=true` yields a real
/// `selAcrScenariosList` (selected from the EEC-declared
/// `eecSrvContSupp.acrScenarios`). No `Location` header and no minted
/// sub-resource; an implicit registration is never fabricated.
async fn handle_eec_context_push(request: &SbiRequest) -> SbiResponse {
    log::info!("EEC context push");
    let value = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let push: EECContextPush = match serde_json::from_value(value) {
        Ok(p) => p,
        Err(e) => {
            return send_bad_request(
                &format!("Missing or invalid mandatory IE (eesId/eecCntx.eecId/eecCntx.cntxId): {e}"),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };
    if push.ees_id.trim().is_empty() {
        return send_bad_request(
            "Mandatory IE eesId is empty",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    let extras = push.eec_cntxs.as_deref().unwrap_or(&[]);
    for cntx in std::iter::once(&push.eec_cntx).chain(extras.iter()) {
        if cntx.eec_id.trim().is_empty() || cntx.cntx_id.trim().is_empty() {
            return send_bad_request(
                "Mandatory IE eecId/cntxId is empty in an EECContext",
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    }

    // The 200-vs-204 rule: 200 only when scenario selection was requested AND
    // the primary context declares supported ACR scenarios to select from;
    // otherwise 204. An empty EECContextPushRes is never emitted.
    let sel_acr_scenarios = if push.acr_scenarios_sel_req == Some(true) {
        push.eec_cntx
            .eec_srv_cont_supp
            .as_ref()
            .and_then(|c| c.acr_scenarios.clone())
            .filter(|scenarios| !scenarios.is_empty())
    } else {
        None
    };

    let stored = ees_self().read().ok().and_then(|c| {
        let mut all = vec![push.eec_cntx.clone()];
        all.extend(extras.iter().cloned());
        for cntx in all {
            c.eec_context_push(cntx)?;
        }
        Some(())
    });
    if stored.is_none() {
        return send_error(
            507,
            "Insufficient Storage",
            "Failed to store EEC context (capacity exhausted)",
            Some(cause::INSUFFICIENT_RESOURCES),
        );
    }

    match sel_acr_scenarios {
        Some(scenarios) => {
            let res = EECContextPushRes {
                impl_reg: None,
                sel_acr_scenarios_list: Some(scenarios),
            };
            SbiResponse::with_status(200)
                .with_json_body(&res)
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => SbiResponse::with_status(204),
    }
}

/// `PullEecContexts` (`GET .../eees-eeccontextreloc/v1/eec-contexts`,
/// TS29558_Eees_EECContextRelocation.yaml:75-127).
///
/// The pull is query-form: `ees-id` AND `eec-cntx-id` are REQUIRED
/// (yaml:81-92) → 400 `MANDATORY_IE_MISSING` when absent/empty. The optional
/// `sess-cntxs` parameter (a URL-encoded `SessionContexts` JSON document,
/// yaml:93-100) narrows the `sessCntxs` of the returned `EECContext` to the
/// requested `easId`s. Success is 200 with the `EECContext`, else 404.
async fn handle_eec_context_pull(request: &SbiRequest) -> SbiResponse {
    let params = parse_query_params(&request.header.uri);
    let ees_id = query_param(&params, "ees-id").unwrap_or("");
    let cntx_id = query_param(&params, "eec-cntx-id").unwrap_or("");
    if ees_id.trim().is_empty() || cntx_id.trim().is_empty() {
        return send_bad_request(
            "Mandatory query parameters ees-id and eec-cntx-id are required",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    // Optional sess-cntxs filter: a SessionContexts JSON document.
    let requested_sess: Option<SessionContexts> = match query_param(&params, "sess-cntxs") {
        Some(raw) => match serde_json::from_str(raw) {
            Ok(s) => Some(s),
            Err(e) => {
                return send_bad_request(
                    &format!("Invalid sess-cntxs query parameter: {e}"),
                    Some(cause::INVALID_MSG_FORMAT),
                );
            }
        },
        None => None,
    };

    let found = ees_self()
        .read()
        .ok()
        .and_then(|c| c.eec_context_pull(cntx_id));
    match found {
        Some(mut ctx) => {
            if let Some(requested) = requested_sess {
                // Narrow the response sessCntxs to the requested easIds;
                // SessionContexts.sessCntxs has minItems 1, so an empty
                // narrowing omits the member entirely.
                ctx.sess_cntxs = ctx.sess_cntxs.take().and_then(|stored| {
                    let kept: Vec<_> = stored
                        .sess_cntxs
                        .into_iter()
                        .filter(|s| requested.sess_cntxs.iter().any(|r| r.eas_id == s.eas_id))
                        .collect();
                    if kept.is_empty() {
                        None
                    } else {
                        Some(SessionContexts { sess_cntxs: kept })
                    }
                });
            }
            log::debug!("EEC context pulled: cntxId={cntx_id} by eesId={ees_id}");
            SbiResponse::with_status(200)
                .with_json_body(&ctx)
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(
            &format!("EEC context {cntx_id} not found"),
            Some(cause::SUBSCRIPTION_NOT_FOUND),
        ),
    }
}

// ---- D4: eees-acr-param handler ---------------------------------------------

/// `Request` (`POST {apiRoot}/eees-acr-param/v1/send-acrparamsinfo`,
/// TS29558_Eees_ACRParameterInformation.yaml:29-70).
///
/// The spec direction is REVERSED vs the legacy bespoke query: the consumer
/// (S-EAS via EEL) PUSHES `ACRParamsInfo` TO the EES. Parses the spec body
/// (all six IEs REQUIRED), fail-closed 400 `MANDATORY_IE_MISSING`, merges the
/// received source/target AS endpoints + `acrParams` into the `eecId`-keyed ACR
/// state, and returns 204 with no response body (the yaml defines no 200/2xx
/// body).
async fn handle_acr_param_send(request: &SbiRequest) -> SbiResponse {
    log::info!("ACR parameter information send");
    let value = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let info: ACRParamsInfo = match serde_json::from_value(value) {
        Ok(i) => i,
        Err(e) => {
            return send_bad_request(
                &format!(
                    "Missing or invalid mandatory IE \
                     (requestorId/eecId/acId/sAsEndPoint/tAsEndPoint/acrParams): {e}"
                ),
                Some(cause::MANDATORY_IE_MISSING),
            );
        }
    };
    if info.requestor_id.trim().is_empty()
        || info.eec_id.trim().is_empty()
        || info.ac_id.trim().is_empty()
    {
        return send_bad_request(
            "Mandatory IE requestorId/eecId/acId is empty",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    if info.s_as_end_point.is_empty() || info.t_as_end_point.is_empty() {
        return send_bad_request(
            "Mandatory IE sAsEndPoint/tAsEndPoint carries no address",
            Some(cause::MANDATORY_IE_MISSING),
        );
    }
    if let Ok(c) = ees_self().read() {
        c.acr_store_params(&info);
    }
    SbiResponse::with_status(204)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    fn signing_key() -> SigningKey {
        SigningKey::from_slice(&[9u8; 32]).unwrap()
    }

    fn jwks_for(sk: &SigningKey, kid: &str) -> serde_json::Value {
        let point = sk.verifying_key().to_encoded_point(false);
        serde_json::json!({"keys":[{
            "kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":kid,
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }]})
    }

    fn bearer(sk: &SigningKey, kid: &str, scope: &str) -> String {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let header = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{kid}"}}"#);
        let claims = serde_json::json!({
            "iss":"CAPIF","sub":"eec-1","aud":"EES","scope":scope,"exp":exp,"iat":0
        })
        .to_string();
        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
        let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("Bearer {h}.{p}.{s}")
    }

    /// Drive the async router from a synchronous test on a current-thread
    /// runtime. Used by the global-state tests so the serializing `Mutex` guard
    /// is held only across a *synchronous* `block_on`, never across an async
    /// await point (clippy `await_holding_lock`).
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-eesd"]);
        assert_eq!(args.config, "/etc/nextgcore/ees.yaml");
        assert_eq!(args.sbi_port, 7814);
        assert_eq!(args.max_eas, 512);
        // eesd-01: NRF removed in favour of an optional ECS apiRoot.
        assert!(args.ecs_uri.is_none());
    }

    /// eesd-01: a legacy `nees-*` path is no longer routed → 404.
    #[tokio::test]
    async fn test_router_rejects_legacy_nees_path() {
        let req = SbiRequest::post("/nees-easregistration/v1/registrations");
        let resp = ees_sbi_request_handler(req).await;
        assert_eq!(resp.status, 404);
    }

    /// eesd-08: a protected `eees-*` route with no token → 401 (the route
    /// matched and the OAuth2 gate fired before any handler ran).
    #[test]
    fn test_router_eees_route_requires_auth() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        auth::clear_auth_jwks();
        let req = SbiRequest::post("/eees-easregistration/v1/registrations");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 401);
    }

    /// eesd-08: a valid token carrying the wrong scope → 403.
    #[test]
    fn test_router_wrong_scope_403() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));
        let req = SbiRequest::post("/eees-easregistration/v1/registrations")
            .with_header("Authorization", bearer(&sk, "k1", "eees-easdiscovery"));
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 403);
        auth::clear_auth_jwks();
    }

    /// eesd-01/02/03: a valid token + spec example body → 201 with a `Location`
    /// keyed on a server-minted `registrationId` (≠ easId) and an echoed body
    /// whose `easProf.easId` round-trips.
    #[test]
    fn test_eas_register_mints_registration_id_and_location() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        let body =
            r#"{"easProf":{"easId":"eas1.example.com","endPt":{"fqdn":"eas1.example.com"}}}"#;
        let req = SbiRequest::post("/eees-easregistration/v1/registrations")
            .with_header("Authorization", bearer(&sk, "k1", "eees-easregistration"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));

        assert_eq!(resp.status, 201);
        let location = resp.http.get_header("location").cloned().unwrap();
        assert!(location.starts_with(EASREG_REGISTRATIONS_PATH));
        let registration_id = location.rsplit('/').next().unwrap();
        assert_ne!(registration_id, "eas1.example.com");
        assert!(!registration_id.is_empty());

        let stored: EasRegistration =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(stored.eas_prof.eas_id, "eas1.example.com");
        assert_eq!(stored.registration_id.as_deref(), Some(registration_id));

        auth::clear_auth_jwks();
    }

    /// eesd-02: a body missing the mandatory `endPt` → 400 ProblemDetails.
    #[test]
    fn test_eas_register_missing_endpt_400() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        let body = r#"{"easProf":{"easId":"eas1.example.com"}}"#;
        let req = SbiRequest::post("/eees-easregistration/v1/registrations")
            .with_header("Authorization", bearer(&sk, "k1", "eees-easregistration"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 400);

        auth::clear_auth_jwks();
    }

    /// eesd-03: an empty `easId` is rejected as a missing mandatory IE → 400.
    #[test]
    fn test_eas_register_empty_eas_id_400() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        let body = r#"{"easProf":{"easId":"","endPt":{"fqdn":"eas1.example.com"}}}"#;
        let req = SbiRequest::post("/eees-easregistration/v1/registrations")
            .with_header("Authorization", bearer(&sk, "k1", "eees-easregistration"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 400);

        auth::clear_auth_jwks();
    }

    /// eesd-01/05: the `eees-easdiscovery` spec path is routed and, with a valid
    /// discovery-scope token, returns a `discoveredEas` envelope (200).
    #[test]
    fn test_eas_discovery_route_dispatches() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        let body = r#"{"requestorId":"eec-1","easDiscoveryFilter":{"easChars":{"type":"V2X"}}}"#;
        let req = SbiRequest::post("/eees-easdiscovery/v1/eas-profiles/request-discovery")
            .with_header("Authorization", bearer(&sk, "k1", "eees-easdiscovery"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 200);
        assert!(resp
            .http
            .content
            .as_deref()
            .unwrap()
            .contains("discoveredEas"));

        auth::clear_auth_jwks();
    }

    /// Register an EAS through the router and return its server-minted
    /// `registrationId` (from the `Location` header).
    fn register_eas(sk: &SigningKey, eas_id: &str, eas_type: &str) -> String {
        let body = format!(
            r#"{{"easProf":{{"easId":"{eas_id}","endPt":{{"fqdn":"{eas_id}"}},"type":"{eas_type}"}}}}"#
        );
        let req = SbiRequest::post("/eees-easregistration/v1/registrations")
            .with_header("Authorization", bearer(sk, "k1", "eees-easregistration"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 201);
        resp.http
            .get_header("location")
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string()
    }

    /// eesd-04: PUT full-replace updates `expTime`/`type` (200) keeping `easId`;
    /// PUT that changes `easId` is rejected (403).
    #[test]
    fn test_eas_put_replace_and_reject_eas_id_change() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        let id = register_eas(&sk, "eas-put.example.com", "VIDEO");

        // PUT replace: new type + expTime, same easId → 200.
        let body = r#"{"easProf":{"easId":"eas-put.example.com","endPt":{"fqdn":"x"},"type":"AR"},"expTime":"2030-01-01T00:00:00Z"}"#;
        let req = SbiRequest::put(format!("/eees-easregistration/v1/registrations/{id}"))
            .with_header("Authorization", bearer(&sk, "k1", "eees-easregistration"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 200);
        let updated: EasRegistration =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(updated.eas_prof.eas_type.as_deref(), Some("AR"));
        assert_eq!(updated.exp_time.as_deref(), Some("2030-01-01T00:00:00Z"));
        assert_eq!(updated.registration_id.as_deref(), Some(id.as_str()));

        // PUT that changes easId → 403.
        let bad = r#"{"easProf":{"easId":"other.example.com","endPt":{"fqdn":"x"}}}"#;
        let req = SbiRequest::put(format!("/eees-easregistration/v1/registrations/{id}"))
            .with_header("Authorization", bearer(&sk, "k1", "eees-easregistration"))
            .with_body(bad, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 403);

        // PUT on an unknown id → 404.
        let req = SbiRequest::put("/eees-easregistration/v1/registrations/does-not-exist")
            .with_header("Authorization", bearer(&sk, "k1", "eees-easregistration"))
            .with_body(body, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 404);

        auth::clear_auth_jwks();
    }

    /// eesd-04: PATCH RFC 7396 merge updates a mutable field (200).
    #[test]
    fn test_eas_patch_merge() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        let id = register_eas(&sk, "eas-patch.example.com", "VIDEO");
        let patch = r#"{"easProf":{"type":"AR"}}"#;
        let req = SbiRequest::patch(format!("/eees-easregistration/v1/registrations/{id}"))
            .with_header("Authorization", bearer(&sk, "k1", "eees-easregistration"))
            .with_body(patch, "application/merge-patch+json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 200);
        let updated: EasRegistration =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(updated.eas_prof.eas_type.as_deref(), Some("AR"));
        assert_eq!(updated.eas_prof.eas_id, "eas-patch.example.com");

        // PATCH changing the immutable easId → 403.
        let bad = r#"{"easProf":{"easId":"changed.example.com"}}"#;
        let req = SbiRequest::patch(format!("/eees-easregistration/v1/registrations/{id}"))
            .with_header("Authorization", bearer(&sk, "k1", "eees-easregistration"))
            .with_body(bad, "application/merge-patch+json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 403);

        auth::clear_auth_jwks();
    }

    /// eesd-05: discovery filter returns only the matching `EASProfile`; a
    /// non-matching filter returns an empty `discoveredEas`.
    #[test]
    fn test_eas_discovery_filter_returns_matching_profile() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        register_eas(&sk, "eas-disc-uniq.example.com", "V2X");

        // Filter by the exact easId → exactly one match.
        let body = r#"{"requestorId":"eec-1","easDiscoveryFilter":{"easChars":{"easId":"eas-disc-uniq.example.com"}}}"#;
        let req = SbiRequest::post("/eees-easdiscovery/v1/eas-profiles/request-discovery")
            .with_header("Authorization", bearer(&sk, "k1", "eees-easdiscovery"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 200);
        let dr: EasDiscoveryResp =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(dr.discovered_eas.len(), 1);
        assert_eq!(dr.discovered_eas[0].eas.eas_id, "eas-disc-uniq.example.com");

        // Non-matching filter → empty.
        let body = r#"{"requestorId":"eec-1","easDiscoveryFilter":{"easChars":{"easId":"nope.example.com"}}}"#;
        let req = SbiRequest::post("/eees-easdiscovery/v1/eas-profiles/request-discovery")
            .with_header("Authorization", bearer(&sk, "k1", "eees-easdiscovery"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        let dr: EasDiscoveryResp =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(dr.discovered_eas.is_empty());

        auth::clear_auth_jwks();
    }

    /// eesd-05: a discovery subscription create returns 201 + a `Location`.
    #[test]
    fn test_disc_subscription_create() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        let body = r#"{"notificationUri":"http://eec/cb","easDiscoveryFilter":{"easChars":{"easType":"V2X"}}}"#;
        let req = SbiRequest::post("/eees-easdiscovery/v1/subscriptions")
            .with_header("Authorization", bearer(&sk, "k1", "eees-easdiscovery"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 201);
        let loc = resp.http.get_header("location").cloned().unwrap();
        assert!(loc.starts_with(EASDISC_SUBSCRIPTIONS_PATH));

        // The minted subscriptionId is fetchable.
        let sub_id = loc.rsplit('/').next().unwrap();
        let req = SbiRequest::get(format!("/eees-easdiscovery/v1/subscriptions/{sub_id}"))
            .with_header("Authorization", bearer(&sk, "k1", "eees-easdiscovery"));
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 200);

        auth::clear_auth_jwks();
    }

    /// eesd-06: full EEC registration lifecycle through the router
    /// (POST→201/GET→200/PUT→200/PATCH→200/DELETE→204/GET→404) with a
    /// server-minted `expTime`.
    #[test]
    fn test_eec_register_lifecycle_router() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        // POST → 201 + Location + minted expTime.
        let body = r#"{"eecId":"eec1.example.com","ueId":"gpsi-1","acProfs":[{"acId":"ac1"}]}"#;
        let req = SbiRequest::post("/eees-eecregistration/v1/registrations")
            .with_header("Authorization", bearer(&sk, "k1", "eees-eecregistration"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 201);
        let stored: EecRegistration =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(stored.eec_id, "eec1.example.com");
        assert!(
            stored.exp_time.is_some(),
            "EES mints an expTime when absent"
        );
        let id = stored.registration_id.clone().unwrap();

        // GET → 200.
        let req = SbiRequest::get(format!("/eees-eecregistration/v1/registrations/{id}"))
            .with_header("Authorization", bearer(&sk, "k1", "eees-eecregistration"));
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 200);

        // PUT replace → 200; eecId change → 403.
        let put = r#"{"eecId":"eec1.example.com","ueId":"gpsi-2"}"#;
        let req = SbiRequest::put(format!("/eees-eecregistration/v1/registrations/{id}"))
            .with_header("Authorization", bearer(&sk, "k1", "eees-eecregistration"))
            .with_body(put, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 200);
        let bad = r#"{"eecId":"eec2.example.com"}"#;
        let req = SbiRequest::put(format!("/eees-eecregistration/v1/registrations/{id}"))
            .with_header("Authorization", bearer(&sk, "k1", "eees-eecregistration"))
            .with_body(bad, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 403);

        // PATCH merge → 200.
        let patch = r#"{"ueId":"gpsi-3"}"#;
        let req = SbiRequest::patch(format!("/eees-eecregistration/v1/registrations/{id}"))
            .with_header("Authorization", bearer(&sk, "k1", "eees-eecregistration"))
            .with_body(patch, "application/merge-patch+json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 200);
        let patched: EecRegistration =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(patched.ue_id.as_deref(), Some("gpsi-3"));

        // DELETE → 204; subsequent GET → 404.
        let req = SbiRequest::delete(format!("/eees-eecregistration/v1/registrations/{id}"))
            .with_header("Authorization", bearer(&sk, "k1", "eees-eecregistration"));
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 204);
        let req = SbiRequest::get(format!("/eees-eecregistration/v1/registrations/{id}"))
            .with_header("Authorization", bearer(&sk, "k1", "eees-eecregistration"));
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 404);

        auth::clear_auth_jwks();
    }

    /// eesd-08: the EEC registration route is OAuth2-gated (no token → 401).
    #[test]
    fn test_eec_route_requires_auth() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        auth::clear_auth_jwks();
        let req = SbiRequest::post("/eees-eecregistration/v1/registrations");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 401);
    }

    /// eesd-11: a registration carrying `suppFeat="1"` echoes the negotiated
    /// `suppFeat` in the 201 body.
    #[test]
    fn test_supp_feat_echoed_on_register() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        let body =
            r#"{"easProf":{"easId":"eas-feat.example.com","endPt":{"fqdn":"x"}},"suppFeat":"1"}"#;
        let req = SbiRequest::post("/eees-easregistration/v1/registrations")
            .with_header("Authorization", bearer(&sk, "k1", "eees-easregistration"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 201);
        let stored: EasRegistration =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(stored.supp_feat.as_deref(), Some("1"));

        auth::clear_auth_jwks();
    }

    // ---- eesd-07: ACR suite tests -------------------------------------------

    /// ACR Determine (TS 24.558 §6.5.5.2.2): register S-EAS + T-EAS, POST a
    /// spec-shaped body → 204 No Content and a DETERMINED state whose T-EAS is
    /// not the S-EAS.
    #[test]
    fn test_acr_determine_returns_t_eas() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        // Register S-EAS and T-EAS.
        register_eas(&sk, "s-eas.example.com", "V2X");
        register_eas(&sk, "t-eas.example.com", "V2X");

        let body = r#"{
            "requestorId":"eec-acr-1",
            "sEasEndpoint":{"fqdn":"s-eas.example.com"},
            "ueId":"imsi-999700000000001",
            "easId":"s-eas.example.com"
        }"#;
        let req = SbiRequest::post("/eees-appctxtreloc/v1/determine")
            .with_header("Authorization", bearer(&sk, "k1", "eees-appctxtreloc"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 204, "Determine success is 204 No Content");
        assert!(resp.http.content.as_deref().unwrap_or("").is_empty());

        // DETERMINED state recorded (keyed by UE); T-EAS ≠ S-EAS.
        let state = ees_self()
            .read()
            .unwrap()
            .acr_find(Some("imsi-999700000000001"), Some("eec-acr-1"))
            .unwrap();
        assert_eq!(state.status, Some(acr::AcrStatus::Determined));
        let t_eas_id = state.t_eas_id.expect("T-EAS must be determined");
        assert_ne!(t_eas_id, "s-eas.example.com");
        assert!(state.s_eas_endpoint.is_some());
        assert!(state.t_eas_endpoint.is_some());

        auth::clear_auth_jwks();
    }

    /// ACR Determine with an `easId` that is not registered → 404.
    #[test]
    fn test_acr_determine_unknown_s_eas_404() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        let body = r#"{
            "requestorId":"eec-acr-2",
            "sEasEndpoint":{"fqdn":"ghost.example.com"},
            "easId":"ghost.example.com"
        }"#;
        let req = SbiRequest::post("/eees-appctxtreloc/v1/determine")
            .with_header("Authorization", bearer(&sk, "k1", "eees-appctxtreloc"))
            .with_body(body, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 404);

        auth::clear_auth_jwks();
    }

    /// ACR Determine with a missing mandatory IE (`sEasEndpoint`) → 400.
    #[test]
    fn test_acr_determine_missing_ie_400() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        // Missing sEasEndpoint.
        let body = r#"{"requestorId":"eec-1"}"#;
        let req = SbiRequest::post("/eees-appctxtreloc/v1/determine")
            .with_header("Authorization", bearer(&sk, "k1", "eees-appctxtreloc"))
            .with_body(body, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 400);

        auth::clear_auth_jwks();
    }

    /// ACR Initiate (§6.5.5.2.3): POST with the required IEs → 204 + INITIATED;
    /// a missing `tEasEndpoint` → 400.
    #[test]
    fn test_acr_initiate_transitions_state() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        // Valid Initiate → 204.
        let body = r#"{
            "requestorId":"eec-init-1",
            "tEasEndpoint":{"fqdn":"eas-t.example.com"},
            "easNotifInd":true,
            "ueId":"imsi-init-1"
        }"#;
        let req = SbiRequest::post("/eees-appctxtreloc/v1/initiate")
            .with_header("Authorization", bearer(&sk, "k1", "eees-appctxtreloc"))
            .with_body(body, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 204);

        // Verify state is INITIATED in the context.
        let state = ees_self()
            .read()
            .unwrap()
            .acr_find(Some("imsi-init-1"), Some("eec-init-1"))
            .unwrap();
        assert_eq!(state.status, Some(acr::AcrStatus::Initiated));
        assert!(state.t_eas_endpoint.is_some());

        // Initiate without tEasEndpoint → 400.
        let bad = r#"{"requestorId":"eec-init-1","easNotifInd":false}"#;
        let req = SbiRequest::post("/eees-appctxtreloc/v1/initiate")
            .with_header("Authorization", bearer(&sk, "k1", "eees-appctxtreloc"))
            .with_body(bad, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 400);

        auth::clear_auth_jwks();
    }

    /// ACR Declare (§6.5.5.2.4): POST with the three mandatory IEs → 204 +
    /// COMPLETED state; missing `tEasId` → 400.
    #[test]
    fn test_acr_declare_completes_relocation() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        let body = r#"{
            "ueId":"imsi-decl-1",
            "tEasId":"eas-t.example.com",
            "tEasEndpoint":{"fqdn":"eas-t.example.com"},
            "requestorId":"eas-s.example.com"
        }"#;
        let req = SbiRequest::post("/eees-appctxtreloc/v1/declare")
            .with_header("Authorization", bearer(&sk, "k1", "eees-appctxtreloc"))
            .with_body(body, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 204);

        // Verify COMPLETED state (keyed by UE).
        let state = ees_self()
            .read()
            .unwrap()
            .acr_find(Some("imsi-decl-1"), Some("eas-s.example.com"))
            .unwrap();
        assert_eq!(state.status, Some(acr::AcrStatus::Completed));
        assert_eq!(state.t_eas_id.as_deref(), Some("eas-t.example.com"));

        // Missing tEasId → 400.
        let bad = r#"{"ueId":"imsi-decl-1","tEasEndpoint":{"fqdn":"eas-t"},"tEasId":""}"#;
        let req = SbiRequest::post("/eees-appctxtreloc/v1/declare")
            .with_header("Authorization", bearer(&sk, "k1", "eees-appctxtreloc"))
            .with_body(bad, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 400);

        auth::clear_auth_jwks();
    }

    /// EEL-managed ACR (TS 29.558 §8.8): POST `EELACRReq` with an EAS
    /// registered → 200 + INITIATED; missing `easCharacs` → 400.
    #[test]
    fn test_eel_acr_request_200_and_404() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        register_eas(&sk, "eel-t-eas.example.com", "AR");

        // Valid EEL-managed ACR → 200; echoes the app-context store address.
        let body = r#"{
            "ueId":"imsi-eel-1",
            "easCharacs":[{"easId":"eel-t-eas.example.com"}],
            "appCtxtStoreAddr":"https://store.example.com/ctx/eel-1"
        }"#;
        let req = SbiRequest::post("/eees-eel-acr/v1/request-eelacr")
            .with_header("Authorization", bearer(&sk, "k1", "eees-eel-acr"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 200);
        let er: EELACRResp = serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            er.app_ctxt_store_addr.as_deref(),
            Some("https://store.example.com/ctx/eel-1")
        );

        // Verify INITIATED state set by the EEL-managed flow (keyed by UE).
        let state = ees_self()
            .read()
            .unwrap()
            .acr_find(Some("imsi-eel-1"), None)
            .unwrap();
        assert_eq!(state.status, Some(acr::AcrStatus::Initiated));

        // Missing easCharacs → 400.
        let bad = r#"{"ueId":"imsi-eel-1"}"#;
        let req = SbiRequest::post("/eees-eel-acr/v1/request-eelacr")
            .with_header("Authorization", bearer(&sk, "k1", "eees-eel-acr"))
            .with_body(bad, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 400);

        auth::clear_auth_jwks();
    }

    /// ACR status update (TS 29.558 §8.9): POST `ACRUpdateData` with `easId` +
    /// `actResultInfo` → 204; missing `easId` → 400; no status attribute → 400.
    #[test]
    fn test_acr_status_update_200_and_missing_status_400() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        // Valid ACR status update → 204.
        let body = r#"{
            "easId":"upd-t.example.com",
            "actResultInfo":{"actResult":"ACT_SUCCESSFUL"}
        }"#;
        let req = SbiRequest::post("/eees-acrstatus-update/v1/request-acrupdate")
            .with_header("Authorization", bearer(&sk, "k1", "eees-acrstatus-update"))
            .with_body(body, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 204);

        // Missing easId → 400.
        let bad = r#"{"actResultInfo":{"actResult":"ACT_SUCCESSFUL"}}"#;
        let req = SbiRequest::post("/eees-acrstatus-update/v1/request-acrupdate")
            .with_header("Authorization", bearer(&sk, "k1", "eees-acrstatus-update"))
            .with_body(bad, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 400);

        // No status attribute at all (§8.9.6.2.2 NOTE) → 400.
        let bad = r#"{"easId":"upd-t.example.com"}"#;
        let req = SbiRequest::post("/eees-acrstatus-update/v1/request-acrupdate")
            .with_header("Authorization", bearer(&sk, "k1", "eees-acrstatus-update"))
            .with_body(bad, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 400);

        auth::clear_auth_jwks();
    }

    /// eesd-07: ACR routes are OAuth2-gated (no token → 401).
    #[test]
    fn test_acr_routes_require_auth() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        auth::clear_auth_jwks();

        for path in [
            "/eees-appctxtreloc/v1/determine",
            "/eees-appctxtreloc/v1/initiate",
            "/eees-appctxtreloc/v1/declare",
            "/eees-eel-acr/v1/request-eelacr",
            "/eees-acrstatus-update/v1/request-acrupdate",
        ] {
            let req = SbiRequest::post(path);
            assert_eq!(
                block_on(ees_sbi_request_handler(req)).status,
                401,
                "expected 401 for {path}"
            );
        }
    }

    /// eesd-07: the legacy `nees-uecontexttransfer` path is absent → 404.
    #[test]
    fn test_uecontexttransfer_path_is_gone() {
        for path in [
            "/nees-uecontexttransfer/v1/contexts/gpsi-12345",
            "/nees-uecontexttransfer/v1/contexts",
        ] {
            let req = SbiRequest::get(path);
            assert_eq!(
                block_on(ees_sbi_request_handler(req)).status,
                404,
                "expected 404 for {path} (uecontexttransfer removed in eesd-01/07)"
            );
        }
    }

    // ---- eesd-13 tests -------------------------------------------------------

    /// D3 eees-cea: the spec custom op `POST /declare` (CommonEASInfo) → 204
    /// with NO body and NO Location; the declaration is stored keyed by
    /// (appGrpId, easId). The fabricated `/announcements` collection is gone
    /// (404), `GET /declare` → 405, and the DIFFERENT eees-appctxtreloc
    /// `/declare` op still routes to its own handler (no arm-ordering mistake).
    #[test]
    fn test_cea_declare_custom_op() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        // POST /declare with all 4 required IEs → 204 (empty body, no Location).
        let body = r#"{
            "requestorId":"ees-src.example.com",
            "easId":"common-eas.example.com",
            "easEndPt":{"fqdn":"common-eas.edge.example.com"},
            "appGrpId":"grp-1"
        }"#;
        let req = SbiRequest::post("/eees-cea/v1/declare")
            .with_header("Authorization", bearer(&sk, "k1", "eees-cea"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 204);
        assert!(resp.http.content.as_deref().unwrap_or("").is_empty());
        assert!(resp.http.get_header("location").is_none());

        // The declaration is recorded (accept-and-ack, keyed by appGrpId:easId).
        {
            let stored = ees_self()
                .read()
                .unwrap()
                .cea_declared_find("grp-1", "common-eas.example.com")
                .expect("declared common EAS is stored");
            assert_eq!(stored.requestor_id, "ees-src.example.com");
            assert_eq!(
                stored.eas_end_pt.fqdn.as_deref(),
                Some("common-eas.edge.example.com")
            );
        }

        // The fabricated /announcements collection is gone → 404.
        let req = SbiRequest::post("/eees-cea/v1/announcements")
            .with_header("Authorization", bearer(&sk, "k1", "eees-cea"))
            .with_body(body, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 404);

        // GET /declare → 405 (POST-only custom op).
        let req = SbiRequest::get("/eees-cea/v1/declare")
            .with_header("Authorization", bearer(&sk, "k1", "eees-cea"));
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 405);

        // Regression: the DIFFERENT eees-appctxtreloc /declare op still routes
        // to handle_acr_declare (a valid AcrDecReq → 204, NOT 404/CEA).
        let decl_body = r#"{
            "ueId":"imsi-cea-decl-1",
            "tEasId":"eas-t.example.com",
            "tEasEndpoint":{"fqdn":"eas-t.edge.example.com"}
        }"#;
        let req = SbiRequest::post("/eees-appctxtreloc/v1/declare")
            .with_header("Authorization", bearer(&sk, "k1", "eees-appctxtreloc"))
            .with_body(decl_body, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 204);

        auth::clear_auth_jwks();
    }

    /// D3 eees-cea: each of the 4 required IEs missing → 400
    /// MANDATORY_IE_MISSING (and an easEndPt with no address form → 400).
    #[test]
    fn test_cea_declare_missing_required_400() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        for bad in [
            // Missing requestorId.
            r#"{"easId":"e","easEndPt":{"fqdn":"e"},"appGrpId":"g"}"#,
            // Missing easId.
            r#"{"requestorId":"r","easEndPt":{"fqdn":"e"},"appGrpId":"g"}"#,
            // Missing easEndPt.
            r#"{"requestorId":"r","easId":"e","appGrpId":"g"}"#,
            // Missing appGrpId.
            r#"{"requestorId":"r","easId":"e","easEndPt":{"fqdn":"e"}}"#,
            // easEndPt present but carries no address form.
            r#"{"requestorId":"r","easId":"e","easEndPt":{},"appGrpId":"g"}"#,
            // Empty required string.
            r#"{"requestorId":"","easId":"e","easEndPt":{"fqdn":"e"},"appGrpId":"g"}"#,
        ] {
            let req = SbiRequest::post("/eees-cea/v1/declare")
                .with_header("Authorization", bearer(&sk, "k1", "eees-cea"))
                .with_body(bad, "application/json");
            assert_eq!(
                block_on(ees_sbi_request_handler(req)).status,
                400,
                "expected 400 for body {bad}"
            );
        }

        auth::clear_auth_jwks();
    }

    /// D1 eees-appclientinformation: spec `ACInfoSubscription` lifecycle —
    /// POST {"easId":..} → 201 + Location; GET → 200 same body; PUT full
    /// replace → 200; PATCH merge-patch changing only `expTime` → 200 with
    /// `easId` preserved; DELETE → 204; GET → 404.
    #[test]
    fn test_acinfo_lifecycle() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        // POST the minimal spec body (sole mandatory IE easId) → 201.
        let body = r#"{"easId":"eas1.example.com"}"#;
        let req = SbiRequest::post("/eees-appclientinformation/v1/subscriptions")
            .with_header(
                "Authorization",
                bearer(&sk, "k1", "eees-appclientinformation"),
            )
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 201);
        let loc = resp.http.get_header("location").cloned().unwrap();
        assert!(loc.starts_with(APPCLIENTINFO_RESOURCES_PATH));
        let id = loc.rsplit('/').next().unwrap().to_string();
        assert!(!id.is_empty());
        let created: ACInfoSubscription =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(created.eas_id, "eas1.example.com");

        // GET → 200 with the same body.
        let req = SbiRequest::get(format!("/eees-appclientinformation/v1/subscriptions/{id}"))
            .with_header(
                "Authorization",
                bearer(&sk, "k1", "eees-appclientinformation"),
            );
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 200);
        let fetched: ACInfoSubscription =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(fetched, created);

        // PUT full replace → 200 (new acFltrs; easId unchanged).
        let put_body =
            r#"{"easId":"eas1.example.com","acFltrs":[{"acTypesList":["V2X"]}],"suppFeat":"1"}"#;
        let req = SbiRequest::put(format!("/eees-appclientinformation/v1/subscriptions/{id}"))
            .with_header(
                "Authorization",
                bearer(&sk, "k1", "eees-appclientinformation"),
            )
            .with_body(put_body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 200);
        let replaced: ACInfoSubscription =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(replaced.ac_fltrs.is_some());

        // PATCH merge-patch changing ONLY expTime → 200; easId + acFltrs
        // preserved (ACInfoSubscriptionPatch semantics).
        let patch = r#"{"expTime":"2030-01-01T00:00:00Z"}"#;
        let req = SbiRequest::patch(format!("/eees-appclientinformation/v1/subscriptions/{id}"))
            .with_header(
                "Authorization",
                bearer(&sk, "k1", "eees-appclientinformation"),
            )
            .with_body(patch, "application/merge-patch+json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 200);
        let patched: ACInfoSubscription =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(patched.eas_id, "eas1.example.com");
        assert_eq!(patched.exp_time.as_deref(), Some("2030-01-01T00:00:00Z"));
        assert!(patched.ac_fltrs.is_some(), "merge keeps unpatched members");

        // A patch attempting to change the immutable easId is ignored (only
        // ACInfoSubscriptionPatch members are merged).
        let bad_patch = r#"{"easId":"evil.example.com"}"#;
        let req = SbiRequest::patch(format!("/eees-appclientinformation/v1/subscriptions/{id}"))
            .with_header(
                "Authorization",
                bearer(&sk, "k1", "eees-appclientinformation"),
            )
            .with_body(bad_patch, "application/merge-patch+json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 200);
        let unchanged: ACInfoSubscription =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(unchanged.eas_id, "eas1.example.com");

        // DELETE → 204; GET → 404.
        let req = SbiRequest::delete(format!("/eees-appclientinformation/v1/subscriptions/{id}"))
            .with_header(
                "Authorization",
                bearer(&sk, "k1", "eees-appclientinformation"),
            );
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 204);
        let req = SbiRequest::get(format!("/eees-appclientinformation/v1/subscriptions/{id}"))
            .with_header(
                "Authorization",
                bearer(&sk, "k1", "eees-appclientinformation"),
            );
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 404);

        auth::clear_auth_jwks();
    }

    /// D1 fail-closed: the OLD bespoke shape {"acId":"ac1"} (no easId) → 400
    /// with cause MANDATORY_IE_MISSING; a body with acFltrs but no easId →
    /// 400; the non-spec collection GET → 405.
    #[test]
    fn test_acinfo_fail_closed_and_no_collection_get() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        for bad in [
            r#"{"acId":"ac1"}"#,
            r#"{"acFltrs":[{"acIdsList":["ac1"]}]}"#,
            r#"{"easId":""}"#,
        ] {
            let req = SbiRequest::post("/eees-appclientinformation/v1/subscriptions")
                .with_header(
                    "Authorization",
                    bearer(&sk, "k1", "eees-appclientinformation"),
                )
                .with_body(bad, "application/json");
            let resp = block_on(ees_sbi_request_handler(req));
            assert_eq!(resp.status, 400, "expected 400 for body {bad}");
            assert!(
                resp.http
                    .content
                    .as_deref()
                    .unwrap()
                    .contains("MANDATORY_IE_MISSING"),
                "400 ProblemDetails must carry cause MANDATORY_IE_MISSING"
            );
        }

        // The spec defines no collection GET → 405.
        let req = SbiRequest::get("/eees-appclientinformation/v1/subscriptions").with_header(
            "Authorization",
            bearer(&sk, "k1", "eees-appclientinformation"),
        );
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 405);

        auth::clear_auth_jwks();
    }

    /// D1 strict-peer: a raw spec JSON document (hand-derived from
    /// TS29558_Eees_AppClientInformation.yaml, NOT via our structs) is
    /// accepted, and the echoed 201 wire body contains ONLY spec schema keys
    /// (no `subscriptionId`/`acId` leakage).
    #[test]
    fn test_acinfo_strict_peer_body_whitelist() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        // Raw strict-peer body: every ACInfoSubscription member (yaml:317-353).
        let body = r#"{
            "easId":"eas-strict.example.com",
            "acFltrs":[{"acTypesList":["V2X"],"ueIds":["msisdn-14155550001"]}],
            "expTime":"2030-01-01T00:00:00Z",
            "eventReq":{"notifMethod":"ON_EVENT_DETECTION"},
            "notificationDestination":"http://eas-strict.example.com/cb",
            "requestTestNotification":false,
            "websockNotifConfig":{"requestWebsocketUri":true},
            "suppFeat":"1",
            "trigCondParams":["EAS_DISCOVERY"]
        }"#;
        let req = SbiRequest::post("/eees-appclientinformation/v1/subscriptions")
            .with_header(
                "Authorization",
                bearer(&sk, "k1", "eees-appclientinformation"),
            )
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 201);

        // Field-whitelist assert on the raw wire body.
        let wire: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let allowed = [
            "easId",
            "acFltrs",
            "expTime",
            "eventReq",
            "notificationDestination",
            "requestTestNotification",
            "websockNotifConfig",
            "suppFeat",
            "trigCondParams",
        ];
        for key in wire.as_object().unwrap().keys() {
            assert!(
                allowed.contains(&key.as_str()),
                "non-spec field {key} leaked into the wire body"
            );
        }
        assert!(wire.get("subscriptionId").is_none());
        assert!(wire.get("acId").is_none());
        assert_eq!(wire["easId"], "eas-strict.example.com");

        auth::clear_auth_jwks();
    }

    /// eesd-13 eees-acrmgntevent: POST → 201; GET; PUT full-replace; DELETE.
    #[test]
    fn test_acrmgnt_subscription_lifecycle() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        let body = r#"{"notificationUri":"http://eec/acr-mgnt/cb","acrEvents":["ACR_COMPLETED"]}"#;
        let req = SbiRequest::post("/eees-acrmgntevent/v1/subscriptions")
            .with_header("Authorization", bearer(&sk, "k1", "eees-acrmgntevent"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 201);
        let loc = resp.http.get_header("location").cloned().unwrap();
        assert!(loc.starts_with(ACRMGNTEVENT_SUBSCRIPTIONS_PATH));
        let id = loc.rsplit('/').next().unwrap().to_string();
        let created: AcrMgntEventSubsc =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(created.notification_uri, "http://eec/acr-mgnt/cb");
        assert_eq!(created.subscription_id.as_deref(), Some(id.as_str()));

        // GET individual → 200.
        let req = SbiRequest::get(format!("/eees-acrmgntevent/v1/subscriptions/{id}"))
            .with_header("Authorization", bearer(&sk, "k1", "eees-acrmgntevent"));
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 200);

        // PUT full-replace → 200 with new notificationUri.
        let update = r#"{"notificationUri":"http://eec/acr-mgnt/cb2"}"#;
        let req = SbiRequest::put(format!("/eees-acrmgntevent/v1/subscriptions/{id}"))
            .with_header("Authorization", bearer(&sk, "k1", "eees-acrmgntevent"))
            .with_body(update, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 200);
        let updated: AcrMgntEventSubsc =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(updated.notification_uri, "http://eec/acr-mgnt/cb2");
        assert_eq!(updated.subscription_id.as_deref(), Some(id.as_str()));

        // DELETE → 204; second DELETE → 404.
        let req = SbiRequest::delete(format!("/eees-acrmgntevent/v1/subscriptions/{id}"))
            .with_header("Authorization", bearer(&sk, "k1", "eees-acrmgntevent"));
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 204);
        let req = SbiRequest::delete(format!("/eees-acrmgntevent/v1/subscriptions/{id}"))
            .with_header("Authorization", bearer(&sk, "k1", "eees-acrmgntevent"));
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 404);

        auth::clear_auth_jwks();
    }

    /// D2 eees-eeccontextreloc (TS 29.558 §8.7.2): spec push
    /// (EECContextPush{eesId,eecCntx{eecId,cntxId}}) → 204 with NO Location;
    /// old flat push → 400; query-form pull → 200; pull without the required
    /// params → 400; the old path-param pull form → 404; no token → 401.
    #[test]
    fn test_eec_context_push_pull() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        // Spec push (S-EES side of the strict-peer round trip) → 204.
        let body = r#"{
            "eesId":"ees-src",
            "eecCntx":{
                "eecId":"eec1","cntxId":"c-1","ueId":"msisdn-14155550001",
                "sessCntxs":{"sessCntxs":[
                    {"easId":"eas1.example.com","endPt":{"fqdn":"eas1.example.com"}},
                    {"easId":"eas2.example.com","endPt":{"fqdn":"eas2.example.com"}}
                ]}
            }
        }"#;
        let req = SbiRequest::post("/eees-eeccontextreloc/v1/eec-contexts")
            .with_header("Authorization", bearer(&sk, "k1", "eees-eeccontextreloc"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 204, "spec push success is 204 No Content");
        assert!(
            resp.http.get_header("location").is_none(),
            "push mints no sub-resource: Location header must be absent"
        );
        assert!(resp.http.content.as_deref().unwrap_or("").is_empty());

        // OLD flat bespoke push shape → 400 MANDATORY_IE_MISSING.
        let bad = r#"{"eecId":"eec1","ueId":"ue-1"}"#;
        let req = SbiRequest::post("/eees-eeccontextreloc/v1/eec-contexts")
            .with_header("Authorization", bearer(&sk, "k1", "eees-eeccontextreloc"))
            .with_body(bad, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 400);
        assert!(resp
            .http
            .content
            .as_deref()
            .unwrap()
            .contains("MANDATORY_IE_MISSING"));

        // Query-form pull (T-EES side of the round trip) → 200 EECContext.
        let req = SbiRequest::get("/eees-eeccontextreloc/v1/eec-contexts?ees-id=ees-t&eec-cntx-id=c-1")
            .with_header("Authorization", bearer(&sk, "k1", "eees-eeccontextreloc"));
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 200);
        let pulled: services::EECContext =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(pulled.eec_id, "eec1");
        assert_eq!(pulled.cntx_id, "c-1");
        assert_eq!(pulled.ue_id.as_deref(), Some("msisdn-14155550001"));

        // Optional sess-cntxs filter narrows the returned sessCntxs.
        let filter = "%7B%22sessCntxs%22%3A%5B%7B%22easId%22%3A%22eas1.example.com%22%2C%22endPt%22%3A%7B%22fqdn%22%3A%22eas1.example.com%22%7D%7D%5D%7D";
        let req = SbiRequest::get(format!(
            "/eees-eeccontextreloc/v1/eec-contexts?ees-id=ees-t&eec-cntx-id=c-1&sess-cntxs={filter}"
        ))
        .with_header("Authorization", bearer(&sk, "k1", "eees-eeccontextreloc"));
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 200);
        let narrowed: services::EECContext =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let sess = narrowed.sess_cntxs.unwrap();
        assert_eq!(sess.sess_cntxs.len(), 1);
        assert_eq!(sess.sess_cntxs[0].eas_id, "eas1.example.com");

        // Pull without the REQUIRED query params → 400.
        let req = SbiRequest::get("/eees-eeccontextreloc/v1/eec-contexts")
            .with_header("Authorization", bearer(&sk, "k1", "eees-eeccontextreloc"));
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 400);
        let req = SbiRequest::get("/eees-eeccontextreloc/v1/eec-contexts?ees-id=ees-t")
            .with_header("Authorization", bearer(&sk, "k1", "eees-eeccontextreloc"));
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 400);

        // Unknown eec-cntx-id → 404.
        let req = SbiRequest::get("/eees-eeccontextreloc/v1/eec-contexts?ees-id=ees-t&eec-cntx-id=nope")
            .with_header("Authorization", bearer(&sk, "k1", "eees-eeccontextreloc"));
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 404);

        // The OLD path-param pull form → 404 (no individual resource in the yaml).
        let req = SbiRequest::get("/eees-eeccontextreloc/v1/eec-contexts/c-1")
            .with_header("Authorization", bearer(&sk, "k1", "eees-eeccontextreloc"));
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 404);

        // No token → 401.
        auth::clear_auth_jwks();
        let req = SbiRequest::post("/eees-eeccontextreloc/v1/eec-contexts")
            .with_body(body, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 401);

        auth::clear_auth_jwks();
    }

    /// D2: acrScenariosSelReq=true with EEC-declared acrScenarios → 200 with
    /// a non-empty EECContextPushRes.selAcrScenariosList and NO fabricated
    /// implReg; without scenarios → 204.
    #[test]
    fn test_eec_context_push_acr_scenario_selection() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        // Selection requested + scenarios declared → 200.
        let body = r#"{
            "eesId":"ees-src",
            "eecCntx":{
                "eecId":"eec-sel","cntxId":"c-sel",
                "eecSrvContSupp":{"srvContSupp":true,"acrScenarios":["EEC_INITIATED","EEC_EXECUTED_VIA_SOURCE_EES"]}
            },
            "acrScenariosSelReq":true
        }"#;
        let req = SbiRequest::post("/eees-eeccontextreloc/v1/eec-contexts")
            .with_header("Authorization", bearer(&sk, "k1", "eees-eeccontextreloc"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 200);
        let res: EECContextPushRes =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let sel = res.sel_acr_scenarios_list.expect("selection returned");
        assert!(!sel.is_empty());
        assert!(sel.contains(&"EEC_INITIATED".to_string()));
        assert!(res.impl_reg.is_none(), "implReg is never fabricated");

        // Selection requested but the EEC declared no scenarios → 204.
        let body = r#"{
            "eesId":"ees-src",
            "eecCntx":{"eecId":"eec-nosel","cntxId":"c-nosel"},
            "acrScenariosSelReq":true
        }"#;
        let req = SbiRequest::post("/eees-eeccontextreloc/v1/eec-contexts")
            .with_header("Authorization", bearer(&sk, "k1", "eees-eeccontextreloc"))
            .with_body(body, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 204);

        auth::clear_auth_jwks();
    }

    /// D2: the percent-decoding query helper handles plain, encoded, empty and
    /// valueless parameters.
    #[test]
    fn test_parse_query_params_percent_decoding() {
        assert!(parse_query_params("/eec-contexts").is_empty());
        let p = parse_query_params("/eec-contexts?ees-id=ees-t&eec-cntx-id=c-1");
        assert_eq!(query_param(&p, "ees-id"), Some("ees-t"));
        assert_eq!(query_param(&p, "eec-cntx-id"), Some("c-1"));
        assert_eq!(query_param(&p, "missing"), None);

        // Percent-encoded value round-trips ({"a":"b c"}).
        let p = parse_query_params("/x?doc=%7B%22a%22%3A%22b%20c%22%7D");
        assert_eq!(query_param(&p, "doc"), Some(r#"{"a":"b c"}"#));

        // Valueless + empty pairs are tolerated; malformed escapes are kept
        // verbatim rather than dropped.
        let p = parse_query_params("/x?flag&&k=v%2");
        assert_eq!(query_param(&p, "flag"), Some(""));
        assert_eq!(query_param(&p, "k"), Some("v%2"));
    }

    /// D4 eees-acr-param: the spec custom op `POST /send-acrparamsinfo`
    /// (ACRParamsInfo) → 204 and merges the received tAsEndPoint/acrParams into
    /// the eecId-keyed ACR state. The reversed bespoke `/request-acr-params`
    /// query is gone (404) and the wrong-casing body 400s.
    #[test]
    fn test_acr_param_send_stores_state() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        // Spec body: the consumer PUSHES ACR parameters TO the EES → 204.
        let body = r#"{
            "requestorId":"eas-s.example.com",
            "eecId":"eec-param-1",
            "acId":"ac1",
            "sAsEndPoint":{"fqdn":"s-as.edge.example.com"},
            "tAsEndPoint":{"fqdn":"t-as.edge.example.com"},
            "acrParams":{"predictExpTime":"2030-01-01T00:00:00Z"}
        }"#;
        let req = SbiRequest::post("/eees-acr-param/v1/send-acrparamsinfo")
            .with_header("Authorization", bearer(&sk, "k1", "eees-acr-param"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 204);
        assert!(resp.http.content.as_deref().unwrap_or("").is_empty());

        // State assertion: acr_find(eecId) carries the received tAsEndPoint +
        // acrParams (keyed by eecId as the requestor identity).
        {
            let state = ees_self()
                .read()
                .unwrap()
                .acr_find(None, Some("eec-param-1"))
                .expect("ACR state populated by send-acrparamsinfo");
            assert_eq!(
                state.t_eas_endpoint.and_then(|e| e.fqdn).as_deref(),
                Some("t-as.edge.example.com")
            );
            assert_eq!(
                state.s_eas_endpoint.and_then(|e| e.fqdn).as_deref(),
                Some("s-as.edge.example.com")
            );
            assert_eq!(
                state
                    .acr_params
                    .and_then(|p| p.predict_exp_time)
                    .as_deref(),
                Some("2030-01-01T00:00:00Z")
            );
        }

        // The reversed bespoke /request-acr-params query is gone → 404.
        let req = SbiRequest::post("/eees-acr-param/v1/request-acr-params")
            .with_header("Authorization", bearer(&sk, "k1", "eees-acr-param"))
            .with_body(body, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 404);

        // Wrong casing sEasEndpoint/tEasEndpoint (not sAsEndPoint) → 400.
        let bad = r#"{
            "requestorId":"eas-s.example.com",
            "eecId":"eec-param-1",
            "acId":"ac1",
            "sEasEndpoint":{"fqdn":"s-as.edge.example.com"},
            "tEasEndpoint":{"fqdn":"t-as.edge.example.com"},
            "acrParams":{}
        }"#;
        let req = SbiRequest::post("/eees-acr-param/v1/send-acrparamsinfo")
            .with_header("Authorization", bearer(&sk, "k1", "eees-acr-param"))
            .with_body(bad, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 400);

        // No token → 401.
        auth::clear_auth_jwks();
        let req = SbiRequest::post("/eees-acr-param/v1/send-acrparamsinfo")
            .with_body(body, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 401);

        auth::clear_auth_jwks();
    }

    /// eesd-13: all new routes require OAuth2 (no token → 401).
    #[test]
    fn test_eesd13_routes_require_auth() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        auth::clear_auth_jwks();

        for path in [
            "/eees-cea/v1/declare",
            "/eees-appclientinformation/v1/subscriptions",
            "/eees-acrmgntevent/v1/subscriptions",
            "/eees-eeccontextreloc/v1/eec-contexts",
            "/eees-acr-param/v1/send-acrparamsinfo",
        ] {
            let req = SbiRequest::post(path);
            assert_eq!(
                block_on(ees_sbi_request_handler(req)).status,
                401,
                "expected 401 for {path}"
            );
        }
    }

    /// eesd-07: full EEC-triggered ACR flow through the router
    /// (Determine → Initiate → Declare) transitions state correctly.
    #[test]
    fn test_acr_full_eec_triggered_flow() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        register_eas(&sk, "flow-s.example.com", "VIDEO");
        register_eas(&sk, "flow-t.example.com", "VIDEO");

        // A single UE undergoes the relocation; all three ops key on its GPSI.
        let ue = "imsi-flow-1";

        // Step 1: Determine → 204 + DETERMINED.
        let det_body = r#"{
            "requestorId":"eec-flow",
            "sEasEndpoint":{"fqdn":"flow-s.example.com"},
            "ueId":"imsi-flow-1",
            "easId":"flow-s.example.com"
        }"#;
        let req = SbiRequest::post("/eees-appctxtreloc/v1/determine")
            .with_header("Authorization", bearer(&sk, "k1", "eees-appctxtreloc"))
            .with_body(det_body, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 204);
        {
            let state = ees_self()
                .read()
                .unwrap()
                .acr_find(Some(ue), Some("eec-flow"));
            assert_eq!(state.unwrap().status, Some(acr::AcrStatus::Determined));
        }

        // Step 2: Initiate → 204 + INITIATED.
        let init_body = r#"{
            "requestorId":"eec-flow",
            "tEasEndpoint":{"fqdn":"flow-t.example.com"},
            "easNotifInd":true,
            "ueId":"imsi-flow-1"
        }"#;
        let req = SbiRequest::post("/eees-appctxtreloc/v1/initiate")
            .with_header("Authorization", bearer(&sk, "k1", "eees-appctxtreloc"))
            .with_body(init_body, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 204);
        {
            let state = ees_self()
                .read()
                .unwrap()
                .acr_find(Some(ue), Some("eec-flow"));
            assert_eq!(state.unwrap().status, Some(acr::AcrStatus::Initiated));
        }

        // Step 3: Declare → 204 + COMPLETED.
        let decl_body = r#"{
            "ueId":"imsi-flow-1",
            "tEasId":"flow-t.example.com",
            "tEasEndpoint":{"fqdn":"flow-t.example.com"},
            "requestorId":"eec-flow"
        }"#;
        let req = SbiRequest::post("/eees-appctxtreloc/v1/declare")
            .with_header("Authorization", bearer(&sk, "k1", "eees-appctxtreloc"))
            .with_body(decl_body, "application/json");
        assert_eq!(block_on(ees_sbi_request_handler(req)).status, 204);
        {
            let state = ees_self()
                .read()
                .unwrap()
                .acr_find(Some(ue), Some("eec-flow"));
            assert_eq!(state.unwrap().status, Some(acr::AcrStatus::Completed));
        }

        auth::clear_auth_jwks();
    }
}
