//! NextGCore DCCF (Data Collection Co-ordination Function)
//!
//! The DCCF is a Rel-17 optional NF defined in 3GPP TS 23.288 §6.7.
//! It acts as a broker between data producers (AMF, SMF, PCF, etc.)
//! and analytics consumers (NWDAF, ADRF).  Core responsibilities:
//!
//! - Ndccf_DataManagement_Subscribe: consumer registers interest in
//!   network data events (UE location, NF load, QoS, etc.)
//! - Ndccf_DataManagement_Notify: forward collected data to consumers
//! - Ndccf_ContextDocument_Create: bind data subscription to analytics
//! - Routing: fan-out collected data to all matching subscribers

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::client::SbiClient;
use nextgcore_sbi::context::global_context;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{send_method_not_allowed, send_not_found, SbiServer, SbiServerConfig};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod context;

pub use context::*;

/// NextGCore DCCF - Data Collection Co-ordination Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-dccfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Data Collection Co-ordination Function (TS 23.288 §6.7)", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/dccf.yaml")]
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

    /// SBI bind address
    #[arg(long, default_value = "0.0.0.0")]
    sbi_addr: String,

    /// SBI port (TS 29.574 default: 7816)
    #[arg(long, default_value = "7816")]
    sbi_port: u16,

    /// Enable TLS for SBI
    #[arg(long)]
    tls: bool,

    /// TLS certificate path
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS key path
    #[arg(long)]
    tls_key: Option<String>,

    /// NRF URI for NF registration
    #[arg(long, default_value = "http://127.0.0.1:7777")]
    nrf_uri: String,

    /// Maximum concurrent data subscriptions
    #[arg(long, default_value = "4096")]
    max_subscriptions: usize,
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

/// DCCF SBI request handler (called by the SBI server per request).
async fn dccf_request_handler(req: SbiRequest) -> SbiResponse {
    let method = req.header.method.as_str();
    let uri = &req.header.uri;
    let path = uri.split('?').next().unwrap_or(uri);

    log::debug!("DCCF SBI: {method} {path}");

    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // ----------------------------------------------------------------
        // Health check
        // ----------------------------------------------------------------
        ["healthz"] => SbiResponse::ok().with_body(r#"{"status":"ok"}"#, "application/json"),

        // ----------------------------------------------------------------
        // Ndccf_DataManagement (TS 29.574 §5.2)
        // ----------------------------------------------------------------

        // POST /ndccf-datamanagement/v1/subscriptions
        ["ndccf-datamanagement", "v1", "subscriptions"] => match method {
            "POST" => {
                let sub_id = uuid::Uuid::new_v4().to_string();
                // Extract notifyUri from the request body if present (TS 29.574 §5.2)
                let notify_uri = req
                    .http
                    .content
                    .as_deref()
                    .and_then(|body| serde_json::from_str::<serde_json::Value>(body).ok())
                    .and_then(|v| {
                        v.get("notifyUri")
                            .and_then(|u| u.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_default();
                log::info!(
                    "[DCCF] DataManagement subscription created sub_id={sub_id} notify_uri={notify_uri}"
                );
                dccf_context_add_subscription_with_uri(sub_id.clone(), notify_uri);
                let body = format!(r#"{{"subscriptionId":"{sub_id}","status":"ACTIVE"}}"#);
                SbiResponse::created().with_body(body, "application/json")
            }
            _ => send_method_not_allowed(method, "subscriptions"),
        },

        // GET/DELETE /ndccf-datamanagement/v1/subscriptions/{subscriptionId}
        ["ndccf-datamanagement", "v1", "subscriptions", sub_id] => match method {
            "GET" => {
                if dccf_context_has_subscription(sub_id) {
                    let body = format!(r#"{{"subscriptionId":"{sub_id}","status":"ACTIVE"}}"#);
                    SbiResponse::ok().with_body(body, "application/json")
                } else {
                    send_not_found("subscription not found", None)
                }
            }
            "DELETE" => {
                if dccf_context_remove_subscription(sub_id) {
                    log::info!("[DCCF] DataManagement subscription deleted sub_id={sub_id}");
                    SbiResponse::no_content()
                } else {
                    send_not_found("subscription not found", None)
                }
            }
            _ => send_method_not_allowed(method, "subscriptions/{id}"),
        },

        // POST /ndccf-datamanagement/v1/notify — inbound data from producers
        ["ndccf-datamanagement", "v1", "notify"] => match method {
            "POST" => {
                let body = req.http.content.as_deref().unwrap_or("{}").to_string();
                log::debug!("[DCCF] DataManagement notify received len={}", body.len());
                // Get subscriber callback URIs (without holding the context lock)
                let targets = dccf_context_fanout_notify(&body);
                // Fan out: POST notification body to each subscriber's callback URI
                for (sub_id, notify_uri) in targets {
                    if let Some((host, port)) = parse_host_port(&notify_uri) {
                        let body_clone = body.clone();
                        let path = notify_uri
                            .trim_start_matches("https://")
                            .trim_start_matches("http://");
                        // Strip host:port prefix to get the path component
                        let path_only = path.find('/').map(|i| &path[i..]).unwrap_or("/");
                        let path_owned = path_only.to_string();
                        let client = SbiClient::with_host_port(&host, port);
                        tokio::spawn(async move {
                            match client
                                .post_json(&path_owned, &serde_json::json!({"data": body_clone}))
                                .await
                            {
                                Ok(resp) => log::debug!(
                                    "[DCCF] fanout POST {} -> status={}",
                                    sub_id,
                                    resp.status
                                ),
                                Err(e) => log::warn!("[DCCF] fanout POST {sub_id} failed: {e}"),
                            }
                        });
                    } else {
                        log::warn!(
                            "[DCCF] subscriber {sub_id} has unparseable notify_uri: {notify_uri}"
                        );
                    }
                }
                SbiResponse::no_content()
            }
            _ => send_method_not_allowed(method, "notify"),
        },

        // ----------------------------------------------------------------
        // Ndccf_ContextDocument (TS 29.574 §5.3)
        // ----------------------------------------------------------------

        // POST /ndccf-contextdocument/v1/contexts
        ["ndccf-contextdocument", "v1", "contexts"] => match method {
            "POST" => {
                let ctx_id = uuid::Uuid::new_v4().to_string();
                log::info!("[DCCF] ContextDocument context created ctx_id={ctx_id}");
                dccf_context_add_analytics_context(ctx_id.clone());
                let body = format!(r#"{{"contextId":"{ctx_id}"}}"#);
                SbiResponse::created().with_body(body, "application/json")
            }
            _ => send_method_not_allowed(method, "contexts"),
        },

        // GET/DELETE /ndccf-contextdocument/v1/contexts/{contextId}
        ["ndccf-contextdocument", "v1", "contexts", ctx_id] => match method {
            "GET" => {
                if dccf_context_has_analytics_context(ctx_id) {
                    let body = format!(r#"{{"contextId":"{ctx_id}"}}"#);
                    SbiResponse::ok().with_body(body, "application/json")
                } else {
                    send_not_found("context not found", None)
                }
            }
            "DELETE" => {
                dccf_context_remove_analytics_context(ctx_id);
                SbiResponse::no_content()
            }
            _ => send_method_not_allowed(method, "contexts/{id}"),
        },

        // ----------------------------------------------------------------
        // Fallthrough
        // ----------------------------------------------------------------
        _ => send_not_found("resource not found", None),
    }
}

// ---------------------------------------------------------------------------
// OAuth2 rollout (Wave-6 H8): opt-in producer verification + outbound consumer
// token install. Default OFF so the matched-sim E2E path is byte-unchanged;
// enabled per-NF via `NEXTGCORE_SBI_OAUTH2_REQUIRE=1` (overlay-friendly) or the
// `dccf.sbi.oauth2.require: true` yaml knob. TS 33.501 §13.4.1, TS 29.510 §5.4.2.
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
/// NRF JWKS and requires `aud` to include NfType::Dccf; with no NRF URI it
/// fails closed (503). `nrf_uri` empty ⇒ unconfigured ⇒ fail-closed.
fn apply_oauth2_enforcement(mut cfg: SbiServerConfig, nrf_uri: &str) -> SbiServerConfig {
    cfg.require_oauth2 = true;
    let uri = (!nrf_uri.is_empty()).then_some(nrf_uri);
    cfg.oauth2_jwks_uri =
        uri.map(|u| nextgcore_sbi::oauth::JwksCache::for_nrf(u).jwks_uri().to_string());
    cfg = cfg.with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Dccf);
    if let Some(u) = uri {
        let nf_instance_id = format!("dccf-{}", uuid::Uuid::new_v4());
        let _ = OAUTH2_CLIENT.set(Some(Arc::new(nextgcore_sbi::oauth::OAuth2Client::new(
            u,
            nf_instance_id,
            nextgcore_sbi::types::NfType::Dccf,
        ))));
    }
    log::info!(
        "OAuth2 enforcement enabled (JWKS: {})",
        cfg.oauth2_jwks_uri.as_deref().unwrap_or("UNCONFIGURED")
    );
    cfg
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

    log::info!("NextGCore DCCF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Data Collection Co-ordination Function (3GPP TS 23.288 §6.7)");

    dccf_context_init(args.max_subscriptions);

    let nf_instance_id = format!("dccf-{}", uuid::Uuid::new_v4());

    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    let bind_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI bind address")?;
    log::info!("DCCF SBI listening on {bind_addr}");

    let mut sbi_config = SbiServerConfig::new(bind_addr);
    if args.tls {
        if let (Some(cert), Some(key)) = (args.tls_cert, args.tls_key) {
            sbi_config = sbi_config.with_tls(key, cert);
        }
    }
    if oauth2_required(&args.config) {
        sbi_config = apply_oauth2_enforcement(sbi_config, &args.nrf_uri);
    }

    let sbi_server = SbiServer::new(sbi_config);
    sbi_server
        .start(dccf_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    // Register with NRF
    let sbi_ctx = global_context();
    sbi_ctx.set_nrf_uri(&args.nrf_uri).await;
    if let Err(e) = register_with_nrf(&args.sbi_addr, args.sbi_port, &nf_instance_id).await {
        log::warn!("NRF registration failed (will operate without NRF): {e}");
    } else {
        nextgcore_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id.clone(), 5);
    }

    log::info!("NextGCore DCCF ready (instance: {nf_instance_id})");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("DCCF shutting down");
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;

    dccf_context_final();
    log::info!("DCCF shutdown complete");
    Ok(())
}

/// Register DCCF with NRF
async fn register_with_nrf(
    sbi_addr: &str,
    sbi_port: u16,
    nf_instance_id: &str,
) -> Result<(), String> {
    let sbi_ctx = global_context();

    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => {
            log::debug!("No NRF URI configured, skipping NRF registration");
            return Ok(());
        }
    };

    log::info!("Registering DCCF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_profile = serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "DCCF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [{
            "serviceInstanceId": format!("{}-ndccf-datamanagement", nf_instance_id),
            "serviceName": "ndccf-datamanagement",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
        }],
        "allowedNfTypes": ["NWDAF", "AMF", "SMF", "PCF"],
        "heartBeatTimer": 10
    });

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    log::debug!("NRF registration: PUT {path}");

    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("DCCF registered with NRF successfully (id={nf_instance_id})");

            let mut self_instance = nextgcore_sbi::context::NfInstance::new(
                nf_instance_id,
                nextgcore_sbi::types::NfType::Dccf,
            );
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = nextgcore_sbi::context::NfService::new(
                "ndccf-datamanagement",
                nextgcore_sbi::types::SbiServiceType::NdccfDatamanagement,
            );
            svc.port = sbi_port;
            svc.ip_addresses = vec![sbi_addr.to_string()];
            self_instance.add_service(svc);
            sbi_ctx.set_self_instance(self_instance).await;

            Ok(())
        }
        _ => Err(format!(
            "NRF registration returned status {}",
            response.status
        )),
    }
}

/// Parse host and port from a URI string
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

#[cfg(test)]
mod oauth2_h8_tests {
    //! Wave-6 H8 (Phase B) strict-peer OAuth2 enforcement triplet: the real
    //! `dccf_request_handler` is mounted behind nextgcore-sbi's server-side
    //! OAuth2 verification (TS 33.501 §13.4.1). A missing or wrong-audience
    //! Bearer is rejected (401) before the handler runs; a valid NRF-audience
    //! token (aud=DCCF, ES256-signed against the served JWKS) passes through.
    use super::dccf_request_handler;
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
            "iss": "NRF", "sub": "dccf-1", "aud": aud,
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
        super::dccf_context_init(256);
        let port = free_port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Dccf);
        let server = SbiServer::new(cfg);
        server.start(dccf_request_handler).await.expect("server start");
        (server, port)
    }

    #[test]
    fn test_oauth2_require_knob_parses_and_defaults_off() {
        let dir = std::env::temp_dir();
        let off = dir.join(format!("dccf-h8-off-{}.yaml", std::process::id()));
        std::fs::write(&off, "dccf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n").unwrap();
        assert!(!super::oauth2_required(off.to_str().unwrap()));
        let on = dir.join(format!("dccf-h8-on-{}.yaml", std::process::id()));
        std::fs::write(&on, "dccf:\n  sbi:\n    oauth2:\n      require: true\n").unwrap();
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
            client.get("/ndccf-datamanagement/v1/subscriptions"),
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
        let token = build_es256_token(&sk, "nrf-es256", "AMF", "ndccf-datamanagement");
        let req = SbiRequest::get("/ndccf-datamanagement/v1/subscriptions")
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
        let token = build_es256_token(&sk, "nrf-es256", "DCCF", "ndccf-datamanagement");
        let req = SbiRequest::get("/ndccf-datamanagement/v1/subscriptions/does-not-exist")
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
