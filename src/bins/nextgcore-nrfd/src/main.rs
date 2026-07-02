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
    nrf_context_init, nrf_nnrf_nfm_send_nf_profile_changed_notify_all_async,
    nrf_nnrf_nfm_send_nf_status_notify_all_async, nrf_sbi_close, nrf_sbi_open, timer_manager,
    ChangeItem, DiscoveryQuery, NfProfile, NotificationEventType, NrfSmContext, PatchError,
    SbiServerConfig,
};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::oauth::{AccessTokenResponse, OAuth2Client};
use nextgcore_sbi::server::{
    send_bad_request, send_error, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as NextgcoreSbiServerConfig,
};
use nextgcore_sbi::types::NfType;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Typed YAML configuration structs for the SBI OAuth2 knob
// ---------------------------------------------------------------------------

/// SBI OAuth2 enforcement knob (`nrf.sbi.oauth2.require`).
///
/// Defaults to disabled. NOTE (TS 33.501 / TS 29.510): the NRF is itself the
/// OAuth2 Authorization Server — its `/nnrf-oauth2/v1/access-token` and
/// `/nnrf-oauth2/v1/jwks` endpoints must stay reachable WITHOUT a token (no NF
/// can obtain a token before calling the token endpoint). L1's SBI server
/// middleware has no per-path exemption, so blanket server-side enforcement is
/// NOT applied on the NRF; this knob drives the CLIENT-side token acquisition
/// for the NRF's own outbound calls (status notifications to consumers).
#[derive(Debug, Default, Deserialize)]
struct SbiOauth2Yaml {
    /// Client-side: the NRF attaches NRF-issued Bearer tokens on its own
    /// outbound calls (status notifications). Existing knob.
    require: Option<bool>,
    /// nrfd-06: server-side enforcement of OAuth2 on the NRF's own
    /// nnrf-nfm / nnrf-disc producer endpoints (the /nnrf-oauth2 token and
    /// /jwks endpoints stay exempt). Default OFF so the matched simulator —
    /// whose NFs may not all attach tokens yet — is never locked out.
    require_server: Option<bool>,
    /// nrfd-05: require the token endpoint to authenticate the requesting NF
    /// via a Client-Credentials-Assertion (CCA) bound to the body
    /// nfInstanceId. Default OFF (non-TLS dev / matched sim still function).
    ///
    /// I2 semantics extension: when this is ON, client authentication is
    /// satisfied by EITHER a bound CCA (existing path) OR a transport-
    /// authenticated mTLS client identity bound to the body `nfInstanceId`
    /// (see `require_client_cert_binding`). A request carrying NEITHER is
    /// rejected (`invalid_client`).
    require_client_auth: Option<bool>,
    /// I2 (TS 33.501 §13.3.1 / §13.4.1): mandate transport-layer (mTLS)
    /// authentication of the token requester. When ON, the token request MUST
    /// carry a mutually-authenticated TLS client identity whose NF Instance ID
    /// — carried in the certificate URI SubjectAltName (TS 33.310) and conveyed
    /// by the trusted TLS-terminating SBI ingress/SCP in the
    /// `x-forwarded-client-cert` header (Envoy XFCC; RFC 9440 trust model) —
    /// matches the request `nfInstanceId`. Default OFF so non-TLS dev, the
    /// matched simulator, and deployments where the NRF terminates TLS directly
    /// but does not yet surface the verified peer certificate all still
    /// function. The mismatch check itself always runs when an identity is
    /// present, independent of this flag (fail-closed on a forged binding).
    require_client_cert_binding: Option<bool>,
    /// I1 (TS 33.501 §13.3.8.3): cryptographically verify the CCA's ES256 JWS
    /// signature (not just the claim binding). Default OFF so the matched
    /// simulator — which today signs CCAs with a placeholder — is not locked
    /// out; the flip to `true` is a manual host gate, taken only once every NF
    /// signs its CCA with a real key registered under `cca_trusted_keys`.
    cca_verify_signature: Option<bool>,
    /// I1: the trusted per-NF ES256 public keys the NRF verifies CCA signatures
    /// against, keyed by the signing NF's `nfInstanceId`. Each entry carries an
    /// RFC 7517 EC/P-256 JWK. When signature verification is ON and an issuer
    /// has no trusted key here, its CCA is rejected (fail-closed).
    cca_trusted_keys: Option<Vec<CcaTrustedKeyYaml>>,
}

/// I1: one entry of the CCA trusted-key store. `jwk` is an RFC 7517 EC JWK
/// (`kty=EC, crv=P-256, x, y`) parsed by [`nextgcore_sbi::oauth::parse_es256_jwk`].
#[derive(Debug, Default, Deserialize)]
struct CcaTrustedKeyYaml {
    #[serde(rename = "nfInstanceId")]
    nf_instance_id: String,
    jwk: serde_json::Value,
}

#[derive(Debug, Default, Deserialize)]
struct SbiYaml {
    oauth2: Option<SbiOauth2Yaml>,
}

/// nrfd-10: discovery-time policy (SearchResult validityPeriod and the NRF's
/// own default / maximum page size). All optional; absent => conservative
/// defaults that never truncate the matched simulator's tiny registry.
#[derive(Debug, Default, Deserialize)]
struct DiscoveryYaml {
    validity_period: Option<u32>,
    default_page_size: Option<usize>,
    max_page_size: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct NrfSection {
    sbi: Option<SbiYaml>,
    /// nrfd-03: NRF-preconfigured heartbeat default (seconds) used when the NF
    /// proposes none or proposes an out-of-range value.
    #[serde(rename = "heartBeatTimer")]
    heart_beat_timer: Option<u32>,
    /// nrfd-03: accepted heartbeat negotiation bounds (seconds).
    #[serde(rename = "heartBeatTimerMin")]
    heart_beat_timer_min: Option<u32>,
    #[serde(rename = "heartBeatTimerMax")]
    heart_beat_timer_max: Option<u32>,
    discovery: Option<DiscoveryYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct NrfYaml {
    nrf: Option<NrfSection>,
}

// ---------------------------------------------------------------------------
// Runtime policy (nrfd-03 / -05 / -06 / -08 / -10)
// ---------------------------------------------------------------------------

/// NRF-preconfigured heartbeat default (TS 29.510 Table 6.1.6.2.2-1: the NRF
/// "may override" the proposed value "using a preconfigured value").
const NRF_HEARTBEAT_DEFAULT: u32 = 10;
/// Accepted heartbeat negotiation bounds. A proposal outside `[min,max]` is
/// overridden to the default.
const NRF_HEARTBEAT_MIN: u32 = 1;
const NRF_HEARTBEAT_MAX: u32 = 3600;
/// Discovery SearchResult `validityPeriod` default (seconds).
const NRF_DISC_VALIDITY_PERIOD: u32 = 3600;
/// Discovery default / maximum page size. Deliberately generous so default
/// config never truncates the matched simulator (≈1 producer per NF type).
const NRF_DISC_DEFAULT_PAGE_SIZE: usize = 100;
const NRF_DISC_MAX_PAGE_SIZE: usize = 1000;
/// Subscription validity default (seconds) when the consumer proposes none.
const NRF_SUBSCRIPTION_DEFAULT_VALIDITY: u64 = 86400;

/// Resolved runtime policy. Defaults preserve the legacy / matched-sim
/// behaviour exactly; YAML knobs only widen or tighten where explicitly set.
#[derive(Debug, Clone)]
struct NrfPolicy {
    hb_default: u32,
    hb_min: u32,
    hb_max: u32,
    disc_validity_period: u32,
    disc_default_page_size: usize,
    disc_max_page_size: usize,
    /// nrfd-06: enforce OAuth2 on own nnrf-nfm/nnrf-disc endpoints.
    require_oauth2_server: bool,
    /// nrfd-05: enforce CCA (or, per I2, mTLS) client authentication at the
    /// token endpoint.
    require_client_auth: bool,
    /// I2 (TS 33.501 §13.3.1/§13.4.1): mandate a transport-authenticated (mTLS)
    /// client identity bound to the request `nfInstanceId`.
    require_client_cert_binding: bool,
    /// I1 (TS 33.501 §13.3.8.3): cryptographically verify the CCA ES256 JWS
    /// signature (not just the claim binding). Default OFF.
    cca_verify_signature: bool,
    /// I1: `nfInstanceId` -> trusted ES256 verifying key used to check the CCA
    /// signature. Populated from `nrf.sbi.oauth2.cca_trusted_keys`.
    cca_trusted_keys: std::collections::HashMap<String, p256::ecdsa::VerifyingKey>,
}

impl Default for NrfPolicy {
    fn default() -> Self {
        Self {
            hb_default: NRF_HEARTBEAT_DEFAULT,
            hb_min: NRF_HEARTBEAT_MIN,
            hb_max: NRF_HEARTBEAT_MAX,
            disc_validity_period: NRF_DISC_VALIDITY_PERIOD,
            disc_default_page_size: NRF_DISC_DEFAULT_PAGE_SIZE,
            disc_max_page_size: NRF_DISC_MAX_PAGE_SIZE,
            require_oauth2_server: false,
            require_client_auth: false,
            require_client_cert_binding: false,
            cca_verify_signature: false,
            cca_trusted_keys: std::collections::HashMap::new(),
        }
    }
}

impl NrfPolicy {
    /// Fold parsed YAML over the defaults (only set knobs take effect).
    fn from_yaml(yaml: &NrfYaml) -> Self {
        let mut p = Self::default();
        let Some(nrf) = yaml.nrf.as_ref() else {
            return p;
        };
        if let Some(hb) = nrf.heart_beat_timer {
            p.hb_default = hb;
        }
        if let Some(min) = nrf.heart_beat_timer_min {
            p.hb_min = min;
        }
        if let Some(max) = nrf.heart_beat_timer_max {
            p.hb_max = max;
        }
        if let Some(d) = nrf.discovery.as_ref() {
            if let Some(v) = d.validity_period {
                p.disc_validity_period = v;
            }
            if let Some(v) = d.default_page_size.filter(|n| *n > 0) {
                p.disc_default_page_size = v;
            }
            if let Some(v) = d.max_page_size.filter(|n| *n > 0) {
                p.disc_max_page_size = v;
            }
        }
        if let Some(o) = nrf.sbi.as_ref().and_then(|s| s.oauth2.as_ref()) {
            p.require_oauth2_server = o.require_server.unwrap_or(false);
            p.require_client_auth = o.require_client_auth.unwrap_or(false);
            // I2 (TS 33.501 §13.3.1/§13.4.1): mTLS client-cert binding.
            p.require_client_cert_binding = o.require_client_cert_binding.unwrap_or(false);
            // I1 (TS 33.501 §13.3.8.3): CCA ES256 JWS signature verification.
            p.cca_verify_signature = o.cca_verify_signature.unwrap_or(false);
            if let Some(keys) = o.cca_trusted_keys.as_ref() {
                for entry in keys {
                    match nextgcore_sbi::oauth::parse_es256_jwk(&entry.jwk) {
                        Ok(key) => {
                            p.cca_trusted_keys.insert(entry.nf_instance_id.clone(), key);
                        }
                        // A malformed key is dropped (not fatal): the issuer
                        // then has no trusted key and its CCA is rejected at
                        // runtime when verification is ON — i.e. fail-closed.
                        Err(e) => log::warn!(
                            "nrfd-I1: ignoring malformed CCA trusted key for nfInstanceId {:?}: {e}",
                            entry.nf_instance_id
                        ),
                    }
                }
            }
        }
        p
    }

    /// I2: runtime overrides for the client-authentication knobs so the manual
    /// host-gate flip can be A/B-tested in docker WITHOUT a code edit (mirrors
    /// the H9 NAS-security canary runtime-knob pattern). Each env var forces the
    /// corresponding knob ON only; a knob already `true` (from yaml) is never
    /// turned back off here, and an absent/other env value leaves it unchanged —
    /// so the default-safe (OFF) matched-sim path is untouched unless a host
    /// operator explicitly opts in. `NRF_SBI_OAUTH2_REQUIRE_CLIENT_AUTH` and
    /// `NRF_SBI_OAUTH2_REQUIRE_CLIENT_CERT_BINDING` accept `1`/`true`.
    fn apply_env_overrides(&mut self) {
        let forced_on = |key: &str| {
            matches!(
                std::env::var(key).ok().as_deref().map(str::trim),
                Some("1") | Some("true") | Some("TRUE")
            )
        };
        if forced_on("NRF_SBI_OAUTH2_REQUIRE_CLIENT_AUTH") {
            self.require_client_auth = true;
        }
        if forced_on("NRF_SBI_OAUTH2_REQUIRE_CLIENT_CERT_BINDING") {
            self.require_client_cert_binding = true;
        }
    }
}

/// Process-wide resolved policy, set once at startup. Handlers read it via
/// [`nrf_policy`]; before initialisation (e.g. in unit tests) the safe
/// [`NrfPolicy::default`] applies.
static NRF_POLICY: OnceLock<NrfPolicy> = OnceLock::new();

fn nrf_policy() -> &'static NrfPolicy {
    NRF_POLICY.get_or_init(NrfPolicy::default)
}

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

    /// Path to the JSON snapshot file for registered NFProfiles and
    /// subscriptions. When unset (the default) the registry is purely
    /// in-memory and is lost on restart. Also settable via
    /// NEXTGCORE_NRF_STATE_FILE.
    #[arg(long)]
    state_file: Option<String>,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Active NfInstanceNoHeartbeat timer id per NF instance.
///
/// get_expired_events() fires every timer left in the manager, so a heartbeat
/// refresh must DELETE the superseded expiry timer — merely starting a new one
/// leaves the old timer armed and the NF gets suspended on schedule regardless
/// of heartbeats.
static HEARTBEAT_TIMERS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, u64>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// nrfd-03: negotiate the `heartBeatTimer` the NRF will enforce (TS 29.510
/// Table 6.1.6.2.2-1). The NRF reuses the consumer's proposal when it falls
/// within the accepted `[min,max]` bounds; otherwise (absent or out of range)
/// it overrides with the preconfigured default. Pure for unit testing.
fn negotiate_heartbeat(proposed: Option<u32>, default: u32, min: u32, max: u32) -> u32 {
    match proposed {
        Some(v) if v >= min && v <= max => v,
        _ => default,
    }
}

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
    let _otel = nextgcore_metrics::otel::init_otel(
        nextgcore_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
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

    // Initialise the NF registry, optionally restoring persisted profiles and
    // subscriptions. Path precedence: --state-file, then NEXTGCORE_NRF_STATE_FILE.
    // With neither set the registry stays purely in-memory (previous behaviour).
    let nrf_state_file = args
        .state_file
        .clone()
        .or_else(|| std::env::var("NEXTGCORE_NRF_STATE_FILE").ok())
        .filter(|s| !s.is_empty());
    match &nrf_state_file {
        Some(path) => {
            nextgcore_nrfd::init_nf_manager(Some(std::path::PathBuf::from(path)));
            log::info!("NRF registry persistence enabled: {path}");
        }
        None => {
            nextgcore_nrfd::init_nf_manager(None);
            log::info!("NRF registry persistence disabled (in-memory only)");
        }
    }

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

    // Parse configuration (if file exists) and pick up the SBI OAuth2 knob
    // (nrf.sbi.oauth2.require) plus the heartbeat / discovery / server-auth
    // policy (nrfd-03/-05/-06/-10). With no file (the matched-sim default) the
    // conservative `NrfPolicy::default` applies and nothing changes.
    let mut require_oauth2 = false;
    let mut policy = NrfPolicy::default();
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
                if let Ok(yaml) = serde_yaml::from_str::<NrfYaml>(&content) {
                    require_oauth2 = yaml
                        .nrf
                        .as_ref()
                        .and_then(|n| n.sbi.as_ref())
                        .and_then(|s| s.oauth2.as_ref())
                        .and_then(|o| o.require)
                        .unwrap_or(false);
                    policy = NrfPolicy::from_yaml(&yaml);
                }
            }
            Err(e) => {
                log::warn!("Failed to read configuration file: {e}");
            }
        }
    } else {
        log::debug!("Configuration file not found: {}", args.config);
    }
    // I2: apply the env-var runtime overrides (default-safe: forces ON only) so
    // the manual host-gate flip is A/B-testable in docker without a code edit.
    policy.apply_env_overrides();
    if policy.require_oauth2_server {
        log::warn!(
            "nrfd-06: server-side OAuth2 enforcement ENABLED on nnrf-nfm/nnrf-disc \
             (token + jwks endpoints stay exempt)"
        );
    }
    if policy.require_client_auth {
        log::warn!("nrfd-05: token-endpoint client authentication ENABLED (CCA or mTLS)");
    }
    if policy.require_client_cert_binding {
        log::warn!(
            "nrfd-I2: token-endpoint mTLS client-certificate binding REQUIRED \
             (x-forwarded-client-cert URI SAN must match nfInstanceId)"
        );
    }
    if policy.cca_verify_signature {
        log::warn!(
            "nrfd-I1: CCA ES256 JWS signature verification ENABLED ({} trusted key(s))",
            policy.cca_trusted_keys.len()
        );
    }
    NRF_POLICY.set(policy).ok();

    // Client side (T1.1): when SBI OAuth2 is enabled, the NRF acquires and
    // attaches NRF-issued tokens on its own outbound calls (status notify to
    // consumers). The NRF is the Authorization Server, so it points the token
    // client at itself (self_uri).
    //
    // Server side: NOT applied here. Enabling require_oauth2 on the NRF's SBI
    // server would gate the NRF's own /nnrf-oauth2/v1/access-token + /jwks
    // endpoints (L1's middleware has no per-path exemption), deadlocking token
    // issuance for the whole core. See SbiOauth2Yaml docs.
    if require_oauth2 {
        let oauth2 = Arc::new(OAuth2Client::new(
            nrf_self_uri().to_string(),
            nrf_instance_id().to_string(),
            NfType::Nrf,
        ));
        nextgcore_nrfd::sbi_path::set_oauth2_client(oauth2);
        log::info!(
            "SBI OAuth2 enabled: NRF will attach Bearer tokens on outbound \
             calls (issuer/self: {})",
            nrf_self_uri()
        );
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

    // Start actual HTTP/2 SBI server using nextgcore-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let mut sbi_server_config = NextgcoreSbiServerConfig::new(sbi_addr);

    // Wire TLS/mTLS configuration from CLI args into the nextgcore-sbi server
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

/// nrfd-06: which producer paths require a valid OAuth2 Bearer token when
/// server-side enforcement is on. The NRF is itself the Authorization Server,
/// so its `/nnrf-oauth2/*` token + `/jwks` endpoints (and health `/`) MUST stay
/// reachable without a token — only the `nnrf-nfm` and `nnrf-disc` producer
/// services are gated (TS 33.501 §13.4.1 / §13.3.1).
fn oauth2_protected_path(path: &str) -> bool {
    let p = path.trim_start_matches('/');
    p == "nnrf-nfm" || p == "nnrf-disc" || p.starts_with("nnrf-nfm/") || p.starts_with("nnrf-disc/")
}

/// nrfd-06: returns `Some(401)` when the request must be rejected for lacking a
/// valid NRF-issued Bearer token, or `None` when it may proceed. Pure over its
/// inputs (no globals) so the policy is unit-testable without flipping process
/// state. `require == false` (the default) always returns `None`, preserving
/// the matched-sim path; exempt paths (token/jwks/health) always return `None`.
fn enforce_oauth2_on_request(
    path: &str,
    auth_header: Option<&str>,
    require: bool,
    jwks: &serde_json::Value,
) -> Option<SbiResponse> {
    if !require || !oauth2_protected_path(path) {
        return None;
    }
    match nextgcore_sbi::oauth::authorize_bearer(auth_header, jwks) {
        Ok(_) => None,
        Err(e) => Some(send_error(
            401,
            "Unauthorized",
            &format!("OAuth2 access token required: {e}"),
            Some("UNAUTHORIZED"),
        )),
    }
}

/// SBI request handler for NRF
async fn nrf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("NRF SBI request: {method} {uri}");

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // nrfd-06: per-path server-side OAuth2 enforcement (default OFF). The token
    // and jwks endpoints stay exempt so the core can always obtain a token.
    if let Some(rejection) = enforce_oauth2_on_request(
        path,
        request.http.get_header("authorization").map(String::as_str),
        nrf_policy().require_oauth2_server,
        &nrf_jwks_json(),
    ) {
        return rejection;
    }

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
                &format!(
                    "Missing mandatory NFProfile attribute(s): {}",
                    missing.join(", ")
                ),
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

    // nrfd-03: negotiate the heartBeatTimer the NRF will enforce and stamp it
    // onto the stored AND returned profile (TS 29.510 Table 6.1.6.2.2-1: the
    // response carries the value the NRF will use, not the bare proposal).
    let policy = nrf_policy();
    let hb = negotiate_heartbeat(
        nf_profile.heartbeat_timer,
        policy.hb_default,
        policy.hb_min,
        policy.hb_max,
    );
    let mut nf_profile = nf_profile;
    nf_profile.set_heartbeat_timer(hb);

    let nf_type = nf_profile.nf_type.clone();
    let manager = nf_manager();
    // 201 Created on first registration, 200 OK on profile replacement
    // (TS 29.510 PUT response codes).
    let is_new = manager.get(nf_instance_id).is_none();

    match manager.register(nf_profile.clone()) {
        Ok(_) => {
            log::info!("NF {nf_instance_id} ({nf_type}) registered successfully");

            // Arm the no-heartbeat supervision timer from the negotiated value:
            // 2x the interval as tolerance before declaring a missed heartbeat.
            let expiry_secs = (hb as u64) * 2;
            arm_heartbeat_timer(nf_instance_id, Duration::from_secs(expiry_secs));
            log::info!(
                "Heartbeat timer started for NF {nf_instance_id} ({expiry_secs} seconds, 2x {hb}s interval)"
            );

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

/// Derive an RFC 6902-style `ChangeItem` list from a PATCH operation.
///
/// For JSON Patch (`is_json_patch = true`) the applied ops are translated
/// directly (skipping `test` ops which are guards, not changes).  For merge
/// patches the pre- and post-documents are diffed at the top level: each
/// key whose value changed becomes a `replace`, each new key becomes an
/// `add`, and each null-valued key (RFC 7396 delete) becomes a `remove`.
///
/// `pre` must be the stored profile document before the patch; `post` is the
/// document after a successful application.
pub fn compute_profile_changes(
    pre: &serde_json::Value,
    post: &serde_json::Value,
    patch: &serde_json::Value,
    is_json_patch: bool,
) -> Vec<ChangeItem> {
    if is_json_patch {
        let Some(items) = patch.as_array() else {
            return vec![];
        };
        items
            .iter()
            .filter_map(|item| {
                let op = item.get("op")?.as_str()?;
                if op == "test" {
                    return None; // guard op — not a profile change
                }
                let path = item.get("path")?.as_str()?.to_string();
                let value = item.get("value").cloned();
                // For replace/remove, capture the original value from pre-patch doc.
                let orig_value = if op == "replace" || op == "remove" {
                    pre.pointer(&path).cloned()
                } else {
                    None
                };
                Some(ChangeItem {
                    op: op.to_string(),
                    path,
                    value,
                    orig_value,
                })
            })
            .collect()
    } else {
        // Merge patch: diff pre vs post at the top level.
        let Some(patch_obj) = patch.as_object() else {
            return vec![];
        };
        patch_obj
            .iter()
            .map(|(key, patch_val)| {
                let path = format!("/{key}");
                if patch_val.is_null() {
                    // RFC 7396 null = remove
                    ChangeItem {
                        op: "remove".to_string(),
                        path,
                        value: None,
                        orig_value: pre.get(key).cloned(),
                    }
                } else if pre.get(key).is_some() {
                    ChangeItem {
                        op: "replace".to_string(),
                        path,
                        value: post.get(key).cloned(),
                        orig_value: pre.get(key).cloned(),
                    }
                } else {
                    ChangeItem {
                        op: "add".to_string(),
                        path,
                        value: post.get(key).cloned(),
                        orig_value: None,
                    }
                }
            })
            .collect()
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

    // Snapshot the pre-patch JSON — needed for diff / ChangeItem extraction
    // and to detect whether anything actually changed (nrfd-02).
    let pre_patch_doc = profile.to_json();

    // Apply the patch to a copy of the full stored document.
    let mut doc = pre_patch_doc.clone();
    let content_type = request
        .http
        .get_header("content-type")
        .cloned()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let is_json_patch = content_type.contains("json-patch+json") || patch.is_array();
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
    let mut updated = match NfProfile::from_json(&doc) {
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

    // nrfd-03: re-negotiate and stamp the heartBeatTimer the NRF will enforce
    // onto the stored/returned profile (PATCH also carries an update of it).
    let policy = nrf_policy();
    let hb = negotiate_heartbeat(
        updated.heartbeat_timer,
        policy.hb_default,
        policy.hb_min,
        policy.hb_max,
    );
    updated.set_heartbeat_timer(hb);

    if let Err(e) = manager.register(updated.clone()) {
        log::error!("Failed to store patched NF profile {nf_instance_id}: {e}");
        return send_error(500, "Internal Server Error", &e, Some("SYSTEM_FAILURE"));
    }

    // Refresh the no-heartbeat supervision timer on any PATCH (serves as a
    // heartbeat, TS 29.510 §5.2.2.3.2) from the negotiated heartBeatTimer.
    let expiry_secs = (hb as u64) * 2;
    arm_heartbeat_timer(nf_instance_id, Duration::from_secs(expiry_secs));
    log::debug!("Heartbeat timer refreshed for NF {nf_instance_id} ({expiry_secs}s)");

    // nrfd-02: Emit NF_PROFILE_CHANGED to matching subscribers when the
    // profile document changed materially (TS 29.510 §5.2.2.3 / §5.2.2.6).
    let profile_changed = pre_patch_doc != doc;
    if profile_changed {
        let profile_changes = compute_profile_changes(&pre_patch_doc, &doc, &patch, is_json_patch);
        let notify_profile = updated.clone();
        let server_uri = nrf_self_uri().to_string();
        tokio::spawn(async move {
            if let Err(e) = nrf_nnrf_nfm_send_nf_profile_changed_notify_all_async(
                &notify_profile,
                &server_uri,
                profile_changes,
            )
            .await
            {
                log::error!("Failed to send NF_PROFILE_CHANGED notifications: {e}");
            }
        });
    }

    // A heartbeat on a SUSPENDED NF restores it to REGISTERED (TS 29.510).
    // The status transition is always a material change — notify regardless
    // of whether other fields changed (nrfd-02 reactivate path).
    if manager.reactivate(nf_instance_id) {
        log::info!("NF {nf_instance_id} heartbeat received while SUSPENDED, back to REGISTERED");
        // Build the status-change ChangeItem from the reactivation.
        let reactivate_changes = vec![ChangeItem {
            op: "replace".to_string(),
            path: "/nfStatus".to_string(),
            value: Some(serde_json::json!("REGISTERED")),
            orig_value: Some(serde_json::json!("SUSPENDED")),
        }];
        // Re-fetch the now-REGISTERED profile so the body is accurate.
        let reactivated_profile = manager
            .get(nf_instance_id)
            .unwrap_or_else(|| updated.clone());
        let server_uri2 = nrf_self_uri().to_string();
        tokio::spawn(async move {
            if let Err(e) = nrf_nnrf_nfm_send_nf_profile_changed_notify_all_async(
                &reactivated_profile,
                &server_uri2,
                reactivate_changes,
            )
            .await
            {
                log::error!("Failed to send NF_PROFILE_CHANGED (reactivate) notifications: {e}");
            }
        });
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

    // Parse validity duration. The consumer MAY propose `validityTime`; the NRF
    // negotiates the validity it will enforce and returns it as an absolute
    // timestamp (below). Default = preconfigured 24h.
    let validity_duration = subscription
        .get("validityTime")
        .and_then(|v| v.as_u64())
        .unwrap_or(NRF_SUBSCRIPTION_DEFAULT_VALIDITY);

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

    // nrfd-08: the NRF-assigned validityTime is an absolute RFC 3339 timestamp
    // (now + the armed validity duration) so the body matches the armed timer,
    // not the consumer's (possibly absent) proposal.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let validity_time = epoch_to_rfc3339(now + validity_duration);

    // nrfd-08: return the full stored SubscriptionData (all fields), built
    // before the value is moved into the manager.
    let response_body = subscription_response_json(&subscription_data, &validity_time);

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
        .with_json_body(&response_body)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// nrfd-08: serialize a stored `SubscriptionData` to the SubscriptionData 201
/// response body (TS 29.510 §5.2.2.5 / Table 6.1.6.2.x), including the
/// NRF-assigned absolute `validityTime`.
fn subscription_response_json(
    sub: &nextgcore_nrfd::SubscriptionData,
    validity_time: &str,
) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "subscriptionId": sub.id,
        "nfStatusNotificationUri": sub.notification_uri,
        "validityTime": validity_time,
    });
    let map = obj.as_object_mut().expect("object");
    if let Some(ref t) = sub.req_nf_type {
        map.insert("reqNfType".to_string(), t.clone().into());
    }
    if let Some(ref id) = sub.req_nf_instance_id {
        map.insert("reqNfInstanceId".to_string(), id.clone().into());
    }
    if let Some(ref cond) = sub.subscr_cond {
        let mut c = serde_json::Map::new();
        if let Some(ref v) = cond.nf_type {
            c.insert("nfType".to_string(), v.clone().into());
        }
        if let Some(ref v) = cond.service_name {
            c.insert("serviceName".to_string(), v.clone().into());
        }
        if let Some(ref v) = cond.nf_instance_id {
            c.insert("nfInstanceId".to_string(), v.clone().into());
        }
        map.insert("subscrCond".to_string(), serde_json::Value::Object(c));
    }
    obj
}

/// nrfd-08: format epoch seconds (UTC) as an RFC 3339 `YYYY-MM-DDTHH:MM:SSZ`
/// timestamp without pulling in a date/time crate. Uses Howard Hinnant's
/// `civil_from_days` algorithm for the calendar conversion.
fn epoch_to_rfc3339(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil_from_days: days since 1970-01-01 -> (year, month, day).
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
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

    // nrfd-10: clamp the requested page size to the NRF default/maximum, and
    // page over the full match set in the handler (so discover_profiles still
    // returns everything matching). The generous defaults never truncate the
    // matched simulator's tiny registry.
    let policy = nrf_policy();
    let page_size = param("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(policy.disc_default_page_size)
        .clamp(1, policy.disc_max_page_size);
    let page = param("page")
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|p| *p >= 1)
        .unwrap_or(1);

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
        // Page in the handler; ask discover_profiles for the full match set.
        limit: None,
    };

    let all_matches = discover_profiles(&query);
    let total = all_matches.len();
    let (nf_instances, has_more) = paginate_results(all_matches, page, page_size);
    log::info!(
        "Found {} matching NF instances for type {} (page {page}, size {page_size}, returning {})",
        total,
        query.target_nf_type,
        nf_instances.len()
    );

    let mut result = serde_json::json!({
        "validityPeriod": policy.disc_validity_period,
        "nfInstances": nf_instances,
    });
    // nrfd-10: when results are truncated, surface a continuation link to the
    // next page (TS 29.510 Table 6.2.6.2.2 SearchResult `nfInstanceListUri`).
    if has_more {
        let next = page + 1;
        let uri = format!(
            "{}/nnrf-disc/v1/nf-instances?target-nf-type={}&requester-nf-type={}&limit={}&page={}",
            nrf_self_uri(),
            query.target_nf_type,
            query.requester_nf_type,
            page_size,
            next
        );
        if let Some(obj) = result.as_object_mut() {
            obj.insert("nfInstanceListUri".to_string(), serde_json::json!(uri));
        }
    }

    SbiResponse::with_status(200)
        .with_json_body(&result)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// nrfd-10: slice `items` to a 1-indexed `page` of `page_size`, returning the
/// page and whether more results exist beyond it. `page_size` is assumed ≥ 1.
fn paginate_results(
    items: Vec<serde_json::Value>,
    page: usize,
    page_size: usize,
) -> (Vec<serde_json::Value>, bool) {
    let len = items.len();
    let start = page.saturating_sub(1).saturating_mul(page_size);
    let end = start.saturating_add(page_size);
    let has_more = len > end;
    if start >= len {
        return (vec![], false);
    }
    (items[start..end.min(len)].to_vec(), has_more)
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

/// OAuth2 access-token authorization decision (TS 33.501 §13.4.1.1.2 step 2;
/// TS 29.510 §5.4.2.2.2). The NRF acts as the authorization server and must:
///   1. verify the asserted consumer `nfType` matches the registered consumer
///      profile (an identity/parameter mismatch is `invalid_request`); and
///   2. verify each requested service-name scope is offered by — and permitted
///      to the consumer by — at least one registered producer of the target NF
///      type (`allowedNfTypes` profile- and service-level filters, TS 29.510
///      §6.1.6.2; an empty/absent list is "no restriction").
///
/// Returns the granted scope subset, or an RFC 6749 §5.2 error
/// `(code, description)` carried in the 400 `AccessTokenErr`.
///
/// Conservative fallback: when the NRF holds NO profile for the target NF type
/// it cannot positively deny the request — TS 33.501 §13.4.1.1.2 NOTE 1 lets a
/// token without producer NSSAI/NSI claims access all producers of that type
/// per local policy — so the requested scope is granted as-is. The bypass this
/// closes is the prior behaviour of issuing a token to ANY caller for ANY
/// scope/target without checking the consumer or producer profiles.
/// Two S-NSSAIs match when sst is equal and sd is equal (an absent sd only
/// matches an absent sd, per TS 29.571 Snssai).
fn snssai_eq(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    a.get("sst").and_then(|v| v.as_u64()) == b.get("sst").and_then(|v| v.as_u64())
        && a.get("sd").and_then(|v| v.as_str()) == b.get("sd").and_then(|v| v.as_str())
}

/// Two PLMN-Ids match when mcc and mnc are both equal.
fn plmn_eq(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    a.get("mcc").and_then(|v| v.as_str()) == b.get("mcc").and_then(|v| v.as_str())
        && a.get("mnc").and_then(|v| v.as_str()) == b.get("mnc").and_then(|v| v.as_str())
}

/// nrfd-04: does this producer satisfy the requester's PLMN and S-NSSAI
/// restrictions (TS 29.510 Table 6.3.5.2.2-1 `requesterPlmnList` /
/// `requesterSnssaiList`)? When the requester gives a list and the producer
/// advertises that attribute, at least one must match; a producer that
/// advertises none of an attribute "serves any" and stays eligible (mirrors
/// the discovery filter semantics).
fn producer_eligible(
    producer: &NfProfile,
    requester_plmns: &[serde_json::Value],
    requester_snssais: &[serde_json::Value],
) -> bool {
    if !requester_plmns.is_empty() {
        let pp = producer.plmns();
        if !pp.is_empty()
            && !pp
                .iter()
                .any(|x| requester_plmns.iter().any(|q| plmn_eq(x, q)))
        {
            return false;
        }
    }
    if !requester_snssais.is_empty() {
        let ps = producer.snssais();
        if !ps.is_empty()
            && !ps
                .iter()
                .any(|x| requester_snssais.iter().any(|q| snssai_eq(x, q)))
        {
            return false;
        }
    }
    true
}

#[allow(clippy::too_many_arguments)]
fn authorize_access_token(
    consumer: &NfProfile,
    req_nf_type: &str,
    target_nf_type: &str,
    requested_scopes: &[String],
    producers: &[NfProfile],
    requester_plmns: &[serde_json::Value],
    requester_snssais: &[serde_json::Value],
) -> Result<Vec<String>, (&'static str, String)> {
    // (1) The asserted nfType must match the registered consumer profile.
    if !req_nf_type.eq_ignore_ascii_case(&consumer.nf_type) {
        return Err((
            "invalid_request",
            format!(
                "nfType {req_nf_type:?} does not match the registered profile of consumer {} (nfType {:?})",
                consumer.nf_instance_id, consumer.nf_type
            ),
        ));
    }

    // (2) No registered producer of the target type at all: conservative grant.
    if producers.is_empty() {
        log::warn!(
            "Access-token: no registered {target_nf_type} producer; granting requested scope to \
             consumer {} per local policy (TS 33.501 §13.4.1.1.2 NOTE 1)",
            consumer.nf_instance_id
        );
        return Ok(requested_scopes.to_vec());
    }

    // (nrfd-04) Restrict to producers serving the requester's PLMN/slice set.
    let eligible: Vec<&NfProfile> = producers
        .iter()
        .filter(|p| producer_eligible(p, requester_plmns, requester_snssais))
        .collect();

    // (3) Per requested service-name: must be offered by AND permitted to the
    //     consumer by at least one ELIGIBLE producer of the target type.
    let mut granted = Vec::new();
    let mut any_offered = false;
    for service in requested_scopes {
        let mut offered = false;
        let mut permitted = false;
        for p in &eligible {
            let (o, perm) = p.authorizes_service(&consumer.nf_type, service);
            offered |= o;
            permitted |= perm;
            if perm {
                break;
            }
        }
        any_offered |= offered;
        if permitted {
            granted.push(service.clone());
        }
    }

    if !granted.is_empty() {
        return Ok(granted);
    }

    // Nothing authorized: distinguish "an eligible producer offers the service
    // but the consumer type is barred" (unauthorized_client) from "no eligible
    // producer offers the requested service at all" — which also covers a
    // requester PLMN/S-NSSAI that no producer serves (invalid_scope).
    if any_offered {
        Err((
            "unauthorized_client",
            format!(
                "consumer nfType {:?} is not in allowedNfTypes of any {target_nf_type} producer \
                 offering the requested service(s)",
                consumer.nf_type
            ),
        ))
    } else {
        Err((
            "invalid_scope",
            format!(
                "no registered {target_nf_type} producer serving the requester's PLMN/slice offers \
                 the requested service(s) {requested_scopes:?}"
            ),
        ))
    }
}

/// nrfd-05 / CCA hardening: client-credentials-assertion (CCA) binding check
/// (TS 29.510 §6.7.5, TS 33.501 §13.3.8.3). Decodes the CCA JWT payload and
/// verifies its subject/issuer are the body `nfInstanceId`, that it has not
/// expired, that the `iat` timestamp is present and not in the future, and that
/// the `aud` claim matches the NRF's own NF type ("NRF").
///
/// This function performs the claim-binding plus the iat/aud validation mandated
/// of the NRF by §13.3.8.3. The CCA's ES256 JWS SIGNATURE is verified by the
/// companion [`verify_cca_signature`] (I1): the token handler calls it, when the
/// `cca_verify_signature` policy knob is ON, against the requesting NF's trusted
/// public key from the `cca_trusted_keys` store. Signature verification is
/// default-OFF and fail-closed (an issuer with no trusted key, or a bad
/// signature, is rejected). NF trusted-key distribution beyond this config-store
/// (e.g. an x5c cert chain or an mTLS client-cert subject surfaced on
/// `SbiRequest`) remains an additive `nextgcore-sbi` extension.
fn verify_cca_binding(
    cca_jwt: &str,
    expected_nf_instance_id: &str,
    now: u64,
) -> Result<(), (&'static str, String)> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let parts: Vec<&str> = cca_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err((
            "invalid_client",
            "Client Credentials Assertion is not a well-formed JWT".to_string(),
        ));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .ok_or_else(|| {
            (
                "invalid_client",
                "Client Credentials Assertion payload is not valid base64url JSON".to_string(),
            )
        })?;

    // `sub` (and, per TS 29.510 §6.7.5, the assertion is self-issued so `iss`
    // equals `sub`) must be the NF Instance ID asserted in the token request.
    let sub = payload.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    if sub != expected_nf_instance_id {
        return Err((
            "invalid_client",
            format!(
                "CCA subject {sub:?} does not match request nfInstanceId {expected_nf_instance_id:?}"
            ),
        ));
    }
    if let Some(iss) = payload.get("iss").and_then(|v| v.as_str()) {
        if iss != expected_nf_instance_id {
            return Err((
                "invalid_client",
                format!("CCA issuer {iss:?} does not match request nfInstanceId"),
            ));
        }
    }
    // Reject an expired assertion when it carries an `exp` (TS 29.510 §6.7.5).
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_u64()) {
        if exp <= now {
            return Err((
                "invalid_client",
                "Client Credentials Assertion has expired".to_string(),
            ));
        }
    }
    // TS 33.501 §13.3.8.3: the NRF validates the timestamp (iat). The CCA carries
    // it (§13.3.8.2); require its presence and reject a future-dated assertion,
    // allowing a small clock skew.
    const CCA_CLOCK_SKEW_SECS: u64 = 60;
    match payload.get("iat").and_then(|v| v.as_u64()) {
        Some(iat) if iat > now.saturating_add(CCA_CLOCK_SKEW_SECS) => {
            return Err((
                "invalid_client",
                "Client Credentials Assertion iat is in the future".to_string(),
            ));
        }
        Some(_) => {}
        None => {
            return Err((
                "invalid_client",
                "Client Credentials Assertion is missing the mandatory iat claim".to_string(),
            ));
        }
    }
    // TS 33.501 §13.3.8.3: the receiving NRF checks that the audience claim
    // matches its own NF type ("NRF"). `aud` is a JSON string or array of strings.
    let aud_matches_nrf = match payload.get("aud") {
        Some(serde_json::Value::String(s)) => s == "NRF",
        Some(serde_json::Value::Array(a)) => a.iter().any(|v| v.as_str() == Some("NRF")),
        _ => false,
    };
    if !aud_matches_nrf {
        return Err((
            "invalid_client",
            "Client Credentials Assertion audience does not match the NRF's NF type".to_string(),
        ));
    }
    Ok(())
}

/// I1 (TS 33.501 §13.3.8.3): cryptographically verify a CCA's ES256 JWS
/// signature against the requesting NF's trusted public `key`.
///
/// The JWS signing input is the ASCII `base64url(header) "." base64url(payload)`
/// (RFC 7515 §5.2); the JOSE header `alg` MUST be `ES256` — `none` and every
/// other algorithm are rejected so a forged unsigned/downgraded assertion cannot
/// pass (the classic JWS algorithm-substitution hole). ES256 signatures are the
/// fixed 64-byte `r||s` form (RFC 7518 §3.4). Returns `invalid_client` on any
/// failure so the caller emits a fail-closed AccessTokenErr.
fn verify_cca_signature(
    cca_jwt: &str,
    key: &p256::ecdsa::VerifyingKey,
) -> Result<(), (&'static str, String)> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::signature::Verifier;

    let parts: Vec<&str> = cca_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err((
            "invalid_client",
            "Client Credentials Assertion is not a well-formed JWT".to_string(),
        ));
    }
    // JOSE header: the algorithm MUST be ES256 (TS 33.501 §13.3.8.2).
    let header = URL_SAFE_NO_PAD
        .decode(parts[0])
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .ok_or((
            "invalid_client",
            "Client Credentials Assertion header is not valid base64url JSON".to_string(),
        ))?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
        return Err((
            "invalid_client",
            "Client Credentials Assertion alg is not ES256".to_string(),
        ));
    }
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| {
        (
            "invalid_client",
            "Client Credentials Assertion signature is not valid base64url".to_string(),
        )
    })?;
    let signature = p256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|_| {
        (
            "invalid_client",
            "Client Credentials Assertion has a malformed ES256 signature".to_string(),
        )
    })?;
    // Verify over the exact base64url header.payload as received (do NOT
    // re-encode the decoded parts — canonicalisation would change the bytes).
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    key.verify(signing_input.as_bytes(), &signature).map_err(|_| {
        (
            "invalid_client",
            "Client Credentials Assertion signature verification failed".to_string(),
        )
    })?;
    Ok(())
}

/// The HTTP header a trusted TLS-terminating SBI ingress / SCP uses to convey
/// the verified client certificate to the upstream NF (Envoy `x-forwarded-
/// client-cert`, the de-facto SBA service-mesh standard; same trust model as
/// RFC 9440 `Client-Cert`). It MUST be set only by the trusted terminator and
/// stripped from any client-supplied copy at the trust boundary.
const XFCC_HEADER: &str = "x-forwarded-client-cert";

/// Parse the URI SubjectAltName from the FIRST cert entry of an Envoy XFCC
/// header value. The header is a comma-separated list of cert entries (the leaf
/// / immediate peer first); each entry is a `;`-separated list of `Key=Value`
/// pairs whose value may be double-quoted (and a quoted value may itself
/// contain `,` or `;`). Splitting is quote-aware on purpose: a naive split
/// would let an attacker smuggle a fake `URI=` inside a quoted `Subject` DN.
/// Returns the (unquoted) `URI=` value of the leaf entry, or None when absent.
fn parse_xfcc_first_entry_uri(header: &str) -> Option<String> {
    // 1) Take the first cert entry (up to the first UNQUOTED comma).
    let mut in_quotes = false;
    let mut entry_end = header.len();
    for (i, c) in header.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                entry_end = i;
                break;
            }
            _ => {}
        }
    }
    let entry = &header[..entry_end];

    // 2) Split the entry into `Key=Value` pairs on UNQUOTED semicolons.
    let mut pairs: Vec<&str> = Vec::new();
    let mut start = 0usize;
    in_quotes = false;
    for (i, c) in entry.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ';' if !in_quotes => {
                pairs.push(&entry[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    pairs.push(&entry[start..]);

    // 3) Find the URI element (case-insensitive key) and unquote its value.
    for pair in pairs {
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim().eq_ignore_ascii_case("uri") {
                let v = v.trim();
                let v = v
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .unwrap_or(v);
                if v.is_empty() {
                    return None;
                }
                return Some(v.to_string());
            }
        }
    }
    None
}

/// I2 (TS 33.501 §13.3.1/§13.4.1, TS 33.310, TS 29.510 §6.1.6.2): extract the
/// transport-authenticated client NF Instance ID from the request. A 3GPP NF
/// certificate carries the NF Instance ID as a URI SubjectAltName (commonly the
/// URN `urn:uuid:<nfInstanceId>`); a trusted TLS-terminating SBI ingress/SCP
/// conveys that verified SAN to the NRF in the XFCC header. Returns the bare NF
/// Instance ID, or None when no transport identity is present.
///
/// NOTE: this consumes an identity a TRUSTED terminator already verified at the
/// TLS layer; it does not itself validate the certificate chain. When the NRF
/// terminates TLS directly (no SCP), surfacing the rustls-verified peer
/// certificate's SAN into this header (or onto `SbiRequest`) is an additive
/// `nextgcore-sbi` server-glue extension outside this component's boundary.
fn extract_transport_client_nf_instance_id(request: &SbiRequest) -> Option<String> {
    let xfcc = request.http.get_header(XFCC_HEADER)?;
    let uri = parse_xfcc_first_entry_uri(xfcc)?;
    // Strip the `urn:uuid:` scheme+NID (case-insensitive) when present; other
    // URI SAN forms bind on the exact value. `get(..9)` keeps the slice on a
    // char boundary (the value is attacker-influenced).
    let id = match uri.get(..9) {
        Some(prefix) if prefix.eq_ignore_ascii_case("urn:uuid:") => &uri[9..],
        _ => uri.as_str(),
    };
    let id = id.trim();
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

/// I2: verify the transport-authenticated (mTLS) client NF Instance ID is bound
/// to the token request's `nfInstanceId`. A mismatch is `invalid_client`
/// (TS 33.501 §13.4.1: the authenticated consumer identity must equal the NF
/// Instance ID asserted in the request). Combined with [`verify_cca_binding`]
/// (which binds `cca.sub == nfInstanceId`), this transitively binds the mTLS
/// certificate identity to the CCA — closing the "no mTLS/CCA binding" gap.
fn verify_transport_binding(
    cert_nf_instance_id: &str,
    expected_nf_instance_id: &str,
) -> Result<(), (&'static str, String)> {
    if cert_nf_instance_id != expected_nf_instance_id {
        return Err((
            "invalid_client",
            format!(
                "mTLS client-certificate NF Instance ID {cert_nf_instance_id:?} does not match \
                 request nfInstanceId {expected_nf_instance_id:?}"
            ),
        ));
    }
    Ok(())
}

/// I2: decide whether the token request satisfies the configured client-
/// authentication policy, given whether a (already-binding-validated) CCA and a
/// (already-binding-validated) mTLS transport identity are present.
///
/// - `require_client_auth` (nrfd-05 + I2): authentication is satisfied by a
///   bound CCA OR a bound mTLS identity; a request with NEITHER is rejected.
/// - `require_client_cert_binding` (I2): the request MUST additionally carry a
///   bound mTLS transport identity (mandate transport-layer authentication).
///
/// Both knobs default OFF (`NrfPolicy::default`), so with no config/env the
/// function always returns `Ok(())` and the matched-sim path is unchanged.
fn enforce_client_authentication(
    policy: &NrfPolicy,
    has_cca: bool,
    has_transport_identity: bool,
) -> Result<(), (&'static str, String)> {
    if policy.require_client_cert_binding && !has_transport_identity {
        return Err((
            "invalid_client",
            "mTLS client-certificate authentication required \
             (nrf.sbi.oauth2.require_client_cert_binding)"
                .to_string(),
        ));
    }
    if policy.require_client_auth && !has_cca && !has_transport_identity {
        return Err((
            "invalid_client",
            "client authentication required: present a Client Credentials Assertion or an \
             mTLS client certificate (nrf.sbi.oauth2.require_client_auth)"
                .to_string(),
        ));
    }
    Ok(())
}

/// nrfd-07: build the AccessTokenClaims (TS 29.510 §6.3.5.2.4). When the grant
/// resolved a specific producer instance, `aud` becomes that instance-ID array
/// and the optional producer claims (`producerPlmnId`, `producerSnssaiList`,
/// `producerNfSetId`) are populated from its profile; otherwise `aud` is the
/// bare target NF type string. `consumerPlmnId` is taken from the consumer
/// profile when present.
#[allow(clippy::too_many_arguments)]
fn build_access_token_claims(
    iss: &str,
    sub: &str,
    target_nf_type: &str,
    target_instance: Option<&NfProfile>,
    consumer: &NfProfile,
    scope: &str,
    iat: u64,
    exp: u64,
) -> serde_json::Value {
    let aud = match target_instance {
        Some(p) => serde_json::json!([p.nf_instance_id]),
        None => serde_json::Value::String(target_nf_type.to_string()),
    };
    let mut claims = serde_json::json!({
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "scope": scope,
        "exp": exp,
        "iat": iat,
    });
    let obj = claims.as_object_mut().expect("claims is an object");

    if let Some(plmn) = consumer.plmns().into_iter().next() {
        obj.insert("consumerPlmnId".to_string(), plmn);
    }
    if let Some(p) = target_instance {
        if let Some(plmn) = p.plmns().into_iter().next() {
            obj.insert("producerPlmnId".to_string(), plmn);
        }
        let snssais = p.snssais();
        if !snssais.is_empty() {
            obj.insert(
                "producerSnssaiList".to_string(),
                serde_json::Value::Array(snssais),
            );
        }
        if let Some(set_id) = p.attributes.get("nfSetIdList").cloned() {
            obj.insert("producerNsiList".to_string(), set_id);
        }
        if let Some(set_id) = p.attributes.get("nfSetId").cloned() {
            obj.insert("producerNfSetId".to_string(), set_id);
        }
    }
    claims
}

/// nrfd-04/-05/-09: parsed Nnrf_AccessToken request (TS 29.510
/// Table 6.3.5.2.2-1). `nfType`/`targetNfType` are Conditional; the conditional
/// `targetNfInstanceId` is an alternative target selector and the optional
/// `requesterPlmnList`/`requesterSnssaiList` and `cca` are surfaced for the
/// authorization and client-authentication decisions.
#[derive(Debug, Default)]
struct TokenRequestParams {
    grant_type: String,
    nf_instance_id: String,
    nf_type: String,
    target_nf_type: String,
    target_nf_instance_id: String,
    scope: String,
    requester_plmns: Vec<serde_json::Value>,
    requester_snssais: Vec<serde_json::Value>,
    cca: String,
}

/// Parses an Nnrf_AccessToken request body from JSON or, failing that,
/// `application/x-www-form-urlencoded`. nrfd-09: every form key AND value is
/// percent-decoded (and `+` treated as space) so an encoded `nfInstanceId`
/// (e.g. a URN with `%3A`) round-trips correctly. Array-valued form fields
/// carry JSON in the value.
fn parse_token_request(body: &str) -> TokenRequestParams {
    let json_array = |v: Option<&serde_json::Value>| -> Vec<serde_json::Value> {
        v.and_then(|v| v.as_array()).cloned().unwrap_or_default()
    };
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) {
        let s = |k: &str| {
            parsed
                .get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        TokenRequestParams {
            grant_type: s("grant_type"),
            nf_instance_id: s("nfInstanceId"),
            nf_type: s("nfType"),
            target_nf_type: s("targetNfType"),
            target_nf_instance_id: s("targetNfInstanceId"),
            scope: s("scope"),
            requester_plmns: json_array(parsed.get("requesterPlmnList")),
            requester_snssais: json_array(parsed.get("requesterSnssaiList")),
            cca: s("cca"),
        }
    } else {
        let mut p = TokenRequestParams::default();
        // Array values are JSON; decode then parse.
        let parse_json_array = |raw: &str| -> Vec<serde_json::Value> {
            serde_json::from_str::<serde_json::Value>(raw)
                .ok()
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default()
        };
        for pair in body.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                // nrfd-09: percent-decode key AND value (+ => space).
                let key = percent_decode(key);
                let value = percent_decode(value);
                match key.as_str() {
                    "grant_type" => p.grant_type = value,
                    "nfInstanceId" => p.nf_instance_id = value,
                    "nfType" => p.nf_type = value,
                    "targetNfType" => p.target_nf_type = value,
                    "targetNfInstanceId" => p.target_nf_instance_id = value,
                    "scope" => p.scope = value,
                    "requesterPlmnList" => p.requester_plmns = parse_json_array(&value),
                    "requesterSnssaiList" => p.requester_snssais = parse_json_array(&value),
                    "cca" => p.cca = value,
                    _ => {}
                }
            }
        }
        p
    }
}

async fn handle_access_token_request(request: &SbiRequest) -> SbiResponse {
    log::info!("OAuth2 Access Token Request");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    // nrfd-04/-09: parse JSON or percent-decoded form, including the
    // conditional targetNfInstanceId and optional requester PLMN/S-NSSAI lists.
    let req = parse_token_request(body);
    let nf_instance_id = req.nf_instance_id;
    let nf_type = req.nf_type;
    let mut target_nf_type = req.target_nf_type;
    let target_nf_instance_id = req.target_nf_instance_id;

    // RFC 6749 §5.2 error responses, carried as TS 29.510 AccessTokenErr.
    if req.grant_type != "client_credentials" {
        return token_error(
            "unsupported_grant_type",
            &format!(
                "Unsupported grant_type: {:?} (expected client_credentials)",
                req.grant_type
            ),
        );
    }

    if nf_instance_id.is_empty() {
        return token_error("invalid_request", "Missing nfInstanceId");
    }
    if nf_type.is_empty() {
        return token_error("invalid_request", "Missing nfType");
    }
    // nrfd-04: targetNfType is Conditional — accept targetNfInstanceId as an
    // alternative target selector; require at least one of the two.
    if target_nf_type.is_empty() && target_nf_instance_id.is_empty() {
        return token_error(
            "invalid_request",
            "Missing target selector (one of targetNfType or targetNfInstanceId required)",
        );
    }
    if req.scope.is_empty() {
        return token_error("invalid_scope", "Missing scope");
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("value expected")
        .as_secs();

    let policy = nrf_policy();

    // I2 (TS 33.501 §13.3.1/§13.4.1): extract the transport-authenticated (mTLS)
    // client NF Instance ID conveyed by the trusted TLS terminator, and — when
    // one is present — ALWAYS verify it is bound to the request nfInstanceId.
    // The mismatch rejection is unconditional (like the CCA binding below): a
    // forged transport identity is refused regardless of the policy flags.
    let transport_nf_id = extract_transport_client_nf_instance_id(request);
    if let Some(ref cert_id) = transport_nf_id {
        if let Err((code, desc)) = verify_transport_binding(cert_id, &nf_instance_id) {
            return token_error(code, &desc);
        }
    }

    // nrfd-05 + I2: enforce the client-authentication policy. Authentication is
    // satisfied by a bound CCA OR a bound mTLS transport identity; the
    // require_client_cert_binding knob additionally mandates the mTLS identity.
    // Both knobs default OFF so the matched-sim path is unchanged.
    if let Err((code, desc)) =
        enforce_client_authentication(policy, !req.cca.is_empty(), transport_nf_id.is_some())
    {
        return token_error(code, &desc);
    }

    // A present CCA is always validated for binding (TS 29.510 §6.7.5).
    if !req.cca.is_empty() {
        if let Err((code, desc)) = verify_cca_binding(&req.cca, &nf_instance_id, now) {
            return token_error(code, &desc);
        }
        // I1 (TS 33.501 §13.3.8.3): cryptographically verify the CCA's ES256
        // JWS signature against the requesting NF's trusted public key. This is
        // fail-closed and default-OFF (cca_verify_signature): when enabled, an
        // issuer with no configured trusted key is rejected, so a forged CCA —
        // which today passes the claim-binding checks with any placeholder
        // signature — can no longer be accepted.
        if policy.cca_verify_signature {
            match policy.cca_trusted_keys.get(&nf_instance_id) {
                Some(key) => {
                    if let Err((code, desc)) = verify_cca_signature(&req.cca, key) {
                        return token_error(code, &desc);
                    }
                }
                None => {
                    return token_error(
                        "invalid_client",
                        &format!(
                            "no trusted ES256 key configured to verify the CCA signature of \
                             nfInstanceId {nf_instance_id:?}"
                        ),
                    );
                }
            }
        }
    }

    // Verify that the requesting NF is registered: an unknown client is an
    // invalid_client error (RFC 6749 §5.2; TS 29.510 carries it in a 400
    // AccessTokenErr rather than a bare 401).
    let manager = nf_manager();
    let Some(consumer) = manager.get(&nf_instance_id) else {
        return token_error(
            "invalid_client",
            &format!("NF instance {nf_instance_id} is not registered with this NRF"),
        );
    };

    // nrfd-04/-07: resolve the producer set. With targetNfInstanceId, pin the
    // single producer instance and derive its nfType (filling an absent
    // targetNfType); otherwise take all registered producers of the type.
    let all = manager.list();
    let target_instance: Option<NfProfile> = if !target_nf_instance_id.is_empty() {
        let inst = all
            .iter()
            .find(|p| p.nf_instance_id == target_nf_instance_id)
            .cloned();
        if let Some(ref p) = inst {
            if target_nf_type.is_empty() {
                target_nf_type = p.nf_type.clone();
            }
        }
        inst
    } else {
        None
    };
    let producers: Vec<NfProfile> = match target_instance {
        Some(ref p) => vec![p.clone()],
        None => all
            .into_iter()
            .filter(|p| p.nf_type.eq_ignore_ascii_case(&target_nf_type))
            .collect(),
    };

    // Authorization decision (TS 33.501 §13.4.1.1.2 step 2; TS 29.510
    // §5.4.2.2.2): the NRF must verify the consumer profile and that the
    // requested scope is permitted by the target producer set BEFORE minting a
    // token. Without this, the endpoint is an OAuth2 authorization bypass.
    let requested_scopes: Vec<String> = req.scope.split_whitespace().map(String::from).collect();
    let granted_scopes = match authorize_access_token(
        &consumer,
        &nf_type,
        &target_nf_type,
        &requested_scopes,
        &producers,
        &req.requester_plmns,
        &req.requester_snssais,
    ) {
        Ok(granted) => granted,
        Err((code, desc)) => return token_error(code, &desc),
    };
    let scope = granted_scopes.join(" ");

    // Issue a JWT access token signed with ES256 (ECDSA P-256).
    let expires_in = 3600u64; // 1 hour

    let header_json = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{NRF_KID}"}}"#);
    // nrfd-07: `iss` is the NRF NF Instance ID (TS 29.510 §6.3.5.2.4); when a
    // producer instance was pinned, `aud` is its instance-ID array and the
    // optional producer/consumer claims are populated.
    let claims_json = build_access_token_claims(
        nrf_instance_id(),
        &nf_instance_id,
        &target_nf_type,
        target_instance.as_ref(),
        &consumer,
        &scope,
        now,
        now + expires_in,
    );
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

    // -----------------------------------------------------------------
    // nrfd-01: access-token authorization decision (TS 33.501
    // §13.4.1.1.2 step 2 / TS 29.510 §5.4.2.2.2). These exercise the pure
    // decision function in isolation (no global manager / no server), so
    // they are deterministic and parallel-safe.
    // -----------------------------------------------------------------

    /// A consumer NF profile of the given type.
    fn auth_consumer(nf_type: &str) -> NfProfile {
        NfProfile::from_json(&serde_json::json!({
            "nfInstanceId": "11111111-1111-1111-1111-111111111111",
            "nfType": nf_type,
            "nfStatus": "REGISTERED",
        }))
        .expect("valid consumer profile")
    }

    /// A producer NF profile advertising `services`, with an optional
    /// profile-level `allowedNfTypes`.
    fn auth_producer(
        nf_type: &str,
        services: serde_json::Value,
        allowed: Option<serde_json::Value>,
    ) -> NfProfile {
        let mut doc = serde_json::json!({
            "nfInstanceId": format!("prod-{nf_type}"),
            "nfType": nf_type,
            "nfStatus": "REGISTERED",
            "nfServices": services,
        });
        if let Some(a) = allowed {
            doc.as_object_mut()
                .unwrap()
                .insert("allowedNfTypes".into(), a);
        }
        NfProfile::from_json(&doc).expect("valid producer profile")
    }

    #[test]
    fn test_authorize_token_happy_path_permitted_scope() {
        // Valid registered consumer + a producer that offers the service and
        // permits the consumer type -> token (granted scope == requested).
        let consumer = auth_consumer("SMF");
        let udm = auth_producer(
            "UDM",
            serde_json::json!([{"serviceInstanceId": "s0", "serviceName": "nudm-sdm"}]),
            Some(serde_json::json!(["SMF", "AMF"])),
        );
        let granted = authorize_access_token(
            &consumer,
            "SMF",
            "UDM",
            &["nudm-sdm".into()],
            &[udm],
            &[],
            &[],
        )
        .expect("permitted scope must be granted");
        assert_eq!(granted, vec!["nudm-sdm".to_string()]);
    }

    #[test]
    fn test_authorize_token_unoffered_service_is_invalid_scope() {
        // The only producer offers a different service -> invalid_scope, no token.
        let consumer = auth_consumer("SMF");
        let udm = auth_producer(
            "UDM",
            serde_json::json!([{"serviceInstanceId": "s0", "serviceName": "nudm-uecm"}]),
            None,
        );
        let err = authorize_access_token(
            &consumer,
            "SMF",
            "UDM",
            &["nudm-sdm".into()],
            &[udm],
            &[],
            &[],
        )
        .expect_err("unoffered service must be rejected");
        assert_eq!(err.0, "invalid_scope");
    }

    #[test]
    fn test_authorize_token_consumer_type_barred_is_unauthorized_client() {
        // Producer offers the service but restricts it to AMF -> the SMF
        // consumer is unauthorized_client, no token.
        let consumer = auth_consumer("SMF");
        let udm = auth_producer(
            "UDM",
            serde_json::json!([{"serviceInstanceId": "s0", "serviceName": "nudm-sdm"}]),
            Some(serde_json::json!(["AMF"])),
        );
        let err = authorize_access_token(
            &consumer,
            "SMF",
            "UDM",
            &["nudm-sdm".into()],
            &[udm],
            &[],
            &[],
        )
        .expect_err("barred consumer type must be rejected");
        assert_eq!(err.0, "unauthorized_client");
    }

    #[test]
    fn test_authorize_token_nftype_mismatch_is_invalid_request() {
        // Asserted nfType differs from the registered consumer profile.
        let consumer = auth_consumer("SMF");
        let err = authorize_access_token(
            &consumer,
            "AUSF",
            "UDM",
            &["nudm-sdm".into()],
            &[],
            &[],
            &[],
        )
        .expect_err("nfType mismatch must be rejected");
        assert_eq!(err.0, "invalid_request");
    }

    #[test]
    fn test_authorize_token_no_producer_grants_conservatively() {
        // Matched-sim path: a token requested before the producer registers
        // must still be granted so legitimate flows keep working
        // (TS 33.501 §13.4.1.1.2 NOTE 1).
        let consumer = auth_consumer("SMF");
        let granted =
            authorize_access_token(&consumer, "SMF", "UDM", &["nudm-sdm".into()], &[], &[], &[])
                .expect("conservative grant when no producer is registered");
        assert_eq!(granted, vec!["nudm-sdm".to_string()]);
    }

    #[test]
    fn test_authorize_token_grants_only_permitted_subset() {
        // Two requested services; one is barred at the per-service level.
        let consumer = auth_consumer("SMF");
        let udm = auth_producer(
            "UDM",
            serde_json::json!([
                {"serviceInstanceId": "s0", "serviceName": "nudm-sdm"},
                {"serviceInstanceId": "s1", "serviceName": "nudm-uecm",
                 "allowedNfTypes": ["AMF"]}
            ]),
            Some(serde_json::json!(["SMF", "AMF"])),
        );
        let granted = authorize_access_token(
            &consumer,
            "SMF",
            "UDM",
            &["nudm-sdm".into(), "nudm-uecm".into()],
            &[udm],
            &[],
            &[],
        )
        .expect("at least one service is permitted");
        assert_eq!(granted, vec!["nudm-sdm".to_string()]);
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

        let server = SbiServer::new(NextgcoreSbiServerConfig::new(addr));
        server
            .start(nrf_sbi_request_handler)
            .await
            .expect("SBI server starts");

        let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", addr.port());
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
            assert!(
                instances.iter().any(|p| p["nfInstanceId"] == nf_id),
                "registered SMF must be discoverable: {result}"
            );

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
            let resp = client
                .send_request(req)
                .await
                .expect("PATCH remove mandatory");
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

    // -----------------------------------------------------------------
    // SBI OAuth2 knob (T1.1): config parsing + the NRF-as-issuer rule
    // -----------------------------------------------------------------

    #[test]
    fn test_yaml_oauth2_require_parses() {
        let yaml = "nrf:\n  sbi:\n    oauth2:\n      require: true\n";
        let parsed: NrfYaml = serde_yaml::from_str(yaml).unwrap();
        let require = parsed
            .nrf
            .and_then(|n| n.sbi)
            .and_then(|s| s.oauth2)
            .and_then(|o| o.require)
            .unwrap_or(false);
        assert!(require, "oauth2.require should parse to true");
    }

    #[test]
    fn test_yaml_oauth2_absent_defaults_off() {
        // Default config (no oauth2 block) leaves the knob off, preserving the
        // dev/E2E path and the unauthenticated token/jwks endpoints.
        let yaml = "nrf:\n  sbi:\n    server:\n      - address: 0.0.0.0\n        port: 7777\n";
        let parsed: NrfYaml = serde_yaml::from_str(yaml).unwrap();
        let require = parsed
            .nrf
            .and_then(|n| n.sbi)
            .and_then(|s| s.oauth2)
            .and_then(|o| o.require)
            .unwrap_or(false);
        assert!(!require, "absent oauth2 block must default to off");
    }

    /// The NRF is the OAuth2 Authorization Server: its token endpoint must be
    /// reachable WITHOUT a bearer token. We never blanket-enable
    /// require_oauth2 on the NRF's own SBI server (no per-path exemption
    /// exists), so the token endpoint stays open even with the knob on. This
    /// guards that the default server config has require_oauth2 off.
    #[test]
    fn test_nrf_server_never_blanket_requires_oauth2() {
        let cfg = NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], 7777)));
        assert!(
            !cfg.require_oauth2,
            "the NRF server must not gate its own token/jwks endpoints"
        );
    }

    // -----------------------------------------------------------------
    // nrfd-02: NF_PROFILE_CHANGED on NFUpdate (TS 29.510 §5.2.2.3/§5.2.2.6)
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_02_compute_changes_from_json_patch_replace() {
        use serde_json::json;
        let pre =
            json!({"nfInstanceId": "a", "nfType": "SMF", "nfStatus": "REGISTERED", "load": 40});
        let patch = json!([
            {"op": "test",    "path": "/nfStatus", "value": "REGISTERED"},
            {"op": "replace", "path": "/load",     "value": 75}
        ]);
        let mut post = pre.clone();
        apply_json_patch(&mut post, &patch).unwrap();

        let changes = compute_profile_changes(&pre, &post, &patch, true);
        // "test" op must be filtered out — only the replace survives.
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].op, "replace");
        assert_eq!(changes[0].path, "/load");
        assert_eq!(changes[0].value, Some(json!(75)));
        assert_eq!(changes[0].orig_value, Some(json!(40)));
    }

    #[test]
    fn test_nrfd_02_compute_changes_from_json_patch_add() {
        use serde_json::json;
        let pre = json!({"nfInstanceId": "a", "nfType": "SMF", "nfStatus": "REGISTERED"});
        let patch = json!([{"op": "add", "path": "/load", "value": 12}]);
        let mut post = pre.clone();
        apply_json_patch(&mut post, &patch).unwrap();

        let changes = compute_profile_changes(&pre, &post, &patch, true);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].op, "add");
        assert_eq!(changes[0].path, "/load");
        assert_eq!(changes[0].value, Some(json!(12)));
        assert!(changes[0].orig_value.is_none());
    }

    #[test]
    fn test_nrfd_02_compute_changes_from_merge_patch_replace_and_add() {
        use serde_json::json;
        let pre =
            json!({"nfInstanceId": "a", "nfType": "SMF", "nfStatus": "REGISTERED", "load": 40});
        let patch = json!({"load": 70, "priority": 3});
        let mut post = pre.clone();
        json_merge_patch(&mut post, &patch);

        let mut changes = compute_profile_changes(&pre, &post, &patch, false);
        // Sort for determinism
        changes.sort_by(|a, b| a.path.cmp(&b.path));

        assert_eq!(changes.len(), 2);
        let load = changes.iter().find(|c| c.path == "/load").unwrap();
        assert_eq!(load.op, "replace");
        assert_eq!(load.value, Some(json!(70)));
        assert_eq!(load.orig_value, Some(json!(40)));

        let prio = changes.iter().find(|c| c.path == "/priority").unwrap();
        assert_eq!(prio.op, "add");
        assert_eq!(prio.value, Some(json!(3)));
        assert!(prio.orig_value.is_none());
    }

    #[test]
    fn test_nrfd_02_compute_changes_from_merge_patch_null_is_remove() {
        use serde_json::json;
        let pre = json!({"nfInstanceId": "a", "nfType": "SMF", "nfStatus": "REGISTERED", "fqdn": "smf.example.com"});
        let patch = json!({"fqdn": null});
        let mut post = pre.clone();
        json_merge_patch(&mut post, &patch);

        let changes = compute_profile_changes(&pre, &post, &patch, false);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].op, "remove");
        assert_eq!(changes[0].path, "/fqdn");
        assert_eq!(changes[0].orig_value, Some(json!("smf.example.com")));
        assert!(changes[0].value.is_none());
    }

    /// Register an NF + a matching subscriber, apply a load PATCH via the
    /// sync notify path, and assert that NF_PROFILE_CHANGED with the correct
    /// `profileChanges` payload is dispatched to the subscriber.
    #[test]
    fn test_nrfd_02_profile_changed_notify_dispatched_on_patch() {
        use nextgcore_nrfd::nnrf_handler::SubscrCond;
        use nextgcore_nrfd::{nrf_nnrf_nfm_send_nf_profile_changed_notify_all, SubscriptionData};
        use serde_json::json;

        // Build an NF profile.
        let profile = NfProfile::from_json(&json!({
            "nfInstanceId": "nrfd02-test-nf-01",
            "nfType": "SMF",
            "nfStatus": "REGISTERED",
            "load": 40,
        }))
        .unwrap();

        // Build a subscription that matches this NF type.
        let subscription = SubscriptionData {
            id: "nrfd02-sub-01".to_string(),
            req_nf_type: Some("AMF".to_string()),
            req_nf_instance_id: None,
            notification_uri: "http://amf.example.com/nrfd02/notify".to_string(),
            subscr_cond: Some(SubscrCond {
                nf_type: Some("SMF".to_string()),
                service_name: None,
                nf_instance_id: None,
            }),
            validity_duration: 3600,
        };

        // Simulate a PATCH replacing /load.
        let pre = profile.to_json();
        let patch = json!([{"op": "replace", "path": "/load", "value": 75}]);
        let mut post = pre.clone();
        apply_json_patch(&mut post, &patch).unwrap();
        let updated = NfProfile::from_json(&post).unwrap();

        let changes = compute_profile_changes(&pre, &post, &patch, true);
        assert_eq!(changes.len(), 1, "one change item for /load replace");

        // Dispatch via the sync stub (no real HTTP, always returns Success).
        let result = nrf_nnrf_nfm_send_nf_profile_changed_notify_all(
            &updated,
            "http://nrf.example.com",
            &[subscription],
            changes,
        );
        assert!(result.is_ok(), "dispatch must succeed: {result:?}");
        assert_eq!(result.unwrap(), 1, "exactly one notification dispatched");
    }

    /// Assert that the SUSPENDED→REGISTERED reactivate path produces a
    /// NF_PROFILE_CHANGED ChangeItem with nfStatus replace op.
    #[test]
    fn test_nrfd_02_reactivate_change_item_shape() {
        use serde_json::json;

        // The reactivate path in handle_nf_update always constructs this fixed ChangeItem.
        let reactivate_changes = vec![ChangeItem {
            op: "replace".to_string(),
            path: "/nfStatus".to_string(),
            value: Some(json!("REGISTERED")),
            orig_value: Some(json!("SUSPENDED")),
        }];

        assert_eq!(reactivate_changes[0].op, "replace");
        assert_eq!(reactivate_changes[0].path, "/nfStatus");
        assert_eq!(reactivate_changes[0].value, Some(json!("REGISTERED")));
        assert_eq!(reactivate_changes[0].orig_value, Some(json!("SUSPENDED")));

        // Verify it serializes correctly into a NF_PROFILE_CHANGED body.
        use nextgcore_nrfd::nnrf_handler::SubscrCond;
        use nextgcore_nrfd::{nrf_nnrf_nfm_build_nf_profile_changed_notify, SubscriptionData};

        let profile = NfProfile::from_json(&json!({
            "nfInstanceId": "nrfd02-reactivate-nf",
            "nfType": "AMF",
            "nfStatus": "REGISTERED",
        }))
        .unwrap();

        let subscription = SubscriptionData {
            id: "nrfd02-reactivate-sub".to_string(),
            req_nf_type: Some("SMF".to_string()),
            req_nf_instance_id: None,
            notification_uri: "http://smf.example.com/nrfd02/notify".to_string(),
            subscr_cond: Some(SubscrCond {
                nf_type: Some("AMF".to_string()),
                service_name: None,
                nf_instance_id: None,
            }),
            validity_duration: 3600,
        };

        let request = nrf_nnrf_nfm_build_nf_profile_changed_notify(
            &subscription,
            &profile,
            "http://nrf.example.com",
            reactivate_changes,
        )
        .expect("builder must produce a request");

        let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
        assert_eq!(body["event"], "NF_PROFILE_CHANGED");
        let pc = body["profileChanges"].as_array().unwrap();
        assert_eq!(pc.len(), 1);
        assert_eq!(pc[0]["op"], "replace");
        assert_eq!(pc[0]["path"], "/nfStatus");
        assert_eq!(pc[0]["newValue"], "REGISTERED");
        assert_eq!(pc[0]["origValue"], "SUSPENDED");
    }

    // -----------------------------------------------------------------
    // nrfd-03: heartBeatTimer negotiation (TS 29.510 Table 6.1.6.2.2-1)
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_03_negotiate_heartbeat() {
        // In-range proposal is reused.
        assert_eq!(negotiate_heartbeat(Some(30), 10, 1, 3600), 30);
        // Absent proposal -> preconfigured default.
        assert_eq!(negotiate_heartbeat(None, 10, 1, 3600), 10);
        // Out-of-range (below min / above max) -> overridden to default.
        assert_eq!(negotiate_heartbeat(Some(0), 10, 1, 3600), 10);
        assert_eq!(negotiate_heartbeat(Some(99999), 10, 1, 3600), 10);
        // The supervision timer is armed at 2x the negotiated value.
        let hb = negotiate_heartbeat(None, 10, 1, 3600);
        assert_eq!((hb as u64) * 2, 20);
    }

    #[tokio::test]
    async fn test_nrfd_03_register_returns_negotiated_heartbeat() {
        use serde_json::json;
        let id = "nrfd03-reg-nf-01";
        // Register WITHOUT a heartBeatTimer: the 201 body must carry the
        // NRF default and a supervision timer must be armed.
        let mut req = SbiRequest::put(format!("/nnrf-nfm/v1/nf-instances/{id}"));
        req.http.set_content(
            json!({"nfInstanceId": id, "nfType": "SMF", "nfStatus": "REGISTERED"}).to_string(),
        );
        let resp = handle_nf_register(id, &req).await;
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["heartBeatTimer"], NRF_HEARTBEAT_DEFAULT);
        assert!(
            HEARTBEAT_TIMERS.lock().unwrap().contains_key(id),
            "registration must arm the supervision timer from the negotiated value"
        );

        // An out-of-range proposal is overridden to the default in the
        // stored AND returned profile.
        let id2 = "nrfd03-reg-nf-02";
        let mut req2 = SbiRequest::put(format!("/nnrf-nfm/v1/nf-instances/{id2}"));
        req2.http.set_content(
            json!({"nfInstanceId": id2, "nfType": "SMF", "nfStatus": "REGISTERED",
                   "heartBeatTimer": 99999})
            .to_string(),
        );
        let resp2 = handle_nf_register(id2, &req2).await;
        let body2: serde_json::Value =
            serde_json::from_str(resp2.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body2["heartBeatTimer"], NRF_HEARTBEAT_DEFAULT);

        nf_manager().deregister(id).ok();
        nf_manager().deregister(id2).ok();
        disarm_heartbeat_timer(id);
        disarm_heartbeat_timer(id2);
    }

    // -----------------------------------------------------------------
    // nrfd-04: conditional AccessTokenReq IEs (TS 29.510 Table 6.3.5.2.2-1)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn test_nrfd_04_target_instance_and_requester_snssai() {
        use serde_json::json;
        let mgr = nf_manager();
        let consumer_id = "nrfd04-consumer";
        let producer_id = "nrfd04-producer";
        // Unique NF types so no other test's producers pollute the decision.
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": consumer_id, "nfType": "NRFD04C", "nfStatus": "REGISTERED",
            }))
            .unwrap(),
        )
        .unwrap();
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": producer_id, "nfType": "NRFD04P", "nfStatus": "REGISTERED",
                "sNssais": [{"sst": 1, "sd": "010203"}],
                "nfServices": [{"serviceInstanceId": "s0", "serviceName": "nrfd04-svc"}],
            }))
            .unwrap(),
        )
        .unwrap();

        let token_req = |body: serde_json::Value| {
            let mut r = SbiRequest::post("/nnrf-oauth2/v1/access-token");
            r.http.set_content(body.to_string());
            r
        };

        // (a) Only targetNfInstanceId (no targetNfType) -> succeeds.
        let resp = handle_access_token_request(&token_req(json!({
            "grant_type": "client_credentials", "nfInstanceId": consumer_id,
            "nfType": "NRFD04C", "targetNfInstanceId": producer_id, "scope": "nrfd04-svc"
        })))
        .await;
        assert_eq!(
            resp.status, 200,
            "instance-scoped token: {:?}",
            resp.http.content
        );

        // (b) Neither targetNfType nor targetNfInstanceId -> invalid_request.
        let resp = handle_access_token_request(&token_req(json!({
            "grant_type": "client_credentials", "nfInstanceId": consumer_id,
            "nfType": "NRFD04C", "scope": "nrfd04-svc"
        })))
        .await;
        assert_eq!(resp.status, 400);
        let err: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(err["error"], "invalid_request");

        // (c) requesterSnssaiList that no producer serves -> invalid_scope.
        let resp = handle_access_token_request(&token_req(json!({
            "grant_type": "client_credentials", "nfInstanceId": consumer_id,
            "nfType": "NRFD04C", "targetNfType": "NRFD04P", "scope": "nrfd04-svc",
            "requesterSnssaiList": [{"sst": 9}]
        })))
        .await;
        assert_eq!(resp.status, 400);
        let err: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(err["error"], "invalid_scope");

        mgr.deregister(consumer_id).ok();
        mgr.deregister(producer_id).ok();
    }

    // -----------------------------------------------------------------
    // nrfd-05: CCA client-authentication binding (TS 29.510 §6.7.5)
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_05_verify_cca_binding() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use serde_json::json;

        let now = 1_000_000u64;
        // Encode arbitrary CCA claims into a placeholder-signed JWT (signature
        // verification is FLAGGED; this function checks the claim binding + iat/aud).
        let encode_cca = |claims: serde_json::Value| -> String {
            let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
            let p = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
            format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(b"sig"))
        };
        // Conformant CCA defaults: iat=now, aud="NRF" (the NRF's own NF type).
        let cca = |sub: &str, iss: Option<&str>, exp: Option<u64>| -> String {
            let mut claims = json!({ "sub": sub, "iat": now, "aud": "NRF" });
            if let Some(i) = iss {
                claims["iss"] = json!(i);
            }
            if let Some(e) = exp {
                claims["exp"] = json!(e);
            }
            encode_cca(claims)
        };

        // Matching subject + issuer, not expired, iat present, aud NRF -> Ok.
        assert!(
            verify_cca_binding(&cca("nf-1", Some("nf-1"), Some(now + 100)), "nf-1", now).is_ok()
        );
        // Subject mismatch -> invalid_client.
        assert_eq!(
            verify_cca_binding(&cca("nf-2", None, None), "nf-1", now)
                .unwrap_err()
                .0,
            "invalid_client"
        );
        // Expired -> invalid_client.
        assert_eq!(
            verify_cca_binding(&cca("nf-1", None, Some(now - 1)), "nf-1", now)
                .unwrap_err()
                .0,
            "invalid_client"
        );
        // Malformed (not a 3-part JWT) -> invalid_client.
        assert_eq!(
            verify_cca_binding("not-a-jwt", "nf-1", now).unwrap_err().0,
            "invalid_client"
        );
        // TS 33.501 §13.3.8.3 hardening: missing iat -> invalid_client.
        assert_eq!(
            verify_cca_binding(
                &encode_cca(json!({ "sub": "nf-1", "aud": "NRF", "exp": now + 100 })),
                "nf-1",
                now
            )
            .unwrap_err()
            .0,
            "invalid_client"
        );
        // Future-dated iat (beyond skew) -> invalid_client.
        assert_eq!(
            verify_cca_binding(
                &encode_cca(json!({ "sub": "nf-1", "aud": "NRF", "iat": now + 10_000 })),
                "nf-1",
                now
            )
            .unwrap_err()
            .0,
            "invalid_client"
        );
        // Audience not the NRF -> invalid_client.
        assert_eq!(
            verify_cca_binding(
                &encode_cca(json!({ "sub": "nf-1", "aud": "UDM", "iat": now })),
                "nf-1",
                now
            )
            .unwrap_err()
            .0,
            "invalid_client"
        );
        // aud as an array containing NRF -> Ok.
        assert!(verify_cca_binding(
            &encode_cca(json!({ "sub": "nf-1", "aud": ["UDM", "NRF"], "iat": now })),
            "nf-1",
            now
        )
        .is_ok());
    }

    // -----------------------------------------------------------------
    // I1: CCA ES256 JWS signature verification (TS 33.501 §13.3.8.3)
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_i1_verify_cca_signature() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};

        // Deterministic P-256 signer (fixed scalar, well below the group order).
        let sk = SigningKey::from_slice(&[0x11u8; 32]).expect("valid P-256 scalar");
        let vk = sk.verifying_key().to_owned();

        // Produce a real ES256 JWS over base64url(header).base64url(payload).
        let sign = |header_json: &[u8], payload_json: &[u8]| -> String {
            let h = URL_SAFE_NO_PAD.encode(header_json);
            let p = URL_SAFE_NO_PAD.encode(payload_json);
            let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
            format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
        };

        let header = br#"{"alg":"ES256","typ":"JWT"}"#;
        let payload = br#"{"sub":"nf-1","iss":"nf-1","aud":"NRF","iat":1000000}"#;

        // A correctly-signed CCA verifies against the matching public key.
        let cca = sign(header, payload);
        assert!(verify_cca_signature(&cca, &vk).is_ok());

        let parts: Vec<&str> = cca.split('.').collect();

        // Tampered payload (forged claims, original signature) -> rejected: this
        // is exactly the forged-CCA the audit flagged as accepted.
        let forged_payload =
            URL_SAFE_NO_PAD.encode(br#"{"sub":"attacker","iss":"attacker","aud":"NRF","iat":1000000}"#);
        let forged = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);
        assert_eq!(
            verify_cca_signature(&forged, &vk).unwrap_err().0,
            "invalid_client"
        );

        // Valid signature but WRONG (untrusted) key -> rejected.
        let other = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
        assert_eq!(
            verify_cca_signature(&cca, other.verifying_key())
                .unwrap_err()
                .0,
            "invalid_client"
        );

        // alg=none downgrade -> rejected before any crypto (algorithm-substitution).
        let none_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let none_jwt = format!("{}.{}.{}", none_header, parts[1], parts[2]);
        assert_eq!(
            verify_cca_signature(&none_jwt, &vk).unwrap_err().0,
            "invalid_client"
        );

        // Malformed signature bytes (wrong length) -> rejected.
        let bad_sig = format!(
            "{}.{}.{}",
            parts[0],
            parts[1],
            URL_SAFE_NO_PAD.encode(b"short")
        );
        assert_eq!(
            verify_cca_signature(&bad_sig, &vk).unwrap_err().0,
            "invalid_client"
        );

        // Not a well-formed 3-part JWT -> rejected.
        assert_eq!(
            verify_cca_signature("a.b", &vk).unwrap_err().0,
            "invalid_client"
        );
    }

    #[test]
    fn test_nrfd_i1_from_yaml_cca_signature_config() {
        // RFC 7515 Appendix A.3.1 P-256 public key — a valid EC/P-256 JWK.
        let yaml_str = "nrf:\n  sbi:\n    oauth2:\n      cca_verify_signature: true\n      \
             cca_trusted_keys:\n        - nfInstanceId: nf-1\n          jwk:\n            \
             kty: EC\n            crv: P-256\n            \
             x: f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\n            \
             y: x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\n";
        let yaml: NrfYaml = serde_yaml::from_str(yaml_str).expect("parse yaml");
        let policy = NrfPolicy::from_yaml(&yaml);
        assert!(policy.cca_verify_signature);
        assert!(policy.cca_trusted_keys.contains_key("nf-1"));

        // A malformed JWK entry is dropped, not fatal — the issuer then has no
        // trusted key and its CCA is rejected at runtime (fail-closed).
        let bad = "nrf:\n  sbi:\n    oauth2:\n      cca_verify_signature: true\n      \
             cca_trusted_keys:\n        - nfInstanceId: nf-2\n          jwk:\n            \
             kty: EC\n            crv: P-256\n            x: not-valid\n            y: not-valid\n";
        let yaml2: NrfYaml = serde_yaml::from_str(bad).expect("parse yaml");
        let policy2 = NrfPolicy::from_yaml(&yaml2);
        assert!(policy2.cca_verify_signature);
        assert!(!policy2.cca_trusted_keys.contains_key("nf-2"));

        // Defaults: signature verification OFF, empty trust store.
        let def = NrfPolicy::default();
        assert!(!def.cca_verify_signature);
        assert!(def.cca_trusted_keys.is_empty());
    }

    // -----------------------------------------------------------------
    // I2: token-requester transport auth (mTLS/CCA binding) — TS 33.501
    // §13.3.1/§13.4.1, TS 33.310 (NF Instance ID in cert URI SAN),
    // Envoy XFCC / RFC 9440 conveyance trust model.
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_i2_xfcc_uri_extraction() {
        // Leaf entry URI SAN, urn:uuid stripped to the bare NF Instance ID.
        assert_eq!(
            parse_xfcc_first_entry_uri(
                r#"By=spiffe://c/ns/5gc/sa/nrf;Hash=abcd;Subject="CN=SMF,O=Op";URI=urn:uuid:smf-1"#
            )
            .as_deref(),
            Some("urn:uuid:smf-1")
        );

        // Quote-awareness (security): a fake `;URI=` smuggled INSIDE a quoted
        // Subject DN must NOT be treated as a separate URI element — the only
        // real URI element wins.
        assert_eq!(
            parse_xfcc_first_entry_uri(
                r#"Subject="CN=evil;URI=urn:uuid:victim";URI=urn:uuid:real"#
            )
            .as_deref(),
            Some("urn:uuid:real")
        );
        // A quoted Subject carrying only a fake URI (no genuine URI element)
        // yields nothing — the smuggled value is never surfaced.
        assert_eq!(
            parse_xfcc_first_entry_uri(r#"Subject="CN=evil;URI=urn:uuid:victim""#),
            None
        );
        // A quoted value containing a comma does not prematurely end the entry.
        assert_eq!(
            parse_xfcc_first_entry_uri(r#"Subject="O=Foo, Inc";URI=urn:uuid:abc"#).as_deref(),
            Some("urn:uuid:abc")
        );
        // Multiple cert entries: the FIRST (leaf) entry's URI is chosen.
        assert_eq!(
            parse_xfcc_first_entry_uri("URI=urn:uuid:leaf,By=x;URI=urn:uuid:intermediate")
                .as_deref(),
            Some("urn:uuid:leaf")
        );
        // No URI element at all.
        assert_eq!(parse_xfcc_first_entry_uri("Hash=abcd;Subject=\"CN=x\""), None);

        // Full extraction: urn:uuid: prefix (case-insensitive) is stripped.
        let mut req = SbiRequest::post("/nnrf-oauth2/v1/access-token");
        req.http
            .set_header("x-forwarded-client-cert", "Hash=ab;URI=URN:UUID:amf-9");
        assert_eq!(
            extract_transport_client_nf_instance_id(&req).as_deref(),
            Some("amf-9")
        );
        // A non-URN URI SAN binds on the exact value.
        let mut req2 = SbiRequest::post("/x");
        req2.http
            .set_header("x-forwarded-client-cert", "URI=https://amf.example/nf/amf-9");
        assert_eq!(
            extract_transport_client_nf_instance_id(&req2).as_deref(),
            Some("https://amf.example/nf/amf-9")
        );
        // No XFCC header -> no transport identity.
        let bare = SbiRequest::post("/x");
        assert!(extract_transport_client_nf_instance_id(&bare).is_none());
    }

    #[test]
    fn test_nrfd_i2_verify_transport_binding() {
        // Matching cert identity and request nfInstanceId -> Ok.
        assert!(verify_transport_binding("nf-1", "nf-1").is_ok());
        // Mismatch -> invalid_client (a cert for nf-A cannot mint tokens for nf-B).
        assert_eq!(
            verify_transport_binding("nf-A", "nf-B").unwrap_err().0,
            "invalid_client"
        );
    }

    #[test]
    fn test_nrfd_i2_enforce_client_authentication() {
        // Defaults OFF: no authentication required regardless of what's present.
        let def = NrfPolicy::default();
        assert!(enforce_client_authentication(&def, false, false).is_ok());
        assert!(enforce_client_authentication(&def, true, false).is_ok());

        // require_client_auth ON: satisfied by a CCA OR an mTLS identity;
        // neither present -> invalid_client.
        let auth = NrfPolicy {
            require_client_auth: true,
            ..NrfPolicy::default()
        };
        assert!(enforce_client_authentication(&auth, true, false).is_ok());
        assert!(enforce_client_authentication(&auth, false, true).is_ok());
        assert_eq!(
            enforce_client_authentication(&auth, false, false)
                .unwrap_err()
                .0,
            "invalid_client"
        );

        // require_client_cert_binding ON: an mTLS identity is MANDATORY — a CCA
        // alone does not satisfy it.
        let mtls = NrfPolicy {
            require_client_cert_binding: true,
            ..NrfPolicy::default()
        };
        assert!(enforce_client_authentication(&mtls, false, true).is_ok());
        assert_eq!(
            enforce_client_authentication(&mtls, true, false)
                .unwrap_err()
                .0,
            "invalid_client"
        );
    }

    #[test]
    fn test_nrfd_i2_from_yaml_and_env_overrides() {
        // yaml knobs fold into the policy.
        let yaml: NrfYaml = serde_yaml::from_str(
            "nrf:\n  sbi:\n    oauth2:\n      require_client_auth: true\n      \
             require_client_cert_binding: true\n",
        )
        .expect("parse yaml");
        let policy = NrfPolicy::from_yaml(&yaml);
        assert!(policy.require_client_auth);
        assert!(policy.require_client_cert_binding);

        // Defaults are OFF (default-safe / matched-sim untouched).
        let def = NrfPolicy::default();
        assert!(!def.require_client_auth);
        assert!(!def.require_client_cert_binding);

        // Env override forces a default-OFF knob ON without a code edit; an
        // absent/other value leaves it unchanged. Serialized because it mutates
        // process env.
        let mut p = NrfPolicy::default();
        std::env::set_var("NRF_SBI_OAUTH2_REQUIRE_CLIENT_CERT_BINDING", "1");
        p.apply_env_overrides();
        assert!(p.require_client_cert_binding);
        assert!(!p.require_client_auth, "unset knob stays OFF");
        std::env::remove_var("NRF_SBI_OAUTH2_REQUIRE_CLIENT_CERT_BINDING");

        // An env override never turns a yaml-ON knob back off.
        let mut on = NrfPolicy {
            require_client_auth: true,
            ..NrfPolicy::default()
        };
        std::env::set_var("NRF_SBI_OAUTH2_REQUIRE_CLIENT_AUTH", "0");
        on.apply_env_overrides();
        assert!(on.require_client_auth);
        std::env::remove_var("NRF_SBI_OAUTH2_REQUIRE_CLIENT_AUTH");
    }

    /// Strict-peer (real handler) test of the mTLS/CCA binding at the live token
    /// endpoint. The transport-binding mismatch check runs unconditionally (no
    /// flag needed): a forged XFCC identity is rejected even under the default
    /// (OFF) policy — the falsifiable core of I2.
    #[tokio::test]
    async fn test_nrfd_i2_token_endpoint_mtls_binding() {
        use serde_json::json;
        let mgr = nf_manager();
        let consumer_id = "nrfdi2-consumer";
        let producer_id = "nrfdi2-producer";
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": consumer_id, "nfType": "NRFDI2C", "nfStatus": "REGISTERED",
            }))
            .unwrap(),
        )
        .unwrap();
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": producer_id, "nfType": "NRFDI2P", "nfStatus": "REGISTERED",
                "nfServices": [{"serviceInstanceId": "s0", "serviceName": "nrfdi2-svc"}],
            }))
            .unwrap(),
        )
        .unwrap();

        let token_req = |xfcc: Option<&str>| {
            let mut r = SbiRequest::post("/nnrf-oauth2/v1/access-token");
            r.http.set_content(
                json!({
                    "grant_type": "client_credentials", "nfInstanceId": consumer_id,
                    "nfType": "NRFDI2C", "targetNfType": "NRFDI2P", "scope": "nrfdi2-svc"
                })
                .to_string(),
            );
            if let Some(x) = xfcc {
                r.http.set_header("x-forwarded-client-cert", x);
            }
            r
        };

        // (a) A forged/mismatched mTLS identity is rejected with invalid_client
        // even though require_client_auth defaults OFF.
        let resp = handle_access_token_request(&token_req(Some(
            "Hash=ab;URI=urn:uuid:some-other-nf",
        )))
        .await;
        assert_eq!(resp.status, 400, "mismatched cert must be rejected");
        let err: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(err["error"], "invalid_client");

        // (b) A matching mTLS identity binds cleanly -> token issued (200).
        let resp = handle_access_token_request(&token_req(Some(&format!(
            "Hash=ab;URI=urn:uuid:{consumer_id}"
        ))))
        .await;
        assert_eq!(
            resp.status, 200,
            "bound cert must pass: {:?}",
            resp.http.content
        );

        // (c) No mTLS identity, default policy -> unchanged behaviour (200).
        let resp = handle_access_token_request(&token_req(None)).await;
        assert_eq!(resp.status, 200, "default path unchanged");

        mgr.deregister(consumer_id).ok();
        mgr.deregister(producer_id).ok();
    }

    // -----------------------------------------------------------------
    // nrfd-06: per-path server-side OAuth2 enforcement (TS 33.501 §13.4.1)
    // -----------------------------------------------------------------

    /// Mint an NRF-signed ES256 access token (as the token endpoint does).
    fn mint_nrf_token(sub: &str, aud: &str, exp_offset: i64) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use p256::ecdsa::{signature::Signer, Signature};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let header = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{NRF_KID}"}}"#);
        let claims = serde_json::json!({
            "iss": nrf_instance_id(), "sub": sub, "aud": aud, "scope": "x",
            "exp": (now + exp_offset) as u64, "iat": now as u64,
        });
        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let signing_input = format!("{h}.{p}");
        let sig: Signature = nrf_signing_key().sign(signing_input.as_bytes());
        format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    #[test]
    fn test_nrfd_06_protected_path_classification() {
        assert!(oauth2_protected_path("/nnrf-nfm/v1/nf-instances/x"));
        assert!(oauth2_protected_path("/nnrf-disc/v1/nf-instances"));
        assert!(!oauth2_protected_path("/nnrf-oauth2/v1/access-token"));
        assert!(!oauth2_protected_path("/nnrf-oauth2/v1/jwks"));
        assert!(!oauth2_protected_path("/"));
    }

    #[test]
    fn test_nrfd_06_enforce_oauth2_decisions() {
        let jwks = nrf_jwks_json();

        // Default OFF -> always allowed (matched-sim path preserved).
        assert!(
            enforce_oauth2_on_request("/nnrf-disc/v1/nf-instances", None, false, &jwks).is_none()
        );
        // Enforcement ON, protected path, no token -> 401.
        let r = enforce_oauth2_on_request("/nnrf-disc/v1/nf-instances", None, true, &jwks);
        assert_eq!(r.expect("must reject").status, 401);
        // The token + jwks endpoints stay exempt even with enforcement ON.
        assert!(
            enforce_oauth2_on_request("/nnrf-oauth2/v1/access-token", None, true, &jwks).is_none()
        );
        assert!(enforce_oauth2_on_request("/nnrf-oauth2/v1/jwks", None, true, &jwks).is_none());
        // A valid NRF-issued token on a protected path -> allowed.
        let auth = format!("Bearer {}", mint_nrf_token("sub-x", "NRF", 3600));
        assert!(
            enforce_oauth2_on_request("/nnrf-nfm/v1/nf-instances/x", Some(&auth), true, &jwks)
                .is_none()
        );
    }

    // -----------------------------------------------------------------
    // nrfd-07: producer/consumer optional claims (TS 29.510 §6.3.5.2.4)
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_07_instance_scoped_claims() {
        use serde_json::json;
        let consumer = NfProfile::from_json(&json!({
            "nfInstanceId": "c-1", "nfType": "SMF", "nfStatus": "REGISTERED",
            "plmnList": [{"mcc": "001", "mnc": "01"}]
        }))
        .unwrap();
        let producer = NfProfile::from_json(&json!({
            "nfInstanceId": "p-1", "nfType": "UDM", "nfStatus": "REGISTERED",
            "plmnList": [{"mcc": "001", "mnc": "01"}],
            "sNssais": [{"sst": 1, "sd": "010203"}],
            "nfSetId": "set-udm-1"
        }))
        .unwrap();

        // Instance-scoped: aud is the instance-ID array + producer claims set.
        let claims = build_access_token_claims(
            "nrf-iss",
            "c-1",
            "UDM",
            Some(&producer),
            &consumer,
            "nudm-sdm",
            100,
            3700,
        );
        assert_eq!(claims["aud"], json!(["p-1"]));
        assert_eq!(
            claims["producerSnssaiList"],
            json!([{"sst": 1, "sd": "010203"}])
        );
        assert_eq!(claims["consumerPlmnId"], json!({"mcc": "001", "mnc": "01"}));
        assert_eq!(claims["producerPlmnId"], json!({"mcc": "001", "mnc": "01"}));
        assert_eq!(claims["producerNfSetId"], json!("set-udm-1"));

        // Type-scoped (no instance): aud is the bare NF type string.
        let claims2 = build_access_token_claims(
            "nrf-iss", "c-1", "UDM", None, &consumer, "nudm-sdm", 100, 3700,
        );
        assert_eq!(claims2["aud"], json!("UDM"));
        assert!(claims2.get("producerSnssaiList").is_none());
    }

    // -----------------------------------------------------------------
    // nrfd-08: full SubscriptionData + NRF-assigned validityTime
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_08_epoch_to_rfc3339() {
        assert_eq!(epoch_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(epoch_to_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn test_nrfd_08_subscription_response_full_fields() {
        use nextgcore_nrfd::nnrf_handler::SubscrCond;
        use nextgcore_nrfd::SubscriptionData;
        let sub = SubscriptionData {
            id: "sub-08".to_string(),
            req_nf_type: Some("AMF".to_string()),
            req_nf_instance_id: Some("amf-1".to_string()),
            notification_uri: "http://amf/cb".to_string(),
            subscr_cond: Some(SubscrCond {
                nf_type: Some("SMF".to_string()),
                service_name: None,
                nf_instance_id: None,
            }),
            validity_duration: 3600,
        };
        let body = subscription_response_json(&sub, "2023-11-14T22:13:20Z");
        assert_eq!(body["subscriptionId"], "sub-08");
        assert_eq!(body["nfStatusNotificationUri"], "http://amf/cb");
        assert_eq!(body["reqNfType"], "AMF");
        assert_eq!(body["reqNfInstanceId"], "amf-1");
        assert_eq!(body["subscrCond"]["nfType"], "SMF");
        assert_eq!(body["validityTime"], "2023-11-14T22:13:20Z");
    }

    // -----------------------------------------------------------------
    // nrfd-09: percent-decoded form-urlencoded token body
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_09_form_body_percent_decoded() {
        let body = "grant_type=client_credentials&nfInstanceId=urn%3Auuid%3Aabc-123\
                    &nfType=SMF&targetNfType=UDM&scope=nudm-sdm+nudm-uecm";
        let req = parse_token_request(body);
        assert_eq!(req.grant_type, "client_credentials");
        // %3A -> ':' so the URN round-trips through the authorization check.
        assert_eq!(req.nf_instance_id, "urn:uuid:abc-123");
        assert_eq!(req.nf_type, "SMF");
        assert_eq!(req.target_nf_type, "UDM");
        // '+' -> space in the scope list.
        assert_eq!(req.scope, "nudm-sdm nudm-uecm");
    }

    // -----------------------------------------------------------------
    // nrfd-10: discovery pagination + configurable validityPeriod
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_10_paginate_results() {
        use serde_json::json;
        let items: Vec<serde_json::Value> = (0..50).map(|i| json!({ "n": i })).collect();

        // 50 instances, default cap 25 -> 25 returned + more pages exist.
        let (page1, more1) = paginate_results(items.clone(), 1, 25);
        assert_eq!(page1.len(), 25);
        assert!(more1, "page 1 of 50@25 must signal a continuation");
        assert_eq!(page1[0]["n"], 0);

        // Page 2 returns the rest, no further pages.
        let (page2, more2) = paginate_results(items.clone(), 2, 25);
        assert_eq!(page2.len(), 25);
        assert!(!more2);
        assert_eq!(page2[0]["n"], 25);

        // Page past the end -> empty, no more.
        let (page3, more3) = paginate_results(items, 3, 25);
        assert!(page3.is_empty());
        assert!(!more3);

        // validityPeriod default reflects policy (config-driven, nrfd-10).
        assert_eq!(nrf_policy().disc_validity_period, NRF_DISC_VALIDITY_PERIOD);
    }
}
