//! NextGCore AMF (Access and Mobility Management Function)
//!
//! The whole AMF network function lives in this library crate (Wave-6 H1
//! lib-targetization) so peer NF crates can drive the real Namf SBI request
//! handler ([`namf_server::namf_request_handler`]) in-process from strict-peer
//! integration tests instead of hand-rolled lenient mocks; `src/main.rs` is a
//! thin wrapper around [`run`].

pub mod amf_sm;
pub mod context;
pub mod emergency; // #203: Emergency services (TS 23.167)
pub mod event;
pub mod gmm_build;
pub mod gmm_handler;
pub mod gmm_sm;
pub mod metrics;
pub mod namf_handler;
pub mod namf_server;
pub mod nas_security;
pub mod ngap_asn1;
pub mod ngap_handler;
pub mod ngap_mcast; // MBS: NGAP multicast session procedures (TS 38.413 / TS 23.247)
pub mod ngap_path;
pub mod ngap_sm;
pub mod positioning; // LCS: LMF positioning relay (NRPPa N2 / LPP N1) — TS 23.273
pub mod sbi_path;
pub mod snpn; // Rel-16: SNPN authentication (TS 23.501 §5.30)
pub mod timer;
pub mod xn_handover; // Rel-15: Xn path switch and N2 handover (TS 23.502 §4.9)

#[cfg(test)]
mod property_tests;

// Wave-6 H1: expose the real Namf SBI request handler + the N1N2MessageTransfer
// consumer so peer NF crates (lmfd/udmd/smfd/pcfd) can drive them in-process
// for strict-peer tests (TS 29.518 Namf_Communication).
pub use namf_server::{handle_n1_n2_message_transfer_request, namf_request_handler};

/// Helpers for in-process strict-peer tests in *other* crates. Not gated behind
/// `#[cfg(test)]` because cfg(test) items are invisible across crate
/// boundaries; a dev-dependency test in a peer crate must be able to seed the
/// process-global AMF context.
pub mod test_support {
    use std::sync::Mutex;

    /// Process-wide lock so strict-peer tests that touch the global AMF context
    /// run serially. The AMF context is process-global, so parallel tests would
    /// race (cf. the known-flaky `namf_server::tests::
    /// test_ue_context_transfer_error_paths`).
    pub static CONTEXT_GUARD: Mutex<()> = Mutex::new(());

    /// Initialize the process-global AMF context for in-process strict-peer
    /// tests (wraps [`crate::context::amf_context_init`] with test capacities).
    pub fn init_context() {
        crate::context::amf_context_init(64, 1024, 4096);
    }
}

use anyhow::Result;
use clap::Parser;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

// ---------------------------------------------------------------------------
// Typed YAML configuration structs
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct PlmnIdYaml {
    mcc: Option<serde_yaml::Value>,
    mnc: Option<serde_yaml::Value>,
}

#[derive(Debug, Default, Deserialize)]
struct AmfIdYaml {
    region: Option<u8>,
    set: Option<u16>,
    pointer: Option<u8>,
}

#[derive(Debug, Default, Deserialize)]
struct GuamiYaml {
    plmn_id: Option<PlmnIdYaml>,
    amf_id: Option<AmfIdYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct TaiYaml {
    plmn_id: Option<PlmnIdYaml>,
    tac: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct SNssaiYaml {
    sst: Option<u8>,
    sd: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct PlmnSupportYaml {
    plmn_id: Option<PlmnIdYaml>,
    s_nssai: Option<Vec<SNssaiYaml>>,
}

#[derive(Debug, Default, Deserialize)]
struct SecurityYaml {
    integrity_order: Option<Vec<String>>,
    ciphering_order: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
struct NetworkNameYaml {
    full: Option<String>,
    short: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct NrfClientYaml {
    uri: String,
}

#[derive(Debug, Default, Deserialize)]
struct SbiClientYaml {
    nrf: Option<Vec<NrfClientYaml>>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiYaml {
    client: Option<SbiClientYaml>,
}

/// Wave-6 H9 NAS-security canary knob (`amf.nas.use_nextgcore_security`).
/// Default OFF (absent → legacy byte-for-byte NAS path). The `AMF_NAS_SECURITY`
/// env override takes precedence over this yaml value; see
/// `context::resolve_nas_security_canary`.
#[derive(Debug, Default, Deserialize)]
struct NasYaml {
    use_nextgcore_security: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct AmfSection {
    amf_name: Option<String>,
    network_name: Option<NetworkNameYaml>,
    guami: Option<Vec<GuamiYaml>>,
    tai: Option<Vec<TaiYaml>>,
    plmn_support: Option<Vec<PlmnSupportYaml>>,
    security: Option<SecurityYaml>,
    sbi: Option<SbiYaml>,
    nas: Option<NasYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct AmfYaml {
    amf: Option<AmfSection>,
}

// ---------------------------------------------------------------------------
// OAuth2 rollout (Wave-6 H8): opt-in producer verification + outbound consumer
// token install. Default OFF so the matched-sim E2E path is byte-unchanged;
// the docker `amf-oauth2.yaml` overlay (or NEXTGCORE_SBI_OAUTH2_REQUIRE=1) sets
// `amf.sbi.oauth2.require: true`. TS 33.501 §13.4.1, TS 29.510 §5.4.2.
// ---------------------------------------------------------------------------

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on
/// outbound SBI calls (installed only when OAuth2 enforcement is enabled).
static OAUTH2_CLIENT: std::sync::OnceLock<Option<Arc<nextgcore_sbi::oauth::OAuth2Client>>> =
    std::sync::OnceLock::new();

/// The shared OAuth2 client, if SBI OAuth2 enforcement is enabled (Wave-6 H8
/// Phase A). Outbound SBI clients attach a token via `client.with_oauth2`.
fn oauth2_client() -> Option<Arc<nextgcore_sbi::oauth::OAuth2Client>> {
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

/// Attach the process-wide OAuth2 client (when enforcement is on) so the
/// outbound request carries an NRF-issued Bearer token scoped to `target`
/// (aud = the target NF type, TS 33.501 §13.4.1). A no-op when enforcement is
/// off — the matched-sim default — because `oauth2_client()` is then `None`,
/// so the outbound wire is byte-unchanged. Wave-6 H8 Phase A (consumer attach).
pub(crate) fn attach_oauth2(
    client: nextgcore_sbi::client::SbiClient,
    target: nextgcore_sbi::types::NfType,
) -> nextgcore_sbi::client::SbiClient {
    match oauth2_client() {
        Some(oauth2) => client.with_oauth2(oauth2, target),
        None => client,
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
/// NRF JWKS and requires `aud` to include NfType::Amf; with no NRF URI
/// configured it fails closed (503, per nextgcore-sbi server.rs).
async fn apply_oauth2_enforcement(
    mut cfg: nextgcore_sbi::server::SbiServerConfig,
) -> nextgcore_sbi::server::SbiServerConfig {
    let nrf_uri = nextgcore_sbi::context::global_context().get_nrf_uri().await;
    cfg.require_oauth2 = true;
    cfg.oauth2_jwks_uri = nrf_uri.as_deref().map(|uri| {
        nextgcore_sbi::oauth::JwksCache::for_nrf(uri)
            .jwks_uri()
            .to_string()
    });
    cfg = cfg.with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Amf);
    if let Some(uri) = nrf_uri.as_deref() {
        let nf_instance_id = format!("amf-{}", uuid::Uuid::new_v4());
        let _ = OAUTH2_CLIENT.set(Some(Arc::new(nextgcore_sbi::oauth::OAuth2Client::new(
            uri,
            nf_instance_id,
            nextgcore_sbi::types::NfType::Amf,
        ))));
    }
    log::info!(
        "OAuth2 enforcement enabled (JWKS: {})",
        cfg.oauth2_jwks_uri.as_deref().unwrap_or("UNCONFIGURED")
    );
    cfg
}

/// NextGCore AMF - Access and Mobility Management Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-amfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Access and Mobility Management Function")]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/nextgcore/amf.yaml")]
    config: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Disable color output
    #[arg(long)]
    no_color: bool,

    /// Run in daemon mode
    #[arg(short, long)]
    daemon: bool,

    /// NGAP bind address (e.g., "0.0.0.0:38412")
    #[arg(long, default_value = "0.0.0.0:38412")]
    ngap_addr: String,

    /// SCTP transport backend: "userspace" (sctp-proto over UDP, matched
    /// nextgsim gNB) or "kernel" (native Linux kernel SCTP for a standard
    /// external RAN; needs the `kernel-sctp` build feature + libsctp).
    #[arg(long, default_value = "userspace")]
    sctp_backend: String,
}

/// AMF application state
pub struct AmfApp {
    /// Running flag
    running: Arc<AtomicBool>,
    /// Timer manager
    timer_manager: timer::TimerManager,
    /// Metrics
    metrics: metrics::AmfMetrics,
    /// AMF context (thread-safe)
    amf_context: Arc<RwLock<context::AmfContext>>,
    /// NGAP event channel sender
    ngap_event_tx: Option<mpsc::Sender<event::AmfEvent>>,
    /// NGAP event channel receiver
    ngap_event_rx: Option<mpsc::Receiver<event::AmfEvent>>,
}

impl AmfApp {
    /// Create a new AMF application
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(1024);
        Self {
            running: Arc::new(AtomicBool::new(true)),
            timer_manager: timer::TimerManager::new(),
            metrics: metrics::AmfMetrics::new(),
            amf_context: Arc::new(RwLock::new(context::AmfContext::new())),
            ngap_event_tx: Some(tx),
            ngap_event_rx: Some(rx),
        }
    }

    /// Initialize the AMF application
    pub async fn init(&mut self, config_path: &str) -> Result<()> {
        log::info!("Initializing AMF...");

        // Initialize AMF context
        context::amf_context_init(64, 1024, 4096);

        // Load configuration from YAML file
        self.load_config(config_path).await?;

        // Initialize SBI
        sbi_path::amf_sbi_open()?;

        log::info!("AMF initialized successfully");
        Ok(())
    }

    /// Load configuration from YAML file
    async fn load_config(&self, config_path: &str) -> Result<()> {
        log::info!("Loading configuration from: {config_path}");

        let config_content = match std::fs::read_to_string(config_path) {
            Ok(content) => content,
            Err(e) => {
                log::warn!("Could not read config file '{config_path}': {e}. Using defaults.");
                return Ok(());
            }
        };

        let yaml: AmfYaml = match serde_yaml::from_str(&config_content) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Failed to parse YAML config '{config_path}': {e}. Using defaults.");
                return Ok(());
            }
        };

        let amf_section = match yaml.amf {
            Some(s) => s,
            None => {
                log::warn!("No 'amf' section in config file");
                return Ok(());
            }
        };

        // Wave-6 H9 NAS-security canary (nas-06 Phase-6): seed the process-wide
        // runtime knob from `AMF_NAS_SECURITY` env (override) or the yaml
        // `amf.nas.use_nextgcore_security` key. Default OFF keeps the legacy
        // byte-for-byte NAS path; flip is a manual docker gate (see WS-H H9).
        let nas_canary = context::resolve_nas_security_canary(
            std::env::var("AMF_NAS_SECURITY").ok().as_deref(),
            amf_section
                .nas
                .as_ref()
                .and_then(|n| n.use_nextgcore_security),
        );
        context::set_nas_security_canary(nas_canary);

        // Seed NRF URI into SBI context for NF registration
        if let Some(sbi) = &amf_section.sbi {
            if let Some(client) = &sbi.client {
                if let Some(nrf_list) = &client.nrf {
                    if let Some(nrf) = nrf_list.first() {
                        log::info!("NRF URI configured: {}", nrf.uri);
                        nextgcore_sbi::context::global_context()
                            .set_nrf_uri(&nrf.uri)
                            .await;
                    }
                }
            }
        }

        let mut ctx = self.amf_context.write().await;

        // AMF name
        if let Some(name) = amf_section.amf_name {
            log::info!("AMF name: {name}");
            ctx.amf_name = Some(name);
        }

        // Network name
        if let Some(nn) = amf_section.network_name {
            if let Some(full) = nn.full {
                ctx.full_name = context::NetworkName { name: full };
            }
            if let Some(short) = nn.short {
                ctx.short_name = context::NetworkName { name: short };
            }
        }

        // GUAMI list
        for entry in amf_section.guami.unwrap_or_default() {
            if let Some(guami) = Self::resolve_guami(entry) {
                log::info!(
                    "Configured GUAMI: PLMN {}{}{}-{}{}{}, AMF Region={}, Set={}",
                    guami.plmn_id.mcc1,
                    guami.plmn_id.mcc2,
                    guami.plmn_id.mcc3,
                    guami.plmn_id.mnc1,
                    guami.plmn_id.mnc2,
                    if guami.plmn_id.mnc3 == 0xf {
                        String::new()
                    } else {
                        guami.plmn_id.mnc3.to_string()
                    },
                    guami.amf_id.region,
                    guami.amf_id.set
                );
                ctx.served_guami.push(guami);
                ctx.num_of_served_guami += 1;
            }
        }

        // TAI list
        for entry in amf_section.tai.unwrap_or_default() {
            if let Some(served_tai) = Self::resolve_tai(entry) {
                let tac = served_tai.list0.tac.first().copied().unwrap_or(0);
                log::info!(
                    "Configured TAI: PLMN {}{}{}-{}{}{}, TAC={}",
                    served_tai.list0.plmn_id.mcc1,
                    served_tai.list0.plmn_id.mcc2,
                    served_tai.list0.plmn_id.mcc3,
                    served_tai.list0.plmn_id.mnc1,
                    served_tai.list0.plmn_id.mnc2,
                    if served_tai.list0.plmn_id.mnc3 == 0xf {
                        String::new()
                    } else {
                        served_tai.list0.plmn_id.mnc3.to_string()
                    },
                    tac
                );
                ctx.served_tai.push(served_tai);
                ctx.num_of_served_tai += 1;
            }
        }

        // PLMN support
        for entry in amf_section.plmn_support.unwrap_or_default() {
            if let Some(plmn_support) = Self::resolve_plmn_support(entry) {
                log::info!(
                    "Configured PLMN support: PLMN {}{}{}-{}{}{}, {} S-NSSAIs",
                    plmn_support.plmn_id.mcc1,
                    plmn_support.plmn_id.mcc2,
                    plmn_support.plmn_id.mcc3,
                    plmn_support.plmn_id.mnc1,
                    plmn_support.plmn_id.mnc2,
                    if plmn_support.plmn_id.mnc3 == 0xf {
                        String::new()
                    } else {
                        plmn_support.plmn_id.mnc3.to_string()
                    },
                    plmn_support.num_of_s_nssai
                );
                ctx.plmn_support.push(plmn_support);
                ctx.num_of_plmn_support += 1;
            }
        }

        // Security algorithms
        if let Some(security) = amf_section.security {
            for algo_str in security.integrity_order.unwrap_or_default() {
                let algo_id = Self::parse_integrity_algorithm(&algo_str);
                ctx.integrity_order.push(algo_id);
                ctx.num_of_integrity_order += 1;
            }
            for algo_str in security.ciphering_order.unwrap_or_default() {
                let algo_id = Self::parse_ciphering_algorithm(&algo_str);
                ctx.ciphering_order.push(algo_id);
                ctx.num_of_ciphering_order += 1;
            }
        }

        log::info!(
            "AMF configuration loaded: {} GUAMI, {} TAI, {} PLMN support",
            ctx.num_of_served_guami,
            ctx.num_of_served_tai,
            ctx.num_of_plmn_support
        );

        Ok(())
    }

    /// Resolve a PLMN ID from the typed YAML struct (mcc/mnc may be int or string)
    fn resolve_plmn_id(plmn: PlmnIdYaml) -> Option<context::PlmnId> {
        let mcc = plmn.mcc.and_then(|v| match v {
            serde_yaml::Value::Number(n) => n.as_u64().map(|x| x.to_string()),
            serde_yaml::Value::String(s) => Some(s),
            _ => None,
        })?;
        let mnc = plmn.mnc.and_then(|v| match v {
            serde_yaml::Value::Number(n) => n.as_u64().map(|x| x.to_string()),
            serde_yaml::Value::String(s) => Some(s),
            _ => None,
        })?;
        Some(context::PlmnId::new(&mcc, &mnc))
    }

    /// Build a runtime Guami from its typed YAML representation
    fn resolve_guami(entry: GuamiYaml) -> Option<context::Guami> {
        let plmn_id = Self::resolve_plmn_id(entry.plmn_id?)?;
        let amf_id_yaml = entry.amf_id.unwrap_or_default();
        Some(context::Guami {
            plmn_id,
            amf_id: context::AmfId {
                region: amf_id_yaml.region.unwrap_or(0),
                set: amf_id_yaml.set.unwrap_or(0),
                pointer: amf_id_yaml.pointer.unwrap_or(0),
            },
        })
    }

    /// Build a runtime ServedTai from its typed YAML representation
    fn resolve_tai(entry: TaiYaml) -> Option<context::ServedTai> {
        let plmn_id = Self::resolve_plmn_id(entry.plmn_id?)?;
        Some(context::ServedTai {
            list0: context::Tai0List {
                plmn_id,
                tac: vec![entry.tac.unwrap_or(0)],
            },
            ..Default::default()
        })
    }

    /// Build a runtime PlmnSupport from its typed YAML representation
    fn resolve_plmn_support(entry: PlmnSupportYaml) -> Option<context::PlmnSupport> {
        let plmn_id = Self::resolve_plmn_id(entry.plmn_id?)?;
        let s_nssai_list: Vec<context::SNssai> = entry
            .s_nssai
            .unwrap_or_default()
            .into_iter()
            .map(|n| context::SNssai {
                sst: n.sst.unwrap_or(1),
                sd: n.sd,
            })
            .collect();
        let num_of_s_nssai = s_nssai_list.len();
        Some(context::PlmnSupport {
            plmn_id,
            num_of_s_nssai,
            s_nssai: s_nssai_list,
        })
    }

    /// Parse integrity algorithm name to ID
    fn parse_integrity_algorithm(name: &str) -> u8 {
        match name.to_uppercase().as_str() {
            "NIA0" => 0,
            "NIA1" | "128-NIA1" => 1,
            "NIA2" | "128-NIA2" => 2,
            "NIA3" | "128-NIA3" => 3,
            _ => 0,
        }
    }

    /// Parse ciphering algorithm name to ID
    fn parse_ciphering_algorithm(name: &str) -> u8 {
        match name.to_uppercase().as_str() {
            "NEA0" => 0,
            "NEA1" | "128-NEA1" => 1,
            "NEA2" | "128-NEA2" => 2,
            "NEA3" | "128-NEA3" => 3,
            _ => 0,
        }
    }

    /// Initialize NGAP server (async)
    pub async fn init_ngap(
        &mut self,
        ngap_addr: SocketAddr,
        sctp_backend: ngap_path::SctpBackend,
    ) -> Result<()> {
        log::info!("Initializing NGAP server on {ngap_addr}...");

        let event_tx = self
            .ngap_event_tx
            .take()
            .ok_or_else(|| anyhow::anyhow!("NGAP event sender already taken"))?;

        ngap_path::amf_ngap_open(
            Some(ngap_addr),
            sctp_backend,
            Arc::clone(&self.amf_context),
            event_tx,
        )
        .await?;

        log::info!("NGAP server initialized on {ngap_addr}");
        Ok(())
    }

    /// Run the AMF main loop (async version)
    pub async fn run_async(&mut self) -> Result<()> {
        log::info!("AMF running (async mode)...");

        // Take the event receiver
        let mut event_rx = self.ngap_event_rx.take();

        // NGAP socket poll cadence: amf_ngap_poll() drives SCTP accept/handshake
        // and reads at most one datagram per call, so this interval bounds the
        // NG Setup handshake latency — it must stay in the milliseconds (a 10s
        // tick made the gNB's SCTP handshake time out).
        let mut ngap_poll = tokio::time::interval(tokio::time::Duration::from_millis(10));

        loop {
            // Drain all pending events without sleeping between them, then
            // block until the next event or heartbeat tick arrives.
            tokio::select! {
                // An event is ready on the mpsc channel — process it immediately.
                Some(event) = async {
                    if let Some(ref mut rx) = event_rx { rx.recv().await } else { None }
                } => {
                    self.handle_event(event).await;
                    // Drain any additional events that arrived back-to-back.
                    if let Some(ref mut rx) = event_rx {
                        while let Ok(event) = rx.try_recv() {
                            self.handle_event(event).await;
                        }
                    }
                }

                // Periodic tick: run NGAP poll and check the shutdown flag.
                _ = ngap_poll.tick() => {
                    if !self.running.load(Ordering::SeqCst) {
                        break;
                    }
                    // Drain everything ready on the socket before yielding.
                    loop {
                        match ngap_path::amf_ngap_poll().await {
                            Ok(true) => log::debug!("Processed NGAP message"),
                            Ok(false) => break,
                            Err(e) => {
                                log::warn!("NGAP poll error: {e}");
                                break;
                            }
                        }
                    }
                }
            }

            if !self.running.load(Ordering::SeqCst) {
                break;
            }
        }

        log::info!("AMF main loop exited");
        Ok(())
    }

    /// Handle an AMF event
    async fn handle_event(&self, event: event::AmfEvent) {
        log::debug!("Handling event: {:?}", event.id);

        match event.id {
            event::AmfEventId::NgapMessage => {
                if let Some(ref ngap_data) = event.ngap {
                    log::debug!("NGAP message event: gnb_id={:?}", ngap_data.gnb_id);
                    // Process through NGAP FSM
                    // Note: Route to appropriate gNB FSM
                    // gNB FSM lookup and dispatch handled by ngap_path and ngap_sm modules
                }
            }
            event::AmfEventId::NgapTimer => {
                log::debug!("NGAP timer event");
            }
            _ => {
                log::debug!("Unhandled event type: {:?}", event.id);
            }
        }
    }

    /// Run the AMF main loop (sync version, for backwards compatibility)
    pub fn run(&self) -> Result<()> {
        log::info!("AMF running...");

        while self.running.load(Ordering::SeqCst) {
            // Process events
            // In a real implementation, this would:
            // 1. Poll for NGAP messages from gNBs
            // 2. Poll for SBI messages from other NFs
            // 3. Process timer events
            // 4. Handle state machine transitions

            // For now, just sleep briefly
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        log::info!("AMF main loop exited");
        Ok(())
    }

    /// Shutdown the AMF application
    pub fn shutdown(&mut self) {
        log::info!("Shutting down AMF...");

        // Close SBI
        sbi_path::amf_sbi_close();

        // Finalize AMF context
        context::amf_context_final();

        log::info!("AMF shutdown complete");
    }

    /// Shutdown the AMF application (async version)
    pub async fn shutdown_async(&mut self) {
        log::info!("Shutting down AMF...");

        // Close NGAP
        ngap_path::amf_ngap_close().await;

        // Close SBI
        sbi_path::amf_sbi_close();

        // Finalize AMF context
        context::amf_context_final();

        log::info!("AMF shutdown complete");
    }

    /// Signal the application to stop
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Get the running flag for signal handlers
    pub fn running_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }

    /// Get metrics reference
    pub fn metrics(&self) -> &metrics::AmfMetrics {
        &self.metrics
    }

    /// Get timer manager reference
    pub fn timer_manager(&self) -> &timer::TimerManager {
        &self.timer_manager
    }

    /// Get AMF context reference
    pub fn amf_context(&self) -> Arc<RwLock<context::AmfContext>> {
        Arc::clone(&self.amf_context)
    }
}

impl Default for AmfApp {
    fn default() -> Self {
        Self::new()
    }
}

#[tokio::main]
pub async fn run() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize logging
    let log_level = match args.log_level.to_lowercase().as_str() {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => log::LevelFilter::Info,
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_millis()
        .init();

    log::info!("NextGCore AMF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Configuration: {}", args.config);

    // Create AMF application
    let mut app = AmfApp::new();

    // Setup signal handlers
    let running = app.running_flag();
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        running.store(false, Ordering::SeqCst);
    })?;

    // Initialize (async)
    app.init(&args.config).await?;

    // Parse NGAP address + SCTP backend and initialize NGAP server
    let ngap_addr: SocketAddr = args
        .ngap_addr
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid NGAP address '{}': {}", args.ngap_addr, e))?;
    let sctp_backend = ngap_path::SctpBackend::parse(&args.sctp_backend)?;
    app.init_ngap(ngap_addr, sctp_backend).await?;

    // Start the Namf SBI HTTP/2 server (TS 29.518: namf-comm, namf-evts,
    // namf-mt, namf-loc) on the advertised SBI endpoint
    let sbi_addr = std::env::var("AMF_SBI_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
    let sbi_port: u16 = std::env::var("AMF_SBI_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7777);
    let sbi_sock: SocketAddr = format!("{sbi_addr}:{sbi_port}")
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid SBI address '{sbi_addr}:{sbi_port}': {e}"))?;
    let mut sbi_server_config = nextgcore_sbi::server::SbiServerConfig::new(sbi_sock);
    if oauth2_required(&args.config) {
        sbi_server_config = apply_oauth2_enforcement(sbi_server_config).await;
    }
    let sbi_server = nextgcore_sbi::server::SbiServer::new(sbi_server_config);
    sbi_server
        .start(namf_server::namf_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start Namf SBI server: {e}"))?;
    log::info!("Namf SBI HTTP/2 server listening on {sbi_sock}");

    // Register with NRF (if configured)
    match sbi_path::amf_nrf_register(&sbi_addr, sbi_port).await {
        Ok(nf_instance_id) if !nf_instance_id.is_empty() => {
            // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
            // (registered UEs vs configured capacity; TS 29.510 §5.2.2.3.2).
            nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(nf_instance_id, 5, || {
                let ctx = crate::context::amf_self();
                let load = ctx.read().map(|c| c.get_ue_load()).unwrap_or(0);
                load.clamp(0, 100) as u8
            });
        }
        Ok(_) => {}
        Err(e) => {
            log::warn!("NRF registration failed (will operate without NRF): {e}");
        }
    }

    // Discover AUSF and SMF from NRF
    if let Err(e) = sbi_path::amf_nrf_discover("AUSF", "nausf-auth").await {
        log::warn!("AUSF discovery failed (will retry on demand): {e}");
    }
    if let Err(e) = sbi_path::amf_nrf_discover("SMF", "nsmf-pdusession").await {
        log::warn!("SMF discovery failed (will retry on demand): {e}");
    }

    log::info!("NextGCore AMF ready");

    // Run async main loop
    app.run_async().await?;

    // Stop the Namf SBI server before tearing the context down
    if let Err(e) = sbi_server.stop().await {
        log::warn!("Failed to stop Namf SBI server: {e}");
    }

    // Shutdown (async version)
    app.shutdown_async().await;

    log::info!("NextGCore AMF terminated");
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amf_app_creation() {
        let app = AmfApp::new();
        assert!(app.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_amf_app_stop() {
        let app = AmfApp::new();
        assert!(app.running.load(Ordering::SeqCst));
        app.stop();
        assert!(!app.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_amf_app_running_flag() {
        let app = AmfApp::new();
        let flag = app.running_flag();
        assert!(flag.load(Ordering::SeqCst));
        app.stop();
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[test]
    fn test_amf_app_metrics() {
        let app = AmfApp::new();
        app.metrics().inc(metrics::GlobalMetric::RmRegInitReq);
        assert_eq!(app.metrics().get(metrics::GlobalMetric::RmRegInitReq), 1);
    }
}

#[cfg(test)]
mod oauth2_h8_tests {
    //! Wave-6 H8 (Phase B) strict-peer OAuth2 enforcement triplet: the real
    //! `namf_server::namf_request_handler` is mounted behind nextgcore-sbi's
    //! server-side OAuth2 verification (TS 33.501 §13.4.1). A missing or
    //! wrong-audience Bearer is rejected (401) before the handler runs; a valid
    //! NRF-audience token (aud=AMF, ES256-signed against the served JWKS) passes.
    use nextgcore_sbi::client::SbiClient;
    use nextgcore_sbi::message::SbiRequest;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use nextgcore_sbi::types::NfType;
    use std::net::SocketAddr;
    use std::time::Duration;

    /// Reserve a loopback port for a test server.
    ///
    /// Delegates to the shared helper: 21 crates each had a private
    /// probe-and-drop copy of this, which is TOCTOU and flaked under parallel
    /// `cargo test`. One implementation means one place to harden.
    fn free_port() -> u16 {
        nextgcore_sbi::test_support::free_port()
    }

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
            "iss": "NRF", "sub": "amf-1", "aud": aud,
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
        crate::context::amf_context_init(64, 1024, 4096);
        let port = free_port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Amf);
        let server = SbiServer::new(cfg);
        server
            .start(crate::namf_server::namf_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    #[test]
    fn test_oauth2_require_knob_parses_and_defaults_off() {
        let dir = std::env::temp_dir();
        let off = dir.join(format!("amf-h8-off-{}.yaml", std::process::id()));
        std::fs::write(
            &off,
            "amf:\n  sbi:\n    client:\n      nrf:\n        - uri: http://x\n",
        )
        .unwrap();
        assert!(!crate::oauth2_required(off.to_str().unwrap()));
        let on = dir.join(format!("amf-h8-on-{}.yaml", std::process::id()));
        std::fs::write(&on, "amf:\n  sbi:\n    oauth2:\n      require: true\n").unwrap();
        assert!(crate::oauth2_required(on.to_str().unwrap()));
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
            client.get("/namf-comm/v1/subscriptions"),
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
        let token = build_es256_token(&sk, "nrf-es256", "UDM", "namf-comm");
        let req = SbiRequest::get("/namf-comm/v1/subscriptions")
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
        let token = build_es256_token(&sk, "nrf-es256", "AMF", "namf-comm");
        let req = SbiRequest::get("/namf-comm/v1/subscriptions/does-not-exist")
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
