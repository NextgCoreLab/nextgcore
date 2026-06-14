//! PCRF Diameter Path
//!
//! Port of src/pcrf/pcrf-fd-path.c - Diameter stack initialization, peer
//! handling and statistics.
//!
//! The PCRF acts as a Diameter server (RFC 6733 responder): PCEFs (P-GW)
//! connect on Gx (TS 29.212) and AFs (P-CSCF) connect on Rx (TS 29.214).
//! Both applications share one listener; incoming requests are dispatched
//! by Application-Id. The PCRF also originates requests (Gx RAR, Rx ASR)
//! over the peer connections established by the remote nodes; answers are
//! matched to the pending request by Hop-by-Hop Identifier.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use ogs_diameter::config::DiameterConfig;
use ogs_diameter::error::DiameterResult;
use ogs_diameter::gx::{cmd as gx_cmd, GX_APPLICATION_ID};
use ogs_diameter::message::DiameterMessage;
use ogs_diameter::peer::{DiameterPeer, PeerEvent, PeerState};
use ogs_diameter::rx::{cmd as rx_cmd, RX_APPLICATION_ID};
use ogs_diameter::transport::{DiameterListener, DiameterTransport};

use crate::gx_path;
use crate::rx_path;

/// Gx interface statistics
#[derive(Debug, Default)]
pub struct PcrfDiamStatsGx {
    /// CCR received count
    pub rx_ccr: AtomicU64,
    /// CCR error count
    pub rx_ccr_error: AtomicU64,
    /// CCA transmitted count
    pub tx_cca: AtomicU64,
    /// RAR transmitted count
    pub tx_rar: AtomicU64,
    /// RAR error count
    pub tx_rar_error: AtomicU64,
    /// RAA received count
    pub rx_raa: AtomicU64,
    /// Unknown message received count
    pub rx_unknown: AtomicU64,
}

impl PcrfDiamStatsGx {
    /// Create new Gx stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset all counters
    pub fn reset(&self) {
        self.rx_ccr.store(0, Ordering::SeqCst);
        self.rx_ccr_error.store(0, Ordering::SeqCst);
        self.tx_cca.store(0, Ordering::SeqCst);
        self.tx_rar.store(0, Ordering::SeqCst);
        self.tx_rar_error.store(0, Ordering::SeqCst);
        self.rx_raa.store(0, Ordering::SeqCst);
        self.rx_unknown.store(0, Ordering::SeqCst);
    }

    /// Increment CCR received
    pub fn inc_rx_ccr(&self) {
        self.rx_ccr.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment CCR error
    pub fn inc_rx_ccr_error(&self) {
        self.rx_ccr_error.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment CCA transmitted
    pub fn inc_tx_cca(&self) {
        self.tx_cca.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment RAR transmitted
    pub fn inc_tx_rar(&self) {
        self.tx_rar.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment RAR error
    pub fn inc_tx_rar_error(&self) {
        self.tx_rar_error.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment RAA received
    pub fn inc_rx_raa(&self) {
        self.rx_raa.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment unknown received
    pub fn inc_rx_unknown(&self) {
        self.rx_unknown.fetch_add(1, Ordering::SeqCst);
    }
}

/// Rx interface statistics
#[derive(Debug, Default)]
pub struct PcrfDiamStatsRx {
    /// AAR received count
    pub rx_aar: AtomicU64,
    /// AAR error count
    pub rx_aar_error: AtomicU64,
    /// AAA transmitted count
    pub tx_aaa: AtomicU64,
    /// STR received count
    pub rx_str: AtomicU64,
    /// STR error count
    pub rx_str_error: AtomicU64,
    /// STA transmitted count
    pub tx_sta: AtomicU64,
    /// ASR transmitted count (Abort-Session-Request)
    pub tx_asr: AtomicU64,
    /// ASA received count (Abort-Session-Answer)
    pub rx_asa: AtomicU64,
    /// Unknown message received count
    pub rx_unknown: AtomicU64,
}

impl PcrfDiamStatsRx {
    /// Create new Rx stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset all counters
    pub fn reset(&self) {
        self.rx_aar.store(0, Ordering::SeqCst);
        self.rx_aar_error.store(0, Ordering::SeqCst);
        self.tx_aaa.store(0, Ordering::SeqCst);
        self.rx_str.store(0, Ordering::SeqCst);
        self.rx_str_error.store(0, Ordering::SeqCst);
        self.tx_sta.store(0, Ordering::SeqCst);
        self.tx_asr.store(0, Ordering::SeqCst);
        self.rx_asa.store(0, Ordering::SeqCst);
        self.rx_unknown.store(0, Ordering::SeqCst);
    }

    /// Increment AAR received
    pub fn inc_rx_aar(&self) {
        self.rx_aar.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment AAR error
    pub fn inc_rx_aar_error(&self) {
        self.rx_aar_error.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment AAA transmitted
    pub fn inc_tx_aaa(&self) {
        self.tx_aaa.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment STR received
    pub fn inc_rx_str(&self) {
        self.rx_str.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment STR error
    pub fn inc_rx_str_error(&self) {
        self.rx_str_error.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment STA transmitted
    pub fn inc_tx_sta(&self) {
        self.tx_sta.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment ASR transmitted
    pub fn inc_tx_asr(&self) {
        self.tx_asr.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment ASA received
    pub fn inc_rx_asa(&self) {
        self.rx_asa.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment unknown received
    pub fn inc_rx_unknown(&self) {
        self.rx_unknown.fetch_add(1, Ordering::SeqCst);
    }
}

/// PCRF Diameter statistics
#[derive(Debug, Default)]
pub struct PcrfDiamStats {
    /// Gx interface stats
    pub gx: PcrfDiamStatsGx,
    /// Rx interface stats
    pub rx: PcrfDiamStatsRx,
}

impl PcrfDiamStats {
    /// Create new PCRF Diameter stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset all statistics
    pub fn reset(&self) {
        self.gx.reset();
        self.rx.reset();
    }

    /// Get summary string
    pub fn summary(&self) -> String {
        format!(
            "Gx: CCR={}/{} CCA={} RAR={}/{} RAA={} | Rx: AAR={}/{} AAA={} STR={}/{} STA={} ASR={} ASA={}",
            self.gx.rx_ccr.load(Ordering::SeqCst),
            self.gx.rx_ccr_error.load(Ordering::SeqCst),
            self.gx.tx_cca.load(Ordering::SeqCst),
            self.gx.tx_rar.load(Ordering::SeqCst),
            self.gx.tx_rar_error.load(Ordering::SeqCst),
            self.gx.rx_raa.load(Ordering::SeqCst),
            self.rx.rx_aar.load(Ordering::SeqCst),
            self.rx.rx_aar_error.load(Ordering::SeqCst),
            self.rx.tx_aaa.load(Ordering::SeqCst),
            self.rx.rx_str.load(Ordering::SeqCst),
            self.rx.rx_str_error.load(Ordering::SeqCst),
            self.rx.tx_sta.load(Ordering::SeqCst),
            self.rx.tx_asr.load(Ordering::SeqCst),
            self.rx.rx_asa.load(Ordering::SeqCst),
        )
    }
}

/// Global PCRF Diameter statistics
static GLOBAL_PCRF_DIAM_STATS: std::sync::OnceLock<Arc<PcrfDiamStats>> = std::sync::OnceLock::new();

/// Get global PCRF Diameter statistics
pub fn pcrf_diam_stats() -> Arc<PcrfDiamStats> {
    GLOBAL_PCRF_DIAM_STATS
        .get_or_init(|| Arc::new(PcrfDiamStats::new()))
        .clone()
}

// ============================================================================
// Local identity
// ============================================================================

/// Local Diameter identity (Origin-Host / Origin-Realm) of this PCRF
#[derive(Debug, Clone)]
pub struct LocalIdentity {
    /// Origin-Host (DiameterIdentity FQDN)
    pub host: String,
    /// Origin-Realm
    pub realm: String,
}

impl Default for LocalIdentity {
    fn default() -> Self {
        Self {
            host: "pcrf.localdomain".to_string(),
            realm: "localdomain".to_string(),
        }
    }
}

static LOCAL_IDENTITY: OnceLock<StdMutex<LocalIdentity>> = OnceLock::new();

fn local_identity_cell() -> &'static StdMutex<LocalIdentity> {
    LOCAL_IDENTITY.get_or_init(|| StdMutex::new(LocalIdentity::default()))
}

/// Set the local Diameter identity (from configuration, before listen)
pub fn pcrf_fd_set_local_identity(identity: LocalIdentity) {
    if let Ok(mut guard) = local_identity_cell().lock() {
        *guard = identity;
    }
}

/// Get the local Diameter identity
pub fn pcrf_local_identity() -> LocalIdentity {
    local_identity_cell()
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default()
}

// ============================================================================
// Peer registry and PCRF-initiated requests
// ============================================================================

/// A PCRF-initiated request handed to a peer connection task
struct OutboundRequest {
    /// The request message; Hop-by-Hop / End-to-End identifiers are
    /// assigned by the owning connection task before sending.
    msg: DiameterMessage,
    /// Channel on which the matched answer is delivered
    resp: oneshot::Sender<DiameterMessage>,
}

type PeerRegistry = StdMutex<HashMap<String, mpsc::Sender<OutboundRequest>>>;

static PEER_REGISTRY: OnceLock<PeerRegistry> = OnceLock::new();

fn peer_registry() -> &'static PeerRegistry {
    PEER_REGISTRY.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn register_peer(origin_host: &str, tx: mpsc::Sender<OutboundRequest>) {
    if let Ok(mut peers) = peer_registry().lock() {
        peers.insert(origin_host.to_string(), tx);
    }
    log::info!("Diameter peer registered: {origin_host}");
}

fn unregister_peer(origin_host: &str) {
    if let Ok(mut peers) = peer_registry().lock() {
        peers.remove(origin_host);
    }
    log::info!("Diameter peer unregistered: {origin_host}");
}

/// Check whether a Diameter peer with the given Origin-Host is connected
pub fn pcrf_fd_peer_connected(origin_host: &str) -> bool {
    peer_registry()
        .lock()
        .map(|peers| peers.contains_key(origin_host))
        .unwrap_or(false)
}

/// Timeout waiting for an answer to a PCRF-initiated request.
/// Mirrors the Tc-scale timers used by the Diameter base machinery in
/// `ogs-diameter`; there is no application-level retransmission (the
/// transport is reliable; on timeout the error is surfaced to the caller).
const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

/// Send a PCRF-initiated request (Gx RAR / Rx ASR) to the peer identified
/// by its Origin-Host and wait for the matched answer.
pub async fn pcrf_fd_send_request(
    peer_host: &str,
    msg: DiameterMessage,
) -> Result<DiameterMessage, String> {
    let tx = peer_registry()
        .lock()
        .map_err(|e| format!("peer registry lock: {e}"))?
        .get(peer_host)
        .cloned()
        .ok_or_else(|| format!("Diameter peer not connected: {peer_host}"))?;

    let (resp_tx, resp_rx) = oneshot::channel();
    tx.send(OutboundRequest { msg, resp: resp_tx })
        .await
        .map_err(|_| format!("Diameter peer connection closed: {peer_host}"))?;

    match tokio::time::timeout(ANSWER_TIMEOUT, resp_rx).await {
        Ok(Ok(answer)) => Ok(answer),
        Ok(Err(_)) => Err(format!("Diameter peer {peer_host} dropped the request")),
        Err(_) => Err(format!(
            "Timeout waiting for answer from Diameter peer {peer_host}"
        )),
    }
}

// ============================================================================
// Request dispatch (by Application-Id / Command-Code)
// ============================================================================

/// Dispatch an incoming Diameter request to the Gx or Rx application
/// handler and return the answer to send.
async fn dispatch_request(msg: DiameterMessage, local: &LocalIdentity) -> DiameterMessage {
    match (msg.header.application_id, msg.header.command_code) {
        (GX_APPLICATION_ID, gx_cmd::CREDIT_CONTROL) => {
            let (cca, abort_targets) = gx_path::handle_ccr(&msg, local);
            // IP-CAN session terminated: abort the bound Rx sessions (ASR)
            for target in abort_targets {
                let local = local.clone();
                tokio::spawn(async move {
                    rx_path::pcrf_rx_send_asr_for_target(&target, &local).await;
                });
            }
            cca
        }
        (GX_APPLICATION_ID, gx_cmd::RE_AUTH) => {
            // The PCRF originates RAR; an incoming RAR is not supported
            pcrf_diam_stats().gx.inc_rx_unknown();
            gx_path::build_unsupported_answer(
                &msg,
                local,
                gx_path::result_code::DIAMETER_COMMAND_UNSUPPORTED,
            )
        }
        (GX_APPLICATION_ID, _) => {
            pcrf_diam_stats().gx.inc_rx_unknown();
            gx_path::build_unsupported_answer(
                &msg,
                local,
                gx_path::result_code::DIAMETER_COMMAND_UNSUPPORTED,
            )
        }
        (RX_APPLICATION_ID, rx_cmd::AA) => rx_path::handle_aar(&msg, local).await,
        (RX_APPLICATION_ID, rx_cmd::SESSION_TERMINATION) => rx_path::handle_str(&msg, local).await,
        (RX_APPLICATION_ID, _) => {
            pcrf_diam_stats().rx.inc_rx_unknown();
            gx_path::build_unsupported_answer(
                &msg,
                local,
                gx_path::result_code::DIAMETER_COMMAND_UNSUPPORTED,
            )
        }
        (app, cmd) => {
            log::warn!("Request for unsupported application {app} (command {cmd})");
            gx_path::build_unsupported_answer(
                &msg,
                local,
                gx_path::result_code::DIAMETER_APPLICATION_UNSUPPORTED,
            )
        }
    }
}

// ============================================================================
// Connection handling
// ============================================================================

/// Generate a pseudo-random u32 to seed Hop-by-Hop / End-to-End sequences
/// (RFC 6733 section 3: implementations SHOULD use a random start value).
fn rand_seed() -> u32 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos.wrapping_mul(2654435761)
}

const MAX_MISSED_WATCHDOGS: u32 = 3;

/// Run a single accepted peer connection: CER/CEA as responder, then
/// process application messages, watchdogs and PCRF-initiated requests.
async fn run_connection(transport: DiameterTransport, config: DiameterConfig) {
    let peer_addr = transport.peer_addr();
    let local = pcrf_local_identity();

    let mut peer = DiameterPeer::new_responder(transport, &config);
    if let Err(e) = peer.start().await {
        log::warn!("Failed to start peer {peer_addr}: {e}");
        return;
    }

    let (out_tx, mut out_rx) = mpsc::channel::<OutboundRequest>(32);
    let mut pending: HashMap<u32, oneshot::Sender<DiameterMessage>> = HashMap::new();
    let mut hop_by_hop: u32 = rand_seed();
    let mut end_to_end: u32 = rand_seed().wrapping_add(0x5555_5555);
    let mut registered: Option<String> = None;
    let mut missed_watchdogs: u32 = 0;

    let mut watchdog = tokio::time::interval(peer.watchdog_interval());
    // The first tick fires immediately; consume it.
    watchdog.tick().await;

    loop {
        tokio::select! {
            event = peer.next_event() => match event {
                Ok(PeerEvent::Established { origin_host, origin_realm }) => {
                    log::info!(
                        "Diameter peer established: host={origin_host}, realm={origin_realm} ({peer_addr})"
                    );
                    register_peer(&origin_host, out_tx.clone());
                    registered = Some(origin_host);
                }
                Ok(PeerEvent::Message(msg)) => {
                    missed_watchdogs = 0;
                    if msg.header.is_request() {
                        let answer = dispatch_request(msg, &local).await;
                        if let Err(e) = peer.send_message(&answer).await {
                            log::warn!("Failed to send answer to {peer_addr}: {e}");
                            break;
                        }
                    } else if let Some(resp) = pending.remove(&msg.header.hop_by_hop_id) {
                        let _ = resp.send(msg);
                    } else {
                        log::warn!(
                            "Unmatched answer (cmd={}, hbh={}) from {peer_addr}",
                            msg.header.command_code,
                            msg.header.hop_by_hop_id
                        );
                    }
                }
                Ok(PeerEvent::WatchdogAck) => {
                    missed_watchdogs = 0;
                }
                Ok(PeerEvent::Disconnected) => {
                    log::info!("Diameter peer disconnected: {peer_addr}");
                    break;
                }
                Err(e) => {
                    log::warn!("Diameter peer error ({peer_addr}): {e}");
                    break;
                }
            },
            Some(out) = out_rx.recv() => {
                hop_by_hop = hop_by_hop.wrapping_add(1);
                end_to_end = end_to_end.wrapping_add(1);
                let mut msg = out.msg;
                msg.header.hop_by_hop_id = hop_by_hop;
                msg.header.end_to_end_id = end_to_end;
                pending.insert(hop_by_hop, out.resp);
                if let Err(e) = peer.send_message(&msg).await {
                    log::warn!("Failed to send request to {peer_addr}: {e}");
                    pending.remove(&hop_by_hop);
                    break;
                }
            },
            _ = watchdog.tick() => {
                if peer.state() == PeerState::Open {
                    if missed_watchdogs >= MAX_MISSED_WATCHDOGS {
                        log::warn!(
                            "Peer {peer_addr} missed {missed_watchdogs} watchdogs, closing"
                        );
                        break;
                    }
                    if let Err(e) = peer.send_watchdog().await {
                        log::warn!("Failed to send watchdog to {peer_addr}: {e}");
                        break;
                    }
                    missed_watchdogs += 1;
                }
            },
        }
    }

    if let Some(host) = registered {
        unregister_peer(&host);
    }
}

// ============================================================================
// Stack init / listen / final
// ============================================================================

/// Initialize the PCRF Diameter stack (synchronous part)
pub fn pcrf_fd_init() -> Result<(), String> {
    log::info!("Initializing PCRF Diameter stack");
    pcrf_diam_stats().reset();
    Ok(())
}

/// Start the PCRF Diameter listener.
///
/// Binds the listener, spawns the accept loop and returns the bound local
/// address. Peer connections (CER/CEA, DWR/DWA, DPR/DPA) are handled per
/// RFC 6733 by `ogs_diameter::peer::DiameterPeer`; application messages
/// are dispatched to the Gx / Rx handlers.
pub async fn pcrf_fd_listen(
    identity: LocalIdentity,
    addr: SocketAddr,
) -> DiameterResult<SocketAddr> {
    pcrf_fd_set_local_identity(identity.clone());

    let config = DiameterConfig {
        diameter_id: identity.host.clone(),
        diameter_realm: identity.realm.clone(),
        ..Default::default()
    };

    let listener = DiameterListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    log::info!(
        "PCRF Diameter listening on {local_addr} as {} (realm {})",
        identity.host,
        identity.realm
    );

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok(transport) => {
                    log::info!(
                        "Accepted Diameter connection from {}",
                        transport.peer_addr()
                    );
                    let config = config.clone();
                    tokio::spawn(run_connection(transport, config));
                }
                Err(e) => {
                    log::warn!("Failed to accept Diameter connection: {e}");
                }
            }
        }
    });

    Ok(local_addr)
}

/// Finalize the PCRF Diameter stack
pub fn pcrf_fd_final() {
    log::info!("Finalizing PCRF Diameter stack");
    log::info!("PCRF Diameter stats: {}", pcrf_diam_stats().summary());
    if let Ok(mut peers) = peer_registry().lock() {
        peers.clear();
    }
    log::info!("PCRF Diameter stack finalized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gx_stats_new() {
        let stats = PcrfDiamStatsGx::new();
        assert_eq!(stats.rx_ccr.load(Ordering::SeqCst), 0);
        assert_eq!(stats.tx_cca.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_gx_stats_increment() {
        let stats = PcrfDiamStatsGx::new();

        stats.inc_rx_ccr();
        assert_eq!(stats.rx_ccr.load(Ordering::SeqCst), 1);

        stats.inc_tx_cca();
        assert_eq!(stats.tx_cca.load(Ordering::SeqCst), 1);

        stats.inc_tx_rar();
        stats.inc_rx_raa();
        assert_eq!(stats.tx_rar.load(Ordering::SeqCst), 1);
        assert_eq!(stats.rx_raa.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_gx_stats_reset() {
        let stats = PcrfDiamStatsGx::new();

        stats.inc_rx_ccr();
        stats.inc_tx_cca();
        stats.reset();

        assert_eq!(stats.rx_ccr.load(Ordering::SeqCst), 0);
        assert_eq!(stats.tx_cca.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_rx_stats_new() {
        let stats = PcrfDiamStatsRx::new();
        assert_eq!(stats.rx_aar.load(Ordering::SeqCst), 0);
        assert_eq!(stats.tx_aaa.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_rx_stats_increment() {
        let stats = PcrfDiamStatsRx::new();

        stats.inc_rx_aar();
        assert_eq!(stats.rx_aar.load(Ordering::SeqCst), 1);

        stats.inc_tx_aaa();
        assert_eq!(stats.tx_aaa.load(Ordering::SeqCst), 1);

        stats.inc_rx_str();
        stats.inc_tx_sta();
        assert_eq!(stats.rx_str.load(Ordering::SeqCst), 1);
        assert_eq!(stats.tx_sta.load(Ordering::SeqCst), 1);

        stats.inc_tx_asr();
        stats.inc_rx_asa();
        assert_eq!(stats.tx_asr.load(Ordering::SeqCst), 1);
        assert_eq!(stats.rx_asa.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_pcrf_diam_stats() {
        let stats = PcrfDiamStats::new();

        stats.gx.inc_rx_ccr();
        stats.gx.inc_tx_cca();
        stats.rx.inc_rx_aar();
        stats.rx.inc_tx_aaa();

        let summary = stats.summary();
        assert!(summary.contains("CCR=1"));
        assert!(summary.contains("CCA=1"));
        assert!(summary.contains("AAR=1"));
        assert!(summary.contains("AAA=1"));
    }

    #[test]
    fn test_pcrf_fd_init_final() {
        // Test initialization
        let result = pcrf_fd_init();
        assert!(result.is_ok());

        // Test finalization
        pcrf_fd_final();
    }
}
