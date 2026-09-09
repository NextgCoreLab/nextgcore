//! HSS S6a Diameter Path
//!
//! Port of src/hss/hss-s6a-path.c - S6a interface handlers for EPC (TS 29.272)
//! Handles AIR (Authentication-Information-Request), ULR (Update-Location-Request),
//! PUR (Purge-UE-Request) and transmits CLR (Cancel-Location-Request) and
//! IDR (Insert-Subscriber-Data-Request) towards the MME.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};

use nextgcore_diameter::s6a::{self, EUtranVector};
use nextgcore_diameter::{avp_code, Avp, AvpData, DiameterMessage, NEXTGCORE_3GPP_VENDOR_ID};

use crate::fd_path::diam_stats;

/// S6a Application ID
pub const NEXTGCORE_DIAM_S6A_APPLICATION_ID: u32 = 16777251;

/// 48-bit SQN mask (TS 33.102)
const SQN_MASK: u64 = 0xFFFF_FFFF_FFFF;

/// SQN increment per generated vector (matches nextgcore_dbi_increment_sqn step)
const SQN_STEP: u64 = 32;

/// Maximum number of E-UTRAN vectors generated per AIR
const MAX_VECTORS_PER_AIR: u32 = 4;

/// S6a Cancellation Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationType {
    /// MME Update Procedure
    MmeUpdateProcedure = 0,
    /// SGSN Update Procedure
    SgsnUpdateProcedure = 1,
    /// Subscription Withdrawal
    SubscriptionWithdrawal = 2,
    /// Update Procedure IWF
    UpdateProcedureIwf = 3,
    /// Initial Attach Procedure
    InitialAttachProcedure = 4,
}

impl From<u32> for CancellationType {
    fn from(value: u32) -> Self {
        match value {
            0 => CancellationType::MmeUpdateProcedure,
            1 => CancellationType::SgsnUpdateProcedure,
            2 => CancellationType::SubscriptionWithdrawal,
            3 => CancellationType::UpdateProcedureIwf,
            4 => CancellationType::InitialAttachProcedure,
            _ => CancellationType::SubscriptionWithdrawal,
        }
    }
}

/// S6a Subscription Data Mask flags
pub const NEXTGCORE_DIAM_S6A_SUBDATA_MSISDN: u32 = 0x0001;
pub const NEXTGCORE_DIAM_S6A_SUBDATA_ARD: u32 = 0x0002;
pub const NEXTGCORE_DIAM_S6A_SUBDATA_SUB_STATUS: u32 = 0x0004;
pub const NEXTGCORE_DIAM_S6A_SUBDATA_OP_DET_BARRING: u32 = 0x0008;
pub const NEXTGCORE_DIAM_S6A_SUBDATA_NAM: u32 = 0x0010;
pub const NEXTGCORE_DIAM_S6A_SUBDATA_UEAMBR: u32 = 0x0020;
pub const NEXTGCORE_DIAM_S6A_SUBDATA_RAU_TAU_TIMER: u32 = 0x0040;
pub const NEXTGCORE_DIAM_S6A_SUBDATA_APN_CONFIG: u32 = 0x0080;
pub const NEXTGCORE_DIAM_S6A_SUBDATA_ALL: u32 = 0xFFFF;

/// S6a Result Codes
pub const NEXTGCORE_DIAM_S6A_ERROR_USER_UNKNOWN: u32 = 5001;
pub const NEXTGCORE_DIAM_S6A_AUTHENTICATION_DATA_UNAVAILABLE: u32 = 4181;

// ============================================================================
// Failure model (TS 29.272 7.4 + RFC 6733 7.1)
// ============================================================================

/// S6a procedure failure. Each variant maps to the spec-defined answer codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S6aFailure {
    /// DIAMETER_MISSING_AVP (5005)
    MissingAvp,
    /// DIAMETER_COMMAND_UNSUPPORTED (3001, protocol error: E-bit)
    UnsupportedCommand,
    /// DIAMETER_ERROR_USER_UNKNOWN (Experimental 5001)
    UserUnknown,
    /// DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE (Experimental 4181)
    AuthDataUnavailable,
    /// DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION (Experimental 5420)
    UnknownEpsSubscription,
    /// DIAMETER_UNABLE_TO_COMPLY (5012)
    UnableToComply(String),
}

impl S6aFailure {
    /// Returns (Result-Code, Experimental-Result-Code) for the answer.
    pub fn codes(&self) -> (Option<u32>, Option<u32>) {
        match self {
            S6aFailure::MissingAvp => (Some(5005), None),
            S6aFailure::UnsupportedCommand => (Some(3001), None),
            S6aFailure::UserUnknown => (None, Some(s6a::exp_result::ERROR_USER_UNKNOWN)),
            S6aFailure::AuthDataUnavailable => {
                (None, Some(s6a::exp_result::AUTHENTICATION_DATA_UNAVAILABLE))
            }
            S6aFailure::UnknownEpsSubscription => {
                (None, Some(s6a::exp_result::ERROR_UNKNOWN_EPS_SUBSCRIPTION))
            }
            S6aFailure::UnableToComply(_) => (Some(5012), None),
        }
    }

    /// Protocol errors (3xxx) set the E-bit in the answer header (RFC 6733 7.2)
    pub fn is_protocol_error(&self) -> bool {
        matches!(self.codes().0, Some(code) if (3000..4000).contains(&code))
    }
}

fn map_dbi_error(e: &nextgcore_dbi::DbiError) -> S6aFailure {
    match e {
        nextgcore_dbi::DbiError::SubscriberNotFound(_) => S6aFailure::UserUnknown,
        other => S6aFailure::UnableToComply(other.to_string()),
    }
}

// ============================================================================
// Local Diameter identity (Origin-Host / Origin-Realm)
// ============================================================================

fn local_identity() -> &'static RwLock<(String, String)> {
    static IDENTITY: OnceLock<RwLock<(String, String)>> = OnceLock::new();
    IDENTITY.get_or_init(|| {
        RwLock::new((
            "hss.epc.mnc001.mcc001.3gppnetwork.org".to_string(),
            "epc.mnc001.mcc001.3gppnetwork.org".to_string(),
        ))
    })
}

/// Set the HSS Diameter identity used in Origin-Host/Origin-Realm AVPs.
/// Must be called at startup from the loaded configuration.
pub fn hss_s6a_set_identity(origin_host: &str, origin_realm: &str) {
    let mut guard = local_identity().write().expect("identity lock poisoned");
    *guard = (origin_host.to_string(), origin_realm.to_string());
}

fn origin_host_realm() -> (String, String) {
    local_identity()
        .read()
        .expect("identity lock poisoned")
        .clone()
}

/// Generate a unique Session-Id (RFC 6733 8.8: <DiameterIdentity>;<high>;<low>)
fn next_session_id(suffix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let (host, _) = origin_host_realm();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{host};{now};{count};{suffix}")
}

/// Next Hop-by-Hop / End-to-End identifiers for HSS-initiated requests
/// (RFC 6733 Section 3: unique, seeded from time at startup).
fn next_request_ids() -> (u32, u32) {
    static IDS: OnceLock<AtomicU32> = OnceLock::new();
    let counter = IDS.get_or_init(|| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        AtomicU32::new((now.as_secs() as u32) << 20 | (now.subsec_nanos() & 0xFFFFF))
    });
    let id = counter.fetch_add(1, Ordering::Relaxed);
    (id, id)
}

// ============================================================================
// MME peer registry (for HSS-initiated CLR/IDR)
// ============================================================================

type PeerSenders = HashMap<String, tokio::sync::mpsc::UnboundedSender<DiameterMessage>>;

fn peer_registry() -> &'static RwLock<PeerSenders> {
    static REGISTRY: OnceLock<RwLock<PeerSenders>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Register a connected MME peer's outbound channel (keyed by Origin-Host).
pub fn register_mme_peer(
    origin_host: &str,
    sender: tokio::sync::mpsc::UnboundedSender<DiameterMessage>,
) {
    peer_registry()
        .write()
        .expect("peer registry lock poisoned")
        .insert(origin_host.to_string(), sender);
    log::info!("S6a peer registered: {origin_host}");
    // #56: deliver anything that was queued while this peer was disconnected,
    // rather than leaving it to time out against a link that is now up. Called
    // after the registry insert so `send_to_mme` can find the new sender.
    requeue_for_peer(origin_host);
    // #56: and, if this process came up from an unclean shutdown, tell this MME so
    // it re-runs Update Location (TS 29.272 §5.2.3, TS 23.007).
    send_restart_reset_if_armed(origin_host);
}

// ============================================================================
// #56: HSS restart restoration (TS 29.272 §5.2.3, TS 23.007)
// ============================================================================

/// How long after startup an arriving MME is still told about the restart.
///
/// Bounded rather than for the process lifetime: an MME that reconnects an hour
/// later has already re-run Update Location as part of reconnecting, so a Reset
/// then would ask it to redo work it has done. Five minutes covers the reconnect
/// storm that follows a restart.
pub const RESTART_RESET_WINDOW_SECS: u64 = 300;

struct RestartResetState {
    armed: bool,
    armed_at: std::time::Instant,
    user_ids: Vec<String>,
}

fn restart_reset_state() -> &'static RwLock<RestartResetState> {
    static STATE: OnceLock<RwLock<RestartResetState>> = OnceLock::new();
    STATE.get_or_init(|| {
        RwLock::new(RestartResetState {
            armed: false,
            armed_at: std::time::Instant::now(),
            user_ids: Vec::new(),
        })
    })
}

/// Arm restart restoration: every MME that registers within
/// [`RESTART_RESET_WINDOW_SECS`] is sent a Reset-Request (#56).
///
/// Armed rather than sent immediately because at startup **no MME is connected
/// yet** — the HSS is the responder on S6a, so the peers arrive afterwards. Sending
/// at startup would reliably send to nobody, which is the shape of a procedure that
/// looks implemented and never fires.
pub fn arm_restart_reset(user_ids: Vec<String>) {
    if let Ok(mut state) = restart_reset_state().write() {
        state.armed = true;
        state.armed_at = std::time::Instant::now();
        state.user_ids = user_ids;
        log::warn!(
            "HSS restart restoration armed: MMEs registering in the next {}s will be sent a \
             Reset-Request (TS 29.272 §5.2.3)",
            RESTART_RESET_WINDOW_SECS
        );
    }
}

/// Test-only: disarm restart restoration.
///
/// `arm_restart_reset` installs process-global state that stays armed for
/// `RESTART_RESET_WINDOW_SECS`, so a test that arms it and does not disarm makes
/// every LATER test that registers an MME peer receive an unexpected
/// Reset-Request first. That is exactly how three sibling tests broke while this
/// was being written.
#[cfg(test)]
pub(crate) fn disarm_restart_reset() {
    if let Ok(mut state) = restart_reset_state().write() {
        state.armed = false;
        state.user_ids.clear();
    }
}

/// Whether restart restoration is still armed.
pub fn restart_reset_armed() -> bool {
    restart_reset_state()
        .read()
        .map(|s| {
            s.armed
                && s.armed_at.elapsed() < std::time::Duration::from_secs(RESTART_RESET_WINDOW_SECS)
        })
        .unwrap_or(false)
}

/// Send a Reset-Request to a freshly registered MME if restart restoration is armed.
fn send_restart_reset_if_armed(origin_host: &str) {
    if !restart_reset_armed() {
        return;
    }
    let user_ids = restart_reset_state()
        .read()
        .map(|s| s.user_ids.clone())
        .unwrap_or_default();
    let realm = origin_host
        .split_once('.')
        .map(|(_, r)| r)
        .unwrap_or(origin_host);
    let rsr = build_rsr_request(origin_host, realm, &user_ids);
    match send_tracked(origin_host, rsr) {
        Ok(()) => {
            log::info!("HSS restart Reset-Request sent to newly registered MME {origin_host}")
        }
        Err(e) => log::warn!("HSS restart Reset-Request to {origin_host} failed: {e}"),
    }
}

/// Decide whether this start follows an unclean shutdown, from the presence of a
/// running-marker file (#56).
///
/// Pure so the three cases are testable without touching a filesystem at a fixed
/// path: the marker is absent (first start, or a clean previous shutdown), present
/// (the previous run did not remove it, so it died), or the path is unusable.
///
/// A marker that cannot be *created* is reported as `false`: refusing to start, or
/// declaring every start unclean, would be worse than not detecting a crash — a
/// spurious Reset makes every MME re-run Update Location for its whole subscriber
/// base.
pub fn unclean_shutdown_from_marker(marker_existed: bool) -> bool {
    marker_existed
}

/// The running-marker path. `HSS_RUNTIME_DIR` overrides the default so a test, or a
/// deployment without `/var/run/nextgcore`, can point it somewhere writable.
pub fn running_marker_path() -> std::path::PathBuf {
    let dir = std::env::var("HSS_RUNTIME_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "/var/run/nextgcore".to_string());
    std::path::Path::new(&dir).join("hssd-running")
}

/// Claim the running marker, returning whether the previous run left one behind
/// (i.e. whether this start follows an unclean shutdown).
pub fn claim_running_marker() -> bool {
    let path = running_marker_path();
    let existed = path.exists();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&path, b"running\n") {
        log::warn!(
            "HSS could not write the running marker at {}: {e}. Crash detection is therefore \
             disabled for this run, and an unclean shutdown will NOT trigger a Reset.",
            path.display()
        );
        return false;
    }
    existed
}

/// Release the running marker on a clean shutdown, so the next start does not read
/// it as a crash.
pub fn release_running_marker() {
    let path = running_marker_path();
    if let Err(e) = std::fs::remove_file(&path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            log::warn!(
                "HSS could not remove the running marker at {}: {e}. The next start will treat \
                 this shutdown as unclean and send a Reset.",
                path.display()
            );
        }
    }
}

/// Unregister an MME peer on disconnect.
pub fn unregister_mme_peer(origin_host: &str) {
    peer_registry()
        .write()
        .expect("peer registry lock poisoned")
        .remove(origin_host);
    log::info!("S6a peer unregistered: {origin_host}");
}

/// Send an HSS-initiated request to a connected MME peer.
fn send_to_mme(dest_host: &str, msg: DiameterMessage) -> Result<(), String> {
    let registry = peer_registry().read().expect("peer registry lock poisoned");
    let sender = registry
        .get(dest_host)
        .ok_or_else(|| format!("no connected S6a peer for {dest_host}"))?;
    sender
        .send(msg)
        .map_err(|_| format!("S6a peer connection to {dest_host} is closed"))
}

// ============================================================================
// #56: outstanding HSS-initiated requests (RFC 6733 §5.5.4)
// ============================================================================

/// Default Tc-scale retransmission period for an unanswered HSS-initiated
/// request, in seconds. RFC 6733 §12 gives Tc = 30s as the connection timer; the
/// same scale is used here because an S6a peer that has not answered a CLR within
/// that window is either overloaded or gone, and a faster retry adds load to a node
/// that is already struggling.
pub const HSS_INITIATED_RETRANSMIT_SECS: u64 = 30;

/// Maximum transmissions of one HSS-initiated request (the first send plus
/// retries). Bounded because an MME that never answers must not be retried
/// forever: TS 29.272 gives the HSS no obligation beyond a reasonable attempt, and
/// an unbounded queue is a memory leak with a Diameter interface attached.
pub const HSS_INITIATED_MAX_ATTEMPTS: u32 = 3;

/// One HSS-initiated request awaiting its answer.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    /// Session-Id, which is what the answer is correlated on (RFC 6733 §8.8)
    pub session_id: String,
    /// Destination-Host the request was addressed to
    pub dest_host: String,
    /// Command code, for logging and for stats attribution
    pub command_code: u32,
    /// The message itself, kept so it can be retransmitted or requeued verbatim
    pub message: DiameterMessage,
    /// Transmissions so far, including the first
    pub attempts: u32,
    /// Monotonic instant of the last transmission
    pub last_sent: std::time::Instant,
    /// True while the peer is disconnected: the request waits for reconnection
    /// rather than counting down its retries against a socket that does not exist.
    pub awaiting_peer: bool,
}

type PendingTable = HashMap<String, PendingRequest>;

fn pending_requests() -> &'static RwLock<PendingTable> {
    static PENDING: OnceLock<RwLock<PendingTable>> = OnceLock::new();
    PENDING.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Extract the Session-Id from a message, which is the correlation key.
fn message_session_id(msg: &DiameterMessage) -> Option<String> {
    msg.session_id().map(|s| s.to_string())
}

/// Send an HSS-initiated request and record it as outstanding (#56).
///
/// Replaces the previous fire-and-forget `send_to_mme` for the CLR/IDR/DSR/RSR
/// paths. Two behaviour changes, both required by the issue:
///
/// * The request is **tracked** by Session-Id, so its answer can be correlated and
///   a missing answer can be retransmitted. Before this, `handle_s6a_answer` only
///   incremented a counter, so nothing could tell an answered request from a lost
///   one.
/// * A request for a **disconnected** peer is **queued**, not dropped. Before, any
///   momentary link loss silently discarded the procedure — so even the reactive
///   half of S6a was unreliable under transient loss.
fn send_tracked(dest_host: &str, msg: DiameterMessage) -> Result<(), String> {
    let session_id = message_session_id(&msg)
        .ok_or_else(|| "HSS-initiated request has no Session-Id to correlate on".to_string())?;
    let command_code = msg.header.command_code;

    let send_result = send_to_mme(dest_host, msg.clone());
    let awaiting_peer = send_result.is_err();

    {
        let mut pending = pending_requests()
            .write()
            .expect("pending request table lock poisoned");
        pending.insert(
            session_id.clone(),
            PendingRequest {
                session_id: session_id.clone(),
                dest_host: dest_host.to_string(),
                command_code,
                message: msg,
                // A queued request has not been transmitted, so it has made no
                // attempt yet: counting the failed send would spend a retry on a
                // socket that never existed.
                attempts: if awaiting_peer { 0 } else { 1 },
                last_sent: std::time::Instant::now(),
                awaiting_peer,
            },
        );
    }

    match send_result {
        Ok(()) => Ok(()),
        Err(e) => {
            log::warn!(
                "S6a request (cmd={command_code}) to {dest_host} queued for reconnection: {e}"
            );
            // Queued, not failed: the caller's procedure is still in flight.
            Ok(())
        }
    }
}

/// Complete an outstanding request whose answer has arrived.
/// Returns the request if it was outstanding.
fn complete_pending(session_id: &str) -> Option<PendingRequest> {
    pending_requests()
        .write()
        .expect("pending request table lock poisoned")
        .remove(session_id)
}

/// Number of outstanding HSS-initiated requests.
pub fn pending_request_count() -> usize {
    pending_requests().read().map(|p| p.len()).unwrap_or(0)
}

/// What a sweep of the pending table decided to do with one request (#56).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingAction {
    /// Leave it alone: its retransmission timer has not expired.
    Wait,
    /// Retransmit it now.
    Retransmit,
    /// Give up: it has used all its attempts.
    Abandon,
}

/// Decide what to do with one outstanding request, given how long ago it was sent
/// and whether its peer is connected (#56).
///
/// Pure, so every branch is testable without a socket, a timer or a peer.
///
/// A request whose peer is **disconnected** is neither retransmitted nor abandoned
/// while it waits — that is the requeue case, and spending its retry budget against
/// a peer that is not there would abandon it before the peer ever comes back. Once
/// the peer reconnects, `requeue_for_peer` clears the flag and the normal timer
/// applies.
pub fn decide_pending_action(
    attempts: u32,
    elapsed: std::time::Duration,
    peer_connected: bool,
    awaiting_peer: bool,
    retransmit_period: std::time::Duration,
    max_attempts: u32,
) -> PendingAction {
    if awaiting_peer || !peer_connected {
        return PendingAction::Wait;
    }
    if attempts >= max_attempts {
        return PendingAction::Abandon;
    }
    if elapsed < retransmit_period {
        return PendingAction::Wait;
    }
    PendingAction::Retransmit
}

/// Is this peer currently connected?
fn peer_connected(dest_host: &str) -> bool {
    peer_registry()
        .read()
        .map(|r| r.contains_key(dest_host))
        .unwrap_or(false)
}

/// Sweep the outstanding-request table once: retransmit what is due, abandon what
/// has exhausted its attempts (#56, RFC 6733 §5.5.4).
///
/// Returns `(retransmitted, abandoned)`.
pub fn sweep_pending_requests() -> (usize, usize) {
    let period = std::time::Duration::from_secs(HSS_INITIATED_RETRANSMIT_SECS);
    let now = std::time::Instant::now();

    // Decide under the read lock, act after it drops: `send_to_mme` takes the peer
    // registry lock, and holding the pending-table write lock across it is the
    // AB-BA shape this crate already documents elsewhere.
    let decisions: Vec<(String, PendingAction)> = {
        let pending = match pending_requests().read() {
            Ok(p) => p,
            Err(_) => return (0, 0),
        };
        pending
            .values()
            .map(|req| {
                let action = decide_pending_action(
                    req.attempts,
                    now.saturating_duration_since(req.last_sent),
                    peer_connected(&req.dest_host),
                    req.awaiting_peer,
                    period,
                    HSS_INITIATED_MAX_ATTEMPTS,
                );
                (req.session_id.clone(), action)
            })
            .collect()
    };

    let mut retransmitted = 0usize;
    let mut abandoned = 0usize;
    for (session_id, action) in decisions {
        match action {
            PendingAction::Wait => {}
            PendingAction::Retransmit => {
                let to_send = {
                    let pending = pending_requests()
                        .read()
                        .expect("pending request table lock poisoned");
                    pending
                        .get(&session_id)
                        .map(|r| (r.dest_host.clone(), r.message.clone()))
                };
                if let Some((dest_host, msg)) = to_send {
                    match send_to_mme(&dest_host, msg) {
                        Ok(()) => {
                            if let Ok(mut pending) = pending_requests().write() {
                                if let Some(req) = pending.get_mut(&session_id) {
                                    req.attempts += 1;
                                    req.last_sent = std::time::Instant::now();
                                }
                            }
                            retransmitted += 1;
                            log::info!("S6a request {session_id} retransmitted to {dest_host}");
                        }
                        Err(e) => {
                            // The peer went away between the decision and the send.
                            // Park it rather than burning an attempt.
                            if let Ok(mut pending) = pending_requests().write() {
                                if let Some(req) = pending.get_mut(&session_id) {
                                    req.awaiting_peer = true;
                                }
                            }
                            log::warn!("S6a retransmission to {dest_host} deferred: {e}");
                        }
                    }
                }
            }
            PendingAction::Abandon => {
                if let Some(req) = complete_pending(&session_id) {
                    abandoned += 1;
                    log::error!(
                        "S6a request (cmd={}) to {} abandoned after {} attempts with no answer: \
                         MME subscriber state may now diverge from the HSS",
                        req.command_code,
                        req.dest_host,
                        req.attempts
                    );
                }
            }
        }
    }
    (retransmitted, abandoned)
}

/// Flush everything queued for `dest_host` now that it has reconnected (#56).
///
/// Called from the peer registration path, so a CLR or IDR that could not be
/// delivered during a link outage is delivered when the link returns rather than
/// being lost.
pub fn requeue_for_peer(dest_host: &str) -> usize {
    let queued: Vec<(String, DiameterMessage)> = {
        let pending = match pending_requests().read() {
            Ok(p) => p,
            Err(_) => return 0,
        };
        pending
            .values()
            .filter(|r| r.awaiting_peer && r.dest_host == dest_host)
            .map(|r| (r.session_id.clone(), r.message.clone()))
            .collect()
    };
    if queued.is_empty() {
        return 0;
    }

    let mut sent = 0usize;
    for (session_id, msg) in queued {
        if send_to_mme(dest_host, msg).is_ok() {
            if let Ok(mut pending) = pending_requests().write() {
                if let Some(req) = pending.get_mut(&session_id) {
                    req.awaiting_peer = false;
                    req.attempts += 1;
                    req.last_sent = std::time::Instant::now();
                }
            }
            sent += 1;
        }
    }
    if sent > 0 {
        log::info!("S6a: {sent} queued request(s) delivered to reconnected peer {dest_host}");
    }
    sent
}

/// Test-only: empty the outstanding-request table.
///
/// Tests share this process-global table, so each test that inspects it clears it
/// FIRST rather than assuming it starts empty — a sibling's leftover entry would
/// otherwise show up as this test's.
#[cfg(test)]
pub(crate) fn clear_pending_requests() {
    if let Ok(mut pending) = pending_requests().write() {
        pending.clear();
    }
}

/// Initialize S6a interface
pub fn hss_s6a_init() -> Result<(), String> {
    log::info!("Initializing HSS S6a interface");
    Ok(())
}

/// Finalize S6a interface
pub fn hss_s6a_final() {
    log::info!("Finalizing HSS S6a interface");
}

// ============================================================================
// Authentication vector generation (AIR -> AIA)
// ============================================================================

/// Generate a fresh, cryptographically random RAND for each vector
/// (TS 33.401: RAND must not be fixed or reused).
fn fresh_rand() -> [u8; 16] {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::rng().fill_bytes(&mut buf);
    buf
}

fn sqn_to_bytes(sqn: u64) -> [u8; 6] {
    [
        ((sqn >> 40) & 0xFF) as u8,
        ((sqn >> 32) & 0xFF) as u8,
        ((sqn >> 24) & 0xFF) as u8,
        ((sqn >> 16) & 0xFF) as u8,
        ((sqn >> 8) & 0xFF) as u8,
        (sqn & 0xFF) as u8,
    ]
}

/// Verify an AUTS re-synchronisation token and extract SQN_MS
/// (TS 33.102 6.3.5: AUTS = SQN_MS xor AK* || MAC-S, MAC-S = f1*(SQN_MS, RAND, AMF=0)).
///
/// `rand` is the RAND of the challenge that failed synchronisation
/// (carried in Re-Synchronization-Info alongside AUTS).
pub fn process_resync(
    opc: &[u8; 16],
    k: &[u8; 16],
    rand: &[u8; 16],
    auts: &[u8; 14],
) -> Result<u64, S6aFailure> {
    use nextgcore_crypt::milenage::milenage_auts;

    let sqn_ms = milenage_auts(opc, k, rand, auts).map_err(|_| {
        log::warn!("AUTS re-synchronisation failed: MAC-S mismatch");
        S6aFailure::AuthDataUnavailable
    })?;

    let mut sqn = 0u64;
    for b in sqn_ms {
        sqn = (sqn << 8) | b as u64;
    }
    Ok(sqn)
}

/// AIR Response: one or more E-UTRAN authentication vectors
#[derive(Debug, Default)]
pub struct AirResponse {
    /// Generated E-UTRAN vectors (ordered; Item-Number = index + 1)
    pub vectors: Vec<EUtranVector>,
}

/// Handle Authentication-Information-Request (AIR)
///
/// # Arguments
/// * `imsi_bcd` - IMSI in BCD format
/// * `visited_plmn_id` - 3-byte Visited-PLMN-Id from the AIR
/// * `resync` - (RAND, AUTS) from Re-Synchronization-Info, if present
/// * `num_vectors` - Number-Of-Requested-Vectors from the AIR
pub fn handle_air(
    imsi_bcd: &str,
    visited_plmn_id: &[u8],
    resync: Option<([u8; 16], [u8; 14])>,
    num_vectors: u32,
) -> Result<AirResponse, S6aFailure> {
    log::debug!("[{imsi_bcd}] Handling AIR (vectors={num_vectors})");

    use nextgcore_crypt::kdf::nextgcore_auc_kasme;
    use nextgcore_crypt::milenage::{milenage_f1, milenage_f2345, milenage_opc};
    use nextgcore_dbi::{nextgcore_dbi_auth_info, nextgcore_dbi_update_sqn};

    // 1. Get auth info from DB (K, OPc, SQN, AMF)
    let supi = format!("imsi-{imsi_bcd}");
    let auth_info = nextgcore_dbi_auth_info(&supi).map_err(|e| map_dbi_error(&e))?;

    // 2. Compute OPc from OP if needed
    let opc = if auth_info.use_opc {
        auth_info.opc
    } else {
        milenage_opc(&auth_info.k, &auth_info.op)
            .map_err(|_| S6aFailure::UnableToComply("OPc computation failed".into()))?
    };

    // 3. Re-synchronise SQN from AUTS if requested (real f1*/f5* verification,
    //    not a blind SQN bump)
    let mut sqn = auth_info.sqn & SQN_MASK;
    if let Some((auts_rand, auts)) = resync {
        log::debug!("[{imsi_bcd}] Performing AUTS-based SQN re-synchronisation");
        let sqn_ms = process_resync(&opc, &auth_info.k, &auts_rand, &auts)?;
        log::debug!("[{imsi_bcd}] Re-sync OK: SQN_HE={sqn:#x} -> SQN_MS={sqn_ms:#x}");
        sqn = sqn_ms;
    }

    // 4. Generate the requested number of vectors, each with a fresh random
    //    RAND and a strictly increasing SQN
    let n = num_vectors.clamp(1, MAX_VECTORS_PER_AIR);
    let plmn_id: [u8; 3] = [
        visited_plmn_id.first().copied().unwrap_or(0),
        visited_plmn_id.get(1).copied().unwrap_or(0),
        visited_plmn_id.get(2).copied().unwrap_or(0),
    ];

    let mut vectors = Vec::with_capacity(n as usize);
    for _ in 0..n {
        sqn = sqn.wrapping_add(SQN_STEP) & SQN_MASK;
        let sqn_bytes = sqn_to_bytes(sqn);
        let rand = fresh_rand();

        let (mac_a, _mac_s) = milenage_f1(&opc, &auth_info.k, &rand, &sqn_bytes, &auth_info.amf)
            .map_err(|_| S6aFailure::UnableToComply("f1 computation failed".into()))?;
        let (res, ck, ik, ak, _ak_star) = milenage_f2345(&opc, &auth_info.k, &rand)
            .map_err(|_| S6aFailure::UnableToComply("f2-f5 computation failed".into()))?;

        // AUTN = SQN ^ AK || AMF || MAC-A
        let mut autn = [0u8; 16];
        for i in 0..6 {
            autn[i] = sqn_bytes[i] ^ ak[i];
        }
        autn[6..8].copy_from_slice(&auth_info.amf);
        autn[8..16].copy_from_slice(&mac_a);

        let kasme = nextgcore_auc_kasme(&ck, &ik, &plmn_id, &sqn_bytes, &ak);

        vectors.push(EUtranVector {
            rand,
            xres: res.to_vec(),
            autn,
            kasme,
        });
    }

    // 5. Persist the new SQN
    nextgcore_dbi_update_sqn(&supi, sqn).map_err(|e| map_dbi_error(&e))?;

    Ok(AirResponse { vectors })
}

// ============================================================================
// Update-Location (ULR -> ULA)
// ============================================================================

/// ULR Response: subscription data for the ULA
#[derive(Debug, Default)]
pub struct UlrResponse {
    /// EPS subscription data (encoded as a grouped Subscription-Data AVP)
    pub subscription_data: s6a::SubscriptionData,
}

/// Convert the database subscription record into the S6a typed model
/// (TS 29.272 7.3.2 Subscription-Data).
pub fn subscription_data_from_db(
    db: &nextgcore_dbi::NextgcoreSubscriptionData,
) -> s6a::SubscriptionData {
    let mut sub = s6a::SubscriptionData {
        subscriber_status: db.subscriber_status as u32,
        operator_determined_barring: if db.subscriber_status == 1 {
            Some(db.operator_determined_barring as u32)
        } else {
            None
        },
        access_restriction_data: Some(db.access_restriction_data as u32),
        network_access_mode: db.network_access_mode as u32,
        subscribed_rau_tau_timer: (db.subscribed_rau_tau_timer.max(0) as u32) * 60, // minutes -> seconds
        ambr_uplink: db.ambr.uplink,
        ambr_downlink: db.ambr.downlink,
        context_identifier: 1,
        all_apn_configs_included: true,
        // #56: sourced from the subscriber record instead of the hardcoded `None`
        // it used to be, so the AVP is actually sent when one is provisioned. A
        // value that is not a valid 4-hex-char charging class is REFUSED rather
        // than sent mangled: a wrong charging class is a billing error, and the
        // warning names the subscriber so an operator can fix the provisioning.
        charging_characteristics: db.charging_characteristics.as_deref().and_then(|s| {
            let parsed = s6a::ChargingCharacteristics::parse_hex(s);
            if parsed.is_none() {
                log::warn!(
                    "[{}] provisioned charging_characteristics '{s}' is not 4 hexadecimal \
                     characters (TS 29.061 §16.4.7.2); omitting the AVP",
                    db.imsi.as_deref().unwrap_or("?")
                );
            }
            parsed
        }),
        ..Default::default()
    };

    if let Some(m) = db.msisdn.first() {
        sub.msisdn = m.buf[..m.len.min(m.buf.len())].to_vec();
    }
    if let Some(m) = db.msisdn.get(1) {
        sub.a_msisdn = m.buf[..m.len.min(m.buf.len())].to_vec();
    }

    let mut context_id = 1u32;
    for slice in &db.slice {
        for session in &slice.session {
            let apn = s6a::ApnConfiguration {
                context_identifier: context_id,
                service_selection: session
                    .name
                    .clone()
                    .unwrap_or_else(|| "internet".to_string()),
                // DB session_type: 1=IPv4, 2=IPv6, 3=IPv4v6 -> Diameter PDN-Type
                pdn_type: match session.session_type {
                    1 => s6a::pdn_type::IPV4 as u8,
                    2 => s6a::pdn_type::IPV6 as u8,
                    _ => s6a::pdn_type::IPV4V6 as u8,
                },
                qci: session.qos.index,
                arp_priority_level: session.qos.arp.priority_level,
                arp_pre_emption_capability: session.qos.arp.pre_emption_capability != 0,
                arp_pre_emption_vulnerability: session.qos.arp.pre_emption_vulnerability != 0,
                ambr_uplink: session.ambr.uplink,
                ambr_downlink: session.ambr.downlink,
                // #56: the APN's own charging class, falling back to the
                // subscriber-level one. TS 29.272 Table 7.3.1/2 says the AVP holds
                // "the EPS PDN Connection Charging Characteristics data for an EPS
                // APN Configuration, OR ... the Subscribed Charging Characteristics
                // data for the subscriber level", so the per-APN value is the more
                // specific answer and the subscriber value is the default.
                charging_characteristics: session
                    .charging_characteristics
                    .as_deref()
                    .and_then(s6a::ChargingCharacteristics::parse_hex)
                    .or(sub.charging_characteristics),
            };
            sub.apn_configs.push(apn);
            context_id += 1;
        }
    }

    sub
}

/// Does the previously stored serving MME need a Cancel Location before the new
/// one replaces it? (TS 29.272 §5.2.1.1.3, #56)
///
/// > *"the HSS shall send a Cancel Location Request with a Cancellation-Type of
/// > MME_UPDATE_PROCEDURE ... to the previous MME (if any) and replace the stored
/// > MME-Identity"*
///
/// `Some(previous)` only when a previous MME is stored **and differs** from the
/// one now updating. Kept pure and separate from the DB read so the three cases
/// that matter — no previous MME, the same MME re-registering, a genuinely
/// different MME — are testable without Mongo.
///
/// The host comparison is ASCII-case-insensitive because a Diameter identity is a
/// FQDN (RFC 6733 §4.3.1), and treating `MME1.example.org` as a different node
/// from `mme1.example.org` would send a spurious Cancel Location that detaches a
/// UE mid-attach. The realm is compared the same way, but a realm change alone with
/// the same host is still a different node.
pub fn previous_mme_needing_cancel(
    stored: Option<(&str, &str)>,
    new_host: &str,
    new_realm: &str,
) -> Option<(String, String)> {
    let (prev_host, prev_realm) = stored?;
    if prev_host.eq_ignore_ascii_case(new_host) && prev_realm.eq_ignore_ascii_case(new_realm) {
        return None;
    }
    // A stored identity with an empty host names no reachable node.
    if prev_host.trim().is_empty() {
        return None;
    }
    Some((prev_host.to_string(), prev_realm.to_string()))
}

/// Handle Update-Location-Request (ULR)
pub fn handle_ulr(
    imsi_bcd: &str,
    _visited_plmn_id: &[u8],
    ulr_flags: u32,
    mme_host: &str,
    mme_realm: &str,
) -> Result<UlrResponse, S6aFailure> {
    log::debug!("[{imsi_bcd}] Handling ULR from {mme_host}.{mme_realm} (flags={ulr_flags:#x})");

    use nextgcore_dbi::{nextgcore_dbi_subscription_data, nextgcore_dbi_update_mme};

    // 0. #56 / TS 29.272 §5.2.1.1.3: READ the stored MME identity BEFORE
    //    overwriting it. `nextgcore_dbi_update_mme` is a blind `$set`, so once it
    //    has run the previous MME is unrecoverable and the Cancel Location it is
    //    owed can never be sent -- which is how stale UE contexts accumulate on
    //    previous MMEs after an inter-MME TAU.
    //
    //    A lookup failure is NOT fatal: a subscriber attaching for the first time
    //    has no stored MME, which `lookup_serving_mme` reports as an error. Failing
    //    the ULR for that would break every initial attach.
    let previous_mme = lookup_serving_mme(imsi_bcd).ok();
    let cancel_target = previous_mme_needing_cancel(
        previous_mme.as_ref().map(|(h, r)| (h.as_str(), r.as_str())),
        mme_host,
        mme_realm,
    );

    // 1. Update serving MME in DB
    let supi = format!("imsi-{imsi_bcd}");
    nextgcore_dbi_update_mme(&supi, mme_host, mme_realm, true).map_err(|e| map_dbi_error(&e))?;

    // 1b. Cancel Location to the PREVIOUS MME, after the stored identity has been
    //     replaced so a CLA racing back cannot be attributed to the old one.
    //     Non-fatal: the new MME's location update has already succeeded, and
    //     failing it because the OLD MME is unreachable would deny service to a UE
    //     that has correctly attached. The failure is logged and, when the peer is
    //     merely disconnected, the message is queued for its reconnection.
    if let Some((prev_host, prev_realm)) = cancel_target {
        log::info!(
            "[{imsi_bcd}] inter-MME location update: {prev_host} -> {mme_host}; sending Cancel \
             Location (MME_UPDATE_PROCEDURE, TS 29.272 §5.2.1.1.3)"
        );
        if let Err(e) = hss_s6a_send_clr(
            imsi_bcd,
            Some(&prev_host),
            Some(&prev_realm),
            CancellationType::MmeUpdateProcedure,
        ) {
            log::warn!(
                "[{imsi_bcd}] Cancel Location to previous MME {prev_host} not delivered: {e}"
            );
        }
    }

    // 2. Get subscription data from DB
    let db_data = nextgcore_dbi_subscription_data(&supi).map_err(|e| map_dbi_error(&e))?;

    // 3. Convert to S6a Subscription-Data; a subscriber without any APN
    //    configuration has no EPS subscription (TS 29.272 5.2.1.1.3)
    let subscription_data = subscription_data_from_db(&db_data);
    let skip_subscriber_data = ulr_flags & s6a::ulr_flags::SKIP_SUBSCRIBER_DATA != 0;
    if subscription_data.apn_configs.is_empty() && !skip_subscriber_data {
        log::warn!("[{imsi_bcd}] No APN configuration: unknown EPS subscription");
        return Err(S6aFailure::UnknownEpsSubscription);
    }

    log::debug!("[{imsi_bcd}] ULR handled successfully");
    Ok(UlrResponse { subscription_data })
}

// ============================================================================
// Purge-UE (PUR -> PUA)
// ============================================================================

/// PUR Response
#[derive(Debug, Default)]
pub struct PurResponse {
    /// PUA-Flags to return (TS 29.272 7.3.49)
    pub pua_flags: u32,
}

/// Handle Purge-UE-Request (PUR)
pub fn handle_pur(imsi_bcd: &str, pur_flags: u32) -> Result<PurResponse, S6aFailure> {
    log::debug!("[{imsi_bcd}] Handling PUR (flags={pur_flags:#x})");

    use nextgcore_dbi::{mongoc::get_subscriber_collection, mongodb::bson::doc};

    let collection = get_subscriber_collection()
        .map_err(|e| S6aFailure::UnableToComply(format!("subscriber collection: {e}")))?;

    let query = doc! { "imsi": imsi_bcd };
    let update = doc! {
        "$set": {
            "purged": true,
            "purge_flags": pur_flags as i32,
        }
    };

    let result = collection
        .update_one(query, update, None)
        .map_err(|e| S6aFailure::UnableToComply(format!("purge update: {e}")))?;
    if result.matched_count == 0 {
        return Err(S6aFailure::UserUnknown);
    }

    // The UE was purged from the MME: tell the MME to freeze the M-TMSI
    // (TS 29.272 5.2.1.3.3)
    let mut pua_flags = 0;
    if pur_flags & s6a::pur_flags::UE_PURGED_IN_MME != 0 || pur_flags == 0 {
        pua_flags |= s6a::pua_flags::FREEZE_MTMSI;
    }
    if pur_flags & s6a::pur_flags::UE_PURGED_IN_SGSN != 0 {
        pua_flags |= s6a::pua_flags::FREEZE_PTMSI;
    }

    log::debug!("[{imsi_bcd}] PUR handled successfully (pua_flags={pua_flags:#x})");
    Ok(PurResponse { pua_flags })
}

// ============================================================================
// Answer builders
// ============================================================================

/// Add Origin-Host and Origin-Realm AVPs from the configured HSS identity
fn add_origin_avps(msg: &mut DiameterMessage) {
    let (host, realm) = origin_host_realm();
    msg.add_avp(Avp::mandatory(
        avp_code::ORIGIN_HOST,
        AvpData::DiameterIdentity(host),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::ORIGIN_REALM,
        AvpData::DiameterIdentity(realm),
    ));
}

fn new_answer_with_common(request: &DiameterMessage) -> DiameterMessage {
    let mut answer = DiameterMessage::new_answer(request);
    if let Some(sid) = request.session_id() {
        answer.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String(sid.to_string()),
        ));
    }
    answer
}

/// Build a successful AIA from generated vectors
pub fn build_aia_answer(request: &DiameterMessage, resp: &AirResponse) -> DiameterMessage {
    let mut answer = new_answer_with_common(request);
    answer.add_avp(Avp::mandatory(
        avp_code::RESULT_CODE,
        AvpData::Unsigned32(2001),
    ));
    answer.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));
    add_origin_avps(&mut answer);

    let many = resp.vectors.len() > 1;
    let vector_avps: Vec<Avp> = resp
        .vectors
        .iter()
        .enumerate()
        .map(|(i, v)| s6a::build_e_utran_vector_avp(many.then_some(i as u32 + 1), v))
        .collect();
    answer.add_avp(Avp::vendor_mandatory(
        s6a::avp::AUTHENTICATION_INFO,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Grouped(vector_avps),
    ));
    answer
}

/// Build a successful ULA carrying grouped Subscription-Data
pub fn build_ula_answer(request: &DiameterMessage, resp: &UlrResponse) -> DiameterMessage {
    let mut answer = new_answer_with_common(request);
    answer.add_avp(Avp::mandatory(
        avp_code::RESULT_CODE,
        AvpData::Unsigned32(2001),
    ));
    answer.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));
    add_origin_avps(&mut answer);

    // ULA-Flags: Separation Indication (TS 29.272 7.3.8)
    answer.add_avp(Avp::vendor_mandatory(
        s6a::avp::ULA_FLAGS,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Unsigned32(1),
    ));
    answer.add_avp(s6a::build_subscription_data_avp(&resp.subscription_data));
    answer
}

/// Build a successful PUA carrying PUA-Flags
pub fn build_pua_answer(request: &DiameterMessage, resp: &PurResponse) -> DiameterMessage {
    let mut answer = new_answer_with_common(request);
    answer.add_avp(Avp::mandatory(
        avp_code::RESULT_CODE,
        AvpData::Unsigned32(2001),
    ));
    answer.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));
    add_origin_avps(&mut answer);
    answer.add_avp(Avp::vendor_mandatory(
        s6a::avp::PUA_FLAGS,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Unsigned32(resp.pua_flags),
    ));
    answer
}

/// Build a Diameter error answer for the given failure.
///
/// 3GPP-specific failures use Experimental-Result (vendor 10415); base
/// protocol failures use Result-Code. The E-bit is set only for protocol
/// errors (RFC 6733 7.2).
pub fn build_failure_answer(request: &DiameterMessage, failure: &S6aFailure) -> DiameterMessage {
    let mut answer = new_answer_with_common(request);
    let (result_code, exp_code) = failure.codes();
    if let Some(code) = result_code {
        answer.add_avp(Avp::mandatory(
            avp_code::RESULT_CODE,
            AvpData::Unsigned32(code),
        ));
    }
    if let Some(code) = exp_code {
        answer.add_avp(s6a::experimental_result_avp(code));
    }
    answer.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));
    add_origin_avps(&mut answer);
    if failure.is_protocol_error() {
        answer.header.set_error();
    }
    answer
}

// ============================================================================
// S6a Diameter Message Dispatch
// ============================================================================

/// Dispatch an incoming S6a Diameter request and produce an answer.
///
/// NOTE: this performs blocking MongoDB I/O. From async contexts use
/// [`dispatch_s6a_request_async`], which moves the work off the Diameter
/// dispatch thread.
pub fn dispatch_s6a_request(request: &DiameterMessage) -> Option<DiameterMessage> {
    use nextgcore_diameter::s6a::{avp as s6a_avp, cmd};

    let cmd_code = request.header.command_code;

    if request.header.application_id != s6a::S6A_APPLICATION_ID {
        log::warn!(
            "Non-S6a message received: app_id={}",
            request.header.application_id
        );
        return None;
    }
    if !request.header.is_request() {
        return None;
    }

    // User-Name (IMSI) is mandatory in AIR/ULR/PUR (TS 29.272 7.2.x)
    let imsi_bcd = match request.user_name() {
        Some(imsi) => imsi.to_string(),
        None => {
            log::error!("S6a request missing User-Name (IMSI)");
            return Some(build_failure_answer(request, &S6aFailure::MissingAvp));
        }
    };

    match cmd_code {
        cmd::AUTHENTICATION_INFORMATION => {
            log::debug!("[{imsi_bcd}] Dispatching AIR");
            diam_stats().s6a.inc_rx_air();

            // Visited-PLMN-Id is mandatory in AIR (TS 29.272 Table 7.2.5/1)
            let Some(visited_plmn_id) = request
                .find_vendor_avp(s6a_avp::VISITED_PLMN_ID, NEXTGCORE_3GPP_VENDOR_ID)
                .and_then(|a| a.as_octet_string())
                .map(|b| b.to_vec())
            else {
                diam_stats().s6a.inc_rx_air_error();
                return Some(build_failure_answer(request, &S6aFailure::MissingAvp));
            };

            // Requested-EUTRAN-Authentication-Info carries the vector count and
            // the AUTS re-synchronisation token (TS 29.272 7.3.11)
            if request.find_avp(s6a_avp::REQ_EUTRAN_AUTH_INFO).is_none() {
                diam_stats().s6a.inc_rx_air_error();
                return Some(build_failure_answer(request, &S6aFailure::MissingAvp));
            }
            let num_vectors = s6a::find_num_requested_vectors(request).unwrap_or(1);
            let resync = s6a::find_resync_info(request);

            match handle_air(&imsi_bcd, &visited_plmn_id, resync, num_vectors) {
                Ok(resp) => {
                    diam_stats().s6a.inc_tx_aia();
                    Some(build_aia_answer(request, &resp))
                }
                Err(failure) => {
                    log::error!("[{imsi_bcd}] AIR failed: {failure:?}");
                    diam_stats().s6a.inc_rx_air_error();
                    Some(build_failure_answer(request, &failure))
                }
            }
        }
        cmd::UPDATE_LOCATION => {
            log::debug!("[{imsi_bcd}] Dispatching ULR");
            diam_stats().s6a.inc_rx_ulr();

            // Visited-PLMN-Id, RAT-Type and ULR-Flags are mandatory in ULR
            // (TS 29.272 Table 7.2.3/1)
            let Some(visited_plmn_id) = request
                .find_vendor_avp(s6a_avp::VISITED_PLMN_ID, NEXTGCORE_3GPP_VENDOR_ID)
                .and_then(|a| a.as_octet_string())
                .map(|b| b.to_vec())
            else {
                diam_stats().s6a.inc_rx_ulr_error();
                return Some(build_failure_answer(request, &S6aFailure::MissingAvp));
            };
            if request
                .find_vendor_avp(
                    nextgcore_diameter::common::avp_code::RAT_TYPE,
                    NEXTGCORE_3GPP_VENDOR_ID,
                )
                .is_none()
            {
                diam_stats().s6a.inc_rx_ulr_error();
                return Some(build_failure_answer(request, &S6aFailure::MissingAvp));
            }
            let Some(ulr_flags_val) = request
                .find_vendor_avp(s6a_avp::ULR_FLAGS, NEXTGCORE_3GPP_VENDOR_ID)
                .and_then(|a| a.as_u32())
            else {
                diam_stats().s6a.inc_rx_ulr_error();
                return Some(build_failure_answer(request, &S6aFailure::MissingAvp));
            };

            let mme_host = request.origin_host().unwrap_or("unknown").to_string();
            let mme_realm = request.origin_realm().unwrap_or("unknown").to_string();

            match handle_ulr(
                &imsi_bcd,
                &visited_plmn_id,
                ulr_flags_val,
                &mme_host,
                &mme_realm,
            ) {
                Ok(resp) => {
                    diam_stats().s6a.inc_tx_ula();
                    Some(build_ula_answer(request, &resp))
                }
                Err(failure) => {
                    log::error!("[{imsi_bcd}] ULR failed: {failure:?}");
                    diam_stats().s6a.inc_rx_ulr_error();
                    Some(build_failure_answer(request, &failure))
                }
            }
        }
        cmd::PURGE_UE => {
            log::debug!("[{imsi_bcd}] Dispatching PUR");
            diam_stats().s6a.inc_rx_pur();

            // PUR-Flags is optional in PUR (TS 29.272 Table 7.2.13/1)
            let pur_flags = request
                .find_vendor_avp(s6a_avp::PUR_FLAGS, NEXTGCORE_3GPP_VENDOR_ID)
                .and_then(|a| a.as_u32())
                .unwrap_or(0);

            match handle_pur(&imsi_bcd, pur_flags) {
                Ok(resp) => {
                    diam_stats().s6a.inc_tx_pua();
                    Some(build_pua_answer(request, &resp))
                }
                Err(failure) => {
                    log::error!("[{imsi_bcd}] PUR failed: {failure:?}");
                    diam_stats().s6a.inc_rx_pur_error();
                    Some(build_failure_answer(request, &failure))
                }
            }
        }
        // #56: NOR was previously answered 3001 + E-bit by the catch-all below,
        // which tells a conformant MME the whole Notify procedure is unsupported.
        cmd::NOTIFY => {
            log::debug!("[{imsi_bcd}] Dispatching NOR");
            let info = parse_nor(request);
            match handle_nor(&imsi_bcd, &info) {
                Ok(()) => Some(build_noa_answer(request)),
                Err(failure) => {
                    log::error!("[{imsi_bcd}] NOR failed: {failure:?}");
                    Some(build_failure_answer(request, &failure))
                }
            }
        }
        _ => {
            log::warn!("[{imsi_bcd}] Unknown S6a command code: {cmd_code}");
            diam_stats().s6a.inc_rx_unknown();
            Some(build_failure_answer(
                request,
                &S6aFailure::UnsupportedCommand,
            ))
        }
    }
}

/// Async wrapper for [`dispatch_s6a_request`]: runs the blocking MongoDB work
/// on the tokio blocking pool so the Diameter dispatch task is never stalled.
pub async fn dispatch_s6a_request_async(request: DiameterMessage) -> Option<DiameterMessage> {
    match tokio::task::spawn_blocking(move || dispatch_s6a_request(&request)).await {
        Ok(answer) => answer,
        Err(e) => {
            log::error!("S6a dispatch task panicked: {e}");
            None
        }
    }
}

/// Handle an answer to an HSS-initiated request (CLA / IDA).
pub fn handle_s6a_answer(answer: &DiameterMessage) {
    use nextgcore_diameter::s6a::cmd;
    let result_code = answer.result_code();
    let exp_code = s6a::experimental_result_code(answer);
    let success = result_code == Some(2001);

    // #56: correlate the answer to its outstanding request by Session-Id
    // (RFC 6733 §8.8) and CLEAR it, so it is not retransmitted. Before this the
    // function only incremented counters, so nothing could tell an answered
    // request from a lost one and no retransmission was possible.
    let correlated = message_session_id(answer).and_then(|sid| complete_pending(&sid));
    match &correlated {
        Some(req) => log::debug!(
            "S6a answer correlated to outstanding request {} (cmd={}, {} attempt(s))",
            req.session_id,
            req.command_code,
            req.attempts
        ),
        None => log::warn!(
            "S6a answer (cmd={}) matches no outstanding request: it was already abandoned, or the \
             peer echoed a Session-Id this HSS did not send",
            answer.header.command_code
        ),
    }

    match answer.header.command_code {
        cmd::CANCEL_LOCATION => {
            diam_stats().s6a.inc_rx_cla();
            if !success {
                diam_stats().s6a.inc_rx_cla_error();
                log::warn!("CLA failure: result={result_code:?} experimental={exp_code:?}");
            }
        }
        cmd::INSERT_SUBSCRIBER_DATA => {
            diam_stats().s6a.inc_rx_ida();
            if !success {
                diam_stats().s6a.inc_rx_ida_error();
                log::warn!("IDA failure: result={result_code:?} experimental={exp_code:?}");
            }
        }
        // #56: the two HSS-initiated procedures added by this change. They have no
        // dedicated counters, so they are logged rather than silently ignored --
        // an unsuccessful DSA means the MME still holds data the HSS deleted.
        cmd::DELETE_SUBSCRIBER_DATA => {
            if !success {
                log::warn!("DSA failure: result={result_code:?} experimental={exp_code:?}");
            }
        }
        cmd::RESET => {
            if !success {
                log::warn!(
                    "RSA failure: result={result_code:?} experimental={exp_code:?}; this MME did \
                     not accept the restart notification, so its subscriber state may stay stale"
                );
            }
        }
        other => {
            diam_stats().s6a.inc_rx_unknown();
            log::warn!("Unexpected S6a answer: cmd={other}");
        }
    }
}

// ============================================================================
// S6a server (Diameter responder + HSS-initiated requests)
// ============================================================================

/// Run the HSS S6a Diameter server.
///
/// Accepts MME connections, answers AIR/ULR/PUR (Mongo work on the blocking
/// pool) and forwards HSS-initiated CLR/IDR queued via
/// [`hss_s6a_send_clr`]/[`hss_s6a_send_idr`] over the peer's connection.
pub async fn hss_s6a_run_server(
    addr: std::net::SocketAddr,
    config: nextgcore_diameter::config::DiameterConfig,
) -> Result<(), String> {
    use nextgcore_diameter::transport::DiameterListener;

    let listener = DiameterListener::bind(addr)
        .await
        .map_err(|e| format!("S6a listener bind failed: {e}"))?;
    log::info!("HSS S6a Diameter server listening on {addr}");
    hss_s6a_serve(listener, config).await
}

/// Serve S6a on an already-bound listener (see [`hss_s6a_run_server`]).
pub async fn hss_s6a_serve(
    listener: nextgcore_diameter::transport::DiameterListener,
    config: nextgcore_diameter::config::DiameterConfig,
) -> Result<(), String> {
    hss_s6a_set_identity(&config.diameter_id, &config.diameter_realm);

    loop {
        match listener.accept().await {
            Ok(transport) => {
                let peer_addr = transport.peer_addr();
                let config = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_s6a_peer(transport, config).await {
                        log::warn!("S6a peer {peer_addr} closed: {e}");
                    }
                });
            }
            Err(e) => log::warn!("S6a accept failed: {e}"),
        }
    }
}

async fn run_s6a_peer(
    transport: nextgcore_diameter::transport::DiameterTransport,
    config: nextgcore_diameter::config::DiameterConfig,
) -> Result<(), String> {
    use nextgcore_diameter::peer::{DiameterPeer, PeerEvent};

    let mut peer = DiameterPeer::new_responder(transport, &config);
    peer.start().await.map_err(|e| e.to_string())?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<DiameterMessage>();
    let mut registered_host: Option<String> = None;

    let result = loop {
        tokio::select! {
            event = peer.next_event() => match event {
                Ok(PeerEvent::Established { origin_host, origin_realm }) => {
                    log::info!("S6a peer established: {origin_host} ({origin_realm})");
                    register_mme_peer(&origin_host, tx.clone());
                    registered_host = Some(origin_host);
                }
                Ok(PeerEvent::Message(msg)) if msg.header.is_request() => {
                    if let Some(answer) = dispatch_s6a_request_async(msg).await {
                        if let Err(e) = peer.send_message(&answer).await {
                            break Err(e.to_string());
                        }
                    }
                }
                Ok(PeerEvent::Message(msg)) => handle_s6a_answer(&msg),
                Ok(PeerEvent::WatchdogAck) => {}
                Ok(PeerEvent::Disconnected) => break Ok(()),
                Err(e) => break Err(e.to_string()),
            },
            Some(outbound) = rx.recv() => {
                if let Err(e) = peer.send_message(&outbound).await {
                    break Err(e.to_string());
                }
            }
        }
    };

    if let Some(host) = registered_host {
        unregister_mme_peer(&host);
    }
    result
}

// ============================================================================
// HSS-initiated requests: CLR / IDR
// ============================================================================

/// Look up the serving MME's Diameter host/realm for a subscriber.
///
/// NOTE: blocking MongoDB I/O; call from a blocking-safe context.
fn lookup_serving_mme(imsi_bcd: &str) -> Result<(String, String), String> {
    use nextgcore_dbi::{mongoc::get_subscriber_collection, mongodb::bson::doc};

    let collection = get_subscriber_collection()
        .map_err(|e| format!("Failed to get subscriber collection: {e}"))?;

    let query = doc! { "imsi": imsi_bcd };
    let doc = collection
        .find_one(query, None)
        .map_err(|e| format!("Failed to query DB: {e}"))?
        .ok_or_else(|| format!("Subscriber not found: {imsi_bcd}"))?;

    let host = doc
        .get_str("mme_host")
        .map_err(|_| format!("No serving MME recorded for {imsi_bcd}"))?
        .to_string();
    let realm = doc
        .get_str("mme_realm")
        .map_err(|_| format!("No serving MME realm recorded for {imsi_bcd}"))?
        .to_string();

    Ok((host, realm))
}

/// Build a Cancel-Location-Request (TS 29.272 Table 7.2.7/1).
pub fn build_clr_request(
    imsi_bcd: &str,
    dest_host: &str,
    dest_realm: &str,
    cancellation_type: CancellationType,
    clr_flags: Option<u32>,
) -> DiameterMessage {
    use nextgcore_diameter::s6a::{avp, cmd};

    let mut msg = DiameterMessage::new_request(cmd::CANCEL_LOCATION, s6a::S6A_APPLICATION_ID);
    let (hbh, e2e) = next_request_ids();
    msg.header.hop_by_hop_id = hbh;
    msg.header.end_to_end_id = e2e;

    msg.add_avp(Avp::mandatory(
        avp_code::SESSION_ID,
        AvpData::Utf8String(next_session_id(imsi_bcd)),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));
    add_origin_avps(&mut msg);
    msg.add_avp(Avp::mandatory(
        avp_code::DESTINATION_HOST,
        AvpData::DiameterIdentity(dest_host.to_string()),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::DESTINATION_REALM,
        AvpData::DiameterIdentity(dest_realm.to_string()),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::USER_NAME,
        AvpData::Utf8String(imsi_bcd.to_string()),
    ));
    msg.add_avp(Avp::vendor_mandatory(
        avp::CANCELLATION_TYPE,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Enumerated(cancellation_type as i32),
    ));
    if let Some(flags) = clr_flags {
        msg.add_avp(Avp::vendor_mandatory(
            avp::CLR_FLAGS,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::Unsigned32(flags),
        ));
    }
    msg
}

/// Build an Insert-Subscriber-Data-Request (TS 29.272 Table 7.2.9/1).
///
/// Subscription-Data is mandatory in IDR; `subdata_mask` selects which parts
/// of the subscription record are included.
pub fn build_idr_request(
    imsi_bcd: &str,
    dest_host: &str,
    dest_realm: &str,
    idr_flags: u32,
    subscription_data: &s6a::SubscriptionData,
    subdata_mask: u32,
) -> DiameterMessage {
    use nextgcore_diameter::s6a::{avp, cmd};

    // Apply the subdata mask
    let mut sub = subscription_data.clone();
    if subdata_mask & NEXTGCORE_DIAM_S6A_SUBDATA_MSISDN == 0 {
        sub.msisdn.clear();
        sub.a_msisdn.clear();
    }
    if subdata_mask & NEXTGCORE_DIAM_S6A_SUBDATA_ARD == 0 {
        sub.access_restriction_data = None;
    }
    if subdata_mask & NEXTGCORE_DIAM_S6A_SUBDATA_OP_DET_BARRING == 0 {
        sub.operator_determined_barring = None;
    }
    if subdata_mask & NEXTGCORE_DIAM_S6A_SUBDATA_RAU_TAU_TIMER == 0 {
        sub.subscribed_rau_tau_timer = 0;
    }
    if subdata_mask & NEXTGCORE_DIAM_S6A_SUBDATA_UEAMBR == 0 {
        sub.ambr_uplink = 0;
        sub.ambr_downlink = 0;
    }
    if subdata_mask & NEXTGCORE_DIAM_S6A_SUBDATA_APN_CONFIG == 0 {
        sub.apn_configs.clear();
    }

    let mut msg =
        DiameterMessage::new_request(cmd::INSERT_SUBSCRIBER_DATA, s6a::S6A_APPLICATION_ID);
    let (hbh, e2e) = next_request_ids();
    msg.header.hop_by_hop_id = hbh;
    msg.header.end_to_end_id = e2e;

    msg.add_avp(Avp::mandatory(
        avp_code::SESSION_ID,
        AvpData::Utf8String(next_session_id(imsi_bcd)),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));
    add_origin_avps(&mut msg);
    msg.add_avp(Avp::mandatory(
        avp_code::DESTINATION_HOST,
        AvpData::DiameterIdentity(dest_host.to_string()),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::DESTINATION_REALM,
        AvpData::DiameterIdentity(dest_realm.to_string()),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::USER_NAME,
        AvpData::Utf8String(imsi_bcd.to_string()),
    ));
    // Subscription-Data is mandatory in IDR
    msg.add_avp(s6a::build_subscription_data_avp(&sub));
    if idr_flags != 0 {
        msg.add_avp(Avp::vendor_mandatory(
            avp::IDR_FLAGS,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::Unsigned32(idr_flags),
        ));
    }
    msg
}

// ============================================================================
// #56: Notify (NOR -> NOA), TS 29.272 §5.2.5.1.1 / §7.2.17
// ============================================================================

/// What an MME reported in a Notify-Request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NorInfo {
    /// Context-Identifier the PDN-GW identity applies to, when given
    pub context_identifier: Option<u32>,
    /// Service-Selection (the APN) the PDN-GW identity applies to, when given
    pub service_selection: Option<String>,
    /// The dynamically allocated PDN-GW identity (MIP6-Agent-Info)
    pub pdn_gw: s6a::PdnGwIdentity,
    /// NOR-Flags, when given
    pub nor_flags: Option<u32>,
    /// Alert-Reason, when given
    pub alert_reason: Option<i32>,
}

impl NorInfo {
    /// Is there a PDN-GW identity to store, and does it name which APN it belongs
    /// to?
    ///
    /// §5.2.5.1.1 scopes the notification to *"an assignment/change of a
    /// dynamically allocated PDN GW **for an APN**"*, so an identity with no APN
    /// scope cannot be filed against anything. Both scopings are accepted because
    /// the NOR message format offers both `Context-Identifier` and
    /// `Service-Selection` and does not require either.
    pub fn storable_pdn_gw(&self) -> Option<(String, ApnScope)> {
        if self.pdn_gw.is_empty() {
            return None;
        }
        let identity = self.pdn_gw.to_stored_string()?;
        let scope = if let Some(ref apn) = self.service_selection {
            ApnScope::ServiceSelection(apn.clone())
        } else if let Some(id) = self.context_identifier {
            ApnScope::ContextIdentifier(id)
        } else {
            return None;
        };
        Some((identity, scope))
    }
}

/// Which APN a reported PDN-GW identity belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApnScope {
    /// Named by APN (Service-Selection)
    ServiceSelection(String),
    /// Named by the subscription's Context-Identifier
    ContextIdentifier(u32),
}

/// Parse the PDN-GW identity out of a MIP6-Agent-Info AVP (TS 29.272 §7.3.45).
fn parse_mip6_agent_info(avp: &Avp) -> s6a::PdnGwIdentity {
    let mut out = s6a::PdnGwIdentity::default();
    let Ok(members) = avp.parse_grouped() else {
        return out;
    };
    for m in &members {
        match m.code {
            c if c == s6a::avp::MIP_HOME_AGENT_ADDRESS => {
                if let Some(b) = m.as_octet_string() {
                    out.address = Some(b.to_vec());
                }
            }
            c if c == s6a::avp::MIP_HOME_AGENT_HOST => {
                if let Ok(inner) = m.parse_grouped() {
                    let host = inner
                        .iter()
                        .find(|a| a.code == avp_code::DESTINATION_HOST)
                        .and_then(|a| a.as_utf8_string())
                        .map(str::to_string);
                    let realm = inner
                        .iter()
                        .find(|a| a.code == avp_code::DESTINATION_REALM)
                        .and_then(|a| a.as_utf8_string())
                        .map(str::to_string);
                    if let Some(host) = host {
                        out.fqdn = Some((host, realm.unwrap_or_default()));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Parse a Notify-Request (TS 29.272 §7.2.17).
pub fn parse_nor(request: &DiameterMessage) -> NorInfo {
    NorInfo {
        context_identifier: request
            .find_vendor_avp(s6a::avp::CONTEXT_IDENTIFIER, NEXTGCORE_3GPP_VENDOR_ID)
            .and_then(|a| a.as_u32()),
        // Service-Selection is RFC 5778 and carries NO vendor id.
        service_selection: request
            .find_avp(s6a::avp::SERVICE_SELECTION)
            .and_then(|a| a.as_utf8_string())
            .map(str::to_string),
        // MIP6-Agent-Info is RFC 5447 and carries NO vendor id either.
        pdn_gw: request
            .find_avp(s6a::avp::MIP6_AGENT_INFO)
            .map(parse_mip6_agent_info)
            .unwrap_or_default(),
        nor_flags: request
            .find_vendor_avp(s6a::avp::NOR_FLAGS, NEXTGCORE_3GPP_VENDOR_ID)
            .and_then(|a| a.as_u32()),
        alert_reason: request
            .find_vendor_avp(s6a::avp::ALERT_REASON, NEXTGCORE_3GPP_VENDOR_ID)
            .and_then(|a| a.as_i32().or_else(|| a.as_u32().map(|v| v as i32))),
    }
}

/// Handle a Notify-Request: persist any reported dynamic PDN-GW identity
/// (TS 29.272 §5.2.5.1.1).
///
/// A NOR that reports nothing this HSS stores is still answered **successfully**.
/// §7.2.17 makes every informational IE optional, and most of them (terminal
/// information, UE SRVCC capability, monitoring-event status, homogeneous IMS voice
/// support) are things this HSS does not model. Answering 3001 for those — which is
/// what the pre-#56 default arm did — tells a conformant MME the command is
/// unsupported, so it stops using the whole procedure, including the PDN-GW
/// notification that *is* handled.
pub fn handle_nor(imsi_bcd: &str, info: &NorInfo) -> Result<(), S6aFailure> {
    log::debug!("[{imsi_bcd}] Handling NOR: {info:?}");

    let Some((identity, scope)) = info.storable_pdn_gw() else {
        if !info.pdn_gw.is_empty() {
            log::warn!(
                "[{imsi_bcd}] NOR reported a PDN-GW identity with no Context-Identifier and no \
                 Service-Selection: nothing names which APN it belongs to, so it is not stored \
                 (TS 29.272 §5.2.5.1.1)"
            );
        } else {
            log::info!(
                "[{imsi_bcd}] NOR carried nothing this HSS stores (flags={:?}, alert={:?}); \
                 answered NOA",
                info.nor_flags,
                info.alert_reason
            );
        }
        return Ok(());
    };

    persist_pdn_gw_identity(imsi_bcd, &identity, &scope)?;
    log::info!("[{imsi_bcd}] Stored dynamic PDN-GW '{identity}' for {scope:?}");
    Ok(())
}

/// Persist a dynamically allocated PDN-GW identity against its APN
/// (TS 29.272 §5.2.5.1.1).
///
/// Stored on the matching `slice.session` sub-document, which is where this tree's
/// subscriber schema keeps per-APN data, under `pgw_id`. A positional `$set` on the
/// array element is used rather than rewriting the whole slice array: rewriting
/// would race any concurrent provisioning change against this notification.
fn persist_pdn_gw_identity(
    imsi_bcd: &str,
    identity: &str,
    scope: &ApnScope,
) -> Result<(), S6aFailure> {
    use nextgcore_dbi::{mongoc::get_subscriber_collection, mongodb::bson::doc};

    let collection = get_subscriber_collection()
        .map_err(|e| S6aFailure::UnableToComply(format!("subscriber collection: {e}")))?;

    // Scoped by APN name where the MME gave one. A Context-Identifier is this
    // subscription's own ordinal, which `subscription_data_from_db` assigns by
    // enumeration order starting at 1 -- so it is resolved the same way, by
    // position, rather than by a stored field that does not exist.
    let (filter, set_key) = match scope {
        ApnScope::ServiceSelection(apn) => (
            doc! { "imsi": imsi_bcd, "slice.session.name": apn },
            "slice.$[s].session.$[t].pgw_id".to_string(),
        ),
        ApnScope::ContextIdentifier(_) => (doc! { "imsi": imsi_bcd }, "pgw_id".to_string()),
    };

    let update = match scope {
        ApnScope::ServiceSelection(apn) => {
            let opts = nextgcore_dbi::mongodb::options::UpdateOptions::builder()
                .array_filters(vec![
                    doc! { "s.session": { "$elemMatch": { "name": apn } } },
                    doc! { "t.name": apn },
                ])
                .build();
            collection.update_one(filter, doc! { "$set": { set_key: identity } }, opts)
        }
        // No Service-Selection: the identity is recorded at subscriber level with
        // the context id it was reported for, because there is no reliable way to
        // map an ordinal onto an array element without also reading the array, and
        // a read-modify-write here would race provisioning.
        ApnScope::ContextIdentifier(id) => collection.update_one(
            filter,
            doc! { "$set": { "pgw_id": identity, "pgw_id_context": *id as i32 } },
            None,
        ),
    };

    let result =
        update.map_err(|e| S6aFailure::UnableToComply(format!("PDN-GW identity store: {e}")))?;
    if result.matched_count == 0 {
        // The subscriber (or the named APN) is not provisioned. UserUnknown rather
        // than UnableToComply: the MME asked about something this HSS does not have.
        return Err(S6aFailure::UserUnknown);
    }
    Ok(())
}

/// Build a Notify-Answer (TS 29.272 §7.2.18).
pub fn build_noa_answer(request: &DiameterMessage) -> DiameterMessage {
    let mut answer = new_answer_with_common(request);
    answer.add_avp(Avp::mandatory(
        avp_code::RESULT_CODE,
        AvpData::Unsigned32(2001),
    ));
    answer.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));
    add_origin_avps(&mut answer);
    answer
}

// ============================================================================
// #56: Delete-Subscriber-Data (DSR -> DSA) and Reset (RSR -> RSA)
// ============================================================================

/// Build a Delete-Subscriber-Data-Request (TS 29.272 §7.2.11).
///
/// `context_identifiers` is only meaningful with the PDN-subscription-contexts
/// withdrawal bit set; §7.3.25 Note 1 ties the two together, and sending
/// identifiers without the bit would name contexts the MME has not been told to
/// delete.
pub fn build_dsr_request(
    imsi_bcd: &str,
    dest_host: &str,
    dest_realm: &str,
    dsr_flags: u32,
    context_identifiers: &[u32],
) -> DiameterMessage {
    use nextgcore_diameter::s6a::{avp, cmd};

    let mut msg =
        DiameterMessage::new_request(cmd::DELETE_SUBSCRIBER_DATA, s6a::S6A_APPLICATION_ID);
    let (hbh, e2e) = next_request_ids();
    msg.header.hop_by_hop_id = hbh;
    msg.header.end_to_end_id = e2e;

    msg.add_avp(Avp::mandatory(
        avp_code::SESSION_ID,
        AvpData::Utf8String(next_session_id(imsi_bcd)),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));
    add_origin_avps(&mut msg);
    msg.add_avp(Avp::mandatory(
        avp_code::DESTINATION_HOST,
        AvpData::DiameterIdentity(dest_host.to_string()),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::DESTINATION_REALM,
        AvpData::DiameterIdentity(dest_realm.to_string()),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::USER_NAME,
        AvpData::Utf8String(imsi_bcd.to_string()),
    ));
    // DSR-Flags is the one mandatory 3GPP IE of this command.
    msg.add_avp(Avp::vendor_mandatory(
        avp::DSR_FLAGS,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Unsigned32(dsr_flags),
    ));
    if dsr_flags & s6a::dsr_flags::PDN_SUBSCRIPTION_CONTEXTS_WITHDRAWAL != 0 {
        for id in context_identifiers {
            msg.add_avp(Avp::vendor_mandatory(
                avp::CONTEXT_IDENTIFIER,
                NEXTGCORE_3GPP_VENDOR_ID,
                AvpData::Unsigned32(*id),
            ));
        }
    }
    msg
}

/// Build a Reset-Request (TS 29.272 §7.2.15).
///
/// `user_ids` are IMSI prefixes (§7.3.50): the leading MCC+MNC+MSIN digits that
/// identify the affected subscriber set. Empty means "all subscribers of this HSS",
/// which is the plain restart case.
pub fn build_rsr_request(
    dest_host: &str,
    dest_realm: &str,
    user_ids: &[String],
) -> DiameterMessage {
    use nextgcore_diameter::s6a::{avp, cmd};

    let mut msg = DiameterMessage::new_request(cmd::RESET, s6a::S6A_APPLICATION_ID);
    let (hbh, e2e) = next_request_ids();
    msg.header.hop_by_hop_id = hbh;
    msg.header.end_to_end_id = e2e;

    // Reset is not per-subscriber, so the Session-Id is suffixed with the target
    // MME rather than an IMSI.
    msg.add_avp(Avp::mandatory(
        avp_code::SESSION_ID,
        AvpData::Utf8String(next_session_id(dest_host)),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));
    add_origin_avps(&mut msg);
    msg.add_avp(Avp::mandatory(
        avp_code::DESTINATION_HOST,
        AvpData::DiameterIdentity(dest_host.to_string()),
    ));
    msg.add_avp(Avp::mandatory(
        avp_code::DESTINATION_REALM,
        AvpData::DiameterIdentity(dest_realm.to_string()),
    ));
    // NOTE: no User-Name. Reset applies to a SET of subscribers, named by User-Id
    // prefixes, and §7.2.15's message format has no User-Name at all.
    for uid in user_ids {
        msg.add_avp(Avp::vendor_mandatory(
            avp::USER_ID,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::Utf8String(uid.clone()),
        ));
    }
    msg
}

/// Send a Delete-Subscriber-Data-Request to the serving MME (#56).
pub fn hss_s6a_send_dsr(
    imsi_bcd: &str,
    dsr_flags: u32,
    context_identifiers: &[u32],
) -> Result<(), String> {
    log::info!("[{imsi_bcd}] Sending Delete-Subscriber-Data-Request (flags={dsr_flags:#x})");
    let (dest_host, dest_realm) = lookup_serving_mme(imsi_bcd)?;
    let dsr = build_dsr_request(
        imsi_bcd,
        &dest_host,
        &dest_realm,
        dsr_flags,
        context_identifiers,
    );
    send_tracked(&dest_host, dsr)?;
    log::debug!("[{imsi_bcd}] DSR sent to {dest_host}");
    Ok(())
}

/// Send a Reset-Request to every currently registered MME (#56, TS 23.007).
///
/// Returns how many peers it went to. Called at startup after an unclean shutdown:
/// the MMEs are told to re-run Update Location for the affected subscribers,
/// because the HSS cannot know what it lost.
pub fn hss_s6a_send_rsr_to_all(user_ids: &[String]) -> usize {
    let peers: Vec<String> = match peer_registry().read() {
        Ok(r) => r.keys().cloned().collect(),
        Err(_) => return 0,
    };
    if peers.is_empty() {
        log::warn!(
            "HSS restart Reset: no MME peer is connected yet, so no Reset-Request was sent. \
             Restoration depends on the MMEs reconnecting and re-registering."
        );
        return 0;
    }
    let mut sent = 0usize;
    for host in peers {
        // The MME's realm is not recorded in the peer registry, so it is derived
        // from the host by stripping the leading label -- the S6a convention for a
        // Diameter identity (host = <name>.<realm>).
        let realm = host.split_once('.').map(|(_, r)| r).unwrap_or(&host);
        let rsr = build_rsr_request(&host, realm, user_ids);
        match send_tracked(&host, rsr) {
            Ok(()) => {
                sent += 1;
                log::info!("HSS restart Reset-Request sent to {host}");
            }
            Err(e) => log::warn!("HSS restart Reset-Request to {host} failed: {e}"),
        }
    }
    sent
}

/// Send Cancel-Location-Request to the serving MME.
///
/// The CLR is transmitted on the MME's existing S6a connection. Fails if the
/// MME is not currently connected.
///
/// NOTE: performs blocking MongoDB I/O when `mme_host`/`mme_realm` are not
/// provided; call from a blocking-safe context.
pub fn hss_s6a_send_clr(
    imsi_bcd: &str,
    mme_host: Option<&str>,
    mme_realm: Option<&str>,
    cancellation_type: CancellationType,
) -> Result<(), String> {
    log::info!("[{imsi_bcd}] Sending Cancel-Location-Request (type={cancellation_type:?})");

    let (dest_host, dest_realm) = if let (Some(h), Some(r)) = (mme_host, mme_realm) {
        (h.to_string(), r.to_string())
    } else {
        lookup_serving_mme(imsi_bcd)?
    };

    let clr = build_clr_request(imsi_bcd, &dest_host, &dest_realm, cancellation_type, None);
    // #56: tracked, so a missing CLA is retransmitted and a disconnected peer
    // queues the request instead of dropping it.
    send_tracked(&dest_host, clr)?;

    diam_stats().s6a.inc_tx_clr();
    log::debug!("[{imsi_bcd}] CLR sent to {dest_host}");
    Ok(())
}

/// Send Insert-Subscriber-Data-Request to the serving MME.
///
/// The IDR is transmitted on the MME's existing S6a connection. Fails if the
/// MME is not currently connected.
///
/// NOTE: performs blocking MongoDB I/O; call from a blocking-safe context.
pub fn hss_s6a_send_idr(imsi_bcd: &str, idr_flags: u32, subdata_mask: u32) -> Result<(), String> {
    log::info!(
        "[{imsi_bcd}] Sending Insert-Subscriber-Data-Request (flags={idr_flags:#x}, mask={subdata_mask:#x})"
    );

    use nextgcore_dbi::nextgcore_dbi_subscription_data;

    let (dest_host, dest_realm) = lookup_serving_mme(imsi_bcd)?;

    let supi = format!("imsi-{imsi_bcd}");
    let db_data = nextgcore_dbi_subscription_data(&supi)
        .map_err(|e| format!("Failed to get subscription data: {e}"))?;
    let subscription_data = subscription_data_from_db(&db_data);

    let idr = build_idr_request(
        imsi_bcd,
        &dest_host,
        &dest_realm,
        idr_flags,
        &subscription_data,
        subdata_mask,
    );
    send_tracked(&dest_host, idr)?;

    diam_stats().s6a.inc_tx_idr();
    log::debug!("[{imsi_bcd}] IDR sent to {dest_host}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextgcore_crypt::milenage::{milenage_f1, milenage_f2345};

    /// One agreement about the process-global MME peer registry, the outstanding
    /// request table and the restart-reset arming flag (#56).
    ///
    /// All three are process-wide, and they interact: a test that arms restart
    /// restoration makes every later peer registration receive an unexpected
    /// Reset-Request, and a test that reads a peer's channel sees whatever a
    /// sibling queued for the same host. Three existing tests broke exactly this
    /// way while #56 was being written. Every test that registers a peer or inspects
    /// the pending table takes this lock, so there is one agreement rather than
    /// several disjoint ones.
    ///
    /// `std::sync::Mutex` rather than tokio's, so the same lock serves the sync and
    /// `#[tokio::test]` tests alike. No guard is held across an `await`.
    static PEER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_cancellation_type_from_u32() {
        assert_eq!(
            CancellationType::from(0),
            CancellationType::MmeUpdateProcedure
        );
        assert_eq!(
            CancellationType::from(2),
            CancellationType::SubscriptionWithdrawal
        );
        assert_eq!(
            CancellationType::from(99),
            CancellationType::SubscriptionWithdrawal
        );
    }

    #[test]
    fn test_s6a_init_final() {
        assert!(hss_s6a_init().is_ok());
        hss_s6a_final();
    }

    #[test]
    fn test_fresh_rand_is_not_reused() {
        let a = fresh_rand();
        let b = fresh_rand();
        let c = fresh_rand();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, [0u8; 16]);
    }

    /// Construct a valid AUTS with f1*/f5* and verify process_resync extracts
    /// the exact SQN_MS (TS 33.102 6.3.5).
    #[test]
    fn test_process_resync_valid_auts() {
        let k = [0x46u8; 16];
        let opc = [0x8Eu8; 16];
        let rand = [0x23u8; 16];
        let sqn_ms: u64 = 0x0001_2345_6789;
        let sqn_bytes = sqn_to_bytes(sqn_ms);
        let amf_resync = [0x00u8, 0x00];

        // AUTS = (SQN_MS xor AK*) || MAC-S
        let (_res, _ck, _ik, _ak, ak_star) = milenage_f2345(&opc, &k, &rand).unwrap();
        let (_mac_a, mac_s) = milenage_f1(&opc, &k, &rand, &sqn_bytes, &amf_resync).unwrap();
        let mut auts = [0u8; 14];
        for i in 0..6 {
            auts[i] = sqn_bytes[i] ^ ak_star[i];
        }
        auts[6..14].copy_from_slice(&mac_s);

        let extracted = process_resync(&opc, &k, &rand, &auts).unwrap();
        assert_eq!(extracted, sqn_ms);
    }

    /// A tampered AUTS (bad MAC-S) must be rejected with
    /// AUTHENTICATION_DATA_UNAVAILABLE, not silently accepted.
    #[test]
    fn test_process_resync_tampered_auts_rejected() {
        let k = [0x46u8; 16];
        let opc = [0x8Eu8; 16];
        let rand = [0x23u8; 16];
        let auts = [0xFFu8; 14];

        let result = process_resync(&opc, &k, &rand, &auts);
        assert_eq!(result.unwrap_err(), S6aFailure::AuthDataUnavailable);
    }

    #[test]
    fn test_subscription_data_from_db_mapping() {
        use nextgcore_dbi::{
            NextgcoreAmbr, NextgcoreArp, NextgcoreQos, NextgcoreSession, NextgcoreSliceData,
            NextgcoreSubscriptionData,
        };

        let db = NextgcoreSubscriptionData {
            subscriber_status: 0,
            network_access_mode: 2,
            subscribed_rau_tau_timer: 12, // minutes
            access_restriction_data: 0x20,
            ambr: NextgcoreAmbr {
                uplink: 50_000_000,
                downlink: 100_000_000,
            },
            slice: vec![NextgcoreSliceData {
                session: vec![NextgcoreSession {
                    name: Some("internet".to_string()),
                    session_type: 3, // IPv4v6
                    qos: NextgcoreQos {
                        index: 9,
                        arp: NextgcoreArp {
                            priority_level: 8,
                            pre_emption_capability: 0,
                            pre_emption_vulnerability: 1,
                        },
                        ..Default::default()
                    },
                    ambr: NextgcoreAmbr {
                        uplink: 1_000_000,
                        downlink: 2_000_000,
                    },
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };

        let sub = subscription_data_from_db(&db);
        assert_eq!(sub.network_access_mode, 2);
        assert_eq!(sub.subscribed_rau_tau_timer, 720); // seconds
        assert_eq!(sub.ambr_uplink, 50_000_000);
        assert_eq!(sub.ambr_downlink, 100_000_000);
        assert_eq!(sub.apn_configs.len(), 1);
        let apn = &sub.apn_configs[0];
        assert_eq!(apn.context_identifier, 1);
        assert_eq!(apn.service_selection, "internet");
        assert_eq!(
            apn.pdn_type,
            nextgcore_diameter::s6a::pdn_type::IPV4V6 as u8
        );
        assert_eq!(apn.qci, 9);
        assert_eq!(apn.arp_priority_level, 8);
        assert!(!apn.arp_pre_emption_capability);
        assert!(apn.arp_pre_emption_vulnerability);
    }

    fn make_air() -> DiameterMessage {
        nextgcore_diameter::s6a::create_air(
            "test-session-1",
            "mme.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "001010123456789",
            &[0x00, 0xF1, 0x10],
            1,
        )
    }

    /// AIA built from vectors must round-trip the wire and parse back.
    #[test]
    fn test_build_aia_answer_wire_roundtrip() {
        let air = make_air();
        let resp = AirResponse {
            vectors: vec![
                EUtranVector {
                    rand: [1; 16],
                    xres: vec![2; 8],
                    autn: [3; 16],
                    kasme: [4; 32],
                },
                EUtranVector {
                    rand: [5; 16],
                    xres: vec![6; 8],
                    autn: [7; 16],
                    kasme: [8; 32],
                },
            ],
        };
        let aia = build_aia_answer(&air, &resp);
        assert!(aia.header.is_answer());
        assert!(!aia.header.is_error());

        let encoded = aia.encode();
        let mut bytes = encoded.freeze();
        let decoded = DiameterMessage::decode(&mut bytes).unwrap();
        assert_eq!(decoded.result_code(), Some(2001));

        let vectors = nextgcore_diameter::s6a::parse_authentication_info(&decoded);
        assert_eq!(vectors.len(), 2);
        assert_eq!(vectors[0].rand, [1; 16]);
        assert_eq!(vectors[1].kasme, [8; 32]);
    }

    /// ULA Subscription-Data must be a real grouped AVP that survives the wire.
    #[test]
    fn test_build_ula_answer_wire_roundtrip() {
        let ulr = nextgcore_diameter::s6a::create_ulr(
            "test-session-2",
            "mme.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "001010123456789",
            &[0x00, 0xF1, 0x10],
            0x22,
            1004,
        );
        let mut sub = nextgcore_diameter::s6a::SubscriptionData {
            network_access_mode: 2,
            subscribed_rau_tau_timer: 720,
            ambr_uplink: 50_000_000,
            ambr_downlink: 100_000_000,
            context_identifier: 1,
            all_apn_configs_included: true,
            ..Default::default()
        };
        sub.apn_configs
            .push(nextgcore_diameter::s6a::ApnConfiguration {
                context_identifier: 1,
                service_selection: "internet".to_string(),
                pdn_type: nextgcore_diameter::s6a::pdn_type::IPV4V6 as u8,
                qci: 9,
                arp_priority_level: 8,
                arp_pre_emption_capability: false,
                arp_pre_emption_vulnerability: true,
                ambr_uplink: 50_000_000,
                ambr_downlink: 100_000_000,
                charging_characteristics: None,
            });
        let resp = UlrResponse {
            subscription_data: sub.clone(),
        };

        let ula = build_ula_answer(&ulr, &resp);
        let encoded = ula.encode();
        let mut bytes = encoded.freeze();
        let decoded = DiameterMessage::decode(&mut bytes).unwrap();

        assert_eq!(decoded.result_code(), Some(2001));
        let sub_avp = decoded
            .find_avp(nextgcore_diameter::s6a::avp::SUBSCRIPTION_DATA)
            .expect("Subscription-Data AVP");
        assert!(sub_avp.is_vendor_specific());
        let parsed = nextgcore_diameter::s6a::parse_subscription_data_avp(sub_avp);
        assert_eq!(parsed, sub);
    }

    #[test]
    fn test_build_pua_answer_has_pua_flags() {
        let mut pur = DiameterMessage::new_request(
            nextgcore_diameter::s6a::cmd::PURGE_UE,
            NEXTGCORE_DIAM_S6A_APPLICATION_ID,
        );
        pur.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String("pur-session".to_string()),
        ));
        let resp = PurResponse {
            pua_flags: nextgcore_diameter::s6a::pua_flags::FREEZE_MTMSI,
        };
        let pua = build_pua_answer(&pur, &resp);

        let encoded = pua.encode();
        let mut bytes = encoded.freeze();
        let decoded = DiameterMessage::decode(&mut bytes).unwrap();
        let flags = decoded
            .find_vendor_avp(
                nextgcore_diameter::s6a::avp::PUA_FLAGS,
                NEXTGCORE_3GPP_VENDOR_ID,
            )
            .and_then(|a| a.as_u32());
        assert_eq!(
            flags,
            Some(nextgcore_diameter::s6a::pua_flags::FREEZE_MTMSI)
        );
    }

    #[test]
    fn test_failure_answer_codes() {
        let air = make_air();

        // 3GPP error: Experimental-Result, no Result-Code, no E-bit
        let answer = build_failure_answer(&air, &S6aFailure::UserUnknown);
        assert_eq!(answer.result_code(), None);
        assert_eq!(
            nextgcore_diameter::s6a::experimental_result_code(&answer),
            Some(5001)
        );
        assert!(!answer.header.is_error());

        // Base permanent failure: Result-Code, no E-bit
        let answer = build_failure_answer(&air, &S6aFailure::MissingAvp);
        assert_eq!(answer.result_code(), Some(5005));
        assert!(!answer.header.is_error());

        // Protocol error: Result-Code + E-bit
        let answer = build_failure_answer(&air, &S6aFailure::UnsupportedCommand);
        assert_eq!(answer.result_code(), Some(3001));
        assert!(answer.header.is_error());

        // Resync failure: Experimental 4181
        let answer = build_failure_answer(&air, &S6aFailure::AuthDataUnavailable);
        assert_eq!(
            nextgcore_diameter::s6a::experimental_result_code(&answer),
            Some(4181)
        );
    }

    #[test]
    fn test_dispatch_s6a_air_without_db() {
        // Without DB the handler must produce a proper failure answer
        let air = make_air();
        let answer = dispatch_s6a_request(&air).unwrap();
        assert!(answer.header.is_answer());
        assert_eq!(answer.header.command_code, 318);
        // DB unreachable -> UNABLE_TO_COMPLY (or USER_UNKNOWN if the driver
        // resolves the lookup); never silent success
        assert_ne!(answer.result_code(), Some(2001));
    }

    #[test]
    fn test_dispatch_s6a_missing_username() {
        let mut msg = DiameterMessage::new_request(318, NEXTGCORE_DIAM_S6A_APPLICATION_ID);
        msg.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String("test-session".to_string()),
        ));
        let answer = dispatch_s6a_request(&msg).unwrap();
        assert_eq!(answer.result_code(), Some(5005));
    }

    #[test]
    fn test_dispatch_s6a_air_missing_visited_plmn() {
        let mut msg = DiameterMessage::new_request(318, NEXTGCORE_DIAM_S6A_APPLICATION_ID);
        msg.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String("test-session".to_string()),
        ));
        msg.add_avp(Avp::mandatory(
            avp_code::USER_NAME,
            AvpData::Utf8String("001010123456789".to_string()),
        ));
        let answer = dispatch_s6a_request(&msg).unwrap();
        assert_eq!(answer.result_code(), Some(5005));
    }

    #[test]
    fn test_dispatch_s6a_air_missing_requested_auth_info() {
        let mut msg = DiameterMessage::new_request(318, NEXTGCORE_DIAM_S6A_APPLICATION_ID);
        msg.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String("test-session".to_string()),
        ));
        msg.add_avp(Avp::mandatory(
            avp_code::USER_NAME,
            AvpData::Utf8String("001010123456789".to_string()),
        ));
        msg.add_avp(Avp::vendor_mandatory(
            nextgcore_diameter::s6a::avp::VISITED_PLMN_ID,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::OctetString(bytes::Bytes::from_static(&[0x00, 0xF1, 0x10])),
        ));
        let answer = dispatch_s6a_request(&msg).unwrap();
        assert_eq!(answer.result_code(), Some(5005));
    }

    #[test]
    fn test_dispatch_s6a_ulr_missing_mandatory_avps() {
        // ULR without RAT-Type / ULR-Flags / Visited-PLMN-Id -> 5005
        let mut msg = DiameterMessage::new_request(316, NEXTGCORE_DIAM_S6A_APPLICATION_ID);
        msg.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String("test-session".to_string()),
        ));
        msg.add_avp(Avp::mandatory(
            avp_code::USER_NAME,
            AvpData::Utf8String("001010123456789".to_string()),
        ));
        let answer = dispatch_s6a_request(&msg).unwrap();
        assert_eq!(answer.result_code(), Some(5005));
    }

    #[test]
    fn test_dispatch_s6a_unknown_command() {
        let mut msg = DiameterMessage::new_request(999, NEXTGCORE_DIAM_S6A_APPLICATION_ID);
        msg.add_avp(Avp::mandatory(
            avp_code::USER_NAME,
            AvpData::Utf8String("001010123456789".to_string()),
        ));
        let answer = dispatch_s6a_request(&msg).unwrap();
        assert_eq!(answer.result_code(), Some(3001));
        assert!(answer.header.is_error());
    }

    #[test]
    fn test_build_clr_request_mandatory_avps() {
        let clr = build_clr_request(
            "001010123456789",
            "mme.example.com",
            "example.com",
            CancellationType::SubscriptionWithdrawal,
            Some(nextgcore_diameter::s6a::clr_flags::REATTACH_REQUIRED),
        );
        assert!(clr.header.is_request());
        assert_eq!(clr.header.command_code, 317);
        assert_ne!(clr.header.hop_by_hop_id, 0);
        assert_ne!(clr.header.end_to_end_id, 0);
        assert_eq!(clr.user_name(), Some("001010123456789"));
        assert_eq!(clr.destination_host(), Some("mme.example.com"));
        assert_eq!(clr.destination_realm(), Some("example.com"));
        let ct = clr
            .find_vendor_avp(
                nextgcore_diameter::s6a::avp::CANCELLATION_TYPE,
                NEXTGCORE_3GPP_VENDOR_ID,
            )
            .and_then(|a| a.as_i32());
        assert_eq!(ct, Some(2));
        let flags = clr
            .find_vendor_avp(
                nextgcore_diameter::s6a::avp::CLR_FLAGS,
                NEXTGCORE_3GPP_VENDOR_ID,
            )
            .and_then(|a| a.as_u32());
        assert_eq!(
            flags,
            Some(nextgcore_diameter::s6a::clr_flags::REATTACH_REQUIRED)
        );
    }

    #[test]
    fn test_build_idr_request_carries_subscription_data() {
        let mut sub = nextgcore_diameter::s6a::SubscriptionData {
            ambr_uplink: 1000,
            ambr_downlink: 2000,
            ..Default::default()
        };
        sub.apn_configs
            .push(nextgcore_diameter::s6a::ApnConfiguration {
                context_identifier: 1,
                service_selection: "internet".to_string(),
                ..Default::default()
            });
        let idr = build_idr_request(
            "001010123456789",
            "mme.example.com",
            "example.com",
            nextgcore_diameter::s6a::idr_flags::RAT_TYPE,
            &sub,
            NEXTGCORE_DIAM_S6A_SUBDATA_ALL,
        );
        assert_eq!(idr.header.command_code, 319);
        // Subscription-Data must be present (M in IDR) and parse back
        let sub_avp = idr
            .find_avp(nextgcore_diameter::s6a::avp::SUBSCRIPTION_DATA)
            .expect("Subscription-Data");
        let parsed = nextgcore_diameter::s6a::parse_subscription_data_avp(sub_avp);
        assert_eq!(parsed.ambr_uplink, 1000);
        assert_eq!(parsed.apn_configs.len(), 1);
    }

    #[test]
    fn test_build_idr_request_subdata_mask_filters() {
        let mut sub = nextgcore_diameter::s6a::SubscriptionData {
            ambr_uplink: 1000,
            ambr_downlink: 2000,
            subscribed_rau_tau_timer: 720,
            ..Default::default()
        };
        sub.apn_configs
            .push(nextgcore_diameter::s6a::ApnConfiguration::default());
        let idr = build_idr_request(
            "001010123456789",
            "mme.example.com",
            "example.com",
            0,
            &sub,
            NEXTGCORE_DIAM_S6A_SUBDATA_UEAMBR, // only the UE-AMBR
        );
        let sub_avp = idr
            .find_avp(nextgcore_diameter::s6a::avp::SUBSCRIPTION_DATA)
            .unwrap();
        let parsed = nextgcore_diameter::s6a::parse_subscription_data_avp(sub_avp);
        assert_eq!(parsed.ambr_uplink, 1000);
        assert_eq!(parsed.subscribed_rau_tau_timer, 0);
        assert!(parsed.apn_configs.is_empty());
    }

    /// #56 INVERTED this test. It previously required `hss_s6a_send_clr` to FAIL
    /// when no peer is connected, and asserted on the "no connected S6a peer"
    /// message — i.e. it pinned the fire-and-forget defect as the requirement.
    /// Issue #56 criterion 5 is that such a request is *"requeued when the MME
    /// reconnects rather than dropped when no peer is connected"*, so a momentary
    /// link loss must no longer discard the procedure. The queued-then-delivered
    /// behaviour is pinned by
    /// `a_clr_for_a_disconnected_peer_is_queued_and_delivered_on_reconnect`.
    #[test]
    fn test_send_clr_queues_when_no_peer_is_connected() {
        let _guard = PEER_TEST_LOCK.lock().expect("peer test lock");
        clear_pending_requests();
        // Explicit host/realm avoids the DB lookup; no peer registered -> queued
        let result = hss_s6a_send_clr(
            "123456789012345",
            Some("mme.unconnected.example.com"),
            Some("example.com"),
            CancellationType::SubscriptionWithdrawal,
        );
        assert!(
            result.is_ok(),
            "a disconnected peer must queue the request, not lose it"
        );
        assert_eq!(pending_request_count(), 1);
        clear_pending_requests();
    }

    #[test]
    fn test_send_clr_transmits_to_registered_peer() {
        let _guard = PEER_TEST_LOCK.lock().expect("peer test lock");
        disarm_restart_reset();
        clear_pending_requests();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        register_mme_peer("mme.registered.example.com", tx);

        let result = hss_s6a_send_clr(
            "123456789012345",
            Some("mme.registered.example.com"),
            Some("example.com"),
            CancellationType::MmeUpdateProcedure,
        );
        assert!(result.is_ok());

        let sent = rx.try_recv().expect("CLR should be enqueued for the peer");
        assert_eq!(sent.header.command_code, 317);
        assert!(sent.header.is_request());
        assert_eq!(sent.user_name(), Some("123456789012345"));

        unregister_mme_peer("mme.registered.example.com");
    }

    #[test]
    fn test_send_idr_without_db_fails() {
        // IDR requires the subscriber DB; without it the call must error
        let result = hss_s6a_send_idr("123456789012345", 0, NEXTGCORE_DIAM_S6A_SUBDATA_ALL);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_pur_without_db_fails() {
        let result = handle_pur("123456789012345", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_ulr_without_db_fails() {
        let result = handle_ulr(
            "123456789012345",
            &[0x00, 0xF1, 0x10],
            0,
            "mme.example.com",
            "example.com",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_air_without_db_fails() {
        let result = handle_air("123456789012345", &[0x00, 0xF1, 0x10], None, 1);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_dispatch_async_offloads_blocking_work() {
        let air = make_air();
        let answer = dispatch_s6a_request_async(air).await.unwrap();
        assert!(answer.header.is_answer());
        assert_ne!(answer.result_code(), Some(2001));
    }

    /// An HSS advertising S6a/Cx/SWx must accept an MME advertising S6a, and
    /// must REFUSE a peer that speaks only Gx/Rx (RFC 6733 §5.3).
    ///
    /// Distinct from the end-to-end test below, which leaves both registries
    /// empty and therefore exercises the backward-compatibility path rather than
    /// negotiation. This one drives the real `hss_s6a_serve` with the same
    /// application set `main.rs` configures.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn s6a_server_negotiates_applications_with_its_peer() {
        let _guard = PEER_TEST_LOCK.lock().expect("peer test lock");
        disarm_restart_reset();
        clear_pending_requests();
        use nextgcore_diameter::applications::{well_known, ApplicationRegistry};
        use nextgcore_diameter::config::DiameterConfig;
        use nextgcore_diameter::transport::{DiameterClient, DiameterListener};

        let hss_apps = || {
            ApplicationRegistry::new("NextGCore HSS")
                .with_application(well_known::S6A)
                .with_application(well_known::CX)
                .with_application(well_known::SWX)
        };

        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server_cfg = DiameterConfig {
            diameter_id: "hss.neg.example.org".to_string(),
            diameter_realm: "neg.example.org".to_string(),
            address: Some("127.0.0.1".to_string()),
            applications: hss_apps(),
            ..Default::default()
        };
        tokio::spawn(async move {
            let _ = hss_s6a_serve(listener, server_cfg).await;
        });

        // An MME (S6a) shares an application with the HSS: accepted.
        let mme_cfg = DiameterConfig {
            diameter_id: "mme.neg.example.org".to_string(),
            diameter_realm: "neg.example.org".to_string(),
            applications: ApplicationRegistry::new("NextGCore MME")
                .with_application(well_known::S6A),
            ..Default::default()
        };
        let mut mme = DiameterClient::new(mme_cfg, addr);
        mme.connect().await.expect("S6a is common, must connect");
        assert!(mme.is_connected());

        // A PCRF (Gx/Rx) shares nothing with an S6a/Cx/SWx HSS: refused.
        let pcrf_cfg = DiameterConfig {
            diameter_id: "pcrf.neg.example.org".to_string(),
            diameter_realm: "neg.example.org".to_string(),
            applications: ApplicationRegistry::new("NextGCore PCRF")
                .with_application(well_known::GX)
                .with_application(well_known::RX),
            ..Default::default()
        };
        let mut pcrf = DiameterClient::new(pcrf_cfg, addr);
        let result = pcrf.connect().await;
        assert!(
            result.is_err(),
            "a peer with no common application must be refused, got {result:?}"
        );
        assert!(!pcrf.is_connected());
    }

    /// Full S6a integration over real TCP: CER/CEA, AIR dispatched off the
    /// Diameter thread, and an HSS-initiated CLR actually transmitted to the
    /// connected MME peer and answered with a CLA.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_s6a_server_end_to_end_air_and_clr() {
        let _guard = PEER_TEST_LOCK.lock().expect("peer test lock");
        disarm_restart_reset();
        clear_pending_requests();
        use nextgcore_diameter::config::DiameterConfig;
        use nextgcore_diameter::transport::{DiameterClient, DiameterListener};

        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server_cfg = DiameterConfig {
            diameter_id: "hss.e2e.example.org".to_string(),
            diameter_realm: "e2e.example.org".to_string(),
            timer_tc: 30,
            ..Default::default()
        };
        tokio::spawn(async move {
            let _ = hss_s6a_serve(listener, server_cfg).await;
        });

        // MME side: connect (CER/CEA)
        let client_cfg = DiameterConfig {
            diameter_id: "mme.e2e.example.org".to_string(),
            diameter_realm: "e2e.example.org".to_string(),
            timer_tc: 30,
            ..Default::default()
        };
        let mut client = DiameterClient::new(client_cfg, addr);
        client.connect().await.unwrap();

        // AIR -> answered (no DB: well-formed failure, never silence)
        let air = nextgcore_diameter::s6a::create_air(
            "e2e-session-1",
            "mme.e2e.example.org",
            "e2e.example.org",
            "e2e.example.org",
            "001010000000042",
            &[0x00, 0xF1, 0x10],
            1,
        );
        let answer = client.send_request(&air).await.unwrap();
        assert!(answer.header.is_answer());
        assert_eq!(answer.header.command_code, 318);
        assert_ne!(answer.result_code(), Some(2001));

        // HSS-initiated CLR rides the same connection to the registered peer.
        // Registration happens on the server's Established event; retry briefly.
        let mut sent = Err("unsent".to_string());
        for _ in 0..50 {
            sent = hss_s6a_send_clr(
                "001010000000042",
                Some("mme.e2e.example.org"),
                Some("e2e.example.org"),
                CancellationType::SubscriptionWithdrawal,
            );
            if sent.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        sent.expect("CLR should be transmitted to the connected MME");

        let inbound = client
            .recv_inbound_request(std::time::Duration::from_secs(5))
            .await
            .unwrap()
            .expect("MME should receive the CLR");
        assert!(inbound.header.is_request());
        assert_eq!(inbound.header.command_code, 317);
        assert_eq!(inbound.user_name(), Some("001010000000042"));
        let ct = inbound
            .find_vendor_avp(
                nextgcore_diameter::s6a::avp::CANCELLATION_TYPE,
                NEXTGCORE_3GPP_VENDOR_ID,
            )
            .and_then(|a| a.as_i32());
        assert_eq!(ct, Some(CancellationType::SubscriptionWithdrawal as i32));

        // Answer with CLA; the server consumes it (stats path)
        let mut cla = DiameterMessage::new_answer(&inbound);
        if let Some(sid) = inbound.session_id() {
            cla.add_avp(Avp::mandatory(
                avp_code::SESSION_ID,
                AvpData::Utf8String(sid.to_string()),
            ));
        }
        cla.add_avp(Avp::mandatory(
            avp_code::RESULT_CODE,
            AvpData::Unsigned32(2001),
        ));
        client.send_answer(&cla).await.unwrap();
    }

    // ====================================================================
    // #56: HSS-initiated procedures
    // ====================================================================

    // ---- previous-MME Cancel Location on ULR (TS 29.272 §5.2.1.1.3) ----

    /// The case §5.2.1.1.3 exists for: an inter-MME location update.
    #[test]
    fn a_different_previous_mme_needs_a_cancel_location() {
        assert_eq!(
            previous_mme_needing_cancel(
                Some(("mme1.epc.example.org", "epc.example.org")),
                "mme2.epc.example.org",
                "epc.example.org"
            ),
            Some((
                "mme1.epc.example.org".to_string(),
                "epc.example.org".to_string()
            ))
        );
    }

    /// The SAME MME re-registering must NOT be cancelled. A spurious Cancel
    /// Location detaches the UE that has just attached, which is worse than the
    /// stale context this fix exists to clear.
    #[test]
    fn the_same_mme_re_registering_needs_no_cancel_location() {
        assert_eq!(
            previous_mme_needing_cancel(
                Some(("mme1.epc.example.org", "epc.example.org")),
                "mme1.epc.example.org",
                "epc.example.org"
            ),
            None
        );
        // Case-insensitively, because a Diameter identity is a FQDN
        // (RFC 6733 §4.3.1) and a case difference is the same node.
        assert_eq!(
            previous_mme_needing_cancel(
                Some(("MME1.EPC.Example.ORG", "EPC.Example.ORG")),
                "mme1.epc.example.org",
                "epc.example.org"
            ),
            None,
            "a case difference is the same node, not a handover"
        );
    }

    /// A first attach has no previous MME.
    #[test]
    fn no_previous_mme_needs_no_cancel_location() {
        assert_eq!(
            previous_mme_needing_cancel(None, "mme1.epc.example.org", "epc.example.org"),
            None
        );
        assert_eq!(
            previous_mme_needing_cancel(Some(("", "")), "mme1.epc.example.org", "epc.example.org"),
            None,
            "an empty stored host names no reachable node"
        );
    }

    /// A realm change with the same host name is still a different node.
    #[test]
    fn a_realm_change_needs_a_cancel_location() {
        assert_eq!(
            previous_mme_needing_cancel(
                Some(("mme1.epc.a.org", "epc.a.org")),
                "mme1.epc.a.org",
                "epc.b.org"
            ),
            Some(("mme1.epc.a.org".to_string(), "epc.a.org".to_string()))
        );
    }

    // ---- reliability: retransmission, abandonment, requeue (RFC 6733 §5.5.4) ----

    fn secs(n: u64) -> std::time::Duration {
        std::time::Duration::from_secs(n)
    }

    /// An unanswered request past its Tc-scale period is retransmitted.
    #[test]
    fn an_unanswered_request_is_retransmitted_after_the_period() {
        assert_eq!(
            decide_pending_action(1, secs(31), true, false, secs(30), 3),
            PendingAction::Retransmit
        );
    }

    /// Before the period expires it is left alone: retrying sooner adds load to a
    /// peer that may simply be slow.
    #[test]
    fn a_recent_request_is_not_retransmitted() {
        assert_eq!(
            decide_pending_action(1, secs(5), true, false, secs(30), 3),
            PendingAction::Wait
        );
    }

    /// Retries are bounded: an unbounded queue is a memory leak with a Diameter
    /// interface attached.
    #[test]
    fn a_request_out_of_attempts_is_abandoned() {
        assert_eq!(
            decide_pending_action(3, secs(31), true, false, secs(30), 3),
            PendingAction::Abandon
        );
    }

    /// A request whose peer is DISCONNECTED must neither be retransmitted (there is
    /// no socket) nor abandoned (spending its budget against an absent peer would
    /// drop it before the peer returns). It waits — that is the requeue case, and it
    /// is the difference between #56's "requeued when the MME reconnects" and the
    /// old "failed immediately when no peer is connected".
    #[test]
    fn a_request_for_a_disconnected_peer_waits_rather_than_being_abandoned() {
        // Flagged as awaiting the peer, well past the period and out of attempts:
        // still Wait.
        assert_eq!(
            decide_pending_action(3, secs(3600), false, true, secs(30), 3),
            PendingAction::Wait
        );
        // Not flagged, but the peer is gone: also Wait.
        assert_eq!(
            decide_pending_action(1, secs(3600), false, false, secs(30), 3),
            PendingAction::Wait
        );
    }

    /// A CLR for a disconnected MME is QUEUED, not dropped, and delivered when the
    /// peer registers. Before #56 `send_to_mme` returned an error and the procedure
    /// was silently lost.
    #[tokio::test]
    async fn a_clr_for_a_disconnected_peer_is_queued_and_delivered_on_reconnect() {
        let _guard = PEER_TEST_LOCK.lock().expect("peer test lock");
        disarm_restart_reset();
        clear_pending_requests();
        let host = "mme-requeue.epc.example.org";
        // No peer registered: the send fails and the request is parked.
        let clr = build_clr_request(
            "001010000000001",
            host,
            "epc.example.org",
            CancellationType::MmeUpdateProcedure,
            None,
        );
        send_tracked(host, clr).expect("a queued request is not an error to the caller");
        assert_eq!(
            pending_request_count(),
            1,
            "the request must be held, not dropped"
        );

        // The MME connects.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        register_mme_peer(host, tx);

        let delivered = rx
            .try_recv()
            .expect("the queued CLR must be delivered on reconnect");
        assert_eq!(
            delivered.header.command_code,
            nextgcore_diameter::s6a::cmd::CANCEL_LOCATION
        );
        assert_eq!(
            delivered
                .find_vendor_avp(s6a::avp::CANCELLATION_TYPE, NEXTGCORE_3GPP_VENDOR_ID)
                .and_then(|a| a.as_i32()),
            Some(CancellationType::MmeUpdateProcedure as i32),
            "and it must still be the MME_UPDATE_PROCEDURE cancellation it was built as"
        );

        unregister_mme_peer(host);
        clear_pending_requests();
    }

    /// An answer clears its outstanding request, so it is not retransmitted. Before
    /// #56 `handle_s6a_answer` only bumped a counter, so nothing could distinguish
    /// an answered request from a lost one.
    #[tokio::test]
    async fn an_answer_clears_its_outstanding_request() {
        let _guard = PEER_TEST_LOCK.lock().expect("peer test lock");
        disarm_restart_reset();
        clear_pending_requests();
        let host = "mme-correlate.epc.example.org";
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        register_mme_peer(host, tx);

        let clr = build_clr_request(
            "001010000000002",
            host,
            "epc.example.org",
            CancellationType::SubscriptionWithdrawal,
            None,
        );
        send_tracked(host, clr).expect("send");
        assert_eq!(pending_request_count(), 1);

        let sent = rx.try_recv().expect("CLR sent");
        let session_id = sent.session_id().expect("Session-Id").to_string();

        // The MME answers.
        let mut cla = DiameterMessage::new_answer(&sent);
        cla.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String(session_id),
        ));
        cla.add_avp(Avp::mandatory(
            avp_code::RESULT_CODE,
            AvpData::Unsigned32(2001),
        ));
        handle_s6a_answer(&cla);

        assert_eq!(
            pending_request_count(),
            0,
            "an answered request must not stay outstanding, or it will be retransmitted"
        );

        unregister_mme_peer(host);
        clear_pending_requests();
    }

    // ---- NOR / NOA (TS 29.272 §5.2.5.1.1, §7.2.17) ----

    fn build_test_nor(imsi: &str) -> DiameterMessage {
        let mut msg = DiameterMessage::new_request(
            nextgcore_diameter::s6a::cmd::NOTIFY,
            s6a::S6A_APPLICATION_ID,
        );
        msg.header.hop_by_hop_id = 0x4242;
        msg.header.end_to_end_id = 0x4243;
        msg.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String(format!("mme;1;1;{imsi}")),
        ));
        msg.add_avp(Avp::mandatory(
            avp_code::AUTH_SESSION_STATE,
            AvpData::Enumerated(1),
        ));
        msg.add_avp(Avp::mandatory(
            avp_code::ORIGIN_HOST,
            AvpData::DiameterIdentity("mme1.epc.example.org".to_string()),
        ));
        msg.add_avp(Avp::mandatory(
            avp_code::ORIGIN_REALM,
            AvpData::DiameterIdentity("epc.example.org".to_string()),
        ));
        msg.add_avp(Avp::mandatory(
            avp_code::DESTINATION_REALM,
            AvpData::DiameterIdentity("epc.example.org".to_string()),
        ));
        msg.add_avp(Avp::mandatory(
            avp_code::USER_NAME,
            AvpData::Utf8String(imsi.to_string()),
        ));
        msg
    }

    fn roundtrip(msg: &DiameterMessage) -> DiameterMessage {
        let encoded = msg.encode();
        let mut bytes = encoded.freeze();
        DiameterMessage::decode(&mut bytes).expect("decode")
    }

    /// The PDN-GW identity and its APN scope are read off the wire.
    #[test]
    fn parse_nor_reads_the_pdn_gw_identity_and_its_apn() {
        let mut nor = build_test_nor("001010000000010");
        // MIP6-Agent-Info carries NO vendor id (RFC 5447).
        nor.add_avp(Avp::mandatory(
            s6a::avp::MIP6_AGENT_INFO,
            AvpData::Grouped(vec![Avp::mandatory(
                s6a::avp::MIP_HOME_AGENT_HOST,
                AvpData::Grouped(vec![
                    Avp::mandatory(
                        avp_code::DESTINATION_HOST,
                        AvpData::DiameterIdentity("pgw1.epc.example.org".to_string()),
                    ),
                    Avp::mandatory(
                        avp_code::DESTINATION_REALM,
                        AvpData::DiameterIdentity("epc.example.org".to_string()),
                    ),
                ]),
            )]),
        ));
        // Service-Selection also carries no vendor id (RFC 5778).
        nor.add_avp(Avp::mandatory(
            s6a::avp::SERVICE_SELECTION,
            AvpData::Utf8String("internet".to_string()),
        ));

        let info = parse_nor(&roundtrip(&nor));
        assert_eq!(
            info.pdn_gw.fqdn.as_ref().map(|(h, _)| h.as_str()),
            Some("pgw1.epc.example.org")
        );
        assert_eq!(info.service_selection.as_deref(), Some("internet"));
        let (identity, scope) = info.storable_pdn_gw().expect("storable");
        assert_eq!(identity, "pgw1.epc.example.org");
        assert_eq!(scope, ApnScope::ServiceSelection("internet".to_string()));
    }

    /// A PDN-GW identity with no APN scope names nothing to file it against, so it
    /// is refused rather than stored somewhere arbitrary.
    #[test]
    fn an_unscoped_pdn_gw_identity_is_not_storable() {
        let mut nor = build_test_nor("001010000000011");
        nor.add_avp(Avp::mandatory(
            s6a::avp::MIP6_AGENT_INFO,
            AvpData::Grouped(vec![Avp::mandatory(
                s6a::avp::MIP_HOME_AGENT_ADDRESS,
                AvpData::OctetString(bytes::Bytes::from_static(&[0, 1, 10, 45, 0, 1])),
            )]),
        ));
        let info = parse_nor(&roundtrip(&nor));
        assert_eq!(
            info.pdn_gw.address.as_deref(),
            Some(&[0, 1, 10, 45, 0, 1][..])
        );
        assert!(
            info.storable_pdn_gw().is_none(),
            "no Context-Identifier and no Service-Selection means nothing names the APN"
        );
    }

    /// A NOR carrying nothing this HSS stores is answered NOA 2001, not 3001.
    ///
    /// Before #56 it fell to the dispatch catch-all and got 3001 + the E-bit, which
    /// tells a conformant MME the whole Notify command is unsupported — so it stops
    /// using the procedure, including the PDN-GW notification that IS handled.
    #[test]
    fn a_nor_with_nothing_to_store_is_answered_noa() {
        let nor = roundtrip(&build_test_nor("001010000000012"));
        let info = parse_nor(&nor);
        assert!(info.pdn_gw.is_empty());
        assert!(
            handle_nor("001010000000012", &info).is_ok(),
            "an informational NOR this HSS does not model is still a success"
        );

        let noa = roundtrip(&build_noa_answer(&nor));
        assert_eq!(noa.result_code(), Some(2001));
        assert_eq!(
            noa.header.command_code,
            nextgcore_diameter::s6a::cmd::NOTIFY
        );
        assert!(
            !noa.header.is_request(),
            "the R bit must be cleared in the answer"
        );
        assert!(
            !noa.header.is_error(),
            "and the E bit must NOT be set, which 3001 would have required"
        );
    }

    // ---- DSR / RSR builders (TS 29.272 §7.2.11, §7.2.15) ----

    /// DSR-Flags is the one mandatory 3GPP IE, and Context-Identifiers only travel
    /// with the PDN-subscription-contexts bit (§7.3.25 Note 1).
    #[test]
    fn dsr_carries_flags_and_scopes_context_identifiers_to_their_bit() {
        hss_s6a_set_identity("hss.epc.example.org", "epc.example.org");
        let with_bit = roundtrip(&build_dsr_request(
            "001010000000020",
            "mme1.epc.example.org",
            "epc.example.org",
            s6a::dsr_flags::PDN_SUBSCRIPTION_CONTEXTS_WITHDRAWAL,
            &[3, 4],
        ));
        assert_eq!(
            with_bit.header.command_code,
            nextgcore_diameter::s6a::cmd::DELETE_SUBSCRIBER_DATA
        );
        assert!(with_bit.header.is_request());
        assert_eq!(
            with_bit
                .find_vendor_avp(s6a::avp::DSR_FLAGS, NEXTGCORE_3GPP_VENDOR_ID)
                .and_then(|a| a.as_u32()),
            Some(s6a::dsr_flags::PDN_SUBSCRIPTION_CONTEXTS_WITHDRAWAL)
        );
        let ids: Vec<u32> =
            nextgcore_diameter::avp::find_all_avps(&with_bit.avps, s6a::avp::CONTEXT_IDENTIFIER)
                .iter()
                .filter_map(|a| a.as_u32())
                .collect();
        assert_eq!(ids, vec![3, 4]);
        assert_eq!(with_bit.user_name(), Some("001010000000020"));

        // Without the bit, the identifiers must NOT be sent: they would name
        // contexts the MME has not been told to delete.
        let without_bit = roundtrip(&build_dsr_request(
            "001010000000020",
            "mme1.epc.example.org",
            "epc.example.org",
            s6a::dsr_flags::STN_SR,
            &[3, 4],
        ));
        assert!(
            nextgcore_diameter::avp::find_all_avps(&without_bit.avps, s6a::avp::CONTEXT_IDENTIFIER)
                .is_empty(),
            "Context-Identifier without its withdrawal bit is a message the spec does not define"
        );
    }

    /// Reset applies to a SET of subscribers, named by User-Id prefixes. §7.2.15's
    /// message format has no User-Name at all, so sending one would be a per-
    /// subscriber Reset the spec does not define.
    #[test]
    fn rsr_carries_user_id_prefixes_and_no_user_name() {
        hss_s6a_set_identity("hss.epc.example.org", "epc.example.org");
        let rsr = roundtrip(&build_rsr_request(
            "mme1.epc.example.org",
            "epc.example.org",
            &["00101".to_string(), "00102".to_string()],
        ));
        assert_eq!(rsr.header.command_code, nextgcore_diameter::s6a::cmd::RESET);
        assert!(rsr.header.is_request());
        assert_eq!(
            rsr.user_name(),
            None,
            "Reset is not per-subscriber; §7.2.15 has no User-Name"
        );
        let ids: Vec<String> = nextgcore_diameter::avp::find_all_avps(&rsr.avps, s6a::avp::USER_ID)
            .iter()
            .filter_map(|a| a.as_utf8_string().map(str::to_string))
            .collect();
        assert_eq!(ids, vec!["00101".to_string(), "00102".to_string()]);

        // No User-Ids: the plain restart case, "all my subscribers".
        let all = roundtrip(&build_rsr_request(
            "mme1.epc.example.org",
            "epc.example.org",
            &[],
        ));
        assert!(nextgcore_diameter::avp::find_all_avps(&all.avps, s6a::avp::USER_ID).is_empty());
        assert_eq!(
            all.find_avp(avp_code::DESTINATION_HOST)
                .and_then(|a| a.as_utf8_string()),
            Some("mme1.epc.example.org")
        );
    }

    // ---- restart restoration (TS 29.272 §5.2.3, TS 23.007) ----

    /// The marker decides, and the direction matters: a start with no marker must
    /// NOT be treated as a crash, because a spurious Reset makes every MME re-run
    /// Update Location for its whole subscriber base.
    #[test]
    fn a_leftover_running_marker_means_the_previous_shutdown_was_unclean() {
        assert!(unclean_shutdown_from_marker(true));
        assert!(!unclean_shutdown_from_marker(false));
    }

    /// A clean cycle leaves nothing behind; a crash does.
    #[test]
    fn the_running_marker_round_trips_through_a_clean_shutdown() {
        let dir = std::env::temp_dir().join(format!(
            "nextgcore-hss-marker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        // SAFETY: single-threaded test setup; the variable is read by
        // `running_marker_path` in this same thread.
        std::env::set_var("HSS_RUNTIME_DIR", &dir);

        // First ever start: no marker.
        assert!(!claim_running_marker(), "a first start is not a crash");
        assert!(running_marker_path().exists(), "and it leaves its marker");

        // Clean shutdown.
        release_running_marker();
        assert!(!running_marker_path().exists());
        assert!(
            !claim_running_marker(),
            "a start after a clean shutdown is not a crash"
        );

        // Crash: the marker stays.
        assert!(
            claim_running_marker(),
            "a start while a marker is present IS a crash"
        );

        release_running_marker();
        std::env::remove_var("HSS_RUNTIME_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An MME registering while restoration is armed is sent a Reset-Request.
    ///
    /// Armed rather than sent at startup because the HSS is the S6a *responder*: at
    /// startup no MME is connected, so an immediate send reaches nobody — the shape
    /// of a procedure that looks implemented and never fires.
    #[tokio::test]
    async fn an_mme_registering_after_an_unclean_restart_is_sent_a_reset() {
        let _guard = PEER_TEST_LOCK.lock().expect("peer test lock");
        clear_pending_requests();
        hss_s6a_set_identity("hss.epc.example.org", "epc.example.org");
        arm_restart_reset(Vec::new());
        assert!(restart_reset_armed());

        let host = "mme-reset.epc.example.org";
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        register_mme_peer(host, tx);

        let msg = rx
            .try_recv()
            .expect("a registering MME must be sent the Reset");
        assert_eq!(msg.header.command_code, nextgcore_diameter::s6a::cmd::RESET);
        assert_eq!(
            msg.find_avp(avp_code::DESTINATION_HOST)
                .and_then(|a| a.as_utf8_string()),
            Some(host)
        );

        unregister_mme_peer(host);
        clear_pending_requests();
        // Disarm before releasing the lock: leaving it armed makes every later
        // peer registration receive a Reset it did not ask for.
        disarm_restart_reset();
    }
}
