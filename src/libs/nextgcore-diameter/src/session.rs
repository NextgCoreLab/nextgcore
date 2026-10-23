//! Concurrent request/answer multiplexing over a single Diameter connection.
//!
//! # The problem this solves
//!
//! [`crate::transport::DiameterClient::send_request`] takes `&mut self`, so a
//! caller that wants to issue requests from several tasks has to serialise them
//! behind a lock. `nextgcore-mmed` did exactly that: a process-global
//! `Mutex<Option<S6aClientState>>` taken **before** `send_request` and held
//! **across** the await. One slow HSS answer therefore blocked every other
//! subscriber's S6a exchange — not just the one that stalled. Adding a request
//! timeout (see `DiameterError::RequestTimeout`) bounded the outage, but the
//! lock is the cause, so the outage was merely finite rather than absent.
//!
//! # The shape of the fix
//!
//! RFC 6733 §3 gives every request a Hop-by-Hop Identifier and requires the
//! answer to echo it. That is precisely a correlation token, so the conventional
//! design is a *multiplexer*: one task owns the connection and reads
//! continuously; senders register a one-shot channel under their Hop-by-Hop ID
//! and await it. Nothing is serialised except the brief moment of writing to the
//! socket and touching the pending-request map.
//!
//! This also composes with the failover work RFC 6733 §5.5.4 needs: the pending
//! map is exactly the set of requests that would have to be re-sent to an
//! alternate peer with the `T` flag set. That is not implemented here.
//!
//! # What is deliberately NOT here
//!
//! # Watchdog (RFC 6733 §5.5, RFC 3539 §3.4.1)
//!
//! The reader runs the Device-Watchdog algorithm: when nothing has been received
//! for Tw it sends a DWR; when nothing at all arrives within the next Tw it
//! closes the session (RFC 3539's SUSPECT state, whose action is failover: for a
//! single-peer client, failover IS the application's redial). Without it a peer
//! that vanishes without a FIN or RST (a crashed node, a partition) leaves a
//! half-open connection, every request times out, and the session stays "up"
//! until the kernel gives up retransmitting, around 15 minutes (#729).
//!
//! - Reconnection. [`DiameterSession::start`] takes an already-connected
//!   [`DiameterClient`]. When the reader sees the peer go away it fails every
//!   waiter and stops; deciding whether to redial is the application's business
//!   and mixing it in would make this module a supervisor as well as a
//!   multiplexer.
//! - Failover to an alternate peer, and the `T` retransmit flag.
//! - Any change to `DiameterClient::send_request`, which keeps working for the
//!   single-threaded callers (hssd's tests, the crate's own tests).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, Mutex};

use crate::error::{DiameterError, DiameterResult};
use crate::message::DiameterMessage;
use crate::peer::{DiameterPeer, PeerEvent};
use crate::transport::DiameterClient;

/// A request awaiting its answer, keyed by Hop-by-Hop Identifier.
type PendingMap = Arc<Mutex<HashMap<u32, oneshot::Sender<DiameterMessage>>>>;

/// A handle for issuing Diameter requests concurrently over one connection.
///
/// Cheap to clone: every clone shares the same connection, the same pending-map
/// and the same reader task. Requests from different tasks interleave; a slow
/// answer delays only the task waiting for it.
#[derive(Clone)]
pub struct DiameterSession {
    /// Outbound messages, serialised by the writer half of the reader task.
    tx: mpsc::Sender<DiameterMessage>,
    pending: PendingMap,
    /// Peer-initiated requests (e.g. S6a CLR/IDR) for the application to drain.
    inbound_rx: Arc<Mutex<mpsc::Receiver<DiameterMessage>>>,
    hop_by_hop: Arc<AtomicU32>,
    end_to_end: Arc<AtomicU32>,
    request_timeout: Duration,
}

impl DiameterSession {
    /// Take ownership of a connected client and start multiplexing.
    ///
    /// The returned [`JoinHandle`](tokio::task::JoinHandle) is the reader task;
    /// dropping it detaches, and aborting it tears the session down. The client
    /// must already be connected — `start` does not perform CER/CEA.
    pub fn start(client: DiameterClient) -> DiameterResult<(Self, tokio::task::JoinHandle<()>)> {
        let options = SessionOptions::from_config(client.config(), WatchdogStart::Okay);
        Self::start_with(client, options)
    }

    /// [`Self::start`] for a connection re-established after the previous one
    /// failed: the watchdog starts in RFC 3539 §3.4.1 REOPEN, so application
    /// traffic waits until three watchdog exchanges succeed (#729 review M1).
    pub fn start_reopened(
        client: DiameterClient,
    ) -> DiameterResult<(Self, tokio::task::JoinHandle<()>)> {
        let options = SessionOptions::from_config(client.config(), WatchdogStart::Reopen);
        Self::start_with(client, options)
    }

    /// [`Self::start`] with an explicit watchdog interval Tw, not floored at the
    /// RFC's 6 seconds and not jittered when below it. For tests that need a
    /// silent peer detected in milliseconds; production callers use `start`.
    pub fn start_with_watchdog(
        client: DiameterClient,
        tw: Duration,
    ) -> DiameterResult<(Self, tokio::task::JoinHandle<()>)> {
        Self::start_with(
            client,
            SessionOptions {
                tw,
                start: WatchdogStart::Okay,
            },
        )
    }

    /// Start with explicit [`SessionOptions`].
    pub fn start_with(
        client: DiameterClient,
        options: SessionOptions,
    ) -> DiameterResult<(Self, tokio::task::JoinHandle<()>)> {
        Self::start_session(client, options, true)
    }

    /// [`Self::start_with`]; `user_timeout` false leaves the socket's
    /// TCP_USER_TIMEOUT unset, so a test can prove the Tw write bound on its own.
    fn start_session(
        client: DiameterClient,
        options: SessionOptions,
        user_timeout: bool,
    ) -> DiameterResult<(Self, tokio::task::JoinHandle<()>)> {
        let tw = options.tw;
        let request_timeout = Duration::from_secs(client.config().request_timeout as u64);
        let (hop_seed, end_seed) = client.identifier_seeds();
        let peer = client
            .into_peer()
            .ok_or(DiameterError::Protocol("client is not connected".into()))?;

        let (tx, rx) = mpsc::channel::<DiameterMessage>(256);
        // Bounded so a peer flooding CLR/IDR at an application that never drains
        // cannot grow this without limit; the reader logs and drops on overflow.
        let (inbound_tx, inbound_rx) = mpsc::channel::<DiameterMessage>(64);
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

        // #729 review B1: unacknowledged data may not hold the socket longer than
        // 2 x Tw (TCP_USER_TIMEOUT), so a vanished peer fails the connection at
        // the kernel too, whatever is queued.
        if user_timeout {
            if let Err(e) = peer.set_user_timeout(tw * 2) {
                log::warn!(
                    "Diameter: TCP_USER_TIMEOUT not set ({e}); writes are bounded by Tw only"
                );
            }
        }
        let handle = tokio::spawn(run_session(
            peer,
            rx,
            inbound_tx,
            Arc::clone(&pending),
            Watchdog::new(tw, options.start),
        ));

        Ok((
            Self {
                tx,
                pending,
                inbound_rx: Arc::new(Mutex::new(inbound_rx)),
                hop_by_hop: Arc::new(AtomicU32::new(hop_seed)),
                end_to_end: Arc::new(AtomicU32::new(end_seed)),
                request_timeout,
            },
            handle,
        ))
    }

    /// Send a request and await its answer, concurrently with other callers.
    ///
    /// Assigns Hop-by-Hop and End-to-End identifiers when the message carries
    /// zero, per RFC 6733 §3. Returns [`DiameterError::RequestTimeout`] if no
    /// answer arrives within the configured window, and the pending entry is
    /// removed so a very late answer is dropped rather than leaking.
    pub async fn send_request(&self, msg: &DiameterMessage) -> DiameterResult<DiameterMessage> {
        let mut request = msg.clone();
        if request.header.hop_by_hop_id == 0 {
            request.header.hop_by_hop_id = self.next_hop_by_hop();
        }
        if request.header.end_to_end_id == 0 {
            request.header.end_to_end_id = self.next_end_to_end();
        }
        let hop_by_hop_id = request.header.hop_by_hop_id;
        let command = request.header.command_code;

        let (answer_tx, answer_rx) = oneshot::channel();
        // Registered BEFORE the send: if the answer arrived first, the reader
        // would find no waiter and drop it, and this caller would then wait out
        // the full timeout for an answer that had already been and gone.
        self.pending.lock().await.insert(hop_by_hop_id, answer_tx);

        if self.tx.send(request).await.is_err() {
            self.pending.lock().await.remove(&hop_by_hop_id);
            return Err(DiameterError::Protocol("session is closed".into()));
        }

        match tokio::time::timeout(self.request_timeout, answer_rx).await {
            Ok(Ok(answer)) => Ok(answer),
            // The reader dropped the sender: the connection went away.
            Ok(Err(_)) => {
                self.pending.lock().await.remove(&hop_by_hop_id);
                Err(DiameterError::Protocol("peer disconnected".into()))
            }
            Err(_) => {
                self.pending.lock().await.remove(&hop_by_hop_id);
                log::warn!(
                    "Diameter request (command {command}, hop-by-hop {hop_by_hop_id}) \
                     timed out after {}s with no answer",
                    self.request_timeout.as_secs()
                );
                Err(DiameterError::RequestTimeout {
                    command,
                    seconds: self.request_timeout.as_secs(),
                })
            }
        }
    }

    /// Send an answer to a peer-initiated request.
    pub async fn send_answer(&self, msg: &DiameterMessage) -> DiameterResult<()> {
        self.tx
            .send(msg.clone())
            .await
            .map_err(|_| DiameterError::Protocol("session is closed".into()))
    }

    /// Receive a peer-initiated request (e.g. S6a CLR/IDR), waiting up to
    /// `timeout`. `Ok(None)` on timeout.
    pub async fn recv_inbound_request(
        &self,
        timeout: Duration,
    ) -> DiameterResult<Option<DiameterMessage>> {
        let mut rx = self.inbound_rx.lock().await;
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(msg)) => Ok(Some(msg)),
            // Channel closed: the reader stopped, i.e. the peer is gone.
            Ok(None) => Err(DiameterError::Protocol("peer disconnected".into())),
            Err(_) => Ok(None),
        }
    }

    /// Number of requests currently awaiting an answer. Test/diagnostic use;
    /// a non-zero value that never drains indicates leaked waiters.
    pub async fn pending_count(&self) -> usize {
        self.pending.lock().await.len()
    }

    fn next_hop_by_hop(&self) -> u32 {
        // Relaxed is sufficient: uniqueness is all that matters, not ordering
        // relative to other memory operations.
        self.hop_by_hop
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    fn next_end_to_end(&self) -> u32 {
        self.end_to_end
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }
}

/// The reader task: owns the peer, writes queued messages, routes answers.
///
/// Reads and writes are interleaved in one task on purpose. The alternative —
/// separate reader and writer tasks — needs the transport split into halves, and
/// `DiameterTransport` is not written for that. A single task also removes any
/// question of two writers interleaving bytes of different messages.
async fn run_session(
    mut peer: DiameterPeer,
    mut outbound: mpsc::Receiver<DiameterMessage>,
    inbound: mpsc::Sender<DiameterMessage>,
    pending: PendingMap,
    mut watchdog: Watchdog,
) {
    // #729 review B1: every write is bounded by Tw. A peer that stops reading
    // (vanished host, partition) fills the socket buffer, and an unbounded
    // write would park this task, so the watchdog arm could never fire.
    let write_bound = watchdog.tw;
    if watchdog.state == WatchdogState::Reopen {
        // RFC 3539 §3.4.1, connection up from DOWN: send a watchdog at once.
        match tokio::time::timeout(write_bound, peer.send_watchdog()).await {
            Ok(Ok(())) => watchdog.sent(),
            Ok(Err(e)) => {
                log::warn!("Diameter Device-Watchdog-Request not sent: {e}");
                pending.lock().await.clear();
                return;
            }
            Err(_) => {
                log::warn!("Diameter Device-Watchdog-Request write stalled for Tw; closing");
                pending.lock().await.clear();
                return;
            }
        }
    }
    loop {
        tokio::select! {
            // RFC 3539 §3.4.1: the watchdog timer.
            _ = tokio::time::sleep_until(watchdog.deadline) => {
                match watchdog.expired() {
                    TimerAction::SendWatchdog => {
                        match tokio::time::timeout(write_bound, peer.send_watchdog()).await {
                            Ok(Ok(())) => {
                                log::debug!(
                                    "Diameter Device-Watchdog-Request sent to {:?}",
                                    peer.remote_host()
                                );
                                watchdog.sent();
                            }
                            Ok(Err(e)) => {
                                log::warn!("Diameter Device-Watchdog-Request not sent: {e}");
                                break;
                            }
                            Err(_) => {
                                log::warn!(
                                    "Diameter Device-Watchdog-Request to {:?} stalled for Tw \
                                     ({write_bound:?}): the peer is not reading; closing",
                                    peer.remote_host()
                                );
                                break;
                            }
                        }
                    }
                    TimerAction::Wait => {}
                    TimerAction::Close => {
                        log::warn!(
                            "Diameter peer {:?} did not answer the Device-Watchdog-Request \
                             within Tw ({:?}): closing the connection (RFC 3539 §3.4.1, RFC \
                             6733 §5.5)",
                            peer.remote_host(),
                            watchdog.tw
                        );
                        break;
                    }
                }
            }

            // `recv_raw` is cancel-safe (it only awaits a buffered read), which
            // is why this branch is sound. `next_event` would NOT be: it can
            // await a DWA/DPA write, and losing that race mid-write would leave
            // a partial message on the wire.
            read = peer.recv_raw() => {
                let msg = match read {
                    Ok(msg) => msg,
                    Err(e) => {
                        log::info!("Diameter session read ended: {e}");
                        break;
                    }
                };
                let is_dwa = msg.header.is_answer()
                    && msg.header.command_code == crate::message::base_cmd::DEVICE_WATCHDOG;
                // RFC 3539 §3.4.1: any receipt restarts the timer; only a DWA
                // clears the outstanding watchdog (and counts in REOPEN).
                watchdog.received(is_dwa);

                // A DWA is the reader's own, numbered from the peer state
                // machine's identifier space, which can overlap the session's:
                // it must never be handed to an application waiter.
                if is_dwa {
                    log::debug!("Diameter Device-Watchdog-Answer received");
                    continue;
                }

                // RFC 3539 §3.4.1 REOPEN, "Receive non-DWA: Throwaway()": an
                // application message on a connection that has not yet proved
                // itself is not delivered (#816 review m-f). Delivered, its
                // answer would be held behind the REOPEN gate on `outbound`.
                // A REQUEST is not dropped silently, though (#899 review): it is
                // answered DIAMETER_TOO_BUSY (3004, RFC 6733 §7.1.3: a specific
                // server was requested and cannot provide the service now), so
                // the sender keeps it and retries; a silent drop leaves the
                // sender to its own retransmission timer, and hssd's runs out
                // after three attempts 30 s apart. REOPEN here normally lasts
                // three watchdog round trips (each DWA asks for the next proof
                // at once), but can last a Tw or more against a slow peer.
                // Base-protocol messages (DWR, DPR) still reach the state
                // machine, which must answer them.
                if !watchdog.carries_traffic()
                    && msg.header.application_id != crate::message::BASE_APPLICATION_ID
                {
                    REOPEN_DISCARDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if !msg.header.is_request() {
                        log::info!(
                            "Diameter answer (command {}) from {:?} discarded: the connection is \
                             in REOPEN (RFC 3539 §3.4.1)",
                            msg.header.command_code,
                            peer.remote_host()
                        );
                        continue;
                    }
                    log::warn!(
                        "Diameter request (command {}) from {:?} received in REOPEN (RFC 3539 \
                         §3.4.1): answered DIAMETER_TOO_BUSY so it is retried",
                        msg.header.command_code,
                        peer.remote_host()
                    );
                    let busy = peer.protocol_error_answer(&msg, DIAMETER_TOO_BUSY);
                    match tokio::time::timeout(write_bound, peer.send_message(&busy)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            log::warn!("Diameter TOO_BUSY answer not sent: {e}");
                            break;
                        }
                        Err(_) => {
                            log::warn!("Diameter TOO_BUSY answer stalled for Tw; closing");
                            break;
                        }
                    }
                    continue;
                }

                // Answers are routed here rather than through the state machine:
                // an application answer carries no base-protocol meaning, and
                // matching it now keeps the hot path short.
                if msg.header.is_answer() {
                    let waiter = pending.lock().await.remove(&msg.header.hop_by_hop_id);
                    match waiter {
                        Some(tx) => {
                            // Err means the waiter timed out and went away; the
                            // answer is simply late, so drop it quietly.
                            let _ = tx.send(msg);
                        }
                        None => log::debug!(
                            "Diameter answer with unknown hop-by-hop id {} dropped",
                            msg.header.hop_by_hop_id
                        ),
                    }
                    continue;
                }

                // Requests and base-protocol messages go through the state
                // machine, which answers DWR/DPR itself: a write, so bounded.
                match tokio::time::timeout(write_bound, peer.handle_message(msg)).await {
                    Err(_) => {
                        log::warn!(
                            "Diameter answer to {:?} stalled for Tw: the peer is not reading; \
                             closing",
                            peer.remote_host()
                        );
                        break;
                    }
                    Ok(Ok(PeerEvent::Message(request))) => {
                        if let Err(e) = inbound.try_send(request) {
                            log::warn!("inbound Diameter request dropped: {e}");
                        }
                    }
                    Ok(Ok(PeerEvent::Disconnected)) => {
                        log::info!("Diameter peer disconnected");
                        break;
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        log::warn!("Diameter session state error: {e}");
                        break;
                    }
                }
            }

            // Writes are serialised through this one task, so no two messages
            // can interleave on the wire. RFC 3539 §3.4.1 REOPEN: application
            // traffic waits (queued) until the connection has proved itself.
            Some(msg) = outbound.recv(), if watchdog.carries_traffic() => {
                match tokio::time::timeout(write_bound, peer.send_message(&msg)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        log::warn!("Diameter session write failed: {e}");
                        break;
                    }
                    Err(_) => {
                        log::warn!(
                            "Diameter write to {:?} stalled for Tw ({write_bound:?}): the peer \
                             is not reading; closing so the application can redial",
                            peer.remote_host()
                        );
                        break;
                    }
                }
            }
        }
    }

    // Fail every waiter rather than leaving it to time out: dropping the senders
    // closes each oneshot, which surfaces as "peer disconnected" immediately.
    // Without this, a connection loss would stall every in-flight request for
    // the full request_timeout.
    pending.lock().await.clear();
}

/// RFC 6733 §7.1.3 DIAMETER_TOO_BUSY.
const DIAMETER_TOO_BUSY: u32 = 3004;

/// Application messages received in REOPEN and not delivered (#899 review).
static REOPEN_DISCARDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many application messages sessions of this process have not delivered
/// because they arrived in REOPEN (each request among them was answered
/// DIAMETER_TOO_BUSY). For an operator's metrics.
pub fn reopen_discards() -> u64 {
    REOPEN_DISCARDS.load(std::sync::atomic::Ordering::Relaxed)
}

/// RFC 3539 §3.4.1: "Tw MUST NOT be set lower than 6 seconds".
const MIN_TW_SECS: u32 = 6;

/// RFC 3539 §3.4.1: the number of watchdog answers a REOPEN connection needs
/// before it carries traffic again.
const REOPEN_DWA: i32 = 3;

/// Tw for `config`: `timer_tw` floored at the RFC's 6 seconds.
pub fn effective_tw(config: &crate::config::DiameterConfig) -> Duration {
    Duration::from_secs(u64::from(config.timer_tw.max(MIN_TW_SECS)))
}

/// Where a session's watchdog starts (RFC 3539 §3.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogStart {
    /// The first connection to the peer (INITIAL -> OKAY).
    Okay,
    /// A connection re-established after a failure (DOWN -> REOPEN).
    Reopen,
}

/// How a [`DiameterSession`] runs.
#[derive(Debug, Clone, Copy)]
pub struct SessionOptions {
    /// Watchdog interval Tw.
    pub tw: Duration,
    /// Initial watchdog state.
    pub start: WatchdogStart,
}

impl SessionOptions {
    /// Tw from `config` ([`effective_tw`]) and the given start state.
    pub fn from_config(config: &crate::config::DiameterConfig, start: WatchdogStart) -> Self {
        Self {
            tw: effective_tw(config),
            start,
        }
    }
}

/// RFC 3539 §3.4.1 watchdog states for a connected session. DOWN is the
/// session ending: there is no alternate peer to fail over to, so SUSPECT's
/// failover is closing (the application then redials), and the session never
/// returns from SUSPECT to OKAY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchdogState {
    Okay,
    Reopen,
}

/// What the timer's expiry asks for.
#[derive(Debug, PartialEq, Eq)]
enum TimerAction {
    SendWatchdog,
    Wait,
    Close,
}

/// The Device-Watchdog of one connection (RFC 3539 §3.4.1).
struct Watchdog {
    tw: Duration,
    deadline: tokio::time::Instant,
    /// A DWR is outstanding ("Pending").
    dwr_outstanding: bool,
    state: WatchdogState,
    /// REOPEN's NumDWA: DWAs received; -1 after one unanswered expiry.
    num_dwa: i32,
}

impl Watchdog {
    fn new(tw: Duration, start: WatchdogStart) -> Self {
        Self {
            tw,
            deadline: tokio::time::Instant::now() + jittered(tw),
            dwr_outstanding: false,
            state: match start {
                WatchdogStart::Okay => WatchdogState::Okay,
                WatchdogStart::Reopen => WatchdogState::Reopen,
            },
            num_dwa: 0,
        }
    }

    fn set_timer(&mut self) {
        self.deadline = tokio::time::Instant::now() + jittered(self.tw);
    }

    /// Whether application messages may be written: not in REOPEN.
    fn carries_traffic(&self) -> bool {
        self.state == WatchdogState::Okay
    }

    /// A message arrived; `dwa` when it is a Device-Watchdog-Answer.
    fn received(&mut self, dwa: bool) {
        match self.state {
            WatchdogState::Okay => {
                if dwa {
                    self.dwr_outstanding = false;
                }
                self.set_timer();
            }
            WatchdogState::Reopen => {
                if dwa {
                    self.dwr_outstanding = false;
                    // RFC 3539 §3.4.1: NumDWA++, so a DWA after the grace
                    // expiry (NumDWA = -1) brings it to 0: three more are needed.
                    self.num_dwa += 1;
                    if self.num_dwa >= REOPEN_DWA {
                        log::info!(
                            "Diameter connection answered {REOPEN_DWA} watchdogs: back in \
                             service (RFC 3539 §3.4.1 REOPEN -> OKAY)"
                        );
                        self.state = WatchdogState::Okay;
                        self.set_timer();
                    } else {
                        // There is no alternate peer whose traffic would be
                        // disturbed, so the next proof is asked for at once
                        // rather than after Tw: the connection returns to
                        // service in three round trips, not three Tw.
                        self.deadline = tokio::time::Instant::now();
                    }
                }
            }
        }
    }

    /// The timer expired.
    fn expired(&mut self) -> TimerAction {
        match self.state {
            WatchdogState::Okay => {
                if self.dwr_outstanding {
                    // SUSPECT: failover, which for this client is closing.
                    TimerAction::Close
                } else {
                    TimerAction::SendWatchdog
                }
            }
            WatchdogState::Reopen => {
                if self.dwr_outstanding && self.num_dwa < 0 {
                    TimerAction::Close
                } else if self.dwr_outstanding {
                    self.num_dwa = -1;
                    self.set_timer();
                    TimerAction::Wait
                } else {
                    TimerAction::SendWatchdog
                }
            }
        }
    }

    fn sent(&mut self) {
        self.dwr_outstanding = true;
        self.set_timer();
    }
}

/// Tw with the ±2 s jitter RFC 3539 §3.4.1 asks for, so peers that started
/// together do not send their watchdogs in lockstep. Not jittered below the
/// RFC's 6-second floor (test intervals), where ±2 s would swamp the value.
fn jittered(tw: Duration) -> Duration {
    if tw < Duration::from_secs(u64::from(MIN_TW_SECS)) {
        return tw;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    // 0..=4000 ms, centred on Tw.
    let offset_ms = u64::from(nanos % 4001);
    (tw + Duration::from_millis(offset_ms)).saturating_sub(Duration::from_secs(2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::avp::{Avp, AvpData};
    use crate::config::DiameterConfig;
    use crate::transport::DiameterListener;

    const AIR: u32 = 318;
    const S6A_APP: u32 = 16777251;

    fn config(host: &str, timeout_secs: u32) -> DiameterConfig {
        DiameterConfig {
            diameter_id: host.to_string(),
            diameter_realm: "example.com".to_string(),
            request_timeout: timeout_secs,
            ..Default::default()
        }
    }

    /// Answer each request after `delay`, handling requests CONCURRENTLY.
    ///
    /// The concurrency here is essential and was got wrong first time round: a
    /// mock that does `recv -> sleep -> send` in one sequential loop cannot read
    /// request 2 until it has answered request 1, so it serialises the exchange
    /// itself and `requests_from_multiple_tasks_overlap` measured 3x the delay
    /// even though the client was multiplexing correctly. The test was accusing
    /// the code under test of the harness's own defect.
    ///
    /// So this mirrors the real design: one task owns the peer and `select!`s
    /// between reading and writing, while a timer task per request queues the
    /// answer after the delay.
    async fn spawn_delayed_hss(
        listener: DiameterListener,
        delay: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let cfg = config("hss.example.com", 30);
        tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &cfg);
            peer.start().await.unwrap();
            let _cer = peer.next_event().await.unwrap();

            let (answer_tx, mut answer_rx) = mpsc::channel::<DiameterMessage>(16);
            loop {
                tokio::select! {
                    read = peer.recv_raw() => {
                        let Ok(msg) = read else { break };
                        let mut answer = DiameterMessage::new_answer(&msg);
                        answer.add_avp(Avp::mandatory(268, AvpData::Unsigned32(2001)));
                        let tx = answer_tx.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            let _ = tx.send(answer).await;
                        });
                    }
                    Some(answer) = answer_rx.recv() => {
                        if peer.send_message(&answer).await.is_err() {
                            break;
                        }
                    }
                }
            }
        })
    }

    async fn connected_session() -> (
        DiameterSession,
        tokio::task::JoinHandle<()>,
        SocketAddrHolder,
    ) {
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let hss = spawn_delayed_hss(listener, Duration::from_millis(300)).await;

        let mut client = DiameterClient::new(config("mme.example.com", 5), addr);
        client.connect().await.unwrap();
        let (session, reader) = DiameterSession::start(client).unwrap();
        (session, reader, SocketAddrHolder { _hss: hss })
    }

    /// Keeps the HSS task alive for the duration of a test.
    struct SocketAddrHolder {
        _hss: tokio::task::JoinHandle<()>,
    }

    /// The point of the whole change: three requests issued concurrently must
    /// overlap, not queue. With the old lock-across-send they took 3x the
    /// per-request latency; here they should finish in roughly 1x.
    #[tokio::test]
    async fn requests_from_multiple_tasks_overlap() {
        let (session, reader, _hss) = connected_session().await;

        let started = tokio::time::Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..3 {
            let s = session.clone();
            tasks.push(tokio::spawn(async move {
                let req = DiameterMessage::new_request(AIR, S6A_APP);
                s.send_request(&req).await
            }));
        }
        for t in tasks {
            let answer = t.await.unwrap().expect("each request is answered");
            assert_eq!(answer.result_code(), Some(2001));
        }
        let elapsed = started.elapsed();

        // Each answer is delayed 300ms. Serialised => >=900ms; overlapped =>
        // ~300ms. 700ms discriminates without being flaky on a loaded runner.
        assert!(
            elapsed < Duration::from_millis(700),
            "requests were serialised, not multiplexed: {elapsed:?}"
        );
        reader.abort();
    }

    /// Answers must reach the caller that sent the matching request, even when
    /// the peer answers out of order. This is what the Hop-by-Hop map buys, and
    /// a naive implementation that hands each answer to the next waiter in line
    /// would pass the timing test above while failing this one.
    #[tokio::test]
    async fn answers_are_routed_by_hop_by_hop_id() {
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let cfg = config("hss.example.com", 30);
        let hss = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &cfg);
            peer.start().await.unwrap();
            let _cer = peer.next_event().await.unwrap();

            // Collect two requests, then answer them in REVERSE order.
            let first = peer.recv_raw().await.unwrap();
            let second = peer.recv_raw().await.unwrap();
            for req in [second, first] {
                let mut answer = DiameterMessage::new_answer(&req);
                // Echo the session id so the caller can tell them apart.
                if let Some(sid) = req.session_id() {
                    answer.add_avp(Avp::mandatory(
                        crate::common::avp_code::SESSION_ID,
                        AvpData::Utf8String(sid.to_string()),
                    ));
                }
                answer.add_avp(Avp::mandatory(268, AvpData::Unsigned32(2001)));
                peer.send_message(&answer).await.unwrap();
            }
        });

        let mut client = DiameterClient::new(config("mme.example.com", 5), addr);
        client.connect().await.unwrap();
        let (session, reader) = DiameterSession::start(client).unwrap();

        let mut req_a = DiameterMessage::new_request(AIR, S6A_APP);
        req_a.add_avp(Avp::mandatory(
            crate::common::avp_code::SESSION_ID,
            AvpData::Utf8String("session-A".into()),
        ));
        let mut req_b = DiameterMessage::new_request(AIR, S6A_APP);
        req_b.add_avp(Avp::mandatory(
            crate::common::avp_code::SESSION_ID,
            AvpData::Utf8String("session-B".into()),
        ));

        let sa = session.clone();
        let ta = tokio::spawn(async move { sa.send_request(&req_a).await });
        // Ensure A is written first, so "reverse order" is well defined.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let sb = session.clone();
        let tb = tokio::spawn(async move { sb.send_request(&req_b).await });

        let ans_a = ta.await.unwrap().expect("A answered");
        let ans_b = tb.await.unwrap().expect("B answered");

        assert_eq!(
            ans_a.session_id(),
            Some("session-A"),
            "caller A received another caller's answer"
        );
        assert_eq!(
            ans_b.session_id(),
            Some("session-B"),
            "caller B received another caller's answer"
        );
        reader.abort();
        hss.abort();
    }

    /// A stalled request must not block an unrelated one. This is the exact
    /// production symptom: one wedged subscriber lookup previously took the
    /// whole S6a plane with it.
    #[tokio::test]
    async fn a_stalled_request_does_not_block_others() {
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let cfg = config("hss.example.com", 30);
        let hss = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &cfg);
            peer.start().await.unwrap();
            let _cer = peer.next_event().await.unwrap();

            // Never answer the first request; answer every later one at once.
            let _stalled = peer.recv_raw().await.unwrap();
            loop {
                let msg = match peer.recv_raw().await {
                    Ok(m) => m,
                    Err(_) => break,
                };
                let mut answer = DiameterMessage::new_answer(&msg);
                answer.add_avp(Avp::mandatory(268, AvpData::Unsigned32(2001)));
                if peer.send_message(&answer).await.is_err() {
                    break;
                }
            }
        });

        let mut client = DiameterClient::new(config("mme.example.com", 5), addr);
        client.connect().await.unwrap();
        let (session, reader) = DiameterSession::start(client).unwrap();

        // Fire the request that will never be answered.
        let stalled_session = session.clone();
        let stalled = tokio::spawn(async move {
            let req = DiameterMessage::new_request(AIR, S6A_APP);
            stalled_session.send_request(&req).await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // A second request must complete promptly regardless.
        let started = tokio::time::Instant::now();
        let req = DiameterMessage::new_request(AIR, S6A_APP);
        let answer = session
            .send_request(&req)
            .await
            .expect("the healthy request must be answered");
        let elapsed = started.elapsed();

        assert_eq!(answer.result_code(), Some(2001));
        assert!(
            elapsed < Duration::from_secs(2),
            "a stalled request blocked an unrelated one: {elapsed:?}"
        );

        // And the stalled one still terminates on its own timeout.
        let stalled_result = stalled.await.unwrap();
        assert!(
            matches!(stalled_result, Err(DiameterError::RequestTimeout { .. })),
            "expected RequestTimeout, got {stalled_result:?}"
        );
        assert_eq!(
            session.pending_count().await,
            0,
            "a timed-out request leaked its pending entry"
        );
        reader.abort();
        hss.abort();
    }

    /// Losing the connection must fail in-flight requests immediately rather
    /// than stalling each for the full timeout.
    #[tokio::test]
    async fn disconnect_fails_in_flight_requests_promptly() {
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let cfg = config("hss.example.com", 30);
        let hss = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &cfg);
            peer.start().await.unwrap();
            let _cer = peer.next_event().await.unwrap();
            // Read one request, then drop the connection without answering.
            let _req = peer.recv_raw().await.unwrap();
        });

        // request_timeout is 30s here: if the disconnect were not detected the
        // test would take 30s instead of milliseconds.
        let mut client = DiameterClient::new(config("mme.example.com", 30), addr);
        client.connect().await.unwrap();
        let (session, reader) = DiameterSession::start(client).unwrap();

        let started = tokio::time::Instant::now();
        let req = DiameterMessage::new_request(AIR, S6A_APP);
        let result = session.send_request(&req).await;
        let elapsed = started.elapsed();

        assert!(result.is_err(), "expected an error after disconnect");
        assert!(
            elapsed < Duration::from_secs(5),
            "disconnect was not detected promptly: {elapsed:?}"
        );
        reader.abort();
        hss.abort();
    }

    /// A peer-initiated request (S6a CLR/IDR) must reach the application even
    /// while answers are being multiplexed.
    #[tokio::test]
    async fn peer_initiated_requests_reach_the_application() {
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        const CLR: u32 = 317;
        let cfg = config("hss.example.com", 30);
        let hss = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &cfg);
            peer.start().await.unwrap();
            let _cer = peer.next_event().await.unwrap();
            let mut clr = DiameterMessage::new_request(CLR, S6A_APP);
            clr.header.hop_by_hop_id = 0xABCD;
            clr.add_avp(Avp::mandatory(
                crate::common::avp_code::SESSION_ID,
                AvpData::Utf8String("clr-session".into()),
            ));
            peer.send_message(&clr).await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let mut client = DiameterClient::new(config("mme.example.com", 5), addr);
        client.connect().await.unwrap();
        let (session, reader) = DiameterSession::start(client).unwrap();

        let inbound = session
            .recv_inbound_request(Duration::from_secs(3))
            .await
            .expect("no transport error")
            .expect("a CLR should have arrived");
        assert_eq!(inbound.header.command_code, CLR);
        assert_eq!(inbound.session_id(), Some("clr-session"));
        reader.abort();
        hss.abort();
    }

    /// An HSS that completes CER/CEA and then, if `answer_watchdogs`, answers
    /// each DWR (through the peer state machine), or else reads and never
    /// answers anything: a half-open peer. Reports each DWR it sees.
    async fn spawn_watchdog_hss(
        listener: DiameterListener,
        answer_watchdogs: bool,
        dwr_seen: mpsc::UnboundedSender<()>,
    ) -> tokio::task::JoinHandle<()> {
        let cfg = config("hss.example.com", 30);
        tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &cfg);
            peer.start().await.unwrap();
            let _cer = peer.next_event().await.unwrap();
            loop {
                let Ok(msg) = peer.recv_raw().await else {
                    break;
                };
                if msg.header.command_code == crate::message::base_cmd::DEVICE_WATCHDOG
                    && msg.header.is_request()
                {
                    let _ = dwr_seen.send(());
                    if answer_watchdogs && peer.handle_message(msg).await.is_err() {
                        break;
                    }
                }
            }
            // Hold the connection open until the client closes it.
            drop(peer);
        })
    }

    async fn watchdog_session(
        answer_watchdogs: bool,
        tw: Duration,
    ) -> (
        DiameterSession,
        tokio::task::JoinHandle<()>,
        mpsc::UnboundedReceiver<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (dwr_tx, dwr_rx) = mpsc::unbounded_channel();
        let hss = spawn_watchdog_hss(listener, answer_watchdogs, dwr_tx).await;
        let mut client = DiameterClient::new(config("mme.example.com", 30), addr);
        client.connect().await.unwrap();
        let (session, reader) = DiameterSession::start_with_watchdog(client, tw).unwrap();
        (session, reader, dwr_rx, hss)
    }

    /// #729, RFC 3539 §3.4.1 / RFC 6733 §5.5: a peer that goes silent without
    /// closing (no FIN, no RST) is sent a DWR after Tw, and when that is not
    /// answered within another Tw the session ends, failing the in-flight
    /// request at once instead of after request_timeout (30 s here).
    #[tokio::test]
    async fn a_silent_peer_ends_the_session_within_two_tw() {
        let tw = Duration::from_millis(200);
        let (session, reader, mut dwr_rx, _hss) = watchdog_session(false, tw).await;
        let started = std::time::Instant::now();
        let in_flight = {
            let session = session.clone();
            tokio::spawn(async move {
                let air = DiameterMessage::new_request(AIR, S6A_APP);
                session.send_request(&air).await
            })
        };
        tokio::time::timeout(Duration::from_secs(2), dwr_rx.recv())
            .await
            .expect("a Device-Watchdog-Request is sent after Tw")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), reader)
            .await
            .expect("the session ends when the DWR is not answered")
            .unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < tw * 2 + Duration::from_millis(400),
            "detected in about 2 x Tw, took {elapsed:?}"
        );
        let result = tokio::time::timeout(Duration::from_secs(1), in_flight)
            .await
            .expect("the in-flight request fails promptly")
            .unwrap();
        assert!(
            matches!(result, Err(DiameterError::Protocol(_))),
            "{result:?}"
        );
    }

    /// #729: a peer that answers its watchdogs keeps the session up across many
    /// Tw, and a DWA is never handed to an application waiter.
    #[tokio::test]
    async fn a_peer_answering_watchdogs_stays_up() {
        let tw = Duration::from_millis(150);
        let (session, reader, mut dwr_rx, _hss) = watchdog_session(true, tw).await;
        tokio::time::sleep(tw * 8).await;
        assert!(!reader.is_finished(), "an answering peer is not dropped");
        let mut dwrs = 0;
        while dwr_rx.try_recv().is_ok() {
            dwrs += 1;
        }
        assert!(dwrs >= 3, "a DWR every Tw of silence, saw {dwrs}");
        assert_eq!(session.pending_count().await, 0);
        reader.abort();
    }

    /// RFC 3539 §3.4.1: Tw is never below 6 s in production, and is jittered
    /// by at most ±2 s.
    #[test]
    fn tw_is_floored_and_jittered_within_two_seconds() {
        let tw = Duration::from_secs(30);
        for _ in 0..100 {
            let j = jittered(tw);
            assert!(
                j >= Duration::from_secs(28) && j <= Duration::from_secs(32),
                "{j:?}"
            );
        }
        assert_eq!(
            jittered(Duration::from_millis(200)),
            Duration::from_millis(200)
        );
        // `start` takes Tw from effective_tw: floored at 6 s, otherwise as set.
        let low = DiameterConfig {
            timer_tw: 1,
            ..Default::default()
        };
        assert_eq!(effective_tw(&low), Duration::from_secs(6));
        let high = DiameterConfig {
            timer_tw: 45,
            ..Default::default()
        };
        assert_eq!(effective_tw(&high), Duration::from_secs(45));
        assert_eq!(
            SessionOptions::from_config(&low, WatchdogStart::Okay).tw,
            Duration::from_secs(6)
        );
    }

    /// Accept, complete CER/CEA, then hold the connection open and never read
    /// again: a peer whose host vanished, as the socket send buffer sees it.
    async fn spawn_never_reading_hss(listener: DiameterListener) -> tokio::task::JoinHandle<()> {
        let cfg = config("hss.example.com", 30);
        tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &cfg);
            peer.start().await.unwrap();
            let _cer = peer.next_event().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(peer);
        })
    }

    /// #729 review B1: under load, a peer that stops reading fills the socket
    /// buffer. Every write is bounded by Tw, so the session still ends within
    /// about 2 x Tw instead of blocking in a write until TCP gives up.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_peer_that_stops_reading_under_load_ends_the_session() {
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let _hss = spawn_never_reading_hss(listener).await;
        let mut client = DiameterClient::new(config("mme.example.com", 30), addr);
        client.connect().await.unwrap();
        let tw = Duration::from_millis(200);
        let (session, reader) = DiameterSession::start_with_watchdog(client, tw).unwrap();
        let started = std::time::Instant::now();
        let big = bytes::Bytes::from(vec![0x5a; 64 * 1024]);
        for _ in 0..400 {
            let session = session.clone();
            let big = big.clone();
            tokio::spawn(async move {
                let mut air = DiameterMessage::new_request(AIR, S6A_APP);
                air.add_avp(Avp::mandatory(1, AvpData::OctetString(big)));
                let _ = session.send_request(&air).await;
            });
        }
        tokio::time::timeout(Duration::from_secs(3), reader)
            .await
            .expect("the session ends although its writes would block")
            .unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < tw * 2 + Duration::from_millis(600),
            "about 2 x Tw, took {elapsed:?}"
        );
    }

    /// #816 review m-c: the Tw write bound alone ends the session. The socket's
    /// TCP_USER_TIMEOUT is left unset, so nothing else can: on loopback the peer's
    /// stack keeps acknowledging zero-window probes and an unbounded write would
    /// wait forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_tw_write_bound_alone_ends_a_session_whose_peer_stops_reading() {
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let _hss = spawn_never_reading_hss(listener).await;
        let mut client = DiameterClient::new(config("mme.example.com", 30), addr);
        client.connect().await.unwrap();
        let tw = Duration::from_millis(200);
        let (session, reader) = DiameterSession::start_session(
            client,
            SessionOptions {
                tw,
                start: WatchdogStart::Okay,
            },
            false,
        )
        .unwrap();
        // Enough to fill the loopback socket buffers (a few MiB) and no more.
        let big = bytes::Bytes::from(vec![0x5a; 512 * 1024]);
        for _ in 0..16 {
            let session = session.clone();
            let big = big.clone();
            tokio::spawn(async move {
                let mut air = DiameterMessage::new_request(AIR, S6A_APP);
                air.add_avp(Avp::mandatory(1, AvpData::OctetString(big)));
                let _ = session.send_request(&air).await;
            });
        }
        tokio::time::timeout(Duration::from_secs(3), reader)
            .await
            .expect("the write bound ends the session with no TCP_USER_TIMEOUT")
            .unwrap();
    }

    /// #729 review m4: a DWA whose hop-by-hop id equals an application
    /// request's never reaches that request's waiter, which gets its own answer.
    #[tokio::test]
    async fn a_dwa_is_never_an_application_answer() {
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = config("hss.example.com", 30);
        let _hss = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &cfg);
            peer.start().await.unwrap();
            let _cer = peer.next_event().await.unwrap();
            while let Ok(msg) = peer.recv_raw().await {
                if msg.header.command_code == AIR {
                    // A DWA under the request's own hop-by-hop id, first.
                    let mut dwa =
                        DiameterMessage::new_request(crate::message::base_cmd::DEVICE_WATCHDOG, 0);
                    dwa.header.flags = 0;
                    dwa.header.hop_by_hop_id = msg.header.hop_by_hop_id;
                    dwa.header.end_to_end_id = msg.header.end_to_end_id;
                    dwa.add_avp(Avp::mandatory(268, AvpData::Unsigned32(2001)));
                    peer.send_message(&dwa).await.unwrap();
                    let mut answer = DiameterMessage::new_answer(&msg);
                    answer.add_avp(Avp::mandatory(268, AvpData::Unsigned32(2001)));
                    peer.send_message(&answer).await.unwrap();
                }
            }
        });
        let mut client = DiameterClient::new(config("mme.example.com", 5), addr);
        client.connect().await.unwrap();
        let (session, _reader) =
            DiameterSession::start_with_watchdog(client, Duration::from_secs(30)).unwrap();
        let answer = session
            .send_request(&DiameterMessage::new_request(AIR, S6A_APP))
            .await
            .expect("the application answer");
        assert_eq!(answer.header.command_code, AIR, "not the DWA");
    }

    /// #729 review M1, RFC 3539 §3.4.1 REOPEN: a re-established connection
    /// carries no application traffic until three watchdog exchanges succeed;
    /// then the queued request goes out and is answered.
    #[tokio::test]
    async fn a_reopened_connection_carries_traffic_after_three_watchdogs() {
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = config("hss.example.com", 30);
        let (seen_tx, mut seen_rx) = mpsc::unbounded_channel::<u32>();
        let _hss = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &cfg);
            peer.start().await.unwrap();
            let _cer = peer.next_event().await.unwrap();
            while let Ok(msg) = peer.recv_raw().await {
                let _ = seen_tx.send(msg.header.command_code);
                if msg.header.command_code == AIR {
                    let mut answer = DiameterMessage::new_answer(&msg);
                    answer.add_avp(Avp::mandatory(268, AvpData::Unsigned32(2001)));
                    peer.send_message(&answer).await.unwrap();
                } else if peer.handle_message(msg).await.is_err() {
                    break;
                }
            }
        });
        let mut client = DiameterClient::new(config("mme.example.com", 5), addr);
        client.connect().await.unwrap();
        let (session, _reader) = DiameterSession::start_with(
            client,
            SessionOptions {
                tw: Duration::from_millis(200),
                start: WatchdogStart::Reopen,
            },
        )
        .unwrap();
        let answer = session
            .send_request(&DiameterMessage::new_request(AIR, S6A_APP))
            .await
            .expect("answered once the connection is back in service");
        assert_eq!(answer.header.command_code, AIR);
        let mut order = Vec::new();
        while let Ok(c) = seen_rx.try_recv() {
            order.push(c);
        }
        let first_air = order.iter().position(|c| *c == AIR).unwrap();
        assert!(
            order[..first_air]
                .iter()
                .filter(|c| **c == crate::message::base_cmd::DEVICE_WATCHDOG)
                .count()
                >= 3,
            "three watchdogs before any application traffic: {order:?}"
        );
    }

    /// #816 review m-d, RFC 3539 §3.4.1 REOPEN: NumDWA++. A DWA after the grace
    /// expiry set NumDWA to -1 brings it to 0, so three MORE answers are needed;
    /// before the fix the first one counted as 1 and the connection returned to
    /// service on two.
    #[tokio::test]
    async fn a_reopen_dwa_after_the_grace_expiry_counts_from_minus_one() {
        let mut w = Watchdog::new(Duration::from_millis(100), WatchdogStart::Reopen);
        w.sent();
        assert_eq!(w.expired(), TimerAction::Wait, "the grace expiry");
        assert_eq!(w.num_dwa, -1);
        w.received(true);
        assert_eq!(w.num_dwa, 0);
        for _ in 0..2 {
            w.sent();
            w.received(true);
        }
        assert!(
            !w.carries_traffic(),
            "two answers since the grace are not three"
        );
        w.sent();
        w.received(true);
        assert!(w.carries_traffic(), "the third returns it to service");
    }

    /// #816 review m-f / #899 review, RFC 3539 §3.4.1 REOPEN: an application
    /// request arriving before the connection has proved itself is not handed to
    /// the application. It is answered DIAMETER_TOO_BUSY (3004, E bit, its
    /// Session-Id echoed, RFC 6733 §7.1.3), so the sender keeps it, and its retry
    /// once the connection is in service is delivered.
    #[tokio::test]
    async fn an_application_request_during_reopen_is_answered_too_busy_and_its_retry_delivered() {
        const IDR: u32 = 319;
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = config("hss.example.com", 30);
        let (go_tx, mut go_rx) = mpsc::unbounded_channel::<()>();
        let (ans_tx, mut ans_rx) = mpsc::unbounded_channel::<DiameterMessage>();
        let idr = || {
            let mut idr = DiameterMessage::new_request(IDR, S6A_APP);
            idr.header.hop_by_hop_id = 0x816_0001;
            idr.add_avp(Avp::mandatory(263, AvpData::Utf8String("hss;899;1".into())));
            idr
        };
        let _hss = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &cfg);
            peer.start().await.unwrap();
            let _cer = peer.next_event().await.unwrap();
            peer.send_message(&idr()).await.unwrap();
            loop {
                tokio::select! {
                    msg = peer.recv_raw() => {
                        let Ok(msg) = msg else { break };
                        if msg.header.command_code == AIR {
                            let mut answer = DiameterMessage::new_answer(&msg);
                            answer.add_avp(Avp::mandatory(268, AvpData::Unsigned32(2001)));
                            peer.send_message(&answer).await.unwrap();
                        } else if msg.header.command_code == IDR && msg.header.is_answer() {
                            let _ = ans_tx.send(msg);
                        } else if peer.handle_message(msg).await.is_err() {
                            break;
                        }
                    }
                    // The HSS retries the request it was told to retry.
                    Some(()) = go_rx.recv() => {
                        peer.send_message(&idr()).await.unwrap();
                    }
                }
            }
        });
        let discards = reopen_discards();
        let mut client = DiameterClient::new(config("mme.example.com", 5), addr);
        client.connect().await.unwrap();
        let (session, _reader) = DiameterSession::start_with(
            client,
            SessionOptions {
                tw: Duration::from_millis(200),
                start: WatchdogStart::Reopen,
            },
        )
        .unwrap();
        let busy = tokio::time::timeout(Duration::from_secs(2), ans_rx.recv())
            .await
            .expect("the request in REOPEN is answered")
            .unwrap();
        assert_eq!(busy.result_code(), Some(DIAMETER_TOO_BUSY));
        assert!(busy.header.is_error(), "a protocol error: the E bit");
        assert_eq!(busy.session_id(), Some("hss;899;1"));
        assert_eq!(busy.header.hop_by_hop_id, 0x816_0001);
        assert!(reopen_discards() > discards, "counted");
        session
            .send_request(&DiameterMessage::new_request(AIR, S6A_APP))
            .await
            .expect("in service after three watchdogs");
        go_tx.send(()).unwrap();
        let delivered = session
            .recv_inbound_request(Duration::from_secs(2))
            .await
            .unwrap()
            .expect("the retry, in service, is delivered");
        assert_eq!(delivered.session_id(), Some("hss;899;1"));
    }

    /// RFC 3539 §3.4.1 REOPEN: a re-established connection whose peer does not
    /// answer its watchdogs is closed (after the one grace expiry).
    #[tokio::test]
    async fn a_reopened_connection_that_never_answers_is_closed() {
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (dwr_tx, _dwr_rx) = mpsc::unbounded_channel();
        let _hss = spawn_watchdog_hss(listener, false, dwr_tx).await;
        let mut client = DiameterClient::new(config("mme.example.com", 30), addr);
        client.connect().await.unwrap();
        let tw = Duration::from_millis(150);
        let (_session, reader) = DiameterSession::start_with(
            client,
            SessionOptions {
                tw,
                start: WatchdogStart::Reopen,
            },
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), reader)
            .await
            .expect("closed")
            .unwrap();
    }

    /// #729 review B1: TCP_USER_TIMEOUT is settable on the TCP transport.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_tcp_user_timeout_is_set() {
        use crate::transport::{DiameterTransport, DiameterTransportIo};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _accept = tokio::spawn(async move { listener.accept().await });
        let transport = DiameterTransport::connect(addr).await.unwrap();
        transport
            .set_user_timeout(Duration::from_millis(400))
            .unwrap();
        assert_eq!(transport.user_timeout_ms().unwrap(), 400);
    }
}
