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

        let handle = tokio::spawn(run_session(peer, rx, inbound_tx, Arc::clone(&pending)));

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
) {
    loop {
        tokio::select! {
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
                // machine, which answers DWR/DPR itself.
                match peer.handle_message(msg).await {
                    Ok(PeerEvent::Message(request)) => {
                        if let Err(e) = inbound.try_send(request) {
                            log::warn!("inbound Diameter request dropped: {e}");
                        }
                    }
                    Ok(PeerEvent::Disconnected) => {
                        log::info!("Diameter peer disconnected");
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!("Diameter session state error: {e}");
                        break;
                    }
                }
            }

            // Writes are serialised through this one task, so no two messages
            // can interleave on the wire.
            Some(msg) = outbound.recv() => {
                if let Err(e) = peer.send_message(&msg).await {
                    log::warn!("Diameter session write failed: {e}");
                    break;
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
}
