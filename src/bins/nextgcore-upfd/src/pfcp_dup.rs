//! PFCP duplicate-request detection (#1851, TS 29.244 §6.4).
//!
//! A CP function that sees no response within T1 retransmits its request with the
//! same Sequence Number and the same content, up to N1 times (§6.4: "A retransmitted
//! PFCP message shall have the same message content, including the same PFCP header,
//! UDP ports, source and destination IP addresses"). "Not counting retransmissions, a
//! Request message shall be answered with a single Response message", and a request
//! and its response are matched "based on the Sequence Number and the IP address and
//! UDP port". So a retransmission is not a new request: it is answered with the
//! response the original got, and never executed again.
//!
//! Before this, upfd executed every retransmission afresh. A retransmitted Session
//! Establishment created a second session (or, with the F-TEID collision check,
//! was refused because the first one already held its TEIDs) and a retransmitted
//! Modification applied its rule changes twice -- whenever the first response was
//! lost on the way back, which is exactly when the CP function retransmits.
//!
//! [`ResponseCache`] keeps, per peer IP address and UDP port and Sequence Number, a
//! digest of the request and the response sent to it, for [`DUPLICATE_WINDOW`]. It
//! is used for every request type the server answers.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::pfcp_path::{PFCP_N1_MAX_RETRANSMIT, PFCP_T1_DURATION};

/// How long a response is kept for a retransmission of its request: T1 for the
/// original transmission plus T1 for each of the N1 retransmissions (§6.4). T1 and
/// N1 are the peer's and "implementation specific"; this UPF assumes its own
/// (3 s, 3), which also covers sgwcd's (3 s, 2) and smfd's defaults.
pub const DUPLICATE_WINDOW: Duration =
    Duration::from_secs(PFCP_T1_DURATION.as_secs() * (PFCP_N1_MAX_RETRANSMIT as u64 + 1));

/// At most this many responses are kept. At the cap the oldest goes first, so
/// the bound only bites a CP function sending more than this many requests per
/// [`DUPLICATE_WINDOW`] (about 2700 a second), and then only for its oldest
/// requests. Responses are small (a few hundred bytes), so the bound is a few MB.
pub const DUPLICATE_CACHE_MAX: usize = 32 * 1024;

/// Peer endpoint and Sequence Number: what §6.4 matches a request and response on.
type Key = (SocketAddr, u32);

/// The request a response answers, kept as a digest rather than its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    digest: u64,
    len: usize,
}

#[derive(Debug)]
struct Cached {
    request: Fingerprint,
    response: Vec<u8>,
    at: Instant,
}

/// The request being handled now, and the response it has been given so far.
#[derive(Debug)]
struct InFlight {
    key: Key,
    request: Fingerprint,
    response: Option<Vec<u8>>,
}

/// Recent responses to requests, for answering retransmissions (TS 29.244 §6.4).
///
/// Use: [`Self::replay`] before handling a request (a hit is answered from the
/// cache and not handled); [`Self::begin`] when it is handled; [`Self::record`] for
/// every response sent; [`Self::finish`] when the handler returns.
#[derive(Debug)]
pub struct ResponseCache {
    entries: HashMap<Key, Cached>,
    /// Insertion order, for expiry and the cap. A key replaced by a newer request
    /// stays here with its old time and is skipped when it surfaces.
    order: VecDeque<(Key, Instant)>,
    in_flight: Option<InFlight>,
    hasher: RandomState,
    window: Duration,
    cap: usize,
}

impl Default for ResponseCache {
    fn default() -> Self {
        Self::new(DUPLICATE_WINDOW, DUPLICATE_CACHE_MAX)
    }
}

impl ResponseCache {
    /// A cache keeping responses for `window`, at most `cap` of them.
    pub fn new(window: Duration, cap: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            in_flight: None,
            hasher: RandomState::new(),
            window,
            cap: cap.max(1),
        }
    }

    fn fingerprint(&self, request: &[u8]) -> Fingerprint {
        Fingerprint {
            digest: self.hasher.hash_one(request),
            len: request.len(),
        }
    }

    /// Drop what has outlived the window.
    fn expire(&mut self, now: Instant) {
        while let Some(&(key, at)) = self.order.front() {
            if now.saturating_duration_since(at) < self.window {
                break;
            }
            self.order.pop_front();
            if self.entries.get(&key).is_some_and(|c| c.at == at) {
                self.entries.remove(&key);
            }
        }
    }

    /// The response to send again when `request` from `peer` with Sequence Number
    /// `seq` is a retransmission of one already answered within the window.
    ///
    /// Only the SAME request is a retransmission (§6.4: same content). A different
    /// request reusing a recent Sequence Number -- a peer that restarted and numbers
    /// from 1 again -- is a new request and gets `None`.
    pub fn replay(
        &mut self,
        peer: SocketAddr,
        seq: u32,
        request: &[u8],
        now: Instant,
    ) -> Option<Vec<u8>> {
        self.expire(now);
        let fp = self.fingerprint(request);
        self.entries
            .get(&(peer, seq))
            .filter(|c| c.request == fp)
            .map(|c| c.response.clone())
    }

    /// The server starts handling `request` from `peer` with Sequence Number `seq`.
    pub fn begin(&mut self, peer: SocketAddr, seq: u32, request: &[u8]) {
        self.in_flight = Some(InFlight {
            key: (peer, seq),
            request: self.fingerprint(request),
            response: None,
        });
    }

    /// `response` is being sent to `to`. It is kept when it answers the request in
    /// flight (same peer endpoint and Sequence Number), otherwise ignored.
    pub fn record(&mut self, to: SocketAddr, response: &[u8]) {
        let Some(seq) = response_sequence_number(response) else {
            return;
        };
        if let Some(f) = self.in_flight.as_mut().filter(|f| f.key == (to, seq)) {
            f.response = Some(response.to_vec());
        }
    }

    /// The request in flight has been handled. Its response is kept when `keep` and
    /// one was sent; a request that got no response (held, or failed before
    /// answering) is handled afresh when retransmitted.
    pub fn finish(&mut self, keep: bool, now: Instant) {
        let Some(InFlight {
            key,
            request,
            response: Some(response),
        }) = self.in_flight.take()
        else {
            return;
        };
        if !keep {
            return;
        }
        self.expire(now);
        self.entries.insert(
            key,
            Cached {
                request,
                response,
                at: now,
            },
        );
        self.order.push_back((key, now));
        while self.entries.len() > self.cap {
            let Some((old, at)) = self.order.pop_front() else {
                break;
            };
            if self.entries.get(&old).is_some_and(|c| c.at == at) {
                self.entries.remove(&old);
            }
        }
    }

    /// Forget every kept response: the peer's requests from here on belong to a new
    /// association (a new Setup, or a restart detected), so a request matching one
    /// of the old ones is the new incarnation's and is handled, not answered with
    /// what its predecessor was told. The request in flight is unaffected.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    /// How many responses are kept (test/diagnostic accessor).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no response is kept.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The Sequence Number of an encoded PFCP message (TS 29.244 §7.2.2.1): three
/// octets after the SEID when the S flag is set, right after the length otherwise.
fn response_sequence_number(msg: &[u8]) -> Option<u32> {
    let at = if msg.first()? & 0x01 != 0 { 12 } else { 4 };
    let b = msg.get(at..at + 3)?;
    Some(u32::from_be_bytes([0, b[0], b[1], b[2]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 9], port))
    }

    /// A node-level response (no SEID) with Sequence Number `seq`.
    fn node_response(seq: u32, tail: u8) -> Vec<u8> {
        let mut m = vec![0x20, 2, 0, 5];
        m.extend_from_slice(&seq.to_be_bytes()[1..4]);
        m.push(0);
        m.push(tail);
        m
    }

    /// A session-level response (S flag, SEID) with Sequence Number `seq`.
    fn session_response(seq: u32) -> Vec<u8> {
        let mut m = vec![0x21, 51, 0, 12];
        m.extend_from_slice(&0x4242u64.to_be_bytes());
        m.extend_from_slice(&seq.to_be_bytes()[1..4]);
        m.push(0);
        m
    }

    /// Handle `request` as the server does: begin, answer, finish.
    fn answer(c: &mut ResponseCache, p: SocketAddr, seq: u32, request: &[u8], resp: &[u8]) {
        c.begin(p, seq, request);
        c.record(p, resp);
        c.finish(true, Instant::now());
    }

    #[test]
    fn the_window_is_t1_for_the_original_and_each_of_n1_retransmissions() {
        assert_eq!(DUPLICATE_WINDOW, Duration::from_secs(12));
    }

    #[test]
    fn a_retransmission_gets_the_original_response() {
        let mut c = ResponseCache::default();
        let resp = session_response(77);
        answer(&mut c, peer(8805), 77, b"request", &resp);
        assert_eq!(
            c.replay(peer(8805), 77, b"request", Instant::now()),
            Some(resp)
        );
    }

    #[test]
    fn the_sequence_number_is_read_from_both_header_shapes() {
        assert_eq!(
            response_sequence_number(&node_response(0x01_02_03, 0)),
            Some(0x01_02_03)
        );
        assert_eq!(
            response_sequence_number(&session_response(0x0a_0b_0c)),
            Some(0x0a_0b_0c)
        );
        assert_eq!(response_sequence_number(&[0x21, 51, 0]), None);
    }

    #[test]
    fn a_new_request_reusing_a_sequence_number_is_not_a_retransmission() {
        let mut c = ResponseCache::default();
        answer(
            &mut c,
            peer(8805),
            1,
            b"setup, recovery ts 1",
            &node_response(1, 0),
        );
        assert_eq!(
            c.replay(peer(8805), 1, b"setup, recovery ts 2", Instant::now()),
            None,
            "a restarted peer numbering from 1 again is handled, not replayed"
        );
    }

    #[test]
    fn requests_are_matched_by_peer_address_and_port() {
        let mut c = ResponseCache::default();
        answer(&mut c, peer(8805), 5, b"request", &node_response(5, 0));
        assert_eq!(c.replay(peer(8806), 5, b"request", Instant::now()), None);
        assert_eq!(
            c.replay(
                SocketAddr::from(([127, 0, 0, 10], 8805)),
                5,
                b"request",
                Instant::now()
            ),
            None
        );
    }

    #[test]
    fn a_response_is_kept_only_for_the_window() {
        let mut c = ResponseCache::new(Duration::from_secs(12), 16);
        let t0 = Instant::now();
        c.begin(peer(8805), 9, b"request");
        c.record(peer(8805), &node_response(9, 0));
        c.finish(true, t0);
        assert!(c
            .replay(peer(8805), 9, b"request", t0 + Duration::from_secs(11))
            .is_some());
        assert!(c
            .replay(peer(8805), 9, b"request", t0 + Duration::from_secs(12))
            .is_none());
        assert!(c.is_empty());
    }

    #[test]
    fn at_the_cap_the_oldest_response_goes_first() {
        let mut c = ResponseCache::new(Duration::from_secs(12), 2);
        for seq in 1..=3 {
            answer(&mut c, peer(8805), seq, b"request", &node_response(seq, 0));
        }
        assert_eq!(c.len(), 2);
        let now = Instant::now();
        assert!(c.replay(peer(8805), 1, b"request", now).is_none());
        assert!(c.replay(peer(8805), 2, b"request", now).is_some());
        assert!(c.replay(peer(8805), 3, b"request", now).is_some());
    }

    #[test]
    fn a_request_that_got_no_response_or_is_not_kept_is_handled_again() {
        let mut c = ResponseCache::default();
        c.begin(peer(8805), 3, b"held");
        c.finish(true, Instant::now());
        assert!(c.replay(peer(8805), 3, b"held", Instant::now()).is_none());

        c.begin(peer(8805), 4, b"stranger");
        c.record(peer(8805), &node_response(4, 0));
        c.finish(false, Instant::now());
        assert!(c
            .replay(peer(8805), 4, b"stranger", Instant::now())
            .is_none());
    }

    #[test]
    fn a_response_to_another_request_is_not_recorded_for_the_one_in_flight() {
        let mut c = ResponseCache::default();
        c.begin(peer(8805), 3, b"request");
        c.record(peer(8805), &node_response(99, 0)); // another seq
        c.record(peer(8806), &node_response(3, 0)); // another port
        c.finish(true, Instant::now());
        assert!(c.is_empty());
    }

    #[test]
    fn clearing_forgets_the_kept_responses_but_not_the_request_in_flight() {
        let mut c = ResponseCache::default();
        answer(&mut c, peer(8805), 1, b"old", &node_response(1, 0));
        c.begin(peer(8805), 2, b"setup");
        c.record(peer(8805), &node_response(2, 0));
        c.clear();
        c.finish(true, Instant::now());
        let now = Instant::now();
        assert!(c.replay(peer(8805), 1, b"old", now).is_none());
        assert!(c.replay(peer(8805), 2, b"setup", now).is_some());
    }

    #[test]
    fn a_replaced_entry_is_not_expired_by_its_predecessor_s_time() {
        let mut c = ResponseCache::new(Duration::from_secs(12), 16);
        let t0 = Instant::now();
        c.begin(peer(8805), 1, b"old");
        c.record(peer(8805), &node_response(1, 0));
        c.finish(true, t0);
        c.begin(peer(8805), 1, b"new");
        c.record(peer(8805), &node_response(1, 1));
        c.finish(true, t0 + Duration::from_secs(10));
        let later = t0 + Duration::from_secs(13);
        assert_eq!(
            c.replay(peer(8805), 1, b"new", later),
            Some(node_response(1, 1))
        );
    }
}
