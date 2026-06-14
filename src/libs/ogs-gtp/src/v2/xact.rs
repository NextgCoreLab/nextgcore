//! GTPv2-C Transaction Layer (TS 29.274 Section 7.6)
//!
//! Provides sequence-number allocation, request/response transaction binding,
//! T3-RESPONSE/N3-REQUESTS retransmission handling for locally originated
//! requests, and a triggered-response cache so retransmitted peer requests are
//! answered with the original response instead of being re-processed.
//!
//! The manager is timer-agnostic: the owner drives it by calling
//! [`Gtp2XactMgr::poll`] periodically and transmitting whatever it returns.

use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::header::Gtp2MessageType;

/// Maximum GTPv2-C sequence number (24 bits)
pub const GTP2_MAX_SEQUENCE: u32 = 0x00FF_FFFF;

/// Retransmission configuration (TS 29.274 Section 7.6: T3-RESPONSE / N3-REQUESTS)
#[derive(Debug, Clone, Copy)]
pub struct Gtp2XactConfig {
    /// T3-RESPONSE timer: how long to wait for the triggered message
    pub t3_response: Duration,
    /// N3-REQUESTS: maximum number of retransmissions after the initial send
    pub n3_requests: u32,
    /// How long a sent response is cached to absorb duplicate requests
    pub response_hold: Duration,
}

impl Default for Gtp2XactConfig {
    fn default() -> Self {
        Self {
            t3_response: Duration::from_secs(3),
            n3_requests: 3,
            // Open5GS holds responses for (N3+1) * T3 to cover the peer's
            // full retransmission schedule
            response_hold: Duration::from_secs(12),
        }
    }
}

/// A locally originated request awaiting its triggered message
#[derive(Debug, Clone)]
pub struct Gtp2LocalXact {
    /// Sequence number allocated for this request
    pub sequence_number: u32,
    /// Message type of the request that was sent
    pub message_type: u8,
    /// Peer the request was sent to
    pub peer: SocketAddr,
    /// Encoded request bytes (kept for retransmission)
    pub encoded: Bytes,
    /// Opaque caller binding (e.g. session/bearer pool id)
    pub data: u64,
    deadline: Instant,
    retries_left: u32,
}

/// A cached response keyed by (peer, sequence number) for duplicate absorption
#[derive(Debug, Clone)]
struct CachedResponse {
    encoded: Bytes,
    expires: Instant,
}

/// Result of a poll pass
#[derive(Debug, Default)]
pub struct Gtp2XactPoll {
    /// Requests to retransmit now: (peer, encoded bytes)
    pub retransmits: Vec<(SocketAddr, Bytes)>,
    /// Requests whose N3 retransmissions are exhausted; the peer shall be
    /// considered unreachable for these (TS 29.274 Section 7.6)
    pub exhausted: Vec<Gtp2LocalXact>,
}

/// Return the triggered (response) message type for a request type, if the
/// message pair is known (TS 29.274 Table 6.1-1)
pub fn triggered_message_type(request_type: u8) -> Option<u8> {
    use Gtp2MessageType as T;
    let t = match request_type {
        x if x == T::EchoRequest as u8 => T::EchoResponse as u8,
        x if x == T::CreateSessionRequest as u8 => T::CreateSessionResponse as u8,
        x if x == T::ModifyBearerRequest as u8 => T::ModifyBearerResponse as u8,
        x if x == T::DeleteSessionRequest as u8 => T::DeleteSessionResponse as u8,
        x if x == T::ChangeNotificationRequest as u8 => T::ChangeNotificationResponse as u8,
        x if x == T::CreateBearerRequest as u8 => T::CreateBearerResponse as u8,
        x if x == T::UpdateBearerRequest as u8 => T::UpdateBearerResponse as u8,
        x if x == T::DeleteBearerRequest as u8 => T::DeleteBearerResponse as u8,
        x if x == T::CreateIndirectDataForwardingTunnelRequest as u8 => {
            T::CreateIndirectDataForwardingTunnelResponse as u8
        }
        x if x == T::DeleteIndirectDataForwardingTunnelRequest as u8 => {
            T::DeleteIndirectDataForwardingTunnelResponse as u8
        }
        x if x == T::ReleaseAccessBearersRequest as u8 => T::ReleaseAccessBearersResponse as u8,
        x if x == T::DownlinkDataNotification as u8 => T::DownlinkDataNotificationAcknowledge as u8,
        x if x == T::ModifyAccessBearersRequest as u8 => T::ModifyAccessBearersResponse as u8,
        x if x == T::CreateForwardingTunnelRequest as u8 => T::CreateForwardingTunnelResponse as u8,
        x if x == T::DeletePdnConnectionSetRequest as u8 => T::DeletePdnConnectionSetResponse as u8,
        x if x == T::UpdatePdnConnectionSetRequest as u8 => T::UpdatePdnConnectionSetResponse as u8,
        _ => return None,
    };
    Some(t)
}

/// GTPv2-C transaction manager
#[derive(Debug)]
pub struct Gtp2XactMgr {
    config: Gtp2XactConfig,
    next_sequence: u32,
    /// Outstanding locally originated requests, keyed by sequence number
    local: HashMap<u32, Gtp2LocalXact>,
    /// Cached responses for duplicate peer requests
    responses: HashMap<(SocketAddr, u32), CachedResponse>,
}

impl Default for Gtp2XactMgr {
    fn default() -> Self {
        Self::new(Gtp2XactConfig::default())
    }
}

impl Gtp2XactMgr {
    /// Create a manager with the given retransmission configuration
    pub fn new(config: Gtp2XactConfig) -> Self {
        Self {
            config,
            next_sequence: 1,
            local: HashMap::new(),
            responses: HashMap::new(),
        }
    }

    /// Allocate a monotonically increasing 24-bit sequence number
    pub fn alloc_sequence(&mut self) -> u32 {
        let seq = self.next_sequence;
        self.next_sequence = (self.next_sequence + 1) & GTP2_MAX_SEQUENCE;
        if self.next_sequence == 0 {
            self.next_sequence = 1;
        }
        seq
    }

    /// Register a locally originated request for retransmission tracking.
    /// `encoded` must be the exact bytes that were transmitted.
    pub fn register_request(
        &mut self,
        sequence_number: u32,
        message_type: u8,
        peer: SocketAddr,
        encoded: Bytes,
        data: u64,
    ) {
        let xact = Gtp2LocalXact {
            sequence_number,
            message_type,
            peer,
            encoded,
            data,
            deadline: Instant::now() + self.config.t3_response,
            retries_left: self.config.n3_requests,
        };
        self.local.insert(sequence_number, xact);
    }

    /// Match an incoming triggered message to an outstanding request.
    /// Returns the completed transaction if the sequence number matches an
    /// outstanding request and `response_type` is the correct triggered type.
    pub fn match_response(
        &mut self,
        sequence_number: u32,
        response_type: u8,
    ) -> Option<Gtp2LocalXact> {
        let expected = self
            .local
            .get(&sequence_number)
            .and_then(|xact| triggered_message_type(xact.message_type));
        match expected {
            Some(t) if t == response_type => self.local.remove(&sequence_number),
            _ => None,
        }
    }

    /// Number of outstanding locally originated requests
    pub fn outstanding(&self) -> usize {
        self.local.len()
    }

    /// Drive T3/N3: returns requests due for retransmission and exhausted
    /// transactions that must be treated as peer-unreachable.
    pub fn poll(&mut self, now: Instant) -> Gtp2XactPoll {
        let mut result = Gtp2XactPoll::default();
        let mut exhausted_seqs = Vec::new();

        for xact in self.local.values_mut() {
            if now < xact.deadline {
                continue;
            }
            if xact.retries_left == 0 {
                exhausted_seqs.push(xact.sequence_number);
            } else {
                xact.retries_left -= 1;
                xact.deadline = now + self.config.t3_response;
                result.retransmits.push((xact.peer, xact.encoded.clone()));
            }
        }

        for seq in exhausted_seqs {
            if let Some(xact) = self.local.remove(&seq) {
                result.exhausted.push(xact);
            }
        }

        // Expire cached responses
        self.responses.retain(|_, cached| cached.expires > now);

        result
    }

    /// Cache the response sent for a peer request so duplicates can be
    /// answered without re-processing.
    pub fn cache_response(&mut self, peer: SocketAddr, sequence_number: u32, encoded: Bytes) {
        self.responses.insert(
            (peer, sequence_number),
            CachedResponse {
                encoded,
                expires: Instant::now() + self.config.response_hold,
            },
        );
    }

    /// Look up a previously sent response for a (possibly retransmitted)
    /// peer request.
    pub fn lookup_cached_response(&self, peer: SocketAddr, sequence_number: u32) -> Option<Bytes> {
        self.responses
            .get(&(peer, sequence_number))
            .filter(|cached| cached.expires > Instant::now())
            .map(|cached| cached.encoded.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> SocketAddr {
        "127.0.0.1:2123".parse().unwrap()
    }

    #[test]
    fn test_sequence_allocation_monotonic_and_wrapping() {
        let mut mgr = Gtp2XactMgr::default();
        let a = mgr.alloc_sequence();
        let b = mgr.alloc_sequence();
        assert_eq!(b, a + 1);

        // Force wrap
        mgr.next_sequence = GTP2_MAX_SEQUENCE;
        assert_eq!(mgr.alloc_sequence(), GTP2_MAX_SEQUENCE);
        // 0 is skipped after wrap
        assert_eq!(mgr.alloc_sequence(), 1);
    }

    #[test]
    fn test_request_response_binding() {
        let mut mgr = Gtp2XactMgr::default();
        let seq = mgr.alloc_sequence();
        mgr.register_request(
            seq,
            Gtp2MessageType::CreateSessionRequest as u8,
            peer(),
            Bytes::from_static(b"req"),
            42,
        );
        assert_eq!(mgr.outstanding(), 1);

        // Wrong triggered type is not matched
        assert!(mgr
            .match_response(seq, Gtp2MessageType::ModifyBearerResponse as u8)
            .is_none());
        // Unknown sequence is not matched
        assert!(mgr
            .match_response(seq + 1, Gtp2MessageType::CreateSessionResponse as u8)
            .is_none());

        let xact = mgr
            .match_response(seq, Gtp2MessageType::CreateSessionResponse as u8)
            .unwrap();
        assert_eq!(xact.data, 42);
        assert_eq!(mgr.outstanding(), 0);

        // Late duplicate response no longer matches
        assert!(mgr
            .match_response(seq, Gtp2MessageType::CreateSessionResponse as u8)
            .is_none());
    }

    #[test]
    fn test_t3_n3_retransmission_and_exhaustion() {
        let config = Gtp2XactConfig {
            t3_response: Duration::from_millis(10),
            n3_requests: 2,
            response_hold: Duration::from_secs(1),
        };
        let mut mgr = Gtp2XactMgr::new(config);
        let seq = mgr.alloc_sequence();
        mgr.register_request(
            seq,
            Gtp2MessageType::DownlinkDataNotification as u8,
            peer(),
            Bytes::from_static(b"ddn"),
            7,
        );

        let now = Instant::now();

        // Before the deadline nothing happens
        let result = mgr.poll(now);
        assert!(result.retransmits.is_empty());
        assert!(result.exhausted.is_empty());

        // First expiry: retransmit 1 of 2
        let result = mgr.poll(now + Duration::from_millis(11));
        assert_eq!(result.retransmits.len(), 1);
        assert!(result.exhausted.is_empty());

        // Second expiry: retransmit 2 of 2
        let result = mgr.poll(now + Duration::from_millis(22));
        assert_eq!(result.retransmits.len(), 1);

        // Third expiry: exhausted
        let result = mgr.poll(now + Duration::from_millis(33));
        assert!(result.retransmits.is_empty());
        assert_eq!(result.exhausted.len(), 1);
        assert_eq!(result.exhausted[0].sequence_number, seq);
        assert_eq!(result.exhausted[0].data, 7);
        assert_eq!(mgr.outstanding(), 0);
    }

    #[test]
    fn test_response_cache_for_duplicate_requests() {
        let config = Gtp2XactConfig {
            t3_response: Duration::from_secs(1),
            n3_requests: 1,
            response_hold: Duration::from_millis(20),
        };
        let mut mgr = Gtp2XactMgr::new(config);

        mgr.cache_response(peer(), 0x1234, Bytes::from_static(b"rsp"));
        assert_eq!(
            mgr.lookup_cached_response(peer(), 0x1234),
            Some(Bytes::from_static(b"rsp"))
        );
        // Other peer or sequence does not hit
        assert!(mgr
            .lookup_cached_response("127.0.0.2:2123".parse().unwrap(), 0x1234)
            .is_none());
        assert!(mgr.lookup_cached_response(peer(), 0x1235).is_none());

        // Expires after hold duration
        std::thread::sleep(Duration::from_millis(25));
        mgr.poll(Instant::now());
        assert!(mgr.lookup_cached_response(peer(), 0x1234).is_none());
    }

    #[test]
    fn test_triggered_message_type_pairs() {
        use Gtp2MessageType as T;
        assert_eq!(
            triggered_message_type(T::EchoRequest as u8),
            Some(T::EchoResponse as u8)
        );
        assert_eq!(
            triggered_message_type(T::DownlinkDataNotification as u8),
            Some(T::DownlinkDataNotificationAcknowledge as u8)
        );
        assert_eq!(
            triggered_message_type(T::ReleaseAccessBearersRequest as u8),
            Some(T::ReleaseAccessBearersResponse as u8)
        );
        // A response type has no triggered message
        assert_eq!(triggered_message_type(T::CreateSessionResponse as u8), None);
    }
}
