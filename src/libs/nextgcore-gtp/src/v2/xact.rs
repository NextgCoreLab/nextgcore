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

/// The most significant bit of the 24-bit sequence number. TS 29.274 §7.6: "A
/// Sequence Number used for a Command message shall have the most significant bit
/// set to 1", the message it triggers (and that message's reply) carries the same
/// number, and "A Sequence Number used for a Request message, which was not
/// triggered by a Command message shall have the most significant bit set to 0".
pub const GTP2_COMMAND_SEQUENCE_FLAG: u32 = 0x0080_0000;

/// Largest sequence number an initial message that is not a Command may carry
/// (the MSB is clear, TS 29.274 §7.6).
pub const GTP2_MAX_INITIAL_SEQUENCE: u32 = GTP2_COMMAND_SEQUENCE_FLAG - 1;

/// Whether `sequence_number` belongs to a Command exchange: a Command, the
/// message it triggered, or that message's reply (MSB set, TS 29.274 §7.6).
pub fn is_command_sequence(sequence_number: u32) -> bool {
    sequence_number & GTP2_COMMAND_SEQUENCE_FLAG != 0
}

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
/// message pair is known (TS 29.274 Table 6.1-1).
///
/// For a Command this is the triggered *Request* it normally produces; a Command
/// can be answered by more than one message type, so use
/// [`triggered_message_types`] (or [`is_triggered_message`]) to decide whether a
/// received message closes it.
pub fn triggered_message_type(request_type: u8) -> Option<u8> {
    triggered_message_types(request_type).first().copied()
}

/// Every message type that is a triggered message of `initial_type` and so
/// closes its transaction (TS 29.274 §7.6, Table 6.1-1). Empty when
/// `initial_type` is not an initial message this layer knows.
///
/// A Command is closed by the triggered Request it causes, which carries the
/// Command's sequence number (TS 29.274 §7.6: "a Command message ... the
/// triggered message ... shall be a Request"), or by its Failure Indication:
/// - Modify Bearer Command (§7.2.14.1): Update Bearer Request, or Modify Bearer
///   Failure Indication (§7.2.14.2);
/// - Delete Bearer Command (§7.2.17.1): Delete Bearer Request, or Delete Bearer
///   Failure Indication (§7.2.17.2);
/// - Bearer Resource Command (§7.2.5): Create, Update or Delete Bearer Request
///   (TS 23.401 §5.4.5 step 3 lets the PGW pick any of the three), or Bearer
///   Resource Failure Indication (§7.2.6).
pub fn triggered_message_types(initial_type: u8) -> &'static [u8] {
    use Gtp2MessageType as T;
    macro_rules! types {
        ($($t:ident),+) => {{
            const LIST: &[u8] = &[$(T::$t as u8),+];
            LIST
        }};
    }
    match initial_type {
        x if x == T::EchoRequest as u8 => types!(EchoResponse),
        x if x == T::CreateSessionRequest as u8 => types!(CreateSessionResponse),
        x if x == T::ModifyBearerRequest as u8 => types!(ModifyBearerResponse),
        x if x == T::DeleteSessionRequest as u8 => types!(DeleteSessionResponse),
        x if x == T::ChangeNotificationRequest as u8 => types!(ChangeNotificationResponse),
        x if x == T::CreateBearerRequest as u8 => types!(CreateBearerResponse),
        x if x == T::UpdateBearerRequest as u8 => types!(UpdateBearerResponse),
        x if x == T::DeleteBearerRequest as u8 => types!(DeleteBearerResponse),
        x if x == T::CreateIndirectDataForwardingTunnelRequest as u8 => {
            types!(CreateIndirectDataForwardingTunnelResponse)
        }
        x if x == T::DeleteIndirectDataForwardingTunnelRequest as u8 => {
            types!(DeleteIndirectDataForwardingTunnelResponse)
        }
        x if x == T::ReleaseAccessBearersRequest as u8 => types!(ReleaseAccessBearersResponse),
        x if x == T::DownlinkDataNotification as u8 => {
            types!(DownlinkDataNotificationAcknowledge)
        }
        x if x == T::ModifyAccessBearersRequest as u8 => types!(ModifyAccessBearersResponse),
        x if x == T::CreateForwardingTunnelRequest as u8 => {
            types!(CreateForwardingTunnelResponse)
        }
        x if x == T::DeletePdnConnectionSetRequest as u8 => {
            types!(DeletePdnConnectionSetResponse)
        }
        x if x == T::UpdatePdnConnectionSetRequest as u8 => {
            types!(UpdatePdnConnectionSetResponse)
        }
        // #618: the N26/S10/S3 mobility pairs (Table 6.1-1, `29274-j60.txt:2410-2431`).
        x if x == T::IdentificationRequest as u8 => types!(IdentificationResponse),
        x if x == T::ContextRequest as u8 => types!(ContextResponse),
        x if x == T::ForwardRelocationRequest as u8 => types!(ForwardRelocationResponse),
        x if x == T::ForwardRelocationCompleteNotification as u8 => {
            types!(ForwardRelocationCompleteAcknowledge)
        }
        x if x == T::ModifyBearerCommand as u8 => {
            types!(UpdateBearerRequest, ModifyBearerFailureIndication)
        }
        x if x == T::DeleteBearerCommand as u8 => {
            types!(DeleteBearerRequest, DeleteBearerFailureIndication)
        }
        // #592: N26/S10/S3 handover cancel (TS 29.274 §7.3.16-7.3.17).
        x if x == T::RelocationCancelRequest as u8 => types!(RelocationCancelResponse),
        x if x == T::BearerResourceCommand as u8 => types!(
            CreateBearerRequest,
            UpdateBearerRequest,
            DeleteBearerRequest,
            BearerResourceFailureIndication
        ),
        _ => &[],
    }
}

/// Whether `message_type` is a triggered message of `initial_type`, i.e. one
/// that closes a transaction opened by `initial_type` (TS 29.274 §7.6).
pub fn is_triggered_message(initial_type: u8, message_type: u8) -> bool {
    triggered_message_types(initial_type).contains(&message_type)
}

/// Whether `message_type` is a Command (TS 29.274 §7.6), whose triggered
/// message is itself a Request the receiver must answer.
pub fn is_command(message_type: u8) -> bool {
    use Gtp2MessageType as T;
    message_type == T::ModifyBearerCommand as u8
        || message_type == T::DeleteBearerCommand as u8
        || message_type == T::BearerResourceCommand as u8
}

/// GTPv2-C transaction manager
#[derive(Debug)]
pub struct Gtp2XactMgr {
    config: Gtp2XactConfig,
    next_sequence: u32,
    /// Outstanding locally originated requests, keyed by (peer, sequence number).
    ///
    /// The peer is part of the key because a triggered Request (one answering a
    /// peer's Command) carries the *Command's* sequence number, which comes from
    /// the peer's sequence space, not this node's (TS 29.274 §7.6). A relay such as
    /// the SGW-C sends those with numbers it did not allocate, so keyed by number
    /// alone one could silently replace an unrelated outstanding request.
    local: HashMap<(SocketAddr, u32), Gtp2LocalXact>,
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

    /// Allocate a sequence number for an initial message that is NOT a Command:
    /// monotonically increasing in 1..=[`GTP2_MAX_INITIAL_SEQUENCE`], so the most
    /// significant bit is always clear (TS 29.274 §7.6, #727). It wraps back to 1.
    pub fn alloc_sequence(&mut self) -> u32 {
        let seq = self.next_sequence;
        self.next_sequence = if self.next_sequence >= GTP2_MAX_INITIAL_SEQUENCE {
            1
        } else {
            self.next_sequence + 1
        };
        seq
    }

    /// Allocate a sequence number for a Command (Modify / Delete Bearer Command,
    /// Bearer Resource Command): the next number of [`Self::alloc_sequence`] with the
    /// most significant bit set (TS 29.274 §7.6, #727).
    ///
    /// The two spaces cannot overlap, so a peer's own initial Request (MSB clear)
    /// can never close a Command this node sent, and a peer that tells triggered
    /// from initial Requests by the MSB sees the Command's triggered Request as one.
    pub fn alloc_command_sequence(&mut self) -> u32 {
        self.alloc_sequence() | GTP2_COMMAND_SEQUENCE_FLAG
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
        self.local.insert((peer, sequence_number), xact);
    }

    /// Match an incoming triggered message to an outstanding request.
    /// Returns the completed transaction if the sequence number matches an
    /// outstanding request and `response_type` is one of its triggered types
    /// ([`triggered_message_types`]): a Response for a Request, the triggered
    /// Request or the Failure Indication for a Command.
    ///
    /// Matches on any peer. Prefer [`Self::match_response_from`] where the
    /// sender is known.
    pub fn match_response(
        &mut self,
        sequence_number: u32,
        response_type: u8,
    ) -> Option<Gtp2LocalXact> {
        let key = self
            .local
            .iter()
            .find(|((_, seq), xact)| {
                *seq == sequence_number && is_triggered_message(xact.message_type, response_type)
            })
            .map(|(key, _)| *key)?;
        self.local.remove(&key)
    }

    /// [`Self::match_response`] for a triggered message received from `peer`:
    /// only a request sent to that peer can be closed by it.
    pub fn match_response_from(
        &mut self,
        peer: SocketAddr,
        sequence_number: u32,
        response_type: u8,
    ) -> Option<Gtp2LocalXact> {
        let key = (peer, sequence_number);
        match self.local.get(&key) {
            Some(xact) if is_triggered_message(xact.message_type, response_type) => {
                self.local.remove(&key)
            }
            _ => None,
        }
    }

    /// Whether a locally originated request to `peer` at `sequence_number` is
    /// outstanding (a new one there would replace it).
    pub fn is_outstanding(&self, peer: SocketAddr, sequence_number: u32) -> bool {
        self.local.contains_key(&(peer, sequence_number))
    }

    /// Number of outstanding locally originated requests
    pub fn outstanding(&self) -> usize {
        self.local.len()
    }

    /// Drive T3/N3: returns requests due for retransmission and exhausted
    /// transactions that must be treated as peer-unreachable.
    pub fn poll(&mut self, now: Instant) -> Gtp2XactPoll {
        let mut result = Gtp2XactPoll::default();
        let mut exhausted_keys = Vec::new();

        for xact in self.local.values_mut() {
            if now < xact.deadline {
                continue;
            }
            if xact.retries_left == 0 {
                exhausted_keys.push((xact.peer, xact.sequence_number));
            } else {
                xact.retries_left -= 1;
                xact.deadline = now + self.config.t3_response;
                result.retransmits.push((xact.peer, xact.encoded.clone()));
            }
        }

        for key in exhausted_keys {
            if let Some(xact) = self.local.remove(&key) {
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

    /// Drop the cached responses whose hold has expired, without touching the
    /// locally originated requests [`Self::poll`] would also retransmit.
    pub fn expire_responses(&mut self, now: Instant) {
        self.responses.retain(|_, cached| cached.expires > now);
    }

    /// The number of cached responses, expired or not.
    pub fn cached_response_count(&self) -> usize {
        self.responses.len()
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

        // Force wrap: the initial space ends below the Command MSB (#727)
        mgr.next_sequence = GTP2_MAX_INITIAL_SEQUENCE;
        assert_eq!(mgr.alloc_sequence(), GTP2_MAX_INITIAL_SEQUENCE);
        // 0 is skipped after wrap, and 0x800000 is never handed out
        assert_eq!(mgr.alloc_sequence(), 1);
    }

    /// #727, TS 29.274 §7.6: a Command's number has the MSB set, every other
    /// initial message's number has it clear, across the whole allocator cycle.
    #[test]
    fn command_sequences_set_the_msb_and_initial_sequences_never_do() {
        let mut mgr = Gtp2XactMgr::default();
        for start in [1, 0x7F_FFF0, GTP2_MAX_INITIAL_SEQUENCE] {
            mgr.next_sequence = start;
            for _ in 0..64 {
                let initial = mgr.alloc_sequence();
                assert!(
                    (1..=GTP2_MAX_INITIAL_SEQUENCE).contains(&initial),
                    "{initial:#x}"
                );
                assert!(!is_command_sequence(initial), "{initial:#x}");
                let command = mgr.alloc_command_sequence();
                assert!(is_command_sequence(command), "{command:#x}");
                assert!(command <= GTP2_MAX_SEQUENCE, "{command:#x}");
                assert_ne!(command & GTP2_MAX_INITIAL_SEQUENCE, 0, "{command:#x}");
            }
        }
    }

    /// #727 scenario 1: the peer's own initial Create Bearer Request reuses the low
    /// 23 bits of a Command this node sent. It must not close the Command.
    #[test]
    fn a_peers_initial_request_cannot_close_a_command() {
        let mut mgr = Gtp2XactMgr::default();
        let cmd_seq = mgr.alloc_command_sequence();
        mgr.register_request(
            cmd_seq,
            Gtp2MessageType::BearerResourceCommand as u8,
            peer(),
            Bytes::from_static(b"brc"),
            7,
        );
        let peer_initial = cmd_seq & GTP2_MAX_INITIAL_SEQUENCE;
        assert!(mgr
            .match_response_from(
                peer(),
                peer_initial,
                Gtp2MessageType::CreateBearerRequest as u8
            )
            .is_none());
        let closed = mgr
            .match_response_from(peer(), cmd_seq, Gtp2MessageType::CreateBearerRequest as u8)
            .expect("the triggered Request carries the Command's number");
        assert_eq!(closed.data, 7);
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
        assert_eq!(
            triggered_message_type(T::RelocationCancelRequest as u8),
            Some(T::RelocationCancelResponse as u8),
            "#592: the Relocation Cancel Response closes the request"
        );
        // A response type has no triggered message
        assert_eq!(triggered_message_type(T::CreateSessionResponse as u8), None);
    }

    /// #618: the N26/S10 request/response pairs, so a Context Response or a Forward
    /// Relocation Response closes its request and reaches the procedure.
    #[test]
    fn every_n26_request_pairs_with_its_response() {
        use Gtp2MessageType as T;
        for (request, response) in [
            (T::IdentificationRequest, T::IdentificationResponse),
            (T::ContextRequest, T::ContextResponse),
            (T::ForwardRelocationRequest, T::ForwardRelocationResponse),
            (
                T::ForwardRelocationCompleteNotification,
                T::ForwardRelocationCompleteAcknowledge,
            ),
        ] {
            assert_eq!(
                triggered_message_types(request as u8),
                &[response as u8],
                "{request:?}"
            );
            let mut mgr = Gtp2XactMgr::default();
            mgr.register_request(9, request as u8, peer(), Bytes::new(), 0);
            assert!(mgr.match_response_from(peer(), 9, response as u8).is_some());
            assert_eq!(mgr.outstanding(), 0);
        }
        // The acknowledge-type messages open no transaction of their own.
        assert!(triggered_message_types(T::ContextAcknowledge as u8).is_empty());
    }

    /// #591: every Command pairs with the triggered Requests and the Failure
    /// Indication TS 29.274 §7.6 / Table 6.1-1 give it, and with nothing else.
    #[test]
    fn every_command_pairs_with_its_triggered_messages() {
        use Gtp2MessageType as T;
        let pairs: &[(T, &[T])] = &[
            (
                T::ModifyBearerCommand,
                &[T::UpdateBearerRequest, T::ModifyBearerFailureIndication],
            ),
            (
                T::DeleteBearerCommand,
                &[T::DeleteBearerRequest, T::DeleteBearerFailureIndication],
            ),
            (
                T::BearerResourceCommand,
                &[
                    T::CreateBearerRequest,
                    T::UpdateBearerRequest,
                    T::DeleteBearerRequest,
                    T::BearerResourceFailureIndication,
                ],
            ),
        ];
        for (command, triggered) in pairs {
            let command = *command as u8;
            let expected: Vec<u8> = triggered.iter().map(|t| *t as u8).collect();
            assert_eq!(triggered_message_types(command), expected.as_slice());
            assert!(is_command(command));
            for t in 0..=u8::MAX {
                assert_eq!(
                    is_triggered_message(command, t),
                    expected.contains(&t),
                    "command {command} / type {t}"
                );
            }
        }
        // A Command's own Response type does not exist; a Response closes nothing.
        assert!(!is_command(T::DeleteBearerRequest as u8));
        assert_eq!(
            triggered_message_type(T::DeleteBearerCommand as u8),
            Some(T::DeleteBearerRequest as u8)
        );
    }

    /// #591: the triggered message closes a Command's transaction, so T3/N3 no
    /// longer retransmits it.
    #[test]
    fn a_triggered_request_stops_the_command_retransmitting() {
        use Gtp2MessageType as T;
        let config = Gtp2XactConfig {
            t3_response: Duration::from_millis(1),
            n3_requests: 3,
            response_hold: Duration::from_secs(1),
        };
        for (command, triggered) in [
            (T::DeleteBearerCommand, T::DeleteBearerRequest),
            (T::DeleteBearerCommand, T::DeleteBearerFailureIndication),
            (T::ModifyBearerCommand, T::UpdateBearerRequest),
            (T::ModifyBearerCommand, T::ModifyBearerFailureIndication),
            (T::BearerResourceCommand, T::CreateBearerRequest),
            (T::BearerResourceCommand, T::UpdateBearerRequest),
            (T::BearerResourceCommand, T::DeleteBearerRequest),
            (T::BearerResourceCommand, T::BearerResourceFailureIndication),
        ] {
            let mut mgr = Gtp2XactMgr::new(config);
            let seq = mgr.alloc_sequence();
            mgr.register_request(seq, command as u8, peer(), Bytes::from_static(b"cmd"), 7);
            // A Response type is not the triggered message of a Command.
            assert!(mgr
                .match_response(seq, T::DeleteBearerResponse as u8)
                .is_none());
            let closed = mgr
                .match_response_from(peer(), seq, triggered as u8)
                .unwrap_or_else(|| panic!("{command:?} not closed by {triggered:?}"));
            assert_eq!(closed.message_type, command as u8);
            assert_eq!(closed.data, 7);
            std::thread::sleep(Duration::from_millis(3));
            let poll = mgr.poll(Instant::now());
            assert!(
                poll.retransmits.is_empty(),
                "{command:?} still retransmitted"
            );
            assert!(poll.exhausted.is_empty());
        }
    }

    /// A triggered Request a relay sends carries the peer's sequence number, so
    /// the same number may be outstanding towards two peers at once. Each one is
    /// closed only by its own answer.
    #[test]
    fn the_same_sequence_towards_two_peers_is_two_transactions() {
        use Gtp2MessageType as T;
        let other: SocketAddr = "127.0.0.2:2123".parse().unwrap();
        let mut mgr = Gtp2XactMgr::default();
        mgr.register_request(5, T::CreateSessionRequest as u8, peer(), Bytes::new(), 1);
        mgr.register_request(5, T::DeleteBearerRequest as u8, other, Bytes::new(), 2);
        assert_eq!(mgr.outstanding(), 2);
        assert!(mgr
            .match_response_from(peer(), 5, T::DeleteBearerResponse as u8)
            .is_none());
        let closed = mgr
            .match_response_from(other, 5, T::DeleteBearerResponse as u8)
            .unwrap();
        assert_eq!(closed.data, 2);
        let closed = mgr
            .match_response(5, T::CreateSessionResponse as u8)
            .unwrap();
        assert_eq!(closed.data, 1);
        assert_eq!(mgr.outstanding(), 0);
    }
}
