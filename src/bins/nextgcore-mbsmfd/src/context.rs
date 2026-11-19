//! MB-SMF Context Management
//!
//! Multicast/Broadcast Session Management Function context (TS 23.247)
//! Includes N4mb PFCP session management for multicast transport

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::subscription::{SubEntry, SubscriptionStore};
use crate::types::PatchItem;

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SNssai {
    pub sst: u8,
    pub sd: Option<u32>,
}

/// MBS Session ID (TMGI - Temporary Mobile Group Identity)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Tmgi {
    /// MBS Service ID (3 bytes)
    pub mbs_service_id: [u8; 3],
    /// PLMN ID (MCC + MNC)
    pub plmn_id: PlmnId,
}

/// PLMN ID
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PlmnId {
    pub mcc: String,
    pub mnc: String,
}

/// MBS Session Type (TS 23.247 5.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MbsSessionType {
    #[default]
    Multicast,
    Broadcast,
}

/// MBS Session State
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MbsSessionState {
    #[default]
    Created,
    Active,
    Suspended,
    Released,
}

/// N4mb PFCP session state for multicast transport (TS 23.247 7.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum N4mbSessionState {
    #[default]
    Idle,
    EstablishmentPending,
    Established,
    ModificationPending,
    ReleasePending,
}

/// N4mb PFCP session context for UPF multicast transport
#[derive(Debug, Clone)]
pub struct N4mbSession {
    /// PFCP session endpoint ID (local)
    pub local_seid: u64,
    /// PFCP session endpoint ID (UPF)
    pub remote_seid: u64,
    /// UPF address for N4mb
    pub upf_addr: Ipv4Addr,
    /// Session state
    pub state: N4mbSessionState,
    /// Multicast PDR ID (downlink, 1-to-many)
    pub mcast_pdr_id: u16,
    /// Multicast FAR ID (forwarding to gNBs)
    pub mcast_far_id: u32,
    /// GTP-U TEID for multicast DL tunnel (the GTP-U common TEID / `cTeid`
    /// returned to the SMF in ContextUpdate).
    pub dl_teid: u32,
    /// Multicast transport address (UPF endpoint)
    pub transport_addr: Option<Ipv4Addr>,
    /// Lower-layer SSM source address (`llSsm.sourceIpAddr`) advertised to the
    /// SMF for multicast reception (TS 29.532 ContextUpdate). [mbsmfd-03/09]
    pub ll_ssm_src: Option<Ipv4Addr>,
    /// Lower-layer SSM destination (the IP multicast group `llSsm.destIpAddr`),
    /// also the OuterHeaderCreation transport address in the N4mb Create FAR.
    pub ll_ssm_dst: Option<Ipv4Addr>,
    /// Target gNB TEIDs for multicast forwarding
    pub gnb_teids: Vec<GnbMcastEndpoint>,
}

/// gNB endpoint for multicast GTP-U delivery
#[derive(Debug, Clone)]
pub struct GnbMcastEndpoint {
    pub gnb_addr: Ipv4Addr,
    pub teid: u32,
}

impl N4mbSession {
    pub fn new(local_seid: u64, upf_addr: Ipv4Addr) -> Self {
        Self {
            local_seid,
            remote_seid: 0,
            upf_addr,
            state: N4mbSessionState::Idle,
            mcast_pdr_id: 0,
            mcast_far_id: 0,
            dl_teid: 0,
            transport_addr: None,
            ll_ssm_src: None,
            ll_ssm_dst: None,
            gnb_teids: Vec::new(),
        }
    }
}

/// MBS group membership entry
#[derive(Debug, Clone)]
pub struct MbsGroupMember {
    pub supi: String,
    pub pdu_session_id: Option<u8>,
    pub joined_at: u64,
}

/// A broadcast MBS context an AMF created for a session on Namf_MBSBroadcast
/// ContextCreate (#1758): where it lives, so the session's release can delete it
/// (ContextDelete, TS 29.518 §5.6; TS 23.247 §7.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmfMbsContext {
    pub host: String,
    pub port: u16,
    pub nf_instance_id: Option<String>,
    pub context_ref: String,
    /// #1796: the token ending the `notifyUri` this ContextCreate gave the AMF,
    /// by which its ContextStatusNotify is admitted and matched to the session.
    pub notify_token: String,
    /// #1854: the TMGI it was created for, so its delete takes the same
    /// (AMF, TMGI) lane as a create for that TMGI ([`crate::lane`]). `None` when
    /// unknown.
    pub tmgi: Option<Tmgi>,
}

/// #1863: the first MBS session pool ID of this process, the boot time in
/// microseconds since the epoch. IDs used to restart at 1, so after a restart
/// a consumer's stale `mbs-sess-3` named whichever session the new process
/// numbered 3 (another consumer's), and its DELETE released it. Seeding from the
/// clock keeps IDs unique and increasing across restarts without persisting a
/// counter: a restart is more than a microsecond after the previous process's
/// last allocation, and sessions are created far slower than one per
/// microsecond. Kept below 2^53 so a JSON number consumer reads it exactly.
fn boot_session_id_base() -> usize {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as usize)
        .unwrap_or(1)
        .max(1)
}

/// #1930: an AMF context's identity: the AMF and its `mbsContextRef`.
type ContextKey = (String, u16, String);

fn context_key(c: &AmfMbsContext) -> ContextKey {
    (c.host.clone(), c.port, c.context_ref.clone())
}

/// #2015: the deterministic seam of the held-snapshot race: a hook the next
/// mint on this thread runs at the point where it has decided which contexts
/// live sessions hold and is about to reclaim, so a test can try to land a
/// `record_amf_context` exactly there. Thread-local, so no other test sees it.
#[cfg(test)]
mod mint_seam {
    use super::MbSmfContext;
    use std::cell::RefCell;

    type Hook = Box<dyn FnOnce(&MbSmfContext)>;

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    pub fn set(hook: impl FnOnce(&MbSmfContext) + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub fn fire(ctx: &MbSmfContext) {
        if let Some(hook) = HOOK.with(|h| h.borrow_mut().take()) {
            hook(ctx);
        }
    }
}

/// #1796/#1930: one live notify token: the session holding it and the AMF
/// context it names (`None` until the ContextCreate answered).
#[derive(Debug, Clone)]
struct NotifyToken {
    session_id: u64,
    context: Option<ContextKey>,
    /// #1985: mint order, so the cap reclaims the oldest released context first.
    seq: u64,
    /// #2015: the AMF answered this context's ContextDelete with a 204, so the
    /// token is only in its #1796 grace: the one kind of token the mint cap may
    /// reclaim ([`MbSmfContext::mark_amf_context_released`]).
    released: bool,
}

/// #2015: what a notify token is, for the mint cap: held by a live session or a
/// create in flight (`Live`), its context released by the AMF's 204 and in its
/// grace (`Released`), or its context's delete still pending -- in flight,
/// retried or parked -- so the context still exists at the AMF (`Pending`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenClass {
    Live,
    Released,
    Pending,
}

fn token_class(t: &NotifyToken, held: &HashSet<ContextKey>) -> TokenClass {
    match &t.context {
        None => TokenClass::Live,
        Some(k) if held.contains(k) => TokenClass::Live,
        Some(_) if t.released => TokenClass::Released,
        Some(_) => TokenClass::Pending,
    }
}

fn held_contexts(contexts: &HashMap<u64, Vec<AmfMbsContext>>) -> HashSet<ContextKey> {
    contexts.values().flatten().map(context_key).collect()
}

/// #1985: the mint order of [`NotifyToken::seq`].
static NOTIFY_TOKEN_SEQ: AtomicU64 = AtomicU64::new(0);

/// #1796: the most AMF ContextStatusNotify tokens held at once. One is minted per
/// ContextCreate and forgotten when its context is released; past the cap a
/// ContextCreate is not sent.
///
/// #2015: the cap counts the tokens of live sessions, of creates in flight and of
/// contexts the AMF released (204, in their grace). At the cap a mint reclaims
/// the oldest released context's tokens, and refuses when there is none (live
/// sessions fill the cap, as before #1985). It never takes the token of a
/// context whose delete is pending: that context still exists at the AMF, and a
/// session that is handed it again is notified on that token (#1985).
pub const MAX_AMF_NOTIFY_TOKENS: usize = 4096;

/// #2015: the most tokens of contexts whose ContextDelete is pending (in flight,
/// retried or parked), on top of [`MAX_AMF_NOTIFY_TOKENS`], so they never count
/// against a live session's create. Normally the parked set's own ends bound
/// them (`reconcile::MAX_PENDING` eviction, the reconciler's 204/404, `MAX_AGE`,
/// `releasedInd`); a context reused many times holds one token per reuse,
/// though, so this is the hard bound: a mint that would pass it forgets the
/// tokens of the oldest pending context first. The map never holds more than
/// `MAX_AMF_NOTIFY_TOKENS + MAX_PENDING_NOTIFY_TOKENS`.
pub const MAX_PENDING_NOTIFY_TOKENS: usize = crate::reconcile::MAX_PENDING;

/// MBS Session Context (TS 23.247 5.3)
#[derive(Debug, Clone)]
pub struct MbsSession {
    /// Unique pool ID
    pub id: u64,
    /// #1863: the verified NF Instance ID of the consumer that created the
    /// session (`nextgcore_sbi::owner_binding`), the only one that may update
    /// or release it. `None` when created with no verified identity (`dev`).
    pub owner: Option<String>,
    /// MBS Session ID (TMGI)
    pub tmgi: Tmgi,
    /// MBS session type
    pub session_type: MbsSessionType,
    /// Session state
    pub state: MbsSessionState,
    /// S-NSSAI for the session
    pub s_nssai: SNssai,
    /// DNN
    pub dnn: Option<String>,
    /// MBS service area (list of TAIs)
    pub service_area_tacs: Vec<u32>,
    /// QoS flow ID
    pub qfi: u8,
    /// 5QI for the MBS QoS flow
    pub fiveqi: u8,
    /// Maximum bitrate (bps)
    pub max_bitrate: u64,
    /// Multicast transport address (for NGAP)
    pub transport_address: Option<String>,
    /// GTP-U TEID for multicast data
    pub gtp_teid: u32,
    /// Number of joined UEs
    pub joined_ue_count: u32,
    /// SM context reference at SMF
    pub sm_context_ref: Option<String>,
    /// N4mb PFCP session to UPF
    pub n4mb_session: Option<N4mbSession>,
    /// Group membership tracking (SUPI set)
    pub group_members: HashSet<String>,
    /// The SSM the consumer identified this session with, when it used one (#76).
    ///
    /// Distinct from `n4mb_session.ll_ssm_src`/`ll_ssm_dst`, which are the
    /// lower-layer SSM the MB-SMF *allocates* toward NG-RAN. This is the
    /// `MbsSessionId.ssm` the consumer supplied, and it is what an SSM-identified
    /// ContextUpdate has to be resolved by.
    ///
    /// Held as the wire type (`crate::types::Ssm`) rather than parsed into
    /// `std::net::IpAddr`: TS 29.571's `IpAddr` is a choice of two OPTIONAL textual
    /// members, so "the address the consumer sent" and "an address" are not the same
    /// thing, and matching on the received form is what makes a lookup agree with
    /// what was stored.
    pub ssm: Option<crate::types::Ssm>,
    /// The NF consumers (`ContextUpdateReqData.nfcInstanceId`) currently receiving on
    /// this session's shared N4mb transport (#295, TS 23.247 §7.2.1.3/§7.2.1.4).
    ///
    /// Distinct from [`Self::group_members`], which tracks UE SUPIs: a multicast MBS
    /// session is a SHARED distribution session established once and reused across
    /// joins, so the transport underneath it must outlive any single consumer's
    /// departure. Before this set existed, the first consumer to send a ContextUpdate
    /// TERMINATE released the MB-UPF session for every other consumer still receiving
    /// on it — and the remaining consumers' sessions looked fine (state, SBI surface
    /// and TMGI all unchanged) and simply stopped carrying data.
    ///
    /// Keyed on `nfcInstanceId` rather than counted, so a consumer that restarts and
    /// re-STARTs is not counted twice and a repeated TERMINATE cannot decrement twice.
    pub consumers: HashSet<String>,
    /// The RAN nodes currently receiving shared delivery on this session's transport
    /// (#301, TS 23.247 §7.2.1.4/§7.2.2.4), keyed on a canonical form of the
    /// ContextUpdate's `ranNodeId`.
    ///
    /// A SECOND, independent dimension from [`Self::consumers`], not a rename of it.
    /// #295 keyed that set on `nfcInstanceId`, which on the N2 leg is the **AMF's** —
    /// so the AMF leg could not consult it (deregistering the AMF's id finds it absent,
    /// since SMF STARTs populate the set) and must not register into it (an AMF's
    /// silence would then pin the transport open, which #295 explicitly declined to
    /// create). Before this set existed, one RAN node's `MBS_DIS_REL_REQ` deleted the
    /// MB-UPF session for every other RAN node still receiving on it — the same defect
    /// shape as #295's, in a different dimension, and just as quiet: the remaining
    /// RAN nodes' contexts, the `MbsSession` state and the TMGI were all unchanged and
    /// the data simply stopped.
    ///
    /// Keyed on a canonical STRING rather than the decoded structure: `GlobalRanNodeId`
    /// (TS 29.571) is a choice of `gNbId` / `ngeNbId` / `n3IwfId` / `wagfId` / `tngfId`
    /// / `eNbId`, so two JSON objects that mean the same node can differ in member
    /// order and in hex case — and a key that does not agree with what was stored
    /// silently fails to match, which is what [`Self::ssm`] records for the SSM.
    /// Nothing echoes a `ranNodeId` back to a peer, so unlike the SSM there is no
    /// reason to keep the received form; if a future issue needs to, this becomes a map
    /// from key to the received value.
    pub ran_nodes: HashSet<String>,
}

/// Canonical key for a `GlobalRanNodeId` (#301).
///
/// One string per RAN node, stable across member order and hex case, so the key a
/// setup stores is the key a release looks up. Returns `None` for a `ranNodeId` that is
/// not an object — the caller then treats the release as untracked, which is the
/// pre-#301 behaviour rather than a silent non-match.
pub fn canonical_ran_node_key(value: &serde_json::Value) -> Option<String> {
    let obj = value.as_object()?;

    // The PLMN scopes the node id: a gNB id is only unique within its PLMN
    // (TS 38.413 §9.3.1.5), and a session can carry RAN nodes from more than one in a
    // shared-PLMN deployment.
    let plmn = obj
        .get("plmnId")
        .and_then(|p| p.as_object())
        .map(|p| {
            format!(
                "{}-{}",
                p.get("mcc").and_then(|v| v.as_str()).unwrap_or(""),
                p.get("mnc").and_then(|v| v.as_str()).unwrap_or("")
            )
        })
        .unwrap_or_default();

    // gNB id is a structure (bitLength + gNBValue); the rest are plain strings. Checked
    // in a fixed order so a peer that (wrongly) sends two never keys inconsistently.
    if let Some(g) = obj.get("gNbId").and_then(|g| g.as_object()) {
        let bits = g.get("bitLength").and_then(|v| v.as_u64()).unwrap_or(0);
        let val = g
            .get("gNBValue")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_uppercase();
        return Some(format!("{plmn}/gNbId:{bits}:{val}"));
    }
    for member in ["ngeNbId", "n3IwfId", "wagfId", "tngfId", "eNbId", "nid"] {
        if let Some(v) = obj.get(member).and_then(|v| v.as_str()) {
            return Some(format!("{plmn}/{member}:{}", v.to_ascii_uppercase()));
        }
    }

    // No known id member. Key on a canonical rendering of the whole object rather than
    // giving up: an unrecognised-but-consistent RAN node still matches ITSELF, which is
    // all the set needs. `to_string` is not used because it is not guaranteed to order
    // members independently of how they were parsed.
    let mut canonical = String::new();
    canonical_json(value, &mut canonical);
    Some(format!("{plmn}/raw:{canonical}"))
}

/// Render a JSON value with object members in sorted order, so equal values render
/// equal regardless of how they were parsed.
fn canonical_json(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(k);
                out.push(':');
                if let Some(v) = map.get(*k) {
                    canonical_json(v, out);
                }
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// What a consumer's ContextUpdate TERMINATE means for the shared transport (#295).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumerTerminate {
    /// No MBS session matched the TMGI.
    NotFound,
    /// Something is still receiving: the transport stays up. Carries who, because
    /// nothing else in the system can name them.
    ///
    /// #301 widened this from "other consumers" to "other HOLDERS": entries are
    /// prefixed `consumer:` or `ran-node:`, since either dimension being non-empty
    /// keeps the transport up.
    ConsumerRemains { remaining: Vec<String> },
    /// Nothing holds it any more, so the transport is released.
    LastConsumer,
}

/// Who still holds a session's shared N4mb transport (#301).
///
/// Both dimensions in one list, prefixed so a log line and a test assertion can tell
/// them apart. Sorted, because both sides come from `HashSet`s.
fn transport_holders(session: &MbsSession) -> Vec<String> {
    let mut holders: Vec<String> = session
        .consumers
        .iter()
        .map(|c| format!("consumer:{c}"))
        .collect();
    holders.extend(session.ran_nodes.iter().map(|r| format!("ran-node:{r}")));
    holders.sort();
    holders
}

impl MbsSession {
    pub fn new(id: u64, tmgi: Tmgi, session_type: MbsSessionType) -> Self {
        Self {
            id,
            tmgi,
            session_type,
            state: MbsSessionState::Created,
            s_nssai: SNssai::default(),
            dnn: None,
            service_area_tacs: Vec::new(),
            qfi: 1,
            fiveqi: 9,
            max_bitrate: 10_000_000, // 10 Mbps default
            transport_address: None,
            gtp_teid: 0,
            joined_ue_count: 0,
            sm_context_ref: None,
            n4mb_session: None,
            group_members: HashSet::new(),
            ssm: None,
            consumers: HashSet::new(),
            ran_nodes: HashSet::new(),
            owner: None,
        }
    }

    /// Add a UE to the multicast group
    pub fn member_join(&mut self, supi: &str) -> bool {
        if self.group_members.insert(supi.to_string()) {
            self.joined_ue_count = self.group_members.len() as u32;
            log::info!("UE {supi} joined MBS session {}", self.id);
            true
        } else {
            false
        }
    }

    /// Remove a UE from the multicast group
    pub fn member_leave(&mut self, supi: &str) -> bool {
        if self.group_members.remove(supi) {
            self.joined_ue_count = self.group_members.len() as u32;
            log::info!("UE {supi} left MBS session {}", self.id);
            true
        } else {
            false
        }
    }

    /// Check if a UE is a member of this session
    pub fn is_member(&self, supi: &str) -> bool {
        self.group_members.contains(supi)
    }
}

/// N4mb PFCP message types for multicast transport (TS 29.244 extension)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N4mbMessageType {
    SessionEstablishmentRequest,
    SessionEstablishmentResponse,
    SessionModificationRequest,
    SessionModificationResponse,
    SessionReleaseRequest,
    SessionReleaseResponse,
}

/// Build N4mb PFCP Session Establishment for multicast (TS 23.247 7.3.2)
pub fn build_n4mb_session_establishment(
    session: &MbsSession,
    local_seid: u64,
    upf_addr: Ipv4Addr,
) -> N4mbSession {
    let mut n4mb = N4mbSession::new(local_seid, upf_addr);
    n4mb.state = N4mbSessionState::EstablishmentPending;
    // Assign multicast PDR/FAR IDs based on session
    n4mb.mcast_pdr_id = (session.id as u16).wrapping_mul(2).wrapping_add(1000);
    n4mb.mcast_far_id = (session.id as u32).wrapping_mul(2).wrapping_add(2000);
    n4mb.dl_teid = session.gtp_teid;
    // Lower-layer SSM for multicast reception (TS 29.532 §6.2.6.2.6): the source
    // is the (MB-)UPF transport address and the destination is an admin-scoped
    // (239.0.0.0/8) IP multicast group derived deterministically from the
    // session id. This same destination is the OuterHeaderCreation transport
    // address in the N4mb Create FAR (mbsmfd-09).
    n4mb.ll_ssm_src = Some(upf_addr);
    n4mb.ll_ssm_dst = Some(mcast_group_for(session.id));
    n4mb
}

/// Deterministic admin-scoped IPv4 multicast group (239.1.x.y) for an MBS
/// session id — used as the lower-layer SSM destination / N4mb transport address.
pub fn mcast_group_for(session_id: u64) -> Ipv4Addr {
    Ipv4Addr::new(239, 1, (session_id >> 8) as u8, session_id as u8)
}

/// Process N4mb Session Establishment Response
pub fn process_n4mb_establishment_response(
    n4mb: &mut N4mbSession,
    remote_seid: u64,
    dl_teid: u32,
    transport_addr: Ipv4Addr,
) {
    n4mb.remote_seid = remote_seid;
    n4mb.dl_teid = dl_teid;
    n4mb.transport_addr = Some(transport_addr);
    n4mb.state = N4mbSessionState::Established;
    log::info!(
        "N4mb session established: local_seid={} remote_seid={} dl_teid={:#x} transport={}",
        n4mb.local_seid,
        remote_seid,
        dl_teid,
        transport_addr
    );
}

// ---------------------------------------------------------------------------
// mbsmfd-04: TMGI allocation pool (Nmbsmf_TMGI, TS 29.532 §5.2)
// ---------------------------------------------------------------------------

/// Current wall-clock time as whole seconds since the Unix epoch.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format a Unix timestamp as an RFC 3339 / ISO-8601 UTC string (the
/// `DateTime` shape TS 29.571 expects for `expirationTime`). Dependency-free
/// civil-date conversion (Howard Hinnant's algorithm).
pub fn unix_to_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as i64;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Default TMGI lifetime (seconds) before expiry. Refreshed on re-allocation.
pub const TMGI_DEFAULT_TTL_SECS: u64 = 3600;

/// Per-PLMN TMGI allocation pool with per-allocation expiry (TS 29.532 §5.2.2).
///
/// `mbsServiceId` is a 3-octet value allocated monotonically per PLMN; each
/// allocated TMGI tracks an absolute expiry (Unix seconds) that refresh extends.
#[derive(Debug, Default)]
pub struct TmgiPool {
    /// Next free 3-octet service id per PLMN.
    next_id: HashMap<PlmnId, u32>,
    /// Allocated TMGI -> absolute expiry (Unix seconds).
    allocated: HashMap<Tmgi, u64>,
    /// #1863: allocated TMGI -> the verified NF Instance ID of the consumer it
    /// was allocated to (`nextgcore_sbi::owner_binding`). Absent for a TMGI
    /// allocated with no verified identity (`dev`).
    owners: HashMap<Tmgi, String>,
}

/// #1863 (R32 on #1943 M1): the first 24-bit TMGI service id of this process,
/// random, so the TMGIs a previous process allocated (in memory only) are not
/// handed out again from 000001 after a restart. A collision with a TMGI still
/// held from before the restart needs the new run of allocations to reach the
/// old run: with n held and m newly allocated, the odds are about
/// (n + m) / 2^24 per restart (about 6e-6 for 50 each).
fn boot_tmgi_seed() -> u32 {
    let b = uuid::Uuid::new_v4();
    let b = b.as_bytes();
    (u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2])).max(1)
}

/// #1863: why a TMGI operation was refused; nothing was changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TmgiRefusal {
    /// A listed TMGI is not allocated to the requester (allocated to another
    /// consumer, frozen, or, for a refresh, not allocated at all).
    NotOwned(Tmgi),
}

impl TmgiPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate `count` fresh TMGIs in `plmn`, expiring `ttl_secs` from `now`.
    /// Returns the allocated TMGIs and the common absolute expiry.
    pub fn allocate(
        &mut self,
        plmn: &PlmnId,
        count: u32,
        ttl_secs: u64,
        now: u64,
    ) -> (Vec<Tmgi>, u64) {
        self.allocate_owned(plmn, count, ttl_secs, now, None, |_| false)
    }

    /// [`Self::allocate`] for `owner` (#1863). A TMGI still allocated (an
    /// unexpired one after the 24-bit counter wrapped) is skipped, never
    /// handed to a second consumer.
    pub fn allocate_owned(
        &mut self,
        plmn: &PlmnId,
        count: u32,
        ttl_secs: u64,
        now: u64,
        owner: Option<&str>,
        in_use: impl Fn(&Tmgi) -> bool,
    ) -> (Vec<Tmgi>, u64) {
        let expiry = now.saturating_add(ttl_secs);
        let mut out = Vec::with_capacity(count as usize);
        // #1863 (R32 on #1943 M1): the counter starts at a per-boot random
        // point, not at 1, so a restart does not hand out the TMGIs the previous
        // process allocated (which other consumers may still hold).
        let next = self
            .next_id
            .entry(plmn.clone())
            .or_insert_with(boot_tmgi_seed);
        let mut tries = 0u32;
        while out.len() < count as usize && tries < 1 << 24 {
            tries += 1;
            let id = *next;
            *next = next.wrapping_add(1) & 0x00FF_FFFF;
            let tmgi = Tmgi {
                mbs_service_id: [(id >> 16) as u8, (id >> 8) as u8, id as u8],
                plmn_id: plmn.clone(),
            };
            // Skip one still allocated, and one a live MBS session names
            // (R32 on #1943: a session created on an unallocated TMGI).
            if self.allocated.contains_key(&tmgi) || in_use(&tmgi) {
                continue;
            }
            self.allocated.insert(tmgi.clone(), expiry);
            if let Some(owner) = owner {
                self.owners.insert(tmgi.clone(), owner.to_string());
            }
            out.push(tmgi);
        }
        (out, expiry)
    }

    /// Refresh the expiry of the supplied TMGIs, returning the new common
    /// absolute expiry. #1863: every one must be allocated and `may_manage` its
    /// owner, else nothing is refreshed. A TMGI that is not allocated is no
    /// longer inserted: that let a consumer claim one allocated to another
    /// consumer before a restart, or one this MB-SMF never allocated.
    pub fn refresh(
        &mut self,
        tmgis: &[Tmgi],
        ttl_secs: u64,
        now: u64,
        may_manage: impl Fn(Option<&str>) -> bool,
    ) -> Result<u64, TmgiRefusal> {
        if let Some(t) = tmgis
            .iter()
            .find(|t| !self.allocated.contains_key(t) || !may_manage(self.owner_of(t)))
        {
            return Err(TmgiRefusal::NotOwned(t.clone()));
        }
        let expiry = now.saturating_add(ttl_secs);
        for t in tmgis {
            self.allocated.insert(t.clone(), expiry);
        }
        Ok(expiry)
    }

    /// Deallocate the supplied TMGIs; returns how many were present. #1863:
    /// every allocated one must `may_manage` its owner, else nothing is freed
    /// (TS 29.532 §5.2.2.3: the consumer deallocates TMGIs it was allocated).
    /// One that is not allocated is already gone and is skipped.
    pub fn deallocate(
        &mut self,
        tmgis: &[Tmgi],
        may_manage: impl Fn(Option<&str>) -> bool,
    ) -> Result<usize, TmgiRefusal> {
        if let Some(t) = tmgis
            .iter()
            .find(|t| self.allocated.contains_key(t) && !may_manage(self.owner_of(t)))
        {
            return Err(TmgiRefusal::NotOwned(t.clone()));
        }
        Ok(tmgis
            .iter()
            .filter(|t| {
                self.owners.remove(t);
                self.allocated.remove(t).is_some()
            })
            .count())
    }

    /// #1863: allocate `tmgi` to `owner` when it is not allocated (a session
    /// created on a TMGI this MB-SMF did not allocate, or one that expired), so
    /// it is recorded as the creator's and no later Allocate hands it out. An
    /// allocated one is left as it is, and `Err` when `may_use` refuses its
    /// owner.
    pub fn claim(
        &mut self,
        tmgi: &Tmgi,
        owner: Option<&str>,
        ttl_secs: u64,
        now: u64,
        may_use: impl Fn(Option<&str>) -> bool,
    ) -> Result<(), TmgiRefusal> {
        if self.allocated.contains_key(tmgi) {
            return if may_use(self.owner_of(tmgi)) {
                Ok(())
            } else {
                Err(TmgiRefusal::NotOwned(tmgi.clone()))
            };
        }
        self.allocated
            .insert(tmgi.clone(), now.saturating_add(ttl_secs));
        if let Some(owner) = owner {
            self.owners.insert(tmgi.clone(), owner.to_string());
        }
        Ok(())
    }

    /// The consumer `tmgi` is allocated to, if it was bound to one (#1863).
    pub fn owner_of(&self, tmgi: &Tmgi) -> Option<&str> {
        self.owners.get(tmgi).map(String::as_str)
    }

    /// Whether `tmgi` is currently allocated.
    pub fn is_allocated(&self, tmgi: &Tmgi) -> bool {
        self.allocated.contains_key(tmgi)
    }

    /// Drop TMGIs whose expiry is at or before `now`.
    pub fn purge_expired(&mut self, now: u64) {
        self.allocated.retain(|_, &mut expiry| expiry > now);
        let allocated = &self.allocated;
        self.owners.retain(|t, _| allocated.contains_key(t));
    }

    /// Number of currently-allocated TMGIs.
    pub fn len(&self) -> usize {
        self.allocated.len()
    }

    pub fn is_empty(&self) -> bool {
        self.allocated.is_empty()
    }

    /// Expiry (Unix seconds) of a specific TMGI, if allocated.
    pub fn expiry_of(&self, tmgi: &Tmgi) -> Option<u64> {
        self.allocated.get(tmgi).copied()
    }
}

/// MB-SMF Context - main context structure
pub struct MbSmfContext {
    /// MBS session list
    session_list: RwLock<HashMap<u64, MbsSession>>,
    /// TMGI -> session ID hash
    tmgi_hash: RwLock<HashMap<Tmgi, u64>>,
    /// Next session ID generator
    next_session_id: AtomicUsize,
    /// Maximum number of sessions
    max_sessions: usize,
    /// Context initialized flag
    initialized: AtomicBool,
    /// Next N4mb SEID generator
    next_n4mb_seid: AtomicUsize,
    /// Next GTP-U TEID generator for multicast
    next_mcast_teid: AtomicU32,
    /// Nmbsmf_TMGI allocation pool (per-PLMN, with expiry). [mbsmfd-04]
    tmgi_pool: Mutex<TmgiPool>,
    /// Status subscription store (NEF/MBSF/AF-facing). [mbsmfd-05]
    status_subs: Mutex<SubscriptionStore>,
    /// ContextStatus subscription store (SMF-facing). [mbsmfd-05]
    context_status_subs: Mutex<SubscriptionStore>,
    /// #1758: the AMF broadcast MBS contexts each session created, by session id.
    /// Kept beside `session_list` rather than in [`MbsSession`], so no stale session
    /// clone written back by `session_update` can erase one. Lock order:
    /// `session_list` before this.
    amf_contexts: Mutex<HashMap<u64, Vec<AmfMbsContext>>>,
    /// #1796: the live AMF ContextStatusNotify tokens, by token: the session that
    /// holds it and, once the ContextCreate answered, the AMF context it names.
    /// #1930: a token lives as long as its AMF context, not its session (see
    /// [`Self::record_amf_context`]). Lock order: after `amf_contexts`.
    amf_notify_tokens: Mutex<HashMap<String, NotifyToken>>,
    /// #1796: `{scheme}://{advertised host:port}`, the base of the `notifyUri`s
    /// this MB-SMF gives the AMF; `None` until startup sets it.
    amf_notify_base: RwLock<Option<String>>,
}

impl MbSmfContext {
    pub fn new() -> Self {
        Self {
            session_list: RwLock::new(HashMap::new()),
            tmgi_hash: RwLock::new(HashMap::new()),
            next_session_id: AtomicUsize::new(boot_session_id_base()),
            max_sessions: 0,
            initialized: AtomicBool::new(false),
            next_n4mb_seid: AtomicUsize::new(0x100),
            next_mcast_teid: AtomicU32::new(0x0BCA_0001),
            tmgi_pool: Mutex::new(TmgiPool::new()),
            status_subs: Mutex::new(SubscriptionStore::new()),
            context_status_subs: Mutex::new(SubscriptionStore::new()),
            amf_contexts: Mutex::new(HashMap::new()),
            amf_notify_tokens: Mutex::new(HashMap::new()),
            amf_notify_base: RwLock::new(None),
        }
    }

    /// #1796: set the base of the AMF `notifyUri`s (from the advertised SBI address).
    pub fn set_amf_notify_base(&self, base: impl Into<String>) {
        if let Ok(mut b) = self.amf_notify_base.write() {
            *b = Some(base.into());
        }
    }

    /// #1796: the base of the AMF `notifyUri`s, once set.
    pub fn amf_notify_base(&self) -> Option<String> {
        self.amf_notify_base.read().ok()?.clone()
    }

    /// #1796: a fresh ContextStatusNotify token for session `id`, or `None` at
    /// [`MAX_AMF_NOTIFY_TOKENS`] when no released context's tokens can be
    /// reclaimed (#2015).
    ///
    /// #2015: which contexts live sessions hold and the reclaim are decided in
    /// ONE critical section, `amf_contexts` then `amf_notify_tokens` (the order
    /// [`Self::record_amf_context`] takes them in), so a record cannot land
    /// between the two and lose the token it was just handed. Callers may hold
    /// the global context's read guard; nothing here takes the pending set.
    pub fn mint_amf_notify_token(&self, id: u64) -> Option<String> {
        let contexts = self.amf_contexts.lock().ok()?;
        let mut tokens = self.amf_notify_tokens.lock().ok()?;
        if tokens.len() >= MAX_AMF_NOTIFY_TOKENS {
            let held = held_contexts(&contexts);
            #[cfg(test)]
            mint_seam::fire(self);
            if !Self::make_room(&mut tokens, &held) {
                log::warn!(
                    "MBS: {MAX_AMF_NOTIFY_TOKENS} AMF notification tokens held by live \
                     sessions; none minted"
                );
                return None;
            }
        }
        drop(contexts);
        let token = uuid::Uuid::new_v4().simple().to_string();
        tokens.insert(
            token.clone(),
            NotifyToken {
                session_id: id,
                context: None,
                seq: NOTIFY_TOKEN_SEQ.fetch_add(1, Ordering::Relaxed),
                released: false,
            },
        );
        Some(token)
    }

    /// #2015: room for one more token, or false (nothing changed). Live and
    /// released tokens are capped at [`MAX_AMF_NOTIFY_TOKENS`]: at the cap the
    /// oldest released context's tokens are reclaimed, and with none the mint is
    /// refused rather than take a pending context's. Pending tokens are capped
    /// separately at [`MAX_PENDING_NOTIFY_TOKENS`]: past it the oldest pending
    /// context's tokens go, so they never starve a live create.
    fn make_room(tokens: &mut HashMap<String, NotifyToken>, held: &HashSet<ContextKey>) -> bool {
        let counted = tokens
            .values()
            .filter(|t| token_class(t, held) != TokenClass::Pending)
            .count();
        if counted >= MAX_AMF_NOTIFY_TOKENS
            && !Self::forget_oldest(tokens, held, TokenClass::Released)
        {
            return false;
        }
        if tokens.len() >= MAX_AMF_NOTIFY_TOKENS + MAX_PENDING_NOTIFY_TOKENS {
            Self::forget_oldest(tokens, held, TokenClass::Pending);
        }
        true
    }

    /// #1985/#2015: forget every token of the context with the oldest token of
    /// `class` (`Released` or `Pending`; a `Live` one is never taken). Returns
    /// whether there was one.
    fn forget_oldest(
        tokens: &mut HashMap<String, NotifyToken>,
        held: &HashSet<ContextKey>,
        class: TokenClass,
    ) -> bool {
        debug_assert!(class != TokenClass::Live);
        let Some(key) = tokens
            .values()
            .filter(|t| token_class(t, held) == class)
            .filter_map(|t| t.context.as_ref().map(|k| (t.seq, k)))
            .min_by_key(|(seq, _)| *seq)
            .map(|(_, k)| k.clone())
        else {
            return false;
        };
        let before = tokens.len();
        tokens.retain(|_, t| t.context.as_ref() != Some(&key));
        let what = if class == TokenClass::Released {
            "released"
        } else {
            "pending (its delete is not done; a session handed it again is not notified)"
        };
        log::warn!(
            "MBS: AMF notification tokens at their cap; forgot {} of the {what} AMF {}:{} \
             MBS context {}",
            before - tokens.len(),
            key.0,
            key.1,
            key.2
        );
        true
    }

    /// #2015: the AMF answered `c`'s ContextDelete with a 204: its tokens are in
    /// their #1796 grace only, so the mint cap may reclaim them.
    pub fn mark_amf_context_released(&self, c: &AmfMbsContext) {
        let key = context_key(c);
        if let Ok(mut tokens) = self.amf_notify_tokens.lock() {
            for (t, v) in tokens.iter_mut() {
                if *t == c.notify_token || v.context.as_ref() == Some(&key) {
                    v.released = true;
                }
            }
        }
    }

    /// #2015: whether `token`'s context is marked released (a 204), for tests.
    #[cfg(test)]
    pub fn amf_notify_token_released(&self, token: &str) -> bool {
        self.amf_notify_tokens
            .lock()
            .is_ok_and(|t| t.get(token).is_some_and(|v| v.released))
    }

    /// #1796: the session a live ContextStatusNotify token belongs to (#1930: the
    /// session holding its AMF context now).
    pub fn amf_notify_session(&self, token: &str) -> Option<u64> {
        self.amf_notify_tokens
            .lock()
            .ok()?
            .get(token)
            .map(|t| t.session_id)
    }

    /// #1930: forget every notify token of the AMF context `c` names (and `c`'s
    /// own): the context is released at the AMF, so nothing will be notified on
    /// them. Returns how many were forgotten.
    pub fn forget_amf_context_tokens(&self, c: &AmfMbsContext) -> usize {
        let key = context_key(c);
        let Ok(mut tokens) = self.amf_notify_tokens.lock() else {
            return 0;
        };
        let before = tokens.len();
        tokens.retain(|t, v| *t != c.notify_token && v.context.as_ref() != Some(&key));
        before - tokens.len()
    }

    /// #2015: forget `c`'s context's tokens as [`Self::forget_amf_context_tokens`]
    /// does, unless a live session holds that context: for a delete given up on
    /// (evicted or expired), whose context a session may have re-recorded since
    /// the delete left the pending set. The check and the forget are one critical
    /// section, `amf_contexts` then `amf_notify_tokens` (as in
    /// [`Self::record_amf_context`]), so a record cannot land between them.
    /// Returns how many were forgotten.
    pub fn forget_unheld_context_tokens(&self, c: &AmfMbsContext) -> usize {
        let key = context_key(c);
        let Ok(contexts) = self.amf_contexts.lock() else {
            return 0;
        };
        if contexts.values().flatten().any(|h| context_key(h) == key) {
            return 0;
        }
        let Ok(mut tokens) = self.amf_notify_tokens.lock() else {
            return 0;
        };
        let before = tokens.len();
        tokens.retain(|t, v| *t != c.notify_token && v.context.as_ref() != Some(&key));
        before - tokens.len()
    }

    /// #1930: how many notify tokens are held.
    pub fn amf_notify_token_count(&self) -> usize {
        self.amf_notify_tokens.lock().map_or(0, |t| t.len())
    }

    /// #1796: forget a token whose AMF context is gone (or was never created).
    pub fn forget_amf_notify_token(&self, token: &str) {
        if let Ok(mut tokens) = self.amf_notify_tokens.lock() {
            tokens.remove(token);
        }
    }

    /// #1796: the AMF released the context of `token` itself (`releasedInd`):
    /// drop its record, so the session's release does not delete it again, and
    /// the token. Returns whether a record was dropped.
    pub fn drop_amf_context_by_token(&self, token: &str) -> bool {
        // #1930: the token names an AMF context; the record of it may carry
        // another token of the same context (a session that took it over).
        let key = self
            .amf_notify_tokens
            .lock()
            .ok()
            .and_then(|t| t.get(token).and_then(|v| v.context.clone()));
        let names =
            |c: &AmfMbsContext| c.notify_token == token || key.as_ref() == Some(&context_key(c));
        let mut dropped_records = Vec::new();
        if let Ok(mut map) = self.amf_contexts.lock() {
            for list in map.values_mut() {
                list.retain(|c| {
                    let gone = names(c);
                    if gone {
                        dropped_records.push(c.clone());
                    }
                    !gone
                });
            }
            map.retain(|_, list| !list.is_empty());
        }
        self.forget_amf_notify_token(token);
        for c in &dropped_records {
            self.forget_amf_context_tokens(c);
        }
        // #1985: a context no session records (its delete is parked) has tokens
        // too: the AMF released it, so they all go.
        if let (Some(key), Ok(mut tokens)) = (key, self.amf_notify_tokens.lock()) {
            tokens.retain(|_, t| t.context.as_ref() != Some(&key));
        }
        !dropped_records.is_empty()
    }

    /// #1758: record an AMF MBS context for session `id`, only while the session
    /// exists. Holding `session_list` across the insert serialises it with
    /// [`Self::session_remove`]: either the release that removes the session then
    /// takes this context, or this sees the session gone and returns false, and the
    /// caller deletes the context itself.
    pub fn record_amf_context(&self, id: u64, context: AmfMbsContext) -> bool {
        let Ok(session_list) = self.session_list.read() else {
            return false;
        };
        if !session_list.contains_key(&id) {
            return false;
        }
        let Ok(mut map) = self.amf_contexts.lock() else {
            return false;
        };
        let list = map.entry(id).or_default();
        if !list.contains(&context) {
            list.push(context.clone());
        }
        drop(map);
        drop(session_list);
        // #1930: every notify token of this AMF context now belongs to session
        // `id`. The AMF answers a ContextCreate for a TMGI whose context it still
        // holds with that same context (a released session's, whose delete is
        // then dropped) and may keep notifying the notifyUri of the FIRST create,
        // so that token is the live session's now, not the released one's. Each
        // is forgotten when the context is released ([`Self::forget_amf_context_tokens`]).
        let key = context_key(&context);
        if let Ok(mut tokens) = self.amf_notify_tokens.lock() {
            if let Some(own) = tokens.get_mut(&context.notify_token) {
                own.context = Some(key.clone());
            }
            for t in tokens.values_mut() {
                if t.context.as_ref() == Some(&key) {
                    t.session_id = id;
                    // #2015: held again, so no longer released.
                    t.released = false;
                }
            }
        }
        // R24: the AMF hands a session reusing a released session's TMGI the same
        // `mbsContextRef`, so a parked delete of it must not run.
        crate::reconcile::unpark(&context);
        true
    }

    /// R24: whether a live session holds the AMF context `c` (same AMF, same
    /// `mbsContextRef`).
    pub fn amf_context_in_use(&self, c: &AmfMbsContext) -> bool {
        self.amf_contexts.lock().is_ok_and(|m| {
            m.values()
                .flatten()
                .any(|h| h.host == c.host && h.port == c.port && h.context_ref == c.context_ref)
        })
    }

    /// #1758: take every AMF MBS context recorded for session `id`, for its release.
    pub fn take_amf_contexts(&self, id: u64) -> Vec<AmfMbsContext> {
        self.amf_contexts
            .lock()
            .ok()
            .and_then(|mut m| m.remove(&id))
            .unwrap_or_default()
    }

    /// #1758: the AMF MBS contexts recorded for session `id`.
    pub fn amf_contexts_of(&self, id: u64) -> Vec<AmfMbsContext> {
        self.amf_contexts
            .lock()
            .ok()
            .and_then(|m| m.get(&id).cloned())
            .unwrap_or_default()
    }

    pub fn init(&mut self, max_sessions: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_sessions = max_sessions;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("MB-SMF context initialized with max {max_sessions} sessions");
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.session_remove_all();
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("MB-SMF context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Allocate a new N4mb SEID
    pub fn alloc_n4mb_seid(&self) -> u64 {
        self.next_n4mb_seid.fetch_add(1, Ordering::SeqCst) as u64
    }

    /// Allocate a new multicast GTP-U TEID
    pub fn alloc_mcast_teid(&self) -> u32 {
        self.next_mcast_teid.fetch_add(1, Ordering::SeqCst)
    }

    // Session management

    pub fn session_add(&self, tmgi: Tmgi, session_type: MbsSessionType) -> Option<MbsSession> {
        self.session_add_owned(tmgi, session_type, None)
    }

    /// [`Self::session_add`] bound to `owner` (#1863), the only consumer that
    /// may update or release the session.
    pub fn session_add_owned(
        &self,
        tmgi: Tmgi,
        session_type: MbsSessionType,
        owner: Option<String>,
    ) -> Option<MbsSession> {
        self.session_add_claiming(tmgi, session_type, owner, |_| true)
            .ok()
            .flatten()
    }

    /// [`Self::session_add_owned`], also claiming the TMGI for `owner` in the
    /// pool (#1863, R32 on #1943) under the same locks as the add, so no
    /// Allocate can hand it out between the check and the add: an unallocated
    /// or expired TMGI becomes the creator's, and one allocated to a consumer
    /// `may_use` refuses is `Err`, adding nothing. `Ok(None)` is the existing
    /// refusals (cap, duplicate TMGI).
    pub fn session_add_claiming(
        &self,
        tmgi: Tmgi,
        session_type: MbsSessionType,
        owner: Option<String>,
        may_use: impl Fn(Option<&str>) -> bool,
    ) -> Result<Option<MbsSession>, TmgiRefusal> {
        let Ok(mut session_list) = self.session_list.write() else {
            return Ok(None);
        };
        let Ok(mut tmgi_hash) = self.tmgi_hash.write() else {
            return Ok(None);
        };

        if session_list.len() >= self.max_sessions {
            log::error!(
                "Maximum number of MBS sessions [{}] reached",
                self.max_sessions
            );
            return Ok(None);
        }

        // #76: a duplicate TMGI used to overwrite `tmgi_hash` silently, so the
        // earlier session stayed in `session_list` reachable by NOTHING — its TMGI
        // resolved to the new session, and its N4mb session on the MB-UPF could
        // never be released. Refusing is the honest answer: a TMGI identifies one
        // MBS session, so a second create for the same one is the consumer's error,
        // and the existing session is still there to be found or deleted.
        if tmgi_hash.contains_key(&tmgi) {
            log::warn!(
                "MBS session create refused: TMGI {tmgi:?} already identifies session {:?}",
                tmgi_hash.get(&tmgi)
            );
            return Ok(None);
        }
        {
            let now = now_unix();
            let mut pool = self.tmgi_pool.lock().expect("tmgi pool poisoned");
            pool.purge_expired(now);
            pool.claim(&tmgi, owner.as_deref(), TMGI_DEFAULT_TTL_SECS, now, may_use)?;
        }

        let id = self.next_session_id.fetch_add(1, Ordering::SeqCst) as u64;
        let mut session = MbsSession::new(id, tmgi.clone(), session_type);
        session.owner = owner;
        // Allocate a multicast TEID for this session
        session.gtp_teid = self.alloc_mcast_teid();

        tmgi_hash.insert(tmgi, id);
        session_list.insert(id, session.clone());

        log::info!(
            "MBS session added (id={id}, type={session_type:?}, teid={:#x})",
            session.gtp_teid
        );
        Ok(Some(session))
    }

    /// Remove a session's LOCAL state.
    ///
    /// #76: this used to be the whole of DELETE, and its log line said "releasing
    /// N4mb SEID" while releasing nothing — no PFCP Session Deletion Request was
    /// ever sent, so every released MBS session leaked an N4mb session on the
    /// MB-UPF. The wire release is the caller's job (it needs an `await`), which is
    /// why the removed session — carrying its `n4mb_session` — is returned. Callers
    /// must use [`Self::session_mark_release_pending`] first and remove only after
    /// the Session Deletion Response.
    pub fn session_remove(&self, id: u64) -> Option<MbsSession> {
        let mut session_list = self.session_list.write().ok()?;
        let mut tmgi_hash = self.tmgi_hash.write().ok()?;

        if let Some(session) = session_list.remove(&id) {
            tmgi_hash.remove(&session.tmgi);
            log::info!("MBS session local state removed (id={id})");
            return Some(session);
        }
        None
    }

    /// Mark a session's N4mb context `ReleasePending` and return the remote SEID to
    /// address the Session Deletion Request to (#76).
    ///
    /// Two steps rather than one because the deletion is an `await` and the context
    /// is behind a `std` lock: the state transition happens under the lock, the wire
    /// exchange outside it, and the local removal only after the response. The
    /// remote SEID is what the request must be addressed to (TS 29.244 §7.5.4) —
    /// the LOCAL seid would address a session the UP does not know.
    pub fn session_mark_release_pending(&self, id: u64) -> Option<u64> {
        let mut session_list = self.session_list.write().ok()?;
        let session = session_list.get_mut(&id)?;
        let n4mb = session.n4mb_session.as_mut()?;
        n4mb.state = N4mbSessionState::ReleasePending;
        // A session whose establishment never completed has no UP-allocated SEID,
        // so there is nothing on the UP to delete. `None` says so, distinctly from
        // "no N4mb context at all".
        (n4mb.remote_seid != 0).then_some(n4mb.remote_seid)
    }

    pub fn session_remove_all(&self) {
        if let (Ok(mut session_list), Ok(mut tmgi_hash)) =
            (self.session_list.write(), self.tmgi_hash.write())
        {
            session_list.clear();
            tmgi_hash.clear();
        }
        if let Ok(mut m) = self.amf_contexts.lock() {
            m.clear();
        }
        if let Ok(mut t) = self.amf_notify_tokens.lock() {
            t.clear();
        }
    }

    pub fn session_find_by_tmgi(&self, tmgi: &Tmgi) -> Option<MbsSession> {
        // Lock order session_list < tmgi_hash (matches session_add/session_remove).
        // Taking tmgi_hash before session_list would be an AB-BA deadlock vs
        // session_add (which holds session_list while acquiring tmgi_hash).
        let session_list = self.session_list.read().ok()?;
        let tmgi_hash = self.tmgi_hash.read().ok()?;
        tmgi_hash
            .get(tmgi)
            .and_then(|&id| session_list.get(&id).cloned())
    }

    pub fn session_find_by_id(&self, id: u64) -> Option<MbsSession> {
        let session_list = self.session_list.read().ok()?;
        session_list.get(&id).cloned()
    }

    pub fn session_update(&self, session: &MbsSession) -> bool {
        if let Ok(mut session_list) = self.session_list.write() {
            if let Some(existing) = session_list.get_mut(&session.id) {
                *existing = session.clone();
                return true;
            }
        }
        false
    }

    pub fn session_count(&self) -> usize {
        self.session_list.read().map(|l| l.len()).unwrap_or(0)
    }

    /// Activate a session with N4mb PFCP establishment to UPF.
    ///
    /// **Idempotent (#76).** An N4mb session that is already `Established` is
    /// returned unchanged rather than replaced. It used to allocate a fresh
    /// `local_seid` and overwrite `n4mb_session` on every call, so N repeated
    /// joins/STARTs created N PFCP sessions on the MB-UPF and orphaned every
    /// previous one — contrary to the shared-distribution-session model of TS 23.247
    /// §7.2.1.3/§7.2.1.4, where one MB-UPF session is established once and reused
    /// across joins. Under multicast churn that leaked a UPF session per join.
    ///
    /// An `EstablishmentPending` session is NOT short-circuited: its establishment
    /// may have failed, and re-driving it is how a retry works. Only a session the
    /// UP has confirmed is reused.
    pub fn session_activate_n4mb(&self, session_id: u64, upf_addr: Ipv4Addr) -> Option<MbsSession> {
        let mut session_list = self.session_list.write().ok()?;
        let session = session_list.get_mut(&session_id)?;

        if let Some(existing) = session.n4mb_session.as_ref() {
            if existing.state == N4mbSessionState::Established {
                log::debug!(
                    "MBS session {session_id} already has an established N4mb session \
                     (seid={}); reusing it rather than allocating a second",
                    existing.local_seid
                );
                return Some(session.clone());
            }
        }

        let local_seid = self.alloc_n4mb_seid();
        let n4mb = build_n4mb_session_establishment(session, local_seid, upf_addr);

        session.n4mb_session = Some(n4mb);
        session.state = MbsSessionState::Active;
        session.transport_address = Some(upf_addr.to_string());

        log::info!(
            "MBS session {session_id} activated with N4mb to UPF {upf_addr} (seid={local_seid})"
        );
        Some(session.clone())
    }

    /// Find a session by the SSM the consumer identified it with (#76).
    ///
    /// A linear scan rather than a second index. Sessions are capped at
    /// `max_sessions` and ContextUpdate is not a per-packet path, so the cost is
    /// irrelevant — while a second index over the same sessions would be a second
    /// set of invariants to keep in step with `session_add`/`session_remove`, which
    /// is exactly the class of bug the duplicate-TMGI overwrite was.
    pub fn session_find_by_ssm(&self, ssm: &crate::types::Ssm) -> Option<MbsSession> {
        let session_list = self.session_list.read().ok()?;
        session_list
            .values()
            .find(|s| s.ssm.as_ref() == Some(ssm))
            .cloned()
    }

    /// Find a session by the LOCAL N4mb SEID (#76).
    ///
    /// The MB-UPF addresses a Session Report to the CP F-SEID it was given at
    /// establishment, i.e. to our `local_seid` — not to the SEID it allocated
    /// itself. Looking up by `remote_seid` would find nothing for every report.
    pub fn session_find_by_local_seid(&self, seid: u64) -> Option<MbsSession> {
        let session_list = self.session_list.read().ok()?;
        session_list
            .values()
            .find(|s| {
                s.n4mb_session
                    .as_ref()
                    .is_some_and(|n| n.local_seid == seid)
            })
            .cloned()
    }

    /// Activate a session on downlink data arrival (TS 23.247 §7.2.5.2), #76.
    ///
    /// Returns whether the state actually CHANGED. A session already `Active` is
    /// left alone and reports `false`, so the caller can distinguish "traffic
    /// reactivated a deactivated session" — the event that matters — from a report
    /// about a session that was never deactivated. Answering `true` unconditionally
    /// would make the log say a session was reactivated every time a packet arrived.
    pub fn session_activate_on_downlink_data(&self, session_id: u64) -> bool {
        if let Ok(mut list) = self.session_list.write() {
            if let Some(session) = list.get_mut(&session_id) {
                if session.state != MbsSessionState::Active {
                    session.state = MbsSessionState::Active;
                    return true;
                }
            }
        }
        false
    }

    /// Join a UE to an MBS session group
    pub fn session_member_join(&self, session_id: u64, supi: &str) -> bool {
        if let Ok(mut session_list) = self.session_list.write() {
            if let Some(session) = session_list.get_mut(&session_id) {
                return session.member_join(supi);
            }
        }
        false
    }

    /// Remove a UE from an MBS session group
    pub fn session_member_leave(&self, session_id: u64, supi: &str) -> bool {
        if let Ok(mut session_list) = self.session_list.write() {
            if let Some(session) = session_list.get_mut(&session_id) {
                return session.member_leave(supi);
            }
        }
        false
    }

    /// Get all sessions (for listing)
    pub fn all_sessions(&self) -> Vec<MbsSession> {
        self.session_list
            .read()
            .map(|l| l.values().cloned().collect())
            .expect("value expected")
    }

    /// Get active multicast sessions
    pub fn active_multicast_sessions(&self) -> Vec<MbsSession> {
        self.session_list
            .read()
            .map(|l| {
                l.values()
                    .filter(|s| {
                        s.state == MbsSessionState::Active
                            && s.session_type == MbsSessionType::Multicast
                    })
                    .cloned()
                    .collect()
            })
            .expect("value expected")
    }

    // ---- mbsmfd-04: Nmbsmf_TMGI operations ----

    /// Allocate `count` fresh TMGIs in `plmn` (TS 29.532 §5.2.2.2). Returns the
    /// allocated TMGIs and the common expiry (Unix seconds).
    pub fn tmgi_allocate(&self, plmn: &PlmnId, count: u32, ttl_secs: u64) -> (Vec<Tmgi>, u64) {
        self.tmgi_allocate_owned(plmn, count, ttl_secs, None)
    }

    /// [`Self::tmgi_allocate`] bound to `owner` (#1863).
    pub fn tmgi_allocate_owned(
        &self,
        plmn: &PlmnId,
        count: u32,
        ttl_secs: u64,
        owner: Option<&str>,
    ) -> (Vec<Tmgi>, u64) {
        let now = now_unix();
        // The TMGIs live sessions name, read BEFORE the pool lock:
        // `session_add_owned` takes `tmgi_hash` then the pool, so this order
        // never inverts it.
        let in_use: std::collections::HashSet<Tmgi> = self
            .tmgi_hash
            .read()
            .map(|h| h.keys().cloned().collect())
            .unwrap_or_default();
        let mut pool = self.tmgi_pool.lock().expect("tmgi pool poisoned");
        pool.purge_expired(now);
        pool.allocate_owned(plmn, count, ttl_secs, now, owner, |t| in_use.contains(t))
    }

    /// Refresh the supplied TMGIs' expiry (TS 29.532 §5.2.2.2). Returns the new
    /// common expiry (Unix seconds), or the TMGI the requester may not refresh
    /// (#1863), in which case nothing changed.
    pub fn tmgi_refresh(
        &self,
        tmgis: &[Tmgi],
        ttl_secs: u64,
        may_manage: impl Fn(Option<&str>) -> bool,
    ) -> Result<u64, TmgiRefusal> {
        let now = now_unix();
        let mut pool = self.tmgi_pool.lock().expect("tmgi pool poisoned");
        pool.purge_expired(now);
        pool.refresh(tmgis, ttl_secs, now, may_manage)
    }

    /// Deallocate specific TMGIs (TS 29.532 §5.2.2.3); returns how many existed,
    /// or the TMGI the requester may not deallocate (#1863), freeing nothing.
    pub fn tmgi_deallocate(
        &self,
        tmgis: &[Tmgi],
        may_manage: impl Fn(Option<&str>) -> bool,
    ) -> Result<usize, TmgiRefusal> {
        let mut pool = self.tmgi_pool.lock().expect("tmgi pool poisoned");
        pool.deallocate(tmgis, may_manage)
    }

    /// Whether `tmgi` is allocated, and to whom (#1863): `None` when it is not
    /// allocated, `Some(owner)` when it is.
    pub fn tmgi_allocation(&self, tmgi: &Tmgi) -> Option<Option<String>> {
        let now = now_unix();
        let mut pool = self.tmgi_pool.lock().ok()?;
        pool.purge_expired(now);
        pool.is_allocated(tmgi)
            .then(|| pool.owner_of(tmgi).map(str::to_string))
    }

    /// Number of currently-allocated TMGIs.
    pub fn tmgi_count(&self) -> usize {
        self.tmgi_pool.lock().map(|p| p.len()).unwrap_or(0)
    }

    /// Expiry (Unix seconds) of a specific allocated TMGI, if present.
    pub fn tmgi_expiry_of(&self, tmgi: &Tmgi) -> Option<u64> {
        self.tmgi_pool.lock().ok().and_then(|p| p.expiry_of(tmgi))
    }

    // ---- mbsmfd-05: Status / ContextStatus subscription CRUD ----

    /// Add a Status subscription (NEF/MBSF/AF-facing). Returns the new ID.
    pub fn status_sub_add(&self, entry: SubEntry) -> Option<String> {
        self.status_subs.lock().ok().map(|mut s| s.add(entry))
    }

    /// Apply a JSON Patch (RFC 6902 subset) to a Status subscription.
    /// Returns the modified bare document, or None if not found.
    pub fn status_sub_patch(&self, id: &str, ops: &[PatchItem]) -> Option<serde_json::Value> {
        self.status_subs
            .lock()
            .ok()
            .and_then(|mut s| s.patch(id, ops))
    }

    /// #1865: the owner of Status subscription `id` (`None`: no such
    /// subscription; `Some(None)`: ownerless).
    pub fn status_sub_owner(&self, id: &str) -> Option<Option<String>> {
        self.status_subs.lock().ok().and_then(|s| s.owner_of(id))
    }

    /// Remove a Status subscription (DELETE). Returns false if not found.
    pub fn status_sub_remove(&self, id: &str) -> bool {
        self.status_subs
            .lock()
            .ok()
            .map(|mut s| s.remove(id))
            .unwrap_or(false)
    }

    /// Collect Status subscriptions that match `event_type` and `session` key
    /// (for notify fan-out).
    pub fn status_subs_matching(
        &self,
        event_type: &str,
        session: &Option<serde_json::Value>,
    ) -> Vec<SubEntry> {
        self.status_subs
            .lock()
            .ok()
            .map(|s| s.matching(event_type, session))
            .unwrap_or_default()
    }

    /// Number of active Status subscriptions.
    pub fn status_sub_count(&self) -> usize {
        self.status_subs.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// Add a ContextStatus subscription (SMF-facing). Returns the new ID.
    pub fn ctx_sub_add(&self, entry: SubEntry) -> Option<String> {
        self.context_status_subs
            .lock()
            .ok()
            .map(|mut s| s.add(entry))
    }

    /// Apply a JSON Patch (RFC 6902 subset) to a ContextStatus subscription.
    /// Returns the modified bare document, or None if not found.
    pub fn ctx_sub_patch(&self, id: &str, ops: &[PatchItem]) -> Option<serde_json::Value> {
        self.context_status_subs
            .lock()
            .ok()
            .and_then(|mut s| s.patch(id, ops))
    }

    /// #1865: the owner of ContextStatus subscription `id` (`None`: no such
    /// subscription; `Some(None)`: ownerless).
    pub fn ctx_sub_owner(&self, id: &str) -> Option<Option<String>> {
        self.context_status_subs
            .lock()
            .ok()
            .and_then(|s| s.owner_of(id))
    }

    /// Remove a ContextStatus subscription (DELETE). Returns false if not found.
    pub fn ctx_sub_remove(&self, id: &str) -> bool {
        self.context_status_subs
            .lock()
            .ok()
            .map(|mut s| s.remove(id))
            .unwrap_or(false)
    }

    /// Collect ContextStatus subscriptions that match `event_type` and `session` key.
    pub fn ctx_subs_matching(
        &self,
        event_type: &str,
        session: &Option<serde_json::Value>,
    ) -> Vec<SubEntry> {
        self.context_status_subs
            .lock()
            .ok()
            .map(|s| s.matching(event_type, session))
            .unwrap_or_default()
    }

    /// Number of active ContextStatus subscriptions.
    pub fn ctx_sub_count(&self) -> usize {
        self.context_status_subs
            .lock()
            .map(|s| s.len())
            .unwrap_or(0)
    }

    // ---- mbsmfd-03: ContextUpdate Start / Terminate ----

    /// ContextUpdate **Start** (SMF, multicast): resolve the MBS session by TMGI,
    /// ensure an N4mb session is allocated (cTeid + llSsm + PDR/FAR), mark it
    /// establishment-pending and the MBS session Active. Returns the resolved
    /// session snapshot (carrying the freshly allocated N4mb context), or `None`
    /// when no session matches the TMGI.
    pub fn session_context_start(&self, tmgi: &Tmgi, upf_addr: Ipv4Addr) -> Option<MbsSession> {
        let id = {
            let tmgi_hash = self.tmgi_hash.read().ok()?;
            *tmgi_hash.get(tmgi)?
        };
        self.session_activate_n4mb(id, upf_addr)
    }

    /// Register a consumer NF on a session's shared transport (#295).
    ///
    /// Returns the consumer count after the insert, or `None` when no session matches
    /// the TMGI. Idempotent: a consumer that restarts and re-STARTs the same session is
    /// the same entry, which is what keying the set on `nfcInstanceId` buys.
    ///
    /// **Where the count starts, and why this leg.** #295 asks whether a ContextUpdate
    /// START implicitly registers `nfcInstanceId` as a consumer. It does: nothing else
    /// in the tree registers one, TS 23.247 §7.2.1.3 models the START as the establish
    /// side of a shared session, and this makes the count derivable from traffic the
    /// MB-SMF already sees rather than from a member the schema does not have. The
    /// alternative — counting only an explicit `leaveInd` join/leave — would leave the
    /// shared-transport hazard on exactly the `leaveInd == false` path that carries
    /// most of the traffic.
    pub fn session_consumer_register(&self, tmgi: &Tmgi, nfc_instance_id: &str) -> Option<usize> {
        if nfc_instance_id.is_empty() {
            return None;
        }
        let id = {
            let tmgi_hash = self.tmgi_hash.read().ok()?;
            *tmgi_hash.get(tmgi)?
        };
        let mut list = self.session_list.write().ok()?;
        let session = list.get_mut(&id)?;
        let fresh = session.consumers.insert(nfc_instance_id.to_string());
        let count = session.consumers.len();
        if fresh {
            log::info!(
                "[MBS] consumer {nfc_instance_id} registered on session {id} \
                 (TMGI {:02x?}); {count} consumer(s) now hold its shared transport",
                tmgi.mbs_service_id
            );
        }
        Some(count)
    }

    /// ContextUpdate **Terminate** from one consumer (#295): deregister it and say
    /// whether the shared transport may now be released.
    ///
    /// The transport is released only when the set becomes EMPTY. A consumer this
    /// session does not hold does not decrement anything, so a repeated TERMINATE
    /// cannot release a transport another consumer still holds.
    ///
    /// A session with no registered consumers at all yields [`ConsumerTerminate::
    /// LastConsumer`], which is deliberately the pre-#295 behaviour: sessions created
    /// before any START, and every existing single-consumer flow, must keep releasing
    /// on the first TERMINATE.
    pub fn session_context_terminate_for(
        &self,
        tmgi: &Tmgi,
        nfc_instance_id: &str,
    ) -> ConsumerTerminate {
        let id = {
            match self.tmgi_hash.read() {
                Ok(h) => match h.get(tmgi) {
                    Some(&id) => id,
                    None => return ConsumerTerminate::NotFound,
                },
                Err(_) => return ConsumerTerminate::NotFound,
            }
        };
        let remaining = {
            let Ok(mut list) = self.session_list.write() else {
                return ConsumerTerminate::NotFound;
            };
            let Some(session) = list.get_mut(&id) else {
                return ConsumerTerminate::NotFound;
            };
            if !nfc_instance_id.is_empty() {
                session.consumers.remove(nfc_instance_id);
            }
            // #301: the RAN-node set counts too. An SMF's last consumer leaving while a
            // RAN node is still receiving shared delivery must NOT delete the MB-UPF
            // session underneath that RAN node.
            transport_holders(session)
        };
        if !remaining.is_empty() {
            return ConsumerTerminate::ConsumerRemains { remaining };
        }
        // Last consumer: mark the transport for release exactly as the unconditional
        // path does, so the two agree about what "terminating" means locally.
        if self.session_context_terminate(tmgi) {
            ConsumerTerminate::LastConsumer
        } else {
            ConsumerTerminate::NotFound
        }
    }

    /// Shared delivery toward one RAN node is being established (#301, TS 23.247
    /// §7.2.1.4): record it as a holder of the session's shared transport.
    ///
    /// Mirrors [`Self::session_consumer_register`], and for the same reason: the set is
    /// keyed, not counted, so a RAN node whose AMF re-sends `MBS_DIS_SETUP_REQ` is not
    /// counted twice and a repeated `MBS_DIS_REL_REQ` cannot decrement twice.
    pub fn session_ran_node_register(&self, tmgi: &Tmgi, ran_node_key: &str) -> Option<usize> {
        if ran_node_key.is_empty() {
            return None;
        }
        let id = {
            let tmgi_hash = self.tmgi_hash.read().ok()?;
            *tmgi_hash.get(tmgi)?
        };
        let mut list = self.session_list.write().ok()?;
        let session = list.get_mut(&id)?;
        let fresh = session.ran_nodes.insert(ran_node_key.to_string());
        let count = session.ran_nodes.len();
        if fresh {
            log::info!(
                "[MBS] RAN node {ran_node_key} registered on session {id} (TMGI {:02x?}); \
                 {count} RAN node(s) now receive its shared delivery",
                tmgi.mbs_service_id
            );
        }
        Some(count)
    }

    /// `MBS_DIS_REL_REQ` from one RAN node (#301): deregister it and say whether the
    /// shared transport may now be released.
    ///
    /// Released only when NOTHING holds it — neither another RAN node nor an SMF
    /// consumer. A RAN node this session does not hold decrements nothing, so a repeated
    /// release cannot tear down delivery another RAN node is still receiving.
    ///
    /// A session with no registered RAN nodes at all yields
    /// [`ConsumerTerminate::LastConsumer`] when no consumer holds it either, which is
    /// deliberately the pre-#301 behaviour: sessions established before any tracked
    /// setup, and every existing single-RAN-node flow, must keep releasing on the first
    /// `MBS_DIS_REL_REQ`.
    pub fn session_ran_node_release(&self, tmgi: &Tmgi, ran_node_key: &str) -> ConsumerTerminate {
        let id = {
            match self.tmgi_hash.read() {
                Ok(h) => match h.get(tmgi) {
                    Some(&id) => id,
                    None => return ConsumerTerminate::NotFound,
                },
                Err(_) => return ConsumerTerminate::NotFound,
            }
        };
        let remaining = {
            let Ok(mut list) = self.session_list.write() else {
                return ConsumerTerminate::NotFound;
            };
            let Some(session) = list.get_mut(&id) else {
                return ConsumerTerminate::NotFound;
            };
            if !ran_node_key.is_empty() {
                session.ran_nodes.remove(ran_node_key);
            }
            transport_holders(session)
        };
        if !remaining.is_empty() {
            return ConsumerTerminate::ConsumerRemains { remaining };
        }
        if self.session_context_terminate(tmgi) {
            ConsumerTerminate::LastConsumer
        } else {
            ConsumerTerminate::NotFound
        }
    }

    /// ContextUpdate **Terminate** (SMF) / leave: resolve the MBS session by
    /// TMGI and release its N4mb multicast transport (drives the N4mb release
    /// path). Returns whether a session matched.
    ///
    /// Unconditional — it consults neither the consumer set (#295) nor the RAN-node set
    /// (#301). Both `session_context_terminate_for` and `session_ran_node_release` call
    /// it once they have decided nothing holds the transport, so this is the "mark it
    /// released" half rather than the decision.
    pub fn session_context_terminate(&self, tmgi: &Tmgi) -> bool {
        let id = {
            match self.tmgi_hash.read() {
                Ok(h) => match h.get(tmgi) {
                    Some(&id) => id,
                    None => return false,
                },
                Err(_) => return false,
            }
        };
        if let Ok(mut list) = self.session_list.write() {
            if let Some(session) = list.get_mut(&id) {
                // #76: this used to set ReleasePending and then IMMEDIATELY zero
                // `n4mb_session`, so the SEID needed to delete the session on the
                // MB-UPF was discarded before anything could send the deletion. The
                // context is now left in place for the caller to release on the
                // wire and clear afterwards (`session_clear_n4mb`).
                if let Some(n4mb) = session.n4mb_session.as_mut() {
                    n4mb.state = N4mbSessionState::ReleasePending;
                }
                session.state = MbsSessionState::Suspended;
                return true;
            }
        }
        false
    }

    /// Clear a session's N4mb context after its Session Deletion completed (#76).
    ///
    /// Separate from [`Self::session_context_terminate`] so the SEID survives long
    /// enough to be used. Returns whether a context was cleared, so a caller can
    /// tell "released and cleared" from "there was nothing to release".
    pub fn session_clear_n4mb(&self, id: u64) -> bool {
        if let Ok(mut list) = self.session_list.write() {
            if let Some(session) = list.get_mut(&id) {
                let had = session.n4mb_session.is_some();
                session.n4mb_session = None;
                return had;
            }
        }
        false
    }

    /// Apply a successful N4mb Session Establishment Response to the stored
    /// session, transitioning its N4mb context to `Established`. [mbsmfd-02]
    pub fn apply_n4mb_response(
        &self,
        session_id: u64,
        remote_seid: u64,
        dl_teid: u32,
        transport_addr: Ipv4Addr,
    ) -> bool {
        if let Ok(mut list) = self.session_list.write() {
            if let Some(session) = list.get_mut(&session_id) {
                if let Some(n4mb) = session.n4mb_session.as_mut() {
                    process_n4mb_establishment_response(n4mb, remote_seid, dl_teid, transport_addr);
                    return true;
                }
            }
        }
        false
    }
}

impl Default for MbSmfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global MB-SMF context (thread-safe singleton)
static GLOBAL_MBSMF_CONTEXT: std::sync::OnceLock<Arc<RwLock<MbSmfContext>>> =
    std::sync::OnceLock::new();

/// Get the global MB-SMF context
pub fn mbsmf_self() -> Arc<RwLock<MbSmfContext>> {
    GLOBAL_MBSMF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(MbSmfContext::new())))
        .clone()
}

/// Initialize the global MB-SMF context
pub fn mbsmf_context_init(max_sessions: usize) {
    let ctx = mbsmf_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_sessions);
    };
}

/// Finalize the global MB-SMF context
pub fn mbsmf_context_final() {
    let ctx = mbsmf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tmgi(id: u8) -> Tmgi {
        Tmgi {
            mbs_service_id: [id, 0x00, 0x00],
            plmn_id: PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            },
        }
    }

    /// #2015 fixture: an AMF context record of `n`, with `token`.
    fn cap_record_2015(n: usize, token: String) -> AmfMbsContext {
        AmfMbsContext {
            host: "127.0.0.1".to_string(),
            port: 9,
            nf_instance_id: None,
            context_ref: format!("cap-2015-{n}"),
            notify_token: token,
            tmgi: None,
        }
    }

    /// #2015 fixture: `n` contexts a released session left with their deletes
    /// pending (recorded, then taken by the release), refs `from..from + n`.
    fn pending_contexts_2015(ctx: &MbSmfContext, tmgi: u8, from: usize, n: usize) -> Vec<String> {
        let s = ctx
            .session_add(make_tmgi(tmgi), MbsSessionType::Broadcast)
            .expect("released");
        let tokens = (from..from + n)
            .map(|k| {
                let t = ctx.mint_amf_notify_token(s.id).expect("minted");
                assert!(ctx.record_amf_context(s.id, cap_record_2015(k, t.clone())));
                t
            })
            .collect();
        ctx.take_amf_contexts(s.id);
        ctx.session_remove(s.id);
        tokens
    }

    /// **#2015** (item 1): at [`MAX_AMF_NOTIFY_TOKENS`] a mint reclaims only the
    /// tokens of a context the AMF released (204, in its grace), never those of a
    /// context whose delete is pending -- the AMF still holds that context and a
    /// session handed it again is notified on them (#1985). With no released
    /// context the mint is refused, as before #1985, and the refusal applies
    /// nothing; a retried mint is refused the same way. Pending tokens do not
    /// count against the cap, so they never starve a live create. A private
    /// context, so the full map cannot starve another test's mint.
    ///
    /// REVERT-VERIFIED: with `make_room` reclaiming any context no live session
    /// holds (the #1985 rule), "refused rather than take a parked context's
    /// token" fails; with pending tokens counted against the cap, "a live create is not
    /// starved by parked tokens" fails.
    #[test]
    fn the_token_cap_never_reclaims_a_parked_contexts_token_2015() {
        let mut ctx = MbSmfContext::new();
        ctx.init(8);
        // 4096 contexts whose deletes are parked; the AMF then answers 204 for
        // context 0, so only its token is in a grace.
        let parked = pending_contexts_2015(&ctx, 0x51, 0, MAX_PENDING_NOTIFY_TOKENS);
        ctx.mark_amf_context_released(&cap_record_2015(0, parked[0].clone()));
        let live = ctx
            .session_add(make_tmgi(0x52), MbsSessionType::Broadcast)
            .expect("live");
        // Live tokens up to the cap (one released token counts too).
        for _ in 0..MAX_AMF_NOTIFY_TOKENS - 1 {
            assert!(
                ctx.mint_amf_notify_token(live.id).is_some(),
                "a live create is not starved by parked tokens"
            );
        }
        let full = ctx.amf_notify_token_count();
        // The cap: 4095 live + 1 released; 4095 more parked beside it.
        assert_eq!(full, MAX_AMF_NOTIFY_TOKENS + MAX_PENDING_NOTIFY_TOKENS - 1);

        assert!(
            ctx.mint_amf_notify_token(live.id).is_some(),
            "the released context's token makes room"
        );
        assert!(
            ctx.amf_notify_session(&parked[0]).is_none(),
            "the released context's token is reclaimed"
        );
        assert!(
            parked[1..]
                .iter()
                .all(|t| ctx.amf_notify_session(t).is_some()),
            "a parked context's token is never reclaimed"
        );

        // No released context left: refused, and nothing changes -- twice.
        for attempt in 0..2 {
            assert!(
                ctx.mint_amf_notify_token(live.id).is_none(),
                "refused rather than take a parked context's token ({attempt})"
            );
            assert_eq!(
                ctx.amf_notify_token_count(),
                full,
                "a refused mint applies nothing"
            );
            assert!(parked[1..]
                .iter()
                .all(|t| ctx.amf_notify_session(t).is_some()));
        }

        // Control: creates in flight are never reclaimed either.
        let inflight = MbSmfContext::new();
        for _ in 0..MAX_AMF_NOTIFY_TOKENS {
            inflight.mint_amf_notify_token(1).expect("minted");
        }
        assert!(
            inflight.mint_amf_notify_token(1).is_none(),
            "a create in flight keeps its token"
        );
    }

    /// **#2015** (item 1, the hard bound): pending tokens can outgrow the parked
    /// set (a context reused n times holds n tokens), so past
    /// [`MAX_PENDING_NOTIFY_TOKENS`] a mint forgets the oldest pending context's
    /// tokens rather than refuse a live create; the map never passes both caps.
    ///
    /// REVERT-VERIFIED: with the `Pending` forget removed from `make_room`, the
    /// map grows past "never more than both caps"; with the `held` arm removed
    /// from `token_class`, "a held context's token is kept" fails.
    #[test]
    fn past_the_pending_bound_a_mint_forgets_the_oldest_parked_context_2015() {
        let mut ctx = MbSmfContext::new();
        ctx.init(8);
        let a = pending_contexts_2015(&ctx, 0x53, 0, MAX_AMF_NOTIFY_TOKENS);
        let b = pending_contexts_2015(&ctx, 0x54, MAX_AMF_NOTIFY_TOKENS, MAX_AMF_NOTIFY_TOKENS);
        let live = ctx
            .session_add(make_tmgi(0x55), MbsSessionType::Broadcast)
            .expect("live");
        // The live session is handed the oldest parked context again: held.
        assert!(ctx.record_amf_context(live.id, cap_record_2015(0, a[0].clone())));
        assert!(
            ctx.mint_amf_notify_token(live.id).is_some(),
            "a live create is not starved by parked tokens"
        );
        assert_eq!(
            ctx.amf_notify_token_count(),
            MAX_AMF_NOTIFY_TOKENS + MAX_PENDING_NOTIFY_TOKENS,
            "never more than both caps"
        );
        assert_eq!(
            ctx.amf_notify_session(&a[0]),
            Some(live.id),
            "a held context's token is kept"
        );
        assert!(
            ctx.amf_notify_session(&a[1]).is_none(),
            "the oldest pending goes"
        );
        assert!(ctx.amf_notify_session(&a[2]).is_some(), "only that one");
        assert!(ctx.amf_notify_session(&b[0]).is_some());
    }

    /// **#2015** (item 2): the held snapshot and the reclaim are one critical
    /// section with `record_amf_context`. Session B's create was answered with
    /// the oldest pending context K and B records it exactly where a mint at the
    /// bound has decided what live sessions hold and is about to forget K (the
    /// `mint_seam`): the record cannot land there, it lands after the mint, and
    /// B keeps the token it was just handed. Deterministic: the seam records only
    /// if `amf_contexts` is free at that point.
    ///
    /// REVERT-VERIFIED: with `mint_amf_notify_token` dropping `amf_contexts` after
    /// the snapshot (the #1985 code), the record lands in the window, K's tokens
    /// -- B's own among them -- are forgotten, and "B keeps the token it was just
    /// handed" fails.
    #[test]
    fn a_record_racing_the_mint_keeps_its_token_2015() {
        let mut ctx = MbSmfContext::new();
        ctx.init(8);
        // One under both caps, from two released sessions (each held up to the cap).
        let parked = pending_contexts_2015(&ctx, 0x56, 0, MAX_AMF_NOTIFY_TOKENS);
        pending_contexts_2015(
            &ctx,
            0x59,
            MAX_AMF_NOTIFY_TOKENS,
            MAX_PENDING_NOTIFY_TOKENS - 1,
        );
        let b = ctx
            .session_add(make_tmgi(0x57), MbsSessionType::Broadcast)
            .expect("B");
        let tb = ctx.mint_amf_notify_token(b.id).expect("B's token");
        assert_eq!(
            ctx.amf_notify_token_count(),
            MAX_AMF_NOTIFY_TOKENS + MAX_PENDING_NOTIFY_TOKENS
        );
        let k = cap_record_2015(0, tb.clone());
        let landed = std::rc::Rc::new(std::cell::Cell::new(false));
        let (l, rec, bid) = (landed.clone(), k.clone(), b.id);
        mint_seam::set(move |ctx| {
            let free = ctx.amf_contexts.try_lock().is_ok();
            if free {
                assert!(ctx.record_amf_context(bid, rec));
                l.set(true);
            }
        });
        let c = ctx
            .session_add(make_tmgi(0x58), MbsSessionType::Broadcast)
            .expect("C");
        assert!(ctx.mint_amf_notify_token(c.id).is_some(), "C's token");
        if !landed.get() {
            assert!(ctx.record_amf_context(b.id, k));
        }
        assert_eq!(
            ctx.amf_notify_session(&tb),
            Some(b.id),
            "B keeps the token it was just handed"
        );
        assert!(
            ctx.amf_notify_session(&parked[0]).is_none(),
            "K was pending at the mint, so its old token went"
        );
    }

    /// **#1985**: a `releasedInd` for a context whose delete is parked (no session
    /// records it any more) forgets EVERY token of that context, not only the one
    /// it arrived on: the AMF released it, so none will be notified again.
    ///
    /// REVERT-VERIFIED: with the context-wide retain removed from
    /// `drop_amf_context_by_token`, "the context's other token goes too" fails.
    #[test]
    fn a_released_ind_for_a_parked_context_forgets_all_its_tokens_1985() {
        let mut ctx = MbSmfContext::new();
        ctx.init(8);
        let record = |token: String| AmfMbsContext {
            host: "127.0.0.1".to_string(),
            port: 9,
            nf_instance_id: None,
            context_ref: "released-1985".to_string(),
            notify_token: token,
            tmgi: None,
        };
        // A and then B held the context; both released, the delete parked.
        let a = ctx
            .session_add(make_tmgi(0x53), MbsSessionType::Broadcast)
            .expect("A");
        let ta = ctx.mint_amf_notify_token(a.id).expect("A's token");
        assert!(ctx.record_amf_context(a.id, record(ta.clone())));
        ctx.take_amf_contexts(a.id);
        ctx.session_remove(a.id);
        let b = ctx
            .session_add(make_tmgi(0x53), MbsSessionType::Broadcast)
            .expect("B");
        let tb = ctx.mint_amf_notify_token(b.id).expect("B's token");
        assert!(ctx.record_amf_context(b.id, record(tb.clone())));
        ctx.take_amf_contexts(b.id);
        ctx.session_remove(b.id);
        assert_eq!(ctx.amf_notify_session(&ta), Some(b.id), "parked: kept");

        assert!(!ctx.drop_amf_context_by_token(&ta), "no record to drop");
        assert!(ctx.amf_notify_session(&ta).is_none());
        assert!(
            ctx.amf_notify_session(&tb).is_none(),
            "the context's other token goes too"
        );
    }

    #[test]
    fn test_mbsmf_context_new() {
        let ctx = MbSmfContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.session_count(), 0);
    }

    /// #301: the RAN-node key is canonical, so a setup and a release for the same node
    /// match even when the AMF renders the JSON differently.
    ///
    /// This is the decision the issue asks to make deliberately ("the whole decoded
    /// structure, or a canonical string"), and the reason it matters is `ssm`'s: a key
    /// that does not agree with what was stored silently fails to match, and the symptom
    /// is a release that releases nothing while answering 204.
    #[test]
    fn the_ran_node_key_is_stable_across_member_order_and_hex_case() {
        let a: serde_json::Value = serde_json::from_str(
            r#"{"plmnId":{"mcc":"208","mnc":"93"},"gNbId":{"bitLength":24,"gNBValue":"00abcd"}}"#,
        )
        .unwrap();
        // Same node: members in the other order, hex in the other case.
        let b: serde_json::Value = serde_json::from_str(
            r#"{"gNbId":{"gNBValue":"00ABCD","bitLength":24},"plmnId":{"mnc":"93","mcc":"208"}}"#,
        )
        .unwrap();
        assert_eq!(
            canonical_ran_node_key(&a),
            canonical_ran_node_key(&b),
            "one RAN node must produce one key, or its release matches nothing"
        );

        // A different gNB is a different key.
        let c: serde_json::Value = serde_json::from_str(
            r#"{"plmnId":{"mcc":"208","mnc":"93"},"gNbId":{"bitLength":24,"gNBValue":"00abce"}}"#,
        )
        .unwrap();
        assert_ne!(canonical_ran_node_key(&a), canonical_ran_node_key(&c));

        // Same gNB value in a different PLMN is a different node (TS 38.413 §9.3.1.5:
        // a gNB id is only unique within its PLMN).
        let d: serde_json::Value = serde_json::from_str(
            r#"{"plmnId":{"mcc":"001","mnc":"01"},"gNbId":{"bitLength":24,"gNBValue":"00abcd"}}"#,
        )
        .unwrap();
        assert_ne!(canonical_ran_node_key(&a), canonical_ran_node_key(&d));

        // A different bitLength is a different node, not the same one truncated.
        let e: serde_json::Value = serde_json::from_str(
            r#"{"plmnId":{"mcc":"208","mnc":"93"},"gNbId":{"bitLength":22,"gNBValue":"00abcd"}}"#,
        )
        .unwrap();
        assert_ne!(canonical_ran_node_key(&a), canonical_ran_node_key(&e));

        // The other choice members key on their own name, so an ng-eNB and an N3IWF
        // with the same textual id are not the same holder.
        let ngenb: serde_json::Value =
            serde_json::from_str(r#"{"plmnId":{"mcc":"208","mnc":"93"},"ngeNbId":"macroNgeNB-1"}"#)
                .unwrap();
        let n3iwf: serde_json::Value =
            serde_json::from_str(r#"{"plmnId":{"mcc":"208","mnc":"93"},"n3IwfId":"macroNgeNB-1"}"#)
                .unwrap();
        assert_ne!(
            canonical_ran_node_key(&ngenb),
            canonical_ran_node_key(&n3iwf)
        );

        // An unrecognised shape still keys consistently with ITSELF rather than being
        // dropped: it only has to match its own release.
        let odd: serde_json::Value =
            serde_json::from_str(r#"{"plmnId":{"mcc":"208","mnc":"93"},"someFutureId":"x"}"#)
                .unwrap();
        let odd_reordered: serde_json::Value =
            serde_json::from_str(r#"{"someFutureId":"x","plmnId":{"mnc":"93","mcc":"208"}}"#)
                .unwrap();
        assert_eq!(
            canonical_ran_node_key(&odd),
            canonical_ran_node_key(&odd_reordered)
        );

        // Not an object: untracked rather than keyed on nonsense.
        assert_eq!(canonical_ran_node_key(&serde_json::json!("gnb-1")), None);
    }

    #[test]
    fn test_mbsmf_context_init_fini() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        assert!(ctx.is_initialized());

        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_session_add_remove() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);

        let tmgi = Tmgi {
            mbs_service_id: [0x01, 0x02, 0x03],
            plmn_id: PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            },
        };

        let session = ctx
            .session_add(tmgi.clone(), MbsSessionType::Multicast)
            .unwrap();
        assert_eq!(session.session_type, MbsSessionType::Multicast);
        assert_eq!(session.state, MbsSessionState::Created);
        assert_ne!(session.gtp_teid, 0); // TEID should be allocated
        assert_eq!(ctx.session_count(), 1);

        let found = ctx.session_find_by_tmgi(&tmgi);
        assert!(found.is_some());

        ctx.session_remove(session.id);
        assert_eq!(ctx.session_count(), 0);
    }

    #[test]
    fn test_session_update_state() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);

        let tmgi = Tmgi {
            mbs_service_id: [0x0A, 0x0B, 0x0C],
            plmn_id: PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            },
        };

        let mut session = ctx.session_add(tmgi, MbsSessionType::Broadcast).unwrap();
        session.state = MbsSessionState::Active;
        session.joined_ue_count = 5;
        ctx.session_update(&session);

        let found = ctx.session_find_by_id(session.id).unwrap();
        assert_eq!(found.state, MbsSessionState::Active);
        assert_eq!(found.joined_ue_count, 5);
    }

    #[test]
    fn test_active_multicast_sessions() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);

        let mut s1 = ctx
            .session_add(make_tmgi(0x01), MbsSessionType::Multicast)
            .unwrap();
        s1.state = MbsSessionState::Active;
        ctx.session_update(&s1);

        let s2 = ctx
            .session_add(make_tmgi(0x02), MbsSessionType::Broadcast)
            .unwrap();

        let active = ctx.active_multicast_sessions();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, s1.id);
        let _ = s2;
    }

    #[test]
    fn test_n4mb_session_activation() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);

        let session = ctx
            .session_add(make_tmgi(0x10), MbsSessionType::Multicast)
            .unwrap();
        assert!(session.n4mb_session.is_none());

        let activated = ctx
            .session_activate_n4mb(session.id, Ipv4Addr::new(10, 0, 0, 7))
            .unwrap();
        assert_eq!(activated.state, MbsSessionState::Active);
        let n4mb = activated.n4mb_session.unwrap();
        assert_eq!(n4mb.upf_addr, Ipv4Addr::new(10, 0, 0, 7));
        assert_eq!(n4mb.state, N4mbSessionState::EstablishmentPending);
        assert_ne!(n4mb.mcast_pdr_id, 0);
        assert_ne!(n4mb.mcast_far_id, 0);
    }

    #[test]
    fn test_n4mb_establishment_response() {
        let session = MbsSession::new(1, make_tmgi(0x20), MbsSessionType::Multicast);
        let mut n4mb = N4mbSession::new(0x100, Ipv4Addr::new(10, 0, 0, 7));
        assert_eq!(n4mb.state, N4mbSessionState::Idle);

        process_n4mb_establishment_response(
            &mut n4mb,
            0x200,
            0xABCD_0001,
            Ipv4Addr::new(10, 0, 0, 7),
        );

        assert_eq!(n4mb.state, N4mbSessionState::Established);
        assert_eq!(n4mb.remote_seid, 0x200);
        assert_eq!(n4mb.dl_teid, 0xABCD_0001);
        assert_eq!(n4mb.transport_addr, Some(Ipv4Addr::new(10, 0, 0, 7)));
        let _ = session;
    }

    #[test]
    fn test_group_membership_join_leave() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);

        let session = ctx
            .session_add(make_tmgi(0x30), MbsSessionType::Multicast)
            .unwrap();

        // Join
        assert!(ctx.session_member_join(session.id, "imsi-001010000000001"));
        assert!(ctx.session_member_join(session.id, "imsi-001010000000002"));
        // Duplicate join returns false
        assert!(!ctx.session_member_join(session.id, "imsi-001010000000001"));

        let s = ctx.session_find_by_id(session.id).unwrap();
        assert_eq!(s.joined_ue_count, 2);
        assert!(s.is_member("imsi-001010000000001"));

        // Leave
        assert!(ctx.session_member_leave(session.id, "imsi-001010000000001"));
        let s = ctx.session_find_by_id(session.id).unwrap();
        assert_eq!(s.joined_ue_count, 1);
        assert!(!s.is_member("imsi-001010000000001"));

        // Leave non-member returns false
        assert!(!ctx.session_member_leave(session.id, "imsi-001010000000099"));
    }

    #[test]
    fn test_all_sessions() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);

        ctx.session_add(make_tmgi(0x01), MbsSessionType::Multicast);
        ctx.session_add(make_tmgi(0x02), MbsSessionType::Broadcast);

        let all = ctx.all_sessions();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_teid_allocation_unique() {
        let ctx = MbSmfContext::new();
        let t1 = ctx.alloc_mcast_teid();
        let t2 = ctx.alloc_mcast_teid();
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_n4mb_seid_allocation_unique() {
        let ctx = MbSmfContext::new();
        let s1 = ctx.alloc_n4mb_seid();
        let s2 = ctx.alloc_n4mb_seid();
        assert_ne!(s1, s2);
    }

    // ---- mbsmfd-04: TMGI pool ----

    fn plmn() -> PlmnId {
        PlmnId {
            mcc: "001".to_string(),
            mnc: "01".to_string(),
        }
    }

    #[test]
    fn test_tmgi_allocate_distinct_and_expiry() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let (tmgis, expiry) = ctx.tmgi_allocate(&plmn(), 3, TMGI_DEFAULT_TTL_SECS);
        assert_eq!(tmgis.len(), 3);
        // All three are distinct service ids.
        let mut ids: Vec<[u8; 3]> = tmgis.iter().map(|t| t.mbs_service_id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 3);
        assert!(expiry > now_unix());
        assert_eq!(ctx.tmgi_count(), 3);
    }

    #[test]
    fn test_tmgi_refresh_extends_expiry() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let (tmgis, first) = ctx.tmgi_allocate(&plmn(), 1, 1);
        let before = ctx.tmgi_expiry_of(&tmgis[0]).unwrap();
        assert_eq!(before, first);
        // Refresh with a longer TTL extends the recorded expiry.
        let extended = ctx
            .tmgi_refresh(&tmgis, TMGI_DEFAULT_TTL_SECS, |_| true)
            .unwrap();
        assert!(extended >= before);
        assert_eq!(ctx.tmgi_expiry_of(&tmgis[0]), Some(extended));
        assert_eq!(ctx.tmgi_count(), 1);
    }

    #[test]
    fn test_tmgi_deallocate_one_and_all() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let (tmgis, _) = ctx.tmgi_allocate(&plmn(), 3, TMGI_DEFAULT_TTL_SECS);
        // Deallocate exactly one leaves the rest.
        assert_eq!(
            ctx.tmgi_deallocate(std::slice::from_ref(&tmgis[0]), |_| true),
            Ok(1)
        );
        assert_eq!(ctx.tmgi_count(), 2);
        // The rest, by name (#1863: there is no deallocate-all any more).
        assert_eq!(ctx.tmgi_deallocate(&tmgis[1..], |_| true), Ok(2));
        assert_eq!(ctx.tmgi_count(), 0);
    }

    /// #1863: a TMGI is refreshed or deallocated only by the consumer it was
    /// allocated to, all-or-nothing; a refresh no longer claims an unknown
    /// TMGI; and the counter never re-issues a TMGI that is still allocated.
    /// REVERT-VERIFIED: with the `may_manage` filter removed from `deallocate`
    /// B frees A's TMGI; with the `!allocated.contains_key` arm removed from
    /// `refresh` the unknown TMGI is inserted; with the `contains_key` skip
    /// removed from `allocate_owned` the wrapped counter re-issues A's TMGI.
    #[test]
    fn a_tmgi_is_managed_by_the_consumer_it_was_allocated_to_1863() {
        let mut pool = TmgiPool::new();
        let (a, b) = (
            "aaaaaaaa-1863-4000-8000-0000000000a1",
            "bbbbbbbb-1863-4000-8000-0000000000b2",
        );
        let is = |who: &'static str| move |o: Option<&str>| o == Some(who);
        let (mine, _) = pool.allocate_owned(&plmn(), 2, 60, 0, Some(a), |_| false);
        let (theirs, _) = pool.allocate_owned(&plmn(), 1, 60, 0, Some(b), |_| false);
        assert_eq!(pool.owner_of(&mine[0]), Some(a));
        // B lists one of A's beside its own: refused, nothing freed.
        let mixed = vec![theirs[0].clone(), mine[0].clone()];
        assert_eq!(
            pool.deallocate(&mixed, is(b)),
            Err(TmgiRefusal::NotOwned(mine[0].clone()))
        );
        assert_eq!(pool.len(), 3, "a refused deallocate frees nothing");
        assert_eq!(
            pool.refresh(&mine, 600, 0, is(b)),
            Err(TmgiRefusal::NotOwned(mine[0].clone()))
        );
        assert_eq!(pool.expiry_of(&mine[0]), Some(60), "nor refreshes anything");
        // An unknown TMGI is not claimable by refresh.
        let unknown = Tmgi {
            mbs_service_id: [0xEE, 0xEE, 0xEE],
            plmn_id: plmn(),
        };
        assert!(pool
            .refresh(std::slice::from_ref(&unknown), 600, 0, |_| true)
            .is_err());
        assert!(!pool.is_allocated(&unknown));
        // The owner may; an already-gone TMGI is skipped.
        assert_eq!(pool.refresh(&mine, 600, 0, is(a)), Ok(600));
        assert_eq!(pool.deallocate(&[mine[0].clone(), unknown], is(a)), Ok(1));
        // A wrapped counter skips a TMGI still allocated.
        pool.next_id.insert(plmn(), service_id(&mine[1]));
        let (fresh, _) = pool.allocate_owned(&plmn(), 1, 60, 0, Some(b), |_| false);
        assert_ne!(
            fresh[0], mine[1],
            "an allocated TMGI is never handed out twice"
        );
        assert_eq!(pool.owner_of(&mine[1]), Some(a));
    }

    /// #1863 (R32 on #1943 M1): a restarted pool does not start again at
    /// 000001, so it does not hand another consumer the TMGIs the previous
    /// process allocated. Seeds are random: two lifetimes collide with odds
    /// about 2^-24 for one TMGI each.
    /// REVERT-VERIFIED: with the counter seeded at 1 again both lifetimes
    /// return 000001 and the first assertion fails.
    #[test]
    fn a_restarted_pool_does_not_reissue_the_previous_tmgis_1863() {
        let (a, b) = (
            "aaaaaaaa-1863-4000-8000-0000000000a1",
            "bbbbbbbb-1863-4000-8000-0000000000b2",
        );
        let before = TmgiPool::new()
            .allocate_owned(&plmn(), 1, 60, 0, Some(a), |_| false)
            .0;
        let after = TmgiPool::new()
            .allocate_owned(&plmn(), 1, 60, 0, Some(b), |_| false)
            .0;
        assert_ne!(before, after, "a restart re-issued a live TMGI");
        assert_ne!(before[0].mbs_service_id, [0, 0, 1]);
    }

    /// #1863 (R32 on #1943): a session created on a TMGI this MB-SMF never
    /// allocated (or one that expired) claims it for its creator, so a later
    /// Allocate cannot hand it out; and Allocate skips a TMGI a live session
    /// names even when the pool no longer holds it.
    /// REVERT-VERIFIED: with `claim` not inserting, the pool owner assertion
    /// fails; with the `in_use` skip removed, the wrapped allocation returns
    /// the session's TMGI.
    #[test]
    fn a_session_claims_its_tmgi_and_allocate_skips_live_sessions_1863() {
        let a = "aaaaaaaa-1863-4000-8000-0000000000a1";
        let mut ctx = MbSmfContext::new();
        ctx.init(8);
        let tmgi = Tmgi {
            mbs_service_id: [0x12, 0x34, 0x56],
            plmn_id: plmn(),
        };
        ctx.session_add_claiming(
            tmgi.clone(),
            MbsSessionType::Broadcast,
            Some(a.into()),
            |_| true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(ctx.tmgi_allocation(&tmgi), Some(Some(a.to_string())));
        // Another consumer cannot open a session on it either.
        let other = Tmgi {
            mbs_service_id: [0x12, 0x34, 0x57],
            plmn_id: plmn(),
        };
        ctx.session_add_claiming(
            other.clone(),
            MbsSessionType::Broadcast,
            Some(a.into()),
            |_| true,
        )
        .unwrap()
        .unwrap();
        assert!(ctx
            .session_add_claiming(
                Tmgi {
                    mbs_service_id: [0x12, 0x34, 0x56],
                    plmn_id: plmn()
                },
                MbsSessionType::Broadcast,
                Some("b".into()),
                |o| o == Some("b"),
            )
            .map(|s| s.is_none())
            .unwrap_or(true));
        // The pool forgets the TMGI (expired), but the session still names it.
        ctx.tmgi_pool
            .lock()
            .unwrap()
            .deallocate(std::slice::from_ref(&tmgi), |_| true)
            .unwrap();
        ctx.tmgi_pool
            .lock()
            .unwrap()
            .next_id
            .insert(plmn(), service_id(&tmgi));
        let (fresh, _) = ctx.tmgi_allocate_owned(&plmn(), 1, 60, Some("b"));
        assert_ne!(fresh[0], tmgi, "a live session's TMGI is never allocated");
        assert_ne!(fresh[0], other);
    }

    fn service_id(t: &Tmgi) -> u32 {
        (t.mbs_service_id[0] as u32) << 16
            | (t.mbs_service_id[1] as u32) << 8
            | t.mbs_service_id[2] as u32
    }

    /// #1863: session IDs do not restart at 1, so a restart cannot hand a
    /// consumer's stale `mbs-sess-N` to another consumer's session.
    /// REVERT-VERIFIED: with `next_session_id` seeded at 1 the two lifetimes mint
    /// the same ID.
    #[test]
    fn session_ids_are_unique_across_a_restart_1863() {
        let mint = || {
            let mut ctx = MbSmfContext::new();
            ctx.init(8);
            ctx.session_add(
                Tmgi {
                    mbs_service_id: [0, 0, 7],
                    plmn_id: plmn(),
                },
                MbsSessionType::Broadcast,
            )
            .unwrap()
            .id
        };
        let before = mint();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let after = mint();
        assert_ne!(before, 1);
        assert!(before < after, "{before} then {after}");
    }

    // ---- mbsmfd-03: ContextUpdate Start / Terminate ----

    #[test]
    fn test_context_start_allocates_cteid_and_llssm() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let tmgi = make_tmgi(0x42);
        let created = ctx
            .session_add(tmgi.clone(), MbsSessionType::Multicast)
            .unwrap();

        let upf = Ipv4Addr::new(10, 0, 0, 7);
        let started = ctx.session_context_start(&tmgi, upf).expect("started");
        assert_eq!(started.id, created.id);
        assert_eq!(started.state, MbsSessionState::Active);
        let n4mb = started.n4mb_session.expect("n4mb allocated");
        assert_eq!(n4mb.state, N4mbSessionState::EstablishmentPending);
        // cTeid is the allocated DL multicast TEID; llSsm carries src+dst.
        assert_ne!(n4mb.dl_teid, 0);
        assert_eq!(n4mb.ll_ssm_src, Some(upf));
        assert_eq!(n4mb.ll_ssm_dst, Some(mcast_group_for(created.id)));
    }

    #[test]
    fn test_context_start_unknown_tmgi_is_none() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        assert!(ctx
            .session_context_start(&make_tmgi(0x99), Ipv4Addr::new(10, 0, 0, 7))
            .is_none());
    }

    /// **Assertion inverted by #76, and why.** This used to assert that
    /// `session_context_terminate` leaves `n4mb_session` as `None`. That was pinning
    /// the defect as the requirement: zeroing the context discards the remote SEID a
    /// PFCP Session Deletion Request has to be addressed to, so nothing could delete
    /// the session on the MB-UPF even in principle, and every terminate leaked one.
    ///
    /// The governing clause is not a "may": TS 29.244 §7.5.4 has the CP function
    /// **send** a Session Deletion Request to release a PFCP session, and TS 23.247
    /// §7.1.1.4 has releasing an MBS session tear down the associated MB-UPF
    /// resources. So the old assertion was asserting a shortcut past a mandatory
    /// message, and inverting it is legitimate.
    ///
    /// Terminate now marks the context `ReleasePending` and LEAVES it; the wire
    /// release plus the clear is `release_n4mb_transport` in `main.rs`, and the two
    /// handler-level tests that assert the post-handler state
    /// (`test_router_context_update_amf_release_golden_204`,
    /// `mbs_context_update_strict_peer_release_204`) still pass unchanged — which is
    /// what shows the observable behaviour of the SERVICE is preserved and only this
    /// function's own contract narrowed.
    #[test]
    fn test_context_terminate_marks_release_pending_without_discarding_the_seid() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let tmgi = make_tmgi(0x43);
        let created = ctx
            .session_add(tmgi.clone(), MbsSessionType::Multicast)
            .unwrap();
        ctx.session_context_start(&tmgi, Ipv4Addr::new(10, 0, 0, 7))
            .unwrap();
        // Pretend the UP answered, so there is a remote SEID to delete.
        assert!(ctx.apply_n4mb_response(
            created.id,
            0xdead_beef,
            0x1234,
            Ipv4Addr::new(10, 0, 0, 7)
        ));

        assert!(ctx.session_context_terminate(&tmgi));
        let after = ctx.session_find_by_id(created.id).unwrap();
        let n4mb = after.n4mb_session.as_ref().expect(
            "the N4mb context must SURVIVE terminate: its remote SEID is what the \
                     Session Deletion Request is addressed to",
        );
        assert_eq!(n4mb.state, N4mbSessionState::ReleasePending);
        assert_eq!(n4mb.remote_seid, 0xdead_beef);
        assert_eq!(after.state, MbsSessionState::Suspended);

        // The two-step is what the release driver uses: mark, then delete, then clear.
        assert_eq!(
            ctx.session_mark_release_pending(created.id),
            Some(0xdead_beef),
            "the remote SEID must be recoverable for the deletion request"
        );
        assert!(ctx.session_clear_n4mb(created.id));
        assert!(ctx
            .session_find_by_id(created.id)
            .unwrap()
            .n4mb_session
            .is_none());
        assert!(
            !ctx.session_clear_n4mb(created.id),
            "clearing twice must report that there was nothing left to clear"
        );

        // Terminating an unknown TMGI is a no-op.
        assert!(!ctx.session_context_terminate(&make_tmgi(0x77)));
    }

    /// #76 criterion 5: a repeated START must not allocate a second N4mb session.
    ///
    /// N repeated joins used to create N PFCP sessions on the MB-UPF and orphan
    /// every previous one, contrary to the shared-distribution-session model of TS
    /// 23.247 §7.2.1.3/§7.2.1.4. An `EstablishmentPending` session is deliberately
    /// NOT short-circuited: its establishment may have failed, and re-driving it is
    /// how a retry works.
    #[test]
    fn a_repeated_start_reuses_an_established_n4mb_session() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let tmgi = make_tmgi(0x51);
        let created = ctx
            .session_add(tmgi.clone(), MbsSessionType::Multicast)
            .unwrap();
        let upf = Ipv4Addr::new(10, 0, 0, 7);

        let first = ctx.session_context_start(&tmgi, upf).unwrap();
        let first_seid = first.n4mb_session.as_ref().unwrap().local_seid;
        // Not yet established: a second START re-drives it, which is the retry path.
        let retry = ctx.session_context_start(&tmgi, upf).unwrap();
        assert_ne!(
            retry.n4mb_session.as_ref().unwrap().local_seid,
            first_seid,
            "an establishment that never completed must be re-drivable"
        );
        let retry_seid = retry.n4mb_session.as_ref().unwrap().local_seid;

        // Now the UP confirms it. Every later START must reuse this one.
        assert!(ctx.apply_n4mb_response(created.id, 0x99, 0x1234, upf));
        for _ in 0..3 {
            let again = ctx.session_context_start(&tmgi, upf).unwrap();
            let n4mb = again.n4mb_session.as_ref().unwrap();
            assert_eq!(
                n4mb.local_seid, retry_seid,
                "a repeated START must not allocate a new SEID for an established session"
            );
            assert_eq!(n4mb.remote_seid, 0x99, "nor discard the UP-allocated one");
            assert_eq!(n4mb.state, N4mbSessionState::Established);
        }
    }

    /// #76 criterion 7: a second create for a TMGI already in use is refused rather
    /// than silently orphaning the first session.
    ///
    /// The overwrite used to leave the earlier session in `session_list` reachable
    /// by NOTHING — its TMGI resolved to the new session, so it could never be found
    /// or deleted, and its MB-UPF session could never be released.
    #[test]
    fn a_duplicate_tmgi_create_is_refused_and_the_first_session_survives() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let tmgi = make_tmgi(0x61);
        let first = ctx
            .session_add(tmgi.clone(), MbsSessionType::Multicast)
            .expect("the first create succeeds");
        assert!(
            ctx.session_add(tmgi.clone(), MbsSessionType::Multicast)
                .is_none(),
            "a TMGI identifies one MBS session; a second create for it must be refused"
        );
        assert_eq!(
            ctx.session_find_by_tmgi(&tmgi).map(|s| s.id),
            Some(first.id),
            "the TMGI must still resolve to the FIRST session"
        );
        assert_eq!(ctx.session_count(), 1, "and no orphan is left behind");
    }

    #[test]
    fn test_apply_n4mb_response_marks_established() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);
        let tmgi = make_tmgi(0x44);
        let created = ctx
            .session_add(tmgi.clone(), MbsSessionType::Multicast)
            .unwrap();
        ctx.session_context_start(&tmgi, Ipv4Addr::new(10, 0, 0, 7))
            .unwrap();

        assert!(ctx.apply_n4mb_response(
            created.id,
            0x9999,
            0xABCD_0001,
            Ipv4Addr::new(10, 0, 0, 7)
        ));
        let n4mb = ctx
            .session_find_by_id(created.id)
            .unwrap()
            .n4mb_session
            .unwrap();
        assert_eq!(n4mb.state, N4mbSessionState::Established);
        assert_eq!(n4mb.remote_seid, 0x9999);
    }

    #[test]
    fn test_unix_to_rfc3339_known_epoch() {
        // 1970-01-01T00:00:00Z and a known later instant.
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
        // 2021-01-01T00:00:00Z == 1609459200.
        assert_eq!(unix_to_rfc3339(1_609_459_200), "2021-01-01T00:00:00Z");
    }
}
