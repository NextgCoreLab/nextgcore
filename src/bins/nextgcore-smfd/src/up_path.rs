//! User plane path failure and recovery reported on N4 (#994).
//!
//! TS 29.244 §5.10A: "Upon detection of user plane path failure or recovery, the UP
//! function shall initiate PFCP Node Report procedure, towards the CP function
//! controlling the affected PFCP sessions, to send a User Plane Path Failure Report or
//! a User Plane Path Recovery Report including the IP address of the remote GTP-U peer
//! towards which a user plane path failure or recovery has been detected." It goes on:
//! "For 5GC, upon receipt of a User Plane Path Failure Report or a User Plane Path
//! Recovery Report, the SMF shall proceed as specified in clauses 5.4 of TS 23.527",
//! and for EPC as in TS 23.007 §20.3.
//!
//! TS 23.007 §20.3.1 leaves two choices: "delete the bearer contexts associated with
//! the path in failure; or - maintain the bearer contexts associated with the path in
//! failure during an operator configurable maximum path failure duration. The network
//! node shall delete the maintained resources if the path is still down when this
//! duration expires." This SMF maintains them for [`hold_duration`]:
//!
//! - **At once**, for each session with a FAR toward the failed peer: the CN-initiated
//!   deactivation of its UP connection (TS 23.502 §4.3.7, steps 4 and 5). The FARs
//!   toward the peer go to BUFF|NOCP, so downlink data is buffered and reported, and
//!   the UE is paged instead of the data being sent into the failed path. For an N3
//!   FAR, the NG-RAN is told to release the session's resources through the AMF, whose
//!   path is not the failed one. Step 4 also removes the AN Tunnel Info; this SMF
//!   keeps the Outer Header Creation on the buffering FAR instead (#1028 review m6).
//!   It sends nothing while BUFF is set, the next activation replaces it, and it is
//!   how the hold below tells "still points at the failed peer" from "moved".
//! - **After the hold**, a session whose tunnel still points at the peer, i.e. no
//!   Service Request has moved it, is released: PFCP deletion, then a PDU Session
//!   Release with #39 so the UE re-establishes it; an EPC PDN connection is deleted at
//!   the PGW-U and toward the SGW.
//! - **On recovery**, the failed state is cleared, which voids the pending hold.
//!
//! Which sessions use which peer is learnt from this SMF's own accepted Session
//! Establishment and Modification Requests ([`note_session_request`]), per FAR, and
//! kept in `SmfContext::far_peers`, which the durable snapshot carries.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use crate::context::{smf_self, FarPeer};
use crate::n4_build::{apply_action, pfcp_ie};
use crate::pfcp_path::{find_ie, pfcp_message_type};
use crate::restoration::SessionScope;

/// Remote GTP-U peers reported failed (`smf_up_path_failures_total`).
pub static UP_PATH_FAILURES: AtomicU64 = AtomicU64::new(0);
/// Remote GTP-U peers reported recovered (`smf_up_path_recoveries_total`).
pub static UP_PATH_RECOVERIES: AtomicU64 = AtomicU64::new(0);
/// Sessions whose UP connection was deactivated toward a failed or restarted peer
/// (`smf_up_path_sessions_deactivated_total`).
pub static UP_PATH_SESSIONS_DEACTIVATED: AtomicU64 = AtomicU64::new(0);
/// Sessions released because their path was still down after the hold
/// (`smf_up_path_sessions_released_total`).
pub static UP_PATH_SESSIONS_RELEASED: AtomicU64 = AtomicU64::new(0);

/// Node Report Type (TS 29.244 §8.2.69), octet 5.
mod node_report_type {
    pub const UPFR: u8 = 0x01;
    pub const UPRR: u8 = 0x02;
    pub const PURR: u8 = 0x10;
}

/// IE types of the Node Report Request (TS 29.244 Table 7.4.5.1.1-1, §8.1.2).
mod ie {
    pub const NODE_ID: u16 = 60;
    pub const NODE_REPORT_TYPE: u16 = 101;
    pub const USER_PLANE_PATH_FAILURE_REPORT: u16 = 102;
    pub const REMOTE_GTP_U_PEER: u16 = 103;
    pub const USER_PLANE_PATH_RECOVERY_REPORT: u16 = 187;
    pub const PEER_UP_RESTART_REPORT: u16 = 315;
    pub const CAUSE: u16 = 19;
    pub const OFFENDING_IE: u16 = 40;
}

/// PFCP causes this module answers with (TS 29.244 §8.2.1).
pub mod cause {
    pub const REQUEST_ACCEPTED: u8 = 1;
    pub const MANDATORY_IE_MISSING: u8 = 66;
    pub const CONDITIONAL_IE_MISSING: u8 = 67;
    pub const MANDATORY_IE_INCORRECT: u8 = 69;
    pub const NO_ESTABLISHED_PFCP_ASSOCIATION: u8 = 72;
}

// ============================================================================
// Which sessions use which GTP-U peer
// ============================================================================

/// Learn the GTP-U peers of the session with SMF-side SEID `smf_seid` from one of
/// this SMF's own session requests and the UPF's answer (#994).
///
/// An accepted Establishment or Modification applies its Create, Update and Remove
/// FAR IEs; an accepted Deletion, or any answer that the session does not exist
/// (cause 65), forgets the session.
pub fn note_session_request(smf_seid: u64, msg_type: u8, request: &[u8], response: &[u8]) {
    let handle = smf_self();
    let Ok(ctx) = handle.read() else {
        return;
    };
    ctx.note_far_edits(smf_seid, msg_type, request, response);
}

/// Forget the GTP-U peers of these sessions (a teardown that flushed them).
pub fn forget_sessions(seids: impl IntoIterator<Item = u64>) {
    let handle = smf_self();
    let Ok(ctx) = handle.read() else { return };
    if let Ok(mut map) = ctx.far_peers.write() {
        for seid in seids {
            map.remove(&seid);
        }
    };
}

/// Apply the FAR IEs of a session request body to `fars`.
pub fn apply_far_edits(fars: &mut BTreeMap<u32, FarPeer>, body: &[u8]) {
    for (t, v) in ies(body) {
        match t {
            pfcp_ie::CREATE_FAR => {
                let Some(id) = far_id(v) else { continue };
                let action = find_ie(v, pfcp_ie::APPLY_ACTION)
                    .map(crate::n4_build::decode_apply_action)
                    .unwrap_or(0);
                let fp = find_ie(v, pfcp_ie::FORWARDING_PARAMETERS);
                match fp.and_then(|fp| peer_of(fp, None)) {
                    Some(((ip, ip6), access)) => {
                        fars.insert(
                            id,
                            FarPeer {
                                ip,
                                ip6,
                                access,
                                forwarding: action & apply_action::FORW != 0,
                            },
                        );
                    }
                    None => {
                        fars.remove(&id);
                    }
                }
            }
            pfcp_ie::UPDATE_FAR => {
                let Some(id) = far_id(v) else { continue };
                let known = fars.get(&id).copied();
                let peer = find_ie(v, pfcp_ie::UPDATE_FORWARDING_PARAMETERS)
                    .and_then(|ufp| peer_of(ufp, known.map(|k| k.access)))
                    .or(known.map(|k| ((k.ip, k.ip6), k.access)));
                let Some(((ip, ip6), access)) = peer else {
                    continue;
                };
                let forwarding = find_ie(v, pfcp_ie::APPLY_ACTION)
                    .map(|a| crate::n4_build::decode_apply_action(a) & apply_action::FORW != 0)
                    .or(known.map(|k| k.forwarding))
                    .unwrap_or(false);
                fars.insert(
                    id,
                    FarPeer {
                        ip,
                        ip6,
                        access,
                        forwarding,
                    },
                );
            }
            pfcp_ie::REMOVE_FAR => {
                if let Some(id) = far_id(v) {
                    fars.remove(&id);
                }
            }
            _ => {}
        }
    }
}

/// The (type, value) of each top-level IE of `body`.
fn ies(body: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 4 <= body.len() {
        let t = u16::from_be_bytes([body[off], body[off + 1]]);
        let l = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        let end = off + 4 + l;
        if end > body.len() {
            break;
        }
        out.push((t, &body[off + 4..end]));
        off = end;
    }
    out
}

fn far_id(far: &[u8]) -> Option<u32> {
    find_ie(far, pfcp_ie::FAR_ID)
        .filter(|v| v.len() >= 4)
        .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
}

/// The GTP-U peer of a (Update) Forwarding Parameters IE (its address, and a second
/// IPv6 one for a dual-stack header), and whether its Destination Interface is
/// Access (§8.2.24, value 0); `access_default` when the IE has none.
fn peer_of(fp: &[u8], access_default: Option<bool>) -> Option<((IpAddr, Option<IpAddr>), bool)> {
    let addrs = find_ie(fp, pfcp_ie::OUTER_HEADER_CREATION).and_then(outer_header_ips)?;
    let access = find_ie(fp, pfcp_ie::DESTINATION_INTERFACE)
        .and_then(|v| v.first())
        .map(|di| di & 0x0f == 0)
        .or(access_default)
        .unwrap_or(false);
    Some((addrs, access))
}

/// The addresses of an Outer Header Creation IE (TS 29.244 §8.2.56): octets 5-6 are
/// the description, then a TEID when it is GTP-U (octet 5 bit 1 or 2), then IPv4
/// (bit 1, 3 or 5) and IPv6 (bit 2, 4 or 6), in that order. The first is returned,
/// and the IPv6 one second when both are present (#1028 review m4: a dual-stack
/// gNB's failure may name either).
pub fn outer_header_ips(v: &[u8]) -> Option<(IpAddr, Option<IpAddr>)> {
    let desc = *v.first()?;
    let gtpu = desc & 0x03 != 0;
    let has_v4 = desc & 0x15 != 0;
    let has_v6 = desc & 0x2a != 0;
    let mut off = 2 + if gtpu { 4 } else { 0 };
    let v4 = if has_v4 {
        let a: [u8; 4] = v.get(off..off + 4)?.try_into().ok()?;
        off += 4;
        Some(IpAddr::from(a))
    } else {
        None
    };
    let v6 = if has_v6 {
        let a: [u8; 16] = v.get(off..off + 16)?.try_into().ok()?;
        Some(IpAddr::from(a))
    } else {
        None
    };
    match (v4, v6) {
        (Some(a), b) => Some((a, b)),
        (None, Some(b)) => Some((b, None)),
        (None, None) => None,
    }
}

// ============================================================================
// Failed paths and the hold
// ============================================================================

/// Failed remote GTP-U peers, per UPF (its `recovery_time_stamp_key`), each with the
/// generation its hold timer was started under.
fn failed_paths() -> &'static Mutex<HashMap<(String, IpAddr), u64>> {
    static FAILED: std::sync::OnceLock<Mutex<HashMap<(String, IpAddr), u64>>> =
        std::sync::OnceLock::new();
    FAILED.get_or_init(|| Mutex::new(HashMap::new()))
}

static GENERATION: AtomicU64 = AtomicU64::new(1);

/// The hold timers still pending, aborted by a graceful shutdown.
fn hold_timers() -> &'static Mutex<Vec<tokio::task::AbortHandle>> {
    static HOLDS: std::sync::OnceLock<Mutex<Vec<tokio::task::AbortHandle>>> =
        std::sync::OnceLock::new();
    HOLDS.get_or_init(|| Mutex::new(Vec::new()))
}

/// How many remote GTP-U peers are failed now, over all UPFs (`smf_up_paths_failed`).
pub fn failed_path_count() -> usize {
    failed_paths().lock().map(|m| m.len()).unwrap_or(0)
}

/// Whether `ip` is failed as seen from the UPF `upf_key`.
pub fn is_failed(upf_key: &str, ip: IpAddr) -> bool {
    failed_paths()
        .lock()
        .is_ok_and(|m| m.contains_key(&(upf_key.to_string(), ip)))
}

/// How many hold timers are pending (tests).
#[cfg(test)]
pub(crate) fn pending_hold_count() -> usize {
    hold_timers()
        .lock()
        .map(|h| h.iter().filter(|h| !h.is_finished()).count())
        .unwrap_or(0)
}

/// Stop the pending hold timers (a graceful shutdown): their releases would outlive
/// the deadline, and the next incarnation learns the path state again from the UPF.
pub fn abort_hold_timers() {
    if let Ok(mut holds) = hold_timers().lock() {
        for h in holds.drain(..) {
            h.abort();
        }
    }
}

/// Default operator maximum path failure duration (TS 23.007 §20.3.1): its NOTE 2
/// says it is "not intended to maintain bearer contexts during long path failures
/// (e.g. exceeding few minutes at most)".
pub const DEFAULT_HOLD: Duration = Duration::from_secs(120);
/// The longest hold accepted.
pub const MAX_HOLD: Duration = Duration::from_secs(3600);

/// The hold, from `SMF_UP_PATH_FAILURE_HOLD_SECS`.
pub fn hold_duration() -> Duration {
    #[cfg(test)]
    if let Some(hold) = *HOLD_FOR_TEST.lock().unwrap_or_else(|e| e.into_inner()) {
        return hold;
    }
    parse_hold(
        std::env::var("SMF_UP_PATH_FAILURE_HOLD_SECS")
            .ok()
            .as_deref(),
    )
}

/// A test's hold, instead of the environment's.
#[cfg(test)]
static HOLD_FOR_TEST: Mutex<Option<Duration>> = Mutex::new(None);

#[cfg(test)]
pub(crate) fn set_hold_for_test(hold: Option<Duration>) {
    *HOLD_FOR_TEST.lock().unwrap_or_else(|e| e.into_inner()) = hold;
}

/// The one test lock for this module's globals (the failed paths, the holds, the
/// test hold): the process-state lock under a name declared here, not a second lock
/// (two locks over one global are two disjoint agreements, the #276 hang).
#[cfg(test)]
pub(crate) use crate::context::PROCESS_STATE_TEST_LOCK as UP_PATH_TEST_LOCK;

/// `0` releases at once; above [`MAX_HOLD`] is clamped; anything unparsable is the
/// default, with a warning.
pub fn parse_hold(value: Option<&str>) -> Duration {
    let Some(v) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return DEFAULT_HOLD;
    };
    match v.parse::<u64>() {
        Ok(secs) if Duration::from_secs(secs) > MAX_HOLD => {
            log::warn!(
                "SMF_UP_PATH_FAILURE_HOLD_SECS={secs} is above {} s; using {} s",
                MAX_HOLD.as_secs(),
                MAX_HOLD.as_secs()
            );
            MAX_HOLD
        }
        Ok(secs) => Duration::from_secs(secs),
        Err(_) => {
            log::warn!(
                "SMF_UP_PATH_FAILURE_HOLD_SECS={v:?} is not a number of seconds; using {} s",
                DEFAULT_HOLD.as_secs()
            );
            DEFAULT_HOLD
        }
    }
}

// ============================================================================
// The Node Report
// ============================================================================

/// What a Node Report Request reports.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct NodeReport {
    pub failed: Vec<IpAddr>,
    pub recovered: Vec<IpAddr>,
    /// Peer GTP-U entities that restarted (TS 23.007 §20.3.4A); the UP function has
    /// already set the FARs toward them to BUFF and NOCP.
    pub restarted: Vec<IpAddr>,
}

/// Decode a Node Report Request body (TS 29.244 §7.4.5.1). `Err((cause, offending
/// IE))` for one that is missing a mandatory or conditional IE, or whose report names
/// no decodable Remote GTP-U Peer (#1028 review m5).
pub fn parse_node_report(body: &[u8]) -> Result<NodeReport, (u8, u16)> {
    if find_ie(body, ie::NODE_ID).is_none() {
        return Err((cause::MANDATORY_IE_MISSING, ie::NODE_ID));
    }
    let report_type = find_ie(body, ie::NODE_REPORT_TYPE)
        .and_then(|v| v.first().copied())
        .ok_or((cause::MANDATORY_IE_MISSING, ie::NODE_REPORT_TYPE))?;
    let peers = |grouped: u16, bit: u8| -> Result<Vec<IpAddr>, (u8, u16)> {
        if report_type & bit == 0 {
            return Ok(Vec::new());
        }
        let v = find_ie(body, grouped).ok_or((cause::CONDITIONAL_IE_MISSING, grouped))?;
        let peers = remote_peers(v).map_err(|_| (cause::MANDATORY_IE_INCORRECT, grouped))?;
        if peers.is_empty() {
            return Err((cause::MANDATORY_IE_INCORRECT, grouped));
        }
        Ok(peers)
    };
    Ok(NodeReport {
        failed: peers(ie::USER_PLANE_PATH_FAILURE_REPORT, node_report_type::UPFR)?,
        recovered: peers(ie::USER_PLANE_PATH_RECOVERY_REPORT, node_report_type::UPRR)?,
        restarted: peers(ie::PEER_UP_RESTART_REPORT, node_report_type::PURR)?,
    })
}

/// The Remote GTP-U Peer IEs (§8.2.70) of a grouped report, decoded by the shared
/// library codec (#1028 review B1: octet 5 bit 1 is V6, bit 2 is V4). Each peer's
/// IPv4 and IPv6 address both count.
fn remote_peers(grouped: &[u8]) -> Result<Vec<IpAddr>, nextgcore_pfcp::PfcpError> {
    let report = nextgcore_pfcp::types::UserPlanePathFailureReport::decode(grouped)?;
    let mut out = Vec::new();
    for peer in report.remote_gtpu_peers {
        if let Some(v4) = peer.ipv4 {
            out.push(IpAddr::from(v4));
        }
        if let Some(v6) = peer.ipv6 {
            out.push(IpAddr::from(v6).to_canonical());
        }
    }
    Ok(out)
}

/// The Node Report Response (TS 29.244 §7.4.5.2): this SMF's Node ID and the Cause,
/// and the Offending IE with a rejection for a missing IE.
pub fn node_report_response(
    sequence_number: u32,
    node_id: &nextgcore_pfcp::types::NodeId,
    cause: u8,
    offending: Option<u16>,
) -> Vec<u8> {
    let mut nid = bytes::BytesMut::new();
    node_id.encode(&mut nid);
    let mut body = Vec::new();
    body.extend_from_slice(&ie::NODE_ID.to_be_bytes());
    body.extend_from_slice(&(nid.len() as u16).to_be_bytes());
    body.extend_from_slice(&nid);
    body.extend_from_slice(&ie::CAUSE.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.push(cause);
    if let Some(o) = offending {
        body.extend_from_slice(&ie::OFFENDING_IE.to_be_bytes());
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&o.to_be_bytes());
    }
    crate::pfcp_path::encode_wire_message(
        pfcp_message_type::NODE_REPORT_RESPONSE,
        None,
        sequence_number,
        &body,
    )
}

/// One session that uses a failed peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Affected {
    /// The SM context, for a 5G session.
    pub reference: Option<String>,
    /// The session id, for an EPC PDN connection.
    pub epc_sess_id: Option<u64>,
    pub smf_seid: u64,
    pub upf_seid: u64,
    /// Its FARs toward the peer.
    pub fars: Vec<u32>,
    /// Whether one of them is Access (N3, or S5-U at a PGW-U).
    pub access: bool,
}

/// The sessions in `scope` (one UPF's) with a FAR toward one of `peers`: forwarding
/// ones only when `forwarding_only`, else any whose tunnel still points there.
pub fn affected_sessions(
    scope: &SessionScope,
    peers: &HashSet<IpAddr>,
    forwarding_only: bool,
) -> Vec<Affected> {
    let handle = smf_self();
    let Ok(ctx) = handle.read() else {
        return Vec::new();
    };
    // One map guard at a time.
    let five_g: Vec<(String, u64, u64)> = {
        let inherited = ctx
            .cp_n4_seids
            .read()
            .map(|m| m.clone())
            .unwrap_or_default();
        let sessions = ctx
            .pfcp_sessions
            .read()
            .map(|m| m.clone())
            .unwrap_or_default();
        scope
            .refs
            .iter()
            .filter_map(|r| {
                let upf_seid = *sessions.get(r)?;
                let smf_seid = inherited
                    .get(r)
                    .copied()
                    .unwrap_or_else(|| crate::context::derive_cp_n4_seid(r));
                Some((r.clone(), smf_seid, upf_seid))
            })
            .collect()
    };
    let epc: Vec<(u64, u64, u64)> = scope
        .epc_sess_ids
        .iter()
        .filter_map(|id| ctx.sess_find_by_id(*id))
        .map(|s| (s.id, s.smf_n4_seid, s.upf_n4_seid))
        .collect();
    let Ok(far_peers) = ctx.far_peers.read() else {
        return Vec::new();
    };
    let toward = |smf_seid: u64| -> Option<(Vec<u32>, bool)> {
        let fars = far_peers.get(&smf_seid)?;
        let hits: Vec<(u32, bool)> = fars
            .iter()
            .filter(|(_, p)| {
                peers.iter().any(|ip| p.matches(*ip)) && (p.forwarding || !forwarding_only)
            })
            .map(|(id, p)| (*id, p.access))
            .collect();
        (!hits.is_empty()).then(|| {
            let access = hits.iter().any(|(_, a)| *a);
            (hits.into_iter().map(|(id, _)| id).collect(), access)
        })
    };
    let mut out = Vec::new();
    for (r, smf_seid, upf_seid) in five_g {
        if let Some((fars, access)) = toward(smf_seid) {
            out.push(Affected {
                reference: Some(r),
                epc_sess_id: None,
                smf_seid,
                upf_seid,
                fars,
                access,
            });
        }
    }
    for (id, smf_seid, upf_seid) in epc {
        if let Some((fars, access)) = toward(smf_seid) {
            out.push(Affected {
                reference: None,
                epc_sess_id: Some(id),
                smf_seid,
                upf_seid,
                fars,
                access,
            });
        }
    }
    out
}

/// How many sessions are deactivated or released at once.
const PATH_FANOUT: usize = 16;

/// Act on a Node Report from the UPF `upf_key`, whose sessions are `scope` (#994).
/// Called on the N4 receive task after the response went out: the state changes
/// here are synchronous, the per-session work runs in tracked tasks.
pub fn on_node_report(upf_key: &str, scope: SessionScope, report: NodeReport) {
    let hold = hold_duration();
    let mut newly_failed = Vec::new();
    let mut durable_changed = false;
    if let Ok(mut failed) = failed_paths().lock() {
        for ip in &report.failed {
            let key = (upf_key.to_string(), *ip);
            if failed.contains_key(&key) {
                log::debug!("UPF {upf_key}: GTP-U path to {ip} reported failed again");
                continue;
            }
            let generation = GENERATION.fetch_add(1, Ordering::SeqCst);
            failed.insert(key, generation);
            UP_PATH_FAILURES.fetch_add(1, Ordering::Relaxed);
            newly_failed.push((*ip, generation));
        }
        for ip in &report.recovered {
            if failed.remove(&(upf_key.to_string(), *ip)).is_some() {
                UP_PATH_RECOVERIES.fetch_add(1, Ordering::Relaxed);
                log::info!(
                    "UPF {upf_key}: GTP-U path to {ip} recovered (TS 29.244 §5.10A); its \
                     sessions are kept, and are reactivated by their next Service Request"
                );
            }
        }
    }
    // #1028 review m2: a UP function reports a transition once, so the failed paths
    // and when they failed are durable: a path still down across a restart is held
    // and released as TS 23.007 §20.3.1 requires.
    {
        let handle = smf_self();
        if let Ok(ctx) = handle.read() {
            if let Ok(mut durable) = ctx.failed_up_paths.write() {
                let now = unix_now();
                for (ip, _) in &newly_failed {
                    durable.insert(durable_key(upf_key, *ip), now);
                    durable_changed = true;
                }
                for ip in &report.recovered {
                    durable_changed |= durable.remove(&durable_key(upf_key, *ip)).is_some();
                }
            }
            if durable_changed {
                ctx.persist();
            }
        };
    }
    // #1028 review m3: with no hold the release follows at once, so the separate
    // N2-only deactivation would race its #39 for the same session.
    let deactivate: HashSet<IpAddr> = newly_failed
        .iter()
        .filter(|_| !hold.is_zero())
        .map(|(ip, _)| *ip)
        .chain(report.restarted.iter().copied())
        .collect();
    if !deactivate.is_empty() {
        let affected = affected_sessions(&scope, &deactivate, true);
        log::warn!(
            "UPF {upf_key}: GTP-U path failure toward {:?}{}: deactivating the user plane \
             of {} session(s) (TS 23.502 §4.3.7); held for {} s",
            newly_failed.iter().map(|(ip, _)| ip).collect::<Vec<_>>(),
            if report.restarted.is_empty() {
                String::new()
            } else {
                format!(", peer GTP-U restart of {:?}", report.restarted)
            },
            affected.len(),
            hold.as_secs()
        );
        spawn_fanout(affected, "user plane path failure", Action::Deactivate);
    }
    for (ip, generation) in newly_failed {
        arm_hold(upf_key, ip, generation, hold);
    }
}

/// Start the hold timer for a failed path.
fn arm_hold(upf_key: &str, ip: IpAddr, generation: u64, hold: Duration) {
    arm_hold_unless(crate::shutting_down(), upf_key, ip, generation, hold);
}

/// [`arm_hold`], but not once the SMF is shutting down (#1028 review): the hold's
/// #39 releases would only meet NF_FAILOVER. The failed path stays in the snapshot,
/// so the next incarnation re-arms it. Returns whether a hold was armed.
fn arm_hold_unless(
    shutting_down: bool,
    upf_key: &str,
    ip: IpAddr,
    generation: u64,
    hold: Duration,
) -> bool {
    if shutting_down {
        log::info!(
            "UPF {upf_key}: GTP-U path to {ip} failed during the shutdown; no hold is armed, \
             the next start re-arms it"
        );
        return false;
    }
    let upf_key = upf_key.to_string();
    let timer = tokio::spawn(async move {
        tokio::time::sleep(hold).await;
        hold_expired(&upf_key, ip, generation);
    });
    if let Ok(mut holds) = hold_timers().lock() {
        holds.retain(|h| !h.is_finished());
        holds.push(timer.abort_handle());
    }
    true
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The snapshot key of a failed path: the UPF's identity and the peer.
fn durable_key(upf_key: &str, ip: IpAddr) -> String {
    format!("{upf_key}|{ip}")
}

/// After a restart, a re-armed hold waits for its UPF to be associated again, then
/// at least this long (#1028 round 2, m3): a hold that ran out while the SMF was
/// down would otherwise release at boot, before the association, and its PFCP
/// Deletions would wait out T1 x N1 each.
pub const REARM_GRACE: Duration = Duration::from_secs(10);

/// Re-arm the holds of the failed paths the snapshot restored (#1028 review m2), for
/// what is left of each, once their UPF is associated again (and at least
/// [`REARM_GRACE`] after that). Run at boot, once the pool is installed. An entry
/// whose UPF is no longer configured (a renamed hostname UPF, #1028 round 2 m4) is
/// dropped. Returns how many were armed.
///
/// A recovery the UPF reported while this SMF was down is lost (the UPF gives up
/// after N1 retransmissions), so such a path still counts as failed: its sessions are
/// released with #39 after the hold, and the UEs re-establish them. That is the
/// safe direction.
pub fn rearm_restored_holds() -> usize {
    let entries: Vec<(String, u64)> = {
        let handle = smf_self();
        let Ok(ctx) = handle.read() else { return 0 };
        let entries = ctx
            .failed_up_paths
            .read()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), *v)).collect())
            .unwrap_or_default();
        entries
    };
    let pool_keys: Vec<String> = crate::pfcp_path::global_pool()
        .iter()
        .map(|c| c.recovery_time_stamp_key())
        .collect();
    let hold = hold_duration();
    let now = unix_now();
    let mut armed = 0;
    let mut stale = Vec::new();
    for (key, since) in entries {
        let Some((upf_key, ip)) = key
            .rsplit_once('|')
            .and_then(|(k, ip)| Some((k.to_string(), ip.parse::<IpAddr>().ok()?)))
        else {
            stale.push(key);
            continue;
        };
        if !pool_keys.contains(&upf_key) {
            log::info!("UPF {upf_key} is not configured now; its failed path to {ip} is forgotten");
            stale.push(key);
            continue;
        }
        let generation = GENERATION.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut failed) = failed_paths().lock() {
            failed.insert((upf_key.clone(), ip), generation);
        }
        let left = hold.saturating_sub(Duration::from_secs(now.saturating_sub(since)));
        log::warn!(
            "UPF {upf_key}: GTP-U path to {ip} was down at the last shutdown; its sessions \
             are released {} s after the UPF is associated again, unless it recovers",
            left.max(rearm_grace()).as_secs()
        );
        arm_rearmed_hold(upf_key, ip, generation, left.max(rearm_grace()));
        armed += 1;
    }
    if !stale.is_empty() {
        let handle = smf_self();
        if let Ok(ctx) = handle.read() {
            if let Ok(mut m) = ctx.failed_up_paths.write() {
                for k in &stale {
                    m.remove(k);
                }
            }
            ctx.persist();
        };
    }
    armed
}

/// [`REARM_GRACE`], or a test's hold.
fn rearm_grace() -> Duration {
    #[cfg(test)]
    if let Some(hold) = *HOLD_FOR_TEST.lock().unwrap_or_else(|e| e.into_inner()) {
        return hold;
    }
    REARM_GRACE
}

/// A restored hold: first wait for the UPF's association (at most [`MAX_HOLD`]),
/// then `left`.
fn arm_rearmed_hold(upf_key: String, ip: IpAddr, generation: u64, left: Duration) {
    let timer = tokio::spawn(async move {
        let give_up = tokio::time::Instant::now() + MAX_HOLD;
        loop {
            let associated = match crate::pfcp_path::global_pool()
                .into_iter()
                .find(|c| c.recovery_time_stamp_key() == upf_key)
            {
                Some(c) => c.is_associated().await,
                None => {
                    log::info!(
                        "UPF {upf_key} left the pool; the restored hold for its path to {ip} \
                         is dropped"
                    );
                    return;
                }
            };
            if associated {
                break;
            }
            if tokio::time::Instant::now() >= give_up {
                // #1028 review: say so, rather than let the hold vanish silently. The
                // path stays in the snapshot, so the next start re-arms it.
                log::warn!(
                    "UPF {upf_key} was not associated again within {} s; the restored hold \
                     for its GTP-U path to {ip} is given up, and its sessions are not released \
                     by it",
                    MAX_HOLD.as_secs()
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        tokio::time::sleep(left).await;
        hold_expired(&upf_key, ip, generation);
    });
    if let Ok(mut holds) = hold_timers().lock() {
        holds.retain(|h| !h.is_finished());
        holds.push(timer.abort_handle());
    }
}

/// The hold for `ip` at `upf_key` expired: release what still points there, if the
/// path was not recovered (and failed again) meanwhile.
fn hold_expired(upf_key: &str, ip: IpAddr, generation: u64) {
    let still_down = failed_paths()
        .lock()
        .is_ok_and(|m| m.get(&(upf_key.to_string(), ip)) == Some(&generation));
    if !still_down {
        return;
    }
    // Its hold is spent; a restart need not re-arm it (and a peer that never
    // recovers does not stay in the snapshot for good).
    {
        let handle = smf_self();
        if let Ok(ctx) = handle.read() {
            let removed = ctx
                .failed_up_paths
                .write()
                .is_ok_and(|mut m| m.remove(&durable_key(upf_key, ip)).is_some());
            if removed {
                ctx.persist();
            }
        };
    }
    let Some(client) = crate::pfcp_path::global_pool()
        .into_iter()
        .find(|c| c.recovery_time_stamp_key() == upf_key)
    else {
        return;
    };
    let scope = client.session_scope();
    let affected = affected_sessions(&scope, &HashSet::from([ip]), false);
    if affected.is_empty() {
        return;
    }
    log::warn!(
        "UPF {upf_key}: GTP-U path to {ip} still down after {} s (TS 23.007 §20.3.1): \
         releasing the {} session(s) still using it",
        hold_duration().as_secs(),
        affected.len()
    );
    spawn_fanout(affected, "user plane path still down", Action::Release);
}

/// What to do with an affected session.
#[derive(Debug, Clone, Copy)]
enum Action {
    Deactivate,
    Release,
}

fn spawn_fanout(affected: Vec<Affected>, reason: &'static str, action: Action) {
    if affected.is_empty() {
        return;
    }
    let fanout = tokio::spawn(async move {
        let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(PATH_FANOUT));
        let mut set = tokio::task::JoinSet::new();
        for a in affected {
            let Ok(permit) = permits.clone().acquire_owned().await else {
                break;
            };
            set.spawn(async move {
                let _permit = permit;
                match action {
                    Action::Deactivate => {
                        if crate::deactivate_up_toward_failed_path(&a, reason).await {
                            UP_PATH_SESSIONS_DEACTIVATED.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Action::Release => {
                        if crate::release_after_path_failure(&a, reason).await {
                            UP_PATH_SESSIONS_RELEASED.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
        while set.join_next().await.is_some() {}
    });
    crate::pfcp_path::track_restart_fanout(fanout);
}

/// The sessions of an Error Indication Report (TS 29.244 §8.2.21 ERIR): the one
/// session `smf_seid`, for its forwarding FARs toward `peer`, or all its forwarding
/// Access FARs when the report names none.
pub fn deactivate_after_error_indication(smf_seid: u64, peer: Option<IpAddr>) {
    let found = {
        let handle = smf_self();
        let Ok(ctx) = handle.read() else { return };
        // One map guard at a time.
        let inherited = ctx
            .cp_n4_seids
            .read()
            .map(|m| m.clone())
            .unwrap_or_default();
        let reference = ctx.pfcp_sessions.read().ok().and_then(|m| {
            m.iter()
                .find(|(r, _)| {
                    inherited
                        .get(*r)
                        .copied()
                        .unwrap_or_else(|| crate::context::derive_cp_n4_seid(r))
                        == smf_seid
                })
                .map(|(r, upf)| (r.clone(), *upf))
        });
        let fars: Vec<(u32, bool)> = ctx
            .far_peers
            .read()
            .ok()
            .and_then(|m| m.get(&smf_seid).cloned())
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, p)| {
                p.forwarding
                    && match peer {
                        Some(ip) => p.matches(ip),
                        None => p.access,
                    }
            })
            .map(|(id, p)| (id, p.access))
            .collect();
        reference.map(|(r, upf_seid)| (r, upf_seid, fars))
    };
    let Some((reference, upf_seid, fars)) = found else {
        return;
    };
    if fars.is_empty() {
        return;
    }
    let access = fars.iter().any(|(_, a)| *a);
    spawn_fanout(
        vec![Affected {
            reference: Some(reference),
            epc_sess_id: None,
            smf_seid,
            upf_seid,
            fars: fars.into_iter().map(|(id, _)| id).collect(),
            access,
        }],
        "GTP-U Error Indication",
        Action::Deactivate,
    );
}

/// Forget every failed path and hold (tests).
#[cfg(test)]
pub(crate) fn reset_for_test() {
    abort_hold_timers();
    set_hold_for_test(None);
    if let Ok(mut m) = failed_paths().lock() {
        m.clear();
    }
    let handle = smf_self();
    if let Ok(ctx) = handle.read() {
        if let Ok(mut m) = ctx.failed_up_paths.write() {
            m.clear();
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::n4_build::{
        build_create_far, build_session_modification_request, build_update_far_deactivate,
        FarParams, PfcpMessageBuilder, SessionModificationParams,
    };

    fn create_far(id: u32, action: u16, di: u8, ip: [u8; 4]) -> Vec<u8> {
        let far = build_create_far(&FarParams {
            far_id: id,
            apply_action: action,
            destination_interface: Some(di),
            outer_header_creation: Some((0x0100, 0x1000 + id, Some(ip), None)),
            network_instance: None,
        });
        let mut b = PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::CREATE_FAR, &far);
        b.build()
    }

    /// #1091 review G: a Node Report that arrives once the SMF is shutting down
    /// records the failed path (in memory and in the snapshot, for the next start)
    /// but arms no hold.
    #[tokio::test]
    async fn a_node_report_during_the_shutdown_records_the_path_but_arms_no_hold() {
        let _state = UP_PATH_TEST_LOCK.lock().await;
        let upf_key = "upf-1091g:8805";
        let ip: IpAddr = "10.10.91.7".parse().unwrap();
        let before = pending_hold_count();
        crate::set_shutting_down_for_test(true);
        on_node_report(
            upf_key,
            SessionScope::default(),
            NodeReport {
                failed: vec![ip],
                recovered: Vec::new(),
                restarted: Vec::new(),
            },
        );
        crate::set_shutting_down_for_test(false);
        let after = pending_hold_count();
        let failed = is_failed(upf_key, ip);
        let durable = smf_self()
            .read()
            .unwrap()
            .failed_up_paths
            .read()
            .unwrap()
            .contains_key(&durable_key(upf_key, ip));
        on_node_report(
            upf_key,
            SessionScope::default(),
            NodeReport {
                failed: Vec::new(),
                recovered: vec![ip],
                restarted: Vec::new(),
            },
        );

        assert_eq!(after, before, "no hold armed");
        assert!(failed, "the path is recorded failed");
        assert!(durable, "and in the snapshot, for the next start to re-arm");
    }

    /// #1028 review: a path that fails during the shutdown arms no hold (its #39s
    /// would meet NF_FAILOVER); the next start re-arms it from the snapshot.
    #[tokio::test]
    async fn no_hold_is_armed_once_the_smf_is_shutting_down() {
        let _state = UP_PATH_TEST_LOCK.lock().await;
        let ip: IpAddr = "10.10.91.1".parse().unwrap();
        let before = pending_hold_count();
        let armed = arm_hold_unless(true, "upf-1091:8805", ip, 1, Duration::from_secs(60));
        let after = pending_hold_count();
        assert!(!armed);
        assert_eq!(after, before, "no hold timer pending");
    }

    /// #994: the FAR peers of a session follow its Create, Update and Remove FARs.
    #[test]
    fn far_peers_follow_create_update_and_remove() {
        let mut fars = BTreeMap::new();
        apply_far_edits(
            &mut fars,
            &create_far(2, apply_action::FORW, 0, [10, 0, 0, 5]),
        );
        apply_far_edits(
            &mut fars,
            &create_far(3, apply_action::FORW, 2, [10, 9, 0, 1]),
        );
        assert_eq!(
            fars.get(&2),
            Some(&FarPeer {
                ip: "10.0.0.5".parse().unwrap(),
                ip6: None,
                access: true,
                forwarding: true
            })
        );
        assert!(!fars[&3].access, "Destination Interface Core (N9)");

        // Deactivated: still points there, not forwarding.
        let mut b = PfcpMessageBuilder::new();
        b.add_tlv(pfcp_ie::UPDATE_FAR, &build_update_far_deactivate(2));
        apply_far_edits(&mut fars, &b.build());
        assert_eq!(fars[&2].ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert!(!fars[&2].forwarding);

        // Activated toward a new gNB (the Update Forwarding Parameters carry the
        // new Outer Header Creation).
        let update = build_session_modification_request(&SessionModificationParams {
            update_fars_activate: vec![(
                2,
                0,
                Some((0x0100, 0x77, Some([10, 0, 0, 6]), None)),
                false,
            )],
            ..Default::default()
        });
        apply_far_edits(&mut fars, &update);
        assert_eq!(fars[&2].ip, "10.0.0.6".parse::<IpAddr>().unwrap());
        assert!(fars[&2].forwarding && fars[&2].access);

        let remove = build_session_modification_request(&SessionModificationParams {
            remove_far_ids: vec![3],
            ..Default::default()
        });
        apply_far_edits(&mut fars, &remove);
        assert!(!fars.contains_key(&3));
    }

    #[test]
    fn an_outer_header_creation_names_its_addresses() {
        assert_eq!(
            outer_header_ips(&[0x01, 0x00, 0, 0, 0, 1, 10, 0, 0, 7]),
            Some(("10.0.0.7".parse().unwrap(), None))
        );
        let v6: std::net::Ipv6Addr = "2001:db8::7".parse().unwrap();
        let mut only6 = vec![0x02, 0x00, 0, 0, 0, 1];
        only6.extend_from_slice(&v6.octets());
        assert_eq!(outer_header_ips(&only6), Some((IpAddr::V6(v6), None)));
        // #1028 review m4: dual stack, both addresses.
        let mut dual = vec![0x03, 0x00, 0, 0, 0, 1, 10, 0, 0, 7];
        dual.extend_from_slice(&v6.octets());
        assert_eq!(
            outer_header_ips(&dual),
            Some(("10.0.0.7".parse().unwrap(), Some(IpAddr::V6(v6))))
        );
        assert_eq!(outer_header_ips(&[0x01, 0x00, 0, 0]), None, "truncated");
    }

    fn report(report_type: u8, grouped: &[(u16, [u8; 4])]) -> Vec<u8> {
        let mut b = PfcpMessageBuilder::new();
        b.add_tlv(ie::NODE_ID, &[0, 10, 0, 0, 7]);
        b.add_tlv(ie::NODE_REPORT_TYPE, &[report_type]);
        for (t, ip) in grouped {
            let mut peer = PfcpMessageBuilder::new();
            // TS 29.244 §8.2.70: octet 5 bit 2 is V4.
            let mut v = vec![0x02];
            v.extend_from_slice(ip);
            peer.add_tlv(ie::REMOTE_GTP_U_PEER, &v);
            b.add_tlv(*t, &peer.build());
        }
        b.build()
    }

    /// TS 29.244 §7.4.5.1: Node ID and Node Report Type are mandatory, and each
    /// report flagged in the type is conditional on it.
    #[test]
    fn a_node_report_is_decoded_and_checked() {
        let failure = report(0x01, &[(ie::USER_PLANE_PATH_FAILURE_REPORT, [10, 0, 0, 5])]);
        assert_eq!(
            parse_node_report(&failure),
            Ok(NodeReport {
                failed: vec!["10.0.0.5".parse().unwrap()],
                ..Default::default()
            })
        );
        let recovery = report(
            0x02,
            &[(ie::USER_PLANE_PATH_RECOVERY_REPORT, [10, 0, 0, 5])],
        );
        assert_eq!(
            parse_node_report(&recovery).unwrap().recovered,
            vec!["10.0.0.5".parse::<IpAddr>().unwrap()]
        );
        let restart = report(0x10, &[(ie::PEER_UP_RESTART_REPORT, [10, 0, 0, 8])]);
        assert_eq!(
            parse_node_report(&restart).unwrap().restarted,
            vec!["10.0.0.8".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            parse_node_report(&report(0x01, &[])),
            Err((
                cause::CONDITIONAL_IE_MISSING,
                ie::USER_PLANE_PATH_FAILURE_REPORT
            ))
        );
        assert_eq!(
            parse_node_report(&[0, 101, 0, 1, 1]),
            Err((cause::MANDATORY_IE_MISSING, ie::NODE_ID))
        );
        assert_eq!(
            parse_node_report(&[0, 60, 0, 5, 0, 10, 0, 0, 7]),
            Err((cause::MANDATORY_IE_MISSING, ie::NODE_REPORT_TYPE))
        );
    }

    /// #1028 review B1: the bytes a conformant UP function sends (TS 29.244
    /// §8.2.70, and nextgcore's upfd `build_node_report`): an IPv4 peer is
    /// `[0x02, a, b, c, d]`, an IPv6 one `[0x01, 16 octets]`. A report naming none
    /// that decodes is cause 69.
    #[test]
    fn remote_gtpu_peers_decode_as_the_spec_encodes_them() {
        let body = |grouped: &[u8]| {
            let mut b = vec![0, 60, 0, 5, 0, 10, 0, 0, 1, 0, 101, 0, 1, 0x01, 0, 102];
            b.extend_from_slice(&(grouped.len() as u16).to_be_bytes());
            b.extend_from_slice(grouped);
            b
        };
        let v4 = body(&[0, 103, 0, 5, 0x02, 10, 0, 0, 5]);
        assert_eq!(
            parse_node_report(&v4).unwrap().failed,
            vec!["10.0.0.5".parse::<IpAddr>().unwrap()]
        );
        let v6addr: std::net::Ipv6Addr = "2001:db8::5".parse().unwrap();
        let mut g = vec![0, 103, 0, 17, 0x01];
        g.extend_from_slice(&v6addr.octets());
        assert_eq!(
            parse_node_report(&body(&g)).unwrap().failed,
            vec![IpAddr::V6(v6addr)]
        );
        assert_eq!(
            parse_node_report(&body(&[0, 103, 0, 3, 0x02, 10, 0])),
            Err((
                cause::MANDATORY_IE_INCORRECT,
                ie::USER_PLANE_PATH_FAILURE_REPORT
            )),
            "a truncated address"
        );
        assert_eq!(
            parse_node_report(&body(&[])),
            Err((
                cause::MANDATORY_IE_INCORRECT,
                ie::USER_PLANE_PATH_FAILURE_REPORT
            )),
            "no peer"
        );
    }

    /// #1028 round 2, m1: a dual-stack N3 FAR records both addresses, and a failure
    /// naming either one matches it.
    #[test]
    fn a_dual_stack_far_matches_either_address() {
        let v6: std::net::Ipv6Addr = "2001:db8::5".parse().unwrap();
        let mut ohc = vec![0x03, 0x00, 0, 0, 0, 1, 10, 0, 0, 5];
        ohc.extend_from_slice(&v6.octets());
        let mut fp = PfcpMessageBuilder::new();
        fp.add_u8(pfcp_ie::DESTINATION_INTERFACE, 0);
        fp.add_tlv(pfcp_ie::OUTER_HEADER_CREATION, &ohc);
        let mut far = PfcpMessageBuilder::new();
        far.add_tlv(pfcp_ie::FAR_ID, &2u32.to_be_bytes());
        far.add_apply_action(apply_action::FORW);
        far.add_tlv(pfcp_ie::FORWARDING_PARAMETERS, &fp.build());
        let mut body = PfcpMessageBuilder::new();
        body.add_tlv(pfcp_ie::CREATE_FAR, &far.build());
        let mut fars = BTreeMap::new();
        apply_far_edits(&mut fars, &body.build());
        let peer = fars[&2];
        assert!(peer.matches("10.0.0.5".parse().unwrap()));
        assert!(peer.matches(IpAddr::V6(v6)), "the IPv6 address too");
        assert!(!peer.matches("10.0.0.6".parse().unwrap()));
    }

    #[test]
    fn the_hold_is_validated() {
        assert_eq!(parse_hold(None), DEFAULT_HOLD);
        assert_eq!(parse_hold(Some("")), DEFAULT_HOLD);
        assert_eq!(parse_hold(Some("0")), Duration::ZERO);
        assert_eq!(parse_hold(Some("30")), Duration::from_secs(30));
        assert_eq!(parse_hold(Some("99999")), MAX_HOLD);
        assert_eq!(parse_hold(Some("soon")), DEFAULT_HOLD);
    }
}
