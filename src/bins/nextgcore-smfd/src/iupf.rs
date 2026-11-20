//! An intermediate UPF on N9 (#2208, TS 23.502 §4.3.5.4 "Addition of an
//! intermediate UPF", TS 23.501 §5.6.4).
//!
//! When `smf.intermediate_upf` names an I-UPF (and, with `dnns`, the session's
//! DNN is one of them), a new PDU session gets two N4 sessions: the PSA's, as
//! before, and the I-UPF's, established right after it (TS 23.502 §4.3.5.4 steps
//! 3-4: the I-UPF gets the PSA's N9 tunnel, then the PSA the I-UPF's):
//!
//! - **I-UPF.** PDR 1: Source Interface Access, CHOOSE F-TEID (the N3 tunnel the
//!   NG-RAN is given), Outer Header Removal, FAR 1: FORW toward Core with the
//!   PSA's UL F-TEID as Outer Header Creation (N9). PDR 2: Source Interface Core,
//!   CHOOSE F-TEID (the N9 downlink tunnel), Outer Header Removal, FAR 2: toward
//!   Access, BUFF until the NG-RAN's tunnel is known. TS 29.244 §5.2.1 / §8.2.2
//!   NOTE 1: Access and Core are the UL and DL directions on N3 and N9 alike.
//! - **PSA.** Unchanged, except that its FAR 2 (Access side) forwards to the
//!   I-UPF's N9 tunnel instead of the NG-RAN's.
//!
//! The NG-RAN gets the I-UPF's N3 F-TEID. Every later Session Modification the
//! SMF sends for the session is split at one place ([`split_modification`],
//! called from `PfcpClient::session_request`), so no procedure has to know:
//! - an Update FAR 2 that activates the NG-RAN tunnel (activation, Xn and N2
//!   handover, path switch) goes to the I-UPF, and the PSA's FAR 2 is pointed
//!   (again) at the I-UPF's N9 tunnel;
//! - an Update FAR 2 that only changes the Apply Action (BUFF|NOCP at AN release,
//!   #1707's policy) goes to both: the PSA buffers and reports downlink data
//!   (TS 23.502 §4.2.6, the PSA buffering because this tree's I-UPF does not),
//!   and the I-UPF's NG-RAN tunnel stops;
//! - PFCPSMReq-Flags (SNDEM) go with the tunnel change to the I-UPF, which sends
//!   the End Markers toward the old NG-RAN;
//! - everything else (QERs, URRs, SRRs, TSC, the PSA's IE 271) stays at the PSA.
//!
//! A Session Deletion deletes the I-UPF's session first. The record of the I-UPF
//! leg is in the durable snapshot (`iupfLegs`), so a restarted SMF keeps splitting.
//!
//! The I-UPF's own failures (#2225):
//! - **Association loss or restart** (heartbeat loss, a changed Recovery Time
//!   Stamp, an Association Release, cause 72, sessions not retained): every PSA
//!   session with a leg is deleted at its PSA, which is alive, and released with
//!   #39 so the UE re-establishes it ([`release_sessions_of_lost_iupf`]). TS 23.527
//!   §4.3.4 makes restoring the I-UPF's sessions a "may". This tree's I-UPF
//!   chooses its F-TEIDs, so a restored leg would also need the NG-RAN's UL tunnel
//!   moved over N2, and restoration is not done.
//! - **User Plane Path Failure Reports** (TS 29.244 §5.10A) from the I-UPF are
//!   held and released as `up_path` does for the PSA's peers. The I-UPF's scope is
//!   the PSA sessions with a leg ([`session_scope`]). A failed peer of a leg (the
//!   NG-RAN on N3, or the PSA on N9) deactivates the PSA session's access side.
//! - **Session Reports** on a leg SEID are attributed to its PSA session:
//!   Downlink Data Reports page the UE, and Error Indication Reports deactivate the
//!   user plane (TS 23.527 §5.3.3.2).
//! - **A leg deletion the I-UPF did not answer** is queued (at most
//!   [`MAX_PENDING_DELETIONS`], the oldest dropped first). While the queue is not
//!   empty, the next Association Setup asks the I-UPF to retain its sessions
//!   (TS 29.244 §6.2.6.2.1).
//!   - When the I-UPF confirms retention (PSREI), the queue is resent, one pass at
//!     a time, stopping at the first unanswered deletion.
//!   - When it does not, it holds none of those sessions, and the queue is dropped
//!     unsent (R45 M1 on #2268). A restarted I-UPF counts its SEIDs from the start
//!     again, so a queued SEID could otherwise delete a new session's leg.
//!
//! Not done, stated: an I-UPF chosen per location (one configured I-UPF serves
//! every session it applies to), relocation or removal of the I-UPF mid-session
//! (TS 23.502 §4.3.5.5-6), restoring a lost I-UPF's sessions (above), and a split
//! PDU session (additional NG-RAN tunnels, #619) on an I-UPF session (refused,
//! `split_pdu_session_modification`).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::n4_build::{self, pfcp_ie, FarParams, PdrParams, PfcpMessageBuilder};
use crate::pfcp_path::{self, PfcpClient};

/// `smf.intermediate_upf` in the SMF's YAML.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IupfYaml {
    /// The I-UPF's PFCP endpoint: `addr`, `addr:port` or a host name.
    pub pfcp: String,
    /// The DNNs whose sessions get the I-UPF; empty for every session.
    #[serde(default)]
    pub dnns: Vec<String>,
}

/// The bit that marks the SMF-side SEID of an I-UPF leg: the PSA session's CP
/// SEID with bit 47 set. CP SEIDs are `FIVE_G_CP_SEID_BASE` (bit 48) plus a
/// derivation below bit 47, so the two never collide.
pub const LEG_SEID_BIT: u64 = 1 << 47;

/// The SMF-side SEID of the I-UPF leg of the PSA session `psa_seid`.
pub fn leg_seid(psa_seid: u64) -> u64 {
    psa_seid | LEG_SEID_BIT
}

/// Whether `seid` is an I-UPF leg's.
pub fn is_leg_seid(seid: u64) -> bool {
    seid & LEG_SEID_BIT != 0
}

/// The PSA session SEID of a leg SEID.
pub fn psa_seid_of(seid: u64) -> u64 {
    seid & !LEG_SEID_BIT
}

/// The I-UPF leg of one PDU session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IupfLeg {
    /// The SMF-side SEID of the I-UPF's N4 session ([`leg_seid`]).
    pub smf_seid: u64,
    /// The I-UPF's SEID.
    pub upf_seid: u64,
    /// The I-UPF's N3 F-TEID (PDR 1), the one the NG-RAN sends to.
    pub n3: (u32, [u8; 4]),
    /// The I-UPF's N9 F-TEID (PDR 2), the one the PSA's FAR 2 forwards to.
    pub n9: (u32, [u8; 4]),
    /// The PSA's UL F-TEID, the I-UPF's FAR 1 Outer Header Creation.
    pub psa_ul: (u32, [u8; 4]),
    /// The NG-RAN tunnel the I-UPF's FAR 2 forwards to, `None` while it buffers
    /// (R43 M1 on #2243): what a failed split restores.
    #[serde(default)]
    pub dl_tunnel: Option<(u32, [u8; 4])>,
    /// FAR 2's last full Apply Action while it has no NG-RAN tunnel (BUFF, or
    /// BUFF|NOCP at AN release), so a restore puts back exactly that, NOCP and
    /// all, and an idle UE is still paged (R43 on #2243, minor 1). `None`: BUFF.
    #[serde(default)]
    pub idle_action: Option<u16>,
}

struct Config {
    client: Arc<PfcpClient>,
    dnns: Vec<String>,
}

static CONFIG: RwLock<Option<Config>> = RwLock::new(None);

/// Install the configured I-UPF (startup, and tests).
pub fn set(client: Option<(Arc<PfcpClient>, Vec<String>)>) {
    *CONFIG.write().unwrap_or_else(|e| e.into_inner()) =
        client.map(|(client, dnns)| Config { client, dnns });
}

/// The I-UPF's PFCP client, when one is configured.
pub fn client() -> Option<Arc<PfcpClient>> {
    CONFIG
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|c| c.client.clone())
}

/// Whether `client` is the configured I-UPF's (#2225).
pub fn is_client(client: &PfcpClient) -> bool {
    CONFIG
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .is_some_and(|c| std::ptr::eq(Arc::as_ptr(&c.client), client))
}

/// Whether any PSA session has an I-UPF leg.
pub fn has_legs() -> bool {
    let ctx = crate::context::smf_self();
    let Ok(ctx) = ctx.read() else {
        return false;
    };
    let has = ctx.iupf_legs.read().is_ok_and(|l| !l.is_empty());
    has
}

/// The PSA sessions with a leg: `(SM context reference, SMF SEID, PSA's SEID)`.
fn leg_sessions() -> Vec<(String, u64, u64)> {
    let handle = crate::context::smf_self();
    let Ok(ctx) = handle.read() else {
        return Vec::new();
    };
    // One map guard at a time.
    let legs: std::collections::HashSet<u64> = ctx
        .iupf_legs
        .read()
        .map(|l| l.keys().copied().collect())
        .unwrap_or_default();
    if legs.is_empty() {
        return Vec::new();
    }
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
    sessions
        .into_iter()
        .filter_map(|(r, upf_seid)| {
            let seid = inherited
                .get(&r)
                .copied()
                .unwrap_or_else(|| crate::context::derive_cp_n4_seid(&r));
            legs.contains(&seid).then_some((r, seid, upf_seid))
        })
        .collect()
}

/// The I-UPF's sessions as a restoration scope (#2225): the PSA sessions with a
/// leg, marked as the I-UPF's so a report is read against the legs' FARs.
pub fn session_scope() -> crate::restoration::SessionScope {
    let sessions = leg_sessions();
    crate::restoration::SessionScope {
        seids: sessions.iter().map(|(_, s, _)| *s).collect(),
        refs: sessions.into_iter().map(|(r, _, _)| r).collect(),
        epc_sess_ids: Default::default(),
        iupf: true,
    }
}

/// The I-UPF was lost (#2225): its association went, or it restarted. Every leg
/// is forgotten, and its I-UPF session queued for deletion once the I-UPF is
/// back (it may have kept them across a heartbeat loss). Every PSA session with a
/// leg is then deleted at its PSA and released with #39, so the UE re-establishes
/// it. Returns the fan-out.
pub fn release_sessions_of_lost_iupf(reason: &str) -> tokio::task::JoinHandle<()> {
    let sessions = leg_sessions();
    let legs: Vec<(u64, IupfLeg)> = {
        let ctx = crate::context::smf_self();
        let legs = ctx
            .read()
            .ok()
            .and_then(|c| c.iupf_legs.read().ok().map(|l| l.clone()))
            .unwrap_or_default();
        legs.into_iter().collect()
    };
    for (psa_seid, leg) in &legs {
        forget(*psa_seid);
        queue_deletion(leg.smf_seid, leg.upf_seid);
    }
    log::error!(
        "I-UPF lost ({reason}): {} session(s) with an I-UPF leg are deleted at their PSA and \
         released with #39 (TS 23.527 §4.3.4); {} leg(s) forgotten",
        sessions.len(),
        legs.len()
    );
    let affected = sessions
        .into_iter()
        .map(|(reference, smf_seid, upf_seid)| crate::up_path::Affected {
            reference: Some(reference),
            epc_sess_id: None,
            smf_seid,
            upf_seid,
            fars: vec![crate::DL_FAR_ID],
            access: true,
        })
        .collect();
    crate::up_path::release_now(affected, "I-UPF association lost or restarted")
}

/// At most this many unanswered I-UPF session deletions wait for the I-UPF to
/// come back. Beyond that the oldest is dropped, with a warning.
pub const MAX_PENDING_DELETIONS: usize = 4096;

/// I-UPF sessions whose deletion the I-UPF did not answer: `(SMF SEID, I-UPF
/// SEID)` in queue order, and the SMF SEIDs queued, for an O(1) duplicate check
/// (R45 m2 on #2268).
#[derive(Default)]
struct PendingDeletions {
    queue: std::collections::VecDeque<(u64, u64)>,
    queued: std::collections::HashSet<u64>,
}

static PENDING_DELETIONS: std::sync::Mutex<Option<PendingDeletions>> = std::sync::Mutex::new(None);

fn with_pending<T>(f: impl FnOnce(&mut PendingDeletions) -> T) -> T {
    let mut g = PENDING_DELETIONS.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(PendingDeletions::default))
}

pub(crate) fn queue_deletion(smf_seid: u64, upf_seid: u64) {
    with_pending(|p| {
        if !p.queued.insert(smf_seid) {
            return;
        }
        if p.queue.len() >= MAX_PENDING_DELETIONS {
            if let Some((s, _)) = p.queue.pop_front() {
                p.queued.remove(&s);
                log::warn!(
                    "I-UPF deletion queue full: the session of SEID 0x{s:016x} is no longer \
                     retried"
                );
            }
        }
        p.queue.push_back((smf_seid, upf_seid));
    });
}

/// How many I-UPF session deletions wait for the I-UPF.
pub fn pending_deletions() -> usize {
    with_pending(|p| p.queue.len())
}

/// The queued deletions in order (tests).
#[cfg(test)]
pub(crate) fn pending_deletion_list() -> Vec<(u64, u64)> {
    with_pending(|p| p.queue.iter().copied().collect())
}

/// Drop every queued deletion (R45 M1 on #2268): the I-UPF did not retain its
/// sessions across the new association (TS 29.244 §6.2.6.2.2), so it holds none
/// of them, and a queued I-UPF SEID may by now name a new session that the
/// restarted I-UPF gave the same SEID.
pub fn drop_pending_deletions(why: &str) {
    let n = with_pending(|p| {
        p.queued.clear();
        std::mem::take(&mut p.queue).len()
    });
    if n > 0 {
        log::warn!("I-UPF {why}: {n} queued session deletion(s) dropped, never resent");
    }
}

/// Delete the I-UPF session `(smf_seid, upf_seid)`. True when the I-UPF answered,
/// whatever the cause: it then holds no such session.
async fn delete_on_iupf(client: &PfcpClient, smf_seid: u64, upf_seid: u64) -> bool {
    delete_on_iupf_within(client, None, smf_seid, upf_seid).await
}

/// [`delete_on_iupf`], sent only while the association is `generation` when one
/// is given (#2277, [`PfcpClient::session_request_within`]).
async fn delete_on_iupf_within(
    client: &PfcpClient,
    generation: Option<u64>,
    smf_seid: u64,
    upf_seid: u64,
) -> bool {
    let body = n4_build::build_session_deletion_request();
    let kind = pfcp_path::pfcp_message_type::SESSION_DELETION_REQUEST;
    let sent = match generation {
        Some(g) => {
            client
                .session_request_within(g, kind, smf_seid, Some(upf_seid), &body)
                .await
        }
        None => {
            client
                .session_request(kind, smf_seid, Some(upf_seid), &body)
                .await
        }
    };
    match sent {
        Ok(_) => true,
        Err(e) => {
            log::warn!(
                "I-UPF session of SEID 0x{smf_seid:016x} not deleted ({e}); retried once the \
                 I-UPF is associated again"
            );
            false
        }
    }
}

/// Whether a resend pass is running: one at a time (R45 m1 on #2268).
static RETRYING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct RetryingGuard;

impl Drop for RetryingGuard {
    fn drop(&mut self) {
        RETRYING.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// How many resend passes started (tests).
#[cfg(test)]
pub(crate) static RETRY_PASSES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// A test seam: the next resend pass stops before its first deletion, signals
/// `reached`, and waits for `proceed`; `done` is signalled when it ends.
#[cfg(test)]
pub(crate) struct BeforeRetry {
    pub(crate) reached: Arc<tokio::sync::Notify>,
    pub(crate) proceed: Arc<tokio::sync::Notify>,
}

#[cfg(test)]
type RetryHold = (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>);

#[cfg(test)]
static BEFORE_RETRY: std::sync::Mutex<Option<RetryHold>> = std::sync::Mutex::new(None);

#[cfg(test)]
impl BeforeRetry {
    pub(crate) fn arm() -> Self {
        let h = Self {
            reached: Arc::new(tokio::sync::Notify::new()),
            proceed: Arc::new(tokio::sync::Notify::new()),
        };
        *BEFORE_RETRY.lock().unwrap() = Some((h.reached.clone(), h.proceed.clone()));
        h
    }
}

#[cfg(test)]
impl Drop for BeforeRetry {
    fn drop(&mut self) {
        BEFORE_RETRY.lock().unwrap().take();
        self.proceed.notify_one();
    }
}

/// Send the queued I-UPF session deletions again (#2225), after an association
/// setup in which the I-UPF confirmed it retained its sessions (R45 M1 on
/// #2268). One pass at a time. A pass stops at the first deletion the I-UPF does
/// not answer, and that one and the rest stay queued (R45 m1).
///
/// #2277: a pass belongs to the association it started under. It records that
/// association's generation, and each deletion (its first transmission and every
/// retransmission) is sent only under it; once another association replaces it,
/// the deletion is not sent and the pass stops, keeping it and the rest queued. A queued I-UPF SEID
/// names its session only within the association it was queued under; across an
/// I-UPF restart and re-association it may name a new leg the restarted I-UPF
/// gave the same SEID, and that leg would be deleted.
pub fn retry_pending_deletions() {
    if pending_deletions() == 0 {
        return;
    }
    let (Some(client), Ok(rt)) = (client(), tokio::runtime::Handle::try_current()) else {
        return;
    };
    if RETRYING.swap(true, std::sync::atomic::Ordering::SeqCst) {
        log::info!("I-UPF deletion resend already running");
        return;
    }
    let guard = RetryingGuard;
    #[cfg(test)]
    RETRY_PASSES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    rt.spawn(async move {
        let _guard = guard;
        let generation = client.association_generation().await;
        #[cfg(test)]
        {
            let hold = BEFORE_RETRY.lock().unwrap().take();
            if let Some((reached, proceed)) = hold {
                reached.notify_one();
                proceed.notified().await;
            }
        }
        log::info!(
            "I-UPF associated with its sessions retained: resending {} session deletion(s)",
            pending_deletions()
        );
        while let Some((smf_seid, upf_seid)) = with_pending(|p| p.queue.front().copied()) {
            // #2277: under the association the pass started under, or not at all:
            // a deletion refused as the association changed fails, and the pass
            // stops with it and the rest queued.
            if !delete_on_iupf_within(&client, Some(generation), smf_seid, upf_seid).await {
                break;
            }
            with_pending(|p| {
                if p.queue.front() == Some(&(smf_seid, upf_seid)) {
                    p.queue.pop_front();
                    p.queued.remove(&smf_seid);
                }
            });
        }
    });
}

/// Whether a resend pass is running (tests).
#[cfg(test)]
pub(crate) fn retry_running() -> bool {
    RETRYING.load(std::sync::atomic::Ordering::SeqCst)
}

/// Forget every queued deletion (tests).
#[cfg(test)]
pub(crate) fn clear_pending_deletions() {
    with_pending(|p| {
        p.queue.clear();
        p.queued.clear();
    });
}

/// Whether a session on `dnn` gets the I-UPF.
fn applies_to(dnn: &str) -> Option<Arc<PfcpClient>> {
    let g = CONFIG.read().unwrap_or_else(|e| e.into_inner());
    let c = g.as_ref()?;
    (c.dnns.is_empty() || c.dnns.iter().any(|d| d == dnn)).then(|| c.client.clone())
}

/// The 3GPP Interface Type N9 (TS 29.244 Table 8.2.118-1).
pub const INTERFACE_TYPE_N9: u8 = 15;

/// Whether a new session on `dnn` is about to get the I-UPF: one is configured
/// for it and associated. Its PSA's UL PDR then says its Source Interface Type is
/// N9 (IE 160, TS 29.244 §8.2.118), which is how the PSA knows an I-UPF, not the
/// NG-RAN, precedes it (R43 M1 on #2249).
pub fn will_insert(dnn: &str) -> bool {
    applies_to(dnn).is_some_and(|c| c.is_associated_sync())
}

/// The I-UPF leg of the PSA session `psa_seid`, if it has one.
pub fn leg_of(psa_seid: u64) -> Option<IupfLeg> {
    let ctx = crate::context::smf_self();
    let ctx = ctx.read().ok()?;
    let legs = ctx.iupf_legs.read().ok()?;
    legs.get(&psa_seid).copied()
}

/// A test seam (R43 M1 on #2243): the next split modification stops between its
/// halves, signals `reached`, and waits for `proceed`, so a test can cancel it
/// there.
#[cfg(test)]
pub(crate) struct BetweenLegs {
    pub(crate) reached: Arc<tokio::sync::Notify>,
    pub(crate) proceed: Arc<tokio::sync::Notify>,
}

#[cfg(test)]
static BETWEEN_LEGS: std::sync::Mutex<
    Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
> = std::sync::Mutex::new(None);

#[cfg(test)]
impl BetweenLegs {
    pub(crate) fn arm() -> Self {
        let h = Self {
            reached: Arc::new(tokio::sync::Notify::new()),
            proceed: Arc::new(tokio::sync::Notify::new()),
        };
        *BETWEEN_LEGS.lock().unwrap() = Some((h.reached.clone(), h.proceed.clone()));
        h
    }
}

#[cfg(test)]
impl Drop for BetweenLegs {
    fn drop(&mut self) {
        BETWEEN_LEGS.lock().unwrap().take();
        self.proceed.notify_one();
    }
}

/// Stop at an armed [`BetweenLegs`], if any.
#[cfg(test)]
pub(crate) async fn test_hold_between_legs() {
    let hold = BETWEEN_LEGS.lock().unwrap().take();
    if let Some((reached, proceed)) = hold {
        reached.notify_one();
        proceed.notified().await;
    }
}

/// No hold outside tests.
#[cfg(not(test))]
pub(crate) async fn test_hold_between_legs() {}

fn store_leg(psa_seid: u64, leg: Option<IupfLeg>) {
    if let Ok(ctx) = crate::context::smf_self().read() {
        if let Ok(mut legs) = ctx.iupf_legs.write() {
            match leg {
                Some(l) => {
                    legs.insert(psa_seid, l);
                }
                None => {
                    legs.remove(&psa_seid);
                }
            }
        }
    }
}

/// The I-UPF's Session Establishment Request body for the leg of `psa_seid`
/// (see the module docs), flow `qfi`, toward the PSA's UL F-TEID `psa_ul`.
pub fn establishment_body(client: &PfcpClient, psa_seid: u64, psa_ul: (u32, [u8; 4])) -> Vec<u8> {
    let mut b = PfcpMessageBuilder::new();
    let mut node_id = bytes::BytesMut::new();
    client.node_id().encode(&mut node_id);
    b.add_node_id(&node_id);
    b.add_f_seid(leg_seid(psa_seid), Some(client.node_ip()), None);
    let pdr = |pdr_id: u16, source_interface: u8, far_id: u32| PdrParams {
        pdr_id,
        precedence: 100,
        source_interface,
        f_teid: Some((0, None, None)),
        outer_header_removal: Some(0),
        far_id: Some(far_id),
        // No QFI (R43 minor 1 on #2243): the I-UPF relays the tunnel, whatever
        // QoS flows it carries now or later.
        ..Default::default()
    };
    b.add_tlv(
        pfcp_ie::CREATE_PDR,
        &n4_build::build_create_pdr(&pdr(1, 0, 1)),
    );
    b.add_tlv(
        pfcp_ie::CREATE_FAR,
        &n4_build::build_create_far(&FarParams {
            far_id: 1,
            apply_action: n4_build::apply_action::FORW,
            destination_interface: Some(1),
            outer_header_creation: Some((0x0100, psa_ul.0, Some(psa_ul.1), None)),
            ..Default::default()
        }),
    );
    b.add_tlv(
        pfcp_ie::CREATE_PDR,
        &n4_build::build_create_pdr(&pdr(2, 1, 2)),
    );
    b.add_tlv(
        pfcp_ie::CREATE_FAR,
        &n4_build::build_create_far(&FarParams {
            far_id: 2,
            apply_action: n4_build::apply_action::BUFF,
            destination_interface: Some(0),
            ..Default::default()
        }),
    );
    b.build()
}

/// The UP F-SEID and the F-TEID of each Created PDR (by PDR ID) of a Session
/// Establishment Response body.
pub fn parse_establishment_response(body: &[u8]) -> (Option<u64>, HashMap<u16, (u32, [u8; 4])>) {
    let mut seid = None;
    let mut fteids = HashMap::new();
    for (t, v) in tlvs(body) {
        match t {
            57 if v.len() >= 9 => seid = Some(u64::from_be_bytes(v[1..9].try_into().unwrap())),
            8 => {
                let inner = tlvs(v);
                let id = inner
                    .iter()
                    .find(|(t, v)| *t == pfcp_ie::PDR_ID && v.len() >= 2)
                    .map(|(_, v)| u16::from_be_bytes([v[0], v[1]]));
                let f = inner
                    .iter()
                    .find(|(t, v)| *t == pfcp_ie::F_TEID && v.len() >= 9 && v[0] & 0x01 != 0)
                    .map(|(_, v)| {
                        (
                            u32::from_be_bytes(v[1..5].try_into().unwrap()),
                            [v[5], v[6], v[7], v[8]],
                        )
                    });
                if let (Some(id), Some(f)) = (id, f) {
                    fteids.insert(id, f);
                }
            }
            _ => {}
        }
    }
    (seid, fteids)
}

fn tlvs(d: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= d.len() {
        let t = u16::from_be_bytes([d[at], d[at + 1]]);
        let l = u16::from_be_bytes([d[at + 2], d[at + 3]]) as usize;
        let Some(v) = d.get(at + 4..at + 4 + l) else {
            break;
        };
        out.push((t, v));
        at += 4 + l;
    }
    out
}

/// Insert the I-UPF on the new session `psa_seid` (DNN `dnn`, flow `qfi`, PSA
/// UL F-TEID `psa_ul`) when one is configured for it (TS 23.502 §4.3.5.4).
/// Returns the leg, whose N3 F-TEID the NG-RAN is then given; `None` when no
/// I-UPF applies, or when it could not be inserted, in which case the session is
/// served by the PSA alone (logged).
pub async fn insert(psa_seid: u64, dnn: &str, psa_ul: (u32, [u8; 4])) -> Option<IupfLeg> {
    let client = applies_to(dnn)?;
    // R43 minor 4 on #2243: the leg SEID is the PSA's with bit 47 set, so a PSA
    // SEID that already has it (an EPC epoch past 2^15) gets no I-UPF.
    if is_leg_seid(psa_seid) {
        log::error!(
            "PSA SEID 0x{psa_seid:016x} has bit 47 set: no I-UPF leg SEID can be derived; \
             served by the PSA alone"
        );
        return None;
    }
    if !client.is_associated().await {
        log::warn!(
            "I-UPF {} has no PFCP association: the session on DNN {dnn} is served by its PSA \
             alone",
            client.peer()
        );
        return None;
    }
    let body = establishment_body(&client, psa_seid, psa_ul);
    let resp = client
        .session_request(
            pfcp_path::pfcp_message_type::SESSION_ESTABLISHMENT_REQUEST,
            leg_seid(psa_seid),
            Some(0),
            &body,
        )
        .await;
    let resp = match resp {
        Ok((t, r)) if t == pfcp_path::pfcp_message_type::SESSION_ESTABLISHMENT_RESPONSE => r,
        Ok((t, _)) => {
            log::warn!(
                "I-UPF answered Session Establishment with type {t}: served by the PSA alone"
            );
            return None;
        }
        Err(e) => {
            log::warn!("I-UPF Session Establishment failed ({e}): served by the PSA alone");
            return None;
        }
    };
    if pfcp_path::parse_cause(&resp) != Some(pfcp_path::pfcp_cause::REQUEST_ACCEPTED) {
        log::warn!(
            "I-UPF rejected the Session Establishment (cause {:?}): served by the PSA alone",
            pfcp_path::parse_cause(&resp)
        );
        return None;
    }
    let (seid, fteids) = parse_establishment_response(&resp);
    let (Some(upf_seid), Some(n3), Some(n9)) = (seid, fteids.get(&1), fteids.get(&2)) else {
        log::warn!(
            "I-UPF Session Establishment Response lacks its F-SEID or the N3/N9 F-TEIDs: \
             served by the PSA alone"
        );
        return None;
    };
    let leg = IupfLeg {
        smf_seid: leg_seid(psa_seid),
        upf_seid,
        n3: *n3,
        n9: *n9,
        psa_ul,
        dl_tunnel: None,
        idle_action: None,
    };
    store_leg(psa_seid, Some(leg));
    log::info!(
        "I-UPF {} inserted on N9 (TS 23.502 §4.3.5.4): N3 F-TEID 0x{:08x}@{:?}, N9 F-TEID \
         0x{:08x}@{:?}, toward the PSA's 0x{:08x}@{:?}",
        client.peer(),
        n3.0,
        n3.1,
        n9.0,
        n9.1,
        psa_ul.0,
        psa_ul.1
    );
    Some(leg)
}

/// The I-UPF leg went with its session.
pub fn forget(psa_seid: u64) {
    store_leg(psa_seid, None);
}

/// Which way a split Session Modification moves the session's downlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Nothing for the I-UPF: the PSA's alone.
    PsaOnly,
    /// FAR 2 gets an NG-RAN tunnel (activation, handover, path switch): the
    /// I-UPF first, so the PSA forwards only to an I-UPF that can deliver.
    TowardActive((u32, [u8; 4])),
    /// FAR 2's Apply Action alone changes (AN release, BUFF|NOCP): the PSA
    /// first, so it buffers before the I-UPF stops, and nothing is lost between.
    ApplyAction(u16),
}

/// A Session Modification of a PSA session with an I-UPF, split (see the module
/// docs), with what undoes each half when the other fails (R43 M1 on #2243:
/// "a rejected or failed request applies nothing").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Split {
    pub psa: Vec<u8>,
    pub iupf: Option<Vec<u8>>,
    pub direction: Direction,
    /// Puts the I-UPF's FAR 2 back as it was: its previous NG-RAN tunnel, or BUFF.
    pub iupf_restore: Vec<u8>,
    /// Puts the PSA's FAR 2 back as it was: FORW to the I-UPF over N9 while the
    /// I-UPF had a tunnel, else BUFF.
    pub psa_restore: Vec<u8>,
}

fn far2_to(tunnel: Option<(u32, [u8; 4])>, idle_action: Option<u16>) -> Vec<u8> {
    let far = match tunnel {
        Some((teid, ip)) => n4_build::build_update_far_activate(
            crate::DL_FAR_ID,
            0,
            Some((0x0100, teid, Some(ip), None)),
            false,
        ),
        None => n4_build::build_update_far_apply_action(
            crate::DL_FAR_ID,
            idle_action.unwrap_or(n4_build::apply_action::BUFF),
        ),
    };
    let mut b = PfcpMessageBuilder::new();
    b.add_tlv(pfcp_ie::UPDATE_FAR, &far);
    b.build()
}

/// PFCPSMReq-Flags (TS 29.244 §8.2.31) bits: SNDEM (End Markers on the old
/// tunnel) is the I-UPF's, which holds the NG-RAN tunnel; DROBU and QAURR are the
/// PSA's, which holds the buffer and the URRs (R43 minor 2 on #2243).
const SNDEM: u8 = 0x02;

/// Split a Session Modification Request `body` for the PSA session with I-UPF
/// `leg` (see the module docs).
pub fn split_modification(body: &[u8], leg: &IupfLeg) -> Split {
    let mut psa = Vec::new();
    let mut iupf = Vec::new();
    let mut flags: u8 = 0;
    let mut direction = Direction::PsaOnly;
    let push = |out: &mut Vec<u8>, t: u16, v: &[u8]| {
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&(v.len() as u16).to_be_bytes());
        out.extend_from_slice(v);
    };
    for (t, v) in tlvs(body) {
        if t == pfcp_ie::PFCPSMREQ_FLAGS {
            flags |= v.first().copied().unwrap_or(0);
            continue;
        }
        if t != pfcp_ie::UPDATE_FAR {
            push(&mut psa, t, v);
            continue;
        }
        let inner = tlvs(v);
        let far_id = inner
            .iter()
            .find(|(t, v)| *t == pfcp_ie::FAR_ID && v.len() >= 4)
            .map(|(_, v)| u32::from_be_bytes(v[..4].try_into().unwrap()));
        if far_id != Some(crate::DL_FAR_ID) {
            push(&mut psa, t, v);
            continue;
        }
        let ohc = inner
            .iter()
            .find(|(t, _)| *t == pfcp_ie::UPDATE_FORWARDING_PARAMETERS)
            .and_then(|(_, v)| {
                tlvs(v)
                    .into_iter()
                    .find(|(t, _)| *t == pfcp_ie::OUTER_HEADER_CREATION)
                    .map(|(_, o)| o.to_vec())
            });
        push(&mut iupf, t, v);
        if let Some(o) = ohc {
            // The NG-RAN tunnel is the I-UPF's; the PSA forwards to the I-UPF.
            let tunnel = (o.len() >= 10).then(|| {
                (
                    u32::from_be_bytes(o[2..6].try_into().unwrap()),
                    [o[6], o[7], o[8], o[9]],
                )
            });
            direction = Direction::TowardActive(tunnel.unwrap_or((0, [0; 4])));
            let far = n4_build::build_update_far_activate(
                crate::DL_FAR_ID,
                0,
                Some((0x0100, leg.n9.0, Some(leg.n9.1), None)),
                false,
            );
            push(&mut psa, pfcp_ie::UPDATE_FAR, &far);
        } else {
            let action = inner
                .iter()
                .find(|(t, v)| *t == pfcp_ie::APPLY_ACTION && !v.is_empty())
                .map(|(_, v)| {
                    let hi = v.get(1).copied().unwrap_or(0);
                    u16::from(v[0]) | (u16::from(hi) << 8)
                })
                .unwrap_or(0);
            if !matches!(direction, Direction::TowardActive(_)) {
                direction = Direction::ApplyAction(action);
            }
            push(&mut psa, t, v);
        }
    }
    let psa_flags = flags & !SNDEM;
    let iupf_flags = flags & SNDEM;
    let with_flags = |f: u8, rest: Vec<u8>| {
        if f == 0 {
            return rest;
        }
        let mut out = Vec::new();
        push(&mut out, pfcp_ie::PFCPSMREQ_FLAGS, &[f]);
        out.extend_from_slice(&rest);
        out
    };
    let iupf = if iupf.is_empty() {
        None
    } else {
        Some(with_flags(iupf_flags, iupf))
    };
    // SNDEM with nothing for the I-UPF has no tunnel to send End Markers on.
    let psa = with_flags(if iupf.is_none() { flags } else { psa_flags }, psa);
    if iupf.is_none() {
        direction = Direction::PsaOnly;
    }
    Split {
        psa,
        iupf,
        direction,
        iupf_restore: far2_to(leg.dl_tunnel, leg.idle_action),
        psa_restore: far2_to(leg.dl_tunnel.map(|_| leg.n9), leg.idle_action),
    }
}

/// Record the I-UPF's NG-RAN tunnel after a split that both UPFs accepted.
pub fn note_applied(psa_seid: u64, direction: Direction) {
    let Some(mut leg) = leg_of(psa_seid) else {
        return;
    };
    match direction {
        Direction::TowardActive(t) => leg.dl_tunnel = Some(t),
        Direction::ApplyAction(a) if a & n4_build::apply_action::FORW == 0 => {
            leg.dl_tunnel = None;
            leg.idle_action = Some(a);
        }
        _ => return,
    }
    store_leg(psa_seid, Some(leg));
}

/// The PSA session `psa_seid` went without an N4 Deletion reaching its I-UPF
/// (association loss, a restart, an unrestorable session; R43 M2 on #2243): its
/// leg is forgotten and the I-UPF's session deleted, so the I-UPF relays nothing
/// toward a PSA tunnel that is gone. A deletion the I-UPF does not answer is
/// queued and sent again once it is associated again (#2225).
pub fn release_leg(psa_seid: u64) {
    let Some(leg) = leg_of(psa_seid) else {
        return;
    };
    forget(psa_seid);
    let Some(client) = client() else {
        return;
    };
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        log::warn!(
            "I-UPF leg of SEID 0x{psa_seid:016x} forgotten; no runtime to delete its \
             session, queued"
        );
        queue_deletion(leg.smf_seid, leg.upf_seid);
        return;
    };
    rt.spawn(async move {
        if delete_on_iupf(&client, leg.smf_seid, leg.upf_seid).await {
            log::info!("I-UPF session of SEID 0x{psa_seid:016x} deleted: its PSA session is gone");
        } else {
            queue_deletion(leg.smf_seid, leg.upf_seid);
        }
    });
}

/// Every PSA session went at once (`clear_pfcp_sessions`): every leg is released.
pub fn release_all_legs() {
    let seids: Vec<u64> = {
        let ctx = crate::context::smf_self();
        let Ok(ctx) = ctx.read() else {
            return;
        };
        let Ok(legs) = ctx.iupf_legs.read() else {
            return;
        };
        legs.keys().copied().collect()
    };
    for s in seids {
        release_leg(s);
    }
}

/// Restored legs with no I-UPF configured (R43 minor 3 on #2243): said once at
/// startup, since their sessions' modifications then fail until released.
pub fn warn_orphaned_legs() {
    if client().is_some() {
        return;
    }
    let n = crate::context::smf_self()
        .read()
        .ok()
        .and_then(|c| c.iupf_legs.read().ok().map(|l| l.len()))
        .unwrap_or(0);
    if n > 0 {
        log::warn!(
            "{n} restored session(s) have an I-UPF leg but smf.intermediate_upf is not \
             configured: their Session Modifications fail until they are released"
        );
    }
}

#[cfg(test)]
#[path = "iupf_tests.rs"]
mod tests;
