//! Broadcast MBS session contexts and the N2 Broadcast Session procedures they
//! drive (#1796).
//!
//! The MB-SMF creates a broadcast MBS session context with
//! Namf_MBSBroadcast_ContextCreate (TS 29.518 §5.6.2.2) and the AMF sends a
//! BROADCAST SESSION SETUP REQUEST to every NG-RAN node of the MBS service area
//! (TS 23.247 §7.3.1 step 3, TS 38.413 §8.17.1). ContextRelease (§5.6.2.4) sends
//! a BROADCAST SESSION RELEASE REQUEST to the nodes that were set up (TS 23.247
//! §7.3.2 step 4, TS 38.413 §8.17.3).
//!
//! The split of work:
//! - the SBI handler (`namf_server`) validates the request and calls
//!   [`NgapMcastContext::broadcast_create`] / [`NgapMcastContext::broadcast_delete`].
//!   It never touches SCTP.
//! - the NGAP task (`ngap_path::mbs_broadcast`) resolves the target nodes against
//!   its live associations and sends what [`NgapMcastContext::broadcast_plan`]
//!   returns, then feeds the nodes' answers back through
//!   [`NgapMcastContext::broadcast_setup_outcome`] and
//!   [`NgapMcastContext::broadcast_release_outcome`].
//! - everything the AMF must tell the MB-SMF after the ContextCreate response is
//!   a [`BroadcastNotify`] (Namf_MBSBroadcast_ContextStatusNotify, §5.6.2.5),
//!   sent in order per context by [`dispatch_notifies`].
//!
//! When the ContextCreate is answered (TS 29.518 §5.6.2.2 step 2a, TS 23.247
//! §7.3.1 step 7): on the FIRST successful node response, with the response
//! containers received so far and, when every node has answered, the completion
//! indication; with a failure when every node failed (or none serves the area);
//! and, so the MB-SMF's request does not time out, after
//! [`CREATE_ANSWER_WAIT`] with whatever arrived by then. Every later node answer
//! is reported with a ContextStatusNotify, the last one carrying the completion
//! indication.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nextgcore_ngap_gen::generated as ngap_gen;
use serde_json::{json, Value};
use tokio::sync::oneshot;

use crate::context::PlmnId;
use crate::ngap_mcast::{NgapMcastContext, Tmgi};

/// The most broadcast MBS session contexts the AMF holds (#1856). A ContextCreate
/// past it (other than a retry of a held context) is refused, 500
/// INSUFFICIENT_RESOURCES, before anything is stored.
pub const MAX_BROADCAST_CONTEXTS: usize = 4096;

/// The most released contexts whose NG-RAN Release Responses are still awaited.
/// Past it the oldest stops being tracked: its nodes were already sent the
/// Release, only their Release Response Transfers would go unreported.
const MAX_RELEASING: usize = 1024;

/// The most concurrent ContextCreate requests waiting on one context's first
/// NG-RAN answer (a retry while the first is still waiting is one of them).
const MAX_WAITERS: usize = 8;

/// `n2MbsSmInfoList` is `maxItems: 10` in ContextCreateRspData and
/// ContextStatusNotification (`TS29518_Namf_MBSBroadcast.yaml`).
pub const N2_MBS_SM_INFO_LIST_MAX: usize = 10;

/// `maxnoofTAIforMBS` (`ngap-17.9.asn:11413`), the bound on `MBS-ServiceAreaTAIList`.
pub const MAX_SERVICE_AREA_TAIS: usize = 1024;

/// `maxnoofCellsforMBS` (`ngap-17.9.asn:11362`), the bound on `MBS-ServiceAreaCellList`.
pub const MAX_SERVICE_AREA_CELLS: usize = 8192;

/// How often the NGAP task re-checks the contexts when nothing changed: node
/// loss and the MB-SMF's `maxResponseTime` are time- not event-driven.
const SCAN_INTERVAL: Duration = Duration::from_secs(1);

/// How long a ContextCreate waits for the first NG-RAN answer before it is
/// answered with what arrived (the MB-SMF's own request times out at 3 s).
#[cfg(not(test))]
pub const CREATE_ANSWER_WAIT: Duration = Duration::from_secs(2);
#[cfg(test)]
pub const CREATE_ANSWER_WAIT: Duration = Duration::from_millis(300);

/// How long a release waits for its NG-RAN Release Responses before it is over
/// and the unanswered nodes are reported (TS 29.518 §5.6.2.4).
#[cfg(not(test))]
pub const RELEASE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
pub const RELEASE_RESPONSE_TIMEOUT: Duration = Duration::from_millis(400);

/// How long a ContextRelease waits for the NG-RAN Release Responses before it
/// answers (TS 23.247 §7.3.2 steps 7-8: the AMF answers after the NG-RAN).
#[cfg(not(test))]
pub const DELETE_ANSWER_WAIT: Duration = Duration::from_secs(1);
#[cfg(test)]
pub const DELETE_ANSWER_WAIT: Duration = Duration::from_millis(300);

/// `NgapIeType` values (TS 29.518 §6.5.6.3.4).
pub mod ngap_ie_type {
    /// MBS Session Setup or Modification Request Transfer.
    pub const MBS_SES_REQ: &str = "MBS_SES_REQ";
    /// MBS Session Setup or Modification Response Transfer.
    pub const MBS_SES_RSP: &str = "MBS_SES_RSP";
    /// MBS Session Setup or Modification Failure Transfer.
    pub const MBS_SES_FAIL: &str = "MBS_SES_FAIL";
    /// MBS Session Release Response Transfer.
    pub const MBS_SES_REL_RSP: &str = "MBS_SES_REL_RSP";
}

/// An NG-RAN node as the MB-SMF is told about it (`GlobalRanNodeId`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RanNode {
    pub plmn: PlmnId,
    pub gnb_id: u32,
    pub gnb_id_len: u8,
}

impl RanNode {
    fn json(&self) -> Value {
        crate::namf_server::global_ran_node_id_json(&self.plmn, self.gnb_id, self.gnb_id_len)
    }
}

/// A connected NG-RAN node, as the NGAP task sees it after NG Setup.
#[derive(Debug, Clone)]
pub struct LiveGnb {
    pub association_id: u64,
    pub node: RanNode,
    /// Every (broadcast PLMN, TAC) of its Supported TA List.
    pub tais: Vec<(PlmnId, u32)>,
}

/// A cell of the MBS service area (`NcgiTai`: the cell and the TAI it is in).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastCell {
    pub tai: (PlmnId, u32),
    pub plmn: PlmnId,
    /// The 36-bit NR Cell Identity.
    pub nci: u64,
}

/// A location-independent MBS service area (TS 29.571 `MbsServiceArea`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BroadcastServiceArea {
    pub tais: Vec<(PlmnId, u32)>,
    pub cells: Vec<BroadcastCell>,
}

impl BroadcastServiceArea {
    /// Whether `gnb` serves this area: it supports one of its TAIs, or it owns
    /// one of its cells (the gNB ID is the NCI's leftmost `gnb_id_len` bits,
    /// TS 38.413 §9.3.1.7) in a TA it supports.
    pub fn served_by(&self, gnb: &LiveGnb) -> bool {
        self.tais.iter().any(|t| gnb.tais.contains(t))
            || self.cells.iter().any(|c| {
                gnb.tais.contains(&c.tai)
                    && c.plmn == gnb.node.plmn
                    && cell_of_gnb(c.nci, &gnb.node)
            })
    }
}

fn cell_of_gnb(nci: u64, node: &RanNode) -> bool {
    let len = u32::from(node.gnb_id_len.clamp(22, 32));
    (nci >> (36 - len)) as u32 == node.gnb_id
}

/// A validated ContextCreate.
#[derive(Debug, Clone)]
pub struct BroadcastCreate {
    pub tmgi: Tmgi,
    /// The request's `mbsSessionId`, echoed in the response and notifications.
    pub mbs_session_id: Value,
    pub sst: u8,
    pub sd: Option<u32>,
    pub area: BroadcastServiceArea,
    /// The MB-SMF's MBS Session Setup or Modification Request Transfer.
    pub setup_transfer: Vec<u8>,
    pub notify_uri: String,
    pub max_response_time: Option<Duration>,
    /// The ContextCreate's `mbsmfId`: a repeat from the same MB-SMF for the TMGI
    /// is a retry of the same context (#1818).
    pub mbsmf_id: Option<String>,
}

/// Where one NG-RAN node stands in a broadcast MBS session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastGnbState {
    /// Sent the Setup Request, no answer yet.
    SetupSent,
    /// Answered with a Setup Response.
    Established,
    /// Answered with a Setup Failure.
    Failed,
    /// Its association went away (or the send failed) before or after setup.
    Lost,
}

/// An N2 MBS SM container for the MB-SMF, with the node that generated it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N2MbsSmContainer {
    pub ngap_ie_type: &'static str,
    pub data: Vec<u8>,
    pub ran_node: RanNode,
}

/// Why a ContextCreate failed after it was accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateFailure {
    /// No connected NG-RAN node serves the MBS service area.
    NoNgRan,
    /// Every NG-RAN node of the area failed the setup.
    AllRefused,
    /// A ContextRelease removed the context before any node answered.
    Deleted,
}

/// The ContextCreate answer.
#[derive(Debug, Clone, PartialEq)]
pub enum CreateAnswer {
    Created {
        /// The context's own `mbsContextRef` (#1818).
        context_ref: u64,
        mbs_session_id: Value,
        containers: Vec<N2MbsSmContainer>,
        /// Every NG-RAN node has answered (`MBS_SESSION_START_COMPLETE`).
        complete: bool,
    },
    Failed(CreateFailure),
}

impl CreateAnswer {
    /// The same answer, for the waiter of context `context_ref`.
    fn for_member(&self, member: &Member) -> Self {
        match self {
            Self::Created {
                containers,
                complete,
                ..
            } => Self::Created {
                context_ref: member.context_ref,
                mbs_session_id: member.mbs_session_id.clone(),
                containers: containers.clone(),
                complete: *complete,
            },
            Self::Failed(f) => Self::Failed(*f),
        }
    }
}

/// What [`NgapMcastContext::broadcast_create`] did.
#[derive(Debug)]
pub enum CreateStart {
    /// The context already existed and was answered: this is its state.
    Answered(CreateAnswer),
    /// Wait on `rx` for the answer (then [`NgapMcastContext::broadcast_answer_on_timeout`]).
    Wait {
        context_ref: u64,
        rx: oneshot::Receiver<CreateAnswer>,
    },
    /// [`MAX_BROADCAST_CONTEXTS`] reached: nothing was stored.
    Full,
}

/// What [`NgapMcastContext::broadcast_delete`] did.
#[derive(Debug)]
pub enum DeleteStart {
    NotFound,
    /// Removed, and no NG-RAN node is to be released: none holds the session,
    /// or another broadcast context still rides on it (#1818).
    Released,
    /// Removed; the Release goes to the nodes set up. Wait on `rx` for their
    /// Release Response Transfers (then [`NgapMcastContext::broadcast_release_answer_on_timeout`]).
    Wait {
        release_id: u64,
        rx: oneshot::Receiver<Vec<N2MbsSmContainer>>,
        notify_uri: String,
        mbs_session_id: Value,
    },
}

/// One Namf_MBSBroadcast_ContextStatusNotify request (TS 29.518 §5.6.2.5).
#[derive(Debug, Clone, PartialEq)]
pub struct BroadcastNotify {
    /// The context (`mbsContextRef`) it is for; one context's notifications are
    /// delivered in order.
    pub context_ref: u64,
    /// The MB-SMF's `notifyUri`, a callback URI: log it only redacted.
    pub callback_uri: String,
    pub body: Value,
    /// `(content id, NGAP octets)` for each `n2MbsSmInfoList` entry.
    pub parts: Vec<(String, Vec<u8>)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastProcedure {
    Setup,
    Release,
}

/// One NGAP PDU for the NGAP task to send on `associations`. `id` is the MBS
/// session id for a Setup and the release id for a Release.
#[derive(Debug, Clone)]
pub struct BroadcastSend {
    pub id: u64,
    pub tmgi: Tmgi,
    pub procedure: BroadcastProcedure,
    pub pdu: Vec<u8>,
    pub associations: Vec<u64>,
}

/// What the NGAP task must do now. Every Release precedes every Setup, so a
/// released session is gone at a gNB before a new one for the same TMGI is set
/// up on the same (ordered) association.
#[derive(Debug, Default)]
pub struct BroadcastPlan {
    pub sends: Vec<BroadcastSend>,
    pub notifies: Vec<BroadcastNotify>,
}

/// #1818: one Namf_MBSBroadcast context (`mbsContextRef`), as it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastContext {
    /// The MBS session (by TMGI) the context rides on.
    pub session_id: u64,
    /// The ContextCreate's `mbsmfId`, if it sent one.
    pub mbsmf_id: Option<String>,
}

#[derive(Debug)]
struct Gnb {
    association_id: u64,
    node: RanNode,
    state: BroadcastGnbState,
    container: Option<N2MbsSmContainer>,
    reported: bool,
    loss_reported: bool,
}

/// #1818: one ContextCreate resource riding on a broadcast session: whom it is
/// for and where its notifications go.
#[derive(Debug)]
struct Member {
    context_ref: u64,
    mbsmf_id: Option<String>,
    notify_uri: String,
    mbs_session_id: Value,
    waiters: Vec<oneshot::Sender<CreateAnswer>>,
}

/// A broadcast MBS session at the NG-RAN (one per TMGI), with the contexts on it.
#[derive(Debug)]
struct Ctx {
    session_id: u64,
    /// #1818: whether a ContextCreate created the MBS session (rather than
    /// joining one another path holds), so only then is it removed with the
    /// last context.
    owned: bool,
    req: BroadcastCreate,
    received_at: Instant,
    dispatched: bool,
    gnbs: Vec<Gnb>,
    answered: bool,
    complete_reported: bool,
    incomplete_reported: bool,
    members: Vec<Member>,
}

#[derive(Debug)]
struct Releasing {
    /// The context whose release this is.
    context_ref: u64,
    tmgi: Tmgi,
    mbs_session_id: Value,
    notify_uri: String,
    targets: Vec<(u64, RanNode)>,
    started: Instant,
    dispatched: bool,
    containers: Vec<N2MbsSmContainer>,
    answered: bool,
    waiters: Vec<oneshot::Sender<Vec<N2MbsSmContainer>>>,
}

#[derive(Debug, Default)]
struct Inner {
    contexts: HashMap<u64, Ctx>,
    /// By release id, ascending: the oldest outstanding release of a TMGI on a
    /// gNB is the one its Release Response answers.
    releasing: BTreeMap<u64, Releasing>,
    next_ref: u64,
    next_release: u64,
    last_scan: Option<Instant>,
}

impl Inner {
    fn member_count(&self) -> usize {
        self.contexts.values().map(|c| c.members.len()).sum()
    }

    fn ctx_of_ref(&mut self, context_ref: u64) -> Option<&mut Ctx> {
        self.contexts
            .values_mut()
            .find(|c| c.members.iter().any(|m| m.context_ref == context_ref))
    }
}

/// The broadcast half of [`NgapMcastContext`].
#[derive(Debug)]
pub struct BroadcastState {
    inner: Mutex<Inner>,
    dirty: AtomicBool,
    capacity: usize,
}

impl BroadcastState {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            dirty: AtomicBool::new(false),
            capacity,
        }
    }
}

impl Default for BroadcastState {
    fn default() -> Self {
        Self::new(MAX_BROADCAST_CONTEXTS)
    }
}

impl Ctx {
    fn all_responded(&self) -> bool {
        self.gnbs
            .iter()
            .all(|g| g.state != BroadcastGnbState::SetupSent)
    }

    fn any_established(&self) -> bool {
        self.gnbs
            .iter()
            .any(|g| g.state == BroadcastGnbState::Established)
    }

    /// Every node response container, for an answer to a repeated or joining
    /// ContextCreate.
    fn snapshot(&self, member: &Member) -> CreateAnswer {
        CreateAnswer::Created {
            context_ref: member.context_ref,
            mbs_session_id: member.mbs_session_id.clone(),
            containers: self
                .gnbs
                .iter()
                .filter_map(|g| g.container.clone())
                .take(N2_MBS_SM_INFO_LIST_MAX)
                .collect(),
            complete: self.complete_reported,
        }
    }

    /// The containers not yet reported to the MB-SMF, at most `max`, marked reported.
    fn take_unreported(&mut self, max: usize) -> Vec<N2MbsSmContainer> {
        let mut out = Vec::new();
        for g in self.gnbs.iter_mut() {
            if out.len() == max {
                break;
            }
            if let (false, Some(c)) = (g.reported, g.container.as_ref()) {
                out.push(c.clone());
                g.reported = true;
            }
        }
        out
    }

    fn answer_waiters(&mut self, answer: &CreateAnswer) {
        for m in self.members.iter_mut() {
            let mine = answer.for_member(m);
            for w in m.waiters.drain(..) {
                let _ = w.send(mine.clone());
            }
        }
    }

    /// One notification per context on the session, each to its own notifyUri.
    fn notify(&self, containers: &[N2MbsSmContainer]) -> Vec<BroadcastNotify> {
        self.members
            .iter()
            .map(|m| {
                status_notify(
                    m.context_ref,
                    &m.notify_uri,
                    &m.mbs_session_id,
                    containers.to_vec(),
                )
            })
            .collect()
    }

    /// Bring the MB-SMF up to date after a change: answer the ContextCreate when
    /// TS 29.518 §5.6.2.2 says so, otherwise notify what it has not been told.
    /// Returns whether the session is over and must be removed.
    fn settle(&mut self, notifies: &mut Vec<BroadcastNotify>) -> bool {
        if !self.dispatched {
            return false;
        }
        let responded = self.all_responded();
        if !self.answered {
            if self.any_established() {
                self.answered = true;
                let containers = self.take_unreported(N2_MBS_SM_INFO_LIST_MAX);
                let leftovers = self
                    .gnbs
                    .iter()
                    .any(|g| !g.reported && g.container.is_some());
                let complete = responded && !leftovers;
                self.complete_reported = complete;
                let answer = CreateAnswer::Created {
                    context_ref: 0,
                    mbs_session_id: Value::Null,
                    containers,
                    complete,
                };
                self.answer_waiters(&answer);
            } else if responded {
                // TS 23.247 §7.3.1 step 7: "if all NG-RAN(s) report failure, the
                // AMF should respond failure" -- and nothing is kept.
                let failure = if self.gnbs.is_empty() {
                    CreateFailure::NoNgRan
                } else {
                    CreateFailure::AllRefused
                };
                self.answer_waiters(&CreateAnswer::Failed(failure));
                return true;
            } else {
                return false;
            }
        }

        // Answered: what the MB-SMF has not been told goes in notifications.
        let mut batches: Vec<Vec<N2MbsSmContainer>> = Vec::new();
        loop {
            let containers = self.take_unreported(N2_MBS_SM_INFO_LIST_MAX);
            if containers.is_empty() {
                break;
            }
            batches.push(containers);
        }
        let lost: Vec<Value> = self
            .gnbs
            .iter_mut()
            .filter(|g| g.state == BroadcastGnbState::Lost && !g.loss_reported)
            .map(|g| {
                g.loss_reported = true;
                lost_event(&g.node)
            })
            .collect();
        let complete_now = responded && !self.complete_reported;
        let released = responded && !self.any_established();
        if (complete_now || !lost.is_empty() || released) && batches.is_empty() {
            batches.push(Vec::new());
        }
        let last = batches.len().saturating_sub(1);
        for (i, batch) in batches.iter().enumerate() {
            for mut n in self.notify(batch) {
                if i == last {
                    if complete_now {
                        n.body["operationStatus"] = json!("MBS_SESSION_START_COMPLETE");
                    }
                    if !lost.is_empty() {
                        n.body["operationEvents"] = ng_ran_events(&lost);
                    }
                    if released {
                        // No NG-RAN node holds the session any more: it is released
                        // and the MB-SMF told so (TS 29.518 §5.6.2.5, releasedInd).
                        n.body["releasedInd"] = json!(true);
                    }
                }
                notifies.push(n);
            }
        }
        if complete_now {
            self.complete_reported = true;
        }
        released
    }
}

fn lost_event(node: &RanNode) -> Value {
    json!({
        "ngranId": node.json(),
        "ngranFailureIndication": "NG_RAN_NOT_REACHABLE",
    })
}

/// `operationEvents` reporting `list` NG-RAN failures (TS 29.518 §5.6.2.4/5.6.2.5).
fn ng_ran_events(list: &[Value]) -> Value {
    json!([{ "opEventType": "NG_RAN_EVENT", "ngranFailureEventList": list }])
}

impl Releasing {
    /// Returns whether the release is over and must be forgotten.
    fn settle(&mut self, notifies: &mut Vec<BroadcastNotify>) -> bool {
        if !self.dispatched {
            return false;
        }
        let done = self.targets.is_empty();
        if !self.answered {
            if done {
                self.answered = true;
                let containers = std::mem::take(&mut self.containers);
                for w in self.waiters.drain(..) {
                    let _ = w.send(containers.clone());
                }
            }
        } else {
            while !self.containers.is_empty() {
                let n = self.containers.len().min(N2_MBS_SM_INFO_LIST_MAX);
                let chunk: Vec<_> = self.containers.drain(..n).collect();
                notifies.push(status_notify(
                    self.context_ref,
                    &self.notify_uri,
                    &self.mbs_session_id,
                    chunk,
                ));
            }
        }
        done
    }
}

/// A ContextStatusNotification carrying `containers` in `n2MbsSmInfoList`, each
/// with the `ranId` of the node that generated it (TS 29.518 §5.6.2.5 step 1).
fn status_notify(
    context_ref: u64,
    callback_uri: &str,
    mbs_session_id: &Value,
    containers: Vec<N2MbsSmContainer>,
) -> BroadcastNotify {
    let mut body = json!({ "mbsSessionId": mbs_session_id });
    let (list, parts) = n2_mbs_sm_info_list(containers);
    if !list.is_empty() {
        body["n2MbsSmInfoList"] = Value::Array(list);
    }
    BroadcastNotify {
        context_ref,
        callback_uri: callback_uri.to_string(),
        body,
        parts,
    }
}

/// `n2MbsSmInfoList` entries and their binary parts (`n2-1`, `n2-2`, ...).
pub fn n2_mbs_sm_info_list(
    containers: Vec<N2MbsSmContainer>,
) -> (Vec<Value>, Vec<(String, Vec<u8>)>) {
    containers
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            let cid = format!("n2-{}", i + 1);
            (
                json!({
                    "ngapIeType": c.ngap_ie_type,
                    "ngapData": { "contentId": cid },
                    "ranId": c.ran_node.json(),
                }),
                (cid, c.data),
            )
        })
        .unzip()
}

impl NgapMcastContext {
    fn broadcast_inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.broadcast
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Remove the broadcast session `session_id` (every context on it gone, or
    /// its setup failed): the MBS session goes with it only when a ContextCreate
    /// created it (#1818).
    fn drop_broadcast_session(&self, inner: &mut Inner, session_id: u64) {
        if let Some(ctx) = inner.contexts.remove(&session_id) {
            if ctx.owned {
                self.session_remove(session_id);
            }
        }
    }

    /// ContextCreate (TS 29.518 §5.6.2.2). Each ContextCreate gets a context of
    /// its own (#1818) on the TMGI's broadcast session; a repeat from the same
    /// `mbsmfId` is a retry and gets the same context. Only the first context on a
    /// TMGI sends a Setup (from the NGAP task); a later one rides on the session
    /// the NG-RAN already holds. A new context is stored only below the cap.
    pub fn broadcast_create(&self, req: BroadcastCreate, now: Instant) -> CreateStart {
        let mbsmf_id = req.mbsmf_id.clone();
        let mut inner = self.broadcast_inner();
        let total = inner.member_count();
        let capacity = self.broadcast.capacity;
        let next_ref = inner.next_ref + 1;
        let joined = inner
            .contexts
            .iter()
            .find(|(_, c)| c.req.tmgi == req.tmgi)
            .map(|(sid, c)| (*sid, c.members.iter().position(|m| m.mbsmf_id == mbsmf_id)));
        if let Some((sid, existing)) = joined {
            let idx = match existing {
                Some(i) => i,
                None => {
                    if total >= capacity {
                        return CreateStart::Full;
                    }
                    inner.next_ref = next_ref;
                    let ctx = inner.contexts.get_mut(&sid).expect("found above");
                    ctx.members.push(Member {
                        context_ref: next_ref,
                        mbsmf_id,
                        notify_uri: req.notify_uri.clone(),
                        mbs_session_id: req.mbs_session_id.clone(),
                        waiters: Vec::new(),
                    });
                    ctx.members.len() - 1
                }
            };
            return join(inner.contexts.get_mut(&sid).expect("found above"), idx);
        }
        if total >= capacity {
            log::warn!(
                "Namf_MBSBroadcast ContextCreate refused: {total} broadcast MBS contexts held"
            );
            return CreateStart::Full;
        }
        // #1818: join the MBS session another path holds for the TMGI, or create one.
        let (session, owned) = match self.session_find_by_tmgi(&req.tmgi) {
            Some(s) => (s, false),
            None => {
                let area_tacs = req.area.tais.iter().map(|(_, tac)| *tac).collect();
                match self.session_create(req.tmgi.clone(), req.sst, req.sd, area_tacs) {
                    Some(s) => (s, true),
                    None => return CreateStart::Full,
                }
            }
        };
        inner.next_ref = next_ref;
        let (tx, rx) = oneshot::channel();
        let session_id = session.mbs_session_id;
        let member = Member {
            context_ref: next_ref,
            mbsmf_id,
            notify_uri: req.notify_uri.clone(),
            mbs_session_id: req.mbs_session_id.clone(),
            waiters: vec![tx],
        };
        inner.contexts.insert(
            session_id,
            Ctx {
                session_id,
                owned,
                req,
                received_at: now,
                dispatched: false,
                gnbs: Vec::new(),
                answered: false,
                complete_reported: false,
                incomplete_reported: false,
                members: vec![member],
            },
        );
        self.broadcast.dirty.store(true, Ordering::SeqCst);
        CreateStart::Wait {
            context_ref: next_ref,
            rx,
        }
    }

    /// The ContextCreate answer when [`CREATE_ANSWER_WAIT`] ran out before the
    /// first NG-RAN success: the context exists, its setup is in progress, and
    /// what arrives later is notified. `None` when it was already answered (the
    /// waiter has the answer) or is gone.
    pub fn broadcast_answer_on_timeout(&self, context_ref: u64) -> Option<CreateAnswer> {
        let mut inner = self.broadcast_inner();
        let ctx = inner.ctx_of_ref(context_ref)?;
        if ctx.answered {
            return None;
        }
        ctx.answered = true;
        let answer = CreateAnswer::Created {
            context_ref: 0,
            mbs_session_id: Value::Null,
            containers: ctx.take_unreported(N2_MBS_SM_INFO_LIST_MAX),
            complete: false,
        };
        let mine = ctx
            .members
            .iter()
            .find(|m| m.context_ref == context_ref)
            .map(|m| answer.for_member(m));
        ctx.answer_waiters(&answer);
        // Anything past the 10 the answer carried is notified on the next scan.
        self.broadcast.dirty.store(true, Ordering::SeqCst);
        mine
    }

    /// ContextRelease (TS 29.518 §5.6.2.4) of context `context_ref` (#1818: only
    /// that context). While another context rides on the broadcast session, the
    /// NG-RAN keeps it. When this was the last one, the session is removed at once
    /// (so a new ContextCreate for the TMGI starts afresh) and the Release goes to
    /// every node that was sent the Setup and did not fail it.
    pub fn broadcast_delete(&self, context_ref: u64) -> DeleteStart {
        let mut inner = self.broadcast_inner();
        let Some(ctx) = inner.ctx_of_ref(context_ref) else {
            return DeleteStart::NotFound;
        };
        let pos = ctx
            .members
            .iter()
            .position(|m| m.context_ref == context_ref)
            .expect("found above");
        let mut member = ctx.members.remove(pos);
        for w in member.waiters.drain(..) {
            let _ = w.send(CreateAnswer::Failed(CreateFailure::Deleted));
        }
        if !ctx.members.is_empty() {
            return DeleteStart::Released;
        }
        let session_id = ctx.session_id;
        let targets: Vec<(u64, RanNode)> = ctx
            .gnbs
            .iter()
            .filter(|g| {
                matches!(
                    g.state,
                    BroadcastGnbState::SetupSent | BroadcastGnbState::Established
                )
            })
            .map(|g| (g.association_id, g.node.clone()))
            .collect();
        let tmgi = ctx.req.tmgi.clone();
        self.drop_broadcast_session(&mut inner, session_id);
        if targets.is_empty() {
            return DeleteStart::Released;
        }
        if inner.releasing.len() >= MAX_RELEASING {
            if let Some((oldest, _)) = inner.releasing.pop_first() {
                log::warn!(
                    "{MAX_RELEASING} broadcast MBS releases awaiting NG-RAN responses; no longer \
                     tracking release {oldest}"
                );
            }
        }
        inner.next_release += 1;
        let release_id = inner.next_release;
        let (tx, rx) = oneshot::channel();
        inner.releasing.insert(
            release_id,
            Releasing {
                context_ref,
                tmgi,
                mbs_session_id: member.mbs_session_id.clone(),
                notify_uri: member.notify_uri.clone(),
                targets,
                started: Instant::now(),
                dispatched: false,
                containers: Vec::new(),
                answered: false,
                waiters: vec![tx],
            },
        );
        self.broadcast.dirty.store(true, Ordering::SeqCst);
        DeleteStart::Wait {
            release_id,
            rx,
            notify_uri: member.notify_uri,
            mbs_session_id: member.mbs_session_id,
        }
    }

    /// The Release Response Transfers received so far, when
    /// [`DELETE_ANSWER_WAIT`] ran out; later ones are notified.
    pub fn broadcast_release_answer_on_timeout(&self, release_id: u64) -> Vec<N2MbsSmContainer> {
        let mut inner = self.broadcast_inner();
        let Some(r) = inner.releasing.get_mut(&release_id) else {
            return Vec::new();
        };
        if r.answered {
            return Vec::new();
        }
        r.answered = true;
        r.waiters.clear();
        std::mem::take(&mut r.containers)
    }

    /// Whether the NGAP task has broadcast work: a change since the last plan, or
    /// a periodic re-check of held contexts. Claims the work when it returns true.
    pub fn broadcast_has_work(&self, now: Instant) -> bool {
        let mut inner = self.broadcast_inner();
        if inner.contexts.is_empty() && inner.releasing.is_empty() {
            return false;
        }
        let dirty = self.broadcast.dirty.swap(false, Ordering::SeqCst);
        let due = inner
            .last_scan
            .is_none_or(|t| now.saturating_duration_since(t) >= SCAN_INTERVAL);
        if dirty || due {
            inner.last_scan = Some(now);
            return true;
        }
        false
    }

    /// The NGAP task's step: send the Release Request of every released session
    /// and then the Setup Request of every new one (so a gNB drops an old session
    /// before it sets up a new one for the same TMGI), mark nodes whose association
    /// is gone as lost, report a passed `maxResponseTime`, end a release no gNB
    /// answered within [`RELEASE_RESPONSE_TIMEOUT`], and answer / notify the MB-SMF.
    pub fn broadcast_plan(&self, live: &[LiveGnb], now: Instant) -> BroadcastPlan {
        let mut plan = BroadcastPlan::default();
        let mut inner = self.broadcast_inner();

        let mut done = Vec::new();
        for (id, r) in inner.releasing.iter_mut() {
            r.targets.retain(|(assoc, node)| {
                live.iter()
                    .any(|l| l.association_id == *assoc && l.node == *node)
            });
            if !r.dispatched {
                r.dispatched = true;
                if !r.targets.is_empty() {
                    match build_broadcast_session_release_request(&r.tmgi) {
                        Some(pdu) => plan.sends.push(BroadcastSend {
                            id: *id,
                            tmgi: r.tmgi.clone(),
                            procedure: BroadcastProcedure::Release,
                            pdu,
                            associations: r.targets.iter().map(|(a, _)| *a).collect(),
                        }),
                        None => {
                            log::error!(
                                "BroadcastSessionReleaseRequest for release {id} could not be \
                                 encoded"
                            );
                            r.targets.clear();
                        }
                    }
                }
            } else if !r.targets.is_empty()
                && now.saturating_duration_since(r.started) >= RELEASE_RESPONSE_TIMEOUT
            {
                // TS 29.518 §5.6.2.4: the AMF may report the NG-RANs it failed to
                // reach. The release is over either way: nothing is kept for them.
                let unanswered: Vec<Value> = r
                    .targets
                    .drain(..)
                    .map(|(_, node)| lost_event(&node))
                    .collect();
                log::warn!(
                    "Broadcast MBS release {id}: {} NG-RAN node(s) did not answer the Release \
                     within {RELEASE_RESPONSE_TIMEOUT:?}",
                    unanswered.len()
                );
                let mut n =
                    status_notify(r.context_ref, &r.notify_uri, &r.mbs_session_id, Vec::new());
                n.body["operationEvents"] = ng_ran_events(&unanswered);
                // The containers already received go first.
                r.settle(&mut plan.notifies);
                plan.notifies.push(n);
            }
            if r.settle(&mut plan.notifies) {
                done.push(*id);
            }
        }
        for id in done {
            inner.releasing.remove(&id);
        }

        let mut over = Vec::new();
        for ctx in inner.contexts.values_mut() {
            if !ctx.dispatched {
                ctx.dispatched = true;
                let targets: Vec<&LiveGnb> =
                    live.iter().filter(|g| ctx.req.area.served_by(g)).collect();
                if !targets.is_empty() {
                    match build_broadcast_session_setup_request(&ctx.req) {
                        Some(pdu) => {
                            ctx.gnbs = targets
                                .iter()
                                .map(|g| Gnb {
                                    association_id: g.association_id,
                                    node: g.node.clone(),
                                    state: BroadcastGnbState::SetupSent,
                                    container: None,
                                    reported: false,
                                    loss_reported: false,
                                })
                                .collect();
                            plan.sends.push(BroadcastSend {
                                id: ctx.session_id,
                                tmgi: ctx.req.tmgi.clone(),
                                procedure: BroadcastProcedure::Setup,
                                pdu,
                                associations: targets.iter().map(|g| g.association_id).collect(),
                            });
                        }
                        None => log::error!(
                            "BroadcastSessionSetupRequest for MBS session {} could not be \
                             encoded; no NG-RAN node was sent it",
                            ctx.session_id
                        ),
                    }
                } else {
                    log::warn!(
                        "Broadcast MBS session {}: no connected NG-RAN node serves its MBS \
                         service area",
                        ctx.session_id
                    );
                }
            } else {
                for g in ctx.gnbs.iter_mut() {
                    if matches!(
                        g.state,
                        BroadcastGnbState::SetupSent | BroadcastGnbState::Established
                    ) && !live
                        .iter()
                        .any(|l| l.association_id == g.association_id && l.node == g.node)
                    {
                        log::warn!(
                            "Broadcast MBS session {}: NG-RAN node {:#x} (association {}) is \
                             gone ({:?})",
                            ctx.session_id,
                            g.node.gnb_id,
                            g.association_id,
                            g.state
                        );
                        g.state = BroadcastGnbState::Lost;
                    }
                }
            }
            if let Some(max) = ctx.req.max_response_time {
                if ctx.answered
                    && !ctx.incomplete_reported
                    && !ctx.all_responded()
                    && now.saturating_duration_since(ctx.received_at) >= max
                {
                    // TS 29.518 §5.6.2.2 step 2a: one notification of the
                    // incompletion once maxResponseTime has elapsed.
                    ctx.incomplete_reported = true;
                    for mut n in ctx.notify(&[]) {
                        n.body["operationStatus"] = json!("MBS_SESSION_START_INCOMPLETE");
                        plan.notifies.push(n);
                    }
                }
            }
            if ctx.settle(&mut plan.notifies) {
                over.push(ctx.session_id);
            }
        }
        for id in over {
            self.drop_broadcast_session(&mut inner, id);
        }
        plan
    }

    /// The NGAP task could not send `procedure` to `association_id`: the node is
    /// treated as gone for that session (`id` as in [`BroadcastSend`]).
    pub fn broadcast_send_failed(
        &self,
        id: u64,
        procedure: BroadcastProcedure,
        association_id: u64,
    ) -> Vec<BroadcastNotify> {
        let mut notifies = Vec::new();
        let mut inner = self.broadcast_inner();
        match procedure {
            BroadcastProcedure::Setup => {
                let Some(ctx) = inner.contexts.get_mut(&id) else {
                    return notifies;
                };
                for g in ctx.gnbs.iter_mut() {
                    if g.association_id == association_id && g.state == BroadcastGnbState::SetupSent
                    {
                        g.state = BroadcastGnbState::Lost;
                    }
                }
                if ctx.settle(&mut notifies) {
                    self.drop_broadcast_session(&mut inner, id);
                }
            }
            BroadcastProcedure::Release => {
                let Some(r) = inner.releasing.get_mut(&id) else {
                    return notifies;
                };
                r.targets.retain(|(a, _)| *a != association_id);
                if r.settle(&mut notifies) {
                    inner.releasing.remove(&id);
                }
            }
        }
        notifies
    }

    /// A BROADCAST SESSION SETUP RESPONSE (`success`) or FAILURE from
    /// `association_id` for `tmgi`, with its optional transfer. Only the first
    /// answer of a node the Setup was sent to counts; anything else changes nothing.
    pub fn broadcast_setup_outcome(
        &self,
        tmgi: &Tmgi,
        association_id: u64,
        success: bool,
        transfer: Option<Vec<u8>>,
    ) -> Vec<BroadcastNotify> {
        let mut notifies = Vec::new();
        let mut inner = self.broadcast_inner();
        let Some(ctx) = inner.contexts.values_mut().find(|c| c.req.tmgi == *tmgi) else {
            log::warn!(
                "Broadcast Session Setup outcome for tmgi_svc={:#x} from association \
                 {association_id}: the AMF holds no such broadcast MBS session",
                tmgi.service_id_u32()
            );
            return notifies;
        };
        let Some(g) = ctx.gnbs.iter_mut().find(|g| {
            g.association_id == association_id && g.state == BroadcastGnbState::SetupSent
        }) else {
            log::warn!(
                "Broadcast Session Setup outcome for MBS session {} from association \
                 {association_id}, which has no Setup outstanding; ignored",
                ctx.session_id
            );
            return notifies;
        };
        g.state = if success {
            BroadcastGnbState::Established
        } else {
            BroadcastGnbState::Failed
        };
        g.container = transfer.map(|data| N2MbsSmContainer {
            ngap_ie_type: if success {
                ngap_ie_type::MBS_SES_RSP
            } else {
                ngap_ie_type::MBS_SES_FAIL
            },
            data,
            ran_node: g.node.clone(),
        });
        log::info!(
            "Broadcast MBS session {}: NG-RAN node {:#x} {}",
            ctx.session_id,
            g.node.gnb_id,
            if success {
                "set up the session"
            } else {
                "failed the setup"
            }
        );
        let session_id = ctx.session_id;
        if ctx.settle(&mut notifies) {
            self.drop_broadcast_session(&mut inner, session_id);
        }
        notifies
    }

    /// A BROADCAST SESSION RELEASE RESPONSE from `association_id` for `tmgi`. Its
    /// Release Response Transfer goes to the MB-SMF (TS 38.413 §8.17.3.2). When
    /// two releases of the TMGI are outstanding at the gNB, it answers the oldest:
    /// the gNB answers Release Requests in the order the association carried them.
    pub fn broadcast_release_outcome(
        &self,
        tmgi: &Tmgi,
        association_id: u64,
        transfer: Option<Vec<u8>>,
    ) -> Vec<BroadcastNotify> {
        let mut notifies = Vec::new();
        let mut inner = self.broadcast_inner();
        let Some((&id, r)) = inner.releasing.iter_mut().find(|(_, r)| {
            r.dispatched && r.tmgi == *tmgi && r.targets.iter().any(|(a, _)| *a == association_id)
        }) else {
            log::warn!(
                "Broadcast Session Release Response for tmgi_svc={:#x} from association \
                 {association_id}, which has no Release outstanding; ignored",
                tmgi.service_id_u32()
            );
            return notifies;
        };
        let pos = r
            .targets
            .iter()
            .position(|(a, _)| *a == association_id)
            .expect("found above");
        let (_, node) = r.targets.remove(pos);
        if let Some(data) = transfer {
            r.containers.push(N2MbsSmContainer {
                ngap_ie_type: ngap_ie_type::MBS_SES_REL_RSP,
                data,
                ran_node: node,
            });
        }
        if r.settle(&mut notifies) {
            inner.releasing.remove(&id);
        }
        notifies
    }

    /// Each node of the broadcast session context `context_ref` rides on, and
    /// where it stands.
    pub fn broadcast_gnb_states(&self, context_ref: u64) -> Option<Vec<(u64, BroadcastGnbState)>> {
        let mut inner = self.broadcast_inner();
        let ctx = inner.ctx_of_ref(context_ref)?;
        Some(
            ctx.gnbs
                .iter()
                .map(|g| (g.association_id, g.state))
                .collect(),
        )
    }

    /// #1818: the broadcast context `context_ref`, if held.
    pub fn broadcast_context_find(&self, context_ref: u64) -> Option<BroadcastContext> {
        let mut inner = self.broadcast_inner();
        let ctx = inner.ctx_of_ref(context_ref)?;
        let session_id = ctx.session_id;
        ctx.members
            .iter()
            .find(|m| m.context_ref == context_ref)
            .map(|m| BroadcastContext {
                session_id,
                mbsmf_id: m.mbsmf_id.clone(),
            })
    }

    /// The contexts held on `tmgi`'s broadcast session.
    pub fn broadcast_refs_of(&self, tmgi: &Tmgi) -> Vec<u64> {
        let inner = self.broadcast_inner();
        inner
            .contexts
            .values()
            .filter(|c| c.req.tmgi == *tmgi)
            .flat_map(|c| c.members.iter().map(|m| m.context_ref))
            .collect()
    }

    /// Whether the release of context `context_ref` still awaits NG-RAN Release
    /// Responses.
    pub fn broadcast_releasing(&self, context_ref: u64) -> bool {
        self.broadcast_inner()
            .releasing
            .values()
            .any(|r| r.context_ref == context_ref)
    }

    /// Have the next [`Self::broadcast_has_work`] re-check every context now
    /// rather than at the next periodic scan.
    pub fn broadcast_rescan(&self) {
        self.broadcast.dirty.store(true, Ordering::SeqCst);
    }

    /// How many broadcast MBS contexts are held.
    pub fn broadcast_count(&self) -> usize {
        self.broadcast_inner().member_count()
    }
}

/// A repeated or joining ContextCreate on `ctx` for member `idx`: answered with
/// the session's state, or waiting on its first NG-RAN answer.
fn join(ctx: &mut Ctx, idx: usize) -> CreateStart {
    if ctx.answered {
        return CreateStart::Answered(ctx.snapshot(&ctx.members[idx]));
    }
    let member = &mut ctx.members[idx];
    member.waiters.retain(|w| !w.is_closed());
    if member.waiters.len() >= MAX_WAITERS {
        let answer = CreateAnswer::Created {
            context_ref: member.context_ref,
            mbs_session_id: member.mbs_session_id.clone(),
            containers: Vec::new(),
            complete: false,
        };
        return CreateStart::Answered(answer);
    }
    let (tx, rx) = oneshot::channel();
    member.waiters.push(tx);
    CreateStart::Wait {
        context_ref: member.context_ref,
        rx,
    }
}

// ============================================================================
// NGAP builders (generated codec)
// ============================================================================

fn bits(value: u64, n: usize) -> bitvec::vec::BitVec<u8, bitvec::order::Msb0> {
    (0..n).rev().map(|i| (value >> i) & 1 == 1).collect()
}

fn plmn_identity(plmn: &PlmnId) -> ngap_gen::PLMNIdentity {
    ngap_gen::PLMNIdentity(crate::n26_build::encode_plmn_bcd(plmn).to_vec())
}

fn tai(plmn: &PlmnId, tac: u32) -> ngap_gen::TAI {
    ngap_gen::TAI {
        plmn_identity: plmn_identity(plmn),
        tac: ngap_gen::TAC(tac.to_be_bytes()[1..].to_vec()),
        ie_extensions: None,
    }
}

/// The generated `MBS-ServiceArea`: location independent, with the cell and/or
/// TAI lists of the MB-SMF's service area (TS 23.247 §7.3.1 step 3: "The AMF
/// includes the MBS service area").
fn mbs_service_area(area: &BroadcastServiceArea) -> ngap_gen::MBS_ServiceArea {
    ngap_gen::MBS_ServiceArea::Locationindependent(ngap_gen::MBS_ServiceAreaInformation {
        mbs_service_area_cell_list: (!area.cells.is_empty()).then(|| {
            ngap_gen::MBS_ServiceAreaCellList(
                area.cells
                    .iter()
                    .map(|c| ngap_gen::NR_CGI {
                        plmn_identity: plmn_identity(&c.plmn),
                        nr_cell_identity: ngap_gen::NRCellIdentity(bits(c.nci, 36)),
                        ie_extensions: None,
                    })
                    .collect(),
            )
        }),
        mbs_service_area_tai_list: (!area.tais.is_empty()).then(|| {
            ngap_gen::MBS_ServiceAreaTAIList(
                area.tais
                    .iter()
                    .map(|(plmn, tac)| tai(plmn, *tac))
                    .collect(),
            )
        }),
        ie_extensions: None,
    })
}

/// BROADCAST SESSION SETUP REQUEST (TS 38.413 §9.2.15.1, `ngap-17.9.asn:3740`):
/// MBS Session ID, S-NSSAI, MBS Service Area and the MB-SMF's MBS Session Setup
/// Request Transfer, all mandatory and criticality reject; the procedure is
/// criticality reject.
pub fn build_broadcast_session_setup_request(req: &BroadcastCreate) -> Option<Vec<u8>> {
    use ngap_gen::{
        BroadcastSessionSetupRequestProtocolIEs_Entry as Entry,
        BroadcastSessionSetupRequestProtocolIEs_EntryValue as Ie, ProtocolIE_ID,
    };
    let reject = || ngap_gen::Criticality(ngap_gen::Criticality::REJECT);
    let s_nssai = ngap_gen::S_NSSAI {
        sst: ngap_gen::SST(vec![req.sst]),
        sd: req
            .sd
            .map(|sd| ngap_gen::SD(sd.to_be_bytes()[1..].to_vec())),
        ie_extensions: None,
    };
    crate::ngap_mcast::encode_initiating(
        ngap_gen::ID_BROADCAST_SESSION_SETUP,
        ngap_gen::Criticality::REJECT,
        ngap_gen::InitiatingMessageValue::Id_BroadcastSessionSetup(
            ngap_gen::BroadcastSessionSetupRequest {
                protocol_i_es: ngap_gen::BroadcastSessionSetupRequestProtocolIEs(vec![
                    Entry {
                        id: ProtocolIE_ID(ngap_gen::ID_MBS_SESSION_ID),
                        criticality: reject(),
                        value: Ie::Id_MBS_SessionID(crate::ngap_mcast::generated_mbs_session_id(
                            &req.tmgi,
                        )),
                    },
                    Entry {
                        id: ProtocolIE_ID(ngap_gen::ID_S_NSSAI),
                        criticality: reject(),
                        value: Ie::Id_S_NSSAI(s_nssai),
                    },
                    Entry {
                        id: ProtocolIE_ID(ngap_gen::ID_MBS_SERVICE_AREA),
                        criticality: reject(),
                        value: Ie::Id_MBS_ServiceArea(mbs_service_area(&req.area)),
                    },
                    Entry {
                        id: ProtocolIE_ID(ngap_gen::ID_MBS_SESSION_SETUP_REQUEST_TRANSFER),
                        criticality: reject(),
                        value: Ie::Id_MBSSessionSetupRequestTransfer(
                            ngap_gen::Id_MBSSessionSetupRequestTransfer(req.setup_transfer.clone()),
                        ),
                    },
                ]),
            },
        ),
        "BroadcastSessionSetupRequest",
    )
}

/// BROADCAST SESSION RELEASE REQUEST (TS 38.413 §9.2.15.7, `ngap-17.9.asn:3863`):
/// MBS Session ID (reject) and Cause (ignore). The cause is NAS normal-release:
/// the MB-SMF ended the session.
pub fn build_broadcast_session_release_request(tmgi: &Tmgi) -> Option<Vec<u8>> {
    use ngap_gen::{
        BroadcastSessionReleaseRequestProtocolIEs_Entry as Entry,
        BroadcastSessionReleaseRequestProtocolIEs_EntryValue as Ie, ProtocolIE_ID,
    };
    crate::ngap_mcast::encode_initiating(
        ngap_gen::ID_BROADCAST_SESSION_RELEASE,
        ngap_gen::Criticality::REJECT,
        ngap_gen::InitiatingMessageValue::Id_BroadcastSessionRelease(
            ngap_gen::BroadcastSessionReleaseRequest {
                protocol_i_es: ngap_gen::BroadcastSessionReleaseRequestProtocolIEs(vec![
                    Entry {
                        id: ProtocolIE_ID(ngap_gen::ID_MBS_SESSION_ID),
                        criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
                        value: Ie::Id_MBS_SessionID(crate::ngap_mcast::generated_mbs_session_id(
                            tmgi,
                        )),
                    },
                    Entry {
                        id: ProtocolIE_ID(ngap_gen::ID_CAUSE),
                        criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
                        value: Ie::Id_Cause(ngap_gen::Cause::Nas(ngap_gen::CauseNas(
                            ngap_gen::CauseNas::NORMAL_RELEASE,
                        ))),
                    },
                ]),
            },
        ),
        "BroadcastSessionReleaseRequest",
    )
}

/// A gNB's answer to a Broadcast Session procedure, decoded (TS 38.413 §9.2.15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastOutcome {
    /// BROADCAST SESSION SETUP RESPONSE, with its optional Setup Response Transfer.
    SetupResponse {
        tmgi: Tmgi,
        transfer: Option<Vec<u8>>,
    },
    /// BROADCAST SESSION SETUP FAILURE, with its optional Setup Failure Transfer.
    SetupFailure {
        tmgi: Tmgi,
        transfer: Option<Vec<u8>>,
    },
    /// BROADCAST SESSION RELEASE RESPONSE, with its optional Release Response Transfer.
    ReleaseResponse {
        tmgi: Tmgi,
        transfer: Option<Vec<u8>>,
    },
}

/// Decode a Broadcast Session Setup Response / Failure or Release Response.
/// `None` for anything else, or one without a usable MBS Session ID.
pub fn decode_broadcast_outcome(data: &[u8]) -> Option<BroadcastOutcome> {
    macro_rules! find {
        ($msg:expr, $ie:ident, $variant:ident) => {
            $msg.protocol_i_es.0.iter().find_map(|e| match &e.value {
                ngap_gen::$ie::$variant(v) => Some(v.clone()),
                _ => None,
            })
        };
    }
    let (pdu, _) = nextgcore_ngap_gen::decode_with_unknown_ies(data)
        .map_err(|e| log::warn!("Failed to decode a Broadcast Session outcome: {e:?}"))
        .ok()?;
    match pdu {
        ngap_gen::NGAP_PDU::SuccessfulOutcome(m) => match m.value {
            ngap_gen::SuccessfulOutcomeValue::Id_BroadcastSessionSetup(r) => {
                let id = find!(
                    r,
                    BroadcastSessionSetupResponseProtocolIEs_EntryValue,
                    Id_MBS_SessionID
                )?;
                Some(BroadcastOutcome::SetupResponse {
                    tmgi: crate::ngap_mcast::tmgi_from_generated(&id)?,
                    transfer: find!(
                        r,
                        BroadcastSessionSetupResponseProtocolIEs_EntryValue,
                        Id_MBSSessionSetupResponseTransfer
                    )
                    .map(|t| t.0),
                })
            }
            ngap_gen::SuccessfulOutcomeValue::Id_BroadcastSessionRelease(r) => {
                let id = find!(
                    r,
                    BroadcastSessionReleaseResponseProtocolIEs_EntryValue,
                    Id_MBS_SessionID
                )?;
                Some(BroadcastOutcome::ReleaseResponse {
                    tmgi: crate::ngap_mcast::tmgi_from_generated(&id)?,
                    transfer: find!(
                        r,
                        BroadcastSessionReleaseResponseProtocolIEs_EntryValue,
                        Id_MBSSessionReleaseResponseTransfer
                    )
                    .map(|t| t.0),
                })
            }
            _ => None,
        },
        ngap_gen::NGAP_PDU::UnsuccessfulOutcome(m) => match m.value {
            ngap_gen::UnsuccessfulOutcomeValue::Id_BroadcastSessionSetup(f) => {
                let id = find!(
                    f,
                    BroadcastSessionSetupFailureProtocolIEs_EntryValue,
                    Id_MBS_SessionID
                )?;
                Some(BroadcastOutcome::SetupFailure {
                    tmgi: crate::ngap_mcast::tmgi_from_generated(&id)?,
                    transfer: find!(
                        f,
                        BroadcastSessionSetupFailureProtocolIEs_EntryValue,
                        Id_MBSSessionSetupFailureTransfer
                    )
                    .map(|t| t.0),
                })
            }
            _ => None,
        },
        ngap_gen::NGAP_PDU::InitiatingMessage(_) => None,
    }
}

// ============================================================================
// ContextStatusNotify egress, in order per context
// ============================================================================

/// The most notifications queued for one context; past it the oldest is dropped.
const MAX_QUEUED_NOTIFIES: usize = 64;

/// Per-context notification queues. A context's key is present while its sender
/// task runs, so notifications for one context are delivered in the order they
/// were produced.
static NOTIFY_QUEUES: Mutex<Option<HashMap<u64, VecDeque<BroadcastNotify>>>> = Mutex::new(None);

/// Queue `notifies` for delivery, each context's in order on its own task.
pub fn dispatch_notifies(notifies: Vec<BroadcastNotify>) {
    for n in notifies {
        let session_id = n.context_ref;
        let start = {
            let mut guard = NOTIFY_QUEUES
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let queues = guard.get_or_insert_with(HashMap::new);
            match queues.get_mut(&session_id) {
                Some(q) => {
                    if q.len() >= MAX_QUEUED_NOTIFIES {
                        q.pop_front();
                        log::warn!(
                            "Broadcast MBS context {session_id}: ContextStatusNotify backlog \
                             full; dropped the oldest"
                        );
                    }
                    q.push_back(n);
                    false
                }
                None => {
                    queues.insert(session_id, VecDeque::from([n]));
                    true
                }
            }
        };
        if start {
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    handle.spawn(notify_worker(session_id));
                }
                Err(_) => {
                    log::warn!("ContextStatusNotify not sent (no tokio runtime)");
                    if let Some(q) = NOTIFY_QUEUES
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .as_mut()
                    {
                        q.remove(&session_id);
                    }
                }
            }
        }
    }
}

async fn notify_worker(session_id: u64) {
    loop {
        let next = {
            let mut guard = NOTIFY_QUEUES
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(queues) = guard.as_mut() else {
                return;
            };
            match queues.get_mut(&session_id).and_then(VecDeque::pop_front) {
                Some(n) => n,
                None => {
                    queues.remove(&session_id);
                    return;
                }
            }
        };
        send_notify(&next).await;
    }
}

/// POST one ContextStatusNotification (TS 29.518 §5.6.2.5) to the MB-SMF's
/// `notifyUri`: JSON, or multipart/related when it carries N2 containers.
/// Returns the HTTP status, or `None` when it was not delivered.
pub async fn send_notify(n: &BroadcastNotify) -> Option<u16> {
    use nextgcore_sbi::message::{SbiPart, SbiRequest};
    let redacted = nextgcore_sbi::log_redact::redact_last_segment(&n.callback_uri);
    let Some((host, port, path)) = crate::namf_server::parse_http_uri(&n.callback_uri) else {
        log::warn!("ContextStatusNotify: invalid notifyUri {redacted}");
        return None;
    };
    let mut request = match SbiRequest::post(&path).with_json_body(&n.body) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("ContextStatusNotify body build failed: {e}");
            return None;
        }
    };
    for (cid, data) in &n.parts {
        request = request.with_part(SbiPart::with_content(
            cid,
            nextgcore_sbi::constants::content_type::APPLICATION_NGAP,
            bytes::Bytes::copy_from_slice(data),
        ));
    }
    match crate::namf_server::notify_client(&host, port)
        .send_request(request)
        .await
    {
        Ok(resp) => {
            if resp.is_success() {
                log::info!(
                    "ContextStatusNotify for broadcast MBS context {} delivered to {redacted}",
                    n.context_ref
                );
            } else {
                log::warn!(
                    "ContextStatusNotify for broadcast MBS context {} to {redacted} returned {}",
                    n.context_ref,
                    resp.status
                );
            }
            Some(resp.status)
        }
        Err(e) => {
            log::warn!("ContextStatusNotify to {redacted} failed: {e}");
            None
        }
    }
}
