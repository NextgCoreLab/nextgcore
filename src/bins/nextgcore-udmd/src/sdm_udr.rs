//! am-data change notification: from the UDR's Nudr_DM_Notify to the AMF's
//! Nudm_SDM_Notification (#1775), made durable (#1836).
//!
//! TS 23.502 §4.5.1: "Whenever the user profile is changed for a user in the
//! UDM/UDR and the changes affect the user profile in the AMF, the UDM shall notify
//! these changes to the affected AMF by the means of invoking
//! Nudm_SDM_Notification". The AMF subscribes to the UE's `am-data` at registration
//! (`POST /nudm-sdm/v2/{supi}/sdm-subscriptions`, #1748). The change itself is
//! provisioned in the UDR, so this UDM learns of it from the UDR.
//!
//! # The UDR leg
//!
//! While at least one SDM subscription of a SUPI monitors its `am-data`, this UDM
//! holds one subscription for that SUPI at the UDR
//! (`POST /nudr-dr/v2/subscription-data/subs-to-notify`, TS 29.505 §5.2.20 /
//! §5.4.2.6), monitoring `/subscription-data/{supi}/provisioned-data/am-data`. Its
//! `callbackReference` is `/nudm-callback/v1/{supi}/udr-data-change/{token}`, with a
//! token minted per leg: the UDR sends no access token with a notification
//! (TS 33.501 §13.4.1), so the token is what admits it (#1421). No `ueId` is
//! given, so the UDR tells this leg of am-data changes only, not of every change of
//! the UE's data.
//!
//! Legs are reconciled after the SDM subscribe or unsubscribe answered
//! ([`spawn_reconcile`]): an AMF's registration must not wait on the UDR. The
//! reconciles of one SUPI run one at a time, so two of them cannot both create a
//! leg. A leg whose SUPI has no am-data subscription any more is deleted at the
//! UDR (a 404 there means it is gone already).
//!
//! # The notification
//!
//! [`handle_udr_data_change`]: the UDR's `DataChangeNotify` carries `ChangeItem`s
//! per changed am-data member (`op`, `path`, `newValue`, `origValue`; arrays
//! replaced whole, TS 29.503 §5.2.2.5.2). This UDM sends them on, unchanged, in a
//! `ModificationNotification` (TS 29.503 §6.1.6.2.21) to the `callbackReference` of
//! each SDM subscription of the SUPI that monitors am-data, naming
//! `/nudm-sdm/v2/{supi}/am-data` and the subscription's id. The answers
//! (TS 29.503 Table 6.1.5.2-3):
//! - 2xx: delivered, and never sent to that consumer again;
//! - 404: the subscription is gone at the consumer; it is removed here, and the leg
//!   reconciled;
//! - 408, 429, any 5xx, or no answer: resent to that consumer with backoff (#1836,
//!   [`retry_backoff`]), for at most [`retry_window`]; then given up and logged;
//! - any other 4xx: a refusal, not resent. amfd answers 400 for a change it cannot
//!   apply (DECISIONS 2026-11-18-030000), and resending it would only be refused
//!   again.
//!
//! # Accepted, then delivered (#1775 review MAJOR-1)
//!
//! The UDR is answered 204 as soon as the notification is validated (token, body),
//! queued and written to the state file, before any consumer is tried. Acknowledging
//! on acceptance is the option taken over making delivery idempotent: a
//! `ModificationNotification` carries no sequence number or change id the AMF could
//! deduplicate on (TS 29.503 §6.1.6.2.21).
//!
//! Each SUPI has one queue and at most one worker draining it
//! ([`enqueue_locked`]), so the notifications of one SUPI are delivered one at a
//! time, in the order the UDR sent them: a later change cannot overtake an earlier
//! one, and that includes a resent one (#1836): the next change waits until every
//! consumer of the head one has answered or been given up. The consumers of one
//! notification are tried concurrently; one that answered 2xx is struck from the
//! head's pending set, so a retry for another consumer never reaches it twice. A
//! resend after a timeout can reach a consumer that did apply the first copy; in
//! order, that is a no-op at amfd ("Retries are idempotent", amfd `sdm_notify.rs`:
//! ADD/REPLACE set the member to its value, a REMOVE of an absent member changes
//! nothing). A queue holds at most [`MAX_QUEUED_PER_SUPI`] notifications; one more
//! is answered 503, which the UDR resends at its next pass.
//!
//! # Durability (#1836)
//!
//! With a state file (`--state-file` / `NEXTGCORE_UDM_STATE_FILE`) every SDM
//! subscription, every leg (path, token, callback, expiry), every SUPI's queue
//! (with each head's pending consumers) and every SUPI's [`Told`] am-data is written
//! before the operation that changed it is answered ([`STATE_LOCK`]), and restored at
//! start ([`init_state`]). So after a restart the UDR's notifications on a leg are
//! still admitted, an accepted change is still delivered, and the AMF's SDM
//! subscription is still served. Without a state file all of it is memory-only, as
//! before.
//!
//! The file is an append-only log (#1896, [`crate::state_log`]): a write appends
//! only the records it names ([`Rec`]: one SDM subscription, one SUPI's leg, queue
//! or told am-data) as one checksummed line, `fdatasync`ed before the answer, and
//! the log is compacted once it outgrows twice its live size. A write therefore
//! costs the same at 10 000 subscribers as at 100. A #1836 snapshot file is
//! migrated at the first start.
//!
//! The UDR drops a leg on its own: on its `expiry` (TS 29.504 §5.2.2.6.2, which
//! this UDM suggests and refreshes by PATCH, §5.2.2.6.2 last paragraph), or after an
//! hour of failed notifications. [`refresh_legs`] PATCHes each leg periodically; a
//! 404 means it is gone, and the leg is made again. What the AMF missed while it
//! was gone is re-derived ([`resync`]): this UDM keeps the am-data as the UDR last
//! told it ([`Told`]), reads the am-data again after the new leg is made, and tells
//! the AMF the member-by-member difference.

use crate::context::{udm_self, UdmSdmSubscription};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The path segment of the UDR data-change callback; the leg's token follows it,
/// so the shared log redaction hides it.
pub const UDR_DATA_CHANGE_SEGMENT: &str = "udr-data-change";

/// The bound on one UDR or consumer call.
const CALL_TIMEOUT: Duration = Duration::from_secs(3);

/// This UDM's subscription at the UDR for one SUPI's am-data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UdrLeg {
    /// The created resource's path at the UDR, for the PATCH and the DELETE.
    subscription_path: String,
    /// The token in the leg's `callbackReference`.
    token: String,
    /// The `callbackReference` the UDR holds for the leg (#1836): a restart on a new
    /// address re-points it.
    #[serde(default)]
    callback_reference: String,
    /// The expiry last confirmed by the UDR (TS 29.504 §5.2.2.6.2), if any.
    #[serde(default)]
    expiry: Option<String>,
}

/// SUPI -> its UDR leg. Bounded by the SUPIs with an SDM subscription, which the
/// context caps (`max_num_of_sdm_subscriptions`).
///
/// Test lock: `crate::test_support::CONTEXT_GUARD`.
static LEGS: Mutex<Option<HashMap<String, UdrLeg>>> = Mutex::new(None);

/// SUPI -> the lock its reconciles take (deliveries are ordered by the SUPI's
/// single worker instead, [`QUEUES`]). An entry is dropped when no
/// one else holds it, so the map does not outgrow [`LEGS`]'s SUPIs.
static SUPI_LOCKS: Mutex<Option<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> = Mutex::new(None);

/// Spawned reconciles and delivery workers not yet finished; tests wait for none
/// ([`wait_idle`]).
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

/// The most accepted notifications of one SUPI waiting for delivery. One more is
/// answered 503, and the UDR resends it at its next pass.
pub const MAX_QUEUED_PER_SUPI: usize = 32;

/// One accepted notification waiting for delivery.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Queued {
    /// Its am-data `ChangeItem`s.
    changes: Vec<Value>,
    /// The SDM subscriptions still to be told (#1836): `None` until the first try,
    /// which takes every am-data subscription of the SUPI; then the ones whose try
    /// is to be repeated. One that answered is never told again.
    #[serde(default)]
    pending: Option<BTreeSet<String>>,
}

/// SUPI -> the accepted am-data changes waiting for delivery, oldest first. An entry
/// exists exactly while that SUPI's worker runs ([`enqueue_locked`]), so the map is
/// bounded by the SUPIs with a leg ([`LEGS`]: only a leg's token is accepted), and
/// each queue by the one in delivery plus [`MAX_QUEUED_PER_SUPI`] waiting (plus one
/// re-derived change, [`resync`]).
///
/// Test lock: `crate::test_support::CONTEXT_GUARD`.
static QUEUES: Mutex<Option<HashMap<String, VecDeque<Queued>>>> = Mutex::new(None);

/// The am-data of one SUPI as the UDR last told it (#1836): read after the leg is
/// made, then advanced by every accepted change. It is what a re-made leg diffs the
/// am-data read then against, so a change the UDR made while the old leg was gone
/// still reaches the AMF.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct Told {
    /// `None` until read, and after a change it cannot follow (then the next read
    /// takes its place, telling nothing).
    doc: Option<Value>,
    /// Bumped on every accepted change, so a read that a change overtook is retaken.
    #[serde(default)]
    seq: u64,
    /// The read is still to be made ([`refresh_legs`] retries it).
    #[serde(default)]
    resync: bool,
}

/// SUPI -> its [`Told`]. Exists while the SUPI has a leg or one is being made;
/// removed with the leg's last SDM subscription, so bounded like [`LEGS`].
///
/// Test lock: `crate::test_support::CONTEXT_GUARD`.
static TOLD: Mutex<Option<HashMap<String, Told>>> = Mutex::new(None);

/// Serialises every change to the persisted state with its write (#1836): a change
/// and the snapshot that holds it are one step, so an answer given after it is never
/// for state a crash could lose, and two writers cannot interleave snapshots. Taken
/// before any std lock above, never while holding one.
///
/// Test lock: `crate::test_support::CONTEXT_GUARD`.
static STATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The state log (#1896, [`crate::state_log`]), `None` for memory-only.
static STATE_LOG: Mutex<Option<Arc<Mutex<crate::state_log::StateLog>>>> = Mutex::new(None);

/// Bumped by a (simulated) restart: a worker of an older generation stops without
/// touching state.
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// The first wait before a consumer's notification is resent, in ms (doubling).
static RETRY_BASE_MS: AtomicU64 = AtomicU64::new(1_000);
/// The longest wait between two resends.
const RETRY_MAX_WAIT: Duration = Duration::from_secs(60);
/// How long a consumer's notification is resent before it is given up, in ms.
static RETRY_WINDOW_MS: AtomicU64 = AtomicU64::new(600_000);
/// A notification is tried at least this often before it is given up.
const RETRY_MIN_TRIES: u32 = 3;

/// The wait before resend `attempt` (1-based): [`RETRY_BASE_MS`] doubling, at most
/// [`RETRY_MAX_WAIT`].
fn retry_backoff(attempt: u32) -> Duration {
    let base = Duration::from_millis(RETRY_BASE_MS.load(Ordering::SeqCst));
    base.saturating_mul(1u32 << attempt.saturating_sub(1).min(16))
        .min(RETRY_MAX_WAIT)
}

/// How long a consumer's notification is resent before it is given up: ten minutes,
/// so an AMF restart is ridden out, while a dead AMF does not hold the SUPI's queue
/// for long (and a dead AMF's subscription goes on its next 404).
fn retry_window() -> Duration {
    Duration::from_millis(RETRY_WINDOW_MS.load(Ordering::SeqCst))
}

fn lock<T>(m: &'static Mutex<Option<T>>) -> std::sync::MutexGuard<'static, Option<T>> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn leg(supi: &str) -> Option<UdrLeg> {
    lock(&LEGS).as_ref().and_then(|m| m.get(supi).cloned())
}

fn set_leg(supi: &str, leg: Option<UdrLeg>) {
    let mut map = lock(&LEGS);
    let map = map.get_or_insert_with(HashMap::new);
    match leg {
        Some(l) => map.insert(supi.to_string(), l),
        None => map.remove(supi),
    };
}

fn told(supi: &str) -> Option<Told> {
    lock(&TOLD).as_ref().and_then(|m| m.get(supi).cloned())
}

fn set_told(supi: &str, told: Option<Told>) {
    let mut map = lock(&TOLD);
    let map = map.get_or_insert_with(HashMap::new);
    match told {
        Some(t) => map.insert(supi.to_string(), t),
        None => map.remove(supi),
    };
}

fn supi_lock(supi: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut map = SUPI_LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    map.get_or_insert_with(HashMap::new)
        .entry(supi.to_string())
        .or_default()
        .clone()
}

/// Drop `supi`'s lock entry when `held` (the caller's clone) and the map's are its
/// only holders and the SUPI has no leg.
fn release_supi_lock(supi: &str, held: Arc<tokio::sync::Mutex<()>>) {
    let mut map = SUPI_LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(map) = map.as_mut() {
        if Arc::strong_count(&held) == 2 && leg(supi).is_none() {
            map.remove(supi);
        }
    }
}

// ---------------------------------------------------------------------------
// The state file (#1836)
// ---------------------------------------------------------------------------

/// One persisted SDM subscription (TS 29.503 §6.1.6.2.3 `SdmSubscription`, the
/// members this UDM holds).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedSdmSubscription {
    id: String,
    supi: String,
    #[serde(default)]
    nf_instance_id: Option<String>,
    #[serde(default)]
    callback_reference: Option<String>,
    monitored_resource_uris: Vec<String>,
}

/// The state as restored: #1836's snapshot document, and what a replay of the
/// log (#1896) builds.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    #[serde(default)]
    sdm_subscriptions: Vec<SavedSdmSubscription>,
    #[serde(default)]
    legs: HashMap<String, UdrLeg>,
    #[serde(default)]
    queues: HashMap<String, VecDeque<Queued>>,
    #[serde(default)]
    told: HashMap<String, Told>,
}

/// One record of the persisted state (#1896): what a write names, so it writes
/// only these, never the whole state.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Rec<'a> {
    /// The SDM subscription with this id.
    Sub(&'a str),
    /// This SUPI's UDR leg.
    Leg(&'a str),
    /// This SUPI's queue.
    Queue(&'a str),
    /// This SUPI's [`Told`] am-data.
    Told(&'a str),
}

fn saved(s: UdmSdmSubscription) -> SavedSdmSubscription {
    SavedSdmSubscription {
        id: s.id,
        supi: s.supi,
        nf_instance_id: s.nf_instance_id,
        callback_reference: s.callback_reference,
        monitored_resource_uris: s.monitored_resource_uris,
    }
}

/// The log operation putting `rec` as it is now in memory, or deleting it when it
/// is not there.
fn record_op(rec: Rec<'_>) -> Value {
    let (t, k, v) = match rec {
        Rec::Sub(id) => {
            let ctx = udm_self();
            let found = ctx
                .read()
                .ok()
                .and_then(|c| c.sdm_subscription_find_by_id(id));
            ("sub", id, found.map(|s| serde_json::to_value(saved(s))))
        }
        Rec::Leg(supi) => ("leg", supi, leg(supi).map(serde_json::to_value)),
        Rec::Queue(supi) => {
            let q = lock(&QUEUES)
                .as_ref()
                .and_then(|m| m.get(supi).cloned())
                .filter(|q| !q.is_empty());
            ("queue", supi, q.map(serde_json::to_value))
        }
        Rec::Told(supi) => ("told", supi, told(supi).map(serde_json::to_value)),
    };
    match v.and_then(Result::ok) {
        Some(v) => json!({"t": t, "k": k, "v": v}),
        None => json!({"t": t, "k": k}),
    }
}

/// One put per live record: what a compaction writes.
fn all_ops() -> Vec<Value> {
    let subs: Vec<String> = {
        let ctx = udm_self();
        let guard = ctx.read().ok();
        guard
            .map(|c| c.sdm_subscriptions_all())
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.id)
            .collect()
    };
    let legs: Vec<String> = keys_of(&LEGS);
    let queues: Vec<String> = keys_of(&QUEUES);
    let told: Vec<String> = keys_of(&TOLD);
    let mut ops: Vec<Value> = subs.iter().map(|id| record_op(Rec::Sub(id))).collect();
    ops.extend(legs.iter().map(|s| record_op(Rec::Leg(s))));
    ops.extend(queues.iter().map(|s| record_op(Rec::Queue(s))));
    ops.extend(told.iter().map(|s| record_op(Rec::Told(s))));
    ops.retain(|op| op.get("v").is_some());
    ops
}

fn keys_of<T>(m: &'static Mutex<Option<HashMap<String, T>>>) -> Vec<String> {
    let mut k: Vec<String> = lock(m)
        .as_ref()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    k.sort();
    k
}

/// The state the log's operations build, in order; an operation that is not one
/// of this UDM's records is corruption.
fn replay(ops: Vec<Value>) -> Result<Snapshot, String> {
    let mut subs: std::collections::BTreeMap<String, SavedSdmSubscription> = Default::default();
    let mut snap = Snapshot::default();
    for (n, op) in ops.into_iter().enumerate() {
        let bad = |why: &str| format!("state log operation {n}: {why}");
        let t = op
            .get("t")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("no kind"))?;
        let k = op
            .get("k")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("no key"))?
            .to_string();
        let v = op.get("v").cloned();
        fn de<T: serde::de::DeserializeOwned>(v: Value) -> Result<T, String> {
            serde_json::from_value(v).map_err(|e| e.to_string())
        }
        match (t, v) {
            ("sub", Some(v)) => {
                subs.insert(k, de(v).map_err(|e| bad(&e))?);
            }
            ("sub", None) => {
                subs.remove(&k);
            }
            ("leg", Some(v)) => {
                snap.legs.insert(k, de(v).map_err(|e| bad(&e))?);
            }
            ("leg", None) => {
                snap.legs.remove(&k);
            }
            ("queue", Some(v)) => {
                snap.queues.insert(k, de(v).map_err(|e| bad(&e))?);
            }
            ("queue", None) => {
                snap.queues.remove(&k);
            }
            ("told", Some(v)) => {
                snap.told.insert(k, de(v).map_err(|e| bad(&e))?);
            }
            ("told", None) => {
                snap.told.remove(&k);
            }
            (other, _) => return Err(bad(&format!("unknown kind {other}"))),
        }
    }
    snap.sdm_subscriptions = subs.into_values().collect();
    Ok(snap)
}

/// Take [`STATE_LOCK`]: hold it across a change to the persisted state and its
/// [`persist_locked`].
pub(crate) async fn state_lock() -> tokio::sync::MutexGuard<'static, ()> {
    STATE_LOCK.lock().await
}

/// Write `recs` as they are now in memory to the state log (a no-op without
/// one), durably, before the caller answers: one appended line, so the cost is
/// the size of these records, whatever the size of the state (#1896). When the
/// log is due, it is compacted after the write. A compaction that fails is
/// logged: the write itself is already durable. The caller holds [`STATE_LOCK`]
/// (`_held`) across the change and this write.
pub(crate) async fn persist_locked(
    _held: &tokio::sync::MutexGuard<'static, ()>,
    recs: &[Rec<'_>],
) -> Result<(), String> {
    let Some(log) = lock(&STATE_LOG).clone() else {
        return Ok(());
    };
    let ops: Vec<Value> = recs.iter().map(|r| record_op(*r)).collect();
    let writer = log.clone();
    let due = tokio::task::spawn_blocking(move || {
        writer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .append(&ops)
    })
    .await
    .map_err(|e| format!("state write task: {e}"))??;
    if due {
        let all = all_ops();
        let compacted = tokio::task::spawn_blocking(move || {
            log.lock().unwrap_or_else(|e| e.into_inner()).compact(&all)
        })
        .await
        .map_err(|e| format!("compaction task: {e}"))
        .and_then(|r| r);
        if let Err(e) = compacted {
            log::warn!("UDM state log not compacted: {e}");
        }
    }
    Ok(())
}

/// Open the state log `path` (`None`: memory-only) and restore what it holds:
/// the SDM subscriptions, the legs, the queues and the [`Told`] am-data. Each
/// restored queue's worker is started. A damaged log is an error and nothing is
/// restored (the caller fails the start, and the file is kept); a torn last write
/// is cut off ([`crate::state_log`]). A #1836 snapshot at `path` is restored and
/// migrated: the file is rewritten as a log. A log holding more operations than
/// twice its live records is compacted, so the next load stays bounded. Call after
/// `udm_context_init`.
pub async fn init_state(path: Option<std::path::PathBuf>) -> Result<usize, String> {
    let _held = STATE_LOCK.lock().await;
    let (log, snap, compact) = match path {
        None => (None, Snapshot::default(), false),
        Some(path) => {
            let (log, opened) =
                tokio::task::spawn_blocking(move || crate::state_log::StateLog::open(&path))
                    .await
                    .map_err(|e| format!("state log open task: {e}"))??;
            match opened {
                crate::state_log::Opened::Legacy(doc) => {
                    let snap: Snapshot = serde_json::from_value(doc)
                        .map_err(|e| format!("state file does not hold a UDM snapshot: {e}"))?;
                    log::info!("UDM state file holds a #1836 snapshot: migrated to the log");
                    (Some(log), snap, true)
                }
                crate::state_log::Opened::Log { ops, .. } => {
                    let count = ops.len();
                    let snap = replay(ops)?;
                    let live = snap.sdm_subscriptions.len()
                        + snap.legs.len()
                        + snap.queues.len()
                        + snap.told.len();
                    (Some(log), snap, count > 2 * live.max(1))
                }
            }
        }
    };
    // Validated whole above; applied below.
    let restored = snap.sdm_subscriptions.len();
    {
        let ctx = udm_self();
        if let Ok(context) = ctx.read() {
            for s in snap.sdm_subscriptions {
                let mut sub = UdmSdmSubscription::for_supi(
                    s.supi,
                    s.nf_instance_id,
                    s.callback_reference,
                    s.monitored_resource_uris,
                );
                sub.id = s.id;
                if !context.sdm_subscription_insert(sub) {
                    log::error!("state file: SDM subscription over the cap, not restored");
                }
            }
        };
    }
    *lock(&LEGS) = Some(snap.legs);
    *lock(&TOLD) = Some(snap.told);
    let queues: HashMap<String, VecDeque<Queued>> = snap
        .queues
        .into_iter()
        .filter(|(_, q)| !q.is_empty())
        .map(|(supi, mut q)| {
            q.truncate(MAX_QUEUED_PER_SUPI + 2);
            (supi, q)
        })
        .collect();
    let workers: Vec<String> = queues.keys().cloned().collect();
    *lock(&QUEUES) = Some(queues);
    let enabled = log.is_some();
    if let Some(mut log) = log {
        if compact {
            let all = all_ops();
            log = tokio::task::spawn_blocking(move || log.compact(&all).map(|()| log))
                .await
                .map_err(|e| format!("state log compaction task: {e}"))??;
        }
        *lock(&STATE_LOG) = Some(Arc::new(Mutex::new(log)));
    } else {
        *lock(&STATE_LOG) = None;
    }
    for supi in workers {
        spawn_worker(supi);
    }
    if enabled {
        log::info!(
            "UDM state restored: {restored} SDM subscriptions, {} UDR legs",
            lock(&LEGS).as_ref().map_or(0, HashMap::len)
        );
    }
    Ok(restored)
}

// ---------------------------------------------------------------------------
// The leg
// ---------------------------------------------------------------------------

/// Whether `token` is `supi`'s leg token: the check both the handler and the
/// server's OAuth2 callback exemption (#1421) apply.
pub(crate) fn token_matches(supi: &str, token: &str) -> bool {
    leg(supi).is_some_and(|l| crate::ee_amf::tokens_equal(&l.token, token))
}

/// `/nudm-callback/v1/{supi}/udr-data-change/{token}`.
pub fn data_change_path(supi: &str, token: &str) -> String {
    format!("/nudm-callback/v1/{supi}/{UDR_DATA_CHANGE_SEGMENT}/{token}")
}

/// Whether `sub` monitors its UE's am-data.
fn monitors_am_data(sub: &UdmSdmSubscription) -> bool {
    sub.monitored_resource_uris
        .iter()
        .any(|u| u.trim_end_matches('/').ends_with("/am-data"))
}

/// The SDM subscriptions of `supi` that monitor its am-data.
fn am_data_subscriptions(supi: &str) -> Vec<UdmSdmSubscription> {
    let ctx = udm_self();
    let Ok(context) = ctx.read() else {
        return Vec::new();
    };
    context
        .sdm_subscriptions_for_supi(supi)
        .into_iter()
        .filter(monitors_am_data)
        .collect()
}

/// The UDR resource this UDM's leg monitors (TS 29.505).
pub fn udr_am_data_path(supi: &str) -> String {
    format!("/nudr-dr/v2/subscription-data/{supi}/provisioned-data/am-data")
}

/// The leg lifetime this UDM suggests and refreshes, in seconds: three refresh
/// periods, so two missed refreshes do not lose it.
fn leg_lifetime_secs() -> u64 {
    refresh_period().as_secs().max(1) * 3
}

/// A suggested `expiry` (TS 29.504 §5.2.2.6.2) for a leg made or refreshed now:
/// [`leg_lifetime_secs`] ahead, plus up to half a refresh period of jitter, so the
/// legs of many SUPIs do not all expire together (the same clause asks this of the
/// UDR's confirmed expiry).
fn suggested_expiry() -> String {
    let jitter_range = (refresh_period().as_secs() / 2).max(1);
    let jitter = u64::from_le_bytes(
        uuid::Uuid::new_v4().as_bytes()[..8]
            .try_into()
            .unwrap_or([0; 8]),
    ) % jitter_range;
    nextgcore_sbi::datetime::epoch_to_rfc3339(
        nextgcore_sbi::datetime::now_epoch_secs() + leg_lifetime_secs() + jitter,
    )
}

/// The `SubscriptionDataSubscriptions` body of `supi`'s leg (TS 29.505).
pub(crate) fn leg_body(base: &str, supi: &str, token: &str) -> Value {
    json!({
        "callbackReference": format!("{base}{}", data_change_path(supi, token)),
        "monitoredResourceUris": [udr_am_data_path(supi)],
        "expiry": suggested_expiry(),
    })
}

/// Send `request` to the UDR, bounded by [`CALL_TIMEOUT`].
async fn udr_call(request: SbiRequest) -> Result<SbiResponse, String> {
    tokio::time::timeout(
        CALL_TIMEOUT,
        crate::sbi_path::udm_sbi_discover_and_send_nudr_dr(0, 0, request),
    )
    .await
    .map_err(|_| "UDR call timed out".to_string())?
}

/// The body of `resp` as JSON, if it has one.
fn json_body(resp: &SbiResponse) -> Option<Value> {
    resp.http
        .content
        .as_deref()
        .and_then(|b| serde_json::from_str::<Value>(b).ok())
}

/// Create `supi`'s leg at the UDR.
async fn udr_subscribe(base: &str, supi: &str) -> Result<UdrLeg, String> {
    let token = uuid::Uuid::new_v4().simple().to_string();
    let body = leg_body(base, supi, &token);
    let request = SbiRequest::post("/nudr-dr/v2/subscription-data/subs-to-notify")
        .with_json_body(&body)
        .map_err(|e| format!("body: {e}"))?;
    let resp = udr_call(request).await?;
    if resp.status != 201 {
        return Err(format!("UDR answered {}", resp.status));
    }
    let created = json_body(&resp);
    let location = resp
        .http
        .headers
        .get("location")
        .cloned()
        .or_else(|| {
            created
                .as_ref()
                .and_then(|v| v["subscriptionId"].as_str().map(String::from))
                .map(|id| format!("/nudr-dr/v2/subscription-data/subs-to-notify/{id}"))
        })
        .ok_or("201 without a Location or subscriptionId")?;
    // An absolute Location keeps only its path: the call goes to the UDR again.
    let subscription_path = match location.split_once("://") {
        Some((_, rest)) => rest
            .find('/')
            .map_or("/".to_string(), |i| rest[i..].to_string()),
        None => location,
    };
    // The confirmed expiry; an answer without one confirms an unlimited leg.
    let expiry = created
        .as_ref()
        .and_then(|v| v.get("expiry"))
        .and_then(Value::as_str)
        .map(String::from);
    Ok(UdrLeg {
        subscription_path,
        token,
        callback_reference: body["callbackReference"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        expiry,
    })
}

/// Delete a leg at the UDR. Best-effort: a 404 means it is gone already.
async fn udr_unsubscribe(supi: &str, leg: &UdrLeg) {
    match udr_call(SbiRequest::delete(&leg.subscription_path)).await {
        Ok(resp) => log::info!(
            "[{supi}] UDR am-data subscription {} deleted: status={}",
            leg.subscription_path,
            resp.status
        ),
        Err(e) => log::warn!(
            "[{supi}] UDR am-data subscription {} not deleted: {e}",
            leg.subscription_path
        ),
    }
}

/// Reconcile `supi`'s leg after the answer to the operation that changed what it
/// needs.
pub fn spawn_reconcile(supi: &str) {
    spawn_reconcile_attempt(supi.to_string(), 0);
}

/// The most reconciles of one SUPI in a row whose UDR subscribe failed; after them
/// the leg is left unmade until the SUPI's next SDM subscribe or [`refresh_legs`].
const MAX_RECONCILE_ATTEMPTS: u32 = 8;

/// The wait before reconcile attempt `attempt` (1-based retry): 1 s doubling, at
/// most 60 s, so the eight attempts span about three minutes.
fn reconcile_backoff(attempt: u32) -> Duration {
    Duration::from_secs((1u64 << attempt.min(6).saturating_sub(1)).min(60))
}

/// Run reconcile `attempt` of `supi` now. A failed UDR subscribe is retried with
/// backoff (#1775 review minor): the AMF subscribes once per registration, so
/// without the retry a UDR that was down at that moment left the UE without am-data
/// notifications until it registered again.
fn spawn_reconcile_attempt(supi: String, attempt: u32) {
    IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
    tokio::spawn(async move {
        let retry = Box::pin(reconcile(&supi)).await;
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
        if !retry {
            return;
        }
        let next = attempt + 1;
        if next >= MAX_RECONCILE_ATTEMPTS {
            log::error!(
                "[{supi}] UDR am-data subscription not made after {next} attempts; tried \
                 again at the next leg refresh"
            );
            return;
        }
        tokio::time::sleep(reconcile_backoff(next)).await;
        spawn_reconcile_attempt(supi, next);
    });
}

/// Wait until no spawned reconcile or worker is running (tests).
pub async fn wait_idle() {
    for _ in 0..500 {
        if IN_FLIGHT.load(Ordering::SeqCst) == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Make `supi`'s leg exist exactly while an SDM subscription of `supi` monitors its
/// am-data and this UDM has a callback address to give. `true` when the leg is
/// wanted and the UDR subscribe failed, so it is worth retrying.
pub async fn reconcile(supi: &str) -> bool {
    let lock = supi_lock(supi);
    let mut retry = false;
    {
        let _serial = lock.lock().await;
        let want = !am_data_subscriptions(supi).is_empty();
        match (want, leg(supi), crate::ee_amf::notify_base()) {
            (true, None, Some(base)) => match udr_subscribe(&base, supi).await {
                Ok(new_leg) => {
                    log::info!(
                        "[{supi}] subscribed at the UDR for am-data changes: {}",
                        new_leg.subscription_path
                    );
                    {
                        // The leg first, so the UDR's first notification on it is
                        // admitted; the read that tells what was missed follows.
                        let held = STATE_LOCK.lock().await;
                        set_leg(supi, Some(new_leg));
                        let mut t = told(supi).unwrap_or_default();
                        t.resync = true;
                        set_told(supi, Some(t));
                        if let Err(e) =
                            persist_locked(&held, &[Rec::Leg(supi), Rec::Told(supi)]).await
                        {
                            log::error!("[{supi}] UDR leg not written to the state file: {e}");
                        }
                    }
                    Box::pin(resync(supi)).await;
                }
                // The SDM subscription stands; the leg is retried with backoff.
                Err(e) => {
                    log::warn!("[{supi}] UDR am-data subscription not made: {e}; retried");
                    retry = true;
                }
            },
            (true, None, None) => log::warn!(
                "[{supi}] no advertised SBI address: am-data changes are not subscribed at the UDR"
            ),
            (false, Some(old), _) => {
                {
                    let held = STATE_LOCK.lock().await;
                    set_leg(supi, None);
                    set_told(supi, None);
                    if let Err(e) = persist_locked(&held, &[Rec::Leg(supi), Rec::Told(supi)]).await
                    {
                        log::error!("[{supi}] UDR leg removal not written: {e}");
                    }
                }
                udr_unsubscribe(supi, &old).await;
            }
            (false, None, _) if told(supi).is_some() => {
                let held = STATE_LOCK.lock().await;
                set_told(supi, None);
                let _ = persist_locked(&held, &[Rec::Told(supi)]).await;
            }
            _ => {}
        }
    }
    release_supi_lock(supi, lock);
    retry
}

// ---------------------------------------------------------------------------
// Re-deriving what was missed (#1836)
// ---------------------------------------------------------------------------

/// The members of a TS 29.505 `AuthenticationSubscription` that are key material
/// (#1797 / #1812). am-data holds none, but every value this UDM tells the AMF from
/// its own diff passes [`without_key_material`], as the UDR's notifier does
/// (udrd `KEY_MATERIAL_MEMBERS`, which a test keeps equal to this).
pub const KEY_MATERIAL_MEMBERS: [&str; 3] = ["encPermanentKey", "encOpcKey", "encTopcKey"];

/// `v` with every [`KEY_MATERIAL_MEMBERS`] member removed, at any depth.
fn without_key_material(v: &Value) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(k, _)| !KEY_MATERIAL_MEMBERS.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), without_key_material(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(without_key_material).collect()),
        other => other.clone(),
    }
}

fn pointer_token(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

fn unpointer_token(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

/// The `ChangeItem`s (TS 29.571 §5.2.4.8) that take am-data `old` to `new`, one per
/// top-level member that differs, as the UDR words them (udrd
/// `data_store::am_data_changes`; a test keeps the two equal): `ADD` a member `old`
/// lacks, `REMOVE` one `new` lacks, `REPLACE` one whose value changed, the value
/// carried whole (TS 29.503 §5.2.2.5.2) and `origValue` on `REPLACE` and `REMOVE`.
/// No change names or carries a key-material member.
pub(crate) fn am_data_diff(old: &Value, new: &Value) -> Vec<Value> {
    let empty = serde_json::Map::new();
    let old = old.as_object().unwrap_or(&empty);
    let new = new.as_object().unwrap_or(&empty);
    let mut keys: Vec<&String> = old.keys().chain(new.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter(|k| !KEY_MATERIAL_MEMBERS.contains(&k.as_str()))
        .filter_map(|k| {
            let path = format!("/{}", pointer_token(k));
            let clean = without_key_material;
            match (old.get(k), new.get(k)) {
                (None, Some(n)) => Some(json!({"op": "ADD", "path": path, "newValue": clean(n)})),
                (Some(o), None) => {
                    Some(json!({"op": "REMOVE", "path": path, "origValue": clean(o)}))
                }
                (Some(o), Some(n)) if o != n => Some(json!({
                    "op": "REPLACE", "path": path, "newValue": clean(n), "origValue": clean(o)
                })),
                _ => None,
            }
        })
        .collect()
}

/// `doc` with `changes` applied, or `None` when one is not a whole-member (or
/// whole-resource) ADD, REPLACE or REMOVE this UDM can follow.
fn apply_changes(doc: &Value, changes: &[Value]) -> Option<Value> {
    let mut doc = doc.clone();
    for change in changes {
        let op = change.get("op").and_then(Value::as_str)?;
        let path = change.get("path").and_then(Value::as_str)?;
        if path.is_empty() {
            match op {
                "REPLACE" | "ADD" => doc = change.get("newValue")?.clone(),
                "REMOVE" => doc = json!({}),
                _ => return None,
            }
            continue;
        }
        let token = path.strip_prefix('/')?;
        if token.contains('/') {
            return None;
        }
        let key = unpointer_token(token);
        let map = doc.as_object_mut()?;
        match op {
            "ADD" | "REPLACE" => {
                map.insert(key, change.get("newValue")?.clone());
            }
            "REMOVE" => {
                map.remove(&key);
            }
            _ => return None,
        }
    }
    Some(doc)
}

/// `supi`'s am-data as the UDR serves it now, or `None` when it cannot be read.
async fn read_am_data(supi: &str) -> Option<Value> {
    let resp = udr_call(SbiRequest::get(udr_am_data_path(supi)))
        .await
        .map_err(|e| log::warn!("[{supi}] am-data not read from the UDR: {e}"))
        .ok()?;
    if resp.status != 200 {
        log::warn!(
            "[{supi}] am-data read from the UDR answered {}",
            resp.status
        );
        return None;
    }
    json_body(&resp).filter(Value::is_object)
}

/// Re-derive what the AMF missed (#1836): read `supi`'s am-data and queue the
/// difference from its [`Told`] am-data, which then becomes the read. Run after a
/// leg is made: the UDR measures a new leg's changes from the am-data as it is at
/// the subscribe, so a change made while there was no leg (it expired, the UDR
/// dropped it, the UDM was down) is told by nothing else. The first leg of a SUPI
/// has nothing to diff against, and tells nothing. A read that an accepted change
/// overtook is retaken; one that cannot be made leaves `resync` set, and
/// [`refresh_legs`] retries it.
async fn resync(supi: &str) {
    for _ in 0..3 {
        let Some(before) = told(supi) else {
            return;
        };
        let Some(fresh) = read_am_data(supi).await else {
            return;
        };
        let held = STATE_LOCK.lock().await;
        let Some(mut now) = told(supi) else {
            return;
        };
        if now.seq != before.seq {
            // A change was accepted while reading: the read may be older than it.
            continue;
        }
        let changes = now
            .doc
            .as_ref()
            .map(|old| am_data_diff(old, &fresh))
            .unwrap_or_default();
        let saved_queue = lock(&QUEUES).as_ref().and_then(|m| m.get(supi).cloned());
        let started = if changes.is_empty() {
            false
        } else {
            log::info!(
                "[{supi}] {} am-data changes made while there was no UDR leg: told",
                changes.len()
            );
            enqueue_locked(supi, changes, true).unwrap_or(false)
        };
        now.doc = Some(fresh);
        now.resync = false;
        set_told(supi, Some(now));
        if let Err(e) = persist_locked(&held, &[Rec::Queue(supi), Rec::Told(supi)]).await {
            log::error!("[{supi}] re-derived am-data changes not written: {e}");
            // Undo: the resync stays due, and nothing unwritten is delivered.
            set_told(
                supi,
                Some(Told {
                    resync: true,
                    ..before
                }),
            );
            restore_queue(supi, saved_queue);
            return;
        }
        drop(held);
        if started {
            spawn_worker(supi.to_string());
        }
        return;
    }
}

// ---------------------------------------------------------------------------
// Refreshing the legs (#1836)
// ---------------------------------------------------------------------------

/// The leg refresh period env var, in seconds.
pub const LEG_REFRESH_ENV: &str = "UDM_UDR_LEG_REFRESH_S";
const DEFAULT_LEG_REFRESH_S: u64 = 300;

fn refresh_period() -> Duration {
    Duration::from_secs(
        std::env::var(LEG_REFRESH_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|s| *s > 0)
            .unwrap_or(DEFAULT_LEG_REFRESH_S),
    )
}

/// What a leg's refresh came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refreshed {
    /// The UDR holds it, with the new expiry (and callback).
    Kept,
    /// The UDR answered 404: it is gone, and is being made again.
    Gone,
    /// No answer, or another status: tried again at the next refresh.
    Failed,
}

/// Refresh `supi`'s leg: PATCH its `expiry` one lifetime ahead (TS 29.504
/// §5.2.2.6.2: "request an extension of the subscription lifetime before the
/// subscription expires ... by issuing a PUT or PATCH"), and its
/// `callbackReference` when this UDM's address is not the one the UDR holds (a
/// restart on a new address). A 404 says the UDR dropped the leg (expired, or after
/// an hour of failed notifications): it is removed here and made again, and what was
/// missed is re-derived ([`resync`]).
async fn refresh_leg(supi: &str, held_leg: UdrLeg) -> Refreshed {
    let expiry = suggested_expiry();
    let mut items = vec![json!({"op": "replace", "path": "/expiry", "value": expiry})];
    let callback = crate::ee_amf::notify_base()
        .map(|base| format!("{base}{}", data_change_path(supi, &held_leg.token)));
    if let Some(cb) = callback
        .as_ref()
        .filter(|cb| **cb != held_leg.callback_reference)
    {
        items.push(json!({"op": "replace", "path": "/callbackReference", "value": cb}));
    }
    let request = match SbiRequest::patch(&held_leg.subscription_path).with_json_body(&items) {
        Ok(r) => r,
        Err(_) => return Refreshed::Failed,
    };
    let answer = udr_call(request).await;
    let held = STATE_LOCK.lock().await;
    // Another reconcile may have replaced the leg meanwhile.
    if leg(supi).as_ref().map(|l| &l.token) != Some(&held_leg.token) {
        return Refreshed::Kept;
    }
    match answer {
        Ok(resp) if (200..300).contains(&resp.status) => {
            let confirmed = json_body(&resp)
                .and_then(|v| v.get("expiry").and_then(Value::as_str).map(String::from))
                .unwrap_or(expiry);
            let mut l = held_leg;
            l.expiry = Some(confirmed);
            if let Some(cb) = callback {
                l.callback_reference = cb;
            }
            set_leg(supi, Some(l));
            if let Err(e) = persist_locked(&held, &[Rec::Leg(supi)]).await {
                log::error!("[{supi}] refreshed UDR leg not written: {e}");
            }
            Refreshed::Kept
        }
        Ok(resp) if resp.status == 404 => {
            log::warn!(
                "[{supi}] UDR am-data subscription {} is gone at the UDR: made again",
                held_leg.subscription_path
            );
            set_leg(supi, None);
            if let Err(e) = persist_locked(&held, &[Rec::Leg(supi)]).await {
                log::error!("[{supi}] UDR leg removal not written: {e}");
            }
            drop(held);
            spawn_reconcile(supi);
            Refreshed::Gone
        }
        Ok(resp) => {
            log::warn!(
                "[{supi}] UDR leg refresh answered {}; tried again",
                resp.status
            );
            Refreshed::Failed
        }
        Err(e) => {
            log::warn!("[{supi}] UDR leg refresh: {e}; tried again");
            Refreshed::Failed
        }
    }
}

/// One refresh of every leg (#1836), at most 32 at once: [`refresh_leg`] each, and
/// the due [`resync`]s. A SUPI whose leg is wanted but missing (its reconciles gave
/// up) is reconciled again. Returns each SUPI's outcome.
pub async fn refresh_legs() -> Vec<(String, Refreshed)> {
    let legs: Vec<(String, UdrLeg)> = lock(&LEGS)
        .as_ref()
        .map(|m| m.iter().map(|(s, l)| (s.clone(), l.clone())).collect())
        .unwrap_or_default();
    let limit = Arc::new(tokio::sync::Semaphore::new(32));
    let mut each = tokio::task::JoinSet::new();
    for (supi, l) in legs {
        let limit = limit.clone();
        each.spawn(async move {
            let _permit = limit.acquire_owned().await.ok();
            if told(&supi).is_some_and(|t| t.resync) {
                Box::pin(resync(&supi)).await;
            }
            let outcome = Box::pin(refresh_leg(&supi, l)).await;
            (supi, outcome)
        });
    }
    let mut out = Vec::new();
    while let Some(done) = each.join_next().await {
        if let Ok(r) = done {
            out.push(r);
        }
    }
    let wanted: BTreeSet<String> = {
        let ctx = udm_self();
        let guard = ctx.read().ok();
        guard
            .map(|c| c.sdm_subscriptions_all())
            .unwrap_or_default()
            .into_iter()
            .filter(monitors_am_data)
            .map(|s| s.supi)
            .collect()
    };
    for supi in wanted {
        if leg(&supi).is_none() {
            spawn_reconcile(&supi);
        }
    }
    out
}

/// Refresh the legs now, then every [`LEG_REFRESH_ENV`] seconds (default 300).
pub fn spawn_leg_refresh() {
    let period = refresh_period();
    log::info!("UDR am-data legs refreshed every {} s", period.as_secs());
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            // The first tick is at once: a restart audits its restored legs.
            tick.tick().await;
            refresh_legs().await;
        }
    });
}

// ---------------------------------------------------------------------------
// The notification
// ---------------------------------------------------------------------------

/// The am-data `ChangeItem`s of a `DataChangeNotify` (TS 29.505 §5.4.2.6) for
/// `supi`, or why it is malformed. Items naming another resource are skipped: the
/// leg monitors am-data only.
pub(crate) fn am_data_changes(supi: &str, notify: &Value) -> Result<Vec<Value>, String> {
    let items = notify
        .get("notifyItems")
        .and_then(Value::as_array)
        .ok_or("DataChangeNotify needs notifyItems")?;
    let ours = udr_am_data_path(supi);
    let mut changes = Vec::new();
    for item in items {
        let resource = item
            .get("resourceId")
            .and_then(Value::as_str)
            .ok_or("NotifyItem needs resourceId")?;
        let path = resource.split_once("://").map_or(resource, |(_, rest)| {
            rest.find('/').map_or("/", |i| &rest[i..])
        });
        if path.trim_end_matches('/') != ours {
            continue;
        }
        let item_changes = item
            .get("changes")
            .and_then(Value::as_array)
            .ok_or("NotifyItem needs changes")?;
        changes.extend(item_changes.iter().cloned());
    }
    Ok(changes)
}

/// The `ModificationNotification` (TS 29.503 §6.1.6.2.21) telling SDM subscription
/// `subscription_id` of `changes` to `supi`'s am-data.
pub fn modification_notification(supi: &str, subscription_id: &str, changes: &[Value]) -> Value {
    json!({
        "notifyItems": [{
            "resourceId": format!("/nudm-sdm/v2/{supi}/am-data"),
            "changes": changes,
        }],
        "subscriptionId": subscription_id,
    })
}

/// What one consumer's try came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    /// Answered (2xx, a refusal, or 404): not tried again.
    Done,
    /// No answer, 408, 429 or 5xx: tried again after a backoff.
    Retry,
}

/// Tell `sub` of `changes`.
async fn deliver(supi: &str, sub: &UdmSdmSubscription, changes: &[Value]) -> Delivery {
    let Some(callback) = sub.callback_reference.as_deref() else {
        return Delivery::Done;
    };
    let target = nextgcore_sbi::log_redact::redact_last_segment(callback);
    let body = modification_notification(supi, &sub.id, changes);
    let sent = tokio::time::timeout(
        CALL_TIMEOUT,
        crate::sbi_path::udm_sbi_send_callback_notification(callback, &body),
    )
    .await;
    match sent {
        Ok(Ok(resp)) if (200..300).contains(&resp.status) => {
            log::info!(
                "[{supi}] am-data change notified to {target}: {}",
                resp.status
            );
            Delivery::Done
        }
        Ok(Ok(resp)) if resp.status == 404 => {
            log::info!(
                "[{supi}] {target} answered 404: SDM subscription {} is gone, removed",
                sub.id
            );
            {
                let held = STATE_LOCK.lock().await;
                let ctx = udm_self();
                if let Ok(context) = ctx.read() {
                    context.sdm_subscription_remove(&sub.id);
                }
                if let Err(e) = persist_locked(&held, &[Rec::Sub(&sub.id)]).await {
                    log::error!("[{supi}] SDM subscription removal not written: {e}");
                }
            }
            spawn_reconcile(supi);
            Delivery::Done
        }
        Ok(Ok(resp)) if matches!(resp.status, 408 | 429) || resp.status >= 500 => {
            log::warn!(
                "[{supi}] {target} answered {} to the am-data change; resent",
                resp.status
            );
            Delivery::Retry
        }
        Ok(Ok(resp)) => {
            log::warn!(
                "[{supi}] {target} refused the am-data change ({}); not resent",
                resp.status
            );
            Delivery::Done
        }
        Ok(Err(e)) => {
            log::warn!("[{supi}] am-data change not delivered: {e}; resent");
            Delivery::Retry
        }
        Err(_) => {
            log::warn!("[{supi}] am-data change to {target} timed out; resent");
            Delivery::Retry
        }
    }
}

/// `POST /nudm-callback/v1/{supi}/udr-data-change/{token}`: the UDR's
/// `DataChangeNotify` for `supi`'s am-data. Answered 204 once the change is queued
/// and written; 503 when the queue is full or the write failed (nothing is then
/// kept, and the UDR resends it).
pub async fn handle_udr_data_change(supi: &str, token: &str, request: &SbiRequest) -> SbiResponse {
    if !token_matches(supi, token) {
        // Not a leg this UDM holds (one it deleted, or one from before a restart
        // without a state file): 404, on which the UDR removes it.
        return nextgcore_sbi::server::send_not_found(
            "No such UDR data-change subscription",
            Some("SUBSCRIPTION_NOT_FOUND"),
        );
    }
    let notify: Value = match request
        .http
        .content
        .as_deref()
        .map(serde_json::from_str::<Value>)
    {
        Some(Ok(v)) => v,
        _ => {
            return nextgcore_sbi::server::send_bad_request(
                "DataChangeNotify body is not JSON",
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };
    let changes = match am_data_changes(supi, &notify) {
        Ok(c) => c,
        Err(e) => return nextgcore_sbi::server::send_bad_request(&e, Some("INVALID_MSG_FORMAT")),
    };
    if changes.is_empty() {
        return SbiResponse::with_status(204);
    }
    let unavailable =
        |why: &str| nextgcore_sbi::server::send_error(503, "Service Unavailable", why, None);
    let held = STATE_LOCK.lock().await;
    // The leg may have gone while this waited for the lock.
    if !token_matches(supi, token) {
        return nextgcore_sbi::server::send_not_found(
            "No such UDR data-change subscription",
            Some("SUBSCRIPTION_NOT_FOUND"),
        );
    }
    let saved_queue = lock(&QUEUES).as_ref().and_then(|m| m.get(supi).cloned());
    let saved_told = told(supi);
    let started = match enqueue_locked(supi, changes.clone(), false) {
        Ok(started) => started,
        Err(()) => {
            log::warn!(
                "[{supi}] {MAX_QUEUED_PER_SUPI} am-data changes already wait for delivery: \
                 503, the UDR resends this one"
            );
            return unavailable("too many am-data changes waiting for delivery");
        }
    };
    let mut t = saved_told.clone().unwrap_or_default();
    t.seq += 1;
    t.doc = t.doc.as_ref().and_then(|doc| apply_changes(doc, &changes));
    if t.doc.is_none() {
        t.resync = true;
    }
    set_told(supi, Some(t));
    if let Err(e) = persist_locked(&held, &[Rec::Queue(supi), Rec::Told(supi)]).await {
        // Nothing kept: the UDR keeps its baseline and resends.
        log::error!("[{supi}] am-data change not written to the state file: {e}; 503");
        restore_queue(supi, saved_queue);
        set_told(supi, saved_told);
        return unavailable("the change could not be stored");
    }
    drop(held);
    if started {
        spawn_worker(supi.to_string());
    }
    SbiResponse::with_status(204)
}

/// Put `supi`'s queue back to `saved` (undoing an enqueue whose write failed).
fn restore_queue(supi: &str, saved: Option<VecDeque<Queued>>) {
    let mut map = lock(&QUEUES);
    let map = map.get_or_insert_with(HashMap::new);
    match saved {
        Some(q) => map.insert(supi.to_string(), q),
        None => map.remove(supi),
    };
}

/// Queue `changes` for delivery to `supi`'s consumers, behind every change accepted
/// before them. `Ok(true)` when the SUPI had no queue, so the caller starts its
/// worker ([`spawn_worker`]) once the change is written. `Err` when the queue is
/// full ([`MAX_QUEUED_PER_SUPI`]); `over_cap` lets one re-derived change in past
/// the bound ([`resync`]). The caller holds [`STATE_LOCK`].
fn enqueue_locked(supi: &str, changes: Vec<Value>, over_cap: bool) -> Result<bool, ()> {
    let mut map = lock(&QUEUES);
    let map = map.get_or_insert_with(HashMap::new);
    let entry = Queued {
        changes,
        pending: None,
    };
    if let Some(queue) = map.get_mut(supi) {
        // A worker runs for the SUPI and takes this one after the others.
        // The head stays in the queue while it is being delivered, so the bound
        // is on the ones waiting behind it.
        let waiting = queue.len().saturating_sub(1);
        if waiting >= MAX_QUEUED_PER_SUPI && !(over_cap && waiting <= MAX_QUEUED_PER_SUPI) {
            return Err(());
        }
        queue.push_back(entry);
        return Ok(false);
    }
    map.insert(supi.to_string(), VecDeque::from([entry]));
    Ok(true)
}

/// Start `supi`'s worker: it drains the SUPI's queue in order ([`drain`]).
fn spawn_worker(supi: String) {
    let generation = GENERATION.load(Ordering::SeqCst);
    IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
    tokio::spawn(async move {
        Box::pin(drain(&supi, generation)).await;
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
    });
}

/// The oldest change waiting for `supi`'s worker, left in place until it is done
/// with. When none waits the queue is removed, under the same lock, so the worker
/// ends and the next accepted change starts a new one.
fn head_or_end(supi: &str) -> Option<Queued> {
    let mut map = lock(&QUEUES);
    let map = map.as_mut()?;
    let queue = map.get_mut(supi)?;
    match queue.front() {
        Some(head) => Some(head.clone()),
        None => {
            map.remove(supi);
            None
        }
    }
}

/// Drain `supi`'s queue: tell every pending consumer of the head change, resend to
/// those that did not answer with backoff ([`retry_backoff`]), and move on once each
/// has answered or [`retry_window`] has passed. Each step is written before the next
/// (#1836), so a restart resumes where it stopped and tells no one twice who had
/// answered. Stops when a restart's generation replaced `generation`.
async fn drain(supi: &str, generation: u64) {
    let alive = || GENERATION.load(Ordering::SeqCst) == generation;
    let mut attempt = 0u32;
    let mut first_try: Option<std::time::Instant> = None;
    loop {
        let head = {
            // Under the state lock, so a change is taken only once it is written.
            let _held = STATE_LOCK.lock().await;
            if !alive() {
                return;
            }
            head_or_end(supi)
        };
        let Some(head) = head else {
            return;
        };
        let subs = am_data_subscriptions(supi);
        if subs.is_empty() {
            // Its subscriptions went without an unsubscribe (the UE was removed).
            spawn_reconcile(supi);
        }
        let targets: Vec<UdmSdmSubscription> = subs
            .into_iter()
            .filter(|s| head.pending.as_ref().is_none_or(|p| p.contains(&s.id)))
            .collect();
        let mut again = BTreeSet::new();
        if crate::notify::notifications_enabled() {
            let mut each = tokio::task::JoinSet::new();
            for sub in targets {
                let (supi, changes) = (supi.to_string(), head.changes.clone());
                each.spawn(async move {
                    let outcome = deliver(&supi, &sub, &changes).await;
                    (sub.id, outcome)
                });
            }
            while let Some(done) = each.join_next().await {
                if let Ok((id, Delivery::Retry)) = done {
                    again.insert(id);
                }
            }
        }
        let started = *first_try.get_or_insert_with(std::time::Instant::now);
        let give_up = !again.is_empty()
            && attempt + 1 >= RETRY_MIN_TRIES
            && started.elapsed() >= retry_window();
        if give_up {
            log::error!(
                "[{supi}] am-data change not delivered to {} SDM subscription(s) in {} s \
                 ({} tries): given up",
                again.len(),
                retry_window().as_secs(),
                attempt + 1
            );
        }
        let held = STATE_LOCK.lock().await;
        if !alive() {
            return;
        }
        {
            let mut map = lock(&QUEUES);
            let Some(queue) = map.as_mut().and_then(|m| m.get_mut(supi)) else {
                return;
            };
            if again.is_empty() || give_up {
                queue.pop_front();
            } else if let Some(front) = queue.front_mut() {
                front.pending = Some(again.clone());
            }
        }
        if let Err(e) = persist_locked(&held, &[Rec::Queue(supi)]).await {
            log::error!("[{supi}] am-data delivery progress not written: {e}");
        }
        drop(held);
        if again.is_empty() || give_up {
            attempt = 0;
            first_try = None;
        } else {
            attempt += 1;
            tokio::time::sleep(retry_backoff(attempt)).await;
        }
    }
}

/// Forget every leg, queue and told am-data, and stop every worker (tests).
#[cfg(test)]
pub(crate) fn clear_legs() {
    GENERATION.fetch_add(1, Ordering::SeqCst);
    *lock(&LEGS) = None;
    *lock(&QUEUES) = None;
    *lock(&TOLD) = None;
}

/// `supi`'s leg's token, if any (tests).
#[cfg(test)]
pub(crate) fn leg_token(supi: &str) -> Option<String> {
    leg(supi).map(|l| l.token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ee_amf::set_notify_base;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use std::sync::Arc;

    type Seen = Arc<Mutex<Vec<(String, String, Value)>>>;

    async fn wait_listening(addr: std::net::SocketAddr) {
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// A peer answering `status` to every request (201 with a Location to a POST
    /// when `status` is 201), recording (method, path, body). Its base URI.
    async fn stub(status: u16) -> (SbiServer, String, Seen) {
        let seen: Seen = Arc::default();
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        let log = seen.clone();
        server
            .start(move |req: SbiRequest| {
                let log = log.clone();
                async move {
                    let body = req
                        .http
                        .content
                        .as_deref()
                        .and_then(|b| serde_json::from_str(b).ok())
                        .unwrap_or(Value::Null);
                    let path = req.header.uri.clone();
                    log.lock()
                        .expect("seen")
                        .push((req.header.method.clone(), path, body));
                    match (req.header.method.as_str(), status) {
                        ("POST", 201) => SbiResponse::with_status(201).with_header(
                            "Location",
                            "/nudr-dr/v2/subscription-data/subs-to-notify/77",
                        ),
                        ("DELETE", _) => SbiResponse::with_status(204),
                        _ => SbiResponse::with_status(status),
                    }
                }
            })
            .await
            .expect("stub starts");
        wait_listening(addr).await;
        (server, format!("http://127.0.0.1:{}", addr.port()), seen)
    }

    fn requests(seen: &Seen, method: &str) -> Vec<(String, Value)> {
        seen.lock()
            .expect("seen")
            .iter()
            .filter(|(m, _, _)| m == method)
            .map(|(_, p, b)| (p.clone(), b.clone()))
            .collect()
    }

    /// The UDM's own SBI listener (its real router); its base URI.
    async fn udm_server() -> (SbiServer, String) {
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let udm = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        udm.start(crate::app::udm_sbi_request_handler)
            .await
            .expect("udm starts");
        wait_listening(addr).await;
        (udm, format!("http://127.0.0.1:{}", addr.port()))
    }

    /// An AMF's SDM subscribe of `supi`'s am-data with `callback`; the reconcile it
    /// spawned has finished on return.
    async fn sdm_subscribe(supi: &str, callback: &str) -> String {
        let mut req = SbiRequest::post(format!("/nudm-sdm/v2/{supi}/sdm-subscriptions"));
        req.http.content = Some(
            json!({
                "nfInstanceId": "amf-1775",
                "callbackReference": callback,
                "monitoredResourceUris": [format!("/nudm-sdm/v2/{supi}/am-data")],
            })
            .to_string(),
        );
        let resp = crate::app::handle_sdm_subscribe(supi, &req).await;
        assert_eq!(resp.status, 201);
        wait_idle().await;
        serde_json::from_str::<Value>(resp.http.content.as_deref().expect("body")).expect("json")
            ["subscriptionId"]
            .as_str()
            .expect("id")
            .to_string()
    }

    /// The UDR's DataChangeNotify for `supi`'s am-data going from `old` to `new`,
    /// built by udrd's REAL builders.
    fn udr_notify(supi: &str, callback: &str, old: &Value, new: &Value) -> Value {
        use nextgcore_udrd::data_store as udr;
        let sub = udr::StoredSub {
            id: "77".to_string(),
            kind: udr::SubKind::SubscriptionData,
            notify_uri: callback.to_string(),
            body: json!({ "callbackReference": callback }),
            owner: None,
        };
        udr::data_change_notify(
            &sub,
            supi,
            &udr::am_data_path(supi),
            udr::am_data_changes(old, new),
        )
    }

    async fn post(uri: &str, body: &Value) -> u16 {
        crate::sbi_path::udm_sbi_send_callback_notification(uri, body)
            .await
            .expect("answered")
            .status
    }

    /// The locks, a dev profile, fresh UDM and AMF contexts, the UDR env pointed at
    /// `udr_base`. Hold the returned guards.
    #[allow(clippy::await_holding_lock)] // the std guard is the returned serialisation
    async fn setup(
        udr_base: &str,
    ) -> (
        tokio::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        let udr_env = crate::sbi_path::UDR_ENV_TEST_LOCK.lock().await;
        let guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        std::env::remove_var("UDM_NOTIFY_DISABLE");
        crate::context::udm_context_init(64, 64);
        // Other tests' SDM subscriptions stay in the shared context otherwise, and
        // a leg refresh would reconcile them against this test's UDR.
        udm_self().read().expect("ctx").ue_remove_all();
        clear_legs();
        // #1836: memory-only unless a test opens a state file; resends quick.
        init_state(None).await.expect("memory-only");
        RETRY_BASE_MS.store(50, Ordering::SeqCst);
        RETRY_WINDOW_MS.store(600_000, Ordering::SeqCst);
        let port = udr_base.rsplit(':').next().expect("port");
        std::env::set_var("UDR_SBI_ADDR", "127.0.0.1");
        std::env::set_var("UDR_SBI_PORT", port);
        (udr_env, guard)
    }

    /// **#1775 acceptance, TS 23.502 §4.5.1, both peers.** The AMF's SDM
    /// subscription to am-data makes this UDM subscribe at the UDR for that am-data
    /// (TS 29.505), with its own tokened callback. A provisioning change of the
    /// subscribed UE-AMBR and GPSI, as udrd's real builders put it in a
    /// DataChangeNotify, posted to that callback on the UDM's real router, reaches
    /// amfd's REAL `sdmsubscription-notify/{token}` handler, which applies it: the
    /// UE's UE-AMBR and GPSI are the new ones. The AMF unsubscribing takes the UDR
    /// subscription with it.
    ///
    /// REVERT-VERIFIED: with `spawn_reconcile` not called at SDM subscribe, no UDR
    /// subscription is made; with the deliveries skipped in
    /// `handle_udr_data_change`, the UDR is answered 204 and the AMF keeps the old
    /// UE-AMBR.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn a_provisioned_am_data_change_reaches_amfd_through_the_udm_1775() {
        let (_udr, udr_base, udr_seen) = stub(201).await;
        let _locks = setup(&udr_base).await;
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base.clone()));
        let supi = "imsi-001010000017751";
        let amf_token = "0123456789abcdef0123456789a17751";
        let old = json!({
            "subscribedUeAmbr": {"uplink": "1 Mbps", "downlink": "2 Mbps"},
            "gpsis": ["msisdn-4917751"],
        });

        // amfd's REAL Namf router, holding the UE (CM-IDLE) with its am-data.
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let amf = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        amf.start(nextgcore_amfd::namf_request_handler)
            .await
            .expect("amfd starts");
        wait_listening(addr).await;
        nextgcore_amfd::test_support::init_context();
        {
            let ctx = nextgcore_amfd::context::amf_self();
            let guard = ctx.read().expect("amf ctx");
            let ran = guard.ran_ue_add(901_775, 61_775).expect("ran_ue_add");
            let mut ue = guard.amf_ue_add(ran.id).expect("amf_ue_add");
            ue.supi = Some(supi.to_string());
            ue.sdm_notify_token = Some(amf_token.to_string());
            ue.am_data = Some(old.clone());
            ue.gpsi = Some("msisdn-4917751".to_string());
            ue.ue_ambr.uplink = 1_000_000;
            ue.ue_ambr.downlink = 2_000_000;
            ue.ran_ue_id = nextgcore_amfd::context::NEXTGCORE_INVALID_POOL_ID;
            guard.amf_ue_publish(&ue, 61_775, 901_775);
            guard.amf_ue_update(&ue);
        }
        let built = nextgcore_amfd::sbi_path::sdm_callback_reference(supi, Some(amf_token));
        let amf_callback = format!(
            "http://127.0.0.1:{}{}",
            addr.port(),
            &built[built.find("/namf-callback").expect("path")..]
        );

        let sdm_id = sdm_subscribe(supi, &amf_callback).await;
        let made = requests(&udr_seen, "POST");
        assert_eq!(made.len(), 1, "one UDR subscription: {made:?}");
        let (path, body) = &made[0];
        assert_eq!(path, "/nudr-dr/v2/subscription-data/subs-to-notify");
        assert_eq!(
            body["monitoredResourceUris"],
            json!([format!(
                "/nudr-dr/v2/subscription-data/{supi}/provisioned-data/am-data"
            )])
        );
        assert!(
            body.get("ueId").is_none(),
            "am-data only, not every change of the UE"
        );
        let token = leg_token(supi).expect("leg");
        let udm_callback = format!("{udm_base}{}", data_change_path(supi, &token));
        assert_eq!(body["callbackReference"], udm_callback);

        let new = json!({
            "subscribedUeAmbr": {"uplink": "5 Mbps", "downlink": "10 Mbps"},
            "gpsis": ["msisdn-4917759"],
        });
        let notify = udr_notify(supi, &udm_callback, &old, &new);
        assert_eq!(post(&udm_callback, &notify).await, 204);
        // Accepted, then delivered (#1775 review MAJOR-1).
        wait_idle().await;
        let ue = nextgcore_amfd::context::amf_self()
            .read()
            .expect("amf ctx")
            .amf_ue_find_by_supi(supi)
            .expect("ue");
        assert_eq!(
            (ue.ue_ambr.uplink, ue.ue_ambr.downlink),
            (5_000_000, 10_000_000),
            "the new UE-AMBR"
        );
        assert_eq!(ue.gpsi.as_deref(), Some("msisdn-4917759"), "the new GPSI");

        assert_eq!(
            crate::app::handle_sdm_unsubscribe(supi, &sdm_id)
                .await
                .status,
            204
        );
        wait_idle().await;
        assert_eq!(
            requests(&udr_seen, "DELETE"),
            vec![(
                "/nudr-dr/v2/subscription-data/subs-to-notify/77".to_string(),
                Value::Null
            )],
            "the last am-data subscription takes the UDR leg with it"
        );
        assert!(leg_token(supi).is_none());
        amf.stop().await.expect("stop");
    }

    /// **#1775, TS 29.503 Table 6.1.5.2-3 at the consumer.** A notification on a
    /// token this UDM does not hold is 404 (the UDR then removes it) and is sent to
    /// no one. A consumer's 400 is a refusal: the change is sent once and not again,
    /// and the subscription stays. A consumer's 404 says its subscription is gone:
    /// it is removed here, and with it the UDR leg.
    ///
    /// REVERT-VERIFIED: with `token_matches` not checked, the forged notification is
    /// delivered (the 400 consumer sees 2 posts); with the 404 arm not removing the
    /// subscription, it is still stored and no DELETE reaches the UDR.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn refusals_are_not_resent_and_a_gone_consumer_is_removed_1775() {
        let (_udr, udr_base, udr_seen) = stub(201).await;
        let _locks = setup(&udr_base).await;
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base.clone()));
        let (_refusing, refusing_base, refused) = stub(400).await;
        let (_gone, gone_base, gone) = stub(404).await;
        let supi = "imsi-001010000017752";
        let refusing_id = sdm_subscribe(supi, &format!("{refusing_base}/cb/sdm-notify/a")).await;
        let gone_id = sdm_subscribe(supi, &format!("{gone_base}/cb/sdm-notify/b")).await;
        assert_eq!(requests(&udr_seen, "POST").len(), 1, "one leg per SUPI");
        let token = leg_token(supi).expect("leg");
        let udm_callback = format!("{udm_base}{}", data_change_path(supi, &token));
        let notify = udr_notify(
            supi,
            &udm_callback,
            &json!({"gpsis": ["msisdn-1"]}),
            &json!({"gpsis": ["msisdn-2"]}),
        );

        let forged = format!("{udm_base}{}", data_change_path(supi, "0000forged0000"));
        assert_eq!(
            post(&forged, &notify).await,
            404,
            "not a leg this UDM holds"
        );
        assert!(requests(&refused, "POST").is_empty() && requests(&gone, "POST").is_empty());

        assert_eq!(post(&udm_callback, &notify).await, 204);
        wait_idle().await;
        let sent = requests(&refused, "POST");
        assert_eq!(sent.len(), 1, "a refusal is not resent: {sent:?}");
        assert_eq!(
            sent[0].1,
            modification_notification(
                supi,
                &refusing_id,
                &[json!({"op": "REPLACE", "path": "/gpsis",
                         "newValue": ["msisdn-2"], "origValue": ["msisdn-1"]})]
            )
        );
        assert_eq!(requests(&gone, "POST").len(), 1);
        let held: Vec<String> = udm_self()
            .read()
            .expect("ctx")
            .sdm_subscriptions_for_supi(supi)
            .into_iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(held, vec![refusing_id.clone()], "the gone one is removed");
        assert!(!held.contains(&gone_id));
        assert!(
            requests(&udr_seen, "DELETE").is_empty(),
            "one still needs the leg"
        );

        assert_eq!(
            crate::app::handle_sdm_unsubscribe(supi, &refusing_id)
                .await
                .status,
            204
        );
        wait_idle().await;
        assert_eq!(requests(&udr_seen, "DELETE").len(), 1);
    }

    /// A consumer that answers 204 to each notification after `delay(body)`. It
    /// records the body when the answer is made (so the record is in answer order),
    /// or on arrival when `on_arrival`. Its base URI.
    async fn slow_consumer(
        delay: fn(&Value) -> Duration,
        on_arrival: bool,
    ) -> (SbiServer, String, Arc<Mutex<Vec<Value>>>) {
        let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        let log = seen.clone();
        server
            .start(move |req: SbiRequest| {
                let log = log.clone();
                async move {
                    let body: Value = req
                        .http
                        .content
                        .as_deref()
                        .and_then(|b| serde_json::from_str(b).ok())
                        .unwrap_or(Value::Null);
                    if on_arrival {
                        log.lock().expect("seen").push(body.clone());
                    }
                    tokio::time::sleep(delay(&body)).await;
                    if !on_arrival {
                        log.lock().expect("seen").push(body);
                    }
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("consumer starts");
        wait_listening(addr).await;
        (server, format!("http://127.0.0.1:{}", addr.port()), seen)
    }

    /// The `newValue` of the first change of each recorded ModificationNotification.
    fn told_values(seen: &Arc<Mutex<Vec<Value>>>) -> Vec<Value> {
        seen.lock()
            .expect("seen")
            .iter()
            .map(|n| n["notifyItems"][0]["changes"][0]["newValue"].clone())
            .collect()
    }

    /// **#1775 review MAJOR-1** (failure-path check 2, both peers): the UDR's real
    /// delivery (`deliver_notification`, which waits 3 s) is answered 204 as soon as
    /// the UDM has accepted the notification, although its two consumers each take
    /// 2 s to answer, so trying them first would take 4 s, longer than the UDR
    /// waits. So the UDR advances and does not
    /// resend, and each consumer gets exactly one POST.
    ///
    /// REVERT-VERIFIED: with the consumers tried one after another before the UDR is
    /// answered (the code under review), the UDR's delivery times out ("answered
    /// before the consumer").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn the_udr_is_answered_before_a_slow_consumer_1775() {
        let (_udr, udr_base, _udr_seen) = stub(201).await;
        let _locks = setup(&udr_base).await;
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base.clone()));
        // 2 s each: 1 s inside the UDM's 3 s bound on a consumer (#1836 resends a
        // timed-out one), and 4 s one after the other, 1 s longer than the UDR
        // waits (R28: the margin either way is 1 s).
        let (_slow, slow_base, seen) = slow_consumer(|_| Duration::from_secs(2), true).await;
        let (_slower, slower_base, seen_too) =
            slow_consumer(|_| Duration::from_secs(2), true).await;
        let supi = "imsi-001010000017754";
        sdm_subscribe(supi, &format!("{slow_base}/cb/sdm-notify/slow")).await;
        sdm_subscribe(supi, &format!("{slower_base}/cb/sdm-notify/slower")).await;
        let token = leg_token(supi).expect("leg");
        let udm_callback = format!("{udm_base}{}", data_change_path(supi, &token));
        let notify = udr_notify(
            supi,
            &udm_callback,
            &json!({"gpsis": ["msisdn-1"]}),
            &json!({"gpsis": ["msisdn-2"]}),
        );
        let answered =
            nextgcore_udrd::data_store::deliver_notification(&udm_callback, &notify).await;
        assert_eq!(answered, Ok(204), "answered before the consumer");
        // Each answers within the UDM's bound, and is told once.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        wait_idle().await;
        for seen in [&seen, &seen_too] {
            assert_eq!(
                told_values(seen),
                vec![json!(["msisdn-2"])],
                "exactly one POST"
            );
        }
        clear_legs();
    }

    /// **#1775 review MAJOR-3**: two DataChangeNotify of one SUPI that overlap reach
    /// the consumer in the order the UDR sent them, although the first is the slow
    /// one: the consumer takes 800 ms over the first and none over the second. Both
    /// are accepted (204) at once.
    ///
    /// REVERT-VERIFIED: with a second worker started for the SUPI while one runs
    /// (`enqueue_changes` not joining the running worker's queue), the second
    /// change is told first ("in the order the UDR sent them").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn overlapping_changes_of_one_supi_arrive_in_order_1775() {
        let (_udr, udr_base, _udr_seen) = stub(201).await;
        let _locks = setup(&udr_base).await;
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base.clone()));
        let (_slow, slow_base, seen) = slow_consumer(
            |body| {
                if body["notifyItems"][0]["changes"][0]["newValue"] == json!(["msisdn-2"]) {
                    Duration::from_millis(800)
                } else {
                    Duration::ZERO
                }
            },
            false,
        )
        .await;
        let supi = "imsi-001010000017755";
        sdm_subscribe(supi, &format!("{slow_base}/cb/sdm-notify/order")).await;
        let token = leg_token(supi).expect("leg");
        let udm_callback = format!("{udm_base}{}", data_change_path(supi, &token));
        let first = udr_notify(
            supi,
            &udm_callback,
            &json!({"gpsis": ["msisdn-1"]}),
            &json!({"gpsis": ["msisdn-2"]}),
        );
        let second = udr_notify(
            supi,
            &udm_callback,
            &json!({"gpsis": ["msisdn-2"]}),
            &json!({"gpsis": ["msisdn-3"]}),
        );
        assert_eq!(post(&udm_callback, &first).await, 204);
        assert_eq!(post(&udm_callback, &second).await, 204);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        wait_idle().await;
        assert_eq!(
            told_values(&seen),
            vec![json!(["msisdn-2"]), json!(["msisdn-3"])],
            "in the order the UDR sent them"
        );
        clear_legs();
    }

    /// **#1775 review MAJOR-1**: a SUPI's queue is bounded. While its consumer is
    /// slow, the notification after `MAX_QUEUED_PER_SUPI` waiting ones is answered
    /// 503 (the UDR resends it at its next pass); every accepted one is delivered.
    ///
    /// REVERT-VERIFIED: with the bound not checked, that notification is answered
    /// 204 ("bounded").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn a_full_queue_is_answered_503_1775() {
        let (_udr, udr_base, _udr_seen) = stub(201).await;
        let _locks = setup(&udr_base).await;
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base.clone()));
        let (_slow, slow_base, seen) = slow_consumer(
            |body| {
                if body["notifyItems"][0]["changes"][0]["newValue"] == json!(0) {
                    Duration::from_millis(1500)
                } else {
                    Duration::ZERO
                }
            },
            false,
        )
        .await;
        let supi = "imsi-001010000017756";
        sdm_subscribe(supi, &format!("{slow_base}/cb/sdm-notify/full")).await;
        let token = leg_token(supi).expect("leg");
        let udm_callback = format!("{udm_base}{}", data_change_path(supi, &token));
        let change =
            |n: usize| udr_notify(supi, &udm_callback, &json!({"n": n + 1}), &json!({"n": n}));
        // The first is taken by the worker and held by the slow consumer; the
        // next MAX_QUEUED_PER_SUPI wait.
        for n in 0..=MAX_QUEUED_PER_SUPI {
            assert_eq!(post(&udm_callback, &change(n)).await, 204, "{n}");
        }
        assert_eq!(
            post(&udm_callback, &change(MAX_QUEUED_PER_SUPI + 1)).await,
            503,
            "bounded"
        );
        tokio::time::sleep(Duration::from_millis(2000)).await;
        wait_idle().await;
        assert_eq!(seen.lock().expect("seen").len(), MAX_QUEUED_PER_SUPI + 1);
        clear_legs();
    }

    /// #1775: only the am-data items of a DataChangeNotify are passed on, with their
    /// ChangeItems unchanged; a malformed one is refused.
    #[test]
    fn only_am_data_changes_are_passed_on_1775() {
        let supi = "imsi-001010000017753";
        let ambr = json!({"op": "REPLACE", "path": "/subscribedUeAmbr", "newValue": {}});
        let notify = json!({
            "ueId": supi,
            "notifyItems": [
                {"resourceId": format!("/nudr-dr/v2/subscription-data/{supi}/pp-data"),
                 "changes": [{"op": "REPLACE", "path": ""}]},
                {"resourceId": format!(
                    "http://udr:7777/nudr-dr/v2/subscription-data/{supi}/provisioned-data/am-data"),
                 "changes": [ambr]},
            ],
        });
        assert_eq!(am_data_changes(supi, &notify), Ok(vec![ambr]));
        assert!(am_data_changes(supi, &json!({})).is_err());
        assert!(am_data_changes(supi, &json!({"notifyItems": [{"changes": []}]})).is_err());
    }

    // -----------------------------------------------------------------------
    // #1836: durability
    // -----------------------------------------------------------------------

    /// What the programmable UDR holds and was asked.
    #[derive(Default)]
    struct UdrState {
        /// Subscriptions made so far.
        made: u32,
        /// Subscription paths the UDR no longer holds (PATCH answers 404).
        dropped: BTreeSet<String>,
        /// The am-data a GET answers.
        am_data: Value,
        /// (method, path, body) of every request.
        seen: Vec<(String, String, Value)>,
    }

    /// A UDR that makes subscriptions `.../subs-to-notify/{77 + n}` (echoing the
    /// suggested expiry), answers a PATCH 204 unless the subscription was dropped
    /// (404), and serves `am_data` to a GET. Its base URI.
    async fn programmable_udr(am_data: Value) -> (SbiServer, String, Arc<Mutex<UdrState>>) {
        let state = Arc::new(Mutex::new(UdrState {
            am_data,
            ..Default::default()
        }));
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        let st = state.clone();
        server
            .start(move |req: SbiRequest| {
                let st = st.clone();
                async move {
                    let body: Value = req
                        .http
                        .content
                        .as_deref()
                        .and_then(|b| serde_json::from_str(b).ok())
                        .unwrap_or(Value::Null);
                    let (method, path) = (req.header.method.clone(), req.header.uri.clone());
                    let mut st = st.lock().expect("udr");
                    st.seen.push((method.clone(), path.clone(), body.clone()));
                    match method.as_str() {
                        "POST" => {
                            let n = 77 + st.made;
                            st.made += 1;
                            let mut created = body;
                            created["subscriptionId"] = json!(n.to_string());
                            SbiResponse::with_status(201)
                                .with_header(
                                    "Location",
                                    format!("/nudr-dr/v2/subscription-data/subs-to-notify/{n}"),
                                )
                                .with_body(created.to_string(), "application/json")
                        }
                        "PATCH" if st.dropped.contains(&path) => SbiResponse::with_status(404),
                        "PATCH" | "DELETE" => SbiResponse::with_status(204),
                        "GET" => SbiResponse::with_status(200)
                            .with_body(st.am_data.to_string(), "application/json"),
                        _ => SbiResponse::with_status(405),
                    }
                }
            })
            .await
            .expect("udr starts");
        wait_listening(addr).await;
        (server, format!("http://127.0.0.1:{}", addr.port()), state)
    }

    type Answered = Arc<Mutex<Vec<(u16, Value)>>>;

    /// A consumer answering each POST with the next status of `script`, then with
    /// `status`. Records (status, body). Its base URI.
    async fn scripted_consumer(
        script: Vec<u16>,
        status: Arc<std::sync::atomic::AtomicU16>,
    ) -> (SbiServer, String, Answered) {
        let seen: Answered = Arc::default();
        let script = Arc::new(Mutex::new(VecDeque::from(script)));
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        let log = seen.clone();
        server
            .start(move |req: SbiRequest| {
                let (log, script, status) = (log.clone(), script.clone(), status.clone());
                async move {
                    let body: Value = req
                        .http
                        .content
                        .as_deref()
                        .and_then(|b| serde_json::from_str(b).ok())
                        .unwrap_or(Value::Null);
                    let answer = script
                        .lock()
                        .expect("script")
                        .pop_front()
                        .unwrap_or_else(|| status.load(Ordering::SeqCst));
                    log.lock().expect("seen").push((answer, body));
                    SbiResponse::with_status(answer)
                }
            })
            .await
            .expect("consumer starts");
        wait_listening(addr).await;
        (server, format!("http://127.0.0.1:{}", addr.port()), seen)
    }

    /// The `newValue` of the first change of each notification `seen` answered
    /// `status` to.
    fn answered(seen: &Answered, status: Option<u16>) -> Vec<Value> {
        seen.lock()
            .expect("seen")
            .iter()
            .filter(|(s, _)| status.is_none_or(|want| *s == want))
            .map(|(_, n)| n["notifyItems"][0]["changes"][0]["newValue"].clone())
            .collect()
    }

    /// Wait until `seen` holds `n` answers of `status`, for at most 5 s.
    async fn wait_answers(seen: &Answered, status: u16, n: usize) {
        for _ in 0..500 {
            if answered(seen, Some(status)).len() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn temp_state_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "udm-{tag}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    /// A UDM crash: every worker stops, and everything in memory is gone.
    ///
    /// Under [`STATE_LOCK`], as a real crash cannot land between a change and its
    /// write (#1896 R30): `clear_legs` takes no lock of its own, so a worker that
    /// had passed its generation check could otherwise persist its SUPI's queue
    /// from the emptied maps, as a delete, and the "restarted" UDM would find it
    /// gone (`a_1836_snapshot_is_migrated_to_the_log_1896`, 4 in 6 parallel runs).
    async fn crash() {
        {
            let _held = STATE_LOCK.lock().await;
            clear_legs();
            udm_self().read().expect("ctx").ue_remove_all();
        }
        wait_idle().await;
    }

    fn gpsis(n: u32) -> Value {
        json!({"gpsis": [format!("msisdn-{n}")]})
    }

    /// **#1836 part 1, UDM restart (both peers: the UDR's real builders and
    /// delivery, the UDM's real router).** A change the UDM accepted (204 to the
    /// UDR) while its AMF answered 503 is in the state file. After a crash and a
    /// start on that file, the UDR's next notification on the same leg is admitted
    /// (the token is restored, not answered 404 as before), the change accepted
    /// before the crash is delivered, before the later one and once, and the first
    /// refresh re-points the leg to the restarted UDM's new address with the same
    /// token.
    ///
    /// REVERT-VERIFIED: with `persist_locked` writing nothing, nothing is restored
    /// ("the SDM subscription"); with the legs not restored by `init_state`, the
    /// restarted UDM answers the UDR's notification 404 ("the restored leg admits
    /// the UDR"); with the queues not restored, the change accepted before the
    /// crash never arrives ("delivered after the restart, in order, once").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn an_accepted_change_survives_a_udm_restart_1836() {
        let (_udr, udr_base, udr) = programmable_udr(gpsis(1)).await;
        let _locks = setup(&udr_base).await;
        let path = temp_state_path("1836-restart");
        init_state(Some(path.clone())).await.expect("state file");
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base.clone()));
        let status = Arc::new(std::sync::atomic::AtomicU16::new(503));
        let (_amf, amf_base, seen) = scripted_consumer(vec![], status.clone()).await;
        let supi = "imsi-001010000018361";
        let sdm_id = sdm_subscribe(supi, &format!("{amf_base}/cb/sdm-notify/r")).await;
        let token = leg_token(supi).expect("leg");
        let udm_callback = format!("{udm_base}{}", data_change_path(supi, &token));

        let first = udr_notify(supi, &udm_callback, &gpsis(1), &gpsis(2));
        assert_eq!(
            nextgcore_udrd::data_store::deliver_notification(&udm_callback, &first).await,
            Ok(204)
        );
        wait_answers(&seen, 503, 1).await;
        crash().await;
        assert!(!token_matches(supi, &token), "memory is gone");

        // Restarted on a new address, with the AMF back.
        let moved_base = udm_base.replace("127.0.0.1", "localhost");
        set_notify_base(Some(moved_base.clone()));
        status.store(204, Ordering::SeqCst);
        assert_eq!(
            init_state(Some(path.clone())).await,
            Ok(1),
            "the SDM subscription"
        );
        let held: Vec<String> = udm_self()
            .read()
            .expect("ctx")
            .sdm_subscriptions_for_supi(supi)
            .into_iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(held, vec![sdm_id]);
        let second = udr_notify(supi, &udm_callback, &gpsis(2), &gpsis(3));
        assert_eq!(
            nextgcore_udrd::data_store::deliver_notification(&udm_callback, &second).await,
            Ok(204),
            "the restored leg admits the UDR"
        );
        wait_answers(&seen, 204, 2).await;
        wait_idle().await;
        assert_eq!(
            answered(&seen, Some(204)),
            vec![json!(["msisdn-2"]), json!(["msisdn-3"])],
            "delivered after the restart, in order, once"
        );

        let refreshed = refresh_legs().await;
        assert_eq!(refreshed, vec![(supi.to_string(), Refreshed::Kept)]);
        let patches: Vec<(String, Value)> = udr
            .lock()
            .expect("udr")
            .seen
            .iter()
            .filter(|(m, _, _)| m == "PATCH")
            .map(|(_, p, b)| (p.clone(), b.clone()))
            .collect();
        assert_eq!(patches.len(), 1, "{patches:?}");
        assert_eq!(
            patches[0].0,
            "/nudr-dr/v2/subscription-data/subs-to-notify/77"
        );
        assert_eq!(patches[0].1[0]["path"], "/expiry");
        assert_eq!(
            patches[0].1[1],
            json!({"op": "replace", "path": "/callbackReference",
                   "value": format!("{moved_base}{}", data_change_path(supi, &token))}),
            "re-pointed, same token"
        );
        clear_legs();
        let _ = std::fs::remove_file(&path);
    }

    /// **#1836 part 1, failure-path check 1.** A change whose write to the state
    /// file fails is answered 503 and nothing of it is kept: no consumer is told,
    /// and the UDR (which keeps its baseline on a 5xx) resends it.
    ///
    /// REVERT-VERIFIED: with the failed write ignored, the change is answered 204
    /// ("not stored, so not accepted").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn a_change_that_cannot_be_stored_is_not_accepted_1836() {
        let (_udr, udr_base, _udr_state) = programmable_udr(gpsis(1)).await;
        let _locks = setup(&udr_base).await;
        let dir = temp_state_path("1836-dir");
        std::fs::create_dir_all(&dir).expect("dir");
        init_state(Some(dir.join("state.json")))
            .await
            .expect("state file");
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base.clone()));
        let status = Arc::new(std::sync::atomic::AtomicU16::new(204));
        let (_amf, amf_base, seen) = scripted_consumer(vec![], status).await;
        let supi = "imsi-001010000018362";
        sdm_subscribe(supi, &format!("{amf_base}/cb/sdm-notify/w")).await;
        let token = leg_token(supi).expect("leg");
        let udm_callback = format!("{udm_base}{}", data_change_path(supi, &token));
        // The directory goes, and a file takes its place: no write can succeed.
        std::fs::remove_dir_all(&dir).expect("rm");
        std::fs::write(&dir, b"x").expect("file");
        let change = udr_notify(supi, &udm_callback, &gpsis(1), &gpsis(2));
        assert_eq!(
            post(&udm_callback, &change).await,
            503,
            "not stored, so not accepted"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        wait_idle().await;
        assert!(answered(&seen, None).is_empty(), "no one told");
        assert!(lock(&QUEUES).as_ref().is_none_or(|m| !m.contains_key(supi)));
        clear_legs();
        init_state(None).await.expect("memory-only");
        let _ = std::fs::remove_file(&dir);
    }

    /// **#1836 part 2, failure-path check 2 (both peers: the UDM's real router and
    /// delivery).** A consumer that answers 503 is resent the change with backoff
    /// until it answers 204, and the change after it waits: it arrives second. The
    /// other consumer of the same SUPI answered the first try, and is not told
    /// again: each consumer gets each change exactly once with a 2xx.
    ///
    /// REVERT-VERIFIED: with a 5xx not resent (`deliver` answering `Done`), the
    /// failing consumer never gets the first change ("resent until it answers");
    /// with every consumer retried (the head's `pending` ignored), the answering one
    /// is told the first change three times ("not told again").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn a_failed_amf_notification_is_resent_in_order_1836() {
        let (_udr, udr_base, _udr_state) = programmable_udr(gpsis(1)).await;
        let _locks = setup(&udr_base).await;
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base.clone()));
        let ok = || Arc::new(std::sync::atomic::AtomicU16::new(204));
        let (_flaky, flaky_base, flaky) = scripted_consumer(vec![503, 503], ok()).await;
        let (_steady, steady_base, steady) = scripted_consumer(vec![], ok()).await;
        let supi = "imsi-001010000018363";
        sdm_subscribe(supi, &format!("{flaky_base}/cb/sdm-notify/f")).await;
        sdm_subscribe(supi, &format!("{steady_base}/cb/sdm-notify/s")).await;
        let token = leg_token(supi).expect("leg");
        let udm_callback = format!("{udm_base}{}", data_change_path(supi, &token));
        let first = udr_notify(supi, &udm_callback, &gpsis(1), &gpsis(2));
        let second = udr_notify(supi, &udm_callback, &gpsis(2), &gpsis(3));
        assert_eq!(post(&udm_callback, &first).await, 204);
        assert_eq!(post(&udm_callback, &second).await, 204);
        wait_answers(&flaky, 204, 2).await;
        wait_idle().await;
        assert_eq!(
            answered(&flaky, None),
            vec![
                json!(["msisdn-2"]),
                json!(["msisdn-2"]),
                json!(["msisdn-2"]),
                json!(["msisdn-3"])
            ],
            "resent until it answers, and the next change after it"
        );
        assert_eq!(
            answered(&steady, None),
            vec![json!(["msisdn-2"]), json!(["msisdn-3"])],
            "not told again"
        );
        clear_legs();
    }

    /// **#1836 part 2, bounded.** A consumer that never answers 2xx is resent the
    /// change for at most the retry window, then the change is given up and the
    /// SUPI's next change is delivered.
    ///
    /// REVERT-VERIFIED: with the change never given up, the next change does not
    /// arrive ("moves on").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn a_resend_is_given_up_after_its_window_1836() {
        let (_udr, udr_base, _udr_state) = programmable_udr(gpsis(1)).await;
        let _locks = setup(&udr_base).await;
        RETRY_WINDOW_MS.store(200, Ordering::SeqCst);
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base.clone()));
        let down = Arc::new(std::sync::atomic::AtomicU16::new(503));
        let (_amf, amf_base, seen) = scripted_consumer(vec![], down.clone()).await;
        let supi = "imsi-001010000018364";
        sdm_subscribe(supi, &format!("{amf_base}/cb/sdm-notify/g")).await;
        let token = leg_token(supi).expect("leg");
        let udm_callback = format!("{udm_base}{}", data_change_path(supi, &token));
        assert_eq!(
            post(
                &udm_callback,
                &udr_notify(supi, &udm_callback, &gpsis(1), &gpsis(2))
            )
            .await,
            204
        );
        assert_eq!(
            post(
                &udm_callback,
                &udr_notify(supi, &udm_callback, &gpsis(2), &gpsis(3))
            )
            .await,
            204
        );
        for _ in 0..300 {
            if answered(&seen, None).contains(&json!(["msisdn-3"])) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let told = answered(&seen, None);
        let tries = told.iter().filter(|v| **v == json!(["msisdn-2"])).count();
        assert!(tries >= RETRY_MIN_TRIES as usize, "tried {tries} times");
        assert!(told.contains(&json!(["msisdn-3"])), "moves on: {told:?}");
        down.store(204, Ordering::SeqCst);
        wait_idle().await;
        clear_legs();
    }

    /// **#1836 part 3 (both peers: the UDM's real router; udrd's side is
    /// `a_leg_refresh_extends_it_and_a_gone_leg_answers_404_1836`).** The UDR drops
    /// the leg (its expiry passed, or an hour of failures), and meanwhile the
    /// subscriber's GPSI is re-provisioned. The UDM's refresh is answered 404: the
    /// leg is made again with a new token, the am-data is read again, and the
    /// change made while there was no leg reaches the AMF, as the UDR words a
    /// change. The old token is no longer admitted.
    ///
    /// REVERT-VERIFIED: with the refresh's 404 not taken as gone, the leg is not
    /// made again ("the refresh learns the leg is gone"); with `resync` telling
    /// nothing, the AMF is not told the GPSI ("the change made while it was gone").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn a_dropped_udr_leg_is_made_again_and_what_was_missed_told_1836() {
        let (_udr, udr_base, udr) = programmable_udr(gpsis(1)).await;
        let _locks = setup(&udr_base).await;
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base.clone()));
        let ok = Arc::new(std::sync::atomic::AtomicU16::new(204));
        let (_amf, amf_base, seen) = scripted_consumer(vec![], ok).await;
        let supi = "imsi-001010000018365";
        let sdm_id = sdm_subscribe(supi, &format!("{amf_base}/cb/sdm-notify/d")).await;
        let old_token = leg_token(supi).expect("leg");
        let first = udr
            .lock()
            .expect("udr")
            .seen
            .iter()
            .find(|(m, _, _)| m == "POST")
            .map(|(_, _, b)| b.clone())
            .expect("subscribed");
        assert!(
            first["expiry"].as_str().is_some(),
            "an expiry is suggested: {first}"
        );
        assert!(
            answered(&seen, None).is_empty(),
            "a first leg tells nothing"
        );

        {
            let mut st = udr.lock().expect("udr");
            st.dropped
                .insert("/nudr-dr/v2/subscription-data/subs-to-notify/77".to_string());
            st.am_data = gpsis(2);
        }
        assert_eq!(
            refresh_legs().await,
            vec![(supi.to_string(), Refreshed::Gone)],
            "the refresh learns the leg is gone"
        );
        wait_idle().await;
        assert_eq!(udr.lock().expect("udr").made, 2, "made again");
        let new_token = leg_token(supi).expect("a new leg");
        assert_ne!(new_token, old_token);
        wait_answers(&seen, 204, 1).await;
        let told: Vec<Value> = seen
            .lock()
            .expect("seen")
            .iter()
            .map(|(_, b)| b.clone())
            .collect();
        assert_eq!(
            told,
            vec![modification_notification(
                supi,
                &sdm_id,
                &nextgcore_udrd::data_store::am_data_changes(&gpsis(1), &gpsis(2))
            )],
            "the change made while it was gone"
        );
        let stale = format!("{udm_base}{}", data_change_path(supi, &old_token));
        let notify = udr_notify(supi, &stale, &gpsis(2), &gpsis(3));
        assert_eq!(
            post(&stale, &notify).await,
            404,
            "the old leg is not admitted"
        );
        clear_legs();
    }

    /// #1836: the UDM's own diff words a change as the UDR's does (udrd
    /// `am_data_changes`), and like the UDR's notifier (#1812) it never names or
    /// carries key material; the key-material list is the UDR's. Applying a diff
    /// to the old am-data gives the new.
    #[test]
    fn the_udm_diff_is_the_udr_diff_without_key_material_1836() {
        assert_eq!(
            KEY_MATERIAL_MEMBERS,
            nextgcore_udrd::data_store::KEY_MATERIAL_MEMBERS
        );
        let old = json!({"gpsis": ["msisdn-1"], "rfspIndex": 3, "a/b": 1});
        let new = json!({"gpsis": ["msisdn-2"], "mpsPriority": true, "a/b": 2});
        let ours = am_data_diff(&old, &new);
        assert_eq!(
            ours,
            nextgcore_udrd::data_store::am_data_changes(&old, &new)
        );
        assert_eq!(apply_changes(&old, &ours), Some(new.clone()));

        let leaky_old = json!({"x": {"encPermanentKey": "00"}, "encOpcKey": "11"});
        let leaky_new = json!({"x": {"encPermanentKey": "22", "y": 1}, "encOpcKey": "33"});
        let text = Value::Array(am_data_diff(&leaky_old, &leaky_new)).to_string();
        for member in KEY_MATERIAL_MEMBERS {
            assert!(!text.contains(member), "{member} in {text}");
        }
        assert!(text.contains("\"y\":1"), "the rest is told: {text}");
    }

    /// #1836: the shipped compose gives the UDM a state file on a named volume, so
    /// a UDM restart keeps its SDM subscriptions, legs and queued changes. Like
    /// udrd's `shipped_docker_config_enables_udr_persistence`, this pins the
    /// configuration, not the restart.
    #[test]
    fn shipped_docker_config_enables_udm_persistence_1836() {
        let compose = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .expect("crate is at <root>/src/bins/nextgcore-udmd")
            .join("docker/rust/docker-compose.yml");
        let text = std::fs::read_to_string(&compose).expect("compose");
        let state_file = text
            .lines()
            .find_map(|l| {
                l.trim()
                    .strip_prefix(&format!("{}:", crate::app::STATE_FILE_ENV))
            })
            .map(str::trim)
            .expect("the shipped compose sets NEXTGCORE_UDM_STATE_FILE");
        let dir = state_file
            .rsplit_once('/')
            .map(|(d, _)| d)
            .expect("absolute");
        assert!(
            text.contains(&format!("udm_state:{dir}")),
            "on the udm_state volume"
        );
        assert!(text.contains("\n  udm_state:"), "the volume is declared");
    }

    /// An SDM subscribe of `supi`'s am-data with `callback`, as the handler
    /// answers it (status, ProblemDetails cause).
    async fn try_sdm_subscribe(supi: &str, callback: &str) -> (u16, Value) {
        let mut req = SbiRequest::post(format!("/nudm-sdm/v2/{supi}/sdm-subscriptions"));
        req.http.content = Some(
            json!({
                "nfInstanceId": "amf-1836",
                "callbackReference": callback,
                "monitoredResourceUris": [format!("/nudm-sdm/v2/{supi}/am-data")],
            })
            .to_string(),
        );
        let resp = crate::app::handle_sdm_subscribe(supi, &req).await;
        let cause = json_body(&resp).map_or(Value::Null, |b| b["cause"].clone());
        (resp.status, cause)
    }

    /// The ids of the SDM subscriptions the UDM holds for `supi`.
    fn held_ids(supi: &str) -> Vec<String> {
        udm_self()
            .read()
            .expect("ctx")
            .sdm_subscriptions_for_supi(supi)
            .into_iter()
            .map(|s| s.id)
            .collect()
    }

    /// Requests of `method` the programmable UDR got.
    fn udr_requests(udr: &Arc<Mutex<UdrState>>, method: &str) -> usize {
        udr.lock()
            .expect("udr")
            .seen
            .iter()
            .filter(|(m, _, _)| m == method)
            .count()
    }

    /// A state file whose writes fail from `break_it()` on: its directory is
    /// replaced by a regular file. Returns the directory path (a file afterwards).
    async fn breakable_state(tag: &str) -> std::path::PathBuf {
        let dir = temp_state_path(tag);
        std::fs::create_dir_all(&dir).expect("dir");
        init_state(Some(dir.join("state.json")))
            .await
            .expect("state file");
        dir
    }

    fn break_it(dir: &std::path::Path) {
        std::fs::remove_dir_all(dir).expect("rm");
        std::fs::write(dir, b"x").expect("file");
    }

    /// **#1836 (R28 MAJOR 1), failure-path check 1 at the SDM subscribe.** When the
    /// state file cannot be written, the subscribe is answered 500
    /// INSUFFICIENT_RESOURCES and nothing of it is kept: no SDM subscription, so a
    /// later snapshot cannot write it either, and no UDR leg (no reconcile is
    /// started, so no subscribe reaches the UDR).
    ///
    /// REVERT-VERIFIED: with the rollback's `sdm_subscription_remove` skipped, the
    /// subscription is still held ("stores nothing"); with the failed write
    /// ignored, the subscribe is answered 201 ("refused").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn a_subscribe_that_cannot_be_stored_keeps_nothing_1836() {
        let (_udr, udr_base, udr) = programmable_udr(gpsis(1)).await;
        let _locks = setup(&udr_base).await;
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base));
        let dir = breakable_state("1836-sub").await;
        break_it(&dir);
        let supi = "imsi-001010000018366";
        assert_eq!(
            try_sdm_subscribe(supi, "http://127.0.0.1:9/cb/sdm-notify/n").await,
            (500, json!("INSUFFICIENT_RESOURCES")),
            "refused"
        );
        wait_idle().await;
        assert!(held_ids(supi).is_empty(), "stores nothing");
        assert!(leg_token(supi).is_none(), "no leg");
        assert_eq!(udr_requests(&udr, "POST"), 0, "no reconcile");
        clear_legs();
        init_state(None).await.expect("memory-only");
        let _ = std::fs::remove_file(&dir);
    }

    /// **#1836 (R28 MAJOR 2).** A subscribe while the context holds its most SDM
    /// subscriptions is answered 500 INSUFFICIENT_RESOURCES (TS 29.500 Table
    /// 5.2.7.2-1), not 201 for a subscription that was never stored, and no leg is
    /// made for it.
    ///
    /// REVERT-VERIFIED: with the `!inserted` check skipped, the subscribe is
    /// answered 201 ("a full context").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn a_full_sdm_context_is_answered_500_1836() {
        let (_udr, udr_base, udr) = programmable_udr(gpsis(1)).await;
        let _locks = setup(&udr_base).await;
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base));
        {
            let ctx = udm_self();
            let context = ctx.read().expect("ctx");
            let mut n = 0;
            while context.sdm_subscription_insert(UdmSdmSubscription::for_supi(
                format!("imsi-filler-{n}"),
                None,
                None,
                vec!["/nudm-sdm/v2/x/sm-data".to_string()],
            )) {
                n += 1;
                assert!(n < 100_000, "the context has a cap");
            }
        }
        let supi = "imsi-001010000018367";
        assert_eq!(
            try_sdm_subscribe(supi, "http://127.0.0.1:9/cb/sdm-notify/f").await,
            (500, json!("INSUFFICIENT_RESOURCES")),
            "a full context"
        );
        wait_idle().await;
        assert!(held_ids(supi).is_empty());
        assert_eq!(udr_requests(&udr, "POST"), 0, "no leg");
        udm_self().read().expect("ctx").ue_remove_all();
        clear_legs();
    }

    /// **#1836 (R28 minor), failure-path check 1 at the SDM unsubscribe.** When the
    /// state file cannot be written, the unsubscribe is undone and answered 500
    /// INSUFFICIENT_RESOURCES, as the subscribe is: the subscription is still held
    /// (it is still on disk, so a 204 would have it come back after a restart) and
    /// its UDR leg is kept (no DELETE reaches the UDR). The consumer can retry.
    ///
    /// REVERT-VERIFIED: with the removed subscription not put back, it is gone from
    /// memory ("undone"); with the failed write ignored, the unsubscribe is
    /// answered 204 ("refused").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn an_unsubscribe_that_cannot_be_stored_is_undone_1836() {
        let (_udr, udr_base, udr) = programmable_udr(gpsis(1)).await;
        let _locks = setup(&udr_base).await;
        let (_udm, udm_base) = udm_server().await;
        set_notify_base(Some(udm_base));
        let dir = breakable_state("1836-unsub").await;
        let supi = "imsi-001010000018368";
        let id = sdm_subscribe(supi, "http://127.0.0.1:9/cb/sdm-notify/u").await;
        let token = leg_token(supi).expect("leg");
        break_it(&dir);
        let resp = crate::app::handle_sdm_unsubscribe(supi, &id).await;
        assert_eq!(
            (
                resp.status,
                json_body(&resp).map_or(Value::Null, |b| b["cause"].clone())
            ),
            (500, json!("INSUFFICIENT_RESOURCES")),
            "refused"
        );
        wait_idle().await;
        assert_eq!(held_ids(supi), vec![id], "undone");
        assert_eq!(leg_token(supi), Some(token), "the leg is kept");
        assert_eq!(udr_requests(&udr, "DELETE"), 0, "no DELETE at the UDR");
        clear_legs();
        init_state(None).await.expect("memory-only");
        let _ = std::fs::remove_file(&dir);
    }

    /// **#1896, the core claim.** With a state log holding 120 SDM subscriptions
    /// (and their legs and told am-data), one more SDM subscribe appends about as
    /// many bytes as the second one did, under 2 KiB: the write names its records
    /// and writes only those, not the state.
    ///
    /// REVERT-VERIFIED: with `persist_locked` writing every record (`all_ops`), the
    /// 121st subscribe appends the whole state ("only the changed record").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn a_write_appends_only_the_changed_record_1896() {
        let (_udr, udr_base, _udr_state) = programmable_udr(gpsis(1)).await;
        let _locks = setup(&udr_base).await;
        let path = temp_state_path("1896-flat");
        init_state(Some(path.clone())).await.expect("state log");
        // No callback address: no leg is made, so the log holds the SDM
        // subscriptions alone and the measure is of one subscribe's write.
        set_notify_base(None);
        let size = || std::fs::metadata(&path).map_or(0, |m| m.len());
        let subscribe = |n: usize| {
            try_sdm_subscribe_owned(
                format!("imsi-0010100018{n:05}"),
                format!("http://127.0.0.1:9/cb/sdm-notify/{n:05}"),
            )
        };
        assert_eq!(subscribe(0).await.0, 201);
        let first = size();
        assert_eq!(subscribe(1).await.0, 201);
        let second = size() - first;
        for n in 2..120 {
            assert_eq!(subscribe(n).await.0, 201);
        }
        let before = size();
        assert_eq!(subscribe(120).await.0, 201);
        let last = size() - before;
        assert!(
            last < 2048 && last <= second + 16,
            "only the changed record: {last} B after 120, {second} B after 1"
        );
        clear_legs();
        init_state(None).await.expect("memory-only");
        let _ = std::fs::remove_file(&path);
    }

    async fn try_sdm_subscribe_owned(supi: String, callback: String) -> (u16, Value) {
        try_sdm_subscribe(&supi, &callback).await
    }

    /// **#1896, migration (UDM restart).** A state file #1836 wrote (one snapshot
    /// document) is restored at the first start and rewritten as a log: the SDM
    /// subscription, the leg (its token admitted again) and the queued change are
    /// all there, and so they are after a second restart from the log, with a
    /// change made in between. A damaged log fails the start.
    ///
    /// REVERT-VERIFIED: with the migration's compaction skipped, the file is still
    /// the snapshot ("rewritten as a log"), and the change appended to it then makes
    /// the second start fail.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn a_1836_snapshot_is_migrated_to_the_log_1896() {
        let (_udr, udr_base, _udr_state) = programmable_udr(gpsis(1)).await;
        let _locks = setup(&udr_base).await;
        let supi = "imsi-001010000018961";
        let sub = SavedSdmSubscription {
            id: "sdm-1896".to_string(),
            supi: supi.to_string(),
            nf_instance_id: Some("amf-1896".to_string()),
            // Nothing listens there: the queued change stays queued.
            callback_reference: Some("http://127.0.0.1:9/cb/sdm-notify/m".to_string()),
            monitored_resource_uris: vec![format!("/nudm-sdm/v2/{supi}/am-data")],
        };
        let token = "0123456789abcdef0123456789a18961";
        let snapshot = Snapshot {
            sdm_subscriptions: vec![sub],
            legs: HashMap::from([(
                supi.to_string(),
                UdrLeg {
                    subscription_path: "/nudr-dr/v2/subscription-data/subs-to-notify/77"
                        .to_string(),
                    token: token.to_string(),
                    callback_reference: String::new(),
                    expiry: None,
                },
            )]),
            queues: HashMap::from([(
                supi.to_string(),
                VecDeque::from([Queued {
                    changes: vec![json!({"op": "REPLACE", "path": "/gpsis",
                                         "newValue": ["msisdn-2"]})],
                    pending: None,
                }]),
            )]),
            told: HashMap::from([(supi.to_string(), Told::default())]),
        };
        let path = temp_state_path("1896-migrate");
        nextgcore_core::state_store::write_snapshot(
            &path,
            &serde_json::to_value(&snapshot).expect("doc"),
        )
        .expect("a #1836 file");

        assert_eq!(init_state(Some(path.clone())).await, Ok(1));
        let first = std::fs::read(&path).expect("read");
        assert!(
            first.first().is_some_and(u8::is_ascii_hexdigit),
            "rewritten as a log: {}",
            String::from_utf8_lossy(&first[..first.len().min(40)])
        );
        assert!(token_matches(supi, token), "the leg");
        assert_eq!(held_ids(supi), vec!["sdm-1896".to_string()]);
        // A change after the migration is appended to the log.
        assert_eq!(
            try_sdm_subscribe(supi, "http://127.0.0.1:9/cb/sdm-notify/m2")
                .await
                .0,
            201
        );

        crash().await;
        // What the log holds, as the next start replays it.
        let persisted = match crate::state_log::StateLog::open(&path).expect("opens").1 {
            crate::state_log::Opened::Log { ops, .. } => replay(ops).expect("replays"),
            crate::state_log::Opened::Legacy(_) => panic!("rewritten as a log"),
        };
        assert!(persisted.queues.contains_key(supi), "the queue");
        assert_eq!(
            persisted.legs.get(supi).map(|l| l.token.as_str()),
            Some(token)
        );
        assert_eq!(
            init_state(Some(path.clone())).await,
            Ok(2),
            "both, from the log"
        );
        assert!(token_matches(supi, token));

        crash().await;
        let mut damaged = std::fs::read(&path).expect("read");
        damaged[0] = if damaged[0] == b'0' { b'1' } else { b'0' };
        std::fs::write(&path, &damaged).expect("write");
        assert!(
            init_state(Some(path.clone())).await.is_err(),
            "a damaged log fails the start"
        );
        clear_legs();
        init_state(None).await.expect("memory-only");
        let _ = std::fs::remove_file(&path);
    }
}
