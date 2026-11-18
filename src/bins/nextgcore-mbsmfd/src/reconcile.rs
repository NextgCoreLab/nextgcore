//! #1817: the reconciler for Namf_MBSBroadcast ContextDeletes that outlived their
//! retry budget.
//!
//! [`crate::release_amf_contexts`] tries a ContextDelete once and then on
//! `AMF_RELEASE_RETRY_DELAYS` (about 31 s in all). An AMF that is down for longer
//! used to keep the broadcast MBS context for ever: the retry task logged at error
//! and dropped the record, so nothing ever asked again (TS 23.247 §7.3.2 makes the
//! release toward the AMF part of the session release). Now the record is parked
//! here and retried on [`RECONCILE_PERIOD`] until the AMF answers 2xx or 404.
//!
//! Bounded: at most [`MAX_PENDING`] records are kept. Parking one more evicts the
//! oldest, which is logged at error and counted as `abandoned`, so a permanently
//! unreachable AMF cannot grow the set without limit.
//!
//! Ceiling: the set is in memory, like the MBS sessions it serves. mbsmfd has no
//! durable store, so a restart forgets both the sessions and their pending
//! deletes; the AMF's own context cleanup (on N2 release / MB-SMF loss) is what
//! covers that case.

use crate::context::AmfMbsContext;
use crate::namf_client::{self, ContextDeleteOutcome};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

/// Records parked before the oldest is abandoned.
pub const MAX_PENDING: usize = 4096;

/// How often a parked ContextDelete is retried.
#[cfg(not(test))]
pub const RECONCILE_PERIOD: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const RECONCILE_PERIOD: Duration = Duration::from_millis(20);

/// `nextgcore_mbsmf_amf_context_delete_reconciled_total{result}`: parked deletes
/// that the reconciler delivered (`deleted`), evicted at the bound (`abandoned`),
/// or dropped because a live session holds the context again (`reused`, R24).
pub static RECONCILED: nextgcore_metrics::nf::CounterFamily =
    nextgcore_metrics::nf::CounterFamily::new(
        "nextgcore_mbsmf_amf_context_delete_reconciled_total",
        "Namf_MBSBroadcast ContextDeletes that outlived their retry budget, by how \
         the reconciler ended them",
        &["result"],
    );

/// The parked ContextDeletes, oldest first.
///
/// Tests that read or write it hold [`PENDING_TEST_LOCK`], declared beside it.
fn pending() -> &'static Mutex<VecDeque<AmfMbsContext>> {
    static PENDING: Mutex<VecDeque<AmfMbsContext>> = Mutex::new(VecDeque::new());
    &PENDING
}

/// Serialises the tests that touch [`pending`]: a reconcile pass in one test
/// would otherwise deliver (or drain) another test's parked record.
#[cfg(test)]
pub static PENDING_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Park `contexts` for the reconciler. A record already parked is not added twice,
/// so a re-driven release does not send two deletes for one context.
pub fn park(contexts: Vec<AmfMbsContext>) {
    let Ok(mut set) = pending().lock() else {
        return;
    };
    for c in contexts {
        if set.contains(&c) {
            continue;
        }
        if set.len() >= MAX_PENDING {
            if let Some(old) = set.pop_front() {
                log::error!(
                    "MBS: abandoning the ContextDelete of AMF {}:{} MBS context {}: {} \
                     deletes are already pending",
                    old.host,
                    old.port,
                    old.context_ref,
                    MAX_PENDING
                );
                RECONCILED.inc(&["abandoned"]);
            }
        }
        log::warn!(
            "MBS: AMF {}:{} MBS context {} is parked; its ContextDelete is retried every {:?}",
            c.host,
            c.port,
            c.context_ref,
            RECONCILE_PERIOD
        );
        set.push_back(c);
    }
}

/// How many ContextDeletes are parked: the
/// `nextgcore_mbsmf_amf_context_deletes_pending` gauge.
pub fn pending_count() -> usize {
    pending().lock().map(|s| s.len()).unwrap_or(0)
}

/// R24: whether `a` and `b` name the same context at the same AMF (the instance
/// id is not part of the AMF's resource).
fn same_context(a: &AmfMbsContext, b: &AmfMbsContext) -> bool {
    a.host == b.host && a.port == b.port && a.context_ref == b.context_ref
}

/// R24: whether a live MBS session holds `c`. The AMF's ContextCreate is
/// idempotent on the TMGI, so a new session reusing a released one's TMGI is
/// handed the SAME `mbsContextRef`; deleting it then would tear down the new
/// session's live context.
fn held_by_a_live_session(c: &AmfMbsContext) -> bool {
    crate::mbsmf_self()
        .read()
        .is_ok_and(|ctx| ctx.amf_context_in_use(c))
}

/// R24: a session recorded `c` as its own: a parked delete of the same context is
/// dropped, as it would delete that session's live context. Called by
/// `record_amf_context` after the record is made.
pub fn unpark(c: &AmfMbsContext) {
    let removed = match pending().lock() {
        Ok(mut set) => {
            let before = set.len();
            set.retain(|p| !same_context(p, c));
            before - set.len()
        }
        Err(_) => 0,
    };
    if removed > 0 {
        log::info!(
            "MBS: AMF {}:{} MBS context {} is in use again; its parked ContextDelete is dropped",
            c.host,
            c.port,
            c.context_ref
        );
        RECONCILED.inc(&["reused"]);
    }
}

/// The longest one pass sends for. A pass against a blackholed AMF costs a client
/// timeout per record, so past this the rest are re-parked for the next pass.
#[cfg(not(test))]
pub const MAX_PASS: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const MAX_PASS: Duration = Duration::from_millis(500);

/// One reconcile pass: retry parked deletes, oldest first, for at most
/// [`MAX_PASS`]. A 2xx or 404 ends one; a failure, or not reaching it within the
/// pass, re-parks it (ahead of anything parked meanwhile). A record a live session
/// holds again is dropped, not sent (R24). Returns how many the AMF accepted.
pub async fn reconcile_once() -> usize {
    let batch: Vec<AmfMbsContext> = match pending().lock() {
        Ok(mut set) => set.drain(..).collect(),
        Err(_) => return 0,
    };
    let deadline = tokio::time::Instant::now() + MAX_PASS;
    let mut ended = 0;
    let mut still = Vec::new();
    for c in batch {
        if tokio::time::Instant::now() >= deadline {
            still.push(c);
            continue;
        }
        if held_by_a_live_session(&c) {
            log::info!(
                "MBS: AMF {}:{} MBS context {} is in use again; its parked ContextDelete is \
                 dropped",
                c.host,
                c.port,
                c.context_ref
            );
            RECONCILED.inc(&["reused"]);
            continue;
        }
        match namf_client::context_delete(&c).await {
            ContextDeleteOutcome::Deleted | ContextDeleteOutcome::Gone => {
                log::info!(
                    "MBS: reconciler released AMF {}:{} MBS context {}",
                    c.host,
                    c.port,
                    c.context_ref
                );
                RECONCILED.inc(&["deleted"]);
                ended += 1;
            }
            ContextDeleteOutcome::Failed => still.push(c),
        }
    }
    if !still.is_empty() {
        if let Ok(mut set) = pending().lock() {
            // Back at the FRONT, in order: they are older than anything parked
            // while this pass ran, and eviction takes the oldest.
            for c in still.into_iter().rev() {
                if !set.contains(&c) {
                    set.push_front(c);
                }
            }
            while set.len() > MAX_PENDING {
                if let Some(old) = set.pop_front() {
                    log::error!(
                        "MBS: abandoning the ContextDelete of AMF {}:{} MBS context {}: {} \
                         deletes are already pending",
                        old.host,
                        old.port,
                        old.context_ref,
                        MAX_PENDING
                    );
                    RECONCILED.inc(&["abandoned"]);
                }
            }
        }
    }
    ended
}

/// Run [`reconcile_once`] every [`RECONCILE_PERIOD`] for the life of the process.
pub fn spawn_reconciler() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {
        let mut timer = tokio::time::interval(RECONCILE_PERIOD);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is immediate; consume it so the first pass is a period in.
        timer.tick().await;
        loop {
            timer.tick().await;
            reconcile_once().await;
        }
    })
}

/// The reconciler's families, for `/metrics`.
pub fn render(out: &mut String) {
    nextgcore_metrics::nf::write_header(
        out,
        "nextgcore_mbsmf_amf_context_deletes_pending",
        "gauge",
        "Namf_MBSBroadcast ContextDeletes parked for the reconciler",
    );
    use std::fmt::Write as _;
    let _ = writeln!(
        out,
        "nextgcore_mbsmf_amf_context_deletes_pending {}",
        pending_count()
    );
    RECONCILED.render(out);
}

#[cfg(test)]
pub fn clear_for_test() {
    if let Ok(mut set) = pending().lock() {
        set.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(n: usize) -> AmfMbsContext {
        AmfMbsContext {
            host: "127.0.0.1".to_string(),
            // A port nothing listens on: every delete fails to connect.
            port: 9,
            nf_instance_id: None,
            context_ref: n.to_string(),
        }
    }

    /// #1817 bound: parking past [`MAX_PENDING`] evicts the oldest and counts it
    /// as abandoned, and a duplicate is not parked twice.
    ///
    /// REVERT-VERIFIED: with the eviction removed, the set grows to MAX_PENDING + 1.
    #[tokio::test]
    async fn the_parked_set_is_bounded_and_evicts_the_oldest_1817() {
        let _g = PENDING_TEST_LOCK.lock().await;
        clear_for_test();
        let before = RECONCILED.get(&["abandoned"]);
        park((0..MAX_PENDING).map(ctx).collect());
        park(vec![ctx(0)]);
        assert_eq!(
            pending_count(),
            MAX_PENDING,
            "a duplicate is not parked twice"
        );
        park(vec![ctx(MAX_PENDING)]);
        assert_eq!(pending_count(), MAX_PENDING);
        assert_eq!(RECONCILED.get(&["abandoned"]), before + 1);
        let front = pending().lock().unwrap().front().cloned().unwrap();
        assert_eq!(
            front.context_ref, "1",
            "the oldest (ref 0) was the one evicted"
        );
        clear_for_test();
    }

    /// The gauge and the counter are on `/metrics`.
    #[tokio::test]
    async fn the_reconciler_families_render_1817() {
        let _g = PENDING_TEST_LOCK.lock().await;
        clear_for_test();
        park(vec![ctx(1), ctx(2)]);
        let mut out = String::new();
        render(&mut out);
        assert_eq!(
            nextgcore_metrics::nf::sample_value(
                &out,
                "nextgcore_mbsmf_amf_context_deletes_pending"
            ),
            Some(2.0)
        );
        assert!(out.contains("# TYPE nextgcore_mbsmf_amf_context_delete_reconciled_total counter"));
        clear_for_test();
    }
}
