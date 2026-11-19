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
//! No peer starves the others (#1961, the #1954 / #1972 pattern): once a
//! ContextDelete to an AMF fails, that AMF backs off ([`BACKOFF_BASE`], doubling
//! to [`BACKOFF_MAX`]) and its other records wait, in this pass and later ones;
//! a record that was tried and failed goes to the BACK of the queue, while one
//! a pass did not reach keeps its place at the front. A record parked longer
//! than [`MAX_AGE`] ends as `expired`.
//!
//! Ceiling: the set is in memory, like the MBS sessions it serves. mbsmfd has no
//! durable store, so a restart forgets both the sessions and their pending
//! deletes; the AMF's own context cleanup (on N2 release / MB-SMF loss) is what
//! covers that case.

use crate::context::AmfMbsContext;
use crate::namf_client::ContextDeleteOutcome;
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
/// dropped because a live session holds the context again (`reused`, R24), or
/// gave up after [`MAX_AGE`] (`expired`, #1961).
pub static RECONCILED: nextgcore_metrics::nf::CounterFamily =
    nextgcore_metrics::nf::CounterFamily::new(
        "nextgcore_mbsmf_amf_context_delete_reconciled_total",
        "Namf_MBSBroadcast ContextDeletes that outlived their retry budget, by how \
         the reconciler ended them",
        &["result"],
    );

/// One parked ContextDelete, and when it was first parked (#1961).
#[derive(Debug, Clone)]
struct Parked {
    ctx: AmfMbsContext,
    /// Wall-clock, so a test can set it back past [`MAX_AGE`].
    since: std::time::SystemTime,
}

/// The parked ContextDeletes, oldest first.
///
/// Tests that read or write it hold [`PENDING_TEST_LOCK`], declared beside it.
fn pending() -> &'static Mutex<VecDeque<Parked>> {
    static PENDING: Mutex<VecDeque<Parked>> = Mutex::new(VecDeque::new());
    &PENDING
}

/// #1961: how long an entry stays parked before it is given up (`expired`): a
/// peer that has not answered for a day is gone (decommissioned), not
/// restarting, so its entries end rather than wait to be evicted.
pub const MAX_AGE: Duration = Duration::from_secs(24 * 3600);

/// #1961 (the #1954 / #1972 pattern): the first wait before a peer whose
/// request failed is tried again, doubled after each further failure up to
/// [`BACKOFF_MAX`], and cleared by a success. A peer that is backing off is
/// skipped for the rest of the pass and for later passes until its wait ends,
/// so a blackholed peer costs one request timeout per backoff period and
/// cannot starve the entries for healthy peers behind it.
#[cfg(not(test))]
pub const BACKOFF_BASE: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const BACKOFF_BASE: Duration = Duration::from_millis(300);
/// The longest a failing peer is left alone between attempts.
pub const BACKOFF_MAX: Duration = Duration::from_secs(600);

type Backoff = std::collections::HashMap<String, (tokio::time::Instant, Duration)>;

/// Per peer: when it may next be tried, and the current backoff.
fn backoff() -> &'static Mutex<Backoff> {
    static BACKOFF: std::sync::LazyLock<Mutex<Backoff>> =
        std::sync::LazyLock::new(Default::default);
    &BACKOFF
}

fn backing_off(peer: &str) -> bool {
    backoff()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(peer)
        .is_some_and(|(next, _)| tokio::time::Instant::now() < *next)
}

fn note_failure(peer: &str) {
    let mut map = backoff().lock().unwrap_or_else(|e| e.into_inner());
    let wait = map
        .get(peer)
        .map_or(BACKOFF_BASE, |(_, current)| (*current * 2).min(BACKOFF_MAX));
    map.insert(peer.to_string(), (tokio::time::Instant::now() + wait, wait));
}

fn note_success(peer: &str) {
    backoff()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(peer);
}

/// The peer a record's ContextDelete goes to: its AMF.
fn peer_of(c: &AmfMbsContext) -> String {
    format!("{}:{}", c.host, c.port)
}

/// Serialises the tests that touch [`pending`]: a reconcile pass in one test
/// would otherwise deliver (or drain) another test's parked record.
#[cfg(test)]
pub static PENDING_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Park `contexts` for the reconciler. A record already parked is not added twice,
/// so a re-driven release does not send two deletes for one context.
pub fn park(contexts: Vec<AmfMbsContext>) {
    let mut abandoned = Vec::new();
    let Ok(mut set) = pending().lock() else {
        return;
    };
    for c in contexts {
        if set.iter().any(|p| p.ctx == c) {
            continue;
        }
        if set.len() >= MAX_PENDING {
            if let Some(Parked { ctx: old, .. }) = set.pop_front() {
                log::error!(
                    "MBS: abandoning the ContextDelete of AMF {}:{} MBS context {}: {} \
                     deletes are already pending",
                    old.host,
                    old.port,
                    old.context_ref,
                    MAX_PENDING
                );
                RECONCILED.inc(&["abandoned"]);
                abandoned.push(old);
            }
        }
        log::warn!(
            "MBS: AMF {}:{} MBS context {} is parked; its ContextDelete is retried every {:?}",
            c.host,
            c.port,
            c.context_ref,
            RECONCILE_PERIOD
        );
        set.push_back(Parked {
            ctx: c,
            since: std::time::SystemTime::now(),
        });
    }
    drop(set);
    forget_abandoned(&abandoned);
}

/// #1985: an abandoned delete's context is no longer tracked, so its notify
/// tokens go (the bound on the tokens parked deletes keep). Called with the
/// pending set unlocked: forgetting reads the global context, and
/// `record_amf_context` takes the pending set under that read (`unpark`).
///
/// #2015: not when a live session holds the context: one that re-recorded it
/// after the record left the pending set (drained by a pass, or popped by the
/// eviction) found nothing to unpark, and the tokens are its own now. The check
/// and the forget are atomic with `record_amf_context`.
fn forget_abandoned(abandoned: &[AmfMbsContext]) {
    #[cfg(test)]
    if !abandoned.is_empty() {
        if let Some(hook) = BEFORE_FORGET_SEAM
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            hook();
        }
    }
    for c in abandoned {
        crate::forget_abandoned_amf_notify_token(c);
    }
}

/// #2015: the deterministic seam of the abandon/re-record race: run once by the
/// next [`forget_abandoned`] with something to forget, after the records left
/// the pending set and before their tokens are forgotten. Set only under
/// [`PENDING_TEST_LOCK`].
#[cfg(test)]
pub static BEFORE_FORGET_SEAM: Mutex<Option<Box<dyn FnOnce() + Send>>> = Mutex::new(None);

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

/// R24: a session recorded `c` as its own: a parked delete of the same context is
/// dropped, as it would delete that session's live context. Called by
/// `record_amf_context` after the record is made.
pub fn unpark(c: &AmfMbsContext) {
    let removed = match pending().lock() {
        Ok(mut set) => {
            let before = set.len();
            set.retain(|p| !same_context(&p.ctx, c));
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
/// [`MAX_PASS`]. A 2xx or 404 ends one; a record a live session holds again is
/// dropped, not sent (R24); one older than [`MAX_AGE`] ends as `expired`.
///
/// #1961: once a delete to an AMF fails, that AMF backs off and its other records
/// are not tried this pass (nor until the backoff ends); a record tried and failed
/// goes to the BACK of the queue, one not reached keeps its place at the FRONT.
/// Returns how many the AMF accepted.
///
/// #1985 (cancellation): the batch is held by a [`Repark`] guard, so a pass dropped
/// mid-way (its task aborted) re-parks every record it had not ended, including
/// the one in flight -- whose context still exists at the AMF and whose notify
/// tokens are still held. If that delete did land, the next pass's 404 ends it.
pub async fn reconcile_once() -> usize {
    let batch: VecDeque<Parked> = match pending().lock() {
        Ok(mut set) => set.drain(..).collect(),
        Err(_) => return 0,
    };
    let mut pass = Repark {
        untried: Vec::new(),
        inflight: None,
        rest: batch,
        failed: Vec::new(),
        expired: Vec::new(),
    };
    let deadline = tokio::time::Instant::now() + MAX_PASS;
    let mut ended = 0;
    while let Some(p) = pass.rest.pop_front() {
        if p.since.elapsed().unwrap_or_default() > MAX_AGE {
            log::error!(
                "MBS: the ContextDelete of AMF {}:{} MBS context {} expired after {MAX_AGE:?}",
                p.ctx.host,
                p.ctx.port,
                p.ctx.context_ref
            );
            RECONCILED.inc(&["expired"]);
            // #1985: given up on, so the context is no longer tracked and its
            // notify tokens go (as for an abandoned delete), once the guard drops.
            pass.expired.push(p.ctx);
            continue;
        }
        let peer = peer_of(&p.ctx);
        if tokio::time::Instant::now() >= deadline || backing_off(&peer) {
            pass.untried.push(p);
            continue;
        }
        let c = p.ctx.clone();
        pass.inflight = Some(p);
        // #1854: in the (AMF, TMGI) lane, the in-use check and the send together.
        let outcome = crate::delete_in_lane(&c).await;
        let p = pass.inflight.take();
        match outcome {
            None => {
                RECONCILED.inc(&["reused"]);
            }
            Some(outcome @ (ContextDeleteOutcome::Deleted | ContextDeleteOutcome::Gone)) => {
                note_success(&peer);
                log::info!(
                    "MBS: reconciler released AMF {}:{} MBS context {}",
                    c.host,
                    c.port,
                    c.context_ref
                );
                // #1985: the context ends here, so do its notify tokens: at once
                // on a 404, after the grace on a 204 (late NG-RAN answers).
                crate::retire_amf_notify_token(&c, outcome);
                RECONCILED.inc(&["deleted"]);
                ended += 1;
            }
            Some(ContextDeleteOutcome::Failed) => {
                note_failure(&peer);
                pass.failed.extend(p);
            }
        }
    }
    drop(pass);
    ended
}

/// #1985: the records of one [`reconcile_once`] pass it has not ended. Dropping
/// it -- at the end of the pass, or when the pass is cancelled -- puts them back:
/// those not reached (`untried`), the one in flight and the rest of the batch at
/// the FRONT, in order (they are older than anything parked while the pass ran,
/// and eviction takes the oldest); those tried and failed at the BACK (#1961).
/// The notify tokens of evicted and `expired` records are forgotten with the
/// pending set unlocked.
struct Repark {
    untried: Vec<Parked>,
    inflight: Option<Parked>,
    rest: VecDeque<Parked>,
    failed: Vec<Parked>,
    expired: Vec<AmfMbsContext>,
}

impl Drop for Repark {
    fn drop(&mut self) {
        let front: Vec<Parked> = self
            .untried
            .drain(..)
            .chain(self.inflight.take())
            .chain(self.rest.drain(..))
            .collect();
        let failed: Vec<Parked> = self.failed.drain(..).collect();
        let mut gone: Vec<AmfMbsContext> = self.expired.drain(..).collect();
        if !front.is_empty() || !failed.is_empty() {
            if let Ok(mut set) = pending().lock() {
                for p in front.into_iter().rev() {
                    if !set.iter().any(|q| q.ctx == p.ctx) {
                        set.push_front(p);
                    }
                }
                for p in failed {
                    if !set.iter().any(|q| q.ctx == p.ctx) {
                        set.push_back(p);
                    }
                }
                while set.len() > MAX_PENDING {
                    if let Some(Parked { ctx: old, .. }) = set.pop_front() {
                        log::error!(
                            "MBS: abandoning the ContextDelete of AMF {}:{} MBS context {}: {} \
                             deletes are already pending",
                            old.host,
                            old.port,
                            old.context_ref,
                            MAX_PENDING
                        );
                        RECONCILED.inc(&["abandoned"]);
                        gone.push(old);
                    }
                }
            }
        }
        forget_abandoned(&gone);
    }
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
    backoff().lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// Make every parked record look parked `by` earlier (#1961 / #1985 tests of
/// [`MAX_AGE`]). Hold [`PENDING_TEST_LOCK`].
#[cfg(test)]
pub fn backdate_for_test(by: Duration) {
    if let Ok(mut set) = pending().lock() {
        for p in set.iter_mut() {
            p.since -= by;
        }
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
            notify_token: String::new(),
            tmgi: None,
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
        let front = pending().lock().unwrap().front().cloned().unwrap().ctx;
        assert_eq!(
            front.context_ref, "1",
            "the oldest (ref 0) was the one evicted"
        );
        clear_for_test();
    }

    /// #1961: a peer that accepts the connection and never answers, so each
    /// request to it costs the client's whole timeout. Returns its port; the
    /// accepted sockets are held for the life of the test process.
    fn blackhole_1961() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming().flatten() {
                held.push(stream);
            }
        });
        port
    }

    fn ctx_at(port: u16, n: usize) -> AmfMbsContext {
        AmfMbsContext { port, ..ctx(n) }
    }

    /// #1961: deletes toward a blackholed AMF ahead of one toward a healthy AMF
    /// no longer starve it: the healthy one is delivered within two passes, and
    /// the blackholed ones stay parked, tried and failed at the back.
    /// REVERT-VERIFIED: with the old order restored (every not-ended record
    /// re-parked at the front, no backoff), the healthy delete is never reached
    /// and "the healthy AMF gets its delete" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_blackholed_amf_does_not_starve_a_healthy_one_1961() {
        let _g = PENDING_TEST_LOCK.lock().await;
        clear_for_test();
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = hits.clone();
        let (srv, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(
            move |_req: nextgcore_sbi::message::SbiRequest| {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    nextgcore_sbi::message::SbiResponse::with_status(204)
                }
            },
        )
        .await;
        let dead = blackhole_1961();
        park((0..3).map(|n| ctx_at(dead, 19610 + n)).collect());
        park(vec![ctx_at(addr.port(), 19619)]);
        let before = RECONCILED.get(&["deleted"]);
        for _ in 0..2 {
            reconcile_once().await;
        }
        let delivered = RECONCILED.get(&["deleted"]) - before;
        let left: Vec<String> = pending()
            .lock()
            .unwrap()
            .iter()
            .map(|p| p.ctx.context_ref.clone())
            .collect();
        clear_for_test();
        srv.stop().await.ok();
        assert_eq!(delivered, 1, "the healthy AMF gets its delete");
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(left.len(), 3, "the blackholed ones stay parked: {left:?}");
    }

    /// **#2015** (#1961's order, untested until now): after a pass, a record that
    /// was tried and failed sits BEHIND both a record the pass did not reach (its
    /// AMF was backing off) and a record parked while the pass ran -- so a
    /// failing AMF's deletes are not retried first on every pass. The stand-in
    /// AMF parks the new record when F1's delete reaches it, then refuses it.
    ///
    /// REVERT-VERIFIED: with `Repark::drop` pushing the failed records to the
    /// FRONT, "a failed delete goes behind the untried and the newly parked"
    /// fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_delete_goes_behind_untried_and_newly_parked_ones_2015() {
        let _g = PENDING_TEST_LOCK.lock().await;
        clear_for_test();
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = hits.clone();
        let (srv, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(
            move |_req: nextgcore_sbi::message::SbiRequest| {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    // Parked during the pass (another session's release).
                    park(vec![ctx(20153)]);
                    nextgcore_sbi::message::SbiResponse::with_status(503)
                }
            },
        )
        .await;
        park(vec![ctx_at(addr.port(), 20151), ctx_at(addr.port(), 20152)]);
        reconcile_once().await;
        let order: Vec<String> = pending()
            .lock()
            .unwrap()
            .iter()
            .map(|p| p.ctx.context_ref.clone())
            .collect();
        clear_for_test();
        srv.stop().await.ok();
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "F1 tried, F2 skipped for the backoff"
        );
        assert_eq!(
            order,
            ["20152", "20153", "20151"],
            "a failed delete goes behind the untried and the newly parked"
        );
    }

    /// #1961: a record parked longer than [`MAX_AGE`] ends as `expired`, not by
    /// eviction. REVERT-VERIFIED: with the age check removed it stays parked.
    #[tokio::test]
    async fn a_record_older_than_max_age_expires_1961() {
        let _g = PENDING_TEST_LOCK.lock().await;
        clear_for_test();
        park(vec![ctx(19611)]);
        pending().lock().unwrap()[0].since =
            std::time::SystemTime::now() - MAX_AGE - Duration::from_secs(1);
        let before = RECONCILED.get(&["expired"]);
        reconcile_once().await;
        let expired = RECONCILED.get(&["expired"]) - before;
        let left = pending_count();
        clear_for_test();
        assert_eq!((expired, left), (1, 0));
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
