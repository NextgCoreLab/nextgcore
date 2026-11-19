//! #2085: the reconciler for AMF unsubscribes that failed.
//!
//! An unsubscribe of one of this LMF's AMF subscriptions (N1N2MessageUnSubscribe,
//! TS 29.518 §5.2.2.3.4; NonUeN2InfoUnSubscribe, §5.2.2.4.3) used to be tried
//! once. Its local entry was already gone by then, so after a failure the AMF kept
//! the subscription and nothing ever asked it again. amfd's non-UE N2
//! subscriptions never expire, so a lost unsubscribe leaked one subscription for
//! good. Now a failed DELETE is parked here and retried every
//! [`RECONCILE_PERIOD`] until the AMF answers 2xx or 404 (gone).
//!
//! Built on the shared retry helpers (CONVENTIONS, #2042):
//! - **Backoff.** [`nextgcore_core::backoff::PeerBackoff`] per AMF. An AMF that
//!   failed is skipped until its backoff ends, so a dead AMF costs one request
//!   timeout per backoff period, not one per entry per pass.
//! - **Eviction.** [`nextgcore_core::backoff::evict_oldest`] at [`MAX_PENDING`].
//! - **Queue order.** An entry that was tried and failed goes to the back of the
//!   queue. One the pass did not reach keeps its place at the front.
//! - **Bounds.** A pass sends for at most [`MAX_PASS`], and an entry parked
//!   longer than [`MAX_AGE`] ends as expired.
//!
//! Ceiling: the set is in memory, like the subscriptions it serves. A restart
//! forgets it. Shutdown unsubscribes what it holds (`unsubscribe_all`) but
//! cannot retry past its own budget.

use crate::namf_client::DiscoveredAmf;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Unsubscribes parked before the oldest is abandoned.
pub const MAX_PENDING: usize = 4096;

/// How often the parked unsubscribes are retried.
#[cfg(not(test))]
pub const RECONCILE_PERIOD: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const RECONCILE_PERIOD: Duration = Duration::from_millis(20);

/// The longest one pass sends for.
#[cfg(not(test))]
pub const MAX_PASS: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const MAX_PASS: Duration = Duration::from_millis(500);

/// An entry parked this long is given up (`expired`): an AMF that has not
/// answered for a day is decommissioned, not restarting.
pub const MAX_AGE: Duration = Duration::from_secs(24 * 3600);

/// The first wait before an AMF whose DELETE failed is tried again, doubled up
/// to [`BACKOFF_MAX`] and cleared by a delivery.
#[cfg(not(test))]
pub const BACKOFF_BASE: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const BACKOFF_BASE: Duration = Duration::from_millis(300);
/// The longest a failing AMF is left alone between attempts.
pub const BACKOFF_MAX: Duration = Duration::from_secs(600);

/// Per AMF (`host:port`): its backoff. Guarded like [`parked`].
static BACKOFF: nextgcore_core::backoff::PeerBackoff =
    nextgcore_core::backoff::PeerBackoff::new(BACKOFF_BASE, BACKOFF_MAX);

/// One parked unsubscribe.
#[derive(Debug, Clone)]
struct Parked {
    amf: DiscoveredAmf,
    /// The subscription's resource path at the AMF.
    path: String,
    since: Instant,
}

fn peer_of(amf: &DiscoveredAmf) -> String {
    format!("{}:{}", amf.host, amf.port)
}

/// The parked unsubscribes, in the order they get their next turn.
///
/// Tests that read or write it hold [`TEST_LOCK`], declared beside it.
fn parked() -> std::sync::MutexGuard<'static, VecDeque<Parked>> {
    static PARKED: Mutex<VecDeque<Parked>> = Mutex::new(VecDeque::new());
    PARKED.lock().unwrap_or_else(|e| e.into_inner())
}

/// Serialises the tests that touch [`parked`] and [`BACKOFF`].
#[cfg(test)]
pub static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The path of subscription `id` at its AMF: a UE's N1N2 one when
/// `ue_context_id` is given, else the non-UE N2 one.
pub fn subscription_path(ue_context_id: Option<&str>, id: &str) -> String {
    match ue_context_id {
        Some(ue) => format!("/namf-comm/v1/ue-contexts/{ue}/n1-n2-messages/subscriptions/{id}"),
        None => format!("/namf-comm/v1/non-ue-n2-messages/subscriptions/{id}"),
    }
}

/// What one DELETE came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// 2xx, or 404: the AMF holds no such subscription.
    Delivered,
    /// No answer, or any other status: retry.
    Failed,
}

/// DELETE `path` at `amf` once.
pub async fn try_unsubscribe(amf: &DiscoveredAmf, path: &str) -> Outcome {
    match crate::namf_client::client_for(amf)
        .send_request(nextgcore_sbi::message::SbiRequest::delete(path))
        .await
    {
        Ok(resp) if (200..300).contains(&resp.status) || resp.status == 404 => {
            log::debug!(
                "A2: unsubscribe {path} at {} returned {}",
                peer_of(amf),
                resp.status
            );
            Outcome::Delivered
        }
        Ok(resp) => {
            log::warn!(
                "A2: unsubscribe {path} at {} returned {}",
                peer_of(amf),
                resp.status
            );
            Outcome::Failed
        }
        Err(e) => {
            log::warn!("A2: unsubscribe {path} at {} failed: {e}", peer_of(amf));
            Outcome::Failed
        }
    }
}

/// Park a failed unsubscribe. One already parked is not added twice; past
/// [`MAX_PENDING`] the oldest is abandoned.
pub fn park(amf: &DiscoveredAmf, path: &str) {
    let mut set = parked();
    if set
        .iter()
        .any(|p| p.path == path && peer_of(&p.amf) == peer_of(amf))
    {
        return;
    }
    log::warn!(
        "A2: unsubscribe {path} at {} parked; retried every {RECONCILE_PERIOD:?}",
        peer_of(amf)
    );
    set.push_back(Parked {
        amf: amf.clone(),
        path: path.to_string(),
        since: Instant::now(),
    });
    for old in nextgcore_core::backoff::evict_oldest(&mut set, MAX_PENDING, |p| p.since) {
        log::error!(
            "A2: unsubscribe {} at {} abandoned: {MAX_PENDING} are already pending",
            old.path,
            peer_of(&old.amf)
        );
    }
}

/// Unsubscribe `path` at `amf` on its own task, parking it if the DELETE fails.
pub fn spawn_unsubscribe(amf: &DiscoveredAmf, path: String) -> tokio::task::JoinHandle<()> {
    let amf = amf.clone();
    tokio::spawn(async move {
        if try_unsubscribe(&amf, &path).await == Outcome::Failed {
            park(&amf, &path);
        }
    })
}

/// How many unsubscribes are parked.
pub fn parked_count() -> usize {
    parked().len()
}

/// Whether `path` is parked (tests). Hold [`TEST_LOCK`].
#[cfg(test)]
pub fn is_parked(path: &str) -> bool {
    parked().iter().any(|p| p.path == path)
}

/// Make every parked entry look parked `by` earlier (tests of [`MAX_AGE`]).
#[cfg(test)]
pub fn backdate_for_test(by: Duration) {
    for p in parked().iter_mut() {
        p.since -= by;
    }
}

/// Whether `amf` is backing off (tests).
#[cfg(test)]
pub fn backing_off(amf: &DiscoveredAmf) -> bool {
    BACKOFF.backing_off(&peer_of(amf))
}

/// Forget everything parked, and every backoff (tests).
#[cfg(test)]
pub fn clear_for_test() {
    parked().clear();
    BACKOFF.clear();
}

/// How many AMFs one pass sends to at once: each AMF is a lane, so dead AMFs
/// cost a timeout each in parallel rather than in turn, and no AMF starves the
/// others.
const MAX_LANES: usize = 64;

/// One pass over the parked unsubscribes, in turn order, for at most
/// [`MAX_PASS`]. Returns how many ended (delivered or expired).
///
/// Each AMF is a lane, its entries sent in turn, up to [`MAX_LANES`] lanes at
/// once. An AMF that is backing off is not tried and takes no slot. Once a
/// DELETE to an AMF fails, that AMF backs off and the rest of its lane waits. An
/// entry that was tried and failed goes to the back of the queue; one this pass
/// did not try keeps its place at the front, ahead of anything parked meanwhile.
pub async fn reconcile_once() -> usize {
    let batch: Vec<Parked> = parked().drain(..).collect();
    let deadline = tokio::time::Instant::now() + MAX_PASS;
    let mut ended = 0;
    let mut lanes: Vec<(String, Vec<(usize, Parked)>)> = Vec::new();
    for (place, p) in batch.into_iter().enumerate() {
        if p.since.elapsed() > MAX_AGE {
            log::error!(
                "A2: unsubscribe {} at {} expired after {MAX_AGE:?}",
                p.path,
                peer_of(&p.amf)
            );
            ended += 1;
            continue;
        }
        let peer = peer_of(&p.amf);
        match lanes.iter_mut().find(|(l, _)| *l == peer) {
            Some((_, lane)) => lane.push((place, p)),
            None => lanes.push((peer, vec![(place, p)])),
        }
    }

    let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_LANES));
    let mut sending = tokio::task::JoinSet::new();
    let mut outcomes: Vec<(usize, Parked, Option<Outcome>)> = Vec::new();
    for (peer, lane) in lanes {
        let slot = if BACKOFF.backing_off(&peer) {
            None
        } else {
            tokio::time::timeout_at(deadline, gate.clone().acquire_owned())
                .await
                .ok()
                .and_then(Result::ok)
        };
        let Some(slot) = slot else {
            outcomes.extend(lane.into_iter().map(|(place, p)| (place, p, None)));
            continue;
        };
        sending.spawn(async move {
            let _slot = slot;
            let mut failed = false;
            let mut out = Vec::with_capacity(lane.len());
            for (place, p) in lane {
                let outcome = if failed || tokio::time::Instant::now() >= deadline {
                    None
                } else {
                    let sent =
                        tokio::time::timeout_at(deadline, try_unsubscribe(&p.amf, &p.path)).await;
                    match sent {
                        Ok(Outcome::Delivered) => Some(Outcome::Delivered),
                        Ok(Outcome::Failed) | Err(_) => {
                            failed = true;
                            Some(Outcome::Failed)
                        }
                    }
                };
                out.push((place, p, outcome));
            }
            if failed {
                BACKOFF.note_failure(&peer);
            } else if out.iter().any(|(_, _, o)| *o == Some(Outcome::Delivered)) {
                BACKOFF.note_success(&peer);
            }
            out
        });
    }
    while let Some(done) = sending.join_next().await {
        if let Ok(out) = done {
            outcomes.extend(out);
        }
    }
    outcomes.sort_by_key(|(place, _, _)| *place);
    let mut untried = Vec::new();
    let mut failed = Vec::new();
    for (_, p, outcome) in outcomes {
        match outcome {
            Some(Outcome::Delivered) => ended += 1,
            Some(Outcome::Failed) => failed.push(p),
            None => untried.push(p),
        }
    }
    let mut set = parked();
    // Untried first, in their order, ahead of anything parked meanwhile; then
    // what was parked meanwhile; then the failed, at the back.
    let meanwhile: Vec<Parked> = set.drain(..).collect();
    set.extend(untried);
    set.extend(meanwhile);
    set.extend(failed);
    for old in nextgcore_core::backoff::evict_oldest(&mut set, MAX_PENDING, |p| p.since) {
        log::error!(
            "A2: unsubscribe {} at {} abandoned: {MAX_PENDING} are already pending",
            old.path,
            peer_of(&old.amf)
        );
    }
    let still: Vec<String> = set.iter().map(|p| peer_of(&p.amf)).collect();
    drop(set);
    BACKOFF.retain(|peer| still.iter().any(|s| s == peer));
    ended
}

/// Run [`reconcile_once`] every [`RECONCILE_PERIOD`].
pub fn spawn_reconciler() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {
        let mut tick = tokio::time::interval(RECONCILE_PERIOD);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if parked_count() > 0 {
                reconcile_once().await;
            }
        }
    })
}

/// #2085: at shutdown, unsubscribe every subscription this LMF holds at its AMF,
/// all at once and within `budget`. amfd's non-UE N2 subscriptions never expire,
/// so one not unsubscribed here would outlive this LMF for good. Returns how
/// many the AMFs acknowledged (2xx or 404).
pub async fn unsubscribe_all(
    subscriptions: Vec<(DiscoveredAmf, String)>,
    budget: Duration,
) -> usize {
    let mut sending = tokio::task::JoinSet::new();
    for (amf, path) in subscriptions {
        sending.spawn(async move { try_unsubscribe(&amf, &path).await });
    }
    let mut delivered = 0;
    let deadline = tokio::time::Instant::now() + budget;
    while let Ok(Some(done)) = tokio::time::timeout_at(deadline, sending.join_next()).await {
        if matches!(done, Ok(Outcome::Delivered)) {
            delivered += 1;
        }
    }
    if !sending.is_empty() {
        log::warn!(
            "A2: {} AMF unsubscribe(s) unanswered within the {budget:?} shutdown budget",
            sending.len()
        );
    }
    delivered
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn amf_at(port: u16) -> DiscoveredAmf {
        DiscoveredAmf {
            host: "127.0.0.1".to_string(),
            port,
            scheme: "http".to_string(),
            nf_instance_id: None,
        }
    }

    /// A stand-in AMF answering its DELETEs `statuses` in turn (then 204), and
    /// recording their paths.
    async fn scripted_amf(
        statuses: &[u16],
    ) -> (
        nextgcore_sbi::server::SbiServer,
        DiscoveredAmf,
        Arc<Mutex<Vec<String>>>,
    ) {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(Mutex::new(
            statuses.iter().copied().collect::<VecDeque<u16>>(),
        ));
        let (s, sc) = (seen.clone(), script.clone());
        let (server, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(
            move |req: nextgcore_sbi::message::SbiRequest| {
                let (s, sc) = (s.clone(), sc.clone());
                async move {
                    s.lock().unwrap().push(req.header.uri.clone());
                    let status = sc.lock().unwrap().pop_front().unwrap_or(204);
                    nextgcore_sbi::message::SbiResponse::with_status(status)
                }
            },
        )
        .await;
        (server, amf_at(addr.port()), seen)
    }

    /// **#2085**: a DELETE the AMF refuses is parked, not only logged, and the
    /// next pass delivers it.
    ///
    /// REVERT-VERIFIED: with `spawn_unsubscribe` not parking a failure, "the
    /// failed unsubscribe is parked" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_unsubscribe_is_parked_then_delivered_2085() {
        let _g = TEST_LOCK.lock().await;
        clear_for_test();
        let (_server, amf, seen) = scripted_amf(&[500]).await;
        let path = subscription_path(None, "nonue-2085");
        spawn_unsubscribe(&amf, path.clone()).await.unwrap();
        assert!(is_parked(&path), "the failed unsubscribe is parked");
        assert_eq!(reconcile_once().await, 1, "the retry is delivered");
        assert!(!is_parked(&path));
        assert_eq!(*seen.lock().unwrap(), vec![path.clone(), path]);
        clear_for_test();
    }

    /// **#2085**: a 404 ends a parked unsubscribe: the AMF holds no such
    /// subscription. An entry older than [`MAX_AGE`] expires unsent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_404_or_old_age_ends_a_parked_unsubscribe_2085() {
        let _g = TEST_LOCK.lock().await;
        clear_for_test();
        let (_server, amf, seen) = scripted_amf(&[404]).await;
        let gone = subscription_path(Some("ue-2085"), "gone");
        park(&amf, &gone);
        assert_eq!(reconcile_once().await, 1);
        assert!(!is_parked(&gone), "404 is gone");
        let old = subscription_path(Some("ue-2085"), "old");
        park(&amf, &old);
        backdate_for_test(MAX_AGE + Duration::from_secs(1));
        assert_eq!(reconcile_once().await, 1);
        assert!(!is_parked(&old), "expired");
        assert_eq!(seen.lock().unwrap().len(), 1, "the expired one is not sent");
        clear_for_test();
    }

    /// **#2085** (CONVENTIONS: one blackholed-peer test per reconciler): an AMF
    /// that accepts and never answers costs one bounded attempt per pass. Its
    /// entries are re-parked, it backs off and is not tried again in the next
    /// pass, and a healthy AMF parked behind it is delivered in the first pass.
    ///
    /// REVERT-VERIFIED: with the lanes run in turn (no `JoinSet`), the healthy
    /// AMF's unsubscribe waits behind the blackhole and "the healthy AMF is not
    /// starved" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_blackholed_amf_neither_stalls_nor_starves_the_pass_2085() {
        let _g = TEST_LOCK.lock().await;
        clear_for_test();
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hole_port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let a = accepted.clone();
        let hole = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                a.fetch_add(1, Ordering::SeqCst);
                held.push(sock);
            }
        });
        let dead = amf_at(hole_port);
        for n in 0..3 {
            park(&dead, &subscription_path(None, &format!("hole-{n}")));
        }
        let (_server, healthy, seen) = scripted_amf(&[]).await;
        let ok = subscription_path(None, "healthy-2085");
        park(&healthy, &ok);

        let started = std::time::Instant::now();
        assert_eq!(
            reconcile_once().await,
            1,
            "the healthy AMF is not starved: delivered in the first pass"
        );
        assert!(
            started.elapsed() < MAX_PASS + Duration::from_secs(1),
            "the pass is bounded: {:?}",
            started.elapsed()
        );
        assert!(!is_parked(&ok), "the healthy AMF is not starved");
        assert_eq!(*seen.lock().unwrap(), vec![ok]);
        assert_eq!(
            parked_count(),
            3,
            "the blackholed AMF's entries are re-parked"
        );
        assert!(backing_off(&dead), "the blackholed AMF backs off");

        let tried = accepted.load(Ordering::SeqCst);
        assert_eq!(reconcile_once().await, 0);
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            tried,
            "a backing-off AMF is not tried"
        );
        clear_for_test();
        hole.abort();
    }

    /// **#2085**: shutdown unsubscribes every subscription at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unsubscribe_all_sends_every_delete_2085() {
        let (_server, amf, seen) = scripted_amf(&[404]).await;
        let paths = [
            subscription_path(None, "nonue-all"),
            subscription_path(Some("ue-all"), "n1n2-all"),
        ];
        let done = unsubscribe_all(
            paths.iter().map(|p| (amf.clone(), p.clone())).collect(),
            Duration::from_secs(3),
        )
        .await;
        assert_eq!(done, 2);
        let mut got = seen.lock().unwrap().clone();
        got.sort();
        let mut want = paths.to_vec();
        want.sort();
        assert_eq!(got, want);
    }
}
