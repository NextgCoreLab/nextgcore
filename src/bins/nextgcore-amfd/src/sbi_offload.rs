//! SBI work taken off the NGAP task (#796 review M1, shared with #848).
//!
//! The NGAP task serves every gNB. An SBI request it awaits holds all of N2 for
//! as long as the peer takes, and against an address that drops connection
//! attempts (a stale pod IP, a lost node) that is the client's connect timeout
//! per request. So the NGAP task never awaits such a request: it spawns it here,
//! with bounded concurrency, and the result comes back as an [`SbiOutcome`] that
//! `NgapServer::poll` applies on the NGAP task, where every write of its state
//! happens.
//!
//! # Ordering
//! - [`SbiOffload::spawn`] is UNORDERED: use it only for work no later exchange
//!   depends on.
//! - [`SbiOffload::spawn_keyed`] serialises per key, a (AMF UE NGAP ID, PSI)
//!   pair: at most one exchange per key runs, the rest wait in submission order,
//!   so two exchanges for one PDU session reach the peer in the order they were
//!   submitted (#796 re-review M1: a late DEACTIVATED must not overtake a later
//!   ACTIVATING). [`SbiOffload::supersede_key`] drops the queued ones that a
//!   newer decision makes moot; [`SbiOffload::settle_key`] also waits for the
//!   running one; [`SbiOffload::cancel_ue`] (from `forget_ue`) aborts a departed
//!   UE's work and frees its permits; [`SbiOffload::rekey_ue`] follows a UE that
//!   moved to a new AMF UE NGAP ID.
//!
//! Every method is called from the NGAP task (it owns the `SbiOffload`), so the
//! per-key bookkeeping needs no lock: a finished keyed exchange reports back over
//! the same channel as the outcomes, and the next one for its key is started when
//! that report is drained.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;

/// The result of one off-task SBI exchange, applied on the NGAP task. Each
/// feature that offloads adds its variant.
#[derive(Debug)]
pub(crate) enum SbiOutcome {
    /// #796: a re-selection attempt for a waiting PDU Session Establishment.
    Establishment(crate::ngap_path::EstablishmentAttempt),
}

/// What keyed work is serialised on: (AMF UE NGAP ID, PDU session ID).
pub(crate) type SbiKey = (u64, u8);

type BoxedWork = Pin<Box<dyn Future<Output = Option<SbiOutcome>> + Send>>;
/// Keyed work is built only when it is its turn, so a superseded exchange is
/// never even constructed, let alone sent.
type Job = Box<dyn FnOnce() -> BoxedWork + Send>;

/// What a spawned task sends back.
enum Report {
    Outcome(SbiOutcome),
    /// The keyed exchange `job` finished (its outcome, if any, was sent first).
    KeyDone {
        job: u64,
    },
}

#[derive(Default)]
struct KeyQueue {
    /// The running exchange: its id and the handle that aborts it.
    running: Option<(u64, JoinHandle<()>)>,
    queued: VecDeque<Job>,
}

/// Spawner of off-task SBI work, owned by the NGAP server.
pub(crate) struct SbiOffload {
    tx: mpsc::UnboundedSender<Report>,
    rx: mpsc::UnboundedReceiver<Report>,
    permits: Arc<Semaphore>,
    max_in_flight: usize,
    keys: HashMap<SbiKey, KeyQueue>,
    next_job: u64,
    /// Outcomes drained while settling, handed out by `try_recv` first.
    ready: VecDeque<SbiOutcome>,
    /// Spawned and not yet finished, permit or not (for [`SbiOffload::settle`]).
    spawned: Arc<std::sync::atomic::AtomicUsize>,
}

impl std::fmt::Debug for SbiOffload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SbiOffload")
            .field("in_flight", &self.in_flight())
            .field("keys", &self.keys.len())
            .finish()
    }
}

impl SbiOffload {
    /// At most `max_in_flight` exchanges run at once; the rest wait for a permit
    /// inside their own task, never on the caller.
    pub(crate) fn new(max_in_flight: usize) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            tx,
            rx,
            permits: Arc::new(Semaphore::new(max_in_flight)),
            max_in_flight,
            keys: HashMap::new(),
            next_job: 1,
            ready: VecDeque::new(),
            spawned: Arc::default(),
        }
    }

    /// Run `fut` on its own task, UNORDERED with respect to everything else. Its
    /// outcome, if any, is queued for [`SbiOffload::try_recv`]. The caller never
    /// awaits.
    pub(crate) fn spawn<F>(&self, fut: F)
    where
        F: Future<Output = Option<SbiOutcome>> + Send + 'static,
    {
        self.start(Box::pin(fut), None);
    }

    /// Run the work `make` builds after every earlier keyed work for `key` has
    /// finished (or been superseded / cancelled). The caller never awaits.
    pub(crate) fn spawn_keyed<M, F>(&mut self, key: SbiKey, make: M)
    where
        M: FnOnce() -> F + Send + 'static,
        F: Future<Output = Option<SbiOutcome>> + Send + 'static,
    {
        let job: Job = Box::new(move || Box::pin(make()) as BoxedWork);
        let queue = self.keys.entry(key).or_default();
        queue.queued.push_back(job);
        if queue.running.is_none() {
            self.start_next(key);
        }
    }

    /// Drop the keyed work for `key` that has not started. The running exchange,
    /// if any, is left to finish.
    pub(crate) fn supersede_key(&mut self, key: SbiKey) {
        if let Some(queue) = self.keys.get_mut(&key) {
            queue.queued.clear();
            if queue.running.is_none() {
                self.keys.remove(&key);
            }
        }
    }

    /// Drop the queued work for `key` and wait until the running exchange, if
    /// any, has finished. Its outcome is still delivered by `try_recv`. Awaits on
    /// the caller for at most that one exchange.
    pub(crate) async fn settle_key(&mut self, key: SbiKey) {
        let Some(mut queue) = self.keys.remove(&key) else {
            return;
        };
        queue.queued.clear();
        if let Some((_, handle)) = queue.running.take() {
            // A panicked or aborted task is finished too.
            let _ = handle.await;
        }
        // Its KeyDone report finds no running job any more and is ignored.
    }

    /// Abort and drop all keyed work of a UE that is gone, freeing the permits of
    /// its running exchanges. Their outcomes are never delivered.
    pub(crate) fn cancel_ue(&mut self, amf_ue_ngap_id: u64) {
        let gone: Vec<SbiKey> = self
            .keys
            .keys()
            .filter(|(ue, _)| *ue == amf_ue_ngap_id)
            .copied()
            .collect();
        for key in gone {
            if let Some(queue) = self.keys.remove(&key) {
                if let Some((_, handle)) = queue.running {
                    handle.abort();
                }
            }
        }
    }

    /// A UE moved from `old` to `new` (a CM-IDLE return): its keyed work follows.
    pub(crate) fn rekey_ue(&mut self, old: u64, new: u64) {
        let moving: Vec<SbiKey> = self
            .keys
            .keys()
            .filter(|(ue, _)| *ue == old)
            .copied()
            .collect();
        for key in moving {
            if let Some(queue) = self.keys.remove(&key) {
                self.keys.insert((new, key.1), queue);
            }
        }
    }

    /// The next outcome ready to apply, without waiting. Starts the next keyed
    /// work for every key whose running exchange reported done.
    pub(crate) fn try_recv(&mut self) -> Option<SbiOutcome> {
        if let Some(outcome) = self.ready.pop_front() {
            return Some(outcome);
        }
        while let Ok(report) = self.rx.try_recv() {
            match report {
                Report::Outcome(outcome) => return Some(outcome),
                Report::KeyDone { job } => self.key_done(job),
            }
        }
        None
    }

    /// How many exchanges hold a permit right now.
    pub(crate) fn in_flight(&self) -> usize {
        self.max_in_flight - self.permits.available_permits()
    }

    /// Whether any keyed work is queued or running for `key`.
    pub(crate) fn key_busy(&self, key: SbiKey) -> bool {
        self.keys.contains_key(&key)
    }

    /// Tests: wait until every spawned and every queued exchange has finished.
    /// Outcomes stay queued for `try_recv`. Panics after 10 s.
    #[cfg(test)]
    pub(crate) async fn settle(&mut self) {
        for _ in 0..2000 {
            while let Ok(report) = self.rx.try_recv() {
                match report {
                    Report::Outcome(outcome) => self.ready.push_back(outcome),
                    Report::KeyDone { job } => self.key_done(job),
                }
            }
            if self.spawned.load(std::sync::atomic::Ordering::Acquire) == 0 && self.keys.is_empty()
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("off-task SBI work did not finish within 10 s");
    }

    fn key_done(&mut self, job: u64) {
        let Some(key) = self
            .keys
            .iter()
            .find(|(_, q)| q.running.as_ref().is_some_and(|(id, _)| *id == job))
            .map(|(k, _)| *k)
        else {
            // Settled, cancelled or superseded meanwhile.
            return;
        };
        if let Some(queue) = self.keys.get_mut(&key) {
            queue.running = None;
        }
        self.start_next(key);
    }

    fn start_next(&mut self, key: SbiKey) {
        let Some(queue) = self.keys.get_mut(&key) else {
            return;
        };
        let Some(job) = queue.queued.pop_front() else {
            self.keys.remove(&key);
            return;
        };
        let id = self.next_job;
        self.next_job += 1;
        let handle = self.start(job(), Some(id));
        if let Some(queue) = self.keys.get_mut(&key) {
            queue.running = Some((id, handle));
        }
    }

    fn start(&self, work: BoxedWork, job: Option<u64>) -> JoinHandle<()> {
        let tx = self.tx.clone();
        let permits = Arc::clone(&self.permits);
        let spawned = Arc::clone(&self.spawned);
        spawned.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        // Decremented on drop, so an aborted task is counted out too.
        struct Done(Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for Done {
            fn drop(&mut self) {
                self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            }
        }
        tokio::spawn(async move {
            let _done = Done(spawned);
            // The semaphore is never closed, so this cannot fail; if it ever did,
            // running without a permit is better than dropping the work.
            let _permit = permits.acquire_owned().await.ok();
            if let Some(outcome) = work.await {
                // The receiver lives as long as the NGAP server; after it is gone
                // there is nobody to apply the outcome to.
                let _ = tx.send(Report::Outcome(outcome));
            }
            if let Some(job) = job {
                let _ = tx.send(Report::KeyDone { job });
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn until(mut cond: impl FnMut() -> bool) {
        for _ in 0..400 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("condition not reached");
    }

    /// Work beyond the bound waits for a permit in its own task; the caller of
    /// `spawn` is never held, and every task finishes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawn_never_waits_and_bounds_the_work_in_flight() {
        let mut offload = SbiOffload::new(2);
        let gate = Arc::new(Semaphore::new(0));
        let started = std::time::Instant::now();
        for _ in 0..5 {
            let gate = Arc::clone(&gate);
            offload.spawn(async move {
                let _ = gate.acquire().await.map(|p| p.forget());
                None
            });
        }
        assert!(started.elapsed() < Duration::from_millis(100));
        until(|| offload.in_flight() == 2).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(offload.in_flight(), 2, "only two run at once");
        gate.add_permits(5);
        offload.settle().await;
        assert_eq!(offload.in_flight(), 0);
        assert!(offload.try_recv().is_none(), "None outcomes queue nothing");
    }

    /// Two exchanges for one key reach the peer in submission order even when
    /// the first is the slower one; a different key is not held behind them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn keyed_work_runs_in_submission_order() {
        let mut offload = SbiOffload::new(16);
        let seen: Arc<std::sync::Mutex<Vec<&'static str>>> = Arc::default();
        for (name, delay) in [("first", 80u64), ("second", 0)] {
            let seen = Arc::clone(&seen);
            offload.spawn_keyed((1, 5), move || async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                seen.lock().expect("seen").push(name);
                None
            });
        }
        let other = Arc::clone(&seen);
        offload.spawn_keyed((1, 6), move || async move {
            other.lock().expect("seen").push("other key");
            None
        });
        offload.settle().await;
        assert_eq!(
            *seen.lock().expect("seen"),
            vec!["other key", "first", "second"]
        );
    }

    /// Superseded keyed work is never built nor sent; the running one finishes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn superseded_work_never_reaches_the_peer() {
        let mut offload = SbiOffload::new(16);
        let seen: Arc<std::sync::Mutex<Vec<&'static str>>> = Arc::default();
        let gate = Arc::new(tokio::sync::Notify::new());
        {
            let (seen, gate) = (Arc::clone(&seen), Arc::clone(&gate));
            offload.spawn_keyed((2, 1), move || async move {
                gate.notified().await;
                seen.lock().expect("seen").push("running");
                None
            });
        }
        for name in ["queued 1", "queued 2"] {
            let seen = Arc::clone(&seen);
            offload.spawn_keyed((2, 1), move || async move {
                seen.lock().expect("seen").push(name);
                None
            });
        }
        offload.supersede_key((2, 1));
        let seen2 = Arc::clone(&seen);
        offload.spawn_keyed((2, 1), move || async move {
            seen2.lock().expect("seen").push("newest");
            None
        });
        gate.notify_one();
        offload.settle().await;
        assert_eq!(*seen.lock().expect("seen"), vec!["running", "newest"]);
    }

    /// `settle_key` waits for the running exchange and drops the queued ones.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn settle_key_waits_for_the_running_exchange() {
        let mut offload = SbiOffload::new(16);
        let seen: Arc<std::sync::Mutex<Vec<&'static str>>> = Arc::default();
        for (name, delay) in [("running", 50u64), ("queued", 0)] {
            let seen = Arc::clone(&seen);
            offload.spawn_keyed((3, 1), move || async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                seen.lock().expect("seen").push(name);
                None
            });
        }
        until(|| offload.in_flight() == 1).await;
        offload.settle_key((3, 1)).await;
        assert_eq!(*seen.lock().expect("seen"), vec!["running"]);
        assert!(!offload.key_busy((3, 1)));
        offload.settle().await;
        assert_eq!(*seen.lock().expect("seen"), vec!["running"]);
    }

    /// `cancel_ue` aborts a departed UE's running exchanges and frees their
    /// permits; their outcomes are never delivered; other UEs are untouched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_ue_frees_the_permits() {
        let mut offload = SbiOffload::new(2);
        for psi in [1u8, 2] {
            offload.spawn_keyed((4, psi), || async {
                std::future::pending::<()>().await;
                None
            });
        }
        until(|| offload.in_flight() == 2).await;
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&ran);
        offload.spawn_keyed((5, 1), move || async move {
            flag.store(true, std::sync::atomic::Ordering::Release);
            None
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!ran.load(std::sync::atomic::Ordering::Acquire), "no permit");

        offload.cancel_ue(4);

        until(|| ran.load(std::sync::atomic::Ordering::Acquire)).await;
        offload.settle().await;
        assert_eq!(offload.in_flight(), 0);
        assert!(!offload.key_busy((4, 1)) && !offload.key_busy((4, 2)));
    }

    /// `rekey_ue` moves a UE's keyed work to its new id, ordering kept.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rekey_ue_keeps_the_order() {
        let mut offload = SbiOffload::new(16);
        let seen: Arc<std::sync::Mutex<Vec<&'static str>>> = Arc::default();
        let gate = Arc::new(tokio::sync::Notify::new());
        {
            let (seen, gate) = (Arc::clone(&seen), Arc::clone(&gate));
            offload.spawn_keyed((6, 1), move || async move {
                gate.notified().await;
                seen.lock().expect("seen").push("before");
                None
            });
        }
        offload.rekey_ue(6, 7);
        assert!(offload.key_busy((7, 1)) && !offload.key_busy((6, 1)));
        let seen2 = Arc::clone(&seen);
        offload.spawn_keyed((7, 1), move || async move {
            seen2.lock().expect("seen").push("after");
            None
        });
        gate.notify_one();
        offload.settle().await;
        assert_eq!(*seen.lock().expect("seen"), vec!["before", "after"]);
    }
}
