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
//!   ACTIVATING). [`SbiOffload::supersede_key`] drops the work for a key that a
//!   newer decision makes moot and that has not STARTED; [`SbiOffload::settle_key`]
//!   also waits, bounded, for the one that has; [`SbiOffload::cancel_ue`] (from
//!   `forget_ue`) aborts a departed UE's work and frees its permits;
//!   [`SbiOffload::rekey_ue`] follows a UE that moved to a new AMF UE NGAP ID.
//! - [`SbiOffload::spawn_keyed_durable`] is keyed work that nothing drops: the
//!   release of a context nobody will use must reach the peer whatever the UE
//!   does next. Neither `supersede_key`, `settle_key` nor `cancel_ue` drops it,
//!   so a departed UE's release is still sent.
//!
//! # Started means holding a permit (#877 re-review M1)
//! A keyed job is STARTED only once its task holds a concurrency permit: then,
//! and only then, its work is built and sent. Until then it is WAITING, and
//! `supersede_key`, `settle_key` and `cancel_ue` cancel it outright, so a
//! superseded exchange never reaches the peer even when every permit is taken
//! (a blackholed peer, exactly when this helper matters). The switch is one
//! compare-and-swap on the job's state, so a job is either cancelled before it
//! builds anything or runs to completion, never both.
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
    /// #964: the SMF's answer to an N2 handover step (PREPARING or PREPARED) for one
    /// PDU session.
    N2Handover(crate::ngap_path::N2HandoverAnswer),
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

/// A keyed job's state, shared by the NGAP task and the job's own task.
const WAITING: u8 = 0;
const STARTED: u8 = 1;
const CANCELLED: u8 = 2;

/// The keyed job that is next for its key: spawned, and either waiting for a
/// permit or started.
struct Running {
    id: u64,
    handle: JoinHandle<()>,
    state: Arc<std::sync::atomic::AtomicU8>,
    durable: bool,
}

impl Running {
    /// Cancel the job if it has not started. True when it was cancelled, so it
    /// will never build or send anything.
    fn cancel_if_waiting(&self) -> bool {
        let cancelled = self
            .state
            .compare_exchange(
                WAITING,
                CANCELLED,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok();
        if cancelled {
            // It is parked on the semaphore: let go of its place in the queue.
            self.handle.abort();
        }
        cancelled
    }
}

#[derive(Default)]
struct KeyQueue {
    running: Option<Running>,
    /// Not yet spawned, in submission order; `true` marks durable work.
    queued: VecDeque<(Job, bool)>,
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
    /// Tasks that have reached the semaphore and not yet taken a permit.
    ///
    /// A test-only observable, and the one the #877 M1 reproduction needs:
    /// "spawned but not holding a permit" also counts a task that has not been
    /// polled at all, and superseding THAT proves nothing — such a job is
    /// cancelled before it could mark itself started either way. This counts
    /// only tasks really parked on the permit.
    #[cfg(test)]
    at_the_gate: Arc<std::sync::atomic::AtomicUsize>,
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
            #[cfg(test)]
            at_the_gate: Arc::default(),
        }
    }

    /// Run `fut` on its own task, UNORDERED with respect to everything else. Its
    /// outcome, if any, is queued for [`SbiOffload::try_recv`]. The caller never
    /// awaits.
    pub(crate) fn spawn<F>(&self, fut: F)
    where
        F: Future<Output = Option<SbiOutcome>> + Send + 'static,
    {
        self.start(None, Box::new(move || Box::pin(fut) as BoxedWork));
    }

    /// Run the work `make` builds after every earlier keyed work for `key` has
    /// finished (or been superseded / cancelled). `make` is called only once the
    /// job holds a permit. The caller never awaits.
    pub(crate) fn spawn_keyed<M, F>(&mut self, key: SbiKey, make: M)
    where
        M: FnOnce() -> F + Send + 'static,
        F: Future<Output = Option<SbiOutcome>> + Send + 'static,
    {
        self.enqueue(key, Box::new(move || Box::pin(make()) as BoxedWork), false);
    }

    /// [`SbiOffload::spawn_keyed`] for work that must reach the peer whatever
    /// happens next: neither `supersede_key`, `settle_key` nor `cancel_ue` drops
    /// it. For cleanup such as releasing a context nobody will use.
    pub(crate) fn spawn_keyed_durable<M, F>(&mut self, key: SbiKey, make: M)
    where
        M: FnOnce() -> F + Send + 'static,
        F: Future<Output = Option<SbiOutcome>> + Send + 'static,
    {
        self.enqueue(key, Box::new(move || Box::pin(make()) as BoxedWork), true);
    }

    fn enqueue(&mut self, key: SbiKey, job: Job, durable: bool) {
        let queue = self.keys.entry(key).or_default();
        queue.queued.push_back((job, durable));
        if queue.running.is_none() {
            self.start_next(key);
        }
    }

    /// Drop the keyed work for `key` that has not started: the queued work and a
    /// job still waiting for a permit. Durable work stays. A started exchange is
    /// left to finish; its outcome is still delivered.
    pub(crate) fn supersede_key(&mut self, key: SbiKey) {
        let Some(queue) = self.keys.get_mut(&key) else {
            return;
        };
        queue.queued.retain(|(_, durable)| *durable);
        let cancelled = queue
            .running
            .as_ref()
            .is_some_and(|r| !r.durable && r.cancel_if_waiting());
        if cancelled {
            queue.running = None;
            // Durable work queued behind it goes next.
            self.start_next(key);
        } else if queue.running.is_none() && queue.queued.is_empty() {
            self.keys.remove(&key);
        }
    }

    /// [`SbiOffload::supersede_key`], then wait until nothing for `key` is left
    /// running: the started exchange, and any durable work. Outcomes are still
    /// delivered by `try_recv`.
    ///
    /// **This awaits on the caller's task** (the NGAP task, for every caller in
    /// this crate), so it is bounded by `max_wait`: one exchange against a peer
    /// that accepts and never answers can take the SBI client's whole request
    /// timeout. Returns `false` when `max_wait` ran out first; the work is then
    /// still running, and still ordered ahead of anything submitted for `key`.
    pub(crate) async fn settle_key(&mut self, key: SbiKey, max_wait: std::time::Duration) -> bool {
        self.supersede_key(key);
        let deadline = tokio::time::Instant::now() + max_wait;
        loop {
            let Some(queue) = self.keys.get_mut(&key) else {
                return true;
            };
            let Some(running) = queue.running.as_mut() else {
                self.start_next(key);
                continue;
            };
            let id = running.id;
            match tokio::time::timeout_at(deadline, &mut running.handle).await {
                // Finished (a panicked or aborted task is finished too). Its
                // KeyDone report will find another job, or none, and is ignored.
                Ok(_) => {
                    if let Some(queue) = self.keys.get_mut(&key) {
                        if queue.running.as_ref().is_some_and(|r| r.id == id) {
                            queue.running = None;
                        }
                    }
                    self.start_next(key);
                }
                Err(_) => return false,
            }
        }
    }

    /// Abort and drop all keyed work of a UE that is gone, freeing the permits of
    /// its running exchanges; their outcomes are never delivered. Durable work
    /// is kept and still runs.
    pub(crate) fn cancel_ue(&mut self, amf_ue_ngap_id: u64) {
        let gone: Vec<SbiKey> = self
            .keys
            .keys()
            .filter(|(ue, _)| *ue == amf_ue_ngap_id)
            .copied()
            .collect();
        for key in gone {
            let Some(queue) = self.keys.get_mut(&key) else {
                continue;
            };
            queue.queued.retain(|(_, durable)| *durable);
            let aborted = match queue.running.as_ref() {
                Some(r) if !r.durable => {
                    // Mark it so a task between its permit and its build stops.
                    r.state
                        .store(CANCELLED, std::sync::atomic::Ordering::Release);
                    r.handle.abort();
                    true
                }
                _ => false,
            };
            if aborted {
                queue.running = None;
                self.start_next(key);
            } else if queue.running.is_none() && queue.queued.is_empty() {
                self.keys.remove(&key);
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

    /// Tests: how many spawned exchanges are parked ON the permit semaphore
    /// (see [`SbiOffload::at_the_gate`]).
    #[cfg(test)]
    pub(crate) fn waiting_for_a_permit(&self) -> usize {
        self.at_the_gate.load(std::sync::atomic::Ordering::Acquire)
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
            .find(|(_, q)| q.running.as_ref().is_some_and(|r| r.id == job))
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
        let Some((job, durable)) = queue.queued.pop_front() else {
            if queue.running.is_none() {
                self.keys.remove(&key);
            }
            return;
        };
        let id = self.next_job;
        self.next_job += 1;
        let state = Arc::new(std::sync::atomic::AtomicU8::new(WAITING));
        let handle = self.start(Some((id, Arc::clone(&state))), job);
        if let Some(queue) = self.keys.get_mut(&key) {
            queue.running = Some(Running {
                id,
                handle,
                state,
                durable,
            });
        }
    }

    /// Spawn the task that takes a permit, then builds and runs `make`'s work.
    /// For keyed work, `keyed` is its id and state: the work is built only if
    /// the job is still WAITING once it holds the permit.
    fn start(
        &self,
        keyed: Option<(u64, Arc<std::sync::atomic::AtomicU8>)>,
        make: Job,
    ) -> JoinHandle<()> {
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
        // Built here and moved in, so a task aborted before its first poll (a
        // waiting job that was cancelled) still counts itself out when dropped.
        let done = Done(spawned);
        #[cfg(test)]
        let at_the_gate = Arc::clone(&self.at_the_gate);
        tokio::spawn(async move {
            let _done = done;
            #[cfg(test)]
            at_the_gate.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            // The semaphore is never closed, so this cannot fail; if it ever did,
            // running without a permit is better than dropping the work.
            let _permit = permits.acquire_owned().await.ok();
            #[cfg(test)]
            at_the_gate.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            if let Some((_, state)) = &keyed {
                if state
                    .compare_exchange(
                        WAITING,
                        STARTED,
                        std::sync::atomic::Ordering::AcqRel,
                        std::sync::atomic::Ordering::Acquire,
                    )
                    .is_err()
                {
                    // Superseded, settled or cancelled while it waited: nothing is
                    // built, nothing is sent, and the permit goes straight back.
                    return;
                }
            }
            if let Some(outcome) = make().await {
                // The receiver lives as long as the NGAP server; after it is gone
                // there is nobody to apply the outcome to.
                let _ = tx.send(Report::Outcome(outcome));
            }
            if let Some((job, _)) = keyed {
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

    /// Superseded keyed work is never built nor sent; the started one finishes.
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
        // Started: it holds its permit, so supersede leaves it to finish.
        until(|| offload.in_flight() == 1).await;
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
        assert!(offload.settle_key((3, 1), Duration::from_secs(5)).await);
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

    /// Keyed work that records `name` when built and when sent.
    fn recording(
        seen: &Arc<std::sync::Mutex<Vec<String>>>,
        name: &'static str,
    ) -> impl FnOnce() -> std::future::Ready<Option<SbiOutcome>> + Send + 'static {
        let seen = Arc::clone(seen);
        move || {
            seen.lock().expect("seen").push(format!("built {name}"));
            std::future::ready(None)
        }
    }

    /// Occupy the only permit with another UE's exchange until `gate` opens.
    async fn hold_the_permit(offload: &mut SbiOffload, gate: &Arc<Semaphore>) {
        let gate = Arc::clone(gate);
        offload.spawn_keyed((900, 1), move || async move {
            let _ = gate.acquire().await.map(|p| p.forget());
            None
        });
        until(|| offload.in_flight() == 1).await;
    }

    /// #877 re-review M1, the reviewer's reproduction: with every permit taken, a
    /// keyed DEACTIVATED waits for one; it is superseded; the permit is freed.
    /// Nothing is built or sent for it, the key is free at once, and the next
    /// exchange for the key runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_superseded_job_still_waiting_for_a_permit_never_reaches_the_peer() {
        let mut offload = SbiOffload::new(1);
        let gate = Arc::new(Semaphore::new(0));
        hold_the_permit(&mut offload, &gate).await;
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        offload.spawn_keyed((848, 5), recording(&seen, "DEACTIVATED"));
        assert!(offload.key_busy((848, 5)));
        // Parked on the semaphore: this is the reviewer's race, not a task that
        // was never polled.
        until(|| offload.waiting_for_a_permit() == 1).await;

        offload.supersede_key((848, 5));
        assert!(
            !offload.key_busy((848, 5)),
            "nothing for the key has started"
        );

        gate.add_permits(1);
        offload.spawn_keyed((848, 5), recording(&seen, "ACTIVATING"));
        offload.settle().await;
        assert_eq!(*seen.lock().expect("seen"), vec!["built ACTIVATING"]);
        assert_eq!(offload.in_flight(), 0);
    }

    /// `settle_key` on a job that is only waiting for a permit cancels it and
    /// returns at once: it does not wait for the permit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn settle_key_cancels_a_waiting_job_without_waiting_for_a_permit() {
        let mut offload = SbiOffload::new(1);
        let gate = Arc::new(Semaphore::new(0));
        hold_the_permit(&mut offload, &gate).await;
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        offload.spawn_keyed((848, 6), recording(&seen, "DEACTIVATED"));
        until(|| offload.waiting_for_a_permit() == 1).await;

        let started = std::time::Instant::now();
        assert!(offload.settle_key((848, 6), Duration::from_secs(5)).await);
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(!offload.key_busy((848, 6)));

        gate.add_permits(1);
        offload.settle().await;
        assert!(seen.lock().expect("seen").is_empty());
    }

    /// #877 re-review m3: `settle_key` is bounded. A started exchange that never
    /// finishes makes it return `false` after `max_wait`, the work still keyed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn settle_key_is_bounded() {
        let mut offload = SbiOffload::new(4);
        offload.spawn_keyed((848, 7), || async {
            std::future::pending::<()>().await;
            None
        });
        until(|| offload.in_flight() == 1).await;
        let started = std::time::Instant::now();
        assert!(
            !offload
                .settle_key((848, 7), Duration::from_millis(200))
                .await
        );
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(200) && took < Duration::from_secs(2),
            "{took:?}"
        );
        assert!(
            offload.key_busy((848, 7)),
            "the started exchange still holds its key"
        );
        offload.cancel_ue(848);
        offload.settle().await;
    }

    /// Durable work survives `supersede_key` and `cancel_ue`, and runs in its
    /// place in the key's order.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn durable_work_is_never_dropped() {
        let mut offload = SbiOffload::new(1);
        let gate = Arc::new(Semaphore::new(0));
        hold_the_permit(&mut offload, &gate).await;
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        offload.spawn_keyed((850, 5), recording(&seen, "attempt"));
        until(|| offload.waiting_for_a_permit() == 1).await;
        offload.spawn_keyed_durable((850, 5), recording(&seen, "release"));
        offload.spawn_keyed((850, 5), recording(&seen, "later"));
        offload.supersede_key((850, 5));
        offload.spawn_keyed_durable((850, 6), recording(&seen, "release of a gone UE"));
        offload.cancel_ue(850);

        gate.add_permits(1);
        offload.settle().await;
        let mut got = seen.lock().expect("seen").clone();
        got.sort();
        assert_eq!(got, vec!["built release", "built release of a gone UE"]);
    }

    /// #877 re-review M1 / #848's requirement: the abort of a not-yet-started
    /// job and that job starting its exchange are ONE compare-and-swap, so the
    /// race between `supersede_key` and the permit becoming free has exactly
    /// two outcomes and never both.
    ///
    /// 1000 rounds, each releasing the permit and superseding concurrently with
    /// a yield between, so the two land in every interleaving. Either the job
    /// was aborted and NOTHING was built, or it started and built exactly once;
    /// a build after a successful abort (`key_busy` false) is the defect.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn aborting_and_starting_a_job_race_to_one_outcome() {
        let mut aborted_and_built = 0usize;
        let mut aborted = 0usize;
        let mut started = 0usize;
        for round in 0..1000u32 {
            let mut offload = SbiOffload::new(1);
            let hold = Arc::new(Semaphore::new(0));
            hold_the_permit(&mut offload, &hold).await;
            let built = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counter = Arc::clone(&built);
            offload.spawn_keyed((877, 9), move || {
                counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                std::future::ready(None)
            });
            until(|| offload.waiting_for_a_permit() == 1).await;

            // The permit is freed from another task while this one supersedes.
            let release = Arc::clone(&hold);
            let freeing = tokio::spawn(async move {
                release.add_permits(1);
            });
            // A delay that varies with the round, so the supersede lands before
            // the job wakes, while it is waking, and after it has started,
            // across the 1000 rounds. The distribution is asserted below.
            for _ in 0..(round % 4) {
                tokio::task::yield_now().await;
            }
            if round % 4 == 3 {
                tokio::time::sleep(Duration::from_micros(u64::from(round % 400))).await;
            }
            offload.supersede_key((877, 9));
            let was_aborted = !offload.key_busy((877, 9));
            let _ = freeing.await;
            offload.settle().await;

            let builds = built.load(std::sync::atomic::Ordering::Acquire);
            assert!(builds <= 1, "round {round}: built {builds} times");
            if was_aborted {
                aborted += 1;
                if builds > 0 {
                    aborted_and_built += 1;
                }
            } else {
                started += 1;
                assert_eq!(builds, 1, "round {round}: a started job must run its work");
            }
            assert_eq!(offload.in_flight(), 0, "round {round}");
        }
        assert_eq!(
            aborted_and_built, 0,
            "a job reported aborted built its work anyway in {aborted_and_built} of 1000 rounds"
        );
        // Both outcomes must actually occur, or the test is not racing anything.
        // Both outcomes must occur, or the interleavings were not explored.
        assert!(
            aborted > 0 && started > 0,
            "the race was not exercised: aborted {aborted}, started {started} of 1000"
        );
    }
}
