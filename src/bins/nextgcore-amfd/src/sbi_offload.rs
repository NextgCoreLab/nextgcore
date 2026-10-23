//! SBI work taken off the NGAP task (#796 review M1, shared with #848).
//!
//! The NGAP task serves every gNB. An SBI request it awaits holds all of N2 for
//! as long as the peer takes, and against an address that drops connection
//! attempts (a stale pod IP, a lost node) that is the client's connect timeout
//! per request. So the NGAP task never awaits such a request: it spawns it here,
//! with bounded concurrency, and the result comes back as an [`SbiOutcome`] that
//! `NgapServer::poll` applies on the NGAP task, where every write of its state
//! happens.

use std::future::Future;
use std::sync::Arc;

use tokio::sync::{mpsc, Semaphore};

/// The result of one off-task SBI exchange, applied on the NGAP task. Each
/// feature that offloads adds its variant.
#[derive(Debug)]
pub(crate) enum SbiOutcome {
    /// #796: a re-selection attempt for a waiting PDU Session Establishment.
    Establishment(crate::ngap_path::EstablishmentAttempt),
    /// #754: an NG Reset's deferred DEACTIVATED for one PDU session has run.
    NgResetDeactivated {
        token: std::sync::Arc<crate::ngap_path::DeferredDeactivation>,
    },
}

/// Spawner of off-task SBI work, owned by the NGAP server.
pub(crate) struct SbiOffload {
    tx: mpsc::UnboundedSender<SbiOutcome>,
    rx: mpsc::UnboundedReceiver<SbiOutcome>,
    permits: Arc<Semaphore>,
    max_in_flight: usize,
    /// Spawned and not yet finished, permit or not (for [`SbiOffload::settle`]).
    #[cfg(test)]
    spawned: Arc<std::sync::atomic::AtomicUsize>,
}

impl std::fmt::Debug for SbiOffload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SbiOffload")
            .field("in_flight", &self.in_flight())
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
            #[cfg(test)]
            spawned: Arc::default(),
        }
    }

    /// Run `fut` on its own task. Its outcome, if any, is queued for
    /// [`SbiOffload::try_recv`]. The caller never awaits.
    pub(crate) fn spawn<F>(&self, fut: F)
    where
        F: Future<Output = Option<SbiOutcome>> + Send + 'static,
    {
        let tx = self.tx.clone();
        let permits = Arc::clone(&self.permits);
        #[cfg(test)]
        let spawned = {
            self.spawned
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            Arc::clone(&self.spawned)
        };
        tokio::spawn(async move {
            // The semaphore is never closed, so this cannot fail; if it ever did,
            // running without a permit is better than dropping the work.
            let _permit = permits.acquire_owned().await.ok();
            if let Some(outcome) = fut.await {
                // The receiver lives as long as the NGAP server; after it is gone
                // there is nobody to apply the outcome to.
                let _ = tx.send(outcome);
            }
            #[cfg(test)]
            spawned.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        });
    }

    /// Tests: wait until every spawned exchange has finished (its outcome, if
    /// any, is then queued). Panics after 10 s.
    #[cfg(test)]
    pub(crate) async fn settle(&self) {
        for _ in 0..2000 {
            if self.spawned.load(std::sync::atomic::Ordering::Acquire) == 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("off-task SBI work did not finish within 10 s");
    }

    /// The next outcome ready to apply, without waiting.
    pub(crate) fn try_recv(&mut self) -> Option<SbiOutcome> {
        self.rx.try_recv().ok()
    }

    /// How many exchanges hold a permit right now.
    pub(crate) fn in_flight(&self) -> usize {
        self.max_in_flight - self.permits.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Work beyond the bound waits for a permit in its own task; the caller of
    /// `spawn` is never held, and every outcome arrives.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawn_never_waits_and_bounds_the_work_in_flight() {
        let mut offload = SbiOffload::new(2);
        let gate = Arc::new(tokio::sync::Notify::new());
        let started = std::time::Instant::now();
        for _ in 0..5 {
            let gate = Arc::clone(&gate);
            offload.spawn(async move {
                gate.notified().await;
                None
            });
        }
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        for _ in 0..100 {
            if offload.in_flight() == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(offload.in_flight(), 2, "only two run at once");
        for _ in 0..5 {
            gate.notify_one();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        for _ in 0..100 {
            if offload.in_flight() == 0 {
                break;
            }
            gate.notify_waiters();
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(offload.in_flight(), 0);
        offload.settle().await;
        assert!(offload.try_recv().is_none(), "None outcomes queue nothing");
        offload.spawn(async { None });
        offload.settle().await;
    }
}
