//! #1877: the reconciler for BSF binding deregistrations that failed.
//!
//! A deleted (or replaced) SM policy owes the BSF a deregistration of its PCF
//! binding (Nbsf_Management_Deregister, TS 29.521 §5.2.2.3), and so does a binding
//! whose 201 landed after its policy was gone. It was tried once and only logged,
//! so a BSF that was down for a moment kept a binding pointing at this PCF for a
//! session that no longer exists, and kept answering discovery with it. Now a
//! deregistration that fails is parked here and retried every [`RECONCILE_PERIOD`]
//! until the BSF answers 2xx or 404. Same shape as #1817's and smfd #1875's.
//!
//! Bounded at [`MAX_PENDING`] (the oldest evicted, counted `abandoned`); a pass
//! sends for at most [`MAX_PASS`]. Memory-only: a binding id parked before a
//! restart is lost with it.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

/// Records parked before the oldest is abandoned.
pub const MAX_PENDING: usize = 4096;

/// How often a parked deregistration is retried.
#[cfg(not(test))]
pub const RECONCILE_PERIOD: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const RECONCILE_PERIOD: Duration = Duration::from_millis(20);

/// The longest one pass sends for.
pub const MAX_PASS: Duration = Duration::from_secs(30);

/// `pcf_bsf_deregistrations_reconciled_total{result}`: parked deregistrations the
/// reconciler ended, `delivered` (2xx or 404) or `abandoned` (evicted).
pub static RECONCILED: nextgcore_metrics::nf::CounterFamily =
    nextgcore_metrics::nf::CounterFamily::new(
        "pcf_bsf_deregistrations_reconciled_total",
        "Nbsf_Management deregistrations that failed and were parked, by how the \
         reconciler ended them",
        &["result"],
    );

/// The parked binding ids, oldest first.
///
/// Tests that read or write it hold `crate::test_support::CONTEXT_GUARD`, the lock
/// beside the PCF's process-global state this set belongs to, and assert on their
/// own binding ids: any test whose SM policy delete meets an unreachable BSF parks
/// into it.
fn pending() -> &'static Mutex<VecDeque<String>> {
    static PENDING: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
    &PENDING
}

/// Whether `binding_id` is parked (tests).
#[cfg(test)]
pub fn is_parked(binding_id: &str) -> bool {
    lock().iter().any(|b| b == binding_id)
}

fn lock() -> std::sync::MutexGuard<'static, VecDeque<String>> {
    pending().lock().unwrap_or_else(|e| e.into_inner())
}

fn evict(set: &mut VecDeque<String>) {
    while set.len() > MAX_PENDING {
        if let Some(old) = set.pop_front() {
            log::error!(
                "BSF deregistration of binding {old} abandoned: {MAX_PENDING} are already pending"
            );
            RECONCILED.inc(&["abandoned"]);
        }
    }
}

/// Park a deregistration that failed. One already parked is not added twice.
pub fn park(binding_id: &str) {
    let mut set = lock();
    if set.iter().any(|b| b == binding_id) {
        return;
    }
    log::warn!(
        "BSF deregistration of binding {binding_id} failed; parked, retried every \
         {RECONCILE_PERIOD:?}"
    );
    set.push_back(binding_id.to_string());
    evict(&mut set);
}

/// How many deregistrations are parked.
pub fn pending_count() -> usize {
    lock().len()
}

/// Forget every parked deregistration (tests).
#[cfg(test)]
pub fn clear_for_test() {
    lock().clear();
}

/// One pass over the parked deregistrations. Returns how many ended.
pub async fn reconcile_once() -> usize {
    let batch: Vec<String> = lock().drain(..).collect();
    let deadline = tokio::time::Instant::now() + MAX_PASS;
    let mut ended = 0;
    let mut still = Vec::new();
    for id in batch {
        let delivered = tokio::time::Instant::now() < deadline
            && matches!(
                crate::sbi_path::pcf_deregister_bsf_binding(&id).await,
                Ok(true)
            );
        if delivered {
            log::info!("BSF binding {id}: deregistration reconciled");
            RECONCILED.inc(&["delivered"]);
            ended += 1;
        } else {
            still.push(id);
        }
    }
    let mut set = lock();
    for id in still.into_iter().rev() {
        if !set.contains(&id) {
            set.push_front(id);
        }
    }
    evict(&mut set);
    ended
}

/// Run [`reconcile_once`] every [`RECONCILE_PERIOD`] for the life of the process.
pub fn spawn_reconciler() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {
        let mut timer = tokio::time::interval(RECONCILE_PERIOD);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        timer.tick().await;
        loop {
            timer.tick().await;
            reconcile_once().await;
        }
    })
}

/// The reconciler's families, for `/metrics`.
pub fn render(out: &mut String) {
    use std::fmt::Write as _;
    nextgcore_metrics::nf::write_header(
        out,
        "pcf_bsf_deregistrations_pending",
        "gauge",
        "Nbsf_Management deregistrations parked for the reconciler",
    );
    let _ = writeln!(out, "pcf_bsf_deregistrations_pending {}", pending_count());
    RECONCILED.render(out);
}
