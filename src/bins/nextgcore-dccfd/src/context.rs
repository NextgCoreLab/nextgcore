//! DCCF global context and subscription/analytics-context registry
//!
//! Tracks:
//! - Data subscriptions (consumers subscribing to network events)
//! - Analytics context bindings (pairing subscriptions with analytics consumers)
//! - Fan-out state (which consumer URIs should receive a given notification)

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

/// DCCF process-wide context
struct DccfContext {
    /// Active data subscription IDs (Ndccf_DataManagement)
    subscriptions: HashSet<String>,
    /// Active analytics context IDs (Ndccf_ContextDocument)
    analytics_contexts: HashSet<String>,
    /// Maximum allowed subscriptions
    max_subscriptions: usize,
    /// Total notifications fanned out
    fanout_count: u64,
}

static CONTEXT: OnceLock<Mutex<DccfContext>> = OnceLock::new();

fn ctx() -> &'static Mutex<DccfContext> {
    CONTEXT.get().unwrap_or_default()
}

/// Initialize the DCCF context (call once at startup).
pub fn dccf_context_init(max_subscriptions: usize) {
    CONTEXT.get_or_init(|| {
        Mutex::new(DccfContext {
            subscriptions: HashSet::new(),
            analytics_contexts: HashSet::new(),
            max_subscriptions,
            fanout_count: 0,
        })
    });
}

// ---------------------------------------------------------------------------
// Subscription management (Ndccf_DataManagement_Subscribe)
// ---------------------------------------------------------------------------

/// Registers a new subscription.  Returns false if capacity is exhausted.
pub fn dccf_context_add_subscription(sub_id: String) -> bool {
    let mut c = ctx().lock().unwrap();
    if c.subscriptions.len() >= c.max_subscriptions {
        log::warn!("[DCCF] subscription capacity exhausted ({})", c.max_subscriptions);
        return false;
    }
    c.subscriptions.insert(sub_id);
    true
}

/// Removes a subscription.  Returns true if it existed.
pub fn dccf_context_remove_subscription(sub_id: &str) -> bool {
    ctx().lock().unwrap().subscriptions.remove(sub_id)
}

/// Returns true if the subscription exists.
pub fn dccf_context_has_subscription(sub_id: &str) -> bool {
    ctx().lock().unwrap().subscriptions.contains(sub_id)
}

/// Returns the number of active subscriptions.
pub fn dccf_context_subscription_count() -> usize {
    ctx().lock().unwrap().subscriptions.len()
}

// ---------------------------------------------------------------------------
// Analytics context management (Ndccf_ContextDocument_Create)
// ---------------------------------------------------------------------------

/// Registers an analytics context binding.
pub fn dccf_context_add_analytics_context(ctx_id: String) {
    ctx().lock().unwrap().analytics_contexts.insert(ctx_id);
}

/// Returns true if the analytics context exists.
pub fn dccf_context_has_analytics_context(ctx_id: &str) -> bool {
    ctx().lock().unwrap().analytics_contexts.contains(ctx_id)
}

/// Removes an analytics context binding.
pub fn dccf_context_remove_analytics_context(ctx_id: &str) {
    ctx().lock().unwrap().analytics_contexts.remove(ctx_id);
}

// ---------------------------------------------------------------------------
// Fan-out (Ndccf_DataManagement_Notify)
// ---------------------------------------------------------------------------

/// Fans out a notification body to all registered analytics consumers.
///
/// In a full implementation this would iterate over consumer callback URIs
/// and POST the notification.  Here we log and increment the counter.
pub fn dccf_context_fanout_notify(body: &str) {
    let mut c = ctx().lock().unwrap();
    let subscriber_count = c.subscriptions.len();
    c.fanout_count += subscriber_count as u64;
    log::debug!(
        "[DCCF] fanout: {} subscribers, body_len={}, total_fanout={}",
        subscriber_count,
        body.len(),
        c.fanout_count,
    );
}

/// Returns the total number of notification fan-outs performed.
pub fn dccf_context_fanout_count() -> u64 {
    ctx().lock().unwrap().fanout_count
}

/// Finalize the DCCF context (logs summary stats at shutdown).
pub fn dccf_context_final() {
    if let Some(ctx) = CONTEXT.get() {
        let c = ctx.lock().unwrap();
        log::info!(
            "[DCCF] final stats: subscriptions={} analytics_contexts={} fanout_count={}",
            c.subscriptions.len(),
            c.analytics_contexts.len(),
            c.fanout_count,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        let _ = CONTEXT.get_or_init(|| {
            Mutex::new(DccfContext {
                subscriptions: HashSet::new(),
                analytics_contexts: HashSet::new(),
                max_subscriptions: 16,
                fanout_count: 0,
            })
        });
    }

    #[test]
    fn test_subscription_lifecycle() {
        init();
        dccf_context_add_subscription("sub-1".into());
        assert!(dccf_context_has_subscription("sub-1"));
        assert!(dccf_context_remove_subscription("sub-1"));
        assert!(!dccf_context_has_subscription("sub-1"));
        assert!(!dccf_context_remove_subscription("sub-1")); // already gone
    }

    #[test]
    fn test_analytics_context_lifecycle() {
        init();
        dccf_context_add_analytics_context("ctx-1".into());
        assert!(dccf_context_has_analytics_context("ctx-1"));
        dccf_context_remove_analytics_context("ctx-1");
        assert!(!dccf_context_has_analytics_context("ctx-1"));
    }

    #[test]
    fn test_fanout_increments_by_subscriber_count() {
        init();
        // Reset by starting fresh (can't reset OnceLock in tests cleanly; use stable count)
        let before = dccf_context_fanout_count();
        dccf_context_add_subscription("sub-a".into());
        dccf_context_add_subscription("sub-b".into());
        dccf_context_fanout_notify("{}");
        let after = dccf_context_fanout_count();
        // Should have incremented by at least 2 (may be more if other tests added subs)
        assert!(after >= before + 2);
    }
}
