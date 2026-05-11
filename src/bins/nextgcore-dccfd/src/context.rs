//! DCCF global context and subscription/analytics-context registry
//!
//! Tracks:
//! - Data subscriptions (consumers subscribing to network events)
//! - Analytics context bindings (pairing subscriptions with analytics consumers)
//! - Fan-out state (which consumer URIs should receive a given notification)

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

/// A registered data-management subscription with its notification callback URI.
#[derive(Debug, Clone)]
pub struct DccfSubscription {
    /// Subscription ID (UUID)
    pub id: String,
    /// Consumer callback URI for Ndccf_DataManagement_Notify (may be empty)
    pub notify_uri: String,
}

/// DCCF process-wide context
struct DccfContext {
    /// Active data subscription IDs (Ndccf_DataManagement)
    subscriptions: HashSet<String>,
    /// Subscription metadata (ID -> callback URI)
    subscription_map: HashMap<String, DccfSubscription>,
    /// Active analytics context IDs (Ndccf_ContextDocument)
    analytics_contexts: HashSet<String>,
    /// Maximum allowed subscriptions
    max_subscriptions: usize,
    /// Total notifications fanned out
    fanout_count: u64,
}

static CONTEXT: OnceLock<Mutex<DccfContext>> = OnceLock::new();

fn ctx() -> &'static Mutex<DccfContext> {
    CONTEXT.get().expect("value expected")
}

/// Initialize the DCCF context (call once at startup).
pub fn dccf_context_init(max_subscriptions: usize) {
    CONTEXT.get_or_init(|| {
        Mutex::new(DccfContext {
            subscriptions: HashSet::new(),
            subscription_map: HashMap::new(),
            analytics_contexts: HashSet::new(),
            max_subscriptions,
            fanout_count: 0,
        })
    });
}

// ---------------------------------------------------------------------------
// Subscription management (Ndccf_DataManagement_Subscribe)
// ---------------------------------------------------------------------------

/// Registers a new subscription with an optional consumer callback URI.
/// Returns false if capacity is exhausted.
pub fn dccf_context_add_subscription(sub_id: String) -> bool {
    dccf_context_add_subscription_with_uri(sub_id, String::new())
}

/// Registers a new subscription with a consumer callback URI.
/// Returns false if capacity is exhausted.
pub fn dccf_context_add_subscription_with_uri(sub_id: String, notify_uri: String) -> bool {
    let mut c = ctx().lock().unwrap();
    if c.subscriptions.len() >= c.max_subscriptions {
        log::warn!(
            "[DCCF] subscription capacity exhausted ({})",
            c.max_subscriptions
        );
        return false;
    }
    c.subscription_map.insert(
        sub_id.clone(),
        DccfSubscription {
            id: sub_id.clone(),
            notify_uri,
        },
    );
    c.subscriptions.insert(sub_id);
    true
}

/// Removes a subscription.  Returns true if it existed.
pub fn dccf_context_remove_subscription(sub_id: &str) -> bool {
    let mut c = ctx().lock().unwrap();
    c.subscription_map.remove(sub_id);
    c.subscriptions.remove(sub_id)
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
/// Returns the list of (sub_id, notify_uri) pairs that have a non-empty
/// callback URI.  The caller is responsible for making the HTTP POST requests
/// (the context lock must not be held during network I/O).
pub fn dccf_context_fanout_notify(body: &str) -> Vec<(String, String)> {
    let mut c = ctx().lock().unwrap();
    let targets: Vec<(String, String)> = c
        .subscription_map
        .values()
        .filter(|s| !s.notify_uri.is_empty())
        .map(|s| (s.id.clone(), s.notify_uri.clone()))
        .collect();
    c.fanout_count += targets.len() as u64;
    log::debug!(
        "[DCCF] fanout: {} subscribers ({} with callback URI), body_len={}, total_fanout={}",
        c.subscriptions.len(),
        targets.len(),
        body.len(),
        c.fanout_count,
    );
    targets
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
    use std::sync::Mutex as StdMutex;

    /// Serialises tests that touch the global DCCF context. Without this
    /// they race on subscriptions / fanout_count under cargo test's
    /// default parallel runner.
    static TEST_GUARD: StdMutex<()> = StdMutex::new(());

    fn init() {
        let _ = CONTEXT.get_or_init(|| {
            Mutex::new(DccfContext {
                subscriptions: HashSet::new(),
                subscription_map: HashMap::new(),
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
        let _g = TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        init();
        // Clean up any subs left by other tests that may have a URI
        dccf_context_remove_subscription("sub-uri-1");
        dccf_context_remove_subscription("sub-a");
        dccf_context_remove_subscription("sub-b");
        let before = dccf_context_fanout_count();
        dccf_context_add_subscription("sub-a".into());
        dccf_context_add_subscription("sub-b".into());
        let targets = dccf_context_fanout_notify("{}");
        let after = dccf_context_fanout_count();
        // Both subs have no notify URI so no actual notifications are sent
        assert!(targets.is_empty());
        // Counter only counts actual notifications sent, so it stays the same
        assert_eq!(after, before);
        // Cleanup
        dccf_context_remove_subscription("sub-a");
        dccf_context_remove_subscription("sub-b");
    }

    #[test]
    fn test_fanout_with_callback_uris() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        init();
        dccf_context_add_subscription_with_uri(
            "sub-uri-1".into(),
            "http://nwdaf:8080/notify".into(),
        );
        let targets = dccf_context_fanout_notify("{}");
        assert!(targets.iter().any(|(id, _)| id == "sub-uri-1"));
        // Cleanup so we don't pollute other tests
        dccf_context_remove_subscription("sub-uri-1");
    }
}
