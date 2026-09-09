//! DCCF global context and subscription/analytics-context registry
//!
//! Tracks:
//! - Data subscriptions (consumers subscribing to network events)
//! - Analytics context bindings (pairing subscriptions with analytics consumers)
//! - Fan-out state (which consumer URIs should receive a given notification)

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

use crate::data_mgmt::{DataManagementSubsc, SubscriptionScope};

/// A registered data-management subscription (#112).
///
/// Before this it was `(id, notify_uri)` and nothing else: the correlation id was
/// never stored, and neither was what the consumer had actually subscribed TO —
/// which is why the fan-out could not be keyed on anything.
#[derive(Debug, Clone)]
pub struct DccfSubscription {
    /// Subscription ID (UUID), the resource key.
    pub id: String,
    /// Consumer callback URI (`notificURI`). Non-empty by construction: the
    /// handler refuses a subscription without one.
    pub notify_uri: String,
    /// `notifCorrId`, echoed on every notification delivered to this consumer so
    /// it can correlate. Previously not parsed anywhere in the crate.
    pub notif_corr_id: String,
    /// What this subscription covers — the fan-out key.
    pub scope: SubscriptionScope,
    /// The subscription resource as received, echoed on `201`, `GET` and `PUT`.
    /// Stored rather than re-synthesised so the echo cannot drift from what the
    /// consumer sent.
    pub resource: DataManagementSubsc,
}

/// A producer `EventExposure` subscription the DCCF created on consumers' behalf
/// (#112, TS 23.288 §5A.2 — the coordination the DCCF exists to perform).
#[derive(Debug, Clone)]
pub struct ProducerSubscription {
    /// The `(events, target)` scope this producer subscription covers. Two
    /// consumers with the same scope share one producer subscription, which is
    /// the de-duplication that reduces producer load.
    pub scope: SubscriptionScope,
    /// Producer NF instance the subscription was created on.
    pub producer_id: String,
    /// Resource URI returned by the producer, used to delete it later.
    pub resource_uri: String,
    /// Consumer subscription ids currently relying on it. The producer
    /// subscription is removed when this empties — refcounting, so one
    /// consumer's unsubscribe cannot cut off another's data.
    pub consumers: HashSet<String>,
}

/// DCCF process-wide context
struct DccfContext {
    /// Active data subscription IDs (Ndccf_DataManagement)
    subscriptions: HashSet<String>,
    /// Subscription metadata (ID -> callback URI)
    subscription_map: HashMap<String, DccfSubscription>,
    /// Active analytics context IDs (Ndccf_ContextDocument)
    analytics_contexts: HashSet<String>,
    /// Producer subscriptions the DCCF holds on consumers' behalf, keyed by a
    /// canonical form of their scope (#112).
    producer_subs: HashMap<String, ProducerSubscription>,
    /// Maximum allowed subscriptions
    max_subscriptions: usize,
    /// Total notifications fanned out
    fanout_count: u64,
}

static CONTEXT: OnceLock<Mutex<DccfContext>> = OnceLock::new();

/// The ONE lock serialising every test that touches process-global DCCF state
/// (#112).
///
/// This module and `main.rs`'s `data_management_tests` both mutate the same
/// `CONTEXT` singleton — the subscription map, the producer-subscription registry
/// and `fanout_count`. They previously had a private guard each, which is two
/// disjoint agreements about the same variable: `data_management_tests` clears the
/// subscription map between cases and would do so while a `context::tests` case
/// held a subscription it was about to assert on. One green run proved nothing;
/// the failure was order-dependent.
///
/// A single lock is the fix, not a second one. `unwrap_or_else(|e| e.into_inner())`
/// at every acquisition, so one panicking test does not poison the rest.
pub static GLOBAL_TEST_LOCK: Mutex<()> = Mutex::new(());

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
            producer_subs: HashMap::new(),
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
///
/// Kept for the `Ndccf_ContextDocument` side and the pre-#112 tests. A
/// subscription registered this way has an EMPTY scope, so it receives nothing
/// from the keyed fan-out — see [`dccf_context_fanout_notify`].
pub fn dccf_context_add_subscription_with_uri(sub_id: String, notify_uri: String) -> bool {
    dccf_context_store_subscription(DccfSubscription {
        id: sub_id,
        notify_uri,
        notif_corr_id: String::new(),
        scope: SubscriptionScope::default(),
        resource: DataManagementSubsc::default(),
    })
}

/// Store a fully-populated subscription record (#112). Returns false when
/// capacity is exhausted; replaces an existing record with the same id, which is
/// what `PUT` needs.
pub fn dccf_context_store_subscription(sub: DccfSubscription) -> bool {
    let mut c = ctx().lock().unwrap();
    let replacing = c.subscriptions.contains(&sub.id);
    if !replacing && c.subscriptions.len() >= c.max_subscriptions {
        log::warn!(
            "[DCCF] subscription capacity exhausted ({})",
            c.max_subscriptions
        );
        return false;
    }
    if sub.scope.events.is_empty() {
        // Not an error -- the schema permits a `dataSub` shape whose event scope
        // this DCCF cannot determine -- but it IS the reason such a consumer
        // receives nothing, so it must be visible rather than silent. Delivering
        // to it anyway is the cross-consumer disclosure defect #112 names.
        log::warn!(
            "[DCCF] subscription {} has no determinable event scope: it will receive NO \
             notifications. Supply anaSub.eventSubscriptions[].event, or a dataSub carrying an \
             event identifier.",
            sub.id
        );
    }
    c.subscription_map.insert(sub.id.clone(), sub.clone());
    c.subscriptions.insert(sub.id);
    true
}

/// The stored record for a subscription id.
pub fn dccf_context_get_subscription(sub_id: &str) -> Option<DccfSubscription> {
    ctx().lock().unwrap().subscription_map.get(sub_id).cloned()
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

/// Every active subscription id.
///
/// Exists so a test can clear the process-global registry between cases: the
/// context is a `OnceLock`, so one instance is shared across the whole test
/// binary and a stale subscription from a sibling test changes another test's
/// fan-out count.
pub fn dccf_context_subscription_ids() -> Vec<String> {
    ctx()
        .lock()
        .unwrap()
        .subscriptions
        .iter()
        .cloned()
        .collect()
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

/// Fans out a notification to the consumers whose scope MATCHES it (#112).
///
/// Returns `(sub_id, notify_uri, notif_corr_id)` per matching consumer; the
/// caller performs the POSTs, because the context lock must not be held across
/// network I/O.
///
/// This used to return every subscription with a non-empty callback URI,
/// regardless of what it had subscribed to — so any consumer that got a URI
/// stored received every other consumer's collected data. Matching is now on
/// `(events, target)`; see [`SubscriptionScope::matches`] for the rules, including
/// why an indeterminate scope matches nothing rather than everything.
///
/// `notif_corr_id` is returned alongside because each consumer's notification
/// must echo ITS OWN correlation id — one broadcast body cannot serve them all.
pub fn dccf_context_fanout_notify_scoped(
    notif_scope: &SubscriptionScope,
) -> Vec<(String, String, String)> {
    let mut c = ctx().lock().unwrap();
    let total = c.subscription_map.len();
    let targets: Vec<(String, String, String)> = c
        .subscription_map
        .values()
        .filter(|s| !s.notify_uri.is_empty() && s.scope.matches(notif_scope))
        .map(|s| (s.id.clone(), s.notify_uri.clone(), s.notif_corr_id.clone()))
        .collect();
    c.fanout_count += targets.len() as u64;
    log::debug!(
        "[DCCF] fanout: {}/{} subscribers matched events={:?} target={:?}, total_fanout={}",
        targets.len(),
        total,
        notif_scope.events,
        notif_scope.target,
        c.fanout_count,
    );
    targets
}

/// Pre-#112 unkeyed fan-out, retained only for the `Ndccf_ContextDocument`
/// tests that predate scoping. Returns every subscriber with a callback URI.
///
/// Not used by the `Ndccf_DataManagement` notify path any more — that is
/// [`dccf_context_fanout_notify_scoped`]. Left as `cfg(test)` so it cannot be
/// reintroduced into production by accident.
#[cfg(test)]
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

// ---------------------------------------------------------------------------
// #112: producer-subscription coordination (TS 23.288 §5A.2)
// ---------------------------------------------------------------------------

/// Canonical key for a scope, so two consumers asking for the same
/// `(events, target)` map to one producer subscription.
///
/// The events are a `BTreeSet`, so the key is order-independent: two consumers
/// naming the same events in a different order must share, not duplicate.
pub fn scope_key(scope: &SubscriptionScope) -> String {
    format!(
        "{}|{}",
        scope.events.iter().cloned().collect::<Vec<_>>().join(","),
        scope.target.as_deref().unwrap_or("")
    )
}

/// Outcome of claiming a producer subscription for a consumer.
#[derive(Debug, PartialEq, Eq)]
pub enum ProducerClaim {
    /// An existing producer subscription covers this scope; it was reused and no
    /// producer signalling is needed. This is the de-duplication.
    Reused {
        /// The producer NF instance already subscribed to.
        producer_id: String,
    },
    /// No producer subscription covers this scope; the caller must create one and
    /// then record it with [`dccf_context_record_producer_sub`].
    NeedsCreate,
}

/// Claim a producer subscription for `consumer_id` at `scope`.
pub fn dccf_context_claim_producer_sub(
    consumer_id: &str,
    scope: &SubscriptionScope,
) -> ProducerClaim {
    let key = scope_key(scope);
    let mut c = ctx().lock().unwrap();
    match c.producer_subs.get_mut(&key) {
        Some(existing) => {
            existing.consumers.insert(consumer_id.to_string());
            log::info!(
                "[DCCF] reusing producer subscription on {} for scope {key} ({} consumers)",
                existing.producer_id,
                existing.consumers.len()
            );
            ProducerClaim::Reused {
                producer_id: existing.producer_id.clone(),
            }
        }
        None => ProducerClaim::NeedsCreate,
    }
}

/// Record a producer subscription the caller has just created.
pub fn dccf_context_record_producer_sub(
    consumer_id: &str,
    scope: SubscriptionScope,
    producer_id: String,
    resource_uri: String,
) {
    let key = scope_key(&scope);
    let mut c = ctx().lock().unwrap();
    let entry = c.producer_subs.entry(key.clone()).or_insert_with(|| {
        log::info!("[DCCF] created producer subscription on {producer_id} for scope {key}");
        ProducerSubscription {
            scope,
            producer_id,
            resource_uri,
            consumers: HashSet::new(),
        }
    });
    entry.consumers.insert(consumer_id.to_string());
}

/// Release a consumer's claim. Returns the producer subscription to DELETE when
/// this was its last consumer — refcounted, so one consumer's unsubscribe cannot
/// cut off another's data.
pub fn dccf_context_release_producer_sub(consumer_id: &str) -> Option<ProducerSubscription> {
    let mut c = ctx().lock().unwrap();
    let mut orphaned_key = None;
    for (key, sub) in c.producer_subs.iter_mut() {
        if sub.consumers.remove(consumer_id) && sub.consumers.is_empty() {
            orphaned_key = Some(key.clone());
            break;
        }
    }
    let key = orphaned_key?;
    let removed = c.producer_subs.remove(&key);
    if let Some(sub) = &removed {
        log::info!(
            "[DCCF] last consumer for scope {key} released; deleting producer subscription {}",
            sub.resource_uri
        );
    }
    removed
}

/// How many producer subscriptions the DCCF currently holds. The de-duplication
/// assertion: two overlapping consumers must leave this at 1.
pub fn dccf_context_producer_sub_count() -> usize {
    ctx().lock().unwrap().producer_subs.len()
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

    /// Serialises tests that touch the global DCCF context. Without this they
    /// race on subscriptions / fanout_count under cargo test's default parallel
    /// runner.
    ///
    /// #112: this is now the CRATE-WIDE lock, shared with `main.rs`'s
    /// `data_management_tests`, which also mutates the same singleton. A guard
    /// private to this module did not cover that.
    use super::GLOBAL_TEST_LOCK as TEST_GUARD;

    fn init() {
        let _ = CONTEXT.get_or_init(|| {
            Mutex::new(DccfContext {
                subscriptions: HashSet::new(),
                subscription_map: HashMap::new(),
                analytics_contexts: HashSet::new(),
                producer_subs: HashMap::new(),
                max_subscriptions: 16,
                fanout_count: 0,
            })
        });
    }

    #[test]
    fn test_subscription_lifecycle() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        init();
        dccf_context_add_subscription("sub-1".into());
        assert!(dccf_context_has_subscription("sub-1"));
        assert!(dccf_context_remove_subscription("sub-1"));
        assert!(!dccf_context_has_subscription("sub-1"));
        assert!(!dccf_context_remove_subscription("sub-1")); // already gone
    }

    #[test]
    fn test_analytics_context_lifecycle() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
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
