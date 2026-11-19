//! DCCF global context and subscription/analytics-context registry
//!
//! Tracks:
//! - Data subscriptions (consumers subscribing to network events)
//! - Analytics context bindings (pairing subscriptions with analytics consumers)
//! - Fan-out state (which consumer URIs should receive a given notification)

use nextgcore_sbi::callback_auth::CallbackToken;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// #1909: the verified NF Instance ID of the consumer that created the
    /// subscription (`nextgcore_sbi::owner_binding`), the only one that may
    /// read, replace or delete it. Never the self-declared `nfId`. `None` when
    /// created with no verified identity (`dev`). In memory only.
    pub owner: Option<String>,
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
    /// Resource URI returned by the producer, used to delete it later. `None`
    /// while the create is in flight.
    pub resource_uri: Option<String>,
    /// The token in the `notificationURI` handed to the producer (#1518): only a
    /// notification presenting it is fanned out, and only to this subscription's
    /// consumers.
    pub notify_token: CallbackToken,
    /// Which claim created this entry (#1747 review): a late record or abandon of an
    /// earlier claim of the same scope never acts on it.
    pub claim_seq: u64,
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
    /// Active analytics context IDs (Ndccf_ContextDocument) -> the verified
    /// consumer that created it (#1909), `None` when created anonymously (`dev`).
    analytics_contexts: HashMap<String, Option<String>>,
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
/// It also guards the process-global coordination switch, `coordination.rs`'s
/// `COORDINATION_ENABLED` and `COORDINATION_CONFIG`, which tests flip with
/// `coordination::set_coordination_for_test` (#1785, #1822 item 3): the
/// data-management tests switch coordination on under this lock, and
/// `coordination_is_off_by_default` switched it off without the lock, mid-way
/// through their coordination. `set_coordination_for_test` panics when this lock
/// is free.
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
            analytics_contexts: HashMap::new(),
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
        owner: None,
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
#[cfg(test)]
pub fn dccf_context_add_analytics_context(ctx_id: String) {
    dccf_context_add_analytics_context_owned(ctx_id, None);
}

/// Registers an analytics context binding created by `owner` (#1909).
pub fn dccf_context_add_analytics_context_owned(ctx_id: String, owner: Option<String>) {
    ctx()
        .lock()
        .unwrap()
        .analytics_contexts
        .insert(ctx_id, owner);
}

/// Returns true if the analytics context exists.
pub fn dccf_context_has_analytics_context(ctx_id: &str) -> bool {
    ctx()
        .lock()
        .unwrap()
        .analytics_contexts
        .contains_key(ctx_id)
}

/// The consumer an analytics context was created by: `None` when it does not
/// exist, `Some(owner)` when it does (#1909).
pub fn dccf_context_analytics_context_owner(ctx_id: &str) -> Option<Option<String>> {
    ctx()
        .lock()
        .unwrap()
        .analytics_contexts
        .get(ctx_id)
        .cloned()
}

/// Removes an analytics context binding.
pub fn dccf_context_remove_analytics_context(ctx_id: &str) {
    ctx().lock().unwrap().analytics_contexts.remove(ctx_id);
}

// ---------------------------------------------------------------------------
// Fan-out (Ndccf_DataManagement_Notify)
// ---------------------------------------------------------------------------

// The notify path fans out with [`dccf_context_fanout_for_token`], below.

/// Pre-#112 unkeyed fan-out, retained only for the `Ndccf_ContextDocument`
/// tests that predate scoping. Returns every subscriber with a callback URI.
///
/// Not used by the `Ndccf_DataManagement` notify path any more — that is
/// [`dccf_context_fanout_for_token`]. Left as `cfg(test)` so it cannot be
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
#[derive(Debug)]
pub enum ProducerClaim {
    /// An existing producer subscription covers this scope (created, or being
    /// created); it was reused and no producer signalling is needed. This is the
    /// de-duplication.
    Reused {
        /// The producer NF instance already subscribed to.
        producer_id: String,
    },
    /// No producer subscription covered this scope. One is now held in flight for
    /// it, with this token (#1518), so a concurrent claim for the same scope reuses
    /// it rather than creating a second, and the producer's first notification is
    /// admitted even before its 201 arrives. The caller creates it and then calls
    /// [`dccf_context_record_producer_sub`], or [`dccf_context_abandon_producer_sub`]
    /// on failure.
    NeedsCreate {
        /// The token for the subscription's `notificationURI`.
        notify_token: CallbackToken,
        /// This claim, for [`dccf_context_record_producer_sub`] and
        /// [`dccf_context_abandon_producer_sub`].
        claim_seq: u64,
    },
    /// No producer subscription covers this scope and the consumer named no
    /// producer, so none can be created without guessing one.
    NoProducer,
}

/// Claim a producer subscription for `consumer_id` at `scope`, to be created on
/// `producer_id` when none covers the scope yet.
pub fn dccf_context_claim_producer_sub(
    consumer_id: &str,
    scope: &SubscriptionScope,
    producer_id: Option<&str>,
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
        None => {
            let Some(producer_id) = producer_id else {
                return ProducerClaim::NoProducer;
            };
            let notify_token = CallbackToken::mint();
            let claim_seq = CLAIM_SEQ.fetch_add(1, Ordering::Relaxed);
            c.producer_subs.insert(
                key,
                ProducerSubscription {
                    scope: scope.clone(),
                    producer_id: producer_id.to_string(),
                    resource_uri: None,
                    notify_token: notify_token.clone(),
                    claim_seq,
                    consumers: HashSet::from([consumer_id.to_string()]),
                },
            );
            ProducerClaim::NeedsCreate {
                notify_token,
                claim_seq,
            }
        }
    }
}

/// Record that the producer created the subscription claim `claim_seq` made for
/// `scope`. `false` when that claim is no longer held (its every consumer left
/// while the create was in flight, or a later claim of the scope replaced it): the
/// caller then deletes it at the producer.
pub fn dccf_context_record_producer_sub(
    scope: &SubscriptionScope,
    claim_seq: u64,
    resource_uri: String,
) -> bool {
    let key = scope_key(scope);
    let mut c = ctx().lock().unwrap();
    match c.producer_subs.get_mut(&key) {
        Some(entry) if entry.claim_seq == claim_seq && entry.resource_uri.is_none() => {
            log::info!(
                "[DCCF] created producer subscription on {} for scope {key}",
                entry.producer_id
            );
            entry.resource_uri = Some(resource_uri);
            true
        }
        _ => false,
    }
}

/// The create of claim `claim_seq` for `scope` failed or was cancelled: forget the
/// entry, its token with it, if it is still that claim's and still in flight. Its
/// consumers keep their own subscriptions, but no producer data comes for them
/// until a later consumer's claim of the scope creates one (a Limit). Returns the
/// consumer ids that relied on it.
pub fn dccf_context_abandon_producer_sub(scope: &SubscriptionScope, claim_seq: u64) -> Vec<String> {
    let key = scope_key(scope);
    let mut c = ctx().lock().unwrap();
    let ours = c
        .producer_subs
        .get(&key)
        .is_some_and(|e| e.claim_seq == claim_seq && e.resource_uri.is_none());
    if !ours {
        return Vec::new();
    }
    c.producer_subs
        .remove(&key)
        .map(|e| e.consumers.into_iter().collect())
        .unwrap_or_default()
}

/// Whether a producer subscription, created or in flight, covers `scope`.
pub fn dccf_context_holds_producer_sub(scope: &SubscriptionScope) -> bool {
    ctx()
        .lock()
        .unwrap()
        .producer_subs
        .contains_key(&scope_key(scope))
}

/// Claim sequence numbers (#1747 review).
static CLAIM_SEQ: AtomicU64 = AtomicU64::new(1);

/// The consumer subscriptions a producer notification presented on `token` is
/// for (#1518): those of the producer subscription holding it, created or in
/// flight, that the notification's scope matches. `None` when no producer
/// subscription holds `token`. Each entry is `(id, notificURI, notifCorrId)`;
/// the caller performs the POSTs, because the context lock must not be held
/// across network I/O.
///
/// Matching is on `(events, target)` (#112); see [`SubscriptionScope::matches`]
/// for the rules, including why an indeterminate scope matches nothing. Before
/// #1518 any notification on the one token-less URI reached every consumer whose
/// scope it matched, whoever sent it. `notif_corr_id` is returned because each
/// consumer's notification must echo ITS OWN correlation id.
pub fn dccf_context_fanout_for_token(
    token: &str,
    notif_scope: &SubscriptionScope,
) -> Option<Vec<(String, String, String)>> {
    let mut c = ctx().lock().unwrap();
    // Every entry is compared, in constant time.
    let mut consumers = None;
    for p in c.producer_subs.values() {
        if p.notify_token.matches(token) {
            consumers = Some(p.consumers.clone());
        }
    }
    let consumers = consumers?;
    let targets: Vec<(String, String, String)> = c
        .subscription_map
        .values()
        .filter(|s| {
            consumers.contains(&s.id) && !s.notify_uri.is_empty() && s.scope.matches(notif_scope)
        })
        .map(|s| (s.id.clone(), s.notify_uri.clone(), s.notif_corr_id.clone()))
        .collect();
    c.fanout_count += targets.len() as u64;
    Some(targets)
}

/// The producer NF instance of the producer subscription holding `token` (#1518).
pub fn dccf_context_producer_for_token(token: &str) -> Option<String> {
    let c = ctx().lock().unwrap();
    let mut found = None;
    for p in c.producer_subs.values() {
        if p.notify_token.matches(token) {
            found = Some(p.producer_id.clone());
        }
    }
    found
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
            "[DCCF] last consumer for scope {key} released; deleting producer subscription {:?}",
            sub.resource_uri
        );
    }
    removed
}

/// Test-only (#1755): the producer resource URI recorded for `scope`, once the
/// create has been committed.
#[cfg(test)]
pub fn dccf_context_producer_resource(scope: &SubscriptionScope) -> Option<String> {
    let c = ctx().lock().unwrap();
    c.producer_subs
        .values()
        .find(|p| &p.scope == scope)
        .and_then(|p| p.resource_uri.clone())
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
                analytics_contexts: HashMap::new(),
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
