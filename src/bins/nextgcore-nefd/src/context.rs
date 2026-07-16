//! NEF Context Management
//!
//! Network Exposure Function context (TS 23.501 §6.2.5): northbound AF-facing
//! Monitoring Event subscriptions (TS 29.122 §5.3) mapped to the southbound
//! 5GC producer subscriptions they were translated into (AMF
//! Namf_EventExposure per TS 29.518, UDM Nudm_EE per TS 29.503), plus Device
//! Triggering transactions (TS 29.122 §5.10).
//!
//! All state is in-memory (`RwLock<HashMap<..>>`); persistence is out of
//! scope for the minimal NEF (issue #19), matching the other small NFs
//! (pind, nsacfd).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Southbound 5GC event producer a northbound monitoring subscription was
/// translated to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SouthboundProducer {
    /// AMF Namf_EventExposure (TS 29.518).
    Amf,
    /// UDM Nudm_EE (TS 29.503).
    Udm,
}

impl SouthboundProducer {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Amf => "AMF",
            Self::Udm => "UDM",
        }
    }
}

/// Reference to the southbound subscription created on behalf of a
/// northbound AF subscription. Kept so producer notifications can be
/// correlated back to the AF and so the producer-side subscription can be
/// torn down when the AF deletes its northbound subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SouthboundRef {
    pub producer: SouthboundProducer,
    /// Producer-assigned subscription ID.
    pub subscription_id: String,
    /// Path to DELETE on the producer to tear the subscription down.
    pub delete_path: String,
}

/// A northbound TS 29.122 Monitoring Event subscription stored by the NEF.
#[derive(Debug, Clone)]
pub struct NefMonitoringSubscription {
    /// NEF-assigned subscription ID. Doubles as the northbound resource ID
    /// and the southbound notify-correlation identifier (it is embedded in
    /// the callback path handed to AMF/UDM).
    pub id: String,
    /// AF identifier from the request path (`{scsAsId}`).
    pub scs_as_id: String,
    /// TS 29.122 MonitoringType requested by the AF.
    pub monitoring_type: String,
    /// AF callback URI that monitoring notifications are forwarded to.
    pub notification_destination: String,
    /// Southbound producer subscription, when one was established.
    pub southbound: Option<SouthboundRef>,
    /// Raw MonitoringEventSubscription JSON as received.
    pub raw: String,
}

impl NefMonitoringSubscription {
    pub fn new(
        scs_as_id: impl Into<String>,
        monitoring_type: impl Into<String>,
        notification_destination: impl Into<String>,
        raw: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            scs_as_id: scs_as_id.into(),
            monitoring_type: monitoring_type.into(),
            notification_destination: notification_destination.into(),
            southbound: None,
            raw: raw.into(),
        }
    }
}

/// A TS 29.122 §5.10 Device Triggering transaction stored by the NEF.
#[derive(Debug, Clone)]
pub struct NefTriggerTransaction {
    /// NEF-assigned transaction ID.
    pub id: String,
    /// AF identifier from the request path (`{scsAsId}`).
    pub scs_as_id: String,
    /// TS 29.122 DeliveryResult. Stays `TRIGGERED` until an SMS delivery
    /// path exists (no SMSF NF is implemented in this repo).
    pub delivery_result: String,
    /// Raw DeviceTriggering JSON as received.
    pub raw: String,
}

impl NefTriggerTransaction {
    pub fn new(
        scs_as_id: impl Into<String>,
        delivery_result: impl Into<String>,
        raw: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            scs_as_id: scs_as_id.into(),
            delivery_result: delivery_result.into(),
            raw: raw.into(),
        }
    }
}

/// NEF context errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NefContextError {
    MaxSubscriptionsReached,
    MaxTransactionsReached,
    LockPoisoned,
}

impl NefContextError {
    pub fn detail(&self) -> &'static str {
        match self {
            Self::MaxSubscriptionsReached => "Maximum number of monitoring subscriptions reached",
            Self::MaxTransactionsReached => {
                "Maximum number of device triggering transactions reached"
            }
            Self::LockPoisoned => "NEF context lock poisoned",
        }
    }

    pub fn cause(&self) -> &'static str {
        match self {
            Self::MaxSubscriptionsReached => "MAX_SUBSCRIPTIONS_REACHED",
            Self::MaxTransactionsReached => "MAX_TRANSACTIONS_REACHED",
            Self::LockPoisoned => "INTERNAL",
        }
    }
}

/// NEF Context
pub struct NefContext {
    /// Northbound monitoring subscriptions (by NEF subscription ID).
    subscriptions: RwLock<HashMap<String, NefMonitoringSubscription>>,
    /// Device triggering transactions (by transaction ID).
    transactions: RwLock<HashMap<String, NefTriggerTransaction>>,
    /// AMF SBI base URI for southbound Namf_EventExposure. None = southbound
    /// deferred (subscriptions are stored northbound-only).
    amf_uri: Option<String>,
    /// UDM SBI base URI for southbound Nudm_EE. None = southbound deferred.
    udm_uri: Option<String>,
    /// Externally routable base URI of this NEF's SBI server, used as the
    /// prefix of the callback URI handed to producers.
    notify_base: Option<String>,
    /// This NEF's NF instance ID (advertised as `nfId` in southbound
    /// subscribe requests).
    nf_instance_id: Option<String>,
    /// Maximum stored monitoring subscriptions.
    max_subscriptions: usize,
    /// Maximum stored device triggering transactions.
    max_transactions: usize,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl NefContext {
    pub fn new() -> Self {
        Self {
            subscriptions: RwLock::new(HashMap::new()),
            transactions: RwLock::new(HashMap::new()),
            amf_uri: None,
            udm_uri: None,
            notify_base: None,
            nf_instance_id: None,
            max_subscriptions: 0,
            max_transactions: 0,
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self, max_subscriptions: usize, max_transactions: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_subscriptions = max_subscriptions;
        self.max_transactions = max_transactions;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!(
            "NEF context initialized (max {max_subscriptions} subscriptions, {max_transactions} transactions)"
        );
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        if let Ok(mut subs) = self.subscriptions.write() {
            subs.clear();
        }
        if let Ok(mut txns) = self.transactions.write() {
            txns.clear();
        }
        self.initialized.store(false, Ordering::SeqCst);
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Set the endpoint configuration (southbound producer URIs, callback
    /// base, own instance ID). Called once from `main()` after context init.
    pub fn set_endpoints(
        &mut self,
        amf_uri: Option<String>,
        udm_uri: Option<String>,
        notify_base: Option<String>,
        nf_instance_id: Option<String>,
    ) {
        self.amf_uri = amf_uri;
        self.udm_uri = udm_uri;
        self.notify_base = notify_base;
        self.nf_instance_id = nf_instance_id;
    }

    pub fn amf_uri(&self) -> Option<String> {
        self.amf_uri.clone()
    }

    pub fn udm_uri(&self) -> Option<String> {
        self.udm_uri.clone()
    }

    pub fn notify_base(&self) -> Option<String> {
        self.notify_base.clone()
    }

    pub fn nf_instance_id(&self) -> Option<String> {
        self.nf_instance_id.clone()
    }

    /// Insert a monitoring subscription, enforcing the capacity cap.
    pub fn subscription_insert(
        &self,
        sub: NefMonitoringSubscription,
    ) -> Result<(), NefContextError> {
        let mut subs = self
            .subscriptions
            .write()
            .map_err(|_| NefContextError::LockPoisoned)?;
        if subs.len() >= self.max_subscriptions {
            return Err(NefContextError::MaxSubscriptionsReached);
        }
        let id = sub.id.clone();
        subs.insert(id.clone(), sub);
        log::debug!("NEF monitoring subscription inserted (id={id})");
        Ok(())
    }

    /// Find a monitoring subscription by NEF subscription ID.
    pub fn subscription_find(&self, id: &str) -> Option<NefMonitoringSubscription> {
        let subs = self.subscriptions.read().ok()?;
        subs.get(id).cloned()
    }

    /// Remove a monitoring subscription by NEF subscription ID.
    pub fn subscription_remove(&self, id: &str) -> Option<NefMonitoringSubscription> {
        let mut subs = self.subscriptions.write().ok()?;
        subs.remove(id)
    }

    /// Number of stored monitoring subscriptions (NRF `/load` gauge source).
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.read().map(|s| s.len()).unwrap_or(0)
    }

    /// Insert a device triggering transaction, enforcing the capacity cap.
    pub fn transaction_insert(&self, txn: NefTriggerTransaction) -> Result<(), NefContextError> {
        let mut txns = self
            .transactions
            .write()
            .map_err(|_| NefContextError::LockPoisoned)?;
        if txns.len() >= self.max_transactions {
            return Err(NefContextError::MaxTransactionsReached);
        }
        let id = txn.id.clone();
        txns.insert(id.clone(), txn);
        log::debug!("NEF device triggering transaction inserted (id={id})");
        Ok(())
    }

    /// Find a device triggering transaction by transaction ID.
    pub fn transaction_find(&self, id: &str) -> Option<NefTriggerTransaction> {
        let txns = self.transactions.read().ok()?;
        txns.get(id).cloned()
    }

    /// Number of stored device triggering transactions.
    pub fn transaction_count(&self) -> usize {
        self.transactions.read().map(|t| t.len()).unwrap_or(0)
    }
}

impl Default for NefContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global NEF context
static GLOBAL_NEF_CONTEXT: std::sync::OnceLock<Arc<RwLock<NefContext>>> =
    std::sync::OnceLock::new();

pub fn nef_self() -> Arc<RwLock<NefContext>> {
    GLOBAL_NEF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(NefContext::new())))
        .clone()
}

pub fn nef_context_init(max_subscriptions: usize, max_transactions: usize) {
    let ctx = nef_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_subscriptions, max_transactions);
    };
}

pub fn nef_context_final() {
    let ctx = nef_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests use local `NefContext` instances (not the process-global
    // context), so they are race-free without a global test lock.

    fn ctx(max_subs: usize, max_txns: usize) -> NefContext {
        let mut context = NefContext::new();
        context.init(max_subs, max_txns);
        context
    }

    fn sub(scs_as_id: &str) -> NefMonitoringSubscription {
        NefMonitoringSubscription::new(
            scs_as_id,
            "LOCATION_REPORTING",
            "http://af.example.com:8080/notify",
            "{}",
        )
    }

    #[test]
    fn subscription_insert_find_remove_roundtrip() {
        let context = ctx(16, 16);
        let s = sub("af-001");
        let id = s.id.clone();

        context.subscription_insert(s).expect("insert");
        assert_eq!(context.subscription_count(), 1);

        let found = context.subscription_find(&id).expect("find");
        assert_eq!(found.scs_as_id, "af-001");
        assert_eq!(found.monitoring_type, "LOCATION_REPORTING");
        assert!(found.southbound.is_none());

        let removed = context.subscription_remove(&id).expect("remove");
        assert_eq!(removed.id, id);
        assert_eq!(context.subscription_count(), 0);
        assert!(context.subscription_find(&id).is_none());
    }

    #[test]
    fn subscription_cap_is_enforced() {
        let context = ctx(1, 1);
        context
            .subscription_insert(sub("af-a"))
            .expect("first insert fits");
        let err = context
            .subscription_insert(sub("af-b"))
            .expect_err("second insert must hit the cap");
        assert_eq!(err, NefContextError::MaxSubscriptionsReached);
        assert_eq!(err.cause(), "MAX_SUBSCRIPTIONS_REACHED");
        assert_eq!(context.subscription_count(), 1);
    }

    #[test]
    fn transaction_cap_is_enforced() {
        let context = ctx(1, 1);
        context
            .transaction_insert(NefTriggerTransaction::new("af-a", "TRIGGERED", "{}"))
            .expect("first insert fits");
        let err = context
            .transaction_insert(NefTriggerTransaction::new("af-a", "TRIGGERED", "{}"))
            .expect_err("second insert must hit the cap");
        assert_eq!(err, NefContextError::MaxTransactionsReached);
        assert_eq!(context.transaction_count(), 1);
    }

    #[test]
    fn transaction_insert_and_find() {
        let context = ctx(4, 4);
        let txn = NefTriggerTransaction::new("af-trig", "TRIGGERED", r#"{"msisdn":"123"}"#);
        let id = txn.id.clone();
        context.transaction_insert(txn).expect("insert");
        let found = context.transaction_find(&id).expect("find");
        assert_eq!(found.scs_as_id, "af-trig");
        assert_eq!(found.delivery_result, "TRIGGERED");
    }

    #[test]
    fn generated_ids_are_unique() {
        let a = sub("af");
        let b = sub("af");
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn init_guards_reinit_and_fini_clears() {
        let mut context = NefContext::new();
        assert!(!context.is_initialized());
        context.init(8, 8);
        assert!(context.is_initialized());
        // Re-init is a guarded no-op (caps unchanged).
        context.init(1, 1);
        context.subscription_insert(sub("af-1")).expect("insert");
        context
            .subscription_insert(sub("af-2"))
            .expect("caps kept from first init");

        context.fini();
        assert!(!context.is_initialized());
        assert_eq!(context.subscription_count(), 0);
    }

    #[test]
    fn uninitialized_context_rejects_inserts() {
        // max caps default to 0 before init, so inserts are rejected.
        let context = NefContext::new();
        let err = context.subscription_insert(sub("af")).expect_err("cap 0");
        assert_eq!(err, NefContextError::MaxSubscriptionsReached);
    }

    #[test]
    fn southbound_producer_strings() {
        assert_eq!(SouthboundProducer::Amf.as_str(), "AMF");
        assert_eq!(SouthboundProducer::Udm.as_str(), "UDM");
    }

    #[test]
    fn error_details_are_stable() {
        assert_eq!(
            NefContextError::MaxTransactionsReached.cause(),
            "MAX_TRANSACTIONS_REACHED"
        );
        assert_eq!(NefContextError::LockPoisoned.cause(), "INTERNAL");
        assert!(!NefContextError::MaxSubscriptionsReached.detail().is_empty());
    }
}
