//! Event-Driven Pub-Sub for SBI (B6.1)
//!
//! Provides event-driven publish-subscribe messaging between NF instances,
//! enabling real-time event distribution for 6G network analytics and control.
//!
//! Supports NWDAF analytics subscriptions, NEF event exposure, and
//! intent-based network automation triggers.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// Event Types
// ============================================================================

/// SBI event category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SbiEventCategory {
    /// NF status events (registration, deregistration, profile change).
    NfStatus,
    /// Analytics events (NWDAF analytics notifications).
    Analytics,
    /// Policy events (PCF policy decisions).
    Policy,
    /// Session events (PDU session lifecycle).
    Session,
    /// Mobility events (UE mobility, handover).
    Mobility,
    /// Slice events (NSACF admission, quota changes).
    Slice,
    /// Security events (authentication, key refresh).
    Security,
    /// AI/ML events (model updates, inference results).
    AiMl,
    /// ISAC events (sensing results, configuration changes).
    Isac,
    /// Energy events (energy saving mode changes).
    Energy,
}

/// Event notification.
#[derive(Debug, Clone)]
pub struct SbiEvent {
    /// Event ID.
    pub event_id: u64,
    /// Event category.
    pub category: SbiEventCategory,
    /// Event type name (e.g., "UE_MOBILITY", "ABNORMAL_BEHAVIOUR").
    pub event_type: String,
    /// Timestamp (epoch ms).
    pub timestamp_ms: u64,
    /// Source NF instance ID.
    pub source_nf_id: String,
    /// Event payload (JSON-encoded).
    pub payload: String,
    /// Correlation ID for event chains.
    pub correlation_id: Option<String>,
}

impl SbiEvent {
    /// Creates a new event.
    pub fn new(
        event_id: u64,
        category: SbiEventCategory,
        event_type: impl Into<String>,
        source_nf_id: impl Into<String>,
        payload: impl Into<String>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            event_id,
            category,
            event_type: event_type.into(),
            timestamp_ms: now,
            source_nf_id: source_nf_id.into(),
            payload: payload.into(),
            correlation_id: None,
        }
    }

    /// Set correlation ID.
    pub fn with_correlation(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }
}

// ============================================================================
// Subscription
// ============================================================================

/// Event subscription identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriptionId(pub u64);

/// Event subscription filter.
#[derive(Debug, Clone)]
pub struct EventFilter {
    /// Filter by category.
    pub categories: Vec<SbiEventCategory>,
    /// Filter by event type pattern (prefix match).
    pub event_type_prefix: Option<String>,
    /// Filter by source NF ID.
    pub source_nf_id: Option<String>,
}

impl EventFilter {
    /// Creates a filter for a specific category.
    pub fn category(cat: SbiEventCategory) -> Self {
        Self {
            categories: vec![cat],
            event_type_prefix: None,
            source_nf_id: None,
        }
    }

    /// Creates a filter matching all events.
    pub fn all() -> Self {
        Self {
            categories: Vec::new(),
            event_type_prefix: None,
            source_nf_id: None,
        }
    }

    /// Add event type prefix filter.
    pub fn with_type_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.event_type_prefix = Some(prefix.into());
        self
    }

    /// Check if an event matches this filter.
    pub fn matches(&self, event: &SbiEvent) -> bool {
        // Category filter.
        if !self.categories.is_empty() && !self.categories.contains(&event.category) {
            return false;
        }
        // Type prefix filter.
        if let Some(prefix) = &self.event_type_prefix {
            if !event.event_type.starts_with(prefix.as_str()) {
                return false;
            }
        }
        // Source NF filter.
        if let Some(nf_id) = &self.source_nf_id {
            if &event.source_nf_id != nf_id {
                return false;
            }
        }
        true
    }
}

/// Event subscription.
#[derive(Debug, Clone)]
pub struct Subscription {
    /// Subscription ID.
    pub id: SubscriptionId,
    /// Subscriber NF instance ID.
    pub subscriber_nf_id: String,
    /// Notification URI (callback endpoint).
    pub notification_uri: String,
    /// Event filter.
    pub filter: EventFilter,
    /// Expiry time (epoch ms, None = no expiry).
    pub expiry_ms: Option<u64>,
    /// Created timestamp (epoch ms).
    pub created_ms: u64,
    /// Number of notifications sent.
    pub notification_count: u64,
}

impl Subscription {
    /// Creates a new subscription.
    pub fn new(
        id: SubscriptionId,
        subscriber_nf_id: impl Into<String>,
        notification_uri: impl Into<String>,
        filter: EventFilter,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            id,
            subscriber_nf_id: subscriber_nf_id.into(),
            notification_uri: notification_uri.into(),
            filter,
            expiry_ms: None,
            created_ms: now,
            notification_count: 0,
        }
    }

    /// Set expiry duration.
    pub fn with_expiry(mut self, duration: Duration) -> Self {
        self.expiry_ms = Some(self.created_ms + duration.as_millis() as u64);
        self
    }

    /// Check if subscription has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expiry) = self.expiry_ms {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            now > expiry
        } else {
            false
        }
    }
}

// ============================================================================
// Pub-Sub Broker
// ============================================================================

/// Event broker for NF-to-NF pub-sub messaging.
pub struct EventBroker {
    subscriptions: HashMap<SubscriptionId, Subscription>,
    next_sub_id: u64,
    next_event_id: u64,
    total_published: u64,
    total_delivered: u64,
}

impl EventBroker {
    /// Creates a new event broker.
    pub fn new() -> Self {
        Self {
            subscriptions: HashMap::new(),
            next_sub_id: 1,
            next_event_id: 1,
            total_published: 0,
            total_delivered: 0,
        }
    }

    /// Subscribe to events.
    pub fn subscribe(&mut self, sub: Subscription) -> SubscriptionId {
        let id = sub.id;
        self.subscriptions.insert(id, sub);
        id
    }

    /// Allocate a subscription ID.
    pub fn alloc_subscription_id(&mut self) -> SubscriptionId {
        let id = SubscriptionId(self.next_sub_id);
        self.next_sub_id += 1;
        id
    }

    /// Allocate an event ID.
    pub fn alloc_event_id(&mut self) -> u64 {
        let id = self.next_event_id;
        self.next_event_id += 1;
        id
    }

    /// Unsubscribe.
    pub fn unsubscribe(&mut self, id: SubscriptionId) -> bool {
        self.subscriptions.remove(&id).is_some()
    }

    /// Publish an event. Returns list of (SubscriptionId, notification_uri) for delivery.
    pub fn publish(&mut self, event: &SbiEvent) -> Vec<(SubscriptionId, String)> {
        self.total_published += 1;
        let mut targets = Vec::new();

        for (id, sub) in &mut self.subscriptions {
            if sub.is_expired() {
                continue;
            }
            if sub.filter.matches(event) {
                sub.notification_count += 1;
                targets.push((*id, sub.notification_uri.clone()));
                self.total_delivered += 1;
            }
        }

        targets
    }

    /// Remove expired subscriptions.
    pub fn cleanup_expired(&mut self) -> usize {
        let before = self.subscriptions.len();
        self.subscriptions.retain(|_, sub| !sub.is_expired());
        before - self.subscriptions.len()
    }

    /// Total active subscriptions.
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Total events published.
    pub fn total_published(&self) -> u64 {
        self.total_published
    }

    /// Total notifications delivered.
    pub fn total_delivered(&self) -> u64 {
        self.total_delivered
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = SbiEvent::new(1, SbiEventCategory::Analytics, "UE_MOBILITY", "amf-001", "{}");
        assert_eq!(event.event_id, 1);
        assert_eq!(event.category, SbiEventCategory::Analytics);
        assert!(event.timestamp_ms > 0);
    }

    #[test]
    fn test_event_filter_category() {
        let filter = EventFilter::category(SbiEventCategory::Analytics);
        let event = SbiEvent::new(1, SbiEventCategory::Analytics, "TEST", "nf-1", "{}");
        assert!(filter.matches(&event));

        let other = SbiEvent::new(2, SbiEventCategory::Security, "TEST", "nf-1", "{}");
        assert!(!filter.matches(&other));
    }

    #[test]
    fn test_event_filter_type_prefix() {
        let filter = EventFilter::all().with_type_prefix("UE_");
        let event = SbiEvent::new(1, SbiEventCategory::Mobility, "UE_MOBILITY", "nf-1", "{}");
        assert!(filter.matches(&event));

        let other = SbiEvent::new(2, SbiEventCategory::Mobility, "SESSION_CHANGE", "nf-1", "{}");
        assert!(!filter.matches(&other));
    }

    #[test]
    fn test_event_broker_pubsub() {
        let mut broker = EventBroker::new();

        let sub_id = broker.alloc_subscription_id();
        let sub = Subscription::new(
            sub_id,
            "nwdaf-001",
            "http://nwdaf:8080/callback",
            EventFilter::category(SbiEventCategory::Analytics),
        );
        broker.subscribe(sub);

        let event = SbiEvent::new(
            broker.alloc_event_id(),
            SbiEventCategory::Analytics,
            "ABNORMAL_BEHAVIOUR",
            "amf-001",
            "{}",
        );
        let targets = broker.publish(&event);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, sub_id);
    }

    #[test]
    fn test_event_broker_unsubscribe() {
        let mut broker = EventBroker::new();
        let sub_id = broker.alloc_subscription_id();
        let sub = Subscription::new(sub_id, "nf-1", "http://cb", EventFilter::all());
        broker.subscribe(sub);
        assert_eq!(broker.subscription_count(), 1);

        broker.unsubscribe(sub_id);
        assert_eq!(broker.subscription_count(), 0);
    }

    #[test]
    fn test_event_broker_no_match() {
        let mut broker = EventBroker::new();
        let sub_id = broker.alloc_subscription_id();
        let sub = Subscription::new(
            sub_id,
            "nf-1",
            "http://cb",
            EventFilter::category(SbiEventCategory::Security),
        );
        broker.subscribe(sub);

        let event = SbiEvent::new(1, SbiEventCategory::Analytics, "TEST", "nf-2", "{}");
        let targets = broker.publish(&event);
        assert!(targets.is_empty());
    }
}
