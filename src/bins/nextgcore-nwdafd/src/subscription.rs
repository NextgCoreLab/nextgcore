//! NWDAF Analytics Subscription Management (TS 23.288 §5.2)
//!
//! Implements Nnwdaf_EventsSubscription service:
//! - Subscription creation, modification, deletion
//! - Event notification delivery
//! - Subscription filtering by analytics ID, target, and reporting conditions

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::context::AnalyticsId;

/// Subscription notification frequency
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NotificationMethod {
    /// One-shot: notify once and delete subscription
    OneShot,
    /// Periodic: notify every N seconds
    Periodic(u64),
    /// On-change: notify when analytics value changes significantly
    OnChange,
}

/// Reporting conditions for triggering notifications
#[derive(Debug, Clone)]
pub struct ReportingCondition {
    /// Threshold for the analytics metric (e.g., CPU load > 0.8)
    pub threshold: Option<f64>,
    /// Maximum time between reports (even if no change)
    pub max_report_interval_secs: Option<u64>,
    /// Minimum number of events before reporting
    pub min_event_count: Option<u32>,
}

impl Default for ReportingCondition {
    fn default() -> Self {
        Self {
            threshold: None,
            max_report_interval_secs: Some(60),
            min_event_count: None,
        }
    }
}

/// Target of analytics (what to analyze)
#[derive(Debug, Clone)]
pub enum AnalyticsTarget {
    /// Specific UE by SUPI
    Supi(String),
    /// Specific NF instance
    NfInstance(String),
    /// All UEs in a TAI area
    TaiArea(String),
    /// Network-wide analytics
    NetworkWide,
}

/// NWDAF analytics subscription
#[derive(Debug, Clone)]
pub struct AnalyticsSubscription {
    /// Subscription ID (UUID)
    pub subscription_id: String,
    /// Consumer NF URI for notifications
    pub notification_uri: String,
    /// Requested analytics IDs
    pub analytics_ids: Vec<AnalyticsId>,
    /// Target of analytics
    pub target: AnalyticsTarget,
    /// Notification method
    pub notification_method: NotificationMethod,
    /// Reporting conditions
    pub reporting_condition: ReportingCondition,
    /// Subscription expiry (UNIX seconds), None = no expiry
    pub expiry: Option<u64>,
    /// Creation timestamp (UNIX seconds)
    pub created_at: u64,
    /// Last notification sent (UNIX seconds)
    pub last_notified_at: Option<u64>,
    /// Count of notifications sent
    pub notification_count: u32,
}

impl AnalyticsSubscription {
    /// Creates a new subscription
    pub fn new(
        subscription_id: String,
        notification_uri: String,
        analytics_ids: Vec<AnalyticsId>,
        target: AnalyticsTarget,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        Self {
            subscription_id,
            notification_uri,
            analytics_ids,
            target,
            notification_method: NotificationMethod::Periodic(60),
            reporting_condition: ReportingCondition::default(),
            expiry: None,
            created_at: now,
            last_notified_at: None,
            notification_count: 0,
        }
    }

    /// Returns true if this subscription has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.expiry.map(|exp| now > exp).unwrap_or(false)
    }

    /// Checks if this subscription is due for notification (periodic)
    pub fn is_due_for_notification(&self) -> bool {
        if self.is_expired() {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        match self.notification_method {
            NotificationMethod::OneShot => self.notification_count == 0,
            NotificationMethod::Periodic(interval) => {
                self.last_notified_at
                    .map(|last| now.saturating_sub(last) >= interval)
                    .unwrap_or(true)
            }
            NotificationMethod::OnChange => false, // driven by events, not timer
        }
    }

    /// Records a notification being sent
    pub fn mark_notified(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.last_notified_at = Some(now);
        self.notification_count += 1;
    }
}

/// Subscription manager: stores and manages active subscriptions
#[derive(Debug, Default)]
pub struct SubscriptionManager {
    subscriptions: HashMap<String, AnalyticsSubscription>,
    /// Maximum allowed subscriptions
    max_subscriptions: usize,
}

impl SubscriptionManager {
    pub fn new(max_subscriptions: usize) -> Self {
        Self {
            subscriptions: HashMap::new(),
            max_subscriptions,
        }
    }

    /// Adds a new subscription. Returns Err if capacity exceeded.
    pub fn create(
        &mut self,
        sub: AnalyticsSubscription,
    ) -> Result<String, String> {
        if self.subscriptions.len() >= self.max_subscriptions {
            return Err(format!(
                "Subscription capacity exceeded ({}/{})",
                self.subscriptions.len(),
                self.max_subscriptions
            ));
        }
        let id = sub.subscription_id.clone();
        self.subscriptions.insert(id.clone(), sub);
        Ok(id)
    }

    /// Retrieves a subscription by ID
    pub fn get(&self, id: &str) -> Option<&AnalyticsSubscription> {
        self.subscriptions.get(id)
    }

    /// Retrieves a subscription mutably
    pub fn get_mut(&mut self, id: &str) -> Option<&mut AnalyticsSubscription> {
        self.subscriptions.get_mut(id)
    }

    /// Deletes a subscription
    pub fn delete(&mut self, id: &str) -> bool {
        self.subscriptions.remove(id).is_some()
    }

    /// Returns all subscriptions due for notification
    pub fn due_subscriptions(&self) -> Vec<&AnalyticsSubscription> {
        self.subscriptions
            .values()
            .filter(|s| s.is_due_for_notification())
            .collect()
    }

    /// Removes expired subscriptions, returns count removed
    pub fn cleanup_expired(&mut self) -> usize {
        let expired: Vec<_> = self.subscriptions.values()
            .filter(|s| s.is_expired())
            .map(|s| s.subscription_id.clone())
            .collect();
        let count = expired.len();
        for id in expired {
            self.subscriptions.remove(&id);
        }
        count
    }

    pub fn count(&self) -> usize {
        self.subscriptions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sub(id: &str) -> AnalyticsSubscription {
        AnalyticsSubscription::new(
            id.into(),
            "http://amf.local/notify".into(),
            vec![AnalyticsId::NfLoad],
            AnalyticsTarget::NetworkWide,
        )
    }

    #[test]
    fn test_subscription_create_and_get() {
        let mut mgr = SubscriptionManager::new(100);
        let sub = make_sub("sub-001");
        mgr.create(sub).unwrap();
        assert!(mgr.get("sub-001").is_some());
    }

    #[test]
    fn test_subscription_delete() {
        let mut mgr = SubscriptionManager::new(100);
        mgr.create(make_sub("sub-001")).unwrap();
        assert!(mgr.delete("sub-001"));
        assert!(mgr.get("sub-001").is_none());
    }

    #[test]
    fn test_capacity_limit() {
        let mut mgr = SubscriptionManager::new(2);
        mgr.create(make_sub("sub-001")).unwrap();
        mgr.create(make_sub("sub-002")).unwrap();
        let result = mgr.create(make_sub("sub-003"));
        assert!(result.is_err());
    }

    #[test]
    fn test_one_shot_subscription_due() {
        let mut sub = make_sub("sub-001");
        sub.notification_method = NotificationMethod::OneShot;
        assert!(sub.is_due_for_notification());
        sub.mark_notified();
        assert!(!sub.is_due_for_notification());
    }

    #[test]
    fn test_expired_subscription() {
        let mut sub = make_sub("sub-001");
        sub.expiry = Some(1); // expired in 1970
        assert!(sub.is_expired());
        assert!(!sub.is_due_for_notification());
    }

    #[test]
    fn test_cleanup_expired() {
        let mut mgr = SubscriptionManager::new(100);
        let mut sub = make_sub("sub-exp");
        sub.expiry = Some(1);
        mgr.create(sub).unwrap();
        mgr.create(make_sub("sub-valid")).unwrap();
        let removed = mgr.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(mgr.count(), 1);
    }
}
