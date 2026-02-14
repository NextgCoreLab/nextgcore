//! NWDAF Context Management
//!
//! Network Data Analytics Function context (TS 23.288)
//! Manages analytics subscriptions, ML models, and data collection

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

/// Analytics ID types defined in TS 23.288
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnalyticsId {
    /// NF load analytics
    NfLoad,
    /// Network performance analytics
    NetworkPerformance,
    /// UE mobility analytics
    UeMobility,
    /// UE communication patterns
    UeComm,
    /// Abnormal behavior detection
    AbnormalBehaviour,
    /// Service experience analytics
    ServiceExperience,
    /// QoS sustainability analytics
    QosSustainability,
    /// Slice load analytics
    SliceLoad,
    /// User data congestion analytics
    UserDataCongestion,
}

impl AnalyticsId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NfLoad => "NF_LOAD",
            Self::NetworkPerformance => "NETWORK_PERFORMANCE",
            Self::UeMobility => "UE_MOBILITY",
            Self::UeComm => "UE_COMM",
            Self::AbnormalBehaviour => "ABNORMAL_BEHAVIOUR",
            Self::ServiceExperience => "SERVICE_EXPERIENCE",
            Self::QosSustainability => "QOS_SUSTAINABILITY",
            Self::SliceLoad => "SLICE_LOAD",
            Self::UserDataCongestion => "USER_DATA_CONGESTION",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "NF_LOAD" => Some(Self::NfLoad),
            "NETWORK_PERFORMANCE" => Some(Self::NetworkPerformance),
            "UE_MOBILITY" => Some(Self::UeMobility),
            "UE_COMM" => Some(Self::UeComm),
            "ABNORMAL_BEHAVIOUR" => Some(Self::AbnormalBehaviour),
            "SERVICE_EXPERIENCE" => Some(Self::ServiceExperience),
            "QOS_SUSTAINABILITY" => Some(Self::QosSustainability),
            "SLICE_LOAD" => Some(Self::SliceLoad),
            "USER_DATA_CONGESTION" => Some(Self::UserDataCongestion),
            _ => None,
        }
    }
}

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SNssai {
    /// Slice/Service Type (SST)
    pub sst: u8,
    /// Slice Differentiator (SD) - optional 24-bit value
    pub sd: Option<u32>,
}

impl Default for SNssai {
    fn default() -> Self {
        Self { sst: 1, sd: None }
    }
}

/// Analytics subscription
#[derive(Debug, Clone)]
pub struct AnalyticsSubscription {
    /// Unique subscription ID
    pub subscription_id: String,
    /// Analytics type requested
    pub analytics_id: AnalyticsId,
    /// Target SUPI (for UE-specific analytics)
    pub target_supi: Option<String>,
    /// Target S-NSSAI (for slice-specific analytics)
    pub target_snssai: Option<SNssai>,
    /// Notification URI for analytics reports
    pub notification_uri: String,
    /// Subscription expiry time (Unix timestamp)
    pub expiry: u64,
    /// Subscription active flag
    pub active: bool,
}

impl AnalyticsSubscription {
    pub fn new(
        subscription_id: String,
        analytics_id: AnalyticsId,
        notification_uri: String,
        expiry: u64,
    ) -> Self {
        Self {
            subscription_id,
            analytics_id,
            target_supi: None,
            target_snssai: None,
            notification_uri,
            expiry,
            active: true,
        }
    }

    pub fn with_target_supi(mut self, supi: String) -> Self {
        self.target_supi = Some(supi);
        self
    }

    pub fn with_target_snssai(mut self, snssai: SNssai) -> Self {
        self.target_snssai = Some(snssai);
        self
    }

    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expiry
    }
}

/// ML model status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlModelStatus {
    /// Model is being trained
    Training,
    /// Model is trained and ready for inference
    Deployed,
    /// Model is being evaluated
    Evaluating,
    /// Model is inactive
    Inactive,
}

/// ML model information for analytics
#[derive(Debug, Clone)]
pub struct MlModelInfo {
    /// Unique model ID
    pub model_id: String,
    /// Analytics type this model supports
    pub analytics_id: AnalyticsId,
    /// Model version
    pub version: String,
    /// Model accuracy (0.0 - 1.0)
    pub accuracy: f64,
    /// Model status
    pub status: MlModelStatus,
    /// Training data count
    pub training_samples: usize,
    /// Last update timestamp
    pub updated_at: u64,
}

impl MlModelInfo {
    pub fn new(model_id: String, analytics_id: AnalyticsId, version: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            model_id,
            analytics_id,
            version,
            accuracy: 0.0,
            status: MlModelStatus::Training,
            training_samples: 0,
            updated_at: now,
        }
    }

    pub fn is_deployed(&self) -> bool {
        self.status == MlModelStatus::Deployed
    }
}

/// Data source configuration for analytics collection
#[derive(Debug, Clone)]
pub struct DataSource {
    /// Source NF type (e.g., "AMF", "SMF", "UPF")
    pub nf_type: String,
    /// Source NF instance ID
    pub nf_instance_id: String,
    /// Data collection URI
    pub collection_uri: String,
    /// Collection enabled flag
    pub enabled: bool,
}

/// NWDAF Context - main context structure
pub struct NwdafContext {
    /// NF instance ID
    pub nf_instance_id: String,
    /// Analytics subscriptions (subscription_id -> subscription)
    analytics_subscriptions: RwLock<HashMap<String, AnalyticsSubscription>>,
    /// ML models (model_id -> model_info)
    ml_models: RwLock<HashMap<String, MlModelInfo>>,
    /// Data sources (nf_instance_id -> source)
    data_sources: RwLock<HashMap<String, DataSource>>,
    /// Next internal ID generator
    next_id: AtomicUsize,
    /// Maximum subscriptions
    max_subscriptions: usize,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl NwdafContext {
    pub fn new(nf_instance_id: String) -> Self {
        Self {
            nf_instance_id,
            analytics_subscriptions: RwLock::new(HashMap::new()),
            ml_models: RwLock::new(HashMap::new()),
            data_sources: RwLock::new(HashMap::new()),
            next_id: AtomicUsize::new(1),
            max_subscriptions: 0,
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self, max_subscriptions: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_subscriptions = max_subscriptions;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!(
            "NWDAF context initialized: instance={}, max_subscriptions={}",
            self.nf_instance_id,
            max_subscriptions
        );
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        if let Ok(mut subs) = self.analytics_subscriptions.write() {
            subs.clear();
        }
        if let Ok(mut models) = self.ml_models.write() {
            models.clear();
        }
        if let Ok(mut sources) = self.data_sources.write() {
            sources.clear();
        }
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("NWDAF context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Add an analytics subscription
    pub fn add_subscription(&self, subscription: AnalyticsSubscription) -> Option<String> {
        let mut subs = self.analytics_subscriptions.write().ok()?;

        if subs.len() >= self.max_subscriptions {
            log::error!(
                "Maximum analytics subscriptions [{}] reached",
                self.max_subscriptions
            );
            return None;
        }

        let sub_id = subscription.subscription_id.clone();
        subs.insert(sub_id.clone(), subscription);

        log::info!("Analytics subscription added: {sub_id}");
        Some(sub_id)
    }

    /// Remove an analytics subscription
    pub fn remove_subscription(&self, subscription_id: &str) -> Option<AnalyticsSubscription> {
        let mut subs = self.analytics_subscriptions.write().ok()?;
        let removed = subs.remove(subscription_id);
        if removed.is_some() {
            log::info!("Analytics subscription removed: {subscription_id}");
        }
        removed
    }

    /// Get analytics subscription by ID
    pub fn get_subscription(&self, subscription_id: &str) -> Option<AnalyticsSubscription> {
        self.analytics_subscriptions
            .read()
            .ok()?
            .get(subscription_id)
            .cloned()
    }

    /// Get all active subscriptions for a specific analytics type
    pub fn get_analytics(&self, analytics_id: AnalyticsId) -> Vec<AnalyticsSubscription> {
        self.analytics_subscriptions
            .read()
            .map(|subs| {
                subs.values()
                    .filter(|s| s.analytics_id == analytics_id && s.active && !s.is_expired())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Register an ML model
    pub fn register_model(&self, model: MlModelInfo) -> Option<String> {
        let mut models = self.ml_models.write().ok()?;
        let model_id = model.model_id.clone();
        models.insert(model_id.clone(), model);
        log::info!("ML model registered: {model_id}");
        Some(model_id)
    }

    /// Get ML model by ID
    pub fn get_model(&self, model_id: &str) -> Option<MlModelInfo> {
        self.ml_models.read().ok()?.get(model_id).cloned()
    }

    /// Get all deployed models for a specific analytics type
    pub fn get_deployed_models(&self, analytics_id: AnalyticsId) -> Vec<MlModelInfo> {
        self.ml_models
            .read()
            .map(|models| {
                models
                    .values()
                    .filter(|m| m.analytics_id == analytics_id && m.is_deployed())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Update ML model status
    pub fn update_model_status(&self, model_id: &str, status: MlModelStatus) -> bool {
        if let Ok(mut models) = self.ml_models.write() {
            if let Some(model) = models.get_mut(model_id) {
                model.status = status;
                model.updated_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                log::info!("ML model {model_id} status updated to {status:?}");
                return true;
            }
        }
        false
    }

    /// Add a data source
    pub fn add_data_source(&self, source: DataSource) -> bool {
        if let Ok(mut sources) = self.data_sources.write() {
            sources.insert(source.nf_instance_id.clone(), source);
            return true;
        }
        false
    }

    /// Get all enabled data sources
    pub fn get_data_sources(&self) -> Vec<DataSource> {
        self.data_sources
            .read()
            .map(|sources| {
                sources
                    .values()
                    .filter(|s| s.enabled)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn subscription_count(&self) -> usize {
        self.analytics_subscriptions
            .read()
            .map(|s| s.len())
            .unwrap_or(0)
    }

    pub fn model_count(&self) -> usize {
        self.ml_models.read().map(|m| m.len()).unwrap_or(0)
    }

    pub fn data_source_count(&self) -> usize {
        self.data_sources.read().map(|d| d.len()).unwrap_or(0)
    }
}

impl Default for NwdafContext {
    fn default() -> Self {
        Self::new("nwdaf-instance-1".to_string())
    }
}

/// Global NWDAF context (thread-safe singleton)
static GLOBAL_NWDAF_CONTEXT: std::sync::OnceLock<Arc<RwLock<NwdafContext>>> =
    std::sync::OnceLock::new();

/// Get the global NWDAF context
pub fn nwdaf_self() -> Arc<RwLock<NwdafContext>> {
    GLOBAL_NWDAF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(NwdafContext::default())))
        .clone()
}

/// Initialize the global NWDAF context
pub fn nwdaf_context_init(nf_instance_id: String, max_subscriptions: usize) {
    let ctx = nwdaf_self();
    if let Ok(mut context) = ctx.write() {
        context.nf_instance_id = nf_instance_id;
        context.init(max_subscriptions);
    };
}

/// Finalize the global NWDAF context
pub fn nwdaf_context_final() {
    let ctx = nwdaf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analytics_id_conversion() {
        assert_eq!(AnalyticsId::NfLoad.as_str(), "NF_LOAD");
        assert_eq!(
            AnalyticsId::from_str("NF_LOAD"),
            Some(AnalyticsId::NfLoad)
        );
        assert_eq!(AnalyticsId::from_str("INVALID"), None);
    }

    #[test]
    fn test_nwdaf_context_new() {
        let ctx = NwdafContext::new("nwdaf-test".to_string());
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.subscription_count(), 0);
    }

    #[test]
    fn test_nwdaf_context_init_fini() {
        let mut ctx = NwdafContext::new("nwdaf-test".to_string());
        ctx.init(100);
        assert!(ctx.is_initialized());
        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_add_remove_subscription() {
        let mut ctx = NwdafContext::new("nwdaf-test".to_string());
        ctx.init(100);

        let sub = AnalyticsSubscription::new(
            "sub-1".to_string(),
            AnalyticsId::NfLoad,
            "http://localhost:8080/notify".to_string(),
            u64::MAX,
        );

        let sub_id = ctx.add_subscription(sub).unwrap();
        assert_eq!(sub_id, "sub-1");
        assert_eq!(ctx.subscription_count(), 1);

        let removed = ctx.remove_subscription("sub-1");
        assert!(removed.is_some());
        assert_eq!(ctx.subscription_count(), 0);
    }

    #[test]
    fn test_register_model() {
        let mut ctx = NwdafContext::new("nwdaf-test".to_string());
        ctx.init(100);

        let model = MlModelInfo::new(
            "model-1".to_string(),
            AnalyticsId::UeMobility,
            "v1.0".to_string(),
        );

        let model_id = ctx.register_model(model).unwrap();
        assert_eq!(model_id, "model-1");
        assert_eq!(ctx.model_count(), 1);
    }

    #[test]
    fn test_update_model_status() {
        let mut ctx = NwdafContext::new("nwdaf-test".to_string());
        ctx.init(100);

        let model = MlModelInfo::new(
            "model-1".to_string(),
            AnalyticsId::UeMobility,
            "v1.0".to_string(),
        );
        ctx.register_model(model);

        assert!(ctx.update_model_status("model-1", MlModelStatus::Deployed));
        let updated = ctx.get_model("model-1").unwrap();
        assert_eq!(updated.status, MlModelStatus::Deployed);
    }

    #[test]
    fn test_get_analytics_by_type() {
        let mut ctx = NwdafContext::new("nwdaf-test".to_string());
        ctx.init(100);

        ctx.add_subscription(AnalyticsSubscription::new(
            "sub-1".to_string(),
            AnalyticsId::NfLoad,
            "http://localhost:8080".to_string(),
            u64::MAX,
        ));

        ctx.add_subscription(AnalyticsSubscription::new(
            "sub-2".to_string(),
            AnalyticsId::UeMobility,
            "http://localhost:8080".to_string(),
            u64::MAX,
        ));

        let nf_load_subs = ctx.get_analytics(AnalyticsId::NfLoad);
        assert_eq!(nf_load_subs.len(), 1);

        let mobility_subs = ctx.get_analytics(AnalyticsId::UeMobility);
        assert_eq!(mobility_subs.len(), 1);
    }
}
