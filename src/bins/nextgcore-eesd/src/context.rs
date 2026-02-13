//! EES Context Management
//!
//! Edge Enabler Server context (TS 23.558)
//! Manages Edge Application Server (EAS) registrations and UE context transfers

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

/// Edge Application Server (EAS) profile
#[derive(Debug, Clone)]
pub struct EasProfile {
    /// Unique EAS ID
    pub eas_id: String,
    /// EAS endpoint (URI)
    pub endpoint: String,
    /// Application ID (FQDN-based)
    pub app_id: String,
    /// EAS type (e.g., "AR", "VR", "GAME", "VIDEO")
    pub eas_type: String,
    /// Serving area TAC list
    pub serving_area_tacs: Vec<u32>,
    /// EAS status
    pub status: EasStatus,
    /// EAS capabilities
    pub capabilities: EasCapabilities,
    /// DNS name for EAS discovery
    pub dns_name: Option<String>,
}

/// EAS registration status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EasStatus {
    #[default]
    Registered,
    Active,
    Suspended,
    Deregistered,
}

/// EAS capabilities
#[derive(Debug, Clone, Default)]
pub struct EasCapabilities {
    pub max_concurrent_ues: u32,
    pub supported_features: Vec<String>,
    pub compute_capacity_pct: u8,
    pub storage_capacity_mb: u64,
}

/// EAS discovery result
#[derive(Debug, Clone)]
pub struct EasDiscoveryResult {
    pub eas_id: String,
    pub endpoint: String,
    pub app_id: String,
    pub dns_name: Option<String>,
    pub distance_score: f64,
}

/// UE edge context for context transfer during mobility
#[derive(Debug, Clone)]
pub struct UeEdgeContext {
    pub supi: String,
    pub current_eas_id: Option<String>,
    pub app_context_data: Option<String>,
    pub serving_tac: u32,
}

/// EES Context - main context structure
pub struct EesContext {
    /// Registered EAS profiles
    eas_profiles: RwLock<HashMap<String, EasProfile>>,
    /// App ID -> EAS ID index
    app_eas_index: RwLock<HashMap<String, Vec<String>>>,
    /// UE edge contexts (SUPI -> context)
    ue_contexts: RwLock<HashMap<String, UeEdgeContext>>,
    /// Next internal ID generator
    next_id: AtomicUsize,
    /// Maximum EAS registrations
    max_eas: usize,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl EesContext {
    pub fn new() -> Self {
        Self {
            eas_profiles: RwLock::new(HashMap::new()),
            app_eas_index: RwLock::new(HashMap::new()),
            ue_contexts: RwLock::new(HashMap::new()),
            next_id: AtomicUsize::new(1),
            max_eas: 0,
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self, max_eas: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_eas = max_eas;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("EES context initialized with max {max_eas} EAS registrations");
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        if let Ok(mut profiles) = self.eas_profiles.write() {
            profiles.clear();
        }
        if let Ok(mut index) = self.app_eas_index.write() {
            index.clear();
        }
        if let Ok(mut contexts) = self.ue_contexts.write() {
            contexts.clear();
        }
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("EES context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Register an Edge Application Server
    pub fn eas_register(&self, mut profile: EasProfile) -> Option<EasProfile> {
        let mut profiles = self.eas_profiles.write().ok()?;
        let mut index = self.app_eas_index.write().ok()?;

        if profiles.len() >= self.max_eas {
            log::error!("Maximum EAS registrations [{}] reached", self.max_eas);
            return None;
        }

        if profile.eas_id.is_empty() {
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            profile.eas_id = format!("eas-{id}");
        }

        let eas_id = profile.eas_id.clone();
        let app_id = profile.app_id.clone();

        index.entry(app_id.clone())
            .or_default()
            .push(eas_id.clone());
        profiles.insert(eas_id, profile.clone());

        log::info!("EAS registered: {} (app={}, endpoint={})", profile.eas_id, app_id, profile.endpoint);
        Some(profile)
    }

    /// Deregister an EAS
    pub fn eas_deregister(&self, eas_id: &str) -> Option<EasProfile> {
        let mut profiles = self.eas_profiles.write().ok()?;
        let mut index = self.app_eas_index.write().ok()?;

        if let Some(profile) = profiles.remove(eas_id) {
            if let Some(eas_list) = index.get_mut(&profile.app_id) {
                eas_list.retain(|id| id != eas_id);
            }
            log::info!("EAS deregistered: {eas_id}");
            return Some(profile);
        }
        None
    }

    /// Discover EAS by application ID and optional TAC
    pub fn eas_discover(&self, app_id: &str, tac: Option<u32>) -> Vec<EasDiscoveryResult> {
        let profiles = self.eas_profiles.read().ok().unwrap();
        let index = self.app_eas_index.read().ok().unwrap();

        let eas_ids = match index.get(app_id) {
            Some(ids) => ids,
            None => return vec![],
        };

        eas_ids.iter()
            .filter_map(|eas_id| profiles.get(eas_id))
            .filter(|p| p.status == EasStatus::Registered || p.status == EasStatus::Active)
            .filter(|p| {
                match tac {
                    Some(t) => p.serving_area_tacs.is_empty() || p.serving_area_tacs.contains(&t),
                    None => true,
                }
            })
            .map(|p| {
                let distance_score = if let Some(t) = tac {
                    if p.serving_area_tacs.contains(&t) { 1.0 } else { 0.5 }
                } else {
                    0.5
                };
                EasDiscoveryResult {
                    eas_id: p.eas_id.clone(),
                    endpoint: p.endpoint.clone(),
                    app_id: p.app_id.clone(),
                    dns_name: p.dns_name.clone(),
                    distance_score,
                }
            })
            .collect()
    }

    /// Get EAS by ID
    pub fn eas_find(&self, eas_id: &str) -> Option<EasProfile> {
        self.eas_profiles.read().ok()?.get(eas_id).cloned()
    }

    /// Get all registered EAS
    pub fn eas_list(&self) -> Vec<EasProfile> {
        self.eas_profiles.read()
            .map(|p| p.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn eas_count(&self) -> usize {
        self.eas_profiles.read().map(|p| p.len()).unwrap_or(0)
    }

    /// Store UE edge context (for mobility/context transfer)
    pub fn ue_context_store(&self, ctx: UeEdgeContext) -> bool {
        if let Ok(mut contexts) = self.ue_contexts.write() {
            contexts.insert(ctx.supi.clone(), ctx);
            return true;
        }
        false
    }

    /// Get UE edge context
    pub fn ue_context_get(&self, supi: &str) -> Option<UeEdgeContext> {
        self.ue_contexts.read().ok()?.get(supi).cloned()
    }

    /// Transfer UE context to a new EAS (edge relocation)
    pub fn ue_context_transfer(&self, supi: &str, new_eas_id: &str) -> bool {
        if let Ok(mut contexts) = self.ue_contexts.write() {
            if let Some(ctx) = contexts.get_mut(supi) {
                log::info!(
                    "UE {} edge context transfer: {:?} -> {}",
                    supi, ctx.current_eas_id, new_eas_id
                );
                ctx.current_eas_id = Some(new_eas_id.to_string());
                return true;
            }
        }
        false
    }
}

impl Default for EesContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global EES context (thread-safe singleton)
static GLOBAL_EES_CONTEXT: std::sync::OnceLock<Arc<RwLock<EesContext>>> = std::sync::OnceLock::new();

/// Get the global EES context
pub fn ees_self() -> Arc<RwLock<EesContext>> {
    GLOBAL_EES_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(EesContext::new())))
        .clone()
}

/// Initialize the global EES context
pub fn ees_context_init(max_eas: usize) {
    let ctx = ees_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_eas);
    };
}

/// Finalize the global EES context
pub fn ees_context_final() {
    let ctx = ees_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_eas(app: &str, endpoint: &str) -> EasProfile {
        EasProfile {
            eas_id: String::new(),
            endpoint: endpoint.to_string(),
            app_id: app.to_string(),
            eas_type: "VIDEO".to_string(),
            serving_area_tacs: vec![100, 200],
            status: EasStatus::Registered,
            capabilities: EasCapabilities {
                max_concurrent_ues: 1000,
                compute_capacity_pct: 80,
                storage_capacity_mb: 10240,
                ..Default::default()
            },
            dns_name: Some(format!("{app}.edge.local")),
        }
    }

    #[test]
    fn test_ees_context_new() {
        let ctx = EesContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.eas_count(), 0);
    }

    #[test]
    fn test_ees_context_init_fini() {
        let mut ctx = EesContext::new();
        ctx.init(128);
        assert!(ctx.is_initialized());
        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_eas_register_deregister() {
        let mut ctx = EesContext::new();
        ctx.init(128);

        let profile = make_eas("video-stream", "http://eas1:8080");
        let registered = ctx.eas_register(profile).unwrap();
        assert!(!registered.eas_id.is_empty());
        assert_eq!(ctx.eas_count(), 1);

        let found = ctx.eas_find(&registered.eas_id);
        assert!(found.is_some());

        ctx.eas_deregister(&registered.eas_id);
        assert_eq!(ctx.eas_count(), 0);
    }

    #[test]
    fn test_eas_discover_by_app_id() {
        let mut ctx = EesContext::new();
        ctx.init(128);

        ctx.eas_register(make_eas("video-stream", "http://eas1:8080"));
        ctx.eas_register(make_eas("video-stream", "http://eas2:8080"));
        ctx.eas_register(make_eas("ar-app", "http://eas3:8080"));

        let results = ctx.eas_discover("video-stream", None);
        assert_eq!(results.len(), 2);

        let results = ctx.eas_discover("ar-app", None);
        assert_eq!(results.len(), 1);

        let results = ctx.eas_discover("nonexistent", None);
        assert!(results.is_empty());
    }

    #[test]
    fn test_eas_discover_by_tac() {
        let mut ctx = EesContext::new();
        ctx.init(128);

        ctx.eas_register(make_eas("video-stream", "http://eas1:8080"));

        let results = ctx.eas_discover("video-stream", Some(100));
        assert_eq!(results.len(), 1);
        assert!((results[0].distance_score - 1.0).abs() < 0.01);

        let results = ctx.eas_discover("video-stream", Some(999));
        assert!(results.is_empty());
    }

    #[test]
    fn test_ue_context_transfer() {
        let mut ctx = EesContext::new();
        ctx.init(128);

        let ue_ctx = UeEdgeContext {
            supi: "imsi-001010000000001".to_string(),
            current_eas_id: Some("eas-1".to_string()),
            app_context_data: Some("app-state-data".to_string()),
            serving_tac: 100,
        };
        assert!(ctx.ue_context_store(ue_ctx));

        let found = ctx.ue_context_get("imsi-001010000000001").unwrap();
        assert_eq!(found.current_eas_id, Some("eas-1".to_string()));

        assert!(ctx.ue_context_transfer("imsi-001010000000001", "eas-2"));
        let found = ctx.ue_context_get("imsi-001010000000001").unwrap();
        assert_eq!(found.current_eas_id, Some("eas-2".to_string()));
    }
}
