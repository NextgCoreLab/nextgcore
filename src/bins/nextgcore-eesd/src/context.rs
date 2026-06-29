//! EES Context Management
//!
//! Edge Enabler Server context (TS 23.558 / TS 29.558).
//! Backs the `eees-easregistration` service API: stores `EASRegistration`
//! resources keyed by a server-minted `registrationId` (eesd-03) and indexes
//! the consumer `easId` separately for discovery.

use crate::types::{EasProfile, EasRegistration};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// EES Context - main context structure.
pub struct EesContext {
    /// Stored EAS registrations, keyed by the server-minted `registrationId`.
    registrations: RwLock<HashMap<String, EasRegistration>>,
    /// `easId` -> `[registrationId]` index (one easId may map to several
    /// registrations); used for discovery.
    eas_id_index: RwLock<HashMap<String, Vec<String>>>,
    /// Maximum EAS registrations.
    max_eas: usize,
    /// Context initialized flag.
    initialized: AtomicBool,
}

impl EesContext {
    pub fn new() -> Self {
        Self {
            registrations: RwLock::new(HashMap::new()),
            eas_id_index: RwLock::new(HashMap::new()),
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
        if let Ok(mut regs) = self.registrations.write() {
            regs.clear();
        }
        if let Ok(mut index) = self.eas_id_index.write() {
            index.clear();
        }
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("EES context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Register an Edge Application Server.
    ///
    /// Mints a fresh `registrationId` (UUID) as the resource key and preserves
    /// the consumer-provided `easProf.easId` verbatim (eesd-03). Returns the
    /// stored `EASRegistration` (with `registrationId` populated) or `None`
    /// when capacity is exhausted.
    pub fn eas_register(&self, mut reg: EasRegistration) -> Option<EasRegistration> {
        let mut regs = self.registrations.write().ok()?;
        let mut index = self.eas_id_index.write().ok()?;

        if regs.len() >= self.max_eas {
            log::error!("Maximum EAS registrations [{}] reached", self.max_eas);
            return None;
        }

        let registration_id = Uuid::new_v4().to_string();
        reg.registration_id = Some(registration_id.clone());
        let eas_id = reg.eas_prof.eas_id.clone();

        index
            .entry(eas_id.clone())
            .or_default()
            .push(registration_id.clone());
        regs.insert(registration_id.clone(), reg.clone());

        log::info!("EAS registered: registrationId={registration_id} easId={eas_id}");
        Some(reg)
    }

    /// Deregister an EAS registration by its `registrationId`.
    pub fn eas_deregister(&self, registration_id: &str) -> Option<EasRegistration> {
        let mut regs = self.registrations.write().ok()?;
        let mut index = self.eas_id_index.write().ok()?;

        let removed = regs.remove(registration_id)?;
        if let Some(ids) = index.get_mut(&removed.eas_prof.eas_id) {
            ids.retain(|id| id != registration_id);
            if ids.is_empty() {
                index.remove(&removed.eas_prof.eas_id);
            }
        }
        log::info!("EAS deregistered: registrationId={registration_id}");
        Some(removed)
    }

    /// Look up a stored registration by its `registrationId`.
    pub fn eas_find(&self, registration_id: &str) -> Option<EasRegistration> {
        self.registrations
            .read()
            .ok()?
            .get(registration_id)
            .cloned()
    }

    /// Return all stored registrations.
    pub fn eas_list(&self) -> Vec<EasRegistration> {
        self.registrations
            .read()
            .map(|r| r.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn eas_count(&self) -> usize {
        self.registrations.read().map(|r| r.len()).unwrap_or(0)
    }

    /// Minimal EAS discovery by `easId` and/or `type` filter.
    ///
    /// NOTE: the full `EasDiscoveryReq`/`EasDiscoveryFilter`/`EasDiscoveryResp`
    /// model and discovery subscriptions are DEFERRED (eesd-05). This returns
    /// the matching spec `EASProfile`s with no invented scoring.
    pub fn eas_discover(&self, eas_id: Option<&str>, eas_type: Option<&str>) -> Vec<EasProfile> {
        let regs = match self.registrations.read() {
            Ok(r) => r,
            Err(_) => return vec![],
        };
        regs.values()
            .map(|r| &r.eas_prof)
            .filter(|p| eas_id.is_none_or(|id| p.eas_id == id))
            .filter(|p| eas_type.is_none_or(|t| p.eas_type.as_deref() == Some(t)))
            .cloned()
            .collect()
    }
}

impl Default for EesContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global EES context (thread-safe singleton).
static GLOBAL_EES_CONTEXT: std::sync::OnceLock<Arc<RwLock<EesContext>>> = std::sync::OnceLock::new();

/// Get the global EES context.
pub fn ees_self() -> Arc<RwLock<EesContext>> {
    GLOBAL_EES_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(EesContext::new())))
        .clone()
}

/// Initialize the global EES context.
pub fn ees_context_init(max_eas: usize) {
    let ctx = ees_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_eas);
    };
}

/// Finalize the global EES context.
pub fn ees_context_final() {
    let ctx = ees_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EndPoint;

    fn make_reg(eas_id: &str, eas_type: &str) -> EasRegistration {
        EasRegistration {
            eas_prof: EasProfile {
                eas_id: eas_id.to_string(),
                end_pt: EndPoint {
                    fqdn: Some(format!("{eas_id}.edge.local")),
                    ..Default::default()
                },
                prov_id: None,
                eas_type: Some(eas_type.to_string()),
                flex_eas_type: None,
                ac_ids: None,
                svc_area: None,
                svc_kpi: None,
            },
            exp_time: None,
            supp_feat: None,
            registration_id: None,
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

    /// eesd-03: registration mints a UUID `registrationId` distinct from the
    /// consumer `easId`, and preserves the `easId` verbatim.
    #[test]
    fn test_eas_register_mints_registration_id() {
        let mut ctx = EesContext::new();
        ctx.init(128);

        let stored = ctx.eas_register(make_reg("eas1.example.com", "VIDEO")).unwrap();
        let reg_id = stored.registration_id.clone().unwrap();
        assert_ne!(reg_id, "eas1.example.com");
        assert_eq!(stored.eas_prof.eas_id, "eas1.example.com");
        assert_eq!(ctx.eas_count(), 1);

        // GET on the registrationId returns the same easId.
        let found = ctx.eas_find(&reg_id).unwrap();
        assert_eq!(found.eas_prof.eas_id, "eas1.example.com");
    }

    #[test]
    fn test_eas_find_deregister() {
        let mut ctx = EesContext::new();
        ctx.init(128);

        let stored = ctx.eas_register(make_reg("eas2.example.com", "AR")).unwrap();
        let reg_id = stored.registration_id.unwrap();
        assert!(ctx.eas_find(&reg_id).is_some());

        assert!(ctx.eas_deregister(&reg_id).is_some());
        assert_eq!(ctx.eas_count(), 0);
        assert!(ctx.eas_find(&reg_id).is_none());
        assert!(ctx.eas_deregister(&reg_id).is_none());
    }

    #[test]
    fn test_eas_discover_by_eas_id_and_type() {
        let mut ctx = EesContext::new();
        ctx.init(128);

        ctx.eas_register(make_reg("eas1.example.com", "VIDEO"));
        ctx.eas_register(make_reg("eas2.example.com", "AR"));

        assert_eq!(ctx.eas_discover(Some("eas1.example.com"), None).len(), 1);
        assert_eq!(ctx.eas_discover(None, Some("AR")).len(), 1);
        assert_eq!(ctx.eas_discover(None, None).len(), 2);
        assert!(ctx.eas_discover(Some("nope"), None).is_empty());
    }

    #[test]
    fn test_eas_register_capacity_limit() {
        let mut ctx = EesContext::new();
        ctx.init(1);
        assert!(ctx.eas_register(make_reg("a.example.com", "VIDEO")).is_some());
        assert!(ctx.eas_register(make_reg("b.example.com", "VIDEO")).is_none());
    }
}
