//! EES Context Management
//!
//! Edge Enabler Server context (TS 23.558 / TS 29.558).
//! Backs the `eees-easregistration` service API: stores `EASRegistration`
//! resources keyed by a server-minted `registrationId` (eesd-03) and indexes
//! the consumer `easId` separately for discovery.

use crate::acr::{
    acr_ue_key, AcrContextError, AcrDecReq, AcrDetermReq, AcrInitReq, AcrState, AcrStatus,
};
use crate::eec::EecRegistration;
use crate::services::{
    ACInfoSubscription, AcrMgntEventSubsc, CeaAnnouncement, EECContext, ACINFO_PATCHABLE_FIELDS,
};
use crate::types::{
    apply_merge_patch, is_expired, EasDiscoveryFilter, EasDiscoverySubscription, EasProfile,
    EasRegistration,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Outcome of a merge-patch / replace update that can fail for several
/// spec-distinct reasons mapped to different HTTP status codes by the handler.
#[derive(Debug, PartialEq, Eq)]
pub enum UpdateError {
    /// Resource `registrationId` does not exist → 404.
    NotFound,
    /// Attempt to change an immutable identifier (`easId`/`eecId`) → 403.
    IdImmutable,
    /// Result failed re-validation (e.g. missing mandatory IE) → 400.
    Invalid,
    /// Internal lock/serialization failure → 500.
    Internal,
}

/// EES Context - main context structure.
pub struct EesContext {
    /// Stored EAS registrations, keyed by the server-minted `registrationId`.
    registrations: RwLock<HashMap<String, EasRegistration>>,
    /// `easId` -> `[registrationId]` index (one easId may map to several
    /// registrations); used for discovery.
    eas_id_index: RwLock<HashMap<String, Vec<String>>>,
    /// EEC registrations (eesd-06), keyed by the server-minted `registrationId`.
    eec_registrations: RwLock<HashMap<String, EecRegistration>>,
    /// EAS discovery-change subscriptions (eesd-05), keyed by `subscriptionId`.
    disc_subscriptions: RwLock<HashMap<String, EasDiscoverySubscription>>,
    /// ACR relocation states (eesd-07), keyed by `"eecId:sEasId"`.
    acr_states: RwLock<HashMap<String, AcrState>>,
    /// CEA announcements (eesd-13 `eees-cea`), keyed by server-minted `announcementId`.
    cea_announcements: RwLock<HashMap<String, CeaAnnouncement>>,
    /// AC Information subscriptions (`eees-appclientinformation`, TS 29.558
    /// §8.4). The spec `ACInfoSubscription` body carries NO id field: the
    /// server-minted `subscriptionId` lives only as this map's key (returned
    /// via the `Location` header).
    app_client_infos: RwLock<HashMap<String, ACInfoSubscription>>,
    /// ACR management event subscriptions (eesd-13 `eees-acrmgntevent`), keyed by `subscriptionId`.
    acr_mgnt_subscriptions: RwLock<HashMap<String, AcrMgntEventSubsc>>,
    /// EEC contexts (`eees-eeccontextreloc`, TS 29.558 §8.7.2), keyed by the
    /// spec pull key `cntxId` (the `eec-cntx-id` query parameter).
    eec_contexts: RwLock<HashMap<String, EECContext>>,
    /// Maximum registrations (applied per resource family).
    max_eas: usize,
    /// Context initialized flag.
    initialized: AtomicBool,
}

impl EesContext {
    pub fn new() -> Self {
        Self {
            registrations: RwLock::new(HashMap::new()),
            eas_id_index: RwLock::new(HashMap::new()),
            eec_registrations: RwLock::new(HashMap::new()),
            disc_subscriptions: RwLock::new(HashMap::new()),
            acr_states: RwLock::new(HashMap::new()),
            cea_announcements: RwLock::new(HashMap::new()),
            app_client_infos: RwLock::new(HashMap::new()),
            acr_mgnt_subscriptions: RwLock::new(HashMap::new()),
            eec_contexts: RwLock::new(HashMap::new()),
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
        if let Ok(mut eecs) = self.eec_registrations.write() {
            eecs.clear();
        }
        if let Ok(mut subs) = self.disc_subscriptions.write() {
            subs.clear();
        }
        if let Ok(mut states) = self.acr_states.write() {
            states.clear();
        }
        if let Ok(mut anns) = self.cea_announcements.write() {
            anns.clear();
        }
        if let Ok(mut infos) = self.app_client_infos.write() {
            infos.clear();
        }
        if let Ok(mut subs) = self.acr_mgnt_subscriptions.write() {
            subs.clear();
        }
        if let Ok(mut ctxs) = self.eec_contexts.write() {
            ctxs.clear();
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

    /// eesd-05: full discovery — return every stored `EASProfile` that satisfies
    /// `filter` (an absent filter returns all served EASs). No invented scoring.
    pub fn eas_discover_filter(&self, filter: Option<&EasDiscoveryFilter>) -> Vec<EasProfile> {
        let regs = match self.registrations.read() {
            Ok(r) => r,
            Err(_) => return vec![],
        };
        regs.values()
            .map(|r| &r.eas_prof)
            .filter(|p| filter.is_none_or(|f| f.matches(p)))
            .cloned()
            .collect()
    }

    /// eesd-04: full-replace an EAS registration (`UpdateIndEASRegistration`,
    /// PUT). Preserves the `registrationId`; rejects an attempt to change the
    /// immutable `easId`. `reg` is assumed already mandatory-IE-validated.
    pub fn eas_update(
        &self,
        registration_id: &str,
        mut reg: EasRegistration,
    ) -> Result<EasRegistration, UpdateError> {
        let mut regs = self
            .registrations
            .write()
            .map_err(|_| UpdateError::Internal)?;
        let existing = regs.get(registration_id).ok_or(UpdateError::NotFound)?;
        if existing.eas_prof.eas_id != reg.eas_prof.eas_id {
            return Err(UpdateError::IdImmutable);
        }
        reg.registration_id = Some(registration_id.to_string());
        regs.insert(registration_id.to_string(), reg.clone());
        log::info!("EAS registration replaced: registrationId={registration_id}");
        Ok(reg)
    }

    /// eesd-04: RFC 7396 merge-patch an EAS registration
    /// (`ModifyIndEASRegistration`, PATCH). Applies `patch` onto the stored
    /// JSON, re-validates, and rejects an `easId` change.
    pub fn eas_modify(
        &self,
        registration_id: &str,
        patch: &serde_json::Value,
    ) -> Result<EasRegistration, UpdateError> {
        let mut regs = self
            .registrations
            .write()
            .map_err(|_| UpdateError::Internal)?;
        let stored = regs.get(registration_id).ok_or(UpdateError::NotFound)?;
        let old_eas_id = stored.eas_prof.eas_id.clone();

        let mut value = serde_json::to_value(stored).map_err(|_| UpdateError::Internal)?;
        apply_merge_patch(&mut value, patch);
        let mut updated: EasRegistration =
            serde_json::from_value(value).map_err(|_| UpdateError::Invalid)?;

        if updated.eas_prof.eas_id != old_eas_id {
            return Err(UpdateError::IdImmutable);
        }
        if updated.eas_prof.eas_id.trim().is_empty() || updated.eas_prof.end_pt.is_empty() {
            return Err(UpdateError::Invalid);
        }
        updated.registration_id = Some(registration_id.to_string());
        regs.insert(registration_id.to_string(), updated.clone());
        log::info!("EAS registration merge-patched: registrationId={registration_id}");
        Ok(updated)
    }

    // ---- eesd-06: EEC registration store -------------------------------------

    /// Register an EEC; mints a `registrationId`, preserves the `eecId`.
    pub fn eec_register(&self, mut reg: EecRegistration) -> Option<EecRegistration> {
        let mut eecs = self.eec_registrations.write().ok()?;
        if eecs.len() >= self.max_eas {
            log::error!("Maximum EEC registrations [{}] reached", self.max_eas);
            return None;
        }
        let registration_id = Uuid::new_v4().to_string();
        reg.registration_id = Some(registration_id.clone());
        eecs.insert(registration_id.clone(), reg.clone());
        log::info!(
            "EEC registered: registrationId={registration_id} eecId={}",
            reg.eec_id
        );
        Some(reg)
    }

    pub fn eec_find(&self, registration_id: &str) -> Option<EecRegistration> {
        self.eec_registrations
            .read()
            .ok()?
            .get(registration_id)
            .cloned()
    }

    pub fn eec_list(&self) -> Vec<EecRegistration> {
        self.eec_registrations
            .read()
            .map(|r| r.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn eec_deregister(&self, registration_id: &str) -> Option<EecRegistration> {
        let removed = self.eec_registrations.write().ok()?.remove(registration_id);
        if removed.is_some() {
            log::info!("EEC deregistered: registrationId={registration_id}");
        }
        removed
    }

    /// PUT full-replace an EEC registration; rejects an `eecId` change.
    pub fn eec_update(
        &self,
        registration_id: &str,
        mut reg: EecRegistration,
    ) -> Result<EecRegistration, UpdateError> {
        let mut eecs = self
            .eec_registrations
            .write()
            .map_err(|_| UpdateError::Internal)?;
        let existing = eecs.get(registration_id).ok_or(UpdateError::NotFound)?;
        if existing.eec_id != reg.eec_id {
            return Err(UpdateError::IdImmutable);
        }
        reg.registration_id = Some(registration_id.to_string());
        eecs.insert(registration_id.to_string(), reg.clone());
        Ok(reg)
    }

    /// PATCH merge an EEC registration; rejects an `eecId` change.
    pub fn eec_modify(
        &self,
        registration_id: &str,
        patch: &serde_json::Value,
    ) -> Result<EecRegistration, UpdateError> {
        let mut eecs = self
            .eec_registrations
            .write()
            .map_err(|_| UpdateError::Internal)?;
        let stored = eecs.get(registration_id).ok_or(UpdateError::NotFound)?;
        let old_eec_id = stored.eec_id.clone();

        let mut value = serde_json::to_value(stored).map_err(|_| UpdateError::Internal)?;
        apply_merge_patch(&mut value, patch);
        let mut updated: EecRegistration =
            serde_json::from_value(value).map_err(|_| UpdateError::Invalid)?;
        if updated.eec_id != old_eec_id {
            return Err(UpdateError::IdImmutable);
        }
        if updated.validate().is_err() {
            return Err(UpdateError::Invalid);
        }
        updated.registration_id = Some(registration_id.to_string());
        eecs.insert(registration_id.to_string(), updated.clone());
        Ok(updated)
    }

    // ---- eesd-05: EAS discovery subscription store ---------------------------

    pub fn disc_sub_create(
        &self,
        mut sub: EasDiscoverySubscription,
    ) -> Option<EasDiscoverySubscription> {
        let mut subs = self.disc_subscriptions.write().ok()?;
        if subs.len() >= self.max_eas {
            return None;
        }
        let subscription_id = Uuid::new_v4().to_string();
        sub.subscription_id = Some(subscription_id.clone());
        subs.insert(subscription_id, sub.clone());
        Some(sub)
    }

    pub fn disc_sub_find(&self, subscription_id: &str) -> Option<EasDiscoverySubscription> {
        self.disc_subscriptions
            .read()
            .ok()?
            .get(subscription_id)
            .cloned()
    }

    pub fn disc_sub_list(&self) -> Vec<EasDiscoverySubscription> {
        self.disc_subscriptions
            .read()
            .map(|s| s.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn disc_sub_delete(&self, subscription_id: &str) -> Option<EasDiscoverySubscription> {
        self.disc_subscriptions
            .write()
            .ok()?
            .remove(subscription_id)
    }

    pub fn disc_sub_update(
        &self,
        subscription_id: &str,
        mut sub: EasDiscoverySubscription,
    ) -> Result<EasDiscoverySubscription, UpdateError> {
        let mut subs = self
            .disc_subscriptions
            .write()
            .map_err(|_| UpdateError::Internal)?;
        if !subs.contains_key(subscription_id) {
            return Err(UpdateError::NotFound);
        }
        sub.subscription_id = Some(subscription_id.to_string());
        subs.insert(subscription_id.to_string(), sub.clone());
        Ok(sub)
    }

    /// eesd-05 notify stub: count the subscriptions whose filter selects
    /// `changed`. No live notification peer exists in this stack, so delivery is
    /// logged rather than POSTed (wire delivery DEFERRED). Returns the number of
    /// matching subscriptions for testability.
    pub fn notify_discovery_subscribers(&self, changed: &EasProfile) -> usize {
        let subs = match self.disc_subscriptions.read() {
            Ok(s) => s,
            Err(_) => return 0,
        };
        let mut matched = 0;
        for sub in subs.values() {
            if sub.filter_matches(changed) {
                matched += 1;
                log::debug!(
                    "EAS discovery notify (stub): would POST to {} for easId={}",
                    sub.notification_uri,
                    changed.eas_id
                );
            }
        }
        matched
    }

    // ---- eesd-12: expTime lifecycle sweep ------------------------------------

    /// Drop EAS and EEC registrations whose `expTime` is at/before `now_epoch`.
    /// Absent `expTime` ⇒ never expires. Returns the number removed.
    pub fn sweep_expired(&self, now_epoch: i64) -> usize {
        let mut removed = 0;

        if let (Ok(mut regs), Ok(mut index)) =
            (self.registrations.write(), self.eas_id_index.write())
        {
            let expired: Vec<String> = regs
                .iter()
                .filter(|(_, r)| is_expired(r.exp_time.as_deref(), now_epoch))
                .map(|(k, _)| k.clone())
                .collect();
            for id in expired {
                if let Some(r) = regs.remove(&id) {
                    if let Some(ids) = index.get_mut(&r.eas_prof.eas_id) {
                        ids.retain(|x| x != &id);
                        if ids.is_empty() {
                            index.remove(&r.eas_prof.eas_id);
                        }
                    }
                    removed += 1;
                }
            }
        }

        if let Ok(mut eecs) = self.eec_registrations.write() {
            let expired: Vec<String> = eecs
                .iter()
                .filter(|(_, r)| is_expired(r.exp_time.as_deref(), now_epoch))
                .map(|(k, _)| k.clone())
                .collect();
            for id in expired {
                eecs.remove(&id);
                removed += 1;
            }
        }

        if removed > 0 {
            log::info!("EES lifecycle sweep removed {removed} expired registration(s)");
        }
        removed
    }

    // ---- eesd-07: Application Context Relocation (ACR) ----------------------

    /// ACR Determine — select a T-EAS candidate for the given (eecId, sEasId).
    ///
    /// ACR Determine (TS 24.558 §6.5.5.2.2). If `easId` is supplied it must be
    /// a registered EAS (else [`AcrContextError::SEasNotFound`]); a T-EAS is
    /// then selected from the registered pool (the first EAS ≠ S-EAS, else
    /// [`AcrContextError::NoTEasAvailable`]). Records `DETERMINED` state keyed
    /// by the UE and returns it.
    pub fn acr_determine(&self, req: &AcrDetermReq) -> Result<AcrState, AcrContextError> {
        let regs = self
            .registrations
            .read()
            .map_err(|_| AcrContextError::Internal)?;

        if let Some(eid) = req.eas_id.as_deref() {
            if !regs.values().any(|r| r.eas_prof.eas_id == eid) {
                return Err(AcrContextError::SEasNotFound);
            }
        }

        let t_profile = regs
            .values()
            .map(|r| &r.eas_prof)
            .find(|p| Some(p.eas_id.as_str()) != req.eas_id.as_deref());
        let (t_eas_id, t_endpoint) = match t_profile {
            Some(p) => (Some(p.eas_id.clone()), Some(p.end_pt.clone())),
            None => return Err(AcrContextError::NoTEasAvailable),
        };
        drop(regs);

        let state = AcrState {
            requestor_id: Some(req.requestor_id.clone()),
            ue_id: req.ue_id.clone(),
            eas_id: req.eas_id.clone(),
            s_eas_endpoint: Some(req.s_eas_endpoint.clone()),
            t_eas_id: t_eas_id.clone(),
            t_eas_endpoint: t_endpoint,
            status: Some(AcrStatus::Determined),
        };
        let key = acr_ue_key(req.ue_id.as_deref(), Some(&req.requestor_id));
        if let Ok(mut states) = self.acr_states.write() {
            states.insert(key, state.clone());
        }
        log::debug!(
            "ACR determined: requestorId={} ueId={:?} tEasId={:?}",
            req.requestor_id,
            req.ue_id,
            t_eas_id
        );
        Ok(state)
    }

    /// ACR Initiate (TS 24.558 §6.5.5.2.3) — transition the relocation to
    /// `INITIATED` with the supplied T-EAS endpoint. Keyed by the UE; any
    /// previously-determined `tEasId` is preserved.
    pub fn acr_initiate(&self, req: &AcrInitReq) -> AcrState {
        let key = acr_ue_key(req.ue_id.as_deref(), Some(&req.requestor_id));
        let mut state = AcrState {
            requestor_id: Some(req.requestor_id.clone()),
            ue_id: req.ue_id.clone(),
            eas_id: req.eas_id.clone(),
            s_eas_endpoint: req.s_eas_endpoint.clone(),
            t_eas_id: None,
            t_eas_endpoint: Some(req.t_eas_endpoint.clone()),
            status: Some(AcrStatus::Initiated),
        };
        if let Ok(mut states) = self.acr_states.write() {
            if let Some(prev) = states.get(&key) {
                state.t_eas_id = prev.t_eas_id.clone();
            }
            states.insert(key, state.clone());
        }
        log::debug!(
            "ACR initiated: requestorId={} ueId={:?}",
            req.requestor_id,
            req.ue_id
        );
        state
    }

    /// ACR Declare (TS 24.558 §6.5.5.2.4) — mark the relocation `COMPLETED`
    /// with the final T-EAS and (stub) notify. Keyed by the UE (`ueId` is
    /// mandatory in `AcrDecReq`). The EES would notify the T-EAS and any
    /// ACR-status subscribers here; delivery is STUB (logged).
    pub fn acr_declare(&self, req: &AcrDecReq) -> AcrState {
        let key = acr_ue_key(Some(&req.ue_id), req.requestor_id.as_deref());
        let state = AcrState {
            requestor_id: req.requestor_id.clone(),
            ue_id: Some(req.ue_id.clone()),
            eas_id: None,
            s_eas_endpoint: None,
            t_eas_id: Some(req.t_eas_id.clone()),
            t_eas_endpoint: Some(req.t_eas_endpoint.clone()),
            status: Some(AcrStatus::Completed),
        };
        if let Ok(mut states) = self.acr_states.write() {
            states.insert(key, state.clone());
        }
        log::info!(
            "ACR completed (stub notify): ueId={} tEasId={}",
            req.ue_id,
            req.t_eas_id
        );
        state
    }

    /// EEL-managed ACR (TS 29.558 §8.8) — determine + initiate internally for
    /// the UE, selecting a T-EAS from the registered pool. Records `INITIATED`.
    pub fn acr_eel_request(&self, ue_id: &str) -> Result<AcrState, AcrContextError> {
        let regs = self
            .registrations
            .read()
            .map_err(|_| AcrContextError::Internal)?;
        let (t_eas_id, t_endpoint) = match regs.values().map(|r| &r.eas_prof).next() {
            Some(p) => (Some(p.eas_id.clone()), Some(p.end_pt.clone())),
            None => return Err(AcrContextError::NoTEasAvailable),
        };
        drop(regs);

        let state = AcrState {
            requestor_id: None,
            ue_id: Some(ue_id.to_string()),
            eas_id: None,
            s_eas_endpoint: None,
            t_eas_id: t_eas_id.clone(),
            t_eas_endpoint: t_endpoint,
            status: Some(AcrStatus::Initiated),
        };
        let key = acr_ue_key(Some(ue_id), None);
        if let Ok(mut states) = self.acr_states.write() {
            states.insert(key, state.clone());
        }
        log::debug!("EEL ACR initiated: ueId={ue_id} tEasId={:?}", t_eas_id);
        Ok(state)
    }

    /// ACR status update (TS 29.558 §8.9) — record a status change reported by
    /// an EAS. Keyed by `easId` (`ACRUpdateData` carries no `ueId`). The EES
    /// would notify subscribed EAS/EEC endpoints here; delivery is STUB.
    pub fn acr_status_update(&self, eas_id: &str, status: AcrStatus) {
        let key = format!("eas:{eas_id}");
        if let Ok(mut states) = self.acr_states.write() {
            let state = states.entry(key).or_insert_with(AcrState::default);
            state.eas_id = Some(eas_id.to_string());
            state.status = Some(status.clone());
        }
        log::debug!("ACR status update (stub notify): easId={eas_id} status={status:?}");
    }

    /// Look up the current ACR state for a UE (or requestor) identity.
    pub fn acr_find(&self, ue_id: Option<&str>, requestor_id: Option<&str>) -> Option<AcrState> {
        let key = acr_ue_key(ue_id, requestor_id);
        self.acr_states.read().ok()?.get(&key).cloned()
    }

    // ---- eesd-13: eees-cea — Common EAS Announcement -------------------------

    /// Create a CEA announcement; mints an `announcementId`.
    pub fn cea_create(&self, mut ann: CeaAnnouncement) -> Option<CeaAnnouncement> {
        let mut anns = self.cea_announcements.write().ok()?;
        if anns.len() >= self.max_eas {
            return None;
        }
        let id = Uuid::new_v4().to_string();
        ann.announcement_id = Some(id.clone());
        anns.insert(id.clone(), ann.clone());
        log::info!(
            "CEA announcement created: announcementId={id} easId={}",
            ann.eas_id
        );
        Some(ann)
    }

    pub fn cea_find(&self, announcement_id: &str) -> Option<CeaAnnouncement> {
        self.cea_announcements
            .read()
            .ok()?
            .get(announcement_id)
            .cloned()
    }

    pub fn cea_list(&self) -> Vec<CeaAnnouncement> {
        self.cea_announcements
            .read()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn cea_delete(&self, announcement_id: &str) -> Option<CeaAnnouncement> {
        let removed = self.cea_announcements.write().ok()?.remove(announcement_id);
        if removed.is_some() {
            log::info!("CEA announcement deleted: announcementId={announcement_id}");
        }
        removed
    }

    // ---- eees-appclientinformation — AC Information subscriptions (§8.4) -----

    /// Store an `ACInfoSubscription`; mints and returns the server
    /// `subscriptionId` (the map key — the spec wire body carries no id).
    pub fn acinfo_create(&self, sub: ACInfoSubscription) -> Option<String> {
        let mut subs = self.app_client_infos.write().ok()?;
        if subs.len() >= self.max_eas {
            return None;
        }
        let id = Uuid::new_v4().to_string();
        subs.insert(id.clone(), sub.clone());
        log::info!(
            "ACInfoSubscription created: subscriptionId={id} easId={}",
            sub.eas_id
        );
        Some(id)
    }

    pub fn acinfo_find(&self, subscription_id: &str) -> Option<ACInfoSubscription> {
        self.app_client_infos
            .read()
            .ok()?
            .get(subscription_id)
            .cloned()
    }

    pub fn acinfo_delete(&self, subscription_id: &str) -> Option<ACInfoSubscription> {
        let removed = self.app_client_infos.write().ok()?.remove(subscription_id);
        if removed.is_some() {
            log::info!("ACInfoSubscription deleted: subscriptionId={subscription_id}");
        }
        removed
    }

    /// PUT full-replace an existing AC Information subscription
    /// (`UpdateIndAppClientInfoSubscription`, yaml:158-207). `sub` is assumed
    /// already mandatory-IE-validated by the handler.
    pub fn acinfo_update(
        &self,
        subscription_id: &str,
        sub: ACInfoSubscription,
    ) -> Result<ACInfoSubscription, UpdateError> {
        let mut subs = self
            .app_client_infos
            .write()
            .map_err(|_| UpdateError::Internal)?;
        if !subs.contains_key(subscription_id) {
            return Err(UpdateError::NotFound);
        }
        subs.insert(subscription_id.to_string(), sub.clone());
        log::info!("ACInfoSubscription replaced: subscriptionId={subscription_id}");
        Ok(sub)
    }

    /// PATCH merge an AC Information subscription
    /// (`ModifyIndAppClientInfoSubscription`, `application/merge-patch+json`,
    /// yaml:209-266). The RFC 7396 merge is restricted to the
    /// `ACInfoSubscriptionPatch` members (yaml:355-377); any other key in the
    /// patch document — including the immutable `easId` — is ignored.
    pub fn acinfo_modify(
        &self,
        subscription_id: &str,
        patch: &serde_json::Value,
    ) -> Result<ACInfoSubscription, UpdateError> {
        let mut subs = self
            .app_client_infos
            .write()
            .map_err(|_| UpdateError::Internal)?;
        let stored = subs.get(subscription_id).ok_or(UpdateError::NotFound)?;

        // Restrict the merge document to the spec ACInfoSubscriptionPatch keys.
        let filtered = match patch.as_object() {
            Some(map) => serde_json::Value::Object(
                map.iter()
                    .filter(|(k, _)| ACINFO_PATCHABLE_FIELDS.contains(&k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            ),
            None => return Err(UpdateError::Invalid),
        };

        let mut value = serde_json::to_value(stored).map_err(|_| UpdateError::Internal)?;
        apply_merge_patch(&mut value, &filtered);
        let updated: ACInfoSubscription =
            serde_json::from_value(value).map_err(|_| UpdateError::Invalid)?;
        if updated.eas_id.trim().is_empty() {
            return Err(UpdateError::Invalid);
        }
        subs.insert(subscription_id.to_string(), updated.clone());
        log::info!("ACInfoSubscription merge-patched: subscriptionId={subscription_id}");
        Ok(updated)
    }

    // ---- eees-eeccontextreloc — EEC contexts (TS 29.558 §8.7.2) --------------

    /// Push (store/replace) an EEC context, keyed by the spec pull key
    /// `cntxId` (TS29558_Eees_EECContextRelocation.yaml:236-238).
    pub fn eec_context_push(&self, ctx: EECContext) -> Option<()> {
        let mut ctxs = self.eec_contexts.write().ok()?;
        if !ctxs.contains_key(&ctx.cntx_id) && ctxs.len() >= self.max_eas {
            return None;
        }
        log::info!(
            "EEC context pushed: cntxId={} eecId={}",
            ctx.cntx_id,
            ctx.eec_id
        );
        ctxs.insert(ctx.cntx_id.clone(), ctx);
        Some(())
    }

    /// Pull a stored EEC context by its `cntxId` (the `eec-cntx-id` query
    /// parameter of `PullEecContexts`, yaml:87-92).
    pub fn eec_context_pull(&self, cntx_id: &str) -> Option<EECContext> {
        self.eec_contexts.read().ok()?.get(cntx_id).cloned()
    }

    // ---- eesd-13: eees-acrmgntevent — ACR Management Event subscriptions -----

    /// Create an ACR management event subscription; mints a `subscriptionId`.
    pub fn acrmgnt_sub_create(&self, mut sub: AcrMgntEventSubsc) -> Option<AcrMgntEventSubsc> {
        let mut subs = self.acr_mgnt_subscriptions.write().ok()?;
        if subs.len() >= self.max_eas {
            return None;
        }
        let id = Uuid::new_v4().to_string();
        sub.subscription_id = Some(id.clone());
        subs.insert(id.clone(), sub.clone());
        log::info!(
            "ACR management event subscription created: subscriptionId={id} notificationUri={}",
            sub.notification_uri
        );
        Some(sub)
    }

    pub fn acrmgnt_sub_find(&self, subscription_id: &str) -> Option<AcrMgntEventSubsc> {
        self.acr_mgnt_subscriptions
            .read()
            .ok()?
            .get(subscription_id)
            .cloned()
    }

    pub fn acrmgnt_sub_list(&self) -> Vec<AcrMgntEventSubsc> {
        self.acr_mgnt_subscriptions
            .read()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// PUT full-replace an ACR management event subscription.
    pub fn acrmgnt_sub_update(
        &self,
        subscription_id: &str,
        mut sub: AcrMgntEventSubsc,
    ) -> Result<AcrMgntEventSubsc, UpdateError> {
        let mut subs = self
            .acr_mgnt_subscriptions
            .write()
            .map_err(|_| UpdateError::Internal)?;
        if !subs.contains_key(subscription_id) {
            return Err(UpdateError::NotFound);
        }
        sub.subscription_id = Some(subscription_id.to_string());
        subs.insert(subscription_id.to_string(), sub.clone());
        Ok(sub)
    }

    pub fn acrmgnt_sub_delete(&self, subscription_id: &str) -> Option<AcrMgntEventSubsc> {
        let removed = self
            .acr_mgnt_subscriptions
            .write()
            .ok()?
            .remove(subscription_id);
        if removed.is_some() {
            log::info!(
                "ACR management event subscription deleted: subscriptionId={subscription_id}"
            );
        }
        removed
    }

    /// Notify stub: count subscriptions whose `eecId`/`easId` filter matches the
    /// event. Delivery is logged only (no live callback peer).
    pub fn notify_acrmgnt_subscribers(
        &self,
        event_eec_id: Option<&str>,
        event_eas_id: Option<&str>,
    ) -> usize {
        let subs = match self.acr_mgnt_subscriptions.read() {
            Ok(s) => s,
            Err(_) => return 0,
        };
        let mut matched = 0;
        for sub in subs.values() {
            let eec_match = sub
                .eec_id
                .as_deref()
                .is_none_or(|id| Some(id) == event_eec_id);
            let eas_match = sub
                .eas_id
                .as_deref()
                .is_none_or(|id| Some(id) == event_eas_id);
            if eec_match && eas_match {
                matched += 1;
                log::debug!(
                    "ACR management event notify (stub): would POST to {}",
                    sub.notification_uri
                );
            }
        }
        matched
    }
}

impl Default for EesContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global EES context (thread-safe singleton).
static GLOBAL_EES_CONTEXT: std::sync::OnceLock<Arc<RwLock<EesContext>>> =
    std::sync::OnceLock::new();

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

        let stored = ctx
            .eas_register(make_reg("eas1.example.com", "VIDEO"))
            .unwrap();
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

        let stored = ctx
            .eas_register(make_reg("eas2.example.com", "AR"))
            .unwrap();
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
        assert!(ctx
            .eas_register(make_reg("a.example.com", "VIDEO"))
            .is_some());
        assert!(ctx
            .eas_register(make_reg("b.example.com", "VIDEO"))
            .is_none());
    }

    /// eesd-04: PUT full-replace preserves the registrationId and rejects an
    /// easId change.
    #[test]
    fn test_eas_update_replace_and_reject_eas_id_change() {
        let mut ctx = EesContext::new();
        ctx.init(8);
        let stored = ctx
            .eas_register(make_reg("eas1.example.com", "VIDEO"))
            .unwrap();
        let reg_id = stored.registration_id.unwrap();

        // Replace svc/type, keep easId → 200-equivalent Ok.
        let mut replacement = make_reg("eas1.example.com", "AR");
        replacement.exp_time = Some("2030-01-01T00:00:00Z".into());
        let updated = ctx.eas_update(&reg_id, replacement).unwrap();
        assert_eq!(updated.registration_id.as_deref(), Some(reg_id.as_str()));
        assert_eq!(updated.eas_prof.eas_type.as_deref(), Some("AR"));
        assert_eq!(updated.exp_time.as_deref(), Some("2030-01-01T00:00:00Z"));

        // Changing easId is rejected.
        let changed = make_reg("eas2.example.com", "AR");
        assert_eq!(
            ctx.eas_update(&reg_id, changed),
            Err(UpdateError::IdImmutable)
        );

        // Unknown registrationId → NotFound.
        assert_eq!(
            ctx.eas_update("nope", make_reg("eas1.example.com", "AR")),
            Err(UpdateError::NotFound)
        );
    }

    /// eesd-04: PATCH merge-patch updates mutable fields and rejects easId change.
    #[test]
    fn test_eas_modify_merge_patch() {
        let mut ctx = EesContext::new();
        ctx.init(8);
        let stored = ctx
            .eas_register(make_reg("eas1.example.com", "VIDEO"))
            .unwrap();
        let reg_id = stored.registration_id.unwrap();

        let patch = serde_json::json!({"easProf": {"type": "AR"}});
        let updated = ctx.eas_modify(&reg_id, &patch).unwrap();
        assert_eq!(updated.eas_prof.eas_type.as_deref(), Some("AR"));
        assert_eq!(updated.eas_prof.eas_id, "eas1.example.com"); // untouched

        // Patching the immutable easId is rejected.
        let bad = serde_json::json!({"easProf": {"easId": "other.example.com"}});
        assert_eq!(ctx.eas_modify(&reg_id, &bad), Err(UpdateError::IdImmutable));
    }

    fn make_eec(eec_id: &str) -> EecRegistration {
        EecRegistration {
            eec_id: eec_id.into(),
            ue_id: Some("gpsi-1".into()),
            ac_profs: None,
            exp_time: None,
            supp_feat: None,
            registration_id: None,
        }
    }

    /// eesd-06: EEC register/find/update/modify/deregister lifecycle.
    #[test]
    fn test_eec_register_lifecycle() {
        let mut ctx = EesContext::new();
        ctx.init(8);

        let stored = ctx.eec_register(make_eec("eec1.example.com")).unwrap();
        let reg_id = stored.registration_id.clone().unwrap();
        assert_ne!(reg_id, "eec1.example.com");
        assert!(ctx.eec_find(&reg_id).is_some());
        assert_eq!(ctx.eec_list().len(), 1);

        // PUT replace keeps eecId, rejects an eecId change.
        let mut replace = make_eec("eec1.example.com");
        replace.ue_id = Some("gpsi-2".into());
        let updated = ctx.eec_update(&reg_id, replace).unwrap();
        assert_eq!(updated.ue_id.as_deref(), Some("gpsi-2"));
        assert_eq!(
            ctx.eec_update(&reg_id, make_eec("eec2")),
            Err(UpdateError::IdImmutable)
        );

        // PATCH merge.
        let patch = serde_json::json!({"ueId": "gpsi-3"});
        assert_eq!(
            ctx.eec_modify(&reg_id, &patch).unwrap().ue_id.as_deref(),
            Some("gpsi-3")
        );

        assert!(ctx.eec_deregister(&reg_id).is_some());
        assert!(ctx.eec_find(&reg_id).is_none());
        assert!(ctx.eec_deregister(&reg_id).is_none());
    }

    /// eesd-05: discovery subscription create/find/delete + notify-stub matching.
    #[test]
    fn test_disc_subscription_and_notify() {
        let mut ctx = EesContext::new();
        ctx.init(8);
        ctx.eas_register(make_reg("eas1.example.com", "V2X"));

        let sub = EasDiscoverySubscription {
            notification_uri: "http://eec/callback".into(),
            eas_discovery_filter: Some(EasDiscoveryFilter {
                eas_chars: Some(crate::types::EasCharacteristics {
                    eas_type: Some("V2X".into()),
                    ..Default::default()
                }),
            }),
            ..Default::default()
        };
        let created = ctx.disc_sub_create(sub).unwrap();
        let sub_id = created.subscription_id.clone().unwrap();
        assert!(ctx.disc_sub_find(&sub_id).is_some());

        // The V2X EAS matches the V2X-filtered subscription.
        let v2x = make_reg("eas1.example.com", "V2X");
        assert_eq!(ctx.notify_discovery_subscribers(&v2x.eas_prof), 1);
        let ar = make_reg("eas9.example.com", "AR");
        assert_eq!(ctx.notify_discovery_subscribers(&ar.eas_prof), 0);

        assert!(ctx.disc_sub_delete(&sub_id).is_some());
        assert!(ctx.disc_sub_find(&sub_id).is_none());
    }

    /// eesd-12: the sweep drops a lapsed EAS registration but keeps an
    /// expTime-absent (never-expires) one.
    #[test]
    fn test_sweep_expired() {
        let mut ctx = EesContext::new();
        ctx.init(8);

        let mut lapsed = make_reg("expired.example.com", "VIDEO");
        lapsed.exp_time = Some("2000-01-01T00:00:00Z".into());
        ctx.eas_register(lapsed);
        ctx.eas_register(make_reg("forever.example.com", "VIDEO")); // no expTime

        assert_eq!(ctx.eas_count(), 2);
        // now well past 2000 → only the lapsed entry is dropped.
        let removed = ctx
            .sweep_expired(crate::types::parse_rfc3339_to_epoch("2020-01-01T00:00:00Z").unwrap());
        assert_eq!(removed, 1);
        assert_eq!(ctx.eas_count(), 1);
        assert!(!ctx
            .eas_discover(Some("forever.example.com"), None)
            .is_empty());
    }
}
