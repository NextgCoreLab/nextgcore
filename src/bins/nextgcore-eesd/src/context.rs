//! EES Context Management
//!
//! Edge Enabler Server context (TS 23.558 / TS 29.558).
//! Backs the `eees-easregistration` service API: stores `EASRegistration`
//! resources keyed by a server-minted `registrationId` (eesd-03) and indexes
//! the consumer `easId` separately for discovery.

use crate::acr::{
    acr_ue_key, AcrContextError, AcrDecReq, AcrDetermReq, AcrInitReq, AcrState, AcrStatus,
};
use crate::acrevents::{
    ACRCompleteEventInfo, ACREventsSubscription, ACRInfoNotification, TargetInfo,
    ACREVENTS_PATCHABLE_FIELDS,
};
use crate::eec::EecRegistration;
use crate::services::{
    ACInfoSubscription, ACRParamsInfo, AcrMgntEventReport, AcrMgntEventsNotification,
    AcrMgntEventsSubscription, CommonEASInfo, EECContext, ACINFO_PATCHABLE_FIELDS,
    ACRMGNT_PATCHABLE_FIELDS,
};
use crate::types::{
    apply_merge_patch, is_expired, DiscoveredEas, EasDiscoveryFilter, EasDiscoveryNotification,
    EasDiscoverySubscription, EasProfile, EasRegistration, EAS_AVAILABILITY_CHANGE,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Resource collection path for `eees-acrmgntevent` subscriptions (D7); used to
/// build the read-only `self` link stored in each `AcrMgntEventsSubscription`.
const ACRMGNT_SUB_COLLECTION: &str = "/eees-acrmgntevent/v1/subscriptions";

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
    /// Declared common EASs (`eees-cea` `POST /declare`, D3), keyed by
    /// `"{appGrpId}:{easId}"` (the spec op is accept-and-ack with no resource).
    declared_common_eas: RwLock<HashMap<String, CommonEASInfo>>,
    /// AC Information subscriptions (`eees-appclientinformation`, TS 29.558
    /// §8.4). The spec `ACInfoSubscription` body carries NO id field: the
    /// server-minted `subscriptionId` lives only as this map's key (returned
    /// via the `Location` header).
    app_client_infos: RwLock<HashMap<String, ACInfoSubscription>>,
    /// ACR management event subscriptions (`eees-acrmgntevent`, TS 29.558,
    /// D7), keyed by the server-minted `subscriptionId` (the last path segment
    /// of the resource `self` link). Body is the spec-exact
    /// [`AcrMgntEventsSubscription`].
    acr_mgnt_subscriptions: RwLock<HashMap<String, AcrMgntEventsSubscription>>,
    /// ACR events subscriptions (`eees-acrevents`, TS 24.558 §6.4, D5), keyed by
    /// the server-minted `subscriptionId` (the spec body carries no id).
    acrevents_subscriptions: RwLock<HashMap<String, ACREventsSubscription>>,
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
            declared_common_eas: RwLock::new(HashMap::new()),
            app_client_infos: RwLock::new(HashMap::new()),
            acr_mgnt_subscriptions: RwLock::new(HashMap::new()),
            acrevents_subscriptions: RwLock::new(HashMap::new()),
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
        if let Ok(mut declared) = self.declared_common_eas.write() {
            declared.clear();
        }
        if let Ok(mut infos) = self.app_client_infos.write() {
            infos.clear();
        }
        if let Ok(mut subs) = self.acr_mgnt_subscriptions.write() {
            subs.clear();
        }
        if let Ok(mut subs) = self.acrevents_subscriptions.write() {
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

    /// eesd-05 (D6): build an `EasDiscoveryNotification`
    /// (`TS24558_Eees_EASDiscovery.yaml:475-513`) for every discovery
    /// subscription whose filter selects `changed`, and enqueue each for real
    /// delivery via the shared notifier (D6) to the subscriber's
    /// `notificationUri`. Returns the number of matched subscriptions (kept for
    /// testability).
    ///
    /// Collect-then-enqueue: the `(uri, body)` pairs are built UNDER the
    /// `disc_subscriptions` read lock and enqueued only AFTER it is released —
    /// the documented NF-context AB-BA rule (the notifier is never invoked while
    /// holding an `EesContext` lock). The reported `eventType` is
    /// `EAS_AVAILABILITY_CHANGE` (a fresh EAS matching the filter became
    /// available); the notifier POST expects a 204 from the subscriber.
    pub fn notify_discovery_subscribers(&self, changed: &EasProfile) -> usize {
        let mut pending: Vec<(String, serde_json::Value)> = Vec::new();
        {
            let subs = match self.disc_subscriptions.read() {
                Ok(s) => s,
                Err(_) => return 0,
            };
            for (id, sub) in subs.iter() {
                if !sub.filter_matches(changed) {
                    continue;
                }
                let notif = EasDiscoveryNotification {
                    sub_id: id.clone(),
                    event_type: EAS_AVAILABILITY_CHANGE.to_string(),
                    discovered_eas: vec![DiscoveredEas {
                        eas: changed.clone(),
                    }],
                };
                if let Ok(body) = serde_json::to_value(&notif) {
                    pending.push((sub.notification_uri.clone(), body));
                }
            }
        }
        let matched = pending.len();
        for (uri, body) in pending {
            crate::notifier::enqueue(uri, body, "EasDiscoveryNotification");
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

        // D5: sweep expired ACR-events subscriptions (`eees-acrevents`).
        if let Ok(mut subs) = self.acrevents_subscriptions.write() {
            let expired: Vec<String> = subs
                .iter()
                .filter(|(_, s)| is_expired(s.exp_time.as_deref(), now_epoch))
                .map(|(k, _)| k.clone())
                .collect();
            for id in expired {
                subs.remove(&id);
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
            acr_params: None,
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
            acr_params: None,
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
            acr_params: None,
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
            acr_params: None,
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

    /// D4 (`eees-acr-param` `POST /send-acrparamsinfo`): merge the pushed
    /// `ACRParamsInfo` (source/target AS endpoints + `acrParams`) into the
    /// `eecId`-keyed ACR state (created if absent). Keyed the same way
    /// [`acr_find`](Self::acr_find)`(None, Some(eecId))` reads it back.
    pub fn acr_store_params(&self, info: &ACRParamsInfo) {
        let key = acr_ue_key(None, Some(&info.eec_id));
        if let Ok(mut states) = self.acr_states.write() {
            let state = states.entry(key).or_default();
            state
                .requestor_id
                .get_or_insert_with(|| info.eec_id.clone());
            state.s_eas_endpoint = Some(info.s_as_end_point.clone());
            state.t_eas_endpoint = Some(info.t_as_end_point.clone());
            state.acr_params = Some(info.acr_params.clone());
        }
        log::info!(
            "ACR parameters received: eecId={} acId={} requestorId={}",
            info.eec_id,
            info.ac_id,
            info.requestor_id
        );
    }

    // ---- D3: eees-cea — Common EAS Announcement (POST /declare) --------------

    /// Record a declared common EAS (`eees-cea` `POST /declare`). The custom
    /// operation is accept-and-ack: the declaration is stored keyed by
    /// `(appGrpId, easId)` so a redeclaration for the same group+EAS updates in
    /// place. No resource is minted (there is no `/announcements` collection).
    pub fn cea_declare(&self, info: CommonEASInfo) {
        let key = format!("{}:{}", info.app_grp_id, info.eas_id);
        if let Ok(mut declared) = self.declared_common_eas.write() {
            log::info!(
                "Common EAS declared: appGrpId={} easId={}",
                info.app_grp_id,
                info.eas_id
            );
            declared.insert(key, info);
        }
    }

    /// Look up a declared common EAS by `(appGrpId, easId)` (test-only inspector
    /// for the D3 accept-and-ack assertion).
    #[cfg(test)]
    pub fn cea_declared_find(&self, app_grp_id: &str, eas_id: &str) -> Option<CommonEASInfo> {
        let key = format!("{app_grp_id}:{eas_id}");
        self.declared_common_eas.read().ok()?.get(&key).cloned()
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

    // ---- eees-acrevents — ACR events subscriptions (TS 24.558 §6.4, D5) ------

    /// Store an `ACREventsSubscription`; mints and returns the server
    /// `subscriptionId` (the map key — the spec wire body carries no id).
    pub fn acrevents_create(&self, sub: ACREventsSubscription) -> Option<String> {
        let mut subs = self.acrevents_subscriptions.write().ok()?;
        if subs.len() >= self.max_eas {
            return None;
        }
        let id = Uuid::new_v4().to_string();
        subs.insert(id.clone(), sub.clone());
        log::info!(
            "ACREventsSubscription created: subscriptionId={id} eecId={} eventIds={}",
            sub.eec_id,
            sub.event_ids
        );
        Some(id)
    }

    /// Look up an ACR-events subscription by its `subscriptionId`.
    pub fn acrevents_find(&self, subscription_id: &str) -> Option<ACREventsSubscription> {
        self.acrevents_subscriptions
            .read()
            .ok()?
            .get(subscription_id)
            .cloned()
    }

    /// Delete an ACR-events subscription by its `subscriptionId`.
    pub fn acrevents_delete(&self, subscription_id: &str) -> Option<ACREventsSubscription> {
        let removed = self
            .acrevents_subscriptions
            .write()
            .ok()?
            .remove(subscription_id);
        if removed.is_some() {
            log::info!("ACREventsSubscription deleted: subscriptionId={subscription_id}");
        }
        removed
    }

    /// PUT full-replace an existing ACR-events subscription
    /// (`UpdateACREventsSubscription`, yaml:117-172). `sub` is assumed already
    /// mandatory-IE-validated by the handler.
    pub fn acrevents_update(
        &self,
        subscription_id: &str,
        sub: ACREventsSubscription,
    ) -> Result<ACREventsSubscription, UpdateError> {
        let mut subs = self
            .acrevents_subscriptions
            .write()
            .map_err(|_| UpdateError::Internal)?;
        if !subs.contains_key(subscription_id) {
            return Err(UpdateError::NotFound);
        }
        subs.insert(subscription_id.to_string(), sub.clone());
        log::info!("ACREventsSubscription replaced: subscriptionId={subscription_id}");
        Ok(sub)
    }

    /// PATCH merge an ACR-events subscription (`ModifyACREventsSubscription`,
    /// `application/merge-patch+json`, yaml:211-267). The RFC 7396 merge is
    /// restricted to the `ACREventsSubscriptionPatch` members
    /// ([`ACREVENTS_PATCHABLE_FIELDS`]); any other key — including the immutable
    /// `eecId` — is ignored. The merged result is re-validated fail-closed.
    pub fn acrevents_modify(
        &self,
        subscription_id: &str,
        patch: &serde_json::Value,
    ) -> Result<ACREventsSubscription, UpdateError> {
        let mut subs = self
            .acrevents_subscriptions
            .write()
            .map_err(|_| UpdateError::Internal)?;
        let stored = subs.get(subscription_id).ok_or(UpdateError::NotFound)?;

        let filtered = match patch.as_object() {
            Some(map) => serde_json::Value::Object(
                map.iter()
                    .filter(|(k, _)| ACREVENTS_PATCHABLE_FIELDS.contains(&k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            ),
            None => return Err(UpdateError::Invalid),
        };

        let mut value = serde_json::to_value(stored).map_err(|_| UpdateError::Internal)?;
        apply_merge_patch(&mut value, &filtered);
        let updated: ACREventsSubscription =
            serde_json::from_value(value).map_err(|_| UpdateError::Invalid)?;
        // Re-validate the required IEs after the merge (fail-closed).
        if updated.eec_id.trim().is_empty()
            || updated.event_ids.trim().is_empty()
            || updated.notification_destination.trim().is_empty()
            || updated.eas_ids.is_empty()
            || updated.eas_ids.iter().any(|e| e.trim().is_empty())
        {
            return Err(UpdateError::Invalid);
        }
        subs.insert(subscription_id.to_string(), updated.clone());
        log::info!("ACREventsSubscription merge-patched: subscriptionId={subscription_id}");
        Ok(updated)
    }

    /// Collect the `ACRInfoNotification` callbacks that fire for an ACR
    /// transition. Returns `(notificationDestination, body)` pairs for every
    /// subscription selected by [`ACREventsSubscription::matches`].
    ///
    /// Only `acrevents_subscriptions` is read here; the caller pre-builds the
    /// (registration-derived) `trgt_info`/`acr_status` and enqueues delivery
    /// AFTER this returns and its guard drops — collect-then-enqueue avoids the
    /// NF-context AB-BA deadlock class and never holds a lock across delivery.
    #[allow(clippy::too_many_arguments)]
    pub fn acrevents_collect(
        &self,
        event_id: &str,
        eec_id: Option<&str>,
        ue_id: Option<&str>,
        eas_id: Option<&str>,
        trgt_info: Option<TargetInfo>,
        acr_status: Option<ACRCompleteEventInfo>,
    ) -> Vec<(String, ACRInfoNotification)> {
        let subs = match self.acrevents_subscriptions.read() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        subs.iter()
            .filter(|(_, sub)| sub.matches(event_id, eec_id, ue_id, eas_id))
            .map(|(id, sub)| {
                let notif = ACRInfoNotification {
                    sub_id: id.clone(),
                    eas_id: eas_id.unwrap_or_default().to_string(),
                    event_id: event_id.to_string(),
                    ac_id: None,
                    trgt_info: trgt_info.clone(),
                    acr_status: acr_status.clone(),
                    eec_ctxt_reloc: None,
                    acr_scenario_list: None,
                    eas_bundle_info: None,
                    t_eas_end_point_bundle_list: None,
                };
                (sub.notification_destination.clone(), notif)
            })
            .collect()
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

    /// Create an ACR management event subscription (`CreateACRMngEventSubscr`,
    /// yaml:29-163); mints a `subscriptionId` (the map key) and sets the
    /// read-only `self` link. `sub` is assumed already mandatory-IE-validated by
    /// the handler.
    pub fn acrmgnt_sub_create(
        &self,
        mut sub: AcrMgntEventsSubscription,
    ) -> Option<AcrMgntEventsSubscription> {
        let mut subs = self.acr_mgnt_subscriptions.write().ok()?;
        if subs.len() >= self.max_eas {
            return None;
        }
        let id = Uuid::new_v4().to_string();
        sub.self_ = Some(format!("{ACRMGNT_SUB_COLLECTION}/{id}"));
        subs.insert(id.clone(), sub.clone());
        log::info!(
            "ACR management event subscription created: subscriptionId={id} easId={} notificationDestination={}",
            sub.eas_id,
            sub.notification_destination
        );
        Some(sub)
    }

    pub fn acrmgnt_sub_find(&self, subscription_id: &str) -> Option<AcrMgntEventsSubscription> {
        self.acr_mgnt_subscriptions
            .read()
            .ok()?
            .get(subscription_id)
            .cloned()
    }

    pub fn acrmgnt_sub_list(&self) -> Vec<AcrMgntEventsSubscription> {
        self.acr_mgnt_subscriptions
            .read()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// PUT full-replace an ACR management event subscription
    /// (`UpdateIndACRMngEventSubscr`, yaml:262-315). `sub` is assumed already
    /// mandatory-IE-validated by the handler; the immutable `self` link is
    /// re-derived from the resource id.
    pub fn acrmgnt_sub_update(
        &self,
        subscription_id: &str,
        mut sub: AcrMgntEventsSubscription,
    ) -> Result<AcrMgntEventsSubscription, UpdateError> {
        let mut subs = self
            .acr_mgnt_subscriptions
            .write()
            .map_err(|_| UpdateError::Internal)?;
        if !subs.contains_key(subscription_id) {
            return Err(UpdateError::NotFound);
        }
        sub.self_ = Some(format!("{ACRMGNT_SUB_COLLECTION}/{subscription_id}"));
        subs.insert(subscription_id.to_string(), sub.clone());
        Ok(sub)
    }

    /// PATCH merge an ACR management event subscription
    /// (`ModifyIndACRMngEventSubscr`, `application/merge-patch+json`,
    /// yaml:317-372). The RFC 7396 merge is restricted to the
    /// `AcrMgntEventsSubscriptionPatch` members (yaml:521-535); any other key —
    /// including the immutable `easId`/`self` — is ignored. The merged result is
    /// re-validated fail-closed against the required IEs.
    pub fn acrmgnt_sub_modify(
        &self,
        subscription_id: &str,
        patch: &serde_json::Value,
    ) -> Result<AcrMgntEventsSubscription, UpdateError> {
        let mut subs = self
            .acr_mgnt_subscriptions
            .write()
            .map_err(|_| UpdateError::Internal)?;
        let stored = subs.get(subscription_id).ok_or(UpdateError::NotFound)?;

        // Restrict the merge document to the spec AcrMgntEventsSubscriptionPatch keys.
        let filtered = match patch.as_object() {
            Some(map) => serde_json::Value::Object(
                map.iter()
                    .filter(|(k, _)| ACRMGNT_PATCHABLE_FIELDS.contains(&k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            ),
            None => return Err(UpdateError::Invalid),
        };

        let mut value = serde_json::to_value(stored).map_err(|_| UpdateError::Internal)?;
        apply_merge_patch(&mut value, &filtered);
        let mut updated: AcrMgntEventsSubscription =
            serde_json::from_value(value).map_err(|_| UpdateError::Invalid)?;
        // Re-validate required IEs after merge (a patch may clear eventSubscs or
        // notificationDestination).
        if updated.eas_id.trim().is_empty()
            || updated.notification_destination.trim().is_empty()
            || updated.event_subscs.is_empty()
            || updated
                .event_subscs
                .iter()
                .any(|e| e.event.trim().is_empty())
        {
            return Err(UpdateError::Invalid);
        }
        updated.self_ = Some(format!("{ACRMGNT_SUB_COLLECTION}/{subscription_id}"));
        subs.insert(subscription_id.to_string(), updated.clone());
        log::info!(
            "ACR management event subscription merge-patched: subscriptionId={subscription_id}"
        );
        Ok(updated)
    }

    pub fn acrmgnt_sub_delete(&self, subscription_id: &str) -> Option<AcrMgntEventsSubscription> {
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

    /// Build + enqueue an `AcrMgntEventsNotification` (yaml:537-554) for every
    /// subscription whose `eventSubscs` include the fired `event` (and, when a
    /// per-event `appGrpId` filter is present, only when it matches). Returns
    /// the number of matched subscriptions (kept for testability).
    ///
    /// Delivery is fire-and-forget via the shared notifier (D6): the callback
    /// `(uri, body)` pairs are collected UNDER the read lock and enqueued only
    /// AFTER it is released — the documented NF-context AB-BA rule (the notifier
    /// must never be invoked while holding the `EesContext` lock).
    pub fn notify_acrmgnt_subscribers(&self, event: &str, app_grp_id: Option<&str>) -> usize {
        let mut pending: Vec<(String, serde_json::Value)> = Vec::new();
        {
            let subs = match self.acr_mgnt_subscriptions.read() {
                Ok(s) => s,
                Err(_) => return 0,
            };
            for (id, sub) in subs.iter() {
                let matches = sub.event_subscs.iter().any(|es| {
                    es.event == event
                        && es
                            .app_grp_id
                            .as_deref()
                            .is_none_or(|g| Some(g) == app_grp_id)
                });
                if !matches {
                    continue;
                }
                let notif = AcrMgntEventsNotification {
                    subp_id: id.clone(),
                    event_reports: vec![AcrMgntEventReport {
                        event: event.to_string(),
                        ..Default::default()
                    }],
                };
                if let Ok(body) = serde_json::to_value(&notif) {
                    pending.push((sub.notification_destination.clone(), body));
                }
            }
        }
        let matched = pending.len();
        for (uri, body) in pending {
            crate::notifier::enqueue(uri, body, "AcrMgntEventsNotification");
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

    /// eesd-05 (D6): discovery subscription create/find/delete + notify builds a
    /// spec `EasDiscoveryNotification` and enqueues it via the shared notifier
    /// (collect-then-enqueue; asserted through a fresh `QueueNotifier`).
    #[test]
    fn test_disc_subscription_and_notify() {
        use crate::notifier::Notifier;
        use crate::types::EasDiscoveryNotification;

        // Serialize with the other tests that swap the process-global notifier
        // and install a fresh queue to inspect.
        let _g = crate::auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let n = Arc::new(crate::notifier::QueueNotifier::default());
        crate::notifier::set_notifier(n.clone());
        let _ = n.drain();

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

        // Exactly one spec-shaped EasDiscoveryNotification was enqueued.
        let queued = n.drain();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].uri, "http://eec/callback");
        assert_eq!(queued[0].kind, "EasDiscoveryNotification");
        let notif: EasDiscoveryNotification =
            serde_json::from_value(queued[0].body.clone()).unwrap();
        assert_eq!(notif.sub_id, sub_id);
        assert_eq!(notif.event_type, "EAS_AVAILABILITY_CHANGE");
        assert_eq!(notif.discovered_eas.len(), 1);
        assert_eq!(notif.discovered_eas[0].eas.eas_id, "eas1.example.com");

        // A non-matching EAS fires nothing.
        let ar = make_reg("eas9.example.com", "AR");
        assert_eq!(ctx.notify_discovery_subscribers(&ar.eas_prof), 0);
        assert!(n.drain().is_empty());

        assert!(ctx.disc_sub_delete(&sub_id).is_some());
        assert!(ctx.disc_sub_find(&sub_id).is_none());

        // Restore the default notifier for the rest of the suite.
        crate::notifier::set_notifier(Arc::new(crate::notifier::QueueNotifier::default()));
    }

    /// D7: `notify_acrmgnt_subscribers` fires only for subscriptions whose
    /// `eventSubscs` include the event (respecting a per-event `appGrpId`
    /// filter), builds a spec `AcrMgntEventsNotification`, and enqueues it via
    /// the shared notifier (collect-then-enqueue; no ctx lock held across the
    /// enqueue).
    #[test]
    fn test_acrmgnt_notify_builds_and_enqueues() {
        use crate::notifier::Notifier;
        use crate::services::{AcrMgntEventSubsc, AcrMgntEventsSubscription};

        fn subsc(event: &str, app_grp_id: Option<&str>) -> AcrMgntEventSubsc {
            AcrMgntEventSubsc {
                event: event.into(),
                app_grp_id: app_grp_id.map(str::to_string),
                event_filter: None,
                evt_req: None,
                tgt_ue_id: None,
                dnai_chg_type: None,
                eas_ack_ind: None,
                eas_chars: None,
                traf_filter_info: None,
                serv_cont_plan_ind: None,
                eas_ack_svc_cont: None,
            }
        }
        fn subscription(
            eas: &str,
            dest: &str,
            subs: Vec<AcrMgntEventSubsc>,
        ) -> AcrMgntEventsSubscription {
            AcrMgntEventsSubscription {
                self_: None,
                eas_id: eas.into(),
                event_subscs: subs,
                evt_req: None,
                notification_destination: dest.into(),
                event_reports: None,
                availability_info: None,
                fail_event_reports: None,
                request_test_notification: None,
                websock_notif_config: None,
                supp_feat: None,
            }
        }

        // Serialize with the other tests that touch the process-global notifier
        // (e.g. acrevents requestTestNotification), then install a fresh queue.
        let _g = crate::auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let n = Arc::new(crate::notifier::QueueNotifier::default());
        crate::notifier::set_notifier(n.clone());
        let _ = n.drain();

        let mut ctx = EesContext::new();
        ctx.init(8);
        // A: UP_PATH_CHG filtered to appGrpId "grp-1".
        ctx.acrmgnt_sub_create(subscription(
            "eas-a.example.com",
            "http://eec-a/cb",
            vec![subsc("UP_PATH_CHG", Some("grp-1"))],
        ))
        .unwrap();
        // B: ACR_MONITORING, no appGrpId filter (matches any group).
        ctx.acrmgnt_sub_create(subscription(
            "eas-b.example.com",
            "http://eec-b/cb",
            vec![subsc("ACR_MONITORING", None)],
        ))
        .unwrap();

        // UP_PATH_CHG for grp-1 → only A; grp-2 → A's filter excludes it → 0.
        assert_eq!(
            ctx.notify_acrmgnt_subscribers("UP_PATH_CHG", Some("grp-1")),
            1
        );
        assert_eq!(
            ctx.notify_acrmgnt_subscribers("UP_PATH_CHG", Some("grp-2")),
            0
        );
        // ACR_MONITORING (any group) → only B (unfiltered).
        assert_eq!(
            ctx.notify_acrmgnt_subscribers("ACR_MONITORING", Some("grp-9")),
            1
        );

        // Exactly the two matched notifications were enqueued as spec-shaped
        // AcrMgntEventsNotification bodies.
        let queued = n.drain();
        assert_eq!(queued.len(), 2);
        assert!(queued.iter().all(|q| q.kind == "AcrMgntEventsNotification"));
        let a = queued.iter().find(|q| q.uri == "http://eec-a/cb").unwrap();
        let notif: AcrMgntEventsNotification = serde_json::from_value(a.body.clone()).unwrap();
        assert!(!notif.subp_id.is_empty());
        assert_eq!(notif.event_reports.len(), 1);
        assert_eq!(notif.event_reports[0].event, "UP_PATH_CHG");

        // Restore the default notifier for the other tests.
        crate::notifier::set_notifier(Arc::new(crate::notifier::QueueNotifier::default()));
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
