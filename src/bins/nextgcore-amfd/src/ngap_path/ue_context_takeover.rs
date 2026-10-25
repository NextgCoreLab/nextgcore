//! #686 PR 2: an AMF of the AMF Set takes over a UE whose AMF failed.
//!
//! TS 23.501 §5.21.2.3 (AMF auto-recovery, with a UDSF):
//! - the 5G-AN selects "a different AMF from the same AMF set" for a UE whose AMF is
//!   marked failed, and "for deployments with UDSF, any AMF from the same AMF set can be
//!   selected";
//! - "the newly selected AMF retrieves the UE context from the UDSF using SUPI, 5G-GUTI
//!   or AMF UE NGAP ID and it processes the UE message accordingly and updates the
//!   5G-GUTI towards the UE, if necessary";
//! - "When there is a transaction with the UE, the new AMF updates the peer NFs ... with
//!   the new AMF information".
//!
//! TS 23.502 §4.2.2.2.2 step 4 says the same for a Registration ("the new AMF retrieves
//! the stored UE's SUPI and UE context directly from the UDSF").
//!
//! TS 23.527 was not available when this was written (archive downloads are denied in
//! this environment). Its restoration clauses are still to be checked.
//!
//! Here:
//! - **Lookup.** An initial SERVICE REQUEST, or an integrity-protected REGISTRATION
//!   REQUEST, that names a 5G-S-TMSI / 5G-GUTI of this AMF Set which no UE here holds is
//!   looked up in the storage entity, off the NGAP task.
//! - **Claim.** A record another AMF instance wrote is claimed by compare-and-set on the
//!   writer instance (Annex C item 3), restored as a registered CM-IDLE UE, and the
//!   Initial UE Message is processed again.
//! - **Verify.** Integrity checking runs under the stored context as for any CM-IDLE UE.
//! - **Peer updates.** Once the message is verified, this AMF:
//!   - registers with the UDM as the serving AMF (Nudm_UECM_Registration, TS 29.503
//!     §5.3.2.2.2), under its own nfInstanceId and a new `deregCallbackUri`;
//!   - tells each SMF it serves the SM context: `servingNfId`, `smContextStatusUri`,
//!     `guami` and `servingNetwork` (TS 29.502 Table 6.1.6.2.2-1);
//!   - gives the UE a 5G-GUTI of its own GUAMI: in the Registration Accept, or after
//!     the Service Accept with a UE Configuration Update (TS 24.501 §5.4.4). The backup
//!     AMF "shall not use old GUAMI to allocate 5G-GUTI".
//!
//! Peers holding subscriptions of the old AMF (the UDM's SDM subscription, the PCF's AM
//! policy association) re-address their notifications themselves: "the CP NF shall
//! exchange the old AMF information embedded in the Notification Address with the new
//! AMF information" (§5.21.2.3).

use super::ue_context_store::{STmsi, StoredUeContext};
use super::*;

/// What a takeover lookup found, applied on the NGAP task.
#[derive(Debug)]
pub(crate) struct TakeoverAnswer {
    /// The identity looked up: every Initial UE Message held for it is processed again
    /// once the lookup is applied (`NgapServer::pending_takeovers`).
    pub(crate) s_tmsi: STmsi,
    pub(crate) record: Option<Box<StoredUeContext>>,
}

/// The UDM's answer to a takeover's UECM registration.
#[derive(Debug)]
pub(crate) struct TakeoverUecmAnswer {
    pub(crate) supi: String,
    /// The `deregCallbackUri` token registered, kept only if the UDM accepted it (#753).
    pub(crate) token: String,
    pub(crate) accepted: bool,
}

/// Whether another AMF instance's record holds a UE this AMF was told to deregister
/// locally (#1185 review M1).
#[derive(Debug)]
pub(crate) struct DeregOwnerAnswer {
    pub(crate) amf_ue_ngap_id: u64,
    /// The record names another AMF instance: the UE was taken over.
    pub(crate) moved: bool,
    /// What runs when it was not.
    pub(crate) then: AfterOwnerCheck,
}

/// The deregistration an owner check stands before (#1185 review M1, m1). Both release
/// the UE's PDU sessions and policy associations, which a taken-over UE's are not this
/// AMF's to release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AfterOwnerCheck {
    /// The local deregistration a Nudm_UECM_DeregistrationNotification asks for (#602).
    LocalDeregistration,
    /// The implicit deregistration timer expired (TS 24.501 §5.3.7).
    ImplicitDeregistration,
}

/// Which message a taken-over UE came back with: it decides how its new 5G-GUTI goes out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TakeoverVia {
    /// The Registration Accept carries the new 5G-GUTI.
    Registration,
    /// A UE Configuration Update after the Service Accept carries it.
    Service,
}

impl NgapServer {
    /// The 5G-S-TMSI to look for in the store, when `nas` (an initial NAS message) names
    /// one of this AMF Set that no UE here holds.
    ///
    /// `None` in all of these cases:
    /// - the storage is off;
    /// - the message is neither a SERVICE REQUEST nor an integrity-protected
    ///   REGISTRATION REQUEST identified by a 5G-GUTI;
    /// - the identity belongs to another AMF Set;
    /// - a UE here already holds it.
    pub(super) fn takeover_candidate(&self, nas: &[u8]) -> Option<STmsi> {
        self.ue_context_store.as_ref()?;
        let served = self.served_guamis();
        let s_tmsi = match initial_service_request_plain(nas) {
            Some(plain) => service_request_s_tmsi(&plain)?,
            None => {
                let cleartext = initial_protected_registration_request(nas)?;
                let guti = parse_registration_request_pdu(cleartext)
                    .filter(|r| r.identity_type == mobile_identity_type::GUTI)
                    .and_then(|r| r.guti)?;
                let same_region = served.is_empty()
                    || served.iter().any(|(plmn, region, set, _)| {
                        *plmn == guti.plmn_id
                            && *region == guti.amf_region_id
                            && *set == guti.amf_set_id
                    });
                if !same_region {
                    return None;
                }
                (guti.amf_set_id, guti.amf_pointer, guti.tmsi)
            }
        };
        let (set, pointer, tmsi) = s_tmsi;
        if !served.is_empty() && !served.iter().any(|(_, _, s, _)| *s == set) {
            return None;
        }
        // #1185 review m3: looked up by 5G-GUTI under each served GUAMI of the set, not by
        // copying every UE context.
        let held = if served.is_empty() {
            self.ue_auth_state.snapshot().into_iter().any(|(_, st)| {
                let g = &st.amf_ue.current_guti;
                st.registered && g.amf_set_id == set && g.amf_pointer == pointer && g.tmsi == tmsi
            })
        } else {
            served
                .iter()
                .filter(|(_, _, s, _)| *s == set)
                .any(|(plmn, region, _, _)| {
                    let guti = crate::context::Guti5gs {
                        plmn_id: plmn.clone(),
                        amf_region_id: *region,
                        amf_set_id: set,
                        amf_pointer: pointer,
                        tmsi,
                    };
                    self.ue_auth_state
                        .find_by_guti(&guti)
                        .is_some_and(|(_, st)| st.registered)
                })
        };
        (!held).then_some(s_tmsi)
    }

    /// Look `s_tmsi` up in the store and claim it, off the NGAP task. The outcome
    /// re-processes `initial_ue_message`, with or without a context.
    pub(super) fn start_takeover(
        &mut self,
        association_id: u64,
        initial_ue_message: Vec<u8>,
        s_tmsi: STmsi,
    ) {
        // #1185 review m2: a second Initial UE Message for an identity being looked up
        // (a retransmission, a second RRC attempt) waits for the same lookup, rather than
        // finding the record already claimed and being rejected.
        if let Some(waiting) = self.pending_takeovers.get_mut(&s_tmsi) {
            waiting.push((association_id, initial_ue_message));
            return;
        }
        let Some(store) = self.ue_context_store.as_ref() else {
            return;
        };
        let backend = Arc::clone(&store.backend);
        self.pending_takeovers
            .insert(s_tmsi, vec![(association_id, initial_ue_message)]);
        let instance = self.amf_instance();
        log::info!(
            "Initial UE Message names 5G-S-TMSI {:#05x}/{:#04x}/{:#010x} of this AMF Set, held \
             by no UE here: looking for its stored context (TS 23.501 §5.21.2.3)",
            s_tmsi.0,
            s_tmsi.1,
            s_tmsi.2
        );
        self.sbi_offload.spawn(async move {
            let found =
                tokio::task::spawn_blocking(move || backend.take_over(s_tmsi, &instance)).await;
            let record = match found {
                Ok(Ok(record)) => record.map(Box::new),
                Ok(Err(e)) => {
                    log::warn!("Stored UE context lookup failed: {e}");
                    None
                }
                Err(e) => {
                    log::warn!("Stored UE context lookup panicked: {e}");
                    None
                }
            };
            Some(crate::sbi_offload::SbiOutcome::Takeover(TakeoverAnswer {
                s_tmsi,
                record,
            }))
        });
    }

    /// Restore the claimed context, if any, as a registered CM-IDLE UE owed the takeover's
    /// peer updates, then process the Initial UE Message as if it had just arrived.
    pub(super) async fn apply_takeover(&mut self, answer: TakeoverAnswer) -> Result<()> {
        if let Some(rec) = answer.record {
            let held = self
                .ue_auth_state
                .find_by_supi(&rec.supi)
                .is_some_and(|(_, s)| s.registered);
            if held {
                log::info!(
                    "UE {} registered here while its context was being fetched; the stored one \
                     is not used",
                    rec.supi
                );
            } else if let Some(id) = self.install_restored(&rec) {
                self.ue_auth_state.with_mut(id, |s| {
                    // The UE is in 5GMM-IDLE here whatever it was at its old AMF: this
                    // Initial UE Message opens its N1 connection.
                    s.cm_idle = true;
                    s.taken_over = true;
                });
                self.start_reachability_supervision(id).await;
                log::info!(
                    "UE context of {} taken over from AMF instance it was stored by, as UE {id} \
                     ({} PDU session(s))",
                    rec.supi,
                    rec.sessions.len()
                );
            }
        } else {
            log::info!("No stored context claimed for the Initial UE Message; processed as is");
        }
        let waiting = self
            .pending_takeovers
            .remove(&answer.s_tmsi)
            .unwrap_or_default();
        // Each held message is processed; one that fails does not drop the others.
        for (association_id, message) in waiting {
            if let Err(e) = self
                .handle_initial_ue_message_with(association_id, &message, false)
                .await
            {
                log::warn!("A held Initial UE Message was not processed: {e}");
            }
        }
        Ok(())
    }

    /// The takeover's peer updates for UE `amf_ue_ngap_id`, once its message verified
    /// under the taken-over context. They are owed once; a no-op for any other UE.
    /// Called on the NGAP task before the procedure's own SMF exchanges are queued, so
    /// each SMF learns of the new AMF first.
    pub(super) fn complete_takeover(&mut self, amf_ue_ngap_id: u64, via: TakeoverVia) {
        let our = self.served_guamis().first().cloned();
        let Some(state) = self
            .ue_auth_state
            .with_mut(amf_ue_ngap_id, |s| {
                if !std::mem::take(&mut s.taken_over) {
                    return None;
                }
                let (plmn, region, set, pointer) = our.clone().unwrap_or((
                    s.amf_ue.nr_tai.plmn_id.clone(),
                    s.amf_ue.current_guti.amf_region_id,
                    s.amf_ue.current_guti.amf_set_id,
                    s.amf_ue.current_guti.amf_pointer,
                ));
                match via {
                    TakeoverVia::Registration => {
                        // The Accept carries `next_guti`; the UE takes it at Complete.
                        s.amf_ue.next_guti = s.amf_ue.current_guti.clone();
                        s.amf_ue.generate_new_guti();
                        s.amf_ue.next_guti.plmn_id = plmn;
                        s.amf_ue.next_guti.amf_region_id = region;
                        s.amf_ue.next_guti.amf_set_id = set;
                        s.amf_ue.next_guti.amf_pointer = pointer;
                    }
                    TakeoverVia::Service => s.guti_reallocation_owed = true,
                }
                Some(s.clone())
            })
            .flatten()
        else {
            return;
        };
        let Some(supi) = state.amf_ue.supi.clone() else {
            return;
        };
        let instance = self.amf_instance();
        let (plmn, region, set, pointer) = our.unwrap_or((
            state.amf_ue.nr_tai.plmn_id.clone(),
            state.amf_ue.current_guti.amf_region_id,
            state.amf_ue.current_guti.amf_set_id,
            state.amf_ue.current_guti.amf_pointer,
        ));
        let amf_id_hex = crate::sbi_path::amf_id_hex(&crate::context::AmfId {
            region,
            set,
            pointer,
        });
        let (guami_mcc, guami_mnc) = plmn_mcc_mnc_strings(&plmn);
        let (serving_mcc, serving_mnc) = plmn_mcc_mnc_strings(&state.amf_ue.nr_tai.plmn_id);
        log::info!(
            "UE {amf_ue_ngap_id} ({supi}) taken over: registering with the UDM and telling \
             its SMFs this AMF serves it"
        );

        // The UDM: this AMF is the serving AMF now (TS 29.503 §5.3.2.2.2).
        let udm = self.udm_for_takeover();
        let token = crate::sbi_path::new_dereg_callback_token();
        let (uecm_supi, uecm_instance, uecm_mcc, uecm_mnc, uecm_amf_id) = (
            supi.clone(),
            instance.clone(),
            guami_mcc.clone(),
            guami_mnc.clone(),
            amf_id_hex.clone(),
        );
        self.sbi_offload.spawn(async move {
            let (host, port) = match udm {
                Some(udm) => udm,
                None => crate::sbi_path::resolve_nf_endpoint_async(
                    crate::sbi_path::SbiServiceType::NudmUecm,
                )
                .await
                .unwrap_or_else(|_| ("127.0.0.1".to_string(), 7777)),
            };
            let result = crate::sbi_path::call_udm_uecm_registration(
                &host,
                port,
                &uecm_supi,
                &uecm_instance,
                &token,
                &uecm_mcc,
                &uecm_mnc,
                &uecm_amf_id,
            )
            .await;
            if let Err(e) = &result {
                log::warn!("[{uecm_supi}] takeover UECM registration failed: {e}");
            }
            Some(crate::sbi_offload::SbiOutcome::TakeoverUecm(
                TakeoverUecmAnswer {
                    supi: uecm_supi,
                    token,
                    accepted: result.is_ok(),
                },
            ))
        });

        // Each SMF: the new serving AMF, keyed on the session so it precedes the
        // procedure's own exchanges for it.
        for (psi, sm_ref, host, port) in self.ue_sm_contexts(amf_ue_ngap_id) {
            let serving = serde_json::json!({
                "servingNfId": instance,
                "smContextStatusUri": crate::sbi_path::sm_context_status_uri(&supi, psi),
                "guami": {
                    "plmnId": { "mcc": guami_mcc, "mnc": guami_mnc },
                    "amfId": amf_id_hex,
                },
                "servingNetwork": { "mcc": serving_mcc, "mnc": serving_mnc },
            });
            self.sbi_offload
                .spawn_keyed_durable((amf_ue_ngap_id, psi), move || async move {
                    if let Err(e) =
                        crate::sbi_path::call_smf_update_serving_amf(&host, port, &sm_ref, &serving)
                            .await
                    {
                        log::warn!(
                            "UE {amf_ue_ngap_id}: PSI {psi}'s SMF was not told of the new \
                             serving AMF: {e}"
                        );
                    }
                    None
                });
        }
    }

    /// Record the UDM's answer to a takeover's UECM registration: the new
    /// `deregCallbackUri` token is the UE's only once the UDM accepted it (#753).
    pub(super) fn apply_takeover_uecm(&mut self, answer: TakeoverUecmAnswer) {
        if !answer.accepted {
            return;
        }
        if let Some((id, _)) = self.ue_auth_state.find_by_supi(&answer.supi) {
            self.ue_auth_state.with_mut(id, |s| {
                s.amf_ue.uecm_dereg_token = Some(answer.token.clone());
            });
        }
    }

    /// The UDM a takeover registers with: `None` resolves it as registration does. Tests
    /// pin a stand-in with `udm_override` (the resolution reads process-global state).
    fn udm_for_takeover(&self) -> Option<(String, u16)> {
        #[cfg(test)]
        if let Some(udm) = &self.udm_override {
            return Some(udm.clone());
        }
        None
    }

    /// A UE another AMF of the set took over (#1185 review M1): forgotten here, with no
    /// NAS message, no SM context release and no policy termination. Its context,
    /// sessions and policy associations belong to the new AMF (TS 23.502 §4.2.2.2.2
    /// step 14d: SM contexts are released only for an Initial Registration, and policy
    /// associations only when not transferred). A UE with an N2 connection here has it
    /// released (AN release, same step).
    pub(super) async fn forget_moved_ue(&mut self, supi: &str) {
        let Some((id, state)) = self.ue_auth_state.find_by_supi(supi) else {
            return;
        };
        log::info!(
            "UE {id} ({supi}) is served by another AMF of the set now; its context is \
             forgotten here, its sessions and policies stay with the new AMF"
        );
        if !state.cm_idle && state.is_bound() {
            if let Err(e) = self
                .release_ue(
                    state.association_id,
                    id,
                    state.ran_ue_ngap_id,
                    // Cause: NAS deregister (TS 38.413 Section 9.3.1.2, CauseNas value 2)
                    2,
                )
                .await
            {
                log::warn!("UE Context Release Command for UE {id} not sent: {e}");
            }
        } else {
            self.forget_ue(id);
        }
        self.forget_global_ue_entries(id, &state);
    }

    /// Before a deregistration that releases the UE's sessions and policies (`then`),
    /// with the store armed: ask, off the NGAP task, whose the UE's record is. `true` when
    /// the question was asked (the answer decides, [`Self::apply_dereg_owner`]); `false`
    /// when the deregistration goes ahead now. A lookup that fails counts as "not moved",
    /// so the deregistration still runs: an unreachable store must not keep a UE this AMF
    /// serves registered forever.
    pub(super) fn check_owner_before(
        &mut self,
        amf_ue_ngap_id: u64,
        then: AfterOwnerCheck,
    ) -> bool {
        let Some(store) = self.ue_context_store.as_ref() else {
            return false;
        };
        let Some(supi) = self
            .ue_auth_state
            .get(amf_ue_ngap_id)
            .and_then(|s| s.amf_ue.supi.clone())
        else {
            return false;
        };
        let backend = Arc::clone(&store.backend);
        let instance = self.amf_instance();
        self.sbi_offload.spawn(async move {
            let owner = tokio::task::spawn_blocking(move || backend.owner(&supi)).await;
            let moved = matches!(owner, Ok(Ok(Some(o))) if o != instance);
            Some(crate::sbi_offload::SbiOutcome::DeregOwner(
                DeregOwnerAnswer {
                    amf_ue_ngap_id,
                    moved,
                    then,
                },
            ))
        });
        true
    }

    /// Apply [`Self::check_owner_before_local_dereg`]'s answer.
    pub(super) async fn apply_dereg_owner(&mut self, answer: DeregOwnerAnswer) {
        if answer.moved {
            if let Some(supi) = self
                .ue_auth_state
                .get(answer.amf_ue_ngap_id)
                .and_then(|s| s.amf_ue.supi.clone())
            {
                self.forget_moved_ue(&supi).await;
            }
        } else {
            match answer.then {
                AfterOwnerCheck::LocalDeregistration => {
                    if let Err(e) = self.local_deregistration(answer.amf_ue_ngap_id).await {
                        log::warn!(
                            "Local deregistration for UE {} failed: {e}",
                            answer.amf_ue_ngap_id
                        );
                    }
                }
                AfterOwnerCheck::ImplicitDeregistration => {
                    self.implicit_deregistration(answer.amf_ue_ngap_id).await;
                }
            }
        }
    }
}
