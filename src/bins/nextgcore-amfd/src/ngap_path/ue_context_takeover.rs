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
//!   - (#1210) subscribes to the UE's SDM data under its own `callbackReference`
//!     (Nudm_SDM_Subscribe, TS 23.502 §4.2.2.2.2 step 14c), since an
//!     `SdmSubsModification` cannot change it (TS 29.503 §6.1.6.2.31), and then removes
//!     the old AMF's subscription, which the failed AMF cannot do (§5.2.2.4.2). With
//!     `implicitUnsubscribe` the UDM may already have dropped it, so a 404 is fine.
//!   - (#1210) points the PCF's AM and UE policy associations at itself:
//!     `notificationUri` and `guami` (TS 29.507 §4.2.3.1), and `notificationUri`,
//!     `guami` and `servingNfId` (TS 29.525 §4.2.3.1). Both clauses let "an AMF [that]
//!     knows by implementation specific means that the UE context has been transferred
//!     to an AMF with another GUAMI within the AMF set" update them, and §5.21.2.3 has
//!     "the new AMF update[] the peer NFs ... with the new AMF information".

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
    /// #1210: the SDM subscription this AMF made after the registration, if the UDM
    /// accepted it.
    pub(crate) sdm_subscription_id: Option<String>,
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
    /// under the taken-over context, or under a context this AMF restored after its own
    /// restart (#1329: same updates, no GUTI reallocation). They are owed once; a no-op
    /// for any other UE.
    /// Called on the NGAP task before the procedure's own SMF exchanges are queued, so
    /// each SMF learns of the new AMF first.
    pub(super) fn complete_takeover(&mut self, amf_ue_ngap_id: u64, via: TakeoverVia) {
        let our = self.served_guamis().first().cloned();
        let Some(state) = self
            .ue_auth_state
            .with_mut(amf_ue_ngap_id, |s| {
                let taken_over = std::mem::take(&mut s.taken_over);
                let peers_stale = std::mem::take(&mut s.peers_stale);
                if !taken_over && !peers_stale {
                    return None;
                }
                // #1329: a restart restore keeps its GUAMI, so its 5G-GUTI stays; only
                // the peers' callback addresses moved.
                if !taken_over {
                    return Some((false, s.clone()));
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
                Some((true, s.clone()))
            })
            .flatten()
        else {
            return;
        };
        let (taken_over, state) = state;
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
        if taken_over {
            log::info!(
                "UE {amf_ue_ngap_id} ({supi}) taken over: registering with the UDM and telling \
                 its SMFs this AMF serves it"
            );
        } else {
            log::info!(
                "UE {amf_ue_ngap_id} ({supi}) restored after this AMF's restart: giving the UDM \
                 and the PCF this process's callback addresses (its SMFs had them at restore)"
            );
        }

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
        let old_sdm_subscription = state.sdm_subscription_id.clone();
        self.sbi_offload.spawn(async move {
            let (host, port) = match udm {
                Some(udm) => udm,
                None => crate::sbi_path::resolve_nf_endpoint_async(
                    crate::sbi_path::SbiServiceType::NudmUecm,
                )
                .await
                .unwrap_or_else(|_| ("127.0.0.1".to_string(), 7777)),
            };
            let result = crate::sbi_path::retry_peer_update("UECM registration", || {
                crate::sbi_path::call_udm_uecm_registration(
                    &host,
                    port,
                    &uecm_supi,
                    &uecm_instance,
                    &token,
                    &uecm_mcc,
                    &uecm_mnc,
                    &uecm_amf_id,
                )
            })
            .await;
            if let Err(e) = &result {
                log::warn!("[{uecm_supi}] takeover UECM registration failed: {e}");
            }
            // #1210: the SDM subscription, after the registration: with
            // `implicitUnsubscribe` the UDM ends the old AMF's when this AMF registers.
            let sdm_subscription_id = if result.is_ok() {
                takeover_sdm_resubscribe(
                    &host,
                    port,
                    &uecm_supi,
                    &uecm_instance,
                    old_sdm_subscription.as_deref(),
                )
                .await
            } else {
                None
            };
            Some(crate::sbi_offload::SbiOutcome::TakeoverUecm(
                TakeoverUecmAnswer {
                    supi: uecm_supi,
                    token,
                    accepted: result.is_ok(),
                    sdm_subscription_id,
                },
            ))
        });

        // Each SMF: the new serving AMF, keyed on the session so it precedes the
        // procedure's own exchanges for it. #1329 review M1: a restart restore told
        // its SMFs at restore time (`point_smfs_at_self`), so only a takeover here.
        if taken_over {
            self.spawn_smf_serving_updates(amf_ue_ngap_id, &state, false);
        }

        // #1210: the PCF's policy associations now notify this AMF.
        let guami = serde_json::json!({
            "plmnId": { "mcc": guami_mcc, "mnc": guami_mnc },
            "amfId": amf_id_hex,
        });
        let pcf = self.pcf_for_takeover();
        if let Some(pol_asso_id) = state.policy_association_id.clone() {
            let (uri, guami, pcf) = (
                crate::sbi_path::am_policy_notification_uri(&supi),
                guami.clone(),
                pcf.clone(),
            );
            self.sbi_offload.spawn(async move {
                let (host, port) = takeover_pcf(pcf).await;
                if let Err(e) = crate::sbi_path::retry_peer_update("AM policy update", || {
                    crate::sbi_path::call_pcf_am_policy_update_serving_amf(
                        &host,
                        port,
                        &pol_asso_id,
                        &uri,
                        &guami,
                    )
                })
                .await
                {
                    log::warn!(
                        "UE {amf_ue_ngap_id}: AM policy association {pol_asso_id} not pointed \
                         at the new serving AMF: {e}"
                    );
                }
                None
            });
        }
        if let Some(pol_asso_id) = state.ue_policy_association_id.clone() {
            let uri = crate::sbi_path::ue_policy_notification_uri(&supi);
            self.sbi_offload.spawn(async move {
                let (host, port) = takeover_pcf(pcf).await;
                if let Err(e) = crate::sbi_path::retry_peer_update("UE policy update", || {
                    crate::sbi_path::call_pcf_ue_policy_update_serving_amf(
                        &host,
                        port,
                        &pol_asso_id,
                        &uri,
                        &guami,
                        &instance,
                    )
                })
                .await
                {
                    log::warn!(
                        "UE {amf_ue_ngap_id}: UE policy association {pol_asso_id} not pointed \
                         at the new serving AMF: {e}"
                    );
                }
                None
            });
        }
    }

    /// Record the UDM's answer to a takeover's UECM registration: the new
    /// `deregCallbackUri` token is the UE's only once the UDM accepted it (#753).
    /// The serving-AMF identity this AMF gives a peer for UE `state`: its nfInstanceId,
    /// its GUAMI's AMF ID (hex) and PLMN, and the UE's serving PLMN.
    fn serving_identity(
        &self,
        state: &UeNasContext,
    ) -> (String, String, String, String, String, String) {
        let instance = self.amf_instance();
        let (plmn, region, set, pointer) = self.served_guamis().first().cloned().unwrap_or((
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
        (
            instance,
            amf_id_hex,
            guami_mcc,
            guami_mnc,
            serving_mcc,
            serving_mnc,
        )
    }

    /// Tell each SMF of UE `amf_ue_ngap_id` that this AMF serves its SM context, with
    /// this process's `smContextStatusUri` (TS 29.502 Table 6.1.6.2.2-1): the SMF sends
    /// its status notifications and N1N2 transfers, paging among them, there.
    ///
    /// Each attempt is keyed on the session and durable, so it is serialised with the
    /// session's other exchanges and not dropped, and the first precedes the session's
    /// exchanges queued after it. A failed attempt is retried as
    /// [`crate::sbi_path::peer_update_retry_wait`] says (not after a definitive 4xx),
    /// but its backoff holds neither the key nor a permit (#1329 review): the UE's own
    /// procedures for the session (a Service Request's ACTIVATING, a release) run
    /// meanwhile, and the retry is queued behind them. `at_restore`: a restart
    /// restore's update, which also waits its turn at [`RestorePeerLimits`].
    pub(super) fn spawn_smf_serving_updates(
        &mut self,
        amf_ue_ngap_id: u64,
        state: &UeNasContext,
        at_restore: bool,
    ) {
        let Some(supi) = state.amf_ue.supi.clone() else {
            return;
        };
        let (instance, amf_id_hex, guami_mcc, guami_mnc, serving_mcc, serving_mnc) =
            self.serving_identity(state);
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
            let update = ServingUpdate {
                amf_ue_ngap_id,
                psi,
                host,
                port,
                sm_ref,
                serving,
                attempt: 1,
                limits: at_restore.then(|| Arc::clone(&self.restore_peer_limits)),
            };
            self.sbi_offload
                .spawn_keyed_requeueable((amf_ue_ngap_id, psi), update.job(None));
        }
    }

    /// #1329 review M1: after this AMF's restart, every restored UE's SMFs learn this
    /// process's addresses AT RESTORE, not at the UE's next message. An idle UE may send
    /// nothing for a long time, and the SMF pages it through the `smContextStatusUri`
    /// it holds (smfd's paging N1N2MessageTransfer): until then that is the dead pod's,
    /// and downlink data would page nobody. The record is this AMF's own and the GUAMI
    /// is unchanged, so nothing waits on the UE.
    pub(super) fn point_smfs_at_self(&mut self, amf_ue_ngap_id: u64) {
        let Some(state) = self.ue_auth_state.get(amf_ue_ngap_id) else {
            return;
        };
        self.spawn_smf_serving_updates(amf_ue_ngap_id, &state, true);
    }

    pub(super) fn apply_takeover_uecm(&mut self, answer: TakeoverUecmAnswer) {
        if !answer.accepted {
            return;
        }
        if let Some((id, _)) = self.ue_auth_state.find_by_supi(&answer.supi) {
            self.ue_auth_state.with_mut(id, |s| {
                s.amf_ue.uecm_dereg_token = Some(answer.token.clone());
                // #1210: this AMF's own SDM subscription replaces the old AMF's.
                if let Some(sub) = &answer.sdm_subscription_id {
                    s.sdm_subscription_id = Some(sub.clone());
                }
            });
        }
    }

    /// The PCF a takeover re-points the policy associations at: `None` resolves it as
    /// their termination does. Tests pin a stand-in with `pcf_override`.
    fn pcf_for_takeover(&self) -> Option<(String, u16)> {
        #[cfg(test)]
        if let Some(pcf) = &self.pcf_override {
            return Some(pcf.clone());
        }
        None
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
                    // #1185 review m1 (round 3): the timer expired a store round trip ago.
                    // A UE that came back meanwhile, or was supervised again, is not
                    // deregistered on that stale expiry.
                    let still_due = self
                        .ue_auth_state
                        .get(answer.amf_ue_ngap_id)
                        .is_some_and(|s| s.registered && s.cm_idle && s.reachability.is_none());
                    if still_due {
                        self.implicit_deregistration(answer.amf_ue_ngap_id).await;
                    } else {
                        log::info!(
                            "UE {} came back during the owner check; its implicit \
                             deregistration is dropped",
                            answer.amf_ue_ngap_id
                        );
                    }
                }
            }
        }
    }
}

/// #1210: the PCF of a taken-over UE's policy associations, `pinned` or resolved as
/// [`NgapServer::terminate_policy_associations`] resolves it.
async fn takeover_pcf(pinned: Option<(String, u16)>) -> (String, u16) {
    match pinned {
        Some(pcf) => pcf,
        None => crate::sbi_path::resolve_nf_endpoint_async(
            crate::sbi_path::SbiServiceType::NpcfAmPolicyControl,
        )
        .await
        .unwrap_or_else(|_| ("127.0.0.1".to_string(), 7777)),
    }
}

/// #1210: subscribe to a taken-over UE's SDM data under this AMF's callback, then remove
/// the old AMF's subscription `old` (TS 29.503 §5.2.2.3.2, §5.2.2.4.2). Returns the new
/// subscription's id, or `None` when the UDM refused it. The old one is then left
/// alone, so the UE keeps the notifications it has.
async fn takeover_sdm_resubscribe(
    udm_host: &str,
    udm_port: u16,
    supi: &str,
    amf_instance_id: &str,
    old: Option<&str>,
) -> Option<String> {
    let new =
        match crate::sbi_path::call_udm_sdm_subscribe(udm_host, udm_port, supi, amf_instance_id)
            .await
        {
            Ok(id) => id,
            Err(e) => {
                log::warn!("[{supi}] takeover SDM subscription failed: {e}");
                return None;
            }
        };
    if let Some(old) = old.filter(|old| *old != new) {
        if let Err(e) =
            crate::sbi_path::call_udm_sdm_unsubscribe(udm_host, udm_port, supi, old).await
        {
            log::warn!("[{supi}] the old AMF's SDM subscription {old} not removed: {e}");
        }
    }
    Some(new)
}

/// #1329 review: the bound on restart-restore serving-AMF updates in flight, overall
/// and per SMF. An update takes its permits before its attempt and gives them back
/// after it (not across a backoff), so with an SMF blackholed a large restore holds at
/// most `overall` of the offload's permits, and regular signalling keeps the rest.
#[derive(Debug)]
pub(crate) struct RestorePeerLimits {
    overall: Arc<tokio::sync::Semaphore>,
    per_smf_max: usize,
    per_smf: std::sync::Mutex<HashMap<(String, u16), Arc<tokio::sync::Semaphore>>>,
}

/// The permits one restore-time attempt holds.
type RestorePermits = (
    tokio::sync::OwnedSemaphorePermit,
    tokio::sync::OwnedSemaphorePermit,
);

impl RestorePeerLimits {
    pub(crate) fn new(overall: usize, per_smf: usize) -> Self {
        Self {
            overall: Arc::new(tokio::sync::Semaphore::new(overall.max(1))),
            per_smf_max: per_smf.max(1),
            per_smf: std::sync::Mutex::default(),
        }
    }

    fn smf(&self, host: &str, port: u16) -> Arc<tokio::sync::Semaphore> {
        let mut per_smf = self
            .per_smf
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(
            per_smf
                .entry((host.to_string(), port))
                .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(self.per_smf_max))),
        )
    }

    /// The permits for one attempt toward `host:port`, if both are free now.
    fn try_take(&self, host: &str, port: u16) -> Option<RestorePermits> {
        let smf = self.smf(host, port).try_acquire_owned().ok()?;
        let all = Arc::clone(&self.overall).try_acquire_owned().ok()?;
        Some((smf, all))
    }

    /// Wait for the permits for one attempt toward `host:port`: the SMF's first, so
    /// every waiter takes them in the same order.
    async fn take(&self, host: &str, port: u16) -> Option<RestorePermits> {
        let smf = self.smf(host, port).acquire_owned().await.ok()?;
        let all = Arc::clone(&self.overall).acquire_owned().await.ok()?;
        Some((smf, all))
    }
}

/// One SM context's serving-AMF update and how far it got.
struct ServingUpdate {
    amf_ue_ngap_id: u64,
    psi: u8,
    host: String,
    port: u16,
    sm_ref: String,
    serving: serde_json::Value,
    /// The attempt this job makes, from 1.
    attempt: u32,
    /// A restore-time update's limits.
    limits: Option<Arc<RestorePeerLimits>>,
}

impl ServingUpdate {
    /// The keyed job for this attempt. It holds the session's key and an offload
    /// permit only while it runs; a backoff, or a wait for the restore limits, is
    /// spent outside both ([`crate::sbi_offload::Requeuer`]).
    fn job(self, permits: Option<RestorePermits>) -> crate::sbi_offload::RequeueableJob {
        Box::new(move |requeue| Box::pin(self.run(permits, requeue)))
    }

    async fn run(
        mut self,
        permits: Option<RestorePermits>,
        requeue: crate::sbi_offload::Requeuer,
    ) -> Option<crate::sbi_offload::SbiOutcome> {
        let (amf_ue_ngap_id, psi) = (self.amf_ue_ngap_id, self.psi);
        let permits = match (&self.limits, permits) {
            (None, _) => None,
            (Some(_), Some(p)) => Some(p),
            (Some(limits), None) => match limits.try_take(&self.host, self.port) {
                Some(p) => Some(p),
                None => {
                    // The restore's share is in use: wait for it without the key.
                    let limits = Arc::clone(limits);
                    requeue.requeue_when(async move {
                        let permits = limits.take(&self.host, self.port).await;
                        self.job(permits)
                    });
                    return None;
                }
            },
        };
        let result = crate::sbi_path::call_smf_update_serving_amf(
            &self.host,
            self.port,
            &self.sm_ref,
            &self.serving,
        )
        .await;
        drop(permits);
        let Err(e) = result else {
            return None;
        };
        let what = format!("UE {amf_ue_ngap_id}: PSI {psi}'s SMF serving-AMF update");
        match crate::sbi_path::peer_update_retry_wait(self.attempt, &e) {
            None => crate::sbi_path::log_peer_update_given_up(&what, self.attempt, &e),
            Some(wait) => {
                log::warn!(
                    "{what} failed (attempt {} of {}): {e}; retrying in {wait:?}",
                    self.attempt,
                    crate::sbi_path::PEER_UPDATE_ATTEMPTS
                );
                self.attempt += 1;
                requeue.requeue_when(async move {
                    tokio::time::sleep(wait).await;
                    self.job(None)
                });
            }
        }
        None
    }
}
