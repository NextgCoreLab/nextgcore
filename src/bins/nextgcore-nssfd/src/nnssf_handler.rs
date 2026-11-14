//! NSSF NS Selection Handler
//!
//! Port of src/nssf/nnssf-handler.c - NSSF NS selection request handlers

use crate::context::{nssf_self, PlmnId, RoamingIndication, SNssai, Tai};
use crate::event::SbiMessage;

/// Parameters for NS selection request
#[derive(Debug, Clone, Default)]
pub struct NsSelectionParam {
    pub nf_id: Option<String>,
    pub nf_type: Option<String>,
    pub slice_info_for_pdu_session: SliceInfoForPduSession,
    pub tai: Option<Tai>,
    pub home_plmn_id: Option<PlmnId>,
    pub home_snssai: Option<SNssai>,
}

/// Slice info for PDU session
#[derive(Debug, Clone, Default)]
pub struct SliceInfoForPduSession {
    pub presence: bool,
    pub snssai: Option<SNssai>,
    pub roaming_indication: RoamingIndication,
}

/// NSI Information response
#[derive(Debug, Clone)]
pub struct NsiInformation {
    pub nrf_id: String,
    pub nsi_id: String,
}

/// Authorized Network Slice Info response
#[derive(Debug, Clone)]
pub struct AuthorizedNetworkSliceInfo {
    pub nsi_information: Option<NsiInformation>,
}

/// Result of NS selection handling
#[derive(Debug)]
pub enum NsSelectionResult {
    /// Success with authorized slice info
    Success(AuthorizedNetworkSliceInfo),
    /// Need to query H-NSSF (returns home context ID)
    NeedHnssf(u64),
    /// Error with status code and message
    Error(u16, String),
}

/// Handle NS selection GET request from AMF or V-NSSF
/// Port of nssf_nnrf_nsselection_handle_get_from_amf_or_vnssf
pub fn nssf_nnssf_nsselection_handle_get_from_amf_or_vnssf(
    stream_id: u64,
    param: &NsSelectionParam,
) -> NsSelectionResult {
    // Validate required parameters
    if param.nf_id.is_none() {
        return NsSelectionResult::Error(400, "No nf-id".to_string());
    }

    if param.nf_type.is_none() {
        return NsSelectionResult::Error(400, "No nf-type".to_string());
    }

    if !param.slice_info_for_pdu_session.presence {
        return NsSelectionResult::Error(400, "Not implemented except PDU session".to_string());
    }

    let snssai = match &param.slice_info_for_pdu_session.snssai {
        Some(s) => s,
        None => {
            return NsSelectionResult::Error(400, "No sNssai".to_string());
        }
    };

    if param.slice_info_for_pdu_session.roaming_indication == RoamingIndication::NonRoaming
        && param.slice_info_for_pdu_session.roaming_indication == RoamingIndication::default()
    {
        // Check if roaming indication is actually set
        log::debug!(
            "Roaming indication: {:?}",
            param.slice_info_for_pdu_session.roaming_indication
        );
    }

    // Find NSI by S-NSSAI
    let ctx = nssf_self();
    let context = match ctx.read() {
        Ok(c) => c,
        Err(_) => {
            return NsSelectionResult::Error(500, "Internal server error".to_string());
        }
    };

    let nsi = match context.nsi_find_by_s_nssai(snssai) {
        Some(n) => n,
        None => {
            return NsSelectionResult::Error(
                403,
                format!(
                    "Cannot find NSI by S-NSSAI[SST:{} SD:{:?}]",
                    snssai.sst, snssai.sd
                ),
            );
        }
    };

    // Update NSI with roaming indication and TAI
    drop(context);
    let ctx = nssf_self();
    if let Ok(context) = ctx.read() {
        let mut updated_nsi = nsi.clone();
        updated_nsi.roaming_indication = param.slice_info_for_pdu_session.roaming_indication;
        if let Some(ref tai) = param.tai {
            updated_nsi.set_tai(tai.clone());
        }
        context.nsi_update(&updated_nsi);
    }

    // Check if this is a roaming scenario requiring H-NSSF query
    if let (Some(ref home_plmn_id), Some(ref home_snssai)) =
        (&param.home_plmn_id, &param.home_snssai)
    {
        let ctx = nssf_self();
        let context = match ctx.read() {
            Ok(c) => c,
            Err(_) => {
                return NsSelectionResult::Error(500, "Internal server error".to_string());
            }
        };

        // Find or create home context
        let home = context.home_find(home_plmn_id, home_snssai);
        drop(context);

        let home = match home {
            Some(h) => h,
            None => {
                // Create new home context
                let ctx = nssf_self();
                let context = match ctx.read() {
                    Ok(c) => c,
                    Err(_) => {
                        return NsSelectionResult::Error(500, "Internal server error".to_string());
                    }
                };
                match context.home_add(home_plmn_id, home_snssai) {
                    Some(h) => h,
                    None => {
                        return NsSelectionResult::Error(
                            500,
                            format!(
                                "Cannot allocate Home Network by PLMN-ID({}{}) S-NSSAI[SST:{} SD:{:?}]",
                                home_plmn_id.mcc, home_plmn_id.mnc, home_snssai.sst, home_snssai.sd
                            ),
                        );
                    }
                }
            }
        };

        // Check if we already have NRF info for this home network
        if !home.has_nrf_info() {
            // Need to query H-NSSF
            log::debug!(
                "Need to query H-NSSF for home network (stream_id={}, home_id={})",
                stream_id,
                home.id
            );
            return NsSelectionResult::NeedHnssf(home.id);
        }

        // Return home network NSI information
        return NsSelectionResult::Success(AuthorizedNetworkSliceInfo {
            nsi_information: Some(NsiInformation {
                nrf_id: home.nrf_id.clone().expect("value expected"),
                nsi_id: home.nsi_id.clone().expect("value expected"),
            }),
        });
    }

    // Return serving network NSI information
    NsSelectionResult::Success(AuthorizedNetworkSliceInfo {
        nsi_information: Some(NsiInformation {
            nrf_id: nsi.nrf_id.clone(),
            nsi_id: nsi.nsi_id.clone(),
        }),
    })
}

/// Handle NS selection response from H-NSSF
/// Port of nssf_nnrf_nsselection_handle_get_from_hnssf
pub fn nssf_nnssf_nsselection_handle_get_from_hnssf(
    home_id: u64,
    _message: &SbiMessage,
    res_status: u16,
    nrf_id: Option<&str>,
    nsi_id: Option<&str>,
) -> NsSelectionResult {
    // Check response status
    if res_status != 200 {
        return NsSelectionResult::Error(res_status, format!("HTTP response error [{res_status}]"));
    }

    // Validate response
    let nrf_id = match nrf_id {
        Some(id) => id,
        None => {
            return NsSelectionResult::Error(400, "No nrfId".to_string());
        }
    };

    let nsi_id = match nsi_id {
        Some(id) => id,
        None => {
            return NsSelectionResult::Error(400, "No nsiId".to_string());
        }
    };

    // Update home context with NRF info
    let ctx = nssf_self();
    let context = match ctx.read() {
        Ok(c) => c,
        Err(_) => {
            return NsSelectionResult::Error(500, "Internal server error".to_string());
        }
    };

    let mut home = match context.home_find_by_id(home_id) {
        Some(h) => h,
        None => {
            return NsSelectionResult::Error(
                500,
                "Home Network Context has already been removed".to_string(),
            );
        }
    };

    home.set_nrf_info(nrf_id, nsi_id);
    context.home_update(&home);

    log::debug!(
        "H-NSSF response: nrf_id={}, nsi_id={} for home (plmn={}{}, sst={})",
        nrf_id,
        nsi_id,
        home.plmn_id.mcc,
        home.plmn_id.mnc,
        home.s_nssai.sst
    );

    // Return authorized slice info
    NsSelectionResult::Success(AuthorizedNetworkSliceInfo {
        nsi_information: Some(NsiInformation {
            nrf_id: nrf_id.to_string(),
            nsi_id: nsi_id.to_string(),
        }),
    })
}

// ============================================================================
// Registration-scenario NS Selection (TS 29.531 §5.2.3.2, SliceInfoForRegistration)
// ============================================================================

/// Parsed SliceInfoForRegistration content relevant to slice authorization
#[derive(Debug, Clone, Default)]
pub struct RegistrationSliceInfo {
    /// subscribedNssai: (S-NSSAI, defaultIndication)
    pub subscribed: Vec<(SNssai, bool)>,
    /// requestedNssai
    pub requested: Vec<SNssai>,
    /// defaultConfiguredSnssaiInd
    pub default_configured_ind: bool,
    /// mappingOfNssai: (servingSnssai, homeSnssai)
    pub mapping_of_nssai: Vec<(SNssai, SNssai)>,
    /// `allowedNssaiCurrentAccess.accessType` from the request, i.e. the access
    /// the UE is currently on (TS 29.531 `SliceInfoForRegistration`).
    ///
    /// The response's `AllowedNssai.accessType` is a REQUIRED member, and this is
    /// where the consumer states which access it is asking about — before #93 the
    /// response hardcoded `3GPP_ACCESS`, so a non-3GPP registration was reported
    /// back as 3GPP. `None` means the consumer did not say, in which case
    /// `3GPP_ACCESS` remains the documented default (the member cannot be
    /// omitted, and 3GPP access is the case a silent consumer means).
    pub current_access_type: Option<String>,
}

/// Context snapshots needed to authorize a registration request without
/// holding any lock across the computation.
#[derive(Debug, Clone, Default)]
pub struct RegistrationContextSnapshot {
    /// Supported S-NSSAIs in the UE's TAI (None = no TAI given or no
    /// availability data at all -> skip TA filtering)
    pub supported_for_tai: Option<Vec<SNssai>>,
    /// Per-AMF supported S-NSSAIs (nfId, list) from NSSAI availability store
    pub per_nf_support: Vec<(String, Vec<SNssai>)>,
    /// NSI info per S-NSSAI: (S-NSSAI, nrfId, nsiId)
    pub nsi_info: Vec<(SNssai, String, String)>,
    /// Configured target AMF set (used when re-selection is needed)
    pub target_amf_set: Option<String>,
    /// The explicitly CONFIGURED set of S-NSSAIs supported in this PLMN
    /// (TS 29.531 §6.2.3.2.3.1). `None` = no restriction configured, so every
    /// subscribed S-NSSAI is applicable in the PLMN. This is the authoritative
    /// answer to "supported in the serving PLMN"; `per_nf_support` is not (see
    /// the `configuredNssai` derivation below).
    pub plmn_snssai_restriction: Option<Vec<SNssai>>,
}

/// Result of registration-scenario slice authorization
#[derive(Debug, Clone, Default)]
pub struct RegistrationSelection {
    /// (allowed S-NSSAI, optional (nrfId, nsiId), optional mapped home S-NSSAI)
    pub allowed: Vec<(SNssai, Option<(String, String)>, Option<SNssai>)>,
    /// (configured S-NSSAI, optional mapped home S-NSSAI)
    pub configured: Vec<(SNssai, Option<SNssai>)>,
    pub rejected_in_plmn: Vec<SNssai>,
    pub rejected_in_ta: Vec<SNssai>,
    pub target_amf_set: Option<String>,
    pub candidate_amf_list: Vec<String>,
}

/// Authorize the registration-scenario NSSAIs (TS 29.531 §5.2.3.2.3).
///
/// - allowed = requested NSSAIs restricted to the subscribed S-NSSAIs the AMF
///   supplied and to the S-NSSAIs available in the UE's TA
///   (TS 23.501 §5.15.5.2.1 (B)). A requested S-NSSAI counts as subscribed under
///   either its own value or the HPLMN value the consumer's `mappingOfNssai`
///   gives for it, because `subscribedNssai` carries the subscribed HPLMN NSSAI
///   in the inbound-roaming case and serving-PLMN values otherwise
///   (TS 29.531 Table 6.1.6.2.10-1).
/// - the default-marked subscribed S-NSSAIs are considered both when no
///   requestedNssai was sent and when none of the requested ones is permitted or
///   available in the TA — the two cases the same clause names. Only an explicit
///   `defaultIndication` marks one (TS 23.501 §5.15.3: the subscription "shall
///   include at least one default S-NSSAI").
/// - an empty `info.subscribed` permits nothing: every requested S-NSSAI is then
///   rejected in the PLMN and `sel.allowed` comes back empty, which the HTTP
///   layer answers 403 SNSSAI_NOT_SUPPORTED (TS 29.531 §5.2.2.2.2 step 2b).
/// - configured = subscribed S-NSSAIs applicable in the serving PLMN, i.e.
///   restricted by the CONFIGURED PLMN S-NSSAI set when one exists (#346), never
///   by what individual AMFs happen to have reported as available.
/// - requested-but-unsubscribed -> rejectedNssaiInPlmn;
///   subscribed-but-unavailable-in-TA -> rejectedNssaiInTa.
/// - If the requesting AMF (nf-id) reported availability that cannot serve
///   the allowed NSSAI while other AMFs can, targetAmfSet/candidateAmfList
///   are populated for AMF re-selection.
pub fn nssf_nsselection_handle_registration(
    requesting_nf_id: &str,
    info: &RegistrationSliceInfo,
    snapshot: &RegistrationContextSnapshot,
) -> RegistrationSelection {
    let mut sel = RegistrationSelection::default();

    let subscribed: Vec<SNssai> = info.subscribed.iter().map(|(s, _)| s.clone()).collect();

    let mapped = |s: &SNssai| -> Option<SNssai> {
        info.mapping_of_nssai
            .iter()
            .find(|(serving, _)| serving == s)
            .map(|(_, home)| home.clone())
    };

    // Subscription check (TS 23.501 §5.15.5.2.1 (B)): "verifies which S-NSSAI(s)
    // in the Requested NSSAI are permitted based on comparing the Subscribed
    // S-NSSAIs WITH THE S-NSSAIs IN THE MAPPING OF REQUESTED NSSAI TO HPLMN
    // S-NSSAIs".
    //
    // The mapping half matters for inbound roaming, where `subscribedNssai`
    // carries HPLMN values (TS 29.531 Table 6.1.6.2.10-1) while `requestedNssai`
    // carries serving-PLMN ones: comparing the raw serving value against an HPLMN
    // subscription rejects every slice a roamer asks for.
    //
    // Either spelling of the same slice is accepted: the value as requested, or
    // the HPLMN value the consumer's own `mappingOfNssai` gives for it. The
    // clause states the disjunction itself, in (A) and (B) alike: the Allowed
    // NSSAI is determined from "the list of S-NSSAI(s) in the Requested NSSAI
    // permitted based on the Subscribed S-NSSAIs AND/OR the list of S-NSSAI(s)
    // for the Serving PLMN which are mapped to the HPLMN S-NSSAI(s) provided in
    // the mapping of Requested NSSAI permitted based on the Subscribed S-NSSAIs".
    // And a mapping being present does not say which spelling the subscription
    // uses: `mappingOfNssai` may also be present during EPS-to-5GS and intra-5GS
    // handover, where `subscribedNssai` may carry serving-PLMN values.
    //
    // The one widening this admits, stated so it is not mistaken for an
    // oversight: when the subscription is in HPLMN values, a requested
    // serving-PLMN S-NSSAI that HAPPENS TO EQUAL a subscribed HPLMN value is
    // permitted on that coincidence, even if the request's own `mappingOfNssai`
    // maps it to a home value that is not subscribed. It is bounded by the
    // request itself -- the consumer supplies both the mapping and the
    // subscription, so the result never reaches past the subscription it was
    // checked against -- and nothing in the request tells the NSSF which spelling
    // `subscribedNssai` uses, so neither reading can be refused on the request's
    // own evidence.
    let is_subscribed = |s: &SNssai| -> bool {
        subscribed.contains(s) || mapped(s).is_some_and(|home| subscribed.contains(&home))
    };

    // The default-marked Subscribed S-NSSAIs. Only an explicit
    // `defaultIndication: true` marks one. TS 23.501 §5.15.3: "The subscription
    // information shall include at least one default S-NSSAI" (and again for
    // what the UDM sends the AMF). A `subscribedNssai` with no default marked is
    // therefore not a conformant subscription, and reading the gap as "every
    // subscribed S-NSSAI is a default" would hand a consumer that never sends
    // `defaultIndication` the whole subscription as its default set.
    let default_marked: Vec<SNssai> = info
        .subscribed
        .iter()
        .filter(|(_, def)| *def)
        .map(|(s, _)| s.clone())
        .collect();

    // One pass of the two authorization filters over a candidate set:
    // (allowed, rejected in the PLMN = not subscribed, rejected in the TA).
    let permit = |candidates: &[SNssai]| -> (Vec<SNssai>, Vec<SNssai>, Vec<SNssai>) {
        let mut allowed: Vec<SNssai> = Vec::new();
        let mut rejected_in_plmn: Vec<SNssai> = Vec::new();
        for c in candidates {
            if is_subscribed(c) {
                if !allowed.contains(c) {
                    allowed.push(c.clone());
                }
            } else if !rejected_in_plmn.contains(c) {
                rejected_in_plmn.push(c.clone());
            }
        }
        // TA availability check (TS 29.531: rejectedNssaiInTa)
        let mut rejected_in_ta: Vec<SNssai> = Vec::new();
        if let Some(ref supported) = snapshot.supported_for_tai {
            let (in_ta, out_of_ta): (Vec<SNssai>, Vec<SNssai>) =
                allowed.into_iter().partition(|s| supported.contains(s));
            allowed = in_ta;
            rejected_in_ta = out_of_ta;
        }
        (allowed, rejected_in_plmn, rejected_in_ta)
    };

    // Candidate set: the Requested NSSAI, or the default-marked Subscribed
    // S-NSSAIs when the consumer requested nothing.
    let requested_something = !info.requested.is_empty();
    let candidates: Vec<SNssai> = if requested_something {
        info.requested.clone()
    } else {
        default_marked.clone()
    };

    let (mut allowed, rejected_in_plmn, rejected_in_ta) = permit(&candidates);
    sel.rejected_in_plmn = rejected_in_plmn;
    sel.rejected_in_ta = rejected_in_ta;

    // The rest of the same sentence of §5.15.5.2.1 (B): the default-marked
    // S-NSSAIs are considered "in the case that no Requested NSSAI was provided
    // OR NO S-NSSAI FROM THE REQUESTED NSSAI ARE PERMITTED i.e. are not present
    // in the Subscribed S-NSSAIs or not available e.g. at the current UE's
    // Tracking Area". Only the first case was implemented, so a Requested NSSAI
    // that was wholly unsubscribed or wholly unavailable here produced a response
    // with no Allowed NSSAI at all -- which §5.2.2.2.2 step 2a does not allow a
    // 200 to be. The requested S-NSSAIs stay in the rejected lists either way:
    // the consumer asked about those, and the fallback does not un-reject them.
    if allowed.is_empty() && requested_something && !default_marked.is_empty() {
        let (fallback, _, _) = permit(&default_marked);
        allowed = fallback;
    }

    // Attach NSI information where an NSI is configured for the slice
    for s in &allowed {
        let nsi = snapshot
            .nsi_info
            .iter()
            .find(|(n, _, _)| n == s)
            .map(|(_, nrf, nsi)| (nrf.clone(), nsi.clone()));
        sel.allowed.push((s.clone(), nsi, mapped(s)));
    }

    // configuredNssai: the subscribed S-NSSAIs applicable in the serving PLMN
    // (TS 23.501 §5.15.4.1, returned per TS 29.531 §5.2.2.2.4).
    //
    // #346: filtered by the CONFIGURED PLMN S-NSSAI set, not by the union of the
    // NSSAI-availability documents AMFs have registered. Each of those describes
    // ONE AMF's slice picture, which is why `per_nf_support` is the right input
    // for the AMF re-selection immediately below and only there. A slice absent
    // from every registered document has not been shown unsupported by the PLMN,
    // only unreported -- registering availability is per-AMF and optional -- so
    // reading absence as "not supported in the PLMN" silently dropped subscribed
    // slices from the UE's Configured NSSAI the moment any single AMF registered a
    // partial picture. The UE stores the Configured NSSAI in non-volatile memory
    // (TS 24.501 Annex C.1), so that consequence outlives the report that caused
    // it. It is also what made a passing nssfd suite order-dependent: a sibling
    // test's availability document decided this member.
    for s in &subscribed {
        let applicable_in_plmn = match &snapshot.plmn_snssai_restriction {
            Some(configured) => configured.contains(s),
            None => true,
        };
        if applicable_in_plmn && !sel.configured.iter().any(|(c, _)| c == s) {
            sel.configured.push((s.clone(), mapped(s)));
        }
    }

    // AMF re-selection: only when the requesting AMF reported availability
    // that does NOT cover the allowed NSSAI, and at least one other AMF does.
    if !allowed.is_empty() {
        let requester_support = snapshot
            .per_nf_support
            .iter()
            .find(|(id, _)| id == requesting_nf_id)
            .map(|(_, list)| list.clone());
        if let Some(requester_support) = requester_support {
            let requester_serves_all = allowed.iter().all(|s| requester_support.contains(s));
            if !requester_serves_all {
                let candidates_amf: Vec<String> = snapshot
                    .per_nf_support
                    .iter()
                    .filter(|(id, list)| {
                        id != requesting_nf_id && allowed.iter().all(|s| list.contains(s))
                    })
                    .map(|(id, _)| id.clone())
                    .collect();
                if !candidates_amf.is_empty() {
                    sel.candidate_amf_list = candidates_amf;
                    sel.target_amf_set = snapshot.target_amf_set.clone();
                }
            }
        }
    }

    sel
}

/// NRF-based slice availability query result
#[derive(Debug, Clone)]
pub struct NrfSliceAvailability {
    /// Number of NF instances serving this slice
    pub nf_instance_count: usize,
    /// NRF ID that was queried
    pub nrf_id: String,
    /// Whether the slice has available capacity
    pub available: bool,
}

/// Query NRF for NF instances that serve the requested S-NSSAI (TS 29.531)
///
/// This validates that the network actually has NFs available to serve
/// the requested slice, not just that the NSSF is configured with it.
pub fn query_nrf_slice_availability(
    nrf_uri: &str,
    s_nssai: &SNssai,
    target_nf_type: &str,
) -> NrfSliceAvailability {
    log::debug!(
        "Querying NRF ({}) for {} instances serving S-NSSAI[SST:{} SD:{:?}]",
        nrf_uri,
        target_nf_type,
        s_nssai.sst,
        s_nssai.sd
    );

    // In a full implementation this would make an HTTP GET to:
    // {nrf_uri}/nnrf-disc/v1/nf-instances?target-nf-type={target_nf_type}&snssais=[{s_nssai}]
    // For now, we validate against locally known NRF data

    let ctx = nssf_self();
    let context = match ctx.read() {
        Ok(c) => c,
        Err(_) => {
            return NrfSliceAvailability {
                nf_instance_count: 0,
                nrf_id: nrf_uri.to_string(),
                available: false,
            };
        }
    };

    // Check NSSAI availability data (populated by AMFs via Nnssf_NSSAIAvailability)
    let mut nf_count = 0;
    if let Ok(avail) = context.nssai_availability.read() {
        for info in avail.values() {
            if info
                .supported_snssai_list
                .iter()
                .any(|s| s.sst == s_nssai.sst && s.sd == s_nssai.sd)
            {
                nf_count += 1;
            }
        }
    }

    // If no NSSAI availability data, check if we have an NSI configured for this slice
    if nf_count == 0 && context.nsi_find_by_s_nssai(s_nssai).is_some() {
        nf_count = 1; // At least the configured NSI is available
    }

    log::debug!(
        "NRF slice availability: {} NFs for S-NSSAI[SST:{} SD:{:?}]",
        nf_count,
        s_nssai.sst,
        s_nssai.sd
    );

    NrfSliceAvailability {
        nf_instance_count: nf_count,
        nrf_id: nrf_uri.to_string(),
        available: nf_count > 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Take the one process-global guard and hand this test an empty context.
    ///
    /// #346: this used to init the global if it was not already initialised and
    /// take NO lock, so seven tests here mutated the same singleton that `main`'s
    /// tests were asserting against -- `test_nrf_slice_availability_configured`
    /// leaves an NSI in the global NSI table, which every later snapshot reads as
    /// `nsiInformationList`. Returns the guard, so callers must bind it:
    /// `let _guard = setup_context();` (`MutexGuard` is itself `#[must_use]`).
    fn setup_context() -> std::sync::MutexGuard<'static, ()> {
        crate::context::nssf_test_guard(100)
    }

    #[test]
    fn test_ns_selection_missing_nf_id() {
        let _guard = setup_context();
        let param = NsSelectionParam::default();
        let result = nssf_nnssf_nsselection_handle_get_from_amf_or_vnssf(1, &param);
        match result {
            NsSelectionResult::Error(status, msg) => {
                assert_eq!(status, 400);
                assert!(msg.contains("nf-id"));
            }
            _ => panic!("Expected error"),
        }
    }

    #[test]
    fn test_ns_selection_missing_nf_type() {
        let _guard = setup_context();
        let param = NsSelectionParam {
            nf_id: Some("test-nf-id".to_string()),
            ..Default::default()
        };
        let result = nssf_nnssf_nsselection_handle_get_from_amf_or_vnssf(1, &param);
        match result {
            NsSelectionResult::Error(status, msg) => {
                assert_eq!(status, 400);
                assert!(msg.contains("nf-type"));
            }
            _ => panic!("Expected error"),
        }
    }

    #[test]
    fn test_ns_selection_missing_slice_info() {
        let _guard = setup_context();
        let param = NsSelectionParam {
            nf_id: Some("test-nf-id".to_string()),
            nf_type: Some("AMF".to_string()),
            ..Default::default()
        };
        let result = nssf_nnssf_nsselection_handle_get_from_amf_or_vnssf(1, &param);
        match result {
            NsSelectionResult::Error(status, msg) => {
                assert_eq!(status, 400);
                assert!(msg.contains("PDU session"));
            }
            _ => panic!("Expected error"),
        }
    }

    #[test]
    fn test_ns_selection_nsi_not_found() {
        let _guard = setup_context();
        let param = NsSelectionParam {
            nf_id: Some("test-nf-id".to_string()),
            nf_type: Some("AMF".to_string()),
            slice_info_for_pdu_session: SliceInfoForPduSession {
                presence: true,
                snssai: Some(SNssai::new(99, None)), // Non-existent S-NSSAI
                roaming_indication: RoamingIndication::NonRoaming,
            },
            ..Default::default()
        };
        let result = nssf_nnssf_nsselection_handle_get_from_amf_or_vnssf(1, &param);
        match result {
            NsSelectionResult::Error(status, _) => {
                assert_eq!(status, 403);
            }
            _ => panic!("Expected error"),
        }
    }

    #[test]
    fn test_ns_selection_success() {
        let _guard = setup_context();

        // Add an NSI first
        let ctx = nssf_self();
        if let Ok(context) = ctx.read() {
            context.nsi_add("http://nrf.example.com", 1, Some(0x010203));
        }

        let param = NsSelectionParam {
            nf_id: Some("test-nf-id".to_string()),
            nf_type: Some("AMF".to_string()),
            slice_info_for_pdu_session: SliceInfoForPduSession {
                presence: true,
                snssai: Some(SNssai::new(1, Some(0x010203))),
                roaming_indication: RoamingIndication::NonRoaming,
            },
            ..Default::default()
        };
        let result = nssf_nnssf_nsselection_handle_get_from_amf_or_vnssf(1, &param);
        match result {
            NsSelectionResult::Success(info) => {
                assert!(info.nsi_information.is_some());
                let nsi_info = info.nsi_information.unwrap();
                assert!(!nsi_info.nrf_id.is_empty());
            }
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn test_nrf_slice_availability_with_nsi() {
        let _guard = setup_context();

        let ctx = nssf_self();
        if let Ok(context) = ctx.read() {
            context.nsi_add("http://nrf.example.com", 2, Some(0xABCDEF));
        }

        let s_nssai = SNssai::new(2, Some(0xABCDEF));
        let result = query_nrf_slice_availability("http://nrf.example.com", &s_nssai, "SMF");
        assert!(result.available);
        assert!(result.nf_instance_count > 0);
    }

    #[test]
    fn test_nrf_slice_availability_not_configured() {
        let _guard = setup_context();

        let s_nssai = SNssai::new(99, Some(0xFFFFFF));
        let result = query_nrf_slice_availability("http://nrf.example.com", &s_nssai, "SMF");
        assert!(!result.available);
        assert_eq!(result.nf_instance_count, 0);
    }

    // ------------------------------------------------------------------
    // Registration-scenario selection (pure logic, no context needed)
    // ------------------------------------------------------------------

    fn reg_info(subscribed: Vec<(u8, bool)>, requested: Vec<u8>) -> RegistrationSliceInfo {
        RegistrationSliceInfo {
            subscribed: subscribed
                .into_iter()
                .map(|(sst, d)| (SNssai::new(sst, None), d))
                .collect(),
            requested: requested
                .into_iter()
                .map(|s| SNssai::new(s, None))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn test_registration_allowed_and_rejected_in_plmn() {
        let info = reg_info(vec![(1, true), (2, false)], vec![1, 9]);
        let snap = RegistrationContextSnapshot::default();
        let sel = nssf_nsselection_handle_registration("amf-1", &info, &snap);
        assert_eq!(sel.allowed.len(), 1);
        assert_eq!(sel.allowed[0].0, SNssai::new(1, None));
        assert_eq!(sel.rejected_in_plmn, vec![SNssai::new(9, None)]);
        assert!(sel.rejected_in_ta.is_empty());
        // configured = full subscription (no availability data)
        assert_eq!(sel.configured.len(), 2);
        assert!(sel.candidate_amf_list.is_empty());
    }

    /// Inbound roaming: `subscribedNssai` carries HPLMN values and
    /// `requestedNssai` serving-PLMN ones, so the comparison runs through the
    /// `mappingOfNssai` the consumer supplied (TS 23.501 §5.15.5.2.1 (B),
    /// TS 29.531 Table 6.1.6.2.10-1). Without it every roamer's slice is
    /// rejected in the PLMN.
    #[test]
    fn a_requested_snssai_is_compared_through_its_mapping_to_the_hplmn() {
        let home = SNssai::new(1, Some(0x0a0a0a));
        let serving = SNssai::new(2, None);
        let info = RegistrationSliceInfo {
            subscribed: vec![(home.clone(), true)],
            requested: vec![serving.clone()],
            mapping_of_nssai: vec![(serving.clone(), home.clone())],
            ..Default::default()
        };
        let sel = nssf_nsselection_handle_registration(
            "amf-roam",
            &info,
            &RegistrationContextSnapshot::default(),
        );
        assert_eq!(sel.allowed.len(), 1, "{:?}", sel.allowed);
        // The Allowed NSSAI carries the SERVING value, with the HPLMN one mapped.
        assert_eq!(sel.allowed[0].0, serving);
        assert_eq!(sel.allowed[0].2, Some(home));
        assert!(
            sel.rejected_in_plmn.is_empty(),
            "a mapped-and-subscribed S-NSSAI must not be rejected: {:?}",
            sel.rejected_in_plmn
        );

        // An unmapped request is compared raw, and an S-NSSAI the subscription
        // does not carry under EITHER spelling is rejected. No default-marked
        // entry here, so the fallback has nothing to offer.
        let info = RegistrationSliceInfo {
            subscribed: vec![(SNssai::new(1, Some(0x0a0a0a)), false)],
            requested: vec![SNssai::new(5, None)],
            ..Default::default()
        };
        let sel = nssf_nsselection_handle_registration(
            "amf-roam-2",
            &info,
            &RegistrationContextSnapshot::default(),
        );
        assert!(sel.allowed.is_empty());
        assert_eq!(sel.rejected_in_plmn, vec![SNssai::new(5, None)]);
    }

    /// "It considers the S-NSSAI(s) marked as default in the Subscribed
    /// S-NSSAIs in the case that no Requested NSSAI was provided or no S-NSSAI
    /// from the Requested NSSAI are permitted" (TS 23.501 §5.15.5.2.1 (B)) --
    /// the second case too, whether the requested set was unsubscribed or
    /// unavailable in the TA. The requested S-NSSAIs stay rejected.
    #[test]
    fn default_marked_subscribed_snssais_are_considered_when_nothing_requested_is_permitted() {
        // Unavailable in the TA: sst 3 is subscribed but not available here.
        let info = reg_info(vec![(1, true), (3, false)], vec![3]);
        let snap = RegistrationContextSnapshot {
            supported_for_tai: Some(vec![SNssai::new(1, None)]),
            ..Default::default()
        };
        let sel = nssf_nsselection_handle_registration("amf-f1", &info, &snap);
        assert_eq!(sel.allowed.len(), 1, "{:?}", sel.allowed);
        assert_eq!(sel.allowed[0].0, SNssai::new(1, None));
        assert_eq!(sel.rejected_in_ta, vec![SNssai::new(3, None)]);

        // Not subscribed at all: sst 9.
        let info = reg_info(vec![(1, true), (2, false)], vec![9]);
        let sel = nssf_nsselection_handle_registration(
            "amf-f2",
            &info,
            &RegistrationContextSnapshot::default(),
        );
        assert_eq!(sel.allowed.len(), 1, "{:?}", sel.allowed);
        assert_eq!(sel.allowed[0].0, SNssai::new(1, None));
        assert_eq!(sel.rejected_in_plmn, vec![SNssai::new(9, None)]);

        // No default-marked entry: nothing to fall back to, so nothing is
        // allowed -- `defaultIndication` is optional and its absence is not a
        // claim that every subscribed S-NSSAI is a default.
        let info = reg_info(vec![(1, false), (2, false)], vec![9]);
        let sel = nssf_nsselection_handle_registration(
            "amf-f3",
            &info,
            &RegistrationContextSnapshot::default(),
        );
        assert!(sel.allowed.is_empty(), "{:?}", sel.allowed);
        // And with no requestedNssai either: still nothing, not the whole
        // subscription.
        let info = reg_info(vec![(1, false), (2, false)], vec![]);
        let sel = nssf_nsselection_handle_registration(
            "amf-f4",
            &info,
            &RegistrationContextSnapshot::default(),
        );
        assert!(sel.allowed.is_empty(), "{:?}", sel.allowed);
        // The Configured NSSAI is unaffected: it comes from the subscription.
        assert_eq!(sel.configured.len(), 2);
    }

    /// With no Subscribed S-NSSAI nothing is permitted: every requested
    /// S-NSSAI is rejected in the PLMN and none is allowed or configured. The
    /// HTTP layer turns this into 403 SNSSAI_NOT_SUPPORTED (§5.2.2.2.2 step 2b).
    #[test]
    fn selection_with_no_subscribed_snssai_permits_no_requested_snssai() {
        let info = reg_info(vec![], vec![1, 2]);
        let sel = nssf_nsselection_handle_registration(
            "amf-1",
            &info,
            &RegistrationContextSnapshot::default(),
        );
        assert!(sel.allowed.is_empty(), "{:?}", sel.allowed);
        assert!(sel.configured.is_empty(), "{:?}", sel.configured);
        assert_eq!(
            sel.rejected_in_plmn,
            vec![SNssai::new(1, None), SNssai::new(2, None)]
        );
    }

    #[test]
    fn test_registration_defaults_when_no_requested() {
        let info = reg_info(vec![(1, true), (2, false)], vec![]);
        let snap = RegistrationContextSnapshot::default();
        let sel = nssf_nsselection_handle_registration("amf-1", &info, &snap);
        // Only the default-indication subscribed slice is allowed
        assert_eq!(sel.allowed.len(), 1);
        assert_eq!(sel.allowed[0].0, SNssai::new(1, None));
    }

    #[test]
    fn test_registration_rejected_in_ta() {
        let info = reg_info(vec![(1, true), (2, false)], vec![1, 2]);
        let snap = RegistrationContextSnapshot {
            supported_for_tai: Some(vec![SNssai::new(2, None)]),
            ..Default::default()
        };
        let sel = nssf_nsselection_handle_registration("amf-1", &info, &snap);
        assert_eq!(sel.allowed.len(), 1);
        assert_eq!(sel.allowed[0].0, SNssai::new(2, None));
        assert_eq!(sel.rejected_in_ta, vec![SNssai::new(1, None)]);
    }

    #[test]
    fn test_registration_amf_reselection() {
        let info = reg_info(vec![(1, true)], vec![1]);
        let snap = RegistrationContextSnapshot {
            per_nf_support: vec![
                ("amf-a".to_string(), vec![SNssai::new(2, None)]),
                ("amf-b".to_string(), vec![SNssai::new(1, None)]),
            ],
            target_amf_set: Some("999-70-01-001".to_string()),
            ..Default::default()
        };
        // amf-a cannot serve sst=1 but amf-b can -> re-selection info present
        let sel = nssf_nsselection_handle_registration("amf-a", &info, &snap);
        assert_eq!(sel.allowed.len(), 1);
        assert_eq!(sel.candidate_amf_list, vec!["amf-b".to_string()]);
        assert_eq!(sel.target_amf_set.as_deref(), Some("999-70-01-001"));

        // amf-b serves it itself -> no re-selection
        let sel = nssf_nsselection_handle_registration("amf-b", &info, &snap);
        assert!(sel.candidate_amf_list.is_empty());
        assert!(sel.target_amf_set.is_none());
    }

    #[test]
    fn test_registration_nsi_information_attached() {
        let info = reg_info(vec![(1, true)], vec![1]);
        let snap = RegistrationContextSnapshot {
            nsi_info: vec![(
                SNssai::new(1, None),
                "http://nrf.example.com".to_string(),
                "9f8d7c6b-uuid".to_string(),
            )],
            ..Default::default()
        };
        let sel = nssf_nsselection_handle_registration("amf-1", &info, &snap);
        let (_, nsi, _) = &sel.allowed[0];
        let (nrf_id, nsi_id) = nsi.as_ref().expect("nsi info attached");
        assert_eq!(nrf_id, "http://nrf.example.com");
        assert_eq!(nsi_id, "9f8d7c6b-uuid");
    }

    #[test]
    fn test_registration_mapped_home_snssai() {
        let mut info = reg_info(vec![(1, true)], vec![1]);
        info.mapping_of_nssai = vec![(SNssai::new(1, None), SNssai::new(11, Some(0xABCDEF)))];
        let snap = RegistrationContextSnapshot::default();
        let sel = nssf_nsselection_handle_registration("amf-1", &info, &snap);
        assert_eq!(sel.allowed[0].2, Some(SNssai::new(11, Some(0xABCDEF))));
        assert_eq!(sel.configured[0].1, Some(SNssai::new(11, Some(0xABCDEF))));
    }
}
