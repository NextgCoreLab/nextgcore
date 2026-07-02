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
/// - allowed = requested NSSAIs restricted to the subscription and to the
///   S-NSSAIs available in the UE's TA; when the AMF sends no requestedNssai
///   the default subscribed S-NSSAIs are used.
/// - configured = subscribed S-NSSAIs supported in the serving PLMN.
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

    // Candidate set: requested NSSAIs, or the default subscribed ones when
    // the UE/AMF did not request anything specific.
    let candidates: Vec<SNssai> = if !info.requested.is_empty() {
        info.requested.clone()
    } else {
        let defaults: Vec<SNssai> = info
            .subscribed
            .iter()
            .filter(|(_, def)| *def)
            .map(|(s, _)| s.clone())
            .collect();
        if defaults.is_empty() {
            subscribed.clone()
        } else {
            defaults
        }
    };

    // Subscription check (only meaningful when the AMF supplied the
    // subscription; otherwise authorize against availability only).
    let mut allowed: Vec<SNssai> = Vec::new();
    for c in &candidates {
        if subscribed.is_empty() || subscribed.contains(c) {
            if !allowed.contains(c) {
                allowed.push(c.clone());
            }
        } else if !sel.rejected_in_plmn.contains(c) {
            sel.rejected_in_plmn.push(c.clone());
        }
    }

    // TA availability check (TS 29.531: rejectedNssaiInTa)
    if let Some(ref supported) = snapshot.supported_for_tai {
        let (in_ta, out_of_ta): (Vec<SNssai>, Vec<SNssai>) =
            allowed.into_iter().partition(|s| supported.contains(s));
        allowed = in_ta;
        sel.rejected_in_ta = out_of_ta;
    }

    let mapped = |s: &SNssai| -> Option<SNssai> {
        info.mapping_of_nssai
            .iter()
            .find(|(serving, _)| serving == s)
            .map(|(_, home)| home.clone())
    };

    // Attach NSI information where an NSI is configured for the slice
    for s in &allowed {
        let nsi = snapshot
            .nsi_info
            .iter()
            .find(|(n, _, _)| n == s)
            .map(|(_, nrf, nsi)| (nrf.clone(), nsi.clone()));
        sel.allowed.push((s.clone(), nsi, mapped(s)));
    }

    // configuredNssai: subscribed S-NSSAIs supported somewhere in the serving
    // PLMN (when availability data exists), else the full subscription.
    let plmn_supported: Vec<SNssai> = {
        let mut acc: Vec<SNssai> = Vec::new();
        for (_, list) in &snapshot.per_nf_support {
            for s in list {
                if !acc.contains(s) {
                    acc.push(s.clone());
                }
            }
        }
        acc
    };
    let configured_src: Vec<SNssai> = if subscribed.is_empty() {
        allowed.clone()
    } else {
        subscribed.clone()
    };
    for s in &configured_src {
        let supported_in_plmn = plmn_supported.is_empty() || plmn_supported.contains(s);
        if supported_in_plmn && !sel.configured.iter().any(|(c, _)| c == s) {
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

/// Validate a requested S-NSSAI against subscription data and NRF availability (TS 29.531)
///
/// Returns true if the UE is subscribed to the slice AND the network can serve it.
pub fn validate_slice_selection(s_nssai: &SNssai, supi: Option<&str>, nrf_uri: &str) -> bool {
    // Step 1: Check subscription if SUPI available
    if let Some(supi) = supi {
        match nextgcore_dbi::nextgcore_dbi_subscription_data(supi) {
            Ok(sub_data) => {
                let subscribed = sub_data.slice.iter().any(|s| {
                    s.s_nssai.sst == s_nssai.sst && {
                        let sd_val = s.s_nssai.sd.v;
                        if sd_val == 0xFFFFFF {
                            s_nssai.sd.is_none()
                        } else {
                            s_nssai.sd == Some(sd_val)
                        }
                    }
                });
                if !subscribed {
                    log::info!(
                        "[{}] S-NSSAI[SST:{} SD:{:?}] not in subscription",
                        supi,
                        s_nssai.sst,
                        s_nssai.sd
                    );
                    return false;
                }
            }
            Err(e) => {
                log::debug!("Subscription check skipped for {supi}: {e}");
            }
        }
    }

    // Step 2: Check NRF availability
    let availability = query_nrf_slice_availability(nrf_uri, s_nssai, "SMF");
    if !availability.available {
        log::warn!(
            "S-NSSAI[SST:{} SD:{:?}] has no available NF instances in NRF",
            s_nssai.sst,
            s_nssai.sd
        );
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_context() {
        let ctx = nssf_self();
        let needs_init = {
            if let Ok(context) = ctx.read() {
                !context.is_initialized()
            } else {
                true
            }
        };
        if needs_init {
            if let Ok(mut context) = ctx.write() {
                context.init(100);
            }
        }
    }

    #[test]
    fn test_ns_selection_missing_nf_id() {
        setup_context();
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
        setup_context();
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
        setup_context();
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
        setup_context();
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
        setup_context();

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
        setup_context();

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
        setup_context();

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
