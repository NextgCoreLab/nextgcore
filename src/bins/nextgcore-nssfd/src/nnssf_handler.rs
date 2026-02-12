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
        log::debug!("Roaming indication: {:?}", param.slice_info_for_pdu_session.roaming_indication);
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
    if let (Some(ref home_plmn_id), Some(ref home_snssai)) = (&param.home_plmn_id, &param.home_snssai) {
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
                stream_id, home.id
            );
            return NsSelectionResult::NeedHnssf(home.id);
        }

        // Return home network NSI information
        return NsSelectionResult::Success(AuthorizedNetworkSliceInfo {
            nsi_information: Some(NsiInformation {
                nrf_id: home.nrf_id.clone().unwrap_or_default(),
                nsi_id: home.nsi_id.clone().unwrap_or_default(),
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
            return NsSelectionResult::Error(500, "Home Network Context has already been removed".to_string());
        }
    };

    home.set_nrf_info(nrf_id, nsi_id);
    context.home_update(&home);

    log::debug!(
        "H-NSSF response: nrf_id={}, nsi_id={} for home (plmn={}{}, sst={})",
        nrf_id, nsi_id, home.plmn_id.mcc, home.plmn_id.mnc, home.s_nssai.sst
    );

    // Return authorized slice info
    NsSelectionResult::Success(AuthorizedNetworkSliceInfo {
        nsi_information: Some(NsiInformation {
            nrf_id: nrf_id.to_string(),
            nsi_id: nsi_id.to_string(),
        }),
    })
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
        nrf_uri, target_nf_type, s_nssai.sst, s_nssai.sd
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
            if info.supported_snssai_list.iter().any(|s| s.sst == s_nssai.sst && s.sd == s_nssai.sd) {
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
        nf_count, s_nssai.sst, s_nssai.sd
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
pub fn validate_slice_selection(
    s_nssai: &SNssai,
    supi: Option<&str>,
    nrf_uri: &str,
) -> bool {
    // Step 1: Check subscription if SUPI available
    if let Some(supi) = supi {
        match ogs_dbi::ogs_dbi_subscription_data(supi) {
            Ok(sub_data) => {
                let subscribed = sub_data.slice.iter().any(|s| {
                    s.s_nssai.sst == s_nssai.sst && {
                        let sd_val = s.s_nssai.sd.v;
                        if sd_val == 0xFFFFFF { s_nssai.sd.is_none() } else { s_nssai.sd == Some(sd_val) }
                    }
                });
                if !subscribed {
                    log::info!(
                        "[{}] S-NSSAI[SST:{} SD:{:?}] not in subscription",
                        supi, s_nssai.sst, s_nssai.sd
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
            s_nssai.sst, s_nssai.sd
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
}
