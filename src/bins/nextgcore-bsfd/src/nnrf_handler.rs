//! BSF NRF Handler
//!
//! Port of src/bsf/nnrf-handler.c - Handler for NRF discovery responses

use crate::sbi_path::bsf_sbi_send_request;

/// NF discovery search result (simplified)
#[derive(Debug, Clone, Default)]
pub struct SearchResult {
    pub nf_instances: Vec<NfInstanceInfo>,
    pub validity_period: Option<u32>,
}

/// NF instance information (simplified)
#[derive(Debug, Clone, Default)]
pub struct NfInstanceInfo {
    pub nf_instance_id: String,
    pub nf_type: String,
    pub nf_status: String,
    pub fqdn: Option<String>,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub priority: Option<u16>,
    pub capacity: Option<u16>,
    pub load: Option<u8>,
}

/// SBI transaction context for discovery
#[derive(Debug)]
pub struct SbiXactContext {
    pub id: u64,
    pub service_type: String,
    pub target_nf_type: String,
    pub requester_nf_type: String,
    pub sess_id: Option<u64>,
    pub stream_id: Option<u64>,
}

/// Handle NF discover response
/// Port of bsf_nnrf_handle_nf_discover
pub fn bsf_nnrf_handle_nf_discover(
    xact: &SbiXactContext,
    search_result: &SearchResult,
) -> Result<(), String> {
    log::debug!(
        "NF discover response: service_type={}, target_nf_type={}, requester_nf_type={}",
        xact.service_type,
        xact.target_nf_type,
        xact.requester_nf_type
    );

    if search_result.nf_instances.is_empty() {
        log::error!(
            "(NF discover) No [{}:{}]",
            xact.service_type,
            xact.requester_nf_type
        );
        return Err("No NF instances found".to_string());
    }

    // Process search result
    // In C: ogs_nnrf_disc_handle_nf_discover_search_result(SearchResult)
    for nf_instance in &search_result.nf_instances {
        log::debug!(
            "Found NF instance: id={}, type={}, status={}",
            nf_instance.nf_instance_id,
            nf_instance.nf_type,
            nf_instance.nf_status
        );
    }

    // Find NF instance by discovery parameters
    // In C: ogs_sbi_nf_instance_find_by_discovery_param(...)
    let nf_instance = search_result.nf_instances.first()
        .ok_or_else(|| "No suitable NF instance found".to_string())?;

    log::debug!(
        "Selected NF instance: {} ({})",
        nf_instance.nf_instance_id,
        nf_instance.nf_type
    );

    // Send request to discovered NF instance
    // In C: bsf_sbi_send_request(nf_instance, xact)
    let request = crate::sbi_path::PathSbiRequest {
        method: "GET".to_string(),
        uri: format!("/nbsf-management/v1/pcf-bindings"),
        headers: vec![],
        body: None,
    };

    bsf_sbi_send_request(&nf_instance.nf_instance_id, request)?;

    Ok(())
}

/// Handle NF status notify
pub fn handle_nf_status_notify(
    nf_instance_id: &str,
    nf_status: &str,
) -> Result<(), String> {
    log::debug!(
        "NF status notify: nf_instance_id={}, status={}",
        nf_instance_id,
        nf_status
    );

    match nf_status {
        "REGISTERED" => {
            log::info!("NF instance [{}] registered", nf_instance_id);
        }
        "DEREGISTERED" => {
            log::info!("NF instance [{}] deregistered", nf_instance_id);
        }
        "SUSPENDED" => {
            log::warn!("NF instance [{}] suspended", nf_instance_id);
        }
        _ => {
            log::warn!("Unknown NF status [{}] for instance [{}]", nf_status, nf_instance_id);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_result_empty() {
        let xact = SbiXactContext {
            id: 1,
            service_type: "nbsf-management".to_string(),
            target_nf_type: "PCF".to_string(),
            requester_nf_type: "BSF".to_string(),
            sess_id: Some(1),
            stream_id: Some(1),
        };

        let search_result = SearchResult::default();
        let result = bsf_nnrf_handle_nf_discover(&xact, &search_result);
        assert!(result.is_err());
    }

    #[test]
    fn test_search_result_with_instances() {
        let xact = SbiXactContext {
            id: 1,
            service_type: "nbsf-management".to_string(),
            target_nf_type: "PCF".to_string(),
            requester_nf_type: "BSF".to_string(),
            sess_id: Some(1),
            stream_id: Some(1),
        };

        let search_result = SearchResult {
            nf_instances: vec![NfInstanceInfo {
                nf_instance_id: "pcf-001".to_string(),
                nf_type: "PCF".to_string(),
                nf_status: "REGISTERED".to_string(),
                fqdn: Some("pcf.example.com".to_string()),
                ..Default::default()
            }],
            validity_period: Some(3600),
        };

        let result = bsf_nnrf_handle_nf_discover(&xact, &search_result);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_nf_status_notify() {
        let result = handle_nf_status_notify("nf-001", "REGISTERED");
        assert!(result.is_ok());

        let result = handle_nf_status_notify("nf-001", "DEREGISTERED");
        assert!(result.is_ok());

        let result = handle_nf_status_notify("nf-001", "SUSPENDED");
        assert!(result.is_ok());
    }
}
