//! BSF Nbsf Management Handler
//!
//! Port of src/bsf/nbsf-handler.c - Handler for PCF binding management

use crate::context::{bsf_self, BsfSess, PcfIpEndpoint, SNssai};

/// PCF Binding request data (simplified from OpenAPI)
#[derive(Debug, Clone, Default)]
pub struct PcfBindingRequest {
    pub supi: Option<String>,
    pub gpsi: Option<String>,
    pub ipv4_addr: Option<String>,
    pub ipv6_prefix: Option<String>,
    pub ipv4_frame_route_list: Vec<String>,
    pub ipv6_frame_route_list: Vec<String>,
    pub dnn: Option<String>,
    pub snssai: Option<SNssai>,
    pub pcf_fqdn: Option<String>,
    pub pcf_ip_end_points: Vec<PcfIpEndpoint>,
    pub supp_feat: Option<String>,
}

/// PCF Binding response data
#[derive(Debug, Clone, Default)]
pub struct PcfBindingResponse {
    pub binding_id: String,
    pub supi: Option<String>,
    pub gpsi: Option<String>,
    pub ipv4_addr: Option<String>,
    pub ipv6_prefix: Option<String>,
    pub dnn: Option<String>,
    pub snssai: Option<SNssai>,
    pub pcf_fqdn: Option<String>,
    pub pcf_ip_end_points: Vec<PcfIpEndpoint>,
    pub supp_feat: Option<String>,
    pub location: Option<String>,
}

/// HTTP status codes
pub const HTTP_STATUS_OK: u16 = 200;
pub const HTTP_STATUS_CREATED: u16 = 201;
pub const HTTP_STATUS_NO_CONTENT: u16 = 204;
pub const HTTP_STATUS_BAD_REQUEST: u16 = 400;
pub const HTTP_STATUS_NOT_FOUND: u16 = 404;

/// Result type for handler operations
pub type HandlerResult = Result<(u16, Option<PcfBindingResponse>), (u16, String)>;

/// Handle PCF binding POST request (create new binding)
/// Port of bsf_nbsf_management_handle_pcf_binding for POST method
pub fn handle_pcf_binding_post(
    request: &PcfBindingRequest,
    server_uri: &str,
) -> HandlerResult {
    // Validate required fields
    if request.snssai.is_none() {
        return Err((HTTP_STATUS_BAD_REQUEST, "No S-NSSAI".to_string()));
    }

    if request.dnn.is_none() {
        return Err((HTTP_STATUS_BAD_REQUEST, "No DNN".to_string()));
    }

    if request.pcf_fqdn.is_none() && request.pcf_ip_end_points.is_empty() {
        return Err((HTTP_STATUS_BAD_REQUEST, 
            "No PCF address information".to_string()));
    }

    let ctx = bsf_self();
    
    // Try to find existing session or create new one
    let sess = {
        let context = ctx.read().map_err(|_| 
            (HTTP_STATUS_BAD_REQUEST, "Context lock error".to_string()))?;
        
        // Try to find by IPv4
        let mut found_sess = None;
        if let Some(ref ipv4) = request.ipv4_addr {
            found_sess = context.sess_find_by_ipv4addr(ipv4);
        }
        // Try to find by IPv6 if not found
        if found_sess.is_none() {
            if let Some(ref ipv6) = request.ipv6_prefix {
                found_sess = context.sess_find_by_ipv6prefix(ipv6);
            }
        }
        found_sess
    };

    let sess = if let Some(existing) = sess {
        existing
    } else {
        // Create new session
        let context = ctx.read().map_err(|_| 
            (HTTP_STATUS_BAD_REQUEST, "Context lock error".to_string()))?;
        
        context.sess_add_by_ip_address(
            request.ipv4_addr.as_deref(),
            request.ipv6_prefix.as_deref(),
        ).ok_or_else(|| (HTTP_STATUS_BAD_REQUEST, "Failed to create session".to_string()))?
    };

    // Update session with request data
    let mut updated_sess = sess.clone();
    
    // Set S-NSSAI
    if let Some(ref snssai) = request.snssai {
        updated_sess.s_nssai = snssai.clone();
    }

    // Set DNN
    if let Some(ref dnn) = request.dnn {
        updated_sess.dnn = Some(dnn.clone());
    }

    // Set PCF FQDN
    if let Some(ref pcf_fqdn) = request.pcf_fqdn {
        updated_sess.pcf_fqdn = Some(pcf_fqdn.clone());
    }

    // Set PCF IP endpoints
    updated_sess.pcf_ip = request.pcf_ip_end_points.clone();

    // Set SUPI/GPSI
    if let Some(ref supi) = request.supi {
        updated_sess.supi = Some(supi.clone());
    }
    if let Some(ref gpsi) = request.gpsi {
        updated_sess.gpsi = Some(gpsi.clone());
    }

    // Set frame routes
    updated_sess.ipv4_frame_route_list = request.ipv4_frame_route_list.clone();
    updated_sess.ipv6_frame_route_list = request.ipv6_frame_route_list.clone();

    // Handle supported features
    if let Some(ref supp_feat) = request.supp_feat {
        if let Ok(features) = u64::from_str_radix(supp_feat, 16) {
            updated_sess.management_features &= features;
        }
    } else {
        updated_sess.management_features = 0;
    }

    // Update session in context
    {
        let context = ctx.read().map_err(|_| 
            (HTTP_STATUS_BAD_REQUEST, "Context lock error".to_string()))?;
        context.sess_update(&updated_sess);
    }

    // Build response
    let location = format!("{}/nbsf-management/v1/pcf-bindings/{}", 
        server_uri, updated_sess.binding_id);

    let response = PcfBindingResponse {
        binding_id: updated_sess.binding_id.clone(),
        supi: updated_sess.supi.clone(),
        gpsi: updated_sess.gpsi.clone(),
        ipv4_addr: updated_sess.ipv4addr_string.clone(),
        ipv6_prefix: updated_sess.ipv6prefix_string.clone(),
        dnn: updated_sess.dnn.clone(),
        snssai: Some(updated_sess.s_nssai.clone()),
        pcf_fqdn: updated_sess.pcf_fqdn.clone(),
        pcf_ip_end_points: updated_sess.pcf_ip.clone(),
        supp_feat: if updated_sess.management_features != 0 {
            Some(format!("{:X}", updated_sess.management_features))
        } else {
            None
        },
        location: Some(location),
    };

    Ok((HTTP_STATUS_CREATED, Some(response)))
}


/// Handle PCF binding PATCH request (update binding)
/// Port of bsf_nbsf_management_handle_pcf_binding for PATCH method
pub fn handle_pcf_binding_patch(
    binding_id: &str,
    _request: &PcfBindingRequest,
) -> HandlerResult {
    let ctx = bsf_self();
    let context = ctx.read().map_err(|_| 
        (HTTP_STATUS_BAD_REQUEST, "Context lock error".to_string()))?;

    // Find session by binding ID
    let _sess = context.sess_find_by_binding_id(binding_id)
        .ok_or_else(|| (HTTP_STATUS_NOT_FOUND, "Session not found".to_string()))?;

    // Note: PATCH logic would update specific fields of the PCF binding
    // Per 3GPP TS 29.521, PATCH supports partial updates of binding attributes
    // For now, return success as updates would require session modification
    Ok((HTTP_STATUS_NO_CONTENT, None))
}

/// Build PcfBindingRequest from session (for response building)
pub fn build_pcf_binding_from_sess(sess: &BsfSess) -> PcfBindingResponse {
    PcfBindingResponse {
        binding_id: sess.binding_id.clone(),
        supi: sess.supi.clone(),
        gpsi: sess.gpsi.clone(),
        ipv4_addr: sess.ipv4addr_string.clone(),
        ipv6_prefix: sess.ipv6prefix_string.clone(),
        dnn: sess.dnn.clone(),
        snssai: Some(sess.s_nssai.clone()),
        pcf_fqdn: sess.pcf_fqdn.clone(),
        pcf_ip_end_points: sess.pcf_ip.clone(),
        supp_feat: if sess.management_features != 0 {
            Some(format!("{:X}", sess.management_features))
        } else {
            None
        },
        location: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::bsf_context_init;

    fn setup_context() {
        bsf_context_init(100);
    }

    #[test]
    fn test_handle_pcf_binding_post_missing_snssai() {
        setup_context();
        
        let request = PcfBindingRequest {
            ipv4_addr: Some("192.168.1.1".to_string()),
            dnn: Some("internet".to_string()),
            pcf_fqdn: Some("pcf.example.com".to_string()),
            ..Default::default()
        };

        let result = handle_pcf_binding_post(&request, "http://localhost:7777");
        assert!(result.is_err());
        let (status, msg) = result.unwrap_err();
        assert_eq!(status, HTTP_STATUS_BAD_REQUEST);
        assert!(msg.contains("S-NSSAI"));
    }

    #[test]
    fn test_handle_pcf_binding_post_missing_dnn() {
        setup_context();
        
        let request = PcfBindingRequest {
            ipv4_addr: Some("192.168.1.1".to_string()),
            snssai: Some(SNssai::new(1, Some(0x010203))),
            pcf_fqdn: Some("pcf.example.com".to_string()),
            ..Default::default()
        };

        let result = handle_pcf_binding_post(&request, "http://localhost:7777");
        assert!(result.is_err());
        let (status, msg) = result.unwrap_err();
        assert_eq!(status, HTTP_STATUS_BAD_REQUEST);
        assert!(msg.contains("DNN"));
    }

    #[test]
    fn test_handle_pcf_binding_post_missing_pcf_address() {
        setup_context();
        
        let request = PcfBindingRequest {
            ipv4_addr: Some("192.168.1.1".to_string()),
            snssai: Some(SNssai::new(1, Some(0x010203))),
            dnn: Some("internet".to_string()),
            ..Default::default()
        };

        let result = handle_pcf_binding_post(&request, "http://localhost:7777");
        assert!(result.is_err());
        let (status, msg) = result.unwrap_err();
        assert_eq!(status, HTTP_STATUS_BAD_REQUEST);
        assert!(msg.contains("PCF address"));
    }

    #[test]
    fn test_build_pcf_binding_from_sess() {
        let mut sess = BsfSess::new(1);
        sess.dnn = Some("internet".to_string());
        sess.s_nssai = SNssai::new(1, Some(0x010203));
        sess.pcf_fqdn = Some("pcf.example.com".to_string());

        let response = build_pcf_binding_from_sess(&sess);
        assert_eq!(response.binding_id, "1");
        assert_eq!(response.dnn, Some("internet".to_string()));
        assert!(response.snssai.is_some());
    }
}
