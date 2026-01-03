//! SEPP N32c Handler Functions
//!
//! Port of src/sepp/n32c-handler.c - Security capability request/response handlers

use crate::context::{sepp_self, PlmnId, SecurityCapability, SeppNode};

/// Security capability request data (from OpenAPI SecNegotiateReqData)
#[derive(Debug, Clone, Default)]
pub struct SecNegotiateReqData {
    /// Sender FQDN
    pub sender: String,
    /// Supported security capabilities
    pub supported_sec_capability_list: Vec<SecurityCapability>,
    /// Whether 3GPP-SBI-Target-apiRoot is supported
    pub target_apiroot_supported: bool,
    /// PLMN ID list
    pub plmn_id_list: Vec<PlmnId>,
    /// Target PLMN ID
    pub target_plmn_id: Option<PlmnId>,
    /// Supported features
    pub supported_features: Option<String>,
}

/// Security capability response data (from OpenAPI SecNegotiateRspData)
#[derive(Debug, Clone, Default)]
pub struct SecNegotiateRspData {
    /// Sender FQDN
    pub sender: String,
    /// Selected security capability
    pub selected_sec_capability: SecurityCapability,
    /// Whether 3GPP-SBI-Target-apiRoot is supported
    pub target_apiroot_supported: bool,
    /// PLMN ID list
    pub plmn_id_list: Vec<PlmnId>,
    /// Supported features
    pub supported_features: Option<String>,
}

/// Handle security capability request from peer SEPP
/// Port of sepp_n32c_handshake_handle_security_capability_request
pub fn handle_security_capability_request(
    node: &mut SeppNode,
    req_data: &SecNegotiateReqData,
) -> Result<(), String> {
    // Validate sender
    if req_data.sender.is_empty() {
        return Err("No SecNegotiateReqData.sender".to_string());
    }

    // Verify sender matches receiver
    if req_data.sender != node.receiver {
        return Err(format!(
            "FQDN mismatch: expected [{}], got [{}]",
            node.receiver, req_data.sender
        ));
    }

    // Validate supported security capabilities
    if req_data.supported_sec_capability_list.is_empty() {
        return Err("No supported_sec_capability_list".to_string());
    }

    // Check for supported capabilities
    let mut tls = false;
    let mut prins = false;
    let mut none = false;

    for cap in &req_data.supported_sec_capability_list {
        match cap {
            SecurityCapability::Tls => tls = true,
            SecurityCapability::Prins => prins = true,
            SecurityCapability::None => none = true,
            _ => {}
        }
    }

    // Get our security capability configuration
    let ctx = sepp_self();
    let (our_tls, our_prins) = {
        if let Ok(context) = ctx.read() {
            (
                context.security_capability.tls,
                context.security_capability.prins,
            )
        } else {
            (true, false) // Default
        }
    };

    // Negotiate security scheme
    if none {
        node.negotiated_security_scheme = SecurityCapability::None;
    } else if tls && our_tls {
        node.negotiated_security_scheme = SecurityCapability::Tls;
    } else if prins && our_prins {
        node.negotiated_security_scheme = SecurityCapability::Prins;
    } else {
        return Err("Unknown SupportedSecCapability".to_string());
    }

    // Set target API root support
    node.target_apiroot_supported = req_data.target_apiroot_supported;

    // Copy PLMN IDs
    node.plmn_ids.clear();
    for plmn_id in &req_data.plmn_id_list {
        node.add_plmn_id(plmn_id.clone());
    }

    // Set target PLMN ID if present
    if let Some(ref target_plmn_id) = req_data.target_plmn_id {
        node.set_target_plmn_id(target_plmn_id.clone());
    }

    // Parse supported features
    if let Some(ref features_str) = req_data.supported_features {
        if let Ok(features) = u64::from_str_radix(features_str, 16) {
            node.supported_features &= features;
        }
    } else {
        node.supported_features = 0;
    }

    log::info!(
        "[{}] Security capability negotiated: {:?}",
        node.receiver,
        node.negotiated_security_scheme
    );

    Ok(())
}

/// Handle security capability response from peer SEPP
/// Port of sepp_n32c_handshake_handle_security_capability_response
pub fn handle_security_capability_response(
    node: &mut SeppNode,
    rsp_data: &SecNegotiateRspData,
) -> Result<(), String> {
    // Validate sender
    if rsp_data.sender.is_empty() {
        return Err("No SecNegotiateRspData.sender".to_string());
    }

    // Verify sender matches receiver
    if rsp_data.sender != node.receiver {
        return Err(format!(
            "FQDN mismatch: expected [{}], got [{}]",
            node.receiver, rsp_data.sender
        ));
    }

    // Validate selected security capability
    if rsp_data.selected_sec_capability == SecurityCapability::Null {
        return Err("No selected_sec_capability".to_string());
    }

    // Set negotiated security scheme
    node.negotiated_security_scheme = rsp_data.selected_sec_capability;

    // Set target API root support
    node.target_apiroot_supported = rsp_data.target_apiroot_supported;

    // Copy PLMN IDs
    node.plmn_ids.clear();
    for plmn_id in &rsp_data.plmn_id_list {
        node.add_plmn_id(plmn_id.clone());
    }

    // Parse supported features
    if let Some(ref features_str) = rsp_data.supported_features {
        if let Ok(features) = u64::from_str_radix(features_str, 16) {
            node.supported_features &= features;
        }
    } else {
        node.supported_features = 0;
    }

    log::info!(
        "[{}] Security capability response: {:?}",
        node.receiver,
        node.negotiated_security_scheme
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_security_capability_request_tls() {
        let mut node = SeppNode::new(1, "sepp.peer.example.com");
        
        let req_data = SecNegotiateReqData {
            sender: "sepp.peer.example.com".to_string(),
            supported_sec_capability_list: vec![SecurityCapability::Tls],
            target_apiroot_supported: true,
            plmn_id_list: vec![PlmnId::new(310, 260, 3)],
            target_plmn_id: None,
            supported_features: Some("1".to_string()),
        };

        let result = handle_security_capability_request(&mut node, &req_data);
        assert!(result.is_ok());
        assert_eq!(node.negotiated_security_scheme, SecurityCapability::Tls);
        assert!(node.target_apiroot_supported);
        assert_eq!(node.plmn_ids.len(), 1);
    }

    #[test]
    fn test_handle_security_capability_request_none() {
        let mut node = SeppNode::new(1, "sepp.peer.example.com");
        
        let req_data = SecNegotiateReqData {
            sender: "sepp.peer.example.com".to_string(),
            supported_sec_capability_list: vec![SecurityCapability::None],
            target_apiroot_supported: false,
            plmn_id_list: vec![],
            target_plmn_id: None,
            supported_features: None,
        };

        let result = handle_security_capability_request(&mut node, &req_data);
        assert!(result.is_ok());
        assert_eq!(node.negotiated_security_scheme, SecurityCapability::None);
    }

    #[test]
    fn test_handle_security_capability_request_sender_mismatch() {
        let mut node = SeppNode::new(1, "sepp.peer.example.com");
        
        let req_data = SecNegotiateReqData {
            sender: "wrong.sender.com".to_string(),
            supported_sec_capability_list: vec![SecurityCapability::Tls],
            ..Default::default()
        };

        let result = handle_security_capability_request(&mut node, &req_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_security_capability_response() {
        let mut node = SeppNode::new(1, "sepp.peer.example.com");
        
        let rsp_data = SecNegotiateRspData {
            sender: "sepp.peer.example.com".to_string(),
            selected_sec_capability: SecurityCapability::Tls,
            target_apiroot_supported: true,
            plmn_id_list: vec![PlmnId::new(310, 260, 3)],
            supported_features: Some("1".to_string()),
        };

        let result = handle_security_capability_response(&mut node, &rsp_data);
        assert!(result.is_ok());
        assert_eq!(node.negotiated_security_scheme, SecurityCapability::Tls);
    }
}
