//! SEPP N32c Build Functions
//!
//! Port of src/sepp/n32c-build.c - Build security capability request/response messages

use crate::context::{sepp_self, PlmnId, SecurityCapability, SeppNode};
use crate::n32c_handler::{SecNegotiateReqData, SecNegotiateRspData};

/// N32 Handshake feature flags
pub const N32_HANDSHAKE_NFTLST: u64 = 0x01;

/// Build security capability request message
/// Port of sepp_n32c_handshake_build_security_capability_request
pub fn build_security_capability_request(
    node: &mut SeppNode,
    none: bool,
) -> Option<SecNegotiateReqData> {
    let ctx = sepp_self();
    let (sender, security_capability, target_apiroot_supported, serving_plmn_ids) = {
        if let Ok(context) = ctx.read() {
            let sender = context.sender.clone()?;
            let security_capability = context.security_capability.clone();
            let target_apiroot_supported = context.target_apiroot_supported;
            // TODO: Get serving PLMN IDs from local configuration
            let serving_plmn_ids: Vec<PlmnId> = vec![];
            (sender, security_capability, target_apiroot_supported, serving_plmn_ids)
        } else {
            return None;
        }
    };

    let mut req_data = SecNegotiateReqData {
        sender,
        supported_sec_capability_list: Vec::new(),
        target_apiroot_supported: false,
        plmn_id_list: Vec::new(),
        target_plmn_id: None,
        supported_features: None,
    };

    // Build supported security capability list
    if none {
        req_data.supported_sec_capability_list.push(SecurityCapability::None);
    } else {
        if security_capability.tls {
            req_data.supported_sec_capability_list.push(SecurityCapability::Tls);
        }
        if security_capability.prins {
            req_data.supported_sec_capability_list.push(SecurityCapability::Prins);
        }
    }

    if req_data.supported_sec_capability_list.is_empty() {
        log::error!("No supported security capabilities");
        return None;
    }

    // Set target API root support (only if not terminating)
    if !none && target_apiroot_supported {
        req_data.target_apiroot_supported = true;
    }

    // Add serving PLMN IDs
    req_data.plmn_id_list = serving_plmn_ids;

    // Add target PLMN ID if configured
    if let Some(ref target_plmn_id) = node.target_plmn_id {
        req_data.target_plmn_id = Some(target_plmn_id.clone());
    }

    // Set supported features
    node.supported_features |= N32_HANDSHAKE_NFTLST;
    req_data.supported_features = Some(format!("{:x}", node.supported_features));

    log::debug!(
        "[{}] Built security capability request (none={})",
        node.receiver,
        none
    );

    Some(req_data)
}

/// Build security capability response message
/// Port of sepp_n32c_handshake_send_security_capability_response (response building part)
pub fn build_security_capability_response(node: &SeppNode) -> Option<SecNegotiateRspData> {
    let ctx = sepp_self();
    let (sender, serving_plmn_ids) = {
        if let Ok(context) = ctx.read() {
            let sender = context.sender.clone()?;
            // TODO: Get serving PLMN IDs from local configuration
            let serving_plmn_ids: Vec<PlmnId> = vec![];
            (sender, serving_plmn_ids)
        } else {
            return None;
        }
    };

    let mut rsp_data = SecNegotiateRspData {
        sender,
        selected_sec_capability: node.negotiated_security_scheme,
        target_apiroot_supported: false,
        plmn_id_list: Vec::new(),
        supported_features: None,
    };

    // Set target API root support (only if security is enabled)
    if node.negotiated_security_scheme != SecurityCapability::None {
        if node.target_apiroot_supported {
            rsp_data.target_apiroot_supported = true;
        }
    }

    // Add serving PLMN IDs
    rsp_data.plmn_id_list = serving_plmn_ids;

    // Set supported features
    rsp_data.supported_features = Some(format!("{:x}", node.supported_features));

    log::debug!(
        "[{}] Built security capability response (scheme={:?})",
        node.receiver,
        node.negotiated_security_scheme
    );

    Some(rsp_data)
}

/// SBI request structure for N32c handshake
#[derive(Debug, Clone)]
pub struct SbiRequest {
    pub method: String,
    pub service_name: String,
    pub api_version: String,
    pub resource: String,
    pub body: Option<String>,
}

/// Build SBI request for security capability exchange
pub fn build_security_capability_sbi_request(
    node: &mut SeppNode,
    none: bool,
) -> Option<SbiRequest> {
    let req_data = build_security_capability_request(node, none)?;

    // Serialize to JSON
    let body = serde_json::to_string(&SecurityCapabilityRequestJson::from(&req_data)).ok()?;

    Some(SbiRequest {
        method: "POST".to_string(),
        service_name: "n32c-handshake".to_string(),
        api_version: "v1".to_string(),
        resource: "exchange-capability".to_string(),
        body: Some(body),
    })
}

/// JSON representation for serialization
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityCapabilityRequestJson {
    pub sender: String,
    pub supported_sec_capability_list: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "3gppSbiTargetApiRootSupported")]
    pub target_apiroot_supported: Option<i32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub plmn_id_list: Vec<PlmnIdJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_plmn_id: Option<PlmnIdJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_features: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PlmnIdJson {
    pub mcc: String,
    pub mnc: String,
}

impl From<&SecNegotiateReqData> for SecurityCapabilityRequestJson {
    fn from(data: &SecNegotiateReqData) -> Self {
        Self {
            sender: data.sender.clone(),
            supported_sec_capability_list: data
                .supported_sec_capability_list
                .iter()
                .map(|c| c.to_string().to_string())
                .collect(),
            target_apiroot_supported: if data.target_apiroot_supported {
                Some(1)
            } else {
                None
            },
            plmn_id_list: data
                .plmn_id_list
                .iter()
                .map(|p| PlmnIdJson {
                    mcc: format!("{:03}", p.mcc),
                    mnc: if p.mnc_len == 2 {
                        format!("{:02}", p.mnc)
                    } else {
                        format!("{:03}", p.mnc)
                    },
                })
                .collect(),
            target_plmn_id: data.target_plmn_id.as_ref().map(|p| PlmnIdJson {
                mcc: format!("{:03}", p.mcc),
                mnc: if p.mnc_len == 2 {
                    format!("{:02}", p.mnc)
                } else {
                    format!("{:03}", p.mnc)
                },
            }),
            supported_features: data.supported_features.clone(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityCapabilityResponseJson {
    pub sender: String,
    pub selected_sec_capability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "3gppSbiTargetApiRootSupported")]
    pub target_apiroot_supported: Option<i32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub plmn_id_list: Vec<PlmnIdJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_features: Option<String>,
}

impl From<&SecNegotiateRspData> for SecurityCapabilityResponseJson {
    fn from(data: &SecNegotiateRspData) -> Self {
        Self {
            sender: data.sender.clone(),
            selected_sec_capability: data.selected_sec_capability.to_string().to_string(),
            target_apiroot_supported: if data.target_apiroot_supported {
                Some(1)
            } else {
                None
            },
            plmn_id_list: data
                .plmn_id_list
                .iter()
                .map(|p| PlmnIdJson {
                    mcc: format!("{:03}", p.mcc),
                    mnc: if p.mnc_len == 2 {
                        format!("{:02}", p.mnc)
                    } else {
                        format!("{:03}", p.mnc)
                    },
                })
                .collect(),
            supported_features: data.supported_features.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_security_capability_request() {
        let mut node = SeppNode::new(1, "sepp.peer.example.com");
        node.target_plmn_id = Some(PlmnId::new(310, 260, 3));

        // Initialize context with sender
        let ctx = sepp_self();
        if let Ok(mut context) = ctx.write() {
            context.set_sender("sepp.local.example.com");
            context.init(10, 100);
        }

        let req_data = build_security_capability_request(&mut node, false);
        assert!(req_data.is_some());

        let req_data = req_data.unwrap();
        assert_eq!(req_data.sender, "sepp.local.example.com");
        assert!(!req_data.supported_sec_capability_list.is_empty());
    }

    #[test]
    fn test_build_security_capability_request_none() {
        let mut node = SeppNode::new(1, "sepp.peer.example.com");

        // Initialize context with sender
        let ctx = sepp_self();
        if let Ok(mut context) = ctx.write() {
            context.set_sender("sepp.local.example.com");
            context.init(10, 100);
        }

        let req_data = build_security_capability_request(&mut node, true);
        assert!(req_data.is_some());

        let req_data = req_data.unwrap();
        assert_eq!(req_data.supported_sec_capability_list.len(), 1);
        assert_eq!(
            req_data.supported_sec_capability_list[0],
            SecurityCapability::None
        );
    }

    #[test]
    fn test_build_security_capability_response() {
        let mut node = SeppNode::new(1, "sepp.peer.example.com");
        node.negotiated_security_scheme = SecurityCapability::Tls;
        node.target_apiroot_supported = true;
        node.supported_features = N32_HANDSHAKE_NFTLST;

        // Initialize context with sender
        let ctx = sepp_self();
        if let Ok(mut context) = ctx.write() {
            context.set_sender("sepp.local.example.com");
            context.init(10, 100);
        }

        let rsp_data = build_security_capability_response(&node);
        assert!(rsp_data.is_some());

        let rsp_data = rsp_data.unwrap();
        assert_eq!(rsp_data.sender, "sepp.local.example.com");
        assert_eq!(rsp_data.selected_sec_capability, SecurityCapability::Tls);
        assert!(rsp_data.target_apiroot_supported);
    }
}
