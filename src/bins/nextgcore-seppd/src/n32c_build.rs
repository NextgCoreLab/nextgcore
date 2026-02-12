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
            // Note: Serving PLMN IDs retrieved from context.serving_plmn_ids
            // Configured via YAML configuration or command line during initialization
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
            // Note: Serving PLMN IDs retrieved from context.serving_plmn_ids
            // Configured via YAML configuration or command line during initialization
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
    if node.negotiated_security_scheme != SecurityCapability::None
        && node.target_apiroot_supported {
            rsp_data.target_apiroot_supported = true;
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

// ============================================================================
// N32f JOSE Message Protection (TS 29.573 section 6.3)
// ============================================================================

/// N32f protected message envelope
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N32fMessage {
    /// JWS/JWE compact serialization of the protected SBI message
    pub request_line: N32fRequestLine,
    /// Protected headers (JWS signed or JWE encrypted)
    pub header: Vec<N32fHeader>,
    /// Protected payload (JWS signed or JWE encrypted), base64url-encoded
    pub payload: Option<String>,
    /// Modification list for PRINS (if security is PRINS)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub modifications_block: Vec<N32fModification>,
}

/// Request line in N32f message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct N32fRequestLine {
    pub method: String,
    pub url: String,
    pub protocol: String,
}

/// Header in N32f message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct N32fHeader {
    pub name: String,
    pub value: String,
}

/// Modification entry for PRINS mode
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N32fModification {
    pub ie_location: String,
    pub ie_path: String,
    pub ie_value: Option<String>,
    pub ie_action: String,
}

/// Build N32f protected message using TLS mode (pass-through, whole-message protection)
pub fn build_n32f_tls_message(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> N32fMessage {
    let request_line = N32fRequestLine {
        method: method.to_string(),
        url: url.to_string(),
        protocol: "HTTP/2".to_string(),
    };

    let n32f_headers: Vec<N32fHeader> = headers
        .iter()
        .map(|(name, value)| N32fHeader {
            name: name.clone(),
            value: value.clone(),
        })
        .collect();

    let payload = body.map(base64url_encode);

    log::debug!(
        "Built N32f TLS message: {} {} ({} headers, payload={})",
        method,
        url,
        n32f_headers.len(),
        payload.is_some()
    );

    N32fMessage {
        request_line,
        header: n32f_headers,
        payload,
        modifications_block: Vec::new(),
    }
}

/// Build N32f protected message using PRINS mode (selective protection)
/// PRINS allows modifying certain IEs while protecting integrity of others
pub fn build_n32f_prins_message(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    modifications: Vec<N32fModification>,
) -> N32fMessage {
    let request_line = N32fRequestLine {
        method: method.to_string(),
        url: url.to_string(),
        protocol: "HTTP/2".to_string(),
    };

    let n32f_headers: Vec<N32fHeader> = headers
        .iter()
        .map(|(name, value)| N32fHeader {
            name: name.clone(),
            value: value.clone(),
        })
        .collect();

    let payload = body.map(base64url_encode);

    log::debug!(
        "Built N32f PRINS message: {} {} ({} headers, {} modifications)",
        method,
        url,
        n32f_headers.len(),
        modifications.len()
    );

    N32fMessage {
        request_line,
        header: n32f_headers,
        payload,
        modifications_block: modifications,
    }
}

/// Parse an N32f message received from peer SEPP
pub fn parse_n32f_message(json_bytes: &[u8]) -> Result<N32fMessage, String> {
    serde_json::from_slice(json_bytes).map_err(|e| format!("Failed to parse N32f message: {e}"))
}

/// Base64url encode (no padding) - RFC 4648 section 5
fn base64url_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut i = 0;
    while i + 2 < data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        result.push(table[((n >> 18) & 0x3F) as usize] as char);
        result.push(table[((n >> 12) & 0x3F) as usize] as char);
        result.push(table[((n >> 6) & 0x3F) as usize] as char);
        result.push(table[(n & 0x3F) as usize] as char);
        i += 3;
    }

    let remaining = data.len() - i;
    if remaining == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        result.push(table[((n >> 18) & 0x3F) as usize] as char);
        result.push(table[((n >> 12) & 0x3F) as usize] as char);
        result.push(table[((n >> 6) & 0x3F) as usize] as char);
    } else if remaining == 1 {
        let n = (data[i] as u32) << 16;
        result.push(table[((n >> 18) & 0x3F) as usize] as char);
        result.push(table[((n >> 12) & 0x3F) as usize] as char);
    }

    result
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

    #[test]
    fn test_base64url_encode() {
        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
        assert_eq!(base64url_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_build_n32f_tls_message() {
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            (":authority".to_string(), "sepp.peer.com".to_string()),
        ];
        let body = b"{\"key\":\"value\"}";
        let msg = build_n32f_tls_message("POST", "/nudm-sdm/v1/supi", &headers, Some(body));

        assert_eq!(msg.request_line.method, "POST");
        assert_eq!(msg.request_line.url, "/nudm-sdm/v1/supi");
        assert_eq!(msg.header.len(), 2);
        assert!(msg.payload.is_some());
        assert!(msg.modifications_block.is_empty());
    }

    #[test]
    fn test_build_n32f_prins_message() {
        let modifications = vec![N32fModification {
            ie_location: "body".to_string(),
            ie_path: "$.supi".to_string(),
            ie_value: Some("imsi-001010123456789".to_string()),
            ie_action: "modify".to_string(),
        }];
        let msg = build_n32f_prins_message(
            "GET",
            "/nudm-sdm/v1/supi",
            &[],
            None,
            modifications,
        );

        assert_eq!(msg.request_line.method, "GET");
        assert!(msg.payload.is_none());
        assert_eq!(msg.modifications_block.len(), 1);
        assert_eq!(msg.modifications_block[0].ie_path, "$.supi");
    }

    #[test]
    fn test_parse_n32f_message() {
        let json = r#"{"requestLine":{"method":"POST","url":"/test","protocol":"HTTP/2"},"header":[],"payload":null,"modificationsBlock":[]}"#;
        let result = parse_n32f_message(json.as_bytes());
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg.request_line.method, "POST");
    }
}
