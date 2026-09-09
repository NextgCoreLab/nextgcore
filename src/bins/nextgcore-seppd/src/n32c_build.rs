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
            // Serving PLMN IDs from configuration (set via set_serving_plmn_ids)
            let serving_plmn_ids: Vec<PlmnId> = context.serving_plmn_ids.clone();
            (
                sender,
                security_capability,
                target_apiroot_supported,
                serving_plmn_ids,
            )
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
        req_data
            .supported_sec_capability_list
            .push(SecurityCapability::None);
    } else {
        if security_capability.tls {
            req_data
                .supported_sec_capability_list
                .push(SecurityCapability::Tls);
        }
        if security_capability.prins {
            req_data
                .supported_sec_capability_list
                .push(SecurityCapability::Prins);
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
            // Serving PLMN IDs from configuration (set via set_serving_plmn_ids)
            let serving_plmn_ids: Vec<PlmnId> = context.serving_plmn_ids.clone();
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
    if node.negotiated_security_scheme != SecurityCapability::None && node.target_apiroot_supported
    {
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
    /// `3GppSbiTargetApiRootSupported` — capital G, JSON **boolean**, `default:
    /// false` (`TS29573_N32_Handshake.yaml:340-342`). The spec's own comment notes
    /// the name breaks TS 29.501's naming convention and is kept for backward
    /// compatibility, so the casing is not ours to normalise.
    ///
    /// This was `rename = "3gppSbiTargetApiRootSupported"` typed `Option<i32>`. Both
    /// halves were wrong, and the type was the worse one: deserialising a JSON
    /// `true` into an `i32` is a serde **type error**, which aborts the whole
    /// `SecNegotiateReqData` parse and rejects the handshake — precisely when the
    /// peer DOES support target-apiRoot forwarding. `#[serde(default)]` does not
    /// rescue it, because a default applies to an absent field, not a mismatched one.
    ///
    /// Always serialised, never skipped: an explicit `false` equals the schema
    /// default, and emitting the member unconditionally means a peer never has to
    /// infer our capability from an absence.
    #[serde(default, rename = "3GppSbiTargetApiRootSupported")]
    pub target_apiroot_supported: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plmn_id_list: Vec<PlmnIdJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_plmn_id: Option<PlmnIdJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
            target_apiroot_supported: data.target_apiroot_supported,
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
    /// `3GppSbiTargetApiRootSupported` (`yaml:389-391`) — see the request struct's
    /// field for why the name and type both had to change.
    #[serde(default, rename = "3GppSbiTargetApiRootSupported")]
    pub target_apiroot_supported: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plmn_id_list: Vec<PlmnIdJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported_features: Option<String>,
}

impl From<&SecNegotiateRspData> for SecurityCapabilityResponseJson {
    fn from(data: &SecNegotiateRspData) -> Self {
        Self {
            sender: data.sender.clone(),
            selected_sec_capability: data.selected_sec_capability.to_string().to_string(),
            target_apiroot_supported: data.target_apiroot_supported,
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
// N32f TLS-mode envelope (TS 29.573 section 5.3.2: with TLS security the
// message is forwarded as-is over the TLS-protected N32-f connection; this
// envelope only frames it for the /n32f-process endpoint).
// PRINS-mode protection lives in prins.rs (JWE/JWS per section 6.3).
// ============================================================================

/// N32f pass-through message envelope (TLS security mode)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N32fMessage {
    /// Original request line
    pub request_line: N32fRequestLine,
    /// Original headers
    pub header: Vec<N32fHeader>,
    /// Original payload, base64url-encoded
    pub payload: Option<String>,
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

/// Build N32f message using TLS mode (pass-through, whole-message protection
/// is provided by the TLS connection itself)
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

    let payload = body.map(crate::jose::b64url_encode);

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
    }
}

/// Parse an N32f TLS-mode message received from peer SEPP
pub fn parse_n32f_message(json_bytes: &[u8]) -> Result<N32fMessage, String> {
    serde_json::from_slice(json_bytes).map_err(|e| format!("Failed to parse N32f message: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #100 anchor, emit side: the capability goes on the wire as
    /// `3GppSbiTargetApiRootSupported` (capital G) with a JSON **boolean**, never
    /// `0`/`1` and never under the lowercase name.
    ///
    /// Asserted against the serialized text rather than the struct, because the
    /// struct field name is ours and the wire name is the spec's — only the text
    /// pins the rename.
    #[test]
    fn the_target_apiroot_capability_is_a_boolean_under_the_capital_g_name() {
        for supported in [true, false] {
            let data = SecNegotiateReqData {
                sender: "sepp.local.example.com".to_string(),
                supported_sec_capability_list: vec![SecurityCapability::Tls],
                target_apiroot_supported: supported,
                plmn_id_list: vec![],
                target_plmn_id: None,
                supported_features: None,
            };
            let json = serde_json::to_string(&SecurityCapabilityRequestJson::from(&data)).unwrap();
            assert!(
                json.contains(&format!("\"3GppSbiTargetApiRootSupported\":{supported}")),
                "expected the capital-G name with a boolean {supported}; got {json}"
            );
            assert!(
                !json.contains("3gppSbiTargetApiRootSupported"),
                "the lowercase name is not the spec member; got {json}"
            );
            for wrong in [":1", ":0", ":\"true\"", ":\"false\""] {
                assert!(
                    !json.contains(&format!("\"3GppSbiTargetApiRootSupported\"{wrong}")),
                    "the value must be a JSON boolean, not {wrong}; got {json}"
                );
            }
        }
    }

    /// Same, on the response leg (`yaml:389-391`).
    #[test]
    fn the_response_capability_is_also_a_boolean_under_the_capital_g_name() {
        let data = SecNegotiateRspData {
            sender: "sepp.local.example.com".to_string(),
            selected_sec_capability: SecurityCapability::Prins,
            target_apiroot_supported: true,
            plmn_id_list: vec![],
            supported_features: None,
        };
        let json = serde_json::to_string(&SecurityCapabilityResponseJson::from(&data)).unwrap();
        assert!(
            json.contains("\"3GppSbiTargetApiRootSupported\":true"),
            "got {json}"
        );
        assert!(
            !json.contains("3gppSbiTargetApiRootSupported"),
            "got {json}"
        );
    }

    /// #100 anchor, accept side: a conformant peer's boolean `true` deserialises and
    /// reads as capability-supported. This is the regression — it previously failed
    /// with a serde **type error** against `Option<i32>`, aborting the whole
    /// `SecNegotiateReqData` parse and rejecting the handshake in exactly the case
    /// where the peer DOES support target-apiRoot forwarding.
    #[test]
    fn a_conformant_boolean_capability_deserialises_and_reads_as_supported() {
        let body = r#"{"sender":"sepp.peer.example.com",
            "supportedSecCapabilityList":["TLS"],
            "3GppSbiTargetApiRootSupported":true}"#;
        let json: SecurityCapabilityRequestJson =
            serde_json::from_str(body).expect("a boolean true must deserialise, not type-error");
        assert!(json.target_apiroot_supported);

        let body = r#"{"sender":"sepp.peer.example.com",
            "supportedSecCapabilityList":["TLS"],
            "3GppSbiTargetApiRootSupported":false}"#;
        let json: SecurityCapabilityRequestJson = serde_json::from_str(body).unwrap();
        assert!(!json.target_apiroot_supported);

        // And on the response leg.
        let body = r#"{"sender":"sepp.peer.example.com","selectedSecCapability":"PRINS",
            "3GppSbiTargetApiRootSupported":true}"#;
        let json: SecurityCapabilityResponseJson = serde_json::from_str(body).unwrap();
        assert!(json.target_apiroot_supported);
    }

    /// An absent capability flag is `false` (the schema's `default: false`), without
    /// an error — and the **lowercase** spelling this SEPP used to emit is NOT
    /// silently honoured, or a peer running the old code would appear conformant.
    #[test]
    fn an_absent_capability_defaults_to_false_and_the_old_lowercase_name_is_ignored() {
        let body = r#"{"sender":"sepp.peer.example.com","supportedSecCapabilityList":["TLS"]}"#;
        let json: SecurityCapabilityRequestJson =
            serde_json::from_str(body).expect("absent flag must not error");
        assert!(!json.target_apiroot_supported);

        let legacy = r#"{"sender":"sepp.peer.example.com","supportedSecCapabilityList":["TLS"],
            "3gppSbiTargetApiRootSupported":1}"#;
        let json: SecurityCapabilityRequestJson =
            serde_json::from_str(legacy).expect("an unknown member is ignored, not an error");
        assert!(
            !json.target_apiroot_supported,
            "the lowercase integer form is not the spec member and must not be read"
        );
    }

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
    }

    #[test]
    fn test_parse_n32f_message() {
        let json = r#"{"requestLine":{"method":"POST","url":"/test","protocol":"HTTP/2"},"header":[],"payload":null}"#;
        let result = parse_n32f_message(json.as_bytes());
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg.request_line.method, "POST");
    }

    #[test]
    fn test_serving_plmn_ids_from_context() {
        let ctx = sepp_self();
        if let Ok(mut context) = ctx.write() {
            context.set_sender("sepp.local.example.com");
            context.init(10, 100);
            context.set_serving_plmn_ids(vec![PlmnId::new(999, 70, 2)]);
        }

        let mut node = SeppNode::new(2, "sepp.peer.example.com");
        let req_data = build_security_capability_request(&mut node, false).unwrap();
        assert!(req_data
            .plmn_id_list
            .iter()
            .any(|p| p.mcc == 999 && p.mnc == 70));

        let rsp_data = build_security_capability_response(&node).unwrap();
        assert!(rsp_data
            .plmn_id_list
            .iter()
            .any(|p| p.mcc == 999 && p.mnc == 70));

        // Reset to avoid leaking into parallel tests
        if let Ok(mut context) = ctx.write() {
            context.set_serving_plmn_ids(vec![]);
        };
    }
}
