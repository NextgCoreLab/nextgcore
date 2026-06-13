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

    // Negotiate security scheme per TS 29.573 sec 6.1.5.2: select the
    // highest-priority mutually supported capability, TLS > PRINS > NONE.
    // NONE is only selected when the peer offers nothing better (a
    // peer offering only NONE is requesting termination).
    if tls && our_tls {
        node.negotiated_security_scheme = SecurityCapability::Tls;
    } else if prins && our_prins {
        node.negotiated_security_scheme = SecurityCapability::Prins;
    } else if none {
        node.negotiated_security_scheme = SecurityCapability::None;
    } else {
        return Err("No mutually supported security capability".to_string());
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

// ============================================================================
// Exchange-params (N32-c phase 2, TS 29.573 sec 6.1.5.3) and
// N32-f session-key establishment (TS 33.501 sec 13.2)
// ============================================================================

/// Security parameter exchange request (SecParamExchReqData).
///
/// NOTE on `key_nonce`: TS 33.501 sec 13.2.4.4 derives the PRINS session
/// key from the N32-c TLS-session exporter. The rustls plumbing in ogs-sbi
/// does not expose `export_keying_material` through SbiClient/SbiServer,
/// so as a documented deviation each side contributes a random 32-byte
/// nonce here and the key is HKDF-SHA256-derived from both nonces (see
/// [`derive_n32f_session_key`]). Replace with the TLS exporter once
/// ogs-sbi exposes it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecParamExchReqData {
    /// Sender FQDN
    pub sender: String,
    /// N32-f context ID allocated by the requester
    pub n32f_context_id: String,
    /// Supported JWE cipher suites, preference-ordered
    #[serde(default)]
    pub jwe_cipher_suite_list: Vec<String>,
    /// Supported JWS cipher suites, preference-ordered
    #[serde(default)]
    pub jws_cipher_suite_list: Vec<String>,
    /// IE paths the requester permits intermediaries to modify
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modification_policy_allowed_paths: Vec<String>,
    /// Key-agreement nonce, base64url (deviation; see type docs)
    pub key_nonce: String,
    /// Requester's N32-c API root so the responder can deliver n32f-error
    /// reports (practical extension; the spec resolves the sender FQDN)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_api_root: Option<String>,
}

/// Security parameter exchange response (SecParamExchRspData)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecParamExchRspData {
    /// Sender FQDN
    pub sender: String,
    /// N32-f context ID allocated by the responder
    pub n32f_context_id: String,
    /// Selected JWE cipher suite
    pub selected_jwe_cipher_suite: String,
    /// Selected JWS cipher suite
    pub selected_jws_cipher_suite: String,
    /// IE paths the responder permits intermediaries to modify
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modification_policy_allowed_paths: Vec<String>,
    /// Key-agreement nonce, base64url (deviation; see SecParamExchReqData)
    pub key_nonce: String,
}

/// JWE cipher suites this SEPP supports, preference-ordered
pub const SUPPORTED_JWE_SUITES: &[&str] = &["A256GCM"];
/// JWS cipher suites this SEPP supports, preference-ordered
pub const SUPPORTED_JWS_SUITES: &[&str] = &["HS256"];

/// Pick the first locally supported suite from the peer's list
pub fn select_cipher_suite(peer_list: &[String], ours: &[&str]) -> Option<String> {
    ours.iter()
        .find(|s| peer_list.iter().any(|p| p == *s))
        .map(|s| s.to_string())
}

/// Derive the N32-f session key (TS 33.501 sec 13.2.4.4-shaped, with the
/// TLS-exporter IKM replaced by exchanged nonces — see SecParamExchReqData).
///
/// HKDF-SHA256:
///   ikm  = nonce_initiator || nonce_responder
///   salt = lexicographically ordered FQDN pair
///   info = "N32f-PRINS-A256GCM" || ctx_id_initiator || ctx_id_responder
///
/// Both SEPPs compute the identical 32-byte key; it is distinct per
/// FQDN pair and per context-ID pair.
pub fn derive_n32f_session_key(
    nonce_initiator: &[u8],
    nonce_responder: &[u8],
    fqdn_a: &str,
    fqdn_b: &str,
    ctx_id_initiator: &str,
    ctx_id_responder: &str,
) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let (lo, hi) = if fqdn_a <= fqdn_b {
        (fqdn_a, fqdn_b)
    } else {
        (fqdn_b, fqdn_a)
    };
    let salt = format!("{lo}|{hi}");

    let mut ikm = Vec::with_capacity(nonce_initiator.len() + nonce_responder.len());
    ikm.extend_from_slice(nonce_initiator);
    ikm.extend_from_slice(nonce_responder);

    let mut info = b"N32f-PRINS-A256GCM".to_vec();
    info.extend_from_slice(ctx_id_initiator.as_bytes());
    info.extend_from_slice(ctx_id_responder.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Generate a random 32-byte key-agreement nonce (base64url)
pub fn generate_key_nonce() -> String {
    use rand::Rng as _;
    let mut nonce = [0u8; 32];
    rand::rng().fill(&mut nonce);
    crate::jose::b64url_encode(&nonce)
}

/// Handle an exchange-params request (responder side). Selects cipher
/// suites, allocates a local N32-f context ID, derives and installs the
/// session key on `node`, and returns the response to send.
pub fn handle_exchange_params_request(
    node: &mut SeppNode,
    req: &SecParamExchReqData,
) -> Result<SecParamExchRspData, String> {
    if req.sender.is_empty() {
        return Err("No SecParamExchReqData.sender".to_string());
    }
    if req.sender != node.receiver {
        return Err(format!(
            "FQDN mismatch: expected [{}], got [{}]",
            node.receiver, req.sender
        ));
    }
    if node.negotiated_security_scheme != SecurityCapability::Prins {
        return Err("exchange-params requires negotiated PRINS".to_string());
    }

    let jwe = select_cipher_suite(&req.jwe_cipher_suite_list, SUPPORTED_JWE_SUITES)
        .ok_or("No mutually supported JWE cipher suite")?;
    let jws = select_cipher_suite(&req.jws_cipher_suite_list, SUPPORTED_JWS_SUITES)
        .ok_or("No mutually supported JWS cipher suite")?;

    let (local_fqdn, _) = local_identity()?;

    let local_context_id = crate::prins::generate_n32f_context_id();
    let local_nonce = generate_key_nonce();

    let peer_nonce =
        crate::jose::b64url_decode(&req.key_nonce).map_err(|e| format!("bad keyNonce: {e}"))?;
    let our_nonce = crate::jose::b64url_decode(&local_nonce).expect("locally generated");

    // Requester is the initiator
    let session_key = derive_n32f_session_key(
        &peer_nonce,
        &our_nonce,
        &req.sender,
        &local_fqdn,
        &req.n32f_context_id,
        &local_context_id,
    );

    node.n32f_security = Some(crate::context::N32fSecurityInfo {
        local_context_id: local_context_id.clone(),
        peer_context_id: req.n32f_context_id.clone(),
        session_key,
        kid: format!("{}-{}", req.n32f_context_id, local_context_id),
        jwe_cipher_suite: jwe.clone(),
        jws_cipher_suite: jws.clone(),
    });

    // Learn where to deliver n32f-error reports for this peer
    if let Some(ref api_root) = req.sender_api_root {
        node.peer_api_root = Some(api_root.clone());
    }

    log::info!(
        "[{}] N32-f params exchanged: jwe={jwe} jws={jws} local_ctx={local_context_id} peer_ctx={}",
        node.receiver,
        req.n32f_context_id
    );

    Ok(SecParamExchRspData {
        sender: local_fqdn,
        n32f_context_id: local_context_id,
        selected_jwe_cipher_suite: jwe,
        selected_jws_cipher_suite: jws,
        modification_policy_allowed_paths: Vec::new(),
        key_nonce: local_nonce,
    })
}

/// Handle an exchange-params response (initiator side). Verifies the
/// selected suites, derives and installs the session key on `node`.
pub fn handle_exchange_params_response(
    node: &mut SeppNode,
    sent_req: &SecParamExchReqData,
    rsp: &SecParamExchRspData,
) -> Result<(), String> {
    if rsp.sender.is_empty() {
        return Err("No SecParamExchRspData.sender".to_string());
    }
    if rsp.sender != node.receiver {
        return Err(format!(
            "FQDN mismatch: expected [{}], got [{}]",
            node.receiver, rsp.sender
        ));
    }
    if !SUPPORTED_JWE_SUITES.contains(&rsp.selected_jwe_cipher_suite.as_str()) {
        return Err(format!(
            "Peer selected unsupported JWE suite [{}]",
            rsp.selected_jwe_cipher_suite
        ));
    }
    if !SUPPORTED_JWS_SUITES.contains(&rsp.selected_jws_cipher_suite.as_str()) {
        return Err(format!(
            "Peer selected unsupported JWS suite [{}]",
            rsp.selected_jws_cipher_suite
        ));
    }

    let our_nonce = crate::jose::b64url_decode(&sent_req.key_nonce)
        .map_err(|e| format!("bad local keyNonce: {e}"))?;
    let peer_nonce = crate::jose::b64url_decode(&rsp.key_nonce)
        .map_err(|e| format!("bad peer keyNonce: {e}"))?;

    // We (the request sender) are the initiator
    let session_key = derive_n32f_session_key(
        &our_nonce,
        &peer_nonce,
        &sent_req.sender,
        &rsp.sender,
        &sent_req.n32f_context_id,
        &rsp.n32f_context_id,
    );

    node.n32f_security = Some(crate::context::N32fSecurityInfo {
        local_context_id: sent_req.n32f_context_id.clone(),
        peer_context_id: rsp.n32f_context_id.clone(),
        session_key,
        kid: format!("{}-{}", sent_req.n32f_context_id, rsp.n32f_context_id),
        jwe_cipher_suite: rsp.selected_jwe_cipher_suite.clone(),
        jws_cipher_suite: rsp.selected_jws_cipher_suite.clone(),
    });

    log::info!(
        "[{}] N32-f params confirmed: jwe={} jws={} local_ctx={} peer_ctx={}",
        node.receiver,
        rsp.selected_jwe_cipher_suite,
        rsp.selected_jws_cipher_suite,
        sent_req.n32f_context_id,
        rsp.n32f_context_id
    );

    Ok(())
}

/// Get this SEPP's sender FQDN from the global context
fn local_identity() -> Result<(String, ()), String> {
    let ctx = sepp_self();
    let context = ctx
        .read()
        .map_err(|_| "context lock poisoned".to_string())?;
    let sender = context
        .sender
        .clone()
        .ok_or("local sender FQDN not configured")?;
    Ok((sender, ()))
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

    #[test]
    fn test_tls_preferred_over_none() {
        // Peer offers both NONE and TLS: TLS must win (TS 29.573 priority)
        let mut node = SeppNode::new(1, "sepp.peer.example.com");
        let req_data = SecNegotiateReqData {
            sender: "sepp.peer.example.com".to_string(),
            supported_sec_capability_list: vec![SecurityCapability::None, SecurityCapability::Tls],
            ..Default::default()
        };
        handle_security_capability_request(&mut node, &req_data).unwrap();
        assert_eq!(node.negotiated_security_scheme, SecurityCapability::Tls);
    }

    #[test]
    fn test_capability_mismatch_is_negotiation_failure() {
        // Peer offers only PRINS but local config (default) has prins=false
        let mut node = SeppNode::new(1, "sepp.peer.example.com");
        let req_data = SecNegotiateReqData {
            sender: "sepp.peer.example.com".to_string(),
            supported_sec_capability_list: vec![SecurityCapability::Prins],
            ..Default::default()
        };
        // Force known local capabilities
        {
            let ctx = sepp_self();
            let mut context = ctx.write().unwrap();
            context.security_capability.tls = true;
            context.security_capability.prins = false;
        }
        let result = handle_security_capability_request(&mut node, &req_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_select_cipher_suite() {
        let peer = vec!["A128GCM".to_string(), "A256GCM".to_string()];
        assert_eq!(
            select_cipher_suite(&peer, SUPPORTED_JWE_SUITES),
            Some("A256GCM".to_string())
        );
        assert_eq!(
            select_cipher_suite(&["A128CBC-HS256".to_string()], SUPPORTED_JWE_SUITES),
            None
        );
    }

    #[test]
    fn test_key_derivation_symmetric_and_distinct() {
        let n_i = [1u8; 32];
        let n_r = [2u8; 32];
        // Both ends compute the same key regardless of FQDN argument order
        let k1 = derive_n32f_session_key(&n_i, &n_r, "a.example", "b.example", "ctx-i", "ctx-r");
        let k2 = derive_n32f_session_key(&n_i, &n_r, "b.example", "a.example", "ctx-i", "ctx-r");
        assert_eq!(k1, k2);
        // Different PLMN pair -> different key
        let k3 = derive_n32f_session_key(&n_i, &n_r, "a.example", "c.example", "ctx-i", "ctx-r");
        assert_ne!(k1, k3);
        // Different context IDs -> different key
        let k4 = derive_n32f_session_key(&n_i, &n_r, "a.example", "b.example", "ctx-X", "ctx-r");
        assert_ne!(k1, k4);
        // Different nonces -> different key
        let k5 = derive_n32f_session_key(&n_r, &n_i, "a.example", "b.example", "ctx-i", "ctx-r");
        assert_ne!(k1, k5);
    }

    #[test]
    fn test_exchange_params_both_sides_agree() {
        // Initiator A, responder B
        {
            let ctx = sepp_self();
            let mut context = ctx.write().unwrap();
            context.set_sender("sepp.local.example.com");
        }

        // A builds the request
        let a_ctx_id = crate::prins::generate_n32f_context_id();
        let req = SecParamExchReqData {
            sender: "sepp-a.example.com".to_string(),
            n32f_context_id: a_ctx_id.clone(),
            jwe_cipher_suite_list: vec!["A256GCM".to_string()],
            jws_cipher_suite_list: vec!["HS256".to_string()],
            modification_policy_allowed_paths: vec![],
            key_nonce: generate_key_nonce(),
            sender_api_root: None,
        };

        // B (responder) handles it
        let mut node_b = SeppNode::new(10, "sepp-a.example.com");
        node_b.negotiated_security_scheme = SecurityCapability::Prins;
        let rsp = handle_exchange_params_request(&mut node_b, &req).unwrap();
        assert_eq!(rsp.selected_jwe_cipher_suite, "A256GCM");
        assert_eq!(rsp.selected_jws_cipher_suite, "HS256");

        // A (initiator) handles the response
        let mut node_a = SeppNode::new(11, "sepp.local.example.com");
        node_a.negotiated_security_scheme = SecurityCapability::Prins;
        handle_exchange_params_response(&mut node_a, &req, &rsp).unwrap();

        let sec_a = node_a.n32f_security.unwrap();
        let sec_b = node_b.n32f_security.unwrap();
        // Identical session keys, mirrored context IDs
        assert_eq!(sec_a.session_key, sec_b.session_key);
        assert_eq!(sec_a.local_context_id, sec_b.peer_context_id);
        assert_eq!(sec_a.peer_context_id, sec_b.local_context_id);
    }

    #[test]
    fn test_exchange_params_suite_mismatch_rejected() {
        {
            let ctx = sepp_self();
            let mut context = ctx.write().unwrap();
            context.set_sender("sepp.local.example.com");
        }
        let mut node_b = SeppNode::new(12, "sepp-a.example.com");
        node_b.negotiated_security_scheme = SecurityCapability::Prins;
        let req = SecParamExchReqData {
            sender: "sepp-a.example.com".to_string(),
            n32f_context_id: "ctx".to_string(),
            jwe_cipher_suite_list: vec!["A128CBC-HS256".to_string()],
            jws_cipher_suite_list: vec!["HS256".to_string()],
            modification_policy_allowed_paths: vec![],
            key_nonce: generate_key_nonce(),
            sender_api_root: None,
        };
        assert!(handle_exchange_params_request(&mut node_b, &req).is_err());
    }
}
