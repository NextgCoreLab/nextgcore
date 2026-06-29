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
/// Per TS 33.501 §13.2.4.4.1 the PRINS N32-f key hierarchy is derived from the
/// N32-c TLS connection's 64-octet RFC 5705 master exporter (see
/// [`derive_n32f_key_material`]). The TLS master secret for the peer is
/// obtained out-of-band from the N32-c TLS connection (see
/// `set_n32c_tls_exporter_secret`); it is NEVER carried in this message, so
/// there is no `keyNonce`. The asymmetric (ES256) public key each SEPP uses
/// to sign its modificationsBlock entries IS exchanged here so the receiver
/// can verify them (TS 33.501 §13.2.4.6).
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
    /// Requester's ES256 public key (PEM, SubjectPublicKeyInfo) used to sign
    /// its modificationsBlock entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modifications_signing_public_key: Option<String>,
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
    /// Responder's ES256 public key (PEM) for modificationsBlock verification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modifications_signing_public_key: Option<String>,
}

/// JWE cipher suites this SEPP supports, preference-ordered
pub const SUPPORTED_JWE_SUITES: &[&str] = &["A256GCM"];
/// JWS cipher suites this SEPP supports, preference-ordered.
/// ES256 is asymmetric (TS 33.501 §13.2.4.6); HS256 retained for
/// interoperability negotiation but the modificationsBlock is always
/// signed/verified with the asymmetric ES256 key.
pub const SUPPORTED_JWS_SUITES: &[&str] = &["ES256", "HS256"];

// ============================================================================
// N32-c TLS exporter secret store (TS 33.501 §13.2.4.4 / RFC 5705)
//
// The N32-f session key is derived from the N32-c TLS connection's exported
// keying material. ogs-sbi exposes `export_keying_material` on a live rustls
// `ConnectionCommon` (added by L1), but the SbiServer/SbiClient handler
// abstractions do not currently surface that connection to this crate. Until
// they do, the TLS layer deposits the exported secret here keyed by peer
// FQDN; the exchange-params flow consumes it. When no secret is present (e.g.
// the plaintext test transport) the derivation falls back to a deterministic
// context-bound input so both peers still agree.
// ============================================================================

/// Length of the N32 master key (the RFC 5705 exporter secret) we derive the
/// N32-f key hierarchy from (TS 33.501 §13.2.4.4.1). A 64-octet master is a
/// valid HKDF PRK (>= HashLen for SHA-256).
pub const N32F_EXPORTER_SECRET_LEN: usize = 64;

fn exporter_secret_store() -> &'static std::sync::RwLock<std::collections::HashMap<String, Vec<u8>>>
{
    static STORE: std::sync::OnceLock<
        std::sync::RwLock<std::collections::HashMap<String, Vec<u8>>>,
    > = std::sync::OnceLock::new();
    STORE.get_or_init(|| std::sync::RwLock::new(std::collections::HashMap::new()))
}

/// Deposit the RFC 5705 exporter secret derived from the N32-c TLS
/// connection with `peer_fqdn`. Called by the TLS layer once ogs-sbi
/// surfaces the connection; see [`export_n32f_exporter_secret`].
pub fn set_n32c_tls_exporter_secret(peer_fqdn: &str, secret: Vec<u8>) {
    if let Ok(mut store) = exporter_secret_store().write() {
        store.insert(peer_fqdn.to_string(), secret);
    }
}

/// Fetch the exporter secret previously deposited for `peer_fqdn`.
pub fn take_n32c_tls_exporter_secret(peer_fqdn: &str) -> Option<Vec<u8>> {
    exporter_secret_store()
        .write()
        .ok()
        .and_then(|mut s| s.remove(peer_fqdn))
}

/// Pick the first locally supported suite from the peer's list
pub fn select_cipher_suite(peer_list: &[String], ours: &[&str]) -> Option<String> {
    ours.iter()
        .find(|s| peer_list.iter().any(|p| p == *s))
        .map(|s| s.to_string())
}

/// Role of this SEPP in the N32-c handshake. It selects which half of the
/// N32-f key hierarchy this SEPP uses to PROTECT the messages it originates
/// (TS 33.501 §13.2.4.4.1): the handshake initiator uses the "parallel" key
/// set, the responder uses the "reverse" set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N32fRole {
    /// N32-c exchange-params requester → "parallel" key set
    Initiator,
    /// N32-c exchange-params responder → "reverse" key set
    Responder,
}

impl N32fRole {
    /// The peer's role (the originator of inbound messages we unprotect).
    pub fn opposite(self) -> Self {
        match self {
            N32fRole::Initiator => N32fRole::Responder,
            N32fRole::Responder => N32fRole::Initiator,
        }
    }
}

/// Direction of an N32-f message relative to the SBI exchange it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N32fDirection {
    Request,
    Response,
}

/// The full N32-f key hierarchy derived from the 64-octet N32 master key
/// (TS 33.501 §13.2.4.4.1). Four 256-bit session keys + four 64-bit IV salts,
/// one (key, salt) pair per (role, direction). Both SEPPs derive an identical
/// `N32fKeyMaterial` because the master is shared (RFC 5705 exporter) and the
/// N32-f context ID is canonical (`{initiator}-{responder}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N32fKeyMaterial {
    /// Initiator-originated request: (key, iv_salt)
    pub parallel_req: ([u8; 32], [u8; 8]),
    /// Initiator-originated response: (key, iv_salt)
    pub parallel_resp: ([u8; 32], [u8; 8]),
    /// Responder-originated request: (key, iv_salt)
    pub reverse_req: ([u8; 32], [u8; 8]),
    /// Responder-originated response: (key, iv_salt)
    pub reverse_resp: ([u8; 32], [u8; 8]),
}

impl N32fKeyMaterial {
    /// Select the (session key, IV salt) for a message ORIGINATED by a SEPP
    /// acting in `originator_role`, travelling in `direction`. The sender
    /// passes its own role; the receiver passes the peer's role (so both ends
    /// of one message select the same pair).
    pub fn select(
        &self,
        originator_role: N32fRole,
        direction: N32fDirection,
    ) -> (&[u8; 32], &[u8; 8]) {
        let pair = match (originator_role, direction) {
            (N32fRole::Initiator, N32fDirection::Request) => &self.parallel_req,
            (N32fRole::Initiator, N32fDirection::Response) => &self.parallel_resp,
            (N32fRole::Responder, N32fDirection::Request) => &self.reverse_req,
            (N32fRole::Responder, N32fDirection::Response) => &self.reverse_resp,
        };
        (&pair.0, &pair.1)
    }
}

/// N32-KDF (TS 33.501 §13.2.4.4.1): HKDF-Expand ONLY. The 64-octet N32 master
/// from the N32-c TLS RFC 5705 exporter is already a uniformly-random PRK, so
/// the Extract step is skipped (`from_prk`) and only Expand is applied with
/// `info = "N32" || n32_context_id || label`.
fn n32_kdf(master: &[u8], n32_context_id: &str, label: &str, out: &mut [u8]) {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::from_prk(master).expect("master >= 32 bytes (PRK length)");
    let info = [b"N32".as_slice(), n32_context_id.as_bytes(), label.as_bytes()].concat();
    hk.expand(&info, out)
        .expect("valid HKDF-SHA256 Expand output length");
}

/// Derive the four N32-f session keys and four IV salts from the 64-octet
/// master via the N32-KDF (TS 33.501 §13.2.4.4.1). `n32_context_id` is the
/// canonical, shared N32-f context identifier (`{initiator}-{responder}`) so
/// both SEPPs derive identical material.
pub fn derive_n32f_key_material(master: &[u8], n32_context_id: &str) -> N32fKeyMaterial {
    let key = |label: &str| -> [u8; 32] {
        let mut out = [0u8; 32];
        n32_kdf(master, n32_context_id, label, &mut out);
        out
    };
    let salt = |label: &str| -> [u8; 8] {
        let mut out = [0u8; 8];
        n32_kdf(master, n32_context_id, label, &mut out);
        out
    };
    N32fKeyMaterial {
        parallel_req: (key("parallel_request_key"), salt("parallel_request_iv_salt")),
        parallel_resp: (
            key("parallel_response_key"),
            salt("parallel_response_iv_salt"),
        ),
        reverse_req: (key("reverse_request_key"), salt("reverse_request_iv_salt")),
        reverse_resp: (key("reverse_response_key"), salt("reverse_response_iv_salt")),
    }
}

/// Canonical, shared N32-f context identifier used to bind the key hierarchy:
/// `{initiator_ctx}-{responder_ctx}`. Both peers build the same value (it is
/// also the JOSE `kid`), so they derive identical key material.
pub fn canonical_n32f_context_id(ctx_id_initiator: &str, ctx_id_responder: &str) -> String {
    format!("{ctx_id_initiator}-{ctx_id_responder}")
}

/// Resolve the exporter secret used to derive the N32-f session key with
/// `peer_fqdn`. Prefers the real RFC 5705 secret deposited by the TLS layer
/// (TS 33.501 §13.2.4.4); when absent (plaintext/test transport) it falls
/// back to a deterministic, context-bound input so both peers still agree.
///
/// The fallback is NOT a security boundary — it merely lets the PRINS layer
/// be exercised without TLS. With a real N32-c TLS connection,
/// `set_n32c_tls_exporter_secret` makes the live exporter secret available
/// here and the fallback is never used.
fn resolve_exporter_secret(
    peer_fqdn: &str,
    ctx_id_initiator: &str,
    ctx_id_responder: &str,
) -> Vec<u8> {
    if let Some(secret) = take_n32c_tls_exporter_secret(peer_fqdn) {
        log::debug!("[{peer_fqdn}] N32-f key derived from N32-c TLS exporter (TS 33.501)");
        return secret;
    }
    log::warn!(
        "[{peer_fqdn}] no N32-c TLS exporter secret; deriving N32-f key \
         hierarchy from context-bound fallback (no-TLS transport)"
    );
    // Deterministic, identical on both ends because the context-ID pair is
    // mirrored. Domain-separated from any real exporter secret. SHA-512
    // yields exactly 64 octets, a valid HKDF PRK for the N32-KDF.
    use sha2::{Digest, Sha512};
    let mut input = b"N32f-no-tls-fallback".to_vec();
    let (lo, hi) = if ctx_id_initiator <= ctx_id_responder {
        (ctx_id_initiator, ctx_id_responder)
    } else {
        (ctx_id_responder, ctx_id_initiator)
    };
    input.extend_from_slice(lo.as_bytes());
    input.push(b'|');
    input.extend_from_slice(hi.as_bytes());
    Sha512::digest(&input).to_vec()
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

    // Register the requester's ES256 modifications-signing public key so we
    // can verify its modificationsBlock entries (TS 33.501 §13.2.4.6).
    register_peer_signing_key(&req.sender, req.modifications_signing_public_key.as_deref())?;

    // TS 33.501 §13.2.4.4.1: derive the full N32-f key hierarchy from the
    // 64-octet N32 master (RFC 5705 exporter). The requester is the N32-c
    // initiator; we (the responder) use the "reverse" key set to protect the
    // messages we originate. The canonical context ID `{initiator}-{responder}`
    // makes both peers derive identical material.
    let master = resolve_exporter_secret(&req.sender, &req.n32f_context_id, &local_context_id);
    let n32_context_id = canonical_n32f_context_id(&req.n32f_context_id, &local_context_id);
    let key_material = derive_n32f_key_material(&master, &n32_context_id);

    node.n32f_security = Some(crate::context::N32fSecurityInfo {
        local_context_id: local_context_id.clone(),
        peer_context_id: req.n32f_context_id.clone(),
        key_material,
        role: N32fRole::Responder,
        kid: n32_context_id,
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
        modifications_signing_public_key: local_signing_public_key_pem(),
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

    // Register the responder's ES256 modifications-signing public key so we
    // can verify its modificationsBlock entries (TS 33.501 §13.2.4.6).
    register_peer_signing_key(&rsp.sender, rsp.modifications_signing_public_key.as_deref())?;

    // TS 33.501 §13.2.4.4.1: derive the full N32-f key hierarchy from the
    // 64-octet N32 master (RFC 5705 exporter). We (the request sender) are the
    // N32-c initiator and use the "parallel" key set to protect the messages
    // we originate. The canonical context ID `{initiator}-{responder}` makes
    // both peers derive identical material.
    let master =
        resolve_exporter_secret(&rsp.sender, &sent_req.n32f_context_id, &rsp.n32f_context_id);
    let n32_context_id =
        canonical_n32f_context_id(&sent_req.n32f_context_id, &rsp.n32f_context_id);
    let key_material = derive_n32f_key_material(&master, &n32_context_id);

    node.n32f_security = Some(crate::context::N32fSecurityInfo {
        local_context_id: sent_req.n32f_context_id.clone(),
        peer_context_id: rsp.n32f_context_id.clone(),
        key_material,
        role: N32fRole::Initiator,
        kid: n32_context_id,
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

/// Public wrapper for the initiator path (n32_server) to obtain this SEPP's
/// ES256 modifications-signing public key PEM for the exchange-params request.
pub fn local_signing_public_key_pem_pub() -> Option<String> {
    local_signing_public_key_pem()
}

/// PEM-encode this SEPP's ES256 modifications-signing public key for the
/// exchange-params message, ensuring a local identity exists first.
fn local_signing_public_key_pem() -> Option<String> {
    use p256::pkcs8::{EncodePublicKey, LineEnding};
    // Lazily mint an identity if none was provisioned, so a SEPP always has
    // an asymmetric signing key for the modificationsBlock.
    if crate::prins::local_signing_key().is_none() {
        crate::prins::generate_local_identity();
    }
    let sk = crate::prins::local_signing_key()?;
    let vk = sk.verifying_key();
    vk.to_public_key_pem(LineEnding::LF).ok()
}

/// Register a peer's ES256 modifications-signing public key (from the PEM in
/// an exchange-params message) under its sender FQDN. The key is REQUIRED:
/// without it we could not verify the peer's modificationsBlock entries
/// (TS 33.501 §13.2.4.6), so a missing/invalid key fails the handshake.
fn register_peer_signing_key(sender: &str, pem: Option<&str>) -> Result<(), String> {
    let pem = pem.ok_or_else(|| {
        format!("peer [{sender}] sent no modificationsSigningPublicKey (PRINS requires ES256)")
    })?;
    let vk = crate::jose::parse_es256_public_key_pem(pem)
        .map_err(|e| format!("peer [{sender}] sent bad ES256 public key: {e}"))?;
    crate::prins::register_verifying_key(sender, vk);
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

    /// Helper: a freshly minted ES256 public key PEM (a peer's signing key).
    fn test_es256_pubkey_pem() -> String {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::rand_core::OsRng;
        use p256::pkcs8::{EncodePublicKey, LineEnding};
        let sk = SigningKey::random(&mut OsRng);
        sk.verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
    }

    /// Lowercase-hex of a byte slice (KAT documentation helper).
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// KAT (TS 33.501 §13.2.4.4.1 N32-KDF): a fixed 64-octet master `[0x5a;64]`
    /// and a fixed N32-f context ID derive four 32-byte session keys + four
    /// 8-byte IV salts. Each output is checked against an INDEPENDENT in-test
    /// HKDF-Expand-SHA256 reference computed from the documented `info` bytes
    /// (`"N32" || n32_context_id || label`), so the test is self-verifying.
    #[test]
    fn test_n32_kdf_known_answer_vector() {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let master = [0x5au8; 64];
        let n32_context_id = "kat-ctx-0001";
        let km = derive_n32f_key_material(&master, n32_context_id);

        // Independent reference: HKDF-Expand-only over the same PRK + info.
        let expand = |label: &str, len: usize| -> Vec<u8> {
            let hk = Hkdf::<Sha256>::from_prk(&master).unwrap();
            let info =
                [b"N32".as_slice(), n32_context_id.as_bytes(), label.as_bytes()].concat();
            let mut out = vec![0u8; len];
            hk.expand(&info, &mut out).unwrap();
            out
        };

        assert_eq!(km.parallel_req.0.as_slice(), expand("parallel_request_key", 32));
        assert_eq!(km.parallel_req.1.as_slice(), expand("parallel_request_iv_salt", 8));
        assert_eq!(km.parallel_resp.0.as_slice(), expand("parallel_response_key", 32));
        assert_eq!(
            km.parallel_resp.1.as_slice(),
            expand("parallel_response_iv_salt", 8)
        );
        assert_eq!(km.reverse_req.0.as_slice(), expand("reverse_request_key", 32));
        assert_eq!(km.reverse_req.1.as_slice(), expand("reverse_request_iv_salt", 8));
        assert_eq!(km.reverse_resp.0.as_slice(), expand("reverse_response_key", 32));
        assert_eq!(
            km.reverse_resp.1.as_slice(),
            expand("reverse_response_iv_salt", 8)
        );

        // Pinned expected hex for `master=[0x5a;64]`, `n32_context_id="kat-ctx-0001"`
        // (documents the vector; matches the independent HKDF reference above).
        assert_eq!(hex(&km.parallel_req.0), KAT_PARALLEL_REQUEST_KEY);
        assert_eq!(hex(&km.parallel_req.1), KAT_PARALLEL_REQUEST_IV_SALT);
        assert_eq!(hex(&km.parallel_resp.0), KAT_PARALLEL_RESPONSE_KEY);
        assert_eq!(hex(&km.parallel_resp.1), KAT_PARALLEL_RESPONSE_IV_SALT);
        assert_eq!(hex(&km.reverse_req.0), KAT_REVERSE_REQUEST_KEY);
        assert_eq!(hex(&km.reverse_req.1), KAT_REVERSE_REQUEST_IV_SALT);
        assert_eq!(hex(&km.reverse_resp.0), KAT_REVERSE_RESPONSE_KEY);
        assert_eq!(hex(&km.reverse_resp.1), KAT_REVERSE_RESPONSE_IV_SALT);

        // The four session keys are pairwise distinct.
        let keys = [
            km.parallel_req.0,
            km.parallel_resp.0,
            km.reverse_req.0,
            km.reverse_resp.0,
        ];
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "keys {i} and {j} must differ");
            }
        }
        // Each IV salt is exactly 8 bytes, and the four are pairwise distinct.
        let salts = [
            km.parallel_req.1,
            km.parallel_resp.1,
            km.reverse_req.1,
            km.reverse_resp.1,
        ];
        for s in &salts {
            assert_eq!(s.len(), 8);
        }
        for i in 0..salts.len() {
            for j in (i + 1)..salts.len() {
                assert_ne!(salts[i], salts[j], "salts {i} and {j} must differ");
            }
        }
    }

    // Pinned KAT vector for master=[0x5a;64], n32_context_id="kat-ctx-0001".
    const KAT_PARALLEL_REQUEST_KEY: &str =
        "5b6170e2eddda87d53846435e2e123dd0af477ee78fd4d32e0a5de0eacdbf91b";
    const KAT_PARALLEL_REQUEST_IV_SALT: &str = "e075ef5cf1e183bf";
    const KAT_PARALLEL_RESPONSE_KEY: &str =
        "9f7d358bec9041fcc2daa467e84d937c67fe36b1054c30336475c3b43a1b330f";
    const KAT_PARALLEL_RESPONSE_IV_SALT: &str = "48ae73f00fec4cff";
    const KAT_REVERSE_REQUEST_KEY: &str =
        "de260e5e520a2ef2f1fc6361d47841922b5ebd667ea41b6b86432ea8bf10c1be";
    const KAT_REVERSE_REQUEST_IV_SALT: &str = "1c2d3023d4d39ade";
    const KAT_REVERSE_RESPONSE_KEY: &str =
        "bcd5cf7906d4ad3f83e42cc299c73505b8890b9bb3c9e3dfb25286db8b84fdc0";
    const KAT_REVERSE_RESPONSE_IV_SALT: &str = "fe1d7b847195935d";

    /// Determinism + sensitivity of the N32-KDF: identical inputs yield
    /// identical material; a different master or a different N32-f context ID
    /// yields different material (TS 33.501 §13.2.4.4.1).
    #[test]
    fn test_key_material_determinism_and_sensitivity() {
        let master_a = [0x11u8; 64];
        let master_b = [0x22u8; 64];

        let k1 = derive_n32f_key_material(&master_a, "ctx-i-ctx-r");
        let k2 = derive_n32f_key_material(&master_a, "ctx-i-ctx-r");
        assert_eq!(k1, k2, "same master + context => identical material");

        // Different context ID (info) -> different material
        let k3 = derive_n32f_key_material(&master_a, "ctx-X-ctx-r");
        assert_ne!(k1, k3);

        // Different master (PRK) -> different material
        let k4 = derive_n32f_key_material(&master_b, "ctx-i-ctx-r");
        assert_ne!(k1, k4);
    }

    /// The no-TLS fallback exporter secret is exactly 64 octets (a valid HKDF
    /// PRK) and is mirrored across the context-ID pair so both peers agree.
    #[test]
    fn test_resolve_exporter_secret_fallback_is_64_octets() {
        // No secret deposited for this peer => fallback path.
        let s1 = resolve_exporter_secret("no-tls-peer.example.com", "ctx-i", "ctx-r");
        let s2 = resolve_exporter_secret("no-tls-peer.example.com", "ctx-r", "ctx-i");
        assert_eq!(s1.len(), 64);
        assert_eq!(s1, s2, "fallback is order-independent across the ctx pair");
    }

    /// C6: with the SAME TLS exporter secret deposited for both peers (as a
    /// real N32-c TLS connection would yield), both sides derive an identical
    /// N32-f session key (TS 33.501 §13.2.4.4).
    #[test]
    fn test_exchange_params_tls_exporter_key_agreement() {
        {
            let ctx = sepp_self();
            let mut context = ctx.write().unwrap();
            context.set_sender("sepp.local.example.com");
        }

        // The same RFC 5705 exporter secret both N32-c endpoints would see.
        let exporter_secret = vec![0x5au8; N32F_EXPORTER_SECRET_LEN];
        set_n32c_tls_exporter_secret("sepp-a.example.com", exporter_secret.clone());
        set_n32c_tls_exporter_secret("sepp.local.example.com", exporter_secret);

        // A builds the request, carrying its ES256 signing pubkey.
        let a_ctx_id = crate::prins::generate_n32f_context_id();
        let req = SecParamExchReqData {
            sender: "sepp-a.example.com".to_string(),
            n32f_context_id: a_ctx_id.clone(),
            jwe_cipher_suite_list: vec!["A256GCM".to_string()],
            jws_cipher_suite_list: vec!["ES256".to_string()],
            modification_policy_allowed_paths: vec![],
            modifications_signing_public_key: Some(test_es256_pubkey_pem()),
            sender_api_root: None,
        };

        // B (responder) handles it
        let mut node_b = SeppNode::new(10, "sepp-a.example.com");
        node_b.negotiated_security_scheme = SecurityCapability::Prins;
        let rsp = handle_exchange_params_request(&mut node_b, &req).unwrap();
        assert_eq!(rsp.selected_jwe_cipher_suite, "A256GCM");
        assert_eq!(rsp.selected_jws_cipher_suite, "ES256");
        // The responder advertises its own signing pubkey back.
        assert!(rsp.modifications_signing_public_key.is_some());

        // A (initiator) handles the response
        let mut node_a = SeppNode::new(11, "sepp.local.example.com");
        node_a.negotiated_security_scheme = SecurityCapability::Prins;
        handle_exchange_params_response(&mut node_a, &req, &rsp).unwrap();

        let sec_a = node_a.n32f_security.unwrap();
        let sec_b = node_b.n32f_security.unwrap();
        // Identical key hierarchy derived from the shared TLS master secret;
        // mirrored context IDs and mirrored roles (initiator vs responder).
        assert_eq!(sec_a.key_material, sec_b.key_material);
        assert_eq!(sec_a.role, N32fRole::Initiator);
        assert_eq!(sec_b.role, N32fRole::Responder);
        assert_eq!(sec_a.local_context_id, sec_b.peer_context_id);
        assert_eq!(sec_a.peer_context_id, sec_b.local_context_id);
        // Both kids equal the canonical `{initiator}-{responder}` context ID.
        assert_eq!(sec_a.kid, sec_b.kid);
        assert_eq!(sec_a.kid, format!("{}-{}", a_ctx_id, sec_b.local_context_id));
    }

    #[test]
    fn test_exchange_params_rejects_missing_signing_key() {
        {
            let ctx = sepp_self();
            let mut context = ctx.write().unwrap();
            context.set_sender("sepp.local.example.com");
        }
        let mut node_b = SeppNode::new(13, "sepp-a.example.com");
        node_b.negotiated_security_scheme = SecurityCapability::Prins;
        // No modifications_signing_public_key => handshake must be rejected.
        let req = SecParamExchReqData {
            sender: "sepp-a.example.com".to_string(),
            n32f_context_id: "ctx".to_string(),
            jwe_cipher_suite_list: vec!["A256GCM".to_string()],
            jws_cipher_suite_list: vec!["ES256".to_string()],
            modification_policy_allowed_paths: vec![],
            modifications_signing_public_key: None,
            sender_api_root: None,
        };
        let err = handle_exchange_params_request(&mut node_b, &req).unwrap_err();
        assert!(err.contains("modificationsSigningPublicKey"), "got: {err}");
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
            jws_cipher_suite_list: vec!["ES256".to_string()],
            modification_policy_allowed_paths: vec![],
            modifications_signing_public_key: Some(test_es256_pubkey_pem()),
            sender_api_root: None,
        };
        assert!(handle_exchange_params_request(&mut node_b, &req).is_err());
    }
}
