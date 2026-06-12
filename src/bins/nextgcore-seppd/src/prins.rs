//! PRINS - PRotection of attributes at the Inter-PLMN N32 interface
//!
//! Implements N32-f message protection per TS 29.573 sec 6.3 and
//! TS 33.501 sec 13.2:
//!
//! - `DataToIntegrityProtectBlock` (metaData / requestLine / headers /
//!   payload with `encBlockIndex` references) travels as the JWE AAD
//! - `DataToIntegrityProtectAndCipherBlock` (`dataToEncrypt` array) is the
//!   JWE plaintext (alg="dir", enc="A256GCM")
//! - `modificationsBlock` is a chain of flattened JWS objects; the first
//!   entry is created by the sending SEPP over the JWE tag, each IPX
//!   modification appends a JWS whose payload references the previous tag
//! - decode/verify failures map onto `N32fErrorType` for the
//!   `/n32c-handshake/v1/n32f-error` report (TS 29.573 sec 6.1.5.4)
//!
//! Session keys are per-peer, established during the N32-c
//! exchange-params handshake (see `n32c_handler::derive_n32f_session_key`).

use std::collections::HashMap;

use crate::jose::{
    self, b64url_decode, b64url_encode, FlatJwe, FlatJws, JoseError, JWE_KEY_LEN,
};

// ============================================================================
// Data-type / protection-policy profiles (TS 29.573 sec 6.1.5.3.4)
// ============================================================================

/// Data-type profile defining which IEs to protect for a given API.
#[derive(Debug, Clone)]
pub struct DataTypeProfile {
    /// Profile identifier
    pub id: String,
    /// API service name this profile applies to
    pub service_name: String,
    /// IEs that must be encrypted (JSON paths into the body)
    pub encrypt_ies: Vec<IeDescriptor>,
}

/// Descriptor for an information element to protect
#[derive(Debug, Clone)]
pub struct IeDescriptor {
    /// Location: "BODY", "HEADER", or "URI_PARAM"
    pub location: String,
    /// JSON path expression (e.g., "$.supi", "$.pei")
    pub path: String,
}

/// Modification policy: which IE paths an intermediary (or peer) is
/// allowed to modify via the modificationsBlock JSON-Patch operations.
#[derive(Debug, Clone, Default)]
pub struct ModificationPolicy {
    /// JSON paths that may be modified (empty = nothing may be modified)
    pub allowed_paths: Vec<String>,
}

/// PRINS security context for an established N32-f connection.
#[derive(Debug, Clone)]
pub struct PrinsContext {
    /// N32-f context ID allocated by the local SEPP (peer puts this into
    /// the metaData of messages it sends to us)
    pub local_context_id: String,
    /// N32-f context ID allocated by the peer SEPP (we put this into the
    /// metaData of messages we send to the peer)
    pub peer_context_id: String,
    /// Session key established during the N32-c exchange-params handshake
    pub session_key: [u8; JWE_KEY_LEN],
    /// Key identifier (kid) for the session key
    pub kid: String,
    /// This SEPP's FQDN (JWS identity of locally created modification entries)
    pub local_fqdn: String,
    /// Data-type profiles agreed during the N32-c handshake
    pub profiles: Vec<DataTypeProfile>,
    /// Modification policy agreed during the N32-c handshake
    pub modification_policy: ModificationPolicy,
}

impl PrinsContext {
    pub fn new(
        local_context_id: impl Into<String>,
        peer_context_id: impl Into<String>,
        session_key: [u8; JWE_KEY_LEN],
        kid: impl Into<String>,
        local_fqdn: impl Into<String>,
    ) -> Self {
        let mut ctx = Self {
            local_context_id: local_context_id.into(),
            peer_context_id: peer_context_id.into(),
            session_key,
            kid: kid.into(),
            local_fqdn: local_fqdn.into(),
            profiles: Vec::new(),
            modification_policy: ModificationPolicy::default(),
        };
        ctx.add_default_profiles();
        ctx
    }

    /// Add default data-type profiles for common 5G APIs
    pub fn add_default_profiles(&mut self) {
        self.profiles.push(DataTypeProfile {
            id: "nudm-sdm-profile".to_string(),
            service_name: "nudm-sdm".to_string(),
            encrypt_ies: vec![
                IeDescriptor {
                    location: "BODY".to_string(),
                    path: "$.supi".to_string(),
                },
                IeDescriptor {
                    location: "BODY".to_string(),
                    path: "$.pei".to_string(),
                },
                IeDescriptor {
                    location: "BODY".to_string(),
                    path: "$.gpsi".to_string(),
                },
            ],
        });
        self.profiles.push(DataTypeProfile {
            id: "nudm-uecm-profile".to_string(),
            service_name: "nudm-uecm".to_string(),
            encrypt_ies: vec![
                IeDescriptor {
                    location: "BODY".to_string(),
                    path: "$.supi".to_string(),
                },
                IeDescriptor {
                    location: "BODY".to_string(),
                    path: "$.pei".to_string(),
                },
            ],
        });
        self.profiles.push(DataTypeProfile {
            id: "nausf-auth-profile".to_string(),
            service_name: "nausf-auth".to_string(),
            encrypt_ies: vec![
                IeDescriptor {
                    location: "BODY".to_string(),
                    path: "$.supiOrSuci".to_string(),
                },
                IeDescriptor {
                    location: "BODY".to_string(),
                    path: "$.authenticationVector".to_string(),
                },
            ],
        });
    }

    /// Find applicable profile for a given service name
    pub fn find_profile(&self, service_name: &str) -> Option<&DataTypeProfile> {
        self.profiles
            .iter()
            .find(|p| p.service_name == service_name)
    }
}

// ============================================================================
// TS 29.573 sec 6.3 reformatted-message structures
// ============================================================================

/// metaData of the DataToIntegrityProtectBlock (TS 29.573 table 6.3.2-1)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N32fMetaData {
    /// N32-f context ID allocated by the *receiving* SEPP
    pub n32f_context_id: String,
    /// Unique message ID (for n32f-error correlation)
    pub message_id: String,
    /// Identity of the first-hop IPX (empty when none)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub authorized_ipx_id: String,
}

/// Request line of the original SBI request
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct N32fRequestLine {
    pub method: String,
    pub url: String,
    pub protocol: String,
}

/// HTTP header carried in the clear (integrity-protected) block
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct N32fHeader {
    pub name: String,
    pub value: String,
}

/// One payload element: either a cleartext JSON value or a reference into
/// the encrypted `dataToEncrypt` array (`{"encBlockIndex": i}`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N32fPayloadElement {
    pub ie_path: String,
    pub ie_value_location: String,
    pub value: serde_json::Value,
}

/// DataToIntegrityProtectBlock: integrity-protected (JWE AAD) but cleartext
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataToIntegrityProtectBlock {
    pub meta_data: N32fMetaData,
    pub request_line: N32fRequestLine,
    #[serde(default)]
    pub headers: Vec<N32fHeader>,
    #[serde(default)]
    pub payload: Vec<N32fPayloadElement>,
}

/// DataToIntegrityProtectAndCipherBlock: the JWE plaintext
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataToIntegrityProtectAndCipherBlock {
    pub data_to_encrypt: Vec<serde_json::Value>,
}

/// Payload of a modificationsBlock JWS entry (TS 29.573 sec 6.3.4)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModificationsBlockPayload {
    /// FQDN of the entity that created this entry
    pub identity: String,
    /// JSON-Patch (RFC 6902) operations against the clear payload
    #[serde(default)]
    pub operations: Vec<serde_json::Value>,
    /// JWE tag (first entry) or previous entry's JWS signature (chain link)
    pub tag: String,
}

/// The protected N32-f message (N32fReformattedReqMsg shape)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N32fReformattedMessage {
    /// FlatJweJson: AAD = DataToIntegrityProtectBlock,
    /// plaintext = DataToIntegrityProtectAndCipherBlock
    pub reformatted_data: FlatJwe,
    /// FlatJwsJson chain (first entry by the sending SEPP)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modifications_block: Vec<FlatJws>,
}

// ============================================================================
// n32f-error reporting (TS 29.573 sec 6.1.5.4, N32fErrorInfo)
// ============================================================================

/// N32-f error types (TS 29.573 table 6.1.5.4.x)
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum N32fErrorType {
    #[serde(rename = "INTEGRITY_CHECK_FAILED")]
    IntegrityCheckFailed,
    #[serde(rename = "INTEGRITY_CHECK_ON_MODIFICATIONS_FAILED")]
    IntegrityCheckOnModificationsFailed,
    #[serde(rename = "MODIFICATIONS_INSTRUCTIONS_FAILED")]
    ModificationsInstructionsFailed,
    #[serde(rename = "DECIPHERING_FAILED")]
    DecipheringFailed,
    #[serde(rename = "MESSAGE_RECONSTRUCTION_FAILED")]
    MessageReconstructionFailed,
    #[serde(rename = "UNAVAILABLE_PRINS_CONTEXT")]
    UnavailablePrinsContext,
    #[serde(rename = "POLICY_MISMATCH")]
    PolicyMismatch,
}

/// N32fErrorInfo body POSTed to {apiRoot}/n32c-handshake/v1/n32f-error
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N32fErrorInfo {
    /// messageId of the failed N32-f message
    pub n32f_message_id: String,
    /// What failed
    pub n32f_error_type: N32fErrorType,
    /// FQDNs of failed modification entries (when applicable)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_modification_list: Vec<String>,
    /// Additional diagnostics
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub error_details_list: Vec<String>,
}

/// Error raised while unprotecting an N32-f message; carries everything
/// needed to produce the spec-shaped n32f-error report.
#[derive(Debug, Clone)]
pub struct N32fUnprotectError {
    pub error_type: N32fErrorType,
    pub message_id: Option<String>,
    pub detail: String,
    pub failed_modifications: Vec<String>,
}

impl N32fUnprotectError {
    fn new(error_type: N32fErrorType, message_id: Option<String>, detail: impl Into<String>) -> Self {
        Self {
            error_type,
            message_id,
            detail: detail.into(),
            failed_modifications: Vec::new(),
        }
    }

    /// Convert into the on-the-wire N32fErrorInfo
    pub fn to_error_info(&self) -> N32fErrorInfo {
        N32fErrorInfo {
            n32f_message_id: self.message_id.clone().unwrap_or_else(|| "unknown".into()),
            n32f_error_type: self.error_type,
            failed_modification_list: self.failed_modifications.clone(),
            error_details_list: vec![self.detail.clone()],
        }
    }
}

impl std::fmt::Display for N32fUnprotectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.error_type, self.detail)
    }
}

// ============================================================================
// Protect (sending SEPP)
// ============================================================================

/// Apply PRINS protection to an outgoing SBI request, producing the
/// N32fReformattedMessage per TS 29.573 sec 6.3.
pub fn protect_message(
    ctx: &PrinsContext,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<N32fReformattedMessage, JoseError> {
    let service_name = extract_service_name(url);
    let profile = ctx.find_profile(&service_name);

    let mut cipher_block = DataToIntegrityProtectAndCipherBlock::default();
    let mut payload_elements: Vec<N32fPayloadElement> = Vec::new();

    if let Some(body_bytes) = body {
        let parsed: Option<serde_json::Value> = serde_json::from_slice(body_bytes).ok();
        match parsed {
            Some(mut json) => {
                // Move profile-designated IEs into the cipher block,
                // replacing them with encBlockIndex references.
                if let (Some(profile), Some(obj)) = (profile, json.as_object_mut()) {
                    for ie in &profile.encrypt_ies {
                        if ie.location != "BODY" {
                            continue;
                        }
                        let Some(field) = ie.path.strip_prefix("$.") else {
                            continue;
                        };
                        if let Some(original) = obj.remove(field) {
                            let idx = cipher_block.data_to_encrypt.len();
                            cipher_block.data_to_encrypt.push(original);
                            payload_elements.push(N32fPayloadElement {
                                ie_path: ie.path.clone(),
                                ie_value_location: "BODY".to_string(),
                                value: serde_json::json!({ "encBlockIndex": idx }),
                            });
                        }
                    }
                }
                // The remaining (cleartext) body
                payload_elements.push(N32fPayloadElement {
                    ie_path: "$".to_string(),
                    ie_value_location: "BODY".to_string(),
                    value: json,
                });
            }
            None => {
                // Non-JSON body: carry opaque, base64url-encoded
                payload_elements.push(N32fPayloadElement {
                    ie_path: "$".to_string(),
                    ie_value_location: "BODY_RAW".to_string(),
                    value: serde_json::Value::String(b64url_encode(body_bytes)),
                });
            }
        }
    }

    let integrity_block = DataToIntegrityProtectBlock {
        meta_data: N32fMetaData {
            // The receiver looks the context up by the ID *it* allocated
            n32f_context_id: ctx.peer_context_id.clone(),
            message_id: generate_message_id(),
            authorized_ipx_id: String::new(),
        },
        request_line: N32fRequestLine {
            method: method.to_string(),
            url: url.to_string(),
            protocol: "HTTP/2".to_string(),
        },
        headers: headers
            .iter()
            .map(|(name, value)| N32fHeader {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
        payload: payload_elements,
    };

    let aad_bytes =
        serde_json::to_vec(&integrity_block).map_err(|e| JoseError::Format(e.to_string()))?;
    let plaintext =
        serde_json::to_vec(&cipher_block).map_err(|e| JoseError::Format(e.to_string()))?;

    let jwe = jose::jwe_encrypt(
        &ctx.session_key,
        &plaintext,
        Some(&aad_bytes),
        Some(&ctx.kid),
    )?;

    // First modificationsBlock entry: signed by the sending SEPP over the
    // JWE tag (binds the chain to this exact protected message).
    let mods_payload = ModificationsBlockPayload {
        identity: ctx.local_fqdn.clone(),
        operations: Vec::new(),
        tag: jwe.tag.clone(),
    };
    let mods_bytes =
        serde_json::to_vec(&mods_payload).map_err(|e| JoseError::Format(e.to_string()))?;
    let jws = jose::jws_sign(&ctx.session_key, &mods_bytes, Some(&ctx.kid))?;

    log::info!(
        "PRINS protect: {} {} ({} encrypted IEs, msg_id in AAD)",
        method,
        url,
        cipher_block.data_to_encrypt.len()
    );

    Ok(N32fReformattedMessage {
        reformatted_data: jwe,
        modifications_block: vec![jws],
    })
}

// ============================================================================
// Unprotect (receiving SEPP)
// ============================================================================

/// Reconstructed SBI request after successful unprotection.
#[derive(Debug, Clone)]
pub struct ReconstructedRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub message_id: String,
}

/// Verify and remove PRINS protection from a received N32fReformattedMessage.
///
/// Verification order per TS 29.573: parse AAD (cleartext copy is needed
/// for the error report's messageId), verify the JWS modification chain,
/// AEAD-decrypt (which authenticates the AAD), apply allowed JSON-Patch
/// operations, then reassemble the original request.
pub fn unprotect_message(
    ctx: &PrinsContext,
    msg: &N32fReformattedMessage,
) -> Result<ReconstructedRequest, N32fUnprotectError> {
    // --- Parse the (not yet authenticated) AAD for metaData/messageId ---
    let aad_b64 = msg.reformatted_data.aad.as_ref().ok_or_else(|| {
        N32fUnprotectError::new(
            N32fErrorType::MessageReconstructionFailed,
            None,
            "missing JWE aad (DataToIntegrityProtectBlock)",
        )
    })?;
    let aad_bytes = b64url_decode(aad_b64).map_err(|e| {
        N32fUnprotectError::new(N32fErrorType::MessageReconstructionFailed, None, e.to_string())
    })?;
    let integrity_block: DataToIntegrityProtectBlock = serde_json::from_slice(&aad_bytes)
        .map_err(|e| {
            N32fUnprotectError::new(
                N32fErrorType::MessageReconstructionFailed,
                None,
                format!("bad DataToIntegrityProtectBlock: {e}"),
            )
        })?;
    let message_id = integrity_block.meta_data.message_id.clone();

    // The peer must address us by the context ID we allocated
    if integrity_block.meta_data.n32f_context_id != ctx.local_context_id {
        return Err(N32fUnprotectError::new(
            N32fErrorType::UnavailablePrinsContext,
            Some(message_id),
            format!(
                "unknown n32fContextId [{}]",
                integrity_block.meta_data.n32f_context_id
            ),
        ));
    }

    // --- Verify the JWS modification chain ---
    if msg.modifications_block.is_empty() {
        return Err(N32fUnprotectError::new(
            N32fErrorType::IntegrityCheckOnModificationsFailed,
            Some(message_id),
            "empty modificationsBlock",
        ));
    }
    let mut operations: Vec<serde_json::Value> = Vec::new();
    let mut expected_tag = msg.reformatted_data.tag.clone();
    for (i, jws) in msg.modifications_block.iter().enumerate() {
        let payload_bytes = jose::jws_verify(&ctx.session_key, jws).map_err(|e| {
            let mut err = N32fUnprotectError::new(
                N32fErrorType::IntegrityCheckOnModificationsFailed,
                Some(message_id.clone()),
                format!("modificationsBlock[{i}]: {e}"),
            );
            err.failed_modifications.push(format!("entry-{i}"));
            err
        })?;
        let payload: ModificationsBlockPayload = serde_json::from_slice(&payload_bytes)
            .map_err(|e| {
                N32fUnprotectError::new(
                    N32fErrorType::IntegrityCheckOnModificationsFailed,
                    Some(message_id.clone()),
                    format!("modificationsBlock[{i}] payload: {e}"),
                )
            })?;
        // Chain check: entry must reference the JWE tag (first) or the
        // previous entry's signature.
        if payload.tag != expected_tag {
            let mut err = N32fUnprotectError::new(
                N32fErrorType::IntegrityCheckOnModificationsFailed,
                Some(message_id.clone()),
                format!("modificationsBlock[{i}] chain tag mismatch"),
            );
            err.failed_modifications.push(payload.identity.clone());
            return Err(err);
        }
        // Policy check on requested modifications
        for op in &payload.operations {
            let path = op.get("path").and_then(|p| p.as_str()).unwrap_or("");
            if !ctx
                .modification_policy
                .allowed_paths
                .iter()
                .any(|allowed| allowed == path)
            {
                let mut err = N32fUnprotectError::new(
                    N32fErrorType::PolicyMismatch,
                    Some(message_id.clone()),
                    format!("modification of [{path}] not permitted by policy"),
                );
                err.failed_modifications.push(payload.identity.clone());
                return Err(err);
            }
        }
        operations.extend(payload.operations.iter().cloned());
        expected_tag = jws.signature.clone();
    }

    // --- AEAD decrypt; authenticates the AAD (integrity block) ---
    let plaintext = jose::jwe_decrypt(&ctx.session_key, &msg.reformatted_data).map_err(|e| {
        let error_type = match e {
            JoseError::Tampered => N32fErrorType::IntegrityCheckFailed,
            _ => N32fErrorType::DecipheringFailed,
        };
        N32fUnprotectError::new(error_type, Some(message_id.clone()), e.to_string())
    })?;
    let cipher_block: DataToIntegrityProtectAndCipherBlock = serde_json::from_slice(&plaintext)
        .map_err(|e| {
            N32fUnprotectError::new(
                N32fErrorType::DecipheringFailed,
                Some(message_id.clone()),
                format!("bad DataToIntegrityProtectAndCipherBlock: {e}"),
            )
        })?;

    // --- Reassemble the original request ---
    let mut body_json: Option<serde_json::Value> = None;
    let mut body_raw: Option<Vec<u8>> = None;
    let mut encrypted_fields: Vec<(String, serde_json::Value)> = Vec::new();

    for element in &integrity_block.payload {
        match element.ie_value_location.as_str() {
            "BODY" => {
                if element.ie_path == "$" {
                    body_json = Some(element.value.clone());
                } else if let Some(field) = element.ie_path.strip_prefix("$.") {
                    let idx = element
                        .value
                        .get("encBlockIndex")
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| {
                            N32fUnprotectError::new(
                                N32fErrorType::MessageReconstructionFailed,
                                Some(message_id.clone()),
                                format!("payload element [{}] missing encBlockIndex", element.ie_path),
                            )
                        })? as usize;
                    let value = cipher_block.data_to_encrypt.get(idx).ok_or_else(|| {
                        N32fUnprotectError::new(
                            N32fErrorType::MessageReconstructionFailed,
                            Some(message_id.clone()),
                            format!("encBlockIndex {idx} out of range"),
                        )
                    })?;
                    encrypted_fields.push((field.to_string(), value.clone()));
                }
            }
            "BODY_RAW" => {
                let encoded = element.value.as_str().unwrap_or("");
                body_raw = Some(b64url_decode(encoded).map_err(|e| {
                    N32fUnprotectError::new(
                        N32fErrorType::MessageReconstructionFailed,
                        Some(message_id.clone()),
                        e.to_string(),
                    )
                })?);
            }
            _ => {}
        }
    }

    // Restore encrypted IEs into the body
    if !encrypted_fields.is_empty() {
        let json = body_json.get_or_insert_with(|| serde_json::json!({}));
        if let Some(obj) = json.as_object_mut() {
            for (field, value) in encrypted_fields {
                obj.insert(field, value);
            }
        }
    }

    // Apply policy-approved JSON-Patch replace operations from the chain
    if !operations.is_empty() {
        if let Some(ref mut json) = body_json {
            apply_json_patch_replaces(json, &operations).map_err(|detail| {
                N32fUnprotectError::new(
                    N32fErrorType::ModificationsInstructionsFailed,
                    Some(message_id.clone()),
                    detail,
                )
            })?;
        }
    }

    let body = match (body_json, body_raw) {
        (Some(json), _) => Some(serde_json::to_vec(&json).map_err(|e| {
            N32fUnprotectError::new(
                N32fErrorType::MessageReconstructionFailed,
                Some(message_id.clone()),
                e.to_string(),
            )
        })?),
        (None, Some(raw)) => Some(raw),
        (None, None) => None,
    };

    let headers: HashMap<String, String> = integrity_block
        .headers
        .iter()
        .map(|h| (h.name.clone(), h.value.clone()))
        .collect();

    log::info!(
        "PRINS unprotect OK: {} {} (msg_id={})",
        integrity_block.request_line.method,
        integrity_block.request_line.url,
        message_id
    );

    Ok(ReconstructedRequest {
        method: integrity_block.request_line.method.clone(),
        url: integrity_block.request_line.url.clone(),
        headers,
        body,
        message_id,
    })
}

/// Apply RFC 6902 "replace" operations (the only kind PRINS intermediaries
/// use against the cleartext body). Paths use JSON-Pointer (e.g. "/amount").
fn apply_json_patch_replaces(
    json: &mut serde_json::Value,
    operations: &[serde_json::Value],
) -> Result<(), String> {
    for op in operations {
        let kind = op.get("op").and_then(|v| v.as_str()).unwrap_or("");
        if kind != "replace" {
            return Err(format!("unsupported JSON-Patch op [{kind}]"));
        }
        let path = op
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or("missing path")?;
        let value = op.get("value").cloned().ok_or("missing value")?;
        let target = json
            .pointer_mut(path)
            .ok_or_else(|| format!("path [{path}] not found"))?;
        *target = value;
    }
    Ok(())
}

// ============================================================================
// Helpers
// ============================================================================

/// Extract service name from URL (e.g., "/nudm-sdm/v1/..." -> "nudm-sdm")
pub fn extract_service_name(url: &str) -> String {
    let path = url.split('?').next().unwrap_or(url);
    path.trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Generate a unique message ID for n32f-error correlation
fn generate_message_id() -> String {
    use rand::Rng as _;
    let r: u64 = rand::rng().random();
    format!("{r:016x}")
}

/// Generate an N32-f context ID
pub fn generate_n32f_context_id() -> String {
    use rand::Rng as _;
    let r: u64 = rand::rng().random();
    format!("{r:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx() -> PrinsContext {
        PrinsContext::new(
            "ctx-local-1111",
            "ctx-peer-2222",
            [0x42u8; 32],
            "kid-test",
            "sepp.home.example.com",
        )
    }

    /// The receiving side of the pair above (keys equal, context IDs mirrored)
    fn receiver_ctx() -> PrinsContext {
        PrinsContext::new(
            "ctx-peer-2222",
            "ctx-local-1111",
            [0x42u8; 32],
            "kid-test",
            "sepp.visited.example.com",
        )
    }

    fn sample_body() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "supi": "imsi-001010000000001",
            "pei": "imeisv-1234567890123456",
            "nssai": {"sst": 1}
        }))
        .unwrap()
    }

    #[test]
    fn protect_unprotect_roundtrip() {
        let sender = test_ctx();
        let receiver = receiver_ctx();
        let headers = vec![("content-type".to_string(), "application/json".to_string())];

        let msg = protect_message(
            &sender,
            "POST",
            "/nudm-sdm/v1/supi",
            &headers,
            Some(&sample_body()),
        )
        .unwrap();

        // SUPI/PEI must not appear in the cleartext AAD
        let aad = b64url_decode(msg.reformatted_data.aad.as_ref().unwrap()).unwrap();
        let aad_str = String::from_utf8(aad).unwrap();
        assert!(!aad_str.contains("imsi-001010000000001"));
        assert!(!aad_str.contains("imeisv-1234567890123456"));
        // Non-sensitive IE stays cleartext
        assert!(aad_str.contains("nssai"));

        let rec = unprotect_message(&receiver, &msg).unwrap();
        assert_eq!(rec.method, "POST");
        assert_eq!(rec.url, "/nudm-sdm/v1/supi");
        let body: serde_json::Value = serde_json::from_slice(&rec.body.unwrap()).unwrap();
        assert_eq!(body["supi"], "imsi-001010000000001");
        assert_eq!(body["pei"], "imeisv-1234567890123456");
        assert_eq!(body["nssai"]["sst"], 1);
        assert_eq!(rec.headers.get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn tampered_aad_detected_as_integrity_failure() {
        let sender = test_ctx();
        let receiver = receiver_ctx();
        let mut msg = protect_message(&sender, "POST", "/nudm-sdm/v1/supi", &[], Some(&sample_body()))
            .unwrap();

        // Tamper with a cleartext field inside the integrity block
        let aad = b64url_decode(msg.reformatted_data.aad.as_ref().unwrap()).unwrap();
        let mut block: DataToIntegrityProtectBlock = serde_json::from_slice(&aad).unwrap();
        block.request_line.url = "/nudm-sdm/v1/EVIL".to_string();
        msg.reformatted_data.aad = Some(b64url_encode(&serde_json::to_vec(&block).unwrap()));

        let err = unprotect_message(&receiver, &msg).unwrap_err();
        assert_eq!(err.error_type, N32fErrorType::IntegrityCheckFailed);
    }

    #[test]
    fn tampered_ciphertext_detected() {
        let sender = test_ctx();
        let receiver = receiver_ctx();
        let mut msg = protect_message(&sender, "POST", "/nudm-sdm/v1/supi", &[], Some(&sample_body()))
            .unwrap();
        let mut ct = b64url_decode(&msg.reformatted_data.ciphertext).unwrap();
        ct[0] ^= 0xff;
        msg.reformatted_data.ciphertext = b64url_encode(&ct);

        let err = unprotect_message(&receiver, &msg).unwrap_err();
        assert_eq!(err.error_type, N32fErrorType::IntegrityCheckFailed);
    }

    #[test]
    fn tampered_modifications_chain_detected() {
        let sender = test_ctx();
        let receiver = receiver_ctx();
        let mut msg = protect_message(&sender, "POST", "/nudm-sdm/v1/supi", &[], Some(&sample_body()))
            .unwrap();

        // Forge the modification entry payload without a valid signature
        msg.modifications_block[0].payload = b64url_encode(
            serde_json::to_vec(&ModificationsBlockPayload {
                identity: "evil-ipx".to_string(),
                operations: vec![serde_json::json!({"op":"replace","path":"/nssai/sst","value":9})],
                tag: msg.reformatted_data.tag.clone(),
            })
            .unwrap()
            .as_slice(),
        );

        let err = unprotect_message(&receiver, &msg).unwrap_err();
        assert_eq!(
            err.error_type,
            N32fErrorType::IntegrityCheckOnModificationsFailed
        );
        assert!(!err.failed_modifications.is_empty());
    }

    #[test]
    fn modification_chain_with_valid_allowed_patch_applies() {
        let sender = test_ctx();
        let mut receiver = receiver_ctx();
        receiver.modification_policy.allowed_paths = vec!["/nssai/sst".to_string()];

        let mut msg = protect_message(&sender, "POST", "/nudm-sdm/v1/supi", &[], Some(&sample_body()))
            .unwrap();

        // A (key-holding) intermediary appends a chained, signed patch entry
        let prev_sig = msg.modifications_block[0].signature.clone();
        let patch_payload = ModificationsBlockPayload {
            identity: "ipx1.example.com".to_string(),
            operations: vec![serde_json::json!({"op":"replace","path":"/nssai/sst","value":7})],
            tag: prev_sig,
        };
        let jws = jose::jws_sign(
            &sender.session_key,
            &serde_json::to_vec(&patch_payload).unwrap(),
            Some("kid-test"),
        )
        .unwrap();
        msg.modifications_block.push(jws);

        let rec = unprotect_message(&receiver, &msg).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&rec.body.unwrap()).unwrap();
        assert_eq!(body["nssai"]["sst"], 7);
        // Encrypted IEs still restored
        assert_eq!(body["supi"], "imsi-001010000000001");
    }

    #[test]
    fn modification_violating_policy_rejected() {
        let sender = test_ctx();
        let receiver = receiver_ctx(); // empty policy: nothing modifiable

        let mut msg = protect_message(&sender, "POST", "/nudm-sdm/v1/supi", &[], Some(&sample_body()))
            .unwrap();
        let prev_sig = msg.modifications_block[0].signature.clone();
        let patch_payload = ModificationsBlockPayload {
            identity: "ipx1.example.com".to_string(),
            operations: vec![serde_json::json!({"op":"replace","path":"/nssai/sst","value":7})],
            tag: prev_sig,
        };
        let jws = jose::jws_sign(
            &sender.session_key,
            &serde_json::to_vec(&patch_payload).unwrap(),
            None,
        )
        .unwrap();
        msg.modifications_block.push(jws);

        let err = unprotect_message(&receiver, &msg).unwrap_err();
        assert_eq!(err.error_type, N32fErrorType::PolicyMismatch);
    }

    #[test]
    fn wrong_session_key_detected() {
        let sender = test_ctx();
        let mut receiver = receiver_ctx();
        receiver.session_key = [0x43u8; 32];

        let msg = protect_message(&sender, "POST", "/nudm-sdm/v1/supi", &[], Some(&sample_body()))
            .unwrap();
        let err = unprotect_message(&receiver, &msg).unwrap_err();
        // JWS chain is checked first and fails under the wrong key
        assert_eq!(
            err.error_type,
            N32fErrorType::IntegrityCheckOnModificationsFailed
        );
    }

    #[test]
    fn unknown_context_id_rejected() {
        let sender = test_ctx();
        let mut receiver = receiver_ctx();
        receiver.local_context_id = "ctx-other-9999".to_string();

        let msg = protect_message(&sender, "POST", "/nudm-sdm/v1/supi", &[], Some(&sample_body()))
            .unwrap();
        let err = unprotect_message(&receiver, &msg).unwrap_err();
        assert_eq!(err.error_type, N32fErrorType::UnavailablePrinsContext);
    }

    #[test]
    fn non_json_body_roundtrip() {
        let sender = test_ctx();
        let receiver = receiver_ctx();
        let raw = b"\x00\x01binary payload\xff";
        let msg =
            protect_message(&sender, "PUT", "/nsmf-pdusession/v1/sm", &[], Some(raw)).unwrap();
        let rec = unprotect_message(&receiver, &msg).unwrap();
        assert_eq!(rec.body.unwrap(), raw);
    }

    #[test]
    fn error_info_serialization_is_spec_shaped() {
        let err = N32fUnprotectError {
            error_type: N32fErrorType::DecipheringFailed,
            message_id: Some("abc123".to_string()),
            detail: "tag mismatch".to_string(),
            failed_modifications: vec![],
        };
        let info = err.to_error_info();
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["n32fMessageId"], "abc123");
        assert_eq!(json["n32fErrorType"], "DECIPHERING_FAILED");
    }

    #[test]
    fn test_extract_service_name() {
        assert_eq!(extract_service_name("/nudm-sdm/v1/supi"), "nudm-sdm");
        assert_eq!(
            extract_service_name("/nausf-auth/v1/ue-authentications"),
            "nausf-auth"
        );
        assert_eq!(extract_service_name(""), "");
    }
}
