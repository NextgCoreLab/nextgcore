//! PRINS - Protection of Information on N32 interface
//!
//! Implements JSON patch-based protection of sensitive IEs per TS 29.573 sec 5.3.3.
//! PRINS allows selective protection of information elements in the SBI message body
//! while allowing IPX intermediaries to modify non-protected fields.
//!
//! Protected IEs include: SUPI, PEI, GPSI, and other subscriber identifiers.

use std::collections::HashMap;

use crate::n32c_build::{N32fMessage, N32fModification};

/// Data-type profile defining which IEs to protect for a given API.
#[derive(Debug, Clone)]
pub struct DataTypeProfile {
    /// Profile identifier
    pub id: String,
    /// API service name this profile applies to
    pub service_name: String,
    /// IEs that must be encrypted
    pub encrypt_ies: Vec<IeDescriptor>,
    /// IEs that must be integrity-protected (signed)
    pub sign_ies: Vec<IeDescriptor>,
}

/// Descriptor for an information element to protect
#[derive(Debug, Clone)]
pub struct IeDescriptor {
    /// Location: "body", "header", or "queryParam"
    pub location: String,
    /// JSON path expression (e.g., "$.supi", "$.pei")
    pub path: String,
}

/// PRINS context for a peer SEPP connection
#[derive(Debug, Clone)]
pub struct PrinsContext {
    /// N32f context ID (unique per PRINS session)
    pub context_id: String,
    /// Data-type profiles agreed during N32c handshake
    pub profiles: Vec<DataTypeProfile>,
    /// Shared secret for IE encryption (derived during handshake)
    pub shared_key: Vec<u8>,
}

impl PrinsContext {
    /// Create a new PRINS context with a generated context ID
    pub fn new() -> Self {
        let context_id = format!("n32f-ctx-{:016x}", random_u64());
        Self {
            context_id,
            profiles: Vec::new(),
            shared_key: Vec::new(),
        }
    }

    /// Create with specific context ID (for receiving side)
    pub fn with_id(context_id: impl Into<String>) -> Self {
        Self {
            context_id: context_id.into(),
            profiles: Vec::new(),
            shared_key: Vec::new(),
        }
    }

    /// Add default data-type profiles for common 5G APIs
    pub fn add_default_profiles(&mut self) {
        // Profile for NUDM (subscriber data management)
        self.profiles.push(DataTypeProfile {
            id: "nudm-sdm-profile".to_string(),
            service_name: "nudm-sdm".to_string(),
            encrypt_ies: vec![
                IeDescriptor { location: "body".to_string(), path: "$.supi".to_string() },
                IeDescriptor { location: "body".to_string(), path: "$.pei".to_string() },
                IeDescriptor { location: "body".to_string(), path: "$.gpsi".to_string() },
            ],
            sign_ies: vec![
                IeDescriptor { location: "body".to_string(), path: "$.nssai".to_string() },
            ],
        });

        // Profile for NAUSF (authentication)
        self.profiles.push(DataTypeProfile {
            id: "nausf-auth-profile".to_string(),
            service_name: "nausf-auth".to_string(),
            encrypt_ies: vec![
                IeDescriptor { location: "body".to_string(), path: "$.supiOrSuci".to_string() },
                IeDescriptor { location: "body".to_string(), path: "$.authenticationVector".to_string() },
            ],
            sign_ies: vec![],
        });
    }

    /// Find applicable profile for a given service name
    pub fn find_profile(&self, service_name: &str) -> Option<&DataTypeProfile> {
        self.profiles.iter().find(|p| p.service_name == service_name)
    }
}

impl Default for PrinsContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Apply PRINS protection to an N32f message.
///
/// Per TS 29.573 sec 6.3.2: For PRINS mode, sensitive IEs are replaced
/// with encrypted/signed values, and the modifications block describes
/// what was protected.
pub fn apply_prins_protection(
    message: &mut N32fMessage,
    prins_ctx: &PrinsContext,
) -> Vec<N32fModification> {
    let mut modifications = Vec::new();

    // Extract service name from the request URL
    let service_name = extract_service_name(&message.request_line.url);

    // Find applicable data-type profile
    let profile = match prins_ctx.find_profile(&service_name) {
        Some(p) => p,
        None => {
            log::debug!("No PRINS profile for service: {service_name}");
            return modifications;
        }
    };

    // Process body payload for IEs to encrypt
    if let Some(ref payload) = message.payload {
        if let Ok(decoded) = base64url_decode(payload) {
            if let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&decoded) {
                let mut modified = false;

                for ie in &profile.encrypt_ies {
                    if ie.location == "body" {
                        if let Some(field_name) = ie.path.strip_prefix("$.") {
                            if let Some(obj) = json.as_object_mut() {
                                if let Some(original_value) = obj.remove(field_name) {
                                    // Encrypt the IE value (simplified: XOR-based placeholder)
                                    let encrypted = encrypt_ie(
                                        &serde_json::to_string(&original_value).unwrap_or_default(),
                                        &prins_ctx.shared_key,
                                    );
                                    obj.insert(
                                        field_name.to_string(),
                                        serde_json::Value::String(encrypted.clone()),
                                    );
                                    modifications.push(N32fModification {
                                        ie_location: ie.location.clone(),
                                        ie_path: ie.path.clone(),
                                        ie_value: Some(encrypted),
                                        ie_action: "encrypt".to_string(),
                                    });
                                    modified = true;
                                }
                            }
                        }
                    }
                }

                for ie in &profile.sign_ies {
                    if ie.location == "body" {
                        if let Some(field_name) = ie.path.strip_prefix("$.") {
                            if let Some(obj) = json.as_object() {
                                if let Some(value) = obj.get(field_name) {
                                    let signature = sign_ie(
                                        &serde_json::to_string(value).unwrap_or_default(),
                                        &prins_ctx.shared_key,
                                    );
                                    modifications.push(N32fModification {
                                        ie_location: ie.location.clone(),
                                        ie_path: ie.path.clone(),
                                        ie_value: Some(signature),
                                        ie_action: "sign".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }

                if modified {
                    if let Ok(new_payload) = serde_json::to_vec(&json) {
                        message.payload = Some(base64url_encode(&new_payload));
                    }
                }
            }
        }
    }

    // Store modifications in the message
    message.modifications_block = modifications.clone();

    log::info!(
        "PRINS protection applied: {} modifications for {}",
        modifications.len(),
        service_name
    );

    modifications
}

/// Remove PRINS protection from an N32f message (receiving side).
///
/// Reverses the encryption applied by the sending SEPP using the
/// shared key established during N32c handshake.
pub fn remove_prins_protection(
    message: &mut N32fMessage,
    prins_ctx: &PrinsContext,
) -> Result<(), String> {
    if message.modifications_block.is_empty() {
        return Ok(());
    }

    let payload = message.payload.as_ref().ok_or("No payload to unprotect")?;
    let decoded = base64url_decode(payload).map_err(|e| format!("Base64 decode failed: {e}"))?;
    let mut json: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|e| format!("JSON parse failed: {e}"))?;

    for modification in &message.modifications_block {
        if modification.ie_action == "encrypt" {
            if let Some(field_name) = modification.ie_path.strip_prefix("$.") {
                if modification.ie_location == "body" {
                    if let Some(obj) = json.as_object_mut() {
                        if let Some(encrypted_value) = obj.get(field_name).and_then(|v| v.as_str()) {
                            let decrypted = decrypt_ie(encrypted_value, &prins_ctx.shared_key);
                            if let Ok(original_value) = serde_json::from_str::<serde_json::Value>(&decrypted) {
                                obj.insert(field_name.to_string(), original_value);
                            }
                        }
                    }
                }
            }
        }
    }

    if let Ok(new_payload) = serde_json::to_vec(&json) {
        message.payload = Some(base64url_encode(&new_payload));
    }

    log::info!(
        "PRINS protection removed: {} modifications processed",
        message.modifications_block.len()
    );

    Ok(())
}

/// Process an incoming N32f request (receiving SEPP side).
///
/// Extracts the original SBI request from the N32f message envelope,
/// removing PRINS protection if applicable.
pub fn process_n32f_request(
    n32f_json: &[u8],
    prins_ctx: Option<&PrinsContext>,
) -> Result<(String, String, HashMap<String, String>, Option<Vec<u8>>), String> {
    let mut message = crate::n32c_build::parse_n32f_message(n32f_json)?;

    // If PRINS context is available and there are modifications, unprotect
    if let Some(ctx) = prins_ctx {
        if !message.modifications_block.is_empty() {
            remove_prins_protection(&mut message, ctx)?;
        }
    }

    // Extract the original request components
    let method = message.request_line.method;
    let url = message.request_line.url;

    let mut headers = HashMap::new();
    for header in &message.header {
        headers.insert(header.name.clone(), header.value.clone());
    }

    let body = message.payload
        .and_then(|p| base64url_decode(&p).ok());

    Ok((method, url, headers, body))
}

// ============================================================================
// Crypto helpers (simplified for initial implementation)
// ============================================================================

/// Encrypt an IE value (simplified XOR-based encryption).
/// In production, this would use AES-GCM or similar AEAD.
fn encrypt_ie(plaintext: &str, key: &[u8]) -> String {
    let mut result = Vec::with_capacity(plaintext.len());
    let key_bytes = if key.is_empty() { &[0x42u8] } else { key };
    for (i, b) in plaintext.bytes().enumerate() {
        result.push(b ^ key_bytes[i % key_bytes.len()]);
    }
    base64url_encode(&result)
}

/// Decrypt an IE value
fn decrypt_ie(ciphertext: &str, key: &[u8]) -> String {
    if let Ok(decoded) = base64url_decode(ciphertext) {
        let key_bytes = if key.is_empty() { &[0x42u8] } else { key };
        let mut result = Vec::with_capacity(decoded.len());
        for (i, b) in decoded.iter().enumerate() {
            result.push(b ^ key_bytes[i % key_bytes.len()]);
        }
        String::from_utf8(result).unwrap_or_default()
    } else {
        String::new()
    }
}

/// Sign an IE value (simplified HMAC placeholder).
/// In production, this would use HMAC-SHA256 or JWS.
fn sign_ie(value: &str, key: &[u8]) -> String {
    let key_bytes = if key.is_empty() { &[0x42u8] } else { key };
    let mut hash: u64 = 0;
    for (i, b) in value.bytes().enumerate() {
        hash = hash.wrapping_mul(31).wrapping_add((b ^ key_bytes[i % key_bytes.len()]) as u64);
    }
    format!("{hash:016x}")
}

/// Extract service name from URL (e.g., "/nudm-sdm/v1/..." -> "nudm-sdm")
fn extract_service_name(url: &str) -> String {
    let path = url.split('?').next().unwrap_or(url);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    parts.first().map(|s| s.to_string()).unwrap_or_default()
}

/// Simple base64url encode (no padding)
fn base64url_encode(data: &[u8]) -> String {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::new();
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

/// Base64url decode
fn base64url_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for c in input.chars() {
        let val = match c {
            'A'..='Z' => (c as u32) - ('A' as u32),
            'a'..='z' => (c as u32) - ('a' as u32) + 26,
            '0'..='9' => (c as u32) - ('0' as u32) + 52,
            '-' => 62,
            '_' => 63,
            '=' => continue,
            _ => return Err(format!("Invalid base64url character: {c}")),
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(result)
}

/// Simple random u64 for context ID generation
fn random_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    now.as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prins_context_creation() {
        let mut ctx = PrinsContext::new();
        assert!(ctx.context_id.starts_with("n32f-ctx-"));
        ctx.add_default_profiles();
        assert_eq!(ctx.profiles.len(), 2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = b"test-key-12345";
        let plaintext = "\"imsi-001010000000001\"";
        let encrypted = encrypt_ie(plaintext, key);
        let decrypted = decrypt_ie(&encrypted, key);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_base64url_roundtrip() {
        let data = b"Hello, PRINS!";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_extract_service_name() {
        assert_eq!(extract_service_name("/nudm-sdm/v1/supi"), "nudm-sdm");
        assert_eq!(extract_service_name("/nausf-auth/v1/ue-authentications"), "nausf-auth");
        assert_eq!(extract_service_name(""), "");
    }

    #[test]
    fn test_prins_protection_roundtrip() {
        use crate::n32c_build::*;

        let mut prins_ctx = PrinsContext::new();
        prins_ctx.shared_key = b"shared-secret-key".to_vec();
        prins_ctx.add_default_profiles();

        let body = serde_json::json!({
            "supi": "imsi-001010000000001",
            "pei": "imeisv-1234567890123456",
            "nssai": {"sst": 1}
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let mut message = build_n32f_prins_message(
            "POST",
            "/nudm-sdm/v1/supi",
            &headers,
            Some(&body_bytes),
            Vec::new(),
        );

        // Apply protection
        let mods = apply_prins_protection(&mut message, &prins_ctx);
        assert!(!mods.is_empty());

        // Verify SUPI was encrypted
        if let Some(ref payload) = message.payload {
            let decoded = base64url_decode(payload).unwrap();
            let json: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
            // SUPI should no longer be plaintext
            let supi_val = json.get("supi").unwrap().as_str().unwrap();
            assert_ne!(supi_val, "imsi-001010000000001");
        }

        // Remove protection
        let result = remove_prins_protection(&mut message, &prins_ctx);
        assert!(result.is_ok());

        // Verify SUPI is restored
        if let Some(ref payload) = message.payload {
            let decoded = base64url_decode(payload).unwrap();
            let json: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
            let supi_val = json.get("supi").unwrap();
            assert_eq!(supi_val, "imsi-001010000000001");
        }
    }

    #[test]
    fn test_process_n32f_request() {
        use crate::n32c_build::*;

        let body = b"{\"key\":\"value\"}";
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let message = build_n32f_tls_message("GET", "/nudm-sdm/v1/supi", &headers, Some(body));
        let json_bytes = serde_json::to_vec(&message).unwrap();

        let (method, url, hdrs, _body) = process_n32f_request(&json_bytes, None).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(url, "/nudm-sdm/v1/supi");
        assert_eq!(hdrs.get("content-type").unwrap(), "application/json");
    }
}
