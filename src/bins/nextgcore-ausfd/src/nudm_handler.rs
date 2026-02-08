//! NUDM UEAU Handlers
//!
//! Port of src/ausf/nudm-handler.c - NUDM UEAU response handlers

use crate::context::{ausf_self, AuthResult, AuthType};

/// Get the links member name based on auth type
#[allow(dead_code)]
fn links_member_name(auth_type: AuthType) -> &'static str {
    match auth_type {
        AuthType::FiveGAka | AuthType::EapAkaPrime => "5g-aka",
        AuthType::EapTls => "eap-session",
    }
}

/// Handle NUDM UEAU get response (security-information/generate-auth-data)
///
/// Port of ausf_nudm_ueau_handle_get()
pub fn ausf_nudm_ueau_handle_get(ausf_ue_id: u64, _stream_id: u64) -> bool {
    let ctx = ausf_self();
    let context = ctx.write().unwrap();

    let mut ausf_ue = match context.ue_find_by_id(ausf_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("AUSF UE not found [{ausf_ue_id}]");
            return false;
        }
    };

    log::debug!("[{}] Handle NUDM UEAU get response", ausf_ue.suci);

    // Note: In the C code, this extracts AuthenticationInfoResult from the response
    // and validates the authentication vector. The following values are extracted:
    // - AuthenticationInfoResult.auth_type
    // - AuthenticationInfoResult.supi
    // - AuthenticationVector.rand
    // - AuthenticationVector.xres_star
    // - AuthenticationVector.autn
    // - AuthenticationVector.kausf
    // For now, we'll simulate the processing

    // Validate auth type (only 5G_AKA supported)
    // if auth_type != AuthType::FiveGAka {
    //     log::error!("[{}] Not supported Auth Method", ausf_ue.suci);
    //     return false;
    // }

    // Validate AV type (only 5G_HE_AKA supported)
    // if av_type != AvType::FiveGHeAka {
    //     log::error!("[{}] Not supported Auth Method", ausf_ue.suci);
    //     return false;
    // }

    // Set SUPI from response
    // if let Some(supi) = authentication_info_result.supi {
    //     context.ue_set_supi(ausf_ue_id, &supi);
    // }

    // Set auth type
    ausf_ue.auth_type = AuthType::FiveGAka;

    // Calculate HXRES* from stored RAND and XRES*
    // (RAND, XRES*, AUTN, KAUSF are populated by process_authentication_vector)
    ausf_ue.calculate_hxres_star();

    // Update UE in context
    context.ue_update(&ausf_ue);

    // Note: Build and send UeAuthenticationCtx response
    // In C code, this builds the response with:
    // - auth_type
    // - 5g_auth_data (rand, autn, hxres_star)
    // - _links (href to 5g-aka-confirmation endpoint)
    // The HTTP 201 Created response is built and sent via the HTTP handler in main.rs

    log::debug!(
        "[{}] Sending UeAuthenticationCtx response",
        ausf_ue.suci
    );

    true
}

/// Handle NUDM UEAU auth removal indication response
///
/// Port of ausf_nudm_ueau_handle_auth_removal_ind()
pub fn ausf_nudm_ueau_handle_auth_removal_ind(ausf_ue_id: u64, _stream_id: u64) -> bool {
    let ctx = ausf_self();
    let context = ctx.read().unwrap();

    let ausf_ue = match context.ue_find_by_id(ausf_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("AUSF UE not found [{ausf_ue_id}]");
            return false;
        }
    };

    log::debug!(
        "[{}] Handle NUDM UEAU auth removal indication response",
        ausf_ue.suci
    );

    // Note: Send 204 No Content response
    // The HTTP 204 No Content response is built and sent via the HTTP handler in main.rs

    true
}

/// Handle NUDM UEAU result confirmation inform response
///
/// Port of ausf_nudm_ueau_handle_result_confirmation_inform()
pub fn ausf_nudm_ueau_handle_result_confirmation_inform(ausf_ue_id: u64, _stream_id: u64) -> bool {
    let ctx = ausf_self();
    let context = ctx.write().unwrap();

    let mut ausf_ue = match context.ue_find_by_id(ausf_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("AUSF UE not found [{ausf_ue_id}]");
            return false;
        }
    };

    log::debug!(
        "[{}] Handle NUDM UEAU result confirmation inform response",
        ausf_ue.suci
    );

    // Note: In the C code, this extracts AuthEvent from the response
    // and stores the auth event resource URI. The following values are extracted:
    // - AuthEvent.success
    // - http.location (resource URI)

    // Auth result is already set by nausf_handler during confirmation
    // (either AuthenticationSuccess or AuthenticationFailure based on HRES* vs HXRES*)
    // The UDM just confirms storage of the auth event.
    log::debug!(
        "[{}] Auth result from UDM confirmation: {:?}",
        ausf_ue.suci,
        ausf_ue.auth_result
    );

    // Calculate KSEAF
    ausf_ue.calculate_kseaf();

    // Update UE in context
    context.ue_update(&ausf_ue);

    // Build and send ConfirmationDataResponse
    // In C code, this builds the response with:
    // - auth_result
    // - supi
    // - kseaf

    log::debug!(
        "[{}] Sending ConfirmationDataResponse",
        ausf_ue.suci
    );

    // Note: The HTTP 200 OK response with ConfirmationDataResponse is built
    // and sent via the HTTP handler in main.rs

    true
}

/// Process authentication info result from UDM
pub struct AuthenticationInfoResult {
    pub auth_type: AuthType,
    pub supi: String,
    pub rand: [u8; 16],
    pub xres_star: [u8; 16],
    pub autn: [u8; 16],
    pub kausf: [u8; 32],
}

/// Process authentication vector from UDM response
pub fn process_authentication_vector(
    ausf_ue_id: u64,
    auth_info: &AuthenticationInfoResult,
) -> Result<(), &'static str> {
    let ctx = ausf_self();
    let context = ctx.write().unwrap();

    let ausf_ue = match context.ue_find_by_id(ausf_ue_id) {
        Some(ue) => ue,
        None => {
            return Err("AUSF UE not found");
        }
    };

    // Validate auth type
    if auth_info.auth_type != AuthType::FiveGAka {
        return Err("Not supported Auth Method");
    }

    // Set SUPI
    context.ue_set_supi(ausf_ue_id, &auth_info.supi);

    // Store authentication vector
    let mut updated_ue = ausf_ue.clone();
    updated_ue.auth_type = auth_info.auth_type;
    updated_ue.rand = auth_info.rand;
    updated_ue.xres_star = auth_info.xres_star;
    updated_ue.autn = auth_info.autn;
    updated_ue.kausf = auth_info.kausf;

    // Calculate HXRES*
    updated_ue.calculate_hxres_star();

    // Update UE in context
    context.ue_update(&updated_ue);

    Ok(())
}

/// Build UeAuthenticationCtx response
pub struct UeAuthenticationCtx {
    pub auth_type: AuthType,
    pub rand: String,
    pub autn: String,
    pub hxres_star: String,
    pub links_href: String,
}

/// Build the UeAuthenticationCtx for response
pub fn build_ue_authentication_ctx(
    ausf_ue_id: u64,
    server_uri: &str,
) -> Option<UeAuthenticationCtx> {
    let ctx = ausf_self();
    let context = ctx.read().unwrap();

    let ausf_ue = context.ue_find_by_id(ausf_ue_id)?;

    // Convert bytes to hex strings
    let rand_hex = bytes_to_hex(&ausf_ue.rand);
    let hxres_star_hex = bytes_to_hex(&ausf_ue.hxres_star);

    // Build links href
    let links_href = format!(
        "{}/nausf-auth/v1/ue-authentications/{}/5g-aka-confirmation",
        server_uri, ausf_ue.ctx_id
    );

    let autn_hex = bytes_to_hex(&ausf_ue.autn);

    Some(UeAuthenticationCtx {
        auth_type: ausf_ue.auth_type,
        rand: rand_hex,
        autn: autn_hex,
        hxres_star: hxres_star_hex,
        links_href,
    })
}

/// Build ConfirmationDataResponse
pub struct ConfirmationDataResponse {
    pub auth_result: AuthResult,
    pub supi: String,
    pub kseaf: String,
}

/// Build the ConfirmationDataResponse for response
pub fn build_confirmation_data_response(ausf_ue_id: u64) -> Option<ConfirmationDataResponse> {
    let ctx = ausf_self();
    let context = ctx.read().unwrap();

    let ausf_ue = context.ue_find_by_id(ausf_ue_id)?;

    let kseaf_hex = bytes_to_hex(&ausf_ue.kseaf);

    Some(ConfirmationDataResponse {
        auth_result: ausf_ue.auth_result,
        supi: ausf_ue.supi.clone()?,
        kseaf: kseaf_hex,
    })
}

/// Convert bytes to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_links_member_name() {
        assert_eq!(links_member_name(AuthType::FiveGAka), "5g-aka");
        assert_eq!(links_member_name(AuthType::EapAkaPrime), "5g-aka");
        assert_eq!(links_member_name(AuthType::EapTls), "eap-session");
    }

    #[test]
    fn test_bytes_to_hex() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(bytes_to_hex(&bytes), "0123456789abcdef");
    }

    #[test]
    fn test_hex_to_bytes() {
        let hex = "0123456789abcdef";
        let expected = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(hex_to_bytes(hex), expected);
    }

    #[test]
    fn test_hex_roundtrip() {
        let original = [0xde, 0xad, 0xbe, 0xef];
        let hex = bytes_to_hex(&original);
        let bytes = hex_to_bytes(&hex);
        assert_eq!(bytes, original);
    }
}
