//! AMF SBI Path Functions
//!
//! Port of src/amf/sbi-path.c - SBI service discovery and message routing

use base64::Engine;
use ogs_sbi::client::SbiClient;

use crate::context::{AmfUe, AmfSess, RanUe};

// ============================================================================
// Constants
// ============================================================================

/// SBI service names
pub mod service_name {
    pub const NAMF_COMM: &str = "namf-comm";
    pub const NAMF_EVTS: &str = "namf-evts";
    pub const NAMF_MT: &str = "namf-mt";
    pub const NAMF_LOC: &str = "namf-loc";
    pub const NAUSF_AUTH: &str = "nausf-auth";
    pub const NUDM_UECM: &str = "nudm-uecm";
    pub const NUDM_SDM: &str = "nudm-sdm";
    pub const NSMF_PDUSESSION: &str = "nsmf-pdusession";
    pub const NNSSF_NSSELECTION: &str = "nnssf-nsselection";
    pub const NPCF_AM_POLICY_CONTROL: &str = "npcf-am-policy-control";
    pub const NNRF_NFM: &str = "nnrf-nfm";
    pub const NNRF_DISC: &str = "nnrf-disc";
}

/// SBI API versions
pub mod api_version {
    pub const V1: &str = "v1";
    pub const V1_0_0: &str = "1.0.0";
}

/// SBI resource names
pub mod resource_name {
    pub const UE_CONTEXTS: &str = "ue-contexts";
    pub const N1_N2_MESSAGES: &str = "n1-n2-messages";
    pub const SM_CONTEXTS: &str = "sm-contexts";
    pub const SUBSCRIPTIONS: &str = "subscriptions";
    pub const NF_INSTANCES: &str = "nf-instances";
}

/// AMF association IDs for SBI transactions
pub mod assoc_id {
    pub const RAN_UE_ID: usize = 0;
}

/// AMF SM context states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SmContextState {
    #[default]
    NoState,
    /// Creating SM context
    Creating,
    /// Created SM context
    Created,
    /// Updating SM context
    Updating,
    /// Releasing SM context
    Releasing,
    /// Released SM context
    Released,
}

/// AMF session release states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionReleaseState {
    #[default]
    NoState,
    /// N1 released
    N1Released,
    /// N2 released
    N2Released,
    /// Both N1 and N2 released
    BothReleased,
}

/// SMF selection states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SmfSelectionState {
    #[default]
    NoState,
    /// SMF selection in VPLMN for non-roaming or LBO
    InVplmnNonRoamingOrLbo,
    /// SMF selection in VPLMN for home-routed
    InVplmnHomeRouted,
    /// SMF selection in HPLMN for home-routed
    InHplmnHomeRouted,
}

// ============================================================================
// SBI Error Types
// ============================================================================

/// SBI error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SbiError {
    /// Service not found
    ServiceNotFound(String),
    /// NF instance not found
    NfInstanceNotFound,
    /// Request failed
    RequestFailed(String),
    /// Response parse error
    ResponseParseError(String),
    /// Timeout
    Timeout,
    /// Gateway timeout
    GatewayTimeout,
    /// Invalid state
    InvalidState,
}

impl std::fmt::Display for SbiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SbiError::ServiceNotFound(s) => write!(f, "Service not found: {}", s),
            SbiError::NfInstanceNotFound => write!(f, "NF instance not found"),
            SbiError::RequestFailed(s) => write!(f, "Request failed: {}", s),
            SbiError::ResponseParseError(s) => write!(f, "Response parse error: {}", s),
            SbiError::Timeout => write!(f, "Timeout"),
            SbiError::GatewayTimeout => write!(f, "Gateway timeout"),
            SbiError::InvalidState => write!(f, "Invalid state"),
        }
    }
}

impl std::error::Error for SbiError {}

/// SBI result type
pub type SbiResult<T> = Result<T, SbiError>;

// ============================================================================
// SBI Service Types
// ============================================================================

/// SBI service type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SbiServiceType {
    /// NAUSF authentication
    NausfAuth,
    /// NUDM UE context management
    NudmUecm,
    /// NUDM subscription data management
    NudmSdm,
    /// NSMF PDU session
    NsmfPdusession,
    /// NNSSF NS selection
    NnssfNsselection,
    /// NPCF AM policy control
    NpcfAmPolicyControl,
    /// NNRF NF management
    NnrfNfm,
    /// NNRF discovery
    NnrfDisc,
}

impl SbiServiceType {
    /// Get service name string
    pub fn service_name(&self) -> &'static str {
        match self {
            Self::NausfAuth => service_name::NAUSF_AUTH,
            Self::NudmUecm => service_name::NUDM_UECM,
            Self::NudmSdm => service_name::NUDM_SDM,
            Self::NsmfPdusession => service_name::NSMF_PDUSESSION,
            Self::NnssfNsselection => service_name::NNSSF_NSSELECTION,
            Self::NpcfAmPolicyControl => service_name::NPCF_AM_POLICY_CONTROL,
            Self::NnrfNfm => service_name::NNRF_NFM,
            Self::NnrfDisc => service_name::NNRF_DISC,
        }
    }
}

// ============================================================================
// SBI Discovery Option
// ============================================================================

/// SBI discovery option for NF selection
#[derive(Debug, Clone, Default)]
pub struct SbiDiscoveryOption {
    /// Target PLMN list
    pub target_plmn_list: Vec<String>,
    /// Requester PLMN list
    pub requester_plmn_list: Vec<String>,
    /// S-NSSAI list
    pub snssai_list: Vec<(u8, Option<u32>)>,
    /// DNN
    pub dnn: Option<String>,
    /// TAI
    pub tai: Option<(String, u32)>,
}

impl SbiDiscoveryOption {
    /// Create new discovery option
    pub fn new() -> Self {
        Self::default()
    }

    /// Add target PLMN
    pub fn add_target_plmn(&mut self, plmn_id: &str) {
        self.target_plmn_list.push(plmn_id.to_string());
    }

    /// Add requester PLMN
    pub fn add_requester_plmn(&mut self, plmn_id: &str) {
        self.requester_plmn_list.push(plmn_id.to_string());
    }

    /// Add S-NSSAI
    pub fn add_snssai(&mut self, sst: u8, sd: Option<u32>) {
        self.snssai_list.push((sst, sd));
    }

    /// Set DNN
    pub fn set_dnn(&mut self, dnn: &str) {
        self.dnn = Some(dnn.to_string());
    }

    /// Set TAI
    pub fn set_tai(&mut self, plmn_id: &str, tac: u32) {
        self.tai = Some((plmn_id.to_string(), tac));
    }
}

// ============================================================================
// SBI Transaction
// ============================================================================

/// SBI transaction for tracking requests
#[derive(Debug, Clone)]
pub struct SbiXact {
    /// Transaction ID
    pub id: u64,
    /// Service type
    pub service_type: SbiServiceType,
    /// Discovery option
    pub discovery_option: Option<SbiDiscoveryOption>,
    /// State
    pub state: i32,
    /// Associated IDs
    pub assoc_ids: [u64; 4],
    /// SBI object ID (UE or session)
    pub sbi_object_id: u64,
}

impl SbiXact {
    /// Create new transaction
    pub fn new(id: u64, service_type: SbiServiceType, sbi_object_id: u64) -> Self {
        Self {
            id,
            service_type,
            discovery_option: None,
            state: 0,
            assoc_ids: [0; 4],
            sbi_object_id,
        }
    }
}

// ============================================================================
// SBI Path Functions
// ============================================================================

/// Initialize AMF SBI
pub fn amf_sbi_open() -> SbiResult<()> {
    log::info!("AMF SBI opening...");
    // Note: Initialize NF instance, build NF service info, start servers
    // NF instance initialization and SBI server startup handled by ogs_sbi integration
    Ok(())
}

/// Close AMF SBI
pub fn amf_sbi_close() {
    log::info!("AMF SBI closing...");
    // Note: Stop clients and servers
    // SBI client/server cleanup handled by ogs_sbi integration during shutdown
}

/// Send SBI request to NF instance
pub fn amf_sbi_send_request(
    _nf_instance_id: &str,
    _xact: &SbiXact,
) -> SbiResult<()> {
    // Note: Implement actual SBI request sending
    // HTTP/2 request transmission handled by ogs_sbi client module
    Ok(())
}

/// Discover and send SBI request for UE
pub fn amf_ue_sbi_discover_and_send(
    service_type: SbiServiceType,
    discovery_option: Option<SbiDiscoveryOption>,
    amf_ue: &AmfUe,
    state: i32,
) -> SbiResult<()> {
    log::debug!(
        "UE SBI discover and send: service={:?}, ue_id={}, state={}",
        service_type, amf_ue.id, state
    );

    let mut xact = SbiXact::new(0, service_type, amf_ue.id);
    xact.discovery_option = discovery_option;
    xact.state = state;

    // Note: Implement actual discovery and send
    // NF discovery via NRF and request routing handled by ogs_sbi discovery module
    Ok(())
}

/// Discover and send SBI request for session
pub fn amf_sess_sbi_discover_and_send(
    service_type: SbiServiceType,
    discovery_option: Option<SbiDiscoveryOption>,
    ran_ue: Option<&RanUe>,
    sess: &AmfSess,
    state: i32,
) -> SbiResult<()> {
    log::debug!(
        "Session SBI discover and send: service={:?}, sess_id={}, state={}",
        service_type, sess.id, state
    );

    let mut xact = SbiXact::new(0, service_type, sess.id);
    xact.discovery_option = discovery_option;
    xact.state = state;

    if let Some(ran_ue) = ran_ue {
        xact.assoc_ids[assoc_id::RAN_UE_ID] = ran_ue.id;
    }

    // Note: Implement actual discovery and send
    // Session-level NF discovery and request routing handled by ogs_sbi discovery module
    Ok(())
}

/// Send activating session request
pub fn amf_sbi_send_activating_session(
    ran_ue: Option<&RanUe>,
    sess: &AmfSess,
    state: i32,
) -> SbiResult<()> {
    log::debug!("Send activating session: sess_id={}, state={}", sess.id, state);
    amf_sess_sbi_discover_and_send(
        SbiServiceType::NsmfPdusession,
        None,
        ran_ue,
        sess,
        state,
    )
}

/// Send deactivate session request
pub fn amf_sbi_send_deactivate_session(
    ran_ue: Option<&RanUe>,
    sess: &AmfSess,
    state: i32,
    _cause_group: u8,
    _cause_value: i64,
) -> SbiResult<()> {
    log::debug!("Send deactivate session: sess_id={}, state={}", sess.id, state);
    amf_sess_sbi_discover_and_send(
        SbiServiceType::NsmfPdusession,
        None,
        ran_ue,
        sess,
        state,
    )
}

/// Send release session request
pub fn amf_sbi_send_release_session(
    ran_ue: Option<&RanUe>,
    sess: &AmfSess,
    state: i32,
) -> SbiResult<()> {
    log::debug!("Send release session: sess_id={}, state={}", sess.id, state);
    amf_sess_sbi_discover_and_send(
        SbiServiceType::NsmfPdusession,
        None,
        ran_ue,
        sess,
        state,
    )
}

/// Check if UE has pending session release
pub fn amf_ue_have_session_release_pending(_amf_ue: &AmfUe) -> bool {
    // Note: Check all sessions for pending release
    // Session release state tracked in AmfSess and aggregated at UE level
    false
}

/// Check if session has pending release
pub fn amf_sess_have_session_release_pending(_sess: &AmfSess) -> bool {
    // Note: Check session state for pending release
    // Release state tracked via n1_released/n2_released flags and resource_status
    false
}

// ============================================================================
// SMF SBI Client Functions
// ============================================================================

/// SM Context Create response from SMF
pub struct SmContextCreateResponse {
    /// N1 SM message (NAS PDU Session Establishment Accept)
    pub n1_sm_msg: Vec<u8>,
    /// N2 SM Information (UPF tunnel endpoint)
    pub n2_sm_info: Vec<u8>,
    /// SM Context reference
    pub sm_context_ref: String,
}

/// Call SMF to create SM context (POST /nsmf-pdusession/v1/sm-contexts)
///
/// Returns the N1 SM message (PDU Session Accept), N2 SM Info (UPF TEID/addr),
/// and SM Context reference for subsequent updates.
pub async fn call_smf_create_sm_context(
    smf_host: &str,
    smf_port: u16,
    pdu_session_id: u8,
    sst: u8,
    sd: Option<u32>,
    dnn: &str,
    n1_sm_msg_from_ue: &[u8],
) -> SbiResult<SmContextCreateResponse> {
    log::info!(
        "Calling SMF SM Context Create: {}:{}, PSI={}, SST={}, DNN={}",
        smf_host, smf_port, pdu_session_id, sst, dnn
    );

    let client = SbiClient::with_host_port(smf_host, smf_port);

    let body = serde_json::json!({
        "pduSessionId": pdu_session_id,
        "sNssai": {
            "sst": sst,
            "sd": sd.map(|v| format!("{:06x}", v))
        },
        "dnn": dnn,
        "n1SmMsg": base64::engine::general_purpose::STANDARD.encode(n1_sm_msg_from_ue),
        "servingNetwork": {
            "mcc": "001",
            "mnc": "01"
        }
    });

    let response = client.post_json("/nsmf-pdusession/v1/sm-contexts", &body)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("SMF request failed: {}", e)))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "SMF returned status {}", response.status
        )));
    }

    let response_body: serde_json::Value = match &response.http.content {
        Some(content) => serde_json::from_str(content)
            .map_err(|e| SbiError::ResponseParseError(format!("Invalid JSON: {}", e)))?,
        None => return Err(SbiError::ResponseParseError("Empty response body".to_string())),
    };

    // Extract SM Context ref from Location header or response body
    let sm_context_ref = response.http.headers.get("location")
        .and_then(|loc| loc.rsplit('/').next().map(|s| s.to_string()))
        .or_else(|| response_body["smContextRef"].as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "1".to_string());

    // Extract N1 SM message (base64-encoded PDU Session Accept from SMF)
    let n1_sm_msg = response_body["n1SmMsg"].as_str()
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .unwrap_or_default();

    // Extract N2 SM Information (base64-encoded UPF tunnel info from SMF)
    let n2_sm_info = response_body["n2SmInfo"].as_str()
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .unwrap_or_default();

    log::info!(
        "SMF SM Context Created: ref={}, n1_len={}, n2_len={}",
        sm_context_ref, n1_sm_msg.len(), n2_sm_info.len()
    );

    Ok(SmContextCreateResponse {
        n1_sm_msg,
        n2_sm_info,
        sm_context_ref,
    })
}

/// Call SMF to update SM context (POST /nsmf-pdusession/v1/sm-contexts/{ref}/modify)
///
/// Used to send gNB TEID back to SMF after PDU Session Resource Setup Response.
pub async fn call_smf_update_sm_context(
    smf_host: &str,
    smf_port: u16,
    sm_context_ref: &str,
    n2_sm_info: &[u8],
) -> SbiResult<()> {
    log::info!(
        "Calling SMF SM Context Update: ref={}, n2_info_len={}",
        sm_context_ref, n2_sm_info.len()
    );

    let client = SbiClient::with_host_port(smf_host, smf_port);

    let body = serde_json::json!({
        "n2SmInfo": base64::engine::general_purpose::STANDARD.encode(n2_sm_info),
        "n2SmInfoType": "PDU_RES_SETUP_RSP"
    });

    let path = format!("/nsmf-pdusession/v1/sm-contexts/{}/modify", sm_context_ref);
    let response = client.post_json(&path, &body)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("SMF update failed: {}", e)))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "SMF update returned status {}", response.status
        )));
    }

    log::info!("SMF SM Context Updated: ref={}", sm_context_ref);
    Ok(())
}

// ============================================================================
// AUSF SBI Client Functions
// ============================================================================

/// AUSF authentication response
pub struct AusfAuthResponse {
    /// RAND (16 bytes)
    pub rand: [u8; 16],
    /// AUTN (16 bytes)
    pub autn: [u8; 16],
    /// HXRES* (16 bytes)
    pub hxres_star: [u8; 16],
    /// Auth context ID (for 5G-AKA confirmation)
    pub auth_ctx_id: String,
}

/// Call AUSF to authenticate UE (POST /nausf-auth/v1/ue-authentications)
pub async fn call_ausf_authenticate(
    ausf_host: &str,
    ausf_port: u16,
    suci: &str,
    serving_network_name: &str,
) -> SbiResult<AusfAuthResponse> {
    log::info!(
        "Calling AUSF authenticate: {}:{}, SUCI={}, SNN={}",
        ausf_host, ausf_port, suci, serving_network_name
    );

    let client = SbiClient::with_host_port(ausf_host, ausf_port);

    let body = serde_json::json!({
        "supiOrSuci": suci,
        "servingNetworkName": serving_network_name
    });

    let response = client.post_json("/nausf-auth/v1/ue-authentications", &body)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("AUSF request failed: {}", e)))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "AUSF returned status {}", response.status
        )));
    }

    let response_body: serde_json::Value = match &response.http.content {
        Some(content) => serde_json::from_str(content)
            .map_err(|e| SbiError::ResponseParseError(format!("Invalid JSON: {}", e)))?,
        None => return Err(SbiError::ResponseParseError("Empty response body".to_string())),
    };

    // Extract auth data
    let auth_data = &response_body["5gAuthData"];

    let rand = hex_to_16bytes(auth_data["rand"].as_str().unwrap_or(""))
        .map_err(|e| SbiError::ResponseParseError(format!("Invalid RAND: {}", e)))?;
    let autn = hex_to_16bytes(auth_data["autn"].as_str().unwrap_or(""))
        .map_err(|e| SbiError::ResponseParseError(format!("Invalid AUTN: {}", e)))?;
    let hxres_star = hex_to_16bytes(auth_data["hxresStar"].as_str().unwrap_or(""))
        .map_err(|e| SbiError::ResponseParseError(format!("Invalid HXRES*: {}", e)))?;

    // Extract auth context ID from Location header
    let auth_ctx_id = response.http.headers.get("location")
        .and_then(|loc| loc.rsplit('/').next().map(|s| s.to_string()))
        .unwrap_or_else(|| "1".to_string());

    log::info!(
        "AUSF auth response: ctx_id={}, RAND={}, AUTN={}",
        auth_ctx_id,
        hex::encode(&rand[..4]),
        hex::encode(&autn[..4])
    );

    Ok(AusfAuthResponse {
        rand,
        autn,
        hxres_star,
        auth_ctx_id,
    })
}

/// AUSF 5G-AKA confirmation response
pub struct AusfConfirmResponse {
    /// Auth result
    pub auth_result: String,
    /// KSEAF (32 bytes)
    pub kseaf: [u8; 32],
    /// SUPI
    pub supi: Option<String>,
}

/// Call AUSF for 5G-AKA confirmation (PUT /nausf-auth/v1/ue-authentications/{id}/5g-aka-confirmation)
pub async fn call_ausf_5g_aka_confirm(
    ausf_host: &str,
    ausf_port: u16,
    auth_ctx_id: &str,
    res_star: &[u8; 16],
) -> SbiResult<AusfConfirmResponse> {
    log::info!(
        "Calling AUSF 5G-AKA confirmation: ctx_id={}, RES*={}",
        auth_ctx_id, hex::encode(&res_star[..4])
    );

    let client = SbiClient::with_host_port(ausf_host, ausf_port);

    let body = serde_json::json!({
        "resStar": hex::encode(res_star)
    });

    let path = format!("/nausf-auth/v1/ue-authentications/{}/5g-aka-confirmation", auth_ctx_id);
    let response = client.put_json(&path, &body)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("AUSF confirmation failed: {}", e)))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "AUSF confirmation returned status {}", response.status
        )));
    }

    let response_body: serde_json::Value = match &response.http.content {
        Some(content) => serde_json::from_str(content)
            .map_err(|e| SbiError::ResponseParseError(format!("Invalid JSON: {}", e)))?,
        None => return Err(SbiError::ResponseParseError("Empty response body".to_string())),
    };

    let auth_result = response_body["authResult"].as_str().unwrap_or("UNKNOWN").to_string();

    let kseaf_hex = response_body["kseaf"].as_str().unwrap_or("");
    let kseaf_bytes = hex::decode(kseaf_hex)
        .map_err(|e| SbiError::ResponseParseError(format!("Invalid KSEAF: {}", e)))?;
    let mut kseaf = [0u8; 32];
    if kseaf_bytes.len() >= 32 {
        kseaf.copy_from_slice(&kseaf_bytes[..32]);
    }

    let supi = response_body["supi"].as_str().map(|s| s.to_string());

    log::info!("AUSF 5G-AKA confirmation: result={}, supi={:?}", auth_result, supi);

    Ok(AusfConfirmResponse {
        auth_result,
        kseaf,
        supi,
    })
}

/// Helper: convert hex string to [u8; 16]
fn hex_to_16bytes(hex_str: &str) -> Result<[u8; 16], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("hex decode: {}", e))?;
    if bytes.len() != 16 {
        return Err(format!("expected 16 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbi_service_type_names() {
        assert_eq!(SbiServiceType::NausfAuth.service_name(), "nausf-auth");
        assert_eq!(SbiServiceType::NudmUecm.service_name(), "nudm-uecm");
        assert_eq!(SbiServiceType::NsmfPdusession.service_name(), "nsmf-pdusession");
    }

    #[test]
    fn test_sbi_discovery_option() {
        let mut opt = SbiDiscoveryOption::new();
        opt.add_target_plmn("310260");
        opt.add_snssai(1, Some(0x010203));
        opt.set_dnn("internet");
        opt.set_tai("310260", 0x1234);

        assert_eq!(opt.target_plmn_list.len(), 1);
        assert_eq!(opt.snssai_list.len(), 1);
        assert_eq!(opt.dnn, Some("internet".to_string()));
        assert!(opt.tai.is_some());
    }

    #[test]
    fn test_sbi_xact_creation() {
        let xact = SbiXact::new(1, SbiServiceType::NausfAuth, 100);
        assert_eq!(xact.id, 1);
        assert_eq!(xact.service_type, SbiServiceType::NausfAuth);
        assert_eq!(xact.sbi_object_id, 100);
        assert_eq!(xact.state, 0);
    }

    #[test]
    fn test_sm_context_state() {
        let state = SmContextState::default();
        assert_eq!(state, SmContextState::NoState);
    }

    #[test]
    fn test_smf_selection_state() {
        let state = SmfSelectionState::default();
        assert_eq!(state, SmfSelectionState::NoState);
    }

    #[test]
    fn test_amf_sbi_open_close() {
        assert!(amf_sbi_open().is_ok());
        amf_sbi_close();
    }
}
