//! AMF SBI Path Functions
//!
//! Port of src/amf/sbi-path.c - SBI service discovery and message routing

use base64::Engine;
use ogs_sbi::client::SbiClient;
use ogs_sbi::context::{global_context, NfInstance, NfService};

use crate::context::{AmfSess, AmfUe, RanUe};

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
    pub const NNSACF_NSAC: &str = "nnsacf-nsac";
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
            SbiError::ServiceNotFound(s) => write!(f, "Service not found: {s}"),
            SbiError::NfInstanceNotFound => write!(f, "NF instance not found"),
            SbiError::RequestFailed(s) => write!(f, "Request failed: {s}"),
            SbiError::ResponseParseError(s) => write!(f, "Response parse error: {s}"),
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
    /// NNSACF network slice admission control
    NnsacfNsac,
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
            Self::NnsacfNsac => service_name::NNSACF_NSAC,
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

/// Initialize AMF SBI - build self NF instance and store in SBI context
pub fn amf_sbi_open() -> SbiResult<()> {
    log::info!("AMF SBI opening...");

    // Build self NF instance for AMF
    let nf_instance_id = uuid::Uuid::new_v4().to_string();
    let sbi_addr = std::env::var("AMF_SBI_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
    let sbi_port: u16 = std::env::var("AMF_SBI_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7777);

    let mut nf_instance = NfInstance::new(&nf_instance_id, ogs_sbi::types::NfType::Amf);
    nf_instance.ipv4_addresses.push(sbi_addr.clone());

    // Register Namf services: namf-comm, namf-evts, namf-mt, namf-loc
    let mut comm_service = NfService::new("namf-comm", ogs_sbi::types::SbiServiceType::NamfComm);
    comm_service.versions = vec!["v1".to_string()];
    comm_service.port = sbi_port;
    comm_service.ip_addresses.push(sbi_addr.clone());
    nf_instance.add_service(comm_service);

    let mut evts_service = NfService::new("namf-evts", ogs_sbi::types::SbiServiceType::NamfEvts);
    evts_service.versions = vec!["v1".to_string()];
    evts_service.port = sbi_port;
    nf_instance.add_service(evts_service);

    // Store self NF instance in global SBI context
    let sbi_ctx = global_context();
    tokio::spawn(async move {
        sbi_ctx.set_self_instance(nf_instance).await;
    });

    // Set NRF URI if configured via env var
    if let Ok(nrf_uri) = std::env::var("NRF_URI") {
        let sbi_ctx = global_context();
        tokio::spawn(async move {
            sbi_ctx.set_nrf_uri(nrf_uri).await;
        });
    }

    log::info!("AMF SBI opened (nf_instance_id={nf_instance_id}, addr={sbi_addr}:{sbi_port})");
    Ok(())
}

/// Close AMF SBI
pub fn amf_sbi_close() {
    log::info!("AMF SBI closing...");
    let sbi_ctx = global_context();
    if let Ok(_handle) = tokio::runtime::Handle::try_current() {
        tokio::spawn(async move {
            sbi_ctx.clear_clients().await;
            sbi_ctx.clear_nf_instances().await;
        });
    }
    log::info!("AMF SBI closed");
}

/// Register AMF NF instance with NRF
///
/// Sends PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId} to NRF.
/// Returns the NF instance ID on success so the caller can start a heartbeat worker.
pub async fn amf_nrf_register(sbi_addr: &str, sbi_port: u16) -> Result<String, String> {
    let sbi_ctx = global_context();

    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => {
            log::debug!("No NRF URI configured, skipping NRF registration");
            return Ok(String::new());
        }
    };

    log::info!("Registering AMF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_instance_id = uuid::Uuid::new_v4().to_string();

    let nf_profile = serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "AMF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [{
            "serviceInstanceId": format!("{nf_instance_id}-namf-comm"),
            "serviceName": "namf-comm",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{
                "ipv4Address": sbi_addr,
                "port": sbi_port
            }]
        }],
        "allowedNfTypes": ["SMF", "AUSF", "UDM", "PCF", "NSSF"],
        "heartBeatTimer": 10
    });

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    log::debug!("NRF registration: PUT {path}");

    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("AMF registered with NRF (id={nf_instance_id})");

            // Update self instance in SBI context
            let mut self_instance = NfInstance::new(&nf_instance_id, ogs_sbi::types::NfType::Amf);
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = NfService::new("namf-comm", ogs_sbi::types::SbiServiceType::NamfComm);
            svc.port = sbi_port;
            svc.ip_addresses = vec![sbi_addr.to_string()];
            self_instance.add_service(svc);
            sbi_ctx.set_self_instance(self_instance).await;

            Ok(nf_instance_id)
        }
        _ => Err(format!(
            "NRF registration returned status {}",
            response.status
        )),
    }
}

/// Discover NF services from NRF
///
/// Queries GET /nnrf-disc/v1/nf-instances?target-nf-type={type}&service-names={svc}
pub async fn amf_nrf_discover(target_nf_type: &str, service_name: &str) -> Result<(), String> {
    let sbi_ctx = global_context();

    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => return Ok(()),
    };

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let path = format!(
        "/nnrf-disc/v1/nf-instances?target-nf-type={target_nf_type}&requester-nf-type=AMF&service-names={service_name}"
    );

    let response = client
        .get(&path)
        .await
        .map_err(|e| format!("NRF discovery failed: {e}"))?;

    if response.status != 200 {
        return Err(format!("NRF discovery returned status {}", response.status));
    }

    let body = response
        .http
        .content
        .ok_or("Empty NRF discovery response")?;
    let json: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("Invalid NRF discovery response: {e}"))?;

    if let Some(nf_instances) = json.get("nfInstances").and_then(|v| v.as_array()) {
        for nf_json in nf_instances {
            let nf_id = nf_json
                .get("nfInstanceId")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let nf_type_str = nf_json.get("nfType").and_then(|v| v.as_str()).unwrap_or("");

            let nf_type = match nf_type_str {
                "AUSF" => ogs_sbi::types::NfType::Ausf,
                "UDM" => ogs_sbi::types::NfType::Udm,
                "SMF" => ogs_sbi::types::NfType::Smf,
                "PCF" => ogs_sbi::types::NfType::Pcf,
                "NSSF" => ogs_sbi::types::NfType::Nssf,
                "NRF" => ogs_sbi::types::NfType::Nrf,
                _ => continue,
            };

            let mut instance = NfInstance::new(nf_id, nf_type);

            if let Some(fqdn) = nf_json.get("fqdn").and_then(|v| v.as_str()) {
                instance.fqdn = Some(fqdn.to_string());
            }
            if let Some(addrs) = nf_json.get("ipv4Addresses").and_then(|v| v.as_array()) {
                instance.ipv4_addresses = addrs
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
            }

            if let Some(services) = nf_json.get("nfServices").and_then(|v| v.as_array()) {
                for svc_json in services {
                    let svc_name = svc_json
                        .get("serviceName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if let Some(svc_type) = ogs_sbi::types::SbiServiceType::from_name(svc_name) {
                        let mut svc = NfService::new(svc_name, svc_type);
                        if let Some(endpoints) =
                            svc_json.get("ipEndPoints").and_then(|v| v.as_array())
                        {
                            if let Some(ep) = endpoints.first() {
                                if let Some(addr) = ep.get("ipv4Address").and_then(|v| v.as_str()) {
                                    svc.ip_addresses.push(addr.to_string());
                                }
                                if let Some(port) = ep.get("port").and_then(|v| v.as_u64()) {
                                    svc.port = port as u16;
                                }
                            }
                        }
                        instance.add_service(svc);
                    }
                }
            }

            sbi_ctx.add_nf_instance(instance).await;
            log::info!("Discovered {nf_type_str} instance: {nf_id}");
        }
    }

    Ok(())
}

/// Parse host and port from a URI string (e.g., "http://localhost:7777")
fn parse_host_port(uri: &str) -> Option<(String, u16)> {
    let without_scheme = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    let (host_port, _path) = without_scheme
        .split_once('/')
        .unwrap_or((without_scheme, ""));
    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let port: u16 = port_str.parse().ok()?;
        Some((host.to_string(), port))
    } else {
        let default_port = if uri.starts_with("https://") { 443 } else { 80 };
        Some((host_port.to_string(), default_port))
    }
}

/// Send SBI request to NF instance
pub fn amf_sbi_send_request(_nf_instance_id: &str, _xact: &SbiXact) -> SbiResult<()> {
    // Note: Implement actual SBI request sending
    // HTTP/2 request transmission handled by ogs_sbi client module
    Ok(())
}

/// Discover NF endpoint for the given service type using SbiContext cache + env var fallback
fn resolve_nf_endpoint(service_type: SbiServiceType) -> SbiResult<(String, u16)> {
    // Map AMF SbiServiceType to ogs_sbi SbiServiceType and env var names
    let (ogs_service_type, env_addr, env_port, default_port) = match service_type {
        SbiServiceType::NausfAuth => (
            ogs_sbi::types::SbiServiceType::NausfAuth,
            "AUSF_SBI_ADDR",
            "AUSF_SBI_PORT",
            7777u16,
        ),
        SbiServiceType::NudmUecm => (
            ogs_sbi::types::SbiServiceType::NudmUecm,
            "UDM_SBI_ADDR",
            "UDM_SBI_PORT",
            7777,
        ),
        SbiServiceType::NudmSdm => (
            ogs_sbi::types::SbiServiceType::NudmSdm,
            "UDM_SBI_ADDR",
            "UDM_SBI_PORT",
            7777,
        ),
        SbiServiceType::NsmfPdusession => (
            ogs_sbi::types::SbiServiceType::NsmfPdusession,
            "SMF_SBI_ADDR",
            "SMF_SBI_PORT",
            7777,
        ),
        SbiServiceType::NnssfNsselection => (
            ogs_sbi::types::SbiServiceType::NnssfNsselection,
            "NSSF_SBI_ADDR",
            "NSSF_SBI_PORT",
            7777,
        ),
        SbiServiceType::NpcfAmPolicyControl => (
            ogs_sbi::types::SbiServiceType::NpcfAmPolicyControl,
            "PCF_SBI_ADDR",
            "PCF_SBI_PORT",
            7777,
        ),
        _ => {
            return Err(SbiError::ServiceNotFound(format!("{service_type:?}")));
        }
    };

    // Try SbiContext cache first (non-blocking check using try_read on tokio runtime)
    // Use a blocking approach since callers may not be async
    let sbi_ctx = global_context();
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        // We're inside a tokio runtime, spawn a blocking task
        let svc_type = ogs_service_type;
        let ctx = sbi_ctx.clone();
        if let Ok(result) = handle.block_on(async {
            let instances = ctx.find_nf_instances_by_service(svc_type).await;
            if let Some(inst) = instances.first() {
                if let Some(svc) = inst.find_service(svc_type) {
                    let host = svc
                        .ip_addresses
                        .first()
                        .or(inst.ipv4_addresses.first())
                        .or(svc.fqdn.as_ref())
                        .or(inst.fqdn.as_ref());
                    if let Some(h) = host {
                        return Ok((h.clone(), svc.port));
                    }
                }
            }
            Err(())
        }) {
            return Ok(result);
        }
    }

    // Fallback: use env vars
    let host = std::env::var(env_addr).map_err(|_| SbiError::NfInstanceNotFound)?;
    let port = std::env::var(env_port)
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(default_port);
    log::info!("Using env var fallback for {service_type:?}: {host}:{port}");
    Ok((host, port))
}

/// Resolve the SMF SBI endpoint (host, port).
///
/// Convenience wrapper for the SMF service type used from ngap_handler.
pub fn resolve_smf_endpoint() -> SbiResult<(String, u16)> {
    resolve_nf_endpoint(SbiServiceType::NsmfPdusession)
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
        service_type,
        amf_ue.id,
        state
    );

    let mut xact = SbiXact::new(0, service_type, amf_ue.id);
    xact.discovery_option = discovery_option;
    xact.state = state;

    // Resolve the target NF endpoint
    let (host, port) = resolve_nf_endpoint(service_type)?;
    log::info!(
        "UE SBI resolved {:?} -> {host}:{port} for ue_id={}",
        service_type,
        amf_ue.id
    );

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
        service_type,
        sess.id,
        state
    );

    let mut xact = SbiXact::new(0, service_type, sess.id);
    xact.discovery_option = discovery_option;
    xact.state = state;

    if let Some(ran_ue) = ran_ue {
        xact.assoc_ids[assoc_id::RAN_UE_ID] = ran_ue.id;
    }

    // Resolve the target NF endpoint
    let (host, port) = resolve_nf_endpoint(service_type)?;
    log::info!(
        "Session SBI resolved {:?} -> {host}:{port} for sess_id={}",
        service_type,
        sess.id
    );

    Ok(())
}

/// Send activating session request
pub fn amf_sbi_send_activating_session(
    ran_ue: Option<&RanUe>,
    sess: &AmfSess,
    state: i32,
) -> SbiResult<()> {
    log::debug!(
        "Send activating session: sess_id={}, state={}",
        sess.id,
        state
    );
    amf_sess_sbi_discover_and_send(SbiServiceType::NsmfPdusession, None, ran_ue, sess, state)
}

/// Send deactivate session request
pub fn amf_sbi_send_deactivate_session(
    ran_ue: Option<&RanUe>,
    sess: &AmfSess,
    state: i32,
    _cause_group: u8,
    _cause_value: i64,
) -> SbiResult<()> {
    log::debug!(
        "Send deactivate session: sess_id={}, state={}",
        sess.id,
        state
    );
    amf_sess_sbi_discover_and_send(SbiServiceType::NsmfPdusession, None, ran_ue, sess, state)
}

/// Send release session request
pub fn amf_sbi_send_release_session(
    ran_ue: Option<&RanUe>,
    sess: &AmfSess,
    state: i32,
) -> SbiResult<()> {
    log::debug!("Send release session: sess_id={}, state={}", sess.id, state);
    amf_sess_sbi_discover_and_send(SbiServiceType::NsmfPdusession, None, ran_ue, sess, state)
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
    redcap_indication: bool,
) -> SbiResult<SmContextCreateResponse> {
    log::info!(
        "Calling SMF SM Context Create: {smf_host}:{smf_port}, PSI={pdu_session_id}, SST={sst}, \
         DNN={dnn}, redcap={redcap_indication}"
    );

    let client = SbiClient::with_host_port(smf_host, smf_port);

    // redcapIndication propagates the UE's Reduced-Capability status to the SMF
    // (TS 29.502 SmContextCreateData) so the SMF can apply a reduced
    // session-AMBR for RedCap devices (Rel-17).
    let body = serde_json::json!({
        "pduSessionId": pdu_session_id,
        "sNssai": {
            "sst": sst,
            "sd": sd.map(|v| format!("{v:06x}"))
        },
        "dnn": dnn,
        "n1SmMsg": base64::engine::general_purpose::STANDARD.encode(n1_sm_msg_from_ue),
        "redcapIndication": redcap_indication,
        "servingNetwork": {
            "mcc": "001",
            "mnc": "01"
        }
    });

    let response = client
        .post_json("/nsmf-pdusession/v1/sm-contexts", &body)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("SMF request failed: {e}")))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "SMF returned status {}",
            response.status
        )));
    }

    let response_body: serde_json::Value = match &response.http.content {
        Some(content) => serde_json::from_str(content)
            .map_err(|e| SbiError::ResponseParseError(format!("Invalid JSON: {e}")))?,
        None => {
            return Err(SbiError::ResponseParseError(
                "Empty response body".to_string(),
            ))
        }
    };

    // Extract SM Context ref from Location header or response body
    let sm_context_ref = response
        .http
        .headers
        .get("location")
        .and_then(|loc| loc.rsplit('/').next().map(|s| s.to_string()))
        .or_else(|| {
            response_body["smContextRef"]
                .as_str()
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "1".to_string());

    // Extract N1 SM message (base64-encoded PDU Session Accept from SMF)
    let n1_sm_msg = response_body["n1SmMsg"]
        .as_str()
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .expect("value expected");

    // Extract N2 SM Information (base64-encoded UPF tunnel info from SMF)
    let n2_sm_info = response_body["n2SmInfo"]
        .as_str()
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .expect("value expected");

    log::info!(
        "SMF SM Context Created: ref={}, n1_len={}, n2_len={}",
        sm_context_ref,
        n1_sm_msg.len(),
        n2_sm_info.len()
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
        sm_context_ref,
        n2_sm_info.len()
    );

    let client = SbiClient::with_host_port(smf_host, smf_port);

    let body = serde_json::json!({
        "n2SmInfo": base64::engine::general_purpose::STANDARD.encode(n2_sm_info),
        "n2SmInfoType": "PDU_RES_SETUP_RSP"
    });

    let path = format!("/nsmf-pdusession/v1/sm-contexts/{sm_context_ref}/modify");
    let response = client
        .post_json(&path, &body)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("SMF update failed: {e}")))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "SMF update returned status {}",
            response.status
        )));
    }

    log::info!("SMF SM Context Updated: ref={sm_context_ref}");
    Ok(())
}

/// SM Context Update response from SMF (with optional N1/N2 info)
pub struct SmContextUpdateResponse {
    /// N1 SM message (NAS PDU Session Modification Command) - optional
    pub n1_sm_msg: Vec<u8>,
    /// N2 SM Information (updated QoS/tunnel info for gNB) - optional
    pub n2_sm_info: Vec<u8>,
}

/// Call SMF to update SM context with N1 SM info (UE-initiated modification)
///
/// Sends POST /nsmf-pdusession/v1/sm-contexts/{ref}/modify with N1 SM info
/// from UE's PDU Session Modification Request. Returns updated N1+N2 from SMF.
pub async fn call_smf_update_sm_context_with_n1(
    smf_host: &str,
    smf_port: u16,
    sm_context_ref: &str,
    n1_sm_msg: &[u8],
) -> SbiResult<SmContextUpdateResponse> {
    log::info!(
        "Calling SMF SM Context Update (N1): ref={}, n1_len={}",
        sm_context_ref,
        n1_sm_msg.len()
    );

    let client = SbiClient::with_host_port(smf_host, smf_port);

    let body = serde_json::json!({
        "n1SmMsg": base64::engine::general_purpose::STANDARD.encode(n1_sm_msg),
        "n2SmInfoType": "PDU_RES_MOD_REQ"
    });

    let path = format!("/nsmf-pdusession/v1/sm-contexts/{sm_context_ref}/modify");
    let response = client
        .post_json(&path, &body)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("SMF update failed: {e}")))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "SMF update returned status {}",
            response.status
        )));
    }

    let response_body: serde_json::Value = match &response.http.content {
        Some(content) => serde_json::from_str(content).unwrap_or(serde_json::json!({})),
        None => serde_json::json!({}),
    };

    let n1_sm_msg = response_body["n1SmMsg"]
        .as_str()
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .expect("value expected");

    let n2_sm_info = response_body["n2SmInfo"]
        .as_str()
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .expect("value expected");

    log::info!(
        "SMF SM Context Updated (N1): ref={sm_context_ref}, n1_len={}, n2_len={}",
        n1_sm_msg.len(),
        n2_sm_info.len()
    );

    Ok(SmContextUpdateResponse {
        n1_sm_msg,
        n2_sm_info,
    })
}

/// Release an SM context via SMF SBI
///
/// Sends POST /nsmf-pdusession/v1/sm-contexts/{ref}/release to SMF,
/// which triggers PFCP Session Deletion to UPF.
pub async fn call_smf_release_sm_context(
    smf_host: &str,
    smf_port: u16,
    sm_context_ref: &str,
) -> SbiResult<()> {
    log::info!("Calling SMF SM Context Release: ref={sm_context_ref}");

    let client = SbiClient::with_host_port(smf_host, smf_port);

    let body = serde_json::json!({
        "cause": "REL_DUE_TO_UE_REQUEST"
    });

    let path = format!("/nsmf-pdusession/v1/sm-contexts/{sm_context_ref}/release");
    let response = client
        .post_json(&path, &body)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("SMF release failed: {e}")))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "SMF release returned status {}",
            response.status
        )));
    }

    log::info!("SMF SM Context Released: ref={sm_context_ref}");
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
    call_ausf_authenticate_with_resync(ausf_host, ausf_port, suci, serving_network_name, None).await
}

/// Call AUSF to authenticate UE with optional resynchronization info
/// (POST /nausf-auth/v1/ue-authentications with resynchronizationInfo,
/// TS 29.509 Section 5.2.2.2.2 / TS 24.501 Section 5.4.1.3.7 case e: SQN failure).
///
/// `resync` carries (RAND, AUTS) from the UE's Authentication Failure
/// (cause #21 "synch failure", Authentication failure parameter IE).
pub async fn call_ausf_authenticate_with_resync(
    ausf_host: &str,
    ausf_port: u16,
    suci: &str,
    serving_network_name: &str,
    resync: Option<([u8; 16], [u8; 14])>,
) -> SbiResult<AusfAuthResponse> {
    log::info!(
        "Calling AUSF authenticate: {ausf_host}:{ausf_port}, SUCI={suci}, SNN={serving_network_name}, resync={}",
        resync.is_some()
    );

    let client = SbiClient::with_host_port(ausf_host, ausf_port);

    let mut body = serde_json::json!({
        "supiOrSuci": suci,
        "servingNetworkName": serving_network_name
    });
    if let Some((rand, auts)) = resync {
        body["resynchronizationInfo"] = serde_json::json!({
            "rand": hex::encode(rand),
            "auts": hex::encode(auts),
        });
    }

    let response = client
        .post_json("/nausf-auth/v1/ue-authentications", &body)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("AUSF request failed: {e}")))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "AUSF returned status {}",
            response.status
        )));
    }

    let response_body: serde_json::Value = match &response.http.content {
        Some(content) => serde_json::from_str(content)
            .map_err(|e| SbiError::ResponseParseError(format!("Invalid JSON: {e}")))?,
        None => {
            return Err(SbiError::ResponseParseError(
                "Empty response body".to_string(),
            ))
        }
    };

    // Extract auth data
    let auth_data = &response_body["5gAuthData"];

    let rand = hex_to_16bytes(auth_data["rand"].as_str().unwrap_or(""))
        .map_err(|e| SbiError::ResponseParseError(format!("Invalid RAND: {e}")))?;
    let autn = hex_to_16bytes(auth_data["autn"].as_str().unwrap_or(""))
        .map_err(|e| SbiError::ResponseParseError(format!("Invalid AUTN: {e}")))?;
    let hxres_star = hex_to_16bytes(auth_data["hxresStar"].as_str().unwrap_or(""))
        .map_err(|e| SbiError::ResponseParseError(format!("Invalid HXRES*: {e}")))?;

    // Extract auth context ID from Location header
    let auth_ctx_id = response
        .http
        .headers
        .get("location")
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
        auth_ctx_id,
        hex::encode(&res_star[..4])
    );

    let client = SbiClient::with_host_port(ausf_host, ausf_port);

    let body = serde_json::json!({
        "resStar": hex::encode(res_star)
    });

    let path = format!("/nausf-auth/v1/ue-authentications/{auth_ctx_id}/5g-aka-confirmation");
    let response = client
        .put_json(&path, &body)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("AUSF confirmation failed: {e}")))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "AUSF confirmation returned status {}",
            response.status
        )));
    }

    let response_body: serde_json::Value = match &response.http.content {
        Some(content) => serde_json::from_str(content)
            .map_err(|e| SbiError::ResponseParseError(format!("Invalid JSON: {e}")))?,
        None => {
            return Err(SbiError::ResponseParseError(
                "Empty response body".to_string(),
            ))
        }
    };

    let auth_result = response_body["authResult"]
        .as_str()
        .unwrap_or("UNKNOWN")
        .to_string();

    let kseaf_hex = response_body["kseaf"].as_str().unwrap_or("");
    let kseaf_bytes = hex::decode(kseaf_hex)
        .map_err(|e| SbiError::ResponseParseError(format!("Invalid KSEAF: {e}")))?;
    let mut kseaf = [0u8; 32];
    if kseaf_bytes.len() >= 32 {
        kseaf.copy_from_slice(&kseaf_bytes[..32]);
    }

    let supi = response_body["supi"].as_str().map(|s| s.to_string());

    log::info!("AUSF 5G-AKA confirmation: result={auth_result}, supi={supi:?}");

    Ok(AusfConfirmResponse {
        auth_result,
        kseaf,
        supi,
    })
}

// ============================================================================
// UDM / PCF SBI Client Functions (registration procedure, TS 23.502 4.2.2.2.2)
// ============================================================================

/// Async NF endpoint resolution: SbiContext discovery cache first, env fallback.
///
/// Unlike `resolve_nf_endpoint`, this is safe to call from async context
/// (no `Handle::block_on`).
pub async fn resolve_nf_endpoint_async(service_type: SbiServiceType) -> SbiResult<(String, u16)> {
    let (ogs_service_type, env_addr, env_port, default_port) = match service_type {
        SbiServiceType::NausfAuth => (
            ogs_sbi::types::SbiServiceType::NausfAuth,
            "AUSF_SBI_ADDR",
            "AUSF_SBI_PORT",
            7777u16,
        ),
        SbiServiceType::NudmUecm => (
            ogs_sbi::types::SbiServiceType::NudmUecm,
            "UDM_SBI_ADDR",
            "UDM_SBI_PORT",
            7777,
        ),
        SbiServiceType::NudmSdm => (
            ogs_sbi::types::SbiServiceType::NudmSdm,
            "UDM_SBI_ADDR",
            "UDM_SBI_PORT",
            7777,
        ),
        SbiServiceType::NsmfPdusession => (
            ogs_sbi::types::SbiServiceType::NsmfPdusession,
            "SMF_SBI_ADDR",
            "SMF_SBI_PORT",
            7777,
        ),
        SbiServiceType::NnssfNsselection => (
            ogs_sbi::types::SbiServiceType::NnssfNsselection,
            "NSSF_SBI_ADDR",
            "NSSF_SBI_PORT",
            7777,
        ),
        SbiServiceType::NpcfAmPolicyControl => (
            ogs_sbi::types::SbiServiceType::NpcfAmPolicyControl,
            "PCF_SBI_ADDR",
            "PCF_SBI_PORT",
            7777,
        ),
        SbiServiceType::NnsacfNsac => (
            ogs_sbi::types::SbiServiceType::NnsacfNsac,
            "NSACF_SBI_ADDR",
            "NSACF_SBI_PORT",
            7777,
        ),
        _ => return Err(SbiError::ServiceNotFound(format!("{service_type:?}"))),
    };

    let sbi_ctx = global_context();
    let instances = sbi_ctx.find_nf_instances_by_service(ogs_service_type).await;
    if let Some(inst) = instances.first() {
        if let Some(svc) = inst.find_service(ogs_service_type) {
            let host = svc
                .ip_addresses
                .first()
                .or(inst.ipv4_addresses.first())
                .or(svc.fqdn.as_ref())
                .or(inst.fqdn.as_ref());
            if let Some(h) = host {
                return Ok((h.clone(), svc.port));
            }
        }
    }

    let host = std::env::var(env_addr).map_err(|_| SbiError::NfInstanceNotFound)?;
    let port = std::env::var(env_port)
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(default_port);
    Ok((host, port))
}

/// Nudm_UECM_Registration (amf3gpp-access):
/// PUT /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access (TS 29.503 5.3.2.2.2)
pub async fn call_udm_uecm_registration(
    udm_host: &str,
    udm_port: u16,
    supi: &str,
    amf_instance_id: &str,
    guami_plmn_mcc: &str,
    guami_plmn_mnc: &str,
    amf_id_hex: &str,
) -> SbiResult<()> {
    let client = SbiClient::with_host_port(udm_host, udm_port);

    let body = serde_json::json!({
        "amfInstanceId": amf_instance_id,
        "deregCallbackUri": format!("/namf-callback/v1/{supi}/dereg-notify"),
        "guami": {
            "plmnId": { "mcc": guami_plmn_mcc, "mnc": guami_plmn_mnc },
            "amfId": amf_id_hex,
        },
        "ratType": "NR"
    });

    let path = format!("/nudm-uecm/v1/{supi}/registrations/amf-3gpp-access");
    let response = client
        .put_json(&path, &body)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("UECM registration failed: {e}")))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "UECM registration returned status {}",
            response.status
        )));
    }
    log::info!("[{supi}] Nudm_UECM_Registration (amf-3gpp-access) OK");
    Ok(())
}

/// Subscribed AM data returned by Nudm_SDM_Get (am-data)
#[derive(Debug, Clone, Default)]
pub struct AmDataResponse {
    /// Subscribed UE-AMBR uplink (e.g. "1 Gbps") if present
    pub ue_ambr_uplink: Option<String>,
    /// Subscribed UE-AMBR downlink if present
    pub ue_ambr_downlink: Option<String>,
    /// Subscribed S-NSSAIs (SST, optional SD)
    pub nssai: Vec<(u8, Option<u32>)>,
}

/// Nudm_SDM_Get (am-data): GET /nudm-sdm/v1/{supi}/am-data (TS 29.503 5.2.2.2.1)
pub async fn call_udm_sdm_get_am_data(
    udm_host: &str,
    udm_port: u16,
    supi: &str,
) -> SbiResult<AmDataResponse> {
    let client = SbiClient::with_host_port(udm_host, udm_port);
    let path = format!("/nudm-sdm/v1/{supi}/am-data");
    let response = client
        .get(&path)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("SDM am-data failed: {e}")))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "SDM am-data returned status {}",
            response.status
        )));
    }

    let mut out = AmDataResponse::default();
    if let Some(content) = &response.http.content {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
            out.ue_ambr_uplink = json["subscribedUeAmbr"]["uplink"]
                .as_str()
                .map(String::from);
            out.ue_ambr_downlink = json["subscribedUeAmbr"]["downlink"]
                .as_str()
                .map(String::from);
            if let Some(list) = json["nssai"]["defaultSingleNssais"].as_array() {
                for s in list {
                    if let Some(sst) = s["sst"].as_u64() {
                        let sd = s["sd"]
                            .as_str()
                            .and_then(|h| u32::from_str_radix(h, 16).ok());
                        out.nssai.push((sst as u8, sd));
                    }
                }
            }
        }
    }
    log::info!(
        "[{supi}] Nudm_SDM_Get am-data OK ({} S-NSSAI)",
        out.nssai.len()
    );
    Ok(out)
}

/// Nudm_SDM_Subscribe: POST /nudm-sdm/v1/{supi}/sdm-subscriptions (TS 29.503 5.2.2.3.2)
///
/// Returns the subscription ID assigned by UDM.
pub async fn call_udm_sdm_subscribe(
    udm_host: &str,
    udm_port: u16,
    supi: &str,
    amf_instance_id: &str,
) -> SbiResult<String> {
    let client = SbiClient::with_host_port(udm_host, udm_port);

    let body = serde_json::json!({
        "nfInstanceId": amf_instance_id,
        "callbackReference": format!("/namf-callback/v1/{supi}/sdmsubscription-notify"),
        "monitoredResourceUris": [format!("/nudm-sdm/v1/{supi}/am-data")],
        "implicitUnsubscribe": true
    });

    let path = format!("/nudm-sdm/v1/{supi}/sdm-subscriptions");
    let response = client
        .post_json(&path, &body)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("SDM subscribe failed: {e}")))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "SDM subscribe returned status {}",
            response.status
        )));
    }

    let sub_id = response
        .http
        .headers
        .get("location")
        .and_then(|loc| loc.rsplit('/').next().map(String::from))
        .or_else(|| {
            response.http.content.as_ref().and_then(|c| {
                serde_json::from_str::<serde_json::Value>(c)
                    .ok()
                    .and_then(|j| j["subscriptionId"].as_str().map(String::from))
            })
        })
        .unwrap_or_else(|| "1".to_string());

    log::info!("[{supi}] Nudm_SDM_Subscribe OK (subscriptionId={sub_id})");
    Ok(sub_id)
}

/// Npcf_AMPolicyControl_Create: POST /npcf-am-policy-control/v1/policies
/// (TS 29.507 4.2.2.2). Returns the policy association ID.
pub async fn call_pcf_am_policy_create(
    pcf_host: &str,
    pcf_port: u16,
    supi: &str,
    serving_plmn_mcc: &str,
    serving_plmn_mnc: &str,
) -> SbiResult<String> {
    let client = SbiClient::with_host_port(pcf_host, pcf_port);

    let body = serde_json::json!({
        "notificationUri": format!("/namf-callback/v1/{supi}/am-policy-notify"),
        "supi": supi,
        "servingPlmn": { "mcc": serving_plmn_mcc, "mnc": serving_plmn_mnc },
        "suppFeat": ""
    });

    let response = client
        .post_json("/npcf-am-policy-control/v1/policies", &body)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("AM policy create failed: {e}")))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "AM policy create returned status {}",
            response.status
        )));
    }

    let assoc_id = response
        .http
        .headers
        .get("location")
        .and_then(|loc| loc.rsplit('/').next().map(String::from))
        .or_else(|| {
            response.http.content.as_ref().and_then(|c| {
                serde_json::from_str::<serde_json::Value>(c)
                    .ok()
                    .and_then(|j| j["polAssoId"].as_str().map(String::from))
            })
        })
        .unwrap_or_else(|| "1".to_string());

    log::info!("[{supi}] Npcf_AMPolicyControl_Create OK (polAssoId={assoc_id})");
    Ok(assoc_id)
}

/// Result of an Nnsacf UE-admission query (TS 29.536 UeACResponseData).
#[derive(Debug, Clone)]
pub struct NsacfUeAdmissionResult {
    /// Whether the UE was admitted for the requested S-NSSAI.
    pub admitted: bool,
    /// Configured maximum number of UEs for the slice (informational).
    pub max_num_ues: Option<u64>,
}

/// Nnsacf_NSAC UE-admission query (TS 29.536 Section 5.2.2.2 / 6.1).
///
/// POST {apiRoot}/nnsacf-nsac/v1/slices/ues with UeACRequestData. The NSACF
/// returns HTTP 200 with `UeACResponseData { admittedFlag, maxNumUEs? }` for
/// BOTH admit and reject decisions — over-limit is signalled by
/// `admittedFlag=false`, never by a non-2xx status. `update_flag=true` requests
/// the NSACF to enforce (increase) the per-slice UE count.
pub async fn call_nsacf_ue_admission(
    nsacf_host: &str,
    nsacf_port: u16,
    nf_id: &str,
    snssai_sst: u8,
    snssai_sd: Option<u32>,
    access_type: &str,
    update_flag: bool,
) -> SbiResult<NsacfUeAdmissionResult> {
    let client = SbiClient::with_host_port(nsacf_host, nsacf_port);

    let mut snssai = serde_json::json!({ "sst": snssai_sst });
    if let Some(sd) = snssai_sd {
        snssai["sd"] = serde_json::Value::String(format!("{sd:06X}"));
    }

    let body = serde_json::json!({
        "snssai": snssai,
        "nfId": nf_id,
        "updateFlag": update_flag,
        "updateList": [ { "accessType": access_type } ],
    });

    let response = client
        .post_json("/nnsacf-nsac/v1/slices/ues", &body)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("NSACF UE admission failed: {e}")))?;

    // The NSACF answers admit AND reject with HTTP 200; only a transport/other
    // status is a hard error.
    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "NSACF UE admission returned status {}",
            response.status
        )));
    }

    let json: serde_json::Value = response
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str(c).ok())
        .ok_or_else(|| {
            SbiError::RequestFailed("NSACF UE admission: empty/invalid body".to_string())
        })?;

    let result = parse_nsacf_ue_admission_response(&json);
    log::info!(
        "Nnsacf UE admission (SST={snssai_sst}, SD={snssai_sd:?}): admittedFlag={}, maxNumUEs={:?}",
        result.admitted,
        result.max_num_ues
    );
    Ok(result)
}

/// Parse a UeACResponseData body (TS 29.536). `admittedFlag` absent or false
/// means the UE is NOT admitted (default deny).
fn parse_nsacf_ue_admission_response(json: &serde_json::Value) -> NsacfUeAdmissionResult {
    NsacfUeAdmissionResult {
        admitted: json["admittedFlag"].as_bool().unwrap_or(false),
        max_num_ues: json["maxNumUEs"].as_u64(),
    }
}

/// Nudm_UECM_DeregistrationNotification cleanup: PATCH purge on deregistration
/// (TS 29.503 5.3.2.4: AMF sets purgeFlag when the UE deregisters).
pub async fn call_udm_uecm_deregistration(
    udm_host: &str,
    udm_port: u16,
    supi: &str,
) -> SbiResult<()> {
    let client = SbiClient::with_host_port(udm_host, udm_port);

    let body = serde_json::json!({ "purgeFlag": true });
    let path = format!("/nudm-uecm/v1/{supi}/registrations/amf-3gpp-access");
    let response = client
        .patch_json(&path, &body)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("UECM deregistration failed: {e}")))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "UECM deregistration returned status {}",
            response.status
        )));
    }
    log::info!("[{supi}] Nudm_UECM amf-3gpp-access purge OK");
    Ok(())
}

/// Helper: convert hex string to [u8; 16]
fn hex_to_16bytes(hex_str: &str) -> Result<[u8; 16], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("hex decode: {e}"))?;
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
        assert_eq!(
            SbiServiceType::NsmfPdusession.service_name(),
            "nsmf-pdusession"
        );
    }

    #[test]
    fn test_nsacf_service_name() {
        assert_eq!(SbiServiceType::NnsacfNsac.service_name(), "nnsacf-nsac");
    }

    #[test]
    fn test_nsacf_admission_response_parse() {
        // admittedFlag=true -> admitted; registration proceeds.
        let granted = serde_json::json!({
            "snssai": { "sst": 1 },
            "admittedFlag": true,
            "maxNumUEs": 1000
        });
        let r = parse_nsacf_ue_admission_response(&granted);
        assert!(r.admitted);
        assert_eq!(r.max_num_ues, Some(1000));

        // admittedFlag=false (HTTP 200, over-limit) -> rejected.
        let denied = serde_json::json!({
            "snssai": { "sst": 1 },
            "admittedFlag": false
        });
        assert!(!parse_nsacf_ue_admission_response(&denied).admitted);

        // Missing admittedFlag -> default deny.
        let empty = serde_json::json!({ "snssai": { "sst": 1 } });
        assert!(!parse_nsacf_ue_admission_response(&empty).admitted);
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_amf_sbi_open_close() {
        assert!(amf_sbi_open().is_ok());
        amf_sbi_close();
    }
}
