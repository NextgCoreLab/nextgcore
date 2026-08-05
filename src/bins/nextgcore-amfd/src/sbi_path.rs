//! AMF SBI Path Functions
//!
//! Port of src/amf/sbi-path.c - SBI service discovery and message routing

use base64::Engine;
use nextgcore_sbi::client::SbiClient;
use nextgcore_sbi::constants::content_type;
use nextgcore_sbi::context::{global_context, NfInstance, NfService};
use nextgcore_sbi::message::{SbiPart, SbiRequest, SbiResponse};

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

    let mut nf_instance = NfInstance::new(&nf_instance_id, nextgcore_sbi::types::NfType::Amf);
    nf_instance.ipv4_addresses.push(sbi_addr.clone());

    // Register Namf services: namf-comm, namf-evts, namf-mt, namf-loc
    let mut comm_service =
        NfService::new("namf-comm", nextgcore_sbi::types::SbiServiceType::NamfComm);
    comm_service.versions = vec!["v1".to_string()];
    comm_service.port = sbi_port;
    comm_service.ip_addresses.push(sbi_addr.clone());
    nf_instance.add_service(comm_service);

    let mut evts_service =
        NfService::new("namf-evts", nextgcore_sbi::types::SbiServiceType::NamfEvts);
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
            let mut self_instance =
                NfInstance::new(&nf_instance_id, nextgcore_sbi::types::NfType::Amf);
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc =
                NfService::new("namf-comm", nextgcore_sbi::types::SbiServiceType::NamfComm);
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
                "AUSF" => nextgcore_sbi::types::NfType::Ausf,
                "UDM" => nextgcore_sbi::types::NfType::Udm,
                "SMF" => nextgcore_sbi::types::NfType::Smf,
                "PCF" => nextgcore_sbi::types::NfType::Pcf,
                "NSSF" => nextgcore_sbi::types::NfType::Nssf,
                "NRF" => nextgcore_sbi::types::NfType::Nrf,
                // NSAC (TS 23.501 §5.15.11): without this arm a discovered
                // NSACF profile was silently DROPPED here, so UE admission
                // always fell back to degrade-open.
                "NSACF" => nextgcore_sbi::types::NfType::Nsacf,
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
                    if let Some(svc_type) =
                        nextgcore_sbi::types::SbiServiceType::from_name(svc_name)
                    {
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
    // HTTP/2 request transmission handled by nextgcore_sbi client module
    Ok(())
}

/// Discover NF endpoint for the given service type using SbiContext cache + env var fallback
fn resolve_nf_endpoint(service_type: SbiServiceType) -> SbiResult<(String, u16)> {
    // Map AMF SbiServiceType to nextgcore_sbi SbiServiceType and env var names
    let (nextgcore_service_type, env_addr, env_port, default_port) = match service_type {
        SbiServiceType::NausfAuth => (
            nextgcore_sbi::types::SbiServiceType::NausfAuth,
            "AUSF_SBI_ADDR",
            "AUSF_SBI_PORT",
            7777u16,
        ),
        SbiServiceType::NudmUecm => (
            nextgcore_sbi::types::SbiServiceType::NudmUecm,
            "UDM_SBI_ADDR",
            "UDM_SBI_PORT",
            7777,
        ),
        SbiServiceType::NudmSdm => (
            nextgcore_sbi::types::SbiServiceType::NudmSdm,
            "UDM_SBI_ADDR",
            "UDM_SBI_PORT",
            7777,
        ),
        SbiServiceType::NsmfPdusession => (
            nextgcore_sbi::types::SbiServiceType::NsmfPdusession,
            "SMF_SBI_ADDR",
            "SMF_SBI_PORT",
            7777,
        ),
        SbiServiceType::NnssfNsselection => (
            nextgcore_sbi::types::SbiServiceType::NnssfNsselection,
            "NSSF_SBI_ADDR",
            "NSSF_SBI_PORT",
            7777,
        ),
        SbiServiceType::NpcfAmPolicyControl => (
            nextgcore_sbi::types::SbiServiceType::NpcfAmPolicyControl,
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
        let svc_type = nextgcore_service_type;
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

/// Extract an N1/N2 binary payload referenced from the JSON root of an SMF
/// response, accepting BOTH the conformant multipart/related form and the
/// legacy base64-in-JSON form.
///
/// Per TS 29.502 §6.1.2.2.2 / §6.1.2.4 the JSON attribute is a RefToBinaryData
/// pointer (`{ "contentId": "<id>" }`) whose bytes live in the multipart binary
/// part with the matching `Content-Id` (decoded by `SbiClient` into
/// `response.http.parts`). When no matching part is present the attribute is
/// read as a base64 string, so a legacy SMF still interoperates.
fn extract_binary_ref(
    response: &SbiResponse,
    root: &serde_json::Value,
    field: &str,
) -> Option<Vec<u8>> {
    let attr = &root[field];
    if let Some(content_id) = attr["contentId"].as_str() {
        if let Some(part) = response
            .http
            .parts
            .iter()
            .find(|p| p.content_id.as_deref() == Some(content_id))
        {
            return Some(part.data.to_vec());
        }
    }
    if let Some(b64) = attr.as_str() {
        return base64::engine::general_purpose::STANDARD.decode(b64).ok();
    }
    None
}

/// Build the multipart/related `Nsmf_PDUSession_CreateSMContext` request: the
/// JSON root carries the SmContextCreateData with the N1 container as a
/// RefToBinaryData pointer, and the UE's PDU Session Establishment Request
/// travels as a 5gnas binary part (TS 29.502 §6.1.2.2.2). The `SbiClient`
/// serializes the attached part into the multipart/related body.
fn build_create_sm_context_request(
    pdu_session_id: u8,
    sst: u8,
    sd: Option<u32>,
    dnn: &str,
    n1_sm_msg_from_ue: &[u8],
    redcap_indication: bool,
) -> SbiRequest {
    let body = serde_json::json!({
        "pduSessionId": pdu_session_id,
        "sNssai": {
            "sst": sst,
            "sd": sd.map(|v| format!("{v:06x}"))
        },
        "dnn": dnn,
        "n1SmMsg": { "contentId": "n1SmMsg" },
        "redcapIndication": redcap_indication,
        "servingNetwork": {
            "mcc": "001",
            "mnc": "01"
        }
    });
    SbiRequest::post("/nsmf-pdusession/v1/sm-contexts")
        .with_body(body.to_string(), content_type::APPLICATION_JSON)
        .with_part(SbiPart::with_content(
            "n1SmMsg",
            content_type::APPLICATION_5GNAS,
            bytes::Bytes::copy_from_slice(n1_sm_msg_from_ue),
        ))
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

    let client = crate::attach_oauth2(
        SbiClient::with_host_port(smf_host, smf_port),
        nextgcore_sbi::types::NfType::Smf,
    );

    // redcapIndication propagates the UE's Reduced-Capability status to the SMF
    // (TS 29.502 SmContextCreateData) so the SMF can apply a reduced
    // session-AMBR for RedCap devices (Rel-17). The N1 container is sent as a
    // multipart/related 5gnas binary part (smfd-01).
    let request = build_create_sm_context_request(
        pdu_session_id,
        sst,
        sd,
        dnn,
        n1_sm_msg_from_ue,
        redcap_indication,
    );

    let response = client
        .send_request(request)
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

    // Extract N1 SM message (PDU Session Accept) and N2 SM Information (UPF
    // tunnel info) from the SMF response: multipart 5gnas/ngap binary parts
    // (smfd-01) or, from a legacy SMF, base64-in-JSON. `extract_binary_ref`
    // accepts both.
    let n1_sm_msg = extract_binary_ref(&response, &response_body, "n1SmMsg")
        .ok_or_else(|| SbiError::ResponseParseError("SMF response missing n1SmMsg".to_string()))?;

    let n2_sm_info = extract_binary_ref(&response, &response_body, "n2SmInfo")
        .ok_or_else(|| SbiError::ResponseParseError("SMF response missing n2SmInfo".to_string()))?;

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

    let client = crate::attach_oauth2(
        SbiClient::with_host_port(smf_host, smf_port),
        nextgcore_sbi::types::NfType::Smf,
    );

    // N2 SM transfer (gNB DL F-TEID) carried as a multipart/related ngap binary
    // part referenced by RefToBinaryData (smfd-02).
    let body = serde_json::json!({
        "n2SmInfo": { "contentId": "n2SmInfo" },
        "n2SmInfoType": "PDU_RES_SETUP_RSP"
    });

    let path = format!("/nsmf-pdusession/v1/sm-contexts/{sm_context_ref}/modify");
    let request = SbiRequest::post(&path)
        .with_body(body.to_string(), content_type::APPLICATION_JSON)
        .with_part(SbiPart::with_content(
            "n2SmInfo",
            content_type::APPLICATION_NGAP,
            bytes::Bytes::copy_from_slice(n2_sm_info),
        ));
    let response = client
        .send_request(request)
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

    let client = crate::attach_oauth2(
        SbiClient::with_host_port(smf_host, smf_port),
        nextgcore_sbi::types::NfType::Smf,
    );

    // UE-initiated modification: the UE's N1 container is carried as a
    // multipart/related 5gnas binary part referenced by RefToBinaryData
    // (smfd-02).
    let body = serde_json::json!({
        "n1SmMsg": { "contentId": "n1SmMsg" },
        "n2SmInfoType": "PDU_RES_MOD_REQ"
    });

    let path = format!("/nsmf-pdusession/v1/sm-contexts/{sm_context_ref}/modify");
    let request = SbiRequest::post(&path)
        .with_body(body.to_string(), content_type::APPLICATION_JSON)
        .with_part(SbiPart::with_content(
            "n1SmMsg",
            content_type::APPLICATION_5GNAS,
            bytes::Bytes::copy_from_slice(n1_sm_msg),
        ));
    let response = client
        .send_request(request)
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

    // N1 (PDU Session Modification Command) + N2 (QoS flow mod) from the SMF:
    // multipart binary parts or legacy base64-in-JSON.
    let n1_sm_msg = extract_binary_ref(&response, &response_body, "n1SmMsg").unwrap_or_default();
    let n2_sm_info = extract_binary_ref(&response, &response_body, "n2SmInfo").unwrap_or_default();

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

    let client = crate::attach_oauth2(
        SbiClient::with_host_port(smf_host, smf_port),
        nextgcore_sbi::types::NfType::Smf,
    );

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

    let client = crate::attach_oauth2(
        SbiClient::with_host_port(ausf_host, ausf_port),
        nextgcore_sbi::types::NfType::Ausf,
    );

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

    let client = crate::attach_oauth2(
        SbiClient::with_host_port(ausf_host, ausf_port),
        nextgcore_sbi::types::NfType::Ausf,
    );

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
    let (nextgcore_service_type, env_addr, env_port, default_port) = match service_type {
        SbiServiceType::NausfAuth => (
            nextgcore_sbi::types::SbiServiceType::NausfAuth,
            "AUSF_SBI_ADDR",
            "AUSF_SBI_PORT",
            7777u16,
        ),
        SbiServiceType::NudmUecm => (
            nextgcore_sbi::types::SbiServiceType::NudmUecm,
            "UDM_SBI_ADDR",
            "UDM_SBI_PORT",
            7777,
        ),
        SbiServiceType::NudmSdm => (
            nextgcore_sbi::types::SbiServiceType::NudmSdm,
            "UDM_SBI_ADDR",
            "UDM_SBI_PORT",
            7777,
        ),
        SbiServiceType::NsmfPdusession => (
            nextgcore_sbi::types::SbiServiceType::NsmfPdusession,
            "SMF_SBI_ADDR",
            "SMF_SBI_PORT",
            7777,
        ),
        SbiServiceType::NnssfNsselection => (
            nextgcore_sbi::types::SbiServiceType::NnssfNsselection,
            "NSSF_SBI_ADDR",
            "NSSF_SBI_PORT",
            7777,
        ),
        SbiServiceType::NpcfAmPolicyControl => (
            nextgcore_sbi::types::SbiServiceType::NpcfAmPolicyControl,
            "PCF_SBI_ADDR",
            "PCF_SBI_PORT",
            7777,
        ),
        SbiServiceType::NnsacfNsac => (
            nextgcore_sbi::types::SbiServiceType::NnsacfNsac,
            "NSACF_SBI_ADDR",
            "NSACF_SBI_PORT",
            7777,
        ),
        _ => return Err(SbiError::ServiceNotFound(format!("{service_type:?}"))),
    };

    let sbi_ctx = global_context();
    let endpoint_from_cache = |instances: Vec<NfInstance>| {
        let inst = instances.first()?;
        let svc = inst.find_service(nextgcore_service_type)?;
        let host = svc
            .ip_addresses
            .first()
            .or(inst.ipv4_addresses.first())
            .or(svc.fqdn.as_ref())
            .or(inst.fqdn.as_ref())?;
        Some((host.clone(), svc.port))
    };

    let instances = sbi_ctx
        .find_nf_instances_by_service(nextgcore_service_type)
        .await;
    if let Some(ep) = endpoint_from_cache(instances) {
        return Ok(ep);
    }

    // Cache miss: perform on-demand NRF discovery (TS 29.510 §5.3.2) for this
    // exact service and re-check. Without this, an NF that registered with the
    // NRF after this AMF populated its cache (e.g. the NSACF) was never found
    // and the resolver silently fell back to env/localhost — which is how
    // slice admission control ended up permanently degrade-open in the E2E.
    let target_nf_type = match service_type {
        SbiServiceType::NausfAuth => "AUSF",
        SbiServiceType::NudmUecm | SbiServiceType::NudmSdm => "UDM",
        SbiServiceType::NsmfPdusession => "SMF",
        SbiServiceType::NnssfNsselection => "NSSF",
        SbiServiceType::NpcfAmPolicyControl => "PCF",
        SbiServiceType::NnsacfNsac => "NSACF",
        _ => "",
    };
    if !target_nf_type.is_empty()
        && amf_nrf_discover(target_nf_type, service_type.service_name())
            .await
            .is_ok()
    {
        let instances = sbi_ctx
            .find_nf_instances_by_service(nextgcore_service_type)
            .await;
        if let Some(ep) = endpoint_from_cache(instances) {
            return Ok(ep);
        }
    }

    let host = std::env::var(env_addr).map_err(|_| SbiError::NfInstanceNotFound)?;
    let port = std::env::var(env_port)
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(default_port);
    Ok((host, port))
}

/// Base URL (`http://{advertised_sbi_addr}:{port}`) the AMF advertises for its
/// own SBI server — the same address/port `run()` binds the Namf HTTP/2 server
/// to and the NRF NFProfile advertises (env `AMF_SBI_ADDR`/`AMF_SBI_PORT`,
/// defaults `127.0.0.1:7777`, matching [`amf_sbi_open`]).
///
/// WSB-4: callback URIs the AMF registers with peers (e.g. the Nudm_UECM
/// `deregCallbackUri`, TS 29.503 §5.3.2.2.2) MUST be absolute so the peer can
/// POST to them — a relative URI is rejected by udmd's `parse_callback_uri`,
/// which is exactly what broke the network-initiated deregistration round trip.
/// Shared helper for every amfd inbound SBI callback (dereg-notify, and the
/// still-unserved am-policy-notify / sdmsubscription-notify — WS-A reuses this).
pub fn advertised_sbi_base() -> String {
    let addr = std::env::var("AMF_SBI_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("AMF_SBI_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7777);
    format!("http://{addr}:{port}")
}

/// The absolute Nudm_UECM `deregCallbackUri` the AMF registers for `supi`
/// (WSB-4, TS 29.503 §5.3.2.3.2). Routed by `namf_server` at
/// `POST /namf-callback/v1/{supi}/dereg-notify`.
pub fn dereg_callback_uri(supi: &str) -> String {
    format!(
        "{}/namf-callback/v1/{supi}/dereg-notify",
        advertised_sbi_base()
    )
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
    let client = crate::attach_oauth2(
        SbiClient::with_host_port(udm_host, udm_port),
        nextgcore_sbi::types::NfType::Udm,
    );

    let body = serde_json::json!({
        "amfInstanceId": amf_instance_id,
        // WSB-4: absolute URI (was relative) so udmd can POST the
        // DeregistrationNotification back (TS 29.503 §5.3.2.3.2).
        "deregCallbackUri": dereg_callback_uri(supi),
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

/// Nudm_SDM_Get (am-data): GET /nudm-sdm/v2/{supi}/am-data (TS 29.503 5.2.2.2.1)
///
/// Nudm_SDM is at v2 per TS 29.503 6.1.1, unlike the other Nudm services which
/// are v1. This consumer emitted v1 against a UDM that advertised v1, so the
/// pair agreed with each other and disagreed with the spec.
pub async fn call_udm_sdm_get_am_data(
    udm_host: &str,
    udm_port: u16,
    supi: &str,
) -> SbiResult<AmDataResponse> {
    let client = crate::attach_oauth2(
        SbiClient::with_host_port(udm_host, udm_port),
        nextgcore_sbi::types::NfType::Udm,
    );
    let path = format!("/nudm-sdm/v2/{supi}/am-data");
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

/// Nudm_SDM_Subscribe: POST /nudm-sdm/v2/{supi}/sdm-subscriptions (TS 29.503 5.2.2.3.2)
///
/// Returns the subscription ID assigned by UDM.
pub async fn call_udm_sdm_subscribe(
    udm_host: &str,
    udm_port: u16,
    supi: &str,
    amf_instance_id: &str,
) -> SbiResult<String> {
    let client = crate::attach_oauth2(
        SbiClient::with_host_port(udm_host, udm_port),
        nextgcore_sbi::types::NfType::Udm,
    );

    let body = serde_json::json!({
        "nfInstanceId": amf_instance_id,
        "callbackReference": format!("/namf-callback/v1/{supi}/sdmsubscription-notify"),
        "monitoredResourceUris": [format!("/nudm-sdm/v2/{supi}/am-data")],
        "implicitUnsubscribe": true
    });

    let path = format!("/nudm-sdm/v2/{supi}/sdm-subscriptions");
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
    let client = crate::attach_oauth2(
        SbiClient::with_host_port(pcf_host, pcf_port),
        nextgcore_sbi::types::NfType::Pcf,
    );

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

/// Wave-6 E7 kill-switch for the UE Policy Association at registration:
/// `AMF_UE_POLICY_ASSOC=off` (also `0`/`false`, case-insensitive) restores
/// the pre-E7 registration byte-flow (no Npcf_UEPolicyControl create/delete).
/// Default (unset or any other value) is enabled.
pub fn ue_policy_assoc_enabled() -> bool {
    ue_policy_assoc_enabled_value(std::env::var("AMF_UE_POLICY_ASSOC").ok().as_deref())
}

/// Pure classifier behind [`ue_policy_assoc_enabled`] (env-free for tests).
fn ue_policy_assoc_enabled_value(value: Option<&str>) -> bool {
    !matches!(
        value.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("off") | Some("0") | Some("false")
    )
}

/// Npcf_UEPolicyControl_Create: POST /npcf-ue-policy-control/v1/policies
/// (TS 29.525 §4.2.2 — the AMF is the NF service consumer creating the UE
/// Policy Association at registration; Wave-6 E7). The body is a
/// PolicyAssociationRequest (TS29525_Npcf_UEPolicyControl.yaml:381-461):
/// `notificationUri`/`supi`/`suppFeat` (the members pcfd validates as
/// mandatory) plus the `servingPlmn` and `guami` optionals so the PCF can
/// address the serving AMF for the Namf N1N2 delivery leg (E4). Returns the
/// policy association ID parsed from the Location header (fallback:
/// `polAssoId` in the body).
#[allow(clippy::too_many_arguments)]
pub async fn call_pcf_ue_policy_create(
    pcf_host: &str,
    pcf_port: u16,
    supi: &str,
    serving_plmn_mcc: &str,
    serving_plmn_mnc: &str,
    guami_mcc: &str,
    guami_mnc: &str,
    guami_amf_id_hex: &str,
) -> SbiResult<String> {
    let client = crate::attach_oauth2(
        SbiClient::with_host_port(pcf_host, pcf_port),
        nextgcore_sbi::types::NfType::Pcf,
    );

    let body = serde_json::json!({
        "notificationUri": format!("/namf-callback/v1/{supi}/ue-policy-notify"),
        "supi": supi,
        "suppFeat": "",
        "servingPlmn": { "mcc": serving_plmn_mcc, "mnc": serving_plmn_mnc },
        "guami": {
            "plmnId": { "mcc": guami_mcc, "mnc": guami_mnc },
            "amfId": guami_amf_id_hex,
        },
    });

    let response = client
        .post_json("/npcf-ue-policy-control/v1/policies", &body)
        .await
        .map_err(|e| SbiError::RequestFailed(format!("UE policy create failed: {e}")))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "UE policy create returned status {}",
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
        .ok_or_else(|| {
            SbiError::RequestFailed(
                "UE policy create: no Location header and no polAssoId in body".to_string(),
            )
        })?;

    log::info!("[{supi}] Npcf_UEPolicyControl_Create OK (polAssoId={assoc_id})");
    Ok(assoc_id)
}

/// Npcf_UEPolicyControl_Delete: DELETE
/// /npcf-ue-policy-control/v1/policies/{polAssoId} (TS 29.525 §4.2.4 —
/// Wave-6 E7, the deregistration leg of the UE Policy Association).
pub async fn call_pcf_ue_policy_delete(
    pcf_host: &str,
    pcf_port: u16,
    pol_asso_id: &str,
) -> SbiResult<()> {
    let client = crate::attach_oauth2(
        SbiClient::with_host_port(pcf_host, pcf_port),
        nextgcore_sbi::types::NfType::Pcf,
    );

    let response = client
        .delete(&format!(
            "/npcf-ue-policy-control/v1/policies/{pol_asso_id}"
        ))
        .await
        .map_err(|e| SbiError::RequestFailed(format!("UE policy delete failed: {e}")))?;

    if !response.is_success() {
        return Err(SbiError::RequestFailed(format!(
            "UE policy delete returned status {}",
            response.status
        )));
    }

    log::info!("Npcf_UEPolicyControl_Delete OK (polAssoId={pol_asso_id})");
    Ok(())
}

/// Result of an Nnsacf UE-admission query (TS 29.536).
#[derive(Debug, Clone)]
pub struct NsacfUeAdmissionResult {
    /// Whether the UE was admitted for the requested S-NSSAI.
    pub admitted: bool,
}

/// Nnsacf_NSAC UE-admission query (TS 29.536 §6.1.3.2).
///
/// POST {apiRoot}/nnsacf-nsac/v1/slices/ues with a nested `UeACRequestData`
/// (§6.1.6.2.2): `ueACRequestInfo[]` each with a mandatory `supi`, `anType` and
/// an `acuOperationList[]` of `{updateFlag, snssai}`. The admission RESULT is
/// the HTTP status (§6.1.3.2.3.1): **204** all requested S-NSSAIs admitted,
/// **200** `UeACResponseData.acuFailureList` (a map keyed by SUPI) for partial
/// failure, **403** ProblemDetails for total failure. `update_flag=true`
/// requests INCREASE (enforce the per-slice UE count); false requests DECREASE.
///
/// Degrade-open: any transport error or unexpected status returns
/// `admitted=true`, so a missing/failing NSACF never blocks registration.
pub async fn call_nsacf_ue_admission(
    nsacf_host: &str,
    nsacf_port: u16,
    nf_id: &str,
    supi: &str,
    snssai_sst: u8,
    snssai_sd: Option<u32>,
    access_type: &str,
    update_flag: bool,
) -> SbiResult<NsacfUeAdmissionResult> {
    let client = crate::attach_oauth2(
        SbiClient::with_host_port(nsacf_host, nsacf_port),
        nextgcore_sbi::types::NfType::Nsacf,
    );

    let mut snssai = serde_json::json!({ "sst": snssai_sst });
    if let Some(sd) = snssai_sd {
        snssai["sd"] = serde_json::Value::String(format!("{sd:06X}"));
    }

    // TS 29.536 §6.1.6.2.2/.9/.5 nested UeACRequestData.
    let body = serde_json::json!({
        "nfId": nf_id,
        "ueACRequestInfo": [{
            "supi": supi,
            "anType": access_type,
            "acuOperationList": [{
                "updateFlag": if update_flag { "INCREASE" } else { "DECREASE" },
                "snssai": snssai,
            }],
        }],
    });

    let response = match client.post_json("/nnsacf-nsac/v1/slices/ues", &body).await {
        Ok(r) => r,
        Err(e) => {
            // Degrade-open: NSACF unreachable -> admit.
            log::warn!("NSACF UE admission unreachable, admitting (degrade-open): {e}");
            return Ok(NsacfUeAdmissionResult { admitted: true });
        }
    };

    let admitted = match response.status {
        // All requested S-NSSAIs admitted.
        204 => true,
        // Total failure (ProblemDetails) -> not admitted.
        403 => false,
        // Partial failure: UeACResponseData.acuFailureList keyed by SUPI. Our
        // SUPI appearing means our single requested S-NSSAI failed.
        200 => {
            let our_supi_failed = response
                .http
                .content
                .as_deref()
                .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
                .and_then(|j| {
                    j.get("acuFailureList")
                        .and_then(|m| m.get(supi))
                        .map(|entries| !entries.is_null())
                })
                .unwrap_or(false);
            !our_supi_failed
        }
        // Unexpected status: degrade-open rather than block registration.
        other => {
            log::warn!("NSACF UE admission returned status {other}, admitting (degrade-open)");
            true
        }
    };

    log::info!(
        "Nnsacf UE admission (SST={snssai_sst}, SD={snssai_sd:?}, supi={supi}): admitted={admitted}"
    );
    Ok(NsacfUeAdmissionResult { admitted })
}

/// Nudm_UECM_DeregistrationNotification cleanup: PATCH purge on deregistration
/// (TS 29.503 5.3.2.4: AMF sets purgeFlag when the UE deregisters).
pub async fn call_udm_uecm_deregistration(
    udm_host: &str,
    udm_port: u16,
    supi: &str,
) -> SbiResult<()> {
    let client = crate::attach_oauth2(
        SbiClient::with_host_port(udm_host, udm_port),
        nextgcore_sbi::types::NfType::Udm,
    );

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

    // ------------------------------------------------------------------
    // nsacf-01/02 pairing: call_nsacf_ue_admission sends a nested
    // UeACRequestData and maps 204 / 200-acuFailureList / 403, degrade-open.
    // ------------------------------------------------------------------

    fn nsacf_free_port() -> u16 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        port
    }

    /// Stub NSACF: validates the nested UeACRequestData shape (TS 29.536), then
    /// answers by SUPI — "imsi-reject" -> 403 (total failure), "imsi-partial" ->
    /// 200 with an acuFailureList naming that SUPI, otherwise 204 (admitted).
    async fn stub_nsacf_ue(
        req: nextgcore_sbi::message::SbiRequest,
    ) -> nextgcore_sbi::message::SbiResponse {
        let path = req.header.uri.split('?').next().unwrap_or("").to_string();
        if !path.ends_with("/nnsacf-nsac/v1/slices/ues") {
            return nextgcore_sbi::message::SbiResponse::with_status(404);
        }
        let body: serde_json::Value = req
            .http
            .content
            .as_deref()
            .and_then(|c| serde_json::from_str(c).ok())
            .unwrap_or(serde_json::Value::Null);
        // Conformant nested shape (no flat data.snssai/updateFlag/supi).
        assert!(body["nfId"].is_string(), "request must carry nfId");
        let info = &body["ueACRequestInfo"][0];
        assert!(info["anType"].is_string(), "anType present");
        let supi = info["supi"].as_str().unwrap_or("").to_string();
        let op = &info["acuOperationList"][0];
        assert!(
            op["updateFlag"] == "INCREASE" || op["updateFlag"] == "DECREASE",
            "updateFlag INCREASE/DECREASE"
        );
        assert!(op["snssai"]["sst"].is_u64(), "op carries snssai");

        match supi.as_str() {
            "imsi-reject" => nextgcore_sbi::message::SbiResponse::with_status(403).with_body(
                serde_json::json!({"status": 403, "cause": "ALL_SLICE_FAILED"}).to_string(),
                "application/problem+json",
            ),
            "imsi-partial" => {
                let resp = serde_json::json!({
                    "acuFailureList": {
                        supi: [{ "snssai": op["snssai"].clone(), "reason": "EXCEED_MAX_UE_NUM" }]
                    }
                });
                nextgcore_sbi::message::SbiResponse::with_status(200)
                    .with_json_body(&resp)
                    .unwrap_or_else(|_| nextgcore_sbi::message::SbiResponse::with_status(200))
            }
            _ => nextgcore_sbi::message::SbiResponse::with_status(204),
        }
    }

    #[tokio::test]
    async fn nsacf_ue_admission_204_403_200_failure_list() {
        let port = nsacf_free_port();
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(addr),
        );
        server.start(stub_nsacf_ue).await.expect("start stub NSACF");

        let run = async {
            // 204 No Content -> admitted (registration proceeds).
            let r = call_nsacf_ue_admission(
                "127.0.0.1",
                port,
                "amf-1",
                "imsi-admit",
                1,
                None,
                "3GPP_ACCESS",
                true,
            )
            .await
            .expect("ok");
            assert!(r.admitted, "204 -> admitted");

            // 403 ProblemDetails (total failure) -> not admitted.
            let r = call_nsacf_ue_admission(
                "127.0.0.1",
                port,
                "amf-1",
                "imsi-reject",
                1,
                None,
                "3GPP_ACCESS",
                true,
            )
            .await
            .expect("ok");
            assert!(!r.admitted, "403 -> not admitted");

            // 200 acuFailureList naming our SUPI -> not admitted.
            let r = call_nsacf_ue_admission(
                "127.0.0.1",
                port,
                "amf-1",
                "imsi-partial",
                1,
                None,
                "3GPP_ACCESS",
                true,
            )
            .await
            .expect("ok");
            assert!(!r.admitted, "200 acuFailureList[supi] -> not admitted");
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), run)
            .await
            .expect("round trip timed out");
        server.stop().await.ok();
    }

    #[tokio::test]
    async fn nsacf_ue_admission_degrade_open_on_transport_error() {
        // Nothing listening -> degrade-open: admitted=true so registration is
        // never blocked by a missing/unreachable NSACF.
        let port = nsacf_free_port();
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            call_nsacf_ue_admission(
                "127.0.0.1",
                port,
                "amf-1",
                "imsi-x",
                1,
                None,
                "3GPP_ACCESS",
                true,
            ),
        )
        .await
        .expect("bounded")
        .expect("degrade-open returns Ok");
        assert!(r.admitted, "transport error must degrade-open to admitted");
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

    // ------------------------------------------------------------------
    // smfd-01 / smfd-02 pairing: multipart/related N1/N2 carriage on the
    // amfd↔smfd Nsmf_PDUSession path (TS 29.502 §6.1.2.2.2 / §6.1.2.4)
    // ------------------------------------------------------------------

    /// A UE PDU Session Establishment Request N1 container (PSI=5, PTI=2).
    const UE_N1_REQUEST: [u8; 14] = [
        0x2E, 0x05, 0x02, 0xC1, 0xFF, 0xFF, 0x93, 0xA2, 0x28, 0x01, 0x00, 0x55, 0x00, 0x10,
    ];

    /// amfd's CreateSmContext request is multipart/related: the JSON root holds
    /// the SmContextCreateData with the N1 as a RefToBinaryData pointer, and the
    /// UE's N1 travels in a 5gnas binary part with the exact UE bytes.
    #[test]
    fn amfd_create_request_is_multipart_with_n1_part() {
        let request =
            build_create_sm_context_request(5, 1, None, "internet", &UE_N1_REQUEST, false);

        // Serialize the request's parts exactly as the SBI client would, then
        // decode it back to prove the wire shape the SMF receives.
        let boundary = nextgcore_sbi::multipart::generate_boundary();
        let body = nextgcore_sbi::multipart::encode(
            request.http.content.as_deref(),
            &request.http.parts,
            &boundary,
        );
        let ct = nextgcore_sbi::multipart::content_type_with_boundary(&boundary);
        let decoded = nextgcore_sbi::multipart::decode(&ct, &body).expect("decode multipart");

        let root: serde_json::Value =
            serde_json::from_str(decoded.json.as_deref().unwrap()).unwrap();
        assert_eq!(root["n1SmMsg"]["contentId"].as_str(), Some("n1SmMsg"));
        assert_eq!(root["pduSessionId"].as_u64(), Some(5));
        assert_eq!(root["dnn"].as_str(), Some("internet"));

        let n1_part = decoded
            .parts
            .iter()
            .find(|p| p.content_id.as_deref() == Some("n1SmMsg"))
            .expect("n1 part");
        assert_eq!(n1_part.data.as_ref(), UE_N1_REQUEST.as_slice());
        assert_eq!(
            n1_part.content_type.as_deref(),
            Some(content_type::APPLICATION_5GNAS)
        );
    }

    /// Cross-decode: bytes shaped exactly as smfd emits a multipart
    /// SmContextCreatedData response (JSON root with N1/N2 RefToBinaryData +
    /// 5gnas/ngap parts) are parsed by amfd's `extract_binary_ref` to the exact
    /// N1/N2 containers.
    #[test]
    fn amfd_parses_smfd_multipart_response() {
        let n1 = vec![0x2E, 0x05, 0x02, 0xC2, 0x00, 0x09]; // accept-ish N1
        let n2 = vec![0x00, 0x00, 0x03, 0x00, 0x8b, 0x00]; // ngap transfer-ish

        // Reproduce smfd's response wire emission via the shared encoder.
        let root = serde_json::json!({
            "smContextRef": "7",
            "pduSessionId": 5,
            "upCnxState": "ACTIVATING",
            "n1SmMsg": { "contentId": "n1SmMsg" },
            "n2SmInfo": { "contentId": "n2SmInfo" },
            "n2SmInfoType": "PDU_RES_SETUP_REQ"
        });
        let parts = vec![
            SbiPart::with_content(
                "n1SmMsg",
                content_type::APPLICATION_5GNAS,
                bytes::Bytes::copy_from_slice(&n1),
            ),
            SbiPart::with_content(
                "n2SmInfo",
                content_type::APPLICATION_NGAP,
                bytes::Bytes::copy_from_slice(&n2),
            ),
        ];
        let boundary = nextgcore_sbi::multipart::generate_boundary();
        let body = nextgcore_sbi::multipart::encode(Some(&root.to_string()), &parts, &boundary);
        let ct = nextgcore_sbi::multipart::content_type_with_boundary(&boundary);

        // Client-side: decode into the response amfd's caller would see.
        let decoded = nextgcore_sbi::multipart::decode(&ct, &body).unwrap();
        let mut response = SbiResponse::with_status(201);
        response.http.content = decoded.json.clone();
        response.http.parts = decoded.parts;
        let response_body: serde_json::Value =
            serde_json::from_str(decoded.json.as_deref().unwrap()).unwrap();

        assert_eq!(
            extract_binary_ref(&response, &response_body, "n1SmMsg").unwrap(),
            n1
        );
        assert_eq!(
            extract_binary_ref(&response, &response_body, "n2SmInfo").unwrap(),
            n2
        );
    }

    /// Backward compatibility: amfd still extracts N1/N2 from a legacy
    /// base64-in-JSON SMF response (no multipart parts).
    #[test]
    fn amfd_parses_legacy_base64_response() {
        let n1 = vec![0x2E, 0x05, 0x02, 0xC2];
        let n2 = vec![0x00, 0x00, 0x03];
        let response_body = serde_json::json!({
            "n1SmMsg": base64::engine::general_purpose::STANDARD.encode(&n1),
            "n2SmInfo": base64::engine::general_purpose::STANDARD.encode(&n2),
        });
        // No parts on the response → falls back to the base64 strings.
        let response = SbiResponse::with_status(201);
        assert_eq!(
            extract_binary_ref(&response, &response_body, "n1SmMsg").unwrap(),
            n1
        );
        assert_eq!(
            extract_binary_ref(&response, &response_body, "n2SmInfo").unwrap(),
            n2
        );
    }

    // ------------------------------------------------------------------
    // Wave-6 E7 — Npcf_UEPolicyControl consumer (TS 29.525 §4.2.2/§4.2.4)
    // ------------------------------------------------------------------

    /// Kill-switch classifier: AMF_UE_POLICY_ASSOC=off/0/false disables the
    /// UE Policy Association leg; unset or anything else keeps it enabled
    /// (env-free pure-function test to avoid process-global env races).
    #[test]
    fn ue_policy_assoc_kill_switch_classifier() {
        assert!(ue_policy_assoc_enabled_value(None), "default (unset) = on");
        assert!(!ue_policy_assoc_enabled_value(Some("off")));
        assert!(!ue_policy_assoc_enabled_value(Some("OFF")));
        assert!(!ue_policy_assoc_enabled_value(Some(" off ")));
        assert!(!ue_policy_assoc_enabled_value(Some("0")));
        assert!(!ue_policy_assoc_enabled_value(Some("false")));
        assert!(ue_policy_assoc_enabled_value(Some("on")));
        assert!(ue_policy_assoc_enabled_value(Some("1")));
        assert!(ue_policy_assoc_enabled_value(Some("")));
    }

    /// Paired-emit stub of pcfd's REAL `handle_ue_policy_create`
    /// (bins/nextgcore-pcfd/src/main.rs:677-713). It re-asserts, with line
    /// citations, exactly what the real handler validates and answers:
    ///
    /// * mandatory PolicyAssociationRequest members `notificationUri`,
    ///   `supi`, `suppFeat` → 400 MANDATORY_IE_MISSING when absent
    ///   (main.rs:686-695, TS 29.525);
    /// * 201 + `Location: /npcf-ue-policy-control/v1/policies/{polAssoId}`
    ///   (main.rs:706-710) with the PolicyAssociation body shape
    ///   (main.rs:701-705).
    ///
    /// NOTE: this is a cross-check of the emitted request against the peer's
    /// contract, not the in-process strict-peer test — pcfd's handler lives
    /// only in its binary target (not its lib), so it cannot be mounted here.
    async fn stub_pcf_ue_policy(
        req: nextgcore_sbi::message::SbiRequest,
    ) -> nextgcore_sbi::message::SbiResponse {
        let path = req.header.uri.split('?').next().unwrap_or("").to_string();

        // DELETE /npcf-ue-policy-control/v1/policies/{id} → 204 (pcfd
        // main.rs:731-740 via ue_policy_remove).
        if req.header.method == "DELETE" {
            return if path.ends_with("/npcf-ue-policy-control/v1/policies/pol-ue-42") {
                nextgcore_sbi::message::SbiResponse::with_status(204)
            } else {
                nextgcore_sbi::message::SbiResponse::with_status(404)
            };
        }

        if !path.ends_with("/npcf-ue-policy-control/v1/policies") {
            return nextgcore_sbi::message::SbiResponse::with_status(404);
        }
        let body: serde_json::Value = req
            .http
            .content
            .as_deref()
            .and_then(|c| serde_json::from_str(c).ok())
            .unwrap_or(serde_json::Value::Null);

        // The three members pcfd's real handler requires (main.rs:686-695).
        for mandatory in ["notificationUri", "supi", "suppFeat"] {
            if !body[mandatory].is_string() {
                return nextgcore_sbi::message::SbiResponse::with_status(400).with_body(
                    serde_json::json!({
                        "status": 400,
                        "cause": "MANDATORY_IE_MISSING",
                        "detail": format!("{mandatory} is required"),
                    })
                    .to_string(),
                    "application/problem+json",
                );
            }
        }
        // SUPI-keyed behavior so the error path is drivable per test case.
        if body["supi"].as_str() == Some("imsi-pcf-unavailable") {
            return nextgcore_sbi::message::SbiResponse::with_status(503);
        }

        // amfd's notification URI convention (mirrors the AM-policy one):
        // /namf-callback/v1/{supi}/ue-policy-notify.
        let supi = body["supi"].as_str().unwrap_or_default();
        if body["notificationUri"].as_str()
            != Some(format!("/namf-callback/v1/{supi}/ue-policy-notify").as_str())
        {
            return nextgcore_sbi::message::SbiResponse::with_status(400).with_body(
                serde_json::json!({
                    "status": 400,
                    "cause": "INVALID_NOTIFICATION_URI",
                })
                .to_string(),
                "application/problem+json",
            );
        }

        // The optionals amfd promises so the PCF can address the serving AMF
        // for the E4 Namf delivery leg: servingPlmn (PlmnIdNid) and guami
        // (Guami — TS29525 yaml:427-428/452-453). Reject drift so the test
        // fails if amfd stops sending them well-formed.
        if !(body["servingPlmn"]["mcc"].is_string() && body["servingPlmn"]["mnc"].is_string()) {
            return nextgcore_sbi::message::SbiResponse::with_status(400).with_body(
                serde_json::json!({
                    "status": 400,
                    "cause": "INVALID_SERVING_PLMN",
                })
                .to_string(),
                "application/problem+json",
            );
        }
        if !(body["guami"]["plmnId"]["mcc"].is_string()
            && body["guami"]["plmnId"]["mnc"].is_string()
            && body["guami"]["amfId"].is_string())
        {
            return nextgcore_sbi::message::SbiResponse::with_status(400).with_body(
                serde_json::json!({
                    "status": 400,
                    "cause": "INVALID_GUAMI",
                })
                .to_string(),
                "application/problem+json",
            );
        }

        // pcfd's real 201 (main.rs:701-712): PolicyAssociation body + Location.
        let resp = serde_json::json!({
            "suppFeat": "0",
            "triggers": ["UE_POLICY"],
            "request": {
                "notificationUri": body["notificationUri"],
                "supi": body["supi"],
                "suppFeat": body["suppFeat"],
            },
        });
        nextgcore_sbi::message::SbiResponse::with_status(201)
            .with_header(
                "Location",
                "/npcf-ue-policy-control/v1/policies/pol-ue-42".to_string(),
            )
            .with_json_body(&resp)
            .unwrap_or_else(|_| nextgcore_sbi::message::SbiResponse::with_status(201))
    }

    async fn start_pcf_ue_policy_stub() -> (nextgcore_sbi::server::SbiServer, u16) {
        let port = nsacf_free_port();
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(addr),
        );
        server
            .start(stub_pcf_ue_policy)
            .await
            .expect("start stub PCF");
        (server, port)
    }

    /// call_pcf_ue_policy_create sends a schema-exact PolicyAssociationRequest
    /// (TS29525_Npcf_UEPolicyControl.yaml:381-461) — the pcfd-mandatory
    /// members plus servingPlmn (PlmnIdNid) and guami (Guami) — and parses
    /// the polAssoId out of the Location header.
    #[tokio::test]
    async fn ue_policy_create_posts_spec_body_and_parses_location() {
        let (server, port) = start_pcf_ue_policy_stub().await;

        let assoc = call_pcf_ue_policy_create(
            "127.0.0.1",
            port,
            "imsi-001010000060040",
            "001",
            "01",
            "001",
            "01",
            "020040",
        )
        .await
        .expect("UE policy create against paired stub");
        assert_eq!(assoc, "pol-ue-42", "polAssoId parsed from Location");

        server.stop().await.expect("server stop");
    }

    /// A PCF 5xx yields Err — the registration call site logs a WARN and
    /// continues, so registration outcome is unchanged by construction
    /// (fire-and-forget, ngap_path.rs complete_registration step 3b).
    #[tokio::test]
    async fn ue_policy_create_5xx_is_err_not_panic() {
        let (server, port) = start_pcf_ue_policy_stub().await;

        let result = call_pcf_ue_policy_create(
            "127.0.0.1",
            port,
            "imsi-pcf-unavailable",
            "001",
            "01",
            "001",
            "01",
            "020040",
        )
        .await;
        assert!(result.is_err(), "5xx from PCF must surface as Err");

        server.stop().await.expect("server stop");
    }

    /// An unreachable PCF (connection refused) also yields Err, not a panic.
    #[tokio::test]
    async fn ue_policy_create_unreachable_is_err() {
        let port = nsacf_free_port(); // nothing listening
        let result = call_pcf_ue_policy_create(
            "127.0.0.1",
            port,
            "imsi-001010000060041",
            "001",
            "01",
            "001",
            "01",
            "020040",
        )
        .await;
        assert!(result.is_err(), "unreachable PCF must surface as Err");
    }

    /// The deregistration leg DELETEs the association resource (TS 29.525
    /// §4.2.4) and maps 204 → Ok, 404 → Err.
    #[tokio::test]
    async fn ue_policy_delete_deletes_resource() {
        let (server, port) = start_pcf_ue_policy_stub().await;

        call_pcf_ue_policy_delete("127.0.0.1", port, "pol-ue-42")
            .await
            .expect("delete existing association");
        assert!(
            call_pcf_ue_policy_delete("127.0.0.1", port, "pol-ue-does-not-exist")
                .await
                .is_err(),
            "404 must surface as Err"
        );

        server.stop().await.expect("server stop");
    }
}
