//! UDM SBI Path Functions
//!
//! Port of src/udm/sbi-path.c - SBI server and client path functions

use std::sync::atomic::{AtomicBool, Ordering};

use crate::context::{udm_self, NfProfileConfig};
use nextgcore_sbi::context::{global_context, NfInstance, NfService};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::types::{NfType, SbiServiceType};

/// SBI server configuration
#[derive(Debug, Clone)]
pub struct SbiServerConfig {
    /// Server address
    pub addr: String,
    /// Server port
    pub port: u16,
    /// TLS enabled
    pub tls_enabled: bool,
    /// TLS certificate path
    pub tls_cert: Option<String>,
    /// TLS key path
    pub tls_key: Option<String>,
}

impl Default for SbiServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 7777, // UDM default port
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
        }
    }
}

/// SBI server state
static SBI_RUNNING: AtomicBool = AtomicBool::new(false);

/// The Nudm services this UDM serves, with the API version each is defined at
/// and its `SbiServiceType`.
///
/// ONE list, consumed by both the typed self-instance built in [`udm_sbi_open`]
/// and the JSON NFProfile built by [`build_udm_nf_profile`]. Before #85 those
/// were two hand-written lists that disagreed: one advertised `nudm-sdm` at
/// `v1` and the other at `v2`, neither advertised the routed `nudm-ee` at all,
/// and which profile the NRF saw depended on the registration path taken.
///
/// The version per service is normative and easy to get wrong: TS 29.503 §6.1.1
/// says "The `<apiVersion>` shall be v2" for **Nudm_SDM** only; every other
/// Nudm service is v1.
pub const UDM_ADVERTISED_SERVICES: [(&str, &str, SbiServiceType); 6] = [
    ("nudm-sdm", "v2", SbiServiceType::NudmSdm),
    ("nudm-uecm", "v1", SbiServiceType::NudmUecm),
    ("nudm-ueau", "v1", SbiServiceType::NudmUeau),
    ("nudm-ee", "v1", SbiServiceType::NudmEe),
    ("nudm-pp", "v1", SbiServiceType::NudmPp),
    ("nudm-mt", "v1", SbiServiceType::NudmMt),
];

/// Build the UDM's NFProfile for NRF registration (TS 29.510 §6.1.6.2.2).
///
/// The single source of truth for what this UDM advertises: the service list
/// comes from [`UDM_ADVERTISED_SERVICES`] and the operator knobs
/// (`heartBeatTimer`, `allowedNfTypes`) from [`NfProfileConfig`], so no caller
/// can advertise a different surface than another.
pub fn build_udm_nf_profile(
    nf_instance_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
    config: &NfProfileConfig,
) -> serde_json::Value {
    let services: Vec<serde_json::Value> = UDM_ADVERTISED_SERVICES
        .iter()
        .map(|(name, version, _)| {
            serde_json::json!({
                "serviceInstanceId": format!("{nf_instance_id}-{name}"),
                "serviceName": name,
                "versions": [{
                    "apiVersionInUri": version,
                    // apiFullVersion must agree with the URI version, not lag it.
                    "apiFullVersion": format!("{}.0.0", version.trim_start_matches('v')),
                }],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            })
        })
        .collect();
    serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "UDM",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": services,
        "allowedNfTypes": config.allowed_nf_types,
        "heartBeatTimer": config.heart_beat_timer,
    })
}

/// Open SBI server and register with NRF
///
/// Port of udm_sbi_open()
pub fn udm_sbi_open(config: Option<SbiServerConfig>) -> Result<(), String> {
    let config = config.unwrap_or_default();

    log::info!("Opening UDM SBI server on {}:{}", config.addr, config.port);

    // Build self NF instance for UDM
    let nf_instance_id = uuid::Uuid::new_v4().to_string();
    let mut nf_instance = NfInstance::new(&nf_instance_id, NfType::Udm);
    nf_instance.ipv4_addresses.push(config.addr.clone());

    // Register every Nudm service this UDM serves, from the shared table so the
    // self instance and the NRF profile cannot disagree (#85).
    for (name, version, service_type) in UDM_ADVERTISED_SERVICES {
        let mut service = NfService::new(name, service_type);
        service.versions = vec![version.to_string()];
        service.port = config.port;
        nf_instance.add_service(service);
    }
    nf_instance.heartbeat_interval = udm_self()
        .read()
        .map(|ctx| ctx.nf_profile_config().heart_beat_timer)
        .unwrap_or(10);

    // Store self NF instance in global SBI context
    // Use spawn to avoid blocking the runtime (block_on panics inside async)
    let sbi_ctx = global_context();
    tokio::spawn(async move {
        sbi_ctx.set_self_instance(nf_instance.clone()).await;
    });

    SBI_RUNNING.store(true, Ordering::SeqCst);

    log::info!("UDM SBI server opened successfully (nf_instance_id={nf_instance_id})");
    Ok(())
}

/// Register UDM NF instance with NRF
///
/// Sends NFRegister (PUT) to NRF at /nnrf-nfm/v1/nf-instances/{nfInstanceId}
pub async fn udm_nrf_register(nrf_host: &str, nrf_port: u16) -> Result<(), String> {
    let sbi_ctx = global_context();
    let self_instance = sbi_ctx
        .get_self_instance()
        .await
        .ok_or("Self NF instance not initialized")?;

    let client = sbi_ctx.get_client(nrf_host, nrf_port).await;

    let path = format!("/nnrf-nfm/v1/nf-instances/{}", self_instance.id);

    // Build NF profile JSON for registration through the SHARED builder (#85):
    // this path used to render the self instance by hand, producing a profile
    // that differed from the one `app::register_with_nrf_id` sent.
    let sbi_addr = self_instance
        .ipv4_addresses
        .first()
        .cloned()
        .unwrap_or_default();
    let sbi_port = self_instance
        .services
        .first()
        .map(|s| s.port)
        .unwrap_or(7777);
    let profile_config = udm_self()
        .read()
        .map(|ctx| ctx.nf_profile_config())
        .unwrap_or_default();
    let nf_profile = build_udm_nf_profile(&self_instance.id, &sbi_addr, sbi_port, &profile_config);

    let request = SbiRequest::put(&path)
        .with_json_body(&nf_profile)
        .map_err(|e| format!("Failed to serialize NF profile: {e}"))?;

    let response = client
        .send_request(request)
        .await
        .map_err(|e| format!("NRF registration request failed: {e}"))?;

    if response.is_success() {
        // Parse heartbeat interval from response if provided
        log::info!("UDM registered with NRF (status={})", response.status);
        Ok(())
    } else {
        Err(format!(
            "NRF registration failed with status {}",
            response.status
        ))
    }
}

/// Send NRF heartbeat (PATCH to NRF)
pub async fn udm_nrf_heartbeat(nrf_host: &str, nrf_port: u16) -> Result<(), String> {
    let sbi_ctx = global_context();
    let self_instance = sbi_ctx
        .get_self_instance()
        .await
        .ok_or("Self NF instance not initialized")?;

    let client = sbi_ctx.get_client(nrf_host, nrf_port).await;

    let path = format!("/nnrf-nfm/v1/nf-instances/{}", self_instance.id);

    let update = serde_json::json!([{
        "op": "replace",
        "path": "/nfStatus",
        "value": "REGISTERED"
    }, {
        "op": "replace",
        "path": "/load",
        "value": crate::context::get_ue_load()
    }]);

    let request = SbiRequest::patch(&path)
        .with_json_body(&update)
        .map_err(|e| format!("Failed to serialize heartbeat: {e}"))?;

    let response = client
        .send_request(request)
        .await
        .map_err(|e| format!("NRF heartbeat request failed: {e}"))?;

    if response.is_success() {
        log::debug!("NRF heartbeat OK (status={})", response.status);
        Ok(())
    } else {
        Err(format!(
            "NRF heartbeat failed with status {}",
            response.status
        ))
    }
}

/// Discover NF instances via NRF
///
/// Queries /nnrf-disc/v1/nf-instances?target-nf-type={type}
pub async fn udm_nrf_discover(
    nrf_host: &str,
    nrf_port: u16,
    target_nf_type: NfType,
) -> Result<Vec<NfInstance>, String> {
    let sbi_ctx = global_context();
    let _self_instance = sbi_ctx
        .get_self_instance()
        .await
        .ok_or("Self NF instance not initialized")?;

    let client = sbi_ctx.get_client(nrf_host, nrf_port).await;

    let target_type_str = match target_nf_type {
        NfType::Udr => "UDR",
        NfType::Ausf => "AUSF",
        NfType::Amf => "AMF",
        NfType::Smf => "SMF",
        _ => "UNKNOWN",
    };

    let request = SbiRequest::get("/nnrf-disc/v1/nf-instances")
        .with_param("target-nf-type", target_type_str)
        .with_param("requester-nf-type", "UDM");

    let response = client
        .send_request(request)
        .await
        .map_err(|e| format!("NRF discovery request failed: {e}"))?;

    if !response.is_success() {
        return Err(format!(
            "NRF discovery failed with status {}",
            response.status
        ));
    }

    // Parse discovered NF instances from response body
    let body = response
        .http
        .content
        .ok_or_else(|| "NRF discovery response has no body".to_string())?;
    let search_result: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse NRF discovery response: {e}"))?;

    // #235: the SearchResult's validityPeriod bounds how long these profiles may
    // be selected; without it a cached peer was chosen for the process lifetime.
    let validity = nextgcore_sbi::context::search_result_validity(&search_result);

    let mut instances = Vec::new();
    if let Some(nf_instances) = search_result.get("nfInstances").and_then(|v| v.as_array()) {
        for nf_json in nf_instances {
            let id = nf_json
                .get("nfInstanceId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let mut instance = NfInstance::new(&id, target_nf_type);

            if let Some(addrs) = nf_json.get("ipv4Addresses").and_then(|v| v.as_array()) {
                for addr in addrs {
                    if let Some(s) = addr.as_str() {
                        instance.ipv4_addresses.push(s.to_string());
                    }
                }
            }

            // Cache discovered instance in SBI context, bounded by validityPeriod
            sbi_ctx
                .add_nf_instance_with_validity(instance.clone(), validity)
                .await;
            instances.push(instance);
        }
    }

    log::info!(
        "NRF discovery found {} {} instances",
        instances.len(),
        target_type_str
    );
    Ok(instances)
}

// #235: `udm_nrf_deregister(nrf_host, nrf_port)` used to live here — a per-NF
// copy of NFDeregister that had NO caller, so udmd never actually deregistered
// despite owning the only client in the workspace. The one client is now
// `nextgcore_sbi::heartbeat::deregister_nf`, driven from `app.rs`'s shutdown
// path via `deregister_self()` and from the NES sleep path in `nes_driver.rs`.
// Keeping the local copy would have made three implementations of one DELETE.

/// Close SBI server
///
/// Port of udm_sbi_close()
pub fn udm_sbi_close() {
    log::info!("Closing UDM SBI server");

    // Clear SBI client connections
    let sbi_ctx = global_context();
    if let Ok(_handle) = tokio::runtime::Handle::try_current() {
        // Use spawn instead of block_on to avoid panicking when called from async context
        tokio::spawn(async move {
            sbi_ctx.clear_clients().await;
            sbi_ctx.clear_nf_instances().await;
        });
    }

    SBI_RUNNING.store(false, Ordering::SeqCst);

    log::info!("UDM SBI server closed");
}

/// Check if SBI server is running
pub fn udm_sbi_is_running() -> bool {
    SBI_RUNNING.load(Ordering::SeqCst)
}

/// Send SBI request to a specific NF instance by ID
///
/// Port of udm_sbi_send_request()
pub async fn udm_sbi_send_request(
    nf_instance_id: &str,
    request: SbiRequest,
) -> Result<SbiResponse, String> {
    let sbi_ctx = global_context();

    // Look up the NF instance to get its address
    let nf_instance = sbi_ctx
        .get_nf_instance(nf_instance_id)
        .await
        .ok_or_else(|| format!("NF instance not found: {nf_instance_id}"))?;

    let host = nf_instance
        .ipv4_addresses
        .first()
        .ok_or_else(|| format!("NF instance {nf_instance_id} has no IPv4 address"))?;

    // Determine port from first service or default
    let port = nf_instance.services.first().map(|s| s.port).unwrap_or(80);

    let client = sbi_ctx.get_client(host, port).await;

    log::debug!(
        "Sending SBI request to NF [{}] at {}:{} ({})",
        nf_instance_id,
        host,
        port,
        request.header.method
    );

    match client.send_request(request).await {
        Ok(response) => Ok(response),
        Err(e) => {
            // #235: a TRANSPORT failure is evidence the cached profile is wrong,
            // so drop it and let the next call re-discover. Deliberately not done
            // for an error STATUS: a 4xx/5xx means the peer answered, i.e. the
            // endpoint is live and the profile is fine.
            sbi_ctx.evict_nf_instance_on_failure(nf_instance_id).await;
            Err(format!("SBI request to {nf_instance_id} failed: {e}"))
        }
    }
}

/// The ONE agreement about the `UDR_SBI_ADDR` / `UDR_SBI_PORT` environment, for
/// tests (#308).
///
/// Declared beside the fallback below rather than inside `mod tests`, so a sibling
/// module that starts writing these variables reaches the same static instead of
/// declaring a second one. `app.rs` had three writers and no lock at all: each
/// pointed the fallback at its own mock UDR, and the fallback names ONE UDR for
/// every `nudr` query, so whoever wrote last owned every sibling's UDR traffic.
///
/// It covers readers as well as writers. `smfd`'s equivalent flake (#308's subject)
/// was a locked writer and an unlocked reader disagreeing about one variable, which
/// is not weaker protection than none — it is none, with a lock to look at.
#[cfg(test)]
pub(crate) static UDR_ENV_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Discover UDR and send a NUDR-DR request
///
/// Port of udm_sbi_discover_and_send() for UDR queries.
/// 1. Looks up cached UDR instances in SBI context
/// 2. If none found, returns error (caller should trigger NRF discovery first)
/// 3. Sends the request to the first available UDR
pub async fn udm_sbi_discover_and_send_nudr_dr(
    udm_ue_id: u64,
    stream_id: u64,
    request: SbiRequest,
) -> Result<SbiResponse, String> {
    let sbi_ctx = global_context();

    // Find UDR instances (from discovery cache or env var fallback)
    let udr_instances = sbi_ctx.find_nf_instances_by_type(NfType::Udr).await;

    // #235: remember WHICH cached profile was selected, so a transport failure
    // can evict that entry rather than leaving the consumer retrying a dead
    // endpoint. `None` on the env-var fallback path — there is no cache entry to
    // blame for a misconfigured environment variable.
    let selected_instance_id: Option<String>;

    let (host_str, port);
    if let Some(udr) = udr_instances.first() {
        selected_instance_id = Some(udr.id.clone());
        host_str = udr
            .ipv4_addresses
            .first()
            .ok_or("UDR has no IPv4 address")?
            .clone();
        port = udr
            .find_service(SbiServiceType::NudrDr)
            .map(|s| s.port)
            .unwrap_or(80);
    } else {
        selected_instance_id = None;
        // Fallback: use UDR_SBI_ADDR/UDR_SBI_PORT env vars
        host_str = std::env::var("UDR_SBI_ADDR")
            .map_err(|_| "No UDR instance discovered and UDR_SBI_ADDR not set".to_string())?;
        port = std::env::var("UDR_SBI_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(7777);
        log::info!("Using UDR env var fallback: {host_str}:{port}");
    }

    // Attach an NRF-issued Bearer token to the Nudr_DataRepository call when
    // OAuth2 enforcement is on (Wave-6 H8 Phase A); pooled/no-op otherwise.
    let client = crate::app::peer_client(&host_str, port, NfType::Udr).await;

    log::debug!(
        "Sending NUDR-DR request for UE [{udm_ue_id}] stream [{stream_id}] to UDR at {host_str}:{port}"
    );

    match client.send_request(request).await {
        Ok(response) => Ok(response),
        Err(e) => {
            // #235: transport failure only — an error status means the UDR
            // answered, so its cached profile is still correct.
            if let Some(id) = selected_instance_id {
                sbi_ctx.evict_nf_instance_on_failure(&id).await;
            }
            Err(format!("NUDR-DR request to UDR failed: {e}"))
        }
    }
}

/// Build and send authentication subscription GET to UDR
///
/// Builds: GET /nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription
pub async fn udm_nudr_dr_send_auth_subscription_get(
    supi: &str,
    udm_ue_id: u64,
    stream_id: u64,
) -> Result<SbiResponse, String> {
    let path = format!(
        "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription"
    );
    let request = SbiRequest::get(&path);
    udm_sbi_discover_and_send_nudr_dr(udm_ue_id, stream_id, request).await
}

/// Build and send SQN update PATCH to UDR
///
/// Builds: PATCH /nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription
pub async fn udm_nudr_dr_send_auth_subscription_patch(
    supi: &str,
    sqn_hex: &str,
    udm_ue_id: u64,
    stream_id: u64,
) -> Result<SbiResponse, String> {
    let path = format!(
        "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription"
    );
    let patch_body = serde_json::json!([{
        "op": "replace",
        "path": "/sequenceNumber/sqn",
        "value": sqn_hex
    }]);
    let request = SbiRequest::patch(&path)
        .with_json_body(&patch_body)
        .map_err(|e| format!("Failed to serialize PATCH body: {e}"))?;

    udm_sbi_discover_and_send_nudr_dr(udm_ue_id, stream_id, request).await
}

/// Build and send provisioned data GET to UDR
///
/// Builds: GET /nudr-dr/v2/subscription-data/{supi}/provisioned-data/{dataset}
pub async fn udm_nudr_dr_send_provisioned_data_get(
    supi: &str,
    dataset: &str,
    udm_ue_id: u64,
    stream_id: u64,
) -> Result<SbiResponse, String> {
    let path = format!("/nudr-dr/v2/subscription-data/{supi}/provisioned-data/{dataset}");
    let request = SbiRequest::get(&path);
    udm_sbi_discover_and_send_nudr_dr(udm_ue_id, stream_id, request).await
}

/// Build and send provisioned data GET to UDR with forwarded query parameters (udmd-08).
///
/// Forwards standardised SDM query params (`plmn-id`, `dataset-names`,
/// `supported-features`, `single-nssai`) to the UDR so the response is
/// already scoped.
pub async fn udm_nudr_dr_send_provisioned_data_get_with_params(
    supi: &str,
    dataset: &str,
    params: &std::collections::HashMap<String, String>,
) -> Result<SbiResponse, String> {
    let path = format!("/nudr-dr/v2/subscription-data/{supi}/provisioned-data/{dataset}");
    let mut request = SbiRequest::get(&path);
    for (k, v) in params {
        request = request.with_param(k, v);
    }
    udm_sbi_discover_and_send_nudr_dr(0, 0, request).await
}

// ---------------------------------------------------------------------------
// UECM context-data persistence (Nudr_DataRepository, TS 29.505) — udmd-01/02
// ---------------------------------------------------------------------------

/// Build the UDR `context-data` URI for a resource under a SUPI.
///
/// `resource` is the path under `context-data/`, e.g. `amf-3gpp-access`,
/// `amf-non-3gpp-access`, `smsf-3gpp-access`, `ip-sm-gw`, `smf-registrations`
/// or `smf-registrations/{psi}` (TS 29.505 §5.2.2).
fn context_data_path(supi: &str, resource: &str) -> String {
    format!("/nudr-dr/v2/subscription-data/{supi}/context-data/{resource}")
}

/// GET a UECM `context-data` resource from UDR (#84 read-through, udmd-02
/// prior read).
///
/// Builds: `GET /nudr-dr/v2/subscription-data/{supi}/context-data/{resource}`
pub async fn udm_nudr_dr_send_context_get(
    supi: &str,
    resource: &str,
) -> Result<SbiResponse, String> {
    let path = context_data_path(supi, resource);
    udm_sbi_discover_and_send_nudr_dr(0, 0, SbiRequest::get(&path)).await
}

/// PUT a UECM `context-data` resource to UDR (udmd-01).
///
/// Builds: `PUT /nudr-dr/v2/subscription-data/{supi}/context-data/{resource}`
pub async fn udm_nudr_dr_send_context_put(
    supi: &str,
    resource: &str,
    body: &serde_json::Value,
) -> Result<SbiResponse, String> {
    let path = context_data_path(supi, resource);
    let request = SbiRequest::put(&path)
        .with_json_body(body)
        .map_err(|e| format!("Failed to serialize {resource} context: {e}"))?;
    udm_sbi_discover_and_send_nudr_dr(0, 0, request).await
}

/// PATCH a UECM `context-data` resource in UDR (udmd-05: purgeFlag /
/// modification).
///
/// Builds: `PATCH /nudr-dr/v2/subscription-data/{supi}/context-data/{resource}`
pub async fn udm_nudr_dr_send_context_patch(
    supi: &str,
    resource: &str,
    body: &serde_json::Value,
) -> Result<SbiResponse, String> {
    let path = context_data_path(supi, resource);
    let request = SbiRequest::patch(&path)
        .with_json_body(body)
        .map_err(|e| format!("Failed to serialize {resource} context patch: {e}"))?;
    udm_sbi_discover_and_send_nudr_dr(0, 0, request).await
}

/// DELETE a UECM context-data resource from UDR (udmd-01 deregistration).
///
/// Builds: `DELETE /nudr-dr/v2/subscription-data/{supi}/context-data/{resource}`
pub async fn udm_nudr_dr_send_context_delete(
    supi: &str,
    resource: &str,
) -> Result<SbiResponse, String> {
    let path = context_data_path(supi, resource);
    udm_sbi_discover_and_send_nudr_dr(0, 0, SbiRequest::delete(&path)).await
}

/// PUT an AuthEvent to the UDR authentication-status resource (udmd-09).
///
/// Builds: `PUT /nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-status`
pub async fn udm_nudr_dr_send_auth_status_put(
    supi: &str,
    body: &serde_json::Value,
) -> Result<SbiResponse, String> {
    let path =
        format!("/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-status");
    let request = SbiRequest::put(&path)
        .with_json_body(body)
        .map_err(|e| format!("Failed to serialize auth status body: {e}"))?;
    udm_sbi_discover_and_send_nudr_dr(0, 0, request).await
}

// ---------------------------------------------------------------------------
// Generic subscription-data resources (Nudr_DataRepository, TS 29.505) — #85
// ---------------------------------------------------------------------------

/// Build the UDR `subscription-data` URI for a resource under a UE identifier.
///
/// `resource` is the path under `subscription-data/{ueId}/`, e.g.
/// `identity-data`, `pp-data` or `pp-data-store/{afInstanceId}`.
fn subscription_data_path(ue_id: &str, resource: &str) -> String {
    format!("/nudr-dr/v2/subscription-data/{ue_id}/{resource}")
}

/// GET a UDR `subscription-data` resource (#85: identity-data, pp-data, ...).
pub async fn udm_nudr_dr_send_subscription_data_get(
    ue_id: &str,
    resource: &str,
) -> Result<SbiResponse, String> {
    let path = subscription_data_path(ue_id, resource);
    udm_sbi_discover_and_send_nudr_dr(0, 0, SbiRequest::get(&path)).await
}

/// PUT a UDR `subscription-data` resource (#85: pp-data-store entries).
pub async fn udm_nudr_dr_send_subscription_data_put(
    ue_id: &str,
    resource: &str,
    body: &serde_json::Value,
) -> Result<SbiResponse, String> {
    let path = subscription_data_path(ue_id, resource);
    let request = SbiRequest::put(&path)
        .with_json_body(body)
        .map_err(|e| format!("Failed to serialize {resource}: {e}"))?;
    udm_sbi_discover_and_send_nudr_dr(0, 0, request).await
}

/// PATCH a UDR `subscription-data` resource (#85: pp-data provisioning).
pub async fn udm_nudr_dr_send_subscription_data_patch(
    ue_id: &str,
    resource: &str,
    body: &serde_json::Value,
) -> Result<SbiResponse, String> {
    let path = subscription_data_path(ue_id, resource);
    let request = SbiRequest::patch(&path)
        .with_json_body(body)
        .map_err(|e| format!("Failed to serialize {resource} patch: {e}"))?;
    udm_sbi_discover_and_send_nudr_dr(0, 0, request).await
}

/// DELETE a UDR `subscription-data` resource (#85: pp-data-store entries).
pub async fn udm_nudr_dr_send_subscription_data_delete(
    ue_id: &str,
    resource: &str,
) -> Result<SbiResponse, String> {
    let path = subscription_data_path(ue_id, resource);
    udm_sbi_discover_and_send_nudr_dr(0, 0, SbiRequest::delete(&path)).await
}

// ---------------------------------------------------------------------------
// Namf_MT client (#85 Nudm_MT QueryUeInfo, TS 29.518 §5.4.2.3)
// ---------------------------------------------------------------------------

/// `GET /namf-mt/v1/ue-contexts/{supi}?info-class=...` on the UE's serving AMF —
/// Namf_MT_ProvideDomainSelectionInfo (TS 29.518 §5.4.2.3).
///
/// Nudm_MT `QueryUeInfo` is a proxy operation: the UE information the consumer
/// asks for (T-ADS) lives in the AMF, not the UDM (TS 29.503 §5.10.2.2). AMF
/// selection therefore prefers the `amfInstanceId` recorded in the UE's UECM
/// registration — the AMF that is actually serving this UE — and falls back to a
/// cached AMF instance, then to the `AMF_SBI_ADDR`/`AMF_SBI_PORT` env vars
/// (mirrors the AUSF helpers above). Asking an arbitrary AMF would answer with
/// another AMF's view of a UE it does not serve.
pub async fn udm_amf_send_mt_ue_context_info(
    amf_instance_id: Option<&str>,
    supi: &str,
    info_class: &str,
) -> Result<SbiResponse, String> {
    let path = format!("/namf-mt/v1/ue-contexts/{supi}");
    let build_request = || SbiRequest::get(&path).with_param("info-class", info_class);

    if let Some(id) = amf_instance_id {
        if global_context().get_nf_instance(id).await.is_some() {
            return udm_sbi_send_request(id, build_request()).await;
        }
    }

    let sbi_ctx = global_context();
    let amf_instances = sbi_ctx.find_nf_instances_by_type(NfType::Amf).await;
    if let Some(amf) = amf_instances.first() {
        let host = amf
            .ipv4_addresses
            .first()
            .ok_or("AMF instance has no IPv4 address")?;
        let port = amf.services.first().map(|s| s.port).unwrap_or(80);
        let client = sbi_ctx.get_client(host, port).await;
        return client
            .send_request(build_request())
            .await
            .map_err(|e| format!("Namf_MT request to AMF failed: {e}"));
    }

    let host = std::env::var("AMF_SBI_ADDR")
        .map_err(|_| "No AMF instance discovered and AMF_SBI_ADDR not set".to_string())?;
    let port: u16 = std::env::var("AMF_SBI_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7777);
    let client = sbi_ctx.get_client(&host, port).await;
    client
        .send_request(build_request())
        .await
        .map_err(|e| format!("Namf_MT request to AMF failed: {e}"))
}

/// DELETE the UDR authentication-status resource for a SUPI (#84 `DeleteAuth`).
///
/// TS 29.503 §5.4.2.3.3: `DeleteAuth` removes the authentication result the UDM
/// stored on `ConfirmAuth`, which lives in the UDR
/// (`authentication-data/authentication-status`, TS 29.505 §6.3.3). The
/// collection form is addressed because the UDM stores one status per serving
/// network and an `authEventId` names the UDM's own resource, not a network.
///
/// Builds: `DELETE /nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-status`
pub async fn udm_nudr_dr_send_auth_status_delete(supi: &str) -> Result<SbiResponse, String> {
    let path =
        format!("/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-status");
    udm_sbi_discover_and_send_nudr_dr(0, 0, SbiRequest::delete(&path)).await
}

/// Parse an absolute SBI callback URI into `(host, port, path)`.
///
/// Returns `None` for a relative URI (no scheme/authority) since a host cannot
/// be resolved — the caller treats that as a best-effort skip.
fn parse_callback_uri(uri: &str) -> Option<(String, u16, String)> {
    let (default_port, without_scheme) = if let Some(rest) = uri.strip_prefix("https://") {
        (443u16, rest)
    } else if let Some(rest) = uri.strip_prefix("http://") {
        (80u16, rest)
    } else {
        return None;
    };
    let (authority, path) = match without_scheme.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (without_scheme, "/".to_string()),
    };
    if authority.is_empty() {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), default_port),
    };
    Some((host, port, path))
}

/// POST a `DeregistrationData` to an old AMF's deregistration callback URI
/// (udmd-02, TS 29.503 §5.3.2.3.2). Best-effort: the caller logs failures and
/// does not fail the new registration.
pub async fn udm_sbi_send_dereg_notification(
    callback_uri: &str,
    body: &serde_json::Value,
) -> Result<SbiResponse, String> {
    udm_sbi_send_callback_notification(callback_uri, body).await
}

/// POST a notification body to an absolute `callbackReference` supplied by a
/// consumer.
///
/// Shared by the UECM dereg notification and by the SDM / EE producers (#83):
/// all three are "POST this JSON to the absolute URI the consumer gave us", and
/// having one implementation means a fix to the URI parsing or the client reaches
/// every notification the UDM sends.
pub async fn udm_sbi_send_callback_notification(
    callback_uri: &str,
    body: &serde_json::Value,
) -> Result<SbiResponse, String> {
    let (host, port, path) = parse_callback_uri(callback_uri)
        .ok_or_else(|| format!("callback reference is not an absolute URI: {callback_uri}"))?;
    let client = global_context().get_client(&host, port).await;
    client
        .post_json(&path, body)
        .await
        .map_err(|e| format!("Notification POST to {callback_uri} failed: {e}"))
}

// ---------------------------------------------------------------------------
// Nausf_SoRProtection client (Wave-6 F-04, TS 29.509 / TS 33.501 §6.14.2.1)
// ---------------------------------------------------------------------------

/// POST a `SorInfo` to the AUSF's Nausf_SoRProtection Protect custom operation
/// (`POST /nausf-sorprotection/v1/{supi}/ue-sor`, specs/TS29509_Nausf_SoRProtection.yaml:27).
///
/// AUSF selection (TS 33.501 §6.14.2.1 step 8 — "the AUSF that holds the latest
/// K_AUSF"): prefer the `ausf_instance_id` captured at authentication time;
/// fall back to a cached AUSF instance, then to the `AUSF_SBI_ADDR`/
/// `AUSF_SBI_PORT` env vars (mirrors the UDR fallback). When none resolves the
/// call errors and the caller withholds `sorInfo` (fail-closed).
pub async fn udm_ausf_send_sor_protect(
    supi: &str,
    ausf_instance_id: Option<&str>,
    sor_info: &serde_json::Value,
) -> Result<SbiResponse, String> {
    let path = format!("/nausf-sorprotection/v1/{supi}/ue-sor");
    let build_request = || {
        SbiRequest::post(&path)
            .with_json_body(sor_info)
            .map_err(|e| format!("Failed to serialize SorInfo: {e}"))
    };

    // 1. Prefer the AUSF that authenticated this UE (holds the latest KAUSF).
    if let Some(id) = ausf_instance_id {
        if global_context().get_nf_instance(id).await.is_some() {
            return udm_sbi_send_request(id, build_request()?).await;
        }
    }

    let sbi_ctx = global_context();

    // 2. Any cached AUSF instance discovered via NRF.
    let ausf_instances = sbi_ctx.find_nf_instances_by_type(NfType::Ausf).await;
    if let Some(ausf) = ausf_instances.first() {
        let host = ausf
            .ipv4_addresses
            .first()
            .ok_or("AUSF instance has no IPv4 address")?;
        let port = ausf.services.first().map(|s| s.port).unwrap_or(80);
        let client = sbi_ctx.get_client(host, port).await;
        return client
            .send_request(build_request()?)
            .await
            .map_err(|e| format!("Nausf_SoRProtection request to AUSF failed: {e}"));
    }

    // 3. Env-var fallback (matches the UDR env fallback pattern).
    let host = std::env::var("AUSF_SBI_ADDR")
        .map_err(|_| "No AUSF instance discovered and AUSF_SBI_ADDR not set".to_string())?;
    let port: u16 = std::env::var("AUSF_SBI_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7777);
    let client = sbi_ctx.get_client(&host, port).await;
    client
        .send_request(build_request()?)
        .await
        .map_err(|e| format!("Nausf_SoRProtection request to AUSF failed: {e}"))
}

// ---------------------------------------------------------------------------
// Nausf_UPUProtection client (Wave-6 F-05, TS 29.509 / TS 33.501 §6.15.2.1)
// ---------------------------------------------------------------------------

/// POST a `UpuInfo` to the AUSF's Nausf_UPUProtection Protect custom operation
/// (`POST /nausf-upuprotection/v1/{supi}/ue-upu`, specs/TS29509_Nausf_UPUProtection.yaml:27).
///
/// AUSF selection (TS 33.501 §6.15.2.1 — "the AUSF that holds the latest
/// K_AUSF"): prefer the `ausf_instance_id` captured at authentication time;
/// fall back to a cached AUSF instance, then to the `AUSF_SBI_ADDR`/
/// `AUSF_SBI_PORT` env vars (mirrors the SoR helper). When none resolves the
/// call errors and the caller withholds `upuInfo` (fail-closed).
pub async fn udm_ausf_send_upu_protect(
    supi: &str,
    ausf_instance_id: Option<&str>,
    upu_info: &serde_json::Value,
) -> Result<SbiResponse, String> {
    let path = format!("/nausf-upuprotection/v1/{supi}/ue-upu");
    let build_request = || {
        SbiRequest::post(&path)
            .with_json_body(upu_info)
            .map_err(|e| format!("Failed to serialize UpuInfo: {e}"))
    };

    // 1. Prefer the AUSF that authenticated this UE (holds the latest KAUSF).
    if let Some(id) = ausf_instance_id {
        if global_context().get_nf_instance(id).await.is_some() {
            return udm_sbi_send_request(id, build_request()?).await;
        }
    }

    let sbi_ctx = global_context();

    // 2. Any cached AUSF instance discovered via NRF.
    let ausf_instances = sbi_ctx.find_nf_instances_by_type(NfType::Ausf).await;
    if let Some(ausf) = ausf_instances.first() {
        let host = ausf
            .ipv4_addresses
            .first()
            .ok_or("AUSF instance has no IPv4 address")?;
        let port = ausf.services.first().map(|s| s.port).unwrap_or(80);
        let client = sbi_ctx.get_client(host, port).await;
        return client
            .send_request(build_request()?)
            .await
            .map_err(|e| format!("Nausf_UPUProtection request to AUSF failed: {e}"));
    }

    // 3. Env-var fallback (matches the SoR env fallback pattern).
    let host = std::env::var("AUSF_SBI_ADDR")
        .map_err(|_| "No AUSF instance discovered and AUSF_SBI_ADDR not set".to_string())?;
    let port: u16 = std::env::var("AUSF_SBI_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7777);
    let client = sbi_ctx.get_client(&host, port).await;
    client
        .send_request(build_request()?)
        .await
        .map_err(|e| format!("Nausf_UPUProtection request to AUSF failed: {e}"))
}

/// SBI transaction for tracking requests
#[derive(Debug, Clone)]
pub struct SbiXact {
    /// Transaction ID
    pub id: u64,
    /// Associated SBI object ID (e.g., udm_ue_id)
    pub sbi_object_id: u64,
    /// Associated stream ID for response
    pub assoc_stream_id: u64,
    /// Service type
    pub service_type: String,
    /// State for multi-step operations
    pub state: u32,
}

impl SbiXact {
    /// Create a new SBI transaction
    pub fn new(id: u64, sbi_object_id: u64, service_type: &str) -> Self {
        Self {
            id,
            sbi_object_id,
            assoc_stream_id: 0,
            service_type: service_type.to_string(),
            state: 0,
        }
    }
}

/// SBI server handle (placeholder)
pub struct SbiServer {
    config: SbiServerConfig,
}

impl SbiServer {
    /// Create a new SBI server
    pub fn new(config: SbiServerConfig) -> Self {
        Self { config }
    }

    /// Get server URI
    pub fn uri(&self) -> String {
        let scheme = if self.config.tls_enabled {
            "https"
        } else {
            "http"
        };
        format!("{}://{}:{}", scheme, self.config.addr, self.config.port)
    }
}

// #242 removed `send_sbi_response(stream_id, SbiResponse)` from here. It was a
// LOGGING PLACEHOLDER -- it formatted a debug line and returned, with a comment
// saying a real implementation would look up the stream and queue the response --
// and its only callers were `sbi_response.rs`'s error helpers, reached solely
// from the unreachable state-machine request path. So every error response that
// path appeared to send (400, 403, 404, 405, 504) went nowhere even in principle,
// which is a second, independent reason that path could not have served a request.
// `udmd`'s live responses are built and sent by `app.rs::udm_sbi_route` through
// `nextgcore_sbi`'s own server, which needs no such shim.

#[cfg(test)]
mod tests {
    use super::*;

    /// #235: a TRANSPORT failure to a cached NF must evict that cached profile,
    /// so the next call re-discovers instead of retrying an endpoint the NRF may
    /// already have replaced. This is the WIRING, not the library helper — the
    /// helper has its own tests in `nextgcore-sbi`, and a passing helper test says
    /// nothing about whether any caller invokes it.
    ///
    /// Port 1 on loopback is used rather than an allocated-then-dropped port:
    /// binding it needs root, so nothing can be listening and the refusal is
    /// deterministic with no port allocation to contend on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transport_failure_evicts_the_cached_instance_by_id() {
        // The discovery cache is process-global and all three #235 tests below
        // seed `NfType::Udr` entries, so `.first()` in the by-type test could pick
        // up a sibling's profile. `CONTEXT_GUARD` is udmd's existing process-wide
        // test lock; poison-tolerant so one failing test does not turn its
        // siblings into misleading second failures.
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // The SBI profile defaults to Production, so `get_client` would build a
        // TLS client and fail loading /etc/nextgcore/tls/client.crt instead of
        // being refused by the port. That is still a transport failure, so the
        // eviction assertion would pass -- for the wrong reason, and only when
        // another test had not already forced Dev. Force it here so the failure
        // the test documents is the failure the test gets.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

        let sbi_ctx = global_context();
        let instance_id = "udmd-235-evict-by-id";

        let mut instance = NfInstance::new(instance_id, NfType::Udr);
        instance.ipv4_addresses.push("127.0.0.1".to_string());
        let mut svc = NfService::new("nudr-dr", SbiServiceType::NudrDr);
        svc.port = 1;
        instance.add_service(svc);
        sbi_ctx
            .add_nf_instance_with_validity(instance, std::time::Duration::from_secs(3600))
            .await;
        assert!(
            sbi_ctx.get_nf_instance(instance_id).await.is_some(),
            "precondition: the profile is cached and live"
        );

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            udm_sbi_send_request(instance_id, SbiRequest::get("/nudr-dr/v2/ping")),
        )
        .await
        .expect("the refused connection must not hang");
        assert!(result.is_err(), "connecting to a closed port must fail");

        assert!(
            sbi_ctx.get_nf_instance(instance_id).await.is_none(),
            "a transport failure must evict the cached profile"
        );
    }

    /// The same wiring on the by-type selection path (`find_nf_instances_by_type`
    /// then send), which resolves the UDR without being handed an ID. Kept as its
    /// own test because the two paths evict from different places: this one has to
    /// remember which instance it selected.
    ///
    /// `.first()` over a process-global map is order-dependent, and the two
    /// sibling tests here also seed `NfType::Udr` entries — this test DID pick up
    /// the by-id test's profile and evict that instead, intermittently, before the
    /// guard below was added. Do not remove the guard on the grounds that the IDs
    /// are distinct: distinctness was never the problem, the shared view was.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transport_failure_evicts_the_selected_udr() {
        // The discovery cache is process-global and all three #235 tests below
        // seed `NfType::Udr` entries, so `.first()` in the by-type test could pick
        // up a sibling's profile. `CONTEXT_GUARD` is udmd's existing process-wide
        // test lock; poison-tolerant so one failing test does not turn its
        // siblings into misleading second failures.
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // See the sibling test: Dev profile so the failure is the refused
        // connection this test is about, not a missing TLS certificate.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

        let sbi_ctx = global_context();
        let instance_id = "udmd-235-evict-selected-udr";

        let mut instance = NfInstance::new(instance_id, NfType::Udr);
        instance.ipv4_addresses.push("127.0.0.1".to_string());
        let mut svc = NfService::new("nudr-dr", SbiServiceType::NudrDr);
        svc.port = 1;
        instance.add_service(svc);
        sbi_ctx
            .add_nf_instance_with_validity(instance, std::time::Duration::from_secs(3600))
            .await;

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            udm_sbi_discover_and_send_nudr_dr(1, 1, SbiRequest::get("/nudr-dr/v2/ping")),
        )
        .await
        .expect("the refused connection must not hang");
        assert!(result.is_err(), "connecting to a closed port must fail");

        assert!(
            sbi_ctx.get_nf_instance(instance_id).await.is_none(),
            "a transport failure must evict the UDR profile that was selected"
        );
    }

    /// #235: the discovery WIRING — a profile learned from the NRF must carry the
    /// SearchResult's `validityPeriod` into the cache, not be cached forever.
    ///
    /// Driven through the real `udm_nrf_discover` against a stub NRF, because the
    /// interesting failure is a discovery path that calls `add_nf_instance`
    /// (permanent) instead of `add_nf_instance_with_validity`. A library-level
    /// test cannot see that: the plain method still works, it is just the wrong
    /// one to call. `validityPeriod: 0` makes the assertion immediate and
    /// sleep-free.
    ///
    /// The other three discovery writers (`amfd`, `ausfd`, `nssfd`) have the same
    /// three lines and no equivalent test — see the spec's Ceilings section.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discovery_honours_the_search_result_validity_period() {
        // The discovery cache is process-global and all three #235 tests below
        // seed `NfType::Udr` entries, so `.first()` in the by-type test could pick
        // up a sibling's profile. `CONTEXT_GUARD` is udmd's existing process-wide
        // test lock; poison-tolerant so one failing test does not turn its
        // siblings into misleading second failures.
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Dev profile: the stub NRF below is plain HTTP, and the default
        // Production profile would make the client attempt TLS against it.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

        let (addr_listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = nextgcore_sbi::server::SbiServer::on_listener(
            nextgcore_sbi::server::SbiServerConfig::new(addr),
            addr_listener,
        );
        server
            .start(|_req: SbiRequest| async move {
                let body = serde_json::json!({
                    // The NRF says "do not cache this". Honouring it is the point.
                    "validityPeriod": 0,
                    "nfInstances": [{
                        "nfInstanceId": "udmd-235-validity-udr",
                        "nfType": "UDR",
                        "nfStatus": "REGISTERED",
                        "ipv4Addresses": ["127.0.0.1"],
                    }]
                });
                SbiResponse::ok().with_json_body(&body).unwrap()
            })
            .await
            .expect("stub NRF starts");

        let sbi_ctx = global_context();
        // `udm_nrf_discover` refuses to run without a self instance.
        sbi_ctx
            .set_self_instance(NfInstance::new("udmd-235-self", NfType::Udm))
            .await;

        let discovered = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            udm_nrf_discover("127.0.0.1", addr.port(), NfType::Udr),
        )
        .await
        .expect("discovery must not hang")
        .expect("discovery succeeds");
        assert_eq!(discovered.len(), 1, "the stub returned one profile");

        // Returned to the caller, but NOT selectable from the cache: a zero
        // validityPeriod means this answer was good for this call only.
        assert!(
            sbi_ctx
                .get_nf_instance("udmd-235-validity-udr")
                .await
                .is_none(),
            "a zero validityPeriod must not leave a selectable cache entry"
        );

        server.stop().await.expect("stub NRF stops");
    }

    #[test]
    fn test_sbi_server_config_default() {
        let config = SbiServerConfig::default();
        assert_eq!(config.addr, "127.0.0.1");
        assert_eq!(config.port, 7777);
        assert!(!config.tls_enabled);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_sbi_open_close() {
        assert!(!udm_sbi_is_running());

        udm_sbi_open(None).unwrap();
        assert!(udm_sbi_is_running());

        udm_sbi_close();
        assert!(!udm_sbi_is_running());
    }

    #[test]
    fn test_sbi_server_uri() {
        let config = SbiServerConfig {
            addr: "192.168.1.1".to_string(),
            port: 8080,
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
        };
        let server = SbiServer::new(config);
        assert_eq!(server.uri(), "http://192.168.1.1:8080");
    }

    #[test]
    fn test_sbi_server_uri_tls() {
        let config = SbiServerConfig {
            addr: "192.168.1.1".to_string(),
            port: 8443,
            tls_enabled: true,
            tls_cert: Some("/path/to/cert".to_string()),
            tls_key: Some("/path/to/key".to_string()),
        };
        let server = SbiServer::new(config);
        assert_eq!(server.uri(), "https://192.168.1.1:8443");
    }

    #[test]
    fn test_sbi_xact() {
        let xact = SbiXact::new(1, 100, "nudm-ueau");
        assert_eq!(xact.id, 1);
        assert_eq!(xact.sbi_object_id, 100);
        assert_eq!(xact.service_type, "nudm-ueau");
        assert_eq!(xact.state, 0);
    }

    /// WSB-4: amfd now registers an ABSOLUTE deregCallbackUri (it was relative,
    /// which `parse_callback_uri` rejected -> the DeregistrationNotification
    /// round trip was broken). The absolute URI must parse; the old relative
    /// form must still be rejected (fail-closed, TS 29.503 §5.3.2.3.2 Uri).
    #[test]
    fn parse_callback_uri_accepts_absolute_amf_dereg_uri() {
        let uri = "http://127.0.0.1:7777/namf-callback/v1/imsi-001010000000001/dereg-notify";
        assert_eq!(
            parse_callback_uri(uri),
            Some((
                "127.0.0.1".to_string(),
                7777,
                "/namf-callback/v1/imsi-001010000000001/dereg-notify".to_string(),
            ))
        );
        // The pre-WSB-4 relative amfd URI is still rejected (no host to POST).
        assert_eq!(
            parse_callback_uri("/namf-callback/v1/imsi-001010000000001/dereg-notify"),
            None
        );
    }
}
