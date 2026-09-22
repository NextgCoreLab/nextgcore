//! BSF SBI Path Functions
//!
//! Port of src/bsf/sbi-path.c - SBI server/client path functions

use std::sync::atomic::{AtomicBool, Ordering};

use nextgcore_sbi::context::{global_context, NfInstance, NfService};
use nextgcore_sbi::types::{NfType, SbiServiceType, UriScheme};

/// SBI server configuration
#[derive(Debug, Clone)]
pub struct SbiServerConfig {
    pub addr: String,
    pub port: u16,
    pub tls_enabled: bool,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub nrf_uri: Option<String>,
}

impl Default for SbiServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 7777,
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
            nrf_uri: None,
        }
    }
}

/// SBI server state
static SBI_SERVER_RUNNING: AtomicBool = AtomicBool::new(false);

/// Parse host and port from a URI string (e.g., "http://127.0.0.1:7777")
fn parse_uri_host_port(uri_str: &str) -> Result<(String, u16), String> {
    let stripped = uri_str
        .strip_prefix("https://")
        .or_else(|| uri_str.strip_prefix("http://"))
        .unwrap_or(uri_str);
    let (host, port_str) = if let Some(idx) = stripped.rfind(':') {
        (&stripped[..idx], &stripped[idx + 1..])
    } else {
        (
            stripped,
            if uri_str.starts_with("https") {
                "443"
            } else {
                "80"
            },
        )
    };
    let port: u16 = port_str
        .split('/')
        .next()
        .unwrap_or(port_str)
        .parse()
        .map_err(|e| format!("Invalid port in URI: {e}"))?;
    Ok((host.to_string(), port))
}

/// Every service this BSF serves, with the NF types allowed to consume it
/// (TS 29.510 §6.1.6.2.3 `NFService.allowedNfTypes`).
///
/// ONE table, consumed by [`build_bsf_nf_instance`] here and by
/// `lib.rs`'s `bsf_nf_profile_json`, so the self instance and the registered
/// NFProfile cannot disagree (#392).
///
/// TS 23.501 §6.2.19 and TS 29.521 define the BSF as a producer of binding
/// management only; it originates no service request in that role, so this is
/// the whole advertised surface.
pub const BSF_SERVICES: &[(SbiServiceType, &[&str])] = &[
    // TS 29.521 Nbsf_Management. The PCF registers and the AF/NEF/SMF look up
    // PCF bindings; SCP is allowed because it proxies on their behalf.
    (
        SbiServiceType::NbsfManagement,
        &["PCF", "AF", "NEF", "SMF", "SCP"],
    ),
];

/// The NF types allowed to consume `service_name`, or an empty slice for a
/// service this BSF does not serve.
pub fn allowed_nf_types_for(service_name: &str) -> &'static [&'static str] {
    BSF_SERVICES
        .iter()
        .find(|(t, _)| t.to_name() == service_name)
        .map(|(_, allowed)| *allowed)
        .unwrap_or(&[])
}

/// Build the BSF NF instance with service information
fn build_bsf_nf_instance(config: &SbiServerConfig) -> NfInstance {
    // Issue #187: the BSF's self NF instance must carry the SAME nfInstanceId its
    // OAuth2 client asserts in a CCA, or the NRF has a trusted key for one identity
    // and a registration for another.
    let nf_id = nextgcore_sbi::nf_instance_id::nf_instance_id(NfType::Bsf).to_string();
    let mut nf_instance = NfInstance::new(&nf_id, NfType::Bsf);

    nf_instance.ipv4_addresses.push(config.addr.clone());
    nf_instance.heartbeat_interval = 10;

    let scheme = if config.tls_enabled {
        UriScheme::Https
    } else {
        UriScheme::Http
    };

    for (service_type, _allowed) in BSF_SERVICES {
        let mut svc = NfService::new(service_type.to_name(), *service_type);
        svc.scheme = scheme;
        svc.ip_addresses.push(config.addr.clone());
        svc.port = config.port;
        nf_instance.add_service(svc);
    }

    nf_instance
}

/// Open the SBI server context: publish the self NF instance and the NRF URI.
///
/// Port of bsf_sbi_open.
///
/// #392: this function used to also PUT an NFProfile to the NRF, so every BSF
/// startup registered TWICE — once here and once from `lib.rs` after the
/// listener came up. Both now target the same `nfInstanceId` (#187), so the
/// second was an idempotent overwrite, and the profile the NRF served was
/// whichever PUT landed last. The two were not equivalent: this one carried no
/// per-service `ipEndPoints` and no `allowedNfTypes`, so a consumer that
/// discovered `nbsf-management` from it had no port to dial. Worse, it fired
/// BEFORE `sbi_server.start()`, advertising an endpoint that would have refused
/// the first consumer to connect.
///
/// Registration therefore happens exactly once, from `lib.rs`'s
/// `register_with_nrf`, after the listener accepts. This is the same treatment
/// PR #237 applied to `pcfd`.
pub fn bsf_sbi_open(config: Option<SbiServerConfig>) -> Result<(), String> {
    if SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        return Err("SBI server already running".to_string());
    }

    let config = config.unwrap_or_default();

    log::info!("Opening BSF SBI server on {}:{}", config.addr, config.port);

    let nf_instance = build_bsf_nf_instance(&config);
    let nf_id = nf_instance.id.clone();
    let nrf_uri_clone = config.nrf_uri.clone();

    let sbi_ctx = global_context();
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            sbi_ctx.set_self_instance(nf_instance).await;
            if let Some(ref nrf_uri) = nrf_uri_clone {
                sbi_ctx.set_nrf_uri(nrf_uri).await;
            } else {
                log::info!("No NRF URI configured, BSF running in standalone mode");
            }
        });
    } else {
        log::debug!("No tokio runtime available, skipping self-instance publication");
    }

    log::info!("BSF NF instance built (id={nf_id})");

    SBI_SERVER_RUNNING.store(true, Ordering::SeqCst);

    log::info!("BSF SBI server opened successfully");
    Ok(())
}

/// Close SBI server and deregister from NRF
/// Port of bsf_sbi_close
pub fn bsf_sbi_close() {
    if !SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    log::info!("Closing BSF SBI server");

    // Attempt async deregistration (only if tokio runtime is available)
    let sbi_ctx = global_context();
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            if let (Some(nrf_uri), Some(self_instance)) = (
                sbi_ctx.get_nrf_uri().await,
                sbi_ctx.get_self_instance().await,
            ) {
                if let Ok((host, port)) = parse_uri_host_port(&nrf_uri) {
                    let client = sbi_ctx.get_client(&host, port).await;
                    let path = format!("/nnrf-nfm/v1/nf-instances/{}", self_instance.id);
                    if let Err(e) = client.delete(&path).await {
                        log::warn!("Failed to deregister BSF from NRF: {e}");
                    } else {
                        log::info!("BSF deregistered from NRF");
                    }
                }
            }
            sbi_ctx.clear_clients().await;
        });
    }

    SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

    log::info!("BSF SBI server closed");
}

/// Check if SBI server is running
pub fn bsf_sbi_is_running() -> bool {
    SBI_SERVER_RUNNING.load(Ordering::SeqCst)
}

// #234: a dead consumer-side NRF-discovery path used to live here. Removed:
// `PathSbiRequestBuilder`, `PathSbiRequest`, `SbiXact`, `bsf_sbi_send_request`,
// `bsf_sbi_discover_and_send` and `bsf_sbi_send_response`.
//
// The first two of those functions logged at debug, did nothing, and returned a
// FABRICATED `Ok(1)` transaction ID -- a stub that lies to its caller. The third
// returned `Ok(())` without sending anything, and had no caller but its own test.
// `SbiXact` had no reference anywhere in the crate, not even a test, and
// `PathSbiRequestBuilder` only named the struct beside it.
//
// "Wire it per TS 29.521 / TS 29.510" was ruled out on evidence rather than left
// open, so it is not re-litigated: bsfd's `nnrf-nfm` obligations are ALREADY
// complete (`register_with_nrf` PUTs the profile, `spawn_heartbeat_worker_with_load`
// runs in `lib.rs`, and `bsf_sbi_close` tears down); TS 23.501 6.2.19 and TS 29.521
// define the BSF as a PRODUCER of binding management with no originated service
// request for that role; and the giveaway was that the discovery handler hardcoded
// `GET /nbsf-management/v1/pcf-bindings`, i.e. it would have had the BSF query ITS
// OWN SERVICE on another NF. That is a copy-paste artefact of the C port, not a
// procedure. Implementing a generic discover-and-send would have invented a
// capability nothing asked for.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbi_server_config_default() {
        let config = SbiServerConfig::default();
        assert_eq!(config.addr, "127.0.0.1");
        assert_eq!(config.port, 7777);
        assert!(!config.tls_enabled);
    }

    #[test]
    fn test_sbi_open_close() {
        // Reset state
        SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

        let result = bsf_sbi_open(None);
        assert!(result.is_ok());
        assert!(bsf_sbi_is_running());

        // Try to open again while running - should fail
        let result = bsf_sbi_open(None);
        assert!(result.is_err());

        bsf_sbi_close();
        assert!(!bsf_sbi_is_running());
    }
}
