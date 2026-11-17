//! #1529: the EES as an AF toward the 5GC, and an OAuth2 client of the NFs it
//! calls.
//!
//! TS 23.558 §6.2 (`23558-k20.txt:2698-2700`): "The ECS, EES and EAS act as AFs
//! for consuming network services from the 3GPP 5G Core Network entities over the
//! Service Based Architecture". TS 29.510 has no `EES` `NFType`, so the EES's
//! identity at the NRF is an `AF` NF instance; the AF is a named consumer of
//! `Nsmf_EventExposure` (TS 29.508 §4.1.3.2, `29508-k00.txt:603-621`).
//!
//! TS 33.501 §13.4.1.1.2: a consumer obtains an access token from the NRF (the
//! client credentials grant, TS 29.510 `Nnrf_AccessToken`) and presents it on its
//! request; TS 29.500 §6.7.3 puts it in `Authorization: Bearer`. nrfd only issues
//! a token to a requester it has registered, so with `--nrf-uri` the EES first
//! registers an `AF` NFProfile (no services: it produces none to 5GC consumers),
//! heartbeats it, and deregisters it at shutdown. Its client authentication to
//! the NRF is the shared CCA (`NEXTGCORE_SBI_CCA_SIGNING_KEY_FILE`, public half
//! published under `NEXTGCORE_SBI_CCA_PUBLIC_JWK_DIR`), as for every other NF.
//!
//! Without `--nrf-uri` nothing changes: no registration, no token, and an SMF
//! that enforces OAuth2 refuses the request (the refusal is counted, #1523).

use std::sync::{Arc, OnceLock};

use nextgcore_sbi::oauth::OAuth2Client;
use nextgcore_sbi::types::NfType;

/// The token client, installed once by [`start`] when `--nrf-uri` is set.
static OAUTH2_CLIENT: OnceLock<Arc<OAuth2Client>> = OnceLock::new();

/// The OAuth2 client outbound requests to 5GC NFs attach their token with, if
/// this EES has an NRF (`--nrf-uri`).
pub fn oauth2_client() -> Option<Arc<OAuth2Client>> {
    #[cfg(test)]
    if let Some(client) = OAUTH2_CLIENT_TEST_OVERRIDE
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
    {
        return Some(client);
    }
    OAUTH2_CLIENT.get().cloned()
}

/// Tests: a client [`oauth2_client`] returns instead of the once-set one.
#[cfg(test)]
pub(crate) static OAUTH2_CLIENT_TEST_OVERRIDE: std::sync::RwLock<Option<Arc<OAuth2Client>>> =
    std::sync::RwLock::new(None);

/// The `AF` NFProfile (TS 29.510 Table 6.1.6.2.2-1) this EES registers: the
/// three mandatory attributes, its address, the heartbeat timer, and one
/// `nfServices` entry, `eees-eeccontextreloc` at `scheme://host:port`, offered
/// to AF consumers.
///
/// #1664: the EEC context relocation pull (EDGE-9) carries an NRF-issued token
/// of scope `eees-eeccontextreloc` (operator decision, option 1). nrfd issues a
/// scope only when a registered producer of the target type offers it
/// (TS 33.501 §13.4.1.1.2 step 2), so each EES, the S-EES side of that pull,
/// offers it here. No service is offered to 5GC consumers.
pub fn af_profile(nf_instance_id: &str, host: &str, scheme: &str, port: u16) -> serde_json::Value {
    nextgcore_sbi::nf_addressing::classify_profile_host(
        serde_json::json!({
            "nfInstanceId": nf_instance_id,
            "nfType": NfType::Af.to_str(),
            "nfStatus": "REGISTERED",
            "ipv4Addresses": [host],
            "heartBeatTimer": 10,
            "nfServices": [{
                "serviceInstanceId": crate::auth::SCOPE_EECCONTEXTRELOC,
                "serviceName": crate::auth::SCOPE_EECCONTEXTRELOC,
                "versions": [{ "apiVersionInUri": "v1", "apiFullVersion": "1.2.0" }],
                "scheme": scheme,
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{ "port": port }],
                "allowedNfTypes": [NfType::Af.to_str()]
            }]
        }),
        host,
    )
}

/// The AF's `nfInstanceId` for this process's shared instance id `shared` (the
/// eesId). TS 29.571 `NfInstanceId` is `format: uuid`, but `--ees-id` may be any
/// string (`ees1.example.com`). A hyphenated UUID is used as it is (lower-cased),
/// so one id names
/// the EES at the ECS and the NRF; anything else maps to a stable name-based UUID
/// (RFC 9562 version 8, the first 16 octets of SHA-256 over a fixed prefix and the
/// eesId), so a restart with the same `--ees-id` registers, and is trusted by a
/// CCA trust store, under the same id.
pub fn af_instance_id(shared: &str) -> String {
    if let Ok(u) = uuid::Uuid::try_parse(shared) {
        if u.hyphenated().to_string() == shared.to_ascii_lowercase() {
            return u.hyphenated().to_string();
        }
    }
    use sha2::Digest;
    let digest = sha2::Sha256::digest(format!("nextgcore-ees-af:{shared}").as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_custom_bytes(bytes)
        .into_uuid()
        .hyphenated()
        .to_string()
}

/// One NFRegister (PUT) of [`af_profile`] at `nrf_uri`.
async fn register_once(
    nrf_uri: &str,
    nf_instance_id: &str,
    host: &str,
    scheme: &str,
    port: u16,
) -> Result<(), String> {
    let (nrf_host, nrf_port) = crate::ecs_registration::parse_host_port(nrf_uri)
        .ok_or_else(|| format!("invalid --nrf-uri {nrf_uri:?}"))?;
    let client = nextgcore_sbi::context::global_context()
        .get_client(&nrf_host, nrf_port)
        .await;
    let profile = af_profile(nf_instance_id, host, scheme, port);
    let resp = client
        .put_json(
            &format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}"),
            &profile,
        )
        .await
        .map_err(|e| format!("NFRegister failed: {e}"))?;
    match resp.status {
        200 | 201 => {
            log::info!(
                "EES registered at the NRF as AF nfInstanceId {nf_instance_id} \
                 (TS 23.558 §6.2), for 5GC access tokens"
            );
            // #434: what a 404 heartbeat re-registers if the NRF loses us.
            nextgcore_sbi::heartbeat::set_registered_profile(&profile);
            Ok(())
        }
        status => Err(format!("NFRegister answered {status}")),
    }
}

/// With an NRF: install the token client and register this EES as an AF
/// (retried in the background on failure, #1482; the heartbeat starts after the
/// attempt that succeeds). The client is installed first: a token request made
/// before the registration lands is refused by the NRF and retried by the
/// caller, which is the same state as an NRF that is down.
pub async fn start(nrf_uri: &str, host: &str, scheme: &str, port: u16) {
    let shared = nextgcore_sbi::nf_instance_id::nf_instance_id(NfType::Af);
    let nf_instance_id = af_instance_id(shared);
    if nf_instance_id != shared {
        log::info!(
            "AF nfInstanceId {nf_instance_id}: derived from the eesId {shared:?}, which is not \
             a UUID (TS 29.571 NfInstanceId); provision the CCA trust store under this id"
        );
    }
    let ctx = nextgcore_sbi::context::global_context();
    ctx.set_nrf_uri(nrf_uri).await;
    let _ = OAUTH2_CLIENT.set(Arc::new(OAuth2Client::new(
        nrf_uri,
        nf_instance_id.clone(),
        NfType::Af,
    )));
    let (nrf_uri, host, id, scheme) = (
        nrf_uri.to_string(),
        host.to_string(),
        nf_instance_id,
        scheme.to_string(),
    );
    nextgcore_sbi::heartbeat::register_or_retry(
        "EES",
        Default::default(),
        move || {
            let (nrf_uri, host, id, scheme) =
                (nrf_uri.clone(), host.clone(), id.clone(), scheme.clone());
            async move {
                register_once(&nrf_uri, &id, &host, &scheme, port)
                    .await
                    .map(|()| Some(id))
            }
        },
        |nf_instance_id| nextgcore_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id, 5),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A UUID eesId is the AF id as it is; any other eesId (`--ees-id
    /// ees1.example.com`) maps to a stable, canonical UUID, never to itself.
    #[test]
    fn the_af_instance_id_is_always_a_uuid() {
        let id = "6b1d7e3c-1529-4000-8000-000000000001";
        assert_eq!(af_instance_id(id), id);
        assert_eq!(af_instance_id(&id.to_ascii_uppercase()), id);
        for other in [
            "ees1.example.com",
            "ees-1",
            "6b1d7e3c152940008000000000000001",
            "",
        ] {
            let derived = af_instance_id(other);
            let u = uuid::Uuid::try_parse(&derived).expect("a UUID");
            assert_eq!(u.hyphenated().to_string(), derived, "canonical form");
            assert_ne!(derived, other);
            assert_eq!(af_instance_id(other), derived, "stable");
        }
        assert_ne!(
            af_instance_id("ees1.example.com"),
            af_instance_id("ees2.example.com")
        );
    }

    /// The profile nrfd needs to issue this EES a token: an AF instance, the
    /// three mandatory attributes, and (#1664) the one service an EES peer pulls
    /// with a token, `eees-eeccontextreloc`, offered to AF consumers only.
    #[test]
    fn the_af_profile_is_a_minimal_af_instance() {
        let p = af_profile(
            "6b1d7e3c-1529-4000-8000-000000000001",
            "10.0.0.7",
            "https",
            7443,
        );
        assert_eq!(p["nfType"], "AF");
        assert_eq!(p["nfStatus"], "REGISTERED");
        assert_eq!(p["nfInstanceId"], "6b1d7e3c-1529-4000-8000-000000000001");
        assert_eq!(p["ipv4Addresses"], serde_json::json!(["10.0.0.7"]));
        let svc = &p["nfServices"][0];
        assert_eq!(p["nfServices"].as_array().map(Vec::len), Some(1));
        assert_eq!(svc["serviceName"], "eees-eeccontextreloc");
        assert_eq!(svc["scheme"], "https");
        assert_eq!(svc["ipEndPoints"][0]["port"], 7443);
        assert_eq!(svc["allowedNfTypes"], serde_json::json!(["AF"]));
        let v6 = af_profile(
            "6b1d7e3c-1529-4000-8000-000000000001",
            "fd00::7",
            "http",
            7777,
        );
        assert_eq!(v6["ipv6Addresses"], serde_json::json!(["fd00::7"]));
        assert!(v6.get("ipv4Addresses").is_none());
    }
}
