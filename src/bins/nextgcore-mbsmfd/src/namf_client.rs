//! MB-SMF -> AMF client: AMF discovery and the Namf MBS invocations
//! (TS 23.247 §7.2.5.2 and §7.3.1 step 2, TS 29.518 §5.6-5.7).
//!
//! Before this module the create handler terminated at `session_add` and no AMF
//! interaction happened at all, so the N2 MBS SM containers this MB-SMF builds
//! correctly were never carried onward and the RAN never learned of a session.
//!
//! TS 23.247 §7.3.1 step 2 makes the AMF discovery the MB-SMF's job: it selects
//! the serving AMF(s) for the MBS service area, then drives broadcast setup
//! toward the RAN through them.
//!
//! Resource names come from the OpenAPI in `6g_docs/specs`
//! (`TS29518_Namf_MBSBroadcast.yaml` server url `{apiRoot}/namf-mbs-bc/v1`,
//! `TS29518_Namf_MBSCommunication.yaml` `{apiRoot}/namf-mbs-comm/v1`), not from
//! prose.

use std::time::Duration;

use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
use nextgcore_sbi::context::global_context;
use serde_json::{json, Value};

use crate::context::Tmgi;

/// An AMF the MB-SMF may drive MBS N2 signalling through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredAmf {
    pub host: String,
    pub port: u16,
    pub nf_instance_id: Option<String>,
}

/// Discover an AMF serving MBS via the NRF
/// (`GET /nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=MB_SMF
/// &service-names=namf-mbs-bc`).
///
/// `None` on ANY failure -- no NRF configured, transport error, or no instance
/// advertising the service. The caller treats that as "no AMF to drive" and says
/// so, rather than falling back to a hardcoded address: a wrong AMF would set up
/// a bearer in the wrong service area.
pub async fn discover_amf() -> Option<DiscoveredAmf> {
    let nrf_uri = global_context().get_nrf_uri().await?;
    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri)?;

    let client = SbiClient::new(
        SbiClientConfig::new(nrf_host, nrf_port)
            .with_connect_timeout(Duration::from_secs(2))
            .with_request_timeout(Duration::from_secs(3)),
    );

    // `service-names` filters to AMFs that actually advertise the MBS broadcast
    // service; an AMF without it would 404 the ContextCreate.
    let path = "/nnrf-disc/v1/nf-instances?target-nf-type=AMF\
                &requester-nf-type=MB_SMF&service-names=namf-mbs-bc";
    let response = match client.get(path).await {
        Ok(r) => r,
        Err(e) => {
            log::warn!("MBS: NRF discovery of a serving AMF failed: {e}");
            return None;
        }
    };
    if response.status != 200 {
        log::warn!(
            "MBS: NRF discovery of a serving AMF returned status {}",
            response.status
        );
        return None;
    }

    let json: Value = serde_json::from_str(&response.http.content?).ok()?;
    parse_amf_search_result(&json)
}

/// Pick an AMF out of an NRF `SearchResult` (TS 29.510 §6.2.6.2.2).
///
/// Takes the first instance carrying a usable `namf-mbs-bc` endpoint. No
/// load-balancing or priority ordering: with one AMF in this deployment a
/// selection policy would be untestable code.
fn parse_amf_search_result(json: &Value) -> Option<DiscoveredAmf> {
    for instance in json.get("nfInstances")?.as_array()? {
        let nf_instance_id = instance
            .get("nfInstanceId")
            .and_then(Value::as_str)
            .map(str::to_owned);

        // Prefer an ipEndPoint on the namf-mbs-bc service, then fall back to the
        // instance's own ipv4Addresses -- the same order the other consumers use.
        let from_service = instance
            .get("nfServices")
            .and_then(Value::as_array)
            .and_then(|services| {
                services
                    .iter()
                    .filter(|s| {
                        s.get("serviceName")
                            .and_then(Value::as_str)
                            .is_some_and(|n| n == "namf-mbs-bc")
                    })
                    .find_map(|s| {
                        let ep = s.get("ipEndPoints")?.as_array()?.first()?;
                        let host = ep.get("ipv4Address").and_then(Value::as_str)?.to_owned();
                        let port = ep.get("port").and_then(Value::as_u64).unwrap_or(80) as u16;
                        Some((host, port))
                    })
            });

        let endpoint = from_service.or_else(|| {
            let host = instance
                .get("ipv4Addresses")?
                .as_array()?
                .first()?
                .as_str()?
                .to_owned();
            Some((host, 80))
        });

        if let Some((host, port)) = endpoint {
            return Some(DiscoveredAmf {
                host,
                port,
                nf_instance_id,
            });
        }
    }
    None
}

/// Split `http://host:port` (or bare `host:port`) into its parts.
fn parse_host_port(uri: &str) -> Option<(String, u16)> {
    let authority = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))
        .unwrap_or(uri)
        .split('/')
        .next()?;
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host.to_owned(), port.parse().ok()?)),
        None => Some((authority.to_owned(), 80)),
    }
}

/// `MbsSessionId` as TS 29.571 spells it, for a Namf request body.
fn mbs_session_id_json(tmgi: &Tmgi) -> Value {
    json!({
        "tmgi": {
            "mbsServiceId": hex::encode(tmgi.mbs_service_id),
            "plmnId": { "mcc": tmgi.plmn_id.mcc, "mnc": tmgi.plmn_id.mnc },
        }
    })
}

/// The MBS context reference an AMF returned from ContextCreate.
pub type MbsContextRef = String;

/// `POST /namf-mbs-bc/v1/mbs-contexts` — Namf_MBSBroadcast ContextCreate
/// (TS 29.518 §5.6), i.e. TS 23.247 §7.3.1's request for broadcast setup toward
/// the RAN.
///
/// Returns the AMF's `mbsContextRef` on 201. `None` on any failure, logged:
/// this is best-effort relative to the session create, which has already
/// succeeded locally by the time it runs. A failed AMF leg means the RAN does
/// not have the session, which the caller reports rather than hides.
pub async fn context_create(amf: &DiscoveredAmf, tmgi: &Tmgi) -> Option<MbsContextRef> {
    let client = SbiClient::new(
        SbiClientConfig::new(amf.host.clone(), amf.port)
            .with_connect_timeout(Duration::from_secs(2))
            .with_request_timeout(Duration::from_secs(3)),
    );

    let body = json!({ "mbsSessionId": mbs_session_id_json(tmgi) });
    let response = match client
        .post_json("/namf-mbs-bc/v1/mbs-contexts", &body)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            log::warn!(
                "MBS: Namf_MBSBroadcast ContextCreate to {}:{} failed: {e}",
                amf.host,
                amf.port
            );
            return None;
        }
    };

    if response.status != 201 {
        log::warn!(
            "MBS: Namf_MBSBroadcast ContextCreate returned status {} from {}:{}",
            response.status,
            amf.host,
            amf.port
        );
        return None;
    }

    let json: Value = serde_json::from_str(&response.http.content?).ok()?;
    let context_ref = json
        .get("mbsContextRef")
        .and_then(Value::as_str)
        .map(str::to_owned);

    if context_ref.is_none() {
        log::warn!("MBS: ContextCreate 201 carried no mbsContextRef");
    }
    context_ref
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::PlmnId;

    fn tmgi() -> Tmgi {
        Tmgi {
            mbs_service_id: [0x00, 0xBE, 0xEF],
            plmn_id: PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            },
        }
    }

    /// The `mbsServiceId` is 6 hex digits, which is what the OpenAPI's
    /// `pattern: '^[A-Fa-f0-9]{6}$'` requires -- a 3-byte array rendered any
    /// other way is refused by the AMF with a 400.
    #[test]
    fn an_mbs_session_id_body_renders_the_service_id_as_six_hex_digits() {
        let body = mbs_session_id_json(&tmgi());
        assert_eq!(body["tmgi"]["mbsServiceId"], json!("00beef"));
        assert_eq!(body["tmgi"]["plmnId"]["mcc"], json!("001"));
        assert_eq!(body["tmgi"]["plmnId"]["mnc"], json!("01"));
    }

    /// Discovery prefers the `namf-mbs-bc` service's own endpoint over the
    /// instance-level address, because an AMF may serve MBS on a different port
    /// from its other services.
    #[test]
    fn discovery_prefers_the_mbs_service_endpoint_over_the_instance_address() {
        let json = json!({
            "nfInstances": [{
                "nfInstanceId": "amf-1",
                "ipv4Addresses": ["10.0.0.1"],
                "nfServices": [
                    { "serviceName": "namf-comm",
                      "ipEndPoints": [{ "ipv4Address": "10.0.0.1", "port": 7777 }] },
                    { "serviceName": "namf-mbs-bc",
                      "ipEndPoints": [{ "ipv4Address": "10.0.0.2", "port": 8888 }] },
                ],
            }]
        });
        let amf = parse_amf_search_result(&json).expect("an AMF must be selected");
        assert_eq!(amf.host, "10.0.0.2");
        assert_eq!(amf.port, 8888, "the namf-mbs-bc endpoint, not namf-comm's");
        assert_eq!(amf.nf_instance_id.as_deref(), Some("amf-1"));
    }

    /// An instance with no MBS service falls back to its instance address, so a
    /// minimal NRF registration still yields a usable AMF.
    #[test]
    fn discovery_falls_back_to_the_instance_address() {
        let json = json!({
            "nfInstances": [{ "nfInstanceId": "amf-2", "ipv4Addresses": ["10.0.0.9"] }]
        });
        let amf = parse_amf_search_result(&json).expect("an AMF must be selected");
        assert_eq!((amf.host.as_str(), amf.port), ("10.0.0.9", 80));
    }

    /// An empty or addressless SearchResult yields None rather than a default
    /// address: driving the wrong AMF would set up a bearer in the wrong service
    /// area, so no AMF is better than a guessed one.
    #[test]
    fn discovery_yields_none_rather_than_a_default_address() {
        assert!(parse_amf_search_result(&json!({ "nfInstances": [] })).is_none());
        assert!(parse_amf_search_result(&json!({})).is_none());
        assert!(
            parse_amf_search_result(&json!({ "nfInstances": [{ "nfInstanceId": "amf-3" }] }))
                .is_none(),
            "an instance with no address at all must not be selected"
        );
    }

    #[test]
    fn host_port_parsing_handles_the_uri_forms_the_nrf_returns() {
        assert_eq!(
            parse_host_port("http://10.0.0.1:7777"),
            Some(("10.0.0.1".to_string(), 7777))
        );
        assert_eq!(
            parse_host_port("https://nrf.example:443/some/path"),
            Some(("nrf.example".to_string(), 443))
        );
        assert_eq!(
            parse_host_port("10.0.0.1:8080"),
            Some(("10.0.0.1".to_string(), 8080))
        );
        // No port: the SBI default, not a parse failure.
        assert_eq!(
            parse_host_port("http://nrf.example"),
            Some(("nrf.example".to_string(), 80))
        );
    }
}
