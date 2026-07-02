//! lmfd → AMF Namf_Communication client leg (Wave-6 A2).
//!
//! Implements the LMF-initiated 5GC-MT-LR downlink transfer (TS 23.273
//! §6.11.1/§6.11.2):
//!
//! 1. NRF discovery of the serving AMF's `namf-comm` service
//!    (TS 29.510 `GET /nnrf-disc/v1/nf-instances?target-nf-type=AMF&...`),
//!    preferring `InputData.amfId` (TS 29.572 InputData.amfId = NfInstanceId)
//!    when the consumer supplied it.
//! 2. `Namf_Communication_N1N2MessageSubscribe` (TS 29.518 §5.2.2.6) so the
//!    AMF can deliver uplink LPP/NRPPa to our A4 notify-callback routes
//!    (`/nlmf-loc/v1/notify/n1`, `/nlmf-loc/v1/notify/n2`); the returned
//!    subscription id is cached per (AMF, ueContextId) and reused.
//! 3. `Namf_Communication_N1N2MessageTransfer` (TS 29.518 §5.2.2.3.1) as a
//!    `multipart/related` POST (TS 29.500 §6.1.2.3): jsonData =
//!    `N1N2MessageTransferReqData` {n1MessageContainer (n1MessageClass LPP),
//!    lcsCorrelationId, servingLMFIdentification} + one binary part
//!    (Content-Id `lpp-req`, `application/vnd.3gpp.5gnas`) carrying the UPER
//!    LPP `RequestLocationInformation` verbatim.
//!
//! Fail-closed: every failure on this leg surfaces to the DetermineLocation
//! handler as 504 `UNREACHABLE_USER` (TS 29.572 Table 6.1.7.3-1) — a
//! location is NEVER fabricated.

use bytes::Bytes;
use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
use nextgcore_sbi::context::global_context;
use nextgcore_sbi::message::{SbiPart, SbiRequest};
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;

use crate::lmf_self;

/// Content-Id of the multipart binary part carrying the LPP PDU
/// (referenced by `n1MessageContainer.n1MessageContent.contentId`).
pub const LPP_CONTENT_ID: &str = "lpp-req";

/// Content-Type of an N1 binary part (TS 29.518 §6.1.6.4.3 binaryDataN1Message).
pub const N1_CONTENT_TYPE: &str = "application/vnd.3gpp.5gnas";

/// lmfd notify-callback routes registered in the A3 subscription (consumer-
/// chosen callback URIs, served by the A4 handlers — NOT TS 29.572 resources).
pub const N1_NOTIFY_PATH: &str = "/nlmf-loc/v1/notify/n1";
pub const N2_NOTIFY_PATH: &str = "/nlmf-loc/v1/notify/n2";

/// A discovered serving-AMF `namf-comm` endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredAmf {
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub nf_instance_id: Option<String>,
}

impl DiscoveredAmf {
    /// Cache key for the per-(AMF, UE) subscription store.
    fn subscription_key(&self, ue_context_id: &str) -> String {
        format!("{}:{}|{}", self.host, self.port, ue_context_id)
    }
}

/// Outcome of the N1N2MessageTransfer POST toward the serving AMF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferOutcome {
    /// 200 N1_N2_TRANSFER_INITIATED — the AMF accepted the downlink.
    Initiated,
    /// 504 UE_NOT_REACHABLE (TS 29.518 Table 6.1.7.3-1) — maps straight to
    /// DetermineLocation 504 UNREACHABLE_USER (A6 cause mapping).
    UeNotReachable,
    /// Any other failure (transport error, unexpected status, 409 retry
    /// exhausted). Fail-closed: treated as "user unreachable", never a fix.
    Failed(String),
}

// ---------------------------------------------------------------------------
// Typed jsonData bodies (deterministic field order for the golden vectors).
// ---------------------------------------------------------------------------

/// `RefToBinaryData` (TS 29.571).
#[derive(Serialize)]
struct RefToBinaryData<'a> {
    #[serde(rename = "contentId")]
    content_id: &'a str,
}

/// `N1MessageContainer` (TS 29.518 §6.1.6.2.4).
#[derive(Serialize)]
struct N1MessageContainer<'a> {
    #[serde(rename = "n1MessageClass")]
    n1_message_class: &'a str,
    #[serde(rename = "n1MessageContent")]
    n1_message_content: RefToBinaryData<'a>,
}

/// `N1N2MessageTransferReqData` (TS 29.518 §6.1.6.2.3,
/// specs/TS29518_Namf_Communication.yaml — n1MessageContainer +
/// lcsCorrelationId (TS 29.572 CorrelationID) + servingLMFIdentification).
#[derive(Serialize)]
struct N1N2MessageTransferReqData<'a> {
    #[serde(rename = "n1MessageContainer")]
    n1_message_container: N1MessageContainer<'a>,
    #[serde(rename = "lcsCorrelationId")]
    lcs_correlation_id: &'a str,
    #[serde(rename = "servingLMFIdentification")]
    serving_lmf_identification: &'a str,
}

/// `UeN1N2InfoSubscriptionCreateData` (TS 29.518 §6.1.6.2.x,
/// yaml UeN1N2InfoSubscriptionCreateData: n1MessageClass+n1NotifyCallbackUri,
/// n2InformationClass+n2NotifyCallbackUri).
#[derive(Serialize)]
struct UeN1N2InfoSubscriptionCreateData {
    #[serde(rename = "n1MessageClass")]
    n1_message_class: &'static str,
    #[serde(rename = "n1NotifyCallbackUri")]
    n1_notify_callback_uri: String,
    #[serde(rename = "n2InformationClass")]
    n2_information_class: &'static str,
    #[serde(rename = "n2NotifyCallbackUri")]
    n2_notify_callback_uri: String,
}

// ---------------------------------------------------------------------------
// Request builders (pure — unit/golden tested).
// ---------------------------------------------------------------------------

/// Build the multipart N1N2MessageTransfer request:
/// `POST /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages` with jsonData
/// root + one binary LPP part (Content-Id `lpp-req`).
pub fn build_n1n2_transfer_request(
    ue_context_id: &str,
    lcs_correlation_id: &str,
    serving_lmf_identification: &str,
    lpp_pdu: Vec<u8>,
) -> SbiRequest {
    let req_data = N1N2MessageTransferReqData {
        n1_message_container: N1MessageContainer {
            n1_message_class: "LPP",
            n1_message_content: RefToBinaryData {
                content_id: LPP_CONTENT_ID,
            },
        },
        lcs_correlation_id,
        serving_lmf_identification,
    };
    // Struct serialization to a string cannot fail (no non-string map keys).
    let json = serde_json::to_string(&req_data).unwrap_or_default();
    SbiRequest::post(format!(
        "/namf-comm/v1/ue-contexts/{ue_context_id}/n1-n2-messages"
    ))
    .with_body(json, "application/json")
    .with_part(SbiPart::with_content(
        LPP_CONTENT_ID,
        N1_CONTENT_TYPE,
        Bytes::from(lpp_pdu),
    ))
}

/// Build the N1N2MessageSubscribe request:
/// `POST /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages/subscriptions`
/// registering both the LPP (N1) and NRPPa (N2) notify callbacks.
pub fn build_n1n2_subscription_request(ue_context_id: &str, callback_base: &str) -> SbiRequest {
    let base = callback_base.trim_end_matches('/');
    let body = UeN1N2InfoSubscriptionCreateData {
        n1_message_class: "LPP",
        n1_notify_callback_uri: format!("{base}{N1_NOTIFY_PATH}"),
        // Class spelling matches the amfd A3 store/producer contract.
        n2_information_class: "NRPPa",
        n2_notify_callback_uri: format!("{base}{N2_NOTIFY_PATH}"),
    };
    let json = serde_json::to_string(&body).unwrap_or_default();
    SbiRequest::post(format!(
        "/namf-comm/v1/ue-contexts/{ue_context_id}/n1-n2-messages/subscriptions"
    ))
    .with_body(json, "application/json")
}

// ---------------------------------------------------------------------------
// NRF discovery (TS 29.510; pattern cloned from pcfd sbi_path).
// ---------------------------------------------------------------------------

/// Parse an NRF SearchResult for AMF `namf-comm` endpoints. Prefers the
/// instance whose `nfInstanceId` equals `preferred_amf_id` (InputData.amfId);
/// otherwise the first instance exposing the service.
pub fn parse_amf_search_result(
    json: &Value,
    preferred_amf_id: Option<&str>,
) -> Option<DiscoveredAmf> {
    let instances = json.get("nfInstances")?.as_array()?;
    if let Some(pref) = preferred_amf_id {
        if let Some(amf) = instances
            .iter()
            .filter(|nf| nf.get("nfInstanceId").and_then(Value::as_str) == Some(pref))
            .find_map(instance_endpoint)
        {
            return Some(amf);
        }
        log::warn!("InputData.amfId '{pref}' not discoverable; falling back to any AMF");
    }
    instances.iter().find_map(instance_endpoint)
}

/// Extract the `namf-comm` service endpoint from one NF instance.
fn instance_endpoint(nf: &Value) -> Option<DiscoveredAmf> {
    let nf_instance_id = nf
        .get("nfInstanceId")
        .and_then(Value::as_str)
        .map(String::from);
    let services = nf.get("nfServices")?.as_array()?;
    for svc in services {
        if svc.get("serviceName").and_then(Value::as_str) != Some("namf-comm") {
            continue;
        }
        let scheme = svc
            .get("scheme")
            .and_then(Value::as_str)
            .unwrap_or("http")
            .to_string();
        // Prefer the service ipEndPoints; fall back to instance ipv4Addresses.
        if let Some(ep) = svc
            .get("ipEndPoints")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
        {
            if let Some(host) = ep.get("ipv4Address").and_then(Value::as_str) {
                let port = ep.get("port").and_then(Value::as_u64).unwrap_or(80) as u16;
                return Some(DiscoveredAmf {
                    host: host.to_string(),
                    port,
                    scheme,
                    nf_instance_id,
                });
            }
        }
        if let Some(host) = nf
            .get("ipv4Addresses")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
        {
            return Some(DiscoveredAmf {
                host: host.to_string(),
                port: 80,
                scheme,
                nf_instance_id,
            });
        }
    }
    None
}

/// Discover the serving AMF's `namf-comm` endpoint via the NRF
/// (`GET /nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=LMF&service-names=namf-comm`).
/// `None` on ANY failure (no NRF configured, transport error, no instance) —
/// the caller fail-closes with 504 UNREACHABLE_USER.
pub async fn discover_amf(preferred_amf_id: Option<&str>) -> Option<DiscoveredAmf> {
    let ctx = global_context();
    let Some(nrf_uri) = ctx.get_nrf_uri().await else {
        log::warn!("A2: no NRF URI configured; cannot discover the serving AMF");
        return None;
    };
    let (nrf_host, nrf_port) = crate::parse_host_port(&nrf_uri)?;
    let client = ctx.get_client(&nrf_host, nrf_port).await;
    let path = "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=LMF&service-names=namf-comm";
    let response = match client.get(path).await {
        Ok(r) => r,
        Err(e) => {
            log::warn!("A2: NRF discovery failed: {e}");
            return None;
        }
    };
    if response.status != 200 {
        log::warn!("A2: NRF discovery returned status {}", response.status);
        return None;
    }
    let body = response.http.content?;
    let json: Value = match serde_json::from_str(&body) {
        Ok(j) => j,
        Err(e) => {
            log::warn!("A2: invalid NRF discovery response: {e}");
            return None;
        }
    };
    parse_amf_search_result(&json, preferred_amf_id)
}

// ---------------------------------------------------------------------------
// Live legs (bounded-timeout client; timeouts nest under the handler wait cap).
// ---------------------------------------------------------------------------

/// Bounded-timeout SBI client for a discovered AMF (connect 2s, request 3s —
/// strictly inside the DetermineLocation wait budget).
fn client_for(amf: &DiscoveredAmf) -> SbiClient {
    // Attach an NRF-issued Bearer token when OAuth2 enforcement is on (Wave-6
    // H8 Phase A); no-op otherwise so the matched-sim default path is unchanged.
    crate::attach_oauth2(
        SbiClient::new(
            SbiClientConfig::new(amf.host.clone(), amf.port)
                .with_connect_timeout(Duration::from_secs(2))
                .with_request_timeout(Duration::from_secs(3)),
        ),
        nextgcore_sbi::types::NfType::Amf,
    )
}

/// Ensure an N1N2 subscription (TS 29.518 §5.2.2.6) exists on `amf` for
/// `ue_context_id`, registering our A4 callback routes. The subscription id
/// is cached per (AMF, ueContextId) and reused across requests. Best-effort:
/// on failure the transfer still proceeds (the lcsCorrelationId fallback
/// recorded by the AMF's transfer handler routes the uplink), and a missing
/// uplink simply times the session out → 504, never a fabricated fix.
pub async fn ensure_n1n2_subscription(amf: &DiscoveredAmf, ue_context_id: &str) {
    let key = amf.subscription_key(ue_context_id);
    let (cached, callback_base) = match lmf_self().read() {
        Ok(c) => (c.amf_subscription_get(&key), c.callback_base()),
        Err(_) => (None, None),
    };
    if cached.is_some() {
        return;
    }
    let Some(base) = callback_base else {
        log::warn!("A2: no callback base configured; skipping N1N2 subscription");
        return;
    };
    let request = build_n1n2_subscription_request(ue_context_id, &base);
    let client = client_for(amf);
    match client.send_request(request).await {
        Ok(resp) if resp.status == 201 => {
            let sub_id = resp
                .http
                .content
                .as_deref()
                .and_then(|b| serde_json::from_str::<Value>(b).ok())
                .and_then(|v| {
                    v.get("n1n2NotifySubscriptionId")
                        .and_then(Value::as_str)
                        .map(String::from)
                });
            match sub_id {
                Some(id) => {
                    log::info!("A2: N1N2 subscription created on AMF for [{ue_context_id}]: {id}");
                    if let Ok(c) = lmf_self().read() {
                        c.amf_subscription_set(key, id);
                    }
                }
                None => log::warn!(
                    "A2: N1N2 subscription 201 without n1n2NotifySubscriptionId (not cached)"
                ),
            }
        }
        Ok(resp) => log::warn!(
            "A2: N1N2 subscription create for [{ue_context_id}] returned {}",
            resp.status
        ),
        Err(e) => log::warn!("A2: N1N2 subscription create failed: {e}"),
    }
}

/// POST the multipart N1N2MessageTransfer to the serving AMF
/// (TS 29.518 §5.2.2.3.1). 200 → [`TransferOutcome::Initiated`];
/// 504 UE_NOT_REACHABLE → [`TransferOutcome::UeNotReachable`]; a 409
/// temporary rejection is retried exactly once (bounded); anything else
/// fails closed.
pub async fn send_n1n2_transfer(
    amf: &DiscoveredAmf,
    ue_context_id: &str,
    lcs_correlation_id: &str,
    serving_lmf_identification: &str,
    lpp_pdu: Vec<u8>,
) -> TransferOutcome {
    let client = client_for(amf);
    for attempt in 0..2u8 {
        let request = build_n1n2_transfer_request(
            ue_context_id,
            lcs_correlation_id,
            serving_lmf_identification,
            lpp_pdu.clone(),
        );
        match client.send_request(request).await {
            Ok(resp) => match resp.status {
                200 => {
                    let cause = resp
                        .http
                        .content
                        .as_deref()
                        .and_then(|b| serde_json::from_str::<Value>(b).ok())
                        .and_then(|v| v.get("cause").and_then(Value::as_str).map(String::from));
                    if cause.as_deref() != Some("N1_N2_TRANSFER_INITIATED") {
                        log::warn!("A2: N1N2MessageTransfer 200 with cause {cause:?}");
                    }
                    return TransferOutcome::Initiated;
                }
                504 => return TransferOutcome::UeNotReachable,
                409 if attempt == 0 => {
                    log::warn!("A2: N1N2MessageTransfer 409 (temporary); retrying once");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                status => return TransferOutcome::Failed(format!("AMF returned status {status}")),
            },
            Err(e) => return TransferOutcome::Failed(e.to_string()),
        }
    }
    TransferOutcome::Failed("409 temporary rejection persisted after one retry".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextgcore_sbi::multipart;
    use serde_json::json;

    // -- Golden byte-vector (A2 acceptance): the multipart transfer body -----
    //
    // Hand-derived from TS 29.500 §6.1.2.3 + RFC 2387/2046 with a FIXED
    // boundary and a FIXED synthetic LPP payload: the encoder is NOT consulted
    // to produce the expectation. Layout (CRLF line ends):
    //
    //   --<boundary>                          (dash-boundary)
    //   Content-Type: application/json        (root part = jsonData)
    //   <empty line>
    //   <N1N2MessageTransferReqData JSON>
    //   --<boundary>
    //   Content-Id: lpp-req                   (RefToBinaryData target)
    //   Content-Type: application/vnd.3gpp.5gnas
    //   <empty line>
    //   <LPP PDU bytes verbatim>
    //   --<boundary>--                        (close-delimiter)
    #[test]
    fn golden_n1n2_transfer_multipart_body() {
        let lpp: Vec<u8> = vec![0x92, 0x00, 0x1C, 0x00, 0x07];
        let request =
            build_n1n2_transfer_request("imsi-001010000000001", "corr-0001", "lmf-1", lpp.clone());
        assert_eq!(
            request.header.uri,
            "/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"
        );
        assert_eq!(request.header.method, "POST");

        // Boundary-normalized encode (the live client mints a random boundary;
        // the layout is boundary-independent).
        let body = multipart::encode(request.http.content.as_deref(), &request.http.parts, "gold");

        let expected: Vec<u8> = [
            b"--gold\r\n".as_slice(),
            b"Content-Type: application/json\r\n\r\n",
            br#"{"n1MessageContainer":{"n1MessageClass":"LPP","n1MessageContent":{"contentId":"lpp-req"}},"lcsCorrelationId":"corr-0001","servingLMFIdentification":"lmf-1"}"#,
            b"\r\n",
            b"--gold\r\n",
            b"Content-Id: lpp-req\r\n",
            b"Content-Type: application/vnd.3gpp.5gnas\r\n\r\n",
            &lpp,
            b"\r\n",
            b"--gold--\r\n",
        ]
        .concat();
        assert_eq!(
            body, expected,
            "multipart body deviates from the hand-derived TS 29.500 §6.1.2.3 layout"
        );
    }

    // -- The REAL LPP PDU survives the encode→decode pipe byte-exact ---------
    //
    // Encodes with the SAME `multipart::encode` the SBI client uses on the
    // wire, decodes with the SAME `multipart::decode` the SBI *server* (and
    // therefore amfd) uses, and asserts (a) every N1N2MessageTransferReqData
    // field amfd's positioning relay keys on, (b) contentId resolution, and
    // (c) the exact LPP bytes (transparent-relay property).
    #[test]
    fn n1n2_transfer_decodes_with_sbi_multipart_decoder_to_exact_lpp_bytes() {
        let lpp = crate::codec_glue::build_lpp_ecid_request(7).expect("LPP encode");
        let corr = uuid::Uuid::new_v4().to_string();
        let request =
            build_n1n2_transfer_request("imsi-001010000000042", &corr, "lmf-gold", lpp.clone());

        let boundary = multipart::generate_boundary();
        let content_type = multipart::content_type_with_boundary(&boundary);
        let wire = multipart::encode(
            request.http.content.as_deref(),
            &request.http.parts,
            &boundary,
        );

        let decoded = multipart::decode(&content_type, &wire).expect("multipart decode");
        let root = decoded.json.expect("jsonData root part");
        let v: Value = serde_json::from_str(&root).expect("jsonData parses");

        // Structural contract of amfd try_positioning_relay: class LPP + a
        // contentId that resolves to a binary part.
        assert_eq!(
            v.pointer("/n1MessageContainer/n1MessageClass")
                .and_then(Value::as_str),
            Some("LPP")
        );
        let content_id = v
            .pointer("/n1MessageContainer/n1MessageContent/contentId")
            .and_then(Value::as_str)
            .expect("contentId present");
        let part = decoded
            .parts
            .iter()
            .find(|p| p.content_id.as_deref() == Some(content_id))
            .expect("contentId resolves to a binary part");
        assert_eq!(
            part.data.as_ref(),
            lpp.as_slice(),
            "LPP PDU must survive the multipart pipe byte-exact"
        );
        assert_eq!(part.content_type.as_deref(), Some(N1_CONTENT_TYPE));

        // TS 29.572 CorrelationID bounds (1..255 chars).
        let corr_wire = v
            .get("lcsCorrelationId")
            .and_then(Value::as_str)
            .expect("lcsCorrelationId present");
        assert!(
            (1..=255).contains(&corr_wire.len()),
            "CorrelationID length out of TS 29.572 bounds"
        );
        assert_eq!(corr_wire, corr);
        assert_eq!(
            v.get("servingLMFIdentification").and_then(Value::as_str),
            Some("lmf-gold")
        );
    }

    // -- Subscription create body: both (class, callback) pairs complete -----
    #[test]
    fn subscription_request_registers_both_callback_pairs() {
        let request =
            build_n1n2_subscription_request("imsi-001010000000042", "http://10.0.0.5:7816/");
        assert_eq!(
            request.header.uri,
            "/namf-comm/v1/ue-contexts/imsi-001010000000042/n1-n2-messages/subscriptions"
        );
        let v: Value =
            serde_json::from_str(request.http.content.as_deref().expect("body")).expect("json");
        // amfd's A3 handler rejects 400 unless each present class carries its
        // callback URI — assert complete pairs with resolvable HTTP URIs.
        assert_eq!(v["n1MessageClass"], "LPP");
        assert_eq!(
            v["n1NotifyCallbackUri"],
            "http://10.0.0.5:7816/nlmf-loc/v1/notify/n1"
        );
        assert_eq!(v["n2InformationClass"], "NRPPa");
        assert_eq!(
            v["n2NotifyCallbackUri"],
            "http://10.0.0.5:7816/nlmf-loc/v1/notify/n2"
        );
    }

    // -- NRF SearchResult parsing: amfId preference + fallback ---------------
    #[test]
    fn parse_amf_search_result_prefers_input_amf_id() {
        let search = json!({
            "nfInstances": [
                {
                    "nfInstanceId": "amf-aaa",
                    "nfServices": [{
                        "serviceName": "namf-comm",
                        "scheme": "http",
                        "ipEndPoints": [{"ipv4Address": "10.0.0.1", "port": 7777}]
                    }]
                },
                {
                    "nfInstanceId": "amf-bbb",
                    "nfServices": [{
                        "serviceName": "namf-comm",
                        "scheme": "http",
                        "ipEndPoints": [{"ipv4Address": "10.0.0.2", "port": 8888}]
                    }]
                }
            ]
        });
        // Preferred instance wins.
        let amf = parse_amf_search_result(&search, Some("amf-bbb")).expect("amf");
        assert_eq!(amf.host, "10.0.0.2");
        assert_eq!(amf.port, 8888);
        assert_eq!(amf.nf_instance_id.as_deref(), Some("amf-bbb"));
        // No preference → first namf-comm instance.
        let amf = parse_amf_search_result(&search, None).expect("amf");
        assert_eq!(amf.host, "10.0.0.1");
        // Unknown preference → WARN + fallback (never a hard failure).
        let amf = parse_amf_search_result(&search, Some("amf-zzz")).expect("amf");
        assert_eq!(amf.host, "10.0.0.1");
    }

    #[test]
    fn parse_amf_search_result_requires_namf_comm() {
        let search = json!({
            "nfInstances": [{
                "nfInstanceId": "amf-aaa",
                "nfServices": [{
                    "serviceName": "namf-evts",
                    "ipEndPoints": [{"ipv4Address": "10.0.0.1", "port": 7777}]
                }]
            }]
        });
        assert!(parse_amf_search_result(&search, None).is_none());
        assert!(parse_amf_search_result(&json!({}), None).is_none());
    }
}
