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
//!    (`/nlmf-loc/v1/notify/n1-message-notify/{token}`,
//!    `/nlmf-loc/v1/notify/n2-info-notify/{token}`, #1518); the returned
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
use nextgcore_sbi::callback_auth::CallbackToken;
use nextgcore_sbi::client::SbiClient;
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
/// chosen callback URIs, served by the A4 handlers — NOT TS 29.572 resources):
/// `{NOTIFY_PREFIX}/{segment}/{token}`, where the token is the subscription's
/// (#1518). Both segments are in `nextgcore_sbi::log_redact::CALLBACK_TOKEN_SEGMENTS`.
pub const NOTIFY_PREFIX: &str = "/nlmf-loc/v1/notify";
/// The segment before the token of the `n1NotifyCallbackUri`.
pub const N1_NOTIFY_SEGMENT: &str = "n1-message-notify";
/// The segment before the token of the `n2NotifyCallbackUri`.
pub const N2_NOTIFY_SEGMENT: &str = "n2-info-notify";

/// The path of this LMF's `kind` notify callback for `token` (#1518).
pub fn notify_path(kind: crate::context::NotifyKind, token: &str) -> String {
    let segment = match kind {
        crate::context::NotifyKind::N1 => N1_NOTIFY_SEGMENT,
        crate::context::NotifyKind::N2 => N2_NOTIFY_SEGMENT,
    };
    format!("{NOTIFY_PREFIX}/{segment}/{token}")
}

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
    pub fn subscription_key(&self, ue_context_id: &str) -> String {
        format!("{}:{}|{}", self.host, self.port, ue_context_id)
    }

    /// Cache key for this AMF's non-UE NRPPa subscription.
    pub fn non_ue_subscription_key(&self) -> String {
        format!("{}:{}|non-ue-nrppa", self.host, self.port)
    }
}

/// Outcome of the N1N2MessageTransfer POST toward the serving AMF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferOutcome {
    /// 200 N1_N2_TRANSFER_INITIATED — the AMF accepted the downlink — or 202
    /// ATTEMPTING_TO_REACH_UE: the UE is CM-IDLE and being paged, and the AMF
    /// delivers the downlink once it is connected (TS 29.518 §5.2.2.3.1, #1087).
    /// Either way the answer is coming, so the session waits for it.
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

/// Content-Id of the NRPPa binary part in an N2 information transfer (#103).
///
/// Distinct from [`LPP_CONTENT_ID`]: a transfer may carry both an LPP N1 message and
/// an NRPPa N2 PDU, and the AMF resolves each `contentId` independently, so sharing
/// one would make the second part unreachable.
pub const NRPPA_CONTENT_ID: &str = "nrppa-req";

/// Content type of an NRPPa PDU part (TS 29.518: NGAP-shaped binary).
pub const N2_CONTENT_TYPE: &str = "application/vnd.3gpp.ngap";

/// Build an N1N2MessageTransfer carrying an **NRPPa PDU toward the serving gNB**
/// (#103, TS 29.518 §5.2.2.3, TS 23.273 §6.11.2).
///
/// The AMF's positioning relay accepts exactly this shape — an
/// `n2InfoContainer.nrppaInfo` with `nrppaPdu.ngapIeType == "NRPPA_PDU"` and a
/// `ngapData.contentId` resolving to a binary part — and delivers it over NGAP
/// procedure 8 (UE-associated NRPPa transport). `nfId` carries this LMF's identity,
/// which the AMF seeds into the NGAP RoutingID so the gNB's uplink reply routes back
/// here rather than to whichever LMF the AMF last spoke to.
///
/// `n2InformationClass` is `"NRPPa"`, matching the class this LMF already subscribes
/// its N2 notify callback under: a transfer whose class disagreed with the
/// subscription would be delivered and then have nowhere to report back to.
pub fn build_n2_nrppa_transfer_request(
    ue_context_id: &str,
    lcs_correlation_id: &str,
    serving_lmf_identification: &str,
    nrppa_pdu: Vec<u8>,
) -> SbiRequest {
    let body = serde_json::json!({
        "n2InfoContainer": {
            "n2InformationClass": "NRPPa",
            "nrppaInfo": {
                "nfId": serving_lmf_identification,
                "nrppaPdu": {
                    "ngapIeType": "NRPPA_PDU",
                    "ngapData": { "contentId": NRPPA_CONTENT_ID },
                },
            },
        },
        "lcsCorrelationId": lcs_correlation_id,
        "servingLMFIdentification": serving_lmf_identification,
    });
    SbiRequest::post(format!(
        "/namf-comm/v1/ue-contexts/{ue_context_id}/n1-n2-messages"
    ))
    .with_body(body.to_string(), "application/json")
    .with_part(SbiPart::with_content(
        NRPPA_CONTENT_ID,
        N2_CONTENT_TYPE,
        Bytes::from(nrppa_pdu),
    ))
}

/// Build the N1N2MessageSubscribe request:
/// `POST /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages/subscriptions`
/// registering both the LPP (N1) and NRPPa (N2) notify callbacks, each carrying
/// its own token from `start` (#1518).
pub fn build_n1n2_subscription_request(
    ue_context_id: &str,
    callback_base: &str,
    n1_token: &CallbackToken,
    n2_token: &CallbackToken,
) -> SbiRequest {
    use crate::context::NotifyKind;
    let base = callback_base.trim_end_matches('/');
    let body = UeN1N2InfoSubscriptionCreateData {
        n1_message_class: "LPP",
        n1_notify_callback_uri: format!("{base}{}", notify_path(NotifyKind::N1, n1_token.as_str())),
        // Class spelling matches the amfd A3 store/producer contract.
        n2_information_class: "NRPPa",
        n2_notify_callback_uri: format!("{base}{}", notify_path(NotifyKind::N2, n2_token.as_str())),
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
        // #1324: the endpoint's IPv4 or IPv6 address, else the service's or the
        // AMF's (IPv4, IPv6, FQDN).
        if let Some(host) = nextgcore_sbi::nf_addressing::service_host(nf, Some(svc)) {
            let port = nextgcore_sbi::nf_addressing::service_port(Some(svc)).unwrap_or(80);
            return Some(DiscoveredAmf {
                host,
                port,
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
pub(crate) fn client_for(amf: &DiscoveredAmf) -> SbiClient {
    // Attach an NRF-issued Bearer token when OAuth2 enforcement is on (Wave-6
    // H8 Phase A); no-op otherwise so the matched-sim default path is unchanged.
    crate::attach_oauth2(
        SbiClient::new(
            nextgcore_sbi::security::sbi_peer_client_config(&amf.host, amf.port)
                .with_connect_timeout(Duration::from_secs(2))
                .with_request_timeout(Duration::from_secs(3)),
        ),
        nextgcore_sbi::types::NfType::Amf,
    )
}

/// Ensure an N1N2 subscription (TS 29.518 §5.2.2.6) exists on `amf` for
/// `ue_context_id`, registering our A4 callback routes with fresh tokens (#1518).
/// The subscription is held per (AMF, ueContextId) and reused across requests;
/// only one create per key is in flight at a time. Best-effort: on failure the
/// transfer still proceeds, and a missing uplink simply times the session out →
/// 504, never a fabricated fix.
pub async fn ensure_n1n2_subscription(amf: &DiscoveredAmf, ue_context_id: &str) {
    let key = amf.subscription_key(ue_context_id);
    let Some(base) = lmf_self().read().ok().and_then(|c| c.callback_base()) else {
        log::warn!("A2: no callback base configured; skipping N1N2 subscription");
        return;
    };
    let Some((start, evicted)) = lmf_self()
        .read()
        .ok()
        .and_then(|c| c.amf_subscription_begin(&key, amf, Some(ue_context_id)))
    else {
        return;
    };
    if let Some(old) = evicted {
        spawn_unsubscribe(old);
    }
    let Some(n1_token) = start.n1_token.clone() else {
        return;
    };
    let request = build_n1n2_subscription_request(ue_context_id, &base, &n1_token, &start.n2_token);
    // From here every exit, an await cancelled included, commits or abandons.
    let in_flight = InFlightCreate {
        key,
        start,
        amf: amf.clone(),
        ue_context_id: Some(ue_context_id.to_string()),
        armed: true,
    };
    // #1877: the create, its commit included, runs on its own task. Awaited inline,
    // a create whose caller went away (the DetermineLocation consumer disconnected)
    // dropped `in_flight` after the AMF had made the subscription: the entry was
    // abandoned and the AMF's subscription recorded nowhere, so nothing deleted it.
    let (amf, ue_context_id) = (amf.clone(), ue_context_id.to_string());
    let _ = tokio::spawn(async move {
        create_n1n2_subscription(&amf, &ue_context_id, request, in_flight).await;
    })
    .await;
}

/// The N1N2 subscription create and its commit (#1877: on its own task).
async fn create_n1n2_subscription(
    amf: &DiscoveredAmf,
    ue_context_id: &str,
    request: SbiRequest,
    in_flight: InFlightCreate,
) {
    let client = client_for(amf);
    let created = match client.send_request(request).await {
        Ok(resp) if resp.status == 201 => {
            let sub_id = created_subscription_id(&resp, "n1n2NotifySubscriptionId");
            if sub_id.is_none() {
                log::warn!(
                    "A2: N1N2 subscription 201 without n1n2NotifySubscriptionId or Location (not cached)"
                );
            }
            sub_id
        }
        Ok(resp) => {
            log::warn!(
                "A2: N1N2 subscription create for [{ue_context_id}] returned {}",
                resp.status
            );
            None
        }
        Err(e) => {
            log::warn!("A2: N1N2 subscription create failed: {e}");
            None
        }
    };
    match created {
        Some(id) => {
            log::info!("A2: N1N2 subscription created on AMF for [{ue_context_id}]: {id}");
            in_flight.committed(id);
        }
        None => drop(in_flight),
    }
}

/// The AMF no longer knows `ue_context_id` (it answered 404, TS 29.518
/// Table 6.1.7.3-1 CONTEXT_NOT_FOUND), so it holds no subscription for it
/// either, e.g. after an AMF restart (#1518): forget ours, so the next request
/// subscribes again rather than relying on one that is gone.
pub fn forget_n1n2_subscription(amf: &DiscoveredAmf, ue_context_id: &str) {
    if let Ok(c) = lmf_self().read() {
        c.amf_subscription_forget(&amf.subscription_key(ue_context_id));
    }
}

/// Holds a subscription create in flight (#1518, R8 M2). Dropped without
/// [`InFlightCreate::committed`] (the create failed, or the task running it was
/// cancelled, e.g. when the consumer of the DetermineLocation that started it
/// disconnects), it abandons the entry, so the key can be subscribed again and the
/// entry does not hold a cap slot forever.
struct InFlightCreate {
    key: String,
    start: crate::context::SubscriptionStart,
    amf: DiscoveredAmf,
    ue_context_id: Option<String>,
    /// Cleared once committed: drop then leaves the entry alone.
    armed: bool,
}

impl InFlightCreate {
    /// The AMF created it with `id`: record it. When the entry went while the
    /// create was in flight (forgotten or evicted, R8 m2), unsubscribe at the AMF
    /// instead, so the AMF holds no subscription this LMF does not know about.
    fn committed(mut self, id: String) {
        self.armed = false;
        let recorded = lmf_self()
            .read()
            .is_ok_and(|c| c.amf_subscription_created(&self.key, &self.start, id.clone()));
        if !recorded {
            log::info!("A2: subscription {id} was dropped while being created; unsubscribing");
            spawn_unsubscribe_id(&self.amf, self.ue_context_id.as_deref(), &id);
        }
    }
}

impl Drop for InFlightCreate {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(c) = lmf_self().read() {
            c.amf_subscription_abandon(&self.key, &self.start);
        }
    }
}

/// Unsubscribe an evicted subscription at its AMF (TS 29.518 §5.2.2.3.4
/// N1N2MessageUnSubscribe, §5.2.2.4.3 NonUeN2InfoUnSubscribe), best-effort and in
/// the background: its tokens are already refused, so the AMF would otherwise go on
/// notifying a URI that answers 404.
fn spawn_unsubscribe(sub: crate::context::AmfSubscription) {
    let Some(id) = sub.subscription_id.as_deref() else {
        return;
    };
    log::info!("A2: subscription cap reached; unsubscribing the oldest ({id}) at its AMF");
    spawn_unsubscribe_id(&sub.amf, sub.ue_context_id.as_deref(), id);
}

/// DELETE subscription `id` (a UE's N1N2 one when `ue_context_id` is given, else
/// the non-UE one) at `amf`, best-effort and in the background.
///
/// #2085: a DELETE that fails is parked with [`crate::amf_unsubscribe`] and
/// retried until the AMF answers, instead of only being logged: the local entry
/// is already gone, so nothing else would ever ask the AMF again.
fn spawn_unsubscribe_id(amf: &DiscoveredAmf, ue_context_id: Option<&str>, id: &str) {
    crate::amf_unsubscribe::spawn_unsubscribe(
        amf,
        crate::amf_unsubscribe::subscription_path(ue_context_id, id),
    );
}

/// #2085: the AMF's id for a subscription it answered 201 to: `field` of the
/// body, else the last segment of the `Location` header (TS 29.518: the created
/// resource's URI, `.../subscriptions/{subscriptionId}`). A 201 whose id was
/// only in `Location` used to be left unrecorded, and so never unsubscribed.
fn created_subscription_id(
    resp: &nextgcore_sbi::message::SbiResponse,
    field: &str,
) -> Option<String> {
    resp.http
        .content
        .as_deref()
        .and_then(|b| serde_json::from_str::<Value>(b).ok())
        .and_then(|v| v.get(field).and_then(Value::as_str).map(String::from))
        .or_else(|| {
            resp.http
                .get_header("Location")
                .and_then(|l| l.trim_end_matches('/').rsplit('/').next())
                .filter(|id| !id.is_empty())
                .map(String::from)
        })
}

/// POST the multipart N1N2MessageTransfer to the serving AMF
/// (TS 29.518 §5.2.2.3.1). 200 → [`TransferOutcome::Initiated`];
/// 504 UE_NOT_REACHABLE → [`TransferOutcome::UeNotReachable`]; a 409
/// temporary rejection is retried exactly once (bounded); anything else
/// fails closed.
/// POST an NRPPa N2 information transfer (#103).
///
/// Best-effort by design and separate from [`send_n1n2_transfer`]: the NRPPa leg
/// solicits gNB measurements that *improve* a fix, while the LPP leg is what asks
/// the UE for the measurements a fix needs at all. A gNB that declines NRPPa must
/// not fail a positioning request the UE could still answer, so this returns the
/// outcome for logging and the caller proceeds either way.
pub async fn send_n2_nrppa_transfer(
    amf: &DiscoveredAmf,
    ue_context_id: &str,
    lcs_correlation_id: &str,
    serving_lmf_identification: &str,
    nrppa_pdu: Vec<u8>,
) -> TransferOutcome {
    let client = client_for(amf);
    let request = build_n2_nrppa_transfer_request(
        ue_context_id,
        lcs_correlation_id,
        serving_lmf_identification,
        nrppa_pdu,
    );
    match client.send_request(request).await {
        // 202: the UE is being paged; the NRPPa follows once it is connected.
        Ok(resp) if resp.status == 200 || resp.status == 202 => TransferOutcome::Initiated,
        Ok(resp) if resp.status == 504 => TransferOutcome::UeNotReachable,
        Ok(resp) => {
            log::warn!("NRPPa N2 transfer returned status {}", resp.status);
            TransferOutcome::Failed(format!("NRPPa N2 transfer status {}", resp.status))
        }
        Err(e) => {
            log::warn!("NRPPa N2 transfer failed: {e}");
            TransferOutcome::Failed(format!("NRPPa N2 transfer: {e}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Non-UE-associated NRPPa (#807; TS 29.518 §5.2.2.4.1.2 and §5.2.2.4.4.2)
// ---------------------------------------------------------------------------

/// Content-Id of the NRPPa part of a NonUeN2MessageTransfer.
pub const NON_UE_NRPPA_CONTENT_ID: &str = "nrppa-non-ue";

/// Build a `NonUeN2MessageTransfer` (TS 29.518 §5.2.2.4.1.2) carrying a
/// non-UE-associated NRPPa PDU to one NG-RAN node:
/// `POST /namf-comm/v1/non-ue-n2-messages/transfer` with an
/// `N2InformationTransferReqData` whose `n2Information` is of class NRPPa.
///
/// §5.2.2.4.1.2 step 1: the body carries "the NG RAN node identifier(s) to which the
/// transfer needs to be initiated" (`globalRanNodeList`) and "the NF Instance
/// Identifier of the NF Service Consumer (e.g. LMF) in "nfId"" (`nrppaInfo.nfId`,
/// mandatory in `NrppaInformation`). The AMF puts the nfId in the NGAP Routing ID,
/// which is how the gNB's answer finds this LMF again.
pub fn build_non_ue_nrppa_transfer_request(
    node: &crate::site_config::NgRanNode,
    nf_id: &str,
    nrppa_pdu: Vec<u8>,
) -> SbiRequest {
    let body = serde_json::json!({
        "globalRanNodeList": [node.global_ran_node_id()],
        "n2Information": {
            "n2InformationClass": "NRPPa",
            "nrppaInfo": {
                "nfId": nf_id,
                "nrppaPdu": {
                    "ngapIeType": "NRPPA_PDU",
                    "ngapData": { "contentId": NON_UE_NRPPA_CONTENT_ID },
                },
            },
        },
    });
    SbiRequest::post("/namf-comm/v1/non-ue-n2-messages/transfer")
        .with_body(body.to_string(), "application/json")
        .with_part(SbiPart::with_content(
            NON_UE_NRPPA_CONTENT_ID,
            N2_CONTENT_TYPE,
            Bytes::from(nrppa_pdu),
        ))
}

/// POST a NonUeN2MessageTransfer. 200 `N2_INFO_TRANSFER_INITIATED` is
/// [`TransferOutcome::Initiated`]; `PARTIAL_N2_INFO_TRANSFER` cannot happen for the
/// single node this sends to, and anything else is a failure.
pub async fn send_non_ue_nrppa_transfer(
    amf: &DiscoveredAmf,
    node: &crate::site_config::NgRanNode,
    nf_id: &str,
    nrppa_pdu: Vec<u8>,
) -> TransferOutcome {
    let client = client_for(amf);
    let request = build_non_ue_nrppa_transfer_request(node, nf_id, nrppa_pdu);
    match client.send_request(request).await {
        Ok(resp) if resp.status == 200 => {
            let result = resp
                .http
                .content
                .as_deref()
                .and_then(|b| serde_json::from_str::<Value>(b).ok())
                .and_then(|v| v.get("result").and_then(Value::as_str).map(String::from));
            if result.as_deref() == Some("N2_INFO_TRANSFER_INITIATED") {
                TransferOutcome::Initiated
            } else {
                TransferOutcome::Failed(format!("NonUeN2MessageTransfer result {result:?}"))
            }
        }
        Ok(resp) => {
            TransferOutcome::Failed(format!("NonUeN2MessageTransfer status {}", resp.status))
        }
        Err(e) => TransferOutcome::Failed(format!("NonUeN2MessageTransfer: {e}")),
    }
}

/// Build a `NonUeN2InfoSubscribe` (TS 29.518 §5.2.2.4.2) for the NRPPa class, so
/// the AMF has a notification URI for this LMF's non-UE-associated NRPPa answers
/// (§5.2.2.4.4.2). The nfId lets the AMF pick this LMF's subscription by the NGAP
/// Routing ID the answer comes back with. The URI carries the subscription's
/// token (#1518).
pub fn build_non_ue_nrppa_subscription_request(
    nf_id: &str,
    callback_base: &str,
    n2_token: &CallbackToken,
) -> SbiRequest {
    let base = callback_base.trim_end_matches('/');
    let body = serde_json::json!({
        "n2InformationClass": "NRPPa",
        "n2NotifyCallbackUri": format!(
            "{base}{}",
            notify_path(crate::context::NotifyKind::N2, n2_token.as_str())
        ),
        "nfId": nf_id,
    });
    SbiRequest::post("/namf-comm/v1/non-ue-n2-messages/subscriptions")
        .with_body(body.to_string(), "application/json")
}

/// Ensure this LMF has a non-UE NRPPa subscription on `amf`, held per AMF with its
/// own token (#1518). Best-effort: without one the AMF falls back to a UE's N1N2
/// NRPPa subscription, whose N2 callback this LMF also admits for non-UE answers.
pub async fn ensure_non_ue_nrppa_subscription(amf: &DiscoveredAmf, nf_id: &str) {
    let key = amf.non_ue_subscription_key();
    let Some(base) = lmf_self().read().ok().and_then(|c| c.callback_base()) else {
        log::warn!("Multi-RTT: no callback base configured; no non-UE NRPPa subscription");
        return;
    };
    let Some((start, evicted)) = lmf_self()
        .read()
        .ok()
        .and_then(|c| c.amf_subscription_begin(&key, amf, None))
    else {
        return;
    };
    if let Some(old) = evicted {
        spawn_unsubscribe(old);
    }
    let request = build_non_ue_nrppa_subscription_request(nf_id, &base, &start.n2_token);
    // From here every exit, an await cancelled included, commits or abandons.
    let in_flight = InFlightCreate {
        key,
        start,
        amf: amf.clone(),
        ue_context_id: None,
        armed: true,
    };
    // #1877: on its own task, as `ensure_n1n2_subscription`'s create.
    let amf = amf.clone();
    let _ = tokio::spawn(async move {
        create_non_ue_nrppa_subscription(&amf, request, in_flight).await;
    })
    .await;
}

/// The non-UE NRPPa subscription create and its commit (#1877: on its own task).
async fn create_non_ue_nrppa_subscription(
    amf: &DiscoveredAmf,
    request: SbiRequest,
    in_flight: InFlightCreate,
) {
    let client = client_for(amf);
    let created = match client.send_request(request).await {
        Ok(resp) if resp.status == 201 => {
            let id = created_subscription_id(&resp, "n2NotifySubscriptionId");
            if id.is_none() {
                log::warn!("Multi-RTT: NonUeN2InfoSubscribe 201 without n2NotifySubscriptionId or Location");
            }
            id
        }
        Ok(resp) => {
            log::warn!("Multi-RTT: NonUeN2InfoSubscribe returned {}", resp.status);
            None
        }
        Err(e) => {
            log::warn!("Multi-RTT: NonUeN2InfoSubscribe failed: {e}");
            None
        }
    };
    match created {
        Some(id) => {
            log::info!("Multi-RTT: non-UE NRPPa subscription on the AMF: {id}");
            in_flight.committed(id);
        }
        None => drop(in_flight),
    }
}

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
                // TS 29.518 §5.2.2.3.1: a CM-IDLE UE is paged and the LPP is
                // delivered after its Service Request (#1087).
                202 => {
                    log::info!(
                        "A2: N1N2MessageTransfer 202 ATTEMPTING_TO_REACH_UE: the UE is paged; \
                         waiting for its answer"
                    );
                    return TransferOutcome::Initiated;
                }
                504 => return TransferOutcome::UeNotReachable,
                // The AMF does not know the UE context, so no subscription for it
                // survives there either (#1518).
                404 => {
                    forget_n1n2_subscription(amf, ue_context_id);
                    return TransferOutcome::Failed("AMF returned status 404".to_string());
                }
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
        let (n1, n2) = (CallbackToken::mint(), CallbackToken::mint());
        let request = build_n1n2_subscription_request(
            "imsi-001010000000042",
            "http://10.0.0.5:7816/",
            &n1,
            &n2,
        );
        assert_eq!(
            request.header.uri,
            "/namf-comm/v1/ue-contexts/imsi-001010000000042/n1-n2-messages/subscriptions"
        );
        let v: Value =
            serde_json::from_str(request.http.content.as_deref().expect("body")).expect("json");
        // amfd's A3 handler rejects 400 unless each present class carries its
        // callback URI — assert complete pairs with resolvable HTTP URIs.
        assert_eq!(v["n1MessageClass"], "LPP");
        // #1518: each URI carries its own token, after the redacted segment.
        assert_eq!(
            v["n1NotifyCallbackUri"],
            format!(
                "http://10.0.0.5:7816/nlmf-loc/v1/notify/n1-message-notify/{}",
                n1.as_str()
            )
        );
        assert_eq!(v["n2InformationClass"], "NRPPa");
        assert_eq!(
            v["n2NotifyCallbackUri"],
            format!(
                "http://10.0.0.5:7816/nlmf-loc/v1/notify/n2-info-notify/{}",
                n2.as_str()
            )
        );
        assert_ne!(n1.as_str(), n2.as_str());
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

    /// A stand-in AMF answering every request with `status`.
    async fn amf_answering(status: u16) -> (nextgcore_sbi::server::SbiServer, DiscoveredAmf) {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = nextgcore_sbi::server::SbiServer::on_listener(
            nextgcore_sbi::server::SbiServerConfig::new(addr),
            listener,
        );
        server
            .start(move |_req: nextgcore_sbi::message::SbiRequest| async move {
                let cause = match status {
                    202 => "ATTEMPTING_TO_REACH_UE",
                    504 => "UE_NOT_REACHABLE",
                    _ => "N1_N2_TRANSFER_INITIATED",
                };
                nextgcore_sbi::message::SbiResponse::with_status(status)
                    .with_json_body(&serde_json::json!({ "cause": cause }))
                    .unwrap()
            })
            .await
            .expect("stand-in AMF starts");
        let amf = DiscoveredAmf {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            scheme: "http".to_string(),
            nf_instance_id: None,
        };
        (server, amf)
    }

    /// **#2085**: a 201 whose subscription id is only in `Location` (TS 29.518:
    /// the created resource's URI) is recorded under that id, so it is
    /// unsubscribed later; and shutdown takes every created subscription, with
    /// its resource path at the AMF, for `amf_unsubscribe::unsubscribe_all`.
    ///
    /// REVERT-VERIFIED: with the `Location` fallback removed from
    /// `created_subscription_id`, "recorded under the id in Location" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_201_with_only_a_location_is_recorded_and_unsubscribed_at_shutdown_2085() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (_server, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(
            |_req: nextgcore_sbi::message::SbiRequest| async move {
                let mut resp = nextgcore_sbi::message::SbiResponse::with_status(201);
                resp.http.set_header(
                    "Location",
                    "http://amf/namf-comm/v1/non-ue-n2-messages/subscriptions/loc-2085",
                );
                resp
            },
        )
        .await;
        let amf = DiscoveredAmf {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            scheme: "http".to_string(),
            nf_instance_id: None,
        };
        lmf_self()
            .read()
            .unwrap()
            .set_callback_base("http://127.0.0.1:1");
        ensure_non_ue_nrppa_subscription(&amf, "lmf-2085").await;
        let key = amf.non_ue_subscription_key();
        let mut recorded = None;
        for _ in 0..200 {
            recorded = lmf_self().read().unwrap().amf_subscription_get(&key);
            if recorded.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            recorded.as_deref(),
            Some("loc-2085"),
            "recorded under the id in Location"
        );
        let taken = lmf_self().read().unwrap().amf_subscriptions_take_created();
        assert!(
            taken.contains(&(
                amf.clone(),
                "/namf-comm/v1/non-ue-n2-messages/subscriptions/loc-2085".to_string()
            )),
            "{taken:?}"
        );
        assert!(!lmf_self().read().unwrap().amf_subscription_holds(&key));
    }

    /// #1087, TS 29.518 §5.2.2.3.1: 202 ATTEMPTING_TO_REACH_UE (the UE is CM-IDLE
    /// and paged) is an initiated transfer for both the LPP and the NRPPa leg, not a
    /// failure: the AMF delivers once the UE is connected. 504 stays unreachable.
    #[tokio::test]
    async fn a_202_from_the_amf_is_an_initiated_transfer_and_504_is_unreachable() {
        let (_amf, amf) = amf_answering(202).await;
        assert!(matches!(
            send_n1n2_transfer(&amf, "imsi-001010010870101", "c", "lmf", vec![0x90]).await,
            TransferOutcome::Initiated
        ));
        assert!(matches!(
            send_n2_nrppa_transfer(&amf, "imsi-001010010870101", "c", "lmf", vec![0x00]).await,
            TransferOutcome::Initiated
        ));
        let (_amf, amf) = amf_answering(504).await;
        assert!(matches!(
            send_n1n2_transfer(&amf, "imsi-001010010870102", "c", "lmf", vec![0x90]).await,
            TransferOutcome::UeNotReachable
        ));
        assert!(matches!(
            send_n2_nrppa_transfer(&amf, "imsi-001010010870102", "c", "lmf", vec![0x00]).await,
            TransferOutcome::UeNotReachable
        ));
    }
}

/// #1324 review: producer to consumer. A peer profile built with an IPv4, IPv6 or
/// FQDN host (as this codebase's producers build them) resolves to that host.
#[cfg(test)]
mod tests_peer_host_kind_1324 {
    use super::*;
    use nextgcore_sbi::nf_addressing::{dialled_host, sample_search_result, SAMPLE_HOSTS};

    #[test]
    fn a_peer_at_any_host_type_is_resolved() {
        for host in SAMPLE_HOSTS {
            let r = sample_search_result("AMF", "namf-comm", host, 7796);
            let amf = instance_endpoint(&r["nfInstances"][0]).expect("an AMF");
            assert_eq!((amf.host, amf.port), (dialled_host(host), 7796));
        }
    }
}
