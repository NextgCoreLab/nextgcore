//! Nudm UE Context Management (UECM) request processing — TS 29.503 §5.3.
//!
//! These are the conformance pieces for the LIVE UECM handlers:
//! - **udmd-03**: mandatory-IE validation of AMF/SMF registrations.
//! - **udmd-01**: persistence of the registration to UDR (Nudr_DataRepository
//!   `context-data`), keeping the local UE context only as a cache.
//! - **udmd-02**: Deregistration Notification to the old AMF on re-registration
//!   with a different serving AMF.
//!
//! The UDR interaction is funnelled through [`UdrClient`] so the live handlers
//! can be unit-gated with a mock instead of a running udrd.

use crate::context::udm_self;
use nextgcore_sbi::message::SbiResponse;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// ProblemDetails (RFC 7807 / TS 29.500)
// ---------------------------------------------------------------------------

/// Minimal ProblemDetails carried by a validation failure.
#[derive(Debug, Clone)]
pub struct ProblemDetails {
    /// HTTP status code.
    pub status: u16,
    /// Machine-readable cause (TS 29.500).
    pub cause: String,
    /// Human-readable detail.
    pub detail: String,
}

impl ProblemDetails {
    /// A `400 MANDATORY_IE_MISSING` problem (TS 29.500).
    fn mandatory_ie_missing(detail: impl Into<String>) -> Self {
        Self {
            status: 400,
            cause: "MANDATORY_IE_MISSING".to_string(),
            detail: detail.into(),
        }
    }

    /// Render the problem as an SBI response body.
    pub fn into_response(self) -> SbiResponse {
        SbiResponse::with_status(self.status)
            .with_json_body(&json!({
                "status": self.status,
                "cause": self.cause,
                "detail": self.detail,
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(self.status))
    }
}

// ---------------------------------------------------------------------------
// udmd-03: mandatory-IE validation
// ---------------------------------------------------------------------------

fn require_str<'a>(v: &'a Value, key: &str, label: &str) -> Result<&'a str, ProblemDetails> {
    match v.get(key).and_then(|x| x.as_str()) {
        Some(s) if !s.is_empty() => Ok(s),
        _ => Err(ProblemDetails::mandatory_ie_missing(format!(
            "{label} is missing"
        ))),
    }
}

fn require_obj<'a>(v: &'a Value, key: &str, label: &str) -> Result<&'a Value, ProblemDetails> {
    match v.get(key) {
        Some(o) if o.is_object() => Ok(o),
        _ => Err(ProblemDetails::mandatory_ie_missing(format!(
            "{label} is missing"
        ))),
    }
}

/// Which AMF access-registration resource a UECM request addresses.
///
/// `amf-3gpp-access` and `amf-non-3gpp-access` are **distinct** resources with
/// distinct operations (TS 29.503 §6.2.3, §5.3.2.4.2), and a UE may be
/// registered over both at once. The access is therefore threaded through every
/// step that names a resource — the UDR `context-data` path, the local cache
/// slot, the `Location` header and the `DeregistrationData.accessType` — as an
/// explicit parameter rather than defaulted, because the defect this type fixes
/// (#84) was a non-3GPP registration silently reusing the 3GPP helper and
/// tearing the UE's 3GPP registration down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UecmAccess {
    /// 3GPP access (`amf-3gpp-access`, `smsf-3gpp-access`).
    ThreeGpp,
    /// Non-3GPP access (`amf-non-3gpp-access`, `smsf-non-3gpp-access`) — the
    /// N3IWF / TNGF / W-AGF cases of TS 23.501 §4.2.8.
    Non3Gpp,
}

impl UecmAccess {
    /// The AMF-registration resource name, both as the UECM sub-resource and as
    /// the UDR `context-data` resource (TS 29.505 §5.2.2).
    pub fn amf_resource(self) -> &'static str {
        match self {
            Self::ThreeGpp => "amf-3gpp-access",
            Self::Non3Gpp => "amf-non-3gpp-access",
        }
    }

    /// The SMSF-registration resource name for this access.
    pub fn smsf_resource(self) -> &'static str {
        match self {
            Self::ThreeGpp => "smsf-3gpp-access",
            Self::Non3Gpp => "smsf-non-3gpp-access",
        }
    }

    /// The TS 29.571 `AccessType` enum value for this access. Carried on the
    /// `DeregistrationData` the old AMF keys its network-initiated
    /// deregistration on, so it must name the access that actually changed.
    pub fn access_type(self) -> &'static str {
        match self {
            Self::ThreeGpp => "3GPP_ACCESS",
            Self::Non3Gpp => "NON_3GPP_ACCESS",
        }
    }

    /// The `Location` URI of the AMF-registration resource for `supi`.
    pub fn amf_location(self, supi: &str) -> String {
        format!("/nudm-uecm/v1/{supi}/registrations/{}", self.amf_resource())
    }

    /// Resolve a UECM path segment to its access, or `None` when the segment
    /// names neither AMF-registration resource.
    pub fn from_amf_resource(segment: &str) -> Option<Self> {
        match segment {
            "amf-3gpp-access" => Some(Self::ThreeGpp),
            "amf-non-3gpp-access" => Some(Self::Non3Gpp),
            _ => None,
        }
    }

    /// Resolve a UECM path segment to its access for the SMSF resources.
    pub fn from_smsf_resource(segment: &str) -> Option<Self> {
        match segment {
            "smsf-3gpp-access" => Some(Self::ThreeGpp),
            "smsf-non-3gpp-access" => Some(Self::Non3Gpp),
            _ => None,
        }
    }
}

/// Validate the mandatory IEs of an `Amf3GppAccessRegistration`
/// (TS 29.503 §6.2.6): `amfInstanceId`, `deregCallbackUri`,
/// `guami{amfId, plmnId{mcc, mnc}}`, `ratType`.
pub fn validate_amf_3gpp_registration(body: &Value) -> Result<(), ProblemDetails> {
    require_str(
        body,
        "amfInstanceId",
        "Amf3GppAccessRegistration.amfInstanceId",
    )?;
    require_str(
        body,
        "deregCallbackUri",
        "Amf3GppAccessRegistration.deregCallbackUri",
    )?;
    let guami = require_obj(body, "guami", "Amf3GppAccessRegistration.guami")?;
    require_str(guami, "amfId", "Amf3GppAccessRegistration.guami.amfId")?;
    let plmn = require_obj(guami, "plmnId", "Amf3GppAccessRegistration.guami.plmnId")?;
    require_str(plmn, "mcc", "Amf3GppAccessRegistration.guami.plmnId.mcc")?;
    require_str(plmn, "mnc", "Amf3GppAccessRegistration.guami.plmnId.mnc")?;
    require_str(body, "ratType", "Amf3GppAccessRegistration.ratType")?;
    Ok(())
}

/// Validate the mandatory IEs of an `AmfNon3GppAccessRegistration`
/// (TS 29.503 §6.2.6.2.x): the `Amf3GppAccessRegistration` set **plus**
/// `imsVoPs`, which the non-3GPP schema additionally marks required.
pub fn validate_amf_non_3gpp_registration(body: &Value) -> Result<(), ProblemDetails> {
    require_str(
        body,
        "amfInstanceId",
        "AmfNon3GppAccessRegistration.amfInstanceId",
    )?;
    require_str(
        body,
        "deregCallbackUri",
        "AmfNon3GppAccessRegistration.deregCallbackUri",
    )?;
    let guami = require_obj(body, "guami", "AmfNon3GppAccessRegistration.guami")?;
    require_str(guami, "amfId", "AmfNon3GppAccessRegistration.guami.amfId")?;
    let plmn = require_obj(guami, "plmnId", "AmfNon3GppAccessRegistration.guami.plmnId")?;
    require_str(plmn, "mcc", "AmfNon3GppAccessRegistration.guami.plmnId.mcc")?;
    require_str(plmn, "mnc", "AmfNon3GppAccessRegistration.guami.plmnId.mnc")?;
    require_str(body, "ratType", "AmfNon3GppAccessRegistration.ratType")?;
    require_str(body, "imsVoPs", "AmfNon3GppAccessRegistration.imsVoPs")?;
    Ok(())
}

/// Validate an AMF access registration for `access`.
pub fn validate_amf_registration(body: &Value, access: UecmAccess) -> Result<(), ProblemDetails> {
    match access {
        UecmAccess::ThreeGpp => validate_amf_3gpp_registration(body),
        UecmAccess::Non3Gpp => validate_amf_non_3gpp_registration(body),
    }
}

/// Validate the mandatory IEs of an `SmsfRegistration` (TS 29.503 §6.2.6.2.9):
/// `smsfInstanceId` and `plmnId{mcc, mnc}`.
pub fn validate_smsf_registration(body: &Value) -> Result<(), ProblemDetails> {
    require_str(body, "smsfInstanceId", "SmsfRegistration.smsfInstanceId")?;
    let plmn = require_obj(body, "plmnId", "SmsfRegistration.plmnId")?;
    require_str(plmn, "mcc", "SmsfRegistration.plmnId.mcc")?;
    require_str(plmn, "mnc", "SmsfRegistration.plmnId.mnc")?;
    Ok(())
}

/// The `IpSmGwRegistration` address members (TS 29.503 §6.2.6.2.16). The schema
/// is an `anyOf` over "at least one of these is present", so the check is
/// presence-of-any rather than a fixed required list.
const IP_SM_GW_ADDRESS_IES: [&str; 5] = [
    "ipSmGwMapAddress",
    "ipSmGwDiameterAddress",
    "ipsmgwIpv4",
    "ipsmgwIpv6",
    "ipsmgwFqdn",
];

/// Validate an `IpSmGwRegistration`: at least one address member must be
/// present, else the registration names no IP-SM-GW to route to.
pub fn validate_ip_sm_gw_registration(body: &Value) -> Result<(), ProblemDetails> {
    if !body.is_object() {
        return Err(ProblemDetails::mandatory_ie_missing(
            "IpSmGwRegistration must be a JSON object",
        ));
    }
    let has_address = IP_SM_GW_ADDRESS_IES.iter().any(|ie| match body.get(*ie) {
        None | Some(Value::Null) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    });
    if !has_address {
        return Err(ProblemDetails::mandatory_ie_missing(format!(
            "IpSmGwRegistration requires one of: {}",
            IP_SM_GW_ADDRESS_IES.join(", ")
        )));
    }
    Ok(())
}

/// Validate the mandatory IEs of an `SmfRegistration` (TS 29.503 §6.2.x):
/// `smfInstanceId`, `pduSessionId`, `singleNssai`, `dnn`.
pub fn validate_smf_registration(body: &Value) -> Result<(), ProblemDetails> {
    require_str(body, "smfInstanceId", "SmfRegistration.smfInstanceId")?;
    let psi_ok = body
        .get("pduSessionId")
        .map(|v| v.is_number() || v.is_string())
        .unwrap_or(false);
    if !psi_ok {
        return Err(ProblemDetails::mandatory_ie_missing(
            "SmfRegistration.pduSessionId is missing",
        ));
    }
    require_obj(body, "singleNssai", "SmfRegistration.singleNssai")?;
    require_str(body, "dnn", "SmfRegistration.dnn")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// UDR client abstraction (udmd-01/02) — Live talks to udrd; Mock is test-only
// ---------------------------------------------------------------------------

/// Client over the Nudr_DataRepository operations the live UECM handlers need.
///
/// `Live` discovers UDR and sends real requests; `Mock` (test-only) records the
/// outgoing operations so the handlers can be unit-gated without a running udrd.
pub enum UdrClient {
    /// Discovers and sends to the live UDR (Nudr_DataRepository).
    Live,
    /// Test double that records calls and replays canned responses.
    #[cfg(test)]
    Mock(std::sync::Arc<MockUdr>),
}

impl UdrClient {
    /// GET a `context-data` resource. `resource` is the path under
    /// `context-data/`, e.g. `amf-non-3gpp-access` or `smf-registrations/5`.
    ///
    /// One generic accessor per verb rather than one pair per resource: the #84
    /// overwrite existed because `amf_context_put` hardcoded
    /// `amf-3gpp-access`, and a hardcoded resource cannot be got wrong twice if
    /// there is nowhere left to hardcode it.
    async fn context_get(&self, supi: &str, resource: &str) -> Result<SbiResponse, String> {
        match self {
            UdrClient::Live => crate::sbi_path::udm_nudr_dr_send_context_get(supi, resource).await,
            #[cfg(test)]
            UdrClient::Mock(m) => Ok(m.context_get(supi, resource)),
        }
    }

    /// PUT a `context-data` resource.
    async fn context_put(
        &self,
        supi: &str,
        resource: &str,
        body: &Value,
    ) -> Result<SbiResponse, String> {
        match self {
            UdrClient::Live => {
                crate::sbi_path::udm_nudr_dr_send_context_put(supi, resource, body).await
            }
            #[cfg(test)]
            UdrClient::Mock(m) => Ok(m.context_put(supi, resource, body)),
        }
    }

    /// PATCH a `context-data` resource.
    async fn context_patch(
        &self,
        supi: &str,
        resource: &str,
        body: &Value,
    ) -> Result<SbiResponse, String> {
        match self {
            UdrClient::Live => {
                crate::sbi_path::udm_nudr_dr_send_context_patch(supi, resource, body).await
            }
            #[cfg(test)]
            UdrClient::Mock(m) => Ok(m.context_patch(supi, resource, body)),
        }
    }

    /// DELETE a `context-data` resource.
    async fn context_delete(&self, supi: &str, resource: &str) -> Result<SbiResponse, String> {
        match self {
            UdrClient::Live => {
                crate::sbi_path::udm_nudr_dr_send_context_delete(supi, resource).await
            }
            #[cfg(test)]
            UdrClient::Mock(m) => Ok(m.context_delete(supi, resource)),
        }
    }

    async fn send_dereg_notification(
        &self,
        callback_uri: &str,
        body: &Value,
    ) -> Result<SbiResponse, String> {
        match self {
            UdrClient::Live => {
                crate::sbi_path::udm_sbi_send_dereg_notification(callback_uri, body).await
            }
            #[cfg(test)]
            UdrClient::Mock(m) => Ok(m.send_dereg_notification(callback_uri, body)),
        }
    }
}

// ---------------------------------------------------------------------------
// Live UECM handlers (validate -> persist -> notify)
// ---------------------------------------------------------------------------

/// Read the prior AMF registration for `access`: UDR first (udmd-02), then the
/// local cache.
async fn read_prior_amf_registration(
    supi: &str,
    client: &UdrClient,
    access: UecmAccess,
) -> Option<Value> {
    if let Ok(resp) = client.context_get(supi, access.amf_resource()).await {
        if resp.is_success() {
            if let Some(v) = resp
                .http
                .content
                .as_deref()
                .and_then(|b| serde_json::from_str::<Value>(b).ok())
            {
                return Some(v);
            }
        }
    }
    cached_prior_amf_registration(supi, access)
}

/// Local-cache fallback for the prior AMF registration (amfInstanceId +
/// deregCallbackUri), used when UDR has no stored context-data.
///
/// Reads the cache slot for `access`: a UE registered over both accesses has two
/// serving AMFs, and answering the non-3GPP question with the 3GPP AMF would
/// send that AMF a deregistration for a registration it never lost.
fn cached_prior_amf_registration(supi: &str, access: UecmAccess) -> Option<Value> {
    let ctx = udm_self();
    let context = ctx.read().ok()?;
    let ue = context.ue_find_by_supi(supi)?;
    let (amf_id, callback) = match access {
        UecmAccess::ThreeGpp => (ue.amf_instance_id.clone()?, ue.dereg_callback_uri),
        UecmAccess::Non3Gpp => (
            ue.non_3gpp_amf_instance_id.clone()?,
            ue.non_3gpp_dereg_callback_uri,
        ),
    };
    Some(json!({
        "amfInstanceId": amf_id,
        "deregCallbackUri": callback,
    }))
}

/// Cache the serving-AMF identity locally so udmd-02 still works when UDR does
/// not persist context-data. `None` clears the slot (deregistration).
fn cache_amf_registration(supi: &str, body: Option<&Value>, access: UecmAccess) {
    let ctx = udm_self();
    let context = match ctx.read() {
        Ok(c) => c,
        Err(_) => return,
    };
    // A clear (`body == None`) never creates a UE: it would be created only to
    // be removed again by the deregistration that asked for the clear.
    let ue = context
        .ue_find_by_supi(supi)
        .or_else(|| body.and_then(|_| context.ue_add(supi)));
    if let Some(mut ue) = ue {
        let field = |key: &str| {
            body.and_then(|b| b.get(key))
                .and_then(|v| v.as_str())
                .map(String::from)
        };
        let amf_instance_id = field("amfInstanceId");
        let dereg_callback_uri = field("deregCallbackUri");
        match access {
            UecmAccess::ThreeGpp => {
                ue.amf_instance_id = amf_instance_id;
                ue.dereg_callback_uri = dereg_callback_uri;
            }
            UecmAccess::Non3Gpp => {
                ue.non_3gpp_amf_instance_id = amf_instance_id;
                ue.non_3gpp_dereg_callback_uri = dereg_callback_uri;
            }
        }
        context.ue_update(&ue);
    }
}

/// Build the Nudm_UECM `DeregistrationData` notification body (TS 29.503
/// §5.3.2.3.2): `deregReason` + `accessType`. Both members are mandatory — the
/// old AMF's dereg-notify handler keys its network-initiated deregistration on
/// `accessType` (WSB-4), so it must be present on the wire, and it must name the
/// access whose registration was actually superseded: a 3GPP-access value on a
/// non-3GPP re-registration makes the old AMF tear down a 3GPP registration
/// that is still live (#84). The old AMF's registration was superseded by a
/// fresh UE initial registration in the new AMF over that access. Exposed so
/// peer NF crates (amfd) can drive the exact wire body through their real
/// handler in strict-peer tests.
pub fn build_dereg_notification_body(access: UecmAccess) -> Value {
    json!({ "deregReason": "UE_INITIAL_REGISTRATION", "accessType": access.access_type() })
}

/// udmd-02: notify the old AMF if the serving AMF changed; suppress when the new
/// amfInstanceId equals the old one.
async fn notify_old_amf_if_changed(
    supi: &str,
    prior: &Value,
    new: &Value,
    client: &UdrClient,
    access: UecmAccess,
) {
    let old_id = prior.get("amfInstanceId").and_then(|v| v.as_str());
    let new_id = new.get("amfInstanceId").and_then(|v| v.as_str());
    let old_uri = prior.get("deregCallbackUri").and_then(|v| v.as_str());
    let (old_id, new_id, old_uri) = match (old_id, new_id, old_uri) {
        (Some(o), Some(n), Some(u)) if !u.is_empty() => (o, n, u),
        _ => return,
    };
    if old_id == new_id {
        // Suppression rule (TS 29.503 §5.3.2.2.2): same serving AMF, no notify.
        return;
    }
    let dereg = build_dereg_notification_body(access);
    match client.send_dereg_notification(old_uri, &dereg).await {
        Ok(resp) => log::info!(
            "[{supi}] Deregistration notification to old AMF {old_uri} -> {}",
            resp.status
        ),
        Err(e) => {
            log::warn!("[{supi}] Deregistration notification to old AMF {old_uri} failed: {e}")
        }
    }
}

/// Map a UDR write response. Returns `Some(503)` when UDR replied 5xx (the
/// handler should early-return it); otherwise `None`, degrading gracefully
/// (best-effort) on transport errors and non-5xx statuses so the matched-sim
/// happy path still completes when udrd lacks context-data support.
fn udr_write_outcome(
    supi: &str,
    op: &str,
    result: Result<SbiResponse, String>,
) -> Option<SbiResponse> {
    match result {
        Ok(resp) if resp.is_success() => None,
        Ok(resp) if resp.status >= 500 => {
            log::error!("[{supi}] UDR {op} returned {}", resp.status);
            Some(nextgcore_sbi::server::send_service_unavailable(
                "UDR persistence failed",
            ))
        }
        Ok(resp) => {
            log::warn!("[{supi}] UDR {op} returned {} (degraded)", resp.status);
            None
        }
        Err(e) => {
            log::warn!("[{supi}] UDR {op} failed: {e} (degraded)");
            None
        }
    }
}

/// Compare two GUAMI objects for equality (udmd-05).
///
/// Considers amfId + plmnId.mcc + plmnId.mnc. Missing fields never match.
fn guami_matches(a: &Value, b: &Value) -> bool {
    a.get("amfId").and_then(|x| x.as_str()) == b.get("amfId").and_then(|x| x.as_str())
        && a.pointer("/plmnId/mcc").and_then(|x| x.as_str())
            == b.pointer("/plmnId/mcc").and_then(|x| x.as_str())
        && a.pointer("/plmnId/mnc").and_then(|x| x.as_str())
            == b.pointer("/plmnId/mnc").and_then(|x| x.as_str())
}

/// Process an AMF access registration PUT for `access`
/// (udmd-03/01/02/06; TS 29.503 §5.3.2.2.2 `3GppRegistration` /
/// §5.3.2.4.2 `Non3GppRegistration`).
///
/// `access` selects the resource end to end — validation schema, UDR
/// `context-data` resource, cache slot, `Location` and the
/// `DeregistrationData.accessType` — so a non-3GPP registration cannot touch the
/// 3GPP one (#84).
pub async fn process_amf_registration(
    supi: &str,
    body: &Value,
    client: &UdrClient,
    access: UecmAccess,
) -> SbiResponse {
    // udmd-03: reject payloads missing any mandatory IE.
    if let Err(problem) = validate_amf_registration(body, access) {
        log::warn!(
            "[{supi}] AMF {} registration rejected: {}",
            access.amf_resource(),
            problem.detail
        );
        return problem.into_response();
    }

    // udmd-02: read the prior registration before overwriting.
    let prior = read_prior_amf_registration(supi, client, access).await;
    // udmd-06: remember whether a prior registration existed for status-code choice.
    let is_update = prior.is_some();

    // udmd-01: persist the validated registration to UDR.
    if let Some(resp) = udr_write_outcome(
        supi,
        "AMF context PUT",
        client.context_put(supi, access.amf_resource(), body).await,
    ) {
        return resp;
    }

    // udmd-02: notify the old AMF if the serving AMF changed.
    if let Some(prior) = prior {
        notify_old_amf_if_changed(supi, &prior, body, client, access).await;
    }

    // Local cache (UDR is the system of record).
    cache_amf_registration(supi, Some(body), access);

    // #83: the UE's AMF context data set just changed, so SDM subscribers
    // monitoring it get a ModificationNotification and EE subscribers get a
    // MonitoringReport. Awaited rather than spawned so the notification is
    // ordered after the UDR write it reports: a subscriber that reacts by reading
    // the data set must not find the state the notification is about missing.
    // Delivery failures are logged inside and never fail this operation.
    crate::notify::notify_ue_context_change(
        supi,
        if is_update {
            crate::notify::UeContextEvent::AmfContextUpdated
        } else {
            crate::notify::UeContextEvent::AmfRegistered
        },
    )
    .await;

    // udmd-06: 201 on create, 200 on update.
    let status = if is_update { 200 } else { 201 };
    let mut resp = SbiResponse::with_status(status)
        .with_json_body(&json!({
            "amfInstanceId": body.get("amfInstanceId"),
            "deregCallbackUri": body.get("deregCallbackUri"),
            "guami": body.get("guami"),
            "ratType": body.get("ratType"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(status));
    if status == 201 {
        resp = resp.with_header("Location", access.amf_location(supi));
    }
    resp
}

/// Read a `context-data` resource and parse it, mapping the UDR outcome to the
/// UECM read semantics: `Ok(Some(doc))` when stored, `Ok(None)` when UDR says
/// 404, `Err(response)` when UDR could not answer.
///
/// Shared by every UECM GET so a UDR fault is never reported to the consumer as
/// "not registered" — the distinction the read handlers below depend on.
async fn read_context_resource(
    supi: &str,
    client: &UdrClient,
    resource: &str,
) -> Result<Option<Value>, SbiResponse> {
    match client.context_get(supi, resource).await {
        Ok(resp) if resp.is_success() => match resp
            .http
            .content
            .as_deref()
            .and_then(|b| serde_json::from_str::<Value>(b).ok())
        {
            Some(v) => Ok(Some(v)),
            None => {
                log::error!("[{supi}] UDR {resource} GET returned unparseable body");
                Err(nextgcore_sbi::server::send_service_unavailable(
                    "UDR response invalid",
                ))
            }
        },
        Ok(resp) if resp.status == 404 => Ok(None),
        Ok(resp) => {
            log::error!("[{supi}] UDR {resource} GET returned {}", resp.status);
            Err(nextgcore_sbi::server::send_service_unavailable(
                "UDR context GET failed",
            ))
        }
        Err(e) => {
            log::warn!("[{supi}] UDR {resource} GET failed: {e}");
            Err(nextgcore_sbi::server::send_service_unavailable(
                "UDR unavailable",
            ))
        }
    }
}

/// A `404 CONTEXT_NOT_FOUND` for an addressed-but-unregistered UECM resource.
fn context_not_found(resource: &str) -> SbiResponse {
    ProblemDetails {
        status: 404,
        cause: "CONTEXT_NOT_FOUND".to_string(),
        detail: format!("No {resource} registration stored for this UE"),
    }
    .into_response()
}

/// Process a GET of an AMF access registration (TS 29.503 §5.3.2.5
/// `Get3GppRegistration` / `GetNon3GppRegistration`): read-through to the UDR
/// `context-data` resource for `access`.
pub async fn process_amf_registration_get(
    supi: &str,
    client: &UdrClient,
    access: UecmAccess,
) -> SbiResponse {
    match read_context_resource(supi, client, access.amf_resource()).await {
        Ok(Some(doc)) => SbiResponse::with_status(200)
            .with_json_body(&doc)
            .unwrap_or_else(|_| nextgcore_sbi::server::send_internal_error("serialize failed")),
        Ok(None) => context_not_found(access.amf_resource()),
        Err(resp) => resp,
    }
}

/// Process a PATCH to an AMF access registration (udmd-05; TS 29.503
/// §5.3.2.4.2 `UpdateAmfRegistration` / `UpdateNon3GppRegistration`).
///
/// Validates that the GUAMI in the PATCH body matches the stored registration
/// (ownership check, TS 29.503 §5.3.2.4); applies the update to UDR on match.
/// A `purgeFlag` of `true` is a **deregistration**, not a field update: TS 29.503
/// §5.3.2.4.2 defines it as the AMF telling the UDM the UE's context is gone, so
/// leaving the registration in place after acknowledging it (as this handler did
/// before #84) makes the UDM keep answering with a serving AMF that has already
/// released the UE.
pub async fn process_amf_registration_update(
    supi: &str,
    body: &Value,
    client: &UdrClient,
    access: UecmAccess,
) -> SbiResponse {
    // Read the stored registration.
    let stored = match read_context_resource(supi, client, access.amf_resource()).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return ProblemDetails {
                status: 404,
                cause: "CONTEXT_NOT_FOUND".to_string(),
                detail: "No AMF registration found for this SUPI".to_string(),
            }
            .into_response();
        }
        Err(resp) => return resp,
    };

    // GUAMI ownership check (TS 29.503 §5.3.2.4).
    //
    // Checked only when the PATCH carries a GUAMI. The IE is required by the
    // `Amf3GppAccessRegistrationModification` schema, but the repo's own AMF
    // sends a bare `{"purgeFlag": true}` on deregistration, and refusing that
    // would turn a working deregistration into a 400 — so an absent GUAMI is
    // accepted and only a *disagreeing* one is refused.
    if let (Some(stored_guami), Some(req_guami)) = (stored.get("guami"), body.get("guami")) {
        if !guami_matches(stored_guami, req_guami) {
            log::warn!("[{supi}] PATCH rejected: GUAMI mismatch");
            return ProblemDetails {
                status: 403,
                cause: "INVALID_GUAMI".to_string(),
                detail: "GUAMI in PATCH body does not match stored registration".to_string(),
            }
            .into_response();
        }
    }

    // purgeFlag == true is a deregistration (TS 29.503 §5.3.2.4.2), so the
    // resource is removed rather than patched.
    if body.get("purgeFlag").and_then(|v| v.as_bool()) == Some(true) {
        log::info!(
            "[{supi}] UECM PATCH carries purgeFlag -> deregistering {}",
            access.amf_resource()
        );
        return process_amf_deregistration(supi, client, access).await;
    }

    // Apply the PATCH to UDR.
    if let Some(err_resp) = udr_write_outcome(
        supi,
        "AMF context PATCH",
        client
            .context_patch(supi, access.amf_resource(), body)
            .await,
    ) {
        return err_resp;
    }

    SbiResponse::with_status(204)
}

/// Process a `POST .../registrations/amf-3gpp-access/dereg-amf` (TS 29.503
/// §5.3.2.4.2 `DeregAMF`), the spec-defined AMF deregistration.
///
/// The body is an `AmfDeregInfo`, whose only member — `deregReason` — is
/// mandatory. It is validated rather than ignored because the reason is the
/// only thing distinguishing this from an accidental POST, and a 204 for a
/// bodyless request would report a deregistration the consumer did not describe.
pub async fn process_dereg_amf(supi: &str, body: &Value, client: &UdrClient) -> SbiResponse {
    if let Err(problem) = require_str(body, "deregReason", "AmfDeregInfo.deregReason") {
        log::warn!("[{supi}] dereg-amf rejected: {}", problem.detail);
        return problem.into_response();
    }
    let reason = body
        .get("deregReason")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    log::info!("[{supi}] UECM dereg-amf (deregReason={reason})");
    process_amf_deregistration(supi, client, UecmAccess::ThreeGpp).await
}

/// The UDR `context-data` resource for one PDU session's SMF registration.
fn smf_registration_resource(pdu_session_id: &str) -> String {
    format!("smf-registrations/{pdu_session_id}")
}

/// Process an SMF registration PUT (udmd-03/01/06).
pub async fn process_smf_registration(
    supi: &str,
    pdu_session_id: &str,
    body: &Value,
    client: &UdrClient,
) -> SbiResponse {
    // udmd-03: reject payloads missing any mandatory IE.
    if let Err(problem) = validate_smf_registration(body) {
        log::warn!("[{supi}] SMF registration rejected: {}", problem.detail);
        return problem.into_response();
    }

    let resource = smf_registration_resource(pdu_session_id);

    // udmd-06: check whether a prior registration exists.
    let is_update = matches!(
        client.context_get(supi, &resource).await,
        Ok(resp) if resp.is_success()
    );

    // udmd-01: persist the per-PDU-session registration to UDR.
    if let Some(resp) = udr_write_outcome(
        supi,
        "SMF context PUT",
        client.context_put(supi, &resource, body).await,
    ) {
        return resp;
    }

    // #83: the UE's SMF context data set just changed, so SDM subscribers
    // monitoring it get a ModificationNotification and EE subscribers get a
    // MonitoringReport. Awaited rather than spawned so the notification is
    // ordered after the UDR write it reports: a subscriber that reacts by reading
    // the data set must not find the state the notification is about missing.
    // Delivery failures are logged inside and never fail this operation.
    crate::notify::notify_ue_context_change(supi, crate::notify::UeContextEvent::SmfRegistered)
        .await;

    // udmd-06: 201 on create, 200 on update.
    let status = if is_update { 200 } else { 201 };
    let mut resp = SbiResponse::with_status(status)
        .with_json_body(&json!({
            "smfInstanceId": body.get("smfInstanceId"),
            "pduSessionId": body.get("pduSessionId"),
            "singleNssai": body.get("singleNssai"),
            "dnn": body.get("dnn"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(status));
    if status == 201 {
        resp = resp.with_header(
            "Location",
            format!("/nudm-uecm/v1/{supi}/registrations/smf-registrations/{pdu_session_id}"),
        );
    }
    resp
}

/// Process an AMF deregistration for `access` (udmd-01): purge the UDR
/// context-data resource for that access, then return 204.
///
/// The local UE context is only dropped once **neither** access holds a
/// registration: a UE deregistering from non-3GPP access while still registered
/// over 3GPP must keep its cached 3GPP serving AMF, or the next 3GPP
/// re-registration cannot find an old AMF to notify.
pub async fn process_amf_deregistration(
    supi: &str,
    client: &UdrClient,
    access: UecmAccess,
) -> SbiResponse {
    if let Err(e) = client.context_delete(supi, access.amf_resource()).await {
        log::warn!("[{supi}] UDR AMF context DELETE failed: {e} (degraded)");
    }

    // Local cache cleanup: clear this access's slot, and drop the UE entirely
    // only when the other access is not registered either.
    cache_amf_registration(supi, None, access);
    let ctx = udm_self();
    if let Ok(context) = ctx.read() {
        if let Some(ue) = context.ue_find_by_supi(supi) {
            if ue.amf_instance_id.is_none() && ue.non_3gpp_amf_instance_id.is_none() {
                context.ue_remove(ue.id);
            }
        }
    }

    // #83: the UE's AMF context data set just changed, so SDM subscribers
    // monitoring it get a ModificationNotification and EE subscribers get a
    // MonitoringReport. Awaited rather than spawned so the notification is
    // ordered after the UDR write it reports: a subscriber that reacts by reading
    // the data set must not find the state the notification is about missing.
    // Delivery failures are logged inside and never fail this operation.
    crate::notify::notify_ue_context_change(supi, crate::notify::UeContextEvent::AmfDeregistered)
        .await;

    SbiResponse::with_status(204)
}

/// Process an SMF deregistration DELETE (udmd-01): purge the per-PDU-session UDR
/// context-data, then return 204.
pub async fn process_smf_deregistration(
    supi: &str,
    pdu_session_id: &str,
    client: &UdrClient,
) -> SbiResponse {
    let relative = smf_registration_resource(pdu_session_id);
    if let Err(e) = client.context_delete(supi, &relative).await {
        log::warn!("[{supi}] UDR SMF context DELETE failed: {e} (degraded)");
    }

    // #83: the SMF context data set changed; see the AMF sites above.
    crate::notify::notify_ue_context_change(supi, crate::notify::UeContextEvent::SmfDeregistered)
        .await;

    SbiResponse::with_status(204)
}

/// Process a GET of one PDU session's SMF registration (TS 29.503 §5.3.2.5).
pub async fn process_smf_registration_get(
    supi: &str,
    pdu_session_id: &str,
    client: &UdrClient,
) -> SbiResponse {
    let resource = smf_registration_resource(pdu_session_id);
    match read_context_resource(supi, client, &resource).await {
        Ok(Some(doc)) => SbiResponse::with_status(200)
            .with_json_body(&doc)
            .unwrap_or_else(|_| nextgcore_sbi::server::send_internal_error("serialize failed")),
        Ok(None) => context_not_found(&resource),
        Err(resp) => resp,
    }
}

/// Process a GET of the SMF-registration **collection** (TS 29.503 §5.3.2.5
/// `GetSmfRegistration`), returning an `SmfRegistrationInfo`.
///
/// The UDR collection resource answers with a bare JSON array (TS 29.505), while
/// the UECM operation is defined to return the `SmfRegistrationInfo` object with
/// its `smfRegistrationList` member — so the wrap happens here rather than
/// forwarding the UDR shape and hoping the consumer is lenient. An empty list is
/// a 404: `smfRegistrationList` has `minItems: 1`, so "registered for nothing"
/// is not a representable answer.
pub async fn process_smf_registrations_get(supi: &str, client: &UdrClient) -> SbiResponse {
    let doc = match read_context_resource(supi, client, "smf-registrations").await {
        Ok(Some(doc)) => doc,
        Ok(None) => return context_not_found("smf-registrations"),
        Err(resp) => return resp,
    };
    // Accept both the UDR array form and an already-wrapped object, so a UDR
    // that grows the object form later does not double-wrap.
    let list = match &doc {
        Value::Array(items) => items.clone(),
        Value::Object(_) => match doc.get("smfRegistrationList").and_then(|v| v.as_array()) {
            Some(items) => items.clone(),
            // A single SmfRegistration document: treat as a one-element list.
            None => vec![doc.clone()],
        },
        _ => {
            log::error!("[{supi}] UDR smf-registrations returned neither array nor object");
            return nextgcore_sbi::server::send_service_unavailable("UDR response invalid");
        }
    };
    if list.is_empty() {
        return context_not_found("smf-registrations");
    }
    SbiResponse::with_status(200)
        .with_json_body(&json!({ "smfRegistrationList": list }))
        .unwrap_or_else(|_| nextgcore_sbi::server::send_internal_error("serialize failed"))
}

/// Process a GET of the UE's location information (TS 29.503 §5.3.2.5
/// `GetLocationInfo`), returning a `LocationInfo`.
///
/// Composed from the stored AMF registrations rather than read from a UDR
/// resource of its own, because that is what the IE holds: `LocationInfo` is a
/// list of `RegistrationLocationInfo`, each naming the serving AMF and the
/// access types it serves. One AMF serving both accesses therefore yields ONE
/// entry with two `accessTypeList` members — not two entries — which is also
/// what keeps the list inside its `maxItems: 2` bound.
pub async fn process_location_info_get(supi: &str, client: &UdrClient) -> SbiResponse {
    let three_gpp = read_context_resource(supi, client, UecmAccess::ThreeGpp.amf_resource()).await;
    let non_3gpp = read_context_resource(supi, client, UecmAccess::Non3Gpp.amf_resource()).await;
    // A UDR fault on either read is reported as such: answering with a partial
    // location would claim the UE is registered over one access only.
    let three_gpp = match three_gpp {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let non_3gpp = match non_3gpp {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let mut entries: Vec<Value> = Vec::new();
    for (reg, access) in [
        (three_gpp, UecmAccess::ThreeGpp),
        (non_3gpp, UecmAccess::Non3Gpp),
    ] {
        let Some(reg) = reg else { continue };
        let Some(amf_instance_id) = reg.get("amfInstanceId").and_then(|v| v.as_str()) else {
            log::warn!(
                "[{supi}] stored {} registration has no amfInstanceId — omitted from LocationInfo",
                access.amf_resource()
            );
            continue;
        };
        // Same AMF on both accesses -> one entry carrying both access types.
        if let Some(existing) = entries
            .iter_mut()
            .find(|e| e.get("amfInstanceId").and_then(|v| v.as_str()) == Some(amf_instance_id))
        {
            if let Some(list) = existing
                .get_mut("accessTypeList")
                .and_then(|v| v.as_array_mut())
            {
                list.push(json!(access.access_type()));
            }
            continue;
        }
        let mut entry = json!({
            "amfInstanceId": amf_instance_id,
            "accessTypeList": [access.access_type()],
        });
        if let (Some(obj), Some(guami)) = (entry.as_object_mut(), reg.get("guami")) {
            obj.insert("guami".to_string(), guami.clone());
            if let Some(plmn) = guami.get("plmnId") {
                obj.insert("plmnId".to_string(), plmn.clone());
            }
        }
        entries.push(entry);
    }

    if entries.is_empty() {
        return context_not_found("location");
    }
    let mut info = json!({ "registrationLocationInfoList": entries, "supi": supi });
    if let (Some(obj), Some(gpsi)) = (info.as_object_mut(), cached_gpsi(supi)) {
        obj.insert("gpsi".to_string(), json!(gpsi));
    }
    SbiResponse::with_status(200)
        .with_json_body(&info)
        .unwrap_or_else(|_| nextgcore_sbi::server::send_internal_error("serialize failed"))
}

/// The UE's GPSI, if the UDM happens to hold one.
///
/// Always `None` today: the UDM never learns a GPSI, which is its own tracked
/// defect (#205 on the AMF side, #85 for the UDM's identifier translation). The
/// hook exists so `LocationInfo.gpsi` is populated the moment a GPSI is
/// available rather than fabricating one from the SUPI, which would be a
/// different subscriber identity.
fn cached_gpsi(_supi: &str) -> Option<String> {
    None
}

/// Process an SMSF registration PUT for `access` (TS 29.503 §5.3.2.x
/// `3GppSmsfRegistration` / `Non3GppSmsfRegistration`).
pub async fn process_smsf_registration(
    supi: &str,
    body: &Value,
    client: &UdrClient,
    access: UecmAccess,
) -> SbiResponse {
    if let Err(problem) = validate_smsf_registration(body) {
        log::warn!("[{supi}] SMSF registration rejected: {}", problem.detail);
        return problem.into_response();
    }
    let resource = access.smsf_resource();
    let is_update = matches!(
        client.context_get(supi, resource).await,
        Ok(resp) if resp.is_success()
    );
    if let Some(resp) = udr_write_outcome(
        supi,
        "SMSF context PUT",
        client.context_put(supi, resource, body).await,
    ) {
        return resp;
    }
    let status = if is_update { 200 } else { 201 };
    let mut resp = SbiResponse::with_status(status)
        .with_json_body(body)
        .unwrap_or_else(|_| SbiResponse::with_status(status));
    if status == 201 {
        resp = resp.with_header(
            "Location",
            format!("/nudm-uecm/v1/{supi}/registrations/{resource}"),
        );
    }
    resp
}

/// Process an SMSF registration GET for `access` (TS 29.503
/// `Get3GppSmsfRegistration` / `GetNon3GppSmsfRegistration`).
pub async fn process_smsf_registration_get(
    supi: &str,
    client: &UdrClient,
    access: UecmAccess,
) -> SbiResponse {
    match read_context_resource(supi, client, access.smsf_resource()).await {
        Ok(Some(doc)) => SbiResponse::with_status(200)
            .with_json_body(&doc)
            .unwrap_or_else(|_| nextgcore_sbi::server::send_internal_error("serialize failed")),
        Ok(None) => context_not_found(access.smsf_resource()),
        Err(resp) => resp,
    }
}

/// Process an SMSF deregistration DELETE for `access`
/// (`3GppSmsfDeregistration` / `Non3GppSmsfDeregistration`).
pub async fn process_smsf_deregistration(
    supi: &str,
    client: &UdrClient,
    access: UecmAccess,
) -> SbiResponse {
    if let Err(e) = client.context_delete(supi, access.smsf_resource()).await {
        log::warn!("[{supi}] UDR SMSF context DELETE failed: {e} (degraded)");
    }
    SbiResponse::with_status(204)
}

/// The UDR `context-data` resource holding the IP-SM-GW registration.
const IP_SM_GW_RESOURCE: &str = "ip-sm-gw";

/// Process an IP-SM-GW registration PUT (TS 29.503 `IpSmGwRegistration`).
pub async fn process_ip_sm_gw_registration(
    supi: &str,
    body: &Value,
    client: &UdrClient,
) -> SbiResponse {
    if let Err(problem) = validate_ip_sm_gw_registration(body) {
        log::warn!(
            "[{supi}] IP-SM-GW registration rejected: {}",
            problem.detail
        );
        return problem.into_response();
    }
    let is_update = matches!(
        client.context_get(supi, IP_SM_GW_RESOURCE).await,
        Ok(resp) if resp.is_success()
    );
    if let Some(resp) = udr_write_outcome(
        supi,
        "IP-SM-GW context PUT",
        client.context_put(supi, IP_SM_GW_RESOURCE, body).await,
    ) {
        return resp;
    }
    let status = if is_update { 200 } else { 201 };
    let mut resp = SbiResponse::with_status(status)
        .with_json_body(body)
        .unwrap_or_else(|_| SbiResponse::with_status(status));
    if status == 201 {
        resp = resp.with_header(
            "Location",
            format!("/nudm-uecm/v1/{supi}/registrations/{IP_SM_GW_RESOURCE}"),
        );
    }
    resp
}

/// Process an IP-SM-GW registration GET (`GetIpSmGwRegistration`).
pub async fn process_ip_sm_gw_registration_get(supi: &str, client: &UdrClient) -> SbiResponse {
    match read_context_resource(supi, client, IP_SM_GW_RESOURCE).await {
        Ok(Some(doc)) => SbiResponse::with_status(200)
            .with_json_body(&doc)
            .unwrap_or_else(|_| nextgcore_sbi::server::send_internal_error("serialize failed")),
        Ok(None) => context_not_found(IP_SM_GW_RESOURCE),
        Err(resp) => resp,
    }
}

/// Process an IP-SM-GW deregistration DELETE (`IpSmGwDeregistration`).
pub async fn process_ip_sm_gw_deregistration(supi: &str, client: &UdrClient) -> SbiResponse {
    if let Err(e) = client.context_delete(supi, IP_SM_GW_RESOURCE).await {
        log::warn!("[{supi}] UDR IP-SM-GW context DELETE failed: {e} (degraded)");
    }
    SbiResponse::with_status(204)
}

// ---------------------------------------------------------------------------
// Test double (mock UDR)
// ---------------------------------------------------------------------------

/// A recorded outgoing UDR / old-AMF operation (test-only).
///
/// `resource` is the `context-data` resource the call addressed
/// (`amf-3gpp-access`, `amf-non-3gpp-access`, `smf-registrations/5`, ...), so a
/// test can pin *which* resource a handler touched — the assertion the #84
/// overwrite defect needed and did not have.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq)]
pub enum UdrCall {
    CtxGet {
        supi: String,
        resource: String,
    },
    CtxPut {
        supi: String,
        resource: String,
        body: Value,
    },
    CtxPatch {
        supi: String,
        resource: String,
        body: Value,
    },
    CtxDelete {
        supi: String,
        resource: String,
    },
    DeregNotify {
        callback_uri: String,
        body: Value,
    },
}

/// Stateful mock UDR: `context_get` returns the last value stored by
/// `context_put` for the SAME resource (or a seeded prior), so re-registration
/// scenarios behave like a real repository and a write to one resource is
/// invisible to a read of another.
#[cfg(test)]
pub struct MockUdr {
    stored: std::sync::Mutex<std::collections::HashMap<String, Value>>,
    put_status: u16,
    patch_status: u16,
    dereg_status: u16,
    /// When set, every `context_get` answers with this status instead of
    /// consulting `stored` — the UDR-fault case a read handler must not confuse
    /// with "no such registration".
    get_status: Option<u16>,
    calls: std::sync::Mutex<Vec<UdrCall>>,
}

#[cfg(test)]
impl MockUdr {
    fn new() -> Self {
        Self {
            stored: std::sync::Mutex::new(std::collections::HashMap::new()),
            put_status: 201,
            patch_status: 204,
            dereg_status: 204,
            get_status: None,
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Make every `context_get` fail with `status`.
    fn with_get_status(mut self, status: u16) -> Self {
        self.get_status = Some(status);
        self
    }

    /// Seed a stored `amf-3gpp-access` registration.
    fn with_prior(prior: Value) -> Self {
        Self::new().with_stored(UecmAccess::ThreeGpp.amf_resource(), prior)
    }

    /// Seed an arbitrary stored `context-data` resource.
    fn with_stored(self, resource: &str, doc: Value) -> Self {
        self.stored
            .lock()
            .unwrap()
            .insert(resource.to_string(), doc);
        self
    }

    /// Override the status the mocked old-AMF dereg-notify callback returns
    /// (default 204). Used by the H3 step-3 "logs-and-continues" test to prove
    /// a FAILING notification does not wedge udmd's re-registration
    /// (TS 29.503 §5.3.2.2.2 best-effort semantics).
    fn with_dereg_status(mut self, status: u16) -> Self {
        self.dereg_status = status;
        self
    }

    /// The document currently stored under `resource`, if any.
    fn stored_doc(&self, resource: &str) -> Option<Value> {
        self.stored.lock().unwrap().get(resource).cloned()
    }

    fn context_get(&self, supi: &str, resource: &str) -> SbiResponse {
        self.calls.lock().unwrap().push(UdrCall::CtxGet {
            supi: supi.to_string(),
            resource: resource.to_string(),
        });
        if let Some(status) = self.get_status {
            return SbiResponse::with_status(status);
        }
        match self.stored_doc(resource) {
            Some(v) => SbiResponse::with_status(200)
                .with_json_body(&v)
                .unwrap_or_else(|_| SbiResponse::with_status(200)),
            None => SbiResponse::with_status(404),
        }
    }

    fn context_put(&self, supi: &str, resource: &str, body: &Value) -> SbiResponse {
        self.calls.lock().unwrap().push(UdrCall::CtxPut {
            supi: supi.to_string(),
            resource: resource.to_string(),
            body: body.clone(),
        });
        self.stored
            .lock()
            .unwrap()
            .insert(resource.to_string(), body.clone());
        SbiResponse::with_status(self.put_status)
    }

    fn context_patch(&self, supi: &str, resource: &str, body: &Value) -> SbiResponse {
        self.calls.lock().unwrap().push(UdrCall::CtxPatch {
            supi: supi.to_string(),
            resource: resource.to_string(),
            body: body.clone(),
        });
        SbiResponse::with_status(self.patch_status)
    }

    fn context_delete(&self, supi: &str, resource: &str) -> SbiResponse {
        self.calls.lock().unwrap().push(UdrCall::CtxDelete {
            supi: supi.to_string(),
            resource: resource.to_string(),
        });
        self.stored.lock().unwrap().remove(resource);
        SbiResponse::with_status(204)
    }

    fn send_dereg_notification(&self, callback_uri: &str, body: &Value) -> SbiResponse {
        self.calls.lock().unwrap().push(UdrCall::DeregNotify {
            callback_uri: callback_uri.to_string(),
            body: body.clone(),
        });
        SbiResponse::with_status(self.dereg_status)
    }

    fn calls(&self) -> Vec<UdrCall> {
        self.calls.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn valid_amf_body() -> Value {
        json!({
            "amfInstanceId": "amf-a-0001",
            "deregCallbackUri": "http://amf-a.example.org:7777/namf-callback/v1/imsi-x/dereg-notify",
            "guami": {
                "plmnId": { "mcc": "001", "mnc": "01" },
                "amfId": "cafe00"
            },
            "ratType": "NR"
        })
    }

    fn valid_smf_body() -> Value {
        json!({
            "smfInstanceId": "smf-0001",
            "pduSessionId": 5,
            "singleNssai": { "sst": 1, "sd": "000001" },
            "dnn": "internet"
        })
    }

    fn problem_cause(resp: &SbiResponse) -> Option<String> {
        let v: Value = serde_json::from_str(resp.http.content.as_deref()?).ok()?;
        v.get("cause").and_then(|c| c.as_str()).map(String::from)
    }

    fn remove_path(mut v: Value, path: &[&str]) -> Value {
        let (last, parents) = path.split_last().expect("non-empty path");
        let mut cur = &mut v;
        for p in parents {
            cur = cur.get_mut(*p).expect("intermediate path exists");
        }
        cur.as_object_mut().expect("parent is object").remove(*last);
        v
    }

    fn deregister_count(calls: &[UdrCall]) -> usize {
        calls
            .iter()
            .filter(|c| matches!(c, UdrCall::DeregNotify { .. }))
            .count()
    }

    // ----- udmd-03 ---------------------------------------------------------

    #[tokio::test]
    async fn test_amf_registration_missing_each_mandatory_ie_returns_400() {
        let missing: &[&[&str]] = &[
            &["amfInstanceId"],
            &["deregCallbackUri"],
            &["guami"],
            &["guami", "amfId"],
            &["guami", "plmnId", "mcc"],
            &["guami", "plmnId", "mnc"],
            &["ratType"],
        ];
        for path in missing {
            let body = remove_path(valid_amf_body(), path);
            let mock = Arc::new(MockUdr::new());
            let client = UdrClient::Mock(mock.clone());
            let resp = process_amf_registration(
                "imsi-001010000000301",
                &body,
                &client,
                UecmAccess::ThreeGpp,
            )
            .await;
            assert_eq!(resp.status, 400, "missing {path:?} should be 400");
            assert_eq!(
                problem_cause(&resp).as_deref(),
                Some("MANDATORY_IE_MISSING"),
                "missing {path:?} cause"
            );
            // Validation must short-circuit before any UDR write.
            assert!(
                !mock.calls().iter().any(|c| matches!(
                    c,
                    UdrCall::CtxPut { resource, .. } if resource == "amf-3gpp-access"
                )),
                "missing {path:?} must not persist to UDR"
            );
        }
    }

    #[tokio::test]
    async fn test_smf_registration_missing_each_mandatory_ie_returns_400() {
        let missing: &[&[&str]] = &[
            &["smfInstanceId"],
            &["pduSessionId"],
            &["singleNssai"],
            &["dnn"],
        ];
        for path in missing {
            let body = remove_path(valid_smf_body(), path);
            let mock = Arc::new(MockUdr::new());
            let client = UdrClient::Mock(mock.clone());
            let resp = process_smf_registration("imsi-001010000000302", "5", &body, &client).await;
            assert_eq!(resp.status, 400, "missing {path:?} should be 400");
            assert_eq!(
                problem_cause(&resp).as_deref(),
                Some("MANDATORY_IE_MISSING"),
                "missing {path:?} cause"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_amf_registration_complete_returns_201() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());
        let resp = process_amf_registration(
            "imsi-001010000000303",
            &valid_amf_body(),
            &client,
            UecmAccess::ThreeGpp,
        )
        .await;
        assert_eq!(resp.status, 201);
    }

    // ----- udmd-01 ---------------------------------------------------------

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_amf_registration_persists_put_to_udr() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000000310";
        let body = valid_amf_body();
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());

        let resp = process_amf_registration(supi, &body, &client, UecmAccess::ThreeGpp).await;
        assert_eq!(resp.status, 201);

        let put = mock.calls().into_iter().find_map(|c| match c {
            UdrCall::CtxPut {
                supi,
                resource,
                body,
            } if resource == "amf-3gpp-access" => Some((supi, body)),
            _ => None,
        });
        let (put_supi, put_body) = put.expect("an AMF context PUT was issued to UDR");
        assert_eq!(put_supi, supi);
        assert_eq!(put_body, body, "PUT carries the received registration body");
    }

    #[tokio::test]
    async fn test_smf_registration_persists_put_to_udr() {
        let supi = "imsi-001010000000311";
        let body = valid_smf_body();
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());

        let resp = process_smf_registration(supi, "5", &body, &client).await;
        assert_eq!(resp.status, 201);

        let put = mock.calls().into_iter().find_map(|c| match c {
            UdrCall::CtxPut {
                supi,
                resource,
                body,
            } if resource.starts_with("smf-registrations/") => Some((supi, resource, body)),
            _ => None,
        });
        let (put_supi, resource, put_body) = put.expect("an SMF context PUT was issued to UDR");
        assert_eq!(put_supi, supi);
        assert_eq!(resource, "smf-registrations/5");
        assert_eq!(put_body, body);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_amf_registration_udr_5xx_maps_to_503() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let mut mock = MockUdr::new();
        mock.put_status = 500;
        let mock = Arc::new(mock);
        let client = UdrClient::Mock(mock.clone());
        let resp = process_amf_registration(
            "imsi-001010000000312",
            &valid_amf_body(),
            &client,
            UecmAccess::ThreeGpp,
        )
        .await;
        assert_eq!(resp.status, 503, "UDR 5xx maps to 503");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_amf_deregistration_deletes_udr_context() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000000313";
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());
        let resp = process_amf_deregistration(supi, &client, UecmAccess::ThreeGpp).await;
        assert_eq!(resp.status, 204);
        assert!(
            mock.calls().iter().any(|c| matches!(
                c,
                UdrCall::CtxDelete { resource, .. } if resource == "amf-3gpp-access"
            )),
            "deregistration issues a UDR context-data DELETE"
        );
    }

    // ----- udmd-05 ---------------------------------------------------------

    #[tokio::test]
    async fn test_amf_registration_update_wrong_guami_returns_403() {
        let stored = json!({
            "amfInstanceId": "amf-a-0001",
            "deregCallbackUri": "http://amf-a.example.org/dereg",
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
            "ratType": "NR"
        });
        let mock = Arc::new(MockUdr::with_prior(stored));
        let client = UdrClient::Mock(mock.clone());

        let wrong_guami = json!({
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "deadff" },
            "purgeFlag": true
        });
        let resp = process_amf_registration_update(
            "imsi-udmd05-0001",
            &wrong_guami,
            &client,
            UecmAccess::ThreeGpp,
        )
        .await;
        assert_eq!(resp.status, 403, "wrong GUAMI must be 403");
        assert_eq!(
            problem_cause(&resp).as_deref(),
            Some("INVALID_GUAMI"),
            "cause must be INVALID_GUAMI"
        );
        // No PATCH should have been sent to UDR
        assert!(
            !mock
                .calls()
                .iter()
                .any(|c| matches!(c, UdrCall::CtxPatch { .. } | UdrCall::CtxDelete { .. })),
            "neither a UDR PATCH nor a DELETE may be issued when GUAMI mismatches"
        );
    }

    #[tokio::test]
    async fn test_amf_registration_update_matching_guami_returns_204_and_patches_udr() {
        let stored = json!({
            "amfInstanceId": "amf-a-0001",
            "deregCallbackUri": "http://amf-a.example.org/dereg",
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
            "ratType": "NR"
        });
        let mock = Arc::new(MockUdr::with_prior(stored));
        let client = UdrClient::Mock(mock.clone());

        // A genuine field modification, NOT a purge: `purgeFlag: true` is a
        // deregistration (TS 29.503 §5.3.2.4.2) and is covered by its own test
        // below, so using it here would test the wrong branch of this handler.
        let patch = json!({
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
            "pei": "imeisv-1234567890123456"
        });
        let resp = process_amf_registration_update(
            "imsi-udmd05-0002",
            &patch,
            &client,
            UecmAccess::ThreeGpp,
        )
        .await;
        assert_eq!(resp.status, 204, "matching GUAMI must be 204");
        assert!(
            mock.calls()
                .iter()
                .any(|c| matches!(c, UdrCall::CtxPatch { .. })),
            "UDR PATCH must be issued when GUAMI matches"
        );
    }

    #[tokio::test]
    async fn test_amf_registration_update_no_prior_returns_404() {
        // Empty mock → no stored registration → 404
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock);
        let patch =
            json!({ "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" } });
        let resp = process_amf_registration_update(
            "imsi-udmd05-0003",
            &patch,
            &client,
            UecmAccess::ThreeGpp,
        )
        .await;
        assert_eq!(resp.status, 404);
    }

    // ----- udmd-06 ---------------------------------------------------------

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_amf_registration_first_put_201_second_put_200() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-udmd06-0001";
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());

        // First PUT → no prior → 201 + Location
        let resp =
            process_amf_registration(supi, &valid_amf_body(), &client, UecmAccess::ThreeGpp).await;
        assert_eq!(resp.status, 201, "first PUT must be 201");
        // set_header lowercases all header keys (HTTP/2 convention).
        let loc = resp
            .http
            .headers
            .get("location")
            .cloned()
            .unwrap_or_default();
        assert!(
            loc.contains(supi),
            "Location header must reference the SUPI"
        );

        // Second PUT → prior exists → 200
        let resp =
            process_amf_registration(supi, &valid_amf_body(), &client, UecmAccess::ThreeGpp).await;
        assert_eq!(resp.status, 200, "second PUT must be 200");
    }

    #[tokio::test]
    async fn test_smf_registration_first_put_201_second_put_200() {
        let supi = "imsi-udmd06-0002";
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());

        // First PUT → 201
        let resp = process_smf_registration(supi, "5", &valid_smf_body(), &client).await;
        assert_eq!(resp.status, 201, "first SMF PUT must be 201");

        // Second PUT → prior stored → 200
        let resp = process_smf_registration(supi, "5", &valid_smf_body(), &client).await;
        assert_eq!(resp.status, 200, "second SMF PUT must be 200");
    }

    // ----- udmd-02 ---------------------------------------------------------

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_reregistration_notifies_old_amf_then_suppresses_same_id() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000000320";
        let amf_a_uri =
            "http://amf-a.example.org:7777/namf-callback/v1/imsi-x/dereg-notify".to_string();

        let prior = json!({
            "amfInstanceId": "amf-a-0001",
            "deregCallbackUri": amf_a_uri,
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
            "ratType": "NR"
        });
        let mock = Arc::new(MockUdr::with_prior(prior));
        let client = UdrClient::Mock(mock.clone());

        // AMF-B registers over AMF-A -> a DeregistrationData POST to AMF-A.
        // The UDR already holds AMF-A's registration, so this is an UPDATE → 200
        // (TS 29.503 §5.3.2.2: resource exists → 200 OK, not 201 Created).
        let mut body_b = valid_amf_body();
        body_b["amfInstanceId"] = json!("amf-b-0002");
        body_b["deregCallbackUri"] =
            json!("http://amf-b.example.org:7777/namf-callback/v1/imsi-x/dereg-notify");
        let resp = process_amf_registration(supi, &body_b, &client, UecmAccess::ThreeGpp).await;
        assert_eq!(
            resp.status, 200,
            "re-registration over existing AMF-A must be 200 (update)"
        );

        let calls = mock.calls();
        assert_eq!(
            deregister_count(&calls),
            1,
            "exactly one dereg notification"
        );
        let notified = calls.iter().find_map(|c| match c {
            UdrCall::DeregNotify { callback_uri, body } => {
                Some((callback_uri.clone(), body.clone()))
            }
            _ => None,
        });
        let (uri, dereg_body) = notified.expect("a dereg notification was sent");
        assert_eq!(uri, amf_a_uri, "notification targets the OLD AMF (AMF-A)");
        assert_eq!(
            dereg_body.get("deregReason").and_then(|v| v.as_str()),
            Some("UE_INITIAL_REGISTRATION")
        );

        // Re-register with the SAME AMF-B id -> suppressed, no new notification.
        // Still an update (prior = AMF-B now stored) → 200.
        let resp = process_amf_registration(supi, &body_b, &client, UecmAccess::ThreeGpp).await;
        assert_eq!(
            resp.status, 200,
            "same-AMF re-registration still updates the resource → 200"
        );
        assert_eq!(
            deregister_count(&mock.calls()),
            1,
            "no notification when amfInstanceId is unchanged"
        );
    }

    // ----- H3 / WSB-4: udmd -> amfd deregistration-notify STRICT-PEER -------
    //
    // Wave-6 WSB-4 (upgraded from the H3 hand-off). The emission-decision test
    // above proves udmd *decides* to notify; these tests prove udmd's
    // PRODUCTION `DeregistrationData` body is one amfd's REAL Namf_Callback
    // consumer accepts over the WIRE — POSTing the raw JSON through amfd's real
    // `nextgcore_amfd::namf_request_handler` at the `/namf-callback/v1/{supi}/
    // dereg-notify` route amfd itself registers, NOT a lenient mock and no
    // longer just the pre-WSB-4 in-memory `handle_dereg_notify` call.
    //
    // Spec: TS 29.503 §5.3.2.3.2 (Nudm_UECM DeregistrationNotification;
    // DeregistrationData = deregReason + accessType); DeregistrationReason
    // enum values verified against specs/29503-j60.txt:27268-27298. The full
    // WSB-4 round trip (absolute deregCallbackUri, router arm, serde decode,
    // fail-closed 400, network-initiated-dereg enqueue) is exercised here.

    /// Drive udmd's REAL re-registration emission and return the exact
    /// `(callbackUri, DeregistrationData)` JSON body udmd POSTs to the old AMF.
    async fn capture_udmd_dereg_body() -> (String, Value) {
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000000399";
        let amf_a_uri =
            "http://amf-a.example.org:7777/namf-callback/v1/imsi-x/dereg-notify".to_string();
        let prior = json!({
            "amfInstanceId": "amf-a-0001",
            "deregCallbackUri": amf_a_uri,
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
            "ratType": "NR"
        });
        let mock = Arc::new(MockUdr::with_prior(prior));
        let client = UdrClient::Mock(mock.clone());

        // AMF-B registers over the stored AMF-A -> udmd emits a dereg notify.
        let mut body_b = valid_amf_body();
        body_b["amfInstanceId"] = json!("amf-b-0002");
        body_b["deregCallbackUri"] =
            json!("http://amf-b.example.org:7777/namf-callback/v1/imsi-x/dereg-notify");
        let _ = process_amf_registration(supi, &body_b, &client, UecmAccess::ThreeGpp).await;

        mock.calls()
            .into_iter()
            .find_map(|c| match c {
                UdrCall::DeregNotify { callback_uri, body } => Some((callback_uri, body)),
                _ => None,
            })
            .expect("udmd emitted a DeregistrationData notification")
    }

    /// Seed a real `AmfUe` (resolvable by SUPI) in amfd's process-global
    /// context so `namf_request_handler`'s SUPI lookup succeeds. Returns the
    /// AMF-UE-NGAP-ID (== the enqueued dereg's `amf_ue_ngap_id`).
    fn seed_amf_ue(supi: &str, ran_ue_ngap_id: u64) -> u64 {
        let ctx = nextgcore_amfd::context::amf_self();
        let guard = ctx.read().expect("amf ctx lock");
        let ran = guard
            .ran_ue_add(900_400, ran_ue_ngap_id)
            .expect("ran_ue_add");
        let ue = guard.amf_ue_add(ran.id).expect("amf_ue_add");
        guard.amf_ue_set_supi(ue.id, supi);
        let mut ue = ue;
        ue.supi = Some(supi.to_string());
        guard.amf_ue_update(&ue);
        ue.id
    }

    /// Drain amfd's process-global network-dereg queue, keep only this UE's
    /// items and re-add the rest (queue is process-global; parallel tests must
    /// not steal each other's enqueues).
    fn drain_network_deregs_for(ue_id: u64) -> Vec<nextgcore_amfd::context::PendingNetworkDereg> {
        let ctx = nextgcore_amfd::context::amf_self();
        let guard = ctx.read().expect("amf ctx lock");
        let (mine, others): (Vec<_>, Vec<_>) = guard
            .network_dereg_drain()
            .into_iter()
            .partition(|d| d.amf_ue_ngap_id == ue_id);
        for item in others {
            guard.network_dereg_add(item);
        }
        mine
    }

    /// WSB-4 acceptance: udmd's REAL production DeregistrationData body ->
    /// amfd's REAL Namf_Callback handler over the wire -> 204 + exactly one
    /// network-initiated deregistration enqueued (reregistration_required=true
    /// for UE_INITIAL_REGISTRATION). A relative URI or a missing router arm
    /// would fail this (the whole point of the WSB-4 round trip).
    #[tokio::test]
    // The amf-context guard is intentionally held across the async
    // namf_request_handler await to serialize the shared process-global amf
    // context (current-thread test runtime, so this is deadlock-free).
    #[allow(clippy::await_holding_lock)]
    async fn test_dereg_notify_strict_peer_amfd_accepts_udmd_body() {
        use nextgcore_sbi::message::SbiRequest;

        // Capture udmd's production notify body BEFORE taking the amf guard.
        let (uri, body) = capture_udmd_dereg_body().await;

        // Reverse-shape pins on udmd's production body: absolute URI + both
        // mandatory members present (WSB-4 added accessType).
        assert!(
            uri.starts_with("http://") || uri.starts_with("https://"),
            "dereg callback URI must be absolute so amfd can be reached: {uri}"
        );
        assert_eq!(
            body.get("deregReason").and_then(|v| v.as_str()),
            Some("UE_INITIAL_REGISTRATION")
        );
        assert_eq!(
            body.get("accessType").and_then(|v| v.as_str()),
            Some("3GPP_ACCESS"),
            "WSB-4: udmd's DeregistrationData must carry accessType (amfd keys on it)"
        );

        let supi = "imsi-001010000000399";
        // Hold the guard across seed + real handler + drain so a parallel test
        // cannot re-init (wipe) the global amf context in between — that race
        // was the intermittent "0 vs 1 enqueued" failure.
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_amfd::test_support::init_context();
        let ue_id = seed_amf_ue(supi, 60_100);

        // Drive udmd's REAL body through amfd's REAL Namf SBI handler at the
        // path amfd itself registers as its absolute deregCallbackUri.
        let path = format!("/namf-callback/v1/{supi}/dereg-notify");
        let req = SbiRequest::post(path).with_json_body(&body).expect("json");
        let resp = nextgcore_amfd::namf_request_handler(req).await;
        assert_eq!(
            resp.status, 204,
            "amfd must 204-accept udmd's dereg body, got {} ({:?})",
            resp.status, resp.http.content
        );

        // The real handler enqueued exactly one network-initiated dereg.
        let queued = drain_network_deregs_for(ue_id);
        assert_eq!(
            queued.len(),
            1,
            "exactly one network-initiated dereg enqueued"
        );
        assert_eq!(queued[0].amf_ue_ngap_id, ue_id);
        assert!(
            queued[0].reregistration_required,
            "UE_INITIAL_REGISTRATION => reregistration_required (TS 23.502 §4.2.2.3.3)"
        );
    }

    /// Negative twin: a non-3GPP-access dereg is accepted (204) but triggers no
    /// 3GPP network-initiated deregistration — proves the accept above is
    /// discriminating, not a blanket 2xx-and-enqueue.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // see the twin test above
    async fn test_dereg_notify_strict_peer_non_3gpp_no_enqueue() {
        use nextgcore_sbi::message::SbiRequest;
        let supi = "imsi-001010000000398";
        // Held across the async handler + drain (see the twin test above).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_amfd::test_support::init_context();
        let ue_id = seed_amf_ue(supi, 60_101);
        let body =
            json!({ "deregReason": "UE_INITIAL_REGISTRATION", "accessType": "NON_3GPP_ACCESS" });
        let path = format!("/namf-callback/v1/{supi}/dereg-notify");
        let req = SbiRequest::post(path).with_json_body(&body).expect("json");
        let resp = nextgcore_amfd::namf_request_handler(req).await;
        assert_eq!(resp.status, 204, "non-3GPP dereg is accepted");
        assert!(
            drain_network_deregs_for(ue_id).is_empty(),
            "no 3GPP network-initiated dereg for a non-3GPP-access notify"
        );
    }

    /// Fail-closed twins: a missing mandatory accessType -> 400; an unknown
    /// SUPI -> 404 CONTEXT_NOT_FOUND (TS 29.500 §5.2.7 / TS 29.518 §6.1.7.3).
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // guard held across handler await (see twin above)
    async fn test_dereg_notify_fail_closed_400_and_404() {
        use nextgcore_sbi::message::SbiRequest;
        let supi = "imsi-001010000000397";
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_amfd::test_support::init_context();
        let _ue_id = seed_amf_ue(supi, 60_102);

        // 400: mandatory accessType absent (WSB-4 fail-closed).
        let missing = json!({ "deregReason": "UE_INITIAL_REGISTRATION" });
        let path = format!("/namf-callback/v1/{supi}/dereg-notify");
        let resp = nextgcore_amfd::namf_request_handler(
            SbiRequest::post(path)
                .with_json_body(&missing)
                .expect("json"),
        )
        .await;
        assert_eq!(
            resp.status, 400,
            "missing accessType must fail closed (400)"
        );

        // 404: unknown SUPI (never seeded).
        let unknown = "imsi-001019999999999";
        let full = json!({ "deregReason": "UE_INITIAL_REGISTRATION", "accessType": "3GPP_ACCESS" });
        let path2 = format!("/namf-callback/v1/{unknown}/dereg-notify");
        let resp2 = nextgcore_amfd::namf_request_handler(
            SbiRequest::post(path2).with_json_body(&full).expect("json"),
        )
        .await;
        assert_eq!(
            resp2.status, 404,
            "unknown SUPI must be 404 CONTEXT_NOT_FOUND"
        );
    }

    // ----- H3 finish: reverse-shape cross-decode pin + step-3 negatives ------
    //
    // Wave-6 H3 (TS 29.503 §5.3.2.3.2) implementation steps 2 & 3. Step 1
    // (strict-peer accept + resulting AmfUe/enqueue state) is proven above; the
    // tests below close:
    //   step 2 — the reverse-shape cross-decode pin: amfd's OWN
    //            `DeregistrationData` struct (namf_handler.rs:143) <-> udmd's
    //            serializer, BOTH directions, so a `deregReason`/`accessType`
    //            field-name or enum-string drift on EITHER side fails a test;
    //   step 3 — the negatives: a deregReason amfd's REAL handler rejects
    //            (-> 400 MANDATORY_IE_INCORRECT), and udmd logs-and-continues
    //            (a FAILING notification must not wedge re-registration).

    /// Canonical TS 29.503 §5.3.2.3.2 `DeregistrationReason` wire strings for
    /// amfd's OWN enum. The match is exhaustive so a renamed/added amfd variant
    /// forces this pin to be revisited — the compile-time half of the
    /// field-drift guard the H3 cross-decode step exists to provide.
    fn amfd_dereg_reason_wire(
        r: nextgcore_amfd::namf_handler::DeregistrationReason,
    ) -> &'static str {
        use nextgcore_amfd::namf_handler::DeregistrationReason as R;
        match r {
            R::UeInitialRegistration => "UE_INITIAL_REGISTRATION",
            R::UeRegistrationAreaChange => "UE_REGISTRATION_AREA_CHANGE",
            R::SubscriptionWithdrawn => "SUBSCRIPTION_WITHDRAWN",
            R::FiveGsToEpsMobility => "5GS_TO_EPS_MOBILITY",
            R::FiveGsToEpsMobilityUeInitialRegistration => {
                "5GS_TO_EPS_MOBILITY_UE_INITIAL_REGISTRATION"
            }
            R::ReregistrationRequired => "REREGISTRATION_REQUIRED",
            R::SmfContextTransferred => "SMF_CONTEXT_TRANSFERRED",
        }
    }

    /// Canonical TS 29.503 `AccessType` wire strings for amfd's OWN enum
    /// (exhaustive — same compile-time drift-guard rationale as above).
    fn amfd_access_type_wire(a: nextgcore_amfd::namf_handler::AccessType) -> &'static str {
        use nextgcore_amfd::namf_handler::AccessType as A;
        match a {
            A::ThreeGppAccess => "3GPP_ACCESS",
            A::NonThreeGppAccess => "NON_3GPP_ACCESS",
        }
    }

    /// H3 step 2 — reverse-shape cross-decode pin, BOTH directions:
    ///  (1) ENCODE: construct amfd's OWN `DeregistrationData` struct for a UE
    ///      that re-registered in a new AMF over 3GPP access, render it to its
    ///      canonical TS 29.503 wire strings, and assert it is field/value-
    ///      identical to udmd's production `build_dereg_notification_body()`;
    ///  (2) DECODE: feed udmd's production body through amfd's REAL handler and
    ///      assert it decodes to the semantics of that same struct
    ///      (reregistration required for UE_INITIAL_REGISTRATION).
    /// A field-name or enum-string drift on either side breaks one direction.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // guard held across handler await (see twin above)
    async fn test_dereg_notify_cross_decode_amfd_struct_and_udmd_body() {
        use nextgcore_amfd::namf_handler::{AccessType, DeregistrationData, DeregistrationReason};
        use nextgcore_sbi::message::SbiRequest;

        // Direction 1 (encode pin) — amfd's OWN struct rendered to the wire.
        let amfd_struct = DeregistrationData {
            dereg_reason: DeregistrationReason::UeInitialRegistration,
            access_type: AccessType::ThreeGppAccess,
        };
        let from_amfd_struct = json!({
            "deregReason": amfd_dereg_reason_wire(amfd_struct.dereg_reason),
            "accessType": amfd_access_type_wire(amfd_struct.access_type),
        });
        assert_eq!(
            from_amfd_struct,
            build_dereg_notification_body(UecmAccess::ThreeGpp),
            "amfd's DeregistrationData wire form must be field/value-identical to \
             udmd's emitted body (TS 29.503 §5.3.2.3.2 cross-decode pin)"
        );

        // Direction 2 (decode pin) — udmd's body through amfd's REAL handler.
        let supi = "imsi-001010000000396";
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_amfd::test_support::init_context();
        let ue_id = seed_amf_ue(supi, 60_103);
        let path = format!("/namf-callback/v1/{supi}/dereg-notify");
        let req = SbiRequest::post(path)
            .with_json_body(&build_dereg_notification_body(UecmAccess::ThreeGpp))
            .expect("json");
        let resp = nextgcore_amfd::namf_request_handler(req).await;
        assert_eq!(resp.status, 204, "amfd decodes udmd's body -> 204");
        let queued = drain_network_deregs_for(ue_id);
        assert_eq!(queued.len(), 1, "one network-initiated dereg enqueued");
        assert!(
            queued[0].reregistration_required,
            "UE_INITIAL_REGISTRATION decodes to reregistration_required=true"
        );
    }

    /// Decoder-discrimination pin: a non-initial reason amfd recognises
    /// (SUBSCRIPTION_WITHDRAWN) is accepted (204) and still enqueues a
    /// network-initiated dereg, but with `reregistration_required=false` —
    /// proving amfd's REAL decoder keys on the EXACT deregReason string, not a
    /// blanket accept (TS 23.502 §4.2.2.3.3: only UE_INITIAL_REGISTRATION asks
    /// the UE to re-register).
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // guard held across handler await (see twin above)
    async fn test_dereg_notify_strict_peer_non_initial_reason_no_rereg() {
        use nextgcore_sbi::message::SbiRequest;
        let supi = "imsi-001010000000395";
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_amfd::test_support::init_context();
        let ue_id = seed_amf_ue(supi, 60_104);
        let body = json!({ "deregReason": "SUBSCRIPTION_WITHDRAWN", "accessType": "3GPP_ACCESS" });
        let path = format!("/namf-callback/v1/{supi}/dereg-notify");
        let resp = nextgcore_amfd::namf_request_handler(
            SbiRequest::post(path).with_json_body(&body).expect("json"),
        )
        .await;
        assert_eq!(
            resp.status, 204,
            "a recognised non-initial reason is accepted"
        );
        let queued = drain_network_deregs_for(ue_id);
        assert_eq!(queued.len(), 1, "3GPP-access dereg is still enqueued");
        assert!(
            !queued[0].reregistration_required,
            "SUBSCRIPTION_WITHDRAWN must NOT set reregistration_required"
        );
    }

    /// H3 step 3 (first half) — a deregReason amfd's REAL handler does not
    /// recognise fails closed: 400 MANDATORY_IE_INCORRECT and NO dereg enqueued
    /// (TS 29.500 §5.2.7). Proves the accept above is discriminating, not a
    /// blanket 2xx.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // guard held across handler await (see twin above)
    async fn test_dereg_notify_strict_peer_rejects_unknown_reason() {
        use nextgcore_sbi::message::SbiRequest;
        let supi = "imsi-001010000000394";
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_amfd::test_support::init_context();
        let ue_id = seed_amf_ue(supi, 60_105);
        let body = json!({ "deregReason": "NOT_A_REAL_REASON", "accessType": "3GPP_ACCESS" });
        let path = format!("/namf-callback/v1/{supi}/dereg-notify");
        let resp = nextgcore_amfd::namf_request_handler(
            SbiRequest::post(path).with_json_body(&body).expect("json"),
        )
        .await;
        assert_eq!(
            resp.status, 400,
            "an unknown deregReason must fail closed (400)"
        );
        assert_eq!(
            problem_cause(&resp).as_deref(),
            Some("MANDATORY_IE_INCORRECT"),
            "unknown deregReason -> MANDATORY_IE_INCORRECT"
        );
        assert!(
            drain_network_deregs_for(ue_id).is_empty(),
            "a rejected notify must not enqueue a network-initiated dereg"
        );
    }

    /// H3 step 3 (second half) — udmd logs-and-continues: a FAILING dereg
    /// notification to the old AMF must not wedge the new registration
    /// (TS 29.503 §5.3.2.2.2 best-effort). The old-AMF callback is mocked to
    /// return 500; udmd's re-registration must still complete (200) and the
    /// notification must have been attempted exactly once.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_reregistration_continues_when_dereg_notify_fails() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000000393";
        let amf_a_uri =
            "http://amf-a.example.org:7777/namf-callback/v1/imsi-x/dereg-notify".to_string();
        let prior = json!({
            "amfInstanceId": "amf-a-0001",
            "deregCallbackUri": amf_a_uri,
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
            "ratType": "NR"
        });
        // The old-AMF dereg-notify callback FAILS (500).
        let mock = Arc::new(MockUdr::with_prior(prior).with_dereg_status(500));
        let client = UdrClient::Mock(mock.clone());

        let mut body_b = valid_amf_body();
        body_b["amfInstanceId"] = json!("amf-b-0002");
        body_b["deregCallbackUri"] =
            json!("http://amf-b.example.org:7777/namf-callback/v1/imsi-x/dereg-notify");
        let resp = process_amf_registration(supi, &body_b, &client, UecmAccess::ThreeGpp).await;
        assert_eq!(
            resp.status, 200,
            "a failing dereg notification must NOT wedge re-registration"
        );
        assert_eq!(
            deregister_count(&mock.calls()),
            1,
            "the (failed) dereg notification was attempted exactly once"
        );
    }

    /// #83 WIRING: a real `process_amf_registration` must produce the SDM and EE
    /// notifications, not just the standalone producer.
    ///
    /// Written because revert-verification exposed the gap: removing the
    /// `notify_ue_context_change` call from this function left every notify test
    /// green, since they all called the producer directly. That is the recorded
    /// lesson that a tested helper leaves the wiring untested — the helper was
    /// covered nine ways and the one line that invokes it was not covered at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn amf_registration_notifies_sdm_and_ee_subscribers() {
        use nextgcore_sbi::message::{SbiRequest as SReq, SbiResponse as SResp};
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        use std::sync::Mutex as StdMutex;

        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Declared, not inherited: loopback plaintext stub (see notify.rs).
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        std::env::remove_var("UDM_NOTIFY_DISABLE");
        crate::context::udm_context_init(1024, 4096);

        let supi = "imsi-001010000000883";
        let seen: Arc<StdMutex<Vec<Value>>> = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let addr = nextgcore_sbi::test_support::ephemeral_addr();
        let server = SbiServer::new(SbiServerConfig::new(addr));
        server
            .start(move |req: SReq| {
                let sink = Arc::clone(&sink);
                async move {
                    if let Some(b) = req.http.content.as_deref() {
                        if let Ok(v) = serde_json::from_str::<Value>(b) {
                            sink.lock().expect("sink").push(v);
                        }
                    }
                    SResp::with_status(204)
                }
            })
            .await
            .expect("stub callback starts");
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let uri = format!("http://127.0.0.1:{}/cb", addr.port());

        {
            let ctx = udm_self();
            let context = ctx.read().expect("context");
            // Clear anything a previous test left for this SUPI.
            for sub in context.sdm_subscriptions_for_supi(supi) {
                context.sdm_subscription_remove(&sub.id);
            }
            for sub in context.ee_subscriptions_for_supi(supi) {
                context.ee_subscription_remove(&sub.id);
            }
            context.sdm_subscription_insert(crate::context::UdmSdmSubscription::for_supi(
                supi,
                Some("nf-1".to_string()),
                Some(uri.clone()),
                vec![format!("/nudm-sdm/v2/{supi}/ue-context-in-amf-data")],
            ));
            context.ee_subscription_insert(crate::context::UdmEeSubscription::for_ue(
                supi,
                uri.clone(),
                "{}",
            ));
        }

        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());
        let resp =
            process_amf_registration(supi, &valid_amf_body(), &client, UecmAccess::ThreeGpp).await;
        assert_eq!(
            resp.status, 201,
            "the registration itself must still succeed"
        );

        // Both notifications must have gone out as a consequence of the
        // registration, with no extra call from the test.
        let bodies = {
            let mut out = Vec::new();
            for _ in 0..100 {
                out = seen.lock().expect("sink").clone();
                if out.len() >= 2 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            out
        };
        assert_eq!(
            bodies.len(),
            2,
            "an AMF registration must notify both the SDM and the EE subscriber: {bodies:?}"
        );
        assert!(
            bodies.iter().any(|b| b["notifyItems"][0]["resourceId"]
                == format!("/nudm-sdm/v2/{supi}/ue-context-in-amf-data")),
            "no SDM ModificationNotification among {bodies:?}"
        );
        assert!(
            bodies
                .iter()
                .any(|b| b["reportList"][0]["eventType"] == "UE_REACHABILITY_FOR_DATA"),
            "no EE MonitoringReport among {bodies:?}"
        );

        {
            let ctx = udm_self();
            let context = ctx.read().expect("context");
            for sub in context.sdm_subscriptions_for_supi(supi) {
                context.sdm_subscription_remove(&sub.id);
            }
            for sub in context.ee_subscriptions_for_supi(supi) {
                context.ee_subscription_remove(&sub.id);
            }
        }
    }

    // ----- #84: the two AMF access registrations are separate resources ------

    /// A valid `AmfNon3GppAccessRegistration` (the 3GPP set plus `imsVoPs`).
    fn valid_non_3gpp_body() -> Value {
        let mut b = valid_amf_body();
        b["amfInstanceId"] = json!("amf-n3-0001");
        b["deregCallbackUri"] =
            json!("http://amf-n3.example.org:7777/namf-callback/v1/imsi-x/dereg-notify");
        b["ratType"] = json!("VIRTUAL");
        b["imsVoPs"] = json!("HOMOGENEOUS_SUPPORT");
        b
    }

    /// #84 gap 1, the load-bearing one: registering over non-3GPP access must
    /// not read, rewrite or delete the `amf-3gpp-access` record, and must not
    /// tell the 3GPP AMF anything at all.
    ///
    /// Revert check: hardcoding `UecmAccess::ThreeGpp` inside
    /// `process_amf_registration` (the pre-#84 behaviour, where
    /// `handle_amf_non3gpp_registration` called the 3GPP helper) fails the
    /// stored-3GPP-record assertion with AMF-N3's id.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn non_3gpp_registration_leaves_the_3gpp_record_intact() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000000840";

        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());

        let three_gpp = valid_amf_body();
        let resp = process_amf_registration(supi, &three_gpp, &client, UecmAccess::ThreeGpp).await;
        assert_eq!(resp.status, 201, "3GPP registration creates the resource");

        let non_3gpp = valid_non_3gpp_body();
        let resp = process_amf_registration(supi, &non_3gpp, &client, UecmAccess::Non3Gpp).await;
        assert_eq!(
            resp.status, 201,
            "the non-3GPP resource does not exist yet, so this is a CREATE — a 200 \
             would mean it found the 3GPP registration"
        );
        assert_eq!(
            resp.http.headers.get("location").map(String::as_str),
            Some(format!("/nudm-uecm/v1/{supi}/registrations/amf-non-3gpp-access").as_str()),
            "Location must name the non-3GPP resource"
        );

        // The 3GPP record is byte-identical to what was registered.
        assert_eq!(
            mock.stored_doc("amf-3gpp-access").as_ref(),
            Some(&three_gpp),
            "the non-3GPP registration overwrote the 3GPP record"
        );
        assert_eq!(
            mock.stored_doc("amf-non-3gpp-access").as_ref(),
            Some(&non_3gpp),
            "the non-3GPP registration must be stored under its own resource"
        );

        // Nothing addressed at the 3GPP resource after its own PUT, and the
        // 3GPP AMF was never told its registration ended.
        let calls = mock.calls();
        let three_gpp_writes = calls
            .iter()
            .filter(|c| {
                matches!(
                    c,
                    UdrCall::CtxPut { resource, .. }
                        | UdrCall::CtxPatch { resource, .. }
                        | UdrCall::CtxDelete { resource, .. }
                        if resource == "amf-3gpp-access"
                )
            })
            .count();
        assert_eq!(
            three_gpp_writes, 1,
            "exactly one write to amf-3gpp-access (its own registration): {calls:?}"
        );
        assert_eq!(
            deregister_count(&calls),
            0,
            "a non-3GPP registration must not deregister the 3GPP AMF"
        );

        // Both cache slots are populated independently.
        let ctx = udm_self();
        let context = ctx.read().expect("context");
        let ue = context.ue_find_by_supi(supi).expect("UE cached");
        assert_eq!(ue.amf_instance_id.as_deref(), Some("amf-a-0001"));
        assert_eq!(ue.non_3gpp_amf_instance_id.as_deref(), Some("amf-n3-0001"));
    }

    /// #84 gap 1/2: a non-3GPP re-registration notifies the OLD NON-3GPP AMF,
    /// with `accessType: NON_3GPP_ACCESS`, and leaves the 3GPP AMF alone.
    ///
    /// Revert check: `build_dereg_notification_body` with `accessType` pinned to
    /// `3GPP_ACCESS` fails the accessType assertion — and that value is what
    /// makes amfd tear a live 3GPP registration down (see the strict-peer twin
    /// `test_dereg_notify_strict_peer_non_3gpp_no_enqueue`).
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn non_3gpp_reregistration_notifies_the_non_3gpp_amf() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000000841";

        let n3_old_uri = "http://amf-n3-old.example.org:7777/namf-callback/v1/imsi-x/dereg-notify";
        let mock = Arc::new(
            MockUdr::new()
                .with_stored(
                    "amf-3gpp-access",
                    json!({
                        "amfInstanceId": "amf-3gpp-live",
                        "deregCallbackUri": "http://amf-3gpp.example.org:7777/namf-callback/v1/imsi-x/dereg-notify",
                        "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
                        "ratType": "NR"
                    }),
                )
                .with_stored(
                    "amf-non-3gpp-access",
                    json!({
                        "amfInstanceId": "amf-n3-old",
                        "deregCallbackUri": n3_old_uri,
                        "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe01" },
                        "ratType": "VIRTUAL",
                        "imsVoPs": "HOMOGENEOUS_SUPPORT"
                    }),
                ),
        );
        let client = UdrClient::Mock(mock.clone());

        let resp =
            process_amf_registration(supi, &valid_non_3gpp_body(), &client, UecmAccess::Non3Gpp)
                .await;
        assert_eq!(resp.status, 200, "the non-3GPP resource existed -> update");

        let calls = mock.calls();
        assert_eq!(
            deregister_count(&calls),
            1,
            "exactly one dereg notification"
        );
        let (uri, body) = calls
            .iter()
            .find_map(|c| match c {
                UdrCall::DeregNotify { callback_uri, body } => {
                    Some((callback_uri.clone(), body.clone()))
                }
                _ => None,
            })
            .expect("a dereg notification was sent");
        assert_eq!(uri, n3_old_uri, "the OLD NON-3GPP AMF is the one notified");
        assert_eq!(
            body.get("accessType").and_then(|v| v.as_str()),
            Some("NON_3GPP_ACCESS"),
            "DeregistrationData must name the access that actually changed"
        );
        assert_eq!(
            mock.stored_doc("amf-3gpp-access")
                .and_then(|d| d["amfInstanceId"].as_str().map(String::from))
                .as_deref(),
            Some("amf-3gpp-live"),
            "the 3GPP registration is untouched"
        );
    }

    /// The non-3GPP schema additionally requires `imsVoPs`
    /// (TS 29.503 `AmfNon3GppAccessRegistration`), so a body that would be a
    /// valid 3GPP registration is refused here — and refused before any write.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn non_3gpp_registration_requires_ims_vo_ps() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());
        let resp = process_amf_registration(
            "imsi-001010000000842",
            &valid_amf_body(),
            &client,
            UecmAccess::Non3Gpp,
        )
        .await;
        assert_eq!(resp.status, 400);
        assert_eq!(
            problem_cause(&resp).as_deref(),
            Some("MANDATORY_IE_MISSING")
        );
        assert!(
            mock.calls()
                .iter()
                .all(|c| !matches!(c, UdrCall::CtxPut { .. })),
            "a rejected registration must not write to UDR"
        );
        // The same body IS valid for 3GPP access, so the refusal is about the
        // non-3GPP schema and not about the body being malformed in general.
        let resp = process_amf_registration(
            "imsi-001010000000842",
            &valid_amf_body(),
            &client,
            UecmAccess::ThreeGpp,
        )
        .await;
        assert_eq!(resp.status, 201);
    }

    // ----- #84 gap 2: the UECM read operations -------------------------------

    #[tokio::test]
    async fn get_amf_registration_returns_the_stored_record_per_access() {
        for access in [UecmAccess::ThreeGpp, UecmAccess::Non3Gpp] {
            let stored = json!({ "amfInstanceId": format!("amf-for-{}", access.amf_resource()) });
            let mock = Arc::new(MockUdr::new().with_stored(access.amf_resource(), stored.clone()));
            let client = UdrClient::Mock(mock.clone());

            let resp = process_amf_registration_get("imsi-1", &client, access).await;
            assert_eq!(resp.status, 200, "{} GET", access.amf_resource());
            let body: Value =
                serde_json::from_str(resp.http.content.as_deref().expect("body")).unwrap();
            assert_eq!(body, stored, "the stored record is returned verbatim");

            // The OTHER access is not registered, so its GET is a 404 — the read
            // must not fall through to the resource that happens to exist.
            let other = match access {
                UecmAccess::ThreeGpp => UecmAccess::Non3Gpp,
                UecmAccess::Non3Gpp => UecmAccess::ThreeGpp,
            };
            let resp = process_amf_registration_get("imsi-1", &client, other).await;
            assert_eq!(resp.status, 404, "{} GET", other.amf_resource());
            assert_eq!(
                problem_cause(&resp).as_deref(),
                Some("CONTEXT_NOT_FOUND"),
                "TS 29.503 Table 6.2.7.3-1"
            );
        }
    }

    /// A UDR fault on a UECM GET must NOT be reported as "not registered": a 404
    /// would tell a consumer the UE has no serving AMF when the truth is that
    /// the UDM could not find out — and a `(H)GMLC` acting on that answer stops
    /// looking for the UE.
    #[tokio::test]
    async fn a_udr_fault_on_a_uecm_get_is_503_not_404() {
        let mock = Arc::new(MockUdr::new().with_get_status(500));
        let client = UdrClient::Mock(mock);
        for resp in [
            process_amf_registration_get("imsi-1", &client, UecmAccess::ThreeGpp).await,
            process_amf_registration_get("imsi-1", &client, UecmAccess::Non3Gpp).await,
            process_smf_registrations_get("imsi-1", &client).await,
            process_smf_registration_get("imsi-1", "5", &client).await,
            process_location_info_get("imsi-1", &client).await,
            process_smsf_registration_get("imsi-1", &client, UecmAccess::ThreeGpp).await,
            process_ip_sm_gw_registration_get("imsi-1", &client).await,
        ] {
            assert_eq!(
                resp.status, 503,
                "a UDR 5xx must surface as 503, never as an empty-but-successful read"
            );
        }
    }

    #[tokio::test]
    async fn get_smf_registrations_wraps_the_udr_array_as_smf_registration_info() {
        let reg = valid_smf_body();
        let mock = Arc::new(MockUdr::new().with_stored("smf-registrations", json!([reg.clone()])));
        let client = UdrClient::Mock(mock);

        let resp = process_smf_registrations_get("imsi-1", &client).await;
        assert_eq!(resp.status, 200);
        let body: Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).unwrap();
        assert_eq!(
            body["smfRegistrationList"],
            json!([reg]),
            "TS 29.503 SmfRegistrationInfo wraps the list the UDR returns bare"
        );

        // minItems: 1 — an empty collection is not a representable answer.
        let mock = Arc::new(MockUdr::new().with_stored("smf-registrations", json!([])));
        let client = UdrClient::Mock(mock);
        let resp = process_smf_registrations_get("imsi-1", &client).await;
        assert_eq!(resp.status, 404, "an empty smfRegistrationList is a 404");
    }

    #[tokio::test]
    async fn get_individual_smf_registration_addresses_the_pdu_session() {
        let reg = valid_smf_body();
        let mock = Arc::new(MockUdr::new().with_stored("smf-registrations/5", json!(reg.clone())));
        let client = UdrClient::Mock(mock.clone());

        let resp = process_smf_registration_get("imsi-1", "5", &client).await;
        assert_eq!(resp.status, 200);
        let body: Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).unwrap();
        assert_eq!(body, reg);

        let resp = process_smf_registration_get("imsi-1", "6", &client).await;
        assert_eq!(resp.status, 404, "another PDU session is not this one");
    }

    /// `GetLocationInfo` is composed from the AMF registrations: one entry per
    /// serving AMF, with every access that AMF serves in its `accessTypeList`.
    #[tokio::test]
    async fn get_location_info_composes_one_entry_per_serving_amf() {
        let guami = json!({ "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" });

        // Two different AMFs -> two entries, one access type each.
        let mock = Arc::new(
            MockUdr::new()
                .with_stored(
                    "amf-3gpp-access",
                    json!({ "amfInstanceId": "amf-a", "guami": guami }),
                )
                .with_stored("amf-non-3gpp-access", json!({ "amfInstanceId": "amf-b" })),
        );
        let client = UdrClient::Mock(mock);
        let resp = process_location_info_get("imsi-1", &client).await;
        assert_eq!(resp.status, 200);
        let body: Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).unwrap();
        let list = body["registrationLocationInfoList"]
            .as_array()
            .expect("list")
            .clone();
        assert_eq!(list.len(), 2, "two serving AMFs -> two entries: {list:?}");
        assert_eq!(list[0]["amfInstanceId"], "amf-a");
        assert_eq!(list[0]["accessTypeList"], json!(["3GPP_ACCESS"]));
        assert_eq!(list[0]["guami"], guami, "the GUAMI is carried when stored");
        assert_eq!(list[1]["amfInstanceId"], "amf-b");
        assert_eq!(list[1]["accessTypeList"], json!(["NON_3GPP_ACCESS"]));
        assert_eq!(body["supi"], "imsi-1");
        assert!(
            body.get("gpsi").is_none(),
            "no GPSI is known, so none is fabricated"
        );

        // ONE AMF serving both accesses -> ONE entry with both access types,
        // which is also what keeps the list inside maxItems: 2.
        let mock = Arc::new(
            MockUdr::new()
                .with_stored("amf-3gpp-access", json!({ "amfInstanceId": "amf-both" }))
                .with_stored(
                    "amf-non-3gpp-access",
                    json!({ "amfInstanceId": "amf-both" }),
                ),
        );
        let client = UdrClient::Mock(mock);
        let resp = process_location_info_get("imsi-1", &client).await;
        let body: Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).unwrap();
        let list = body["registrationLocationInfoList"].as_array().unwrap();
        assert_eq!(list.len(), 1, "one AMF -> one entry: {list:?}");
        assert_eq!(
            list[0]["accessTypeList"],
            json!(["3GPP_ACCESS", "NON_3GPP_ACCESS"])
        );

        // No registration at all -> 404 (TS 29.503 §5.3.2.5.9 step 2b).
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock);
        let resp = process_location_info_get("imsi-1", &client).await;
        assert_eq!(resp.status, 404);
    }

    #[tokio::test]
    async fn smsf_registration_round_trips_per_access() {
        for access in [UecmAccess::ThreeGpp, UecmAccess::Non3Gpp] {
            let mock = Arc::new(MockUdr::new());
            let client = UdrClient::Mock(mock.clone());

            // Mandatory IEs first: smsfInstanceId + plmnId.
            let resp = process_smsf_registration(
                "imsi-1",
                &json!({ "smsfInstanceId": "smsf-1" }),
                &client,
                access,
            )
            .await;
            assert_eq!(resp.status, 400, "plmnId is mandatory");

            let body = json!({
                "smsfInstanceId": "smsf-1",
                "plmnId": { "mcc": "001", "mnc": "01" }
            });
            let resp = process_smsf_registration("imsi-1", &body, &client, access).await;
            assert_eq!(resp.status, 201, "{}", access.smsf_resource());
            assert_eq!(
                resp.http.headers.get("location").map(String::as_str),
                Some(
                    format!(
                        "/nudm-uecm/v1/imsi-1/registrations/{}",
                        access.smsf_resource()
                    )
                    .as_str()
                )
            );

            let resp = process_smsf_registration_get("imsi-1", &client, access).await;
            assert_eq!(resp.status, 200, "the SMSF registration reads back");
            let got: Value =
                serde_json::from_str(resp.http.content.as_deref().expect("body")).unwrap();
            assert_eq!(got, body);

            let resp = process_smsf_deregistration("imsi-1", &client, access).await;
            assert_eq!(resp.status, 204);
            let resp = process_smsf_registration_get("imsi-1", &client, access).await;
            assert_eq!(resp.status, 404, "deregistration removed it");
        }
    }

    #[tokio::test]
    async fn ip_sm_gw_registration_round_trips_and_requires_an_address() {
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());

        // anyOf: a registration naming no IP-SM-GW address routes nowhere.
        let resp =
            process_ip_sm_gw_registration("imsi-1", &json!({ "unriIndicator": true }), &client)
                .await;
        assert_eq!(resp.status, 400);
        assert_eq!(
            problem_cause(&resp).as_deref(),
            Some("MANDATORY_IE_MISSING")
        );

        for address in [
            json!({ "ipsmgwFqdn": "ipsmgw.example.org" }),
            json!({ "ipsmgwIpv4": "10.0.0.9" }),
            json!({ "ipSmGwMapAddress": "491721075423" }),
        ] {
            let mock = Arc::new(MockUdr::new());
            let client = UdrClient::Mock(mock.clone());
            let resp = process_ip_sm_gw_registration("imsi-1", &address, &client).await;
            assert_eq!(resp.status, 201, "{address} must be accepted");
            let resp = process_ip_sm_gw_registration_get("imsi-1", &client).await;
            assert_eq!(resp.status, 200);
            let got: Value =
                serde_json::from_str(resp.http.content.as_deref().expect("body")).unwrap();
            assert_eq!(got, address);
        }

        let resp = process_ip_sm_gw_deregistration("imsi-1", &client).await;
        assert_eq!(resp.status, 204);
    }

    // ----- #84 gap 3: spec deregistration -----------------------------------

    /// `POST .../amf-3gpp-access/dereg-amf` is the spec deregistration: it needs
    /// an `AmfDeregInfo.deregReason` and it removes the registration.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn dereg_amf_requires_a_reason_and_deletes_the_registration() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000000843";
        let mock = Arc::new(MockUdr::with_prior(valid_amf_body()));
        let client = UdrClient::Mock(mock.clone());

        // No deregReason -> 400, and nothing deleted.
        let resp = process_dereg_amf(supi, &json!({}), &client).await;
        assert_eq!(resp.status, 400);
        assert_eq!(
            problem_cause(&resp).as_deref(),
            Some("MANDATORY_IE_MISSING")
        );
        assert!(
            mock.stored_doc("amf-3gpp-access").is_some(),
            "a rejected dereg-amf must not delete the registration"
        );

        let resp = process_dereg_amf(
            supi,
            &json!({ "deregReason": "SUBSCRIPTION_WITHDRAWN" }),
            &client,
        )
        .await;
        assert_eq!(resp.status, 204);
        assert!(
            mock.stored_doc("amf-3gpp-access").is_none(),
            "dereg-amf removes the UDR context-data resource"
        );
    }

    /// `purgeFlag: true` on the update PATCH is a deregistration
    /// (TS 29.503 §5.3.2.4.2) — the shape this repo's own AMF sends. Before #84
    /// it was acknowledged with 204 and patched into the stored document, so the
    /// UDM kept answering with a serving AMF that had released the UE.
    ///
    /// Revert check: dropping the `purgeFlag` branch makes the stored record
    /// survive and this test fails on the `is_none()` assertion.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn purge_flag_patch_deregisters_rather_than_patching() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000000844";
        let mock = Arc::new(MockUdr::with_prior(valid_amf_body()));
        let client = UdrClient::Mock(mock.clone());

        // Exactly what nextgcore's AMF sends: a bare purge, no GUAMI.
        let resp = process_amf_registration_update(
            supi,
            &json!({ "purgeFlag": true }),
            &client,
            UecmAccess::ThreeGpp,
        )
        .await;
        assert_eq!(resp.status, 204);
        assert!(
            mock.stored_doc("amf-3gpp-access").is_none(),
            "purgeFlag must deregister the UE, not patch the flag into the record"
        );
        assert!(
            mock.calls().iter().any(|c| matches!(
                c,
                UdrCall::CtxDelete { resource, .. } if resource == "amf-3gpp-access"
            )),
            "the purge issues a UDR context-data DELETE"
        );
        // A purge on one access leaves the other alone.
        assert!(
            !mock.calls().iter().any(|c| matches!(
                c,
                UdrCall::CtxDelete { resource, .. } if resource == "amf-non-3gpp-access"
            )),
            "a 3GPP purge must not delete the non-3GPP registration"
        );
    }

    /// Deregistering one access keeps the other access's cached serving AMF, so
    /// the next re-registration on the surviving access still has an old AMF to
    /// notify.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn deregistering_one_access_keeps_the_other_cached() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000000845";
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());

        let _ =
            process_amf_registration(supi, &valid_amf_body(), &client, UecmAccess::ThreeGpp).await;
        let _ =
            process_amf_registration(supi, &valid_non_3gpp_body(), &client, UecmAccess::Non3Gpp)
                .await;

        let resp = process_amf_deregistration(supi, &client, UecmAccess::Non3Gpp).await;
        assert_eq!(resp.status, 204);

        let ctx = udm_self();
        let context = ctx.read().expect("context");
        let ue = context
            .ue_find_by_supi(supi)
            .expect("the UE survives a single-access deregistration");
        assert_eq!(
            ue.amf_instance_id.as_deref(),
            Some("amf-a-0001"),
            "the 3GPP serving AMF is still cached"
        );
        assert!(
            ue.non_3gpp_amf_instance_id.is_none(),
            "the deregistered access's slot is cleared"
        );
        drop(context);

        // Deregistering the remaining access drops the UE entirely.
        let resp = process_amf_deregistration(supi, &client, UecmAccess::ThreeGpp).await;
        assert_eq!(resp.status, 204);
        let context = ctx.read().expect("context");
        assert!(
            context.ue_find_by_supi(supi).is_none(),
            "with neither access registered the UE context is dropped"
        );
    }
}
