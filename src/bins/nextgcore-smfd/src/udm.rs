//! UDM interaction: `Nudm_UECM_Registration` and `Nudm_SDM_Get sm-data` (#79).
//!
//! TS 23.502 §4.3.2.2.1 step 4: during UE-requested PDU Session Establishment the
//! SMF **registers itself with the UDM** as the serving SMF for the SUPI/PDU
//! session (`Nudm_UECM_Registration`, TS 29.503 §5.3.2) and **retrieves the SM
//! subscription data** (`Nudm_SDM_Get sm-data`, §5.2.2.2), then enforces what it
//! retrieved.
//!
//! # What was missing, precisely
//!
//! #204 gave this daemon a UDM *discovery* routine and one real SDM call — for
//! `smf-select-data`, to learn the subscribed default DNN when the AMF supplies
//! none. That is the whole of the SMF's UDM interaction before #79:
//!
//! - **No UECM registration at all.** `rg smf-registrations` across `src/`
//!   returned nothing, so the UDM held no serving-SMF record and any procedure
//!   that resolves the serving SMF through the UDM had nothing to resolve.
//! - **No `sm-data` retrieval**, so the subscribed session-AMBR and default 5QI
//!   were never consulted. QoS came from the AMF's request body and
//!   `policy::PolicyDecision::config_default_for_dnn` — a *local config* default.
//!   Behind a real UDM that means the SMF applies the operator's file instead of
//!   the subscriber's profile.
//!
//! # The subscription is a baseline, and the PCF still outranks it
//!
//! TS 23.503 §6.1.3.2: the PCF authorises the session-AMBR and default QoS, using
//! the subscribed values as input. So the precedence here is
//! `PCF` then `subscription` then `config default`, and the subscription is
//! consulted only to build the input the PCF's decision replaces — or, with no PCF
//! configured, to be the answer.
//! Getting this order wrong in the other direction would have a subscription
//! override a policy decision, which is a conformance defect rather than a
//! degradation.
//!
//! # Off by default
//!
//! Gated on `SMF_UDM=1`. A runtime switch for the recorded reason (a
//! cargo-feature-gated path is left uncompiled by CI and rots), and off by default
//! because #79 says so explicitly: the E2E harness has no conformant UDM, and
//! enforcing subscription data that no UDM supplies would regress the matched-sim
//! data-plane path that CI does gate on.

use std::sync::atomic::{AtomicBool, Ordering};

/// Is the UDM leg enabled for this process?
static UDM_ENABLED: AtomicBool = AtomicBool::new(false);

/// This SMF's NF instance id, as the NRF knows it.
///
/// Seeded from the value NRF registration used, so the `smfInstanceId` the UDM
/// records is the one a peer resolving this SMF through the NRF would dial. A
/// second, independently minted uuid would make the UDM's serving-SMF record point
/// at an instance nothing else in the deployment knows.
static SMF_INSTANCE_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Enable the UDM leg (called once at startup).
pub fn enable() {
    UDM_ENABLED.store(true, Ordering::SeqCst);
    log::info!(
        "[SMF] UDM interaction ENABLED: sessions will register with the UDM and \
         enforce subscribed SM data (TS 23.502 §4.3.2.2.1)"
    );
}

pub fn enabled() -> bool {
    UDM_ENABLED.load(Ordering::SeqCst)
}

/// Record the NF instance id NRF registration used.
pub fn set_instance_id(id: &str) {
    if !id.is_empty() {
        let _ = SMF_INSTANCE_ID.set(id.to_string());
    }
}

/// This SMF's instance id. Falls back to a stable per-process uuid when NRF
/// registration never happened, so a UECM registration still carries the
/// `smfInstanceId` its schema requires rather than an empty string.
pub fn smf_instance_id() -> &'static str {
    SMF_INSTANCE_ID.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

/// Test-only: set the switch without going through startup.
///
/// The caller must hold [`crate::context::PROCESS_STATE_TEST_LOCK`]: this switch is
/// one of the four ambient globals that lock covers, and #308 showed that guarding
/// the writers while leaving the readers free is not weaker protection but none.
#[cfg(test)]
pub fn set_for_test(on: bool) {
    UDM_ENABLED.store(on, Ordering::SeqCst);
}

/// The subscribed values this SMF acts on, from `SessionManagementSubscriptionData`.
///
/// A narrow struct rather than the whole schema: these are the members #79 names as
/// enforceable (`sessionAmbr`, `5gQosProfile.5qi`), plus the ARP that comes with the
/// QoS profile because TS 29.571 makes it `required` there and it is what an EPS
/// bearer's ARP is derived from (#117). Everything else in `DnnConfiguration` is
/// deliberately not modelled — a member parsed and never enforced reads as
/// implemented and is not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubscribedSmData {
    /// Subscribed session-AMBR uplink, in bits per second.
    pub sess_ambr_ul_bps: Option<u64>,
    /// Subscribed session-AMBR downlink, in bits per second.
    pub sess_ambr_dl_bps: Option<u64>,
    /// Subscribed default 5QI.
    pub default_5qi: Option<u8>,
    /// ARP priority level from the subscribed default QoS profile.
    pub arp_priority_level: Option<u8>,
}

impl SubscribedSmData {
    /// Whether anything enforceable was retrieved. A response that parsed but
    /// carried none of these is not an error — the subscription simply states no
    /// override — but it is worth distinguishing from a failed fetch at the call
    /// site, so the log can say which happened.
    pub fn is_empty(&self) -> bool {
        self.sess_ambr_ul_bps.is_none()
            && self.sess_ambr_dl_bps.is_none()
            && self.default_5qi.is_none()
            && self.arp_priority_level.is_none()
    }
}

/// Parse a bit rate as TS 29.571's `BitRate` states it: a decimal number followed
/// by a unit, e.g. `"200 Mbps"`.
///
/// Returns `None` for anything unparseable rather than defaulting to zero: a
/// session AMBR of 0 would police the subscriber's traffic to nothing, which is far
/// worse than falling back to the configured default.
pub fn parse_bit_rate(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    let split = raw
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(raw.len());
    let (value, unit) = raw.split_at(split);
    let value: f64 = value.trim().parse().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let multiplier: f64 = match unit.trim().to_ascii_lowercase().as_str() {
        "bps" => 1.0,
        "kbps" => 1e3,
        "mbps" => 1e6,
        "gbps" => 1e9,
        "tbps" => 1e12,
        other => {
            log::warn!("subscribed BitRate '{raw}' has unrecognised unit '{other}'; ignored");
            return None;
        }
    };
    let bps = value * multiplier;
    if bps > u64::MAX as f64 {
        return None;
    }
    Some(bps as u64)
}

/// Extract the enforceable subscription values for `dnn` out of an `sm-data` body.
///
/// The response is either one `SessionManagementSubscriptionData` or an array of
/// them (one per S-NSSAI); both are accepted, and when an S-NSSAI is supplied the
/// matching entry is preferred over the first. Inside it, `dnnConfigurations` is a
/// map keyed by DNN, and TS 29.503 allows the **wildcard DNN** as a key, so an
/// exact match is tried first and the wildcard second.
///
/// Split out from the request so every one of those shapes is testable without a
/// UDM — which matters more than usual here, because `dnnConfigurations` being a
/// free-form map means a wrong key lookup silently yields "no subscription" rather
/// than an error.
pub fn parse_sm_data(
    json: &serde_json::Value,
    dnn: &str,
    sst: u8,
    sd: Option<&str>,
) -> SubscribedSmData {
    let entries: Vec<&serde_json::Value> = match json {
        serde_json::Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    // Prefer the entry whose singleNssai matches; fall back to the first.
    let entry = entries
        .iter()
        .find(|e| {
            let nssai = &e["singleNssai"];
            nssai["sst"].as_u64() == Some(sst as u64)
                && match sd {
                    Some(sd) => nssai["sd"].as_str() == Some(sd),
                    None => nssai.get("sd").is_none() || nssai["sd"].is_null(),
                }
        })
        .or(entries.first())
        .copied();
    let Some(entry) = entry else {
        return SubscribedSmData::default();
    };

    let configs = &entry["dnnConfigurations"];
    // TS 29.503: the wildcard DNN is a permitted key. Exact match wins.
    let config = configs
        .get(dnn)
        .or_else(|| configs.get("*"))
        .unwrap_or(&serde_json::Value::Null);

    let ambr = &config["sessionAmbr"];
    let qos = &config["5gQosProfile"];
    SubscribedSmData {
        sess_ambr_ul_bps: ambr["uplink"].as_str().and_then(parse_bit_rate),
        sess_ambr_dl_bps: ambr["downlink"].as_str().and_then(parse_bit_rate),
        // 5Qi is 0..=255 in TS 29.571.
        default_5qi: qos["5qi"].as_u64().and_then(|v| u8::try_from(v).ok()),
        arp_priority_level: qos["arp"]["priorityLevel"]
            .as_u64()
            .filter(|p| (1..=15).contains(p))
            .map(|p| p as u8),
    }
}

/// `Nudm_SDM_Get sm-data` for one DNN (TS 29.503 §5.2.2.2).
///
/// Scoped with `?dnn=` only. `single-nssai` is deliberately omitted for the reason
/// #204 documented at `smf_select_data_path`: its value is JSON, the shared SBI
/// server stores query values without percent-decoding them (issue #65), so a
/// conformantly-encoded value cannot round-trip in-tree. The S-NSSAI is instead
/// matched inside [`parse_sm_data`], which needs no wire support.
pub async fn fetch_sm_data(
    supi: &str,
    dnn: &str,
    sst: u8,
    sd: Option<&str>,
) -> Option<SubscribedSmData> {
    if !enabled() {
        return None;
    }
    let (host, port) = crate::discover_udm_sdm_endpoint().await?;
    let client = nextgcore_sbi::context::global_context()
        .get_client(&host, port)
        .await;
    let path = format!("/nudm-sdm/v2/{supi}/sm-data?dnn={dnn}");
    let response = match client.get(&path).await {
        Ok(r) => r,
        Err(e) => {
            log::warn!(
                "[{supi}] Nudm_SDM_Get sm-data failed: {e}. QoS falls back to the \
                 configured default for DNN {dnn}."
            );
            return None;
        }
    };
    if !response.is_success() {
        log::warn!(
            "[{supi}] Nudm_SDM_Get sm-data returned status {}. QoS falls back to the \
             configured default for DNN {dnn}.",
            response.status
        );
        return None;
    }
    let body = response.http.content.as_deref().unwrap_or_default();
    let json: serde_json::Value = match serde_json::from_str(body) {
        Ok(j) => j,
        Err(e) => {
            log::warn!("[{supi}] sm-data is not valid JSON: {e}");
            return None;
        }
    };
    let data = parse_sm_data(&json, dnn, sst, sd);
    if data.is_empty() {
        log::info!(
            "[{supi}] sm-data carried no enforceable values for DNN {dnn}: the \
             subscription states no session-AMBR or default 5QI override"
        );
    } else {
        log::info!("[{supi}] subscribed SM data for DNN {dnn}: {data:?}");
    }
    Some(data)
}

/// `Nudm_UECM_Registration` — register as the serving SMF for this PDU session
/// (TS 29.503 §5.3.2.2, `PUT .../registrations/smf-registrations/{pduSessionId}`).
///
/// The four `required` members of `SmfRegistration` are `smfInstanceId`,
/// `pduSessionId`, `singleNssai` and `plmnId`. `plmnId` comes from the serving PLMN
/// the AMF supplied on the create request — **not** from a configured home PLMN:
/// the registration records where the session is being served, and for a roamer
/// those differ.
///
/// Failure is non-fatal and says what it costs: the UDM holds no serving-SMF record
/// for this session, so procedures that resolve the serving SMF through the UDM
/// will not find it. Refusing the session instead would make a UDM outage a total
/// outage.
pub async fn register_as_serving_smf(
    supi: &str,
    pdu_session_id: u8,
    dnn: &str,
    sst: u8,
    sd: Option<&str>,
    plmn: Option<(&str, &str)>,
) -> bool {
    if !enabled() {
        return false;
    }
    let Some((host, port)) = crate::discover_udm_uecm_endpoint().await else {
        log::warn!(
            "[{supi}] no UDM nudm-uecm endpoint: cannot register as serving SMF for \
             PSI {pdu_session_id}, so the UDM holds no serving-SMF record for it"
        );
        return false;
    };
    let Some((mcc, mnc)) = plmn else {
        // plmnId is `required`. Sending the registration without it would be
        // rejected by a conformant UDM, and inventing a PLMN would record the
        // session as served somewhere it is not.
        log::warn!(
            "[{supi}] the create request carried no serving PLMN: SmfRegistration \
             requires plmnId, so no UECM registration is sent for PSI {pdu_session_id}"
        );
        return false;
    };

    let mut body = serde_json::json!({
        "smfInstanceId": smf_instance_id(),
        "pduSessionId": pdu_session_id,
        "singleNssai": { "sst": sst },
        "plmnId": { "mcc": mcc, "mnc": mnc },
        "dnn": dnn,
    });
    if let Some(sd) = sd {
        body["singleNssai"]["sd"] = serde_json::json!(sd);
    }

    let path = format!("/nudm-uecm/v1/{supi}/registrations/smf-registrations/{pdu_session_id}");
    let request = nextgcore_sbi::message::SbiRequest::put(path).with_body(
        body.to_string(),
        nextgcore_sbi::constants::content_type::APPLICATION_JSON,
    );
    let client = nextgcore_sbi::context::global_context()
        .get_client(&host, port)
        .await;
    match client.send_request(request).await {
        // 201 (created) and 200/204 (replaced) are all success for a PUT upsert.
        Ok(resp) if resp.is_success() => {
            log::info!(
                "[{supi}] registered as serving SMF for PSI {pdu_session_id} (status {})",
                resp.status
            );
            true
        }
        Ok(resp) => {
            log::warn!(
                "[{supi}] Nudm_UECM_Registration for PSI {pdu_session_id} returned status {}: \
                 the UDM holds no serving-SMF record for this session",
                resp.status
            );
            false
        }
        Err(e) => {
            log::warn!(
                "[{supi}] Nudm_UECM_Registration for PSI {pdu_session_id} failed: {e}: \
                 the UDM holds no serving-SMF record for this session"
            );
            false
        }
    }
}

/// `Nudm_UECM_Deregistration` — remove the serving-SMF record when the PDU session
/// is released (issue #293, TS 29.503 §5.3.2.4,
/// `DELETE .../registrations/smf-registrations/{pduSessionId}`).
///
/// #79 added the registration and nothing removed it, so a UDM accumulated
/// serving-SMF records for released sessions. The damage, in order of how badly it
/// bites: a procedure resolving the serving SMF through the UDM resolves a
/// **released** session to this SMF, which answers `404 CONTEXT_NOT_FOUND` at best;
/// a re-established session with the same `pduSessionId` overwrites the stale record,
/// so it self-heals for the common case and is permanent for a `pduSessionId` the UE
/// never reuses; and `udmd`'s store grows without bound for long-lived subscribers.
///
/// Failure is non-fatal — the session is being released either way — and names the
/// record that is now stale, because that is the only trace an operator gets.
pub async fn deregister_serving_smf(supi: &str, pdu_session_id: u8) -> bool {
    if !enabled() {
        return false;
    }
    let Some((host, port)) = crate::discover_udm_uecm_endpoint().await else {
        log::warn!(
            "[{supi}] no UDM nudm-uecm endpoint: the serving-SMF record for PSI \
             {pdu_session_id} is left behind and will resolve a released session to \
             this SMF"
        );
        return false;
    };
    let path = format!("/nudm-uecm/v1/{supi}/registrations/smf-registrations/{pdu_session_id}");
    let client = nextgcore_sbi::context::global_context()
        .get_client(&host, port)
        .await;
    match client
        .send_request(nextgcore_sbi::message::SbiRequest::delete(path))
        .await
    {
        // 204 is the defined answer; 404 means the UDM does not hold it, which is the
        // state this call wanted and not a failure worth reporting as one.
        Ok(resp) if resp.is_success() || resp.status == 404 => {
            log::info!(
                "[{supi}] serving-SMF registration for PSI {pdu_session_id} removed \
                 (status {})",
                resp.status
            );
            true
        }
        Ok(resp) => {
            log::warn!(
                "[{supi}] Nudm_UECM_Deregistration for PSI {pdu_session_id} returned \
                 status {}: the serving-SMF record is STALE and will resolve a released \
                 session to this SMF",
                resp.status
            );
            false
        }
        Err(e) => {
            log::warn!(
                "[{supi}] Nudm_UECM_Deregistration for PSI {pdu_session_id} failed: {e}: \
                 the serving-SMF record is STALE and will resolve a released session to \
                 this SMF"
            );
            false
        }
    }
}

/// `Nudm_SDM_Subscribe` — ask the UDM to notify this SMF when the subscriber's SM
/// data changes (issue #293, TS 29.503 §5.2.2.3,
/// `POST /nudm-sdm/v2/{supi}/sdm-subscriptions`).
///
/// Returns the subscription id, taken from the `Location` header the UDM must send
/// (TS 29.503 §5.2.2.3.1), so the release path can delete the resource it created.
/// `None` on any failure: a session without a subscription is a working session whose
/// QoS simply does not follow a mid-session administrative edit, which is exactly the
/// pre-#293 behaviour.
///
/// **The order matters and is the reason #79 left this out.** Subscribing creates a
/// resource on the UDM whose notifications go to a callback URI, so a subscription
/// sent by an SMF that serves no notification handler creates a resource that
/// notifies into a `404` — strictly worse than not subscribing, because the UDM then
/// retries against us. The handler
/// (`nsmf-callback/v1/sdm-notify/{smContextRef}`) is therefore part of this same
/// change, and `callback_uri` is the caller's proof that it has one.
pub async fn subscribe_sm_data(
    supi: &str,
    callback_uri: &str,
    dnn: &str,
    sst: u8,
    sd: Option<&str>,
) -> Option<String> {
    if !enabled() {
        return None;
    }
    let (host, port) = crate::discover_udm_sdm_endpoint().await?;

    // `nfInstanceId`, `callbackReference` and `monitoredResourceUris` are the three
    // `required` members of SdmSubscription (TS 29.503). The monitored URI is the
    // same `sm-data` resource `fetch_sm_data` reads, scoped to this session's DNN, so
    // the UDM notifies about the document this session actually depends on.
    let mut monitored = format!("/nudm-sdm/v2/{supi}/sm-data?dnn={dnn}&sst={sst}");
    if let Some(sd) = sd {
        monitored.push_str(&format!("&sd={sd}"));
    }
    let body = serde_json::json!({
        "nfInstanceId": smf_instance_id(),
        "callbackReference": callback_uri,
        "monitoredResourceUris": [monitored],
    });

    let path = format!("/nudm-sdm/v2/{supi}/sdm-subscriptions");
    let request = nextgcore_sbi::message::SbiRequest::post(path).with_body(
        body.to_string(),
        nextgcore_sbi::constants::content_type::APPLICATION_JSON,
    );
    let client = nextgcore_sbi::context::global_context()
        .get_client(&host, port)
        .await;
    let response = match client.send_request(request).await {
        Ok(resp) => resp,
        Err(e) => {
            log::warn!(
                "[{supi}] Nudm_SDM_Subscribe failed: {e}. Subscription changes will not \
                 reach this session until it re-establishes."
            );
            return None;
        }
    };
    if !response.is_success() {
        log::warn!(
            "[{supi}] Nudm_SDM_Subscribe returned status {}. Subscription changes will \
             not reach this session until it re-establishes.",
            response.status
        );
        return None;
    }
    let id =
        subscription_id_from_location(response.http.get_header("Location").map(String::as_str))
            .or_else(|| {
                response
                    .http
                    .content
                    .as_deref()
                    .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
                    .and_then(|v| {
                        v.get("subscriptionId")
                            .and_then(|s| s.as_str())
                            .map(str::to_string)
                    })
            });
    match id {
        Some(id) => {
            log::info!("[{supi}] subscribed to SM data changes (subscription {id})");
            Some(id)
        }
        None => {
            // A subscription whose id we do not know is a resource we can never
            // delete: an orphan on the UDM, notifying a callback whose session is
            // gone. Reported rather than stored as an empty string.
            log::warn!(
                "[{supi}] Nudm_SDM_Subscribe succeeded but named no subscription id \
                 (no Location header): the subscription is an ORPHAN this SMF cannot delete"
            );
            None
        }
    }
}

/// Take the last non-empty path segment of a `Location` header as the resource id.
///
/// Separated so the shapes a conformant UDM may send are testable: an absolute URI,
/// a relative path, and a path with a trailing slash all name the same id, and
/// `udmd` itself answers with a relative one.
pub fn subscription_id_from_location(location: Option<&str>) -> Option<String> {
    let raw = location?.split('?').next().unwrap_or_default();
    raw.trim_end_matches('/')
        .rsplit('/')
        .find(|seg| !seg.is_empty())
        .map(str::to_string)
}

/// `Nudm_SDM_Unsubscribe` — delete the subscription created at establishment
/// (issue #293, TS 29.503 §5.2.2.4,
/// `DELETE /nudm-sdm/v2/{supi}/sdm-subscriptions/{subscriptionId}`).
///
/// Non-fatal, and the consequence named on failure is the one that matters: the
/// subscription outlives the session, so the UDM keeps notifying a callback URI whose
/// `smContextRef` no longer resolves.
pub async fn unsubscribe_sm_data(supi: &str, subscription_id: &str) -> bool {
    if !enabled() {
        return false;
    }
    let Some((host, port)) = crate::discover_udm_sdm_endpoint().await else {
        log::warn!(
            "[{supi}] no UDM nudm-sdm endpoint: SDM subscription {subscription_id} is \
             left behind and will notify a callback whose session is gone"
        );
        return false;
    };
    let path = format!("/nudm-sdm/v2/{supi}/sdm-subscriptions/{subscription_id}");
    let client = nextgcore_sbi::context::global_context()
        .get_client(&host, port)
        .await;
    match client
        .send_request(nextgcore_sbi::message::SbiRequest::delete(path))
        .await
    {
        Ok(resp) if resp.is_success() || resp.status == 404 => {
            log::info!("[{supi}] SDM subscription {subscription_id} deleted");
            true
        }
        Ok(resp) => {
            log::warn!(
                "[{supi}] Nudm_SDM_Unsubscribe({subscription_id}) returned status {}: the \
                 subscription outlives its session and will notify a dead callback",
                resp.status
            );
            false
        }
        Err(e) => {
            log::warn!(
                "[{supi}] Nudm_SDM_Unsubscribe({subscription_id}) failed: {e}: the \
                 subscription outlives its session and will notify a dead callback"
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_subscription_id_is_the_last_segment_of_whatever_location_shape_arrives() {
        assert_eq!(
            subscription_id_from_location(Some(
                "http://udm:7777/nudm-sdm/v2/imsi-1/sdm-subscriptions/sub-42"
            )),
            Some("sub-42".to_string())
        );
        assert_eq!(
            subscription_id_from_location(Some("/nudm-sdm/v2/imsi-1/sdm-subscriptions/sub-42")),
            Some("sub-42".to_string())
        );
        assert_eq!(
            subscription_id_from_location(Some("/nudm-sdm/v2/imsi-1/sdm-subscriptions/sub-42/")),
            Some("sub-42".to_string()),
            "a trailing slash names the same resource"
        );
        assert_eq!(
            subscription_id_from_location(Some("/sdm-subscriptions/sub-42?expires=1")),
            Some("sub-42".to_string()),
            "a query string is not part of the id"
        );
        assert_eq!(subscription_id_from_location(None), None);
        assert_eq!(subscription_id_from_location(Some("")), None);
        assert_eq!(subscription_id_from_location(Some("/")), None);
    }

    #[test]
    fn bit_rates_parse_in_every_unit_and_refuse_nonsense() {
        assert_eq!(parse_bit_rate("200 Mbps"), Some(200_000_000));
        assert_eq!(parse_bit_rate("1Gbps"), Some(1_000_000_000));
        assert_eq!(parse_bit_rate("500 Kbps"), Some(500_000));
        assert_eq!(parse_bit_rate("64 bps"), Some(64));
        assert_eq!(parse_bit_rate("1.5 Mbps"), Some(1_500_000));
        // A unit we do not know must yield None, not a silent 1x multiplier: a
        // subscription meaning gigabits enforced as bits would police a subscriber
        // to nothing.
        assert_eq!(parse_bit_rate("200 Zbps"), None);
        assert_eq!(parse_bit_rate(""), None);
        assert_eq!(parse_bit_rate("Mbps"), None);
        assert_eq!(parse_bit_rate("-5 Mbps"), None);
    }

    fn sm_data_body() -> serde_json::Value {
        serde_json::json!({
            "singleNssai": { "sst": 1, "sd": "010203" },
            "dnnConfigurations": {
                "internet": {
                    "pduSessionTypes": { "defaultSessionType": "IPV4" },
                    "sscModes": { "defaultSscMode": "SSC_MODE_1" },
                    "sessionAmbr": { "uplink": "100 Mbps", "downlink": "500 Mbps" },
                    "5gQosProfile": {
                        "5qi": 7,
                        "arp": { "priorityLevel": 3, "preemptCap": "NOT_PREEMPT",
                                 "preemptVuln": "PREEMPTABLE" }
                    }
                }
            }
        })
    }

    #[test]
    fn sm_data_yields_the_subscribed_ambr_and_default_5qi_for_the_right_dnn() {
        let data = parse_sm_data(&sm_data_body(), "internet", 1, Some("010203"));
        assert_eq!(data.sess_ambr_ul_bps, Some(100_000_000));
        assert_eq!(data.sess_ambr_dl_bps, Some(500_000_000));
        assert_eq!(data.default_5qi, Some(7));
        assert_eq!(data.arp_priority_level, Some(3));
        assert!(!data.is_empty());

        // A DNN the subscription does not configure yields nothing enforceable --
        // NOT another DNN's values, which is what a "take the first entry" lookup
        // over a map would do.
        let other = parse_sm_data(&sm_data_body(), "ims", 1, Some("010203"));
        assert!(
            other.is_empty(),
            "an unconfigured DNN must not inherit another DNN's subscription, got {other:?}"
        );
    }

    /// TS 29.503 allows the wildcard DNN as a `dnnConfigurations` key, and it is
    /// the fallback rather than the winner: an exact entry must beat it.
    #[test]
    fn the_wildcard_dnn_is_a_fallback_and_never_beats_an_exact_entry() {
        let body = serde_json::json!({
            "singleNssai": { "sst": 1 },
            "dnnConfigurations": {
                "*": { "sessionAmbr": { "uplink": "1 Mbps", "downlink": "1 Mbps" } },
                "internet": { "sessionAmbr": { "uplink": "100 Mbps", "downlink": "500 Mbps" } }
            }
        });
        assert_eq!(
            parse_sm_data(&body, "internet", 1, None).sess_ambr_ul_bps,
            Some(100_000_000),
            "the exact DNN entry must win"
        );
        assert_eq!(
            parse_sm_data(&body, "anything-else", 1, None).sess_ambr_ul_bps,
            Some(1_000_000),
            "an unlisted DNN falls back to the wildcard"
        );
    }

    /// An array response is one entry per S-NSSAI, and the matching one must be
    /// chosen: taking the first would apply another slice's subscription.
    #[test]
    fn an_array_response_selects_the_matching_snssai() {
        let body = serde_json::json!([
            {
                "singleNssai": { "sst": 2 },
                "dnnConfigurations": { "internet": {
                    "sessionAmbr": { "uplink": "1 Mbps", "downlink": "1 Mbps" } } }
            },
            {
                "singleNssai": { "sst": 1, "sd": "010203" },
                "dnnConfigurations": { "internet": {
                    "sessionAmbr": { "uplink": "100 Mbps", "downlink": "500 Mbps" } } }
            }
        ]);
        assert_eq!(
            parse_sm_data(&body, "internet", 1, Some("010203")).sess_ambr_ul_bps,
            Some(100_000_000),
            "the entry for the session's own S-NSSAI must be chosen, not the first"
        );
        assert_eq!(
            parse_sm_data(&body, "internet", 2, None).sess_ambr_ul_bps,
            Some(1_000_000)
        );
    }

    #[test]
    fn a_malformed_or_absent_subscription_yields_nothing_rather_than_zero() {
        for body in [
            serde_json::json!({}),
            serde_json::json!({ "singleNssai": { "sst": 1 } }),
            serde_json::json!({ "singleNssai": { "sst": 1 },
                                "dnnConfigurations": { "internet": {} } }),
            // An AMBR whose units are unrecognisable: better no override than a 0.
            serde_json::json!({ "singleNssai": { "sst": 1 },
                                "dnnConfigurations": { "internet": {
                                    "sessionAmbr": { "uplink": "lots", "downlink": "more" } } } }),
        ] {
            let data = parse_sm_data(&body, "internet", 1, None);
            assert!(data.is_empty(), "expected nothing enforceable from {body}");
            assert_ne!(
                data.sess_ambr_ul_bps,
                Some(0),
                "a zero AMBR would police the subscriber to nothing"
            );
        }

        // An out-of-range ARP priority level is dropped rather than clamped: the
        // value is meaningless, and clamping would invent a priority.
        let body = serde_json::json!({ "singleNssai": { "sst": 1 },
            "dnnConfigurations": { "internet": {
                "5gQosProfile": { "5qi": 9, "arp": { "priorityLevel": 0 } } } } });
        let data = parse_sm_data(&body, "internet", 1, None);
        assert_eq!(data.default_5qi, Some(9));
        assert_eq!(data.arp_priority_level, None);
    }

    #[tokio::test]
    async fn a_disabled_leg_neither_fetches_nor_registers() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        set_for_test(false);
        assert!(fetch_sm_data("imsi-1", "internet", 1, None).await.is_none());
        assert!(
            !register_as_serving_smf("imsi-1", 5, "internet", 1, None, Some(("001", "01"))).await
        );
    }
    /// #79 criterion 1, on the wire: the SMF really performs
    /// `Nudm_UECM_Registration` and `Nudm_SDM_Get sm-data`.
    ///
    /// The recorded `(method, path, body)` is the assertion. Neither operation had
    /// ANY caller before this — `rg smf-registrations` across `src/` was empty — so
    /// a test that only checked the returned value would pass against a function
    /// that answered from nowhere.
    #[tokio::test]
    async fn the_smf_registers_with_the_udm_and_fetches_sm_data() {
        use nextgcore_sbi::message::{SbiRequest, SbiResponse};
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        use std::net::SocketAddr;

        // Loopback plaintext peer: the default SbiProfile is Production and would
        // refuse the connection, failing this test for an unrelated reason.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

        // TWO locks, and both are needed: the switch, and the `UDM_SBI_*`
        // environment this test re-points at its own loopback UDM. The second is
        // the crate-root one `main.rs`'s #204 tests also take — a lock of this
        // module's own would be a second disjoint agreement about one variable, and
        // that is exactly how this test first flaked.
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        set_for_test(true);

        // `(method, path, body, dnn-query-param)`. The fourth field exists because
        // the shared SBI server STRIPS the query string from `header.uri` and
        // delivers pairs in `http.params`, so asserting the scoping against the URI
        // would assert something the server never puts there.
        #[allow(clippy::type_complexity)]
        let seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String, String, String)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let port = nextgcore_sbi::test_support::free_port();
        let udm = SbiServer::new(SbiServerConfig::new(SocketAddr::from((
            [127, 0, 0, 1],
            port,
        ))));
        udm.start(move |req: SbiRequest| {
            let sink = sink.clone();
            async move {
                sink.lock().unwrap_or_else(|e| e.into_inner()).push((
                    req.header.method.clone(),
                    req.header.uri.clone(),
                    req.http.content.clone().unwrap_or_default(),
                    req.http.get_param("dnn").cloned().unwrap_or_default(),
                ));
                if req.header.uri.contains("/sm-data") {
                    return SbiResponse::with_status(200)
                        .with_json_body(&sm_data_body())
                        .unwrap_or_else(|_| SbiResponse::with_status(200));
                }
                SbiResponse::with_status(201)
            }
        })
        .await
        .expect("udm start");

        // Both legs discover the UDM through the env fallback, which names one UDM
        // for every nudm service (see `discover_udm_service_endpoint`).
        std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
        std::env::set_var("UDM_SBI_PORT", port.to_string());

        let supi = "imsi-001010000000079";
        assert!(
            register_as_serving_smf(supi, 5, "internet", 1, Some("010203"), Some(("001", "01")))
                .await,
            "the UECM registration must succeed against a 201"
        );
        let data = fetch_sm_data(supi, "internet", 1, Some("010203"))
            .await
            .expect("sm-data must be fetched");
        assert_eq!(data.sess_ambr_ul_bps, Some(100_000_000));
        assert_eq!(data.default_5qi, Some(7));

        let requests = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();

        // Matched by SUPI as well as by resource: this loopback server is reachable
        // by any sibling test that reads `UDM_SBI_*` (the create path fetches the
        // subscribed default DNN from it), so a bare "find a registration" could
        // pick up a request this test did not make.
        let reg = requests
            .iter()
            .find(|(_, uri, _, _)| uri.contains("smf-registrations") && uri.contains(supi))
            .unwrap_or_else(|| panic!("a UECM registration must be sent, got {requests:?}"));
        assert_eq!(reg.0, "PUT", "TS 29.503 §5.3.2.2 registers with a PUT");
        assert_eq!(
            reg.1, "/nudm-uecm/v1/imsi-001010000000079/registrations/smf-registrations/5",
            "the resource is per PDU session"
        );
        let body: serde_json::Value = serde_json::from_str(&reg.2).expect("json");
        // The four `required` members of SmfRegistration.
        for required in ["smfInstanceId", "pduSessionId", "singleNssai", "plmnId"] {
            assert!(
                body.get(required).is_some(),
                "SmfRegistration.{required} is required, got {body}"
            );
        }
        assert_eq!(body["pduSessionId"], serde_json::json!(5));
        assert_eq!(body["singleNssai"]["sst"], serde_json::json!(1));
        assert_eq!(body["singleNssai"]["sd"], serde_json::json!("010203"));
        assert_eq!(body["plmnId"]["mcc"], serde_json::json!("001"));
        assert!(
            body["smfInstanceId"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "smfInstanceId must be a real value, not an empty string"
        );

        let sdm = requests
            .iter()
            .find(|(_, uri, _, _)| uri.ends_with("/sm-data") && uri.contains(supi))
            .unwrap_or_else(|| panic!("an sm-data GET must be sent, got {requests:?}"));
        assert_eq!(sdm.0, "GET");
        assert_eq!(
            sdm.1, "/nudm-sdm/v2/imsi-001010000000079/sm-data",
            "Nudm_SDM is at v2, unlike the other Nudm services"
        );
        assert_eq!(
            sdm.3, "internet",
            "the request must be scoped to the session's DNN. `single-nssai` is \
             deliberately omitted -- see `fetch_sm_data`"
        );

        // A registration with no serving PLMN is NOT sent: plmnId is required, and
        // inventing one would record the session as served somewhere it is not.
        seen.lock().unwrap_or_else(|e| e.into_inner()).clear();
        assert!(!register_as_serving_smf(supi, 6, "internet", 1, None, None).await);
        let after = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            !after
                .iter()
                .any(|(_, uri, _, _)| uri.contains("smf-registrations") && uri.contains(supi)),
            "no PLMN means no registration on the wire, got {after:?}"
        );

        set_for_test(false);
        std::env::remove_var("UDM_SBI_ADDR");
        std::env::remove_var("UDM_SBI_PORT");
        udm.stop().await.expect("stop");
    }
}
