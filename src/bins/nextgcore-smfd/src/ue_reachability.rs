//! #1707: a UE the AMF reported unreachable, TS 23.502 §4.2.3.3 steps 3a and 3c
//! (`23502-k20.txt:7114-7120`, `:7259-7277`).
//!
//! Two AMF answers record one ([`record_ue_unreachable`]):
//! - a paging transfer refused with 504 UE_NOT_REACHABLE (TS 29.518 §5.2.2.3.1, "the
//!   UE is not reachable for paging"), for every session of the UE;
//! - an N1N2TransferFailure notification with UE_NOT_REACHABLE_FOR_SESSION, which
//!   names "the non-3GPP PDU session" (TS 29.518 Table 6.1.6.3.x), for that session.
//!
//! While a record holds, a Downlink Data Report pages nothing (step 3a, "if the SMF
//! had previously been notified that the UE is unreachable",
//! [`ue_unreachable_holds`]). Step 3c's network policy toward the UPF is
//! `SMF_UE_UNREACHABLE_UPF_POLICY` ([`UpfPolicy`]); then the SMF "subscribes to the
//! AMF for UE reachability event notifications": a Namf_EventExposure
//! REACHABILITY_REPORT subscription with the "UE Reachable for DL Traffic" filter
//! (TS 29.518 §5.3.1, `29518-k00.txt:5069-5080`), the report for "when the UE becomes
//! reachable for sending downlink data".
//!
//! A record ends ([`clear`]) when:
//! - that subscription notifies REACHABLE ([`handle_reachability_notify`]);
//! - the UE's user plane is activated, which only a reachable UE does;
//! - `SMF_UE_UNREACHABLE_HOLD_SECS` (default 3600 s) passes, which bounds a record whose
//!   AMF restarted and lost the subscription. The subscription carries the same
//!   expiry, so the AMF drops it too.
//!
//! Ending one restores the downlink FAR the policy changed, to BUFF|NOCP, and deletes
//! the subscription.

use crate::context;
use crate::n4_build::apply_action;

/// TS 23.502 §4.2.3.3 step 3c's network policy toward the UPF, for a UE the AMF
/// reported unreachable: `SMF_UE_UNREACHABLE_UPF_POLICY`.
///
/// The step's second and third options are one Apply Action on the wire: buffering
/// stops with DROP, and "the NOCP flag and BDPN flag may only be set if the BUFF
/// flag is set" (TS 29.244 §8.2.26, `29244-k00.txt:30338`), so DROP sends no Data
/// Notification either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpfPolicy {
    /// `refrain` (the default): the fourth option. The SMF "refrains from sending
    /// further Namf_Communication_N1N2MessageTransfer message for DL data", and the
    /// UPF is not told. Its buffering episode has reported already, and it reports
    /// again only once the FAR is re-armed.
    Refrain,
    /// `stop-notifications`: the FAR buffers without NOCP.
    StopNotifications,
    /// `discard` (or `stop-notifications-and-discard`): the FAR drops, which discards
    /// the buffered data (TS 29.244 §5.2.3.1).
    Discard,
}

impl UpfPolicy {
    fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "refrain" => Some(Self::Refrain),
            "stop-notifications" => Some(Self::StopNotifications),
            "discard" | "stop-notifications-and-discard" => Some(Self::Discard),
            _ => None,
        }
    }

    /// The downlink FAR's Apply Action under this policy, `None` for no change.
    fn far_action(self) -> Option<u16> {
        match self {
            Self::Refrain => None,
            Self::StopNotifications => Some(apply_action::BUFF),
            Self::Discard => Some(apply_action::DROP),
        }
    }
}

/// A test's [`upf_policy`] and [`hold`], under `PROCESS_STATE_TEST_LOCK`.
#[cfg(test)]
pub(crate) static TEST_OVERRIDES: std::sync::Mutex<(
    Option<UpfPolicy>,
    Option<std::time::Duration>,
)> = std::sync::Mutex::new((None, None));

pub(crate) fn upf_policy() -> UpfPolicy {
    #[cfg(test)]
    if let Some(p) = TEST_OVERRIDES.lock().unwrap_or_else(|e| e.into_inner()).0 {
        return p;
    }
    match std::env::var("SMF_UE_UNREACHABLE_UPF_POLICY") {
        Ok(v) => UpfPolicy::parse(&v).unwrap_or_else(|| {
            log::warn!(
                "SMF_UE_UNREACHABLE_UPF_POLICY={v:?} is none of refrain, stop-notifications, \
                 discard, stop-notifications-and-discard: refrain is used"
            );
            UpfPolicy::Refrain
        }),
        Err(_) => UpfPolicy::Refrain,
    }
}

/// How long a record holds with no word from the AMF: `SMF_UE_UNREACHABLE_HOLD_SECS`,
/// 3600 s by default (past amfd's mobile reachable timer and implicit
/// deregistration, TS 24.501 §5.3.7).
fn hold() -> std::time::Duration {
    #[cfg(test)]
    if let Some(d) = TEST_OVERRIDES.lock().unwrap_or_else(|e| e.into_inner()).1 {
        return d;
    }
    let secs = std::env::var("SMF_UE_UNREACHABLE_HOLD_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(3600);
    std::time::Duration::from_secs(secs)
}

/// The `eventNotifyUri` of the REACHABILITY_REPORT subscription for the record at
/// `sm_context_ref`: `{apiRoot}/nsmf-callback/v1/{smContextRef}/ue-reachability/{token}`.
pub(crate) fn notify_uri(
    sm_context_ref: &str,
    token: &nextgcore_sbi::callback_auth::CallbackToken,
) -> String {
    format!(
        "{}/nsmf-callback/v1/{sm_context_ref}/ue-reachability/{}",
        crate::self_sbi_uri(),
        token.as_str()
    )
}

/// Step 3a: whether a Downlink Data Report for `sm_context_ref` must not contact the
/// AMF. The session holds a record, or another session of its UE holds a UE-wide one.
pub(crate) fn ue_unreachable_holds(sm_context_ref: &str) -> bool {
    let handle = crate::smf_self();
    let Ok(ctx) = handle.read() else {
        return false;
    };
    let Ok(bindings) = ctx.policy_bindings.read() else {
        return false;
    };
    let Some(own) = bindings.get(sm_context_ref) else {
        return false;
    };
    own.ue_unreachable.is_some()
        || bindings
            .values()
            .any(|b| b.supi == own.supi && b.ue_unreachable.as_ref().is_some_and(|u| u.ue_wide))
}

/// Step 3c: the AMF said the UE of `sm_context_ref` is unreachable (`ue_wide`) or
/// unreachable for that session. The record is made under one bindings guard, so a
/// repeated indication makes none: a session's second, or any session's once a
/// UE-wide one holds. (A UE-wide indication on a session holding a session-scoped
/// record widens it.) Then, off the caller's task, the UPF policy is applied and the
/// subscription created ([`establish`]). `true` when a record was made.
pub(crate) fn record_ue_unreachable(sm_context_ref: &str, ue_wide: bool) -> bool {
    let Some(amf_uri) = crate::serving_amf_uri(sm_context_ref) else {
        log::warn!(
            "UE of ref={sm_context_ref} unreachable, with no serving AMF to subscribe at: \
             not recorded"
        );
        return false;
    };
    let made = {
        let handle = crate::smf_self();
        let Ok(ctx) = handle.read() else {
            return false;
        };
        let Ok(mut bindings) = ctx.policy_bindings.write() else {
            return false;
        };
        let Some(supi) = bindings.get(sm_context_ref).map(|b| b.supi.clone()) else {
            return false;
        };
        let covered = bindings.iter().any(|(r, b)| {
            r != sm_context_ref
                && b.supi == supi
                && b.ue_unreachable.as_ref().is_some_and(|u| u.ue_wide)
        });
        let Some(binding) = bindings.get_mut(sm_context_ref) else {
            return false;
        };
        match binding.ue_unreachable.as_mut() {
            Some(held) => {
                held.ue_wide |= ue_wide;
                None
            }
            None if covered => None,
            None => {
                let token = nextgcore_sbi::callback_auth::CallbackToken::mint();
                let ended = std::sync::Arc::new(tokio::sync::Notify::new());
                binding.ue_unreachable = Some(context::UeUnreachable {
                    ue_wide,
                    notify_token: token.clone(),
                    amf_uri: amf_uri.clone(),
                    subscription_id: None,
                    upf_action: None,
                    ended: ended.clone(),
                });
                Some((supi, token, ended))
            }
        }
    };
    let Some((supi, token, ended)) = made else {
        log::info!("UE of ref={sm_context_ref} reported unreachable again: already recorded");
        return false;
    };
    log::warn!(
        "UE of ref={sm_context_ref} unreachable ({}): no paging for downlink data until the \
         AMF reports it reachable (TS 23.502 §4.2.3.3 steps 3a, 3c)",
        if ue_wide {
            "all its sessions"
        } else {
            "this session"
        }
    );
    if let Ok(rt) = tokio::runtime::Handle::try_current() {
        let sm_context_ref = sm_context_ref.to_string();
        rt.spawn(async move {
            establish(&sm_context_ref, &supi, &amf_uri, &token, &ended).await;
        });
    }
    true
}

/// Whether the record at `sm_context_ref` is still the one `token` names.
fn holds_token(sm_context_ref: &str, token: &nextgcore_sbi::callback_auth::CallbackToken) -> bool {
    crate::lookup_policy_binding(sm_context_ref)
        .and_then(|b| b.ue_unreachable)
        .is_some_and(|u| u.notify_token.matches(token.as_str()))
}

/// Update the record at `sm_context_ref` named by `token`, if it still holds.
fn update_record(
    sm_context_ref: &str,
    token: &nextgcore_sbi::callback_auth::CallbackToken,
    f: impl FnOnce(&mut context::UeUnreachable),
) -> bool {
    let handle = crate::smf_self();
    let Ok(ctx) = handle.read() else {
        return false;
    };
    let Ok(mut bindings) = ctx.policy_bindings.write() else {
        return false;
    };
    match bindings
        .get_mut(sm_context_ref)
        .and_then(|b| b.ue_unreachable.as_mut())
        .filter(|u| u.notify_token.matches(token.as_str()))
    {
        Some(u) => {
            f(u);
            true
        }
        None => false,
    }
}

/// The record's step 3c work, in order: the UPF policy, the subscription, then the
/// hold. Each step's outcome is kept only while the record is still the one `token`
/// names. A record cleared meanwhile is undone here (review rule: clean up a late
/// success): the FAR changed after the clear is restored, the subscription created
/// after it deleted. The hold ends early when the record does (`ended`), so a record
/// cleared after milliseconds leaves no task sleeping out the hour (#1773 R13 m4).
async fn establish(
    sm_context_ref: &str,
    supi: &str,
    amf_uri: &str,
    token: &nextgcore_sbi::callback_auth::CallbackToken,
    ended: &tokio::sync::Notify,
) {
    if let Some(action) = upf_policy().far_action() {
        let smf_seid = crate::smf_n4_seid_for(sm_context_ref);
        let _far =
            crate::SmContextLock::acquire(crate::dl_far_locks(), &smf_seid.to_string()).await;
        if holds_token(sm_context_ref, token) && session_deactivated(sm_context_ref) {
            if let Some(upf_seid) = crate::lookup_upf_seid(sm_context_ref) {
                match crate::pfcp_set_dl_far_action(smf_seid, upf_seid, action).await {
                    Ok(()) => {
                        if !update_record(sm_context_ref, token, |u| u.upf_action = Some(action)) {
                            // Cleared while the UPF was answering: put it back.
                            restore_far_locked(sm_context_ref, smf_seid, upf_seid).await;
                        }
                    }
                    Err(e) => log::warn!(
                        "Step 3c policy for the unreachable UE of ref={sm_context_ref}: the \
                         UPF did not take it ({e}); its FAR is unchanged"
                    ),
                }
            }
        }
    }
    if !holds_token(sm_context_ref, token) {
        return;
    }
    match subscribe(sm_context_ref, supi, amf_uri, token).await {
        Ok(id) => {
            if !update_record(sm_context_ref, token, |u| {
                u.subscription_id = Some(id.clone())
            }) {
                // Cleared before the 201: a conformant AMF sends the immediate REACHABLE
                // report ahead of it (TS 29.518 §5.3.1, `29518-k00.txt:5074-5080`).
                unsubscribe(amf_uri, &id).await;
                return;
            }
        }
        Err(e) => log::warn!(
            "REACHABILITY_REPORT subscription for the UE of ref={sm_context_ref} failed ({e}): \
             the record ends at its hold ({:?})",
            hold()
        ),
    }
    {
        let _holding = Holding::enter(token);
        tokio::select! {
            () = tokio::time::sleep(hold()) => {}
            () = ended.notified() => return,
        }
    }
    if let Some(record) = take_token(sm_context_ref, token) {
        log::warn!(
            "UE of ref={sm_context_ref} recorded unreachable for {:?} with no reachability \
             report: the record ends, and a report pages again",
            hold()
        );
        undo(sm_context_ref.to_string(), record).await;
    }
}

/// The holds in progress, by their record's token: what a test reads to see a hold
/// end with its record ([`hold_running`]).
static HOLDS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// One record's hold in progress, listed in [`HOLDS`] until dropped.
struct Holding(String);

impl Holding {
    fn enter(token: &nextgcore_sbi::callback_auth::CallbackToken) -> Self {
        let token = token.as_str().to_string();
        HOLDS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(token.clone());
        Self(token)
    }
}

impl Drop for Holding {
    fn drop(&mut self) {
        let mut holds = HOLDS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(at) = holds.iter().position(|r| *r == self.0) {
            holds.swap_remove(at);
        }
    }
}

/// Whether the hold of the record whose token is `token` is in progress.
#[cfg(test)]
pub(crate) fn hold_running(token: &str) -> bool {
    HOLDS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|t| t == token)
}

fn session_deactivated(sm_context_ref: &str) -> bool {
    crate::smf_self().read().ok().is_some_and(|ctx| {
        ctx.sess_find_by_sm_context_ref(sm_context_ref)
            .is_some_and(|s| s.up_cnx_state == context::UpCnxState::Deactivated)
    })
}

/// `Namf_EventExposure_Subscribe` (TS 29.518 §5.3.2.2.2) for `supi`'s REACHABILITY_REPORT,
/// "UE Reachable for DL Traffic", at the serving AMF. `Ok` with its `subscriptionId`.
async fn subscribe(
    sm_context_ref: &str,
    supi: &str,
    amf_uri: &str,
    token: &nextgcore_sbi::callback_auth::CallbackToken,
) -> Result<String, String> {
    let (host, port) =
        crate::policy::split_host_port(amf_uri).ok_or_else(|| format!("bad AMF URI {amf_uri}"))?;
    let expiry_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_add(hold())
        .as_secs();
    // AmfEventSubscription (TS 29.518 Table 6.2.6.2.3-1): eventList, eventNotifyUri,
    // notifyCorrelationId and nfId are mandatory.
    let body = serde_json::json!({
        "subscription": {
            "eventList": [{
                "type": "REACHABILITY_REPORT",
                "reachabilityFilter": "UE_REACHABLE_DL_TRAFFIC",
            }],
            "eventNotifyUri": notify_uri(sm_context_ref, token),
            "notifyCorrelationId": sm_context_ref,
            "nfId": crate::self_nf_id().await,
            "supi": supi,
            "options": {
                "trigger": "CONTINUOUS",
                "expiry": nextgcore_sbi::datetime::epoch_to_rfc3339(expiry_epoch),
            },
        }
    });
    let config = nextgcore_sbi::security::sbi_peer_client_config(&host, port)
        .with_connect_timeout(std::time::Duration::from_secs(2))
        .with_request_timeout(std::time::Duration::from_secs(3));
    let resp = crate::namf_client(config)
        .post_json("/namf-evts/v1/subscriptions", &body)
        .await
        .map_err(|e| e.to_string())?;
    if resp.status != 201 {
        return Err(format!("status {}", resp.status));
    }
    resp.http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
        .and_then(|v| v["subscriptionId"].as_str().map(str::to_string))
        .or_else(|| resp.http.get_header("location").cloned())
        .and_then(|s| s.rsplit('/').next().map(str::to_string))
        .filter(|id| !id.is_empty())
        .ok_or_else(|| "201 with no subscriptionId".to_string())
}

/// `Namf_EventExposure_Unsubscribe` (TS 29.518 §5.3.2.4.2). A 404 is a subscription the
/// AMF no longer holds, which is the outcome wanted.
async fn unsubscribe(amf_uri: &str, subscription_id: &str) {
    let Some((host, port)) = crate::policy::split_host_port(amf_uri) else {
        return;
    };
    let config = nextgcore_sbi::security::sbi_peer_client_config(&host, port)
        .with_connect_timeout(std::time::Duration::from_secs(2))
        .with_request_timeout(std::time::Duration::from_secs(3));
    match crate::namf_client(config)
        .delete(&format!("/namf-evts/v1/subscriptions/{subscription_id}"))
        .await
    {
        Ok(resp) if matches!(resp.status, 200 | 204 | 404) => {}
        Ok(resp) => log::warn!(
            "REACHABILITY_REPORT unsubscribe at {host}:{port}: status {}; it ends at its expiry",
            resp.status
        ),
        Err(e) => log::warn!(
            "REACHABILITY_REPORT unsubscribe at {host}:{port} failed ({e}); it ends at its expiry"
        ),
    }
}

/// Take the record at `sm_context_ref` if `token` names it.
fn take_token(
    sm_context_ref: &str,
    token: &nextgcore_sbi::callback_auth::CallbackToken,
) -> Option<context::UeUnreachable> {
    let handle = crate::smf_self();
    let ctx = handle.read().ok()?;
    let mut bindings = ctx.policy_bindings.write().ok()?;
    let binding = bindings.get_mut(sm_context_ref)?;
    binding
        .ue_unreachable
        .as_ref()
        .filter(|u| u.notify_token.matches(token.as_str()))?;
    binding.ue_unreachable.take()
}

/// Take every record of the UE of `sm_context_ref`: the UE is reachable.
fn take_for_ue(sm_context_ref: &str) -> Vec<(String, context::UeUnreachable)> {
    let handle = crate::smf_self();
    let Ok(ctx) = handle.read() else {
        return Vec::new();
    };
    let Ok(mut bindings) = ctx.policy_bindings.write() else {
        return Vec::new();
    };
    let Some(supi) = bindings.get(sm_context_ref).map(|b| b.supi.clone()) else {
        return Vec::new();
    };
    bindings
        .iter_mut()
        .filter(|(_, b)| b.supi == supi)
        .filter_map(|(r, b)| b.ue_unreachable.take().map(|u| (r.clone(), u)))
        .inspect(|(_, u)| u.ended.notify_one())
        .collect()
}

/// The UE of `sm_context_ref` is reachable: its records end, each undone off the
/// caller's task. `true` when there was one.
pub(crate) fn clear(sm_context_ref: &str, why: &str) -> bool {
    let taken = take_for_ue(sm_context_ref);
    if taken.is_empty() {
        return false;
    }
    log::info!(
        "UE of ref={sm_context_ref} reachable ({why}): its unreachable record ends, and a \
         Downlink Data Report pages again"
    );
    if let Ok(rt) = tokio::runtime::Handle::try_current() {
        for (r, record) in taken {
            rt.spawn(undo(r, record));
        }
    }
    true
}

/// A session's binding was taken (a release): its record's subscription is deleted.
/// Its FAR goes with the PFCP session.
pub(crate) fn forget(record: context::UeUnreachable) {
    record.ended.notify_one();
    if let (Some(id), Ok(rt)) = (
        record.subscription_id,
        tokio::runtime::Handle::try_current(),
    ) {
        let amf_uri = record.amf_uri;
        rt.spawn(async move { unsubscribe(&amf_uri, &id).await });
    }
}

/// Undo what a record did: the FAR back to BUFF|NOCP, the subscription deleted.
pub(crate) async fn undo(sm_context_ref: String, record: context::UeUnreachable) {
    if record.upf_action.is_some() {
        let smf_seid = crate::smf_n4_seid_for(&sm_context_ref);
        if let Some(upf_seid) = crate::lookup_upf_seid(&sm_context_ref) {
            let _far =
                crate::SmContextLock::acquire(crate::dl_far_locks(), &smf_seid.to_string()).await;
            restore_far_locked(&sm_context_ref, smf_seid, upf_seid).await;
        }
    }
    if let Some(id) = record.subscription_id {
        unsubscribe(&record.amf_uri, &id).await;
    }
}

/// Re-arm the downlink FAR to BUFF|NOCP, the caller holding its `dl_far_locks` entry.
/// Only for a session still DEACTIVATED: an activation sets FORW under the same lock
/// after it marked the session ACTIVATING, so a restore after that would undo it.
/// And only while no newer record holds a FAR change of its own: an undo that waited
/// on the lock while a new record's `establish` took it first is stale, and would put
/// back BUFF|NOCP under a record that believes DROP (#1773 R13 m1).
async fn restore_far_locked(sm_context_ref: &str, smf_seid: u64, upf_seid: u64) {
    if !session_deactivated(sm_context_ref) {
        return;
    }
    if crate::lookup_policy_binding(sm_context_ref)
        .and_then(|b| b.ue_unreachable)
        .is_some_and(|u| u.upf_action.is_some())
    {
        log::info!(
            "Downlink FAR of ref={sm_context_ref} not re-armed: a newer unreachable record \
             holds its own step 3c action"
        );
        return;
    }
    if let Err(e) =
        crate::pfcp_set_dl_far_action(smf_seid, upf_seid, apply_action::BUFF | apply_action::NOCP)
            .await
    {
        log::warn!(
            "Restoring the downlink FAR of ref={sm_context_ref} to BUFF|NOCP failed ({e}): \
             it is re-armed at the next deactivation"
        );
    }
}

/// `POST {ref}/ue-reachability/{token}`: the AMF's Namf_EventExposure notification
/// (TS 29.518 §5.3.2.4.1, AmfEventNotification) for a record's subscription. The router
/// has checked the token. A REACHABILITY_REPORT of REACHABLE ends the UE's records;
/// another report changes nothing. A body that is not an AmfEventNotification is
/// refused with nothing changed.
pub(crate) async fn handle_reachability_notify(
    sm_context_ref: &str,
    request: &nextgcore_sbi::message::SbiRequest,
) -> nextgcore_sbi::message::SbiResponse {
    let reports = request
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
        .and_then(|b| b.get("reportList").and_then(|l| l.as_array()).cloned());
    let Some(reports) = reports else {
        return crate::problem_400(
            "INVALID_MSG_FORMAT",
            "AmfEventNotification needs a reportList array",
        );
    };
    let reachable = reports
        .iter()
        .any(|r| r["type"] == "REACHABILITY_REPORT" && r["reachability"] == "REACHABLE");
    if reachable {
        clear(sm_context_ref, "the AMF's REACHABILITY_REPORT");
    }
    nextgcore_sbi::message::SbiResponse::with_status(204)
}
