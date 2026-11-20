//! G2-1: NRF-sourced NF_LOAD data collection (TS 23.288 §6.5 Table 6.5.2-1:
//! the data source for NF load analytics is the NRF).
//!
//! Two halves:
//!
//! 1. **Subscribe / renew** — the NWDAF POSTs an Nnrf_NFManagement
//!    NFStatusSubscribe (TS 29.510 §5.2.2.5) `SubscriptionData` to
//!    `{nrfUri}/nnrf-nfm/v1/subscriptions` with our
//!    `nfStatusNotificationUri`; `subscrCond` is omitted so every NF matches.
//!    Failures degrade to no-data (log + retry on the dispatcher tick) —
//!    the NF never panics and analytics simply report nothing.
//!
//! 2. **Ingest** — the NRF POSTs TS 29.510 §5.2.2.6 `NotificationData`
//!    (`event`, `nfInstanceUri`, optional `nfProfile` / `profileChanges`)
//!    to our callback. `NFProfile.load` (0..=100) becomes an
//!    [`NfLoadSample`] (`cpu = load / 100`); `profileChanges` `/load`
//!    add/replace items update the cached load and yield a sample;
//!    NF_DEREGISTERED drops the instance. Malformed bodies are rejected
//!    with 400 (fail-closed); unknown *fields* are ignored per TS 29.500
//!    SBI extensibility.

use crate::analytics::{NfLoadSample, NfProfileMeta};
use crate::context::{NrfStatusSubscription, NwdafContext};
use crate::notification_dispatcher::parse_notify_uri;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::send_bad_request;
use serde_json::Value;
use std::sync::{Arc, RwLock};

/// #1421: the NRF's notification carries no OAuth2 bearer (TS 33.501 §13.4.1),
/// so the `nfStatusNotificationUri` this NWDAF subscribes with ends in an
/// unguessable per-process token, `/nnwdaf-callback/v1/nf-status-notify/{token}`
/// (the #940 pattern; `nf-status-notify` is in
/// `nextgcore_sbi::log_redact::CALLBACK_TOKEN_SEGMENTS`, so logs never show it).
/// An OAuth2-required listener admits a notification on it by that token.
pub const CALLBACK_SEGMENT: &str = "nf-status-notify";

/// #2093 / #2172: the per-subscription token book, shared with every
/// NFStatusNotify receiver (`nextgcore_sbi::nf_status_notify`).
pub use nextgcore_sbi::nf_status_notify::{TokenBook, RETIRED_TOKEN_GRACE};

static TOKENS: std::sync::Mutex<TokenBook> = std::sync::Mutex::new(TokenBook::new());

fn tokens() -> std::sync::MutexGuard<'static, TokenBook> {
    TOKENS.lock().unwrap_or_else(|e| e.into_inner())
}

/// The token of the subscription in force (minted when there is none yet).
pub fn callback_token() -> String {
    tokens().current_or_mint()
}

/// The callback path carrying `token`.
pub fn callback_path_for(token: &str) -> String {
    format!("/nnwdaf-callback/v1/{CALLBACK_SEGMENT}/{token}")
}

/// The callback path of the subscription in force.
pub fn callback_path() -> String {
    callback_path_for(&callback_token())
}

/// `callback_uri` with its token segment replaced by `token`, or `None` when it
/// is not one of these callbacks and so cannot carry the token (#2131).
pub fn callback_uri_with_token(callback_uri: &str, token: &str) -> Option<String> {
    let marker = format!("/nnwdaf-callback/v1/{CALLBACK_SEGMENT}/");
    callback_uri
        .find(&marker)
        .map(|at| format!("{}{}", &callback_uri[..at], callback_path_for(token)))
}

/// #2131 (R40 on #2119): mint the token for one NFStatusSubscribe and the
/// callback URI carrying it. `None` when `callback_uri` has no token segment:
/// the token is abandoned at once, so it is never activated (notifications on
/// such a URI could name no subscription, and are refused anyway), and no
/// subscribe is sent.
fn mint_for_subscribe(book: &mut TokenBook, callback_uri: &str) -> Option<(String, String)> {
    let token = book.mint();
    match callback_uri_with_token(callback_uri, &token) {
        Some(uri) => Some((token, uri)),
        None => {
            book.abandon(&token);
            None
        }
    }
}

/// Whether `token` names a subscription this NWDAF holds (#2093): the check
/// both the route and the server's OAuth2 callback exemption (#1421) apply.
pub fn holds_callback_token(token: &str) -> bool {
    tokens().holds(token, std::time::Instant::now())
}

/// Renew the NRF subscription when it expires within this margin (seconds).
/// Two default dispatcher ticks (2 × 30 s) plus slack.
const RENEW_MARGIN_SECS: u64 = 120;

/// The notification events we subscribe for (`reqNotifEvents`, TS 29.510).
const REQ_NOTIF_EVENTS: [&str; 3] = ["NF_REGISTERED", "NF_DEREGISTERED", "NF_PROFILE_CHANGED"];

// ─────────────────────────────────────────────────────────────────────────────
// Subscribe / renew
// ─────────────────────────────────────────────────────────────────────────────

/// Build the TS 29.510 `SubscriptionData` request body for NFStatusSubscribe.
/// `subscrCond` is deliberately omitted: the NWDAF wants load data for ALL
/// NF instances (TS 23.288 §6.5).
pub fn build_nf_status_subscription_body(callback_uri: &str) -> Value {
    serde_json::json!({
        "nfStatusNotificationUri": callback_uri,
        "reqNfType": "NWDAF",
        "reqNotifEvents": REQ_NOTIF_EVENTS,
    })
}

/// Parse the NRF's 201 response into an [`NrfStatusSubscription`].
///
/// `subscriptionId` is read from the response body (TS 29.510
/// `SubscriptionData`), falling back to the last segment of the `Location`
/// header. `validityTime` (RFC 3339) becomes an absolute Unix expiry.
pub fn parse_subscription_create_response(
    body: Option<&str>,
    location: Option<&str>,
) -> Option<NrfStatusSubscription> {
    let parsed: Option<Value> = body.and_then(|b| serde_json::from_str(b).ok());

    let from_body = parsed
        .as_ref()
        .and_then(|v| v.get("subscriptionId"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let from_location = location
        .and_then(|l| l.rsplit('/').next())
        .filter(|s| !s.is_empty())
        .map(String::from);
    let subscription_id = from_body.or(from_location)?;

    let validity_unix = parsed
        .as_ref()
        .and_then(|v| v.get("validityTime"))
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.timestamp().max(0) as u64);

    Some(NrfStatusSubscription {
        subscription_id,
        validity_unix,
    })
}

/// POST the NFStatusSubscribe to the NRF and store the resulting subscription
/// state in the context. Non-fatal on every failure path (logs a warning);
/// the dispatcher tick retries via [`maybe_renew_nrf_subscription`].
pub async fn subscribe_nf_status(ctx: &Arc<RwLock<NwdafContext>>) {
    let config = match ctx.read().ok().and_then(|g| g.nrf_collector_config()) {
        Some(c) => c,
        None => return, // collector not armed (e.g., unit tests)
    };

    let (_, _, base_path) = match parse_notify_uri(&config.nrf_uri) {
        Some(t) => t,
        None => {
            log::warn!(
                "NRF NFStatusSubscribe: invalid NRF URI '{}'",
                config.nrf_uri
            );
            return;
        }
    };
    let path = format!(
        "{}/nnrf-nfm/v1/subscriptions",
        base_path.trim_end_matches('/')
    );

    // #2093: this subscription's own token. #2131: only on a callback that can
    // carry it.
    let Some((token, callback_uri)) = mint_for_subscribe(&mut tokens(), &config.callback_uri)
    else {
        log::error!(
            "NRF NFStatusSubscribe not sent: the callback URI has no /nnwdaf-callback/v1/\
             {CALLBACK_SEGMENT}/ token segment, so its notifications could name no \
             subscription"
        );
        return;
    };
    let previous_validity = ctx
        .read()
        .ok()
        .and_then(|g| g.nrf_status_subscription())
        .and_then(|sub| sub.validity_unix);
    let body = build_nf_status_subscription_body(&callback_uri);
    let Some(client) = crate::notification_dispatcher::nrf_client(&config.nrf_uri) else {
        log::warn!(
            "NRF NFStatusSubscribe: invalid NRF URI '{}'",
            config.nrf_uri
        );
        return;
    };
    match client.post_json(&path, &body).await {
        Ok(resp) if resp.status == 201 || resp.status == 200 => {
            let location = resp.http.get_header("Location").map(String::from);
            match parse_subscription_create_response(
                resp.http.content.as_deref(),
                location.as_deref(),
            ) {
                Some(sub) => {
                    log::info!(
                        "NRF NFStatusSubscribe active: id={} validity_unix={:?}",
                        sub.subscription_id,
                        sub.validity_unix
                    );
                    if let Ok(guard) = ctx.read() {
                        guard.set_nrf_status_subscription(Some(sub));
                    }
                    tokens().activate(&token, retire_at(previous_validity));
                }
                None => {
                    tokens().abandon(&token);
                    log::warn!(
                        "NRF NFStatusSubscribe: 201 without a parseable subscriptionId — will retry"
                    )
                }
            }
        }
        Ok(resp) => {
            tokens().abandon(&token);
            log::warn!(
                "NRF NFStatusSubscribe rejected (status {}) — will retry",
                resp.status
            )
        }
        Err(e) => {
            tokens().abandon(&token);
            log::warn!("NRF NFStatusSubscribe failed: {e} — will retry")
        }
    }
}

/// When a replaced subscription's token stops working (#2093): when that
/// subscription lapses at the NRF (`validity_unix`), else after
/// [`RETIRED_TOKEN_GRACE`].
fn retire_at(validity_unix: Option<u64>) -> std::time::Instant {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let left = validity_unix
        .map(|v| std::time::Duration::from_secs(v.saturating_sub(now_unix)))
        .unwrap_or(RETIRED_TOKEN_GRACE)
        .min(std::time::Duration::from_secs(24 * 3600));
    std::time::Instant::now() + left
}

/// Dispatcher-tick hook: (re-)subscribe when the collector is armed and there
/// is no active subscription, or the active one expires within
/// [`RENEW_MARGIN_SECS`]. No-op when the collector is not armed.
pub async fn maybe_renew_nrf_subscription(ctx: &Arc<RwLock<NwdafContext>>) {
    let (armed, current) = match ctx.read() {
        Ok(guard) => (
            guard.nrf_collector_config().is_some(),
            guard.nrf_status_subscription(),
        ),
        Err(_) => return,
    };
    if !armed {
        return;
    }

    let needs_subscribe = match current {
        None => true,
        Some(sub) => match sub.validity_unix {
            None => false, // no expiry communicated → nothing to renew
            Some(expiry) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::ZERO)
                    .as_secs();
                expiry.saturating_sub(now) <= RENEW_MARGIN_SECS
            }
        },
    };

    if needs_subscribe {
        subscribe_nf_status(ctx).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NFStatusNotify ingestion
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed TS 29.510 §5.2.2.6 `NotificationData`, reduced to what NF_LOAD
/// ingestion needs.
#[derive(Debug)]
struct ParsedNfStatusNotification {
    event: NfStatusEvent,
    nf_instance_id: String,
    /// From `nfProfile` when present: (nfType, nfStatus, load).
    profile: Option<(String, String, Option<u8>)>,
    /// The effective new `/load` from `profileChanges` (add/replace), and
    /// whether a `/load` remove was seen.
    load_change: Option<LoadChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NfStatusEvent {
    Registered,
    Deregistered,
    ProfileChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadChange {
    /// `/load` add/replace with the new value.
    Set(u8),
    /// `/load` remove.
    Removed,
}

/// Extract a 0..=100 load from a JSON number, rejecting out-of-range values.
fn parse_load(v: &Value) -> Option<u8> {
    v.as_u64().filter(|&n| n <= 100).map(|n| n as u8)
}

/// Parse and validate a `NotificationData` body. Mandatory-IE violations and
/// malformed values return `(detail, cause)` for a 400 ProblemDetails
/// (fail-closed); unknown additional fields are ignored (SBI extensibility).
fn parse_notification_data(
    data: &Value,
) -> Result<ParsedNfStatusNotification, (String, &'static str)> {
    let event_token = match data.get("event").and_then(|v| v.as_str()) {
        Some(t) if !t.is_empty() => t,
        _ => {
            return Err((
                "event is a mandatory IE".to_string(),
                "MANDATORY_IE_MISSING",
            ))
        }
    };
    let event = match event_token {
        "NF_REGISTERED" => NfStatusEvent::Registered,
        "NF_DEREGISTERED" => NfStatusEvent::Deregistered,
        "NF_PROFILE_CHANGED" => NfStatusEvent::ProfileChanged,
        other => {
            return Err((
                format!("Unsupported NotificationEventType: {other}"),
                "MANDATORY_IE_INCORRECT",
            ))
        }
    };

    let nf_instance_uri = match data.get("nfInstanceUri").and_then(|v| v.as_str()) {
        Some(u) if !u.is_empty() => u,
        _ => {
            return Err((
                "nfInstanceUri is a mandatory IE".to_string(),
                "MANDATORY_IE_MISSING",
            ))
        }
    };
    let nf_instance_id = match nf_instance_uri
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
    {
        Some(id) => id.to_string(),
        None => {
            return Err((
                format!("nfInstanceUri has no instance id: {nf_instance_uri}"),
                "MANDATORY_IE_INCORRECT",
            ))
        }
    };

    let profile = match data.get("nfProfile") {
        Some(Value::Object(p)) => {
            let nf_type = p
                .get("nfType")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let nf_status = p
                .get("nfStatus")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if nf_type.is_empty() || nf_status.is_empty() {
                return Err((
                    "nfProfile must carry nfType and nfStatus".to_string(),
                    "MANDATORY_IE_MISSING",
                ));
            }
            let load = p.get("load").and_then(parse_load);
            Some((nf_type, nf_status, load))
        }
        Some(_) => {
            return Err((
                "nfProfile must be an object".to_string(),
                "MANDATORY_IE_INCORRECT",
            ))
        }
        None => None,
    };

    // TS 29.510: for NF_PROFILE_CHANGED one of nfProfile / profileChanges /
    // completeNfProfile must be present; for NF_REGISTERED, nfProfile (or
    // completeNfProfile, which we treat identically) must be present.
    let profile_changes = data.get("profileChanges").and_then(|v| v.as_array());
    match event {
        NfStatusEvent::Registered if profile.is_none() => {
            return Err((
                "NF_REGISTERED requires nfProfile".to_string(),
                "MANDATORY_IE_MISSING",
            ))
        }
        NfStatusEvent::ProfileChanged if profile.is_none() && profile_changes.is_none() => {
            return Err((
                "NF_PROFILE_CHANGED requires nfProfile or profileChanges".to_string(),
                "MANDATORY_IE_MISSING",
            ))
        }
        _ => {}
    }

    // Walk profileChanges for `/load` items (TS 29.510 ChangeItem: op, path,
    // newValue). Later items win. A malformed newValue on /load fails closed.
    let mut load_change = None;
    if let Some(changes) = profile_changes {
        for item in changes {
            let path = item.get("path").and_then(|v| v.as_str()).unwrap_or("");
            if path != "/load" {
                continue;
            }
            let op = item.get("op").and_then(|v| v.as_str()).unwrap_or("");
            match op {
                "add" | "replace" => match item.get("newValue").and_then(parse_load) {
                    Some(load) => load_change = Some(LoadChange::Set(load)),
                    None => {
                        return Err((
                            "profileChanges /load newValue must be an integer 0..=100".to_string(),
                            "MANDATORY_IE_INCORRECT",
                        ))
                    }
                },
                "remove" => load_change = Some(LoadChange::Removed),
                _ => {}
            }
        }
    }

    Ok(ParsedNfStatusNotification {
        event,
        nf_instance_id,
        profile,
        load_change,
    })
}

/// Apply a parsed notification to the shared analytics engine.
///
/// Lock order (nf-context-lock-deadlocks): the caller holds the outer context
/// read guard; this takes the interior engine mutex.
fn ingest_notification(ctx: &NwdafContext, parsed: &ParsedNfStatusNotification) {
    let mut engine = ctx.lock_engine();
    let id = parsed.nf_instance_id.as_str();

    match parsed.event {
        NfStatusEvent::Deregistered => {
            log::debug!("NFStatusNotify: NF_DEREGISTERED {id} — dropping samples");
            engine.remove_nf_instance(id);
            return;
        }
        NfStatusEvent::Registered | NfStatusEvent::ProfileChanged => {}
    }

    // Update the cached profile metadata from nfProfile when present.
    if let Some((nf_type, nf_status, load)) = &parsed.profile {
        engine.upsert_nf_meta(
            id,
            NfProfileMeta {
                nf_type: nf_type.clone(),
                nf_status: nf_status.clone(),
                last_load: *load,
            },
        );
    }

    // Determine the effective new load: profileChanges `/load` wins over the
    // (already-patched) nfProfile.load nrfd also includes.
    let effective_load = match parsed.load_change {
        Some(LoadChange::Set(load)) => Some(load),
        Some(LoadChange::Removed) => {
            if let Some(meta) = engine.nf_meta(id) {
                let mut cleared = meta.clone();
                cleared.last_load = None;
                engine.upsert_nf_meta(id, cleared);
            }
            None
        }
        None => parsed.profile.as_ref().and_then(|(_, _, load)| *load),
    };

    if let Some(load) = effective_load {
        let nf_type = engine
            .nf_meta(id)
            .map(|m| m.nf_type.clone())
            .unwrap_or_else(|| "UNKNOWN".to_string());
        if let Some(meta) = engine.nf_meta(id) {
            let mut updated = meta.clone();
            updated.last_load = Some(load);
            engine.upsert_nf_meta(id, updated);
        }
        log::debug!("NFStatusNotify: ingesting load={load} for {id} ({nf_type})");
        engine.ingest_nf_load(NfLoadSample::now(
            &nf_type,
            id,
            f64::from(load) / 100.0,
            0.0,
            0,
        ));
    }
}

/// Handle `POST /nnwdaf-nfstatus-notify/v1/notify` against an explicit
/// context (isolated-context variant for tests; mirrors the DI pilot in
/// `main.rs`).
pub async fn handle_nf_status_notify_with_ctx(
    ctx: &Arc<RwLock<NwdafContext>>,
    request: &SbiRequest,
) -> SbiResponse {
    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let data: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let parsed = match parse_notification_data(&data) {
        Ok(p) => p,
        Err((detail, cause)) => return send_bad_request(&detail, Some(cause)),
    };

    match ctx.read() {
        Ok(guard) => ingest_notification(&guard, &parsed),
        Err(e) => {
            log::error!("handle_nf_status_notify: failed to read context: {e}");
            return nextgcore_sbi::server::send_internal_error("context unavailable");
        }
    }

    // TS 29.510 §5.2.2.6: NFStatusNotify success response is 204 No Content.
    SbiResponse::with_status(204)
}

/// #2081: why an NFStatusNotify may not be ingested, or `None` to go on.
///
/// The NF load values in a notification feed NF_LOAD analytics, so only the NRF,
/// about a subscription this NWDAF made, may deliver one. Under the production
/// SBI profile:
/// - `correlated` must hold: the request came in on a tokenised callback whose
///   token the [`TokenBook`] holds (#2093: one token per subscription, so the
///   subscription in force, one being subscribed, or a replaced one in its
///   grace window). The token-less route of subscriptions made before #1421
///   carries none, so it is refused;
/// - the TLS peer must be the NRF, or an SCP relaying it: the verified client
///   certificate names NF type NRF, or is a relay's naming SCP
///   ([`nextgcore_sbi::owner_binding::is_relay_certificate`]: relay types only;
///   RFC 9310). The NRF's notification carries no bearer (TS 33.501 §13.4.1),
///   so the certificate plus the per-subscription token is the only proof. A
///   certificate naming SCP and another NF type is that NF's, not a relay's
///   (#2131, the #2113 rule), and is refused like any other NF.
///
/// Under dev both are accepted as before (plaintext, nothing to verify).
pub fn refuse_notifier(
    request: &SbiRequest,
    correlated: bool,
    production: bool,
) -> Option<SbiResponse> {
    // #2172: the rule every NFStatusNotify receiver applies (#2093, #2131 and
    // #2153 included: an NRF-only certificate, or a relay-only one naming SCP).
    nextgcore_sbi::nf_status_notify::refuse_notifier(request, correlated, production)
}

/// Handle an NFStatusNotify that arrived on the tokenised callback
/// (`correlated`) or the legacy token-less one, after [`refuse_notifier`] under
/// the process's SBI profile (#2081): refused before anything is parsed or
/// ingested.
pub async fn handle_nf_status_notify_from(request: &SbiRequest, correlated: bool) -> SbiResponse {
    handle_nf_status_notify_gated_with_ctx(
        &crate::context::nwdaf_self(),
        request,
        correlated,
        nextgcore_sbi::security::SbiProfile::resolve().is_production(),
    )
    .await
}

/// [`handle_nf_status_notify_from`] against `ctx` under the profile `production`
/// says (#2081): the refusal comes before the body is read.
pub async fn handle_nf_status_notify_gated_with_ctx(
    ctx: &Arc<RwLock<NwdafContext>>,
    request: &SbiRequest,
    correlated: bool,
    production: bool,
) -> SbiResponse {
    if let Some(refused) = refuse_notifier(request, correlated, production) {
        return refused;
    }
    handle_nf_status_notify_with_ctx(ctx, request).await
}

/// Handle `POST /nnwdaf-nfstatus-notify/v1/notify` (TS 29.510 NFStatusNotify
/// callback) against the global context.
pub async fn handle_nf_status_notify(request: &SbiRequest) -> SbiResponse {
    let ctx = crate::context::nwdaf_self();
    handle_nf_status_notify_with_ctx(&ctx, request).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::AnalyticsId;
    use crate::notification_dispatcher::{compute_event_infos, EventInfoFilter};
    use serde_json::json;

    fn isolated_ctx() -> Arc<RwLock<NwdafContext>> {
        let mut ctx = NwdafContext::new("nwdaf-collector-test".to_string());
        ctx.init(64);
        Arc::new(RwLock::new(ctx))
    }

    fn notify_req(body: &Value) -> SbiRequest {
        SbiRequest::post("/nnwdaf-nfstatus-notify/v1/notify")
            .with_json_body(body)
            .expect("valid JSON body")
    }

    fn nf_load_infos(ctx: &Arc<RwLock<NwdafContext>>, instance: &str) -> Vec<Value> {
        let guard = ctx.read().unwrap();
        let engine = guard.lock_engine();
        let infos = compute_event_infos(
            &engine,
            AnalyticsId::NfLoad,
            &EventInfoFilter {
                nf_instance_ids: vec![instance.to_string()],
                nf_types: Vec::new(),
                ..Default::default()
            },
        );
        infos.as_array().cloned().unwrap_or_default()
    }

    // ── golden TS 29.510 NotificationData bodies (typed from the yaml /
    //    nrfd's serializer, NOT produced by any encoder in this crate) ────────

    /// #2081 (probe): under production a forged NFStatusNotify cannot poison NF_LOAD.
    /// From an AMF's certificate, an SCP's, or no certificate, on the right
    /// callback; or from the NRF on the token-less legacy callback: 403 and no
    /// load ingested. From the NRF on the tokenised callback: 204 and ingested.
    /// Under dev, as before. REVERT-VERIFIED: with the NRF check removed the AMF
    /// probe is ingested; with the correlation check removed the legacy one is.
    #[tokio::test]
    async fn only_the_nrf_on_a_correlated_callback_feeds_nf_load_2081() {
        let body = json!({
            "event": "NF_REGISTERED",
            "nfInstanceUri": "http://nrf.example:7777/nnrf-nfm/v1/nf-instances/amf-2081",
            "nfProfile": {
                "nfInstanceId": "amf-2081",
                "nfType": "AMF",
                "nfStatus": "REGISTERED",
                "load": 99
            }
        });
        let from = |types: &[&str]| {
            let mut r = notify_req(&body);
            if !types.is_empty() {
                r.peer_cert_nf_instance_id = Some("cccccccc-2081-4000-8000-00000000000c".into());
            }
            r.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
            r
        };
        for (req, correlated, what) in [
            (from(&["AMF"]), true, "an AMF's certificate"),
            (from(&[]), true, "no certificate"),
            (from(&["SCP"]), false, "an SCP on the legacy callback"),
            (from(&["NRF"]), false, "the NRF on the legacy callback"),
        ] {
            let ctx = isolated_ctx();
            let resp = handle_nf_status_notify_gated_with_ctx(&ctx, &req, correlated, true).await;
            assert_eq!(resp.status, 403, "{what}");
            assert!(
                nf_load_infos(&ctx, "amf-2081").is_empty(),
                "{what} poisoned NF_LOAD"
            );
        }
        let ctx = isolated_ctx();
        let resp = handle_nf_status_notify_gated_with_ctx(&ctx, &from(&["NRF"]), true, true).await;
        assert_eq!(resp.status, 204);
        assert_eq!(nf_load_infos(&ctx, "amf-2081").len(), 1);
        // Dev: as before.
        let ctx = isolated_ctx();
        let resp = handle_nf_status_notify_gated_with_ctx(&ctx, &from(&[]), false, false).await;
        assert_eq!(resp.status, 204);
    }

    /// #2093: each subscribe gets its own token, and a replaced subscription's
    /// stops working when its grace window ends; a token never minted is never
    /// held.
    #[test]
    fn callback_tokens_are_per_subscription_2093() {
        let mut book = TokenBook::default();
        let first = book.mint();
        let now = std::time::Instant::now();
        assert!(book.holds(&first, now), "held while being subscribed");
        book.activate(&first, now);
        let second = book.mint();
        assert_ne!(first, second, "one token per subscription");
        // The first stays valid for its grace window after the second replaces it.
        book.activate(&second, now + std::time::Duration::from_secs(60));
        assert!(book.holds(&first, now));
        assert!(book.holds(&second, now));
        assert!(!book.holds(&first, now + std::time::Duration::from_secs(61)));
        assert!(book.holds(&second, now + std::time::Duration::from_secs(61)));
        // A failed subscribe's token is forgotten.
        let failed = book.mint();
        book.abandon(&failed);
        assert!(!book.holds(&failed, now));
        assert!(!book.holds("0123456789abcdef0123456789abcdef", now));
    }

    /// #2131 (R40 on #2119): a callback URI without the token segment cannot
    /// carry the token, so none is left pending (none can be activated) and no
    /// subscribe is sent; a tokenised one gets the minted token, held.
    ///
    /// REVERT-VERIFIED: with `callback_uri_with_token` returning the URI
    /// unchanged when it has no token segment, the tokenless case yields a URI
    /// and the `None` assertion fails.
    #[test]
    fn a_callback_that_cannot_carry_the_token_activates_none_2131() {
        let mut book = TokenBook::default();
        assert_eq!(
            mint_for_subscribe(
                &mut book,
                "https://nwdaf.example:8443/nnwdaf-callback/v1/other"
            ),
            None
        );
        assert_eq!(book.pending_len(), 0, "the minted token was abandoned");
        assert!(book.current().is_none());
        let (token, uri) = mint_for_subscribe(
            &mut book,
            &format!(
                "https://nwdaf.example:8443{}",
                callback_path_for("placeholder")
            ),
        )
        .expect("a tokenised callback");
        assert_eq!(
            uri,
            format!("https://nwdaf.example:8443/nnwdaf-callback/v1/{CALLBACK_SEGMENT}/{token}")
        );
        assert!(book.holds(&token, std::time::Instant::now()));
    }

    /// #2093 (probe), under production: the NRF directly, or an SCP presenting
    /// the subscription's own token, feeds NF_LOAD; an SCP presenting another
    /// (replaced, lapsed) subscription's token, and a forged sender with the right
    /// token, do not. REVERT-VERIFIED: with the SCP arm removed the relayed
    /// notification is refused; with one process-wide token the lapsed one is held.
    /// #2131: with `holds`'s `until > now` check dropped, "once its grace
    /// window has passed" fails (pruning cannot reach that token); with the SCP
    /// arm back on `names("SCP")`, the mixed `[SCP, AMF]` certificate is
    /// admitted.
    #[tokio::test]
    async fn the_nrf_or_an_scp_with_this_subscriptions_token_feeds_nf_load_2093() {
        let body = json!({
            "event": "NF_REGISTERED",
            "nfInstanceUri": "http://nrf.example:7777/nnrf-nfm/v1/nf-instances/smf-2093",
            "nfProfile": {
                "nfInstanceId": "smf-2093",
                "nfType": "SMF",
                "nfStatus": "REGISTERED",
                "load": 70
            }
        });
        let mut book = TokenBook::default();
        let now = std::time::Instant::now();
        // #2131: a replaced token still IN the book (its grace ends at `now + 1
        // s`, after the pruning `activate` does), so only `holds`'s lapse check
        // can refuse it once that instant has passed.
        let graced = book.mint();
        book.activate(&graced, now);
        let old = book.mint();
        book.activate(&old, now + std::time::Duration::from_secs(1));
        let current = book.mint();
        book.activate(&current, now); // the old one lapses at once
        let from = |types: &[&str]| {
            let mut r = notify_req(&body);
            r.peer_cert_nf_instance_id = Some("dddddddd-2093-4000-8000-00000000000d".into());
            r.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
            r
        };
        let deliver_at = |types: &'static [&'static str], token: String, at_ms: u64| {
            let correlated = book.holds(&token, now + std::time::Duration::from_millis(at_ms));
            let req = from(types);
            async move {
                let ctx = isolated_ctx();
                let resp =
                    handle_nf_status_notify_gated_with_ctx(&ctx, &req, correlated, true).await;
                (resp.status, nf_load_infos(&ctx, "smf-2093").len())
            }
        };
        let deliver = |types: &'static [&'static str], token: String| deliver_at(types, token, 1);
        assert_eq!(
            deliver(&["NRF"], current.clone()).await,
            (204, 1),
            "the NRF directly"
        );
        assert_eq!(
            deliver(&["SCP"], current.clone()).await,
            (204, 1),
            "an SCP with this subscription's token"
        );
        assert_eq!(
            deliver(&["SCP"], old.clone()).await,
            (403, 0),
            "an SCP with another (lapsed) subscription's token"
        );
        assert_eq!(
            deliver(&["AMF"], current.clone()).await,
            (403, 0),
            "a forged sender with the right token"
        );
        // #2131 (R40): the lapse check alone. `graced` is still in the book:
        // held within its grace window, refused once it has passed.
        assert_eq!(
            deliver_at(&["SCP"], graced.clone(), 1).await,
            (204, 1),
            "a replaced subscription's token within its grace window"
        );
        assert_eq!(
            deliver_at(&["SCP"], graced.clone(), 2_000).await,
            (403, 0),
            "the same token once its grace window has passed"
        );
        // #2131 (R40): a certificate naming SCP and another type is that NF's
        // (the #2113 relay rule), not a relay's.
        assert_eq!(
            deliver(&["SCP", "AMF"], current.clone()).await,
            (403, 0),
            "a mixed [SCP, AMF] certificate is an AMF's"
        );
    }

    /// #2093: every NFStatusSubscribe names a token of its own in its
    /// `nfStatusNotificationUri`, the NRF's acceptance makes it the current one,
    /// and the one it replaces stays held through its grace window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn each_subscribe_names_its_own_token_2093() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let seen = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let nrf = nextgcore_sbi::server::SbiServer::on_listener(
            nextgcore_sbi::server::SbiServerConfig::new(addr),
            listener,
        );
        let sink = Arc::clone(&seen);
        nrf.start(move |req: SbiRequest| {
            let sink = Arc::clone(&sink);
            async move {
                let body: Value =
                    serde_json::from_str(req.http.content.as_deref().unwrap_or("{}")).unwrap();
                let n = {
                    let mut seen = sink.lock().unwrap();
                    seen.push(body);
                    seen.len()
                };
                SbiResponse::with_status(201)
                    .with_json_body(&json!({ "subscriptionId": format!("sub-2093-{n}") }))
                    .unwrap()
            }
        })
        .await
        .expect("stub NRF");
        let ctx = isolated_ctx();
        ctx.read()
            .unwrap()
            .set_nrf_collector_config(crate::context::NrfCollectorConfig {
                nrf_uri: format!("http://{addr}"),
                callback_uri: format!("http://127.0.0.1:7777{}", callback_path_for("seed")),
            });
        subscribe_nf_status(&ctx).await;
        subscribe_nf_status(&ctx).await;
        nrf.stop().await.expect("stop");

        let tokens: Vec<String> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|b| {
                b["nfStatusNotificationUri"]
                    .as_str()
                    .unwrap()
                    .rsplit('/')
                    .next()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(tokens.len(), 2);
        assert_ne!(tokens[0], tokens[1], "one token per subscription");
        assert!(tokens.iter().all(|t| t != "seed"));
        assert_eq!(callback_token(), tokens[1], "the accepted one is current");
        assert!(
            holds_callback_token(&tokens[0]),
            "the replaced one, in its grace window"
        );
    }

    /// #2081: both routes go through the gate under the real profile.
    #[test]
    fn both_nf_status_routes_go_through_the_gate_2081() {
        let main = include_str!("main.rs");
        assert_eq!(
            main.matches("nrf_collector::handle_nf_status_notify_from(&request, true)")
                .count(),
            1
        );
        assert_eq!(
            main.matches("nrf_collector::handle_nf_status_notify_from(&request, false)")
                .count(),
            1
        );
        assert!(!main.contains("nrf_collector::handle_nf_status_notify(&request)"));
    }

    /// NF_REGISTERED with a full `nfProfile` carrying `load` ingests one
    /// sample with `cpu = load/100` and caches the profile metadata.
    #[tokio::test]
    async fn test_notify_nf_registered_full_profile_ingests_load() {
        let ctx = isolated_ctx();
        // Golden body: TS 29.510 §5.2.2.6 NotificationData with nfProfile
        // (shape matches nrfd's build_notification_json).
        let body = json!({
            "event": "NF_REGISTERED",
            "nfInstanceUri": "http://nrf.example:7777/nnrf-nfm/v1/nf-instances/amf-g21-reg",
            "nfProfile": {
                "nfInstanceId": "amf-g21-reg",
                "nfType": "AMF",
                "nfStatus": "REGISTERED",
                "load": 40
            }
        });
        let resp = handle_nf_status_notify_with_ctx(&ctx, &notify_req(&body)).await;
        assert_eq!(resp.status, 204, "NFStatusNotify success must be 204");

        let infos = nf_load_infos(&ctx, "amf-g21-reg");
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0]["nfType"].as_str(), Some("AMF"));
        assert_eq!(infos[0]["nfLoadLevelAverage"].as_u64(), Some(40));
        assert_eq!(infos[0]["nfStatus"]["statusRegistered"].as_u64(), Some(100));
    }

    /// NF_PROFILE_CHANGED with `profileChanges` `/load` replace (nrfd's
    /// `newValue` key) ingests the new load; a subsequent add also ingests.
    #[tokio::test]
    async fn test_notify_profile_changed_load_replace_and_add() {
        let ctx = isolated_ctx();
        let register = json!({
            "event": "NF_REGISTERED",
            "nfInstanceUri": "http://nrf.example:7777/nnrf-nfm/v1/nf-instances/smf-g21-chg",
            "nfProfile": {
                "nfInstanceId": "smf-g21-chg",
                "nfType": "SMF",
                "nfStatus": "REGISTERED",
                "load": 40
            }
        });
        assert_eq!(
            handle_nf_status_notify_with_ctx(&ctx, &notify_req(&register))
                .await
                .status,
            204
        );

        // Golden replace body (matches nrfd's profileChanges serialization:
        // op/path/newValue/origValue).
        let replace = json!({
            "event": "NF_PROFILE_CHANGED",
            "nfInstanceUri": "http://nrf.example:7777/nnrf-nfm/v1/nf-instances/smf-g21-chg",
            "profileChanges": [
                { "op": "replace", "path": "/load", "newValue": 80, "origValue": 40 }
            ]
        });
        assert_eq!(
            handle_nf_status_notify_with_ctx(&ctx, &notify_req(&replace))
                .await
                .status,
            204
        );
        let infos = nf_load_infos(&ctx, "smf-g21-chg");
        // Samples [40, 80] → average 60.
        assert_eq!(infos[0]["nfLoadLevelAverage"].as_u64(), Some(60));
        assert_eq!(infos[0]["nfLoadLevelpeak"].as_u64(), Some(80));

        // add op is also accepted (TS 29.510 ChangeItem).
        let add = json!({
            "event": "NF_PROFILE_CHANGED",
            "nfInstanceUri": "http://nrf.example:7777/nnrf-nfm/v1/nf-instances/smf-g21-chg",
            "profileChanges": [
                { "op": "add", "path": "/load", "newValue": 90 }
            ]
        });
        assert_eq!(
            handle_nf_status_notify_with_ctx(&ctx, &notify_req(&add))
                .await
                .status,
            204
        );
        let infos = nf_load_infos(&ctx, "smf-g21-chg");
        // Samples [40, 80, 90] → average 70.
        assert_eq!(infos[0]["nfLoadLevelAverage"].as_u64(), Some(70));
    }

    /// `/load` remove clears the cached load without fabricating a sample;
    /// changes not touching `/load` ingest nothing new.
    #[tokio::test]
    async fn test_notify_profile_changed_load_remove_and_unrelated() {
        let ctx = isolated_ctx();
        let register = json!({
            "event": "NF_REGISTERED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/upf-g21-rm",
            "nfProfile": {
                "nfInstanceId": "upf-g21-rm",
                "nfType": "UPF",
                "nfStatus": "REGISTERED",
                "load": 50
            }
        });
        handle_nf_status_notify_with_ctx(&ctx, &notify_req(&register)).await;

        // Unrelated change (no /load) → still one sample.
        let unrelated = json!({
            "event": "NF_PROFILE_CHANGED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/upf-g21-rm",
            "profileChanges": [
                { "op": "replace", "path": "/priority", "newValue": 3 }
            ]
        });
        assert_eq!(
            handle_nf_status_notify_with_ctx(&ctx, &notify_req(&unrelated))
                .await
                .status,
            204
        );
        let infos = nf_load_infos(&ctx, "upf-g21-rm");
        assert_eq!(
            infos[0]["nfLoadLevelAverage"].as_u64(),
            Some(50),
            "an unrelated change must not add a load sample"
        );

        // /load remove → 204, no new sample (average unchanged).
        let remove = json!({
            "event": "NF_PROFILE_CHANGED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/upf-g21-rm",
            "profileChanges": [
                { "op": "remove", "path": "/load", "origValue": 50 }
            ]
        });
        assert_eq!(
            handle_nf_status_notify_with_ctx(&ctx, &notify_req(&remove))
                .await
                .status,
            204
        );
        let infos = nf_load_infos(&ctx, "upf-g21-rm");
        assert_eq!(infos[0]["nfLoadLevelAverage"].as_u64(), Some(50));
    }

    /// NF_DEREGISTERED drops the instance's samples: analytics stop reporting
    /// it (fail-closed — no data survives the NRF saying the NF is gone).
    #[tokio::test]
    async fn test_notify_nf_deregistered_drops_instance() {
        let ctx = isolated_ctx();
        let register = json!({
            "event": "NF_REGISTERED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/pcf-g21-dereg",
            "nfProfile": {
                "nfInstanceId": "pcf-g21-dereg",
                "nfType": "PCF",
                "nfStatus": "REGISTERED",
                "load": 25
            }
        });
        handle_nf_status_notify_with_ctx(&ctx, &notify_req(&register)).await;
        assert_eq!(nf_load_infos(&ctx, "pcf-g21-dereg").len(), 1);

        // Golden dereg body: no nfProfile (nrfd omits it for deregistration).
        let dereg = json!({
            "event": "NF_DEREGISTERED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/pcf-g21-dereg"
        });
        assert_eq!(
            handle_nf_status_notify_with_ctx(&ctx, &notify_req(&dereg))
                .await
                .status,
            204
        );
        assert!(
            nf_load_infos(&ctx, "pcf-g21-dereg").is_empty(),
            "a deregistered NF must vanish from NF_LOAD analytics"
        );
    }

    // ── fail-closed mandatory-IE validation ─────────────────────────────────

    #[tokio::test]
    async fn test_notify_missing_event_400() {
        let ctx = isolated_ctx();
        let body = json!({
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/x"
        });
        let resp = handle_nf_status_notify_with_ctx(&ctx, &notify_req(&body)).await;
        assert_eq!(resp.status, 400, "missing event must be 400");
    }

    #[tokio::test]
    async fn test_notify_missing_nf_instance_uri_400() {
        let ctx = isolated_ctx();
        let body = json!({ "event": "NF_REGISTERED" });
        let resp = handle_nf_status_notify_with_ctx(&ctx, &notify_req(&body)).await;
        assert_eq!(resp.status, 400, "missing nfInstanceUri must be 400");
    }

    #[tokio::test]
    async fn test_notify_unknown_event_400() {
        let ctx = isolated_ctx();
        let body = json!({
            "event": "NF_EXPLODED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/x"
        });
        let resp = handle_nf_status_notify_with_ctx(&ctx, &notify_req(&body)).await;
        assert_eq!(resp.status, 400, "unknown event enum must be 400");
    }

    #[tokio::test]
    async fn test_notify_registered_without_profile_400() {
        let ctx = isolated_ctx();
        let body = json!({
            "event": "NF_REGISTERED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/x"
        });
        let resp = handle_nf_status_notify_with_ctx(&ctx, &notify_req(&body)).await;
        assert_eq!(resp.status, 400, "NF_REGISTERED without nfProfile is 400");
    }

    #[tokio::test]
    async fn test_notify_profile_changed_without_payload_400() {
        let ctx = isolated_ctx();
        let body = json!({
            "event": "NF_PROFILE_CHANGED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/x"
        });
        let resp = handle_nf_status_notify_with_ctx(&ctx, &notify_req(&body)).await;
        assert_eq!(
            resp.status, 400,
            "NF_PROFILE_CHANGED without nfProfile/profileChanges is 400"
        );
    }

    #[tokio::test]
    async fn test_notify_out_of_range_load_400() {
        let ctx = isolated_ctx();
        let body = json!({
            "event": "NF_PROFILE_CHANGED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/x",
            "profileChanges": [
                { "op": "replace", "path": "/load", "newValue": 250 }
            ]
        });
        let resp = handle_nf_status_notify_with_ctx(&ctx, &notify_req(&body)).await;
        assert_eq!(
            resp.status, 400,
            "NFProfile.load is 0..=100; out-of-range must fail closed"
        );
    }

    #[tokio::test]
    async fn test_notify_malformed_json_400() {
        let ctx = isolated_ctx();
        let req = SbiRequest::post("/nnwdaf-nfstatus-notify/v1/notify")
            .with_body("{not json", "application/json");
        let resp = handle_nf_status_notify_with_ctx(&ctx, &req).await;
        assert_eq!(resp.status, 400, "malformed JSON must be 400");
    }

    /// Unknown additional fields are IGNORED (TS 29.500 SBI extensibility) —
    /// only malformed/missing mandatory IEs fail.
    #[tokio::test]
    async fn test_notify_unknown_fields_ignored() {
        let ctx = isolated_ctx();
        let body = json!({
            "event": "NF_REGISTERED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/amf-g21-ext",
            "nfProfile": {
                "nfInstanceId": "amf-g21-ext",
                "nfType": "AMF",
                "nfStatus": "REGISTERED",
                "load": 10,
                "futureRel19Field": { "x": 1 }
            },
            "someNewTopLevelField": true
        });
        let resp = handle_nf_status_notify_with_ctx(&ctx, &notify_req(&body)).await;
        assert_eq!(resp.status, 204, "unknown fields must be ignored");
        assert_eq!(nf_load_infos(&ctx, "amf-g21-ext").len(), 1);
    }

    // ── subscription body / response parsing ─────────────────────────────────

    /// The SubscriptionData we POST carries exactly the TS 29.510 fields nrfd
    /// parses: nfStatusNotificationUri (mandatory), reqNfType, reqNotifEvents;
    /// subscrCond is omitted so ALL NF instances match.
    #[test]
    fn test_subscription_body_shape() {
        let body = build_nf_status_subscription_body(
            "http://10.0.0.5:7815/nnwdaf-nfstatus-notify/v1/notify",
        );
        assert_eq!(
            body["nfStatusNotificationUri"].as_str(),
            Some("http://10.0.0.5:7815/nnwdaf-nfstatus-notify/v1/notify")
        );
        assert_eq!(body["reqNfType"].as_str(), Some("NWDAF"));
        let events: Vec<&str> = body["reqNotifEvents"]
            .as_array()
            .expect("array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(
            events,
            vec!["NF_REGISTERED", "NF_DEREGISTERED", "NF_PROFILE_CHANGED"]
        );
        assert!(
            body.get("subscrCond").is_none(),
            "subscrCond must be omitted (subscribe to all NFs)"
        );
    }

    /// The 201 parser reads subscriptionId from the body (nrfd's
    /// subscription_response_json shape) and converts the RFC 3339
    /// validityTime to Unix seconds; it falls back to the Location header.
    #[test]
    fn test_parse_subscription_create_response() {
        // Golden body: nrfd 201 response shape.
        let body = r#"{
            "subscriptionId": "sub-123",
            "nfStatusNotificationUri": "http://cb/notify",
            "validityTime": "2026-07-01T12:00:00+00:00"
        }"#;
        let sub = parse_subscription_create_response(Some(body), None).expect("parsed");
        assert_eq!(sub.subscription_id, "sub-123");
        // 2026-07-01T12:00:00Z == 1782907200 Unix (hand-derived:
        // days(1970-01-01..2026-07-01) = 20635; 20635*86400 + 12*3600
        // = 1782864000 + 43200 = 1782907200).
        assert_eq!(sub.validity_unix, Some(1_782_907_200));

        // Location-header fallback.
        let sub =
            parse_subscription_create_response(None, Some("/nnrf-nfm/v1/subscriptions/sub-456"))
                .expect("parsed");
        assert_eq!(sub.subscription_id, "sub-456");
        assert_eq!(sub.validity_unix, None);

        // Neither → None (caller retries).
        assert!(parse_subscription_create_response(Some("{}"), None).is_none());
    }

    /// Renewal predicate: no subscription → subscribe; expiring within the
    /// margin → subscribe; healthy → leave alone. Exercised through
    /// `maybe_renew_nrf_subscription` with an unroutable NRF so the POST
    /// fails fast and the state stays observable.
    #[tokio::test]
    async fn test_maybe_renew_paths() {
        let ctx = isolated_ctx();

        // Not armed → no-op (no panic, no network).
        maybe_renew_nrf_subscription(&ctx).await;
        assert!(ctx.read().unwrap().nrf_status_subscription().is_none());

        // Armed with a healthy subscription (far-future expiry) → untouched.
        {
            let guard = ctx.read().unwrap();
            guard.set_nrf_collector_config(crate::context::NrfCollectorConfig {
                nrf_uri: "http://127.0.0.1:1".to_string(), // unroutable port
                callback_uri: "http://127.0.0.1:2/nnwdaf-nfstatus-notify/v1/notify".to_string(),
            });
            guard.set_nrf_status_subscription(Some(NrfStatusSubscription {
                subscription_id: "sub-healthy".to_string(),
                validity_unix: Some(u64::MAX),
            }));
        }
        maybe_renew_nrf_subscription(&ctx).await;
        assert_eq!(
            ctx.read()
                .unwrap()
                .nrf_status_subscription()
                .expect("kept")
                .subscription_id,
            "sub-healthy",
            "a healthy subscription must not be replaced"
        );

        // Expiring subscription → renewal attempted (POST fails against the
        // unroutable NRF, state keeps the old id — retry semantics, no panic).
        {
            let guard = ctx.read().unwrap();
            guard.set_nrf_status_subscription(Some(NrfStatusSubscription {
                subscription_id: "sub-expiring".to_string(),
                validity_unix: Some(0),
            }));
        }
        maybe_renew_nrf_subscription(&ctx).await;
        assert_eq!(
            ctx.read()
                .unwrap()
                .nrf_status_subscription()
                .expect("kept on failure")
                .subscription_id,
            "sub-expiring",
            "a failed renewal must not clear the stored subscription"
        );
    }
}
